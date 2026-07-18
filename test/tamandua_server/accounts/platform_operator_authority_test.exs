defmodule TamanduaServer.Accounts.PlatformOperatorAuthorityTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Accounts.{
    PlatformOperatorAuthorization,
    PlatformOperatorCapabilities,
    PlatformOperatorElevationProof,
    PlatformOperatorEvent,
    PlatformOperatorExternalReceipt,
    PlatformOperatorGrant,
    PlatformOperatorSession,
    User
  }

  @now ~U[2026-07-16 12:00:00.000000Z]
  @user_id "11111111-1111-4111-8111-111111111111"
  @grant_id "22222222-2222-4222-8222-222222222222"
  @elevation_id "33333333-3333-4333-8333-333333333333"
  @session_binding String.duplicate("s", 48)
  @raw_proof String.duplicate("p", 48)
  @capability :global_threat_intel_manage

  test "capability vocabulary is exact and has no wildcard" do
    assert PlatformOperatorCapabilities.all() == [
             "organizations_metadata_read",
             "global_threat_intel_manage",
             "misp_global_read",
             "misp_global_manage"
           ]

    assert PlatformOperatorCapabilities.normalize(@capability) ==
             {:ok, "global_threat_intel_manage"}

    assert PlatformOperatorCapabilities.normalize("misp_global_read") ==
             {:ok, "misp_global_read"}

    assert PlatformOperatorCapabilities.normalize("*") == {:error, :unknown_capability}
    assert PlatformOperatorCapabilities.normalize(:system_all) == {:error, :unknown_capability}
  end

  test "grant changeset rejects unknown, duplicate, and expired capabilities" do
    valid_attrs = %{
      user_id: @user_id,
      granted_by_user_id: Ecto.UUID.generate(),
      capabilities: ["misp_global_read"],
      reason: "approved platform support operation",
      expires_at: DateTime.add(@now, 3_600, :second)
    }

    assert PlatformOperatorGrant.create_changeset(%PlatformOperatorGrant{}, valid_attrs, @now).valid?

    refute PlatformOperatorGrant.create_changeset(
             %PlatformOperatorGrant{},
             %{valid_attrs | granted_by_user_id: @user_id},
             @now
           ).valid?

    refute PlatformOperatorGrant.create_changeset(
             %PlatformOperatorGrant{},
             %{valid_attrs | capabilities: ["misp_global_read", "misp_global_read"]},
             @now
           ).valid?

    refute PlatformOperatorGrant.create_changeset(
             %PlatformOperatorGrant{},
             %{valid_attrs | capabilities: ["system_all"]},
             @now
           ).valid?

    refute PlatformOperatorGrant.create_changeset(
             %PlatformOperatorGrant{},
             %{valid_attrs | expires_at: @now},
             @now
           ).valid?
  end

  test "elevation schema accepts only digest material, exact audience, purpose, and bounded time order" do
    attrs = %{
      user_id: @user_id,
      grant_id: @grant_id,
      proof_hash: digest(@raw_proof),
      session_binding_hash: digest(@session_binding),
      mfa_timestep_hash: digest("mfa-step"),
      audience: "misp_global_manage",
      purpose: "platform_operation",
      issued_at: @now,
      expires_at: DateTime.add(@now, 300, :second)
    }

    assert PlatformOperatorElevationProof.changeset(
             %PlatformOperatorElevationProof{},
             attrs
           ).valid?

    refute PlatformOperatorElevationProof.changeset(
             %PlatformOperatorElevationProof{},
             %{attrs | proof_hash: @raw_proof}
           ).valid?

    refute PlatformOperatorElevationProof.changeset(
             %PlatformOperatorElevationProof{},
             %{attrs | audience: "*"}
           ).valid?

    refute PlatformOperatorElevationProof.changeset(
             %PlatformOperatorElevationProof{},
             %{attrs | purpose: "anything"}
           ).valid?
  end

  test "append-only event changeset refuses metadata that could persist auth secrets" do
    base = %{
      event_type: "authorization_denied",
      outcome: "denied",
      reason: "elevation_missing",
      occurred_at: @now
    }

    assert PlatformOperatorEvent.changeset(
             %PlatformOperatorEvent{},
             Map.put(base, :metadata, %{request_id: "req-1"})
           ).valid?

    refute PlatformOperatorEvent.changeset(
             %PlatformOperatorEvent{},
             Map.put(base, :metadata, %{nested: %{elevation_proof: @raw_proof}})
           ).valid?

    refute PlatformOperatorEvent.changeset(
             %PlatformOperatorEvent{},
             Map.put(base, :metadata, %{session_binding_hash: digest(@session_binding)})
           ).valid?
  end

  test "external receipt schema accepts only digest material and paired terminal state" do
    attrs = %{
      operation_id: "operation-123",
      token_hash: digest("receipt-token"),
      worker_identity_hash: digest("worker-identity"),
      intent_event_id: Ecto.UUID.generate(),
      issued_at: @now,
      expires_at: DateTime.add(@now, 3_600, :second)
    }

    assert PlatformOperatorExternalReceipt.changeset(
             %PlatformOperatorExternalReceipt{},
             attrs
           ).valid?

    refute PlatformOperatorExternalReceipt.changeset(
             %PlatformOperatorExternalReceipt{},
             %{attrs | token_hash: "raw-receipt-token"}
           ).valid?

    refute PlatformOperatorExternalReceipt.changeset(
             %PlatformOperatorExternalReceipt{},
             Map.merge(attrs, %{terminal_at: @now, terminal_outcome: nil})
           ).valid?
  end

  test "authorizes only active session actor with matching grant and elevation" do
    assert {:ok, decision} =
             PlatformOperatorAuthorization.evaluate(
               actor(),
               @capability,
               grant(),
               elevation(),
               @now
             )

    assert decision == %{
             capability: "global_threat_intel_manage",
             grant_id: @grant_id,
             elevation_proof_id: @elevation_id,
             user_id: @user_id
           }
  end

  test "rejects API keys, inactive users, unknown capability, and missing elevation" do
    assert PlatformOperatorAuthorization.validate_actor(%{auth_method: :api_key}) ==
             {:error, :api_keys_forbidden}

    assert {:error, :inactive_user} =
             PlatformOperatorAuthorization.evaluate(
               %{actor() | user: %{actor().user | is_active: false}},
               @capability,
               grant(),
               elevation(),
               @now
             )

    assert {:error, :unknown_capability} =
             PlatformOperatorAuthorization.evaluate(
               actor(),
               :system_all,
               grant(),
               elevation(),
               @now
             )

    assert {:error, :elevation_missing} =
             PlatformOperatorAuthorization.evaluate(actor(), @capability, grant(), nil, @now)
  end

  test "rejects expired or revoked grants" do
    assert {:error, :grant_expired} =
             PlatformOperatorAuthorization.evaluate(
               actor(),
               @capability,
               %{grant() | expires_at: @now},
               elevation(),
               @now
             )

    assert {:error, :grant_revoked} =
             PlatformOperatorAuthorization.evaluate(
               actor(),
               @capability,
               %{grant() | revoked_at: @now},
               elevation(),
               @now
             )
  end

  test "rejects expired, wrong-session, wrong-audience, and wrong-purpose elevation" do
    assert {:error, :elevation_expired} =
             PlatformOperatorAuthorization.evaluate(
               actor(),
               @capability,
               grant(),
               %{elevation() | expires_at: @now},
               @now
             )

    assert {:error, :elevation_wrong_session} =
             PlatformOperatorAuthorization.evaluate(
               %{actor() | session_binding: String.duplicate("x", 48)},
               @capability,
               grant(),
               elevation(),
               @now
             )

    assert {:error, :elevation_wrong_audience} =
             PlatformOperatorAuthorization.evaluate(
               actor(),
               @capability,
               grant(),
               %{elevation() | audience: "misp_global_read"},
               @now
             )

    assert {:error, :elevation_wrong_purpose} =
             PlatformOperatorAuthorization.evaluate(
               actor(),
               @capability,
               grant(),
               %{elevation() | purpose: "other"},
               @now
             )
  end

  test "rejects absent or short-lived session binding material" do
    assert {:error, :persistent_session_required} =
             PlatformOperatorAuthorization.evaluate(
               Map.delete(actor(), :session_binding),
               @capability,
               grant(),
               elevation(),
               @now
             )

    assert {:error, :persistent_session_required} =
             PlatformOperatorAuthorization.evaluate(
               %{actor() | session_binding: "short"},
               @capability,
               grant(),
               elevation(),
               @now
             )
  end

  test "rejects future, consumed, and revoked one-shot elevation proofs" do
    assert {:error, :elevation_issued_in_future} =
             PlatformOperatorAuthorization.evaluate(
               actor(),
               @capability,
               grant(),
               %{elevation() | issued_at: DateTime.add(@now, 1, :second)},
               @now
             )

    assert {:error, :elevation_already_consumed} =
             PlatformOperatorAuthorization.evaluate(
               actor(),
               @capability,
               grant(),
               %{elevation() | consumed_at: @now, consumed_operation_id: "operation-1"},
               @now
             )

    assert {:error, :elevation_revoked} =
             PlatformOperatorAuthorization.evaluate(
               actor(),
               @capability,
               grant(),
               %{elevation() | revoked_at: @now},
               @now
             )
  end

  test "arbitrary provisioning and revocation are fail closed" do
    alias TamanduaServer.Accounts.PlatformOperatorAuthority

    assert PlatformOperatorAuthority.provision_grant(%{}) ==
             {:error, :two_person_ceremony_required}

    assert PlatformOperatorAuthority.revoke_grant(grant(), @user_id, "arbitrary revoke") ==
             {:error, :two_person_ceremony_required}
  end

  test "arbitrary execution callbacks are permanently fail closed" do
    alias TamanduaServer.Accounts.PlatformOperatorAuthority

    assert PlatformOperatorAuthority.authorize_and_execute(
             actor(),
             @capability,
             %{id: "operation-123", target: "misp:global"},
             fn _ -> raise "must never execute" end
           ) == {:error, :declarative_authority_operation_required}
  end

  test "authorization evidence remains pending until a receipt-bound terminal outcome" do
    authority =
      File.read!(
        Path.expand(
          "../../../lib/tamandua_server/accounts/platform_operator_authority.ex",
          __DIR__
        )
      )

    assert authority =~ ~s(event_type: "authorization_allowed")
    assert authority =~ ~s(reason: "external_execution_authorized_pending_outcome")

    assert authority =~
             ~r/event_type: "authorization_allowed"[\s\S]{0,500}outcome: "pending"/

    refute authority =~ ~s(reason: "authorized_and_executed")
  end

  test "TOTP verification returns the counter that matched across the tolerance window" do
    secret = :crypto.strong_rand_bytes(20) |> Base.encode32(padding: false)
    current_counter = div(DateTime.to_unix(@now), 30)
    future_counter = current_counter + 1
    future_code = totp_at_counter(secret, future_counter)

    assert {:ok, ^future_counter} =
             TamanduaServer.Accounts.verify_totp_with_counter(secret, future_code,
               unix_time: DateTime.to_unix(@now)
             )

    assert {:ok, ^future_counter} =
             TamanduaServer.Accounts.verify_totp_with_counter(secret, future_code,
               unix_time: DateTime.to_unix(@now) + 30
             )

    live_counter = div(System.system_time(:second), 30)
    assert TamanduaServer.Accounts.verify_totp(secret, totp_at_counter(secret, live_counter))

    rate_limited_secret = :crypto.strong_rand_bytes(20) |> Base.encode32(padding: false)

    for _ <- 1..5 do
      assert {:error, :invalid_totp} =
               TamanduaServer.Accounts.verify_totp_with_counter(
                 rate_limited_secret,
                 "xxxxxx",
                 unix_time: DateTime.to_unix(@now)
               )
    end

    assert {:error, :rate_limited} =
             TamanduaServer.Accounts.verify_totp_with_counter(
               rate_limited_secret,
               totp_at_counter(rate_limited_secret, current_counter),
               unix_time: DateTime.to_unix(@now)
             )
  end

  test "external outcome rejects oversized receipt and worker identity before persistence" do
    assert {:error, :invalid_external_outcome} =
             TamanduaServer.Accounts.PlatformOperatorAuthority.record_external_outcome(
               "operation-oversized-receipt",
               String.duplicate("r", 129),
               "trusted-worker-identity",
               :succeeded,
               "completed"
             )

    assert {:error, :invalid_external_outcome} =
             TamanduaServer.Accounts.PlatformOperatorAuthority.record_external_outcome(
               "operation-oversized-worker",
               String.duplicate("r", 43),
               String.duplicate("w", 257),
               :succeeded,
               "completed"
             )
  end

  test "MFA issuance revokes prior active proof and pins a unique timestep digest" do
    authority =
      File.read!(
        Path.expand(
          "../../../lib/tamandua_server/accounts/platform_operator_authority.ex",
          __DIR__
        )
      )

    migration =
      File.read!(
        Path.expand(
          "../../../priv/repo/migrations/20260716004000_create_platform_operator_authority.exs",
          __DIR__
        )
      )

    assert authority =~ "proof.session_binding_hash == ^session.binding_hash"
    assert authority =~ "is_nil(proof.consumed_at)"
    assert authority =~ "Repo.update_all(set: [revoked_at: now])"
    assert authority =~ "mfa_timestep_hash"
    assert migration =~ "platform_operator_elevation_proofs_mfa_step_uidx"
  end

  test "two tenant session labels cannot bootstrap without offline one-time secret" do
    alias TamanduaServer.Accounts.PlatformOperatorAuthority

    previous_enabled = Application.get_env(:tamandua_server, :platform_operator_ceremony_enabled)

    previous_hash =
      Application.get_env(:tamandua_server, :platform_operator_bootstrap_secret_hash)

    on_exit(fn ->
      restore_env(:platform_operator_ceremony_enabled, previous_enabled)
      restore_env(:platform_operator_bootstrap_secret_hash, previous_hash)
    end)

    Application.put_env(:tamandua_server, :platform_operator_ceremony_enabled, true)
    Application.delete_env(:tamandua_server, :platform_operator_bootstrap_secret_hash)

    tenant_session_label = %{
      session_id: "caller-controlled-session",
      session_binding: @session_binding
    }

    assert PlatformOperatorAuthority.approve_grant(
             @user_id,
             %{},
             tenant_session_label,
             tenant_session_label,
             ceremony_secret: nil
           ) == {:error, :offline_ceremony_secret_required}
  end

  test "migration enforces hash-only proofs and database-level append-only events" do
    migration =
      File.read!(
        Path.expand(
          "../../../priv/repo/migrations/20260716004000_create_platform_operator_authority.exs",
          __DIR__
        )
      )

    assert migration =~ "octet_length(proof_hash) = 32"
    assert migration =~ "octet_length(session_binding_hash) = 32"
    assert migration =~ "octet_length(mfa_timestep_hash) = 32"
    assert migration =~ "platform_operator_external_receipts"
    assert migration =~ "worker_identity_hash"
    assert migration =~ "BEFORE UPDATE OR DELETE ON platform_operator_events"
    assert migration =~ "BEFORE TRUNCATE ON platform_operator_events"
    assert migration =~ "purpose = 'platform_operation'"
    assert migration =~ "consumed_operation_id"
    assert migration =~ "refusing destructive rollback"
    assert migration =~ "REVOKE ALL PRIVILEGES"
    assert migration =~ "GRANT SELECT, INSERT, UPDATE ON platform_operator_grants"
    refute migration =~ "add :proof,"
    refute migration =~ "add :session_binding,"
  end

  defp actor do
    %{
      user: %User{id: @user_id, is_active: true},
      session: %PlatformOperatorSession{
        id: "session-record-1",
        user_id: @user_id,
        binding_hash: digest(@session_binding),
        authenticated_at: DateTime.add(@now, -60, :second),
        expires_at: DateTime.add(@now, 3_600, :second)
      },
      session_binding: @session_binding,
      elevation_proof: @raw_proof
    }
  end

  defp grant do
    %PlatformOperatorGrant{
      id: @grant_id,
      user_id: @user_id,
      capabilities: ["global_threat_intel_manage"],
      expires_at: DateTime.add(@now, 3_600, :second)
    }
  end

  defp elevation do
    %PlatformOperatorElevationProof{
      id: @elevation_id,
      user_id: @user_id,
      grant_id: @grant_id,
      proof_hash: digest(@raw_proof),
      session_binding_hash: digest(@session_binding),
      mfa_timestep_hash: digest("mfa-step"),
      audience: "global_threat_intel_manage",
      purpose: "platform_operation",
      issued_at: @now,
      expires_at: DateTime.add(@now, 300, :second)
    }
  end

  defp digest(value), do: :crypto.hash(:sha256, value)

  defp totp_at_counter(secret, counter) do
    {:ok, decoded_secret} = Base.decode32(secret, padding: false)
    hmac = :crypto.mac(:hmac, :sha, decoded_secret, <<counter::unsigned-big-integer-size(64)>>)
    offset = Bitwise.band(:binary.at(hmac, 19), 0x0F)
    <<_::binary-size(offset), code::unsigned-big-integer-size(32), _::binary>> = hmac

    code
    |> Bitwise.band(0x7FFFFFFF)
    |> rem(1_000_000)
    |> Integer.to_string()
    |> String.pad_leading(6, "0")
  end

  defp restore_env(key, nil), do: Application.delete_env(:tamandua_server, key)
  defp restore_env(key, value), do: Application.put_env(:tamandua_server, key, value)
end
