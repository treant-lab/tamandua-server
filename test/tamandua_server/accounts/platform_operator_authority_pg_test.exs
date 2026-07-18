defmodule TamanduaServer.Accounts.PlatformOperatorAuthorityPGTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Accounts.{
    PlatformOperatorAuthority,
    PlatformOperatorElevationProof,
    PlatformOperatorEvent,
    PlatformOperatorExternalReceipt,
    PlatformOperatorGrant,
    PlatformOperatorSession,
    User
  }

  @now ~U[2026-07-16 12:00:00.000000Z]
  @capability "misp_global_manage"
  @binding String.duplicate("session-binding-", 3)

  defmodule SessionStore do
    @behaviour TamanduaServer.Accounts.PlatformOperatorSession.Store

    @impl true
    def fetch_for_update(_repo, session_id, _binding) do
      case :ets.lookup(__MODULE__, session_id) do
        [{^session_id, session}] -> {:ok, session}
        [] -> {:error, :persistent_session_required}
      end
    end
  end

  defmodule SafeDBPreflightProbe do
    @behaviour TamanduaServer.Accounts.PlatformOperatorDBPreflight.Probe

    @impl true
    def inspect_role(_repo) do
      {:ok,
       %{
         role: "authority_test_runtime",
         superuser: false,
         bypass_rls: false,
         inherits_roles: false,
         missing_tables: 0,
         owns_table: false,
         member_of_owner: false,
         prohibited_dml: false
       }}
    end
  end

  setup do
    table = :ets.new(SessionStore, [:named_table, :public, read_concurrency: true])
    previous_store = Application.get_env(:tamandua_server, :platform_operator_session_store)

    previous_probe =
      Application.get_env(:tamandua_server, :platform_operator_db_preflight_probe)

    Application.put_env(:tamandua_server, :platform_operator_session_store, SessionStore)

    Application.put_env(
      :tamandua_server,
      :platform_operator_db_preflight_probe,
      SafeDBPreflightProbe
    )

    on_exit(fn ->
      if :ets.whereis(SessionStore) != :undefined, do: :ets.delete(table)

      if is_nil(previous_store),
        do: Application.delete_env(:tamandua_server, :platform_operator_session_store),
        else:
          Application.put_env(:tamandua_server, :platform_operator_session_store, previous_store)

      if is_nil(previous_probe),
        do: Application.delete_env(:tamandua_server, :platform_operator_db_preflight_probe),
        else:
          Application.put_env(
            :tamandua_server,
            :platform_operator_db_preflight_probe,
            previous_probe
          )
    end)

    :ok
  end

  test "proof is consumed once under row lock, including concurrent replay" do
    %{actor: actor, user: user, proof: proof} = authority_fixture()

    results =
      1..2
      |> Task.async_stream(
        fn number ->
          PlatformOperatorAuthority.authorize_external_intent(
            actor,
            @capability,
            %{
              id: "concurrent-operation-#{number}",
              target: "misp:global",
              worker_identity: "misp-worker-primary"
            },
            now: @now
          )
        end,
        max_concurrency: 2,
        timeout: 5_000
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.count(results, &match?({:ok, _}, &1)) == 1
    assert Enum.count(results, &match?({:error, :elevation_already_consumed}, &1)) == 1
    assert Repo.reload!(proof).consumed_at
    assert Repo.reload!(user).is_active
  end

  test "arbitrary callback is never invoked and does not consume proof" do
    %{actor: actor, user: user, proof: proof} = authority_fixture()

    assert {:error, :declarative_authority_operation_required} =
             PlatformOperatorAuthority.authorize_and_execute(
               actor,
               @capability,
               %{id: "rollback-operation", target: "misp:global"},
               fn _decision ->
                 Repo.update!(Ecto.Changeset.change(user, locale: "pt-BR"))
               end,
               now: @now
             )

    assert Repo.reload!(user).locale != "pt-BR"
    assert is_nil(Repo.reload!(proof).consumed_at)
  end

  test "future proof and API-key provenance fail closed" do
    %{actor: actor, proof: proof} = authority_fixture()

    Repo.update_all(from(item in PlatformOperatorElevationProof, where: item.id == ^proof.id),
      set: [issued_at: DateTime.add(@now, 60, :second)]
    )

    assert {:error, :elevation_issued_in_future} =
             PlatformOperatorAuthority.authorize_external_intent(
               actor,
               @capability,
               %{
                 id: "future-proof-operation-2",
                 target: "misp:global",
                 worker_identity: "misp-worker-primary"
               },
               now: @now
             )

    assert {:error, :api_keys_forbidden} =
             PlatformOperatorAuthority.authorize_external_intent(
               Map.put(actor, :auth_method, :api_key),
               @capability,
               %{
                 id: "api-key-operation",
                 target: "misp:global",
                 worker_identity: "misp-worker-primary"
               },
               now: @now
             )
  end

  test "external outcome requires the one-time receipt and bound worker identity" do
    %{actor: actor} = authority_fixture()

    assert {:ok, intent} =
             PlatformOperatorAuthority.authorize_external_intent(
               actor,
               @capability,
               %{
                 id: "external-operation-1",
                 target: "misp:global",
                 worker_identity: "misp-worker-primary"
               },
               now: @now
             )

    receipt = Repo.get_by!(PlatformOperatorExternalReceipt, operation_id: intent.operation_id)

    allowed =
      Repo.get_by!(PlatformOperatorEvent,
        operation_id: intent.operation_id,
        event_type: "authorization_allowed"
      )

    assert byte_size(receipt.token_hash) == 32
    refute receipt.token_hash == intent.receipt_token
    assert allowed.outcome == "pending"
    assert allowed.reason == "external_execution_authorized_pending_outcome"

    assert {:error, :invalid_external_receipt} =
             PlatformOperatorAuthority.record_external_outcome(
               intent.operation_id,
               String.duplicate("x", 43),
               "misp-worker-primary",
               :succeeded,
               "completed",
               now: DateTime.add(@now, 10, :second)
             )

    assert {:error, :invalid_external_receipt} =
             PlatformOperatorAuthority.record_external_outcome(
               intent.operation_id,
               intent.receipt_token,
               "foreign-worker-id",
               :succeeded,
               "completed",
               now: DateTime.add(@now, 10, :second)
             )

    assert {:ok, %{idempotent_replay: false}} =
             PlatformOperatorAuthority.record_external_outcome(
               intent.operation_id,
               intent.receipt_token,
               "misp-worker-primary",
               :succeeded,
               "completed",
               now: DateTime.add(@now, 10, :second)
             )

    assert {:ok, %{idempotent_replay: true}} =
             PlatformOperatorAuthority.record_external_outcome(
               intent.operation_id,
               intent.receipt_token,
               "misp-worker-primary",
               :succeeded,
               "completed replay",
               now: DateTime.add(@now, 20, :second)
             )
  end

  test "database rejects a second proof for the same MFA timestep session and capability" do
    %{proof: proof} = authority_fixture()

    duplicate =
      PlatformOperatorElevationProof.changeset(%PlatformOperatorElevationProof{}, %{
        user_id: proof.user_id,
        grant_id: proof.grant_id,
        proof_hash: :crypto.strong_rand_bytes(32),
        session_binding_hash: proof.session_binding_hash,
        mfa_timestep_hash: proof.mfa_timestep_hash,
        audience: proof.audience,
        purpose: proof.purpose,
        issued_at: proof.issued_at,
        expires_at: proof.expires_at
      })

    assert {:error, changeset} = Repo.insert(duplicate)
    assert "has already been taken" in errors_on(changeset).mfa_timestep_hash
  end

  test "future-window TOTP cannot issue a second proof when that counter becomes current" do
    %{actor: actor, user: user} = authority_fixture()
    secret = :crypto.strong_rand_bytes(20) |> Base.encode32(padding: false)

    user
    |> Ecto.Changeset.change(mfa_enabled: true, mfa_secret: secret)
    |> Repo.update!()

    current_counter = div(DateTime.to_unix(@now), 30)
    verified_counter = current_counter + 1
    future_code = totp_at_counter(secret, verified_counter)

    assert {:ok, first} =
             PlatformOperatorAuthority.issue_elevation(actor, @capability, future_code, now: @now)

    assert {:error, %Ecto.Changeset{}} =
             PlatformOperatorAuthority.issue_elevation(
               actor,
               @capability,
               future_code,
               now: DateTime.add(@now, 30, :second)
             )

    first_proof = Repo.get!(PlatformOperatorElevationProof, first.elevation_proof_id)
    assert is_nil(first_proof.revoked_at)

    active_count =
      from(proof in PlatformOperatorElevationProof,
        where:
          proof.user_id == ^user.id and proof.audience == ^@capability and
            is_nil(proof.revoked_at) and is_nil(proof.consumed_at)
      )
      |> Repo.aggregate(:count)

    assert active_count == 1
  end

  test "denied audit attributes actor only through the trusted session store" do
    %{actor: actor, user: user} = authority_fixture()

    operation = fn id ->
      %{
        id: id,
        target: "misp:global",
        worker_identity: "misp-worker-primary"
      }
    end

    assert {:ok, _} =
             PlatformOperatorAuthority.authorize_external_intent(
               actor,
               @capability,
               operation.("attribution-operation-1"),
               now: @now
             )

    assert {:error, :elevation_already_consumed} =
             PlatformOperatorAuthority.authorize_external_intent(
               actor,
               @capability,
               operation.("attribution-operation-2"),
               now: @now
             )

    denied =
      Repo.get_by!(PlatformOperatorEvent,
        event_type: "authorization_denied",
        operation_id: "attribution-operation-2"
      )

    assert denied.actor_user_id == user.id
    assert denied.subject_user_id == user.id
  end

  test "offline revoke race has one winner and invalidates outstanding proofs" do
    %{proof: proof, grant: grant} = fixture = authority_fixture()
    requester = insert(:user, is_active: true)
    approver = insert(:user, is_active: true)
    requester_ref = install_session(requester)
    approver_ref = install_session(approver)
    secret = String.duplicate("offline-revoke-secret-", 2)

    old_enabled = Application.get_env(:tamandua_server, :platform_operator_ceremony_enabled)
    old_hash = Application.get_env(:tamandua_server, :platform_operator_revoke_secret_hash)
    Application.put_env(:tamandua_server, :platform_operator_ceremony_enabled, true)

    Application.put_env(
      :tamandua_server,
      :platform_operator_revoke_secret_hash,
      :crypto.hash(:sha256, secret) |> Base.encode16(case: :lower)
    )

    on_exit(fn ->
      restore_env(:platform_operator_ceremony_enabled, old_enabled)
      restore_env(:platform_operator_revoke_secret_hash, old_hash)
    end)

    results =
      1..2
      |> Task.async_stream(fn _ ->
        PlatformOperatorAuthority.approve_revoke(
          grant.id,
          "offline governed emergency revocation",
          requester_ref,
          approver_ref,
          now: @now,
          ceremony_secret: secret
        )
      end)
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.count(results, &match?({:ok, _}, &1)) == 1
    assert Enum.count(results, &match?({:error, _}, &1)) == 1
    assert Repo.reload!(proof).revoked_at
    assert fixture.user.id == grant.user_id
  end

  defp authority_fixture do
    user = insert(:user, is_active: true)
    approver = insert(:user, is_active: true)

    grant =
      %PlatformOperatorGrant{}
      |> PlatformOperatorGrant.create_changeset(
        %{
          user_id: user.id,
          granted_by_user_id: approver.id,
          capabilities: [@capability],
          reason: "governed integration-test grant",
          expires_at: DateTime.add(@now, 3_600, :second)
        },
        @now
      )
      |> Repo.insert!()

    raw_proof = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
    binding_hash = :crypto.hash(:sha256, @binding)
    session_id = Ecto.UUID.generate()

    session = %PlatformOperatorSession{
      id: session_id,
      user_id: user.id,
      binding_hash: binding_hash,
      authenticated_at: DateTime.add(@now, -60, :second),
      expires_at: DateTime.add(@now, 3_600, :second)
    }

    :ets.insert(SessionStore, {session_id, session})

    proof =
      %PlatformOperatorElevationProof{}
      |> PlatformOperatorElevationProof.changeset(%{
        user_id: user.id,
        grant_id: grant.id,
        proof_hash: :crypto.hash(:sha256, raw_proof),
        session_binding_hash: binding_hash,
        mfa_timestep_hash: :crypto.hash(:sha256, "fixture-mfa-step"),
        audience: @capability,
        purpose: PlatformOperatorElevationProof.purpose(),
        issued_at: @now,
        expires_at: DateTime.add(@now, 300, :second)
      })
      |> Repo.insert!()

    %{
      user: user,
      grant: grant,
      proof: proof,
      actor: %{
        session_id: session_id,
        session_binding: @binding,
        elevation_proof: raw_proof
      }
    }
  end

  defp install_session(user) do
    session_id = Ecto.UUID.generate()

    session = %PlatformOperatorSession{
      id: session_id,
      user_id: user.id,
      binding_hash: :crypto.hash(:sha256, @binding),
      authenticated_at: DateTime.add(@now, -60, :second),
      expires_at: DateTime.add(@now, 3_600, :second)
    }

    :ets.insert(SessionStore, {session_id, session})
    %{session_id: session_id, session_binding: @binding}
  end

  defp restore_env(key, nil), do: Application.delete_env(:tamandua_server, key)
  defp restore_env(key, value), do: Application.put_env(:tamandua_server, key, value)

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
end
