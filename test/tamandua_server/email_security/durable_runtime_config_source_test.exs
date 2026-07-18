defmodule TamanduaServer.EmailSecurity.DurableRuntimeConfigSourceTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.EmailSecurity.{
    DurableRuntimeConfig,
    DurableRuntimeConfigVersion
  }

  alias TamanduaServer.EmailSecurity.DurableRuntimeConfig.VaultFingerprintKeyBackend

  @migration "priv/repo/migrations/20260716006000_create_email_integration_durable_config.exs"

  setup do
    previous = Application.get_env(:tamandua_server, :email_runtime_persistence_enabled)

    on_exit(fn ->
      if is_nil(previous),
        do: Application.delete_env(:tamandua_server, :email_runtime_persistence_enabled),
        else: Application.put_env(:tamandua_server, :email_runtime_persistence_enabled, previous)
    end)

    :ok
  end

  test "durable authority is default-off before touching PostgreSQL or Vault" do
    Application.delete_env(:tamandua_server, :email_runtime_persistence_enabled)

    refute DurableRuntimeConfig.enabled?()

    assert {:error, :email_runtime_persistence_disabled} =
             DurableRuntimeConfig.create_pending(
               Ecto.UUID.generate(),
               :microsoft365,
               %{},
               %{client_secret: "must-not-be-used"},
               owner_id: "source-test"
             )

    assert {:ok,
            %{
              persistence_enabled: false,
              configured: false,
              committed_revision: 0,
              applied_revision: 0,
              apply_status: "disabled"
            }} = DurableRuntimeConfig.committed_metadata("not-even-a-uuid", :microsoft365)
  end

  test "ciphertext is redacted by the Ecto schema" do
    version = %DurableRuntimeConfigVersion{
      secret_ciphertext: "vault:v1:sentinel-secret",
      request_fingerprint: :crypto.strong_rand_bytes(32),
      ciphertext_sha256: :crypto.strong_rand_bytes(32)
    }

    refute inspect(version) =~ "sentinel-secret"
    refute inspect(version) =~ "secret_ciphertext"
    refute inspect(version) =~ "request_fingerprint"
    refute inspect(version) =~ "ciphertext_sha256"
  end

  test "Vault HMAC key envelope accepts only exact canonical Base64" do
    raw = :crypto.strong_rand_bytes(32)
    encoded = Base.encode64(raw)
    unpadded = String.trim_trailing(encoded, "=")

    zero_encoded = Base.encode64(:binary.copy(<<0>>, 32))
    noncanonical_pad_bits = String.slice(zero_encoded, 0, 42) <> "B="
    url_safe = Base.url_encode64(:binary.copy(<<255>>, 32))

    assert {:ok, ^raw} = VaultFingerprintKeyBackend.normalize(%{"value_b64" => encoded})

    for rejected <- [
          raw,
          %{"value" => encoded},
          %{value_b64: encoded},
          %{"value_b64" => encoded, "extra" => true},
          %{"value_b64" => "%%%not-base64%%%"},
          %{"value_b64" => encoded <> "\n"},
          %{"value_b64" => unpadded},
          %{"value_b64" => encoded <> "="},
          %{"value_b64" => url_safe},
          %{"value_b64" => noncanonical_pad_bits},
          %{"value_b64" => Base.encode64(:crypto.strong_rand_bytes(31))},
          %{"value_b64" => Base.encode64(:crypto.strong_rand_bytes(129))},
          %{},
          123
        ] do
      assert {:error, _reason} = VaultFingerprintKeyBackend.normalize(rejected)
    end

    context = File.read!("lib/tamandua_server/email_security/durable_runtime_config.ex")
    assert context =~ "byte_size(key) >= 32 and byte_size(key) <= 128"
  end

  test "provider public configuration is an exact allowlist before any database access" do
    Application.put_env(:tamandua_server, :email_runtime_persistence_enabled, true)
    organization_id = Ecto.UUID.generate()

    for key <- ["Client_Secret", "client-secret", "unknown_key"] do
      assert {:error, :unknown_public_config_key} =
               DurableRuntimeConfig.create_pending(
                 organization_id,
                 :microsoft365,
                 Map.put(m365_public(), key, "must-not-be-public"),
                 %{client_secret: "kept-in-secret-envelope"},
                 owner_id: "source-test",
                 expected_revision: 0
               )
    end

    assert {:error, :unknown_public_config_key} =
             DurableRuntimeConfig.create_pending(
               organization_id,
               :google_workspace,
               Map.put(google_public(), :client_id, "not-in-google-contract"),
               %{client_email: "svc@example.test", private_key: "not-a-key"},
               owner_id: "source-test",
               expected_revision: 0
             )

    assert {:error, :incomplete_public_config} =
             DurableRuntimeConfig.create_pending(
               organization_id,
               :microsoft365,
               Map.delete(m365_public(), :client_id),
               %{client_secret: "secret"},
               owner_id: "source-test",
               expected_revision: 0
             )

    for invalid_secret <- [
          %{},
          %{client_secret: ""},
          %{client_secret: "   \t"},
          %{client_secret: String.duplicate("x", 16_385)},
          %{client_secret: "ok", extra: "rejected"},
          %{"client_secret" => "string", client_secret: "atom-collision"}
        ] do
      assert {:error, reason} =
               DurableRuntimeConfig.create_pending(
                 organization_id,
                 :microsoft365,
                 m365_public(),
                 invalid_secret,
                 owner_id: "source-test",
                 expected_revision: 0
               )

      assert reason in [:invalid_candidate_config, :invalid_secret_config, :ambiguous_config_key]
    end

    for invalid_google_secret <- [
          "/tmp/service-account.json",
          %{service_account_key: %{client_email: "svc@example.test", private_key: "nested"}},
          %{client_email: "svc@example.test", private_key: "not-a-pem", extra: "rejected"},
          %{client_email: "svc@example.test", private_key: "not-a-pem"},
          %{client_email: "svc@example.test", private_key: weak_rsa_private_key()}
        ] do
      assert {:error, _reason} =
               DurableRuntimeConfig.create_pending(
                 organization_id,
                 :google_workspace,
                 google_public(),
                 invalid_google_secret,
                 owner_id: "source-test",
                 expected_revision: 0
               )
    end

    assert {:error, :invalid_config_key} =
             DurableRuntimeConfig.create_pending(
               organization_id,
               :microsoft365,
               Map.put(m365_public(), {:tuple, :key}, "invalid"),
               %{client_secret: "secret"},
               owner_id: "source-test",
               expected_revision: 0
             )

    source =
      File.read!("lib/tamandua_server/email_security/durable_runtime_config.ex")

    assert source =~ "@maximum_secret_envelope_bytes 1_048_576"
    assert source =~ "@maximum_client_secret_bytes 16_384"
    assert source =~ "@maximum_ciphertext_bytes 2_097_152"
    assert source =~ "encode_bounded(envelope, @maximum_secret_envelope_bytes)"
  end

  test "migration enforces RLS, immutable content and secret-free notification payload" do
    source = File.read!(@migration)

    assert source =~ "ENABLE ROW LEVEL SECURITY"

    assert source =~ "FORCE ROW LEVEL SECURITY"
    assert source =~ "current_organization_id()"
    assert source =~ "prevent_email_config_version_content_mutation"
    assert source =~ "prevent_email_config_version_destruction"
    assert source =~ "BEFORE DELETE"
    assert source =~ "BEFORE TRUNCATE"
    assert source =~ "REVOKE DELETE, TRUNCATE"
    assert source =~ "tamandua_email_runtime_config"

    [notify_body] =
      Regex.run(
        ~r/CREATE FUNCTION notify_email_runtime_config_head\(\).*?\$\$(.*?)\$\$/s,
        source,
        capture: :all_but_first
      )

    refute notify_body =~ "secret_ciphertext"
    refute notify_body =~ "public_config"
    refute notify_body =~ "pending_operation_id"
    refute notify_body =~ "organization_id"
    refute notify_body =~ "provider"
    refute notify_body =~ "revision"
    assert notify_body =~ "pg_notify('tamandua_email_runtime_config', 'changed')"
    assert source =~ "AFTER UPDATE OF committed_revision, applied_revision, apply_status"
    refute notify_body =~ "AFTER INSERT OR UPDATE ON email_integration_config_heads"
  end

  test "migration declares tenant/provider/revision and lifecycle constraints" do
    source = File.read!(@migration)
    context = File.read!("lib/tamandua_server/email_security/durable_runtime_config.ex")

    assert source =~ "[:organization_id, :provider, :revision]"
    assert source =~ "pending_revision > committed_revision"
    assert source =~ "[:id, :organization_id, :provider]"
    assert source =~ "email_config_versions_head_scope_fkey"
    assert source =~ "FOREIGN KEY (head_id, organization_id, provider)"
    assert source =~ "ON DELETE RESTRICT"
    assert source =~ "on_delete: :restrict"
    refute source =~ "on_delete: :delete_all"
    assert source =~ "email_integration_config_versions_one_pending_idx"
    assert source =~ "email_integration_config_versions_one_committed_idx"
    assert source =~ "email_config_versions_public_no_secrets_check"
    assert source =~ "email_config_versions_public_contract_check"
    refute source =~ "jsonb_object_length"

    assert source =~
             "(public_config - ARRAY['tenant_id', 'client_id', 'poll_interval_ms', 'enabled']) = '{}'::jsonb"

    assert source =~
             "(public_config - ARRAY['admin_email', 'poll_interval_ms', 'enabled']) = '{}'::jsonb"

    refute source =~ "customer_id"
    assert source =~ "public_config::text !~*"
    assert source =~ "email_config_versions_vault_ciphertext_check"
    assert context =~ "select: max(version.revision)"
    assert context =~ "compare_ledger_revision(locked_revision, plan.revision)"
    assert context =~ "primary_health: {:ok, %{authenticated: true}}"
    refute context =~ "Map.get(health, :authenticated, true)"
    assert context =~ "Caller-provided operation IDs support response-loss replay"
    assert source =~ "[:organization_id, :provider, :operation_id]"
    assert source =~ "email_config_versions_idempotency_check"
    assert source =~ "octet_length(request_fingerprint) = 32"
    assert source =~ "request_fingerprint_key_version > 0"
    assert source =~ "octet_length(ciphertext_sha256) = 32"
    assert source =~ "enforce_email_config_pending_consistency"
    assert source =~ "DEFERRABLE INITIALLY DEFERRED"
    assert context =~ ":crypto.mac(:hmac, :sha256, key, encoded)"

    assert context =~ "defmodule VaultFingerprintKeyBackend"
    assert context =~ "VaultProvider.get_secret(\"email-runtime/idempotency-hmac/v\#{version}\")"
    refute context =~ "Manager.get(\"email-runtime/idempotency-hmac/"
    assert context =~ "defp fingerprint_material"
    assert context =~ "{:ok, key} <- fingerprint_key(key_version)"
    assert context =~ "defp request_fingerprint(\n         key,"
    refute context =~ ":email_runtime_idempotency_hmac_keys"

    assert context =~ ":crypto.hash_equals(left, right)"
    assert context =~ "@secret_schema_version 2"
    assert context =~ "tamandua.email-runtime-config.snapshot.v2"
    assert context =~ "snapshot_sha256"
    assert context =~ "envelope[\"operation_id\"] == version.operation_id"
  end

  test "retention is fail-closed until an explicit tenant offboarding workflow exists" do
    source = File.read!(@migration)

    assert source =~ "prevent_email_config_version_destruction"
    assert source =~ "email_config_version_delete_denied"
    assert source =~ "email_config_version_truncate_denied"
    assert source =~ "REVOKE DELETE, TRUNCATE"

    # This deliberately blocks organization/head cascade deletion. A governed
    # retention/tombstone workflow remains a production blocker.
    refute source =~ "on_delete: :delete_all"
  end

  test "migration trigger functions pin name resolution and qualify deferred ledger reads" do
    source = File.read!(@migration)

    assert length(Regex.scan(~r/SET search_path = pg_catalog, public, pg_temp/, source)) == 4
    assert source =~ "pending_head public.email_integration_config_heads%ROWTYPE"
    assert source =~ "FROM public.email_integration_config_heads"
    assert source =~ "FROM public.email_integration_config_versions"
    refute Regex.match?(~r/\bFROM email_integration_config_(heads|versions)\b/, source)
    assert source =~ "pg_catalog.clock_timestamp()"
    assert source =~ "pg_catalog.pg_notify"
  end

  test "commit race terminal branch reuses integrity-checked classification" do
    context = File.read!("lib/tamandua_server/email_security/durable_runtime_config.ex")

    [commit_staged_body] =
      Regex.run(
        ~r/defp commit_staged\(.*?\n  end\n\n  defp commit_pending_locked/s,
        context,
        capture: :all
      )

    assert commit_staged_body =~ "with :ok <- validate_ciphertext_digest(version) do"
    assert commit_staged_body =~ "{:ok, version_receipt(version, true)}"
  end

  defp m365_public do
    %{tenant_id: "tenant", client_id: "client", poll_interval_ms: 60_000, enabled: true}
  end

  defp google_public do
    %{admin_email: "admin@example.test", poll_interval_ms: 60_000, enabled: true}
  end

  defp weak_rsa_private_key do
    private_key = :public_key.generate_key({:rsa, 1_024, 65_537})

    :RSAPrivateKey
    |> :public_key.pem_entry_encode(private_key)
    |> then(&:public_key.pem_encode([&1]))
  end
end
