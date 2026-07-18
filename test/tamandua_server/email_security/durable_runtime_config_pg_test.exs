defmodule TamanduaServer.EmailSecurity.DurableRuntimeConfigPGTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.EmailSecurity.{
    DurableRuntimeConfig,
    DurableRuntimeConfigHead,
    DurableRuntimeConfigVersion
  }

  alias TamanduaServer.Repo.MultiTenant
  alias Ecto.Adapters.SQL.Sandbox

  if System.get_env("TAMANDUA_EMAIL_DURABLE_PG_TESTS") != "true" do
    @moduletag skip:
                 "set TAMANDUA_EMAIL_DURABLE_PG_TESTS=true after applying the additive migration to an isolated PostgreSQL database"
  end

  defmodule FakeVault do
    @behaviour TamanduaServer.EmailSecurity.DurableRuntimeConfig.SecretsBackend

    @impl true
    def health do
      {:ok, %{primary_backend: :vault, primary_health: {:ok, %{authenticated: true}}}}
    end

    @impl true
    def encrypt("email-runtime-config", plaintext) do
      {:ok, "vault:v7:" <> Base.url_encode64(plaintext, padding: false)}
    end

    @impl true
    def decrypt("email-runtime-config", "vault:v7:" <> encoded) do
      Base.url_decode64(encoded, padding: false)
    end
  end

  defmodule BarrierVault do
    @behaviour TamanduaServer.EmailSecurity.DurableRuntimeConfig.SecretsBackend

    alias TamanduaServer.EmailSecurity.DurableRuntimeConfigPGTest.FakeVault

    @impl true
    def health, do: FakeVault.health()

    @impl true
    def encrypt(key, plaintext) do
      {coordinator, barrier_ref} =
        Application.fetch_env!(:tamandua_server, :email_runtime_cas_barrier)

      send(coordinator, {:cas_encrypt_ready, barrier_ref, self()})

      receive do
        {:release_cas_encrypt, ^barrier_ref} -> FakeVault.encrypt(key, plaintext)
      after
        10_000 -> {:error, :cas_encrypt_barrier_timeout}
      end
    end

    @impl true
    def decrypt(key, ciphertext), do: FakeVault.decrypt(key, ciphertext)
  end

  defmodule BarrierDecryptVault do
    @behaviour TamanduaServer.EmailSecurity.DurableRuntimeConfig.SecretsBackend

    alias TamanduaServer.EmailSecurity.DurableRuntimeConfigPGTest.FakeVault

    @impl true
    def health, do: FakeVault.health()

    @impl true
    def encrypt(key, plaintext), do: FakeVault.encrypt(key, plaintext)

    @impl true
    def decrypt(key, ciphertext) do
      {coordinator, barrier_ref} =
        Application.fetch_env!(:tamandua_server, :email_runtime_cas_barrier)

      send(coordinator, {:commit_decrypt_ready, barrier_ref, self()})

      receive do
        {:release_commit_decrypt, ^barrier_ref} -> FakeVault.decrypt(key, ciphertext)
      after
        10_000 -> {:error, :commit_decrypt_barrier_timeout}
      end
    end
  end

  defmodule RandomizedVault do
    @behaviour TamanduaServer.EmailSecurity.DurableRuntimeConfig.SecretsBackend

    alias TamanduaServer.EmailSecurity.DurableRuntimeConfigPGTest.FakeVault

    @impl true
    def health, do: FakeVault.health()

    @impl true
    def encrypt("email-runtime-config", plaintext) do
      observer =
        Application.fetch_env!(:tamandua_server, :email_runtime_randomized_vault_observer)

      send(observer, {:randomized_vault_encrypt, self()})

      {:ok,
       "vault:v9:" <>
         Base.url_encode64(:crypto.strong_rand_bytes(16) <> plaintext, padding: false)}
    end

    @impl true
    def decrypt("email-runtime-config", "vault:v9:" <> encoded) do
      with {:ok, <<_nonce::binary-size(16), plaintext::binary>>} <-
             Base.url_decode64(encoded, padding: false) do
        {:ok, plaintext}
      end
    end
  end

  defmodule MustNotBeCalledVault do
    @behaviour TamanduaServer.EmailSecurity.DurableRuntimeConfig.SecretsBackend

    @impl true
    def health, do: raise("Vault health must not be called")

    @impl true
    def encrypt(_key, _plaintext), do: raise("Vault encrypt must not be called")

    @impl true
    def decrypt(_key, _ciphertext), do: raise("Vault decrypt must not be called")
  end

  defmodule ObservingFingerprintKeyBackend do
    @behaviour TamanduaServer.EmailSecurity.DurableRuntimeConfig.FingerprintKeyBackend

    alias TamanduaServer.EmailSecurity.DurableRuntimeConfig.TestMapFingerprintKeyBackend
    alias TamanduaServer.Repo

    @impl true
    def fetch(version) do
      observer =
        Application.fetch_env!(:tamandua_server, :email_runtime_fingerprint_key_observer)

      send(observer, {:fingerprint_key_fetch, version, Repo.in_transaction?()})
      TestMapFingerprintKeyBackend.fetch(version)
    end
  end

  defmodule ChurningFingerprintKeyBackend do
    @behaviour TamanduaServer.EmailSecurity.DurableRuntimeConfig.FingerprintKeyBackend

    alias TamanduaServer.EmailSecurity.DurableRuntimeConfig.TestMapFingerprintKeyBackend

    @impl true
    def fetch(version) do
      observer =
        Application.fetch_env!(:tamandua_server, :email_runtime_fingerprint_key_observer)

      send(observer, {:churning_fingerprint_key_fetch, version})

      Application.put_env(
        :tamandua_server,
        :email_runtime_idempotency_hmac_active_key_version,
        version + 1
      )

      TestMapFingerprintKeyBackend.fetch(version)
    end
  end

  defmodule KVContractFingerprintKeyBackend do
    @behaviour TamanduaServer.EmailSecurity.DurableRuntimeConfig.FingerprintKeyBackend

    alias TamanduaServer.EmailSecurity.DurableRuntimeConfig.VaultFingerprintKeyBackend

    @impl true
    def fetch(_version) do
      :tamandua_server
      |> Application.fetch_env!(:email_runtime_fingerprint_kv_fixture)
      |> VaultFingerprintKeyBackend.normalize()
    end
  end

  defmodule SwappedEnvelopeVault do
    @behaviour TamanduaServer.EmailSecurity.DurableRuntimeConfig.SecretsBackend

    alias TamanduaServer.EmailSecurity.DurableRuntimeConfigPGTest.FakeVault

    @impl true
    def health, do: FakeVault.health()

    @impl true
    def encrypt(key, plaintext), do: FakeVault.encrypt(key, plaintext)

    @impl true
    def decrypt(key, ciphertext) do
      with {:ok, plaintext} <- FakeVault.decrypt(key, ciphertext),
           {:ok, envelope} <- Jason.decode(plaintext) do
        Jason.encode(Map.put(envelope, "snapshot_sha256", "tampered-digest"))
      end
    end
  end

  defmodule SwappedOperationVault do
    @behaviour TamanduaServer.EmailSecurity.DurableRuntimeConfig.SecretsBackend

    alias TamanduaServer.EmailSecurity.DurableRuntimeConfigPGTest.FakeVault

    @impl true
    def health, do: FakeVault.health()

    @impl true
    def encrypt(key, plaintext), do: FakeVault.encrypt(key, plaintext)

    @impl true
    def decrypt(key, ciphertext) do
      with {:ok, plaintext} <- FakeVault.decrypt(key, ciphertext),
           {:ok, envelope} <- Jason.decode(plaintext) do
        Jason.encode(Map.put(envelope, "operation_id", Ecto.UUID.generate()))
      end
    end
  end

  defmodule UnhealthyVault do
    @behaviour TamanduaServer.EmailSecurity.DurableRuntimeConfig.SecretsBackend

    @impl true
    def health do
      {:ok, %{primary_backend: :vault, primary_health: {:ok, %{authenticated: false}}}}
    end

    @impl true
    def encrypt(_key, _plaintext), do: raise("encryption must not run when Vault is unhealthy")

    @impl true
    def decrypt(_key, _ciphertext), do: raise("decryption must not run when Vault is unhealthy")
  end

  defmodule PartialHealthVault do
    @behaviour TamanduaServer.EmailSecurity.DurableRuntimeConfig.SecretsBackend

    @impl true
    def health do
      {:ok, %{primary_backend: :vault, primary_health: {:ok, %{token_ttl: 3_600}}}}
    end

    @impl true
    def encrypt(_key, _plaintext),
      do: raise("encryption must not run without explicit authenticated:true")

    @impl true
    def decrypt(_key, _ciphertext),
      do: raise("decryption must not run without explicit authenticated:true")
  end

  setup do
    previous = Application.get_env(:tamandua_server, :email_runtime_persistence_enabled)

    previous_backend =
      Application.get_env(:tamandua_server, :email_runtime_test_secrets_backend)

    previous_override =
      Application.get_env(:tamandua_server, :email_runtime_allow_test_secrets_backend)

    previous_cas_barrier =
      Application.get_env(:tamandua_server, :email_runtime_cas_barrier)

    previous_hmac_keys =
      Application.get_env(:tamandua_server, :email_runtime_idempotency_hmac_test_keys)

    previous_fingerprint_backend =
      Application.get_env(:tamandua_server, :email_runtime_test_fingerprint_key_backend)

    previous_fingerprint_override =
      Application.get_env(:tamandua_server, :email_runtime_allow_test_fingerprint_key_backend)

    previous_hmac_active =
      Application.get_env(
        :tamandua_server,
        :email_runtime_idempotency_hmac_active_key_version
      )

    previous_randomized_observer =
      Application.get_env(:tamandua_server, :email_runtime_randomized_vault_observer)

    previous_outer_transaction_override =
      Application.get_env(:tamandua_server, :email_runtime_allow_test_outer_transaction)

    previous_fingerprint_observer =
      Application.get_env(:tamandua_server, :email_runtime_fingerprint_key_observer)

    previous_kv_fixture =
      Application.get_env(:tamandua_server, :email_runtime_fingerprint_kv_fixture)

    Application.put_env(:tamandua_server, :email_runtime_persistence_enabled, true)
    Application.put_env(:tamandua_server, :email_runtime_test_secrets_backend, FakeVault)
    Application.put_env(:tamandua_server, :email_runtime_allow_test_secrets_backend, true)

    Application.put_env(:tamandua_server, :email_runtime_idempotency_hmac_test_keys, %{
      1 => :crypto.strong_rand_bytes(32),
      2 => :crypto.strong_rand_bytes(32)
    })

    Application.put_env(
      :tamandua_server,
      :email_runtime_test_fingerprint_key_backend,
      DurableRuntimeConfig.TestMapFingerprintKeyBackend
    )

    Application.put_env(
      :tamandua_server,
      :email_runtime_allow_test_fingerprint_key_backend,
      true
    )

    Application.put_env(
      :tamandua_server,
      :email_runtime_idempotency_hmac_active_key_version,
      1
    )

    Application.put_env(:tamandua_server, :email_runtime_allow_test_outer_transaction, true)

    on_exit(fn ->
      if is_nil(previous),
        do: Application.delete_env(:tamandua_server, :email_runtime_persistence_enabled),
        else: Application.put_env(:tamandua_server, :email_runtime_persistence_enabled, previous)

      if is_nil(previous_backend),
        do: Application.delete_env(:tamandua_server, :email_runtime_test_secrets_backend),
        else:
          Application.put_env(
            :tamandua_server,
            :email_runtime_test_secrets_backend,
            previous_backend
          )

      if is_nil(previous_override),
        do: Application.delete_env(:tamandua_server, :email_runtime_allow_test_secrets_backend),
        else:
          Application.put_env(
            :tamandua_server,
            :email_runtime_allow_test_secrets_backend,
            previous_override
          )

      if is_nil(previous_cas_barrier),
        do: Application.delete_env(:tamandua_server, :email_runtime_cas_barrier),
        else:
          Application.put_env(
            :tamandua_server,
            :email_runtime_cas_barrier,
            previous_cas_barrier
          )

      if is_nil(previous_hmac_keys),
        do: Application.delete_env(:tamandua_server, :email_runtime_idempotency_hmac_test_keys),
        else:
          Application.put_env(
            :tamandua_server,
            :email_runtime_idempotency_hmac_test_keys,
            previous_hmac_keys
          )

      if is_nil(previous_fingerprint_backend),
        do:
          Application.delete_env(
            :tamandua_server,
            :email_runtime_test_fingerprint_key_backend
          ),
        else:
          Application.put_env(
            :tamandua_server,
            :email_runtime_test_fingerprint_key_backend,
            previous_fingerprint_backend
          )

      if is_nil(previous_fingerprint_override),
        do:
          Application.delete_env(
            :tamandua_server,
            :email_runtime_allow_test_fingerprint_key_backend
          ),
        else:
          Application.put_env(
            :tamandua_server,
            :email_runtime_allow_test_fingerprint_key_backend,
            previous_fingerprint_override
          )

      if is_nil(previous_hmac_active),
        do:
          Application.delete_env(
            :tamandua_server,
            :email_runtime_idempotency_hmac_active_key_version
          ),
        else:
          Application.put_env(
            :tamandua_server,
            :email_runtime_idempotency_hmac_active_key_version,
            previous_hmac_active
          )

      if is_nil(previous_randomized_observer),
        do:
          Application.delete_env(
            :tamandua_server,
            :email_runtime_randomized_vault_observer
          ),
        else:
          Application.put_env(
            :tamandua_server,
            :email_runtime_randomized_vault_observer,
            previous_randomized_observer
          )

      if is_nil(previous_outer_transaction_override),
        do:
          Application.delete_env(
            :tamandua_server,
            :email_runtime_allow_test_outer_transaction
          ),
        else:
          Application.put_env(
            :tamandua_server,
            :email_runtime_allow_test_outer_transaction,
            previous_outer_transaction_override
          )

      if is_nil(previous_fingerprint_observer),
        do:
          Application.delete_env(
            :tamandua_server,
            :email_runtime_fingerprint_key_observer
          ),
        else:
          Application.put_env(
            :tamandua_server,
            :email_runtime_fingerprint_key_observer,
            previous_fingerprint_observer
          )

      if is_nil(previous_kv_fixture),
        do: Application.delete_env(:tamandua_server, :email_runtime_fingerprint_kv_fixture),
        else:
          Application.put_env(
            :tamandua_server,
            :email_runtime_fingerprint_kv_fixture,
            previous_kv_fixture
          )
    end)

    %{organization: insert(:organization)}
  end

  test "caller operation replay keeps first randomized ciphertext across HMAC rotation", %{
    organization: org
  } do
    operation_id = Ecto.UUID.generate()
    Application.put_env(:tamandua_server, :email_runtime_test_secrets_backend, RandomizedVault)
    Application.put_env(:tamandua_server, :email_runtime_randomized_vault_observer, self())

    args = [
      org.id,
      :microsoft365,
      m365_public(),
      %{client_secret: "response-loss-secret"},
      [owner_id: "retry-owner", expected_revision: 0, operation_id: operation_id]
    ]

    assert {:ok, first_receipt = %{replayed: false, status: "pending"}} =
             apply(DurableRuntimeConfig, :create_pending, args)

    assert_receive {:randomized_vault_encrypt, _pid}

    Application.put_env(
      :tamandua_server,
      :email_runtime_idempotency_hmac_active_key_version,
      2
    )

    assert {:ok,
            replay_receipt = %{replayed: true, operation_id: ^operation_id, status: "pending"}} =
             apply(DurableRuntimeConfig, :create_pending, args)

    assert Map.delete(first_receipt, :replayed) == Map.delete(replay_receipt, :replayed)

    refute_receive {:randomized_vault_encrypt, _pid}, 50

    changed_args = List.replace_at(args, 3, %{client_secret: "different-secret"})

    assert {:error, :idempotency_conflict} =
             apply(DurableRuntimeConfig, :create_pending, changed_args)

    refute_receive {:randomized_vault_encrypt, _pid}, 50

    %{2 => key_two} =
      Application.fetch_env!(:tamandua_server, :email_runtime_idempotency_hmac_test_keys)
      |> Map.take([2])

    Application.put_env(:tamandua_server, :email_runtime_idempotency_hmac_test_keys, %{
      2 => key_two
    })

    assert {:error, :idempotency_key_unavailable} =
             apply(DurableRuntimeConfig, :create_pending, args)

    refute_receive {:randomized_vault_encrypt, _pid}, 50

    assert {:ok, _aborted} =
             DurableRuntimeConfig.abort_pending(
               org.id,
               :microsoft365,
               operation_id,
               "retry-owner",
               "operator_cancelled"
             )

    Application.put_env(:tamandua_server, :email_runtime_idempotency_hmac_test_keys, %{
      2 => :crypto.strong_rand_bytes(129)
    })

    oversized_key_args =
      args
      |> List.replace_at(4,
        owner_id: "oversized-key-owner",
        expected_revision: 0,
        operation_id: Ecto.UUID.generate()
      )

    assert {:error, :idempotency_key_unavailable} =
             apply(DurableRuntimeConfig, :create_pending, oversized_key_args)

    refute_receive {:randomized_vault_encrypt, _pid}, 50

    Application.put_env(:tamandua_server, :email_runtime_idempotency_hmac_test_keys, %{
      2 => :crypto.strong_rand_bytes(32)
    })

    Application.put_env(
      :tamandua_server,
      :email_runtime_allow_test_fingerprint_key_backend,
      false
    )

    assert {:error, :idempotency_key_unavailable} =
             apply(DurableRuntimeConfig, :create_pending, oversized_key_args)

    refute_receive {:randomized_vault_encrypt, _pid}, 50
  end

  test "outer transactions fail closed before create or commit calls Vault", %{organization: org} do
    assert {:ok, pending} =
             DurableRuntimeConfig.create_pending(
               org.id,
               :microsoft365,
               m365_public(),
               %{client_secret: "outer-transaction-secret"},
               owner_id: "outer-owner",
               expected_revision: 0
             )

    Application.put_env(
      :tamandua_server,
      :email_runtime_test_secrets_backend,
      MustNotBeCalledVault
    )

    Application.put_env(:tamandua_server, :email_runtime_allow_test_outer_transaction, false)

    assert {:error, :outer_transaction_not_supported} =
             DurableRuntimeConfig.create_pending(
               org.id,
               :google_workspace,
               google_public(),
               google_secret("outer"),
               owner_id: "outer-owner",
               expected_revision: 0
             )

    assert {:error, :outer_transaction_not_supported} =
             DurableRuntimeConfig.commit_pending(
               org.id,
               :microsoft365,
               pending.operation_id,
               "outer-owner"
             )
  end

  test "HMAC version churn exhausts a bounded retry budget without Vault", %{organization: org} do
    Application.put_env(:tamandua_server, :email_runtime_idempotency_hmac_test_keys, %{
      1 => :crypto.strong_rand_bytes(32),
      2 => :crypto.strong_rand_bytes(32),
      3 => :crypto.strong_rand_bytes(32),
      4 => :crypto.strong_rand_bytes(32)
    })

    Application.put_env(
      :tamandua_server,
      :email_runtime_test_fingerprint_key_backend,
      ChurningFingerprintKeyBackend
    )

    Application.put_env(:tamandua_server, :email_runtime_fingerprint_key_observer, self())

    Application.put_env(
      :tamandua_server,
      :email_runtime_test_secrets_backend,
      MustNotBeCalledVault
    )

    assert {:error, :idempotency_retry_exhausted} =
             DurableRuntimeConfig.create_pending(
               org.id,
               :microsoft365,
               m365_public(),
               %{client_secret: "bounded-churn-secret"},
               owner_id: "bounded-churn-owner",
               expected_revision: 0,
               operation_id: Ecto.UUID.generate()
             )

    assert_receive {:churning_fingerprint_key_fetch, 1}
    assert_receive {:churning_fingerprint_key_fetch, 2}
    assert_receive {:churning_fingerprint_key_fetch, 3}
    refute_receive {:churning_fingerprint_key_fetch, _version}, 50
  end

  test "KV HMAC key contract fails closed for ambiguous and oversized envelopes", %{
    organization: org
  } do
    Application.put_env(
      :tamandua_server,
      :email_runtime_test_fingerprint_key_backend,
      KVContractFingerprintKeyBackend
    )

    raw = :crypto.strong_rand_bytes(32)

    Application.put_env(:tamandua_server, :email_runtime_fingerprint_kv_fixture, %{
      "value_b64" => Base.encode64(raw)
    })

    assert {:ok, pending} =
             DurableRuntimeConfig.create_pending(
               org.id,
               :microsoft365,
               m365_public(),
               %{client_secret: "kv-contract-secret"},
               owner_id: "kv-contract-owner",
               expected_revision: 0
             )

    assert {:ok, _aborted} =
             DurableRuntimeConfig.abort_pending(
               org.id,
               :microsoft365,
               pending.operation_id,
               "kv-contract-owner",
               "operator_cancelled"
             )

    Application.put_env(
      :tamandua_server,
      :email_runtime_test_secrets_backend,
      MustNotBeCalledVault
    )

    invalid_values = [
      raw,
      %{"value" => Base.encode64(raw)},
      %{"value_b64" => Base.encode64(raw), "extra" => true},
      %{"value_b64" => "not-base64%%%"},
      %{"value_b64" => String.trim_trailing(Base.encode64(raw), "=")},
      %{"value_b64" => Base.encode64(raw) <> "\n"},
      %{"value_b64" => Base.encode64(raw) <> "="},
      %{"value_b64" => Base.url_encode64(:binary.copy(<<255>>, 32))},
      %{"value_b64" => String.slice(Base.encode64(:binary.copy(<<0>>, 32)), 0, 42) <> "B="},
      %{"value_b64" => Base.encode64(:crypto.strong_rand_bytes(31))},
      %{"value_b64" => Base.encode64(:crypto.strong_rand_bytes(129))}
    ]

    Enum.each(invalid_values, fn invalid ->
      Application.put_env(
        :tamandua_server,
        :email_runtime_fingerprint_kv_fixture,
        invalid
      )

      assert {:error, :idempotency_key_unavailable} =
               DurableRuntimeConfig.create_pending(
                 org.id,
                 :microsoft365,
                 m365_public(),
                 %{client_secret: "must-not-reach-vault"},
                 owner_id: "kv-invalid-owner",
                 expected_revision: 0,
                 operation_id: Ecto.UUID.generate()
               )
    end)
  end

  test "terminal commit and abort retries do not call Vault", %{organization: org} do
    assert {:ok, pending} =
             DurableRuntimeConfig.create_pending(
               org.id,
               :microsoft365,
               m365_public(),
               %{client_secret: "terminal-replay-secret"},
               owner_id: "terminal-owner",
               expected_revision: 0,
               operation_id: Ecto.UUID.generate()
             )

    assert {:ok, committed_receipt = %{status: "committed", replayed: false}} =
             DurableRuntimeConfig.commit_pending(
               org.id,
               :microsoft365,
               pending.operation_id,
               "terminal-owner"
             )

    Application.put_env(:tamandua_server, :email_runtime_test_secrets_backend, UnhealthyVault)

    assert {:ok, committed_replay = %{status: "committed", replayed: true}} =
             DurableRuntimeConfig.commit_pending(
               org.id,
               :microsoft365,
               pending.operation_id,
               "terminal-owner"
             )

    assert Map.delete(committed_receipt, :replayed) == Map.delete(committed_replay, :replayed)

    Application.put_env(:tamandua_server, :email_runtime_test_secrets_backend, FakeVault)

    assert {:ok, abortable} =
             DurableRuntimeConfig.create_pending(
               org.id,
               :microsoft365,
               m365_public(%{client_id: "next-client"}),
               %{client_secret: "abort-replay-secret"},
               owner_id: "abort-owner",
               expected_revision: 1,
               operation_id: Ecto.UUID.generate()
             )

    assert {:ok, aborted_receipt = %{status: "aborted", replayed: false}} =
             DurableRuntimeConfig.abort_pending(
               org.id,
               :microsoft365,
               abortable.operation_id,
               "abort-owner",
               "operator_cancelled"
             )

    assert {:ok, aborted_replay = %{status: "aborted", replayed: true}} =
             DurableRuntimeConfig.abort_pending(
               org.id,
               :microsoft365,
               abortable.operation_id,
               "abort-owner",
               "operator_cancelled"
             )

    assert Map.delete(aborted_receipt, :replayed) == Map.delete(aborted_replay, :replayed)

    assert {:error, :abort_reason_conflict} =
             DurableRuntimeConfig.abort_pending(
               org.id,
               :microsoft365,
               abortable.operation_id,
               "abort-owner",
               "different_reason"
             )
  end

  test "ciphertext digest corruption fails before Vault health or decrypt", %{organization: org} do
    operation_id = Ecto.UUID.generate()
    lease_expires_at = DateTime.add(DateTime.utc_now(), 30, :second)

    MultiTenant.with_organization(org.id, fn ->
      Repo.transaction(fn ->
        head =
          %DurableRuntimeConfigHead{}
          |> DurableRuntimeConfigHead.create_changeset(%{
            organization_id: org.id,
            provider: "microsoft365"
          })
          |> Repo.insert!()

        ciphertext = "vault:v7:" <> Base.url_encode64("corrupted", padding: false)

        %DurableRuntimeConfigVersion{}
        |> DurableRuntimeConfigVersion.pending_changeset(%{
          head_id: head.id,
          organization_id: org.id,
          provider: "microsoft365",
          revision: 1,
          base_revision: 0,
          public_config: m365_public(),
          secret_ciphertext: ciphertext,
          vault_key_name: "email-runtime-config",
          vault_ciphertext_version: 7,
          secret_schema_version: 2,
          operation_id: operation_id,
          created_by: "integrity-owner",
          lease_expires_at: lease_expires_at,
          request_fingerprint: :crypto.strong_rand_bytes(32),
          request_fingerprint_key_version: 1,
          ciphertext_sha256: :crypto.strong_rand_bytes(32)
        })
        |> Repo.insert!()

        head
        |> DurableRuntimeConfigHead.pending_changeset(%{
          pending_revision: 1,
          pending_operation_id: operation_id,
          pending_owner_id: "integrity-owner",
          pending_expires_at: lease_expires_at
        })
        |> Repo.update!()
      end)
    end)

    Application.put_env(:tamandua_server, :email_runtime_test_secrets_backend, UnhealthyVault)

    assert {:error, :ciphertext_integrity_mismatch} =
             DurableRuntimeConfig.commit_pending(
               org.id,
               :microsoft365,
               operation_id,
               "integrity-owner"
             )

    MultiTenant.with_organization(org.id, fn ->
      Repo.transaction(fn ->
        version = Repo.get_by!(DurableRuntimeConfigVersion, operation_id: operation_id)

        version
        |> DurableRuntimeConfigVersion.lifecycle_changeset(%{
          status: "committed",
          committed_at: DateTime.utc_now()
        })
        |> Repo.update!()

        Repo.get_by!(DurableRuntimeConfigHead,
          organization_id: org.id,
          provider: "microsoft365"
        )
        |> Ecto.Changeset.change(%{
          committed_revision: 1,
          pending_revision: nil,
          pending_operation_id: nil,
          pending_owner_id: nil,
          pending_expires_at: nil,
          apply_status: "pending"
        })
        |> Repo.update!()
      end)
    end)

    assert {:error, :ciphertext_integrity_mismatch} =
             DurableRuntimeConfig.commit_pending(
               org.id,
               :microsoft365,
               operation_id,
               "integrity-owner"
             )
  end

  test "deferred pending consistency rejects orphan ledger and divergent head", %{
    organization: org
  } do
    assert_raise Postgrex.Error, fn ->
      MultiTenant.with_organization(org.id, fn ->
        Repo.transaction(fn ->
          {_head, _version, _expires_at} = insert_raw_pending!(org, "microsoft365")
          Repo.query!("SET CONSTRAINTS email_config_version_pending_consistency IMMEDIATE")
        end)
      end)
    end

    assert_raise Postgrex.Error, fn ->
      MultiTenant.with_organization(org.id, fn ->
        Repo.transaction(fn ->
          {head, version, expires_at} = insert_raw_pending!(org, "microsoft365")

          head
          |> DurableRuntimeConfigHead.pending_changeset(%{
            pending_revision: version.revision,
            pending_operation_id: version.operation_id,
            pending_owner_id: "divergent-owner",
            pending_expires_at: expires_at
          })
          |> Repo.update!()

          Repo.query!("SET CONSTRAINTS email_config_head_pending_consistency IMMEDIATE")
        end)
      end)
    end

    assert_raise Postgrex.Error, fn ->
      MultiTenant.with_organization(org.id, fn ->
        Repo.transaction(fn ->
          {head, version, expires_at} = insert_raw_pending!(org, "microsoft365")

          head =
            head
            |> DurableRuntimeConfigHead.pending_changeset(%{
              pending_revision: version.revision,
              pending_operation_id: version.operation_id,
              pending_owner_id: version.created_by,
              pending_expires_at: expires_at
            })
            |> Repo.update!()

          head
          |> Ecto.Changeset.change(%{
            pending_revision: nil,
            pending_operation_id: nil,
            pending_owner_id: nil,
            pending_expires_at: nil
          })
          |> Repo.update!()

          Repo.query!("SET CONSTRAINTS email_config_head_pending_consistency IMMEDIATE")
        end)
      end)
    end
  end

  test "database exact-key contract rejects extra public keys", %{organization: org} do
    candidates = [
      {"microsoft365", Map.put(m365_public(), "extra", "rejected")},
      {"google_workspace", Map.put(google_public(), "extra", "rejected")}
    ]

    Enum.each(candidates, fn {provider, public_config} ->
      assert_raise Postgrex.Error, fn ->
        MultiTenant.with_organization(org.id, fn ->
          Repo.transaction(fn -> insert_raw_pending!(org, provider, public_config) end)
        end)
      end
    end)
  end

  test "deferred committed consistency rejects bogus head and supersede-only transition", %{
    organization: org
  } do
    assert_raise Postgrex.Error, fn ->
      MultiTenant.with_organization(org.id, fn ->
        Repo.transaction(fn ->
          head =
            %DurableRuntimeConfigHead{}
            |> DurableRuntimeConfigHead.create_changeset(%{
              organization_id: org.id,
              provider: "microsoft365"
            })
            |> Repo.insert!()

          head
          |> Ecto.Changeset.change(committed_revision: 99)
          |> Repo.update!()

          Repo.query!("SET CONSTRAINTS email_config_head_pending_consistency IMMEDIATE")
        end)
      end)
    end

    assert_raise Postgrex.Error, fn ->
      MultiTenant.with_organization(org.id, fn ->
        Repo.transaction(fn ->
          {_head, version, _expires_at} = insert_raw_pending!(org, "microsoft365")

          version
          |> DurableRuntimeConfigVersion.lifecycle_changeset(%{
            status: "committed",
            committed_at: DateTime.utc_now()
          })
          |> Repo.update!()

          Repo.query!("SET CONSTRAINTS email_config_version_pending_consistency IMMEDIATE")
        end)
      end)
    end

    assert {:ok, pending} =
             DurableRuntimeConfig.create_pending(
               org.id,
               :microsoft365,
               m365_public(),
               %{client_secret: "committed-linkage-secret"},
               owner_id: "committed-linkage-owner",
               expected_revision: 0
             )

    assert {:ok, %{status: "committed"}} =
             DurableRuntimeConfig.commit_pending(
               org.id,
               :microsoft365,
               pending.operation_id,
               "committed-linkage-owner"
             )

    assert_raise Postgrex.Error, fn ->
      MultiTenant.with_organization(org.id, fn ->
        Repo.transaction(fn ->
          Repo.get_by!(DurableRuntimeConfigVersion, operation_id: pending.operation_id)
          |> DurableRuntimeConfigVersion.lifecycle_changeset(%{
            status: "superseded",
            committed_at: DateTime.utc_now()
          })
          |> Repo.update!()

          Repo.query!("SET CONSTRAINTS email_config_version_pending_consistency IMMEDIATE")
        end)
      end)
    end
  end

  test "deferred consistency ignores pg_temp relation shadows", %{organization: org} do
    {head, version, expires_at} =
      MultiTenant.with_organization(org.id, fn ->
        Repo.transaction(fn ->
          {head, version, expires_at} = insert_raw_pending!(org, "microsoft365")

          head
          |> DurableRuntimeConfigHead.pending_changeset(%{
            pending_revision: version.revision,
            pending_operation_id: version.operation_id,
            pending_owner_id: version.created_by,
            pending_expires_at: expires_at
          })
          |> Repo.update!()

          {head, version, expires_at}
        end)
        |> then(fn {:ok, value} -> value end)
      end)

    assert_raise Postgrex.Error, fn ->
      MultiTenant.with_organization(org.id, fn ->
        Repo.transaction(fn ->
          Repo.query!("""
          CREATE TEMP TABLE email_integration_config_heads
          (LIKE public.email_integration_config_heads INCLUDING DEFAULTS)
          ON COMMIT DROP
          """)

          Repo.query!("""
          CREATE TEMP TABLE email_integration_config_versions
          (LIKE public.email_integration_config_versions INCLUDING DEFAULTS)
          ON COMMIT DROP
          """)

          assert %{rows: [[shadow_head, shadow_version]]} =
                   Repo.query!("""
                   SELECT
                     to_regclass('pg_temp.email_integration_config_heads') IS NOT NULL,
                     to_regclass('pg_temp.email_integration_config_versions') IS NOT NULL
                   """)

          assert shadow_head and shadow_version

          Repo.query!(
            """
            UPDATE public.email_integration_config_heads
            SET pending_revision = NULL,
                pending_operation_id = NULL,
                pending_owner_id = NULL,
                pending_expires_at = NULL
            WHERE id = $1 AND organization_id = $2 AND provider = $3
            """,
            [head.id, org.id, "microsoft365"]
          )

          assert version.operation_id
          assert expires_at
          Repo.query!("SET CONSTRAINTS email_config_head_pending_consistency IMMEDIATE")
        end)
      end)
    end
  end

  test "pending then commit advances durable desired state without plaintext", %{
    organization: org
  } do
    sentinel = " \tpg-sentinel-secret-do-not-store\n"

    assert {:ok, pending} =
             DurableRuntimeConfig.create_pending(
               org.id,
               :microsoft365,
               m365_public(%{tenant_id: "tenant-a"}),
               %{client_secret: sentinel},
               owner_id: "pg-test",
               expected_revision: 0
             )

    version =
      MultiTenant.with_organization(org.id, fn ->
        Repo.get_by!(DurableRuntimeConfigVersion, operation_id: pending.operation_id)
      end)

    refute version.secret_ciphertext =~ sentinel
    refute inspect(version) =~ sentinel
    refute Jason.encode!(version.public_config) =~ sentinel

    assert "vault:v7:" <> encoded_envelope = version.secret_ciphertext
    assert {:ok, envelope_json} = Base.url_decode64(encoded_envelope, padding: false)
    assert {:ok, envelope} = Jason.decode(envelope_json)
    assert envelope["schema_version"] == 2
    assert envelope["operation_id"] == pending.operation_id
    assert envelope["secret_config"]["client_secret"] == sentinel
    assert is_binary(envelope["snapshot_sha256"])

    assert {:ok, %{status: "committed", revision: 1}} =
             DurableRuntimeConfig.commit_pending(
               org.id,
               :microsoft365,
               pending.operation_id,
               "pg-test"
             )
  end

  if System.get_env("TAMANDUA_EMAIL_DURABLE_DISPOSABLE_PG_TESTS") != "true" do
    @tag skip:
           "set TAMANDUA_EMAIL_DURABLE_DISPOSABLE_PG_TESTS=true only for an isolated disposable PostgreSQL database"
  end

  test "same tenant/provider expected revision is CAS serialized on independent sessions" do
    organization =
      Task.async(fn -> Sandbox.unboxed_run(Repo, fn -> insert(:organization) end) end)
      |> Task.await(10_000)

    coordinator = self()
    barrier_ref = make_ref()

    Application.put_env(
      :tamandua_server,
      :email_runtime_test_secrets_backend,
      BarrierVault
    )

    Application.put_env(
      :tamandua_server,
      :email_runtime_cas_barrier,
      {coordinator, barrier_ref}
    )

    tasks =
      Enum.map(1..2, fn number ->
        Task.async(fn ->
          Sandbox.unboxed_run(Repo, fn ->
            Repo.checkout(fn ->
              %{rows: [[backend_pid]]} = Repo.query!("SELECT pg_backend_pid()")
              send(coordinator, {:cas_backend_ready, barrier_ref, self(), backend_pid})

              receive do
                {:start_cas, ^barrier_ref} -> :ok
              after
                10_000 -> raise "CAS start barrier timed out"
              end

              result =
                DurableRuntimeConfig.create_pending(
                  organization.id,
                  :google_workspace,
                  google_public(%{poll_interval_ms: 10_000 + number}),
                  google_secret(number),
                  owner_id: "concurrent-#{number}",
                  expected_revision: 0
                )

              {backend_pid, result}
            end)
          end)
        end)
      end)

    ready_sessions = collect_cas_workers(:cas_backend_ready, barrier_ref, 2)
    backend_pids = Enum.map(ready_sessions, fn {_worker, backend_pid} -> backend_pid end)
    assert length(Enum.uniq(backend_pids)) == 2

    Enum.each(ready_sessions, fn {worker, _backend_pid} ->
      send(worker, {:start_cas, barrier_ref})
    end)

    encrypt_workers = collect_cas_workers(:cas_encrypt_ready, barrier_ref, 2)

    Enum.each(encrypt_workers, fn {worker, _unused} ->
      send(worker, {:release_cas_encrypt, barrier_ref})
    end)

    results = Enum.map(tasks, &Task.await(&1, 20_000))

    assert Enum.sort(Enum.map(results, fn {backend_pid, _result} -> backend_pid end)) ==
             Enum.sort(backend_pids)

    results = Enum.map(results, fn {_backend_pid, result} -> result end)

    assert Enum.count(results, &match?({:ok, _}, &1)) == 1

    assert Enum.count(
             results,
             &match?(
               {:error, reason}
               when reason in [
                      :pending_operation_active,
                      :revision_conflict,
                      :ledger_revision_conflict
                    ],
               &1
             )
           ) == 1
  end

  test "same operation converges across sessions when active HMAC rotates between preflights" do
    organization =
      Task.async(fn -> Sandbox.unboxed_run(Repo, fn -> insert(:organization) end) end)
      |> Task.await(10_000)

    operation_id = Ecto.UUID.generate()
    coordinator = self()
    barrier_ref = make_ref()

    Application.put_env(:tamandua_server, :email_runtime_test_secrets_backend, BarrierVault)
    Application.put_env(:tamandua_server, :email_runtime_cas_barrier, {coordinator, barrier_ref})

    Application.put_env(
      :tamandua_server,
      :email_runtime_test_fingerprint_key_backend,
      ObservingFingerprintKeyBackend
    )

    Application.put_env(:tamandua_server, :email_runtime_fingerprint_key_observer, self())

    start_worker = fn ->
      Task.async(fn ->
        Sandbox.unboxed_run(Repo, fn ->
          Repo.checkout(fn ->
            %{rows: [[backend_pid]]} = Repo.query!("SELECT pg_backend_pid()")

            result =
              DurableRuntimeConfig.create_pending(
                organization.id,
                :microsoft365,
                m365_public(),
                %{client_secret: "same-operation-race-secret"},
                owner_id: "same-operation-owner",
                expected_revision: 0,
                operation_id: operation_id
              )

            {backend_pid, result}
          end)
        end)
      end)
    end

    first = start_worker.()
    assert_receive {:fingerprint_key_fetch, 1, false}, 10_000
    [{first_encrypt_worker, _}] = collect_cas_workers(:cas_encrypt_ready, barrier_ref, 1)

    Application.put_env(
      :tamandua_server,
      :email_runtime_idempotency_hmac_active_key_version,
      2
    )

    second = start_worker.()
    assert_receive {:fingerprint_key_fetch, 2, false}, 10_000
    [{second_encrypt_worker, _}] = collect_cas_workers(:cas_encrypt_ready, barrier_ref, 1)

    send(first_encrypt_worker, {:release_cas_encrypt, barrier_ref})
    send(second_encrypt_worker, {:release_cas_encrypt, barrier_ref})

    results = [Task.await(first, 20_000), Task.await(second, 20_000)]
    assert length(Enum.uniq(Enum.map(results, &elem(&1, 0)))) == 2

    receipts = Enum.map(results, fn {_backend_pid, {:ok, receipt}} -> receipt end)
    assert Enum.sort(Enum.map(receipts, & &1.replayed)) == [false, true]
    assert receipts |> Enum.map(&Map.delete(&1, :replayed)) |> Enum.uniq() |> length() == 1
    refute_receive {:fingerprint_key_fetch, _version, true}, 100

    MultiTenant.with_organization(organization.id, fn ->
      assert Repo.aggregate(
               from(version in DurableRuntimeConfigVersion,
                 where:
                   version.organization_id == ^organization.id and
                     version.provider == "microsoft365" and
                     version.operation_id == ^operation_id
               ),
               :count
             ) == 1

      head =
        Repo.get_by!(DurableRuntimeConfigHead,
          organization_id: organization.id,
          provider: "microsoft365"
        )

      assert head.pending_operation_id == operation_id
    end)
  end

  test "commit versus abort is serialized across independent sessions" do
    organization =
      Task.async(fn -> Sandbox.unboxed_run(Repo, fn -> insert(:organization) end) end)
      |> Task.await(10_000)

    {:ok, pending} =
      Task.async(fn ->
        Sandbox.unboxed_run(Repo, fn ->
          Repo.checkout(fn ->
            DurableRuntimeConfig.create_pending(
              organization.id,
              :microsoft365,
              m365_public(),
              %{client_secret: "terminal-race-secret"},
              owner_id: "terminal-race-owner",
              expected_revision: 0
            )
          end)
        end)
      end)
      |> Task.await(20_000)

    coordinator = self()
    race_ref = make_ref()

    operations = [
      fn ->
        DurableRuntimeConfig.commit_pending(
          organization.id,
          :microsoft365,
          pending.operation_id,
          "terminal-race-owner"
        )
      end,
      fn ->
        DurableRuntimeConfig.abort_pending(
          organization.id,
          :microsoft365,
          pending.operation_id,
          "terminal-race-owner",
          "operator_cancelled"
        )
      end
    ]

    tasks =
      Enum.map(operations, fn operation ->
        Task.async(fn ->
          Sandbox.unboxed_run(Repo, fn ->
            Repo.checkout(fn ->
              %{rows: [[backend_pid]]} = Repo.query!("SELECT pg_backend_pid()")
              send(coordinator, {:terminal_race_ready, race_ref, self(), backend_pid})

              receive do
                {:start_terminal_race, ^race_ref} -> operation.()
              after
                10_000 -> raise "terminal race start timed out"
              end
            end)
          end)
        end)
      end)

    workers = collect_cas_workers(:terminal_race_ready, race_ref, 2)
    assert length(Enum.uniq(Enum.map(workers, fn {_worker, pid} -> pid end))) == 2
    Enum.each(workers, fn {worker, _pid} -> send(worker, {:start_terminal_race, race_ref}) end)

    results = Enum.map(tasks, &Task.await(&1, 20_000))
    assert Enum.count(results, &match?({:ok, _receipt}, &1)) == 1

    assert Enum.count(
             results,
             &match?(
               {:error, reason}
               when reason in [:operation_aborted, :operation_already_committed],
               &1
             )
           ) == 1
  end

  test "two commits converge through the terminal second-stage branch" do
    organization =
      Task.async(fn -> Sandbox.unboxed_run(Repo, fn -> insert(:organization) end) end)
      |> Task.await(10_000)

    {:ok, pending} =
      Task.async(fn ->
        Sandbox.unboxed_run(Repo, fn ->
          Repo.checkout(fn ->
            DurableRuntimeConfig.create_pending(
              organization.id,
              :microsoft365,
              m365_public(),
              %{client_secret: "two-commit-race-secret"},
              owner_id: "two-commit-owner",
              expected_revision: 0
            )
          end)
        end)
      end)
      |> Task.await(20_000)

    coordinator = self()
    barrier_ref = make_ref()

    Application.put_env(
      :tamandua_server,
      :email_runtime_test_secrets_backend,
      BarrierDecryptVault
    )

    Application.put_env(:tamandua_server, :email_runtime_cas_barrier, {coordinator, barrier_ref})

    tasks =
      Enum.map(1..2, fn _index ->
        Task.async(fn ->
          Sandbox.unboxed_run(Repo, fn ->
            Repo.checkout(fn ->
              DurableRuntimeConfig.commit_pending(
                organization.id,
                :microsoft365,
                pending.operation_id,
                "two-commit-owner"
              )
            end)
          end)
        end)
      end)

    decrypt_workers = collect_cas_workers(:commit_decrypt_ready, barrier_ref, 2)

    Enum.each(decrypt_workers, fn {worker, _unused} ->
      send(worker, {:release_commit_decrypt, barrier_ref})
    end)

    receipts =
      Enum.map(tasks, fn task ->
        assert {:ok, receipt} = Task.await(task, 20_000)
        receipt
      end)

    assert Enum.sort(Enum.map(receipts, & &1.replayed)) == [false, true]
    assert receipts |> Enum.map(&Map.delete(&1, :replayed)) |> Enum.uniq() |> length() == 1
  end

  test "lifecycle timestamps and reasons are database-owned and committed time is preserved", %{
    organization: org
  } do
    arbitrary_past = ~U[2000-01-01 00:00:00.000000Z]

    assert {:ok, first} =
             DurableRuntimeConfig.create_pending(
               org.id,
               :microsoft365,
               m365_public(),
               %{client_secret: "first-lifecycle-secret"},
               owner_id: "lifecycle-owner",
               expected_revision: 0
             )

    first_version =
      MultiTenant.with_organization(org.id, fn ->
        Repo.transaction(fn ->
          version =
            Repo.get_by!(DurableRuntimeConfigVersion, operation_id: first.operation_id)
            |> DurableRuntimeConfigVersion.lifecycle_changeset(%{
              status: "committed",
              committed_at: arbitrary_past,
              aborted_at: arbitrary_past,
              abort_reason_code: "must_be_cleared"
            })
            |> Repo.update!()

          Repo.get_by!(DurableRuntimeConfigHead,
            organization_id: org.id,
            provider: "microsoft365"
          )
          |> Ecto.Changeset.change(%{
            committed_revision: version.revision,
            pending_revision: nil,
            pending_operation_id: nil,
            pending_owner_id: nil,
            pending_expires_at: nil,
            apply_status: "pending"
          })
          |> Repo.update!()

          Repo.query!("SET CONSTRAINTS ALL IMMEDIATE")
          version
        end)
        |> then(fn {:ok, version} -> version end)
      end)

    assert DateTime.compare(first_version.committed_at, first_version.inserted_at) in [:eq, :gt]
    refute first_version.committed_at == arbitrary_past
    assert first_version.updated_at == first_version.committed_at
    assert is_nil(first_version.aborted_at)
    assert is_nil(first_version.abort_reason_code)

    assert {:ok, aborted} =
             DurableRuntimeConfig.create_pending(
               org.id,
               :google_workspace,
               google_public(),
               google_secret("abort-lifecycle"),
               owner_id: "abort-lifecycle-owner",
               expected_revision: 0
             )

    aborted_version =
      MultiTenant.with_organization(org.id, fn ->
        Repo.transaction(fn ->
          version =
            Repo.get_by!(DurableRuntimeConfigVersion, operation_id: aborted.operation_id)
            |> DurableRuntimeConfigVersion.lifecycle_changeset(%{
              status: "aborted",
              committed_at: arbitrary_past,
              aborted_at: arbitrary_past,
              abort_reason_code: "operator_cancelled"
            })
            |> Repo.update!()

          Repo.get_by!(DurableRuntimeConfigHead,
            organization_id: org.id,
            provider: "google_workspace"
          )
          |> Ecto.Changeset.change(%{
            pending_revision: nil,
            pending_operation_id: nil,
            pending_owner_id: nil,
            pending_expires_at: nil
          })
          |> Repo.update!()

          Repo.query!("SET CONSTRAINTS ALL IMMEDIATE")
          version
        end)
        |> then(fn {:ok, version} -> version end)
      end)

    assert DateTime.compare(aborted_version.aborted_at, aborted_version.inserted_at) in [:eq, :gt]
    refute aborted_version.aborted_at == arbitrary_past
    assert aborted_version.updated_at == aborted_version.aborted_at
    assert is_nil(aborted_version.committed_at)
    assert aborted_version.abort_reason_code == "operator_cancelled"

    assert {:ok, replacement} =
             DurableRuntimeConfig.create_pending(
               org.id,
               :microsoft365,
               m365_public(%{client_id: "replacement-client"}),
               %{client_secret: "replacement-lifecycle-secret"},
               owner_id: "lifecycle-owner",
               expected_revision: 1
             )

    assert {:ok, %{status: "committed"}} =
             DurableRuntimeConfig.commit_pending(
               org.id,
               :microsoft365,
               replacement.operation_id,
               "lifecycle-owner"
             )

    superseded_version =
      MultiTenant.with_organization(org.id, fn ->
        Repo.get_by!(DurableRuntimeConfigVersion, operation_id: first.operation_id)
      end)

    assert superseded_version.committed_at == first_version.committed_at
    assert DateTime.compare(superseded_version.updated_at, first_version.updated_at) in [:eq, :gt]
    refute superseded_version.updated_at == arbitrary_past
    assert is_nil(superseded_version.aborted_at)
    assert is_nil(superseded_version.abort_reason_code)
  end

  test "inserted_at is immutable", %{organization: org} do
    assert {:ok, pending} =
             DurableRuntimeConfig.create_pending(
               org.id,
               :microsoft365,
               m365_public(),
               %{client_secret: "immutable-inserted-at-secret"},
               owner_id: "immutable-owner",
               expected_revision: 0
             )

    assert_raise Postgrex.Error, fn ->
      MultiTenant.with_organization(org.id, fn ->
        Repo.get_by!(DurableRuntimeConfigVersion, operation_id: pending.operation_id)
        |> Ecto.Changeset.change(inserted_at: ~U[2000-01-01 00:00:00.000000Z])
        |> Repo.update!()
      end)
    end
  end

  test "aborted lifecycle rejects non-canonical reason codes", %{organization: org} do
    assert {:ok, pending} =
             DurableRuntimeConfig.create_pending(
               org.id,
               :microsoft365,
               m365_public(),
               %{client_secret: "invalid-reason-secret"},
               owner_id: "invalid-reason-owner",
               expected_revision: 0
             )

    assert_raise Postgrex.Error, fn ->
      MultiTenant.with_organization(org.id, fn ->
        Repo.get_by!(DurableRuntimeConfigVersion, operation_id: pending.operation_id)
        |> DurableRuntimeConfigVersion.lifecycle_changeset(%{
          status: "aborted",
          aborted_at: ~U[2000-01-01 00:00:00.000000Z],
          abort_reason_code: "not canonical"
        })
        |> Repo.update!()
      end)
    end
  end

  test "committed lifecycle state cannot be inserted directly", %{organization: org} do
    assert_terminal_insert_rejected(org, %{
      status: "committed",
      committed_at: ~U[2000-01-01 00:00:00.000000Z],
      aborted_at: nil,
      abort_reason_code: nil
    })
  end

  test "superseded lifecycle state cannot be inserted directly", %{organization: org} do
    assert_terminal_insert_rejected(org, %{
      status: "superseded",
      committed_at: ~U[2000-01-01 00:00:00.000000Z],
      aborted_at: nil,
      abort_reason_code: nil
    })
  end

  test "aborted lifecycle state cannot be inserted directly", %{organization: org} do
    assert_terminal_insert_rejected(org, %{
      status: "aborted",
      committed_at: nil,
      aborted_at: ~U[2000-01-01 00:00:00.000000Z],
      abort_reason_code: "operator_cancelled"
    })
  end

  test "aborted and expired revisions are never reused", %{organization: org} do
    assert {:ok, first} =
             DurableRuntimeConfig.create_pending(
               org.id,
               :microsoft365,
               m365_public(),
               %{client_secret: "first-secret"},
               owner_id: "abort-owner",
               expected_revision: 0
             )

    assert first.revision == 1

    assert {:ok, _head} =
             DurableRuntimeConfig.abort_pending(
               org.id,
               :microsoft365,
               first.operation_id,
               "abort-owner",
               "operator_cancelled"
             )

    assert {:ok, second} =
             DurableRuntimeConfig.create_pending(
               org.id,
               :microsoft365,
               m365_public(),
               %{client_secret: "second-secret"},
               owner_id: "expiry-owner",
               expected_revision: 0,
               lease_seconds: 5
             )

    assert second.revision == 2

    MultiTenant.with_organization(org.id, fn -> Repo.query!("SELECT pg_sleep(5.1)") end)

    for _attempt <- 1..2 do
      assert {:error, :pending_lease_expired} =
               DurableRuntimeConfig.commit_pending(
                 org.id,
                 :microsoft365,
                 second.operation_id,
                 "expiry-owner"
               )
    end

    assert {:ok, third} =
             DurableRuntimeConfig.create_pending(
               org.id,
               :microsoft365,
               m365_public(),
               %{client_secret: "third-secret"},
               owner_id: "retry-owner",
               expected_revision: 0
             )

    assert third.revision == 3

    statuses =
      MultiTenant.with_organization(org.id, fn ->
        from(version in DurableRuntimeConfigVersion,
          where: version.organization_id == ^org.id and version.provider == "microsoft365",
          order_by: version.revision,
          select: {version.revision, version.status}
        )
        |> Repo.all()
      end)

    assert statuses == [{1, "aborted"}, {2, "aborted"}, {3, "pending"}]
  end

  test "RLS hides heads and versions from another organization", %{organization: org} do
    other = insert(:organization)

    assert {:ok, pending} =
             DurableRuntimeConfig.create_pending(
               org.id,
               :microsoft365,
               m365_public(),
               %{client_secret: "tenant-a-only"},
               owner_id: "rls-test",
               expected_revision: 0
             )

    assert MultiTenant.with_organization(other.id, fn ->
             Repo.get_by(DurableRuntimeConfigVersion, operation_id: pending.operation_id)
           end) == nil

    assert MultiTenant.with_organization(other.id, fn ->
             Repo.get_by(DurableRuntimeConfigHead,
               organization_id: org.id,
               provider: "microsoft365"
             )
           end) == nil
  end

  test "ciphertext envelope cannot be committed under a different binding", %{organization: org} do
    assert {:ok, pending} =
             DurableRuntimeConfig.create_pending(
               org.id,
               :google_workspace,
               google_public(),
               google_secret("binding"),
               owner_id: "binding-test",
               expected_revision: 0
             )

    Application.put_env(
      :tamandua_server,
      :email_runtime_test_secrets_backend,
      SwappedEnvelopeVault
    )

    assert {:error, :secret_envelope_binding_mismatch} =
             DurableRuntimeConfig.commit_pending(
               org.id,
               :google_workspace,
               pending.operation_id,
               "binding-test"
             )

    Application.put_env(
      :tamandua_server,
      :email_runtime_test_secrets_backend,
      SwappedOperationVault
    )

    assert {:error, :secret_envelope_binding_mismatch} =
             DurableRuntimeConfig.commit_pending(
               org.id,
               :google_workspace,
               pending.operation_id,
               "binding-test"
             )

    assert {:ok, %{configured: false, committed_revision: 0}} =
             DurableRuntimeConfig.committed_metadata(org.id, :google_workspace)
  end

  test "unhealthy Vault fails closed before creating a pending head", %{organization: org} do
    Application.put_env(
      :tamandua_server,
      :email_runtime_test_secrets_backend,
      UnhealthyVault
    )

    assert {:error, :vault_transit_unavailable} =
             DurableRuntimeConfig.create_pending(
               org.id,
               :microsoft365,
               m365_public(),
               %{client_secret: "must-never-reach-db"},
               owner_id: "vault-health-test",
               expected_revision: 0
             )

    assert MultiTenant.with_organization(org.id, fn ->
             Repo.get_by(DurableRuntimeConfigHead,
               organization_id: org.id,
               provider: "microsoft365"
             )
           end) == nil
  end

  test "partial Vault health without authenticated true fails closed", %{organization: org} do
    Application.put_env(
      :tamandua_server,
      :email_runtime_test_secrets_backend,
      PartialHealthVault
    )

    assert {:error, :vault_transit_unavailable} =
             DurableRuntimeConfig.create_pending(
               org.id,
               :google_workspace,
               google_public(),
               google_secret("partial-health"),
               owner_id: "partial-health-test",
               expected_revision: 0
             )
  end

  test "composite head scope rejects cross-head versions and head deletion", %{
    organization: org
  } do
    assert {:ok, pending} =
             DurableRuntimeConfig.create_pending(
               org.id,
               :microsoft365,
               m365_public(),
               %{client_secret: "retained-secret"},
               owner_id: "composite-test",
               expected_revision: 0
             )

    m365_head =
      MultiTenant.with_organization(org.id, fn ->
        Repo.get_by!(DurableRuntimeConfigHead,
          organization_id: org.id,
          provider: "microsoft365"
        )
      end)

    assert {:error, changeset} =
             MultiTenant.with_organization(org.id, fn ->
               %DurableRuntimeConfigVersion{}
               |> DurableRuntimeConfigVersion.pending_changeset(%{
                 head_id: m365_head.id,
                 organization_id: org.id,
                 provider: "google_workspace",
                 revision: 1,
                 public_config: google_public(),
                 secret_ciphertext: "vault:v7:cross-head",
                 vault_key_name: "email-runtime-config",
                 vault_ciphertext_version: 7,
                 secret_schema_version: 2,
                 operation_id: Ecto.UUID.generate(),
                 created_by: "composite-test"
               })
               |> Repo.insert()
             end)

    assert "does not exist" in errors_on(changeset).head_id

    assert_raise Ecto.ConstraintError, fn ->
      MultiTenant.with_organization(org.id, fn -> Repo.delete!(m365_head) end)
    end

    assert MultiTenant.with_organization(org.id, fn ->
             Repo.get_by!(DurableRuntimeConfigVersion, operation_id: pending.operation_id)
           end)
  end

  test "catalog has forced RLS and notification definition contains no config columns" do
    assert %{rows: rows} =
             Repo.query!("""
             SELECT relname, relrowsecurity, relforcerowsecurity
             FROM pg_class
             WHERE relname IN (
               'email_integration_config_heads',
               'email_integration_config_versions'
             )
             ORDER BY relname
             """)

    assert Enum.all?(rows, fn [_name, rls, force] -> rls and force end)

    assert %{rows: [[definition]]} =
             Repo.query!("""
             SELECT pg_get_functiondef('notify_email_runtime_config_head()'::regprocedure)
             """)

    refute definition =~ "secret_ciphertext"
    refute definition =~ "public_config"
    refute definition =~ "pending_operation_id"
    refute definition =~ "organization_id"
    refute definition =~ "provider"
    refute definition =~ "revision"
    assert definition =~ "pg_notify('tamandua_email_runtime_config'::text, 'changed'::text)"

    assert %{rows: [[trigger_definition]]} =
             Repo.query!("""
             SELECT pg_get_triggerdef(oid)
             FROM pg_trigger
             WHERE tgname = 'email_runtime_config_head_notify'
             """)

    assert trigger_definition =~
             "UPDATE OF committed_revision, applied_revision, apply_status"

    refute trigger_definition =~ "INSERT"
    assert trigger_definition =~ "OLD.committed_revision IS DISTINCT FROM NEW.committed_revision"

    assert %{rows: delete_rules} =
             Repo.query!("""
             SELECT conname, confdeltype
             FROM pg_constraint
             WHERE conname IN (
               'email_config_versions_head_scope_fkey',
               'email_integration_config_heads_organization_id_fkey',
               'email_integration_config_versions_organization_id_fkey'
             )
             ORDER BY conname
             """)

    assert length(delete_rules) == 3
    assert Enum.all?(delete_rules, fn [_name, delete_rule] -> delete_rule == "r" end)
  end

  defp collect_cas_workers(event, barrier_ref, count) do
    Enum.map(1..count, fn _index ->
      receive do
        {^event, ^barrier_ref, worker, backend_pid} -> {worker, backend_pid}
        {^event, ^barrier_ref, worker} -> {worker, nil}
      after
        10_000 -> flunk("timed out waiting for #{event}")
      end
    end)
  end

  defp insert_raw_pending!(organization, provider, public_config \\ nil) do
    head =
      %DurableRuntimeConfigHead{}
      |> DurableRuntimeConfigHead.create_changeset(%{
        organization_id: organization.id,
        provider: provider
      })
      |> Repo.insert!()

    ciphertext = "vault:v7:" <> Base.url_encode64("pending-consistency", padding: false)
    expires_at = DateTime.add(DateTime.utc_now(), 60, :second)

    version =
      %DurableRuntimeConfigVersion{}
      |> DurableRuntimeConfigVersion.pending_changeset(%{
        head_id: head.id,
        organization_id: organization.id,
        provider: provider,
        revision: 1,
        base_revision: 0,
        public_config: public_config || m365_public(),
        secret_ciphertext: ciphertext,
        vault_key_name: "email-runtime-config",
        vault_ciphertext_version: 7,
        secret_schema_version: 2,
        operation_id: Ecto.UUID.generate(),
        created_by: "ledger-owner",
        lease_expires_at: expires_at,
        request_fingerprint: :crypto.strong_rand_bytes(32),
        request_fingerprint_key_version: 1,
        ciphertext_sha256: :crypto.hash(:sha256, ciphertext)
      })
      |> Repo.insert!()

    {head, version, expires_at}
  end

  defp m365_public(overrides \\ %{}) do
    Map.merge(
      %{
        "tenant_id" => "tenant-id",
        "client_id" => "client-id",
        "poll_interval_ms" => 60_000,
        "enabled" => true
      },
      string_key_overrides(overrides)
    )
  end

  defp google_public(overrides \\ %{}) do
    Map.merge(
      %{
        "admin_email" => "admin@example.test",
        "poll_interval_ms" => 60_000,
        "enabled" => true
      },
      string_key_overrides(overrides)
    )
  end

  defp google_secret(suffix) do
    private_key =
      Process.get({__MODULE__, :google_rsa_private_key}) ||
        generate_google_rsa_private_key()

    %{
      "client_email" => "service-#{suffix}@example.test",
      "private_key" => private_key
    }
  end

  defp generate_google_rsa_private_key do
    private_key = :public_key.generate_key({:rsa, 2_048, 65_537})

    pem =
      :RSAPrivateKey
      |> :public_key.pem_entry_encode(private_key)
      |> then(&:public_key.pem_encode([&1]))

    Process.put({__MODULE__, :google_rsa_private_key}, pem)
    pem
  end

  defp string_key_overrides(overrides) do
    Map.new(overrides, fn {key, value} -> {to_string(key), value} end)
  end

  defp assert_terminal_insert_rejected(org, lifecycle) do
    assert {:ok, _pending} =
             DurableRuntimeConfig.create_pending(
               org.id,
               :microsoft365,
               m365_public(),
               %{client_secret: "terminal-insert-guard-secret"},
               owner_id: "terminal-insert-owner",
               expected_revision: 0
             )

    head =
      MultiTenant.with_organization(org.id, fn ->
        Repo.get_by!(DurableRuntimeConfigHead,
          organization_id: org.id,
          provider: "microsoft365"
        )
      end)

    assert_raise Postgrex.Error, fn ->
      MultiTenant.with_organization(org.id, fn ->
        %DurableRuntimeConfigVersion{}
        |> Ecto.Changeset.change(
          Map.merge(lifecycle, %{
            head_id: head.id,
            organization_id: org.id,
            provider: "microsoft365",
            revision: 100,
            public_config: m365_public(),
            secret_ciphertext: "vault:v7:terminal-insert",
            vault_key_name: "email-runtime-config",
            vault_ciphertext_version: 7,
            secret_schema_version: 2,
            operation_id: Ecto.UUID.generate(),
            created_by: "terminal-insert-owner"
          })
        )
        |> Repo.insert!()
      end)
    end
  end
end
