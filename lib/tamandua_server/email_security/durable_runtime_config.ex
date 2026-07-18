defmodule TamanduaServer.EmailSecurity.DurableRuntimeConfig do
  @moduledoc """
  Default-off PostgreSQL desired-state staging for email integrations.

  This module does not start or reload providers. A committed revision is
  durable desired state only; runtime reconciliation is a separate slice.

  Caller-provided operation IDs support response-loss replay. Request identity
  is bound by a governed, versioned HMAC; raw secret hashes are never stored.
  Historical keys at `email-runtime/idempotency-hmac/vN` must remain available
  for the full ledger retention horizon. Removing one fails closed with
  `:idempotency_key_unavailable`; retention and key retirement are one gate.
  Each path contains exactly `%{"value_b64" => "<canonical standard Base64>"}`;
  raw Manager values are rejected so provider fallbacks cannot silently change
  the governed key contract.
  """

  import Ecto.Query

  alias TamanduaServer.EmailSecurity.{
    DurableRuntimeConfigHead,
    DurableRuntimeConfigVersion
  }

  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant

  @vault_key_name "email-runtime-config"
  @secret_schema_version 2
  @minimum_lease_seconds 5
  @maximum_lease_seconds 300
  @maximum_public_config_bytes 16_384
  @maximum_client_secret_bytes 16_384
  @maximum_google_private_key_bytes 65_536
  @maximum_secret_envelope_bytes 1_048_576
  @maximum_ciphertext_bytes 2_097_152
  @providers ~w(microsoft365 google_workspace)
  @public_config_keys %{
    "microsoft365" => MapSet.new(~w(tenant_id client_id poll_interval_ms enabled)),
    "google_workspace" => MapSet.new(~w(admin_email poll_interval_ms enabled))
  }
  @lock_domain "tamandua:email-runtime-config:v1"
  @request_fingerprint_domain "tamandua.email-runtime-config.request.v1"

  defmodule SecretsBackend do
    @moduledoc false

    @callback health() :: {:ok, map()} | {:error, term()}
    @callback encrypt(String.t(), binary()) :: {:ok, String.t()} | {:error, term()}
    @callback decrypt(String.t(), String.t()) :: {:ok, binary()} | {:error, term()}
  end

  defmodule ManagerSecretsBackend do
    @moduledoc false
    @behaviour SecretsBackend

    alias TamanduaServer.Secrets.Manager

    @impl true
    def health, do: Manager.health()

    @impl true
    def encrypt(key_name, plaintext), do: Manager.encrypt(plaintext, key_name)

    @impl true
    def decrypt(key_name, ciphertext), do: Manager.decrypt(ciphertext, key_name)
  end

  defmodule FingerprintKeyBackend do
    @moduledoc false
    @callback fetch(pos_integer()) :: {:ok, binary()} | {:error, term()}
  end

  defmodule VaultFingerprintKeyBackend do
    @moduledoc false
    @behaviour FingerprintKeyBackend

    alias TamanduaServer.Secrets.VaultProvider

    @impl true
    def fetch(version) when is_integer(version) and version > 0 do
      with {:ok, value} <- VaultProvider.get_secret("email-runtime/idempotency-hmac/v#{version}") do
        normalize(value)
      end
    end

    def fetch(_version), do: {:error, :invalid_key_version}

    def normalize(%{"value_b64" => encoded} = envelope)
        when map_size(envelope) == 1 and is_binary(encoded) and byte_size(encoded) >= 44 and
               byte_size(encoded) <= 172 do
      with {:ok, decoded} <- Base.decode64(encoded, padding: true),
           true <- byte_size(decoded) >= 32 and byte_size(decoded) <= 128,
           true <- Base.encode64(decoded) == encoded do
        {:ok, decoded}
      else
        _other -> {:error, :invalid_key_encoding}
      end
    end

    def normalize(_value), do: {:error, :invalid_key_contract}
  end

  defmodule TestMapFingerprintKeyBackend do
    @moduledoc false
    @behaviour FingerprintKeyBackend

    @impl true
    def fetch(version) when is_integer(version) and version > 0 do
      with {:ok, keys} <-
             Application.fetch_env(:tamandua_server, :email_runtime_idempotency_hmac_test_keys),
           true <- is_map(keys),
           {:ok, key} <- Map.fetch(keys, version) do
        {:ok, key}
      else
        _other -> {:error, :key_unavailable}
      end
    end

    def fetch(_version), do: {:error, :invalid_key_version}
  end

  @spec enabled?() :: boolean()
  def enabled? do
    Application.get_env(:tamandua_server, :email_runtime_persistence_enabled, false) == true
  end

  @doc """
  Creates one leased pending revision using revision-bound Vault Transit ciphertext.

  `public_config` and `secret_config` are complete candidate maps. This initial
  slice intentionally does not merge partial secrets or mutate any provider.
  """
  def create_pending(
        organization_id,
        provider,
        public_config,
        secret_config,
        opts \\ []
      ) do
    with :ok <- require_enabled(),
         :ok <- require_top_level_transaction(),
         {:ok, organization_id} <- canonical_uuid(organization_id),
         {:ok, provider} <- canonical_provider(provider),
         {:ok, public_config, secret_config} <-
           normalize_candidate_maps(provider, public_config, secret_config),
         {:ok, owner_id} <- required_identifier(opts, :owner_id),
         {:ok, lease_seconds} <- lease_seconds(opts),
         {:ok, expected_revision} <- expected_revision_option(opts),
         operation_id <- Keyword.get_lazy(opts, :operation_id, &Ecto.UUID.generate/0),
         {:ok, operation_id} <- canonical_uuid(operation_id),
         {:ok, preparation} <-
           prepare_create_unlocked(
             organization_id,
             provider,
             expected_revision,
             public_config,
             secret_config,
             operation_id,
             owner_id,
             lease_seconds,
             0
           ) do
      complete_create(preparation)
    end
  end

  @doc """
  Commits a pending revision after decrypting and validating its bound envelope.
  """
  def commit_pending(organization_id, provider, operation_id, owner_id) do
    with :ok <- require_enabled(),
         :ok <- require_top_level_transaction(),
         {:ok, organization_id} <- canonical_uuid(organization_id),
         {:ok, provider} <- canonical_provider(provider),
         {:ok, operation_id} <- canonical_uuid(operation_id),
         {:ok, owner_id} <- canonical_identifier(owner_id),
         {:ok, preparation} <-
           prepare_commit(organization_id, provider, operation_id, owner_id) do
      complete_commit(preparation, organization_id, provider, operation_id, owner_id)
    end
  end

  @doc """
  Aborts a matching pending operation. The committed revision is never changed.
  """
  def abort_pending(organization_id, provider, operation_id, owner_id, reason_code) do
    with :ok <- require_enabled(),
         {:ok, organization_id} <- canonical_uuid(organization_id),
         {:ok, provider} <- canonical_provider(provider),
         {:ok, operation_id} <- canonical_uuid(operation_id),
         {:ok, owner_id} <- canonical_identifier(owner_id),
         {:ok, reason_code} <- canonical_reason_code(reason_code) do
      tenant_transaction(organization_id, fn ->
        with :ok <- acquire_lock(organization_id, provider),
             {:ok, now} <- database_now(),
             %DurableRuntimeConfigVersion{} = version <-
               fetch_operation_for_update(organization_id, provider, operation_id),
             :ok <- validate_operation_owner(version, owner_id) do
          abort_locked(version, reason_code, now)
        else
          nil -> {:error, :operation_not_found}
          {:error, _reason} = error -> error
        end
      end)
      |> unwrap_terminal_error()
    end
  end

  @doc """
  Reads the current committed revision without returning decrypted secret data.
  """
  def committed_metadata(organization_id, provider) do
    if enabled?() do
      committed_metadata_enabled(organization_id, provider)
    else
      {:ok,
       %{
         persistence_enabled: false,
         configured: false,
         committed_revision: 0,
         applied_revision: 0,
         apply_status: "disabled"
       }}
    end
  end

  defp committed_metadata_enabled(organization_id, provider) do
    with {:ok, organization_id} <- canonical_uuid(organization_id),
         {:ok, provider} <- canonical_provider(provider) do
      tenant_transaction(organization_id, fn ->
        case Repo.one(
               from(head in DurableRuntimeConfigHead,
                 where: head.organization_id == ^organization_id and head.provider == ^provider
               )
             ) do
          nil ->
            {:ok,
             %{
               persistence_enabled: true,
               configured: false,
               committed_revision: 0,
               applied_revision: 0,
               apply_status: "never_applied"
             }}

          head ->
            {:ok,
             %{
               persistence_enabled: true,
               configured: head.committed_revision > 0,
               committed_revision: head.committed_revision,
               applied_revision: head.applied_revision,
               apply_status: head.apply_status
             }}
        end
      end)
    end
  end

  defp prepare_create_unlocked(
         organization_id,
         provider,
         expected_revision,
         public_config,
         secret_config,
         operation_id,
         owner_id,
         lease_seconds,
         attempt
       )
       when attempt < 3 do
    with {:ok, {key_version, base_revision}} <-
           fingerprint_material(
             organization_id,
             provider,
             operation_id,
             expected_revision
           ),
         {:ok, key} <- fingerprint_key(key_version),
         {:ok, fingerprint} <-
           request_fingerprint(
             key,
             organization_id,
             provider,
             operation_id,
             owner_id,
             base_revision,
             lease_seconds,
             public_config,
             secret_config
           ),
         {:ok, preparation} <-
           prepare_create(
             organization_id,
             provider,
             expected_revision,
             public_config,
             secret_config,
             operation_id,
             owner_id,
             lease_seconds,
             key_version,
             base_revision,
             fingerprint,
             attempt
           ) do
      case preparation do
        :retry ->
          prepare_create_unlocked(
            organization_id,
            provider,
            expected_revision,
            public_config,
            secret_config,
            operation_id,
            owner_id,
            lease_seconds,
            attempt + 1
          )

        ready ->
          {:ok, ready}
      end
    end
  end

  defp prepare_create_unlocked(
         _organization_id,
         _provider,
         _expected_revision,
         _public_config,
         _secret_config,
         _operation_id,
         _owner_id,
         _lease_seconds,
         _attempt
       ),
       do: {:error, :idempotency_retry_exhausted}

  defp prepare_create(
         organization_id,
         provider,
         expected_revision,
         public_config,
         secret_config,
         operation_id,
         owner_id,
         lease_seconds,
         candidate_key_version,
         candidate_base_revision,
         candidate_fingerprint,
         attempt
       ) do
    tenant_transaction(organization_id, fn ->
      with :ok <- acquire_lock(organization_id, provider),
           {:ok, now} <- database_now(),
           existing <- fetch_operation_for_update(organization_id, provider, operation_id) do
        case existing do
          %DurableRuntimeConfigVersion{} = version ->
            with {:ok, base_revision} <- replay_base_revision(version, expected_revision) do
              if version.request_fingerprint_key_version == candidate_key_version and
                   base_revision == candidate_base_revision do
                with :ok <-
                       validate_create_replay(version, owner_id, candidate_fingerprint),
                     {:ok, version} <- materialize_expired_version(version, now) do
                  {:ok, {:replay, version_receipt(version, true)}}
                end
              else
                {:ok, :retry}
              end
            end

          nil ->
            with {:ok, head} <- get_or_create_head(organization_id, provider),
                 {:ok, head} <- clear_expired_pending(head, now),
                 {:ok, base_revision} <- new_base_revision(head, expected_revision),
                 :ok <- ensure_no_pending(head),
                 {:ok, revision} <- next_ledger_revision_locked(organization_id, provider),
                 {:ok, key_version} <- active_fingerprint_key_version() do
              if key_version == candidate_key_version and base_revision == candidate_base_revision do
                {:ok,
                 {:encrypt,
                  %{
                    organization_id: organization_id,
                    provider: provider,
                    base_revision: base_revision,
                    revision: revision,
                    public_config: public_config,
                    secret_config: secret_config,
                    operation_id: operation_id,
                    owner_id: owner_id,
                    lease_seconds: lease_seconds,
                    expected_revision: expected_revision,
                    attempt: attempt,
                    request_fingerprint: candidate_fingerprint,
                    request_fingerprint_key_version: key_version
                  }}}
              else
                {:ok, :retry}
              end
            end
        end
      end
    end)
  end

  defp complete_create({:replay, receipt}), do: {:ok, receipt}

  defp complete_create({:encrypt, plan}) do
    backend = secrets_backend()

    with :ok <- require_vault_transit(backend),
         {:ok, ciphertext, vault_version} <-
           encrypt_bound_secret(
             backend,
             plan.organization_id,
             plan.provider,
             plan.revision,
             plan.operation_id,
             plan.public_config,
             plan.secret_config
           ) do
      stage_pending(plan, ciphertext, vault_version)
    end
  end

  defp stage_pending(plan, ciphertext, vault_version) do
    result =
      tenant_transaction(plan.organization_id, fn ->
        with :ok <- acquire_lock(plan.organization_id, plan.provider),
             {:ok, now} <- database_now(),
             existing <-
               fetch_operation_for_update(plan.organization_id, plan.provider, plan.operation_id) do
          case existing do
            %DurableRuntimeConfigVersion{} = version ->
              if version.request_fingerprint_key_version ==
                   plan.request_fingerprint_key_version and
                   version.base_revision == plan.base_revision do
                with :ok <-
                       validate_create_replay(
                         version,
                         plan.owner_id,
                         plan.request_fingerprint
                       ),
                     {:ok, version} <- materialize_expired_version(version, now) do
                  {:ok, version_receipt(version, true)}
                end
              else
                {:ok, :retry}
              end

            nil ->
              with {:ok, head} <- get_or_create_head(plan.organization_id, plan.provider),
                   {:ok, head} <- clear_expired_pending(head, now),
                   :ok <- compare_revision(head, plan.base_revision),
                   :ok <- ensure_no_pending(head),
                   {:ok, locked_revision} <-
                     next_ledger_revision_locked(plan.organization_id, plan.provider),
                   :ok <- compare_ledger_revision(locked_revision, plan.revision),
                   lease_expires_at <- DateTime.add(now, plan.lease_seconds, :second),
                   {:ok, version} <-
                     insert_pending_version(
                       head,
                       plan,
                       ciphertext,
                       vault_version,
                       lease_expires_at
                     ),
                   {:ok, _staged_head} <-
                     set_pending(
                       head,
                       version.revision,
                       plan.operation_id,
                       plan.owner_id,
                       lease_expires_at
                     ) do
                {:ok, version_receipt(version, false)}
              end
          end
        end
      end)

    case result do
      {:ok, :retry} ->
        with {:ok, preparation} <-
               prepare_create_unlocked(
                 plan.organization_id,
                 plan.provider,
                 plan.expected_revision,
                 plan.public_config,
                 plan.secret_config,
                 plan.operation_id,
                 plan.owner_id,
                 plan.lease_seconds,
                 plan.attempt + 1
               ) do
          complete_create(preparation)
        end

      other ->
        other
    end
  end

  defp prepare_commit(organization_id, provider, operation_id, owner_id) do
    tenant_transaction(organization_id, fn ->
      with :ok <- acquire_lock(organization_id, provider),
           {:ok, now} <- database_now(),
           %DurableRuntimeConfigVersion{} = version <-
             fetch_operation_for_update(organization_id, provider, operation_id),
           :ok <- validate_operation_owner(version, owner_id) do
        classify_commit_locked(version, now)
      else
        nil -> {:error, :operation_not_found}
        {:error, _reason} = error -> error
      end
    end)
  end

  defp complete_commit({:terminal, receipt}, _org, _provider, _operation, _owner),
    do: {:ok, receipt}

  defp complete_commit({:terminal_error, reason}, _org, _provider, _operation, _owner),
    do: {:error, reason}

  defp complete_commit({:decrypt, pending}, organization_id, provider, operation_id, owner_id) do
    backend = secrets_backend()

    with :ok <- require_vault_transit(backend),
         :ok <- decrypt_and_validate_bound_secret(backend, pending),
         result <- commit_staged(organization_id, provider, operation_id, owner_id) do
      unwrap_terminal_error(result)
    end
  end

  defp classify_commit_locked(%{status: status} = version, _now)
       when status in ["committed", "superseded"] do
    with :ok <- validate_ciphertext_digest(version) do
      {:ok, {:terminal, version_receipt(version, true)}}
    end
  end

  defp classify_commit_locked(
         %{status: "aborted", abort_reason_code: "lease_expired"} = version,
         _now
       ) do
    with :ok <- validate_ciphertext_digest(version) do
      {:ok, {:terminal_error, :pending_lease_expired}}
    end
  end

  defp classify_commit_locked(%{status: "aborted"} = version, _now) do
    with :ok <- validate_ciphertext_digest(version) do
      {:ok, {:terminal_error, :operation_aborted}}
    end
  end

  defp classify_commit_locked(%{status: "pending"} = version, now) do
    with {:ok, head} <- fetch_head_for_update(version.organization_id, version.provider),
         :ok <- match_pending(head, version.operation_id, version.created_by) do
      if DateTime.compare(version.lease_expires_at, now) == :gt do
        case validate_ciphertext_digest(version) do
          :ok -> {:ok, {:decrypt, version}}
          {:error, _reason} = error -> error
        end
      else
        with {:ok, _aborted} <- materialize_expired_version(version, now) do
          {:ok, {:terminal_error, :pending_lease_expired}}
        end
      end
    end
  end

  defp commit_staged(organization_id, provider, operation_id, owner_id) do
    tenant_transaction(organization_id, fn ->
      with :ok <- acquire_lock(organization_id, provider),
           {:ok, now} <- database_now(),
           %DurableRuntimeConfigVersion{} = version <-
             fetch_operation_for_update(organization_id, provider, operation_id),
           :ok <- validate_operation_owner(version, owner_id) do
        case version.status do
          status when status in ["committed", "superseded"] ->
            with :ok <- validate_ciphertext_digest(version) do
              {:ok, version_receipt(version, true)}
            end

          "aborted" ->
            classify_commit_locked(version, now)

          "pending" ->
            commit_pending_locked(version, now)
        end
      else
        nil -> {:error, :operation_not_found}
        {:error, _reason} = error -> error
      end
    end)
  end

  defp commit_pending_locked(version, now) do
    with {:ok, head} <- fetch_head_for_update(version.organization_id, version.provider),
         :ok <- match_pending(head, version.operation_id, version.created_by) do
      if DateTime.compare(version.lease_expires_at, now) == :gt do
        with :ok <- validate_ciphertext_digest(version),
             :ok <-
               supersede_current(
                 version.organization_id,
                 version.provider,
                 head.committed_revision,
                 now
               ),
             {:ok, committed} <-
               commit_version(
                 version.organization_id,
                 version.provider,
                 head.id,
                 version.revision,
                 version.operation_id,
                 now
               ),
             {:ok, _committed_head} <- clear_pending(head, committed.revision, "pending") do
          {:ok, version_receipt(committed, false)}
        end
      else
        with {:ok, _aborted} <- materialize_expired_version(version, now) do
          {:ok, {:terminal_error, :pending_lease_expired}}
        end
      end
    end
  end

  defp expected_revision_option(opts) do
    case Keyword.fetch(opts, :expected_revision) do
      {:ok, revision} when is_integer(revision) and revision >= 0 ->
        {:ok, {:provided, revision}}

      {:ok, _invalid} ->
        {:error, :invalid_expected_revision}

      :error ->
        {:ok, :automatic}
    end
  end

  defp next_ledger_revision_locked(organization_id, provider) do
    latest =
      Repo.one(
        from(version in DurableRuntimeConfigVersion,
          where: version.organization_id == ^organization_id and version.provider == ^provider,
          select: max(version.revision)
        )
      ) || 0

    {:ok, latest + 1}
  end

  defp fingerprint_material(organization_id, provider, operation_id, expected_revision) do
    tenant_transaction(organization_id, fn ->
      case Repo.one(
             from(version in DurableRuntimeConfigVersion,
               where:
                 version.organization_id == ^organization_id and
                   version.provider == ^provider and version.operation_id == ^operation_id,
               select: {version.request_fingerprint_key_version, version.base_revision}
             )
           ) do
        {key_version, base_revision} ->
          {:ok, {key_version, base_revision}}

        nil ->
          base_revision =
            case expected_revision do
              {:provided, revision} ->
                revision

              :automatic ->
                Repo.one(
                  from(head in DurableRuntimeConfigHead,
                    where:
                      head.organization_id == ^organization_id and head.provider == ^provider,
                    select: head.committed_revision
                  )
                ) || 0
            end

          with {:ok, key_version} <- active_fingerprint_key_version() do
            {:ok, {key_version, base_revision}}
          end
      end
    end)
  end

  defp fetch_operation_for_update(organization_id, provider, operation_id) do
    Repo.one(
      from(version in DurableRuntimeConfigVersion,
        where:
          version.organization_id == ^organization_id and version.provider == ^provider and
            version.operation_id == ^operation_id,
        lock: "FOR UPDATE"
      )
    )
  end

  defp replay_base_revision(version, :automatic), do: {:ok, version.base_revision}

  defp replay_base_revision(version, {:provided, base_revision}) do
    if version.base_revision == base_revision,
      do: {:ok, base_revision},
      else: {:error, :idempotency_conflict}
  end

  defp new_base_revision(head, :automatic), do: {:ok, head.committed_revision}

  defp new_base_revision(head, {:provided, base_revision}) do
    case compare_revision(head, base_revision) do
      :ok -> {:ok, base_revision}
      {:error, _reason} = error -> error
    end
  end

  defp validate_create_replay(version, owner_id, fingerprint) do
    if version.created_by == owner_id and
         secure_digest_equal?(version.request_fingerprint, fingerprint) do
      validate_ciphertext_digest(version)
    else
      {:error, :idempotency_conflict}
    end
  end

  defp materialize_expired_version(%{status: "pending"} = version, now) do
    if DateTime.compare(version.lease_expires_at, now) == :gt do
      {:ok, version}
    else
      with {:ok, head} <- fetch_head_for_update(version.organization_id, version.provider),
           :ok <- match_pending(head, version.operation_id, version.created_by),
           {:ok, aborted} <-
             abort_version(
               version.organization_id,
               version.provider,
               version.head_id,
               version.revision,
               version.operation_id,
               "lease_expired",
               now
             ),
           {:ok, _head} <- clear_pending(head, head.committed_revision, head.apply_status) do
        {:ok, aborted}
      end
    end
  end

  defp materialize_expired_version(version, _now), do: {:ok, version}

  defp abort_locked(%{status: "pending"} = version, reason_code, now) do
    with {:ok, head} <- fetch_head_for_update(version.organization_id, version.provider),
         :ok <- match_pending(head, version.operation_id, version.created_by) do
      if DateTime.compare(version.lease_expires_at, now) == :gt do
        with {:ok, aborted} <-
               abort_version(
                 version.organization_id,
                 version.provider,
                 version.head_id,
                 version.revision,
                 version.operation_id,
                 reason_code,
                 now
               ),
             {:ok, _head} <- clear_pending(head, head.committed_revision, head.apply_status) do
          {:ok, version_receipt(aborted, false)}
        end
      else
        with {:ok, _aborted} <- materialize_expired_version(version, now) do
          {:ok, {:terminal_error, :pending_lease_expired}}
        end
      end
    end
  end

  defp abort_locked(
         %{status: "aborted", abort_reason_code: "lease_expired"} = version,
         _reason,
         _now
       ) do
    with :ok <- validate_ciphertext_digest(version) do
      {:ok, {:terminal_error, :pending_lease_expired}}
    end
  end

  defp abort_locked(%{status: "aborted"} = version, reason_code, _now) do
    with :ok <- validate_ciphertext_digest(version) do
      if version.abort_reason_code == reason_code,
        do: {:ok, version_receipt(version, true)},
        else: {:ok, {:terminal_error, :abort_reason_conflict}}
    end
  end

  defp abort_locked(%{status: status} = version, _reason_code, _now)
       when status in ["committed", "superseded"] do
    with :ok <- validate_ciphertext_digest(version) do
      {:ok, {:terminal_error, :operation_already_committed}}
    end
  end

  defp validate_operation_owner(version, owner_id) do
    if version.created_by == owner_id,
      do: :ok,
      else: {:error, :operation_conflict}
  end

  defp validate_ciphertext_digest(version) do
    digest = :crypto.hash(:sha256, version.secret_ciphertext)

    if secure_digest_equal?(version.ciphertext_sha256, digest),
      do: :ok,
      else: {:error, :ciphertext_integrity_mismatch}
  end

  defp unwrap_terminal_error({:ok, {:terminal_error, reason}}), do: {:error, reason}
  defp unwrap_terminal_error(result), do: result

  defp version_receipt(version, replayed) do
    %{
      operation_id: version.operation_id,
      revision: version.revision,
      status: version.status,
      pending_expires_at: version.lease_expires_at,
      replayed: replayed
    }
  end

  defp get_or_create_head(organization_id, provider) do
    case Repo.one(head_query(organization_id, provider, true)) do
      nil ->
        %DurableRuntimeConfigHead{}
        |> DurableRuntimeConfigHead.create_changeset(%{
          organization_id: organization_id,
          provider: provider
        })
        |> Repo.insert()

      head ->
        {:ok, head}
    end
  end

  defp fetch_head_for_update(organization_id, provider) do
    case Repo.one(head_query(organization_id, provider, true)) do
      nil -> {:error, :integration_not_configured}
      head -> {:ok, head}
    end
  end

  defp head_query(organization_id, provider, for_update?) do
    query =
      from(head in DurableRuntimeConfigHead,
        where: head.organization_id == ^organization_id and head.provider == ^provider
      )

    if for_update?, do: lock(query, "FOR UPDATE"), else: query
  end

  defp insert_pending_version(head, plan, ciphertext, vault_version, lease_expires_at) do
    %DurableRuntimeConfigVersion{}
    |> DurableRuntimeConfigVersion.pending_changeset(%{
      head_id: head.id,
      organization_id: head.organization_id,
      provider: head.provider,
      revision: plan.revision,
      base_revision: plan.base_revision,
      public_config: plan.public_config,
      secret_ciphertext: ciphertext,
      vault_key_name: @vault_key_name,
      vault_ciphertext_version: vault_version,
      secret_schema_version: @secret_schema_version,
      operation_id: plan.operation_id,
      created_by: plan.owner_id,
      lease_expires_at: lease_expires_at,
      request_fingerprint: plan.request_fingerprint,
      request_fingerprint_key_version: plan.request_fingerprint_key_version,
      ciphertext_sha256: :crypto.hash(:sha256, ciphertext)
    })
    |> Repo.insert()
  end

  defp set_pending(head, revision, operation_id, owner_id, expires_at) do
    head
    |> DurableRuntimeConfigHead.pending_changeset(%{
      pending_revision: revision,
      pending_operation_id: operation_id,
      pending_owner_id: owner_id,
      pending_expires_at: expires_at
    })
    |> Repo.update()
  end

  defp clear_pending(head, committed_revision, apply_status) do
    head
    |> Ecto.Changeset.change(%{
      committed_revision: committed_revision,
      pending_revision: nil,
      pending_operation_id: nil,
      pending_owner_id: nil,
      pending_expires_at: nil,
      apply_status: apply_status,
      last_apply_error_code: nil
    })
    |> Repo.update()
  end

  defp clear_expired_pending(%{pending_operation_id: nil} = head, _now), do: {:ok, head}

  defp clear_expired_pending(head, now) do
    if DateTime.compare(head.pending_expires_at, now) == :gt do
      {:ok, head}
    else
      with {:ok, _version} <-
             abort_version(
               head.organization_id,
               head.provider,
               head.id,
               head.pending_revision,
               head.pending_operation_id,
               "lease_expired",
               now
             ),
           {:ok, cleared} <- clear_pending(head, head.committed_revision, head.apply_status) do
        {:ok, cleared}
      end
    end
  end

  defp abort_version(
         organization_id,
         provider,
         head_id,
         revision,
         operation_id,
         reason_code,
         now
       ) do
    case Repo.one(
           from(version in DurableRuntimeConfigVersion,
             where:
               version.organization_id == ^organization_id and version.provider == ^provider and
                 version.head_id == ^head_id and version.revision == ^revision and
                 version.operation_id == ^operation_id and version.status == "pending",
             lock: "FOR UPDATE"
           )
         ) do
      nil ->
        {:error, :pending_operation_not_found}

      version ->
        version
        |> DurableRuntimeConfigVersion.lifecycle_changeset(%{
          status: "aborted",
          aborted_at: now,
          abort_reason_code: reason_code
        })
        |> Repo.update()
    end
  end

  defp supersede_current(organization_id, provider, committed_revision, now) do
    {count, _rows} =
      from(version in DurableRuntimeConfigVersion,
        where:
          version.organization_id == ^organization_id and version.provider == ^provider and
            version.revision == ^committed_revision and version.status == "committed"
      )
      |> Repo.update_all(set: [status: "superseded", updated_at: now])

    expected_count = if committed_revision == 0, do: 0, else: 1

    if count == expected_count,
      do: :ok,
      else: {:error, :committed_revision_ledger_mismatch}
  end

  defp commit_version(organization_id, provider, head_id, revision, operation_id, now) do
    case Repo.one(
           from(version in DurableRuntimeConfigVersion,
             where:
               version.organization_id == ^organization_id and version.provider == ^provider and
                 version.head_id == ^head_id and version.revision == ^revision and
                 version.operation_id == ^operation_id and version.status == "pending",
             lock: "FOR UPDATE"
           )
         ) do
      nil ->
        {:error, :pending_operation_not_found}

      version ->
        version
        |> DurableRuntimeConfigVersion.lifecycle_changeset(%{
          status: "committed",
          committed_at: now
        })
        |> Repo.update()
    end
  end

  defp compare_revision(%{committed_revision: expected}, expected), do: :ok
  defp compare_revision(_head, _expected), do: {:error, :revision_conflict}

  defp compare_ledger_revision(revision, revision), do: :ok
  defp compare_ledger_revision(_locked, _proposed), do: {:error, :ledger_revision_conflict}

  defp ensure_no_pending(%{pending_operation_id: nil}), do: :ok
  defp ensure_no_pending(_head), do: {:error, :pending_operation_active}

  defp match_pending(head, operation_id, owner_id) do
    if head.pending_operation_id == operation_id and head.pending_owner_id == owner_id do
      :ok
    else
      {:error, :pending_operation_mismatch}
    end
  end

  defp encrypt_bound_secret(
         backend,
         organization_id,
         provider,
         revision,
         operation_id,
         public_config,
         secret_config
       ) do
    with {:ok, snapshot_sha256} <- snapshot_digest(provider, public_config, secret_config),
         envelope <- %{
           "schema_version" => @secret_schema_version,
           "organization_id" => organization_id,
           "provider" => provider,
           "revision" => revision,
           "operation_id" => operation_id,
           "snapshot_sha256" => snapshot_sha256,
           "secret_config" => secret_config
         },
         {:ok, envelope} <- encode_bounded(envelope, @maximum_secret_envelope_bytes),
         {:ok, ciphertext} <-
           safe_backend_call(fn -> backend.encrypt(@vault_key_name, envelope) end),
         true <-
           is_binary(ciphertext) and byte_size(ciphertext) <= @maximum_ciphertext_bytes,
         {:ok, vault_version} <- vault_ciphertext_version(ciphertext) do
      {:ok, ciphertext, vault_version}
    else
      false -> {:error, :invalid_vault_ciphertext}
      {:error, :payload_too_large} -> {:error, :secret_config_too_large}
      {:error, :invalid_json} -> {:error, :invalid_secret_config}
      {:error, _reason} = error -> error
    end
  end

  defp decrypt_and_validate_bound_secret(backend, version) do
    with {:ok, plaintext} <-
           safe_backend_call(fn ->
             backend.decrypt(version.vault_key_name, version.secret_ciphertext)
           end),
         true <- is_binary(plaintext) and byte_size(plaintext) <= @maximum_secret_envelope_bytes,
         {:ok, envelope} <- Jason.decode(plaintext),
         true <- envelope["schema_version"] == version.secret_schema_version,
         true <- envelope["organization_id"] == version.organization_id,
         true <- envelope["provider"] == version.provider,
         true <- envelope["revision"] == version.revision,
         true <- envelope["operation_id"] == version.operation_id,
         {:ok, public_config, secret_config} <-
           normalize_candidate_maps(
             version.provider,
             version.public_config,
             envelope["secret_config"]
           ),
         {:ok, snapshot_sha256} <-
           snapshot_digest(version.provider, public_config, secret_config),
         true <- envelope["snapshot_sha256"] == snapshot_sha256 do
      :ok
    else
      false -> {:error, :secret_envelope_binding_mismatch}
      {:error, _reason} -> {:error, :secret_envelope_invalid}
      _other -> {:error, :secret_envelope_invalid}
    end
  end

  defp require_vault_transit(backend) do
    case safe_backend_call(fn -> backend.health() end) do
      {:ok,
       %{
         primary_backend: :vault,
         primary_health: {:ok, %{authenticated: true}}
       }} ->
        :ok

      _other ->
        {:error, :vault_transit_unavailable}
    end
  end

  defp safe_backend_call(fun) do
    fun.()
  rescue
    _error -> {:error, :secrets_backend_unavailable}
  catch
    :exit, _reason -> {:error, :secrets_backend_unavailable}
  end

  defp acquire_lock(organization_id, provider) do
    {key_one, key_two} = lock_keys(organization_id, provider)

    case Repo.query("SELECT pg_advisory_xact_lock($1, $2)", [key_one, key_two]) do
      {:ok, _result} -> :ok
      {:error, _reason} -> {:error, :runtime_config_lock_unavailable}
    end
  end

  defp lock_keys(organization_id, provider) do
    digest =
      :crypto.hash(:sha256, @lock_domain <> <<0>> <> organization_id <> <<0>> <> provider)

    <<key_one::signed-32, key_two::signed-32, _rest::binary>> = digest
    {key_one, key_two}
  end

  defp database_now do
    case Repo.query("SELECT clock_timestamp()") do
      {:ok, %{rows: [[%DateTime{} = now]]}} -> {:ok, now}
      {:ok, %{rows: [[%NaiveDateTime{} = now]]}} -> DateTime.from_naive(now, "Etc/UTC")
      _other -> {:error, :database_clock_unavailable}
    end
  end

  defp tenant_transaction(organization_id, fun) do
    previous_organization_id = Repo.get_organization_id()

    if previous_organization_id != nil and previous_organization_id != organization_id do
      {:error, :nested_organization_context_mismatch}
    else
      Repo.put_organization_id(organization_id)

      try do
        Repo.transaction(fn ->
          case MultiTenant.put_organization_id(organization_id) do
            :ok ->
              case fun.() do
                {:ok, value} -> value
                {:error, reason} -> Repo.rollback(reason)
              end

            {:error, reason} ->
              Repo.rollback({:tenant_context_unavailable, reason})
          end
        end)
        |> case do
          {:ok, value} -> {:ok, value}
          {:error, reason} -> {:error, reason}
        end
      after
        case previous_organization_id do
          nil -> Repo.clear_organization_id()
          previous -> Repo.put_organization_id(previous)
        end
      end
    end
  end

  defp normalize_candidate_maps(provider, public_config, secret_config)
       when is_map(public_config) and is_map(secret_config) and map_size(secret_config) > 0 do
    with {:ok, public_config} <- normalize_top_level_map(public_config),
         {:ok, secret_config} <- normalize_top_level_map(secret_config) do
      allowed_keys = Map.fetch!(@public_config_keys, provider)
      candidate_keys = Map.keys(public_config) |> MapSet.new()

      cond do
        not MapSet.subset?(candidate_keys, allowed_keys) ->
          {:error, :unknown_public_config_key}

        candidate_keys != allowed_keys ->
          {:error, :incomplete_public_config}

        not valid_public_config_values?(provider, public_config) ->
          {:error, :invalid_public_config}

        not json_size_within?(public_config, @maximum_public_config_bytes) ->
          {:error, :invalid_public_config}

        not valid_secret_config?(provider, secret_config) ->
          {:error, :invalid_secret_config}

        true ->
          {:ok, public_config, secret_config}
      end
    end
  end

  defp normalize_candidate_maps(_provider, _public_config, _secret_config),
    do: {:error, :invalid_candidate_config}

  defp valid_public_config_values?("microsoft365", %{
         "tenant_id" => tenant_id,
         "client_id" => client_id,
         "poll_interval_ms" => poll_interval_ms,
         "enabled" => enabled
       }) do
    valid_public_identifier?(tenant_id, 512) and valid_public_identifier?(client_id, 512) and
      valid_poll_interval?(poll_interval_ms) and is_boolean(enabled)
  end

  defp valid_public_config_values?("google_workspace", %{
         "admin_email" => admin_email,
         "poll_interval_ms" => poll_interval_ms,
         "enabled" => enabled
       }) do
    valid_email?(admin_email) and valid_poll_interval?(poll_interval_ms) and is_boolean(enabled)
  end

  defp valid_public_config_values?(_provider, _config), do: false

  defp valid_secret_config?("microsoft365", %{"client_secret" => client_secret} = config)
       when map_size(config) == 1 do
    valid_secret_binary?(client_secret, @maximum_client_secret_bytes)
  end

  defp valid_secret_config?(
         "google_workspace",
         %{"client_email" => client_email, "private_key" => private_key} = config
       )
       when map_size(config) == 2 do
    valid_email?(client_email) and valid_rsa_private_key_pem?(private_key)
  end

  defp valid_secret_config?(_provider, _config), do: false

  defp valid_public_identifier?(value, maximum_bytes) do
    is_binary(value) and byte_size(value) > 0 and byte_size(value) <= maximum_bytes and
      String.valid?(value) and value == String.trim(value)
  end

  defp valid_secret_binary?(value, maximum_bytes) do
    is_binary(value) and byte_size(value) > 0 and byte_size(value) <= maximum_bytes and
      String.valid?(value) and String.trim(value) != ""
  end

  defp valid_email?(value) do
    valid_public_identifier?(value, 320) and
      Regex.match?(~r/^[^\s@]+@[^\s@]+\.[^\s@]+$/, value)
  end

  defp valid_poll_interval?(value),
    do: is_integer(value) and value >= 10_000 and value <= 86_400_000

  defp valid_rsa_private_key_pem?(value) do
    if valid_secret_binary?(value, @maximum_google_private_key_bytes) do
      try do
        case :public_key.pem_decode(value) do
          [entry] ->
            decoded = :public_key.pem_entry_decode(entry)
            valid_rsa_private_key?(decoded)

          _other ->
            false
        end
      rescue
        _error -> false
      catch
        _kind, _reason -> false
      end
    else
      false
    end
  end

  defp valid_rsa_private_key?(decoded) do
    is_tuple(decoded) and tuple_size(decoded) > 2 and elem(decoded, 0) == :RSAPrivateKey and
      is_integer(elem(decoded, 2)) and elem(decoded, 2) >= :erlang.bsl(1, 2_047)
  end

  defp snapshot_digest(provider, public_config, secret_config) do
    canonical = canonical_snapshot(provider, public_config, secret_config)

    case Jason.encode(canonical) do
      {:ok, encoded} ->
        digest =
          encoded
          |> then(&:crypto.hash(:sha256, &1))
          |> Base.url_encode64(padding: false)

        {:ok, digest}

      {:error, _reason} ->
        {:error, :invalid_candidate_config}
    end
  end

  defp active_fingerprint_key_version do
    case Application.fetch_env(
           :tamandua_server,
           :email_runtime_idempotency_hmac_active_key_version
         ) do
      {:ok, version} when is_integer(version) and version > 0 ->
        {:ok, version}

      _other ->
        {:error, :idempotency_key_unavailable}
    end
  end

  defp fingerprint_key(version) when is_integer(version) and version > 0 do
    backend = fingerprint_key_backend()

    with {:ok, key} <- safe_backend_call(fn -> backend.fetch(version) end),
         true <- is_binary(key) and byte_size(key) >= 32 and byte_size(key) <= 128 do
      {:ok, key}
    else
      _other -> {:error, :idempotency_key_unavailable}
    end
  end

  defp fingerprint_key_backend do
    configured =
      Application.get_env(
        :tamandua_server,
        :email_runtime_test_fingerprint_key_backend,
        VaultFingerprintKeyBackend
      )

    test_override? =
      configured != VaultFingerprintKeyBackend and
        Application.get_env(
          :tamandua_server,
          :email_runtime_allow_test_fingerprint_key_backend,
          false
        ) == true and test_mix_environment?()

    if test_override?, do: configured, else: VaultFingerprintKeyBackend
  end

  defp request_fingerprint(
         key,
         organization_id,
         provider,
         operation_id,
         owner_id,
         base_revision,
         lease_seconds,
         public_config,
         secret_config
       ) do
    canonical = [
      ["domain", @request_fingerprint_domain],
      ["organization_id", organization_id],
      ["provider", provider],
      ["operation_id", operation_id],
      ["owner_id", owner_id],
      ["base_revision", base_revision],
      ["lease_seconds", lease_seconds],
      ["public_config", canonical_public_config(provider, public_config)],
      ["secret_config", canonical_secret_config(provider, secret_config)]
    ]

    with {:ok, encoded} <- Jason.encode(canonical) do
      {:ok, :crypto.mac(:hmac, :sha256, key, encoded)}
    else
      _other -> {:error, :invalid_candidate_config}
    end
  end

  defp canonical_public_config("microsoft365", config) do
    [
      ["tenant_id", config["tenant_id"]],
      ["client_id", config["client_id"]],
      ["poll_interval_ms", config["poll_interval_ms"]],
      ["enabled", config["enabled"]]
    ]
  end

  defp canonical_public_config("google_workspace", config) do
    [
      ["admin_email", config["admin_email"]],
      ["poll_interval_ms", config["poll_interval_ms"]],
      ["enabled", config["enabled"]]
    ]
  end

  defp canonical_secret_config("microsoft365", config),
    do: [["client_secret", config["client_secret"]]]

  defp canonical_secret_config("google_workspace", config),
    do: [["client_email", config["client_email"]], ["private_key", config["private_key"]]]

  defp secure_digest_equal?(left, right)
       when is_binary(left) and is_binary(right) and byte_size(left) == 32 and
              byte_size(right) == 32 do
    :crypto.hash_equals(left, right)
  end

  defp secure_digest_equal?(_left, _right), do: false

  defp canonical_snapshot("microsoft365", public_config, secret_config) do
    [
      ["domain", "tamandua.email-runtime-config.snapshot.v2"],
      ["provider", "microsoft365"],
      [
        "public_config",
        canonical_public_config("microsoft365", public_config)
      ],
      ["secret_config", canonical_secret_config("microsoft365", secret_config)]
    ]
  end

  defp canonical_snapshot("google_workspace", public_config, secret_config) do
    [
      ["domain", "tamandua.email-runtime-config.snapshot.v2"],
      ["provider", "google_workspace"],
      [
        "public_config",
        canonical_public_config("google_workspace", public_config)
      ],
      [
        "secret_config",
        canonical_secret_config("google_workspace", secret_config)
      ]
    ]
  end

  defp json_size_within?(value, maximum_bytes) do
    case Jason.encode(value) do
      {:ok, encoded} -> byte_size(encoded) <= maximum_bytes
      {:error, _reason} -> false
    end
  end

  defp encode_bounded(value, maximum_bytes) do
    case Jason.encode(value) do
      {:ok, encoded} when byte_size(encoded) <= maximum_bytes -> {:ok, encoded}
      {:ok, _encoded} -> {:error, :payload_too_large}
      {:error, _reason} -> {:error, :invalid_json}
    end
  end

  defp normalize_top_level_map(map) do
    Enum.reduce_while(map, {:ok, %{}}, fn
      {key, value}, {:ok, normalized} when is_binary(key) or is_atom(key) ->
        key = if is_atom(key), do: Atom.to_string(key), else: key

        if Map.has_key?(normalized, key) do
          {:halt, {:error, :ambiguous_config_key}}
        else
          {:cont, {:ok, Map.put(normalized, key, value)}}
        end

      {_key, _value}, _acc ->
        {:halt, {:error, :invalid_config_key}}
    end)
  end

  defp required_identifier(opts, key) do
    case Keyword.fetch(opts, key) do
      {:ok, value} -> canonical_identifier(value)
      :error -> {:error, {:required_option, key}}
    end
  end

  defp canonical_identifier(value) when is_binary(value) do
    value = String.trim(value)

    if value != "" and byte_size(value) <= 255,
      do: {:ok, value},
      else: {:error, :invalid_identifier}
  end

  defp canonical_identifier(_value), do: {:error, :invalid_identifier}

  defp canonical_reason_code(value) when is_binary(value) do
    value = String.trim(value)

    if Regex.match?(~r/^[a-z0-9_:-]{1,100}$/, value),
      do: {:ok, value},
      else: {:error, :invalid_reason_code}
  end

  defp canonical_reason_code(_value), do: {:error, :invalid_reason_code}

  defp canonical_provider(value) when is_atom(value),
    do: canonical_provider(Atom.to_string(value))

  defp canonical_provider(value) when value in @providers, do: {:ok, value}
  defp canonical_provider(_value), do: {:error, :unsupported_provider}

  defp canonical_uuid(value) do
    case Ecto.UUID.cast(value) do
      {:ok, uuid} -> {:ok, uuid}
      :error -> {:error, :invalid_uuid}
    end
  end

  defp lease_seconds(opts) do
    value = Keyword.get(opts, :lease_seconds, 30)

    if is_integer(value) and value >= @minimum_lease_seconds and value <= @maximum_lease_seconds,
      do: {:ok, value},
      else: {:error, :invalid_lease_seconds}
  end

  defp vault_ciphertext_version(ciphertext) when is_binary(ciphertext) do
    case Regex.run(~r/^vault:v(\d+):/, ciphertext, capture: :all_but_first) do
      [version] -> {:ok, String.to_integer(version)}
      _other -> {:error, :invalid_vault_ciphertext}
    end
  end

  defp vault_ciphertext_version(_ciphertext), do: {:error, :invalid_vault_ciphertext}

  defp secrets_backend do
    configured =
      Application.get_env(
        :tamandua_server,
        :email_runtime_test_secrets_backend,
        ManagerSecretsBackend
      )

    test_override? =
      configured != ManagerSecretsBackend and
        Application.get_env(
          :tamandua_server,
          :email_runtime_allow_test_secrets_backend,
          false
        ) == true and test_mix_environment?()

    if test_override?, do: configured, else: ManagerSecretsBackend
  end

  defp test_mix_environment? do
    Code.ensure_loaded?(Mix) and function_exported?(Mix, :env, 0) and
      apply(Mix, :env, []) == :test
  end

  defp require_enabled do
    if enabled?(), do: :ok, else: {:error, :email_runtime_persistence_disabled}
  end

  defp require_top_level_transaction do
    test_override? =
      Application.get_env(
        :tamandua_server,
        :email_runtime_allow_test_outer_transaction,
        false
      ) == true and test_mix_environment?()

    if Repo.in_transaction?() and not test_override?,
      do: {:error, :outer_transaction_not_supported},
      else: :ok
  end
end
