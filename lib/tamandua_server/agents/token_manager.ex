defmodule TamanduaServer.Agents.TokenManager do
  @moduledoc """
  Manages agent JWT token lifecycle, rotation, and revocation.

  Features:
  - Automatic token generation with configurable TTL
  - Token versioning with generation tracking
  - In-memory revocation list (ETS) for fast validation
  - Audit logging of all token operations
  - Periodic cleanup of expired tokens
  - Replay attack prevention via generation tracking

  ## Security Model

  1. Each agent has a monotonically increasing `token_generation` counter
  2. Only tokens matching the current generation are valid
  3. Old tokens are automatically revoked when a new token is issued
  4. Revoked tokens are cached in ETS for 7 days for forensics
  5. All token operations are audit logged

  ## Configuration

  Token TTL and refresh window are configurable per-agent in the agents table:
  - `token_ttl_hours`: Token lifetime (default: 720 hours / 30 days)
  - `token_refresh_window_percent`: When to allow refresh (default: 60%)
  - `token_rotation_enabled`: Enable/disable rotation per agent
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.Audit
  alias TamanduaServer.Agents.AgentCredential
  alias TamanduaServer.Agents.Credentials
  import Ecto.Query

  @cleanup_interval :timer.hours(1)
  @revocation_cache_ttl_days 7
  @default_token_ttl_hours 720
  @default_refresh_window_percent 60
  @minimum_token_ttl_hours 720
  # Grace period after token expiry during which an agent may still refresh.
  # 7 days balances offline-agent recovery against the window in which a
  # stolen expired token remains usable (previously 30 days, which kept
  # exfiltrated tokens refreshable for a full month past expiry).
  @default_refresh_grace_seconds 7 * 24 * 3600
  @maximum_refresh_grace_seconds 30 * 24 * 3600
  # Refresh counts above this threshold are anomalous for a normally
  # behaving agent (with a 720h TTL and 60% refresh window this represents
  # years of continuous refreshes) and may indicate token abuse.
  @default_refresh_count_warning_threshold 100
  @maximum_jti_reference_input_bytes 255
  @jti_reference_hex_chars 12

  defmodule AgentToken do
    use Ecto.Schema
    import Ecto.Changeset

    @primary_key {:id, :binary_id, autogenerate: true}
    @foreign_key_type :binary_id

    schema "agent_tokens" do
      field(:agent_id, :binary_id)
      field(:token_generation, :integer)
      field(:token_hash, :string)
      field(:issued_at, :utc_datetime_usec)
      field(:expires_at, :utc_datetime_usec)
      field(:last_refreshed_at, :utc_datetime_usec)
      field(:revoked_at, :utc_datetime_usec)
      field(:revocation_reason, :string)
      field(:refresh_count, :integer, default: 0)
      field(:ip_address, :string)
      field(:user_agent, :string)

      timestamps()
    end

    def changeset(token, attrs) do
      token
      |> cast(attrs, [
        :agent_id,
        :token_generation,
        :token_hash,
        :issued_at,
        :expires_at,
        :last_refreshed_at,
        :revoked_at,
        :revocation_reason,
        :refresh_count,
        :ip_address,
        :user_agent
      ])
      |> validate_required([:agent_id, :token_generation, :token_hash, :issued_at, :expires_at])
      |> unique_constraint([:agent_id, :token_generation])
    end
  end

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Generate a new JWT token for an agent.

  The caller must provide the authoritative organization from its already
  validated tenant boundary. Legacy calls without that scope fail closed.

  Returns {:ok, jwt, token_record} or {:error, reason}.
  Automatically revokes previous tokens and increments generation.
  """
  @spec issue_token(String.t()) :: {:error, :organization_scope_required}
  def issue_token(_agent_id), do: {:error, :organization_scope_required}

  @spec issue_token(String.t(), keyword()) :: {:error, :organization_scope_required}
  def issue_token(_agent_id, opts) when is_list(opts),
    do: {:error, :organization_scope_required}

  @spec issue_token(String.t(), String.t()) ::
          {:ok, String.t(), struct()} | {:error, atom()}
  def issue_token(agent_id, organization_id) when is_binary(organization_id),
    do: issue_token(agent_id, organization_id, [])

  def issue_token(_agent_id, _organization_id),
    do: {:error, :organization_scope_required}

  @spec issue_token(String.t(), String.t(), keyword()) ::
          {:ok, String.t(), struct()} | {:error, atom()}
  def issue_token(agent_id, organization_id, opts) when is_list(opts) do
    with {:ok, canonical_agent_id} <- canonical_uuid(agent_id, :invalid_agent_id),
         {:ok, canonical_organization_id} <-
           canonical_uuid(organization_id, :organization_scope_required) do
      GenServer.call(
        __MODULE__,
        {:issue_token, canonical_agent_id, canonical_organization_id, opts}
      )
    end
  end

  @doc false
  def issue_token_in_current_tenant(%TamanduaServer.Agents.Agent{} = agent, opts \\ [])
      when is_list(opts) do
    organization_id = agent.organization_id

    case {Repo.get_organization_id(), Repo.in_transaction?()} do
      {^organization_id, true} ->
        with {:ok, canonical_agent_id} <- canonical_uuid(agent.id, :invalid_agent_id),
             {:ok, canonical_organization_id} <-
               canonical_uuid(organization_id, :organization_scope_required),
             %TamanduaServer.Agents.Agent{} = locked_agent <-
               get_agent_for_issuance(canonical_agent_id, canonical_organization_id) do
          do_issue_locked_agent(locked_agent, opts)
        else
          nil -> {:error, :agent_not_found}
          {:error, _reason} = error -> error
        end

      _other ->
        {:error, :tenant_context_required}
    end
  end

  def issue_token_in_current_tenant(_agent, _opts), do: {:error, :tenant_context_required}

  @doc """
  Refresh an existing token if it's within the refresh window.

  Returns {:ok, new_jwt, new_token_record} or {:error, reason}.
  """
  def refresh_token(current_token, opts \\ []) do
    GenServer.call(__MODULE__, {:refresh_token, current_token, opts})
  end

  @doc """
  Validate a token and check if it's revoked.

  Returns {:ok, claims} or {:error, reason}.
  """
  def validate_token(token) do
    do_validate_token(token)
  rescue
    _error ->
      Logger.error("Token validation failed")
      {:error, :database_error}
  end

  @doc """
  Revalidates an exact agent JWT while the caller already owns the matching
  tenant transaction.

  This helper deliberately does not open a tenant transaction. It locks the
  current agent, token record, and active credential before checking the
  generation, presented-token hash, revocation, and expiry. Callers must keep
  the protected state transition in the same transaction after this returns.
  """
  def validate_token_in_current_tenant(
        token,
        expected_organization_id,
        expected_agent_id,
        expected_generation
      ) do
    with true <- is_binary(token) and byte_size(token) > 0,
         {:ok, expected_organization_id} <-
           canonical_uuid(expected_organization_id, :invalid_claims),
         {:ok, expected_agent_id} <- canonical_uuid(expected_agent_id, :invalid_claims),
         true <- is_integer(expected_generation) and expected_generation > 0,
         ^expected_organization_id <- Repo.get_organization_id(),
         {:ok, claims} <- decode_token(token),
         {:ok, token_agent_id, token_generation, token_organization_id, credential_jti} <-
           extract_token_identity(claims),
         true <- token_agent_id == expected_agent_id,
         true <- token_generation == expected_generation,
         true <- token_organization_id == expected_organization_id,
         {:ok, agent} <-
           get_agent_for_token(expected_agent_id, expected_organization_id, lock: true),
         :ok <- validate_current_generation(agent, expected_generation),
         :ok <- check_revocation_cache(expected_agent_id, expected_generation),
         {:ok, token_record} <-
           get_token_record_for_update(expected_agent_id, expected_generation),
         :ok <- validate_presented_token_hash(token_record, token),
         :ok <- validate_not_revoked(token_record),
         :ok <- validate_not_expired(token_record),
         {:ok, _credential} <-
           get_active_credential(
             credential_jti,
             expected_agent_id,
             expected_organization_id,
             lock: true
           ) do
      {:ok, claims}
    else
      _ -> {:error, :invalid_token}
    end
  rescue
    _error ->
      Logger.error("Locked agent token validation failed")
      {:error, :database_error}
  end

  @doc """
  Revoke a token or all tokens for an agent.

  Options:
  - :reason - Reason for revocation (string)
  - :all_generations - Revoke all tokens for the agent (boolean)
  """
  def revoke_token(_agent_id), do: {:error, :organization_scope_required}

  def revoke_token(_agent_id, opts) when is_list(opts),
    do: {:error, :organization_scope_required}

  def revoke_token(agent_id, organization_id) when is_binary(organization_id),
    do: revoke_token(agent_id, organization_id, [])

  def revoke_token(_agent_id, _organization_id),
    do: {:error, :organization_scope_required}

  def revoke_token(agent_id, organization_id, opts) when is_list(opts) do
    with {:ok, canonical_agent_id} <- canonical_uuid(agent_id, :invalid_agent_id),
         {:ok, canonical_organization_id} <-
           canonical_uuid(organization_id, :organization_scope_required) do
      GenServer.call(
        __MODULE__,
        {:revoke_token, canonical_agent_id, canonical_organization_id, opts}
      )
    end
  end

  @doc """
  Get token statistics for an agent.
  """
  def get_token_stats(_agent_id), do: {:error, :organization_scope_required}

  def get_token_stats(agent_id, organization_id) do
    with {:ok, canonical_agent_id} <- canonical_uuid(agent_id, :invalid_agent_id),
         {:ok, canonical_organization_id} <-
           canonical_uuid(organization_id, :organization_scope_required) do
      GenServer.call(
        __MODULE__,
        {:get_token_stats, canonical_agent_id, canonical_organization_id}
      )
    end
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Create ETS table for revocation cache
    :ets.new(:agent_token_revocations, [
      :set,
      :named_table,
      :public,
      read_concurrency: true
    ])

    # Schedule periodic cleanup
    schedule_cleanup()

    # Preload revocation list from database. Test harnesses can disable this
    # when the SQL sandbox owns connections before endpoint/controller tests.
    unless skip_revocation_preload?() do
      load_revocations()
    end

    Logger.info("TokenManager started")
    {:ok, %{}}
  end

  @impl true
  def handle_call({:issue_token, agent_id, organization_id, opts}, _from, state) do
    result =
      try do
        MultiTenant.with_organization(organization_id, fn ->
          case do_issue_token(agent_id, organization_id, opts) do
            {:ok, _jwt, _token_record} = success -> success
            # MultiTenant owns the transaction. A throw makes Ecto roll it
            # back while preserving the typed domain error for the caller.
            {:error, reason} -> throw({:token_issuance_failed, reason})
          end
        end)
      catch
        {:token_issuance_failed, reason} -> {:error, reason}
      end

    {:reply, result, state}
  rescue
    _error ->
      Logger.error("Token issuance transaction failed")
      {:reply, {:error, :database_error}, state}
  end

  @impl true
  def handle_call({:refresh_token, current_token, opts}, _from, state) do
    result = do_refresh_token(current_token, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:validate_token, token}, _from, state) do
    result = do_validate_token(token)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:revoke_token, agent_id, organization_id, opts}, _from, state) do
    result =
      run_tenant_operation(organization_id, :revoke, fn ->
        do_revoke_token(agent_id, organization_id, opts)
      end)

    result =
      case result do
        {:ok, %{revoked_tokens: revoked_tokens} = details} ->
          Enum.each(revoked_tokens, fn token ->
            add_to_revocation_cache(
              agent_id,
              token.token_generation,
              token.revoked_at,
              token.revocation_reason
            )
          end)

          {:ok, Map.delete(details, :revoked_tokens)}

        other ->
          other
      end

    {:reply, result, state}
  rescue
    _error ->
      Logger.error("Token revocation transaction failed")
      {:reply, {:error, :database_error}, state}
  end

  @impl true
  def handle_call({:get_token_stats, agent_id, organization_id}, _from, state) do
    result =
      run_tenant_operation(organization_id, :stats, fn ->
        do_get_token_stats(agent_id, organization_id)
      end)

    {:reply, result, state}
  rescue
    _error ->
      Logger.error("Token statistics transaction failed")
      {:reply, {:error, :database_error}, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_expired_tokens()
    schedule_cleanup()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp do_issue_token(agent_id, organization_id, opts) do
    case get_agent_for_issuance(agent_id, organization_id) do
      nil ->
        {:error, :agent_not_found}

      agent ->
        do_issue_locked_agent(agent, opts)
    end
  end

  defp do_issue_locked_agent(%{token_rotation_enabled: false}, _opts),
    do: {:error, :token_rotation_disabled}

  defp do_issue_locked_agent(agent, opts) do
    new_generation = next_generation(agent.current_token_generation)

    with :ok <- update_agent_generation(agent, new_generation),
         :ok <- revoke_previous_generations(agent.id, new_generation),
         :ok <- revoke_active_credentials(agent.id, agent.organization_id, "token_rotated") do
      issue_credential_and_token(agent, new_generation, opts)
    end
  end

  defp issue_credential_and_token(agent, new_generation, opts) do
    ttl_hours = token_ttl_hours(agent)
    now = DateTime.utc_now()
    expires_at = DateTime.add(now, ttl_hours * 3600, :second)
    jti = generate_jti()

    case Credentials.issue_credential_in_current_tenant(agent,
           jti: jti,
           issued_at: now,
           expires_at: credential_expires_at(expires_at),
           ip_address: opts[:ip_address],
           issued_by_user_id: opts[:issued_by_user_id]
         ) do
      {:ok, ^jti, _credential} ->
        do_encode_and_store_token(
          agent.id,
          agent.organization_id,
          new_generation,
          jti,
          ttl_hours,
          now,
          expires_at,
          opts
        )

      {:error, _reason} ->
        Logger.error("Failed to issue DB-backed credential for agent #{agent.id}")

        {:error, :credential_storage_failed}
    end
  end

  defp do_encode_and_store_token(
         agent_id,
         organization_id,
         generation,
         jti,
         ttl_hours,
         now,
         expires_at,
         opts
       ) do
    claims = %{
      agent_id: agent_id,
      org_id: organization_id,
      organization_id: organization_id,
      generation: generation,
      credential_jti: jti,
      jti: jti,
      type: "agent",
      iat: DateTime.to_unix(now),
      exp: DateTime.to_unix(expires_at)
    }

    case TamanduaServer.Guardian.encode_and_sign(
           %{id: agent_id},
           claims,
           ttl: {ttl_hours, :hours}
         ) do
      {:ok, jwt, _claims} ->
        token_hash = hash_token(jwt)

        token_attrs = %{
          agent_id: agent_id,
          token_generation: generation,
          token_hash: token_hash,
          issued_at: now,
          expires_at: expires_at,
          ip_address: opts[:ip_address],
          user_agent: opts[:user_agent]
        }

        case %AgentToken{}
             |> AgentToken.changeset(token_attrs)
             |> Repo.insert() do
          {:ok, token_record} ->
            audit_token_operation(:issue, agent_id, organization_id, generation, opts)

            Logger.info(
              "Issued token for agent #{agent_id}, generation #{generation}, " <>
                "jti_ref #{jti_reference(jti)}, expires #{expires_at}"
            )

            {:ok, jwt, token_record}

          {:error, _changeset} ->
            Logger.error("Failed to store token record")
            {:error, :token_storage_failed}
        end

      {:error, _reason} ->
        Logger.error("Failed to encode JWT")
        {:error, :jwt_encoding_failed}
    end
  end

  defp do_refresh_token(current_token, opts) do
    with {:ok, claims} <- decode_token_for_refresh(current_token),
         {:ok, agent_id, generation, organization_id, credential_jti} <-
           extract_token_identity(claims) do
      run_tenant_operation(organization_id, :refresh, fn ->
        do_refresh_token_in_tenant(
          current_token,
          claims,
          agent_id,
          generation,
          organization_id,
          credential_jti,
          opts
        )
      end)
      |> normalize_refresh_result()
    else
      {:error, :outside_refresh_window} ->
        {:error, :too_early_to_refresh}

      {:error, :revoked} ->
        {:error, :token_revoked}

      {:error, reason} ->
        Logger.warning("Token refresh rejected")
        {:error, reason}
    end
  rescue
    _error ->
      Logger.error("Token refresh failed")
      {:error, :database_error}
  end

  defp normalize_refresh_result({:error, :outside_refresh_window}),
    do: {:error, :too_early_to_refresh}

  defp normalize_refresh_result({:error, :revoked}), do: {:error, :token_revoked}
  defp normalize_refresh_result(result), do: result

  defp do_refresh_token_in_tenant(
         current_token,
         claims,
         agent_id,
         generation,
         organization_id,
         credential_jti,
         opts
       ) do
    with {:ok, agent} <- get_agent_for_token(agent_id, organization_id, lock: true),
         :ok <- validate_token_rotation_enabled(agent),
         :ok <- validate_current_generation(agent, generation),
         {:ok, token_record} <- get_token_record_for_update(agent_id, generation),
         :ok <- validate_presented_token_hash(token_record, current_token),
         :ok <- maybe_validate_refresh_window(token_record, claims, agent),
         :ok <- validate_not_revoked(token_record),
         :ok <- validate_refresh_grace(token_record),
         {:ok, old_credential} <-
           get_active_credential(credential_jti, agent_id, organization_id, lock: true) do
      rotate_refreshed_token(agent, token_record, old_credential, generation, opts)
    end
  end

  defp rotate_refreshed_token(agent, token_record, old_credential, generation, opts) do
    ttl_hours = token_ttl_hours(agent)
    now = DateTime.utc_now()
    expires_at = DateTime.add(now, ttl_hours * 3600, :second)
    new_jti = generate_jti()

    with {:ok, ^new_jti, _credential} <-
           Credentials.issue_credential_in_current_tenant(agent,
             jti: new_jti,
             issued_at: now,
             expires_at: credential_expires_at(expires_at),
             ip_address: opts[:ip_address],
             issued_by_user_id: opts[:issued_by_user_id]
           ),
         {:ok, new_jwt} <-
           encode_refreshed_token(agent, generation, new_jti, ttl_hours, now, expires_at),
         {:ok, updated_token_record} <-
           persist_refreshed_token(token_record, new_jwt, now, expires_at, opts),
         {:ok, _revoked_credential} <-
           old_credential
           |> AgentCredential.revoke_changeset("token_refreshed")
           |> Repo.update() do
      audit_token_operation(
        :refresh,
        agent.id,
        agent.organization_id,
        generation,
        Keyword.put(opts, :credential_jti, new_jti)
      )

      maybe_warn_refresh_count_anomaly(updated_token_record, agent.id, generation)
      {:ok, new_jwt, updated_token_record}
    else
      {:error, %Ecto.Changeset{}} ->
        Logger.error("Failed to persist atomic token refresh")
        {:error, :credential_storage_failed}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp encode_refreshed_token(agent, generation, jti, ttl_hours, now, expires_at) do
    claims = %{
      agent_id: agent.id,
      org_id: agent.organization_id,
      organization_id: agent.organization_id,
      generation: generation,
      credential_jti: jti,
      jti: jti,
      type: "agent",
      iat: DateTime.to_unix(now),
      exp: DateTime.to_unix(expires_at)
    }

    case TamanduaServer.Guardian.encode_and_sign(
           %{id: agent.id},
           claims,
           ttl: {ttl_hours, :hours}
         ) do
      {:ok, jwt, _claims} ->
        {:ok, jwt}

      {:error, _reason} ->
        Logger.error("Failed to encode refreshed JWT")
        {:error, :jwt_encoding_failed}
    end
  end

  defp persist_refreshed_token(token_record, new_jwt, now, expires_at, opts) do
    token_record
    |> Ecto.Changeset.change(%{
      token_hash: hash_token(new_jwt),
      issued_at: now,
      last_refreshed_at: now,
      expires_at: expires_at,
      refresh_count: (token_record.refresh_count || 0) + 1,
      ip_address: opts[:ip_address] || token_record.ip_address,
      user_agent: opts[:user_agent] || token_record.user_agent
    })
    |> Repo.update()
    |> case do
      {:ok, updated} -> {:ok, updated}
      {:error, _changeset} -> {:error, :token_storage_failed}
    end
  end

  defp do_validate_token(token) do
    with {:ok, claims} <- decode_token(token),
         {:ok, agent_id, generation, organization_id, credential_jti} <-
           extract_token_identity(claims) do
      run_tenant_operation(organization_id, :validate, fn ->
        with :ok <- check_revocation_cache(agent_id, generation),
             {:ok, agent} <- get_agent_for_token(agent_id, organization_id),
             :ok <- validate_current_generation(agent, generation),
             {:ok, token_record} <- get_token_record(agent_id, generation),
             :ok <- validate_presented_token_hash(token_record, token),
             :ok <- validate_not_revoked(token_record),
             :ok <- validate_not_expired(token_record),
             {:ok, _credential} <-
               get_active_credential(credential_jti, agent_id, organization_id) do
          {:ok, claims}
        end
      end)
    end
  end

  defp do_revoke_token(agent_id, organization_id, opts) do
    reason = opts[:reason] || "manual_revocation"

    with {:ok, agent} <- get_agent_for_token(agent_id, organization_id, lock: true) do
      tokens_to_revoke = tokens_to_revoke(agent, opts)
      now = DateTime.utc_now()

      revoked_tokens =
        Enum.map(tokens_to_revoke, fn token ->
          token
          |> Ecto.Changeset.change(revoked_at: now, revocation_reason: reason)
          |> Repo.update!()
        end)

      :ok = revoke_active_credentials(agent_id, organization_id, reason)

      Enum.each(revoked_tokens, fn token ->
        audit_token_operation(
          :revoke,
          agent_id,
          organization_id,
          token.token_generation,
          reason: reason
        )
      end)

      {:ok, %{revoked_count: length(revoked_tokens), revoked_tokens: revoked_tokens}}
    end
  end

  defp do_get_token_stats(agent_id, organization_id) do
    with {:ok, agent} <- get_agent_for_token(agent_id, organization_id) do
      stats =
        from(t in AgentToken,
          where: t.agent_id == ^agent.id,
          select: %{
            total_tokens: count(t.id),
            active_tokens: fragment("COUNT(CASE WHEN ? IS NULL THEN 1 END)", t.revoked_at),
            revoked_tokens: fragment("COUNT(CASE WHEN ? IS NOT NULL THEN 1 END)", t.revoked_at),
            total_refreshes: sum(t.refresh_count)
          }
        )
        |> Repo.one()

      {:ok,
       Map.merge(stats || %{}, %{
         current_generation: current_generation(agent.current_token_generation),
         rotation_enabled: agent.token_rotation_enabled,
         token_ttl_hours: token_ttl_hours(agent)
       })}
    end
  end

  # Helper Functions

  defp get_agent_for_issuance(agent_id, organization_id) do
    from(a in TamanduaServer.Agents.Agent,
      where: a.id == ^agent_id and a.organization_id == ^organization_id,
      lock: "FOR UPDATE"
    )
    |> Repo.one()
  end

  defp get_agent_for_token(agent_id, organization_id, opts \\ []) do
    query =
      from(a in TamanduaServer.Agents.Agent,
        where: a.id == ^agent_id and a.organization_id == ^organization_id
      )

    query = if opts[:lock], do: from(a in query, lock: "FOR UPDATE"), else: query

    case Repo.one(query) do
      nil -> {:error, :agent_not_found}
      agent -> {:ok, agent}
    end
  end

  defp get_active_credential(jti, agent_id, organization_id, opts \\ []) do
    query =
      from(c in AgentCredential,
        where:
          c.jti == ^jti and c.agent_id == ^agent_id and
            c.organization_id == ^organization_id
      )

    query = if opts[:lock], do: from(c in query, lock: "FOR UPDATE"), else: query

    case Repo.one(query) do
      nil ->
        {:error, :credential_not_found}

      credential ->
        case AgentCredential.validate(credential) do
          :ok -> {:ok, credential}
          {:error, reason} -> {:error, reason}
        end
    end
  end

  defp tokens_to_revoke(agent, opts) do
    query =
      from(t in AgentToken,
        where: t.agent_id == ^agent.id and is_nil(t.revoked_at),
        lock: "FOR UPDATE"
      )

    query =
      if opts[:all_generations] do
        query
      else
        generation = current_generation(agent.current_token_generation)
        from(t in query, where: t.token_generation == ^generation)
      end

    Repo.all(query)
  end

  defp validate_presented_token_hash(token_record, token) do
    if Plug.Crypto.secure_compare(token_record.token_hash, hash_token(token)) do
      :ok
    else
      {:error, :stale_token}
    end
  end

  defp run_tenant_operation(organization_id, operation, fun) do
    try do
      MultiTenant.with_organization(organization_id, fn ->
        case fun.() do
          success
          when is_tuple(success) and tuple_size(success) >= 2 and elem(success, 0) == :ok ->
            success

          {:error, reason} ->
            throw({:token_operation_failed, operation, reason})
        end
      end)
    catch
      {:token_operation_failed, ^operation, reason} -> {:error, reason}
    end
  end

  defp update_agent_generation(agent, new_generation) do
    case agent
         |> Ecto.Changeset.change(current_token_generation: new_generation)
         |> Repo.update() do
      {:ok, _agent} ->
        :ok

      {:error, _changeset} ->
        Logger.error("Failed to update agent token generation")
        {:error, :generation_update_failed}
    end
  end

  defp generate_jti do
    24
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end

  defp jti_reference(jti)
       when is_binary(jti) and byte_size(jti) > 0 and
              byte_size(jti) <= @maximum_jti_reference_input_bytes do
    jti
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
    |> binary_part(0, @jti_reference_hex_chars)
  end

  defp jti_reference(_jti), do: "unavailable"

  defp revoke_previous_generations(agent_id, new_generation) do
    now = DateTime.utc_now()

    from(t in AgentToken,
      where:
        t.agent_id == ^agent_id and
          t.token_generation < ^new_generation and
          is_nil(t.revoked_at)
    )
    |> Repo.update_all(
      set: [
        revoked_at: now,
        revocation_reason: "superseded_by_generation_#{new_generation}"
      ]
    )

    :ok
  end

  defp revoke_active_credentials(agent_id, organization_id, reason) do
    now = DateTime.utc_now()

    from(c in AgentCredential,
      where:
        c.agent_id == ^agent_id and c.organization_id == ^organization_id and
          is_nil(c.revoked_at)
    )
    |> Repo.update_all(set: [revoked_at: now, revocation_reason: reason])

    :ok
  end

  defp next_generation(value) when value in [nil, 0], do: 1
  defp next_generation(value) when is_integer(value) and value > 0, do: value + 1

  defp current_generation(value) when value in [nil, 0], do: 0
  defp current_generation(value) when is_integer(value) and value > 0, do: value

  defp canonical_uuid(value, error_reason) when is_binary(value) do
    case Ecto.UUID.cast(value) do
      {:ok, canonical} -> {:ok, canonical}
      :error -> {:error, error_reason}
    end
  end

  defp canonical_uuid(_value, error_reason), do: {:error, error_reason}

  defp hash_token(token) do
    :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)
  end

  defp decode_token(token) do
    case TamanduaServer.Guardian.decode_and_verify(token) do
      {:ok, claims} -> {:ok, claims}
      {:error, reason} -> {:error, reason}
    end
  end

  defp decode_token_for_refresh(token) do
    case decode_token(token) do
      {:ok, claims} ->
        {:ok, claims}

      {:error, reason} ->
        if expired_token_error?(reason) do
          recover_expired_refresh_claims(token)
        else
          {:error, reason}
        end
    end
  end

  defp expired_token_error?(reason) when reason in [:token_expired, "token_expired", :expired],
    do: true

  defp expired_token_error?({reason, _details}) when reason in [:token_expired, :expired],
    do: true

  defp expired_token_error?(_reason), do: false

  defp recover_expired_refresh_claims(token) do
    # Guardian.Token.Jwt.decode_token verifies the JWT signature but deliberately
    # does not apply temporal claim checks. The tenant transaction below then
    # requires an exact hash match with the locked DB row and enforces the
    # bounded refresh grace period.
    case Guardian.Token.Jwt.decode_token(TamanduaServer.Guardian, token) do
      {:ok, claims} -> {:ok, Map.put(claims, "_tamandua_expired_refresh_recovered", true)}
      {:error, _reason} -> {:error, :invalid_token}
    end
  end

  defp extract_token_info(claims) do
    agent_id = claims["agent_id"]
    generation = claims["generation"]

    if agent_id && generation do
      {:ok, agent_id, generation}
    else
      {:error, :invalid_claims}
    end
  end

  defp extract_token_identity(claims) do
    organization_id = claims["org_id"]
    duplicate_organization_id = claims["organization_id"]
    credential_jti = claims["credential_jti"] || claims["jti"]

    with true <- organization_id == duplicate_organization_id,
         {:ok, agent_id, generation} <- extract_token_info(claims),
         {:ok, canonical_agent_id} <- canonical_uuid(agent_id, :invalid_claims),
         {:ok, canonical_organization_id} <-
           canonical_uuid(organization_id, :invalid_claims),
         true <- is_integer(generation) and generation > 0,
         true <- is_binary(credential_jti) and byte_size(credential_jti) > 0 do
      {:ok, canonical_agent_id, generation, canonical_organization_id, credential_jti}
    else
      _ -> {:error, :invalid_claims}
    end
  end

  defp get_token_record(agent_id, generation) do
    case Repo.get_by(AgentToken, agent_id: agent_id, token_generation: generation) do
      nil -> {:error, :token_not_found}
      token -> {:ok, token}
    end
  end

  defp get_token_record_for_update(agent_id, generation) do
    from(t in AgentToken,
      where: t.agent_id == ^agent_id and t.token_generation == ^generation,
      lock: "FOR UPDATE"
    )
    |> Repo.one()
    |> case do
      nil -> {:error, :token_not_found}
      token -> {:ok, token}
    end
  end

  defp maybe_validate_refresh_window(
         _token_record,
         %{
           "_tamandua_expired_refresh_recovered" => true
         },
         _agent
       ) do
    :ok
  end

  defp maybe_validate_refresh_window(token_record, _claims, agent),
    do: validate_refresh_window(token_record, agent)

  defp validate_refresh_window(token_record, agent) do
    refresh_window =
      min(
        agent.token_refresh_window_percent || @default_refresh_window_percent,
        @default_refresh_window_percent
      )

    now = DateTime.utc_now()
    ttl = DateTime.diff(token_record.expires_at, token_record.issued_at, :second)
    elapsed = DateTime.diff(now, token_record.issued_at, :second)
    percent_elapsed = elapsed / ttl * 100

    if percent_elapsed >= refresh_window do
      :ok
    else
      {:error, :outside_refresh_window}
    end
  end

  defp validate_not_revoked(%{revoked_at: nil}), do: :ok
  defp validate_not_revoked(_), do: {:error, :revoked}

  defp validate_not_expired(token_record) do
    if DateTime.compare(DateTime.utc_now(), token_record.expires_at) == :lt do
      :ok
    else
      {:error, :expired}
    end
  end

  @doc """
  The effective refresh grace period in seconds.

  Configurable via `config :tamandua_server, :agent_token_refresh_grace_seconds`.
  Defaults to 7 days.
  """
  def refresh_grace_seconds do
    case Application.get_env(
           :tamandua_server,
           :agent_token_refresh_grace_seconds,
           @default_refresh_grace_seconds
         ) do
      seconds when is_integer(seconds) and seconds >= 0 ->
        min(seconds, @maximum_refresh_grace_seconds)

      _invalid ->
        # Invalid configuration must not silently enlarge the recovery window.
        0
    end
  end

  @doc """
  The refresh-count threshold above which a warning is logged.

  Configurable via
  `config :tamandua_server, :agent_token_refresh_count_warning_threshold`.
  Defaults to #{@default_refresh_count_warning_threshold}.
  """
  def refresh_count_warning_threshold do
    Application.get_env(
      :tamandua_server,
      :agent_token_refresh_count_warning_threshold,
      @default_refresh_count_warning_threshold
    )
  end

  # Log a warning when an agent's token has been refreshed an anomalous
  # number of times -- a possible indicator of a replayed/stolen token
  # being kept alive indefinitely through refreshes.
  # Public (but undocumented) so the anomaly path is directly testable
  # without a full DB-backed refresh cycle.
  @doc false
  def maybe_warn_refresh_count_anomaly(token_record, agent_id, generation) do
    threshold = refresh_count_warning_threshold()

    if is_integer(threshold) and threshold > 0 and
         (token_record.refresh_count || 0) > threshold do
      Logger.warning(
        "Anomalous token refresh count for agent #{agent_id}: " <>
          "#{token_record.refresh_count} refreshes on generation #{generation} " <>
          "(threshold #{threshold}). Possible token abuse -- consider rotating " <>
          "the agent token generation."
      )
    end

    :ok
  end

  defp validate_refresh_grace(token_record) do
    cutoff = DateTime.add(token_record.expires_at, refresh_grace_seconds(), :second)

    if DateTime.compare(DateTime.utc_now(), cutoff) == :lt do
      :ok
    else
      {:error, :refresh_grace_expired}
    end
  end

  defp credential_expires_at(token_expires_at) do
    DateTime.add(token_expires_at, refresh_grace_seconds(), :second)
  end

  defp validate_current_generation(agent, generation) do
    if current_generation(agent.current_token_generation) == generation do
      :ok
    else
      {:error, :generation_mismatch}
    end
  end

  defp validate_token_rotation_enabled(%{token_rotation_enabled: true}), do: :ok
  defp validate_token_rotation_enabled(_agent), do: {:error, :token_rotation_disabled}

  defp token_ttl_hours(agent) do
    configured = agent.token_ttl_hours || @default_token_ttl_hours
    max(configured, @minimum_token_ttl_hours)
  end

  defp check_revocation_cache(agent_id, generation) do
    if :ets.whereis(:agent_token_revocations) == :undefined do
      :ok
    else
      case :ets.lookup(:agent_token_revocations, {agent_id, generation}) do
        [] -> :ok
        [{_, _revoked_at, _reason}] -> {:error, :revoked}
      end
    end
  end

  defp add_to_revocation_cache(agent_id, generation, revoked_at, reason) do
    :ets.insert(:agent_token_revocations, {{agent_id, generation}, revoked_at, reason})
  end

  defp load_revocations do
    cutoff =
      DateTime.utc_now()
      |> DateTime.add(-@revocation_cache_ttl_days * 24 * 3600, :second)

    revoked_tokens =
      from(t in AgentToken,
        where: not is_nil(t.revoked_at) and t.revoked_at > ^cutoff,
        select: {t.agent_id, t.token_generation, t.revoked_at, t.revocation_reason}
      )
      |> Repo.all()

    Enum.each(revoked_tokens, fn {agent_id, generation, revoked_at, reason} ->
      :ets.insert(:agent_token_revocations, {{agent_id, generation}, revoked_at, reason})
    end)

    Logger.info("Loaded #{length(revoked_tokens)} revoked tokens into cache")
  end

  defp skip_revocation_preload? do
    System.get_env("TAMANDUA_SKIP_TOKEN_REVOCATION_PRELOAD", "false") == "true"
  end

  defp cleanup_expired_tokens do
    cutoff =
      DateTime.utc_now()
      |> DateTime.add(-@revocation_cache_ttl_days * 24 * 3600, :second)

    # Delete old token records
    {deleted_count, _} =
      from(t in AgentToken,
        where: t.expires_at < ^cutoff
      )
      |> Repo.delete_all()

    # Clean ETS cache
    now = DateTime.utc_now()

    :ets.foldl(
      fn {{agent_id, generation}, revoked_at, _reason}, acc ->
        if DateTime.diff(now, revoked_at, :second) > @revocation_cache_ttl_days * 24 * 3600 do
          :ets.delete(:agent_token_revocations, {agent_id, generation})
        end

        acc
      end,
      nil,
      :agent_token_revocations
    )

    if deleted_count > 0 do
      Logger.info("Cleaned up #{deleted_count} expired token records")
    end
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end

  defp audit_token_operation(operation, agent_id, organization_id, generation, opts) do
    # Log to audit system
    Audit.log_event(%{
      event_type: "token_#{operation}",
      actor_type: "system",
      resource_type: "agent_token",
      resource_id: "#{agent_id}:gen#{generation}",
      metadata: %{
        agent_id: agent_id,
        organization_id: organization_id,
        token_generation: generation,
        ip_address: opts[:ip_address],
        user_agent: opts[:user_agent],
        reason: opts[:reason]
      }
    })
  rescue
    _error ->
      Logger.warning("Failed to audit token operation")
  end
end
