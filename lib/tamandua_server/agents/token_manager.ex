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
  alias TamanduaServer.Agents.Credentials
  import Ecto.Query

  @cleanup_interval :timer.hours(1)
  @revocation_cache_ttl_days 7
  @default_token_ttl_hours 720
  @default_refresh_window_percent 60
  @minimum_token_ttl_hours 720
  @default_refresh_grace_seconds 30 * 24 * 3600

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

  Returns {:ok, jwt, token_record} or {:error, reason}.
  Automatically revokes previous tokens and increments generation.
  """
  def issue_token(agent_id, opts \\ []) do
    GenServer.call(__MODULE__, {:issue_token, agent_id, opts})
  end

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
    GenServer.call(__MODULE__, {:validate_token, token})
  end

  @doc """
  Revoke a token or all tokens for an agent.

  Options:
  - :reason - Reason for revocation (string)
  - :all_generations - Revoke all tokens for the agent (boolean)
  """
  def revoke_token(agent_id, opts \\ []) do
    GenServer.call(__MODULE__, {:revoke_token, agent_id, opts})
  end

  @doc """
  Get token statistics for an agent.
  """
  def get_token_stats(agent_id) do
    GenServer.call(__MODULE__, {:get_token_stats, agent_id})
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

    # Preload revocation list from database
    load_revocations()

    Logger.info("TokenManager started")
    {:ok, %{}}
  end

  @impl true
  def handle_call({:issue_token, agent_id, opts}, _from, state) do
    result = MultiTenant.with_bypass(fn -> do_issue_token(agent_id, opts) end)
    {:reply, result, state}
  rescue
    e ->
      Logger.error("Token issuance bypass failed: #{Exception.message(e)}")
      {:reply, {:error, :internal_error}, state}
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
  def handle_call({:revoke_token, agent_id, opts}, _from, state) do
    result = do_revoke_token(agent_id, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_token_stats, agent_id}, _from, state) do
    result = do_get_token_stats(agent_id)
    {:reply, result, state}
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

  defp do_issue_token(agent_id, opts) do
    agent = get_agent(agent_id)

    if agent && agent.token_rotation_enabled != false do
      # Increment generation
      new_generation = (agent.current_token_generation || 1) + 1

      # Update agent's current generation
      update_agent_generation(agent_id, new_generation)

      # Revoke all previous tokens for this agent
      revoke_previous_generations(agent_id, new_generation)

      # Calculate expiry
      ttl_hours = token_ttl_hours(agent)
      now = DateTime.utc_now()
      expires_at = DateTime.add(now, ttl_hours * 3600, :second)
      organization_id = agent.organization_id
      jti = generate_jti()

      with {:ok, ^jti, _credential} <-
             Credentials.issue_credential(agent_id, organization_id,
               jti: jti,
               ttl_hours: ttl_hours,
               ip_address: opts[:ip_address],
               issued_by_user_id: opts[:issued_by_user_id]
             ) do
        do_encode_and_store_token(
          agent_id,
          organization_id,
          new_generation,
          jti,
          ttl_hours,
          now,
          expires_at,
          opts
        )
      else
        {:error, reason} ->
          Logger.error(
            "Failed to issue DB-backed credential for agent #{agent_id}: #{inspect(reason)}"
          )

          {:error, :credential_storage_failed}
      end
    else
      {:error, :token_rotation_disabled}
    end
  rescue
    e ->
      Logger.error("Token issuance failed: #{Exception.message(e)}")
      {:error, :internal_error}
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
            audit_token_operation(:issue, agent_id, generation, opts)

            Logger.info(
              "Issued token for agent #{agent_id}, generation #{generation}, jti #{jti}, expires #{expires_at}"
            )

            {:ok, jwt, token_record}

          {:error, changeset} ->
            Logger.error("Failed to store token record: #{inspect(changeset.errors)}")
            {:error, :token_storage_failed}
        end

      {:error, reason} ->
        Logger.error("Failed to encode JWT: #{inspect(reason)}")
        {:error, :jwt_encoding_failed}
    end
  end

  defp do_refresh_token(current_token, opts) do
    with {:ok, claims} <- decode_token_for_refresh(current_token),
         {:ok, agent_id, generation} <- extract_token_info(claims),
         {:ok, token_record} <- get_token_record(agent_id, generation),
         :ok <- validate_refresh_window(token_record),
         :ok <- validate_not_revoked(token_record),
         :ok <- validate_refresh_grace(token_record),
         :ok <- validate_current_generation(agent_id, generation) do
      # Issue new token with same generation (refresh doesn't increment)
      agent = get_agent(agent_id)

      if agent do
        ttl_hours = token_ttl_hours(agent)
        now = DateTime.utc_now()
        expires_at = DateTime.add(now, ttl_hours * 3600, :second)
        org_id = claims["org_id"] || claims["organization_id"] || agent.organization_id
        token_jti = claims["jti"]
        credential_jti = claims["credential_jti"] || token_jti

        new_claims = %{
          agent_id: agent_id,
          org_id: org_id,
          organization_id: org_id,
          generation: generation,
          credential_jti: credential_jti,
          jti: token_jti,
          type: "agent",
          iat: DateTime.to_unix(now),
          exp: DateTime.to_unix(expires_at)
        }

        case TamanduaServer.Guardian.encode_and_sign(
               %{id: agent_id},
               new_claims,
               ttl: {ttl_hours, :hours}
             ) do
          {:ok, new_jwt, _} ->
            # Update token record
            token_hash = hash_token(new_jwt)

            case token_record
                 |> Ecto.Changeset.change(%{
                   token_hash: token_hash,
                   last_refreshed_at: now,
                   expires_at: expires_at,
                   refresh_count: token_record.refresh_count + 1,
                   ip_address: opts[:ip_address] || token_record.ip_address,
                   user_agent: opts[:user_agent] || token_record.user_agent
                 })
                 |> Repo.update() do
              {:ok, updated_token_record} ->
                if is_binary(credential_jti) do
                  case Credentials.extend_expiry(credential_jti, expires_at) do
                    {:ok, _credential} ->
                      :ok

                    {:error, reason} ->
                      Logger.warning(
                        "Failed to extend DB-backed credential #{credential_jti}: #{inspect(reason)}"
                      )
                  end
                end

                audit_token_operation(:refresh, agent_id, generation, opts)

                Logger.info(
                  "Refreshed token for agent #{agent_id}, generation #{generation}, refresh count #{updated_token_record.refresh_count}"
                )

                {:ok, new_jwt, updated_token_record}

              {:error, changeset} ->
                Logger.error("Failed to persist refreshed token: #{inspect(changeset.errors)}")
                {:error, :token_storage_failed}
            end

          {:error, reason} ->
            Logger.error("Failed to encode refreshed JWT: #{inspect(reason)}")
            {:error, :jwt_encoding_failed}
        end
      else
        {:error, :agent_not_found}
      end
    else
      {:error, :outside_refresh_window} ->
        {:error, :too_early_to_refresh}

      {:error, :revoked} ->
        {:error, :token_revoked}

      {:error, reason} ->
        Logger.warning("Token refresh failed: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("Token refresh failed: #{Exception.message(e)}")
      {:error, :internal_error}
  end

  defp do_validate_token(token) do
    with {:ok, claims} <- decode_token(token),
         {:ok, agent_id, generation} <- extract_token_info(claims),
         :ok <- check_revocation_cache(agent_id, generation),
         {:ok, token_record} <- get_token_record(agent_id, generation),
         :ok <- validate_not_revoked(token_record),
         :ok <- validate_not_expired(token_record),
         :ok <- validate_current_generation(agent_id, generation) do
      {:ok, claims}
    else
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_revoke_token(agent_id, opts) do
    reason = opts[:reason] || "manual_revocation"

    tokens_to_revoke =
      if opts[:all_generations] do
        # Revoke all tokens for this agent
        from(t in AgentToken,
          where: t.agent_id == ^agent_id and is_nil(t.revoked_at)
        )
        |> Repo.all()
      else
        # Revoke only current generation
        case get_agent(agent_id) do
          nil ->
            # Unknown agent: nothing to revoke for the current generation.
            []

          agent ->
            generation = agent.current_token_generation || 1

            from(t in AgentToken,
              where:
                t.agent_id == ^agent_id and t.token_generation == ^generation and
                  is_nil(t.revoked_at)
            )
            |> Repo.all()
        end
      end

    now = DateTime.utc_now()

    Enum.each(tokens_to_revoke, fn token ->
      token
      |> Ecto.Changeset.change(%{
        revoked_at: now,
        revocation_reason: reason
      })
      |> Repo.update()

      # Add to revocation cache
      add_to_revocation_cache(agent_id, token.token_generation, now, reason)

      # Audit log
      audit_token_operation(:revoke, agent_id, token.token_generation, %{reason: reason})
    end)

    count = length(tokens_to_revoke)
    Logger.info("Revoked #{count} token(s) for agent #{agent_id}, reason: #{reason}")

    {:ok, %{revoked_count: count}}
  end

  defp do_get_token_stats(agent_id) do
    stats =
      from(t in AgentToken,
        where: t.agent_id == ^agent_id,
        select: %{
          total_tokens: count(t.id),
          active_tokens: fragment("COUNT(CASE WHEN ? IS NULL THEN 1 END)", t.revoked_at),
          revoked_tokens: fragment("COUNT(CASE WHEN ? IS NOT NULL THEN 1 END)", t.revoked_at),
          total_refreshes: sum(t.refresh_count)
        }
      )
      |> Repo.one()

    case get_agent(agent_id) do
      nil ->
        {:error, :agent_not_found}

      agent ->
        {:ok,
         Map.merge(stats || %{}, %{
           current_generation: agent.current_token_generation || 1,
           rotation_enabled: agent.token_rotation_enabled,
           token_ttl_hours: token_ttl_hours(agent)
         })}
    end
  end

  # Helper Functions

  defp get_agent(agent_id) do
    Repo.get_by(TamanduaServer.Agents.Agent, id: agent_id)
  end

  defp update_agent_generation(agent_id, new_generation) do
    from(a in TamanduaServer.Agents.Agent,
      where: a.id == ^agent_id,
      update: [set: [current_token_generation: ^new_generation]]
    )
    |> Repo.update_all([])
  end

  defp generate_jti do
    24
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end

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
  end

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

  defp expired_token_error?(reason) do
    reason
    |> inspect()
    |> String.downcase()
    |> then(&(String.contains?(&1, "exp") or String.contains?(&1, "expired")))
  end

  defp recover_expired_refresh_claims(token) do
    token_hash = hash_token(token)

    case get_token_record_by_hash(token_hash) do
      {:ok, token_record} ->
        with :ok <- validate_not_revoked(token_record),
             :ok <- validate_refresh_grace(token_record),
             :ok <-
               validate_current_generation(token_record.agent_id, token_record.token_generation),
             {:ok, claims} <- decode_unverified_claims(token),
             {:ok, agent_id, generation} <- extract_token_info(claims),
             true <-
               agent_id == token_record.agent_id and generation == token_record.token_generation do
          Logger.info(
            "Recovered expired refresh token for agent #{agent_id}, generation #{generation} via DB hash match"
          )

          {:ok, claims}
        else
          false -> {:error, :generation_mismatch}
          {:error, reason} -> {:error, reason}
        end

      error ->
        error
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

  defp get_token_record(agent_id, generation) do
    case Repo.get_by(AgentToken, agent_id: agent_id, token_generation: generation) do
      nil -> {:error, :token_not_found}
      token -> {:ok, token}
    end
  end

  defp get_token_record_by_hash(token_hash) do
    case Repo.get_by(AgentToken, token_hash: token_hash) do
      nil -> {:error, :token_not_found}
      token -> {:ok, token}
    end
  end

  defp validate_refresh_window(token_record) do
    agent = get_agent(token_record.agent_id)

    if agent do
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
    else
      {:error, :agent_not_found}
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

  defp validate_refresh_grace(token_record) do
    grace_seconds =
      Application.get_env(
        :tamandua_server,
        :agent_token_refresh_grace_seconds,
        @default_refresh_grace_seconds
      )

    cutoff = DateTime.add(token_record.expires_at, grace_seconds, :second)

    if DateTime.compare(DateTime.utc_now(), cutoff) == :lt do
      :ok
    else
      {:error, :refresh_grace_expired}
    end
  end

  defp validate_current_generation(agent_id, generation) do
    case get_agent(agent_id) do
      nil ->
        {:error, :agent_not_found}

      agent ->
        if (agent.current_token_generation || 1) == generation do
          :ok
        else
          {:error, :generation_mismatch}
        end
    end
  end

  defp token_ttl_hours(agent) do
    configured = agent.token_ttl_hours || @default_token_ttl_hours
    max(configured, @minimum_token_ttl_hours)
  end

  defp check_revocation_cache(agent_id, generation) do
    case :ets.lookup(:agent_token_revocations, {agent_id, generation}) do
      [] -> :ok
      [{_, _revoked_at, _reason}] -> {:error, :revoked}
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

  defp audit_token_operation(operation, agent_id, generation, opts) do
    # Log to audit system
    Audit.log_event(%{
      event_type: "token_#{operation}",
      actor_type: "system",
      resource_type: "agent_token",
      resource_id: "#{agent_id}:gen#{generation}",
      metadata: %{
        agent_id: agent_id,
        token_generation: generation,
        ip_address: opts[:ip_address],
        user_agent: opts[:user_agent],
        reason: opts[:reason]
      }
    })
  rescue
    e ->
      Logger.warning("Failed to audit token operation: #{Exception.message(e)}")
  end

  defp decode_unverified_claims(token) when is_binary(token) do
    with [_header, payload, _signature] <- String.split(token, "."),
         {:ok, json} <- base64url_decode(payload),
         {:ok, claims} <- Jason.decode(json) do
      {:ok, claims}
    else
      _ -> {:error, :invalid_token}
    end
  end

  defp decode_unverified_claims(_), do: {:error, :invalid_token}

  defp base64url_decode(value) when is_binary(value) do
    padded = value <> String.duplicate("=", rem(4 - rem(byte_size(value), 4), 4))
    Base.url_decode64(padded)
  end
end
