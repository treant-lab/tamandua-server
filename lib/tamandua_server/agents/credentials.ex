defmodule TamanduaServer.Agents.Credentials do
  @moduledoc """
  Tenant-bound lifecycle for DB-backed agent socket credentials.

  Every public data operation requires the credential JTI, agent ID and
  organization ID needed to express its ownership boundary. Historical
  organization-less entrypoints fail closed.
  """

  import Ecto.Query
  require Logger

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Agents
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Agents.AgentCredential
  alias TamanduaServer.Audit
  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant

  @default_ttl_hours 720
  @minimum_ttl_hours 720
  @default_list_limit 100
  @maximum_list_limit 500
  @default_cleanup_limit 500
  @maximum_cleanup_limit 1_000
  @maximum_reason_bytes 512
  @maximum_jti_bytes 255
  @maximum_ip_bytes 64
  @maximum_ttl_hours 2_160

  @doc "Issues a credential after proving the agent belongs to the tenant."
  def issue_credential(agent_id, organization_id, opts \\ []) do
    with :ok <- validate_issue_options(opts),
         {:ok, agent_id} <- canonical_uuid(agent_id, :invalid_agent_id),
         {:ok, organization_id} <- canonical_uuid(organization_id, :invalid_organization_id) do
      with_tenant(organization_id, fn ->
        with {:ok, _agent} <- Agents.get_agent_for_org(organization_id, agent_id),
             {:ok, locked_agent} <- lock_agent(agent_id, organization_id) do
          issue_credential_record(locked_agent, opts)
        end
      end)
    end
  end

  @doc false
  def issue_credential_in_current_tenant(%Agent{} = agent, opts \\ []) do
    organization_id = agent.organization_id

    case {Repo.get_organization_id(), Repo.in_transaction?()} do
      {^organization_id, true} ->
        with :ok <- validate_issue_options(opts),
             {:ok, locked_agent} <- lock_agent(agent.id, organization_id) do
          issue_credential_record(locked_agent, opts)
        end

      _other ->
        {:error, :tenant_context_required}
    end
  end

  defp issue_credential_record(%Agent{} = agent, opts) do
    agent_id = agent.id
    organization_id = agent.organization_id
    jti = Keyword.get(opts, :jti) || generate_jti()

    with {:ok, issued_at} <- credential_issued_at(opts),
         {:ok, expires_at} <- credential_expiry(issued_at, opts) do
      attrs = %{
        agent_id: agent_id,
        organization_id: organization_id,
        jti: jti,
        issued_at: issued_at,
        expires_at: expires_at,
        issued_from_ip: Keyword.get(opts, :ip_address),
        issued_by_user_id: Keyword.get(opts, :issued_by_user_id)
      }

      case %AgentCredential{} |> AgentCredential.changeset(attrs) |> Repo.insert() do
        {:ok, credential} ->
          audit_credential_event(:issue, credential, opts)
          {:ok, jti, credential}

        {:error, changeset} ->
          Logger.error(
            "Failed to issue credential for agent #{agent_id}: #{inspect(changeset.errors)}"
          )

          {:error, changeset}
      end
    end
  end

  @doc "Validates an exact tenant credential and records use under a row lock."
  def validate_and_record_use(jti, agent_id, organization_id, peer_ip \\ nil) do
    with :ok <- validate_optional_bounded_string(peer_ip, @maximum_ip_bytes, :invalid_ip_address) do
      with_identity(agent_id, organization_id, fn agent_id, organization_id ->
        with_tenant(organization_id, fn ->
          with {:ok, credential} <- get_locked(jti, agent_id, organization_id),
               :ok <- AgentCredential.validate(credential),
               {:ok, updated} <-
                 credential |> AgentCredential.usage_changeset(peer_ip) |> Repo.update() do
            {:ok, updated}
          else
            {:error, reason} = error ->
              audit_validation_failure(jti, agent_id, organization_id, reason)
              error
          end
        end)
      end)
    end
  end

  @doc "Validates an exact tenant credential without changing usage."
  def validate(jti, agent_id, organization_id) do
    with_identity(agent_id, organization_id, fn agent_id, organization_id ->
      with_tenant(organization_id, fn ->
        with {:ok, credential} <- get_exact(jti, agent_id, organization_id),
             :ok <- AgentCredential.validate(credential) do
          {:ok, credential}
        end
      end)
    end)
  end

  @doc "Returns whether the exact tenant credential is currently valid."
  def valid?(jti, agent_id, organization_id) do
    match?({:ok, _credential}, validate(jti, agent_id, organization_id))
  end

  def valid?(_jti), do: false

  @doc "Returns an exact tenant credential."
  def get_by_jti(jti, agent_id, organization_id) do
    with_identity(agent_id, organization_id, fn agent_id, organization_id ->
      with_tenant(organization_id, fn -> get_exact(jti, agent_id, organization_id) end)
    end)
  end

  def get_by_jti(_jti), do: {:error, :organization_scope_required}

  @doc "Revokes one exact tenant credential under the same row lock used by validation."
  def revoke(jti, agent_id, organization_id, reason \\ "manual_revocation") do
    with :ok <- validate_reason(reason) do
      with_identity(agent_id, organization_id, fn agent_id, organization_id ->
        with_tenant(organization_id, fn ->
          with {:ok, credential} <- get_locked(jti, agent_id, organization_id),
               {:ok, revoked} <-
                 credential |> AgentCredential.revoke_changeset(reason) |> Repo.update() do
            audit_credential_event(:revoke, revoked, %{reason: reason})
            {:ok, revoked}
          end
        end)
      end)
    end
  end

  def revoke(_jti), do: {:error, :organization_scope_required}
  def revoke(_jti, _reason), do: {:error, :organization_scope_required}

  @doc "Revokes every active credential for one exact tenant agent."
  def revoke_all_for_agent(agent_id, organization_id) do
    case canonical_uuid(organization_id, :organization_scope_required) do
      {:ok, _organization_id} ->
        revoke_all_for_agent(agent_id, organization_id, "agent_credentials_revoked")

      {:error, _reason} ->
        {:error, :organization_scope_required}
    end
  end

  def revoke_all_for_agent(agent_id, organization_id, reason) do
    with :ok <- validate_reason(reason) do
      with_identity(agent_id, organization_id, fn agent_id, organization_id ->
        with_tenant(organization_id, fn ->
          with {:ok, _agent} <- lock_agent(agent_id, organization_id) do
            now = DateTime.utc_now()

            {count, _} =
              from(c in AgentCredential,
                where:
                  c.agent_id == ^agent_id and c.organization_id == ^organization_id and
                    is_nil(c.revoked_at)
              )
              |> Repo.update_all(set: [revoked_at: now, revocation_reason: reason])

            audit_bulk_revocation(agent_id, organization_id, count, reason)
            {:ok, count}
          end
        end)
      end)
    end
  end

  def revoke_all_for_agent(_agent_id), do: {:error, :organization_scope_required}

  @doc "Revokes all active credentials for a canonical tenant."
  def revoke_all_for_org(organization_id, reason \\ "organization_credentials_revoked") do
    with :ok <- validate_reason(reason),
         {:ok, organization_id} <- canonical_uuid(organization_id, :invalid_organization_id) do
      with_tenant(organization_id, fn ->
        case lock_organization(organization_id) do
          {:error, reason} ->
            {:error, reason}

          {:ok, _organization} ->
            now = DateTime.utc_now()

            {count, _} =
              from(c in AgentCredential,
                where: c.organization_id == ^organization_id and is_nil(c.revoked_at)
              )
              |> Repo.update_all(set: [revoked_at: now, revocation_reason: reason])

            audit_org_revocation(organization_id, count, reason)
            {:ok, count}
        end
      end)
    end
  end

  def revoke_all_for_organization(organization_id, reason \\ "organization_credentials_revoked"),
    do: revoke_all_for_org(organization_id, reason)

  @doc "Lists active credentials for an exact tenant agent with a hard bound."
  def list_active_for_agent(agent_id, organization_id, opts \\ []) do
    with_identity(agent_id, organization_id, fn agent_id, organization_id ->
      with :ok <- validate_options(opts, [:limit]),
           {:ok, limit} <- bounded_limit(opts, @default_list_limit, @maximum_list_limit) do
        with_tenant(organization_id, fn ->
          now = DateTime.utc_now()

          from(c in AgentCredential,
            where:
              c.agent_id == ^agent_id and c.organization_id == ^organization_id and
                is_nil(c.revoked_at) and c.expires_at > ^now,
            order_by: [desc: c.issued_at],
            limit: ^limit
          )
          |> Repo.all()
        end)
      end
    end)
  end

  def list_active_for_agent(_agent_id), do: {:error, :organization_scope_required}

  @doc "Returns exact tenant credential statistics for an agent."
  def get_stats(agent_id, organization_id) do
    with_identity(agent_id, organization_id, fn agent_id, organization_id ->
      with_tenant(organization_id, fn -> stats_in_scope(agent_id, organization_id) end)
    end)
  end

  def get_stats(_agent_id), do: {:error, :organization_scope_required}

  @doc "Deletes a bounded batch of tenant credentials expired before the retention cutoff."
  def cleanup_expired(organization_id, older_than_days, opts \\ []) do
    with {:ok, organization_id} <- canonical_uuid(organization_id, :invalid_organization_id),
         :ok <- validate_retention_days(older_than_days),
         :ok <- validate_options(opts, [:limit]),
         {:ok, limit} <- bounded_limit(opts, @default_cleanup_limit, @maximum_cleanup_limit) do
      with_tenant(organization_id, fn ->
        now = DateTime.utc_now()
        cutoff = DateTime.add(now, -older_than_days * 24 * 3600, :second)

        ids =
          from(c in AgentCredential,
            where:
              c.organization_id == ^organization_id and c.expires_at <= ^now and
                c.expires_at < ^cutoff,
            order_by: [asc: c.expires_at, asc: c.id],
            select: c.id,
            limit: ^limit
          )

        {count, _} =
          from(c in AgentCredential,
            where:
              c.organization_id == ^organization_id and c.id in subquery(ids) and
                c.expires_at <= ^now and c.expires_at < ^cutoff
          )
          |> Repo.delete_all()

        {:ok, count}
      end)
    end
  end

  def cleanup_expired(), do: {:error, :organization_scope_required}
  def cleanup_expired(_legacy_days), do: {:error, :organization_scope_required}

  def extend_expiry(_jti, _expires_at),
    do: {:error, :unsupported_legacy_expiry_extension}

  defp get_exact(jti, agent_id, organization_id)
       when is_binary(jti) and byte_size(jti) > 0 and byte_size(jti) <= @maximum_jti_bytes do
    case Repo.one(
           from(c in AgentCredential,
             where:
               c.jti == ^jti and c.agent_id == ^agent_id and
                 c.organization_id == ^organization_id
           )
         ) do
      nil -> {:error, :credential_not_found}
      credential -> {:ok, credential}
    end
  end

  defp get_exact(_jti, _agent_id, _organization_id), do: {:error, :invalid_jti}

  defp get_locked(jti, agent_id, organization_id)
       when is_binary(jti) and byte_size(jti) > 0 and byte_size(jti) <= @maximum_jti_bytes do
    case Repo.one(
           from(c in AgentCredential,
             where:
               c.jti == ^jti and c.agent_id == ^agent_id and
                 c.organization_id == ^organization_id,
             lock: "FOR UPDATE"
           )
         ) do
      nil -> {:error, :credential_not_found}
      credential -> {:ok, credential}
    end
  end

  defp get_locked(_jti, _agent_id, _organization_id), do: {:error, :invalid_jti}

  defp lock_agent(agent_id, organization_id) do
    case Repo.one(
           from(a in Agent,
             where: a.id == ^agent_id and a.organization_id == ^organization_id,
             lock: "FOR UPDATE"
           )
         ) do
      nil -> {:error, :agent_not_found}
      agent -> {:ok, agent}
    end
  end

  defp lock_organization(organization_id) do
    case Repo.one(
           from(o in Organization,
             where: o.id == ^organization_id,
             lock: "FOR UPDATE"
           )
         ) do
      nil -> {:error, :organization_not_found}
      organization -> {:ok, organization}
    end
  end

  defp stats_in_scope(agent_id, organization_id) do
    now = DateTime.utc_now()

    stats =
      from(c in AgentCredential,
        where: c.agent_id == ^agent_id and c.organization_id == ^organization_id,
        select: %{
          total: count(c.id),
          active:
            fragment(
              "COUNT(CASE WHEN ? IS NULL AND ? > ? THEN 1 END)",
              c.revoked_at,
              c.expires_at,
              ^now
            ),
          revoked: fragment("COUNT(CASE WHEN ? IS NOT NULL THEN 1 END)", c.revoked_at),
          expired:
            fragment(
              "COUNT(CASE WHEN ? IS NULL AND ? <= ? THEN 1 END)",
              c.revoked_at,
              c.expires_at,
              ^now
            ),
          total_uses: sum(c.use_count)
        }
      )
      |> Repo.one()

    last_used =
      from(c in AgentCredential,
        where:
          c.agent_id == ^agent_id and c.organization_id == ^organization_id and
            not is_nil(c.last_used_at),
        order_by: [desc: c.last_used_at],
        limit: 1,
        select: %{jti: c.jti, last_used_at: c.last_used_at, last_used_ip: c.last_used_ip}
      )
      |> Repo.one()

    Map.put(stats || %{}, :last_used, last_used)
  end

  defp with_identity(agent_id, organization_id, fun) do
    with {:ok, agent_id} <- canonical_uuid(agent_id, :invalid_agent_id),
         {:ok, organization_id} <- canonical_uuid(organization_id, :invalid_organization_id) do
      fun.(agent_id, organization_id)
    end
  end

  defp with_tenant(organization_id, fun) do
    case {Repo.get_organization_id(), Repo.in_transaction?()} do
      {nil, _in_transaction?} -> MultiTenant.with_organization(organization_id, fun)
      {^organization_id, true} -> fun.()
      {^organization_id, false} -> MultiTenant.with_organization(organization_id, fun)
      {_other, _in_transaction?} -> {:error, :cross_tenant_context}
    end
  rescue
    error ->
      Logger.error("Credential tenant operation failed: #{Exception.message(error)}")
      {:error, :database_error}
  end

  defp canonical_uuid(value, error) when is_binary(value) do
    case Ecto.UUID.cast(value) do
      {:ok, canonical} -> {:ok, canonical}
      :error -> {:error, error}
    end
  end

  defp canonical_uuid(_value, error), do: {:error, error}

  defp bounded_limit(opts, default, maximum) when is_list(opts) do
    case Keyword.get(opts, :limit, default) do
      limit when is_integer(limit) and limit > 0 and limit <= maximum -> {:ok, limit}
      _ -> {:error, :invalid_limit}
    end
  end

  defp bounded_limit(_opts, _default, _maximum), do: {:error, :invalid_options}

  defp validate_issue_options(opts) do
    allowed = [:jti, :issued_at, :expires_at, :ttl_hours, :ip_address, :issued_by_user_id]

    with :ok <- validate_options(opts, allowed),
         :ok <- validate_optional_bounded_string(opts[:jti], @maximum_jti_bytes, :invalid_jti),
         :ok <-
           validate_optional_bounded_string(
             opts[:ip_address],
             @maximum_ip_bytes,
             :invalid_ip_address
           ) do
      :ok
    end
  end

  defp validate_options(opts, allowed) when is_list(opts) do
    if Keyword.keyword?(opts) and Enum.all?(Keyword.keys(opts), &(&1 in allowed)),
      do: :ok,
      else: {:error, :invalid_options}
  end

  defp validate_options(_opts, _allowed), do: {:error, :invalid_options}

  defp validate_optional_bounded_string(nil, _maximum, _error), do: :ok

  defp validate_optional_bounded_string(value, maximum, _error)
       when is_binary(value) and byte_size(value) > 0 and byte_size(value) <= maximum,
       do: :ok

  defp validate_optional_bounded_string(_value, _maximum, error), do: {:error, error}

  defp validate_reason(reason)
       when is_binary(reason) and byte_size(reason) > 0 and
              byte_size(reason) <= @maximum_reason_bytes,
       do: :ok

  defp validate_reason(_reason), do: {:error, :invalid_revocation_reason}

  defp validate_retention_days(days) when is_integer(days) and days >= 1 and days <= 365, do: :ok
  defp validate_retention_days(_days), do: {:error, :invalid_retention_days}

  defp credential_issued_at(opts) do
    case Keyword.fetch(opts, :issued_at) do
      {:ok, %DateTime{} = issued_at} ->
        if DateTime.compare(issued_at, DateTime.utc_now()) in [:lt, :eq],
          do: {:ok, issued_at},
          else: {:error, :invalid_credential_issued_at}

      {:ok, _invalid} ->
        {:error, :invalid_credential_issued_at}

      :error ->
        {:ok, DateTime.utc_now()}
    end
  end

  defp credential_expiry(now, opts) do
    case Keyword.fetch(opts, :expires_at) do
      {:ok, %DateTime{} = expires_at} ->
        if DateTime.compare(expires_at, now) == :gt,
          do: {:ok, expires_at},
          else: {:error, :invalid_credential_expiry}

      {:ok, _invalid} ->
        {:error, :invalid_credential_expiry}

      :error ->
        case Keyword.get(opts, :ttl_hours, @default_ttl_hours) do
          ttl_hours
          when is_integer(ttl_hours) and ttl_hours > 0 and ttl_hours <= @maximum_ttl_hours ->
            ttl_hours = max(ttl_hours, @minimum_ttl_hours)
            {:ok, DateTime.add(now, ttl_hours * 3600, :second)}

          _invalid ->
            {:error, :invalid_credential_ttl}
        end
    end
  end

  defp generate_jti do
    :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  end

  defp audit_credential_event(action, credential, opts) do
    credential_reference = credential_reference(credential.jti)

    Audit.log_event(%{
      event_type: "agent_credential_#{action}",
      actor_type: if(opts[:issued_by_user_id], do: "user", else: "system"),
      actor_id: opts[:issued_by_user_id],
      resource_type: "agent_credential",
      resource_id: credential_reference,
      metadata: %{
        agent_id: credential.agent_id,
        organization_id: credential.organization_id,
        credential_reference: credential_reference,
        expires_at: credential.expires_at,
        ip_address: opts[:ip_address] || credential.issued_from_ip,
        reason: opts[:reason]
      }
    })
  rescue
    error -> Logger.warning("Failed to audit credential event: #{Exception.message(error)}")
  end

  defp audit_validation_failure(jti, agent_id, organization_id, reason) do
    credential_reference = credential_reference(jti)

    Audit.log_event(%{
      event_type: "agent_credential_validation_failed",
      actor_type: "system",
      resource_type: "agent_credential",
      resource_id: credential_reference,
      metadata: %{
        agent_id: agent_id,
        organization_id: organization_id,
        credential_reference: credential_reference,
        failure_reason: reason
      }
    })
  rescue
    error -> Logger.warning("Failed to audit validation failure: #{Exception.message(error)}")
  end

  defp audit_bulk_revocation(agent_id, organization_id, count, reason) do
    Audit.log_event(%{
      event_type: "agent_credentials_bulk_revoked",
      actor_type: "system",
      resource_type: "agent",
      resource_id: agent_id,
      metadata: %{
        agent_id: agent_id,
        organization_id: organization_id,
        revoked_count: count,
        reason: reason
      }
    })
  rescue
    error -> Logger.warning("Failed to audit bulk revocation: #{Exception.message(error)}")
  end

  defp audit_org_revocation(organization_id, count, reason) do
    Audit.log_event(%{
      event_type: "organization_agent_credentials_revoked",
      actor_type: "system",
      resource_type: "organization",
      resource_id: organization_id,
      metadata: %{organization_id: organization_id, revoked_count: count, reason: reason}
    })
  rescue
    error ->
      Logger.warning("Failed to audit organization revocation: #{Exception.message(error)}")
  end

  # A JTI identifies a live bearer credential and must not be copied verbatim
  # into the longer-lived audit surface. The digest remains stable for
  # correlation without disclosing the presented identifier.
  defp credential_reference(jti)
       when is_binary(jti) and byte_size(jti) > 0 and byte_size(jti) <= @maximum_jti_bytes do
    :crypto.hash(:sha256, jti) |> Base.encode16(case: :lower)
  end

  defp credential_reference(_invalid_jti), do: "invalid"
end
