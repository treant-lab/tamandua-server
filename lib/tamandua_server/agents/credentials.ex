defmodule TamanduaServer.Agents.Credentials do
  @moduledoc """
  Context module for managing agent credentials.

  Provides DB-backed credential validation for agent WebSocket connections
  as required by ACCOUNT_INTEGRITY_THREAT_MODEL.md:

  - Validate token against DB-backed agent credential record
  - Check active/not-revoked status, org binding, token jti
  - Update last_used_at on successful validation
  - Issue and revoke credentials with audit trail

  ## Usage

      # Validate a token's jti during socket connect
      case Credentials.validate_and_record_use(jti, agent_id, org_id, peer_ip) do
        {:ok, credential} -> # proceed with connection
        {:error, :credential_not_found} -> # reject
        {:error, :credential_revoked} -> # reject
        {:error, :credential_expired} -> # reject
        {:error, :org_mismatch} -> # reject
        {:error, :agent_mismatch} -> # reject
      end

      # Revoke a credential
      Credentials.revoke(jti, "compromised_agent")

      # Revoke all credentials for an agent
      Credentials.revoke_all_for_agent(agent_id, "agent_decommissioned")
  """

  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Agents.AgentCredential
  alias TamanduaServer.Audit
  import Ecto.Query

  @default_ttl_hours 720
  @minimum_ttl_hours 720

  @doc """
  Issue a new credential for an agent.

  Returns {:ok, jti, credential} or {:error, changeset}.
  """
  def issue_credential(agent_id, organization_id, opts \\ []) do
    jti = Keyword.get(opts, :jti) || generate_jti()
    now = DateTime.utc_now()

    ttl_hours = Keyword.get(opts, :ttl_hours, @default_ttl_hours) |> max(@minimum_ttl_hours)
    expires_at = DateTime.add(now, ttl_hours * 3600, :second)

    attrs = %{
      agent_id: agent_id,
      organization_id: organization_id,
      jti: jti,
      issued_at: now,
      expires_at: expires_at,
      issued_from_ip: Keyword.get(opts, :ip_address),
      issued_by_user_id: Keyword.get(opts, :issued_by_user_id)
    }

    case %AgentCredential{}
         |> AgentCredential.changeset(attrs)
         |> Repo.insert() do
      {:ok, credential} ->
        audit_credential_event(:issue, credential, opts)
        Logger.info("Issued credential #{jti} for agent #{agent_id}")
        {:ok, jti, credential}

      {:error, changeset} ->
        Logger.error("Failed to issue credential for agent #{agent_id}: #{inspect(changeset.errors)}")
        {:error, changeset}
    end
  end

  @doc """
  Validate a credential by jti and record its use.

  This is the main validation function called during socket connect.
  Returns {:ok, credential} or {:error, reason}.
  """
  def validate_and_record_use(jti, agent_id, organization_id, peer_ip \\ nil) do
    case get_by_jti(jti) do
      nil ->
        Logger.warning("Credential not found: jti=#{jti}")
        {:error, :credential_not_found}

      credential ->
        with :ok <- validate_ownership(credential, agent_id, organization_id),
             :ok <- AgentCredential.validate(credential) do
          # Update usage tracking
          {:ok, updated} =
            credential
            |> AgentCredential.usage_changeset(peer_ip)
            |> Repo.update()

          {:ok, updated}
        else
          {:error, reason} = error ->
            audit_validation_failure(jti, agent_id, reason)
            error
        end
    end
  end

  @doc """
  Validate a credential by jti without updating usage.
  Used for quick validation checks.
  """
  def validate(jti, agent_id, organization_id) do
    case get_by_jti(jti) do
      nil ->
        {:error, :credential_not_found}

      credential ->
        with :ok <- validate_ownership(credential, agent_id, organization_id),
             :ok <- AgentCredential.validate(credential) do
          {:ok, credential}
        end
    end
  end

  @doc """
  Check if a credential exists and is valid (not revoked, not expired).
  Does not update usage tracking.
  """
  def valid?(jti) do
    case get_by_jti(jti) do
      nil -> false
      credential -> AgentCredential.validate(credential) == :ok
    end
  end

  @doc """
  Revoke a credential by jti.
  """
  def revoke(jti, reason \\ "manual_revocation") do
    case get_by_jti(jti) do
      nil ->
        {:error, :not_found}

      credential ->
        {:ok, revoked} =
          credential
          |> AgentCredential.revoke_changeset(reason)
          |> Repo.update()

        audit_credential_event(:revoke, revoked, %{reason: reason})
        Logger.info("Revoked credential #{jti}, reason: #{reason}")
        {:ok, revoked}
    end
  end

  @doc """
  Revoke all credentials for an agent.
  Returns the count of revoked credentials.
  """
  def revoke_all_for_agent(agent_id, reason \\ "agent_credentials_revoked") do
    now = DateTime.utc_now()

    {count, _} =
      from(c in AgentCredential,
        where: c.agent_id == ^agent_id and is_nil(c.revoked_at)
      )
      |> Repo.update_all(set: [revoked_at: now, revocation_reason: reason])

    if count > 0 do
      audit_bulk_revocation(agent_id, count, reason)
      Logger.info("Revoked #{count} credentials for agent #{agent_id}, reason: #{reason}")
    end

    {:ok, count}
  end

  @doc """
  Revoke all credentials for an organization.
  Used when an organization is suspended or compromised.
  """
  def revoke_all_for_organization(organization_id, reason \\ "organization_credentials_revoked") do
    now = DateTime.utc_now()

    {count, _} =
      from(c in AgentCredential,
        where: c.organization_id == ^organization_id and is_nil(c.revoked_at)
      )
      |> Repo.update_all(set: [revoked_at: now, revocation_reason: reason])

    if count > 0 do
      Logger.warning("Revoked #{count} credentials for organization #{organization_id}, reason: #{reason}")
    end

    {:ok, count}
  end

  @doc """
  Get a credential by jti.
  """
  def get_by_jti(jti) do
    Repo.get_by(AgentCredential, jti: jti)
  end

  @doc """
  Extend the expiry for an active credential.

  Token refresh keeps the same JTI, so the DB-backed credential must remain
  aligned with the refreshed JWT expiry used by socket authentication.
  """
  def extend_expiry(jti, expires_at) do
    case get_by_jti(jti) do
      nil ->
        {:error, :not_found}

      credential ->
        credential
        |> Ecto.Changeset.change(expires_at: expires_at)
        |> Repo.update()
    end
  end

  @doc """
  List active credentials for an agent.
  """
  def list_active_for_agent(agent_id) do
    now = DateTime.utc_now()

    from(c in AgentCredential,
      where: c.agent_id == ^agent_id and
             is_nil(c.revoked_at) and
             c.expires_at > ^now,
      order_by: [desc: c.issued_at]
    )
    |> Repo.all()
  end

  @doc """
  Clean up expired credentials older than the specified days.
  """
  def cleanup_expired(older_than_days \\ 30) do
    cutoff = DateTime.utc_now() |> DateTime.add(-older_than_days * 24 * 3600, :second)

    {count, _} =
      from(c in AgentCredential,
        where: c.expires_at < ^cutoff
      )
      |> Repo.delete_all()

    if count > 0 do
      Logger.info("Cleaned up #{count} expired credentials older than #{older_than_days} days")
    end

    {:ok, count}
  end

  @doc """
  Get credential statistics for an agent.
  """
  def get_stats(agent_id) do
    now = DateTime.utc_now()

    stats =
      from(c in AgentCredential,
        where: c.agent_id == ^agent_id,
        select: %{
          total: count(c.id),
          active: fragment("COUNT(CASE WHEN ? IS NULL AND ? > ? THEN 1 END)",
                           c.revoked_at, c.expires_at, ^now),
          revoked: fragment("COUNT(CASE WHEN ? IS NOT NULL THEN 1 END)", c.revoked_at),
          expired: fragment("COUNT(CASE WHEN ? IS NULL AND ? <= ? THEN 1 END)",
                           c.revoked_at, c.expires_at, ^now),
          total_uses: sum(c.use_count)
        }
      )
      |> Repo.one()

    # Get last used credential
    last_used =
      from(c in AgentCredential,
        where: c.agent_id == ^agent_id and not is_nil(c.last_used_at),
        order_by: [desc: c.last_used_at],
        limit: 1,
        select: %{
          jti: c.jti,
          last_used_at: c.last_used_at,
          last_used_ip: c.last_used_ip
        }
      )
      |> Repo.one()

    Map.put(stats || %{}, :last_used, last_used)
  end

  # Private functions

  defp generate_jti do
    # Generate a cryptographically secure random JTI
    :crypto.strong_rand_bytes(32)
    |> Base.url_encode64(padding: false)
  end

  defp validate_ownership(credential, agent_id, organization_id) do
    cond do
      credential.agent_id != agent_id ->
        Logger.warning("Credential agent mismatch: expected #{agent_id}, got #{credential.agent_id}")
        {:error, :agent_mismatch}

      credential.organization_id != organization_id ->
        Logger.warning("Credential org mismatch: expected #{organization_id}, got #{credential.organization_id}")
        {:error, :org_mismatch}

      true ->
        :ok
    end
  end

  defp audit_credential_event(action, credential, opts) do
    Audit.log_event(%{
      event_type: "agent_credential_#{action}",
      actor_type: if(opts[:issued_by_user_id], do: "user", else: "system"),
      actor_id: opts[:issued_by_user_id],
      resource_type: "agent_credential",
      resource_id: credential.jti,
      metadata: %{
        agent_id: credential.agent_id,
        organization_id: credential.organization_id,
        jti: credential.jti,
        expires_at: credential.expires_at,
        ip_address: opts[:ip_address] || credential.issued_from_ip,
        reason: opts[:reason]
      }
    })
  rescue
    e ->
      Logger.warning("Failed to audit credential event: #{Exception.message(e)}")
  end

  defp audit_validation_failure(jti, agent_id, reason) do
    Audit.log_event(%{
      event_type: "agent_credential_validation_failed",
      actor_type: "system",
      resource_type: "agent_credential",
      resource_id: jti,
      metadata: %{
        agent_id: agent_id,
        jti: jti,
        failure_reason: reason
      }
    })
  rescue
    e ->
      Logger.warning("Failed to audit validation failure: #{Exception.message(e)}")
  end

  defp audit_bulk_revocation(agent_id, count, reason) do
    Audit.log_event(%{
      event_type: "agent_credentials_bulk_revoked",
      actor_type: "system",
      resource_type: "agent",
      resource_id: agent_id,
      metadata: %{
        agent_id: agent_id,
        revoked_count: count,
        reason: reason
      }
    })
  rescue
    e ->
      Logger.warning("Failed to audit bulk revocation: #{Exception.message(e)}")
  end
end
