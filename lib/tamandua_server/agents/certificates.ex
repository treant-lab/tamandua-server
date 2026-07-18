defmodule TamanduaServer.Agents.Certificates do
  @moduledoc """
  Public API for managing agent certificates.

  This module provides functions for:
  - Listing certificates
  - Revoking certificates
  - Viewing certificate details
  - Certificate rotation
  """

  import Ecto.Query
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Agents.{AgentCertificate, RevokedCertificate, CertificateManager}

  @doc """
  Lists all agent certificates.
  """
  def list_certificates(filters \\ []) do
    query = from c in AgentCertificate

    query =
      Enum.reduce(filters, query, fn
        {:agent_id, agent_id}, q ->
          where(q, [c], c.agent_id == ^agent_id)

        {:pinned, pinned}, q ->
          where(q, [c], c.pinned == ^pinned)

        {:expired, true}, q ->
          now = DateTime.utc_now()
          where(q, [c], c.valid_until < ^now)

        {:expired, false}, q ->
          now = DateTime.utc_now()
          where(q, [c], c.valid_until >= ^now)

        _, q ->
          q
      end)

    query
    |> order_by([c], desc: c.last_seen_at)
    |> Repo.all()
    |> Repo.preload(:agent)
  end

  @doc """
  Gets a certificate by fingerprint.
  """
  def get_certificate(fingerprint) do
    AgentCertificate
    |> Repo.get_by(fingerprint: fingerprint)
    |> Repo.preload(:agent)
  end

  @doc """
  Gets all certificates for an agent.
  """
  def get_agent_certificates(agent_id) do
    from(c in AgentCertificate, where: c.agent_id == ^agent_id)
    |> order_by([c], desc: c.first_seen_at)
    |> Repo.all()
  end

  @doc """
  Revokes a certificate.

  ## Options
  - `:reason` - Reason for revocation (required)
  - `:revoked_by_id` - User ID who revoked the certificate
  - `:notes` - Additional notes about the revocation

  ## Reasons
  - "compromised" - Certificate or private key compromised
  - "rotation" - Normal certificate rotation
  - "decommissioned" - Agent decommissioned
  - "policy_violation" - Policy violation
  - "expired" - Certificate expired
  - "other" - Other reason
  """
  def revoke_certificate(fingerprint, opts \\ []) do
    with {:ok, _cert} <- get_certificate_result(fingerprint),
         :ok <- check_not_already_revoked(fingerprint),
         {:ok, revocation} <- CertificateManager.revoke_certificate(fingerprint, opts) do
      Logger.info("Certificate revoked: #{fingerprint}, reason: #{opts[:reason]}")
      {:ok, revocation}
    else
      {:error, :not_found} ->
        {:error, "Certificate not found"}

      {:error, :already_revoked} ->
        {:error, "Certificate already revoked"}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Lists all revoked certificates.
  """
  def list_revoked_certificates do
    from(r in RevokedCertificate)
    |> order_by([r], desc: r.revoked_at)
    |> Repo.all()
    |> Repo.preload([:agent, :revoked_by])
  end

  @doc """
  Gets a revoked certificate by fingerprint.
  """
  def get_revoked_certificate(fingerprint) do
    RevokedCertificate
    |> Repo.get_by(fingerprint: fingerprint)
    |> case do
      nil -> {:error, :not_found}
      cert -> {:ok, Repo.preload(cert, [:agent, :revoked_by])}
    end
  end

  @doc """
  Checks if a certificate is revoked.
  """
  def is_revoked?(fingerprint) do
    case Repo.get_by(RevokedCertificate, fingerprint: fingerprint) do
      nil -> false
      _ -> true
    end
  end

  @doc """
  Unpins a certificate (allows rotation).

  This doesn't revoke the certificate, but allows a new certificate to be pinned
  on the next connection.
  """
  def unpin_certificate(fingerprint) do
    case get_certificate(fingerprint) do
      nil ->
        {:error, :not_found}

      cert ->
        cert
        |> AgentCertificate.changeset(%{pinned: false})
        |> Repo.update()
    end
  end

  @doc """
  Gets certificate statistics.
  """
  def get_statistics do
    total = Repo.aggregate(AgentCertificate, :count)
    pinned = Repo.aggregate(from(c in AgentCertificate, where: c.pinned == true), :count)
    revoked = Repo.aggregate(RevokedCertificate, :count)

    now = DateTime.utc_now()
    expired = Repo.aggregate(
      from(c in AgentCertificate, where: c.valid_until < ^now),
      :count
    )

    expiring_soon = Repo.aggregate(
      from(c in AgentCertificate,
        where: c.valid_until < ^DateTime.add(now, 30, :day) and c.valid_until >= ^now
      ),
      :count
    )

    %{
      total: total,
      pinned: pinned,
      revoked: revoked,
      expired: expired,
      expiring_soon: expiring_soon
    }
  end

  @doc """
  Finds certificates expiring within the given number of days.
  """
  def find_expiring_certificates(days \\ 30) do
    now = DateTime.utc_now()
    expiry_threshold = DateTime.add(now, days, :day)

    from(c in AgentCertificate,
      where: c.valid_until >= ^now and c.valid_until < ^expiry_threshold,
      where: c.pinned == true
    )
    |> order_by([c], asc: c.valid_until)
    |> Repo.all()
    |> Repo.preload(:agent)
  end

  # Private functions

  defp get_certificate_result(fingerprint) do
    case get_certificate(fingerprint) do
      nil -> {:error, :not_found}
      cert -> {:ok, cert}
    end
  end

  defp check_not_already_revoked(fingerprint) do
    if is_revoked?(fingerprint) do
      {:error, :already_revoked}
    else
      :ok
    end
  end
end
