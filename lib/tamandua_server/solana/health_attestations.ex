defmodule TamanduaServer.Solana.HealthAttestations do
  @moduledoc """
  Context module for managing health attestations.

  Health attestations provide a privacy-preserving on-chain proof that an
  endpoint was monitored for a given time window, including aggregate security
  metrics (alert counts by severity).

  ## Usage

      # Create an attestation for an agent
      {:ok, attestation} = HealthAttestations.create_attestation(agent_id)

      # Submit the attestation to Solana
      {:ok, updated} = HealthAttestations.attest_to_solana(attestation)

      # Get the latest attestation for an agent
      attestation = HealthAttestations.get_latest_for_agent(agent_id)

      # List recent attestations
      attestations = HealthAttestations.list_recent_attestations(10)
  """

  import Ecto.Query, warn: false
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Agents
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Agents.Registry
  alias TamanduaServer.Solana.HealthAttestation
  alias TamanduaServer.Solana.Client, as: SolanaClient

  @default_window_hours 24

  # --------------------------------------------------------------------------
  # Public API
  # --------------------------------------------------------------------------

  @doc """
  Creates a health attestation for an agent based on their last 24 hours of data.

  This function:
  1. Looks up the agent in the database
  2. Fetches alert counts from the last window_hours
  3. Gets the agent's current policy profile
  4. Generates a pseudonym from the agent_id
  5. Creates a health hash of all fields
  6. Persists the attestation record

  ## Options
  - `:window_hours` - Time window for alert aggregation (default: 24)

  ## Examples

      iex> create_attestation("agent-uuid-123")
      {:ok, %HealthAttestation{}}

      iex> create_attestation("nonexistent-agent")
      {:error, :agent_not_found}
  """
  @spec create_attestation(String.t(), keyword()) :: {:ok, HealthAttestation.t()} | {:error, term()}
  def create_attestation(agent_id, opts \\ []) do
    window_hours = Keyword.get(opts, :window_hours, @default_window_hours)

    with {:ok, agent} <- get_agent(agent_id),
         alert_counts <- count_alerts_in_window(agent_id, window_hours),
         policy_profile <- get_policy_profile(agent),
         last_seen <- get_last_seen(agent),
         pseudonym <- generate_pseudonym(agent_id),
         health_hash <- compute_health_hash(pseudonym, window_hours, alert_counts, policy_profile, last_seen) do
      attrs = %{
        agent_id: agent_id,
        organization_id: agent.organization_id,
        agent_pseudonym: pseudonym,
        window_hours: window_hours,
        critical_alerts: alert_counts.critical,
        high_alerts: alert_counts.high,
        medium_alerts: alert_counts.medium,
        low_alerts: alert_counts.low,
        last_seen: last_seen,
        policy_profile: policy_profile,
        health_hash: health_hash
      }

      %HealthAttestation{}
      |> HealthAttestation.changeset(attrs)
      |> Repo.insert()
    end
  end

  @doc """
  Submits an attestation to the Solana blockchain and updates the record.

  Returns the updated attestation with the Solana signature and attested_at timestamp.

  ## Examples

      iex> attest_to_solana(attestation)
      {:ok, %HealthAttestation{solana_signature: "5abc...", attested_at: ~U[2026-05-08 12:00:00Z]}}

      iex> attest_to_solana(attestation)
      {:error, :solana_disabled}
  """
  @spec attest_to_solana(HealthAttestation.t()) :: {:ok, HealthAttestation.t()} | {:error, term()}
  def attest_to_solana(%HealthAttestation{} = attestation) do
    params = build_solana_params(attestation)

    case SolanaClient.submit_attestation(params) do
      {:ok, signature} ->
        now = DateTime.utc_now() |> DateTime.truncate(:second)

        attestation
        |> HealthAttestation.solana_changeset(%{
          solana_signature: signature,
          attested_at: now
        })
        |> Repo.update()

      {:error, reason} = error ->
        Logger.error("[HealthAttestations] Failed to attest to Solana: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Creates an attestation and immediately submits it to Solana.

  This is a convenience function that combines `create_attestation/2` and `attest_to_solana/1`.

  ## Examples

      iex> create_and_attest(agent_id)
      {:ok, %HealthAttestation{solana_signature: "5abc..."}}
  """
  @spec create_and_attest(String.t(), keyword()) :: {:ok, HealthAttestation.t()} | {:error, term()}
  def create_and_attest(agent_id, opts \\ []) do
    with {:ok, attestation} <- create_attestation(agent_id, opts),
         {:ok, attested} <- attest_to_solana(attestation) do
      {:ok, attested}
    end
  end

  @doc """
  Gets the latest health attestation for an agent by agent_id.

  ## Examples

      iex> get_latest_for_agent("agent-uuid-123")
      %HealthAttestation{}

      iex> get_latest_for_agent("nonexistent")
      nil
  """
  @spec get_latest_for_agent(String.t()) :: HealthAttestation.t() | nil
  def get_latest_for_agent(agent_id) do
    HealthAttestation
    |> where([h], h.agent_id == ^agent_id)
    |> order_by([h], desc: h.inserted_at)
    |> limit(1)
    |> Repo.one()
  end

  @doc """
  Gets the latest health attestation for an agent by pseudonym.

  This is useful for public verification where the real agent_id is not known.

  ## Examples

      iex> get_latest_by_pseudonym("abc123def456")
      %HealthAttestation{}
  """
  @spec get_latest_by_pseudonym(String.t()) :: HealthAttestation.t() | nil
  def get_latest_by_pseudonym(pseudonym) do
    HealthAttestation
    |> where([h], h.agent_pseudonym == ^pseudonym)
    |> order_by([h], desc: h.inserted_at)
    |> limit(1)
    |> Repo.one()
  end

  @doc """
  Gets an attestation by its Solana signature.

  ## Examples

      iex> get_by_signature("5abc123...")
      %HealthAttestation{}
  """
  @spec get_by_signature(String.t()) :: HealthAttestation.t() | nil
  def get_by_signature(signature) when is_binary(signature) do
    HealthAttestation
    |> where([h], h.solana_signature == ^signature)
    |> Repo.one()
  end

  @doc """
  Lists recent health attestations with optional filtering.

  ## Options
  - `:limit` - Maximum number of results (default: 20, max: 100)
  - `:offset` - Offset for pagination (default: 0)
  - `:attested_only` - Only return attestations that have been submitted to Solana (default: false)
  - `:organization_id` - Filter by organization (for tenant-scoped queries)

  ## Examples

      iex> list_recent_attestations(10)
      [%HealthAttestation{}, ...]

      iex> list_recent_attestations(10, attested_only: true)
      [%HealthAttestation{solana_signature: "..."}, ...]
  """
  @spec list_recent_attestations(integer(), keyword()) :: [HealthAttestation.t()]
  def list_recent_attestations(limit \\ 20, opts \\ []) do
    limit = min(limit, 100)
    offset = Keyword.get(opts, :offset, 0)
    attested_only = Keyword.get(opts, :attested_only, false)
    organization_id = Keyword.get(opts, :organization_id)

    query =
      HealthAttestation
      |> order_by([h], desc: h.inserted_at)
      |> limit(^limit)
      |> offset(^offset)

    query =
      if attested_only do
        where(query, [h], not is_nil(h.solana_signature))
      else
        query
      end

    query =
      if organization_id do
        where(query, [h], h.organization_id == ^organization_id)
      else
        query
      end

    Repo.all(query)
  end

  @doc """
  Lists attestations for an organization (tenant-scoped).

  ## Options
  - `:limit` - Maximum number of results (default: 20)
  - `:offset` - Offset for pagination (default: 0)
  - `:attested_only` - Only return submitted attestations
  """
  @spec list_attestations_for_org(String.t(), keyword()) :: [HealthAttestation.t()]
  def list_attestations_for_org(organization_id, opts \\ []) do
    list_recent_attestations(
      Keyword.get(opts, :limit, 20),
      Keyword.put(opts, :organization_id, organization_id)
    )
  end

  @doc """
  Gets attestation statistics for an organization.

  Returns a map with counts and aggregations.
  """
  @spec get_stats_for_org(String.t()) :: map()
  def get_stats_for_org(organization_id) do
    query =
      from h in HealthAttestation,
        where: h.organization_id == ^organization_id,
        select: %{
          total: count(h.id),
          attested: count(h.solana_signature),
          pending: filter(count(h.id), is_nil(h.solana_signature)),
          avg_critical: avg(h.critical_alerts),
          avg_high: avg(h.high_alerts),
          total_critical: sum(h.critical_alerts),
          total_high: sum(h.high_alerts)
        }

    Repo.one(query) ||
      %{
        total: 0,
        attested: 0,
        pending: 0,
        avg_critical: 0,
        avg_high: 0,
        total_critical: 0,
        total_high: 0
      }
  end

  @doc """
  Gets a Solscan URL for an attestation's transaction.
  """
  @spec solscan_url(HealthAttestation.t()) :: String.t() | nil
  def solscan_url(%HealthAttestation{solana_signature: nil}), do: nil
  def solscan_url(%HealthAttestation{solana_signature: sig}), do: SolanaClient.solscan_url(sig)

  @doc """
  Verifies that a health hash matches the attestation data.

  This is useful for external verification of attestations.
  """
  @spec verify_health_hash(HealthAttestation.t()) :: boolean()
  def verify_health_hash(%HealthAttestation{} = attestation) do
    alert_counts = %{
      critical: attestation.critical_alerts,
      high: attestation.high_alerts,
      medium: attestation.medium_alerts,
      low: attestation.low_alerts
    }

    computed_hash = compute_health_hash(
      attestation.agent_pseudonym,
      attestation.window_hours,
      alert_counts,
      attestation.policy_profile,
      attestation.last_seen
    )

    computed_hash == attestation.health_hash
  end

  # --------------------------------------------------------------------------
  # Private Helpers
  # --------------------------------------------------------------------------

  defp get_agent(agent_id) do
    case Agents.get_agent(agent_id) do
      nil -> {:error, :agent_not_found}
      agent -> {:ok, agent}
    end
  end

  defp count_alerts_in_window(agent_id, window_hours) do
    cutoff = DateTime.add(DateTime.utc_now(), -window_hours, :hour)

    # Query alerts from the database for this agent in the time window
    query =
      from a in TamanduaServer.Alerts.Alert,
        where: a.agent_id == ^agent_id,
        where: a.inserted_at >= ^cutoff,
        group_by: a.severity,
        select: {a.severity, count(a.id)}

    counts =
      query
      |> Repo.all()
      |> Map.new()

    %{
      critical: Map.get(counts, "critical", 0),
      high: Map.get(counts, "high", 0),
      medium: Map.get(counts, "medium", 0),
      low: Map.get(counts, "low", 0)
    }
  end

  defp get_policy_profile(%Agent{config: config}) when is_map(config) do
    config["performance_profile"] ||
      config["profile"] ||
      config["policy_profile"] ||
      config[:performance_profile] ||
      config[:profile] ||
      config[:policy_profile] ||
      "balanced"
  end

  defp get_policy_profile(_), do: "balanced"

  defp get_last_seen(%Agent{last_seen_at: %NaiveDateTime{} = dt}) do
    DateTime.from_naive!(dt, "Etc/UTC")
  end

  defp get_last_seen(%Agent{id: agent_id}) do
    # Try to get from the ETS registry
    case Registry.get(agent_id) do
      {:ok, %{last_seen_at: ts}} when is_integer(ts) ->
        DateTime.from_unix!(div(ts, 1000), :second)

      _ ->
        DateTime.utc_now()
    end
  end

  @doc """
  Generates a pseudonym from an agent_id.

  The pseudonym is the first 12 hex characters of SHA256(agent_id).
  This provides privacy while allowing correlation of attestations for the same agent.
  """
  @spec generate_pseudonym(String.t()) :: String.t()
  def generate_pseudonym(agent_id) when is_binary(agent_id) do
    :crypto.hash(:sha256, agent_id)
    |> Base.encode16(case: :lower)
    |> String.slice(0, 12)
  end

  defp compute_health_hash(pseudonym, window_hours, alert_counts, policy_profile, last_seen) do
    # Create a deterministic payload for hashing
    payload =
      [
        pseudonym,
        to_string(window_hours),
        to_string(alert_counts.critical),
        to_string(alert_counts.high),
        to_string(alert_counts.medium),
        to_string(alert_counts.low),
        policy_profile,
        format_timestamp(last_seen)
      ]
      |> Enum.join("|")

    :crypto.hash(:sha256, payload)
    |> Base.encode16(case: :lower)
  end

  defp format_timestamp(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_timestamp(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
  defp format_timestamp(nil), do: "unknown"
  defp format_timestamp(ts) when is_integer(ts), do: DateTime.from_unix!(ts, :second) |> DateTime.to_iso8601()

  defp build_solana_params(%HealthAttestation{} = attestation) do
    %{
      attestation_type: "endpoint_health",
      posture_hash: Base.decode16!(attestation.health_hash, case: :lower),
      org_pseudonym: :crypto.hash(:sha256, attestation.organization_id || "unknown"),
      agent_pseudonym: :crypto.hash(:sha256, attestation.agent_pseudonym),
      timestamp: attestation.inserted_at,
      posture_status: compute_posture_status(attestation),
      critical_alerts: attestation.critical_alerts,
      high_alerts: attestation.high_alerts,
      active_alerts: attestation.critical_alerts + attestation.high_alerts,
      window_hours: attestation.window_hours,
      policy_profile: attestation.policy_profile
    }
  end

  defp compute_posture_status(%HealthAttestation{critical_alerts: c, high_alerts: h}) do
    cond do
      c > 0 -> "critical"
      h > 0 -> "at_risk"
      true -> "monitored"
    end
  end
end
