defmodule TamanduaServer.Solana.FleetHealthAttestation do
  @moduledoc """
  Fleet-level "Proof of Health" attestation service for Tamandua EDR.

  This GenServer periodically collects aggregate health metrics from all
  connected agents and publishes a privacy-preserving attestation to Solana
  devnet. This provides cryptographic proof that the EDR fleet was monitored
  and healthy at a given point in time.

  ## Features

  - Periodic health attestations (default: hourly)
  - Privacy-preserving: only aggregate counts and hashes, no PII
  - Manual trigger support for on-demand attestation
  - Coverage metrics (healthy/total agents ratio)
  - Version distribution tracking

  ## Privacy Guarantees

  **What DOES go on-chain:**
  - Fleet hash: SHA256 of all agent pseudonyms + metrics
  - Agent count: Total number of agents monitored
  - Healthy count: Number of agents in healthy state
  - Coverage percentage: Healthy/total ratio
  - OS distribution (counts only): {"windows": 10, "linux": 5, "macos": 2}
  - Version distribution (counts only): {"1.0.0": 12, "0.9.0": 5}
  - Timestamp: When the attestation was created

  **What NEVER goes on-chain:**
  - Agent IDs or pseudonyms
  - Hostnames
  - IP addresses
  - Individual agent health details
  - Any PII

  ## Configuration

      config :tamandua_server, TamanduaServer.Solana.FleetHealthAttestation,
        enabled: true,
        interval_hours: 1,
        min_agents_for_attestation: 1

  ## Usage

      # Start with default options (via supervision tree)
      FleetHealthAttestation.start_link([])

      # Manually trigger an attestation
      {:ok, result} = FleetHealthAttestation.attest_now()

      # Get current fleet health status
      {:ok, status} = FleetHealthAttestation.get_fleet_status()

      # Get last attestation info
      {:ok, attestation} = FleetHealthAttestation.get_last_attestation()
  """

  use GenServer
  require Logger

  alias TamanduaServer.Agents.Registry
  alias TamanduaServer.Agents.HealthMonitor
  alias TamanduaServer.Solana.Client, as: SolanaClient

  # Default interval: 1 hour
  @default_min_agents 1

  defstruct [
    :interval_ms,
    :min_agents,
    :last_attestation,
    :last_attestation_at,
    :last_signature,
    :enabled
  ]

  # ===========================================================================
  # Client API
  # ===========================================================================

  @doc """
  Starts the FleetHealthAttestation GenServer.
  """
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Manually trigger a fleet health attestation.

  Returns `{:ok, %{signature: ..., attestation: ...}}` on success,
  or `{:error, reason}` on failure.
  """
  @spec attest_now() :: {:ok, map()} | {:error, term()}
  def attest_now do
    GenServer.call(__MODULE__, :attest_now, 60_000)
  end

  @doc """
  Get the current fleet health status without creating an attestation.

  Returns aggregate metrics for all connected agents.
  """
  @spec get_fleet_status() :: {:ok, map()}
  def get_fleet_status do
    GenServer.call(__MODULE__, :get_fleet_status)
  end

  @doc """
  Get information about the last successful attestation.
  """
  @spec get_last_attestation() :: {:ok, map()} | {:error, :no_attestation}
  def get_last_attestation do
    GenServer.call(__MODULE__, :get_last_attestation)
  end

  @doc """
  Get the Solscan URL for the last attestation transaction.
  """
  @spec get_last_solscan_url() :: {:ok, String.t()} | {:error, :no_attestation}
  def get_last_solscan_url do
    GenServer.call(__MODULE__, :get_last_solscan_url)
  end

  @doc """
  Check if fleet attestation is enabled.
  """
  @spec enabled?() :: boolean()
  def enabled? do
    GenServer.call(__MODULE__, :enabled?)
  end

  # ===========================================================================
  # Server Callbacks
  # ===========================================================================

  @impl true
  def init(_opts) do
    config = Application.get_env(:tamandua_server, __MODULE__, [])
    configured_enabled = Keyword.get(config, :enabled, true)
    signer_available? = solana_signer_available?()
    enabled = configured_enabled and signer_available?
    interval_hours = Keyword.get(config, :interval_hours, 1)
    interval_ms = :timer.hours(interval_hours)
    min_agents = Keyword.get(config, :min_agents_for_attestation, @default_min_agents)

    state = %__MODULE__{
      interval_ms: interval_ms,
      min_agents: min_agents,
      last_attestation: nil,
      last_attestation_at: nil,
      last_signature: nil,
      enabled: enabled
    }

    if enabled do
      Logger.info("[FleetHealthAttestation] Starting with interval: #{interval_hours} hour(s)")
      # Schedule first attestation after initial delay (5 minutes) to allow agents to connect
      Process.send_after(self(), :initial_attestation, :timer.minutes(5))
    else
      if configured_enabled and not signer_available? do
        Logger.warning("[FleetHealthAttestation] Disabled because Solana signer keypair is unavailable")
      else
        Logger.info("[FleetHealthAttestation] Disabled by configuration")
      end
    end

    {:ok, state}
  end

  defp solana_signer_available? do
    try do
      case SolanaClient.get_signer_pubkey() do
        {:ok, _pubkey} -> true
        _ -> false
      end
    rescue
      _ -> false
    catch
      :exit, _ -> false
    end
  end

  @impl true
  def handle_call(:attest_now, _from, %{enabled: false} = state) do
    {:reply, {:error, :fleet_attestation_disabled}, state}
  end

  @impl true
  def handle_call(:attest_now, _from, state) do
    case create_and_submit_attestation() do
      {:ok, result} ->
        new_state = %{state |
          last_attestation: result.attestation,
          last_attestation_at: DateTime.utc_now(),
          last_signature: result.signature
        }
        {:reply, {:ok, result}, new_state}

      {:error, _} = error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call(:get_fleet_status, _from, state) do
    status = collect_fleet_health()
    {:reply, {:ok, status}, state}
  end

  @impl true
  def handle_call(:get_last_attestation, _from, state) do
    if state.last_attestation do
      {:reply, {:ok, %{
        attestation: state.last_attestation,
        attested_at: state.last_attestation_at,
        signature: state.last_signature
      }}, state}
    else
      {:reply, {:error, :no_attestation}, state}
    end
  end

  @impl true
  def handle_call(:get_last_solscan_url, _from, state) do
    if state.last_signature do
      {:reply, {:ok, SolanaClient.solscan_url(state.last_signature)}, state}
    else
      {:reply, {:error, :no_attestation}, state}
    end
  end

  @impl true
  def handle_call(:enabled?, _from, state) do
    {:reply, state.enabled, state}
  end

  @impl true
  def handle_info(:initial_attestation, state) do
    # Run first attestation and schedule periodic ones
    state = handle_periodic_attestation(state)
    schedule_attestation(state.interval_ms)
    {:noreply, state}
  end

  @impl true
  def handle_info(:periodic_attestation, state) do
    state = handle_periodic_attestation(state)
    schedule_attestation(state.interval_ms)
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ===========================================================================
  # Private Functions
  # ===========================================================================

  defp schedule_attestation(interval_ms) do
    Process.send_after(self(), :periodic_attestation, interval_ms)
  end

  defp handle_periodic_attestation(state) do
    Logger.info("[FleetHealthAttestation] Running periodic fleet health attestation")

    case create_and_submit_attestation() do
      {:ok, result} ->
        Logger.info("[FleetHealthAttestation] Attestation successful: #{result.signature}")
        %{state |
          last_attestation: result.attestation,
          last_attestation_at: DateTime.utc_now(),
          last_signature: result.signature
        }

      {:error, reason} ->
        Logger.warning("[FleetHealthAttestation] Attestation failed: #{inspect(reason)}")
        state
    end
  end

  defp create_and_submit_attestation do
    fleet_health = collect_fleet_health()

    if fleet_health.total_agents < 1 do
      Logger.debug("[FleetHealthAttestation] No agents connected, skipping attestation")
      {:error, :no_agents}
    else
      attestation = build_attestation(fleet_health)
      params = build_solana_params(attestation)

      case SolanaClient.submit_attestation(params) do
        {:ok, signature} ->
          Logger.info("[FleetHealthAttestation] Fleet health attested on Solana: #{signature}")
          {:ok, %{signature: signature, attestation: attestation}}

        {:error, reason} = error ->
          Logger.error("[FleetHealthAttestation] Failed to attest: #{inspect(reason)}")
          error
      end
    end
  end

  @doc false
  def collect_fleet_health do
    # Get all registered agents from ETS registry
    agents = Registry.list_all()

    # Get health stats from HealthMonitor
    health_stats = case HealthMonitor.get_stats() do
      {:ok, stats} -> stats
      _ -> %{}
    end

    # Count agents by status
    status_counts = Enum.reduce(agents, %{online: 0, offline: 0, isolated: 0}, fn agent, acc ->
      status = agent[:status] || :offline
      Map.update(acc, status, 1, &(&1 + 1))
    end)

    # Count by OS type
    os_distribution = agents
      |> Enum.group_by(&(&1[:os_type] || "unknown"))
      |> Enum.map(fn {os, list} -> {os, length(list)} end)
      |> Map.new()

    # Count by version
    version_distribution = agents
      |> Enum.group_by(&(&1[:agent_version] || "unknown"))
      |> Enum.map(fn {ver, list} -> {ver, length(list)} end)
      |> Map.new()

    # Calculate coverage metrics
    total = length(agents)
    healthy = status_counts[:online] || 0
    coverage_pct = if total > 0, do: Float.round(healthy / total * 100, 1), else: 0.0

    # Get agent pseudonyms for fleet hash (privacy-preserving)
    agent_pseudonyms = agents
      |> Enum.map(&(&1[:agent_id]))
      |> Enum.reject(&is_nil/1)
      |> Enum.sort()
      |> Enum.map(&pseudonymize/1)

    %{
      timestamp: DateTime.utc_now(),
      total_agents: total,
      healthy_agents: healthy,
      offline_agents: status_counts[:offline] || 0,
      isolated_agents: status_counts[:isolated] || 0,
      coverage_percentage: coverage_pct,
      os_distribution: os_distribution,
      version_distribution: version_distribution,
      agent_pseudonyms: agent_pseudonyms,
      # From HealthMonitor stats
      average_health_score: Map.get(health_stats, :average_health_score, 0),
      critical_count: Map.get(health_stats, :critical, 0),
      warning_count: Map.get(health_stats, :warning, 0)
    }
  end

  defp build_attestation(fleet_health) do
    # Compute a deterministic fleet hash from all agent pseudonyms and metrics
    fleet_hash = compute_fleet_hash(fleet_health)

    %{
      schema: "tamandua.fleet_health",
      version: 1,
      type: "fleet_health_proof",
      timestamp: fleet_health.timestamp,
      fleet_hash: fleet_hash,
      metrics: %{
        total_agents: fleet_health.total_agents,
        healthy_agents: fleet_health.healthy_agents,
        offline_agents: fleet_health.offline_agents,
        isolated_agents: fleet_health.isolated_agents,
        coverage_percentage: fleet_health.coverage_percentage,
        average_health_score: fleet_health.average_health_score,
        critical_count: fleet_health.critical_count,
        warning_count: fleet_health.warning_count
      },
      distributions: %{
        os: sanitize_distribution(fleet_health.os_distribution),
        version: sanitize_distribution(fleet_health.version_distribution)
      },
      privacy: %{
        assertion: "aggregate_fleet_metrics_only",
        excludes: ["agent_ids", "hostnames", "ip_addresses", "individual_health"]
      }
    }
  end

  defp compute_fleet_hash(fleet_health) do
    # Create a deterministic hash from:
    # - Sorted list of agent pseudonyms
    # - Aggregate metrics
    # - Timestamp (Unix)
    payload = [
      # Agent pseudonyms (already hashed)
      Enum.join(fleet_health.agent_pseudonyms, ","),
      # Metrics
      to_string(fleet_health.total_agents),
      to_string(fleet_health.healthy_agents),
      to_string(fleet_health.offline_agents),
      to_string(fleet_health.isolated_agents),
      to_string(fleet_health.coverage_percentage),
      to_string(fleet_health.average_health_score),
      # Timestamp
      DateTime.to_unix(fleet_health.timestamp) |> to_string()
    ]
    |> Enum.join("|")

    :crypto.hash(:sha256, payload)
    |> Base.encode16(case: :lower)
  end

  defp build_solana_params(attestation) do
    fleet_hash = Base.decode16!(attestation.fleet_hash, case: :lower)
    metrics = attestation.metrics

    %{
      attestation_type: "fleet_health",
      posture_hash: fleet_hash,
      # Use a fleet-level pseudonym (hash of "tamandua_fleet")
      org_pseudonym: :crypto.hash(:sha256, "tamandua_fleet"),
      agent_pseudonym: :crypto.hash(:sha256, "fleet_aggregate"),
      timestamp: attestation.timestamp,
      posture_status: compute_fleet_status(metrics),
      # Pack fleet metrics into available fields
      critical_alerts: metrics.critical_count,
      high_alerts: metrics.warning_count,
      active_alerts: metrics.total_agents,
      window_hours: 1,
      policy_profile: format_fleet_summary(metrics)
    }
  end

  defp compute_fleet_status(metrics) do
    coverage = metrics.coverage_percentage

    cond do
      metrics.critical_count > 0 -> "critical"
      coverage < 50.0 -> "degraded"
      coverage < 80.0 -> "partial"
      true -> "healthy"
    end
  end

  defp format_fleet_summary(metrics) do
    # Create a compact summary that fits in policy_profile field
    "#{metrics.healthy_agents}/#{metrics.total_agents}@#{metrics.coverage_percentage}%"
  end

  defp sanitize_distribution(dist) when is_map(dist) do
    # Only include counts, no identifying info
    dist
    |> Enum.map(fn {key, count} ->
      {sanitize_key(key), count}
    end)
    |> Map.new()
  end

  defp sanitize_key(key) when is_binary(key) do
    key
    |> String.downcase()
    |> String.slice(0, 20)
  end
  defp sanitize_key(key), do: to_string(key) |> sanitize_key()

  defp pseudonymize(agent_id) when is_binary(agent_id) do
    :crypto.hash(:sha256, agent_id)
    |> Base.encode16(case: :lower)
    |> String.slice(0, 12)
  end
  defp pseudonymize(_), do: "unknown"
end
