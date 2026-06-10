defmodule TamanduaServer.ThreatIntel.Feeds.SocketDev do
  @moduledoc """
  Socket.dev Threat Intelligence Feed Integration.

  Socket.dev provides real-time monitoring and detection of:
  - Malicious packages in npm, PyPI, cargo, rubygems, and Go ecosystems
  - Supply chain attacks and typosquatting attempts
  - Known vulnerabilities in package dependencies
  - Suspicious package behavior and risk scoring

  ## Configuration

      config :tamandua_server, TamanduaServer.ThreatIntel.Feeds.SocketDev,
        api_key: "YOUR_SOCKET_API_KEY",
        enabled: true,
        sync_interval_hours: 4

  ## API Access

  Requires Socket.dev API key. Sign up at https://socket.dev
  """

  use GenServer
  require Logger

  alias TamanduaServer.ThreatIntel.Aggregator

  @base_url "https://api.socket.dev"
  @default_sync_interval :timer.hours(4)
  @http_timeout 60_000
  @batch_size 50

  # Ecosystems to monitor
  @ecosystems ["npm", "pypi", "cargo", "rubygems", "go"]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Lookup a specific package for risk assessment.
  Returns malicious status, risk score, and reason if applicable.
  """
  @spec lookup(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def lookup(ecosystem, package_name) do
    GenServer.call(__MODULE__, {:lookup, ecosystem, package_name}, @http_timeout)
  end

  @doc """
  Trigger manual sync of all malicious packages.
  """
  @spec sync_all() :: :ok
  def sync_all do
    GenServer.cast(__MODULE__, :sync_all)
  end

  @doc """
  Get current feed status and statistics.
  """
  @spec get_status() :: map()
  def get_status do
    GenServer.call(__MODULE__, :get_status)
  end

  @doc """
  Convert Socket.dev package data to IOC format.
  Public for testing purposes.
  """
  @spec package_to_ioc(map()) :: map()
  def package_to_ioc(package) do
    ecosystem = package["ecosystem"] || "npm"
    name = package["name"] || ""
    version = package["version"] || "latest"
    risk_score = package["risk_score"] || 50

    %{
      type: "package_name",
      value: String.downcase("#{ecosystem}:#{name}@#{version}"),
      source: "socket_dev",
      severity: severity_from_score(risk_score),
      confidence: risk_score / 100.0,
      tags: ["supply_chain", ecosystem],
      metadata: %{
        "ecosystem" => ecosystem,
        "package_name" => name,
        "package_version" => version,
        "risk_score" => risk_score,
        "reason" => package["reason"] || "Malicious package detected"
      }
    }
  end

  @doc """
  Map Socket.dev risk score to severity level.
  Public for testing purposes.
  """
  @spec severity_from_score(integer()) :: String.t()
  def severity_from_score(score) when score >= 80, do: "critical"
  def severity_from_score(score) when score >= 60, do: "high"
  def severity_from_score(score) when score >= 40, do: "medium"
  def severity_from_score(_), do: "low"

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(opts) do
    state = %{
      api_key: Keyword.get(opts, :api_key) || System.get_env("SOCKET_API_KEY"),
      enabled: Keyword.get(opts, :enabled, true),
      sync_interval: Keyword.get(opts, :sync_interval, @default_sync_interval),
      last_sync: nil,
      stats: %{
        lookups: 0,
        packages_imported: 0,
        errors: 0
      }
    }

    # Update enabled flag based on API key presence
    state = %{state | enabled: state.enabled && state.api_key != nil}

    if state.enabled do
      # Schedule initial sync after 30 seconds
      Process.send_after(self(), :initial_sync, :timer.seconds(30))
      schedule_sync(state.sync_interval)
      Logger.info("[SocketDev] Initialized with API key configured")
    else
      Logger.info("[SocketDev] Disabled - no API key configured")
    end

    {:ok, state}
  end

  @impl true
  def handle_call({:lookup, ecosystem, package_name}, _from, state) do
    unless state.api_key do
      {:reply, {:error, :not_configured}, state}
    else
      result = do_lookup(ecosystem, package_name, state)
      new_stats = Map.update!(state.stats, :lookups, &(&1 + 1))
      {:reply, result, %{state | stats: new_stats}}
    end
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      enabled: state.enabled,
      configured: state.api_key != nil,
      last_sync: state.last_sync,
      stats: state.stats
    }
    {:reply, status, state}
  end

  @impl true
  def handle_cast(:sync_all, state) do
    if state.api_key do
      Task.start(fn -> fetch_malicious_packages(state) end)
      {:noreply, %{state | last_sync: DateTime.utc_now()}}
    else
      {:noreply, state}
    end
  end

  @impl true
  def handle_info(:initial_sync, state) do
    if state.api_key do
      Logger.info("[SocketDev] Starting initial sync...")
      Task.start(fn -> fetch_malicious_packages(state) end)
    end
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:periodic_sync, state) do
    if state.api_key do
      Logger.info("[SocketDev] Starting periodic sync...")
      Task.start(fn -> fetch_malicious_packages(state) end)
      schedule_sync(state.sync_interval)
    end
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions - API Calls
  # ============================================================================

  defp do_lookup(ecosystem, package_name, state) do
    # Socket.dev API endpoint for package score
    # Note: Actual endpoint structure may vary - this is based on common patterns
    url = "#{@base_url}/v0/#{ecosystem}/#{URI.encode(package_name)}/score"

    headers = [
      {"Authorization", "Bearer #{state.api_key}"},
      {"Accept", "application/json"}
    ]

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, data} ->
            risk_score = data["score"] || data["risk_score"] || 0
            malicious = risk_score >= 60

            {:ok, %{
              malicious: malicious,
              risk_score: risk_score,
              reason: data["reason"] || data["issues"] || "No issues detected"
            }}

          {:error, reason} ->
            {:error, {:parse_error, reason}}
        end

      {:ok, %Finch.Response{status: 404}} ->
        {:ok, %{malicious: false, risk_score: 0, reason: "Package not found"}}

      {:ok, %Finch.Response{status: 429}} ->
        Logger.warning("[SocketDev] Rate limit hit, backing off...")
        {:error, :rate_limited}

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_malicious_packages(state) do
    Logger.info("[SocketDev] Fetching malicious packages for all ecosystems...")

    total_imported = Enum.reduce(@ecosystems, 0, fn ecosystem, acc ->
      case fetch_ecosystem_packages(ecosystem, state) do
        {:ok, count} -> acc + count
        {:error, reason} ->
          Logger.error("[SocketDev] Failed to fetch #{ecosystem} packages: #{inspect(reason)}")
          acc
      end
    end)

    Logger.info("[SocketDev] Imported #{total_imported} malicious packages total")
    {:ok, total_imported}
  end

  defp fetch_ecosystem_packages(ecosystem, state) do
    # Socket.dev batch API endpoint
    # Note: Actual endpoint structure based on Socket.dev API documentation
    url = "#{@base_url}/v0/report/batch"

    headers = [
      {"Authorization", "Bearer #{state.api_key}"},
      {"Accept", "application/json"},
      {"Content-Type", "application/json"}
    ]

    body = Jason.encode!(%{
      "ecosystem" => ecosystem,
      "malicious_only" => true,
      "limit" => @batch_size
    })

    case Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: resp_body}} ->
        case Jason.decode(resp_body) do
          {:ok, %{"packages" => packages}} ->
            iocs = Enum.map(packages, &package_to_ioc/1)

            # Submit to aggregator
            Aggregator.ingest_batch("socket_dev", iocs)

            Logger.info("[SocketDev] Imported #{length(iocs)} #{ecosystem} packages")
            {:ok, length(iocs)}

          {:ok, _} ->
            {:ok, 0}

          {:error, reason} ->
            {:error, {:parse_error, reason}}
        end

      {:ok, %Finch.Response{status: 429}} ->
        # Rate limit - back off and retry
        Logger.warning("[SocketDev] Rate limit hit for #{ecosystem}, backing off...")
        Process.sleep(5000)
        fetch_ecosystem_packages(ecosystem, state)

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp schedule_sync(interval) do
    Process.send_after(self(), :periodic_sync, interval)
  end
end
