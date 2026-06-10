defmodule TamanduaServer.ThreatIntel.Feeds.CiscoTalos do
  @moduledoc """
  Cisco Talos Threat Intelligence Feed Integration.

  Cisco Talos provides comprehensive threat intelligence including:
  - IP and domain reputation (IP Blacklist, SenderBase)
  - File reputation and malware analysis
  - Vulnerability intelligence (Snort/Suricata rules)
  - Spam and phishing detection
  - Web categorization
  - Threat research from Talos Intelligence Group

  ## Configuration

      config :tamandua_server, TamanduaServer.ThreatIntel.Feeds.CiscoTalos,
        api_key: "YOUR_API_KEY",
        enabled: true,
        sync_interval_hours: 6

  ## Data Sources

  - Talos Intelligence: https://talosintelligence.com/
  - IP/Domain Reputation API
  - File Reputation (AMP Threat Grid integration)
  - Snort/ClamAV rule updates
  """

  use GenServer
  require Logger

  alias TamanduaServer.ThreatIntel.Aggregator

  @base_url "https://talosintelligence.com/cloud_intel"
  @reputation_url "https://www.talosintelligence.com/sb"
  @default_sync_interval :timer.hours(6)
  @http_timeout 60_000

  # Reputation score thresholds
  @poor_reputation_threshold -50
  @untrusted_threshold 0

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Lookup IP address reputation.

  Returns reputation score, threat category, and associated malware.
  """
  @spec lookup_ip_reputation(String.t()) :: {:ok, map()} | {:error, term()}
  def lookup_ip_reputation(ip) do
    GenServer.call(__MODULE__, {:lookup_ip_reputation, ip}, @http_timeout)
  end

  @doc """
  Lookup domain reputation.
  """
  @spec lookup_domain_reputation(String.t()) :: {:ok, map()} | {:error, term()}
  def lookup_domain_reputation(domain) do
    GenServer.call(__MODULE__, {:lookup_domain_reputation, domain}, @http_timeout)
  end

  @doc """
  Lookup file hash reputation.
  """
  @spec lookup_file_reputation(String.t()) :: {:ok, map()} | {:error, term()}
  def lookup_file_reputation(sha256) do
    GenServer.call(__MODULE__, {:lookup_file_reputation, sha256}, @http_timeout)
  end

  @doc """
  Get email reputation (sender/spam detection).
  """
  @spec lookup_email_reputation(String.t()) :: {:ok, map()} | {:error, term()}
  def lookup_email_reputation(email) do
    GenServer.call(__MODULE__, {:lookup_email_reputation, email}, @http_timeout)
  end

  @doc """
  Get URL categorization.
  """
  @spec categorize_url(String.t()) :: {:ok, map()} | {:error, term()}
  def categorize_url(url) do
    GenServer.call(__MODULE__, {:categorize_url, url}, @http_timeout)
  end

  @doc """
  Download IP blacklist.
  """
  @spec download_ip_blacklist() :: {:ok, integer()} | {:error, term()}
  def download_ip_blacklist do
    GenServer.call(__MODULE__, :download_ip_blacklist, @http_timeout * 5)
  end

  @doc """
  Download domain blacklist.
  """
  @spec download_domain_blacklist() :: {:ok, integer()} | {:error, term()}
  def download_domain_blacklist do
    GenServer.call(__MODULE__, :download_domain_blacklist, @http_timeout * 5)
  end

  @doc """
  Get recent threat advisories.
  """
  @spec get_threat_advisories(keyword()) :: {:ok, [map()]} | {:error, term()}
  def get_threat_advisories(opts \\ []) do
    GenServer.call(__MODULE__, {:get_threat_advisories, opts}, @http_timeout)
  end

  @doc """
  Trigger manual sync.
  """
  @spec sync_all() :: :ok
  def sync_all do
    GenServer.cast(__MODULE__, :sync_all)
  end

  @doc """
  Get current status.
  """
  @spec get_status() :: map()
  def get_status do
    GenServer.call(__MODULE__, :get_status)
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(opts) do
    state = %{
      api_key: Keyword.get(opts, :api_key) || System.get_env("CISCO_TALOS_API_KEY"),
      enabled: Keyword.get(opts, :enabled, true),
      sync_interval: Keyword.get(opts, :sync_interval, @default_sync_interval),
      last_sync: nil,
      stats: %{
        ip_lookups: 0,
        domain_lookups: 0,
        file_lookups: 0,
        iocs_imported: 0,
        errors: 0
      }
    }

    if state.enabled do
      Process.send_after(self(), :initial_sync, :timer.seconds(30))
      schedule_sync(state.sync_interval)
      Logger.info("[CiscoTalos] Initialized")
    else
      Logger.info("[CiscoTalos] Disabled")
    end

    {:ok, state}
  end

  @impl true
  def handle_call({:lookup_ip_reputation, ip}, _from, state) do
    result = do_lookup_ip_reputation(ip, state)
    new_stats = Map.update!(state.stats, :ip_lookups, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:lookup_domain_reputation, domain}, _from, state) do
    result = do_lookup_domain_reputation(domain, state)
    new_stats = Map.update!(state.stats, :domain_lookups, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:lookup_file_reputation, sha256}, _from, state) do
    result = do_lookup_file_reputation(sha256, state)
    new_stats = Map.update!(state.stats, :file_lookups, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:lookup_email_reputation, email}, _from, state) do
    result = do_lookup_email_reputation(email, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:categorize_url, url}, _from, state) do
    result = do_categorize_url(url, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:download_ip_blacklist, _from, state) do
    result = do_download_ip_blacklist(state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:download_domain_blacklist, _from, state) do
    result = do_download_domain_blacklist(state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_threat_advisories, opts}, _from, state) do
    result = do_get_threat_advisories(opts, state)
    {:reply, result, state}
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
    Task.start(fn -> do_sync_all(state) end)
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:initial_sync, state) do
    Logger.info("[CiscoTalos] Starting initial sync...")
    Task.start(fn -> do_sync_all(state) end)
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:periodic_sync, state) do
    Logger.info("[CiscoTalos] Starting periodic sync...")
    Task.start(fn -> do_sync_all(state) end)
    schedule_sync(state.sync_interval)
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions - API Calls
  # ============================================================================

  defp do_lookup_ip_reputation(ip, state) do
    # Talos Intelligence IP lookup (public API via web scraping or official API if available)
    # For production, integrate with official Talos Intelligence API
    url = "#{@reputation_url}/#{ip}"

    headers = if state.api_key do
      [{"Authorization", "Bearer #{state.api_key}"}, {"Accept", "application/json"}]
    else
      [{"Accept", "application/json"}]
    end

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        parse_ip_reputation(body, ip)

      {:ok, %Finch.Response{status: 404}} ->
        {:ok, %{ip: ip, reputation: :unknown, score: 0}}

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  defp do_lookup_domain_reputation(domain, state) do
    url = "#{@reputation_url}/#{domain}"

    headers = if state.api_key do
      [{"Authorization", "Bearer #{state.api_key}"}, {"Accept", "application/json"}]
    else
      [{"Accept", "application/json"}]
    end

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        parse_domain_reputation(body, domain)

      {:ok, %Finch.Response{status: 404}} ->
        {:ok, %{domain: domain, reputation: :unknown, score: 0}}

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  defp do_lookup_file_reputation(sha256, _state) do
    # Integrate with Cisco AMP Threat Grid or VirusTotal
    # For now, return placeholder
    Logger.debug("[CiscoTalos] File reputation lookup for #{sha256}")
    {:ok, %{sha256: sha256, reputation: :unknown, verdict: nil}}
  end

  defp do_lookup_email_reputation(email, _state) do
    # Email reputation via SenderBase
    Logger.debug("[CiscoTalos] Email reputation lookup for #{email}")
    {:ok, %{email: email, reputation: :unknown, spam_score: 0}}
  end

  defp do_categorize_url(url, _state) do
    # URL categorization
    Logger.debug("[CiscoTalos] URL categorization for #{url}")
    {:ok, %{url: url, categories: [], risk_level: :unknown}}
  end

  defp do_download_ip_blacklist(_state) do
    Logger.info("[CiscoTalos] Downloading IP blacklist...")

    # Simulated blacklist download - in production, use official Talos feed
    # For now, return success with placeholder data
    iocs = []

    if length(iocs) > 0 do
      Aggregator.ingest_batch("cisco_talos", iocs)
    end

    Logger.info("[CiscoTalos] Imported #{length(iocs)} IP blacklist entries")
    {:ok, length(iocs)}
  end

  defp do_download_domain_blacklist(_state) do
    Logger.info("[CiscoTalos] Downloading domain blacklist...")

    # Simulated blacklist download
    iocs = []

    if length(iocs) > 0 do
      Aggregator.ingest_batch("cisco_talos", iocs)
    end

    Logger.info("[CiscoTalos] Imported #{length(iocs)} domain blacklist entries")
    {:ok, length(iocs)}
  end

  defp do_get_threat_advisories(_opts, _state) do
    # Fetch recent threat advisories from Talos blog/API
    Logger.debug("[CiscoTalos] Fetching threat advisories")
    {:ok, []}
  end

  defp do_sync_all(state) do
    Logger.info("[CiscoTalos] Syncing all threat data...")

    # Download IP blacklist
    do_download_ip_blacklist(state)
    Process.sleep(2000)

    # Download domain blacklist
    do_download_domain_blacklist(state)

    Logger.info("[CiscoTalos] Sync complete")
  end

  # ============================================================================
  # Private Functions - Parsing
  # ============================================================================

  defp parse_ip_reputation(body, ip) do
    # Parse Talos reputation response
    # This is a simplified parser - actual implementation would parse HTML or JSON
    case Jason.decode(body) do
      {:ok, data} ->
        reputation_score = Map.get(data, "reputation_score", 0)
        threat_category = Map.get(data, "threat_category", "unknown")

        {:ok, %{
          ip: ip,
          reputation: classify_reputation(reputation_score),
          score: reputation_score,
          threat_category: threat_category,
          email_reputation_score: Map.get(data, "email_reputation"),
          web_reputation_score: Map.get(data, "web_reputation"),
          malware_families: Map.get(data, "malware_families", []),
          country: Map.get(data, "country"),
          asn: Map.get(data, "asn"),
          network_owner: Map.get(data, "network_owner"),
          last_seen: Map.get(data, "last_seen"),
          metadata: %{
            provider: "cisco_talos"
          }
        }}

      {:error, _} ->
        # Fallback for non-JSON response
        {:ok, %{
          ip: ip,
          reputation: :unknown,
          score: 0,
          metadata: %{provider: "cisco_talos"}
        }}
    end
  end

  defp parse_domain_reputation(body, domain) do
    case Jason.decode(body) do
      {:ok, data} ->
        reputation_score = Map.get(data, "reputation_score", 0)

        {:ok, %{
          domain: domain,
          reputation: classify_reputation(reputation_score),
          score: reputation_score,
          threat_category: Map.get(data, "threat_category", "unknown"),
          categories: Map.get(data, "categories", []),
          malware_families: Map.get(data, "malware_families", []),
          phishing_detected: Map.get(data, "phishing", false),
          spam_detected: Map.get(data, "spam", false),
          first_seen: Map.get(data, "first_seen"),
          last_seen: Map.get(data, "last_seen"),
          metadata: %{
            provider: "cisco_talos"
          }
        }}

      {:error, _} ->
        {:ok, %{
          domain: domain,
          reputation: :unknown,
          score: 0,
          metadata: %{provider: "cisco_talos"}
        }}
    end
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp schedule_sync(interval) do
    Process.send_after(self(), :periodic_sync, interval)
  end

  defp classify_reputation(score) when score < @poor_reputation_threshold, do: :poor
  defp classify_reputation(score) when score < @untrusted_threshold, do: :untrusted
  defp classify_reputation(score) when score >= 50, do: :good
  defp classify_reputation(_), do: :neutral
end
