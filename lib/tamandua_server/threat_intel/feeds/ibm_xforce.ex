defmodule TamanduaServer.ThreatIntel.Feeds.IBMXForce do
  @moduledoc """
  IBM X-Force Exchange Threat Intelligence Feed Integration.

  IBM X-Force provides comprehensive threat intelligence including:
  - IP reputation with risk scores
  - URL and malware analysis
  - Vulnerability intelligence (CVE database)
  - Historical threat data
  - Threat actor profiles and TTPs
  - Industry-specific threat intelligence

  ## Configuration

      config :tamandua_server, TamanduaServer.ThreatIntel.Feeds.IBMXForce,
        api_key: "YOUR_API_KEY",
        api_password: "YOUR_API_PASSWORD",
        enabled: true,
        sync_interval_hours: 4

  ## API Access

  Requires IBM X-Force Exchange account and API credentials.
  API Documentation: https://exchange.xforce.ibmcloud.com/api/doc/
  """

  use GenServer
  require Logger

  alias TamanduaServer.ThreatIntel.Aggregator

  @base_url "https://api.xforce.ibmcloud.com"
  @default_sync_interval :timer.hours(4)
  @http_timeout 60_000

  # Risk score thresholds
  @high_risk_threshold 7
  @medium_risk_threshold 4

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Lookup IP address threat intelligence.
  """
  @spec lookup_ip(String.t()) :: {:ok, map()} | {:error, term()}
  def lookup_ip(ip) do
    GenServer.call(__MODULE__, {:lookup_ip, ip}, @http_timeout)
  end

  @doc """
  Lookup URL threat intelligence.
  """
  @spec lookup_url(String.t()) :: {:ok, map()} | {:error, term()}
  def lookup_url(url) do
    GenServer.call(__MODULE__, {:lookup_url, url}, @http_timeout)
  end

  @doc """
  Lookup malware family information.
  """
  @spec lookup_malware(String.t()) :: {:ok, map()} | {:error, term()}
  def lookup_malware(malware_family) do
    GenServer.call(__MODULE__, {:lookup_malware, malware_family}, @http_timeout)
  end

  @doc """
  Lookup vulnerability (CVE) information.
  """
  @spec lookup_vulnerability(String.t()) :: {:ok, map()} | {:error, term()}
  def lookup_vulnerability(cve_id) do
    GenServer.call(__MODULE__, {:lookup_vulnerability, cve_id}, @http_timeout)
  end

  @doc """
  Get IP reputation history.
  """
  @spec get_ip_history(String.t()) :: {:ok, [map()]} | {:error, term()}
  def get_ip_history(ip) do
    GenServer.call(__MODULE__, {:get_ip_history, ip}, @http_timeout)
  end

  @doc """
  Get malware analysis for file hash.
  """
  @spec get_malware_analysis(String.t()) :: {:ok, map()} | {:error, term()}
  def get_malware_analysis(hash) do
    GenServer.call(__MODULE__, {:get_malware_analysis, hash}, @http_timeout)
  end

  @doc """
  Search for threat collections.
  """
  @spec search_collections(String.t()) :: {:ok, [map()]} | {:error, term()}
  def search_collections(query) do
    GenServer.call(__MODULE__, {:search_collections, query}, @http_timeout)
  end

  @doc """
  Get collection details and IOCs.
  """
  @spec get_collection(String.t()) :: {:ok, map()} | {:error, term()}
  def get_collection(collection_id) do
    GenServer.call(__MODULE__, {:get_collection, collection_id}, @http_timeout)
  end

  @doc """
  Download latest threat intelligence collections.
  """
  @spec download_latest_collections() :: {:ok, integer()} | {:error, term()}
  def download_latest_collections do
    GenServer.call(__MODULE__, :download_latest_collections, @http_timeout * 5)
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
      api_key: Keyword.get(opts, :api_key) || System.get_env("IBM_XFORCE_API_KEY"),
      api_password: Keyword.get(opts, :api_password) || System.get_env("IBM_XFORCE_API_PASSWORD"),
      enabled: Keyword.get(opts, :enabled, true),
      sync_interval: Keyword.get(opts, :sync_interval, @default_sync_interval),
      last_sync: nil,
      stats: %{
        ip_lookups: 0,
        url_lookups: 0,
        malware_lookups: 0,
        vulnerability_lookups: 0,
        collections_fetched: 0,
        iocs_imported: 0,
        errors: 0
      }
    }

    if state.enabled && state.api_key && state.api_password do
      Process.send_after(self(), :initial_sync, :timer.seconds(30))
      schedule_sync(state.sync_interval)
      Logger.info("[IBMXForce] Initialized with API credentials configured")
    else
      Logger.info("[IBMXForce] Disabled - no API credentials configured")
    end

    {:ok, state}
  end

  @impl true
  def handle_call({:lookup_ip, ip}, _from, state) do
    result = do_lookup_ip(ip, state)
    new_stats = Map.update!(state.stats, :ip_lookups, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:lookup_url, url}, _from, state) do
    result = do_lookup_url(url, state)
    new_stats = Map.update!(state.stats, :url_lookups, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:lookup_malware, malware_family}, _from, state) do
    result = do_lookup_malware(malware_family, state)
    new_stats = Map.update!(state.stats, :malware_lookups, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:lookup_vulnerability, cve_id}, _from, state) do
    result = do_lookup_vulnerability(cve_id, state)
    new_stats = Map.update!(state.stats, :vulnerability_lookups, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:get_ip_history, ip}, _from, state) do
    result = do_get_ip_history(ip, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_malware_analysis, hash}, _from, state) do
    result = do_get_malware_analysis(hash, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:search_collections, query}, _from, state) do
    result = do_search_collections(query, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_collection, collection_id}, _from, state) do
    result = do_get_collection(collection_id, state)
    new_stats = Map.update!(state.stats, :collections_fetched, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call(:download_latest_collections, _from, state) do
    result = do_download_latest_collections(state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      enabled: state.enabled,
      configured: state.api_key != nil && state.api_password != nil,
      last_sync: state.last_sync,
      stats: state.stats
    }
    {:reply, status, state}
  end

  @impl true
  def handle_cast(:sync_all, state) do
    if state.api_key && state.api_password do
      Task.start(fn -> do_sync_all(state) end)
    end
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:initial_sync, state) do
    if state.api_key && state.api_password do
      Logger.info("[IBMXForce] Starting initial sync...")
      Task.start(fn -> do_sync_all(state) end)
    end
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:periodic_sync, state) do
    if state.api_key && state.api_password do
      Logger.info("[IBMXForce] Starting periodic sync...")
      Task.start(fn -> do_sync_all(state) end)
      schedule_sync(state.sync_interval)
    end
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions - API Calls
  # ============================================================================

  defp do_lookup_ip(ip, state) do
    unless state.api_key && state.api_password do
      {:error, :not_configured}
    else
      url = "#{@base_url}/ipr/#{ip}"
      headers = api_headers(state)

      case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_ip_response(body)

        {:ok, %Finch.Response{status: 404}} ->
          {:ok, %{ip: ip, found: false, score: 0}}

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_lookup_url(url_to_lookup, state) do
    unless state.api_key && state.api_password do
      {:error, :not_configured}
    else
      encoded_url = Base.encode64(url_to_lookup)
      url = "#{@base_url}/url/#{encoded_url}"
      headers = api_headers(state)

      case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_url_response(body)

        {:ok, %Finch.Response{status: 404}} ->
          {:ok, %{url: url_to_lookup, found: false}}

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_lookup_malware(malware_family, state) do
    unless state.api_key && state.api_password do
      {:error, :not_configured}
    else
      url = "#{@base_url}/malware/#{URI.encode(malware_family)}"
      headers = api_headers(state)

      case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_malware_response(body)

        {:ok, %Finch.Response{status: 404}} ->
          {:error, :not_found}

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_lookup_vulnerability(cve_id, state) do
    unless state.api_key && state.api_password do
      {:error, :not_configured}
    else
      url = "#{@base_url}/vulnerabilities/#{cve_id}"
      headers = api_headers(state)

      case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_vulnerability_response(body)

        {:ok, %Finch.Response{status: 404}} ->
          {:error, :not_found}

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_get_ip_history(ip, state) do
    unless state.api_key && state.api_password do
      {:error, :not_configured}
    else
      url = "#{@base_url}/ipr/history/#{ip}"
      headers = api_headers(state)

      case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_ip_history(body)

        {:ok, %Finch.Response{status: 404}} ->
          {:ok, []}

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_get_malware_analysis(hash, state) do
    unless state.api_key && state.api_password do
      {:error, :not_configured}
    else
      url = "#{@base_url}/malware/#{hash}"
      headers = api_headers(state)

      case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_malware_analysis(body)

        {:ok, %Finch.Response{status: 404}} ->
          {:error, :not_found}

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_search_collections(query, state) do
    unless state.api_key && state.api_password do
      {:error, :not_configured}
    else
      url = "#{@base_url}/casefiles/public"
      headers = api_headers(state)
      params = URI.encode_query(%{"q" => query, "limit" => 50})

      case Finch.build(:get, "#{url}?#{params}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_collections_list(body)

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_get_collection(collection_id, state) do
    unless state.api_key && state.api_password do
      {:error, :not_configured}
    else
      url = "#{@base_url}/casefiles/public/#{collection_id}"
      headers = api_headers(state)

      case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_collection_details(body)

        {:ok, %Finch.Response{status: 404}} ->
          {:error, :not_found}

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_download_latest_collections(state) do
    Logger.info("[IBMXForce] Downloading latest threat collections...")

    case do_search_collections("malware", state) do
      {:ok, collections} ->
        iocs = Enum.flat_map(Enum.take(collections, 10), fn collection ->
          case do_get_collection(collection.id, state) do
            {:ok, details} ->
              extract_collection_iocs(details)

            {:error, _} ->
              []
          end
        end)

        if length(iocs) > 0 do
          Aggregator.ingest_batch("ibm_xforce", iocs)
        end

        Logger.info("[IBMXForce] Imported #{length(iocs)} IOCs from collections")
        {:ok, length(iocs)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_sync_all(state) do
    Logger.info("[IBMXForce] Syncing all threat data...")

    # Download latest collections
    do_download_latest_collections(state)

    Logger.info("[IBMXForce] Sync complete")
  end

  # ============================================================================
  # Private Functions - Parsing
  # ============================================================================

  defp parse_ip_response(body) do
    case Jason.decode(body) do
      {:ok, data} ->
        score = Map.get(data, "score", 0)
        {:ok, %{
          ip: Map.get(data, "ip"),
          found: true,
          score: score,
          risk_level: risk_level_from_score(score),
          categories: Map.get(data, "cats", %{}),
          reason: Map.get(data, "reason"),
          reasonDescription: Map.get(data, "reasonDescription"),
          country: Map.get(data, "geo", %{}) |> Map.get("country"),
          subnets: Map.get(data, "subnets", []),
          history: Map.get(data, "history", []),
          metadata: %{
            provider: "ibm_xforce"
          }
        }}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_url_response(body) do
    case Jason.decode(body) do
      {:ok, data} ->
        result = Map.get(data, "result", %{})
        {:ok, %{
          url: result["url"],
          found: true,
          score: result["score"] || 0,
          categories: result["cats"] || %{},
          application: result["application"],
          metadata: %{
            provider: "ibm_xforce"
          }
        }}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_malware_response(body) do
    case Jason.decode(body) do
      {:ok, data} ->
        {:ok, %{
          malware_family: Map.get(data, "malware", %{}) |> Map.get("family"),
          type: Map.get(data, "malware", %{}) |> Map.get("type"),
          aliases: Map.get(data, "malware", %{}) |> Map.get("aliases", []),
          origins: Map.get(data, "malware", %{}) |> Map.get("origins", []),
          risk: Map.get(data, "malware", %{}) |> Map.get("risk"),
          first_seen: Map.get(data, "created"),
          metadata: %{
            provider: "ibm_xforce"
          }
        }}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_vulnerability_response(body) do
    case Jason.decode(body) do
      {:ok, data} ->
        {:ok, %{
          cve_id: data["cve"],
          title: data["title"],
          description: data["description"],
          risk_level: data["risk_level"],
          cvss_score: get_in(data, ["cvss", "score"]),
          cvss_vector: get_in(data, ["cvss", "vector"]),
          published: data["reported"],
          exploit_maturity: data["exploit_maturity"],
          references: data["references"] || [],
          affected_products: data["affected_products"] || [],
          metadata: %{
            provider: "ibm_xforce"
          }
        }}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_ip_history(body) do
    case Jason.decode(body) do
      {:ok, %{"history" => history}} ->
        {:ok, history}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_malware_analysis(body) do
    case Jason.decode(body) do
      {:ok, data} ->
        {:ok, %{
          hash: data["hash"],
          malware_family: get_in(data, ["malware", "family"]),
          malware_type: get_in(data, ["malware", "type"]),
          risk: get_in(data, ["malware", "risk"]),
          origins: get_in(data, ["malware", "origins"]) || [],
          created: data["created"],
          metadata: %{
            provider: "ibm_xforce"
          }
        }}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_collections_list(body) do
    case Jason.decode(body) do
      {:ok, %{"casefiles" => collections}} ->
        parsed = Enum.map(collections, fn c ->
          %{
            id: c["caseFileID"],
            title: c["title"],
            created: c["created"],
            tags: c["tags"] || []
          }
        end)
        {:ok, parsed}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_collection_details(body) do
    case Jason.decode(body) do
      {:ok, data} ->
        {:ok, %{
          id: data["caseFileID"],
          title: data["title"],
          description: data["description"],
          created: data["created"],
          tags: data["tags"] || [],
          contents: data["contents"] || [],
          indicators: extract_indicators_from_contents(data["contents"] || [])
        }}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp extract_indicators_from_contents(contents) do
    Enum.flat_map(contents, fn content ->
      case content["type"] do
        "ip" -> [%{type: "ip", value: content["value"]}]
        "domain" -> [%{type: "domain", value: content["value"]}]
        "url" -> [%{type: "url", value: content["value"]}]
        "md5" -> [%{type: "hash_md5", value: content["value"]}]
        "sha1" -> [%{type: "hash_sha1", value: content["value"]}]
        "sha256" -> [%{type: "hash_sha256", value: content["value"]}]
        _ -> []
      end
    end)
  end

  defp extract_collection_iocs(details) do
    Enum.map(details.indicators, fn indicator ->
      %{
        type: indicator.type,
        value: String.downcase(indicator.value),
        source: "ibm_xforce",
        severity: "medium",
        confidence: 0.75,
        tags: ["xforce", "collection:#{details.id}"] ++ details.tags,
        metadata: %{
          "collection_title" => details.title,
          "collection_id" => details.id,
          "provider" => "ibm_xforce"
        }
      }
    end)
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp api_headers(state) do
    auth = Base.encode64("#{state.api_key}:#{state.api_password}")
    [
      {"Authorization", "Basic #{auth}"},
      {"Accept", "application/json"}
    ]
  end

  defp schedule_sync(interval) do
    Process.send_after(self(), :periodic_sync, interval)
  end

  defp risk_level_from_score(score) when score >= @high_risk_threshold, do: :high
  defp risk_level_from_score(score) when score >= @medium_risk_threshold, do: :medium
  defp risk_level_from_score(score) when score > 0, do: :low
  defp risk_level_from_score(_), do: :clean
end
