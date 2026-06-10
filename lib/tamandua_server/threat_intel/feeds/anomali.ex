defmodule TamanduaServer.ThreatIntel.Feeds.Anomali do
  @moduledoc """
  Anomali ThreatStream Threat Intelligence Feed Integration.

  Anomali ThreatStream provides premium threat intelligence including:
  - Real-time threat intelligence from 100+ sources
  - Machine learning-based threat scoring
  - Threat actor tracking and attribution
  - Indicator enrichment and correlation
  - STIX/TAXII support
  - Industry-specific threat intelligence

  ## Configuration

      config :tamandua_server, TamanduaServer.ThreatIntel.Feeds.Anomali,
        api_key: "YOUR_API_KEY",
        username: "YOUR_USERNAME",
        enabled: true,
        sync_interval_hours: 4

  ## API Access

  Requires Anomali ThreatStream subscription and API credentials.
  API Documentation: https://threatstream.anomali.com/api/v2/
  """

  use GenServer
  require Logger

  alias TamanduaServer.ThreatIntel.Aggregator

  @base_url "https://api.threatstream.com/api/v2"
  @default_sync_interval :timer.hours(4)
  @http_timeout 60_000

  # Confidence score thresholds
  @high_confidence_threshold 75
  @medium_confidence_threshold 50

  # Indicator types mapping
  @indicator_types [
    "ip",
    "domain",
    "url",
    "md5",
    "sha1",
    "sha256",
    "email",
    "ssdeep"
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Search for threat intelligence indicators.
  """
  @spec search_intelligence(map()) :: {:ok, [map()]} | {:error, term()}
  def search_intelligence(criteria) do
    GenServer.call(__MODULE__, {:search_intelligence, criteria}, @http_timeout * 2)
  end

  @doc """
  Get indicator details by ID.
  """
  @spec get_indicator(integer()) :: {:ok, map()} | {:error, term()}
  def get_indicator(indicator_id) do
    GenServer.call(__MODULE__, {:get_indicator, indicator_id}, @http_timeout)
  end

  @doc """
  Lookup specific indicator value.
  """
  @spec lookup_indicator(atom(), String.t()) :: {:ok, map()} | {:error, term()}
  def lookup_indicator(indicator_type, value) do
    GenServer.call(__MODULE__, {:lookup_indicator, indicator_type, value}, @http_timeout)
  end

  @doc """
  Get threat actor information.
  """
  @spec get_actor(String.t()) :: {:ok, map()} | {:error, term()}
  def get_actor(actor_id) do
    GenServer.call(__MODULE__, {:get_actor, actor_id}, @http_timeout)
  end

  @doc """
  List threat actors.
  """
  @spec list_actors(keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_actors(opts \\ []) do
    GenServer.call(__MODULE__, {:list_actors, opts}, @http_timeout)
  end

  @doc """
  Get vulnerability intelligence.
  """
  @spec get_vulnerability(String.t()) :: {:ok, map()} | {:error, term()}
  def get_vulnerability(cve_id) do
    GenServer.call(__MODULE__, {:get_vulnerability, cve_id}, @http_timeout)
  end

  @doc """
  Get threat bulletin.
  """
  @spec get_threat_bulletin(integer()) :: {:ok, map()} | {:error, term()}
  def get_threat_bulletin(bulletin_id) do
    GenServer.call(__MODULE__, {:get_threat_bulletin, bulletin_id}, @http_timeout)
  end

  @doc """
  List recent threat bulletins.
  """
  @spec list_threat_bulletins(keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_threat_bulletins(opts \\ []) do
    GenServer.call(__MODULE__, {:list_threat_bulletins, opts}, @http_timeout)
  end

  @doc """
  Download high-confidence indicators.
  """
  @spec download_high_confidence_indicators() :: {:ok, integer()} | {:error, term()}
  def download_high_confidence_indicators do
    GenServer.call(__MODULE__, :download_high_confidence_indicators, @http_timeout * 5)
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
      api_key: Keyword.get(opts, :api_key) || System.get_env("ANOMALI_API_KEY"),
      username: Keyword.get(opts, :username) || System.get_env("ANOMALI_USERNAME"),
      enabled: Keyword.get(opts, :enabled, true),
      sync_interval: Keyword.get(opts, :sync_interval, @default_sync_interval),
      last_sync: nil,
      stats: %{
        indicator_lookups: 0,
        actors_fetched: 0,
        bulletins_fetched: 0,
        iocs_imported: 0,
        errors: 0
      }
    }

    if state.enabled && state.api_key && state.username do
      Process.send_after(self(), :initial_sync, :timer.seconds(30))
      schedule_sync(state.sync_interval)
      Logger.info("[Anomali] Initialized with API key configured")
    else
      Logger.info("[Anomali] Disabled - no API credentials configured")
    end

    {:ok, state}
  end

  @impl true
  def handle_call({:search_intelligence, criteria}, _from, state) do
    result = do_search_intelligence(criteria, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_indicator, indicator_id}, _from, state) do
    result = do_get_indicator(indicator_id, state)
    new_stats = Map.update!(state.stats, :indicator_lookups, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:lookup_indicator, indicator_type, value}, _from, state) do
    result = do_lookup_indicator(indicator_type, value, state)
    new_stats = Map.update!(state.stats, :indicator_lookups, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:get_actor, actor_id}, _from, state) do
    result = do_get_actor(actor_id, state)
    new_stats = Map.update!(state.stats, :actors_fetched, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:list_actors, opts}, _from, state) do
    result = do_list_actors(opts, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_vulnerability, cve_id}, _from, state) do
    result = do_get_vulnerability(cve_id, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_threat_bulletin, bulletin_id}, _from, state) do
    result = do_get_threat_bulletin(bulletin_id, state)
    new_stats = Map.update!(state.stats, :bulletins_fetched, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:list_threat_bulletins, opts}, _from, state) do
    result = do_list_threat_bulletins(opts, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:download_high_confidence_indicators, _from, state) do
    result = do_download_high_confidence_indicators(state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      enabled: state.enabled,
      configured: state.api_key != nil && state.username != nil,
      last_sync: state.last_sync,
      stats: state.stats
    }
    {:reply, status, state}
  end

  @impl true
  def handle_cast(:sync_all, state) do
    if state.api_key && state.username do
      Task.start(fn -> do_sync_all(state) end)
    end
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:initial_sync, state) do
    if state.api_key && state.username do
      Logger.info("[Anomali] Starting initial sync...")
      Task.start(fn -> do_sync_all(state) end)
    end
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:periodic_sync, state) do
    if state.api_key && state.username do
      Logger.info("[Anomali] Starting periodic sync...")
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

  defp do_search_intelligence(criteria, state) do
    unless state.api_key && state.username do
      {:error, :not_configured}
    else
      url = "#{@base_url}/intelligence"
      headers = api_headers(state)

      params = build_search_params(criteria)

      case Finch.build(:get, "#{url}?#{URI.encode_query(params)}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout * 2) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_intelligence_response(body)

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_get_indicator(indicator_id, state) do
    unless state.api_key && state.username do
      {:error, :not_configured}
    else
      url = "#{@base_url}/intelligence/#{indicator_id}"
      headers = api_headers(state)

      case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_indicator_details(body)

        {:ok, %Finch.Response{status: 404}} ->
          {:error, :not_found}

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_lookup_indicator(indicator_type, value, state) do
    criteria = %{
      type: indicator_type,
      value: value,
      limit: 10
    }
    do_search_intelligence(criteria, state)
  end

  defp do_get_actor(actor_id, state) do
    unless state.api_key && state.username do
      {:error, :not_configured}
    else
      url = "#{@base_url}/actors/#{actor_id}"
      headers = api_headers(state)

      case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_actor_details(body)

        {:ok, %Finch.Response{status: 404}} ->
          {:error, :not_found}

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_list_actors(opts, state) do
    unless state.api_key && state.username do
      {:error, :not_configured}
    else
      url = "#{@base_url}/actors"
      headers = api_headers(state)

      params = %{
        "limit" => Keyword.get(opts, :limit, 50),
        "offset" => Keyword.get(opts, :offset, 0)
      }

      case Finch.build(:get, "#{url}?#{URI.encode_query(params)}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_actors_list(body)

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_get_vulnerability(cve_id, state) do
    unless state.api_key && state.username do
      {:error, :not_configured}
    else
      url = "#{@base_url}/vulnerabilities"
      headers = api_headers(state)

      params = %{"name" => cve_id}

      case Finch.build(:get, "#{url}?#{URI.encode_query(params)}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
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

  defp do_get_threat_bulletin(bulletin_id, state) do
    unless state.api_key && state.username do
      {:error, :not_configured}
    else
      url = "#{@base_url}/threatbulletins/#{bulletin_id}"
      headers = api_headers(state)

      case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_bulletin_details(body)

        {:ok, %Finch.Response{status: 404}} ->
          {:error, :not_found}

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_list_threat_bulletins(opts, state) do
    unless state.api_key && state.username do
      {:error, :not_configured}
    else
      url = "#{@base_url}/threatbulletins"
      headers = api_headers(state)

      params = %{
        "limit" => Keyword.get(opts, :limit, 20),
        "offset" => Keyword.get(opts, :offset, 0),
        "order_by" => "-created_ts"
      }

      case Finch.build(:get, "#{url}?#{URI.encode_query(params)}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_bulletins_list(body)

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_download_high_confidence_indicators(state) do
    Logger.info("[Anomali] Downloading high-confidence indicators...")

    criteria = %{
      confidence__gte: @high_confidence_threshold,
      status: "active",
      limit: 5000
    }

    case do_search_intelligence(criteria, state) do
      {:ok, indicators} ->
        iocs = Enum.map(indicators, &indicator_to_ioc/1)
        |> Enum.reject(&is_nil/1)

        if length(iocs) > 0 do
          Aggregator.ingest_batch("anomali", iocs)
        end

        Logger.info("[Anomali] Imported #{length(iocs)} high-confidence IOCs")
        {:ok, length(iocs)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_sync_all(state) do
    Logger.info("[Anomali] Syncing all threat data...")

    # Download high-confidence indicators
    do_download_high_confidence_indicators(state)

    Logger.info("[Anomali] Sync complete")
  end

  # ============================================================================
  # Private Functions - Parsing
  # ============================================================================

  defp parse_intelligence_response(body) do
    case Jason.decode(body) do
      {:ok, %{"objects" => indicators}} ->
        {:ok, indicators}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_indicator_details(body) do
    case Jason.decode(body) do
      {:ok, data} ->
        {:ok, %{
          id: data["id"],
          type: data["type"],
          value: data["value"],
          confidence: data["confidence"],
          severity: data["severity"],
          status: data["status"],
          tags: extract_tags(data["tags"]),
          threat_type: data["threat_type"],
          malware_family: data["malware_family"],
          first_seen: data["created_ts"],
          last_seen: data["modified_ts"],
          source: data["source"],
          metadata: %{
            provider: "anomali",
            tlp: data["tlp"]
          }
        }}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_actor_details(body) do
    case Jason.decode(body) do
      {:ok, data} ->
        {:ok, %{
          id: data["id"],
          name: data["name"],
          description: data["description"],
          aliases: data["aliases"] || [],
          sophistication_level: data["sophistication_level"],
          primary_motivation: data["primary_motivation"],
          goals: data["goals"] || [],
          targets: data["targets"] || [],
          created: data["created_ts"],
          modified: data["modified_ts"],
          metadata: %{
            provider: "anomali",
            resource_uri: data["resource_uri"]
          }
        }}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_actors_list(body) do
    case Jason.decode(body) do
      {:ok, %{"objects" => actors}} ->
        parsed = Enum.map(actors, fn a ->
          %{
            id: a["id"],
            name: a["name"],
            sophistication_level: a["sophistication_level"],
            primary_motivation: a["primary_motivation"]
          }
        end)
        {:ok, parsed}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_vulnerability_response(body) do
    case Jason.decode(body) do
      {:ok, %{"objects" => [vuln | _]}} ->
        {:ok, %{
          id: vuln["id"],
          name: vuln["name"],
          description: vuln["description"],
          cvss_score: vuln["cvss_score"],
          published_date: vuln["published_date"],
          updated_date: vuln["updated_date"],
          metadata: %{
            provider: "anomali"
          }
        }}

      {:ok, %{"objects" => []}} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_bulletin_details(body) do
    case Jason.decode(body) do
      {:ok, data} ->
        {:ok, %{
          id: data["id"],
          name: data["name"],
          body: data["body"],
          created: data["created_ts"],
          modified: data["modified_ts"],
          is_public: data["is_public"],
          threat_actors: data["threat_actors"] || [],
          ttps: data["ttps"] || [],
          signatures: data["signatures"] || [],
          metadata: %{
            provider: "anomali",
            tlp: data["tlp"]
          }
        }}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_bulletins_list(body) do
    case Jason.decode(body) do
      {:ok, %{"objects" => bulletins}} ->
        parsed = Enum.map(bulletins, fn b ->
          %{
            id: b["id"],
            name: b["name"],
            created: b["created_ts"],
            is_public: b["is_public"]
          }
        end)
        {:ok, parsed}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp indicator_to_ioc(indicator) do
    ioc_type = map_indicator_type(indicator["type"])

    if ioc_type do
      %{
        type: ioc_type,
        value: String.downcase(to_string(indicator["value"] || "")),
        source: "anomali",
        severity: severity_from_confidence(indicator["confidence"]),
        confidence: (indicator["confidence"] || 50) / 100.0,
        tags: ["anomali"] ++ extract_tags(indicator["tags"]),
        metadata: %{
          "threat_type" => indicator["threat_type"],
          "malware_family" => indicator["malware_family"],
          "source" => indicator["source"],
          "tlp" => indicator["tlp"],
          "provider" => "anomali"
        }
      }
    else
      nil
    end
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp api_headers(state) do
    [
      {"Authorization", "apikey #{state.username}:#{state.api_key}"},
      {"Accept", "application/json"}
    ]
  end

  defp schedule_sync(interval) do
    Process.send_after(self(), :periodic_sync, interval)
  end

  defp build_search_params(criteria) do
    params = %{
      "limit" => Map.get(criteria, :limit, 100),
      "offset" => Map.get(criteria, :offset, 0)
    }

    params = if criteria[:type] do
      Map.put(params, "type", to_string(criteria[:type]))
    else
      params
    end

    params = if criteria[:value] do
      Map.put(params, "value", criteria[:value])
    else
      params
    end

    params = if criteria[:confidence__gte] do
      Map.put(params, "confidence__gte", criteria[:confidence__gte])
    else
      params
    end

    params = if criteria[:status] do
      Map.put(params, "status", criteria[:status])
    else
      params
    end

    params
  end

  defp map_indicator_type("ip"), do: "ip"
  defp map_indicator_type("domain"), do: "domain"
  defp map_indicator_type("url"), do: "url"
  defp map_indicator_type("md5"), do: "hash_md5"
  defp map_indicator_type("sha1"), do: "hash_sha1"
  defp map_indicator_type("sha256"), do: "hash_sha256"
  defp map_indicator_type("email"), do: "email"
  defp map_indicator_type(_), do: nil

  defp severity_from_confidence(confidence) when confidence >= @high_confidence_threshold, do: "critical"
  defp severity_from_confidence(confidence) when confidence >= @medium_confidence_threshold, do: "high"
  defp severity_from_confidence(_), do: "medium"

  defp extract_tags(nil), do: []
  defp extract_tags(tags) when is_list(tags) do
    Enum.map(tags, fn
      %{"name" => name} -> name
      tag when is_binary(tag) -> tag
      _ -> nil
    end)
    |> Enum.reject(&is_nil/1)
  end
  defp extract_tags(_), do: []
end
