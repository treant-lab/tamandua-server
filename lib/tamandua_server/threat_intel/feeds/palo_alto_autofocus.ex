defmodule TamanduaServer.ThreatIntel.Feeds.PaloAltoAutoFocus do
  @moduledoc """
  Palo Alto Networks AutoFocus Threat Intelligence Feed Integration.

  AutoFocus provides advanced threat intelligence including:
  - Threat campaign tracking
  - Malware family analysis with WildFire integration
  - Targeted attack indicators
  - Unit 42 threat research integration
  - Advanced persistent threats (APT) tracking
  - Behavioral malware analysis

  ## Configuration

      config :tamandua_server, TamanduaServer.ThreatIntel.Feeds.PaloAltoAutoFocus,
        api_key: "YOUR_API_KEY",
        enabled: true,
        sync_interval_hours: 4

  ## API Access

  Requires Palo Alto Networks AutoFocus subscription.
  API Documentation: https://docs.paloaltonetworks.com/autofocus
  """

  use GenServer
  require Logger

  alias TamanduaServer.ThreatIntel.Aggregator

  @base_url "https://autofocus.paloaltonetworks.com/api/v1.0"
  @default_sync_interval :timer.hours(4)
  @http_timeout 60_000

  # Confidence mappings
  @confidence_map %{
    "high" => 0.95,
    "medium" => 0.75,
    "low" => 0.5
  }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Search for samples matching criteria.
  """
  @spec search_samples(map()) :: {:ok, [map()]} | {:error, term()}
  def search_samples(criteria) do
    GenServer.call(__MODULE__, {:search_samples, criteria}, @http_timeout * 2)
  end

  @doc """
  Get sample analysis details.
  """
  @spec get_sample_analysis(String.t()) :: {:ok, map()} | {:error, term()}
  def get_sample_analysis(sha256) do
    GenServer.call(__MODULE__, {:get_sample_analysis, sha256}, @http_timeout)
  end

  @doc """
  Search for sessions (network traffic analysis).
  """
  @spec search_sessions(map()) :: {:ok, [map()]} | {:error, term()}
  def search_sessions(criteria) do
    GenServer.call(__MODULE__, {:search_sessions, criteria}, @http_timeout * 2)
  end

  @doc """
  Get threat tags and campaigns.
  """
  @spec get_tags(keyword()) :: {:ok, [map()]} | {:error, term()}
  def get_tags(opts \\ []) do
    GenServer.call(__MODULE__, {:get_tags, opts}, @http_timeout)
  end

  @doc """
  Get tag details including IOCs.
  """
  @spec get_tag_details(String.t()) :: {:ok, map()} | {:error, term()}
  def get_tag_details(tag_name) do
    GenServer.call(__MODULE__, {:get_tag_details, tag_name}, @http_timeout)
  end

  @doc """
  Export IOCs for a specific tag/campaign.
  """
  @spec export_tag_iocs(String.t()) :: {:ok, [map()]} | {:error, term()}
  def export_tag_iocs(tag_name) do
    GenServer.call(__MODULE__, {:export_tag_iocs, tag_name}, @http_timeout * 3)
  end

  @doc """
  Get top attacks.
  """
  @spec get_top_attacks(keyword()) :: {:ok, [map()]} | {:error, term()}
  def get_top_attacks(opts \\ []) do
    GenServer.call(__MODULE__, {:get_top_attacks, opts}, @http_timeout)
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
      api_key: Keyword.get(opts, :api_key) || System.get_env("PALOALTO_AUTOFOCUS_API_KEY"),
      enabled: Keyword.get(opts, :enabled, true),
      sync_interval: Keyword.get(opts, :sync_interval, @default_sync_interval),
      last_sync: nil,
      stats: %{
        samples_analyzed: 0,
        tags_fetched: 0,
        iocs_imported: 0,
        sessions_analyzed: 0,
        errors: 0
      }
    }

    if state.enabled && state.api_key do
      Process.send_after(self(), :initial_sync, :timer.seconds(30))
      schedule_sync(state.sync_interval)
      Logger.info("[AutoFocus] Initialized with API key configured")
    else
      Logger.info("[AutoFocus] Disabled - no API key configured")
    end

    {:ok, state}
  end

  @impl true
  def handle_call({:search_samples, criteria}, _from, state) do
    result = do_search_samples(criteria, state)
    new_stats = Map.update!(state.stats, :samples_analyzed, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:get_sample_analysis, sha256}, _from, state) do
    result = do_get_sample_analysis(sha256, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:search_sessions, criteria}, _from, state) do
    result = do_search_sessions(criteria, state)
    new_stats = Map.update!(state.stats, :sessions_analyzed, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:get_tags, opts}, _from, state) do
    result = do_get_tags(opts, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_tag_details, tag_name}, _from, state) do
    result = do_get_tag_details(tag_name, state)
    new_stats = Map.update!(state.stats, :tags_fetched, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:export_tag_iocs, tag_name}, _from, state) do
    result = do_export_tag_iocs(tag_name, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_top_attacks, opts}, _from, state) do
    result = do_get_top_attacks(opts, state)
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
    if state.api_key do
      Task.start(fn -> do_sync_all(state) end)
    end
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:initial_sync, state) do
    if state.api_key do
      Logger.info("[AutoFocus] Starting initial sync...")
      Task.start(fn -> do_sync_all(state) end)
    end
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:periodic_sync, state) do
    if state.api_key do
      Logger.info("[AutoFocus] Starting periodic sync...")
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

  defp do_search_samples(criteria, state) do
    unless state.api_key do
      {:error, :not_configured}
    else
      url = "#{@base_url}/samples/search"

      headers = api_headers(state.api_key)

      # Build query from criteria
      query = build_sample_query(criteria)

      body = Jason.encode!(%{
        "query" => query,
        "size" => Map.get(criteria, :limit, 100),
        "from" => Map.get(criteria, :offset, 0),
        "sort" => %{
          "create_date" => %{"order" => "desc"}
        }
      })

      case Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout * 2) do
        {:ok, %Finch.Response{status: 200, body: resp_body}} ->
          parse_samples_response(resp_body)

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_get_sample_analysis(sha256, state) do
    unless state.api_key do
      {:error, :not_configured}
    else
      url = "#{@base_url}/sample/#{sha256}/analysis"

      headers = api_headers(state.api_key)

      case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_sample_analysis(body)

        {:ok, %Finch.Response{status: 404}} ->
          {:error, :not_found}

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_search_sessions(criteria, state) do
    unless state.api_key do
      {:error, :not_configured}
    else
      url = "#{@base_url}/sessions/search"

      headers = api_headers(state.api_key)

      query = build_session_query(criteria)

      body = Jason.encode!(%{
        "query" => query,
        "size" => Map.get(criteria, :limit, 100),
        "from" => Map.get(criteria, :offset, 0)
      })

      case Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout * 2) do
        {:ok, %Finch.Response{status: 200, body: resp_body}} ->
          parse_sessions_response(resp_body)

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_get_tags(opts, state) do
    unless state.api_key do
      {:error, :not_configured}
    else
      url = "#{@base_url}/tags"

      headers = api_headers(state.api_key)

      params = %{
        "scope" => Keyword.get(opts, :scope, "public"),
        "pageSize" => Keyword.get(opts, :limit, 200),
        "tagClass" => Keyword.get(opts, :class, "actor,campaign,exploit,malware_family")
      }

      case Finch.build(:get, "#{url}?#{URI.encode_query(params)}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_tags_response(body)

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_get_tag_details(tag_name, state) do
    unless state.api_key do
      {:error, :not_configured}
    else
      url = "#{@base_url}/tag/#{URI.encode(tag_name)}"

      headers = api_headers(state.api_key)

      case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_tag_details(body)

        {:ok, %Finch.Response{status: 404}} ->
          {:error, :not_found}

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_export_tag_iocs(tag_name, state) do
    unless state.api_key do
      {:error, :not_configured}
    else
      Logger.info("[AutoFocus] Exporting IOCs for tag: #{tag_name}")

      url = "#{@base_url}/export"

      headers = api_headers(state.api_key)

      body = Jason.encode!(%{
        "query" => %{
          "operator" => "all",
          "children" => [
            %{
              "field" => "sample.tag",
              "operator" => "is",
              "value" => tag_name
            }
          ]
        },
        "fileType" => "json",
        "indicatorType" => "all"
      })

      case Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout * 3) do
        {:ok, %Finch.Response{status: 200, body: resp_body}} ->
          case Jason.decode(resp_body) do
            {:ok, %{"indicators" => indicators}} ->
              iocs = parse_indicators_to_iocs(indicators, tag_name)
              Aggregator.ingest_batch("palo_alto_autofocus", iocs)
              Logger.info("[AutoFocus] Imported #{length(iocs)} IOCs from tag #{tag_name}")
              {:ok, iocs}

            _ ->
              {:ok, []}
          end

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_get_top_attacks(opts, state) do
    unless state.api_key do
      {:error, :not_configured}
    else
      url = "#{@base_url}/top-tags"

      headers = api_headers(state.api_key)

      params = %{
        "scope" => Keyword.get(opts, :scope, "global"),
        "tagClasses" => "actor,campaign,exploit,malware_family",
        "timeRange" => Keyword.get(opts, :time_range, "last_7_days")
      }

      case Finch.build(:get, "#{url}?#{URI.encode_query(params)}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_top_attacks(body)

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_sync_all(state) do
    Logger.info("[AutoFocus] Syncing all threat data...")

    # Get top campaigns and export their IOCs
    case do_get_tags([scope: "public", class: "campaign,malware_family"], state) do
      {:ok, tags} ->
        top_tags = Enum.take(tags, 20)

        Enum.each(top_tags, fn tag ->
          try do
            do_export_tag_iocs(tag.tag_name, state)
          rescue
            e -> Logger.error("[AutoFocus] Failed to export tag #{tag.tag_name}: #{inspect(e)}")
          end

          # Rate limiting
          Process.sleep(3000)
        end)

      {:error, reason} ->
        Logger.error("[AutoFocus] Failed to get tags: #{inspect(reason)}")
    end

    Logger.info("[AutoFocus] Sync complete")
  end

  # ============================================================================
  # Private Functions - Parsing
  # ============================================================================

  defp parse_samples_response(body) do
    case Jason.decode(body) do
      {:ok, %{"hits" => samples}} ->
        parsed = Enum.map(samples, fn sample ->
          %{
            sha256: sample["_source"]["sha256"],
            md5: sample["_source"]["md5"],
            sha1: sample["_source"]["sha1"],
            file_type: sample["_source"]["filetype"],
            size: sample["_source"]["size"],
            create_date: sample["_source"]["create_date"],
            finish_date: sample["_source"]["finish_date"],
            malware: sample["_source"]["malware"],
            tags: sample["_source"]["tag"] || [],
            verdict: sample["_source"]["verdict"],
            wildfire_verdict: sample["_source"]["wildfire_verdict"]
          }
        end)
        {:ok, parsed}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_sample_analysis(body) do
    case Jason.decode(body) do
      {:ok, data} ->
        {:ok, %{
          sha256: data["sha256"],
          analysis_time: data["finish_date"],
          verdict: data["verdict"],
          malware: data["malware"],
          tags: data["tag"] || [],
          apk_app_name: data["apk_app_name"],
          apk_package_name: data["apk_package_name"],
          connections: data["connection"] || [],
          dns_requests: data["dns"] || [],
          http_requests: data["http"] || [],
          processes: data["process"] || [],
          file_behaviors: data["behavior"] || [],
          registry_actions: data["registry"] || [],
          japi_calls: data["japi"] || []
        }}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_sessions_response(body) do
    case Jason.decode(body) do
      {:ok, %{"hits" => sessions}} ->
        parsed = Enum.map(sessions, fn session ->
          src = session["_source"]
          %{
            session_id: src["session_id"],
            timestamp: src["timestamp"],
            src_ip: src["src_ip"],
            dst_ip: src["dst_ip"],
            src_port: src["src_port"],
            dst_port: src["dst_port"],
            application: src["app"],
            tags: src["tag"] || [],
            threat_id: src["threat_id"],
            url_category: src["url_category_list"]
          }
        end)
        {:ok, parsed}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_tags_response(body) do
    case Jason.decode(body) do
      {:ok, %{"tags" => tags}} ->
        parsed = Enum.map(tags, fn tag ->
          %{
            tag_name: tag["tag_name"],
            public_tag_name: tag["public_tag_name"],
            tag_class: tag["tag_class"],
            description: tag["description"],
            customer_name: tag["customer_name"],
            source: tag["source"],
            count: tag["count"]
          }
        end)
        {:ok, parsed}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_tag_details(body) do
    case Jason.decode(body) do
      {:ok, data} ->
        {:ok, %{
          tag_name: data["tag_name"],
          tag_class: data["tag_class"],
          description: data["description"],
          aliases: data["aliases"] || [],
          related_tags: data["related_tags"] || [],
          references: data["references"] || [],
          created_at: data["created_at"],
          updated_at: data["updated_at"]
        }}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_top_attacks(body) do
    case Jason.decode(body) do
      {:ok, %{"tags" => tags}} ->
        parsed = Enum.map(tags, fn tag ->
          %{
            tag_name: tag["tag_name"],
            tag_class: tag["tag_class"],
            count: tag["count"],
            trend: tag["trend"]
          }
        end)
        {:ok, parsed}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_indicators_to_iocs(indicators, tag_name) do
    Enum.map(indicators, fn indicator ->
      indicator_type = indicator["indicator_type"]
      value = indicator["indicator"]

      ioc_type = map_indicator_type(indicator_type)

      if ioc_type do
        %{
          type: ioc_type,
          value: String.downcase(to_string(value)),
          source: "palo_alto_autofocus",
          severity: severity_from_confidence(indicator["confidence"]),
          confidence: Map.get(@confidence_map, indicator["confidence"], 0.7),
          tags: ["autofocus", tag_name, indicator_type],
          metadata: %{
            "tag" => tag_name,
            "indicator_type" => indicator_type,
            "first_seen" => indicator["first_seen"],
            "last_seen" => indicator["last_seen"],
            "provider" => "palo_alto_autofocus"
          }
        }
      else
        nil
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp api_headers(api_key) do
    [
      {"apiKey", api_key},
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]
  end

  defp schedule_sync(interval) do
    Process.send_after(self(), :periodic_sync, interval)
  end

  defp build_sample_query(criteria) do
    children = []

    children = if criteria[:malware_family] do
      [%{
        "field" => "sample.malware",
        "operator" => "is",
        "value" => criteria[:malware_family]
      } | children]
    else
      children
    end

    children = if criteria[:tag] do
      [%{
        "field" => "sample.tag",
        "operator" => "is",
        "value" => criteria[:tag]
      } | children]
    else
      children
    end

    children = if criteria[:file_type] do
      [%{
        "field" => "sample.filetype",
        "operator" => "is",
        "value" => criteria[:file_type]
      } | children]
    else
      children
    end

    %{
      "operator" => "all",
      "children" => children
    }
  end

  defp build_session_query(criteria) do
    children = []

    children = if criteria[:dst_ip] do
      [%{
        "field" => "session.dst_ip",
        "operator" => "is",
        "value" => criteria[:dst_ip]
      } | children]
    else
      children
    end

    children = if criteria[:src_ip] do
      [%{
        "field" => "session.src_ip",
        "operator" => "is",
        "value" => criteria[:src_ip]
      } | children]
    else
      children
    end

    children = if criteria[:tag] do
      [%{
        "field" => "session.tag",
        "operator" => "is",
        "value" => criteria[:tag]
      } | children]
    else
      children
    end

    %{
      "operator" => "all",
      "children" => children
    }
  end

  defp map_indicator_type("IPV4_ADDRESS"), do: "ip"
  defp map_indicator_type("IPV6_ADDRESS"), do: "ip"
  defp map_indicator_type("DOMAIN"), do: "domain"
  defp map_indicator_type("URL"), do: "url"
  defp map_indicator_type("FILEHASH_MD5"), do: "hash_md5"
  defp map_indicator_type("FILEHASH_SHA1"), do: "hash_sha1"
  defp map_indicator_type("FILEHASH_SHA256"), do: "hash_sha256"
  defp map_indicator_type("EMAIL_ADDRESS"), do: "email"
  defp map_indicator_type(_), do: nil

  defp severity_from_confidence("high"), do: "critical"
  defp severity_from_confidence("medium"), do: "high"
  defp severity_from_confidence("low"), do: "medium"
  defp severity_from_confidence(_), do: "medium"
end
