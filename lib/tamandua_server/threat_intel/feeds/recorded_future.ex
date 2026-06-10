defmodule TamanduaServer.ThreatIntel.Feeds.RecordedFuture do
  @moduledoc """
  Recorded Future Threat Intelligence Feed Integration.

  Recorded Future provides premium threat intelligence including:
  - IP addresses with risk scores
  - Domain risk intelligence
  - Hash intelligence with malware attribution
  - Vulnerability intelligence (CVEs)
  - Threat actor profiles and campaigns

  ## Configuration

      config :tamandua_server, TamanduaServer.ThreatIntel.Feeds.RecordedFuture,
        api_token: "YOUR_API_TOKEN",
        enabled: true,
        sync_interval_hours: 4

  ## API Endpoints

  - Risk Lists: Pre-computed lists of risky indicators
  - Intelligence API: Real-time lookups and enrichment
  - Fusion Files: Bulk downloads for high-volume use
  """

  use GenServer
  require Logger

  alias TamanduaServer.Detection.IOCs
  alias TamanduaServer.ThreatIntel.Aggregator

  @base_url "https://api.recordedfuture.com/v2"
  @fusion_url "https://api.recordedfuture.com/gw/fusions"
  @connect_url "https://api.recordedfuture.com/v3"

  @default_sync_interval :timer.hours(4)
  @http_timeout 60_000

  # Risk score thresholds
  @high_risk_threshold 65
  @critical_risk_threshold 90

  # Feed types available from Recorded Future
  @risk_list_types [
    :ip_high_risk,
    :ip_critical_risk,
    :domain_high_risk,
    :domain_critical_risk,
    :hash_high_risk,
    :hash_critical_risk,
    :url_high_risk,
    :vulnerability_critical
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Lookup an indicator in Recorded Future for enrichment.

  Returns risk score, related entities, and threat context.
  """
  @spec lookup(atom(), String.t()) :: {:ok, map()} | {:error, term()}
  def lookup(indicator_type, value) do
    GenServer.call(__MODULE__, {:lookup, indicator_type, value}, @http_timeout)
  end

  @doc """
  Batch lookup multiple indicators.
  """
  @spec batch_lookup(atom(), [String.t()]) :: {:ok, [map()]} | {:error, term()}
  def batch_lookup(indicator_type, values) when is_list(values) do
    GenServer.call(__MODULE__, {:batch_lookup, indicator_type, values}, @http_timeout * 2)
  end

  @doc """
  Get the risk score for an indicator.
  """
  @spec get_risk_score(atom(), String.t()) :: {:ok, integer()} | {:error, term()}
  def get_risk_score(indicator_type, value) do
    case lookup(indicator_type, value) do
      {:ok, %{risk_score: score}} -> {:ok, score}
      error -> error
    end
  end

  @doc """
  Download a risk list (requires Fusion Files entitlement).
  """
  @spec download_risk_list(atom()) :: {:ok, integer()} | {:error, term()}
  def download_risk_list(list_type) when list_type in @risk_list_types do
    GenServer.call(__MODULE__, {:download_risk_list, list_type}, @http_timeout * 5)
  end

  @doc """
  Get threat actor intelligence.
  """
  @spec get_threat_actor(String.t()) :: {:ok, map()} | {:error, term()}
  def get_threat_actor(actor_name) do
    GenServer.call(__MODULE__, {:get_threat_actor, actor_name}, @http_timeout)
  end

  @doc """
  Search for threat actors by criteria.
  """
  @spec search_threat_actors(map()) :: {:ok, [map()]} | {:error, term()}
  def search_threat_actors(criteria) do
    GenServer.call(__MODULE__, {:search_threat_actors, criteria}, @http_timeout)
  end

  @doc """
  Get vulnerability intelligence for CVE.
  """
  @spec get_vulnerability(String.t()) :: {:ok, map()} | {:error, term()}
  def get_vulnerability(cve_id) do
    GenServer.call(__MODULE__, {:get_vulnerability, cve_id}, @http_timeout)
  end

  @doc """
  Trigger manual sync of all risk lists.
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

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(opts) do
    state = %{
      api_token: Keyword.get(opts, :api_token) || System.get_env("RECORDED_FUTURE_API_TOKEN"),
      enabled: Keyword.get(opts, :enabled, true),
      sync_interval: Keyword.get(opts, :sync_interval, @default_sync_interval),
      last_sync: nil,
      sync_status: %{},
      stats: %{
        lookups: 0,
        iocs_imported: 0,
        errors: 0
      }
    }

    if state.enabled && state.api_token do
      # Schedule initial sync
      Process.send_after(self(), :initial_sync, :timer.seconds(30))
      schedule_sync(state.sync_interval)
      Logger.info("[RecordedFuture] Initialized with API token configured")
    else
      Logger.info("[RecordedFuture] Disabled - no API token configured")
    end

    {:ok, state}
  end

  @impl true
  def handle_call({:lookup, indicator_type, value}, _from, state) do
    result = do_lookup(indicator_type, value, state)
    new_stats = Map.update!(state.stats, :lookups, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:batch_lookup, indicator_type, values}, _from, state) do
    result = do_batch_lookup(indicator_type, values, state)
    new_stats = Map.update!(state.stats, :lookups, &(&1 + length(values)))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:download_risk_list, list_type}, _from, state) do
    result = do_download_risk_list(list_type, state)

    new_state = case result do
      {:ok, count} ->
        new_stats = Map.update!(state.stats, :iocs_imported, &(&1 + count))
        %{state | stats: new_stats, sync_status: Map.put(state.sync_status, list_type, %{
          status: :ok,
          last_sync: DateTime.utc_now(),
          count: count
        })}

      {:error, _} ->
        new_stats = Map.update!(state.stats, :errors, &(&1 + 1))
        %{state | stats: new_stats, sync_status: Map.put(state.sync_status, list_type, %{
          status: :error,
          last_sync: nil
        })}
    end

    {:reply, result, new_state}
  end

  @impl true
  def handle_call({:get_threat_actor, actor_name}, _from, state) do
    result = do_get_threat_actor(actor_name, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:search_threat_actors, criteria}, _from, state) do
    result = do_search_threat_actors(criteria, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_vulnerability, cve_id}, _from, state) do
    result = do_get_vulnerability(cve_id, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      enabled: state.enabled,
      configured: state.api_token != nil,
      last_sync: state.last_sync,
      sync_status: state.sync_status,
      stats: state.stats
    }
    {:reply, status, state}
  end

  @impl true
  def handle_cast(:sync_all, state) do
    if state.api_token do
      Task.start(fn -> do_sync_all(state) end)
    end
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:initial_sync, state) do
    if state.api_token do
      Logger.info("[RecordedFuture] Starting initial sync...")
      Task.start(fn -> do_sync_all(state) end)
    end
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:periodic_sync, state) do
    if state.api_token do
      Logger.info("[RecordedFuture] Starting periodic sync...")
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

  defp do_lookup(indicator_type, value, state) do
    unless state.api_token do
      {:error, :not_configured}
    else
      entity_type = indicator_type_to_entity(indicator_type)
      url = "#{@base_url}/#{entity_type}/#{URI.encode(value)}"

      headers = [
        {"X-RFToken", state.api_token},
        {"Accept", "application/json"}
      ]

      case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_lookup_response(body, indicator_type)

        {:ok, %Finch.Response{status: 404}} ->
          {:ok, %{found: false, risk_score: 0}}

        {:ok, %Finch.Response{status: code, body: body}} ->
          Logger.warning("[RecordedFuture] API returned #{code}: #{String.slice(body, 0, 200)}")
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          Logger.error("[RecordedFuture] HTTP error: #{inspect(reason)}")
          {:error, reason}
      end
    end
  end

  defp do_batch_lookup(indicator_type, values, state) do
    unless state.api_token do
      {:error, :not_configured}
    else
      # RF supports batch lookups via sonar endpoint
      entity_type = indicator_type_to_entity(indicator_type)
      url = "#{@base_url}/sonar/#{entity_type}"

      headers = [
        {"X-RFToken", state.api_token},
        {"Accept", "application/json"},
        {"Content-Type", "application/json"}
      ]

      body = Jason.encode!(%{
        "entities" => Enum.map(values, &%{"name" => &1})
      })

      case Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout * 2) do
        {:ok, %Finch.Response{status: 200, body: resp_body}} ->
          parse_batch_response(resp_body, indicator_type)

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_download_risk_list(list_type, state) do
    unless state.api_token do
      {:error, :not_configured}
    else
      list_name = risk_list_name(list_type)
      url = "#{@fusion_url}/#{list_name}"

      headers = [
        {"X-RFToken", state.api_token},
        {"Accept", "text/csv"}
      ]

      Logger.info("[RecordedFuture] Downloading risk list: #{list_type}")

      case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout * 5) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          iocs = parse_risk_list(body, list_type)

          # Submit to aggregator for deduplication and enrichment
          Aggregator.ingest_batch("recorded_future", iocs)

          Logger.info("[RecordedFuture] Imported #{length(iocs)} IOCs from #{list_type}")
          {:ok, length(iocs)}

        {:ok, %Finch.Response{status: code}} ->
          Logger.warning("[RecordedFuture] Risk list download returned #{code}")
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          Logger.error("[RecordedFuture] Risk list download error: #{inspect(reason)}")
          {:error, reason}
      end
    end
  end

  defp do_get_threat_actor(actor_name, state) do
    unless state.api_token do
      {:error, :not_configured}
    else
      # Search for threat actor entity
      url = "#{@base_url}/threatActor/search"

      headers = [
        {"X-RFToken", state.api_token},
        {"Accept", "application/json"},
        {"Content-Type", "application/json"}
      ]

      body = Jason.encode!(%{
        "filter" => %{
          "name" => %{"$contains" => actor_name}
        },
        "fields" => ["id", "name", "type", "targets", "techniques", "tools", "aliases", "firstSeen", "lastSeen"]
      })

      case Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: resp_body}} ->
          parse_threat_actor_response(resp_body)

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_search_threat_actors(criteria, state) do
    unless state.api_token do
      {:error, :not_configured}
    else
      url = "#{@base_url}/threatActor/search"

      headers = [
        {"X-RFToken", state.api_token},
        {"Accept", "application/json"},
        {"Content-Type", "application/json"}
      ]

      # Build filter from criteria
      filter = build_actor_search_filter(criteria)

      body = Jason.encode!(%{
        "filter" => filter,
        "fields" => ["id", "name", "type", "targets", "techniques", "aliases"],
        "limit" => Map.get(criteria, :limit, 50)
      })

      case Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: resp_body}} ->
          parse_threat_actors_list(resp_body)

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_get_vulnerability(cve_id, state) do
    unless state.api_token do
      {:error, :not_configured}
    else
      url = "#{@base_url}/vulnerability/#{URI.encode(cve_id)}"

      headers = [
        {"X-RFToken", state.api_token},
        {"Accept", "application/json"}
      ]

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

  defp do_sync_all(state) do
    Logger.info("[RecordedFuture] Syncing all risk lists...")

    Enum.each(@risk_list_types, fn list_type ->
      try do
        do_download_risk_list(list_type, state)
      rescue
        e -> Logger.error("[RecordedFuture] Failed to sync #{list_type}: #{inspect(e)}")
      end

      # Rate limiting - RF API has limits
      Process.sleep(2000)
    end)

    Logger.info("[RecordedFuture] Sync complete")
  end

  # ============================================================================
  # Private Functions - Parsing
  # ============================================================================

  defp parse_lookup_response(body, indicator_type) do
    case Jason.decode(body) do
      {:ok, %{"data" => data}} ->
        risk_score = get_in(data, ["risk", "score"]) || 0
        risk_rules = get_in(data, ["risk", "evidenceDetails"]) || []

        {:ok, %{
          found: true,
          risk_score: risk_score,
          risk_level: risk_level(risk_score),
          type: indicator_type,
          risk_rules: Enum.map(risk_rules, fn rule ->
            %{
              name: rule["rule"],
              criticality: rule["criticalityLabel"],
              evidence_string: rule["evidenceString"],
              timestamp: rule["timestamp"]
            }
          end),
          threat_lists: get_in(data, ["threatLists"]) || [],
          related_entities: extract_related_entities(data),
          metadata: %{
            first_seen: get_in(data, ["timestamps", "firstSeen"]),
            last_seen: get_in(data, ["timestamps", "lastSeen"]),
            intel_card: get_in(data, ["intelCard"])
          }
        }}

      {:ok, _} ->
        {:ok, %{found: false, risk_score: 0}}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_batch_response(body, _indicator_type) do
    case Jason.decode(body) do
      {:ok, %{"data" => %{"results" => results}}} ->
        entities = Enum.map(results, fn result ->
          %{
            value: get_in(result, ["entity", "name"]),
            found: true,
            risk_score: get_in(result, ["risk", "score"]) || 0,
            risk_level: risk_level(get_in(result, ["risk", "score"]) || 0)
          }
        end)
        {:ok, entities}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_risk_list(csv_body, list_type) do
    {ioc_type, _threshold} = list_type_to_ioc_type(list_type)

    csv_body
    |> String.split("\n")
    |> Enum.drop(1)  # Skip header
    |> Enum.reject(&(&1 == "" or String.starts_with?(&1, "#")))
    |> Enum.map(fn line ->
      case String.split(line, ",") do
        [value, risk_score | rest] ->
          score = parse_integer(risk_score)

          %{
            type: ioc_type,
            value: String.downcase(String.trim(value, "\"")),
            source: "recorded_future",
            severity: severity_from_risk_score(score),
            confidence: confidence_from_risk_score(score),
            tags: ["recorded_future", list_type_to_tag(list_type)],
            metadata: %{
              "risk_score" => score,
              "risk_rules" => parse_risk_rules(rest),
              "provider" => "recorded_future"
            }
          }

        _ ->
          nil
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp parse_threat_actor_response(body) do
    case Jason.decode(body) do
      {:ok, %{"data" => %{"results" => [result | _]}}} ->
        {:ok, %{
          id: result["id"],
          name: get_in(result, ["entity", "name"]),
          aliases: get_in(result, ["aliases"]) || [],
          targets: extract_targets(result),
          techniques: extract_techniques(result),
          tools: get_in(result, ["tools"]) || [],
          first_seen: get_in(result, ["timestamps", "firstSeen"]),
          last_seen: get_in(result, ["timestamps", "lastSeen"]),
          metadata: %{
            provider: "recorded_future",
            intel_card: get_in(result, ["intelCard"])
          }
        }}

      {:ok, %{"data" => %{"results" => []}}} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_threat_actors_list(body) do
    case Jason.decode(body) do
      {:ok, %{"data" => %{"results" => results}}} ->
        actors = Enum.map(results, fn result ->
          %{
            id: result["id"],
            name: get_in(result, ["entity", "name"]),
            aliases: get_in(result, ["aliases"]) || [],
            targets: extract_targets(result),
            techniques: extract_techniques(result)
          }
        end)
        {:ok, actors}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_vulnerability_response(body) do
    case Jason.decode(body) do
      {:ok, %{"data" => data}} ->
        {:ok, %{
          cve_id: get_in(data, ["entity", "name"]),
          risk_score: get_in(data, ["risk", "score"]) || 0,
          cvss_score: get_in(data, ["cvss", "score"]),
          cvss_vector: get_in(data, ["cvss", "accessVector"]),
          affected_products: get_in(data, ["affectedProducts"]) || [],
          exploits_available: get_in(data, ["exploits"]) != nil,
          exploit_count: length(get_in(data, ["exploits"]) || []),
          threat_actors: extract_vuln_threat_actors(data),
          published_date: get_in(data, ["publishedDate"]),
          trending: get_in(data, ["trending"]) == true,
          metadata: %{
            provider: "recorded_future",
            intel_card: get_in(data, ["intelCard"])
          }
        }}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp schedule_sync(interval) do
    Process.send_after(self(), :periodic_sync, interval)
  end

  defp indicator_type_to_entity(:ip), do: "ip"
  defp indicator_type_to_entity(:domain), do: "domain"
  defp indicator_type_to_entity(:hash), do: "hash"
  defp indicator_type_to_entity(:hash_md5), do: "hash"
  defp indicator_type_to_entity(:hash_sha1), do: "hash"
  defp indicator_type_to_entity(:hash_sha256), do: "hash"
  defp indicator_type_to_entity(:url), do: "url"
  defp indicator_type_to_entity(:cve), do: "vulnerability"
  defp indicator_type_to_entity(_), do: "ip"

  defp risk_list_name(:ip_high_risk), do: "ip_risk_list_high"
  defp risk_list_name(:ip_critical_risk), do: "ip_risk_list_critical"
  defp risk_list_name(:domain_high_risk), do: "domain_risk_list_high"
  defp risk_list_name(:domain_critical_risk), do: "domain_risk_list_critical"
  defp risk_list_name(:hash_high_risk), do: "hash_risk_list_high"
  defp risk_list_name(:hash_critical_risk), do: "hash_risk_list_critical"
  defp risk_list_name(:url_high_risk), do: "url_risk_list_high"
  defp risk_list_name(:vulnerability_critical), do: "vulnerability_risk_list_critical"
  defp risk_list_name(_), do: "ip_risk_list_high"

  defp list_type_to_ioc_type(:ip_high_risk), do: {"ip", @high_risk_threshold}
  defp list_type_to_ioc_type(:ip_critical_risk), do: {"ip", @critical_risk_threshold}
  defp list_type_to_ioc_type(:domain_high_risk), do: {"domain", @high_risk_threshold}
  defp list_type_to_ioc_type(:domain_critical_risk), do: {"domain", @critical_risk_threshold}
  defp list_type_to_ioc_type(:hash_high_risk), do: {"hash_sha256", @high_risk_threshold}
  defp list_type_to_ioc_type(:hash_critical_risk), do: {"hash_sha256", @critical_risk_threshold}
  defp list_type_to_ioc_type(:url_high_risk), do: {"url", @high_risk_threshold}
  defp list_type_to_ioc_type(:vulnerability_critical), do: {"cve", @critical_risk_threshold}
  defp list_type_to_ioc_type(_), do: {"ip", @high_risk_threshold}

  defp list_type_to_tag(:ip_high_risk), do: "ip_high_risk"
  defp list_type_to_tag(:ip_critical_risk), do: "ip_critical_risk"
  defp list_type_to_tag(:domain_high_risk), do: "domain_high_risk"
  defp list_type_to_tag(:domain_critical_risk), do: "domain_critical_risk"
  defp list_type_to_tag(:hash_high_risk), do: "hash_high_risk"
  defp list_type_to_tag(:hash_critical_risk), do: "hash_critical_risk"
  defp list_type_to_tag(:url_high_risk), do: "url_high_risk"
  defp list_type_to_tag(:vulnerability_critical), do: "vuln_critical"
  defp list_type_to_tag(_), do: "unknown"

  defp risk_level(score) when score >= @critical_risk_threshold, do: :critical
  defp risk_level(score) when score >= @high_risk_threshold, do: :high
  defp risk_level(score) when score >= 40, do: :medium
  defp risk_level(_), do: :low

  defp severity_from_risk_score(score) when score >= @critical_risk_threshold, do: "critical"
  defp severity_from_risk_score(score) when score >= @high_risk_threshold, do: "high"
  defp severity_from_risk_score(score) when score >= 40, do: "medium"
  defp severity_from_risk_score(_), do: "low"

  defp confidence_from_risk_score(score), do: min(score / 100.0, 1.0)

  defp parse_integer(str) do
    case Integer.parse(String.trim(str)) do
      {n, _} -> n
      :error -> 0
    end
  end

  defp parse_risk_rules([]), do: []
  defp parse_risk_rules([rules_str | _]) do
    rules_str
    |> String.trim("\"")
    |> String.split(";")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
  end

  defp extract_related_entities(data) do
    %{
      related_ips: get_in(data, ["relatedEntities", "ip"]) || [],
      related_domains: get_in(data, ["relatedEntities", "domain"]) || [],
      related_hashes: get_in(data, ["relatedEntities", "hash"]) || [],
      related_malware: get_in(data, ["relatedEntities", "malware"]) || [],
      threat_actors: get_in(data, ["relatedEntities", "threatActor"]) || []
    }
  end

  defp extract_targets(result) do
    targets = get_in(result, ["targets"]) || []
    Enum.map(targets, fn t ->
      %{
        name: get_in(t, ["entity", "name"]),
        type: get_in(t, ["entity", "type"])
      }
    end)
  end

  defp extract_techniques(result) do
    techniques = get_in(result, ["techniques"]) || []
    Enum.map(techniques, fn t ->
      get_in(t, ["entity", "name"])
    end)
  end

  defp extract_vuln_threat_actors(data) do
    actors = get_in(data, ["relatedEntities", "threatActor"]) || []
    Enum.map(actors, fn a ->
      %{
        name: get_in(a, ["entity", "name"]),
        id: get_in(a, ["entity", "id"])
      }
    end)
  end

  defp build_actor_search_filter(criteria) do
    filter = %{}

    filter = if criteria[:target_sector] do
      Map.put(filter, "targets.entity.type", %{"$eq" => criteria[:target_sector]})
    else
      filter
    end

    filter = if criteria[:origin_country] do
      Map.put(filter, "locations.entity.name", %{"$contains" => criteria[:origin_country]})
    else
      filter
    end

    filter = if criteria[:technique] do
      Map.put(filter, "techniques.entity.name", %{"$contains" => criteria[:technique]})
    else
      filter
    end

    filter
  end
end
