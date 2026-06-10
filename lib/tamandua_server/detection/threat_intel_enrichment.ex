defmodule TamanduaServer.Detection.ThreatIntelEnrichment do
  @moduledoc """
  Real-time Threat Intelligence Enrichment Service.

  Provides on-demand enrichment of events with threat intelligence data:
  - Hash reputation lookups (VirusTotal, MalwareBazaar)
  - Domain/URL reputation checks
  - IP geolocation and reputation
  - IOC matching against local cache

  ## Usage

      # Enrich a file event with hash reputation
      ThreatIntelEnrichment.enrich_hash("abc123...")

      # Check domain reputation
      ThreatIntelEnrichment.check_domain("suspicious.com")

      # Full event enrichment
      ThreatIntelEnrichment.enrich_event(event)
  """

  use GenServer
  require Logger

  alias TamanduaServer.ThreatIntel
  alias TamanduaServer.Detection.IOCs

  @virustotal_api "https://www.virustotal.com/api/v3"
  @abuseipdb_api "https://api.abuseipdb.com/api/v2"
  @urlscan_api "https://urlscan.io/api/v1"

  # Cache TTL for enrichment results (1 hour)
  @cache_ttl :timer.hours(1)

  # Rate limiting
  @vt_rate_limit 4  # requests per minute for free tier
  @rate_window :timer.minutes(1)

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Enrich a hash with reputation data from multiple sources.

  Returns enrichment data including:
  - `:malicious` - Number of engines flagging as malicious
  - `:suspicious` - Number of engines flagging as suspicious
  - `:harmless` - Number of engines flagging as harmless
  - `:verdict` - Overall verdict (:clean, :suspicious, :malicious, :unknown)
  - `:first_seen` - When first seen in the wild
  - `:names` - Known file names
  - `:tags` - Associated tags/families
  """
  @spec enrich_hash(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def enrich_hash(hash, opts \\ []) do
    GenServer.call(__MODULE__, {:enrich_hash, hash, opts}, 30_000)
  end

  @doc """
  Check domain reputation and categorization.

  Returns:
  - `:verdict` - Overall verdict
  - `:categories` - Domain categories
  - `:popularity` - Popularity ranking if available
  - `:registrar` - Domain registrar
  - `:creation_date` - Domain creation date
  - `:malicious_votes` - Number of malicious votes
  """
  @spec check_domain(String.t()) :: {:ok, map()} | {:error, term()}
  def check_domain(domain) do
    GenServer.call(__MODULE__, {:check_domain, domain}, 30_000)
  end

  @doc """
  Check IP reputation and geolocation.

  Returns:
  - `:verdict` - Overall verdict
  - `:abuse_score` - Abuse confidence score (0-100)
  - `:country` - Country code
  - `:isp` - ISP name
  - `:usage_type` - Usage type (residential, datacenter, etc.)
  - `:is_tor` - Whether IP is a Tor exit node
  - `:is_vpn` - Whether IP is a known VPN
  """
  @spec check_ip(String.t()) :: {:ok, map()} | {:error, term()}
  def check_ip(ip) do
    GenServer.call(__MODULE__, {:check_ip, ip}, 30_000)
  end

  @doc """
  Check URL reputation.

  Returns:
  - `:verdict` - Overall verdict
  - `:categories` - URL categories
  - `:screenshot_url` - Screenshot if available
  - `:final_url` - Final URL after redirects
  """
  @spec check_url(String.t()) :: {:ok, map()} | {:error, term()}
  def check_url(url) do
    GenServer.call(__MODULE__, {:check_url, url}, 30_000)
  end

  @doc """
  Enrich a full event with all available threat intelligence.

  Analyzes the event payload and enriches with relevant TI data.
  """
  @spec enrich_event(map()) :: {:ok, map()} | {:error, term()}
  def enrich_event(event) do
    GenServer.call(__MODULE__, {:enrich_event, event}, 60_000)
  end

  @doc """
  Batch enrich multiple IOCs.
  """
  @spec batch_enrich([map()]) :: {:ok, [map()]} | {:error, term()}
  def batch_enrich(iocs) do
    GenServer.call(__MODULE__, {:batch_enrich, iocs}, 120_000)
  end

  @doc """
  Check if an IOC matches our local threat intel cache.
  """
  @spec check_local_cache(atom(), String.t()) :: {:ok, map()} | :not_found
  def check_local_cache(type, value) do
    ThreatIntel.lookup(type, value)
  end

  @doc """
  Configure API keys for premium services.
  """
  @spec configure(atom(), String.t()) :: :ok
  def configure(service, api_key) when service in [:virustotal, :abuseipdb, :urlscan] do
    GenServer.call(__MODULE__, {:configure, service, api_key})
  end

  @doc """
  Get current configuration status.
  """
  @spec get_config_status() :: map()
  def get_config_status do
    GenServer.call(__MODULE__, :get_config_status)
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(opts) do
    # Create ETS cache for enrichment results
    :ets.new(:ti_enrichment_cache, [:named_table, :set, :public, read_concurrency: true])

    state = %{
      api_keys: %{
        virustotal: System.get_env("VIRUSTOTAL_API_KEY"),
        abuseipdb: System.get_env("ABUSEIPDB_API_KEY"),
        urlscan: System.get_env("URLSCAN_API_KEY")
      },
      rate_limits: %{
        virustotal: {0, nil}  # {request_count, window_start}
      },
      stats: %{
        lookups: 0,
        cache_hits: 0,
        api_calls: 0,
        errors: 0
      },
      enabled: Keyword.get(opts, :enabled, true)
    }

    Logger.info("[ThreatIntelEnrichment] Initialized")
    {:ok, state}
  end

  @impl true
  def handle_call({:enrich_hash, hash, opts}, _from, state) do
    normalized = String.downcase(hash)
    hash_type = determine_hash_type(normalized)

    # Check cache first
    case get_cached(:hash, normalized) do
      {:ok, cached} ->
        state = update_stats(state, :cache_hit)
        {:reply, {:ok, cached}, state}

      :miss ->
        # Check local TI cache
        local_match = check_local_cache(hash_type, normalized)

        # Query external services
        {result, state} = do_enrich_hash(normalized, hash_type, local_match, opts, state)

        # Cache result
        if match?({:ok, _}, result), do: cache_result(:hash, normalized, elem(result, 1))

        {:reply, result, state}
    end
  end

  @impl true
  def handle_call({:check_domain, domain}, _from, state) do
    normalized = String.downcase(domain)

    case get_cached(:domain, normalized) do
      {:ok, cached} ->
        state = update_stats(state, :cache_hit)
        {:reply, {:ok, cached}, state}

      :miss ->
        # Check local TI
        local_match = check_local_cache(:domain, normalized)

        {result, state} = do_check_domain(normalized, local_match, state)

        if match?({:ok, _}, result), do: cache_result(:domain, normalized, elem(result, 1))

        {:reply, result, state}
    end
  end

  @impl true
  def handle_call({:check_ip, ip}, _from, state) do
    case get_cached(:ip, ip) do
      {:ok, cached} ->
        state = update_stats(state, :cache_hit)
        {:reply, {:ok, cached}, state}

      :miss ->
        local_match = check_local_cache(:ip, ip)
        {result, state} = do_check_ip(ip, local_match, state)

        if match?({:ok, _}, result), do: cache_result(:ip, ip, elem(result, 1))

        {:reply, result, state}
    end
  end

  @impl true
  def handle_call({:check_url, url}, _from, state) do
    normalized = String.downcase(url)

    case get_cached(:url, normalized) do
      {:ok, cached} ->
        state = update_stats(state, :cache_hit)
        {:reply, {:ok, cached}, state}

      :miss ->
        local_match = check_local_cache(:url, normalized)
        {result, state} = do_check_url(normalized, local_match, state)

        if match?({:ok, _}, result), do: cache_result(:url, normalized, elem(result, 1))

        {:reply, result, state}
    end
  end

  @impl true
  def handle_call({:enrich_event, event}, _from, state) do
    {enrichment, state} = do_enrich_event(event, state)
    {:reply, {:ok, enrichment}, state}
  end

  @impl true
  def handle_call({:batch_enrich, iocs}, _from, state) do
    {results, state} =
      Enum.reduce(iocs, {[], state}, fn ioc, {acc, s} ->
        {result, s} = enrich_single_ioc(ioc, s)
        {[result | acc], s}
      end)

    {:reply, {:ok, Enum.reverse(results)}, state}
  end

  @impl true
  def handle_call({:configure, service, api_key}, _from, state) do
    state = put_in(state.api_keys[service], api_key)
    Logger.info("[ThreatIntelEnrichment] Configured #{service} API key")
    {:reply, :ok, state}
  end

  @impl true
  def handle_call(:get_config_status, _from, state) do
    status = %{
      configured: %{
        virustotal: state.api_keys.virustotal != nil,
        abuseipdb: state.api_keys.abuseipdb != nil,
        urlscan: state.api_keys.urlscan != nil
      },
      stats: state.stats,
      enabled: state.enabled
    }
    {:reply, status, state}
  end

  # ============================================================================
  # Private Functions - Hash Enrichment
  # ============================================================================

  defp do_enrich_hash(hash, hash_type, local_match, opts, state) do
    enrichment = %{
      hash: hash,
      hash_type: hash_type,
      local_match: local_match != :not_found,
      local_data: if(local_match != :not_found, do: elem(local_match, 1), else: nil),
      virustotal: nil,
      verdict: :unknown,
      enriched_at: DateTime.utc_now()
    }

    # Query VirusTotal if configured and allowed
    {vt_result, state} =
      if state.api_keys.virustotal && Keyword.get(opts, :skip_vt, false) == false do
        query_virustotal_hash(hash, hash_type, state)
      else
        {nil, state}
      end

    enrichment = %{enrichment | virustotal: vt_result}

    # Calculate overall verdict
    verdict = calculate_hash_verdict(enrichment)
    enrichment = %{enrichment | verdict: verdict}

    state = update_stats(state, :lookup)
    {{:ok, enrichment}, state}
  end

  defp query_virustotal_hash(hash, hash_type, state) do
    # Check rate limit
    {state, allowed} = check_rate_limit(state, :virustotal)

    if allowed do
      api_key = state.api_keys.virustotal
      url = "#{@virustotal_api}/files/#{hash}"
      headers = [{"x-apikey", api_key}]

      state = update_stats(state, :api_call)

      case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: 15_000) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          case Jason.decode(body) do
            {:ok, %{"data" => data}} ->
              attrs = Map.get(data, "attributes", %{})
              stats = Map.get(attrs, "last_analysis_stats", %{})

              result = %{
                malicious: Map.get(stats, "malicious", 0),
                suspicious: Map.get(stats, "suspicious", 0),
                harmless: Map.get(stats, "harmless", 0),
                undetected: Map.get(stats, "undetected", 0),
                type_description: Map.get(attrs, "type_description"),
                meaningful_name: Map.get(attrs, "meaningful_name"),
                names: Map.get(attrs, "names", []) |> Enum.take(5),
                tags: Map.get(attrs, "tags", []),
                first_submission: Map.get(attrs, "first_submission_date"),
                last_analysis: Map.get(attrs, "last_analysis_date"),
                signature_info: Map.get(attrs, "signature_info"),
                sandbox_verdicts: extract_sandbox_verdicts(attrs)
              }

              {result, state}

            _ ->
              {nil, update_stats(state, :error)}
          end

        {:ok, %Finch.Response{status: 404}} ->
          # Not found - hash not in VT database
          {%{not_found: true}, state}

        {:ok, %Finch.Response{status: 429}} ->
          Logger.warning("[ThreatIntelEnrichment] VirusTotal rate limit hit")
          {%{rate_limited: true}, state}

        {:error, reason} ->
          Logger.error("[ThreatIntelEnrichment] VT error: #{inspect(reason)}")
          {nil, update_stats(state, :error)}
      end
    else
      {%{rate_limited: true}, state}
    end
  end

  defp extract_sandbox_verdicts(attrs) do
    attrs
    |> Map.get("sandbox_verdicts", %{})
    |> Enum.take(3)
    |> Enum.map(fn {sandbox, verdict} ->
      %{sandbox: sandbox, verdict: Map.get(verdict, "category")}
    end)
  end

  defp calculate_hash_verdict(enrichment) do
    cond do
      enrichment.local_match ->
        :malicious

      enrichment.virustotal && enrichment.virustotal[:malicious] > 5 ->
        :malicious

      enrichment.virustotal && enrichment.virustotal[:malicious] > 0 ->
        :suspicious

      enrichment.virustotal && enrichment.virustotal[:harmless] > 10 ->
        :clean

      enrichment.virustotal && enrichment.virustotal[:not_found] ->
        :unknown

      true ->
        :unknown
    end
  end

  # ============================================================================
  # Private Functions - Domain Enrichment
  # ============================================================================

  defp do_check_domain(domain, local_match, state) do
    enrichment = %{
      domain: domain,
      local_match: local_match != :not_found,
      local_data: if(local_match != :not_found, do: elem(local_match, 1), else: nil),
      virustotal: nil,
      whois: nil,
      verdict: :unknown,
      enriched_at: DateTime.utc_now()
    }

    # Query VirusTotal for domain
    {vt_result, state} =
      if state.api_keys.virustotal do
        query_virustotal_domain(domain, state)
      else
        {nil, state}
      end

    enrichment = %{enrichment | virustotal: vt_result}

    # Calculate verdict
    verdict = calculate_domain_verdict(enrichment)
    enrichment = %{enrichment | verdict: verdict}

    state = update_stats(state, :lookup)
    {{:ok, enrichment}, state}
  end

  defp query_virustotal_domain(domain, state) do
    {state, allowed} = check_rate_limit(state, :virustotal)

    if allowed do
      api_key = state.api_keys.virustotal
      url = "#{@virustotal_api}/domains/#{domain}"
      headers = [{"x-apikey", api_key}]

      state = update_stats(state, :api_call)

      case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: 15_000) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          case Jason.decode(body) do
            {:ok, %{"data" => data}} ->
              attrs = Map.get(data, "attributes", %{})
              stats = Map.get(attrs, "last_analysis_stats", %{})

              result = %{
                malicious: Map.get(stats, "malicious", 0),
                suspicious: Map.get(stats, "suspicious", 0),
                harmless: Map.get(stats, "harmless", 0),
                categories: Map.get(attrs, "categories", %{}),
                registrar: Map.get(attrs, "registrar"),
                creation_date: Map.get(attrs, "creation_date"),
                popularity_ranks: Map.get(attrs, "popularity_ranks", %{}),
                last_analysis: Map.get(attrs, "last_analysis_date")
              }

              {result, state}

            _ ->
              {nil, update_stats(state, :error)}
          end

        {:ok, %Finch.Response{status: 404}} ->
          {%{not_found: true}, state}

        {:ok, %Finch.Response{status: 429}} ->
          {%{rate_limited: true}, state}

        {:error, reason} ->
          Logger.error("[ThreatIntelEnrichment] VT domain error: #{inspect(reason)}")
          {nil, update_stats(state, :error)}
      end
    else
      {%{rate_limited: true}, state}
    end
  end

  defp calculate_domain_verdict(enrichment) do
    cond do
      enrichment.local_match ->
        :malicious

      enrichment.virustotal && enrichment.virustotal[:malicious] > 3 ->
        :malicious

      enrichment.virustotal && enrichment.virustotal[:malicious] > 0 ->
        :suspicious

      enrichment.virustotal && enrichment.virustotal[:harmless] > 5 ->
        :clean

      true ->
        :unknown
    end
  end

  # ============================================================================
  # Private Functions - IP Enrichment
  # ============================================================================

  defp do_check_ip(ip, local_match, state) do
    enrichment = %{
      ip: ip,
      local_match: local_match != :not_found,
      local_data: if(local_match != :not_found, do: elem(local_match, 1), else: nil),
      abuseipdb: nil,
      virustotal: nil,
      verdict: :unknown,
      enriched_at: DateTime.utc_now()
    }

    # Query AbuseIPDB
    {abuse_result, state} =
      if state.api_keys.abuseipdb do
        query_abuseipdb(ip, state)
      else
        {nil, state}
      end

    enrichment = %{enrichment | abuseipdb: abuse_result}

    # Query VirusTotal for IP
    {vt_result, state} =
      if state.api_keys.virustotal do
        query_virustotal_ip(ip, state)
      else
        {nil, state}
      end

    enrichment = %{enrichment | virustotal: vt_result}

    # Calculate verdict
    verdict = calculate_ip_verdict(enrichment)
    enrichment = %{enrichment | verdict: verdict}

    state = update_stats(state, :lookup)
    {{:ok, enrichment}, state}
  end

  defp query_abuseipdb(ip, state) do
    api_key = state.api_keys.abuseipdb
    url = "#{@abuseipdb_api}/check?ipAddress=#{ip}&maxAgeInDays=90"
    headers = [{"Key", api_key}, {"Accept", "application/json"}]

    state = update_stats(state, :api_call)

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: 15_000) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, %{"data" => data}} ->
            result = %{
              abuse_confidence_score: Map.get(data, "abuseConfidenceScore", 0),
              country_code: Map.get(data, "countryCode"),
              isp: Map.get(data, "isp"),
              domain: Map.get(data, "domain"),
              usage_type: Map.get(data, "usageType"),
              total_reports: Map.get(data, "totalReports", 0),
              last_reported: Map.get(data, "lastReportedAt"),
              is_whitelisted: Map.get(data, "isWhitelisted", false),
              is_tor: Map.get(data, "isTor", false)
            }

            {result, state}

          _ ->
            {nil, update_stats(state, :error)}
        end

      {:error, reason} ->
        Logger.error("[ThreatIntelEnrichment] AbuseIPDB error: #{inspect(reason)}")
        {nil, update_stats(state, :error)}
    end
  end

  defp query_virustotal_ip(ip, state) do
    {state, allowed} = check_rate_limit(state, :virustotal)

    if allowed do
      api_key = state.api_keys.virustotal
      url = "#{@virustotal_api}/ip_addresses/#{ip}"
      headers = [{"x-apikey", api_key}]

      state = update_stats(state, :api_call)

      case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: 15_000) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          case Jason.decode(body) do
            {:ok, %{"data" => data}} ->
              attrs = Map.get(data, "attributes", %{})
              stats = Map.get(attrs, "last_analysis_stats", %{})

              result = %{
                malicious: Map.get(stats, "malicious", 0),
                suspicious: Map.get(stats, "suspicious", 0),
                harmless: Map.get(stats, "harmless", 0),
                asn: Map.get(attrs, "asn"),
                as_owner: Map.get(attrs, "as_owner"),
                country: Map.get(attrs, "country"),
                network: Map.get(attrs, "network"),
                last_analysis: Map.get(attrs, "last_analysis_date")
              }

              {result, state}

            _ ->
              {nil, update_stats(state, :error)}
          end

        {:ok, %Finch.Response{status: 429}} ->
          {%{rate_limited: true}, state}

        {:error, reason} ->
          Logger.error("[ThreatIntelEnrichment] VT IP error: #{inspect(reason)}")
          {nil, update_stats(state, :error)}
      end
    else
      {%{rate_limited: true}, state}
    end
  end

  defp calculate_ip_verdict(enrichment) do
    cond do
      enrichment.local_match ->
        :malicious

      enrichment.abuseipdb && enrichment.abuseipdb[:abuse_confidence_score] > 75 ->
        :malicious

      enrichment.abuseipdb && enrichment.abuseipdb[:abuse_confidence_score] > 25 ->
        :suspicious

      enrichment.virustotal && enrichment.virustotal[:malicious] > 3 ->
        :malicious

      enrichment.abuseipdb && enrichment.abuseipdb[:is_whitelisted] ->
        :clean

      true ->
        :unknown
    end
  end

  # ============================================================================
  # Private Functions - URL Enrichment
  # ============================================================================

  defp do_check_url(url, local_match, state) do
    enrichment = %{
      url: url,
      local_match: local_match != :not_found,
      local_data: if(local_match != :not_found, do: elem(local_match, 1), else: nil),
      virustotal: nil,
      verdict: :unknown,
      enriched_at: DateTime.utc_now()
    }

    # Extract domain for additional check
    domain = extract_domain_from_url(url)

    # Query VirusTotal for URL
    {vt_result, state} =
      if state.api_keys.virustotal do
        query_virustotal_url(url, state)
      else
        {nil, state}
      end

    enrichment = %{enrichment | virustotal: vt_result, extracted_domain: domain}

    # Calculate verdict
    verdict = calculate_url_verdict(enrichment)
    enrichment = %{enrichment | verdict: verdict}

    state = update_stats(state, :lookup)
    {{:ok, enrichment}, state}
  end

  defp query_virustotal_url(url, state) do
    {state, allowed} = check_rate_limit(state, :virustotal)

    if allowed do
      api_key = state.api_keys.virustotal
      # URL needs to be base64 encoded for VT API
      url_id = Base.url_encode64(url, padding: false)
      api_url = "#{@virustotal_api}/urls/#{url_id}"
      headers = [{"x-apikey", api_key}]

      state = update_stats(state, :api_call)

      case Finch.build(:get, api_url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: 15_000) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          case Jason.decode(body) do
            {:ok, %{"data" => data}} ->
              attrs = Map.get(data, "attributes", %{})
              stats = Map.get(attrs, "last_analysis_stats", %{})

              result = %{
                malicious: Map.get(stats, "malicious", 0),
                suspicious: Map.get(stats, "suspicious", 0),
                harmless: Map.get(stats, "harmless", 0),
                categories: Map.get(attrs, "categories", %{}),
                final_url: Map.get(attrs, "last_final_url"),
                title: Map.get(attrs, "title"),
                last_analysis: Map.get(attrs, "last_analysis_date")
              }

              {result, state}

            _ ->
              {nil, update_stats(state, :error)}
          end

        {:ok, %Finch.Response{status: 404}} ->
          {%{not_found: true}, state}

        {:ok, %Finch.Response{status: 429}} ->
          {%{rate_limited: true}, state}

        {:error, reason} ->
          Logger.error("[ThreatIntelEnrichment] VT URL error: #{inspect(reason)}")
          {nil, update_stats(state, :error)}
      end
    else
      {%{rate_limited: true}, state}
    end
  end

  defp calculate_url_verdict(enrichment) do
    cond do
      enrichment.local_match ->
        :malicious

      enrichment.virustotal && enrichment.virustotal[:malicious] > 3 ->
        :malicious

      enrichment.virustotal && enrichment.virustotal[:malicious] > 0 ->
        :suspicious

      enrichment.virustotal && enrichment.virustotal[:harmless] > 5 ->
        :clean

      true ->
        :unknown
    end
  end

  # ============================================================================
  # Private Functions - Full Event Enrichment
  # ============================================================================

  defp do_enrich_event(event, state) do
    enrichment = %{
      event_id: Map.get(event, :id),
      enrichments: [],
      ioc_matches: [],
      threat_score: 0,
      enriched_at: DateTime.utc_now(),
      verdict: :clean
    }

    payload = Map.get(event, :payload, %{})

    # Extract and enrich hashes
    {hash_enrichments, state} = enrich_event_hashes(payload, state)

    # Extract and enrich IPs
    {ip_enrichments, state} = enrich_event_ips(payload, state)

    # Extract and enrich domains
    {domain_enrichments, state} = enrich_event_domains(payload, state)

    all_enrichments = hash_enrichments ++ ip_enrichments ++ domain_enrichments

    # Calculate overall threat score
    threat_score = calculate_event_threat_score(all_enrichments)

    enrichment = %{
      enrichment |
      enrichments: all_enrichments,
      threat_score: threat_score,
      verdict: if(threat_score > 70, do: :malicious, else: if(threat_score > 30, do: :suspicious, else: :clean))
    }

    {enrichment, state}
  end

  defp enrich_event_hashes(payload, state) do
    hashes = extract_hashes_from_payload(payload)

    Enum.reduce(hashes, {[], state}, fn {hash_type, hash}, {acc, s} ->
      case do_enrich_hash(hash, hash_type, :not_found, [skip_vt: false], s) do
        {{:ok, enrichment}, s} -> {[%{type: :hash, value: hash, enrichment: enrichment} | acc], s}
        {_, s} -> {acc, s}
      end
    end)
  end

  defp enrich_event_ips(payload, state) do
    ips = extract_ips_from_payload(payload)

    Enum.reduce(ips, {[], state}, fn ip, {acc, s} ->
      case do_check_ip(ip, :not_found, s) do
        {{:ok, enrichment}, s} -> {[%{type: :ip, value: ip, enrichment: enrichment} | acc], s}
        {_, s} -> {acc, s}
      end
    end)
  end

  defp enrich_event_domains(payload, state) do
    domains = extract_domains_from_payload(payload)

    Enum.reduce(domains, {[], state}, fn domain, {acc, s} ->
      case do_check_domain(domain, :not_found, s) do
        {{:ok, enrichment}, s} -> {[%{type: :domain, value: domain, enrichment: enrichment} | acc], s}
        {_, s} -> {acc, s}
      end
    end)
  end

  defp extract_hashes_from_payload(payload) do
    hashes = []

    hashes = if sha256 = Map.get(payload, :sha256) || Map.get(payload, "sha256") do
      [{:hash_sha256, sha256} | hashes]
    else
      hashes
    end

    hashes = if md5 = Map.get(payload, :md5) || Map.get(payload, "md5") do
      [{:hash_md5, md5} | hashes]
    else
      hashes
    end

    hashes
  end

  defp extract_ips_from_payload(payload) do
    ips = []

    ips = if remote_ip = Map.get(payload, :remote_ip) || Map.get(payload, "remote_ip") do
      [remote_ip | ips]
    else
      ips
    end

    ips = if dest_ip = Map.get(payload, :dest_ip) || Map.get(payload, "dest_ip") do
      [dest_ip | ips]
    else
      ips
    end

    Enum.uniq(ips)
  end

  defp extract_domains_from_payload(payload) do
    domains = []

    domains = if domain = Map.get(payload, :domain) || Map.get(payload, "domain") do
      [domain | domains]
    else
      domains
    end

    domains = if hostname = Map.get(payload, :hostname) || Map.get(payload, "hostname") do
      [hostname | domains]
    else
      domains
    end

    Enum.uniq(domains)
  end

  defp calculate_event_threat_score(enrichments) do
    if Enum.empty?(enrichments) do
      0
    else
      scores = Enum.map(enrichments, fn e ->
        case e.enrichment.verdict do
          :malicious -> 100
          :suspicious -> 50
          :clean -> 0
          _ -> 20
        end
      end)

      Enum.sum(scores) / length(scores)
    end
  end

  defp enrich_single_ioc(%{type: type, value: value}, state) do
    case type do
      t when t in [:hash_sha256, :hash_sha1, :hash_md5] ->
        do_enrich_hash(value, type, :not_found, [], state)

      :ip ->
        do_check_ip(value, :not_found, state)

      :domain ->
        do_check_domain(value, :not_found, state)

      :url ->
        do_check_url(value, :not_found, state)

      _ ->
        {{:error, :unsupported_type}, state}
    end
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp determine_hash_type(hash) do
    case String.length(hash) do
      32 -> :hash_md5
      40 -> :hash_sha1
      64 -> :hash_sha256
      _ -> :unknown
    end
  end

  defp extract_domain_from_url(url) do
    case URI.parse(url) do
      %URI{host: host} when is_binary(host) -> host
      _ -> nil
    end
  end

  defp get_cached(type, value) do
    key = {type, value}

    case :ets.lookup(:ti_enrichment_cache, key) do
      [{^key, data, inserted_at}] ->
        age = DateTime.diff(DateTime.utc_now(), inserted_at, :millisecond)

        if age < @cache_ttl do
          {:ok, data}
        else
          :ets.delete(:ti_enrichment_cache, key)
          :miss
        end

      [] ->
        :miss
    end
  end

  defp cache_result(type, value, data) do
    key = {type, value}
    :ets.insert(:ti_enrichment_cache, {key, data, DateTime.utc_now()})
  end

  defp check_rate_limit(state, :virustotal) do
    {count, window_start} = state.rate_limits.virustotal
    now = System.monotonic_time(:millisecond)

    cond do
      is_nil(window_start) ->
        # First request
        state = put_in(state.rate_limits.virustotal, {1, now})
        {state, true}

      now - window_start > @rate_window ->
        # Window expired, reset
        state = put_in(state.rate_limits.virustotal, {1, now})
        {state, true}

      count < @vt_rate_limit ->
        # Under limit
        state = put_in(state.rate_limits.virustotal, {count + 1, window_start})
        {state, true}

      true ->
        # Rate limited
        {state, false}
    end
  end

  defp update_stats(state, type) do
    case type do
      :lookup ->
        update_in(state.stats.lookups, &(&1 + 1))

      :cache_hit ->
        update_in(state.stats.cache_hits, &(&1 + 1))

      :api_call ->
        update_in(state.stats.api_calls, &(&1 + 1))

      :error ->
        update_in(state.stats.errors, &(&1 + 1))
    end
  end
end
