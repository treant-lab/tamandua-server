defmodule TamanduaServer.Detection.ThreatIntel.UnifiedEnrichment do
  @moduledoc """
  Unified Threat Intelligence Enrichment Service.

  Aggregates threat intelligence from multiple providers:
  - Abuse.ch (MalwareBazaar, URLhaus, ThreatFox)
  - VirusTotal (requires API key)
  - AlienVault OTX (requires API key)
  - Shodan (requires API key, IP enrichment only)

  Performs parallel lookups across all configured providers and merges results
  into a comprehensive enrichment report.

  ## Usage

      # Enrich a hash with all available providers
      UnifiedEnrichment.enrich(:hash, "abc123...")

      # Enrich an IP address
      UnifiedEnrichment.enrich(:ip, "192.168.1.1")

      # Enrich with specific providers only
      UnifiedEnrichment.enrich(:domain, "evil.com", providers: [:virustotal, :alienvault])

      # Configure API keys
      UnifiedEnrichment.configure(:virustotal, "api-key")

  ## Configuration

  Set environment variables or configure in config:

      config :tamandua_server, :threat_intel,
        virustotal_api_key: System.get_env("VT_API_KEY"),
        alienvault_api_key: System.get_env("OTX_API_KEY"),
        shodan_api_key: System.get_env("SHODAN_API_KEY")
  """

  use GenServer
  require Logger

  alias TamanduaServer.Detection.ThreatIntel.{AbuseCh, VirusTotal, AlienVault, Shodan, Feeds}

  # Timeout for individual provider lookups
  @provider_timeout 10_000

  # Timeout for the entire enrichment operation
  @enrichment_timeout 30_000

  # Default providers per indicator type
  @default_providers %{
    hash: [:feeds, :virustotal, :alienvault],
    ip: [:feeds, :virustotal, :alienvault, :shodan],
    domain: [:feeds, :virustotal, :alienvault],
    url: [:feeds, :virustotal, :alienvault]
  }

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Starts the UnifiedEnrichment GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Enrich an indicator using all available threat intelligence providers.

  Performs parallel lookups and merges results into a unified report.

  ## Parameters
  - `indicator_type` - One of: :hash, :ip, :domain, :url
  - `indicator_value` - The indicator to enrich
  - `opts` - Options:
    - `:providers` - List of specific providers to use (default: all available)
    - `:timeout` - Timeout in milliseconds (default: 30000)

  ## Examples

      iex> enrich(:hash, "abc123def456...")
      {:ok, %{
        indicator: "abc123def456...",
        indicator_type: :hash,
        verdict: :malicious,
        confidence: 0.95,
        sources: [:virustotal, :alienvault, :feeds],
        enrichments: %{
          virustotal: %{detection_stats: %{malicious: 45, ...}, ...},
          alienvault: %{pulse_count: 5, ...},
          feeds: %{found: true, threat_type: "malware", ...}
        },
        threat_summary: %{
          malware_families: ["Emotet", "TrickBot"],
          threat_types: ["trojan", "banking"],
          tags: ["c2", "ransomware"],
          first_seen: ~U[2024-01-15 10:00:00Z]
        },
        enriched_at: ~U[2024-01-20 15:30:00Z]
      }}

      iex> enrich(:ip, "192.168.1.1", providers: [:shodan, :virustotal])
      {:ok, %{...}}
  """
  @spec enrich(atom(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def enrich(indicator_type, indicator_value, opts \\ [])
      when indicator_type in [:hash, :ip, :domain, :url] and is_binary(indicator_value) do
    GenServer.call(__MODULE__, {:enrich, indicator_type, indicator_value, opts}, @enrichment_timeout + 5_000)
  end

  @doc """
  Batch enrich multiple indicators.

  ## Examples

      iex> batch_enrich([
        %{type: :hash, value: "abc123..."},
        %{type: :ip, value: "192.168.1.1"},
        %{type: :domain, value: "evil.com"}
      ])
      {:ok, [%{indicator: "abc123...", ...}, ...]}
  """
  @spec batch_enrich([map()], keyword()) :: {:ok, [map()]} | {:error, term()}
  def batch_enrich(indicators, opts \\ []) when is_list(indicators) do
    GenServer.call(__MODULE__, {:batch_enrich, indicators, opts}, 120_000)
  end

  @doc """
  Configure an API key for a specific provider.

  ## Examples

      iex> configure(:virustotal, "your-api-key")
      :ok
  """
  @spec configure(atom(), String.t()) :: :ok
  def configure(provider, api_key)
      when provider in [:virustotal, :alienvault, :shodan] and is_binary(api_key) do
    GenServer.call(__MODULE__, {:configure, provider, api_key})
  end

  @doc """
  Get the status of all providers.

  ## Examples

      iex> get_providers_status()
      %{
        virustotal: %{configured: true, rate_limit: %{remaining: 3}},
        alienvault: %{configured: true},
        shodan: %{configured: false},
        feeds: %{configured: true, ioc_count: 50000}
      }
  """
  @spec get_providers_status() :: map()
  def get_providers_status do
    GenServer.call(__MODULE__, :get_providers_status)
  end

  @doc """
  Quick lookup - check if an indicator is known malicious without full enrichment.

  Returns a simple verdict without performing expensive external lookups.

  ## Examples

      iex> quick_check(:hash, "abc123...")
      {:ok, %{
        found: true,
        verdict: :malicious,
        source: "feeds",
        confidence: 0.95
      }}
  """
  @spec quick_check(atom(), String.t()) :: {:ok, map()}
  def quick_check(indicator_type, indicator_value)
      when indicator_type in [:hash, :ip, :domain, :url] and is_binary(indicator_value) do
    GenServer.call(__MODULE__, {:quick_check, indicator_type, indicator_value})
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    state = %{
      enabled: Keyword.get(opts, :enabled, true),
      stats: %{
        enrichments: 0,
        batch_enrichments: 0,
        quick_checks: 0,
        errors: 0
      }
    }

    Logger.info("[UnifiedEnrichment] Initialized")
    {:ok, state}
  end

  @impl true
  def handle_call({:enrich, indicator_type, indicator_value, opts}, _from, state) do
    state = update_stats(state, :enrichment)

    result = do_enrich(indicator_type, indicator_value, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:batch_enrich, indicators, opts}, _from, state) do
    state = update_stats(state, :batch_enrichment)

    results = Enum.map(indicators, fn ind ->
      type = Map.get(ind, :type)
      value = Map.get(ind, :value)

      if type && value do
        case do_enrich(type, value, opts) do
          {:ok, result} -> result
          {:error, reason} -> %{indicator: value, indicator_type: type, error: reason}
        end
      else
        %{error: :invalid_indicator}
      end
    end)

    {:reply, {:ok, results}, state}
  end

  @impl true
  def handle_call({:configure, provider, api_key}, _from, state) do
    case provider do
      :virustotal -> VirusTotal.configure(api_key)
      :alienvault -> AlienVault.configure(api_key)
      :shodan -> Shodan.configure(api_key)
    end

    {:reply, :ok, state}
  end

  @impl true
  def handle_call(:get_providers_status, _from, state) do
    status = %{
      virustotal: safe_get_status(VirusTotal),
      alienvault: safe_get_status(AlienVault),
      shodan: safe_get_status(Shodan),
      feeds: safe_get_feed_status()
    }

    {:reply, status, state}
  end

  @impl true
  def handle_call({:quick_check, indicator_type, indicator_value}, _from, state) do
    state = update_stats(state, :quick_check)

    result = do_quick_check(indicator_type, indicator_value)
    {:reply, result, state}
  end

  # ============================================================================
  # Private Functions - Enrichment
  # ============================================================================

  defp do_enrich(indicator_type, indicator_value, opts) do
    timeout = Keyword.get(opts, :timeout, @enrichment_timeout)
    requested_providers = Keyword.get(opts, :providers)

    # Determine which providers to use
    providers = if requested_providers do
      requested_providers
    else
      Map.get(@default_providers, indicator_type, [:feeds])
    end

    # Filter to only available providers
    available_providers = filter_available_providers(providers)

    # Spawn tasks for each provider
    tasks = Enum.map(available_providers, fn provider ->
      Task.async(fn ->
        try do
          result = query_provider(provider, indicator_type, indicator_value)
          {provider, result}
        rescue
          e ->
            Logger.warning("[UnifiedEnrichment] Provider #{provider} error: #{Exception.message(e)}")
            {provider, {:error, :provider_error}}
        end
      end)
    end)

    # Await all tasks with timeout
    results = Task.await_many(tasks, min(timeout, @enrichment_timeout))
    |> Enum.into(%{})

    # Merge results into unified report
    merge_enrichment_results(indicator_type, indicator_value, results)
  end

  defp filter_available_providers(providers) do
    Enum.filter(providers, fn provider ->
      case provider do
        :feeds -> true  # Always available
        :virustotal ->
          case safe_get_status(VirusTotal) do
            %{configured: true} -> true
            _ -> false
          end
        :alienvault ->
          case safe_get_status(AlienVault) do
            %{configured: true} -> true
            _ -> false
          end
        :shodan ->
          case safe_get_status(Shodan) do
            %{configured: true} -> true
            _ -> false
          end
        _ -> false
      end
    end)
  end

  defp query_provider(:feeds, :hash, value) do
    Feeds.check_hash(value)
  end

  defp query_provider(:feeds, :ip, value) do
    Feeds.check_ip(value)
  end

  defp query_provider(:feeds, :domain, value) do
    Feeds.check_domain(value)
  end

  defp query_provider(:feeds, :url, value) do
    Feeds.check_url(value)
  end

  defp query_provider(:virustotal, :hash, value) do
    VirusTotal.lookup_hash(value)
  end

  defp query_provider(:virustotal, :ip, value) do
    VirusTotal.lookup_ip(value)
  end

  defp query_provider(:virustotal, :domain, value) do
    VirusTotal.lookup_domain(value)
  end

  defp query_provider(:virustotal, :url, value) do
    VirusTotal.lookup_url(value)
  end

  defp query_provider(:alienvault, :hash, value) do
    AlienVault.get_indicator(:file, value)
  end

  defp query_provider(:alienvault, :ip, value) do
    type = if String.contains?(value, ":"), do: :ipv6, else: :ipv4
    AlienVault.get_indicator(type, value)
  end

  defp query_provider(:alienvault, :domain, value) do
    AlienVault.get_indicator(:domain, value)
  end

  defp query_provider(:alienvault, :url, value) do
    AlienVault.get_indicator(:url, value)
  end

  defp query_provider(:shodan, :ip, value) do
    Shodan.lookup_ip(value)
  end

  defp query_provider(_provider, _type, _value) do
    {:error, :unsupported}
  end

  defp merge_enrichment_results(indicator_type, indicator_value, results) do
    # Extract successful results
    enrichments = results
    |> Enum.filter(fn {_provider, result} ->
      match?({:ok, %{found: true}}, result) or
      match?({:ok, %{detection_stats: _}}, result) or
      match?({:ok, %{pulse_count: _}}, result) or
      match?({:ok, %{ports: _}}, result)
    end)
    |> Enum.map(fn {provider, {:ok, data}} -> {provider, data} end)
    |> Enum.into(%{})

    # Determine which providers returned data
    sources = Map.keys(enrichments)

    # Calculate overall verdict
    {verdict, confidence} = calculate_verdict(enrichments)

    # Extract threat summary
    threat_summary = extract_threat_summary(enrichments)

    report = %{
      indicator: indicator_value,
      indicator_type: indicator_type,
      verdict: verdict,
      confidence: confidence,
      sources: sources,
      enrichments: enrichments,
      threat_summary: threat_summary,
      enriched_at: DateTime.utc_now()
    }

    {:ok, report}
  end

  defp calculate_verdict(enrichments) do
    scores = Enum.map(enrichments, fn {provider, data} ->
      calculate_provider_score(provider, data)
    end)
    |> Enum.filter(&(&1 != nil))

    if Enum.empty?(scores) do
      {:unknown, 0.0}
    else
      avg_score = Enum.sum(scores) / length(scores)
      max_score = Enum.max(scores)

      # Use max score for verdict, avg for confidence
      verdict = cond do
        max_score >= 0.7 -> :malicious
        max_score >= 0.3 -> :suspicious
        max_score > 0 -> :low_risk
        true -> :clean
      end

      {verdict, Float.round(avg_score, 2)}
    end
  end

  defp calculate_provider_score(:virustotal, data) do
    stats = Map.get(data, :detection_stats, %{})
    malicious = Map.get(stats, :malicious, 0)
    suspicious = Map.get(stats, :suspicious, 0)
    harmless = Map.get(stats, :harmless, 0)
    undetected = Map.get(stats, :undetected, 0)
    total = malicious + suspicious + harmless + undetected

    if total > 0 do
      (malicious + suspicious * 0.5) / total
    else
      nil
    end
  end

  defp calculate_provider_score(:alienvault, data) do
    pulse_count = Map.get(data, :pulse_count, 0)
    reputation = Map.get(data, :reputation, 0)

    cond do
      pulse_count > 10 -> 0.8
      pulse_count > 5 -> 0.6
      pulse_count > 0 -> 0.4
      reputation > 0 -> 0.1
      true -> nil
    end
  end

  defp calculate_provider_score(:feeds, data) do
    if Map.get(data, :found, false) do
      Map.get(data, :confidence, 0.8)
    else
      nil
    end
  end

  defp calculate_provider_score(:shodan, data) do
    vulns = Map.get(data, :vulns, [])
    ports = Map.get(data, :ports, [])

    cond do
      length(vulns) > 5 -> 0.6
      length(vulns) > 0 -> 0.3
      length(ports) > 20 -> 0.2
      true -> nil
    end
  end

  defp extract_threat_summary(enrichments) do
    malware_families = enrichments
    |> Enum.flat_map(fn {_provider, data} ->
      family = Map.get(data, :malware_family) || Map.get(data, :signature)
      if family, do: [family], else: []
    end)
    |> Enum.uniq()

    threat_types = enrichments
    |> Enum.flat_map(fn {_provider, data} ->
      type = Map.get(data, :threat_type)
      if type, do: [type], else: []
    end)
    |> Enum.uniq()

    tags = enrichments
    |> Enum.flat_map(fn {_provider, data} ->
      Map.get(data, :tags, [])
    end)
    |> Enum.uniq()
    |> Enum.take(20)

    first_seen = enrichments
    |> Enum.map(fn {_provider, data} ->
      Map.get(data, :first_seen) || Map.get(data, :first_submission_date)
    end)
    |> Enum.filter(&(&1 != nil))
    |> Enum.min_by(&DateTime.to_unix/1, fn -> nil end)

    # Extract CVEs from Shodan
    cves = case Map.get(enrichments, :shodan) do
      %{vulns: vulns} when is_list(vulns) ->
        Enum.map(vulns, fn v ->
          if is_map(v), do: Map.get(v, :cve), else: v
        end)
        |> Enum.filter(&is_binary/1)
        |> Enum.take(10)
      _ -> []
    end

    # Extract categories from VirusTotal
    categories = case Map.get(enrichments, :virustotal) do
      %{categories: cats} when is_map(cats) -> cats
      _ -> %{}
    end

    %{
      malware_families: malware_families,
      threat_types: threat_types,
      tags: tags,
      first_seen: first_seen,
      cves: cves,
      categories: categories
    }
  end

  # ============================================================================
  # Private Functions - Quick Check
  # ============================================================================

  defp do_quick_check(indicator_type, indicator_value) do
    # Only check local feeds for quick check (no external API calls)
    result = case indicator_type do
      :hash -> Feeds.check_hash(indicator_value)
      :ip -> Feeds.check_ip(indicator_value)
      :domain -> Feeds.check_domain(indicator_value)
      :url -> Feeds.check_url(indicator_value)
    end

    case result do
      {:ok, %{found: true} = data} ->
        {:ok, %{
          found: true,
          verdict: :malicious,
          source: data[:source] || "feeds",
          confidence: data[:confidence] || 0.8,
          threat_type: data[:threat_type],
          malware_family: data[:malware_family]
        }}

      {:ok, %{found: false}} ->
        {:ok, %{found: false, verdict: :unknown, source: nil, confidence: 0.0}}

      {:error, reason} ->
        {:ok, %{found: false, verdict: :unknown, source: nil, confidence: 0.0, error: reason}}
    end
  end

  # ============================================================================
  # Private Functions - Helpers
  # ============================================================================

  defp safe_get_status(module) do
    try do
      module.get_status()
    rescue
      _ -> %{configured: false, error: :not_running}
    catch
      :exit, _ -> %{configured: false, error: :not_running}
    end
  end

  defp safe_get_feed_status do
    try do
      Feeds.get_stats()
    rescue
      _ -> %{configured: false, error: :not_running}
    catch
      :exit, _ -> %{configured: false, error: :not_running}
    end
  end

  defp update_stats(state, type) do
    case type do
      :enrichment -> update_in(state.stats.enrichments, &(&1 + 1))
      :batch_enrichment -> update_in(state.stats.batch_enrichments, &(&1 + 1))
      :quick_check -> update_in(state.stats.quick_checks, &(&1 + 1))
      :error -> update_in(state.stats.errors, &(&1 + 1))
    end
  end
end
