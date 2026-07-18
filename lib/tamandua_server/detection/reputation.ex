defmodule TamanduaServer.Detection.Reputation do
  @moduledoc """
  Cloud-based Reputation Service

  Provides multi-dimensional reputation scoring for files, domains, IPs, and certificates.
  Integrates with external reputation APIs and maintains local first-seen tracking.

  ## Features
  - File reputation based on hash (SHA256, SHA1, MD5)
  - Domain reputation with categorization
  - IP reputation with geolocation and abuse data
  - Certificate reputation (issuer, validity, transparency)
  - First-seen tracking for unknown files and domains
  - Caching layer for performance
  - Confidence scoring with source weighting

  ## External Integrations
  - VirusTotal API (file, domain, IP)
  - AbuseIPDB (IP reputation)
  - Google Safe Browsing (URL/domain)
  - Certificate Transparency logs
  """

  use GenServer
  require Logger


  # ETS tables for caching
  @file_cache_table :reputation_file_cache
  @domain_cache_table :reputation_domain_cache
  @ip_cache_table :reputation_ip_cache
  @cert_cache_table :reputation_cert_cache
  @first_seen_table :reputation_first_seen

  # Cache TTL in seconds
  @cache_ttl_seconds 3600  # 1 hour
  @first_seen_ttl_seconds 86400 * 30  # 30 days

  # Reputation score thresholds
  @malicious_threshold 70
  @suspicious_threshold 40

  # ============================================================================
  # Types
  # ============================================================================

  @type reputation_verdict :: :malicious | :suspicious | :clean | :unknown
  @type confidence_level :: :high | :medium | :low

  defmodule FileReputation do
    @moduledoc "File reputation result"
    defstruct [
      :sha256,
      :sha1,
      :md5,
      :verdict,           # :malicious, :suspicious, :clean, :unknown
      :score,             # 0-100
      :confidence,        # :high, :medium, :low
      :malware_family,    # e.g., "Emotet", "Cobalt Strike"
      :detection_names,   # List of AV detection names
      :first_seen,        # DateTime when first seen
      :last_seen,         # DateTime when last seen
      :prevalence,        # :rare, :uncommon, :common
      :signed,            # boolean
      :signer,            # certificate signer name
      :sources,           # List of reputation sources used
      :categories,        # List of threat categories
      :mitre_techniques,  # Associated MITRE ATT&CK techniques
      :cached_at          # When result was cached
    ]
  end

  defmodule DomainReputation do
    @moduledoc "Domain reputation result"
    defstruct [
      :domain,
      :verdict,           # :malicious, :suspicious, :clean, :unknown
      :score,             # 0-100
      :confidence,
      :categories,        # e.g., ["phishing", "malware_distribution"]
      :registrar,
      :creation_date,
      :age_days,
      :first_seen,
      :whois_privacy,     # boolean - privacy protection enabled
      :dga_score,         # DGA likelihood (0-100)
      :parked,            # boolean - domain parking
      :sources,
      :cached_at
    ]
  end

  defmodule IPReputation do
    @moduledoc "IP address reputation result"
    defstruct [
      :ip,
      :verdict,
      :score,             # 0-100
      :confidence,
      :abuse_score,       # AbuseIPDB score
      :categories,        # e.g., ["botnet", "scanner", "tor_exit"]
      :country_code,
      :asn,
      :asn_name,
      :is_tor,
      :is_vpn,
      :is_proxy,
      :is_datacenter,
      :first_seen,
      :reports_count,     # Number of abuse reports
      :sources,
      :cached_at
    ]
  end

  defmodule CertificateReputation do
    @moduledoc "Certificate reputation result"
    defstruct [
      :fingerprint,       # SHA256 of certificate
      :subject,
      :issuer,
      :verdict,
      :score,
      :confidence,
      :valid_from,
      :valid_to,
      :is_expired,
      :is_self_signed,
      :is_ev,             # Extended Validation
      :ct_logged,         # Certificate Transparency
      :issuer_reputation, # Issuer reputation score
      :first_seen,
      :sources,
      :cached_at
    ]
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    # Create ETS tables for caching
    create_cache_tables()

    # Load configuration
    config = load_config()

    # Schedule periodic cache cleanup
    Process.send_after(self(), :cleanup_cache, :timer.minutes(10))

    # Schedule periodic first-seen persistence
    Process.send_after(self(), :persist_first_seen, :timer.minutes(5))

    state = %{
      config: config,
      stats: %{
        file_queries: 0,
        domain_queries: 0,
        ip_queries: 0,
        cert_queries: 0,
        cache_hits: 0,
        cache_misses: 0,
        api_calls: 0,
        api_errors: 0
      }
    }

    Logger.info("Reputation service started")
    {:ok, state}
  end

  @impl true
  def handle_call({:check_file, hash, hash_type}, _from, state) do
    {result, new_state} = do_check_file(hash, hash_type, state)
    {:reply, result, new_state}
  end

  @impl true
  def handle_call({:check_domain, domain}, _from, state) do
    {result, new_state} = do_check_domain(domain, state)
    {:reply, result, new_state}
  end

  @impl true
  def handle_call({:check_ip, ip}, _from, state) do
    {result, new_state} = do_check_ip(ip, state)
    {:reply, result, new_state}
  end

  @impl true
  def handle_call({:check_certificate, fingerprint, cert_data}, _from, state) do
    {result, new_state} = do_check_certificate(fingerprint, cert_data, state)
    {:reply, result, new_state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_call({:report_first_seen, type, value}, _from, state) do
    record_first_seen(type, value)
    {:reply, :ok, state}
  end

  @impl true
  def handle_info(:cleanup_cache, state) do
    cleanup_expired_cache()
    Process.send_after(self(), :cleanup_cache, :timer.minutes(10))
    {:noreply, state}
  end

  @impl true
  def handle_info(:persist_first_seen, state) do
    persist_first_seen_to_db()
    Process.send_after(self(), :persist_first_seen, :timer.minutes(5))
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Check file reputation by hash.
  Returns {:ok, %FileReputation{}} or {:error, reason}
  """
  @spec check_file(String.t(), atom()) :: {:ok, FileReputation.t()} | {:error, term()}
  def check_file(hash, hash_type \\ :sha256) when hash_type in [:sha256, :sha1, :md5] do
    GenServer.call(__MODULE__, {:check_file, String.downcase(hash), hash_type}, 30_000)
  end

  @doc """
  Check domain reputation.
  """
  @spec check_domain(String.t()) :: {:ok, DomainReputation.t()} | {:error, term()}
  def check_domain(domain) do
    GenServer.call(__MODULE__, {:check_domain, String.downcase(domain)}, 30_000)
  end

  @doc """
  Check IP address reputation.
  """
  @spec check_ip(String.t()) :: {:ok, IPReputation.t()} | {:error, term()}
  def check_ip(ip) do
    GenServer.call(__MODULE__, {:check_ip, ip}, 30_000)
  end

  @doc """
  Check certificate reputation.
  """
  @spec check_certificate(String.t(), map()) :: {:ok, CertificateReputation.t()} | {:error, term()}
  def check_certificate(fingerprint, cert_data \\ %{}) do
    GenServer.call(__MODULE__, {:check_certificate, fingerprint, cert_data}, 30_000)
  end

  @doc """
  Get reputation service statistics.
  """
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Report first-seen observation for tracking unknown entities.
  """
  @spec report_first_seen(atom(), String.t()) :: :ok
  def report_first_seen(type, value) when type in [:file, :domain, :ip, :cert] do
    GenServer.call(__MODULE__, {:report_first_seen, type, value})
  end

  @doc """
  Quick verdict check for file (returns :malicious, :suspicious, :clean, or :unknown).
  """
  @spec quick_file_verdict(String.t()) :: reputation_verdict()
  def quick_file_verdict(sha256) do
    case check_file(sha256, :sha256) do
      {:ok, %FileReputation{verdict: verdict}} -> verdict
      _ -> :unknown
    end
  end

  @doc """
  Quick verdict check for domain.
  """
  @spec quick_domain_verdict(String.t()) :: reputation_verdict()
  def quick_domain_verdict(domain) do
    case check_domain(domain) do
      {:ok, %DomainReputation{verdict: verdict}} -> verdict
      _ -> :unknown
    end
  end

  @doc """
  Quick verdict check for IP.
  """
  @spec quick_ip_verdict(String.t()) :: reputation_verdict()
  def quick_ip_verdict(ip) do
    case check_ip(ip) do
      {:ok, %IPReputation{verdict: verdict}} -> verdict
      _ -> :unknown
    end
  end

  # ============================================================================
  # File Reputation
  # ============================================================================

  defp do_check_file(hash, hash_type, state) do
    new_stats = update_stat(state.stats, :file_queries)

    # Check cache first
    case get_cached(@file_cache_table, hash) do
      {:ok, cached} ->
        new_stats = update_stat(new_stats, :cache_hits)
        {{:ok, cached}, %{state | stats: new_stats}}

      :miss ->
        new_stats = update_stat(new_stats, :cache_misses)

        # Query external APIs
        result = query_file_reputation(hash, hash_type, state.config)

        # Record first-seen if unknown
        if result.verdict == :unknown do
          record_first_seen(:file, hash)
        end

        # Cache result
        cache_result(@file_cache_table, hash, result)

        {{:ok, result}, %{state | stats: new_stats}}
    end
  end

  defp query_file_reputation(hash, hash_type, config) do
    sources = []
    scores = []

    # Query VirusTotal if configured
    {vt_result, sources, scores} =
      if config[:virustotal_api_key] do
        case query_virustotal_file(hash, config[:virustotal_api_key]) do
          {:ok, vt_data} ->
            score = calculate_vt_file_score(vt_data)
            {vt_data, ["virustotal" | sources], [score | scores]}
          _ ->
            {nil, sources, scores}
        end
      else
        {nil, sources, scores}
      end

    # Check local first-seen database
    first_seen = get_first_seen(:file, hash)

    # Calculate aggregate score
    {final_score, confidence} = aggregate_scores(scores)
    verdict = score_to_verdict(final_score)

    # Extract malware family and detection names from VT
    {malware_family, detection_names} = extract_vt_detections(vt_result)

    # Build base struct
    base_reputation = %FileReputation{
      verdict: verdict,
      score: final_score,
      confidence: confidence,
      malware_family: malware_family,
      detection_names: detection_names,
      first_seen: first_seen,
      last_seen: DateTime.utc_now(),
      prevalence: calculate_prevalence(vt_result),
      signed: vt_result && vt_result["data"]["attributes"]["signature_info"]["verified"] == "Signed",
      signer: vt_result && get_in(vt_result, ["data", "attributes", "signature_info", "signers"]),
      sources: sources,
      categories: extract_categories(vt_result),
      mitre_techniques: extract_mitre_techniques(vt_result),
      cached_at: DateTime.utc_now()
    }

    # Set the appropriate hash field based on hash_type
    case hash_type do
      :sha256 -> %{base_reputation | sha256: hash}
      :sha1 -> %{base_reputation | sha1: hash}
      :md5 -> %{base_reputation | md5: hash}
      _ -> %{base_reputation | sha256: hash}
    end
  end

  defp query_virustotal_file(hash, api_key) do
    url = "https://www.virustotal.com/api/v3/files/#{hash}"
    headers = [{"x-apikey", api_key}]

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: 10_000) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        Jason.decode(body)

      {:ok, %Finch.Response{status: 404}} ->
        {:error, :not_found}

      {:ok, %Finch.Response{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e ->
      Logger.warning("VirusTotal query failed: #{inspect(e)}")
      {:error, :exception}
  end

  defp calculate_vt_file_score(nil), do: 0
  defp calculate_vt_file_score(vt_data) do
    stats = get_in(vt_data, ["data", "attributes", "last_analysis_stats"]) || %{}

    malicious = stats["malicious"] || 0
    suspicious = stats["suspicious"] || 0
    total = stats["harmless"] || 0 + stats["undetected"] || 0 + malicious + suspicious

    if total > 0 do
      detection_rate = (malicious + suspicious * 0.5) / total
      round(detection_rate * 100)
    else
      0
    end
  end

  defp extract_vt_detections(nil), do: {nil, []}
  defp extract_vt_detections(vt_data) do
    results = get_in(vt_data, ["data", "attributes", "last_analysis_results"]) || %{}

    detections = results
    |> Enum.filter(fn {_engine, result} ->
      result["category"] in ["malicious", "suspicious"]
    end)
    |> Enum.map(fn {engine, result} ->
      %{engine: engine, name: result["result"]}
    end)

    # Extract most common malware family
    family = detections
    |> Enum.map(& &1.name)
    |> Enum.filter(& &1)
    |> Enum.frequencies()
    |> Enum.max_by(fn {_name, count} -> count end, fn -> {nil, 0} end)
    |> elem(0)

    {family, Enum.map(detections, & &1.name)}
  end

  defp calculate_prevalence(nil), do: :unknown
  defp calculate_prevalence(vt_data) do
    times_submitted = get_in(vt_data, ["data", "attributes", "times_submitted"]) || 0

    cond do
      times_submitted > 1000 -> :common
      times_submitted > 100 -> :uncommon
      true -> :rare
    end
  end

  defp extract_categories(nil), do: []
  defp extract_categories(vt_data) do
    popular_threat_classification = get_in(vt_data, ["data", "attributes", "popular_threat_classification"])

    if popular_threat_classification do
      labels = popular_threat_classification["suggested_threat_label"] || []
      categories = popular_threat_classification["popular_threat_category"] || []
      Enum.uniq(labels ++ Enum.map(categories, & &1["value"]))
    else
      []
    end
  end

  defp extract_mitre_techniques(nil), do: []
  defp extract_mitre_techniques(vt_data) do
    sandbox_verdicts = get_in(vt_data, ["data", "attributes", "sandbox_verdicts"]) || %{}

    sandbox_verdicts
    |> Enum.flat_map(fn {_sandbox, data} ->
      data["mitre_attack_techniques"] || []
    end)
    |> Enum.map(& &1["id"])
    |> Enum.uniq()
  end

  # ============================================================================
  # Domain Reputation
  # ============================================================================

  defp do_check_domain(domain, state) do
    new_stats = update_stat(state.stats, :domain_queries)

    case get_cached(@domain_cache_table, domain) do
      {:ok, cached} ->
        new_stats = update_stat(new_stats, :cache_hits)
        {{:ok, cached}, %{state | stats: new_stats}}

      :miss ->
        new_stats = update_stat(new_stats, :cache_misses)

        result = query_domain_reputation(domain, state.config)

        if result.verdict == :unknown do
          record_first_seen(:domain, domain)
        end

        cache_result(@domain_cache_table, domain, result)

        {{:ok, result}, %{state | stats: new_stats}}
    end
  end

  defp query_domain_reputation(domain, config) do
    sources = []
    scores = []

    # Query VirusTotal for domain
    {vt_result, sources, scores} =
      if config[:virustotal_api_key] do
        case query_virustotal_domain(domain, config[:virustotal_api_key]) do
          {:ok, vt_data} ->
            score = calculate_vt_domain_score(vt_data)
            {vt_data, ["virustotal" | sources], [score | scores]}
          _ ->
            {nil, sources, scores}
        end
      else
        {nil, sources, scores}
      end

    # Calculate DGA score locally
    dga_score = calculate_dga_score(domain)
    scores = if dga_score > 50, do: [dga_score | scores], else: scores

    # Check local first-seen
    first_seen = get_first_seen(:domain, domain)

    # Calculate domain age penalty for young domains
    age_days = extract_domain_age(vt_result)
    age_score = calculate_age_score(age_days)
    scores = if age_score > 0, do: [age_score | scores], else: scores

    {final_score, confidence} = aggregate_scores(scores)
    verdict = score_to_verdict(final_score)

    %DomainReputation{
      domain: domain,
      verdict: verdict,
      score: final_score,
      confidence: confidence,
      categories: extract_domain_categories(vt_result),
      registrar: get_in(vt_result, ["data", "attributes", "registrar"]),
      creation_date: get_in(vt_result, ["data", "attributes", "creation_date"]),
      age_days: age_days,
      first_seen: first_seen,
      whois_privacy: check_whois_privacy(vt_result),
      dga_score: dga_score,
      parked: check_parked_domain(vt_result),
      sources: sources,
      cached_at: DateTime.utc_now()
    }
  end

  defp query_virustotal_domain(domain, api_key) do
    url = "https://www.virustotal.com/api/v3/domains/#{domain}"
    headers = [{"x-apikey", api_key}]

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: 10_000) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        Jason.decode(body)

      {:ok, %Finch.Response{status: 404}} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    _ -> {:error, :exception}
  end

  defp calculate_vt_domain_score(nil), do: 0
  defp calculate_vt_domain_score(vt_data) do
    stats = get_in(vt_data, ["data", "attributes", "last_analysis_stats"]) || %{}

    malicious = stats["malicious"] || 0
    suspicious = stats["suspicious"] || 0
    total = (stats["harmless"] || 0) + (stats["undetected"] || 0) + malicious + suspicious

    if total > 0 do
      round((malicious + suspicious * 0.5) / total * 100)
    else
      0
    end
  end

  defp calculate_dga_score(domain) do
    # Calculate entropy-based DGA score
    labels = String.split(domain, ".")
    sld = Enum.at(labels, -2) || ""

    if String.length(sld) < 4 do
      0
    else
      entropy = calculate_string_entropy(sld)
      consonant_ratio = calculate_consonant_ratio(sld)

      # High entropy + high consonant ratio = likely DGA
      base_score = if entropy > 4.0, do: 30, else: 0
      consonant_bonus = if consonant_ratio > 0.7, do: 30, else: 0
      length_bonus = if String.length(sld) > 15, do: 20, else: 0

      min(base_score + consonant_bonus + length_bonus, 100)
    end
  end

  defp calculate_string_entropy(string) when byte_size(string) == 0, do: 0.0
  defp calculate_string_entropy(string) do
    freq = string
    |> String.graphemes()
    |> Enum.frequencies()

    total = String.length(string)

    freq
    |> Enum.reduce(0.0, fn {_char, count}, acc ->
      p = count / total
      acc - p * :math.log2(p)
    end)
  end

  defp calculate_consonant_ratio(string) do
    chars = String.downcase(string) |> String.graphemes()
    consonants = ~w(b c d f g h j k l m n p q r s t v w x y z)

    consonant_count = Enum.count(chars, &(&1 in consonants))
    total = length(chars)

    if total > 0, do: consonant_count / total, else: 0.0
  end

  defp extract_domain_age(nil), do: nil
  defp extract_domain_age(vt_data) do
    creation_date = get_in(vt_data, ["data", "attributes", "creation_date"])

    if creation_date do
      now = DateTime.utc_now() |> DateTime.to_unix()
      div(now - creation_date, 86400)
    else
      nil
    end
  end

  defp calculate_age_score(nil), do: 0
  defp calculate_age_score(age_days) when age_days < 7, do: 40  # Very young domain
  defp calculate_age_score(age_days) when age_days < 30, do: 25
  defp calculate_age_score(age_days) when age_days < 90, do: 10
  defp calculate_age_score(_), do: 0

  defp extract_domain_categories(nil), do: []
  defp extract_domain_categories(vt_data) do
    categories = get_in(vt_data, ["data", "attributes", "categories"]) || %{}
    Map.values(categories) |> Enum.uniq()
  end

  defp check_whois_privacy(nil), do: false
  defp check_whois_privacy(vt_data) do
    whois = get_in(vt_data, ["data", "attributes", "whois"]) || ""
    String.contains?(String.downcase(whois), ["privacy", "redacted", "private"])
  end

  defp check_parked_domain(nil), do: false
  defp check_parked_domain(vt_data) do
    categories = get_in(vt_data, ["data", "attributes", "categories"]) || %{}
    values = Map.values(categories) |> Enum.map(&String.downcase/1)
    Enum.any?(values, &String.contains?(&1, "parked"))
  end

  # ============================================================================
  # IP Reputation
  # ============================================================================

  defp do_check_ip(ip, state) do
    new_stats = update_stat(state.stats, :ip_queries)

    case get_cached(@ip_cache_table, ip) do
      {:ok, cached} ->
        new_stats = update_stat(new_stats, :cache_hits)
        {{:ok, cached}, %{state | stats: new_stats}}

      :miss ->
        new_stats = update_stat(new_stats, :cache_misses)

        result = query_ip_reputation(ip, state.config)

        if result.verdict == :unknown do
          record_first_seen(:ip, ip)
        end

        cache_result(@ip_cache_table, ip, result)

        {{:ok, result}, %{state | stats: new_stats}}
    end
  end

  defp query_ip_reputation(ip, config) do
    sources = []
    scores = []

    # Query AbuseIPDB
    {abuse_result, sources, scores} =
      if config[:abuseipdb_api_key] do
        case query_abuseipdb(ip, config[:abuseipdb_api_key]) do
          {:ok, data} ->
            score = data["data"]["abuseConfidenceScore"] || 0
            {data, ["abuseipdb" | sources], [score | scores]}
          _ ->
            {nil, sources, scores}
        end
      else
        {nil, sources, scores}
      end

    # Query VirusTotal for IP
    {vt_result, sources, scores} =
      if config[:virustotal_api_key] do
        case query_virustotal_ip(ip, config[:virustotal_api_key]) do
          {:ok, vt_data} ->
            score = calculate_vt_ip_score(vt_data)
            {vt_data, ["virustotal" | sources], [score | scores]}
          _ ->
            {nil, sources, scores}
        end
      else
        {nil, sources, scores}
      end

    first_seen = get_first_seen(:ip, ip)

    {final_score, confidence} = aggregate_scores(scores)
    verdict = score_to_verdict(final_score)

    %IPReputation{
      ip: ip,
      verdict: verdict,
      score: final_score,
      confidence: confidence,
      abuse_score: abuse_result && get_in(abuse_result, ["data", "abuseConfidenceScore"]),
      categories: extract_ip_categories(abuse_result, vt_result),
      country_code: get_in(abuse_result, ["data", "countryCode"]) ||
                    get_in(vt_result, ["data", "attributes", "country"]),
      asn: get_in(vt_result, ["data", "attributes", "asn"]),
      asn_name: get_in(vt_result, ["data", "attributes", "as_owner"]),
      is_tor: check_tor_exit(abuse_result),
      is_vpn: check_vpn(abuse_result),
      is_proxy: check_proxy(abuse_result),
      is_datacenter: check_datacenter(vt_result),
      first_seen: first_seen,
      reports_count: get_in(abuse_result, ["data", "totalReports"]),
      sources: sources,
      cached_at: DateTime.utc_now()
    }
  end

  defp query_abuseipdb(ip, api_key) do
    url = "https://api.abuseipdb.com/api/v2/check?ipAddress=#{ip}&maxAgeInDays=90"
    headers = [{"Key", api_key}, {"Accept", "application/json"}]

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: 10_000) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        Jason.decode(body)
      _ ->
        {:error, :api_error}
    end
  rescue
    _ -> {:error, :exception}
  end

  defp query_virustotal_ip(ip, api_key) do
    url = "https://www.virustotal.com/api/v3/ip_addresses/#{ip}"
    headers = [{"x-apikey", api_key}]

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: 10_000) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        Jason.decode(body)
      _ ->
        {:error, :api_error}
    end
  rescue
    _ -> {:error, :exception}
  end

  defp calculate_vt_ip_score(nil), do: 0
  defp calculate_vt_ip_score(vt_data) do
    stats = get_in(vt_data, ["data", "attributes", "last_analysis_stats"]) || %{}

    malicious = stats["malicious"] || 0
    suspicious = stats["suspicious"] || 0
    total = (stats["harmless"] || 0) + (stats["undetected"] || 0) + malicious + suspicious

    if total > 0 do
      round((malicious + suspicious * 0.5) / total * 100)
    else
      0
    end
  end

  defp extract_ip_categories(abuse_result, _vt_result) do
    if abuse_result do
      usage_types = get_in(abuse_result, ["data", "usageType"]) || ""
      categories = String.split(usage_types, "/") |> Enum.map(&String.trim/1)
      categories
    else
      []
    end
  end

  defp check_tor_exit(nil), do: false
  defp check_tor_exit(abuse_result) do
    get_in(abuse_result, ["data", "isTor"]) == true
  end

  defp check_vpn(nil), do: false
  defp check_vpn(abuse_result) do
    usage = get_in(abuse_result, ["data", "usageType"]) || ""
    String.contains?(String.downcase(usage), "vpn")
  end

  defp check_proxy(nil), do: false
  defp check_proxy(abuse_result) do
    get_in(abuse_result, ["data", "isPublic"]) == true
  end

  defp check_datacenter(nil), do: false
  defp check_datacenter(vt_data) do
    network = get_in(vt_data, ["data", "attributes", "network"]) || ""
    as_owner = get_in(vt_data, ["data", "attributes", "as_owner"]) || ""

    datacenter_keywords = ["amazon", "google", "microsoft", "azure", "digitalocean",
                           "linode", "vultr", "ovh", "hetzner", "oracle cloud"]

    Enum.any?(datacenter_keywords, fn kw ->
      String.contains?(String.downcase(network <> as_owner), kw)
    end)
  end

  # ============================================================================
  # Certificate Reputation
  # ============================================================================

  defp do_check_certificate(fingerprint, cert_data, state) do
    new_stats = update_stat(state.stats, :cert_queries)

    case get_cached(@cert_cache_table, fingerprint) do
      {:ok, cached} ->
        new_stats = update_stat(new_stats, :cache_hits)
        {{:ok, cached}, %{state | stats: new_stats}}

      :miss ->
        new_stats = update_stat(new_stats, :cache_misses)

        result = analyze_certificate(fingerprint, cert_data)

        cache_result(@cert_cache_table, fingerprint, result)

        {{:ok, result}, %{state | stats: new_stats}}
    end
  end

  defp analyze_certificate(fingerprint, cert_data) do
    # Extract certificate fields
    subject = cert_data[:subject] || cert_data["subject"]
    issuer = cert_data[:issuer] || cert_data["issuer"]
    valid_from = parse_cert_date(cert_data[:valid_from] || cert_data["valid_from"])
    valid_to = parse_cert_date(cert_data[:valid_to] || cert_data["valid_to"])

    is_expired = if valid_to, do: DateTime.compare(DateTime.utc_now(), valid_to) == :gt, else: nil
    is_self_signed = subject == issuer

    # Calculate score based on certificate properties
    scores = []

    # Self-signed penalty
    scores = if is_self_signed, do: [30 | scores], else: scores

    # Expired penalty
    scores = if is_expired == true, do: [40 | scores], else: scores

    # Short validity period (less than 30 days) is suspicious
    validity_days = if valid_from && valid_to do
      DateTime.diff(valid_to, valid_from, :day)
    else
      nil
    end
    scores = if validity_days && validity_days < 30, do: [20 | scores], else: scores

    # Known bad issuer check
    issuer_score = check_issuer_reputation(issuer)
    scores = if issuer_score > 0, do: [issuer_score | scores], else: scores

    {final_score, confidence} = aggregate_scores(scores)
    verdict = score_to_verdict(final_score)

    first_seen = get_first_seen(:cert, fingerprint)

    %CertificateReputation{
      fingerprint: fingerprint,
      subject: subject,
      issuer: issuer,
      verdict: verdict,
      score: final_score,
      confidence: confidence,
      valid_from: valid_from,
      valid_to: valid_to,
      is_expired: is_expired,
      is_self_signed: is_self_signed,
      is_ev: check_ev_certificate(cert_data),
      ct_logged: check_ct_logged(cert_data),
      issuer_reputation: 100 - issuer_score,
      first_seen: first_seen,
      sources: ["local_analysis"],
      cached_at: DateTime.utc_now()
    }
  end

  defp parse_cert_date(nil), do: nil
  defp parse_cert_date(date) when is_binary(date) do
    case DateTime.from_iso8601(date) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end
  defp parse_cert_date(%DateTime{} = dt), do: dt
  defp parse_cert_date(_), do: nil

  defp check_issuer_reputation(nil), do: 0
  defp check_issuer_reputation(issuer) do
    issuer_lower = String.downcase(issuer)

    # Known suspicious issuers or patterns
    suspicious_patterns = [
      "let's encrypt",  # Not inherently bad, but often abused
      "self-signed",
      "localhost",
      "test",
      "example"
    ]

    if Enum.any?(suspicious_patterns, &String.contains?(issuer_lower, &1)) do
      20
    else
      0
    end
  end

  defp check_ev_certificate(cert_data) do
    # EV certificates have specific OID in policies
    policies = cert_data[:policies] || cert_data["policies"] || []
    Enum.any?(policies, &String.contains?(to_string(&1), "2.23.140.1.1"))
  end

  defp check_ct_logged(_cert_data) do
    # Would check Certificate Transparency logs
    # For now, return nil (unknown)
    nil
  end

  # ============================================================================
  # Cache Management
  # ============================================================================

  defp create_cache_tables do
    tables = [@file_cache_table, @domain_cache_table, @ip_cache_table,
              @cert_cache_table, @first_seen_table]

    Enum.each(tables, fn table ->
      case :ets.whereis(table) do
        :undefined ->
          :ets.new(table, [:set, :public, :named_table])
        _ ->
          :ok
      end
    end)
  end

  defp get_cached(table, key) do
    case :ets.lookup(table, key) do
      [{^key, result, cached_at}] ->
        if DateTime.diff(DateTime.utc_now(), cached_at, :second) < @cache_ttl_seconds do
          {:ok, result}
        else
          :miss
        end
      [] ->
        :miss
    end
  end

  defp cache_result(table, key, result) do
    :ets.insert(table, {key, result, DateTime.utc_now()})
  end

  defp cleanup_expired_cache do
    now = DateTime.utc_now()
    tables = [@file_cache_table, @domain_cache_table, @ip_cache_table, @cert_cache_table]

    Enum.each(tables, fn table ->
      :ets.foldl(fn {key, _result, cached_at}, acc ->
        if DateTime.diff(now, cached_at, :second) >= @cache_ttl_seconds do
          :ets.delete(table, key)
        end
        acc
      end, :ok, table)
    end)

    # Evict stale first-seen entries (durable copies are persisted to Postgres).
    # Without this sweep the table grows unbounded with one entry per unique
    # indicator (hash/domain/IP) ever observed across the fleet.
    :ets.foldl(fn {key, first_seen}, acc ->
      if DateTime.diff(now, first_seen, :second) >= @first_seen_ttl_seconds do
        :ets.delete(@first_seen_table, key)
      end
      acc
    end, :ok, @first_seen_table)

    Logger.debug("Reputation cache cleanup completed")
  end

  # ============================================================================
  # First-Seen Tracking
  # ============================================================================

  defp record_first_seen(type, value) do
    key = {type, value}
    now = DateTime.utc_now()

    case :ets.lookup(@first_seen_table, key) do
      [] ->
        :ets.insert(@first_seen_table, {key, now})
      _ ->
        :ok  # Already recorded
    end
  end

  defp get_first_seen(type, value) do
    key = {type, value}

    case :ets.lookup(@first_seen_table, key) do
      [{^key, first_seen}] -> first_seen
      [] -> nil
    end
  end

  defp persist_first_seen_to_db do
    # Persist first-seen records to database for durability
    try do
      entries = :ets.tab2list(@first_seen_table)

      Enum.each(entries, fn {{type, value}, first_seen} ->
        TamanduaServer.Repo.insert_all(
          "reputation_first_seen",
          [%{
            entity_type: to_string(type),
            entity_value: value,
            first_seen_at: first_seen,
            updated_at: DateTime.utc_now()
          }],
          on_conflict: :nothing,
          conflict_target: [:entity_type, :entity_value]
        )
      end)
    rescue
      _ -> :ok  # Table may not exist
    end
  end

  # ============================================================================
  # Score Aggregation
  # ============================================================================

  defp aggregate_scores([]), do: {0, :low}
  defp aggregate_scores(scores) do
    avg = Enum.sum(scores) / length(scores)
    max = Enum.max(scores)

    # Final score weighted towards max
    final_score = round(avg * 0.4 + max * 0.6)

    confidence = cond do
      length(scores) >= 3 -> :high
      length(scores) >= 2 -> :medium
      true -> :low
    end

    {min(final_score, 100), confidence}
  end

  defp score_to_verdict(score) when score >= @malicious_threshold, do: :malicious
  defp score_to_verdict(score) when score >= @suspicious_threshold, do: :suspicious
  defp score_to_verdict(score) when score > 0, do: :clean
  defp score_to_verdict(_), do: :unknown

  # ============================================================================
  # Helpers
  # ============================================================================

  defp update_stat(stats, key) do
    Map.update(stats, key, 1, &(&1 + 1))
  end

  defp load_config do
    %{
      virustotal_api_key: Application.get_env(:tamandua_server, :virustotal_api_key),
      abuseipdb_api_key: Application.get_env(:tamandua_server, :abuseipdb_api_key),
      google_safebrowsing_api_key: Application.get_env(:tamandua_server, :google_safebrowsing_api_key)
    }
  end
end
