defmodule TamanduaServer.Detection.DNSAnalyzer do
  @moduledoc """
  Advanced DNS threat detection module.

  Provides real-time analysis of DNS query events to detect:
  - DGA (Domain Generation Algorithm) domains via Shannon entropy
  - DNS beaconing (periodic C2 communication)
  - DNS-based data exfiltration (encoded subdomain labels)
  - Suspicious TLD usage

  Called from the Detection Engine for every dns_query event.
  Maintains per-agent, per-domain state in ETS for temporal analysis.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Detection.Config
  alias TamanduaServer.Detection.DNSBlocklist
  alias TamanduaServer.Detection.IOCs
  alias TamanduaServer.Agents.OrgLookup

  @ets_query_log :dns_query_log
  @ets_subdomain_tracker :dns_subdomain_tracker
  @ets_blocklist :dns_blocklist
  @analyze_timeout 10_000
  @read_timeout 15_000

  @dns_whitelist [
    "microsoft.com", "windows.com", "windowsupdate.com",
    "google.com", "googleapis.com", "gstatic.com",
    "apple.com", "icloud.com",
    "cloudflare.com", "cloudflare-dns.com",
    "amazonaws.com", "cloudfront.net",
    "akamai.net", "akamaized.net",
    "mozilla.org", "mozilla.net",
    "office.com", "office365.com", "outlook.com",
    "teams.microsoft.com", "skype.com",
    "github.com", "githubusercontent.com",
    "docker.com", "docker.io",
    "ubuntu.com", "debian.org",
    "ntp.org", "pool.ntp.org"
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Analyze a DNS query event and return a list of detections.

  Each detection is a map with:
  - :type - atom identifying the detection category
  - :confidence - float 0.0..1.0
  - :description - human-readable explanation
  - :mitre_techniques - list of relevant MITRE ATT&CK technique IDs
  """
  @spec analyze_dns_event(map()) :: [map()]
  def analyze_dns_event(event) do
    GenServer.call(__MODULE__, {:analyze, event}, @analyze_timeout)
  end

  @doc """
  Return the current DNS blocklist as a list of maps.
  """
  @spec get_blocklist() :: [map()]
  def get_blocklist do
    GenServer.call(__MODULE__, :get_blocklist, @read_timeout)
  end

  @spec get_blocklist(String.t() | nil) :: [map()]
  def get_blocklist(organization_id) do
    GenServer.call(__MODULE__, {:get_blocklist, organization_id}, @read_timeout)
  end

  @doc """
  Add domains to the blocklist.
  Returns {:ok, count_added}.
  """
  @spec add_to_blocklist([String.t()], String.t(), String.t()) :: {:ok, integer()}
  def add_to_blocklist(domains, reason, blocked_by) do
    GenServer.call(__MODULE__, {:add_blocklist, domains, reason, blocked_by}, @read_timeout)
  end

  @spec add_to_blocklist([String.t()], String.t(), String.t(), String.t() | nil) ::
          {:ok, integer()} | {:error, atom()}
  def add_to_blocklist(domains, reason, blocked_by, organization_id) do
    GenServer.call(__MODULE__, {:add_blocklist, organization_id, domains, reason, blocked_by}, @read_timeout)
  end

  @doc """
  Remove a domain from the blocklist.
  Returns :ok or {:error, :not_found}.
  """
  @spec remove_from_blocklist(String.t()) :: :ok | {:error, :not_found}
  def remove_from_blocklist(domain) do
    GenServer.call(__MODULE__, {:remove_blocklist, domain}, @read_timeout)
  end

  @spec remove_from_blocklist(String.t(), String.t() | nil) :: :ok | {:error, atom()}
  def remove_from_blocklist(domain, organization_id) do
    GenServer.call(__MODULE__, {:remove_blocklist, organization_id, domain}, @read_timeout)
  end

  @doc """
  Bulk import domains from a list of strings.
  """
  @spec import_blocklist([String.t()], String.t()) :: {:ok, integer()}
  def import_blocklist(domains, reason \\ "Bulk import") do
    GenServer.call(__MODULE__, {:import_blocklist, domains, reason}, @read_timeout)
  end

  @spec import_blocklist([String.t()], String.t(), String.t() | nil) :: {:ok, integer()} | {:error, atom()}
  def import_blocklist(domains, reason, organization_id) do
    GenServer.call(__MODULE__, {:import_blocklist, organization_id, domains, reason}, @read_timeout)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    :ets.new(@ets_query_log, [:named_table, :bag, :public, read_concurrency: true])
    :ets.new(@ets_subdomain_tracker, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_blocklist, [:named_table, :set, :public, read_concurrency: true])
    load_blocklist_cache()

    schedule_cleanup()
    Logger.info("DNS Analyzer started")
    {:ok, %{}}
  end

  @impl true
  def handle_call({:analyze, event}, _from, state) do
    detections = do_analyze(event)
    {:reply, detections, state}
  end

  @impl true
  def handle_call(:get_blocklist, _from, state) do
    entries =
      :ets.tab2list(@ets_blocklist)
      |> Enum.map(fn {domain, meta} ->
        Map.put(meta, :domain, domain)
      end)
      |> Enum.sort_by(& &1[:blocked_at], {:desc, DateTime})

    {:reply, entries, state}
  end

  @impl true
  def handle_call({:get_blocklist, organization_id}, _from, state) do
    entries =
      organization_id
      |> DNSBlocklist.list_entries()
      |> Enum.map(&blocklist_entry_to_map/1)

    {:reply, entries, state}
  end

  @impl true
  def handle_call({:add_blocklist, domains, reason, blocked_by}, _from, state) do
    now = DateTime.utc_now()

    count =
      domains
      |> Enum.map(&String.downcase(String.trim(&1)))
      |> Enum.reject(&(&1 == ""))
      |> Enum.count(fn domain ->
        meta = %{
          blocked_at: now,
          blocked_by: blocked_by,
          reason: reason
        }

        :ets.insert(@ets_blocklist, {domain, meta})
        true
      end)

    {:reply, {:ok, count}, state}
  end

  @impl true
  def handle_call({:add_blocklist, organization_id, domains, reason, blocked_by}, _from, state) do
    case DNSBlocklist.add_entries(organization_id, domains, reason, blocked_by) do
      {:ok, count} ->
        cache_blocklist_entries(organization_id, domains, reason, blocked_by)
        {:reply, {:ok, count}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:remove_blocklist, domain}, _from, state) do
    domain = domain |> to_string() |> String.downcase() |> String.trim()

    case :ets.lookup(@ets_blocklist, domain) do
      [] -> {:reply, {:error, :not_found}, state}
      _ ->
        :ets.delete(@ets_blocklist, domain)
        {:reply, :ok, state}
    end
  end

  @impl true
  def handle_call({:remove_blocklist, organization_id, domain}, _from, state) do
    normalized_domain = DNSBlocklist.normalize_domain(domain)

    case DNSBlocklist.remove_entry(organization_id, normalized_domain) do
      :ok ->
        :ets.delete(@ets_blocklist, {organization_id, normalized_domain})
        {:reply, :ok, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:import_blocklist, domains, reason}, _from, state) do
    now = DateTime.utc_now()

    count =
      domains
      |> Enum.map(&String.downcase(String.trim(&1)))
      |> Enum.reject(&(&1 == ""))
      |> Enum.reject(&String.starts_with?(&1, "#"))
      |> Enum.count(fn domain ->
        meta = %{
          blocked_at: now,
          blocked_by: "bulk_import",
          reason: reason
        }

        :ets.insert(@ets_blocklist, {domain, meta})
        true
      end)

    {:reply, {:ok, count}, state}
  end

  @impl true
  def handle_call({:import_blocklist, organization_id, domains, reason}, _from, state) do
    case DNSBlocklist.add_entries(organization_id, domains, reason, "bulk_import", "bulk_import") do
      {:ok, count} ->
        cache_blocklist_entries(organization_id, domains, reason, "bulk_import")
        {:reply, {:ok, count}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_old_data()
    schedule_cleanup()
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Core Analysis Logic
  # ============================================================================

  defp do_analyze(event) do
    payload = event[:payload] || event["payload"] || %{}
    dns_payload = payload[:dns] || payload["dns"] || %{}
    domain = dns_domain(payload, dns_payload)
    query_type = dns_query_type(payload, dns_payload)
    agent_id = event[:agent_id] || event["agent_id"]
    organization_id = event[:organization_id] || event["organization_id"] || OrgLookup.get_org_id(agent_id)
    timestamp = event[:timestamp] || event["timestamp"] || System.system_time(:millisecond)

    domain = String.downcase(String.trim(domain))

    if domain == "" or is_safe_domain?(domain) do
      []
    else
      # Record the query for temporal analysis
      record_query(agent_id, domain, timestamp)
      record_subdomain(agent_id, domain, timestamp)

      detections = []

      # 1. DGA detection via Shannon entropy
      detections = detections ++ detect_dga(domain)

      # 2. Beaconing detection (frequency analysis)
      detections = detections ++ detect_beaconing(agent_id, domain, timestamp)

      # 3. Exfiltration detection (subdomain diversity + long labels)
      detections = detections ++ detect_exfiltration(agent_id, domain, timestamp)

      # 4. Suspicious TLD check
      detections = detections ++ detect_suspicious_tld(domain)

      # 5. TXT record abuse
      detections = detections ++ detect_txt_abuse(domain, query_type)

      # 6. Blocklist check
      detections = detections ++ check_blocklist(domain, organization_id)

      # 7. Threat Intelligence feed check
      detections = detections ++ check_threat_intel(domain)

    detections
    end
  end

  defp dns_domain(payload, dns_payload) do
    first_present([
      payload[:query],
      payload["query"],
      payload[:query_name],
      payload["query_name"],
      payload[:domain],
      payload["domain"],
      payload[:dns_query],
      payload["dns_query"],
      payload[:"dns.domain"],
      payload["dns.domain"],
      payload[:host],
      payload["host"],
      payload[:hostname],
      payload["hostname"],
      dns_payload[:query],
      dns_payload["query"],
      dns_payload[:query_name],
      dns_payload["query_name"],
      dns_payload[:domain],
      dns_payload["domain"]
    ], "")
  end

  defp dns_query_type(payload, dns_payload) do
    first_present([
      payload[:query_type],
      payload["query_type"],
      payload[:record_type],
      payload["record_type"],
      payload[:"dns.query_type"],
      payload["dns.query_type"],
      payload[:"dns.record_type"],
      payload["dns.record_type"],
      dns_payload[:query_type],
      dns_payload["query_type"],
      dns_payload[:record_type],
      dns_payload["record_type"]
    ], "A")
  end

  defp first_present(values, default) do
    Enum.find_value(values, default, fn
      nil -> nil
      "" -> nil
      value -> value
    end)
  end

  # --------------------------------------------------------------------------
  # DGA Detection
  # --------------------------------------------------------------------------

  defp detect_dga(domain) do
    # Skip DGA analysis for whitelisted domains
    if whitelisted_domain?(domain) do
      []
    else
      do_detect_dga(domain)
    end
  end

  defp do_detect_dga(domain) do
    # Extract the second-level domain (e.g., "abc123xyz" from "abc123xyz.evil.com")
    labels = String.split(domain, ".")
    sld = if length(labels) >= 2, do: Enum.at(labels, length(labels) - 2), else: hd(labels)

    detections = []

    # Shannon entropy of the SLD
    entropy = shannon_entropy(sld)

    detections =
      if entropy > Config.entropy_threshold() do
        [%{
          type: :dga_high_entropy,
          confidence: min(0.5 + (entropy - Config.entropy_threshold()) * 0.2, 0.95),
          description:
            "Domain '#{domain}' has high Shannon entropy (#{Float.round(entropy, 2)}), " <>
            "suggesting DGA-generated domain",
          mitre_techniques: ["T1568.002"]
        } | detections]
      else
        detections
      end

    # Consonant-to-vowel ratio check on SLD
    {consonants, vowels} = count_consonants_vowels(sld)
    cv_ratio = if vowels > 0, do: consonants / vowels, else: consonants * 1.0

    detections =
      if String.length(sld) >= 8 and cv_ratio > 5.0 do
        [%{
          type: :dga_character_distribution,
          confidence: min(0.4 + cv_ratio * 0.05, 0.85),
          description:
            "Domain '#{domain}' has unusual consonant-to-vowel ratio (#{Float.round(cv_ratio, 1)}:1), " <>
            "suggesting DGA-generated domain",
          mitre_techniques: ["T1568.002"]
        } | detections]
      else
        detections
      end

    # Numeric mixing check
    alpha_count = sld |> String.graphemes() |> Enum.count(&(&1 =~ ~r/[a-z]/))
    digit_count = sld |> String.graphemes() |> Enum.count(&(&1 =~ ~r/[0-9]/))

    detections =
      if String.length(sld) >= 10 and alpha_count > 0 and digit_count > 0 and
           digit_count / (alpha_count + digit_count) > 0.3 do
        [%{
          type: :dga_mixed_alphanum,
          confidence: 0.6,
          description:
            "Domain '#{domain}' has heavy numeric/alpha mixing " <>
            "(#{digit_count} digits in #{String.length(sld)} chars), suggesting DGA",
          mitre_techniques: ["T1568.002"]
        } | detections]
      else
        detections
      end

    # Long label check
    longest_label =
      labels
      |> Enum.map(&String.length/1)
      |> Enum.max(fn -> 0 end)

    detections =
      if longest_label > Config.long_label_threshold() do
        [%{
          type: :dga_long_label,
          confidence: min(0.5 + (longest_label - Config.long_label_threshold()) * 0.02, 0.85),
          description:
            "Domain '#{domain}' contains a label with #{longest_label} characters (>#{Config.long_label_threshold()}), " <>
            "suggesting DGA or data encoding",
          mitre_techniques: ["T1568.002", "T1048"]
        } | detections]
      else
        detections
      end

    detections
  end

  # --------------------------------------------------------------------------
  # Beaconing Detection
  # --------------------------------------------------------------------------

  defp detect_beaconing(agent_id, domain, now) do
    # Skip beaconing analysis for whitelisted domains
    if whitelisted_domain?(domain) do
      []
    else
      do_detect_beaconing(agent_id, domain, now)
    end
  end

  defp do_detect_beaconing(agent_id, domain, now) do
    # Extract parent domain (last two labels) to group queries
    parent = extract_parent_domain(domain)

    # Count queries to this parent domain from this agent within the window
    cutoff = now - Config.beaconing_window_ms()

    count =
      :ets.lookup(@ets_query_log, {agent_id, parent})
      |> Enum.count(fn {{_agent, _dom}, ts} -> ts >= cutoff end)

    if count > Config.beaconing_query_threshold() do
      # Calculate interval regularity
      timestamps =
        :ets.lookup(@ets_query_log, {agent_id, parent})
        |> Enum.map(fn {_key, ts} -> ts end)
        |> Enum.filter(&(&1 >= cutoff))
        |> Enum.sort()

      regularity = calculate_interval_regularity(timestamps)

      confidence = cond do
        regularity > 0.9 and count > 100 -> 0.95
        regularity > 0.7 and count > 50 -> 0.85
        count > 50 -> 0.7
        true -> 0.5
      end

      [%{
        type: :dns_beaconing,
        confidence: confidence,
        description:
          "Domain '#{parent}' queried #{count} times in #{div(Config.beaconing_window_ms(), 60_000)} minutes " <>
          "from agent #{agent_id} (interval regularity: #{Float.round(regularity, 2)}), " <>
          "suggesting C2 beaconing",
        mitre_techniques: ["T1071.004", "T1573"]
      }]
    else
      []
    end
  end

  # --------------------------------------------------------------------------
  # Exfiltration Detection
  # --------------------------------------------------------------------------

  defp detect_exfiltration(agent_id, domain, now) do
    # Skip exfiltration analysis for whitelisted domains
    if whitelisted_domain?(domain) do
      []
    else
      do_detect_exfiltration(agent_id, domain, now)
    end
  end

  defp do_detect_exfiltration(agent_id, domain, now) do
    parent = extract_parent_domain(domain)
    labels = String.split(domain, ".")
    detections = []

    # Check for long encoded subdomain labels (>30 chars)
    long_labels =
      labels
      |> Enum.slice(0..(length(labels) - 3)//1)
      |> Enum.filter(&(String.length(&1) > Config.exfil_label_threshold()))

    detections =
      if length(long_labels) > 0 do
        longest = Enum.max_by(long_labels, &String.length/1)
        [%{
          type: :dns_exfiltration_long_label,
          confidence: min(0.6 + (String.length(longest) - Config.exfil_label_threshold()) * 0.01, 0.95),
          description:
            "DNS query to '#{domain}' contains encoded subdomain label " <>
            "(#{String.length(longest)} chars), suggesting data exfiltration",
          mitre_techniques: ["T1048", "T1071.004"]
        } | detections]
      else
        detections
      end

    # Check for high unique subdomain diversity under the same parent
    tracker_key = {agent_id, parent}
    cutoff = now - Config.exfil_window_ms()

    unique_count =
      case :ets.lookup(@ets_subdomain_tracker, tracker_key) do
        [{_key, subdomains_map}] ->
          subdomains_map
          |> Enum.count(fn {_sub, ts} -> ts >= cutoff end)

        [] ->
          0
      end

    detections =
      if unique_count > Config.exfil_subdomain_threshold() do
        [%{
          type: :dns_exfiltration_subdomain_volume,
          confidence: min(0.6 + unique_count * 0.005, 0.95),
          description:
            "#{unique_count} unique subdomains queried under '#{parent}' " <>
            "in #{div(Config.exfil_window_ms(), 60_000)} minutes from agent #{agent_id}, " <>
            "suggesting DNS data exfiltration",
          mitre_techniques: ["T1048", "T1071.004"]
        } | detections]
      else
        detections
      end

    detections
  end

  # --------------------------------------------------------------------------
  # Suspicious TLD Detection
  # --------------------------------------------------------------------------

  defp detect_suspicious_tld(domain) do
    tld = "." <> (domain |> String.split(".") |> List.last())

    if tld in Config.suspicious_tlds() do
      [%{
        type: :suspicious_tld,
        confidence: 0.4,
        description:
          "DNS query to '#{domain}' uses TLD '#{tld}' commonly associated " <>
          "with malicious activity",
        mitre_techniques: ["T1071.004", "T1583.001"]
      }]
    else
      []
    end
  end

  # --------------------------------------------------------------------------
  # TXT Record Abuse
  # --------------------------------------------------------------------------

  defp detect_txt_abuse(domain, query_type) do
    query_type_str = to_string(query_type) |> String.upcase()

    if query_type_str == "TXT" do
      # TXT queries to non-standard domains are suspicious
      is_standard_txt =
        String.contains?(domain, "_domainkey.") or
        String.contains?(domain, "_dmarc.") or
        String.contains?(domain, "_spf.") or
        String.contains?(domain, "_acme-challenge.")

      if not is_standard_txt do
        [%{
          type: :dns_txt_query,
          confidence: 0.5,
          description:
            "DNS TXT record query to '#{domain}' may indicate C2 communication " <>
            "or data exfiltration via DNS TXT records",
          mitre_techniques: ["T1071.004", "T1048"]
        }]
      else
        []
      end
    else
      []
    end
  end

  # --------------------------------------------------------------------------
  # Blocklist Check
  # --------------------------------------------------------------------------

  defp check_blocklist(domain, organization_id) do
    # Check exact match and parent domains
    domains_to_check = [domain | parent_domains(domain)]

    matches =
      Enum.flat_map(domains_to_check, fn d ->
        lookup_blocklist_entry(organization_id, d)
      end)

    case matches do
      [{matched_domain, meta} | _] ->
        [%{
          type: :blocklisted_domain,
          confidence: 1.0,
          description:
            "DNS query to '#{domain}' matches blocklisted domain '#{matched_domain}' " <>
            "(reason: #{meta[:reason] || "N/A"})",
          mitre_techniques: ["T1071.004"]
        }]

      [] ->
        []
    end
  end

  defp lookup_blocklist_entry(organization_id, domain) do
    scoped_key = {organization_id, domain}

    case :ets.lookup(@ets_blocklist, scoped_key) do
      [{^scoped_key, meta}] ->
        [{domain, meta}]

      [] ->
        case :ets.lookup(@ets_blocklist, domain) do
          [{^domain, meta}] -> [{domain, meta}]
          [] -> []
        end
    end
  end

  # --------------------------------------------------------------------------
  # Threat Intelligence Check
  # --------------------------------------------------------------------------

  defp check_threat_intel(domain) do
    domains_to_check = [domain | parent_domains(domain)]

    # Check all domain variants against both ETS threat intel and DB IOCs
    result =
      Enum.find_value(domains_to_check, [], fn d ->
        case check_single_domain_intel(d, domain) do
          [] -> nil
          detections -> detections
        end
      end)

    result || []
  end

  defp check_single_domain_intel(check_domain, original_domain) do
    detections = []

    # 1. Check ETS-based ThreatIntel cache (from automated feeds)
    detections =
      try do
        case TamanduaServer.ThreatIntel.lookup(:domain, check_domain) do
          {:ok, ioc} ->
            source = Map.get(ioc, :source, "threat_feed")
            severity = Map.get(ioc, :severity, "medium")
            tags = Map.get(ioc, :tags, [])
            tag_info = if(tags != [], do: ", tags: #{Enum.join(tags, ", ")}", else: "")

            [%{
              type: :threat_intel_domain,
              confidence: severity_to_confidence(severity),
              description:
                "DNS query to '#{original_domain}' matches threat intel IOC " <>
                "'#{check_domain}' (source: #{source}, severity: #{severity}#{tag_info})",
              mitre_techniques: ["T1071.004", "T1568"]
            } | detections]

          :not_found ->
            detections
        end
      rescue
        _ -> detections
      end

    # 2. Check database IOCs (manually added + imported indicators)
    detections =
      try do
        case IOCs.lookup("domain", check_domain) do
          {:ok, ioc} ->
            [%{
              type: :ioc_domain_match,
              confidence: severity_to_confidence(to_string(ioc.severity)),
              description:
                "DNS query to '#{original_domain}' matches known malicious domain " <>
                "'#{check_domain}' (source: #{ioc.source})",
              mitre_techniques: ["T1071.004"]
            } | detections]

          {:error, :not_found} ->
            detections
        end
      rescue
        _ -> detections
      end

    detections
  end

  defp severity_to_confidence("critical"), do: 0.95
  defp severity_to_confidence("high"), do: 0.85
  defp severity_to_confidence("medium"), do: 0.70
  defp severity_to_confidence("low"), do: 0.50
  defp severity_to_confidence(_), do: 0.70

  # ============================================================================
  # Helper Functions
  # ============================================================================

  @doc """
  Calculate Shannon entropy of a string.
  Higher values indicate more randomness.
  """
  @spec shannon_entropy(String.t()) :: float()
  def shannon_entropy(""), do: 0.0

  def shannon_entropy(string) do
    len = String.length(string)

    if len == 0 do
      0.0
    else
      string
      |> String.graphemes()
      |> Enum.frequencies()
      |> Enum.reduce(0.0, fn {_char, count}, acc ->
        probability = count / len
        acc - probability * :math.log2(probability)
      end)
    end
  end

  defp count_consonants_vowels(string) do
    vowels = ~w(a e i o u)
    chars = string |> String.downcase() |> String.graphemes() |> Enum.filter(&(&1 =~ ~r/[a-z]/))

    vowel_count = Enum.count(chars, &(&1 in vowels))
    consonant_count = length(chars) - vowel_count

    {consonant_count, vowel_count}
  end

  defp extract_parent_domain(domain) do
    parts = String.split(domain, ".")

    if length(parts) >= 2 do
      parts |> Enum.take(-2) |> Enum.join(".")
    else
      domain
    end
  end

  defp parent_domains(domain) do
    parts = String.split(domain, ".")

    if length(parts) > 2 do
      # Generate all parent domains: a.b.c.d -> [b.c.d, c.d]
      2..(length(parts) - 1)
      |> Enum.map(fn i ->
        parts |> Enum.take(-i) |> Enum.join(".")
      end)
    else
      []
    end
  end

  defp is_safe_domain?(domain) do
    Enum.any?(Config.safe_domains(), fn safe ->
      String.ends_with?(domain, safe)
    end)
  end

  defp whitelisted_domain?(domain) when is_binary(domain) do
    domain_lower = String.downcase(domain)
    Enum.any?(@dns_whitelist, fn trusted ->
      domain_lower == trusted or String.ends_with?(domain_lower, "." <> trusted)
    end)
  end
  defp whitelisted_domain?(_), do: false

  defp record_query(agent_id, domain, timestamp) do
    parent = extract_parent_domain(domain)
    :ets.insert(@ets_query_log, {{agent_id, parent}, timestamp})
  end

  defp load_blocklist_cache do
    DNSBlocklist.list_active_entries()
    |> Enum.each(fn entry ->
      cache_blocklist_entry(
        entry.organization_id,
        entry.normalized_domain,
        entry.reason,
        entry.blocked_by,
        entry.updated_at || entry.inserted_at
      )
    end)
  rescue
    e ->
      Logger.warning("Failed to load DNS blocklist cache from database: #{inspect(e)}")
      :ok
  end

  defp cache_blocklist_entries(organization_id, domains, reason, blocked_by) do
    now = DateTime.utc_now()

    domains
    |> Enum.map(&DNSBlocklist.normalize_domain/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
    |> Enum.each(fn domain ->
      cache_blocklist_entry(organization_id, domain, reason, blocked_by, now)
    end)
  end

  defp cache_blocklist_entry(organization_id, domain, reason, blocked_by, blocked_at) do
    meta = %{
      blocked_at: blocked_at,
      blocked_by: blocked_by,
      reason: reason,
      organization_id: organization_id
    }

    :ets.insert(@ets_blocklist, {{organization_id, domain}, meta})
  end

  defp blocklist_entry_to_map(entry) do
    %{
      domain: entry.normalized_domain || entry.domain,
      blocked_at: entry.updated_at || entry.inserted_at,
      blocked_by: entry.blocked_by,
      reason: entry.reason,
      source: entry.source,
      active: entry.active,
      organization_id: entry.organization_id
    }
  end

  defp record_subdomain(agent_id, domain, timestamp) do
    parts = String.split(domain, ".")

    if length(parts) > 2 do
      parent = extract_parent_domain(domain)
      # The subdomain portion (everything except the last two labels)
      subdomain = parts |> Enum.take(length(parts) - 2) |> Enum.join(".")
      tracker_key = {agent_id, parent}

      existing =
        case :ets.lookup(@ets_subdomain_tracker, tracker_key) do
          [{_key, map}] -> map
          [] -> %{}
        end

      updated = Map.put(existing, subdomain, timestamp)
      :ets.insert(@ets_subdomain_tracker, {tracker_key, updated})
    end
  end

  defp calculate_interval_regularity(timestamps) when length(timestamps) < 3, do: 0.0

  defp calculate_interval_regularity(timestamps) do
    # Calculate intervals between consecutive timestamps
    intervals =
      timestamps
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.map(fn [a, b] -> b - a end)
      |> Enum.filter(&(&1 > 0))

    if length(intervals) < 2 do
      0.0
    else
      mean = Enum.sum(intervals) / length(intervals)

      if mean == 0 do
        0.0
      else
        # Calculate coefficient of variation (lower = more regular)
        variance =
          intervals
          |> Enum.map(fn i -> (i - mean) * (i - mean) end)
          |> Enum.sum()
          |> Kernel./(length(intervals))

        std_dev = :math.sqrt(variance)
        cv = std_dev / mean

        # Convert CV to a 0-1 regularity score (lower CV = higher regularity)
        max(0.0, min(1.0, 1.0 - cv))
      end
    end
  end

  defp cleanup_old_data do
    now = System.system_time(:millisecond)
    cutoff = now - Config.dns_data_ttl()

    # Clean query log
    :ets.tab2list(@ets_query_log)
    |> Enum.each(fn {key, ts} ->
      if ts < cutoff do
        :ets.delete_object(@ets_query_log, {key, ts})
      end
    end)

    # Clean subdomain tracker - remove old entries from each map
    :ets.tab2list(@ets_subdomain_tracker)
    |> Enum.each(fn {key, subdomains_map} ->
      cleaned =
        subdomains_map
        |> Enum.reject(fn {_sub, ts} -> ts < cutoff end)
        |> Map.new()

      if map_size(cleaned) == 0 do
        :ets.delete(@ets_subdomain_tracker, key)
      else
        :ets.insert(@ets_subdomain_tracker, {key, cleaned})
      end
    end)

    Logger.debug("DNS Analyzer cleanup completed")
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, Config.dns_cleanup_interval())
  end
end
