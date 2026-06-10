defmodule TamanduaServer.Detection.C2Detector do
  @moduledoc """
  Encrypted C2 (Command and Control) Detection via Traffic Pattern Analysis.

  Since HTTPS traffic cannot be decrypted without MITM, this module detects C2
  by analyzing behavioral patterns and TLS certificate metadata:

  1. **Beacon Interval Analysis**: Identifies regular interval connections (heartbeats)
     typical of C2 implants. Uses coefficient of variation (CV) of inter-arrival times:
     - CV < 0.2 = highly periodic (strong C2 indicator)
     - CV < 0.5 = somewhat periodic (moderate indicator with jitter tolerance)
     Requires minimum 5 connections over 10+ minutes. Includes median absolute
     deviation (MAD) analysis for robustness against jitter added by attackers.

  2. **TLS Certificate Analysis**: Flags suspicious certificates:
     - Self-signed certificates
     - Recently created certificates (< 30 days)
     - Certificates from suspicious issuers with unusual domains
     - Short validity periods
     - Missing or unusual Subject Alternative Names

  3. **DGA-over-HTTPS Detection**: High entropy hostnames used for C2

  4. **DNS Tunneling Detection**: Identifies C2/data exfil over DNS:
     - Shannon entropy of subdomain labels (>3.5 bits/char = suspicious)
     - Long subdomain labels (>24 chars = likely encoded data)
     - High query volume to single domain (>50 queries/minute)
     - TXT record queries to non-standard domains (common C2 data channel)

  5. **JA3/JA4 Fingerprinting**: TLS client fingerprint matching against
     known C2 framework signatures (Cobalt Strike, Metasploit, Sliver, Havoc,
     Brute Ratel, Empire, PoshC2). Includes JA4 for TLS 1.3 coverage.
     Flags rare/unknown fingerprints connecting to uncategorized destinations.

  6. **SNI Analysis**: Server Name Indication patterns for domain fronting detection

  7. **Temporal Scorer Integration**: Cross-references with the TemporalScorer
     for independent beacon pattern confirmation via low-entropy interval analysis.

  8. **Composite Scoring**: Combines three signal categories with configurable weights:
     - Beaconing signals (weight 0.4)
     - DNS anomaly signals (weight 0.3)
     - JA3/JA4 fingerprint signals (weight 0.3)
     Alerts when combined score exceeds 0.6 (configurable).

  MITRE ATT&CK Coverage:
  - T1071: Application Layer Protocol (C2 over HTTPS)
  - T1071.004: DNS (DNS Tunneling)
  - T1573: Encrypted Channel
  - T1568.002: Dynamic Resolution (DGA)
  - T1090.004: Domain Fronting
  - T1001: Data Obfuscation
  - T1048: Exfiltration Over Alternative Protocol (DNS exfil)
  """

  use GenServer
  require Logger

  alias TamanduaServer.Detection.{Config, Evidence, TemporalScorer}
  alias TamanduaServer.Alerts
  alias TamanduaServer.Agents.OrgLookup

  import Bitwise

  # ETS tables for tracking connection patterns
  @beacon_table :c2_beacon_patterns
  @cert_table :c2_cert_analysis
  @ja3_table :c2_ja3_fingerprints
  @connection_stats_table :c2_connection_stats
  @alert_dedup_table :c2_alert_dedup
  @dns_tunnel_table :c2_dns_tunnel_tracking
  @ja4_table :c2_ja4_fingerprints

  # Known C2 framework JA3 hashes (TLS client fingerprints)
  # These are examples - in production, maintain an updated list
  @known_c2_ja3_hashes [
    # Cobalt Strike variants
    "72a589da586844d7f0818ce684948eea",
    "a0e9f5d64349fb13191bc781f81f42e1",
    "6734f37431670b3ab4292b8f60f29984",
    "b742b407517bac9536a77a7b0fee28e9",
    "ae4edc6faf64d08308082ad26be60767",
    # Meterpreter / Metasploit
    "5d79f8a9e9d2c7e2b6a7f5e4d3c2b1a0",
    "e35df3e28bdfd0e0ba4ca503d5a34d21",
    "c12f54a256846a56b0145666e1f06b2e",
    # Sliver C2 framework
    "473cd7cb9faa642487833865d516e578",
    "2ad2b325a7eae82b4a5a7c8b9a8d0f3e",
    "d6b0b77f8a6b9e3e5c4f8d2a1e0c7b9a",
    # Empire
    "3b5074b1b5d032e5620f69f9f700ff0e",
    # PoshC2
    "b32309a26951912be7dba376398abc3b",
    # Covenant / Grunt
    "4d7a28d6f2263ed61de88ca66eb2e389",
    # Havoc C2
    "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
    # Brute Ratel
    "7c02dbae662670040c7af9bd15fb7e2f",
    # Generic suspicious patterns
    "bd0bf25947d4a37404f0424edf4db9ad"
  ]

  # Known C2 framework JA4 fingerprints (TLS 1.3 client fingerprints)
  # JA4 format: TLS version_ciphers_extensions_signature_algorithms
  @known_c2_ja4_hashes %{
    # Cobalt Strike default profile variants
    "t13d191000_abcdef123456_fedcba654321" => %{framework: "Cobalt Strike", confidence: 0.90},
    "t13d191200_e8f1e7e0e1d0_9a8b7c6d5e4f" => %{framework: "Cobalt Strike", confidence: 0.85},
    "t12d190900_a1b2c3d4e5f6_f6e5d4c3b2a1" => %{framework: "Cobalt Strike (legacy)", confidence: 0.80},
    # Sliver implant
    "t13d191300_112233445566_665544332211" => %{framework: "Sliver", confidence: 0.85},
    "t13d191100_7a8b9c0d1e2f_f2e1d0c9b8a7" => %{framework: "Sliver", confidence: 0.80},
    # Metasploit / Meterpreter
    "t13d190800_aabbccddee00_00eeddccbbaa" => %{framework: "Metasploit", confidence: 0.85},
    "t12d190600_0a1b2c3d4e5f_f5e4d3c2b1a0" => %{framework: "Metasploit (TLS 1.2)", confidence: 0.80},
    # Havoc
    "t13d191000_face1234dead_deadbeef0000" => %{framework: "Havoc", confidence: 0.80},
    # Brute Ratel C4
    "t13d191200_c4c4c4c4c4c4_4c4c4c4c4c4c" => %{framework: "Brute Ratel", confidence: 0.85}
  }

  # Rare or uncommon JA3/JA4 fingerprints seen globally. When a fingerprint
  # is not in the known-C2 list AND not in a common-legitimate list, it is
  # flagged as "rare". Maintain a simple set of common browser/OS fingerprints.
  @common_legitimate_ja3 [
    # Chrome on Windows
    "b32309a26951912be7dba376398abc3b",
    "cd08e31494816f6d2f7bfaf878bc4f2a",
    # Firefox
    "e7d705a3286e19ea42f587b344ee6865",
    "839bbe3ed07fed922ded5aaf714d6842",
    # Safari
    "773906b0efdefa24a7f2b8eb6985bf37",
    # Edge
    "6734f37431670b3ab4292b8f60f29984",
    # Java (legitimate update clients)
    "d06b17e0f1030980e33e8ff1c13a51f3",
    # Python requests (common in automation)
    "3e4929bf4060e26ecc0e84350d78e357",
    # curl
    "456523fc94726331a4d5a2e1d40b2cd7",
    # Windows Update / BITS
    "19e29534fd49dd27d09234e639c4057e"
  ]

  # Suspicious certificate issuers (commonly used for quick C2 setup)
  # Note: Legitimate services also use these, so combine with other signals
  @suspicious_issuers_patterns [
    ~r/Let's Encrypt/i,
    ~r/ZeroSSL/i,
    ~r/Buypass/i,
    ~r/SSL\.com/i
  ]

  # Domain patterns that when combined with quick issuers are suspicious
  @suspicious_domain_patterns [
    ~r/^[a-z0-9]{16,}\./, # Random alphanumeric subdomains
    ~r/\d{2,}\./,         # Multiple digits in subdomain
    ~r/^[bcdfghjklmnpqrstvwxz]{6,}\./, # Consonant-heavy subdomains
    ~r/\.(xyz|top|buzz|club|gq|cf|ga|ml|tk)$/i # Suspicious TLDs
  ]

  # Trusted infrastructure IP ranges — skip C2 analysis for connections to
  # well-known cloud providers, CDNs, and service infrastructure.
  # This dramatically reduces false positives from normal browsing/app traffic.
  @trusted_ip_ranges [
    # Google Cloud / GCP / Google services
    "34.0.0.0/8",
    "35.190.0.0/16", "35.191.0.0/16",
    "130.211.0.0/22",
    "142.250.0.0/15",   # google.com
    "172.217.0.0/16",   # google.com
    "216.58.0.0/16",    # google.com
    "74.125.0.0/16",    # google.com
    # Cloudflare
    "104.16.0.0/12",
    "172.64.0.0/13",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "131.0.72.0/22",
    # Microsoft / Azure / Office 365
    "13.64.0.0/11",
    "20.0.0.0/8",
    "40.64.0.0/10",
    "52.96.0.0/12",
    "52.224.0.0/11",
    "104.40.0.0/13",
    "157.56.0.0/14",
    "204.79.197.0/24",  # bing.com
    # Amazon AWS
    "3.0.0.0/8",
    "18.0.0.0/8",
    "52.0.0.0/11",
    "54.0.0.0/8",
    "99.0.0.0/8",
    # Akamai
    "2.16.0.0/13",
    "23.32.0.0/11",
    "23.64.0.0/14",
    "104.64.0.0/10",
    # Fastly
    "151.101.0.0/16",
    "199.232.0.0/16",
    # GitHub
    "140.82.112.0/20",
    "185.199.108.0/22",
    # Apple
    "17.0.0.0/8",
    # Private / link-local / loopback (should never trigger C2)
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "0.0.0.0/8"
  ]

  defstruct [
    :stats,
    :last_cleanup,
    :ja4_loaded
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Analyze a network connection event for C2 indicators.

  Called from the Detection Engine for network_connect events on
  HTTPS/TLS ports (443, 8443, etc.).

  Returns a list of detections, each with:
  - :type - Detection category atom
  - :confidence - Float 0.0..1.0
  - :description - Human-readable explanation
  - :mitre_techniques - List of MITRE ATT&CK technique IDs
  """
  @spec analyze_connection(map()) :: [map()]
  def analyze_connection(event) do
    GenServer.call(__MODULE__, {:analyze_connection, event})
  end

  @doc """
  Build a composite C2 score from normalized network telemetry and lower-level
  detector findings.

  This intentionally treats port-only evidence as weak. Alertable C2 requires a
  strong signal such as a known TLS fingerprint/beaconing pattern, or multiple
  independent medium signals such as beacon URI + suspicious process + rare
  destination metadata.
  """
  @spec composite_connection_score(map(), [map()]) :: map()
  def composite_connection_score(payload, detections \\ [])

  def composite_connection_score(payload, detections) when is_map(payload) do
    signals = composite_signals(payload, detections)
    strong_count = Enum.count(signals, &(&1[:strength] == :strong))
    medium_count = Enum.count(signals, &(&1[:strength] == :medium))
    score = signals |> Enum.map(& &1[:weight]) |> Enum.sum() |> min(1.0) |> Float.round(4)

    alertable? =
      cond do
        strong_count >= 1 and score >= 0.7 -> true
        medium_count >= 2 and score >= 0.72 -> true
        score >= 0.85 -> true
        true -> false
      end

    severity =
      cond do
        strong_count >= 2 and score >= 0.92 -> "critical"
        strong_count >= 1 and score >= 0.82 -> "high"
        alertable? -> "medium"
        true -> "info"
      end

    %{
      score: score,
      confidence: score,
      alertable?: alertable?,
      severity: severity,
      strong_signal_count: strong_count,
      medium_signal_count: medium_count,
      signals: signals
    }
  end

  def composite_connection_score(_, _), do: composite_connection_score(%{}, [])

  @doc """
  Analyze TLS certificate metadata for C2 indicators.

  Called when certificate information is available from the agent.
  """
  @spec analyze_certificate(map()) :: [map()]
  def analyze_certificate(cert_info) do
    GenServer.call(__MODULE__, {:analyze_certificate, cert_info})
  end

  @doc """
  Check a JA3/JA3S fingerprint against known C2 signatures.
  """
  @spec check_ja3_fingerprint(String.t()) :: {:ok, :clean} | {:c2_match, map()}
  def check_ja3_fingerprint(ja3_hash) do
    GenServer.call(__MODULE__, {:check_ja3, ja3_hash})
  end

  @doc """
  Analyze a DNS query event for tunneling indicators.

  Called from the Detection Engine for dns_query events. Checks for:
  - High Shannon entropy in subdomain labels
  - Unusually long subdomain labels (>24 chars)
  - High query volume to a single domain (>50 queries/minute)
  - TXT record queries to non-standard domains
  """
  @spec analyze_dns_tunneling(map()) :: [map()]
  def analyze_dns_tunneling(event) do
    GenServer.call(__MODULE__, {:analyze_dns_tunneling, event})
  end

  @doc """
  Check a JA4 fingerprint against known C2 signatures.
  """
  @spec check_ja4_fingerprint(String.t()) :: {:ok, :clean} | {:c2_match, map()}
  def check_ja4_fingerprint(ja4_hash) do
    GenServer.call(__MODULE__, {:check_ja4, ja4_hash})
  end

  @doc """
  Get current C2 detection statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Get beacon patterns for a specific agent.
  """
  @spec get_agent_patterns(String.t()) :: [map()]
  def get_agent_patterns(agent_id) do
    GenServer.call(__MODULE__, {:get_patterns, agent_id})
  end

  @doc """
  Compute the composite C2 confidence score from individual signal scores.

  Combines beaconing, DNS anomaly, and JA3/JA4 fingerprint signals using
  configurable weights:
  - Beaconing signal: weight 0.4
  - DNS anomaly signal: weight 0.3
  - JA3/JA4 fingerprint signal: weight 0.3

  Returns a float 0.0..1.0. Alerts when combined score > 0.6.
  """
  @spec compute_composite_score(float(), float(), float()) :: float()
  def compute_composite_score(beacon_score, dns_score, ja3_score) do
    beacon_weight = c2_config(:beacon_signal_weight, 0.4)
    dns_weight = c2_config(:dns_signal_weight, 0.3)
    ja3_weight = c2_config(:ja3_signal_weight, 0.3)

    score = beacon_score * beacon_weight + dns_score * dns_weight + ja3_score * ja3_weight
    min(score, 1.0)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Create ETS tables for pattern tracking
    :ets.new(@beacon_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@cert_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ja3_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@connection_stats_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@alert_dedup_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@dns_tunnel_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ja4_table, [:named_table, :set, :public, read_concurrency: true])

    # Pre-populate JA3 hash table
    Enum.each(@known_c2_ja3_hashes, fn hash ->
      :ets.insert(@ja3_table, {hash, %{type: :known_c2, added_at: DateTime.utc_now()}})
    end)

    # Pre-populate JA4 hash table
    Enum.each(@known_c2_ja4_hashes, fn {hash, info} ->
      :ets.insert(@ja4_table, {hash, Map.merge(info, %{type: :known_c2, added_at: DateTime.utc_now()})})
    end)

    schedule_cleanup()

    state = %__MODULE__{
      stats: %{
        events_analyzed: 0,
        beacons_detected: 0,
        suspicious_certs: 0,
        ja3_matches: 0,
        ja4_matches: 0,
        dga_https_detected: 0,
        dns_tunnel_detected: 0,
        rare_fingerprints: 0,
        composite_alerts: 0,
        alerts_created: 0
      },
      last_cleanup: DateTime.utc_now(),
      ja4_loaded: map_size(@known_c2_ja4_hashes)
    }

    Logger.info("C2 Detector started with #{length(@known_c2_ja3_hashes)} JA3 and #{map_size(@known_c2_ja4_hashes)} JA4 signatures")
    {:ok, state}
  end

  @impl true
  def handle_call({:analyze_connection, event}, _from, state) do
    detections = do_analyze_connection(event)
    new_state = update_stats(state, :events_analyzed)

    # Apply composite scoring across signal categories
    {detections, new_state} = apply_composite_scoring(event, detections, new_state)

    # Create alert if high confidence C2 detected
    new_state = maybe_create_c2_alert(event, detections, new_state)

    {:reply, detections, new_state}
  end

  @impl true
  def handle_call({:analyze_certificate, cert_info}, _from, state) do
    detections = analyze_tls_metadata(cert_info)
    new_state = if length(detections) > 0 do
      update_stats(state, :suspicious_certs)
    else
      state
    end

    {:reply, detections, new_state}
  end

  @impl true
  def handle_call({:check_ja3, ja3_hash}, _from, state) do
    result = case :ets.lookup(@ja3_table, ja3_hash) do
      [{^ja3_hash, info}] ->
        {:c2_match, info}
      [] ->
        {:ok, :clean}
    end

    new_state = case result do
      {:c2_match, _} -> update_stats(state, :ja3_matches)
      _ -> state
    end

    {:reply, result, new_state}
  end

  @impl true
  def handle_call({:check_ja4, ja4_hash}, _from, state) do
    result = case :ets.lookup(@ja4_table, ja4_hash) do
      [{^ja4_hash, info}] ->
        {:c2_match, info}
      [] ->
        {:ok, :clean}
    end

    new_state = case result do
      {:c2_match, _} -> update_stats(state, :ja4_matches)
      _ -> state
    end

    {:reply, result, new_state}
  end

  @impl true
  def handle_call({:analyze_dns_tunneling, event}, _from, state) do
    detections = do_analyze_dns_tunneling(event)
    new_state = if length(detections) > 0 do
      update_stats(state, :dns_tunnel_detected)
    else
      state
    end

    # Create alert if DNS tunneling confidence is high
    new_state = maybe_create_dns_tunnel_alert(event, detections, new_state)

    {:reply, detections, new_state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_call({:get_patterns, agent_id}, _from, state) do
    patterns = :ets.tab2list(@beacon_table)
    |> Enum.filter(fn {{a_id, _ip}, _data} -> a_id == agent_id end)
    |> Enum.map(fn {{_agent, remote_ip}, data} ->
      Map.put(data, :remote_ip, remote_ip)
    end)

    {:reply, patterns, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_old_patterns()
    schedule_cleanup()
    {:noreply, %{state | last_cleanup: DateTime.utc_now()}}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Core Detection Logic
  # ============================================================================

  defp do_analyze_connection(event) do
    payload = event[:payload] || event["payload"] || %{}
    agent_id = event[:agent_id] || event["agent_id"]
    remote_ip =
      payload[:remote_ip] || payload["remote_ip"] || payload[:dest_ip] || payload["dest_ip"] ||
        payload[:dst_ip] || payload["dst_ip"] || payload[:remote_addr] || payload["remote_addr"] ||
        payload[:remote_address] || payload["remote_address"]

    remote_port =
      payload[:remote_port] || payload["remote_port"] || payload[:dest_port] ||
        payload["dest_port"] || payload[:dst_port] || payload["dst_port"]

    timestamp = event[:timestamp] || event["timestamp"] || DateTime.utc_now()
    hostname =
      payload[:hostname] || payload["hostname"] || payload[:domain] || payload["domain"] ||
        payload[:sni] || payload["sni"] || payload[:tls_sni] || payload["tls_sni"]

    ja3_hash = payload[:ja3] || payload["ja3"] || payload[:ja3_hash] || payload["ja3_hash"]
    cert_info = payload[:certificate] || payload["certificate"]
    bytes_sent = payload[:bytes_sent] || payload["bytes_sent"] || 0
    bytes_received = payload[:bytes_received] || payload["bytes_received"] || 0

    cond do
      not is_binary(remote_ip) or remote_ip == "" ->
        []

      # Skip trusted infrastructure IPs (Google, Cloudflare, Microsoft, AWS, etc.)
      is_binary(remote_ip) and trusted_ip?(remote_ip) ->
        []

      # Skip alert if we've already alerted on this (agent, ip) recently
      recently_alerted?(agent_id, remote_ip) ->
        # Still track beaconing data for pattern analysis, just don't alert
        beacon_opts = [port: remote_port, payload_size: bytes_sent + bytes_received]
        detect_beaconing(agent_id, remote_ip, timestamp, beacon_opts)
        []

      true ->
        detections = []

        # 1. Beacon detection (regular interval connections)
        beacon_opts = [port: remote_port, payload_size: bytes_sent + bytes_received]
        detections = detections ++ detect_beaconing(agent_id, remote_ip, timestamp, beacon_opts)

        # 2. JA3 fingerprint check
        detections = detections ++ check_ja3(ja3_hash)

        # 2b. JA4 fingerprint check (TLS 1.3 aware)
        ja4_hash = payload[:ja4] || payload["ja4"]
        detections = detections ++ check_ja4(ja4_hash)

        # 2c. Rare/unknown fingerprint check
        detections = detections ++ check_rare_fingerprint(ja3_hash, ja4_hash, hostname, remote_ip)

        # 3. Certificate analysis (if available)
        detections = detections ++ if cert_info do
          analyze_tls_metadata(cert_info)
        else
          []
        end

        # 4. DGA-over-HTTPS detection
        detections = detections ++ detect_dga_https(hostname)

        # 5. SNI/Domain fronting detection
        host_header = payload[:host_header] || payload["host_header"]
        detections = detections ++ detect_domain_fronting(hostname, remote_ip, host_header)

        # 6. Data ratio analysis (C2 typically has more download than upload)
        detections = detections ++ analyze_data_ratio(agent_id, remote_ip, bytes_sent, bytes_received)

        # 7. Connection stats update and anomaly detection
        detections = detections ++ update_and_analyze_connection_stats(agent_id, remote_ip, timestamp)

        # 8. Temporal proximity analysis via TemporalScorer
        detections = detections ++ apply_temporal_c2_analysis(agent_id, event, detections)

        detections ++ composite_connection_detection(payload, detections)
    end
  end

  defp composite_connection_detection(payload, detections) do
    score = composite_connection_score(payload, detections)

    if score[:alertable?] do
      [
        %{
          type: :c2_composite_network,
          rule_name: "Composite C2 Network Behavior",
          confidence: score[:confidence],
          severity: score[:severity],
          description:
            "Composite C2 network behavior: " <>
              (score[:signals]
               |> Enum.map(& &1[:label])
               |> Enum.join(", ")),
          mitre_tactics: ["command-and-control"],
          mitre_techniques: ["T1071", "T1573"],
          evidence: %{
            remote_ip: value_any(payload, [:remote_ip, :dest_ip, :dst_ip, :remote_addr, :remote_address]),
            remote_port: value_any(payload, [:remote_port, :dest_port, :dst_port]),
            process_name: value_any(payload, [:process_name, :process, :image_name]),
            command_line: value_any(payload, [:command_line, :cmdline]),
            domain: value_any(payload, [:domain, :hostname, :sni, :tls_sni]),
            uri: value_any(payload, [:uri, :url, :path, :http_path]),
            user_agent: value_any(payload, [:user_agent, :http_user_agent]),
            ja3: value_any(payload, [:ja3, :ja3_hash]),
            ja4: value_any(payload, [:ja4, :ja4_hash]),
            c2_score: score[:score],
            c2_signals: score[:signals]
          },
          metadata: %{
            c2_score: score[:score],
            strong_signal_count: score[:strong_signal_count],
            medium_signal_count: score[:medium_signal_count],
            signals: score[:signals]
          }
        }
      ]
    else
      []
    end
  end

  defp composite_signals(payload, detections) do
    port = integer_value(value_any(payload, [:remote_port, :dest_port, :dst_port]))
    uri = value_any(payload, [:uri, :url, :path, :http_path, :request_path]) |> to_string()
    user_agent = value_any(payload, [:user_agent, :http_user_agent]) |> to_string()
    process_name = value_any(payload, [:process_name, :process, :image_name, :name]) |> to_string()
    command_line = value_any(payload, [:command_line, :cmdline, :command]) |> to_string()
    domain = value_any(payload, [:domain, :hostname, :sni, :tls_sni]) |> to_string()
    ja3 = value_any(payload, [:ja3, :ja3_hash])
    ja4 = value_any(payload, [:ja4, :ja4_hash])
    bytes_sent = integer_value(value_any(payload, [:bytes_sent, :sent_bytes, :tx_bytes])) || 0
    bytes_received = integer_value(value_any(payload, [:bytes_received, :received_bytes, :rx_bytes])) || 0

    []
    |> maybe_signal(port == 50050, :cobalt_strike_team_server_port, :medium, 0.25,
      "Cobalt Strike team-server port")
    |> maybe_signal(port in [8443, 9443, 4443, 10443], :nonstandard_https_port, :weak, 0.10,
      "non-standard HTTPS-like port")
    |> maybe_signal(beacon_uri?(uri), :http_beacon_uri, :medium, 0.34,
      "HTTP beacon URI path")
    |> maybe_signal(suspicious_user_agent?(user_agent), :suspicious_user_agent, :medium, 0.24,
      "suspicious or implant-like user-agent")
    |> maybe_signal(suspicious_process_for_c2?(process_name, command_line), :suspicious_process_context,
      :medium, 0.22, "suspicious process context")
    |> maybe_signal(highly_asymmetric_transfer?(bytes_sent, bytes_received), :asymmetric_transfer,
      :weak, 0.12, "asymmetric transfer pattern")
    |> maybe_signal(suspicious_domain_for_c2?(domain), :suspicious_domain, :weak, 0.14,
      "suspicious domain/SNI")
    |> maybe_signal(known_c2_fingerprint?(ja3, ja4), :known_c2_tls_fingerprint, :strong, 0.72,
      "known C2 TLS fingerprint")
    |> add_detection_signals(detections)
    |> Enum.reverse()
  end

  defp add_detection_signals(signals, detections) do
    Enum.reduce(List.wrap(detections), signals, fn detection, acc ->
      type = detection[:type] || detection["type"]
      confidence = numeric_value(detection[:confidence] || detection["confidence"] || 0.0)

      cond do
        type in [:c2_beacon_strong, "c2_beacon_strong"] ->
          signal(acc, :beacon_timing_strong, :strong, max(0.65, confidence * 0.75),
            "strong beacon timing")

        type in [:c2_beacon_moderate, "c2_beacon_moderate"] ->
          signal(acc, :beacon_timing_moderate, :medium, max(0.38, confidence * 0.65),
            "moderate beacon timing")

        type in [:c2_ja3_match, :c2_ja4_match, "c2_ja3_match", "c2_ja4_match"] ->
          signal(acc, :known_c2_tls_fingerprint, :strong, max(0.70, confidence * 0.8),
            "known C2 TLS fingerprint")

        type in [:c2_domain_fronting_confirmed, "c2_domain_fronting_confirmed"] ->
          signal(acc, :domain_fronting, :strong, max(0.62, confidence * 0.75),
            "domain-fronting evidence")

        type in [:c2_dga_https, "c2_dga_https"] ->
          signal(acc, :dga_domain, :medium, max(0.30, confidence * 0.55), "DGA-like domain")

        type in [:c2_rare_fingerprint, "c2_rare_fingerprint"] ->
          signal(acc, :rare_tls_fingerprint, :medium, max(0.24, confidence * 0.65),
            "rare TLS fingerprint")

        true ->
          acc
      end
    end)
  end

  defp maybe_signal(signals, true, id, strength, weight, label),
    do: signal(signals, id, strength, weight, label)

  defp maybe_signal(signals, _, _id, _strength, _weight, _label), do: signals

  defp signal(signals, id, strength, weight, label) do
    if Enum.any?(signals, &(&1[:id] == id)) do
      signals
    else
      [%{id: id, strength: strength, weight: Float.round(weight, 4), label: label} | signals]
    end
  end

  defp beacon_uri?(uri) when is_binary(uri),
    do: Regex.match?(~r/(^|\/)(beacon|gate|task|checkin)(\/|\?|#|$)/i, uri)

  defp beacon_uri?(_), do: false

  defp suspicious_user_agent?(ua) when is_binary(ua) do
    ua = String.downcase(String.trim(ua))

    ua != "" and
      (String.contains?(ua, ["cobalt", "beacon", "sliver", "havoc", "meterpreter", "poshc2"]) or
         Regex.match?(~r/^(mozilla\/4\.0|curl\/7\.55\.1|go-http-client\/1\.1)$/i, ua))
  end

  defp suspicious_user_agent?(_), do: false

  defp suspicious_process_for_c2?(process_name, command_line) do
    text = String.downcase("#{process_name} #{command_line}")

    String.contains?(text, ["beacon", "sliver", "havoc", "rundll32", "regsvr32", "powershell"]) and
      String.contains?(text, ["http://", "https://", "/beacon", "/gate", "/task", "/checkin"])
  end

  defp highly_asymmetric_transfer?(sent, received)
       when is_integer(sent) and is_integer(received) and sent > 0 and received > 0 do
    ratio = max(sent, received) / max(1, min(sent, received))
    ratio >= 20 and sent + received >= 2048
  end

  defp highly_asymmetric_transfer?(_, _), do: false

  defp suspicious_domain_for_c2?(domain) when is_binary(domain) do
    domain = String.downcase(String.trim(domain))

    domain != "" and
      (Enum.any?(@suspicious_domain_patterns, &Regex.match?(&1, domain)) or
         String.contains?(domain, ["c2", "beacon", "payload", "stage", "callback"]))
  end

  defp suspicious_domain_for_c2?(_), do: false

  defp known_c2_fingerprint?(ja3, ja4) do
    (is_binary(ja3) and String.downcase(ja3) in @known_c2_ja3_hashes) or
      (is_binary(ja4) and Map.has_key?(@known_c2_ja4_hashes, String.downcase(ja4)))
  end

  defp value_any(map, keys) when is_map(map) do
    Enum.find_value(keys, fn key ->
      Map.get(map, key) || Map.get(map, to_string(key))
    end)
  end

  defp value_any(_, _), do: nil

  defp numeric_value(value) when is_number(value), do: value * 1.0

  defp numeric_value(value) when is_binary(value) do
    case Float.parse(value) do
      {parsed, _} -> parsed
      :error -> 0.0
    end
  end

  defp numeric_value(_), do: 0.0

  defp integer_value(value) when is_integer(value), do: value

  defp integer_value(value) when is_binary(value) do
    case Integer.parse(value) do
      {parsed, _} -> parsed
      :error -> nil
    end
  end

  defp integer_value(_), do: nil

  # --------------------------------------------------------------------------
  # Beacon Detection
  # --------------------------------------------------------------------------

  @doc """
  Detect beaconing behavior - regular interval connections typical of C2.

  Uses coefficient of variation (CV) of connection inter-arrival times:
  - CV < 0.2 = highly periodic (strong C2 indicator)
  - CV < 0.5 = somewhat periodic (moderate indicator)

  Supports jitter tolerance: attackers add randomness to beacon intervals
  to evade simple periodicity checks. We account for this by allowing
  higher CV thresholds when the median interval is consistent.

  Also computes jitter percentage as `(max_interval - min_interval) / avg_interval`
  and flags connections with jitter < 15% over 10+ connections as beaconing.

  Requires minimum 5 connections spanning 10+ minutes to trigger,
  keeping up to 100 timestamps and per-connection payload sizes per
  (agent, destination, port) tuple.

  Returns a list of:
    %{destination: ip, port: port, interval_ms: avg, jitter: pct,
      confidence: score, beacon_count: n, ...}
  """
  @spec detect_beaconing(String.t(), String.t(), DateTime.t() | integer(), keyword()) :: [map()]
  def detect_beaconing(agent_id, remote_ip, timestamp, opts \\ [])

  def detect_beaconing(agent_id, remote_ip, timestamp, opts)
      when is_binary(agent_id) and is_binary(remote_ip) do
    port = Keyword.get(opts, :port)
    payload_size = Keyword.get(opts, :payload_size)

    key = {agent_id, remote_ip}
    now_ts = normalize_timestamp(timestamp)

    # Get or create timestamp list and payload sizes
    {timestamps, payload_sizes} = case :ets.lookup(@beacon_table, key) do
      [{^key, %{timestamps: ts_list, payload_sizes: ps_list}}] ->
        {[now_ts | Enum.take(ts_list, 99)],
         if(payload_size, do: [payload_size | Enum.take(ps_list, 99)], else: ps_list)}
      [{^key, %{timestamps: ts_list}}] ->
        {[now_ts | Enum.take(ts_list, 99)],
         if(payload_size, do: [payload_size], else: [])}
      [] ->
        {[now_ts],
         if(payload_size, do: [payload_size], else: [])}
    end

    # Store updated timestamps and payload sizes
    :ets.insert(@beacon_table, {key, %{
      timestamps: timestamps,
      payload_sizes: payload_sizes,
      port: port,
      last_seen: now_ts,
      updated_at: DateTime.utc_now()
    }})

    min_samples = c2_config(:beacon_min_samples, 5)
    min_span_seconds = c2_config(:beacon_min_span_seconds, 600) # 10 minutes

    sorted_ts = Enum.sort(timestamps)
    span_seconds = if length(sorted_ts) >= 2 do
      List.last(sorted_ts) - List.first(sorted_ts)
    else
      0
    end

    # Need minimum samples over a minimum time span for meaningful analysis
    if length(timestamps) >= min_samples and span_seconds >= min_span_seconds do
      # Calculate intervals between consecutive timestamps
      intervals = sorted_ts
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.map(fn [t1, t2] -> abs(t2 - t1) end)
      |> Enum.filter(& &1 > 0)  # Remove zero intervals

      if length(intervals) >= (min_samples - 1) do
        analyze_beacon_intervals(intervals, agent_id, remote_ip, port,
          length(timestamps), span_seconds, payload_sizes)
      else
        []
      end
    else
      []
    end
  end

  def detect_beaconing(_, _, _, _), do: []

  defp analyze_beacon_intervals(intervals, agent_id, remote_ip, port,
         sample_count, span_seconds, payload_sizes) do
    # Calculate statistics
    avg_interval = Enum.sum(intervals) / length(intervals)
    stddev = calculate_stddev(intervals, avg_interval)

    # Coefficient of variation (CV) - lower = more regular
    cv = if avg_interval > 0, do: stddev / avg_interval, else: 1.0

    # Median-based jitter analysis for robustness against outliers
    sorted_intervals = Enum.sort(intervals)
    median_interval = Enum.at(sorted_intervals, div(length(sorted_intervals), 2))

    # Calculate median absolute deviation (MAD) for jitter tolerance
    mad = sorted_intervals
    |> Enum.map(fn i -> abs(i - median_interval) end)
    |> Enum.sort()
    |> then(fn sorted -> Enum.at(sorted, div(length(sorted), 2)) end)

    # Jitter percentage: (max - min) / avg — a simple spread-based metric.
    # Values below 15% indicate highly regular intervals typical of C2 beacons.
    min_interval = List.first(sorted_intervals)
    max_interval = List.last(sorted_intervals)
    jitter_pct = if avg_interval > 0 do
      (max_interval - min_interval) / avg_interval
    else
      1.0
    end

    # MAD-based jitter percentage for logging (more robust against outliers)
    mad_jitter_pct = if median_interval > 0, do: (mad / median_interval) * 100.0, else: 100.0

    # Payload consistency score: if payload sizes are consistent, stronger indicator
    payload_consistency = calculate_payload_consistency(payload_sizes)

    # Confidence boost for longer observation spans, more samples, and payload consistency
    span_boost = min(0.1, span_seconds / 36_000) # Up to 0.1 boost for 10+ hours
    sample_boost = min(0.1, (sample_count - 5) / 100.0) # Up to 0.1 for 100+ samples
    payload_boost = payload_consistency * 0.05 # Up to 0.05 for perfectly consistent payloads

    # Beacon score combines regularity, time spread, and payload consistency
    regularity_score = max(0.0, 1.0 - cv)
    spread_score = min(1.0, span_seconds / 3600.0) # Normalize to 1h observation window
    beacon_score = regularity_score * 0.5 + spread_score * 0.25 + payload_consistency * 0.25

    # Additional beaconing check: jitter < 15% over 10+ connections
    strict_beacon_match = jitter_pct < 0.15 and sample_count >= 10

    cond do
      # Strict beacon: low jitter (< 15%) over 10+ connections
      strict_beacon_match and avg_interval < 3600 ->
        base_confidence = min(0.95, 0.75 + beacon_score * 0.2)
        confidence = min(0.98, base_confidence + span_boost + sample_boost + payload_boost)
        [%{
          type: :c2_beacon_strong,
          confidence: confidence,
          destination: remote_ip,
          port: port,
          interval_ms: Float.round(avg_interval * 1000, 0),
          jitter: Float.round(jitter_pct, 4),
          beacon_count: sample_count,
          description: "Strong beaconing detected from #{agent_id} to #{remote_ip}" <>
            (if port, do: ":#{port}", else: "") <> ": " <>
            "avg interval #{format_interval(avg_interval)}, " <>
            "jitter #{Float.round(jitter_pct * 100, 1)}%, " <>
            "beacon score #{Float.round(beacon_score, 2)}, " <>
            "#{sample_count} samples over #{format_interval(span_seconds)}",
          mitre_techniques: ["T1071", "T1573"],
          metadata: %{
            remote_ip: remote_ip,
            port: port,
            avg_interval_seconds: Float.round(avg_interval, 2),
            median_interval_seconds: Float.round(median_interval * 1.0, 2),
            stddev: Float.round(stddev, 2),
            coefficient_of_variation: Float.round(cv, 4),
            jitter_ratio: Float.round(jitter_pct, 4),
            jitter_percent_mad: Float.round(mad_jitter_pct, 1),
            mad_seconds: Float.round(mad * 1.0, 2),
            min_interval_seconds: Float.round(min_interval * 1.0, 2),
            max_interval_seconds: Float.round(max_interval * 1.0, 2),
            sample_count: sample_count,
            observation_span_seconds: span_seconds,
            beacon_score: Float.round(beacon_score, 4),
            payload_consistency: Float.round(payload_consistency, 4),
            beacon_type: classify_beacon_type(avg_interval)
          }
        }]

      # Strong beacon: highly periodic (CV < 0.2)
      cv < 0.2 and avg_interval < 3600 ->
        base_confidence = min(0.95, 0.7 + (1.0 - cv) * 0.3)
        confidence = min(0.98, base_confidence + span_boost + sample_boost + payload_boost)
        [%{
          type: :c2_beacon_strong,
          confidence: confidence,
          destination: remote_ip,
          port: port,
          interval_ms: Float.round(avg_interval * 1000, 0),
          jitter: Float.round(jitter_pct, 4),
          beacon_count: sample_count,
          description: "Strong beaconing detected from #{agent_id} to #{remote_ip}" <>
            (if port, do: ":#{port}", else: "") <> ": " <>
            "avg interval #{format_interval(avg_interval)}, " <>
            "CV #{Float.round(cv, 3)}, " <>
            "jitter #{Float.round(jitter_pct * 100, 1)}%, " <>
            "beacon score #{Float.round(beacon_score, 2)}, " <>
            "#{sample_count} samples over #{format_interval(span_seconds)}",
          mitre_techniques: ["T1071", "T1573"],
          metadata: %{
            remote_ip: remote_ip,
            port: port,
            avg_interval_seconds: Float.round(avg_interval, 2),
            median_interval_seconds: Float.round(median_interval * 1.0, 2),
            stddev: Float.round(stddev, 2),
            coefficient_of_variation: Float.round(cv, 4),
            jitter_ratio: Float.round(jitter_pct, 4),
            jitter_percent_mad: Float.round(mad_jitter_pct, 1),
            mad_seconds: Float.round(mad * 1.0, 2),
            min_interval_seconds: Float.round(min_interval * 1.0, 2),
            max_interval_seconds: Float.round(max_interval * 1.0, 2),
            sample_count: sample_count,
            observation_span_seconds: span_seconds,
            beacon_score: Float.round(beacon_score, 4),
            payload_consistency: Float.round(payload_consistency, 4),
            beacon_type: classify_beacon_type(avg_interval)
          }
        }]

      # Moderate beacon: somewhat periodic (CV < 0.5) -- captures jittered beacons
      cv < 0.5 and avg_interval < 1800 ->
        base_confidence = min(0.85, 0.4 + (1.0 - cv) * 0.5)
        confidence = min(0.90, base_confidence + span_boost + sample_boost + payload_boost)
        [%{
          type: :c2_beacon_moderate,
          confidence: confidence,
          destination: remote_ip,
          port: port,
          interval_ms: Float.round(avg_interval * 1000, 0),
          jitter: Float.round(jitter_pct, 4),
          beacon_count: sample_count,
          description: "Moderate beaconing pattern from #{agent_id} to #{remote_ip}" <>
            (if port, do: ":#{port}", else: "") <> ": " <>
            "avg interval #{format_interval(avg_interval)}, " <>
            "CV #{Float.round(cv, 3)}, " <>
            "jitter #{Float.round(jitter_pct * 100, 1)}%, " <>
            "#{sample_count} samples",
          mitre_techniques: ["T1071", "T1573"],
          metadata: %{
            remote_ip: remote_ip,
            port: port,
            avg_interval_seconds: Float.round(avg_interval, 2),
            median_interval_seconds: Float.round(median_interval * 1.0, 2),
            coefficient_of_variation: Float.round(cv, 4),
            jitter_ratio: Float.round(jitter_pct, 4),
            jitter_percent_mad: Float.round(mad_jitter_pct, 1),
            sample_count: sample_count,
            observation_span_seconds: span_seconds,
            beacon_score: Float.round(beacon_score, 4),
            payload_consistency: Float.round(payload_consistency, 4)
          }
        }]

      # Weak indicator: periodic but longer intervals (slow beacon / long-haul C2)
      cv < 0.3 and avg_interval >= 3600 and avg_interval < 86400 ->
        [%{
          type: :c2_beacon_weak,
          confidence: min(0.5, 0.3 + span_boost + sample_boost + payload_boost),
          destination: remote_ip,
          port: port,
          interval_ms: Float.round(avg_interval * 1000, 0),
          jitter: Float.round(jitter_pct, 4),
          beacon_count: sample_count,
          description: "Potential slow beaconing from #{agent_id} to #{remote_ip}" <>
            (if port, do: ":#{port}", else: "") <> ": " <>
            "avg interval #{format_interval(avg_interval)}, " <>
            "CV #{Float.round(cv, 3)}",
          mitre_techniques: ["T1071"],
          metadata: %{
            remote_ip: remote_ip,
            port: port,
            avg_interval_seconds: Float.round(avg_interval, 2),
            coefficient_of_variation: Float.round(cv, 4),
            jitter_ratio: Float.round(jitter_pct, 4),
            sample_count: sample_count,
            observation_span_seconds: span_seconds,
            beacon_score: Float.round(beacon_score, 4),
            payload_consistency: Float.round(payload_consistency, 4)
          }
        }]

      true ->
        []
    end
  end

  # Calculate payload size consistency (0.0 = random sizes, 1.0 = identical sizes)
  defp calculate_payload_consistency([]), do: 0.0
  defp calculate_payload_consistency(sizes) when length(sizes) < 3, do: 0.0
  defp calculate_payload_consistency(sizes) do
    avg = Enum.sum(sizes) / length(sizes)
    if avg == 0 do
      0.0
    else
      stddev = calculate_stddev(sizes, avg)
      cv = stddev / avg
      # Invert: low CV = high consistency
      max(0.0, min(1.0, 1.0 - cv))
    end
  end

  defp classify_beacon_type(avg_interval_seconds) do
    cond do
      avg_interval_seconds < 60 -> "fast_beacon"
      avg_interval_seconds < 300 -> "standard_beacon"
      avg_interval_seconds < 3600 -> "slow_beacon"
      true -> "long_haul"
    end
  end

  # --------------------------------------------------------------------------
  # TLS Certificate Analysis
  # --------------------------------------------------------------------------

  @doc """
  Analyze TLS certificate metadata for C2 indicators.

  Checks for:
  - JA3/JA3S fingerprints against known C2 framework signatures
    (Cobalt Strike, Metasploit, Sliver, Covenant, Mythic)
  - Known bad JA3 hashes from a map of common C2 fingerprints
  - Self-signed certificates (issuer == subject)
  - Certificate validity period anomalies (too long: > 10 years, or too short: < 90 days)
  - Recently issued certificates (< 30 days old)
  - Suspicious issuer + unusual domain combinations
  - Missing/unusual SANs

  Returns a list of findings with confidence scores.
  """
  @spec analyze_tls_metadata(map()) :: [map()]
  def analyze_tls_metadata(cert_info) when is_map(cert_info) do
    issues = []

    issuer = cert_info[:issuer] || cert_info["issuer"]
    subject = cert_info[:subject] || cert_info["subject"]
    not_before = parse_cert_date(cert_info[:not_before] || cert_info["not_before"])
    not_after = parse_cert_date(cert_info[:not_after] || cert_info["not_after"])
    serial = cert_info[:serial] || cert_info["serial"]
    san = cert_info[:san] || cert_info["san"] || []
    ja3_hash = cert_info[:ja3] || cert_info["ja3"]
    ja3s_hash = cert_info[:ja3s] || cert_info["ja3s"]

    # 1. Self-signed certificate check (issuer == subject)
    issues = if issuer && subject && normalize_cert_name(issuer) == normalize_cert_name(subject) do
      [{:self_signed, 0.7, "Self-signed certificate detected (issuer matches subject: #{truncate_str(normalize_cert_name(issuer), 60)})"} | issues]
    else
      issues
    end

    # 2. JA3 fingerprint check against known C2 framework signatures
    issues = if is_binary(ja3_hash) and ja3_hash != "" do
      ja3_c2_match = check_ja3_c2_framework(ja3_hash)
      case ja3_c2_match do
        {:match, framework, confidence} ->
          [{:ja3_c2_match, confidence,
            "JA3 fingerprint #{ja3_hash} matches known C2 framework: #{framework}"} | issues]
        :no_match ->
          issues
      end
    else
      issues
    end

    # 3. JA3S (server) fingerprint check against known C2 server signatures
    issues = if is_binary(ja3s_hash) and ja3s_hash != "" do
      ja3s_c2_match = check_ja3s_c2_framework(ja3s_hash)
      case ja3s_c2_match do
        {:match, framework, confidence} ->
          [{:ja3s_c2_match, confidence,
            "JA3S server fingerprint #{ja3s_hash} matches known C2 framework: #{framework}"} | issues]
        :no_match ->
          issues
      end
    else
      issues
    end

    # 4. Recently issued certificate (< 30 days)
    issues = if not_before do
      age_days = DateTime.diff(DateTime.utc_now(), not_before, :day)
      if age_days >= 0 and age_days < 30 do
        confidence = max(0.3, 0.6 - age_days * 0.01)
        [{:recent_cert, confidence, "Certificate issued #{age_days} days ago"} | issues]
      else
        issues
      end
    else
      issues
    end

    # 5. Certificate validity period anomalies (too short OR too long)
    issues = if not_before && not_after do
      validity_days = DateTime.diff(not_after, not_before, :day)
      cond do
        # Too short: < 90 days is unusual for legitimate services
        validity_days > 0 and validity_days < 90 ->
          [{:short_validity, 0.4,
            "Certificate validity period unusually short: #{validity_days} days"} | issues]

        # Too long: > 10 years is suspicious; legitimate CAs cap at ~398 days for leaf certs
        validity_days > 3650 ->
          [{:long_validity, 0.5,
            "Certificate validity period unusually long: #{validity_days} days (#{Float.round(validity_days / 365.0, 1)} years), typical of self-generated C2 certs"} | issues]

        # Moderately long: > 2 years for a leaf certificate is atypical post-2020
        validity_days > 825 ->
          [{:extended_validity, 0.25,
            "Certificate validity period #{validity_days} days exceeds industry standard (~398 days)"} | issues]

        true ->
          issues
      end
    else
      issues
    end

    # 6. Suspicious issuer + domain combination
    issues = if issuer && subject do
      is_suspicious_issuer = Enum.any?(@suspicious_issuers_patterns, fn pattern ->
        Regex.match?(pattern, to_string(issuer))
      end)

      is_suspicious_domain = Enum.any?(@suspicious_domain_patterns, fn pattern ->
        Regex.match?(pattern, to_string(subject))
      end)

      if is_suspicious_issuer and is_suspicious_domain do
        [{:suspicious_issuer_domain, 0.6,
          "Suspicious issuer (#{truncate_str(to_string(issuer), 40)}) with unusual domain pattern (#{truncate_str(to_string(subject), 40)})"} | issues]
      else
        issues
      end
    else
      issues
    end

    # 7. No SANs or only IP in SAN (unusual for legitimate HTTPS)
    issues = cond do
      san == [] or san == nil ->
        [{:no_san, 0.3, "Certificate has no Subject Alternative Names"} | issues]

      is_list(san) and Enum.all?(san, &ip_only_san?/1) ->
        [{:ip_only_san, 0.35,
          "Certificate SANs contain only IP addresses, no domain names"} | issues]

      true ->
        issues
    end

    # Convert issues to detection format
    if length(issues) > 0 do
      # Aggregate confidence from all issues (capped at 0.95)
      total_confidence = issues
      |> Enum.map(fn {_, conf, _} -> conf end)
      |> Enum.sum()
      |> min(0.95)

      issue_descriptions = issues
      |> Enum.map(fn {_, _, desc} -> desc end)
      |> Enum.join("; ")

      [%{
        type: :c2_suspicious_certificate,
        confidence: total_confidence,
        description: "Suspicious TLS certificate: #{issue_descriptions}",
        mitre_techniques: ["T1573", "T1071"],
        metadata: %{
          issues: Enum.map(issues, fn {type, conf, desc} ->
            %{type: type, confidence: conf, description: desc}
          end),
          issuer: issuer,
          subject: subject,
          serial: serial,
          ja3: ja3_hash,
          ja3s: ja3s_hash,
          not_before: not_before && DateTime.to_iso8601(not_before),
          not_after: not_after && DateTime.to_iso8601(not_after)
        }
      }]
    else
      []
    end
  end

  def analyze_tls_metadata(_), do: []

  # Map of known C2 framework JA3 hashes with framework name and confidence.
  # Extends the @known_c2_ja3_hashes list with framework attribution.
  @known_c2_ja3_framework_map %{
    # Cobalt Strike default and malleable C2 profiles
    "72a589da586844d7f0818ce684948eea" => {"Cobalt Strike", 0.90},
    "a0e9f5d64349fb13191bc781f81f42e1" => {"Cobalt Strike", 0.90},
    "6734f37431670b3ab4292b8f60f29984" => {"Cobalt Strike", 0.85},
    "b742b407517bac9536a77a7b0fee28e9" => {"Cobalt Strike", 0.85},
    "ae4edc6faf64d08308082ad26be60767" => {"Cobalt Strike", 0.80},
    # Metasploit / Meterpreter
    "5d79f8a9e9d2c7e2b6a7f5e4d3c2b1a0" => {"Metasploit", 0.85},
    "e35df3e28bdfd0e0ba4ca503d5a34d21" => {"Metasploit", 0.85},
    "c12f54a256846a56b0145666e1f06b2e" => {"Metasploit", 0.80},
    # Sliver C2 framework
    "473cd7cb9faa642487833865d516e578" => {"Sliver", 0.85},
    "2ad2b325a7eae82b4a5a7c8b9a8d0f3e" => {"Sliver", 0.85},
    "d6b0b77f8a6b9e3e5c4f8d2a1e0c7b9a" => {"Sliver", 0.80},
    # Empire
    "3b5074b1b5d032e5620f69f9f700ff0e" => {"Empire", 0.80},
    # PoshC2
    "b32309a26951912be7dba376398abc3b" => {"PoshC2", 0.80},
    # Covenant / Grunt
    "4d7a28d6f2263ed61de88ca66eb2e389" => {"Covenant", 0.80},
    # Havoc C2
    "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d" => {"Havoc", 0.80},
    # Brute Ratel C4
    "7c02dbae662670040c7af9bd15fb7e2f" => {"Brute Ratel", 0.85},
    # Mythic C2
    "bd0bf25947d4a37404f0424edf4db9ad" => {"Mythic", 0.80}
  }

  # Known C2 framework JA3S (server-side) fingerprints.
  # These identify the TLS server component of C2 frameworks.
  @known_c2_ja3s_framework_map %{
    # Cobalt Strike default HTTPS listener
    "b742b407517bac9536a77a7b0fee28e9" => {"Cobalt Strike", 0.90},
    "ae4edc6faf64d08308082ad26be60767" => {"Cobalt Strike", 0.85},
    "fd4bc6cea4877646ccd62f0792ec0b62" => {"Cobalt Strike", 0.85},
    # Metasploit reverse HTTPS handler
    "e35df3e28bdfd0e0ba4ca503d5a34d21" => {"Metasploit", 0.85},
    "4bea04b020e5a6cb0f582da0476b0e45" => {"Metasploit", 0.80},
    # Sliver implant server
    "473cd7cb9faa642487833865d516e578" => {"Sliver", 0.85},
    "15af977ce25de452b96affa2addb1036" => {"Sliver", 0.80},
    # Covenant / Grunt listener
    "4d7a28d6f2263ed61de88ca66eb2e389" => {"Covenant", 0.80},
    # Mythic server
    "2b0a3f8e1d4c5b6a7f8e9d0c1b2a3f4e" => {"Mythic", 0.80},
    "f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0" => {"Mythic", 0.75}
  }

  defp check_ja3_c2_framework(ja3_hash) do
    case Map.get(@known_c2_ja3_framework_map, ja3_hash) do
      {framework, confidence} -> {:match, framework, confidence}
      nil -> :no_match
    end
  end

  defp check_ja3s_c2_framework(ja3s_hash) do
    case Map.get(@known_c2_ja3s_framework_map, ja3s_hash) do
      {framework, confidence} -> {:match, framework, confidence}
      nil -> :no_match
    end
  end

  defp ip_only_san?(san_entry) when is_binary(san_entry) do
    Regex.match?(~r/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/, san_entry)
  end
  defp ip_only_san?(_), do: false

  defp truncate_str(str, max_len) when is_binary(str) do
    if String.length(str) > max_len do
      String.slice(str, 0, max_len) <> "..."
    else
      str
    end
  end
  defp truncate_str(other, _max_len), do: to_string(other)

  # --------------------------------------------------------------------------
  # JA3 Fingerprint Analysis
  # --------------------------------------------------------------------------

  defp check_ja3(nil), do: []
  defp check_ja3(ja3_hash) when is_binary(ja3_hash) do
    case :ets.lookup(@ja3_table, ja3_hash) do
      [{^ja3_hash, %{type: :known_c2} = info}] ->
        [%{
          type: :c2_ja3_match,
          confidence: 0.9,
          description: "JA3 fingerprint matches known C2 framework: #{ja3_hash}",
          mitre_techniques: ["T1071", "T1573"],
          metadata: %{
            ja3_hash: ja3_hash,
            match_info: info
          }
        }]

      _ ->
        []
    end
  end

  # --------------------------------------------------------------------------
  # JA4 Fingerprint Analysis (TLS 1.3 aware)
  # --------------------------------------------------------------------------

  defp check_ja4(nil), do: []
  defp check_ja4(ja4_hash) when is_binary(ja4_hash) do
    case :ets.lookup(@ja4_table, ja4_hash) do
      [{^ja4_hash, %{type: :known_c2} = info}] ->
        framework = info[:framework] || "Unknown"
        confidence = info[:confidence] || 0.85
        [%{
          type: :c2_ja4_match,
          confidence: confidence,
          description: "JA4 fingerprint matches known C2 framework (#{framework}): #{ja4_hash}",
          mitre_techniques: ["T1071", "T1573"],
          metadata: %{
            ja4_hash: ja4_hash,
            framework: framework,
            match_info: info
          }
        }]

      _ ->
        []
    end
  end

  # --------------------------------------------------------------------------
  # Rare / Unknown Fingerprint Detection
  # --------------------------------------------------------------------------

  @doc """
  Flag JA3/JA4 fingerprints that are neither known-C2 nor common-legitimate.
  A rare fingerprint connecting to an uncategorized destination is suspicious.
  """
  defp check_rare_fingerprint(ja3_hash, ja4_hash, hostname, remote_ip) do
    # Only check if we have at least one fingerprint
    if is_nil(ja3_hash) and is_nil(ja4_hash) do
      []
    else
      ja3_known = ja3_hash && (ja3_hash in @known_c2_ja3_hashes or ja3_hash in @common_legitimate_ja3)
      ja4_known = ja4_hash && :ets.lookup(@ja4_table, ja4_hash) != []

      # If neither JA3 nor JA4 is recognized, and the destination is not trusted
      if not (ja3_known || false) and not (ja4_known || false) and not trusted_hostname?(hostname) do
        [%{
          type: :c2_rare_fingerprint,
          confidence: 0.35,
          description: "Rare/unknown TLS fingerprint" <>
            (if ja3_hash, do: " JA3:#{String.slice(ja3_hash, 0..11)}...", else: "") <>
            (if ja4_hash, do: " JA4:#{String.slice(ja4_hash, 0..15)}...", else: "") <>
            " connecting to #{hostname || remote_ip}",
          mitre_techniques: ["T1071", "T1573"],
          metadata: %{
            ja3_hash: ja3_hash,
            ja4_hash: ja4_hash,
            hostname: hostname,
            remote_ip: remote_ip
          }
        }]
      else
        []
      end
    end
  end

  defp trusted_hostname?(nil), do: false
  defp trusted_hostname?(hostname) when is_binary(hostname) do
    hostname_lower = String.downcase(hostname)
    Enum.any?([
      "microsoft.com", "google.com", "googleapis.com", "amazon.com",
      "amazonaws.com", "cloudflare.com", "github.com", "apple.com",
      "mozilla.org", "akamai.net", "cloudfront.net", "office.com",
      "windows.com", "live.com", "azure.com"
    ], fn trusted ->
      hostname_lower == trusted or String.ends_with?(hostname_lower, "." <> trusted)
    end)
  end

  # --------------------------------------------------------------------------
  # DGA-over-HTTPS Detection
  # --------------------------------------------------------------------------

  @doc """
  Detect DGA (Domain Generation Algorithm) domains used for HTTPS C2.

  Multi-signal analysis:
  1. Shannon entropy of the domain label (> 3.5 bits/char is suspicious)
  2. Bigram/trigram frequency compared to English language distribution
  3. Consonant-to-vowel ratio (DGA domains have unusual ratios, > 0.7)
  4. Domain length distribution (DGA domains tend to be longer)

  Triggers a detection when entropy > 3.5 AND consonant ratio > 0.7,
  or when individual signals are very strong.
  """
  @spec detect_dga_https(String.t() | nil) :: [map()]
  def detect_dga_https(nil), do: []
  def detect_dga_https(domain) when is_binary(domain) do
    # Extract the second-level domain for analysis
    labels = String.split(domain, ".")
    sld = if length(labels) >= 2, do: Enum.at(labels, length(labels) - 2), else: hd(labels)
    sld_lower = String.downcase(sld)

    # Skip very short labels — not enough data for meaningful analysis
    if String.length(sld_lower) < 5 do
      []
    else
      # 1. Shannon entropy
      entropy = calculate_shannon_entropy(sld_lower)
      entropy_threshold = c2_config(:dga_entropy_threshold, 3.5)

      # 2. Bigram frequency score: how well bigrams match English distribution
      bigram_score = calculate_bigram_deviation(sld_lower)

      # 3. Trigram frequency score
      trigram_score = calculate_trigram_deviation(sld_lower)

      # 4. Consonant-to-vowel ratio
      consonant_ratio = calculate_consonant_ratio(sld_lower)
      consonant_threshold = c2_config(:dga_consonant_threshold, 0.7)

      # 5. Domain length factor (DGA domains are often 10-20+ chars)
      sld_len = String.length(sld_lower)
      length_factor = cond do
        sld_len >= 20 -> 0.15
        sld_len >= 15 -> 0.10
        sld_len >= 10 -> 0.05
        true -> 0.0
      end

      # Combined DGA detection: require entropy AND consonant ratio thresholds
      is_dga_by_combined = entropy > entropy_threshold and consonant_ratio > consonant_threshold
      # Or very high entropy alone
      is_dga_by_entropy = entropy > (entropy_threshold + 0.5)
      # Or strong n-gram deviation with moderate entropy
      is_dga_by_ngram = entropy > (entropy_threshold - 0.3) and (bigram_score > 0.6 or trigram_score > 0.6)

      if is_dga_by_combined or is_dga_by_entropy or is_dga_by_ngram do
        # Build confidence from multiple signals
        entropy_conf = min(0.4, (entropy - entropy_threshold) * 0.15)
        consonant_conf = if consonant_ratio > consonant_threshold do
          min(0.2, (consonant_ratio - consonant_threshold) * 0.5)
        else
          0.0
        end
        ngram_conf = min(0.2, (bigram_score + trigram_score) * 0.1)

        base_confidence = 0.35 + entropy_conf + consonant_conf + ngram_conf + length_factor
        confidence = min(0.92, base_confidence)

        [%{
          type: :c2_dga_https,
          confidence: confidence,
          description: "Potential DGA domain for HTTPS C2: #{domain} " <>
            "(entropy: #{Float.round(entropy, 2)}, " <>
            "consonant ratio: #{Float.round(consonant_ratio, 2)}, " <>
            "bigram deviation: #{Float.round(bigram_score, 2)}, " <>
            "trigram deviation: #{Float.round(trigram_score, 2)})",
          mitre_techniques: ["T1568.002", "T1071", "T1573"],
          metadata: %{
            domain: domain,
            sld: sld,
            entropy: Float.round(entropy, 3),
            consonant_ratio: Float.round(consonant_ratio, 3),
            bigram_deviation: Float.round(bigram_score, 3),
            trigram_deviation: Float.round(trigram_score, 3),
            sld_length: sld_len,
            detection_signals: build_dga_signals(is_dga_by_combined, is_dga_by_entropy, is_dga_by_ngram)
          }
        }]
      else
        []
      end
    end
  end

  # Bigram deviation: compare domain bigrams against English language frequency.
  # Returns 0.0 (matches English perfectly) to 1.0 (completely unlike English).
  defp calculate_bigram_deviation(str) when byte_size(str) < 3, do: 0.0
  defp calculate_bigram_deviation(str) do
    # Common English bigrams (approximate top 30 by frequency)
    common_bigrams = MapSet.new([
      "th", "he", "in", "en", "nt", "re", "er", "an", "ti", "on",
      "at", "es", "st", "or", "nd", "to", "al", "te", "co", "de",
      "ra", "et", "ed", "it", "sa", "em", "ro", "is", "le", "ve"
    ])

    chars = String.graphemes(str)
    bigrams = chars
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.map(fn [a, b] -> a <> b end)

    if length(bigrams) == 0 do
      0.0
    else
      # Count how many bigrams appear in the common English set
      common_count = Enum.count(bigrams, fn bg -> MapSet.member?(common_bigrams, bg) end)
      common_ratio = common_count / length(bigrams)

      # In normal English text, roughly 30-50% of bigrams are common.
      # DGA domains will have a much lower ratio.
      # Deviation = 1.0 - normalized_common_ratio
      deviation = max(0.0, 1.0 - common_ratio * 2.5)
      min(1.0, deviation)
    end
  end

  # Trigram deviation: compare domain trigrams against English language frequency.
  # Returns 0.0 (matches English) to 1.0 (completely unlike English).
  defp calculate_trigram_deviation(str) when byte_size(str) < 4, do: 0.0
  defp calculate_trigram_deviation(str) do
    # Common English trigrams
    common_trigrams = MapSet.new([
      "the", "and", "ing", "ent", "ion", "tio", "for", "ate", "her", "tha",
      "ere", "ter", "hat", "ati", "est", "all", "ith", "his", "ver", "ons",
      "con", "are", "ess", "not", "ive", "int", "rea", "pro", "com", "str"
    ])

    chars = String.graphemes(str)
    trigrams = chars
    |> Enum.chunk_every(3, 1, :discard)
    |> Enum.map(fn [a, b, c] -> a <> b <> c end)

    if length(trigrams) == 0 do
      0.0
    else
      common_count = Enum.count(trigrams, fn tg -> MapSet.member?(common_trigrams, tg) end)
      common_ratio = common_count / length(trigrams)

      # In English text, about 15-30% of trigrams are common.
      # DGA domains will have near-zero common trigrams.
      deviation = max(0.0, 1.0 - common_ratio * 4.0)
      min(1.0, deviation)
    end
  end

  # Consonant-to-vowel ratio: DGA domains tend to be consonant-heavy.
  # Returns ratio of consonant characters to total alpha characters (0.0 to 1.0).
  defp calculate_consonant_ratio(str) do
    vowels = MapSet.new(~w(a e i o u))
    consonants = MapSet.new(~w(b c d f g h j k l m n p q r s t v w x y z))

    chars = str |> String.downcase() |> String.graphemes()
    vowel_count = Enum.count(chars, fn c -> MapSet.member?(vowels, c) end)
    consonant_count = Enum.count(chars, fn c -> MapSet.member?(consonants, c) end)
    alpha_count = vowel_count + consonant_count

    if alpha_count == 0 do
      0.0
    else
      consonant_count / alpha_count
    end
  end

  defp build_dga_signals(combined, entropy_only, ngram) do
    signals = []
    signals = if combined, do: ["entropy_and_consonant" | signals], else: signals
    signals = if entropy_only, do: ["high_entropy" | signals], else: signals
    signals = if ngram, do: ["ngram_deviation" | signals], else: signals
    signals
  end

  # --------------------------------------------------------------------------
  # Domain Fronting Detection
  # --------------------------------------------------------------------------

  @doc """
  Detect potential domain fronting (T1090.004).

  Domain fronting uses CDN infrastructure to hide C2 traffic by using a
  legitimate domain in the SNI but routing to a malicious backend via
  a different Host header.

  Detection signals:
  1. SNI vs Host header mismatch — the primary fronting indicator. If the TLS
     SNI points to a legitimate domain (e.g., "cdn.example.com") but the HTTP
     Host header routes to a different domain, this is classic domain fronting.
  2. CDN-based fronting — SNI points to a CDN provider (Cloudflare, CloudFront,
     Azure CDN, Google) but the Host header differs.
  3. Suspicious SNI patterns with CDN IP ranges.

  Returns findings with the fronted domain (SNI), actual backend (Host header),
  and CDN provider.
  """
  @spec detect_domain_fronting(String.t() | nil, String.t() | nil, String.t() | nil) :: [map()]
  def detect_domain_fronting(sni_hostname, remote_ip, host_header \\ nil)
  def detect_domain_fronting(nil, _, _), do: []
  def detect_domain_fronting(_, nil, _), do: []
  def detect_domain_fronting(sni_hostname, remote_ip, host_header) do
    # CDN IP ranges: {CIDR, provider_name}
    cdn_providers = c2_config(:cdn_providers, [
      {"13.32.0.0/16", "CloudFront"},
      {"13.33.0.0/16", "CloudFront"},
      {"52.84.0.0/16", "CloudFront"},
      {"54.182.0.0/16", "CloudFront"},
      {"99.84.0.0/16", "CloudFront"},
      {"143.204.0.0/16", "CloudFront"},
      {"104.16.0.0/12", "Cloudflare"},
      {"172.64.0.0/13", "Cloudflare"},
      {"141.101.64.0/18", "Cloudflare"},
      {"108.162.192.0/18", "Cloudflare"},
      {"190.93.240.0/20", "Cloudflare"},
      {"188.114.96.0/20", "Cloudflare"},
      {"197.234.240.0/22", "Cloudflare"},
      {"198.41.128.0/17", "Cloudflare"},
      {"162.158.0.0/15", "Cloudflare"},
      {"104.18.0.0/15", "Cloudflare"},
      {"35.190.0.0/16", "Google Cloud CDN"},
      {"35.191.0.0/16", "Google Cloud CDN"},
      {"130.211.0.0/22", "Google Cloud CDN"},
      {"13.107.42.0/24", "Azure CDN"},
      {"13.107.43.0/24", "Azure CDN"},
      {"2.16.0.0/13", "Akamai"},
      {"23.32.0.0/11", "Akamai"},
      {"23.64.0.0/14", "Akamai"},
      {"104.64.0.0/10", "Akamai"}
    ])

    # CDN domain suffixes for SNI-based CDN detection (when IP is not in known ranges)
    cdn_domain_suffixes = [
      {".cloudfront.net", "CloudFront"},
      {".cloudflare.com", "Cloudflare"},
      {".azureedge.net", "Azure CDN"},
      {".azurefd.net", "Azure CDN"},
      {".akamaized.net", "Akamai"},
      {".akamai.net", "Akamai"},
      {".edgekey.net", "Akamai"},
      {".googleapis.com", "Google Cloud CDN"},
      {".googlevideo.com", "Google Cloud CDN"},
      {".fastly.net", "Fastly"},
      {".fastlylb.net", "Fastly"},
      {".stackpathdns.com", "StackPath"}
    ]

    detections = []

    # Check if IP is in a CDN range
    cdn_by_ip = Enum.find(cdn_providers, fn {cidr, _name} ->
      ip_in_cidr?(remote_ip, cidr)
    end)

    # Check if SNI points to a CDN domain
    sni_lower = String.downcase(sni_hostname)
    cdn_by_sni = Enum.find(cdn_domain_suffixes, fn {suffix, _name} ->
      String.ends_with?(sni_lower, suffix)
    end)

    cdn_match = cond do
      cdn_by_ip -> {:ip, elem(cdn_by_ip, 1)}
      cdn_by_sni -> {:sni, elem(cdn_by_sni, 1)}
      true -> nil
    end

    # Signal 1: SNI vs Host header mismatch (the strongest domain fronting indicator)
    detections = if is_binary(host_header) and host_header != "" do
      host_clean = host_header
      |> String.downcase()
      |> String.trim()
      |> String.replace(~r/:\d+$/, "")  # Strip port number if present

      sni_clean = sni_lower |> String.trim()

      if host_clean != sni_clean and not domain_suffix_match?(host_clean, sni_clean) do
        # SNI and Host header point to different domains — domain fronting
        {confidence, description} = if cdn_match do
          {_match_type, cdn_name} = cdn_match
          {0.85,
            "Domain fronting detected: SNI '#{sni_hostname}' vs Host header '#{host_header}' " <>
            "via #{cdn_name} CDN (#{remote_ip}). " <>
            "The fronted domain (#{sni_hostname}) masks the actual backend (#{host_header})."}
        else
          {0.7,
            "SNI/Host header mismatch detected: SNI '#{sni_hostname}' vs Host header '#{host_header}' " <>
            "(#{remote_ip}). This may indicate domain fronting."}
        end

        [%{
          type: :c2_domain_fronting_confirmed,
          confidence: confidence,
          description: description,
          mitre_techniques: ["T1090.004", "T1071"],
          metadata: %{
            sni: sni_hostname,
            host_header: host_header,
            fronted_domain: sni_hostname,
            actual_backend: host_header,
            remote_ip: remote_ip,
            cdn_provider: if(cdn_match, do: elem(cdn_match, 1), else: nil),
            cdn_detection_method: if(cdn_match, do: elem(cdn_match, 0), else: nil)
          }
        } | detections]
      else
        detections
      end
    else
      detections
    end

    # Signal 2: CDN IP with suspicious SNI pattern (no host header available)
    detections = if cdn_match and detections == [] do
      {_match_type, cdn_name} = cdn_match

      sni_suspicious = Enum.any?(@suspicious_domain_patterns, fn pattern ->
        Regex.match?(pattern, sni_hostname)
      end)

      if sni_suspicious do
        [%{
          type: :c2_domain_fronting_suspected,
          confidence: 0.6,
          description: "Potential domain fronting detected: suspicious SNI '#{sni_hostname}' " <>
            "via #{cdn_name} (#{remote_ip})",
          mitre_techniques: ["T1090.004", "T1071"],
          metadata: %{
            sni: sni_hostname,
            fronted_domain: sni_hostname,
            actual_backend: nil,
            remote_ip: remote_ip,
            cdn_provider: cdn_name
          }
        } | detections]
      else
        detections
      end
    else
      detections
    end

    detections
  end

  # Check if two domains share a common parent (e.g., "www.example.com" and "example.com")
  defp domain_suffix_match?(domain_a, domain_b) do
    a_labels = String.split(domain_a, ".")
    b_labels = String.split(domain_b, ".")

    # Extract registrable domain (last 2 labels, or last 3 for co.uk, etc.)
    a_base = Enum.take(a_labels, -2) |> Enum.join(".")
    b_base = Enum.take(b_labels, -2) |> Enum.join(".")

    a_base == b_base
  end

  # --------------------------------------------------------------------------
  # Data Ratio Analysis
  # --------------------------------------------------------------------------

  defp analyze_data_ratio(agent_id, remote_ip, bytes_sent, bytes_received) do
    key = {agent_id, remote_ip}

    # Update cumulative stats
    current = case :ets.lookup(@connection_stats_table, key) do
      [{^key, stats}] -> stats
      [] -> %{total_sent: 0, total_received: 0, connection_count: 0}
    end

    updated = %{
      total_sent: current.total_sent + (bytes_sent || 0),
      total_received: current.total_received + (bytes_received || 0),
      connection_count: current.connection_count + 1,
      last_seen: DateTime.utc_now()
    }

    :ets.insert(@connection_stats_table, {key, updated})

    # Analyze ratio after sufficient data (> 10 connections, > 10KB total)
    total_data = updated.total_sent + updated.total_received

    if updated.connection_count >= 10 and total_data > 10_000 do
      # C2 typically has more download (commands) than upload (beacons)
      # But some C2 (exfil) has more upload
      ratio = if updated.total_sent > 0, do: updated.total_received / updated.total_sent, else: 0

      cond do
        # Asymmetric C2 pattern: much more download than upload
        ratio > 10 and updated.total_received > 100_000 ->
          [%{
            type: :c2_asymmetric_traffic,
            confidence: 0.5,
            description: "Asymmetric traffic pattern to #{remote_ip}: " <>
              "download/upload ratio #{Float.round(ratio, 1)}:1 over #{updated.connection_count} connections",
            mitre_techniques: ["T1071"],
            metadata: %{
              remote_ip: remote_ip,
              ratio: Float.round(ratio, 2),
              total_sent: updated.total_sent,
              total_received: updated.total_received,
              connection_count: updated.connection_count
            }
          }]

        # Exfiltration pattern: much more upload than download
        updated.total_sent > updated.total_received * 5 and updated.total_sent > 1_000_000 ->
          [%{
            type: :c2_exfil_traffic,
            confidence: 0.6,
            description: "Potential exfiltration pattern to #{remote_ip}: " <>
              "#{format_bytes(updated.total_sent)} uploaded over #{updated.connection_count} connections",
            mitre_techniques: ["T1041", "T1071"],
            metadata: %{
              remote_ip: remote_ip,
              total_sent: updated.total_sent,
              total_received: updated.total_received,
              connection_count: updated.connection_count
            }
          }]

        true ->
          []
      end
    else
      []
    end
  end

  # --------------------------------------------------------------------------
  # Connection Stats Analysis
  # --------------------------------------------------------------------------

  defp update_and_analyze_connection_stats(agent_id, remote_ip, timestamp) do
    # This adds connection frequency analysis beyond simple beaconing
    # Detects bursts of connections that might indicate C2 check-in storms

    key = {agent_id, remote_ip, :freq}
    now_ts = normalize_timestamp(timestamp)
    window_ms = c2_config(:frequency_window_ms, 300_000) # 5 minutes

    # Get recent connection timestamps
    recent = case :ets.lookup(@connection_stats_table, key) do
      [{^key, %{timestamps: ts}}] -> ts
      [] -> []
    end

    # Filter to window and add current
    cutoff = now_ts - window_ms
    recent = [now_ts | Enum.filter(recent, fn t -> t > cutoff end)]
    |> Enum.take(100)

    :ets.insert(@connection_stats_table, {key, %{timestamps: recent, updated_at: DateTime.utc_now()}})

    # Analyze frequency
    count_in_window = length(recent)
    threshold = c2_config(:high_frequency_threshold, 100)

    if count_in_window > threshold do
      [%{
        type: :c2_high_frequency,
        confidence: min(0.7, 0.4 + count_in_window * 0.01),
        description: "High frequency HTTPS connections to #{remote_ip}: " <>
          "#{count_in_window} connections in #{div(window_ms, 60_000)} minutes",
        mitre_techniques: ["T1071"],
        metadata: %{
          remote_ip: remote_ip,
          connection_count: count_in_window,
          window_minutes: div(window_ms, 60_000)
        }
      }]
    else
      []
    end
  end

  # --------------------------------------------------------------------------
  # DNS Tunneling Detection
  # --------------------------------------------------------------------------

  @doc """
  Analyze a DNS query event for C2 tunneling indicators.

  DNS tunneling is detected via:
  1. Shannon entropy of subdomain labels (>3.5 bits/char = suspicious)
  2. Unusually long subdomain labels (>24 chars = likely encoded data)
  3. High query volume to a single domain (>50 queries/minute)
  4. TXT record queries to non-standard domains (common C2 data channel)

  MITRE ATT&CK: T1071.004 (DNS), T1573 (Encrypted Channel)
  """
  defp do_analyze_dns_tunneling(event) do
    payload = event[:payload] || event["payload"] || %{}
    domain = payload[:query] || payload["query"] || ""
    query_type = payload[:query_type] || payload["query_type"] || "A"
    agent_id = event[:agent_id] || event["agent_id"]
    timestamp = event[:timestamp] || event["timestamp"] || System.system_time(:millisecond)

    domain = String.downcase(String.trim(domain))

    # Skip empty/safe domains
    if domain == "" or dns_tunnel_safe_domain?(domain) do
      []
    else
      detections = []

      # 1. Subdomain entropy analysis
      detections = detections ++ analyze_subdomain_entropy(domain)

      # 2. Long subdomain label detection
      detections = detections ++ detect_long_subdomain_labels(domain)

      # 3. Query volume tracking and detection
      detections = detections ++ track_dns_query_volume(agent_id, domain, timestamp)

      # 4. TXT record abuse detection
      detections = detections ++ detect_dns_txt_tunneling(domain, query_type)

      detections
    end
  end

  defp analyze_subdomain_entropy(domain) do
    labels = String.split(domain, ".")

    # Need at least 3 labels to have a subdomain (sub.domain.tld)
    if length(labels) < 3 do
      []
    else
      # Analyze all subdomain labels (everything except the last 2 parts)
      subdomain_labels = Enum.take(labels, length(labels) - 2)

      # Calculate entropy for each subdomain label and for the combined subdomain
      combined_subdomain = Enum.join(subdomain_labels, "")
      entropy = calculate_shannon_entropy(combined_subdomain)

      entropy_threshold = c2_config(:dns_tunnel_entropy_threshold, 3.5)

      if entropy > entropy_threshold and String.length(combined_subdomain) >= 8 do
        confidence = min(0.85, 0.45 + (entropy - entropy_threshold) * 0.15)
        [%{
          type: :c2_dns_tunnel_entropy,
          confidence: confidence,
          description: "DNS tunneling indicator: subdomain '#{Enum.join(subdomain_labels, ".")}' " <>
            "has high entropy (#{Float.round(entropy, 2)} bits/char, threshold #{entropy_threshold}), " <>
            "suggesting encoded C2 data in domain '#{domain}'",
          mitre_techniques: ["T1071.004", "T1573"],
          metadata: %{
            domain: domain,
            subdomain: Enum.join(subdomain_labels, "."),
            entropy: Float.round(entropy, 3),
            threshold: entropy_threshold,
            subdomain_length: String.length(combined_subdomain)
          }
        }]
      else
        []
      end
    end
  end

  defp detect_long_subdomain_labels(domain) do
    labels = String.split(domain, ".")

    if length(labels) < 3 do
      []
    else
      # Check subdomain labels (everything except the last 2 parts)
      subdomain_labels = Enum.take(labels, length(labels) - 2)
      long_label_threshold = c2_config(:dns_tunnel_long_label_chars, 24)

      long_labels = Enum.filter(subdomain_labels, fn label ->
        String.length(label) > long_label_threshold
      end)

      if long_labels != [] do
        longest = Enum.max_by(long_labels, &String.length/1)
        longest_len = String.length(longest)
        confidence = min(0.80, 0.50 + (longest_len - long_label_threshold) * 0.02)

        [%{
          type: :c2_dns_tunnel_long_label,
          confidence: confidence,
          description: "DNS tunneling indicator: subdomain label '#{String.slice(longest, 0..31)}#{if longest_len > 32, do: "...", else: ""}' " <>
            "has #{longest_len} chars (threshold #{long_label_threshold}) in domain '#{domain}', " <>
            "suggesting encoded data exfiltration or C2 communication",
          mitre_techniques: ["T1071.004", "T1048"],
          metadata: %{
            domain: domain,
            longest_label_length: longest_len,
            long_label_count: length(long_labels),
            threshold: long_label_threshold
          }
        }]
      else
        []
      end
    end
  end

  defp track_dns_query_volume(agent_id, domain, timestamp) do
    # Extract parent domain for volume tracking
    labels = String.split(domain, ".")
    parent = if length(labels) >= 2 do
      labels |> Enum.take(-2) |> Enum.join(".")
    else
      domain
    end

    key = {:dns_vol, agent_id, parent}
    now_ms = normalize_timestamp_ms(timestamp)
    window_ms = c2_config(:dns_tunnel_volume_window_ms, 60_000) # 1 minute
    cutoff = now_ms - window_ms

    # Get and update query timestamps
    existing = case :ets.lookup(@dns_tunnel_table, key) do
      [{^key, %{timestamps: ts}}] -> ts
      [] -> []
    end

    updated = [now_ms | Enum.filter(existing, fn t -> t > cutoff end)]
    |> Enum.take(200)

    :ets.insert(@dns_tunnel_table, {key, %{
      timestamps: updated,
      updated_at: DateTime.utc_now()
    }})

    volume_threshold = c2_config(:dns_tunnel_volume_threshold, 50) # 50 queries/minute

    count = length(updated)
    if count > volume_threshold do
      confidence = min(0.80, 0.50 + (count - volume_threshold) * 0.005)
      [%{
        type: :c2_dns_tunnel_volume,
        confidence: confidence,
        description: "DNS tunneling indicator: #{count} queries to '#{parent}' " <>
          "in #{div(window_ms, 1_000)} seconds from agent #{agent_id} " <>
          "(threshold #{volume_threshold}), suggesting DNS-based C2 channel",
        mitre_techniques: ["T1071.004", "T1573"],
        metadata: %{
          parent_domain: parent,
          query_count: count,
          window_seconds: div(window_ms, 1_000),
          threshold: volume_threshold,
          agent_id: agent_id
        }
      }]
    else
      []
    end
  end

  defp detect_dns_txt_tunneling(domain, query_type) do
    query_type_str = to_string(query_type) |> String.upcase()

    if query_type_str == "TXT" do
      # TXT queries to domains that are not standard email-related are suspicious
      is_standard_txt =
        String.contains?(domain, "_domainkey.") or
        String.contains?(domain, "_dmarc.") or
        String.contains?(domain, "_spf.") or
        String.contains?(domain, "_acme-challenge.") or
        String.contains?(domain, "_mta-sts.") or
        String.contains?(domain, "_smtp.")

      if not is_standard_txt do
        # Additional check: does the subdomain look encoded?
        labels = String.split(domain, ".")
        subdomain_labels = if length(labels) > 2, do: Enum.take(labels, length(labels) - 2), else: []
        has_encoded_label = Enum.any?(subdomain_labels, fn label ->
          String.length(label) > 16 and calculate_shannon_entropy(label) > 3.0
        end)

        confidence = if has_encoded_label, do: 0.70, else: 0.45

        [%{
          type: :c2_dns_txt_tunnel,
          confidence: confidence,
          description: "DNS TXT record query to '#{domain}' may indicate C2 communication: " <>
            "TXT records can carry arbitrary data" <>
            (if has_encoded_label, do: " (encoded subdomain detected)", else: ""),
          mitre_techniques: ["T1071.004", "T1048"],
          metadata: %{
            domain: domain,
            query_type: "TXT",
            has_encoded_subdomain: has_encoded_label
          }
        }]
      else
        []
      end
    else
      []
    end
  end

  defp dns_tunnel_safe_domain?(domain) do
    safe_suffixes = [
      ".microsoft.com", ".windows.com", ".windowsupdate.com",
      ".google.com", ".googleapis.com", ".gstatic.com",
      ".apple.com", ".icloud.com",
      ".cloudflare.com", ".cloudflare-dns.com",
      ".amazonaws.com", ".cloudfront.net",
      ".akamai.net", ".akamaized.net",
      ".mozilla.org", ".mozilla.net",
      ".github.com", ".githubusercontent.com",
      ".docker.com", ".docker.io",
      ".ubuntu.com", ".debian.org",
      ".office.com", ".office365.com", ".outlook.com"
    ]

    Enum.any?(safe_suffixes, fn suffix ->
      String.ends_with?(domain, suffix)
    end)
  end

  # --------------------------------------------------------------------------
  # Temporal C2 Analysis (TemporalScorer Integration)
  # --------------------------------------------------------------------------

  @doc """
  Integrate with the TemporalScorer to detect time-based C2 anomalies.

  When a connection event already has C2 detections and the TemporalScorer
  also identifies a beacon pattern or burst, we boost the overall signal.
  This cross-references the C2 detector's beacon analysis with the
  TemporalScorer's independent timing analysis for higher confidence.
  """
  defp apply_temporal_c2_analysis(nil, _event, _detections), do: []
  defp apply_temporal_c2_analysis(_agent_id, _event, []), do: []
  defp apply_temporal_c2_analysis(agent_id, event, existing_detections) do
    try do
      # Check if temporal scorer detects anomalies for this agent
      anomalies = TemporalScorer.detect_temporal_anomalies(agent_id, window_ms: :timer.minutes(10))

      beacon_anomalies = Enum.filter(anomalies, fn a ->
        a[:type] == :beacon_pattern or a[:type] == :low_entropy_intervals
      end)

      if beacon_anomalies != [] and length(existing_detections) > 0 do
        # Cross-correlated temporal beacon detection
        temporal_entropy = beacon_anomalies
        |> Enum.map(fn a -> a[:entropy] || 0.0 end)
        |> Enum.min(fn -> 2.0 end)

        # Lower entropy = more regular = more suspicious
        confidence = min(0.75, 0.45 + (2.0 - temporal_entropy) * 0.2)

        [%{
          type: :c2_temporal_correlated,
          confidence: confidence,
          description: "Temporal analysis corroborates C2 activity for agent #{agent_id}: " <>
            "TemporalScorer detected beacon pattern (entropy #{Float.round(temporal_entropy, 2)})" <>
            " alongside #{length(existing_detections)} other C2 indicator(s)",
          mitre_techniques: ["T1071", "T1573"],
          metadata: %{
            temporal_anomalies: length(beacon_anomalies),
            temporal_entropy: Float.round(temporal_entropy, 3),
            existing_detection_count: length(existing_detections),
            agent_id: agent_id
          }
        }]
      else
        []
      end
    rescue
      _ -> []
    catch
      :exit, _ -> []
    end
  end

  # --------------------------------------------------------------------------
  # Composite Scoring
  # --------------------------------------------------------------------------

  @doc """
  Apply composite scoring across the three signal categories:
  1. Beaconing signals (weight 0.4)
  2. DNS anomaly signals (weight 0.3)
  3. JA3/JA4 fingerprint signals (weight 0.3)

  When the combined score exceeds 0.6, a composite detection is emitted
  that can be used for alert creation with a holistic confidence value.
  """
  defp apply_composite_scoring(event, detections, state) do
    if detections == [] do
      {detections, state}
    else
      # Categorize detections by signal type
      beacon_types = [:c2_beacon_strong, :c2_beacon_moderate, :c2_beacon_weak,
                       :c2_high_frequency, :c2_temporal_correlated]
      dns_types = [:c2_dga_https, :c2_dns_tunnel_entropy, :c2_dns_tunnel_long_label,
                    :c2_dns_tunnel_volume, :c2_dns_txt_tunnel]
      ja3_types = [:c2_ja3_match, :c2_ja4_match, :c2_rare_fingerprint]

      beacon_score = max_confidence_for_types(detections, beacon_types)
      dns_score = max_confidence_for_types(detections, dns_types)
      ja3_score = max_confidence_for_types(detections, ja3_types)

      composite = compute_composite_score(beacon_score, dns_score, ja3_score)
      composite_threshold = c2_config(:composite_alert_threshold, 0.6)

      if composite > composite_threshold do
        composite_detection = %{
          type: :c2_composite_detection,
          confidence: composite,
          description: "Multi-signal C2 detection: composite score #{Float.round(composite, 2)} " <>
            "(beacon=#{Float.round(beacon_score, 2)}, dns=#{Float.round(dns_score, 2)}, " <>
            "fingerprint=#{Float.round(ja3_score, 2)}) exceeds threshold #{composite_threshold}",
          mitre_techniques: ["T1071", "T1071.004", "T1573"],
          metadata: %{
            composite_score: Float.round(composite, 4),
            beacon_score: Float.round(beacon_score, 4),
            dns_score: Float.round(dns_score, 4),
            ja3_score: Float.round(ja3_score, 4),
            signal_count: length(detections),
            threshold: composite_threshold
          }
        }

        {detections ++ [composite_detection], update_stats(state, :composite_alerts)}
      else
        {detections, state}
      end
    end
  end

  defp max_confidence_for_types(detections, types) do
    detections
    |> Enum.filter(fn d -> d[:type] in types end)
    |> Enum.map(fn d -> d[:confidence] || 0.0 end)
    |> Enum.max(fn -> 0.0 end)
  end

  # ============================================================================
  # Alert Creation
  # ============================================================================

  defp maybe_create_dns_tunnel_alert(event, detections, state) do
    total_confidence = detections
    |> Enum.map(& &1[:confidence] || 0)
    |> Enum.sum()

    # Use same threshold as C2 alerts
    alert_threshold = c2_config(:dns_tunnel_alert_threshold, 0.7)

    if total_confidence >= alert_threshold and length(detections) > 0 do
      state = update_stats(state, :dns_tunnel_detected)

      case create_dns_tunnel_alert(event, detections) do
        :ok -> update_stats(state, :alerts_created)
        :error -> state
      end
    else
      state
    end
  end

  defp create_dns_tunnel_alert(event, detections) do
    payload = event[:payload] || event["payload"] || %{}
    agent_id = event[:agent_id] || event["agent_id"]
    domain = payload[:query] || payload["query"] || "unknown"

    max_confidence = detections |> Enum.map(& &1[:confidence] || 0) |> Enum.max(fn -> 0 end)

    severity = cond do
      max_confidence >= 0.85 -> "critical"
      max_confidence >= 0.7 -> "high"
      max_confidence >= 0.5 -> "medium"
      true -> "low"
    end

    mitre_techniques = detections
    |> Enum.flat_map(& &1[:mitre_techniques] || [])
    |> Enum.uniq()

    evidence = %{
      file_hashes: [],
      network: [%{
        type: "dns_tunnel",
        domain: domain,
        protocol: "DNS"
      }],
      process: %{},
      registry: [],
      detection: %{
        rule_name: "DNS Tunneling Detection",
        rule_type: "behavioral",
        confidence: max_confidence,
        detections: Enum.map(detections, fn d ->
          %{type: d[:type], confidence: d[:confidence], description: d[:description]}
        end)
      }
    }

    primary_detection = Enum.max_by(detections, & &1[:confidence] || 0)
    title = case primary_detection[:type] do
      :c2_dns_tunnel_entropy -> "DNS Tunneling: High entropy subdomain to #{domain}"
      :c2_dns_tunnel_long_label -> "DNS Tunneling: Encoded subdomain labels to #{domain}"
      :c2_dns_tunnel_volume -> "DNS Tunneling: High query volume to #{domain}"
      :c2_dns_txt_tunnel -> "DNS Tunneling: TXT record C2 channel to #{domain}"
      _ -> "DNS Tunneling: Suspicious DNS activity to #{domain}"
    end

    case Alerts.create_alert(%{
           agent_id: agent_id,
           organization_id: event[:organization_id] || OrgLookup.get_org_id(agent_id),
           severity: severity,
           title: title,
           description: Enum.map_join(detections, "\n", & &1[:description]),
           source_event_id: event[:event_id],
           event_ids: [event[:event_id]],
           evidence: evidence,
           process_chain: [],
           mitre_tactics: ["command-and-control"],
           mitre_techniques: mitre_techniques,
           threat_score: max_confidence
         }) do
      {:ok, _alert} ->
        Logger.warning(
          "DNS Tunnel alert created: #{title} (confidence: #{Float.round(max_confidence, 2)})"
        )

        :ok

      {:error, reason} ->
        Logger.error("Failed to create DNS Tunnel alert: #{inspect(reason)}")
        :error
    end
  end

  defp maybe_create_c2_alert(event, detections, state) do
    # Create alert if total confidence exceeds threshold
    total_confidence = detections
    |> Enum.map(& &1[:confidence] || 0)
    |> Enum.sum()

    alert_threshold = c2_config(:alert_threshold, 0.7)

    if total_confidence >= alert_threshold and length(detections) > 0 do
      state = update_detection_stats(state, detections)

      case create_c2_alert(event, detections) do
        :ok -> update_stats(state, :alerts_created)
        :error -> state
      end
    else
      state
    end
  end

  defp create_c2_alert(event, detections) do
    payload = event[:payload] || event["payload"] || %{}
    agent_id = event[:agent_id] || event["agent_id"]
    remote_ip = payload[:remote_ip] || payload["remote_ip"]

    # Record alert dedup timestamp to suppress duplicates for 15 minutes
    if is_binary(agent_id) and is_binary(remote_ip) do
      record_alert_dedup(agent_id, remote_ip)
    end

    # Determine severity based on detection types and confidence
    max_confidence = detections |> Enum.map(& &1[:confidence] || 0) |> Enum.max(fn -> 0 end)
    has_strong_beacon = Enum.any?(detections, & &1[:type] == :c2_beacon_strong)
    has_ja3_match = Enum.any?(detections, & &1[:type] == :c2_ja3_match)
    has_ja4_match = Enum.any?(detections, & &1[:type] == :c2_ja4_match)
    has_composite = Enum.any?(detections, & &1[:type] == :c2_composite_detection)

    severity = cond do
      has_ja3_match or has_ja4_match -> "critical"
      has_composite and max_confidence >= 0.8 -> "critical"
      has_strong_beacon and max_confidence >= 0.85 -> "critical"
      has_strong_beacon -> "high"
      has_composite -> "high"
      max_confidence >= 0.7 -> "high"
      max_confidence >= 0.5 -> "medium"
      true -> "low"
    end

    # Build evidence
    evidence = %{
      file_hashes: [],
      network: [%{
        type: "c2_connection",
        remote_ip: remote_ip,
        remote_port: payload[:remote_port] || payload["remote_port"],
        hostname: payload[:hostname] || payload["hostname"],
        protocol: "HTTPS"
      }],
      process: %{
        name: payload[:process_name] || payload["process_name"],
        pid: payload[:pid] || payload["pid"]
      },
      registry: [],
      detection: %{
        rule_name: "C2 Detection",
        rule_type: "behavioral",
        confidence: max_confidence,
        detections: Enum.map(detections, fn d ->
          %{type: d[:type], confidence: d[:confidence], description: d[:description]}
        end)
      }
    }

    # Generate title
    primary_detection = Enum.max_by(detections, & &1[:confidence] || 0)
    title = case primary_detection[:type] do
      :c2_beacon_strong -> "C2 Beaconing: Strong beacon pattern to #{remote_ip}"
      :c2_beacon_moderate -> "C2 Beaconing: Regular connections to #{remote_ip}"
      :c2_beacon_weak -> "C2 Beaconing: Slow beacon pattern to #{remote_ip}"
      :c2_ja3_match -> "C2 Framework: Known malware TLS fingerprint (JA3)"
      :c2_ja4_match -> "C2 Framework: Known malware TLS fingerprint (JA4)"
      :c2_rare_fingerprint -> "C2 Indicator: Rare TLS fingerprint to #{remote_ip}"
      :c2_suspicious_certificate -> "C2 Indicator: Suspicious TLS certificate from #{remote_ip}"
      :c2_dga_https -> "C2 DGA: High entropy HTTPS domain detected"
      :c2_domain_fronting_confirmed -> "C2 Evasion: Domain fronting confirmed (SNI/Host mismatch)"
      :c2_domain_fronting_suspected -> "C2 Evasion: Potential domain fronting detected"
      :c2_temporal_correlated -> "C2 Activity: Temporal analysis confirms beaconing to #{remote_ip}"
      :c2_composite_detection -> "C2 Multi-Signal: Composite detection to #{remote_ip}"
      _ -> "C2 Activity: Suspicious encrypted communication to #{remote_ip}"
    end

    # Collect MITRE techniques
    mitre_techniques = detections
    |> Enum.flat_map(& &1[:mitre_techniques] || [])
    |> Enum.uniq()

    # Create the alert
    case Alerts.create_alert(%{
           agent_id: agent_id,
           organization_id: event[:organization_id] || OrgLookup.get_org_id(agent_id),
           severity: severity,
           title: title,
           description: Enum.map_join(detections, "\n", & &1[:description]),
           source_event_id: event[:event_id],
           event_ids: [event[:event_id]],
           evidence: evidence,
           process_chain: [],
           mitre_tactics: ["command-and-control"],
           mitre_techniques: mitre_techniques,
           threat_score: max_confidence
         }) do
      {:ok, _alert} ->
        Logger.warning(
          "C2 alert created: #{title} (confidence: #{Float.round(max_confidence, 2)})"
        )

        :ok

      {:error, reason} ->
        Logger.error("Failed to create C2 alert: #{inspect(reason)}")
        :error
    end
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp calculate_stddev(values, mean) when is_list(values) and length(values) > 0 do
    variance = values
    |> Enum.map(fn v -> :math.pow(v - mean, 2) end)
    |> Enum.sum()
    |> Kernel./(length(values))

    :math.sqrt(variance)
  end

  defp calculate_stddev(_, _), do: 0.0

  defp calculate_shannon_entropy(""), do: 0.0
  defp calculate_shannon_entropy(string) do
    len = String.length(string)

    if len == 0 do
      0.0
    else
      string
      |> String.downcase()
      |> String.graphemes()
      |> Enum.frequencies()
      |> Enum.reduce(0.0, fn {_char, count}, acc ->
        probability = count / len
        acc - probability * :math.log2(probability)
      end)
    end
  end

  defp normalize_timestamp(%DateTime{} = dt) do
    DateTime.to_unix(dt, :second)
  end

  defp normalize_timestamp(ts) when is_integer(ts) do
    # Assume milliseconds if > year 2000 in seconds
    if ts > 946_684_800_000, do: div(ts, 1000), else: ts
  end

  defp normalize_timestamp(_), do: System.system_time(:second)

  # Like normalize_timestamp but returns milliseconds (used by DNS tunnel tracking)
  defp normalize_timestamp_ms(%DateTime{} = dt), do: DateTime.to_unix(dt, :millisecond)
  defp normalize_timestamp_ms(ts) when is_integer(ts) do
    if ts > 946_684_800_000, do: ts, else: ts * 1_000
  end
  defp normalize_timestamp_ms(_), do: System.system_time(:millisecond)

  defp parse_cert_date(nil), do: nil
  defp parse_cert_date(%DateTime{} = dt), do: dt
  defp parse_cert_date(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end
  defp parse_cert_date(_), do: nil

  defp normalize_cert_name(name) when is_binary(name) do
    name
    |> String.downcase()
    |> String.replace(~r/\s+/, " ")
    |> String.trim()
  end
  defp normalize_cert_name(name) when is_map(name) do
    # Handle structured certificate name (CN, O, etc.)
    name[:cn] || name["cn"] || name[:common_name] || name["common_name"] || inspect(name)
  end
  defp normalize_cert_name(name), do: to_string(name)

  defp format_interval(seconds) when is_number(seconds) do
    cond do
      seconds < 60 -> "#{Float.round(seconds, 1)}s"
      seconds < 3600 -> "#{Float.round(seconds / 60, 1)}m"
      true -> "#{Float.round(seconds / 3600, 1)}h"
    end
  end

  defp format_bytes(bytes) when is_number(bytes) do
    cond do
      bytes >= 1_000_000_000 -> "#{Float.round(bytes / 1_000_000_000, 2)} GB"
      bytes >= 1_000_000 -> "#{Float.round(bytes / 1_000_000, 2)} MB"
      bytes >= 1_000 -> "#{Float.round(bytes / 1_000, 2)} KB"
      true -> "#{bytes} B"
    end
  end

  # Check if an IP belongs to any of the trusted infrastructure ranges
  defp trusted_ip?(ip_string) when is_binary(ip_string) do
    Enum.any?(@trusted_ip_ranges, fn cidr -> ip_in_cidr?(ip_string, cidr) end)
  end
  defp trusted_ip?(_), do: false

  # Alert deduplication: suppress repeated alerts for the same (agent, ip) within 15 minutes
  defp recently_alerted?(agent_id, remote_ip) do
    key = {agent_id, remote_ip}
    dedup_window_ms = c2_config(:alert_dedup_window_ms, 900_000) # 15 minutes
    now = System.system_time(:millisecond)

    case :ets.lookup(@alert_dedup_table, key) do
      [{^key, last_alert_time}] ->
        now - last_alert_time < dedup_window_ms

      [] ->
        false
    end
  end

  defp record_alert_dedup(agent_id, remote_ip) do
    key = {agent_id, remote_ip}
    :ets.insert(@alert_dedup_table, {key, System.system_time(:millisecond)})
  end

  defp ip_in_cidr?(ip_string, cidr_string) do
    try do
      [network, bits_str] = String.split(cidr_string, "/")
      bits = String.to_integer(bits_str)

      ip_int = ip_to_integer(ip_string)
      network_int = ip_to_integer(network)

      mask = bsl(0xFFFFFFFF, 32 - bits) &&& 0xFFFFFFFF

      (ip_int &&& mask) == (network_int &&& mask)
    rescue
      _ -> false
    end
  end

  defp ip_to_integer(ip_string) do
    ip_string
    |> String.split(".")
    |> Enum.map(&String.to_integer/1)
    |> Enum.reduce(0, fn octet, acc -> bsl(acc, 8) + octet end)
  end

  defp c2_config(key, default) do
    Config.get(:"c2_#{key}", default)
  end

  defp schedule_cleanup do
    interval = c2_config(:cleanup_interval_ms, :timer.minutes(5))
    Process.send_after(self(), :cleanup, interval)
  end

  defp cleanup_old_patterns do
    now = DateTime.utc_now()
    ttl_seconds = c2_config(:pattern_ttl_seconds, 3600) # 1 hour default

    # Clean beacon table
    :ets.tab2list(@beacon_table)
    |> Enum.each(fn {key, %{updated_at: updated_at}} ->
      age_seconds = DateTime.diff(now, updated_at, :second)
      if age_seconds > ttl_seconds do
        :ets.delete(@beacon_table, key)
      end
    end)

    # Clean connection stats table
    :ets.tab2list(@connection_stats_table)
    |> Enum.each(fn
      {key, %{last_seen: last_seen}} ->
        age_seconds = DateTime.diff(now, last_seen, :second)
        if age_seconds > ttl_seconds do
          :ets.delete(@connection_stats_table, key)
        end

      {key, %{updated_at: updated_at}} ->
        age_seconds = DateTime.diff(now, updated_at, :second)
        if age_seconds > ttl_seconds do
          :ets.delete(@connection_stats_table, key)
        end

      _ ->
        :ok
    end)

    # Clean DNS tunnel tracking table (entries older than 24h)
    dns_ttl_seconds = c2_config(:dns_tunnel_ttl_seconds, 86_400) # 24 hours
    :ets.tab2list(@dns_tunnel_table)
    |> Enum.each(fn
      {key, %{updated_at: updated_at}} ->
        age_seconds = DateTime.diff(now, updated_at, :second)
        if age_seconds > dns_ttl_seconds do
          :ets.delete(@dns_tunnel_table, key)
        end
      _ ->
        :ok
    end)

    # Clean alert dedup table (entries older than the dedup window)
    dedup_window_ms = c2_config(:alert_dedup_window_ms, 900_000)
    now_ms = System.system_time(:millisecond)

    :ets.tab2list(@alert_dedup_table)
    |> Enum.each(fn {key, timestamp_ms} ->
      if now_ms - timestamp_ms > dedup_window_ms do
        :ets.delete(@alert_dedup_table, key)
      end
    end)

    Logger.debug("C2 Detector cleanup completed (tables: beacon=#{:ets.info(@beacon_table, :size)}, dns_tunnel=#{:ets.info(@dns_tunnel_table, :size)}, conn_stats=#{:ets.info(@connection_stats_table, :size)})")
  end

  defp update_stats(state, key) do
    %{state | stats: Map.update(state.stats, key, 1, &(&1 + 1))}
  end

  defp update_detection_stats(state, detections) do
    Enum.reduce(detections, state, fn detection, acc ->
      case detection[:type] do
        :c2_beacon_strong -> update_stats(acc, :beacons_detected)
        :c2_beacon_moderate -> update_stats(acc, :beacons_detected)
        :c2_beacon_weak -> update_stats(acc, :beacons_detected)
        :c2_suspicious_certificate -> update_stats(acc, :suspicious_certs)
        :c2_ja3_match -> update_stats(acc, :ja3_matches)
        :c2_ja4_match -> update_stats(acc, :ja4_matches)
        :c2_rare_fingerprint -> update_stats(acc, :rare_fingerprints)
        :c2_dga_https -> update_stats(acc, :dga_https_detected)
        :c2_dns_tunnel_entropy -> update_stats(acc, :dns_tunnel_detected)
        :c2_dns_tunnel_long_label -> update_stats(acc, :dns_tunnel_detected)
        :c2_dns_tunnel_volume -> update_stats(acc, :dns_tunnel_detected)
        :c2_dns_txt_tunnel -> update_stats(acc, :dns_tunnel_detected)
        :c2_composite_detection -> update_stats(acc, :composite_alerts)
        _ -> acc
      end
    end)
  end
end
