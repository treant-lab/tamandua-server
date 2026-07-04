defmodule TamanduaServer.NDR.EncryptedTraffic do
  @moduledoc """
  NDR Encrypted Traffic Analysis Module.

  Analyzes encrypted traffic without decryption using metadata and behavioral patterns:

  1. **JA3/JA3S Fingerprinting**: TLS client and server fingerprint analysis
     against known malware and C2 framework signatures

  2. **TLS Certificate Analysis**: Certificate validity, issuer reputation,
     self-signed detection, and unusual certificate patterns

  3. **Encrypted C2 Detection**: Behavioral patterns indicative of C2
     communication over encrypted channels

  4. **Certificate Transparency Monitoring**: Detection of newly issued
     certificates for monitored domains

  5. **TLS Version Analysis**: Detection of outdated or suspicious TLS versions

  This module integrates with the existing C2Detector for comprehensive
  encrypted traffic analysis.

  MITRE ATT&CK Coverage:
  - T1071.001: Web Protocols (HTTPS C2)
  - T1573: Encrypted Channel
  - T1573.001: Symmetric Cryptography
  - T1573.002: Asymmetric Cryptography
  - T1090.004: Domain Fronting
  """

  use GenServer
  import Ecto.Query, warn: false
  require Logger

  alias TamanduaServer.Alerts
  alias TamanduaServer.Agents.OrgLookup
  alias TamanduaServer.Detection.C2Detector
  alias TamanduaServer.NDR.EventNormalizer
  alias TamanduaServer.Repo

  # ETS tables
  @ja3_fingerprints_table :ndr_ja3_fingerprints
  @certificate_cache_table :ndr_certificate_cache
  @tls_sessions_table :ndr_tls_sessions
  @ja3_stats_table :ndr_ja3_stats

  # Known malicious JA3 fingerprints
  @known_malicious_ja3 %{
    # Cobalt Strike
    "72a589da586844d7f0818ce684948eea" => %{name: "Cobalt Strike", type: :c2},
    "a0e9f5d64349fb13191bc781f81f42e1" => %{name: "Cobalt Strike HTTPS", type: :c2},
    "6734f37431670b3ab4292b8f60f29984" => %{name: "Cobalt Strike Beacon", type: :c2},
    # Meterpreter
    "5d79f8a9e9d2c7e2b6a7f5e4d3c2b1a0" => %{name: "Meterpreter", type: :c2},
    "4d7a28d6f2916cfdee36259c0bcbb36a" => %{name: "Meterpreter Reverse HTTPS", type: :c2},
    # Empire
    "3b5074b1b5d032e5620f69f9f700ff0e" => %{name: "Empire", type: :c2},
    # PoshC2
    "b32309a26951912be7dba376398abc3b" => %{name: "PoshC2", type: :c2},
    # Sliver
    "7dabc2e90200e8b7c1e95c4b88ca6ef6" => %{name: "Sliver", type: :c2},
    # Generic Suspicious
    "bd0bf25947d4a37404f0424edf4db9ad" => %{name: "Generic C2", type: :suspicious},
    # Malware families
    "e7d705a3286e19ea42f587b344ee6865" => %{name: "Emotet", type: :malware},
    "769e39b10a2d8760ad2f91cc33ba4fd3" => %{name: "TrickBot", type: :malware}
  }

  # Suspicious certificate issuers (often abused for C2)
  @suspicious_issuers [
    "Let's Encrypt",
    "ZeroSSL",
    "Buypass",
    "SSL.com Free"
  ]

  # Suspicious TLDs often used in C2
  @suspicious_tlds [".xyz", ".top", ".buzz", ".club", ".gq", ".cf", ".ga", ".ml", ".tk", ".work", ".click"]

  defstruct [
    :stats,
    :last_cleanup
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Analyze an encrypted connection event.
  """
  @spec analyze_event(map()) :: [map()]
  def analyze_event(event) do
    GenServer.call(__MODULE__, {:analyze, event})
  end

  @doc """
  Check a JA3 fingerprint against known signatures.
  """
  @spec check_ja3(String.t()) :: {:ok, :clean} | {:match, map()}
  def check_ja3(ja3_hash) do
    GenServer.call(__MODULE__, {:check_ja3, ja3_hash})
  end

  @doc """
  Get JA3 fingerprint statistics.
  """
  @spec get_ja3_stats(keyword()) :: [map()]
  def get_ja3_stats(opts \\ []) do
    GenServer.call(__MODULE__, {:get_ja3_stats, opts})
  end

  @doc """
  Get certificate analysis results.
  """
  @spec get_certificate_analysis(keyword()) :: [map()]
  def get_certificate_analysis(opts \\ []) do
    GenServer.call(__MODULE__, {:get_certificate_analysis, opts})
  end

  @doc """
  Get TLS session information.
  """
  @spec get_tls_sessions(keyword()) :: [map()]
  def get_tls_sessions(opts \\ []) do
    GenServer.call(__MODULE__, {:get_tls_sessions, opts})
  end

  @doc """
  Add a custom JA3 fingerprint to the detection database.
  """
  @spec add_ja3_signature(String.t(), map()) :: :ok
  def add_ja3_signature(ja3_hash, metadata) do
    GenServer.cast(__MODULE__, {:add_ja3, ja3_hash, metadata})
  end

  @doc """
  Get overall statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    :ets.new(@ja3_fingerprints_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@certificate_cache_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@tls_sessions_table, [:named_table, :bag, :public, read_concurrency: true])
    :ets.new(@ja3_stats_table, [:named_table, :set, :public, read_concurrency: true])

    # Pre-populate known malicious JA3 fingerprints
    Enum.each(@known_malicious_ja3, fn {hash, info} ->
      :ets.insert(@ja3_fingerprints_table, {hash, Map.put(info, :source, :built_in)})
    end)

    schedule_cleanup()

    state = %__MODULE__{
      stats: %{
        events_analyzed: 0,
        ja3_matches: 0,
        suspicious_certs: 0,
        self_signed_certs: 0,
        alerts_created: 0,
        unique_ja3_seen: 0
      },
      last_cleanup: DateTime.utc_now()
    }

    Logger.info("NDR Encrypted Traffic Analyzer started with #{map_size(@known_malicious_ja3)} known JA3 signatures")
    {:ok, state}
  end

  @impl true
  def handle_call({:analyze, event}, _from, state) do
    {detections, new_state} = do_analyze(event, state)
    {:reply, detections, new_state}
  end

  @impl true
  def handle_call({:check_ja3, ja3_hash}, _from, state) do
    result = do_check_ja3(ja3_hash)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_ja3_stats, opts}, _from, state) do
    stats = fetch_ja3_stats(opts)
    {:reply, stats, state}
  end

  @impl true
  def handle_call({:get_certificate_analysis, opts}, _from, state) do
    analysis = fetch_certificate_analysis(opts)
    {:reply, analysis, state}
  end

  @impl true
  def handle_call({:get_tls_sessions, opts}, _from, state) do
    sessions = fetch_tls_sessions(opts)
    {:reply, sessions, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_cast({:add_ja3, ja3_hash, metadata}, state) do
    info = Map.merge(metadata, %{source: :custom, added_at: DateTime.utc_now()})
    :ets.insert(@ja3_fingerprints_table, {ja3_hash, info})
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_old_data()
    schedule_cleanup()
    {:noreply, %{state | last_cleanup: DateTime.utc_now()}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Core Analysis Logic
  # ============================================================================

  defp do_analyze(event, state) do
    event = EventNormalizer.normalize_event(event)
    payload = event[:payload] || event["payload"] || %{}
    agent_id = event[:agent_id] || event["agent_id"]
    organization_id = event[:organization_id] || event["organization_id"] || OrgLookup.get_org_id(agent_id)
    remote_ip = payload[:remote_ip] || payload["remote_ip"]
    remote_port = payload[:remote_port] || payload["remote_port"]

    # Extract TLS metadata
    ja3_hash = payload[:ja3] || payload["ja3"]
    ja3s_hash = payload[:ja3s] || payload["ja3s"]
    sni = payload[:sni] || payload["sni"] || payload[:tls_sni] || payload["tls_sni"] ||
      payload[:domain] || payload["domain"] || payload[:hostname] || payload["hostname"]
    tls_version = payload[:tls_version] || payload["tls_version"]
    certificate = payload[:certificate] || payload["certificate"]
    certificate_risk = payload[:certificate_risk] || payload["certificate_risk"]
    encrypted_dns_transport = payload[:encrypted_dns_transport] || payload["encrypted_dns_transport"]
    alpn = payload[:alpn] || payload["alpn"]
    alpn_protocols = payload[:alpn_protocols] || payload["alpn_protocols"] || []
    quic_version = payload[:quic_version] || payload["quic_version"]
    http_version = payload[:http_version] || payload["http_version"]
    ech_present = payload[:ech_present] || payload["ech_present"]

    detections = []
    new_state = update_stats(state, :events_analyzed)

    # Record TLS session only when the event carries encrypted/TLS metadata.
    if tls_session_event?(payload) do
      record_tls_session(agent_id, %{
        organization_id: organization_id,
        event_id: EventNormalizer.source_event_id(event),
        local_ip: payload[:local_ip] || payload["local_ip"],
        local_port: payload[:local_port] || payload["local_port"],
        remote_ip: remote_ip,
        remote_port: remote_port,
        domain: payload[:domain] || payload["domain"] || sni,
        ja3: ja3_hash,
        ja3s: ja3s_hash,
        sni: sni,
        tls_version: tls_version,
        alpn: alpn,
        alpn_protocols: alpn_protocols,
        quic_version: quic_version,
        http_version: http_version,
        ech_present: ech_present,
        encrypted_dns_transport: encrypted_dns_transport,
        certificate_fingerprint: EventNormalizer.certificate_fingerprint(certificate),
        certificate: certificate,
        certificate_risk: certificate_risk,
        process: EventNormalizer.process_context(event),
        enrichment: session_enrichment(event, payload),
        timestamp: DateTime.utc_now()
      }, event)
    end

    # 1. JA3 fingerprint analysis
    {ja3_detections, new_state} = analyze_ja3(event, ja3_hash, new_state)
    detections = detections ++ ja3_detections

    # 2. JA3S (server) fingerprint analysis
    {ja3s_detections, new_state} = analyze_ja3s(event, ja3s_hash, new_state)
    detections = detections ++ ja3s_detections

    # 3. Certificate analysis
    {cert_detections, new_state} = if certificate do
      analyze_certificate(event, certificate, new_state)
    else
      {[], new_state}
    end
    detections = detections ++ cert_detections

    # 4. SNI analysis
    sni_detections = analyze_sni(event, sni)
    detections = detections ++ sni_detections

    # 5. TLS version analysis
    tls_detections = analyze_tls_version(event, tls_version)
    detections = detections ++ tls_detections

    # 6. Certificate risk emitted by endpoint/network sensor
    certificate_risk_detections = analyze_certificate_risk(event, certificate_risk)
    detections = detections ++ certificate_risk_detections

    # 7. Encrypted DNS transport analysis
    encrypted_dns_detections = analyze_encrypted_dns(event, encrypted_dns_transport)
    detections = detections ++ encrypted_dns_detections

    # 8. Delegate to C2Detector for behavioral analysis
    c2_detections = try do
      C2Detector.analyze_connection(event)
    rescue
      _ -> []
    catch
      _, _ -> []
    end
    detections = detections ++ c2_detections

    # Create alerts for significant detections
    final_state = Enum.reduce(detections, new_state, fn detection, acc ->
      if detection.confidence >= 0.6 do
        case create_encrypted_traffic_alert(event, detection) do
          :ok -> update_stats(acc, :alerts_created)
          :error -> acc
        end
      else
        acc
      end
    end)

    {detections, final_state}
  end

  # --------------------------------------------------------------------------
  # JA3 Analysis
  # --------------------------------------------------------------------------

  defp analyze_ja3(_event, nil, state), do: {[], state}
  defp analyze_ja3(event, ja3_hash, state) do
    # Track JA3 occurrence
    track_ja3_occurrence(ja3_hash, event)

    payload = event[:payload] || event["payload"] || %{}
    remote_ip = payload[:remote_ip] || payload["remote_ip"]

    case do_check_ja3(ja3_hash) do
      {:match, info} ->
        confidence = case info[:type] do
          :c2 -> 0.9
          :malware -> 0.85
          :suspicious -> 0.7
          _ -> 0.6
        end

        detection = %{
          type: :ja3_known_malicious,
          confidence: confidence,
          description: "JA3 fingerprint matches known malware: #{info[:name]} (#{ja3_hash})",
          mitre_techniques: ["T1071.001", "T1573"],
          metadata: %{
            ja3_hash: ja3_hash,
            matched_signature: info[:name],
            signature_type: info[:type],
            remote_ip: remote_ip
          }
        }

        {[detection], update_stats(state, :ja3_matches)}

      {:ok, :clean} ->
        # Check for unusual JA3 patterns even if not in database
        {check_unusual_ja3(event, ja3_hash), state}
    end
  end

  defp analyze_ja3s(_event, nil, state), do: {[], state}
  defp analyze_ja3s(event, ja3s_hash, state) do
    payload = event[:payload] || event["payload"] || %{}
    remote_ip = payload[:remote_ip] || payload["remote_ip"]

    # JA3S fingerprints for known C2 servers
    known_c2_ja3s = [
      "ae4edc6faf64d08308082ad26be60767",  # Common Cobalt Strike server
      "fd4bc6cea4877646ccd62f0792ec0b62"   # Generic C2 server
    ]

    if ja3s_hash in known_c2_ja3s do
      detection = %{
        type: :ja3s_known_c2_server,
        confidence: 0.85,
        description: "Server JA3S fingerprint matches known C2 infrastructure: #{ja3s_hash}",
        mitre_techniques: ["T1071.001", "T1573"],
        metadata: %{
          ja3s_hash: ja3s_hash,
          remote_ip: remote_ip
        }
      }

      {[detection], state}
    else
      {[], state}
    end
  end

  defp check_unusual_ja3(_event, ja3_hash) do
    # Calculate JA3 entropy - unusually high entropy might indicate evasion
    entropy = calculate_entropy(ja3_hash)

    if entropy > 4.0 do
      [%{
        type: :unusual_ja3_entropy,
        confidence: 0.4,
        description: "Unusual JA3 fingerprint entropy (#{Float.round(entropy, 2)})",
        mitre_techniques: ["T1573"],
        metadata: %{ja3_hash: ja3_hash, entropy: entropy}
      }]
    else
      []
    end
  end

  defp do_check_ja3(ja3_hash) do
    case :ets.lookup(@ja3_fingerprints_table, ja3_hash) do
      [{^ja3_hash, info}] -> {:match, info}
      [] -> {:ok, :clean}
    end
  end

  defp track_ja3_occurrence(ja3_hash, event) do
    payload = event[:payload] || event["payload"] || %{}
    agent_id = event[:agent_id] || event["agent_id"]
    organization_id = event[:organization_id] || event["organization_id"] || OrgLookup.get_org_id(agent_id)
    remote_ip = payload[:remote_ip] || payload["remote_ip"]
    now = DateTime.utc_now()

    case :ets.lookup(@ja3_stats_table, ja3_hash) do
      [{^ja3_hash, stats}] ->
        updated = %{stats |
          occurrence_count: stats.occurrence_count + 1,
          agents: MapSet.put(stats.agents, agent_id),
          destinations: MapSet.put(stats.destinations, remote_ip),
          last_seen: now
        }
        :ets.insert(@ja3_stats_table, {ja3_hash, updated})

      [] ->
        stats = %{
          ja3_hash: ja3_hash,
          occurrence_count: 1,
          agents: MapSet.new([agent_id]),
          destinations: MapSet.new([remote_ip]),
          first_seen: now,
          last_seen: now
        }
        :ets.insert(@ja3_stats_table, {ja3_hash, stats})
    end

    persist_ja3_stat(organization_id, agent_id, ja3_hash, payload, now)
  end

  # --------------------------------------------------------------------------
  # Certificate Analysis
  # --------------------------------------------------------------------------

  defp analyze_certificate(event, cert_info, state) when is_map(cert_info) do
    payload = event[:payload] || event["payload"] || %{}
    remote_ip = payload[:remote_ip] || payload["remote_ip"]

    detections = []
    new_state = state

    issuer = cert_info[:issuer] || cert_info["issuer"]
    subject = cert_info[:subject] || cert_info["subject"]
    not_before = parse_cert_date(cert_info[:not_before] || cert_info["not_before"])
    not_after = parse_cert_date(cert_info[:not_after] || cert_info["not_after"])
    san = cert_info[:san] || cert_info["san"] || []

    # Cache certificate
    cache_certificate(remote_ip, cert_info, event)

    # 1. Self-signed certificate detection
    {detections, new_state} = if is_self_signed?(issuer, subject) do
      detection = %{
        type: :self_signed_certificate,
        confidence: 0.7,
        description: "Self-signed certificate detected from #{remote_ip}",
        mitre_techniques: ["T1573.002"],
        metadata: %{
          subject: subject,
          remote_ip: remote_ip
        }
      }
      {[detection | detections], update_stats(new_state, :self_signed_certs)}
    else
      {detections, new_state}
    end

    # 2. Recently issued certificate (< 7 days)
    detections = if not_before do
      age_days = DateTime.diff(DateTime.utc_now(), not_before, :day)
      if age_days >= 0 and age_days < 7 do
        detection = %{
          type: :recently_issued_certificate,
          confidence: 0.5,
          description: "Recently issued certificate (#{age_days} days old) from #{remote_ip}",
          mitre_techniques: ["T1573.002"],
          metadata: %{
            age_days: age_days,
            not_before: not_before,
            issuer: issuer,
            remote_ip: remote_ip
          }
        }
        [detection | detections]
      else
        detections
      end
    else
      detections
    end

    # 3. Short validity period (< 30 days)
    detections = if not_before && not_after do
      validity_days = DateTime.diff(not_after, not_before, :day)
      if validity_days > 0 and validity_days < 30 do
        detection = %{
          type: :short_validity_certificate,
          confidence: 0.5,
          description: "Short validity certificate (#{validity_days} days) from #{remote_ip}",
          mitre_techniques: ["T1573.002"],
          metadata: %{
            validity_days: validity_days,
            remote_ip: remote_ip
          }
        }
        [detection | detections]
      else
        detections
      end
    else
      detections
    end

    # 4. Suspicious issuer + suspicious domain combination
    detections = if issuer && subject do
      is_suspicious_issuer = Enum.any?(@suspicious_issuers, &String.contains?(to_string(issuer), &1))
      is_suspicious_domain = is_suspicious_domain?(to_string(subject))

      if is_suspicious_issuer and is_suspicious_domain do
        detection = %{
          type: :suspicious_issuer_domain_combo,
          confidence: 0.65,
          description: "Suspicious certificate issuer (#{issuer}) with suspicious domain (#{subject})",
          mitre_techniques: ["T1573.002", "T1583.001"],
          metadata: %{
            issuer: issuer,
            subject: subject,
            remote_ip: remote_ip
          }
        }
        [detection | detections]
      else
        detections
      end
    else
      detections
    end

    # 5. No SANs (unusual for legitimate HTTPS)
    detections = if san == [] or is_nil(san) do
      detection = %{
        type: :no_san_certificate,
        confidence: 0.4,
        description: "Certificate has no Subject Alternative Names from #{remote_ip}",
        mitre_techniques: ["T1573.002"],
        metadata: %{remote_ip: remote_ip, subject: subject}
      }
      [detection | detections]
    else
      detections
    end

    # Update stats if suspicious cert found
    final_state = if length(detections) > 0 do
      update_stats(new_state, :suspicious_certs)
    else
      new_state
    end

    {detections, final_state}
  end

  defp analyze_certificate(_event, _cert_info, state), do: {[], state}

  defp is_self_signed?(issuer, subject) when is_binary(issuer) and is_binary(subject) do
    normalize_name(issuer) == normalize_name(subject)
  end
  defp is_self_signed?(_, _), do: false

  defp normalize_name(name) when is_binary(name) do
    name
    |> String.downcase()
    |> String.replace(~r/\s+/, " ")
    |> String.trim()
  end
  defp normalize_name(_), do: ""

  defp is_suspicious_domain?(domain) do
    Enum.any?(@suspicious_tlds, &String.ends_with?(domain, &1)) or
    Regex.match?(~r/^[a-z0-9]{16,}\./, domain)  # Random-looking subdomain
  end

  defp cache_certificate(remote_ip, cert_info, event) do
    :ets.insert(@certificate_cache_table, {remote_ip, %{
      certificate: cert_info,
      cached_at: DateTime.utc_now()
    }})

    persist_certificate_analysis(remote_ip, cert_info, event)
  end

  # --------------------------------------------------------------------------
  # SNI Analysis
  # --------------------------------------------------------------------------

  defp analyze_sni(_event, nil), do: []
  defp analyze_sni(event, sni) do
    payload = event[:payload] || event["payload"] || %{}
    remote_ip = payload[:remote_ip] || payload["remote_ip"]

    detections = []

    # Check for suspicious TLD
    detections = if is_suspicious_domain?(sni) do
      [%{
        type: :suspicious_sni_tld,
        confidence: 0.5,
        description: "Connection to suspicious TLD: #{sni}",
        mitre_techniques: ["T1071.001", "T1583.001"],
        metadata: %{sni: sni, remote_ip: remote_ip}
      } | detections]
    else
      detections
    end

    # Check for high entropy domain (potential DGA)
    domain_entropy = calculate_domain_entropy(sni)
    detections = if domain_entropy > 4.0 do
      [%{
        type: :high_entropy_sni,
        confidence: min(0.7, 0.4 + (domain_entropy - 4.0) * 0.15),
        description: "High entropy domain name: #{sni} (entropy: #{Float.round(domain_entropy, 2)})",
        mitre_techniques: ["T1568.002", "T1071.001"],
        metadata: %{sni: sni, entropy: domain_entropy, remote_ip: remote_ip}
      } | detections]
    else
      detections
    end

    # Check for IP-based SNI (unusual)
    detections = if Regex.match?(~r/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/, sni) do
      [%{
        type: :ip_based_sni,
        confidence: 0.5,
        description: "IP address used as SNI: #{sni}",
        mitre_techniques: ["T1071.001"],
        metadata: %{sni: sni}
      } | detections]
    else
      detections
    end

    detections
  end

  # --------------------------------------------------------------------------
  # TLS Version Analysis
  # --------------------------------------------------------------------------

  defp analyze_tls_version(_event, nil), do: []
  defp analyze_tls_version(event, tls_version) do
    payload = event[:payload] || event["payload"] || %{}
    remote_ip = payload[:remote_ip] || payload["remote_ip"]

    tls_version_str = to_string(tls_version)

    # Check for outdated TLS versions
    if tls_version_str in ["SSLv3", "TLSv1.0", "TLSv1.1", "SSL3", "TLS1.0", "TLS1.1"] do
      [%{
        type: :outdated_tls_version,
        confidence: 0.5,
        description: "Outdated TLS version used: #{tls_version}",
        mitre_techniques: ["T1573"],
        metadata: %{tls_version: tls_version, remote_ip: remote_ip}
      }]
    else
      []
    end
  end

  defp tls_session_event?(payload) do
    (payload[:is_encrypted] || payload["is_encrypted"]) == true or
      not is_nil(payload[:sni] || payload["sni"] || payload[:tls_sni] || payload["tls_sni"]) or
      not is_nil(payload[:tls_version] || payload["tls_version"]) or
      not is_nil(payload[:ja3] || payload["ja3"]) or
      not is_nil(payload[:ja3s] || payload["ja3s"]) or
      not is_nil(payload[:certificate] || payload["certificate"])
  end

  defp analyze_certificate_risk(_event, nil), do: []
  defp analyze_certificate_risk(event, risk) do
    risk_value =
      cond do
        is_number(risk) -> risk / 1
        is_binary(risk) ->
          case Float.parse(risk) do
            {parsed, _} -> parsed
            :error -> 0.0
          end
        true -> 0.0
      end

    if risk_value >= 0.6 do
      payload = event[:payload] || event["payload"] || %{}

      [%{
        type: :high_certificate_risk,
        confidence: min(0.95, risk_value),
        description: "High-risk TLS certificate observed for #{payload[:remote_ip] || payload["remote_ip"]}",
        mitre_techniques: ["T1573.002"],
        metadata: %{
          certificate_risk: risk_value,
          remote_ip: payload[:remote_ip] || payload["remote_ip"],
          sni: payload[:sni] || payload["sni"]
        }
      }]
    else
      []
    end
  end

  defp analyze_encrypted_dns(_event, nil), do: []
  defp analyze_encrypted_dns(event, transport) do
    payload = event[:payload] || event["payload"] || %{}
    normalized = transport |> to_string() |> String.downcase()
    remote_ip = payload[:remote_ip] || payload["remote_ip"]
    remote_port = payload[:remote_port] || payload["remote_port"]
    process = EventNormalizer.process_context(event)

    confidence =
      case normalized do
        "dot" -> 0.7
        "doq" -> 0.75
        "doh" -> 0.65
        _ -> 0.6
      end

    [%{
      type: :encrypted_dns_transport,
      confidence: confidence,
      description: "Encrypted DNS transport observed: #{String.upcase(normalized)}",
      mitre_techniques: ["T1071.004", "T1573"],
      metadata: %{
        encrypted_dns_transport: normalized,
        remote_ip: remote_ip,
        remote_port: remote_port,
        sni: payload[:sni] || payload["sni"],
        alpn: payload[:alpn] || payload["alpn"],
        process_name: process[:process_name] || process[:name]
      }
      |> reject_empty_values()
    }]
  end

  defp session_enrichment(event, payload) do
    base = event[:enrichment] || event["enrichment"] || %{}

    encrypted_metadata =
      %{
        alpn: payload[:alpn] || payload["alpn"],
        alpn_protocols: payload[:alpn_protocols] || payload["alpn_protocols"],
        cipher_suite: payload[:cipher_suite] || payload["cipher_suite"],
        tls_extensions: payload[:tls_extensions] || payload["tls_extensions"],
        ech_present: payload[:ech_present] || payload["ech_present"],
        quic_version: payload[:quic_version] || payload["quic_version"],
        is_quic: payload[:is_quic] || payload["is_quic"],
        http_version: payload[:http_version] || payload["http_version"],
        encrypted_dns_transport: payload[:encrypted_dns_transport] || payload["encrypted_dns_transport"],
        dns_resolver: payload[:dns_resolver] || payload["dns_resolver"]
      }
      |> reject_empty_values()

    if encrypted_metadata == %{} do
      base
    else
      Map.put(base, :encrypted_metadata, encrypted_metadata)
    end
  end

  # ============================================================================
  # Query Functions
  # ============================================================================

  defp fetch_ja3_stats(opts) do
    limit = Keyword.get(opts, :limit, 50)
    sort_by = Keyword.get(opts, :sort_by, :occurrence_count)

    ets_stats = :ets.tab2list(@ja3_stats_table)
    |> Enum.map(fn {hash, stats} ->
      is_malicious = case do_check_ja3(hash) do
        {:match, info} -> info
        _ -> nil
      end

      %{
        ja3_hash: hash,
        occurrence_count: stats.occurrence_count,
        unique_agents: MapSet.size(stats.agents),
        unique_destinations: MapSet.size(stats.destinations),
        first_seen: stats.first_seen,
        last_seen: stats.last_seen,
        is_malicious: is_malicious != nil,
        malware_info: is_malicious
      }
    end)
    |> Enum.sort_by(&Map.get(&1, sort_by), :desc)
    |> Enum.take(limit)

    persisted_ja3_stats(limit, sort_by)
    |> merge_by(ets_stats, [:agent_id, :ja3_hash], limit)
    |> Enum.sort_by(&Map.get(&1, sort_by, 0), :desc)
    |> Enum.take(limit)
  end

  defp fetch_certificate_analysis(opts) do
    agent_id = Keyword.get(opts, :agent_id)
    limit = Keyword.get(opts, :limit, 50)

    ets_analysis = :ets.tab2list(@certificate_cache_table)
    |> Enum.map(fn {ip, data} ->
      cert = data.certificate
      %{
        remote_ip: ip,
        subject: cert[:subject] || cert["subject"],
        issuer: cert[:issuer] || cert["issuer"],
        not_before: cert[:not_before] || cert["not_before"],
        not_after: cert[:not_after] || cert["not_after"],
        is_self_signed: is_self_signed?(
          cert[:issuer] || cert["issuer"],
          cert[:subject] || cert["subject"]
        ),
        cached_at: data.cached_at
      }
    end)
    |> Enum.sort_by(& &1.cached_at, {:desc, DateTime})
    |> Enum.take(limit)

    persisted_certificate_analysis(agent_id, limit)
    |> merge_by(ets_analysis, [:agent_id, :remote_ip, :fingerprint], limit)
  end

  defp fetch_tls_sessions(opts) do
    agent_id = Keyword.get(opts, :agent_id)
    limit = Keyword.get(opts, :limit, 100)

    ets_sessions = :ets.tab2list(@tls_sessions_table)
    |> Enum.filter(fn {aid, _} -> is_nil(agent_id) or aid == agent_id end)
    |> Enum.map(fn {_, session} -> session end)
    |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})
    |> Enum.take(limit)

    persisted_tls_sessions(agent_id, limit)
    |> merge_by(ets_sessions, [:agent_id, :event_id, :remote_ip, :remote_port, :timestamp], limit)
  end

  defp record_tls_session(agent_id, session, event) do
    :ets.insert(@tls_sessions_table, {agent_id, session})
    persist_tls_session(agent_id, session, event)
  end

  # ============================================================================
  # Alert Creation
  # ============================================================================

  defp create_encrypted_traffic_alert(event, detection) do
    agent_id = event[:agent_id] || event["agent_id"]

    severity = case detection.confidence do
      c when c >= 0.8 -> "high"
      c when c >= 0.6 -> "medium"
      _ -> "low"
    end

    title = case detection.type do
      :ja3_known_malicious -> "NDR: Malicious JA3 Fingerprint Detected"
      :ja3s_known_c2_server -> "NDR: Known C2 Server Fingerprint"
      :self_signed_certificate -> "NDR: Self-Signed Certificate"
      :recently_issued_certificate -> "NDR: Recently Issued Certificate"
      :suspicious_issuer_domain_combo -> "NDR: Suspicious Certificate Pattern"
      :suspicious_sni_tld -> "NDR: Suspicious TLD in SNI"
      :high_entropy_sni -> "NDR: High Entropy Domain (Potential DGA)"
      :outdated_tls_version -> "NDR: Outdated TLS Version"
      :high_certificate_risk -> "NDR: High-Risk TLS Certificate"
      :encrypted_dns_transport -> "NDR: Encrypted DNS Transport Observed"
      _ -> "NDR: Encrypted Traffic Anomaly"
    end

    case Alerts.create_alert(%{
           agent_id: agent_id,
           organization_id: event[:organization_id] || OrgLookup.get_org_id(agent_id),
           severity: severity,
           title: title,
           description: detection.description,
           source_event_id: EventNormalizer.source_event_uuid(event),
           event_ids: EventNormalizer.source_event_ids(event),
           evidence: EventNormalizer.alert_evidence(event, detection, :tls_metadata),
           raw_event: event,
           detection_metadata: detection.metadata || %{},
           mitre_tactics: ["command-and-control"],
           mitre_techniques: detection.mitre_techniques || [],
           threat_score: detection.confidence
         }) do
      {:ok, _alert} ->
        :ok

      {:error, reason} ->
        Logger.warning("Failed to create encrypted traffic alert (#{detection.type}): #{inspect(reason)}")
        :error
    end
  end

  # ============================================================================
  # Persistence
  # ============================================================================

  defp persist_tls_session(agent_id, session, event) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    Repo.insert_all("ndr_tls_sessions", [
      %{
        id: Ecto.UUID.generate(),
        organization_id: session[:organization_id],
        agent_id: agent_id,
        event_id: dump_uuid(EventNormalizer.source_event_id(event)),
        timestamp: session[:timestamp] || now,
        local_ip: session[:local_ip],
        local_port: session[:local_port],
        remote_ip: session[:remote_ip],
        remote_port: session[:remote_port],
        protocol: EventNormalizer.get_field(event[:payload] || event["payload"] || %{}, :protocol),
        domain: session[:domain],
        sni: session[:sni],
        tls_version: session[:tls_version],
        ja3: session[:ja3],
        ja3s: session[:ja3s],
        certificate_fingerprint: session[:certificate_fingerprint],
        certificate: session[:certificate] || %{},
        certificate_risk: session[:certificate_risk],
        enrichment: session[:enrichment] || %{},
        process: session[:process] || %{},
        inserted_at: now,
        updated_at: now
      }
    ], on_conflict: :nothing)
  rescue
    e -> Logger.debug("NDR TLS session persistence unavailable: #{Exception.message(e)}")
  end

  defp persist_ja3_stat(organization_id, agent_id, ja3_hash, payload, timestamp) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    Repo.insert_all("ndr_ja3_stats", [
      %{
        id: Ecto.UUID.generate(),
        organization_id: organization_id,
        agent_id: agent_id,
        ja3_hash: ja3_hash,
        ja3s_hash: payload[:ja3s] || payload["ja3s"],
        occurrence_count: 1,
        first_seen: timestamp,
        last_seen: timestamp,
        destinations: [payload[:remote_ip] || payload["remote_ip"]] |> Enum.reject(&is_nil/1),
        metadata: %{
          sni: payload[:sni] || payload["sni"],
          domain: payload[:domain] || payload["domain"],
          tls_version: payload[:tls_version] || payload["tls_version"]
        },
        inserted_at: now,
        updated_at: now
      }
    ],
      on_conflict: [
        inc: [occurrence_count: 1],
        set: [last_seen: timestamp, updated_at: now]
      ],
      conflict_target: [:organization_id, :agent_id, :ja3_hash]
    )
  rescue
    e -> Logger.debug("NDR JA3 persistence unavailable: #{Exception.message(e)}")
  end

  defp persist_certificate_analysis(remote_ip, cert_info, event) do
    agent_id = event[:agent_id] || event["agent_id"]
    organization_id = event[:organization_id] || event["organization_id"] || OrgLookup.get_org_id(agent_id)
    payload = event[:payload] || event["payload"] || %{}
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    fingerprint = EventNormalizer.certificate_fingerprint(cert_info)
    issuer = cert_info[:issuer] || cert_info["issuer"]
    subject = cert_info[:subject] || cert_info["subject"]
    not_before = parse_cert_date(cert_info[:not_before] || cert_info["not_before"])
    not_after = parse_cert_date(cert_info[:not_after] || cert_info["not_after"])

    Repo.insert_all("ndr_certificate_analyses", [
      %{
        id: Ecto.UUID.generate(),
        organization_id: organization_id,
        agent_id: agent_id,
        event_id: dump_uuid(EventNormalizer.source_event_id(event)),
        remote_ip: remote_ip,
        remote_port: payload[:remote_port] || payload["remote_port"],
        domain: payload[:domain] || payload["domain"] || payload[:sni] || payload["sni"],
        fingerprint: fingerprint,
        subject: subject,
        issuer: issuer,
        not_before: not_before,
        not_after: not_after,
        is_self_signed: is_self_signed?(issuer, subject),
        risk_score: payload[:certificate_risk] || payload["certificate_risk"],
        certificate: cert_info,
        analysis: %{
          no_san: (cert_info[:san] || cert_info["san"] || []) in [nil, []],
          suspicious_domain: subject && is_suspicious_domain?(to_string(subject))
        },
        inserted_at: now,
        updated_at: now
      }
    ], on_conflict: :nothing)
  rescue
    e -> Logger.debug("NDR certificate persistence unavailable: #{Exception.message(e)}")
  end

  defp persisted_tls_sessions(agent_id, limit) do
    query =
      from(s in "ndr_tls_sessions",
        order_by: [desc: field(s, :timestamp)],
        limit: ^limit,
        select: %{
          agent_id: field(s, :agent_id),
          organization_id: field(s, :organization_id),
          event_id: field(s, :event_id),
          local_ip: field(s, :local_ip),
          local_port: field(s, :local_port),
          remote_ip: field(s, :remote_ip),
          remote_port: field(s, :remote_port),
          protocol: field(s, :protocol),
          domain: field(s, :domain),
          ja3: field(s, :ja3),
          ja3s: field(s, :ja3s),
          sni: field(s, :sni),
          tls_version: field(s, :tls_version),
          certificate_fingerprint: field(s, :certificate_fingerprint),
          certificate_risk: field(s, :certificate_risk),
          process: field(s, :process),
          enrichment: field(s, :enrichment),
          timestamp: field(s, :timestamp)
        }
      )

    query =
      if is_nil(agent_id) do
        query
      else
        from(s in query, where: field(s, :agent_id) == ^agent_id)
      end

    query
    |> Repo.all()
  rescue
    _ -> []
  end

  defp persisted_certificate_analysis(agent_id, limit) do
    query =
      from(c in "ndr_certificate_analyses",
        order_by: [desc: field(c, :inserted_at)],
        limit: ^limit,
        select: %{
          agent_id: field(c, :agent_id),
          organization_id: field(c, :organization_id),
          remote_ip: field(c, :remote_ip),
          remote_port: field(c, :remote_port),
          domain: field(c, :domain),
          fingerprint: field(c, :fingerprint),
          subject: field(c, :subject),
          issuer: field(c, :issuer),
          not_before: field(c, :not_before),
          not_after: field(c, :not_after),
          is_self_signed: field(c, :is_self_signed),
          risk_score: field(c, :risk_score),
          certificate: field(c, :certificate),
          analysis: field(c, :analysis),
          cached_at: field(c, :inserted_at)
        }
      )

    query =
      if is_nil(agent_id) do
        query
      else
        from(c in query, where: field(c, :agent_id) == ^agent_id)
      end

    query
    |> Repo.all()
  rescue
    _ -> []
  end

  defp persisted_ja3_stats(limit, sort_by) do
    order_field =
      case sort_by do
        :unique_agents -> :occurrence_count
        :unique_destinations -> :occurrence_count
        :last_seen -> :last_seen
        _ -> :occurrence_count
      end

    from(j in "ndr_ja3_stats",
      order_by: [desc: field(j, ^order_field)],
      limit: ^limit,
      select: %{
        agent_id: field(j, :agent_id),
        organization_id: field(j, :organization_id),
        ja3_hash: field(j, :ja3_hash),
        ja3s_hash: field(j, :ja3s_hash),
        occurrence_count: field(j, :occurrence_count),
        unique_agents: 1,
        unique_destinations: fragment("cardinality(?)", field(j, :destinations)),
        first_seen: field(j, :first_seen),
        last_seen: field(j, :last_seen),
        destinations: field(j, :destinations),
        metadata: field(j, :metadata)
      }
    )
    |> Repo.all()
    |> Enum.map(fn stat ->
      is_malicious =
        case do_check_ja3(stat.ja3_hash) do
          {:match, info} -> info
          _ -> nil
        end

      stat
      |> Map.put(:is_malicious, is_malicious != nil)
      |> Map.put(:malware_info, is_malicious)
    end)
  rescue
    _ -> []
  end

  defp merge_by(persisted, ets_rows, keys, limit) do
    (persisted ++ ets_rows)
    |> Enum.uniq_by(fn row -> Enum.map(keys, &Map.get(row, &1)) end)
    |> Enum.sort_by(&sortable_time/1, :desc)
    |> Enum.take(limit)
  end

  defp sortable_time(row) do
    case row[:timestamp] || row[:cached_at] do
      %DateTime{} = dt -> DateTime.to_unix(dt, :microsecond)
      %NaiveDateTime{} = ndt -> ndt |> DateTime.from_naive!("Etc/UTC") |> DateTime.to_unix(:microsecond)
      _ -> 0
    end
  end

  defp dump_uuid(nil), do: nil
  defp dump_uuid(value) when is_binary(value) do
    case Ecto.UUID.cast(value) do
      {:ok, uuid} -> uuid
      :error -> nil
    end
  end
  defp dump_uuid(_), do: nil

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp reject_empty_values(map) when is_map(map) do
    Map.reject(map, fn {_key, value} -> value in [nil, "", [], %{}] end)
  end

  defp calculate_entropy(string) when is_binary(string) do
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

  defp calculate_domain_entropy(domain) when is_binary(domain) do
    # Extract second-level domain for entropy calculation
    parts = String.split(domain, ".")
    sld = if length(parts) >= 2, do: Enum.at(parts, length(parts) - 2), else: domain

    calculate_entropy(sld)
  end

  defp calculate_domain_entropy(_), do: 0.0

  defp parse_cert_date(nil), do: nil
  defp parse_cert_date(%DateTime{} = dt), do: dt
  defp parse_cert_date(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end
  defp parse_cert_date(_), do: nil

  defp update_stats(state, key) do
    %{state | stats: Map.update(state.stats, key, 1, &(&1 + 1))}
  end

  defp cleanup_old_data do
    cutoff = DateTime.utc_now() |> DateTime.add(-3600, :second)

    # Clean TLS sessions
    :ets.tab2list(@tls_sessions_table)
    |> Enum.each(fn {key, session} ->
      if DateTime.compare(session.timestamp, cutoff) == :lt do
        :ets.delete_object(@tls_sessions_table, {key, session})
      end
    end)

    Logger.debug("NDR Encrypted Traffic cleanup completed")
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, :timer.minutes(10))
  end
end
