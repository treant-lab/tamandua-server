defmodule TamanduaServer.Detection.Evidence do
  @moduledoc """
  Extracts structured evidence from telemetry events for alert enrichment.

  This module provides functions to extract and normalize evidence from telemetry
  events into a structured format suitable for forensic analysis and threat hunting.

  ## Evidence Structure

  The extracted evidence includes:
  - `process` - PID, PPID, name, command line, image path, user, elevation, signing, parent chain
  - `file` - Path, hashes (SHA256/SHA1/MD5), size, entropy, signing, creation time
  - `network` - Source/destination IPs and ports, protocol, direction, bytes, domain
  - `registry` - Key path, value name, value data, operation
  - `dns` - Query name, query type, response, suspicion flag
  - `user` - Username, domain, SID, logon type
  - `indicators` - All IOC-matchable values (IPs, domains, hashes, URLs)
  - `detection` - Rule name, type, confidence, matched patterns
  """

  @agent_detection_type_map %{
    "yara" => "yara",
    "sigma" => "sigma",
    "ml" => "ml",
    "behavioral" => "behavioral",
    "behavioral_chain" => "behavioral",
    "correlated" => "correlation",
    "ioc" => "ioc",
    "ioc_match" => "ioc",
    "threat_intel" => "threat_intel",
    "threat_intel_feed" => "threat_intel",
    "entropy" => "entropy",
    "honeyfile" => "deception",
    "ransomware" => "ransomware",
    "malware" => "malware",
    "memory_threat" => "memory_threat",
    "memory_evasion" => "memory_threat",
    "driver_threat" => "driver_threat",
    "wmi_persistence" => "persistence",
    "persistence" => "persistence",
    "registry_persistence" => "persistence",
    "scheduled_task" => "persistence",
    "usb_threat" => "usb_threat",
    "exploit_mitigation" => "exploit_mitigation",
    "browser_stealer" => "credential_theft",
    "credential_theft" => "credential_theft",
    "credential_access" => "credential_theft",
    "defense_evasion" => "defense_evasion",
    "script_threat" => "script_threat",
    "lateral_movement" => "lateral_movement",
    "process_hollowing" => "process_injection",
    "process_injection" => "process_injection",
    "module_stomping" => "process_injection",
    "transacted_hollowing" => "process_injection",
    "thread_hijacking" => "process_injection",
    "process_doppelganging" => "process_injection",
    "phantom_dll_hollowing" => "process_injection",
    "container_threat" => "container_threat",
    "clipboard_capture" => "collection",
    "input_capture" => "credential_theft",
    "firmware_threat" => "firmware_threat",
    "firmware" => "firmware_threat",
    "network_anomaly" => "network_anomaly",
    "network_fingerprint" => "network_anomaly",
    "certificate_anomaly" => "network_anomaly",
    "ad_threat" => "identity_threat",
    "office_macro" => "script_threat",
    "office_email" => "phishing",
    "file_integrity" => "file_integrity",
    "dll_sideloading" => "defense_evasion",
    "lolbin_abuse" => "defense_evasion",
    "llm_request" => "ai_security",
    "ai_model_load" => "ai_security",
    "supply_chain" => "supply_chain",
    "command_line_spoofing" => "defense_evasion",
    "stack_spoofing" => "defense_evasion",
    "heavens_gate" => "defense_evasion",
    "ttp_match" => "behavioral",
    "kernel_syscall" => "defense_evasion",
    "unknown" => nil
  }

  @doc """
  Extract structured evidence from an event and optional detection results.

  ## Parameters

  - `event` - The telemetry event map (with :payload or "payload" key)
  - `detections` - List of detection results (optional)

  ## Returns

  A map with keys: `:process`, `:file`, `:network`, `:registry`, `:dns`,
  `:user`, `:indicators`, `:detection`, and `:file_hashes` (alias for backward compat)

  ## Examples

      iex> Evidence.extract(%{payload: %{pid: 1234, name: "cmd.exe"}}, [])
      %{
        process: %{pid: 1234, name: "cmd.exe", ...},
        file: %{},
        network: [],
        registry: [],
        dns: %{},
        user: %{},
        indicators: [],
        detection: %{},
        file_hashes: []
      }
  """
  @spec extract(map(), list()) :: map()
  def extract(event, detections \\ []) do
    payload = event[:payload] || event["payload"] || %{}

    %{
      process: extract_process_info(payload),
      file: extract_file_evidence(payload),
      network: extract_network_indicators(payload),
      registry: extract_registry_info(payload),
      dns: extract_dns_evidence(payload),
      user: extract_user_evidence(payload),
      indicators: extract_indicators(payload),
      detection: extract_detection_info(detections),
      # Backward compatibility -- some callers reference :file_hashes
      file_hashes: extract_file_hashes(payload)
    }
    |> Map.merge(extract_consumer_context(event, payload))
  end

  @consumer_context_fields ~w(
    ai_network_risk ai_evidence_limit network_visibility_state
    tls_fingerprints_available certificate_visibility risk_indicators
    matched_patterns artifact_type redacted_preview
  )

  defp extract_consumer_context(event, payload) do
    metadata = event[:metadata] || event["metadata"] || %{}
    contexts = [metadata, payload]

    fields =
      Enum.reduce(@consumer_context_fields, %{}, fn key, acc ->
        value = Enum.reduce_while(contexts, nil, fn context, _acc ->
          case consumer_context_value(context, key) do
            :missing -> {:cont, nil}
            value -> {:halt, value}
          end
        end)
        if value in [nil, "", []], do: acc, else: Map.put(acc, String.to_atom(key), value)
      end)

    if is_map(metadata) and map_size(metadata) > 0,
      do: Map.put(fields, :metadata, metadata),
      else: fields
  end

  defp consumer_context_value(context, key) when is_map(context) do
    atom_key = String.to_atom(key)

    case Map.fetch(context, key) do
      {:ok, value} -> value

      :error ->
        case Map.fetch(context, atom_key) do
          {:ok, value} -> value
          :error -> :missing
        end
    end
  end

  defp consumer_context_value(_, _), do: :missing

  @doc """
  Extract file hash information from the event payload.

  Returns a list of hash maps with SHA256, SHA1, MD5, and file path.
  """
  @spec extract_file_hashes(map()) :: list(map())
  def extract_file_hashes(payload) do
    sha256 = get_field(payload, :sha256)
    sha1 = get_field(payload, :sha1)
    md5 = get_field(payload, :md5)
    path = get_field(payload, :path)

    if sha256 || sha1 || md5 do
      [
        %{
          sha256: sha256,
          sha1: sha1,
          md5: md5,
          path: path
        }
        |> reject_nil_values()
      ]
    else
      []
    end
  end

  @doc """
  Extract network indicators from the event payload.

  Returns a list of network indicator maps including IPs, domains, ports.
  """
  @spec extract_network_indicators(map()) :: list(map())
  def extract_network_indicators(payload) do
    indicators = []

    # Extract remote IP indicator
    indicators =
      if ip = get_field(payload, :remote_ip) do
        indicator = %{
          type: "ip",
          value: ip,
          direction: "outbound",
          port: get_field(payload, :remote_port)
        }
        |> reject_nil_values()

        [indicator | indicators]
      else
        indicators
      end

    # Extract local IP indicator if present
    indicators =
      if ip = get_field(payload, :local_ip) do
        indicator = %{
          type: "ip",
          value: ip,
          direction: "inbound",
          port: get_field(payload, :local_port)
        }
        |> reject_nil_values()

        [indicator | indicators]
      else
        indicators
      end

    # Extract domain indicator
    indicators =
      if domain = get_field(payload, :domain) do
        indicator = %{
          type: "domain",
          value: domain,
          resolved_ip: get_field(payload, :resolved_ip)
        }
        |> reject_nil_values()

        [indicator | indicators]
      else
        indicators
      end

    # Extract DNS query
    indicators =
      if query = get_field(payload, :query) do
        # Only add if not already captured as domain
        domain = get_field(payload, :domain)
        if query != domain do
          indicator = %{
            type: "dns_query",
            value: query,
            query_type: get_field(payload, :query_type)
          }
          |> reject_nil_values()

          [indicator | indicators]
        else
          indicators
        end
      else
        indicators
      end

    Enum.reverse(indicators)
  end

  @doc """
  Extract process information from the event payload.

  Returns a map with PID, PPID, name, command line, image path, user, hashes,
  elevation status, signature info, and parent chain metadata.
  """
  @spec extract_process_info(map()) :: map()
  def extract_process_info(payload) do
    %{
      pid:
        get_field(payload, :pid) ||
          get_field(payload, :process_id) ||
          get_field(payload, :process_pid) ||
          get_field(payload, :source_pid) ||
          get_field(payload, :target_pid),
      ppid: get_field(payload, :ppid),
      name: get_field(payload, :name) || get_field(payload, :process_name),
      cmdline: get_field(payload, :cmdline) || get_field(payload, :command_line),
      image_path: get_field(payload, :path) || get_field(payload, :process_path) || get_field(payload, :image_path),
      user: get_field(payload, :user) || get_field(payload, :username),
      path: get_field(payload, :path) || get_field(payload, :process_path),
      sha256: get_field(payload, :sha256),
      is_elevated: get_field(payload, :is_elevated),
      is_signed: get_field(payload, :is_signed),
      signer: get_field(payload, :signer),
      parent_name: get_field(payload, :parent_name) || get_field(payload, :parent_process),
      parent_path: get_field(payload, :parent_path),
      parent_cmdline: get_field(payload, :parent_cmdline) || get_field(payload, :parent_command_line),
      start_time: get_field(payload, :start_time) || get_field(payload, :timestamp)
    }
    |> reject_nil_values()
  end

  @doc """
  Extract registry information from the event payload.

  Returns a list of registry operation maps (Windows-specific).
  """
  @spec extract_registry_info(map()) :: list(map())
  def extract_registry_info(payload) do
    key = get_field(payload, :registry_key) || get_field(payload, :key_path)

    if key do
      [
        %{
          key: key,
          value: get_field(payload, :registry_value) || get_field(payload, :value_name),
          data: get_field(payload, :registry_data) || get_field(payload, :value_data),
          operation: get_field(payload, :registry_operation) || get_field(payload, :operation)
        }
        |> reject_nil_values()
      ]
    else
      []
    end
  end

  @doc """
  Extract detection metadata from the list of detection results.

  Returns a map with rule name, type, confidence, and matched pattern.
  """
  @spec extract_detection_info(list()) :: map()
  def extract_detection_info(detections) do
    case detections do
      [first | _] when is_map(first) ->
        %{
          rule_name:
            detection_field(first, :pattern_name) ||
              detection_field(first, :rule_name) ||
              detection_field(first, :name) ||
              detection_field(first, :description) ||
              type_to_string(detection_field(first, :type)),
          rule_type: detect_rule_type(first),
          source: detect_rule_type(first),
          detection_source: detect_rule_type(first),
          detection_type:
            type_to_string(detection_field(first, :detection_type) || detection_field(first, :type)),
          confidence: extract_confidence(first),
          matched_pattern: detection_field(first, :matched_pattern) || detection_field(first, :pattern),
          severity: detection_field(first, :severity) || detection_field(first, :severity_score),
          mitre_attack_id: detection_field(first, :mitre_attack_id) || detection_field(first, :technique_id),
          mitre_tactics: detection_field(first, :mitre_tactics),
          mitre_techniques: detection_field(first, :mitre_techniques)
        }
        |> reject_nil_values()

      _ ->
        %{}
    end
  end

  # ===========================================================================
  # File Evidence
  # ===========================================================================

  @doc """
  Extract file-level evidence from the event payload.

  Returns a map with path, hashes, size, entropy, signing info, and timestamps.
  """
  @spec extract_file_evidence(map()) :: map()
  def extract_file_evidence(payload) do
    %{
      path: get_field(payload, :path) || get_field(payload, :file_path),
      sha256: get_field(payload, :sha256),
      sha1: get_field(payload, :sha1),
      md5: get_field(payload, :md5),
      size: get_field(payload, :file_size) || get_field(payload, :size),
      entropy: get_field(payload, :entropy),
      is_signed: get_field(payload, :is_signed),
      signer: get_field(payload, :signer),
      creation_time: get_field(payload, :creation_time) || get_field(payload, :file_created),
      modification_time: get_field(payload, :modification_time) || get_field(payload, :file_modified)
    }
    |> reject_nil_values()
  end

  # ===========================================================================
  # DNS Evidence
  # ===========================================================================

  @doc """
  Extract DNS evidence from the event payload.

  Returns a map with query name, query type, response records, and suspicion flags.
  """
  @spec extract_dns_evidence(map()) :: map()
  def extract_dns_evidence(payload) do
    query_name = get_field(payload, :query) || get_field(payload, :query_name) || get_field(payload, :domain)

    if query_name do
      %{
        query_name: query_name,
        query_type: get_field(payload, :query_type) || get_field(payload, :record_type),
        response: get_field(payload, :response) || get_field(payload, :resolved_ip) || get_field(payload, :answers),
        response_code: get_field(payload, :response_code) || get_field(payload, :rcode),
        is_suspicious: get_field(payload, :is_suspicious) || get_field(payload, :suspicious),
        ttl: get_field(payload, :ttl),
        server: get_field(payload, :dns_server) || get_field(payload, :server)
      }
      |> reject_nil_values()
    else
      %{}
    end
  end

  # ===========================================================================
  # User Evidence
  # ===========================================================================

  @doc """
  Extract user evidence from the event payload.

  Returns a map with username, domain, SID, and logon type.
  """
  @spec extract_user_evidence(map()) :: map()
  def extract_user_evidence(payload) do
    username = get_field(payload, :user) || get_field(payload, :username) || get_field(payload, :account_name)

    if username do
      %{
        username: username,
        domain: get_field(payload, :domain) || get_field(payload, :user_domain) || get_field(payload, :account_domain),
        sid: get_field(payload, :sid) || get_field(payload, :user_sid),
        logon_type: get_field(payload, :logon_type),
        logon_id: get_field(payload, :logon_id),
        is_elevated: get_field(payload, :is_elevated),
        session_id: get_field(payload, :session_id)
      }
      |> reject_nil_values()
    else
      %{}
    end
  end

  # ===========================================================================
  # IOC Indicators
  # ===========================================================================

  @doc """
  Extract all IOC-matchable indicator values from the event payload.

  Returns a list of indicator maps, each with `:type` and `:value` keys.
  Types include: ip, domain, hash_sha256, hash_sha1, hash_md5, url.
  """
  @spec extract_indicators(map()) :: list(map())
  def extract_indicators(payload) do
    indicators = []

    # IPs
    indicators = add_indicator(indicators, "ip", get_field(payload, :remote_ip))
    indicators = add_indicator(indicators, "ip", get_field(payload, :local_ip))
    indicators = add_indicator(indicators, "ip", get_field(payload, :src_ip))
    indicators = add_indicator(indicators, "ip", get_field(payload, :dst_ip))

    # Domains
    indicators = add_indicator(indicators, "domain", get_field(payload, :domain))
    indicators = add_indicator(indicators, "domain", get_field(payload, :query))
    indicators = add_indicator(indicators, "domain", get_field(payload, :hostname))

    # Hashes
    indicators = add_indicator(indicators, "hash_sha256", get_field(payload, :sha256))
    indicators = add_indicator(indicators, "hash_sha1", get_field(payload, :sha1))
    indicators = add_indicator(indicators, "hash_md5", get_field(payload, :md5))

    # URLs
    indicators = add_indicator(indicators, "url", get_field(payload, :url))

    # Deduplicate by {type, value}
    indicators
    |> Enum.uniq_by(fn ind -> {ind.type, ind.value} end)
    |> Enum.reverse()
  end

  defp add_indicator(indicators, _type, nil), do: indicators
  defp add_indicator(indicators, _type, ""), do: indicators
  defp add_indicator(indicators, type, value) do
    [%{type: type, value: to_string(value)} | indicators]
  end

  # ===========================================================================
  # Contextual Alert Title Builder
  # ===========================================================================

  @doc """
  Build a contextual alert title from event data, detections, and MITRE techniques.

  Generates descriptive titles such as:
  - "Credential Dumping: mimikatz.exe (PID 4523) accessing LSASS [T1003.001]"
  - "Suspicious Process Chain: winword.exe -> cmd.exe -> powershell.exe [T1059.001]"
  - "Network C2 Beacon: svchost.exe connecting to 185.x.x.x:443 every 60s [T1071.001]"

  ## Parameters

  - `event` - The telemetry event map
  - `detections` - List of detection results
  - `mitre_techniques` - List of MITRE technique IDs (optional, extracted from detections if nil)

  ## Returns

  A string with the contextual title.
  """
  @spec build_contextual_title(map(), list(), list() | nil) :: String.t()
  def build_contextual_title(event, detections, mitre_techniques \\ nil) do
    payload = event[:payload] || event["payload"] || %{}
    detection = List.first(detections) || %{}

    techniques = mitre_techniques || (
      detections
      |> Enum.flat_map(fn d -> d[:mitre_techniques] || [] end)
      |> Enum.uniq()
    )

    primary_technique = List.first(techniques)
    category = technique_to_category(primary_technique, detection)

    # Extract key context from the payload
    process_name = get_field(payload, :name) || get_field(payload, :process_name)
    pid = get_field(payload, :pid)
    parent_name = get_field(payload, :parent_name) || get_field(payload, :parent_process)
    remote_ip = get_field(payload, :remote_ip) || get_field(payload, :dst_ip)
    remote_port = get_field(payload, :remote_port) || get_field(payload, :dst_port)
    domain = get_field(payload, :query) || get_field(payload, :domain)
    file_path = get_field(payload, :path)

    # Build the action description
    action = detection[:description] || detection[:rule_name] || detection[:pattern_name] || "detected"

    # Build the technique tag
    technique_tag = if primary_technique, do: " [#{primary_technique}]", else: ""

    # Build contextual detail based on available data
    detail = cond do
      # Process chain: parent -> child
      process_name && parent_name && pid ->
        "#{parent_name} -> #{process_name} (PID #{pid})"

      # Process with network connection
      process_name && remote_ip && remote_port ->
        "#{process_name} connecting to #{remote_ip}:#{remote_port}"

      # Process with domain resolution
      process_name && domain ->
        "#{process_name} resolving #{domain}"

      # Process with PID
      process_name && pid ->
        "#{process_name} (PID #{pid})"

      # Network only
      remote_ip && remote_port ->
        "#{remote_ip}:#{remote_port}"

      # DNS only
      domain ->
        domain

      # File only
      file_path ->
        Path.basename(to_string(file_path))

      # Process name only
      process_name ->
        process_name

      true ->
        nil
    end

    # Assemble the title
    if detail do
      "#{category}: #{detail}#{technique_tag}"
    else
      "#{category}: #{action}#{technique_tag}"
    end
    |> String.trim()
    |> String.slice(0, 255)
  end

  # Map a MITRE technique ID to a human-readable category.
  # Falls back to detection type or "Suspicious Activity".
  defp technique_to_category(nil, detection) do
    detection_type = detection[:type]

    case detection_type do
      :sigma -> "Sigma Detection"
      :sigma_aggregation -> "Sigma Aggregation"
      :yara -> "YARA Detection"
      :ioc -> "IOC Match"
      :ml -> "ML Detection"
      :threat_intel_feed -> "Threat Intel"
      :ttp_match -> "TTP Detection"
      :c2_beacon_strong -> "C2 Beaconing"
      :c2_beacon_moderate -> "C2 Beaconing"
      :c2_ja3_match -> "C2 Framework"
      :c2_suspicious_certificate -> "C2 Indicator"
      :c2_dga_https -> "C2 DGA"
      :c2_domain_fronting_suspected -> "C2 Evasion"
      :c2_high_frequency -> "C2 Activity"
      :c2_exfil_traffic -> "Data Exfiltration"
      _ -> "Suspicious Activity"
    end
  end

  defp technique_to_category(technique, _detection) do
    case technique do
      "T1003" <> _ -> "Credential Dumping"
      "T1055" <> _ -> "Process Injection"
      "T1059" <> _ -> "Command Execution"
      "T1059.001" -> "PowerShell Execution"
      "T1059.003" -> "Windows Command Shell"
      "T1059.005" -> "VBScript Execution"
      "T1021" <> _ -> "Lateral Movement"
      "T1547" <> _ -> "Persistence"
      "T1543" <> _ -> "Service Creation"
      "T1053" <> _ -> "Scheduled Task"
      "T1486" <> _ -> "Ransomware"
      "T1490" <> _ -> "Recovery Inhibition"
      "T1105" <> _ -> "Remote File Download"
      "T1070" <> _ -> "Defense Evasion"
      "T1071" <> _ -> "Command and Control"
      "T1027" <> _ -> "Obfuscation"
      "T1047" <> _ -> "WMI Execution"
      "T1218" <> _ -> "Signed Binary Proxy Execution"
      "T1036" <> _ -> "Masquerading"
      "T1041" <> _ -> "Data Exfiltration"
      "T1078" <> _ -> "Valid Accounts"
      "T1562" <> _ -> "Security Tool Tampering"
      "T1571" <> _ -> "Non-Standard Port"
      "T1566" <> _ -> "Phishing"
      "T1189" <> _ -> "Drive-by Compromise"
      "T1204" <> _ -> "User Execution"
      "T1140" <> _ -> "Deobfuscation"
      "T1197" <> _ -> "BITS Jobs"
      "T1112" <> _ -> "Registry Modification"
      "T1548" <> _ -> "Privilege Escalation"
      "T1564" <> _ -> "Hidden Execution"
      "T1568" <> _ -> "Dynamic Resolution (DGA)"
      "T1573" <> _ -> "Encrypted C2 Channel"
      "T1090" <> _ -> "C2 Proxy/Fronting"
      "T1570" <> _ -> "Lateral Tool Transfer"
      "T1087" <> _ -> "Account Discovery"
      "T1082" <> _ -> "System Discovery"
      "T1016" <> _ -> "Network Discovery"
      "T1033" <> _ -> "User Discovery"
      "T1560" <> _ -> "Data Staging"
      "T1555" <> _ -> "Credential Store Access"
      "T1552" <> _ -> "Credential Storage Access"
      "T1095" <> _ -> "Non-Application Layer Protocol"
      _ -> "Suspicious Activity"
    end
  end

  # Private helpers

  defp get_field(payload, key) when is_atom(key) do
    payload[key] || payload[Atom.to_string(key)]
  end

  defp detect_rule_type(detection) do
    detection_type = detection_field(detection, :detection_type) || detection_field(detection, :type)
    rule_name = detection_field(detection, :rule_name) || detection_field(detection, :name)

    cond do
      truthy?(detection_field(detection, :yara_match)) || detection_field(detection, :yara_rule) -> "yara"
      truthy?(detection_field(detection, :sigma_match)) || detection_field(detection, :sigma_rule) -> "sigma"
      detection_field(detection, :ml_score) || detection_field(detection, :ml_result) -> "ml"
      normalized_rule_type(detection_type) -> normalized_rule_type(detection_type)
      inferred_rule_type(rule_name) -> inferred_rule_type(rule_name)
      detection_field(detection, :correlation_score) -> "correlation"
      true -> "unknown"
    end
  end

  defp detection_field(detection, key) when is_map(detection) do
    detection[key] || detection[Atom.to_string(key)]
  end

  defp truthy?(value), do: value not in [nil, false, "", 0]

  defp normalized_rule_type(type) when is_atom(type),
    do: type |> Atom.to_string() |> normalized_rule_type()

  defp normalized_rule_type(type) when is_binary(type) do
    normalized =
      type
      |> String.trim()
      |> Macro.underscore()

    Map.get(@agent_detection_type_map, normalized)
  end

  defp normalized_rule_type(_), do: nil

  defp inferred_rule_type(rule_name) when is_binary(rule_name) do
    normalized = String.downcase(rule_name)

    cond do
      String.starts_with?(normalized, "kernel_syscall_") -> "defense_evasion"
      String.starts_with?(normalized, "registry_") -> "persistence"
      String.contains?(normalized, "powershell") -> "defense_evasion"
      String.contains?(normalized, "execution_policy") -> "defense_evasion"
      String.contains?(normalized, "persistence") -> "persistence"
      String.contains?(normalized, "credential") -> "credential_theft"
      String.contains?(normalized, "ransomware") -> "ransomware"
      String.contains?(normalized, "lateral") -> "lateral_movement"
      String.contains?(normalized, "defense_evasion") -> "defense_evasion"
      true -> nil
    end
  end

  defp inferred_rule_type(_), do: nil

  defp extract_confidence(detection) do
    cond do
      confidence = detection[:confidence] ->
        confidence

      score = detection[:severity_score] ->
        # Convert severity score (0-100) to confidence (0-1)
        score / 100

      ml_score = detection[:ml_score] ->
        ml_score

      true ->
        nil
    end
  end

  defp type_to_string(nil), do: nil
  defp type_to_string(type) when is_atom(type), do: Atom.to_string(type)
  defp type_to_string(type) when is_binary(type), do: type
  defp type_to_string(_), do: nil

  defp reject_nil_values(map) when is_map(map) do
    map
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end
end
