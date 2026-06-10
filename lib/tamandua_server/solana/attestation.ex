defmodule TamanduaServer.Solana.Attestation do
  @moduledoc """
  Incident attestation service for Tamanduá Sentinel.

  This module creates tamper-evident attestations for security incidents
  on the Solana blockchain. Key principles:

  - **Private telemetry, public proof**: Only redacted hashes go on-chain
  - **Pseudonymization**: Org/agent IDs are hashed before submission
  - **MITRE mapping**: Each incident includes ATT&CK technique reference
  - **Detection bounties**: Rule authors can earn rewards

  ## Usage

      # Attest an alert
      {:ok, tx_signature} = Attestation.attest_alert(alert)

      # Check attestation status
      {:ok, attestation} = Attestation.get_attestation(alert)

  ## Privacy Guarantees (PRIVACY-01, PRIVACY-02)

  **What NEVER goes on-chain:**
  - Hostnames (victim-pc.local, server.internal)
  - Usernames (john.doe, admin)
  - File paths (C:\\Users\\victim\\malware.exe, /home/user/payload)
  - Process command lines (powershell -enc ..., cmd.exe /c whoami)
  - Internal IP addresses (10.x.x.x, 192.168.x.x, 172.16-31.x.x, 127.x.x.x)
  - Private domains (.local, .lan, .internal, .corp)
  - Internal URLs (http://192.168.1.1/admin)
  - Raw event payloads
  - User credentials
  - Any personally identifiable information (PII)

  **What DOES go on-chain (public IOCs only):**
  - File hashes (SHA256, SHA1, MD5)
  - Public domains (malware.com, c2.evil.net)
  - Public URLs (https://evil.com/payload.exe)
  - Public IP addresses (1.2.3.4, 8.8.8.8)
  - MITRE ATT&CK technique IDs (T1555.003)
  - Detection rule hash (SHA256 of rule ID)
  - Malware family name (if identified)
  - Threat classification (infostealer, ransomware, c2, endpoint_threat)

  **Privacy mechanisms:**
  - IOC type filtering: Only 6 types allowed (hash_sha256, hash_sha1, hash_md5, domain, url, ip)
  - Private IP detection: RFC1918, localhost, link-local ranges filtered
  - Private domain detection: .local, .lan, .internal, .corp suffixes filtered
  - URL validation: Scheme must be http/https, host must be public
  - Organization pseudonymization: SHA256(org_id) instead of real ID
  - Agent pseudonymization: SHA256(agent_id) instead of real ID

  **Traffic Light Protocol (TLP) classification:**
  - TLP:CLEAR - No IOCs redacted, all data is public
  - TLP:AMBER - Some IOCs redacted, contains redacted sensitive data

  ## Example Redaction

  **Before (alert indicators):**
  ```elixir
  [
    %{type: "hostname", value: "victim-pc.local"},
    %{type: "username", value: "john.doe"},
    %{type: "ip", value: "192.168.1.100"},
    %{type: "path", value: "C:\\\\Users\\\\victim\\\\AppData\\\\malware.exe"},
    %{type: "hash_sha256", value: "abc123..."},
    %{type: "domain", value: "evil.com"},
    %{type: "ip", value: "1.2.3.4"}
  ]
  ```

  **After (public manifest):**
  ```elixir
  %{
    iocs: [
      %{type: "hash_sha256", value: "abc123...", source: "tamandua"},
      %{type: "domain", value: "evil.com", source: "tamandua"},
      %{type: "ip", value: "1.2.3.4", source: "tamandua"}
    ],
    ioc_count: 3,
    redacted_ioc_count: 4,
    tlp: "amber"
  }
  ```

  **Redacted:** hostname, username, internal IP, file path (4 IOCs removed)
  **Included:** hash, public domain, public IP (3 safe IOCs)

  ## Redaction Rules

  The attestation pipeline automatically removes all sensitive data. No configuration needed.
  Privacy is enforced at the code level, not by policy.
  """

  require Logger

  alias TamanduaServer.Solana.Client
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Agents.Agent

  @severity_map %{
    "info" => 1,
    "low" => 2,
    "medium" => 3,
    "high" => 4,
    "critical" => 5
  }

  @public_ioc_types ~w(hash_sha256 hash_sha1 hash_md5 domain url ip)
  @sensitive_ioc_types ~w(hostname username user path file_path command_line cmdline process_path image_path local_ip)

  @doc """
  Create an on-chain attestation for an alert.

  This is called automatically when an alert is created (if enabled).
  """
  @spec attest_alert(Alert.t()) :: {:ok, String.t()} | {:error, term()}
  def attest_alert(%Alert{} = alert) do
    params = build_attestation_params(alert)

    case Client.submit_attestation(params) do
      {:ok, signature} ->
        Logger.info("Alert #{alert.id} attested on Solana: #{signature}")
        {:ok, signature}

      {:error, reason} ->
        Logger.error("Failed to attest alert #{alert.id}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Create an on-chain attestation for an incident (alert with evidence).
  """
  @spec attest_incident(map()) :: {:ok, String.t()} | {:error, term()}
  def attest_incident(incident) do
    params = %{
      incident_hash: compute_incident_hash(incident),
      severity: Map.get(incident, :severity, 3),
      mitre_technique: Map.get(incident, :mitre_technique, "UNKNOWN"),
      rule_hash: compute_rule_hash(incident),
      org_pseudonym: pseudonymize(Map.get(incident, :organization_id)),
      agent_pseudonym: pseudonymize(Map.get(incident, :agent_id)),
      timestamp: Map.get(incident, :detected_at, DateTime.utc_now())
    }

    Client.submit_attestation(params)
  end

  @doc """
  Get the attestation for an alert from Solana.
  """
  @spec get_attestation(Alert.t()) :: {:ok, map()} | {:error, term()}
  def get_attestation(%Alert{} = alert) do
    incident_hash = compute_incident_hash(alert)
    Client.get_attestation(incident_hash)
  end

  @doc """
  Generate a Solscan URL for an alert's attestation transaction.
  """
  @spec solscan_url(Alert.t()) :: String.t() | nil
  def solscan_url(%Alert{blockchain_tx_id: nil}), do: nil
  def solscan_url(%Alert{blockchain_tx_id: tx_id}) do
    Client.solscan_url(tx_id)
  end

  @doc """
  Check if an alert has been attested on-chain.
  """
  @spec attested?(Alert.t()) :: boolean()
  def attested?(%Alert{blockchain_tx_id: nil}), do: false
  def attested?(%Alert{blockchain_tx_id: _}), do: true

  @doc """
  Create an on-chain endpoint security posture attestation.

  This is not a "clean endpoint" proof. It is a privacy-safe proof that the agent
  was monitored for a window and summarizes aggregate security posture only.
  """
  @spec attest_agent_health(Agent.t(), map()) :: {:ok, String.t()} | {:error, term()}
  def attest_agent_health(%Agent{} = agent, posture) when is_map(posture) do
    manifest = build_health_manifest(agent, posture)

    params = %{
      attestation_type: "endpoint_health",
      posture_hash: compute_manifest_hash(manifest),
      org_pseudonym: pseudonymize(agent.organization_id),
      agent_pseudonym: pseudonymize(agent.id),
      timestamp: Map.get(posture, :window_ended_at, DateTime.utc_now()),
      posture_status: manifest.status,
      critical_alerts: manifest.critical_alerts,
      high_alerts: manifest.high_alerts,
      active_alerts: manifest.active_alerts,
      window_hours: manifest.window_hours,
      policy_profile: manifest.policy_profile
    }

    case Client.submit_attestation(params) do
      {:ok, signature} ->
        Logger.info("Agent #{agent.id} health posture attested on Solana: #{signature}")
        {:ok, signature}

      {:error, reason} ->
        Logger.error("Failed to attest agent #{agent.id} health posture: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Build a privacy-safe endpoint posture manifest.

  The full manifest remains local/off-chain. The Solana memo stores only its hash
  plus compact aggregate fields. No hostname, IP address, username, local path, or
  raw telemetry is included.
  """
  @spec build_health_manifest(Agent.t(), map()) :: map()
  def build_health_manifest(%Agent{} = agent, posture) when is_map(posture) do
    window_started_at = Map.get(posture, :window_started_at, DateTime.add(DateTime.utc_now(), -24 * 60 * 60, :second))
    window_ended_at = Map.get(posture, :window_ended_at, DateTime.utc_now())
    critical_alerts = Map.get(posture, :critical_alerts, 0)
    high_alerts = Map.get(posture, :high_alerts, 0)
    active_alerts = Map.get(posture, :active_alerts, 0)
    attestation_window_hours = window_hours(window_started_at, window_ended_at)

    %{
      schema: "tamandua.endpoint_security_posture",
      version: 1,
      type: "endpoint_health",
      status: posture_status(agent, critical_alerts, high_alerts),
      agent_pseudonym: pseudonymize(agent.id) |> Base.encode16(case: :lower),
      org_pseudonym: pseudonymize(agent.organization_id) |> Base.encode16(case: :lower),
      agent_online: agent.status == "online",
      policy_profile: extract_policy_profile(agent),
      window_started_at: format_manifest_datetime(window_started_at),
      window_ended_at: format_manifest_datetime(window_ended_at),
      window_hours: attestation_window_hours,
      active_alerts: active_alerts,
      window_alerts: Map.get(posture, :window_alerts, 0),
      critical_alerts: critical_alerts,
      high_alerts: high_alerts,
      medium_alerts: Map.get(posture, :medium_alerts, 0),
      low_alerts: Map.get(posture, :low_alerts, 0),
      assertion: "monitored_endpoint_no_absolute_clean_claim",
      privacy: %{
        excludes: ["hostname", "ip_address", "username", "file_path", "command_line", "raw_telemetry"],
        includes: ["pseudonyms", "aggregate_alert_counts", "policy_profile", "time_window"]
      }
    }
  end

  # Private functions

  @doc """
  Build attestation parameters for Solana submission.

  ## v2 Attestation Schema (SOLANA-02)

  Required fields:
  - incident_hash: SHA256 of redacted alert payload
  - manifest_hash: SHA256 of public IOC manifest
  - severity: 1-5 (info/low/medium/high/critical)
  - mitre_technique: ATT&CK technique ID (e.g., T1555.003)
  - rule_hash: SHA256 of detection rule ID
  - org_pseudonym: SHA256 of organization ID
  - agent_pseudonym: SHA256 of agent ID
  - timestamp: Unix timestamp
  - ioc_count: Number of public IOCs
  - ioc_types: List of IOC types included
  - threat_class: infostealer/ransomware/c2/endpoint_threat
  - malware_family: Optional malware family name
  - tlp: Traffic Light Protocol (clear/amber)
  - confidence: Detection confidence 0.0-1.0
  """
  defp build_attestation_params(%Alert{} = alert) do
    manifest = build_public_manifest(alert)

    %{
      incident_hash: compute_incident_hash(alert),
      severity: severity_to_int(alert.severity),
      mitre_technique: extract_mitre_technique(alert),
      rule_hash: compute_rule_hash(alert),
      org_pseudonym: pseudonymize(alert.organization_id),
      agent_pseudonym: pseudonymize(alert.agent_id),
      timestamp: alert_timestamp(alert),
      manifest_hash: compute_manifest_hash(manifest),
      ioc_count: manifest.ioc_count,
      ioc_types: manifest.ioc_types,
      confidence: manifest.confidence,
      tlp: manifest.tlp,
      threat_class: manifest.threat_class,
      malware_family: manifest.malware_family
    }
  end

  @doc """
  Build the privacy-safe IOC manifest used by attestation v2.

  The full manifest remains local/off-chain. The Solana transaction stores only
  its hash plus compact summary fields, so the public record is useful without
  exposing tenant telemetry.
  """
  @spec build_public_manifest(Alert.t()) :: map()
  def build_public_manifest(%Alert{} = alert) do
    {public_iocs, redacted_count} =
      alert
      |> extract_alert_indicators()
      |> sanitize_indicators()

    ioc_types =
      public_iocs
      |> Enum.map(& &1.type)
      |> Enum.uniq()
      |> Enum.sort()

    %{
      schema: "tamandua.attestation_manifest",
      version: 2,
      tlp: classify_tlp(public_iocs, redacted_count),
      incident_hash: compute_incident_hash(alert) |> Base.encode16(case: :lower),
      severity: alert.severity || "medium",
      mitre_technique: extract_mitre_technique(alert),
      rule_hash: compute_rule_hash(alert) |> Base.encode16(case: :lower),
      ioc_count: length(public_iocs),
      ioc_types: ioc_types,
      redacted_ioc_count: redacted_count,
      confidence: extract_confidence(alert),
      threat_class: extract_threat_class(alert),
      malware_family: extract_malware_family(alert),
      # Use alert timestamp for determinism (PRIVACY-03)
      # Note: generated_at is NOT included in manifest_hash computation
      generated_at: alert_timestamp(alert) |> DateTime.to_iso8601(),
      iocs: Enum.take(public_iocs, 20)
    }
  end

  @doc """
  Compute a stable SHA256 hash for the local/off-chain public manifest.
  """
  @spec compute_manifest_hash(map()) :: binary()
  def compute_manifest_hash(manifest) when is_map(manifest) do
    manifest
    |> Jason.encode!()
    |> then(&:crypto.hash(:sha256, &1))
  end

  @doc """
  Compute the incident hash from an alert.

  This is a SHA256 hash of the redacted alert payload:
  - Alert ID
  - Severity
  - MITRE technique
  - Rule ID
  - Timestamp
  - Pseudonymized org/agent

  NO raw telemetry data is included.
  """
  def compute_incident_hash(%Alert{} = alert) do
    payload = [
      to_string(alert.id),
      to_string(alert.severity),
      extract_mitre_technique(alert),
      alert |> extract_rule_id() |> to_string(),
      DateTime.to_iso8601(alert_timestamp(alert)),
      pseudonymize(alert.organization_id) |> Base.encode16(case: :lower),
      pseudonymize(alert.agent_id) |> Base.encode16(case: :lower)
    ]
    |> Enum.join("|")

    :crypto.hash(:sha256, payload)
  end

  def compute_incident_hash(incident) when is_map(incident) do
    payload = [
      to_string(Map.get(incident, :id, UUID.uuid4())),
      to_string(Map.get(incident, :severity, "medium")),
      Map.get(incident, :mitre_technique, "UNKNOWN"),
      to_string(Map.get(incident, :rule_id, "unknown")),
      DateTime.to_iso8601(Map.get(incident, :detected_at, DateTime.utc_now())),
      pseudonymize(Map.get(incident, :organization_id)) |> Base.encode16(case: :lower),
      pseudonymize(Map.get(incident, :agent_id)) |> Base.encode16(case: :lower)
    ]
    |> Enum.join("|")

    :crypto.hash(:sha256, payload)
  end

  defp posture_status(%Agent{} = agent, critical_alerts, high_alerts) do
    cond do
      critical_alerts > 0 -> "critical"
      high_alerts > 0 -> "at_risk"
      agent.status != "online" -> "not_reporting"
      true -> "monitored"
    end
  end

  defp extract_policy_profile(%Agent{config: config}) when is_map(config) do
    get_field(config, :performance_profile) ||
      get_field(config, :profile) ||
      get_field(config, :policy_profile) ||
      "default"
  end

  defp extract_policy_profile(_), do: "default"

  defp window_hours(%DateTime{} = start_dt, %DateTime{} = end_dt) do
    max(DateTime.diff(end_dt, start_dt, :second), 0)
    |> div(3600)
  end

  defp window_hours(_, _), do: 24

  defp format_manifest_datetime(%DateTime{} = datetime), do: DateTime.to_iso8601(datetime)
  defp format_manifest_datetime(value), do: value

  defp compute_rule_hash(%Alert{} = alert) do
    :crypto.hash(:sha256, alert |> extract_rule_id() |> to_string())
  end

  defp compute_rule_hash(incident) when is_map(incident) do
    rule_id = Map.get(incident, :rule_id, UUID.uuid4())
    :crypto.hash(:sha256, to_string(rule_id))
  end

  defp extract_alert_indicators(%Alert{} = alert) do
    []
    |> Kernel.++(get_in_map(alert.evidence, ["indicators"]) || [])
    |> Kernel.++(get_in_map(alert.evidence, [:indicators]) || [])
    |> Kernel.++(get_in_map(alert.enrichment, ["indicators"]) || [])
    |> Kernel.++(get_in_map(alert.enrichment, [:indicators]) || [])
    |> Kernel.++(extract_raw_event_indicators(alert.raw_event || %{}))
    |> Kernel.++(extract_metadata_indicators(alert.detection_metadata || %{}))
  end

  defp extract_raw_event_indicators(payload) when is_map(payload) do
    [
      {"hash_sha256", get_field(payload, :sha256)},
      {"hash_sha1", get_field(payload, :sha1)},
      {"hash_md5", get_field(payload, :md5)},
      {"domain", get_field(payload, :domain) || get_field(payload, :query)},
      {"url", get_field(payload, :url)},
      {"ip", get_field(payload, :remote_ip) || get_field(payload, :dst_ip)}
    ]
    |> Enum.flat_map(fn
      {_type, nil} -> []
      {_type, ""} -> []
      {type, value} -> [%{type: type, value: to_string(value), source: "alert_payload"}]
    end)
  end

  defp extract_raw_event_indicators(_), do: []

  defp extract_metadata_indicators(metadata) when is_map(metadata) do
    metadata["iocs"] || metadata[:iocs] || metadata["indicators"] || metadata[:indicators] || []
  end

  defp sanitize_indicators(indicators) when is_list(indicators) do
    indicators
    |> Enum.reduce({[], 0}, fn indicator, {public, redacted} ->
      case normalize_indicator(indicator) do
        {:public, ioc} -> {[ioc | public], redacted}
        :redacted -> {public, redacted + 1}
        :skip -> {public, redacted}
      end
    end)
    |> then(fn {public, redacted} ->
      public =
        public
        |> Enum.uniq_by(fn ioc -> {ioc.type, ioc.value} end)
        |> Enum.sort_by(fn ioc -> {ioc.type, ioc.value} end)

      {public, redacted}
    end)
  end

  defp normalize_indicator(%{} = indicator) do
    type = get_field(indicator, :type) || get_field(indicator, :ioc_type)
    value = get_field(indicator, :value) || get_field(indicator, :ioc_value)
    source = get_field(indicator, :source)
    confidence = get_field(indicator, :confidence)

    normalize_indicator_value(type, value, source, confidence)
  end

  defp normalize_indicator({type, value}), do: normalize_indicator_value(type, value, nil, nil)
  defp normalize_indicator(_), do: :skip

  defp normalize_indicator_value(nil, _value, _source, _confidence), do: :skip
  defp normalize_indicator_value(_type, nil, _source, _confidence), do: :skip
  defp normalize_indicator_value(type, value, source, confidence) do
    type = normalize_ioc_type(type)
    value = value |> to_string() |> String.trim()

    cond do
      value == "" ->
        :skip

      type in @sensitive_ioc_types ->
        :redacted

      type not in @public_ioc_types ->
        :redacted

      type == "ip" and not public_ip?(value) ->
        :redacted

      type == "domain" and not public_domain?(value) ->
        :redacted

      type == "url" and not public_url?(value) ->
        :redacted

      true ->
        {:public,
         %{
           type: type,
           value: normalize_ioc_value(type, value),
           source: source || "tamandua",
           confidence: normalize_confidence(confidence)
         }
         |> reject_nil_values()}
    end
  end

  defp normalize_ioc_type(type) do
    type
    |> to_string()
    |> String.downcase()
    |> String.replace("-", "_")
    |> case do
      "sha256" -> "hash_sha256"
      "sha1" -> "hash_sha1"
      "md5" -> "hash_md5"
      "dns_query" -> "domain"
      other -> other
    end
  end

  defp normalize_ioc_value(type, value) when type in ["hash_sha256", "hash_sha1", "hash_md5", "domain", "ip"] do
    String.downcase(value)
  end

  defp normalize_ioc_value(_type, value), do: value

  defp public_ip?(value) do
    case :inet.parse_address(String.to_charlist(value)) do
      {:ok, {10, _, _, _}} -> false
      {:ok, {127, _, _, _}} -> false
      {:ok, {169, 254, _, _}} -> false
      {:ok, {172, b, _, _}} when b >= 16 and b <= 31 -> false
      {:ok, {192, 168, _, _}} -> false
      {:ok, {0, _, _, _}} -> false
      {:ok, {255, 255, 255, 255}} -> false
      {:ok, _} -> true
      _ -> false
    end
  end

  defp public_domain?(value) do
    domain = String.downcase(value)

    String.contains?(domain, ".") and
      not String.ends_with?(domain, ".local") and
      not String.ends_with?(domain, ".lan") and
      not String.ends_with?(domain, ".internal") and
      not String.ends_with?(domain, ".corp") and
      not String.contains?(domain, "\\")
  end

  defp public_url?(value) do
    case URI.parse(value) do
      %URI{scheme: scheme, host: host} when scheme in ["http", "https"] and is_binary(host) ->
        public_domain?(host) or public_ip?(host)

      _ ->
        false
    end
  end

  defp classify_tlp(_public_iocs, redacted_count) when redacted_count > 0, do: "amber"
  defp classify_tlp(_public_iocs, _redacted_count), do: "clear"

  defp extract_confidence(%Alert{} = alert) do
    value =
      get_field(alert.detection_metadata || %{}, :confidence) ||
        get_field(alert.enrichment || %{}, :confidence) ||
        alert.threat_score

    normalize_confidence(value)
  end

  defp normalize_confidence(nil), do: nil
  defp normalize_confidence(value) when is_integer(value), do: min(max(value / 100, 0.0), 1.0)
  defp normalize_confidence(value) when is_float(value) and value > 1.0, do: min(value / 100, 1.0)
  defp normalize_confidence(value) when is_float(value), do: min(max(value, 0.0), 1.0)
  defp normalize_confidence(value) when is_binary(value) do
    case Float.parse(value) do
      {number, _} -> normalize_confidence(number)
      :error -> nil
    end
  end
  defp normalize_confidence(_), do: nil

  defp extract_threat_class(%Alert{} = alert) do
    metadata = alert.detection_metadata || %{}
    enrichment = alert.enrichment || %{}

    get_field(metadata, :threat_class) ||
      get_field(metadata, :threat_type) ||
      get_field(enrichment, :threat_class) ||
      infer_threat_class(alert)
  end

  defp extract_malware_family(%Alert{} = alert) do
    metadata = alert.detection_metadata || %{}
    enrichment = alert.enrichment || %{}

    get_field(metadata, :malware_family) ||
      get_field(enrichment, :malware_family)
  end

  defp infer_threat_class(%Alert{} = alert) do
    text =
      [alert.title, alert.description, extract_mitre_technique(alert)]
      |> Enum.reject(&is_nil/1)
      |> Enum.join(" ")
      |> String.downcase()

    cond do
      String.contains?(text, ["stealer", "credential", "t1555", "cookie"]) -> "infostealer"
      String.contains?(text, ["ransomware", "t1486"]) -> "ransomware"
      String.contains?(text, ["c2", "command and control", "beacon"]) -> "c2"
      true -> "endpoint_threat"
    end
  end

  defp get_in_map(map, path) when is_map(map) do
    get_in(map, path)
  rescue
    _ -> nil
  end

  defp get_in_map(_map, _path), do: nil

  defp get_field(map, key) when is_map(map) and is_atom(key) do
    map[key] || map[Atom.to_string(key)]
  end

  defp reject_nil_values(map) when is_map(map) do
    map
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Map.new()
  end

  defp extract_mitre_technique(%Alert{mitre_techniques: [technique | _]}) when is_binary(technique) do
    technique
  end
  defp extract_mitre_technique(%Alert{mitre_techniques: [%{id: technique_id} | _]}) do
    technique_id
  end
  defp extract_mitre_technique(%Alert{detection_metadata: %{"mitre_technique" => technique}}) when is_binary(technique) do
    technique
  end
  defp extract_mitre_technique(%Alert{detection_metadata: %{mitre_technique: technique}}) when is_binary(technique) do
    technique
  end
  defp extract_mitre_technique(_), do: "UNKNOWN"

  defp extract_rule_id(%Alert{detection_metadata: metadata}) when is_map(metadata) do
    metadata["rule_id"] ||
      metadata[:rule_id] ||
      metadata["rule_name"] ||
      metadata[:rule_name] ||
      metadata["name"] ||
      metadata[:name] ||
      "unknown"
  end
  defp extract_rule_id(_), do: "unknown"

  defp alert_timestamp(%Alert{last_seen_at: %DateTime{} = dt}), do: dt
  defp alert_timestamp(%Alert{inserted_at: %DateTime{} = dt}), do: dt
  defp alert_timestamp(_), do: DateTime.utc_now()

  defp severity_to_int(severity) when is_binary(severity) do
    Map.get(@severity_map, String.downcase(severity), 3)
  end
  defp severity_to_int(severity) when is_integer(severity) and severity >= 1 and severity <= 5 do
    severity
  end
  defp severity_to_int(_), do: 3

  @doc """
  Pseudonymize an identifier using SHA256.

  This ensures no real org/agent IDs are exposed on-chain.
  """
  def pseudonymize(nil), do: :crypto.hash(:sha256, "tamandua:unknown")
  def pseudonymize(id) when is_binary(id) do
    :crypto.hash(:sha256, id)
  end
  def pseudonymize(id), do: pseudonymize(to_string(id))
end
