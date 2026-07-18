defmodule TamanduaServer.XDR.Parsers.CheckPoint do
  @moduledoc """
  Parser for Check Point firewall and security gateway logs.

  Supports:
  - SmartLog format (OPSEC LEA)
  - Log Exporter format
  - CEF format (via Check Point Log Exporter)
  - Syslog format

  ## Log Types

  - Firewall logs (FW)
  - VPN logs
  - Anti-Bot logs
  - Anti-Virus logs
  - Threat Emulation logs
  - IPS logs
  - Application Control logs
  - URL Filtering logs
  - DLP logs
  - Audit logs

  ## SmartLog Format

  Check Point SmartLog uses a key-value format with semicolon separators.
  """

  alias TamanduaServer.XDR.NormalizedEvent

  @behaviour TamanduaServer.XDR.Parser

  # Log type mapping
  @log_types %{
    "firewall" => :firewall,
    "vpn" => :vpn,
    "anti-bot" => :threat,
    "anti-virus" => :threat,
    "threat emulation" => :threat,
    "ips" => :ips,
    "application control" => :application,
    "url filtering" => :url,
    "dlp" => :dlp,
    "audit" => :audit,
    "smartdefense" => :ips,
    "identity awareness" => :identity
  }

  # Action mapping
  @action_mapping %{
    "accept" => "allowed",
    "allow" => "allowed",
    "drop" => "dropped",
    "reject" => "rejected",
    "block" => "blocked",
    "detect" => "detected",
    "prevent" => "prevented",
    "ask" => "prompted",
    "inform" => "informed",
    "bypass" => "bypassed",
    "encrypt" => "encrypted",
    "decrypt" => "decrypted"
  }

  # Severity mapping
  @severity_mapping %{
    "critical" => "critical",
    "high" => "high",
    "medium" => "medium",
    "low" => "low",
    "info" => "info",
    "informational" => "info"
  }

  # MITRE ATT&CK mapping by blade
  @mitre_mapping %{
    :threat => ["T1204", "T1059"],
    :ips => ["T1190", "T1210"],
    :url => ["T1071.001"],
    :vpn => ["T1133"],
    :dlp => ["T1048", "T1041"]
  }

  @impl true
  def parse(raw_log) when is_binary(raw_log) do
    cond do
      # Check for CEF format
      String.starts_with?(raw_log, "CEF:") ->
        parse_cef_format(raw_log)

      # Check for SmartLog key-value format
      String.contains?(raw_log, "product=") or String.contains?(raw_log, "action=") ->
        parse_smartlog_format(raw_log)

      # Try generic syslog format
      true ->
        parse_syslog_format(raw_log)
    end
  end

  @impl true
  def source_type, do: :firewall

  @impl true
  def vendor, do: "checkpoint"

  @impl true
  def product, do: "security-gateway"

  # ============================================================================
  # SmartLog Format Parsing
  # ============================================================================

  defp parse_smartlog_format(raw_log) do
    # Parse key=value pairs separated by semicolons or pipes
    pairs = raw_log
    |> String.split(~r/[;|]/)
    |> Enum.map(&String.trim/1)
    |> Enum.map(&parse_key_value/1)
    |> Enum.reject(&is_nil/1)
    |> Map.new()

    normalize_smartlog_event(pairs, raw_log)
  end

  defp parse_key_value(pair) do
    case String.split(pair, "=", parts: 2) do
      [key, value] ->
        key = key |> String.trim() |> String.downcase() |> String.replace(" ", "_")
        value = value |> String.trim() |> String.trim("\"")
        {key, value}
      _ -> nil
    end
  end

  defp normalize_smartlog_event(parsed, raw_log) do
    log_type = determine_log_type(parsed)
    action = Map.get(@action_mapping, String.downcase(parsed["action"] || ""), parsed["action"])
    severity = determine_severity(parsed, log_type)
    mitre = Map.get(@mitre_mapping, log_type, [])

    event = %{
      id: Ecto.UUID.generate(),
      timestamp: parse_checkpoint_timestamp(parsed["time"] || parsed["logtime"] || parsed["date"]),
      source_type: :firewall,
      vendor: "checkpoint",
      product: parsed["product"] || "security-gateway",
      raw_log: raw_log,
      action: action,
      category: to_string(log_type),
      severity: severity,
      source_ip: parsed["src"] || parsed["source"] || parsed["s_addr"],
      dest_ip: parsed["dst"] || parsed["destination"] || parsed["d_addr"],
      source_port: parse_port(parsed["s_port"] || parsed["src_port"]),
      dest_port: parse_port(parsed["d_port"] || parsed["dst_port"] || parsed["service_port"]),
      protocol: parsed["proto"] || parsed["protocol"] || parsed["ip_proto"],
      user: parsed["user"] || parsed["src_user_name"] || parsed["user_name"],
      rule_name: parsed["rule_name"] || parsed["rule"],
      rule_id: parsed["rule_uid"],
      policy_name: parsed["policy_name"] || parsed["policy"],
      interface: parsed["ifname"] || parsed["interface_name"],
      direction: parsed["ifdir"] || parsed["direction"],
      service: parsed["service"] || parsed["service_name"],
      application: parsed["app_name"] || parsed["application_name"],
      url: parsed["resource"] || parsed["url"],
      domain: parsed["domain"],
      file_name: parsed["file_name"],
      file_hash: parsed["file_md5"] || parsed["file_sha256"] || parsed["file_sha1"],
      threat_name: parsed["malware_name"] || parsed["attack_name"] || parsed["protection_name"],
      attack_info: parsed["attack_info"] || parsed["attack"],
      confidence: parsed["confidence_level"],
      protection_type: parsed["protection_type"],
      blade: parsed["blade"] || parsed["product"],
      origin: parsed["origin"] || parsed["orig"],
      nat_source_ip: parsed["xlatesrc"] || parsed["nat_src"],
      nat_dest_ip: parsed["xlatedst"] || parsed["nat_dst"],
      nat_source_port: parse_port(parsed["xlatesport"]),
      nat_dest_port: parse_port(parsed["xlatedport"]),
      bytes_sent: parse_int(parsed["sent_bytes"] || parsed["client_outbound_bytes"]),
      bytes_received: parse_int(parsed["received_bytes"] || parsed["client_inbound_bytes"]),
      packets: parse_int(parsed["packets"]),
      session_id: parsed["session_id"] || parsed["uid"],
      message: parsed["message_info"] || parsed["msg"] || parsed["description"],
      mitre_techniques: mitre
    }

    # Add VPN-specific fields
    event = if log_type == :vpn do
      Map.merge(event, %{
        vpn_peer: parsed["peer_gateway"] || parsed["peer"],
        vpn_community: parsed["community"],
        encryption_method: parsed["encryption_method"],
        ike_version: parsed["ike_version"]
      })
    else
      event
    end

    # Add threat-specific fields
    event = if log_type == :threat do
      Map.merge(event, %{
        malware_family: parsed["malware_family"],
        malware_action: parsed["malware_action"],
        te_verdict: parsed["verdict"]
      })
    else
      event
    end

    {:ok, NormalizedEvent.new(event)}
  end

  defp determine_log_type(parsed) do
    product = String.downcase(parsed["product"] || parsed["blade"] || "")

    cond do
      String.contains?(product, "anti-bot") -> :threat
      String.contains?(product, "anti-virus") -> :threat
      String.contains?(product, "threat") -> :threat
      String.contains?(product, "ips") or String.contains?(product, "smartdefense") -> :ips
      String.contains?(product, "application") -> :application
      String.contains?(product, "url") -> :url
      String.contains?(product, "dlp") -> :dlp
      String.contains?(product, "vpn") -> :vpn
      String.contains?(product, "identity") -> :identity
      String.contains?(product, "audit") -> :audit
      true -> :firewall
    end
  end

  defp determine_severity(parsed, log_type) do
    # Check explicit severity
    if severity = parsed["severity"] || parsed["attack_severity"] do
      Map.get(@severity_mapping, String.downcase(severity), "medium")
    else
      # Determine severity based on log type and action
      case log_type do
        :threat -> "high"
        :ips -> "high"
        :dlp -> "high"
        :firewall ->
          action = String.downcase(parsed["action"] || "")
          if action in ["drop", "reject", "block"], do: "medium", else: "info"
        _ -> "info"
      end
    end
  end

  # ============================================================================
  # CEF Format Parsing
  # ============================================================================

  defp parse_cef_format(raw_log) do
    # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    case String.split(raw_log, "|", parts: 8) do
      ["CEF:" <> version, _vendor, product, device_version, sig_id, name, severity | rest] ->
        extension = Enum.join(rest, "|")
        extension_map = parse_cef_extension(extension)

        event = %{
          id: Ecto.UUID.generate(),
          timestamp: parse_checkpoint_timestamp(extension_map["rt"] || extension_map["end"]),
          source_type: :firewall,
          vendor: "checkpoint",
          product: product,
          raw_log: raw_log,
          cef_version: version,
          device_version: device_version,
          signature_id: sig_id,
          name: name,
          severity: normalize_cef_severity(severity),
          action: extension_map["act"] || extension_map["deviceAction"],
          category: extension_map["cat"] || "firewall",
          source_ip: extension_map["src"] || extension_map["sourceAddress"],
          dest_ip: extension_map["dst"] || extension_map["destinationAddress"],
          source_port: parse_port(extension_map["spt"] || extension_map["sourcePort"]),
          dest_port: parse_port(extension_map["dpt"] || extension_map["destinationPort"]),
          protocol: extension_map["proto"] || extension_map["transportProtocol"],
          user: extension_map["suser"] || extension_map["sourceUserName"],
          dest_user: extension_map["duser"] || extension_map["destinationUserName"],
          bytes_in: parse_int(extension_map["in"] || extension_map["bytesIn"]),
          bytes_out: parse_int(extension_map["out"] || extension_map["bytesOut"]),
          message: extension_map["msg"] || extension_map["message"],
          request: extension_map["request"],
          url: extension_map["request"]
        }

        {:ok, NormalizedEvent.new(event)}

      _ ->
        {:error, :invalid_cef_format}
    end
  end

  defp parse_cef_extension(extension) do
    # Parse key=value pairs in CEF extension
    # Handle escaped characters and multi-word values
    Regex.scan(~r/(\w+)=([^\s]+(?:\s+(?![a-zA-Z]+=)[^\s]+)*)/, extension)
    |> Enum.map(fn [_, key, value] -> {key, String.trim(value)} end)
    |> Map.new()
  end

  defp normalize_cef_severity(severity) do
    case Integer.parse(severity) do
      {n, _} when n <= 3 -> "low"
      {n, _} when n <= 6 -> "medium"
      {n, _} when n <= 8 -> "high"
      {n, _} when n > 8 -> "critical"
      _ -> Map.get(@severity_mapping, String.downcase(severity), "medium")
    end
  end

  # ============================================================================
  # Syslog Format Parsing
  # ============================================================================

  defp parse_syslog_format(raw_log) do
    # Try to extract Check Point specific patterns
    # Format: timestamp hostname product: message
    case Regex.run(~r/^(\S+)\s+(\S+)\s+(\S+):\s*(.+)$/, raw_log) do
      [_, timestamp, hostname, product, message] ->
        # Parse the message as key-value pairs if possible
        pairs = parse_message_to_kv(message)

        event = %{
          id: Ecto.UUID.generate(),
          timestamp: parse_checkpoint_timestamp(timestamp),
          source_type: :firewall,
          vendor: "checkpoint",
          product: product,
          device_hostname: hostname,
          raw_log: raw_log,
          message: message,
          action: pairs["action"],
          source_ip: pairs["src"] || pairs["source"],
          dest_ip: pairs["dst"] || pairs["dest"],
          source_port: parse_port(pairs["sport"]),
          dest_port: parse_port(pairs["dport"]),
          protocol: pairs["proto"],
          user: pairs["user"],
          category: "firewall",
          severity: "info"
        }

        {:ok, NormalizedEvent.new(event)}

      nil ->
        # Fallback: just store the raw log
        {:ok, NormalizedEvent.new(%{
          id: Ecto.UUID.generate(),
          timestamp: DateTime.utc_now(),
          source_type: :firewall,
          vendor: "checkpoint",
          product: "security-gateway",
          raw_log: raw_log,
          message: raw_log,
          category: "firewall",
          severity: "info"
        })}
    end
  end

  defp parse_message_to_kv(message) do
    # Try to parse space-separated key=value pairs
    Regex.scan(~r/(\w+)=("[^"]*"|\S+)/, message)
    |> Enum.map(fn [_, key, value] ->
      value = String.trim(value, "\"")
      {String.downcase(key), value}
    end)
    |> Map.new()
  end

  # ============================================================================
  # Utility Functions
  # ============================================================================

  defp parse_checkpoint_timestamp(nil), do: DateTime.utc_now()
  defp parse_checkpoint_timestamp(timestamp_str) do
    # Check Point uses various timestamp formats
    formats = [
      # Unix timestamp
      :unix,
      # ISO 8601
      "{ISO:Extended}",
      # Check Point native format
      "{D}{Mshort}{YYYY} {h24}:{m}:{s}",
      # Standard formats
      "{YYYY}-{0M}-{0D} {h24}:{m}:{s}",
      "{YYYY}/{0M}/{0D} {h24}:{m}:{s}",
      "{Mshort} {D} {h24}:{m}:{s}"
    ]

    # Try unix timestamp first
    case Integer.parse(timestamp_str) do
      {unix_ts, ""} when unix_ts > 1_000_000_000 ->
        DateTime.from_unix!(unix_ts)
      {unix_ts, ""} when unix_ts > 1_000_000_000_000 ->
        DateTime.from_unix!(div(unix_ts, 1000))
      _ ->
        TamanduaServer.DateTimeParser.parse_utc!(timestamp_str)
    end
  rescue
    _ -> DateTime.utc_now()
  end

  defp parse_port(nil), do: nil
  defp parse_port(""), do: nil
  defp parse_port(port) when is_binary(port) do
    case Integer.parse(port) do
      {n, _} -> n
      :error -> nil
    end
  end
  defp parse_port(port) when is_integer(port), do: port

  defp parse_int(nil), do: nil
  defp parse_int(""), do: nil
  defp parse_int(value) when is_binary(value) do
    case Integer.parse(value) do
      {n, _} -> n
      :error -> nil
    end
  end
  defp parse_int(value) when is_integer(value), do: value
end
