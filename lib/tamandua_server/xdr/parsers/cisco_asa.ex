defmodule TamanduaServer.XDR.Parsers.CiscoASA do
  @moduledoc """
  Parser for Cisco ASA (Adaptive Security Appliance) firewall logs.

  Supports:
  - Syslog format messages
  - ASDM (Adaptive Security Device Manager) format
  - NetFlow records
  - VPN events
  - Access control events
  - Threat detection events

  ## Message Format

  Cisco ASA logs follow this pattern:
  `<priority>timestamp host %ASA-severity-message_id: message_text`

  ## Example Messages

  ```
  %ASA-6-302013: Built inbound TCP connection 12345 for outside:10.0.0.1/1234 to inside:192.168.1.1/80
  %ASA-4-106023: Deny tcp src outside:10.0.0.1/1234 dst inside:192.168.1.1/80 by access-group "outside_in"
  %ASA-1-106021: Deny protocol connection spoof from 10.0.0.1 to 192.168.1.1 on interface outside
  ```
  """

  alias TamanduaServer.XDR.NormalizedEvent

  @behaviour TamanduaServer.XDR.Parser

  # ASA message ID to action mapping
  @action_mapping %{
    # Connection events
    "302013" => "connection_built",
    "302014" => "connection_teardown",
    "302015" => "connection_built",
    "302016" => "connection_teardown",
    "302020" => "connection_built",
    "302021" => "connection_teardown",

    # Access control events
    "106001" => "denied",
    "106006" => "denied",
    "106007" => "denied",
    "106010" => "denied",
    "106011" => "denied",
    "106012" => "denied",
    "106014" => "denied",
    "106015" => "denied",
    "106017" => "denied",
    "106018" => "denied",
    "106020" => "denied",
    "106021" => "denied",
    "106022" => "denied",
    "106023" => "denied",
    "106100" => "acl_hit",

    # Attack events
    "106016" => "attack",
    "400000" => "ids_attack",
    "400001" => "ids_signature",
    "400002" => "ids_string",
    "400003" => "ids_sig_string",
    "400004" => "ids_shun",
    "400005" => "ids_exclude",
    "400006" => "ids_sig_disable",
    "400007" => "ids_sig_enable",
    "400008" => "ids_sig_update",
    "400009" => "ids_shun_removed",
    "400010" => "ids_block",
    "400011" => "ids_fragment_attack",
    "400012" => "ids_scan",
    "400013" => "ids_sweep",

    # NAT events
    "305009" => "nat_translation_built",
    "305010" => "nat_translation_teardown",
    "305011" => "nat_translation_built",
    "305012" => "nat_translation_teardown",

    # VPN events
    "713228" => "vpn_tunnel_built",
    "713229" => "vpn_tunnel_teardown",
    "722022" => "vpn_client_connected",
    "722023" => "vpn_client_disconnected",
    "722033" => "vpn_group_locked",
    "722034" => "vpn_group_unlocked",
    "722051" => "vpn_client_ip_assigned",
    "722053" => "vpn_client_statistics",

    # Authentication events
    "109001" => "auth_began",
    "109002" => "auth_succeeded",
    "109003" => "auth_failed",
    "109005" => "auth_succeeded",
    "109006" => "auth_succeeded",
    "109007" => "auth_failed",
    "109008" => "auth_succeeded",
    "109011" => "auth_ip_assigned",
    "109012" => "auth_completed",
    "109025" => "auth_session_end",
    "109026" => "auth_proxy_session",

    # Threat detection events
    "733100" => "threat_detected",
    "733101" => "threat_dropped",
    "733102" => "threat_scanning",
    "733103" => "threat_scanning",
    "733104" => "threat_shunned",
    "733105" => "threat_blocked",

    # System events
    "111008" => "user_executed",
    "111009" => "user_executed",
    "111010" => "user_session",
    "502103" => "user_privilege",
    "502111" => "config_changed",
    "611101" => "auth_failed",
    "611102" => "auth_failed"
  }

  # Severity mapping
  @severity_mapping %{
    "0" => "critical",  # Emergencies
    "1" => "critical",  # Alerts
    "2" => "critical",  # Critical
    "3" => "high",      # Errors
    "4" => "medium",    # Warnings
    "5" => "low",       # Notifications
    "6" => "info",      # Informational
    "7" => "info"       # Debugging
  }

  # MITRE ATT&CK mapping
  @mitre_mapping %{
    "denied" => ["T1090", "T1071"],
    "attack" => ["T1190", "T1210"],
    "ids_attack" => ["T1190", "T1210"],
    "ids_scan" => ["T1046"],
    "ids_sweep" => ["T1046"],
    "threat_scanning" => ["T1046"],
    "vpn_client_connected" => ["T1133"],
    "auth_failed" => ["T1110"],
    "threat_blocked" => ["T1562.004"]
  }

  @impl true
  def parse(raw_log) when is_binary(raw_log) do
    with {:ok, parsed} <- parse_asa_message(raw_log) do
      normalize_event(parsed)
    end
  end

  @impl true
  def source_type, do: :firewall

  @impl true
  def vendor, do: "cisco"

  @impl true
  def product, do: "asa"

  # ============================================================================
  # Parsing Logic
  # ============================================================================

  defp parse_asa_message(raw_log) do
    # Pattern: %ASA-severity-message_id: message_text
    case Regex.run(~r/%ASA-(\d)-(\d{6}):\s*(.+)$/s, raw_log) do
      [_, severity, message_id, message_text] ->
        {:ok, %{
          raw: raw_log,
          severity_level: severity,
          message_id: message_id,
          message_text: message_text,
          timestamp: extract_timestamp(raw_log)
        }}

      nil ->
        # Try alternative format with hostname
        case Regex.run(~r/(\S+)\s+%ASA-(\d)-(\d{6}):\s*(.+)$/s, raw_log) do
          [_, hostname, severity, message_id, message_text] ->
            {:ok, %{
              raw: raw_log,
              hostname: hostname,
              severity_level: severity,
              message_id: message_id,
              message_text: message_text,
              timestamp: extract_timestamp(raw_log)
            }}

          nil ->
            {:error, :invalid_format}
        end
    end
  end

  defp extract_timestamp(raw_log) do
    # Try various timestamp formats
    cond do
      # MMM DD HH:MM:SS
      match = Regex.run(~r/^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/, raw_log) ->
        parse_syslog_timestamp(Enum.at(match, 1))

      # YYYY-MM-DD HH:MM:SS
      match = Regex.run(~r/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/, raw_log) ->
        case NaiveDateTime.from_iso8601(String.replace(Enum.at(match, 1), " ", "T") <> ":00") do
          {:ok, naive} -> DateTime.from_naive!(naive, "Etc/UTC")
          _ -> DateTime.utc_now()
        end

      true ->
        DateTime.utc_now()
    end
  end

  defp parse_syslog_timestamp(timestamp_str) do
    # Parse "MMM DD HH:MM:SS" format
    now = DateTime.utc_now()
    year = now.year

    case Timex.parse(timestamp_str <> " #{year}", "{Mshort} {D} {h24}:{m}:{s} {YYYY}") do
      {:ok, datetime} -> datetime
      _ -> DateTime.utc_now()
    end
  rescue
    _ -> DateTime.utc_now()
  end

  defp normalize_event(parsed) do
    action = Map.get(@action_mapping, parsed.message_id, "unknown")
    severity = Map.get(@severity_mapping, parsed.severity_level, "info")
    mitre_techniques = Map.get(@mitre_mapping, action, [])

    # Parse message-specific details
    details = parse_message_details(parsed.message_id, parsed.message_text)

    event = %{
      id: Ecto.UUID.generate(),
      timestamp: parsed.timestamp,
      source_type: :firewall,
      vendor: "cisco",
      product: "asa",
      action: action,
      category: determine_category(action),
      severity: severity,
      message_id: parsed.message_id,
      description: parsed.message_text,
      raw_log: parsed.raw,
      mitre_techniques: mitre_techniques
    }

    # Merge parsed details
    event = Map.merge(event, details)

    # Add hostname if present
    event = if parsed[:hostname] do
      Map.put(event, :device_hostname, parsed.hostname)
    else
      event
    end

    {:ok, NormalizedEvent.new(event)}
  end

  defp determine_category(action) do
    cond do
      String.contains?(action, "connection") -> "network"
      String.contains?(action, "denied") -> "access_control"
      String.contains?(action, "attack") or String.contains?(action, "ids") -> "intrusion"
      String.contains?(action, "threat") -> "threat"
      String.contains?(action, "vpn") -> "vpn"
      String.contains?(action, "auth") -> "authentication"
      String.contains?(action, "nat") -> "translation"
      true -> "general"
    end
  end

  defp parse_message_details(message_id, message_text) do
    case message_id do
      # Connection built/teardown
      id when id in ["302013", "302014", "302015", "302016", "302020", "302021"] ->
        parse_connection_message(message_text)

      # Access denied
      id when id in ["106001", "106006", "106007", "106014", "106015", "106020", "106021", "106022", "106023"] ->
        parse_denied_message(message_text)

      # ACL hit
      "106100" ->
        parse_acl_message(message_text)

      # VPN events
      id when id in ["713228", "713229", "722022", "722023", "722051"] ->
        parse_vpn_message(message_text)

      # Authentication events
      id when id in ["109001", "109002", "109003", "109005", "109006", "109007", "109008"] ->
        parse_auth_message(message_text)

      # Threat detection
      id when id in ["733100", "733101", "733102", "733103", "733104", "733105"] ->
        parse_threat_message(message_text)

      # IDS events
      id when id in ["400000", "400001", "400002", "400003", "400010", "400011", "400012", "400013"] ->
        parse_ids_message(message_text)

      _ ->
        %{}
    end
  end

  defp parse_connection_message(text) do
    # Pattern: Built inbound TCP connection 12345 for outside:10.0.0.1/1234 (10.0.0.1/1234) to inside:192.168.1.1/80 (192.168.1.1/80)
    result = %{}

    # Extract protocol
    result = case Regex.run(~r/(TCP|UDP|ICMP|GRE|IPSEC)/i, text) do
      [_, protocol] -> Map.put(result, :protocol, String.downcase(protocol))
      _ -> result
    end

    # Extract direction
    result = case Regex.run(~r/(inbound|outbound)/i, text) do
      [_, direction] -> Map.put(result, :direction, String.downcase(direction))
      _ -> result
    end

    # Extract source interface and IP
    result = case Regex.run(~r/for\s+(\S+):(\d+\.\d+\.\d+\.\d+)\/(\d+)/, text) do
      [_, interface, ip, port] ->
        result
        |> Map.put(:source_interface, interface)
        |> Map.put(:source_ip, ip)
        |> Map.put(:source_port, String.to_integer(port))
      _ -> result
    end

    # Extract destination interface and IP
    result = case Regex.run(~r/to\s+(\S+):(\d+\.\d+\.\d+\.\d+)\/(\d+)/, text) do
      [_, interface, ip, port] ->
        result
        |> Map.put(:dest_interface, interface)
        |> Map.put(:dest_ip, ip)
        |> Map.put(:dest_port, String.to_integer(port))
      _ -> result
    end

    # Extract connection ID
    result = case Regex.run(~r/connection\s+(\d+)/, text) do
      [_, conn_id] -> Map.put(result, :connection_id, conn_id)
      _ -> result
    end

    # Extract bytes
    result = case Regex.run(~r/duration\s+(\S+)\s+bytes\s+(\d+)/, text) do
      [_, duration, bytes] ->
        result
        |> Map.put(:duration, duration)
        |> Map.put(:bytes, String.to_integer(bytes))
      _ -> result
    end

    result
  end

  defp parse_denied_message(text) do
    result = %{outcome: "denied"}

    # Extract protocol
    result = case Regex.run(~r/(tcp|udp|icmp|ip)\s+src/i, text) do
      [_, protocol] -> Map.put(result, :protocol, String.downcase(protocol))
      _ -> result
    end

    # Extract source
    result = case Regex.run(~r/src\s+(\S+):(\d+\.\d+\.\d+\.\d+)(?:\/(\d+))?/, text) do
      [_, interface, ip, port] ->
        result
        |> Map.put(:source_interface, interface)
        |> Map.put(:source_ip, ip)
        |> Map.put(:source_port, if(port, do: String.to_integer(port), else: nil))
      [_, interface, ip] ->
        result
        |> Map.put(:source_interface, interface)
        |> Map.put(:source_ip, ip)
      _ -> result
    end

    # Extract destination
    result = case Regex.run(~r/dst\s+(\S+):(\d+\.\d+\.\d+\.\d+)(?:\/(\d+))?/, text) do
      [_, interface, ip, port] ->
        result
        |> Map.put(:dest_interface, interface)
        |> Map.put(:dest_ip, ip)
        |> Map.put(:dest_port, if(port, do: String.to_integer(port), else: nil))
      [_, interface, ip] ->
        result
        |> Map.put(:dest_interface, interface)
        |> Map.put(:dest_ip, ip)
      _ -> result
    end

    # Extract access group
    result = case Regex.run(~r/by\s+access-group\s+"([^"]+)"/, text) do
      [_, acl_name] -> Map.put(result, :acl_name, acl_name)
      _ -> result
    end

    result
  end

  defp parse_acl_message(text) do
    result = %{}

    # Extract ACL details
    result = case Regex.run(~r/access-list\s+(\S+)\s+(permitted|denied)/, text) do
      [_, acl_name, action] ->
        result
        |> Map.put(:acl_name, acl_name)
        |> Map.put(:outcome, action)
      _ -> result
    end

    # Extract protocol and IPs
    Map.merge(result, parse_denied_message(text))
  end

  defp parse_vpn_message(text) do
    result = %{}

    # Extract VPN user
    result = case Regex.run(~r/user\s*[=:]?\s*['"]?(\S+?)['"]?(?:\s|$)/i, text) do
      [_, user] -> Map.put(result, :user, user)
      _ -> result
    end

    # Extract client IP
    result = case Regex.run(~r/(?:client|peer)\s+(?:IP|address)[:\s]+(\d+\.\d+\.\d+\.\d+)/i, text) do
      [_, ip] -> Map.put(result, :source_ip, ip)
      _ -> result
    end

    # Extract assigned IP
    result = case Regex.run(~r/assigned\s+(?:IP|address)[:\s]+(\d+\.\d+\.\d+\.\d+)/i, text) do
      [_, ip] -> Map.put(result, :assigned_ip, ip)
      _ -> result
    end

    # Extract tunnel type
    result = case Regex.run(~r/(IKEv[12]|IPSec|SSL|AnyConnect)/i, text) do
      [_, tunnel_type] -> Map.put(result, :tunnel_type, tunnel_type)
      _ -> result
    end

    # Extract group
    result = case Regex.run(~r/group\s*[=:]?\s*['"]?(\S+?)['"]?(?:\s|$)/i, text) do
      [_, group] -> Map.put(result, :vpn_group, group)
      _ -> result
    end

    result
  end

  defp parse_auth_message(text) do
    result = %{}

    # Extract user
    result = case Regex.run(~r/user\s*[=:]?\s*['"]?(\S+?)['"]?\s+from/i, text) do
      [_, user] -> Map.put(result, :user, user)
      _ -> result
    end

    # Extract source IP
    result = case Regex.run(~r/from\s+(\d+\.\d+\.\d+\.\d+)/i, text) do
      [_, ip] -> Map.put(result, :source_ip, ip)
      _ -> result
    end

    # Extract server
    result = case Regex.run(~r/(?:to|server)\s+(\S+)/i, text) do
      [_, server] -> Map.put(result, :auth_server, server)
      _ -> result
    end

    # Determine outcome
    result = cond do
      String.contains?(text, "succeeded") -> Map.put(result, :outcome, "success")
      String.contains?(text, "failed") -> Map.put(result, :outcome, "failure")
      String.contains?(text, "denied") -> Map.put(result, :outcome, "failure")
      true -> result
    end

    result
  end

  defp parse_threat_message(text) do
    result = %{}

    # Extract threat type
    result = case Regex.run(~r/threat\s+rate\s+(\S+)/i, text) do
      [_, threat_type] -> Map.put(result, :threat_type, threat_type)
      _ -> result
    end

    # Extract source IP
    result = case Regex.run(~r/(?:from|host)\s+(\d+\.\d+\.\d+\.\d+)/i, text) do
      [_, ip] -> Map.put(result, :source_ip, ip)
      _ -> result
    end

    # Extract rate
    result = case Regex.run(~r/rate\s+(\d+)\s+per\s+(\w+)/i, text) do
      [_, rate, period] ->
        result
        |> Map.put(:rate, String.to_integer(rate))
        |> Map.put(:rate_period, period)
      _ -> result
    end

    result
  end

  defp parse_ids_message(text) do
    result = %{}

    # Extract signature ID
    result = case Regex.run(~r/sig[:\s]+(\d+)/i, text) do
      [_, sig_id] -> Map.put(result, :signature_id, sig_id)
      _ -> result
    end

    # Extract signature name
    result = case Regex.run(~r/sig\s+name[:\s]+(.+?)(?:\s+from|$)/i, text) do
      [_, sig_name] -> Map.put(result, :signature_name, String.trim(sig_name))
      _ -> result
    end

    # Extract attacker IP
    result = case Regex.run(~r/from\s+(\d+\.\d+\.\d+\.\d+)/i, text) do
      [_, ip] -> Map.put(result, :source_ip, ip)
      _ -> result
    end

    # Extract target IP
    result = case Regex.run(~r/to\s+(\d+\.\d+\.\d+\.\d+)/i, text) do
      [_, ip] -> Map.put(result, :dest_ip, ip)
      _ -> result
    end

    result
  end
end
