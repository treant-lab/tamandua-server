defmodule TamanduaServer.XDR.Sources.Firewall do
  @moduledoc """
  XDR source connector for firewall logs.

  Supports:
  - Palo Alto Networks (PAN-OS)
  - Fortinet FortiGate
  - Cisco ASA
  - Check Point
  - Sophos XG

  Each vendor has specific field mappings to normalize to the XDR schema.
  """

  require Logger


  @vendors %{
    "palo_alto" => &__MODULE__.parse_palo_alto/1,
    "fortinet" => &__MODULE__.parse_fortinet/1,
    "cisco_asa" => &__MODULE__.parse_cisco_asa/1,
    "checkpoint" => &__MODULE__.parse_checkpoint/1,
    "sophos" => &__MODULE__.parse_sophos/1
  }

  @doc """
  Parse a firewall log event.

  ## Options
  - :vendor - Specific vendor (palo_alto, fortinet, cisco_asa, checkpoint, sophos)
  """
  @spec parse(map() | binary(), keyword()) :: {:ok, map()} | {:error, term()}
  def parse(data, opts \\ []) do
    vendor = Keyword.get(opts, :vendor)

    cond do
      vendor && Map.has_key?(@vendors, vendor) ->
        parser = Map.get(@vendors, vendor)
        parser.(data)

      is_map(data) ->
        detect_and_parse_map(data)

      is_binary(data) ->
        detect_and_parse_string(data)

      true ->
        {:error, :invalid_input}
    end
  end

  # Vendor detection

  defp detect_and_parse_map(data) do
    cond do
      # Palo Alto has specific fields
      Map.has_key?(data, "FUTURE_USE") or Map.has_key?(data, "Receive Time") ->
        parse_palo_alto(data)

      # Fortinet uses devname, srcip, dstip
      Map.has_key?(data, "devname") and Map.has_key?(data, "srcip") ->
        parse_fortinet(data)

      # Cisco ASA messages have ASA- prefix in message ID
      (data["message_id"] || "") |> String.contains?("ASA-") ->
        parse_cisco_asa(data)

      # Check Point uses fw1_ fields
      Map.has_key?(data, "product") and data["product"] == "VPN-1 & FireWall-1" ->
        parse_checkpoint(data)

      true ->
        # Generic firewall parsing
        parse_generic_firewall(data)
    end
  end

  defp detect_and_parse_string(data) do
    cond do
      String.contains?(data, "TRAFFIC,") or String.contains?(data, "THREAT,") ->
        # Palo Alto CSV format
        parse_palo_alto_csv(data)

      String.contains?(data, "devname=") and String.contains?(data, "srcip=") ->
        # Fortinet key=value format
        parse_fortinet_kv(data)

      String.contains?(data, "%ASA-") ->
        # Cisco ASA syslog format
        parse_cisco_asa_syslog(data)

      true ->
        {:error, :unknown_vendor}
    end
  end

  # Palo Alto Networks Parsing

  @doc false
  def parse_palo_alto(data) when is_map(data) do
    event = %{
      timestamp: parse_palo_timestamp(data["Receive Time"] || data["receive_time"]),
      source_type: "firewall",
      device_vendor: "Palo Alto Networks",
      source_ip: data["Source Address"] || data["src"],
      source_port: parse_int(data["Source Port"] || data["sport"]),
      dest_ip: data["Destination Address"] || data["dst"],
      dest_port: parse_int(data["Destination Port"] || data["dport"]),
      network_protocol: data["Protocol"] || data["proto"],
      network_transport: data["Application"] || data["app"],
      action: normalize_pan_action(data["Action"] || data["action"]),
      user_name: data["Source User"] || data["srcuser"],
      dest_user: data["Destination User"] || data["dstuser"],
      rule_name: data["Rule"] || data["rule"],
      threat_name: data["Threat/Content Name"] || data["threatid"],
      threat_category: data["Threat Category"] || data["category"],
      severity: normalize_pan_severity(data["Severity"] || data["severity"]),
      url: data["URL/Filename"] || data["misc"],
      file_name: data["File/URL"] || data["filedigest"],
      bytes_in: parse_int(data["Bytes Received"] || data["bytes_received"]),
      bytes_out: parse_int(data["Bytes Sent"] || data["bytes_sent"]),
      network_direction: normalize_direction(data["Direction"] || data["direction"]),
      parsed_fields: data
    }

    # Add MITRE mappings for threat events
    event = if event[:threat_name] do
      Map.merge(event, pan_threat_to_mitre(event[:threat_category]))
    else
      event
    end

    {:ok, event}
  end

  defp parse_palo_alto_csv(line) do
    # Palo Alto CSV format varies by log type
    fields = String.split(line, ",")

    case Enum.at(fields, 3) do
      "TRAFFIC" -> parse_pan_traffic_csv(fields)
      "THREAT" -> parse_pan_threat_csv(fields)
      _ -> {:error, :unknown_pan_log_type}
    end
  end

  defp parse_pan_traffic_csv(fields) do
    # PAN-OS traffic log CSV format (simplified - actual has many more fields)
    event = %{
      timestamp: parse_palo_timestamp(Enum.at(fields, 1)),
      source_type: "firewall",
      device_vendor: "Palo Alto Networks",
      event_type: "traffic",
      source_ip: Enum.at(fields, 7),
      dest_ip: Enum.at(fields, 8),
      source_port: parse_int(Enum.at(fields, 24)),
      dest_port: parse_int(Enum.at(fields, 25)),
      network_protocol: Enum.at(fields, 29),
      network_transport: Enum.at(fields, 14),
      action: normalize_pan_action(Enum.at(fields, 30)),
      rule_name: Enum.at(fields, 11),
      severity: "info"
    }

    {:ok, event}
  end

  defp parse_pan_threat_csv(fields) do
    event = %{
      timestamp: parse_palo_timestamp(Enum.at(fields, 1)),
      source_type: "firewall",
      device_vendor: "Palo Alto Networks",
      event_type: "threat",
      source_ip: Enum.at(fields, 7),
      dest_ip: Enum.at(fields, 8),
      source_port: parse_int(Enum.at(fields, 24)),
      dest_port: parse_int(Enum.at(fields, 25)),
      network_protocol: Enum.at(fields, 29),
      action: normalize_pan_action(Enum.at(fields, 30)),
      threat_name: Enum.at(fields, 31),
      threat_category: Enum.at(fields, 32),
      severity: normalize_pan_severity(Enum.at(fields, 35))
    }

    {:ok, event}
  end

  defp parse_palo_timestamp(nil), do: DateTime.utc_now()
  defp parse_palo_timestamp(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ ->
        # Try PAN format: "2023/01/15 10:30:00"
        case Regex.run(~r/^(\d{4})\/(\d{2})\/(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/, ts) do
          [_, y, m, d, h, min, s] ->
            case NaiveDateTime.new(
              String.to_integer(y), String.to_integer(m), String.to_integer(d),
              String.to_integer(h), String.to_integer(min), String.to_integer(s)
            ) do
              {:ok, ndt} -> DateTime.from_naive!(ndt, "Etc/UTC")
              _ -> DateTime.utc_now()
            end
          _ -> DateTime.utc_now()
        end
    end
  end

  defp normalize_pan_action(nil), do: "unknown"
  defp normalize_pan_action(action) when is_binary(action) do
    case String.downcase(action) do
      a when a in ["allow", "allowed"] -> "allow"
      a when a in ["deny", "denied", "drop"] -> "deny"
      a when a in ["block", "blocked", "reset-both", "reset-client", "reset-server"] -> "block"
      a when a in ["alert"] -> "alert"
      _ -> "unknown"
    end
  end

  defp normalize_pan_severity(nil), do: "info"
  defp normalize_pan_severity(sev) when is_binary(sev) do
    case String.downcase(sev) do
      "critical" -> "critical"
      "high" -> "high"
      "medium" -> "medium"
      "low" -> "low"
      "informational" -> "info"
      _ -> "info"
    end
  end

  defp pan_threat_to_mitre(nil), do: %{}
  defp pan_threat_to_mitre(category) when is_binary(category) do
    case String.downcase(category) do
      cat when cat in ["malware", "virus", "spyware"] ->
        %{mitre_tactics: ["execution"], mitre_techniques: ["T1204"]}
      cat when cat in ["command-and-control", "c2"] ->
        %{mitre_tactics: ["command_and_control"], mitre_techniques: ["T1071"]}
      cat when cat in ["exploit", "vulnerability"] ->
        %{mitre_tactics: ["initial_access"], mitre_techniques: ["T1190"]}
      cat when cat in ["phishing", "email-link"] ->
        %{mitre_tactics: ["initial_access"], mitre_techniques: ["T1566"]}
      _ -> %{}
    end
  end

  # Fortinet Parsing

  @doc false
  def parse_fortinet(data) when is_map(data) do
    event = %{
      timestamp: parse_fortinet_timestamp(data["date"], data["time"]),
      source_type: "firewall",
      device_vendor: "Fortinet",
      source_name: data["devname"],
      source_ip: data["srcip"],
      source_port: parse_int(data["srcport"]),
      dest_ip: data["dstip"],
      dest_port: parse_int(data["dstport"]),
      network_protocol: data["proto"],
      network_transport: data["service"] || data["app"],
      action: normalize_fortinet_action(data["action"]),
      outcome: normalize_fortinet_outcome(data["status"]),
      user_name: data["user"] || data["srcname"],
      rule_name: data["policyname"] || data["policyid"],
      threat_name: data["attack"] || data["virus"],
      threat_category: data["attackname"] || data["viruscat"],
      severity: normalize_fortinet_severity(data["level"]),
      url: data["hostname"],
      bytes_in: parse_int(data["rcvdbyte"]),
      bytes_out: parse_int(data["sentbyte"]),
      network_direction: normalize_fortinet_direction(data["direction"]),
      parsed_fields: data
    }

    {:ok, event}
  end

  defp parse_fortinet_kv(line) do
    # Parse key=value format
    data = Regex.scan(~r/(\w+)=(?:"([^"]*)"|(\S+))/, line)
    |> Enum.reduce(%{}, fn
      [_, key, quoted, ""], acc -> Map.put(acc, key, quoted)
      [_, key, "", unquoted], acc -> Map.put(acc, key, unquoted)
      _, acc -> acc
    end)

    parse_fortinet(data)
  end

  defp parse_fortinet_timestamp(date, time) when is_binary(date) and is_binary(time) do
    case DateTime.from_iso8601("#{date}T#{time}Z") do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end
  defp parse_fortinet_timestamp(_, _), do: DateTime.utc_now()

  defp normalize_fortinet_action(nil), do: "unknown"
  defp normalize_fortinet_action(action) when is_binary(action) do
    case String.downcase(action) do
      "accept" -> "allow"
      "deny" -> "deny"
      "drop" -> "block"
      "close" -> "allow"
      a -> a
    end
  end

  defp normalize_fortinet_outcome(nil), do: "unknown"
  defp normalize_fortinet_outcome(status) when is_binary(status) do
    case String.downcase(status) do
      "success" -> "success"
      "failure" -> "failure"
      _ -> "unknown"
    end
  end

  defp normalize_fortinet_severity(nil), do: "info"
  defp normalize_fortinet_severity(level) when is_binary(level) do
    case String.downcase(level) do
      "critical" -> "critical"
      "alert" -> "high"
      "emergency" -> "critical"
      "error" -> "high"
      "warning" -> "medium"
      "notice" -> "low"
      _ -> "info"
    end
  end

  defp normalize_fortinet_direction(nil), do: nil
  defp normalize_fortinet_direction(dir) when is_binary(dir) do
    case String.downcase(dir) do
      "outgoing" -> "outbound"
      "incoming" -> "inbound"
      d -> d
    end
  end

  # Cisco ASA Parsing

  @doc false
  def parse_cisco_asa(data) when is_map(data) do
    event = %{
      timestamp: data["timestamp"] || DateTime.utc_now(),
      source_type: "firewall",
      device_vendor: "Cisco",
      device_product: "ASA",
      source_ip: data["src_ip"] || data["source_address"],
      source_port: parse_int(data["src_port"] || data["source_port"]),
      dest_ip: data["dst_ip"] || data["destination_address"],
      dest_port: parse_int(data["dst_port"] || data["destination_port"]),
      network_protocol: data["protocol"],
      action: normalize_asa_action(data["action"]),
      user_name: data["user"],
      rule_name: data["acl_name"] || data["access_group"],
      severity: normalize_asa_severity(data["severity"]),
      message: data["message"],
      signature_id: data["message_id"],
      network_direction: normalize_asa_direction(data["direction"]),
      parsed_fields: data
    }

    {:ok, event}
  end

  defp parse_cisco_asa_syslog(line) do
    # Parse ASA syslog format: "%ASA-severity-message_id: message"
    case Regex.run(~r/%ASA-(\d)-(\d+):\s*(.*)/, line) do
      [_, severity, msg_id, message] ->
        # Extract IPs and ports from message
        {src_ip, src_port} = extract_asa_address(message, "source")
        {dst_ip, dst_port} = extract_asa_address(message, "dest")

        data = %{
          "severity" => severity,
          "message_id" => "ASA-" <> msg_id,
          "message" => message,
          "src_ip" => src_ip,
          "src_port" => src_port,
          "dst_ip" => dst_ip,
          "dst_port" => dst_port,
          "action" => extract_asa_action(msg_id, message)
        }

        parse_cisco_asa(data)

      _ ->
        {:error, :invalid_asa_format}
    end
  end

  defp extract_asa_address(message, type) do
    pattern = if type == "source" do
      ~r/(?:from|src)\s+(?:inside:|outside:)?(\d+\.\d+\.\d+\.\d+)(?:\/(\d+))?/i
    else
      ~r/(?:to|dst)\s+(?:inside:|outside:)?(\d+\.\d+\.\d+\.\d+)(?:\/(\d+))?/i
    end

    case Regex.run(pattern, message) do
      [_, ip, port] -> {ip, port}
      [_, ip] -> {ip, nil}
      _ -> {nil, nil}
    end
  end

  defp extract_asa_action(msg_id, message) do
    # Common ASA message IDs and their actions
    case msg_id do
      id when id in ["106001", "106006", "106007", "106014", "106015", "106100"] -> "deny"
      id when id in ["302013", "302014", "302015", "302016", "302020", "302021"] -> "allow"
      id when id in ["113004", "113005"] -> "allow"  # AAA success
      id when id in ["113006", "113015", "113019"] -> "deny"  # AAA failure
      _ ->
        # Try to infer from message
        msg_lower = String.downcase(message)
        cond do
          String.contains?(msg_lower, ["denied", "deny", "drop"]) -> "deny"
          String.contains?(msg_lower, ["permitted", "built", "teardown"]) -> "allow"
          true -> "unknown"
        end
    end
  end

  defp normalize_asa_action(nil), do: "unknown"
  defp normalize_asa_action(action) when is_binary(action) do
    case String.downcase(action) do
      a when a in ["permit", "permitted", "built", "teardown"] -> "allow"
      a when a in ["deny", "denied", "drop", "dropped"] -> "deny"
      a -> a
    end
  end

  defp normalize_asa_severity(nil), do: "info"
  defp normalize_asa_severity(sev) when is_binary(sev) do
    case sev do
      "0" -> "critical"  # Emergency
      "1" -> "critical"  # Alert
      "2" -> "critical"  # Critical
      "3" -> "high"      # Error
      "4" -> "medium"    # Warning
      "5" -> "low"       # Notification
      "6" -> "info"      # Informational
      "7" -> "info"      # Debugging
      _ -> "info"
    end
  end

  defp normalize_asa_direction(nil), do: nil
  defp normalize_asa_direction(dir) when is_binary(dir) do
    case String.downcase(dir) do
      d when d in ["inside", "internal"] -> "inbound"
      d when d in ["outside", "external"] -> "outbound"
      d -> d
    end
  end

  # Check Point Parsing

  @doc false
  def parse_checkpoint(data) when is_map(data) do
    event = %{
      timestamp: parse_checkpoint_timestamp(data),
      source_type: "firewall",
      device_vendor: "Check Point",
      device_product: data["product"],
      source_ip: data["src"] || data["origin"],
      source_port: parse_int(data["s_port"]),
      dest_ip: data["dst"],
      dest_port: parse_int(data["service"]),
      network_protocol: data["proto"],
      action: normalize_checkpoint_action(data["action"]),
      user_name: data["user"] || data["src_user_name"],
      rule_name: data["rule_name"] || data["rule"],
      severity: normalize_checkpoint_severity(data["severity"]),
      message: data["message"] || data["info"],
      parsed_fields: data
    }

    {:ok, event}
  end

  defp parse_checkpoint_timestamp(data) do
    # Check Point uses multiple timestamp fields
    ts = data["time"] || data["logtime"] || data["i/f_dir"]

    case DateTime.from_iso8601(to_string(ts)) do
      {:ok, dt, _} -> dt
      _ ->
        # Try Unix timestamp
        case Integer.parse(to_string(ts)) do
          {epoch, _} ->
            case DateTime.from_unix(epoch) do
              {:ok, dt} -> dt
              _ -> DateTime.utc_now()
            end
          _ -> DateTime.utc_now()
        end
    end
  end

  defp normalize_checkpoint_action(nil), do: "unknown"
  defp normalize_checkpoint_action(action) when is_binary(action) do
    case String.downcase(action) do
      "accept" -> "allow"
      "drop" -> "block"
      "reject" -> "deny"
      "block" -> "block"
      a -> a
    end
  end

  defp normalize_checkpoint_severity(nil), do: "info"
  defp normalize_checkpoint_severity(sev) when is_binary(sev) do
    case String.downcase(sev) do
      "critical" -> "critical"
      "high" -> "high"
      "medium" -> "medium"
      "low" -> "low"
      _ -> "info"
    end
  end

  # Sophos Parsing

  @doc false
  def parse_sophos(data) when is_map(data) do
    event = %{
      timestamp: data["timestamp"] || DateTime.utc_now(),
      source_type: "firewall",
      device_vendor: "Sophos",
      source_ip: data["srcip"] || data["src_ip"],
      source_port: parse_int(data["srcport"]),
      dest_ip: data["dstip"] || data["dst_ip"],
      dest_port: parse_int(data["dstport"]),
      network_protocol: data["proto"],
      network_transport: data["app"],
      action: normalize_sophos_action(data["fw_rule_action"]),
      user_name: data["user"],
      rule_name: data["fw_rule_name"],
      severity: "info",
      parsed_fields: data
    }

    {:ok, event}
  end

  defp normalize_sophos_action(nil), do: "unknown"
  defp normalize_sophos_action(action) when is_binary(action) do
    case String.downcase(action) do
      "allow" -> "allow"
      "drop" -> "block"
      "deny" -> "deny"
      a -> a
    end
  end

  # Generic Firewall Parsing

  defp parse_generic_firewall(data) do
    event = %{
      timestamp: data["timestamp"] || DateTime.utc_now(),
      source_type: "firewall",
      source_ip: data["src_ip"] || data["srcip"] || data["source_ip"],
      source_port: parse_int(data["src_port"] || data["srcport"]),
      dest_ip: data["dst_ip"] || data["dstip"] || data["dest_ip"],
      dest_port: parse_int(data["dst_port"] || data["dstport"]),
      network_protocol: data["proto"] || data["protocol"],
      action: data["action"],
      user_name: data["user"],
      severity: data["severity"] || "info",
      parsed_fields: data
    }

    {:ok, event}
  end

  # Helpers

  defp normalize_direction(nil), do: nil
  defp normalize_direction(dir) when is_binary(dir) do
    case String.downcase(dir) do
      d when d in ["inbound", "in", "ingress", "incoming", "client-to-server"] -> "inbound"
      d when d in ["outbound", "out", "egress", "outgoing", "server-to-client"] -> "outbound"
      d when d in ["internal", "lateral"] -> "internal"
      _ -> nil
    end
  end

  defp parse_int(nil), do: nil
  defp parse_int(val) when is_integer(val), do: val
  defp parse_int(val) when is_binary(val) do
    case Integer.parse(val) do
      {i, _} -> i
      _ -> nil
    end
  end
  defp parse_int(_), do: nil
end
