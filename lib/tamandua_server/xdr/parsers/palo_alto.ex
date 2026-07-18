defmodule TamanduaServer.XDR.Parsers.PaloAlto do
  @moduledoc """
  Parser for Palo Alto Networks firewall logs.

  Supports:
  - Traffic logs
  - Threat logs
  - URL filtering logs
  - WildFire logs
  - Authentication logs
  - GlobalProtect logs
  - System logs

  ## Log Format

  Palo Alto uses CSV format with predefined fields for each log type.
  The log type is identified by the "type" field in position 3.

  ## Example Traffic Log

  ```
  1,2024/01/15 10:30:00,serial,TRAFFIC,end,2049,2024/01/15 10:30:00,192.168.1.10,10.0.0.50,0.0.0.0,0.0.0.0,allow-all,,,web-browsing,vsys1,trust,untrust,ethernet1/1,ethernet1/2,Log Forwarding Profile,2024/01/15 10:30:00,12345,1,54321,443,0,0,0x19,tcp,allow,1234,567,890,5,2024/01/15 10:29:55,0,any,0,1234567890,0x8000000000000000,192.168.0.0-192.168.255.255,United States,0,5,5,aged-out,0,0,0,0,,PA-820,from-policy,,,0,,0,,N/A,0,0,0,0,af0c9f4e-27e1-4f0f-8c22-a87c63dee6d3
  ```
  """

  alias TamanduaServer.XDR.NormalizedEvent

  @behaviour TamanduaServer.XDR.Parser

  # Log type definitions
  @log_types %{
    "TRAFFIC" => :traffic,
    "THREAT" => :threat,
    "URL" => :url,
    "WILDFIRE" => :wildfire,
    "DATA" => :data,
    "CONFIG" => :config,
    "SYSTEM" => :system,
    "CORRELATED" => :correlated,
    "GTP" => :gtp,
    "SCTP" => :sctp,
    "AUTHENTICATION" => :authentication,
    "USERID" => :userid,
    "GLOBALPROTECT" => :globalprotect
  }

  # Traffic log action mapping
  @traffic_actions %{
    "allow" => "allowed",
    "deny" => "denied",
    "drop" => "dropped",
    "reset-client" => "reset",
    "reset-server" => "reset",
    "reset-both" => "reset"
  }

  # Threat type mapping
  @threat_types %{
    "virus" => "malware",
    "spyware" => "spyware",
    "vulnerability" => "exploit",
    "url" => "url_filtering",
    "wildfire" => "malware",
    "wildfire-virus" => "malware",
    "flood" => "dos",
    "scan" => "reconnaissance",
    "data" => "data_leak",
    "file" => "file_blocking"
  }

  # Severity mapping
  @severity_mapping %{
    "critical" => "critical",
    "high" => "high",
    "medium" => "medium",
    "low" => "low",
    "informational" => "info"
  }

  # MITRE ATT&CK mapping
  @mitre_mapping %{
    "malware" => ["T1204", "T1059"],
    "spyware" => ["T1204", "T1082"],
    "exploit" => ["T1190", "T1203"],
    "reconnaissance" => ["T1046"],
    "dos" => ["T1498", "T1499"],
    "data_leak" => ["T1048", "T1041"],
    "url_filtering" => ["T1071.001"],
    "brute_force" => ["T1110"],
    "vpn_connection" => ["T1133"]
  }

  @impl true
  def parse(raw_log) when is_binary(raw_log) do
    with {:ok, fields} <- parse_csv(raw_log),
         {:ok, log_type} <- extract_log_type(fields),
         {:ok, parsed} <- parse_by_type(log_type, fields) do
      normalize_event(log_type, parsed, raw_log)
    end
  end

  @impl true
  def source_type, do: :firewall

  @impl true
  def vendor, do: "paloalto"

  @impl true
  def product, do: "pan-os"

  # ============================================================================
  # Parsing Logic
  # ============================================================================

  defp parse_csv(raw_log) do
    # Handle quoted fields
    fields = raw_log
    |> String.trim()
    |> String.split(",")
    |> Enum.map(&String.trim/1)

    {:ok, fields}
  end

  defp extract_log_type(fields) when length(fields) > 3 do
    type_str = Enum.at(fields, 3)
    case Map.get(@log_types, type_str) do
      nil -> {:error, :unknown_log_type}
      type -> {:ok, type}
    end
  end
  defp extract_log_type(_), do: {:error, :invalid_format}

  defp parse_by_type(:traffic, fields), do: parse_traffic_log(fields)
  defp parse_by_type(:threat, fields), do: parse_threat_log(fields)
  defp parse_by_type(:url, fields), do: parse_url_log(fields)
  defp parse_by_type(:wildfire, fields), do: parse_wildfire_log(fields)
  defp parse_by_type(:authentication, fields), do: parse_auth_log(fields)
  defp parse_by_type(:globalprotect, fields), do: parse_globalprotect_log(fields)
  defp parse_by_type(:system, fields), do: parse_system_log(fields)
  defp parse_by_type(_, fields), do: parse_generic_log(fields)

  defp parse_traffic_log(fields) do
    # Traffic log field positions (PAN-OS 10.x format)
    {:ok, %{
      receive_time: safe_get(fields, 1),
      serial_number: safe_get(fields, 2),
      type: "traffic",
      subtype: safe_get(fields, 4),
      generated_time: safe_get(fields, 6),
      source_ip: safe_get(fields, 7),
      dest_ip: safe_get(fields, 8),
      nat_source_ip: safe_get(fields, 9),
      nat_dest_ip: safe_get(fields, 10),
      rule_name: safe_get(fields, 11),
      source_user: safe_get(fields, 12),
      dest_user: safe_get(fields, 13),
      application: safe_get(fields, 14),
      virtual_system: safe_get(fields, 15),
      source_zone: safe_get(fields, 16),
      dest_zone: safe_get(fields, 17),
      ingress_interface: safe_get(fields, 18),
      egress_interface: safe_get(fields, 19),
      log_action: safe_get(fields, 20),
      session_id: safe_get(fields, 22),
      repeat_count: safe_get(fields, 23),
      source_port: safe_get_int(fields, 24),
      dest_port: safe_get_int(fields, 25),
      nat_source_port: safe_get_int(fields, 26),
      nat_dest_port: safe_get_int(fields, 27),
      flags: safe_get(fields, 28),
      protocol: safe_get(fields, 29),
      action: safe_get(fields, 30),
      bytes: safe_get_int(fields, 31),
      bytes_sent: safe_get_int(fields, 32),
      bytes_received: safe_get_int(fields, 33),
      packets: safe_get_int(fields, 34),
      start_time: safe_get(fields, 35),
      elapsed_time: safe_get_int(fields, 36),
      category: safe_get(fields, 37),
      sequence_number: safe_get(fields, 39),
      action_flags: safe_get(fields, 40),
      source_country: safe_get(fields, 41),
      dest_country: safe_get(fields, 42),
      packets_sent: safe_get_int(fields, 44),
      packets_received: safe_get_int(fields, 45),
      session_end_reason: safe_get(fields, 46)
    }}
  end

  defp parse_threat_log(fields) do
    {:ok, %{
      receive_time: safe_get(fields, 1),
      serial_number: safe_get(fields, 2),
      type: "threat",
      subtype: safe_get(fields, 4),
      generated_time: safe_get(fields, 6),
      source_ip: safe_get(fields, 7),
      dest_ip: safe_get(fields, 8),
      nat_source_ip: safe_get(fields, 9),
      nat_dest_ip: safe_get(fields, 10),
      rule_name: safe_get(fields, 11),
      source_user: safe_get(fields, 12),
      dest_user: safe_get(fields, 13),
      application: safe_get(fields, 14),
      virtual_system: safe_get(fields, 15),
      source_zone: safe_get(fields, 16),
      dest_zone: safe_get(fields, 17),
      ingress_interface: safe_get(fields, 18),
      egress_interface: safe_get(fields, 19),
      log_action: safe_get(fields, 20),
      session_id: safe_get(fields, 22),
      repeat_count: safe_get(fields, 23),
      source_port: safe_get_int(fields, 24),
      dest_port: safe_get_int(fields, 25),
      nat_source_port: safe_get_int(fields, 26),
      nat_dest_port: safe_get_int(fields, 27),
      flags: safe_get(fields, 28),
      protocol: safe_get(fields, 29),
      action: safe_get(fields, 30),
      threat_name: safe_get(fields, 31),
      threat_category: safe_get(fields, 32),
      severity: safe_get(fields, 33),
      direction: safe_get(fields, 34),
      sequence_number: safe_get(fields, 35),
      action_flags: safe_get(fields, 36),
      source_country: safe_get(fields, 37),
      dest_country: safe_get(fields, 38),
      content_type: safe_get(fields, 39),
      pcap_id: safe_get(fields, 40),
      file_digest: safe_get(fields, 41),
      cloud: safe_get(fields, 42),
      url_index: safe_get_int(fields, 43),
      user_agent: safe_get(fields, 44),
      file_type: safe_get(fields, 45),
      xff: safe_get(fields, 46),
      referer: safe_get(fields, 47),
      sender: safe_get(fields, 48),
      subject: safe_get(fields, 49),
      recipient: safe_get(fields, 50),
      report_id: safe_get(fields, 51)
    }}
  end

  defp parse_url_log(fields) do
    {:ok, %{
      receive_time: safe_get(fields, 1),
      serial_number: safe_get(fields, 2),
      type: "url",
      subtype: safe_get(fields, 4),
      generated_time: safe_get(fields, 6),
      source_ip: safe_get(fields, 7),
      dest_ip: safe_get(fields, 8),
      nat_source_ip: safe_get(fields, 9),
      nat_dest_ip: safe_get(fields, 10),
      rule_name: safe_get(fields, 11),
      source_user: safe_get(fields, 12),
      dest_user: safe_get(fields, 13),
      application: safe_get(fields, 14),
      virtual_system: safe_get(fields, 15),
      source_zone: safe_get(fields, 16),
      dest_zone: safe_get(fields, 17),
      ingress_interface: safe_get(fields, 18),
      egress_interface: safe_get(fields, 19),
      log_action: safe_get(fields, 20),
      session_id: safe_get(fields, 22),
      source_port: safe_get_int(fields, 24),
      dest_port: safe_get_int(fields, 25),
      protocol: safe_get(fields, 29),
      action: safe_get(fields, 30),
      url: safe_get(fields, 31),
      url_category: safe_get(fields, 32),
      severity: safe_get(fields, 33),
      content_type: safe_get(fields, 34),
      user_agent: safe_get(fields, 35),
      referer: safe_get(fields, 36),
      http_method: safe_get(fields, 37)
    }}
  end

  defp parse_wildfire_log(fields) do
    {:ok, %{
      receive_time: safe_get(fields, 1),
      serial_number: safe_get(fields, 2),
      type: "wildfire",
      subtype: safe_get(fields, 4),
      generated_time: safe_get(fields, 6),
      source_ip: safe_get(fields, 7),
      dest_ip: safe_get(fields, 8),
      rule_name: safe_get(fields, 11),
      source_user: safe_get(fields, 12),
      application: safe_get(fields, 14),
      session_id: safe_get(fields, 22),
      source_port: safe_get_int(fields, 24),
      dest_port: safe_get_int(fields, 25),
      protocol: safe_get(fields, 29),
      action: safe_get(fields, 30),
      threat_name: safe_get(fields, 31),
      category: safe_get(fields, 32),
      severity: safe_get(fields, 33),
      direction: safe_get(fields, 34),
      file_digest: safe_get(fields, 41),
      file_type: safe_get(fields, 45),
      file_name: safe_get(fields, 46),
      file_size: safe_get_int(fields, 47),
      verdict: safe_get(fields, 48),
      report_id: safe_get(fields, 51)
    }}
  end

  defp parse_auth_log(fields) do
    {:ok, %{
      receive_time: safe_get(fields, 1),
      serial_number: safe_get(fields, 2),
      type: "authentication",
      subtype: safe_get(fields, 4),
      generated_time: safe_get(fields, 6),
      virtual_system: safe_get(fields, 7),
      source_ip: safe_get(fields, 8),
      user: safe_get(fields, 9),
      normalize_user: safe_get(fields, 10),
      object: safe_get(fields, 11),
      auth_policy: safe_get(fields, 12),
      repeat_count: safe_get(fields, 13),
      auth_id: safe_get(fields, 14),
      vendor: safe_get(fields, 15),
      log_type: safe_get(fields, 16),
      auth_protocol: safe_get(fields, 17),
      auth_server_profile: safe_get(fields, 19),
      description: safe_get(fields, 20),
      client_type: safe_get(fields, 21),
      event_type: safe_get(fields, 22),
      factor_number: safe_get(fields, 23),
      sequence_number: safe_get(fields, 24),
      action_flags: safe_get(fields, 25)
    }}
  end

  defp parse_globalprotect_log(fields) do
    {:ok, %{
      receive_time: safe_get(fields, 1),
      serial_number: safe_get(fields, 2),
      type: "globalprotect",
      subtype: safe_get(fields, 4),
      generated_time: safe_get(fields, 6),
      virtual_system: safe_get(fields, 7),
      event_id: safe_get(fields, 8),
      stage: safe_get(fields, 9),
      auth_method: safe_get(fields, 10),
      tunnel_type: safe_get(fields, 11),
      source_user: safe_get(fields, 12),
      source_region: safe_get(fields, 13),
      machine_name: safe_get(fields, 14),
      source_ip: safe_get(fields, 15),
      public_ipv4: safe_get(fields, 16),
      public_ipv6: safe_get(fields, 17),
      private_ipv4: safe_get(fields, 18),
      private_ipv6: safe_get(fields, 19),
      host_id: safe_get(fields, 20),
      serial_number_device: safe_get(fields, 21),
      client_version: safe_get(fields, 22),
      client_os: safe_get(fields, 23),
      client_os_version: safe_get(fields, 24),
      repeat_count: safe_get(fields, 25),
      reason: safe_get(fields, 26),
      error: safe_get(fields, 27),
      description: safe_get(fields, 28),
      status: safe_get(fields, 29),
      location: safe_get(fields, 30),
      login_duration: safe_get_int(fields, 31),
      connect_method: safe_get(fields, 32),
      error_code: safe_get(fields, 33),
      portal: safe_get(fields, 34),
      sequence_number: safe_get(fields, 35),
      action_flags: safe_get(fields, 36),
      gateway: safe_get(fields, 40)
    }}
  end

  defp parse_system_log(fields) do
    {:ok, %{
      receive_time: safe_get(fields, 1),
      serial_number: safe_get(fields, 2),
      type: "system",
      subtype: safe_get(fields, 4),
      generated_time: safe_get(fields, 6),
      virtual_system: safe_get(fields, 7),
      event_id: safe_get(fields, 8),
      object: safe_get(fields, 9),
      module: safe_get(fields, 11),
      severity: safe_get(fields, 12),
      description: safe_get(fields, 13),
      sequence_number: safe_get(fields, 14),
      action_flags: safe_get(fields, 15)
    }}
  end

  defp parse_generic_log(fields) do
    {:ok, %{
      receive_time: safe_get(fields, 1),
      serial_number: safe_get(fields, 2),
      type: safe_get(fields, 3),
      subtype: safe_get(fields, 4),
      generated_time: safe_get(fields, 6),
      fields: fields
    }}
  end

  defp safe_get(list, index) do
    Enum.at(list, index)
  end

  defp safe_get_int(list, index) do
    case Enum.at(list, index) do
      nil -> nil
      "" -> nil
      value ->
        case Integer.parse(value) do
          {int, _} -> int
          :error -> nil
        end
    end
  end

  # ============================================================================
  # Normalization
  # ============================================================================

  defp normalize_event(log_type, parsed, raw_log) do
    base_event = %{
      id: Ecto.UUID.generate(),
      timestamp: parse_timestamp(parsed[:generated_time] || parsed[:receive_time]),
      source_type: :firewall,
      vendor: "paloalto",
      product: "pan-os",
      raw_log: raw_log,
      device_serial: parsed[:serial_number]
    }

    event = case log_type do
      :traffic -> normalize_traffic_event(base_event, parsed)
      :threat -> normalize_threat_event(base_event, parsed)
      :url -> normalize_url_event(base_event, parsed)
      :wildfire -> normalize_wildfire_event(base_event, parsed)
      :authentication -> normalize_auth_event(base_event, parsed)
      :globalprotect -> normalize_globalprotect_event(base_event, parsed)
      :system -> normalize_system_event(base_event, parsed)
      _ -> normalize_generic_event(base_event, parsed)
    end

    {:ok, NormalizedEvent.new(event)}
  end

  defp normalize_traffic_event(base, parsed) do
    action = Map.get(@traffic_actions, parsed[:action], parsed[:action])

    Map.merge(base, %{
      action: action,
      category: "network",
      severity: if(action == "denied" or action == "dropped", do: "medium", else: "info"),
      source_ip: parsed[:source_ip],
      dest_ip: parsed[:dest_ip],
      source_port: parsed[:source_port],
      dest_port: parsed[:dest_port],
      protocol: parsed[:protocol],
      application: parsed[:application],
      user: parsed[:source_user],
      rule_name: parsed[:rule_name],
      source_zone: parsed[:source_zone],
      dest_zone: parsed[:dest_zone],
      bytes: parsed[:bytes],
      bytes_sent: parsed[:bytes_sent],
      bytes_received: parsed[:bytes_received],
      packets: parsed[:packets],
      session_id: parsed[:session_id],
      source_country: parsed[:source_country],
      dest_country: parsed[:dest_country],
      session_end_reason: parsed[:session_end_reason],
      nat_source_ip: parsed[:nat_source_ip],
      nat_dest_ip: parsed[:nat_dest_ip]
    })
  end

  defp normalize_threat_event(base, parsed) do
    threat_type = Map.get(@threat_types, String.downcase(parsed[:subtype] || ""), "unknown")
    severity = Map.get(@severity_mapping, String.downcase(parsed[:severity] || ""), "medium")
    mitre = Map.get(@mitre_mapping, threat_type, [])

    Map.merge(base, %{
      action: parsed[:action],
      category: "threat",
      severity: severity,
      threat_type: threat_type,
      threat_name: parsed[:threat_name],
      threat_category: parsed[:threat_category],
      source_ip: parsed[:source_ip],
      dest_ip: parsed[:dest_ip],
      source_port: parsed[:source_port],
      dest_port: parsed[:dest_port],
      protocol: parsed[:protocol],
      application: parsed[:application],
      user: parsed[:source_user],
      rule_name: parsed[:rule_name],
      direction: parsed[:direction],
      file_hash: parsed[:file_digest],
      file_type: parsed[:file_type],
      user_agent: parsed[:user_agent],
      source_country: parsed[:source_country],
      dest_country: parsed[:dest_country],
      mitre_techniques: mitre
    })
  end

  defp normalize_url_event(base, parsed) do
    severity = Map.get(@severity_mapping, String.downcase(parsed[:severity] || ""), "low")

    Map.merge(base, %{
      action: parsed[:action],
      category: "url_filtering",
      severity: severity,
      source_ip: parsed[:source_ip],
      dest_ip: parsed[:dest_ip],
      source_port: parsed[:source_port],
      dest_port: parsed[:dest_port],
      protocol: parsed[:protocol],
      application: parsed[:application],
      user: parsed[:source_user],
      url: parsed[:url],
      url_category: parsed[:url_category],
      user_agent: parsed[:user_agent],
      http_method: parsed[:http_method],
      referer: parsed[:referer],
      rule_name: parsed[:rule_name]
    })
  end

  defp normalize_wildfire_event(base, parsed) do
    severity = Map.get(@severity_mapping, String.downcase(parsed[:severity] || ""), "high")

    Map.merge(base, %{
      action: parsed[:action],
      category: "malware",
      severity: severity,
      threat_name: parsed[:threat_name],
      source_ip: parsed[:source_ip],
      dest_ip: parsed[:dest_ip],
      source_port: parsed[:source_port],
      dest_port: parsed[:dest_port],
      protocol: parsed[:protocol],
      application: parsed[:application],
      user: parsed[:source_user],
      file_hash: parsed[:file_digest],
      file_type: parsed[:file_type],
      file_name: parsed[:file_name],
      file_size: parsed[:file_size],
      verdict: parsed[:verdict],
      direction: parsed[:direction],
      mitre_techniques: ["T1204", "T1059"]
    })
  end

  defp normalize_auth_event(base, parsed) do
    outcome = cond do
      String.contains?(String.downcase(parsed[:description] || ""), "failed") -> "failure"
      String.contains?(String.downcase(parsed[:description] || ""), "denied") -> "failure"
      String.contains?(String.downcase(parsed[:description] || ""), "success") -> "success"
      true -> "unknown"
    end

    Map.merge(base, %{
      action: "authentication",
      category: "authentication",
      severity: if(outcome == "failure", do: "medium", else: "info"),
      outcome: outcome,
      user: parsed[:user],
      source_ip: parsed[:source_ip],
      auth_protocol: parsed[:auth_protocol],
      auth_server: parsed[:auth_server_profile],
      description: parsed[:description],
      client_type: parsed[:client_type],
      mitre_techniques: if(outcome == "failure", do: ["T1110"], else: [])
    })
  end

  defp normalize_globalprotect_event(base, parsed) do
    status = parsed[:status] || ""
    is_success = String.contains?(String.downcase(status), "success") or
                 String.contains?(String.downcase(status), "connected")

    Map.merge(base, %{
      action: "vpn_connection",
      category: "vpn",
      severity: if(is_success, do: "info", else: "medium"),
      outcome: if(is_success, do: "success", else: "failure"),
      user: parsed[:source_user],
      source_ip: parsed[:source_ip],
      public_ip: parsed[:public_ipv4],
      private_ip: parsed[:private_ipv4],
      machine_name: parsed[:machine_name],
      client_os: parsed[:client_os],
      client_version: parsed[:client_version],
      tunnel_type: parsed[:tunnel_type],
      auth_method: parsed[:auth_method],
      gateway: parsed[:gateway],
      portal: parsed[:portal],
      status: status,
      reason: parsed[:reason],
      error: parsed[:error],
      description: parsed[:description],
      mitre_techniques: ["T1133"]
    })
  end

  defp normalize_system_event(base, parsed) do
    severity = Map.get(@severity_mapping, String.downcase(parsed[:severity] || ""), "info")

    Map.merge(base, %{
      action: "system_event",
      category: "system",
      severity: severity,
      event_id: parsed[:event_id],
      module: parsed[:module],
      object: parsed[:object],
      description: parsed[:description]
    })
  end

  defp normalize_generic_event(base, parsed) do
    Map.merge(base, %{
      action: parsed[:subtype] || "unknown",
      category: "general",
      severity: "info",
      additional_data: parsed
    })
  end

  defp parse_timestamp(nil), do: DateTime.utc_now()
  defp parse_timestamp(timestamp_str) do
    TamanduaServer.DateTimeParser.parse_utc!(timestamp_str)
  rescue
    _ -> DateTime.utc_now()
  end
end
