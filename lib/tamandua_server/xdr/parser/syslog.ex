defmodule TamanduaServer.XDR.Parser.Syslog do
  @moduledoc """
  Parser for Syslog formatted logs.

  Supports both RFC 5424 (structured syslog) and RFC 3164 (BSD syslog).

  RFC 5424 Format:
  <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG

  RFC 3164 Format:
  <PRI>TIMESTAMP HOSTNAME TAG: MSG

  Example RFC 5424:
  <134>1 2023-01-15T10:30:00Z firewall app 1234 - - Connection blocked from 192.168.1.1

  Example RFC 3164:
  <134>Jan 15 10:30:00 firewall app[1234]: Connection blocked from 192.168.1.1
  """

  require Logger

  @severity_map %{
    0 => "critical",  # Emergency
    1 => "critical",  # Alert
    2 => "critical",  # Critical
    3 => "high",      # Error
    4 => "medium",    # Warning
    5 => "low",       # Notice
    6 => "info",      # Informational
    7 => "info"       # Debug
  }

  @facility_map %{
    0 => "kern",
    1 => "user",
    2 => "mail",
    3 => "daemon",
    4 => "auth",
    5 => "syslog",
    6 => "lpr",
    7 => "news",
    8 => "uucp",
    9 => "cron",
    10 => "authpriv",
    11 => "ftp",
    12 => "ntp",
    13 => "audit",
    14 => "alert",
    15 => "clock",
    16 => "local0",
    17 => "local1",
    18 => "local2",
    19 => "local3",
    20 => "local4",
    21 => "local5",
    22 => "local6",
    23 => "local7"
  }

  @doc """
  Parse a syslog formatted log line.

  Returns {:ok, map} on success, {:error, reason} on failure.
  """
  @spec parse(binary()) :: {:ok, map()} | {:error, term()}
  def parse(line) when is_binary(line) do
    line = String.trim(line)

    cond do
      # RFC 5424 format (has version number after PRI)
      Regex.match?(~r/^<\d+>\d\s/, line) ->
        parse_rfc5424(line)

      # RFC 3164 format
      Regex.match?(~r/^<\d+>/, line) ->
        parse_rfc3164(line)

      # No PRI header - try to parse as plain message
      true ->
        parse_plain_message(line)
    end
  end

  def parse(_), do: {:error, :invalid_input}

  # RFC 5424 Parsing

  defp parse_rfc5424(line) do
    # <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA SP MSG
    regex = ~r/^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+((?:\[.*?\]\s*)*)?(.*)$/s

    case Regex.run(regex, line) do
      [_full, pri, version, timestamp, hostname, app_name, procid, msgid, sd, msg] ->
        {facility, severity} = decode_pri(pri)

        event = %{
          syslog_version: version,
          syslog_facility: facility,
          syslog_severity: severity,
          severity: Map.get(@severity_map, severity, "info"),
          timestamp: parse_rfc5424_timestamp(timestamp),
          source_hostname: nilify(hostname),
          device_product: nilify(app_name),
          process_id: nilify(procid),
          message_id: nilify(msgid),
          message: String.trim(msg),
          parsed_fields: parse_structured_data(sd)
        }

        # Try to extract additional fields from the message
        enriched = enrich_from_message(event)

        {:ok, enriched}

      _ ->
        {:error, :invalid_rfc5424_format}
    end
  end

  defp nilify("-"), do: nil
  defp nilify(""), do: nil
  defp nilify(v), do: v

  defp parse_rfc5424_timestamp(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end

  defp parse_structured_data(nil), do: %{}
  defp parse_structured_data(""), do: %{}
  defp parse_structured_data("-"), do: %{}

  defp parse_structured_data(sd) do
    # Parse [id param=value param=value][id param=value]
    Regex.scan(~r/\[(\S+?)((?:\s+\S+=(?:"[^"]*"|[^\s\]]+))*)\]/, sd)
    |> Enum.reduce(%{}, fn [_full, id, params], acc ->
      param_map = parse_sd_params(params)
      Map.put(acc, id, param_map)
    end)
  end

  defp parse_sd_params(params) do
    Regex.scan(~r/(\S+)=(?:"([^"]*)"|(\S+))/, params)
    |> Enum.reduce(%{}, fn
      [_full, key, quoted, ""], acc -> Map.put(acc, key, unescape_sd_value(quoted))
      [_full, key, "", unquoted], acc -> Map.put(acc, key, unquoted)
      _, acc -> acc
    end)
  end

  defp unescape_sd_value(value) do
    value
    |> String.replace("\\\"", "\"")
    |> String.replace("\\\\", "\\")
    |> String.replace("\\]", "]")
  end

  # RFC 3164 Parsing

  defp parse_rfc3164(line) do
    # <PRI>TIMESTAMP HOSTNAME TAG[PID]: MSG
    # or <PRI>TIMESTAMP HOSTNAME TAG: MSG

    # First extract PRI
    case Regex.run(~r/^<(\d+)>(.*)$/, line) do
      [_full, pri, rest] ->
        {facility, severity} = decode_pri(pri)

        # Parse the rest (timestamp, hostname, tag, message)
        parsed = parse_rfc3164_body(rest)

        event = Map.merge(parsed, %{
          syslog_facility: facility,
          syslog_severity: severity,
          severity: Map.get(@severity_map, severity, "info")
        })

        enriched = enrich_from_message(event)

        {:ok, enriched}

      _ ->
        {:error, :invalid_rfc3164_format}
    end
  end

  defp parse_rfc3164_body(body) do
    # Try multiple patterns

    # Pattern 1: "Jan 15 10:30:00 hostname tag[pid]: message"
    with nil <- try_parse_3164_pattern1(body),
         # Pattern 2: "Jan 15 10:30:00 hostname tag: message"
         nil <- try_parse_3164_pattern2(body),
         # Pattern 3: "2023-01-15T10:30:00 hostname tag: message"
         nil <- try_parse_3164_iso_timestamp(body) do
      # Fallback: just treat everything as message
      %{message: body}
    end
  end

  defp try_parse_3164_pattern1(body) do
    # "Jan 15 10:30:00 hostname tag[pid]: message"
    regex = ~r/^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)\[(\d+)\]:\s*(.*)$/s

    case Regex.run(regex, body) do
      [_full, timestamp, hostname, tag, pid, msg] ->
        %{
          timestamp: parse_bsd_timestamp(timestamp),
          source_hostname: hostname,
          device_product: tag,
          process_id: pid,
          message: msg
        }
      _ -> nil
    end
  end

  defp try_parse_3164_pattern2(body) do
    # "Jan 15 10:30:00 hostname tag: message"
    regex = ~r/^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?):\s*(.*)$/s

    case Regex.run(regex, body) do
      [_full, timestamp, hostname, tag, msg] ->
        %{
          timestamp: parse_bsd_timestamp(timestamp),
          source_hostname: hostname,
          device_product: tag,
          message: msg
        }
      _ -> nil
    end
  end

  defp try_parse_3164_iso_timestamp(body) do
    # "2023-01-15T10:30:00Z hostname tag: message"
    regex = ~r/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s+(\S+)\s+(\S+?):\s*(.*)$/s

    case Regex.run(regex, body) do
      [_full, timestamp, hostname, tag, msg] ->
        %{
          timestamp: parse_rfc5424_timestamp(timestamp),
          source_hostname: hostname,
          device_product: tag,
          message: msg
        }
      _ -> nil
    end
  end

  defp parse_bsd_timestamp(ts) do
    # BSD timestamp: "Jan 15 10:30:00" (no year)
    # We assume current year
    year = DateTime.utc_now().year

    case Regex.run(~r/^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$/, ts) do
      [_full, month_str, day, hour, min, sec] ->
        month = month_to_number(month_str)
        day = String.to_integer(day)
        hour = String.to_integer(hour)
        min = String.to_integer(min)
        sec = String.to_integer(sec)

        case NaiveDateTime.new(year, month, day, hour, min, sec) do
          {:ok, ndt} ->
            case DateTime.from_naive(ndt, "Etc/UTC") do
              {:ok, dt} -> dt
              _ -> nil
            end
          _ -> nil
        end

      _ -> nil
    end
  end

  defp month_to_number("Jan"), do: 1
  defp month_to_number("Feb"), do: 2
  defp month_to_number("Mar"), do: 3
  defp month_to_number("Apr"), do: 4
  defp month_to_number("May"), do: 5
  defp month_to_number("Jun"), do: 6
  defp month_to_number("Jul"), do: 7
  defp month_to_number("Aug"), do: 8
  defp month_to_number("Sep"), do: 9
  defp month_to_number("Oct"), do: 10
  defp month_to_number("Nov"), do: 11
  defp month_to_number("Dec"), do: 12
  defp month_to_number(_), do: 1

  # Plain message parsing

  defp parse_plain_message(line) do
    event = %{
      timestamp: DateTime.utc_now(),
      message: line,
      severity: "info"
    }

    {:ok, enrich_from_message(event)}
  end

  # Helper functions

  defp decode_pri(pri) when is_binary(pri) do
    case Integer.parse(pri) do
      {n, _} -> decode_pri(n)
      _ -> {1, 6}  # Default to user.info
    end
  end

  defp decode_pri(pri) when is_integer(pri) do
    facility = div(pri, 8)
    severity = rem(pri, 8)
    {facility, severity}
  end

  defp enrich_from_message(event) do
    msg = event[:message] || ""

    event
    |> extract_ip_addresses(msg)
    |> extract_user(msg)
    |> extract_action(msg)
    |> extract_url(msg)
    |> extract_port(msg)
  end

  defp extract_ip_addresses(event, msg) do
    # Extract IP addresses from message
    ips = Regex.scan(~r/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/, msg)
    |> Enum.map(fn [_, ip] -> ip end)
    |> Enum.uniq()

    case ips do
      [src] -> Map.put(event, :source_ip, src)
      [src, dst | _] -> event |> Map.put(:source_ip, src) |> Map.put(:dest_ip, dst)
      _ -> event
    end
  end

  defp extract_user(event, msg) do
    case Regex.run(~r/(?:user|username|usr|uid)[\s:=]+["']?([^\s"',;]+)/i, msg) do
      [_, user] -> Map.put(event, :user_name, user)
      _ -> event
    end
  end

  defp extract_action(event, msg) do
    msg_lower = String.downcase(msg)

    action = cond do
      String.contains?(msg_lower, ["denied", "reject", "drop", "block"]) -> "deny"
      String.contains?(msg_lower, ["allow", "accept", "permit", "pass"]) -> "allow"
      String.contains?(msg_lower, ["alert", "warning", "warn"]) -> "alert"
      true -> nil
    end

    if action, do: Map.put(event, :action, action), else: event
  end

  defp extract_url(event, msg) do
    case Regex.run(~r/(https?:\/\/[^\s<>"]+)/i, msg) do
      [_, url] -> Map.put(event, :url, url)
      _ -> event
    end
  end

  defp extract_port(event, msg) do
    case Regex.run(~r/(?:port|dport|sport)[\s:=]+(\d{1,5})/i, msg) do
      [_, port] ->
        case Integer.parse(port) do
          {p, _} when p > 0 and p <= 65535 -> Map.put(event, :dest_port, p)
          _ -> event
        end
      _ -> event
    end
  end
end
