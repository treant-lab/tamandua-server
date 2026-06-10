defmodule TamanduaServer.XDR.Parser.Generic do
  @moduledoc """
  Generic parser for unstructured log lines.

  Uses pattern matching and heuristics to extract common security fields
  from arbitrary log formats. Falls back to storing the raw message if
  specific fields cannot be extracted.
  """

  require Logger

  @doc """
  Parse a generic log line.

  Returns {:ok, map} on success, {:error, reason} on failure.
  """
  @spec parse(binary() | map()) :: {:ok, map()} | {:error, term()}
  def parse(data) when is_map(data) do
    # Already structured, just pass through
    {:ok, data}
  end

  def parse(data) when is_binary(data) do
    data = String.trim(data)

    if String.length(data) == 0 do
      {:error, :empty_input}
    else
      event = %{
        timestamp: DateTime.utc_now(),
        message: data,
        severity: infer_severity(data)
      }

      enriched = event
      |> extract_timestamp(data)
      |> extract_ip_addresses(data)
      |> extract_ports(data)
      |> extract_user(data)
      |> extract_domain(data)
      |> extract_url(data)
      |> extract_file(data)
      |> extract_hash(data)
      |> extract_action(data)
      |> extract_protocol(data)

      {:ok, enriched}
    end
  end

  def parse(_), do: {:error, :invalid_input}

  # Field extraction

  defp extract_timestamp(event, data) do
    # Try various timestamp patterns
    patterns = [
      # ISO 8601
      ~r/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/,
      # Common datetime format
      ~r/(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/,
      # US format
      ~r/(\d{1,2}\/\d{1,2}\/\d{4}\s+\d{2}:\d{2}:\d{2})/,
      # Syslog BSD
      ~r/([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/
    ]

    timestamp = Enum.find_value(patterns, fn pattern ->
      case Regex.run(pattern, data) do
        [_, ts] -> parse_timestamp(ts)
        _ -> nil
      end
    end)

    if timestamp do
      Map.put(event, :timestamp, timestamp)
    else
      event
    end
  end

  defp parse_timestamp(ts) do
    # Try ISO 8601
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ ->
        # Try other formats
        try_parse_datetime(ts)
    end
  end

  defp try_parse_datetime(ts) do
    # Try common format: "2023-01-15 10:30:00"
    case Regex.run(~r/^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/, ts) do
      [_, y, m, d, h, min, s] ->
        case NaiveDateTime.new(
          String.to_integer(y),
          String.to_integer(m),
          String.to_integer(d),
          String.to_integer(h),
          String.to_integer(min),
          String.to_integer(s)
        ) do
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

  defp extract_ip_addresses(event, data) do
    # IPv4 pattern
    ipv4_pattern = ~r/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/

    # IPv6 pattern (simplified)
    ipv6_pattern = ~r/\b([0-9a-fA-F:]{2,39})\b/

    ipv4_matches = Regex.scan(ipv4_pattern, data)
    |> Enum.map(fn [_, ip] -> ip end)
    |> Enum.filter(&valid_ipv4?/1)
    |> Enum.uniq()

    # Try to identify source vs destination
    event = case ipv4_matches do
      [] -> event
      [single] ->
        # Check context to determine if source or destination
        if Regex.match?(~r/(?:from|source|src|client)\s*[=:]*\s*#{Regex.escape(single)}/i, data) do
          Map.put(event, :source_ip, single)
        else
          Map.put(event, :dest_ip, single)
        end

      [first, second | _] ->
        # First IP is usually source, second is destination
        event
        |> Map.put(:source_ip, first)
        |> Map.put(:dest_ip, second)
    end

    event
  end

  defp valid_ipv4?(ip) do
    parts = String.split(ip, ".")
    length(parts) == 4 and Enum.all?(parts, fn part ->
      case Integer.parse(part) do
        {n, ""} -> n >= 0 and n <= 255
        _ -> false
      end
    end)
  end

  defp extract_ports(event, data) do
    # Look for port patterns
    event = case Regex.run(~r/(?:sport|source.?port|src.?port|spt)\s*[=:]+\s*(\d{1,5})/i, data) do
      [_, port] -> maybe_add_port(event, :source_port, port)
      _ -> event
    end

    case Regex.run(~r/(?:dport|dest.?port|dst.?port|dpt|port)\s*[=:]+\s*(\d{1,5})/i, data) do
      [_, port] -> maybe_add_port(event, :dest_port, port)
      _ -> event
    end
  end

  defp maybe_add_port(event, field, port_str) do
    case Integer.parse(port_str) do
      {port, _} when port > 0 and port <= 65535 -> Map.put(event, field, port)
      _ -> event
    end
  end

  defp extract_user(event, data) do
    patterns = [
      ~r/(?:user|username|usr|uid|account)\s*[=:]+\s*["']?([^\s"',;\\]+)/i,
      ~r/user=["']?([^\s"',;\\]+)/i,
      ~r/logon\s+(?:by|as)\s+["']?([^\s"',;\\]+)/i
    ]

    Enum.find_value(patterns, fn pattern ->
      case Regex.run(pattern, data) do
        [_, user] when byte_size(user) > 0 -> user
        _ -> nil
      end
    end)
    |> case do
      nil -> event
      user -> Map.put(event, :user_name, user)
    end
  end

  defp extract_domain(event, data) do
    # Look for domain patterns
    patterns = [
      ~r/(?:domain|host|hostname|server)\s*[=:]+\s*["']?([a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,})/i,
      ~r/\b([a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.(?:[a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.)*[a-zA-Z]{2,})\b/
    ]

    Enum.find_value(patterns, fn pattern ->
      case Regex.run(pattern, data) do
        [_, domain] -> domain
        _ -> nil
      end
    end)
    |> case do
      nil -> event
      domain ->
        if valid_domain?(domain) and not Regex.match?(~r/^\d/, domain) do
          Map.put(event, :url_domain, domain)
        else
          event
        end
    end
  end

  defp valid_domain?(domain) do
    # Basic domain validation
    String.length(domain) >= 4 and String.contains?(domain, ".") and
    not String.contains?(domain, "..")
  end

  defp extract_url(event, data) do
    case Regex.run(~r/(https?:\/\/[^\s<>"']+)/i, data) do
      [_, url] ->
        uri = URI.parse(url)
        event
        |> Map.put(:url, url)
        |> Map.put(:url_domain, uri.host)
        |> Map.put(:url_path, uri.path)
      _ -> event
    end
  end

  defp extract_file(event, data) do
    # Windows path
    windows_match = Regex.run(~r/(?:file|path|filename)\s*[=:]+\s*["']?([A-Za-z]:\\[^\s"',;]+)/i, data)

    # Unix path
    unix_match = Regex.run(~r/(?:file|path|filename)\s*[=:]+\s*["']?(\/[^\s"',;]+)/i, data)

    case windows_match || unix_match do
      [_, path] ->
        filename = Path.basename(path)
        event
        |> Map.put(:file_path, path)
        |> Map.put(:file_name, filename)
      _ -> event
    end
  end

  defp extract_hash(event, data) do
    # SHA256
    event = case Regex.run(~r/(?:sha256|hash256)\s*[=:]+\s*([a-fA-F0-9]{64})/i, data) do
      [_, hash] -> Map.put(event, :file_hash_sha256, String.downcase(hash))
      _ -> event
    end

    # MD5
    case Regex.run(~r/(?:md5|hash)\s*[=:]+\s*([a-fA-F0-9]{32})/i, data) do
      [_, hash] -> Map.put(event, :file_hash_md5, String.downcase(hash))
      _ -> event
    end
  end

  defp extract_action(event, data) do
    data_lower = String.downcase(data)

    action = cond do
      Regex.match?(~r/\b(denied|deny|reject|refused|drop|block|blocked)\b/i, data_lower) ->
        "deny"

      Regex.match?(~r/\b(allow|allowed|accept|accepted|permit|permitted|pass|passed)\b/i, data_lower) ->
        "allow"

      Regex.match?(~r/\b(alert|alerted|warning|warn)\b/i, data_lower) ->
        "alert"

      Regex.match?(~r/\b(quarantine|quarantined|isolate|isolated)\b/i, data_lower) ->
        "quarantine"

      true -> nil
    end

    if action do
      event
      |> Map.put(:action, action)
      |> Map.put(:outcome, if(action in ["deny", "quarantine"], do: "failure", else: "success"))
    else
      event
    end
  end

  defp extract_protocol(event, data) do
    data_upper = String.upcase(data)

    protocol = cond do
      Regex.match?(~r/\bTCP\b/, data_upper) -> "TCP"
      Regex.match?(~r/\bUDP\b/, data_upper) -> "UDP"
      Regex.match?(~r/\bICMP\b/, data_upper) -> "ICMP"
      Regex.match?(~r/\bHTTPS?\b/, data_upper) -> "HTTP"
      Regex.match?(~r/\bDNS\b/, data_upper) -> "DNS"
      Regex.match?(~r/\bSSH\b/, data_upper) -> "SSH"
      Regex.match?(~r/\bFTP\b/, data_upper) -> "FTP"
      Regex.match?(~r/\bSMTP\b/, data_upper) -> "SMTP"
      Regex.match?(~r/\bSMB\b/, data_upper) -> "SMB"
      Regex.match?(~r/\bRDP\b/, data_upper) -> "RDP"
      true -> nil
    end

    if protocol do
      Map.put(event, :network_protocol, protocol)
    else
      event
    end
  end

  defp infer_severity(data) do
    data_lower = String.downcase(data)

    cond do
      Regex.match?(~r/\b(critical|emergency|emerg|crit|fatal)\b/, data_lower) -> "critical"
      Regex.match?(~r/\b(error|err|fail|failed|attack|malware|virus|exploit)\b/, data_lower) -> "high"
      Regex.match?(~r/\b(warning|warn|alert|suspicious|anomal)\b/, data_lower) -> "medium"
      Regex.match?(~r/\b(notice|info|information|denied|blocked)\b/, data_lower) -> "low"
      true -> "info"
    end
  end
end
