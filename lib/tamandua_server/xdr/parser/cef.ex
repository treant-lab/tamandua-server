defmodule TamanduaServer.XDR.Parser.CEF do
  @moduledoc """
  Parser for Common Event Format (CEF) logs.

  CEF Format:
  CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

  Example:
  CEF:0|Security|ThreatDetection|1.0|100|Malware Detected|10|src=192.168.1.1 dst=10.0.0.1 act=block

  Extension keys follow CEF naming conventions:
  - src/dst: source/destination IP
  - spt/dpt: source/destination port
  - suser/duser: source/destination user
  - act: action taken
  - msg: message
  - cs1-cs6: custom strings
  - cn1-cn3: custom numbers
  """

  require Logger

  @severity_map %{
    "0" => "info",
    "1" => "info",
    "2" => "info",
    "3" => "low",
    "4" => "low",
    "5" => "medium",
    "6" => "medium",
    "7" => "high",
    "8" => "high",
    "9" => "critical",
    "10" => "critical"
  }

  # CEF extension key to normalized field mapping
  @key_mapping %{
    "src" => :source_ip,
    "dst" => :dest_ip,
    "spt" => :source_port,
    "dpt" => :dest_port,
    "shost" => :source_hostname,
    "dhost" => :dest_hostname,
    "suser" => :user_name,
    "duser" => :dest_user,
    "act" => :action,
    "outcome" => :outcome,
    "proto" => :network_protocol,
    "app" => :network_transport,
    "request" => :url,
    "requestURL" => :url,
    "requestMethod" => :http_method,
    "fname" => :file_name,
    "fpath" => :file_path,
    "fsize" => :file_size,
    "fileHash" => :file_hash_sha256,
    "msg" => :message,
    "reason" => :reason,
    "cat" => :event_category,
    "deviceDirection" => :network_direction,
    "deviceExternalId" => :device_id,
    "rt" => :timestamp,
    "start" => :start_time,
    "end" => :end_time,
    "in" => :bytes_in,
    "out" => :bytes_out
  }

  @doc """
  Parse a CEF formatted log line.

  Returns {:ok, map} on success, {:error, reason} on failure.
  """
  @spec parse(binary()) :: {:ok, map()} | {:error, term()}
  def parse(line) when is_binary(line) do
    line = String.trim(line)

    # Handle syslog prefix if present
    {_syslog_meta, cef_content} = extract_syslog_prefix(line)

    case parse_cef_content(cef_content) do
      {:ok, event} -> {:ok, event}
      {:error, reason} -> {:error, reason}
    end
  end

  def parse(_), do: {:error, :invalid_input}

  defp extract_syslog_prefix(line) do
    # CEF can be embedded in syslog: "<priority>timestamp host CEF:..."
    case Regex.run(~r/^(?:<\d+>)?(?:.+?\s+)?(?:CEF:.+)$/s, line) do
      [_full] ->
        case String.split(line, "CEF:", parts: 2) do
          [prefix, rest] -> {prefix, "CEF:" <> rest}
          _ -> {"", line}
        end
      _ ->
        {"", line}
    end
  end

  defp parse_cef_content(content) do
    if String.starts_with?(content, "CEF:") do
      content = String.trim_leading(content, "CEF:")
      parse_cef_fields(content)
    else
      {:error, :not_cef_format}
    end
  end

  defp parse_cef_fields(content) do
    # Split header (pipe-delimited) from extension (key=value pairs)
    parts = String.split(content, "|", parts: 8)

    case parts do
      [version, vendor, product, device_version, signature_id, name, severity | rest] ->
        extension = List.first(rest) || ""

        event = %{
          cef_version: version,
          device_vendor: vendor,
          device_product: product,
          device_version: device_version,
          signature_id: signature_id,
          rule_name: name,
          severity: map_severity(severity),
          raw_severity: severity
        }

        # Parse extension key=value pairs
        extension_fields = parse_extension(extension)

        # Merge and normalize
        {:ok, Map.merge(event, normalize_extension(extension_fields))}

      _ ->
        {:error, :invalid_cef_header}
    end
  end

  defp map_severity(sev) when is_binary(sev) do
    sev_clean = String.trim(sev)
    Map.get(@severity_map, sev_clean, "info")
  end

  defp parse_extension(extension) when is_binary(extension) do
    extension = String.trim(extension)

    # Parse key=value pairs, handling escaped characters
    # CEF uses \= for literal equals and \\ for literal backslash
    parse_kv_pairs(extension, %{})
  end

  defp parse_extension(_), do: %{}

  defp parse_kv_pairs("", acc), do: acc

  defp parse_kv_pairs(str, acc) do
    # Find the next key=value pair
    case Regex.run(~r/^([a-zA-Z0-9_]+)=((?:[^\\=]|\\.)*?)(?:\s+([a-zA-Z0-9_]+=)|$)/s, str) do
      [_full, key, value, next_key] ->
        value = unescape_cef_value(String.trim(value))
        remaining = String.trim_leading(str, key <> "=" <> value)
        remaining = if next_key != "", do: String.trim_leading(remaining), else: ""
        parse_kv_pairs(remaining, Map.put(acc, key, value))

      [_full, key, value] ->
        value = unescape_cef_value(String.trim(value))
        Map.put(acc, key, value)

      nil ->
        # Try simpler parsing for remaining content
        case Regex.run(~r/^([a-zA-Z0-9_]+)=(.*)$/s, String.trim(str)) do
          [_full, key, value] ->
            Map.put(acc, key, unescape_cef_value(String.trim(value)))
          _ ->
            acc
        end
    end
  end

  defp unescape_cef_value(value) do
    value
    |> String.replace("\\=", "=")
    |> String.replace("\\\\", "\\")
    |> String.replace("\\n", "\n")
    |> String.replace("\\r", "\r")
  end

  defp normalize_extension(fields) do
    # Map CEF keys to normalized field names
    normalized = Enum.reduce(fields, %{}, fn {key, value}, acc ->
      case Map.get(@key_mapping, key) do
        nil ->
          # Keep unmapped fields in parsed_fields
          Map.update(acc, :parsed_fields, %{key => value}, &Map.put(&1, key, value))
        field_name ->
          Map.put(acc, field_name, value)
      end
    end)

    # Parse timestamp from rt field if present
    case Map.get(normalized, :timestamp) do
      nil -> normalized
      ts_str ->
        case parse_cef_timestamp(ts_str) do
          {:ok, ts} -> Map.put(normalized, :timestamp, ts)
          _ -> normalized
        end
    end
  end

  defp parse_cef_timestamp(ts) when is_binary(ts) do
    # CEF timestamps can be in multiple formats:
    # - Milliseconds since epoch: "1234567890123"
    # - MMM dd yyyy HH:mm:ss
    # - ISO 8601

    cond do
      Regex.match?(~r/^\d+$/, ts) ->
        case Integer.parse(ts) do
          {millis, _} ->
            case DateTime.from_unix(millis, :millisecond) do
              {:ok, dt} -> {:ok, dt}
              _ -> :error
            end
          _ -> :error
        end

      true ->
        case DateTime.from_iso8601(ts) do
          {:ok, dt, _} -> {:ok, dt}
          _ -> :error
        end
    end
  end

  defp parse_cef_timestamp(_), do: :error
end
