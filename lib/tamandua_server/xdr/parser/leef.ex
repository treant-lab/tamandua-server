defmodule TamanduaServer.XDR.Parser.LEEF do
  @moduledoc """
  Parser for Log Event Extended Format (LEEF) logs.

  LEEF is IBM's log format used by QRadar and other products.

  LEEF Format:
  LEEF:Version|Vendor|Product|Version|EventID|Key1=Value1<tab>Key2=Value2

  Example:
  LEEF:2.0|IBM|QRadar|7.3.0|1001|src=192.168.1.1	dst=10.0.0.1	usrName=admin

  LEEF 2.0 uses tab as default delimiter, LEEF 1.0 uses pipe.
  """

  require Logger

  # LEEF key to normalized field mapping
  @key_mapping %{
    "src" => :source_ip,
    "dst" => :dest_ip,
    "srcPort" => :source_port,
    "dstPort" => :dest_port,
    "srcPreNAT" => :source_nat_ip,
    "srcPostNAT" => :source_nat_ip_post,
    "dstPreNAT" => :dest_nat_ip,
    "dstPostNAT" => :dest_nat_ip_post,
    "srcMAC" => :source_mac,
    "dstMAC" => :dest_mac,
    "sev" => :severity,
    "usrName" => :user_name,
    "srcUserName" => :source_user,
    "dstUserName" => :dest_user,
    "domain" => :user_domain,
    "url" => :url,
    "proto" => :network_protocol,
    "policy" => :rule_name,
    "action" => :action,
    "devTime" => :timestamp,
    "devTimeFormat" => :timestamp_format,
    "cat" => :event_category,
    "resource" => :resource,
    "srcBytes" => :bytes_in,
    "dstBytes" => :bytes_out,
    "srcPackets" => :packets_in,
    "dstPackets" => :packets_out,
    "identSrc" => :source_identity,
    "identDst" => :dest_identity,
    "accountName" => :account_name,
    "fileName" => :file_name,
    "filePath" => :file_path,
    "fileSize" => :file_size,
    "fileType" => :file_type,
    "filePermission" => :file_permission,
    "oldFileName" => :old_file_name,
    "oldFilePath" => :old_file_path
  }

  @doc """
  Parse a LEEF formatted log line.

  Returns {:ok, map} on success, {:error, reason} on failure.
  """
  @spec parse(binary()) :: {:ok, map()} | {:error, term()}
  def parse(line) when is_binary(line) do
    line = String.trim(line)

    # Handle syslog prefix if present
    {_syslog_meta, leef_content} = extract_syslog_prefix(line)

    case parse_leef_content(leef_content) do
      {:ok, event} -> {:ok, event}
      {:error, reason} -> {:error, reason}
    end
  end

  def parse(_), do: {:error, :invalid_input}

  defp extract_syslog_prefix(line) do
    case String.split(line, "LEEF:", parts: 2) do
      [prefix, rest] -> {prefix, "LEEF:" <> rest}
      _ -> {"", line}
    end
  end

  defp parse_leef_content(content) do
    if String.starts_with?(content, "LEEF:") do
      content = String.trim_leading(content, "LEEF:")
      parse_leef_fields(content)
    else
      {:error, :not_leef_format}
    end
  end

  defp parse_leef_fields(content) do
    # Split header fields (pipe-delimited)
    parts = String.split(content, "|", parts: 6)

    case parts do
      [version, vendor, product, prod_version, event_id | rest] ->
        extension = List.first(rest) || ""

        # LEEF 2.0 may have a delimiter specification
        {delimiter, extension} = extract_delimiter(version, extension)

        event = %{
          leef_version: version,
          device_vendor: vendor,
          device_product: product,
          device_version: prod_version,
          event_id: event_id,
          signature_id: event_id
        }

        # Parse extension key=value pairs
        extension_fields = parse_extension(extension, delimiter)

        # Merge and normalize
        {:ok, Map.merge(event, normalize_extension(extension_fields))}

      _ ->
        {:error, :invalid_leef_header}
    end
  end

  defp extract_delimiter(version, extension) do
    if String.starts_with?(version, "2.0") do
      # LEEF 2.0 default delimiter is tab, but can be specified
      # Format: "2.0^delimiter" where delimiter is a single char
      case String.split(version, "^", parts: 2) do
        [_, delim] when byte_size(delim) == 1 ->
          {delim, extension}
        _ ->
          {"\t", extension}
      end
    else
      # LEEF 1.0 uses pipe or tab
      if String.contains?(extension, "\t") do
        {"\t", extension}
      else
        {"|", extension}
      end
    end
  end

  defp parse_extension(extension, delimiter) when is_binary(extension) do
    extension = String.trim(extension)

    # Split by delimiter and parse key=value pairs
    extension
    |> String.split(delimiter)
    |> Enum.reduce(%{}, fn pair, acc ->
      case String.split(pair, "=", parts: 2) do
        [key, value] ->
          Map.put(acc, String.trim(key), String.trim(value))
        _ ->
          acc
      end
    end)
  end

  defp parse_extension(_, _), do: %{}

  defp normalize_extension(fields) do
    # Map LEEF keys to normalized field names
    normalized = Enum.reduce(fields, %{}, fn {key, value}, acc ->
      case Map.get(@key_mapping, key) do
        nil ->
          # Keep unmapped fields in parsed_fields
          Map.update(acc, :parsed_fields, %{key => value}, &Map.put(&1, key, value))
        field_name ->
          Map.put(acc, field_name, value)
      end
    end)

    # Parse severity
    normalized = case Map.get(normalized, :severity) do
      nil -> normalized
      sev -> Map.put(normalized, :severity, map_severity(sev))
    end

    # Parse timestamp from devTime field
    case Map.get(normalized, :timestamp) do
      nil -> normalized
      ts_str ->
        format = Map.get(normalized, :timestamp_format)
        case parse_leef_timestamp(ts_str, format) do
          {:ok, ts} -> Map.put(normalized, :timestamp, ts)
          _ -> normalized
        end
    end
  end

  defp map_severity(sev) when is_binary(sev) do
    case Integer.parse(sev) do
      {n, _} when n >= 9 -> "critical"
      {n, _} when n >= 7 -> "high"
      {n, _} when n >= 4 -> "medium"
      {n, _} when n >= 1 -> "low"
      _ -> "info"
    end
  end

  defp map_severity(_), do: "info"

  defp parse_leef_timestamp(ts, format) when is_binary(ts) do
    cond do
      # Epoch milliseconds
      Regex.match?(~r/^\d{13}$/, ts) ->
        case Integer.parse(ts) do
          {millis, _} ->
            case DateTime.from_unix(millis, :millisecond) do
              {:ok, dt} -> {:ok, dt}
              _ -> :error
            end
          _ -> :error
        end

      # Epoch seconds
      Regex.match?(~r/^\d{10}$/, ts) ->
        case Integer.parse(ts) do
          {secs, _} ->
            case DateTime.from_unix(secs) do
              {:ok, dt} -> {:ok, dt}
              _ -> :error
            end
          _ -> :error
        end

      # Try ISO 8601
      true ->
        case DateTime.from_iso8601(ts) do
          {:ok, dt, _} -> {:ok, dt}
          _ ->
            # Try custom format parsing if format hint provided
            if format do
              parse_custom_timestamp(ts, format)
            else
              :error
            end
        end
    end
  end

  defp parse_leef_timestamp(_, _), do: :error

  defp parse_custom_timestamp(ts, _format) do
    # Basic parsing for common formats
    # In production, would use Timex or similar for full format support
    case DateTime.from_iso8601(ts <> "Z") do
      {:ok, dt, _} -> {:ok, dt}
      _ -> :error
    end
  end
end
