defmodule TamanduaServer.Telemetry.LogNormalizer do
  @moduledoc """
  Parses and normalizes third-party log formats into a common schema for
  storage in ClickHouse.

  Supported formats:
  - RFC 5424 syslog
  - RFC 3164 (BSD) syslog
  - CEF (Common Event Format) - ArcSight, Palo Alto, Check Point, etc.
  - LEEF (Log Event Extended Format) - IBM QRadar

  All parsed events are normalized to a common schema that includes source
  metadata, severity, extracted network fields, and the original raw message.
  """

  require Logger

  @syslog_facilities %{
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
    13 => "security",
    14 => "console",
    15 => "solaris-cron",
    16 => "local0",
    17 => "local1",
    18 => "local2",
    19 => "local3",
    20 => "local4",
    21 => "local5",
    22 => "local6",
    23 => "local7"
  }

  @cef_severity_map %{
    "0" => 0,
    "1" => 1,
    "2" => 2,
    "3" => 3,
    "4" => 4,
    "5" => 5,
    "6" => 6,
    "7" => 7,
    "8" => 7,
    "9" => 7,
    "10" => 7,
    "low" => 3,
    "medium" => 5,
    "high" => 7,
    "very-high" => 7,
    "unknown" => 4
  }

  @leef_severity_map %{
    "0" => 0,
    "1" => 1,
    "2" => 2,
    "3" => 3,
    "4" => 4,
    "5" => 5,
    "6" => 6,
    "7" => 7,
    "8" => 7,
    "9" => 7,
    "10" => 7
  }

  # CEF extension key aliases to common field names
  @cef_key_aliases %{
    "src" => :src_ip,
    "dst" => :dst_ip,
    "spt" => :src_port,
    "dpt" => :dst_port,
    "proto" => :protocol,
    "act" => :action,
    "suser" => :user,
    "duser" => :dst_user,
    "shost" => :src_host,
    "dhost" => :dst_host,
    "fname" => :file_name,
    "fsize" => :file_size,
    "request" => :request_url,
    "msg" => :message,
    "cn1" => :custom_number_1,
    "cn2" => :custom_number_2,
    "cn3" => :custom_number_3,
    "cs1" => :custom_string_1,
    "cs2" => :custom_string_2,
    "cs3" => :custom_string_3,
    "cs4" => :custom_string_4,
    "cs5" => :custom_string_5,
    "cs6" => :custom_string_6,
    "sourceAddress" => :src_ip,
    "destinationAddress" => :dst_ip,
    "sourcePort" => :src_port,
    "destinationPort" => :dst_port,
    "transportProtocol" => :protocol,
    "deviceAction" => :action,
    "sourceUserName" => :user,
    "destinationUserName" => :dst_user,
    "sourceHostName" => :src_host,
    "destinationHostName" => :dst_host,
    "fileName" => :file_name,
    "fileSize" => :file_size,
    "requestUrl" => :request_url,
    "deviceAddress" => :device_ip,
    "deviceHostName" => :device_hostname,
    "deviceExternalId" => :device_external_id,
    "externalId" => :external_id,
    "outcome" => :outcome,
    "reason" => :reason,
    "app" => :application,
    "cat" => :category,
    "rt" => :receipt_time,
    "end" => :end_time,
    "start" => :start_time,
    "in" => :bytes_in,
    "out" => :bytes_out,
    "requestMethod" => :request_method,
    "requestClientApplication" => :user_agent
  }

  # LEEF key aliases
  @leef_key_aliases %{
    "src" => :src_ip,
    "dst" => :dst_ip,
    "srcPort" => :src_port,
    "dstPort" => :dst_port,
    "proto" => :protocol,
    "action" => :action,
    "usrName" => :user,
    "srcPreNAT" => :src_pre_nat,
    "dstPreNAT" => :dst_pre_nat,
    "srcPostNAT" => :src_post_nat,
    "dstPostNAT" => :dst_post_nat,
    "policy" => :policy,
    "resource" => :resource,
    "url" => :request_url,
    "category" => :category,
    "devTime" => :device_time,
    "devTimeFormat" => :device_time_format,
    "sev" => :severity_label,
    "identSrc" => :identity_src,
    "identHostName" => :identity_hostname,
    "accountName" => :account_name,
    "srcBytes" => :bytes_in,
    "dstBytes" => :bytes_out,
    "totalBytes" => :total_bytes
  }

  # IPv4 regex pattern
  @ipv4_pattern ~r/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/

  # IPv6 simplified pattern (covers common representations)
  @ipv6_pattern ~r/\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/

  # Domain pattern
  @domain_pattern ~r/\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/

  # Hash patterns
  @md5_pattern ~r/\b[a-fA-F0-9]{32}\b/
  @sha1_pattern ~r/\b[a-fA-F0-9]{40}\b/
  @sha256_pattern ~r/\b[a-fA-F0-9]{64}\b/

  # ── RFC 5424 Parser ────────────────────────────────────────────────

  @doc """
  Parse an RFC 5424 syslog message.

  Format:
    <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA [SP MSG]

  Example:
    <34>1 2024-01-15T12:00:00.000Z firewall.example.com snort 1234 IDS - Intrusion detected from 10.0.0.1

  Returns `{:ok, parsed_map}` or `{:error, reason}`.
  """
  @spec parse_rfc5424(String.t()) :: {:ok, map()} | {:error, String.t()}
  def parse_rfc5424(raw) when is_binary(raw) do
    raw = String.trim(raw)

    with {:ok, priority, rest} <- parse_priority(raw),
         {facility, severity} = decode_priority(priority),
         {:ok, _version, rest} <- parse_version(rest),
         {:ok, timestamp, rest} <- parse_rfc5424_timestamp(rest),
         {:ok, hostname, rest} <- parse_token(rest),
         {:ok, app_name, rest} <- parse_token(rest),
         {:ok, proc_id, rest} <- parse_token(rest),
         {:ok, msg_id, rest} <- parse_token(rest),
         {:ok, structured_data, rest} <- parse_structured_data(rest) do
      message = String.trim(rest)

      parsed = %{
        format: :rfc5424,
        priority: priority,
        facility: facility,
        facility_name: Map.get(@syslog_facilities, facility, "unknown"),
        severity: severity,
        timestamp: timestamp,
        hostname: nilvalue_to_nil(hostname),
        app_name: nilvalue_to_nil(app_name),
        proc_id: nilvalue_to_nil(proc_id),
        msg_id: nilvalue_to_nil(msg_id),
        structured_data: structured_data,
        message: message,
        raw: raw
      }

      {:ok, parsed}
    else
      {:error, reason} ->
        # Fallback: try RFC 3164
        case parse_rfc3164(raw) do
          {:ok, _} = result -> result
          {:error, _} -> {:error, "RFC 5424 parse failed: #{reason}"}
        end
    end
  end

  def parse_rfc5424(_), do: {:error, "input must be a binary string"}

  # ── RFC 3164 Parser ────────────────────────────────────────────────

  @doc """
  Parse an RFC 3164 (BSD) syslog message.

  Format:
    <PRI>TIMESTAMP HOSTNAME APP-NAME[PROCID]: MSG

  Example:
    <13>Jan 15 12:00:00 myhost sshd[12345]: Accepted publickey for root

  Returns `{:ok, parsed_map}` or `{:error, reason}`.
  """
  @spec parse_rfc3164(String.t()) :: {:ok, map()} | {:error, String.t()}
  def parse_rfc3164(raw) when is_binary(raw) do
    raw = String.trim(raw)

    with {:ok, priority, rest} <- parse_priority(raw),
         {facility, severity} = decode_priority(priority) do
      # RFC 3164 timestamp format: "Mmm dd HH:MM:SS" or "Mmm  d HH:MM:SS"
      case parse_bsd_timestamp(rest) do
        {:ok, timestamp, rest2} ->
          {hostname, app_name, proc_id, message} = parse_bsd_header_and_message(rest2)

          parsed = %{
            format: :rfc3164,
            priority: priority,
            facility: facility,
            facility_name: Map.get(@syslog_facilities, facility, "unknown"),
            severity: severity,
            timestamp: timestamp,
            hostname: hostname,
            app_name: app_name,
            proc_id: proc_id,
            msg_id: nil,
            structured_data: %{},
            message: message,
            raw: raw
          }

          {:ok, parsed}

        {:error, _} ->
          # Timestamp parse failed -- treat entire remainder as message
          parsed = %{
            format: :rfc3164,
            priority: priority,
            facility: facility,
            facility_name: Map.get(@syslog_facilities, facility, "unknown"),
            severity: severity,
            timestamp: DateTime.utc_now(),
            hostname: nil,
            app_name: nil,
            proc_id: nil,
            msg_id: nil,
            structured_data: %{},
            message: rest,
            raw: raw
          }

          {:ok, parsed}
      end
    else
      {:error, _reason} ->
        # No valid priority -- treat the entire line as a plain message
        {:ok,
         %{
           format: :rfc3164,
           priority: 13,
           facility: 1,
           facility_name: "user",
           severity: 5,
           timestamp: DateTime.utc_now(),
           hostname: nil,
           app_name: nil,
           proc_id: nil,
           msg_id: nil,
           structured_data: %{},
           message: raw,
           raw: raw
         }}
    end
  end

  def parse_rfc3164(_), do: {:error, "input must be a binary string"}

  # ── CEF Parser ─────────────────────────────────────────────────────

  @doc """
  Parse a CEF (Common Event Format) message.

  Format:
    CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

  Extension is a set of key=value pairs separated by spaces. Values containing
  spaces are allowed; the parser handles the `key=value` boundary correctly by
  looking for the next known key token.

  Example:
    CEF:0|Palo Alto Networks|PAN-OS|9.1.0|threat|URL Filtering|5|src=10.0.0.1 dst=192.168.1.1 dpt=443 act=blocked

  Handles the common case where a syslog header precedes the CEF payload:
    <14>Jan 15 12:00:00 firewall CEF:0|...

  Returns `{:ok, parsed_map}` or `{:error, reason}`.
  """
  @spec parse_cef(String.t()) :: {:ok, map()} | {:error, String.t()}
  def parse_cef(raw) when is_binary(raw) do
    raw = String.trim(raw)

    # Extract CEF payload -- it may be preceded by a syslog header
    case extract_cef_payload(raw) do
      {:ok, syslog_prefix, cef_body} ->
        case String.split(cef_body, "|", parts: 8) do
          [version_str, vendor, product, device_version, sig_id, name, severity_str | rest] ->
            version = parse_cef_version(version_str)
            severity = Map.get(@cef_severity_map, String.downcase(String.trim(severity_str)), 4)

            extension_str =
              case rest do
                [ext] -> ext
                [] -> ""
              end

            extensions = parse_cef_extensions(extension_str)
            extracted = map_cef_to_extracted(extensions)

            # Parse syslog priority if present
            {syslog_facility, syslog_severity, syslog_hostname, syslog_timestamp} =
              parse_syslog_prefix(syslog_prefix)

            parsed = %{
              format: :cef,
              cef_version: version,
              device_vendor: String.trim(vendor),
              device_product: String.trim(product),
              device_version: String.trim(device_version),
              signature_id: String.trim(sig_id),
              name: String.trim(name),
              severity: severity,
              syslog_facility: syslog_facility,
              syslog_severity: syslog_severity,
              syslog_hostname: syslog_hostname,
              timestamp: syslog_timestamp || DateTime.utc_now(),
              extensions: extensions,
              extracted: extracted,
              message: name,
              raw: raw
            }

            {:ok, parsed}

          _ ->
            {:error, "CEF header does not contain enough pipe-delimited fields"}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  def parse_cef(_), do: {:error, "input must be a binary string"}

  # ── LEEF Parser ────────────────────────────────────────────────────

  @doc """
  Parse a LEEF (Log Event Extended Format) message.

  LEEF 1.0:
    LEEF:1.0|Vendor|Product|Version|EventID|key1=value1\\tkey2=value2
  LEEF 2.0:
    LEEF:2.0|Vendor|Product|Version|EventID|delimiter|key1=value1...

  The delimiter in LEEF 2.0 can be a tab (0x09), caret (^), or pipe (|) among
  others. LEEF 1.0 always uses tab as the attribute delimiter.

  Example:
    LEEF:1.0|IBM|QRadar|7.3.2|Authentication|src=10.0.0.1\\tdst=192.168.1.1\\tusrName=admin

  Returns `{:ok, parsed_map}` or `{:error, reason}`.
  """
  @spec parse_leef(String.t()) :: {:ok, map()} | {:error, String.t()}
  def parse_leef(raw) when is_binary(raw) do
    raw = String.trim(raw)

    # Extract LEEF payload -- may be preceded by a syslog header
    case extract_leef_payload(raw) do
      {:ok, syslog_prefix, leef_body} ->
        case parse_leef_header(leef_body) do
          {:ok, version, vendor, product, product_version, event_id, attributes_str} ->
            delimiter = determine_leef_delimiter(version, attributes_str)
            attributes = parse_leef_attributes(attributes_str, delimiter)
            extracted = map_leef_to_extracted(attributes)

            severity =
              case attributes["sev"] do
                nil -> 4
                sev -> Map.get(@leef_severity_map, String.trim(sev), 4)
              end

            {syslog_facility, syslog_severity, syslog_hostname, syslog_timestamp} =
              parse_syslog_prefix(syslog_prefix)

            parsed = %{
              format: :leef,
              leef_version: version,
              device_vendor: vendor,
              device_product: product,
              device_version: product_version,
              event_id: event_id,
              severity: severity,
              syslog_facility: syslog_facility,
              syslog_severity: syslog_severity,
              syslog_hostname: syslog_hostname,
              timestamp: syslog_timestamp || DateTime.utc_now(),
              attributes: attributes,
              extracted: extracted,
              message: "#{vendor} #{product} #{event_id}",
              raw: raw
            }

            {:ok, parsed}

          {:error, reason} ->
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  def parse_leef(_), do: {:error, "input must be a binary string"}

  # ── Normalize ──────────────────────────────────────────────────────

  @doc """
  Convert any parsed format into the common normalized schema.

  The common schema is:
    %{
      source_type: "syslog" | "cef" | "leef" | "json",
      source_ip: String.t(),
      timestamp: DateTime.t(),
      severity: integer(),    # 0-7
      facility: String.t(),
      hostname: String.t(),
      app_name: String.t(),
      message: String.t(),
      extracted: %{...},
      raw: String.t()
    }
  """
  @spec normalize(map()) :: map()
  def normalize(%{format: :rfc5424} = parsed) do
    %{
      source_type: "syslog",
      source_ip: nil,
      timestamp: parsed.timestamp,
      severity: parsed.severity,
      facility: parsed.facility_name,
      hostname: parsed.hostname || "",
      app_name: parsed.app_name || "",
      message: parsed.message || "",
      extracted: %{
        src_ip: nil,
        dst_ip: nil,
        src_port: nil,
        dst_port: nil,
        protocol: nil,
        action: nil,
        user: nil,
        device_vendor: nil,
        device_product: nil,
        signature_id: nil
      },
      raw: parsed.raw
    }
  end

  def normalize(%{format: :rfc3164} = parsed) do
    %{
      source_type: "syslog",
      source_ip: nil,
      timestamp: parsed.timestamp,
      severity: parsed.severity,
      facility: parsed.facility_name,
      hostname: parsed.hostname || "",
      app_name: parsed.app_name || "",
      message: parsed.message || "",
      extracted: %{
        src_ip: nil,
        dst_ip: nil,
        src_port: nil,
        dst_port: nil,
        protocol: nil,
        action: nil,
        user: nil,
        device_vendor: nil,
        device_product: nil,
        signature_id: nil
      },
      raw: parsed.raw
    }
  end

  def normalize(%{format: :cef} = parsed) do
    extracted = parsed.extracted || %{}

    %{
      source_type: "cef",
      source_ip: nil,
      timestamp: parsed.timestamp,
      severity: parsed.severity,
      facility: "cef",
      hostname: parsed.syslog_hostname || to_string(extracted[:device_hostname] || ""),
      app_name: parsed.device_product || "",
      message: parsed.name || parsed.message || "",
      extracted: %{
        src_ip: to_string_or_nil(extracted[:src_ip]),
        dst_ip: to_string_or_nil(extracted[:dst_ip]),
        src_port: to_integer_or_nil(extracted[:src_port]),
        dst_port: to_integer_or_nil(extracted[:dst_port]),
        protocol: to_string_or_nil(extracted[:protocol]),
        action: to_string_or_nil(extracted[:action]),
        user: to_string_or_nil(extracted[:user]),
        device_vendor: parsed.device_vendor,
        device_product: parsed.device_product,
        signature_id: parsed.signature_id
      },
      raw: parsed.raw
    }
  end

  def normalize(%{format: :leef} = parsed) do
    extracted = parsed.extracted || %{}

    %{
      source_type: "leef",
      source_ip: nil,
      timestamp: parsed.timestamp,
      severity: parsed.severity,
      facility: "leef",
      hostname: parsed.syslog_hostname || to_string(extracted[:identity_hostname] || ""),
      app_name: parsed.device_product || "",
      message: parsed.message || "",
      extracted: %{
        src_ip: to_string_or_nil(extracted[:src_ip]),
        dst_ip: to_string_or_nil(extracted[:dst_ip]),
        src_port: to_integer_or_nil(extracted[:src_port]),
        dst_port: to_integer_or_nil(extracted[:dst_port]),
        protocol: to_string_or_nil(extracted[:protocol]),
        action: to_string_or_nil(extracted[:action]),
        user: to_string_or_nil(extracted[:user]),
        device_vendor: parsed.device_vendor,
        device_product: parsed.device_product,
        signature_id: parsed.event_id
      },
      raw: parsed.raw
    }
  end

  def normalize(%{} = json_event) do
    # Normalize a JSON event that was submitted directly via the API
    %{
      source_type: to_string(json_event["source_type"] || json_event[:source_type] || "json"),
      source_ip: to_string(json_event["source_ip"] || json_event[:source_ip] || ""),
      timestamp: parse_any_timestamp(json_event["timestamp"] || json_event[:timestamp]),
      severity: parse_severity(json_event["severity"] || json_event[:severity]),
      facility: to_string(json_event["facility"] || json_event[:facility] || "json"),
      hostname: to_string(json_event["hostname"] || json_event[:hostname] || ""),
      app_name: to_string(json_event["app_name"] || json_event[:app_name] || ""),
      message: to_string(json_event["message"] || json_event[:message] || ""),
      extracted: normalize_extracted(json_event["extracted"] || json_event[:extracted] || %{}),
      raw: safe_json_encode(json_event)
    }
  end

  # ── IOC Extraction ─────────────────────────────────────────────────

  @doc """
  Extract IOCs (Indicators of Compromise) from a normalized event.

  Extracts:
  - IPv4 addresses (from extracted fields and raw message)
  - IPv6 addresses
  - Domain names
  - File hashes (MD5, SHA1, SHA256)

  Returns a map with categorized IOC lists.
  """
  @spec extract_iocs(map()) :: map()
  def extract_iocs(normalized_event) do
    message = normalized_event[:message] || normalized_event["message"] || ""
    raw = normalized_event[:raw] || normalized_event["raw"] || ""
    extracted = normalized_event[:extracted] || normalized_event["extracted"] || %{}

    # Combine all text sources for IOC scanning
    text = "#{message} #{raw}"

    # Extract IPs from both parsed fields and raw text
    field_ips =
      [extracted[:src_ip], extracted[:dst_ip]]
      |> Enum.reject(&is_nil/1)
      |> Enum.reject(&(&1 == ""))

    text_ipv4s = Regex.scan(@ipv4_pattern, text) |> List.flatten() |> Enum.uniq()
    text_ipv6s = Regex.scan(@ipv6_pattern, text) |> List.flatten() |> Enum.uniq()

    all_ips =
      (field_ips ++ text_ipv4s ++ text_ipv6s)
      |> Enum.uniq()
      |> Enum.reject(&private_ip?/1)

    # Extract domains
    domains =
      Regex.scan(@domain_pattern, text)
      |> List.flatten()
      |> Enum.uniq()
      |> Enum.reject(&common_tld_noise?/1)

    # Extract hashes
    sha256s = Regex.scan(@sha256_pattern, text) |> List.flatten() |> Enum.uniq()
    sha1s = Regex.scan(@sha1_pattern, text) |> List.flatten() |> Enum.uniq()
    # Remove SHA256 matches from SHA1 candidates (SHA256 contains valid SHA1 substrings)
    sha1s = sha1s -- Enum.flat_map(sha256s, fn h -> [String.slice(h, 0, 40)] end)
    md5s = Regex.scan(@md5_pattern, text) |> List.flatten() |> Enum.uniq()
    # Remove SHA1 & SHA256 overlaps from MD5 candidates
    md5s = md5s -- Enum.flat_map(sha1s ++ sha256s, fn h -> [String.slice(h, 0, 32)] end)

    %{
      ips: all_ips,
      domains: domains,
      hashes: %{
        md5: md5s,
        sha1: sha1s,
        sha256: sha256s
      },
      total_count: length(all_ips) + length(domains) + length(md5s) + length(sha1s) + length(sha256s)
    }
  end

  @doc """
  Auto-detect the format of a raw log line and parse it accordingly.

  Tries formats in order: CEF, LEEF, RFC 5424, RFC 3164, then falls back to
  treating the line as a plain text syslog message.
  """
  @spec auto_parse(String.t()) :: {:ok, map()} | {:error, String.t()}
  def auto_parse(raw) when is_binary(raw) do
    raw = String.trim(raw)

    cond do
      String.contains?(raw, "CEF:") ->
        parse_cef(raw)

      String.contains?(raw, "LEEF:") ->
        parse_leef(raw)

      Regex.match?(~r/^<\d{1,3}>\d /, raw) ->
        parse_rfc5424(raw)

      Regex.match?(~r/^<\d{1,3}>/, raw) ->
        parse_rfc3164(raw)

      true ->
        # Plain text -- wrap as RFC 3164 with default priority
        parse_rfc3164("<13>#{raw}")
    end
  end

  def auto_parse(_), do: {:error, "input must be a binary string"}

  # ── Private: Priority Parsing ──────────────────────────────────────

  defp parse_priority(<<"<", rest::binary>>) do
    case Integer.parse(rest) do
      {pri, ">" <> remainder} when pri >= 0 and pri <= 191 ->
        {:ok, pri, remainder}

      _ ->
        {:error, "invalid priority value"}
    end
  end

  defp parse_priority(_), do: {:error, "missing priority '<PRI>'"}

  defp decode_priority(priority) when is_integer(priority) do
    facility = div(priority, 8)
    severity = rem(priority, 8)
    {facility, severity}
  end

  # ── Private: RFC 5424 Helpers ──────────────────────────────────────

  defp parse_version(str) do
    case str do
      "1 " <> rest -> {:ok, 1, rest}
      "1" <> rest -> {:ok, 1, rest}
      _ -> {:error, "unsupported or missing syslog version"}
    end
  end

  defp parse_rfc5424_timestamp(str) do
    {token, rest} = next_sp_token(str)

    case token do
      "-" ->
        {:ok, DateTime.utc_now(), rest}

      ts_str ->
        case DateTime.from_iso8601(ts_str) do
          {:ok, dt, _offset} -> {:ok, dt, rest}
          {:error, _} ->
            # Try NaiveDateTime and assume UTC
            case NaiveDateTime.from_iso8601(ts_str) do
              {:ok, ndt} ->
                {:ok, DateTime.from_naive!(ndt, "Etc/UTC"), rest}
              {:error, _} ->
                {:error, "invalid RFC 5424 timestamp: #{ts_str}"}
            end
        end
    end
  end

  defp parse_token(str) do
    {token, rest} = next_sp_token(str)
    {:ok, token, rest}
  end

  defp parse_structured_data("-" <> rest) do
    rest = if String.starts_with?(rest, " "), do: String.trim_leading(rest, " "), else: rest
    {:ok, %{}, rest}
  end

  defp parse_structured_data(str) do
    case parse_sd_elements(str, %{}) do
      {:ok, sd, rest} -> {:ok, sd, String.trim_leading(rest)}
      {:error, _reason} -> {:ok, %{}, str}
    end
  end

  defp parse_sd_elements("[" <> rest, acc) do
    case String.split(rest, "]", parts: 2) do
      [element_body, remainder] ->
        {sd_id, params} = parse_sd_element(element_body)
        new_acc = Map.put(acc, sd_id, params)
        # Check for more SD elements or message
        remainder = String.trim_leading(remainder)

        if String.starts_with?(remainder, "[") do
          parse_sd_elements(remainder, new_acc)
        else
          {:ok, new_acc, remainder}
        end

      _ ->
        {:error, "unterminated structured-data element"}
    end
  end

  defp parse_sd_elements(str, acc) do
    {:ok, acc, str}
  end

  defp parse_sd_element(body) do
    parts = String.split(body, " ", parts: 2)

    case parts do
      [sd_id] ->
        {sd_id, %{}}

      [sd_id, params_str] ->
        params = parse_sd_params(params_str)
        {sd_id, params}
    end
  end

  defp parse_sd_params(str) do
    # Parse key="value" pairs, handling escaped quotes
    Regex.scan(~r/(\w[\w\.\-]*)="((?:[^"\\]|\\.)*)"/, str)
    |> Enum.reduce(%{}, fn
      [_full, key, value], acc ->
        Map.put(acc, key, String.replace(value, "\\\"", "\""))
      _, acc ->
        acc
    end)
  end

  # ── Private: RFC 3164 / BSD Helpers ────────────────────────────────

  @months %{
    "Jan" => 1, "Feb" => 2, "Mar" => 3, "Apr" => 4,
    "May" => 5, "Jun" => 6, "Jul" => 7, "Aug" => 8,
    "Sep" => 9, "Oct" => 10, "Nov" => 11, "Dec" => 12
  }

  defp parse_bsd_timestamp(str) do
    # BSD timestamp: "Mmm dd HH:MM:SS " or "Mmm  d HH:MM:SS "
    regex = ~r/^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(.*)/s

    case Regex.run(regex, str) do
      [_full, month_str, day_str, hour_str, min_str, sec_str, rest] ->
        month = Map.get(@months, month_str, 1)
        day = String.to_integer(day_str)
        hour = String.to_integer(hour_str)
        minute = String.to_integer(min_str)
        second = String.to_integer(sec_str)

        # BSD syslog doesn't include year; assume current year
        now = DateTime.utc_now()
        year = now.year

        case NaiveDateTime.new(year, month, day, hour, minute, second) do
          {:ok, ndt} ->
            dt = DateTime.from_naive!(ndt, "Etc/UTC")
            {:ok, dt, rest}

          {:error, _} ->
            {:ok, DateTime.utc_now(), rest}
        end

      nil ->
        # Try ISO 8601 timestamp (some BSD implementations use it)
        {token, rest} = next_sp_token(str)

        case DateTime.from_iso8601(token) do
          {:ok, dt, _} -> {:ok, dt, rest}
          {:error, _} -> {:error, "unrecognized BSD timestamp"}
        end
    end
  end

  defp parse_bsd_header_and_message(str) do
    str = String.trim_leading(str)

    # Try to parse "HOSTNAME APP-NAME[PID]: MSG" or "HOSTNAME APP-NAME: MSG"
    case Regex.run(~r/^(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)/s, str) do
      [_full, hostname, app_name, proc_id, message] ->
        proc_id = if proc_id == "", do: nil, else: proc_id
        {hostname, app_name, proc_id, message}

      nil ->
        # Try "HOSTNAME MSG" without app_name
        case Regex.run(~r/^(\S+)\s+(.*)/s, str) do
          [_full, hostname, message] ->
            {hostname, nil, nil, message}

          nil ->
            {nil, nil, nil, str}
        end
    end
  end

  # ── Private: CEF Helpers ───────────────────────────────────────────

  defp extract_cef_payload(raw) do
    case :binary.match(raw, "CEF:") do
      {pos, _len} ->
        prefix = binary_part(raw, 0, pos)
        cef_body = binary_part(raw, pos + 4, byte_size(raw) - pos - 4)
        {:ok, String.trim(prefix), cef_body}

      :nomatch ->
        {:error, "no CEF: header found"}
    end
  end

  defp parse_cef_version(version_str) do
    version_str = String.trim(version_str)

    case Integer.parse(version_str) do
      {v, _} -> v
      :error -> 0
    end
  end

  defp parse_cef_extensions(""), do: %{}

  defp parse_cef_extensions(ext_str) do
    # CEF extensions: key=value pairs separated by whitespace.
    # Values can contain spaces, but keys cannot. We use a regex that matches
    # key=value where the value runs until the next key= pattern or end of string.
    ext_str = String.trim(ext_str)

    # Split on key=value boundaries: look ahead for the next "word=" pattern
    # This regex captures key and value, where value extends to the next key=
    # or end of string.
    Regex.scan(~r/(\w+)=((?:(?!\s+\w+=).)*)/s, ext_str)
    |> Enum.reduce(%{}, fn
      [_full, key, value], acc ->
        Map.put(acc, String.trim(key), String.trim(value))

      _, acc ->
        acc
    end)
  end

  defp map_cef_to_extracted(extensions) do
    Enum.reduce(extensions, %{}, fn {key, value}, acc ->
      case Map.get(@cef_key_aliases, key) do
        # Keep unknown keys as raw strings. Calling String.to_atom/1 on
        # attacker-controlled CEF keys would mint unbounded atoms and exhaust
        # the BEAM atom table (whole-VM crash). Downstream only reads the known
        # mapped atom keys, so unknown keys are never consumed anyway.
        nil -> Map.put(acc, key, value)
        mapped_key -> Map.put(acc, mapped_key, value)
      end
    end)
  end

  # ── Private: LEEF Helpers ──────────────────────────────────────────

  defp extract_leef_payload(raw) do
    case :binary.match(raw, "LEEF:") do
      {pos, _len} ->
        prefix = binary_part(raw, 0, pos)
        leef_body = binary_part(raw, pos + 5, byte_size(raw) - pos - 5)
        {:ok, String.trim(prefix), leef_body}

      :nomatch ->
        {:error, "no LEEF: header found"}
    end
  end

  defp parse_leef_header(body) do
    parts = String.split(body, "|")

    case parts do
      [version, vendor, product, prod_version, event_id | rest] ->
        # LEEF 2.0 has a delimiter field as the 6th pipe-separated value
        {attributes_str, _actual_delimiter} =
          if String.starts_with?(version, "2") and length(rest) >= 1 do
            # rest[0] is the delimiter specifier, rest[1..] is attributes
            [_delim_spec | attr_parts] = rest
            {Enum.join(attr_parts, "|"), nil}
          else
            {Enum.join(rest, "|"), nil}
          end

        {:ok, String.trim(version), String.trim(vendor), String.trim(product),
         String.trim(prod_version), String.trim(event_id), attributes_str}

      _ ->
        {:error, "LEEF header does not contain enough pipe-delimited fields"}
    end
  end

  defp determine_leef_delimiter(version, attributes_str) do
    cond do
      # LEEF 1.0 always uses tab
      String.starts_with?(version, "1") -> "\t"
      # LEEF 2.0 -- detect from content
      String.contains?(attributes_str, "\t") -> "\t"
      String.contains?(attributes_str, "^") -> "^"
      # Default to tab
      true -> "\t"
    end
  end

  defp parse_leef_attributes(str, delimiter) do
    str
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

  defp map_leef_to_extracted(attributes) do
    Enum.reduce(attributes, %{}, fn {key, value}, acc ->
      case Map.get(@leef_key_aliases, key) do
        # Keep unknown keys as raw strings to avoid atom-table exhaustion from
        # attacker-controlled LEEF attributes. Downstream only reads the known
        # mapped atom keys.
        nil -> Map.put(acc, key, value)
        mapped_key -> Map.put(acc, mapped_key, value)
      end
    end)
  end

  # ── Private: Syslog Prefix for CEF/LEEF ───────────────────────────

  defp parse_syslog_prefix(""), do: {nil, nil, nil, nil}

  defp parse_syslog_prefix(prefix) do
    case parse_priority(prefix) do
      {:ok, priority, rest} ->
        {facility, severity} = decode_priority(priority)

        case parse_bsd_timestamp(rest) do
          {:ok, timestamp, rest2} ->
            {hostname, _, _, _} = parse_bsd_header_and_message(rest2)
            {facility, severity, hostname, timestamp}

          {:error, _} ->
            {facility, severity, nil, nil}
        end

      {:error, _} ->
        {nil, nil, nil, nil}
    end
  end

  # ── Private: Utility Functions ─────────────────────────────────────

  defp next_sp_token(str) do
    str = String.trim_leading(str)

    case String.split(str, " ", parts: 2) do
      [token, rest] -> {token, rest}
      [token] -> {token, ""}
    end
  end

  defp nilvalue_to_nil("-"), do: nil
  defp nilvalue_to_nil(val), do: val

  defp to_string_or_nil(nil), do: nil
  defp to_string_or_nil(val), do: to_string(val)

  defp to_integer_or_nil(nil), do: nil

  defp to_integer_or_nil(val) when is_integer(val), do: val

  defp to_integer_or_nil(val) when is_binary(val) do
    case Integer.parse(val) do
      {n, _} -> n
      :error -> nil
    end
  end

  defp to_integer_or_nil(_), do: nil

  defp parse_any_timestamp(nil), do: DateTime.utc_now()

  defp parse_any_timestamp(%DateTime{} = dt), do: dt

  defp parse_any_timestamp(ts) when is_integer(ts) and ts > 1_000_000_000_000 do
    case DateTime.from_unix(ts, :millisecond) do
      {:ok, dt} -> dt
      _ -> DateTime.utc_now()
    end
  end

  defp parse_any_timestamp(ts) when is_integer(ts) and ts > 0 do
    case DateTime.from_unix(ts) do
      {:ok, dt} -> dt
      _ -> DateTime.utc_now()
    end
  end

  defp parse_any_timestamp(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      {:error, _} -> DateTime.utc_now()
    end
  end

  defp parse_any_timestamp(_), do: DateTime.utc_now()

  defp parse_severity(nil), do: 5

  defp parse_severity(sev) when is_integer(sev) and sev >= 0 and sev <= 7, do: sev
  defp parse_severity(sev) when is_integer(sev), do: min(max(sev, 0), 7)

  defp parse_severity(sev) when is_binary(sev) do
    case Integer.parse(sev) do
      {n, _} -> min(max(n, 0), 7)
      :error ->
        case String.downcase(sev) do
          "emergency" -> 0
          "alert" -> 1
          "critical" -> 2
          "error" -> 3
          "warning" -> 4
          "notice" -> 5
          "info" -> 6
          "informational" -> 6
          "debug" -> 7
          _ -> 5
        end
    end
  end

  defp parse_severity(_), do: 5

  defp normalize_extracted(ext) when is_map(ext) do
    %{
      src_ip: to_string_or_nil(ext["src_ip"] || ext[:src_ip]),
      dst_ip: to_string_or_nil(ext["dst_ip"] || ext[:dst_ip]),
      src_port: to_integer_or_nil(ext["src_port"] || ext[:src_port]),
      dst_port: to_integer_or_nil(ext["dst_port"] || ext[:dst_port]),
      protocol: to_string_or_nil(ext["protocol"] || ext[:protocol]),
      action: to_string_or_nil(ext["action"] || ext[:action]),
      user: to_string_or_nil(ext["user"] || ext[:user]),
      device_vendor: to_string_or_nil(ext["device_vendor"] || ext[:device_vendor]),
      device_product: to_string_or_nil(ext["device_product"] || ext[:device_product]),
      signature_id: to_string_or_nil(ext["signature_id"] || ext[:signature_id])
    }
  end

  defp normalize_extracted(_), do: %{
    src_ip: nil, dst_ip: nil, src_port: nil, dst_port: nil,
    protocol: nil, action: nil, user: nil,
    device_vendor: nil, device_product: nil, signature_id: nil
  }

  defp private_ip?(ip) when is_binary(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, {10, _, _, _}} -> true
      {:ok, {172, b, _, _}} when b >= 16 and b <= 31 -> true
      {:ok, {192, 168, _, _}} -> true
      {:ok, {127, _, _, _}} -> true
      {:ok, {0, 0, 0, 0}} -> true
      _ -> false
    end
  rescue
    _ -> false
  end

  defp common_tld_noise?(domain) do
    # Filter out common false positives in domain extraction
    String.ends_with?(domain, ".local") or
      String.ends_with?(domain, ".internal") or
      String.ends_with?(domain, ".localhost") or
      domain in ["example.com", "test.com", "localhost.localdomain"]
  end

  defp safe_json_encode(data) when is_map(data) do
    case Jason.encode(data) do
      {:ok, json} -> json
      _ -> "{}"
    end
  end

  defp safe_json_encode(data) when is_binary(data), do: data
  defp safe_json_encode(_), do: "{}"
end
