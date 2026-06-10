defmodule TamanduaServer.XDR.Sources.Proxy do
  @moduledoc """
  XDR source connector for web proxy logs.

  Supports:
  - Zscaler Internet Access (ZIA)
  - Broadcom/Symantec Blue Coat (ProxySG)
  - Squid Proxy
  - McAfee Web Gateway
  - Forcepoint Web Security

  Normalizes web traffic data including URLs, user agents, and categorization.
  """

  require Logger

  @vendors %{
    "zscaler" => &__MODULE__.parse_zscaler/1,
    "bluecoat" => &__MODULE__.parse_bluecoat/1,
    "squid" => &__MODULE__.parse_squid/1,
    "mcafee" => &__MODULE__.parse_mcafee/1,
    "forcepoint" => &__MODULE__.parse_forcepoint/1
  }

  @doc """
  Parse a proxy log event.

  ## Options
  - :vendor - Specific vendor (zscaler, bluecoat, squid, mcafee, forcepoint)
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

  defp detect_and_parse_map(data) do
    cond do
      # Zscaler has specific fields
      Map.has_key?(data, "Company") and Map.has_key?(data, "ClientIP") ->
        parse_zscaler(data)

      # Blue Coat ELFF format
      Map.has_key?(data, "sc-status") or Map.has_key?(data, "cs-uri-stem") ->
        parse_bluecoat(data)

      # Squid native format
      Map.has_key?(data, "squid_action") or Map.has_key?(data, "squid_status") ->
        parse_squid(data)

      true ->
        parse_generic_proxy(data)
    end
  end

  defp detect_and_parse_string(data) do
    cond do
      # Squid access log format
      Regex.match?(~r/^\d+\.\d+\s+\d+\s+[\d\.]+\s+\w+_\w+\/\d+/, data) ->
        parse_squid_line(data)

      # Blue Coat ELFF (tab-separated with specific fields)
      Regex.match?(~r/^"\d{4}-\d{2}-\d{2}/, data) ->
        parse_bluecoat_line(data)

      true ->
        {:error, :unknown_vendor}
    end
  end

  # Zscaler Parsing

  @doc false
  def parse_zscaler(data) when is_map(data) do
    event = %{
      timestamp: parse_zscaler_timestamp(data["time"] || data["DateTime"]),
      source_type: "proxy",
      device_vendor: "Zscaler",
      device_product: "ZIA",
      source_ip: data["ClientIP"] || data["clientpublicIP"],
      source_hostname: data["Hostname"],
      user_name: data["Login"] || data["user"],
      user_email: data["Login"],
      url: build_zscaler_url(data),
      url_domain: data["ServerIP"] || data["urlhostname"] || data["hostname"],
      url_path: data["URL"],
      network_protocol: "HTTP",
      action: normalize_zscaler_action(data["Action"]),
      outcome: if(data["Action"] == "Blocked", do: "failure", else: "success"),
      threat_name: data["threatname"],
      threat_category: data["urlsupercategory"] || data["urlcategory"],
      severity: zscaler_severity(data),
      file_name: data["filename"],
      file_hash_md5: data["md5"],
      bytes_in: parse_int(data["requestsize"]),
      bytes_out: parse_int(data["responsesize"]),
      event_category: "web",
      event_type: data["event_type"] || "proxy",
      parsed_fields: %{
        company: data["Company"],
        department: data["Department"],
        location: data["Location"],
        dlp_engine: data["dlpengine"],
        dlp_dictionaries: data["dlpdictionaries"],
        url_class: data["urlclass"],
        app_name: data["appname"],
        app_class: data["appclass"],
        bandwidth_class: data["bwclassname"],
        device_type: data["devicetype"],
        device_model: data["devicemodel"],
        device_os: data["deviceostype"],
        device_os_version: data["deviceosversion"]
      }
    }

    # Add MITRE mappings for threats
    event = if event[:threat_name] do
      Map.merge(event, %{
        mitre_tactics: ["initial_access"],
        mitre_techniques: ["T1189"]  # Drive-by Compromise
      })
    else
      event
    end

    {:ok, event}
  end

  defp build_zscaler_url(data) do
    protocol = data["protocolevent"] || "https"
    hostname = data["hostname"] || data["urlhostname"]
    path = data["URL"] || data["urlpath"]

    if hostname do
      "#{protocol}://#{hostname}#{path || ""}"
    else
      path
    end
  end

  defp parse_zscaler_timestamp(nil), do: DateTime.utc_now()
  defp parse_zscaler_timestamp(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end

  defp normalize_zscaler_action(nil), do: "unknown"
  defp normalize_zscaler_action(action) when is_binary(action) do
    case String.downcase(action) do
      "allowed" -> "allow"
      "blocked" -> "block"
      "cautioned" -> "alert"
      "isolated" -> "quarantine"
      a -> a
    end
  end

  defp zscaler_severity(data) do
    cond do
      data["threatname"] -> "high"
      data["Action"] == "Blocked" -> "medium"
      data["dlpengine"] -> "medium"
      true -> "info"
    end
  end

  # Blue Coat / Broadcom Parsing

  @doc false
  def parse_bluecoat(data) when is_map(data) do
    event = %{
      timestamp: parse_bluecoat_timestamp(data["date"], data["time"]),
      source_type: "proxy",
      device_vendor: "Broadcom",
      device_product: "Blue Coat ProxySG",
      source_ip: data["c-ip"],
      source_port: parse_int(data["c-port"]),
      dest_ip: data["s-ip"],
      dest_port: parse_int(data["s-port"]),
      user_name: data["cs-user"] || data["cs-username"],
      url: build_bluecoat_url(data),
      url_domain: data["cs-host"],
      url_path: data["cs-uri-stem"],
      network_protocol: data["cs-uri-scheme"] || "HTTP",
      action: normalize_bluecoat_action(data["sc-filter-result"]),
      outcome: bluecoat_outcome(data["sc-status"]),
      threat_category: data["sc-filter-category"],
      severity: bluecoat_severity(data),
      http_method: data["cs-method"],
      http_status: parse_int(data["sc-status"]),
      bytes_in: parse_int(data["sc-bytes"]),
      bytes_out: parse_int(data["cs-bytes"]),
      event_category: "web",
      parsed_fields: %{
        user_agent: data["cs(User-Agent)"],
        referer: data["cs(Referer)"],
        content_type: data["rs(Content-Type)"],
        x_forwarded_for: data["x-bluecoat-via"],
        filter_result: data["sc-filter-result"],
        filter_category: data["sc-filter-category"]
      }
    }

    {:ok, event}
  end

  defp parse_bluecoat_line(line) do
    # ELFF format is typically tab or space separated with quoted fields
    # Simple parsing - real implementation would handle ELFF header
    fields = String.split(line, ~r/[\t\s]+/)
    |> Enum.map(&String.trim(&1, "\""))

    # Minimal extraction - would need ELFF header for proper mapping
    data = %{
      "date" => Enum.at(fields, 0),
      "time" => Enum.at(fields, 1),
      "c-ip" => Enum.at(fields, 2),
      "sc-status" => Enum.at(fields, 3)
    }

    parse_bluecoat(data)
  end

  defp build_bluecoat_url(data) do
    scheme = data["cs-uri-scheme"] || "http"
    host = data["cs-host"]
    path = data["cs-uri-stem"]
    query = data["cs-uri-query"]

    cond do
      host && path && query -> "#{scheme}://#{host}#{path}?#{query}"
      host && path -> "#{scheme}://#{host}#{path}"
      host -> "#{scheme}://#{host}"
      true -> nil
    end
  end

  defp parse_bluecoat_timestamp(date, time) when is_binary(date) and is_binary(time) do
    case DateTime.from_iso8601("#{date}T#{time}Z") do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end
  defp parse_bluecoat_timestamp(_, _), do: DateTime.utc_now()

  defp normalize_bluecoat_action(nil), do: "unknown"
  defp normalize_bluecoat_action(result) when is_binary(result) do
    case String.downcase(result) do
      r when r in ["observed", "allowed", "proxied"] -> "allow"
      r when r in ["denied", "blocked"] -> "block"
      r when r in ["warned", "cautioned"] -> "alert"
      r -> r
    end
  end

  defp bluecoat_outcome(nil), do: "unknown"
  defp bluecoat_outcome(status) when is_binary(status) do
    case Integer.parse(status) do
      {code, _} when code >= 200 and code < 400 -> "success"
      {code, _} when code >= 400 -> "failure"
      _ -> "unknown"
    end
  end
  defp bluecoat_outcome(status) when is_integer(status) do
    cond do
      status >= 200 and status < 400 -> "success"
      status >= 400 -> "failure"
      true -> "unknown"
    end
  end

  defp bluecoat_severity(data) do
    action = normalize_bluecoat_action(data["sc-filter-result"])
    cond do
      action == "block" -> "medium"
      action == "alert" -> "low"
      true -> "info"
    end
  end

  # Squid Parsing

  @doc false
  def parse_squid(data) when is_map(data) do
    event = %{
      timestamp: parse_squid_timestamp(data["timestamp"]),
      source_type: "proxy",
      device_vendor: "Squid",
      device_product: "Squid Proxy",
      source_ip: data["client_ip"],
      user_name: data["user"] || "-",
      url: data["url"],
      url_domain: extract_squid_domain(data["url"]),
      network_protocol: "HTTP",
      action: normalize_squid_action(data["squid_action"] || data["action"]),
      outcome: squid_outcome(data["http_status"] || data["squid_status"]),
      http_method: data["http_method"] || data["method"],
      http_status: parse_int(data["http_status"] || data["status"]),
      bytes_out: parse_int(data["bytes"]),
      event_category: "web",
      parsed_fields: %{
        response_time: data["response_time"],
        peer_status: data["peer_status"],
        content_type: data["content_type"]
      }
    }

    {:ok, event}
  end

  defp parse_squid_line(line) do
    # Squid native format: timestamp response_time client_ip squid_action/http_status bytes method url user peer_status/peer_host content_type
    case Regex.run(~r/^(\d+\.\d+)\s+(\d+)\s+([\d\.]+)\s+(\w+)\/(\d+)\s+(\d+)\s+(\w+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(\S*)/, line) do
      [_, ts, resp_time, client_ip, squid_action, http_status, bytes, method, url, user, peer, content_type] ->
        data = %{
          "timestamp" => ts,
          "response_time" => resp_time,
          "client_ip" => client_ip,
          "squid_action" => squid_action,
          "http_status" => http_status,
          "bytes" => bytes,
          "http_method" => method,
          "url" => url,
          "user" => user,
          "peer_status" => peer,
          "content_type" => content_type
        }
        parse_squid(data)

      _ ->
        {:error, :invalid_squid_format}
    end
  end

  defp parse_squid_timestamp(nil), do: DateTime.utc_now()
  defp parse_squid_timestamp(ts) when is_binary(ts) do
    case Float.parse(ts) do
      {epoch, _} ->
        case DateTime.from_unix(trunc(epoch)) do
          {:ok, dt} -> dt
          _ -> DateTime.utc_now()
        end
      _ -> DateTime.utc_now()
    end
  end

  defp extract_squid_domain(nil), do: nil
  defp extract_squid_domain(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{host: host} when is_binary(host) -> host
      _ -> nil
    end
  end

  defp normalize_squid_action(nil), do: "unknown"
  defp normalize_squid_action(action) when is_binary(action) do
    action_upper = String.upcase(action)
    cond do
      String.contains?(action_upper, "HIT") -> "allow"
      String.contains?(action_upper, "MISS") -> "allow"
      String.contains?(action_upper, "DENIED") -> "deny"
      String.contains?(action_upper, "NONE") -> "block"
      String.contains?(action_upper, "DIRECT") -> "allow"
      true -> "allow"
    end
  end

  defp squid_outcome(nil), do: "unknown"
  defp squid_outcome(status) when is_binary(status) do
    case Integer.parse(status) do
      {code, _} when code >= 200 and code < 400 -> "success"
      {code, _} when code >= 400 -> "failure"
      {0, _} -> "failure"  # Squid uses 0 for connection failures
      _ -> "unknown"
    end
  end
  defp squid_outcome(status) when is_integer(status), do: squid_outcome(to_string(status))

  # McAfee Web Gateway Parsing

  @doc false
  def parse_mcafee(data) when is_map(data) do
    event = %{
      timestamp: data["timestamp"] || DateTime.utc_now(),
      source_type: "proxy",
      device_vendor: "McAfee",
      device_product: "Web Gateway",
      source_ip: data["client_ip"] || data["src_ip"],
      user_name: data["user"] || data["user_name"],
      url: data["url"] || data["request_url"],
      url_domain: data["host"] || data["destination_host"],
      network_protocol: data["protocol"] || "HTTP",
      action: normalize_mcafee_action(data["action"] || data["block_reason"]),
      outcome: if(data["action"] == "DENIED", do: "failure", else: "success"),
      threat_name: data["virus_name"] || data["threat_name"],
      threat_category: data["category"] || data["url_category"],
      severity: mcafee_severity(data),
      http_method: data["http_method"],
      http_status: parse_int(data["http_status"]),
      bytes_in: parse_int(data["bytes_received"]),
      bytes_out: parse_int(data["bytes_sent"]),
      event_category: "web",
      parsed_fields: data
    }

    {:ok, event}
  end

  defp normalize_mcafee_action(nil), do: "unknown"
  defp normalize_mcafee_action(action) when is_binary(action) do
    case String.upcase(action) do
      "ALLOWED" -> "allow"
      "DENIED" -> "deny"
      "BLOCKED" -> "block"
      a -> String.downcase(a)
    end
  end

  defp mcafee_severity(data) do
    cond do
      data["virus_name"] || data["threat_name"] -> "high"
      data["action"] in ["DENIED", "BLOCKED"] -> "medium"
      true -> "info"
    end
  end

  # Forcepoint Parsing

  @doc false
  def parse_forcepoint(data) when is_map(data) do
    event = %{
      timestamp: data["timestamp"] || DateTime.utc_now(),
      source_type: "proxy",
      device_vendor: "Forcepoint",
      device_product: "Web Security",
      source_ip: data["srcip"] || data["client_ip"],
      user_name: data["user"] || data["username"],
      url: data["url"],
      url_domain: data["host"] || data["destination"],
      network_protocol: data["protocol"] || "HTTP",
      action: normalize_forcepoint_action(data["disposition"] || data["action"]),
      outcome: forcepoint_outcome(data["disposition"]),
      threat_category: data["category"],
      severity: forcepoint_severity(data),
      http_method: data["method"],
      http_status: parse_int(data["status_code"]),
      bytes_in: parse_int(data["bytes_in"]),
      bytes_out: parse_int(data["bytes_out"]),
      event_category: "web",
      parsed_fields: data
    }

    {:ok, event}
  end

  defp normalize_forcepoint_action(nil), do: "unknown"
  defp normalize_forcepoint_action(disposition) when is_binary(disposition) do
    case String.downcase(disposition) do
      d when d in ["permitted", "allowed"] -> "allow"
      d when d in ["blocked", "denied"] -> "block"
      d when d in ["warned", "confirmed"] -> "alert"
      d -> d
    end
  end

  defp forcepoint_outcome(nil), do: "unknown"
  defp forcepoint_outcome(disposition) when is_binary(disposition) do
    case String.downcase(disposition) do
      d when d in ["permitted", "allowed", "confirmed"] -> "success"
      d when d in ["blocked", "denied"] -> "failure"
      _ -> "unknown"
    end
  end

  defp forcepoint_severity(data) do
    action = normalize_forcepoint_action(data["disposition"] || data["action"])
    cond do
      action == "block" -> "medium"
      action == "alert" -> "low"
      true -> "info"
    end
  end

  # Generic Proxy Parsing

  defp parse_generic_proxy(data) do
    event = %{
      timestamp: data["timestamp"] || DateTime.utc_now(),
      source_type: "proxy",
      source_ip: data["client_ip"] || data["src_ip"] || data["c-ip"],
      user_name: data["user"] || data["username"],
      url: data["url"] || data["request_url"],
      url_domain: data["host"] || data["destination"],
      network_protocol: data["protocol"] || "HTTP",
      action: data["action"],
      http_method: data["method"] || data["http_method"],
      http_status: parse_int(data["status"] || data["http_status"]),
      event_category: "web",
      severity: "info",
      parsed_fields: data
    }

    {:ok, event}
  end

  # Helpers

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
