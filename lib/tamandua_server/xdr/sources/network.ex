defmodule TamanduaServer.XDR.Sources.Network do
  @moduledoc """
  XDR source connector for network security monitoring logs.

  Supports:
  - Zeek (formerly Bro) - Network analysis framework
  - Suricata - IDS/IPS engine
  - Snort - IDS/IPS engine
  - Corelight - Enterprise Zeek
  - Darktrace - AI-driven network detection

  Normalizes network traffic metadata, DNS queries, HTTP transactions,
  TLS handshakes, and IDS/IPS alerts.
  """

  require Logger

  @vendors %{
    "zeek" => &__MODULE__.parse_zeek/1,
    "suricata" => &__MODULE__.parse_suricata/1,
    "snort" => &__MODULE__.parse_snort/1,
    "corelight" => &__MODULE__.parse_corelight/1,
    "darktrace" => &__MODULE__.parse_darktrace/1
  }

  @doc """
  Parse a network security log event.

  ## Options
  - :vendor - Specific vendor (zeek, suricata, snort, corelight, darktrace)
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
      # Zeek JSON
      Map.has_key?(data, "_path") and Map.has_key?(data, "ts") -> parse_zeek(data)

      # Suricata EVE JSON
      Map.has_key?(data, "event_type") and Map.has_key?(data, "src_ip") -> parse_suricata(data)

      # Snort JSON
      Map.has_key?(data, "sid") and Map.has_key?(data, "gid") -> parse_snort(data)

      # Corelight
      Map.has_key?(data, "_path") and Map.has_key?(data, "corelight_shunted") -> parse_corelight(data)

      # Darktrace
      Map.has_key?(data, "did") and Map.has_key?(data, "score") -> parse_darktrace(data)

      true -> parse_generic_network(data)
    end
  end

  defp detect_and_parse_string(data) do
    # Try JSON first
    case Jason.decode(data) do
      {:ok, json} -> detect_and_parse_map(json)
      {:error, _} ->
        # Try Snort/Suricata alert format
        cond do
          String.contains?(data, "[**]") -> parse_snort_fast(data)
          String.contains?(data, "Classification:") -> parse_snort_full(data)
          true -> {:error, :unknown_format}
        end
    end
  end

  # Zeek Parsing

  @doc false
  def parse_zeek(data) when is_map(data) do
    log_type = data["_path"]

    base = %{
      timestamp: parse_zeek_timestamp(data["ts"]),
      source_type: "network",
      device_vendor: "Zeek",
      device_product: "Zeek",
      source_ip: data["id.orig_h"] || data["orig_h"],
      source_port: data["id.orig_p"] || data["orig_p"],
      dest_ip: data["id.resp_h"] || data["resp_h"],
      dest_port: data["id.resp_p"] || data["resp_p"],
      network_protocol: data["proto"],
      event_category: "network",
      event_type: log_type
    }

    # Type-specific parsing
    type_fields = case log_type do
      "conn" -> parse_zeek_conn(data)
      "dns" -> parse_zeek_dns(data)
      "http" -> parse_zeek_http(data)
      "ssl" -> parse_zeek_ssl(data)
      "files" -> parse_zeek_files(data)
      "notice" -> parse_zeek_notice(data)
      "x509" -> parse_zeek_x509(data)
      "smtp" -> parse_zeek_smtp(data)
      "ssh" -> parse_zeek_ssh(data)
      "kerberos" -> parse_zeek_kerberos(data)
      _ -> %{severity: "info", parsed_fields: data}
    end

    event = Map.merge(base, type_fields)
    event = add_zeek_mitre(event, log_type, data)

    {:ok, event}
  end

  defp parse_zeek_timestamp(ts) when is_float(ts) do
    case DateTime.from_unix(trunc(ts)) do
      {:ok, dt} -> dt
      _ -> DateTime.utc_now()
    end
  end
  defp parse_zeek_timestamp(ts) when is_binary(ts) do
    case Float.parse(ts) do
      {f, _} -> parse_zeek_timestamp(f)
      _ -> DateTime.utc_now()
    end
  end
  defp parse_zeek_timestamp(_), do: DateTime.utc_now()

  defp parse_zeek_conn(data) do
    %{
      network_direction: zeek_direction(data["local_orig"], data["local_resp"]),
      network_transport: data["service"],
      action: zeek_conn_action(data["conn_state"]),
      outcome: zeek_conn_outcome(data["conn_state"]),
      severity: "info",
      parsed_fields: %{
        uid: data["uid"],
        conn_state: data["conn_state"],
        duration: data["duration"],
        orig_bytes: data["orig_bytes"],
        resp_bytes: data["resp_bytes"],
        orig_pkts: data["orig_pkts"],
        resp_pkts: data["resp_pkts"],
        history: data["history"],
        missed_bytes: data["missed_bytes"],
        tunnel_parents: data["tunnel_parents"]
      }
    }
  end

  defp parse_zeek_dns(data) do
    %{
      dns_query: data["query"],
      url_domain: data["query"],
      action: "allow",
      outcome: if(data["rcode_name"] == "NOERROR", do: "success", else: "failure"),
      severity: zeek_dns_severity(data),
      parsed_fields: %{
        uid: data["uid"],
        trans_id: data["trans_id"],
        query: data["query"],
        qclass: data["qclass"],
        qclass_name: data["qclass_name"],
        qtype: data["qtype"],
        qtype_name: data["qtype_name"],
        rcode: data["rcode"],
        rcode_name: data["rcode_name"],
        answers: data["answers"],
        ttls: data["TTLs"],
        rejected: data["rejected"]
      }
    }
  end

  defp parse_zeek_http(data) do
    %{
      url: build_http_url(data),
      url_domain: data["host"],
      url_path: data["uri"],
      http_method: data["method"],
      http_status: data["status_code"],
      action: "allow",
      outcome: zeek_http_outcome(data["status_code"]),
      severity: zeek_http_severity(data),
      parsed_fields: %{
        uid: data["uid"],
        host: data["host"],
        uri: data["uri"],
        user_agent: data["user_agent"],
        referrer: data["referrer"],
        request_body_len: data["request_body_len"],
        response_body_len: data["response_body_len"],
        status_code: data["status_code"],
        status_msg: data["status_msg"],
        info_code: data["info_code"],
        info_msg: data["info_msg"],
        filename: data["filename"],
        tags: data["tags"],
        proxied: data["proxied"]
      }
    }
  end

  defp parse_zeek_ssl(data) do
    %{
      url_domain: data["server_name"],
      network_transport: "TLS",
      action: zeek_ssl_action(data),
      outcome: zeek_ssl_outcome(data),
      severity: zeek_ssl_severity(data),
      parsed_fields: %{
        uid: data["uid"],
        version: data["version"],
        cipher: data["cipher"],
        curve: data["curve"],
        server_name: data["server_name"],
        resumed: data["resumed"],
        established: data["established"],
        cert_chain_fuids: data["cert_chain_fuids"],
        client_cert_chain_fuids: data["client_cert_chain_fuids"],
        subject: data["subject"],
        issuer: data["issuer"],
        validation_status: data["validation_status"],
        ja3: data["ja3"],
        ja3s: data["ja3s"]
      }
    }
  end

  defp parse_zeek_files(data) do
    %{
      file_name: data["filename"],
      file_hash_sha256: data["sha256"],
      file_hash_md5: data["md5"],
      file_size: data["total_bytes"],
      severity: zeek_file_severity(data),
      parsed_fields: %{
        fuid: data["fuid"],
        source: data["source"],
        depth: data["depth"],
        analyzers: data["analyzers"],
        mime_type: data["mime_type"],
        duration: data["duration"],
        local_orig: data["local_orig"],
        is_orig: data["is_orig"],
        seen_bytes: data["seen_bytes"],
        missing_bytes: data["missing_bytes"],
        overflow_bytes: data["overflow_bytes"],
        timedout: data["timedout"],
        extracted: data["extracted"],
        extracted_cutoff: data["extracted_cutoff"],
        extracted_size: data["extracted_size"]
      }
    }
  end

  defp parse_zeek_notice(data) do
    %{
      rule_name: data["note"],
      threat_name: data["note"],
      message: data["msg"],
      severity: zeek_notice_severity(data["note"]),
      action: data["actions"] |> List.first() || "alert",
      parsed_fields: %{
        uid: data["uid"],
        fuid: data["fuid"],
        note: data["note"],
        msg: data["msg"],
        sub: data["sub"],
        n: data["n"],
        src: data["src"],
        dst: data["dst"],
        p: data["p"],
        peer_descr: data["peer_descr"],
        actions: data["actions"],
        suppress_for: data["suppress_for"]
      }
    }
  end

  defp parse_zeek_x509(data) do
    %{
      severity: "info",
      parsed_fields: %{
        id: data["id"],
        certificate_version: data["certificate.version"],
        certificate_serial: data["certificate.serial"],
        certificate_subject: data["certificate.subject"],
        certificate_issuer: data["certificate.issuer"],
        certificate_not_valid_before: data["certificate.not_valid_before"],
        certificate_not_valid_after: data["certificate.not_valid_after"],
        certificate_key_alg: data["certificate.key_alg"],
        certificate_sig_alg: data["certificate.sig_alg"],
        certificate_key_type: data["certificate.key_type"],
        certificate_key_length: data["certificate.key_length"],
        san_dns: data["san.dns"],
        san_uri: data["san.uri"],
        san_email: data["san.email"],
        san_ip: data["san.ip"]
      }
    }
  end

  defp parse_zeek_smtp(data) do
    %{
      email_subject: data["subject"],
      email_from: data["from"],
      email_to: encode_list(data["to"]),
      email_direction: "outbound",
      severity: "info",
      parsed_fields: %{
        uid: data["uid"],
        trans_depth: data["trans_depth"],
        helo: data["helo"],
        mailfrom: data["mailfrom"],
        rcptto: data["rcptto"],
        date: data["date"],
        from: data["from"],
        to: data["to"],
        cc: data["cc"],
        reply_to: data["reply_to"],
        msg_id: data["msg_id"],
        in_reply_to: data["in_reply_to"],
        subject: data["subject"],
        x_originating_ip: data["x_originating_ip"],
        first_received: data["first_received"],
        second_received: data["second_received"],
        last_reply: data["last_reply"],
        path: data["path"],
        user_agent: data["user_agent"],
        tls: data["tls"],
        fuids: data["fuids"],
        is_webmail: data["is_webmail"]
      }
    }
  end

  defp parse_zeek_ssh(data) do
    %{
      network_transport: "SSH",
      severity: zeek_ssh_severity(data),
      action: if(data["auth_success"], do: "allow", else: "deny"),
      outcome: if(data["auth_success"], do: "success", else: "failure"),
      parsed_fields: %{
        uid: data["uid"],
        version: data["version"],
        auth_success: data["auth_success"],
        auth_attempts: data["auth_attempts"],
        direction: data["direction"],
        client: data["client"],
        server: data["server"],
        cipher_alg: data["cipher_alg"],
        mac_alg: data["mac_alg"],
        compression_alg: data["compression_alg"],
        kex_alg: data["kex_alg"],
        host_key_alg: data["host_key_alg"],
        host_key: data["host_key"],
        remote_location: data["remote_location"]
      }
    }
  end

  defp parse_zeek_kerberos(data) do
    %{
      user_name: data["client"],
      dest_user: data["service"],
      severity: zeek_kerberos_severity(data),
      action: zeek_kerberos_action(data),
      outcome: zeek_kerberos_outcome(data),
      parsed_fields: %{
        uid: data["uid"],
        request_type: data["request_type"],
        client: data["client"],
        service: data["service"],
        success: data["success"],
        error_code: data["error_code"],
        error_msg: data["error_msg"],
        from: data["from"],
        till: data["till"],
        cipher: data["cipher"],
        forwardable: data["forwardable"],
        renewable: data["renewable"],
        client_cert_subject: data["client_cert_subject"],
        client_cert_fuid: data["client_cert_fuid"],
        server_cert_subject: data["server_cert_subject"],
        server_cert_fuid: data["server_cert_fuid"]
      }
    }
  end

  # Zeek helpers

  defp zeek_direction(true, false), do: "outbound"
  defp zeek_direction(false, true), do: "inbound"
  defp zeek_direction(true, true), do: "internal"
  defp zeek_direction(_, _), do: "external"

  defp zeek_conn_action(state) do
    case state do
      s when s in ["S0", "REJ", "RSTO", "RSTOS0", "RSTRH"] -> "block"
      _ -> "allow"
    end
  end

  defp zeek_conn_outcome(state) do
    case state do
      s when s in ["SF", "S1", "S2", "S3", "RSTO", "RSTOS0"] -> "success"
      s when s in ["REJ", "S0", "SH", "SHR"] -> "failure"
      _ -> "unknown"
    end
  end

  defp zeek_dns_severity(data) do
    cond do
      data["rejected"] == true -> "medium"
      data["rcode_name"] == "NXDOMAIN" -> "low"
      true -> "info"
    end
  end

  defp zeek_http_outcome(nil), do: "unknown"
  defp zeek_http_outcome(code) when is_integer(code) do
    cond do
      code >= 200 and code < 400 -> "success"
      code >= 400 -> "failure"
      true -> "unknown"
    end
  end

  defp zeek_http_severity(data) do
    code = data["status_code"]
    cond do
      code && code >= 500 -> "medium"
      code && code >= 400 -> "low"
      true -> "info"
    end
  end

  defp zeek_ssl_action(data) do
    if data["established"], do: "allow", else: "block"
  end

  defp zeek_ssl_outcome(data) do
    if data["established"], do: "success", else: "failure"
  end

  defp zeek_ssl_severity(data) do
    cond do
      data["validation_status"] != nil and data["validation_status"] != "ok" -> "medium"
      data["established"] == false -> "low"
      true -> "info"
    end
  end

  defp zeek_file_severity(data) do
    mime = data["mime_type"] || ""
    cond do
      String.contains?(mime, ["executable", "msdownload", "x-dosexec"]) -> "medium"
      String.contains?(mime, ["javascript", "vbscript"]) -> "low"
      true -> "info"
    end
  end

  defp zeek_notice_severity(nil), do: "medium"
  defp zeek_notice_severity(note) do
    high = ~w(Attack::Injection Attack::Malware Scan::Port_Scan SSL::Invalid_Server_Cert)
    medium = ~w(SSH::Password_Guessing DNS::External_Name Weird::Activity)

    cond do
      Enum.any?(high, &String.contains?(note, &1)) -> "high"
      Enum.any?(medium, &String.contains?(note, &1)) -> "medium"
      true -> "low"
    end
  end

  defp zeek_ssh_severity(data) do
    cond do
      data["auth_attempts"] && data["auth_attempts"] > 3 -> "medium"
      data["auth_success"] == false -> "low"
      true -> "info"
    end
  end

  defp zeek_kerberos_severity(data) do
    cond do
      data["error_code"] != nil -> "medium"
      data["success"] == false -> "low"
      true -> "info"
    end
  end

  defp zeek_kerberos_action(data) do
    if data["success"] || data["success"] == nil, do: "allow", else: "deny"
  end

  defp zeek_kerberos_outcome(data) do
    cond do
      data["success"] == true -> "success"
      data["success"] == false or data["error_code"] -> "failure"
      true -> "unknown"
    end
  end

  defp build_http_url(data) do
    host = data["host"]
    uri = data["uri"]
    if host && uri, do: "http://#{host}#{uri}", else: nil
  end

  defp add_zeek_mitre(event, log_type, data) do
    mitre = case log_type do
      "notice" ->
        note = data["note"] || ""
        cond do
          String.contains?(note, "Scan") ->
            %{mitre_tactics: ["discovery"], mitre_techniques: ["T1046"]}
          String.contains?(note, "Attack") ->
            %{mitre_tactics: ["execution"], mitre_techniques: ["T1203"]}
          true -> %{}
        end

      "ssh" ->
        if (data["auth_attempts"] || 0) > 3 do
          %{mitre_tactics: ["credential_access"], mitre_techniques: ["T1110"]}
        else
          %{}
        end

      "dns" ->
        answers = data["answers"] || []
        if length(answers) > 10 do
          %{mitre_tactics: ["command_and_control"], mitre_techniques: ["T1071.004"]}
        else
          %{}
        end

      _ -> %{}
    end

    Map.merge(event, mitre)
  end

  # Suricata Parsing

  @doc false
  def parse_suricata(data) when is_map(data) do
    event_type = data["event_type"]

    base = %{
      timestamp: parse_suricata_timestamp(data["timestamp"]),
      source_type: "network",
      device_vendor: "Suricata",
      device_product: "Suricata",
      source_ip: data["src_ip"],
      source_port: data["src_port"],
      dest_ip: data["dest_ip"],
      dest_port: data["dest_port"],
      network_protocol: data["proto"],
      network_direction: data["direction"],
      event_category: "network",
      event_type: event_type
    }

    type_fields = case event_type do
      "alert" -> parse_suricata_alert(data)
      "dns" -> parse_suricata_dns(data)
      "http" -> parse_suricata_http(data)
      "tls" -> parse_suricata_tls(data)
      "fileinfo" -> parse_suricata_fileinfo(data)
      "flow" -> parse_suricata_flow(data)
      _ -> %{severity: "info", parsed_fields: data}
    end

    event = Map.merge(base, type_fields)
    event = add_suricata_mitre(event, data)

    {:ok, event}
  end

  defp parse_suricata_timestamp(nil), do: DateTime.utc_now()
  defp parse_suricata_timestamp(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end

  defp parse_suricata_alert(data) do
    alert = data["alert"] || %{}

    %{
      rule_name: alert["signature"],
      rule_id: to_string(alert["signature_id"]),
      threat_category: alert["category"],
      severity: suricata_severity(alert["severity"]),
      action: data["action"] || alert["action"] || "alert",
      message: alert["signature"],
      parsed_fields: %{
        signature_id: alert["signature_id"],
        signature: alert["signature"],
        category: alert["category"],
        severity: alert["severity"],
        rev: alert["rev"],
        gid: alert["gid"],
        metadata: alert["metadata"]
      }
    }
  end

  defp parse_suricata_dns(data) do
    dns = data["dns"] || %{}

    %{
      dns_query: dns["query"] || dns["rrname"],
      url_domain: dns["query"] || dns["rrname"],
      severity: "info",
      parsed_fields: %{
        type: dns["type"],
        id: dns["id"],
        flags: dns["flags"],
        qr: dns["qr"],
        aa: dns["aa"],
        tc: dns["tc"],
        rd: dns["rd"],
        ra: dns["ra"],
        rcode: dns["rcode"],
        rrname: dns["rrname"],
        rrtype: dns["rrtype"],
        rdata: dns["rdata"],
        ttl: dns["ttl"]
      }
    }
  end

  defp parse_suricata_http(data) do
    http = data["http"] || %{}

    %{
      url: http["url"],
      url_domain: http["hostname"],
      url_path: http["url"],
      http_method: http["http_method"],
      http_status: http["status"],
      severity: "info",
      parsed_fields: %{
        hostname: http["hostname"],
        url: http["url"],
        http_user_agent: http["http_user_agent"],
        http_content_type: http["http_content_type"],
        http_refer: http["http_refer"],
        http_method: http["http_method"],
        protocol: http["protocol"],
        status: http["status"],
        redirect: http["redirect"],
        length: http["length"]
      }
    }
  end

  defp parse_suricata_tls(data) do
    tls = data["tls"] || %{}

    %{
      url_domain: tls["sni"],
      network_transport: "TLS",
      severity: suricata_tls_severity(tls),
      parsed_fields: %{
        subject: tls["subject"],
        issuerdn: tls["issuerdn"],
        serial: tls["serial"],
        fingerprint: tls["fingerprint"],
        sni: tls["sni"],
        version: tls["version"],
        notbefore: tls["notbefore"],
        notafter: tls["notafter"],
        ja3: tls["ja3"],
        ja3s: tls["ja3s"]
      }
    }
  end

  defp parse_suricata_fileinfo(data) do
    fileinfo = data["fileinfo"] || %{}

    %{
      file_name: fileinfo["filename"],
      file_hash_sha256: fileinfo["sha256"],
      file_hash_md5: fileinfo["md5"],
      file_size: fileinfo["size"],
      severity: suricata_file_severity(fileinfo),
      parsed_fields: %{
        filename: fileinfo["filename"],
        magic: fileinfo["magic"],
        gaps: fileinfo["gaps"],
        state: fileinfo["state"],
        stored: fileinfo["stored"],
        size: fileinfo["size"],
        tx_id: fileinfo["tx_id"],
        sha1: fileinfo["sha1"],
        sha256: fileinfo["sha256"],
        md5: fileinfo["md5"]
      }
    }
  end

  defp parse_suricata_flow(data) do
    flow = data["flow"] || %{}

    %{
      severity: "info",
      action: "allow",
      outcome: flow["state"],
      parsed_fields: %{
        pkts_toserver: flow["pkts_toserver"],
        pkts_toclient: flow["pkts_toclient"],
        bytes_toserver: flow["bytes_toserver"],
        bytes_toclient: flow["bytes_toclient"],
        start: flow["start"],
        end: flow["end"],
        age: flow["age"],
        state: flow["state"],
        reason: flow["reason"],
        alerted: flow["alerted"]
      }
    }
  end

  defp suricata_severity(1), do: "critical"
  defp suricata_severity(2), do: "high"
  defp suricata_severity(3), do: "medium"
  defp suricata_severity(_), do: "low"

  defp suricata_tls_severity(tls) do
    cond do
      tls["ja3"] in known_malicious_ja3() -> "high"
      tls["version"] in ["SSLv3", "TLSv1.0"] -> "medium"
      true -> "info"
    end
  end

  defp known_malicious_ja3 do
    # Sample known malicious JA3 hashes
    ["51c64c77e60f3980eea90869b68c58a8"]  # Emotet
  end

  defp suricata_file_severity(fileinfo) do
    magic = fileinfo["magic"] || ""
    cond do
      String.contains?(magic, ["executable", "PE32"]) -> "medium"
      String.contains?(magic, ["script", "JavaScript"]) -> "low"
      true -> "info"
    end
  end

  defp add_suricata_mitre(event, data) do
    alert = data["alert"] || %{}
    category = alert["category"] || ""

    mitre = cond do
      String.contains?(category, "Malware") ->
        %{mitre_tactics: ["execution"], mitre_techniques: ["T1204"]}

      String.contains?(category, "Command and Control") ->
        %{mitre_tactics: ["command_and_control"], mitre_techniques: ["T1071"]}

      String.contains?(category, "Exploit") ->
        %{mitre_tactics: ["initial_access"], mitre_techniques: ["T1190"]}

      String.contains?(category, "Scan") ->
        %{mitre_tactics: ["discovery"], mitre_techniques: ["T1046"]}

      true -> %{}
    end

    Map.merge(event, mitre)
  end

  # Snort Parsing

  @doc false
  def parse_snort(data) when is_map(data) do
    event = %{
      timestamp: data["timestamp"] || DateTime.utc_now(),
      source_type: "network",
      device_vendor: "Snort",
      device_product: "Snort IDS",
      source_ip: data["src_ip"] || data["src"],
      source_port: data["src_port"] || data["sport"],
      dest_ip: data["dst_ip"] || data["dst"],
      dest_port: data["dst_port"] || data["dport"],
      network_protocol: data["proto"],
      event_category: "network",
      event_type: "alert",
      rule_name: data["msg"] || data["message"],
      rule_id: "#{data["gid"] || 1}:#{data["sid"]}:#{data["rev"] || 0}",
      signature_id: to_string(data["sid"]),
      threat_category: data["classtype"] || data["classification"],
      severity: snort_severity(data["priority"]),
      action: "alert",
      parsed_fields: %{
        sid: data["sid"],
        gid: data["gid"],
        rev: data["rev"],
        msg: data["msg"],
        classtype: data["classtype"],
        priority: data["priority"],
        metadata: data["metadata"]
      }
    }

    {:ok, event}
  end

  defp parse_snort_fast(line) do
    # Fast alert format: [**] [gid:sid:rev] msg [**]
    case Regex.run(~r/\[\*\*\]\s*\[(\d+):(\d+):(\d+)\]\s*(.*?)\s*\[\*\*\]/, line) do
      [_, gid, sid, rev, msg] ->
        data = %{
          "gid" => String.to_integer(gid),
          "sid" => String.to_integer(sid),
          "rev" => String.to_integer(rev),
          "msg" => msg
        }
        parse_snort(data)

      _ -> {:error, :invalid_snort_format}
    end
  end

  defp parse_snort_full(line) do
    # Full alert format with more details
    gid_sid_rev = Regex.run(~r/\[(\d+):(\d+):(\d+)\]/, line)
    msg = Regex.run(~r/\[\*\*\].*?\[\*\*\]\s*(.+?)\s*\[\*\*\]/, line)
    classification = Regex.run(~r/\[Classification:\s*(.+?)\]/, line)
    priority = Regex.run(~r/\[Priority:\s*(\d+)\]/, line)
    src_dst = Regex.run(~r/(\d+\.\d+\.\d+\.\d+):?(\d+)?\s*->\s*(\d+\.\d+\.\d+\.\d+):?(\d+)?/, line)

    data = %{
      "gid" => if(gid_sid_rev, do: String.to_integer(Enum.at(gid_sid_rev, 1))),
      "sid" => if(gid_sid_rev, do: String.to_integer(Enum.at(gid_sid_rev, 2))),
      "rev" => if(gid_sid_rev, do: String.to_integer(Enum.at(gid_sid_rev, 3))),
      "msg" => if(msg, do: Enum.at(msg, 1)),
      "classtype" => if(classification, do: Enum.at(classification, 1)),
      "priority" => if(priority, do: String.to_integer(Enum.at(priority, 1))),
      "src_ip" => if(src_dst, do: Enum.at(src_dst, 1)),
      "src_port" => if(src_dst, do: Enum.at(src_dst, 2)),
      "dst_ip" => if(src_dst, do: Enum.at(src_dst, 3)),
      "dst_port" => if(src_dst, do: Enum.at(src_dst, 4))
    }

    parse_snort(data)
  end

  defp snort_severity(nil), do: "medium"
  defp snort_severity(1), do: "critical"
  defp snort_severity(2), do: "high"
  defp snort_severity(3), do: "medium"
  defp snort_severity(_), do: "low"

  # Corelight Parsing (Enterprise Zeek)

  @doc false
  def parse_corelight(data) when is_map(data) do
    # Corelight extends Zeek with additional metadata
    {:ok, base_event} = parse_zeek(data)

    corelight_fields = %{
      device_vendor: "Corelight",
      device_product: "Corelight Sensor",
      parsed_fields: Map.merge(base_event[:parsed_fields] || %{}, %{
        corelight_shunted: data["corelight_shunted"],
        sensor_uid: data["sensor_uid"],
        sensor_name: data["sensor_name"]
      })
    }

    {:ok, Map.merge(base_event, corelight_fields)}
  end

  # Darktrace Parsing

  @doc false
  def parse_darktrace(data) when is_map(data) do
    event = %{
      timestamp: parse_darktrace_timestamp(data["time"]),
      source_type: "network",
      device_vendor: "Darktrace",
      device_product: "Enterprise Immune System",
      source_ip: data["device"]["ip"],
      source_hostname: data["device"]["hostname"],
      dest_ip: data["destination"]["ip"],
      dest_port: data["destination"]["port"],
      user_name: data["device"]["user"],
      event_category: "network",
      event_type: data["model"]["name"],
      rule_name: data["model"]["name"],
      threat_category: data["model"]["category"],
      severity: darktrace_severity(data["score"]),
      action: "alert",
      parsed_fields: %{
        did: data["did"],
        model_name: data["model"]["name"],
        model_uuid: data["model"]["uuid"],
        model_category: data["model"]["category"],
        score: data["score"],
        breach_score: data["breachScore"],
        components: data["components"],
        triggered_components: data["triggeredComponents"],
        device: data["device"],
        destination: data["destination"]
      }
    }

    event = add_darktrace_mitre(event, data)
    {:ok, event}
  end

  defp parse_darktrace_timestamp(nil), do: DateTime.utc_now()
  defp parse_darktrace_timestamp(ts) when is_integer(ts) do
    case DateTime.from_unix(ts, :millisecond) do
      {:ok, dt} -> dt
      _ -> DateTime.utc_now()
    end
  end
  defp parse_darktrace_timestamp(ts) when is_binary(ts) do
    case Integer.parse(ts) do
      {n, _} -> parse_darktrace_timestamp(n)
      _ -> DateTime.utc_now()
    end
  end

  defp darktrace_severity(score) when is_number(score) do
    cond do
      score >= 0.8 -> "critical"
      score >= 0.6 -> "high"
      score >= 0.4 -> "medium"
      score >= 0.2 -> "low"
      true -> "info"
    end
  end
  defp darktrace_severity(_), do: "medium"

  defp add_darktrace_mitre(event, data) do
    model = data["model"] || %{}
    category = model["category"] || ""

    mitre = cond do
      String.contains?(category, "Anomalous Connection") ->
        %{mitre_tactics: ["command_and_control"], mitre_techniques: ["T1071"]}

      String.contains?(category, "Unusual Activity") ->
        %{mitre_tactics: ["discovery"], mitre_techniques: ["T1046"]}

      String.contains?(category, "Compliance") ->
        %{mitre_tactics: ["exfiltration"], mitre_techniques: ["T1048"]}

      true -> %{}
    end

    Map.merge(event, mitre)
  end

  # Generic Network Parsing

  defp parse_generic_network(data) do
    event = %{
      timestamp: data["timestamp"] || DateTime.utc_now(),
      source_type: "network",
      source_ip: data["src_ip"] || data["source_ip"],
      source_port: data["src_port"] || data["source_port"],
      dest_ip: data["dst_ip"] || data["dest_ip"],
      dest_port: data["dst_port"] || data["dest_port"],
      network_protocol: data["proto"] || data["protocol"],
      event_category: "network",
      severity: data["severity"] || "info",
      parsed_fields: data
    }

    {:ok, event}
  end

  # Helpers

  defp encode_list(nil), do: nil
  defp encode_list(list) when is_list(list), do: Jason.encode!(list)
  defp encode_list(str) when is_binary(str), do: str
  defp encode_list(_), do: nil
end
