defmodule TamanduaServer.XDR.Parser.JSON do
  @moduledoc """
  Parser for JSON formatted logs.

  Handles structured JSON logs from various sources:
  - AWS CloudTrail
  - Azure Activity Logs
  - GCP Audit Logs
  - Generic JSON logs

  Auto-detects source type and applies appropriate field mappings.
  """

  require Logger

  @doc """
  Parse a JSON formatted log event.

  Returns {:ok, map} on success, {:error, reason} on failure.
  """
  @spec parse(binary() | map()) :: {:ok, map()} | {:error, term()}
  def parse(data) when is_map(data) do
    # Already parsed JSON
    normalized = normalize_json(data)
    {:ok, normalized}
  end

  def parse(data) when is_binary(data) do
    case Jason.decode(data) do
      {:ok, json} when is_map(json) ->
        normalized = normalize_json(json)
        {:ok, normalized}

      {:ok, _} ->
        {:error, :not_json_object}

      {:error, reason} ->
        {:error, {:json_parse_error, reason}}
    end
  end

  def parse(_), do: {:error, :invalid_input}

  defp normalize_json(json) do
    # Detect source type and apply appropriate mapping
    cond do
      aws_cloudtrail?(json) -> normalize_cloudtrail(json)
      azure_activity?(json) -> normalize_azure_activity(json)
      gcp_audit?(json) -> normalize_gcp_audit(json)
      zeek_log?(json) -> normalize_zeek(json)
      suricata_eve?(json) -> normalize_suricata(json)
      okta_log?(json) -> normalize_okta(json)
      generic_ecs?(json) -> normalize_ecs(json)
      true -> normalize_generic(json)
    end
  end

  # Source detection

  defp aws_cloudtrail?(json) do
    Map.has_key?(json, "eventSource") and Map.has_key?(json, "awsRegion")
  end

  defp azure_activity?(json) do
    Map.has_key?(json, "operationName") and Map.has_key?(json, "resourceId")
  end

  defp gcp_audit?(json) do
    Map.has_key?(json, "protoPayload") or
    (Map.has_key?(json, "logName") and String.contains?(json["logName"] || "", "cloudaudit"))
  end

  defp zeek_log?(json) do
    Map.has_key?(json, "ts") and Map.has_key?(json, "_path")
  end

  defp suricata_eve?(json) do
    Map.has_key?(json, "event_type") and Map.has_key?(json, "src_ip")
  end

  defp okta_log?(json) do
    Map.has_key?(json, "eventType") and Map.has_key?(json, "actor")
  end

  defp generic_ecs?(json) do
    # Elastic Common Schema detection
    Map.has_key?(json, "@timestamp") or
    (Map.has_key?(json, "event") and is_map(json["event"]))
  end

  # AWS CloudTrail normalization

  defp normalize_cloudtrail(json) do
    user_identity = json["userIdentity"] || %{}
    source_ip = json["sourceIPAddress"]

    %{
      timestamp: parse_timestamp(json["eventTime"]),
      cloud_provider: "aws",
      cloud_service: extract_aws_service(json["eventSource"]),
      cloud_region: json["awsRegion"],
      cloud_account_id: json["recipientAccountId"],
      cloud_resource_id: extract_resource_id(json),
      event_category: "cloud",
      event_type: json["eventName"],
      action: json["eventName"],
      outcome: if(json["errorCode"], do: "failure", else: "success"),
      user_name: user_identity["userName"] || user_identity["principalId"],
      user_domain: user_identity["accountId"],
      source_ip: source_ip,
      severity: cloudtrail_severity(json),
      parsed_fields: %{
        event_source: json["eventSource"],
        event_id: json["eventID"],
        error_code: json["errorCode"],
        error_message: json["errorMessage"],
        request_parameters: json["requestParameters"],
        response_elements: json["responseElements"],
        user_identity: user_identity
      }
    }
  end

  defp extract_aws_service(nil), do: nil
  defp extract_aws_service(event_source) do
    case String.split(event_source, ".") do
      [service | _] -> service
      _ -> event_source
    end
  end

  defp extract_resource_id(json) do
    resources = json["resources"] || []
    case resources do
      [%{"ARN" => arn} | _] -> arn
      _ ->
        # Try to extract from request parameters
        params = json["requestParameters"] || %{}
        params["resourceArn"] || params["bucketName"] || params["instanceId"]
    end
  end

  defp cloudtrail_severity(json) do
    cond do
      json["errorCode"] != nil -> "medium"
      String.contains?(json["eventName"] || "", "Delete") -> "medium"
      String.contains?(json["eventName"] || "", "Create") -> "low"
      true -> "info"
    end
  end

  # Azure Activity Log normalization

  defp normalize_azure_activity(json) do
    caller = json["caller"] || json["identity"]
    properties = json["properties"] || %{}

    %{
      timestamp: parse_timestamp(json["time"] || json["eventTimestamp"]),
      cloud_provider: "azure",
      cloud_service: extract_azure_service(json["resourceId"]),
      cloud_region: json["location"],
      cloud_account_id: json["subscriptionId"],
      cloud_resource_id: json["resourceId"],
      event_category: json["category"] || "cloud",
      event_type: json["operationName"],
      action: json["operationName"],
      outcome: normalize_azure_outcome(json["resultType"]),
      user_name: extract_azure_user(caller),
      source_ip: properties["clientIPAddress"] || json["callerIpAddress"],
      severity: azure_severity(json),
      parsed_fields: %{
        operation_id: json["operationId"],
        correlation_id: json["correlationId"],
        result_signature: json["resultSignature"],
        properties: properties
      }
    }
  end

  defp extract_azure_service(nil), do: nil
  defp extract_azure_service(resource_id) do
    case Regex.run(~r|/providers/([^/]+)|, resource_id) do
      [_, provider] -> provider
      _ -> nil
    end
  end

  defp normalize_azure_outcome(nil), do: "unknown"
  defp normalize_azure_outcome(result) do
    case String.downcase(result) do
      r when r in ["success", "succeeded", "accepted"] -> "success"
      r when r in ["failure", "failed"] -> "failure"
      _ -> "unknown"
    end
  end

  defp extract_azure_user(nil), do: nil
  defp extract_azure_user(caller) when is_binary(caller), do: caller
  defp extract_azure_user(caller) when is_map(caller) do
    caller["claims"]["name"] || caller["claims"]["upn"] || caller["principalId"]
  end

  defp azure_severity(json) do
    level = json["level"] || ""
    case String.downcase(level) do
      "critical" -> "critical"
      "error" -> "high"
      "warning" -> "medium"
      _ -> "info"
    end
  end

  # GCP Audit Log normalization

  defp normalize_gcp_audit(json) do
    proto = json["protoPayload"] || json
    auth_info = proto["authenticationInfo"] || %{}
    request_meta = proto["requestMetadata"] || %{}
    resource = json["resource"] || %{}
    labels = resource["labels"] || %{}

    %{
      timestamp: parse_timestamp(json["timestamp"] || json["receiveTimestamp"]),
      cloud_provider: "gcp",
      cloud_service: proto["serviceName"],
      cloud_region: labels["location"] || labels["zone"],
      cloud_account_id: labels["project_id"],
      cloud_resource_id: proto["resourceName"],
      event_category: "cloud",
      event_type: proto["methodName"],
      action: proto["methodName"],
      outcome: gcp_outcome(proto),
      user_name: auth_info["principalEmail"],
      source_ip: request_meta["callerIp"],
      severity: gcp_severity(json),
      parsed_fields: %{
        log_name: json["logName"],
        insert_id: json["insertId"],
        service_name: proto["serviceName"],
        method_name: proto["methodName"],
        authorization_info: proto["authorizationInfo"]
      }
    }
  end

  defp gcp_outcome(proto) do
    status = proto["status"] || %{}
    case status["code"] do
      0 -> "success"
      nil -> "success"
      _ -> "failure"
    end
  end

  defp gcp_severity(json) do
    case json["severity"] do
      "CRITICAL" -> "critical"
      "ERROR" -> "high"
      "WARNING" -> "medium"
      "NOTICE" -> "low"
      _ -> "info"
    end
  end

  # Zeek/Bro log normalization

  defp normalize_zeek(json) do
    log_type = json["_path"]

    base = %{
      timestamp: parse_zeek_timestamp(json["ts"]),
      event_category: "network",
      event_type: log_type,
      source_ip: json["id.orig_h"] || json["orig_h"],
      source_port: json["id.orig_p"] || json["orig_p"],
      dest_ip: json["id.resp_h"] || json["resp_h"],
      dest_port: json["id.resp_p"] || json["resp_p"],
      network_protocol: json["proto"],
      severity: "info"
    }

    # Add type-specific fields
    type_fields = case log_type do
      "conn" ->
        %{
          network_direction: zeek_direction(json["local_orig"], json["local_resp"]),
          bytes_in: json["orig_bytes"],
          bytes_out: json["resp_bytes"]
        }

      "dns" ->
        %{
          dns_query: json["query"],
          event_type: "dns_query"
        }

      "http" ->
        %{
          url: build_url(json["host"], json["uri"]),
          url_domain: json["host"],
          url_path: json["uri"],
          http_method: json["method"]
        }

      "ssl" ->
        %{
          url_domain: json["server_name"],
          network_transport: "TLS"
        }

      "files" ->
        %{
          file_name: json["filename"],
          file_hash_sha256: json["sha256"],
          file_hash_md5: json["md5"],
          file_size: json["total_bytes"]
        }

      "notice" ->
        %{
          severity: zeek_notice_severity(json["n"]),
          rule_name: json["note"],
          message: json["msg"]
        }

      _ -> %{}
    end

    Map.merge(base, type_fields)
    |> Map.put(:parsed_fields, json)
  end

  defp parse_zeek_timestamp(ts) when is_float(ts) do
    case DateTime.from_unix(trunc(ts)) do
      {:ok, dt} -> dt
      _ -> nil
    end
  end

  defp parse_zeek_timestamp(ts) when is_binary(ts) do
    case Float.parse(ts) do
      {f, _} -> parse_zeek_timestamp(f)
      _ -> nil
    end
  end

  defp parse_zeek_timestamp(_), do: nil

  defp zeek_direction(true, false), do: "outbound"
  defp zeek_direction(false, true), do: "inbound"
  defp zeek_direction(true, true), do: "internal"
  defp zeek_direction(_, _), do: "external"

  defp zeek_notice_severity(notice_type) do
    high_severity = ~w(Attack::Injection Attack::Malware Scan::Port_Scan)
    if notice_type in high_severity, do: "high", else: "medium"
  end

  defp build_url(nil, _), do: nil
  defp build_url(_, nil), do: nil
  defp build_url(host, uri), do: "http://#{host}#{uri}"

  # Suricata EVE JSON normalization

  defp normalize_suricata(json) do
    event_type = json["event_type"]

    base = %{
      timestamp: parse_timestamp(json["timestamp"]),
      event_category: "network",
      event_type: event_type,
      source_ip: json["src_ip"],
      source_port: json["src_port"],
      dest_ip: json["dest_ip"],
      dest_port: json["dest_port"],
      network_protocol: json["proto"]
    }

    type_fields = case event_type do
      "alert" ->
        alert = json["alert"] || %{}
        %{
          severity: suricata_severity(alert["severity"]),
          rule_name: alert["signature"],
          rule_id: to_string(alert["signature_id"]),
          threat_category: alert["category"],
          action: json["action"] || alert["action"]
        }

      "dns" ->
        dns = json["dns"] || %{}
        %{
          dns_query: dns["query"] || dns["rrname"],
          event_type: "dns_query"
        }

      "http" ->
        http = json["http"] || %{}
        %{
          url: http["url"],
          url_domain: http["hostname"],
          url_path: http["url"],
          http_method: http["http_method"]
        }

      "tls" ->
        tls = json["tls"] || %{}
        %{
          url_domain: tls["sni"],
          network_transport: "TLS"
        }

      "fileinfo" ->
        fileinfo = json["fileinfo"] || %{}
        %{
          file_name: fileinfo["filename"],
          file_hash_sha256: fileinfo["sha256"],
          file_hash_md5: fileinfo["md5"],
          file_size: fileinfo["size"]
        }

      _ -> %{}
    end

    Map.merge(base, type_fields)
    |> Map.put(:parsed_fields, json)
  end

  defp suricata_severity(1), do: "critical"
  defp suricata_severity(2), do: "high"
  defp suricata_severity(3), do: "medium"
  defp suricata_severity(_), do: "low"

  # Okta log normalization

  defp normalize_okta(json) do
    actor = json["actor"] || %{}
    client = json["client"] || %{}
    outcome = json["outcome"] || %{}
    target = List.first(json["target"] || []) || %{}

    %{
      timestamp: parse_timestamp(json["published"]),
      event_category: "authentication",
      event_type: json["eventType"],
      action: json["eventType"],
      outcome: okta_outcome(outcome["result"]),
      user_name: actor["alternateId"] || actor["displayName"],
      user_email: actor["alternateId"],
      source_ip: client["ipAddress"],
      dest_user: target["alternateId"],
      severity: okta_severity(json, outcome),
      parsed_fields: %{
        uuid: json["uuid"],
        actor: actor,
        client: client,
        outcome: outcome,
        target: json["target"],
        transaction: json["transaction"],
        debug_context: json["debugContext"]
      }
    }
  end

  defp okta_outcome("SUCCESS"), do: "success"
  defp okta_outcome("FAILURE"), do: "failure"
  defp okta_outcome(_), do: "unknown"

  defp okta_severity(json, outcome) do
    event_type = json["eventType"] || ""
    cond do
      outcome["result"] == "FAILURE" and String.contains?(event_type, "user.session") -> "medium"
      String.contains?(event_type, "security") -> "high"
      outcome["result"] == "FAILURE" -> "low"
      true -> "info"
    end
  end

  # Generic ECS normalization

  defp normalize_ecs(json) do
    event = json["event"] || %{}
    source = json["source"] || %{}
    destination = json["destination"] || %{}
    user = json["user"] || %{}
    file = json["file"] || %{}
    url = json["url"] || %{}
    dns = json["dns"] || %{}

    %{
      timestamp: parse_timestamp(json["@timestamp"]),
      event_category: event["category"],
      event_type: event["type"],
      action: event["action"],
      outcome: event["outcome"],
      severity: event["severity_name"] || "info",
      source_ip: source["ip"],
      source_port: source["port"],
      dest_ip: destination["ip"],
      dest_port: destination["port"],
      user_name: user["name"],
      user_email: user["email"],
      user_domain: user["domain"],
      file_name: file["name"],
      file_path: file["path"],
      file_hash_sha256: file["hash"]["sha256"],
      file_size: file["size"],
      url: url["full"],
      url_domain: url["domain"],
      url_path: url["path"],
      dns_query: dns["question"]["name"],
      parsed_fields: json
    }
  end

  # Generic normalization

  defp normalize_generic(json) do
    # Try to extract common fields with various naming conventions
    %{
      timestamp: extract_timestamp(json),
      source_ip: json["src_ip"] || json["source_ip"] || json["srcip"] || json["client_ip"],
      source_port: json["src_port"] || json["source_port"] || json["srcport"],
      dest_ip: json["dst_ip"] || json["dest_ip"] || json["dstip"] || json["server_ip"],
      dest_port: json["dst_port"] || json["dest_port"] || json["dstport"],
      user_name: json["user"] || json["username"] || json["user_name"],
      action: json["action"] || json["result"] || json["status"],
      severity: json["severity"] || json["level"] || "info",
      event_type: json["type"] || json["event_type"] || json["eventType"],
      event_category: json["category"] || json["event_category"],
      message: json["message"] || json["msg"],
      parsed_fields: json
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  # Helper functions

  defp parse_timestamp(nil), do: nil
  defp parse_timestamp(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ ->
        # Try parsing epoch timestamp
        case Integer.parse(ts) do
          {epoch, _} -> parse_epoch(epoch)
          _ -> nil
        end
    end
  end
  defp parse_timestamp(ts) when is_integer(ts), do: parse_epoch(ts)
  defp parse_timestamp(ts) when is_float(ts), do: parse_epoch(trunc(ts))
  defp parse_timestamp(%DateTime{} = ts), do: ts
  defp parse_timestamp(_), do: nil

  defp parse_epoch(epoch) when epoch > 1_000_000_000_000 do
    # Milliseconds
    case DateTime.from_unix(epoch, :millisecond) do
      {:ok, dt} -> dt
      _ -> nil
    end
  end

  defp parse_epoch(epoch) do
    # Seconds
    case DateTime.from_unix(epoch) do
      {:ok, dt} -> dt
      _ -> nil
    end
  end

  defp extract_timestamp(json) do
    ts_fields = ["timestamp", "@timestamp", "time", "eventTime", "ts", "datetime", "date"]

    Enum.find_value(ts_fields, fn field ->
      case Map.get(json, field) do
        nil -> nil
        ts -> parse_timestamp(ts)
      end
    end) || DateTime.utc_now()
  end
end
