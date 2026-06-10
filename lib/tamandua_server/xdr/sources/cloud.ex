defmodule TamanduaServer.XDR.Sources.Cloud do
  @moduledoc """
  XDR source connector for cloud audit logs.

  Supports:
  - AWS CloudTrail
  - Azure Activity Log / Azure Monitor
  - GCP Cloud Audit Logs
  - Alibaba Cloud ActionTrail
  - Oracle Cloud Audit

  Normalizes cloud infrastructure events including IAM changes,
  resource modifications, and security findings.
  """

  require Logger

  @vendors %{
    "aws" => &__MODULE__.parse_cloudtrail/1,
    "azure" => &__MODULE__.parse_azure/1,
    "gcp" => &__MODULE__.parse_gcp/1,
    "alibaba" => &__MODULE__.parse_alibaba/1,
    "oracle" => &__MODULE__.parse_oracle/1
  }

  @doc """
  Parse a cloud audit log event.

  ## Options
  - :vendor - Specific vendor (aws, azure, gcp, alibaba, oracle)
  """
  @spec parse(map(), keyword()) :: {:ok, map()} | {:error, term()}
  def parse(data, opts \\ []) when is_map(data) do
    vendor = Keyword.get(opts, :vendor) || detect_vendor(data)

    cond do
      vendor && Map.has_key?(@vendors, vendor) ->
        parser = Map.get(@vendors, vendor)
        parser.(data)

      true ->
        parse_generic_cloud(data)
    end
  end

  defp detect_vendor(data) do
    cond do
      # AWS CloudTrail
      Map.has_key?(data, "eventSource") and Map.has_key?(data, "awsRegion") -> "aws"

      # Azure
      Map.has_key?(data, "operationName") and Map.has_key?(data, "resourceId") -> "azure"

      # GCP
      Map.has_key?(data, "protoPayload") or
      (Map.has_key?(data, "logName") and String.contains?(data["logName"] || "", "cloudaudit")) -> "gcp"

      # Alibaba
      Map.has_key?(data, "eventSource") and Map.has_key?(data, "userAgent") and
      String.contains?(data["eventSource"] || "", "aliyun") -> "alibaba"

      true -> nil
    end
  end

  # AWS CloudTrail Parsing

  @doc false
  def parse_cloudtrail(data) when is_map(data) do
    user_identity = data["userIdentity"] || %{}
    request_params = data["requestParameters"] || %{}
    response = data["responseElements"] || %{}

    event = %{
      timestamp: parse_timestamp(data["eventTime"]),
      source_type: "cloud",
      device_vendor: "Amazon Web Services",
      device_product: "CloudTrail",
      cloud_provider: "aws",
      cloud_service: extract_aws_service(data["eventSource"]),
      cloud_region: data["awsRegion"],
      cloud_account_id: data["recipientAccountId"],
      cloud_resource_id: extract_cloudtrail_resource(data),
      source_ip: data["sourceIPAddress"],
      user_name: extract_aws_user(user_identity),
      user_domain: user_identity["accountId"],
      event_category: "cloud",
      event_type: data["eventName"],
      action: data["eventName"],
      outcome: if(data["errorCode"], do: "failure", else: "success"),
      severity: cloudtrail_severity(data),
      parsed_fields: %{
        event_id: data["eventID"],
        event_type: data["eventType"],
        event_category: data["eventCategory"],
        event_source: data["eventSource"],
        user_identity: user_identity,
        user_agent: data["userAgent"],
        request_parameters: request_params,
        response_elements: response,
        error_code: data["errorCode"],
        error_message: data["errorMessage"],
        additional_event_data: data["additionalEventData"],
        resources: data["resources"],
        read_only: data["readOnly"],
        management_event: data["managementEvent"]
      }
    }

    event = add_cloudtrail_mitre(event, data)
    {:ok, event}
  end

  defp extract_aws_service(nil), do: nil
  defp extract_aws_service(event_source) do
    case String.split(event_source, ".") do
      [service | _] -> service
      _ -> event_source
    end
  end

  defp extract_aws_user(user_identity) do
    user_identity["userName"] ||
    user_identity["principalId"] ||
    get_in(user_identity, ["sessionContext", "sessionIssuer", "userName"])
  end

  defp extract_cloudtrail_resource(data) do
    resources = data["resources"] || []
    request_params = data["requestParameters"] || %{}

    cond do
      is_list(resources) and length(resources) > 0 ->
        case List.first(resources) do
          %{"ARN" => arn} -> arn
          _ -> nil
        end

      request_params["resourceArn"] -> request_params["resourceArn"]
      request_params["bucketName"] -> "arn:aws:s3:::#{request_params["bucketName"]}"
      request_params["instanceId"] -> request_params["instanceId"]
      request_params["functionName"] -> request_params["functionName"]
      request_params["roleName"] -> request_params["roleName"]
      true -> nil
    end
  end

  defp cloudtrail_severity(data) do
    event_name = data["eventName"] || ""
    error_code = data["errorCode"]

    cond do
      # High severity: IAM/security changes
      String.contains?(event_name, ["Delete", "Remove"]) and
      String.contains?(event_name, ["Policy", "Role", "User", "Group"]) -> "high"

      # High severity: Security group modifications
      String.contains?(event_name, ["AuthorizeSecurityGroup", "RevokeSecurityGroup"]) -> "high"

      # High severity: Encryption/KMS operations
      String.contains?(event_name, ["ScheduleKeyDeletion", "DisableKey"]) -> "high"

      # Medium severity: Failed authentication
      error_code in ["AccessDenied", "UnauthorizedAccess"] -> "medium"

      # Medium severity: Resource creation in sensitive services
      String.starts_with?(event_name, "Create") and
      extract_aws_service(data["eventSource"]) in ["iam", "kms", "organizations"] -> "medium"

      # Medium severity: Console logins
      event_name == "ConsoleLogin" -> "medium"

      # Low severity: Successful read operations
      data["readOnly"] == true -> "info"

      # Default
      error_code != nil -> "medium"
      true -> "info"
    end
  end

  defp add_cloudtrail_mitre(event, data) do
    event_name = data["eventName"] || ""
    event_source = data["eventSource"] || ""

    mitre = cond do
      # Credential Access
      String.contains?(event_name, ["GetSecretValue", "GetPasswordData"]) ->
        %{mitre_tactics: ["credential_access"], mitre_techniques: ["T1552"]}

      # Privilege Escalation / Persistence
      String.contains?(event_name, ["CreateUser", "CreateRole", "AttachRolePolicy", "AttachUserPolicy"]) ->
        %{mitre_tactics: ["persistence", "privilege_escalation"], mitre_techniques: ["T1098"]}

      # Defense Evasion
      String.contains?(event_name, ["StopLogging", "DeleteTrail", "UpdateTrail"]) and
      String.contains?(event_source, "cloudtrail") ->
        %{mitre_tactics: ["defense_evasion"], mitre_techniques: ["T1562.008"]}

      # Defense Evasion - GuardDuty
      String.contains?(event_name, ["DeleteDetector", "StopMonitoringMembers"]) ->
        %{mitre_tactics: ["defense_evasion"], mitre_techniques: ["T1562.001"]}

      # Data Exfiltration
      String.contains?(event_name, ["GetObject"]) and
      String.contains?(event_source, "s3") and data["errorCode"] == nil ->
        %{mitre_tactics: ["collection"], mitre_techniques: ["T1530"]}

      # Discovery
      String.contains?(event_name, ["Describe", "List", "Get"]) and
      extract_aws_service(event_source) in ["ec2", "iam", "s3"] ->
        %{mitre_tactics: ["discovery"], mitre_techniques: ["T1580"]}

      # Initial Access - Console Login
      event_name == "ConsoleLogin" ->
        %{mitre_tactics: ["initial_access"], mitre_techniques: ["T1078.004"]}

      true -> %{}
    end

    Map.merge(event, mitre)
  end

  # Azure Parsing

  @doc false
  def parse_azure(data) when is_map(data) do
    properties = data["properties"] || %{}
    caller = data["caller"] || data["identity"]
    claims = extract_azure_claims(data)

    event = %{
      timestamp: parse_timestamp(data["time"] || data["eventTimestamp"]),
      source_type: "cloud",
      device_vendor: "Microsoft",
      device_product: "Azure Monitor",
      cloud_provider: "azure",
      cloud_service: extract_azure_service(data["resourceId"]),
      cloud_region: data["location"],
      cloud_account_id: data["subscriptionId"],
      cloud_resource_id: data["resourceId"],
      source_ip: properties["clientIPAddress"] || data["callerIpAddress"],
      user_name: extract_azure_user(caller, claims),
      user_email: claims["upn"] || claims["email"],
      event_category: data["category"] || "cloud",
      event_type: data["operationName"],
      action: data["operationName"],
      outcome: normalize_azure_outcome(data["resultType"]),
      severity: azure_severity(data),
      parsed_fields: %{
        operation_id: data["operationId"],
        correlation_id: data["correlationId"],
        level: data["level"],
        result_type: data["resultType"],
        result_signature: data["resultSignature"],
        result_description: data["resultDescription"],
        resource_group: data["resourceGroup"],
        resource_type: data["resourceType"],
        properties: properties,
        claims: claims
      }
    }

    event = add_azure_mitre(event, data)
    {:ok, event}
  end

  defp extract_azure_service(nil), do: nil
  defp extract_azure_service(resource_id) do
    case Regex.run(~r|/providers/([^/]+)|, resource_id) do
      [_, provider] -> provider
      _ -> nil
    end
  end

  defp extract_azure_claims(data) do
    cond do
      is_map(data["claims"]) -> data["claims"]
      is_map(data["identity"]) and is_map(data["identity"]["claims"]) -> data["identity"]["claims"]
      true -> %{}
    end
  end

  defp extract_azure_user(caller, claims) do
    cond do
      is_binary(caller) -> caller
      claims["name"] -> claims["name"]
      claims["upn"] -> claims["upn"]
      is_map(caller) and caller["principalId"] -> caller["principalId"]
      true -> nil
    end
  end

  defp normalize_azure_outcome(nil), do: "unknown"
  defp normalize_azure_outcome(result) do
    case String.downcase(to_string(result)) do
      r when r in ["success", "succeeded", "accepted", "ok"] -> "success"
      r when r in ["failure", "failed"] -> "failure"
      _ -> "unknown"
    end
  end

  defp azure_severity(data) do
    level = String.downcase(to_string(data["level"] || ""))
    operation = data["operationName"] || ""

    cond do
      level == "critical" -> "critical"
      level == "error" -> "high"
      level == "warning" -> "medium"

      # High severity operations
      String.contains?(operation, ["roleAssignment", "policyAssignment"]) -> "high"
      String.contains?(operation, ["networkSecurityGroups/delete"]) -> "high"
      String.contains?(operation, ["keyvault"]) and String.contains?(operation, ["delete"]) -> "high"

      # Medium severity
      String.contains?(operation, ["write"]) -> "medium"
      String.contains?(operation, ["delete"]) -> "medium"

      true -> "info"
    end
  end

  defp add_azure_mitre(event, data) do
    operation = data["operationName"] || ""

    mitre = cond do
      # Privilege Escalation
      String.contains?(operation, "roleAssignments/write") ->
        %{mitre_tactics: ["privilege_escalation"], mitre_techniques: ["T1098.003"]}

      # Defense Evasion
      String.contains?(operation, "activityLogAlerts/delete") or
      String.contains?(operation, "diagnosticSettings/delete") ->
        %{mitre_tactics: ["defense_evasion"], mitre_techniques: ["T1562.008"]}

      # Persistence
      String.contains?(operation, "automationAccounts") or
      String.contains?(operation, "scheduledQueryRules/write") ->
        %{mitre_tactics: ["persistence"], mitre_techniques: ["T1098"]}

      # Discovery
      String.contains?(operation, ["list", "read"]) ->
        %{mitre_tactics: ["discovery"], mitre_techniques: ["T1580"]}

      true -> %{}
    end

    Map.merge(event, mitre)
  end

  # GCP Parsing

  @doc false
  def parse_gcp(data) when is_map(data) do
    proto = data["protoPayload"] || data
    auth_info = proto["authenticationInfo"] || %{}
    request_meta = proto["requestMetadata"] || %{}
    resource = data["resource"] || %{}
    labels = resource["labels"] || %{}
    status = proto["status"] || %{}

    event = %{
      timestamp: parse_timestamp(data["timestamp"] || data["receiveTimestamp"]),
      source_type: "cloud",
      device_vendor: "Google Cloud",
      device_product: "Cloud Audit Logs",
      cloud_provider: "gcp",
      cloud_service: proto["serviceName"],
      cloud_region: labels["location"] || labels["zone"],
      cloud_account_id: labels["project_id"],
      cloud_resource_id: proto["resourceName"],
      source_ip: request_meta["callerIp"],
      user_name: auth_info["principalEmail"],
      user_email: auth_info["principalEmail"],
      event_category: "cloud",
      event_type: proto["methodName"],
      action: proto["methodName"],
      outcome: if(status["code"] == 0 or status["code"] == nil, do: "success", else: "failure"),
      severity: gcp_severity(data),
      parsed_fields: %{
        log_name: data["logName"],
        insert_id: data["insertId"],
        severity: data["severity"],
        service_name: proto["serviceName"],
        method_name: proto["methodName"],
        resource_name: proto["resourceName"],
        caller_ip: request_meta["callerIp"],
        caller_supplied_user_agent: request_meta["callerSuppliedUserAgent"],
        authorization_info: proto["authorizationInfo"],
        request: proto["request"],
        response: proto["response"],
        metadata: proto["metadata"],
        status: status
      }
    }

    event = add_gcp_mitre(event, proto)
    {:ok, event}
  end

  defp gcp_severity(data) do
    severity = data["severity"]
    proto = data["protoPayload"] || %{}
    method = proto["methodName"] || ""
    status = proto["status"] || %{}

    cond do
      severity == "CRITICAL" -> "critical"
      severity == "ERROR" -> "high"
      severity == "WARNING" -> "medium"

      # High severity methods
      String.contains?(method, ["SetIamPolicy"]) -> "high"
      String.contains?(method, ["delete"]) and String.contains?(method, ["key"]) -> "high"

      # Failed operations
      status["code"] != nil and status["code"] != 0 -> "medium"

      severity == "NOTICE" -> "low"
      true -> "info"
    end
  end

  defp add_gcp_mitre(event, proto) do
    method = proto["methodName"] || ""

    mitre = cond do
      # Privilege Escalation
      String.contains?(method, "SetIamPolicy") ->
        %{mitre_tactics: ["privilege_escalation"], mitre_techniques: ["T1098.003"]}

      # Defense Evasion
      String.contains?(method, ["sink", "metric"]) and String.contains?(method, "delete") ->
        %{mitre_tactics: ["defense_evasion"], mitre_techniques: ["T1562.008"]}

      # Persistence
      String.contains?(method, ["ServiceAccount", "CreateKey"]) ->
        %{mitre_tactics: ["persistence"], mitre_techniques: ["T1098.001"]}

      # Discovery
      String.contains?(method, ["list", "get"]) ->
        %{mitre_tactics: ["discovery"], mitre_techniques: ["T1580"]}

      true -> %{}
    end

    Map.merge(event, mitre)
  end

  # Alibaba Cloud Parsing

  @doc false
  def parse_alibaba(data) when is_map(data) do
    event = %{
      timestamp: parse_timestamp(data["eventTime"]),
      source_type: "cloud",
      device_vendor: "Alibaba Cloud",
      device_product: "ActionTrail",
      cloud_provider: "alibaba",
      cloud_service: data["eventSource"],
      cloud_region: data["acsRegion"],
      cloud_account_id: data["userIdentity"]["accountId"],
      cloud_resource_id: data["resourceArn"] || data["resourceName"],
      source_ip: data["sourceIpAddress"],
      user_name: data["userIdentity"]["userName"] || data["userIdentity"]["principalId"],
      event_category: "cloud",
      event_type: data["eventName"],
      action: data["eventName"],
      outcome: if(data["errorCode"], do: "failure", else: "success"),
      severity: alibaba_severity(data),
      parsed_fields: %{
        event_id: data["eventId"],
        event_version: data["eventVersion"],
        event_type: data["eventType"],
        user_identity: data["userIdentity"],
        request_parameters: data["requestParameters"],
        response_elements: data["responseElements"],
        error_code: data["errorCode"],
        error_message: data["errorMessage"]
      }
    }

    {:ok, event}
  end

  defp alibaba_severity(data) do
    event_name = data["eventName"] || ""
    error_code = data["errorCode"]

    cond do
      error_code != nil -> "medium"
      String.contains?(event_name, ["Delete", "Remove"]) -> "medium"
      String.contains?(event_name, ["Create", "Attach"]) and
      String.contains?(event_name, ["Policy", "Role"]) -> "high"
      true -> "info"
    end
  end

  # Oracle Cloud Parsing

  @doc false
  def parse_oracle(data) when is_map(data) do
    event = %{
      timestamp: parse_timestamp(data["eventTime"]),
      source_type: "cloud",
      device_vendor: "Oracle Cloud",
      device_product: "Audit",
      cloud_provider: "oracle",
      cloud_service: data["source"],
      cloud_region: data["region"],
      cloud_account_id: data["tenantId"],
      cloud_resource_id: data["resourceId"],
      source_ip: data["clientIpAddress"],
      user_name: data["principalName"] || data["principalId"],
      event_category: "cloud",
      event_type: data["eventType"],
      action: data["eventName"],
      outcome: if(data["responseStatus"] == "200", do: "success", else: "failure"),
      severity: oracle_severity(data),
      parsed_fields: %{
        event_id: data["eventId"],
        compartment_id: data["compartmentId"],
        compartment_name: data["compartmentName"],
        request_action: data["requestAction"],
        request_id: data["requestId"],
        response_status: data["responseStatus"],
        response_time: data["responseTime"],
        data: data["data"]
      }
    }

    {:ok, event}
  end

  defp oracle_severity(data) do
    event_type = data["eventType"] || ""
    response_status = data["responseStatus"]

    cond do
      response_status && String.starts_with?(response_status, "4") -> "medium"
      response_status && String.starts_with?(response_status, "5") -> "high"
      String.contains?(event_type, ["Delete"]) -> "medium"
      String.contains?(event_type, ["Policy", "Identity"]) -> "medium"
      true -> "info"
    end
  end

  # Generic Cloud Parsing

  defp parse_generic_cloud(data) do
    event = %{
      timestamp: parse_timestamp(data["timestamp"] || data["eventTime"] || data["time"]),
      source_type: "cloud",
      cloud_provider: data["provider"] || data["cloud_provider"],
      cloud_service: data["service"] || data["event_source"],
      cloud_region: data["region"],
      cloud_account_id: data["account_id"] || data["account"],
      cloud_resource_id: data["resource_id"] || data["resource"],
      source_ip: data["source_ip"] || data["client_ip"],
      user_name: data["user"] || data["principal"],
      event_category: "cloud",
      event_type: data["event_type"] || data["action"],
      action: data["action"],
      outcome: data["outcome"] || data["status"],
      severity: data["severity"] || "info",
      parsed_fields: data
    }

    {:ok, event}
  end

  # Helpers

  defp parse_timestamp(nil), do: DateTime.utc_now()
  defp parse_timestamp(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ ->
        case Integer.parse(ts) do
          {epoch, _} when epoch > 1_000_000_000_000 ->
            case DateTime.from_unix(epoch, :millisecond) do
              {:ok, dt} -> dt
              _ -> DateTime.utc_now()
            end
          {epoch, _} ->
            case DateTime.from_unix(epoch) do
              {:ok, dt} -> dt
              _ -> DateTime.utc_now()
            end
          _ -> DateTime.utc_now()
        end
    end
  end
  defp parse_timestamp(%DateTime{} = ts), do: ts
  defp parse_timestamp(_), do: DateTime.utc_now()
end
