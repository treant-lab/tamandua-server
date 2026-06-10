defmodule TamanduaServer.XDR.Parsers.AWSGuardDuty do
  @moduledoc """
  Parser for AWS GuardDuty findings.

  AWS GuardDuty is a threat detection service that continuously monitors
  for malicious activity and unauthorized behavior in AWS accounts.

  ## Finding Types

  GuardDuty findings are categorized by threat purpose:
  - **Backdoor**: Resources being used for DDoS attacks or unauthorized access
  - **Behavior**: Anomalous API activity patterns
  - **CryptoCurrency**: Resources used for cryptocurrency mining
  - **DefenseEvasion**: Attempts to avoid detection
  - **Discovery**: Reconnaissance activity
  - **Exfiltration**: Data exfiltration attempts
  - **Impact**: Service disruption attempts
  - **InitialAccess**: Initial compromise indicators
  - **PenTest**: Penetration testing activity
  - **Persistence**: Maintaining access
  - **Policy**: IAM/S3 policy violations
  - **PrivilegeEscalation**: Privilege escalation attempts
  - **Recon**: Reconnaissance activity
  - **Stealth**: Evasion techniques
  - **Trojan**: Trojan-related activity
  - **UnauthorizedAccess**: Unauthorized access attempts

  ## Input Format

  Expects JSON format from GuardDuty findings (via CloudWatch Events, SNS, or S3).
  """

  alias TamanduaServer.XDR.NormalizedEvent

  @behaviour TamanduaServer.XDR.Parser

  # Finding type to MITRE ATT&CK mapping
  @mitre_mapping %{
    "backdoor" => ["T1095", "T1571"],
    "behavior" => ["T1078"],
    "cryptocurrency" => ["T1496"],
    "defenseevasion" => ["T1070", "T1562"],
    "discovery" => ["T1580", "T1087"],
    "exfiltration" => ["T1567", "T1048"],
    "impact" => ["T1498", "T1485"],
    "initialaccess" => ["T1190", "T1078"],
    "pentest" => ["T1595"],
    "persistence" => ["T1098", "T1136"],
    "policy" => ["T1078.004"],
    "privilegeescalation" => ["T1078", "T1548"],
    "recon" => ["T1595", "T1592"],
    "stealth" => ["T1562", "T1070"],
    "trojan" => ["T1204", "T1059"],
    "unauthorizedaccess" => ["T1078", "T1110"]
  }

  # Severity mapping (GuardDuty uses 0-10 scale)
  @severity_thresholds %{
    critical: 8.0,
    high: 7.0,
    medium: 4.0,
    low: 1.0
  }

  @impl true
  def parse(raw_log) when is_binary(raw_log) do
    case Jason.decode(raw_log) do
      {:ok, finding} ->
        normalize_finding(finding, raw_log)
      {:error, _} ->
        {:error, :invalid_json}
    end
  end

  def parse(finding) when is_map(finding) do
    normalize_finding(finding, Jason.encode!(finding))
  end

  @impl true
  def source_type, do: :cloud

  @impl true
  def vendor, do: "aws"

  @impl true
  def product, do: "guardduty"

  # ============================================================================
  # Normalization
  # ============================================================================

  defp normalize_finding(finding, raw_log) do
    # Handle both direct finding format and CloudWatch event format
    finding = extract_finding(finding)

    # Extract main finding details
    severity_num = finding["Severity"] || finding["severity"] || 0
    finding_type = finding["Type"] || finding["type"] || ""
    threat_purpose = extract_threat_purpose(finding_type)

    event = %{
      id: finding["Id"] || finding["id"] || Ecto.UUID.generate(),
      timestamp: parse_guardduty_timestamp(finding["UpdatedAt"] || finding["CreatedAt"]),
      source_type: :cloud,
      vendor: "aws",
      product: "guardduty",
      raw_log: raw_log,

      # Finding identification
      finding_id: finding["Id"] || finding["id"],
      finding_type: finding_type,
      threat_purpose: threat_purpose,
      title: finding["Title"] || finding["title"],
      description: finding["Description"] || finding["description"],

      # Severity
      severity: calculate_severity(severity_num),
      severity_score: severity_num,

      # AWS context
      aws_account_id: finding["AccountId"] || finding["accountId"],
      aws_region: finding["Region"] || finding["region"],
      partition: finding["Partition"] || finding["partition"],

      # Resource information
      resource: extract_resource_info(finding["Resource"] || finding["resource"]),

      # Service information
      service: extract_service_info(finding["Service"] || finding["service"]),

      # Action details
      action: extract_action(finding),

      # Network information
      source_ip: extract_source_ip(finding),
      dest_ip: extract_dest_ip(finding),
      source_port: extract_source_port(finding),
      dest_port: extract_dest_port(finding),
      protocol: extract_protocol(finding),

      # Additional context
      category: map_category(threat_purpose),
      mitre_techniques: Map.get(@mitre_mapping, String.downcase(threat_purpose), []),
      confidence: finding["Confidence"] || finding["confidence"],

      # Evidence
      evidence: extract_evidence(finding)
    }

    {:ok, NormalizedEvent.new(event)}
  end

  defp extract_finding(event) do
    # Handle CloudWatch Events format
    cond do
      event["detail"] -> event["detail"]
      event["finding"] -> event["finding"]
      event["Type"] or event["type"] -> event
      true -> event
    end
  end

  defp extract_threat_purpose(finding_type) do
    # Finding type format: ThreatPurpose:ResourceType/ThreatFamilyName.Subtype!Subtype2
    case String.split(finding_type, ":") do
      [purpose | _] -> purpose
      _ -> "Unknown"
    end
  end

  defp calculate_severity(severity_num) when is_number(severity_num) do
    cond do
      severity_num >= @severity_thresholds.critical -> "critical"
      severity_num >= @severity_thresholds.high -> "high"
      severity_num >= @severity_thresholds.medium -> "medium"
      severity_num >= @severity_thresholds.low -> "low"
      true -> "info"
    end
  end
  defp calculate_severity(_), do: "info"

  defp map_category(threat_purpose) do
    case String.downcase(threat_purpose) do
      "backdoor" -> "intrusion"
      "behavior" -> "anomaly"
      "cryptocurrency" -> "cryptomining"
      "defenseevasion" -> "defense_evasion"
      "discovery" -> "discovery"
      "exfiltration" -> "exfiltration"
      "impact" -> "impact"
      "initialaccess" -> "initial_access"
      "pentest" -> "penetration_testing"
      "persistence" -> "persistence"
      "policy" -> "policy_violation"
      "privilegeescalation" -> "privilege_escalation"
      "recon" -> "reconnaissance"
      "stealth" -> "evasion"
      "trojan" -> "malware"
      "unauthorizedaccess" -> "unauthorized_access"
      _ -> "threat"
    end
  end

  # ============================================================================
  # Resource Extraction
  # ============================================================================

  defp extract_resource_info(nil), do: %{}
  defp extract_resource_info(resource) when is_map(resource) do
    resource_type = resource["ResourceType"] || resource["resourceType"]

    base_info = %{
      type: resource_type
    }

    # Extract type-specific details
    case resource_type do
      "Instance" ->
        instance = resource["InstanceDetails"] || resource["instanceDetails"] || %{}
        Map.merge(base_info, %{
          instance_id: instance["InstanceId"] || instance["instanceId"],
          instance_type: instance["InstanceType"] || instance["instanceType"],
          availability_zone: instance["AvailabilityZone"] || instance["availabilityZone"],
          image_id: instance["ImageId"] || instance["imageId"],
          platform: instance["Platform"] || instance["platform"],
          instance_state: instance["InstanceState"] || instance["instanceState"],
          tags: extract_tags(instance["Tags"] || instance["tags"]),
          network_interfaces: extract_network_interfaces(instance["NetworkInterfaces"])
        })

      "AccessKey" ->
        access_key = resource["AccessKeyDetails"] || resource["accessKeyDetails"] || %{}
        Map.merge(base_info, %{
          access_key_id: access_key["AccessKeyId"] || access_key["accessKeyId"],
          principal_id: access_key["PrincipalId"] || access_key["principalId"],
          user_name: access_key["UserName"] || access_key["userName"],
          user_type: access_key["UserType"] || access_key["userType"]
        })

      "S3Bucket" ->
        s3 = resource["S3BucketDetails"] || resource["s3BucketDetails"] || []
        s3_info = if is_list(s3) and length(s3) > 0, do: hd(s3), else: %{}
        Map.merge(base_info, %{
          bucket_name: s3_info["Name"] || s3_info["name"],
          bucket_arn: s3_info["Arn"] || s3_info["arn"],
          bucket_type: s3_info["Type"] || s3_info["type"],
          owner_id: get_in(s3_info, ["Owner", "Id"]) || get_in(s3_info, ["owner", "id"])
        })

      "EKSCluster" ->
        eks = resource["EksClusterDetails"] || resource["eksClusterDetails"] || %{}
        Map.merge(base_info, %{
          cluster_name: eks["Name"] || eks["name"],
          cluster_arn: eks["Arn"] || eks["arn"],
          cluster_status: eks["Status"] || eks["status"]
        })

      "Container" ->
        container = resource["ContainerDetails"] || resource["containerDetails"] || %{}
        Map.merge(base_info, %{
          container_runtime: container["ContainerRuntime"] || container["containerRuntime"],
          container_id: container["Id"] || container["id"],
          container_name: container["Name"] || container["name"],
          image: container["Image"] || container["image"],
          volume_mounts: container["VolumeMounts"] || container["volumeMounts"]
        })

      "Lambda" ->
        lambda = resource["LambdaDetails"] || resource["lambdaDetails"] || %{}
        Map.merge(base_info, %{
          function_name: lambda["FunctionName"] || lambda["functionName"],
          function_arn: lambda["FunctionArn"] || lambda["functionArn"],
          function_version: lambda["FunctionVersion"] || lambda["functionVersion"],
          role: lambda["Role"] || lambda["role"]
        })

      "RDSDBInstance" ->
        rds = resource["RdsDbInstanceDetails"] || resource["rdsDbInstanceDetails"] || %{}
        Map.merge(base_info, %{
          db_instance_id: rds["DbInstanceIdentifier"] || rds["dbInstanceIdentifier"],
          db_cluster_id: rds["DbClusterIdentifier"] || rds["dbClusterIdentifier"],
          engine: rds["Engine"] || rds["engine"]
        })

      _ ->
        base_info
    end
  end
  defp extract_resource_info(_), do: %{}

  defp extract_tags(nil), do: []
  defp extract_tags(tags) when is_list(tags) do
    Enum.map(tags, fn tag ->
      {tag["Key"] || tag["key"], tag["Value"] || tag["value"]}
    end)
  end
  defp extract_tags(_), do: []

  defp extract_network_interfaces(nil), do: []
  defp extract_network_interfaces(interfaces) when is_list(interfaces) do
    Enum.map(interfaces, fn ni ->
      %{
        network_interface_id: ni["NetworkInterfaceId"] || ni["networkInterfaceId"],
        private_ip: ni["PrivateIpAddress"] || ni["privateIpAddress"],
        public_ip: ni["PublicIp"] || ni["publicIp"],
        vpc_id: ni["VpcId"] || ni["vpcId"],
        subnet_id: ni["SubnetId"] || ni["subnetId"],
        security_groups: ni["SecurityGroups"] || ni["securityGroups"] || []
      }
    end)
  end
  defp extract_network_interfaces(_), do: []

  # ============================================================================
  # Service Information Extraction
  # ============================================================================

  defp extract_service_info(nil), do: %{}
  defp extract_service_info(service) when is_map(service) do
    action = service["Action"] || service["action"] || %{}
    action_type = action["ActionType"] || action["actionType"]

    base_info = %{
      action_type: action_type,
      detector_id: service["DetectorId"] || service["detectorId"],
      event_first_seen: service["EventFirstSeen"] || service["eventFirstSeen"],
      event_last_seen: service["EventLastSeen"] || service["eventLastSeen"],
      archived: service["Archived"] || service["archived"],
      count: service["Count"] || service["count"],
      additional_info: service["AdditionalInfo"] || service["additionalInfo"]
    }

    # Extract action-specific details
    case action_type do
      "NETWORK_CONNECTION" ->
        nc = action["NetworkConnectionAction"] || action["networkConnectionAction"] || %{}
        Map.merge(base_info, %{
          connection_direction: nc["ConnectionDirection"] || nc["connectionDirection"],
          blocked: nc["Blocked"] || nc["blocked"],
          remote_ip: get_in(nc, ["RemoteIpDetails", "IpAddressV4"]) ||
                     get_in(nc, ["remoteIpDetails", "ipAddressV4"]),
          remote_port: get_in(nc, ["RemotePortDetails", "Port"]) ||
                       get_in(nc, ["remotePortDetails", "port"]),
          local_port: get_in(nc, ["LocalPortDetails", "Port"]) ||
                      get_in(nc, ["localPortDetails", "port"]),
          protocol: nc["Protocol"] || nc["protocol"],
          remote_country: get_in(nc, ["RemoteIpDetails", "Country", "CountryName"]) ||
                          get_in(nc, ["remoteIpDetails", "country", "countryName"]),
          remote_city: get_in(nc, ["RemoteIpDetails", "City", "CityName"]) ||
                       get_in(nc, ["remoteIpDetails", "city", "cityName"]),
          remote_org: get_in(nc, ["RemoteIpDetails", "Organization", "Org"]) ||
                      get_in(nc, ["remoteIpDetails", "organization", "org"]),
          remote_asn: get_in(nc, ["RemoteIpDetails", "Organization", "Asn"]) ||
                      get_in(nc, ["remoteIpDetails", "organization", "asn"])
        })

      "DNS_REQUEST" ->
        dns = action["DnsRequestAction"] || action["dnsRequestAction"] || %{}
        Map.merge(base_info, %{
          domain: dns["Domain"] || dns["domain"],
          blocked: dns["Blocked"] || dns["blocked"],
          protocol: dns["Protocol"] || dns["protocol"]
        })

      "AWS_API_CALL" ->
        api = action["AwsApiCallAction"] || action["awsApiCallAction"] || %{}
        Map.merge(base_info, %{
          api: api["Api"] || api["api"],
          caller_type: api["CallerType"] || api["callerType"],
          service_name: api["ServiceName"] || api["serviceName"],
          remote_ip: get_in(api, ["RemoteIpDetails", "IpAddressV4"]) ||
                     get_in(api, ["remoteIpDetails", "ipAddressV4"]),
          remote_country: get_in(api, ["RemoteIpDetails", "Country", "CountryName"]) ||
                          get_in(api, ["remoteIpDetails", "country", "countryName"]),
          user_agent: api["UserAgent"] || api["userAgent"],
          error_code: api["ErrorCode"] || api["errorCode"],
          affected_resources: api["AffectedResources"] || api["affectedResources"]
        })

      "PORT_PROBE" ->
        probe = action["PortProbeAction"] || action["portProbeAction"] || %{}
        port_details = probe["PortProbeDetails"] || probe["portProbeDetails"] || []
        Map.merge(base_info, %{
          blocked: probe["Blocked"] || probe["blocked"],
          port_probe_details: Enum.map(port_details, fn pd ->
            %{
              local_port: get_in(pd, ["LocalPortDetails", "Port"]) ||
                          get_in(pd, ["localPortDetails", "port"]),
              remote_ip: get_in(pd, ["RemoteIpDetails", "IpAddressV4"]) ||
                         get_in(pd, ["remoteIpDetails", "ipAddressV4"])
            }
          end)
        })

      "KUBERNETES_API_CALL" ->
        k8s = action["KubernetesApiCallAction"] || action["kubernetesApiCallAction"] || %{}
        Map.merge(base_info, %{
          request_uri: k8s["RequestUri"] || k8s["requestUri"],
          verb: k8s["Verb"] || k8s["verb"],
          user_agent: k8s["UserAgent"] || k8s["userAgent"],
          remote_ip: get_in(k8s, ["RemoteIpDetails", "IpAddressV4"]) ||
                     get_in(k8s, ["remoteIpDetails", "ipAddressV4"]),
          status_code: k8s["StatusCode"] || k8s["statusCode"],
          namespace: k8s["Namespace"] || k8s["namespace"]
        })

      _ ->
        base_info
    end
  end
  defp extract_service_info(_), do: %{}

  defp extract_action(finding) do
    service = finding["Service"] || finding["service"] || %{}
    action = service["Action"] || service["action"] || %{}
    action["ActionType"] || action["actionType"] || "unknown"
  end

  # ============================================================================
  # Network Information Extraction
  # ============================================================================

  defp extract_source_ip(finding) do
    service = finding["Service"] || finding["service"] || %{}
    action = service["Action"] || service["action"] || %{}

    get_in(action, ["NetworkConnectionAction", "RemoteIpDetails", "IpAddressV4"]) ||
    get_in(action, ["networkConnectionAction", "remoteIpDetails", "ipAddressV4"]) ||
    get_in(action, ["AwsApiCallAction", "RemoteIpDetails", "IpAddressV4"]) ||
    get_in(action, ["awsApiCallAction", "remoteIpDetails", "ipAddressV4"]) ||
    get_in(action, ["PortProbeAction", "PortProbeDetails", Access.at(0), "RemoteIpDetails", "IpAddressV4"]) ||
    get_in(action, ["KubernetesApiCallAction", "RemoteIpDetails", "IpAddressV4"])
  end

  defp extract_dest_ip(finding) do
    service = finding["Service"] || finding["service"] || %{}
    action = service["Action"] || service["action"] || %{}

    get_in(action, ["NetworkConnectionAction", "LocalIpDetails", "IpAddressV4"]) ||
    get_in(action, ["networkConnectionAction", "localIpDetails", "ipAddressV4"])
  end

  defp extract_source_port(finding) do
    service = finding["Service"] || finding["service"] || %{}
    action = service["Action"] || service["action"] || %{}

    get_in(action, ["NetworkConnectionAction", "RemotePortDetails", "Port"]) ||
    get_in(action, ["networkConnectionAction", "remotePortDetails", "port"])
  end

  defp extract_dest_port(finding) do
    service = finding["Service"] || finding["service"] || %{}
    action = service["Action"] || service["action"] || %{}

    get_in(action, ["NetworkConnectionAction", "LocalPortDetails", "Port"]) ||
    get_in(action, ["networkConnectionAction", "localPortDetails", "port"])
  end

  defp extract_protocol(finding) do
    service = finding["Service"] || finding["service"] || %{}
    action = service["Action"] || service["action"] || %{}

    get_in(action, ["NetworkConnectionAction", "Protocol"]) ||
    get_in(action, ["networkConnectionAction", "protocol"]) ||
    get_in(action, ["DnsRequestAction", "Protocol"]) ||
    get_in(action, ["dnsRequestAction", "protocol"])
  end

  # ============================================================================
  # Evidence Extraction
  # ============================================================================

  defp extract_evidence(finding) do
    %{
      threat_intelligence: finding["ThreatIntelligenceDetails"] ||
                           finding["threatIntelligenceDetails"],
      anomalous_behavior: finding["AnomalousBehavior"] ||
                          finding["anomalousBehavior"],
      additional_info: get_in(finding, ["Service", "AdditionalInfo"]) ||
                       get_in(finding, ["service", "additionalInfo"])
    }
  end

  # ============================================================================
  # Timestamp Parsing
  # ============================================================================

  defp parse_guardduty_timestamp(nil), do: DateTime.utc_now()
  defp parse_guardduty_timestamp(timestamp) when is_binary(timestamp) do
    case DateTime.from_iso8601(timestamp) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end
  defp parse_guardduty_timestamp(_), do: DateTime.utc_now()
end
