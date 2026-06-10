defmodule TamanduaServer.XDR.Parsers.AzureDefender do
  @moduledoc """
  Parser for Microsoft Azure Defender (formerly Azure Security Center) alerts.

  Azure Defender provides threat protection for workloads running in Azure,
  on-premises, and in other clouds.

  ## Alert Types

  - **Compute**: VM security alerts, container threats
  - **Network**: DDoS, network anomalies
  - **Storage**: Suspicious storage access
  - **Database**: SQL injection, anomalous queries
  - **Identity**: Suspicious sign-ins, impossible travel
  - **IoT**: IoT device compromises
  - **Resource Manager**: Suspicious Azure operations

  ## Input Format

  Expects JSON format from Azure Defender alerts (via Azure Event Hub, Logic Apps, or Azure Sentinel).
  """

  alias TamanduaServer.XDR.NormalizedEvent

  @behaviour TamanduaServer.XDR.Parser

  # Alert category to MITRE ATT&CK mapping
  @mitre_mapping %{
    "bruteforce" => ["T1110"],
    "collection" => ["T1560", "T1074"],
    "commandcontrol" => ["T1071", "T1573"],
    "credentialaccess" => ["T1003", "T1552"],
    "defenseevasion" => ["T1562", "T1070"],
    "discovery" => ["T1087", "T1082"],
    "execution" => ["T1059", "T1204"],
    "exfiltration" => ["T1041", "T1567"],
    "impact" => ["T1486", "T1490"],
    "initialaccess" => ["T1190", "T1078"],
    "lateralmovement" => ["T1021", "T1570"],
    "persistence" => ["T1098", "T1136"],
    "privilegeescalation" => ["T1548", "T1068"],
    "reconnaissance" => ["T1595", "T1592"]
  }

  # Severity mapping
  @severity_mapping %{
    "high" => "high",
    "medium" => "medium",
    "low" => "low",
    "informational" => "info"
  }

  @impl true
  def parse(raw_log) when is_binary(raw_log) do
    case Jason.decode(raw_log) do
      {:ok, alert} ->
        normalize_alert(alert, raw_log)
      {:error, _} ->
        {:error, :invalid_json}
    end
  end

  def parse(alert) when is_map(alert) do
    normalize_alert(alert, Jason.encode!(alert))
  end

  @impl true
  def source_type, do: :cloud

  @impl true
  def vendor, do: "microsoft"

  @impl true
  def product, do: "defender"

  # ============================================================================
  # Normalization
  # ============================================================================

  defp normalize_alert(alert, raw_log) do
    # Handle different alert formats (Azure Sentinel, Security Center, etc.)
    alert = extract_alert_data(alert)

    properties = alert["properties"] || alert
    severity = String.downcase(properties["severity"] || "medium")
    intent = extract_intent(properties)
    tactics = extract_tactics(properties)

    event = %{
      id: alert["name"] || alert["id"] || Ecto.UUID.generate(),
      timestamp: parse_azure_timestamp(properties["timeGeneratedUtc"] || properties["startTimeUtc"] || alert["time"]),
      source_type: :cloud,
      vendor: "microsoft",
      product: "defender",
      raw_log: raw_log,

      # Alert identification
      alert_name: properties["alertDisplayName"] || properties["alertName"],
      alert_type: properties["alertType"],
      alert_uri: properties["alertUri"],
      description: properties["description"],
      product_name: properties["productName"],
      product_component: properties["productComponentName"],
      provider_name: properties["providerName"],
      vendor_name: properties["vendorName"],

      # Severity and status
      severity: Map.get(@severity_mapping, severity, "medium"),
      status: properties["status"],
      is_incident: properties["isIncident"],
      correlation_key: properties["correlationKey"],

      # Timing
      start_time: parse_azure_timestamp(properties["startTimeUtc"]),
      end_time: parse_azure_timestamp(properties["endTimeUtc"]),
      processing_end_time: parse_azure_timestamp(properties["processingEndTimeUtc"]),

      # Azure context
      subscription_id: extract_subscription_id(alert),
      resource_id: alert["id"] || properties["resourceId"],
      resource_type: extract_resource_type(alert),
      resource_group: extract_resource_group(alert),
      workspace_id: properties["workspaceId"],

      # Intent and tactics
      intent: intent,
      kill_chain_intent: properties["killChainIntent"],
      category: determine_category(intent, properties),
      tactics: tactics,

      # Network information
      source_ip: extract_source_ip(properties),
      dest_ip: extract_dest_ip(properties),
      source_port: extract_port(properties, "sourcePort"),
      dest_port: extract_port(properties, "destinationPort"),

      # User information
      user: extract_user(properties),
      user_principal_name: extract_upn(properties),
      account_name: extract_account_name(properties),

      # Resource information
      compromised_entity: properties["compromisedEntity"],
      affected_resource: extract_affected_resource(properties),

      # Extended properties
      extended_properties: extract_extended_properties(properties),

      # Remediation
      remediation_steps: properties["remediationSteps"],

      # Entities
      entities: extract_entities(properties),

      # MITRE mapping
      mitre_techniques: extract_mitre_techniques(properties, intent)
    }

    {:ok, NormalizedEvent.new(event)}
  end

  defp extract_alert_data(alert) do
    # Handle Azure Event Hub envelope format
    cond do
      alert["records"] ->
        # Multiple records in batch
        hd(alert["records"])
      alert["data"] && alert["data"]["context"] ->
        # Azure Monitor format
        alert["data"]["context"]
      alert["properties"] ->
        # Direct alert format
        alert
      alert["AlertDisplayName"] || alert["alertDisplayName"] ->
        # Flattened properties format
        %{"properties" => alert}
      true ->
        alert
    end
  end

  defp extract_intent(properties) do
    intent = properties["intent"] || properties["Intent"]

    if intent do
      intent
      |> String.split(",")
      |> Enum.map(&String.trim/1)
    else
      []
    end
  end

  defp extract_tactics(properties) do
    # Extract MITRE tactics from various fields
    tactics = []

    tactics = if intent = properties["intent"] || properties["Intent"] do
      tactics ++ String.split(intent, ",")
    else
      tactics
    end

    tactics = if kill_chain = properties["killChainIntent"] do
      tactics ++ [kill_chain]
    else
      tactics
    end

    tactics
    |> Enum.map(&String.trim/1)
    |> Enum.map(&String.downcase/1)
    |> Enum.uniq()
  end

  defp determine_category([], properties) do
    # Fallback to product name or alert type
    product = String.downcase(properties["productName"] || properties["alertType"] || "")
    cond do
      String.contains?(product, "sql") -> "database"
      String.contains?(product, "storage") -> "storage"
      String.contains?(product, "vm") or String.contains?(product, "compute") -> "compute"
      String.contains?(product, "network") -> "network"
      String.contains?(product, "identity") or String.contains?(product, "aad") -> "identity"
      String.contains?(product, "container") or String.contains?(product, "kubernetes") -> "container"
      String.contains?(product, "iot") -> "iot"
      true -> "general"
    end
  end
  defp determine_category(intents, _properties) do
    # Use primary intent as category
    primary_intent = hd(intents) |> String.downcase()
    cond do
      String.contains?(primary_intent, "credential") -> "credential_access"
      String.contains?(primary_intent, "lateral") -> "lateral_movement"
      String.contains?(primary_intent, "exfil") -> "exfiltration"
      String.contains?(primary_intent, "execution") -> "execution"
      String.contains?(primary_intent, "privilege") -> "privilege_escalation"
      String.contains?(primary_intent, "persist") -> "persistence"
      String.contains?(primary_intent, "defense") -> "defense_evasion"
      String.contains?(primary_intent, "discovery") -> "discovery"
      String.contains?(primary_intent, "collection") -> "collection"
      String.contains?(primary_intent, "impact") -> "impact"
      String.contains?(primary_intent, "command") or String.contains?(primary_intent, "c2") -> "c2"
      true -> primary_intent
    end
  end

  # ============================================================================
  # Azure Resource Extraction
  # ============================================================================

  defp extract_subscription_id(alert) do
    resource_id = alert["id"] || ""
    case Regex.run(~r/subscriptions\/([^\/]+)/, resource_id) do
      [_, sub_id] -> sub_id
      _ -> nil
    end
  end

  defp extract_resource_group(alert) do
    resource_id = alert["id"] || ""
    case Regex.run(~r/resourceGroups\/([^\/]+)/, resource_id) do
      [_, rg] -> rg
      _ -> nil
    end
  end

  defp extract_resource_type(alert) do
    resource_id = alert["id"] || ""
    case Regex.run(~r/providers\/([^\/]+\/[^\/]+)/, resource_id) do
      [_, type] -> type
      _ -> nil
    end
  end

  defp extract_affected_resource(properties) do
    %{
      id: properties["resourceId"],
      display_name: properties["compromisedEntity"],
      type: properties["resourceType"],
      identifiers: properties["resourceIdentifiers"]
    }
  end

  # ============================================================================
  # Entity Extraction
  # ============================================================================

  defp extract_entities(properties) do
    entities = properties["entities"] || properties["Entities"] || []

    Enum.map(entities, fn entity ->
      entity_type = entity["type"] || entity["Type"]
      %{
        type: entity_type,
        properties: extract_entity_properties(entity_type, entity)
      }
    end)
  end

  defp extract_entity_properties("ip", entity) do
    %{
      address: entity["address"] || entity["Address"],
      location: %{
        country: entity["countryName"] || get_in(entity, ["location", "countryName"]),
        city: entity["city"] || get_in(entity, ["location", "city"]),
        latitude: entity["latitude"] || get_in(entity, ["location", "latitude"]),
        longitude: entity["longitude"] || get_in(entity, ["location", "longitude"])
      }
    }
  end

  defp extract_entity_properties("host", entity) do
    %{
      hostname: entity["hostName"] || entity["HostName"],
      dns_domain: entity["dnsDomain"],
      azure_id: entity["azureID"],
      os_family: entity["osFamily"],
      os_version: entity["osVersion"]
    }
  end

  defp extract_entity_properties("account", entity) do
    %{
      name: entity["name"] || entity["Name"],
      nt_domain: entity["ntDomain"],
      upn_suffix: entity["upnSuffix"],
      azure_ad_user_id: entity["aadUserId"],
      sid: entity["sid"],
      display_name: entity["displayName"]
    }
  end

  defp extract_entity_properties("file", entity) do
    %{
      name: entity["name"] || entity["Name"],
      directory: entity["directory"],
      file_hash: entity["fileHash"] || %{
        algorithm: entity["fileHashType"],
        value: entity["fileHashValue"]
      }
    }
  end

  defp extract_entity_properties("process", entity) do
    %{
      process_id: entity["processId"],
      command_line: entity["commandLine"],
      elevation_token: entity["elevationToken"],
      creation_time: entity["creationTimeUtc"],
      image_file: entity["imageFile"]
    }
  end

  defp extract_entity_properties("url", entity) do
    %{
      url: entity["url"] || entity["Url"]
    }
  end

  defp extract_entity_properties("azure-resource", entity) do
    %{
      resource_id: entity["resourceId"],
      subscription_id: entity["subscriptionId"]
    }
  end

  defp extract_entity_properties("mailbox", entity) do
    %{
      mailbox_address: entity["mailboxPrimaryAddress"],
      display_name: entity["displayName"],
      upn: entity["upn"]
    }
  end

  defp extract_entity_properties("malware", entity) do
    %{
      name: entity["name"],
      category: entity["category"]
    }
  end

  defp extract_entity_properties(_, entity) do
    # Return all properties for unknown entity types
    entity
  end

  # ============================================================================
  # Network Information Extraction
  # ============================================================================

  defp extract_source_ip(properties) do
    # Check various fields for source IP
    extended = properties["extendedProperties"] || properties["ExtendedProperties"] || %{}
    entities = properties["entities"] || properties["Entities"] || []

    # Try extended properties first
    ip = extended["Source IP"] || extended["sourceIp"] || extended["attacker ip"] ||
         extended["Client IP Address"] || extended["IP address"]

    # Try entities
    ip = ip || Enum.find_value(entities, fn entity ->
      if (entity["type"] || entity["Type"]) == "ip" do
        entity["address"] || entity["Address"]
      end
    end)

    ip
  end

  defp extract_dest_ip(properties) do
    extended = properties["extendedProperties"] || properties["ExtendedProperties"] || %{}
    extended["Destination IP"] || extended["destinationIp"] || extended["Target IP"]
  end

  defp extract_port(properties, field) do
    extended = properties["extendedProperties"] || properties["ExtendedProperties"] || %{}
    port_str = extended[field] || extended[Macro.camelize(field)]

    case Integer.parse(port_str || "") do
      {port, _} -> port
      :error -> nil
    end
  end

  # ============================================================================
  # User Information Extraction
  # ============================================================================

  defp extract_user(properties) do
    extended = properties["extendedProperties"] || properties["ExtendedProperties"] || %{}
    entities = properties["entities"] || properties["Entities"] || []

    # Try extended properties
    user = extended["User Name"] || extended["userName"] || extended["User Principal Name"]

    # Try entities
    user = user || Enum.find_value(entities, fn entity ->
      if (entity["type"] || entity["Type"]) == "account" do
        entity["name"] || entity["Name"] || entity["displayName"]
      end
    end)

    user
  end

  defp extract_upn(properties) do
    extended = properties["extendedProperties"] || properties["ExtendedProperties"] || %{}
    entities = properties["entities"] || properties["Entities"] || []

    upn = extended["User Principal Name"] || extended["userPrincipalName"]

    upn = upn || Enum.find_value(entities, fn entity ->
      if (entity["type"] || entity["Type"]) == "account" do
        entity["userPrincipalName"] || "#{entity["name"]}@#{entity["upnSuffix"]}"
      end
    end)

    upn
  end

  defp extract_account_name(properties) do
    entities = properties["entities"] || properties["Entities"] || []

    Enum.find_value(entities, fn entity ->
      if (entity["type"] || entity["Type"]) == "account" do
        entity["name"] || entity["Name"]
      end
    end)
  end

  # ============================================================================
  # Extended Properties Extraction
  # ============================================================================

  defp extract_extended_properties(properties) do
    extended = properties["extendedProperties"] || properties["ExtendedProperties"] || %{}

    # Clean up and normalize keys
    extended
    |> Enum.map(fn {key, value} ->
      normalized_key = key
      |> String.replace(" ", "_")
      |> String.downcase()
      {normalized_key, value}
    end)
    |> Map.new()
  end

  # ============================================================================
  # MITRE Mapping
  # ============================================================================

  defp extract_mitre_techniques(properties, intents) do
    # First check if MITRE techniques are directly provided
    techniques = properties["mitreTechniques"] || properties["MitreTechniques"] || []

    if length(techniques) > 0 do
      techniques
    else
      # Map from intents
      intents
      |> Enum.flat_map(fn intent ->
        normalized = intent |> String.downcase() |> String.replace([" ", "-", "_"], "")
        Map.get(@mitre_mapping, normalized, [])
      end)
      |> Enum.uniq()
    end
  end

  # ============================================================================
  # Timestamp Parsing
  # ============================================================================

  defp parse_azure_timestamp(nil), do: DateTime.utc_now()
  defp parse_azure_timestamp(timestamp) when is_binary(timestamp) do
    # Azure uses ISO 8601 format with Z suffix or offset
    case DateTime.from_iso8601(timestamp) do
      {:ok, dt, _} -> dt
      _ ->
        # Try without timezone
        case NaiveDateTime.from_iso8601(timestamp) do
          {:ok, ndt} -> DateTime.from_naive!(ndt, "Etc/UTC")
          _ -> DateTime.utc_now()
        end
    end
  end
  defp parse_azure_timestamp(_), do: DateTime.utc_now()
end
