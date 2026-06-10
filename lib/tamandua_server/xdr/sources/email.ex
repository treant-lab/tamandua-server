defmodule TamanduaServer.XDR.Sources.Email do
  @moduledoc """
  XDR source connector for email security logs.

  Supports:
  - Microsoft 365 Defender for Office 365
  - Google Workspace Security
  - Proofpoint Email Protection
  - Mimecast
  - Barracuda Email Security Gateway

  Normalizes email security events including spam, phishing, and malware detection.
  """

  require Logger

  @vendors %{
    "o365" => &__MODULE__.parse_o365/1,
    "google_workspace" => &__MODULE__.parse_google_workspace/1,
    "proofpoint" => &__MODULE__.parse_proofpoint/1,
    "mimecast" => &__MODULE__.parse_mimecast/1,
    "barracuda" => &__MODULE__.parse_barracuda/1
  }

  @doc """
  Parse an email security log event.

  ## Options
  - :vendor - Specific vendor (o365, google_workspace, proofpoint, mimecast, barracuda)
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

      true ->
        {:error, :invalid_input}
    end
  end

  defp detect_and_parse_map(data) do
    cond do
      # Microsoft 365
      Map.has_key?(data, "RecordType") and Map.has_key?(data, "Workload") ->
        parse_o365(data)

      # Google Workspace
      Map.has_key?(data, "actor") and Map.has_key?(data, "events") ->
        parse_google_workspace(data)

      # Proofpoint
      Map.has_key?(data, "threatStatus") or Map.has_key?(data, "senderIP") ->
        parse_proofpoint(data)

      # Mimecast
      Map.has_key?(data, "acc") and Map.has_key?(data, "Sender") ->
        parse_mimecast(data)

      true ->
        parse_generic_email(data)
    end
  end

  # Microsoft 365 Defender for Office Parsing

  @doc false
  def parse_o365(data) when is_map(data) do
    event = %{
      timestamp: parse_o365_timestamp(data["CreationTime"]),
      source_type: "email",
      device_vendor: "Microsoft",
      device_product: "Office 365",
      source_ip: data["ClientIP"] || data["SenderIp"],
      user_name: data["UserId"],
      user_email: data["UserId"],
      email_subject: data["Subject"],
      email_from: data["SenderAddress"] || data["From"],
      email_to: encode_recipients(data["Recipients"] || data["To"]),
      email_direction: o365_email_direction(data["Directionality"]),
      action: normalize_o365_action(data["PolicyAction"] || data["Verdict"]),
      outcome: o365_outcome(data),
      threat_name: data["ThreatType"] || data["MalwareName"],
      threat_category: o365_threat_category(data),
      severity: o365_severity(data),
      event_category: "email",
      event_type: o365_event_type(data["RecordType"]),
      file_name: extract_attachment_name(data["AttachmentData"]),
      file_hash_sha256: extract_attachment_hash(data["AttachmentData"]),
      url: data["Url"],
      parsed_fields: %{
        record_type: data["RecordType"],
        workload: data["Workload"],
        operation: data["Operation"],
        organization_id: data["OrganizationId"],
        message_id: data["NetworkMessageId"] || data["MessageId"],
        internet_message_id: data["InternetMessageId"],
        confidence_level: data["ConfidenceLevel"],
        detection_method: data["DetectionMethod"],
        delivered_to: data["DeliveredTo"],
        delivery_action: data["DeliveryAction"],
        delivery_location: data["DeliveryLocation"],
        policy_name: data["PolicyName"],
        threat_detection: data["ThreatDetectionMethod"],
        original_delivery_location: data["OriginalDeliveryLocation"],
        latest_delivery_location: data["LatestDeliveryLocation"]
      }
    }

    # Add MITRE mappings for threats
    event = add_email_mitre_mappings(event)

    {:ok, event}
  end

  defp parse_o365_timestamp(nil), do: DateTime.utc_now()
  defp parse_o365_timestamp(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end

  defp o365_email_direction(nil), do: nil
  defp o365_email_direction(dir) when is_binary(dir) do
    case String.downcase(dir) do
      "inbound" -> "inbound"
      "outbound" -> "outbound"
      "intraorg" -> "internal"
      _ -> nil
    end
  end

  defp normalize_o365_action(nil), do: "unknown"
  defp normalize_o365_action(action) when is_binary(action) do
    case String.downcase(action) do
      a when a in ["block", "blocked", "reject", "rejected"] -> "block"
      a when a in ["quarantine", "quarantined"] -> "quarantine"
      a when a in ["deliver", "delivered", "allow", "allowed"] -> "allow"
      a when a in ["replace", "replaced"] -> "forward"
      a when a in ["zap", "zapped"] -> "quarantine"
      _ -> action
    end
  end

  defp o365_outcome(data) do
    action = normalize_o365_action(data["PolicyAction"] || data["Verdict"])
    if action in ["block", "quarantine"], do: "success", else: "unknown"
  end

  defp o365_threat_category(data) do
    cond do
      data["ThreatType"] == "Malware" -> "malware"
      data["ThreatType"] == "Phish" -> "phishing"
      data["ThreatType"] == "Spam" -> "spam"
      data["ThreatType"] -> data["ThreatType"]
      data["ConfidenceLevel"] in ["High", "Medium"] -> "suspicious"
      true -> nil
    end
  end

  defp o365_severity(data) do
    cond do
      data["ThreatType"] == "Malware" -> "critical"
      data["ThreatType"] == "Phish" -> "high"
      data["ConfidenceLevel"] == "High" -> "high"
      data["ConfidenceLevel"] == "Medium" -> "medium"
      data["ThreatType"] == "Spam" -> "low"
      true -> "info"
    end
  end

  defp o365_event_type(record_type) do
    case record_type do
      28 -> "malware_detection"
      29 -> "phish_detection"
      30 -> "spam_detection"
      47 -> "safe_links"
      48 -> "safe_attachments"
      _ -> "email_event"
    end
  end

  # Google Workspace Parsing

  @doc false
  def parse_google_workspace(data) when is_map(data) do
    actor = data["actor"] || %{}
    events = data["events"] || []
    event_data = List.first(events) || %{}
    params = build_params_map(event_data["parameters"] || [])

    event = %{
      timestamp: parse_google_timestamp(data["id"]["time"]),
      source_type: "email",
      device_vendor: "Google",
      device_product: "Workspace",
      source_ip: data["ipAddress"],
      user_email: actor["email"],
      user_name: actor["email"],
      email_subject: params["subject"],
      email_from: params["from"] || params["sender"],
      email_to: params["to"] || params["recipient"],
      email_direction: google_email_direction(params),
      action: normalize_google_action(event_data["name"]),
      outcome: google_outcome(params),
      threat_name: params["spam_classification"] || params["threat_name"],
      threat_category: google_threat_category(params),
      severity: google_severity(params),
      event_category: "email",
      event_type: event_data["name"] || "email_event",
      file_name: params["attachment_name"],
      file_hash_sha256: params["attachment_hash"],
      parsed_fields: %{
        event_name: event_data["name"],
        event_type: event_data["type"],
        parameters: params,
        actor_key: actor["key"],
        actor_type: actor["type"],
        message_id: params["message_id"]
      }
    }

    event = add_email_mitre_mappings(event)
    {:ok, event}
  end

  defp build_params_map(params) when is_list(params) do
    Enum.reduce(params, %{}, fn param, acc ->
      name = param["name"]
      value = param["value"] || param["intValue"] || param["boolValue"]
      Map.put(acc, name, value)
    end)
  end

  defp parse_google_timestamp(nil), do: DateTime.utc_now()
  defp parse_google_timestamp(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end

  defp google_email_direction(params) do
    cond do
      params["is_internal"] == true -> "internal"
      params["direction"] == "inbound" -> "inbound"
      params["direction"] == "outbound" -> "outbound"
      true -> nil
    end
  end

  defp normalize_google_action(nil), do: "unknown"
  defp normalize_google_action(action) when is_binary(action) do
    case String.downcase(action) do
      a when a in ["spam_marked", "phishing_marked"] -> "quarantine"
      a when a in ["message_rejected", "bounce"] -> "block"
      a when a in ["message_delivered"] -> "allow"
      _ -> action
    end
  end

  defp google_outcome(params) do
    cond do
      params["spam_classification"] in ["SPAM", "PHISHING"] -> "success"
      params["message_rejected"] == true -> "success"
      true -> "unknown"
    end
  end

  defp google_threat_category(params) do
    cond do
      params["spam_classification"] == "PHISHING" -> "phishing"
      params["spam_classification"] == "SPAM" -> "spam"
      params["is_malware"] == true -> "malware"
      true -> nil
    end
  end

  defp google_severity(params) do
    cond do
      params["is_malware"] == true -> "critical"
      params["spam_classification"] == "PHISHING" -> "high"
      params["spam_classification"] == "SPAM" -> "low"
      true -> "info"
    end
  end

  # Proofpoint Parsing

  @doc false
  def parse_proofpoint(data) when is_map(data) do
    event = %{
      timestamp: parse_proofpoint_timestamp(data["messageTime"]),
      source_type: "email",
      device_vendor: "Proofpoint",
      device_product: "Email Protection",
      source_ip: data["senderIP"],
      user_email: data["recipient"] || List.first(data["recipients"] || []),
      user_name: data["recipient"],
      email_subject: data["subject"],
      email_from: data["sender"],
      email_to: encode_recipients(data["recipients"]),
      email_direction: proofpoint_direction(data["messageType"]),
      action: normalize_proofpoint_action(data["threatStatus"]),
      outcome: proofpoint_outcome(data),
      threat_name: data["threatType"],
      threat_category: proofpoint_threat_category(data),
      severity: proofpoint_severity(data),
      event_category: "email",
      event_type: data["type"] || "email_threat",
      url: data["threatURL"],
      file_name: extract_attachment_name(data["attachments"]),
      file_hash_sha256: extract_attachment_hash(data["attachments"]),
      parsed_fields: %{
        campaign_id: data["campaignId"],
        threat_id: data["threatID"],
        classification: data["classification"],
        cluster: data["cluster"],
        quarantine_folder: data["quarantineFolder"],
        quarantine_rule: data["quarantineRule"],
        message_id: data["GUID"],
        phish_score: data["phishScore"],
        spam_score: data["spamScore"],
        impostor_score: data["impostorScore"]
      }
    }

    event = add_email_mitre_mappings(event)
    {:ok, event}
  end

  defp parse_proofpoint_timestamp(nil), do: DateTime.utc_now()
  defp parse_proofpoint_timestamp(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end

  defp proofpoint_direction(nil), do: nil
  defp proofpoint_direction(type) when is_binary(type) do
    case String.downcase(type) do
      "inbound" -> "inbound"
      "outbound" -> "outbound"
      "internal" -> "internal"
      _ -> nil
    end
  end

  defp normalize_proofpoint_action(nil), do: "unknown"
  defp normalize_proofpoint_action(status) when is_binary(status) do
    case String.downcase(status) do
      "active" -> "alert"
      "cleared" -> "allow"
      "falsePositive" -> "allow"
      _ -> status
    end
  end

  defp proofpoint_outcome(data) do
    cond do
      data["quarantined"] == true -> "success"
      data["blocked"] == true -> "success"
      true -> "unknown"
    end
  end

  defp proofpoint_threat_category(data) do
    case data["classification"] do
      "malware" -> "malware"
      "phish" -> "phishing"
      "spam" -> "spam"
      "impostor" -> "bec"
      _ -> data["threatType"]
    end
  end

  defp proofpoint_severity(data) do
    cond do
      data["classification"] == "malware" -> "critical"
      data["classification"] in ["phish", "impostor"] -> "high"
      data["classification"] == "spam" -> "low"
      (data["phishScore"] || 0) > 80 -> "high"
      true -> "medium"
    end
  end

  # Mimecast Parsing

  @doc false
  def parse_mimecast(data) when is_map(data) do
    event = %{
      timestamp: parse_mimecast_timestamp(data["datetime"] || data["Datetime"]),
      source_type: "email",
      device_vendor: "Mimecast",
      device_product: "Email Security",
      source_ip: data["IP"] || data["SenderIP"],
      user_email: data["Recipient"] || data["Rcpt"],
      user_name: data["Recipient"],
      email_subject: data["Subject"],
      email_from: data["Sender"] || data["From"],
      email_to: data["Recipient"],
      email_direction: mimecast_direction(data["Route"]),
      action: normalize_mimecast_action(data["Act"] || data["Action"]),
      outcome: mimecast_outcome(data),
      threat_name: data["MsgReason"] || data["Reason"],
      threat_category: mimecast_threat_category(data),
      severity: mimecast_severity(data),
      event_category: "email",
      event_type: data["aCode"] || "email_event",
      file_name: data["AttachmentName"],
      parsed_fields: %{
        acc: data["acc"],
        definition: data["Definition"],
        spam_score: data["SpamScore"],
        spam_info: data["SpamInfo"],
        virus_found: data["VirusFound"],
        message_id: data["MsgId"],
        size: data["Size"]
      }
    }

    event = add_email_mitre_mappings(event)
    {:ok, event}
  end

  defp parse_mimecast_timestamp(nil), do: DateTime.utc_now()
  defp parse_mimecast_timestamp(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end

  defp mimecast_direction(nil), do: nil
  defp mimecast_direction(route) when is_binary(route) do
    case String.downcase(route) do
      "inbound" -> "inbound"
      "outbound" -> "outbound"
      "internal" -> "internal"
      _ -> nil
    end
  end

  defp normalize_mimecast_action(nil), do: "unknown"
  defp normalize_mimecast_action(action) when is_binary(action) do
    case String.downcase(action) do
      a when a in ["hld", "hold", "held"] -> "quarantine"
      a when a in ["rej", "reject", "rejected", "bou", "bounce"] -> "block"
      a when a in ["acc", "accept", "accepted", "del", "deliver", "delivered"] -> "allow"
      _ -> action
    end
  end

  defp mimecast_outcome(data) do
    action = normalize_mimecast_action(data["Act"] || data["Action"])
    if action in ["block", "quarantine"], do: "success", else: "unknown"
  end

  defp mimecast_threat_category(data) do
    cond do
      data["VirusFound"] -> "malware"
      (data["SpamScore"] || 0) > 5 -> "spam"
      String.contains?(data["MsgReason"] || "", "phish") -> "phishing"
      true -> nil
    end
  end

  defp mimecast_severity(data) do
    cond do
      data["VirusFound"] -> "critical"
      String.contains?(data["MsgReason"] || "", "phish") -> "high"
      (data["SpamScore"] || 0) > 8 -> "medium"
      (data["SpamScore"] || 0) > 5 -> "low"
      true -> "info"
    end
  end

  # Barracuda Parsing

  @doc false
  def parse_barracuda(data) when is_map(data) do
    event = %{
      timestamp: data["timestamp"] || DateTime.utc_now(),
      source_type: "email",
      device_vendor: "Barracuda",
      device_product: "Email Security Gateway",
      source_ip: data["src_ip"] || data["sender_ip"],
      user_email: data["recipient"] || data["rcpt"],
      user_name: data["recipient"],
      email_subject: data["subject"],
      email_from: data["sender"] || data["from"],
      email_to: data["recipient"],
      email_direction: data["direction"],
      action: normalize_barracuda_action(data["action"]),
      outcome: barracuda_outcome(data),
      threat_name: data["reason"] || data["block_reason"],
      threat_category: barracuda_threat_category(data),
      severity: barracuda_severity(data),
      event_category: "email",
      file_name: data["attachment_name"],
      parsed_fields: data
    }

    event = add_email_mitre_mappings(event)
    {:ok, event}
  end

  defp normalize_barracuda_action(nil), do: "unknown"
  defp normalize_barracuda_action(action) when is_binary(action) do
    case String.downcase(action) do
      "allowed" -> "allow"
      "blocked" -> "block"
      "quarantined" -> "quarantine"
      a -> a
    end
  end

  defp barracuda_outcome(data) do
    action = normalize_barracuda_action(data["action"])
    if action in ["block", "quarantine"], do: "success", else: "unknown"
  end

  defp barracuda_threat_category(data) do
    reason = String.downcase(data["reason"] || "")
    cond do
      String.contains?(reason, "virus") or String.contains?(reason, "malware") -> "malware"
      String.contains?(reason, "phish") -> "phishing"
      String.contains?(reason, "spam") -> "spam"
      true -> nil
    end
  end

  defp barracuda_severity(data) do
    category = barracuda_threat_category(data)
    case category do
      "malware" -> "critical"
      "phishing" -> "high"
      "spam" -> "low"
      _ -> "info"
    end
  end

  # Generic Email Parsing

  defp parse_generic_email(data) do
    event = %{
      timestamp: data["timestamp"] || DateTime.utc_now(),
      source_type: "email",
      source_ip: data["sender_ip"] || data["src_ip"],
      user_email: data["recipient"] || data["to"],
      email_subject: data["subject"],
      email_from: data["sender"] || data["from"],
      email_to: data["recipient"] || data["to"],
      action: data["action"],
      threat_name: data["threat"] || data["reason"],
      severity: data["severity"] || "info",
      event_category: "email",
      parsed_fields: data
    }

    event = add_email_mitre_mappings(event)
    {:ok, event}
  end

  # MITRE Mappings

  defp add_email_mitre_mappings(event) do
    case event[:threat_category] do
      "phishing" ->
        Map.merge(event, %{
          mitre_tactics: ["initial_access"],
          mitre_techniques: ["T1566.001", "T1566.002"]  # Phishing: Spearphishing Attachment/Link
        })

      "malware" ->
        Map.merge(event, %{
          mitre_tactics: ["initial_access", "execution"],
          mitre_techniques: ["T1566.001", "T1204.002"]  # Phishing with malicious attachment, User Execution
        })

      "bec" ->
        Map.merge(event, %{
          mitre_tactics: ["initial_access"],
          mitre_techniques: ["T1566.002", "T1534"]  # Phishing: Link, Internal Spearphishing
        })

      "spam" ->
        Map.merge(event, %{
          mitre_tactics: ["initial_access"],
          mitre_techniques: ["T1566"]  # Phishing
        })

      _ ->
        event
    end
  end

  # Helpers

  defp encode_recipients(nil), do: nil
  defp encode_recipients(recipients) when is_list(recipients), do: Jason.encode!(recipients)
  defp encode_recipients(recipient) when is_binary(recipient), do: recipient
  defp encode_recipients(_), do: nil

  defp extract_attachment_name(nil), do: nil
  defp extract_attachment_name(attachments) when is_list(attachments) do
    case List.first(attachments) do
      %{"fileName" => name} -> name
      %{"name" => name} -> name
      _ -> nil
    end
  end
  defp extract_attachment_name(_), do: nil

  defp extract_attachment_hash(nil), do: nil
  defp extract_attachment_hash(attachments) when is_list(attachments) do
    case List.first(attachments) do
      %{"sha256" => hash} -> hash
      %{"hash" => hash} -> hash
      _ -> nil
    end
  end
  defp extract_attachment_hash(_), do: nil
end
