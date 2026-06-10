defmodule TamanduaServer.Audit.Forwarders.SiemForwarder do
  @moduledoc """
  Forwards audit logs to SIEM platforms (QRadar, Sentinel, etc.).
  """

  def forward(audit_log, config) do
    siem_type = config["siem_type"]

    case siem_type do
      "qradar" -> forward_to_qradar(audit_log, config)
      "sentinel" -> forward_to_sentinel(audit_log, config)
      "elastic" -> forward_to_elastic(audit_log, config)
      _ -> {:error, "Unknown SIEM type: #{siem_type}"}
    end
  end

  defp forward_to_qradar(audit_log, config) do
    # QRadar uses syslog LEF format
    TamanduaServer.Audit.Forwarders.SyslogForwarder.forward(audit_log, config)
  end

  defp forward_to_sentinel(audit_log, config) do
    workspace_id = config["workspace_id"]
    shared_key = config["shared_key"]
    log_type = config["log_type"] || "TamanduaAudit"

    # Azure Sentinel Data Collector API
    url = "https://#{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    
    payload = Jason.encode!([build_sentinel_payload(audit_log)])
    timestamp = DateTime.to_iso8601(audit_log.inserted_at)
    
    signature = build_sentinel_signature(shared_key, payload, timestamp)

    headers = [
      {"Content-Type", "application/json"},
      {"Log-Type", log_type},
      {"x-ms-date", timestamp},
      {"Authorization", signature}
    ]

    case HTTPoison.post(url, payload, headers) do
      {:ok, %{status_code: 200}} -> {:ok, :forwarded}
      {:ok, %{status_code: code}} -> {:error, "HTTP #{code}"}
      {:error, reason} -> {:error, reason}
    end
  end

  defp forward_to_elastic(audit_log, config) do
    url = config["elasticsearch_url"]
    index = config["index"] || "tamandua-audit"
    
    doc_url = "#{url}/#{index}/_doc/#{audit_log.id}"
    payload = Jason.encode!(build_elastic_payload(audit_log))

    headers = [{"Content-Type", "application/json"}]
    
    headers = if config["api_key"] do
      [{"Authorization", "ApiKey #{config["api_key"]}"} | headers]
    else
      headers
    end

    case HTTPoison.put(doc_url, payload, headers) do
      {:ok, %{status_code: code}} when code in [200, 201] -> {:ok, :forwarded}
      {:ok, %{status_code: code}} -> {:error, "HTTP #{code}"}
      {:error, reason} -> {:error, reason}
    end
  end

  defp build_sentinel_payload(log) do
    %{
      TimeGenerated: log.inserted_at,
      UserId: log.user_id,
      OrganizationId: log.organization_id,
      Action: log.action,
      ResourceType: log.resource_type,
      ResourceId: log.resource_id,
      IpAddress: log.ip_address,
      Success: log.success,
      Severity: log.severity,
      Category: log.category,
      Suspicious: log.suspicious,
      RiskScore: log.risk_score
    }
  end

  defp build_elastic_payload(log) do
    %{
      "@timestamp" => log.inserted_at,
      user_id: log.user_id,
      organization_id: log.organization_id,
      action: log.action,
      resource_type: log.resource_type,
      resource_id: log.resource_id,
      ip_address: log.ip_address,
      user_agent: log.user_agent,
      success: log.success,
      severity: log.severity,
      category: log.category,
      metadata: log.metadata,
      suspicious: log.suspicious,
      risk_score: log.risk_score
    }
  end

  defp build_sentinel_signature(shared_key, payload, timestamp) do
    string_to_sign = "POST\n#{byte_size(payload)}\napplication/json\nx-ms-date:#{timestamp}\n/api/logs"
    decoded_key = Base.decode64!(shared_key)
    signature = :crypto.mac(:hmac, :sha256, decoded_key, string_to_sign) |> Base.encode64()
    "SharedKey #{signature}"
  end
end
