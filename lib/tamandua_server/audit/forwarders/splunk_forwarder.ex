defmodule TamanduaServer.Audit.Forwarders.SplunkForwarder do
  @moduledoc """
  Forwards audit logs to Splunk HEC (HTTP Event Collector).
  """

  require Logger

  def forward(audit_log, config) do
    url = config["hec_url"]
    token = config["hec_token"]
    index = config["index"] || "main"
    source = config["source"] || "tamandua_edr"

    event = %{
      time: DateTime.to_unix(audit_log.inserted_at),
      source: source,
      sourcetype: "tamandua:audit",
      index: index,
      event: build_event_payload(audit_log)
    }

    headers = [
      {"Authorization", "Splunk #{token}"},
      {"Content-Type", "application/json"}
    ]

    case HTTPoison.post(url, Jason.encode!(event), headers) do
      {:ok, %{status_code: 200}} -> {:ok, :forwarded}
      {:ok, %{status_code: code, body: body}} -> {:error, "HTTP #{code}: #{body}"}
      {:error, reason} -> {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp build_event_payload(log) do
    %{
      id: log.id,
      timestamp: log.inserted_at,
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
      changes: log.changes,
      suspicious: log.suspicious,
      suspicious_reason: log.suspicious_reason,
      risk_score: log.risk_score
    }
  end
end
