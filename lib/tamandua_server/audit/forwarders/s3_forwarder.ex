defmodule TamanduaServer.Audit.Forwarders.S3Forwarder do
  @moduledoc """
  Forwards audit logs to AWS S3.
  """

  def forward(audit_log, config) do
    bucket = config["bucket"]
    region = config["region"] || "us-east-1"
    prefix = config["prefix"] || "audit-logs"

    date = Date.utc_today()
    key = "#{prefix}/#{date.year}/#{date.month}/#{date.day}/#{audit_log.id}.json"

    payload = Jason.encode!(audit_log_to_map(audit_log))

    case ExAws.S3.put_object(bucket, key, payload)
         |> ExAws.request(region: region) do
      {:ok, _} -> {:ok, :forwarded}
      {:error, reason} -> {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp audit_log_to_map(log) do
    Map.take(log, [
      :id, :inserted_at, :user_id, :organization_id, :action,
      :resource_type, :resource_id, :ip_address, :user_agent,
      :success, :severity, :category, :metadata, :changes,
      :suspicious, :suspicious_reason, :risk_score
    ])
  end
end
