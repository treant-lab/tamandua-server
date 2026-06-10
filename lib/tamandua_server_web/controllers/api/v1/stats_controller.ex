defmodule TamanduaServerWeb.API.V1.StatsController do
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Agents
  alias TamanduaServer.Alerts
  alias TamanduaServer.Telemetry
  alias TamanduaServer.Detection

  # Extract organization_id from current user for multi-tenant isolation
  defp get_org_id(conn) do
    case conn.assigns[:current_user] do
      %{organization_id: org_id} when not is_nil(org_id) -> org_id
      _ -> nil
    end
  end

  def overview(conn, _params) do
    org_id = get_org_id(conn)

    stats = %{
      total_agents: Agents.count_agents_for_org(org_id),
      online_agents: Agents.count_online_for_org(org_id),
      open_alerts: Alerts.count_active_for_org(org_id),
      critical_alerts: Alerts.count_by_severity_for_org(org_id, :critical),
      high_alerts: Alerts.count_by_severity_for_org(org_id, :high),
      medium_alerts: Alerts.count_by_severity_for_org(org_id, :medium),
      low_alerts: Alerts.count_by_severity_for_org(org_id, :low),
      events_today: Telemetry.count_events_today_for_org(org_id),
      detections_today: Detection.count_detections_today_for_org(org_id)
    }

    json(conn, %{data: stats})
  end

  def agents(conn, _params) do
    org_id = get_org_id(conn)

    total = Agents.count_agents_for_org(org_id)
    online = Agents.count_online_for_org(org_id)

    stats = %{
      total: total,
      online: online,
      offline: total - online,
      by_os: Agents.count_by_os_for_org(org_id),
      by_version: Agents.count_by_version_for_org(org_id)
    }

    json(conn, %{data: stats})
  end

  def alerts(conn, params) do
    org_id = get_org_id(conn)
    time_range = params["time_range"] || "7d"

    stats = %{
      total: Alerts.count_active_for_org(org_id),
      by_severity: %{
        critical: Alerts.count_by_severity_for_org(org_id, :critical),
        high: Alerts.count_by_severity_for_org(org_id, :high),
        medium: Alerts.count_by_severity_for_org(org_id, :medium),
        low: Alerts.count_by_severity_for_org(org_id, :low)
      },
      trend: Alerts.get_trend_for_org(org_id, time_range)
    }

    json(conn, %{data: stats})
  end

  def detections(conn, params) do
    org_id = get_org_id(conn)
    time_range = params["time_range"] || "7d"

    stats = %{
      total: Detection.count_detections_today_for_org(org_id),
      by_type: Detection.count_by_type_for_org(org_id),
      top_rules: Detection.get_top_rules_for_org(org_id, limit: 10),
      trend: Detection.get_trend_for_org(org_id, time_range)
    }

    json(conn, %{data: stats})
  end

  @doc """
  Get Solana attestation statistics.

  Returns counts of attested alerts, bounty payments, and Solana integration status.
  """
  def attestations(conn, _params) do
    alias TamanduaServer.Solana.Client

    attestation_stats = Alerts.public_attestation_stats()

    stats = %{
      enabled: Client.enabled?(),
      rpc_url: Client.rpc_url(),
      total_attested: attestation_stats.total_attested,
      total_bounties: attestation_stats.total_bounties,
      total_bounty_sol: attestation_stats.total_bounty_sol,
      signer_pubkey: get_signer_pubkey()
    }

    json(conn, %{data: stats})
  end

  defp get_signer_pubkey do
    alias TamanduaServer.Solana.Client

    case Client.get_signer_pubkey() do
      {:ok, pubkey} -> pubkey
      _ -> nil
    end
  end
end
