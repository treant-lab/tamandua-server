defmodule TamanduaServer.Workers.DriftScanWorker do
  @moduledoc """
  Scheduled worker for automatic configuration drift scanning.

  Runs hourly to scan all agents for configuration drift.
  """

  use Oban.Worker,
    queue: :scheduled,
    max_attempts: 3

  require Logger

  alias TamanduaServer.Agents.DriftDetector

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"organization_id" => organization_id}}) do
    Logger.info("[DriftScanWorker] Starting scheduled drift scan for organization #{organization_id}")

    case DriftDetector.scan_organization(organization_id, scan_type: "scheduled") do
      {:ok, result} ->
        Logger.info(
          "[DriftScanWorker] Completed scan: #{result.scanned}/#{result.total} agents scanned, " <>
          "#{result.failed} failed"
        )

        # Send summary notification if drifts detected
        if has_critical_drifts?(result) do
          send_drift_alert(organization_id, result)
        end

        :ok

      {:error, reason} ->
        Logger.error("[DriftScanWorker] Scan failed for organization #{organization_id}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @impl Oban.Worker
  def perform(%Oban.Job{}) do
    # Scan all organizations
    Logger.info("[DriftScanWorker] Starting scheduled drift scan for all organizations")

    organizations = TamanduaServer.Repo.all(TamanduaServer.Accounts.Organization)

    Enum.each(organizations, fn org ->
      %{organization_id: org.id}
      |> __MODULE__.new()
      |> Oban.insert()
    end)

    :ok
  end

  # Private functions

  defp has_critical_drifts?(result) do
    Enum.any?(result.results, fn
      {:ok, _agent_id, scan_result} ->
        scan_result.severity_counts[:critical] > 0 or
        scan_result.severity_counts[:high] > 0

      _ ->
        false
    end)
  end

  defp send_drift_alert(organization_id, result) do
    # Count total critical and high drifts
    totals = Enum.reduce(result.results, %{critical: 0, high: 0}, fn
      {:ok, _agent_id, scan_result}, acc ->
        %{
          critical: acc.critical + (scan_result.severity_counts[:critical] || 0),
          high: acc.high + (scan_result.severity_counts[:high] || 0)
        }

      _, acc ->
        acc
    end)

    if totals.critical > 0 or totals.high > 0 do
      # Create alert
      TamanduaServer.Alerts.create_alert(%{
        organization_id: organization_id,
        type: "configuration_drift",
        severity: if(totals.critical > 0, do: "critical", else: "high"),
        title: "Configuration drift detected in scheduled scan",
        description: """
        Scheduled drift scan detected configuration issues:
        - #{totals.critical} critical drifts
        - #{totals.high} high severity drifts
        - #{result.scanned} agents scanned

        Review the drift dashboard for details.
        """,
        metadata: %{
          scan_type: "scheduled",
          total_agents: result.total,
          scanned_agents: result.scanned,
          failed_scans: result.failed,
          critical_drifts: totals.critical,
          high_drifts: totals.high
        }
      })

      # Broadcast notification
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "organization:#{organization_id}",
        {:drift_scan_alert, %{
          critical_drifts: totals.critical,
          high_drifts: totals.high,
          agents_scanned: result.scanned
        }}
      )
    end
  end

  @doc """
  Schedules drift scans for all organizations.

  Call this from application startup or use Oban scheduling:

      config :tamandua_server, Oban,
        plugins: [
          {Oban.Plugins.Cron,
           crontab: [
             {"0 * * * *", TamanduaServer.Workers.DriftScanWorker}  # Every hour
           ]}
        ]
  """
  def schedule_all do
    %{}
    |> __MODULE__.new()
    |> Oban.insert()
  end
end
