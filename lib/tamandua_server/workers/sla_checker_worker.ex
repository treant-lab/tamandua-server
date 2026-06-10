defmodule TamanduaServer.Workers.SLACheckerWorker do
  @moduledoc """
  Periodic worker to check for SLA breaches and send warnings.

  Runs every 5 minutes to check:
  - Alerts approaching acknowledge deadline (within 15 minutes)
  - Alerts approaching resolve deadline (within 30 minutes)
  - Alerts that have breached deadlines (need flag update)
  """

  use Oban.Worker,
    queue: :sla_checks,
    max_attempts: 3

  require Logger

  alias TamanduaServer.Alerts.SLATracker

  @impl Oban.Worker
  def perform(%Oban.Job{args: args}) do
    organization_id = Map.get(args, "organization_id")
    warning_threshold_minutes = Map.get(args, "warning_threshold_minutes", 15)

    Logger.info("[SLACheckerWorker] Running SLA check for org #{organization_id || "all"}")

    result = SLATracker.check_sla_breaches(
      organization_id: organization_id,
      warning_threshold_minutes: warning_threshold_minutes
    )

    Logger.info(
      "[SLACheckerWorker] SLA check complete: " <>
      "#{result.approaching_acknowledge} approaching ack, " <>
      "#{result.approaching_resolve} approaching resolve, " <>
      "#{result.breached_acknowledge} breached ack, " <>
      "#{result.breached_resolve} breached resolve"
    )

    :ok
  end

  @doc """
  Schedule SLA checks for all organizations.

  This should be called from Application.start/2 to set up recurring checks.
  """
  def schedule_recurring_checks do
    # Schedule a check every 5 minutes
    %{}
    |> new(schedule_in: 0)
    |> Oban.insert()

    # Schedule next check in 5 minutes
    %{}
    |> new(schedule_in: 300) # 5 minutes
    |> Oban.insert()
  end
end
