defmodule TamanduaServer.Reports.Scheduler do
  @moduledoc """
  Report Scheduler for Tamandua EDR.

  Provides Oban-based job scheduling for automated report generation:
  - Daily, weekly, monthly schedules
  - Configurable report templates and recipients
  - Email delivery
  - Schedule management
  """

  use Oban.Worker,
    queue: :reports,
    max_attempts: 3,
    # Prevent duplicate jobs within 5 minutes
    unique: [period: 300]

  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Reports.{Engine, ScheduledReport}

  import Ecto.Query

  # ============================================================================
  # Oban Worker Callbacks
  # ============================================================================

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"scheduled_report_id" => id}}) do
    case get_scheduled_report(id) do
      nil ->
        Logger.warning("Scheduled report #{id} not found, skipping")
        :ok

      schedule ->
        if schedule.enabled do
          execute_scheduled_report(schedule)
        else
          Logger.info("Scheduled report #{id} is disabled, skipping")
          :ok
        end
    end
  end

  @impl Oban.Worker
  def perform(%Oban.Job{args: args}) do
    Logger.warning("Unknown job args: #{inspect(args)}")
    :ok
  end

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Creates a new scheduled report.

  ## Options
  - `:name` - Schedule name (required)
  - `:template_id` - Report template ID (required)
  - `:schedule` - Cron expression or preset (daily, weekly, monthly)
  - `:recipients` - List of email addresses
  - `:format` - Output format (:pdf, :html, :csv)
  - `:params` - Additional template parameters
  - `:enabled` - Whether schedule is active (default: true)
  """
  def create_schedule(opts) do
    attrs = %{
      name: opts[:name] || "Scheduled Report",
      template_id: opts[:template_id],
      schedule: normalize_schedule(opts[:schedule] || "weekly"),
      recipients: opts[:recipients] || [],
      format: to_string(opts[:format] || :pdf),
      params: opts[:params] || %{},
      enabled: Map.get(opts, :enabled, true),
      created_by: opts[:created_by],
      organization_id: opts[:organization_id],
      last_run_at: nil,
      next_run_at: calculate_next_run(opts[:schedule] || "weekly")
    }

    changeset = ScheduledReport.changeset(%ScheduledReport{}, attrs)

    case Repo.insert(changeset) do
      {:ok, schedule} ->
        # Schedule the first job
        schedule_next_job(schedule)
        {:ok, schedule}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Updates a scheduled report.
  """
  def update_schedule(id, opts) do
    case get_scheduled_report(id) do
      nil ->
        {:error, :not_found}

      schedule ->
        attrs =
          Map.take(opts, [:name, :template_id, :schedule, :recipients, :format, :params, :enabled])
          |> Enum.into(%{})
          |> maybe_update_schedule_timing(opts[:schedule])

        changeset = ScheduledReport.changeset(schedule, attrs)

        case Repo.update(changeset) do
          {:ok, updated} ->
            # Reschedule if timing changed
            if opts[:schedule] do
              cancel_pending_jobs(updated.id)
              schedule_next_job(updated)
            end

            {:ok, updated}

          {:error, changeset} ->
            {:error, changeset}
        end
    end
  end

  @doc """
  Deletes a scheduled report.
  """
  def delete_schedule(id) do
    case get_scheduled_report(id) do
      nil ->
        {:error, :not_found}

      schedule ->
        cancel_pending_jobs(id)
        Repo.delete(schedule)
    end
  end

  @doc """
  Lists all scheduled reports.
  """
  def list_schedules(opts \\ []) do
    query = from(s in ScheduledReport, order_by: [asc: s.name])

    query =
      if org_id = opts[:organization_id] do
        where(query, [s], s.organization_id == ^org_id)
      else
        query
      end

    query =
      if opts[:enabled_only] do
        where(query, [s], s.enabled == true)
      else
        query
      end

    Repo.all(query)
  end

  @doc """
  Gets a scheduled report by ID.
  """
  def get_scheduled_report(id) do
    Repo.get(ScheduledReport, id)
  end

  @doc """
  Manually triggers a scheduled report to run now.
  """
  def run_now(id) do
    case get_scheduled_report(id) do
      nil ->
        {:error, :not_found}

      schedule ->
        execute_scheduled_report(schedule)
    end
  end

  @doc """
  Gets execution history for a scheduled report.
  """
  def get_history(schedule_id, limit \\ 20) do
    query =
      from(r in TamanduaServer.Reports.Report,
        where: r.schedule_id == ^schedule_id,
        order_by: [desc: r.inserted_at],
        limit: ^limit
      )

    Repo.all(query)
  end

  @doc """
  Pauses a scheduled report.
  """
  def pause_schedule(id) do
    update_schedule(id, %{enabled: false})
  end

  @doc """
  Resumes a paused scheduled report.
  """
  def resume_schedule(id) do
    case get_scheduled_report(id) do
      nil ->
        {:error, :not_found}

      _schedule ->
        with {:ok, updated} <- update_schedule(id, %{enabled: true}) do
          schedule_next_job(updated)
          {:ok, updated}
        end
    end
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp execute_scheduled_report(schedule) do
    Logger.info("Executing scheduled report: #{schedule.name} (#{schedule.template_id})")

    # Calculate date range based on schedule frequency
    {date_from, date_to} = calculate_date_range(schedule.schedule)

    # Generate the report
    opts = [
      date_from: date_from,
      date_to: date_to,
      format: String.to_atom(schedule.format),
      params: schedule.params
    ]

    case Engine.generate(schedule.template_id, opts) do
      {:ok, report} ->
        # Update last run time
        update_last_run(schedule)

        # Send email if recipients configured
        if length(schedule.recipients) > 0 do
          Engine.email_report(report.data, schedule.recipients,
            subject: "[Tamandua EDR] #{schedule.name}",
            format: String.to_atom(schedule.format)
          )
        end

        # Schedule next run
        schedule_next_job(schedule)

        Logger.info("Scheduled report #{schedule.name} completed successfully")
        :ok

      {:error, reason} ->
        Logger.error("Scheduled report #{schedule.name} failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  # 6 AM daily
  defp normalize_schedule("daily"), do: "0 6 * * *"
  # 6 AM Monday
  defp normalize_schedule("weekly"), do: "0 6 * * 1"
  # 6 AM first of month
  defp normalize_schedule("monthly"), do: "0 6 1 * *"
  defp normalize_schedule(cron) when is_binary(cron), do: cron
  # Default to weekly
  defp normalize_schedule(_), do: "0 6 * * 1"

  defp calculate_next_run(schedule) do
    cron = normalize_schedule(schedule)

    case Crontab.CronExpression.Parser.parse(cron) do
      {:ok, cron_expr} ->
        Crontab.Scheduler.get_next_run_date(cron_expr, DateTime.utc_now())
        |> case do
          {:ok, next} -> next
          # Default to tomorrow
          _ -> DateTime.add(DateTime.utc_now(), 86400, :second)
        end

      _ ->
        # Default to tomorrow
        DateTime.add(DateTime.utc_now(), 86400, :second)
    end
  end

  defp calculate_date_range(schedule) do
    today = Date.utc_today()
    to = Date.to_iso8601(today)

    from =
      case schedule do
        s when s in ["0 6 * * *", "daily"] ->
          Date.add(today, -1) |> Date.to_iso8601()

        s when s in ["0 6 * * 1", "weekly"] ->
          Date.add(today, -7) |> Date.to_iso8601()

        s when s in ["0 6 1 * *", "monthly"] ->
          Date.add(today, -30) |> Date.to_iso8601()

        _ ->
          # Default to last 7 days
          Date.add(today, -7) |> Date.to_iso8601()
      end

    {from, to}
  end

  defp schedule_next_job(schedule) do
    next_run = calculate_next_run(schedule.schedule)

    # Calculate delay in seconds
    delay = DateTime.diff(next_run, DateTime.utc_now())
    # At least 1 minute
    delay = max(delay, 60)

    %{scheduled_report_id: schedule.id}
    |> __MODULE__.new(schedule_in: delay)
    |> Oban.insert()

    # Update next_run_at
    schedule
    |> ScheduledReport.changeset(%{next_run_at: next_run})
    |> Repo.update()

    Logger.info("Scheduled next run for #{schedule.name} at #{next_run}")
  end

  defp cancel_pending_jobs(schedule_id) do
    # Cancel any pending Oban jobs for this schedule
    Oban.Job
    |> where([j], j.worker == "TamanduaServer.Reports.Scheduler")
    |> where([j], j.state in ["available", "scheduled"])
    |> where([j], fragment("?->>'scheduled_report_id' = ?", j.args, ^to_string(schedule_id)))
    |> Repo.delete_all()
  end

  defp update_last_run(schedule) do
    schedule
    |> ScheduledReport.changeset(%{last_run_at: DateTime.utc_now()})
    |> Repo.update()
  end

  defp maybe_update_schedule_timing(attrs, nil), do: attrs

  defp maybe_update_schedule_timing(attrs, schedule) do
    Map.merge(attrs, %{
      schedule: normalize_schedule(schedule),
      next_run_at: calculate_next_run(schedule)
    })
  end
end
