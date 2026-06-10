defmodule TamanduaServer.Workers.ScheduledExportWorker do
  @moduledoc """
  Oban worker for scheduled alert exports.

  Runs periodically to check for scheduled export templates and trigger exports.
  Also handles cleanup of expired export files.
  """

  use Oban.Worker,
    queue: :scheduled,
    max_attempts: 1

  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.{Exporter, ExportTemplate}

  import Ecto.Query

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"action" => "run_scheduled_exports"}}) do
    Logger.info("[ScheduledExportWorker] Running scheduled exports")

    templates = list_due_templates()

    Enum.each(templates, &trigger_template_export/1)

    {:ok, %{triggered: length(templates)}}
  end

  def perform(%Oban.Job{args: %{"action" => "cleanup_expired_exports"}}) do
    Logger.info("[ScheduledExportWorker] Cleaning up expired exports")

    Exporter.cleanup_expired_exports()

    :ok
  end

  # ===========================================================================
  # Scheduled Export Triggers
  # ===========================================================================

  defp list_due_templates do
    now = DateTime.utc_now()

    ExportTemplate
    |> where([t], t.scheduled == true)
    |> where([t], not is_nil(t.schedule_cron))
    |> Repo.all()
    |> Enum.filter(&should_run_template?(&1, now))
  end

  defp should_run_template?(template, now) do
    case template.last_run_at do
      nil ->
        # Never run before, run now
        true

      last_run ->
        # Check if it's time to run based on cron expression
        case Crontab.CronExpression.Parser.parse(template.schedule_cron) do
          {:ok, cron_expr} ->
            # Check if cron matches current time
            next_run = Crontab.Scheduler.get_next_run_date(cron_expr, last_run)
            DateTime.compare(now, next_run) != :lt

          {:error, _} ->
            Logger.warning("[ScheduledExportWorker] Invalid cron expression for template #{template.id}")
            false
        end
    end
  end

  defp trigger_template_export(template) do
    Logger.info("[ScheduledExportWorker] Triggering export for template: #{template.name}")

    # Determine delivery config based on template
    delivery_config = build_delivery_config(template)

    # Create export job
    case Exporter.create_export(
           template.organization_id,
           template.created_by_id,
           format: template.format,
           filter_json: template.filter_json,
           columns: template.columns,
           delivery_method: template.delivery_method,
           delivery_config: delivery_config,
           template_id: template.id,
           triggered_by: "scheduled"
         ) do
      {:ok, _job} ->
        # Update template last_run_at
        Exporter.mark_template_run(template.id)
        Logger.info("[ScheduledExportWorker] Export job created for template #{template.name}")

      {:error, reason} ->
        Logger.error("[ScheduledExportWorker] Failed to create export job: #{inspect(reason)}")
    end
  end

  defp build_delivery_config(template) do
    # Extract delivery config from template
    case template.delivery_config do
      config when is_map(config) -> config
      _ -> %{}
    end
  end

  # ===========================================================================
  # Scheduling Helpers
  # ===========================================================================

  @doc """
  Schedules the recurring jobs.
  Should be called on application startup.
  """
  def schedule_recurring_jobs do
    # Run scheduled exports every hour
    %{action: "run_scheduled_exports"}
    |> new(schedule: "0 * * * *")  # Every hour
    |> Oban.insert()

    # Cleanup expired exports daily at 2 AM
    %{action: "cleanup_expired_exports"}
    |> new(schedule: "0 2 * * *")  # 2 AM daily
    |> Oban.insert()

    :ok
  end
end
