defmodule TamanduaServer.Workers.ReportWorker do
  @moduledoc """
  Oban worker for scheduled report generation and delivery.

  Handles:
  - Scheduled report generation
  - Multiple delivery methods (email, S3, SFTP, webhook)
  - Retry logic for failed deliveries
  - Report archival
  """

  use Oban.Worker,
    queue: :reports,
    max_attempts: 3,
    unique: [period: 300]

  require Logger

  alias TamanduaServer.Reports.{Engine, Scheduler, Delivery, TemplateManager}

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"type" => "scheduled_report", "scheduled_report_id" => id}}) do
    Logger.info("Executing scheduled report job for schedule ID: #{id}")

    case Scheduler.get_scheduled_report(id) do
      nil ->
        Logger.warning("Scheduled report #{id} not found")
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
  def perform(%Oban.Job{args: %{"type" => "generate_and_deliver", "template_id" => template_id} = args}) do
    Logger.info("Generating and delivering report for template: #{template_id}")

    date_from = args["date_from"]
    date_to = args["date_to"]
    format = safe_report_atom(args["format"] || "pdf", :pdf)
    delivery_methods = args["delivery_methods"] || [%{"method" => "email"}]

    # Generate report
    case generate_report(template_id, date_from, date_to, format, args) do
      {:ok, report_data, content} ->
        # Deliver via all configured methods
        results = Enum.map(delivery_methods, fn method_config ->
          deliver_report(report_data, content, method_config)
        end)

        # Check if any delivery succeeded
        if Enum.any?(results, fn {status, _} -> status == :ok end) do
          {:ok, %{delivered: length(results)}}
        else
          {:error, :all_deliveries_failed}
        end

      {:error, reason} ->
        Logger.error("Report generation failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @impl Oban.Worker
  def perform(%Oban.Job{args: args}) do
    Logger.warning("Unknown report worker job type: #{inspect(args)}")
    :ok
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  # Convert untrusted (Oban args / DB) strings to atoms WITHOUT growing the
  # global atom table. Valid report formats (:pdf/:html/:csv/:json) and
  # delivery methods (:email/:s3/:sftp) already exist as compile-time literals,
  # so they resolve via to_existing_atom; unknown values fall back to `default`.
  defp safe_report_atom(value, _default) when is_atom(value), do: value

  defp safe_report_atom(value, default) when is_binary(value) do
    String.to_existing_atom(value)
  rescue
    ArgumentError -> default
  end

  defp safe_report_atom(_value, default), do: default

  defp execute_scheduled_report(schedule) do
    {date_from, date_to} = calculate_date_range(schedule.schedule)
    format = safe_report_atom(schedule.format, :pdf)

    case generate_report(schedule.template_id, date_from, date_to, format, %{}) do
      {:ok, report_data, content} ->
        # Update last run time
        Scheduler.update_schedule(schedule.id, %{last_run_at: DateTime.utc_now()})

        # Email delivery if recipients configured
        if length(schedule.recipients) > 0 do
          delivery_config = %{
            "method" => "email",
            "recipients" => schedule.recipients,
            "format" => schedule.format,
            "subject" => "[Tamandua EDR] #{schedule.name}"
          }

          deliver_report(report_data, content, delivery_config)
        end

        # Schedule next run
        schedule_next_run(schedule)

        Logger.info("Scheduled report #{schedule.name} completed successfully")
        :ok

      {:error, reason} ->
        Logger.error("Scheduled report #{schedule.name} failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp generate_report(template_id, date_from, date_to, format, params) do
    # Check if it's a custom template or built-in template
    case TemplateManager.get_template(template_id) do
      {:ok, custom_template} ->
        # Generate from custom template
        case TemplateManager.generate_from_template(template_id, date_from, date_to, []) do
          {:ok, report_data} ->
            # Convert to requested format
            case Engine.convert_to_format(report_data, format) do
              {:ok, content} -> {:ok, report_data, content}
              error -> error
            end

          error -> error
        end

      {:error, :not_found} ->
        # Try built-in template
        case Engine.generate(template_id, [
          date_from: date_from,
          date_to: date_to,
          format: format,
          params: params
        ]) do
          {:ok, result} ->
            {:ok, result.data, result.content}

          error -> error
        end
    end
  end

  defp deliver_report(report_data, content, delivery_config) do
    method = safe_report_atom(delivery_config["method"] || "email", :email)

    opts = [
      method: method,
      recipients: delivery_config["recipients"],
      format: safe_report_atom(delivery_config["format"] || "pdf", :pdf),
      subject: delivery_config["subject"],
      bucket: delivery_config["bucket"],
      s3_path: delivery_config["s3_path"],
      sftp_host: delivery_config["sftp_host"],
      sftp_path: delivery_config["sftp_path"],
      sftp_username: delivery_config["sftp_username"],
      sftp_password: delivery_config["sftp_password"],
      webhook_url: delivery_config["webhook_url"],
      file_path: delivery_config["file_path"]
    ]

    case Delivery.deliver(report_data, content, opts) do
      {:ok, :delivered} ->
        Logger.info("Report delivered successfully via #{method}")
        {:ok, :delivered}

      {:error, reason} ->
        Logger.error("Report delivery failed via #{method}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp calculate_date_range(schedule) do
    today = Date.utc_today()
    to = Date.to_iso8601(today)

    from = case schedule do
      s when s in ["0 6 * * *", "daily"] ->
        Date.add(today, -1) |> Date.to_iso8601()

      s when s in ["0 6 * * 1", "weekly"] ->
        Date.add(today, -7) |> Date.to_iso8601()

      s when s in ["0 6 1 * *", "monthly"] ->
        Date.add(today, -30) |> Date.to_iso8601()

      _ ->
        Date.add(today, -7) |> Date.to_iso8601()
    end

    {from, to}
  end

  defp schedule_next_run(schedule) do
    # Calculate next run time
    case Crontab.CronExpression.Parser.parse(schedule.schedule) do
      {:ok, cron_expr} ->
        case Crontab.Scheduler.get_next_run_date(cron_expr, DateTime.utc_now()) do
          {:ok, next_run} ->
            delay = DateTime.diff(next_run, DateTime.utc_now())
            delay = max(delay, 60)  # At least 1 minute

            # Schedule next Oban job
            %{type: "scheduled_report", scheduled_report_id: schedule.id}
            |> __MODULE__.new(schedule_in: delay)
            |> Oban.insert()

            # Update schedule record
            Scheduler.update_schedule(schedule.id, %{next_run_at: next_run})

          _ ->
            Logger.warning("Failed to calculate next run for schedule #{schedule.id}")
        end

      _ ->
        Logger.warning("Invalid cron expression for schedule #{schedule.id}")
    end
  end
end
