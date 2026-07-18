defmodule TamanduaServer.Hunting.QueryScheduler do
  @moduledoc """
  GenServer for scheduling and executing saved queries automatically.
  Handles notifications and result history tracking.
  """
  use GenServer
  require Logger

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Hunting.{
    QuerySchedule,
    QueryResultHistory
  }
  alias TamanduaServer.Hunting.SavedQueries
  alias TamanduaServer.Notifications

  @check_interval :timer.minutes(1)

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Creates a new scheduled query.
  """
  def create_schedule(attrs) do
    %QuerySchedule{}
    |> QuerySchedule.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a scheduled query.
  """
  def update_schedule(%QuerySchedule{} = schedule, attrs) do
    schedule
    |> QuerySchedule.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a scheduled query.
  """
  def delete_schedule(%QuerySchedule{} = schedule) do
    Repo.delete(schedule)
  end

  @doc """
  Lists all schedules for a user.
  """
  def list_schedules(user_id) do
    from(s in QuerySchedule,
      where: s.user_id == ^user_id,
      order_by: [desc: s.inserted_at],
      preload: [:saved_query]
    )
    |> Repo.all()
  end

  @doc """
  Gets a schedule by ID.
  """
  def get_schedule(id) do
    QuerySchedule
    |> Repo.get(id)
    |> Repo.preload([:saved_query, :parameter_values])
  end

  @doc """
  Manually executes a scheduled query.
  """
  def execute_now(schedule_id) do
    GenServer.call(__MODULE__, {:execute_now, schedule_id}, :timer.minutes(5))
  end

  @doc """
  Lists execution history for a schedule.
  """
  def list_execution_history(schedule_id, limit \\ 50) do
    from(h in QueryResultHistory,
      where: h.query_schedule_id == ^schedule_id,
      order_by: [desc: h.inserted_at],
      limit: ^limit
    )
    |> Repo.all()
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Schedule periodic check
    schedule_check()
    Logger.info("Query scheduler started")
    {:ok, %{}}
  end

  @impl true
  def handle_info(:check_schedules, state) do
    execute_due_schedules()
    schedule_check()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def handle_call({:execute_now, schedule_id}, _from, state) do
    result =
      case get_schedule(schedule_id) do
        nil ->
          {:error, :not_found}

        schedule ->
          execute_schedule(schedule)
      end

    {:reply, result, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp schedule_check do
    Process.send_after(self(), :check_schedules, @check_interval)
  end

  defp execute_due_schedules do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    schedules =
      from(s in QuerySchedule,
        where: s.enabled == true and s.next_execution_at <= ^now,
        preload: [:saved_query, :parameter_values, :user]
      )
      |> Repo.all()

    Enum.each(schedules, &execute_schedule/1)
  end

  defp execute_schedule(%QuerySchedule{} = schedule) do
    Logger.info("Executing scheduled query: #{schedule.id}")
    start_time = System.monotonic_time(:millisecond)

    try do
      # Build query with parameters
      query_text = apply_parameters(schedule.saved_query.query, schedule.parameter_values)

      # Execute query
      result =
        SavedQueries.execute_query(query_text,
          user_id: schedule.user_id,
          organization_id: schedule.organization_id
        )

      execution_time = System.monotonic_time(:millisecond) - start_time

      case result do
        {:ok, %{data: data}} ->
          result_count = length(data)
          handle_successful_execution(schedule, query_text, result_count, execution_time, data)

        {:error, reason} ->
          handle_failed_execution(schedule, query_text, reason, execution_time)
      end
    rescue
      error ->
        execution_time = System.monotonic_time(:millisecond) - start_time
        error_msg = Exception.message(error)
        Logger.error("Query execution failed: #{error_msg}")
        handle_failed_execution(schedule, schedule.saved_query.query, error_msg, execution_time)
    end
  end

  defp apply_parameters(query_text, parameter_values) do
    Enum.reduce(parameter_values, query_text, fn param, acc ->
      String.replace(acc, "{#{param.parameter_name}}", param.parameter_value)
    end)
  end

  defp handle_successful_execution(schedule, query_text, result_count, execution_time, data) do
    # Update schedule
    schedule
    |> QuerySchedule.mark_executed_changeset(result_count, "success")
    |> Repo.update()

    # Save result history
    save_result_history(schedule, query_text, result_count, execution_time, "success", data)

    # Check if alert should be sent
    if should_alert?(schedule, result_count) do
      send_alerts(schedule, result_count, data)
    end

    {:ok, result_count}
  end

  defp handle_failed_execution(schedule, query_text, error_reason, execution_time) do
    error_msg = if is_binary(error_reason), do: error_reason, else: inspect(error_reason)

    # Update schedule
    schedule
    |> QuerySchedule.mark_executed_changeset(0, "error", error_msg)
    |> Repo.update()

    # Save result history
    save_result_history(schedule, query_text, 0, execution_time, "error", nil, error_msg)

    {:error, error_reason}
  end

  defp save_result_history(
         schedule,
         query_text,
         result_count,
         execution_time,
         status,
         data \\ nil,
         error_msg \\ nil
       ) do
    summary =
      if data do
        %{
          total_results: result_count,
          sample_results: Enum.take(data, 10)
        }
      else
        nil
      end

    %QueryResultHistory{}
    |> QueryResultHistory.changeset(%{
      query_schedule_id: schedule.id,
      saved_query_id: schedule.saved_query_id,
      user_id: schedule.user_id,
      query_text: query_text,
      result_count: result_count,
      execution_time_ms: execution_time,
      status: status,
      error_message: error_msg,
      results_summary: summary
    })
    |> Repo.insert()
  end

  defp should_alert?(schedule, result_count) do
    schedule.alert_on_results and
      (is_nil(schedule.result_threshold) or result_count > schedule.result_threshold)
  end

  defp send_alerts(schedule, result_count, data) do
    alert_message = build_alert_message(schedule, result_count, data)

    Enum.each(schedule.alert_channels, fn channel ->
      send_alert_by_channel(channel, schedule, alert_message)
    end)
  end

  defp build_alert_message(schedule, result_count, data) do
    sample_results = Enum.take(data, 5)

    """
    Scheduled Query Alert: #{schedule.saved_query.name}

    Results: #{result_count} matches found
    Threshold: #{schedule.result_threshold || "N/A"}
    Time: #{DateTime.utc_now() |> DateTime.to_string()}

    Query: #{schedule.saved_query.query}

    Sample Results:
    #{inspect(sample_results, pretty: true)}
    """
  end

  defp send_alert_by_channel("email", schedule, message) do
    Enum.each(schedule.notification_emails, fn email ->
      try do
        Notifications.send_email(
          to: email,
          subject: "Query Alert: #{schedule.saved_query.name}",
          body: message
        )
      rescue
        error ->
          Logger.error("Failed to send email alert: #{Exception.message(error)}")
      end
    end)
  end

  defp send_alert_by_channel("slack", schedule, message) do
    Enum.each(schedule.notification_slack_channels, fn channel ->
      try do
        Notifications.send_slack_notification(
          channel: channel,
          message: message
        )
      rescue
        error ->
          Logger.error("Failed to send Slack alert: #{Exception.message(error)}")
      end
    end)
  end

  defp send_alert_by_channel("webhook", schedule, message) do
    Enum.each(schedule.notification_webhook_urls, fn url ->
      try do
        HTTPoison.post(url, Jason.encode!(%{message: message}), [
          {"Content-Type", "application/json"}
        ])
      rescue
        error ->
          Logger.error("Failed to send webhook alert: #{Exception.message(error)}")
      end
    end)
  end

  defp send_alert_by_channel(_unknown, _schedule, _message), do: :ok
end
