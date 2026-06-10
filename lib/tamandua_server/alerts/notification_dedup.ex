defmodule TamanduaServer.Alerts.NotificationDedup do
  @moduledoc """
  Notification deduplication to prevent spam.

  Tracks recently sent notifications and prevents re-sending notifications
  for the same alert within a configurable window (default: 15 minutes).

  Also implements alert storm detection - if too many alerts are sent
  in a short time, switches to digest mode.
  """

  use GenServer
  require Logger

  # Default dedup window: 15 minutes
  @default_dedup_window_minutes 15

  # Alert storm threshold: >10 alerts in 5 minutes
  @storm_threshold 10
  @storm_window_minutes 5

  # Client API
  # ===========================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Check if an alert notification was recently sent.

  Returns:
  - `:not_duplicate` - Alert not seen recently, safe to send
  - `{:duplicate, last_sent_at}` - Alert was sent recently, skip
  """
  def check_recent(alert) do
    GenServer.call(__MODULE__, {:check_recent, alert})
  end

  @doc """
  Record that a notification was sent for an alert.
  """
  def record_notification(alert) do
    GenServer.cast(__MODULE__, {:record, alert})
  end

  @doc """
  Check if we're in an alert storm condition.

  Returns:
  - `:normal` - Normal operation
  - `{:storm, count}` - Alert storm detected, count is number of alerts in window
  """
  def check_storm do
    GenServer.call(__MODULE__, :check_storm)
  end

  @doc """
  Get deduplication statistics.
  """
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Clear all deduplication state (useful for testing).
  """
  def clear do
    GenServer.cast(__MODULE__, :clear)
  end

  # Server Callbacks
  # ===========================================================================

  @impl true
  def init(_opts) do
    # Create ETS table to track sent notifications
    :ets.new(:notification_dedup, [:set, :named_table, :public, read_concurrency: true])

    # Create ETS table to track alert rate for storm detection
    :ets.new(:notification_rate, [:ordered_set, :named_table, :public])

    # Schedule cleanup every 5 minutes
    schedule_cleanup()

    {:ok, %{
      dedup_window_minutes: Application.get_env(:tamandua_server, :notification_dedup_minutes, @default_dedup_window_minutes),
      storm_threshold: @storm_threshold,
      storm_window_minutes: @storm_window_minutes
    }}
  end

  @impl true
  def handle_call({:check_recent, alert}, _from, state) do
    alert_id = extract_alert_id(alert)
    now = System.system_time(:second)
    cutoff = now - (state.dedup_window_minutes * 60)

    case :ets.lookup(:notification_dedup, alert_id) do
      [{^alert_id, last_sent}] when last_sent > cutoff ->
        {:reply, {:duplicate, timestamp_to_datetime(last_sent)}, state}

      _ ->
        {:reply, :not_duplicate, state}
    end
  end

  @impl true
  def handle_call(:check_storm, _from, state) do
    now = System.system_time(:second)
    cutoff = now - (state.storm_window_minutes * 60)

    # Count notifications in the storm window
    count = :ets.select_count(:notification_rate, [
      {{:"$1", :"$2"}, [{:>, :"$1", cutoff}], [true]}
    ])

    result = if count >= state.storm_threshold do
      {:storm, count}
    else
      :normal
    end

    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    total_tracked = :ets.info(:notification_dedup, :size)
    rate_entries = :ets.info(:notification_rate, :size)

    now = System.system_time(:second)
    recent_cutoff = now - 300  # Last 5 minutes

    recent_count = :ets.select_count(:notification_rate, [
      {{:"$1", :"$2"}, [{:>, :"$1", recent_cutoff}], [true]}
    ])

    stats = %{
      total_tracked: total_tracked,
      recent_notifications: recent_count,
      rate_entries: rate_entries,
      dedup_window_minutes: state.dedup_window_minutes,
      storm_threshold: state.storm_threshold
    }

    {:reply, stats, state}
  end

  @impl true
  def handle_cast({:record, alert}, state) do
    alert_id = extract_alert_id(alert)
    now = System.system_time(:second)

    # Record in dedup table
    :ets.insert(:notification_dedup, {alert_id, now})

    # Record in rate table for storm detection
    :ets.insert(:notification_rate, {now, alert_id})

    {:noreply, state}
  end

  @impl true
  def handle_cast(:clear, state) do
    :ets.delete_all_objects(:notification_dedup)
    :ets.delete_all_objects(:notification_rate)
    Logger.info("[NotificationDedup] Cleared all dedup state")
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    perform_cleanup(state)
    schedule_cleanup()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # Private Helpers
  # ===========================================================================

  defp extract_alert_id(%{id: id}), do: id
  defp extract_alert_id(alert) when is_map(alert) do
    alert[:id] || alert["id"] || "unknown"
  end

  defp timestamp_to_datetime(unix_seconds) do
    DateTime.from_unix!(unix_seconds)
  end

  defp perform_cleanup(state) do
    now = System.system_time(:second)
    dedup_cutoff = now - (state.dedup_window_minutes * 60)
    rate_cutoff = now - (state.storm_window_minutes * 60)

    # Clean up old dedup entries
    dedup_spec = [
      {{:"$1", :"$2"}, [{:<, :"$2", dedup_cutoff}], [true]}
    ]
    dedup_deleted = :ets.select_delete(:notification_dedup, dedup_spec)

    # Clean up old rate entries
    rate_spec = [
      {{:"$1", :"$2"}, [{:<, :"$1", rate_cutoff}], [true]}
    ]
    rate_deleted = :ets.select_delete(:notification_rate, rate_spec)

    if dedup_deleted + rate_deleted > 0 do
      Logger.debug(
        "[NotificationDedup] Cleanup: removed #{dedup_deleted} dedup entries, " <>
        "#{rate_deleted} rate entries"
      )
    end
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, 5 * 60 * 1000)  # 5 minutes
  end
end
