defmodule TamanduaServer.Notifications.Throttler do
  @moduledoc """
  Notification throttling engine.

  Tracks notification rates per integration and enforces throttle limits
  to prevent notification spam.

  Uses ETS for fast, in-memory rate limiting with sliding window.
  """

  use GenServer
  require Logger

  @table :notification_throttler
  @cleanup_interval :timer.minutes(5)

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Check if an integration is currently throttled.

  Returns true if the integration has exceeded its max notifications per hour.
  """
  def throttled?(%{id: integration_id, throttle_enabled: false}), do: false

  def throttled?(%{id: integration_id, throttle_enabled: true, throttle_max_per_hour: max}) do
    count = get_count(integration_id)
    count >= max
  end

  @doc """
  Record a notification sent for an integration.
  """
  def record(integration_id) do
    now = System.system_time(:second)

    try do
      :ets.insert(@table, {{integration_id, now}, 1})
      :ok
    rescue
      ArgumentError ->
        Logger.warning("[Throttler] ETS table not ready, skipping record")
        :ok
    end
  end

  @doc """
  Get the number of notifications sent in the last hour for an integration.
  """
  def get_count(integration_id) do
    cutoff = System.system_time(:second) - 3600  # 1 hour ago

    try do
      @table
      |> :ets.select([
        {{{:"$1", :"$2"}, :_}, [{:andalso, {:==, :"$1", integration_id}, {:>=, :"$2", cutoff}}], [true]}
      ])
      |> length()
    rescue
      ArgumentError ->
        Logger.warning("[Throttler] ETS table not ready, returning 0")
        0
    end
  end

  @doc """
  Get stats for an integration (for display in UI).
  """
  def get_stats(integration_id) do
    last_hour = get_count(integration_id)

    %{
      last_hour: last_hour,
      throttled: last_hour >= get_max(integration_id)
    }
  end

  defp get_max(integration_id) do
    # This would ideally query the integration record
    # For now, return a default
    60
  end

  # Server callbacks

  @impl true
  def init(_opts) do
    # Create ETS table
    :ets.new(@table, [:named_table, :public, :bag, read_concurrency: true])

    # Schedule periodic cleanup
    schedule_cleanup()

    Logger.info("[Throttler] Started notification throttler")
    {:ok, %{}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_old_entries()
    schedule_cleanup()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private helpers

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end

  defp cleanup_old_entries do
    cutoff = System.system_time(:second) - 7200  # 2 hours ago (keep extra for safety)

    try do
      # Delete entries older than cutoff
      :ets.select_delete(@table, [
        {{{:_, :"$1"}, :_}, [{:<, :"$1", cutoff}], [true]}
      ])

      Logger.debug("[Throttler] Cleaned up old entries (cutoff: #{cutoff})")
    rescue
      e ->
        Logger.error("[Throttler] Error during cleanup: #{inspect(e)}")
    end
  end
end
