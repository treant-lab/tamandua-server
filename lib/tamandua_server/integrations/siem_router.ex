defmodule TamanduaServer.Integrations.SIEMRouter do
  @moduledoc """
  Unified router for dispatching alerts to configured SIEM integrations.

  Supports parallel dispatch to multiple SIEMs (Splunk, Sentinel, Elastic, etc.)
  with configurable batching and priority routing.

  ## Features

  - `route_alert/2` - Send a single alert to all enabled SIEMs
  - `route_batch/2` - Batch send multiple alerts
  - `queue_for_batch/1` - Add alert to batch queue (for low-priority alerts)
  - `get_enabled_siem_integrations/0` - List enabled SIEMs with health status
  - `config/0` - Get current SIEM configuration

  ## Routing Logic

  - **Critical/High severity** - Sent immediately to all enabled SIEMs
  - **Medium/Low/Info severity** - Batched and sent every 5 seconds

  ## Configuration

      config :tamandua_server, :siem_integrations, %{
        splunk: %{
          enabled: true,
          hec_url: "https://splunk.example.com:8088",
          hec_token: "your-hec-token",
          index: "tamandua"
        },
        sentinel: %{
          enabled: true,
          workspace_id: "your-workspace-id",
          shared_key: "your-shared-key"
        }
      }
  """

  use GenServer
  require Logger

  alias TamanduaServer.Integrations.SIEM.{SplunkHEC, Config}
  alias TamanduaServer.Integrations.SIEM.SentinelConnector

  @batch_interval_ms 5_000
  @batch_size 100
  @high_priority_severities ["critical", "high"]

  # SIEM module mapping
  @siem_modules %{
    splunk: SplunkHEC,
    sentinel: SentinelConnector
  }

  defstruct [
    :batch_queue,
    :batch_timer_ref,
    :stats
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Route a single alert to all enabled SIEM integrations.

  ## Parameters

  - `alert` - Alert map with id, title, severity, hostname, etc.
  - `opts` - Optional:
    - `:priority` - :immediate or :batch (default based on severity)
    - `:siems` - List of specific SIEMs to send to (default: all enabled)

  ## Returns

  `{:ok, results}` list of {siem, result} tuples, `{:error, reason}` on failure.
  """
  @spec route_alert(map(), keyword()) :: {:ok, [tuple()]} | {:error, term()}
  def route_alert(alert, opts \\ []) do
    GenServer.call(__MODULE__, {:route_alert, alert, opts}, 60_000)
  catch
    :exit, {:noproc, _} ->
      # GenServer not started, send directly
      do_route_alert(alert, opts)
  end

  @doc """
  Route multiple alerts as a batch to all enabled SIEMs.

  ## Parameters

  - `alerts` - List of alert maps
  - `opts` - Optional configuration

  ## Returns

  `{:ok, results}` with dispatch results, `{:error, reason}` on failure.
  """
  @spec route_batch([map()], keyword()) :: {:ok, [tuple()]} | {:error, term()}
  def route_batch(alerts, opts \\ []) when is_list(alerts) do
    GenServer.call(__MODULE__, {:route_batch, alerts, opts}, 120_000)
  catch
    :exit, {:noproc, _} ->
      do_route_batch(alerts, opts)
  end

  @doc """
  Queue an alert for batched sending.

  Low-priority alerts are queued and sent in batches every 5 seconds.

  ## Parameters

  - `alert` - Alert map to queue

  ## Returns

  `:ok`
  """
  @spec queue_for_batch(map()) :: :ok
  def queue_for_batch(alert) do
    GenServer.cast(__MODULE__, {:queue_alert, alert})
  catch
    :exit, {:noproc, _} -> :ok
  end

  @doc """
  Get list of enabled SIEM integrations with their status.

  ## Returns

  List of maps with :type, :enabled, :health_status.
  """
  @spec get_enabled_siem_integrations() :: [map()]
  def get_enabled_siem_integrations do
    Config.list_all()
    |> Enum.filter(& &1.enabled)
  end

  @doc """
  Get current SIEM configuration.

  ## Returns

  Map of SIEM configurations.
  """
  @spec config() :: map()
  def config do
    Application.get_env(:tamandua_server, :siem_integrations, %{})
  end

  @doc """
  Get routing statistics.

  ## Returns

  Map with alerts_routed, batches_sent, errors, by_siem counts.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  catch
    :exit, {:noproc, _} ->
      %{alerts_routed: 0, batches_sent: 0, errors: 0, by_siem: %{}}
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("[SIEMRouter] Starting SIEM router")

    state = %__MODULE__{
      batch_queue: [],
      batch_timer_ref: nil,
      stats: %{
        alerts_routed: 0,
        batches_sent: 0,
        errors: 0,
        by_siem: %{},
        last_activity: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:route_alert, alert, opts}, _from, state) do
    {results, new_stats} = do_route_alert_with_stats(alert, opts, state.stats)
    {:reply, {:ok, results}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:route_batch, alerts, opts}, _from, state) do
    {results, new_stats} = do_route_batch_with_stats(alerts, opts, state.stats)
    {:reply, {:ok, results}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_cast({:queue_alert, alert}, state) do
    new_queue = [alert | state.batch_queue]

    # Start batch timer if not running
    timer_ref = if state.batch_timer_ref do
      state.batch_timer_ref
    else
      Process.send_after(self(), :flush_batch, @batch_interval_ms)
    end

    # Flush if queue is full
    if length(new_queue) >= @batch_size do
      send(self(), :flush_batch)
    end

    {:noreply, %{state | batch_queue: new_queue, batch_timer_ref: timer_ref}}
  end

  @impl true
  def handle_info(:flush_batch, state) do
    if length(state.batch_queue) > 0 do
      {_results, new_stats} = do_route_batch_with_stats(state.batch_queue, [], state.stats)
      {:noreply, %{state | batch_queue: [], batch_timer_ref: nil, stats: new_stats}}
    else
      {:noreply, %{state | batch_timer_ref: nil}}
    end
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp do_route_alert(alert, opts) do
    enabled_siems = get_target_siems(opts)

    if length(enabled_siems) == 0 do
      {:ok, []}
    else
      results = enabled_siems
      |> Task.async_stream(fn {siem_type, siem_config} ->
        result = send_to_siem(siem_type, alert, siem_config)
        {siem_type, result}
      end, timeout: 30_000, on_timeout: :kill_task)
      |> Enum.map(fn
        {:ok, result} -> result
        {:exit, reason} -> {:unknown, {:error, reason}}
      end)

      {:ok, results}
    end
  end

  defp do_route_alert_with_stats(alert, opts, stats) do
    enabled_siems = get_target_siems(opts)

    if length(enabled_siems) == 0 do
      {[], stats}
    else
      results = enabled_siems
      |> Task.async_stream(fn {siem_type, siem_config} ->
        result = send_to_siem(siem_type, alert, siem_config)
        {siem_type, result}
      end, timeout: 30_000, on_timeout: :kill_task)
      |> Enum.map(fn
        {:ok, result} -> result
        {:exit, reason} -> {:unknown, {:error, reason}}
      end)

      new_stats = update_stats(stats, results, 1)
      {results, new_stats}
    end
  end

  defp do_route_batch(alerts, opts) do
    enabled_siems = get_target_siems(opts)

    if length(enabled_siems) == 0 do
      {:ok, []}
    else
      results = enabled_siems
      |> Task.async_stream(fn {siem_type, siem_config} ->
        result = send_batch_to_siem(siem_type, alerts, siem_config)
        {siem_type, result}
      end, timeout: 60_000, on_timeout: :kill_task)
      |> Enum.map(fn
        {:ok, result} -> result
        {:exit, reason} -> {:unknown, {:error, reason}}
      end)

      {:ok, results}
    end
  end

  defp do_route_batch_with_stats(alerts, opts, stats) do
    enabled_siems = get_target_siems(opts)

    if length(enabled_siems) == 0 do
      {[], stats}
    else
      results = enabled_siems
      |> Task.async_stream(fn {siem_type, siem_config} ->
        result = send_batch_to_siem(siem_type, alerts, siem_config)
        {siem_type, result}
      end, timeout: 60_000, on_timeout: :kill_task)
      |> Enum.map(fn
        {:ok, result} -> result
        {:exit, reason} -> {:unknown, {:error, reason}}
      end)

      new_stats = stats
      |> update_stats(results, length(alerts))
      |> Map.update(:batches_sent, 1, &(&1 + 1))

      {results, new_stats}
    end
  end

  defp get_target_siems(opts) do
    all_config = config()
    requested_siems = Keyword.get(opts, :siems)

    all_config
    |> Enum.filter(fn {siem_type, siem_config} ->
      siem_config[:enabled] == true &&
      (is_nil(requested_siems) || siem_type in requested_siems)
    end)
  end

  defp send_to_siem(:splunk, alert, siem_config) do
    Logger.debug("[SIEMRouter] Sending alert to Splunk: #{alert[:id]}")
    SplunkHEC.send_alert(alert, siem_config)
  end

  defp send_to_siem(:sentinel, alert, siem_config) do
    Logger.debug("[SIEMRouter] Sending alert to Sentinel: #{alert[:id]}")
    SentinelConnector.send_alert(alert, siem_config)
  end

  defp send_to_siem(:elastic, alert, siem_config) do
    Logger.debug("[SIEMRouter] Sending alert to Elastic: #{alert[:id]}")
    # Elastic integration placeholder
    if function_exported?(TamanduaServer.Integrations.Elastic, :send_alert, 2) do
      TamanduaServer.Integrations.Elastic.send_alert(alert, siem_config)
    else
      {:error, :not_implemented}
    end
  end

  defp send_to_siem(:qradar, alert, siem_config) do
    Logger.debug("[SIEMRouter] Sending alert to QRadar: #{alert[:id]}")
    # QRadar integration placeholder
    if function_exported?(TamanduaServer.Integrations.SIEM.QRadar, :send_alert, 2) do
      TamanduaServer.Integrations.SIEM.QRadar.send_alert(alert, siem_config)
    else
      {:error, :not_implemented}
    end
  end

  defp send_to_siem(siem_type, _alert, _config) do
    Logger.warning("[SIEMRouter] Unknown SIEM type: #{siem_type}")
    {:error, :unknown_siem_type}
  end

  defp send_batch_to_siem(:splunk, alerts, siem_config) do
    Logger.debug("[SIEMRouter] Sending #{length(alerts)} alerts to Splunk")
    SplunkHEC.send_batch(alerts, siem_config)
  end

  defp send_batch_to_siem(:sentinel, alerts, siem_config) do
    Logger.debug("[SIEMRouter] Sending #{length(alerts)} alerts to Sentinel")
    SentinelConnector.send_batch(alerts, siem_config)
  end

  defp send_batch_to_siem(siem_type, alerts, siem_config) do
    # Fall back to individual sends for SIEMs without batch support
    results = Enum.map(alerts, fn alert ->
      send_to_siem(siem_type, alert, siem_config)
    end)

    errors = Enum.filter(results, &match?({:error, _}, &1))
    if length(errors) > 0 do
      {:error, {:partial_failure, length(errors), length(alerts)}}
    else
      :ok
    end
  end

  defp update_stats(stats, results, alert_count) do
    {successes, failures} = Enum.split_with(results, fn
      {_, :ok} -> true
      {_, {:ok, _}} -> true
      _ -> false
    end)

    by_siem = Enum.reduce(results, stats.by_siem, fn {siem_type, result}, acc ->
      current = Map.get(acc, siem_type, %{success: 0, failure: 0})
      updated = case result do
        :ok -> %{current | success: current.success + alert_count}
        {:ok, _} -> %{current | success: current.success + alert_count}
        _ -> %{current | failure: current.failure + alert_count}
      end
      Map.put(acc, siem_type, updated)
    end)

    %{stats |
      alerts_routed: stats.alerts_routed + alert_count,
      errors: stats.errors + length(failures),
      by_siem: by_siem,
      last_activity: DateTime.utc_now()
    }
  end

  @doc """
  Determine if an alert should be sent immediately based on severity.

  ## Parameters

  - `alert` - Alert map with :severity field

  ## Returns

  Boolean indicating if alert should be sent immediately.
  """
  @spec high_priority?(map()) :: boolean()
  def high_priority?(alert) do
    severity = alert[:severity] || alert["severity"] || ""
    String.downcase(to_string(severity)) in @high_priority_severities
  end
end
