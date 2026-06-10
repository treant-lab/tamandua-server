defmodule TamanduaServer.Integrations.SOAR.Executor do
  @moduledoc """
  SOAR Playbook Execution Engine

  Dispatches playbook executions to configured SOAR platforms and tracks their
  lifecycle through status transitions:

      pending -> running -> completed | failed

  ## Features

  - Real playbook execution trigger dispatching to the configured SOAR platform
  - Execution status tracking with ETS-backed state
  - Result collection and storage
  - Configurable retry logic for failed executions (exponential backoff)
  - Webhook callback handler for async execution results from SOAR platforms
  - Automatic execution timeout detection

  ## Usage

      # Trigger a playbook on the configured SOAR platform
      {:ok, execution_id} = Executor.trigger(platform, playbook_name, params)

      # Check status
      {:ok, status} = Executor.get_status(execution_id)

      # Handle a webhook callback from the SOAR platform
      :ok = Executor.handle_webhook_callback(execution_id, result_payload)
  """

  use GenServer
  require Logger

  alias TamanduaServer.Integrations.IntegrationLog

  @ets_table :soar_executions
  @max_retries 3
  @initial_retry_delay_ms 5_000
  @execution_timeout_ms 30 * 60 * 1_000  # 30 minutes
  @timeout_check_interval :timer.minutes(5)

  defstruct [
    :stats
  ]

  # Execution record structure stored in ETS
  # %{
  #   id: String.t(),
  #   platform: atom(),
  #   playbook_name: String.t(),
  #   params: map(),
  #   status: "pending" | "running" | "completed" | "failed" | "retrying",
  #   platform_run_id: String.t() | nil,
  #   result: map() | nil,
  #   error_message: String.t() | nil,
  #   retry_count: non_neg_integer(),
  #   started_at: DateTime.t(),
  #   updated_at: DateTime.t(),
  #   completed_at: DateTime.t() | nil
  # }

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Trigger a playbook execution on the specified SOAR platform.

  Returns `{:ok, execution_id}` on successful dispatch, or `{:error, reason}`.
  """
  @spec trigger(atom(), String.t(), map()) :: {:ok, String.t()} | {:error, term()}
  def trigger(platform, playbook_name, params \\ %{}) do
    GenServer.call(__MODULE__, {:trigger, platform, playbook_name, params}, 60_000)
  end

  @doc """
  Get the current status of an execution.

  Returns `{:ok, execution_map}` or `{:error, :not_found}`.
  """
  @spec get_status(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_status(execution_id) do
    case :ets.lookup(@ets_table, execution_id) do
      [{_id, execution}] -> {:ok, execution}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Handle an async webhook callback from a SOAR platform reporting execution results.

  The `payload` should include at minimum a `"status"` field and optionally
  `"result"` and `"error"` fields.
  """
  @spec handle_webhook_callback(String.t(), map()) :: :ok | {:error, :not_found}
  def handle_webhook_callback(execution_id, payload) do
    GenServer.call(__MODULE__, {:webhook_callback, execution_id, payload})
  end

  @doc """
  Manually retry a failed execution.
  """
  @spec retry(String.t()) :: {:ok, String.t()} | {:error, term()}
  def retry(execution_id) do
    GenServer.call(__MODULE__, {:retry, execution_id}, 60_000)
  end

  @doc """
  Cancel a running or pending execution.
  """
  @spec cancel(String.t()) :: :ok | {:error, term()}
  def cancel(execution_id) do
    GenServer.call(__MODULE__, {:cancel, execution_id})
  end

  @doc """
  List all executions, optionally filtered by platform or status.
  """
  @spec list_executions(keyword()) :: [map()]
  def list_executions(opts \\ []) do
    platform = Keyword.get(opts, :platform)
    status = Keyword.get(opts, :status)
    limit = Keyword.get(opts, :limit, 100)

    :ets.tab2list(@ets_table)
    |> Enum.map(fn {_id, exec} -> exec end)
    |> Enum.filter(fn exec ->
      (is_nil(platform) or exec.platform == platform) and
      (is_nil(status) or exec.status == status)
    end)
    |> Enum.sort_by(& &1.started_at, {:desc, DateTime})
    |> Enum.take(limit)
  end

  @doc """
  Get execution statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ---------------------------------------------------------------------------
  # Server Callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    :ets.new(@ets_table, [:named_table, :set, :public, read_concurrency: true])
    Logger.info("SOAR Playbook Executor started")

    schedule_timeout_check()

    {:ok, %__MODULE__{
      stats: %{
        triggered: 0,
        completed: 0,
        failed: 0,
        retried: 0,
        webhook_callbacks: 0,
        last_activity: nil
      }
    }}
  end

  @impl true
  def handle_call({:trigger, platform, playbook_name, params}, _from, state) do
    execution_id = generate_id()

    execution = %{
      id: execution_id,
      platform: platform,
      playbook_name: playbook_name,
      params: params,
      status: "pending",
      platform_run_id: nil,
      result: nil,
      error_message: nil,
      retry_count: 0,
      started_at: DateTime.utc_now(),
      updated_at: DateTime.utc_now(),
      completed_at: nil
    }

    :ets.insert(@ets_table, {execution_id, execution})

    # Dispatch to the SOAR platform asynchronously
    send(self(), {:dispatch, execution_id})

    new_stats = %{state.stats |
      triggered: state.stats.triggered + 1,
      last_activity: DateTime.utc_now()
    }

    {:reply, {:ok, execution_id}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:webhook_callback, execution_id, payload}, _from, state) do
    case :ets.lookup(@ets_table, execution_id) do
      [{_id, execution}] ->
        callback_status = payload["status"] || payload[:status]
        result = payload["result"] || payload[:result]
        error = payload["error"] || payload[:error]

        new_status = normalize_callback_status(callback_status)

        updated = %{execution |
          status: new_status,
          result: result,
          error_message: if(new_status == "failed", do: error || execution.error_message, else: nil),
          updated_at: DateTime.utc_now(),
          completed_at: if(new_status in ["completed", "failed"], do: DateTime.utc_now(), else: nil)
        }

        :ets.insert(@ets_table, {execution_id, updated})

        IntegrationLog.log_call(to_string(execution.platform), "webhook_callback", %{
          status: new_status,
          request_body: payload,
          response_body: result
        })

        new_stats = update_completion_stats(state.stats, new_status)

        {:reply, :ok, %{state | stats: new_stats}}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:retry, execution_id}, _from, state) do
    case :ets.lookup(@ets_table, execution_id) do
      [{_id, execution}] when execution.status == "failed" ->
        updated = %{execution |
          status: "retrying",
          error_message: nil,
          retry_count: execution.retry_count + 1,
          updated_at: DateTime.utc_now()
        }

        :ets.insert(@ets_table, {execution_id, updated})
        send(self(), {:dispatch, execution_id})

        new_stats = %{state.stats | retried: state.stats.retried + 1}
        {:reply, {:ok, execution_id}, %{state | stats: new_stats}}

      [{_id, _execution}] ->
        {:reply, {:error, :not_failed}, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:cancel, execution_id}, _from, state) do
    case :ets.lookup(@ets_table, execution_id) do
      [{_id, execution}] when execution.status in ["pending", "running", "retrying"] ->
        updated = %{execution |
          status: "failed",
          error_message: "Cancelled by user",
          updated_at: DateTime.utc_now(),
          completed_at: DateTime.utc_now()
        }

        :ets.insert(@ets_table, {execution_id, updated})
        {:reply, :ok, state}

      [{_id, _execution}] ->
        {:reply, {:error, :already_completed}, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_info({:dispatch, execution_id}, state) do
    case :ets.lookup(@ets_table, execution_id) do
      [{_id, execution}] ->
        dispatch_to_platform(execution)
        {:noreply, state}

      [] ->
        {:noreply, state}
    end
  end

  @impl true
  def handle_info({:retry_dispatch, execution_id, delay_ms}, state) do
    Process.send_after(self(), {:dispatch, execution_id}, delay_ms)
    {:noreply, state}
  end

  @impl true
  def handle_info(:check_timeouts, state) do
    now = DateTime.utc_now()

    :ets.tab2list(@ets_table)
    |> Enum.each(fn {execution_id, execution} ->
      if execution.status in ["pending", "running", "retrying"] do
        elapsed_ms = DateTime.diff(now, execution.started_at, :millisecond)

        if elapsed_ms > @execution_timeout_ms do
          Logger.warning("SOAR execution #{execution_id} timed out after #{div(elapsed_ms, 1000)}s")

          updated = %{execution |
            status: "failed",
            error_message: "Execution timed out after #{div(elapsed_ms, 60_000)} minutes",
            updated_at: now,
            completed_at: now
          }

          :ets.insert(@ets_table, {execution_id, updated})
        end
      end
    end)

    schedule_timeout_check()
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ---------------------------------------------------------------------------
  # Private Functions
  # ---------------------------------------------------------------------------

  defp dispatch_to_platform(execution) do
    module = get_soar_module(execution.platform)

    if module do
      # Update status to running
      running = %{execution | status: "running", updated_at: DateTime.utc_now()}
      :ets.insert(@ets_table, {execution.id, running})

      # Perform the actual API call with logging
      result = IntegrationLog.log_api_call(
        to_string(execution.platform),
        "trigger_playbook",
        %{playbook: execution.playbook_name, params: execution.params},
        fn ->
          module.trigger_playbook(execution.playbook_name, execution.params)
        end
      )

      case result do
        {:ok, platform_run_id} ->
          updated = %{running |
            platform_run_id: platform_run_id,
            updated_at: DateTime.utc_now()
          }
          :ets.insert(@ets_table, {execution.id, updated})

          # Start polling for status if the platform supports it
          schedule_status_poll(execution.id, execution.platform, platform_run_id)

        {:error, reason} ->
          handle_dispatch_failure(execution, reason)
      end
    else
      handle_dispatch_failure(execution, "Unsupported platform: #{execution.platform}")
    end
  rescue
    e ->
      handle_dispatch_failure(execution, Exception.message(e))
  end

  defp handle_dispatch_failure(execution, reason) do
    error_msg = if is_binary(reason), do: reason, else: inspect(reason)

    if execution.retry_count < @max_retries do
      # Schedule retry with exponential backoff
      delay = @initial_retry_delay_ms * :math.pow(2, execution.retry_count) |> round()

      Logger.warning(
        "SOAR execution #{execution.id} failed (attempt #{execution.retry_count + 1}/#{@max_retries + 1}), " <>
        "retrying in #{div(delay, 1000)}s: #{error_msg}"
      )

      updated = %{execution |
        status: "retrying",
        error_message: error_msg,
        retry_count: execution.retry_count + 1,
        updated_at: DateTime.utc_now()
      }

      :ets.insert(@ets_table, {execution.id, updated})
      send(self(), {:retry_dispatch, execution.id, delay})
    else
      Logger.error("SOAR execution #{execution.id} permanently failed after #{@max_retries + 1} attempts: #{error_msg}")

      updated = %{execution |
        status: "failed",
        error_message: error_msg,
        updated_at: DateTime.utc_now(),
        completed_at: DateTime.utc_now()
      }

      :ets.insert(@ets_table, {execution.id, updated})
    end
  end

  defp schedule_status_poll(execution_id, platform, platform_run_id) do
    # Poll status every 30 seconds for up to 10 minutes
    Task.start(fn ->
      poll_execution_status(execution_id, platform, platform_run_id, 0)
    end)
  end

  defp poll_execution_status(_execution_id, _platform, _platform_run_id, poll_count) when poll_count >= 20 do
    :ok  # Stop polling after ~10 minutes (20 * 30s)
  end

  defp poll_execution_status(execution_id, platform, platform_run_id, poll_count) do
    Process.sleep(30_000)  # 30 second intervals

    # Check if execution is still running
    case :ets.lookup(@ets_table, execution_id) do
      [{_id, execution}] when execution.status in ["running"] ->
        module = get_soar_module(platform)

        if module do
          case module.get_playbook_status(platform_run_id) do
            {:ok, %{status: "completed"} = result} ->
              updated = %{execution |
                status: "completed",
                result: result,
                updated_at: DateTime.utc_now(),
                completed_at: DateTime.utc_now()
              }
              :ets.insert(@ets_table, {execution_id, updated})

            {:ok, %{status: "failed"} = result} ->
              updated = %{execution |
                status: "failed",
                result: result,
                error_message: result[:error] || "Execution failed on #{platform}",
                updated_at: DateTime.utc_now(),
                completed_at: DateTime.utc_now()
              }
              :ets.insert(@ets_table, {execution_id, updated})

            {:ok, %{status: status}} when status in ["running", "pending", "unknown"] ->
              # Still running, continue polling
              poll_execution_status(execution_id, platform, platform_run_id, poll_count + 1)

            _ ->
              # Unknown status, continue polling
              poll_execution_status(execution_id, platform, platform_run_id, poll_count + 1)
          end
        end

      _ ->
        :ok  # Execution no longer running, stop polling
    end
  end

  defp normalize_callback_status(status) when is_binary(status) do
    case String.downcase(status) do
      "completed" -> "completed"
      "success" -> "completed"
      "succeeded" -> "completed"
      "done" -> "completed"
      "failed" -> "failed"
      "error" -> "failed"
      "cancelled" -> "failed"
      "running" -> "running"
      "in_progress" -> "running"
      "pending" -> "pending"
      _ -> "completed"  # Default to completed for unknown terminal states
    end
  end
  defp normalize_callback_status(_), do: "completed"

  defp update_completion_stats(stats, "completed") do
    %{stats | completed: stats.completed + 1, webhook_callbacks: stats.webhook_callbacks + 1, last_activity: DateTime.utc_now()}
  end
  defp update_completion_stats(stats, "failed") do
    %{stats | failed: stats.failed + 1, webhook_callbacks: stats.webhook_callbacks + 1, last_activity: DateTime.utc_now()}
  end
  defp update_completion_stats(stats, _) do
    %{stats | webhook_callbacks: stats.webhook_callbacks + 1, last_activity: DateTime.utc_now()}
  end

  defp get_soar_module(:xsoar), do: TamanduaServer.Integrations.SOAR.XSOAR
  defp get_soar_module(:splunk_soar), do: TamanduaServer.Integrations.SOAR.SplunkSOAR
  defp get_soar_module(:ibm_soar), do: TamanduaServer.Integrations.SOAR.IBMSOAR
  defp get_soar_module(:fortisoar), do: TamanduaServer.Integrations.SOAR.FortiSOAR
  defp get_soar_module(:chronicle), do: TamanduaServer.Integrations.SOAR.GoogleChronicle
  defp get_soar_module(:swimlane), do: TamanduaServer.Integrations.SOAR.Swimlane
  defp get_soar_module(:tines), do: TamanduaServer.Integrations.SOAR.Tines
  defp get_soar_module(_), do: nil

  defp generate_id do
    "soar_exec_" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
  end

  defp schedule_timeout_check do
    Process.send_after(self(), :check_timeouts, @timeout_check_interval)
  end
end
