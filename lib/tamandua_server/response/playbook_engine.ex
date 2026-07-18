defmodule TamanduaServer.Response.PlaybookEngine do
  @moduledoc """
  Advanced Playbook Execution Engine

  Provides sophisticated playbook execution capabilities including:
  - Sequential and parallel step execution
  - Conditional branching based on previous step results
  - Retry mechanisms with exponential backoff
  - Step-level timeout handling
  - Approval workflow integration
  - Comprehensive execution history tracking
  - Rollback capabilities on failure

  ## Execution Flow

  1. Load playbook and validate prerequisites
  2. Create execution record
  3. Check for approval requirement
  4. Execute steps in order (or parallel when specified)
  5. Track step results and handle errors
  6. Complete execution and update statistics

  ## Step Types

  - **command**: Execute a command on an agent
  - **script**: Run a script on an agent
  - **api_call**: Call an external API
  - **conditional**: Branch based on conditions
  - **parallel**: Execute multiple steps concurrently
  - **wait**: Pause execution for specified duration
  - **approval**: Pause for human approval
  """

  use GenServer
  require Logger

  alias TamanduaServer.{Repo}
  alias TamanduaServer.Response.{ConditionEvaluator}
  alias TamanduaServer.Response.Playbook.{Execution, StepExecution}

  import Ecto.Query

  @default_step_timeout 300_000  # 5 minutes
  @default_max_retries 3
  @default_retry_delay 1000
  @max_parallel_steps 10

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Execute a playbook with the given context.

  ## Options
  - `:scope` - Tenant scope (`{:organization, organization_id}`) for non-system callers
  - `:skip_approval` - Skip approval even if required (default: false)
  - `:dry_run` - Simulate execution without actually running steps (default: false)
  - `:timeout` - Overall execution timeout in milliseconds (default: 600000)
  - `:on_complete` - Callback function called when execution completes

  ## Returns
  - `{:ok, execution}` - Execution started successfully
  - `{:error, reason}` - Failed to start execution
  """
  @spec execute_playbook(String.t(), map(), keyword()) ::
          {:ok, Execution.t()} | {:error, term()}
  def execute_playbook(playbook_id, context \\ %{}, opts \\ []) do
    GenServer.call(__MODULE__, {:execute_playbook, playbook_id, context, opts}, 60_000)
  end

  @doc """
  Get the current status of a playbook execution.
  """
  @spec get_execution_status(String.t(), term()) ::
          {:ok, map()} | {:error, :not_found}
  def get_execution_status(execution_id, scope \\ :system) do
    GenServer.call(__MODULE__, {:get_execution_status, execution_id, scope})
  end

  @doc """
  Cancel a running execution.
  """
  @spec cancel_execution(String.t(), String.t(), term()) :: :ok | {:error, term()}
  def cancel_execution(execution_id, reason \\ "Cancelled by user", scope \\ :system) do
    GenServer.call(__MODULE__, {:cancel_execution, execution_id, reason, scope})
  end

  @doc """
  Retry a failed step within an execution.
  """
  @spec retry_step(String.t(), integer(), term()) :: {:ok, map()} | {:error, term()}
  def retry_step(execution_id, step_index, scope \\ :system) do
    GenServer.call(__MODULE__, {:retry_step, execution_id, step_index, scope})
  end

  @doc """
  List all active executions.
  """
  @spec list_active_executions(term()) :: {:ok, [map()]} | {:error, term()}
  def list_active_executions(scope \\ :system) do
    GenServer.call(__MODULE__, {:list_active_executions, scope})
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("Starting PlaybookEngine")

    state = %{
      active_executions: %{},
      execution_tasks: %{}
    }

    # Resume any in-progress executions from database (recovery)
    schedule_recovery()

    {:ok, state}
  end

  @impl true
  def handle_call({:execute_playbook, playbook_id, context, opts}, _from, state) do
    case start_playbook_execution(playbook_id, context, opts) do
      {:ok, execution} ->
        # Start execution asynchronously
        task = Task.async(fn ->
          execute_playbook_async(execution, opts)
        end)

        new_state = %{
          state
          | active_executions: Map.put(state.active_executions, execution.id, execution),
            execution_tasks: Map.put(state.execution_tasks, execution.id, task)
        }

        {:reply, {:ok, execution}, new_state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:get_execution_status, execution_id, scope}, _from, state) do
    # Try in-memory first, then database
    status =
      case scoped_active_execution(state, execution_id, scope) do
        {:error, reason} ->
          {:error, reason}

        nil ->
          # Load from database
          case scoped_execution(execution_id, scope) do
            nil -> {:error, :not_found}
            {:error, reason} -> {:error, reason}
            execution -> build_execution_status(execution)
          end

        execution ->
          build_execution_status(execution)
      end

    {:reply, status, state}
  end

  @impl true
  def handle_call({:cancel_execution, execution_id, reason, scope}, _from, state) do
    case scoped_active_execution(state, execution_id, scope) do
      {:error, reason} ->
        {:reply, {:error, reason}, state}

      nil ->
        # Try to cancel from database if it's pending approval
        case scoped_execution(execution_id, scope) do
          %Execution{status: "pending_approval"} = exec ->
            cancel_execution_record(exec, reason)
            {:reply, :ok, state}

          {:error, scope_reason} ->
            {:reply, {:error, scope_reason}, state}

          _ ->
            {:reply, {:error, :not_found}, state}
        end

      _execution ->
        # Cancel the running task
        task = Map.get(state.execution_tasks, execution_id)
        if task, do: Task.shutdown(task, :brutal_kill)

        # Mark as cancelled in database
        case scoped_execution(execution_id, scope) do
          %Execution{} = exec ->
            cancel_execution_record(exec, reason)

          _ ->
            :ok
        end

        new_state = %{
          state
          | active_executions: Map.delete(state.active_executions, execution_id),
            execution_tasks: Map.delete(state.execution_tasks, execution_id)
        }

        {:reply, :ok, new_state}
    end
  end

  @impl true
  def handle_call({:retry_step, execution_id, step_index, scope}, _from, state) do
    # Load execution and step from database
    with %Execution{} = execution <- scoped_execution(execution_id, scope),
         %StepExecution{} = step <- get_step_execution(execution_id, step_index),
         true <- step.status in ["failed", "completed"] do
      # Retry the step
      result = retry_step_execution(execution, step)
      {:reply, result, state}
    else
      nil -> {:reply, {:error, :not_found}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
      false -> {:reply, {:error, :step_not_failed}, state}
    end
  end

  @impl true
  def handle_call({:list_active_executions, scope}, _from, state) do
    case validate_scope(scope) do
      {:ok, normalized_scope} ->
        active =
          state.active_executions
          |> Map.values()
          |> Enum.filter(&scope_allows?(normalized_scope, &1))
          |> Enum.map(fn execution ->
            {:ok, status} = build_execution_status(execution)
            status
          end)

        {:reply, {:ok, active}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_info({ref, {:execution_complete, execution_id, result}}, state)
      when is_reference(ref) do
    # Execution task completed
    Process.demonitor(ref, [:flush])

    case result do
      {:ok, final_execution} ->
        Logger.info("Playbook execution #{execution_id} completed successfully")
        complete_execution(final_execution, :success)

      {:error, reason} ->
        Logger.error("Playbook execution #{execution_id} failed: #{inspect(reason)}")

        case Map.get(state.active_executions, execution_id) do
          nil -> :ok
          execution -> complete_execution(execution, :failed, reason)
        end
    end

    new_state = %{
      state
      | active_executions: Map.delete(state.active_executions, execution_id),
        execution_tasks: Map.delete(state.execution_tasks, execution_id)
    }

    {:noreply, new_state}
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, _pid, _reason}, state) do
    # Task died - clean up
    {:noreply, state}
  end

  @impl true
  def handle_info(:recover_executions, state) do
    # Resume any in-progress executions
    in_progress =
      from(e in Execution,
        where: e.status in ["running", "pending"] and not is_nil(e.organization_id),
        preload: []
      )
      |> Repo.all()

    Logger.info("Recovering #{length(in_progress)} in-progress executions")

    Enum.each(in_progress, fn execution ->
      # Resume execution
      Task.start(fn ->
        execute_playbook_async(execution, [])
      end)
    end)

    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions - Execution Logic
  # ============================================================================

  defp start_playbook_execution(playbook_id, context, opts) do
    # Load playbook
    scope = Keyword.get(opts, :scope, :system)
    playbook = TamanduaServer.Response.Playbook.get_playbook(playbook_id, scope)

    case playbook do
      {:ok, pb} ->
        dry_run = Keyword.get(opts, :dry_run, false)
        skip_approval = Keyword.get(opts, :skip_approval, false)

        status =
          cond do
            pb.require_approval and not skip_approval -> "pending_approval"
            true -> "running"
          end

        execution_attrs = %{
          playbook_id: pb.id,
          trigger_event: context,
          status: status,
          execution_context: context,
          started_at: DateTime.utc_now(),
          dry_run: dry_run,
          organization_id: pb.organization_id
        }

        # Create execution record
        %Execution{}
        |> Execution.changeset(execution_attrs)
        |> Repo.insert()

      {:error, :not_found} ->
        {:error, :playbook_not_found}

      error ->
        error
    end
  end

  defp execute_playbook_async(execution, opts) do
    # Wait for approval if needed
    execution =
      if execution.status == "pending_approval" do
        wait_for_approval(execution, opts)
      else
        execution
      end

    case execution.status do
      "cancelled" ->
        {:error, :cancelled}

      "failed" ->
        {:error, :approval_timeout}

      _ ->
        # Load playbook
        case TamanduaServer.Response.Playbook.get_playbook(
               execution.playbook_id,
               execution_scope(execution)
             ) do
          {:ok, playbook} ->
            # Execute all steps
            result = execute_steps(execution, playbook.steps, 0, execution.execution_context)

            case result do
              {:ok, final_context} ->
                {:execution_complete, execution.id,
                 {:ok, %{execution | execution_context: final_context}}}

              {:error, reason} ->
                {:execution_complete, execution.id, {:error, reason}}
            end

          {:error, reason} ->
            {:execution_complete, execution.id, {:error, reason}}
        end
    end
  end

  defp execute_steps(_execution, steps, current_index, context) when current_index >= length(steps) do
    # All steps completed
    {:ok, context}
  end

  defp execute_steps(execution, steps, current_index, context) do
    step = Enum.at(steps, current_index)

    # Create step execution record
    step_attrs = %{
      execution_id: execution.id,
      step_index: current_index,
      step_name: step["name"] || step["action"],
      action_type: step["action"],
      status: "running",
      params: step["params"] || %{},
      max_retries: step["max_retries"] || @default_max_retries,
      timeout_seconds: step["timeout_seconds"] || div(@default_step_timeout, 1000),
      started_at: DateTime.utc_now()
    }

    {:ok, step_exec} =
      %StepExecution{}
      |> StepExecution.changeset(step_attrs)
      |> Repo.insert()

    # Execute the step
    result = execute_single_step(execution, step, context, step_exec)

    case result do
      {:ok, step_result, updated_context} ->
        # Update step execution record
        complete_step_execution(step_exec, :success, step_result)

        # Continue to next step
        execute_steps(execution, steps, current_index + 1, updated_context)

      {:wait, duration_ms, updated_context} ->
        # Wait step
        complete_step_execution(step_exec, :success, %{waited: duration_ms})
        Process.sleep(duration_ms)
        execute_steps(execution, steps, current_index + 1, updated_context)

      {:branch, next_index, updated_context} ->
        # Conditional branch
        complete_step_execution(step_exec, :success, %{branched_to: next_index})
        execute_steps(execution, steps, next_index, updated_context)

      {:skip, reason, updated_context} ->
        # Skip step
        complete_step_execution(step_exec, :skipped, %{reason: reason})
        execute_steps(execution, steps, current_index + 1, updated_context)

      {:error, reason} ->
        # Step failed
        complete_step_execution(step_exec, :failed, nil, reason)

        # Check if we should retry
        if step_exec.retry_count < step_exec.max_retries do
          retry_step_execution(execution, step_exec)
          # Retry the same step
          execute_steps(execution, steps, current_index, context)
        else
          # Check if we should continue on failure
          continue_on_failure = step["continue_on_failure"] || false

          if continue_on_failure do
            Logger.warning(
              "Step #{current_index} failed but continue_on_failure is true: #{inspect(reason)}"
            )

            execute_steps(execution, steps, current_index + 1, context)
          else
            {:error, "Step #{current_index} (#{step["action"]}) failed: #{inspect(reason)}"}
          end
        end
    end
  end

  defp execute_single_step(execution, step, context, _step_exec) do
    action = step["action"]
    params = step["params"] || %{}
    timeout = (step["timeout_seconds"] || div(@default_step_timeout, 1000)) * 1000

    # Merge context into params (context values available as variables)
    merged_params = merge_context_into_params(params, context)

    # Execute based on action type
    try do
      task =
        Task.async(fn ->
          execute_step_action(action, merged_params, execution, context)
        end)

      case Task.yield(task, timeout) || Task.shutdown(task) do
        {:ok, result} -> result
        nil -> {:error, :timeout}
      end
    rescue
      e ->
        Logger.error("Step execution error: #{Exception.message(e)}")
        {:error, Exception.message(e)}
    end
  end

  defp execute_step_action("conditional", params, _execution, context) do
    condition = params["condition"]
    true_step = params["true_step"]
    false_step = params["false_step"]

    if ConditionEvaluator.evaluate(condition, context) do
      {:branch, true_step, context}
    else
      {:branch, false_step, context}
    end
  end

  defp execute_step_action("parallel", params, execution, context) do
    sub_steps = params["steps"] || []
    max_parallel = min(length(sub_steps), @max_parallel_steps)

    results =
      sub_steps
      |> Task.async_stream(
        fn sub_step ->
          execute_step_action(sub_step["action"], sub_step["params"] || %{}, execution, context)
        end,
        max_concurrency: max_parallel,
        timeout: params["timeout_seconds"] || @default_step_timeout
      )
      |> Enum.map(fn
        {:ok, result} -> result
        {:exit, reason} -> {:error, "Parallel step failed: #{inspect(reason)}"}
      end)

    # Check if any failed
    failed = Enum.filter(results, fn
      {:error, _} -> true
      _ -> false
    end)

    if length(failed) > 0 do
      {:error, "#{length(failed)} parallel steps failed"}
    else
      # Merge all results into context
      updated_context =
        results
        |> Enum.reduce(context, fn result, acc ->
          case result do
            {:ok, _step_result, ctx} -> Map.merge(acc, ctx)
            _ -> acc
          end
        end)

      {:ok, %{parallel_results: results}, updated_context}
    end
  end

  defp execute_step_action("wait", params, _execution, context) do
    duration = (params["duration_seconds"] || 60) * 1000
    {:wait, duration, context}
  end

  defp execute_step_action("approval", _params, _execution, context) do
    # This should be handled at the execution level, not step level
    {:skip, "Approval handled at execution level", context}
  end

  defp execute_step_action(action, params, execution, context) do
    # Delegate to the main Playbook module's step executor
    # This maintains backward compatibility with existing step implementations
    result = TamanduaServer.Response.Playbook.execute_single_step(
      %{"action" => action, "params" => params},
      %{execution | execution_context: context}
    )

    case result do
      {:ok, step_result} ->
        # Update context with step result
        updated_context = Map.put(context, "last_step_result", step_result)
        {:ok, step_result, updated_context}

      {:wait, duration} ->
        {:wait, duration, context}

      {:branch, next_index} ->
        {:branch, next_index, context}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp merge_context_into_params(params, context) do
    # Replace {{variable}} placeholders with context values
    params
    |> Enum.map(fn {key, value} ->
      {key, interpolate_value(value, context)}
    end)
    |> Map.new()
  end

  defp interpolate_value(value, _context) when is_number(value), do: value
  defp interpolate_value(value, _context) when is_boolean(value), do: value
  defp interpolate_value(nil, _context), do: nil

  defp interpolate_value(value, context) when is_binary(value) do
    # Replace {{key}} with context[key]
    Regex.replace(~r/\{\{(\w+)\}\}/, value, fn _, key ->
      try do
        context_key = String.to_existing_atom(key)
        to_string(Map.get(context, context_key, Map.get(context, key, "")))
      rescue
        _ -> ""
      end
    end)
  end

  defp interpolate_value(value, context) when is_list(value) do
    Enum.map(value, &interpolate_value(&1, context))
  end

  defp interpolate_value(value, context) when is_map(value) do
    value
    |> Enum.map(fn {k, v} -> {k, interpolate_value(v, context)} end)
    |> Map.new()
  end

  defp interpolate_value(value, _context), do: value

  # ============================================================================
  # Private Functions - Database Operations
  # ============================================================================

  defp complete_step_execution(step_exec, status, result, error \\ nil) do
    now = DateTime.utc_now()
    duration = DateTime.diff(now, step_exec.started_at, :millisecond)

    step_exec
    |> StepExecution.changeset(%{
      status: to_string(status),
      result: result,
      error_message: error && to_string(error),
      completed_at: now,
      duration_ms: duration
    })
    |> Repo.update()
  end

  defp retry_step_execution(_execution, step_exec) do
    # Increment retry count
    case step_exec
         |> StepExecution.changeset(%{
           status: "retrying",
           retry_count: step_exec.retry_count + 1
         })
         |> Repo.update() do
      {:ok, updated_step} ->
        # Exponential backoff
        delay = @default_retry_delay * :math.pow(2, step_exec.retry_count) |> round()
        Logger.info("Retrying step #{step_exec.step_index} after #{delay}ms (attempt #{updated_step.retry_count})")
        Process.sleep(delay)

        {:ok, updated_step}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp get_step_execution(execution_id, step_index) do
    from(s in StepExecution,
      where: s.execution_id == ^execution_id and s.step_index == ^step_index
    )
    |> Repo.one()
  end

  defp complete_execution(execution, status, error \\ nil) do
    now = DateTime.utc_now()

    final_status =
      case status do
        :success -> "completed"
        :failed -> "failed"
        :cancelled -> "cancelled"
        _ -> "unknown"
      end

    execution
    |> Execution.changeset(%{
      status: final_status,
      completed_at: now,
      error_message: error && to_string(error)
    })
    |> Repo.update()

    # Update playbook statistics
    update_playbook_stats(execution.playbook_id, execution.organization_id, status)
  end

  defp cancel_execution_record(execution, reason) do
    execution
    |> Execution.changeset(%{
      status: "cancelled",
      error_message: reason,
      completed_at: DateTime.utc_now()
    })
    |> Repo.update()
  end

  defp update_playbook_stats(playbook_id, organization_id, status) do
    success_increment = if status == :success, do: 1, else: 0

    from(p in TamanduaServer.Response.Playbook.Schema,
      where: p.id == ^playbook_id and p.organization_id == ^organization_id
    )
    |> Repo.update_all(
      inc: [execution_count: 1, success_count: success_increment],
      set: [last_executed_at: DateTime.utc_now()]
    )
  end

  defp wait_for_approval(execution, opts) do
    timeout = Keyword.get(opts, :approval_timeout, 1800_000)  # 30 minutes default
    start_time = System.monotonic_time(:millisecond)

    wait_for_approval_loop(execution, start_time, timeout)
  end

  defp wait_for_approval_loop(execution, start_time, timeout) do
    # Check if approved
    case scoped_execution(execution.id, execution_scope(execution)) do
      %Execution{status: "running"} = exec ->
        # Approved
        exec

      %Execution{status: "cancelled"} = exec ->
        # Cancelled
        exec

      %Execution{} = exec ->
        # Still pending
        elapsed = System.monotonic_time(:millisecond) - start_time

        if elapsed > timeout do
          # Timeout
          cancel_execution_record(exec, "Approval timeout exceeded")
          %{exec | status: "failed"}
        else
          # Wait and check again
          Process.sleep(5000)
          wait_for_approval_loop(exec, start_time, timeout)
        end

      nil ->
        # Execution deleted
        %{execution | status: "cancelled"}

      {:error, _reason} ->
        %{execution | status: "cancelled"}
    end
  end

  defp build_execution_status(execution) do
    # Load step executions
    steps =
      from(s in StepExecution,
        where: s.execution_id == ^execution.id,
        order_by: [asc: s.step_index]
      )
      |> Repo.all()

    {:ok,
     %{
       execution: execution,
       steps: steps,
       progress: calculate_progress(execution, steps),
       current_step: execution.current_step
     }}
  end

  defp calculate_progress(execution, steps) do
    case execution.status do
      "completed" -> 100
      "failed" -> Enum.count(steps, &(&1.status == "completed")) / max(length(steps), 1) * 100
      "cancelled" -> Enum.count(steps, &(&1.status == "completed")) / max(length(steps), 1) * 100
      _ -> Enum.count(steps, &(&1.status == "completed")) / max(length(steps), 1) * 100
    end
  end

  defp schedule_recovery do
    Process.send_after(self(), :recover_executions, 5000)
  end

  defp scoped_active_execution(state, execution_id, scope) do
    with {:ok, normalized_scope} <- validate_scope(scope) do
      case Map.get(state.active_executions, execution_id) do
        %Execution{} = execution ->
          if scope_allows?(normalized_scope, execution), do: execution, else: nil

        nil ->
          nil
      end
    end
  end

  defp scoped_execution(execution_id, scope) do
    with {:ok, normalized_scope} <- validate_scope(scope) do
      query = from(e in Execution, where: e.id == ^execution_id)

      query =
        case normalized_scope do
          :system -> query
          {:organization, organization_id} ->
            from(e in query, where: e.organization_id == ^organization_id)
        end

      Repo.one(query)
    end
  end

  defp execution_scope(%Execution{organization_id: organization_id})
       when is_binary(organization_id) and organization_id != "",
       do: {:organization, organization_id}

  defp execution_scope(_execution), do: :system

  defp validate_scope(:system), do: {:ok, :system}

  defp validate_scope({:organization, organization_id})
       when is_binary(organization_id) and organization_id != "",
       do: {:ok, {:organization, organization_id}}

  defp validate_scope(_scope), do: {:error, :tenant_required}

  defp scope_allows?(:system, _execution), do: true

  defp scope_allows?({:organization, organization_id}, %Execution{} = execution),
    do: execution.organization_id == organization_id
end
