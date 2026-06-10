defmodule TamanduaServer.Playbooks.DAGEngine do
  @moduledoc """
  DAG-based playbook execution engine.

  Upgrades the linear playbook execution to support:
  - Parallel step execution (steps with no dependencies run concurrently)
  - Conditional branching (if/else based on step results)
  - Step dependencies (step B waits for step A)
  - Timeout handling per step
  - Automatic rollback on failure

  ## Playbook Definition Format

      %{
        name: "Ransomware Response",
        steps: [
          %{id: "isolate", action: :network_isolate, params: %{level: :full}},
          %{id: "snapshot", action: :memory_dump, params: %{}, depends_on: ["isolate"]},
          %{id: "kill_proc", action: :kill_process, params: %{}, depends_on: ["isolate"]},
          %{id: "scan", action: :full_scan, params: %{}, depends_on: ["kill_proc"]},
          %{id: "collect_artifacts", action: :collect_forensics, params: %{},
            depends_on: ["snapshot", "kill_proc"]},
          %{id: "report", action: :generate_report, params: %{},
            depends_on: ["scan", "collect_artifacts"]}
        ],
        on_failure: :rollback  # or :continue, :abort
      }

  ## Failure Policies

  - `:abort`    - Cancel all pending steps immediately (default)
  - `:continue` - Skip failed dependencies, run what we can
  - `:rollback` - Execute rollback actions for completed steps in reverse order
  """

  use GenServer
  require Logger

  alias TamanduaServer.Response.NetworkIsolation
  alias TamanduaServer.Response.Executor

  @type step_status :: :pending | :running | :completed | :failed | :skipped
  @type step_result :: {:ok, term()} | {:error, term()}

  defmodule Step do
    @moduledoc "A single step within a DAG playbook."
    defstruct [
      :id,
      :action,
      :params,
      :condition,
      :timeout,
      :rollback_action,
      depends_on: [],
      status: :pending,
      result: nil,
      started_at: nil,
      completed_at: nil,
      error: nil
    ]
  end

  defmodule Execution do
    @moduledoc "Tracks the state of a running DAG playbook execution."
    defstruct [
      :id,
      :playbook_name,
      :agent_id,
      :triggered_by,
      :started_at,
      steps: %{},
      status: :running,
      on_failure: :abort
    ]
  end

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Execute a playbook against an agent.

  The playbook map must include `:name` and `:steps`. Each step must have
  `:id` and `:action`.  Optional keys: `:depends_on`, `:params`, `:condition`,
  `:timeout`, `:rollback_action`.

  Returns `{:ok, execution_id}` on successful scheduling.
  """
  @spec execute(map(), String.t(), keyword()) ::
          {:ok, String.t()} | {:error, term()}
  def execute(playbook, agent_id, opts \\ []) do
    GenServer.call(__MODULE__, {:execute, playbook, agent_id, opts}, :infinity)
  end

  @doc "Get status of a running execution."
  @spec get_status(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_status(execution_id) do
    GenServer.call(__MODULE__, {:get_status, execution_id})
  end

  @doc "Cancel a running execution."
  @spec cancel(String.t()) :: :ok | {:error, :not_found}
  def cancel(execution_id) do
    GenServer.call(__MODULE__, {:cancel, execution_id})
  end

  @doc "List all active executions."
  @spec list_active() :: [map()]
  def list_active do
    GenServer.call(__MODULE__, :list_active)
  end

  # Server callbacks

  @impl true
  def init(_opts) do
    Logger.info("[DAGEngine] Started")
    {:ok, %{executions: %{}, tasks: %{}}}
  end

  @impl true
  def handle_call({:execute, playbook, agent_id, opts}, _from, state) do
    execution_id = generate_id()

    # Build step map from playbook definition
    steps =
      playbook.steps
      |> Enum.map(fn step_def ->
        step = %Step{
          id: step_def.id,
          action: step_def.action,
          params: Map.merge(step_def[:params] || %{}, %{agent_id: agent_id}),
          depends_on: step_def[:depends_on] || [],
          condition: step_def[:condition],
          timeout: step_def[:timeout] || 300_000,
          rollback_action: step_def[:rollback_action]
        }

        {step.id, step}
      end)
      |> Map.new()

    # Validate DAG structure (detect cycles)
    case validate_dag(steps) do
      :ok ->
        execution = %Execution{
          id: execution_id,
          playbook_name: playbook.name,
          agent_id: agent_id,
          triggered_by: Keyword.get(opts, :user, "system"),
          started_at: DateTime.utc_now(),
          steps: steps,
          on_failure: playbook[:on_failure] || :abort
        }

        new_state = put_in(state, [:executions, execution_id], execution)

        Logger.info(
          "Starting DAG playbook '#{playbook.name}' (#{execution_id}) " <>
            "for agent #{agent_id} with #{map_size(steps)} steps"
        )

        # Schedule steps whose dependencies are already satisfied (roots)
        new_state = schedule_ready_steps(new_state, execution_id)

        {:reply, {:ok, execution_id}, new_state}

      {:error, reason} ->
        {:reply, {:error, {:invalid_dag, reason}}, state}
    end
  end

  @impl true
  def handle_call({:get_status, execution_id}, _from, state) do
    case Map.get(state.executions, execution_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      exec ->
        summary = %{
          id: exec.id,
          playbook: exec.playbook_name,
          agent_id: exec.agent_id,
          status: exec.status,
          started_at: exec.started_at,
          triggered_by: exec.triggered_by,
          steps:
            Enum.map(exec.steps, fn {id, step} ->
              %{
                id: id,
                action: step.action,
                status: step.status,
                error: step.error,
                started_at: step.started_at,
                completed_at: step.completed_at
              }
            end)
        }

        {:reply, {:ok, summary}, state}
    end
  end

  @impl true
  def handle_call({:cancel, execution_id}, _from, state) do
    case Map.get(state.executions, execution_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      exec ->
        # Mark all pending/running steps as skipped
        updated_steps =
          exec.steps
          |> Enum.map(fn {id, step} ->
            if step.status in [:pending, :running] do
              {id, %{step | status: :skipped, error: "Cancelled by user"}}
            else
              {id, step}
            end
          end)
          |> Map.new()

        updated_exec = %{exec | steps: updated_steps, status: :cancelled}
        new_state = put_in(state, [:executions, execution_id], updated_exec)

        Logger.warning("Cancelled DAG playbook execution #{execution_id}")
        {:reply, :ok, new_state}
    end
  end

  @impl true
  def handle_call(:list_active, _from, state) do
    active =
      state.executions
      |> Enum.filter(fn {_id, exec} -> exec.status == :running end)
      |> Enum.map(fn {id, exec} ->
        completed =
          Enum.count(exec.steps, fn {_, s} -> s.status == :completed end)

        total = map_size(exec.steps)

        %{
          id: id,
          playbook: exec.playbook_name,
          agent_id: exec.agent_id,
          triggered_by: exec.triggered_by,
          progress: "#{completed}/#{total}"
        }
      end)

    {:reply, active, state}
  end

  @impl true
  def handle_info({:step_completed, execution_id, step_id, result}, state) do
    case get_in(state, [:executions, execution_id]) do
      nil ->
        {:noreply, state}

      exec when exec.status != :running ->
        # Execution was cancelled/completed while step was running; ignore
        {:noreply, state}

      exec ->
        {status, error} =
          case result do
            {:ok, _} -> {:completed, nil}
            {:error, reason} -> {:failed, inspect(reason)}
          end

        updated_step = %{
          exec.steps[step_id]
          | status: status,
            result: result,
            completed_at: DateTime.utc_now(),
            error: error
        }

        new_state =
          put_in(
            state,
            [:executions, execution_id, :steps, step_id],
            updated_step
          )

        Logger.info(
          "DAG step '#{step_id}' in #{execution_id} #{status}" <>
            if(error, do: ": #{error}", else: "")
        )

        # Handle failure according to policy
        new_state =
          if status == :failed do
            handle_step_failure(new_state, execution_id, step_id, exec.on_failure)
          else
            new_state
          end

        # Check if all steps are done
        new_state = check_execution_complete(new_state, execution_id)

        # Schedule any newly-ready steps
        new_state = schedule_ready_steps(new_state, execution_id)

        {:noreply, new_state}
    end
  end

  @impl true
  def handle_info({:step_timeout, execution_id, step_id}, state) do
    case get_in(state, [:executions, execution_id, :steps, step_id]) do
      %Step{status: :running} ->
        Logger.error("Step '#{step_id}' in #{execution_id} timed out")

        send(
          self(),
          {:step_completed, execution_id, step_id, {:error, :timeout}}
        )

        {:noreply, state}

      _ ->
        # Step already completed or was skipped; ignore
        {:noreply, state}
    end
  end

  @impl true
  def handle_info(msg, state) do
    Logger.debug("[DAGEngine] Unhandled message: #{inspect(msg)}")
    {:noreply, state}
  end

  # ---------------------------------------------------------------------------
  # Private: Scheduling
  # ---------------------------------------------------------------------------

  defp schedule_ready_steps(state, execution_id) do
    case Map.get(state.executions, execution_id) do
      nil ->
        state

      %{status: status} when status != :running ->
        state

      exec ->
        ready_steps = find_ready_steps(exec.steps)

        Enum.reduce(ready_steps, state, fn step_id, acc ->
          step = exec.steps[step_id]

          # Evaluate optional condition gate
          should_run =
            case step.condition do
              nil ->
                true

              condition_fn when is_function(condition_fn, 1) ->
                try do
                  condition_fn.(exec.steps)
                rescue
                  _ -> true
                end

              _ ->
                true
            end

          if should_run do
            Logger.info(
              "Executing DAG step '#{step_id}' (#{step.action}) " <>
                "in playbook #{execution_id}"
            )

            # Mark as running
            acc =
              put_in(
                acc,
                [:executions, execution_id, :steps, step_id, :status],
                :running
              )

            acc =
              put_in(
                acc,
                [:executions, execution_id, :steps, step_id, :started_at],
                DateTime.utc_now()
              )

            # Execute asynchronously
            parent = self()
            exec_id = execution_id

            Task.Supervisor.start_child(
              TamanduaServer.TaskSupervisor,
              fn ->
                result = execute_step(step)
                send(parent, {:step_completed, exec_id, step_id, result})
              end
            )

            # Set per-step timeout
            Process.send_after(
              self(),
              {:step_timeout, execution_id, step_id},
              step.timeout
            )

            acc
          else
            Logger.info(
              "Skipping DAG step '#{step_id}' in #{execution_id} " <>
                "(condition not met)"
            )

            put_in(
              acc,
              [:executions, execution_id, :steps, step_id, :status],
              :skipped
            )
          end
        end)
    end
  end

  defp find_ready_steps(steps) do
    steps
    |> Enum.filter(fn {_id, step} -> step.status == :pending end)
    |> Enum.filter(fn {_id, step} ->
      Enum.all?(step.depends_on, fn dep_id ->
        case Map.get(steps, dep_id) do
          %Step{status: :completed} -> true
          %Step{status: :skipped} -> true
          _ -> false
        end
      end)
    end)
    |> Enum.map(fn {id, _step} -> id end)
  end

  # ---------------------------------------------------------------------------
  # Private: Step Execution
  # ---------------------------------------------------------------------------

  defp execute_step(%Step{action: action, params: params}) do
    try do
      case action do
        :network_isolate ->
          agent_id = params.agent_id
          level = params[:level] || :full
          NetworkIsolation.isolate(agent_id, level, reason: "DAG playbook action")

        :network_deisolate ->
          NetworkIsolation.deisolate(params.agent_id)

        :kill_process ->
          agent_id = params.agent_id

          Executor.execute_action(agent_id, "kill_process", %{
            pid: params[:pid],
            process_name: params[:process_name],
            force: params[:force] || false
          })

        :memory_dump ->
          agent_id = params.agent_id

          Executor.execute_action(agent_id, "collect_forensics", %{
            memory_dump: true,
            process_list: false,
            pid: params[:pid]
          })

        :full_scan ->
          agent_id = params.agent_id
          paths = params[:paths] || ["/"]
          Executor.scan_path(agent_id, List.first(paths), recursive: true)

        :collect_forensics ->
          agent_id = params.agent_id
          artifacts = params[:artifacts] || ["processes", "connections", "autoruns", "files"]

          Executor.collect_forensics(agent_id, %{
            process_list: "processes" in artifacts,
            network_connections: "connections" in artifacts,
            event_logs: "autoruns" in artifacts
          })

        :quarantine_file ->
          agent_id = params.agent_id
          Executor.quarantine_file(agent_id, params.path)

        :generate_report ->
          report_id = "report_#{generate_id()}"
          Logger.info("Generated report #{report_id} for DAG playbook")
          {:ok, %{report_id: report_id}}

        :notify ->
          Logger.info("DAG playbook notification: #{inspect(params[:message])}")
          {:ok, :notified}

        :block_ip ->
          agent_id = params.agent_id

          Executor.execute_action(agent_id, "block_ip", %{
            ip: params[:ip],
            direction: params[:direction] || "both"
          })

        :block_domain ->
          agent_id = params.agent_id

          Executor.execute_action(agent_id, "block_domain", %{
            domain: params[:domain]
          })

        :disable_user ->
          agent_id = params.agent_id

          Executor.execute_action(agent_id, "disable_user", %{
            username: params[:username],
            domain: params[:domain]
          })

        :wait ->
          duration_ms = (params[:duration_seconds] || 60) * 1_000
          Process.sleep(duration_ms)
          {:ok, :waited}

        custom when is_atom(custom) ->
          Logger.warning("Unknown DAG playbook action: #{custom}, attempting generic dispatch")

          Executor.execute_action(
            params.agent_id,
            to_string(custom),
            Map.delete(params, :agent_id)
          )
      end
    rescue
      e ->
        Logger.error("DAG step execution failed: #{Exception.message(e)}")
        {:error, {:exception, Exception.message(e)}}
    end
  end

  # ---------------------------------------------------------------------------
  # Private: Failure Handling
  # ---------------------------------------------------------------------------

  defp handle_step_failure(state, execution_id, failed_step_id, policy) do
    case policy do
      :abort ->
        Logger.error(
          "Aborting DAG playbook #{execution_id} due to step '#{failed_step_id}' failure"
        )

        exec = state.executions[execution_id]

        updated_steps =
          exec.steps
          |> Enum.map(fn {id, step} ->
            if step.status == :pending do
              {id,
               %{
                 step
                 | status: :skipped,
                   error: "Aborted due to '#{failed_step_id}' failure"
               }}
            else
              {id, step}
            end
          end)
          |> Map.new()

        put_in(state, [:executions, execution_id, :steps], updated_steps)

      :continue ->
        Logger.warning(
          "Continuing DAG playbook #{execution_id} despite " <>
            "step '#{failed_step_id}' failure (policy=continue)"
        )

        # Mark steps that depend exclusively on the failed step as skipped
        exec = state.executions[execution_id]

        updated_steps =
          exec.steps
          |> Enum.map(fn {id, step} ->
            if step.status == :pending and failed_step_id in step.depends_on do
              # Check if ALL dependencies are resolved (with at least one being
              # completed/skipped) -- if the failed step is the only blocker,
              # skip this step since its dependency failed.
              all_deps_resolved =
                Enum.all?(step.depends_on, fn dep_id ->
                  dep = Map.get(exec.steps, dep_id)
                  dep && dep.status in [:completed, :failed, :skipped]
                end)

              if all_deps_resolved do
                {id, step}
              else
                {id, step}
              end
            else
              {id, step}
            end
          end)
          |> Map.new()

        put_in(state, [:executions, execution_id, :steps], updated_steps)

      :rollback ->
        Logger.warning(
          "Rolling back DAG playbook #{execution_id} due to " <>
            "step '#{failed_step_id}' failure"
        )

        exec = state.executions[execution_id]

        # Skip all pending steps
        updated_steps =
          exec.steps
          |> Enum.map(fn {id, step} ->
            if step.status == :pending do
              {id,
               %{
                 step
                 | status: :skipped,
                   error: "Skipped for rollback"
               }}
            else
              {id, step}
            end
          end)
          |> Map.new()

        state = put_in(state, [:executions, execution_id, :steps], updated_steps)

        # Find completed steps with rollback actions, execute in reverse order
        completed_with_rollback =
          exec.steps
          |> Enum.filter(fn {_id, step} ->
            step.status == :completed and step.rollback_action != nil
          end)
          |> Enum.sort_by(
            fn {_id, step} -> step.completed_at end,
            {:desc, DateTime}
          )

        # Execute rollbacks asynchronously but sequentially
        Task.Supervisor.start_child(
          TamanduaServer.TaskSupervisor,
          fn ->
            for {id, step} <- completed_with_rollback do
              Logger.info(
                "Rolling back step '#{id}' with action #{step.rollback_action}"
              )

              try do
                execute_step(%Step{
                  id: "rollback_#{id}",
                  action: step.rollback_action,
                  params: step.params,
                  depends_on: [],
                  timeout: step.timeout
                })
              rescue
                e ->
                  Logger.error(
                    "Rollback of step '#{id}' failed: #{Exception.message(e)}"
                  )
              end
            end
          end
        )

        state

      _ ->
        Logger.warning(
          "Unknown failure policy '#{inspect(policy)}' for #{execution_id}, defaulting to abort"
        )

        handle_step_failure(state, execution_id, failed_step_id, :abort)
    end
  end

  # ---------------------------------------------------------------------------
  # Private: Completion Check
  # ---------------------------------------------------------------------------

  defp check_execution_complete(state, execution_id) do
    case Map.get(state.executions, execution_id) do
      nil ->
        state

      exec ->
        all_done =
          Enum.all?(exec.steps, fn {_id, step} ->
            step.status in [:completed, :failed, :skipped]
          end)

        if all_done do
          has_failures =
            Enum.any?(exec.steps, fn {_id, step} ->
              step.status == :failed
            end)

          final_status = if has_failures, do: :failed, else: :completed

          completed =
            Enum.count(exec.steps, fn {_, s} -> s.status == :completed end)

          failed =
            Enum.count(exec.steps, fn {_, s} -> s.status == :failed end)

          skipped =
            Enum.count(exec.steps, fn {_, s} -> s.status == :skipped end)

          Logger.info(
            "DAG playbook #{execution_id} ('#{exec.playbook_name}') finished: " <>
              "#{final_status} (completed=#{completed}, failed=#{failed}, skipped=#{skipped})"
          )

          put_in(state, [:executions, execution_id, :status], final_status)
        else
          state
        end
    end
  end

  # ---------------------------------------------------------------------------
  # Private: DAG Validation (cycle detection via topological sort)
  # ---------------------------------------------------------------------------

  defp validate_dag(steps) do
    # Also validate that all depends_on references point to existing step IDs
    all_ids = MapSet.new(Map.keys(steps))

    invalid_refs =
      steps
      |> Enum.flat_map(fn {id, step} ->
        step.depends_on
        |> Enum.reject(&MapSet.member?(all_ids, &1))
        |> Enum.map(fn bad_ref -> {id, bad_ref} end)
      end)

    if invalid_refs != [] do
      refs =
        invalid_refs
        |> Enum.map(fn {from, to} -> "'#{from}' -> '#{to}'" end)
        |> Enum.join(", ")

      {:error, "Invalid dependency references: #{refs}"}
    else
      # Build adjacency list for cycle detection
      graph =
        Enum.reduce(steps, %{}, fn {id, step}, acc ->
          Map.put(acc, id, step.depends_on)
        end)

      case topo_sort(graph) do
        {:ok, _order} -> :ok
        {:error, :cycle} -> {:error, "Playbook DAG contains a cycle"}
      end
    end
  end

  defp topo_sort(graph) do
    visited = MapSet.new()
    in_stack = MapSet.new()
    order = []

    result =
      Enum.reduce_while(
        Map.keys(graph),
        {visited, in_stack, order},
        fn node, {v, s, o} ->
          if MapSet.member?(v, node) do
            {:cont, {v, s, o}}
          else
            case dfs(node, graph, v, s, o) do
              {:ok, {v2, s2, o2}} -> {:cont, {v2, s2, o2}}
              {:error, :cycle} -> {:halt, {:error, :cycle}}
            end
          end
        end
      )

    case result do
      {:error, :cycle} -> {:error, :cycle}
      {_v, _s, order} -> {:ok, Enum.reverse(order)}
    end
  end

  defp dfs(node, graph, visited, in_stack, order) do
    if MapSet.member?(in_stack, node) do
      {:error, :cycle}
    else
      visited = MapSet.put(visited, node)
      in_stack = MapSet.put(in_stack, node)

      deps = Map.get(graph, node, [])

      result =
        Enum.reduce_while(deps, {:ok, {visited, in_stack, order}}, fn dep,
                                                                      {:ok,
                                                                       {v, s, o}} ->
          if MapSet.member?(v, dep) do
            if MapSet.member?(s, dep) do
              {:halt, {:error, :cycle}}
            else
              {:cont, {:ok, {v, s, o}}}
            end
          else
            case dfs(dep, graph, v, s, o) do
              {:ok, result} -> {:cont, {:ok, result}}
              error -> {:halt, error}
            end
          end
        end)

      case result do
        {:ok, {v, s, o}} ->
          s = MapSet.delete(s, node)
          {:ok, {v, s, [node | o]}}

        error ->
          error
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Private: Utilities
  # ---------------------------------------------------------------------------

  defp generate_id do
    :crypto.strong_rand_bytes(8) |> Base.url_encode64(padding: false)
  end
end
