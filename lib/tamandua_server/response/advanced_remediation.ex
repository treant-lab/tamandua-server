defmodule TamanduaServer.Response.AdvancedRemediation do
  @moduledoc """
  Advanced Remediation Engine for SentinelOne-class autonomous response.

  Provides comprehensive remediation capabilities:
  - Registry cleanup and persistence removal
  - Scheduled task management
  - Service uninstallation
  - Browser extension removal
  - Persistence mechanism eradication
  - Full system rollback support

  All remediation actions are executed in parallel where possible
  to achieve sub-second response times.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Response.Executor
  alias TamanduaServer.Agents.Registry

  # Remediation action timeout (ms)
  @action_timeout 30_000

  # State structure
  defstruct [
    :active_remediations,
    :remediation_history,
    :rollback_points
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Execute full remediation on an agent - removes all persistence and malware traces.
  Returns immediately with a remediation job ID.
  """
  @spec full_remediation(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def full_remediation(agent_id, context \\ %{}) do
    GenServer.call(__MODULE__, {:full_remediation, agent_id, context})
  end

  @doc """
  Clean registry entries associated with malware persistence.
  """
  @spec registry_cleanup(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def registry_cleanup(agent_id, params \\ %{}) do
    GenServer.call(__MODULE__, {:registry_cleanup, agent_id, params})
  end

  @doc """
  Remove malicious scheduled tasks.
  """
  @spec scheduled_task_removal(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def scheduled_task_removal(agent_id, params \\ %{}) do
    GenServer.call(__MODULE__, {:scheduled_task_removal, agent_id, params})
  end

  @doc """
  Uninstall malicious services.
  """
  @spec service_uninstallation(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def service_uninstallation(agent_id, params \\ %{}) do
    GenServer.call(__MODULE__, {:service_uninstallation, agent_id, params})
  end

  @doc """
  Remove all persistence mechanisms from a compromised host.
  """
  @spec persistence_removal(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def persistence_removal(agent_id, params \\ %{}) do
    GenServer.call(__MODULE__, {:persistence_removal, agent_id, params})
  end

  @doc """
  Remove malicious browser extensions.
  """
  @spec browser_extension_removal(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def browser_extension_removal(agent_id, params \\ %{}) do
    GenServer.call(__MODULE__, {:browser_extension_removal, agent_id, params})
  end

  @doc """
  WMI subscription cleanup.
  """
  @spec wmi_cleanup(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def wmi_cleanup(agent_id, params \\ %{}) do
    GenServer.call(__MODULE__, {:wmi_cleanup, agent_id, params})
  end

  @doc """
  Remove DLL hijacking persistence.
  """
  @spec dll_hijack_cleanup(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def dll_hijack_cleanup(agent_id, params \\ %{}) do
    GenServer.call(__MODULE__, {:dll_hijack_cleanup, agent_id, params})
  end

  @doc """
  Get remediation job status.
  """
  @spec get_remediation_status(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_remediation_status(job_id) do
    GenServer.call(__MODULE__, {:get_status, job_id})
  end

  @doc """
  List recent remediation jobs.
  """
  @spec list_remediations(keyword()) :: {:ok, [map()]}
  def list_remediations(opts \\ []) do
    GenServer.call(__MODULE__, {:list_remediations, opts})
  end

  @doc """
  Create a rollback point before remediation.
  """
  @spec create_rollback_point(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def create_rollback_point(agent_id, description) do
    GenServer.call(__MODULE__, {:create_rollback_point, agent_id, description})
  end

  @doc """
  Rollback to a previous state.
  """
  @spec rollback(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def rollback(agent_id, rollback_point_id) do
    GenServer.call(__MODULE__, {:rollback, agent_id, rollback_point_id})
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("Starting Advanced Remediation Engine")

    state = %__MODULE__{
      active_remediations: %{},
      remediation_history: [],
      rollback_points: %{}
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:full_remediation, agent_id, context}, _from, state) do
    job_id = generate_job_id()
    start_time = System.monotonic_time(:millisecond)

    Logger.info("Starting full remediation on agent #{agent_id}, job_id: #{job_id}")

    # Create rollback point first
    rollback_result = create_rollback_point_internal(agent_id, "Pre-remediation snapshot")

    # Build remediation task list
    tasks = build_full_remediation_tasks(agent_id, context)

    # Execute all tasks in parallel for speed
    remediation_job = %{
      id: job_id,
      agent_id: agent_id,
      type: :full_remediation,
      status: :running,
      started_at: DateTime.utc_now(),
      context: context,
      rollback_point: rollback_result,
      tasks: tasks,
      results: %{},
      errors: []
    }

    # Start async execution
    spawn_link(fn ->
      results = execute_parallel_remediation(tasks, agent_id)
      duration_ms = System.monotonic_time(:millisecond) - start_time

      GenServer.cast(__MODULE__, {:remediation_complete, job_id, results, duration_ms})
    end)

    new_active = Map.put(state.active_remediations, job_id, remediation_job)

    {:reply, {:ok, %{job_id: job_id, status: :running, tasks: length(tasks)}},
     %{state | active_remediations: new_active}}
  end

  @impl true
  def handle_call({:registry_cleanup, agent_id, params}, _from, state) do
    result = execute_remediation_action(agent_id, "registry_cleanup", %{
      hives: params[:hives] || ["HKLM", "HKCU"],
      patterns: params[:patterns] || [],
      known_malware_keys: params[:known_malware_keys] || [],
      remove_run_keys: params[:remove_run_keys] || true,
      remove_services: params[:remove_services] || true,
      remove_drivers: params[:remove_drivers] || false,
      backup_before_delete: params[:backup_before_delete] || true
    })

    {:reply, result, state}
  end

  @impl true
  def handle_call({:scheduled_task_removal, agent_id, params}, _from, state) do
    result = execute_remediation_action(agent_id, "scheduled_task_removal", %{
      task_names: params[:task_names] || [],
      patterns: params[:patterns] || [],
      remove_unsigned: params[:remove_unsigned] || false,
      remove_suspicious_paths: params[:remove_suspicious_paths] || true,
      paths_whitelist: params[:paths_whitelist] || ["C:\\Windows\\", "C:\\Program Files\\"],
      backup_before_delete: true
    })

    {:reply, result, state}
  end

  @impl true
  def handle_call({:service_uninstallation, agent_id, params}, _from, state) do
    result = execute_remediation_action(agent_id, "service_uninstallation", %{
      service_names: params[:service_names] || [],
      patterns: params[:patterns] || [],
      stop_before_remove: true,
      remove_binaries: params[:remove_binaries] || true,
      paths_whitelist: params[:paths_whitelist] || ["C:\\Windows\\", "C:\\Program Files\\"],
      backup_service_config: true
    })

    {:reply, result, state}
  end

  @impl true
  def handle_call({:persistence_removal, agent_id, params}, _from, state) do
    job_id = generate_job_id()
    start_time = System.monotonic_time(:millisecond)

    # Create rollback point
    _rollback_result = create_rollback_point_internal(agent_id, "Pre-persistence removal")

    # Execute all persistence removal tasks in parallel
    tasks = [
      {:registry, %{action: "registry_cleanup", params: %{remove_run_keys: true}}},
      {:scheduled_tasks, %{action: "scheduled_task_removal", params: %{remove_suspicious_paths: true}}},
      {:services, %{action: "service_uninstallation", params: %{patterns: params[:service_patterns] || []}}},
      {:wmi, %{action: "wmi_cleanup", params: %{}}},
      {:startup_folders, %{action: "startup_folder_cleanup", params: %{}}},
      {:browser_extensions, %{action: "browser_extension_removal", params: %{}}},
      {:dll_hijacks, %{action: "dll_hijack_cleanup", params: %{}}}
    ]

    spawn_link(fn ->
      results = Enum.map(tasks, fn {name, task} ->
        result = execute_remediation_action(agent_id, task.action, task.params)
        {name, result}
      end)
      |> Map.new()

      duration_ms = System.monotonic_time(:millisecond) - start_time
      GenServer.cast(__MODULE__, {:persistence_removal_complete, job_id, results, duration_ms})
    end)

    {:reply, {:ok, %{job_id: job_id, status: :running}}, state}
  end

  @impl true
  def handle_call({:browser_extension_removal, agent_id, params}, _from, state) do
    result = execute_remediation_action(agent_id, "browser_extension_removal", %{
      browsers: params[:browsers] || ["chrome", "firefox", "edge", "brave"],
      extension_ids: params[:extension_ids] || [],
      patterns: params[:patterns] || [],
      remove_unknown: params[:remove_unknown] || false,
      whitelist: params[:whitelist] || []
    })

    {:reply, result, state}
  end

  @impl true
  def handle_call({:wmi_cleanup, agent_id, params}, _from, state) do
    result = execute_remediation_action(agent_id, "wmi_cleanup", %{
      remove_event_subscriptions: params[:remove_event_subscriptions] || true,
      remove_event_filters: params[:remove_event_filters] || true,
      remove_event_consumers: params[:remove_event_consumers] || true,
      patterns: params[:patterns] || [],
      whitelist: params[:whitelist] || []
    })

    {:reply, result, state}
  end

  @impl true
  def handle_call({:dll_hijack_cleanup, agent_id, params}, _from, state) do
    result = execute_remediation_action(agent_id, "dll_hijack_cleanup", %{
      scan_paths: params[:scan_paths] || ["C:\\Windows\\System32\\", "C:\\Windows\\SysWOW64\\"],
      known_hijack_dlls: params[:known_hijack_dlls] || [],
      verify_signatures: true,
      remove_unsigned: params[:remove_unsigned] || false,
      quarantine_suspicious: true
    })

    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_status, job_id}, _from, state) do
    case Map.get(state.active_remediations, job_id) do
      nil ->
        # Check history
        case Enum.find(state.remediation_history, fn r -> r.id == job_id end) do
          nil -> {:reply, {:error, :not_found}, state}
          job -> {:reply, {:ok, job}, state}
        end

      job ->
        {:reply, {:ok, job}, state}
    end
  end

  @impl true
  def handle_call({:list_remediations, opts}, _from, state) do
    limit = Keyword.get(opts, :limit, 50)
    agent_id = Keyword.get(opts, :agent_id)

    all = state.remediation_history
    |> Enum.concat(Map.values(state.active_remediations))
    |> Enum.sort_by(& &1.started_at, {:desc, DateTime})

    filtered = if agent_id do
      Enum.filter(all, fn r -> r.agent_id == agent_id end)
    else
      all
    end

    {:reply, {:ok, Enum.take(filtered, limit)}, state}
  end

  @impl true
  def handle_call({:create_rollback_point, agent_id, description}, _from, state) do
    result = create_rollback_point_internal(agent_id, description)

    new_points = case result do
      {:ok, point} ->
        agent_points = Map.get(state.rollback_points, agent_id, [])
        Map.put(state.rollback_points, agent_id, [point | agent_points])

      _ ->
        state.rollback_points
    end

    {:reply, result, %{state | rollback_points: new_points}}
  end

  @impl true
  def handle_call({:rollback, agent_id, rollback_point_id}, _from, state) do
    result = execute_remediation_action(agent_id, "rollback", %{
      rollback_point_id: rollback_point_id,
      restore_registry: true,
      restore_files: true,
      restore_services: true,
      restore_scheduled_tasks: true
    })

    {:reply, result, state}
  end

  @impl true
  def handle_cast({:remediation_complete, job_id, results, duration_ms}, state) do
    case Map.get(state.active_remediations, job_id) do
      nil ->
        {:noreply, state}

      job ->
        completed_job = %{job |
          status: if(all_successful?(results), do: :completed, else: :completed_with_errors),
          completed_at: DateTime.utc_now(),
          results: results,
          duration_ms: duration_ms
        }

        Logger.info("Remediation #{job_id} completed in #{duration_ms}ms")

        new_active = Map.delete(state.active_remediations, job_id)
        new_history = [completed_job | state.remediation_history] |> Enum.take(1000)

        {:noreply, %{state | active_remediations: new_active, remediation_history: new_history}}
    end
  end

  @impl true
  def handle_cast({:persistence_removal_complete, job_id, results, duration_ms}, state) do
    Logger.info("Persistence removal #{job_id} completed in #{duration_ms}ms: #{inspect(results)}")
    {:noreply, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp generate_job_id do
    "rem_" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
  end

  defp build_full_remediation_tasks(agent_id, context) do
    base_tasks = [
      %{name: "kill_malicious_processes", action: "kill_process", priority: 1, params: %{
        pid: context[:pid],
        kill_children: true
      }},
      %{name: "quarantine_malware", action: "quarantine_file", priority: 2, params: %{
        path: context[:file_path],
        calculate_hash: true
      }},
      %{name: "registry_cleanup", action: "registry_cleanup", priority: 3, params: %{
        remove_run_keys: true,
        patterns: context[:registry_patterns] || []
      }},
      %{name: "scheduled_task_cleanup", action: "scheduled_task_removal", priority: 3, params: %{
        remove_suspicious_paths: true
      }},
      %{name: "service_cleanup", action: "service_uninstallation", priority: 3, params: %{
        patterns: context[:service_patterns] || []
      }},
      %{name: "wmi_cleanup", action: "wmi_cleanup", priority: 4, params: %{}},
      %{name: "startup_cleanup", action: "startup_folder_cleanup", priority: 4, params: %{}},
      %{name: "browser_extension_cleanup", action: "browser_extension_removal", priority: 5, params: %{}}
    ]

    # Add context-specific tasks
    extra_tasks = cond do
      context[:ransomware] ->
        [%{name: "ransomware_remediation", action: "ransomware_remediate", priority: 1, params: %{
          path: context[:affected_path] || "C:\\Users",
          dry_run: false
        }}]

      context[:credential_theft] ->
        [%{name: "credential_cleanup", action: "credential_cleanup", priority: 2, params: %{
          clear_cached_credentials: true,
          force_password_change: false
        }}]

      true ->
        []
    end

    Enum.concat(base_tasks, extra_tasks)
    |> Enum.sort_by(& &1.priority)
  end

  defp execute_parallel_remediation(tasks, agent_id) do
    # Group by priority for parallel execution within priority levels
    tasks
    |> Enum.group_by(& &1.priority)
    |> Enum.sort_by(fn {priority, _} -> priority end)
    |> Enum.flat_map(fn {_priority, priority_tasks} ->
      # Execute all tasks at the same priority level in parallel
      priority_tasks
      |> Task.async_stream(fn task ->
        start = System.monotonic_time(:millisecond)
        result = execute_remediation_action(agent_id, task.action, task.params)
        duration = System.monotonic_time(:millisecond) - start

        %{
          name: task.name,
          action: task.action,
          result: result,
          duration_ms: duration
        }
      end, timeout: @action_timeout, on_timeout: :kill_task)
      |> Enum.map(fn
        {:ok, result} -> result
        {:exit, reason} -> %{name: "unknown", action: "unknown", result: {:error, reason}, duration_ms: 0}
      end)
    end)
  end

  defp execute_remediation_action(agent_id, action, params) do
    Logger.debug("Executing remediation action #{action} on agent #{agent_id}")

    case Executor.execute_action(agent_id, action, params) do
      {:ok, response} ->
        {:ok, response}

      {:error, reason} ->
        Logger.error("Remediation action #{action} failed on agent #{agent_id}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp create_rollback_point_internal(agent_id, description) do
    point_id = "rp_" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)

    case Executor.execute_action(agent_id, "create_rollback_point", %{
      point_id: point_id,
      description: description,
      include_registry: true,
      include_services: true,
      include_scheduled_tasks: true,
      include_vss_snapshot: true
    }) do
      {:ok, response} ->
        {:ok, %{
          id: point_id,
          agent_id: agent_id,
          description: description,
          created_at: DateTime.utc_now(),
          details: response
        }}

      {:error, reason} ->
        Logger.error("Failed to create rollback point on agent #{agent_id}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp all_successful?(results) when is_list(results) do
    Enum.all?(results, fn
      %{result: {:ok, _}} -> true
      %{result: {:error, _}} -> false
      _ -> false
    end)
  end

  defp all_successful?(results) when is_map(results) do
    Enum.all?(results, fn
      {_key, {:ok, _}} -> true
      {_key, {:error, _}} -> false
      _ -> false
    end)
  end
end
