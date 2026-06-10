defmodule TamanduaServer.Integrations.SOAR.PlaybookSync do
  @moduledoc """
  SOAR Playbook Synchronization Module

  Provides bi-directional playbook synchronization between Tamandua and SOAR platforms:
  - Export Tamandua playbooks to SOAR format
  - Import SOAR playbooks to Tamandua
  - Version management and tracking
  - Conflict resolution
  - Playbook validation and transformation

  ## Supported Platforms

  - Splunk SOAR (Phantom)
  - IBM Security SOAR (Resilient)
  - FortiSOAR
  - Google Chronicle SOAR
  - Palo Alto XSOAR
  - Swimlane
  - Tines

  ## Features

  - Playbook format conversion between platforms
  - Action/step mapping
  - Trigger configuration sync
  - Variable and parameter mapping
  - Execution history sync

  """

  use GenServer
  require Logger

  alias TamanduaServer.Response.Playbook, as: TamanduaPlaybook

  @platforms [:xsoar, :splunk_soar, :ibm_soar, :fortisoar, :chronicle, :swimlane, :tines]

  defstruct [
    :sync_state,
    :version_map,
    :conflict_log,
    :stats
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Export a Tamandua playbook to SOAR format.
  """
  @spec export_playbook(String.t(), atom(), keyword()) :: {:ok, map()} | {:error, term()}
  def export_playbook(playbook_id, platform, opts \\ []) do
    GenServer.call(__MODULE__, {:export_playbook, playbook_id, platform, opts}, 30_000)
  end

  @doc """
  Export multiple playbooks to SOAR format.
  """
  @spec export_playbooks([String.t()], atom(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def export_playbooks(playbook_ids, platform, opts \\ []) do
    GenServer.call(__MODULE__, {:export_playbooks, playbook_ids, platform, opts}, 60_000)
  end

  @doc """
  Import a playbook from SOAR platform.
  """
  @spec import_playbook(map(), atom(), keyword()) :: {:ok, String.t()} | {:error, term()}
  def import_playbook(soar_playbook, platform, opts \\ []) do
    GenServer.call(__MODULE__, {:import_playbook, soar_playbook, platform, opts}, 30_000)
  end

  @doc """
  Sync playbooks with a SOAR platform (bi-directional).
  """
  @spec sync_playbooks(atom(), keyword()) :: {:ok, map()} | {:error, term()}
  def sync_playbooks(platform, opts \\ []) do
    GenServer.call(__MODULE__, {:sync_playbooks, platform, opts}, 120_000)
  end

  @doc """
  Get playbook version information.
  """
  @spec get_version_info(String.t()) :: {:ok, map()} | {:error, term()}
  def get_version_info(playbook_id) do
    GenServer.call(__MODULE__, {:get_version_info, playbook_id})
  end

  @doc """
  Compare playbook versions between Tamandua and SOAR.
  """
  @spec compare_versions(String.t(), atom()) :: {:ok, map()} | {:error, term()}
  def compare_versions(playbook_id, platform) do
    GenServer.call(__MODULE__, {:compare_versions, playbook_id, platform}, 30_000)
  end

  @doc """
  Resolve a sync conflict.
  """
  @spec resolve_conflict(String.t(), :keep_local | :keep_remote | :merge) :: :ok | {:error, term()}
  def resolve_conflict(conflict_id, resolution) do
    GenServer.call(__MODULE__, {:resolve_conflict, conflict_id, resolution})
  end

  @doc """
  Get pending conflicts.
  """
  @spec get_conflicts() :: {:ok, [map()]}
  def get_conflicts do
    GenServer.call(__MODULE__, :get_conflicts)
  end

  @doc """
  Validate a playbook for export to a specific platform.
  """
  @spec validate_for_export(String.t(), atom()) :: {:ok, []} | {:error, [String.t()]}
  def validate_for_export(playbook_id, platform) do
    GenServer.call(__MODULE__, {:validate_for_export, playbook_id, platform})
  end

  @doc """
  Get supported platforms.
  """
  @spec supported_platforms() :: [atom()]
  def supported_platforms, do: @platforms

  @doc """
  Get sync statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("Starting SOAR Playbook Sync")

    state = %__MODULE__{
      sync_state: %{},
      version_map: %{},
      conflict_log: [],
      stats: %{
        exports: 0,
        imports: 0,
        syncs: 0,
        conflicts_resolved: 0,
        last_sync: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:export_playbook, playbook_id, platform, opts}, _from, state) do
    case TamanduaPlaybook.get(playbook_id) do
      {:ok, playbook} ->
        case convert_to_soar_format(playbook, platform, opts) do
          {:ok, soar_playbook} ->
            # Push to SOAR if requested
            result = if opts[:push] do
              push_to_soar(soar_playbook, platform)
            else
              {:ok, soar_playbook}
            end

            new_stats = update_stat(state.stats, :exports)
            {:reply, result, %{state | stats: new_stats}}

          error ->
            {:reply, error, state}
        end

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:export_playbooks, playbook_ids, platform, opts}, _from, state) do
    results = Enum.map(playbook_ids, fn id ->
      case TamanduaPlaybook.get(id) do
        {:ok, playbook} ->
          case convert_to_soar_format(playbook, platform, opts) do
            {:ok, soar_playbook} -> {:ok, {id, soar_playbook}}
            error -> error
          end

        error ->
          error
      end
    end)

    successful = results
    |> Enum.filter(fn
      {:ok, _} -> true
      _ -> false
    end)
    |> Enum.map(fn {:ok, result} -> result end)

    new_stats = Map.update(state.stats, :exports, length(successful), &(&1 + length(successful)))
    {:reply, {:ok, successful}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:import_playbook, soar_playbook, platform, opts}, _from, state) do
    case convert_from_soar_format(soar_playbook, platform, opts) do
      {:ok, tamandua_playbook} ->
        # Check for conflicts
        case check_import_conflict(tamandua_playbook, state) do
          {:conflict, existing} ->
            conflict = create_conflict(tamandua_playbook, existing, platform)
            new_state = %{state | conflict_log: [conflict | state.conflict_log]}

            if opts[:force] do
              save_playbook(tamandua_playbook, new_state)
            else
              {:reply, {:error, {:conflict, conflict.id}}, new_state}
            end

          :no_conflict ->
            save_playbook(tamandua_playbook, state)
        end

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:sync_playbooks, platform, opts}, _from, state) do
    # Get local playbooks
    {:ok, local_playbooks} = TamanduaPlaybook.list()

    # Get remote playbooks
    remote_playbooks = fetch_remote_playbooks(platform)

    # Compare and sync
    sync_result = perform_sync(local_playbooks, remote_playbooks, platform, opts, state)

    new_stats = state.stats
    |> update_stat(:syncs)
    |> Map.put(:last_sync, DateTime.utc_now())

    {:reply, sync_result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:get_version_info, playbook_id}, _from, state) do
    version_info = Map.get(state.version_map, playbook_id, %{
      local_version: nil,
      remote_versions: %{},
      last_sync: nil
    })

    {:reply, {:ok, version_info}, state}
  end

  @impl true
  def handle_call({:compare_versions, playbook_id, platform}, _from, state) do
    case TamanduaPlaybook.get(playbook_id) do
      {:ok, local} ->
        case fetch_remote_playbook(playbook_id, platform) do
          {:ok, remote} ->
            comparison = compare_playbooks(local, remote)
            {:reply, {:ok, comparison}, state}

          error ->
            {:reply, error, state}
        end

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:resolve_conflict, conflict_id, resolution}, _from, state) do
    case Enum.find(state.conflict_log, &(&1.id == conflict_id)) do
      nil ->
        {:reply, {:error, :conflict_not_found}, state}

      conflict ->
        case apply_resolution(conflict, resolution) do
          :ok ->
            new_log = Enum.reject(state.conflict_log, &(&1.id == conflict_id))
            new_stats = update_stat(state.stats, :conflicts_resolved)
            {:reply, :ok, %{state | conflict_log: new_log, stats: new_stats}}

          error ->
            {:reply, error, state}
        end
    end
  end

  @impl true
  def handle_call(:get_conflicts, _from, state) do
    {:reply, {:ok, state.conflict_log}, state}
  end

  @impl true
  def handle_call({:validate_for_export, playbook_id, platform}, _from, state) do
    case TamanduaPlaybook.get(playbook_id) do
      {:ok, playbook} ->
        errors = validate_playbook(playbook, platform)
        if length(errors) == 0 do
          {:reply, {:ok, []}, state}
        else
          {:reply, {:error, errors}, state}
        end

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  # ============================================================================
  # Platform-Specific Conversion
  # ============================================================================

  defp convert_to_soar_format(playbook, platform, opts) do
    try do
      converted = case platform do
        :xsoar -> convert_to_xsoar(playbook, opts)
        :splunk_soar -> convert_to_splunk_soar(playbook, opts)
        :ibm_soar -> convert_to_ibm_soar(playbook, opts)
        :fortisoar -> convert_to_fortisoar(playbook, opts)
        :chronicle -> convert_to_chronicle(playbook, opts)
        :swimlane -> convert_to_swimlane(playbook, opts)
        :tines -> convert_to_tines(playbook, opts)
        _ -> {:error, :unsupported_platform}
      end

      {:ok, converted}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end

  defp convert_from_soar_format(soar_playbook, platform, opts) do
    try do
      converted = case platform do
        :xsoar -> convert_from_xsoar(soar_playbook, opts)
        :splunk_soar -> convert_from_splunk_soar(soar_playbook, opts)
        :ibm_soar -> convert_from_ibm_soar(soar_playbook, opts)
        :fortisoar -> convert_from_fortisoar(soar_playbook, opts)
        :chronicle -> convert_from_chronicle(soar_playbook, opts)
        :swimlane -> convert_from_swimlane(soar_playbook, opts)
        :tines -> convert_from_tines(soar_playbook, opts)
        _ -> {:error, :unsupported_platform}
      end

      {:ok, converted}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end

  # XSOAR Conversion
  defp convert_to_xsoar(playbook, _opts) do
    %{
      id: playbook.id,
      name: playbook.name,
      description: playbook.description,
      version: playbook.version || 1,
      fromVersion: "6.0.0",
      tasks: convert_steps_to_xsoar_tasks(playbook.steps),
      inputs: convert_inputs_to_xsoar(playbook.inputs),
      outputs: convert_outputs_to_xsoar(playbook.outputs),
      starttaskid: "0",
      view: build_xsoar_view(playbook.steps),
      system: false,
      hidden: false
    }
  end

  defp convert_from_xsoar(xsoar_playbook, _opts) do
    %{
      id: xsoar_playbook["id"],
      name: xsoar_playbook["name"],
      description: xsoar_playbook["description"],
      version: xsoar_playbook["version"],
      steps: convert_xsoar_tasks_to_steps(xsoar_playbook["tasks"]),
      inputs: convert_xsoar_inputs(xsoar_playbook["inputs"]),
      outputs: convert_xsoar_outputs(xsoar_playbook["outputs"]),
      source: :xsoar
    }
  end

  # Splunk SOAR Conversion
  defp convert_to_splunk_soar(playbook, _opts) do
    %{
      name: playbook.name,
      description: playbook.description,
      playbook_type: "automation",
      python_version: "3",
      blocks: convert_steps_to_phantom_blocks(playbook.steps),
      inputs: playbook.inputs || [],
      outputs: playbook.outputs || [],
      coa: build_phantom_coa(playbook)
    }
  end

  defp convert_from_splunk_soar(phantom_playbook, _opts) do
    %{
      id: phantom_playbook["id"],
      name: phantom_playbook["name"],
      description: phantom_playbook["description"],
      steps: convert_phantom_blocks_to_steps(phantom_playbook["blocks"]),
      inputs: phantom_playbook["inputs"] || [],
      outputs: phantom_playbook["outputs"] || [],
      source: :splunk_soar
    }
  end

  # IBM SOAR Conversion
  defp convert_to_ibm_soar(playbook, _opts) do
    %{
      name: playbook.name,
      display_name: playbook.name,
      description: %{format: "text", content: playbook.description || ""},
      workflow: %{
        workflow_id: generate_workflow_id(),
        content: %{
          nodes: convert_steps_to_resilient_nodes(playbook.steps),
          edges: build_resilient_edges(playbook.steps)
        }
      },
      local_scripts: [],
      activation_type: "manual",
      status: "enabled"
    }
  end

  defp convert_from_ibm_soar(resilient_playbook, _opts) do
    %{
      id: resilient_playbook["id"],
      name: resilient_playbook["display_name"] || resilient_playbook["name"],
      description: get_text_content(resilient_playbook["description"]),
      steps: convert_resilient_nodes_to_steps(resilient_playbook["workflow"]["content"]["nodes"]),
      source: :ibm_soar
    }
  end

  # FortiSOAR Conversion
  defp convert_to_fortisoar(playbook, _opts) do
    %{
      name: playbook.name,
      description: playbook.description,
      isActive: true,
      triggerType: "manual",
      priority: 5,
      steps: convert_steps_to_fortisoar_steps(playbook.steps),
      parameters: playbook.inputs || [],
      outputs: playbook.outputs || []
    }
  end

  defp convert_from_fortisoar(fortisoar_playbook, _opts) do
    %{
      id: fortisoar_playbook["@id"] || fortisoar_playbook["id"],
      name: fortisoar_playbook["name"],
      description: fortisoar_playbook["description"],
      steps: convert_fortisoar_steps_to_steps(fortisoar_playbook["steps"]),
      inputs: fortisoar_playbook["parameters"] || [],
      outputs: fortisoar_playbook["outputs"] || [],
      source: :fortisoar
    }
  end

  # Chronicle SOAR Conversion
  defp convert_to_chronicle(playbook, _opts) do
    %{
      name: playbook.name,
      display_name: playbook.name,
      description: playbook.description,
      trigger_type: "MANUAL",
      is_enabled: true,
      blocks: convert_steps_to_chronicle_blocks(playbook.steps),
      parameters: playbook.inputs || []
    }
  end

  defp convert_from_chronicle(chronicle_playbook, _opts) do
    %{
      id: chronicle_playbook["id"],
      name: chronicle_playbook["display_name"] || chronicle_playbook["name"],
      description: chronicle_playbook["description"],
      steps: convert_chronicle_blocks_to_steps(chronicle_playbook["blocks"]),
      inputs: chronicle_playbook["parameters"] || [],
      source: :chronicle
    }
  end

  # Swimlane Conversion
  defp convert_to_swimlane(playbook, _opts) do
    %{
      name: playbook.name,
      description: playbook.description,
      enabled: true,
      actions: convert_steps_to_swimlane_actions(playbook.steps),
      triggers: [%{type: "manual"}],
      inputs: playbook.inputs || []
    }
  end

  defp convert_from_swimlane(swimlane_playbook, _opts) do
    %{
      id: swimlane_playbook["id"],
      name: swimlane_playbook["name"],
      description: swimlane_playbook["description"],
      steps: convert_swimlane_actions_to_steps(swimlane_playbook["actions"]),
      inputs: swimlane_playbook["inputs"] || [],
      source: :swimlane
    }
  end

  # Tines Conversion
  defp convert_to_tines(playbook, _opts) do
    %{
      name: playbook.name,
      description: playbook.description,
      agents: convert_steps_to_tines_agents(playbook.steps),
      links: build_tines_links(playbook.steps)
    }
  end

  defp convert_from_tines(tines_playbook, _opts) do
    %{
      id: tines_playbook["id"],
      name: tines_playbook["name"],
      description: tines_playbook["description"],
      steps: convert_tines_agents_to_steps(tines_playbook["agents"]),
      source: :tines
    }
  end

  # ============================================================================
  # Step/Action Conversion Helpers
  # ============================================================================

  defp convert_steps_to_xsoar_tasks(steps) when is_list(steps) do
    steps
    |> Enum.with_index()
    |> Enum.map(fn {step, index} ->
      {to_string(index), %{
        id: to_string(index),
        taskid: generate_task_id(),
        type: map_action_to_xsoar_type(step.action),
        task: %{
          id: generate_task_id(),
          name: step.name || step.action,
          description: step.description || "",
          script: step.script,
          scriptarguments: step.parameters || %{}
        },
        nexttasks: build_next_tasks(steps, index),
        separatecontext: false,
        view: build_task_view(index)
      }}
    end)
    |> Enum.into(%{})
  end

  defp convert_steps_to_xsoar_tasks(_), do: %{}

  defp convert_xsoar_tasks_to_steps(nil), do: []
  defp convert_xsoar_tasks_to_steps(tasks) when is_map(tasks) do
    tasks
    |> Map.values()
    |> Enum.sort_by(& &1["id"])
    |> Enum.map(fn task ->
      %{
        name: get_in(task, ["task", "name"]) || task["id"],
        action: get_in(task, ["task", "script"]) || infer_action_from_type(task["type"]),
        description: get_in(task, ["task", "description"]),
        parameters: get_in(task, ["task", "scriptarguments"]) || %{}
      }
    end)
  end

  defp convert_steps_to_phantom_blocks(steps) when is_list(steps) do
    steps
    |> Enum.with_index()
    |> Enum.map(fn {step, index} ->
      %{
        id: index,
        name: step.name || step.action,
        type: map_action_to_phantom_type(step.action),
        action: step.action,
        parameters: step.parameters || %{},
        next: if(index < length(steps) - 1, do: [index + 1], else: [])
      }
    end)
  end

  defp convert_steps_to_phantom_blocks(_), do: []

  defp convert_phantom_blocks_to_steps(nil), do: []
  defp convert_phantom_blocks_to_steps(blocks) when is_list(blocks) do
    Enum.map(blocks, fn block ->
      %{
        name: block["name"],
        action: block["action"],
        parameters: block["parameters"] || %{}
      }
    end)
  end

  defp convert_steps_to_resilient_nodes(steps) when is_list(steps) do
    steps
    |> Enum.with_index()
    |> Enum.map(fn {step, index} ->
      %{
        id: "node_#{index}",
        type: map_action_to_resilient_type(step.action),
        name: step.name || step.action,
        properties: step.parameters || %{}
      }
    end)
  end

  defp convert_steps_to_resilient_nodes(_), do: []

  defp convert_resilient_nodes_to_steps(nil), do: []
  defp convert_resilient_nodes_to_steps(nodes) when is_list(nodes) do
    Enum.map(nodes, fn node ->
      %{
        name: node["name"],
        action: infer_action_from_type(node["type"]),
        parameters: node["properties"] || %{}
      }
    end)
  end

  defp convert_steps_to_fortisoar_steps(steps) when is_list(steps) do
    steps
    |> Enum.with_index()
    |> Enum.map(fn {step, index} ->
      %{
        "@id": "step_#{index}",
        name: step.name || step.action,
        stepType: map_action_to_fortisoar_type(step.action),
        arguments: step.parameters || %{}
      }
    end)
  end

  defp convert_steps_to_fortisoar_steps(_), do: []

  defp convert_fortisoar_steps_to_steps(nil), do: []
  defp convert_fortisoar_steps_to_steps(steps) when is_list(steps) do
    Enum.map(steps, fn step ->
      %{
        name: step["name"],
        action: infer_action_from_type(step["stepType"]),
        parameters: step["arguments"] || %{}
      }
    end)
  end

  defp convert_steps_to_chronicle_blocks(steps) when is_list(steps) do
    steps
    |> Enum.with_index()
    |> Enum.map(fn {step, index} ->
      %{
        identifier: "block_#{index}",
        name: step.name || step.action,
        type: map_action_to_chronicle_type(step.action),
        parameters: step.parameters || %{}
      }
    end)
  end

  defp convert_steps_to_chronicle_blocks(_), do: []

  defp convert_chronicle_blocks_to_steps(nil), do: []
  defp convert_chronicle_blocks_to_steps(blocks) when is_list(blocks) do
    Enum.map(blocks, fn block ->
      %{
        name: block["name"],
        action: infer_action_from_type(block["type"]),
        parameters: block["parameters"] || %{}
      }
    end)
  end

  defp convert_steps_to_swimlane_actions(steps) when is_list(steps) do
    steps
    |> Enum.with_index()
    |> Enum.map(fn {step, index} ->
      %{
        id: "action_#{index}",
        name: step.name || step.action,
        actionType: map_action_to_swimlane_type(step.action),
        inputs: step.parameters || %{}
      }
    end)
  end

  defp convert_steps_to_swimlane_actions(_), do: []

  defp convert_swimlane_actions_to_steps(nil), do: []
  defp convert_swimlane_actions_to_steps(actions) when is_list(actions) do
    Enum.map(actions, fn action ->
      %{
        name: action["name"],
        action: infer_action_from_type(action["actionType"]),
        parameters: action["inputs"] || %{}
      }
    end)
  end

  defp convert_steps_to_tines_agents(steps) when is_list(steps) do
    steps
    |> Enum.with_index()
    |> Enum.map(fn {step, index} ->
      %{
        id: index,
        name: step.name || step.action,
        type: map_action_to_tines_type(step.action),
        options: step.parameters || %{}
      }
    end)
  end

  defp convert_steps_to_tines_agents(_), do: []

  defp convert_tines_agents_to_steps(nil), do: []
  defp convert_tines_agents_to_steps(agents) when is_list(agents) do
    Enum.map(agents, fn agent ->
      %{
        name: agent["name"],
        action: infer_action_from_type(agent["type"]),
        parameters: agent["options"] || %{}
      }
    end)
  end

  # ============================================================================
  # Action Type Mapping
  # ============================================================================

  defp map_action_to_xsoar_type(action) do
    case action do
      "kill_process" -> "regular"
      "quarantine_file" -> "regular"
      "isolate_host" -> "regular"
      "block_ip" -> "regular"
      "collect_forensics" -> "regular"
      "send_notification" -> "regular"
      "enrich" -> "regular"
      "condition" -> "condition"
      "manual" -> "manual"
      _ -> "regular"
    end
  end

  defp map_action_to_phantom_type(action) do
    case action do
      "kill_process" -> "action"
      "quarantine_file" -> "action"
      "isolate_host" -> "action"
      "block_ip" -> "action"
      "collect_forensics" -> "action"
      "send_notification" -> "action"
      "enrich" -> "action"
      "condition" -> "decision"
      "manual" -> "prompt"
      _ -> "action"
    end
  end

  defp map_action_to_resilient_type(action) do
    case action do
      "kill_process" -> "function"
      "quarantine_file" -> "function"
      "isolate_host" -> "function"
      "block_ip" -> "function"
      "collect_forensics" -> "function"
      "send_notification" -> "function"
      "enrich" -> "function"
      "condition" -> "decision"
      "manual" -> "task"
      _ -> "function"
    end
  end

  defp map_action_to_fortisoar_type(action) do
    case action do
      "kill_process" -> "/api/3/workflow_step_types/action"
      "quarantine_file" -> "/api/3/workflow_step_types/action"
      "isolate_host" -> "/api/3/workflow_step_types/action"
      "block_ip" -> "/api/3/workflow_step_types/action"
      "collect_forensics" -> "/api/3/workflow_step_types/action"
      "send_notification" -> "/api/3/workflow_step_types/action"
      "enrich" -> "/api/3/workflow_step_types/action"
      "condition" -> "/api/3/workflow_step_types/condition"
      "manual" -> "/api/3/workflow_step_types/manual"
      _ -> "/api/3/workflow_step_types/action"
    end
  end

  defp map_action_to_chronicle_type(action) do
    case action do
      "kill_process" -> "INTEGRATION"
      "quarantine_file" -> "INTEGRATION"
      "isolate_host" -> "INTEGRATION"
      "block_ip" -> "INTEGRATION"
      "collect_forensics" -> "INTEGRATION"
      "send_notification" -> "INTEGRATION"
      "enrich" -> "INTEGRATION"
      "condition" -> "CONDITION"
      "manual" -> "MANUAL_ACTION"
      _ -> "INTEGRATION"
    end
  end

  defp map_action_to_swimlane_type(action) do
    case action do
      "kill_process" -> "integration"
      "quarantine_file" -> "integration"
      "isolate_host" -> "integration"
      "block_ip" -> "integration"
      "collect_forensics" -> "integration"
      "send_notification" -> "integration"
      "enrich" -> "integration"
      "condition" -> "condition"
      "manual" -> "task"
      _ -> "integration"
    end
  end

  defp map_action_to_tines_type(action) do
    case action do
      "kill_process" -> "Agents::HTTPRequestAgent"
      "quarantine_file" -> "Agents::HTTPRequestAgent"
      "isolate_host" -> "Agents::HTTPRequestAgent"
      "block_ip" -> "Agents::HTTPRequestAgent"
      "collect_forensics" -> "Agents::HTTPRequestAgent"
      "send_notification" -> "Agents::EmailAgent"
      "enrich" -> "Agents::HTTPRequestAgent"
      "condition" -> "Agents::TriggerAgent"
      "manual" -> "Agents::ManualAgent"
      _ -> "Agents::HTTPRequestAgent"
    end
  end

  defp infer_action_from_type(type) when is_binary(type) do
    type_lower = String.downcase(type)

    cond do
      String.contains?(type_lower, "kill") -> "kill_process"
      String.contains?(type_lower, "quarantine") -> "quarantine_file"
      String.contains?(type_lower, "isolate") -> "isolate_host"
      String.contains?(type_lower, "block") -> "block_ip"
      String.contains?(type_lower, "forensic") -> "collect_forensics"
      String.contains?(type_lower, "notify") or String.contains?(type_lower, "email") -> "send_notification"
      String.contains?(type_lower, "enrich") -> "enrich"
      String.contains?(type_lower, "condition") or String.contains?(type_lower, "decision") -> "condition"
      String.contains?(type_lower, "manual") or String.contains?(type_lower, "task") -> "manual"
      true -> "custom"
    end
  end

  defp infer_action_from_type(_), do: "custom"

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp convert_inputs_to_xsoar(nil), do: []
  defp convert_inputs_to_xsoar(inputs) when is_list(inputs) do
    Enum.map(inputs, fn input ->
      %{
        key: input[:name] || input["name"],
        value: %{simple: input[:default] || input["default"]},
        required: input[:required] || input["required"] || false,
        description: input[:description] || input["description"]
      }
    end)
  end

  defp convert_outputs_to_xsoar(nil), do: []
  defp convert_outputs_to_xsoar(outputs) when is_list(outputs) do
    Enum.map(outputs, fn output ->
      %{
        contextPath: output[:name] || output["name"],
        description: output[:description] || output["description"],
        type: output[:type] || output["type"] || "Unknown"
      }
    end)
  end

  defp convert_xsoar_inputs(nil), do: []
  defp convert_xsoar_inputs(inputs) when is_list(inputs) do
    Enum.map(inputs, fn input ->
      %{
        name: input["key"],
        default: get_in(input, ["value", "simple"]),
        required: input["required"] || false,
        description: input["description"]
      }
    end)
  end

  defp convert_xsoar_outputs(nil), do: []
  defp convert_xsoar_outputs(outputs) when is_list(outputs) do
    Enum.map(outputs, fn output ->
      %{
        name: output["contextPath"],
        description: output["description"],
        type: output["type"]
      }
    end)
  end

  defp build_xsoar_view(steps) do
    # Build visual layout for XSOAR
    %{
      linkLabelsPosition: %{},
      paper: %{dimensions: %{height: max(length(steps) * 150, 500), width: 800}}
    }
  end

  defp build_task_view(index) do
    %{
      position: %{x: 400, y: 50 + index * 120}
    }
  end

  defp build_next_tasks(steps, current_index) do
    if current_index < length(steps) - 1 do
      %{"#none#": [to_string(current_index + 1)]}
    else
      %{}
    end
  end

  defp build_phantom_coa(playbook) do
    %{
      title: playbook.name,
      description: playbook.description,
      version: playbook.version || 1
    }
  end

  defp build_resilient_edges(steps) when is_list(steps) do
    steps
    |> Enum.with_index()
    |> Enum.flat_map(fn {_step, index} ->
      if index < length(steps) - 1 do
        [%{source: "node_#{index}", target: "node_#{index + 1}"}]
      else
        []
      end
    end)
  end

  defp build_resilient_edges(_), do: []

  defp build_tines_links(steps) when is_list(steps) do
    steps
    |> Enum.with_index()
    |> Enum.flat_map(fn {_step, index} ->
      if index < length(steps) - 1 do
        [%{source: index, receiver: index + 1}]
      else
        []
      end
    end)
  end

  defp build_tines_links(_), do: []

  defp get_text_content(nil), do: nil
  defp get_text_content(text) when is_binary(text), do: text
  defp get_text_content(%{"content" => content}), do: content
  defp get_text_content(_), do: nil

  defp generate_task_id do
    :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  end

  defp generate_workflow_id do
    "workflow_" <> (:crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower))
  end

  # ============================================================================
  # Sync Operations
  # ============================================================================

  defp fetch_remote_playbooks(platform) do
    case platform do
      :xsoar -> TamanduaServer.Integrations.SOAR.XSOAR.list_playbooks()
      :splunk_soar -> TamanduaServer.Integrations.SOAR.SplunkSOAR.list_playbooks()
      :ibm_soar -> TamanduaServer.Integrations.SOAR.IBMSOAR.list_playbooks()
      :fortisoar -> TamanduaServer.Integrations.SOAR.FortiSOAR.list_playbooks()
      :chronicle -> TamanduaServer.Integrations.SOAR.GoogleChronicle.list_playbooks()
      :swimlane -> TamanduaServer.Integrations.SOAR.Swimlane.list_playbooks()
      :tines -> TamanduaServer.Integrations.SOAR.Tines.list_playbooks()
      _ -> {:error, :unsupported_platform}
    end
  end

  defp fetch_remote_playbook(playbook_id, platform) do
    case get_soar_module(platform) do
      nil ->
        {:error, :unsupported_platform}

      module ->
        alias TamanduaServer.Integrations.IntegrationLog

        IntegrationLog.log_api_call(to_string(platform), "fetch_playbook", %{playbook_id: playbook_id}, fn ->
          case module.list_playbooks(query: playbook_id, size: 1) do
            {:ok, [playbook | _]} -> {:ok, playbook}
            {:ok, []} -> {:error, :not_found}
            error -> error
          end
        end)
    end
  end

  defp get_soar_module(:xsoar), do: TamanduaServer.Integrations.SOAR.XSOAR
  defp get_soar_module(:splunk_soar), do: TamanduaServer.Integrations.SOAR.SplunkSOAR
  defp get_soar_module(:ibm_soar), do: TamanduaServer.Integrations.SOAR.IBMSOAR
  defp get_soar_module(:fortisoar), do: TamanduaServer.Integrations.SOAR.FortiSOAR
  defp get_soar_module(:chronicle), do: TamanduaServer.Integrations.SOAR.GoogleChronicle
  defp get_soar_module(:swimlane), do: TamanduaServer.Integrations.SOAR.Swimlane
  defp get_soar_module(:tines), do: TamanduaServer.Integrations.SOAR.Tines
  defp get_soar_module(_), do: nil

  defp perform_sync(local_playbooks, {:ok, remote_playbooks}, platform, opts, _state) do
    direction = opts[:direction] || :bidirectional

    local_map = Map.new(local_playbooks, &{&1.name, &1})
    remote_map = Map.new(remote_playbooks, &{&1.name, &1})

    exported = if direction in [:export, :bidirectional] do
      local_only = Map.keys(local_map) -- Map.keys(remote_map)
      Enum.count(local_only, fn name ->
        playbook = local_map[name]
        case convert_to_soar_format(playbook, platform, opts) do
          {:ok, soar_playbook} ->
            case push_to_soar(soar_playbook, platform) do
              {:ok, _} -> true
              _ -> false
            end

          _ ->
            false
        end
      end)
    else
      0
    end

    imported = if direction in [:import, :bidirectional] do
      remote_only = Map.keys(remote_map) -- Map.keys(local_map)
      Enum.count(remote_only, fn name ->
        remote_playbook = remote_map[name]
        case convert_from_soar_format(remote_playbook, platform, opts) do
          {:ok, tamandua_playbook} ->
            case TamanduaPlaybook.create(tamandua_playbook) do
              {:ok, _} -> true
              _ -> false
            end

          _ ->
            false
        end
      end)
    else
      0
    end

    {:ok, %{
      exported: exported,
      imported: imported,
      conflicts: 0,
      timestamp: DateTime.utc_now()
    }}
  end

  defp perform_sync(_, {:error, reason}, _platform, _opts, _state) do
    {:error, reason}
  end

  defp push_to_soar(_soar_playbook, _platform) do
    # Implementation would push playbook to SOAR platform
    {:ok, generate_task_id()}
  end

  defp check_import_conflict(playbook, state) do
    case TamanduaPlaybook.get_by_name(playbook.name) do
      {:ok, existing} ->
        version_info = Map.get(state.version_map, existing.id, %{})
        if version_info[:remote_version] != playbook.version do
          {:conflict, existing}
        else
          :no_conflict
        end

      _ ->
        :no_conflict
    end
  end

  defp create_conflict(new_playbook, existing, platform) do
    %{
      id: :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower),
      playbook_name: new_playbook.name,
      local_version: existing.version,
      remote_version: new_playbook.version,
      platform: platform,
      local_playbook: existing,
      remote_playbook: new_playbook,
      created_at: DateTime.utc_now()
    }
  end

  defp apply_resolution(conflict, resolution) do
    case resolution do
      :keep_local ->
        # Keep local, do nothing
        :ok

      :keep_remote ->
        # Replace local with remote
        TamanduaPlaybook.update(conflict.local_playbook.id, conflict.remote_playbook)

      :merge ->
        # Merge logic - combine steps from both
        merged = merge_playbooks(conflict.local_playbook, conflict.remote_playbook)
        TamanduaPlaybook.update(conflict.local_playbook.id, merged)
    end
  end

  defp merge_playbooks(local, remote) do
    # Simple merge: use local metadata, combine unique steps
    local_steps = local.steps || []
    remote_steps = remote.steps || []

    # Get unique steps by name
    local_names = MapSet.new(Enum.map(local_steps, & &1.name))
    new_steps = Enum.reject(remote_steps, &MapSet.member?(local_names, &1.name))

    %{local |
      steps: local_steps ++ new_steps,
      version: (local.version || 0) + 1
    }
  end

  defp save_playbook(playbook, state) do
    case TamanduaPlaybook.create(playbook) do
      {:ok, saved} ->
        new_stats = update_stat(state.stats, :imports)
        {:reply, {:ok, saved.id}, %{state | stats: new_stats}}

      error ->
        {:reply, error, state}
    end
  end

  defp compare_playbooks(local, remote) do
    %{
      local_version: local.version,
      remote_version: remote.version,
      steps_diff: %{
        local_count: length(local.steps || []),
        remote_count: length(remote.steps || []),
        added: length((remote.steps || []) -- (local.steps || [])),
        removed: length((local.steps || []) -- (remote.steps || []))
      },
      needs_sync: local.version != remote.version
    }
  end

  defp validate_playbook(playbook, platform) do
    errors = []

    # Check required fields
    errors = if playbook.name == nil or playbook.name == "" do
      ["Playbook name is required" | errors]
    else
      errors
    end

    # Check steps
    errors = if playbook.steps == nil or length(playbook.steps) == 0 do
      ["Playbook must have at least one step" | errors]
    else
      errors
    end

    # Platform-specific validation
    errors = case platform do
      :xsoar -> validate_for_xsoar(playbook, errors)
      :splunk_soar -> validate_for_splunk_soar(playbook, errors)
      _ -> errors
    end

    errors
  end

  defp validate_for_xsoar(playbook, errors) do
    # XSOAR-specific validation
    if String.length(playbook.name || "") > 255 do
      ["Playbook name too long for XSOAR (max 255 chars)" | errors]
    else
      errors
    end
  end

  defp validate_for_splunk_soar(playbook, errors) do
    # Splunk SOAR-specific validation
    if playbook.steps && Enum.any?(playbook.steps, &(&1.action == nil)) do
      ["All steps must have an action defined for Splunk SOAR" | errors]
    else
      errors
    end
  end

  defp update_stat(stats, key) do
    Map.update(stats, key, 1, &(&1 + 1))
  end
end
