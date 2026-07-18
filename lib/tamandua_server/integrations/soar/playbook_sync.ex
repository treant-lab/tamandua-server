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
  @spec get_version_info(String.t(), term()) :: {:ok, map()} | {:error, term()}
  def get_version_info(playbook_id, scope \\ nil) do
    GenServer.call(__MODULE__, {:get_version_info, playbook_id, scope})
  end

  @doc """
  Compare playbook versions between Tamandua and SOAR.
  """
  @spec compare_versions(String.t(), atom(), term()) :: {:ok, map()} | {:error, term()}
  def compare_versions(playbook_id, platform, scope \\ nil) do
    GenServer.call(__MODULE__, {:compare_versions, playbook_id, platform, scope}, 30_000)
  end

  @doc """
  Resolve a sync conflict.
  """
  @spec resolve_conflict(String.t(), :keep_local | :keep_remote | :merge, term()) ::
          :ok | {:error, term()}
  def resolve_conflict(conflict_id, resolution, scope \\ nil) do
    GenServer.call(__MODULE__, {:resolve_conflict, conflict_id, resolution, scope})
  end

  @doc """
  Get pending conflicts.
  """
  @spec get_conflicts(term()) :: {:ok, [map()]} | {:error, term()}
  def get_conflicts(scope \\ nil) do
    GenServer.call(__MODULE__, {:get_conflicts, scope})
  end

  @doc """
  Validate a playbook for export to a specific platform.
  """
  @spec validate_for_export(String.t(), atom(), term()) :: {:ok, []} | {:error, term()}
  def validate_for_export(playbook_id, platform, scope \\ nil) do
    GenServer.call(__MODULE__, {:validate_for_export, playbook_id, platform, scope})
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
    case engine_get_playbook(playbook_id, opts[:scope]) do
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
      case engine_get_playbook(id, opts[:scope]) do
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
        case check_import_conflict(tamandua_playbook, state, opts[:scope]) do
          {:conflict, existing} ->
            conflict = create_conflict(tamandua_playbook, existing, platform, opts[:scope])
            new_state = %{state | conflict_log: [conflict | state.conflict_log]}

            if opts[:force] do
              save_playbook(tamandua_playbook, new_state, opts[:scope])
            else
              {:reply, {:error, {:conflict, conflict.id}}, new_state}
            end

          :no_conflict ->
            save_playbook(tamandua_playbook, state, opts[:scope])
        end

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:sync_playbooks, platform, opts}, _from, state) do
    # Get local playbooks
    case engine_list_playbooks(opts[:scope]) do
      {:ok, local_playbooks} ->
        # Get remote playbooks
        remote_playbooks = fetch_remote_playbooks(platform)

        # Compare and sync
        sync_result = perform_sync(local_playbooks, remote_playbooks, platform, opts, state)

        new_stats = state.stats
        |> update_stat(:syncs)
        |> Map.put(:last_sync, DateTime.utc_now())

        {:reply, sync_result, %{state | stats: new_stats}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_version_info, playbook_id, scope}, _from, state) do
    version_info = Map.get(state.version_map, {scope, playbook_id}, %{
      local_version: nil,
      remote_versions: %{},
      last_sync: nil
    })

    reply = if valid_scope?(scope), do: {:ok, version_info}, else: {:error, :tenant_required}
    {:reply, reply, state}
  end

  @impl true
  def handle_call({:compare_versions, playbook_id, platform, scope}, _from, state) do
    case engine_get_playbook(playbook_id, scope) do
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
  def handle_call({:resolve_conflict, conflict_id, resolution, scope}, _from, state) do
    if valid_scope?(scope) do
      case Enum.find(state.conflict_log, &(&1.id == conflict_id and &1.scope == scope)) do
        nil ->
          {:reply, {:error, :conflict_not_found}, state}

        conflict ->
          case apply_resolution(conflict, resolution) do
            :ok ->
              new_log =
                Enum.reject(state.conflict_log, &(&1.id == conflict_id and &1.scope == scope))

              new_stats = update_stat(state.stats, :conflicts_resolved)
              {:reply, :ok, %{state | conflict_log: new_log, stats: new_stats}}

            error ->
              {:reply, error, state}
          end
        end
    else
      {:reply, {:error, :tenant_required}, state}
    end
  end

  @impl true
  def handle_call({:get_conflicts, scope}, _from, state) do
    if valid_scope?(scope) do
      conflicts = Enum.filter(state.conflict_log, &(&1.scope == scope))
      {:reply, {:ok, conflicts}, state}
    else
      {:reply, {:error, :tenant_required}, state}
    end
  end

  @impl true
  def handle_call({:validate_for_export, playbook_id, platform, scope}, _from, state) do
    case engine_get_playbook(playbook_id, scope) do
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
  #
  # NOTE: Response.Playbook.Schema has NO playbook-level `inputs`, `outputs`
  # or `version` fields (see playbook.ex Schema), and persisted steps are
  # string-keyed maps. The old dot access (playbook.inputs, playbook.version,
  # step.name, ...) raised KeyError at runtime for every persisted playbook —
  # masked by the blanket rescue in convert_to_soar_format/3, so exports
  # always failed. field_value/3 reads what actually exists (and passes
  # through :inputs/:outputs/:version when the value is a plain map, e.g. a
  # SOAR payload being round-tripped) instead of inventing schema fields.
  defp convert_to_xsoar(playbook, _opts) do
    steps = field_value(playbook, :steps, [])

    %{
      id: field_value(playbook, :id),
      name: field_value(playbook, :name),
      description: field_value(playbook, :description),
      version: field_value(playbook, :version) || 1,
      fromVersion: "6.0.0",
      tasks: convert_steps_to_xsoar_tasks(steps),
      inputs: convert_inputs_to_xsoar(field_value(playbook, :inputs)),
      outputs: convert_outputs_to_xsoar(field_value(playbook, :outputs)),
      starttaskid: "0",
      view: build_xsoar_view(steps),
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
      name: field_value(playbook, :name),
      description: field_value(playbook, :description),
      playbook_type: "automation",
      python_version: "3",
      blocks: convert_steps_to_phantom_blocks(field_value(playbook, :steps, [])),
      # Schema has no inputs/outputs fields; only plain-map payloads carry them.
      inputs: field_value(playbook, :inputs, []),
      outputs: field_value(playbook, :outputs, []),
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
    steps = field_value(playbook, :steps, [])

    %{
      name: field_value(playbook, :name),
      display_name: field_value(playbook, :name),
      description: %{format: "text", content: field_value(playbook, :description, "")},
      workflow: %{
        workflow_id: generate_workflow_id(),
        content: %{
          nodes: convert_steps_to_resilient_nodes(steps),
          edges: build_resilient_edges(steps)
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
      name: field_value(playbook, :name),
      description: field_value(playbook, :description),
      isActive: true,
      triggerType: "manual",
      priority: 5,
      steps: convert_steps_to_fortisoar_steps(field_value(playbook, :steps, [])),
      # Schema has no inputs/outputs fields; only plain-map payloads carry them.
      parameters: field_value(playbook, :inputs, []),
      outputs: field_value(playbook, :outputs, [])
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
      name: field_value(playbook, :name),
      display_name: field_value(playbook, :name),
      description: field_value(playbook, :description),
      trigger_type: "MANUAL",
      is_enabled: true,
      blocks: convert_steps_to_chronicle_blocks(field_value(playbook, :steps, [])),
      # Schema has no inputs field; only plain-map payloads carry it.
      parameters: field_value(playbook, :inputs, [])
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
      name: field_value(playbook, :name),
      description: field_value(playbook, :description),
      enabled: true,
      actions: convert_steps_to_swimlane_actions(field_value(playbook, :steps, [])),
      triggers: [%{type: "manual"}],
      # Schema has no inputs field; only plain-map payloads carry it.
      inputs: field_value(playbook, :inputs, [])
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
    steps = field_value(playbook, :steps, [])

    %{
      name: field_value(playbook, :name),
      description: field_value(playbook, :description),
      agents: convert_steps_to_tines_agents(steps),
      links: build_tines_links(steps)
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

  # Persisted playbook steps are string-keyed maps (Schema normalize_steps/1
  # coerces every key to a string); fresh SOAR conversions are atom-keyed.
  # Dot access (step.name, step.action, ...) raised KeyError on the persisted
  # shape, so field_value/3 is used throughout the step converters.
  defp convert_steps_to_xsoar_tasks(steps) when is_list(steps) do
    steps
    |> Enum.with_index()
    |> Enum.map(fn {step, index} ->
      {to_string(index), %{
        id: to_string(index),
        taskid: generate_task_id(),
        type: map_action_to_xsoar_type(field_value(step, :action)),
        task: %{
          id: generate_task_id(),
          name: field_value(step, :name) || field_value(step, :action),
          description: field_value(step, :description, ""),
          script: field_value(step, :script),
          scriptarguments: field_value(step, :parameters, %{})
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
        name: field_value(step, :name) || field_value(step, :action),
        type: map_action_to_phantom_type(field_value(step, :action)),
        action: field_value(step, :action),
        parameters: field_value(step, :parameters, %{}),
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
        type: map_action_to_resilient_type(field_value(step, :action)),
        name: field_value(step, :name) || field_value(step, :action),
        properties: field_value(step, :parameters, %{})
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
        name: field_value(step, :name) || field_value(step, :action),
        stepType: map_action_to_fortisoar_type(field_value(step, :action)),
        arguments: field_value(step, :parameters, %{})
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
        name: field_value(step, :name) || field_value(step, :action),
        type: map_action_to_chronicle_type(field_value(step, :action)),
        parameters: field_value(step, :parameters, %{})
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
        name: field_value(step, :name) || field_value(step, :action),
        actionType: map_action_to_swimlane_type(field_value(step, :action)),
        inputs: field_value(step, :parameters, %{})
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
        name: field_value(step, :name) || field_value(step, :action),
        type: map_action_to_tines_type(field_value(step, :action)),
        options: field_value(step, :parameters, %{})
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
      title: field_value(playbook, :name),
      description: field_value(playbook, :description),
      # Schema has no version field; only plain-map payloads carry one.
      version: field_value(playbook, :version) || 1
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
            case engine_create_playbook(tamandua_playbook, opts[:scope]) do
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

  defp check_import_conflict(playbook, state, scope) do
    case engine_get_playbook_by_name(field_value(playbook, :name), scope) do
      {:ok, existing} ->
        version_info = Map.get(state.version_map, {scope, existing.id}, %{})

        # Some convert_from_* results carry no :version key (IBM/Tines), and
        # dot access raised KeyError there; nil is an honest "unknown version".
        if version_info[:remote_version] != field_value(playbook, :version) do
          {:conflict, existing}
        else
          :no_conflict
        end

      _ ->
        :no_conflict
    end
  end

  defp create_conflict(new_playbook, existing, platform, scope) do
    %{
      id: :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower),
      playbook_name: field_value(new_playbook, :name),
      # Schema has no version field, so the local version is honestly nil;
      # remote version comes from the SOAR payload when present.
      local_version: field_value(existing, :version),
      remote_version: field_value(new_playbook, :version),
      platform: platform,
      scope: scope,
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
        engine_update_playbook(conflict.local_playbook.id, conflict.remote_playbook, conflict.scope)

      :merge ->
        # Merge logic - combine steps from both
        merged = merge_playbooks(conflict.local_playbook, conflict.remote_playbook)
        engine_update_playbook(conflict.local_playbook.id, merged, conflict.scope)
    end
  end

  defp merge_playbooks(local, remote) do
    # Simple merge: use local metadata, combine unique steps.
    local_steps = field_value(local, :steps, [])
    remote_steps = field_value(remote, :steps, [])

    # Steps may be string-keyed (persisted JSONB) or atom-keyed (fresh SOAR
    # conversions); compare identity by name across both shapes.
    local_names =
      local_steps
      |> Enum.map(&field_value(&1, :name))
      |> MapSet.new()
    new_steps = Enum.reject(remote_steps, &MapSet.member?(local_names, field_value(&1, :name)))

    # `local` is a Playbook.Schema struct with no :version field, so the old
    # `%{local | version: ...}` raised KeyError. There is no local version
    # tracking on the schema to bump; return plain map attrs (the engine
    # changeset requires plain maps anyway) with only the merged steps.
    local
    |> sanitize_playbook_attrs()
    |> Map.put(:steps, local_steps ++ new_steps)
  end

  defp save_playbook(playbook, state, scope) do
    case engine_create_playbook(playbook, scope) do
      {:ok, saved} ->
        new_stats = update_stat(state.stats, :imports)
        {:reply, {:ok, saved.id}, %{state | stats: new_stats}}

      error ->
        {:reply, error, state}
    end
  end

  defp compare_playbooks(local, remote) do
    local_steps = field_value(local, :steps, [])
    remote_steps = field_value(remote, :steps, [])
    local_version = field_value(local, :version)
    remote_version = field_value(remote, :version)

    %{
      local_version: local_version,
      remote_version: remote_version,
      steps_diff: %{
        local_count: length(local_steps),
        remote_count: length(remote_steps),
        added: length(remote_steps -- local_steps),
        removed: length(local_steps -- remote_steps)
      },
      needs_sync: local_version != remote_version
    }
  end

  defp validate_playbook(playbook, platform) do
    errors = []
    name = field_value(playbook, :name)
    steps = field_value(playbook, :steps, [])

    errors =
      if is_nil(name) or name == "" do
        ["Playbook name is required" | errors]
      else
        errors
      end

    errors =
      if length(steps) == 0 do
        ["Playbook must have at least one step" | errors]
      else
        errors
      end

    errors = case platform do
      :xsoar -> validate_for_xsoar(playbook, errors)
      :splunk_soar -> validate_for_splunk_soar(playbook, errors)
      _ -> errors
    end

    errors
  end

  defp validate_for_xsoar(playbook, errors) do
    # XSOAR-specific validation
    if String.length(field_value(playbook, :name, "") || "") > 255 do
      ["Playbook name too long for XSOAR (max 255 chars)" | errors]
    else
      errors
    end
  end

  defp validate_for_splunk_soar(playbook, errors) do
    # Splunk SOAR-specific validation
    steps = field_value(playbook, :steps, [])

    if Enum.any?(steps, &(field_value(&1, :action) == nil)) do
      ["All steps must have an action defined for Splunk SOAR" | errors]
    else
      errors
    end
  end

  defp update_stat(stats, key) do
    Map.update(stats, key, 1, &(&1 + 1))
  end

  # ============================================================================
  # Playbook Engine Bridge
  # ============================================================================
  # The real local playbook API is TamanduaServer.Response.Playbook. Scope is
  # always explicit so imports, exports, versions and conflicts stay tenant-bound.
  # The engine is a GenServer, so a stopped/crashed engine surfaces as an EXIT
  # from GenServer.call, not an exception — catch :exit and degrade honestly.

  defp engine_get_playbook(id, scope) do
    TamanduaPlaybook.get_playbook(id, scope)
  catch
    :exit, _ -> {:error, :playbook_engine_unavailable}
  end

  defp engine_list_playbooks(scope) do
    TamanduaPlaybook.list_playbooks(%{}, scope)
  catch
    :exit, _ -> {:error, :playbook_engine_unavailable}
  end

  defp engine_create_playbook(attrs, scope) do
    TamanduaPlaybook.create_playbook(sanitize_playbook_attrs(attrs), scope)
  catch
    :exit, _ -> {:error, :playbook_engine_unavailable}
  end

  defp engine_update_playbook(id, attrs, scope) do
    TamanduaPlaybook.update_playbook(id, sanitize_playbook_attrs(attrs), scope)
  catch
    :exit, _ -> {:error, :playbook_engine_unavailable}
  end

  # The engine exposes no name-based lookup; resolve via list_playbooks/0.
  defp engine_get_playbook_by_name(name, scope) do
    case engine_list_playbooks(scope) do
      {:ok, playbooks} ->
        case Enum.find(playbooks, &(field_value(&1, :name) == name)) do
          nil -> {:error, :not_found}
          playbook -> {:ok, playbook}
        end

      error ->
        error
    end
  end

  # Converted SOAR payloads are plain maps, but merge results
  # (merge_playbooks/2) are Playbook schema structs; the engine's
  # Schema.changeset/2 requires plain map params.
  defp sanitize_playbook_attrs(%_{} = struct) do
    struct |> Map.from_struct() |> Map.delete(:__meta__)
  end

  defp sanitize_playbook_attrs(attrs) when is_map(attrs), do: attrs

  defp valid_scope?(:system), do: true

  defp valid_scope?({:organization, organization_id}),
    do: is_binary(organization_id) and organization_id != ""

  defp valid_scope?(_scope), do: false

  defp field_value(value, key, default \\ nil)

  defp field_value(%_{} = struct, key, default) when is_atom(key) do
    struct
    |> Map.from_struct()
    |> Map.get(key, default)
  end

  defp field_value(map, key, default) when is_map(map) and is_atom(key) do
    Map.get(map, key, Map.get(map, Atom.to_string(key), default))
  end

  defp field_value(_value, _key, default), do: default
end
