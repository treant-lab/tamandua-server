defmodule TamanduaServer.Forensics.Engine do
  @moduledoc """
  Main forensic investigation engine.

  Manages full-lifecycle investigations linked to alerts, including:
  - Investigation creation, tracking, and closure
  - Timeline reconstruction from multiple telemetry sources
  - Forensic artifact collection requests to agents
  - Evidence chain-of-custody tracking with hashes and timestamps
  - State machine: open -> collecting -> analyzing -> reporting -> closed

  Investigations are tracked in ETS for fast access. Each investigation
  maintains a chain of custody log, collected evidence inventory, and
  links to source alerts and agents.
  """
  use GenServer
  require Logger

  alias TamanduaServer.Forensics.Timeline
  alias TamanduaServer.Forensics.ArtifactAnalyzer
  alias TamanduaServer.Agents

  # ETS tables
  @investigations_table :forensics_investigations
  @evidence_table :forensics_evidence
  @stats_table :forensics_stats

  # Valid investigation states
  @valid_states ~w(open collecting analyzing reporting closed)
  @valid_transitions %{
    "open" => ["collecting", "analyzing", "closed"],
    "collecting" => ["analyzing", "reporting", "closed"],
    "analyzing" => ["reporting", "closed"],
    "reporting" => ["closed", "analyzing"],
    "closed" => ["open"]
  }

  # Artifact types that can be requested from agents
  @artifact_types ~w(
    memory_dump process_memory mft_entries prefetch_files shimcache amcache
    event_log_security event_log_system event_log_powershell
    browser_history browser_downloads scheduled_tasks services autoruns
    registry_hive network_connections loaded_dlls open_files
    srum_data usnjrnl disk_image
  )

  # ── Client API ──────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Creates a new forensic investigation.

  ## Parameters
    - `params` - Map with:
      - `:title` (required) - Investigation title
      - `:description` - Detailed description
      - `:alert_ids` - List of alert IDs to link
      - `:agent_ids` - List of agent IDs under investigation
      - `:priority` - "low", "medium", "high", "critical" (default "medium")
      - `:assigned_to` - User ID of lead investigator
      - `:tags` - List of tags
      - `:created_by` - User ID of creator

  ## Returns
    - `{:ok, investigation}` on success
    - `{:error, reason}` on failure
  """
  @spec create_investigation(map()) :: {:ok, map()} | {:error, term()}
  def create_investigation(params) when is_map(params) do
    GenServer.call(__MODULE__, {:create_investigation, params})
  end

  @doc """
  Gets an investigation by ID.
  """
  @spec get_investigation(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_investigation(investigation_id) do
    GenServer.call(__MODULE__, {:get_investigation, investigation_id})
  end

  @doc """
  Lists investigations with optional filters.

  ## Filters
    - `:status` - Filter by state
    - `:priority` - Filter by priority
    - `:assigned_to` - Filter by assigned user
    - `:agent_id` - Filter by linked agent
    - `:alert_id` - Filter by linked alert
    - `:limit` - Max results (default 50)
    - `:offset` - Pagination offset (default 0)
  """
  @spec list_investigations(map()) :: {:ok, [map()]}
  def list_investigations(filters \\ %{}) do
    GenServer.call(__MODULE__, {:list_investigations, filters})
  end

  @doc """
  Transitions an investigation to a new state.

  Valid transitions:
    - open -> collecting, analyzing, closed
    - collecting -> analyzing, reporting, closed
    - analyzing -> reporting, closed
    - reporting -> closed, analyzing
    - closed -> open (reopen)
  """
  @spec transition_state(String.t(), String.t(), map()) :: {:ok, map()} | {:error, term()}
  def transition_state(investigation_id, new_state, opts \\ %{}) do
    GenServer.call(__MODULE__, {:transition_state, investigation_id, new_state, opts})
  end

  @doc """
  Adds an alert to an investigation.
  """
  @spec add_alert(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def add_alert(investigation_id, alert_id) do
    GenServer.call(__MODULE__, {:add_alert, investigation_id, alert_id})
  end

  @doc """
  Adds an agent to an investigation.
  """
  @spec add_agent(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def add_agent(investigation_id, agent_id) do
    GenServer.call(__MODULE__, {:add_agent, investigation_id, agent_id})
  end

  @doc """
  Requests specific forensic artifacts from an agent.

  ## Parameters
    - `investigation_id` - The investigation ID
    - `agent_id` - Target agent
    - `artifact_types` - List of artifact types (see @artifact_types)
    - `opts` - Collection options:
      - `:process_pid` - For targeted process memory dump
      - `:paths` - Specific file paths to collect
      - `:time_range` - Time range for event logs
      - `:requested_by` - User ID

  ## Returns
    - `{:ok, collection_request}` on success
  """
  @spec request_artifacts(String.t(), String.t(), [String.t()], map()) ::
          {:ok, map()} | {:error, term()}
  def request_artifacts(investigation_id, agent_id, artifact_types, opts \\ %{}) do
    GenServer.call(__MODULE__, {:request_artifacts, investigation_id, agent_id, artifact_types, opts})
  end

  @doc """
  Records evidence receipt into an investigation's chain of custody.

  ## Parameters
    - `investigation_id` - The investigation ID
    - `evidence` - Map with:
      - `:type` - Evidence type
      - `:source_agent_id` - Agent that provided it
      - `:hash_sha256` - SHA-256 hash of the evidence
      - `:hash_md5` - MD5 hash (optional)
      - `:size_bytes` - Size in bytes
      - `:storage_path` - Where evidence is stored
      - `:description` - Description
      - `:collected_by` - User or system ID
  """
  @spec record_evidence(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def record_evidence(investigation_id, evidence) do
    GenServer.call(__MODULE__, {:record_evidence, investigation_id, evidence})
  end

  @doc """
  Lists evidence for an investigation.
  """
  @spec list_evidence(String.t()) :: {:ok, [map()]} | {:error, :not_found}
  def list_evidence(investigation_id) do
    GenServer.call(__MODULE__, {:list_evidence, investigation_id})
  end

  @doc """
  Gets the unified timeline for an investigation, merging events from
  all linked agents across the investigation time range.
  """
  @spec get_timeline(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def get_timeline(investigation_id, opts \\ %{}) do
    GenServer.call(__MODULE__, {:get_timeline, investigation_id, opts}, 30_000)
  end

  @doc """
  Adds a note to the investigation log.
  """
  @spec add_note(String.t(), String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def add_note(investigation_id, user_id, content) do
    GenServer.call(__MODULE__, {:add_note, investigation_id, user_id, content})
  end

  @doc """
  Generates a forensic report for the investigation.

  Returns a structured report with timeline, evidence inventory,
  findings, indicators of compromise, and recommendations.
  """
  @spec generate_report(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def generate_report(investigation_id, opts \\ %{}) do
    GenServer.call(__MODULE__, {:generate_report, investigation_id, opts}, 60_000)
  end

  @doc """
  Closes an investigation with a final summary.
  """
  @spec close_investigation(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def close_investigation(investigation_id, summary \\ %{}) do
    GenServer.call(__MODULE__, {:close_investigation, investigation_id, summary})
  end

  @doc """
  Returns investigation statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Returns supported artifact types.
  """
  @spec artifact_types() :: [String.t()]
  def artifact_types, do: @artifact_types

  # ── GenServer Callbacks ─────────────────────────────────────────────

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@investigations_table, [:named_table, :public, :set, read_concurrency: true])
    :ets.new(@evidence_table, [:named_table, :public, :bag, read_concurrency: true])
    :ets.new(@stats_table, [:named_table, :public, :set, read_concurrency: true])

    # Initialize stats counters
    :ets.insert(@stats_table, {:total_created, 0})
    :ets.insert(@stats_table, {:total_closed, 0})
    :ets.insert(@stats_table, {:total_evidence, 0})
    :ets.insert(@stats_table, {:total_artifacts_requested, 0})

    Logger.info("[ForensicsEngine] Started — ETS tables initialized")
    {:ok, %{}}
  end

  @impl true
  def handle_call({:create_investigation, params}, _from, state) do
    title = Map.get(params, :title) || Map.get(params, "title")

    if is_nil(title) or title == "" do
      {:reply, {:error, :title_required}, state}
    else
      investigation = build_investigation(params)
      :ets.insert(@investigations_table, {investigation.id, investigation})
      increment_stat(:total_created)

      Logger.info("[ForensicsEngine] Created investigation #{investigation.id}: #{title}")
      {:reply, {:ok, investigation}, state}
    end
  end

  @impl true
  def handle_call({:get_investigation, id}, _from, state) do
    case :ets.lookup(@investigations_table, id) do
      [{^id, investigation}] -> {:reply, {:ok, investigation}, state}
      [] -> {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:list_investigations, filters}, _from, state) do
    investigations =
      :ets.tab2list(@investigations_table)
      |> Enum.map(fn {_id, inv} -> inv end)
      |> apply_filters(filters)
      |> Enum.sort_by(& &1.updated_at, {:desc, DateTime})
      |> apply_pagination(filters)

    {:reply, {:ok, investigations}, state}
  end

  @impl true
  def handle_call({:transition_state, id, new_state, opts}, _from, state) do
    with {:ok, investigation} <- lookup(id),
         :ok <- validate_transition(investigation.status, new_state) do
      user_id = Map.get(opts, :user_id) || Map.get(opts, "user_id") || "system"
      reason = Map.get(opts, :reason) || Map.get(opts, "reason") || ""

      log_entry = %{
        action: "state_transition",
        from: investigation.status,
        to: new_state,
        user_id: user_id,
        reason: reason,
        timestamp: DateTime.utc_now()
      }

      updated = %{investigation |
        status: new_state,
        updated_at: DateTime.utc_now(),
        activity_log: investigation.activity_log ++ [log_entry]
      }

      :ets.insert(@investigations_table, {id, updated})
      {:reply, {:ok, updated}, state}
    else
      {:error, _} = error -> {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:add_alert, id, alert_id}, _from, state) do
    with {:ok, investigation} <- lookup(id) do
      if alert_id in investigation.alert_ids do
        {:reply, {:ok, investigation}, state}
      else
        log_entry = %{
          action: "alert_added",
          alert_id: alert_id,
          timestamp: DateTime.utc_now()
        }

        updated = %{investigation |
          alert_ids: investigation.alert_ids ++ [alert_id],
          updated_at: DateTime.utc_now(),
          activity_log: investigation.activity_log ++ [log_entry]
        }

        :ets.insert(@investigations_table, {id, updated})
        {:reply, {:ok, updated}, state}
      end
    else
      error -> {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:add_agent, id, agent_id}, _from, state) do
    with {:ok, investigation} <- lookup(id) do
      if agent_id in investigation.agent_ids do
        {:reply, {:ok, investigation}, state}
      else
        log_entry = %{
          action: "agent_added",
          agent_id: agent_id,
          timestamp: DateTime.utc_now()
        }

        updated = %{investigation |
          agent_ids: investigation.agent_ids ++ [agent_id],
          updated_at: DateTime.utc_now(),
          activity_log: investigation.activity_log ++ [log_entry]
        }

        :ets.insert(@investigations_table, {id, updated})
        {:reply, {:ok, updated}, state}
      end
    else
      error -> {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:request_artifacts, inv_id, agent_id, types, opts}, _from, state) do
    with {:ok, investigation} <- lookup(inv_id),
         :ok <- validate_artifact_types(types) do
      request_id = generate_id()
      now = DateTime.utc_now()
      requested_by = Map.get(opts, :requested_by) || Map.get(opts, "requested_by") || "system"

      collection_request = %{
        id: request_id,
        investigation_id: inv_id,
        agent_id: agent_id,
        artifact_types: types,
        status: "pending",
        process_pid: Map.get(opts, :process_pid) || Map.get(opts, "process_pid"),
        paths: Map.get(opts, :paths) || Map.get(opts, "paths") || [],
        time_range: Map.get(opts, :time_range) || Map.get(opts, "time_range"),
        requested_by: requested_by,
        requested_at: now
      }

      log_entry = %{
        action: "artifacts_requested",
        agent_id: agent_id,
        artifact_types: types,
        request_id: request_id,
        requested_by: requested_by,
        timestamp: now
      }

      updated = %{investigation |
        status: if(investigation.status == "open", do: "collecting", else: investigation.status),
        artifact_requests: investigation.artifact_requests ++ [collection_request],
        updated_at: now,
        activity_log: investigation.activity_log ++ [log_entry]
      }

      # Ensure agent is tracked
      updated = if agent_id in updated.agent_ids do
        updated
      else
        %{updated | agent_ids: updated.agent_ids ++ [agent_id]}
      end

      :ets.insert(@investigations_table, {inv_id, updated})
      increment_stat(:total_artifacts_requested)

      # Send collection command to the agent asynchronously
      dispatch_collection(collection_request)

      {:reply, {:ok, collection_request}, state}
    else
      {:error, _} = error -> {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:record_evidence, inv_id, evidence_data}, _from, state) do
    with {:ok, investigation} <- lookup(inv_id) do
      evidence_id = generate_id()
      now = DateTime.utc_now()

      evidence = %{
        id: evidence_id,
        investigation_id: inv_id,
        type: Map.get(evidence_data, :type) || Map.get(evidence_data, "type") || "unknown",
        source_agent_id: Map.get(evidence_data, :source_agent_id) || Map.get(evidence_data, "source_agent_id"),
        hash_sha256: Map.get(evidence_data, :hash_sha256) || Map.get(evidence_data, "hash_sha256"),
        hash_md5: Map.get(evidence_data, :hash_md5) || Map.get(evidence_data, "hash_md5"),
        size_bytes: Map.get(evidence_data, :size_bytes) || Map.get(evidence_data, "size_bytes"),
        storage_path: Map.get(evidence_data, :storage_path) || Map.get(evidence_data, "storage_path"),
        description: Map.get(evidence_data, :description) || Map.get(evidence_data, "description"),
        collected_by: Map.get(evidence_data, :collected_by) || Map.get(evidence_data, "collected_by") || "system",
        collected_at: now,
        chain_of_custody: [
          %{
            action: "received",
            user_id: Map.get(evidence_data, :collected_by) || "system",
            timestamp: now,
            notes: "Evidence received and recorded"
          }
        ],
        metadata: Map.get(evidence_data, :metadata) || Map.get(evidence_data, "metadata") || %{}
      }

      # Insert into evidence ETS table
      :ets.insert(@evidence_table, {inv_id, evidence})

      log_entry = %{
        action: "evidence_recorded",
        evidence_id: evidence_id,
        evidence_type: evidence.type,
        hash_sha256: evidence.hash_sha256,
        timestamp: now
      }

      updated = %{investigation |
        evidence_count: investigation.evidence_count + 1,
        updated_at: now,
        activity_log: investigation.activity_log ++ [log_entry]
      }

      :ets.insert(@investigations_table, {inv_id, updated})
      increment_stat(:total_evidence)

      {:reply, {:ok, evidence}, state}
    else
      error -> {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:list_evidence, inv_id}, _from, state) do
    case :ets.lookup(@investigations_table, inv_id) do
      [{^inv_id, _}] ->
        evidence =
          :ets.lookup(@evidence_table, inv_id)
          |> Enum.map(fn {_inv_id, ev} -> ev end)
          |> Enum.sort_by(& &1.collected_at, {:desc, DateTime})

        {:reply, {:ok, evidence}, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:get_timeline, inv_id, opts}, _from, state) do
    with {:ok, investigation} <- lookup(inv_id) do
      timeline_opts = %{
        agent_ids: investigation.agent_ids,
        from: Map.get(opts, :from) || investigation.created_at,
        to: Map.get(opts, :to) || DateTime.utc_now(),
        event_types: Map.get(opts, :event_types),
        process_filter: Map.get(opts, :process_filter),
        user_filter: Map.get(opts, :user_filter),
        severity_filter: Map.get(opts, :severity_filter),
        limit: Map.get(opts, :limit, 2000),
        format: Map.get(opts, :format, "json")
      }

      result = Timeline.build_unified_timeline(timeline_opts)
      {:reply, result, state}
    else
      error -> {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:add_note, inv_id, user_id, content}, _from, state) do
    with {:ok, investigation} <- lookup(inv_id) do
      now = DateTime.utc_now()

      log_entry = %{
        action: "note_added",
        user_id: user_id,
        content: content,
        timestamp: now
      }

      updated = %{investigation |
        notes: investigation.notes ++ [log_entry],
        updated_at: now,
        activity_log: investigation.activity_log ++ [log_entry]
      }

      :ets.insert(@investigations_table, {inv_id, updated})
      {:reply, {:ok, updated}, state}
    else
      error -> {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:generate_report, inv_id, opts}, _from, state) do
    with {:ok, investigation} <- lookup(inv_id) do
      report = do_generate_report(investigation, opts)

      log_entry = %{
        action: "report_generated",
        timestamp: DateTime.utc_now(),
        format: Map.get(opts, :format, "json")
      }

      updated = %{investigation |
        status: if(investigation.status in ["analyzing", "collecting"], do: "reporting", else: investigation.status),
        updated_at: DateTime.utc_now(),
        activity_log: investigation.activity_log ++ [log_entry]
      }

      :ets.insert(@investigations_table, {inv_id, updated})
      {:reply, {:ok, report}, state}
    else
      error -> {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:close_investigation, inv_id, summary}, _from, state) do
    with {:ok, investigation} <- lookup(inv_id) do
      now = DateTime.utc_now()

      log_entry = %{
        action: "investigation_closed",
        summary: summary,
        timestamp: now
      }

      updated = %{investigation |
        status: "closed",
        closed_at: now,
        summary: summary,
        updated_at: now,
        activity_log: investigation.activity_log ++ [log_entry]
      }

      :ets.insert(@investigations_table, {inv_id, updated})
      increment_stat(:total_closed)

      Logger.info("[ForensicsEngine] Closed investigation #{inv_id}")
      {:reply, {:ok, updated}, state}
    else
      error -> {:reply, error, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = compile_stats()
    {:reply, stats, state}
  end

  @impl true
  def handle_info({:collection_result, request_id, result}, state) do
    # Handle artifact collection results from agents
    handle_collection_result(request_id, result)
    {:noreply, state}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.debug("[ForensicsEngine] Unexpected message: #{inspect(msg)}")
    {:noreply, state}
  end

  # ── Private: Investigation Builder ──────────────────────────────────

  defp build_investigation(params) do
    now = DateTime.utc_now()
    id = generate_id()

    %{
      id: id,
      title: Map.get(params, :title) || Map.get(params, "title"),
      description: Map.get(params, :description) || Map.get(params, "description") || "",
      status: "open",
      priority: Map.get(params, :priority) || Map.get(params, "priority") || "medium",
      alert_ids: normalize_list(Map.get(params, :alert_ids) || Map.get(params, "alert_ids")),
      agent_ids: normalize_list(Map.get(params, :agent_ids) || Map.get(params, "agent_ids")),
      assigned_to: Map.get(params, :assigned_to) || Map.get(params, "assigned_to"),
      created_by: Map.get(params, :created_by) || Map.get(params, "created_by"),
      tags: normalize_list(Map.get(params, :tags) || Map.get(params, "tags")),
      notes: [],
      artifact_requests: [],
      evidence_count: 0,
      findings: [],
      summary: nil,
      created_at: now,
      updated_at: now,
      closed_at: nil,
      activity_log: [
        %{
          action: "investigation_created",
          user_id: Map.get(params, :created_by) || Map.get(params, "created_by") || "system",
          timestamp: now
        }
      ]
    }
  end

  # ── Private: State Validation ───────────────────────────────────────

  defp validate_transition(current, new_state) do
    if new_state in @valid_states do
      allowed = Map.get(@valid_transitions, current, [])
      if new_state in allowed do
        :ok
      else
        {:error, {:invalid_transition, current, new_state}}
      end
    else
      {:error, {:invalid_state, new_state}}
    end
  end

  defp validate_artifact_types(types) when is_list(types) do
    invalid = Enum.reject(types, &(&1 in @artifact_types))
    if invalid == [] do
      :ok
    else
      {:error, {:invalid_artifact_types, invalid}}
    end
  end

  defp validate_artifact_types(_), do: {:error, :artifact_types_must_be_list}

  # ── Private: Filtering & Pagination ────────────────────────────────

  defp apply_filters(investigations, filters) when is_map(filters) do
    investigations
    |> maybe_filter_field(filters, :status, "status")
    |> maybe_filter_field(filters, :priority, "priority")
    |> maybe_filter_field(filters, :assigned_to, "assigned_to")
    |> maybe_filter_member(filters, :agent_id, "agent_id", :agent_ids)
    |> maybe_filter_member(filters, :alert_id, "alert_id", :alert_ids)
  end

  defp maybe_filter_field(list, filters, atom_key, string_key) do
    value = Map.get(filters, atom_key) || Map.get(filters, string_key)
    if value do
      Enum.filter(list, fn inv -> Map.get(inv, atom_key) == value end)
    else
      list
    end
  end

  defp maybe_filter_member(list, filters, atom_key, string_key, member_field) do
    value = Map.get(filters, atom_key) || Map.get(filters, string_key)
    if value do
      Enum.filter(list, fn inv -> value in Map.get(inv, member_field, []) end)
    else
      list
    end
  end

  defp apply_pagination(list, filters) do
    limit = to_integer(Map.get(filters, :limit) || Map.get(filters, "limit"), 50)
    offset = to_integer(Map.get(filters, :offset) || Map.get(filters, "offset"), 0)

    list
    |> Enum.drop(offset)
    |> Enum.take(limit)
  end

  # ── Private: Collection Dispatch ───────────────────────────────────

  defp dispatch_collection(request) do
    Task.Supervisor.start_child(
      TamanduaServer.TaskSupervisor,
      fn -> send_collection_command(request) end
    )
  rescue
    _ ->
      spawn(fn -> send_collection_command(request) end)
  end

  defp send_collection_command(request) do
    command = %{
      type: "collect_forensics",
      request_id: request.id,
      investigation_id: request.investigation_id,
      artifact_types: request.artifact_types,
      options: %{
        process_pid: request.process_pid,
        paths: request.paths,
        time_range: request.time_range,
        compress: true,
        encrypt: true
      }
    }

    case Agents.send_command(request.agent_id, command) do
      :ok ->
        Logger.info("[ForensicsEngine] Collection command sent to agent #{request.agent_id}")

      {:ok, _} ->
        Logger.info("[ForensicsEngine] Collection command sent to agent #{request.agent_id}")

      {:error, reason} ->
        Logger.warning("[ForensicsEngine] Failed to send collection to agent #{request.agent_id}: #{inspect(reason)}")
    end
  rescue
    e ->
      Logger.warning("[ForensicsEngine] Collection dispatch error: #{Exception.message(e)}")
  end

  defp handle_collection_result(request_id, result) do
    # Find the investigation that owns this request
    :ets.tab2list(@investigations_table)
    |> Enum.find(fn {_id, inv} ->
      Enum.any?(inv.artifact_requests, fn r -> r.id == request_id end)
    end)
    |> case do
      {inv_id, investigation} ->
        now = DateTime.utc_now()

        # Update the request status
        updated_requests = Enum.map(investigation.artifact_requests, fn r ->
          if r.id == request_id do
            %{r | status: result[:status] || "completed"}
          else
            r
          end
        end)

        log_entry = %{
          action: "collection_result_received",
          request_id: request_id,
          status: result[:status] || "completed",
          timestamp: now
        }

        updated = %{investigation |
          artifact_requests: updated_requests,
          updated_at: now,
          activity_log: investigation.activity_log ++ [log_entry]
        }

        :ets.insert(@investigations_table, {inv_id, updated})

      nil ->
        Logger.warning("[ForensicsEngine] Received result for unknown request: #{request_id}")
    end
  end

  # ── Private: Report Generation ─────────────────────────────────────

  defp do_generate_report(investigation, opts) do
    now = DateTime.utc_now()

    # Collect evidence
    evidence =
      :ets.lookup(@evidence_table, investigation.id)
      |> Enum.map(fn {_id, ev} -> ev end)

    # Build timeline summary
    timeline_summary = build_timeline_summary(investigation)

    # Analyze artifacts if any evidence was collected
    artifact_analysis = analyze_collected_artifacts(evidence)

    # Extract IOCs from the investigation data
    iocs = extract_investigation_iocs(investigation, evidence)

    # Build findings
    findings = build_findings(investigation, evidence, artifact_analysis)

    report_format = Map.get(opts, :format, "json")

    report = %{
      id: generate_id(),
      investigation_id: investigation.id,
      title: "Forensic Report: #{investigation.title}",
      generated_at: now,
      format: report_format,
      investigation_summary: %{
        id: investigation.id,
        title: investigation.title,
        description: investigation.description,
        status: investigation.status,
        priority: investigation.priority,
        created_at: investigation.created_at,
        duration_hours: DateTime.diff(now, investigation.created_at, :second) / 3600,
        alert_count: length(investigation.alert_ids),
        agent_count: length(investigation.agent_ids),
        evidence_count: investigation.evidence_count
      },
      timeline_summary: timeline_summary,
      evidence_inventory: Enum.map(evidence, fn ev ->
        %{
          id: ev.id,
          type: ev.type,
          source_agent_id: ev.source_agent_id,
          hash_sha256: ev.hash_sha256,
          size_bytes: ev.size_bytes,
          collected_at: ev.collected_at,
          chain_of_custody_entries: length(ev.chain_of_custody)
        }
      end),
      artifact_analysis: artifact_analysis,
      indicators_of_compromise: iocs,
      findings: findings,
      recommendations: build_recommendations(investigation, findings),
      activity_log: investigation.activity_log,
      notes: investigation.notes
    }

    report
  end

  defp build_timeline_summary(investigation) do
    case Timeline.build_unified_timeline(%{
      agent_ids: investigation.agent_ids,
      from: investigation.created_at,
      to: DateTime.utc_now(),
      limit: 500
    }) do
      {:ok, timeline} ->
        %{
          total_events: timeline.total_events,
          event_type_distribution: timeline.event_type_distribution,
          time_range: %{
            from: timeline.from,
            to: timeline.to
          },
          notable_events: Enum.take(timeline.notable_events, 20)
        }

      {:error, _} ->
        %{
          total_events: 0,
          event_type_distribution: %{},
          time_range: %{from: investigation.created_at, to: DateTime.utc_now()},
          notable_events: []
        }
    end
  end

  defp analyze_collected_artifacts(evidence) do
    evidence
    |> Enum.filter(fn ev -> ev.type in ["prefetch_files", "shimcache", "amcache", "srum_data"] end)
    |> Enum.map(fn ev ->
      case ArtifactAnalyzer.analyze(ev.type, ev.metadata) do
        {:ok, analysis} -> %{evidence_id: ev.id, type: ev.type, analysis: analysis}
        {:error, _} -> %{evidence_id: ev.id, type: ev.type, analysis: %{status: "analysis_failed"}}
      end
    end)
  end

  defp extract_investigation_iocs(_investigation, evidence) do
    # Extract from evidence metadata
    evidence_iocs = evidence
    |> Enum.flat_map(fn ev ->
      meta = ev.metadata || %{}
      iocs = meta["iocs"] || meta[:iocs] || []
      if is_list(iocs), do: iocs, else: []
    end)

    # Extract hashes as IOCs
    hash_iocs = evidence
    |> Enum.filter(fn ev -> ev.hash_sha256 && ev.hash_sha256 != "" end)
    |> Enum.map(fn ev ->
      %{type: "hash_sha256", value: ev.hash_sha256, source: "evidence_#{ev.id}"}
    end)

    (evidence_iocs ++ hash_iocs)
    |> Enum.uniq_by(fn ioc ->
      value = ioc[:value] || ioc["value"] || ""
      type = ioc[:type] || ioc["type"] || ""
      "#{type}:#{value}"
    end)
  end

  defp build_findings(_investigation, evidence, artifact_analysis) do
    findings = []

    # Flag high-entropy evidence (potential packed/encrypted malware)
    findings = evidence
    |> Enum.filter(fn ev ->
      meta = ev.metadata || %{}
      entropy = meta["entropy"] || meta[:entropy]
      is_number(entropy) and entropy > 7.5
    end)
    |> Enum.reduce(findings, fn ev, acc ->
      [%{
        severity: "high",
        type: "high_entropy_artifact",
        description: "Evidence #{ev.id} (#{ev.type}) has high entropy, suggesting packed or encrypted content",
        evidence_id: ev.id
      } | acc]
    end)

    # Flag suspicious artifact analysis results
    findings = artifact_analysis
    |> Enum.filter(fn aa ->
      analysis = aa.analysis
      score = analysis[:suspiciousness_score] || analysis["suspiciousness_score"] || 0
      score > 70
    end)
    |> Enum.reduce(findings, fn aa, acc ->
      [%{
        severity: "medium",
        type: "suspicious_artifact",
        description: "Artifact analysis flagged #{aa.type} as suspicious (evidence #{aa.evidence_id})",
        evidence_id: aa.evidence_id
      } | acc]
    end)

    Enum.reverse(findings)
  end

  defp build_recommendations(_investigation, findings) do
    recommendations = []

    has_high_findings = Enum.any?(findings, fn f -> f.severity == "high" end)
    has_suspicious = Enum.any?(findings, fn f -> f.type == "suspicious_artifact" end)

    recommendations = if has_high_findings do
      ["Escalate investigation -- high-severity findings detected" | recommendations]
    else
      recommendations
    end

    recommendations = if has_suspicious do
      ["Submit suspicious artifacts to sandbox for dynamic analysis" | recommendations]
    else
      recommendations
    end

    recommendations = ["Review timeline for lateral movement indicators" | recommendations]
    recommendations = ["Cross-reference IOCs with threat intelligence feeds" | recommendations]

    Enum.reverse(recommendations)
  end

  # ── Private: Statistics ─────────────────────────────────────────────

  defp compile_stats do
    all = :ets.tab2list(@investigations_table) |> Enum.map(fn {_id, inv} -> inv end)

    by_status = Enum.frequencies_by(all, & &1.status)
    by_priority = Enum.frequencies_by(all, & &1.priority)

    total_created = get_stat(:total_created)
    total_closed = get_stat(:total_closed)
    total_evidence = get_stat(:total_evidence)
    total_artifacts_requested = get_stat(:total_artifacts_requested)

    # Calculate average investigation duration for closed cases
    closed = Enum.filter(all, fn inv -> inv.status == "closed" and inv.closed_at end)
    avg_duration_hours = if length(closed) > 0 do
      total_hours = Enum.reduce(closed, 0, fn inv, acc ->
        acc + DateTime.diff(inv.closed_at, inv.created_at, :second) / 3600
      end)
      Float.round(total_hours / length(closed), 1)
    else
      0.0
    end

    %{
      total_investigations: length(all),
      active_investigations: length(all) - Map.get(by_status, "closed", 0),
      by_status: by_status,
      by_priority: by_priority,
      total_created: total_created,
      total_closed: total_closed,
      total_evidence_items: total_evidence,
      total_artifacts_requested: total_artifacts_requested,
      average_duration_hours: avg_duration_hours
    }
  end

  defp increment_stat(key) do
    :ets.update_counter(@stats_table, key, {2, 1})
  rescue
    _ -> :ok
  end

  defp get_stat(key) do
    case :ets.lookup(@stats_table, key) do
      [{^key, value}] -> value
      [] -> 0
    end
  end

  # ── Private: Helpers ────────────────────────────────────────────────

  defp lookup(id) do
    case :ets.lookup(@investigations_table, id) do
      [{^id, investigation}] -> {:ok, investigation}
      [] -> {:error, :not_found}
    end
  end

  defp generate_id do
    :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  end

  defp normalize_list(nil), do: []
  defp normalize_list(list) when is_list(list), do: list
  defp normalize_list(value), do: [value]

  defp to_integer(nil, default), do: default
  defp to_integer(v, _default) when is_integer(v), do: v
  defp to_integer(v, default) when is_binary(v) do
    case Integer.parse(v) do
      {n, _} -> n
      :error -> default
    end
  end
  defp to_integer(_, default), do: default
end
