defmodule TamanduaServer.Detection.Storyline do
  @moduledoc """
  Autonomous Storyline Engine - SentinelOne-style attack chain reconstruction.

  Maintains process tree graphs per agent and automatically:
  1. Groups related detections into Incidents (storylines)
  2. Propagates risk scores through parent-child process relationships
  3. Reconstructs full attack chains from individual detections

  Architecture:
  - ETS table for process trees ({organization_id, agent_id} -> process graph)
  - ETS table for active storylines (storyline_id -> incident data)
  - Score propagation: child detection increases parent score (upward)
  - Context inheritance: parent context flows to children (downward)

  Thread safety: All mutations go through the GenServer. ETS reads are direct
  for performance (public read_concurrency tables).
  """

  use GenServer
  require Logger

  @process_tree_table :tamandua_process_trees
  @storyline_table :tamandua_storylines
  @pid_to_storyline_table :tamandua_pid_to_storyline

  # Score decay factor when propagating upward to ancestors
  @ancestor_decay 0.7
  # Score factor for context inheritance to children
  @child_context_factor 0.5
  # Storyline score threshold for creating/escalating incident alerts
  @incident_threshold 70.0
  # Process node TTL: 24 hours in seconds
  @process_ttl_seconds 86_400
  # Cleanup interval: every 15 minutes
  @cleanup_interval_ms 900_000

  # ------------------------------------------------------------------
  # Structs
  # ------------------------------------------------------------------

  defmodule ProcessNode do
    @moduledoc false
    defstruct [
      :pid,
      :ppid,
      :name,
      :path,
      :cmdline,
      :start_time,
      :exit_time,
      :user,
      :sha256,
      :is_elevated,
      :is_signed,
      :organization_id,
      children: [],
      risk_score: 0.0,
      context_score: 0.0,
      detections: [],
      storyline_id: nil,
      terminated: false
    ]
  end

  defmodule StorylineData do
    @moduledoc false
    defstruct [
      :id,
      :agent_id,
      :organization_id,
      :root_pid,
      :created_at,
      :updated_at,
      :alert_id,
      processes: MapSet.new(),
      detections: [],
      total_score: 0.0,
      severity: :low,
      status: :active,
      mitre_tactics: MapSet.new(),
      mitre_techniques: MapSet.new()
    ]
  end

  # ------------------------------------------------------------------
  # Client API
  # ------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Ingest a process create/exit event to maintain the process tree.

  Called from the telemetry pipeline for every process lifecycle event.
  """
  @spec ingest_process_event(String.t(), map()) :: :ok
  def ingest_process_event(agent_id, event) do
    with_organization(agent_id, fn organization_id ->
      GenServer.cast(__MODULE__, {:process_event, organization_id, agent_id, event})
    end)
  end

  @doc """
  Ingest a detection to link it to a storyline.

  Called by Detection.Engine after a detection is created. Finds or creates
  a storyline for the process, propagates scores, and broadcasts severity
  changes.
  """
  @spec ingest_detection(String.t(), map()) :: :ok
  def ingest_detection(agent_id, detection) do
    with_organization(agent_id, fn organization_id ->
      GenServer.cast(__MODULE__, {:detection, organization_id, agent_id, detection})
    end)
  end

  @doc """
  Get a full storyline by its ID. Returns the storyline struct with all
  processes and detections.
  """
  @spec get_storyline(String.t(), String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_storyline(organization_id, storyline_id) do
    case :ets.lookup(@storyline_table, storyline_id) do
      [{^storyline_id, %{organization_id: ^organization_id} = storyline}] ->
        {:ok, serialize_storyline(storyline)}

      _ ->
        {:error, :not_found}
    end
  end

  @doc "List storylines belonging to one organization."
  @spec list_storylines(String.t(), keyword()) :: {:ok, [map()]}
  def list_storylines(organization_id, opts \\ []) do
    {:ok, tenant_storylines(organization_id, opts)}
  end

  @doc """
  List active storylines for an agent.

  Options:
  - `:status` - Filter by status (:active, :resolved). Default: all.
  - `:min_severity` - Minimum severity (:low, :medium, :high, :critical).
  - `:limit` - Maximum results. Default: 50.
  """
  @spec get_agent_storylines(String.t(), String.t(), keyword()) :: {:ok, [map()]}
  def get_agent_storylines(organization_id, agent_id, opts \\ []) do
    {:ok, tenant_storylines(organization_id, Keyword.put(opts, :agent_id, agent_id))}
  end

  @doc """
  Merge two storylines when they are discovered to be related.
  The second storyline is absorbed into the first.
  """
  @spec merge_storylines(String.t(), String.t(), String.t()) :: :ok | {:error, term()}
  def merge_storylines(organization_id, storyline_id_1, storyline_id_2) do
    GenServer.call(__MODULE__, {:merge, organization_id, storyline_id_1, storyline_id_2})
  end

  @doc """
  Return summary statistics about the Storyline engine state.
  """
  @spec stats(String.t()) :: map()
  def stats(organization_id) do
    GenServer.call(__MODULE__, {:stats, organization_id})
  end

  # ------------------------------------------------------------------
  # Server Callbacks
  # ------------------------------------------------------------------

  @impl true
  def init(_opts) do
    # Create ETS tables with public read access for concurrent lookups
    :ets.new(@process_tree_table, [
      :set,
      :public,
      :named_table,
      read_concurrency: true
    ])

    :ets.new(@storyline_table, [
      :set,
      :public,
      :named_table,
      read_concurrency: true
    ])

    :ets.new(@pid_to_storyline_table, [
      :set,
      :public,
      :named_table,
      read_concurrency: true
    ])

    # Schedule periodic cleanup
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)

    Logger.info("[Storyline] Autonomous Storyline Engine started")

    {:ok,
     %{
       stats_by_organization: %{}
     }}
  end

  # -- Process events --------------------------------------------------

  @impl true
  def handle_cast({:process_event, organization_id, agent_id, event}, state) do
    handle_process_event(organization_id, agent_id, event)

    {:noreply,
     update_in(state.stats_by_organization, fn stats_by_org ->
       increment_tenant_counter(stats_by_org, organization_id, :process_events)
     end)}
  end

  # -- Detections ------------------------------------------------------

  @impl true
  def handle_cast({:detection, organization_id, agent_id, detection}, state) do
    {storyline_created, incident_created} =
      handle_detection(organization_id, agent_id, detection)

    counters =
      state.stats_by_organization
      |> increment_tenant_counter(organization_id, :detections_ingested)
      |> maybe_increment_tenant_counter(organization_id, :storylines_created, storyline_created)
      |> maybe_increment_tenant_counter(organization_id, :incidents_created, incident_created)

    {:noreply, %{state | stats_by_organization: counters}}
  end

  # -- Merges ----------------------------------------------------------

  @impl true
  def handle_call({:merge, organization_id, id1, id2}, _from, state) do
    result = do_merge_storylines(organization_id, id1, id2)

    counters =
      maybe_increment_tenant_counter(
        state.stats_by_organization,
        organization_id,
        :storylines_merged,
        result == :ok
      )

    {:reply, result, %{state | stats_by_organization: counters}}
  end

  @impl true
  def handle_call({:stats, organization_id}, _from, state) do
    reply = %{
      process_tree_size: tenant_process_tree_size(organization_id),
      storyline_count: tenant_storyline_count(organization_id),
      pid_mappings: tenant_pid_mapping_count(organization_id),
      counters: Map.get(state.stats_by_organization, organization_id, empty_counters())
    }

    {:reply, reply, state}
  end

  # -- Periodic cleanup ------------------------------------------------

  @impl true
  def handle_info(:cleanup, state) do
    removed = cleanup_expired_nodes()

    stats_by_organization =
      Map.new(state.stats_by_organization, fn {organization_id, counters} ->
        {organization_id, Map.update!(counters, :cleanups, &(&1 + 1))}
      end)

    if removed > 0 do
      Logger.info("[Storyline] Cleanup removed #{removed} expired process nodes")
    end

    Process.send_after(self(), :cleanup, @cleanup_interval_ms)
    {:noreply, %{state | stats_by_organization: stats_by_organization}}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ------------------------------------------------------------------
  # Process Event Handling
  # ------------------------------------------------------------------

  defp handle_process_event(organization_id, agent_id, event) do
    payload = event[:payload] || event["payload"] || %{}
    event_type = to_string(event[:event_type] || event["event_type"] || "")

    case event_type do
      type when type in ["process_create", "process"] ->
        handle_process_create(organization_id, agent_id, payload)

      type when type in ["process_terminate", "process_exit"] ->
        handle_process_exit(organization_id, agent_id, payload)

      _ ->
        :ok
    end
  end

  defp handle_process_create(organization_id, agent_id, payload) do
    pid = get_payload_int(payload, "pid")
    ppid = get_payload_int(payload, "ppid")

    if pid do
      node = %ProcessNode{
        pid: pid,
        ppid: ppid,
        name: payload["name"] || payload[:name],
        path: payload["path"] || payload[:path] || payload["image_path"] || payload[:image_path],
        cmdline:
          payload["cmdline"] || payload[:cmdline] || payload["command_line"] ||
            payload[:command_line],
        start_time: DateTime.utc_now(),
        user: payload["user"] || payload[:user],
        sha256: payload["sha256"] || payload[:sha256],
        is_elevated: payload["is_elevated"] || payload[:is_elevated] || false,
        is_signed: payload["is_signed"] || payload[:is_signed],
        organization_id: organization_id
      }

      key = process_key(organization_id, agent_id, pid)
      :ets.insert(@process_tree_table, {key, node})

      # Register as child of parent
      if ppid do
        parent_key = process_key(organization_id, agent_id, ppid)

        case :ets.lookup(@process_tree_table, parent_key) do
          [{^parent_key, %{organization_id: ^organization_id} = parent}] ->
            updated_parent = %{parent | children: Enum.uniq([pid | parent.children])}
            :ets.insert(@process_tree_table, {parent_key, updated_parent})

            # Inherit parent's storyline if it has one
            if parent.organization_id == organization_id &&
                 storyline_belongs_to?(parent.storyline_id, organization_id) do
              assign_pid_to_storyline(organization_id, agent_id, pid, parent.storyline_id)
              updated_node = %{node | storyline_id: parent.storyline_id}
              :ets.insert(@process_tree_table, {key, updated_node})

              # Add process to the storyline's process set
              case :ets.lookup(@storyline_table, parent.storyline_id) do
                [{sid, %{organization_id: ^organization_id} = storyline}] ->
                  updated = %{
                    storyline
                    | processes: MapSet.put(storyline.processes, pid),
                      updated_at: DateTime.utc_now()
                  }

                  :ets.insert(@storyline_table, {sid, updated})

                _ ->
                  :ok
              end
            end

          _ ->
            :ok
        end
      end
    end
  end

  defp handle_process_exit(organization_id, agent_id, payload) do
    pid = get_payload_int(payload, "pid")

    if pid do
      key = process_key(organization_id, agent_id, pid)

      case :ets.lookup(@process_tree_table, key) do
        [{^key, %{organization_id: ^organization_id} = node}] ->
          updated = %{node | terminated: true, exit_time: DateTime.utc_now()}
          :ets.insert(@process_tree_table, {key, updated})

        _ ->
          :ok
      end
    end
  end

  # ------------------------------------------------------------------
  # Detection Handling
  # ------------------------------------------------------------------

  defp handle_detection(organization_id, agent_id, detection) do
    payload = detection[:payload] || detection["payload"] || detection[:raw_event] || %{}
    pid = get_payload_int(payload, "pid") || get_payload_int(detection, "pid")

    detections = detection[:detections] || [detection]
    score = calculate_detection_score(detection)

    mitre_tactics =
      detections
      |> Enum.flat_map(fn d -> d[:mitre_tactics] || [] end)
      |> MapSet.new()

    mitre_techniques =
      detections
      |> Enum.flat_map(fn d -> d[:mitre_techniques] || [] end)
      |> MapSet.new()

    detection_record = %{
      id: detection[:event_id] || detection[:alert_id] || Ecto.UUID.generate(),
      event_type: detection[:event_type],
      score: score,
      title: detection[:title] || build_detection_title(detections),
      mitre_tactics: MapSet.to_list(mitre_tactics),
      mitre_techniques: MapSet.to_list(mitre_techniques),
      timestamp: DateTime.utc_now()
    }

    # Find or create storyline for this process
    {storyline_id, storyline_created} =
      find_or_create_storyline(organization_id, agent_id, pid, detection_record)

    # Add detection to the storyline
    add_detection_to_storyline(
      organization_id,
      storyline_id,
      detection_record,
      mitre_tactics,
      mitre_techniques
    )

    # Update the process node with detection info
    if pid do
      key = process_key(organization_id, agent_id, pid)

      case :ets.lookup(@process_tree_table, key) do
        [{^key, %{organization_id: ^organization_id} = node}] ->
          updated = %{
            node
            | risk_score: node.risk_score + score,
              detections: [detection_record | node.detections],
              storyline_id: storyline_id
          }

          :ets.insert(@process_tree_table, {key, updated})

        _ ->
          :ok
      end
    end

    # Propagate scores through process tree
    propagate_scores_upward(organization_id, agent_id, pid, score)
    propagate_context_downward(organization_id, agent_id, pid, score)

    # Check if storyline crosses incident threshold
    incident_created = maybe_create_incident(organization_id, storyline_id, agent_id)

    {storyline_created, incident_created}
  end

  defp find_or_create_storyline(organization_id, agent_id, pid, _detection_record) do
    cond do
      # 1. Process already in a storyline
      pid && has_storyline?(organization_id, agent_id, pid) ->
        {get_storyline_for_pid(organization_id, agent_id, pid), false}

      # 2. Process has a parent in a storyline
      pid && parent_has_storyline?(organization_id, agent_id, pid) ->
        storyline_id = get_parent_storyline(organization_id, agent_id, pid)
        assign_pid_to_storyline(organization_id, agent_id, pid, storyline_id)
        {storyline_id, false}

      # 3. Create new storyline
      true ->
        storyline_id = Ecto.UUID.generate()
        now = DateTime.utc_now()

        storyline = %StorylineData{
          id: storyline_id,
          agent_id: agent_id,
          organization_id: organization_id,
          root_pid: pid,
          created_at: now,
          updated_at: now,
          processes: if(pid, do: MapSet.new([pid]), else: MapSet.new()),
          detections: [],
          total_score: 0.0,
          severity: :low,
          status: :active,
          mitre_tactics: MapSet.new(),
          mitre_techniques: MapSet.new()
        }

        :ets.insert(@storyline_table, {storyline_id, storyline})

        if pid do
          assign_pid_to_storyline(organization_id, agent_id, pid, storyline_id)
        end

        Logger.debug(
          "[Storyline] Created new storyline #{storyline_id} for agent #{agent_id}, root PID #{inspect(pid)}"
        )

        {storyline_id, true}
    end
  end

  defp add_detection_to_storyline(
         organization_id,
         storyline_id,
         detection_record,
         mitre_tactics,
         mitre_techniques
       ) do
    case :ets.lookup(@storyline_table, storyline_id) do
      [{^storyline_id, %{organization_id: ^organization_id} = storyline}] ->
        if duplicate_detection?(storyline, detection_record) do
          :ok
        else
          updated = %{
            storyline
            | detections: [detection_record | storyline.detections],
              total_score: storyline.total_score + detection_record.score,
              mitre_tactics: MapSet.union(storyline.mitre_tactics, mitre_tactics),
              mitre_techniques: MapSet.union(storyline.mitre_techniques, mitre_techniques),
              updated_at: DateTime.utc_now()
          }

          # Recalculate severity
          updated = %{updated | severity: calculate_severity(updated)}

          :ets.insert(@storyline_table, {storyline_id, updated})

          # Broadcast if severity changed
          if updated.severity != storyline.severity do
            broadcast_severity_change(updated)
          end
        end

      _ ->
        :ok
    end
  end

  defp duplicate_detection?(storyline, detection_record) do
    detection_id = detection_record.id

    Enum.any?(storyline.detections, fn existing ->
      existing.id == detection_id
    end)
  end

  # ------------------------------------------------------------------
  # Score Propagation
  # ------------------------------------------------------------------

  defp propagate_scores_upward(organization_id, agent_id, pid, score)
       when is_integer(pid) and pid > 0 do
    key = process_key(organization_id, agent_id, pid)

    case :ets.lookup(@process_tree_table, key) do
      [{^key, %{organization_id: ^organization_id} = node}]
      when is_integer(node.ppid) and node.ppid > 0 ->
        propagate_to_ancestor(organization_id, agent_id, node.ppid, score, @ancestor_decay, 10)

      _ ->
        :ok
    end
  end

  defp propagate_scores_upward(_organization_id, _agent_id, _pid, _score), do: :ok

  defp propagate_to_ancestor(_organization_id, _agent_id, _pid, _score, _decay, 0), do: :ok

  defp propagate_to_ancestor(_organization_id, _agent_id, _pid, score, _decay, _depth)
       when score < 0.1,
       do: :ok

  defp propagate_to_ancestor(organization_id, agent_id, pid, score, decay, depth) do
    key = process_key(organization_id, agent_id, pid)
    contribution = score * decay

    case :ets.lookup(@process_tree_table, key) do
      [{^key, %{organization_id: ^organization_id} = node}] ->
        updated = %{node | risk_score: node.risk_score + contribution}
        :ets.insert(@process_tree_table, {key, updated})

        # If this ancestor is in a storyline, update storyline total
        if node.storyline_id do
          case :ets.lookup(@storyline_table, node.storyline_id) do
            [{sid, %{organization_id: ^organization_id} = storyline}] ->
              updated_sl = %{
                storyline
                | total_score: storyline.total_score + contribution,
                  updated_at: DateTime.utc_now()
              }

              :ets.insert(@storyline_table, {sid, updated_sl})

            _ ->
              :ok
          end
        end

        # Continue up the tree
        if is_integer(node.ppid) and node.ppid > 0 do
          propagate_to_ancestor(
            organization_id,
            agent_id,
            node.ppid,
            score,
            decay * @ancestor_decay,
            depth - 1
          )
        end

      _ ->
        :ok
    end
  end

  defp propagate_context_downward(organization_id, agent_id, pid, score)
       when is_integer(pid) and pid > 0 do
    key = process_key(organization_id, agent_id, pid)

    case :ets.lookup(@process_tree_table, key) do
      [{^key, %{organization_id: ^organization_id} = node}] ->
        context_contribution = score * @child_context_factor

        Enum.each(node.children, fn child_pid ->
          propagate_context_to_child(organization_id, agent_id, child_pid, context_contribution)
        end)

      _ ->
        :ok
    end
  end

  defp propagate_context_downward(_organization_id, _agent_id, _pid, _score), do: :ok

  defp propagate_context_to_child(organization_id, agent_id, child_pid, context_score)
       when context_score >= 0.1 do
    key = process_key(organization_id, agent_id, child_pid)

    case :ets.lookup(@process_tree_table, key) do
      [{^key, %{organization_id: ^organization_id} = node}] ->
        updated = %{node | context_score: node.context_score + context_score}
        :ets.insert(@process_tree_table, {key, updated})

      _ ->
        :ok
    end
  end

  defp propagate_context_to_child(_organization_id, _agent_id, _child_pid, _context_score),
    do: :ok

  # ------------------------------------------------------------------
  # Incident Creation
  # ------------------------------------------------------------------

  defp maybe_create_incident(organization_id, storyline_id, agent_id) do
    case :ets.lookup(@storyline_table, storyline_id) do
      [{^storyline_id, %{organization_id: ^organization_id} = storyline}] ->
        if storyline.total_score >= @incident_threshold and is_nil(storyline.alert_id) do
          create_incident_alert(storyline, agent_id)
          true
        else
          if storyline.alert_id do
            # Update existing alert if severity changed
            update_incident_alert(storyline)
          end

          false
        end

      _ ->
        false
    end
  end

  defp create_incident_alert(storyline, agent_id) do
    tactics = MapSet.to_list(storyline.mitre_tactics)
    techniques = MapSet.to_list(storyline.mitre_techniques)

    title = build_incident_title(storyline)
    description = build_incident_description(storyline)

    alert_attrs = %{
      agent_id: agent_id,
      organization_id: storyline.organization_id,
      severity: to_string(storyline.severity),
      title: title,
      description: description,
      event_ids: storyline.detections |> Enum.map(& &1.id) |> Enum.take(100),
      mitre_tactics: tactics,
      mitre_techniques: techniques,
      threat_score: min(storyline.total_score / 100.0, 1.0),
      storyline_id: storyline.id,
      detection_metadata: %{
        "rule_type" => "storyline_incident",
        "rule_name" => "Storyline Incident: #{title}",
        "storyline_id" => storyline.id,
        "process_count" => MapSet.size(storyline.processes),
        "detection_count" => length(storyline.detections),
        "confidence" => min(storyline.total_score / 100.0, 1.0)
      },
      evidence: %{
        "storyline_id" => storyline.id,
        "processes" => MapSet.to_list(storyline.processes),
        "total_score" => storyline.total_score,
        "tactics" => tactics,
        "techniques" => techniques
      }
    }

    case TamanduaServer.Alerts.create_alert(alert_attrs) do
      {:ok, alert} ->
        # Link alert back to storyline
        updated = %{storyline | alert_id: alert.id}
        :ets.insert(@storyline_table, {storyline.id, updated})

        Logger.warning(
          "[Storyline] Incident alert created: #{alert.id} for storyline #{storyline.id} " <>
            "(score: #{storyline.total_score}, severity: #{storyline.severity})"
        )

        # Persist immediately on incident creation (critical data)
        TamanduaServer.Detection.StorylinePersistence.persist_storyline(storyline.id)

        broadcast_incident_created(updated, alert)

      {:error, changeset} ->
        Logger.error("[Storyline] Failed to create incident alert: #{inspect(changeset)}")
    end
  end

  defp update_incident_alert(storyline) do
    if storyline.alert_id do
      try do
        case TamanduaServer.Alerts.get_alert_for_org(
               storyline.organization_id,
               storyline.alert_id
             ) do
          {:error, :not_found} ->
            :ok

          {:ok, alert} ->
            new_severity = to_string(storyline.severity)
            new_score = min(storyline.total_score / 100.0, 1.0)

            TamanduaServer.Alerts.update_alert(alert, %{
              severity: new_severity,
              threat_score: new_score,
              mitre_tactics: MapSet.to_list(storyline.mitre_tactics),
              mitre_techniques: MapSet.to_list(storyline.mitre_techniques)
            })
        end
      rescue
        _ -> :ok
      catch
        :exit, _ -> :ok
      end
    end
  end

  # ------------------------------------------------------------------
  # Storyline Merge
  # ------------------------------------------------------------------

  defp do_merge_storylines(organization_id, id1, id2) do
    with [{^id1, s1}] <- :ets.lookup(@storyline_table, id1),
         [{^id2, s2}] <- :ets.lookup(@storyline_table, id2),
         true <- s1.organization_id == organization_id,
         true <- s2.organization_id == organization_id do
      if id1 == id2 do
        {:error, :same_storyline}
      else
        merge_tenant_storylines(organization_id, id1, id2, s1, s2)
      end
    else
      _ -> {:error, :not_found}
    end
  end

  defp merge_tenant_storylines(organization_id, id1, id2, s1, s2) do
    merged = %{
      s1
      | processes: MapSet.union(s1.processes, s2.processes),
        detections: s1.detections ++ s2.detections,
        total_score: s1.total_score + s2.total_score,
        mitre_tactics: MapSet.union(s1.mitre_tactics, s2.mitre_tactics),
        mitre_techniques: MapSet.union(s1.mitre_techniques, s2.mitre_techniques),
        updated_at: DateTime.utc_now()
    }

    merged = %{merged | severity: calculate_severity(merged)}

    :ets.insert(@storyline_table, {id1, merged})

    # Re-point all PIDs from s2 to s1
    s2.processes
    |> MapSet.to_list()
    |> Enum.each(fn pid ->
      :ets.insert(
        @pid_to_storyline_table,
        {process_key(organization_id, s2.agent_id, pid), id1}
      )

      # Update process node
      key = process_key(organization_id, s2.agent_id, pid)

      case :ets.lookup(@process_tree_table, key) do
        [{^key, %{organization_id: ^organization_id} = node}] ->
          :ets.insert(@process_tree_table, {key, %{node | storyline_id: id1}})

        _ ->
          :ok
      end
    end)

    # Delete the absorbed storyline
    :ets.delete(@storyline_table, id2)

    Logger.info("[Storyline] Merged storyline #{id2} into #{id1}")

    :ok
  end

  # ------------------------------------------------------------------
  # Cleanup
  # ------------------------------------------------------------------

  defp cleanup_expired_nodes do
    cutoff = DateTime.utc_now() |> DateTime.add(-@process_ttl_seconds, :second)

    expired_keys =
      :ets.tab2list(@process_tree_table)
      |> Enum.filter(fn {_key, node} ->
        # Evict terminated nodes past TTL, OR any node whose start is older than
        # the TTL window. The latter reclaims nodes whose terminate/exit event
        # was never received (missed exits, agent crash, dropped telemetry),
        # which would otherwise leak forever on an always-on server.
        (node.terminated and node.exit_time != nil and
           DateTime.compare(node.exit_time, cutoff) == :lt) or
          DateTime.compare(node.start_time, cutoff) == :lt
      end)
      |> Enum.map(fn {key, _node} -> key end)

    Enum.each(expired_keys, fn key ->
      :ets.delete(@process_tree_table, key)
      :ets.delete(@pid_to_storyline_table, key)
    end)

    # Also cleanup storylines with no recent activity. Sweep by inactivity
    # (updated_at older than the TTL window) regardless of status: storylines
    # are created with status :active and no code path sets :resolved, so the
    # previous status-gated filter never evicted anything and the table (with
    # its growing detection lists) leaked for the server's lifetime.
    storyline_cutoff = DateTime.utc_now() |> DateTime.add(-@process_ttl_seconds, :second)

    :ets.tab2list(@storyline_table)
    |> Enum.filter(fn {_id, s} ->
      DateTime.compare(s.updated_at, storyline_cutoff) == :lt
    end)
    |> Enum.each(fn {id, _s} -> :ets.delete(@storyline_table, id) end)

    length(expired_keys)
  end

  # ------------------------------------------------------------------
  # Severity Calculation
  # ------------------------------------------------------------------

  defp calculate_severity(storyline) do
    total_score = storyline.total_score
    unique_tactics = MapSet.size(storyline.mitre_tactics)
    _process_count = MapSet.size(storyline.processes)

    cond do
      total_score > 90 or unique_tactics >= 4 -> :critical
      total_score > 70 or unique_tactics >= 3 -> :high
      total_score > 40 or unique_tactics >= 2 -> :medium
      true -> :low
    end
  end

  # ------------------------------------------------------------------
  # Helpers
  # ------------------------------------------------------------------

  defp has_storyline?(organization_id, agent_id, pid) do
    get_storyline_for_pid(organization_id, agent_id, pid) != nil
  end

  defp get_storyline_for_pid(organization_id, agent_id, pid) do
    key = process_key(organization_id, agent_id, pid)

    case :ets.lookup(@pid_to_storyline_table, key) do
      [{^key, sid}] -> if storyline_belongs_to?(sid, organization_id), do: sid
      _ -> nil
    end
  end

  defp parent_has_storyline?(organization_id, agent_id, pid) do
    key = process_key(organization_id, agent_id, pid)

    case :ets.lookup(@process_tree_table, key) do
      [{^key, %{organization_id: ^organization_id} = node}]
      when is_integer(node.ppid) and node.ppid > 0 ->
        has_storyline?(organization_id, agent_id, node.ppid)

      _ ->
        false
    end
  end

  defp get_parent_storyline(organization_id, agent_id, pid) do
    key = process_key(organization_id, agent_id, pid)

    case :ets.lookup(@process_tree_table, key) do
      [{^key, %{organization_id: ^organization_id} = node}]
      when is_integer(node.ppid) and node.ppid > 0 ->
        get_storyline_for_pid(organization_id, agent_id, node.ppid)

      _ ->
        nil
    end
  end

  defp assign_pid_to_storyline(organization_id, agent_id, pid, storyline_id) do
    if storyline_belongs_to?(storyline_id, organization_id) do
      do_assign_pid_to_storyline(organization_id, agent_id, pid, storyline_id)
    else
      :ok
    end
  end

  defp do_assign_pid_to_storyline(organization_id, agent_id, pid, storyline_id) do
    key = process_key(organization_id, agent_id, pid)
    :ets.insert(@pid_to_storyline_table, {key, storyline_id})

    # Update process node
    case :ets.lookup(@process_tree_table, key) do
      [{^key, %{organization_id: ^organization_id} = node}] ->
        :ets.insert(@process_tree_table, {key, %{node | storyline_id: storyline_id}})

      _ ->
        :ok
    end

    # Add to storyline process set
    case :ets.lookup(@storyline_table, storyline_id) do
      [{^storyline_id, %{organization_id: ^organization_id} = storyline}] ->
        updated = %{
          storyline
          | processes: MapSet.put(storyline.processes, pid),
            updated_at: DateTime.utc_now()
        }

        :ets.insert(@storyline_table, {storyline_id, updated})

      _ ->
        :ok
    end
  end

  defp process_key(organization_id, agent_id, pid), do: {organization_id, agent_id, pid}

  defp calculate_detection_score(detection) do
    threat_score = detection[:threat_score] || 0.0

    # Convert 0.0-1.0 range to 0-100 for the storyline scoring
    base_score =
      if is_number(threat_score) and threat_score <= 1.0 do
        threat_score * 100.0
      else
        threat_score
      end

    # Ensure minimum score for any detection
    max(base_score, 10.0)
  end

  defp build_detection_title(detections) when is_list(detections) do
    detections
    |> Enum.map(fn d -> d[:rule_name] || d[:type] || "Detection" end)
    |> Enum.take(3)
    |> Enum.join(", ")
  end

  defp build_detection_title(_), do: "Detection"

  defp build_incident_title(storyline) do
    techniques = MapSet.to_list(storyline.mitre_techniques) |> Enum.take(3)
    process_count = MapSet.size(storyline.processes)

    technique_str =
      if length(techniques) > 0 do
        " [#{Enum.join(techniques, ", ")}]"
      else
        ""
      end

    "Storyline Incident: #{process_count} processes, #{length(storyline.detections)} detections#{technique_str}"
  end

  defp build_incident_description(storyline) do
    tactics = MapSet.to_list(storyline.mitre_tactics)
    techniques = MapSet.to_list(storyline.mitre_techniques)

    """
    Autonomous Storyline Engine detected a correlated attack chain.

    Severity: #{storyline.severity}
    Total Risk Score: #{Float.round(storyline.total_score, 1)}
    Processes Involved: #{MapSet.size(storyline.processes)}
    Detections: #{length(storyline.detections)}
    MITRE Tactics: #{Enum.join(tactics, ", ")}
    MITRE Techniques: #{Enum.join(techniques, ", ")}
    Root PID: #{storyline.root_pid}
    """
    |> String.trim()
  end

  defp get_payload_int(payload, key) when is_map(payload) do
    value = payload[key] || payload[String.to_atom(key)]
    parse_int(value)
  end

  defp get_payload_int(_, _), do: nil

  defp parse_int(val) when is_integer(val), do: val

  defp parse_int(val) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> nil
    end
  end

  defp parse_int(_), do: nil

  defp serialize_storyline(%StorylineData{} = s) do
    %{
      id: s.id,
      agent_id: s.agent_id,
      organization_id: s.organization_id,
      root_pid: s.root_pid,
      processes: MapSet.to_list(s.processes),
      detections: s.detections,
      total_score: s.total_score,
      severity: s.severity,
      status: s.status,
      alert_id: s.alert_id,
      mitre_tactics: MapSet.to_list(s.mitre_tactics),
      mitre_techniques: MapSet.to_list(s.mitre_techniques),
      created_at: s.created_at,
      updated_at: s.updated_at
    }
  end

  defp maybe_filter_status(storylines, nil), do: storylines

  defp maybe_filter_status(storylines, status) do
    Enum.filter(storylines, &(&1.status == status))
  end

  defp maybe_filter_severity(storylines, nil), do: storylines

  defp maybe_filter_severity(storylines, min_severity) do
    severity_order = %{low: 0, medium: 1, high: 2, critical: 3}
    min_ord = Map.get(severity_order, min_severity, 0)

    Enum.filter(storylines, fn s ->
      Map.get(severity_order, s.severity, 0) >= min_ord
    end)
  end

  defp tenant_storylines(organization_id, opts) do
    limit = Keyword.get(opts, :limit, 50)
    status_filter = Keyword.get(opts, :status)
    min_severity = Keyword.get(opts, :min_severity)
    agent_id = Keyword.get(opts, :agent_id)

    @storyline_table
    |> :ets.tab2list()
    |> Enum.map(fn {_id, storyline} -> storyline end)
    |> Enum.filter(&(&1.organization_id == organization_id))
    |> maybe_filter_agent(agent_id)
    |> maybe_filter_status(status_filter)
    |> maybe_filter_severity(min_severity)
    |> Enum.sort_by(& &1.updated_at, {:desc, DateTime})
    |> Enum.take(limit)
    |> Enum.map(&serialize_storyline/1)
  end

  defp maybe_filter_agent(storylines, nil), do: storylines

  defp maybe_filter_agent(storylines, agent_id),
    do: Enum.filter(storylines, &(&1.agent_id == agent_id))

  defp empty_counters do
    %{
      process_events: 0,
      detections_ingested: 0,
      storylines_created: 0,
      storylines_merged: 0,
      incidents_created: 0,
      cleanups: 0
    }
  end

  defp increment_tenant_counter(stats_by_org, organization_id, counter) do
    Map.update(
      stats_by_org,
      organization_id,
      Map.update!(empty_counters(), counter, &(&1 + 1)),
      fn counters ->
        Map.update!(counters, counter, &(&1 + 1))
      end
    )
  end

  defp maybe_increment_tenant_counter(stats_by_org, _organization_id, _counter, false),
    do: stats_by_org

  defp maybe_increment_tenant_counter(stats_by_org, organization_id, counter, true),
    do: increment_tenant_counter(stats_by_org, organization_id, counter)

  defp tenant_process_tree_size(organization_id) do
    @process_tree_table
    |> :ets.tab2list()
    |> Enum.count(fn
      {{^organization_id, _agent_id, _pid}, %{organization_id: ^organization_id}} -> true
      _ -> false
    end)
  end

  defp tenant_storyline_count(organization_id) do
    @storyline_table
    |> :ets.tab2list()
    |> Enum.count(fn {_id, storyline} -> storyline.organization_id == organization_id end)
  end

  defp tenant_pid_mapping_count(organization_id) do
    @pid_to_storyline_table
    |> :ets.tab2list()
    |> Enum.count(fn
      {{^organization_id, _agent_id, _pid}, storyline_id} ->
        storyline_belongs_to?(storyline_id, organization_id)

      _ ->
        false
    end)
  end

  defp storyline_belongs_to?(storyline_id, organization_id) do
    case :ets.lookup(@storyline_table, storyline_id) do
      [{^storyline_id, %{organization_id: ^organization_id}}] -> true
      _ -> false
    end
  end

  defp with_organization(agent_id, callback) do
    case TamanduaServer.Agents.OrgLookup.get_org_id(agent_id) do
      organization_id when is_binary(organization_id) -> callback.(organization_id)
      _ -> Logger.warning("[Storyline] Dropped unowned telemetry for agent #{agent_id}")
    end

    :ok
  rescue
    error ->
      Logger.warning(
        "[Storyline] Failed to resolve organization for agent #{agent_id}: #{Exception.message(error)}"
      )

      :ok
  catch
    :exit, reason ->
      Logger.warning(
        "[Storyline] Failed to resolve organization for agent #{agent_id}: #{inspect(reason)}"
      )

      :ok
  end

  # ------------------------------------------------------------------
  # PubSub Broadcasts
  # ------------------------------------------------------------------

  defp broadcast_severity_change(storyline) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "storyline:#{storyline.agent_id}",
      {:storyline_severity_changed, serialize_storyline(storyline)}
    )

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "storylines:#{storyline.organization_id}",
      {:storyline_severity_changed, serialize_storyline(storyline)}
    )
  rescue
    _ -> :ok
  end

  defp broadcast_incident_created(storyline, alert) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "storyline:#{storyline.agent_id}",
      {:storyline_incident_created,
       %{
         storyline: serialize_storyline(storyline),
         alert_id: alert.id
       }}
    )

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "storylines:#{storyline.organization_id}",
      {:storyline_incident_created,
       %{
         storyline: serialize_storyline(storyline),
         alert_id: alert.id
       }}
    )
  rescue
    _ -> :ok
  end
end
