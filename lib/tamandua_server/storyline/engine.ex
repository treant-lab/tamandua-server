defmodule TamanduaServer.Storyline.Engine do
  @moduledoc """
  Storyline Engine - SentinelOne-style attack visualization.

  The Storyline Engine builds comprehensive attack narratives from correlated events,
  providing security analysts with a clear understanding of:
  - What happened (sequence of events)
  - How it happened (causal chains)
  - Why it matters (threat assessment)
  - Where it started (root cause identification)

  Key Features:
  - Causal chain detection: Identifies the sequence of events that led to an attack
  - Automatic threat story generation: Creates human-readable narratives
  - Timeline reconstruction: Shows branching paths of attack progression
  - Cross-entity correlation: Connects processes, files, network, registry changes
  """

  alias TamanduaServer.{Repo, Alerts}
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Telemetry.Event
  alias TamanduaServer.Storyline.{Builder, Renderer}

  import Ecto.Query

  require Logger

  @type storyline :: %{
          id: String.t(),
          alert_id: String.t() | nil,
          agent_id: String.t(),
          title: String.t(),
          summary: String.t(),
          severity: atom(),
          root_cause: map() | nil,
          nodes: list(map()),
          edges: list(map()),
          timeline: list(map()),
          threat_indicators: list(map()),
          mitre_techniques: list(String.t()),
          attack_phase: String.t(),
          confidence_score: float(),
          generated_at: DateTime.t(),
          time_range: map()
        }

  @doc """
  Generate a complete storyline for an alert.

  Takes an alert ID and reconstructs the full attack story by:
  1. Fetching the alert and its associated events
  2. Building the causal chain
  3. Identifying root cause
  4. Generating the visual graph
  5. Creating a human-readable narrative
  """
  @spec generate_for_alert(String.t(), keyword()) :: {:ok, storyline()} | {:error, term()}
  def generate_for_alert(alert_id, opts \\ []) do
    with {:ok, organization_id} <- require_organization_id(opts),
         {:ok, alert} <- fetch_alert(alert_id, organization_id),
         {:ok, events} <- fetch_alert_events(alert, opts) do
      events = enrich_events_from_alert_metadata(events, alert)
      events = normalize_storyline_events(events)
      build_storyline(alert, events, opts)
    end
  end

  @doc """
  Generate a storyline starting from a specific process.
  """
  @spec generate_from_process(String.t(), integer(), keyword()) ::
          {:ok, storyline()} | {:error, term()}
  def generate_from_process(agent_id, pid, opts \\ []) do
    time_window = Keyword.get(opts, :time_window_minutes, 60)

    with {:ok, organization_id} <- require_organization_id(opts),
         {:ok, events} <- fetch_process_events(agent_id, pid, time_window, organization_id),
         {:ok, storyline} <- build_storyline_from_events(agent_id, events, opts) do
      {:ok, storyline}
    end
  end

  @doc """
  Generate a storyline from a list of event IDs.
  """
  @spec generate_from_events(list(String.t()), keyword()) :: {:ok, storyline()} | {:error, term()}
  def generate_from_events(event_ids, opts \\ []) when is_list(event_ids) do
    with {:ok, organization_id} <- require_organization_id(opts),
         {:ok, events} <- fetch_events_by_ids(event_ids, organization_id),
         {:ok, agent_id} <- extract_agent_id(events),
         {:ok, storyline} <- build_storyline_from_events(agent_id, events, opts) do
      {:ok, storyline}
    end
  end

  @doc """
  Analyze a storyline with AI assistance.

  Uses the AI module to provide:
  - Threat assessment
  - Attack technique identification
  - Recommended actions
  - Similar past incidents
  """
  @spec analyze_storyline(storyline(), keyword()) :: {:ok, map()} | {:error, term()}
  def analyze_storyline(storyline, opts \\ []) do
    with {:ok, organization_id} <- require_organization_id(opts),
         {:ok, storyline} <- normalize_analysis_storyline(storyline, organization_id) do
      analysis = %{
        threat_assessment: assess_threat(storyline),
        attack_techniques: identify_techniques(storyline),
        recommended_actions: recommend_actions(storyline),
        confidence: calculate_confidence(storyline),
        similar_incidents: find_similar_incidents(storyline),
        attack_narrative: generate_narrative(storyline)
      }

      analysis =
        if Keyword.get(opts, :use_ai, false) do
          enhance_with_ai(analysis, storyline)
        else
          analysis
        end

      {:ok, analysis}
    end
  end

  @doc """
  Get the attack phase based on storyline events.

  Returns one of:
  - initial_access
  - execution
  - persistence
  - privilege_escalation
  - defense_evasion
  - credential_access
  - discovery
  - lateral_movement
  - collection
  - command_and_control
  - exfiltration
  - impact
  """
  @spec determine_attack_phase(storyline()) :: String.t()
  def determine_attack_phase(storyline) do
    techniques = storyline[:mitre_techniques] || []

    # Map techniques to phases
    phase_mapping = %{
      # Phishing
      "T1566" => "initial_access",
      # Exploit Public-Facing Application
      "T1190" => "initial_access",
      # Command and Scripting Interpreter
      "T1059" => "execution",
      # Scheduled Task/Job
      "T1053" => "persistence",
      # Boot or Logon Autostart Execution
      "T1547" => "persistence",
      # Abuse Elevation Control Mechanism
      "T1548" => "privilege_escalation",
      # Access Token Manipulation
      "T1134" => "privilege_escalation",
      # Indicator Removal
      "T1070" => "defense_evasion",
      # Masquerading
      "T1036" => "defense_evasion",
      # OS Credential Dumping
      "T1003" => "credential_access",
      # System Information Discovery
      "T1082" => "discovery",
      # Remote Services
      "T1021" => "lateral_movement",
      # Archive Collected Data
      "T1560" => "collection",
      # Application Layer Protocol
      "T1071" => "command_and_control",
      # Exfiltration Over C2 Channel
      "T1041" => "exfiltration",
      # Data Encrypted for Impact
      "T1486" => "impact"
    }

    # Find the most advanced phase
    phases_order = [
      "initial_access",
      "execution",
      "persistence",
      "privilege_escalation",
      "defense_evasion",
      "credential_access",
      "discovery",
      "lateral_movement",
      "collection",
      "command_and_control",
      "exfiltration",
      "impact"
    ]

    detected_phases =
      techniques
      |> Enum.map(fn tech ->
        # Extract base technique ID (e.g., T1059 from T1059.001)
        base = String.split(tech, ".") |> hd()
        Map.get(phase_mapping, base)
      end)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    # Return the most advanced phase detected
    phases_order
    |> Enum.reverse()
    |> Enum.find("unknown", fn phase -> phase in detected_phases end)
  end

  # Private functions

  defp require_organization_id(opts) do
    case Keyword.get(opts, :organization_id) do
      organization_id when is_binary(organization_id) and organization_id != "" ->
        {:ok, organization_id}

      _ ->
        {:error, :organization_required}
    end
  end

  defp normalize_analysis_storyline(storyline, organization_id) when is_map(storyline) do
    required_lists = [:nodes, :edges, :timeline, :threat_indicators, :mitre_techniques]
    severity = normalize_storyline_severity(Map.get(storyline, :severity))
    confidence_score = Map.get(storyline, :confidence_score)

    if Enum.all?(required_lists, &is_list(Map.get(storyline, &1))) and
         Enum.all?(Map.get(storyline, :nodes), &valid_analysis_node?/1) and
         Enum.all?(Map.get(storyline, :timeline), &is_map/1) and
         Enum.all?(Map.get(storyline, :mitre_techniques), &is_binary/1) and
         severity != :unknown and is_number(confidence_score) and confidence_score >= 0.0 and
         confidence_score <= 1.0 and is_binary(Map.get(storyline, :attack_phase)) do
      normalized =
        storyline
        |> Map.put(:organization_id, organization_id)
        |> Map.put(:severity, severity)
        |> Map.put(:root_cause, Map.get(storyline, :root_cause))
        |> Map.put(:alert_id, Map.get(storyline, :alert_id))
        |> Map.put(:events, normalize_analysis_maps(Map.get(storyline, :events, [])))
        |> Map.put(:detections, normalize_analysis_maps(Map.get(storyline, :detections, [])))
        |> Map.put(:nodes, normalize_analysis_nodes(Map.get(storyline, :nodes)))
        |> Map.put(:timeline, normalize_analysis_timeline(Map.get(storyline, :timeline)))

      {:ok, normalized}
    else
      {:error, :invalid_storyline}
    end
  end

  defp normalize_analysis_storyline(_storyline, _organization_id),
    do: {:error, :invalid_storyline}

  defp normalize_storyline_severity(value) when value in [:critical, "critical"], do: :critical
  defp normalize_storyline_severity(value) when value in [:high, "high"], do: :high
  defp normalize_storyline_severity(value) when value in [:medium, "medium"], do: :medium
  defp normalize_storyline_severity(value) when value in [:low, "low"], do: :low
  defp normalize_storyline_severity(_value), do: :unknown

  defp normalize_analysis_nodes(nodes) do
    Enum.map(nodes, fn
      node when is_map(node) -> Map.update(node, :type, nil, &normalize_storyline_node_type/1)
      node -> node
    end)
  end

  defp valid_analysis_node?(node) when is_map(node) do
    [:process_name, :name, :entity_name, :path, :remote_addr, :destination]
    |> Enum.all?(fn field ->
      case Map.get(node, field) do
        nil -> true
        value -> is_binary(value)
      end
    end)
  end

  defp valid_analysis_node?(_node), do: false

  defp normalize_storyline_node_type(value) when value in [:process, "process"], do: :process
  defp normalize_storyline_node_type(value) when value in [:file, "file"], do: :file
  defp normalize_storyline_node_type(value) when value in [:network, "network"], do: :network
  defp normalize_storyline_node_type(value) when value in [:registry, "registry"], do: :registry
  defp normalize_storyline_node_type(value), do: value

  defp normalize_analysis_timeline(timeline) do
    Enum.map(timeline, fn
      event when is_map(event) ->
        Map.update(event, :severity, nil, fn severity ->
          severity |> normalize_storyline_severity() |> to_string()
        end)

      event ->
        event
    end)
  end

  defp normalize_analysis_maps(value) when is_list(value), do: Enum.filter(value, &is_map/1)
  defp normalize_analysis_maps(_value), do: []

  defp fetch_alert(alert_id, organization_id) do
    case Alerts.get_alert_for_org(organization_id, alert_id) do
      {:ok, alert} -> {:ok, alert}
      {:error, _} -> {:error, :alert_not_found}
    end
  end

  defp fetch_alert_events(alert, opts) do
    limit = Keyword.get(opts, :limit, 500)

    # Strategy 1: Direct event ID lookup (most precise)
    direct_ids =
      ((alert.event_ids || []) ++ (Map.get(alert, :contributing_events) || []))
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    events =
      if direct_ids != [] do
        Event
        |> where([e], e.organization_id == ^alert.organization_id)
        |> where([e], e.id in ^direct_ids)
        |> order_by([e], asc: e.timestamp)
        |> Repo.all()
      else
        []
      end

    # Strategy 2: Process-scoped query (PIDs from process_chain)
    events =
      if events == [] and is_list(alert.process_chain) and alert.process_chain != [] do
        pids =
          alert.process_chain
          |> Enum.flat_map(fn p -> [p["pid"], p["ppid"]] end)
          |> Enum.reject(&is_nil/1)
          |> Enum.uniq()

        if pids != [] do
          time_window = Keyword.get(opts, :time_window_minutes, 30)
          {start_time, end_time} = alert_time_range(alert, time_window)
          pid_strings = Enum.map(pids, &to_string/1)

          Event
          |> where([e], e.organization_id == ^alert.organization_id)
          |> where([e], e.agent_id == ^alert.agent_id)
          |> where([e], e.timestamp >= ^start_time and e.timestamp <= ^end_time)
          |> where(
            [e],
            fragment(
              "(?->>'pid') = ANY(?) OR (?->>'ppid') = ANY(?)",
              e.payload,
              ^pid_strings,
              e.payload,
              ^pid_strings
            )
          )
          |> order_by([e], asc: e.timestamp)
          |> limit(^limit)
          |> Repo.all()
        else
          []
        end
      else
        events
      end

    # Strategy 3: Time-window fallback (original behavior)
    events =
      if events == [] do
        time_window = Keyword.get(opts, :time_window_minutes, 30)
        {start_time, end_time} = alert_time_range(alert, time_window)

        Event
        |> where([e], e.organization_id == ^alert.organization_id)
        |> where([e], e.agent_id == ^alert.agent_id)
        |> where([e], e.timestamp >= ^start_time and e.timestamp <= ^end_time)
        |> order_by([e], asc: e.timestamp)
        |> limit(^limit)
        |> Repo.all()
      else
        events
      end

    {:ok, events}
  end

  defp alert_time_range(alert, time_window_minutes) do
    alert_time = alert.inserted_at
    start_time = NaiveDateTime.add(alert_time, -time_window_minutes * 60, :second)
    end_time = NaiveDateTime.add(alert_time, div(time_window_minutes, 2) * 60, :second)
    {start_time, end_time}
  end

  defp fetch_process_events(agent_id, pid, time_window_minutes, organization_id) do
    end_time = DateTime.utc_now()
    start_time = DateTime.add(end_time, -time_window_minutes * 60, :second)

    events =
      Event
      |> maybe_scope_events(organization_id)
      |> where([e], e.agent_id == ^agent_id)
      |> where([e], e.timestamp >= ^start_time and e.timestamp <= ^end_time)
      |> where(
        [e],
        fragment(
          "(?->>'pid')::int = ? OR (?->>'ppid')::int = ?",
          e.payload,
          ^pid,
          e.payload,
          ^pid
        )
      )
      |> order_by([e], asc: e.timestamp)
      |> limit(500)
      |> Repo.all()

    {:ok, events}
  end

  defp fetch_events_by_ids(event_ids, organization_id) do
    events =
      Event
      |> maybe_scope_events(organization_id)
      |> where([e], e.id in ^event_ids)
      |> order_by([e], asc: e.timestamp)
      |> Repo.all()

    if Enum.empty?(events) do
      {:error, :no_events_found}
    else
      {:ok, events}
    end
  end

  defp maybe_scope_events(query, nil), do: query

  defp maybe_scope_events(query, organization_id),
    do: where(query, [e], e.organization_id == ^organization_id)

  defp enrich_events_from_alert_metadata(events, alert) do
    synthetic_events = synthesize_events_from_alert(alert)

    cond do
      events == [] ->
        synthetic_events

      synthetic_events == [] ->
        events

      true ->
        (events ++ synthetic_events)
        |> Enum.uniq_by(&event_id/1)
        |> sort_events_by_timestamp()
    end
  end

  defp event_id(%{id: id}), do: id
  defp event_id(%{"id" => id}), do: id
  defp event_id(event), do: :erlang.phash2(event)

  # Synthesize event-like maps from alert metadata when no DB events are found.
  # This enables Builder.build_causal_chain to produce a process tree graph from
  # the alert's own process_chain, evidence, and MITRE technique data.
  defp synthesize_events_from_alert(alert) do
    base_timestamp = safe_datetime(alert.inserted_at)
    agent_id = alert.agent_id
    process_chain = alert.process_chain || []
    techniques = alert.mitre_techniques || []
    chain_length = length(process_chain)

    # 1. Process chain → process_create events (staggered in causal order)
    process_events =
      process_chain
      |> Enum.with_index()
      |> Enum.map(fn {proc, idx} ->
        ts = DateTime.add(base_timestamp, -(chain_length - idx), :second)

        # Attach MITRE techniques to the last process (the detected one)
        detections =
          if idx == chain_length - 1 do
            Enum.map(techniques, fn tech ->
              detection_from_alert(alert, tech, "behavioral")
            end)
          else
            []
          end

        %{
          id: "synth_proc_#{alert.id}_#{idx}",
          agent_id: agent_id,
          timestamp: ts,
          event_type: "process_create",
          severity: if(idx == chain_length - 1, do: to_string(alert.severity), else: "info"),
          payload: %{
            "pid" => proc["pid"],
            "ppid" => proc["ppid"],
            "name" => proc["name"] || proc["process_name"],
            "path" => proc["path"] || proc["image_path"],
            "cmdline" => proc["cmdline"] || proc["command_line"],
            "user" => proc["user"]
          },
          detections: detections
        }
      end)

    # 2. Evidence process -> process_create event. Agent detections often store
    # the process context here even when the persisted process_chain is empty.
    evidence_process_events =
      case get_evidence_process(alert.evidence || %{}) do
        nil ->
          []

        process ->
          [
            %{
              id: "synth_evidence_process_#{alert.id}",
              agent_id: agent_id,
              timestamp: base_timestamp,
              event_type: "process_create",
              severity: to_string(alert.severity),
              payload: %{
                "pid" =>
                  process["pid"] || process[:pid] || process["process_id"] || process[:process_id],
                "ppid" =>
                  process["ppid"] || process[:ppid] || process["parent_pid"] ||
                    process[:parent_pid],
                "name" =>
                  process["name"] || process[:name] || process["process_name"] ||
                    process[:process_name],
                "path" =>
                  process["path"] || process[:path] || process["image_path"] ||
                    process[:image_path],
                "cmdline" =>
                  process["cmdline"] || process[:cmdline] || process["command_line"] ||
                    process[:command_line],
                "user" => process["user"] || process[:user],
                "sha256" => process["sha256"] || process[:sha256],
                "is_elevated" => process["is_elevated"] || process[:is_elevated],
                "is_signed" => process["is_signed"] || process[:is_signed],
                "parent_name" => process["parent_name"] || process[:parent_name],
                "parent_path" => process["parent_path"] || process[:parent_path]
              },
              detections:
                Enum.map(techniques, fn tech ->
                  detection_from_alert(alert, tech, "detection")
                end)
            }
          ]
      end

    # 3. Raw event -> event matching detection_metadata event_type
    raw_events =
      case alert.raw_event do
        raw when is_map(raw) and map_size(raw) > 0 ->
          event_type =
            get_in(alert.detection_metadata || %{}, ["event_type"]) || "process_create"

          [
            %{
              id: "synth_raw_#{alert.id}",
              agent_id: agent_id,
              timestamp: base_timestamp,
              event_type: event_type,
              severity: to_string(alert.severity),
              payload: raw,
              detections:
                Enum.map(techniques, fn tech ->
                  detection_from_alert(alert, tech, "detection")
                end)
            }
          ]

        _ ->
          []
      end

    # 4. Evidence -> file/network/registry events
    evidence_events = synthesize_evidence_events(alert)

    # Combine, deduplicate, and sort by timestamp
    (process_events ++ evidence_process_events ++ raw_events ++ evidence_events)
    |> Enum.uniq_by(& &1[:id])
    |> sort_events_by_timestamp()
  end

  defp get_evidence_process(evidence) when is_map(evidence) do
    case Map.get(evidence, "process") || Map.get(evidence, :process) do
      process when is_map(process) and map_size(process) > 0 -> process
      _ -> nil
    end
  end

  defp get_evidence_process(_), do: nil

  defp detection_from_alert(alert, technique, fallback_type) do
    metadata = alert.detection_metadata || %{}

    evidence_detection =
      get_in(alert.evidence || %{}, ["detection"]) || get_in(alert.evidence || %{}, [:detection]) ||
        %{}

    %{
      "name" =>
        get_any(evidence_detection, ["rule_name", :rule_name, "name", :name]) ||
          get_any(metadata, ["rule_name", :rule_name, "name", :name]) ||
          alert.title ||
          "Alert detection",
      "rule_name" =>
        get_any(evidence_detection, ["rule_name", :rule_name]) ||
          get_any(metadata, ["rule_name", :rule_name]) ||
          alert.title,
      "type" =>
        get_any(evidence_detection, [
          "detection_type",
          :detection_type,
          "rule_type",
          :rule_type,
          "type",
          :type
        ]) ||
          get_any(metadata, [
            "detection_type",
            :detection_type,
            "rule_type",
            :rule_type,
            "type",
            :type
          ]) ||
          fallback_type,
      "severity" => to_string(alert.severity || "info"),
      "confidence" =>
        get_any(evidence_detection, ["confidence", :confidence]) ||
          get_any(metadata, ["confidence", :confidence]),
      "mitre_techniques" => [technique],
      "mitre_tactics" => alert.mitre_tactics || []
    }
    |> Enum.reject(fn {_key, value} -> value in [nil, "", []] end)
    |> Map.new()
  end

  defp synthesize_evidence_events(alert) do
    evidence = alert.evidence || %{}
    base_timestamp = safe_datetime(alert.inserted_at)
    agent_id = alert.agent_id

    # File operations from evidence
    files = Map.get(evidence, "files", []) ++ Map.get(evidence, :files, [])
    file_hashes = Map.get(evidence, "file_hashes", []) ++ Map.get(evidence, :file_hashes, [])
    all_files = (files ++ file_hashes) |> Enum.uniq()

    file_events =
      all_files
      |> Enum.with_index()
      |> Enum.map(fn {file, idx} ->
        path = file["path"] || file[:path] || ""

        %{
          id: "synth_file_#{alert.id}_#{idx}",
          agent_id: agent_id,
          timestamp: DateTime.add(base_timestamp, idx + 1, :second),
          event_type: "file_create",
          severity: "info",
          payload: %{
            "path" => path,
            "sha256" => file["sha256"] || file[:sha256],
            "name" => Path.basename(to_string(path))
          },
          detections: []
        }
      end)

    # Network connections from evidence
    network = Map.get(evidence, "network", []) ++ Map.get(evidence, :network, [])

    network_events =
      network
      |> Enum.with_index()
      |> Enum.map(fn {conn, idx} ->
        %{
          id: "synth_net_#{alert.id}_#{idx}",
          agent_id: agent_id,
          timestamp: DateTime.add(base_timestamp, idx + 1, :second),
          event_type: "network_connect",
          severity: "info",
          payload: %{
            "remote_addr" =>
              conn["remote_addr"] || conn["destination"] || conn["value"] ||
                conn[:remote_addr] || conn[:destination] || conn[:value],
            "remote_port" => conn["remote_port"] || conn[:remote_port],
            "protocol" => conn["protocol"] || conn[:protocol]
          },
          detections: []
        }
      end)

    # Registry changes from evidence
    registry = Map.get(evidence, "registry", []) ++ Map.get(evidence, :registry, [])

    registry_events =
      registry
      |> Enum.with_index()
      |> Enum.map(fn {reg, idx} ->
        %{
          id: "synth_reg_#{alert.id}_#{idx}",
          agent_id: agent_id,
          timestamp: DateTime.add(base_timestamp, idx + 1, :second),
          event_type: "registry_write",
          severity: "info",
          payload: %{
            "key" => reg["key"] || reg[:key],
            "value" => reg["value"] || reg[:value],
            "name" => reg["name"] || reg[:name]
          },
          detections: []
        }
      end)

    file_events ++ network_events ++ registry_events
  end

  defp extract_agent_id([event | _]) do
    {:ok, event.agent_id}
  end

  defp extract_agent_id([]) do
    {:error, :no_events}
  end

  defp build_storyline(alert, events, opts) do
    # Build the storyline using the Builder module
    with {:ok, causal_chain} <- Builder.build_causal_chain(events),
         {:ok, root_cause} <- Builder.identify_root_cause(causal_chain),
         {:ok, graph_data} <- Renderer.render(causal_chain, alert, opts) do
      storyline = %{
        id: generate_storyline_id(),
        alert_id: alert.id,
        agent_id: alert.agent_id,
        organization_id: alert.organization_id,
        title: generate_title(alert, root_cause),
        summary: generate_summary(alert, causal_chain),
        severity: alert.severity,
        root_cause: root_cause,
        nodes: graph_data.nodes,
        edges: graph_data.edges,
        timeline: build_timeline(events),
        threat_indicators: extract_threat_indicators(events, alert),
        mitre_techniques: extract_mitre_techniques(alert, events),
        attack_phase: "unknown",
        confidence_score: calculate_confidence_score(causal_chain, root_cause),
        generated_at: DateTime.utc_now(),
        time_range: %{
          start: events |> List.first() |> get_timestamp(),
          end: events |> List.last() |> get_timestamp()
        }
      }

      # Determine attack phase
      storyline = Map.put(storyline, :attack_phase, determine_attack_phase(storyline))

      {:ok, storyline}
    end
  end

  defp build_storyline_from_events(agent_id, events, opts) do
    events = normalize_storyline_events(events)

    with {:ok, causal_chain} <- Builder.build_causal_chain(events),
         {:ok, root_cause} <- Builder.identify_root_cause(causal_chain),
         {:ok, graph_data} <- Renderer.render_from_events(causal_chain, agent_id, opts) do
      storyline = %{
        id: generate_storyline_id(),
        alert_id: nil,
        agent_id: agent_id,
        organization_id: Keyword.get(opts, :organization_id),
        title: "Process Activity Investigation",
        summary: generate_events_summary(events),
        severity: determine_severity(events),
        root_cause: root_cause,
        nodes: graph_data.nodes,
        edges: graph_data.edges,
        timeline: build_timeline(events),
        threat_indicators: extract_threat_indicators(events, nil),
        mitre_techniques: extract_mitre_from_events(events),
        attack_phase: "unknown",
        confidence_score: calculate_confidence_score(causal_chain, root_cause),
        generated_at: DateTime.utc_now(),
        time_range: %{
          start: events |> List.first() |> get_timestamp(),
          end: events |> List.last() |> get_timestamp()
        }
      }

      storyline = Map.put(storyline, :attack_phase, determine_attack_phase(storyline))

      {:ok, storyline}
    end
  end

  defp generate_storyline_id do
    "storyline_#{:crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)}"
  end

  defp generate_title(alert, root_cause) do
    root_name =
      case root_cause do
        %{process_name: name} when is_binary(name) -> name
        %{entity_name: name} when is_binary(name) -> name
        _ -> "Unknown Process"
      end

    "#{alert.title} - Originating from #{root_name}"
  end

  defp generate_summary(alert, causal_chain) do
    node_count = length(causal_chain.nodes)
    process_count = Enum.count(causal_chain.nodes, &(&1.type == :process))
    file_count = Enum.count(causal_chain.nodes, &(&1.type == :file))
    network_count = Enum.count(causal_chain.nodes, &(&1.type == :network))

    """
    Attack storyline for alert "#{alert.title}" involving #{node_count} entities: \
    #{process_count} processes, #{file_count} file operations, and #{network_count} network connections. \
    Severity: #{alert.severity}.
    """
    |> String.trim()
  end

  defp generate_events_summary(events) do
    event_count = length(events)
    event_types = events |> Enum.map(& &1.event_type) |> Enum.uniq() |> Enum.join(", ")

    "Investigation covering #{event_count} events of types: #{event_types}"
  end

  defp build_timeline(events) do
    events
    |> Enum.map(fn event ->
      %{
        id: event.id,
        timestamp: event.timestamp,
        event_type: event.event_type,
        summary: summarize_event(event),
        severity: event.severity || "info",
        payload: storyline_payload(event),
        detections: event_detections(event)
      }
    end)
  end

  defp summarize_event(event) do
    case event.event_type do
      "process_create" ->
        name = get_in(event.payload, ["name"]) || "process"
        "Process created: #{name}"

      "process_terminate" ->
        name = get_in(event.payload, ["name"]) || "process"
        "Process terminated: #{name}"

      "file_create" ->
        path = get_in(event.payload, ["path"]) || "file"
        "File created: #{Path.basename(path)}"

      "file_modify" ->
        path = get_in(event.payload, ["path"]) || "file"
        "File modified: #{Path.basename(path)}"

      "file_delete" ->
        path = get_in(event.payload, ["path"]) || "file"
        "File deleted: #{Path.basename(path)}"

      "network_connect" ->
        dest = get_in(event.payload, ["remote_addr"]) || "unknown"
        port = get_in(event.payload, ["remote_port"]) || "?"
        "Network connection to #{dest}:#{port}"

      "dns_query" ->
        domain = get_in(event.payload, ["query"]) || "unknown"
        "DNS query: #{domain}"

      "registry_write" ->
        key = get_in(event.payload, ["key"]) || "registry key"
        "Registry modified: #{String.slice(key, -60..-1) || key}"

      _ ->
        "#{event.event_type} event"
    end
  end

  defp sanitize_payload(payload) when is_map(payload) do
    # Remove potentially sensitive data
    payload
    |> Map.drop(["password", "secret", "token", "key", "credential"])
  end

  defp sanitize_payload(_), do: %{}

  @consumer_visibility_fields ~w(
    ai_network_risk ai_evidence_limit network_visibility_state
    tls_fingerprints_available certificate_visibility risk_indicators
    matched_patterns artifact_type redacted_preview
  )

  defp storyline_payload(event) do
    payload = event |> event_payload() |> sanitize_payload()
    enrichment = Map.get(event, :enrichment) || Map.get(event, "enrichment") || %{}
    metadata = get_any(enrichment, ["metadata", :metadata]) || %{}

    visible_metadata =
      Enum.reduce(@consumer_visibility_fields, %{}, fn key, acc ->
        case visibility_metadata_value(metadata, key) do
          value when value in [nil, "", []] -> acc
          :missing -> acc
          value -> Map.put(acc, key, value)
        end
      end)

    if map_size(visible_metadata) == 0 do
      payload
    else
      Map.update(payload, "metadata", visible_metadata, fn existing ->
        if is_map(existing), do: Map.merge(visible_metadata, existing), else: visible_metadata
      end)
    end
  end

  defp visibility_metadata_value(metadata, key) when is_map(metadata) do
    case Map.fetch(metadata, key) do
      {:ok, value} ->
        value

      :error ->
        case Map.fetch(metadata, String.to_atom(key)) do
          {:ok, value} -> value
          :error -> :missing
        end
    end
  end

  defp visibility_metadata_value(_, _), do: :missing

  defp event_detections(event) when is_map(event) do
    payload = Map.get(event, :payload) || Map.get(event, "payload") || %{}

    Map.get(event, :detections) ||
      Map.get(event, "detections") ||
      Map.get(payload, "detections") ||
      Map.get(payload, :detections) ||
      []
  end

  defp event_detections(_), do: []

  defp extract_threat_indicators(events, alert) do
    indicators = []

    # Extract from events
    event_indicators =
      events
      |> Enum.flat_map(fn event ->
        extract_event_indicators(event)
      end)

    # Extract from alert evidence if available
    alert_indicators =
      if alert && alert.evidence do
        extract_alert_indicators(alert.evidence)
      else
        []
      end

    (indicators ++ event_indicators ++ alert_indicators)
    |> Enum.uniq_by(& &1.value)
  end

  defp extract_event_indicators(event) do
    payload = event_payload(event)

    [
      indicator("hash_sha256", get_any(payload, ["sha256", :sha256, "hash", :hash])),
      indicator(
        "domain",
        get_any(payload, ["query", :query, "domain", :domain, "hostname", :hostname, "sni", :sni])
      ),
      indicator(
        "ip",
        get_any(payload, [
          "remote_addr",
          :remote_addr,
          "remote_ip",
          :remote_ip,
          "dst_ip",
          :dst_ip,
          "ip",
          :ip
        ])
      ),
      indicator("url", get_any(payload, ["url", :url, "uri", :uri])),
      suspicious_file_indicator(
        get_any(payload, ["path", :path, "image_path", :image_path, "file_path", :file_path])
      )
    ]
    |> Enum.concat(
      command_line_indicators(
        get_any(payload, ["cmdline", :cmdline, "command_line", :command_line, "command", :command])
      )
    )
    |> Enum.reject(&is_nil/1)
  end

  defp event_payload(%Event{payload: payload}) when is_map(payload), do: payload
  defp event_payload(%{payload: payload}) when is_map(payload), do: payload
  defp event_payload(%{"payload" => payload}) when is_map(payload), do: payload
  defp event_payload(event) when is_map(event), do: event
  defp event_payload(_), do: %{}

  defp indicator(_type, value) when value in [nil, "", []], do: nil
  defp indicator(type, value), do: %{type: type, value: to_string(value), source: "event"}

  defp suspicious_file_indicator(path) when is_binary(path) do
    if suspicious_path?(path), do: indicator("file_path", path), else: nil
  end

  defp suspicious_file_indicator(_), do: nil

  defp command_line_indicators(cmdline) when is_binary(cmdline) do
    decoded = decode_powershell_encoded_command(cmdline)
    text = Enum.join([cmdline, decoded || ""], "\n")

    Regex.scan(~r/\bhttps?:\/\/[^\s'"`<>]+/i, text)
    |> Enum.map(fn [url] -> indicator("url", Regex.replace(~r/[)\].,]+$/, url, "")) end)
  end

  defp command_line_indicators(_), do: []

  defp decode_powershell_encoded_command(cmdline) when is_binary(cmdline) do
    case Regex.run(~r/(?:-|\/)(?:enc|encodedcommand)\s+([A-Za-z0-9+\/=_-]+)/i, cmdline) do
      [_, encoded] ->
        encoded
        |> String.replace("-", "+")
        |> String.replace("_", "/")
        |> pad_base64()
        |> Base.decode64()
        |> case do
          {:ok, bytes} -> decode_utf16le(bytes)
          _ -> nil
        end

      _ ->
        nil
    end
  end

  defp decode_powershell_encoded_command(_), do: nil

  defp pad_base64(value) do
    case rem(String.length(value), 4) do
      0 -> value
      n -> value <> String.duplicate("=", 4 - n)
    end
  end

  defp decode_utf16le(bytes) when is_binary(bytes) do
    bytes
    |> :unicode.characters_to_binary({:utf16, :little}, :utf8)
    |> case do
      decoded when is_binary(decoded) -> String.trim(decoded)
      _ -> nil
    end
  rescue
    _ -> nil
  end

  defp extract_alert_indicators(evidence) when is_map(evidence) do
    indicators = []

    # Extract file hashes
    file_hashes = Map.get(evidence, "file_hashes", []) ++ Map.get(evidence, :file_hashes, [])

    hash_indicators =
      Enum.flat_map(file_hashes, fn hash ->
        Enum.flat_map(["sha256", "sha1", "md5"], fn algo ->
          value = Map.get(hash, algo) || Map.get(hash, String.to_atom(algo))
          if value, do: [%{type: "hash_#{algo}", value: value, source: "alert"}], else: []
        end)
      end)

    # Extract network indicators
    network = Map.get(evidence, "network", []) ++ Map.get(evidence, :network, [])

    network_indicators =
      Enum.map(network, fn n ->
        type = Map.get(n, "type") || Map.get(n, :type) || "network"
        value = Map.get(n, "value") || Map.get(n, :value)
        %{type: type, value: value, source: "alert"}
      end)
      |> Enum.reject(&is_nil(&1.value))

    indicators ++ hash_indicators ++ network_indicators
  end

  defp extract_alert_indicators(_), do: []

  defp suspicious_path?(path) do
    suspicious_patterns = [
      ~r/\\temp\\/i,
      ~r/\\tmp\//i,
      ~r/\\appdata\\local\\temp/i,
      ~r/\\downloads\\/i,
      ~r/\\public\\/i,
      ~r/powershell/i,
      ~r/cmd\.exe/i,
      ~r/wscript/i,
      ~r/cscript/i,
      ~r/mshta/i
    ]

    Enum.any?(suspicious_patterns, &Regex.match?(&1, path || ""))
  end

  defp extract_mitre_techniques(alert, _events) do
    (alert.mitre_techniques || [])
    |> Enum.uniq()
  end

  defp extract_mitre_from_events(events) do
    events
    |> Enum.flat_map(fn event ->
      event_detections(event)
      |> Enum.flat_map(fn detection ->
        detection["mitre_techniques"] || detection[:mitre_techniques] || []
      end)
    end)
    |> Enum.uniq()
  end

  defp calculate_confidence(storyline) do
    events = storyline[:events] || []
    nodes = storyline[:nodes] || []
    edges = storyline[:edges] || []
    detections = storyline[:detections] || []

    base_score = 0.5

    # Higher confidence with more events
    event_bonus = min(length(events) / 50, 0.15)

    # Higher confidence with detections
    detection_bonus = min(length(detections) / 10, 0.15)

    # Higher confidence with clear node/edge structure
    structure_bonus = min((length(nodes) + length(edges)) / 40, 0.1)

    # Higher confidence with critical/high severity detections
    severity_bonus =
      if Enum.any?(detections, &(&1[:severity] in ["critical", "high"])), do: 0.1, else: 0.0

    min(base_score + event_bonus + detection_bonus + structure_bonus + severity_bonus, 1.0)
    |> Float.round(2)
  end

  defp calculate_confidence_score(causal_chain, root_cause) do
    base_score = 0.5

    # Higher confidence if we found a clear root cause
    root_cause_bonus = if root_cause, do: 0.2, else: 0.0

    # Higher confidence with more complete causal chain
    chain_bonus = min(length(causal_chain.nodes) / 20, 0.2)

    # Higher confidence with clear edges
    edge_bonus = min(length(causal_chain.edges) / 30, 0.1)

    min(base_score + root_cause_bonus + chain_bonus + edge_bonus, 1.0)
    |> Float.round(2)
  end

  defp determine_severity(events) do
    severities =
      events
      |> Enum.map(& &1.severity)
      |> Enum.reject(&is_nil/1)

    cond do
      "critical" in severities -> :critical
      "high" in severities -> :high
      "medium" in severities -> :medium
      "low" in severities -> :low
      true -> :info
    end
  end

  defp get_timestamp(%Event{timestamp: ts}), do: ts
  defp get_timestamp(%{timestamp: ts}), do: ts
  defp get_timestamp(%{"timestamp" => ts}), do: ts
  defp get_timestamp(_), do: nil

  defp normalize_storyline_events(events) when is_list(events) do
    events
    |> Enum.map(&put_normalized_timestamp/1)
    |> sort_events_by_timestamp()
  end

  defp normalize_storyline_events(_), do: []

  defp put_normalized_timestamp(%Event{} = event) do
    event
    |> Map.put(:timestamp, safe_datetime(event.timestamp))
    |> Map.update(:payload, %{}, &enrich_payload_for_storyline/1)
  end

  defp put_normalized_timestamp(event) when is_map(event) do
    timestamp = event |> get_timestamp() |> safe_datetime()
    payload = event |> event_payload() |> enrich_payload_for_storyline()

    event
    |> Map.put(:timestamp, timestamp)
    |> Map.put(:payload, payload)
    |> Map.delete("timestamp")
  end

  defp put_normalized_timestamp(event), do: event

  defp sort_events_by_timestamp(events) do
    Enum.sort_by(events, &(get_timestamp(&1) |> datetime_sort_key()))
  end

  defp datetime_sort_key(value) do
    value
    |> safe_datetime()
    |> DateTime.to_unix(:microsecond)
  end

  defp safe_datetime(%DateTime{} = dt), do: dt

  defp safe_datetime(%NaiveDateTime{} = ndt) do
    DateTime.from_naive!(ndt, "Etc/UTC")
  end

  defp safe_datetime(value) when is_binary(value) do
    trimmed = String.trim(value)

    case DateTime.from_iso8601(trimmed) do
      {:ok, dt, _offset} ->
        dt

      _ ->
        case NaiveDateTime.from_iso8601(String.trim_trailing(trimmed, "Z")) do
          {:ok, ndt} -> DateTime.from_naive!(ndt, "Etc/UTC")
          _ -> DateTime.utc_now()
        end
    end
  end

  defp safe_datetime(value) when is_integer(value) do
    unit = if abs(value) > 10_000_000_000, do: :millisecond, else: :second

    case DateTime.from_unix(value, unit) do
      {:ok, dt} -> dt
      _ -> DateTime.utc_now()
    end
  end

  defp safe_datetime(_), do: DateTime.utc_now()

  defp enrich_payload_for_storyline(payload) when is_map(payload) do
    cmdline =
      get_any(payload, ["cmdline", :cmdline, "command_line", :command_line, "command", :command])

    decoded = decode_powershell_encoded_command(cmdline)

    urls =
      command_line_indicators(cmdline)
      |> Enum.filter(&(&1.type == "url"))
      |> Enum.map(& &1.value)
      |> Enum.uniq()

    payload
    |> maybe_put_payload("decoded_command", decoded)
    |> maybe_put_payload("embedded_urls", urls)
  end

  defp enrich_payload_for_storyline(_), do: %{}

  defp maybe_put_payload(payload, _key, value) when value in [nil, "", []], do: payload
  defp maybe_put_payload(payload, key, value), do: Map.put(payload, key, value)

  defp get_any(map, keys) when is_map(map) and is_list(keys) do
    Enum.find_value(keys, fn key ->
      case Map.get(map, key) do
        value when value not in [nil, "", []] -> value
        _ -> nil
      end
    end)
  end

  defp get_any(_, _), do: nil

  # Analysis functions

  defp assess_threat(storyline) do
    %{
      severity: storyline.severity,
      confidence: storyline.confidence_score,
      phase: storyline.attack_phase,
      indicators_count: length(storyline.threat_indicators),
      techniques_count: length(storyline.mitre_techniques),
      risk_level: calculate_risk_level(storyline)
    }
  end

  defp calculate_risk_level(storyline) do
    severity_score =
      case storyline.severity do
        :critical -> 100
        :high -> 75
        :medium -> 50
        :low -> 25
        _ -> 10
      end

    technique_score = min(length(storyline.mitre_techniques) * 10, 50)
    indicator_score = min(length(storyline.threat_indicators) * 5, 30)

    total = severity_score + technique_score + indicator_score

    cond do
      total >= 150 -> "critical"
      total >= 100 -> "high"
      total >= 50 -> "medium"
      true -> "low"
    end
  end

  defp identify_techniques(storyline) do
    storyline.mitre_techniques
    |> Enum.map(fn technique_id ->
      %{
        id: technique_id,
        name: get_technique_name(technique_id),
        tactic: get_technique_tactic(technique_id),
        description: get_technique_description(technique_id)
      }
    end)
  end

  defp get_technique_name(technique_id) do
    # Common technique names mapping
    techniques = %{
      "T1059" => "Command and Scripting Interpreter",
      "T1059.001" => "PowerShell",
      "T1059.003" => "Windows Command Shell",
      "T1547" => "Boot or Logon Autostart Execution",
      "T1547.001" => "Registry Run Keys / Startup Folder",
      "T1003" => "OS Credential Dumping",
      "T1003.001" => "LSASS Memory",
      "T1071" => "Application Layer Protocol",
      "T1071.001" => "Web Protocols",
      "T1566" => "Phishing",
      "T1566.001" => "Spearphishing Attachment",
      "T1486" => "Data Encrypted for Impact",
      "T1055" => "Process Injection",
      "T1055.001" => "Dynamic-link Library Injection"
    }

    Map.get(techniques, technique_id, "Unknown Technique")
  end

  defp get_technique_tactic(technique_id) do
    tactics = %{
      "T1059" => "Execution",
      "T1059.001" => "Execution",
      "T1059.003" => "Execution",
      "T1547" => "Persistence",
      "T1547.001" => "Persistence",
      "T1003" => "Credential Access",
      "T1003.001" => "Credential Access",
      "T1071" => "Command and Control",
      "T1071.001" => "Command and Control",
      "T1566" => "Initial Access",
      "T1566.001" => "Initial Access",
      "T1486" => "Impact",
      "T1055" => "Defense Evasion",
      "T1055.001" => "Defense Evasion"
    }

    Map.get(tactics, technique_id, "Unknown")
  end

  defp get_technique_description(technique_id) do
    descriptions = %{
      "T1059" => "Adversaries may abuse command and script interpreters to execute commands.",
      "T1059.001" => "Adversaries may abuse PowerShell commands and scripts for execution.",
      "T1059.003" => "Adversaries may abuse the Windows command shell (cmd.exe) for execution.",
      "T1547" =>
        "Adversaries may configure system settings to automatically execute a program during system boot.",
      "T1003" =>
        "Adversaries may attempt to dump credentials to obtain account login and credential material.",
      "T1071" =>
        "Adversaries may communicate using application layer protocols to avoid detection.",
      "T1566" => "Adversaries may send phishing messages to gain access to victim systems.",
      "T1486" => "Adversaries may encrypt data on target systems to interrupt availability.",
      "T1055" => "Adversaries may inject code into processes to evade process-based defenses."
    }

    base_id = technique_id |> String.split(".") |> hd()

    Map.get(descriptions, technique_id) ||
      Map.get(descriptions, base_id, "No description available.")
  end

  defp recommend_actions(storyline) do
    actions = []

    # Based on severity
    actions =
      case storyline.severity do
        :critical ->
          [
            %{
              priority: "immediate",
              action: "Isolate affected endpoint",
              reason: "Critical severity detected"
            },
            %{
              priority: "immediate",
              action: "Collect forensic artifacts",
              reason: "Preserve evidence before remediation"
            }
            | actions
          ]

        :high ->
          [
            %{
              priority: "high",
              action: "Investigate process chain",
              reason: "High severity requires immediate attention"
            },
            %{
              priority: "high",
              action: "Check for lateral movement",
              reason: "Prevent spread to other systems"
            }
            | actions
          ]

        _ ->
          actions
      end

    # Based on attack phase
    actions =
      case storyline.attack_phase do
        "credential_access" ->
          [
            %{
              priority: "immediate",
              action: "Reset compromised credentials",
              reason: "Credential theft detected"
            },
            %{
              priority: "high",
              action: "Review access logs",
              reason: "Check for credential misuse"
            }
            | actions
          ]

        "exfiltration" ->
          [
            %{
              priority: "immediate",
              action: "Block outbound connections",
              reason: "Data exfiltration in progress"
            },
            %{
              priority: "high",
              action: "Identify exfiltrated data",
              reason: "Assess data breach impact"
            }
            | actions
          ]

        "lateral_movement" ->
          [
            %{
              priority: "immediate",
              action: "Isolate affected systems",
              reason: "Prevent further spread"
            },
            %{
              priority: "high",
              action: "Scan adjacent systems",
              reason: "Identify compromised hosts"
            }
            | actions
          ]

        _ ->
          actions
      end

    # Based on indicators
    if length(storyline.threat_indicators) > 5 do
      _actions = [
        %{
          priority: "medium",
          action: "Export IOCs to threat intel",
          reason: "Multiple indicators detected"
        }
        | actions
      ]
    end

    actions
    |> Enum.uniq_by(& &1.action)
    |> Enum.sort_by(fn a ->
      case a.priority do
        "immediate" -> 0
        "high" -> 1
        "medium" -> 2
        _ -> 3
      end
    end)
  end

  defp find_similar_incidents(storyline) do
    techniques = MapSet.new(storyline[:mitre_techniques] || storyline.mitre_techniques || [])

    # Nothing to compare if we have no identifying features
    if MapSet.size(techniques) == 0 and
         Enum.empty?(extract_process_names(storyline)) and
         Enum.empty?(extract_file_paths(storyline)) and
         Enum.empty?(extract_network_destinations(storyline)) do
      []
    else
      # Query recent alerts from the last 30 days that have MITRE techniques
      cutoff = NaiveDateTime.add(NaiveDateTime.utc_now(), -30 * 24 * 3600, :second)

      organization_id = storyline[:organization_id]

      candidate_alerts =
        if organization_id do
          Alert
          |> where([a], a.organization_id == ^organization_id)
          |> where([a], a.inserted_at >= ^cutoff)
          |> where([a], a.id != ^(storyline[:alert_id] || ""))
          |> where([a], fragment("array_length(?, 1) > 0", a.mitre_techniques))
          |> order_by([a], desc: a.inserted_at)
          |> limit(100)
          |> Repo.all()
        else
          []
        end

      # Extract feature sets from the current storyline for comparison
      storyline_process_names = extract_process_names(storyline) |> MapSet.new()
      storyline_file_paths = extract_file_paths(storyline) |> MapSet.new()
      storyline_network_dests = extract_network_destinations(storyline) |> MapSet.new()

      candidate_alerts
      |> Enum.map(fn alert ->
        alert_techniques = MapSet.new(alert.mitre_techniques || [])
        alert_process_names = extract_process_names_from_alert(alert) |> MapSet.new()
        alert_file_paths = extract_file_paths_from_alert(alert) |> MapSet.new()
        alert_network_dests = extract_network_dests_from_alert(alert) |> MapSet.new()

        # Weighted Jaccard similarity across feature dimensions
        technique_sim = jaccard_similarity(techniques, alert_techniques)
        process_sim = jaccard_similarity(storyline_process_names, alert_process_names)
        file_sim = jaccard_similarity(storyline_file_paths, alert_file_paths)
        network_sim = jaccard_similarity(storyline_network_dests, alert_network_dests)

        # Weights: MITRE techniques carry the most weight, then processes,
        # then file paths and network destinations
        weighted_score =
          technique_sim * 0.40 +
            process_sim * 0.25 +
            file_sim * 0.20 +
            network_sim * 0.15

        %{
          alert_id: alert.id,
          title: alert.title,
          severity: alert.severity,
          similarity_score: Float.round(weighted_score, 3),
          matching_techniques:
            MapSet.intersection(techniques, alert_techniques) |> MapSet.to_list(),
          matching_processes:
            MapSet.intersection(storyline_process_names, alert_process_names) |> MapSet.to_list(),
          occurred_at: alert.inserted_at
        }
      end)
      |> Enum.filter(fn incident -> incident.similarity_score > 0.1 end)
      |> Enum.sort_by(& &1.similarity_score, :desc)
      |> Enum.take(5)
    end
  end

  # Jaccard similarity: |A intersect B| / |A union B|
  defp jaccard_similarity(set_a, set_b) do
    union_size = MapSet.union(set_a, set_b) |> MapSet.size()

    if union_size == 0 do
      0.0
    else
      intersection_size = MapSet.intersection(set_a, set_b) |> MapSet.size()
      intersection_size / union_size
    end
  end

  # Extract process names from storyline nodes
  defp extract_process_names(storyline) do
    nodes = storyline[:nodes] || []

    nodes
    |> Enum.filter(fn node -> node[:type] == :process end)
    |> Enum.map(fn node ->
      (node[:process_name] || node[:name] || node[:entity_name] || "")
      |> String.downcase()
    end)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  # Extract file paths from storyline nodes
  defp extract_file_paths(storyline) do
    nodes = storyline[:nodes] || []

    nodes
    |> Enum.filter(fn node -> node[:type] == :file end)
    |> Enum.map(fn node ->
      (node[:path] || node[:name] || node[:entity_name] || "")
      |> String.downcase()
    end)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  # Extract network destinations from storyline nodes
  defp extract_network_destinations(storyline) do
    nodes = storyline[:nodes] || []

    nodes
    |> Enum.filter(fn node -> node[:type] == :network end)
    |> Enum.map(fn node ->
      (node[:remote_addr] || node[:destination] || node[:name] || "")
      |> String.downcase()
    end)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  # Extract features from alert evidence/process_chain for comparison
  defp extract_process_names_from_alert(alert) do
    names_from_chain =
      (alert.process_chain || [])
      |> Enum.map(fn entry ->
        (entry["name"] || entry["process_name"] || "")
        |> String.downcase()
      end)

    names_from_evidence =
      case alert.evidence do
        %{"processes" => procs} when is_list(procs) ->
          Enum.map(procs, fn p -> (p["name"] || "") |> String.downcase() end)

        _ ->
          []
      end

    (names_from_chain ++ names_from_evidence)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  defp extract_file_paths_from_alert(alert) do
    case alert.evidence do
      %{"files" => files} when is_list(files) ->
        Enum.map(files, fn f -> (f["path"] || "") |> String.downcase() end)
        |> Enum.reject(&(&1 == ""))

      _ ->
        []
    end
  end

  defp extract_network_dests_from_alert(alert) do
    case alert.evidence do
      %{"network" => conns} when is_list(conns) ->
        Enum.map(conns, fn n ->
          (n["remote_addr"] || n["destination"] || n["value"] || "") |> String.downcase()
        end)
        |> Enum.reject(&(&1 == ""))

      _ ->
        []
    end
  end

  defp generate_narrative(storyline) do
    root_cause_text =
      case storyline.root_cause do
        %{process_name: name, cmdline: cmdline} when is_binary(name) ->
          "The attack originated from the process '#{name}'#{if cmdline, do: " with command line: #{String.slice(cmdline, 0, 100)}", else: ""}."

        %{entity_name: name, type: type} ->
          "The activity started with a #{type} entity: #{name}."

        _ ->
          "The root cause could not be definitively determined."
      end

    phase_text =
      case storyline.attack_phase do
        "unknown" -> ""
        phase -> " The attack has progressed to the '#{String.replace(phase, "_", " ")}' phase."
      end

    technique_text =
      if length(storyline.mitre_techniques) > 0 do
        techniques = storyline.mitre_techniques |> Enum.take(3) |> Enum.join(", ")
        " Detected MITRE ATT&CK techniques include: #{techniques}."
      else
        ""
      end

    indicator_text =
      if length(storyline.threat_indicators) > 0 do
        " #{length(storyline.threat_indicators)} threat indicators were identified."
      else
        ""
      end

    """
    #{root_cause_text}#{phase_text}#{technique_text}#{indicator_text}

    The storyline encompasses #{length(storyline.nodes)} entities and #{length(storyline.edges)} relationships, \
    with a confidence score of #{trunc(storyline.confidence_score * 100)}%.
    """
    |> String.trim()
  end

  defp enhance_with_ai(analysis, storyline) do
    try do
      ai_module =
        cond do
          Process.whereis(TamanduaServer.AISecurity.AgenticAnalyst) ->
            :agentic_analyst

          Code.ensure_loaded?(TamanduaServer.AI.QueryInterface) ->
            :query_interface

          true ->
            nil
        end

      case ai_module do
        nil ->
          Logger.debug("AI modules unavailable, returning base storyline analysis")
          analysis

        module_type ->
          prompt_data = build_ai_prompt(storyline, analysis)

          case call_ai_module(module_type, prompt_data) do
            {:ok, ai_response} ->
              merge_ai_response(analysis, ai_response)

            {:error, reason} ->
              Logger.warning("AI storyline enhancement failed: #{inspect(reason)}")
              analysis
          end
      end
    rescue
      e ->
        Logger.error("AI enhancement error: #{Exception.message(e)}")
        analysis
    end
  end

  defp build_ai_prompt(storyline, analysis) do
    # Extract process names, file paths, and network connections from timeline
    events_summary =
      (storyline[:timeline] || [])
      |> Enum.take(50)
      |> Enum.map(fn event ->
        %{
          timestamp: event[:timestamp],
          type: event[:event_type],
          summary: event[:summary],
          severity: event[:severity],
          alert_id: event[:alert_id] || storyline[:alert_id],
          organization_id: event[:organization_id] || storyline[:organization_id]
        }
      end)

    process_names =
      (storyline[:nodes] || [])
      |> Enum.filter(fn node -> node[:type] == :process end)
      |> Enum.map(fn node -> node[:process_name] || node[:name] || node[:entity_name] end)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    file_paths =
      (storyline[:nodes] || [])
      |> Enum.filter(fn node -> node[:type] == :file end)
      |> Enum.map(fn node -> node[:path] || node[:name] || node[:entity_name] end)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    network_connections =
      (storyline[:nodes] || [])
      |> Enum.filter(fn node -> node[:type] == :network end)
      |> Enum.map(fn node -> node[:remote_addr] || node[:destination] || node[:name] end)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    technique_ids = storyline[:mitre_techniques] || []
    technique_details = analysis[:attack_techniques] || []

    %{
      type: :storyline_enhancement,
      alert_id: storyline[:alert_id],
      organization_id: storyline[:organization_id],
      events: events_summary,
      techniques: technique_ids,
      technique_details: technique_details,
      process_names: process_names,
      file_paths: file_paths,
      network_connections: network_connections,
      severity: storyline[:severity],
      attack_phase: storyline[:attack_phase],
      root_cause: storyline[:root_cause],
      time_range: storyline[:time_range],
      node_count: length(storyline[:nodes] || []),
      edge_count: length(storyline[:edges] || []),
      context: """
      Analyze this attack chain and provide:
      1) A concise narrative summary of what occurred
      2) Descriptions of the MITRE ATT&CK techniques observed
      3) Recommended remediation steps prioritized by urgency
      4) An overall risk assessment (critical/high/medium/low) with justification
      """
    }
  end

  defp call_ai_module(:agentic_analyst, prompt_data) do
    # The AgenticAnalyst is a GenServer; construct an alert-like triage
    # request containing the storyline context for analysis
    first_event = prompt_data[:events] |> List.first() || %{}
    alert_id = get_in(first_event, [:alert_id]) || prompt_data[:alert_id] || "storyline"
    organization_id = Map.get(first_event, :organization_id) || prompt_data[:organization_id]

    if is_nil(organization_id) do
      {:error, :organization_required}
    else
      case TamanduaServer.AISecurity.AgenticAnalyst.triage_alert(alert_id, organization_id) do
        {:ok, investigation_id} ->
          # Retrieve the investigation result with a brief wait for async processing
          Process.sleep(500)

          case TamanduaServer.AISecurity.AgenticAnalyst.get_investigation(investigation_id,
                 organization_id: organization_id
               ) do
            {:ok, investigation} ->
              {:ok,
               %{
                 ai_narrative: investigation[:explanation] || investigation[:summary] || "",
                 ai_remediation: investigation[:recommended_actions] || [],
                 ai_risk_assessment: investigation[:risk_level] || "unknown",
                 ai_techniques: investigation[:techniques] || [],
                 ai_confidence: investigation[:confidence] || 0.0
               }}

            {:error, reason} ->
              {:error, reason}
          end

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  defp call_ai_module(:query_interface, prompt_data) do
    # Use QueryInterface's process_query with a descriptive natural language prompt
    query_text = build_nl_query(prompt_data)

    case TamanduaServer.AI.QueryInterface.process_query(query_text, time_range: "24h") do
      %{summary: summary, results: results} ->
        technique_descriptions =
          (prompt_data[:technique_details] || [])
          |> Enum.map(fn t -> "#{t[:id]}: #{t[:name]} (#{t[:tactic]})" end)
          |> Enum.join("; ")

        remediation_steps = generate_ai_remediation(prompt_data)

        {:ok,
         %{
           ai_narrative: build_ai_narrative(prompt_data, summary, results),
           ai_remediation: remediation_steps,
           ai_risk_assessment: assess_risk_from_prompt(prompt_data),
           ai_techniques: technique_descriptions,
           ai_confidence: 0.7
         }}

      _ ->
        {:error, :unexpected_ai_response}
    end
  end

  defp build_nl_query(prompt_data) do
    process_part =
      case prompt_data[:process_names] do
        [_ | _] = names -> "processes #{Enum.take(names, 5) |> Enum.join(", ")}"
        _ -> "processes"
      end

    network_part =
      case prompt_data[:network_connections] do
        [_ | _] = conns ->
          " with network connections to #{Enum.take(conns, 3) |> Enum.join(", ")}"

        _ ->
          ""
      end

    technique_part =
      case prompt_data[:techniques] do
        [_ | _] = techs -> " involving techniques #{Enum.take(techs, 5) |> Enum.join(", ")}"
        _ -> ""
      end

    "Analyze attack chain involving #{process_part}#{network_part}#{technique_part}"
  end

  defp build_ai_narrative(prompt_data, summary, _results) do
    root_info =
      case prompt_data[:root_cause] do
        %{process_name: name} when is_binary(name) -> "originating from '#{name}'"
        %{entity_name: name} when is_binary(name) -> "starting with '#{name}'"
        _ -> "with an undetermined origin"
      end

    phase_info =
      case prompt_data[:attack_phase] do
        nil -> ""
        "unknown" -> ""
        phase -> " The attack progressed to the #{String.replace(phase, "_", " ")} phase."
      end

    process_info =
      case prompt_data[:process_names] do
        [_ | _] = names ->
          " Key processes involved: #{Enum.take(names, 5) |> Enum.join(", ")}."

        _ ->
          ""
      end

    network_info =
      case prompt_data[:network_connections] do
        [_ | _] = conns ->
          " External connections observed to: #{Enum.take(conns, 3) |> Enum.join(", ")}."

        _ ->
          ""
      end

    """
    AI-Enhanced Analysis: Attack chain #{root_info} involving \
    #{prompt_data[:node_count]} entities and #{prompt_data[:edge_count]} relationships.#{phase_info}\
    #{process_info}#{network_info} \
    Query analysis: #{summary}
    """
    |> String.trim()
  end

  defp generate_ai_remediation(prompt_data) do
    base_steps = []

    # Severity-based remediation
    base_steps =
      case prompt_data[:severity] do
        sev when sev in [:critical, "critical"] ->
          [
            %{priority: "immediate", step: "Isolate affected endpoint from network immediately"},
            %{priority: "immediate", step: "Initiate incident response procedures"},
            %{
              priority: "immediate",
              step: "Collect volatile forensic artifacts (memory dump, active connections)"
            }
            | base_steps
          ]

        sev when sev in [:high, "high"] ->
          [
            %{
              priority: "high",
              step: "Investigate process chain and determine scope of compromise"
            },
            %{priority: "high", step: "Check for lateral movement indicators on adjacent systems"}
            | base_steps
          ]

        _ ->
          base_steps
      end

    # Phase-based remediation
    base_steps =
      case prompt_data[:attack_phase] do
        "credential_access" ->
          [
            %{
              priority: "immediate",
              step: "Force password reset for all potentially compromised accounts"
            },
            %{priority: "high", step: "Review Active Directory for unauthorized changes"}
            | base_steps
          ]

        "exfiltration" ->
          [
            %{priority: "immediate", step: "Block identified external destinations at firewall"},
            %{priority: "high", step: "Determine scope and classification of exfiltrated data"}
            | base_steps
          ]

        "lateral_movement" ->
          [
            %{priority: "immediate", step: "Segment network to contain affected systems"},
            %{priority: "high", step: "Scan peer systems for identical IOCs"}
            | base_steps
          ]

        "command_and_control" ->
          [
            %{priority: "immediate", step: "Block C2 communication channels"},
            %{
              priority: "high",
              step: "Identify all endpoints communicating with C2 infrastructure"
            }
            | base_steps
          ]

        _ ->
          base_steps
      end

    # Technique-based remediation
    techniques = prompt_data[:techniques] || []

    base_steps =
      if Enum.any?(techniques, &String.starts_with?(&1, "T1059")) do
        [
          %{
            priority: "high",
            step: "Enable constrained language mode for PowerShell and audit script execution"
          }
          | base_steps
        ]
      else
        base_steps
      end

    base_steps =
      if Enum.any?(techniques, &String.starts_with?(&1, "T1003")) do
        [
          %{priority: "immediate", step: "Enable Credential Guard and audit LSASS access"}
          | base_steps
        ]
      else
        base_steps
      end

    base_steps =
      if Enum.any?(techniques, &String.starts_with?(&1, "T1486")) do
        [
          %{priority: "immediate", step: "Verify backup integrity and isolate backup systems"}
          | base_steps
        ]
      else
        base_steps
      end

    base_steps
    |> Enum.uniq_by(& &1.step)
    |> Enum.sort_by(fn s ->
      case s.priority do
        "immediate" -> 0
        "high" -> 1
        "medium" -> 2
        _ -> 3
      end
    end)
  end

  defp assess_risk_from_prompt(prompt_data) do
    severity_score =
      case prompt_data[:severity] do
        sev when sev in [:critical, "critical"] -> 40
        sev when sev in [:high, "high"] -> 30
        sev when sev in [:medium, "medium"] -> 20
        _ -> 10
      end

    technique_score = min(length(prompt_data[:techniques] || []) * 8, 30)

    network_score = if length(prompt_data[:network_connections] || []) > 0, do: 15, else: 0

    phase_score =
      case prompt_data[:attack_phase] do
        "exfiltration" -> 20
        "impact" -> 20
        "command_and_control" -> 15
        "lateral_movement" -> 15
        "credential_access" -> 10
        _ -> 0
      end

    total = severity_score + technique_score + network_score + phase_score

    cond do
      total >= 80 -> "critical"
      total >= 55 -> "high"
      total >= 30 -> "medium"
      true -> "low"
    end
  end

  defp merge_ai_response(analysis, ai_response) when is_map(ai_response) do
    analysis
    |> Map.put(:ai_narrative, ai_response[:ai_narrative] || "")
    |> Map.put(:ai_remediation, ai_response[:ai_remediation] || [])
    |> Map.put(:ai_risk_assessment, ai_response[:ai_risk_assessment] || "unknown")
    |> Map.put(:ai_techniques, ai_response[:ai_techniques] || [])
    |> Map.put(:ai_confidence, ai_response[:ai_confidence] || 0.0)
    |> Map.put(:ai_enhanced, true)
  end
end
