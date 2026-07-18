defmodule TamanduaServer.Response.AutonomousEngine do
  @moduledoc """
  ML-Driven Autonomous Response Engine

  Provides intelligent response recommendations by combining:
  - Risk assessment (severity, MITRE technique danger, asset criticality,
    historical FP rates, time-of-day, process lineage)
  - Confidence-thresholded execution (auto-execute, notify, recommend, alert-only)
  - Blast radius prediction (affected processes, users, downtime estimate)
  - Asset criticality management (auto-detection and manual overrides)
  - Feedback loop (analyst verdicts adjust per-rule / per-technique confidence)
  - Full pipeline: assess -> recommend -> threshold check -> execute or queue

  ## ETS Tables

  * `:autonomous_response_decisions` - Decision history keyed by alert_id
  * `:autonomous_asset_criticality` - Asset criticality scores per agent/hostname
  * `:autonomous_response_stats` - Aggregate statistics counters

  ## Integration

  * Broadcasts decisions on `"autonomous_response:decisions"` via Phoenix.PubSub
  * Executes actions through `TamanduaServer.Response.Executor`
  * Reads alerts via `TamanduaServer.Alerts`
  """

  use GenServer
  require Logger

  alias TamanduaServer.Response.Executor

  # ── ETS table names ──────────────────────────────────────────────
  @decisions_table :autonomous_response_decisions
  @criticality_table :autonomous_asset_criticality
  @stats_table :autonomous_response_stats

  # ── Timers ───────────────────────────────────────────────────────
  @stats_decay_interval :timer.minutes(60)
  @criticality_refresh_interval :timer.minutes(30)

  # ── MITRE technique dangerousness (higher = more dangerous) ─────
  @technique_danger %{
    # Execution
    "T1059" => 0.8, "T1059.001" => 0.85, "T1059.003" => 0.8,
    "T1059.005" => 0.75, "T1059.006" => 0.75, "T1059.007" => 0.7,
    "T1204" => 0.6, "T1204.001" => 0.6, "T1204.002" => 0.65,
    "T1053" => 0.7, "T1053.005" => 0.7,
    # Persistence
    "T1547" => 0.75, "T1547.001" => 0.75, "T1543" => 0.8,
    "T1543.003" => 0.8, "T1546" => 0.7, "T1546.001" => 0.7,
    # Privilege Escalation
    "T1548" => 0.85, "T1548.002" => 0.85, "T1134" => 0.85,
    "T1068" => 0.95,
    # Defense Evasion
    "T1055" => 0.9, "T1055.001" => 0.9, "T1055.012" => 0.9,
    "T1036" => 0.6, "T1036.005" => 0.65, "T1070" => 0.75,
    "T1070.001" => 0.75, "T1027" => 0.65, "T1562" => 0.85,
    "T1562.001" => 0.9,
    # Credential Access
    "T1003" => 0.95, "T1003.001" => 0.95, "T1003.002" => 0.9,
    "T1003.003" => 0.9, "T1110" => 0.7, "T1558" => 0.85,
    "T1558.003" => 0.85, "T1552" => 0.8,
    # Discovery
    "T1087" => 0.4, "T1082" => 0.35, "T1083" => 0.35,
    "T1016" => 0.35, "T1049" => 0.4, "T1018" => 0.45,
    # Lateral Movement
    "T1021" => 0.85, "T1021.001" => 0.85, "T1021.002" => 0.85,
    "T1021.006" => 0.8, "T1570" => 0.8, "T1080" => 0.75,
    # Collection / Exfiltration
    "T1560" => 0.7, "T1005" => 0.6, "T1041" => 0.9,
    "T1048" => 0.9, "T1567" => 0.85,
    # Command and Control
    "T1071" => 0.75, "T1105" => 0.7, "T1572" => 0.8,
    "T1573" => 0.75, "T1090" => 0.8,
    # Impact
    "T1486" => 1.0, "T1490" => 0.95, "T1489" => 0.85,
    "T1485" => 0.95, "T1529" => 0.8, "T1531" => 0.85
  }

  # ── LOLBins (Living off the Land binaries) ──────────────────────
  @lolbins MapSet.new([
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe",
    "cmstp.exe", "wmic.exe", "forfiles.exe", "pcalua.exe",
    "bash.exe", "python.exe", "perl.exe", "ruby.exe"
  ])

  # ── Critical Windows services / processes ───────────────────────
  @critical_processes MapSet.new([
    "svchost.exe", "lsass.exe", "csrss.exe", "wininit.exe",
    "services.exe", "smss.exe", "winlogon.exe", "dwm.exe",
    "System", "Registry", "explorer.exe", "spoolsv.exe",
    "SearchIndexer.exe", "taskhostw.exe"
  ])

  # ── System files / shared libraries ─────────────────────────────
  @system_paths [
    "C:\\Windows\\System32\\",
    "C:\\Windows\\SysWOW64\\",
    "C:\\Windows\\WinSxS\\",
    "/usr/lib/",
    "/usr/lib64/",
    "/lib/",
    "/lib64/",
    "/usr/bin/",
    "/usr/sbin/"
  ]

  # ── GenServer State ─────────────────────────────────────────────
  defstruct [
    thresholds: %{
      auto_execute: 0.95,
      auto_with_notify: 0.80,
      recommend: 0.60,
      alert_only: 0.0
    },
    feedback_history: %{},
    fp_rates: %{},
    initialized: false
  ]

  # ==================================================================
  # Client API
  # ==================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Assess risk for a given alert.

  Returns a map with :risk_score, :severity_score, :technique_score,
  :criticality_score, :fp_adjustment, :time_factor, :lineage_risk,
  and :combined_confidence.
  """
  @spec assess_risk(map()) :: {:ok, map()}
  def assess_risk(alert) do
    # Risk assessment is read-only from ETS -- no GenServer call needed
    {:ok, do_assess_risk(alert)}
  end

  @doc """
  Recommend response actions for a given risk assessment.

  Returns a list of action recommendations with :action_type, :target,
  :confidence, :reasoning, :blast_radius, and :execution_mode.
  """
  @spec recommend_actions(map()) :: {:ok, list(map())}
  def recommend_actions(assessment) do
    {:ok, do_recommend_actions(assessment)}
  end

  @doc """
  Predict the blast radius of a response action on a given agent.

  Returns :affected_processes, :affected_users, :estimated_downtime,
  and :risk_level.
  """
  @spec predict_blast_radius(String.t(), map()) :: {:ok, map()}
  def predict_blast_radius(action_type, params) do
    {:ok, do_predict_blast_radius(action_type, params)}
  end

  @doc """
  Set asset criticality for an agent. Score must be 0.0..1.0.
  """
  @spec set_asset_criticality(String.t(), map()) :: :ok
  def set_asset_criticality(agent_id, attrs) do
    GenServer.call(__MODULE__, {:set_criticality, agent_id, attrs})
  end

  @doc """
  Get asset criticality for an agent. Returns a map with :score, :role, :source.
  """
  @spec get_asset_criticality(String.t()) :: map()
  def get_asset_criticality(agent_id) do
    do_get_criticality(agent_id)
  end

  @doc """
  Return current confidence thresholds.
  """
  @spec get_thresholds() :: {:ok, map()}
  def get_thresholds do
    GenServer.call(__MODULE__, :get_thresholds)
  end

  @doc """
  Update confidence thresholds.
  """
  @spec update_thresholds(map()) :: {:ok, map()}
  def update_thresholds(new_thresholds) do
    GenServer.call(__MODULE__, {:update_thresholds, new_thresholds})
  end

  @doc """
  Record the outcome of a decision (confirmed, false_positive, adjusted).
  Feeds back into per-rule and per-technique FP rates.
  """
  @spec record_outcome(String.t(), String.t(), map()) :: :ok
  def record_outcome(alert_id, verdict, metadata \\ %{}) do
    GenServer.cast(__MODULE__, {:record_outcome, alert_id, verdict, metadata})
  end

  @doc """
  Recalculate confidence adjustments based on historical outcomes.
  """
  @spec adjust_confidence(String.t() | nil) :: {:ok, map()}
  def adjust_confidence(rule_name \\ nil) do
    GenServer.call(__MODULE__, {:adjust_confidence, rule_name})
  end

  @doc """
  Full pipeline: assess -> recommend -> check thresholds -> execute or queue.
  """
  @spec process_alert(map()) :: {:ok, map()}
  def process_alert(alert) do
    GenServer.call(__MODULE__, {:process_alert, alert}, 30_000)
  end

  @doc """
  Simulate the autonomous pipeline without executing any actions.
  """
  @spec simulate(map()) :: {:ok, map()}
  def simulate(alert) do
    GenServer.call(__MODULE__, {:simulate, alert})
  end

  @doc """
  Get aggregate statistics.
  """
  @spec get_stats() :: {:ok, map()}
  def get_stats do
    {:ok, do_get_stats()}
  end

  @doc """
  Get recent decisions (last N).
  """
  @spec get_decisions(keyword()) :: {:ok, list(map())}
  def get_decisions(opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    decisions = do_get_decisions(limit)
    {:ok, decisions}
  end

  # ==================================================================
  # GenServer Callbacks
  # ==================================================================

  @impl true
  def init(_opts) do
    Logger.info("[AutonomousEngine] Starting ML-driven autonomous response engine")

    init_ets_tables()

    schedule_stats_decay()
    schedule_criticality_refresh()

    {:ok, %__MODULE__{initialized: true}}
  end

  @impl true
  def handle_call(:get_thresholds, _from, state) do
    {:reply, {:ok, state.thresholds}, state}
  end

  @impl true
  def handle_call({:update_thresholds, new_thresholds}, _from, state) do
    merged = Map.merge(state.thresholds, normalize_thresholds(new_thresholds))
    new_state = %{state | thresholds: merged}
    Logger.info("[AutonomousEngine] Thresholds updated: #{inspect(merged)}")
    {:reply, {:ok, merged}, new_state}
  end

  @impl true
  def handle_call({:set_criticality, agent_id, attrs}, _from, state) do
    score = Map.get(attrs, :score, Map.get(attrs, "score", 0.5))
    role = Map.get(attrs, :role, Map.get(attrs, "role", "workstation"))
    source = Map.get(attrs, :source, Map.get(attrs, "source", "manual"))

    score_f = ensure_float(score)
    clamped = max(0.0, min(1.0, score_f))

    entry = %{
      score: clamped,
      role: to_string(role),
      source: to_string(source),
      updated_at: DateTime.utc_now()
    }

    :ets.insert(@criticality_table, {agent_id, entry})
    increment_stat(:criticality_updates)
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:process_alert, alert}, _from, state) do
    result = do_process_alert(alert, state.thresholds, _dry_run = false)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:simulate, alert}, _from, state) do
    result = do_process_alert(alert, state.thresholds, _dry_run = true)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:adjust_confidence, rule_name}, _from, state) do
    adjustments = compute_confidence_adjustments(rule_name)
    new_fp_rates = Map.merge(state.fp_rates, adjustments)
    {:reply, {:ok, adjustments}, %{state | fp_rates: new_fp_rates}}
  end

  @impl true
  def handle_cast({:record_outcome, alert_id, verdict, metadata}, state) do
    new_state = do_record_outcome(state, alert_id, verdict, metadata)
    {:noreply, new_state}
  end

  @impl true
  def handle_info(:stats_decay, state) do
    decay_stats()
    schedule_stats_decay()
    {:noreply, state}
  end

  @impl true
  def handle_info(:criticality_refresh, state) do
    refresh_auto_criticality()
    schedule_criticality_refresh()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ==================================================================
  # ETS Initialization
  # ==================================================================

  defp init_ets_tables do
    safe_create_table(@decisions_table, [:ordered_set, :public, :named_table,
      read_concurrency: true, write_concurrency: true])
    safe_create_table(@criticality_table, [:set, :public, :named_table,
      read_concurrency: true, write_concurrency: true])
    safe_create_table(@stats_table, [:set, :public, :named_table,
      read_concurrency: true, write_concurrency: true])

    # Seed initial stats counters
    initial_stats = [
      {:alerts_processed, 0},
      {:auto_executed, 0},
      {:auto_with_notify, 0},
      {:recommended, 0},
      {:alert_only, 0},
      {:outcomes_recorded, 0},
      {:false_positives, 0},
      {:true_positives, 0},
      {:criticality_updates, 0}
    ]

    Enum.each(initial_stats, fn {key, val} ->
      :ets.insert_new(@stats_table, {key, val})
    end)
  end

  defp safe_create_table(name, opts) do
    case :ets.whereis(name) do
      :undefined -> :ets.new(name, opts)
      _ref -> name
    end
  end

  # ==================================================================
  # Risk Assessment (pure functions -- no GenServer state needed)
  # ==================================================================

  defp do_assess_risk(alert) do
    severity_score = severity_to_score(alert)
    technique_score = technique_danger_score(alert)
    criticality_score = asset_criticality_score(alert)
    fp_adjustment = false_positive_adjustment(alert)
    time_factor = time_of_day_factor()
    lineage_risk = process_lineage_risk(alert)

    # Weighted combination
    raw_score =
      severity_score * 0.25 +
      technique_score * 0.25 +
      criticality_score * 0.15 +
      time_factor * 0.05 +
      lineage_risk * 0.15 +
      (1.0 - fp_adjustment) * 0.15

    combined = max(0.0, min(1.0, raw_score))

    %{
      alert_id: extract_alert_id(alert),
      risk_score: Float.round(combined, 4),
      severity_score: Float.round(severity_score, 4),
      technique_score: Float.round(technique_score, 4),
      criticality_score: Float.round(criticality_score, 4),
      fp_adjustment: Float.round(fp_adjustment, 4),
      time_factor: Float.round(time_factor, 4),
      lineage_risk: Float.round(lineage_risk, 4),
      combined_confidence: Float.round(combined, 4),
      severity: extract_severity(alert),
      agent_id: extract_agent_id(alert),
      techniques: extract_techniques(alert),
      assessed_at: DateTime.utc_now()
    }
  end

  defp severity_to_score(alert) do
    case extract_severity(alert) do
      "critical" -> 1.0
      "high" -> 0.8
      "medium" -> 0.5
      "low" -> 0.2
      _ -> 0.3
    end
  end

  defp technique_danger_score(alert) do
    techniques = extract_techniques(alert)

    if techniques == [] do
      0.5
    else
      scores = Enum.map(techniques, fn t -> Map.get(@technique_danger, t, 0.5) end)
      Enum.max(scores)
    end
  end

  defp asset_criticality_score(alert) do
    agent_id = extract_agent_id(alert)

    if agent_id do
      crit = do_get_criticality(agent_id)
      crit.score
    else
      0.5
    end
  end

  defp false_positive_adjustment(alert) do
    # Look up historical FP rate for the alert's rule / title
    key = fp_key(alert)

    case :ets.lookup(@stats_table, {:fp_rate, key}) do
      [{_, rate}] -> rate
      [] -> 0.0
    end
  rescue
    ArgumentError -> 0.0
  end

  defp time_of_day_factor do
    hour = DateTime.utc_now().hour

    cond do
      hour >= 8 and hour <= 18 -> 0.8   # Business hours: higher risk weight
      hour >= 22 or hour <= 5 -> 0.5    # Off-hours: lower risk weight
      true -> 0.65                       # Shoulder hours
    end
  end

  defp process_lineage_risk(alert) do
    chain = extract_process_chain(alert)

    if chain == [] do
      0.5
    else
      lolbin_count =
        chain
        |> Enum.map(fn entry -> extract_process_name(entry) end)
        |> Enum.count(fn name ->
          name != nil and MapSet.member?(@lolbins, String.downcase(name))
        end)

      cond do
        lolbin_count >= 3 -> 1.0
        lolbin_count == 2 -> 0.85
        lolbin_count == 1 -> 0.7
        true -> 0.4
      end
    end
  end

  # ==================================================================
  # Response Recommendations
  # ==================================================================

  defp do_recommend_actions(assessment) do
    confidence = assessment.combined_confidence
    severity = assessment.severity
    agent_id = assessment.agent_id
    techniques = assessment.techniques || []

    execution_mode = determine_execution_mode(confidence, severity)

    actions = build_action_list(severity, techniques, agent_id, assessment)

    Enum.map(actions, fn action ->
      blast = do_predict_blast_radius(action.action_type, %{
        agent_id: agent_id,
        target: action.target
      })

      Map.merge(action, %{
        confidence: Float.round(confidence, 4),
        execution_mode: execution_mode,
        blast_radius: blast,
        recommended_at: DateTime.utc_now()
      })
    end)
  end

  defp determine_execution_mode(confidence, severity) do
    # Read thresholds from GenServer state would block; use defaults.
    # Callers who need custom thresholds go through process_alert/1.
    determine_mode_with_thresholds(confidence, severity, %{
      auto_execute: 0.95,
      auto_with_notify: 0.80,
      recommend: 0.60,
      alert_only: 0.0
    })
  end

  defp determine_mode_with_thresholds(confidence, severity, thresholds) do
    cond do
      confidence >= thresholds.auto_execute and severity in ["critical", "high"] ->
        :auto_execute
      confidence >= thresholds.auto_with_notify and severity in ["critical", "high"] ->
        :auto_with_notify
      confidence >= thresholds.recommend ->
        :recommend
      true ->
        :alert_only
    end
  end

  defp build_action_list(severity, techniques, agent_id, assessment) do
    base_actions = []

    # Credential theft -> kill process + quarantine
    base_actions =
      if has_technique_prefix?(techniques, "T1003") do
        base_actions ++ [
          %{action_type: "kill_process", target: %{agent_id: agent_id},
            reasoning: "Credential dumping detected (LSASS access)"},
          %{action_type: "quarantine_file", target: %{agent_id: agent_id},
            reasoning: "Quarantine credential theft tool"}
        ]
      else
        base_actions
      end

    # Ransomware -> isolate + kill + quarantine
    base_actions =
      if has_technique_prefix?(techniques, "T1486") do
        base_actions ++ [
          %{action_type: "isolate_network", target: %{agent_id: agent_id},
            reasoning: "Ransomware detected -- isolate to prevent lateral spread"},
          %{action_type: "kill_process", target: %{agent_id: agent_id},
            reasoning: "Terminate ransomware process"},
          %{action_type: "quarantine_file", target: %{agent_id: agent_id},
            reasoning: "Quarantine ransomware binary"}
        ]
      else
        base_actions
      end

    # Lateral movement -> isolate
    base_actions =
      if has_technique_prefix?(techniques, "T1021") or has_technique_prefix?(techniques, "T1570") do
        base_actions ++ [
          %{action_type: "isolate_network", target: %{agent_id: agent_id},
            reasoning: "Lateral movement detected -- contain compromised host"}
        ]
      else
        base_actions
      end

    # Process injection -> kill
    base_actions =
      if has_technique_prefix?(techniques, "T1055") do
        base_actions ++ [
          %{action_type: "kill_process", target: %{agent_id: agent_id},
            reasoning: "Process injection detected -- terminate injecting process"}
        ]
      else
        base_actions
      end

    # If no specific technique-based actions, fall back on severity
    if base_actions == [] do
      case severity do
        "critical" ->
          [
            %{action_type: "kill_process", target: %{agent_id: agent_id},
              reasoning: "Critical severity -- terminate suspicious process"},
            %{action_type: "quarantine_file", target: %{agent_id: agent_id},
              reasoning: "Critical severity -- quarantine suspicious file"},
            %{action_type: "isolate_network", target: %{agent_id: agent_id},
              reasoning: "Critical severity -- isolate host"}
          ]

        "high" ->
          [
            %{action_type: "kill_process", target: %{agent_id: agent_id},
              reasoning: "High severity -- terminate suspicious process"},
            %{action_type: "quarantine_file", target: %{agent_id: agent_id},
              reasoning: "High severity -- quarantine suspicious file"}
          ]

        "medium" ->
          alert_id = Map.get(assessment, :alert_id)
          [
            %{action_type: "collect_forensics", target: %{agent_id: agent_id},
              reasoning: "Medium severity alert #{alert_id} -- gather evidence for triage"}
          ]

        _ ->
          alert_id = Map.get(assessment, :alert_id)
          [
            %{action_type: "alert_only", target: %{agent_id: agent_id},
              reasoning: "Low severity alert #{alert_id} -- monitor only"}
          ]
      end
    else
      base_actions
    end
  end

  defp has_technique_prefix?(techniques, prefix) do
    Enum.any?(techniques, fn t -> String.starts_with?(t, prefix) end)
  end

  # ==================================================================
  # Blast Radius Prediction
  # ==================================================================

  defp do_predict_blast_radius(action_type, params) do
    agent_id = Map.get(params, :agent_id) || Map.get(params, "agent_id")
    target = Map.get(params, :target) || Map.get(params, "target") || %{}

    case to_string(action_type) do
      "kill_process" ->
        predict_kill_blast(agent_id, target)

      "quarantine_file" ->
        predict_quarantine_blast(agent_id, target)

      "isolate_network" ->
        predict_isolate_blast(agent_id)

      _ ->
        %{
          affected_processes: 0,
          affected_users: 0,
          estimated_downtime: 0,
          risk_level: "low",
          details: "No blast radius prediction for action: #{action_type}"
        }
    end
  end

  defp predict_kill_blast(agent_id, target) do
    process_name = extract_process_name(target)

    {affected, downtime, risk} =
      cond do
        process_name != nil and MapSet.member?(@critical_processes, process_name) ->
          {50, 300, "critical"}
        process_name != nil and String.ends_with?(process_name, "svc.exe") ->
          {10, 60, "high"}
        true ->
          {1, 0, "low"}
      end

    %{
      affected_processes: affected,
      affected_users: if(risk == "critical", do: estimate_users(agent_id), else: 1),
      estimated_downtime: downtime,
      risk_level: risk,
      is_critical_process: process_name != nil and MapSet.member?(@critical_processes, process_name),
      process_name: process_name
    }
  end

  defp predict_quarantine_blast(_agent_id, target) do
    path = Map.get(target, :path) || Map.get(target, "path") || ""

    is_system = Enum.any?(@system_paths, fn sp -> String.starts_with?(path, sp) end)
    is_dll = String.ends_with?(path, ".dll") or String.ends_with?(path, ".so")

    {affected, downtime, risk} =
      cond do
        is_system and is_dll -> {20, 120, "critical"}
        is_system -> {5, 60, "high"}
        is_dll -> {10, 30, "medium"}
        true -> {0, 0, "low"}
      end

    %{
      affected_processes: affected,
      affected_users: if(risk in ["critical", "high"], do: 5, else: 0),
      estimated_downtime: downtime,
      risk_level: risk,
      is_system_file: is_system,
      is_shared_library: is_dll,
      file_path: path
    }
  end

  defp predict_isolate_blast(agent_id) do
    criticality = do_get_criticality(agent_id)

    {users, downtime, risk} =
      cond do
        criticality.score >= 0.9 ->
          {100, 600, "critical"}
        criticality.score >= 0.7 ->
          {20, 300, "high"}
        criticality.score >= 0.5 ->
          {5, 120, "medium"}
        true ->
          {1, 30, "low"}
      end

    %{
      affected_processes: 0,
      affected_users: users,
      estimated_downtime: downtime,
      risk_level: risk,
      asset_criticality: criticality.score,
      asset_role: criticality.role,
      details: "Network isolation will sever all connections except management"
    }
  end

  defp estimate_users(_agent_id), do: 10

  # ==================================================================
  # Asset Criticality (ETS reads -- no GenServer call needed)
  # ==================================================================

  defp do_get_criticality(agent_id) when is_binary(agent_id) do
    case :ets.lookup(@criticality_table, agent_id) do
      [{_, entry}] -> entry
      [] -> auto_detect_criticality(agent_id)
    end
  rescue
    ArgumentError -> %{score: 0.5, role: "unknown", source: "default"}
  end

  defp do_get_criticality(_), do: %{score: 0.5, role: "unknown", source: "default"}

  defp auto_detect_criticality(agent_id) do
    # Attempt to read agent metadata for role detection
    agent_info = try do
      case TamanduaServer.Agents.Registry.get(agent_id) do
        {:ok, info} -> info
        _ -> %{}
      end
    rescue
      _ -> %{}
    catch
      _, _ -> %{}
    end

    hostname = Map.get(agent_info, :hostname, "") |> to_string() |> String.downcase()
    os_type = Map.get(agent_info, :os_type, "") |> to_string() |> String.downcase()

    {score, role} =
      cond do
        String.contains?(hostname, "dc") or String.contains?(hostname, "domain") ->
          {1.0, "domain_controller"}
        String.contains?(hostname, "sql") or String.contains?(hostname, "db") or
          String.contains?(hostname, "postgres") or String.contains?(hostname, "mysql") ->
          {0.9, "database_server"}
        String.contains?(hostname, "web") or String.contains?(hostname, "www") or
          String.contains?(hostname, "nginx") or String.contains?(hostname, "apache") ->
          {0.8, "web_server"}
        String.contains?(hostname, "srv") or String.contains?(hostname, "server") ->
          {0.7, "server"}
        String.contains?(hostname, "dev") or String.contains?(hostname, "test") or
          String.contains?(hostname, "staging") ->
          {0.3, "development"}
        os_type == "linux" ->
          {0.6, "linux_workstation"}
        true ->
          {0.5, "workstation"}
      end

    %{score: score, role: role, source: "auto_detected"}
  end

  defp refresh_auto_criticality do
    # Re-evaluate auto-detected entries (not manual overrides)
    entries = :ets.tab2list(@criticality_table)

    Enum.each(entries, fn {agent_id, entry} ->
      if entry.source == "auto_detected" do
        new_entry = auto_detect_criticality(agent_id)
        :ets.insert(@criticality_table, {agent_id, new_entry})
      end
    end)
  rescue
    ArgumentError -> :ok
  end

  # ==================================================================
  # Full Processing Pipeline
  # ==================================================================

  defp do_process_alert(alert, thresholds, dry_run) do
    assessment = do_assess_risk(alert)
    actions = do_recommend_actions(assessment)

    mode = determine_mode_with_thresholds(
      assessment.combined_confidence,
      assessment.severity,
      thresholds
    )

    execution_results =
      if dry_run do
        Enum.map(actions, fn action ->
          %{action: action.action_type, status: "simulated", mode: mode}
        end)
      else
        execute_pipeline(actions, mode, alert)
      end

    decision = %{
      alert_id: assessment.alert_id,
      assessment: assessment,
      recommended_actions: actions,
      execution_mode: mode,
      execution_results: execution_results,
      dry_run: dry_run,
      decided_at: DateTime.utc_now()
    }

    # Persist decision and update stats
    unless dry_run do
      store_decision(decision)
      update_pipeline_stats(mode)
      broadcast_decision(decision)
    end

    decision
  end

  defp execute_pipeline(actions, mode, alert) do
    case mode do
      :auto_execute ->
        if autonomous_execution_enabled?() do
          Enum.map(actions, fn action -> execute_action(action, alert, mode) end)
        else
          automatic_execution_blocked(actions, mode)
        end

      :auto_with_notify ->
        results =
          if autonomous_execution_enabled?() do
            Enum.map(actions, fn action -> execute_action(action, alert, mode) end)
          else
            automatic_execution_blocked(actions, mode)
          end

        notify_analysts(alert, actions, results)
        results

      :recommend ->
        notify_analysts(alert, actions, [])
        Enum.map(actions, fn action ->
          %{action: action.action_type, status: "awaiting_analyst", mode: :recommend}
        end)

      :alert_only ->
        Enum.map(actions, fn action ->
          %{action: action.action_type, status: "alert_only", mode: :alert_only}
        end)
    end
  end

  defp execute_action(action, alert, mode) do
    agent_id = get_in(action, [:target, :agent_id]) || extract_agent_id(alert)

    if agent_id == nil do
      %{action: action.action_type, status: "skipped", reason: "no agent_id"}
    else
      case action.action_type do
        "kill_process" ->
          pid = extract_process_pid(alert)
          if pid do
            execute_if_enabled("kill_process", mode, fn -> Executor.kill_process(agent_id, pid) end)
          else
            %{action: "kill_process", status: "skipped", reason: "no pid available"}
          end

        "quarantine_file" ->
          path = extract_file_path(alert)
          if path do
            # Safety instrumentation: when the target resolves to a protected
            # entity, either BLOCK the action (enforcing) or log a would-block
            # warning while leaving behavior unchanged (report-only default).
            cond do
              protected_target?(path) and response_safety_enforce?() ->
                Logger.warning("[ResponseSafety] BLOCKED response on protected target: #{path} (enforcing)")
                %{action: "quarantine_file", status: "blocked", reason: "protected_target"}

              true ->
                if protected_target?(path) do
                  Logger.warning("[ResponseSafety] would-block response on protected target: #{path} (report-only)")
                end

                execute_if_enabled("quarantine_file", mode, fn ->
                  Executor.quarantine_file(agent_id, path)
                end)
            end
          else
            %{action: "quarantine_file", status: "skipped", reason: "no file path"}
          end

        "isolate_network" ->
          execute_if_enabled("isolate_network", mode, fn -> Executor.isolate_network(agent_id) end)

        "collect_forensics" ->
          execute_if_enabled("collect_forensics", mode, fn ->
            Executor.collect_forensics(agent_id)
          end)

        other ->
          %{action: other, status: "unsupported"}
      end
    end
  end

  defp automatic_execution_blocked(actions, mode) do
    Enum.map(actions, fn action ->
      %{
        action: action.action_type,
        status: "blocked",
        reason: "autonomous_execution_disabled",
        mode: mode
      }
    end)
  end

  defp execute_if_enabled(action_type, mode, executor) do
    if mode in [:auto_execute, :auto_with_notify] and autonomous_execution_enabled?() do
      case executor.() do
        {:ok, response} -> %{action: action_type, status: "executed", result: response}
        {:error, error} -> %{action: action_type, status: "failed", error: inspect(error)}
      end
    else
      %{
        action: action_type,
        status: "cancelled",
        reason: "autonomous_execution_disabled",
        mode: mode
      }
    end
  end

  # Product-level emergency stop. Only literal true enables autonomous response;
  # missing or unreadable configuration remains fail-closed.
  defp autonomous_execution_enabled? do
    Application.get_env(:tamandua_server, :autonomous_execution_enabled, false) === true
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  defp notify_analysts(alert, actions, results) do
    alert_id = extract_alert_id(alert)
    action_summary = Enum.map(actions, fn a -> a.action_type end) |> Enum.join(", ")

    payload = %{
      type: "autonomous_response_notification",
      alert_id: alert_id,
      actions: action_summary,
      results: results,
      timestamp: DateTime.utc_now()
    }

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "autonomous_response:notifications",
      {:autonomous_notification, payload}
    )
  rescue
    _ -> :ok
  end

  # ==================================================================
  # Decision Storage
  # ==================================================================

  defp store_decision(decision) do
    key = {System.monotonic_time(), decision.alert_id}
    :ets.insert(@decisions_table, {key, decision})
  rescue
    ArgumentError -> :ok
  end

  defp do_get_decisions(limit) do
    # Ordered set -- traverse in reverse for most-recent-first
    all = :ets.tab2list(@decisions_table)

    all
    |> Enum.map(fn {_key, decision} -> decision end)
    |> Enum.sort_by(fn d -> d.decided_at end, {:desc, DateTime})
    |> Enum.take(limit)
  rescue
    ArgumentError -> []
  end

  defp broadcast_decision(decision) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "autonomous_response:decisions",
      {:autonomous_decision, decision}
    )
  rescue
    _ -> :ok
  end

  # ==================================================================
  # Feedback Loop
  # ==================================================================

  defp do_record_outcome(state, alert_id, verdict, metadata) do
    increment_stat(:outcomes_recorded)

    fp_key = Map.get(metadata, :rule_name) || Map.get(metadata, "rule_name") || alert_id

    case verdict do
      "false_positive" ->
        increment_stat(:false_positives)
        update_fp_rate(fp_key, :increment)

      "confirmed" ->
        increment_stat(:true_positives)
        update_fp_rate(fp_key, :decrement)

      _ ->
        :ok
    end

    # Store in feedback history
    entry = %{
      alert_id: alert_id,
      verdict: verdict,
      metadata: metadata,
      recorded_at: DateTime.utc_now()
    }

    new_history = Map.put(state.feedback_history, alert_id, entry)
    %{state | feedback_history: new_history}
  end

  defp update_fp_rate(key, direction) do
    current =
      case :ets.lookup(@stats_table, {:fp_rate, key}) do
        [{_, rate}] -> rate
        [] -> 0.0
      end

    new_rate = case direction do
      :increment -> min(1.0, current + 0.05)
      :decrement -> max(0.0, current - 0.02)
    end

    :ets.insert(@stats_table, {{:fp_rate, key}, new_rate})
  rescue
    ArgumentError -> :ok
  end

  defp compute_confidence_adjustments(nil) do
    # Compute for all tracked keys
    all = :ets.match(@stats_table, {{:fp_rate, :"$1"}, :"$2"})

    all
    |> Enum.map(fn [key, rate] -> {key, rate} end)
    |> Map.new()
  rescue
    ArgumentError -> %{}
  end

  defp compute_confidence_adjustments(rule_name) do
    case :ets.lookup(@stats_table, {:fp_rate, rule_name}) do
      [{_, rate}] -> %{rule_name => rate}
      [] -> %{rule_name => 0.0}
    end
  rescue
    ArgumentError -> %{rule_name => 0.0}
  end

  # ==================================================================
  # Statistics
  # ==================================================================

  defp do_get_stats do
    counters = [
      :alerts_processed, :auto_executed, :auto_with_notify,
      :recommended, :alert_only, :outcomes_recorded,
      :false_positives, :true_positives, :criticality_updates
    ]

    stats = Enum.map(counters, fn key ->
      case :ets.lookup(@stats_table, key) do
        [{_, val}] -> {key, val}
        [] -> {key, 0}
      end
    end)
    |> Map.new()

    decisions_count =
      try do
        :ets.info(@decisions_table, :size)
      rescue
        _ -> 0
      end

    criticality_count =
      try do
        :ets.info(@criticality_table, :size)
      rescue
        _ -> 0
      end

    Map.merge(stats, %{
      total_decisions: decisions_count,
      total_assets_tracked: criticality_count,
      engine_status: "running"
    })
  rescue
    ArgumentError ->
      %{engine_status: "initializing"}
  end

  defp increment_stat(key) do
    :ets.update_counter(@stats_table, key, {2, 1}, {key, 0})
  rescue
    ArgumentError -> :ok
  end

  defp update_pipeline_stats(mode) do
    increment_stat(:alerts_processed)

    case mode do
      :auto_execute -> increment_stat(:auto_executed)
      :auto_with_notify -> increment_stat(:auto_with_notify)
      :recommend -> increment_stat(:recommended)
      :alert_only -> increment_stat(:alert_only)
    end
  end

  defp decay_stats do
    # Slight decay on FP rates over time (prevents stale FP data)
    all = :ets.match(@stats_table, {{:fp_rate, :"$1"}, :"$2"})

    Enum.each(all, fn [key, rate] ->
      decayed = rate * 0.99
      :ets.insert(@stats_table, {{:fp_rate, key}, decayed})
    end)
  rescue
    ArgumentError -> :ok
  end

  # ==================================================================
  # Scheduling
  # ==================================================================

  defp schedule_stats_decay do
    Process.send_after(self(), :stats_decay, @stats_decay_interval)
  end

  defp schedule_criticality_refresh do
    Process.send_after(self(), :criticality_refresh, @criticality_refresh_interval)
  end

  # ==================================================================
  # Helpers -- Extract fields from heterogeneous alert maps / structs
  # ==================================================================

  defp extract_alert_id(alert) do
    Map.get(alert, :id) || Map.get(alert, "id") || "unknown"
  end

  defp extract_severity(alert) do
    sev = Map.get(alert, :severity) || Map.get(alert, "severity") || "medium"
    to_string(sev) |> String.downcase()
  end

  defp extract_agent_id(alert) do
    Map.get(alert, :agent_id) || Map.get(alert, "agent_id")
  end

  defp extract_techniques(alert) do
    techniques = Map.get(alert, :mitre_techniques) || Map.get(alert, "mitre_techniques") || []
    if is_list(techniques), do: techniques, else: []
  end

  defp extract_process_chain(alert) do
    chain = Map.get(alert, :process_chain) || Map.get(alert, "process_chain") || []
    if is_list(chain), do: chain, else: []
  end

  # REPORT-ONLY protected-target check. Mirrors Executor.protected_target?/1 but
  # inlined here because that helper is private to the Executor module. Matches on
  # the case-insensitive basename so bare names and full paths both match.
  @protected_targets ~w(
    lsass.exe system services.exe csrss.exe wininit.exe winlogon.exe smss.exe
    tamandua_agent tamandua_agent.exe tamandua_watchdog tamandua_watchdog.exe
    tamandua_driver tamandua_driver.sys
  )

  defp protected_target?(name_or_path) when is_binary(name_or_path) do
    basename = name_or_path |> Path.basename() |> String.downcase()
    basename in @protected_targets
  end

  defp protected_target?(_), do: false

  # Whether the response-safety guard should ENFORCE (block) rather than merely
  # report. Defaults to false: report-only behavior is preserved unless an
  # operator explicitly opts in via `config :tamandua_server, :response_safety_enforce, true`.
  defp response_safety_enforce?, do: Application.get_env(:tamandua_server, :response_safety_enforce, false)

  defp extract_process_name(entry) when is_map(entry) do
    name = Map.get(entry, :name) || Map.get(entry, "name") ||
           Map.get(entry, :process_name) || Map.get(entry, "process_name")

    if name, do: Path.basename(to_string(name)), else: nil
  end

  defp extract_process_name(name) when is_binary(name), do: Path.basename(name)
  defp extract_process_name(_), do: nil

  defp extract_process_pid(alert) do
    evidence = Map.get(alert, :evidence) || Map.get(alert, "evidence") || %{}
    detection = Map.get(alert, :detection_metadata) || Map.get(alert, "detection_metadata") || %{}

    pid = Map.get(evidence, :pid) || Map.get(evidence, "pid") ||
          Map.get(detection, :pid) || Map.get(detection, "pid")

    case pid do
      nil -> nil
      p when is_integer(p) -> p
      p when is_binary(p) ->
        case Integer.parse(p) do
          {n, _} -> n
          :error -> nil
        end
      _ -> nil
    end
  end

  defp extract_file_path(alert) do
    evidence = Map.get(alert, :evidence) || Map.get(alert, "evidence") || %{}
    detection = Map.get(alert, :detection_metadata) || Map.get(alert, "detection_metadata") || %{}

    Map.get(evidence, :file_path) || Map.get(evidence, "file_path") ||
    Map.get(detection, :file_path) || Map.get(detection, "file_path") ||
    Map.get(evidence, :path) || Map.get(evidence, "path")
  end

  defp fp_key(alert) do
    title = Map.get(alert, :title) || Map.get(alert, "title") || ""
    rule = get_in(alert, [:detection_metadata, :rule_name]) ||
           get_in(alert, ["detection_metadata", "rule_name"]) ||
           title

    to_string(rule)
  end

  defp normalize_thresholds(thresholds) when is_map(thresholds) do
    allowed = [:auto_execute, :auto_with_notify, :recommend, :alert_only]

    thresholds
    |> Enum.reduce(%{}, fn {k, v}, acc ->
      key = normalize_key(k, allowed)
      if key, do: Map.put(acc, key, ensure_float(v)), else: acc
    end)
  end

  defp normalize_key(k, allowed) when is_atom(k) do
    if k in allowed, do: k, else: nil
  end

  defp normalize_key(k, allowed) when is_binary(k) do
    atom =
      try do
        String.to_existing_atom(k)
      rescue
        ArgumentError -> nil
      end

    if atom && atom in allowed, do: atom, else: nil
  end

  defp normalize_key(_, _), do: nil

  defp ensure_float(v) when is_float(v), do: v
  defp ensure_float(v) when is_integer(v), do: v / 1
  defp ensure_float(v) when is_binary(v) do
    case Float.parse(v) do
      {f, _} -> f
      :error -> 0.0
    end
  end
  defp ensure_float(_), do: 0.0
end
