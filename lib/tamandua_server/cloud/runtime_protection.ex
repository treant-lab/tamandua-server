defmodule TamanduaServer.Cloud.RuntimeProtection do
  @moduledoc """
  Cloud Runtime Protection for cloud workloads.

  Provides real-time threat detection and protection for cloud workloads including:
  - Container drift detection
  - Runtime threat detection
  - Kubernetes admission control
  - Cloud workload behavior monitoring
  - Anomaly detection in cloud environments

  ## Features

  ### Container Drift Detection
  Detects when container file systems have been modified from their original image,
  which may indicate compromise or unauthorized changes.

  ### Kubernetes Admission Control
  Integrates with K8s admission webhooks to enforce security policies
  before workloads are deployed.

  ### Runtime Threat Detection
  Real-time monitoring for:
  - Cryptomining processes
  - Reverse shells
  - Privilege escalation attempts
  - Container escape attempts
  - Suspicious network connections

  ### Behavioral Monitoring
  Baselines normal workload behavior and detects anomalies including:
  - Unusual process execution
  - Abnormal network patterns
  - Resource usage anomalies
  - API call patterns
  """

  use GenServer
  require Logger

  alias TamanduaServer.{Alerts, Telemetry}
  alias TamanduaServer.Cloud.Finding
  alias TamanduaServer.Agents.OrgLookup

  # ETS tables for runtime state
  @workload_state_table :cloud_workload_state
  @baselines_table :cloud_workload_baselines
  @drift_table :container_drift_cache
  @admission_policies_table :k8s_admission_policies

  # Threat signatures
  @cryptominer_processes [
    "xmrig", "minerd", "cpuminer", "cgminer", "bfgminer", "ethminer",
    "nbminer", "phoenixminer", "t-rex", "gminer", "lolminer"
  ]

  @reverse_shell_patterns [
    ~r/bash\s+-i\s+>&\s+\/dev\/tcp/,
    ~r/nc\s+.*-e\s+(\/bin\/)?(ba)?sh/,
    ~r/python.*socket.*connect.*spawn/,
    ~r/perl.*socket.*INET.*exec/,
    ~r/ruby.*TCPSocket.*exec/,
    ~r/php.*fsockopen.*\/bin\/(ba)?sh/,
    ~r/socat.*exec.*sh/,
    ~r/mkfifo.*nc.*sh/
  ]

  @privilege_escalation_commands [
    "sudo", "su", "pkexec", "doas", "setuid", "setgid",
    "chmod u+s", "chmod g+s", "chown root"
  ]

  @container_escape_indicators [
    "/var/run/docker.sock",
    "/var/run/containerd",
    "/proc/1/root",
    "nsenter",
    "unshare",
    "cgroup_release_agent",
    "/sys/kernel/uevent_helper"
  ]

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Process a runtime event from a cloud workload.
  """
  def process_event(agent_id, event) do
    GenServer.cast(__MODULE__, {:process_event, agent_id, event})
  end

  @doc """
  Check container for drift from original image.
  """
  def check_drift(container_id, filesystem_snapshot) do
    GenServer.call(__MODULE__, {:check_drift, container_id, filesystem_snapshot})
  end

  @doc """
  Evaluate a Kubernetes admission request.
  Returns :allow, :deny, or {:deny, reason}.
  """
  def evaluate_admission(admission_request) do
    GenServer.call(__MODULE__, {:evaluate_admission, admission_request})
  end

  @doc """
  Get runtime protection status for a workload.
  """
  def get_workload_status(workload_id) do
    GenServer.call(__MODULE__, {:get_workload_status, workload_id})
  end

  @doc """
  List all monitored workloads.
  """
  def list_monitored_workloads(filters \\ %{}) do
    GenServer.call(__MODULE__, {:list_workloads, filters})
  end

  @doc """
  Create or update workload baseline.
  """
  def update_baseline(workload_id, baseline_data) do
    GenServer.call(__MODULE__, {:update_baseline, workload_id, baseline_data})
  end

  @doc """
  Get workload baseline.
  """
  def get_baseline(workload_id) do
    GenServer.call(__MODULE__, {:get_baseline, workload_id})
  end

  @doc """
  Add Kubernetes admission policy.
  """
  def add_admission_policy(policy) do
    GenServer.call(__MODULE__, {:add_admission_policy, policy})
  end

  @doc """
  List Kubernetes admission policies.
  """
  def list_admission_policies do
    GenServer.call(__MODULE__, :list_admission_policies)
  end

  @doc """
  Get runtime protection statistics.
  """
  def get_statistics do
    GenServer.call(__MODULE__, :get_statistics)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@workload_state_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@baselines_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@drift_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@admission_policies_table, [:set, :named_table, :public, read_concurrency: true])

    # Initialize default admission policies
    initialize_default_admission_policies()

    # Schedule periodic baseline learning and cleanup
    :timer.send_interval(60_000, :baseline_learning)
    :timer.send_interval(300_000, :cleanup_stale)

    Logger.info("Cloud Runtime Protection service started")
    {:ok, %{events_processed: 0, threats_detected: 0}}
  end

  @impl true
  def handle_cast({:process_event, agent_id, event}, state) do
    new_state = analyze_runtime_event(agent_id, event, state)
    {:noreply, new_state}
  end

  @impl true
  def handle_call({:check_drift, container_id, snapshot}, _from, state) do
    result = check_container_drift(container_id, snapshot)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:evaluate_admission, request}, _from, state) do
    result = evaluate_admission_request(request)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_workload_status, workload_id}, _from, state) do
    result =
      case :ets.lookup(@workload_state_table, workload_id) do
        [{^workload_id, workload}] -> {:ok, workload}
        [] -> {:error, :not_found}
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:list_workloads, filters}, _from, state) do
    workloads =
      :ets.tab2list(@workload_state_table)
      |> Enum.map(fn {_id, workload} -> workload end)
      |> apply_workload_filters(filters)

    {:reply, workloads, state}
  end

  @impl true
  def handle_call({:update_baseline, workload_id, baseline_data}, _from, state) do
    baseline = %{
      workload_id: workload_id,
      processes: baseline_data[:processes] || [],
      network_connections: baseline_data[:network_connections] || [],
      file_access_patterns: baseline_data[:file_access_patterns] || [],
      resource_usage: baseline_data[:resource_usage] || %{},
      api_patterns: baseline_data[:api_patterns] || [],
      learning_complete: false,
      samples: 0,
      created_at: DateTime.utc_now(),
      updated_at: DateTime.utc_now()
    }

    :ets.insert(@baselines_table, {workload_id, baseline})
    {:reply, {:ok, baseline}, state}
  end

  @impl true
  def handle_call({:get_baseline, workload_id}, _from, state) do
    result =
      case :ets.lookup(@baselines_table, workload_id) do
        [{^workload_id, baseline}] -> {:ok, baseline}
        [] -> {:error, :not_found}
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:add_admission_policy, policy}, _from, state) do
    policy_id = policy[:id] || Ecto.UUID.generate()

    full_policy = %{
      id: policy_id,
      name: policy[:name],
      description: policy[:description],
      enabled: policy[:enabled] != false,
      scope: policy[:scope] || :cluster,
      namespace_selector: policy[:namespace_selector],
      rules: policy[:rules] || [],
      action: policy[:action] || :deny,
      created_at: DateTime.utc_now()
    }

    :ets.insert(@admission_policies_table, {policy_id, full_policy})
    {:reply, {:ok, full_policy}, state}
  end

  @impl true
  def handle_call(:list_admission_policies, _from, state) do
    policies =
      :ets.tab2list(@admission_policies_table)
      |> Enum.map(fn {_id, policy} -> policy end)

    {:reply, policies, state}
  end

  @impl true
  def handle_call(:get_statistics, _from, state) do
    workloads = :ets.info(@workload_state_table, :size)
    baselines = :ets.info(@baselines_table, :size)
    policies = :ets.info(@admission_policies_table, :size)

    stats = %{
      monitored_workloads: workloads,
      workloads_with_baselines: baselines,
      admission_policies: policies,
      events_processed: state.events_processed,
      threats_detected: state.threats_detected
    }

    {:reply, stats, state}
  end

  @impl true
  def handle_info(:baseline_learning, state) do
    # Process baseline learning for workloads
    learn_baselines()
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup_stale, state) do
    # Remove stale workload entries
    cleanup_stale_workloads()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions - Runtime Analysis

  defp analyze_runtime_event(agent_id, event, state) do
    event_type = event["type"] || event[:type]
    workload_id = event["workload_id"] || event[:workload_id] || event["container_id"]

    # Update workload state
    update_workload_state(workload_id, agent_id, event)

    # Run threat detection
    threats =
      []
      |> check_cryptominer(event)
      |> check_reverse_shell(event)
      |> check_privilege_escalation(event)
      |> check_container_escape(event)
      |> check_behavioral_anomaly(workload_id, event)

    # Generate alerts for detected threats
    Enum.each(threats, fn threat ->
      generate_threat_alert(agent_id, workload_id, threat, event)
    end)

    # Update statistics
    %{
      state
      | events_processed: state.events_processed + 1,
        threats_detected: state.threats_detected + length(threats)
    }
  end

  defp update_workload_state(nil, _agent_id, _event), do: :ok

  defp update_workload_state(workload_id, agent_id, event) do
    now = DateTime.utc_now()

    workload =
      case :ets.lookup(@workload_state_table, workload_id) do
        [{^workload_id, existing}] ->
          %{
            existing
            | last_event: now,
              event_count: existing.event_count + 1,
              last_event_type: event["type"]
          }

        [] ->
          %{
            id: workload_id,
            agent_id: agent_id,
            type: event["workload_type"] || "container",
            name: event["workload_name"] || event["container_name"],
            image: event["image"],
            namespace: event["namespace"],
            cluster: event["cluster"],
            status: :monitored,
            first_seen: now,
            last_event: now,
            event_count: 1,
            last_event_type: event["type"],
            threat_score: 0,
            anomalies_detected: 0
          }
      end

    :ets.insert(@workload_state_table, {workload_id, workload})
  end

  defp check_cryptominer(threats, event) do
    process_name = event["process_name"] || event["cmdline"] || ""
    process_lower = String.downcase(process_name)

    is_miner =
      Enum.any?(@cryptominer_processes, fn miner ->
        String.contains?(process_lower, miner)
      end)

    if is_miner do
      [
        %{
          type: :cryptominer,
          severity: "critical",
          title: "Cryptominer Process Detected",
          description: "Potential cryptomining process detected: #{process_name}",
          mitre_technique: "T1496",
          confidence: 0.95
        }
        | threats
      ]
    else
      threats
    end
  end

  defp check_reverse_shell(threats, event) do
    cmdline = event["cmdline"] || ""

    is_reverse_shell =
      Enum.any?(@reverse_shell_patterns, fn pattern ->
        Regex.match?(pattern, cmdline)
      end)

    if is_reverse_shell do
      [
        %{
          type: :reverse_shell,
          severity: "critical",
          title: "Reverse Shell Detected",
          description: "Potential reverse shell detected in command: #{String.slice(cmdline, 0, 200)}",
          mitre_technique: "T1059",
          confidence: 0.9
        }
        | threats
      ]
    else
      threats
    end
  end

  defp check_privilege_escalation(threats, event) do
    cmdline = event["cmdline"] || ""
    process_name = event["process_name"] || ""
    user = event["user"]
    effective_user = event["effective_user"]

    # Check for privilege escalation commands
    has_priv_esc_cmd =
      Enum.any?(@privilege_escalation_commands, fn cmd ->
        String.contains?(cmdline, cmd) or String.contains?(process_name, cmd)
      end)

    # Check for UID change to root
    uid_escalation =
      user != nil and effective_user != nil and user != "root" and effective_user == "root"

    cond do
      uid_escalation ->
        [
          %{
            type: :privilege_escalation,
            severity: "critical",
            title: "Privilege Escalation Detected",
            description: "User #{user} escalated privileges to root",
            mitre_technique: "T1548",
            confidence: 0.95
          }
          | threats
        ]

      has_priv_esc_cmd ->
        [
          %{
            type: :privilege_escalation_attempt,
            severity: "high",
            title: "Privilege Escalation Attempt",
            description: "Potential privilege escalation command: #{String.slice(cmdline, 0, 200)}",
            mitre_technique: "T1548",
            confidence: 0.7
          }
          | threats
        ]

      true ->
        threats
    end
  end

  defp check_container_escape(threats, event) do
    cmdline = event["cmdline"] || ""
    file_path = event["file_path"] || ""
    combined = cmdline <> " " <> file_path

    is_escape_indicator =
      Enum.any?(@container_escape_indicators, fn indicator ->
        String.contains?(combined, indicator)
      end)

    if is_escape_indicator do
      [
        %{
          type: :container_escape,
          severity: "critical",
          title: "Container Escape Attempt Detected",
          description: "Potential container escape attempt detected accessing sensitive resources",
          mitre_technique: "T1611",
          confidence: 0.85
        }
        | threats
      ]
    else
      threats
    end
  end

  defp check_behavioral_anomaly(threats, workload_id, _event) when is_nil(workload_id), do: threats

  defp check_behavioral_anomaly(threats, workload_id, event) do
    case :ets.lookup(@baselines_table, workload_id) do
      [{^workload_id, baseline}] when baseline.learning_complete ->
        anomalies = []

        # Check process anomaly
        anomalies =
          if event["process_name"] do
            process = event["process_name"]

            if process not in baseline.processes do
              [
                %{
                  type: :behavioral_anomaly,
                  severity: "medium",
                  title: "Unusual Process Execution",
                  description: "Process '#{process}' not in baseline for this workload",
                  mitre_technique: "T1059",
                  confidence: 0.6
                }
                | anomalies
              ]
            else
              anomalies
            end
          else
            anomalies
          end

        # Check network anomaly
        anomalies =
          if event["dest_ip"] && event["dest_port"] do
            connection = "#{event["dest_ip"]}:#{event["dest_port"]}"

            if connection not in baseline.network_connections do
              [
                %{
                  type: :network_anomaly,
                  severity: "medium",
                  title: "Unusual Network Connection",
                  description: "Connection to #{connection} not in baseline",
                  mitre_technique: "T1071",
                  confidence: 0.5
                }
                | anomalies
              ]
            else
              anomalies
            end
          else
            anomalies
          end

        threats ++ anomalies

      _ ->
        threats
    end
  end

  defp generate_threat_alert(agent_id, workload_id, threat, event) do
    evidence = %{
      file_hashes: [],
      network:
        if event["dest_ip"] do
          [%{ip: event["dest_ip"], port: event["dest_port"]}]
        else
          []
        end,
      process: %{
        name: event["process_name"],
        cmdline: event["cmdline"],
        pid: event["pid"]
      },
      registry: [],
      detection: %{
        rule_name: threat.title,
        rule_type: "cloud_runtime",
        confidence: threat.confidence,
        matched_pattern: threat.description
      }
    }

    Alerts.create_alert(%{
      agent_id: agent_id,
      organization_id: OrgLookup.get_org_id(agent_id),
      title: "Cloud Runtime: #{threat.title}",
      description: """
      #{threat.description}

      Workload: #{workload_id}
      Image: #{event["image"]}
      Namespace: #{event["namespace"]}
      """,
      severity: threat.severity,
      source_event_id: event["event_id"],
      event_ids: if(event["event_id"], do: [event["event_id"]], else: []),
      evidence: evidence,
      mitre_techniques: [threat.mitre_technique],
      category: "cloud_runtime",
      source: "cloud_runtime_protection",
      metadata: %{
        workload_id: workload_id,
        threat_type: Atom.to_string(threat.type),
        confidence: threat.confidence,
        mitre_technique: threat.mitre_technique
      }
    })
  end

  # Private Functions - Container Drift Detection

  defp check_container_drift(container_id, current_snapshot) do
    case :ets.lookup(@drift_table, container_id) do
      [{^container_id, original_snapshot}] ->
        # Compare snapshots
        changes = compare_filesystems(original_snapshot, current_snapshot)

        if Enum.empty?(changes) do
          {:ok, :no_drift}
        else
          drift_result = %{
            container_id: container_id,
            changes: changes,
            drift_score: calculate_drift_score(changes),
            detected_at: DateTime.utc_now()
          }

          {:drift_detected, drift_result}
        end

      [] ->
        # Store as baseline
        :ets.insert(@drift_table, {container_id, current_snapshot})
        {:ok, :baseline_created}
    end
  end

  defp compare_filesystems(original, current) do
    original_files = MapSet.new(Map.keys(original.files || %{}))
    current_files = MapSet.new(Map.keys(current.files || %{}))

    added = MapSet.difference(current_files, original_files) |> MapSet.to_list()
    removed = MapSet.difference(original_files, current_files) |> MapSet.to_list()

    modified =
      MapSet.intersection(original_files, current_files)
      |> Enum.filter(fn file ->
        original.files[file] != current.files[file]
      end)

    %{
      added: added,
      removed: removed,
      modified: modified,
      total_changes: length(added) + length(removed) + length(modified)
    }
  end

  defp calculate_drift_score(changes) do
    # Critical paths that significantly increase drift score
    critical_paths = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/etc/passwd", "/etc/shadow"]

    base_score = changes.total_changes * 5

    critical_changes =
      (changes.added ++ changes.modified)
      |> Enum.count(fn file ->
        Enum.any?(critical_paths, fn path -> String.starts_with?(file, path) end)
      end)

    min(100, base_score + critical_changes * 20)
  end

  # Private Functions - Kubernetes Admission Control

  defp evaluate_admission_request(request) do
    policies =
      :ets.tab2list(@admission_policies_table)
      |> Enum.map(fn {_id, policy} -> policy end)
      |> Enum.filter(fn p -> p.enabled end)

    # Check if request matches any policy that would deny it
    violations =
      Enum.flat_map(policies, fn policy ->
        if policy_applies?(policy, request) do
          check_policy_rules(policy, request)
        else
          []
        end
      end)

    if Enum.empty?(violations) do
      :allow
    else
      reasons = Enum.map(violations, fn v -> v.reason end) |> Enum.join("; ")
      {:deny, reasons}
    end
  end

  defp policy_applies?(policy, request) do
    # Check namespace selector
    namespace_match =
      case policy.namespace_selector do
        nil -> true
        selector -> matches_namespace_selector?(request.namespace, selector)
      end

    # Check scope
    scope_match =
      case policy.scope do
        :cluster -> true
        :namespace -> request.namespace != nil
        _ -> true
      end

    namespace_match and scope_match
  end

  defp matches_namespace_selector?(_namespace, nil), do: true

  defp matches_namespace_selector?(namespace, selector) do
    case selector do
      %{include: includes} -> namespace in includes
      %{exclude: excludes} -> namespace not in excludes
      %{regex: pattern} -> Regex.match?(~r/#{pattern}/, namespace)
      _ -> true
    end
  end

  defp check_policy_rules(policy, request) do
    Enum.flat_map(policy.rules, fn rule ->
      check_admission_rule(rule, request)
    end)
  end

  defp check_admission_rule(%{type: :no_privileged}, request) do
    if get_in(request, [:spec, :containers]) do
      privileged =
        Enum.any?(request.spec.containers, fn c ->
          get_in(c, [:securityContext, :privileged]) == true
        end)

      if privileged do
        [%{rule: :no_privileged, reason: "Privileged containers are not allowed"}]
      else
        []
      end
    else
      []
    end
  end

  defp check_admission_rule(%{type: :no_host_network}, request) do
    if get_in(request, [:spec, :hostNetwork]) == true do
      [%{rule: :no_host_network, reason: "Host network access is not allowed"}]
    else
      []
    end
  end

  defp check_admission_rule(%{type: :no_host_pid}, request) do
    if get_in(request, [:spec, :hostPID]) == true do
      [%{rule: :no_host_pid, reason: "Host PID namespace is not allowed"}]
    else
      []
    end
  end

  defp check_admission_rule(%{type: :no_root}, request) do
    if get_in(request, [:spec, :containers]) do
      runs_as_root =
        Enum.any?(request.spec.containers, fn c ->
          get_in(c, [:securityContext, :runAsUser]) == 0 or
            get_in(c, [:securityContext, :runAsNonRoot]) == false
        end)

      if runs_as_root do
        [%{rule: :no_root, reason: "Running as root is not allowed"}]
      else
        []
      end
    else
      []
    end
  end

  defp check_admission_rule(%{type: :allowed_registries, registries: allowed}, request) do
    if get_in(request, [:spec, :containers]) do
      invalid_images =
        Enum.filter(request.spec.containers, fn c ->
          image = c[:image] || ""
          not Enum.any?(allowed, fn reg -> String.starts_with?(image, reg) end)
        end)

      if Enum.empty?(invalid_images) do
        []
      else
        [
          %{
            rule: :allowed_registries,
            reason: "Images must be from allowed registries: #{Enum.join(allowed, ", ")}"
          }
        ]
      end
    else
      []
    end
  end

  defp check_admission_rule(%{type: :require_resource_limits}, request) do
    if get_in(request, [:spec, :containers]) do
      missing_limits =
        Enum.filter(request.spec.containers, fn c ->
          is_nil(get_in(c, [:resources, :limits]))
        end)

      if Enum.empty?(missing_limits) do
        []
      else
        [%{rule: :require_resource_limits, reason: "All containers must have resource limits"}]
      end
    else
      []
    end
  end

  defp check_admission_rule(%{type: :no_latest_tag}, request) do
    if get_in(request, [:spec, :containers]) do
      uses_latest =
        Enum.any?(request.spec.containers, fn c ->
          image = c[:image] || ""
          String.ends_with?(image, ":latest") or not String.contains?(image, ":")
        end)

      if uses_latest do
        [%{rule: :no_latest_tag, reason: "Latest tag is not allowed, use specific version tags"}]
      else
        []
      end
    else
      []
    end
  end

  defp check_admission_rule(%{type: :require_read_only_root}, request) do
    if get_in(request, [:spec, :containers]) do
      writable_root =
        Enum.any?(request.spec.containers, fn c ->
          get_in(c, [:securityContext, :readOnlyRootFilesystem]) != true
        end)

      if writable_root do
        [%{rule: :require_read_only_root, reason: "Read-only root filesystem is required"}]
      else
        []
      end
    else
      []
    end
  end

  defp check_admission_rule(_, _), do: []

  # Private Functions - Baseline Learning

  defp learn_baselines do
    workloads = :ets.tab2list(@workload_state_table)

    Enum.each(workloads, fn {workload_id, workload} ->
      case :ets.lookup(@baselines_table, workload_id) do
        [{^workload_id, baseline}] when not baseline.learning_complete ->
          # Continue learning if we have enough samples
          if baseline.samples >= 100 do
            updated = %{baseline | learning_complete: true, updated_at: DateTime.utc_now()}
            :ets.insert(@baselines_table, {workload_id, updated})
            Logger.info("Baseline learning complete for workload: #{workload_id}")
          end

        [] ->
          # Create new baseline for new workloads
          if workload.event_count >= 10 do
            baseline = %{
              workload_id: workload_id,
              processes: [],
              network_connections: [],
              file_access_patterns: [],
              resource_usage: %{},
              api_patterns: [],
              learning_complete: false,
              samples: 0,
              created_at: DateTime.utc_now(),
              updated_at: DateTime.utc_now()
            }

            :ets.insert(@baselines_table, {workload_id, baseline})
          end

        _ ->
          :ok
      end
    end)
  end

  defp cleanup_stale_workloads do
    cutoff = DateTime.add(DateTime.utc_now(), -3600, :second)

    stale =
      :ets.foldl(
        fn {id, workload}, acc ->
          if DateTime.compare(workload.last_event, cutoff) == :lt do
            [id | acc]
          else
            acc
          end
        end,
        [],
        @workload_state_table
      )

    Enum.each(stale, fn id ->
      :ets.delete(@workload_state_table, id)
    end)
  end

  # Private Functions - Default Policies

  defp initialize_default_admission_policies do
    # No privileged containers
    :ets.insert(@admission_policies_table, {
      "policy-no-privileged",
      %{
        id: "policy-no-privileged",
        name: "No Privileged Containers",
        description: "Blocks deployment of privileged containers",
        enabled: true,
        scope: :cluster,
        namespace_selector: %{exclude: ["kube-system"]},
        rules: [%{type: :no_privileged}],
        action: :deny,
        created_at: DateTime.utc_now()
      }
    })

    # No host namespace access
    :ets.insert(@admission_policies_table, {
      "policy-no-host-access",
      %{
        id: "policy-no-host-access",
        name: "No Host Namespace Access",
        description: "Blocks pods with host network or PID access",
        enabled: true,
        scope: :cluster,
        namespace_selector: %{exclude: ["kube-system"]},
        rules: [%{type: :no_host_network}, %{type: :no_host_pid}],
        action: :deny,
        created_at: DateTime.utc_now()
      }
    })

    # Require resource limits
    :ets.insert(@admission_policies_table, {
      "policy-resource-limits",
      %{
        id: "policy-resource-limits",
        name: "Require Resource Limits",
        description: "Requires all containers to specify resource limits",
        enabled: true,
        scope: :cluster,
        namespace_selector: nil,
        rules: [%{type: :require_resource_limits}],
        action: :deny,
        created_at: DateTime.utc_now()
      }
    })

    # No latest tag
    :ets.insert(@admission_policies_table, {
      "policy-no-latest",
      %{
        id: "policy-no-latest",
        name: "No Latest Tag",
        description: "Blocks images using the latest tag",
        enabled: true,
        scope: :cluster,
        namespace_selector: %{exclude: ["kube-system", "default"]},
        rules: [%{type: :no_latest_tag}],
        action: :deny,
        created_at: DateTime.utc_now()
      }
    })
  end

  # Private Functions - Helpers

  defp apply_workload_filters(workloads, filters) do
    workloads
    |> filter_by(:agent_id, filters[:agent_id])
    |> filter_by(:type, filters[:type])
    |> filter_by(:namespace, filters[:namespace])
    |> filter_by(:status, filters[:status])
  end

  defp filter_by(list, _field, nil), do: list

  defp filter_by(list, field, value) do
    Enum.filter(list, fn w -> Map.get(w, field) == value end)
  end
end
