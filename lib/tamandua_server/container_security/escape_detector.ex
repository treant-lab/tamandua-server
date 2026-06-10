defmodule TamanduaServer.ContainerSecurity.EscapeDetector do
  @moduledoc """
  Container Escape Detection Correlation Engine.

  A GenServer that performs real-time detection and cross-correlation of
  container escape attempts by analyzing telemetry events from agents.

  ## Detection Patterns

  Detects the following known container escape techniques:

  - **CVE-2019-5736 (runc overwrite)**: /proc/self/exe access from containers,
    runc binary modifications
  - **CVE-2020-15257 (containerd shim)**: Abstract unix socket connections
    from container namespaces
  - **CVE-2021-22555 (Netfilter)**: Privilege escalation via netfilter setsockopt
  - **CVE-2022-0185 (FS context)**: unshare + mount namespace manipulation
  - **CVE-2022-0847 (Dirty Pipe)**: splice() pipe exploitation patterns
  - **Generic patterns**: nsenter from container, mounting host filesystem,
    accessing /proc/1, Docker socket access

  ## Cross-Correlation

  - Correlates container PID namespace events with host PID events
  - Detects when container process gains host capabilities
  - Matches container network namespace breakout to host network activity
  - Tracks privilege escalation chains:
    container unprivileged -> container root -> host root

  ## MITRE ATT&CK

  - T1611: Escape to Host
  - T1610: Deploy Container

  ## Integration

  - Subscribes to telemetry events via PubSub "dashboard:events"
  - Creates alerts via `TamanduaServer.Alerts`
  - Tracks per-container risk scores in ETS
  - Publishes escape events on PubSub "container:escape_events"
  """

  use GenServer
  require Logger

  alias TamanduaServer.Alerts

  # ETS tables
  @risk_scores_table :container_escape_risk_scores
  @escape_events_table :container_escape_events
  @namespace_correlation_table :container_ns_correlation
  @escalation_chains_table :container_escalation_chains

  # Cleanup interval: 2 minutes
  @cleanup_interval_ms 120_000

  # PubSub topics
  @events_topic "dashboard:events"
  @escape_topic "container:escape_events"

  # Risk score decay: decay applied per cleanup cycle
  @risk_decay_per_cycle 5

  # Risk threshold for auto-alerting
  @alert_risk_threshold 70

  # Time window for correlating related events (seconds)
  @correlation_window_secs 120

  # Maximum escalation chain length before alerting
  @max_chain_length 3

  # ---- Known CVE patterns ----

  # CVE-2019-5736: runc container escape via /proc/self/exe overwrite
  @cve_2019_5736_indicators [
    "/proc/self/exe",
    "/proc/self/fd",
    "/usr/bin/runc",
    "/usr/sbin/runc",
    "/usr/local/bin/runc",
    "/run/containerd/",
    "runc init"
  ]

  # CVE-2020-15257: containerd shim API abstract unix socket exploit
  @cve_2020_15257_indicators [
    "containerd-shim",
    "@/containerd-shim/",
    "shim.sock",
    "abstract unix socket"
  ]

  # CVE-2021-22555: Netfilter setsockopt privilege escalation
  @cve_2021_22555_indicators [
    "setsockopt",
    "NFNETLINK",
    "netfilter",
    "nf_tables",
    "ip_tables",
    "ip6_tables",
    "xt_compat"
  ]

  # CVE-2022-0185: FS context heap overflow via unshare
  @cve_2022_0185_indicators [
    "unshare",
    "CLONE_NEWNS",
    "CLONE_NEWUSER",
    "fsconfig",
    "mount_setattr",
    "legacy_parse_param"
  ]

  # CVE-2022-0847: Dirty Pipe - splice() exploitation
  @cve_2022_0847_indicators [
    "splice",
    "pipe_buf_release",
    "PIPE_BUF_FLAG_CAN_MERGE",
    "/etc/passwd",
    "pipe_write"
  ]

  # Generic escape indicators
  @generic_escape_indicators %{
    nsenter: ["nsenter", "--mount", "--target", "--pid", "--net"],
    host_mount: ["/proc/1/root", "/host", "mount -t proc", "mount -t sysfs"],
    proc_access: ["/proc/1/", "/proc/1/cgroup", "/proc/1/environ", "/proc/1/ns/"],
    docker_socket: [
      "/var/run/docker.sock",
      "/run/docker.sock",
      "docker.sock",
      "/var/run/containerd/containerd.sock",
      "/run/containerd/containerd.sock"
    ],
    cgroup_escape: [
      "release_agent",
      "notify_on_release",
      "/sys/fs/cgroup",
      "cgroup.event_control"
    ],
    kernel_module: ["insmod", "modprobe", "init_module", "finit_module"],
    capability_abuse: ["capsh", "setcap", "getcap", "CAP_SYS_ADMIN"]
  }

  # Dangerous capabilities that enable container escape
  @escape_enabling_capabilities [
    "CAP_SYS_ADMIN",
    "CAP_SYS_PTRACE",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_DAC_OVERRIDE",
    "SYS_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "SYS_RAWIO",
    "NET_ADMIN"
  ]

  # -----------------------------------------------------------------------
  # Client API
  # -----------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Analyze a single telemetry event for container escape indicators.
  Returns the analysis result.
  """
  @spec analyze_event(map()) :: :ok | {:escape_detected, map()}
  def analyze_event(event) do
    GenServer.call(__MODULE__, {:analyze_event, event}, 5_000)
  catch
    :exit, _ -> :ok
  end

  @doc """
  Get the current risk score for a container.
  """
  @spec get_risk_score(String.t()) :: non_neg_integer()
  def get_risk_score(container_id) do
    case :ets.lookup(@risk_scores_table, container_id) do
      [{^container_id, %{score: score}}] -> score
      [] -> 0
    end
  rescue
    ArgumentError -> 0
  end

  @doc """
  Get all containers with risk scores above a threshold.
  """
  @spec high_risk_containers(non_neg_integer()) :: [map()]
  def high_risk_containers(threshold \\ 50) do
    :ets.foldl(
      fn {container_id, data}, acc ->
        if data.score >= threshold do
          [Map.put(data, :container_id, container_id) | acc]
        else
          acc
        end
      end,
      [],
      @risk_scores_table
    )
    |> Enum.sort_by(& &1.score, :desc)
  rescue
    ArgumentError -> []
  end

  @doc """
  Get recent escape detection events.
  """
  @spec recent_events(non_neg_integer()) :: [map()]
  def recent_events(limit \\ 50) do
    :ets.foldl(
      fn {_key, event}, acc -> [event | acc] end,
      [],
      @escape_events_table
    )
    |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})
    |> Enum.take(limit)
  rescue
    ArgumentError -> []
  end

  @doc """
  Get active escalation chains.
  """
  @spec active_escalation_chains() :: [map()]
  def active_escalation_chains do
    :ets.foldl(
      fn {_key, chain}, acc -> [chain | acc] end,
      [],
      @escalation_chains_table
    )
    |> Enum.sort_by(& &1.last_updated, {:desc, DateTime})
  rescue
    ArgumentError -> []
  end

  @doc """
  Get detection statistics.
  """
  @spec stats() :: map()
  def stats do
    GenServer.call(__MODULE__, :stats, 5_000)
  catch
    :exit, _ ->
      %{
        total_events_analyzed: 0,
        escape_detections: 0,
        active_risk_scores: 0,
        active_escalation_chains: 0,
        recent_escape_events: 0
      }
  end

  # -----------------------------------------------------------------------
  # GenServer Callbacks
  # -----------------------------------------------------------------------

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@risk_scores_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@escape_events_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@namespace_correlation_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@escalation_chains_table, [:set, :named_table, :public, read_concurrency: true])

    # Subscribe to telemetry events from the ingestor
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, @events_topic)

    # Schedule periodic cleanup
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)

    Logger.info("[EscapeDetector] Container escape detection engine started")

    state = %{
      total_events_analyzed: 0,
      escape_detections: 0,
      last_detection_at: nil
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:analyze_event, event}, _from, state) do
    {result, new_state} = do_analyze_event(event, state)
    {:reply, result, new_state}
  end

  @impl true
  def handle_call(:stats, _from, state) do
    risk_count = try do
      :ets.info(@risk_scores_table, :size) || 0
    rescue
      _ -> 0
    end

    chain_count = try do
      :ets.info(@escalation_chains_table, :size) || 0
    rescue
      _ -> 0
    end

    event_count = try do
      :ets.info(@escape_events_table, :size) || 0
    rescue
      _ -> 0
    end

    stats = %{
      total_events_analyzed: state.total_events_analyzed,
      escape_detections: state.escape_detections,
      active_risk_scores: risk_count,
      active_escalation_chains: chain_count,
      recent_escape_events: event_count,
      last_detection_at: state.last_detection_at
    }

    {:reply, stats, state}
  end

  # Handle batched events from the ingestor PubSub broadcast
  @impl true
  def handle_info({:new_events, events}, state) when is_list(events) do
    new_state = Enum.reduce(events, state, fn event, acc ->
      {_result, updated} = do_analyze_event(event, acc)
      updated
    end)

    {:noreply, new_state}
  end

  # Handle single event messages
  @impl true
  def handle_info({:telemetry_event, event}, state) do
    {_result, new_state} = do_analyze_event(event, state)
    {:noreply, new_state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_stale_data()
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # -----------------------------------------------------------------------
  # Core Analysis Logic
  # -----------------------------------------------------------------------

  defp do_analyze_event(event, state) do
    state = %{state | total_events_analyzed: state.total_events_analyzed + 1}

    event_type = event[:event_type] || event["event_type"]
    payload = event[:payload] || event["payload"] || %{}
    agent_id = event[:agent_id] || event["agent_id"]
    container_id = payload["container_id"] || payload[:container_id]

    # Skip if no useful data
    if is_nil(agent_id) do
      {:ok, state}
    else
      detections = []

      # 1. Check for CVE-specific escape patterns
      detections = detections ++ check_cve_patterns(event_type, payload, agent_id, container_id)

      # 2. Check for generic escape indicators
      detections = detections ++ check_generic_escape(event_type, payload, agent_id, container_id)

      # 3. Cross-correlate PID namespaces (container PID vs host PID)
      detections = detections ++ check_namespace_correlation(event_type, payload, agent_id, container_id)

      # 4. Check for capability escalation
      detections = detections ++ check_capability_escalation(event_type, payload, agent_id, container_id)

      # 5. Track privilege escalation chains
      detections = detections ++ update_escalation_chain(event_type, payload, agent_id, container_id)

      # Process detections
      if detections != [] do
        state = %{state |
          escape_detections: state.escape_detections + length(detections),
          last_detection_at: DateTime.utc_now()
        }

        Enum.each(detections, fn detection ->
          # Update risk score
          update_risk_score(container_id || agent_id, detection)

          # Record escape event
          record_escape_event(detection)

          # Create alert
          create_escape_alert(detection)

          # Broadcast to interested parties
          broadcast_escape_event(detection)
        end)

        {{:escape_detected, List.first(detections)}, state}
      else
        {:ok, state}
      end
    end
  end

  # -----------------------------------------------------------------------
  # CVE-Specific Pattern Detection
  # -----------------------------------------------------------------------

  defp check_cve_patterns(event_type, payload, agent_id, container_id) do
    detections = []

    # Build a searchable string from all payload fields
    search_text = build_search_text(event_type, payload)

    # CVE-2019-5736: runc overwrite
    detections =
      if matches_any?(search_text, @cve_2019_5736_indicators) do
        # Additional check: look for /proc/self/exe write access from a containerized process
        is_container_context = container_id != nil or
          payload_indicates_container?(payload)

        if is_container_context do
          detection = %{
            type: :cve_2019_5736,
            cve: "CVE-2019-5736",
            name: "runc Container Escape (CVE-2019-5736)",
            description: "Detected /proc/self/exe access or runc binary modification from container context. " <>
              "This is a known container escape vector that overwrites the host runc binary.",
            severity: "critical",
            confidence: 0.92,
            agent_id: agent_id,
            container_id: container_id,
            mitre_techniques: ["T1611"],
            mitre_tactics: ["Privilege Escalation"],
            risk_score_delta: 40,
            payload_excerpt: truncate_payload(payload),
            matched_indicators: find_matched(@cve_2019_5736_indicators, search_text),
            timestamp: DateTime.utc_now()
          }
          [detection | detections]
        else
          detections
        end
      else
        detections
      end

    # CVE-2020-15257: containerd shim abstract unix socket
    detections =
      if matches_any?(search_text, @cve_2020_15257_indicators) do
        if event_type in ["network_connect", "network", "unix_socket", :network_connect, :unix_socket] do
          detection = %{
            type: :cve_2020_15257,
            cve: "CVE-2020-15257",
            name: "containerd Shim API Escape (CVE-2020-15257)",
            description: "Detected connection to containerd shim abstract unix socket from container namespace. " <>
              "Exploiting this allows container escape via the containerd shim API.",
            severity: "critical",
            confidence: 0.88,
            agent_id: agent_id,
            container_id: container_id,
            mitre_techniques: ["T1611"],
            mitre_tactics: ["Privilege Escalation"],
            risk_score_delta: 35,
            payload_excerpt: truncate_payload(payload),
            matched_indicators: find_matched(@cve_2020_15257_indicators, search_text),
            timestamp: DateTime.utc_now()
          }
          [detection | detections]
        else
          detections
        end
      else
        detections
      end

    # CVE-2021-22555: Netfilter setsockopt
    detections =
      if matches_any?(search_text, @cve_2021_22555_indicators) do
        if event_type in ["syscall", "process_create", :syscall, :process_create] do
          detection = %{
            type: :cve_2021_22555,
            cve: "CVE-2021-22555",
            name: "Netfilter Privilege Escalation (CVE-2021-22555)",
            description: "Detected setsockopt operations targeting netfilter subsystem from container. " <>
              "This is a kernel privilege escalation that can be used to escape containers.",
            severity: "critical",
            confidence: 0.80,
            agent_id: agent_id,
            container_id: container_id,
            mitre_techniques: ["T1611"],
            mitre_tactics: ["Privilege Escalation"],
            risk_score_delta: 35,
            payload_excerpt: truncate_payload(payload),
            matched_indicators: find_matched(@cve_2021_22555_indicators, search_text),
            timestamp: DateTime.utc_now()
          }
          [detection | detections]
        else
          detections
        end
      else
        detections
      end

    # CVE-2022-0185: FS context unshare
    detections =
      if matches_any?(search_text, @cve_2022_0185_indicators) do
        # Look for unshare combined with mount namespace manipulation
        has_unshare = String.contains?(search_text, "unshare")
        has_ns_manipulation = String.contains?(search_text, "CLONE_NEWNS") or
          String.contains?(search_text, "CLONE_NEWUSER") or
          String.contains?(search_text, "fsconfig")

        if has_unshare or has_ns_manipulation do
          detection = %{
            type: :cve_2022_0185,
            cve: "CVE-2022-0185",
            name: "Filesystem Context Heap Overflow (CVE-2022-0185)",
            description: "Detected unshare and/or mount namespace manipulation from container. " <>
              "CVE-2022-0185 exploits a heap overflow in the filesystem context to escape containers.",
            severity: "critical",
            confidence: 0.85,
            agent_id: agent_id,
            container_id: container_id,
            mitre_techniques: ["T1611"],
            mitre_tactics: ["Privilege Escalation"],
            risk_score_delta: 38,
            payload_excerpt: truncate_payload(payload),
            matched_indicators: find_matched(@cve_2022_0185_indicators, search_text),
            timestamp: DateTime.utc_now()
          }
          [detection | detections]
        else
          detections
        end
      else
        detections
      end

    # CVE-2022-0847: Dirty Pipe
    detections =
      if matches_any?(search_text, @cve_2022_0847_indicators) do
        has_splice = String.contains?(search_text, "splice")
        has_pipe = String.contains?(search_text, "pipe")
        has_sensitive_target = String.contains?(search_text, "/etc/passwd") or
          String.contains?(search_text, "/etc/shadow")

        if (has_splice and has_pipe) or has_sensitive_target do
          detection = %{
            type: :cve_2022_0847,
            cve: "CVE-2022-0847",
            name: "Dirty Pipe Container Escape (CVE-2022-0847)",
            description: "Detected splice/pipe exploitation pattern consistent with Dirty Pipe vulnerability. " <>
              "This allows overwriting read-only files and can be used to escape containers.",
            severity: "critical",
            confidence: 0.87,
            agent_id: agent_id,
            container_id: container_id,
            mitre_techniques: ["T1611"],
            mitre_tactics: ["Privilege Escalation"],
            risk_score_delta: 40,
            payload_excerpt: truncate_payload(payload),
            matched_indicators: find_matched(@cve_2022_0847_indicators, search_text),
            timestamp: DateTime.utc_now()
          }
          [detection | detections]
        else
          detections
        end
      else
        detections
      end

    detections
  end

  # -----------------------------------------------------------------------
  # Generic Escape Pattern Detection
  # -----------------------------------------------------------------------

  defp check_generic_escape(event_type, payload, agent_id, container_id) do
    search_text = build_search_text(event_type, payload)
    detections = []

    # Check each generic indicator category
    Enum.reduce(@generic_escape_indicators, detections, fn {category, indicators}, acc ->
      if matches_any?(search_text, indicators) do
        # Only alert if we have container context evidence
        is_container = container_id != nil or payload_indicates_container?(payload)

        if is_container do
          {name, description, severity, confidence, risk_delta} =
            generic_detection_metadata(category)

          detection = %{
            type: {:generic, category},
            cve: nil,
            name: name,
            description: description,
            severity: severity,
            confidence: confidence,
            agent_id: agent_id,
            container_id: container_id,
            mitre_techniques: mitre_for_category(category),
            mitre_tactics: ["Privilege Escalation"],
            risk_score_delta: risk_delta,
            payload_excerpt: truncate_payload(payload),
            matched_indicators: find_matched(indicators, search_text),
            timestamp: DateTime.utc_now()
          }
          [detection | acc]
        else
          acc
        end
      else
        acc
      end
    end)
  end

  defp generic_detection_metadata(:nsenter) do
    {"nsenter Container Breakout",
     "Detected nsenter command execution from container context. " <>
       "nsenter allows entering host namespaces from a container, effectively escaping isolation.",
     "critical", 0.90, 35}
  end

  defp generic_detection_metadata(:host_mount) do
    {"Host Filesystem Mount from Container",
     "Detected attempt to mount host filesystem or access /proc/1/root from container. " <>
       "This provides direct access to the host filesystem.",
     "critical", 0.88, 30}
  end

  defp generic_detection_metadata(:proc_access) do
    {"Host /proc/1 Access from Container",
     "Detected access to /proc/1 (init process) from container context. " <>
       "Accessing the host init process namespace files enables container escape.",
     "high", 0.82, 25}
  end

  defp generic_detection_metadata(:docker_socket) do
    {"Docker/Containerd Socket Access",
     "Detected container accessing the Docker or containerd runtime socket. " <>
       "Access to the runtime socket allows full control over the container runtime and host.",
     "critical", 0.95, 40}
  end

  defp generic_detection_metadata(:cgroup_escape) do
    {"Cgroup Escape Attempt",
     "Detected manipulation of cgroup release_agent or notify_on_release from container. " <>
       "This is a well-known container escape technique via cgroup v1.",
     "critical", 0.90, 38}
  end

  defp generic_detection_metadata(:kernel_module) do
    {"Kernel Module Loading from Container",
     "Detected attempt to load a kernel module from container context. " <>
       "Loading kernel modules bypasses all container isolation.",
     "critical", 0.92, 40}
  end

  defp generic_detection_metadata(:capability_abuse) do
    {"Linux Capability Abuse in Container",
     "Detected manipulation of Linux capabilities from container context. " <>
       "Capability escalation can be used to break out of container isolation.",
     "high", 0.78, 20}
  end

  defp mitre_for_category(:nsenter), do: ["T1611"]
  defp mitre_for_category(:host_mount), do: ["T1611"]
  defp mitre_for_category(:proc_access), do: ["T1611"]
  defp mitre_for_category(:docker_socket), do: ["T1611", "T1610"]
  defp mitre_for_category(:cgroup_escape), do: ["T1611"]
  defp mitre_for_category(:kernel_module), do: ["T1611"]
  defp mitre_for_category(:capability_abuse), do: ["T1611"]

  # -----------------------------------------------------------------------
  # Namespace Correlation
  # -----------------------------------------------------------------------

  defp check_namespace_correlation(event_type, payload, agent_id, container_id) do
    # Look for PID namespace breakout: a container process appearing in the host PID namespace
    container_pid = payload["container_pid"] || payload[:container_pid]
    host_pid = payload["host_pid"] || payload[:host_pid] || payload["pid"] || payload[:pid]
    pid_namespace = payload["pid_namespace"] || payload[:pid_namespace]
    net_namespace = payload["net_namespace"] || payload[:net_namespace]

    # Track namespace mappings for later correlation
    if container_id && host_pid do
      key = "#{agent_id}:#{container_id}"
      entry = %{
        container_id: container_id,
        agent_id: agent_id,
        container_pid: container_pid,
        host_pid: host_pid,
        pid_namespace: pid_namespace,
        net_namespace: net_namespace,
        event_type: event_type,
        timestamp: DateTime.utc_now()
      }
      :ets.insert(@namespace_correlation_table, {key, entry})
    end

    # Detect container process in host PID namespace
    detections =
      if container_id && pid_namespace == "host" do
        detection = %{
          type: :pid_namespace_breakout,
          cve: nil,
          name: "Container Process in Host PID Namespace",
          description: "A process from container #{container_id} was observed in the host PID namespace. " <>
            "This indicates the container has broken out of its PID namespace isolation.",
          severity: "critical",
          confidence: 0.93,
          agent_id: agent_id,
          container_id: container_id,
          mitre_techniques: ["T1611"],
          mitre_tactics: ["Privilege Escalation"],
          risk_score_delta: 40,
          payload_excerpt: truncate_payload(payload),
          matched_indicators: ["pid_namespace=host"],
          timestamp: DateTime.utc_now()
        }
        [detection]
      else
        []
      end

    # Detect network namespace breakout
    detections =
      if container_id && net_namespace == "host" do
        # Check if this container was NOT started with host networking
        # (if it was, this is expected behavior not an escape)
        container_info = get_container_info(container_id)
        expected_host_net = container_info != nil and container_info.host_network

        if expected_host_net do
          detections
        else
          detection = %{
            type: :net_namespace_breakout,
            cve: nil,
            name: "Container Network Namespace Breakout",
            description: "Container #{container_id} observed in host network namespace " <>
              "despite not being configured for host networking. This suggests a namespace escape.",
            severity: "high",
            confidence: 0.85,
            agent_id: agent_id,
            container_id: container_id,
            mitre_techniques: ["T1611"],
            mitre_tactics: ["Privilege Escalation"],
            risk_score_delta: 30,
            payload_excerpt: truncate_payload(payload),
            matched_indicators: ["net_namespace=host", "unexpected_host_network"],
            timestamp: DateTime.utc_now()
          }
          [detection | detections]
        end
      else
        detections
      end

    # Cross-correlate: look for host events that match a known container process
    if host_pid && !container_id do
      correlations = find_namespace_correlations(agent_id, host_pid)

      Enum.reduce(correlations, detections, fn corr, acc ->
        detection = %{
          type: :cross_namespace_correlation,
          cve: nil,
          name: "Cross-Namespace Process Correlation",
          description: "Host PID #{host_pid} correlates with container #{corr.container_id} " <>
            "process (container PID #{corr.container_pid}). " <>
            "A container process is executing in the host context.",
          severity: "high",
          confidence: 0.80,
          agent_id: agent_id,
          container_id: corr.container_id,
          mitre_techniques: ["T1611"],
          mitre_tactics: ["Privilege Escalation"],
          risk_score_delta: 25,
          payload_excerpt: truncate_payload(payload),
          matched_indicators: [
            "host_pid=#{host_pid}",
            "container_pid=#{corr.container_pid}",
            "container=#{corr.container_id}"
          ],
          timestamp: DateTime.utc_now()
        }
        [detection | acc]
      end)
    else
      detections
    end
  end

  # -----------------------------------------------------------------------
  # Capability Escalation Detection
  # -----------------------------------------------------------------------

  defp check_capability_escalation(_event_type, payload, agent_id, container_id) do
    new_capabilities = payload["capabilities"] || payload[:capabilities] || []
    effective_caps = payload["effective_capabilities"] || payload[:effective_capabilities]
    uid = payload["uid"] || payload[:uid]
    euid = payload["euid"] || payload[:euid]

    detections = []

    # Check if container process gained escape-enabling capabilities
    gained_dangerous = if is_list(new_capabilities) do
      Enum.filter(new_capabilities, fn cap ->
        cap_str = to_string(cap)
        Enum.any?(@escape_enabling_capabilities, &String.contains?(cap_str, &1))
      end)
    else
      []
    end

    detections =
      if gained_dangerous != [] and container_id do
        detection = %{
          type: :capability_gain,
          cve: nil,
          name: "Container Process Gained Host Capabilities",
          description: "Container #{container_id} process gained dangerous capabilities: " <>
            "#{Enum.join(gained_dangerous, ", ")}. " <>
            "These capabilities enable container escape.",
          severity: "critical",
          confidence: 0.90,
          agent_id: agent_id,
          container_id: container_id,
          mitre_techniques: ["T1611"],
          mitre_tactics: ["Privilege Escalation"],
          risk_score_delta: 35,
          payload_excerpt: truncate_payload(payload),
          matched_indicators: Enum.map(gained_dangerous, &"cap:#{&1}"),
          timestamp: DateTime.utc_now()
        }
        [detection | detections]
      else
        detections
      end

    # Check for UID 0 gain in container (root in host namespace)
    detections =
      if container_id && euid == 0 && uid != 0 do
        detection = %{
          type: :uid_escalation,
          cve: nil,
          name: "Container Process Escalated to Root",
          description: "Container #{container_id} process escalated from UID #{uid} to effective UID 0 (root). " <>
            "This may indicate privilege escalation within or out of the container.",
          severity: "high",
          confidence: 0.82,
          agent_id: agent_id,
          container_id: container_id,
          mitre_techniques: ["T1611"],
          mitre_tactics: ["Privilege Escalation"],
          risk_score_delta: 25,
          payload_excerpt: truncate_payload(payload),
          matched_indicators: ["uid_change:#{uid}->0"],
          timestamp: DateTime.utc_now()
        }
        [detection | detections]
      else
        detections
      end

    # Check if all capabilities are present (fully privileged)
    detections =
      if effective_caps == "ffffffffffffffff" or effective_caps == "0000003fffffffff" do
        if container_id do
          detection = %{
            type: :full_capabilities,
            cve: nil,
            name: "Container Running with Full Host Capabilities",
            description: "Container #{container_id} has full capability set (#{effective_caps}), " <>
              "equivalent to an uncontained host process. Container isolation is ineffective.",
            severity: "critical",
            confidence: 0.95,
            agent_id: agent_id,
            container_id: container_id,
            mitre_techniques: ["T1611", "T1610"],
            mitre_tactics: ["Privilege Escalation"],
            risk_score_delta: 40,
            payload_excerpt: truncate_payload(payload),
            matched_indicators: ["full_caps:#{effective_caps}"],
            timestamp: DateTime.utc_now()
          }
          [detection | detections]
        else
          detections
        end
      else
        detections
      end

    detections
  end

  # -----------------------------------------------------------------------
  # Privilege Escalation Chain Tracking
  # -----------------------------------------------------------------------

  defp update_escalation_chain(event_type, payload, agent_id, container_id) do
    # Track escalation progression:
    # Step 1: container unprivileged user
    # Step 2: container root (UID 0 inside container)
    # Step 3: host root (escaped with UID 0 on host)

    uid = payload["uid"] || payload[:uid]
    euid = payload["euid"] || payload[:euid]
    is_host_context = payload["is_host_context"] || payload[:is_host_context]
    pid_namespace = payload["pid_namespace"] || payload[:pid_namespace]

    # Only track chains for container processes
    if is_nil(container_id) do
      []
    else
      chain_key = "#{agent_id}:#{container_id}"

      current_chain = case :ets.lookup(@escalation_chains_table, chain_key) do
        [{^chain_key, chain}] -> chain
        [] -> %{
          container_id: container_id,
          agent_id: agent_id,
          steps: [],
          current_level: :unprivileged,
          last_updated: DateTime.utc_now()
        }
      end

      # Determine the current privilege level from this event
      new_level = determine_privilege_level(uid, euid, is_host_context, pid_namespace)

      # Only add to chain if this is an escalation (not a repeat or de-escalation)
      detections =
        if is_escalation?(current_chain.current_level, new_level) do
          step = %{
            level: new_level,
            event_type: event_type,
            uid: uid,
            euid: euid,
            is_host: is_host_context || pid_namespace == "host",
            timestamp: DateTime.utc_now()
          }

          updated_chain = %{current_chain |
            steps: current_chain.steps ++ [step],
            current_level: new_level,
            last_updated: DateTime.utc_now()
          }

          :ets.insert(@escalation_chains_table, {chain_key, updated_chain})

          # Alert if chain reaches maximum length (full escalation path detected)
          if length(updated_chain.steps) >= @max_chain_length do
            levels = Enum.map(updated_chain.steps, & &1.level) |> Enum.map(&Atom.to_string/1)

            detection = %{
              type: :escalation_chain_complete,
              cve: nil,
              name: "Complete Container Escape Escalation Chain",
              description: "Container #{container_id} completed a full privilege escalation chain: " <>
                Enum.join(levels, " -> ") <> ". " <>
                "This strongly indicates a successful container escape.",
              severity: "critical",
              confidence: 0.95,
              agent_id: agent_id,
              container_id: container_id,
              mitre_techniques: ["T1611"],
              mitre_tactics: ["Privilege Escalation"],
              risk_score_delta: 50,
              payload_excerpt: truncate_payload(payload),
              matched_indicators: Enum.map(updated_chain.steps, fn s ->
                "#{s.level}(uid=#{s.uid},euid=#{s.euid})"
              end),
              timestamp: DateTime.utc_now()
            }
            [detection]
          else
            []
          end
        else
          []
        end

      detections
    end
  end

  defp determine_privilege_level(uid, euid, is_host_context, pid_namespace) do
    is_host = is_host_context == true or pid_namespace == "host"
    effective_uid = euid || uid

    cond do
      is_host and effective_uid == 0 -> :host_root
      is_host -> :host_user
      effective_uid == 0 -> :container_root
      true -> :unprivileged
    end
  end

  defp is_escalation?(current, new) do
    level_order = %{
      unprivileged: 0,
      container_root: 1,
      host_user: 2,
      host_root: 3
    }

    current_order = Map.get(level_order, current, 0)
    new_order = Map.get(level_order, new, 0)
    new_order > current_order
  end

  # -----------------------------------------------------------------------
  # Risk Score Management
  # -----------------------------------------------------------------------

  defp update_risk_score(entity_id, detection) when is_binary(entity_id) do
    delta = detection.risk_score_delta

    current = case :ets.lookup(@risk_scores_table, entity_id) do
      [{^entity_id, data}] -> data
      [] -> %{score: 0, detections: [], last_updated: nil}
    end

    new_score = min(100, current.score + delta)

    detection_entry = %{
      type: detection.type,
      name: detection.name,
      severity: detection.severity,
      confidence: detection.confidence,
      timestamp: detection.timestamp
    }

    updated = %{
      score: new_score,
      detections: Enum.take([detection_entry | current.detections], 50),
      last_updated: DateTime.utc_now()
    }

    :ets.insert(@risk_scores_table, {entity_id, updated})

    # Check if we crossed the alert threshold
    if new_score >= @alert_risk_threshold and current.score < @alert_risk_threshold do
      Logger.warning(
        "[EscapeDetector] Container/agent #{entity_id} risk score crossed threshold: " <>
          "#{current.score} -> #{new_score}"
      )
    end
  end

  defp update_risk_score(nil, _detection), do: :ok

  # -----------------------------------------------------------------------
  # Escape Event Recording
  # -----------------------------------------------------------------------

  defp record_escape_event(detection) do
    event_key = "#{detection.agent_id}:#{:erlang.system_time(:millisecond)}"

    event = %{
      key: event_key,
      type: detection.type,
      cve: detection.cve,
      name: detection.name,
      description: detection.description,
      severity: detection.severity,
      confidence: detection.confidence,
      agent_id: detection.agent_id,
      container_id: detection.container_id,
      mitre_techniques: detection.mitre_techniques,
      matched_indicators: detection.matched_indicators,
      timestamp: detection.timestamp
    }

    :ets.insert(@escape_events_table, {event_key, event})
  end

  # -----------------------------------------------------------------------
  # Alert Creation
  # -----------------------------------------------------------------------

  defp create_escape_alert(detection) do
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      cve_prefix = if detection.cve, do: "[#{detection.cve}] ", else: ""

      evidence = %{
        file_hashes: [],
        network: [],
        process: detection.payload_excerpt || %{},
        registry: [],
        detection: %{
          rule_name: "Container Escape: #{detection.name}",
          rule_type: "container_escape",
          confidence: detection.confidence,
          matched_pattern: Enum.join(detection.matched_indicators || [], ", ")
        }
      }

      alert_attrs = %{
        agent_id: detection.agent_id,
        organization_id: TamanduaServer.Agents.OrgLookup.get_org_id(detection.agent_id),
        title: "#{cve_prefix}Container Escape: #{detection.name}",
        description: detection.description,
        severity: detection.severity,
        source_event_id: nil,
        event_ids: [],
        evidence: evidence,
        mitre_techniques: detection.mitre_techniques,
        mitre_tactics: detection.mitre_tactics,
        category: "container_escape",
        source: "container_escape_detector",
        metadata: %{
          container_id: detection.container_id,
          cve: detection.cve,
          detection_type: to_string_type(detection.type),
          confidence: detection.confidence,
          matched_indicators: detection.matched_indicators,
          risk_score_delta: detection.risk_score_delta
        }
      }

      case Alerts.create_alert(alert_attrs) do
        {:ok, alert} ->
          Logger.warning(
            "[EscapeDetector] Alert created: #{alert.id} - #{detection.name} " <>
              "(container: #{detection.container_id || "unknown"}, agent: #{detection.agent_id})"
          )

        {:error, reason} ->
          Logger.error(
            "[EscapeDetector] Failed to create alert for #{detection.name}: #{inspect(reason)}"
          )
      end
    end)
  end

  # -----------------------------------------------------------------------
  # PubSub Broadcasting
  # -----------------------------------------------------------------------

  defp broadcast_escape_event(detection) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      @escape_topic,
      {:container_escape_detected, %{
        type: detection.type,
        cve: detection.cve,
        name: detection.name,
        severity: detection.severity,
        agent_id: detection.agent_id,
        container_id: detection.container_id,
        confidence: detection.confidence,
        timestamp: detection.timestamp
      }}
    )
  end

  # -----------------------------------------------------------------------
  # Cleanup
  # -----------------------------------------------------------------------

  defp cleanup_stale_data do
    now = DateTime.utc_now()
    cutoff = DateTime.add(now, -600, :second)

    # Decay risk scores
    stale_risk = :ets.foldl(
      fn {id, data}, acc ->
        new_score = max(0, data.score - @risk_decay_per_cycle)
        if new_score == 0 do
          [id | acc]
        else
          :ets.insert(@risk_scores_table, {id, %{data | score: new_score}})
          acc
        end
      end,
      [],
      @risk_scores_table
    )
    Enum.each(stale_risk, &:ets.delete(@risk_scores_table, &1))

    # Remove old escape events (keep last 10 minutes)
    stale_events = :ets.foldl(
      fn {key, event}, acc ->
        if DateTime.compare(event.timestamp, cutoff) == :lt do
          [key | acc]
        else
          acc
        end
      end,
      [],
      @escape_events_table
    )
    Enum.each(stale_events, &:ets.delete(@escape_events_table, &1))

    # Remove old namespace correlations
    stale_ns = :ets.foldl(
      fn {key, entry}, acc ->
        if DateTime.compare(entry.timestamp, cutoff) == :lt do
          [key | acc]
        else
          acc
        end
      end,
      [],
      @namespace_correlation_table
    )
    Enum.each(stale_ns, &:ets.delete(@namespace_correlation_table, &1))

    # Remove stale escalation chains (older than 10 minutes without updates)
    stale_chains = :ets.foldl(
      fn {key, chain}, acc ->
        if DateTime.compare(chain.last_updated, cutoff) == :lt do
          [key | acc]
        else
          acc
        end
      end,
      [],
      @escalation_chains_table
    )
    Enum.each(stale_chains, &:ets.delete(@escalation_chains_table, &1))
  end

  # -----------------------------------------------------------------------
  # Helper Functions
  # -----------------------------------------------------------------------

  # Build a single searchable string from event type and payload fields
  defp build_search_text(event_type, payload) when is_map(payload) do
    fields = [
      to_string(event_type),
      payload["name"] || payload[:name],
      payload["path"] || payload[:path],
      payload["cmdline"] || payload[:cmdline],
      payload["command"] || payload[:command],
      payload["process_name"] || payload[:process_name],
      payload["parent_name"] || payload[:parent_name],
      payload["image"] || payload[:image],
      payload["file_path"] || payload[:file_path],
      payload["target_path"] || payload[:target_path],
      payload["source_path"] || payload[:source_path],
      payload["syscall"] || payload[:syscall],
      payload["destination"] || payload[:destination],
      payload["remote_address"] || payload[:remote_address],
      payload["socket_path"] || payload[:socket_path],
      payload["mount_source"] || payload[:mount_source],
      payload["mount_target"] || payload[:mount_target]
    ]

    fields
    |> Enum.reject(&is_nil/1)
    |> Enum.join(" ")
    |> String.downcase()
  end

  defp build_search_text(event_type, _payload) do
    to_string(event_type)
  end

  # Check if any indicator appears in the search text
  defp matches_any?(search_text, indicators) do
    search_lower = String.downcase(search_text)
    Enum.any?(indicators, fn indicator ->
      String.contains?(search_lower, String.downcase(indicator))
    end)
  end

  # Find which specific indicators matched
  defp find_matched(indicators, search_text) do
    search_lower = String.downcase(search_text)
    Enum.filter(indicators, fn indicator ->
      String.contains?(search_lower, String.downcase(indicator))
    end)
  end

  # Check if the payload suggests this is a container context
  defp payload_indicates_container?(payload) when is_map(payload) do
    container_fields = [
      "container_id", "container_name", "container_runtime",
      "k8s_namespace", "k8s_pod", "docker_id", "cgroup"
    ]

    # Check for explicit container fields
    has_container_field = Enum.any?(container_fields, fn field ->
      val = payload[field] || payload[String.to_atom(field)]
      val != nil and val != ""
    end)

    # Check cgroup for container evidence
    cgroup = payload["cgroup"] || payload[:cgroup] || ""
    has_container_cgroup = String.contains?(to_string(cgroup), "docker") or
      String.contains?(to_string(cgroup), "containerd") or
      String.contains?(to_string(cgroup), "cri-o") or
      String.contains?(to_string(cgroup), "kubepods")

    has_container_field or has_container_cgroup
  end

  defp payload_indicates_container?(_), do: false

  # Look up container info from the ContainerSecurity module
  defp get_container_info(container_id) do
    case TamanduaServer.ContainerSecurity.get_container(container_id) do
      {:ok, container} -> container
      _ -> nil
    end
  rescue
    _ -> nil
  catch
    :exit, _ -> nil
  end

  # Find namespace correlations matching a host PID
  defp find_namespace_correlations(agent_id, host_pid) do
    cutoff = DateTime.add(DateTime.utc_now(), -@correlation_window_secs, :second)

    :ets.foldl(
      fn {_key, entry}, acc ->
        if entry.agent_id == agent_id and
           entry.host_pid == host_pid and
           DateTime.compare(entry.timestamp, cutoff) == :gt do
          [entry | acc]
        else
          acc
        end
      end,
      [],
      @namespace_correlation_table
    )
  rescue
    _ -> []
  end

  # Truncate payload for storage in detections
  defp truncate_payload(payload) when is_map(payload) do
    payload
    |> Map.take([
      "name", "path", "cmdline", "command", "pid", "container_id",
      "container_name", "image", "uid", "euid", "syscall",
      :name, :path, :cmdline, :command, :pid, :container_id,
      :container_name, :image, :uid, :euid, :syscall
    ])
  end

  defp truncate_payload(_), do: %{}

  # Convert detection type to string for JSON serialization
  defp to_string_type({:generic, category}), do: "generic_#{category}"
  defp to_string_type(type) when is_atom(type), do: Atom.to_string(type)
  defp to_string_type(type), do: to_string(type)
end
