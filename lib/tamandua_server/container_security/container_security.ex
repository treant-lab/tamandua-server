defmodule TamanduaServer.ContainerSecurity do
  @moduledoc """
  Container Runtime Security GenServer.

  Aggregates and analyzes container telemetry from agents, providing:
  - Container inventory across all agents
  - Security policy enforcement
  - Image vulnerability tracking (via Trivy integration)
  - Kubernetes workload security
  - Container escape detection correlation
  - Runtime threat detection

  ## MITRE ATT&CK Coverage
  - T1610: Deploy Container
  - T1611: Escape to Host
  - T1612: Build Image on Host
  - T1613: Container and Resource Discovery

  ## Vulnerability Scanning

  Uses Trivy for vulnerability scanning. Configure in your config:

      config :tamandua_server, :trivy,
        enabled: true,
        mode: :cli,  # or :server
        server_url: "http://localhost:4954",
        timeout: 120_000
  """

  use GenServer
  require Logger

  alias TamanduaServer.{Alerts}
  alias TamanduaServer.ContainerSecurity.Trivy

  @container_table :container_inventory
  @image_table :container_images
  @policy_table :container_policies
  @k8s_workloads_table :k8s_workloads
  @vuln_cache_table :image_vulnerabilities

  # Container security policies
  defmodule Policy do
    defstruct [
      :id,
      :name,
      :description,
      :scope,                    # :global, :namespace, :agent_group
      :scope_value,              # namespace name, agent group id
      :enabled,
      :rules,
      :actions,                  # :alert, :block, :audit
      :created_at,
      :updated_at
    ]
  end

  defmodule Container do
    defstruct [
      :id,
      :container_id,
      :name,
      :image,
      :image_tag,
      :image_digest,
      :runtime,                  # docker, containerd, cri-o, podman
      :agent_id,
      :hostname,
      :status,                   # running, stopped, paused, created
      :pid,
      :user,
      :command,
      :created_at,
      :started_at,
      # Security context
      :privileged,
      :host_network,
      :host_pid,
      :host_ipc,
      :capabilities,
      :security_opts,
      :read_only_rootfs,
      :run_as_root,
      # Mounts
      :host_mounts,
      :sensitive_mounts,
      # K8s metadata
      :k8s_namespace,
      :k8s_pod,
      :k8s_service_account,
      :k8s_labels,
      # Security assessment
      :security_score,
      :security_violations,
      :last_seen
    ]
  end

  defmodule KubernetesWorkload do
    defstruct [
      :id,
      :cluster_id,
      :namespace,
      :name,
      :kind,                     # Pod, Deployment, DaemonSet, StatefulSet
      :replicas,
      :containers,
      :service_account,
      :security_context,
      :network_policies,
      :pod_security_policy,
      :security_score,
      :violations,
      :last_updated
    ]
  end

  defmodule ImageVulnerability do
    defstruct [
      :image,
      :tag,
      :digest,
      :vulnerabilities,          # list of CVEs
      :critical_count,
      :high_count,
      :medium_count,
      :low_count,
      :scan_time,
      :scanner                   # trivy, clair, etc.
    ]
  end

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Record a container event from an agent.
  """
  def record_container_event(agent_id, container_event) do
    GenServer.cast(__MODULE__, {:container_event, agent_id, container_event})
  end

  @doc """
  Get all containers matching filters.
  """
  def list_containers(filters \\ %{}) do
    GenServer.call(__MODULE__, {:list_containers, filters})
  end

  @doc """
  Get container by ID.
  """
  def get_container(container_id) do
    GenServer.call(__MODULE__, {:get_container, container_id})
  end

  @doc """
  Get containers for a specific agent.
  """
  def containers_for_agent(agent_id) do
    GenServer.call(__MODULE__, {:containers_for_agent, agent_id})
  end

  @doc """
  Get all unique images.
  """
  def list_images(filters \\ %{}) do
    GenServer.call(__MODULE__, {:list_images, filters})
  end

  @doc """
  Get image vulnerability info.
  """
  def get_image_vulnerabilities(image, tag \\ "latest") do
    GenServer.call(__MODULE__, {:get_image_vulns, image, tag})
  end

  @doc """
  Scan image for vulnerabilities.

  Uses Trivy scanner (CLI or server mode based on configuration).
  Results are cached for 1 hour.

  ## Options

  Pass options to override default configuration:
  - `:timeout` - Scan timeout in milliseconds (default from config)
  - `:force` - If true, bypass cache and force a fresh scan

  ## Examples

      iex> ContainerSecurity.scan_image("alpine", "3.18")
      {:ok, %ImageVulnerability{critical_count: 0, ...}}

      iex> ContainerSecurity.scan_image("nginx", "latest", force: true)
      {:ok, %ImageVulnerability{...}}
  """
  def scan_image(image, tag \\ "latest") do
    GenServer.call(__MODULE__, {:scan_image, image, tag}, 180_000)
  end

  @doc """
  Check if the vulnerability scanner is available.

  Returns `true` if Trivy is properly configured and accessible.
  """
  def scanner_available? do
    Trivy.available?()
  end

  @doc """
  Get the scanner version.

  Returns `{:ok, version}` or `{:error, reason}`.
  """
  def scanner_version do
    Trivy.version()
  end

  @doc """
  Get container security policies.
  """
  def list_policies(scope \\ nil) do
    GenServer.call(__MODULE__, {:list_policies, scope})
  end

  @doc """
  Create or update a security policy.
  """
  def upsert_policy(policy_attrs) do
    GenServer.call(__MODULE__, {:upsert_policy, policy_attrs})
  end

  @doc """
  Delete a security policy.
  """
  def delete_policy(policy_id) do
    GenServer.call(__MODULE__, {:delete_policy, policy_id})
  end

  @doc """
  Evaluate container against policies.
  """
  def evaluate_container(container) do
    GenServer.call(__MODULE__, {:evaluate_container, container})
  end

  @doc """
  Get Kubernetes workloads.
  """
  def list_k8s_workloads(filters \\ %{}) do
    GenServer.call(__MODULE__, {:list_k8s_workloads, filters})
  end

  @doc """
  Get container security statistics.
  """
  def get_statistics do
    GenServer.call(__MODULE__, :get_statistics)
  end

  @doc """
  Get high-risk containers.
  """
  def high_risk_containers(limit \\ 20) do
    GenServer.call(__MODULE__, {:high_risk_containers, limit})
  end

  @doc """
  Get container runtime distribution.
  """
  def runtime_distribution do
    GenServer.call(__MODULE__, :runtime_distribution)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@container_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@image_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@policy_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@k8s_workloads_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@vuln_cache_table, [:set, :named_table, :public, read_concurrency: true])

    # Initialize default policies
    initialize_default_policies()

    # Schedule cleanup
    :timer.send_interval(60_000, :cleanup_stale)

    Logger.info("Container Security service started")
    {:ok, %{}}
  end

  @impl true
  def handle_cast({:container_event, agent_id, event}, state) do
    process_container_event(agent_id, event)
    {:noreply, state}
  end

  @impl true
  def handle_call({:list_containers, filters}, _from, state) do
    containers = list_containers_internal(filters)
    {:reply, containers, state}
  end

  @impl true
  def handle_call({:get_container, container_id}, _from, state) do
    result = case :ets.lookup(@container_table, container_id) do
      [{^container_id, container}] -> {:ok, container}
      [] -> {:error, :not_found}
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call({:containers_for_agent, agent_id}, _from, state) do
    containers = :ets.foldl(
      fn {_id, c}, acc ->
        if c.agent_id == agent_id, do: [c | acc], else: acc
      end,
      [],
      @container_table
    )
    {:reply, containers, state}
  end

  @impl true
  def handle_call({:list_images, filters}, _from, state) do
    images = list_images_internal(filters)
    {:reply, images, state}
  end

  @impl true
  def handle_call({:get_image_vulns, image, tag}, _from, state) do
    key = "#{image}:#{tag}"
    result = case :ets.lookup(@vuln_cache_table, key) do
      [{^key, vulns}] -> {:ok, vulns}
      [] -> {:error, :not_found}
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call({:scan_image, image, tag}, _from, state) do
    result = scan_image_internal(image, tag)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:list_policies, scope}, _from, state) do
    policies = list_policies_internal(scope)
    {:reply, policies, state}
  end

  @impl true
  def handle_call({:upsert_policy, attrs}, _from, state) do
    result = upsert_policy_internal(attrs)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:delete_policy, policy_id}, _from, state) do
    :ets.delete(@policy_table, policy_id)
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:evaluate_container, container}, _from, state) do
    result = evaluate_container_internal(container)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:list_k8s_workloads, filters}, _from, state) do
    workloads = list_k8s_workloads_internal(filters)
    {:reply, workloads, state}
  end

  @impl true
  def handle_call(:get_statistics, _from, state) do
    stats = compute_statistics()
    {:reply, stats, state}
  end

  @impl true
  def handle_call({:high_risk_containers, limit}, _from, state) do
    containers = :ets.foldl(
      fn {_id, c}, acc -> [c | acc] end,
      [],
      @container_table
    )
    |> Enum.sort_by(& &1.security_score)
    |> Enum.take(limit)

    {:reply, containers, state}
  end

  @impl true
  def handle_call(:runtime_distribution, _from, state) do
    dist = :ets.foldl(
      fn {_id, c}, acc ->
        runtime = c.runtime || "unknown"
        Map.update(acc, runtime, 1, &(&1 + 1))
      end,
      %{},
      @container_table
    )
    {:reply, dist, state}
  end

  @impl true
  def handle_info(:cleanup_stale, state) do
    # Remove containers not seen in the last 5 minutes
    cutoff = DateTime.add(DateTime.utc_now(), -300, :second)

    stale = :ets.foldl(
      fn {id, c}, acc ->
        if DateTime.compare(c.last_seen, cutoff) == :lt do
          [id | acc]
        else
          acc
        end
      end,
      [],
      @container_table
    )

    Enum.each(stale, &:ets.delete(@container_table, &1))

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp process_container_event(agent_id, event) do
    # Parse event data
    action = event["action"]
    container_data = event

    case action do
      action when action in ["create", "start", "created", nil] ->
        # Create or update container record
        container = build_container(agent_id, container_data)

        # Evaluate against policies
        violations = evaluate_container_internal(container)

        # Update security score
        container = %{container |
          security_violations: violations,
          security_score: calculate_security_score(container, violations)
        }

        # Store container
        :ets.insert(@container_table, {container.id, container})

        # Track image
        track_image(container)

        # Track K8s workload if applicable
        if container.k8s_namespace && container.k8s_pod do
          track_k8s_workload(container)
        end

        # Generate alerts for critical violations
        if violations != [] do
          generate_violation_alerts(agent_id, container, violations)
        end

      action when action in ["stop", "delete", "deleted", "die"] ->
        container_id = container_data["container_id"]
        if container_id do
          :ets.delete(@container_table, container_id)
        end

      "exec" ->
        # Container exec - potential lateral movement
        handle_container_exec(agent_id, container_data)

      "escape_attempt" ->
        # Critical - container escape attempt detected
        handle_escape_attempt(agent_id, container_data)

      _ ->
        Logger.debug("Unknown container action: #{action}")
    end
  end

  defp build_container(agent_id, data) do
    container_id = data["container_id"] || Ecto.UUID.generate()

    %Container{
      id: container_id,
      container_id: container_id,
      name: data["container_name"],
      image: data["image"],
      image_tag: data["image_tag"] || "latest",
      image_digest: data["image_digest"],
      runtime: data["runtime"],
      agent_id: agent_id,
      hostname: data["hostname"],
      status: "running",
      pid: data["pid"],
      user: data["user"],
      command: data["command"],
      created_at: DateTime.utc_now(),
      started_at: DateTime.utc_now(),
      privileged: data["privileged"] || false,
      host_network: data["network_mode"] == "host",
      host_pid: data["pid_mode"] == "host",
      host_ipc: data["ipc_mode"] == "host",
      capabilities: data["capabilities"] || [],
      security_opts: data["security_opts"] || [],
      read_only_rootfs: data["read_only_rootfs"] || false,
      run_as_root: is_root_user(data["user"]),
      host_mounts: data["host_mounts"] || [],
      sensitive_mounts: extract_sensitive_mounts(data["host_mounts"] || []),
      k8s_namespace: data["k8s_namespace"],
      k8s_pod: data["k8s_pod"],
      k8s_service_account: data["k8s_service_account"],
      k8s_labels: data["labels"] || %{},
      security_score: 100,
      security_violations: [],
      last_seen: DateTime.utc_now()
    }
  end

  defp is_root_user(nil), do: true
  defp is_root_user(""), do: true
  defp is_root_user("0"), do: true
  defp is_root_user("root"), do: true
  defp is_root_user(_), do: false

  defp extract_sensitive_mounts(mounts) do
    sensitive_paths = [
      "/", "/etc", "/etc/shadow", "/etc/passwd",
      "/var/run/docker.sock", "/var/run/containerd",
      "/var/lib/kubelet", "/proc", "/sys", "/dev",
      "/root", "/home", "/.ssh"
    ]

    mounts
    |> Enum.filter(fn mount ->
      source = mount["source"] || ""
      Enum.any?(sensitive_paths, &String.starts_with?(source, &1))
    end)
  end

  defp evaluate_container_internal(container) do
    policies = list_policies_internal(nil)

    violations = policies
    |> Enum.filter(& &1.enabled)
    |> Enum.flat_map(fn policy ->
      evaluate_policy(policy, container)
    end)

    violations
  end

  defp evaluate_policy(%Policy{rules: rules}, container) do
    rules
    |> Enum.filter(&rule_matches?(&1, container))
    |> Enum.map(fn rule ->
      %{
        rule_name: rule[:name],
        severity: rule[:severity] || "medium",
        description: rule[:description],
        mitre_technique: rule[:mitre_technique]
      }
    end)
  end

  defp rule_matches?(%{type: :privileged}, container), do: container.privileged
  defp rule_matches?(%{type: :host_network}, container), do: container.host_network
  defp rule_matches?(%{type: :host_pid}, container), do: container.host_pid
  defp rule_matches?(%{type: :host_ipc}, container), do: container.host_ipc
  defp rule_matches?(%{type: :run_as_root}, container), do: container.run_as_root
  defp rule_matches?(%{type: :writable_rootfs}, container), do: not container.read_only_rootfs

  defp rule_matches?(%{type: :dangerous_capability, capabilities: dangerous}, container) do
    Enum.any?(container.capabilities, fn cap ->
      Enum.any?(dangerous, &String.contains?(cap, &1))
    end)
  end

  defp rule_matches?(%{type: :sensitive_mount}, container) do
    container.sensitive_mounts != []
  end

  defp rule_matches?(%{type: :docker_socket_mount}, container) do
    Enum.any?(container.host_mounts, fn mount ->
      source = mount["source"] || ""
      String.contains?(source, "docker.sock") or
      String.contains?(source, "containerd.sock")
    end)
  end

  defp rule_matches?(%{type: :vulnerable_image, images: vulnerable}, container) do
    full_image = "#{container.image}:#{container.image_tag}"
    Enum.any?(vulnerable, &String.contains?(full_image, &1))
  end

  defp rule_matches?(_, _), do: false

  defp calculate_security_score(container, violations) do
    base_score = 100

    # Deductions for security issues
    deductions = [
      {container.privileged, 30},
      {container.host_network, 15},
      {container.host_pid, 15},
      {container.host_ipc, 10},
      {container.run_as_root, 10},
      {not container.read_only_rootfs, 5},
      {container.sensitive_mounts != [], 15}
    ]

    score = Enum.reduce(deductions, base_score, fn {condition, penalty}, acc ->
      if condition, do: acc - penalty, else: acc
    end)

    # Additional deductions for violations
    violation_penalty = Enum.reduce(violations, 0, fn v, acc ->
      case v.severity do
        "critical" -> acc + 20
        "high" -> acc + 10
        "medium" -> acc + 5
        _ -> acc + 2
      end
    end)

    max(0, score - violation_penalty)
  end

  defp track_image(container) do
    key = "#{container.image}:#{container.image_tag}"

    case :ets.lookup(@image_table, key) do
      [{^key, image_info}] ->
        # Update container count
        updated = Map.update(image_info, :container_count, 1, &(&1 + 1))
        :ets.insert(@image_table, {key, updated})

      [] ->
        # New image
        image_info = %{
          image: container.image,
          tag: container.image_tag,
          digest: container.image_digest,
          first_seen: DateTime.utc_now(),
          last_seen: DateTime.utc_now(),
          container_count: 1,
          agents: [container.agent_id]
        }
        :ets.insert(@image_table, {key, image_info})
    end
  end

  defp track_k8s_workload(container) do
    key = "#{container.k8s_namespace}/#{container.k8s_pod}"

    workload = %KubernetesWorkload{
      id: key,
      cluster_id: nil,  # Would be set if we have cluster info
      namespace: container.k8s_namespace,
      name: container.k8s_pod,
      kind: "Pod",
      replicas: 1,
      containers: [container.name],
      service_account: container.k8s_service_account,
      security_context: %{
        privileged: container.privileged,
        run_as_root: container.run_as_root,
        read_only_rootfs: container.read_only_rootfs
      },
      network_policies: [],
      pod_security_policy: nil,
      security_score: container.security_score,
      violations: container.security_violations,
      last_updated: DateTime.utc_now()
    }

    :ets.insert(@k8s_workloads_table, {key, workload})
  end

  defp generate_violation_alerts(agent_id, container, violations) do
    Enum.each(violations, fn violation ->
      if violation.severity in ["critical", "high"] do
        # Build evidence for container violation alerts
        evidence = %{
          file_hashes: [],
          network: [],
          process: %{
            name: container.name,
            path: container.image
          },
          registry: [],
          detection: %{
            rule_name: "Container Violation: #{violation.rule_name}",
            rule_type: "container_policy",
            confidence: 0.9,
            matched_pattern: violation.description
          }
        }

        Alerts.create_alert(%{
          agent_id: agent_id,
          organization_id: TamanduaServer.Agents.OrgLookup.get_org_id(agent_id),
          title: "Container Security Violation: #{violation.rule_name}",
          description: """
          Container: #{container.name} (#{container.container_id})
          Image: #{container.image}:#{container.image_tag}
          Violation: #{violation.description}
          """,
          severity: violation.severity,
          # Container violations are policy-based, not triggered by a single event
          source_event_id: nil,
          event_ids: [],
          evidence: evidence,
          mitre_techniques: List.wrap(violation.mitre_technique),
          category: "container_security",
          source: "container_security",
          metadata: %{
            container_id: container.container_id,
            container_name: container.name,
            image: container.image,
            violation_type: violation.rule_name,
            mitre_technique: violation.mitre_technique
          }
        })
      end
    end)
  end

  defp handle_container_exec(agent_id, data) do
    container_id = data["container_id"]
    command = data["command"]

    Logger.warning("Container exec detected: #{container_id}, command: #{command}")

    # Check for suspicious exec commands
    suspicious_patterns = [
      ~r/\/bin\/(ba)?sh/,
      ~r/nsenter/,
      ~r/chroot/,
      ~r/mount/,
      ~r/curl.*\|.*sh/,
      ~r/wget.*\|.*sh/
    ]

    is_suspicious = Enum.any?(suspicious_patterns, &Regex.match?(&1, command || ""))

    if is_suspicious do
      # Extract event_id if available in the data
      event_id = data["event_id"]

      # Build evidence for container exec alerts
      evidence = %{
        file_hashes: [],
        network: [],
        process: %{
          name: container_id,
          cmdline: command
        },
        registry: [],
        detection: %{
          rule_name: "Container Exec: Suspicious Command",
          rule_type: "container_runtime",
          confidence: 0.85,
          matched_pattern: command
        }
      }

      Alerts.create_alert(%{
        agent_id: agent_id,
        organization_id: TamanduaServer.Agents.OrgLookup.get_org_id(agent_id),
        title: "Suspicious Container Exec Detected",
        description: "Suspicious command executed in container #{container_id}: #{command}",
        severity: "high",
        source_event_id: event_id,
        event_ids: if(event_id, do: [event_id], else: []),
        evidence: evidence,
        mitre_techniques: ["T1059"],
        category: "container_security",
        source: "container_security",
        metadata: %{
          container_id: container_id,
          command: command,
          mitre_technique: "T1059"
        }
      })
    end
  end

  defp handle_escape_attempt(agent_id, data) do
    violation_type = data["violation_type"]
    description = data["description"]
    event_id = data["event_id"]

    Logger.error("Container escape attempt detected: #{violation_type}")

    # Build evidence for container escape alerts
    evidence = %{
      file_hashes: [],
      network: [],
      process: %{
        name: data["container_id"] || data["process_name"],
        cmdline: data["command"]
      },
      registry: [],
      detection: %{
        rule_name: "Container Escape: #{violation_type}",
        rule_type: "container_escape",
        confidence: 0.95,
        matched_pattern: violation_type
      }
    }

    Alerts.create_alert(%{
      agent_id: agent_id,
      organization_id: TamanduaServer.Agents.OrgLookup.get_org_id(agent_id),
      title: "CRITICAL: Container Escape Attempt Detected",
      description: description,
      severity: "critical",
      source_event_id: event_id,
      event_ids: if(event_id, do: [event_id], else: []),
      evidence: evidence,
      mitre_techniques: ["T1611"],
      category: "container_escape",
      source: "container_security",
      metadata: %{
        violation_type: violation_type,
        mitre_technique: "T1611"
      }
    })
  end

  defp list_containers_internal(filters) do
    :ets.foldl(
      fn {_id, c}, acc -> [c | acc] end,
      [],
      @container_table
    )
    |> apply_container_filters(filters)
  end

  defp apply_container_filters(containers, filters) do
    containers
    |> filter_by_agent(filters[:agent_id])
    |> filter_by_runtime(filters[:runtime])
    |> filter_by_image(filters[:image])
    |> filter_by_status(filters[:status])
    |> filter_by_namespace(filters[:namespace])
    |> filter_by_privileged(filters[:privileged])
  end

  defp filter_by_agent(containers, nil), do: containers
  defp filter_by_agent(containers, agent_id) do
    Enum.filter(containers, &(&1.agent_id == agent_id))
  end

  defp filter_by_runtime(containers, nil), do: containers
  defp filter_by_runtime(containers, runtime) do
    Enum.filter(containers, &(&1.runtime == runtime))
  end

  defp filter_by_image(containers, nil), do: containers
  defp filter_by_image(containers, image) do
    Enum.filter(containers, &String.contains?(&1.image || "", image))
  end

  defp filter_by_status(containers, nil), do: containers
  defp filter_by_status(containers, status) do
    Enum.filter(containers, &(&1.status == status))
  end

  defp filter_by_namespace(containers, nil), do: containers
  defp filter_by_namespace(containers, namespace) do
    Enum.filter(containers, &(&1.k8s_namespace == namespace))
  end

  defp filter_by_privileged(containers, nil), do: containers
  defp filter_by_privileged(containers, true), do: Enum.filter(containers, & &1.privileged)
  defp filter_by_privileged(containers, false), do: Enum.filter(containers, &(not &1.privileged))

  defp list_images_internal(filters) do
    :ets.foldl(
      fn {_key, img}, acc -> [img | acc] end,
      [],
      @image_table
    )
    |> filter_images(filters)
  end

  defp filter_images(images, filters) do
    images
    |> filter_image_by_name(filters[:name])
    |> filter_image_by_tag(filters[:tag])
  end

  defp filter_image_by_name(images, nil), do: images
  defp filter_image_by_name(images, name) do
    Enum.filter(images, &String.contains?(&1.image || "", name))
  end

  defp filter_image_by_tag(images, nil), do: images
  defp filter_image_by_tag(images, tag) do
    Enum.filter(images, &(&1.tag == tag))
  end

  defp scan_image_internal(image, tag) do
    # Uses Trivy scanner with result caching (1 hour TTL)
    key = "#{image}:#{tag}"

    # Check if we have cached results
    case :ets.lookup(@vuln_cache_table, key) do
      [{^key, cached}] ->
        # Return cached if less than 1 hour old
        if DateTime.diff(DateTime.utc_now(), cached.scan_time) < 3600 do
          {:ok, cached}
        else
          do_scan_image(image, tag)
        end

      [] ->
        do_scan_image(image, tag)
    end
  end

  defp do_scan_image(image, tag) do
    # Use real Trivy scanner
    case Trivy.scan_image(image, tag) do
      {:ok, trivy_result} ->
        # Convert Trivy result to our ImageVulnerability struct
        vulns = %ImageVulnerability{
          image: image,
          tag: tag,
          digest: trivy_result.digest,
          vulnerabilities: convert_trivy_vulns(trivy_result.vulnerabilities),
          critical_count: trivy_result.critical_count,
          high_count: trivy_result.high_count,
          medium_count: trivy_result.medium_count,
          low_count: trivy_result.low_count,
          scan_time: trivy_result.scan_time,
          scanner: "trivy"
        }

        key = "#{image}:#{tag}"
        :ets.insert(@vuln_cache_table, {key, vulns})

        Logger.info(
          "Trivy scan completed for #{image}:#{tag} - " <>
            "Critical: #{vulns.critical_count}, High: #{vulns.high_count}, " <>
            "Medium: #{vulns.medium_count}, Low: #{vulns.low_count}"
        )

        {:ok, vulns}

      {:error, :trivy_disabled} ->
        Logger.warning("Trivy is disabled, returning empty scan result for #{image}:#{tag}")
        {:error, :scanner_disabled}

      {:error, :trivy_not_found} ->
        Logger.error("Trivy binary not found. Install Trivy or use server mode.")
        {:error, :scanner_not_available}

      {:error, :timeout} ->
        Logger.error("Trivy scan timed out for #{image}:#{tag}")
        {:error, :scan_timeout}

      {:error, {:connection_failed, reason}} ->
        Logger.error("Failed to connect to Trivy server: #{inspect(reason)}")
        {:error, :scanner_not_available}

      {:error, {:trivy_failed, exit_code, output}} ->
        Logger.error("Trivy scan failed for #{image}:#{tag} (exit #{exit_code})")
        Logger.debug("Trivy output: #{String.slice(output, 0, 500)}")
        {:error, {:scan_failed, output}}

      {:error, reason} ->
        Logger.error("Trivy scan failed for #{image}:#{tag}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  # Convert Trivy vulnerability format to our internal format
  defp convert_trivy_vulns(trivy_vulns) do
    Enum.map(trivy_vulns, fn v ->
      %{
        cve: v.cve,
        severity: String.downcase(v.severity),
        package: v.package,
        installed_version: v.installed_version,
        fixed_version: v.fixed_version,
        title: v[:title],
        description: v[:description],
        cvss_score: v[:cvss_score],
        references: v[:references] || []
      }
    end)
  end

  defp list_policies_internal(nil) do
    :ets.foldl(
      fn {_id, policy}, acc -> [policy | acc] end,
      [],
      @policy_table
    )
  end

  defp list_policies_internal(scope) do
    :ets.foldl(
      fn {_id, policy}, acc ->
        if policy.scope == scope, do: [policy | acc], else: acc
      end,
      [],
      @policy_table
    )
  end

  defp upsert_policy_internal(attrs) do
    policy_id = attrs[:id] || Ecto.UUID.generate()

    policy = %Policy{
      id: policy_id,
      name: attrs[:name],
      description: attrs[:description],
      scope: attrs[:scope] || :global,
      scope_value: attrs[:scope_value],
      enabled: attrs[:enabled] != false,
      rules: attrs[:rules] || [],
      actions: attrs[:actions] || [:alert],
      created_at: DateTime.utc_now(),
      updated_at: DateTime.utc_now()
    }

    :ets.insert(@policy_table, {policy_id, policy})
    {:ok, policy}
  end

  defp list_k8s_workloads_internal(filters) do
    :ets.foldl(
      fn {_key, workload}, acc -> [workload | acc] end,
      [],
      @k8s_workloads_table
    )
    |> filter_workloads(filters)
  end

  defp filter_workloads(workloads, filters) do
    workloads
    |> filter_workload_by_namespace(filters[:namespace])
    |> filter_workload_by_kind(filters[:kind])
  end

  defp filter_workload_by_namespace(workloads, nil), do: workloads
  defp filter_workload_by_namespace(workloads, ns) do
    Enum.filter(workloads, &(&1.namespace == ns))
  end

  defp filter_workload_by_kind(workloads, nil), do: workloads
  defp filter_workload_by_kind(workloads, kind) do
    Enum.filter(workloads, &(&1.kind == kind))
  end

  defp compute_statistics do
    containers = :ets.foldl(
      fn {_id, c}, acc -> [c | acc] end,
      [],
      @container_table
    )

    images = :ets.foldl(
      fn {_key, img}, acc -> [img | acc] end,
      [],
      @image_table
    )

    %{
      total_containers: length(containers),
      running_containers: Enum.count(containers, &(&1.status == "running")),
      privileged_containers: Enum.count(containers, & &1.privileged),
      host_network_containers: Enum.count(containers, & &1.host_network),
      root_containers: Enum.count(containers, & &1.run_as_root),
      high_risk_containers: Enum.count(containers, &(&1.security_score < 50)),
      unique_images: length(images),
      k8s_workloads: :ets.info(@k8s_workloads_table, :size),
      policies_active: Enum.count(list_policies_internal(nil), & &1.enabled),
      average_security_score: calculate_average_score(containers),
      runtime_distribution: calculate_runtime_distribution(containers),
      violation_summary: calculate_violation_summary(containers)
    }
  end

  defp calculate_average_score([]), do: 0
  defp calculate_average_score(containers) do
    total = Enum.reduce(containers, 0, &(&1.security_score + &2))
    Float.round(total / length(containers), 1)
  end

  defp calculate_runtime_distribution(containers) do
    Enum.reduce(containers, %{}, fn c, acc ->
      runtime = c.runtime || "unknown"
      Map.update(acc, runtime, 1, &(&1 + 1))
    end)
  end

  defp calculate_violation_summary(containers) do
    containers
    |> Enum.flat_map(& &1.security_violations)
    |> Enum.reduce(%{}, fn v, acc ->
      rule = v[:rule_name] || "unknown"
      Map.update(acc, rule, 1, &(&1 + 1))
    end)
  end

  defp initialize_default_policies do
    # Default security policies

    # No privileged containers
    upsert_policy_internal(%{
      id: "policy-no-privileged",
      name: "No Privileged Containers",
      description: "Blocks containers running in privileged mode",
      scope: :global,
      enabled: true,
      rules: [
        %{type: :privileged, name: "privileged_container", severity: "critical",
          description: "Container running in privileged mode", mitre_technique: "T1611"}
      ],
      actions: [:alert, :block]
    })

    # No host namespace access
    upsert_policy_internal(%{
      id: "policy-no-host-namespace",
      name: "No Host Namespace Access",
      description: "Blocks containers with host network, PID, or IPC namespace access",
      scope: :global,
      enabled: true,
      rules: [
        %{type: :host_network, name: "host_network", severity: "high",
          description: "Container has host network access", mitre_technique: "T1611"},
        %{type: :host_pid, name: "host_pid", severity: "high",
          description: "Container has host PID namespace access", mitre_technique: "T1611"},
        %{type: :host_ipc, name: "host_ipc", severity: "medium",
          description: "Container has host IPC namespace access", mitre_technique: "T1611"}
      ],
      actions: [:alert]
    })

    # No Docker socket mount
    upsert_policy_internal(%{
      id: "policy-no-docker-socket",
      name: "No Container Runtime Socket Mount",
      description: "Prevents mounting container runtime sockets (escape vector)",
      scope: :global,
      enabled: true,
      rules: [
        %{type: :docker_socket_mount, name: "docker_socket_mount", severity: "critical",
          description: "Container has access to container runtime socket", mitre_technique: "T1611"}
      ],
      actions: [:alert, :block]
    })

    # No sensitive host mounts
    upsert_policy_internal(%{
      id: "policy-no-sensitive-mounts",
      name: "No Sensitive Host Mounts",
      description: "Prevents mounting sensitive host paths",
      scope: :global,
      enabled: true,
      rules: [
        %{type: :sensitive_mount, name: "sensitive_mount", severity: "high",
          description: "Container mounts sensitive host path", mitre_technique: "T1611"}
      ],
      actions: [:alert]
    })

    # No dangerous capabilities
    upsert_policy_internal(%{
      id: "policy-no-dangerous-caps",
      name: "No Dangerous Capabilities",
      description: "Blocks containers with dangerous Linux capabilities",
      scope: :global,
      enabled: true,
      rules: [
        %{type: :dangerous_capability, name: "dangerous_capability", severity: "high",
          capabilities: ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO"],
          description: "Container has dangerous Linux capability", mitre_technique: "T1611"}
      ],
      actions: [:alert]
    })

    # Require read-only root filesystem
    upsert_policy_internal(%{
      id: "policy-readonly-rootfs",
      name: "Require Read-Only Root Filesystem",
      description: "Containers should have read-only root filesystem",
      scope: :global,
      enabled: true,
      rules: [
        %{type: :writable_rootfs, name: "writable_rootfs", severity: "low",
          description: "Container has writable root filesystem", mitre_technique: "T1610"}
      ],
      actions: [:audit]
    })

    # Don't run as root
    upsert_policy_internal(%{
      id: "policy-no-root",
      name: "Don't Run as Root",
      description: "Containers should not run as root user",
      scope: :global,
      enabled: true,
      rules: [
        %{type: :run_as_root, name: "run_as_root", severity: "medium",
          description: "Container is running as root user", mitre_technique: "T1610"}
      ],
      actions: [:audit]
    })
  end
end
