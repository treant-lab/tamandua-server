defmodule TamanduaServer.NetworkDiscovery.RogueDetector do
  @moduledoc """
  Rogue Device Detection & Isolation Engine

  Detects unauthorized devices on network segments and optionally triggers
  automatic isolation. Provides:

  - Policy-based: define allowed device types per subnet
  - Rogue device detection against subnet policies
  - Auto-isolation: instruct nearby agents to block traffic to/from rogue devices
  - Alert generation with device details and recommended actions
  - Whitelist management for known devices
  - Rate-limited alerting to prevent alert storms
  """

  use GenServer
  require Logger

  alias TamanduaServer.Agents.CommandManager
  alias TamanduaServer.NetworkDiscovery.DeviceInventory

  # ============================================================================
  # Types
  # ============================================================================

  defmodule SubnetPolicy do
    @moduledoc "Defines what is allowed on a specific subnet."
    defstruct [
      :subnet,
      :name,
      :description,
      allowed_device_types: [],     # e.g., ["workstation", "server", "printer"]
      allowed_vendors: [],           # e.g., ["Dell", "HP", "Cisco"]
      allowed_mac_prefixes: [],      # e.g., ["00:50:56", "00:0C:29"] for VMware
      max_devices: nil,              # Optional: max expected devices on subnet
      auto_isolate: false,           # Whether to automatically isolate rogue devices
      isolation_level: "full",       # "full"|"partial"|"alert_only"
      alert_severity: "high",        # Alert severity for rogue detections
      enabled: true
    ]
  end

  defmodule RogueDetection do
    @moduledoc "A rogue device detection record."
    defstruct [
      :id,
      :device_id,
      :mac_address,
      :ip_addresses,
      :device_type,
      :vendor,
      :subnet,
      :violation_type,     # "unauthorized_type"|"unauthorized_vendor"|"unauthorized_mac"|"new_unknown"
      :violation_details,
      :policy_name,
      :risk_score,
      :action_taken,       # "alert"|"isolated"|"blocked"
      :isolated_by_agents,
      :detected_at,
      :resolved_at,
      :resolved_by,
      :status              # "active"|"resolved"|"whitelisted"
    ]
  end

  # ============================================================================
  # GenServer State
  # ============================================================================

  defstruct [
    :policies,             # %{subnet => SubnetPolicy}
    :detections,           # %{detection_id => RogueDetection}
    :alert_cooldown,       # %{device_key => last_alert_time}
    :isolation_commands,   # [{agent_id, device_ip, action}]
    :stats
  ]

  # Minimum seconds between alerts for the same device
  @alert_cooldown_secs 300

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Set a subnet policy defining what devices are allowed.
  """
  def set_policy(subnet, policy_attrs) do
    GenServer.call(__MODULE__, {:set_policy, subnet, policy_attrs})
  end

  @doc """
  Remove a subnet policy.
  """
  def remove_policy(subnet) do
    GenServer.call(__MODULE__, {:remove_policy, subnet})
  end

  @doc """
  List all subnet policies.
  """
  def list_policies do
    GenServer.call(__MODULE__, :list_policies)
  end

  @doc """
  Evaluate a device against subnet policies.
  Returns :ok if authorized, {:rogue, violations} if not.
  """
  def evaluate_device(device) do
    GenServer.call(__MODULE__, {:evaluate_device, device})
  end

  @doc """
  Run a full sweep: evaluate all known devices against policies.
  """
  def run_sweep do
    GenServer.cast(__MODULE__, :run_sweep)
  end

  @doc """
  List active rogue detections.
  """
  def list_detections(filters \\ %{}) do
    GenServer.call(__MODULE__, {:list_detections, filters})
  end

  @doc """
  Resolve a rogue detection (mark as addressed).
  """
  def resolve_detection(detection_id, resolved_by) do
    GenServer.call(__MODULE__, {:resolve_detection, detection_id, resolved_by})
  end

  @doc """
  Get rogue detection statistics.
  """
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("[RogueDetector] Starting Rogue Device Detection Engine")

    state = %__MODULE__{
      policies: load_default_policies(),
      detections: %{},
      alert_cooldown: %{},
      isolation_commands: [],
      stats: %{
        total_detections: 0,
        active_detections: 0,
        devices_isolated: 0,
        last_sweep: nil
      }
    }

    # Subscribe to new device alerts
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:network_discovery")

    # Schedule periodic sweeps
    schedule_sweep()

    {:ok, state}
  end

  @impl true
  def handle_call({:set_policy, subnet, attrs}, _from, state) do
    policy = struct(SubnetPolicy, Map.put(attrs, :subnet, subnet))
    new_policies = Map.put(state.policies, subnet, policy)
    Logger.info("[RogueDetector] Policy set for subnet #{subnet}: #{inspect(policy.name)}")
    {:reply, {:ok, policy}, %{state | policies: new_policies}}
  end

  @impl true
  def handle_call({:remove_policy, subnet}, _from, state) do
    new_policies = Map.delete(state.policies, subnet)
    {:reply, :ok, %{state | policies: new_policies}}
  end

  @impl true
  def handle_call(:list_policies, _from, state) do
    {:reply, {:ok, Map.values(state.policies)}, state}
  end

  @impl true
  def handle_call({:evaluate_device, device}, _from, state) do
    result = evaluate_device_against_policies(device, state.policies)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:list_detections, filters}, _from, state) do
    detections = state.detections
      |> Map.values()
      |> filter_detections(filters)
      |> Enum.sort_by(& &1.detected_at, {:desc, DateTime})

    {:reply, {:ok, detections}, state}
  end

  @impl true
  def handle_call({:resolve_detection, detection_id, resolved_by}, _from, state) do
    case Map.get(state.detections, detection_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      detection ->
        updated = %{detection |
          status: "resolved",
          resolved_at: DateTime.utc_now(),
          resolved_by: resolved_by
        }
        new_detections = Map.put(state.detections, detection_id, updated)
        new_state = %{state | detections: new_detections}
        {:reply, {:ok, updated}, update_detection_stats(new_state)}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, {:ok, state.stats}, state}
  end

  @impl true
  def handle_cast(:run_sweep, state) do
    Logger.info("[RogueDetector] Running rogue device sweep")

    new_state = case DeviceInventory.list_devices() do
      {:ok, devices} ->
        Enum.reduce(devices, state, fn device, acc ->
          process_device_evaluation(acc, device)
        end)

      {:error, reason} ->
        Logger.error("[RogueDetector] Failed to list devices: #{inspect(reason)}")
        state
    end

    new_state = %{new_state | stats: Map.put(new_state.stats, :last_sweep, DateTime.utc_now())}

    schedule_sweep()
    {:noreply, update_detection_stats(new_state)}
  end

  # Handle new device alerts from DeviceInventory
  @impl true
  def handle_info({:new_device_discovered, device_info}, state) do
    # Convert alert info to a device-like map for evaluation
    pseudo_device = %{
      id: device_info.device_id,
      mac_address: device_info.mac_address,
      ip_addresses: device_info.ip_addresses,
      device_type: device_info.device_type,
      vendor: device_info.vendor,
      subnet: device_info.subnet,
      whitelisted: false,
      managed: false
    }

    new_state = process_device_evaluation(state, pseudo_device)
    {:noreply, update_detection_stats(new_state)}
  end

  @impl true
  def handle_info({:device_type_changed, _change_info}, state) do
    # Device type changes are suspicious - trigger a sweep
    GenServer.cast(self(), :run_sweep)
    {:noreply, state}
  end

  @impl true
  def handle_info(:periodic_sweep, state) do
    GenServer.cast(self(), :run_sweep)
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp process_device_evaluation(state, device) do
    # Skip whitelisted devices
    if Map.get(device, :whitelisted, false) do
      state
    else
      case evaluate_device_against_policies(device, state.policies) do
        {:rogue, violations} ->
          handle_rogue_device(state, device, violations)

        :ok ->
          state
      end
    end
  end

  defp evaluate_device_against_policies(device, policies) do
    subnet = Map.get(device, :subnet) || Map.get(device, "subnet")

    # Find matching policy
    policy = find_matching_policy(subnet, policies)

    case policy do
      nil ->
        # No policy for this subnet - check if device looks suspicious
        if Map.get(device, :device_type) == "unknown" && !Map.get(device, :managed, false) do
          {:rogue, [%{type: "new_unknown", details: "Unknown device on unmonitored subnet"}]}
        else
          :ok
        end

      %SubnetPolicy{enabled: false} ->
        :ok

      policy ->
        violations = check_policy_violations(device, policy)
        if Enum.empty?(violations) do
          :ok
        else
          {:rogue, violations}
        end
    end
  end

  defp find_matching_policy(nil, _policies), do: nil
  defp find_matching_policy(subnet, policies) do
    # Exact match first
    case Map.get(policies, subnet) do
      nil ->
        # Try to find a policy for a parent subnet
        # e.g., device on 192.168.1.0/24, policy for 192.168.0.0/16
        policies
        |> Enum.find(fn {policy_subnet, _policy} ->
          subnet_contains?(policy_subnet, subnet)
        end)
        |> case do
          {_key, policy} -> policy
          nil -> nil
        end

      policy ->
        policy
    end
  end

  defp subnet_contains?(_parent, _child) do
    # Simplified: just check if the first 2 octets match for now
    # A full CIDR containment check would parse both and compare
    false
  end

  defp check_policy_violations(device, policy) do
    violations = []

    device_type = Map.get(device, :device_type) || Map.get(device, "device_type") || "unknown"
    vendor = Map.get(device, :vendor) || Map.get(device, "vendor")
    mac = Map.get(device, :mac_address) || Map.get(device, "mac_address")
    managed = Map.get(device, :managed, false)

    # Check device type
    violations = if policy.allowed_device_types != [] &&
                    device_type not in policy.allowed_device_types &&
                    !managed do
      [%{
        type: "unauthorized_type",
        details: "Device type '#{device_type}' not allowed on subnet #{policy.subnet}. " <>
                 "Allowed types: #{Enum.join(policy.allowed_device_types, ", ")}"
      } | violations]
    else
      violations
    end

    # Check vendor
    violations = if policy.allowed_vendors != [] && vendor do
      vendor_lower = String.downcase(vendor)
      allowed = Enum.any?(policy.allowed_vendors, fn v ->
        String.contains?(vendor_lower, String.downcase(v))
      end)

      if !allowed && !managed do
        [%{
          type: "unauthorized_vendor",
          details: "Vendor '#{vendor}' not in allowed list for subnet #{policy.subnet}"
        } | violations]
      else
        violations
      end
    else
      violations
    end

    # Check MAC prefix
    violations = if policy.allowed_mac_prefixes != [] && mac do
      mac_upper = String.upcase(mac)
      prefix_allowed = Enum.any?(policy.allowed_mac_prefixes, fn prefix ->
        String.starts_with?(mac_upper, String.upcase(prefix))
      end)

      if !prefix_allowed && !managed do
        [%{
          type: "unauthorized_mac",
          details: "MAC prefix of '#{mac}' not in allowed list for subnet #{policy.subnet}"
        } | violations]
      else
        violations
      end
    else
      violations
    end

    violations
  end

  defp handle_rogue_device(state, device, violations) do
    device_key = Map.get(device, :mac_address) || Map.get(device, :id) || "unknown"

    # Check alert cooldown
    now = DateTime.utc_now()
    last_alert = Map.get(state.alert_cooldown, device_key)
    in_cooldown = last_alert && DateTime.diff(now, last_alert) < @alert_cooldown_secs

    if in_cooldown do
      state
    else
      # Create detection record
      detection_id = Ecto.UUID.generate()
      primary_violation = List.first(violations)

      subnet = Map.get(device, :subnet)
      policy = find_matching_policy(subnet, state.policies)

      detection = %RogueDetection{
        id: detection_id,
        device_id: Map.get(device, :id),
        mac_address: Map.get(device, :mac_address),
        ip_addresses: Map.get(device, :ip_addresses, []),
        device_type: Map.get(device, :device_type, "unknown"),
        vendor: Map.get(device, :vendor),
        subnet: subnet,
        violation_type: primary_violation[:type],
        violation_details: Enum.map(violations, & &1[:details]) |> Enum.join("; "),
        policy_name: if(policy, do: policy.name, else: "default"),
        risk_score: calculate_rogue_risk(device, violations),
        action_taken: determine_action(policy),
        isolated_by_agents: [],
        detected_at: now,
        status: "active"
      }

      # Emit alert
      emit_rogue_alert(detection)

      # Execute auto-isolation if policy allows
      new_state = if policy && policy.auto_isolate && policy.isolation_level != "alert_only" do
        execute_isolation(state, detection, policy)
      else
        state
      end

      new_detections = Map.put(new_state.detections, detection_id, detection)
      new_cooldown = Map.put(new_state.alert_cooldown, device_key, now)

      Logger.warning(
        "[RogueDetector] Rogue device detected: #{device_key} " <>
        "(#{detection.violation_type}) on #{subnet || "unknown subnet"}"
      )

      %{new_state |
        detections: new_detections,
        alert_cooldown: new_cooldown
      }
    end
  end

  defp calculate_rogue_risk(device, violations) do
    base = 50

    # More violations = higher risk
    violation_bonus = length(violations) * 10

    # Unknown devices are riskier
    type_bonus = if Map.get(device, :device_type) == "unknown", do: 15, else: 0

    # IoT/camera devices are risky when unauthorized
    iot_bonus = if Map.get(device, :device_type) in ["iot", "camera"], do: 20, else: 0

    min(base + violation_bonus + type_bonus + iot_bonus, 100)
  end

  defp determine_action(nil), do: "alert"
  defp determine_action(%SubnetPolicy{auto_isolate: true, isolation_level: "full"}), do: "isolated"
  defp determine_action(%SubnetPolicy{auto_isolate: true, isolation_level: "partial"}), do: "blocked"
  defp determine_action(_), do: "alert"

  defp execute_isolation(state, detection, policy) do
    # Get agents on the same subnet to execute isolation
    case DeviceInventory.get_subnet_agents() do
      {:ok, agent_subnets} ->
        agents_on_subnet = agent_subnets
          |> Enum.filter(fn {_aid, nets} -> detection.subnet in nets end)
          |> Enum.map(fn {aid, _} -> aid end)

        # Queue block_ip commands through the persisted AgentCommand pipeline
        # (CommandManager.queue_command/4 -> Worker.dispatch_persisted_command/2
        # -> push(socket, "command", ...)). The previous implementation
        # broadcast {:network_isolation, command} on the
        # "agent:<id>:commands" PubSub topic, which has no subscriber
        # anywhere in the server - the command never reached any agent.
        #
        # Payload follows the Rust agent's block_ip contract
        # (apps/tamandua_agent/src/response/mod.rs `block_ip`): keys "ip",
        # "direction", "reason". The agent does NOT implement MAC-level
        # blocking or timed expiry, so the old target_mac/duration_minutes/
        # isolation_level fields are not sent (they were never honored).
        Enum.each(agents_on_subnet, fn agent_id ->
          Enum.each(detection.ip_addresses, fn ip ->
            payload = %{
              ip: ip,
              direction: "both",
              reason:
                "Rogue device: #{detection.violation_type} " <>
                  "(isolation_level=#{policy.isolation_level})"
            }

            case CommandManager.queue_command(agent_id, :block_ip, payload, priority: 8) do
              {:ok, _command} ->
                :ok

              {:error, reason} ->
                Logger.warning(
                  "[RogueDetector] Failed to queue block_ip for agent #{agent_id} " <>
                    "(ip #{ip}): #{inspect(reason)}"
                )
            end
          end)
        end)

        Logger.warning(
          "[RogueDetector] block_ip commands queued for #{length(agents_on_subnet)} agents " <>
          "for rogue device #{detection.mac_address || List.first(detection.ip_addresses)}"
        )

        %{state | isolation_commands: [
          {agents_on_subnet, detection.ip_addresses, detection.id}
          | state.isolation_commands
        ]}

      {:error, _} ->
        state
    end
  end

  defp emit_rogue_alert(detection) do
    alert = %{
      alert_type: "rogue_device",
      severity: "high",
      title: "Rogue device detected on network",
      description: detection.violation_details,
      device_id: detection.device_id,
      mac_address: detection.mac_address,
      ip_addresses: detection.ip_addresses,
      device_type: detection.device_type,
      vendor: detection.vendor,
      subnet: detection.subnet,
      violation_type: detection.violation_type,
      risk_score: detection.risk_score,
      action_taken: detection.action_taken,
      detection_id: detection.id,
      timestamp: detection.detected_at,
      recommended_actions: [
        "Investigate device identity and purpose",
        "Verify with network/IT team if device is authorized",
        "Consider adding to whitelist if legitimate",
        "Block or isolate if unauthorized"
      ]
    }

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alerts:feed",
      {:alert_created, alert}
    )
  end

  defp filter_detections(detections, filters) do
    Enum.filter(detections, fn detection ->
      Enum.all?(filters, fn
        {:status, status} -> detection.status == status
        {:subnet, subnet} -> detection.subnet == subnet
        {:violation_type, type} -> detection.violation_type == type
        {:min_risk, score} -> detection.risk_score >= score
        _ -> true
      end)
    end)
  end

  defp update_detection_stats(state) do
    active = Enum.count(state.detections, fn {_, d} -> d.status == "active" end)
    isolated = Enum.count(state.detections, fn {_, d} -> d.action_taken in ["isolated", "blocked"] end)

    stats = %{
      total_detections: map_size(state.detections),
      active_detections: active,
      devices_isolated: isolated,
      last_sweep: state.stats[:last_sweep]
    }

    %{state | stats: stats}
  end

  defp load_default_policies do
    # Provide sensible default policies for common subnets
    # These can be overridden via the API
    %{
      # Example: corporate workstation subnet
      # "10.0.1.0/24" => %SubnetPolicy{
      #   subnet: "10.0.1.0/24",
      #   name: "Corporate Workstations",
      #   allowed_device_types: ["workstation", "server", "printer"],
      #   auto_isolate: false,
      #   enabled: true
      # }
    }
  end

  defp schedule_sweep do
    # Run sweep every 5 minutes
    Process.send_after(self(), :periodic_sweep, 300_000)
  end
end
