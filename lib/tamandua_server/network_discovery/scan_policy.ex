defmodule TamanduaServer.NetworkDiscovery.ScanPolicy do
  @moduledoc """
  Scan Policy Manager

  Manages per-subnet scan policies for network discovery.  Controls:

  - Whether scanning is enabled per subnet
  - Scan type: passive_only or active
  - Scan interval / schedule
  - Excluded IPs and ports
  - Minimum agent count threshold per subnet
  - Scan windows (time-of-day restrictions)
  - Agent scan assignment to avoid duplicate scanning
  - Global scan settings
  """

  use GenServer
  require Logger

  alias TamanduaServer.NetworkDiscovery.DeviceInventory

  # ============================================================================
  # Types
  # ============================================================================

  defmodule Policy do
    @moduledoc "Scan policy for a specific subnet."
    defstruct [
      :id,
      :subnet,
      :name,
      :description,
      scan_enabled: true,
      scan_type: "passive_only",     # "passive_only"|"active"
      scan_interval_secs: 300,       # Seconds between scans
      excluded_ips: [],
      excluded_ports: [],
      min_agent_count: 1,            # Minimum agents on subnet before active scan
      scan_window_start: nil,        # Hour (0-23), nil = no restriction
      scan_window_end: nil,          # Hour (0-23), nil = no restriction
      max_scan_rate_pps: 50,         # Max packets per second
      active_scan_ports: [22, 23, 80, 443, 445, 3389, 8080],
      snmp_communities: ["public"],
      priority: 0,                   # Higher priority policies take precedence
      organization_id: nil,
      created_at: nil,
      updated_at: nil
    ]
  end

  defmodule AgentAssignment do
    @moduledoc "Scan assignment for a specific agent."
    defstruct [
      :agent_id,
      :subnet,
      :assigned_ranges,    # List of IP ranges to scan
      :scan_type,
      :scan_ports,
      :rate_limit,
      :last_assigned,
      :expires_at
    ]
  end

  # ============================================================================
  # GenServer State
  # ============================================================================

  defstruct [
    :policies,             # %{subnet => Policy}
    :global_settings,      # Global scan settings
    :assignments,          # %{{agent_id, subnet} => AgentAssignment}
    :agent_capabilities    # %{agent_id => %{subnets: [], last_report: DateTime}}
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Create or update a scan policy for a subnet.
  """
  def upsert_policy(subnet, attrs) do
    GenServer.call(__MODULE__, {:upsert_policy, subnet, attrs})
  end

  @doc """
  Delete a scan policy.
  """
  def delete_policy(subnet) do
    GenServer.call(__MODULE__, {:delete_policy, subnet})
  end

  @doc """
  Get the effective policy for a subnet.
  """
  def get_policy(subnet) do
    GenServer.call(__MODULE__, {:get_policy, subnet})
  end

  @doc """
  List all scan policies.
  """
  def list_policies do
    GenServer.call(__MODULE__, :list_policies)
  end

  @doc """
  Update global scan settings.
  """
  def update_global_settings(settings) do
    GenServer.call(__MODULE__, {:update_global_settings, settings})
  end

  @doc """
  Get global scan settings.
  """
  def get_global_settings do
    GenServer.call(__MODULE__, :get_global_settings)
  end

  @doc """
  Register an agent's scan capabilities (subnets, etc).
  Called when agent reports its network interfaces.
  """
  def register_agent(agent_id, subnets) do
    GenServer.cast(__MODULE__, {:register_agent, agent_id, subnets})
  end

  @doc """
  Get scan assignments for an agent. Returns the config the agent should use.
  """
  def get_agent_config(agent_id) do
    GenServer.call(__MODULE__, {:get_agent_config, agent_id})
  end

  @doc """
  Check if scanning should be active on a subnet right now.
  """
  def should_scan?(subnet) do
    GenServer.call(__MODULE__, {:should_scan, subnet})
  end

  @doc """
  Get per-subnet agent counts.
  """
  def get_subnet_agent_counts do
    GenServer.call(__MODULE__, :get_subnet_agent_counts)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("[ScanPolicy] Starting Scan Policy Manager")

    state = %__MODULE__{
      policies: %{},
      global_settings: default_global_settings(),
      assignments: %{},
      agent_capabilities: %{}
    }

    # Schedule periodic assignment refresh
    schedule_assignment_refresh()

    {:ok, state}
  end

  @impl true
  def handle_call({:upsert_policy, subnet, attrs}, _from, state) do
    now = DateTime.utc_now()

    policy = case Map.get(state.policies, subnet) do
      nil ->
        struct(Policy, Map.merge(attrs, %{
          id: Ecto.UUID.generate(),
          subnet: subnet,
          created_at: now,
          updated_at: now
        }))

      existing ->
        struct(existing, Map.merge(attrs, %{updated_at: now}))
    end

    new_policies = Map.put(state.policies, subnet, policy)
    Logger.info("[ScanPolicy] Policy upserted for subnet #{subnet}: #{inspect(policy.name)}")

    {:reply, {:ok, policy}, %{state | policies: new_policies}}
  end

  @impl true
  def handle_call({:delete_policy, subnet}, _from, state) do
    new_policies = Map.delete(state.policies, subnet)
    # Also remove assignments for this subnet
    new_assignments = state.assignments
      |> Enum.reject(fn {{_aid, s}, _} -> s == subnet end)
      |> Map.new()

    {:reply, :ok, %{state | policies: new_policies, assignments: new_assignments}}
  end

  @impl true
  def handle_call({:get_policy, subnet}, _from, state) do
    case Map.get(state.policies, subnet) do
      nil -> {:reply, {:ok, default_policy(subnet)}, state}
      policy -> {:reply, {:ok, policy}, state}
    end
  end

  @impl true
  def handle_call(:list_policies, _from, state) do
    policies = Map.values(state.policies) |> Enum.sort_by(& &1.subnet)
    {:reply, {:ok, policies}, state}
  end

  @impl true
  def handle_call({:update_global_settings, settings}, _from, state) do
    new_settings = Map.merge(state.global_settings, settings)
    {:reply, {:ok, new_settings}, %{state | global_settings: new_settings}}
  end

  @impl true
  def handle_call(:get_global_settings, _from, state) do
    {:reply, {:ok, state.global_settings}, state}
  end

  @impl true
  def handle_call({:get_agent_config, agent_id}, _from, state) do
    config = build_agent_config(agent_id, state)
    {:reply, {:ok, config}, state}
  end

  @impl true
  def handle_call({:should_scan, subnet}, _from, state) do
    policy = Map.get(state.policies, subnet, default_policy(subnet))

    can_scan = policy.scan_enabled &&
               in_scan_window?(policy) &&
               meets_agent_threshold?(subnet, policy, state)

    {:reply, can_scan, state}
  end

  @impl true
  def handle_call(:get_subnet_agent_counts, _from, state) do
    counts = state.agent_capabilities
      |> Enum.flat_map(fn {_aid, caps} -> caps.subnets end)
      |> Enum.frequencies()

    {:reply, {:ok, counts}, state}
  end

  @impl true
  def handle_cast({:register_agent, agent_id, subnets}, state) do
    caps = %{
      subnets: subnets,
      last_report: DateTime.utc_now()
    }
    new_caps = Map.put(state.agent_capabilities, agent_id, caps)

    # Report to DeviceInventory for scan coordination
    DeviceInventory.report_subnets(agent_id, subnets)

    {:noreply, %{state | agent_capabilities: new_caps}}
  end

  @impl true
  def handle_info(:refresh_assignments, state) do
    new_state = refresh_all_assignments(state)
    schedule_assignment_refresh()
    {:noreply, new_state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp build_agent_config(agent_id, state) do
    caps = Map.get(state.agent_capabilities, agent_id, %{subnets: []})
    subnets = caps[:subnets] || []

    # Build per-subnet scan config
    subnet_configs = Enum.map(subnets, fn subnet ->
      policy = Map.get(state.policies, subnet, default_policy(subnet))
      assignment = Map.get(state.assignments, {agent_id, subnet})

      %{
        subnet: subnet,
        scan_enabled: policy.scan_enabled && meets_agent_threshold?(subnet, policy, state),
        scan_type: policy.scan_type,
        scan_interval_secs: policy.scan_interval_secs,
        excluded_ips: policy.excluded_ips,
        scan_ports: policy.active_scan_ports,
        max_scan_rate_pps: policy.max_scan_rate_pps,
        snmp_communities: policy.snmp_communities,
        assigned_ranges: if(assignment, do: assignment.assigned_ranges, else: [subnet]),
        scan_window_start: policy.scan_window_start,
        scan_window_end: policy.scan_window_end
      }
    end)

    %{
      agent_id: agent_id,
      global_settings: state.global_settings,
      subnet_configs: subnet_configs
    }
  end

  defp refresh_all_assignments(state) do
    # For each subnet with a policy, compute agent assignments
    new_assignments = state.policies
      |> Enum.flat_map(fn {subnet, policy} ->
        if policy.scan_enabled && policy.scan_type == "active" do
          compute_subnet_assignments(subnet, policy, state)
        else
          []
        end
      end)
      |> Map.new()

    %{state | assignments: new_assignments}
  end

  defp compute_subnet_assignments(subnet, policy, state) do
    now = DateTime.utc_now()
    expires = DateTime.add(now, policy.scan_interval_secs * 2, :second)

    # Find agents on this subnet
    agents = state.agent_capabilities
      |> Enum.filter(fn {_aid, caps} -> subnet in (caps[:subnets] || []) end)
      |> Enum.map(fn {aid, _} -> aid end)
      |> Enum.sort()

    total = length(agents)

    if total == 0 do
      []
    else
      # Parse subnet to get IP range
      ip_ranges = split_subnet_ranges(subnet, total)

      agents
      |> Enum.with_index()
      |> Enum.map(fn {agent_id, idx} ->
        range = Enum.at(ip_ranges, idx, subnet)

        assignment = %AgentAssignment{
          agent_id: agent_id,
          subnet: subnet,
          assigned_ranges: [range],
          scan_type: policy.scan_type,
          scan_ports: policy.active_scan_ports,
          rate_limit: policy.max_scan_rate_pps,
          last_assigned: now,
          expires_at: expires
        }

        {{agent_id, subnet}, assignment}
      end)
    end
  end

  defp split_subnet_ranges(subnet, num_agents) when num_agents <= 1 do
    [subnet]
  end

  defp split_subnet_ranges(subnet, num_agents) do
    # Split the subnet into N roughly equal ranges
    case parse_cidr(subnet) do
      {:ok, _base_ip, prefix_len} ->
        host_bits = 32 - prefix_len
        total_hosts = :math.pow(2, host_bits) |> round()
        hosts_per_agent = max(div(total_hosts, num_agents), 1)

        0..(num_agents - 1)
        |> Enum.map(fn i ->
          _start_offset = i * hosts_per_agent
          # For simplicity, return the original subnet with metadata
          # The agent uses its index to scan every Nth host
          "#{subnet}#agent_slice=#{i}/#{num_agents}"
        end)

      :error ->
        List.duplicate(subnet, num_agents)
    end
  end

  defp parse_cidr(cidr) do
    case String.split(cidr, "/") do
      [ip_str, prefix_str] ->
        case {parse_ipv4(ip_str), Integer.parse(prefix_str)} do
          {{:ok, _ip}, {prefix, ""}} when prefix >= 0 and prefix <= 32 ->
            {:ok, ip_str, prefix}
          _ ->
            :error
        end
      _ ->
        :error
    end
  end

  defp parse_ipv4(ip_str) do
    parts = String.split(ip_str, ".")
    if length(parts) == 4 do
      octets = Enum.map(parts, fn p ->
        case Integer.parse(p) do
          {n, ""} when n >= 0 and n <= 255 -> n
          _ -> nil
        end
      end)
      if Enum.all?(octets, & &1 != nil) do
        {:ok, octets}
      else
        :error
      end
    else
      :error
    end
  end

  defp in_scan_window?(%Policy{scan_window_start: nil}), do: true
  defp in_scan_window?(%Policy{scan_window_end: nil}), do: true
  defp in_scan_window?(policy) do
    now_hour = DateTime.utc_now().hour

    if policy.scan_window_start <= policy.scan_window_end do
      now_hour >= policy.scan_window_start && now_hour < policy.scan_window_end
    else
      # Wraps around midnight
      now_hour >= policy.scan_window_start || now_hour < policy.scan_window_end
    end
  end

  defp meets_agent_threshold?(subnet, policy, state) do
    agent_count = state.agent_capabilities
      |> Enum.count(fn {_aid, caps} -> subnet in (caps[:subnets] || []) end)

    agent_count >= policy.min_agent_count
  end

  defp default_policy(subnet) do
    %Policy{
      id: nil,
      subnet: subnet,
      name: "Default",
      scan_enabled: true,
      scan_type: "passive_only",
      scan_interval_secs: 300,
      min_agent_count: 1
    }
  end

  defp default_global_settings do
    %{
      discovery_enabled: true,
      max_concurrent_scans: 5,
      global_rate_limit_pps: 200,
      default_scan_type: "passive_only",
      alert_on_new_devices: true,
      auto_classify_devices: true,
      stale_device_days: 7,
      max_devices_per_subnet: 10_000
    }
  end

  defp schedule_assignment_refresh do
    # Refresh assignments every 5 minutes
    Process.send_after(self(), :refresh_assignments, 300_000)
  end
end
