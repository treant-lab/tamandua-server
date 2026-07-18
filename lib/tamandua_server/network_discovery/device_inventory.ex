defmodule TamanduaServer.NetworkDiscovery.DeviceInventory do
  @moduledoc """
  Global Network Device Inventory - SentinelOne Ranger-style

  GenServer maintaining a global inventory of all discovered network devices
  across all agents. Provides:

  - Device sighting merging from multiple agents
  - Device state machine: new -> identified -> classified -> managed/unmanaged
  - Category classification: Secured, Unsecured, Unsupported, Unknown
  - Device state transition tracking over time
  - Alert generation on new device appearance
  - Alert on device type changes (potential spoofing)
  - Integration with existing AssetManager
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo

  # ============================================================================
  # Device Schema
  # ============================================================================

  defmodule NetworkDevice do
    use Ecto.Schema
    import Ecto.Changeset

    @primary_key {:id, :binary_id, autogenerate: true}
    @foreign_key_type :binary_id
    schema "network_devices" do
      field :mac_address, :string
      field :ip_addresses, {:array, :string}, default: []
      field :hostnames, {:array, :string}, default: []

      # OS fingerprinting
      field :os_family, :string
      field :os_version, :string
      field :os_confidence, :float, default: 0.0
      field :os_evidence, {:array, :string}, default: []

      # Classification
      field :device_type, :string, default: "unknown"
      field :device_category, :string, default: "unknown"  # secured|unsecured|unsupported|unknown
      field :device_state, :string, default: "new"  # new|identified|classified|managed|unmanaged

      # Network info
      field :open_ports, {:array, :map}, default: []
      field :services, {:array, :map}, default: []
      field :vendor, :string
      field :subnet, :string

      # Discovery metadata
      field :first_seen, :utc_datetime_usec
      field :last_seen, :utc_datetime_usec
      field :discovery_method, :string
      field :discovered_by_agents, {:array, :string}, default: []

      # Management status
      field :managed, :boolean, default: false
      field :agent_id, :binary_id  # linked Tamandua agent if managed
      field :whitelisted, :boolean, default: false
      field :whitelist_reason, :string

      # Fingerprint data
      field :ttl, :integer
      field :tcp_window_size, :integer

      # Risk assessment
      field :risk_score, :integer, default: 0
      field :risk_factors, {:array, :string}, default: []

      # State transition history
      field :state_history, {:array, :map}, default: []

      # Organization (multi-tenancy)
      field :organization_id, :binary_id

      timestamps()
    end

    @valid_device_types [
      "server", "workstation", "printer", "camera", "iot",
      "network_device", "mobile", "storage_device", "voip", "unknown"
    ]

    @valid_categories ["secured", "unsecured", "unsupported", "unknown"]

    @valid_states ["new", "identified", "classified", "managed", "unmanaged"]

    def changeset(device, attrs) do
      device
      |> cast(attrs, [
        :mac_address, :ip_addresses, :hostnames, :os_family, :os_version,
        :os_confidence, :os_evidence, :device_type, :device_category,
        :device_state, :open_ports, :services, :vendor, :subnet,
        :first_seen, :last_seen, :discovery_method, :discovered_by_agents,
        :managed, :agent_id, :whitelisted, :whitelist_reason,
        :ttl, :tcp_window_size, :risk_score, :risk_factors,
        :state_history, :organization_id
      ])
      |> validate_inclusion(:device_type, @valid_device_types)
      |> validate_inclusion(:device_category, @valid_categories)
      |> validate_inclusion(:device_state, @valid_states)
    end
  end

  # ============================================================================
  # GenServer State
  # ============================================================================

  defstruct [
    :devices,           # %{device_key => NetworkDevice}
    :agent_subnets,     # %{agent_id => [subnets]}
    :managed_agents,    # MapSet of agent_ids with Tamandua
    :stats
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Ingest discovered devices from an agent telemetry event.
  Merges device sightings and updates the global inventory.
  """
  def ingest_discovery(agent_id, discovery_event) do
    GenServer.cast(__MODULE__, {:ingest_discovery, agent_id, discovery_event})
  end

  @doc """
  Report an agent's local subnets for scan coordination.
  """
  def report_subnets(agent_id, subnets) do
    GenServer.cast(__MODULE__, {:report_subnets, agent_id, subnets})
  end

  @doc """
  List all discovered devices with optional filters.
  """
  def list_devices(filters \\ %{}) do
    GenServer.call(__MODULE__, {:list_devices, filters})
  end

  @doc """
  Get a specific device by ID.
  """
  def get_device(device_id) do
    GenServer.call(__MODULE__, {:get_device, device_id})
  end

  @doc """
  Whitelist a device (mark as authorized).
  """
  def whitelist_device(device_id, reason \\ "Manual whitelist") do
    GenServer.call(__MODULE__, {:whitelist_device, device_id, reason})
  end

  @doc """
  Remove a device from the whitelist.
  """
  def remove_whitelist(device_id) do
    GenServer.call(__MODULE__, {:remove_whitelist, device_id})
  end

  @doc """
  Get device inventory summary statistics.
  """
  def get_summary do
    GenServer.call(__MODULE__, :get_summary)
  end

  @doc """
  Get scan coordination info: which agents are on which subnets.
  """
  def get_subnet_agents do
    GenServer.call(__MODULE__, :get_subnet_agents)
  end

  @doc """
  Assign scan ranges to an agent to avoid duplicate scanning.
  Returns list of CIDR ranges the agent should scan.
  """
  def get_assigned_ranges(agent_id) do
    GenServer.call(__MODULE__, {:get_assigned_ranges, agent_id})
  end

  @doc """
  Mark a device as managed (has Tamandua agent installed).
  """
  def mark_managed(device_id, agent_id) do
    GenServer.call(__MODULE__, {:mark_managed, device_id, agent_id})
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("[DeviceInventory] Starting Network Device Inventory")

    state = %__MODULE__{
      devices: load_devices(),
      agent_subnets: %{},
      managed_agents: MapSet.new(),
      stats: %{
        total_devices: 0,
        new_devices_24h: 0,
        managed_count: 0,
        unmanaged_count: 0,
        last_ingest: nil
      }
    }

    # Schedule periodic tasks
    schedule_stats_update()
    schedule_stale_device_cleanup()

    {:ok, update_stats(state)}
  end

  @impl true
  def handle_cast({:ingest_discovery, agent_id, discovery_event}, state) do
    devices = Map.get(discovery_event, "devices", [])
    subnet = Map.get(discovery_event, "subnet", "unknown")
    now = DateTime.utc_now()

    new_state = Enum.reduce(devices, state, fn device_data, acc ->
      process_discovered_device(acc, agent_id, device_data, subnet, now)
    end)

    new_state = %{new_state | stats: Map.put(new_state.stats, :last_ingest, now)}

    {:noreply, update_stats(new_state)}
  end

  @impl true
  def handle_cast({:report_subnets, agent_id, subnets}, state) do
    new_subnets = Map.put(state.agent_subnets, agent_id, subnets)
    {:noreply, %{state | agent_subnets: new_subnets}}
  end

  @impl true
  def handle_call({:list_devices, filters}, _from, state) do
    devices = state.devices
      |> Map.values()
      |> filter_devices(filters)
      |> Enum.sort_by(& &1.last_seen, {:desc, DateTime})

    {:reply, {:ok, devices}, state}
  end

  @impl true
  def handle_call({:get_device, device_id}, _from, state) do
    result = Enum.find(Map.values(state.devices), fn d -> d.id == device_id end)
    case result do
      nil -> {:reply, {:error, :not_found}, state}
      device -> {:reply, {:ok, device}, state}
    end
  end

  @impl true
  def handle_call({:whitelist_device, device_id, reason}, _from, state) do
    case find_device_by_id(state.devices, device_id) do
      {key, device} ->
        updated = %{device |
          whitelisted: true,
          whitelist_reason: reason,
          state_history: [
            %{state: "whitelisted", timestamp: DateTime.utc_now(), reason: reason}
            | device.state_history
          ]
        }
        save_device(updated)
        new_devices = Map.put(state.devices, key, updated)
        {:reply, {:ok, updated}, %{state | devices: new_devices}}

      nil ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:remove_whitelist, device_id}, _from, state) do
    case find_device_by_id(state.devices, device_id) do
      {key, device} ->
        updated = %{device | whitelisted: false, whitelist_reason: nil}
        save_device(updated)
        new_devices = Map.put(state.devices, key, updated)
        {:reply, {:ok, updated}, %{state | devices: new_devices}}

      nil ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call(:get_summary, _from, state) do
    {:reply, {:ok, state.stats}, state}
  end

  @impl true
  def handle_call(:get_subnet_agents, _from, state) do
    {:reply, {:ok, state.agent_subnets}, state}
  end

  @impl true
  def handle_call({:get_assigned_ranges, agent_id}, _from, state) do
    ranges = compute_assigned_ranges(agent_id, state.agent_subnets)
    {:reply, {:ok, ranges}, state}
  end

  @impl true
  def handle_call({:mark_managed, device_id, agent_id}, _from, state) do
    case find_device_by_id(state.devices, device_id) do
      {key, device} ->
        updated = transition_state(device, "managed", agent_id)
        save_device(updated)
        new_devices = Map.put(state.devices, key, updated)
        new_managed = MapSet.put(state.managed_agents, agent_id)
        {:reply, {:ok, updated}, %{state | devices: new_devices, managed_agents: new_managed}}

      nil ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_info(:update_stats, state) do
    schedule_stats_update()
    {:noreply, update_stats(state)}
  end

  @impl true
  def handle_info(:cleanup_stale_devices, state) do
    # Mark devices not seen in 7 days as stale
    cutoff = DateTime.add(DateTime.utc_now(), -7 * 24 * 3600, :second)

    new_devices = state.devices
      |> Enum.map(fn {key, device} ->
        if DateTime.compare(device.last_seen, cutoff) == :lt do
          updated = %{device | device_state: "stale"}
          save_device(updated)
          {key, updated}
        else
          {key, device}
        end
      end)
      |> Map.new()

    schedule_stale_device_cleanup()
    {:noreply, %{state | devices: new_devices}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp process_discovered_device(state, agent_id, device_data, subnet, now) do
    # Generate device key from MAC or primary IP
    device_key = device_key(device_data)

    case Map.get(state.devices, device_key) do
      nil ->
        # New device - create entry
        device = create_device(device_data, agent_id, subnet, now)
        Logger.info("[DeviceInventory] New device discovered: #{device_key} (#{device.device_type}) by agent #{agent_id}")

        # Alert on new device
        emit_new_device_alert(device, agent_id)

        save_device(device)
        %{state | devices: Map.put(state.devices, device_key, device)}

      existing ->
        # Known device - merge sighting
        updated = merge_device_sighting(existing, device_data, agent_id, now)

        # Check for device type change (potential spoofing)
        if existing.device_type != "unknown" and
           updated.device_type != existing.device_type do
          Logger.warning(
            "[DeviceInventory] Device type change detected for #{device_key}: " <>
            "#{existing.device_type} -> #{updated.device_type} (potential spoofing)"
          )
          emit_device_type_change_alert(existing, updated, agent_id)
        end

        save_device(updated)
        %{state | devices: Map.put(state.devices, device_key, updated)}
    end
  end

  defp device_key(device_data) do
    mac = Map.get(device_data, "mac_address")
    if mac && mac != "" do
      String.upcase(mac)
    else
      ips = Map.get(device_data, "ip_addresses", [])
      List.first(ips) || "unknown"
    end
  end

  defp create_device(data, agent_id, subnet, now) do
    os_guess = Map.get(data, "os_guess")

    %NetworkDevice{
      id: Ecto.UUID.generate(),
      mac_address: Map.get(data, "mac_address"),
      ip_addresses: Map.get(data, "ip_addresses", []),
      hostnames: Map.get(data, "hostnames", []),
      os_family: deep_get(os_guess, ["os_family"]),
      os_version: deep_get(os_guess, ["os_version"]),
      os_confidence: (deep_get(os_guess, ["confidence"]) || 0.0) / 1.0,
      os_evidence: deep_get(os_guess, ["evidence"]) || [],
      device_type: Map.get(data, "device_type", "unknown"),
      device_category: classify_category(data),
      device_state: "new",
      open_ports: Map.get(data, "open_ports", []),
      services: Map.get(data, "services", []),
      vendor: Map.get(data, "vendor"),
      subnet: subnet,
      first_seen: now,
      last_seen: now,
      discovery_method: Map.get(data, "discovery_method", "unknown"),
      discovered_by_agents: [agent_id],
      managed: Map.get(data, "managed", false),
      ttl: Map.get(data, "ttl"),
      tcp_window_size: Map.get(data, "tcp_window_size"),
      risk_score: calculate_device_risk(data),
      risk_factors: identify_risk_factors(data),
      state_history: [%{state: "new", timestamp: now, agent: agent_id}]
    }
  end

  defp merge_device_sighting(existing, new_data, agent_id, now) do
    # Merge IP addresses
    new_ips = Map.get(new_data, "ip_addresses", [])
    merged_ips = Enum.uniq(existing.ip_addresses ++ new_ips)

    # Merge hostnames
    new_hostnames = Map.get(new_data, "hostnames", [])
    merged_hostnames = Enum.uniq(existing.hostnames ++ new_hostnames)

    # Merge open ports
    new_ports = Map.get(new_data, "open_ports", [])
    merged_ports = merge_ports(existing.open_ports, new_ports)

    # Merge services
    new_services = Map.get(new_data, "services", [])
    merged_services = merge_services(existing.services, new_services)

    # Merge discovered_by_agents
    merged_agents = Enum.uniq([agent_id | existing.discovered_by_agents])

    # Update OS guess if new one has higher confidence
    os_guess = Map.get(new_data, "os_guess")
    {os_family, os_version, os_confidence, os_evidence} =
      if os_guess && (deep_get(os_guess, ["confidence"]) || 0.0) > existing.os_confidence do
        {
          deep_get(os_guess, ["os_family"]) || existing.os_family,
          deep_get(os_guess, ["os_version"]) || existing.os_version,
          (deep_get(os_guess, ["confidence"]) || 0.0) / 1.0,
          deep_get(os_guess, ["evidence"]) || existing.os_evidence
        }
      else
        {existing.os_family, existing.os_version, existing.os_confidence, existing.os_evidence}
      end

    # Update device type if was unknown and new data has classification
    new_type = Map.get(new_data, "device_type", "unknown")
    device_type = if existing.device_type == "unknown" && new_type != "unknown" do
      new_type
    else
      existing.device_type
    end

    # Auto-advance state machine
    device_state = advance_state(existing.device_state, device_type, merged_services)

    %{existing |
      ip_addresses: merged_ips,
      hostnames: merged_hostnames,
      os_family: os_family,
      os_version: os_version,
      os_confidence: os_confidence,
      os_evidence: os_evidence,
      device_type: device_type,
      device_state: device_state,
      open_ports: merged_ports,
      services: merged_services,
      vendor: Map.get(new_data, "vendor") || existing.vendor,
      last_seen: now,
      discovered_by_agents: merged_agents,
      risk_score: calculate_device_risk(new_data),
      risk_factors: identify_risk_factors(new_data)
    }
  end

  defp merge_ports(existing, new_ports) do
    existing_set = MapSet.new(existing, fn p -> Map.get(p, "port") || Map.get(p, :port) end)

    new_unique = Enum.reject(new_ports, fn p ->
      port = Map.get(p, "port") || Map.get(p, :port)
      MapSet.member?(existing_set, port)
    end)

    existing ++ new_unique
  end

  defp merge_services(existing, new_services) do
    existing_set = MapSet.new(existing, fn s -> Map.get(s, "port") || Map.get(s, :port) end)

    new_unique = Enum.reject(new_services, fn s ->
      port = Map.get(s, "port") || Map.get(s, :port)
      MapSet.member?(existing_set, port)
    end)

    existing ++ new_unique
  end

  # State machine: new -> identified -> classified -> managed/unmanaged
  defp advance_state("new", device_type, _services) when device_type != "unknown", do: "identified"
  defp advance_state("new", _type, services) when length(services) > 0, do: "identified"
  defp advance_state("identified", device_type, _services) when device_type != "unknown", do: "classified"
  defp advance_state(current, _type, _services), do: current

  defp transition_state(device, new_state, agent_id) do
    history_entry = %{
      from: device.device_state,
      to: new_state,
      timestamp: DateTime.utc_now(),
      agent: agent_id
    }

    managed = new_state == "managed"

    %{device |
      device_state: new_state,
      managed: managed,
      agent_id: if(managed, do: agent_id, else: device.agent_id),
      device_category: if(managed, do: "secured", else: device.device_category),
      state_history: [history_entry | device.state_history]
    }
  end

  # Device category classification
  defp classify_category(data) do
    managed = Map.get(data, "managed", false)
    device_type = Map.get(data, "device_type", "unknown")

    cond do
      managed -> "secured"
      device_type in ["printer", "camera", "iot", "network_device", "voip", "storage_device"] -> "unsupported"
      device_type in ["server", "workstation", "mobile"] -> "unsecured"
      true -> "unknown"
    end
  end

  # Risk scoring for discovered devices
  defp calculate_device_risk(data) do
    base = 0
    device_type = Map.get(data, "device_type", "unknown")
    managed = Map.get(data, "managed", false)
    open_ports = Map.get(data, "open_ports", [])
    services = Map.get(data, "services", [])

    # Unmanaged devices are inherently riskier
    risk = if managed, do: base, else: base + 20

    # High-risk device types
    risk = risk + case device_type do
      "iot" -> 30
      "camera" -> 25
      "printer" -> 15
      "unknown" -> 20
      _ -> 0
    end

    # Risky open ports
    risky_ports = [23, 69, 161, 445, 3389, 5900]
    risky_port_count = Enum.count(open_ports, fn p ->
      port = Map.get(p, "port") || Map.get(p, :port)
      port in risky_ports
    end)
    risk = risk + risky_port_count * 10

    # Telnet is especially risky
    has_telnet = Enum.any?(open_ports, fn p ->
      port = Map.get(p, "port") || Map.get(p, :port)
      port == 23
    end)
    risk = if has_telnet, do: risk + 15, else: risk

    min(risk, 100)
  end

  defp identify_risk_factors(data) do
    factors = []
    open_ports = Map.get(data, "open_ports", [])
    managed = Map.get(data, "managed", false)

    factors = if !managed, do: ["unmanaged_device" | factors], else: factors

    port_numbers = Enum.map(open_ports, fn p ->
      Map.get(p, "port") || Map.get(p, :port)
    end)

    factors = if 23 in port_numbers, do: ["telnet_open" | factors], else: factors
    factors = if 69 in port_numbers, do: ["tftp_open" | factors], else: factors
    factors = if 161 in port_numbers, do: ["snmp_open" | factors], else: factors
    factors = if 5900 in port_numbers, do: ["vnc_open" | factors], else: factors
    factors = if 3389 in port_numbers, do: ["rdp_open" | factors], else: factors
    factors = if 445 in port_numbers, do: ["smb_open" | factors], else: factors

    device_type = Map.get(data, "device_type", "unknown")
    factors = if device_type == "iot", do: ["iot_device" | factors], else: factors
    factors = if device_type == "camera", do: ["ip_camera" | factors], else: factors

    factors
  end

  # Alert generation
  defp emit_new_device_alert(device, agent_id) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alerts:network_discovery",
      {:new_device_discovered, %{
        device_id: device.id,
        mac_address: device.mac_address,
        ip_addresses: device.ip_addresses,
        device_type: device.device_type,
        vendor: device.vendor,
        subnet: device.subnet,
        discovered_by: agent_id,
        risk_score: device.risk_score,
        timestamp: DateTime.utc_now()
      }}
    )
  end

  defp emit_device_type_change_alert(old_device, new_device, agent_id) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alerts:network_discovery",
      {:device_type_changed, %{
        device_id: old_device.id,
        mac_address: old_device.mac_address,
        ip_addresses: old_device.ip_addresses,
        old_type: old_device.device_type,
        new_type: new_device.device_type,
        detected_by: agent_id,
        potential_spoofing: true,
        timestamp: DateTime.utc_now()
      }}
    )
  end

  # Compute assigned scan ranges for an agent, avoiding overlap with other agents
  defp compute_assigned_ranges(agent_id, agent_subnets) do
    agent_nets = Map.get(agent_subnets, agent_id, [])

    Enum.flat_map(agent_nets, fn subnet ->
      # Find all agents on this subnet
      agents_on_subnet = agent_subnets
        |> Enum.filter(fn {_aid, nets} -> subnet in nets end)
        |> Enum.map(fn {aid, _} -> aid end)
        |> Enum.sort()

      # Assign this agent a slice based on its position in sorted agent list
      agent_index = Enum.find_index(agents_on_subnet, &(&1 == agent_id)) || 0
      total_agents = length(agents_on_subnet)

      if total_agents > 0 do
        # Simple round-robin: each agent gets every Nth IP
        # Return the subnet with agent index metadata
        [%{subnet: subnet, agent_index: agent_index, total_agents: total_agents}]
      else
        [%{subnet: subnet, agent_index: 0, total_agents: 1}]
      end
    end)
  end

  defp filter_devices(devices, filters) do
    Enum.filter(devices, fn device ->
      Enum.all?(filters, fn
        {:device_type, type} -> device.device_type == type
        {:device_category, cat} -> device.device_category == cat
        {:device_state, state} -> device.device_state == state
        {:managed, managed} -> device.managed == managed
        {:subnet, subnet} -> device.subnet == subnet
        {:vendor, vendor} -> device.vendor && String.contains?(String.downcase(device.vendor), String.downcase(vendor))
        {:min_risk, score} -> device.risk_score >= score
        {:whitelisted, wl} -> device.whitelisted == wl
        {:search, query} ->
          q = String.downcase(query)
          String.contains?(String.downcase(device.mac_address || ""), q) or
          Enum.any?(device.ip_addresses, &String.contains?(String.downcase(&1), q)) or
          Enum.any?(device.hostnames, &String.contains?(String.downcase(&1), q)) or
          String.contains?(String.downcase(device.vendor || ""), q)
        _ -> true
      end)
    end)
  end

  defp find_device_by_id(devices, device_id) do
    Enum.find(devices, fn {_key, device} -> device.id == device_id end)
  end

  defp update_stats(state) do
    devices = Map.values(state.devices)
    now = DateTime.utc_now()
    day_ago = DateTime.add(now, -24 * 3600, :second)

    stats = %{
      total_devices: length(devices),
      new_devices_24h: Enum.count(devices, fn d ->
        d.first_seen && DateTime.compare(d.first_seen, day_ago) == :gt
      end),
      managed_count: Enum.count(devices, & &1.managed),
      unmanaged_count: Enum.count(devices, &(!&1.managed)),
      by_type: Enum.frequencies_by(devices, & &1.device_type),
      by_category: Enum.frequencies_by(devices, & &1.device_category),
      by_state: Enum.frequencies_by(devices, & &1.device_state),
      high_risk_count: Enum.count(devices, &(&1.risk_score >= 50)),
      whitelisted_count: Enum.count(devices, & &1.whitelisted),
      unique_subnets: devices |> Enum.map(& &1.subnet) |> Enum.uniq() |> length(),
      last_ingest: state.stats[:last_ingest]
    }

    %{state | stats: stats}
  end

  defp load_devices do
    try do
      Repo.all(NetworkDevice)
      |> Enum.map(fn device ->
        key = if device.mac_address, do: String.upcase(device.mac_address), else: List.first(device.ip_addresses) || device.id
        {key, device}
      end)
      |> Map.new()
    rescue
      _ -> %{}
    end
  end

  defp save_device(device) do
    try do
      %NetworkDevice{}
      |> NetworkDevice.changeset(Map.from_struct(device))
      |> Repo.insert(on_conflict: :replace_all, conflict_target: :id)
    rescue
      e ->
        Logger.error("[DeviceInventory] Failed to save device: #{inspect(e)}")
        {:error, e}
    end
  end

  defp deep_get(nil, _path), do: nil
  defp deep_get(map, []), do: map
  defp deep_get(map, [key | rest]) when is_map(map), do: deep_get(Map.get(map, key), rest)
  defp deep_get(_, _), do: nil

  defp schedule_stats_update do
    Process.send_after(self(), :update_stats, 60_000)
  end

  defp schedule_stale_device_cleanup do
    Process.send_after(self(), :cleanup_stale_devices, 3_600_000)
  end
end
