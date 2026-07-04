defmodule TamanduaServer.DeviceControl do
  @moduledoc """
  Context module for USB device control and policy management.

  Manages:
  - Device group policies (IT Admin, Developer, Standard, Kiosk, etc.)
  - Device whitelists and blocklists
  - Write protection settings
  - Encryption enforcement
  - Device event history
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Agents

  # ETS tables for fast lookups
  @policies_table :usb_policies
  @whitelist_table :usb_whitelist
  @blocklist_table :usb_blocklist
  @device_history_table :usb_device_history
  @agent_groups_table :usb_agent_groups

  # Default policies
  @default_policies %{
    "it_admin" => %{
      group: "it_admin",
      allowed_classes: ["mass_storage", "hid", "hub", "audio", "video", "network_adapter", "wireless_controller", "smart_card", "communications", "printer"],
      blocked_classes: [],
      allowed_devices: [],
      blocked_devices: [],
      write_protection: "none",
      require_encryption: false,
      max_storage_size_gb: 0,
      allow_network_adapters: true,
      allow_wireless: true,
      audit_all: true
    },
    "developer" => %{
      group: "developer",
      allowed_classes: ["mass_storage", "hid", "hub", "audio", "video", "communications"],
      blocked_classes: [],
      allowed_devices: [],
      blocked_devices: [],
      write_protection: "audit_only",
      require_encryption: false,
      max_storage_size_gb: 128,
      allow_network_adapters: true,
      allow_wireless: false,
      audit_all: true
    },
    "standard" => %{
      group: "standard",
      allowed_classes: ["hid", "hub", "audio"],
      blocked_classes: [],
      allowed_devices: [],
      blocked_devices: [],
      write_protection: "none",
      require_encryption: false,
      max_storage_size_gb: 0,
      allow_network_adapters: false,
      allow_wireless: false,
      audit_all: true
    },
    "kiosk" => %{
      group: "kiosk",
      allowed_classes: ["hid", "hub"],
      blocked_classes: ["mass_storage", "network_adapter", "wireless_controller"],
      allowed_devices: [],
      blocked_devices: [],
      write_protection: "read_only",
      require_encryption: true,
      max_storage_size_gb: 0,
      allow_network_adapters: false,
      allow_wireless: false,
      audit_all: true
    },
    "executive" => %{
      group: "executive",
      allowed_classes: ["mass_storage", "hid", "hub", "audio"],
      blocked_classes: ["network_adapter", "wireless_controller"],
      allowed_devices: [],
      blocked_devices: [],
      write_protection: "none",
      require_encryption: true,
      max_storage_size_gb: 0,
      allow_network_adapters: false,
      allow_wireless: false,
      audit_all: true
    }
  }

  # ===========================================================================
  # Client API
  # ===========================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  List all device group policies.
  """
  def list_policies do
    GenServer.call(__MODULE__, :list_policies)
  end

  @doc """
  Get policy for a specific device group.
  """
  def get_policy(group) do
    GenServer.call(__MODULE__, {:get_policy, group})
  end

  @doc """
  Create or update a device group policy.
  """
  def upsert_policy(policy_params) do
    GenServer.call(__MODULE__, {:upsert_policy, policy_params})
  end

  @doc """
  Delete a device group policy.
  """
  def delete_policy(group) do
    GenServer.call(__MODULE__, {:delete_policy, group})
  end

  @doc """
  Get the global device whitelist.
  """
  def get_whitelist do
    GenServer.call(__MODULE__, :get_whitelist)
  end

  @doc """
  Add devices to whitelist.
  """
  def add_to_whitelist(devices) do
    GenServer.call(__MODULE__, {:add_to_whitelist, devices})
  end

  @doc """
  Remove devices from whitelist.
  """
  def remove_from_whitelist(devices) do
    GenServer.call(__MODULE__, {:remove_from_whitelist, devices})
  end

  @doc """
  Get the global device blocklist.
  """
  def get_blocklist do
    GenServer.call(__MODULE__, :get_blocklist)
  end

  @doc """
  Add devices to blocklist.
  """
  def add_to_blocklist(devices) do
    GenServer.call(__MODULE__, {:add_to_blocklist, devices})
  end

  @doc """
  Remove devices from blocklist.
  """
  def remove_from_blocklist(devices) do
    GenServer.call(__MODULE__, {:remove_from_blocklist, devices})
  end

  @doc """
  Assign an agent to a device group.
  """
  def assign_agent_group(agent_id, group) do
    GenServer.call(__MODULE__, {:assign_agent_group, agent_id, group})
  end

  @doc """
  Get the device group for an agent.
  """
  def get_agent_group(agent_id) do
    GenServer.call(__MODULE__, {:get_agent_group, agent_id})
  end

  @doc """
  List all connected USB devices.
  """
  def list_connected_devices(filters \\ %{}) do
    GenServer.call(__MODULE__, {:list_connected_devices, filters})
  end

  @doc """
  Get device history for an agent.
  """
  def get_device_history(agent_id, filters \\ %{}) do
    GenServer.call(__MODULE__, {:get_device_history, agent_id, filters})
  end

  @doc """
  Record a USB device event.
  """
  def record_device_event(agent_id, event) do
    GenServer.cast(__MODULE__, {:record_device_event, agent_id, event})
  end

  @doc """
  Get encryption enforcement status.
  """
  def get_encryption_status do
    GenServer.call(__MODULE__, :get_encryption_status)
  end

  @doc """
  Configure encryption enforcement settings.
  """
  def configure_encryption(settings) do
    GenServer.call(__MODULE__, {:configure_encryption, settings})
  end

  @doc """
  Get write protection status.
  """
  def get_write_protection_status(agent_id \\ nil) do
    GenServer.call(__MODULE__, {:get_write_protection_status, agent_id})
  end

  @doc """
  Set write protection mode for a device group.
  """
  def set_write_protection(group, mode) do
    GenServer.call(__MODULE__, {:set_write_protection, group, mode})
  end

  @doc """
  Apply a policy template to a group.
  """
  def apply_template(group, template_name) do
    GenServer.call(__MODULE__, {:apply_template, group, template_name})
  end

  @doc """
  Get device control statistics.
  """
  def get_stats(time_range \\ "24h") do
    if Process.whereis(__MODULE__) do
      GenServer.call(__MODULE__, {:get_stats, time_range})
    else
      unavailable_stats(time_range)
    end
  end

  defp unavailable_stats(time_range) do
    %{
      time_range: time_range,
      total_events: 0,
      blocked_events: 0,
      storage_events: 0,
      connected_devices: 0,
      policies_count: 0,
      whitelist_count: 0,
      blocklist_count: 0,
      categories: %{},
      status: "unavailable",
      reason: "device_control_process_not_started"
    }
  end

  # ===========================================================================
  # Server Callbacks
  # ===========================================================================

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@policies_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@whitelist_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@blocklist_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@device_history_table, [:named_table, :ordered_set, :public, read_concurrency: true])
    :ets.new(@agent_groups_table, [:named_table, :set, :public, read_concurrency: true])

    # Load default policies
    Enum.each(@default_policies, fn {group, policy} ->
      :ets.insert(@policies_table, {group, policy})
    end)

    state = %{
      encryption_settings: %{
        require_bitlocker: false,
        require_veracrypt: false,
        allow_luks: true,
        block_unencrypted: false,
        grace_period_minutes: 0
      },
      connected_devices: %{},
      stats: %{
        total_events: 0,
        blocked_events: 0,
        storage_events: 0,
        last_reset: DateTime.utc_now()
      }
    }

    Logger.info("DeviceControl started with #{map_size(@default_policies)} default policies")

    {:ok, state}
  end

  @impl true
  def handle_call(:list_policies, _from, state) do
    policies = :ets.tab2list(@policies_table)
      |> Enum.map(fn {_group, policy} -> policy end)
    {:reply, policies, state}
  end

  @impl true
  def handle_call({:get_policy, group}, _from, state) do
    case :ets.lookup(@policies_table, group) do
      [{^group, policy}] -> {:reply, {:ok, policy}, state}
      [] -> {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:upsert_policy, policy_params}, _from, state) do
    group = policy_params.group
    policy = Map.merge(%{
      group: group,
      allowed_classes: [],
      blocked_classes: [],
      allowed_devices: [],
      blocked_devices: [],
      write_protection: "none",
      require_encryption: false,
      max_storage_size_gb: 0,
      allow_network_adapters: false,
      allow_wireless: false,
      audit_all: true,
      updated_at: DateTime.utc_now()
    }, policy_params)

    :ets.insert(@policies_table, {group, policy})
    Logger.info("USB policy updated for group: #{group}")
    {:reply, {:ok, policy}, state}
  end

  @impl true
  def handle_call({:delete_policy, group}, _from, state) do
    # Don't allow deleting default policies
    if group in ["it_admin", "developer", "standard", "kiosk", "executive"] do
      {:reply, {:error, :cannot_delete_default}, state}
    else
      case :ets.lookup(@policies_table, group) do
        [{^group, _}] ->
          :ets.delete(@policies_table, group)
          {:reply, {:ok, :deleted}, state}
        [] ->
          {:reply, {:error, :not_found}, state}
      end
    end
  end

  @impl true
  def handle_call(:get_whitelist, _from, state) do
    whitelist = :ets.tab2list(@whitelist_table)
      |> Enum.map(fn {device, metadata} -> Map.put(metadata, :device, device) end)
    {:reply, whitelist, state}
  end

  @impl true
  def handle_call({:add_to_whitelist, devices}, _from, state) do
    Enum.each(devices, fn device ->
      :ets.insert(@whitelist_table, {
        normalize_device(device),
        %{added_at: DateTime.utc_now(), added_by: "api"}
      })
    end)

    whitelist = :ets.tab2list(@whitelist_table)
      |> Enum.map(fn {device, metadata} -> Map.put(metadata, :device, device) end)

    {:reply, {:ok, whitelist}, state}
  end

  @impl true
  def handle_call({:remove_from_whitelist, devices}, _from, state) do
    Enum.each(devices, fn device ->
      :ets.delete(@whitelist_table, normalize_device(device))
    end)

    whitelist = :ets.tab2list(@whitelist_table)
      |> Enum.map(fn {device, metadata} -> Map.put(metadata, :device, device) end)

    {:reply, {:ok, whitelist}, state}
  end

  @impl true
  def handle_call(:get_blocklist, _from, state) do
    blocklist = :ets.tab2list(@blocklist_table)
      |> Enum.map(fn {device, metadata} -> Map.put(metadata, :device, device) end)
    {:reply, blocklist, state}
  end

  @impl true
  def handle_call({:add_to_blocklist, devices}, _from, state) do
    Enum.each(devices, fn device ->
      :ets.insert(@blocklist_table, {
        normalize_device(device),
        %{added_at: DateTime.utc_now(), reason: "manual"}
      })
    end)

    blocklist = :ets.tab2list(@blocklist_table)
      |> Enum.map(fn {device, metadata} -> Map.put(metadata, :device, device) end)

    {:reply, {:ok, blocklist}, state}
  end

  @impl true
  def handle_call({:remove_from_blocklist, devices}, _from, state) do
    Enum.each(devices, fn device ->
      :ets.delete(@blocklist_table, normalize_device(device))
    end)

    blocklist = :ets.tab2list(@blocklist_table)
      |> Enum.map(fn {device, metadata} -> Map.put(metadata, :device, device) end)

    {:reply, {:ok, blocklist}, state}
  end

  @impl true
  def handle_call({:assign_agent_group, agent_id, group}, _from, state) do
    # Validate group exists
    case :ets.lookup(@policies_table, group) do
      [{^group, _}] ->
        :ets.insert(@agent_groups_table, {agent_id, group})
        Logger.info("Agent #{agent_id} assigned to group: #{group}")
        {:reply, {:ok, group}, state}
      [] ->
        {:reply, {:error, :invalid_group}, state}
    end
  end

  @impl true
  def handle_call({:get_agent_group, agent_id}, _from, state) do
    case :ets.lookup(@agent_groups_table, agent_id) do
      [{^agent_id, group}] -> {:reply, {:ok, group}, state}
      [] -> {:reply, {:ok, "standard"}, state}  # Default to standard group
    end
  end

  @impl true
  def handle_call({:list_connected_devices, filters}, _from, state) do
    devices = Map.values(state.connected_devices)
      |> maybe_filter_by_agent(filters[:agent_id])
      |> maybe_filter_by_class(filters[:device_class])
      |> maybe_filter_by_blocked(filters[:blocked])
      |> Enum.take(filters[:limit] || 100)

    {:reply, devices, state}
  end

  @impl true
  def handle_call({:get_device_history, agent_id, filters}, _from, state) do
    # Get history from ETS (ordered by timestamp)
    history = :ets.select(@device_history_table, [
      {{{:"$1", :"$2"}, :"$3"},
       [{:==, :"$1", agent_id}],
       [:"$3"]}
    ])
    |> maybe_filter_history_by_class(filters[:device_class])
    |> maybe_filter_history_blocked(filters[:blocked_only])
    |> Enum.take(filters[:limit] || 100)

    {:reply, {:ok, history}, state}
  end

  @impl true
  def handle_call(:get_encryption_status, _from, state) do
    status = %{
      settings: state.encryption_settings,
      agents_with_encryption: count_agents_with_encryption(state),
      unencrypted_devices: count_unencrypted_devices(state)
    }
    {:reply, status, state}
  end

  @impl true
  def handle_call({:configure_encryption, settings}, _from, state) do
    new_settings = Map.merge(state.encryption_settings, settings)
    {:reply, {:ok, new_settings}, %{state | encryption_settings: new_settings}}
  end

  @impl true
  def handle_call({:get_write_protection_status, agent_id}, _from, state) do
    status = if agent_id do
      case :ets.lookup(@agent_groups_table, agent_id) do
        [{^agent_id, group}] ->
          case :ets.lookup(@policies_table, group) do
            [{^group, policy}] -> %{agent_id: agent_id, mode: policy.write_protection}
            [] -> %{agent_id: agent_id, mode: "none"}
          end
        [] ->
          %{agent_id: agent_id, mode: "none"}
      end
    else
      # Return summary of all groups
      :ets.tab2list(@policies_table)
      |> Enum.map(fn {group, policy} ->
        %{group: group, mode: policy.write_protection}
      end)
    end

    {:reply, status, state}
  end

  @impl true
  def handle_call({:set_write_protection, group, mode}, _from, state) do
    valid_modes = ["none", "read_only", "audit_only", "block_executables"]

    if mode not in valid_modes do
      {:reply, {:error, :invalid_mode}, state}
    else
      case :ets.lookup(@policies_table, group) do
        [{^group, policy}] ->
          updated_policy = Map.put(policy, :write_protection, mode)
          :ets.insert(@policies_table, {group, updated_policy})
          {:reply, {:ok, updated_policy}, state}
        [] ->
          {:reply, {:error, :group_not_found}, state}
      end
    end
  end

  @impl true
  def handle_call({:apply_template, group, template_name}, _from, state) do
    case Map.get(@default_policies, template_name) do
      nil ->
        {:reply, {:error, :template_not_found}, state}
      template ->
        policy = Map.put(template, :group, group)
        :ets.insert(@policies_table, {group, policy})
        {:reply, {:ok, policy}, state}
    end
  end

  @impl true
  def handle_call({:get_stats, time_range}, _from, state) do
    # Parse time range
    hours = case time_range do
      "1h" -> 1
      "6h" -> 6
      "24h" -> 24
      "7d" -> 168
      "30d" -> 720
      _ -> 24
    end

    cutoff = DateTime.add(DateTime.utc_now(), -hours * 3600, :second)

    # Count events in the time range
    events = :ets.select(@device_history_table, [
      {{{:"$1", :"$2"}, :"$3"},
       [{:>=, :"$2", cutoff}],
       [:"$3"]}
    ])

    blocked_count = Enum.count(events, fn e -> e[:blocked] end)
    storage_count = Enum.count(events, fn e -> e[:device_class] == "MassStorage" end)

    # Get all policies and their configurations
    policies = :ets.tab2list(@policies_table)
      |> Enum.map(fn {_group, policy} -> policy end)

    # Build category-based stats
    # Categories: USB, Bluetooth, Removable Storage, Network Adapters, Printers, Cameras, Microphones
    category_stats = build_category_stats(events, policies, state.connected_devices)

    stats = %{
      time_range: time_range,
      total_events: length(events),
      blocked_events: blocked_count,
      storage_events: storage_count,
      connected_devices: map_size(state.connected_devices),
      policies_count: :ets.info(@policies_table, :size),
      whitelist_count: :ets.info(@whitelist_table, :size),
      blocklist_count: :ets.info(@blocklist_table, :size),
      # Category-based stats for frontend
      categories: category_stats
    }

    {:reply, stats, state}
  end

  @impl true
  def handle_cast({:record_device_event, agent_id, event}, state) do
    timestamp = DateTime.utc_now()

    # Store in history
    :ets.insert(@device_history_table, {{agent_id, timestamp}, event})

    # Update connected devices if it's a connect event
    new_connected = case event[:event_type] do
      "connected" ->
        device_key = "#{agent_id}:#{event[:device_path]}"
        Map.put(state.connected_devices, device_key, Map.put(event, :agent_id, agent_id))

      "disconnected" ->
        device_key = "#{agent_id}:#{event[:device_path]}"
        Map.delete(state.connected_devices, device_key)

      _ ->
        state.connected_devices
    end

    # Update stats
    new_stats = %{state.stats |
      total_events: state.stats.total_events + 1,
      blocked_events: state.stats.blocked_events + (if event[:blocked], do: 1, else: 0),
      storage_events: state.stats.storage_events + (if event[:device_class] == "MassStorage", do: 1, else: 0)
    }

    {:noreply, %{state | connected_devices: new_connected, stats: new_stats}}
  end

  # ===========================================================================
  # Private Helpers
  # ===========================================================================

  defp normalize_device(device) when is_binary(device) do
    device |> String.upcase() |> String.trim()
  end
  defp normalize_device(%{"vid" => vid, "pid" => pid}) do
    "#{String.upcase(vid)}:#{String.upcase(pid)}"
  end
  defp normalize_device(device), do: to_string(device)

  defp maybe_filter_by_agent(devices, nil), do: devices
  defp maybe_filter_by_agent(devices, agent_id) do
    Enum.filter(devices, fn d -> d[:agent_id] == agent_id end)
  end

  defp maybe_filter_by_class(devices, nil), do: devices
  defp maybe_filter_by_class(devices, device_class) do
    Enum.filter(devices, fn d -> d[:device_class] == device_class end)
  end

  defp maybe_filter_by_blocked(devices, nil), do: devices
  defp maybe_filter_by_blocked(devices, blocked) do
    Enum.filter(devices, fn d -> d[:blocked] == blocked end)
  end

  defp maybe_filter_history_by_class(history, nil), do: history
  defp maybe_filter_history_by_class(history, device_class) do
    Enum.filter(history, fn h -> h[:device_class] == device_class end)
  end

  defp maybe_filter_history_blocked(history, false), do: history
  defp maybe_filter_history_blocked(history, true) do
    Enum.filter(history, fn h -> h[:blocked] end)
  end

  @doc """
  Count mobile devices reporting disk encryption enabled.

  Returns the count, or `nil` when the value is unknown (e.g. the database
  is unreachable). `nil` is deliberately distinct from `0` so callers and
  UIs do not present an unknown state as "zero encrypted devices".
  Devices with `encryption_enabled: nil` (never reported) are excluded.
  """
  def count_agents_with_encryption do
    import Ecto.Query, only: [from: 2]

    Repo.aggregate(
      from(d in TamanduaServer.Mobile.Device, where: d.encryption_enabled == true),
      :count
    )
  rescue
    error ->
      Logger.warning("DeviceControl: failed to count encrypted devices: #{inspect(error)}")
      nil
  end

  @doc """
  Count mobile devices explicitly reporting disk encryption disabled.

  Returns the count, or `nil` when the value is unknown (e.g. the database
  is unreachable). Devices that have never reported encryption state
  (`encryption_enabled: nil`) are excluded rather than assumed unencrypted.
  """
  def count_unencrypted_devices do
    import Ecto.Query, only: [from: 2]

    Repo.aggregate(
      from(d in TamanduaServer.Mobile.Device, where: d.encryption_enabled == false),
      :count
    )
  rescue
    error ->
      Logger.warning("DeviceControl: failed to count unencrypted devices: #{inspect(error)}")
      nil
  end

  defp count_agents_with_encryption(_state), do: count_agents_with_encryption()

  defp count_unencrypted_devices(_state), do: count_unencrypted_devices()

  @doc """
  Build category-based statistics for frontend display.

  Categories:
  - usb: USB flash drives, external hard drives
  - bluetooth: Bluetooth peripherals
  - removable_storage: Other removable storage
  - network_adapters: Network interface cards
  - printers: Printer devices
  - cameras: Webcams and imaging devices
  - microphones: Audio input devices
  """
  defp build_category_stats(events, policies, connected_devices) do
    # Define device categories with their USB class codes and default status
    categories = [
      %{
        id: "usb",
        name: "USB Storage",
        description: "USB flash drives, external hard drives, and other USB mass storage devices",
        device_classes: ["mass_storage", "MassStorage", "08"],
        icon: "usb"
      },
      %{
        id: "bluetooth",
        name: "Bluetooth",
        description: "Bluetooth peripherals, headsets, and file transfer devices",
        device_classes: ["bluetooth", "Bluetooth", "E0"],
        icon: "bluetooth"
      },
      %{
        id: "removable_storage",
        name: "Removable Storage",
        description: "External hard drives, SSDs, and other removable storage",
        device_classes: ["removable", "external_storage"],
        icon: "hard-drive"
      },
      %{
        id: "network_adapters",
        name: "Network Adapters",
        description: "External network adapters and wireless dongles",
        device_classes: ["network_adapter", "wireless_controller", "wireless", "02"],
        icon: "wifi"
      },
      %{
        id: "printers",
        name: "Printers",
        description: "USB and network printers",
        device_classes: ["printer", "07"],
        icon: "printer"
      },
      %{
        id: "cameras",
        name: "Cameras",
        description: "Webcams and imaging devices",
        device_classes: ["video", "camera", "imaging", "0E"],
        icon: "camera"
      },
      %{
        id: "microphones",
        name: "Microphones",
        description: "Audio input devices and microphones",
        device_classes: ["audio", "microphone", "01"],
        icon: "mic"
      }
    ]

    # Determine the default status per category based on policies
    # Look at the majority of policies to determine if category is typically allowed/blocked
    Enum.map(categories, fn category ->
      # Count events for this category
      category_events = Enum.filter(events, fn event ->
        event_class = to_string(event[:device_class] || "")
        Enum.any?(category.device_classes, fn class ->
          String.downcase(event_class) == String.downcase(class)
        end)
      end)

      # Count connected devices for this category
      connected_count = connected_devices
        |> Map.values()
        |> Enum.count(fn device ->
          device_class = to_string(device[:device_class] || "")
          Enum.any?(category.device_classes, fn class ->
            String.downcase(device_class) == String.downcase(class)
          end)
        end)

      # Determine status based on policies
      # Check if any policy blocks this category
      blocked_by_default = Enum.any?(policies, fn policy ->
        blocked_classes = policy[:blocked_classes] || []
        Enum.any?(category.device_classes, fn class ->
          String.downcase(class) in Enum.map(blocked_classes, &String.downcase/1)
        end)
      end)

      # Determine overall status
      status = cond do
        blocked_by_default -> "blocked"
        true -> "allowed"
      end

      %{
        id: category.id,
        name: category.name,
        description: category.description,
        icon: category.icon,
        status: status,
        event_count: length(category_events),
        blocked_count: Enum.count(category_events, fn e -> e[:blocked] end),
        connected_count: connected_count,
        policy_count: count_policies_for_category(policies, category.device_classes)
      }
    end)
  end

  defp count_policies_for_category(policies, device_classes) do
    Enum.count(policies, fn policy ->
      allowed_classes = policy[:allowed_classes] || []
      blocked_classes = policy[:blocked_classes] || []
      all_classes = allowed_classes ++ blocked_classes

      Enum.any?(device_classes, fn class ->
        String.downcase(class) in Enum.map(all_classes, &String.downcase/1)
      end)
    end)
  end
end
