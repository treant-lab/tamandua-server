defmodule TamanduaServer.Mobile.DeviceRegistry do
  @moduledoc """
  GenServer for mobile device lifecycle management.

  Manages three ETS tables for high-performance reads:
  - `:mobile_device_registry` -- Active device state cache
  - `:mobile_device_compliance` -- Compliance check results
  - `:mobile_device_stats` -- Aggregate statistics

  All mutations flow through the GenServer to ensure serialized writes,
  while reads go directly to ETS for concurrency.
  """

  use GenServer
  require Logger

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Mobile.Device
  alias TamanduaServer.Mobile.MobileApp

  @registry_table :mobile_device_registry
  @compliance_table :mobile_device_compliance
  @stats_table :mobile_device_stats

  @compliance_check_interval :timer.hours(1)
  @stale_device_threshold_hours 24
  @supported_platforms ~w(ios android)

  # Minimum supported OS versions (below these, compliance fails)
  @min_os_versions %{
    "ios" => "15.0",
    "android" => "12"
  }

  # Apps that indicate jailbreak/root
  @jailbreak_indicators [
    # iOS
    "/Applications/Cydia.app",
    "/Library/MobileSubstrate",
    "/usr/sbin/sshd",
    "/etc/apt",
    "/bin/bash",
    "/usr/bin/ssh",
    "cydia://",
    "/var/lib/dpkg",
    "/Applications/FakeCarrier.app",
    "/Applications/SBSettings.app",
    "/Applications/blackra1n.app",
    "/Applications/IntelliScreen.app",
    "/Applications/Snoop-itConfig.app"
  ]

  @root_indicators [
    # Android
    "/system/app/Superuser.apk",
    "/system/xbin/su",
    "/system/bin/su",
    "/sbin/su",
    "/data/local/xbin/su",
    "/data/local/bin/su",
    "/data/local/su",
    "/system/bin/failsafe/su"
  ]

  @root_app_packages [
    "com.topjohnwu.magisk",
    "com.koushikdutta.superuser",
    "eu.chainfire.supersu",
    "com.noshufou.android.su",
    "com.thirdparty.superuser",
    "com.yellowes.su",
    "com.kingroot.kinguser",
    "com.kingo.root",
    "com.oneclick.root"
  ]

  @blacklisted_apps [
    "com.metasploit.stage",
    "com.zimperium.zanti",
    "de.robv.android.xposed",
    "com.saurik.substrate",
    "com.ramdroid.appquarantine",
    "com.amphoras.hidemyroot",
    "com.formyhm.hideroot",
    "com.koushikdutta.rommanager",
    "com.dimonvideo.luckypatcher",
    "com.chelpus.lackypatch",
    "com.android.vending.billing.InAppBillingService.LUCK",
    "com.android.vendinc",
    "com.happymod.apk"
  ]

  # Dangerous permission combinations that suggest spyware
  @spyware_permission_combos [
    ["android.permission.CAMERA", "android.permission.INTERNET", "android.permission.SEND_SMS"],
    ["android.permission.RECORD_AUDIO", "android.permission.INTERNET", "android.permission.ACCESS_FINE_LOCATION"],
    ["android.permission.READ_SMS", "android.permission.INTERNET", "android.permission.READ_CONTACTS"],
    ["android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION",
     "android.permission.INTERNET"]
  ]

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Registers a new mobile device.

  Expects a map with at least `organization_id`, `device_id`, and `platform`.
  Optional fields: `os_version`, `model`, `serial_number`, `owner_email`,
  `manufacturer`, `agent_version`, `ip_address`, `mac_address`.
  """
  @spec register_device(map()) :: {:ok, Device.t()} | {:error, Ecto.Changeset.t()}
  def register_device(attrs) do
    GenServer.call(__MODULE__, {:register_device, attrs})
  end

  @doc """
  Enrolls a device with an MDM provider.

  `enrollment` should contain `mdm_provider`, and optionally `mdm_device_id`.
  """
  @spec enroll_device(String.t(), map()) :: {:ok, Device.t()} | {:error, term()}
  def enroll_device(device_id, enrollment) do
    GenServer.call(__MODULE__, {:enroll_device, device_id, enrollment})
  end

  @doc """
  Updates the status of a device.

  Valid statuses: `active`, `lost`, `wiped`, `retired`, `pending`.
  """
  @spec update_status(String.t(), String.t()) :: {:ok, Device.t()} | {:error, term()}
  def update_status(device_id, status) when status in ~w(active lost wiped retired pending) do
    GenServer.call(__MODULE__, {:update_status, device_id, status})
  end

  @doc """
  Marks a device as inactive (retired).
  """
  @spec deactivate_device(String.t()) :: {:ok, Device.t()} | {:error, term()}
  def deactivate_device(device_id) do
    update_status(device_id, "retired")
  end

  @doc """
  Gets full device info including compliance status from ETS cache.

  Falls back to database if not cached.
  """
  @spec get_device(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_device(device_id) do
    case :ets.lookup(@registry_table, device_id) do
      [{^device_id, device_state}] ->
        compliance = get_cached_compliance(device_id)
        {:ok, Map.put(device_state, :compliance, compliance)}

      [] ->
        case Repo.get(Device, device_id) do
          nil -> {:error, :not_found}
          device -> {:ok, device_to_state(device)}
        end
    end
  end

  @doc """
  Lists devices with optional filters.

  Supported filters:
  - `platform` -- "ios" or "android"
  - `status` -- "active", "lost", "wiped", "retired", "pending"
  - `compliance` -- "compliant", "non_compliant", "unknown"
  - `owner` -- owner email substring match
  - `organization_id` -- scoped to organization
  """
  @spec list_devices(map()) :: [map()]
  def list_devices(filters \\ %{}) do
    @registry_table
    |> :ets.tab2list()
    |> Enum.map(fn {_id, state} -> state end)
    |> apply_filters(filters)
    |> Enum.sort_by(& &1.last_seen_at, {:desc, NaiveDateTime})
  end

  # ---------------------------------------------------------------------------
  # Compliance API
  # ---------------------------------------------------------------------------

  @doc """
  Runs all compliance checks on a device and caches the result.

  Returns a compliance report with individual check results and an overall
  compliant/non_compliant status.
  """
  @spec check_compliance(String.t()) :: {:ok, map()} | {:error, term()}
  def check_compliance(device_id) do
    GenServer.call(__MODULE__, {:check_compliance, device_id})
  end

  @doc """
  Gets the cached compliance report for a device.
  """
  @spec get_compliance_report(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_compliance_report(device_id) do
    case :ets.lookup(@compliance_table, device_id) do
      [{^device_id, report}] -> {:ok, report}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Runs compliance checks on all active devices.
  Returns `{checked_count, non_compliant_count}`.
  """
  @spec bulk_compliance_check() :: {:ok, %{checked: non_neg_integer(), non_compliant: non_neg_integer()}}
  def bulk_compliance_check do
    GenServer.call(__MODULE__, :bulk_compliance_check, :timer.minutes(5))
  end

  @doc """
  Returns aggregate statistics from the stats ETS table.
  """
  @spec get_stats() :: map()
  def get_stats do
    case :ets.lookup(@stats_table, :aggregate) do
      [{:aggregate, stats}] -> stats
      [] -> %{total: 0, active: 0, ios: 0, android: 0, compliant: 0, non_compliant: 0,
              mdm_enrolled: 0, high_risk: 0, stale: 0}
    end
  end

  # ---------------------------------------------------------------------------
  # GenServer Callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    :ets.new(@registry_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@compliance_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@stats_table, [:named_table, :set, :public, read_concurrency: true])

    # Load all active devices into ETS
    load_devices_into_ets()

    # Schedule periodic compliance checks
    schedule_compliance_check()

    Logger.info("[Mobile.DeviceRegistry] Started with ETS tables initialized")
    {:ok, %{last_compliance_check: nil}}
  end

  @impl true
  def handle_call({:register_device, attrs}, _from, state) do
    result =
      %Device{}
      |> Device.registration_changeset(attrs)
      |> Repo.insert()

    case result do
      {:ok, device} ->
        device_state = device_to_state(device)
        :ets.insert(@registry_table, {device.id, device_state})
        refresh_stats()

        Logger.info("[Mobile.DeviceRegistry] Device registered: id=#{device.id} platform=#{device.platform}")
        broadcast_event(:device_registered, device)
        {:reply, {:ok, device}, state}

      {:error, _changeset} = error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:enroll_device, device_id, enrollment}, _from, state) do
    case Repo.get(Device, device_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      device ->
        attrs = %{
          mdm_enrolled: true,
          mdm_provider: enrollment["mdm_provider"] || enrollment[:mdm_provider] || "none",
          mdm_device_id: enrollment["mdm_device_id"] || enrollment[:mdm_device_id],
          mdm_last_sync: NaiveDateTime.utc_now(),
          status: "active",
          enrolled_at: NaiveDateTime.utc_now()
        }

        case device |> Device.mdm_sync_changeset(attrs) |> Repo.update() do
          {:ok, updated_device} ->
            device_state = device_to_state(updated_device)
            :ets.insert(@registry_table, {device_id, device_state})
            refresh_stats()

            Logger.info("[Mobile.DeviceRegistry] Device enrolled: id=#{device_id} provider=#{attrs.mdm_provider}")
            broadcast_event(:device_enrolled, updated_device)
            {:reply, {:ok, updated_device}, state}

          {:error, _} = error ->
            {:reply, error, state}
        end
    end
  end

  @impl true
  def handle_call({:update_status, device_id, new_status}, _from, state) do
    case Repo.get(Device, device_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      device ->
        case device |> Device.changeset(%{status: new_status}) |> Repo.update() do
          {:ok, updated_device} ->
            device_state = device_to_state(updated_device)
            :ets.insert(@registry_table, {device_id, device_state})
            refresh_stats()

            Logger.info("[Mobile.DeviceRegistry] Status updated: id=#{device_id} status=#{new_status}")
            broadcast_event(:device_status_changed, %{device: updated_device, status: new_status})
            {:reply, {:ok, updated_device}, state}

          {:error, _} = error ->
            {:reply, error, state}
        end
    end
  end

  @impl true
  def handle_call({:check_compliance, device_id}, _from, state) do
    case Repo.get(Device, device_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      device ->
        report = run_compliance_checks(device)
        :ets.insert(@compliance_table, {device_id, report})

        # Update device compliance status in DB
        compliance_status = if report.overall_compliant, do: "compliant", else: "non_compliant"

        device
        |> Device.mdm_sync_changeset(%{mdm_compliance_status: compliance_status})
        |> Repo.update()

        # Update ETS cache
        case :ets.lookup(@registry_table, device_id) do
          [{^device_id, device_state}] ->
            updated_state = Map.put(device_state, :compliance_status, compliance_status)
            :ets.insert(@registry_table, {device_id, updated_state})

          [] ->
            :ok
        end

        refresh_stats()
        {:reply, {:ok, report}, state}
    end
  end

  @impl true
  def handle_call(:bulk_compliance_check, _from, state) do
    devices =
      Device
      |> where([d], d.status in ["active", "pending"])
      |> Repo.all()

    results =
      Enum.reduce(devices, %{checked: 0, non_compliant: 0}, fn device, acc ->
        report = run_compliance_checks(device)
        :ets.insert(@compliance_table, {device.id, report})

        compliance_status = if report.overall_compliant, do: "compliant", else: "non_compliant"

        device
        |> Device.mdm_sync_changeset(%{mdm_compliance_status: compliance_status})
        |> Repo.update()

        non_compliant_delta = if report.overall_compliant, do: 0, else: 1
        %{acc | checked: acc.checked + 1, non_compliant: acc.non_compliant + non_compliant_delta}
      end)

    refresh_stats()

    new_state = %{state | last_compliance_check: DateTime.utc_now()}
    Logger.info("[Mobile.DeviceRegistry] Bulk compliance: checked=#{results.checked} non_compliant=#{results.non_compliant}")
    {:reply, {:ok, results}, new_state}
  end

  @impl true
  def handle_info(:scheduled_compliance_check, state) do
    # Run compliance checks in the background
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      devices =
        Device
        |> where([d], d.status in ["active", "pending"])
        |> Repo.all()

      Enum.each(devices, fn device ->
        report = run_compliance_checks(device)
        :ets.insert(@compliance_table, {device.id, report})
      end)

      refresh_stats()
    end)

    schedule_compliance_check()
    {:noreply, %{state | last_compliance_check: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ---------------------------------------------------------------------------
  # Compliance Checks
  # ---------------------------------------------------------------------------

  defp run_compliance_checks(device) do
    now = NaiveDateTime.utc_now()

    checks = [
      check_os_version(device),
      check_encryption(device),
      check_screen_lock(device),
      check_jailbreak_root(device),
      check_blacklisted_apps(device),
      check_mdm_profile(device),
      check_last_checkin(device, now)
    ]

    failed_checks = Enum.filter(checks, fn check -> not check.passed end)
    overall_compliant = Enum.empty?(failed_checks)

    %{
      device_id: device.id,
      platform: device.platform,
      checked_at: now,
      overall_compliant: overall_compliant,
      compliance_status: if(overall_compliant, do: "compliant", else: "non_compliant"),
      checks: checks,
      failed_count: length(failed_checks),
      total_count: length(checks),
      failed_checks: Enum.map(failed_checks, & &1.name),
      risk_score: calculate_compliance_risk(checks)
    }
  end

  defp check_os_version(device) do
    min_version = Map.get(@min_os_versions, device.platform, "0")
    current = device.os_version || "0"

    passed = version_gte?(current, min_version)

    %{
      name: "os_version",
      description: "OS version is supported and patched",
      passed: passed,
      details: %{
        current: current,
        minimum: min_version,
        platform: device.platform
      }
    }
  end

  defp check_encryption(device) do
    passed = device.encryption_enabled == true

    %{
      name: "encryption_enabled",
      description: "Device encryption is enabled",
      passed: passed,
      details: %{encryption_enabled: device.encryption_enabled}
    }
  end

  defp check_screen_lock(device) do
    passed = device.passcode_enabled == true

    %{
      name: "screen_lock",
      description: "Screen lock enabled with PIN/password",
      passed: passed,
      details: %{
        passcode_enabled: device.passcode_enabled,
        passcode_compliant: device.passcode_compliant,
        biometric_enabled: device.biometric_enabled
      }
    }
  end

  defp check_jailbreak_root(device) do
    jailbroken = device.is_jailbroken == true
    rooted = device.is_rooted == true
    passed = not (jailbroken or rooted)

    %{
      name: "not_jailbroken_rooted",
      description: "Device is not jailbroken or rooted",
      passed: passed,
      details: %{is_jailbroken: jailbroken, is_rooted: rooted}
    }
  end

  defp check_blacklisted_apps(device) do
    # Query installed apps that are in the blacklist
    installed_blacklisted =
      MobileApp
      |> MobileApp.by_device(device.id)
      |> where([a], a.bundle_id in ^@blacklisted_apps)
      |> Repo.all()

    passed = Enum.empty?(installed_blacklisted)

    %{
      name: "no_blacklisted_apps",
      description: "No blacklisted applications installed",
      passed: passed,
      details: %{
        blacklisted_found: Enum.map(installed_blacklisted, & &1.bundle_id)
      }
    }
  end

  defp check_mdm_profile(device) do
    passed = device.mdm_enrolled == true

    %{
      name: "mdm_profile_active",
      description: "MDM profile installed and active",
      passed: passed,
      details: %{
        mdm_enrolled: device.mdm_enrolled,
        mdm_provider: device.mdm_provider,
        mdm_compliance_status: device.mdm_compliance_status
      }
    }
  end

  defp check_last_checkin(device, now) do
    threshold_seconds = @stale_device_threshold_hours * 3600

    passed =
      case device.last_seen_at do
        nil -> false
        last_seen -> NaiveDateTime.diff(now, last_seen) < threshold_seconds
      end

    %{
      name: "recent_checkin",
      description: "Device checked in within #{@stale_device_threshold_hours}h",
      passed: passed,
      details: %{
        last_seen_at: device.last_seen_at,
        threshold_hours: @stale_device_threshold_hours
      }
    }
  end

  defp calculate_compliance_risk(checks) do
    weights = %{
      "not_jailbroken_rooted" => 40,
      "encryption_enabled" => 20,
      "screen_lock" => 15,
      "no_blacklisted_apps" => 10,
      "os_version" => 5,
      "mdm_profile_active" => 5,
      "recent_checkin" => 5
    }

    failed_score =
      checks
      |> Enum.reject(& &1.passed)
      |> Enum.reduce(0, fn check, acc ->
        acc + Map.get(weights, check.name, 0)
      end)

    min(100, failed_score)
  end

  # ---------------------------------------------------------------------------
  # Filtering
  # ---------------------------------------------------------------------------

  defp apply_filters(devices, filters) when map_size(filters) == 0, do: devices

  defp apply_filters(devices, filters) do
    devices
    |> filter_by_platform(filters)
    |> filter_by_status(filters)
    |> filter_by_compliance(filters)
    |> filter_by_owner(filters)
    |> filter_by_organization(filters)
  end

  defp filter_by_platform(devices, %{"platform" => platform}) when platform in @supported_platforms do
    Enum.filter(devices, &(&1.platform == platform))
  end
  defp filter_by_platform(devices, _), do: devices

  defp filter_by_status(devices, %{"status" => status}) when is_binary(status) and status != "" do
    Enum.filter(devices, &(&1.status == status))
  end
  defp filter_by_status(devices, _), do: devices

  defp filter_by_compliance(devices, %{"compliance" => compliance}) when compliance in ~w(compliant non_compliant unknown) do
    Enum.filter(devices, fn device ->
      cached = get_cached_compliance(device.id)
      cached_status = if cached, do: cached.compliance_status, else: "unknown"
      cached_status == compliance
    end)
  end
  defp filter_by_compliance(devices, _), do: devices

  defp filter_by_owner(devices, %{"owner" => owner}) when is_binary(owner) and owner != "" do
    owner_lower = String.downcase(owner)
    Enum.filter(devices, fn device ->
      email = device[:user_email] || ""
      String.contains?(String.downcase(email), owner_lower)
    end)
  end
  defp filter_by_owner(devices, _), do: devices

  defp filter_by_organization(devices, %{"organization_id" => org_id}) when is_binary(org_id) do
    Enum.filter(devices, &(&1.organization_id == org_id))
  end
  defp filter_by_organization(devices, _), do: devices

  # ---------------------------------------------------------------------------
  # Internal Helpers
  # ---------------------------------------------------------------------------

  defp load_devices_into_ets do
    devices =
      Device
      |> where([d], d.status in ["active", "pending"])
      |> Repo.all()

    Enum.each(devices, fn device ->
      :ets.insert(@registry_table, {device.id, device_to_state(device)})
    end)

    refresh_stats()
    Logger.info("[Mobile.DeviceRegistry] Loaded #{length(devices)} devices into ETS")
  end

  defp device_to_state(%Device{} = device) do
    %{
      id: device.id,
      device_id: device.device_id,
      platform: device.platform,
      model: device.model,
      manufacturer: device.manufacturer,
      os_version: device.os_version,
      serial_number: device.serial_number,
      agent_version: device.agent_version,
      status: device.status,
      mdm_enrolled: device.mdm_enrolled,
      mdm_provider: device.mdm_provider,
      mdm_device_id: device.mdm_device_id,
      mdm_compliance_status: device.mdm_compliance_status,
      is_jailbroken: device.is_jailbroken,
      is_rooted: device.is_rooted,
      passcode_enabled: device.passcode_enabled,
      encryption_enabled: device.encryption_enabled,
      risk_score: device.risk_score,
      risk_factors: device.risk_factors,
      user_email: device.user_email,
      user_name: device.user_name,
      department: device.department,
      organization_id: device.organization_id,
      last_seen_at: device.last_seen_at,
      enrolled_at: device.enrolled_at,
      compliance_status: device.mdm_compliance_status || "unknown",
      inserted_at: device.inserted_at,
      updated_at: device.updated_at
    }
  end

  defp get_cached_compliance(device_id) do
    case :ets.lookup(@compliance_table, device_id) do
      [{^device_id, report}] -> report
      [] -> nil
    end
  end

  defp refresh_stats do
    all_devices =
      @registry_table
      |> :ets.tab2list()
      |> Enum.map(fn {_id, state} -> state end)

    compliance_list =
      @compliance_table
      |> :ets.tab2list()
      |> Map.new(fn {id, report} -> {id, report} end)

    total = length(all_devices)
    active = Enum.count(all_devices, &(&1.status == "active"))
    ios_count = Enum.count(all_devices, &(&1.platform == "ios"))
    android_count = Enum.count(all_devices, &(&1.platform == "android"))
    mdm_enrolled = Enum.count(all_devices, &(&1.mdm_enrolled == true))
    high_risk = Enum.count(all_devices, &((&1.risk_score || 0) >= 50))

    now = NaiveDateTime.utc_now()
    stale_threshold = @stale_device_threshold_hours * 3600

    stale =
      Enum.count(all_devices, fn device ->
        case device.last_seen_at do
          nil -> true
          last_seen -> NaiveDateTime.diff(now, last_seen) >= stale_threshold
        end
      end)

    compliant =
      Enum.count(all_devices, fn device ->
        case Map.get(compliance_list, device.id) do
          %{overall_compliant: true} -> true
          _ -> false
        end
      end)

    non_compliant =
      Enum.count(all_devices, fn device ->
        case Map.get(compliance_list, device.id) do
          %{overall_compliant: false} -> true
          _ -> false
        end
      end)

    stats = %{
      total: total,
      active: active,
      ios: ios_count,
      android: android_count,
      compliant: compliant,
      non_compliant: non_compliant,
      mdm_enrolled: mdm_enrolled,
      high_risk: high_risk,
      stale: stale,
      updated_at: DateTime.utc_now()
    }

    :ets.insert(@stats_table, {:aggregate, stats})
  end

  defp schedule_compliance_check do
    Process.send_after(self(), :scheduled_compliance_check, @compliance_check_interval)
  end

  defp broadcast_event(event_type, payload) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "mobile:device_events",
      {event_type, payload}
    )
  end

  defp version_gte?(current, minimum) do
    current_parts = parse_version_parts(current)
    minimum_parts = parse_version_parts(minimum)
    compare_version_parts(current_parts, minimum_parts) != :lt
  end

  defp parse_version_parts(version_string) do
    version_string
    |> String.split(".")
    |> Enum.map(fn part ->
      case Integer.parse(part) do
        {num, _} -> num
        :error -> 0
      end
    end)
  end

  defp compare_version_parts([], []), do: :eq
  defp compare_version_parts([], _), do: :lt
  defp compare_version_parts(_, []), do: :gt
  defp compare_version_parts([a | rest_a], [b | rest_b]) do
    cond do
      a > b -> :gt
      a < b -> :lt
      true -> compare_version_parts(rest_a, rest_b)
    end
  end

  # Public accessors for indicator lists (used by ThreatDetection)

  @doc false
  def jailbreak_indicators, do: @jailbreak_indicators

  @doc false
  def root_indicators, do: @root_indicators

  @doc false
  def root_app_packages, do: @root_app_packages

  @doc false
  def blacklisted_apps, do: @blacklisted_apps

  @doc false
  def spyware_permission_combos, do: @spyware_permission_combos
end
