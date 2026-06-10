defmodule TamanduaServer.Mobile.AppInventory do
  @moduledoc """
  App inventory management for mobile devices.

  Provides functions for:
  - Syncing installed apps from MDM providers
  - Checking apps against a blacklist
  - Auditing dangerous permission combinations
  - Getting full app inventory for a device
  - Calculating overall app risk score
  """

  require Logger

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Mobile.{MobileApp, DeviceRegistry}

  # Dangerous permission combinations grouped by threat type
  @dangerous_combos %{
    spyware: [
      ["android.permission.CAMERA", "android.permission.INTERNET", "android.permission.SEND_SMS"],
      ["android.permission.RECORD_AUDIO", "android.permission.INTERNET", "android.permission.ACCESS_FINE_LOCATION"],
      ["android.permission.READ_SMS", "android.permission.INTERNET", "android.permission.READ_CONTACTS"]
    ],
    surveillance: [
      ["android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION"],
      ["android.permission.ACCESS_FINE_LOCATION", "android.permission.RECORD_AUDIO", "android.permission.INTERNET"]
    ],
    data_exfiltration: [
      ["android.permission.READ_CONTACTS", "android.permission.READ_SMS", "android.permission.INTERNET"],
      ["android.permission.READ_EXTERNAL_STORAGE", "android.permission.INTERNET"],
      ["android.permission.READ_CALL_LOG", "android.permission.INTERNET"]
    ],
    device_admin: [
      ["android.permission.BIND_DEVICE_ADMIN"],
      ["android.permission.BIND_ACCESSIBILITY_SERVICE"]
    ]
  }

  @doc """
  Syncs installed apps from an MDM provider for a device.

  `apps_data` is a list of maps, each containing at least `bundle_id`.
  Returns `{:ok, %{inserted: n, updated: n, deleted: n}}`.
  """
  @spec sync_apps(String.t(), [map()]) :: {:ok, map()} | {:error, term()}
  def sync_apps(device_id, apps_data) when is_list(apps_data) do
    existing = Repo.all(MobileApp.by_device(device_id))
    existing_map = Map.new(existing, &{&1.bundle_id, &1})
    incoming_ids = MapSet.new(apps_data, & &1["bundle_id"])

    {inserts, updates} =
      Enum.reduce(apps_data, {[], []}, fn app_data, {ins, upd} ->
        bundle_id = app_data["bundle_id"]
        attrs = Map.put(app_data, "device_id", device_id)

        case Map.get(existing_map, bundle_id) do
          nil ->
            changeset = MobileApp.sync_changeset(%MobileApp{}, attrs)
            {[changeset | ins], upd}

          existing_app ->
            changeset = MobileApp.sync_changeset(existing_app, attrs)
            {ins, [changeset | upd]}
        end
      end)

    to_delete = Enum.reject(existing, &MapSet.member?(incoming_ids, &1.bundle_id))

    Repo.transaction(fn ->
      inserted = Enum.count(inserts, fn cs -> match?({:ok, _}, Repo.insert(cs)) end)
      updated = Enum.count(updates, fn cs -> match?({:ok, _}, Repo.update(cs)) end)
      deleted = length(to_delete)
      Enum.each(to_delete, &Repo.delete/1)

      Logger.info("[AppInventory] Synced device=#{device_id}: inserted=#{inserted} updated=#{updated} deleted=#{deleted}")
      %{inserted: inserted, updated: updated, deleted: deleted}
    end)
  end

  @doc """
  Checks installed apps on a device against the blacklist.

  Returns a list of blacklisted apps found on the device.
  """
  @spec check_blacklist(String.t()) :: {:ok, [map()]}
  def check_blacklist(device_id) do
    blacklist = DeviceRegistry.blacklisted_apps()
    root_packages = DeviceRegistry.root_app_packages()
    all_blocked = blacklist ++ root_packages

    found =
      MobileApp
      |> MobileApp.by_device(device_id)
      |> where([a], a.bundle_id in ^all_blocked)
      |> Repo.all()
      |> Enum.map(fn app ->
        category =
          cond do
            app.bundle_id in blacklist -> "malicious"
            app.bundle_id in root_packages -> "root_tool"
            true -> "unknown"
          end

        %{
          bundle_id: app.bundle_id,
          app_name: app.app_name,
          category: category,
          risk_level: app.risk_level,
          installed_at: app.installed_at
        }
      end)

    {:ok, found}
  end

  @doc """
  Audits apps on a device for dangerous permission combinations.

  Returns a list of apps with suspicious permission patterns, grouped by threat type.
  """
  @spec check_permissions(String.t()) :: {:ok, [map()]}
  def check_permissions(device_id) do
    apps =
      MobileApp
      |> MobileApp.by_device(device_id)
      |> where([a], a.is_system_app == false)
      |> Repo.all()

    findings =
      Enum.flat_map(apps, fn app ->
        permissions = app.permissions || []
        if Enum.empty?(permissions) do
          []
        else
          matched_threats =
            Enum.flat_map(@dangerous_combos, fn {threat_type, combos} ->
              matching =
                Enum.filter(combos, fn combo ->
                  Enum.all?(combo, &(&1 in permissions))
                end)

              if Enum.empty?(matching) do
                []
              else
                [%{
                  threat_type: threat_type,
                  matched_combos: length(matching)
                }]
              end
            end)

          if Enum.empty?(matched_threats) do
            []
          else
            [%{
              bundle_id: app.bundle_id,
              app_name: app.app_name,
              permissions: permissions,
              dangerous_permissions: app.dangerous_permissions || [],
              threats: matched_threats,
              risk_level: app.risk_level
            }]
          end
        end
      end)

    {:ok, findings}
  end

  @doc """
  Gets the full app inventory for a device, enriched with risk data.
  """
  @spec get_inventory(String.t()) :: {:ok, map()}
  def get_inventory(device_id) do
    apps =
      MobileApp
      |> MobileApp.by_device(device_id)
      |> order_by([a], asc: a.app_name)
      |> Repo.all()

    total = length(apps)
    system_apps = Enum.count(apps, & &1.is_system_app)
    user_apps = total - system_apps
    sideloaded = Enum.count(apps, &(&1.installer == "sideload"))

    risk_distribution =
      apps
      |> Enum.group_by(& &1.risk_level)
      |> Enum.map(fn {level, group} -> {level, length(group)} end)
      |> Map.new()

    serialized_apps =
      Enum.map(apps, fn app ->
        %{
          id: app.id,
          bundle_id: app.bundle_id,
          app_name: app.app_name,
          version: app.version,
          installer: app.installer,
          risk_level: app.risk_level,
          risk_reasons: app.risk_reasons,
          dangerous_permissions: app.dangerous_permissions,
          is_system_app: app.is_system_app,
          is_debuggable: app.is_debuggable,
          developer: app.developer,
          category: app.category,
          size_bytes: app.size_bytes,
          installed_at: app.installed_at,
          first_seen_at: app.first_seen_at
        }
      end)

    {:ok, %{
      device_id: device_id,
      total_apps: total,
      system_apps: system_apps,
      user_apps: user_apps,
      sideloaded: sideloaded,
      risk_distribution: risk_distribution,
      apps: serialized_apps,
      scanned_at: NaiveDateTime.utc_now()
    }}
  end

  @doc """
  Calculates an overall app risk score (0-100) for a device.

  The score is based on:
  - Number and severity of risky apps
  - Sideloaded app count
  - Dangerous permission patterns
  - Blacklisted app presence
  """
  @spec get_risk_score(String.t()) :: {:ok, map()}
  def get_risk_score(device_id) do
    apps =
      MobileApp
      |> MobileApp.by_device(device_id)
      |> where([a], a.is_system_app == false)
      |> Repo.all()

    if Enum.empty?(apps) do
      {:ok, %{device_id: device_id, risk_score: 0, risk_level: "low", factors: [], app_count: 0}}
    else
      factors = []
      score = 0

      # Critical risk apps
      critical_apps = Enum.count(apps, &(&1.risk_level == "critical"))
      {score, factors} = if critical_apps > 0 do
        {score + critical_apps * 25,
         [%{factor: "critical_risk_apps", count: critical_apps, weight: 25} | factors]}
      else
        {score, factors}
      end

      # High risk apps
      high_apps = Enum.count(apps, &(&1.risk_level == "high"))
      {score, factors} = if high_apps > 0 do
        {score + high_apps * 15,
         [%{factor: "high_risk_apps", count: high_apps, weight: 15} | factors]}
      else
        {score, factors}
      end

      # Sideloaded apps
      sideloaded = Enum.count(apps, &(&1.installer == "sideload"))
      {score, factors} = if sideloaded > 0 do
        {score + sideloaded * 10,
         [%{factor: "sideloaded_apps", count: sideloaded, weight: 10} | factors]}
      else
        {score, factors}
      end

      # Debuggable apps
      debuggable = Enum.count(apps, & &1.is_debuggable)
      {score, factors} = if debuggable > 0 do
        {score + debuggable * 5,
         [%{factor: "debuggable_apps", count: debuggable, weight: 5} | factors]}
      else
        {score, factors}
      end

      # Blacklisted apps
      blacklist = DeviceRegistry.blacklisted_apps()
      blacklisted = Enum.count(apps, &(&1.bundle_id in blacklist))
      {score, factors} = if blacklisted > 0 do
        {score + blacklisted * 30,
         [%{factor: "blacklisted_apps", count: blacklisted, weight: 30} | factors]}
      else
        {score, factors}
      end

      final_score = min(100, score)

      risk_level =
        cond do
          final_score >= 70 -> "critical"
          final_score >= 50 -> "high"
          final_score >= 25 -> "medium"
          true -> "low"
        end

      {:ok, %{
        device_id: device_id,
        risk_score: final_score,
        risk_level: risk_level,
        factors: factors,
        app_count: length(apps),
        calculated_at: NaiveDateTime.utc_now()
      }}
    end
  end
end
