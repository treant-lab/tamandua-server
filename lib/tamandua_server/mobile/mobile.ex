defmodule TamanduaServer.Mobile do
  @moduledoc """
  Context module for mobile device management.

  Provides functions for managing mobile devices, processing events,
  and coordinating with MDM integrations.
  """

  import Ecto.Query
  require Logger

  alias TamanduaServer.Agents
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Repo

  alias TamanduaServer.Mobile.{
    AppGuardBuildManifest,
    AppGuardProtectedApp,
    AppGuardResearchProgram,
    AppGuardResearchSubmission,
    Device,
    MobileApp,
    MobileEvent
  }

  # MITRE ATT&CK Mobile technique mappings for alert creation.
  # Maps mobile event types to {technique_id, technique_name, tactic}.
  @mobile_mitre_mappings %{
    "jailbreak_detected" => {"T1398", "Modify OS Kernel or Boot Partition", "Defense Evasion"},
    "root_detected" => {"T1398", "Modify OS Kernel or Boot Partition", "Defense Evasion"},
    "suspicious_app_installed" =>
      {"T1444", "Masquerade as Legitimate Application", "Initial Access"},
    "malware_detected" => {"T1444", "Masquerade as Legitimate Application", "Initial Access"},
    "spyware_detected" => {"T1444", "Masquerade as Legitimate Application", "Initial Access"},
    "sideload_attempt" => {"T1444", "Masquerade as Legitimate Application", "Initial Access"},
    "malicious_dns_query" =>
      {"T1446", "Fetch or Obtain Alternate Network Communications", "Command and Control"},
    "suspicious_connection" =>
      {"T1446", "Fetch or Obtain Alternate Network Communications", "Command and Control"},
    "man_in_the_middle" =>
      {"T1446", "Fetch or Obtain Alternate Network Communications", "Command and Control"},
    "certificate_pinning_bypass" =>
      {"T1446", "Fetch or Obtain Alternate Network Communications", "Command and Control"},
    "location_spoofing" => {"T1430", "Location Tracking", "Collection"},
    "geofence_breach" => {"T1430", "Location Tracking", "Collection"},
    "overlay_detected" => {"T1411", "Input Prompt", "Credential Access"},
    "phishing_sms_detected" => {"T1660", "Phishing", "Initial Access"},
    "phishing_url_blocked" => {"T1660", "Phishing", "Initial Access"},
    "debugger_detected" => {"T1622", "Debugger Evasion", "Defense Evasion"},
    "hook_framework_detected" => {"T1622", "Debugger Evasion", "Defense Evasion"},
    "emulator_detected" => {"T1622", "Debugger Evasion", "Defense Evasion"},
    "simulator_detected" => {"T1622", "Debugger Evasion", "Defense Evasion"},
    "tampering_detected" => {"T1398", "Modify OS Kernel or Boot Partition", "Defense Evasion"},
    "browser_tamper_detected" => {"T1622", "Debugger Evasion", "Defense Evasion"},
    "automation_detected" => {"T1622", "Debugger Evasion", "Defense Evasion"},
    "network_exfiltration_suspected" =>
      {"T1446", "Fetch or Obtain Alternate Network Communications", "Command and Control"},
    "commercial_spyware_suspected" => {"T1639", "Exfiltrate Data", "Collection"},
    "integrity_snapshot_changed" =>
      {"T1398", "Modify OS Kernel or Boot Partition", "Defense Evasion"},
    "behavior_anomaly_detected" => {"T1622", "Debugger Evasion", "Defense Evasion"}
  }

  # ============================================================================
  # Device Management
  # ============================================================================

  @doc """
  Lists all mobile devices for an organization.
  """
  def list_devices(organization_id, opts \\ []) do
    filters = Keyword.get(opts, :filters, %{})
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)

    query =
      Device
      |> Device.by_organization(organization_id)
      |> apply_device_filters(filters)
      |> limit(^limit)
      |> offset(^offset)
      |> order_by([d], desc: d.last_seen_at)

    {Repo.all(query), count_devices(organization_id, filters)}
  end

  defp apply_device_filters(query, filters) do
    query
    |> maybe_filter_platform(filters)
    |> maybe_filter_status(filters)
    |> maybe_filter_risk(filters)
    |> maybe_filter_mdm(filters)
  end

  defp maybe_filter_platform(query, %{"platform" => platform})
       when is_binary(platform) and platform != "" do
    Device.by_platform(query, platform)
  end

  defp maybe_filter_platform(query, _), do: query

  defp maybe_filter_status(query, %{"status" => status})
       when is_binary(status) and status != "" do
    Device.by_status(query, status)
  end

  defp maybe_filter_status(query, _), do: query

  defp maybe_filter_risk(query, %{"high_risk" => true}) do
    Device.high_risk(query)
  end

  defp maybe_filter_risk(query, _), do: query

  defp maybe_filter_mdm(query, %{"mdm_enrolled" => true}) do
    Device.mdm_enrolled(query)
  end

  defp maybe_filter_mdm(query, _), do: query

  defp count_devices(organization_id, filters) do
    Device
    |> Device.by_organization(organization_id)
    |> apply_device_filters(filters)
    |> Repo.aggregate(:count)
  end

  @doc """
  Gets a device by ID.
  """
  def get_device(id) do
    Repo.get(Device, id)
  end

  @doc """
  Gets a device by ID, raises if not found.
  """
  def get_device!(id) do
    Repo.get!(Device, id)
  end

  @doc """
  Gets a device by device_id within an organization.
  """
  def get_device_by_device_id(organization_id, device_id) do
    Device
    |> Device.by_organization(organization_id)
    |> where([d], d.device_id == ^device_id)
    |> Repo.one()
  end

  @doc """
  Registers a new mobile device from the agent.
  """
  def register_device(attrs) do
    attrs = normalize_registration_attrs(attrs)
    organization_id = attrs["organization_id"] || attrs[:organization_id]
    device_id = attrs["device_id"] || attrs[:device_id]

    device_result =
      case get_device_by_device_id(organization_id, device_id) do
        nil ->
          %Device{}
          |> Device.registration_changeset(attrs)
          |> Repo.insert()

        %Device{} = device ->
          update_device(device, attrs)
      end

    with {:ok, device} <- device_result,
         {:ok, _agent} <- upsert_mobile_agent(device) do
      {:ok, device}
    end
  end

  @doc """
  Updates a device.
  """
  def update_device(%Device{} = device, attrs) do
    device
    |> Device.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Updates device security posture.
  """
  def update_device_posture(%Device{} = device, attrs) do
    attrs = normalize_posture_attrs(attrs)

    with {:ok, updated_device} <-
           device
           |> Device.posture_changeset(attrs)
           |> Repo.update(),
         {:ok, _agent} <- upsert_mobile_agent(updated_device) do
      {:ok, updated_device}
    end
  end

  defp normalize_posture_attrs(attrs) when is_map(attrs) do
    security_checks = attrs["security_checks"] || attrs[:security_checks] || %{}
    now = utc_now()

    %{}
    |> maybe_put(
      "is_jailbroken",
      first_present(attrs, ["is_jailbroken", :is_jailbroken],
        fallback: first_present(security_checks, ["jailbroken", :jailbroken])
      )
    )
    |> maybe_put(
      "is_rooted",
      first_present(attrs, ["is_rooted", :is_rooted],
        fallback:
          first_present(security_checks, [
            "jailbroken_or_rooted",
            :jailbroken_or_rooted,
            "rooted",
            :rooted
          ])
      )
    )
    |> maybe_put(
      "passcode_enabled",
      first_present(attrs, ["passcode_enabled", :passcode_enabled],
        fallback:
          first_present(security_checks, [
            "passcode_enabled",
            :passcode_enabled,
            "passcode_set",
            :passcode_set
          ])
      )
    )
    |> maybe_put(
      "encryption_enabled",
      first_present(attrs, ["encryption_enabled", :encryption_enabled],
        fallback: first_present(security_checks, ["encryption_enabled", :encryption_enabled])
      )
    )
    |> maybe_put(
      "biometric_enabled",
      first_present(attrs, ["biometric_enabled", :biometric_enabled],
        fallback: first_present(security_checks, ["biometric_enabled", :biometric_enabled])
      )
    )
    |> maybe_put(
      "developer_mode_enabled",
      first_present(attrs, ["developer_mode_enabled", :developer_mode_enabled],
        fallback:
          first_present(security_checks, [
            "developer_mode",
            :developer_mode,
            "developer_mode_enabled",
            :developer_mode_enabled
          ])
      )
    )
    |> maybe_put(
      "usb_debugging_enabled",
      first_present(attrs, ["usb_debugging_enabled", :usb_debugging_enabled],
        fallback:
          first_present(security_checks, [
            "adb_enabled",
            :adb_enabled,
            "usb_debugging",
            :usb_debugging,
            "usb_debugging_enabled",
            :usb_debugging_enabled
          ])
      )
    )
    |> maybe_put(
      "last_seen_at",
      parse_mobile_timestamp(
        attrs["last_seen"] || attrs[:last_seen] || attrs["collected_at"] || attrs[:collected_at]
      ) || now
    )
  end

  defp normalize_posture_attrs(_attrs), do: %{"last_seen_at" => utc_now()}

  defp first_present(map, keys, opts \\ [])

  defp first_present(map, keys, opts) when is_map(map) do
    fallback = Keyword.get(opts, :fallback)

    Enum.reduce_while(keys, fallback, fn key, fallback ->
      case Map.fetch(map, key) do
        {:ok, value} when not is_nil(value) -> {:halt, value}
        _ -> {:cont, fallback}
      end
    end)
  end

  defp first_present(_map, _keys, opts), do: Keyword.get(opts, :fallback)

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp parse_mobile_timestamp(nil), do: nil

  defp parse_mobile_timestamp(%NaiveDateTime{} = value),
    do: NaiveDateTime.truncate(value, :second)

  defp parse_mobile_timestamp(%DateTime{} = value) do
    value
    |> DateTime.to_naive()
    |> NaiveDateTime.truncate(:second)
  end

  defp parse_mobile_timestamp(value) when is_binary(value) do
    trimmed = String.trim(value)

    with {:error, _} <- DateTime.from_iso8601(trimmed),
         {:error, _} <- NaiveDateTime.from_iso8601(String.replace_suffix(trimmed, "Z", "")) do
      nil
    else
      {:ok, %DateTime{} = datetime, _offset} -> parse_mobile_timestamp(datetime)
      {:ok, %NaiveDateTime{} = naive} -> parse_mobile_timestamp(naive)
    end
  end

  defp parse_mobile_timestamp(_value), do: nil

  defp utc_now do
    NaiveDateTime.utc_now()
    |> NaiveDateTime.truncate(:second)
  end

  defp normalize_registration_attrs(attrs) do
    now = utc_now()

    attrs
    |> Map.put("status", "active")
    |> Map.put("last_seen_at", now)
    |> Map.put_new("enrolled_at", now)
  end

  defp upsert_mobile_agent(%Device{} = device) do
    case get_mobile_agent(device.organization_id, device.device_id) do
      nil ->
        Agents.create_agent_for_org(device.organization_id, mobile_agent_attrs(device, %Agent{}))

      %Agent{} = agent ->
        Agents.update_agent(agent, mobile_agent_attrs(device, agent))
    end
  end

  @doc """
  Resolves the server Agent mirror id for a mobile device external id.
  """
  def agent_id_for_device(organization_id, device_id) do
    case get_mobile_agent(organization_id, device_id) do
      %Agent{id: agent_id} -> agent_id
      nil -> nil
    end
  end

  def agent_id_for_device(%Device{} = device) do
    agent_id_for_device(device.organization_id, device.device_id)
  end

  defp get_mobile_agent(organization_id, device_id) do
    Agent
    |> where([a], a.organization_id == ^organization_id and a.machine_id == ^device_id)
    |> Repo.one()
  end

  defp mobile_agent_attrs(%Device{} = device, %Agent{} = agent) do
    %{
      hostname: mobile_agent_hostname(device),
      ip_address: device.ip_address || agent.ip_address,
      os_type: device.platform,
      os_version: device.os_version,
      agent_version: device.agent_version,
      machine_id: device.device_id,
      status: "online",
      last_seen_at: device.last_seen_at || utc_now(),
      config: mobile_agent_config(device, agent.config || %{}),
      tags: merge_mobile_agent_tags(agent.tags || [], device)
    }
  end

  defp mobile_agent_hostname(%Device{} = device) do
    cond do
      is_binary(device.model) and device.model != "" ->
        device.model

      is_binary(device.manufacturer) and device.manufacturer != "" ->
        device.manufacturer

      true ->
        "mobile-" <> String.slice(device.device_id || device.id, 0, 12)
    end
  end

  defp mobile_agent_config(%Device{} = device, existing_config) do
    Map.merge(existing_config, %{
      "source" => "tamandua_mobile",
      "mobile_device_id" => device.id,
      "mobile_device_external_id" => device.device_id,
      "manufacturer" => device.manufacturer,
      "model" => device.model,
      "platform" => device.platform,
      "user_email" => device.user_email,
      "user_name" => device.user_name,
      "mdm_enrolled" => device.mdm_enrolled
    })
  end

  defp merge_mobile_agent_tags(existing_tags, %Device{} = device) do
    (existing_tags ++ ["mobile", "mobile_endpoint", device.platform])
    |> Enum.reject(&is_nil/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  @doc """
  Updates device from MDM sync.
  """
  def update_device_from_mdm(%Device{} = device, attrs) do
    device
    |> Device.mdm_sync_changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a device.
  """
  def delete_device(%Device{} = device) do
    Repo.delete(device)
  end

  @doc """
  Marks device as lost.
  """
  def mark_device_lost(%Device{} = device) do
    update_device(device, %{status: "lost"})
  end

  @doc """
  Marks device as wiped.
  """
  def mark_device_wiped(%Device{} = device) do
    update_device(device, %{status: "wiped"})
  end

  @doc """
  Updates device last seen timestamp.
  """
  def touch_device(%Device{} = device) do
    with {:ok, updated_device} <- update_device(device, %{last_seen_at: utc_now()}),
         {:ok, _agent} <- upsert_mobile_agent(updated_device) do
      {:ok, updated_device}
    end
  end

  @doc """
  Gets device statistics for an organization.
  """
  def get_device_stats(organization_id) do
    base_query = Device |> Device.by_organization(organization_id)

    %{
      total: Repo.aggregate(base_query, :count),
      ios: Repo.aggregate(Device.by_platform(base_query, "ios"), :count),
      android: Repo.aggregate(Device.by_platform(base_query, "android"), :count),
      active: Repo.aggregate(Device.by_status(base_query, "active"), :count),
      compromised: Repo.aggregate(Device.compromised(base_query), :count),
      high_risk: Repo.aggregate(Device.high_risk(base_query), :count),
      mdm_enrolled: Repo.aggregate(Device.mdm_enrolled(base_query), :count),
      stale_24h: Repo.aggregate(Device.stale(base_query, 24), :count)
    }
  end

  # ============================================================================
  # App Inventory
  # ============================================================================

  @doc """
  Lists apps for a device.
  """
  def list_device_apps(device_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 500)
    order_by = Keyword.get(opts, :order_by, :app_name)

    MobileApp
    |> MobileApp.by_device(device_id)
    |> limit(^limit)
    |> order_by([a], ^order_by)
    |> Repo.all()
  end

  @doc """
  Syncs app inventory for a device.
  Returns {:ok, {inserted, updated, deleted}} counts.
  """
  def sync_device_apps(device_id, apps_data) do
    # Get existing apps
    existing = list_device_apps(device_id, limit: 10000)
    existing_map = Map.new(existing, &{&1.bundle_id, &1})
    incoming_ids = MapSet.new(apps_data, & &1["bundle_id"])

    # Process updates and inserts
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

    # Find apps to delete (no longer installed)
    to_delete =
      Enum.filter(existing, fn app ->
        not MapSet.member?(incoming_ids, app.bundle_id)
      end)

    # Execute in transaction
    Repo.transaction(fn ->
      # Insert new apps
      inserted_count =
        Enum.count(inserts, fn changeset ->
          case Repo.insert(changeset) do
            {:ok, _} -> true
            {:error, _} -> false
          end
        end)

      # Update existing apps
      updated_count =
        Enum.count(updates, fn changeset ->
          case Repo.update(changeset) do
            {:ok, _} -> true
            {:error, _} -> false
          end
        end)

      # Delete removed apps
      deleted_count = Enum.count(to_delete)
      Enum.each(to_delete, &Repo.delete/1)

      {inserted_count, updated_count, deleted_count}
    end)
  end

  @doc """
  Gets high-risk apps for an organization.
  """
  def list_high_risk_apps(organization_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)

    MobileApp
    |> MobileApp.high_risk()
    |> join(:inner, [a], d in Device, on: a.device_id == d.id)
    |> where([a, d], d.organization_id == ^organization_id)
    |> limit(^limit)
    |> preload(:device)
    |> Repo.all()
  end

  @doc """
  Gets sideloaded apps for an organization.
  """
  def list_sideloaded_apps(organization_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)

    MobileApp
    |> MobileApp.sideloaded()
    |> join(:inner, [a], d in Device, on: a.device_id == d.id)
    |> where([a, d], d.organization_id == ^organization_id)
    |> limit(^limit)
    |> preload(:device)
    |> Repo.all()
  end

  # ============================================================================
  # App Guard Protected Apps
  # ============================================================================

  @doc """
  Lists protected App Guard apps for an organization.
  """
  def list_app_guard_protected_apps(organization_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    platform = Keyword.get(opts, :platform)

    AppGuardProtectedApp
    |> AppGuardProtectedApp.by_organization(organization_id)
    |> maybe_filter_app_guard_platform(platform)
    |> order_by([app], asc: app.display_name)
    |> limit(^limit)
    |> Repo.all()
  end

  @doc """
  Gets a protected App Guard app by app_id within an organization.
  """
  def get_app_guard_protected_app_by_app_id(organization_id, app_id) do
    AppGuardProtectedApp
    |> AppGuardProtectedApp.by_organization(organization_id)
    |> AppGuardProtectedApp.by_app_id(app_id)
    |> Repo.one()
  end

  @doc """
  Registers a protected App Guard app.
  """
  def create_app_guard_protected_app(attrs) do
    %AppGuardProtectedApp{}
    |> AppGuardProtectedApp.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Lists App Guard build manifests for an organization or one protected app.
  """
  def list_app_guard_build_manifests(organization_id, opts \\ []) do
    app_id = Keyword.get(opts, :app_id)
    limit = Keyword.get(opts, :limit, 100)

    AppGuardBuildManifest
    |> AppGuardBuildManifest.by_organization(organization_id)
    |> maybe_filter_app_guard_app_id(app_id)
    |> AppGuardBuildManifest.latest_first()
    |> limit(^limit)
    |> preload(:protected_app)
    |> Repo.all()
  end

  @doc """
  Stores a build manifest for a registered protected App Guard app.
  """
  def create_app_guard_build_manifest(attrs) do
    organization_id = attrs["organization_id"] || attrs[:organization_id]
    app_id = attrs["app_id"] || attrs[:app_id]

    case get_app_guard_protected_app_by_app_id(organization_id, app_id) do
      nil ->
        {:error, :protected_app_not_found}

      %AppGuardProtectedApp{} = app ->
        attrs =
          attrs
          |> put_app_guard_attr(:protected_app_id, app.id)
          |> put_app_guard_attr(:organization_id, app.organization_id)

        %AppGuardBuildManifest{}
        |> AppGuardBuildManifest.changeset(attrs)
        |> Repo.insert()
    end
  end

  @doc """
  Fetches one App Guard build manifest scoped to an organization.
  """
  def get_app_guard_build_manifest(organization_id, build_id) do
    AppGuardBuildManifest
    |> AppGuardBuildManifest.by_organization(organization_id)
    |> AppGuardBuildManifest.by_build_id(build_id)
    |> Repo.one()
  end

  @doc """
  Verifies client-computed build metadata against a stored App Guard build manifest.

  This is metadata-only: callers submit SHA256 values they computed locally. No
  APK/AAB/IPA bytes are accepted or stored.
  """
  def verify_app_guard_build_manifest(organization_id, build_id, params) do
    case get_app_guard_build_manifest(organization_id, build_id) do
      nil ->
        {:error, :build_manifest_not_found}

      %AppGuardBuildManifest{} = manifest ->
        checks =
          [
            {"artifact_sha256", get_in(manifest.artifact || %{}, ["sha256"])},
            {"certificate_sha256", get_in(manifest.signing || %{}, ["certificate_sha256"])},
            {"config_sha256", get_in(manifest.sdk || %{}, ["config_sha256"])}
          ]
          |> Enum.map(fn {key, expected} ->
            {key, compare_optional_sha256(params[key], expected)}
          end)

        provided = Enum.filter(checks, fn {_key, result} -> not is_nil(result) end)

        if provided == [] do
          {:error, :no_digests_provided}
        else
          {:ok,
           %{
             build_id: manifest.build_id,
             app_id: manifest.app_id,
             verified: Enum.all?(provided, fn {_key, result} -> result == true end),
             checks: Map.new(checks),
             claim_boundary: "metadata_only_no_binary_upload_or_fusion"
           }}
        end
    end
  end

  defp maybe_filter_app_guard_platform(query, nil), do: query
  defp maybe_filter_app_guard_platform(query, ""), do: query

  defp maybe_filter_app_guard_platform(query, platform) when is_binary(platform) do
    AppGuardProtectedApp.by_platform(query, platform |> String.trim() |> String.downcase())
  end

  defp maybe_filter_app_guard_app_id(query, nil), do: query
  defp maybe_filter_app_guard_app_id(query, ""), do: query

  defp maybe_filter_app_guard_app_id(query, app_id),
    do: AppGuardBuildManifest.by_app_id(query, app_id)

  defp compare_optional_sha256(nil, _expected), do: nil
  defp compare_optional_sha256("", _expected), do: nil

  defp compare_optional_sha256(value, expected) when is_binary(value) and is_binary(expected) do
    normalized = value |> String.trim() |> String.downcase()
    expected = String.downcase(expected)

    Regex.match?(~r/^[a-f0-9]{64}$/, normalized) and normalized == expected
  end

  defp compare_optional_sha256(_value, _expected), do: false

  @doc """
  Lists App Guard research programs for an organization.
  """
  def list_app_guard_research_programs(organization_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    status = Keyword.get(opts, :status)

    AppGuardResearchProgram
    |> AppGuardResearchProgram.by_organization(organization_id)
    |> maybe_filter_app_guard_research_status(status)
    |> AppGuardResearchProgram.latest_first()
    |> limit(^limit)
    |> Repo.all()
  end

  @doc """
  Gets one App Guard research program by program_id within an organization.
  """
  def get_app_guard_research_program_by_program_id(organization_id, program_id) do
    AppGuardResearchProgram
    |> AppGuardResearchProgram.by_organization(organization_id)
    |> AppGuardResearchProgram.by_program_id(program_id)
    |> Repo.one()
  end

  @doc """
  Creates an App Guard research program.
  """
  def create_app_guard_research_program(attrs) do
    %AppGuardResearchProgram{}
    |> AppGuardResearchProgram.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Lists App Guard research submissions for an organization.
  """
  def list_app_guard_research_submissions(organization_id, opts \\ []) do
    program_id = Keyword.get(opts, :program_id)
    status = Keyword.get(opts, :status)
    limit = Keyword.get(opts, :limit, 100)

    AppGuardResearchSubmission
    |> AppGuardResearchSubmission.by_organization(organization_id)
    |> maybe_filter_app_guard_submission_program(program_id)
    |> maybe_filter_app_guard_submission_status(status)
    |> AppGuardResearchSubmission.latest_first()
    |> limit(^limit)
    |> preload(:research_program)
    |> Repo.all()
  end

  @doc """
  Gets one App Guard research submission by submission_id within an organization.
  """
  def get_app_guard_research_submission_by_submission_id(organization_id, submission_id) do
    AppGuardResearchSubmission
    |> AppGuardResearchSubmission.by_organization(organization_id)
    |> AppGuardResearchSubmission.by_submission_id(submission_id)
    |> preload(:research_program)
    |> Repo.one()
  end

  @doc """
  Creates an App Guard research submission for a registered program.
  """
  def create_app_guard_research_submission(attrs) do
    organization_id = attrs["organization_id"] || attrs[:organization_id]
    program_id = attrs["program_id"] || attrs[:program_id]

    case get_app_guard_research_program_by_program_id(organization_id, program_id) do
      nil ->
        {:error, :research_program_not_found}

      %AppGuardResearchProgram{} = program ->
        attrs =
          attrs
          |> put_app_guard_attr(:research_program_id, program.id)
          |> put_app_guard_attr(:organization_id, program.organization_id)

        with :ok <- ensure_submission_researcher_scope(attrs, program),
             :ok <- ensure_submission_build_scope(attrs, program) do
          %AppGuardResearchSubmission{}
          |> AppGuardResearchSubmission.changeset(attrs)
          |> Repo.insert()
        end
    end
  end

  @doc """
  Updates reviewer validation for an App Guard research submission.
  """
  def validate_app_guard_research_submission(organization_id, submission_id, attrs) do
    case get_app_guard_research_submission_by_submission_id(organization_id, submission_id) do
      nil ->
        {:error, :research_submission_not_found}

      %AppGuardResearchSubmission{} = submission ->
        submission
        |> AppGuardResearchSubmission.validation_changeset(attrs)
        |> Repo.update()
    end
  end

  defp maybe_filter_app_guard_research_status(query, nil), do: query
  defp maybe_filter_app_guard_research_status(query, ""), do: query

  defp maybe_filter_app_guard_research_status(query, status) when is_binary(status) do
    from(program in query, where: program.status == ^status)
  end

  defp maybe_filter_app_guard_submission_program(query, nil), do: query
  defp maybe_filter_app_guard_submission_program(query, ""), do: query

  defp maybe_filter_app_guard_submission_program(query, program_id),
    do: AppGuardResearchSubmission.by_program_id(query, program_id)

  defp maybe_filter_app_guard_submission_status(query, nil), do: query
  defp maybe_filter_app_guard_submission_status(query, ""), do: query

  defp maybe_filter_app_guard_submission_status(query, status),
    do: AppGuardResearchSubmission.by_status(query, status)

  defp ensure_submission_researcher_scope(attrs, %AppGuardResearchProgram{
         visibility: "private",
         invited_researchers: invited_researchers
       }) do
    researcher_id = attrs["researcher_id"] || attrs[:researcher_id]

    if researcher_id in invited_researchers do
      :ok
    else
      {:error, :research_submission_researcher_not_invited}
    end
  end

  defp ensure_submission_researcher_scope(_attrs, _program), do: :ok

  defp ensure_submission_build_scope(attrs, program) do
    evidence_links = attrs["evidence_links"] || attrs[:evidence_links] || %{}

    build_ids =
      Map.get(evidence_links, "fixed_build_manifest_ids") ||
        Map.get(evidence_links, :fixed_build_manifest_ids) ||
        []

    scoped_build_ids = scoped_build_manifest_ids(program.scope)

    if MapSet.subset?(MapSet.new(build_ids), MapSet.new(scoped_build_ids)) do
      :ok
    else
      {:error, :research_submission_out_of_scope}
    end
  end

  defp scoped_build_manifest_ids(scope) when is_map(scope) do
    targets = Map.get(scope, "targets") || Map.get(scope, :targets) || []

    targets
    |> Enum.filter(fn target ->
      (Map.get(target, "target_type") || Map.get(target, :target_type)) == "build_manifest"
    end)
    |> Enum.map(fn target -> Map.get(target, "value") || Map.get(target, :value) end)
    |> Enum.reject(&is_nil/1)
  end

  defp scoped_build_manifest_ids(_), do: []

  defp put_app_guard_attr(attrs, key, value) do
    string_key = Atom.to_string(key)

    if Enum.any?(Map.keys(attrs), &is_binary/1) do
      Map.put(attrs, string_key, value)
    else
      Map.put(attrs, key, value)
    end
  end

  # ============================================================================
  # Event Management
  # ============================================================================

  @doc """
  Lists events for a device.
  """
  def list_device_events(device_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)
    severity = Keyword.get(opts, :severity)

    query =
      MobileEvent
      |> MobileEvent.by_device(device_id)
      |> MobileEvent.latest_first()
      |> limit(^limit)
      |> offset(^offset)
      |> preload(:device)

    query = if severity, do: MobileEvent.by_severity(query, severity), else: query

    Repo.all(query)
  end

  @doc """
  Lists events for an organization.
  """
  def list_organization_events(organization_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)
    hours = Keyword.get(opts, :hours, 24)

    MobileEvent
    |> MobileEvent.by_organization(organization_id)
    |> MobileEvent.recent(hours)
    |> MobileEvent.latest_first()
    |> limit(^limit)
    |> offset(^offset)
    |> preload(:device)
    |> Repo.all()
  end

  @doc """
  Ingests an event from the mobile agent.
  """
  def ingest_event(attrs) do
    %MobileEvent{}
    |> MobileEvent.ingest_changeset(attrs)
    |> Repo.insert()
    |> maybe_broadcast_event()
    |> maybe_create_alert()
  end

  @doc """
  Batch ingests events from mobile agent.
  """
  def ingest_events(events_data) do
    Enum.map(events_data, &ingest_event/1)
  end

  defp maybe_create_alert({:ok, event} = result) do
    if event.severity in ["high", "critical"] and not synthetic_mobile_validation_event?(event) do
      create_alert_from_mobile_event(event)
    end

    result
  end

  defp maybe_create_alert(error), do: error

  defp maybe_broadcast_event({:ok, %MobileEvent{} = event} = result) do
    broadcast_mobile_event(event)
    result
  end

  defp maybe_broadcast_event(result), do: result

  defp synthetic_mobile_validation_event?(%MobileEvent{} = event) do
    payload = app_guard_payload(event)
    evidence = app_guard_payload_evidence(payload)

    explicit_synthetic? =
      truthy?(payload["synthetic"]) or truthy?(payload["test_event"]) or
        truthy?(payload["validation_event"]) or truthy?(evidence["synthetic"]) or
        truthy?(evidence["test_event"])

    parity_markers = [
      event.rule_id,
      event.device_id,
      payload["event_id"],
      payload["parity_run_id"],
      payload["validation_run_id"],
      evidence["parity_run_id"],
      evidence["validation_run_id"],
      app_guard_get(payload, ["device", "device_id"]),
      app_guard_get(payload, ["device", "serial_number"]),
      app_guard_get(evidence, ["source"])
    ]

    explicit_synthetic? or Enum.any?(parity_markers, &parity_marker?/1)
  end

  defp truthy?(value) when value in [true, "true", "yes", "1", 1], do: true
  defp truthy?(_value), do: false

  defp parity_marker?(value) when is_binary(value) do
    normalized = String.downcase(value)

    String.starts_with?(normalized, "mobile-endpoint-parity-") or
      String.starts_with?(normalized, "agent-mobile-endpoint-parity-") or
      String.starts_with?(normalized, "parity-") or
      String.contains?(normalized, "_parity_") or
      String.contains?(normalized, "-parity-")
  end

  defp parity_marker?(_value), do: false

  defp broadcast_mobile_event(%MobileEvent{} = event) do
    payload = mobile_event_broadcast_payload(event)

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "mobile:events",
      {:mobile_event, payload}
    )

    if app_guard_event?(event) do
      Enum.each(["app_guard:event", "mobile:app_guard_event", "security:app_guard"], fn topic ->
        Phoenix.PubSub.broadcast(TamanduaServer.PubSub, topic, {:app_guard_event, payload})
      end)

      broadcast_app_guard_endpoint_event(event, payload)
    end

    try do
      TamanduaServer.Streaming.StreamManager.broadcast_event(payload)
    rescue
      _ -> :ok
    catch
      _, _ -> :ok
    end
  rescue
    error ->
      Logger.warning(
        "[Mobile] Failed to broadcast mobile event #{event.id}: #{Exception.message(error)}"
      )

      :ok
  end

  defp app_guard_event?(%MobileEvent{payload: %{"schema" => "tamandua.app_guard.event/v1"}}),
    do: true

  defp app_guard_event?(_event), do: false

  defp mobile_event_broadcast_payload(%MobileEvent{} = event) do
    base =
      event.payload || %{}

    Map.merge(base, %{
      "server_event_id" => event.id,
      "organization_id" => event.organization_id,
      "device_db_id" => event.device_id,
      "event_type" => event.event_type,
      "severity" => event.severity,
      "timestamp" => event.timestamp && NaiveDateTime.to_iso8601(event.timestamp),
      "title" => event.title,
      "description" => event.description,
      "app_bundle_id" => event.app_bundle_id,
      "app_name" => event.app_name,
      "domain" => event.domain
    })
  end

  defp broadcast_app_guard_endpoint_event(%MobileEvent{} = event, payload) do
    TamanduaServerWeb.Endpoint.broadcast("events:all", "app_guard:event", payload)
    TamanduaServerWeb.Endpoint.broadcast("events:#{event.device_id}", "app_guard:event", payload)
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  @doc """
  Creates an alert from a high/critical severity mobile event.

  Performs MITRE ATT&CK technique mapping, includes device metadata,
  calculates a mobile-specific risk score based on device compliance,
  and marks the event as alerted.
  """
  def create_alert_from_mobile_event(%MobileEvent{} = event) do
    device = get_device(event.device_id)
    agent_id = mobile_event_agent_id(event, device)
    {mitre_technique, mitre_name, mitre_tactic} = mitre_for_event(event.event_type)
    risk_score = calculate_mobile_risk_score(event, device)

    if is_nil(agent_id) do
      Logger.warning(
        "[Mobile] Skipping alert for event #{event.id}: mobile endpoint agent unavailable " <>
          "device=#{event.device_id}"
      )

      {:error, :mobile_agent_unavailable}
    else
      create_alert_from_mobile_event(
        event,
        device,
        agent_id,
        mitre_technique,
        mitre_name,
        mitre_tactic,
        risk_score
      )
    end
  end

  defp create_alert_from_mobile_event(
         event,
         device,
         agent_id,
         mitre_technique,
         mitre_name,
         mitre_tactic,
         risk_score
       ) do
    alert_attrs = %{
      severity: event.severity,
      title:
        "[#{alert_source_label(event)}] #{event.title || MobileEvent.event_type_description(event.event_type)}",
      description: build_alert_description(event, device),
      organization_id: event.organization_id,
      agent_id: agent_id,
      source_event_id: event.id,
      event_ids: [event.id],
      mitre_techniques: if(mitre_technique, do: [mitre_technique], else: []),
      mitre_tactics: if(mitre_tactic, do: [mitre_tactic], else: []),
      # calculate_mobile_risk_score returns a 0-100 value; canonical threat_score is 0.0-1.0
      threat_score: risk_score / 100,
      status: "new",
      evidence: build_mobile_evidence(event, device),
      recommended_response: recommended_mobile_response(event),
      detection_metadata: %{
        "source" => alert_source(event),
        "category" => app_guard_alert_category(event),
        "event_type" => event.event_type,
        "rule_id" => event.rule_id,
        "rule_name" => mobile_detection_rule_name(event),
        "detection_type" => mobile_detection_type(event),
        "rule_type" => alert_source(event),
        "type" => mobile_detection_type(event),
        "mitre_technique_name" => mitre_name,
        "policy_id" => app_guard_policy_metadata(event)["id"],
        "mode" => app_guard_policy_metadata(event)["mode"],
        "device_id" => event.device_id,
        "mobile_device_id" => device && device.device_id,
        "platform" => device && device.platform,
        "os_version" => device && device.os_version,
        "device_model" => device && device.model,
        "device_manufacturer" => device && device.manufacturer,
        "app_name" => event.app_name,
        "app_bundle_id" => event.app_bundle_id,
        "policy" => app_guard_policy_metadata(event),
        "decision" => app_guard_decision(event),
        "thresholds" => app_guard_policy_metadata(event)["thresholds"],
        "risk_score" => app_guard_policy_metadata(event)["score"],
        "risk_reasons" => app_guard_risk_reasons(event),
        "confidence" => app_guard_confidence(event),
        "claim_boundary" => app_guard_claim_boundary(event)
      },
      raw_event: %{
        "mobile_event_id" => event.id,
        "event_type" => event.event_type,
        "payload" => event.payload,
        "timestamp" => event.timestamp && NaiveDateTime.to_iso8601(event.timestamp)
      }
    }

    case TamanduaServer.Alerts.create_alert(alert_attrs) do
      {:ok, alert} ->
        # Mark the event as alerted and store the alert reference
        event
        |> Ecto.Changeset.change(%{alerted: true, alert_id: alert.id})
        |> Repo.update()

        Logger.info(
          "[Mobile] Alert created: id=#{alert.id} severity=#{event.severity} " <>
            "type=#{event.event_type} device=#{event.device_id}"
        )

        {:ok, alert}

      {:error, reason} ->
        Logger.error("[Mobile] Failed to create alert for event #{event.id}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp mobile_event_agent_id(%MobileEvent{} = event, %Device{} = device) do
    device_agent_id(device.organization_id, device.device_id) ||
      device_agent_id(event.organization_id, device.device_id) ||
      ensure_mobile_event_agent_id(device)
  end

  defp mobile_event_agent_id(%MobileEvent{} = event, _device) do
    case Repo.get(Device, event.device_id) do
      %Device{} = device -> mobile_event_agent_id(event, device)
      nil -> nil
    end
  end

  defp device_agent_id(nil, _device_id), do: nil
  defp device_agent_id(_organization_id, nil), do: nil

  defp device_agent_id(organization_id, device_id) do
    case get_mobile_agent(organization_id, device_id) do
      %Agent{id: agent_id} -> agent_id
      nil -> nil
    end
  end

  defp ensure_mobile_event_agent_id(%Device{} = device) do
    case upsert_mobile_agent(device) do
      {:ok, %Agent{id: agent_id}} -> agent_id
      _ -> nil
    end
  end

  # Returns {technique_id, technique_name, tactic} for a mobile event type,
  # or {nil, nil, nil} if no mapping exists.
  defp mitre_for_event(event_type) do
    case Map.get(@mobile_mitre_mappings, event_type) do
      {technique, name, tactic} -> {technique, name, tactic}
      nil -> {nil, nil, nil}
    end
  end

  defp alert_source(%MobileEvent{payload: %{"schema" => "tamandua.app_guard.event/v1"}}),
    do: "app_guard"

  defp alert_source(_event), do: "mobile_agent"

  defp alert_source_label(%MobileEvent{} = event) do
    case alert_source(event) do
      "app_guard" -> "App Guard"
      _ -> "Mobile"
    end
  end

  defp mobile_detection_rule_name(%MobileEvent{} = event) do
    case alert_source(event) do
      "app_guard" -> "App Guard #{event.event_type}"
      _ -> "Mobile #{event.event_type}"
    end
  end

  defp mobile_detection_type(%MobileEvent{} = event) do
    case alert_source(event) do
      "app_guard" -> "mobile_app_guard"
      _ -> "mobile_security_event"
    end
  end

  defp app_guard_alert_category(%MobileEvent{
         payload: %{"schema" => "tamandua.app_guard.event/v1"}
       }),
       do: "app_guard"

  defp app_guard_alert_category(_event), do: "mobile"

  defp app_guard_mitre_technique(event_type) do
    case mitre_for_event(event_type) do
      {technique, _name, _tactic} -> technique
      _ -> nil
    end
  end

  # Calculates a risk score (0.0 - 100.0) for a mobile event, factoring in
  # the event severity and the device's compliance posture.
  defp calculate_mobile_risk_score(event, device) do
    base_score =
      case event.severity do
        "critical" -> 80.0
        "high" -> 60.0
        "medium" -> 40.0
        "low" -> 20.0
        _ -> 10.0
      end

    compliance_modifier = device_compliance_modifier(device)
    min(100.0, base_score + compliance_modifier)
  end

  # Returns a score modifier (0-20) based on device compliance state.
  # Non-compliant or compromised devices push the risk score higher.
  defp device_compliance_modifier(nil), do: 5.0

  defp device_compliance_modifier(%Device{} = device) do
    modifier = 0.0

    modifier = if device.is_jailbroken or device.is_rooted, do: modifier + 10.0, else: modifier
    modifier = if device.mdm_compliance_status != "compliant", do: modifier + 5.0, else: modifier
    modifier = if device.passcode_enabled == false, do: modifier + 3.0, else: modifier
    modifier = if device.encryption_enabled == false, do: modifier + 2.0, else: modifier

    modifier
  end

  # Builds a human-readable alert description with device context.
  defp build_alert_description(event, device) do
    device_info =
      if device do
        "on #{device.platform || "unknown"} device #{device.device_id} " <>
          "(#{device.model || "unknown model"}, OS #{device.os_version || "unknown"})"
      else
        "on unknown device #{event.device_id}"
      end

    base = "Mobile security event detected #{device_info}."

    extra =
      case event.event_type do
        "jailbreak_detected" ->
          " The device has been jailbroken, bypassing OS security controls."

        "root_detected" ->
          " The device has been rooted, bypassing OS security controls."

        "suspicious_app_installed" ->
          " A suspicious application (#{event.app_name || event.app_bundle_id || "unknown"}) was installed."

        "malware_detected" ->
          " Malware was detected: #{event.app_name || "unknown"}."

        "malicious_dns_query" ->
          " A DNS query to a known malicious domain (#{event.domain || "unknown"}) was detected."

        "overlay_detected" ->
          " A screen overlay attack was detected, possibly capturing credentials."

        "location_spoofing" ->
          " GPS location spoofing was detected on the device."

        "man_in_the_middle" ->
          " A man-in-the-middle attack was detected on the network connection."

        "browser_tamper_detected" ->
          " A protected browser or WebView runtime was modified."

        "automation_detected" ->
          " Browser or app automation indicators were detected."

        "network_exfiltration_suspected" ->
          " Suspicious protected-app network egress was detected."

        "commercial_spyware_suspected" ->
          " Commercial spyware-like protected-app telemetry was detected. Treat this as a suspected triage signal, not family attribution."

        "integrity_snapshot_changed" ->
          " A protected app or WebView integrity snapshot changed."

        "behavior_anomaly_detected" ->
          " Protected-app behavior deviated from the expected interaction profile."

        _ ->
          ""
      end

    base <> extra
  end

  defp recommended_mobile_response(%MobileEvent{event_type: "commercial_spyware_suspected"}) do
    "Quarantine protected app session, collect mobile diagnostics, sync app inventory, review MDM posture, and escalate to mobile forensic workflow. Do not claim family attribution without external forensic evidence."
  end

  defp recommended_mobile_response(%MobileEvent{event_type: "network_exfiltration_suspected"}) do
    "Collect diagnostics, inspect protected-app network evidence, block suspicious domain if present, refresh DNS/network policy, and verify affected session."
  end

  defp recommended_mobile_response(%MobileEvent{event_type: event_type})
       when event_type in [
              "root_detected",
              "jailbreak_detected",
              "hook_framework_detected",
              "tampering_detected",
              "app_integrity_violation"
            ] do
    "Collect diagnostics, sync app inventory, require step-up authentication, and consider MDM lock or app/session containment based on business impact."
  end

  defp recommended_mobile_response(%MobileEvent{}) do
    "Collect diagnostics, review mobile posture and App Guard evidence, then apply MDM-safe response if risk is confirmed."
  end

  # Builds the structured evidence map for the alert.
  defp build_mobile_evidence(event, device) do
    app_guard_payload = app_guard_payload(event)
    app_guard_evidence = app_guard_payload_evidence(app_guard_payload)
    rule_name = mobile_detection_rule_name(event)
    detection_type = mobile_detection_type(event)

    evidence =
      %{
        "source" => alert_source(event),
        "event_type" => event.event_type,
        "detection" => %{
          "rule_id" => event.rule_id,
          "rule_name" => rule_name,
          "name" => rule_name,
          "detection_type" => detection_type,
          "rule_type" => alert_source(event),
          "category" => app_guard_alert_category(event),
          "event_type" => event.event_type,
          "severity" => event.severity,
          "mitre_attack_id" => app_guard_mitre_technique(event.event_type),
          "confidence" => app_guard_confidence(event) || app_guard_risk_score(app_guard_payload)
        },
        "device" => %{
          "device_id" => event.device_id,
          "mobile_device_id" => device && device.device_id,
          "platform" => device && device.platform,
          "model" => device && device.model,
          "manufacturer" => device && device.manufacturer,
          "os_version" => device && device.os_version,
          "serial_number" => device && device.serial_number,
          "mdm_enrolled" => device && device.mdm_enrolled,
          "mdm_provider" => device && device.mdm_provider,
          "mdm_device_id" => device && device.mdm_device_id,
          "mdm_compliance_status" => device && device.mdm_compliance_status,
          "risk_score" => device && device.risk_score,
          "is_jailbroken" => device && device.is_jailbroken,
          "is_rooted" => device && device.is_rooted
        }
      }
      |> put_if_present(
        "app_guard",
        app_guard_context(event, app_guard_payload, app_guard_evidence)
      )
      |> put_if_present("policy", app_guard_policy_metadata(event))
      |> put_if_present("decision_trace", app_guard_decision_trace(event, app_guard_payload))
      |> put_if_present("iocs", app_guard_iocs(event, app_guard_payload, app_guard_evidence))
      |> Map.put(
        "evidence_gaps",
        app_guard_evidence_gaps(event, app_guard_payload, app_guard_evidence)
      )
      |> put_if_present("risk", app_guard_payload["risk"])
      |> put_if_present("session", app_guard_payload["session"])
      |> put_if_present("active_signals", app_guard_payload["active_signals"])
      |> put_if_present("privacy_mode", app_guard_evidence["privacy_mode"])
      |> put_if_present("collector", app_guard_evidence["collector"])
      |> put_if_present("spyware_taxonomy", app_guard_evidence["spyware_taxonomy"])
      |> put_if_present("limitations", spyware_limitations(app_guard_evidence))
      |> put_if_present("claim_boundary", app_guard_claim_boundary(event))

    # Add app context if present
    evidence =
      if event.app_bundle_id || event.app_name do
        Map.put(evidence, "app", %{
          "bundle_id" => event.app_bundle_id,
          "package_or_bundle_id" => app_guard_package_or_bundle_id(event, app_guard_payload),
          "protected_app_id" => app_guard_protected_app_id(app_guard_payload),
          "name" => event.app_name,
          "version" => app_guard_get(app_guard_payload, ["app", "version"]),
          "url" => app_guard_url(app_guard_payload, app_guard_evidence),
          "domain" => app_guard_domain(event, app_guard_payload, app_guard_evidence)
        })
      else
        evidence
      end

    evidence =
      put_if_present(
        evidence,
        "evidence_snapshot",
        app_guard_evidence_snapshot(event, device, app_guard_payload, app_guard_evidence)
      )

    # Add network context if present
    evidence =
      if app_guard_domain(event, app_guard_payload, app_guard_evidence) ||
           app_guard_remote_address(event, app_guard_payload, app_guard_evidence) do
        Map.put(evidence, "network", %{
          "domain" => app_guard_domain(event, app_guard_payload, app_guard_evidence),
          "url" => app_guard_url(app_guard_payload, app_guard_evidence),
          "remote_address" =>
            app_guard_remote_address(event, app_guard_payload, app_guard_evidence),
          "remote_port" => app_guard_remote_port(event, app_guard_payload, app_guard_evidence)
        })
      else
        evidence
      end

    # Add location context if present
    evidence =
      if event.latitude || event.longitude do
        Map.put(evidence, "location", %{
          "latitude" => event.latitude,
          "longitude" => event.longitude
        })
      else
        evidence
      end

    evidence
  end

  defp app_guard_payload(%MobileEvent{payload: payload}) when is_map(payload), do: payload
  defp app_guard_payload(_event), do: %{}

  defp app_guard_payload_evidence(%{"evidence" => evidence}) when is_map(evidence), do: evidence
  defp app_guard_payload_evidence(_payload), do: %{}

  defp app_guard_evidence_snapshot(%MobileEvent{} = event, device, payload, evidence) do
    %{
      "schema" => "tamandua.app_guard.evidence_snapshot/v1",
      "event_id" => payload["event_id"],
      "event_type" => event.event_type,
      "policy_decision" => app_guard_decision_trace(event, payload),
      "thresholds" => app_guard_thresholds(event, payload),
      "signals" => app_guard_signal_list(event, payload, evidence),
      "device_identity" => app_guard_device_identity(event, device, payload),
      "app_identity" => app_guard_app_identity(event, payload, evidence),
      "integrity" => app_guard_integrity_snapshot(payload, evidence),
      "input_provenance" => app_guard_input_provenance(evidence),
      "network" => app_guard_network_snapshot(event, payload, evidence),
      "iocs" => app_guard_iocs(event, payload, evidence),
      "claim_boundary" => app_guard_claim_boundary(event)
    }
    |> compact_map()
  end

  defp app_guard_context(%MobileEvent{} = event, payload, evidence) do
    %{
      "schema" => payload["schema"],
      "event_id" => payload["event_id"],
      "event_type" => event.event_type,
      "protected_app" => app_guard_protected_app(event, payload),
      "url" => app_guard_url(payload, evidence),
      "domain" => app_guard_domain(event, payload, evidence),
      "policy" => app_guard_policy_metadata(event),
      "decision" => app_guard_decision_trace(event, payload),
      "runtime" => app_guard_runtime(payload, evidence),
      "input_provenance" => app_guard_input_provenance(evidence),
      "ingestion" => payload["server_ingestion"],
      "collector" => evidence["collector"],
      "privacy_mode" => evidence["privacy_mode"],
      "active_signals" => payload["active_signals"],
      "claim_boundary" => app_guard_claim_boundary(event)
    }
    |> compact_map()
  end

  defp app_guard_protected_app(%MobileEvent{} = event, payload) do
    app = app_guard_map(payload["app"] || payload["protected_app"])
    package_or_bundle_id = app_guard_package_or_bundle_id(event, payload)

    %{
      "id" => app_guard_protected_app_id(payload),
      "name" => event.app_name || app["name"],
      "bundle_id" => package_or_bundle_id,
      "package_or_bundle_id" => package_or_bundle_id,
      "package_name" => app["package_name"] || app["package"],
      "version" => app["version"] || app["version_name"],
      "build" => app["build"] || app["build_number"]
    }
    |> compact_map()
  end

  defp app_guard_runtime(payload, evidence) do
    runtime =
      app_guard_map(
        payload["runtime"] || evidence["runtime"] || evidence["browser"] || evidence["webview"]
      )

    %{
      "type" => runtime["type"] || evidence["runtime_type"] || evidence["collector"],
      "browser" => runtime["browser"] || evidence["browser_name"],
      "webview_provider" => runtime["webview_provider"] || evidence["webview_provider"],
      "integrity_state" => runtime["integrity_state"] || evidence["integrity_state"],
      "tamper_class" => runtime["tamper_class"] || evidence["tamper_class"]
    }
    |> compact_map()
  end

  defp app_guard_input_provenance(%{"input_provenance" => input_provenance})
       when is_map(input_provenance) do
    if input_provenance["schema"] == "tamandua.input_provenance.aggregate/v1" and
         input_provenance["platform"] == "android" and
         input_provenance["evidence_type"] == "metadata_only" and
         input_provenance["privacy_mode"] == "aggregate_no_content" and
         input_provenance["policy_mode"] == "observe_only" and
         input_provenance["external_claim_allowed"] == false do
      %{
        "schema" => input_provenance["schema"],
        "platform" => input_provenance["platform"],
        "collector" => input_provenance["collector"],
        "collector_state" => input_provenance["collector_state"],
        "evidence_type" => input_provenance["evidence_type"],
        "privacy_mode" => input_provenance["privacy_mode"],
        "policy_mode" => input_provenance["policy_mode"],
        "external_claim_allowed" => input_provenance["external_claim_allowed"],
        "workflow_class" => input_provenance["workflow_class"],
        "sample_count_bucket" => input_provenance["sample_count_bucket"],
        "source_classes_observed" => input_provenance["source_classes_observed"],
        "tool_types_observed" => input_provenance["tool_types_observed"],
        "assistive_technology_context" => input_provenance["assistive_technology_context"],
        "obscured" => input_provenance["obscured"],
        "cadence" => input_provenance["cadence"],
        "completeness" => input_provenance["completeness"],
        "claim_boundary" =>
          "Android aggregate input metadata only; observe-only context, not enforcement or device-wide EDR proof"
      }
      |> compact_map()
    end
  end

  defp app_guard_input_provenance(_evidence), do: nil

  defp app_guard_policy_metadata(%MobileEvent{} = event) do
    payload = app_guard_payload(event)
    risk = app_guard_map(payload["risk"])
    policy = app_guard_map(payload["policy"] || payload["app_guard_policy"])

    %{
      "name" => policy["name"] || policy["policy_name"],
      "id" => policy["id"] || policy["policy_id"] || payload["policy_id"] || risk["policy_id"],
      "mode" => policy["mode"] || policy["enforcement_mode"] || payload["mode"] || risk["mode"],
      "decision" => risk["decision"] || policy["decision"],
      "thresholds" => risk["thresholds"] || policy["thresholds"],
      "score" => risk["score"],
      "reasons" => risk["reasons"] || risk["reason"]
    }
    |> compact_map()
  end

  defp app_guard_decision_trace(%MobileEvent{} = event, payload) do
    risk = app_guard_map(payload["risk"])
    policy = app_guard_policy_metadata(event)

    %{
      "decision" => risk["decision"] || policy["decision"],
      "mode" => risk["mode"] || policy["mode"],
      "score" => risk["score"],
      "thresholds" => risk["thresholds"] || policy["thresholds"],
      "reasons" => risk["reasons"] || risk["reason"] || payload["active_signals"],
      "source" => "app_guard_sdk"
    }
    |> compact_map()
  end

  defp app_guard_decision(%MobileEvent{} = event) do
    event
    |> app_guard_payload()
    |> app_guard_get(["risk", "decision"])
  end

  defp app_guard_risk_reasons(%MobileEvent{} = event) do
    risk =
      event
      |> app_guard_payload()
      |> Map.get("risk", %{})
      |> app_guard_map()

    risk["reasons"] || risk["reason"]
  end

  defp app_guard_risk_score(payload) when is_map(payload),
    do: app_guard_get(payload, ["risk", "score"])

  defp app_guard_risk_score(_payload), do: nil

  defp app_guard_iocs(%MobileEvent{} = event, payload, evidence) do
    embedded_iocs =
      [payload["iocs"], evidence["iocs"], app_guard_get(evidence, ["network", "iocs"])]
      |> Enum.flat_map(&app_guard_ioc_list/1)

    (embedded_iocs ++
       [
         ioc("domain", app_guard_domain(event, payload, evidence)),
         ioc("ip", app_guard_remote_address(event, payload, evidence)),
         ioc("url", app_guard_url(payload, evidence)),
         ioc("package", app_guard_package_or_bundle_id(event, payload)),
         ioc("app", event.app_name || app_guard_get(payload, ["app", "name"]))
       ])
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq_by(&{&1["type"], &1["value"]})
  end

  defp ioc(_type, value) when value in [nil, "", []], do: nil
  defp ioc(type, value), do: %{"type" => type, "value" => value, "source" => "app_guard"}

  defp app_guard_ioc_list(values) when is_list(values) do
    values
    |> Enum.map(fn
      %{"type" => type, "value" => value} -> ioc(type, value)
      %{"kind" => type, "value" => value} -> ioc(type, value)
      %{"indicator_type" => type, "indicator" => value} -> ioc(type, value)
      value when is_binary(value) -> ioc("indicator", value)
      _ -> nil
    end)
  end

  defp app_guard_ioc_list(_values), do: []

  defp app_guard_evidence_gaps(%MobileEvent{} = event, payload, evidence) do
    iocs = app_guard_iocs(event, payload, evidence)
    policy = app_guard_policy_metadata(event)

    [
      evidence_gap(
        policy["id"],
        "policy_id_not_captured",
        "Policy ID was not present in the App Guard payload."
      ),
      evidence_gap(
        policy["mode"],
        "policy_mode_not_captured",
        "Policy enforcement mode was not present in the App Guard payload."
      ),
      evidence_gap(
        policy["thresholds"],
        "policy_thresholds_not_captured",
        "Policy or risk thresholds were not present in the App Guard payload."
      ),
      evidence_gap(
        app_guard_domain(event, payload, evidence) ||
          app_guard_remote_address(event, payload, evidence) || evidence["network"],
        "network_endpoint_not_captured",
        "No raw remote IP/domain was present in the App Guard event."
      ),
      evidence_gap(
        event.app_bundle_id || event.app_name || payload["app"],
        "protected_app_not_identified",
        "Protected app name/package was not present in the App Guard event."
      ),
      evidence_gap(
        evidence["runtime"] || evidence["browser"] || evidence["webview"] ||
          evidence["collector"],
        "runtime_detail_not_captured",
        "Browser/WebView runtime details were not present in the App Guard evidence."
      ),
      evidence_gap(
        payload["risk"],
        "decision_trace_not_captured",
        "Risk decision, score or reasons were not present in the App Guard payload."
      ),
      evidence_gap(
        iocs,
        "iocs_not_extracted",
        "No domain, URL, IP, package or app IOC was present in the App Guard event."
      )
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp app_guard_protected_app_id(payload) when is_map(payload) do
    app_guard_get(payload, ["app", "app_id"]) ||
      app_guard_get(payload, ["protected_app", "app_id"]) ||
      payload["app_id"]
  end

  defp app_guard_package_or_bundle_id(%MobileEvent{} = event, payload) do
    event.app_bundle_id || app_guard_get(payload, ["app", "package_or_bundle_id"]) ||
      app_guard_get(payload, ["app", "bundle_id"]) ||
      app_guard_get(payload, ["app", "package_name"]) ||
      app_guard_get(payload, ["protected_app", "package_or_bundle_id"]) ||
      app_guard_get(payload, ["protected_app", "bundle_id"])
  end

  defp app_guard_thresholds(%MobileEvent{} = event, payload) do
    risk = app_guard_map(payload["risk"])
    policy = app_guard_map(payload["policy"])
    policy_metadata = app_guard_policy_metadata(event)

    risk["thresholds"] || policy["thresholds"] || policy_metadata["thresholds"] ||
      payload["thresholds"] ||
      app_guard_get(payload, ["policy", "thresholds"])
  end

  defp app_guard_signal_list(%MobileEvent{} = event, payload, evidence) do
    risk = app_guard_map(payload["risk"])

    [
      payload["active_signals"],
      payload["signals"],
      risk["reasons"],
      evidence["signals"],
      evidence["detected_signals"],
      event.event_type
    ]
    |> Enum.flat_map(&List.wrap/1)
    |> Enum.map(&app_guard_signal_name/1)
    |> Enum.reject(&(&1 in [nil, ""]))
    |> Enum.uniq()
  end

  defp app_guard_signal_name(%{"name" => name}), do: name
  defp app_guard_signal_name(%{"signal" => signal}), do: signal
  defp app_guard_signal_name(value) when is_binary(value), do: value
  defp app_guard_signal_name(value) when is_atom(value), do: Atom.to_string(value)
  defp app_guard_signal_name(_value), do: nil

  defp app_guard_device_identity(%MobileEvent{} = event, device, payload) do
    payload_device = app_guard_map(payload["device"])

    %{
      "device_id" => payload_device["device_id"] || (device && device.device_id),
      "mobile_event_device_id" => event.device_id,
      "platform" => payload["platform"] || (device && device.platform),
      "model" => payload_device["model"] || (device && device.model),
      "manufacturer" => payload_device["manufacturer"] || (device && device.manufacturer),
      "os_version" => payload_device["os_version"] || (device && device.os_version),
      "serial_number" => payload_device["serial_number"] || (device && device.serial_number),
      "managed" => payload_device["managed"] || (device && device.mdm_enrolled),
      "mdm_provider" => payload_device["mdm_provider"] || (device && device.mdm_provider),
      "mdm_compliance_status" => device && device.mdm_compliance_status
    }
    |> compact_map()
  end

  defp app_guard_app_identity(%MobileEvent{} = event, payload, evidence) do
    app = app_guard_map(payload["app"] || payload["protected_app"])

    %{
      "app_id" => app_guard_protected_app_id(payload),
      "name" => event.app_name || app["display_name"] || app["name"],
      "package_or_bundle_id" => app_guard_package_or_bundle_id(event, payload),
      "version" => app["version"] || app["version_name"],
      "build" => app["build"] || app["build_number"],
      "domain" => app_guard_domain(event, payload, evidence),
      "url" => app_guard_url(payload, evidence)
    }
    |> compact_map()
  end

  defp app_guard_integrity_snapshot(payload, evidence) do
    runtime = app_guard_runtime(payload, evidence)

    integrity =
      app_guard_map(
        payload["integrity"] || evidence["integrity"] || evidence["integrity_snapshot"]
      )

    %{
      "state" =>
        integrity["state"] || integrity["status"] || runtime["integrity_state"] ||
          evidence["integrity_state"],
      "tamper_class" =>
        integrity["tamper_class"] || runtime["tamper_class"] || evidence["tamper_class"],
      "verdict" => integrity["verdict"] || evidence["integrity_verdict"],
      "build_id" =>
        integrity["build_id"] || payload["build_id"] ||
          app_guard_get(payload, ["app", "build_id"]),
      "artifact_sha256" => integrity["artifact_sha256"],
      "certificate_sha256" => integrity["certificate_sha256"],
      "config_sha256" => integrity["config_sha256"],
      "runtime" => runtime
    }
    |> compact_map()
  end

  defp app_guard_network_snapshot(%MobileEvent{} = event, payload, evidence) do
    %{
      "domain" => app_guard_domain(event, payload, evidence),
      "url" => app_guard_url(payload, evidence),
      "remote_address" => app_guard_remote_address(event, payload, evidence),
      "remote_port" => app_guard_remote_port(event, payload, evidence),
      "protocol" =>
        app_guard_get(payload, ["network", "protocol"]) ||
          app_guard_get(evidence, ["network", "protocol"]) ||
          evidence["protocol"]
    }
    |> compact_map()
  end

  defp app_guard_domain(%MobileEvent{} = event, payload, evidence) do
    event.domain || evidence["domain"] || app_guard_get(evidence, ["network", "domain"]) ||
      app_guard_get(payload, ["network", "domain"]) || payload["domain"] ||
      evidence["host"] || evidence["hostname"] || app_guard_get(evidence, ["network", "host"]) ||
      app_guard_get(evidence, ["network", "hostname"]) ||
      app_guard_get(payload, ["network", "host"]) ||
      app_guard_get(payload, ["network", "hostname"]) || payload["host"] || payload["hostname"]
  end

  defp app_guard_remote_address(%MobileEvent{} = event, payload, evidence) do
    event.remote_address ||
      app_guard_get(payload, ["network", "remote_address"]) ||
      app_guard_get(payload, ["network", "remote_ip"]) ||
      app_guard_get(payload, ["network", "destination_ip"]) ||
      app_guard_get(payload, ["network", "dst_ip"]) ||
      app_guard_get(evidence, ["network", "remote_address"]) ||
      app_guard_get(evidence, ["network", "remote_ip"]) ||
      app_guard_get(evidence, ["network", "destination_ip"]) ||
      app_guard_get(evidence, ["network", "dst_ip"]) ||
      evidence["remote_address"] ||
      evidence["remote_ip"] ||
      evidence["destination_ip"] ||
      evidence["dst_ip"]
  end

  defp app_guard_remote_port(%MobileEvent{} = event, payload, evidence) do
    event.remote_port ||
      app_guard_get(payload, ["network", "remote_port"]) ||
      app_guard_get(payload, ["network", "destination_port"]) ||
      app_guard_get(payload, ["network", "dst_port"]) ||
      app_guard_get(payload, ["network", "port"]) ||
      app_guard_get(evidence, ["network", "remote_port"]) ||
      app_guard_get(evidence, ["network", "destination_port"]) ||
      app_guard_get(evidence, ["network", "dst_port"]) ||
      app_guard_get(evidence, ["network", "port"]) ||
      evidence["remote_port"] ||
      evidence["destination_port"] ||
      evidence["dst_port"] ||
      evidence["port"]
  end

  defp app_guard_url(payload, evidence) do
    evidence["url"] || app_guard_get(evidence, ["network", "url"]) || payload["url"] ||
      app_guard_get(payload, ["network", "url"])
  end

  defp evidence_gap(value, code, message) do
    if empty_evidence_value?(value) do
      %{"code" => code, "message" => message}
    else
      nil
    end
  end

  defp empty_evidence_value?(value), do: value in [nil, "", []] or value == %{}

  defp app_guard_map(value) when is_map(value), do: value
  defp app_guard_map(_value), do: %{}

  defp app_guard_get(value, path) when is_list(path) do
    Enum.reduce_while(path, value, fn key, current ->
      case current do
        map when is_map(map) -> {:cont, Map.get(map, key)}
        _ -> {:halt, nil}
      end
    end)
  end

  defp compact_map(map) when is_map(map) do
    map
    |> Enum.reject(fn {_key, value} -> value in [nil, "", [], %{}] end)
    |> Map.new()
  end

  defp compact_map(_), do: %{}

  defp spyware_limitations(%{"spyware_taxonomy" => %{"limitations" => limitations}})
       when is_list(limitations),
       do: limitations

  defp spyware_limitations(_evidence), do: nil

  defp app_guard_confidence(%MobileEvent{} = event) do
    event
    |> app_guard_payload()
    |> app_guard_payload_evidence()
    |> app_guard_get(["spyware_taxonomy", "confidence"])
  end

  defp app_guard_claim_boundary(%MobileEvent{event_type: "commercial_spyware_suspected"}) do
    "metadata-only protected-app triage signal; not device-wide forensic evidence or spyware family attribution"
  end

  defp app_guard_claim_boundary(%MobileEvent{
         payload: %{"schema" => "tamandua.app_guard.event/v1"}
       }) do
    "protected-app App Guard telemetry; not full mobile EDR device-wide visibility"
  end

  defp app_guard_claim_boundary(_event), do: nil

  defp put_if_present(map, _key, value) when value in [nil, "", []], do: map
  defp put_if_present(map, key, value), do: Map.put(map, key, value)

  @doc """
  Gets event statistics for an organization.
  """
  def get_event_stats(organization_id, hours \\ 24) do
    base_query =
      MobileEvent
      |> MobileEvent.by_organization(organization_id)
      |> MobileEvent.recent(hours)

    # Count by severity
    severity_counts =
      base_query
      |> group_by([e], e.severity)
      |> select([e], {e.severity, count(e.id)})
      |> Repo.all()
      |> Map.new()

    # Count by event type (top 10)
    type_counts =
      base_query
      |> group_by([e], e.event_type)
      |> select([e], {e.event_type, count(e.id)})
      |> order_by([e], desc: count(e.id))
      |> limit(10)
      |> Repo.all()

    %{
      total: Repo.aggregate(base_query, :count),
      by_severity: severity_counts,
      by_type: type_counts,
      critical: Map.get(severity_counts, "critical", 0),
      high: Map.get(severity_counts, "high", 0)
    }
  end

  # ============================================================================
  # Security Posture
  # ============================================================================

  @doc """
  Gets overall mobile security posture for an organization.
  """
  def get_security_posture(organization_id) do
    device_stats = get_device_stats(organization_id)
    event_stats = get_event_stats(organization_id, 24)

    # Calculate posture score (0-100, higher is better)
    posture_score = calculate_posture_score(device_stats, event_stats)

    %{
      score: posture_score,
      devices: device_stats,
      events_24h: event_stats,
      risks: identify_risks(device_stats, event_stats),
      recommendations: generate_recommendations(device_stats, event_stats)
    }
  end

  defp calculate_posture_score(device_stats, event_stats) do
    score = 100

    # Deduct for compromised devices
    score = score - device_stats.compromised * 20

    # Deduct for high-risk devices
    score = score - device_stats.high_risk * 5

    # Deduct for critical events
    score = score - event_stats.critical * 10

    # Deduct for high events
    score = score - event_stats.high * 3

    # Deduct for stale devices
    stale_percentage =
      if device_stats.total > 0 do
        device_stats.stale_24h / device_stats.total * 100
      else
        0
      end

    score = score - trunc(stale_percentage / 5)

    max(0, min(100, score))
  end

  defp identify_risks(device_stats, event_stats) do
    risks = []

    risks =
      if device_stats.compromised > 0 do
        [
          %{
            level: "critical",
            type: "compromised_devices",
            count: device_stats.compromised,
            message: "#{device_stats.compromised} device(s) are jailbroken or rooted"
          }
          | risks
        ]
      else
        risks
      end

    risks =
      if device_stats.high_risk > 0 do
        [
          %{
            level: "high",
            type: "high_risk_devices",
            count: device_stats.high_risk,
            message: "#{device_stats.high_risk} device(s) have high risk scores"
          }
          | risks
        ]
      else
        risks
      end

    risks =
      if event_stats.critical > 0 do
        [
          %{
            level: "critical",
            type: "critical_events",
            count: event_stats.critical,
            message: "#{event_stats.critical} critical security event(s) in last 24h"
          }
          | risks
        ]
      else
        risks
      end

    risks
  end

  defp generate_recommendations(device_stats, _event_stats) do
    recommendations = []

    recommendations =
      if device_stats.compromised > 0 do
        [
          %{
            priority: "critical",
            action: "wipe_compromised",
            message: "Wipe or retire compromised devices immediately"
          }
          | recommendations
        ]
      else
        recommendations
      end

    recommendations =
      if device_stats.mdm_enrolled < device_stats.total do
        unenrolled = device_stats.total - device_stats.mdm_enrolled

        [
          %{
            priority: "medium",
            action: "enroll_mdm",
            message: "Enroll #{unenrolled} device(s) in MDM for better management"
          }
          | recommendations
        ]
      else
        recommendations
      end

    recommendations
  end
end
