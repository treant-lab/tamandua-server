defmodule TamanduaServer.Mobile do
  @moduledoc """
  Context module for mobile device management.

  Provides functions for managing mobile devices, processing events,
  and coordinating with MDM integrations.
  """

  import Ecto.Query
  require Logger

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

  defp maybe_filter_platform(query, %{"platform" => platform}) when platform != "" do
    Device.by_platform(query, platform)
  end

  defp maybe_filter_platform(query, _), do: query

  defp maybe_filter_status(query, %{"status" => status}) when status != "" do
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
    %Device{}
    |> Device.registration_changeset(attrs)
    |> Repo.insert()
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
    device
    |> Device.posture_changeset(attrs)
    |> Repo.update()
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
    update_device(device, %{last_seen_at: NaiveDateTime.utc_now()})
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
    now = NaiveDateTime.utc_now()

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

  defp maybe_filter_app_guard_platform(query, nil), do: query
  defp maybe_filter_app_guard_platform(query, ""), do: query

  defp maybe_filter_app_guard_platform(query, platform) when is_binary(platform) do
    AppGuardProtectedApp.by_platform(query, platform |> String.trim() |> String.downcase())
  end

  defp maybe_filter_app_guard_app_id(query, nil), do: query
  defp maybe_filter_app_guard_app_id(query, ""), do: query

  defp maybe_filter_app_guard_app_id(query, app_id),
    do: AppGuardBuildManifest.by_app_id(query, app_id)

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
    if event.severity in ["high", "critical"] do
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
    {mitre_technique, mitre_name, mitre_tactic} = mitre_for_event(event.event_type)
    risk_score = calculate_mobile_risk_score(event, device)

    alert_attrs = %{
      severity: event.severity,
      title:
        "[#{alert_source_label(event)}] #{event.title || MobileEvent.event_type_description(event.event_type)}",
      description: build_alert_description(event, device),
      organization_id: event.organization_id,
      mitre_techniques: if(mitre_technique, do: [mitre_technique], else: []),
      mitre_tactics: if(mitre_tactic, do: [mitre_tactic], else: []),
      # calculate_mobile_risk_score returns a 0-100 value; canonical threat_score is 0.0-1.0
      threat_score: risk_score / 100,
      status: "new",
      evidence: build_mobile_evidence(event, device),
      detection_metadata: %{
        "source" => alert_source(event),
        "event_type" => event.event_type,
        "mitre_technique_name" => mitre_name,
        "device_id" => event.device_id,
        "platform" => device && device.platform,
        "os_version" => device && device.os_version,
        "app_name" => event.app_name,
        "app_bundle_id" => event.app_bundle_id
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

        "integrity_snapshot_changed" ->
          " A protected app or WebView integrity snapshot changed."

        "behavior_anomaly_detected" ->
          " Protected-app behavior deviated from the expected interaction profile."

        _ ->
          ""
      end

    base <> extra
  end

  # Builds the structured evidence map for the alert.
  defp build_mobile_evidence(event, device) do
    evidence = %{
      "source" => alert_source(event),
      "event_type" => event.event_type,
      "device" => %{
        "device_id" => event.device_id,
        "platform" => device && device.platform,
        "model" => device && device.model,
        "os_version" => device && device.os_version,
        "mdm_enrolled" => device && device.mdm_enrolled,
        "mdm_compliance_status" => device && device.mdm_compliance_status,
        "risk_score" => device && device.risk_score,
        "is_jailbroken" => device && device.is_jailbroken,
        "is_rooted" => device && device.is_rooted
      }
    }

    # Add app context if present
    evidence =
      if event.app_bundle_id || event.app_name do
        Map.put(evidence, "app", %{
          "bundle_id" => event.app_bundle_id,
          "name" => event.app_name
        })
      else
        evidence
      end

    # Add network context if present
    evidence =
      if event.domain || event.remote_address do
        Map.put(evidence, "network", %{
          "domain" => event.domain,
          "remote_address" => event.remote_address,
          "remote_port" => event.remote_port
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
