defmodule TamanduaServerWeb.API.V1.MobileController do
  @moduledoc """
  API controller for mobile device management.

  Provides endpoints for:
  - Device registration and management
  - App inventory
  - Event ingestion
  - Security posture
  - Response actions
  - MDM integration

  Boundary: this controller supports mobile companion workflows, endpoint
  enrollment/posture mirroring, MDM actions, and App Guard ingestion. It does not
  claim full phone-wide EDR telemetry until native iOS/Android sensor evidence
  and signed release validation exist.
  """

  use TamanduaServerWeb, :controller

  import Ecto.Query

  alias TamanduaServer.Mobile
  alias TamanduaServer.Mobile.Device
  alias TamanduaServer.Mobile.MDMProvider
  alias TamanduaServer.Mobile.AppGuardReplayGuard
  alias TamanduaServer.Mobile.DeviceRegistry
  alias TamanduaServer.Mobile.MobileDeviceIdentity
  alias TamanduaServer.Mobile.MobileMutationProof
  alias TamanduaServer.Mobile.ThreatDetection
  alias TamanduaServer.Mobile.AppInventory
  alias TamanduaServer.Agents
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Authorization.RBAC

  # V2 schemas for the new mobile_devices_v2 / mdm_commands tables
  alias TamanduaServer.Mobile.DeviceV2
  alias TamanduaServer.Mobile.MDMCommand
  alias TamanduaServer.LiveResponse.{EvidenceSessions, ScreenCaptureArtifacts}
  alias TamanduaServer.Repo

  require Logger

  action_fallback(TamanduaServerWeb.FallbackController)

  # Every mobile endpoint operates on tenant-scoped data. Resolve the
  # caller's organization once, up front, and reject requests without an
  # organization context with a 403 instead of letting downstream code
  # crash with a 500 (previously `get_organization_id/1` raised).
  plug(:require_organization)

  @app_guard_event_types ~w(
    root_detected
    jailbreak_detected
    debugger_detected
    frida_detected
    hook_framework_detected
    native_hook_detected
    emulator_detected
    simulator_detected
    app_integrity_violation
    tampering_detected
    runtime_memory_tamper_detected
    code_signature_drift_detected
    certificate_pinning_bypass
    man_in_the_middle
    suspicious_proxy_detected
    overlay_detected
    shielding_interference_suspected
    browser_tamper_detected
    webview_bridge_risk_detected
    webview_ssl_error_bypass
    automation_detected
    network_exfiltration_suspected
    commercial_spyware_suspected
    spyware_indicator_match
    integrity_snapshot_changed
    behavior_anomaly_detected
    policy_decision
  )
  @app_guard_platforms ~w(android ios)
  @app_guard_severities ~w(low medium high critical)
  @app_guard_decisions ~w(allow observe warn step_up block kill_session)
  @legacy_identity_compatibility %{
    assurance: "unverified",
    mode: "legacy_unbound",
    proof_state: "not_provided"
  }
  @verified_mutation_identity %{
    assurance: "server_verified_pop",
    mode: "fresh_mutation_authorization",
    proof_state: "verified"
  }
  @mutation_authorization_fields ~w(authorization_id challenge_id nonce signature)
  @mobile_v2_mutation_operation "mobile_device_v2_upsert"
  @mobile_v2_mutation_method "POST"
  @mobile_v2_mutation_route "mobile_v2_devices_upsert"

  # ============================================================================
  # Device Management
  # ============================================================================

  @doc """
  GET /api/v1/mobile/agents/:agent_id/overview

  Resolves the mobile device linked to an endpoint agent and returns a compact
  posture/inventory/App Guard overview for web UI detail panels.
  """
  def agent_overview(conn, %{"agent_id" => agent_id}) do
    organization_id = get_organization_id(conn)

    case get_agent_for_org(organization_id, agent_id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "Agent not found"})

      %Agent{} = agent ->
        device = mobile_device_for_agent(organization_id, agent)

        json(conn, %{
          data: mobile_agent_overview_payload(agent, device)
        })
    end
  end

  @doc """
  GET /api/v1/mobile/devices

  Lists mobile devices for the current organization.

  Query params:
    - platform: ios|android
    - status: active|lost|wiped|retired|pending
    - high_risk: true/false
    - mdm_enrolled: true/false
    - limit: number (default 100)
    - offset: number (default 0)
  """
  def index(conn, params) do
    organization_id = get_organization_id(conn)

    filters = %{
      "platform" => params["platform"],
      "status" => params["status"],
      "high_risk" => params["high_risk"] == "true",
      "mdm_enrolled" => params["mdm_enrolled"] == "true"
    }

    opts = [
      filters: filters,
      limit: parse_int(params["limit"], 100),
      offset: parse_int(params["offset"], 0)
    ]

    {devices, total} = Mobile.list_devices(organization_id, opts)

    json(conn, %{
      data: Enum.map(devices, &serialize_device/1),
      meta: %{
        total: total,
        limit: opts[:limit],
        offset: opts[:offset]
      }
    })
  end

  @doc """
  GET /api/v1/mobile/devices/:id

  Gets a specific mobile device.
  """
  def show(conn, %{"id" => id}) do
    with_legacy_device_for_org(conn, id, fn device ->
      json(conn, %{data: serialize_device_detail(device)})
    end)
  end

  @doc """
  POST /api/v1/mobile/devices/register

  Registers a new mobile device from the agent.

  Body:
    {
      "device_id": "unique-device-uuid",
      "platform": "ios|android",
      "model": "iPhone 14 Pro",
      "os_version": "17.0",
      "agent_version": "1.0.0"
    }
  """
  def register(conn, params) do
    organization_id = get_organization_id(conn)
    attrs = Map.put(params, "organization_id", organization_id)

    case legacy_identity_mutation(organization_id, [params["device_id"]], fn ->
           Mobile.register_device(attrs)
         end) do
      {:ok, device} ->
        conn
        |> put_status(:created)
        |> json(%{
          data: serialize_device(device),
          device_identity: @legacy_identity_compatibility,
          message: "Device enrolled successfully."
        })

      {:error, :device_identity_proof_required} ->
        device_identity_proof_required(conn)

      {:error, {:app_guard_device_graph_sync_failed, _reason}} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{
          error: %{
            code: "app_guard_device_graph_sync_failed",
            message:
              "App Guard event was not ingested because the mobile DeviceV2/Agent graph could not be synchronized"
          }
        })

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  PUT /api/v1/mobile/devices/:id

  Updates a mobile device.
  """
  def update(conn, %{"id" => id} = params) do
    with_legacy_device_for_org(conn, id, fn device ->
      organization_id = get_organization_id(conn)
      attrs = Map.put(params, "organization_id", organization_id)

      case legacy_identity_mutation(
             organization_id,
             [device.device_id, attrs["device_id"]],
             fn -> Mobile.update_device(device, attrs) end
           ) do
        {:ok, updated_device} ->
          json(conn, %{
            data: serialize_device(updated_device),
            device_identity: @legacy_identity_compatibility
          })

        {:error, :device_identity_proof_required} ->
          device_identity_proof_required(conn)

        {:error, changeset} ->
          {:error, changeset}
      end
    end)
  end

  @doc """
  DELETE /api/v1/mobile/devices/:id

  Removes a mobile device from management.
  """
  def delete(conn, %{"id" => id}) do
    with_legacy_device_for_org(conn, id, fn device ->
      case Mobile.delete_device(device) do
        {:ok, _} ->
          send_resp(conn, :no_content, "")

        {:error, changeset} ->
          {:error, changeset}
      end
    end)
  end

  @doc """
  GET /api/v1/mobile/devices/:id/posture

  Gets the security posture for a specific device.
  """
  def device_posture(conn, %{"id" => id}) do
    with_legacy_device_for_org(conn, id, fn device ->
      posture = %{
        id: device.id,
        device_id: device.device_id,
        external_device_id: device.device_id,
        platform: device.platform,
        risk_score: device.risk_score,
        risk_factors: device.risk_factors,
        security_checks: %{
          jailbroken_or_rooted: device.is_jailbroken or device.is_rooted,
          passcode_enabled: device.passcode_enabled,
          encryption_enabled: device.encryption_enabled,
          biometric_enabled: device.biometric_enabled,
          developer_mode: device.developer_mode_enabled,
          usb_debugging: device.usb_debugging_enabled,
          mdm_enrolled: device.mdm_enrolled,
          mdm_compliant: device.mdm_compliance_status == "compliant"
        },
        last_assessment: device.last_seen_at || device.updated_at
      }

      json(conn, %{data: posture})
    end)
  end

  @doc """
  POST /api/v1/mobile/devices/:id/posture

  Updates security posture from agent telemetry.
  """
  def update_posture(conn, %{"id" => id} = params) do
    with_legacy_device_for_org(conn, id, fn device ->
      case Mobile.update_device_posture(device, params) do
        {:ok, updated_device} ->
          json(conn, %{
            data: %{
              risk_score: updated_device.risk_score,
              risk_factors: updated_device.risk_factors
            }
          })

        {:error, changeset} ->
          {:error, changeset}
      end
    end)
  end

  # ============================================================================
  # App Inventory
  # ============================================================================

  @doc """
  GET /api/v1/mobile/devices/:id/apps

  Lists installed apps on a device.
  """
  def device_apps(conn, %{"id" => id} = params) do
    with_legacy_device_for_org(conn, id, fn device ->
      opts = [
        limit: parse_int(params["limit"], 500),
        order_by: :app_name
      ]

      apps = Mobile.list_device_apps(device.id, opts)

      json(conn, %{
        data: Enum.map(apps, &serialize_app/1),
        meta: %{total: length(apps)}
      })
    end)
  end

  @doc """
  POST /api/v1/mobile/devices/:id/apps/sync

  Syncs app inventory from agent.

  Body:
    {
      "apps": [
        {
          "bundle_id": "com.example.app",
          "app_name": "Example App",
          "version": "1.0.0",
          "permissions": ["CAMERA", "LOCATION"]
        }
      ]
    }
  """
  def sync_apps(conn, %{"id" => id, "apps" => apps_data}) when is_list(apps_data) do
    with_legacy_device_for_org(conn, id, fn device ->
      case Mobile.sync_device_apps(device.id, apps_data) do
        {:ok, {inserted, updated, deleted}} ->
          json(conn, %{
            success: true,
            message: "App inventory synced",
            stats: %{
              inserted: inserted,
              updated: updated,
              deleted: deleted
            }
          })

        {:error, reason} ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{success: false, error: inspect(reason)})
      end
    end)
  end

  def sync_apps(conn, %{"id" => _id}) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{success: false, error: "apps must be a list"})
  end

  @doc """
  GET /api/v1/mobile/apps/high-risk

  Lists high-risk apps across all devices.
  """
  def high_risk_apps(conn, params) do
    organization_id = get_organization_id(conn)

    opts = [limit: parse_int(params["limit"], 100)]
    apps = Mobile.list_high_risk_apps(organization_id, opts)

    json(conn, %{
      data:
        Enum.map(apps, fn app ->
          serialize_app(app)
          |> Map.put(:device, serialize_device_summary(app.device))
        end)
    })
  end

  @doc """
  GET /api/v1/mobile/apps/sideloaded

  Lists sideloaded apps across all devices.
  """
  def sideloaded_apps(conn, params) do
    organization_id = get_organization_id(conn)

    opts = [limit: parse_int(params["limit"], 100)]
    apps = Mobile.list_sideloaded_apps(organization_id, opts)

    json(conn, %{
      data:
        Enum.map(apps, fn app ->
          serialize_app(app)
          |> Map.put(:device, serialize_device_summary(app.device))
        end)
    })
  end

  # ============================================================================
  # Events
  # ============================================================================

  @doc """
  GET /api/v1/mobile/devices/:id/events

  Lists security events for a device.
  """
  def device_events(conn, %{"id" => id} = params) do
    with_legacy_device_for_org(conn, id, fn device ->
      opts = [
        limit: parse_int(params["limit"], 100),
        offset: parse_int(params["offset"], 0),
        severity: params["severity"]
      ]

      events = Mobile.list_device_events(device.id, opts)

      json(conn, %{
        data: Enum.map(events, &serialize_event/1)
      })
    end)
  end

  @doc """
  GET /api/v1/mobile/events

  Lists security events across all devices.
  """
  def events(conn, params) do
    organization_id = get_organization_id(conn)

    opts = [
      limit: parse_int(params["limit"], 100),
      offset: parse_int(params["offset"], 0),
      hours: parse_int(params["hours"], 24)
    ]

    events = Mobile.list_organization_events(organization_id, opts)

    json(conn, %{
      data:
        Enum.map(events, fn event ->
          serialize_event(event)
          |> Map.put(:device, serialize_device_summary(event.device))
        end)
    })
  end

  @doc """
  GET /api/v1/mobile/v2/events

  V2 alias for the current MobileEvent projection. Device inventory moved to
  mobile_devices_v2, but mobile security events remain in the MobileEvent store.
  """
  def events_v2(conn, params), do: events(conn, params)

  @doc """
  POST /api/v1/mobile/events

  Ingests events from mobile agent.

  Body:
    {
      "device_id": "uuid",
      "events": [
        {
          "event_type": "malicious_dns_query",
          "severity": "high",
          "timestamp": "2026-01-29T12:00:00Z",
          "payload": {"domain": "malware.example.com"}
        }
      ]
    }
  """
  def ingest_events(conn, %{"device_id" => device_id, "events" => events_data})
      when is_list(events_data) do
    organization_id = get_organization_id(conn)

    case get_legacy_device_for_org(organization_id, device_id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "Device not found"})

      device ->
        # Update last seen
        Mobile.touch_device(device)

        # Prepare events with device/org context
        prepared_events =
          Enum.map(events_data, fn event ->
            event
            |> Map.put("device_id", device.id)
            |> Map.put("organization_id", organization_id)
          end)

        results = Mobile.ingest_events(prepared_events)

        success_count = Enum.count(results, &match?({:ok, _}, &1))
        error_count = length(results) - success_count

        json(conn, %{
          success: error_count == 0,
          ingested: success_count,
          errors: error_count
        })
    end
  end

  def ingest_events(conn, _params) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{success: false, error: "device_id and events list are required"})
  end

  @doc """
  POST /api/v1/mobile/app_guard/events

  Ingests one normalized App Guard SDK event.
  """
  def ingest_app_guard_event(conn, %{"schema" => "tamandua.app_guard.event/v1"} = params) do
    organization_id = get_organization_id(conn)

    with :ok <- validate_app_guard_contract(params),
         {:ok, event} <- ingest_verified_app_guard_event(conn, params, organization_id) do
      conn
      |> put_status(:created)
      |> json(%{
        success: true,
        data: serialize_event(event)
      })
    else
      {:error, {:invalid_app_guard_contract, errors}} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Invalid App Guard event payload", details: errors})

      {:error, {:invalid_app_guard_signature, errors}} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Invalid App Guard event signature", details: errors})

      {:error, {:app_guard_replay, errors}} ->
        conn
        |> put_status(:conflict)
        |> json(%{error: "Duplicate App Guard event replay", details: errors})

      {:error, :invalid_device} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Invalid App Guard device payload"})

      {:error, :device_identity_proof_required} ->
        device_identity_proof_required(conn)

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  def ingest_app_guard_event(conn, _params) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "Unsupported App Guard event schema"})
  end

  @doc """
  GET /api/v1/mobile/app_guard/apps

  Lists protected customer apps registered for App Guard.
  """
  def app_guard_apps(conn, params) do
    organization_id = get_organization_id(conn)

    apps =
      Mobile.list_app_guard_protected_apps(organization_id,
        platform: params["platform"],
        limit: parse_int(params["limit"], 100)
      )

    json(conn, %{data: Enum.map(apps, &serialize_app_guard_protected_app/1)})
  end

  @doc """
  POST /api/v1/mobile/app_guard/apps

  Registers a protected customer app for App Guard ingestion.
  """
  def create_app_guard_app(conn, %{"schema" => "tamandua.app_guard.protected_app/v1"} = params) do
    organization_id = get_organization_id(conn)
    attrs = Map.put(params, "organization_id", organization_id)

    case Mobile.create_app_guard_protected_app(attrs) do
      {:ok, app} ->
        conn
        |> put_status(:created)
        |> json(%{success: true, data: serialize_app_guard_protected_app(app)})

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  def create_app_guard_app(conn, _params) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "Unsupported App Guard protected app schema"})
  end

  @doc """
  GET /api/v1/mobile/app_guard/apps/:app_id

  Shows one protected customer app registration.
  """
  def show_app_guard_app(conn, %{"app_id" => app_id}) do
    organization_id = get_organization_id(conn)

    case Mobile.get_app_guard_protected_app_by_app_id(organization_id, app_id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "App Guard protected app not found"})

      app ->
        json(conn, %{data: serialize_app_guard_protected_app(app)})
    end
  end

  @doc """
  GET /api/v1/mobile/app_guard/builds

  Lists App Guard build manifests.
  """
  def app_guard_builds(conn, params) do
    organization_id = get_organization_id(conn)

    builds =
      Mobile.list_app_guard_build_manifests(organization_id,
        app_id: params["app_id"],
        limit: parse_int(params["limit"], 100)
      )

    json(conn, %{data: Enum.map(builds, &serialize_app_guard_build_manifest/1)})
  end

  @doc """
  POST /api/v1/mobile/app_guard/builds

  Stores a protected App Guard build manifest.
  """
  def create_app_guard_build(conn, %{"schema" => "tamandua.app_guard.build_manifest/v1"} = params) do
    organization_id = get_organization_id(conn)
    attrs = Map.put(params, "organization_id", organization_id)

    case Mobile.create_app_guard_build_manifest(attrs) do
      {:ok, manifest} ->
        conn
        |> put_status(:created)
        |> json(%{success: true, data: serialize_app_guard_build_manifest(manifest)})

      {:error, :protected_app_not_found} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "App Guard protected app must be registered before build manifests"})

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  def create_app_guard_build(conn, _params) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "Unsupported App Guard build manifest schema"})
  end

  @doc """
  POST /api/v1/mobile/app_guard/builds/:build_id/verify

  Verifies client-computed build metadata against a stored App Guard build
  manifest. This endpoint is metadata-only; it does not accept or store binaries.
  """
  def verify_app_guard_build(conn, %{"build_id" => build_id} = params) do
    organization_id = get_organization_id(conn)

    case Mobile.verify_app_guard_build_manifest(organization_id, build_id, params) do
      {:ok, result} ->
        json(conn, %{
          success: true,
          data: Map.put(result, :schema, "tamandua.app_guard.build_verification/v1")
        })

      {:error, :build_manifest_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Build manifest not found"})

      {:error, :no_digests_provided} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{
          error: "Provide at least one of artifact_sha256, certificate_sha256, config_sha256"
        })
    end
  end

  @doc """
  GET /api/v1/mobile/app_guard/research/programs

  Lists App Guard research/private bounty programs for reviewer queues.
  """
  def app_guard_research_programs(conn, params) do
    organization_id = get_organization_id(conn)

    programs =
      Mobile.list_app_guard_research_programs(organization_id,
        status: params["status"],
        limit: parse_int(params["limit"], 100)
      )

    json(conn, %{data: Enum.map(programs, &serialize_app_guard_research_program/1)})
  end

  @doc """
  POST /api/v1/mobile/app_guard/research/programs

  Creates an App Guard research/private bounty program.
  """
  def create_app_guard_research_program(
        conn,
        %{"schema" => "tamandua.app_guard.research_program/v1"} = params
      ) do
    organization_id = get_organization_id(conn)
    attrs = Map.put(params, "organization_id", organization_id)

    case Mobile.create_app_guard_research_program(attrs) do
      {:ok, program} ->
        conn
        |> put_status(:created)
        |> json(%{success: true, data: serialize_app_guard_research_program(program)})

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  def create_app_guard_research_program(conn, _params) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "Unsupported App Guard research program schema"})
  end

  @doc """
  GET /api/v1/mobile/app_guard/research/submissions

  Lists App Guard research submissions for triage/reviewer queues.
  """
  def app_guard_research_submissions(conn, params) do
    organization_id = get_organization_id(conn)

    submissions =
      Mobile.list_app_guard_research_submissions(organization_id,
        program_id: params["program_id"],
        status: params["status"],
        limit: parse_int(params["limit"], 100)
      )

    json(conn, %{data: Enum.map(submissions, &serialize_app_guard_research_submission/1)})
  end

  @doc """
  POST /api/v1/mobile/app_guard/research/submissions

  Creates an App Guard research submission.
  """
  def create_app_guard_research_submission(
        conn,
        %{"schema" => "tamandua.app_guard.research_submission/v1"} = params
      ) do
    organization_id = get_organization_id(conn)
    attrs = Map.put(params, "organization_id", organization_id)

    case Mobile.create_app_guard_research_submission(attrs) do
      {:ok, submission} ->
        conn
        |> put_status(:created)
        |> json(%{success: true, data: serialize_app_guard_research_submission(submission)})

      {:error, :research_program_not_found} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "App Guard research program must exist before submissions"})

      {:error, :research_submission_out_of_scope} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "App Guard research submission evidence is outside program scope"})

      {:error, :research_submission_researcher_not_invited} ->
        conn
        |> put_status(:forbidden)
        |> json(%{
          error: "App Guard research submission researcher is not invited to this private program"
        })

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  def create_app_guard_research_submission(conn, _params) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "Unsupported App Guard research submission schema"})
  end

  @doc """
  POST /api/v1/mobile/app_guard/research/submissions/:submission_id/validate

  Stores reviewer validation state for an App Guard research submission.
  """
  def validate_app_guard_research_submission(conn, %{"submission_id" => submission_id} = params) do
    organization_id = get_organization_id(conn)

    case Mobile.validate_app_guard_research_submission(organization_id, submission_id, params) do
      {:ok, submission} ->
        json(conn, %{success: true, data: serialize_app_guard_research_submission(submission)})

      {:error, :research_submission_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "App Guard research submission not found"})

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  # ============================================================================
  # Statistics and Posture
  # ============================================================================

  @doc """
  GET /api/v1/mobile/stats

  Gets mobile device statistics.
  """
  def stats(conn, _params) do
    organization_id = get_organization_id(conn)
    stats = Mobile.get_device_stats(organization_id)
    json(conn, %{data: stats})
  end

  @doc """
  GET /api/v1/mobile/posture

  Gets overall mobile security posture.
  """
  def posture(conn, _params) do
    organization_id = get_organization_id(conn)
    posture = Mobile.get_security_posture(organization_id)
    json(conn, %{data: posture})
  end

  @doc """
  GET /api/v1/mobile/event-stats

  Gets event statistics.
  """
  def event_stats(conn, params) do
    organization_id = get_organization_id(conn)
    hours = parse_int(params["hours"], 24)
    stats = Mobile.get_event_stats(organization_id, hours)
    json(conn, %{data: stats})
  end

  # ============================================================================
  # Response Actions
  # ============================================================================

  @doc """
  POST /api/v1/mobile/devices/:id/lock

  Sends remote lock command to device via the configured MDM provider.
  """
  def lock_device(conn, %{"id" => id} = params) do
    with_legacy_device_for_org(conn, id, fn device ->
      provider = MDMProvider.provider_for_device(device)
      mdm_device_id = device.mdm_device_id || device.device_id

      audit_mdm_action(conn, "lock_device", device)

      case provider.lock_device(mdm_device_id, params) do
        {:ok, result} ->
          Logger.info(
            "[MDM] Lock command sent: device=#{device.device_id} provider=#{inspect(provider)}"
          )

          json(conn, %{
            success: true,
            message: "Lock command sent to device #{device.device_id}",
            command_id: result[:command_id] || result[:command_uuid] || Ecto.UUID.generate(),
            provider: result[:provider],
            status: result[:status]
          })

        {:error, reason} ->
          Logger.error("[MDM] Lock failed: device=#{device.device_id} reason=#{inspect(reason)}")

          conn
          |> put_status(:bad_gateway)
          |> json(%{
            success: false,
            error: format_mdm_error(reason),
            device_id: device.device_id
          })
      end
    end)
  end

  @doc """
  POST /api/v1/mobile/devices/:id/wipe

  Sends remote wipe command to device via the configured MDM provider.
  Supports wipe_type: "full" or "enterprise_only" (default).
  """
  def wipe_device(conn, %{"id" => id} = params) do
    with_legacy_device_for_org(conn, id, fn device ->
      provider = MDMProvider.provider_for_device(device)
      mdm_device_id = device.mdm_device_id || device.device_id

      audit_mdm_action(conn, "wipe_device", device)

      case provider.wipe_device(mdm_device_id, params) do
        {:ok, result} ->
          Mobile.mark_device_wiped(device)

          Logger.info(
            "[MDM] Wipe command sent: device=#{device.device_id} type=#{params["wipe_type"] || "enterprise_only"}"
          )

          json(conn, %{
            success: true,
            message: "Wipe command sent to device #{device.device_id}",
            command_id: result[:command_id] || result[:command_uuid] || Ecto.UUID.generate(),
            provider: result[:provider],
            wipe_type: result[:wipe_type] || params["wipe_type"] || "enterprise_only",
            status: result[:status]
          })

        {:error, reason} ->
          Logger.error("[MDM] Wipe failed: device=#{device.device_id} reason=#{inspect(reason)}")

          conn
          |> put_status(:bad_gateway)
          |> json(%{
            success: false,
            error: format_mdm_error(reason),
            device_id: device.device_id
          })
      end
    end)
  end

  @doc """
  POST /api/v1/mobile/devices/:id/locate

  Requests device location. Returns last known location from our records.
  """
  def locate_device(conn, %{"id" => id}) do
    with_legacy_device_for_org(conn, id, fn device ->
      location =
        device.last_location ||
          %{
            note: "Location not available. Device must have location services enabled."
          }

      json(conn, %{
        success: true,
        device_id: device.device_id,
        location: location
      })
    end)
  end

  @doc """
  POST /api/v1/mobile/devices/:id/message

  Sends a message to the device via MDM lock screen message.
  """
  def send_message(conn, %{"id" => id, "message" => message} = params) do
    with_legacy_device_for_org(conn, id, fn device ->
      provider = MDMProvider.provider_for_device(device)
      mdm_device_id = device.mdm_device_id || device.device_id
      opts = Map.put(params, "message", message)

      audit_mdm_action(conn, "send_message", device)

      case provider.lock_device(mdm_device_id, opts) do
        {:ok, result} ->
          json(conn, %{
            success: true,
            message: "Message sent to device #{device.device_id}",
            command_id: result[:command_id] || result[:command_uuid] || Ecto.UUID.generate(),
            provider: result[:provider],
            status: result[:status]
          })

        {:error, reason} ->
          conn
          |> put_status(:bad_gateway)
          |> json(%{success: false, error: format_mdm_error(reason)})
      end
    end)
  end

  @doc """
  POST /api/v1/mobile/devices/:id/ring

  Rings the device to help locate it.
  """
  def ring_device(conn, %{"id" => id}) do
    with_legacy_device_for_org(conn, id, fn device ->
      provider = MDMProvider.provider_for_device(device)
      mdm_device_id = device.mdm_device_id || device.device_id

      audit_mdm_action(conn, "ring_device", device)

      case provider.lock_device(mdm_device_id, %{"message" => "Tamandua EDR: Locate Device Ring"}) do
        {:ok, result} ->
          json(conn, %{
            success: true,
            message: "Ring command sent to device #{device.device_id}",
            command_id: result[:command_id] || result[:command_uuid] || Ecto.UUID.generate(),
            provider: result[:provider],
            status: result[:status]
          })

        {:error, reason} ->
          conn
          |> put_status(:bad_gateway)
          |> json(%{success: false, error: format_mdm_error(reason)})
      end
    end)
  end

  @doc """
  POST /api/v1/mobile/devices/:id/push-policy

  Pushes a compliance/configuration policy to the device.
  """
  def push_policy(conn, %{"id" => id} = params) do
    with_legacy_device_for_org(conn, id, fn device ->
      provider = MDMProvider.provider_for_device(device)
      mdm_device_id = device.mdm_device_id || device.device_id

      audit_mdm_action(conn, "push_policy", device)

      case provider.push_policy(mdm_device_id, params) do
        {:ok, result} ->
          json(conn, %{
            success: true,
            message: "Policy push initiated for device #{device.device_id}",
            provider: result[:provider],
            status: result[:status]
          })

        {:error, reason} ->
          conn
          |> put_status(:bad_gateway)
          |> json(%{success: false, error: format_mdm_error(reason)})
      end
    end)
  end

  @doc """
  POST /api/v1/mobile/devices/:id/remove-app

  Removes an application from the device.
  """
  def remove_app(conn, %{"id" => id, "app_id" => app_id} = _params) do
    with_legacy_device_for_org(conn, id, fn device ->
      provider = MDMProvider.provider_for_device(device)
      mdm_device_id = device.mdm_device_id || device.device_id

      audit_mdm_action(conn, "remove_app", device)

      case provider.remove_app(mdm_device_id, app_id) do
        {:ok, result} ->
          json(conn, %{
            success: true,
            message: "App removal initiated for #{app_id} on device #{device.device_id}",
            provider: result[:provider],
            status: result[:status]
          })

        {:error, reason} ->
          conn
          |> put_status(:bad_gateway)
          |> json(%{success: false, error: format_mdm_error(reason)})
      end
    end)
  end

  @doc """
  POST /api/v1/mobile/devices/:id/enable-vpn

  Enables or pushes VPN configuration to the device.
  """
  def enable_vpn(conn, %{"id" => id} = params) do
    with_legacy_device_for_org(conn, id, fn device ->
      provider = MDMProvider.provider_for_device(device)
      mdm_device_id = device.mdm_device_id || device.device_id

      audit_mdm_action(conn, "enable_vpn", device)

      case provider.enable_vpn(mdm_device_id, params) do
        {:ok, result} ->
          json(conn, %{
            success: true,
            message: "VPN configuration pushed to device #{device.device_id}",
            provider: result[:provider],
            status: result[:status]
          })

        {:error, reason} ->
          conn
          |> put_status(:bad_gateway)
          |> json(%{success: false, error: format_mdm_error(reason)})
      end
    end)
  end

  @doc """
  GET /api/v1/mobile/devices/:id/compliance

  Validates and returns device compliance status from the MDM provider.
  """
  def device_compliance(conn, %{"id" => id}) do
    with_legacy_device_for_org(conn, id, fn device ->
      provider = MDMProvider.provider_for_device(device)
      mdm_device_id = device.mdm_device_id || device.device_id

      local_compliance = local_mobile_compliance(device)

      remote_compliance =
        if function_exported?(provider, :get_compliance_status, 1) do
          case provider.get_compliance_status(mdm_device_id) do
            {:ok, status} -> status
            {:error, _} -> %{note: "Could not reach MDM provider for remote compliance check"}
          end
        else
          %{note: "MDM provider does not support remote compliance queries"}
        end

      json(conn, %{
        data: %{
          device_id: device.device_id,
          platform: device.platform,
          local: local_compliance,
          remote: remote_compliance,
          overall_compliant:
            local_compliance.local_compliant and
              remote_compliance[:compliant] != false,
          checked_at: DateTime.utc_now() |> DateTime.to_iso8601()
        }
      })
    end)
  end

  # ============================================================================
  # Configuration
  # ============================================================================

  @doc """
  GET /api/v1/mobile/config

  Gets mobile agent configuration.
  """
  def get_config(conn, _params) do
    organization_id = get_organization_id(conn)
    config = load_mobile_config(organization_id)

    json(conn, %{data: config})
  end

  @doc """
  PUT /api/v1/mobile/config

  Updates mobile agent configuration.
  """
  @allowed_config_sections ~w(agent security network collection)
  @allowed_agent_keys ~w(heartbeat_interval_seconds event_batch_size event_flush_interval_seconds)
  @allowed_security_keys ~w(detect_jailbreak detect_root detect_debugger block_malicious_domains scan_installed_apps)
  @allowed_network_keys ~w(enable_dns_monitoring enable_traffic_analysis blocklist_domains)
  @allowed_collection_keys ~w(collect_app_inventory app_inventory_interval_hours collect_device_info device_info_interval_hours)

  def update_config(conn, params) do
    organization_id = get_organization_id(conn)

    # Strip non-config keys (e.g., Phoenix route params)
    config_params = Map.drop(params, ["_format", "action", "controller"])

    case validate_mobile_config(config_params) do
      {:ok, validated_config} ->
        # Persist under a per-org mobile config key in Settings (ETS-backed)
        mobile_category = :"mobile_#{organization_id}"

        ensure_mobile_settings_table()

        current =
          try do
            TamanduaServer.Settings.get(mobile_category)
          rescue
            _ -> %{}
          end

        merged = deep_merge_config(current, validated_config)

        # Store in ETS via the Settings table directly (the Settings GenServer
        # manages :tamandua_settings, which is public)
        :ets.insert(:tamandua_settings, {mobile_category, merged})

        Logger.info(
          "[Mobile] Config updated for org=#{organization_id}: #{inspect(Map.keys(validated_config))}"
        )

        # Broadcast to all connected mobile agents in this organization
        Phoenix.PubSub.broadcast(
          TamanduaServer.PubSub,
          "mobile:org:#{organization_id}",
          {:config_updated, merged}
        )

        json(conn, %{
          success: true,
          message: "Configuration updated successfully",
          data: merged
        })

      {:error, errors} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{
          success: false,
          message: "Invalid configuration",
          errors: errors
        })
    end
  end

  defp load_mobile_config(organization_id) do
    mobile_category = :"mobile_#{organization_id}"

    ensure_mobile_settings_table()

    current =
      try do
        TamanduaServer.Settings.get(mobile_category)
      rescue
        _ -> %{}
      catch
        _, _ -> %{}
      end

    deep_merge_config(default_mobile_config(), current || %{})
  end

  defp ensure_mobile_settings_table do
    case :ets.info(:tamandua_settings) do
      :undefined ->
        :ets.new(:tamandua_settings, [
          :set,
          :public,
          :named_table,
          read_concurrency: true,
          write_concurrency: true
        ])

      _info ->
        :ok
    end
  rescue
    ArgumentError -> :ok
  end

  defp default_mobile_config do
    %{
      "agent" => %{
        "heartbeat_interval_seconds" => 30,
        "event_batch_size" => 50,
        "event_flush_interval_seconds" => 60
      },
      "security" => %{
        "detect_jailbreak" => true,
        "detect_root" => true,
        "detect_debugger" => true,
        "block_malicious_domains" => true,
        "scan_installed_apps" => true
      },
      "network" => %{
        "enable_dns_monitoring" => true,
        "enable_traffic_analysis" => true,
        "blocklist_domains" => []
      },
      "collection" => %{
        "collect_app_inventory" => true,
        "app_inventory_interval_hours" => 24,
        "collect_device_info" => true,
        "device_info_interval_hours" => 6
      }
    }
  end

  # Validates the incoming mobile config params against allowed keys and types.
  defp validate_mobile_config(params) do
    errors = []
    validated = %{}

    {validated, errors} =
      Enum.reduce(params, {validated, errors}, fn {section, values}, {acc_v, acc_e} ->
        cond do
          section not in @allowed_config_sections ->
            {acc_v, ["Unknown configuration section: #{section}" | acc_e]}

          not is_map(values) ->
            {acc_v, ["Section '#{section}' must be a map of key-value pairs" | acc_e]}

          true ->
            allowed_keys = allowed_keys_for_section(section)
            {section_config, section_errors} = validate_section(section, values, allowed_keys)

            acc_v =
              if map_size(section_config) > 0 do
                Map.put(acc_v, section, section_config)
              else
                acc_v
              end

            {acc_v, acc_e ++ section_errors}
        end
      end)

    if errors == [] do
      if map_size(validated) == 0 do
        {:error, ["No valid configuration sections provided"]}
      else
        {:ok, validated}
      end
    else
      {:error, errors}
    end
  end

  defp allowed_keys_for_section("agent"), do: @allowed_agent_keys
  defp allowed_keys_for_section("security"), do: @allowed_security_keys
  defp allowed_keys_for_section("network"), do: @allowed_network_keys
  defp allowed_keys_for_section("collection"), do: @allowed_collection_keys
  defp allowed_keys_for_section(_), do: []

  defp validate_section(section, values, allowed_keys) do
    Enum.reduce(values, {%{}, []}, fn {key, value}, {acc_config, acc_errors} ->
      if key in allowed_keys do
        case validate_config_value(section, key, value) do
          {:ok, validated_value} ->
            {Map.put(acc_config, key, validated_value), acc_errors}

          {:error, reason} ->
            {acc_config, ["#{section}.#{key}: #{reason}" | acc_errors]}
        end
      else
        {acc_config, ["Unknown key '#{key}' in section '#{section}'" | acc_errors]}
      end
    end)
  end

  defp validate_config_value(_section, key, value)
       when key in ~w(heartbeat_interval_seconds event_batch_size event_flush_interval_seconds app_inventory_interval_hours device_info_interval_hours) do
    cond do
      is_integer(value) and value > 0 ->
        {:ok, value}

      is_binary(value) ->
        case Integer.parse(value) do
          {int, _} when int > 0 -> {:ok, int}
          _ -> {:error, "must be a positive integer"}
        end

      true ->
        {:error, "must be a positive integer"}
    end
  end

  defp validate_config_value(_section, key, value)
       when key in ~w(detect_jailbreak detect_root detect_debugger block_malicious_domains scan_installed_apps enable_dns_monitoring enable_traffic_analysis collect_app_inventory collect_device_info) do
    cond do
      is_boolean(value) -> {:ok, value}
      value in ["true", "false"] -> {:ok, value == "true"}
      true -> {:error, "must be a boolean"}
    end
  end

  defp validate_config_value(_section, "blocklist_domains", value) do
    cond do
      is_list(value) and Enum.all?(value, &is_binary/1) -> {:ok, value}
      true -> {:error, "must be a list of domain strings"}
    end
  end

  defp validate_config_value(_section, _key, value) do
    {:ok, value}
  end

  defp deep_merge_config(base, override) when is_map(base) and is_map(override) do
    Map.merge(base, override, fn
      _key, base_val, override_val when is_map(base_val) and is_map(override_val) ->
        deep_merge_config(base_val, override_val)

      _key, _base_val, override_val ->
        override_val
    end)
  end

  defp deep_merge_config(_base, override), do: override

  # ============================================================================
  # MDM Integration Status
  # ============================================================================

  @doc """
  GET /api/v1/mobile/mdm/status

  Gets MDM integration status by checking which providers are configured.
  """
  def mdm_status(conn, _params) do
    _organization_id = get_organization_id(conn)

    providers = [
      {"intune", "Microsoft Intune"},
      {"jamf", "Jamf Pro"}
    ]

    integrations =
      Enum.map(providers, fn {name, display_name} ->
        configured = MDMProvider.configured?(name)

        %{
          provider: name,
          display_name: display_name,
          status: if(configured, do: "configured", else: "not_configured"),
          message:
            if(configured,
              do: "#{display_name} is configured and ready",
              else: "Configure #{display_name} in Settings > Integrations"
            )
        }
      end)

    # Generic provider is always available
    integrations =
      integrations ++
        [
          %{
            provider: "generic",
            display_name: "Manual Queue",
            status: "available",
            message: "Commands are queued for manual execution when no MDM is configured"
          }
        ]

    json(conn, %{data: %{integrations: integrations}})
  end

  @doc """
  POST /api/v1/mobile/mdm/sync

  Triggers sync with all configured MDM providers.
  """
  def mdm_sync(conn, _params) do
    _organization_id = get_organization_id(conn)

    providers = [{"intune", "Microsoft Intune"}, {"jamf", "Jamf Pro"}]

    synced =
      Enum.filter(providers, fn {name, _} -> MDMProvider.configured?(name) end)
      |> Enum.map(fn {name, _} -> name end)

    if synced == [] do
      json(conn, %{
        success: false,
        message:
          "No MDM providers are configured. Configure a provider in Settings > Integrations.",
        synced_providers: []
      })
    else
      Logger.info("[MDM] Sync triggered for providers: #{inspect(synced)}")

      json(conn, %{
        success: true,
        message: "MDM sync initiated for #{length(synced)} provider(s)",
        synced_providers: synced
      })
    end
  end

  # ============================================================================
  # Event Types Reference
  # ============================================================================

  @doc """
  GET /api/v1/mobile/event-types

  Lists all supported mobile event types.
  """
  def event_types(conn, _params) do
    event_types = TamanduaServer.Mobile.MobileEvent.event_types()

    json(conn, %{
      data:
        Enum.map(event_types, fn {type, description} ->
          %{type: type, description: description}
        end)
    })
  end

  # ============================================================================
  # V2 Device CRUD (mobile_devices_v2 table)
  # ============================================================================

  @doc """
  GET /api/v1/mobile/v2/devices

  Lists devices from the mobile_devices_v2 table.

  Query params:
    - platform: ios|android|chromeos|windows|linux
    - compliance_status: compliant|non_compliant|unknown
    - mdm_enrolled: true|false
    - limit: integer (default 100)
    - offset: integer (default 0)
  """
  def index_v2(conn, params) do
    import Ecto.Query

    organization_id = get_organization_id(conn)
    limit = parse_int(params["limit"], 100)
    offset = parse_int(params["offset"], 0)

    query =
      DeviceV2
      |> DeviceV2.by_organization(organization_id)
      |> maybe_filter_v2_platform(params["platform"])
      |> maybe_filter_v2_compliance(params["compliance_status"])
      |> maybe_filter_v2_mdm(params["mdm_enrolled"])
      |> order_by([d], desc: d.last_seen_at)

    total = Repo.aggregate(query, :count)

    devices =
      query
      |> limit(^limit)
      |> offset(^offset)
      |> Repo.all()

    json(conn, %{
      data: Enum.map(devices, &serialize_device_v2/1),
      meta: %{total: total, limit: limit, offset: offset}
    })
  end

  @doc """
  GET /api/v1/mobile/v2/devices/:id

  Shows a single device from mobile_devices_v2.
  """
  def show_v2(conn, %{"id" => id}) do
    organization_id = get_organization_id(conn)

    case get_device_v2_for_org(organization_id, id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "Device not found"})

      device ->
        json(conn, %{data: serialize_device_v2(device)})
    end
  end

  @doc """
  POST /api/v1/mobile/v2/devices

  Creates a device in mobile_devices_v2.
  """
  def create_v2(conn, params) do
    organization_id = get_organization_id(conn)
    body = canonical_mobile_v2_mutation_body(params)
    attrs = Map.put(body, "organization_id", organization_id)
    installation_id = body["device_id"]

    mutation = fn ->
      upsert_mobile_v2_device_and_agent(organization_id, installation_id, attrs)
    end

    result =
      create_v2_identity_mutation(conn, organization_id, installation_id, body, params, mutation)

    case result do
      {:ok, {assurance, :created, device, agent}} ->
        conn
        |> put_status(:created)
        |> json(%{
          data: serialize_device_v2(device),
          agent_projection: serialize_device_v2_agent_projection(agent),
          device_identity: identity_assurance(assurance)
        })

      {:ok, {assurance, :updated, updated, agent}} ->
        json(conn, %{
          data: serialize_device_v2(updated),
          agent_projection: serialize_device_v2_agent_projection(agent),
          device_identity: identity_assurance(assurance)
        })

      {:error, :device_identity_proof_required} ->
        device_identity_proof_required(conn)

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  PUT /api/v1/mobile/v2/devices/:id

  Updates a device in mobile_devices_v2.
  """
  def update_v2(conn, %{"id" => id} = params) do
    organization_id = get_organization_id(conn)

    case get_device_v2_for_org(organization_id, id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "Device not found"})

      device ->
        cond do
          Map.has_key?(params, "mutation_authorization") ->
            device_identity_proof_required(conn)

          Map.has_key?(params, "device_id") and params["device_id"] != device.device_id ->
            immutable_mobile_v2_device_id(conn)

          true ->
            attrs =
              params
              |> Map.drop(["organization_id", "device_id"])
              |> Map.put("organization_id", organization_id)

            case legacy_identity_mutation(organization_id, [device.device_id], fn ->
                   with {:ok, updated} <- Repo.update(DeviceV2.changeset(device, attrs)),
                        {:ok, _agent} <- upsert_device_v2_agent(updated, attrs) do
                     {:ok, updated}
                   end
                 end) do
              {:ok, updated} ->
                json(conn, %{
                  data: serialize_device_v2(updated),
                  device_identity: @legacy_identity_compatibility
                })

              {:error, :device_identity_proof_required} ->
                device_identity_proof_required(conn)

              {:error, changeset} ->
                {:error, changeset}
            end
        end
    end
  end

  @doc """
  DELETE /api/v1/mobile/v2/devices/:id

  Deletes a device from mobile_devices_v2.
  """
  def delete_v2(conn, %{"id" => id}) do
    organization_id = get_organization_id(conn)

    case get_device_v2_for_org(organization_id, id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "Device not found"})

      device ->
        case legacy_identity_mutation(organization_id, [device.device_id], fn ->
               case Repo.delete(device) do
                 {:ok, deleted} -> {:ok, deleted}
                 {:error, reason} -> {:error, reason}
               end
             end) do
          {:ok, _deleted} -> send_resp(conn, :no_content, "")
          {:error, :device_identity_proof_required} -> device_identity_proof_required(conn)
          {:error, changeset} -> {:error, changeset}
        end
    end
  end

  @doc """
  GET /api/v1/mobile/v2/stats

  Returns aggregate counts from mobile_devices_v2 grouped by platform,
  compliance status, and MDM enrollment.
  """
  def stats_v2(conn, _params) do
    import Ecto.Query

    organization_id = get_organization_id(conn)
    base = DeviceV2 |> DeviceV2.by_organization(organization_id)

    total = Repo.aggregate(base, :count)

    platform_counts =
      base
      |> group_by([d], d.platform)
      |> select([d], {d.platform, count(d.id)})
      |> Repo.all()
      |> Map.new()

    compliance_counts =
      base
      |> group_by([d], d.compliance_status)
      |> select([d], {d.compliance_status, count(d.id)})
      |> Repo.all()
      |> Map.new()

    mdm_enrolled = Repo.aggregate(DeviceV2.mdm_enrolled_only(base), :count)
    jailbroken = Repo.aggregate(DeviceV2.jailbroken_only(base), :count)

    stale_cutoff = DateTime.add(DateTime.utc_now(), -24 * 60 * 60, :second)

    stale_24h =
      Repo.aggregate(
        from(d in base, where: is_nil(d.last_seen_at) or d.last_seen_at < ^stale_cutoff),
        :count
      )

    json(conn, %{
      data: %{
        total: total,
        by_platform: platform_counts,
        by_compliance: compliance_counts,
        mdm_enrolled: mdm_enrolled,
        not_enrolled: total - mdm_enrolled,
        jailbroken: jailbroken,
        stale_24h: stale_24h
      }
    })
  end

  @doc """
  GET /api/v1/mobile/v2/posture

  Returns a mobile security posture summary computed from mobile_devices_v2:
  percentage compliant, encrypted, jailbroken, with passcode, etc.
  """
  def posture_v2(conn, _params) do
    import Ecto.Query

    organization_id = get_organization_id(conn)
    base = DeviceV2 |> DeviceV2.by_organization(organization_id)

    total = Repo.aggregate(base, :count)

    if total == 0 do
      json(conn, %{
        data: %{
          total: 0,
          pct_compliant: 100.0,
          pct_encrypted: 100.0,
          pct_jailbroken: 0.0,
          pct_passcode_set: 100.0,
          pct_mdm_enrolled: 0.0,
          score: 100
        }
      })
    else
      compliant = Repo.aggregate(DeviceV2.by_compliance(base, "compliant"), :count)
      encrypted = Repo.aggregate(from(d in base, where: d.encryption_enabled == true), :count)
      jailbroken = Repo.aggregate(DeviceV2.jailbroken_only(base), :count)
      passcode = Repo.aggregate(from(d in base, where: d.passcode_set == true), :count)
      mdm = Repo.aggregate(DeviceV2.mdm_enrolled_only(base), :count)

      pct = fn count -> Float.round(count / total * 100, 1) end

      # Simple score: start at 100, subtract penalties
      score = 100
      score = score - trunc((total - compliant) / total * 30)
      score = score - trunc((total - encrypted) / total * 25)
      score = score - trunc(jailbroken / total * 30)
      score = score - trunc((total - passcode) / total * 15)
      score = max(0, score)

      json(conn, %{
        data: %{
          total: total,
          pct_compliant: pct.(compliant),
          pct_encrypted: pct.(encrypted),
          pct_jailbroken: pct.(jailbroken),
          pct_passcode_set: pct.(passcode),
          pct_mdm_enrolled: pct.(mdm),
          compliant: compliant,
          encrypted: encrypted,
          jailbroken: jailbroken,
          passcode_set: passcode,
          mdm_enrolled: mdm,
          score: score
        }
      })
    end
  end

  # ============================================================================
  # MDM Commands CRUD (mdm_commands table)
  # ============================================================================

  @doc """
  GET /api/v1/mobile/v2/commands

  Lists MDM commands, optionally filtered by device_id, status, command_type, or alert_id.
  """
  def list_commands(conn, params) do
    import Ecto.Query

    organization_id = get_organization_id(conn)
    limit = parse_int(params["limit"], 50)
    offset = parse_int(params["offset"], 0)

    query =
      MDMCommand
      |> MDMCommand.by_organization(organization_id)
      |> maybe_filter_command_device(params["device_id"])
      |> maybe_filter_command_status(params["status"])
      |> maybe_filter_command_type(params["command_type"])
      |> maybe_filter_command_alert(params["alert_id"])
      |> MDMCommand.latest_first()
      |> limit(^limit)
      |> offset(^offset)

    commands = Repo.all(query)

    json(conn, %{
      data: Enum.map(commands, &serialize_command/1)
    })
  end

  @doc """
  POST /api/v1/mobile/v2/commands

  Creates a new MDM command for a device.

  Body:
    {
      "device_id": "uuid",
      "command_type": "lock|wipe|install_profile|...",
      "payload": {}
    }
  """
  def create_command(conn, params) do
    organization_id = get_organization_id(conn)
    user = conn.assigns[:current_user]
    device_id = params["device_id"]
    command_type = params["command_type"]

    with :ok <- authorize_mobile_command(conn, command_type),
         %DeviceV2{} = device <- get_device_v2_for_org(organization_id, device_id),
         :ok <- authorize_privileged_mobile_shell(command_type, device),
         :ok <- validate_mobile_command_alert(organization_id, command_alert_id(params)) do
      attrs =
        params
        |> Map.put("organization_id", organization_id)
        |> Map.put("requested_by", (user && (user.email || user.id)) || "system")
        |> Map.put("status", "pending")
        |> normalize_mobile_command_attrs(device)

      changeset = MDMCommand.changeset(struct(MDMCommand), attrs)

      case Repo.insert(changeset) do
        {:ok, command} ->
          conn
          |> put_status(:created)
          |> json(%{data: serialize_command(command)})

        {:error, changeset} ->
          {:error, changeset}
      end
    else
      {:error, :forbidden} ->
        conn
        |> put_status(:forbidden)
        |> json(%{
          error: "forbidden",
          message: "You don't have permission to send mobile device commands",
          required_permission: "agents_command"
        })

      {:error, :privileged_shell_disabled} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{
          error: "privileged_shell_disabled",
          message:
            "shell_execute requires an Android endpoint build that explicitly opts in to tamandua.endpoint.allow_privileged_shell and reports the privileged shell capability. Use managed_shell for the default mobile response path.",
          required_manifest_flag: "tamandua.endpoint.allow_privileged_shell",
          fallback_command_type: "managed_shell"
        })

      nil ->
        conn |> put_status(:not_found) |> json(%{error: "Device not found"})

      {:error, :alert_not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "Alert not found"})
    end
  end

  @doc """
  GET /api/v1/mobile/v2/commands/:id

  Shows a single MDM command.
  """
  def show_command(conn, %{"id" => id}) do
    organization_id = get_organization_id(conn)

    case get_command_for_org(organization_id, id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "Command not found"})

      command ->
        json(conn, %{data: serialize_command(command)})
    end
  end

  @doc """
  PATCH /api/v1/mobile/v2/commands/:id/status

  Updates the status of an MDM command (e.g. pending -> sent -> completed|failed).
  """
  def update_command_status(conn, %{"id" => id} = params) do
    organization_id = get_organization_id(conn)

    case get_command_for_org(organization_id, id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "Command not found"})

      command ->
        if present_device_id_mismatch?(params["device_id"], command.device_id) do
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{
            error: "Command device identity mismatch",
            required_field: "device_id"
          })
        else
          case terminal_mobile_command_replay(command, params) do
            :same ->
              json(conn, %{data: serialize_command(command)})

            {:conflict, existing_hash, incoming_hash} ->
              conn
              |> put_status(:conflict)
              |> json(%{
                error: "Command terminal result replay conflict",
                existing_result_sha256: existing_hash,
                incoming_result_sha256: incoming_hash
              })

            :continue ->
              now = DateTime.utc_now()

              updates =
                %{}
                |> maybe_put("status", params["status"])
                |> maybe_put("result", params["result"])
                |> normalize_mobile_command_status_updates(command)

              updates =
                cond do
                  updates["status"] == "sent" ->
                    Map.put(updates, "sent_at", now)

                  updates["status"] in ["completed", "failed"] ->
                    updates
                    |> Map.put("completed_at", now)
                    |> Map.put(
                      "payload",
                      ScreenCaptureArtifacts.redact_mobile_command_payload(command.payload || %{})
                    )

                  true ->
                    updates
                end

              changeset = MDMCommand.changeset(command, updates)

              case Repo.update(changeset) do
                {:ok, updated} ->
                  EvidenceSessions.reconcile_mobile_command(updated)
                  json(conn, %{data: serialize_command(updated)})

                {:error, changeset} ->
                  {:error, changeset}
              end
          end
        end
    end
  end

  defp present_device_id_mismatch?(nil, _device_id), do: false
  defp present_device_id_mismatch?("", _device_id), do: false

  defp present_device_id_mismatch?(provided_device_id, command_device_id),
    do: provided_device_id != command_device_id

  defp terminal_mobile_command_replay(%MDMCommand{} = command, %{"status" => status} = params) do
    existing_hash = command.result |> ensure_map() |> Map.get("result_sha256")
    incoming_hash = params["result"] |> ensure_map() |> Map.get("result_sha256")

    cond do
      command.status not in ["completed", "failed"] or status not in ["completed", "failed"] ->
        :continue

      is_binary(existing_hash) and existing_hash != "" and existing_hash == incoming_hash and
          command.status == status ->
        :same

      is_binary(existing_hash) and existing_hash != "" and is_binary(incoming_hash) and
        incoming_hash != "" and existing_hash != incoming_hash ->
        {:conflict, existing_hash, incoming_hash}

      true ->
        :continue
    end
  end

  defp terminal_mobile_command_replay(_command, _params), do: :continue

  # ============================================================================
  # Registry-Based Device Management
  # ============================================================================

  @doc """
  POST /api/v1/mobile/devices/:id/compliance-check

  Runs compliance checks on a device via DeviceRegistry.
  """
  def compliance_check(conn, %{"id" => id}) do
    with_legacy_device_for_org(conn, id, fn device ->
      case DeviceRegistry.check_compliance(device.id) do
        {:ok, report} ->
          json(conn, %{data: report})

        {:error, :not_found} ->
          conn |> put_status(:not_found) |> json(%{error: "Device not found"})
      end
    end)
  end

  @doc """
  GET /api/v1/mobile/devices/:id/compliance-report

  Gets cached compliance report for a device.
  """
  def compliance_report(conn, %{"id" => id}) do
    with_legacy_device_for_org(conn, id, fn device ->
      case DeviceRegistry.get_compliance_report(device.id) do
        {:ok, report} ->
          json(conn, %{data: report})

        {:error, :not_found} ->
          conn
          |> put_status(:not_found)
          |> json(%{error: "No compliance report found. Run a compliance check first."})
      end
    end)
  end

  @doc """
  POST /api/v1/mobile/devices/:id/threat-scan

  Runs a heuristic mobile risk and posture scan on a device.
  """
  def threat_scan(conn, %{"id" => id}) do
    with_legacy_device_for_org(conn, id, fn device ->
      report = ThreatDetection.full_scan(device)

      json(conn, %{data: report})
    end)
  end

  @doc """
  GET /api/v1/mobile/devices/:id/apps/inventory

  Gets the full enriched app inventory for a device.
  """
  def app_inventory(conn, %{"id" => id}) do
    with_legacy_device_for_org(conn, id, fn device ->
      case AppInventory.get_inventory(device.id) do
        {:ok, inventory} ->
          json(conn, %{data: inventory})
      end
    end)
  end

  @doc """
  GET /api/v1/mobile/devices/:id/apps/risk

  Gets the app risk score for a device.
  """
  def app_risk(conn, %{"id" => id}) do
    with_legacy_device_for_org(conn, id, fn device ->
      case AppInventory.get_risk_score(device.id) do
        {:ok, risk} ->
          json(conn, %{data: risk})

        {:error, reason} ->
          conn
          |> put_status(:bad_gateway)
          |> json(%{success: false, error: inspect(reason)})
      end
    end)
  end

  @doc """
  POST /api/v1/mobile/devices/:id/commands/:command

  Sends an MDM command to a device.
  Supported commands: lock, wipe, locate.
  """
  def send_command(conn, %{"id" => id, "command" => command} = params) do
    with :ok <- authorize_mobile_command(conn, command) do
      with_legacy_device_for_org(conn, id, fn device ->
        provider = MDMProvider.provider_for_device(device)
        mdm_device_id = device.mdm_device_id || device.device_id

        audit_mdm_action(conn, command, device)

        result =
          case command do
            "lock" ->
              provider.lock_device(mdm_device_id, params)

            "wipe" ->
              with {:ok, res} <- provider.wipe_device(mdm_device_id, params) do
                Mobile.mark_device_wiped(device)
                {:ok, res}
              end

            "locate" ->
              location = device.last_location || %{note: "Location not available"}

              {:ok,
               %{
                 action: "locate",
                 device_id: device.device_id,
                 location: location,
                 status: "completed"
               }}

            other ->
              {:error, {:unknown_command, other}}
          end

        case result do
          {:ok, res} ->
            json(conn, %{
              success: true,
              command: command,
              device_id: device.device_id,
              result: res
            })

          {:error, {:unknown_command, cmd}} ->
            conn
            |> put_status(:bad_request)
            |> json(%{success: false, error: "Unknown command: #{cmd}"})

          {:error, reason} ->
            conn
            |> put_status(:bad_gateway)
            |> json(%{success: false, error: format_mdm_error(reason)})
        end
      end)
    else
      {:error, :forbidden} ->
        conn
        |> put_status(:forbidden)
        |> json(%{
          error: "forbidden",
          message: "You don't have permission to send mobile device commands",
          required_permission: "agents_command"
        })
    end
  end

  @doc """
  POST /api/v1/mobile/mdm/sync

  Triggers sync with all configured MDM providers (enhanced version).
  """
  def mdm_sync_enhanced(conn, _params) do
    _organization_id = get_organization_id(conn)

    providers = [{"intune", "Microsoft Intune"}, {"jamf", "Jamf Pro"}]

    synced =
      providers
      |> Enum.filter(fn {name, _} -> MDMProvider.configured?(name) end)
      |> Enum.map(fn {name, _} -> name end)

    if synced == [] do
      json(conn, %{
        success: false,
        message: "No MDM providers are configured.",
        synced_providers: []
      })
    else
      Logger.info("[MDM] Sync triggered for providers: #{inspect(synced)}")

      json(conn, %{
        success: true,
        message: "MDM sync initiated for #{length(synced)} provider(s)",
        synced_providers: synced
      })
    end
  end

  @doc """
  GET /api/v1/mobile/registry-stats

  Gets device statistics from the ETS-backed registry.
  """
  def registry_stats(conn, _params) do
    organization_id = get_organization_id(conn)
    devices = DeviceRegistry.list_devices(%{"organization_id" => organization_id})
    stats = registry_stats_for_devices(devices)

    json(conn, %{data: stats})
  end

  @doc """
  POST /api/v1/mobile/compliance/bulk-check

  Runs compliance checks on all active devices.
  """
  def bulk_compliance_check(conn, _params) do
    organization_id = get_organization_id(conn)

    results =
      %{"organization_id" => organization_id, "status" => "active"}
      |> DeviceRegistry.list_devices()
      |> Enum.map(fn device -> {device.id, DeviceRegistry.check_compliance(device.id)} end)

    checked = length(results)

    non_compliant =
      Enum.count(results, fn
        {_id, {:ok, %{overall_compliant: false}}} -> true
        _ -> false
      end)

    json(conn, %{
      success: true,
      data: %{checked: checked, non_compliant: non_compliant},
      message:
        "Bulk compliance check completed: #{checked} checked, #{non_compliant} non-compliant"
    })
  end

  @doc """
  POST /api/v1/mobile/devices/:id/enroll

  Enrolls a device with an MDM provider.
  """
  def enroll_device(conn, %{"id" => id}) do
    with_legacy_device_for_org(conn, id, fn _device ->
      # DeviceRegistry enrollment crosses a GenServer/MDM boundary and cannot
      # participate in the identity transaction. Legacy callers remain closed
      # until this route accepts a server-verified proof context.
      device_identity_proof_required(conn)
    end)
  end

  @doc """
  POST /api/v1/mobile/devices/:id/deactivate

  Deactivates (retires) a device.
  """
  def deactivate(conn, %{"id" => id}) do
    with_legacy_device_for_org(conn, id, fn device ->
      case DeviceRegistry.deactivate_device(device.id) do
        {:ok, device} ->
          json(conn, %{
            success: true,
            data: serialize_device(device),
            message: "Device deactivated"
          })

        {:error, :not_found} ->
          conn |> put_status(:not_found) |> json(%{error: "Device not found"})

        {:error, changeset} ->
          {:error, changeset}
      end
    end)
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  @doc false
  # Plug: resolves the caller's organization and normalizes it into
  # `conn.assigns[:organization_id]`. Halts with 403 when no organization
  # context is available (e.g. token without an org claim), instead of the
  # previous behavior where `get_organization_id/1` raised and produced a 500.
  def require_organization(conn, _opts) do
    org_id = resolve_organization_id(conn)

    if org_id do
      assign(conn, :organization_id, org_id)
    else
      conn
      |> put_status(:forbidden)
      |> json(%{error: "Organization context required"})
      |> halt()
    end
  end

  defp resolve_organization_id(conn) do
    conn.assigns[:organization_id] ||
      conn.assigns[:current_organization_id] ||
      (conn.assigns[:current_user] && conn.assigns[:current_user].organization_id)
  end

  defp get_organization_id(conn) do
    # Guaranteed non-nil for controller actions by the :require_organization
    # plug; the fallback keeps behavior sane if this helper is ever called
    # outside the plug pipeline.
    conn.assigns[:organization_id] || resolve_organization_id(conn)
  end

  # The compatibility path never accepts a proof context from request data.
  # Identity locks and every database mutation share one Repo transaction.
  defp legacy_identity_mutation(organization_id, installation_ids, callback) do
    installation_ids =
      installation_ids
      |> Enum.filter(&(is_binary(&1) and &1 != ""))
      |> Enum.uniq()
      |> Enum.sort()

    case MobileDeviceIdentity.with_legacy_unbound(
           organization_id,
           installation_ids,
           callback
         ) do
      {:error, :invalid_installation_ids} ->
        {:error, :device_identity_proof_required}

      result ->
        result
    end
  end

  defp create_v2_identity_mutation(
         conn,
         organization_id,
         installation_id,
         body,
         params,
         callback
       ) do
    case mutation_authorization(params) do
      :missing ->
        case legacy_identity_mutation(organization_id, [installation_id], fn ->
               case callback.() do
                 {:ok, outcome, device, agent} -> {:ok, {:legacy, outcome, device, agent}}
                 {:error, reason} -> {:error, reason}
               end
             end) do
          result -> result
        end

      {:ok, authorization_id, proof} ->
        consume_mobile_v2_mutation_authorization(
          conn,
          organization_id,
          installation_id,
          body,
          authorization_id,
          proof,
          callback
        )

      {:error, _reason} ->
        {:error, :device_identity_proof_required}
    end
  end

  defp consume_mobile_v2_mutation_authorization(
         conn,
         organization_id,
         installation_id,
         body,
         authorization_id,
         proof,
         callback
       ) do
    with actor_id when is_binary(actor_id) <- authenticated_actor_id(conn),
         true <- is_binary(installation_id) and installation_id != "" do
      expected = %{
        actor_id: actor_id,
        installation_id: installation_id,
        resource_id: installation_id,
        operation: @mobile_v2_mutation_operation,
        http_method: @mobile_v2_mutation_method,
        route_id: @mobile_v2_mutation_route,
        body: body
      }

      Repo.transaction(fn ->
        MobileMutationProof.consume_and_run(
          Repo,
          organization_id,
          authorization_id,
          proof,
          expected,
          fn _authorization ->
            case callback.() do
              {:ok, outcome, device, agent} ->
                {:ok, outcome, device.device_id, {outcome, device, agent}}

              {:error, reason} ->
                {:error, {:mobile_v2_mutation_failed, reason}}
            end
          end
        )
      end)
      |> case do
        {:ok, {:ok, _authorization, {outcome, device, agent}}} ->
          {:ok, {:verified, outcome, device, agent}}

        {:error, {:mobile_v2_mutation_failed, reason}} ->
          {:error, reason}

        {:error, _authorization_error} ->
          {:error, :device_identity_proof_required}
      end
    else
      _ -> {:error, :device_identity_proof_required}
    end
  end

  defp upsert_mobile_v2_device_and_agent(organization_id, installation_id, attrs) do
    case get_device_v2_by_external_id(organization_id, installation_id) do
      nil ->
        with {:ok, device} <- Repo.insert(DeviceV2.changeset(struct(DeviceV2), attrs)),
             {:ok, agent} <- upsert_device_v2_agent(device, attrs) do
          {:ok, :created, device, agent}
        end

      %DeviceV2{} = device ->
        with {:ok, updated} <- Repo.update(DeviceV2.changeset(device, attrs)),
             {:ok, agent} <- upsert_device_v2_agent(updated, attrs) do
          {:ok, :updated, updated, agent}
        end
    end
  end

  defp canonical_mobile_v2_mutation_body(params) do
    Map.drop(params, ["mutation_authorization", "organization_id"])
  end

  defp mutation_authorization(params) when is_map(params) do
    case Map.fetch(params, "mutation_authorization") do
      :error ->
        :missing

      {:ok, authorization} when is_map(authorization) ->
        if Enum.sort(Map.keys(authorization)) == Enum.sort(@mutation_authorization_fields) and
             Enum.all?(@mutation_authorization_fields, fn field ->
               is_binary(authorization[field]) and authorization[field] != ""
             end) do
          {:ok, authorization["authorization_id"], Map.delete(authorization, "authorization_id")}
        else
          {:error, :invalid_mutation_authorization}
        end

      {:ok, _invalid} ->
        {:error, :invalid_mutation_authorization}
    end
  end

  defp mutation_authorization(_params), do: {:error, :invalid_mutation_authorization}

  defp authenticated_actor_id(conn) do
    case conn.assigns[:current_user] do
      %{id: actor_id} when is_binary(actor_id) -> actor_id
      _ -> nil
    end
  end

  defp identity_assurance(:verified), do: @verified_mutation_identity
  defp identity_assurance(:legacy), do: @legacy_identity_compatibility

  defp device_identity_proof_required(conn) do
    conn
    |> put_status(:conflict)
    |> json(%{error: %{code: "device_identity_proof_required"}})
  end

  defp immutable_mobile_v2_device_id(conn) do
    conn
    |> put_status(:conflict)
    |> json(%{error: %{code: "mobile_v2_device_id_immutable"}})
  end

  defp get_agent_for_org(organization_id, agent_id) do
    Agent
    |> where([a], a.organization_id == ^organization_id and a.id == ^agent_id)
    |> Repo.one()
  end

  defp mobile_device_for_agent(organization_id, %Agent{} = agent) do
    config = agent.config || %{}

    v2_id =
      Map.get(config, "mobile_device_v2_id") ||
        Map.get(config, :mobile_device_v2_id)

    external_id =
      Map.get(config, "mobile_device_external_id") ||
        Map.get(config, :mobile_device_external_id) ||
        agent.machine_id

    legacy_id =
      Map.get(config, "mobile_device_id") ||
        Map.get(config, :mobile_device_id)

    get_device_v2_for_org(organization_id, v2_id) ||
      device_v2_by_external_id(organization_id, external_id) ||
      device_v2_by_agent_hints(organization_id, agent) ||
      legacy_device_v2_for_agent(organization_id, legacy_id, external_id) ||
      provision_device_v2_for_mobile_agent(organization_id, agent)
  end

  defp legacy_device_v2_for_agent(organization_id, legacy_id, external_id) do
    legacy_device =
      get_legacy_device_for_org(organization_id, legacy_id) ||
        legacy_device_by_external_id(organization_id, external_id)

    case legacy_device do
      %Device{} = device ->
        ensure_device_v2_for_legacy_device(device)

      _ ->
        nil
    end
  end

  defp device_v2_by_agent_hints(organization_id, %Agent{} = agent) do
    config = agent.config || %{}

    [
      agent.machine_id,
      agent.hostname,
      config["mobile_device_external_id"],
      config[:mobile_device_external_id],
      config["mobile_device_id"],
      config[:mobile_device_id],
      config["device_id"],
      config[:device_id],
      get_in(config, ["device", "device_id"]),
      get_in(config, [:device, :device_id]),
      get_in(config, ["posture", "device", "device_id"]),
      get_in(config, [:posture, :device, :device_id])
    ]
    |> Enum.find_value(&device_v2_by_external_id(organization_id, normalize_lookup_id(&1)))
  end

  defp normalize_lookup_id(value) when is_binary(value), do: String.trim(value)

  defp normalize_lookup_id(value) when is_atom(value),
    do: value |> Atom.to_string() |> String.trim()

  defp normalize_lookup_id(_value), do: nil

  defp provision_device_v2_for_mobile_agent(organization_id, %Agent{} = agent) do
    with true <- provisionable_mobile_command_agent?(agent),
         device_id when is_binary(device_id) and device_id != "" <-
           mobile_agent_command_device_id(agent) do
      case get_device_v2_by_external_id(organization_id, device_id) do
        %DeviceV2{} = device ->
          device

        nil ->
          create_command_device_from_agent(organization_id, agent, device_id)
      end
    else
      _ -> nil
    end
  end

  defp provisionable_mobile_command_agent?(%Agent{} = agent) do
    os = agent.os_type |> to_string() |> String.downcase()
    config = agent.config || %{}
    source = (Map.get(config, "source") || Map.get(config, :source)) |> to_string()
    tags = agent.tags || []

    os in ["android", "ios"] or
      String.contains?(os, "android") or
      String.contains?(os, "ios") or
      source in ["tamandua_mobile", "tamandua_mobile_v2"] or
      Enum.any?(tags, &(&1 in ["mobile", "mobile-v2", "mobile_endpoint"]))
  end

  defp mobile_agent_command_device_id(%Agent{} = agent) do
    config = agent.config || %{}

    [
      config["mobile_device_external_id"],
      config[:mobile_device_external_id],
      config["device_id"],
      config[:device_id],
      get_in(config, ["device", "device_id"]),
      get_in(config, [:device, :device_id]),
      get_in(config, ["posture", "device", "device_id"]),
      get_in(config, [:posture, :device, :device_id]),
      agent.machine_id
    ]
    |> Enum.map(&normalize_lookup_id/1)
    |> Enum.find(&(&1 not in [nil, ""]))
  end

  defp create_command_device_from_agent(organization_id, %Agent{} = agent, device_id) do
    now = DateTime.utc_now()

    attrs = %{
      "organization_id" => organization_id,
      "device_id" => device_id,
      "device_name" => agent.hostname || "mobile-" <> String.slice(device_id, 0, 12),
      "platform" => mobile_agent_platform(agent),
      "os_version" => agent.os_version,
      "model" => mobile_agent_model(agent),
      "owner_email" => mobile_agent_owner_email(agent),
      "mdm_enrolled" => false,
      "mdm_provider" => "tamandua_endpoint",
      "compliance_status" => "unknown",
      "last_seen_at" => now,
      "enrolled_at" => now
    }

    case Repo.insert(DeviceV2.changeset(struct(DeviceV2), attrs)) do
      {:ok, device} ->
        sync_device_v2_agent(device, agent, agent.config || %{})
        device

      {:error, _changeset} ->
        get_device_v2_by_external_id(organization_id, device_id)
    end
  end

  defp ensure_device_v2_for_legacy_device(%Device{} = device) do
    case get_device_v2_by_external_id(device.organization_id, device.device_id) do
      %DeviceV2{} = command_device ->
        command_device

      nil ->
        create_device_v2_from_legacy_device(device)
    end
  end

  defp create_device_v2_from_legacy_device(%Device{} = device) do
    now = DateTime.utc_now()

    attrs = %{
      "organization_id" => device.organization_id,
      "device_id" => device.device_id,
      "device_name" => mobile_device_display_name(device),
      "platform" => legacy_mobile_platform(device),
      "os_version" => device.os_version,
      "model" => device.model,
      "serial_number" => device.serial_number,
      "owner_email" => device.user_email,
      "mdm_enrolled" => device.mdm_enrolled || false,
      "mdm_provider" => device.mdm_provider || "tamandua_mobile",
      "compliance_status" => legacy_mobile_compliance_status(device),
      "encryption_enabled" => device.encryption_enabled || false,
      "jailbroken" => device.is_jailbroken || device.is_rooted || false,
      "passcode_set" => device.passcode_enabled || false,
      "last_seen_at" => device_v2_datetime(device.last_seen_at) || now,
      "enrolled_at" => device_v2_datetime(device.enrolled_at) || now
    }

    case Repo.insert(DeviceV2.changeset(struct(DeviceV2), attrs)) do
      {:ok, command_device} ->
        sync_device_v2_agent(command_device, %{
          "source" => "tamandua_mobile_legacy_bridge",
          "mobile_device_id" => device.id,
          "mobile_device_external_id" => device.device_id
        })

        command_device

      {:error, _changeset} ->
        get_device_v2_by_external_id(device.organization_id, device.device_id)
    end
  end

  defp legacy_mobile_platform(%Device{} = device) do
    platform = device.platform |> to_string() |> String.downcase()

    cond do
      platform in ["ios", "android"] -> platform
      String.contains?(platform, "ios") -> "ios"
      true -> "android"
    end
  end

  defp legacy_mobile_compliance_status(%Device{} = device) do
    case device.mdm_compliance_status do
      status when status in ["compliant", "non_compliant", "unknown"] -> status
      _ -> "unknown"
    end
  end

  defp mobile_agent_platform(%Agent{} = agent) do
    os = agent.os_type |> to_string() |> String.downcase()

    cond do
      String.contains?(os, "ios") or String.contains?(os, "iphone") or
          String.contains?(os, "ipad") ->
        "ios"

      true ->
        "android"
    end
  end

  defp mobile_agent_model(%Agent{} = agent) do
    config = agent.config || %{}

    normalize_lookup_id(
      config["model"] ||
        config[:model] ||
        get_in(config, ["device", "model"]) ||
        get_in(config, [:device, :model]) ||
        get_in(config, ["posture", "device", "model"]) ||
        get_in(config, [:posture, :device, :model])
    )
  end

  defp mobile_agent_owner_email(%Agent{} = agent) do
    config = agent.config || %{}

    normalize_lookup_id(
      config["mobile_owner_email"] ||
        config[:mobile_owner_email] ||
        config["owner_email"] ||
        config[:owner_email] ||
        get_in(config, ["user", "email"]) ||
        get_in(config, [:user, :email])
    )
  end

  defp legacy_device_by_external_id(_organization_id, external_id) when external_id in [nil, ""],
    do: nil

  defp legacy_device_by_external_id(organization_id, external_id),
    do: get_legacy_device_by_external_id(organization_id, external_id)

  defp device_v2_by_external_id(_organization_id, external_id) when external_id in [nil, ""],
    do: nil

  defp device_v2_by_external_id(organization_id, external_id),
    do: get_device_v2_by_external_id(organization_id, external_id)

  defp mobile_agent_overview_payload(%Agent{} = agent, nil) do
    %{
      agent_id: agent.id,
      mobile: mobile_agent?(agent),
      linked: false,
      link_status: mobile_agent_link_status(agent),
      device: nil,
      command_device: nil,
      command_identity: nil,
      posture: nil,
      compliance: nil,
      app_inventory: %{apps: [], total: 0},
      app_guard: %{
        events: [],
        total_recent_events: 0,
        readiness: app_guard_readiness_summary(nil, [], [])
      },
      commands: mobile_command_descriptors(agent)
    }
  end

  defp mobile_agent_overview_payload(%Agent{} = agent, %Device{} = device) do
    command_history = mobile_command_history(device)

    %{
      agent_id: agent.id,
      mobile: true,
      linked: true,
      device: serialize_device_detail(device),
      command_device: mobile_command_device_summary(device),
      command_identity: mobile_command_identity_summary(device),
      last_command: List.first(command_history),
      command_history: command_history,
      posture: mobile_posture_summary(device),
      compliance: local_mobile_compliance(device),
      app_inventory: mobile_app_inventory_summary(device),
      app_guard: mobile_app_guard_summary(device),
      commands: mobile_command_descriptors(agent)
    }
  end

  defp mobile_agent_overview_payload(%Agent{} = agent, %DeviceV2{} = device) do
    command_history = mobile_command_history(device)

    %{
      agent_id: agent.id,
      mobile: true,
      linked: true,
      device: serialize_device_v2(device),
      command_device: mobile_command_device_summary(device),
      command_identity: mobile_command_identity_summary(device),
      last_command: List.first(command_history),
      command_history: command_history,
      posture: mobile_v2_posture_summary(device, agent),
      compliance: mobile_v2_compliance(device),
      app_inventory: %{
        apps: [],
        reported: false,
        coverage: "not_reported",
        total: nil,
        high_risk: nil,
        sideloaded: nil
      },
      app_guard: mobile_v2_app_guard_summary(device),
      commands: mobile_command_descriptors(agent)
    }
  end

  defp mobile_agent?(%Agent{} = agent) do
    os = agent.os_type |> to_string() |> String.downcase()
    config = agent.config || %{}
    source = (Map.get(config, "source") || Map.get(config, :source)) |> to_string()
    tags = agent.tags || []

    os in ["android", "ios"] or
      String.contains?(os, "android") or
      String.contains?(os, "ios") or
      Map.get(config, "source") == "tamandua_mobile" or
      Map.get(config, :source) == "tamandua_mobile" or
      source == "tamandua_mobile_v2" or
      Enum.any?(tags, &(&1 in ["mobile", "mobile-v2", "mobile_endpoint"]))
  end

  defp mobile_agent_link_status(%Agent{} = agent) do
    config = agent.config || %{}

    %{
      reason: "mobile_command_device_not_found",
      expected_identifiers:
        [
          agent.machine_id,
          config["mobile_device_v2_id"],
          config[:mobile_device_v2_id],
          config["mobile_device_external_id"],
          config[:mobile_device_external_id],
          config["mobile_device_id"],
          config[:mobile_device_id],
          config["device_id"],
          config[:device_id],
          get_in(config, ["device", "device_id"]),
          get_in(config, [:device, :device_id]),
          get_in(config, ["posture", "device", "device_id"]),
          get_in(config, [:posture, :device, :device_id])
        ]
        |> Enum.map(&normalize_lookup_id/1)
        |> Enum.reject(&(&1 in [nil, ""]))
        |> Enum.uniq(),
      remediation:
        "Run the mobile app endpoint sync so /mobile/v2/devices upserts this install, or re-enroll the device to refresh the mobile_device_external_id mapping."
    }
  end

  defp mobile_posture_summary(%Device{} = device) do
    %{
      id: device.id,
      device_id: device.device_id,
      external_device_id: device.device_id,
      risk_score: device.risk_score || 0,
      risk_factors: device.risk_factors || [],
      jailbroken_or_rooted: device.is_jailbroken or device.is_rooted,
      passcode_enabled: device.passcode_enabled,
      encryption_enabled: device.encryption_enabled,
      biometric_enabled: device.biometric_enabled,
      developer_mode_enabled: device.developer_mode_enabled,
      usb_debugging_enabled: device.usb_debugging_enabled,
      mdm_enrolled: device.mdm_enrolled,
      mdm_compliance_status: device.mdm_compliance_status,
      last_assessment: format_datetime(device.last_seen_at || device.updated_at)
    }
  end

  defp local_mobile_compliance(%Device{} = device) do
    %{
      jailbroken_or_rooted: device.is_jailbroken or device.is_rooted,
      passcode_enabled: device.passcode_enabled,
      encryption_enabled: device.encryption_enabled,
      mdm_enrolled: device.mdm_enrolled,
      risk_score: device.risk_score,
      risk_factors: device.risk_factors,
      local_compliant:
        not (device.is_jailbroken or device.is_rooted) and
          device.passcode_enabled != false and
          device.encryption_enabled != false
    }
  end

  defp mobile_v2_posture_summary(%DeviceV2{} = device, %Agent{} = agent) do
    reported_posture = mobile_endpoint_posture_from_config(agent.config || %{})

    security_checks =
      ensure_map(reported_posture["security_checks"] || reported_posture[:security_checks])

    hardening = ensure_map(reported_posture["hardening"] || reported_posture[:hardening])

    risk_score =
      reported_posture["risk_score"] || reported_posture[:risk_score] ||
        if(device.jailbroken, do: 85, else: 0)

    risk_factors =
      reported_posture["risk_factors"] || reported_posture[:risk_factors] ||
        mobile_v2_risk_factors(device, security_checks)

    %{
      id: device.id,
      device_id: device.device_id,
      external_device_id: device.device_id,
      platform: device.platform,
      os_version: device.os_version,
      model: device.model,
      risk_score: risk_score,
      risk_factors: risk_factors,
      security_checks: security_checks,
      hardening: hardening,
      jailbroken_or_rooted:
        boolean_from_checks(
          security_checks,
          ["jailbroken_or_rooted", "rooted", "jailbroken"],
          device.jailbroken
        ),
      passcode_enabled:
        boolean_from_checks(
          security_checks,
          ["passcode_enabled", "passcode_set"],
          device.passcode_set
        ),
      encryption_enabled:
        boolean_from_checks(security_checks, ["encryption_enabled"], device.encryption_enabled),
      developer_mode_enabled:
        boolean_from_checks(security_checks, ["developer_mode", "developer_mode_enabled"], nil),
      usb_debugging_enabled:
        boolean_from_checks(security_checks, ["usb_debugging", "adb_enabled"], nil),
      debugger_detected: boolean_from_checks(security_checks, ["debugger_detected"], nil),
      frida_detected: boolean_from_checks(security_checks, ["frida_detected"], nil),
      hook_framework_detected:
        boolean_from_checks(security_checks, ["hook_framework_detected"], nil),
      native_hook_detected: boolean_from_checks(security_checks, ["native_hook_detected"], nil),
      app_integrity_violation:
        boolean_from_checks(security_checks, ["app_integrity_violation"], nil),
      runtime_memory_tamper_detected:
        boolean_from_checks(security_checks, ["runtime_memory_tamper_detected"], nil),
      code_signature_drift_detected:
        boolean_from_checks(security_checks, ["code_signature_drift_detected"], nil),
      code_signature_baseline_configured:
        boolean_from_checks(security_checks, ["code_signature_baseline_configured"], nil),
      tampering_detected: boolean_from_checks(security_checks, ["tampering_detected"], nil),
      mdm_enrolled: device.mdm_enrolled,
      mdm_compliance_status: device.compliance_status,
      last_assessment:
        reported_posture["last_assessment"] || reported_posture[:last_assessment] ||
          format_datetime(device.last_seen_at || device.updated_at)
    }
  end

  defp mobile_v2_posture_summary(%DeviceV2{} = device, _agent) do
    mobile_v2_posture_summary(device, %Agent{config: %{}})
  end

  defp mobile_v2_compliance(%DeviceV2{} = device) do
    %{
      jailbroken_or_rooted: device.jailbroken,
      passcode_enabled: device.passcode_set,
      encryption_enabled: device.encryption_enabled,
      mdm_enrolled: device.mdm_enrolled,
      risk_score: if(device.jailbroken, do: 85, else: 0),
      risk_factors: if(device.jailbroken, do: ["jailbroken_or_rooted"], else: []),
      local_compliant:
        device.jailbroken != true and
          device.passcode_set != false and
          device.encryption_enabled != false
    }
  end

  defp mobile_endpoint_posture_from_config(config) when is_map(config) do
    config
    |> Map.get("posture", config[:posture] || %{})
    |> ensure_map()
  end

  defp mobile_endpoint_posture_from_config(_config), do: %{}

  defp boolean_from_checks(checks, keys, fallback) do
    keys
    |> Enum.map(fn key -> fetch_check_value(checks, key) end)
    |> Enum.find(&is_boolean/1)
    |> case do
      nil -> fallback
      value -> value
    end
  end

  defp fetch_check_value(checks, key) when is_map(checks) do
    cond do
      Map.has_key?(checks, key) -> Map.get(checks, key)
      Map.has_key?(checks, String.to_atom(key)) -> Map.get(checks, String.to_atom(key))
      true -> nil
    end
  end

  defp fetch_check_value(_checks, _key), do: nil

  defp mobile_v2_risk_factors(%DeviceV2{} = device, security_checks) do
    [
      {device.jailbroken || boolean_from_checks(security_checks, ["jailbroken_or_rooted"], false),
       "jailbroken_or_rooted"},
      {boolean_from_checks(security_checks, ["developer_mode", "developer_mode_enabled"], false),
       "developer_mode_enabled"},
      {boolean_from_checks(security_checks, ["usb_debugging", "adb_enabled"], false),
       "usb_debugging_enabled"},
      {boolean_from_checks(security_checks, ["debugger_detected"], false), "debugger_detected"},
      {boolean_from_checks(security_checks, ["frida_detected"], false), "frida_detected"},
      {boolean_from_checks(security_checks, ["hook_framework_detected"], false),
       "hook_framework_detected"},
      {boolean_from_checks(security_checks, ["native_hook_detected"], false),
       "native_hook_detected"},
      {boolean_from_checks(security_checks, ["app_integrity_violation"], false),
       "app_integrity_violation"},
      {boolean_from_checks(security_checks, ["runtime_memory_tamper_detected"], false),
       "runtime_memory_tamper_detected"},
      {boolean_from_checks(security_checks, ["code_signature_drift_detected"], false),
       "code_signature_drift_detected"},
      {boolean_from_checks(security_checks, ["tampering_detected"], false), "tampering_detected"}
    ]
    |> Enum.filter(fn {enabled, _factor} -> enabled == true end)
    |> Enum.map(fn {_enabled, factor} -> factor end)
  end

  defp mobile_app_inventory_summary(%Device{} = device) do
    apps = Mobile.list_device_apps(device.id, limit: 100, order_by: :app_name)
    high_risk = Enum.count(apps, &(&1.risk_level in ["high", "critical"]))

    sideloaded =
      Enum.count(apps, fn app ->
        installer = app.installer |> to_string() |> String.downcase()
        installer in ["sideload", "sideloaded", "unknown", "manual", "adb"]
      end)

    %{
      apps: Enum.map(apps, &serialize_app/1),
      total: length(apps),
      high_risk: high_risk,
      sideloaded: sideloaded
    }
  end

  defp mobile_app_guard_summary(%Device{} = device) do
    events = Mobile.list_device_events(device.id, limit: 8)

    protected_apps =
      Mobile.list_app_guard_protected_apps(device.organization_id,
        platform: device.platform,
        limit: 25
      )

    %{
      events: Enum.map(events, &serialize_event/1),
      total_recent_events: length(events),
      protected_apps: Enum.map(protected_apps, &serialize_app_guard_protected_app/1),
      protected_total: length(protected_apps),
      readiness: app_guard_readiness_summary(device.platform, events, protected_apps)
    }
  end

  defp mobile_v2_app_guard_summary(%DeviceV2{} = device) do
    events =
      case get_legacy_device_by_external_id(device.organization_id, device.device_id) do
        %Device{} = legacy_device -> Mobile.list_device_events(legacy_device.id, limit: 8)
        _ -> []
      end

    protected_apps =
      Mobile.list_app_guard_protected_apps(device.organization_id,
        platform: device.platform,
        limit: 25
      )

    %{
      events: Enum.map(events, &serialize_event/1),
      total_recent_events: length(events),
      protected_apps: Enum.map(protected_apps, &serialize_app_guard_protected_app/1),
      protected_total: length(protected_apps),
      readiness: app_guard_readiness_summary(device.platform, events, protected_apps)
    }
  end

  defp app_guard_readiness_summary(platform, events, protected_apps) do
    active_signal_names =
      events
      |> Enum.flat_map(&app_guard_event_signal_names/1)
      |> Enum.uniq()
      |> Enum.sort()

    gaps =
      []
      |> maybe_add_gap(Enum.empty?(protected_apps), "protected_app_not_registered")
      |> maybe_add_gap(Enum.empty?(events), "no_recent_app_guard_events")
      |> maybe_add_gap(Enum.empty?(active_signal_names), "no_recent_runtime_signals")

    %{
      status: app_guard_readiness_status(gaps),
      platform: platform,
      protected_app_registered: not Enum.empty?(protected_apps),
      recent_event_count: length(events),
      runtime_signal_count: length(active_signal_names),
      runtime_signals: active_signal_names,
      gaps: gaps,
      claim_boundary:
        "App Guard readiness reflects protected-app telemetry and policy evidence. It does not prove binary shielding, white-box crypto, or no-code app hardening."
    }
  end

  defp app_guard_event_signal_names(event) do
    payload =
      case event do
        %{payload: payload} when is_map(payload) -> payload
        %{"payload" => payload} when is_map(payload) -> payload
        _ -> %{}
      end

    payload
    |> get_in(["evidence", "active_signals"])
    |> case do
      signals when is_list(signals) ->
        signals
        |> Enum.map(fn
          %{"name" => name} when is_binary(name) -> name
          %{name: name} when is_binary(name) -> name
          _ -> nil
        end)
        |> Enum.reject(&is_nil/1)

      _ ->
        payload
        |> get_in(["risk", "reasons"])
        |> case do
          reasons when is_list(reasons) -> Enum.filter(reasons, &is_binary/1)
          _ -> []
        end
    end
  end

  defp app_guard_readiness_status([]), do: "ready"

  defp app_guard_readiness_status(gaps) do
    if "protected_app_not_registered" in gaps do
      "missing_protected_app"
    else
      "observing"
    end
  end

  defp maybe_add_gap(gaps, true, gap), do: [gap | gaps]
  defp maybe_add_gap(gaps, false, _gap), do: gaps

  defp mobile_command_descriptors(%Agent{} = agent) do
    if mobile_agent?(agent) do
      [
        %{
          id: "locate",
          label: "Locate",
          destructive: false,
          execution_scope: "mobile_app_endpoint",
          supported_by_mobile_app: true
        },
        %{
          id: "collect_diagnostics",
          label: "Collect Diagnostics",
          destructive: false,
          execution_scope: "mobile_app_endpoint",
          supported_by_mobile_app: true
        },
        %{
          id: "managed_shell",
          label: "Managed Shell",
          destructive: false,
          execution_scope: "mobile_app_endpoint",
          supported_by_mobile_app: true
        },
        %{
          id: "shell_execute",
          label: "Privileged Shell (gated)",
          destructive: true,
          execution_scope: "privileged_mobile_runtime",
          supported_by_mobile_app: privileged_mobile_shell_enabled?(agent),
          requires_manifest_flag: "tamandua.endpoint.allow_privileged_shell"
        },
        %{
          id: "screen_capture",
          label: "Screen Snapshot",
          destructive: false,
          execution_scope: "mobile_screen_session_broker",
          supported_by_mobile_app: true,
          consent_model: "android_system_prompt_or_ios_in_app_user_action",
          claim_boundary:
            "Mobile screen capture is foreground/user-consented only; it is not silent desktop capture."
        },
        %{
          id: "dns_status",
          label: "DNS Status",
          destructive: false,
          execution_scope: "mobile_app_endpoint",
          supported_by_mobile_app: true
        },
        %{
          id: "enable_dns_protection",
          label: "Enable DNS Protection",
          destructive: false,
          execution_scope: "mobile_dns_collector",
          supported_by_mobile_app: false
        },
        %{
          id: "request_dns_vpn_consent",
          label: "Request DNS VPN Consent",
          destructive: false,
          execution_scope: "mobile_dns_collector",
          supported_by_mobile_app: false
        },
        %{
          id: "block_domain",
          label: "Block Domain",
          destructive: false,
          execution_scope: "mobile_dns_collector",
          supported_by_mobile_app: false
        },
        %{
          id: "network_status",
          label: "Network Status",
          destructive: false,
          execution_scope: "mobile_app_endpoint",
          supported_by_mobile_app: true
        },
        %{
          id: "list_network_flows",
          label: "Network Flows",
          destructive: false,
          execution_scope: "packet_collector",
          supported_by_mobile_app: false
        },
        %{
          id: "inspect_packet",
          label: "Inspect Packet",
          destructive: false,
          execution_scope: "packet_collector",
          supported_by_mobile_app: false
        },
        %{
          id: "sync_app_inventory",
          label: "Sync Apps",
          destructive: false,
          execution_scope: "mobile_app_endpoint",
          command_risk: "package_inventory",
          supported_by_mobile_app: true,
          collector_coverage:
            "native package collector when available; current-app/cache fallback otherwise",
          limitations: [
            "Package visibility depends on mobile platform policy and manifest-declared scope",
            "iOS full installed-application inventory requires MDM inventory authority",
            "Fallback mode reports current app or cached posture only"
          ],
          requirements: [
            "Native package collector enabled for full Android package metadata",
            "Declared package visibility scope for protected-app inventory"
          ]
        },
        %{
          id: "inspect_package",
          label: "Inspect Package",
          destructive: false,
          execution_scope: "mobile_app_endpoint",
          command_risk: "package_inspection",
          supported_by_mobile_app: true,
          collector_coverage:
            "native package collector when available; current-app/cache fallback otherwise",
          limitations: [
            "Target package may be invisible unless platform policy and manifest scope allow it",
            "iOS package inspection requires MDM installed-application inventory",
            "Fallback mode can only inspect current app or cached posture entries"
          ],
          requirements: [
            "Native package collector enabled for full Android package metadata",
            "Declared package visibility scope for target package"
          ]
        },
        %{
          id: "lock",
          label: "Lock",
          destructive: false,
          execution_scope: "mdm_provider",
          command_risk: "privileged_device_action",
          supported_by_mobile_app: false,
          requirements: [
            "Managed device enrollment",
            "Device owner or MDM provider command authority"
          ]
        },
        %{
          id: "wipe",
          label: "Wipe",
          destructive: true,
          execution_scope: "mdm_provider",
          command_risk: "destructive_device_action",
          supported_by_mobile_app: false,
          requirements: [
            "Managed device enrollment",
            "Device owner or MDM provider command authority",
            "Auditable operator approval for destructive actions"
          ]
        },
        %{
          id: "remove_app",
          label: "Remove App",
          destructive: true,
          execution_scope: "mdm_provider",
          command_risk: "privileged_device_action",
          supported_by_mobile_app: false,
          requirements: [
            "Managed device enrollment",
            "Device owner or MDM provider command authority",
            "Auditable operator approval for destructive actions"
          ]
        },
        %{
          id: "enable_vpn",
          label: "Enable VPN",
          destructive: false,
          execution_scope: "mdm_provider",
          supported_by_mobile_app: false
        }
      ]
    else
      []
    end
  end

  defp mobile_command_device_summary(%Device{} = device) do
    case get_device_v2_by_external_id(device.organization_id, device.device_id) do
      %DeviceV2{} = command_device ->
        mobile_command_device_summary(command_device)

      _ ->
        nil
    end
  end

  defp mobile_command_device_summary(%DeviceV2{} = command_device) do
    agent = get_device_v2_agent(command_device.organization_id, command_device.device_id)

    %{
      id: command_device.id,
      device_id: command_device.device_id,
      agent_id: agent && agent.id,
      device_name: command_device.device_name,
      platform: command_device.platform,
      mdm_provider: command_device.mdm_provider,
      mdm_enrolled: command_device.mdm_enrolled,
      status: mobile_v2_status(command_device)
    }
  end

  defp mobile_command_identity_summary(%Device{} = device) do
    case get_device_v2_by_external_id(device.organization_id, device.device_id) do
      %DeviceV2{} = command_device -> mobile_command_identity_summary(command_device)
      _ -> nil
    end
  end

  defp mobile_command_identity_summary(%DeviceV2{} = command_device) do
    agent = get_device_v2_agent(command_device.organization_id, command_device.device_id)

    %{
      command_device_id: command_device.id,
      external_device_id: command_device.device_id,
      agent_machine_id: agent && agent.machine_id,
      background_sync_device_id: command_device.id
    }
  end

  defp mobile_v2_status(%DeviceV2{} = device) do
    cond do
      device.mdm_enrolled == true -> "active"
      device.last_seen_at != nil -> "active"
      true -> "pending"
    end
  end

  defp mobile_command_history(%Device{} = device) do
    import Ecto.Query

    case get_device_v2_by_external_id(device.organization_id, device.device_id) do
      %DeviceV2{} = command_device ->
        MDMCommand
        |> MDMCommand.by_organization(device.organization_id)
        |> MDMCommand.by_device(command_device.id)
        |> MDMCommand.latest_first()
        |> limit(5)
        |> Repo.all()
        |> Enum.map(&serialize_command/1)

      _ ->
        []
    end
  end

  defp mobile_command_history(%DeviceV2{} = command_device) do
    import Ecto.Query

    MDMCommand
    |> MDMCommand.by_organization(command_device.organization_id)
    |> MDMCommand.by_device(command_device.id)
    |> MDMCommand.latest_first()
    |> limit(5)
    |> Repo.all()
    |> Enum.map(&serialize_command/1)
  end

  defp get_legacy_device_for_org(_organization_id, nil), do: nil
  defp get_legacy_device_for_org(_organization_id, ""), do: nil

  defp get_legacy_device_for_org(organization_id, id) do
    import Ecto.Query

    case Ecto.UUID.cast(id) do
      {:ok, uuid} ->
        by_database_id =
          Device
          |> Device.by_organization(organization_id)
          |> where([d], d.id == ^uuid)
          |> Repo.one()

        by_database_id || get_legacy_device_by_external_id(organization_id, id)

      :error ->
        get_legacy_device_by_external_id(organization_id, id)
    end
  end

  defp with_legacy_device_for_org(conn, id, callback) when is_function(callback, 1) do
    organization_id = get_organization_id(conn)

    case get_legacy_device_for_org(organization_id, id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "Device not found"})

      device ->
        callback.(device)
    end
  end

  defp get_legacy_device_by_external_id(organization_id, device_id) do
    Mobile.get_device_by_device_id(organization_id, device_id)
  end

  defp ensure_app_guard_device(
         organization_id,
         %{
           "device" => %{"device_id" => external_device_id} = device_attrs,
           "platform" => platform
         },
         ingestion_metadata
       )
       when is_binary(external_device_id) and external_device_id != "" do
    case MobileDeviceIdentity.with_legacy_unbound(
           organization_id,
           [external_device_id],
           fn ->
             ensure_unbound_app_guard_device(
               organization_id,
               external_device_id,
               device_attrs,
               platform
             )
           end
         ) do
      {:error, :device_identity_proof_required} ->
        existing_bound_app_guard_device(
          organization_id,
          external_device_id,
          ingestion_metadata
        )

      {:error, :invalid_installation_ids} ->
        {:error, :invalid_device}

      result ->
        result
    end
  end

  defp ensure_app_guard_device(_organization_id, _params, _ingestion_metadata),
    do: {:error, :invalid_device}

  defp ensure_unbound_app_guard_device(
         organization_id,
         external_device_id,
         device_attrs,
         platform
       ) do
    attrs = %{
      "organization_id" => organization_id,
      "device_id" => external_device_id,
      "platform" => normalize_app_guard_platform(platform),
      "model" => device_attrs["model"],
      "manufacturer" => device_attrs["manufacturer"],
      "os_version" => device_attrs["os_version"],
      "agent_version" => "app_guard",
      "mdm_enrolled" => Map.get(device_attrs, "managed", false),
      "mdm_provider" => app_guard_legacy_mdm_provider(device_attrs["mdm_provider"])
    }

    device_result =
      case get_legacy_device_by_external_id(organization_id, external_device_id) do
        nil ->
          Mobile.register_device(attrs)

        device ->
          Mobile.update_device(
            device,
            app_guard_device_update_attrs(device, device_attrs, platform)
          )
      end

    with {:ok, device} <- device_result,
         {:ok, _device_v2} <-
           ensure_app_guard_device_v2(
             organization_id,
             external_device_id,
             device_attrs,
             platform,
             device
           ) do
      {:ok, device}
    end
  end

  # App Guard HMAC authenticates the app envelope, not the hardware-backed
  # device key. A historical/bound installation is telemetry-only: it may
  # reference an existing tenant-owned Device, but this path never refreshes
  # Device, DeviceV2, or Agent fields.
  defp existing_bound_app_guard_device(
         organization_id,
         external_device_id,
         %{"signed" => true}
       ) do
    case get_legacy_device_by_external_id(organization_id, external_device_id) do
      %Device{} = device -> {:ok, device}
      nil -> {:error, :device_identity_proof_required}
    end
  end

  defp existing_bound_app_guard_device(
         _organization_id,
         _external_device_id,
         _ingestion_metadata
       ),
       do: {:error, :device_identity_proof_required}

  defp app_guard_device_update_attrs(device, device_attrs, platform) do
    %{
      "platform" => normalize_app_guard_platform(platform) || device.platform,
      "model" => device_attrs["model"] || device.model,
      "manufacturer" => device_attrs["manufacturer"] || device.manufacturer,
      "os_version" => device_attrs["os_version"] || device.os_version,
      "agent_version" => device.agent_version || "app_guard",
      "mdm_enrolled" => Map.get(device_attrs, "managed", device.mdm_enrolled),
      "mdm_provider" =>
        app_guard_legacy_mdm_provider(device_attrs["mdm_provider"] || device.mdm_provider),
      "last_seen_at" => utc_now()
    }
    |> Enum.reject(fn {_key, value} -> value in [nil, ""] end)
    |> Map.new()
  end

  defp app_guard_legacy_mdm_provider(provider)
       when provider in [
              "intune",
              "workspace_one",
              "jamf",
              "google_workspace",
              "mobileiron",
              "soti"
            ],
       do: provider

  defp app_guard_legacy_mdm_provider(_provider), do: "none"

  defp ensure_app_guard_device_v2(
         organization_id,
         external_device_id,
         device_attrs,
         platform,
         legacy_device
       ) do
    now = utc_now()

    attrs = %{
      "organization_id" => organization_id,
      "device_id" => external_device_id,
      "device_name" =>
        device_attrs["device_name"] ||
          device_attrs["name"] ||
          device_attrs["model"] ||
          mobile_device_display_name(legacy_device),
      "platform" => normalize_app_guard_platform(platform),
      "os_version" => device_attrs["os_version"],
      "model" => device_attrs["model"],
      "owner_email" => device_attrs["owner_email"] || device_attrs["user_email"],
      "mdm_enrolled" => Map.get(device_attrs, "managed", false),
      "mdm_provider" => device_attrs["mdm_provider"] || "app_guard",
      "compliance_status" => "unknown",
      "last_seen_at" => now,
      "enrolled_at" => now,
      "capabilities" => %{
        "app_guard" => true,
        "managed_shell" => true,
        "endpoint_telemetry" => "mobile"
      }
    }

    device =
      case get_device_v2_by_external_id(organization_id, external_device_id) do
        nil ->
          %DeviceV2{}

        %DeviceV2{} = existing ->
          existing
      end

    with {:ok, device_v2} <- device |> DeviceV2.changeset(attrs) |> Repo.insert_or_update() do
      case upsert_device_v2_agent(device_v2, attrs) do
        {:ok, _agent} ->
          {:ok, device_v2}

        {:error, reason} ->
          {:error, {:app_guard_device_graph_sync_failed, reason}}
      end
    end
  end

  defp validate_app_guard_contract(params) do
    errors =
      []
      |> require_string(params, ["schema"])
      |> require_string(params, ["event_id"])
      |> require_string(params, ["event_type"])
      |> require_string(params, ["severity"])
      |> require_string(params, ["platform"])
      |> require_string(params, ["timestamp"])
      |> require_string(params, ["app", "package_or_bundle_id"])
      |> require_string(params, ["app", "version"])
      |> require_string(params, ["device", "device_id"])
      |> require_integer_range(params, ["risk", "score"], 0, 100)
      |> require_string(params, ["risk", "decision"])
      |> require_list(params, ["risk", "reasons"])
      |> validate_enum(params, ["event_type"], @app_guard_event_types)
      |> validate_enum(params, ["severity"], @app_guard_severities)
      |> validate_enum(params, ["platform"], @app_guard_platforms)
      |> validate_enum(params, ["risk", "decision"], @app_guard_decisions)
      |> validate_timestamp(params, ["timestamp"])

    case Enum.reverse(errors) do
      [] -> :ok
      errors -> {:error, {:invalid_app_guard_contract, errors}}
    end
  end

  defp validate_app_guard_signature(conn, params, organization_id) do
    signature = header(conn, "x-tamandua-signature")
    payload_sha256 = header(conn, "x-tamandua-payload-sha256")
    algorithm = header(conn, "x-tamandua-signature-algorithm")
    signing_key_id = header(conn, "x-tamandua-signing-key-id")
    request_timestamp = header(conn, "x-tamandua-timestamp")
    nonce = header(conn, "x-tamandua-nonce") || params["event_id"]

    request_timestamp = if blank?(request_timestamp), do: nil, else: request_timestamp

    if Enum.all?([signature, payload_sha256, algorithm, signing_key_id], &blank?/1) do
      if allow_unsigned_app_guard_ingestion?() do
        {:ok, unsigned_app_guard_ingestion_metadata()}
      else
        {:error,
         {:invalid_app_guard_signature, [~s(signed App Guard event envelope is required)]}}
      end
    else
      errors =
        []
        |> require_signature_header(signature, "X-Tamandua-Signature")
        |> require_signature_header(payload_sha256, "X-Tamandua-Payload-SHA256")
        |> require_signature_header(algorithm, "X-Tamandua-Signature-Algorithm")
        |> require_signature_header(signing_key_id, "X-Tamandua-Signing-Key-ID")
        |> validate_app_guard_signature_algorithm(algorithm)
        |> validate_app_guard_signing_key_id(signing_key_id)
        |> validate_app_guard_request_timestamp(request_timestamp)

      verification = app_guard_signature_verification(conn, params, signature, payload_sha256)

      errors =
        errors
        |> validate_app_guard_payload_digest(verification, payload_sha256)
        |> validate_app_guard_hmac(verification, signature)
        |> validate_app_guard_replay(organization_id, signing_key_id, payload_sha256, nonce)

      case Enum.reverse(errors) do
        [] ->
          {:ok,
           signed_app_guard_ingestion_metadata(
             signing_key_id,
             payload_sha256,
             signature,
             nonce,
             request_timestamp,
             verification
           )}

        errors ->
          if Enum.any?(
               errors,
               &(&1 in [
                   "duplicate signed App Guard event payload",
                   "duplicate signed App Guard event nonce"
                 ])
             ) do
            {:error, {:app_guard_replay, errors}}
          else
            {:error, {:invalid_app_guard_signature, errors}}
          end
      end
    end
  end

  defp ingest_verified_app_guard_event(conn, params, organization_id) do
    # Replay keys are reserved before graph work and intentionally remain
    # consumed after graph or event failure. The graph transaction commits
    # before event ingestion, so retries require fresh payload/nonce/event_id.
    with {:ok, ingestion_metadata} <-
           validate_app_guard_signature(conn, params, organization_id),
         :ok <- validate_app_guard_event_id_replay(params, organization_id),
         {:ok, device} <-
           ensure_app_guard_device(organization_id, params, ingestion_metadata),
         {:ok, event} <-
           params
           |> app_guard_event_to_mobile_attrs(
             organization_id,
             device.id,
             ingestion_metadata
           )
           |> Mobile.ingest_event() do
      {:ok, event}
    end
  end

  defp require_signature_header(errors, value, name) do
    if blank?(value), do: ["#{name} is required" | errors], else: errors
  end

  defp validate_app_guard_signature_algorithm(errors, algorithm) do
    if blank?(algorithm) or String.upcase(String.trim(algorithm)) == "HMAC-SHA256" do
      errors
    else
      ["X-Tamandua-Signature-Algorithm must be HMAC-SHA256" | errors]
    end
  end

  defp validate_app_guard_signing_key_id(errors, signing_key_id) do
    cond do
      blank?(signing_key_id) ->
        errors

      allowed_app_guard_signing_key_ids() == [] ->
        errors

      signing_key_id in allowed_app_guard_signing_key_ids() ->
        errors

      true ->
        ["X-Tamandua-Signing-Key-ID is not configured for App Guard ingestion" | errors]
    end
  end

  defp validate_app_guard_request_timestamp(errors, nil),
    do: [~s(X-Tamandua-Timestamp is required) | errors]

  defp validate_app_guard_request_timestamp(errors, ""), do: errors

  defp validate_app_guard_request_timestamp(errors, timestamp) do
    with {:ok, datetime, 0} <- DateTime.from_iso8601(String.trim(timestamp)),
         age_seconds <- abs(DateTime.diff(DateTime.utc_now(), datetime, :second)),
         true <- age_seconds <= app_guard_replay_window_seconds() do
      errors
    else
      {:error, _reason} ->
        ["X-Tamandua-Timestamp must be an ISO8601 UTC timestamp" | errors]

      false ->
        ["X-Tamandua-Timestamp is outside the App Guard anti-replay window" | errors]
    end
  end

  defp validate_app_guard_payload_digest(errors, verification, payload_sha256) do
    cond do
      blank?(payload_sha256) ->
        errors

      blank?(verification.raw_body) ->
        ["raw request body is required for signature verification" | errors]

      not app_guard_sha256?(payload_sha256) ->
        ["X-Tamandua-Payload-SHA256 must be a 64-character hex SHA256" | errors]

      is_nil(verification.payload_match) ->
        ["X-Tamandua-Payload-SHA256 does not match canonical payload" | errors]

      true ->
        errors
    end
  end

  defp validate_app_guard_hmac(errors, verification, signature) do
    cond do
      blank?(signature) ->
        errors

      blank?(verification.raw_body) ->
        ["raw request body is required for signature verification" | errors]

      not String.starts_with?(signature, "sha256=") ->
        ["X-Tamandua-Signature must use sha256=<64 hex> format" | errors]

      not app_guard_sha256?(String.replace_prefix(signature, "sha256=", "")) ->
        ["X-Tamandua-Signature must use sha256=<64 hex> format" | errors]

      true ->
        case app_guard_signing_secret() do
          nil ->
            ["App Guard signing secret is not configured" | errors]

          secret ->
            expected =
              verification.payloads
              |> Enum.map(fn {_name, payload} ->
                "sha256=" <> hmac_sha256_hex(secret, payload)
              end)
              |> Enum.find(&secure_compare(normalize_signature(signature), &1))

            if expected do
              errors
            else
              ["X-Tamandua-Signature does not match canonical payload" | errors]
            end
        end
    end
  end

  defp validate_app_guard_replay(errors, organization_id, signing_key_id, payload_sha256, nonce) do
    cond do
      not Enum.empty?(errors) ->
        errors

      true ->
        cond do
          AppGuardReplayGuard.reserve_signed_value(
            organization_id,
            signing_key_id,
            "payload_sha256",
            normalize_hex(payload_sha256),
            app_guard_replay_window_seconds()
          ) == :duplicate ->
            ["duplicate signed App Guard event payload" | errors]

          not blank?(nonce) and
              AppGuardReplayGuard.reserve_signed_value(
                organization_id,
                signing_key_id,
                "nonce",
                nonce,
                app_guard_replay_window_seconds()
              ) == :duplicate ->
            ["duplicate signed App Guard event nonce" | errors]

          true ->
            errors
        end
    end
  end

  defp validate_app_guard_event_id_replay(params, organization_id) do
    event_id = params["event_id"]

    cond do
      blank?(event_id) ->
        :ok

      AppGuardReplayGuard.event_id_seen?(organization_id, event_id) ->
        {:error, {:app_guard_replay, ["duplicate App Guard event_id"]}}

      AppGuardReplayGuard.reserve_event_id(organization_id, event_id) == :duplicate ->
        {:error, {:app_guard_replay, ["duplicate App Guard event_id"]}}

      true ->
        :ok
    end
  end

  defp app_guard_signature_verification(conn, params, _signature, payload_sha256) do
    raw_body = app_guard_raw_body(conn)
    canonical_body = canonical_app_guard_payload(params)
    normalized_sha = if blank?(payload_sha256), do: nil, else: normalize_hex(payload_sha256)

    payloads =
      [{"canonical_json", canonical_body}, {"raw_request_body", raw_body}]
      |> Enum.filter(fn {_name, value} -> is_binary(value) and value != "" end)
      |> Enum.uniq_by(fn {_name, value} -> value end)

    payload_match =
      Enum.find(payloads, fn {_name, value} ->
        secure_compare(normalized_sha || "", sha256_hex(value))
      end)

    %{
      raw_body: raw_body,
      canonical_body: canonical_body,
      payloads: payloads,
      payload_match: payload_match
    }
  end

  defp header(conn, name) do
    conn
    |> get_req_header(name)
    |> List.first()
  end

  defp app_guard_raw_body(conn) do
    case conn.assigns[:raw_body] || conn.private[:raw_body] do
      body when is_binary(body) -> body
      chunks when is_list(chunks) -> chunks |> Enum.reverse() |> Enum.join()
      _ -> nil
    end
  end

  defp app_guard_signing_secret do
    [
      Application.get_env(:tamandua_server, :app_guard_signing_secret),
      System.get_env(~s(TAMANDUA_APP_GUARD_SIGNING_SECRET)),
      System.get_env(~s(TAMANDUA_MOBILE_SDK_SIGNING_SECRET)),
      app_guard_signing_secret_file(~s(TAMANDUA_APP_GUARD_SIGNING_SECRET_FILE)),
      app_guard_signing_secret_file(~s(TAMANDUA_MOBILE_SDK_SIGNING_SECRET_FILE))
    ]
    |> Enum.find(&(is_binary(&1) and not blank?(&1)))
  end

  defp app_guard_signing_secret_file(env_name) do
    env_name
    |> System.get_env()
    |> read_app_guard_signing_secret_file()
  end

  defp read_app_guard_signing_secret_file(path) when is_binary(path) do
    path = String.trim(path)

    if blank?(path) do
      nil
    else
      case File.read(path) do
        {:ok, secret} -> String.trim(secret)
        _ -> nil
      end
    end
  end

  defp read_app_guard_signing_secret_file(_path), do: nil

  defp allowed_app_guard_signing_key_ids do
    [
      Application.get_env(:tamandua_server, :app_guard_signing_key_id),
      Application.get_env(:tamandua_server, :app_guard_signing_key_ids),
      System.get_env(~s(TAMANDUA_APP_GUARD_SIGNING_KEY_ID)),
      System.get_env(~s(TAMANDUA_MOBILE_SDK_SIGNING_KEY_ID))
    ]
    |> List.flatten()
    |> Enum.flat_map(fn
      value when is_binary(value) -> String.split(value, ",", trim: true)
      value when is_list(value) -> value
      _ -> []
    end)
    |> Enum.filter(&is_binary/1)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&blank?/1)
    |> Enum.uniq()
  end

  defp app_guard_replay_window_seconds do
    Application.get_env(:tamandua_server, :app_guard_replay_window_seconds, 300)
  end

  defp allow_unsigned_app_guard_ingestion? do
    Application.get_env(:tamandua_server, :allow_unsigned_app_guard_ingestion, false) == true and
      Application.get_env(:tamandua_server, :env, :prod) in [:dev, :test]
  end

  defp unsigned_app_guard_ingestion_metadata do
    %{
      "signed" => false,
      "anti_replay" => %{
        "checked" => false,
        "reason" => "unsigned_compatibility_mode"
      },
      "telemetry_quality" => %{
        "category" => "app_guard_ingestion",
        "status" => "accepted_unsigned_compatibility",
        "limitations" => [
          "HMAC signing headers were not present; payload origin cannot be cryptographically verified.",
          "Anti-replay checks require signed payload metadata."
        ]
      }
    }
  end

  defp signed_app_guard_ingestion_metadata(
         signing_key_id,
         payload_sha256,
         signature,
         nonce,
         request_timestamp,
         verification
       ) do
    {canonicalization, _payload} = verification.payload_match || {"unknown", nil}

    %{
      "signed" => true,
      "signature_algorithm" => "HMAC-SHA256",
      "signing_key_id" => signing_key_id,
      "payload_sha256" => normalize_hex(payload_sha256),
      "signature_sha256" => sha256_hex(normalize_signature(signature)),
      "canonicalization" => app_guard_canonicalization_name(canonicalization),
      "nonce" => nonce,
      "request_timestamp" => request_timestamp,
      "anti_replay" => %{
        "checked" => true,
        "method" => "persistent_payload_sha256_and_nonce_reservation",
        "window_seconds" => app_guard_replay_window_seconds()
      },
      "telemetry_quality" => %{
        "category" => "app_guard_ingestion",
        "status" => "signed_verified",
        "limitations" => []
      }
    }
    |> Enum.reject(fn {_key, value} -> is_nil(value) or value == "" end)
    |> Map.new()
  end

  defp app_guard_canonicalization_name("canonical_json"),
    do: "json-sort-keys-separators-comma-colon-utf8"

  defp app_guard_canonicalization_name("raw_request_body"), do: "raw_request_body_compatibility"
  defp app_guard_canonicalization_name(value), do: value

  defp canonical_app_guard_payload(value) do
    canonical_json(value)
  end

  defp canonical_json(value) when is_map(value) do
    encoded =
      value
      |> Enum.sort_by(fn {key, _value} -> to_string(key) end)
      |> Enum.map(fn {key, item} ->
        Jason.encode!(to_string(key)) <> ":" <> canonical_json(item)
      end)
      |> Enum.join(",")

    "{" <> encoded <> "}"
  end

  defp canonical_json(value) when is_list(value) do
    encoded =
      value
      |> Enum.map(&canonical_json/1)
      |> Enum.join(",")

    "[" <> encoded <> "]"
  end

  defp canonical_json(value), do: Jason.encode!(value)

  defp sha256_hex(value), do: :crypto.hash(:sha256, value) |> Base.encode16(case: :lower)

  defp hmac_sha256_hex(secret, value) do
    :crypto.mac(:hmac, :sha256, secret, value) |> Base.encode16(case: :lower)
  end

  defp app_guard_sha256?(value) when is_binary(value) do
    String.match?(value, ~r/\A[0-9a-fA-F]{64}\z/)
  end

  defp app_guard_sha256?(_value), do: false

  defp normalize_hex(value), do: value |> String.trim() |> String.downcase()

  defp normalize_signature("sha256=" <> digest), do: "sha256=" <> normalize_hex(digest)
  defp normalize_signature(value), do: value

  defp secure_compare(left, right) when is_binary(left) and is_binary(right) do
    byte_size(left) == byte_size(right) and Plug.Crypto.secure_compare(left, right)
  end

  defp secure_compare(_left, _right), do: false

  defp blank?(value), do: is_nil(value) or (is_binary(value) and String.trim(value) == "")

  defp require_string(errors, params, path) do
    case app_guard_contract_value(params, path) do
      value when is_binary(value) ->
        if String.trim(value) == "",
          do: [field_path(path) <> " is required" | errors],
          else: errors

      _ ->
        [field_path(path) <> " is required" | errors]
    end
  end

  defp require_integer_range(errors, params, path, min, max) do
    case app_guard_contract_value(params, path) do
      value when is_integer(value) and value >= min and value <= max ->
        errors

      _ ->
        ["#{field_path(path)} must be an integer from #{min} to #{max}" | errors]
    end
  end

  defp require_list(errors, params, path) do
    case app_guard_contract_value(params, path) do
      value when is_list(value) ->
        errors

      _ ->
        [field_path(path) <> " must be a list" | errors]
    end
  end

  defp validate_enum(errors, params, path, allowed) do
    value = app_guard_contract_value(params, path)

    normalized =
      if path == ["platform"] and is_binary(value) do
        value |> String.trim() |> String.downcase()
      else
        value
      end

    cond do
      is_nil(value) or value == "" ->
        errors

      normalized in allowed ->
        errors

      true ->
        ["#{field_path(path)} must be one of: #{Enum.join(allowed, ", ")}" | errors]
    end
  end

  defp validate_timestamp(errors, params, path) do
    case app_guard_contract_value(params, path) do
      value when is_binary(value) ->
        trimmed = String.trim(value)

        case DateTime.from_iso8601(trimmed) do
          {:ok, _datetime, _offset} ->
            errors

          {:error, _reason} ->
            case NaiveDateTime.from_iso8601(String.replace_suffix(trimmed, "Z", "")) do
              {:ok, _naive} -> errors
              {:error, _reason} -> [field_path(path) <> " must be ISO-8601" | errors]
            end
        end

      _ ->
        errors
    end
  end

  defp app_guard_contract_value(params, path) do
    Enum.reduce_while(path, params, fn key, current ->
      case current do
        value when is_map(value) -> {:cont, Map.get(value, key)}
        _ -> {:halt, nil}
      end
    end)
  end

  defp field_path(path), do: Enum.join(path, ".")

  defp app_guard_event_to_mobile_attrs(params, organization_id, device_id, ingestion_metadata) do
    app = Map.get(params, "app", %{})
    payload = Map.put(params, "server_ingestion", ingestion_metadata)

    %{
      "device_id" => device_id,
      "organization_id" => organization_id,
      "event_type" => params["event_type"],
      "severity" => params["severity"],
      "timestamp" => normalize_app_guard_timestamp(params["timestamp"]),
      "title" => "App Guard #{params["event_type"]}",
      "description" => app_guard_description(params),
      "payload" => payload,
      "app_bundle_id" => app["package_or_bundle_id"],
      "app_name" => app["display_name"],
      "rule_name" => "app_guard:#{params["event_type"]}",
      "rule_id" => params["event_id"],
      "processed" => true,
      "alerted" => false,
      "domain" => app_guard_evidence_value(params, "domain"),
      "remote_address" => app_guard_evidence_value(params, "remote_address"),
      "remote_port" => app_guard_evidence_value(params, "remote_port"),
      "latitude" => get_in(params, ["evidence", "latitude"]),
      "longitude" => get_in(params, ["evidence", "longitude"])
    }
  end

  defp app_guard_evidence_value(params, "domain") do
    first_app_guard_evidence_value(params, ["domain", "host", "hostname"])
  end

  defp app_guard_evidence_value(params, "remote_address") do
    first_app_guard_evidence_value(params, [
      "remote_address",
      "remote_ip",
      "destination_ip",
      "dst_ip"
    ])
  end

  defp app_guard_evidence_value(params, "remote_port") do
    first_app_guard_evidence_value(params, ["remote_port", "destination_port", "dst_port", "port"])
  end

  defp app_guard_evidence_value(params, field) do
    first_app_guard_evidence_value(params, [field])
  end

  defp first_app_guard_evidence_value(params, fields) do
    Enum.find_value(fields, fn field ->
      get_in(params, ["evidence", field]) ||
        get_in(params, ["evidence", "network", field]) ||
        get_in(params, ["network", field])
    end)
  end

  defp normalize_app_guard_timestamp(nil), do: utc_now()

  defp normalize_app_guard_timestamp(timestamp) when is_binary(timestamp) do
    trimmed = String.trim(timestamp)

    case DateTime.from_iso8601(trimmed) do
      {:ok, datetime, _offset} ->
        datetime
        |> DateTime.to_naive()
        |> NaiveDateTime.truncate(:second)

      {:error, _reason} ->
        case NaiveDateTime.from_iso8601(String.replace_suffix(trimmed, "Z", "")) do
          {:ok, naive} -> NaiveDateTime.truncate(naive, :second)
          {:error, _reason} -> utc_now()
        end
    end
  end

  defp normalize_app_guard_timestamp(timestamp), do: timestamp

  defp utc_now do
    NaiveDateTime.utc_now()
    |> NaiveDateTime.truncate(:second)
  end

  defp normalize_app_guard_platform(platform) when is_binary(platform) do
    case platform |> String.trim() |> String.downcase() do
      "ios" -> "ios"
      "iphoneos" -> "ios"
      "ipados" -> "ios"
      "android" -> "android"
      _ -> platform
    end
  end

  defp normalize_app_guard_platform(platform), do: platform

  defp app_guard_description(params) do
    risk = Map.get(params, "risk", %{})

    reasons =
      case Map.get(risk, "reasons", []) do
        values when is_list(values) -> Enum.join(values, ", ")
        value when is_binary(value) -> value
        _ -> ""
      end

    app_id = get_in(params, ["app", "package_or_bundle_id"]) || "unknown app"

    "App Guard event for #{app_id}; decision=#{risk["decision"]}; score=#{risk["score"]}; reasons=#{reasons}"
  end

  defp parse_int(nil, default), do: default

  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_int(value, _) when is_integer(value), do: value

  defp serialize_device(device) when is_map(device) do
    %{
      id: device.id,
      device_id: device.device_id,
      platform: device.platform,
      model: device.model,
      manufacturer: device.manufacturer,
      os_version: device.os_version,
      agent_version: device.agent_version,
      status: device.status,
      risk_score: device.risk_score,
      is_compromised: device.is_jailbroken or device.is_rooted,
      mdm_enrolled: device.mdm_enrolled,
      mdm_provider: device.mdm_provider,
      last_seen_at: format_datetime(device.last_seen_at),
      enrolled_at: format_datetime(device.enrolled_at)
    }
  end

  defp serialize_device_detail(device) when is_map(device) do
    serialize_device(device)
    |> Map.merge(%{
      serial_number: device.serial_number,
      ip_address: device.ip_address,
      user_email: device.user_email,
      user_name: device.user_name,
      department: device.department,
      security: %{
        is_jailbroken: device.is_jailbroken,
        is_rooted: device.is_rooted,
        passcode_enabled: device.passcode_enabled,
        encryption_enabled: device.encryption_enabled,
        biometric_enabled: device.biometric_enabled,
        developer_mode_enabled: device.developer_mode_enabled,
        usb_debugging_enabled: device.usb_debugging_enabled
      },
      risk_factors: device.risk_factors,
      mdm: %{
        enrolled: device.mdm_enrolled,
        provider: device.mdm_provider,
        device_id: device.mdm_device_id,
        compliance_status: device.mdm_compliance_status,
        last_sync: format_datetime(device.mdm_last_sync)
      },
      tags: device.tags,
      custom_attributes: device.custom_attributes
    })
  end

  defp loaded_assoc(struct, assoc) when is_map(struct) do
    value = Map.get(struct, assoc)
    if Ecto.assoc_loaded?(value), do: value, else: nil
  end

  defp loaded_assoc(_struct, _assoc), do: nil

  defp mobile_device_display_name(device) when is_map(device) do
    cond do
      is_binary(Map.get(device, :model)) and Map.get(device, :model) != "" ->
        Map.get(device, :model)

      is_binary(Map.get(device, :manufacturer)) and Map.get(device, :manufacturer) != "" ->
        Map.get(device, :manufacturer)

      is_binary(Map.get(device, :device_id)) and Map.get(device, :device_id) != "" ->
        "mobile-" <> String.slice(Map.get(device, :device_id), 0, 12)

      true ->
        "mobile-device"
    end
  end

  defp mobile_event_hostname(event, device) do
    payload = Map.get(event, :payload) || %{}

    first_present([
      Map.get(payload, "hostname"),
      Map.get(payload, "agent_hostname"),
      Map.get(payload, "device_name"),
      device && mobile_device_display_name(device),
      Map.get(event, :device_id)
    ])
  end

  defp mobile_event_agent_id(event, device) do
    payload = Map.get(event, :payload) || %{}

    first_present([
      resolved_payload_agent_id(event, Map.get(payload, "agent_id")),
      resolved_payload_agent_id(event, Map.get(payload, "agentId")),
      device && mobile_agent_id_for_device(device)
    ])
  end

  defp mobile_agent_id_for_device(%Device{} = device) do
    case get_agent_by_machine_id(device.organization_id, device.device_id) do
      %Agent{} = agent -> agent.id
      _ -> nil
    end
  end

  defp mobile_agent_id_for_device(%DeviceV2{} = device) do
    case get_agent_by_machine_id(device.organization_id, device.device_id) do
      %Agent{} = agent -> agent.id
      _ -> nil
    end
  end

  defp mobile_agent_id_for_device(_device), do: nil

  defp resolved_payload_agent_id(_event, value) when value in [nil, ""], do: nil

  defp resolved_payload_agent_id(event, value) when is_binary(value) do
    organization_id = Map.get(event, :organization_id) || Map.get(event, "organization_id")

    case get_agent_by_id_or_machine_id(organization_id, value) do
      %Agent{} = agent -> agent.id
      _ -> nil
    end
  end

  defp resolved_payload_agent_id(_event, _value), do: nil

  defp get_agent_by_machine_id(nil, _device_id), do: nil
  defp get_agent_by_machine_id(_organization_id, nil), do: nil

  defp get_agent_by_machine_id(organization_id, device_id) do
    Agent
    |> where([a], a.organization_id == ^organization_id and a.machine_id == ^device_id)
    |> Repo.one()
  end

  defp get_agent_by_id_or_machine_id(nil, _value), do: nil

  defp get_agent_by_id_or_machine_id(organization_id, value) do
    Agent
    |> where(
      [a],
      a.organization_id == ^organization_id and (a.id == ^value or a.machine_id == ^value)
    )
    |> Repo.one()
  end

  defp first_present(values) when is_list(values) do
    Enum.find(values, &(not is_nil(&1) and &1 != ""))
  end

  defp serialize_device_summary(device) when is_map(device) do
    %{
      id: device.id,
      device_id: device.device_id,
      display_name: mobile_device_display_name(device),
      platform: device.platform,
      model: device.model,
      manufacturer: Map.get(device, :manufacturer),
      os_version: Map.get(device, :os_version),
      user_email: Map.get(device, :user_email),
      user_name: Map.get(device, :user_name)
    }
  end

  defp serialize_device_summary(nil), do: nil

  defp serialize_app(app) do
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
      installed_at: format_datetime(app.installed_at)
    }
  end

  defp serialize_event(event) do
    device = loaded_assoc(event, :device)
    hostname = mobile_event_hostname(event, device)

    %{
      id: event.id,
      event_id: get_in(event.payload || %{}, ["event_id"]) || event.rule_id,
      event_type: event.event_type,
      source_type: "mobile",
      agent_id: mobile_event_agent_id(event, device),
      agentId: mobile_event_agent_id(event, device),
      hostname: hostname,
      agent_hostname: hostname,
      severity: event.severity,
      title: event.title,
      description: event.description,
      timestamp: format_datetime(event.timestamp),
      payload: event.payload,
      mitre_technique: event.mitre_technique,
      mitre_tactic: event.mitre_tactic,
      app_bundle_id: event.app_bundle_id,
      app_name: event.app_name,
      domain: event.domain,
      device: serialize_device_summary(device)
    }
  end

  defp serialize_app_guard_protected_app(app) do
    %{
      schema: "tamandua.app_guard.protected_app/v1",
      id: app.id,
      app_id: app.app_id,
      organization_id: app.organization_id,
      display_name: app.display_name,
      platform: app.platform,
      package_or_bundle_id: app.package_or_bundle_id,
      status: app.status,
      ingestion: app.ingestion,
      policy: app.policy,
      created_at: format_datetime(app.manifest_created_at),
      inserted_at: format_datetime(app.inserted_at),
      updated_at: format_datetime(app.updated_at)
    }
  end

  defp serialize_app_guard_build_manifest(manifest) do
    %{
      schema: "tamandua.app_guard.build_manifest/v1",
      id: manifest.id,
      build_id: manifest.build_id,
      app_id: manifest.app_id,
      organization_id: manifest.organization_id,
      platform: manifest.platform,
      version: manifest.version,
      artifact: manifest.artifact,
      signing: manifest.signing,
      sdk: manifest.sdk,
      policy_id: manifest.policy_id,
      created_at: format_datetime(manifest.manifest_created_at),
      inserted_at: format_datetime(manifest.inserted_at),
      updated_at: format_datetime(manifest.updated_at)
    }
  end

  defp serialize_app_guard_research_program(program) do
    %{
      schema: "tamandua.app_guard.research_program/v1",
      id: program.id,
      program_id: program.program_id,
      organization_id: program.organization_id,
      app: program.app,
      name: program.name,
      description: program.description,
      status: program.status,
      visibility: program.visibility,
      program_type: program.program_type,
      scope: program.scope,
      rules: program.rules,
      reward: program.reward,
      invited_researchers: program.invited_researchers,
      created_at: format_datetime(program.manifest_created_at),
      inserted_at: format_datetime(program.inserted_at),
      updated_at: format_datetime(program.updated_at)
    }
  end

  defp serialize_app_guard_research_submission(submission) do
    %{
      schema: "tamandua.app_guard.research_submission/v1",
      id: submission.id,
      submission_id: submission.submission_id,
      program_id: submission.program_id,
      organization_id: submission.organization_id,
      researcher_id: submission.researcher_id,
      title: submission.title,
      description: submission.description,
      severity: submission.severity,
      status: submission.status,
      cvss: submission.cvss,
      technical_details: submission.technical_details,
      evidence_links: submission.evidence_links,
      attachments: submission.attachments,
      validation: submission.validation,
      reward: submission.reward,
      submitted_at: format_datetime(submission.submitted_at),
      inserted_at: format_datetime(submission.inserted_at),
      updated_at: format_datetime(submission.updated_at)
    }
  end

  defp format_datetime(nil), do: nil
  defp format_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)

  # Records an audit trail entry for an MDM response action.
  defp audit_mdm_action(conn, action, device) do
    user = conn.assigns[:current_user]

    spawn(fn ->
      try do
        TamanduaServer.AuditLog.log_response_action(
          user,
          "mobile_#{action}",
          device.device_id,
          %{
            "device_db_id" => device.id,
            "platform" => device.platform,
            "model" => device.model,
            "mdm_provider" => device.mdm_provider,
            "mdm_enrolled" => device.mdm_enrolled
          }
        )
      rescue
        e ->
          Logger.warning("[MDM] Failed to create audit log for #{action}: #{inspect(e)}")
      end
    end)
  end

  # Formats MDM provider errors into user-friendly messages.
  defp format_mdm_error(:intune_not_configured),
    do: "Microsoft Intune is not configured. Set up credentials in Settings > Integrations."

  defp format_mdm_error(:jamf_not_configured),
    do: "Jamf Pro is not configured. Set up credentials in Settings > Integrations."

  defp format_mdm_error({:api_error, status, _body}),
    do: "MDM provider returned error (HTTP #{status}). Check provider configuration."

  defp format_mdm_error({:token_error, status}),
    do: "Failed to authenticate with MDM provider (HTTP #{status}). Check credentials."

  defp format_mdm_error({:request_failed, reason}),
    do: "Could not reach MDM provider: #{inspect(reason)}"

  defp format_mdm_error(other), do: "MDM operation failed: #{inspect(other)}"

  defp authorize_mobile_command(conn, command)
       when command in [
              "lock",
              "wipe",
              "locate",
              "ring",
              "remove_app",
              "enable_vpn",
              "push_policy",
              "push_config",
              "install_profile",
              "remove_profile",
              "update_policy",
              "refresh_network_policy",
              "collect_diagnostics",
              "managed_shell",
              "shell_execute",
              "screen_capture",
              "dns_status",
              "request_dns_vpn_consent",
              "enable_dns_protection",
              "disable_dns_protection",
              "clear_dns_cache",
              "block_domain",
              "unblock_domain",
              "network_status",
              "list_network_flows",
              "inspect_packet",
              "sync_app_inventory",
              "inspect_package"
            ] do
    user = conn.assigns[:current_user]

    if mobile_command_authorized?(user) do
      :ok
    else
      {:error, :forbidden}
    end
  end

  defp authorize_mobile_command(_conn, _command), do: :ok

  defp authorize_privileged_mobile_shell("shell_execute", %DeviceV2{} = device) do
    if privileged_mobile_shell_enabled?(device) do
      :ok
    else
      {:error, :privileged_shell_disabled}
    end
  end

  defp authorize_privileged_mobile_shell(_command_type, _device), do: :ok

  defp mobile_command_authorized?(%{role: role})
       when role in ["admin", "superadmin", "responder"],
       do: true

  defp mobile_command_authorized?(user) do
    RBAC.can?(user, :agents_command) or RBAC.can?(user, :response_execute)
  end

  defp privileged_mobile_shell_enabled?(%DeviceV2{} = device) do
    case get_device_v2_agent(device.organization_id, device.device_id) do
      %Agent{} = agent -> privileged_mobile_shell_enabled?(agent)
      _ -> false
    end
  end

  defp privileged_mobile_shell_enabled?(%Agent{} = agent) do
    config = agent.config || %{}
    capabilities = config["capabilities"] || config[:capabilities] || %{}

    truthy_config?(config["allow_privileged_shell"] || config[:allow_privileged_shell]) or
      truthy_config?(
        config["tamandua.endpoint.allow_privileged_shell"] ||
          config[:tamandua_endpoint_allow_privileged_shell]
      ) or
      truthy_config?(capabilities["privileged_shell"] || capabilities[:privileged_shell]) or
      truthy_config?(capabilities["shell_execute"] || capabilities[:shell_execute]) or
      capabilities["shell"] in ["privileged", "privileged_mobile_runtime"] or
      capabilities[:shell] in ["privileged", "privileged_mobile_runtime"]
  end

  defp privileged_mobile_shell_enabled?(_value), do: false

  defp truthy_config?(value)
       when value in [true, "true", "1", "yes", "enabled", "available", "ready"],
       do: true

  defp truthy_config?(_value), do: false

  defp registry_stats_for_devices(devices) do
    now = NaiveDateTime.utc_now()
    stale_threshold = 24 * 3600

    %{
      total: length(devices),
      active: Enum.count(devices, &(&1.status == "active")),
      ios: Enum.count(devices, &(&1.platform == "ios")),
      android: Enum.count(devices, &(&1.platform == "android")),
      compliant: Enum.count(devices, &(&1.compliance_status == "compliant")),
      non_compliant: Enum.count(devices, &(&1.compliance_status == "non_compliant")),
      mdm_enrolled: Enum.count(devices, &(&1.mdm_enrolled == true)),
      high_risk: Enum.count(devices, &((&1.risk_score || 0) >= 50)),
      stale: Enum.count(devices, &stale_registry_device?(&1, now, stale_threshold)),
      updated_at: DateTime.utc_now()
    }
  end

  defp stale_registry_device?(%{last_seen_at: nil}, _now, _threshold), do: true

  defp stale_registry_device?(%{last_seen_at: last_seen}, now, threshold) do
    NaiveDateTime.diff(now, last_seen) >= threshold
  end

  # ---------------------------------------------------------------------------
  # V2 filter helpers
  # ---------------------------------------------------------------------------

  defp get_device_v2_for_org(_organization_id, nil), do: nil
  defp get_device_v2_for_org(_organization_id, ""), do: nil

  defp get_device_v2_for_org(organization_id, id) do
    import Ecto.Query

    DeviceV2
    |> DeviceV2.by_organization(organization_id)
    |> where([d], d.id == ^id or d.device_id == ^id)
    |> Repo.one()
  end

  defp get_device_v2_by_external_id(_organization_id, nil), do: nil
  defp get_device_v2_by_external_id(_organization_id, ""), do: nil

  defp get_device_v2_by_external_id(organization_id, device_id) do
    import Ecto.Query

    DeviceV2
    |> DeviceV2.by_organization(organization_id)
    |> where([d], d.device_id == ^device_id)
    |> Repo.one()
  end

  defp get_command_for_org(_organization_id, nil), do: nil
  defp get_command_for_org(_organization_id, ""), do: nil

  defp get_command_for_org(organization_id, id) do
    import Ecto.Query

    MDMCommand
    |> MDMCommand.by_organization(organization_id)
    |> where([c], c.id == ^id)
    |> Repo.one()
  end

  defp maybe_filter_v2_platform(query, nil), do: query
  defp maybe_filter_v2_platform(query, ""), do: query
  defp maybe_filter_v2_platform(query, platform), do: DeviceV2.by_platform(query, platform)

  defp maybe_filter_v2_compliance(query, nil), do: query
  defp maybe_filter_v2_compliance(query, ""), do: query
  defp maybe_filter_v2_compliance(query, status), do: DeviceV2.by_compliance(query, status)

  defp maybe_filter_v2_mdm(query, nil), do: query
  defp maybe_filter_v2_mdm(query, "true"), do: DeviceV2.mdm_enrolled_only(query)
  defp maybe_filter_v2_mdm(query, _), do: query

  defp maybe_filter_command_device(query, nil), do: query
  defp maybe_filter_command_device(query, ""), do: query
  defp maybe_filter_command_device(query, device_id), do: MDMCommand.by_device(query, device_id)

  defp maybe_filter_command_status(query, nil), do: query
  defp maybe_filter_command_status(query, ""), do: query
  defp maybe_filter_command_status(query, status), do: MDMCommand.by_status(query, status)

  defp maybe_filter_command_type(query, nil), do: query
  defp maybe_filter_command_type(query, ""), do: query
  defp maybe_filter_command_type(query, command_type), do: MDMCommand.by_type(query, command_type)

  defp maybe_filter_command_alert(query, nil), do: query
  defp maybe_filter_command_alert(query, ""), do: query

  defp maybe_filter_command_alert(query, alert_id) do
    from(c in query,
      where:
        fragment("?->>'alert_id' = ?", c.payload, ^alert_id) or
          fragment("?->'filters'->>'alert_id' = ?", c.payload, ^alert_id)
    )
  end

  defp validate_mobile_command_alert(_organization_id, nil), do: :ok
  defp validate_mobile_command_alert(_organization_id, ""), do: :ok

  defp validate_mobile_command_alert(organization_id, alert_id) do
    with {:ok, alert_uuid} <- Ecto.UUID.cast(alert_id),
         %Alert{} <- Repo.get_by(Alert, id: alert_uuid, organization_id: organization_id) do
      :ok
    else
      _ -> {:error, :alert_not_found}
    end
  end

  defp command_alert_id(params) when is_map(params) do
    params["alert_id"] ||
      get_in(params, ["payload", "alert_id"]) ||
      get_in(params, ["payload", "filters", "alert_id"])
  end

  defp command_alert_id(_params), do: nil

  defp normalize_mobile_command_attrs(attrs, %DeviceV2{} = device) do
    command_type = attrs["command_type"]

    payload =
      command_type
      |> normalize_mobile_network_payload(attrs["payload"] || %{}, attrs, device)
      |> put_common_command_payload(attrs)

    attrs
    |> Map.put("payload", payload)
    |> maybe_mark_unavailable_packet_collector(command_type, device)
  end

  defp normalize_mobile_network_payload("network_status", payload, params, %DeviceV2{} = device) do
    payload
    |> ensure_map()
    |> put_common_network_payload(params, device)
    |> Map.put_new("schema", "tamandua.mobile.network_status.request/v1")
    |> Map.put_new("collector", "mobile_network_status")
    |> Map.put_new("fields", ["connectivity", "interface", "ip_address", "dns", "vpn"])
    |> Map.put_new("visibility_mode", "mobile_os_metadata")
    |> Map.put_new("limitations", mobile_network_limitations(device.platform, "network_status"))
  end

  defp normalize_mobile_network_payload(
         "list_network_flows",
         payload,
         params,
         %DeviceV2{} = device
       ) do
    payload
    |> ensure_map()
    |> put_common_network_payload(params, device)
    |> Map.put_new("schema", "tamandua.mobile.network_flows.request/v1")
    |> Map.put_new("collector", "dns_forwarder")
    |> Map.put_new("coverage", "dns_forwarder_counters_only_no_pcap")
    |> Map.put_new("requires_collector", "dns_forwarder_or_packet_collector")
    |> Map.put_new("visibility_mode", "dns_metadata_summary")
    |> Map.put_new("alternative_visibility", ["dns_status", "network_status"])
    |> Map.put_new(
      "limitations",
      mobile_network_limitations(device.platform, "list_network_flows")
    )
    |> Map.put("filters", network_filters(payload, params, device))
    |> Map.put_new("limit", parse_int(payload["limit"] || params["limit"], 100))
  end

  defp normalize_mobile_network_payload("inspect_packet", payload, params, %DeviceV2{} = device) do
    payload
    |> ensure_map()
    |> put_common_network_payload(params, device)
    |> Map.put_new("schema", "tamandua.mobile.packet_inspection.request/v1")
    |> Map.put_new("collector", "packet_collector")
    |> Map.put_new("requires_collector", "packet_collector")
    |> Map.put_new("visibility_mode", "packet_collector_required")
    |> Map.put_new("fallback_commands", ["list_network_flows", "dns_status", "network_status"])
    |> Map.put_new("limitations", mobile_network_limitations(device.platform, "inspect_packet"))
    |> Map.put("filters", network_filters(payload, params, device))
  end

  defp normalize_mobile_network_payload(_command_type, payload, _params, _device),
    do: ensure_map(payload)

  defp put_common_command_payload(payload, params) do
    payload
    |> ensure_map()
    |> maybe_put(
      "alert_id",
      command_alert_id(%{"alert_id" => params["alert_id"], "payload" => payload})
    )
  end

  defp put_common_network_payload(payload, params, %DeviceV2{} = device) do
    payload
    |> Map.put_new("device_id", device.id)
    |> Map.put_new("external_device_id", device.device_id)
    |> Map.put_new("platform", device.platform)
    |> maybe_put(
      "alert_id",
      command_alert_id(%{"alert_id" => params["alert_id"], "payload" => payload})
    )
    |> Map.put_new("requested_at", DateTime.utc_now() |> DateTime.to_iso8601())
  end

  defp network_filters(payload, params, %DeviceV2{} = device) do
    existing = ensure_map(payload["filters"])

    existing
    |> Map.put_new("device_id", device.id)
    |> Map.put_new("external_device_id", device.device_id)
    |> maybe_put(
      "alert_id",
      command_alert_id(%{"alert_id" => params["alert_id"], "payload" => payload}) ||
        existing["alert_id"]
    )
    |> maybe_put("remote_address", payload["remote_address"] || params["remote_address"])
    |> maybe_put("remote_port", payload["remote_port"] || params["remote_port"])
    |> maybe_put("protocol", payload["protocol"] || params["protocol"])
    |> maybe_put("domain", payload["domain"] || params["domain"])
  end

  defp maybe_mark_unavailable_packet_collector(attrs, command_type, %DeviceV2{} = device)
       when command_type in ["inspect_packet"] do
    capabilities = mobile_device_capabilities(device)

    if packet_collector_available?(capabilities) do
      attrs
    else
      result = packet_collector_unavailable_result(command_type, device, attrs["payload"])

      attrs
      |> Map.put("status", "failed")
      |> Map.put("result", result)
      |> Map.put("completed_at", DateTime.utc_now())
    end
  end

  defp maybe_mark_unavailable_packet_collector(attrs, _command_type, _device), do: attrs

  defp normalize_mobile_command_status_updates(updates, %MDMCommand{} = command) do
    result = normalize_mobile_network_result(command.command_type, updates["result"])

    updates =
      if is_nil(result), do: updates, else: Map.put(updates, "result", result)

    if packet_collector_unavailable_result?(result) do
      Map.put(updates, "status", "failed")
    else
      updates
    end
  end

  defp normalize_mobile_network_result(command_type, result)
       when command_type in ["network_status", "list_network_flows", "inspect_packet"] and
              is_map(result) do
    result
    |> Map.put_new("schema", mobile_network_result_schema(command_type))
    |> Map.put_new("command_type", command_type)
    |> Map.put_new("completed_at", DateTime.utc_now() |> DateTime.to_iso8601())
    |> enrich_mobile_network_result(command_type)
  end

  defp normalize_mobile_network_result(_command_type, result), do: result

  defp mobile_network_result_schema("network_status"),
    do: "tamandua.mobile.network_status.result/v1"

  defp mobile_network_result_schema("list_network_flows"),
    do: "tamandua.mobile.network_flows.result/v1"

  defp mobile_network_result_schema("inspect_packet"),
    do: "tamandua.mobile.packet_inspection.result/v1"

  defp packet_collector_unavailable_result(command_type, %DeviceV2{} = device, payload) do
    payload = ensure_map(payload)

    %{
      "schema" => mobile_network_result_schema(command_type),
      "ok" => false,
      "executed" => false,
      "command_type" => command_type,
      "collector" => "packet_collector",
      "reason" => "requires_packet_collector",
      "message" =>
        "Packet/network flow inspection is not available for this mobile endpoint because no packet_collector capability is registered.",
      "visibility_mode" => "degraded_dns_metadata_available",
      "fallback_commands" => ["list_network_flows", "dns_status", "network_status"],
      "alternative_visibility" => %{
        "dns_forwarder" =>
          "DNS query counters, last query and block decisions when the Android/iOS endpoint collector reports them.",
        "network_status" => "OS connectivity, interface, IP, DNS and VPN posture metadata.",
        "app_guard" => "Protected-app network evidence when emitted by the App Guard SDK."
      },
      "limitations" => mobile_network_limitations(device.platform, command_type),
      "device_id" => device.id,
      "external_device_id" => device.device_id,
      "platform" => device.platform,
      "filters" => ensure_map(payload["filters"]),
      "completed_at" => DateTime.utc_now() |> DateTime.to_iso8601()
    }
  end

  defp packet_collector_unavailable_result?(%{
         "ok" => false,
         "reason" => "requires_packet_collector"
       }),
       do: true

  defp packet_collector_unavailable_result?(%{ok: false, reason: "requires_packet_collector"}),
    do: true

  defp packet_collector_unavailable_result?(_result), do: false

  defp enrich_mobile_network_result(result, "inspect_packet") do
    if packet_collector_unavailable_result?(result) do
      result
      |> Map.put_new("collector", "packet_collector")
      |> Map.put_new("visibility_mode", "degraded_dns_metadata_available")
      |> Map.put_new("fallback_commands", ["list_network_flows", "dns_status", "network_status"])
      |> Map.put_new(
        "limitations",
        mobile_network_limitations(result["platform"], "inspect_packet")
      )
      |> Map.put_new(
        "message",
        "Packet/network flow inspection is not available for this mobile endpoint because no packet_collector capability is registered."
      )
    else
      result
    end
  end

  defp enrich_mobile_network_result(result, _command_type), do: result

  defp mobile_device_capabilities(%DeviceV2{} = device) do
    agent = get_device_v2_agent(device.organization_id, device.device_id)
    config = (agent && agent.config) || %{}
    config["capabilities"] || config[:capabilities] || %{}
  end

  defp packet_collector_available?(capabilities) when is_map(capabilities) do
    packet =
      capabilities["packet_collector"] ||
        capabilities[:packet_collector] ||
        capabilities["network_dpi"] ||
        capabilities[:network_dpi]

    packet in [true, "true", "available", "enabled", "ready"]
  end

  defp packet_collector_available?(_capabilities), do: false

  defp mobile_network_limitations(platform, "network_status") do
    [
      "#{platform || "mobile"} OS network posture only",
      "no packet payload capture",
      "no historical flow reconstruction"
    ]
  end

  defp mobile_network_limitations(platform, "list_network_flows") do
    [
      "#{platform || "mobile"} DNS/flow visibility depends on native collector availability",
      "dns_forwarder coverage is metadata/counter based unless packet_collector is registered",
      "encrypted DNS over HTTPS/TLS/QUIC is not decoded without a dedicated packet or proxy collector",
      "per-app attribution is best-effort and not guaranteed by the current mobile app endpoint"
    ]
  end

  defp mobile_network_limitations(platform, "inspect_packet") do
    [
      "#{platform || "mobile"} packet inspection requires explicit packet_collector or network_dpi capability",
      "no PCAP or payload inspection is claimed by the mobile app endpoint by default",
      "use list_network_flows, dns_status and App Guard evidence as fallback visibility"
    ]
  end

  defp mobile_network_limitations(platform, _command_type) do
    [
      "#{platform || "mobile"} network visibility is capability-gated",
      "unsupported collectors must return explicit degraded state"
    ]
  end

  defp ensure_map(value) when is_map(value), do: value
  defp ensure_map(_value), do: %{}

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, _key, ""), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp sync_device_v2_agent(%DeviceV2{} = device, sync_attrs) do
    case upsert_device_v2_agent(device, sync_attrs) do
      {:ok, _agent} ->
        :ok

      {:error, reason} ->
        Logger.warning(
          "[MobileController] failed to sync mobile v2 device #{device.device_id} as agent: #{inspect(reason)}"
        )

        :error
    end
  end

  defp sync_device_v2_agent(%DeviceV2{} = device, %Agent{} = agent, sync_attrs) do
    case Agents.update_agent(agent, device_v2_agent_attrs(device, agent, sync_attrs)) do
      {:ok, _agent} ->
        :ok

      {:error, reason} ->
        Logger.warning(
          "[MobileController] failed to sync mobile v2 device #{device.device_id} with agent #{agent.id}: #{inspect(reason)}"
        )

        :error
    end
  end

  defp upsert_device_v2_agent(%DeviceV2{} = device, sync_attrs) do
    case get_device_v2_agent(device.organization_id, device.device_id) do
      nil ->
        Agents.create_agent_for_org(
          device.organization_id,
          device_v2_agent_attrs(device, %Agent{}, sync_attrs)
        )

      %Agent{} = agent ->
        Agents.update_agent(agent, device_v2_agent_attrs(device, agent, sync_attrs))
    end
  end

  defp get_device_v2_agent(organization_id, device_id) do
    Agent
    |> where([a], a.organization_id == ^organization_id and a.machine_id == ^device_id)
    |> Repo.one()
  end

  defp serialize_device_v2_agent_projection(%Agent{} = agent) do
    %{
      ok: true,
      agent_id: agent.id,
      machine_id: agent.machine_id,
      status: agent.status,
      agent_version: agent.agent_version,
      source: get_in(agent.config || %{}, ["source"]) || "tamandua_mobile_v2"
    }
  end

  defp device_v2_agent_attrs(%DeviceV2{} = device, %Agent{} = agent, sync_attrs) do
    %{
      hostname: device_v2_hostname(device),
      os_type: device.platform || agent.os_type || "android",
      os_version: device.os_version || agent.os_version,
      agent_version: agent.agent_version || "mobile-v2",
      machine_id: device.device_id,
      status: "online",
      last_seen_at: device_v2_naive_time(device.last_seen_at) || utc_now(),
      config: device_v2_agent_config(device, agent.config || %{}, sync_attrs),
      tags: device_v2_agent_tags(agent.tags || [], device)
    }
  end

  defp device_v2_hostname(%DeviceV2{} = device) do
    cond do
      is_binary(device.device_name) and device.device_name != "" -> device.device_name
      is_binary(device.model) and device.model != "" -> device.model
      true -> "mobile-" <> String.slice(device.device_id || device.id || "unknown", 0, 12)
    end
  end

  defp device_v2_agent_config(%DeviceV2{} = device, existing_config, sync_attrs) do
    shell_enabled =
      privileged_mobile_shell_sync_enabled?(existing_config) ||
        privileged_mobile_shell_sync_enabled?(sync_attrs)

    shell_capabilities =
      if shell_enabled do
        %{
          "live_response" => "mobile_shell",
          "shell" => "privileged_mobile_runtime",
          "privileged_shell" => true,
          "shell_execute" => true
        }
      else
        %{
          "live_response" => "mdm_actions_only",
          "shell" => "unavailable"
        }
      end

    reported_capabilities =
      existing_config
      |> Map.get("capabilities", %{})
      |> normalize_capability_map()
      |> Map.merge(
        normalize_capability_map(sync_attrs["capabilities"] || sync_attrs[:capabilities])
      )

    reported_posture = mobile_endpoint_posture_sync_config(sync_attrs)

    native_endpoint_agent =
      native_endpoint_agent_reported?(
        existing_config,
        sync_attrs,
        reported_capabilities,
        reported_posture
      )

    Map.merge(existing_config, %{
      "source" => "tamandua_mobile_v2",
      "mobile_device_v2_id" => device.id,
      "mobile_device_external_id" => device.device_id,
      "mobile_owner_email" => device.owner_email,
      "model" => device.model,
      "mdm_enrolled" => device.mdm_enrolled,
      "mdm_provider" => device.mdm_provider,
      "compliance_status" => device.compliance_status,
      "live_response" => shell_capabilities["live_response"],
      "tamandua.endpoint.allow_privileged_shell" => shell_enabled,
      "posture" =>
        Map.merge(mobile_endpoint_posture_from_config(existing_config), reported_posture),
      "capabilities" =>
        %{
          "endpoint_telemetry" => "mobile",
          "native_endpoint_agent" => native_endpoint_agent
        }
        |> Map.merge(reported_capabilities)
        |> Map.merge(shell_capabilities)
        |> Map.put("native_endpoint_agent", native_endpoint_agent)
    })
  end

  defp normalize_capability_map(value) when is_map(value), do: value
  defp normalize_capability_map(_value), do: %{}

  defp native_endpoint_agent_reported?(
         existing_config,
         sync_attrs,
         reported_capabilities,
         reported_posture
       ) do
    existing_capabilities =
      existing_config
      |> Map.get("capabilities", %{})
      |> normalize_capability_map()

    existing_posture = mobile_endpoint_posture_from_config(existing_config)

    Enum.any?(
      [
        reported_capabilities["native_endpoint_agent"],
        reported_capabilities[:native_endpoint_agent],
        existing_capabilities["native_endpoint_agent"],
        existing_capabilities[:native_endpoint_agent],
        sync_attrs["native_available"],
        sync_attrs[:native_available],
        reported_posture["native_available"],
        reported_posture[:native_available],
        existing_posture["native_available"],
        existing_posture[:native_available]
      ],
      &truthy_config?/1
    )
  end

  defp mobile_endpoint_posture_sync_config(sync_attrs) when is_map(sync_attrs) do
    security_checks = ensure_map(sync_attrs["security_checks"] || sync_attrs[:security_checks])
    hardening = ensure_map(sync_attrs["hardening"] || sync_attrs[:hardening])
    risk_score = sync_attrs["risk_score"] || sync_attrs[:risk_score]
    risk_factors = sync_attrs["risk_factors"] || sync_attrs[:risk_factors]
    native_available = sync_attrs["native_available"] || sync_attrs[:native_available]

    collected_at =
      sync_attrs["collected_at"] || sync_attrs[:collected_at] ||
        sync_attrs["last_seen"] || sync_attrs[:last_seen]

    %{}
    |> maybe_put_non_empty_map("security_checks", security_checks)
    |> maybe_put_non_empty_map("hardening", hardening)
    |> maybe_put("risk_score", risk_score)
    |> maybe_put("risk_factors", risk_factors)
    |> maybe_put("native_available", native_available)
    |> maybe_put("last_assessment", collected_at)
  end

  defp mobile_endpoint_posture_sync_config(_sync_attrs), do: %{}

  defp maybe_put_non_empty_map(map, _key, nil), do: map

  defp maybe_put_non_empty_map(map, _key, value) when is_map(value) and map_size(value) == 0,
    do: map

  defp maybe_put_non_empty_map(map, key, value) when is_map(value), do: Map.put(map, key, value)
  defp maybe_put_non_empty_map(map, _key, _value), do: map

  defp privileged_mobile_shell_sync_enabled?(value) when is_map(value) do
    capabilities = value["capabilities"] || value[:capabilities] || %{}

    truthy_config?(value["allow_privileged_shell"] || value[:allow_privileged_shell]) ||
      truthy_config?(
        value["tamandua.endpoint.allow_privileged_shell"] ||
          value[:tamandua_endpoint_allow_privileged_shell]
      ) ||
      truthy_config?(value["privileged_shell"] || value[:privileged_shell]) ||
      truthy_config?(value["shell_execute"] || value[:shell_execute]) ||
      truthy_config?(capabilities["privileged_shell"] || capabilities[:privileged_shell]) ||
      truthy_config?(capabilities["shell_execute"] || capabilities[:shell_execute]) ||
      capabilities["shell"] in ["privileged", "privileged_mobile_runtime"] ||
      capabilities[:shell] in ["privileged", "privileged_mobile_runtime"]
  end

  defp privileged_mobile_shell_sync_enabled?(_value), do: false

  defp device_v2_agent_tags(existing_tags, %DeviceV2{} = device) do
    (existing_tags ++ ["mobile", "mobile-v2", device.platform, device.mdm_provider])
    |> Enum.filter(&(is_binary(&1) and &1 != ""))
    |> Enum.uniq()
  end

  defp device_v2_naive_time(%DateTime{} = value), do: DateTime.to_naive(value)
  defp device_v2_naive_time(%NaiveDateTime{} = value), do: value
  defp device_v2_naive_time(_value), do: nil

  defp device_v2_datetime(%DateTime{} = value), do: value

  defp device_v2_datetime(%NaiveDateTime{} = value) do
    DateTime.from_naive!(value, "Etc/UTC")
  end

  defp device_v2_datetime(_value), do: nil

  # ---------------------------------------------------------------------------
  # V2 serializers
  # ---------------------------------------------------------------------------

  defp serialize_device_v2(d) when is_map(d) do
    agent = get_device_v2_agent(d.organization_id, d.device_id)
    agent_config = (agent && agent.config) || %{}
    capabilities = mobile_agent_capabilities(agent_config)
    reported_posture = mobile_endpoint_posture_from_config(agent_config)

    security_checks =
      ensure_map(reported_posture["security_checks"] || reported_posture[:security_checks])

    hardening = ensure_map(reported_posture["hardening"] || reported_posture[:hardening])

    %{
      id: d.id,
      device_id: d.device_id,
      agent_id: agent && agent.id,
      agent_status: agent && agent.status,
      agent_version: agent && agent.agent_version,
      agent_last_seen_at: agent && format_datetime(agent.last_seen_at),
      live_response: agent_config["live_response"] || agent_config[:live_response],
      capabilities: capabilities,
      command_identity: %{
        command_device_id: d.id,
        external_device_id: d.device_id,
        agent_machine_id: agent && agent.machine_id,
        background_sync_device_id: d.id
      },
      device_name: d.device_name,
      platform: d.platform,
      os_version: d.os_version,
      model: d.model,
      serial_number: d.serial_number,
      owner_email: d.owner_email,
      mdm_enrolled: d.mdm_enrolled,
      mdm_provider: d.mdm_provider,
      compliance_status: d.compliance_status,
      encryption_enabled: d.encryption_enabled,
      jailbroken: d.jailbroken,
      passcode_set: d.passcode_set,
      security_checks: security_checks,
      hardening: hardening,
      risk_score:
        reported_posture["risk_score"] || reported_posture[:risk_score] ||
          if(d.jailbroken, do: 85, else: 0),
      last_seen_at: format_datetime(d.last_seen_at),
      enrolled_at: format_datetime(d.enrolled_at),
      inserted_at: format_datetime(d.inserted_at),
      updated_at: format_datetime(d.updated_at)
    }
  end

  defp mobile_agent_capabilities(config) when is_map(config) do
    config
    |> Map.get("capabilities", config[:capabilities] || %{})
    |> normalize_capability_map()
  end

  defp mobile_agent_capabilities(_config), do: %{}

  defp serialize_command(c) when is_map(c) do
    %{
      id: c.id,
      device_id: c.device_id,
      command_type: c.command_type,
      status: c.status,
      payload: c.payload,
      result: c.result,
      sent_at: format_datetime(c.sent_at),
      completed_at: format_datetime(c.completed_at),
      requested_by: c.requested_by,
      inserted_at: format_datetime(c.inserted_at)
    }
  end
end
