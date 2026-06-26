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

  NOTE: This is a foundation/stub implementation. Full mobile agent
  support requires native iOS/Android agent development.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Mobile
  alias TamanduaServer.Mobile.Device
  alias TamanduaServer.Mobile.MDMProvider
  alias TamanduaServer.Mobile.DeviceRegistry
  alias TamanduaServer.Mobile.ThreatDetection
  alias TamanduaServer.Mobile.AppInventory

  # V2 schemas for the new mobile_devices_v2 / mdm_commands tables
  alias TamanduaServer.Mobile.DeviceV2
  alias TamanduaServer.Mobile.MDMCommand
  alias TamanduaServer.Repo

  require Logger

  action_fallback TamanduaServerWeb.FallbackController

  # ============================================================================
  # Device Management
  # ============================================================================

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
    device = Mobile.get_device!(id)
    json(conn, %{data: serialize_device_detail(device)})
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

    case Mobile.register_device(attrs) do
      {:ok, device} ->
        conn
        |> put_status(:created)
        |> json(%{
          data: serialize_device(device),
          message: "Device registered successfully. Awaiting approval."
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
    device = Mobile.get_device!(id)

    case Mobile.update_device(device, params) do
      {:ok, updated_device} ->
        json(conn, %{data: serialize_device(updated_device)})

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  DELETE /api/v1/mobile/devices/:id

  Removes a mobile device from management.
  """
  def delete(conn, %{"id" => id}) do
    device = Mobile.get_device!(id)

    case Mobile.delete_device(device) do
      {:ok, _} ->
        send_resp(conn, :no_content, "")

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  GET /api/v1/mobile/devices/:id/posture

  Gets the security posture for a specific device.
  """
  def device_posture(conn, %{"id" => id}) do
    device = Mobile.get_device!(id)

    posture = %{
      device_id: device.id,
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
      last_assessment: device.updated_at
    }

    json(conn, %{data: posture})
  end

  @doc """
  POST /api/v1/mobile/devices/:id/posture

  Updates security posture from agent telemetry.
  """
  def update_posture(conn, %{"id" => id} = params) do
    device = Mobile.get_device!(id)

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
  end

  # ============================================================================
  # App Inventory
  # ============================================================================

  @doc """
  GET /api/v1/mobile/devices/:id/apps

  Lists installed apps on a device.
  """
  def device_apps(conn, %{"id" => id} = params) do
    _device = Mobile.get_device!(id)

    opts = [
      limit: parse_int(params["limit"], 500),
      order_by: :app_name
    ]

    apps = Mobile.list_device_apps(id, opts)

    json(conn, %{
      data: Enum.map(apps, &serialize_app/1),
      meta: %{total: length(apps)}
    })
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
  def sync_apps(conn, %{"id" => id, "apps" => apps_data}) do
    _device = Mobile.get_device!(id)

    case Mobile.sync_device_apps(id, apps_data) do
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
      data: Enum.map(apps, fn app ->
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
      data: Enum.map(apps, fn app ->
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
    _device = Mobile.get_device!(id)

    opts = [
      limit: parse_int(params["limit"], 100),
      offset: parse_int(params["offset"], 0),
      severity: params["severity"]
    ]

    events = Mobile.list_device_events(id, opts)

    json(conn, %{
      data: Enum.map(events, &serialize_event/1)
    })
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
      data: Enum.map(events, fn event ->
        serialize_event(event)
        |> Map.put(:device, serialize_device_summary(event.device))
      end)
    })
  end

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
  def ingest_events(conn, %{"device_id" => device_id, "events" => events_data}) do
    organization_id = get_organization_id(conn)

    case get_legacy_device_for_org(organization_id, device_id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "Device not found"})

      device ->
        # Update last seen
        Mobile.touch_device(device)

        # Prepare events with device/org context
        prepared_events = Enum.map(events_data, fn event ->
          event
          |> Map.put("device_id", device_id)
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

  @doc """
  POST /api/v1/mobile/app_guard/events

  Ingests one normalized App Guard SDK event.
  """
  def ingest_app_guard_event(conn, %{"schema" => "tamandua.app_guard.event/v1"} = params) do
    organization_id = get_organization_id(conn)

    with {:ok, device} <- ensure_app_guard_device(organization_id, params),
         attrs <- app_guard_event_to_mobile_attrs(params, organization_id, device.id),
         {:ok, event} <- Mobile.ingest_event(attrs) do
      conn
      |> put_status(:created)
      |> json(%{
        success: true,
        data: serialize_event(event)
      })
    else
      {:error, :invalid_device} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "Invalid App Guard device payload"})

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  def ingest_app_guard_event(conn, _params) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "Unsupported App Guard event schema"})
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
    device = Mobile.get_device!(id)
    provider = MDMProvider.provider_for_device(device)
    mdm_device_id = device.mdm_device_id || device.device_id

    audit_mdm_action(conn, "lock_device", device)

    case provider.lock_device(mdm_device_id, params) do
      {:ok, result} ->
        Logger.info("[MDM] Lock command sent: device=#{device.device_id} provider=#{inspect(provider)}")
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
  end

  @doc """
  POST /api/v1/mobile/devices/:id/wipe

  Sends remote wipe command to device via the configured MDM provider.
  Supports wipe_type: "full" or "enterprise_only" (default).
  """
  def wipe_device(conn, %{"id" => id} = params) do
    device = Mobile.get_device!(id)
    provider = MDMProvider.provider_for_device(device)
    mdm_device_id = device.mdm_device_id || device.device_id

    audit_mdm_action(conn, "wipe_device", device)

    case provider.wipe_device(mdm_device_id, params) do
      {:ok, result} ->
        # Mark device as wiped in our records
        Mobile.mark_device_wiped(device)

        Logger.info("[MDM] Wipe command sent: device=#{device.device_id} type=#{params["wipe_type"] || "enterprise_only"}")
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
  end

  @doc """
  POST /api/v1/mobile/devices/:id/locate

  Requests device location. Returns last known location from our records.
  """
  def locate_device(conn, %{"id" => id}) do
    device = Mobile.get_device!(id)

    location = device.last_location || %{
      note: "Location not available. Device must have location services enabled."
    }

    json(conn, %{
      success: true,
      device_id: device.device_id,
      location: location
    })
  end

  @doc """
  POST /api/v1/mobile/devices/:id/message

  Sends a message to the device via MDM lock screen message.
  """
  def send_message(conn, %{"id" => id, "message" => message} = params) do
    device = Mobile.get_device!(id)
    provider = MDMProvider.provider_for_device(device)
    mdm_device_id = device.mdm_device_id || device.device_id

    # Use lock_device with a message to display on lock screen
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
  end

  @doc """
  POST /api/v1/mobile/devices/:id/ring

  Rings the device to help locate it.
  """
  def ring_device(conn, %{"id" => id}) do
    device = Mobile.get_device!(id)
    provider = MDMProvider.provider_for_device(device)
    mdm_device_id = device.mdm_device_id || device.device_id

    audit_mdm_action(conn, "ring_device", device)

    # Ring is implemented as a lock with an audible alert message
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
  end

  @doc """
  POST /api/v1/mobile/devices/:id/push-policy

  Pushes a compliance/configuration policy to the device.
  """
  def push_policy(conn, %{"id" => id} = params) do
    device = Mobile.get_device!(id)
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
  end

  @doc """
  POST /api/v1/mobile/devices/:id/remove-app

  Removes an application from the device.
  """
  def remove_app(conn, %{"id" => id, "app_id" => app_id} = _params) do
    device = Mobile.get_device!(id)
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
  end

  @doc """
  POST /api/v1/mobile/devices/:id/enable-vpn

  Enables or pushes VPN configuration to the device.
  """
  def enable_vpn(conn, %{"id" => id} = params) do
    device = Mobile.get_device!(id)
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
  end

  @doc """
  GET /api/v1/mobile/devices/:id/compliance

  Validates and returns device compliance status from the MDM provider.
  """
  def device_compliance(conn, %{"id" => id}) do
    device = Mobile.get_device!(id)
    provider = MDMProvider.provider_for_device(device)
    mdm_device_id = device.mdm_device_id || device.device_id

    # Local compliance checks (always available)
    local_compliance = %{
      jailbroken_or_rooted: device.is_jailbroken or device.is_rooted,
      passcode_enabled: device.passcode_enabled,
      encryption_enabled: device.encryption_enabled,
      mdm_enrolled: device.mdm_enrolled,
      risk_score: device.risk_score,
      risk_factors: device.risk_factors,
      local_compliant: not (device.is_jailbroken or device.is_rooted) and
                        device.passcode_enabled != false and
                        device.encryption_enabled != false
    }

    # Remote compliance check (if provider supports it)
    remote_compliance = if function_exported?(provider, :get_compliance_status, 1) do
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
        overall_compliant: local_compliance.local_compliant and
                           (remote_compliance[:compliant] != false),
        checked_at: DateTime.utc_now() |> DateTime.to_iso8601()
      }
    })
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

    # Default configuration - in production, load from DB/settings
    config = %{
      agent: %{
        heartbeat_interval_seconds: 30,
        event_batch_size: 50,
        event_flush_interval_seconds: 60
      },
      security: %{
        detect_jailbreak: true,
        detect_root: true,
        detect_debugger: true,
        block_malicious_domains: true,
        scan_installed_apps: true
      },
      network: %{
        enable_dns_monitoring: true,
        enable_traffic_analysis: true,
        blocklist_domains: []
      },
      collection: %{
        collect_app_inventory: true,
        app_inventory_interval_hours: 24,
        collect_device_info: true,
        device_info_interval_hours: 6
      }
    }

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

        current = try do
          TamanduaServer.Settings.get(mobile_category)
        rescue
          _ -> %{}
        end

        merged = deep_merge_config(current, validated_config)

        # Store in ETS via the Settings table directly (the Settings GenServer
        # manages :tamandua_settings, which is public)
        :ets.insert(:tamandua_settings, {mobile_category, merged})

        Logger.info("[Mobile] Config updated for org=#{organization_id}: #{inspect(Map.keys(validated_config))}")

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

  # Validates the incoming mobile config params against allowed keys and types.
  defp validate_mobile_config(params) do
    errors = []
    validated = %{}

    {validated, errors} = Enum.reduce(params, {validated, errors}, fn {section, values}, {acc_v, acc_e} ->
      cond do
        section not in @allowed_config_sections ->
          {acc_v, ["Unknown configuration section: #{section}" | acc_e]}

        not is_map(values) ->
          {acc_v, ["Section '#{section}' must be a map of key-value pairs" | acc_e]}

        true ->
          allowed_keys = allowed_keys_for_section(section)
          {section_config, section_errors} = validate_section(section, values, allowed_keys)

          acc_v = if map_size(section_config) > 0 do
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

  defp validate_config_value(_section, key, value) when key in ~w(heartbeat_interval_seconds event_batch_size event_flush_interval_seconds app_inventory_interval_hours device_info_interval_hours) do
    cond do
      is_integer(value) and value > 0 -> {:ok, value}
      is_binary(value) ->
        case Integer.parse(value) do
          {int, _} when int > 0 -> {:ok, int}
          _ -> {:error, "must be a positive integer"}
        end
      true -> {:error, "must be a positive integer"}
    end
  end

  defp validate_config_value(_section, key, value) when key in ~w(detect_jailbreak detect_root detect_debugger block_malicious_domains scan_installed_apps enable_dns_monitoring enable_traffic_analysis collect_app_inventory collect_device_info) do
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

    integrations = Enum.map(providers, fn {name, display_name} ->
      configured = MDMProvider.configured?(name)
      %{
        provider: name,
        display_name: display_name,
        status: if(configured, do: "configured", else: "not_configured"),
        message: if(configured,
          do: "#{display_name} is configured and ready",
          else: "Configure #{display_name} in Settings > Integrations"
        )
      }
    end)

    # Generic provider is always available
    integrations = integrations ++ [%{
      provider: "generic",
      display_name: "Manual Queue",
      status: "available",
      message: "Commands are queued for manual execution when no MDM is configured"
    }]

    json(conn, %{data: %{integrations: integrations}})
  end

  @doc """
  POST /api/v1/mobile/mdm/sync

  Triggers sync with all configured MDM providers.
  """
  def mdm_sync(conn, _params) do
    _organization_id = get_organization_id(conn)

    providers = [{"intune", "Microsoft Intune"}, {"jamf", "Jamf Pro"}]

    synced = Enum.filter(providers, fn {name, _} -> MDMProvider.configured?(name) end)
             |> Enum.map(fn {name, _} -> name end)

    if synced == [] do
      json(conn, %{
        success: false,
        message: "No MDM providers are configured. Configure a provider in Settings > Integrations.",
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
      data: Enum.map(event_types, fn {type, description} ->
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
    attrs = Map.put(params, "organization_id", organization_id)

    changeset = DeviceV2.changeset(struct(DeviceV2), attrs)

    case Repo.insert(changeset) do
      {:ok, device} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize_device_v2(device)})

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
        changeset = DeviceV2.changeset(device, params)

        case Repo.update(changeset) do
          {:ok, updated} ->
            json(conn, %{data: serialize_device_v2(updated)})

          {:error, changeset} ->
            {:error, changeset}
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
        case Repo.delete(device) do
          {:ok, _} -> send_resp(conn, :no_content, "")
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

    json(conn, %{
      data: %{
        total: total,
        by_platform: platform_counts,
        by_compliance: compliance_counts,
        mdm_enrolled: mdm_enrolled,
        not_enrolled: total - mdm_enrolled
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

  Lists MDM commands, optionally filtered by device_id or status.
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

    with %DeviceV2{} <- get_device_v2_for_org(organization_id, device_id) do
      attrs =
        params
        |> Map.put("organization_id", organization_id)
        |> Map.put("requested_by", (user && (user.email || user.id)) || "system")
        |> Map.put("status", "pending")

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
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "Device not found"})
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
        now = DateTime.utc_now()

        updates =
          %{}
          |> maybe_put("status", params["status"])
          |> maybe_put("result", params["result"])

        updates =
          cond do
            params["status"] == "sent" -> Map.put(updates, "sent_at", now)
            params["status"] in ["completed", "failed"] -> Map.put(updates, "completed_at", now)
            true -> updates
          end

        changeset = MDMCommand.changeset(command, updates)

        case Repo.update(changeset) do
          {:ok, updated} ->
            json(conn, %{data: serialize_command(updated)})

          {:error, changeset} ->
            {:error, changeset}
        end
    end
  end

  # ============================================================================
  # Registry-Based Device Management
  # ============================================================================

  @doc """
  POST /api/v1/mobile/devices/:id/compliance-check

  Runs compliance checks on a device via DeviceRegistry.
  """
  def compliance_check(conn, %{"id" => id}) do
    case DeviceRegistry.check_compliance(id) do
      {:ok, report} ->
        json(conn, %{data: report})

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "Device not found"})
    end
  end

  @doc """
  GET /api/v1/mobile/devices/:id/compliance-report

  Gets cached compliance report for a device.
  """
  def compliance_report(conn, %{"id" => id}) do
    case DeviceRegistry.get_compliance_report(id) do
      {:ok, report} ->
        json(conn, %{data: report})

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "No compliance report found. Run a compliance check first."})
    end
  end

  @doc """
  POST /api/v1/mobile/devices/:id/threat-scan

  Runs a full threat detection scan on a device.
  """
  def threat_scan(conn, %{"id" => id}) do
    device = Mobile.get_device!(id)
    report = ThreatDetection.full_scan(device)

    json(conn, %{data: report})
  end

  @doc """
  GET /api/v1/mobile/devices/:id/apps/inventory

  Gets the full enriched app inventory for a device.
  """
  def app_inventory(conn, %{"id" => id}) do
    _device = Mobile.get_device!(id)

    case AppInventory.get_inventory(id) do
      {:ok, inventory} ->
        json(conn, %{data: inventory})
    end
  end

  @doc """
  GET /api/v1/mobile/devices/:id/apps/risk

  Gets the app risk score for a device.
  """
  def app_risk(conn, %{"id" => id}) do
    _device = Mobile.get_device!(id)

    case AppInventory.get_risk_score(id) do
      {:ok, risk} ->
        json(conn, %{data: risk})
    end
  end

  @doc """
  POST /api/v1/mobile/devices/:id/commands/:command

  Sends an MDM command to a device.
  Supported commands: lock, wipe, locate.
  """
  def send_command(conn, %{"id" => id, "command" => command} = params) do
    device = Mobile.get_device!(id)
    provider = MDMProvider.provider_for_device(device)
    mdm_device_id = device.mdm_device_id || device.device_id

    audit_mdm_action(conn, command, device)

    result = case command do
      "lock" ->
        provider.lock_device(mdm_device_id, params)

      "wipe" ->
        with {:ok, res} <- provider.wipe_device(mdm_device_id, params) do
          Mobile.mark_device_wiped(device)
          {:ok, res}
        end

      "locate" ->
        location = device.last_location || %{note: "Location not available"}
        {:ok, %{action: "locate", device_id: device.device_id, location: location, status: "completed"}}

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
    stats = DeviceRegistry.get_stats()
    json(conn, %{data: stats})
  end

  @doc """
  POST /api/v1/mobile/compliance/bulk-check

  Runs compliance checks on all active devices.
  """
  def bulk_compliance_check(conn, _params) do
    case DeviceRegistry.bulk_compliance_check() do
      {:ok, results} ->
        json(conn, %{
          success: true,
          data: results,
          message: "Bulk compliance check completed: #{results.checked} checked, #{results.non_compliant} non-compliant"
        })
    end
  end

  @doc """
  POST /api/v1/mobile/devices/:id/enroll

  Enrolls a device with an MDM provider.
  """
  def enroll_device(conn, %{"id" => id} = params) do
    case DeviceRegistry.enroll_device(id, params) do
      {:ok, device} ->
        json(conn, %{
          success: true,
          data: serialize_device(device),
          message: "Device enrolled successfully"
        })

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "Device not found"})

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  POST /api/v1/mobile/devices/:id/deactivate

  Deactivates (retires) a device.
  """
  def deactivate(conn, %{"id" => id}) do
    case DeviceRegistry.deactivate_device(id) do
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
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  defp get_organization_id(conn) do
    # Get from tenant scope or current user
    conn.assigns[:organization_id] ||
      (conn.assigns[:current_user] && conn.assigns[:current_user].organization_id) ||
      raise "Organization ID not found"
  end

  defp get_legacy_device_for_org(_organization_id, nil), do: nil
  defp get_legacy_device_for_org(_organization_id, ""), do: nil

  defp get_legacy_device_for_org(organization_id, id) do
    import Ecto.Query

    Device
    |> Device.by_organization(organization_id)
    |> where([d], d.id == ^id)
    |> Repo.one()
  end

  defp get_legacy_device_by_external_id(organization_id, device_id) do
    Mobile.get_device_by_device_id(organization_id, device_id)
  end

  defp ensure_app_guard_device(organization_id, %{
         "device" => %{"device_id" => external_device_id} = device_attrs,
         "platform" => platform
       })
       when is_binary(external_device_id) and external_device_id != "" do
    case get_legacy_device_by_external_id(organization_id, external_device_id) do
      nil ->
        attrs = %{
          "organization_id" => organization_id,
          "device_id" => external_device_id,
          "platform" => platform,
          "model" => device_attrs["model"],
          "manufacturer" => device_attrs["manufacturer"],
          "os_version" => device_attrs["os_version"],
          "agent_version" => "app_guard",
          "mdm_enrolled" => Map.get(device_attrs, "managed", false),
          "mdm_provider" => Map.get(device_attrs, "mdm_provider", "none")
        }

        Mobile.register_device(attrs)

      device ->
        Mobile.touch_device(device)
    end
  end

  defp ensure_app_guard_device(_organization_id, _params), do: {:error, :invalid_device}

  defp app_guard_event_to_mobile_attrs(params, organization_id, device_id) do
    app = Map.get(params, "app", %{})
    risk = Map.get(params, "risk", %{})

    %{
      "device_id" => device_id,
      "organization_id" => organization_id,
      "event_type" => params["event_type"],
      "severity" => params["severity"],
      "timestamp" => normalize_app_guard_timestamp(params["timestamp"]),
      "title" => "App Guard #{params["event_type"]}",
      "description" => app_guard_description(params),
      "payload" => params,
      "app_bundle_id" => app["package_or_bundle_id"],
      "app_name" => app["display_name"],
      "rule_name" => "app_guard:#{params["event_type"]}",
      "rule_id" => params["event_id"],
      "processed" => true,
      "alerted" => false,
      "domain" => get_in(params, ["evidence", "domain"]),
      "remote_address" => get_in(params, ["evidence", "remote_address"]),
      "remote_port" => get_in(params, ["evidence", "remote_port"]),
      "latitude" => get_in(params, ["evidence", "latitude"]),
      "longitude" => get_in(params, ["evidence", "longitude"])
    }
  end

  defp normalize_app_guard_timestamp(nil), do: NaiveDateTime.utc_now()

  defp normalize_app_guard_timestamp(timestamp) when is_binary(timestamp) do
    timestamp
    |> String.trim()
    |> String.replace_suffix("Z", "")
  end

  defp normalize_app_guard_timestamp(timestamp), do: timestamp

  defp app_guard_description(params) do
    risk = Map.get(params, "risk", %{})
    reasons = risk |> Map.get("reasons", []) |> Enum.join(", ")
    "App Guard event for #{get_in(params, ["app", "package_or_bundle_id"]) || "unknown app"}; decision=#{risk["decision"]}; score=#{risk["score"]}; reasons=#{reasons}"
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

  defp serialize_device_summary(device) when is_map(device) do
    %{
      id: device.id,
      device_id: device.device_id,
      platform: device.platform,
      model: device.model
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
    %{
      id: event.id,
      event_type: event.event_type,
      severity: event.severity,
      title: event.title,
      description: event.description,
      timestamp: format_datetime(event.timestamp),
      payload: event.payload,
      mitre_technique: event.mitre_technique,
      mitre_tactic: event.mitre_tactic,
      app_bundle_id: event.app_bundle_id,
      app_name: event.app_name,
      domain: event.domain
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
  defp format_mdm_error(:intune_not_configured), do: "Microsoft Intune is not configured. Set up credentials in Settings > Integrations."
  defp format_mdm_error(:jamf_not_configured), do: "Jamf Pro is not configured. Set up credentials in Settings > Integrations."
  defp format_mdm_error({:api_error, status, _body}), do: "MDM provider returned error (HTTP #{status}). Check provider configuration."
  defp format_mdm_error({:token_error, status}), do: "Failed to authenticate with MDM provider (HTTP #{status}). Check credentials."
  defp format_mdm_error({:request_failed, reason}), do: "Could not reach MDM provider: #{inspect(reason)}"
  defp format_mdm_error(other), do: "MDM operation failed: #{inspect(other)}"

  # ---------------------------------------------------------------------------
  # V2 filter helpers
  # ---------------------------------------------------------------------------

  defp get_device_v2_for_org(_organization_id, nil), do: nil
  defp get_device_v2_for_org(_organization_id, ""), do: nil

  defp get_device_v2_for_org(organization_id, id) do
    import Ecto.Query

    DeviceV2
    |> DeviceV2.by_organization(organization_id)
    |> where([d], d.id == ^id)
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

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  # ---------------------------------------------------------------------------
  # V2 serializers
  # ---------------------------------------------------------------------------

  defp serialize_device_v2(d) when is_map(d) do
    %{
      id: d.id,
      device_id: d.device_id,
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
      last_seen_at: format_datetime(d.last_seen_at),
      enrolled_at: format_datetime(d.enrolled_at),
      inserted_at: format_datetime(d.inserted_at),
      updated_at: format_datetime(d.updated_at)
    }
  end

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
