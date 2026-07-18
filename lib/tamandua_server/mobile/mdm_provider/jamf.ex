defmodule TamanduaServer.Mobile.MDMProvider.Jamf do
  @moduledoc """
  Jamf Pro MDM provider implementation.

  Uses the Jamf Pro API (Classic and Jamf Pro API) to execute device management
  actions on macOS, iOS, and iPadOS devices.

  Requires Jamf Pro API credentials configured in:

      config :tamandua_server, :mdm_providers,
        jamf: [
          base_url: "https://your-instance.jamfcloud.com",
          username: "api-user",
          password: "api-password"
        ]

  ## Jamf Pro API Endpoints

  - Lock: POST /api/v1/macos-managed-software-updates/send-command  (macOS)
           POST /JSSResource/mobiledevicecommands/command/DeviceLock (iOS)
  - Wipe: POST /JSSResource/mobiledevicecommands/command/EraseDevice
  - App removal: DELETE /JSSResource/mobiledeviceapplications/serialnumber/{sn}
  """

  @behaviour TamanduaServer.Mobile.MDMProvider

  require Logger

  # ---------------------------------------------------------------------------
  # Behaviour Callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def lock_device(device_id, opts) do
    message = opts["message"] || "Device locked by Tamandua EDR"

    body = %{
      "mobileDeviceCommandDetail" => %{
        "commandType" => "DeviceLock",
        "message" => message
      },
      "mobileDevices" => [%{"id" => device_id}]
    }

    case jamf_post("/api/v1/mobile-device-commands", body) do
      {:ok, response} ->
        Logger.info("[Jamf] Lock command sent to device #{device_id}")
        {:ok, %{
          action: "lock",
          provider: "jamf",
          device_id: device_id,
          command_uuid: response["commandUuid"],
          status: "sent",
          timestamp: DateTime.utc_now()
        }}

      {:error, reason} = error ->
        Logger.error("[Jamf] Failed to lock device #{device_id}: #{inspect(reason)}")
        error
    end
  end

  @impl true
  def wipe_device(device_id, opts) do
    wipe_type = opts["wipe_type"] || "enterprise_only"

    command_type = case wipe_type do
      "full" -> "EraseDevice"
      _ -> "EraseDevice"
    end

    body = %{
      "mobileDeviceCommandDetail" => %{
        "commandType" => command_type,
        "preserveDataPlan" => wipe_type == "enterprise_only"
      },
      "mobileDevices" => [%{"id" => device_id}]
    }

    case jamf_post("/api/v1/mobile-device-commands", body) do
      {:ok, response} ->
        Logger.info("[Jamf] Wipe (#{wipe_type}) command sent to device #{device_id}")
        {:ok, %{
          action: "wipe",
          provider: "jamf",
          device_id: device_id,
          wipe_type: wipe_type,
          command_uuid: response["commandUuid"],
          status: "sent",
          timestamp: DateTime.utc_now()
        }}

      {:error, reason} = error ->
        Logger.error("[Jamf] Failed to wipe device #{device_id}: #{inspect(reason)}")
        error
    end
  end

  @impl true
  def push_policy(device_id, policy) do
    # In Jamf, policies are assigned to device groups or executed via policy triggers.
    # Send a BlankPush to force the device to check in and re-evaluate profiles.
    body = %{
      "mobileDeviceCommandDetail" => %{
        "commandType" => "BlankPush"
      },
      "mobileDevices" => [%{"id" => device_id}]
    }

    case jamf_post("/api/v1/mobile-device-commands", body) do
      {:ok, response} ->
        Logger.info("[Jamf] Policy push (BlankPush) sent to device #{device_id}")
        {:ok, %{
          action: "push_policy",
          provider: "jamf",
          device_id: device_id,
          policy_id: policy["policy_id"],
          command_uuid: response["commandUuid"],
          status: "sent",
          timestamp: DateTime.utc_now()
        }}

      {:error, reason} = error ->
        Logger.error("[Jamf] Failed to push policy to device #{device_id}: #{inspect(reason)}")
        error
    end
  end

  @impl true
  def remove_app(device_id, app_id) do
    body = %{
      "mobileDeviceCommandDetail" => %{
        "commandType" => "RemoveApplication",
        "identifier" => app_id
      },
      "mobileDevices" => [%{"id" => device_id}]
    }

    case jamf_post("/api/v1/mobile-device-commands", body) do
      {:ok, response} ->
        Logger.info("[Jamf] App removal (#{app_id}) sent to device #{device_id}")
        {:ok, %{
          action: "remove_app",
          provider: "jamf",
          device_id: device_id,
          app_id: app_id,
          command_uuid: response["commandUuid"],
          status: "sent",
          timestamp: DateTime.utc_now()
        }}

      {:error, reason} = error ->
        Logger.error("[Jamf] Failed to remove app #{app_id} from device #{device_id}: #{inspect(reason)}")
        error
    end
  end

  @impl true
  def enable_vpn(device_id, opts) do
    # Jamf manages VPN via configuration profiles. Trigger a BlankPush
    # so the device picks up any newly assigned VPN profile.
    body = %{
      "mobileDeviceCommandDetail" => %{
        "commandType" => "BlankPush"
      },
      "mobileDevices" => [%{"id" => device_id}]
    }

    case jamf_post("/api/v1/mobile-device-commands", body) do
      {:ok, response} ->
        Logger.info("[Jamf] VPN config push sent to device #{device_id}")
        {:ok, %{
          action: "enable_vpn",
          provider: "jamf",
          device_id: device_id,
          vpn_profile: opts["vpn_profile"],
          command_uuid: response["commandUuid"],
          status: "sent",
          timestamp: DateTime.utc_now()
        }}

      {:error, reason} = error ->
        Logger.error("[Jamf] Failed to enable VPN for device #{device_id}: #{inspect(reason)}")
        error
    end
  end

  @impl true
  def get_compliance_status(device_id) do
    case jamf_get("/api/v1/mobile-devices/#{device_id}") do
      {:ok, %{"managed" => managed, "supervised" => supervised} = _body} ->
        {:ok, %{
          provider: "jamf",
          device_id: device_id,
          managed: managed,
          supervised: supervised,
          compliance_state: if(managed, do: "compliant", else: "noncompliant"),
          compliant: managed == true
        }}

      {:ok, body} ->
        {:ok, %{
          provider: "jamf",
          device_id: device_id,
          compliance_state: "unknown",
          compliant: false,
          raw: body
        }}

      {:error, _} = error ->
        error
    end
  end

  # ---------------------------------------------------------------------------
  # Jamf API Helpers
  # ---------------------------------------------------------------------------

  defp jamf_post(path, body) do
    with {:ok, {base_url, auth_header}} <- get_connection_info() do
      url = "#{base_url}#{path}"
      headers = [
        auth_header,
        {"content-type", "application/json"},
        {"accept", "application/json"}
      ]
      encoded_body = Jason.encode!(body)

      request = Finch.build(:post, url, headers, encoded_body)

      case Finch.request(request, TamanduaServer.Finch, receive_timeout: 30_000) do
        {:ok, %Finch.Response{status: status, body: resp_body}} when status in 200..202 ->
          case Jason.decode(resp_body) do
            {:ok, decoded} -> {:ok, decoded}
            {:error, _} -> {:ok, %{"status" => status}}
          end

        {:ok, %Finch.Response{status: status, body: resp_body}} ->
          Logger.warning("[Jamf] API error: status=#{status} body=#{resp_body}")
          {:error, {:api_error, status, resp_body}}

        {:error, reason} ->
          {:error, {:request_failed, reason}}
      end
    end
  end

  defp jamf_get(path) do
    with {:ok, {base_url, auth_header}} <- get_connection_info() do
      url = "#{base_url}#{path}"
      headers = [
        auth_header,
        {"accept", "application/json"}
      ]

      request = Finch.build(:get, url, headers)

      case Finch.request(request, TamanduaServer.Finch, receive_timeout: 15_000) do
        {:ok, %Finch.Response{status: 200, body: resp_body}} ->
          Jason.decode(resp_body)

        {:ok, %Finch.Response{status: status, body: resp_body}} ->
          {:error, {:api_error, status, resp_body}}

        {:error, reason} ->
          {:error, {:request_failed, reason}}
      end
    end
  end

  defp get_connection_info do
    config = TamanduaServer.Mobile.MDMProvider.get_config("jamf")
    base_url = config[:base_url]
    username = config[:username]
    password = config[:password]

    if is_nil(base_url) or is_nil(username) or is_nil(password) do
      {:error, :jamf_not_configured}
    else
      credentials = Base.encode64("#{username}:#{password}")
      auth_header = {"authorization", "Basic #{credentials}"}
      {:ok, {base_url, auth_header}}
    end
  end
end
