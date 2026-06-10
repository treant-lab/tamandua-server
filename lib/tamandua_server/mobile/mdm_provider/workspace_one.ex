defmodule TamanduaServer.Mobile.MDMProvider.WorkspaceOne do
  @moduledoc """
  VMware Workspace ONE (formerly AirWatch) MDM provider implementation.

  Uses the Workspace ONE UEM REST API to execute device management actions.
  Requires configuration in:

      config :tamandua_server, :mdm_providers,
        workspace_one: [
          base_url: "https://as123.awmdm.com",
          api_key: "your-api-key",
          username: "admin",
          password: "secret",
          tenant_code: "your-tenant-code"
        ]

  ## Workspace ONE UEM REST API Endpoints

  - Devices List: GET /api/mdm/devices/search
  - Lock: POST /api/mdm/devices/{id}/commands?command=Lock
  - Wipe: POST /api/mdm/devices/{id}/commands?command=DeviceWipe
  - Sync: POST /api/mdm/devices/{id}/commands?command=SyncDevice
  - Apps: GET /api/mdm/devices/{id}/apps
  - Compliance: GET /api/mdm/devices/{id}/compliance
  """

  @behaviour TamanduaServer.Mobile.MDMProvider

  require Logger

  # ---------------------------------------------------------------------------
  # Behaviour Callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def lock_device(device_id, opts) do
    body = %{}
    body = if opts["message"], do: Map.put(body, "MessageBody", opts["message"]), else: body
    body = if opts["phone_number"], do: Map.put(body, "PhoneNumber", opts["phone_number"]), else: body

    case api_post("/api/mdm/devices/#{device_id}/commands?command=Lock", body) do
      {:ok, _response} ->
        Logger.info("[WorkspaceOne] Lock command sent to device #{device_id}")
        {:ok, %{
          action: "lock",
          provider: "workspace_one",
          device_id: device_id,
          status: "sent",
          timestamp: DateTime.utc_now()
        }}

      {:error, reason} = error ->
        Logger.error("[WorkspaceOne] Failed to lock device #{device_id}: #{inspect(reason)}")
        error
    end
  end

  @impl true
  def wipe_device(device_id, opts) do
    wipe_type = opts["wipe_type"] || "enterprise_only"

    command = case wipe_type do
      "full" -> "DeviceWipe"
      "enterprise_only" -> "EnterpriseWipe"
      _ -> "EnterpriseWipe"
    end

    case api_post("/api/mdm/devices/#{device_id}/commands?command=#{command}", %{}) do
      {:ok, _response} ->
        Logger.info("[WorkspaceOne] #{command} command sent to device #{device_id}")
        {:ok, %{
          action: "wipe",
          provider: "workspace_one",
          device_id: device_id,
          wipe_type: wipe_type,
          status: "sent",
          timestamp: DateTime.utc_now()
        }}

      {:error, reason} = error ->
        Logger.error("[WorkspaceOne] Failed to wipe device #{device_id}: #{inspect(reason)}")
        error
    end
  end

  @impl true
  def push_policy(device_id, policy) do
    # Workspace ONE pushes policies via profile installation
    case api_post("/api/mdm/devices/#{device_id}/commands?command=SyncDevice", %{}) do
      {:ok, _response} ->
        Logger.info("[WorkspaceOne] Policy sync triggered for device #{device_id}")
        {:ok, %{
          action: "push_policy",
          provider: "workspace_one",
          device_id: device_id,
          policy_id: policy["policy_id"],
          status: "sync_triggered",
          timestamp: DateTime.utc_now()
        }}

      {:error, reason} = error ->
        Logger.error("[WorkspaceOne] Failed to push policy to device #{device_id}: #{inspect(reason)}")
        error
    end
  end

  @impl true
  def remove_app(device_id, app_id) do
    body = %{"ApplicationId" => app_id}

    case api_post("/api/mdm/devices/#{device_id}/commands?command=RemoveApplication", body) do
      {:ok, _response} ->
        Logger.info("[WorkspaceOne] App removal (#{app_id}) initiated for device #{device_id}")
        {:ok, %{
          action: "remove_app",
          provider: "workspace_one",
          device_id: device_id,
          app_id: app_id,
          status: "initiated",
          timestamp: DateTime.utc_now()
        }}

      {:error, reason} = error ->
        Logger.error("[WorkspaceOne] Failed to remove app #{app_id} from device #{device_id}: #{inspect(reason)}")
        error
    end
  end

  @impl true
  def enable_vpn(device_id, opts) do
    case api_post("/api/mdm/devices/#{device_id}/commands?command=SyncDevice", %{}) do
      {:ok, _response} ->
        Logger.info("[WorkspaceOne] VPN config sync triggered for device #{device_id}")
        {:ok, %{
          action: "enable_vpn",
          provider: "workspace_one",
          device_id: device_id,
          vpn_profile: opts["vpn_profile"],
          status: "sync_triggered",
          timestamp: DateTime.utc_now()
        }}

      {:error, reason} = error ->
        Logger.error("[WorkspaceOne] Failed to enable VPN for device #{device_id}: #{inspect(reason)}")
        error
    end
  end

  @impl true
  def get_compliance_status(device_id) do
    case api_get("/api/mdm/devices/#{device_id}/compliance") do
      {:ok, %{"ComplianceStatus" => status}} ->
        {:ok, %{
          provider: "workspace_one",
          device_id: device_id,
          compliance_state: String.downcase(status),
          compliant: String.downcase(status) == "compliant"
        }}

      {:ok, body} ->
        {:ok, %{
          provider: "workspace_one",
          device_id: device_id,
          compliance_state: body["ComplianceStatus"] || "unknown",
          compliant: false
        }}

      {:error, _} = error ->
        error
    end
  end

  @impl true
  def sync_devices(config) do
    base_url = config[:base_url] || config["base_url"]
    page_size = 500

    case api_get("/api/mdm/devices/search?pagesize=#{page_size}", base_url) do
      {:ok, %{"Devices" => devices}} when is_list(devices) ->
        mapped = Enum.map(devices, fn d ->
          %{
            "device_id" => to_string(d["Id"] || d["Uuid"]),
            "device_name" => d["DeviceFriendlyName"],
            "platform" => normalize_platform(d["Platform"]),
            "os_version" => d["OperatingSystem"],
            "model" => d["Model"],
            "serial_number" => d["SerialNumber"],
            "user_email" => d["UserEmailAddress"],
            "user_name" => d["UserName"],
            "mdm_provider" => "workspace_one",
            "mdm_enrolled" => true,
            "compliance_status" => String.downcase(d["ComplianceStatus"] || "unknown")
          }
        end)
        {:ok, mapped}

      {:ok, _} ->
        {:ok, []}

      {:error, _} = error ->
        error
    end
  end

  @impl true
  def send_command(device_id, command, opts) do
    ws_command = case command do
      "lock" -> "Lock"
      "wipe" -> "DeviceWipe"
      "enterprise_wipe" -> "EnterpriseWipe"
      "sync" -> "SyncDevice"
      "shutdown" -> "Shutdown"
      "restart" -> "Restart"
      other -> other
    end

    case api_post("/api/mdm/devices/#{device_id}/commands?command=#{ws_command}", opts) do
      {:ok, _} ->
        {:ok, %{
          action: command,
          provider: "workspace_one",
          device_id: device_id,
          ws_command: ws_command,
          status: "sent",
          timestamp: DateTime.utc_now()
        }}

      {:error, _} = error ->
        error
    end
  end

  @impl true
  def get_app_inventory(device_id, _config) do
    case api_get("/api/mdm/devices/#{device_id}/apps") do
      {:ok, %{"DeviceApps" => apps}} when is_list(apps) ->
        mapped = Enum.map(apps, fn app ->
          %{
            "bundle_id" => app["ApplicationIdentifier"] || app["BundleId"],
            "app_name" => app["ApplicationName"],
            "version" => app["InstalledVersion"],
            "is_managed" => app["IsManaged"] || false,
            "status" => app["Status"]
          }
        end)
        {:ok, mapped}

      {:ok, _} ->
        {:ok, []}

      {:error, _} = error ->
        error
    end
  end

  # ---------------------------------------------------------------------------
  # API Helpers
  # ---------------------------------------------------------------------------

  defp api_post(path, body) do
    config = get_config()
    base_url = config[:base_url]

    if is_nil(base_url) do
      {:error, :workspace_one_not_configured}
    else
      url = "#{base_url}#{path}"
      headers = build_headers(config)
      encoded_body = Jason.encode!(body)

      request = Finch.build(:post, url, headers, encoded_body)

      case Finch.request(request, TamanduaServer.Finch, receive_timeout: 30_000) do
        {:ok, %Finch.Response{status: status}} when status in 200..204 ->
          {:ok, %{status: status}}

        {:ok, %Finch.Response{status: status, body: resp_body}} ->
          Logger.warning("[WorkspaceOne] API error: status=#{status} body=#{resp_body}")
          {:error, {:api_error, status, resp_body}}

        {:error, reason} ->
          {:error, {:request_failed, reason}}
      end
    end
  end

  defp api_get(path, base_url_override \\ nil) do
    config = get_config()
    base_url = base_url_override || config[:base_url]

    if is_nil(base_url) do
      {:error, :workspace_one_not_configured}
    else
      url = "#{base_url}#{path}"
      headers = build_headers(config)

      request = Finch.build(:get, url, headers)

      case Finch.request(request, TamanduaServer.Finch, receive_timeout: 15_000) do
        {:ok, %Finch.Response{status: 200, body: resp_body}} ->
          {:ok, Jason.decode!(resp_body)}

        {:ok, %Finch.Response{status: status, body: resp_body}} ->
          {:error, {:api_error, status, resp_body}}

        {:error, reason} ->
          {:error, {:request_failed, reason}}
      end
    end
  end

  defp build_headers(config) do
    api_key = config[:api_key] || ""
    username = config[:username] || ""
    password = config[:password] || ""
    tenant_code = config[:tenant_code] || ""

    auth = Base.encode64("#{username}:#{password}")

    [
      {"aw-tenant-code", tenant_code},
      {"authorization", "Basic #{auth}"},
      {"accept", "application/json;version=2"},
      {"content-type", "application/json"}
    ] ++ if api_key != "", do: [{"aw-api-key", api_key}], else: []
  end

  defp get_config do
    TamanduaServer.Mobile.MDMProvider.get_config("workspace_one")
  end

  defp normalize_platform(platform) when is_binary(platform) do
    case String.downcase(platform) do
      "apple" -> "ios"
      "ios" -> "ios"
      "android" -> "android"
      _ -> String.downcase(platform)
    end
  end
  defp normalize_platform(_), do: "unknown"
end
