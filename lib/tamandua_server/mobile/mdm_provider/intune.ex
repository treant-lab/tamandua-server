defmodule TamanduaServer.Mobile.MDMProvider.Intune do
  @moduledoc """
  Microsoft Intune MDM provider implementation.

  Uses the Microsoft Graph API to execute device management actions.
  Requires Azure AD application credentials configured in:

      config :tamandua_server, :mdm_providers,
        intune: [
          tenant_id: "your-azure-tenant-id",
          client_id: "your-app-client-id",
          client_secret: "your-app-client-secret"
        ]

  ## Microsoft Graph API Endpoints

  - Lock: POST /deviceManagement/managedDevices/{id}/remoteLock
  - Wipe: POST /deviceManagement/managedDevices/{id}/wipe
  - Retire: POST /deviceManagement/managedDevices/{id}/retire
  - Sync: POST /deviceManagement/managedDevices/{id}/syncDevice
  """

  @behaviour TamanduaServer.Mobile.MDMProvider

  require Logger

  @graph_base_url "https://graph.microsoft.com/v1.0"
  @token_url_template "https://login.microsoftonline.com/~s/oauth2/v2.0/token"

  # ---------------------------------------------------------------------------
  # Behaviour Callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def lock_device(device_id, opts) do
    body = %{}
    body = if opts["message"], do: Map.put(body, "notificationTitle", opts["message"]), else: body

    case graph_post("/deviceManagement/managedDevices/#{device_id}/remoteLock", body) do
      {:ok, _response} ->
        Logger.info("[Intune] Lock command sent to device #{device_id}")
        {:ok, %{
          action: "lock",
          provider: "intune",
          device_id: device_id,
          status: "sent",
          timestamp: DateTime.utc_now()
        }}

      {:error, reason} = error ->
        Logger.error("[Intune] Failed to lock device #{device_id}: #{inspect(reason)}")
        error
    end
  end

  @impl true
  def wipe_device(device_id, opts) do
    wipe_type = opts["wipe_type"] || "enterprise_only"

    body = case wipe_type do
      "full" ->
        %{"keepEnrollmentData" => false, "keepUserData" => false}
      "enterprise_only" ->
        %{"keepEnrollmentData" => false, "keepUserData" => true}
      _ ->
        %{"keepEnrollmentData" => false, "keepUserData" => true}
    end

    case graph_post("/deviceManagement/managedDevices/#{device_id}/wipe", body) do
      {:ok, _response} ->
        Logger.info("[Intune] Wipe (#{wipe_type}) command sent to device #{device_id}")
        {:ok, %{
          action: "wipe",
          provider: "intune",
          device_id: device_id,
          wipe_type: wipe_type,
          status: "sent",
          timestamp: DateTime.utc_now()
        }}

      {:error, reason} = error ->
        Logger.error("[Intune] Failed to wipe device #{device_id}: #{inspect(reason)}")
        error
    end
  end

  @impl true
  def push_policy(device_id, policy) do
    # Intune uses device configuration profiles assigned to device groups.
    # Triggering a sync forces the device to re-evaluate assigned policies.
    case graph_post("/deviceManagement/managedDevices/#{device_id}/syncDevice", %{}) do
      {:ok, _response} ->
        Logger.info("[Intune] Policy sync triggered for device #{device_id}")
        {:ok, %{
          action: "push_policy",
          provider: "intune",
          device_id: device_id,
          policy_id: policy["policy_id"],
          status: "sync_triggered",
          timestamp: DateTime.utc_now()
        }}

      {:error, reason} = error ->
        Logger.error("[Intune] Failed to push policy to device #{device_id}: #{inspect(reason)}")
        error
    end
  end

  @impl true
  def remove_app(device_id, app_id) do
    # Graph API: uninstall managed app via mobileAppAssignment
    body = %{
      "@odata.type" => "#microsoft.graph.mobileAppAssignment",
      "intent" => "uninstall",
      "target" => %{
        "@odata.type" => "#microsoft.graph.allDevicesAssignmentTarget"
      }
    }

    case graph_post("/deviceAppManagement/mobileApps/#{app_id}/assignments", body) do
      {:ok, _response} ->
        Logger.info("[Intune] App removal (#{app_id}) initiated for device #{device_id}")
        {:ok, %{
          action: "remove_app",
          provider: "intune",
          device_id: device_id,
          app_id: app_id,
          status: "initiated",
          timestamp: DateTime.utc_now()
        }}

      {:error, reason} = error ->
        Logger.error("[Intune] Failed to remove app #{app_id} from device #{device_id}: #{inspect(reason)}")
        error
    end
  end

  @impl true
  def enable_vpn(device_id, opts) do
    # VPN in Intune is configured via device configuration profiles.
    # Trigger a sync so the device picks up the VPN profile assignment.
    case graph_post("/deviceManagement/managedDevices/#{device_id}/syncDevice", %{}) do
      {:ok, _response} ->
        Logger.info("[Intune] VPN config sync triggered for device #{device_id}")
        {:ok, %{
          action: "enable_vpn",
          provider: "intune",
          device_id: device_id,
          vpn_profile: opts["vpn_profile"],
          status: "sync_triggered",
          timestamp: DateTime.utc_now()
        }}

      {:error, reason} = error ->
        Logger.error("[Intune] Failed to enable VPN for device #{device_id}: #{inspect(reason)}")
        error
    end
  end

  @impl true
  def get_compliance_status(device_id) do
    case graph_get("/deviceManagement/managedDevices/#{device_id}?$select=complianceState,lastSyncDateTime") do
      {:ok, %{"complianceState" => state, "lastSyncDateTime" => last_sync}} ->
        {:ok, %{
          provider: "intune",
          device_id: device_id,
          compliance_state: state,
          last_sync: last_sync,
          compliant: state == "compliant"
        }}

      {:ok, body} ->
        {:ok, %{
          provider: "intune",
          device_id: device_id,
          compliance_state: body["complianceState"] || "unknown",
          compliant: false
        }}

      {:error, _} = error ->
        error
    end
  end

  # ---------------------------------------------------------------------------
  # Graph API Helpers
  # ---------------------------------------------------------------------------

  defp graph_post(path, body) do
    with {:ok, token} <- get_access_token() do
      url = "#{@graph_base_url}#{path}"
      headers = [
        {"authorization", "Bearer #{token}"},
        {"content-type", "application/json"}
      ]
      encoded_body = Jason.encode!(body)

      request = Finch.build(:post, url, headers, encoded_body)

      case Finch.request(request, TamanduaServer.Finch, receive_timeout: 30_000) do
        {:ok, %Finch.Response{status: status}} when status in 200..204 ->
          {:ok, %{status: status}}

        {:ok, %Finch.Response{status: status, body: resp_body}} ->
          Logger.warning("[Intune] Graph API error: status=#{status} body=#{resp_body}")
          {:error, {:api_error, status, resp_body}}

        {:error, reason} ->
          {:error, {:request_failed, reason}}
      end
    end
  end

  defp graph_get(path) do
    with {:ok, token} <- get_access_token() do
      url = "#{@graph_base_url}#{path}"
      headers = [
        {"authorization", "Bearer #{token}"},
        {"content-type", "application/json"}
      ]

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

  defp get_access_token do
    config = TamanduaServer.Mobile.MDMProvider.get_config("intune")
    tenant_id = config[:tenant_id]
    client_id = config[:client_id]
    client_secret = config[:client_secret]

    if is_nil(tenant_id) or is_nil(client_id) or is_nil(client_secret) do
      {:error, :intune_not_configured}
    else
      url = :io_lib.format(@token_url_template, [tenant_id]) |> IO.iodata_to_binary()

      body = URI.encode_query(%{
        "client_id" => client_id,
        "client_secret" => client_secret,
        "scope" => "https://graph.microsoft.com/.default",
        "grant_type" => "client_credentials"
      })

      headers = [{"content-type", "application/x-www-form-urlencoded"}]
      request = Finch.build(:post, url, headers, body)

      case Finch.request(request, TamanduaServer.Finch, receive_timeout: 10_000) do
        {:ok, %Finch.Response{status: 200, body: resp_body}} ->
          case Jason.decode(resp_body) do
            {:ok, %{"access_token" => token}} -> {:ok, token}
            _ -> {:error, :invalid_token_response}
          end

        {:ok, %Finch.Response{status: status, body: resp_body}} ->
          Logger.error("[Intune] Token request failed: status=#{status} body=#{resp_body}")
          {:error, {:token_error, status}}

        {:error, reason} ->
          {:error, {:token_request_failed, reason}}
      end
    end
  end
end
