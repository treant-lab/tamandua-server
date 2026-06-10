defmodule TamanduaServer.Mobile.MDMProvider do
  @moduledoc """
  Behaviour for MDM (Mobile Device Management) provider integrations.

  Defines the contract that all MDM provider implementations must follow.
  Supported providers: Microsoft Intune, Jamf Pro, and a Generic (manual queue)
  provider for environments without an MDM solution.

  ## Usage

      provider = TamanduaServer.Mobile.MDMProvider.get_provider("intune")
      provider.lock_device(device_id, %{message: "Device locked by IT"})
  """

  @type device_id :: String.t()
  @type app_id :: String.t()
  @type opts :: map()
  @type policy :: map()
  @type result :: {:ok, map()} | {:error, term()}

  @doc "Send a remote lock command to a device."
  @callback lock_device(device_id, opts) :: result

  @doc "Send a remote wipe command to a device."
  @callback wipe_device(device_id, opts) :: result

  @doc "Push a compliance/configuration policy to a device."
  @callback push_policy(device_id, policy) :: result

  @doc "Remove an application from a device."
  @callback remove_app(device_id, app_id) :: result

  @doc "Enable or push VPN configuration to a device."
  @callback enable_vpn(device_id, opts) :: result

  @doc "Query device compliance status from the MDM provider."
  @callback get_compliance_status(device_id) :: result

  @doc "Sync device list from the MDM provider."
  @callback sync_devices(config :: map()) :: {:ok, [map()]} | {:error, term()}

  @doc "Send a generic command to a device."
  @callback send_command(device_id, command :: String.t(), opts) :: result

  @doc "Get installed app inventory for a device."
  @callback get_app_inventory(device_id, config :: map()) :: {:ok, [map()]} | {:error, term()}

  # Optional callbacks that providers may implement
  @optional_callbacks [get_compliance_status: 1, sync_devices: 1, send_command: 3, get_app_inventory: 2]

  @doc """
  Returns the MDM provider module for the given provider name.

  Falls back to the Generic provider if the provider is unknown or not configured.
  """
  @spec get_provider(String.t()) :: module()
  def get_provider(provider_name) do
    case provider_name do
      "intune" -> TamanduaServer.Mobile.MDMProvider.Intune
      "workspace_one" -> TamanduaServer.Mobile.MDMProvider.WorkspaceOne
      "jamf" -> TamanduaServer.Mobile.MDMProvider.Jamf
      _ -> TamanduaServer.Mobile.MDMProvider.Generic
    end
  end

  @doc """
  Returns the MDM provider module for a device based on its mdm_provider field.
  """
  @spec provider_for_device(TamanduaServer.Mobile.Device.t()) :: module()
  def provider_for_device(%{mdm_provider: provider}) when provider in ["intune", "jamf", "workspace_one"] do
    get_provider(provider)
  end
  def provider_for_device(_device), do: TamanduaServer.Mobile.MDMProvider.Generic

  @doc """
  Checks whether the given provider is properly configured with credentials.
  """
  @spec configured?(String.t()) :: boolean()
  def configured?(provider_name) do
    config = get_config(provider_name)
    case provider_name do
      "intune" ->
        config[:tenant_id] != nil and config[:client_id] != nil and config[:client_secret] != nil

      "workspace_one" ->
        config[:base_url] != nil and config[:api_key] != nil

      "jamf" ->
        config[:base_url] != nil and config[:username] != nil and config[:password] != nil

      _ ->
        true
    end
  end

  @doc """
  Returns the configuration map for a given MDM provider from application config.
  """
  @spec get_config(String.t()) :: Keyword.t()
  def get_config(provider_name) do
    Application.get_env(:tamandua_server, :mdm_providers, [])
    |> Keyword.get(String.to_existing_atom(provider_name), [])
  rescue
    ArgumentError -> []
  end
end
