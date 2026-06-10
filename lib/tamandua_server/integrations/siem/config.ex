defmodule TamanduaServer.Integrations.SIEM.Config do
  @moduledoc """
  SIEM integration configuration management.

  Provides centralized configuration access for all SIEM integrations:
  - Splunk HEC
  - Microsoft Sentinel
  - Elastic Security
  - QRadar

  Configuration can come from:
  1. Application config (config/runtime.exs)
  2. Environment variables
  3. Database (per-tenant settings)
  """

  require Logger

  @supported_siems [:splunk, :sentinel, :elastic, :qradar]

  @doc """
  Get configuration for a specific SIEM integration.

  ## Parameters

  - `siem_type` - Atom identifying the SIEM (:splunk, :sentinel, :elastic, :qradar)
  - `opts` - Optional keyword list with :organization_id for tenant-specific config

  ## Returns

  Configuration map or nil if not configured.
  """
  @spec get_config(atom(), keyword()) :: map() | nil
  def get_config(siem_type, opts \\ []) when siem_type in @supported_siems do
    org_id = Keyword.get(opts, :organization_id)

    # Try tenant-specific config first
    config = if org_id do
      get_tenant_config(siem_type, org_id)
    end

    # Fall back to global config
    config || get_global_config(siem_type)
  end

  @doc """
  Check if a SIEM integration is enabled.

  ## Parameters

  - `siem_type` - Atom identifying the SIEM

  ## Returns

  Boolean indicating if the integration is enabled.
  """
  @spec enabled?(atom()) :: boolean()
  def enabled?(siem_type) when siem_type in @supported_siems do
    case get_config(siem_type) do
      nil -> false
      config -> config[:enabled] == true
    end
  end

  @doc """
  Get all enabled SIEM integrations.

  ## Returns

  List of enabled SIEM type atoms.
  """
  @spec all_enabled() :: [atom()]
  def all_enabled do
    @supported_siems
    |> Enum.filter(&enabled?/1)
  end

  @doc """
  Get all SIEM integrations with their configuration and status.

  ## Returns

  List of maps with :type, :enabled, :config, :health_status.
  """
  @spec list_all() :: [map()]
  def list_all do
    @supported_siems
    |> Enum.map(fn siem_type ->
      config = get_config(siem_type) || %{}
      %{
        type: siem_type,
        enabled: config[:enabled] == true,
        config: sanitize_config(config),
        health_status: if(config[:enabled], do: :unknown, else: :disabled)
      }
    end)
  end

  @doc """
  Update configuration for a SIEM integration.

  This stores the config in application env for the current runtime.
  For persistent storage, use the database-backed tenant config.

  ## Parameters

  - `siem_type` - Atom identifying the SIEM
  - `config` - Configuration map to merge/update

  ## Returns

  `:ok` on success.
  """
  @spec update_config(atom(), map()) :: :ok
  def update_config(siem_type, config) when siem_type in @supported_siems do
    current = get_global_config(siem_type) || %{}
    merged = Map.merge(current, config)

    all_siems = Application.get_env(:tamandua_server, :siem_integrations, %{})
    updated = Map.put(all_siems, siem_type, merged)
    Application.put_env(:tamandua_server, :siem_integrations, updated)

    Logger.info("[SIEM.Config] Updated #{siem_type} configuration")
    :ok
  end

  @doc """
  Get the list of supported SIEM types.

  ## Returns

  List of supported SIEM type atoms.
  """
  @spec supported_siems() :: [atom()]
  def supported_siems, do: @supported_siems

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp get_global_config(siem_type) do
    all_siems = Application.get_env(:tamandua_server, :siem_integrations, %{})
    Map.get(all_siems, siem_type)
  end

  defp get_tenant_config(siem_type, org_id) do
    # Query database for tenant-specific SIEM config
    try do
      alias TamanduaServer.Repo
      import Ecto.Query

      query = from(ic in "integration_configs",
        where: ic.organization_id == ^org_id and ic.integration_type == ^to_string(siem_type),
        select: ic.config
      )

      case Repo.one(query) do
        nil -> nil
        config when is_binary(config) -> Jason.decode!(config) |> atomize_keys()
        config when is_map(config) -> atomize_keys(config)
      end
    rescue
      _ -> nil
    end
  end

  defp sanitize_config(config) when is_map(config) do
    # Remove sensitive fields from config for display
    sensitive_keys = [:hec_token, :shared_key, :api_key, :client_secret, :password, :rest_password]

    Enum.reduce(sensitive_keys, config, fn key, acc ->
      if Map.has_key?(acc, key) do
        Map.put(acc, key, "***REDACTED***")
      else
        acc
      end
    end)
  end

  defp sanitize_config(nil), do: %{}

  defp atomize_keys(map) when is_map(map) do
    Map.new(map, fn
      {k, v} when is_binary(k) -> {String.to_atom(k), atomize_keys(v)}
      {k, v} -> {k, atomize_keys(v)}
    end)
  end

  defp atomize_keys(list) when is_list(list), do: Enum.map(list, &atomize_keys/1)
  defp atomize_keys(value), do: value
end
