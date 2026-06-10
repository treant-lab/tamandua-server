defmodule TamanduaServer.Licensing.FeatureFlags do
  @moduledoc """
  Feature flag management for license-gated functionality.

  Provides runtime feature checks based on license tier and additional
  feature licenses. Supports:

  - Tier-based feature gating
  - Per-organization feature overrides
  - Feature quotas and usage limits
  - A/B testing and gradual rollouts
  - Emergency feature kill switches

  ## Usage

      # Check if a feature is available
      if FeatureFlags.enabled?(:advanced_forensics, org_id) do
        # Run advanced forensics
      end

      # With fallback
      case FeatureFlags.get_feature_value(:max_agents, org_id) do
        {:ok, limit} -> limit
        :disabled -> 10  # Default fallback
      end

      # Check quota
      if FeatureFlags.within_quota?(:api_calls, org_id) do
        process_api_call()
      end
  """

  use GenServer
  require Logger

  alias TamanduaServer.Licensing.{License, FeatureLicense}
  alias TamanduaServer.Repo

  import Ecto.Query

  # Feature definitions with their requirements
  @feature_requirements %{
    # Core features - available to all tiers
    detection: [:trial, :pro, :enterprise, :mssp],
    dashboards: [:trial, :pro, :enterprise, :mssp],
    alerts: [:trial, :pro, :enterprise, :mssp],
    basic_response: [:trial, :pro, :enterprise, :mssp],

    # Advanced features - Pro and up
    hunting: [:pro, :enterprise, :mssp],
    behavioral_analytics: [:pro, :enterprise, :mssp],
    playbooks: [:pro, :enterprise, :mssp],
    api_access: [:pro, :enterprise, :mssp],

    # Enterprise features
    custom_integrations: [:enterprise, :mssp],
    sso: [:enterprise, :mssp],
    advanced_forensics: [:enterprise, :mssp],
    live_response: [:enterprise, :mssp],
    compliance: [:enterprise, :mssp],

    # MSSP features
    mssp_portal: [:mssp],
    white_labeling: [:mssp],
    sub_licensing: [:mssp],

    # Add-on features (require separate license)
    ai_assistant: :addon,
    threat_intel_premium: :addon,
    cloud_security: :addon,
    container_security: :addon,
    deception: :addon,
    xdr: :addon
  }

  # Feature quotas by tier
  @tier_quotas %{
    trial: %{
      max_agents: 10,
      max_users: 5,
      retention_days: 7,
      api_calls_per_day: 1000,
      storage_gb: 5
    },
    pro: %{
      max_agents: 100,
      max_users: 25,
      retention_days: 90,
      api_calls_per_day: 50_000,
      storage_gb: 100
    },
    enterprise: %{
      max_agents: 10_000,
      max_users: :unlimited,
      retention_days: 365,
      api_calls_per_day: :unlimited,
      storage_gb: 1000
    },
    mssp: %{
      max_agents: 100_000,
      max_users: :unlimited,
      retention_days: 365,
      api_calls_per_day: :unlimited,
      storage_gb: :unlimited
    }
  }

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Check if a feature is enabled for an organization.
  """
  @spec enabled?(atom(), binary()) :: boolean()
  def enabled?(feature, organization_id) do
    GenServer.call(__MODULE__, {:enabled?, feature, organization_id})
  end

  @doc """
  Get all enabled features for an organization.
  """
  @spec list_enabled(binary()) :: [atom()]
  def list_enabled(organization_id) do
    GenServer.call(__MODULE__, {:list_enabled, organization_id})
  end

  @doc """
  Get a feature's value/limit for an organization.
  """
  @spec get_value(atom(), binary()) :: {:ok, term()} | :disabled
  def get_value(feature, organization_id) do
    GenServer.call(__MODULE__, {:get_value, feature, organization_id})
  end

  @doc """
  Get quota limit for a specific metric.
  """
  @spec get_quota(atom(), binary()) :: non_neg_integer() | :unlimited | nil
  def get_quota(metric, organization_id) do
    GenServer.call(__MODULE__, {:get_quota, metric, organization_id})
  end

  @doc """
  Check if organization is within quota for a metric.
  """
  @spec within_quota?(atom(), binary()) :: boolean()
  def within_quota?(metric, organization_id) do
    GenServer.call(__MODULE__, {:within_quota?, metric, organization_id})
  end

  @doc """
  Check if organization has exceeded quota for a metric.
  """
  @spec quota_exceeded?(atom(), binary()) :: boolean()
  def quota_exceeded?(metric, organization_id) do
    not within_quota?(metric, organization_id)
  end

  @doc """
  Get quota usage percentage.
  """
  @spec quota_usage_percent(atom(), binary()) :: float() | :unlimited
  def quota_usage_percent(metric, organization_id) do
    GenServer.call(__MODULE__, {:quota_usage_percent, metric, organization_id})
  end

  @doc """
  Set a feature override for an organization.

  Used for:
  - Granting beta access
  - Temporary feature access
  - A/B testing
  """
  @spec set_override(binary(), atom(), boolean() | term(), keyword()) :: :ok
  def set_override(organization_id, feature, value, opts \\ []) do
    GenServer.call(__MODULE__, {:set_override, organization_id, feature, value, opts})
  end

  @doc """
  Remove a feature override.
  """
  @spec remove_override(binary(), atom()) :: :ok
  def remove_override(organization_id, feature) do
    GenServer.call(__MODULE__, {:remove_override, organization_id, feature})
  end

  @doc """
  Check if feature is globally disabled (kill switch).
  """
  @spec globally_disabled?(atom()) :: boolean()
  def globally_disabled?(feature) do
    GenServer.call(__MODULE__, {:globally_disabled?, feature})
  end

  @doc """
  Set global feature kill switch.
  """
  @spec set_kill_switch(atom(), boolean()) :: :ok
  def set_kill_switch(feature, disabled) do
    GenServer.call(__MODULE__, {:set_kill_switch, feature, disabled})
  end

  @doc """
  Get feature requirements (which tiers can access).
  """
  @spec get_requirements(atom()) :: [atom()] | :addon | nil
  def get_requirements(feature) do
    Map.get(@feature_requirements, feature)
  end

  @doc """
  Get all feature definitions.
  """
  @spec all_features() :: map()
  def all_features, do: @feature_requirements

  @doc """
  Get tier quotas.
  """
  @spec tier_quotas(atom()) :: map() | nil
  def tier_quotas(tier), do: Map.get(@tier_quotas, tier)

  # Decorator macro for feature-gated functions
  defmacro require_feature(feature, org_id_var, do: block) do
    quote do
      if TamanduaServer.Licensing.FeatureFlags.enabled?(unquote(feature), unquote(org_id_var)) do
        unquote(block)
      else
        {:error, :feature_not_licensed}
      end
    end
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    :ets.new(:feature_cache, [:set, :public, :named_table, read_concurrency: true])
    :ets.new(:feature_overrides, [:set, :public, :named_table, read_concurrency: true])
    :ets.new(:kill_switches, [:set, :public, :named_table, read_concurrency: true])

    # Reload cache periodically
    :timer.send_interval(60_000, :reload_cache)

    Logger.info("Feature Flags service started")
    {:ok, %{}}
  end

  @impl true
  def handle_call({:enabled?, feature, organization_id}, _from, state) do
    result = check_feature_enabled(feature, organization_id)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:list_enabled, organization_id}, _from, state) do
    enabled = @feature_requirements
    |> Map.keys()
    |> Enum.filter(&check_feature_enabled(&1, organization_id))

    {:reply, enabled, state}
  end

  @impl true
  def handle_call({:get_value, feature, organization_id}, _from, state) do
    result = get_feature_value(feature, organization_id)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_quota, metric, organization_id}, _from, state) do
    result = get_quota_limit(metric, organization_id)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:within_quota?, metric, organization_id}, _from, state) do
    result = check_within_quota(metric, organization_id)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:quota_usage_percent, metric, organization_id}, _from, state) do
    result = calculate_quota_usage(metric, organization_id)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:set_override, organization_id, feature, value, opts}, _from, state) do
    expires_at = Keyword.get(opts, :expires_at)
    override = %{value: value, expires_at: expires_at, set_at: DateTime.utc_now()}

    :ets.insert(:feature_overrides, {{organization_id, feature}, override})
    invalidate_cache(organization_id)

    Logger.info("Feature override set: org=#{organization_id} feature=#{feature} value=#{inspect(value)}")
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:remove_override, organization_id, feature}, _from, state) do
    :ets.delete(:feature_overrides, {organization_id, feature})
    invalidate_cache(organization_id)

    Logger.info("Feature override removed: org=#{organization_id} feature=#{feature}")
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:globally_disabled?, feature}, _from, state) do
    result = case :ets.lookup(:kill_switches, feature) do
      [{^feature, true}] -> true
      _ -> false
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call({:set_kill_switch, feature, disabled}, _from, state) do
    :ets.insert(:kill_switches, {feature, disabled})

    Logger.warning("Feature kill switch: feature=#{feature} disabled=#{disabled}")
    {:reply, :ok, state}
  end

  @impl true
  def handle_info(:reload_cache, state) do
    # Clear expired overrides
    now = DateTime.utc_now()

    :ets.tab2list(:feature_overrides)
    |> Enum.each(fn {{org_id, feature}, override} ->
      if override.expires_at && DateTime.compare(now, override.expires_at) == :gt do
        :ets.delete(:feature_overrides, {org_id, feature})
        Logger.info("Override expired: org=#{org_id} feature=#{feature}")
      end
    end)

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp check_feature_enabled(feature, organization_id) do
    # Check kill switch first
    if globally_killed?(feature) do
      false
    else
      # Check override
      case get_override(organization_id, feature) do
        {:ok, value} when is_boolean(value) -> value
        {:ok, _value} -> true  # Non-boolean value means enabled
        :not_found ->
          # Check license-based access
          check_license_feature(feature, organization_id)
      end
    end
  end

  defp globally_killed?(feature) do
    case :ets.lookup(:kill_switches, feature) do
      [{^feature, true}] -> true
      _ -> false
    end
  end

  defp get_override(organization_id, feature) do
    case :ets.lookup(:feature_overrides, {organization_id, feature}) do
      [{{^organization_id, ^feature}, override}] ->
        # Check expiration
        if override.expires_at && DateTime.compare(DateTime.utc_now(), override.expires_at) == :gt do
          :ets.delete(:feature_overrides, {organization_id, feature})
          :not_found
        else
          {:ok, override.value}
        end

      [] ->
        :not_found
    end
  end

  defp check_license_feature(feature, organization_id) do
    requirements = Map.get(@feature_requirements, feature)

    case requirements do
      nil ->
        # Unknown feature, deny by default
        false

      :addon ->
        # Requires add-on license
        check_addon_license(feature, organization_id)

      tiers when is_list(tiers) ->
        # Check if org's tier is in allowed list
        case get_org_tier(organization_id) do
          {:ok, tier} -> tier in tiers
          _ -> false
        end
    end
  end

  defp check_addon_license(feature, organization_id) do
    # Check feature_licenses table for add-on
    from(fl in FeatureLicense,
      where: fl.organization_id == ^organization_id,
      where: fl.feature == ^to_string(feature),
      where: fl.enabled == true,
      where: is_nil(fl.expires_at) or fl.expires_at > ^DateTime.utc_now()
    )
    |> Repo.exists?()
  end

  defp get_org_tier(organization_id) do
    case License.get_license(organization_id) do
      {:ok, license} -> {:ok, license.tier}
      error -> error
    end
  end

  defp get_feature_value(feature, organization_id) do
    case get_override(organization_id, feature) do
      {:ok, value} -> {:ok, value}
      :not_found ->
        if check_feature_enabled(feature, organization_id) do
          {:ok, true}
        else
          :disabled
        end
    end
  end

  defp get_quota_limit(metric, organization_id) do
    case get_org_tier(organization_id) do
      {:ok, tier} ->
        quotas = Map.get(@tier_quotas, tier, %{})
        Map.get(quotas, metric)

      _ ->
        # No license - use trial limits
        quotas = Map.get(@tier_quotas, :trial, %{})
        Map.get(quotas, metric)
    end
  end

  defp check_within_quota(metric, organization_id) do
    limit = get_quota_limit(metric, organization_id)

    case limit do
      :unlimited -> true
      nil -> false
      limit when is_integer(limit) ->
        current = get_current_usage(metric, organization_id)
        current < limit
    end
  end

  defp calculate_quota_usage(metric, organization_id) do
    limit = get_quota_limit(metric, organization_id)

    case limit do
      :unlimited -> :unlimited
      nil -> 100.0  # No quota defined - treat as exceeded
      limit when is_integer(limit) ->
        current = get_current_usage(metric, organization_id)
        (current / limit) * 100.0
    end
  end

  defp get_current_usage(metric, organization_id) do
    case metric do
      :max_agents -> count_agents(organization_id)
      :max_users -> count_users(organization_id)
      :storage_gb -> calculate_storage_usage(organization_id)
      :api_calls_per_day -> count_api_calls_today(organization_id)
      _ -> 0
    end
  end

  defp count_agents(organization_id) do
    from(a in TamanduaServer.Agents.Agent,
      where: a.organization_id == ^organization_id,
      select: count()
    )
    |> Repo.one()
  rescue
    _ -> 0
  end

  defp count_users(organization_id) do
    from(u in TamanduaServer.Accounts.User,
      where: u.organization_id == ^organization_id,
      select: count()
    )
    |> Repo.one()
  rescue
    _ -> 0
  end

  defp calculate_storage_usage(_organization_id) do
    # Placeholder - implement based on your storage tracking
    0.0
  end

  defp count_api_calls_today(_organization_id) do
    # Placeholder - implement based on your API logging
    0
  end

  defp invalidate_cache(organization_id) do
    # Clear any cached feature checks for this org
    :ets.match_delete(:feature_cache, {{organization_id, :_}, :_})
  end
end
