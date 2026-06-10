defmodule TamanduaServer.Licensing.LicenseManager do
  @moduledoc """
  High-level license management API.

  Provides a unified interface for:
  - License activation/deactivation
  - License validation
  - Usage tracking
  - Feature checks
  - Upgrade/downgrade handling
  """

  use GenServer
  require Logger

  alias TamanduaServer.Licensing.{License, Activation, LicenseKey, FeatureLicense}
  alias TamanduaServer.Repo

  import Ecto.Query

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get license information for an organization.

  Returns a comprehensive license status including:
  - License tier and type
  - Expiration information
  - Usage statistics
  - Feature availability
  """
  @spec get_license_info(binary()) :: {:ok, map()} | {:error, term()}
  def get_license_info(organization_id) do
    GenServer.call(__MODULE__, {:get_license_info, organization_id})
  end

  @doc """
  Activate a license key for an organization.

  Options:
  - `:activation_ip` - IP address of the activating machine
  - `:activated_by` - User ID who activated
  - `:offline` - Whether this is an offline activation
  """
  @spec activate_license(binary(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def activate_license(organization_id, license_key, opts \\ []) do
    GenServer.call(__MODULE__, {:activate_license, organization_id, license_key, opts})
  end

  @doc """
  Deactivate the current license for an organization.

  This allows the license to be transferred to another organization.
  """
  @spec deactivate_license(binary()) :: {:ok, :deactivated} | {:error, term()}
  def deactivate_license(organization_id) do
    GenServer.call(__MODULE__, {:deactivate_license, organization_id})
  end

  @doc """
  Validate a license key without activating it.

  Returns information about the license key if valid.
  """
  @spec validate_license_key(String.t()) :: {:ok, map()} | {:error, term()}
  def validate_license_key(license_key) do
    GenServer.call(__MODULE__, {:validate_license_key, license_key})
  end

  @doc """
  Check if a specific feature is available for an organization.
  """
  @spec feature_available?(binary(), atom()) :: boolean()
  def feature_available?(organization_id, feature) do
    case get_license_info(organization_id) do
      {:ok, info} ->
        feature in (info.features || [])
      _ ->
        false
    end
  end

  @doc """
  Check if an organization can add more agents.
  """
  @spec can_add_agent?(binary()) :: boolean()
  def can_add_agent?(organization_id) do
    case get_license_info(organization_id) do
      {:ok, info} ->
        info.agent_count < info.agent_limit
      _ ->
        false
    end
  end

  @doc """
  Get remaining agent capacity.
  """
  @spec remaining_agent_capacity(binary()) :: non_neg_integer()
  def remaining_agent_capacity(organization_id) do
    case get_license_info(organization_id) do
      {:ok, info} ->
        max(info.agent_limit - info.agent_count, 0)
      _ ->
        0
    end
  end

  @doc """
  Get usage metrics for billing.
  """
  @spec get_usage_metrics(binary(), keyword()) :: {:ok, map()} | {:error, term()}
  def get_usage_metrics(organization_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_usage_metrics, organization_id, opts})
  end

  @doc """
  Record a usage event for metering.
  """
  @spec record_usage(binary(), atom(), number(), map()) :: :ok | {:error, term()}
  def record_usage(organization_id, metric_type, value, metadata \\ %{}) do
    GenServer.cast(__MODULE__, {:record_usage, organization_id, metric_type, value, metadata})
  end

  @doc """
  Generate an offline activation request.
  """
  @spec generate_offline_request(binary(), String.t()) :: {:ok, String.t()} | {:error, term()}
  def generate_offline_request(organization_id, license_key) do
    GenServer.call(__MODULE__, {:generate_offline_request, organization_id, license_key})
  end

  @doc """
  Complete an offline activation.
  """
  @spec complete_offline_activation(binary(), String.t()) :: {:ok, map()} | {:error, term()}
  def complete_offline_activation(organization_id, activation_response) do
    GenServer.call(__MODULE__, {:complete_offline_activation, organization_id, activation_response})
  end

  @doc """
  Get all license notifications for an organization.
  """
  @spec get_notifications(binary()) :: {:ok, [map()]} | {:error, term()}
  def get_notifications(organization_id) do
    GenServer.call(__MODULE__, {:get_notifications, organization_id})
  end

  @doc """
  Acknowledge a license notification.
  """
  @spec acknowledge_notification(binary(), binary()) :: :ok | {:error, term()}
  def acknowledge_notification(organization_id, notification_id) do
    GenServer.call(__MODULE__, {:acknowledge_notification, organization_id, notification_id})
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Schedule periodic license checks
    :timer.send_interval(3600_000, :check_licenses)

    Logger.info("License Manager started")

    {:ok, %{
      notifications: %{},  # org_id => [notification]
      acknowledged: MapSet.new()
    }}
  end

  @impl true
  def handle_call({:get_license_info, organization_id}, _from, state) do
    result = build_license_info(organization_id)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:activate_license, organization_id, license_key, opts}, _from, state) do
    result = do_activate_license(organization_id, license_key, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:deactivate_license, organization_id}, _from, state) do
    result = do_deactivate_license(organization_id)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:validate_license_key, license_key}, _from, state) do
    result = do_validate_license_key(license_key)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_usage_metrics, organization_id, opts}, _from, state) do
    result = do_get_usage_metrics(organization_id, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:generate_offline_request, organization_id, license_key}, _from, state) do
    result = Activation.generate_offline_request(organization_id, license_key)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:complete_offline_activation, organization_id, response}, _from, state) do
    result = Activation.complete_offline_activation(organization_id, response)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_notifications, organization_id}, _from, state) do
    notifications = Map.get(state.notifications, organization_id, [])
    |> Enum.map(fn n ->
      Map.put(n, :acknowledged, MapSet.member?(state.acknowledged, n.id))
    end)

    {:reply, {:ok, notifications}, state}
  end

  @impl true
  def handle_call({:acknowledge_notification, _organization_id, notification_id}, _from, state) do
    new_acknowledged = MapSet.put(state.acknowledged, notification_id)
    {:reply, :ok, %{state | acknowledged: new_acknowledged}}
  end

  @impl true
  def handle_cast({:record_usage, organization_id, metric_type, value, metadata}, state) do
    License.record_usage(organization_id, metric_type, value, metadata)
    {:noreply, state}
  end

  @impl true
  def handle_info(:check_licenses, state) do
    new_state = check_expiring_licenses(state)
    {:noreply, new_state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp build_license_info(organization_id) do
    case License.get_license(organization_id) do
      {:ok, license} ->
        usage = License.get_usage(organization_id)

        {:ok, %{
          id: license.id,
          organization_id: organization_id,
          license_type: license.tier,
          license_key_masked: mask_license_key(license.license_key),
          expires_at: license.expires_at,
          issued_at: license.issued_at,
          status: usage.license_status,
          features: format_features(license.features),
          seats_used: usage.agent_count,
          seats_total: license.agent_limit,
          days_remaining: usage.days_remaining,
          in_grace_period: usage.in_grace_period,
          billing_cycle: license.billing_cycle,
          auto_renew: license.auto_renew
        }}

      {:error, :no_license} ->
        {:ok, nil}

      error ->
        error
    end
  end

  defp do_activate_license(organization_id, license_key, opts) do
    with {:ok, _claims} <- License.verify_license_key(license_key),
         {:ok, license} <- License.activate_license(organization_id, license_key) do

      # Update activation metadata
      activation_attrs = %{
        activation_ip: Keyword.get(opts, :activation_ip),
        activated_by: Keyword.get(opts, :activated_by),
        activated_at: DateTime.utc_now()
      }

      license
      |> LicenseKey.changeset(activation_attrs)
      |> Repo.update()

      build_license_info(organization_id)
    end
  end

  defp do_deactivate_license(organization_id) do
    case License.deactivate_license(organization_id) do
      {:ok, _} ->
        {:ok, :deactivated}
      error ->
        error
    end
  end

  defp do_validate_license_key(license_key) do
    case License.verify_license_key(license_key) do
      {:ok, claims} ->
        {:ok, %{
          valid: true,
          message: "License key is valid",
          tier: String.to_existing_atom(claims["tier"]),
          expires_at: DateTime.from_unix!(claims["exp"]),
          agent_limit: claims["agent_limit"],
          features: claims["features"]
        }}

      {:error, :invalid_signature} ->
        {:ok, %{valid: false, message: "Invalid license key signature"}}

      {:error, :invalid_format} ->
        {:ok, %{valid: false, message: "Invalid license key format"}}

      {:error, :license_expired} ->
        {:ok, %{valid: false, message: "License key has expired"}}

      {:error, reason} ->
        {:ok, %{valid: false, message: "Validation failed: #{reason}"}}
    end
  end

  defp do_get_usage_metrics(organization_id, opts) do
    metrics = License.get_usage_metrics(organization_id, opts)

    # Calculate additional metrics
    agent_count = get_agent_count(organization_id)
    events_24h = count_events(organization_id, hours: 24)
    threats_24h = count_threats(organization_id, hours: 24)

    {:ok, %{
      endpoints_protected: agent_count,
      events_processed: Enum.find(metrics, & &1.metric_type == "events_processed")[:total] || 0,
      events_processed_24h: events_24h,
      threats_blocked: Enum.find(metrics, & &1.metric_type == "threats_blocked")[:total] || 0,
      threats_blocked_24h: threats_24h,
      storage_used_gb: calculate_storage(organization_id),
      storage_limit_gb: get_storage_limit(organization_id),
      api_calls_24h: count_api_calls(organization_id, hours: 24),
      api_calls_limit: get_api_limit(organization_id)
    }}
  end

  defp check_expiring_licenses(state) do
    # Find licenses expiring in the next 30 days
    thirty_days = DateTime.add(DateTime.utc_now(), 30, :day)

    expiring = from(l in LicenseKey,
      where: l.is_active == true,
      where: l.expires_at <= ^thirty_days,
      select: l
    )
    |> Repo.all()

    new_notifications = Enum.reduce(expiring, state.notifications, fn license, acc ->
      days = calculate_days_remaining(license.expires_at)
      notification = create_expiration_notification(license, days)

      org_notifications = Map.get(acc, license.organization_id, [])
      |> Enum.reject(& &1.type == :expiration_warning)
      |> then(& [notification | &1])

      Map.put(acc, license.organization_id, org_notifications)
    end)

    %{state | notifications: new_notifications}
  end

  defp create_expiration_notification(license, days_remaining) do
    type = if days_remaining <= 0, do: :expired, else: :expiration_warning

    message = cond do
      days_remaining <= 0 ->
        "Your license has expired. Please renew to continue using all features."
      days_remaining <= 7 ->
        "Your license expires in #{days_remaining} days. Renew now to avoid service interruption."
      days_remaining <= 14 ->
        "Your license expires in #{days_remaining} days."
      true ->
        "Your license will expire in #{days_remaining} days."
    end

    %{
      id: "license-#{license.id}-#{type}",
      type: type,
      message: message,
      created_at: DateTime.utc_now(),
      license_id: license.id,
      organization_id: license.organization_id
    }
  end

  defp mask_license_key(nil), do: nil
  defp mask_license_key(key) when byte_size(key) < 10, do: "****"
  defp mask_license_key(key) do
    # Decode the JWT and get the last 4 chars of the nonce for display
    case String.split(key, ".") do
      [_, payload_b64, _] ->
        case Base.url_decode64(payload_b64, padding: false) do
          {:ok, payload} ->
            case Jason.decode(payload) do
              {:ok, %{"nonce" => nonce}} when is_binary(nonce) ->
                "XXXX-XXXX-XXXX-#{String.upcase(String.slice(nonce, -4..-1))}"
              _ ->
                "XXXX-XXXX-XXXX-XXXX"
            end
          _ ->
            "XXXX-XXXX-XXXX-XXXX"
        end
      _ ->
        "XXXX-XXXX-XXXX-XXXX"
    end
  end

  defp format_features(nil), do: []
  defp format_features(features) when is_list(features) do
    Enum.map(features, fn feature ->
      description = FeatureLicense.feature_description(to_string(feature))
      %{
        name: to_string(feature),
        description: description,
        enabled: true,
        category: categorize_feature(feature)
      }
    end)
  end

  defp categorize_feature(feature) do
    categories = FeatureLicense.features_by_category()

    feature_str = to_string(feature)

    cond do
      feature_str in categories.core -> :core
      feature_str in categories.advanced -> :advanced
      feature_str in categories.enterprise -> :enterprise
      feature_str in categories.mssp -> :mssp
      feature_str in categories.addons -> :addon
      true -> :core
    end
  end

  defp calculate_days_remaining(expires_at) do
    now = DateTime.utc_now()
    diff = DateTime.diff(expires_at, now, :day)
    max(diff, 0)
  end

  # Helper functions for metrics (stubs - implement based on your data model)

  defp get_agent_count(organization_id) do
    from(a in TamanduaServer.Agents.Agent,
      where: a.organization_id == ^organization_id,
      select: count()
    )
    |> Repo.one()
  rescue
    _ -> 0
  end

  defp count_events(_organization_id, _opts), do: 0
  defp count_threats(_organization_id, _opts), do: 0
  defp count_api_calls(_organization_id, _opts), do: 0
  defp calculate_storage(_organization_id), do: 0.0
  defp get_storage_limit(_organization_id), do: 100.0
  defp get_api_limit(_organization_id), do: 10000
end
