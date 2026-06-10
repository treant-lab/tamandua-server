defmodule TamanduaServer.Accounts.TenantRateLimit do
  @moduledoc """
  Schema for per-tenant rate limiting configuration.

  Rate limits are tied to license tiers and can be customized
  per organization. This allows MSSP providers to allocate
  resources appropriately across their customer base.

  ## Rate Limit Categories

  - **API Requests**: HTTP API calls to the server
  - **Events**: Telemetry events ingested from agents
  - **Webhooks**: Outbound webhook calls for integrations
  - **Storage**: Data retention and storage limits

  ## License Tier Defaults

  - Trial: Conservative limits for evaluation
  - Pro: Production-ready limits for mid-size deployments
  - Enterprise: High limits with customization options
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "tenant_rate_limits" do
    # API rate limits
    field :api_requests_per_minute, :integer, default: 1000
    field :api_requests_per_hour, :integer, default: 50000
    field :api_requests_per_day, :integer, default: 500000

    # Event ingestion limits
    field :events_per_minute, :integer, default: 10000
    field :events_per_hour, :integer, default: 500000

    # Webhook limits
    field :alert_webhooks_per_hour, :integer, default: 1000

    # Storage limits
    field :max_events_retained_days, :integer, default: 90
    field :max_storage_gb, :integer, default: 100

    # Feature limits
    field :max_concurrent_hunts, :integer, default: 5
    field :max_playbooks, :integer, default: 50
    field :max_sigma_rules, :integer, default: 500
    field :max_yara_rules, :integer, default: 200
    field :max_api_keys, :integer, default: 10

    belongs_to :organization, Organization

    timestamps(type: :utc_datetime_usec)
  end

  @fields ~w(
    organization_id
    api_requests_per_minute api_requests_per_hour api_requests_per_day
    events_per_minute events_per_hour
    alert_webhooks_per_hour
    max_events_retained_days max_storage_gb
    max_concurrent_hunts max_playbooks max_sigma_rules max_yara_rules max_api_keys
  )a

  def changeset(rate_limit, attrs) do
    rate_limit
    |> cast(attrs, @fields)
    |> validate_required([:organization_id])
    |> validate_number(:api_requests_per_minute, greater_than: 0)
    |> validate_number(:api_requests_per_hour, greater_than: 0)
    |> validate_number(:api_requests_per_day, greater_than: 0)
    |> validate_number(:events_per_minute, greater_than: 0)
    |> validate_number(:events_per_hour, greater_than: 0)
    |> validate_number(:alert_webhooks_per_hour, greater_than: 0)
    |> validate_number(:max_events_retained_days, greater_than: 0, less_than_or_equal_to: 365)
    |> validate_number(:max_storage_gb, greater_than: 0)
    |> validate_number(:max_concurrent_hunts, greater_than: 0, less_than_or_equal_to: 100)
    |> validate_number(:max_playbooks, greater_than: 0, less_than_or_equal_to: 1000)
    |> validate_number(:max_sigma_rules, greater_than: 0, less_than_or_equal_to: 10000)
    |> validate_number(:max_yara_rules, greater_than: 0, less_than_or_equal_to: 5000)
    |> validate_number(:max_api_keys, greater_than: 0, less_than_or_equal_to: 100)
    |> unique_constraint(:organization_id)
    |> foreign_key_constraint(:organization_id)
  end

  @doc """
  Returns default rate limits for a license tier.
  """
  def defaults_for_tier(:trial) do
    %{
      api_requests_per_minute: 100,
      api_requests_per_hour: 5000,
      api_requests_per_day: 50000,
      events_per_minute: 1000,
      events_per_hour: 50000,
      alert_webhooks_per_hour: 100,
      max_events_retained_days: 14,
      max_storage_gb: 10,
      max_concurrent_hunts: 2,
      max_playbooks: 10,
      max_sigma_rules: 100,
      max_yara_rules: 50,
      max_api_keys: 2
    }
  end

  def defaults_for_tier(:pro) do
    %{
      api_requests_per_minute: 1000,
      api_requests_per_hour: 50000,
      api_requests_per_day: 500000,
      events_per_minute: 10000,
      events_per_hour: 500000,
      alert_webhooks_per_hour: 1000,
      max_events_retained_days: 90,
      max_storage_gb: 100,
      max_concurrent_hunts: 10,
      max_playbooks: 100,
      max_sigma_rules: 500,
      max_yara_rules: 200,
      max_api_keys: 20
    }
  end

  def defaults_for_tier(:enterprise) do
    %{
      api_requests_per_minute: 10000,
      api_requests_per_hour: 500000,
      api_requests_per_day: 5000000,
      events_per_minute: 100000,
      events_per_hour: 5000000,
      alert_webhooks_per_hour: 10000,
      max_events_retained_days: 365,
      max_storage_gb: 1000,
      max_concurrent_hunts: 50,
      max_playbooks: 500,
      max_sigma_rules: 5000,
      max_yara_rules: 2000,
      max_api_keys: 100
    }
  end

  def defaults_for_tier(_), do: defaults_for_tier(:trial)
end
