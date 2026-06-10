defmodule TamanduaServer.Integrations.Schemas.HealthMetric do
  @moduledoc """
  Schema for integration health metrics.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Repo

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "integration_health_metrics" do
    field :integration_id, :binary_id

    # Connection status
    field :status, :string
    field :last_connected_at, :utc_datetime
    field :last_disconnected_at, :utc_datetime

    # API rate limits
    field :rate_limit_total, :integer
    field :rate_limit_used, :integer
    field :rate_limit_remaining, :integer
    field :rate_limit_reset_at, :utc_datetime

    # Error rates
    field :errors_per_minute, :float
    field :errors_5xx_count, :integer
    field :errors_4xx_count, :integer
    field :total_errors, :integer
    field :total_requests, :integer

    # Latency metrics
    field :latency_avg, :float
    field :latency_p50, :float
    field :latency_p95, :float
    field :latency_p99, :float

    # Sync status
    field :last_sync_at, :utc_datetime
    field :sync_lag_seconds, :integer
    field :pending_items, :integer
    field :synced_items, :integer

    # Credential status
    field :credential_expires_at, :utc_datetime
    field :credential_status, :string

    # Health check
    field :last_health_check_at, :utc_datetime
    field :last_health_check_success, :boolean
    field :health_check_failures, :integer

    field :error_message, :string
    field :metadata, :map

    timestamps()
  end

  @fields [
    :integration_id, :status, :last_connected_at, :last_disconnected_at,
    :rate_limit_total, :rate_limit_used, :rate_limit_remaining, :rate_limit_reset_at,
    :errors_per_minute, :errors_5xx_count, :errors_4xx_count, :total_errors, :total_requests,
    :latency_avg, :latency_p50, :latency_p95, :latency_p99,
    :last_sync_at, :sync_lag_seconds, :pending_items, :synced_items,
    :credential_expires_at, :credential_status,
    :last_health_check_at, :last_health_check_success, :health_check_failures,
    :error_message, :metadata
  ]

  def changeset(metric, attrs) do
    metric
    |> cast(attrs, @fields)
    |> validate_required([:integration_id])
  end

  def create_or_update(integration_id, attrs) do
    case get_latest(integration_id) do
      nil ->
        %__MODULE__{integration_id: integration_id}
        |> changeset(attrs)
        |> Repo.insert()

      existing ->
        existing
        |> changeset(attrs)
        |> Repo.update()
    end
  end

  def get_latest(integration_id) do
    from(m in __MODULE__,
      where: m.integration_id == ^integration_id,
      order_by: [desc: m.inserted_at],
      limit: 1
    )
    |> Repo.one()
  end

  def list_all do
    from(m in __MODULE__,
      order_by: [desc: m.inserted_at]
    )
    |> Repo.all()
  end
end
