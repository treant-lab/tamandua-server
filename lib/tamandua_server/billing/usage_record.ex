defmodule TamanduaServer.Billing.UsageRecord do
  @moduledoc """
  Schema for periodic usage snapshots.

  Usage records capture aggregated metrics for each organization over
  time periods (typically 5 minutes). These are used for:

  - Billing reports and invoices
  - Usage analytics and dashboards
  - Stripe metered billing reporting

  ## Fields

  - `api_calls` - Number of API requests made
  - `model_scans` - Number of ML model scans performed
  - `storage_bytes` - Current storage usage in bytes
  - `agents_active` - Number of active agents
  - `reported_to_stripe` - Whether usage was synced to Stripe
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "usage_records" do
    belongs_to :organization, TamanduaServer.Accounts.Organization

    field :period_start, :utc_datetime_usec
    field :period_end, :utc_datetime_usec

    field :api_calls, :integer, default: 0
    field :model_scans, :integer, default: 0
    field :storage_bytes, :integer, default: 0
    field :agents_active, :integer, default: 0

    field :reported_to_stripe, :boolean, default: false
    field :stripe_usage_record_ids, {:array, :string}, default: []

    timestamps(type: :utc_datetime_usec)
  end

  @doc """
  Creates a changeset for a usage record.
  """
  def changeset(record, attrs) do
    record
    |> cast(attrs, [
      :organization_id,
      :period_start,
      :period_end,
      :api_calls,
      :model_scans,
      :storage_bytes,
      :agents_active,
      :reported_to_stripe,
      :stripe_usage_record_ids
    ])
    |> validate_required([:organization_id, :period_start, :period_end])
    |> validate_number(:api_calls, greater_than_or_equal_to: 0)
    |> validate_number(:model_scans, greater_than_or_equal_to: 0)
    |> validate_number(:storage_bytes, greater_than_or_equal_to: 0)
    |> validate_number(:agents_active, greater_than_or_equal_to: 0)
    |> foreign_key_constraint(:organization_id)
  end

  @doc """
  Marks the record as reported to Stripe.
  """
  def mark_reported_changeset(record, usage_record_ids \\ []) do
    record
    |> change(%{
      reported_to_stripe: true,
      stripe_usage_record_ids: usage_record_ids
    })
  end
end
