defmodule TamanduaServer.Repo.Migrations.AddBillingTables do
  @moduledoc """
  Migration for billing tables: subscriptions and usage_records.

  This migration creates tables for:
  - Stripe subscription tracking
  - Usage metering (API calls, model scans, storage)
  - Links organizations to Stripe customers
  """

  use Ecto.Migration

  def change do
    # Subscriptions table - links Stripe subscriptions to organizations
    create table(:subscriptions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :stripe_customer_id, :string, null: false
      add :stripe_subscription_id, :string
      add :stripe_price_id, :string

      add :status, :string, null: false, default: "active"  # active, past_due, canceled, trialing
      add :current_period_start, :utc_datetime_usec
      add :current_period_end, :utc_datetime_usec
      add :canceled_at, :utc_datetime_usec
      add :cancel_at_period_end, :boolean, default: false

      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:subscriptions, [:organization_id])
    create unique_index(:subscriptions, [:stripe_customer_id])
    create index(:subscriptions, [:stripe_subscription_id], unique: true, where: "stripe_subscription_id IS NOT NULL")
    create index(:subscriptions, [:status])

    # Usage records - periodic snapshots of metered usage
    create table(:usage_records, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :period_start, :utc_datetime_usec, null: false
      add :period_end, :utc_datetime_usec, null: false

      add :api_calls, :integer, default: 0
      add :model_scans, :integer, default: 0
      add :storage_bytes, :bigint, default: 0
      add :agents_active, :integer, default: 0

      add :reported_to_stripe, :boolean, default: false
      add :stripe_usage_record_ids, {:array, :string}, default: []

      timestamps(type: :utc_datetime_usec)
    end

    create index(:usage_records, [:organization_id, :period_start])
    create index(:usage_records, [:reported_to_stripe])

    # Add Stripe customer ID to organizations for quick lookup
    alter table(:organizations) do
      add :stripe_customer_id, :string
    end

    create unique_index(:organizations, [:stripe_customer_id], where: "stripe_customer_id IS NOT NULL")
  end
end
