defmodule TamanduaServer.Repo.Migrations.AddTenantSuspensionFields do
  use Ecto.Migration

  @moduledoc """
  Adds suspension tracking fields to organizations table.

  These fields enable:
  - Tracking when and why an organization was suspended
  - Audit trail of who performed the suspension
  - Quick filtering of suspended organizations
  """

  def change do
    alter table(:organizations) do
      # Suspension tracking
      add_if_not_exists :suspended_at, :utc_datetime_usec
      add_if_not_exists :suspended_by, references(:users, type: :binary_id, on_delete: :nilify_all)
      add_if_not_exists :suspension_reason, :string

      # Reactivation tracking
      add_if_not_exists :reactivated_at, :utc_datetime_usec
      add_if_not_exists :reactivated_by, references(:users, type: :binary_id, on_delete: :nilify_all)
    end

    # Index for finding suspended/active organizations efficiently
    create_if_not_exists index(:organizations, [:is_active])

    # Index for subscription expiration checks
    create_if_not_exists index(:organizations, [:subscription_expires_at])

    # Composite index for active subscription queries
    create_if_not_exists index(:organizations, [:is_active, :subscription_expires_at])
  end
end
