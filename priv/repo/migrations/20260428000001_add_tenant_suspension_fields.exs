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
      add :suspended_at, :utc_datetime_usec
      add :suspended_by, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :suspension_reason, :string

      # Reactivation tracking
      add :reactivated_at, :utc_datetime_usec
      add :reactivated_by, references(:users, type: :binary_id, on_delete: :nilify_all)
    end

    # Index for finding suspended/active organizations efficiently
    create index(:organizations, [:is_active])

    # Index for subscription expiration checks
    create index(:organizations, [:subscription_expires_at])

    # Composite index for active subscription queries
    create index(:organizations, [:is_active, :subscription_expires_at])
  end
end
