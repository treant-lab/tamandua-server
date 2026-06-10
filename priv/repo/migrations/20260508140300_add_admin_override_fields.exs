defmodule TamanduaServer.Repo.Migrations.AddAdminOverrideFields do
  @moduledoc """
  Adds admin override audit fields to submissions and bounty_claims tables.

  These fields track when an admin bypasses automated bounty eligibility checks,
  providing an audit trail for compliance and security review.
  """
  use Ecto.Migration

  def change do
    # Add admin override fields to submissions
    alter table(:submissions) do
      add :admin_override_reason, :string
      add :admin_override_at, :utc_datetime_usec
      add :admin_override_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
    end

    # Add admin override fields to bounty_claims
    alter table(:bounty_claims) do
      add :admin_override, :boolean, default: false
      add :admin_override_reason, :string
      add :admin_override_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
    end

    # Index for querying overridden submissions
    create index(:submissions, [:admin_override_at], where: "admin_override_at IS NOT NULL")
    create index(:bounty_claims, [:admin_override], where: "admin_override = true")
  end
end
