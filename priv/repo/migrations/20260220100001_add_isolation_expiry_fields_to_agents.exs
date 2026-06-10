defmodule TamanduaServer.Repo.Migrations.AddIsolationExpiryFieldsToAgents do
  use Ecto.Migration

  def change do
    alter table(:agents) do
      add :isolation_expires_at, :utc_datetime
      add :previous_network_state, :jsonb
      add :isolation_exceptions, {:array, :jsonb}, default: fragment("'{}'")
    end

    # Add index for efficient expiry queries
    create index(:agents, [:isolation_expires_at], where: "isolation_expires_at IS NOT NULL")
  end
end
