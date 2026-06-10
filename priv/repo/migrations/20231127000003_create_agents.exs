defmodule TamanduaServer.Repo.Migrations.CreateAgents do
  use Ecto.Migration

  def change do
    create table(:agents, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :hostname, :string, null: false
      add :os_type, :string, null: false
      add :os_version, :string
      add :agent_version, :string
      add :machine_id, :binary
      add :status, :string, default: "offline"
      add :last_seen_at, :utc_datetime_usec
      add :ip_address, :string
      add :config, :map, default: %{}
      add :tags, {:array, :string}, default: []
      add :capabilities, {:array, :string}, default: []

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:agents, [:machine_id], where: "machine_id IS NOT NULL")
    create index(:agents, [:organization_id])
    create index(:agents, [:status])
    create index(:agents, [:last_seen_at])
    create index(:agents, [:hostname])
  end
end
