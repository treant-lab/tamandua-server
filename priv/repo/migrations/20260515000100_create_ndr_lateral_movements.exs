defmodule TamanduaServer.Repo.Migrations.CreateNdrLateralMovements do
  use Ecto.Migration

  def change do
    create table(:ndr_lateral_movements, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all)
      add :type, :string, null: false
      add :src_ip, :string
      add :dst_ip, :string
      add :port, :integer
      add :ports_scanned, :integer
      add :hosts_scanned, :integer
      add :username, :string
      add :target_hosts, {:array, :string}, default: [], null: false
      add :metadata, :map, default: %{}, null: false
      add :timestamp, :utc_datetime_usec, null: false

      timestamps(type: :utc_datetime_usec)
    end

    create index(:ndr_lateral_movements, [:organization_id, :timestamp])
    create index(:ndr_lateral_movements, [:agent_id, :timestamp])
    create index(:ndr_lateral_movements, [:type, :timestamp])
    create index(:ndr_lateral_movements, [:src_ip])
    create index(:ndr_lateral_movements, [:dst_ip])
    create index(:ndr_lateral_movements, [:username])
  end
end
