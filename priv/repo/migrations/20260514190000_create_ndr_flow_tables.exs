defmodule TamanduaServer.Repo.Migrations.CreateNdrFlowTables do
  use Ecto.Migration

  def change do
    create table(:ndr_flows, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all)
      add :flow_key, :string, null: false
      add :src_ip, :string, null: false
      add :src_port, :integer
      add :dst_ip, :string, null: false
      add :dst_port, :integer
      add :protocol, :string, null: false
      add :bytes_sent, :bigint, default: 0, null: false
      add :bytes_received, :bigint, default: 0, null: false
      add :total_bytes, :bigint, default: 0, null: false
      add :packet_count, :bigint, default: 0, null: false
      add :process_name, :string
      add :process_pid, :integer
      add :first_seen, :utc_datetime_usec, null: false
      add :last_seen, :utc_datetime_usec, null: false
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:ndr_flows, [:flow_key])
    create index(:ndr_flows, [:organization_id, :last_seen])
    create index(:ndr_flows, [:agent_id, :last_seen])
    create index(:ndr_flows, [:src_ip])
    create index(:ndr_flows, [:dst_ip])
    create index(:ndr_flows, [:protocol])
    create index(:ndr_flows, [:total_bytes])
  end
end
