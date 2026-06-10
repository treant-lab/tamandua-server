defmodule TamanduaServer.Repo.Migrations.CreateNdrProtocolPersistence do
  use Ecto.Migration

  def change do
    create table(:ndr_protocol_stats, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :stats_key, :string, null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all)
      add :protocol, :string, null: false
      add :connection_count, :bigint, default: 0, null: false
      add :total_bytes, :bigint, default: 0, null: false
      add :first_seen, :utc_datetime_usec, null: false
      add :last_seen, :utc_datetime_usec, null: false
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:ndr_protocol_stats, [:stats_key])
    create index(:ndr_protocol_stats, [:organization_id, :last_seen])
    create index(:ndr_protocol_stats, [:agent_id, :last_seen])
    create index(:ndr_protocol_stats, [:protocol])

    create table(:ndr_protocol_observations, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :observation_type, :string, null: false
      add :observation_key, :string, null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all)
      add :src_ip, :string
      add :dst_ip, :string
      add :command, :string
      add :share, :string
      add :file, :text
      add :connection_count, :bigint, default: 1, null: false
      add :first_seen, :utc_datetime_usec, null: false
      add :last_seen, :utc_datetime_usec, null: false
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:ndr_protocol_observations, [:observation_key])
    create index(:ndr_protocol_observations, [:organization_id, :last_seen])
    create index(:ndr_protocol_observations, [:agent_id, :last_seen])
    create index(:ndr_protocol_observations, [:observation_type, :last_seen])
    create index(:ndr_protocol_observations, [:src_ip])
    create index(:ndr_protocol_observations, [:dst_ip])
  end
end
