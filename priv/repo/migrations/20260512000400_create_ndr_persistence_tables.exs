defmodule TamanduaServer.Repo.Migrations.CreateNdrPersistenceTables do
  use Ecto.Migration

  def change do
    create table(:ndr_tls_sessions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all)
      add :event_id, :binary_id
      add :timestamp, :utc_datetime_usec, null: false
      add :local_ip, :string
      add :local_port, :integer
      add :remote_ip, :string
      add :remote_port, :integer
      add :protocol, :string
      add :domain, :string
      add :sni, :string
      add :tls_version, :string
      add :ja3, :string
      add :ja3s, :string
      add :certificate_fingerprint, :string
      add :certificate, :map, default: %{}
      add :certificate_risk, :float
      add :enrichment, :map, default: %{}
      add :process, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create index(:ndr_tls_sessions, [:organization_id, :timestamp])
    create index(:ndr_tls_sessions, [:agent_id, :timestamp])
    create index(:ndr_tls_sessions, [:remote_ip])
    create index(:ndr_tls_sessions, [:domain])
    create index(:ndr_tls_sessions, [:sni])
    create index(:ndr_tls_sessions, [:ja3])
    create index(:ndr_tls_sessions, [:ja3s])

    create table(:ndr_ja3_stats, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all)
      add :ja3_hash, :string, null: false
      add :ja3s_hash, :string
      add :occurrence_count, :integer, default: 1, null: false
      add :first_seen, :utc_datetime_usec, null: false
      add :last_seen, :utc_datetime_usec, null: false
      add :destinations, {:array, :string}, default: []
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:ndr_ja3_stats, [:organization_id, :agent_id, :ja3_hash])
    create index(:ndr_ja3_stats, [:ja3_hash])
    create index(:ndr_ja3_stats, [:last_seen])

    create table(:ndr_certificate_analyses, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all)
      add :event_id, :binary_id
      add :remote_ip, :string
      add :remote_port, :integer
      add :domain, :string
      add :fingerprint, :string
      add :subject, :text
      add :issuer, :text
      add :not_before, :utc_datetime_usec
      add :not_after, :utc_datetime_usec
      add :is_self_signed, :boolean, default: false
      add :risk_score, :float
      add :certificate, :map, default: %{}
      add :analysis, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create index(:ndr_certificate_analyses, [:organization_id, :inserted_at])
    create index(:ndr_certificate_analyses, [:agent_id, :inserted_at])
    create index(:ndr_certificate_analyses, [:remote_ip])
    create index(:ndr_certificate_analyses, [:domain])
    create index(:ndr_certificate_analyses, [:fingerprint])
  end
end
