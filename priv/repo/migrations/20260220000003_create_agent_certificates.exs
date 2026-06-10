defmodule TamanduaServer.Repo.Migrations.CreateAgentCertificates do
  use Ecto.Migration

  def change do
    create table(:agent_certificates, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false
      add :fingerprint, :string, null: false
      add :public_key_hash, :binary, null: false
      add :subject_dn, :string
      add :issuer_dn, :string
      add :serial_number, :string
      add :valid_from, :utc_datetime, null: false
      add :valid_until, :utc_datetime, null: false
      add :first_seen_at, :utc_datetime, null: false
      add :last_seen_at, :utc_datetime, null: false
      add :pinned, :boolean, default: true
      add :metadata, :map, default: %{}

      timestamps()
    end

    create unique_index(:agent_certificates, [:fingerprint])
    create index(:agent_certificates, [:agent_id])
    create index(:agent_certificates, [:public_key_hash])
    create index(:agent_certificates, [:valid_until])
  end
end
