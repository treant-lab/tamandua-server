defmodule TamanduaServer.Repo.Migrations.CreateRevokedCertificates do
  use Ecto.Migration

  def change do
    create table(:revoked_certificates, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :fingerprint, :string, null: false
      add :serial_number, :string
      add :agent_id, references(:agents, type: :binary_id, on_delete: :nilify_all)
      add :revoked_at, :utc_datetime, null: false
      add :revoked_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :reason, :string
      add :notes, :text
      add :metadata, :map, default: %{}

      timestamps()
    end

    create unique_index(:revoked_certificates, [:fingerprint])
    create index(:revoked_certificates, [:agent_id])
    create index(:revoked_certificates, [:serial_number])
    create index(:revoked_certificates, [:revoked_at])
  end
end
