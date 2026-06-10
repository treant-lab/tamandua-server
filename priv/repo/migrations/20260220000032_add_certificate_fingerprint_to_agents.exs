defmodule TamanduaServer.Repo.Migrations.AddCertificateFingerprintToAgents do
  use Ecto.Migration

  def change do
    alter table(:agents) do
      add :certificate_fingerprint, :string
      add :certificate_subject, :string
      add :certificate_valid_until, :utc_datetime
    end

    create index(:agents, [:certificate_fingerprint])
  end
end
