defmodule TamanduaServer.Repo.Migrations.AddProofManifestFieldsToAlerts do
  use Ecto.Migration

  def change do
    alter table(:alerts) do
      add :incident_hash, :string
      add :manifest_hash, :string
      add :attestation_tlp, :string
      add :attestation_ioc_count, :integer
      add :attestation_ioc_types, {:array, :string}, default: []
      add :attestation_redacted_ioc_count, :integer
      add :attestation_confidence, :float
      add :attestation_threat_class, :string
      add :attestation_malware_family, :string
      add :public_manifest, :map, default: %{}
    end

    create index(:alerts, [:incident_hash], where: "incident_hash IS NOT NULL")
    create index(:alerts, [:manifest_hash], where: "manifest_hash IS NOT NULL")
  end
end
