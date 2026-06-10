defmodule TamanduaServer.Repo.Migrations.CreateGeneratedYaraRules do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:generated_yara_rules, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :rule_content, :text, null: false
      add :source_hash, :string, null: false
      add :malware_family, :string
      add :ml_confidence, :float, null: false
      add :status, :string, null: false, default: "staged"
      add :expires_at, :utc_datetime_usec, null: false
      add :reviewed_at, :utc_datetime_usec
      add :metadata, :map, default: %{}

      add :reviewed_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists unique_index(:generated_yara_rules, [:name])
    create_if_not_exists index(:generated_yara_rules, [:source_hash])
    create_if_not_exists index(:generated_yara_rules, [:status])
    create_if_not_exists index(:generated_yara_rules, [:malware_family])
    create_if_not_exists index(:generated_yara_rules, [:expires_at])
    create_if_not_exists index(:generated_yara_rules, [:organization_id])
    create_if_not_exists index(:generated_yara_rules, [:ml_confidence])
  end
end
