defmodule TamanduaServer.Repo.Migrations.CreateRuleImportJobs do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:rule_import_jobs, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:type, :string)
      add(:source_type, :string)
      add(:source_url, :string)
      add(:status, :string, default: "pending")
      add(:total_rules, :integer, default: 0, null: false)
      add(:imported_rules, :integer, default: 0, null: false)
      add(:skipped_rules, :integer, default: 0, null: false)
      add(:failed_rules, :integer, default: 0, null: false)
      add(:error_message, :text)
      add(:conflict_resolution, :string, default: "skip")
      add(:validation_enabled, :boolean, default: true, null: false)
      add(:metadata, :map, default: %{}, null: false)
      add(:started_at, :utc_datetime_usec)
      add(:completed_at, :utc_datetime_usec)

      add(
        :organization_id,
        references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:user_id, references(:users, type: :binary_id, on_delete: :nilify_all))

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists(index(:rule_import_jobs, [:organization_id]))
    create_if_not_exists(index(:rule_import_jobs, [:status]))
  end
end
