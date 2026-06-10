defmodule TamanduaServer.Repo.Migrations.CreateRuleVersions do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:rule_versions, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:rule_type, :string, null: false)
      add(:rule_id, :binary_id, null: false)
      add(:version, :integer, default: 1, null: false)
      add(:content, :text)
      add(:checksum, :string)
      add(:change_summary, :text)

      add(:changed_by, references(:users, type: :binary_id, on_delete: :nilify_all))

      add(
        :organization_id,
        references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists(index(:rule_versions, [:organization_id]))
    create_if_not_exists(index(:rule_versions, [:rule_type, :rule_id]))

    create_if_not_exists(
      unique_index(
        :rule_versions,
        [:rule_type, :rule_id, :version],
        name: :rule_versions_type_id_version_index
      )
    )
  end
end
