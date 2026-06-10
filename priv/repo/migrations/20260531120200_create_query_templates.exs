defmodule TamanduaServer.Repo.Migrations.CreateQueryTemplates do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:query_templates, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:name, :string)
      add(:description, :text)
      add(:category, :string)
      add(:subcategory, :string)
      add(:query, :text)
      add(:query_format, :string, default: "tql")
      add(:tags, {:array, :string}, default: [], null: false)
      add(:mitre_techniques, {:array, :string}, default: [], null: false)
      add(:severity, :string)
      add(:is_built_in, :boolean, default: false, null: false)
      add(:is_public, :boolean, default: false, null: false)
      add(:usage_count, :integer, default: 0, null: false)
      add(:variables, :map, default: %{}, null: false)

      # Built-in/public templates may not belong to a specific org or author.
      add(:organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all))
      add(:created_by_id, references(:users, type: :binary_id, on_delete: :nilify_all))

      timestamps()
    end

    create_if_not_exists(index(:query_templates, [:organization_id]))
    create_if_not_exists(index(:query_templates, [:created_by_id]))
    create_if_not_exists(index(:query_templates, [:category]))
    create_if_not_exists(index(:query_templates, [:is_built_in]))
    create_if_not_exists(index(:query_templates, [:is_public]))
  end
end
