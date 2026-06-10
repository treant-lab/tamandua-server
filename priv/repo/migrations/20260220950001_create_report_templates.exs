defmodule TamanduaServer.Repo.Migrations.CreateReportTemplates do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:report_templates, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :category, :string, null: false
      add :is_public, :boolean, default: false
      add :is_system, :boolean, default: false

      # Layout configuration
      add :layout, :map, default: %{}

      # Widget configurations
      add :widgets, {:array, :map}, default: []

      # Branding
      add :branding, :map, default: %{}

      # Metadata
      add :created_by, :string
      add :last_modified_by, :string
      add :version, :integer, default: 1
      add :tags, {:array, :string}, default: []

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :user_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      timestamps()
    end

    create_if_not_exists index(:report_templates, [:organization_id])
    create_if_not_exists index(:report_templates, [:user_id])
    create_if_not_exists index(:report_templates, [:category])
    create_if_not_exists index(:report_templates, [:is_public])
    create_if_not_exists index(:report_templates, [:is_system])
    create_if_not_exists index(:report_templates, [:name])
  end
end
