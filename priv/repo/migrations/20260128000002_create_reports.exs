defmodule TamanduaServer.Repo.Migrations.CreateReports do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:reports, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :template_id, :string, null: false
      add :date_from, :string, null: false
      add :date_to, :string, null: false
      add :generated_by, :string
      add :status, :string, default: "ready"
      add :data, :map, default: %{}
      add :user_id, references(:users, on_delete: :nilify_all, type: :binary_id)
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps()
    end

    create_if_not_exists index(:reports, [:template_id])
    create_if_not_exists index(:reports, [:user_id])
    create_if_not_exists index(:reports, [:inserted_at])
    create_if_not_exists index(:reports, [:status])
    create_if_not_exists index(:reports, [:organization_id])
  end
end
