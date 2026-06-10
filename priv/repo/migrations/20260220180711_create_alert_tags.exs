defmodule TamanduaServer.Repo.Migrations.CreateAlertTags do
  use Ecto.Migration

  def change do
    # Alert tags table
    create table(:alert_tags, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :color, :string, default: "#6B7280"  # Default gray
      add :category, :string  # predefined categories: malware, phishing, lateral_movement, data_exfil, etc.
      add :metadata, :map, default: %{}  # JSONB for extensibility
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false
      add :created_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:alert_tags, [:organization_id, :name], name: :alert_tags_org_name_unique)
    create index(:alert_tags, [:organization_id])
    create index(:alert_tags, [:category])

    # Many-to-many join table for alert-tag associations
    create table(:alert_tag_assignments, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :alert_id, references(:alerts, type: :binary_id, on_delete: :delete_all), null: false
      add :tag_id, references(:alert_tags, type: :binary_id, on_delete: :delete_all), null: false
      add :assigned_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create unique_index(:alert_tag_assignments, [:alert_id, :tag_id], name: :alert_tag_assignments_unique)
    create index(:alert_tag_assignments, [:alert_id])
    create index(:alert_tag_assignments, [:tag_id])
    create index(:alert_tag_assignments, [:assigned_by_id])
  end
end
