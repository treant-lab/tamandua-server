defmodule TamanduaServer.Repo.Migrations.CreateSubmissions do
  use Ecto.Migration

  def change do
    create table(:submissions, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :type, :string, null: false
      add :contributor_wallet, :string, null: false
      add :payload, :map, null: false
      add :status, :string, null: false, default: "submitted"
      add :title, :string, null: false
      add :description, :text

      add :organization_id, references(:organizations, type: :uuid, on_delete: :delete_all), null: false
      add :submitted_by_id, references(:users, type: :uuid, on_delete: :nilify_all)
      add :linked_alert_id, references(:alerts, type: :uuid, on_delete: :nilify_all)

      timestamps(type: :utc_datetime_usec)
    end

    create index(:submissions, [:status])
    create index(:submissions, [:contributor_wallet])
    create index(:submissions, [:linked_alert_id])
    create index(:submissions, [:organization_id])
    create index(:submissions, [:type])
  end
end
