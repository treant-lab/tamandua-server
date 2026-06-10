defmodule TamanduaServer.Repo.Migrations.CreateIncidentCandidates do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:incident_candidates, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:fingerprint, :string, null: false)
      add(:title, :string, null: false)
      add(:status, :string, null: false, default: "candidate")
      add(:severity, :string, null: false, default: "info")
      add(:score, :integer, null: false, default: 0)
      add(:scoring_version, :string, null: false)

      add(:event_ids, {:array, :binary_id}, null: false, default: [])
      add(:relation_types, {:array, :string}, null: false, default: [])
      add(:supporting_entities, {:array, :string}, null: false, default: [])
      add(:metadata, :map, null: false, default: %{})

      add(:feedback_verdict, :string)
      add(:feedback_notes, :text)
      add(:feedback_by_id, references(:users, type: :binary_id, on_delete: :nilify_all))
      add(:feedback_at, :utc_datetime_usec)

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists(index(:incident_candidates, [:organization_id, :status, :inserted_at]))
    create_if_not_exists(index(:incident_candidates, [:organization_id, :score]))
    create_if_not_exists(index(:incident_candidates, [:feedback_verdict]))

    create_if_not_exists(
      unique_index(:incident_candidates, [:organization_id, :fingerprint],
        name: :incident_candidates_unique_org_fingerprint
      )
    )
  end
end
