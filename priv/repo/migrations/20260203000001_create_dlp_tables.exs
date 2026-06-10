defmodule TamanduaServer.Repo.Migrations.CreateDlpTables do
  @moduledoc """
  Creates the DLP (Data Loss Prevention) tables: policies and incidents.

  These tables support content-aware data loss prevention including policy
  management, incident tracking, severity escalation, and integration with
  the existing alert system.
  """

  use Ecto.Migration

  def change do
    # ------------------------------------------------------------------
    # dlp_policies: DLP policy definitions
    # ------------------------------------------------------------------
    create_if_not_exists table(:dlp_policies, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :classifiers, {:array, :string}, null: false, default: []
      add :destinations, {:array, :string}, null: false, default: []
      add :action, :string, null: false, default: "log"
      add :severity, :string, null: false, default: "medium"
      add :enabled, :boolean, null: false, default: true

      add :organization_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all),
          null: true

      timestamps()
    end

    create_if_not_exists index(:dlp_policies, [:organization_id])
    create_if_not_exists index(:dlp_policies, [:enabled])
    create_if_not_exists index(:dlp_policies, [:action])

    # ------------------------------------------------------------------
    # dlp_incidents: DLP policy violation incidents
    # ------------------------------------------------------------------
    create_if_not_exists table(:dlp_incidents, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, :string, null: false
      add :user_name, :string
      add :source_process, :string
      add :source_path, :text
      add :destination, :string
      add :classifier_matches, {:array, :string}, null: false, default: []
      add :policy_id, references(:dlp_policies, type: :binary_id, on_delete: :nilify_all)
      add :policy_name, :string
      add :action_taken, :string, null: false
      add :severity, :string, null: false, default: "medium"
      add :content_hash, :string
      add :content_size, :bigint, default: 0
      add :max_confidence, :float, default: 0.0
      add :status, :string, null: false, default: "open"
      add :escalation_level, :integer, default: 0
      add :analyst_notes, :text

      add :organization_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all),
          null: true

      timestamps()
    end

    create_if_not_exists index(:dlp_incidents, [:agent_id])
    create_if_not_exists index(:dlp_incidents, [:user_name])
    create_if_not_exists index(:dlp_incidents, [:policy_id])
    create_if_not_exists index(:dlp_incidents, [:status])
    create_if_not_exists index(:dlp_incidents, [:severity])
    create_if_not_exists index(:dlp_incidents, [:organization_id])
    create_if_not_exists index(:dlp_incidents, [:destination])
    create_if_not_exists index(:dlp_incidents, [:inserted_at])

    # Composite index for common query patterns
    create_if_not_exists index(:dlp_incidents, [:organization_id, :status, :severity],
             name: :dlp_incidents_org_status_severity_idx
           )

    create_if_not_exists index(:dlp_incidents, [:organization_id, :user_name, :inserted_at],
             name: :dlp_incidents_org_user_time_idx
           )
  end
end
