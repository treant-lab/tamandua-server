defmodule TamanduaServer.Repo.Migrations.CreateRemediationWorkflows do
  use Ecto.Migration

  def change do
    create table(:remediation_workflows, primary_key: false) do
      add :id, :binary_id, primary_key: true

      # References
      add :alert_id, references(:alerts, type: :binary_id, on_delete: :nilify_all)
      add :policy_id, references(:remediation_policies, type: :binary_id, on_delete: :nilify_all)
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      # State tracking
      add :state, :string, null: false, default: "pending"
      add :previous_state, :string
      add :execution_mode, :string, null: false  # auto, queued, pending_approval

      # Action details (copied from policy at creation time)
      add :action_type, :string, null: false
      add :action_config, :map, default: %{}

      # Execution tracking
      add :started_at, :utc_datetime_usec
      add :completed_at, :utc_datetime_usec
      add :failed_at, :utc_datetime_usec
      add :cancelled_at, :utc_datetime_usec

      # Results and errors
      add :result, :map, default: %{}
      add :error_message, :text
      add :retry_count, :integer, default: 0

      # Approval tracking (for pending_approval mode)
      add :approved_at, :utc_datetime_usec
      add :approved_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :approval_notes, :text

      # Oban job reference
      add :oban_job_id, :bigint

      timestamps(type: :utc_datetime_usec)
    end

    create index(:remediation_workflows, [:alert_id])
    create index(:remediation_workflows, [:policy_id])
    create index(:remediation_workflows, [:organization_id])
    create index(:remediation_workflows, [:state])
    create index(:remediation_workflows, [:execution_mode])
    create index(:remediation_workflows, [:inserted_at])

    # Composite index for common queries
    create index(:remediation_workflows, [:organization_id, :state, :inserted_at])
  end
end
