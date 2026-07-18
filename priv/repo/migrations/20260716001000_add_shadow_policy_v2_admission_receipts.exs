defmodule TamanduaServer.Repo.Migrations.AddShadowPolicyV2AdmissionReceipts do
  use Ecto.Migration

  def up do
    alter table(:ai_investigation_runs) do
      add(:admission_disposition, :string, null: false, default: "enqueued")
      add(:admission_reason, :string, null: false, default: "legacy_or_explicit_request")
    end

    create(
      constraint(:ai_investigation_runs, :ai_investigation_runs_admission_disposition_check,
        check:
          "admission_disposition IN ('enqueued', 'ineligible', 'capacity_limited', 'disabled', 'degraded')"
      )
    )

    create(
      index(
        :ai_investigation_runs,
        [:organization_id, :source, :admission_disposition, :inserted_at],
        name: :ai_investigation_runs_org_admission_window_idx
      )
    )
  end

  def down do
    drop_if_exists(
      index(:ai_investigation_runs, [], name: :ai_investigation_runs_org_admission_window_idx)
    )

    drop_if_exists(
      constraint(:ai_investigation_runs, :ai_investigation_runs_admission_disposition_check)
    )

    alter table(:ai_investigation_runs) do
      remove(:admission_reason)
      remove(:admission_disposition)
    end
  end
end
