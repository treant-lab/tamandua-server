defmodule TamanduaServer.Repo.Migrations.CreateAppGuardResearch do
  use Ecto.Migration

  def change do
    create table(:app_guard_research_programs, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:program_id, :string, null: false)
      add(:name, :string, null: false)
      add(:description, :text)
      add(:status, :string, null: false)
      add(:visibility, :string, null: false)
      add(:program_type, :string, null: false, default: "vulnerability_disclosure")
      add(:app, :map, null: false, default: %{})
      add(:scope, :map, null: false, default: %{})
      add(:rules, :text, null: false)
      add(:reward, :map, null: false, default: %{})
      add(:invited_researchers, {:array, :string}, null: false, default: [])
      add(:manifest_created_at, :utc_datetime_usec, null: false)

      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:app_guard_research_programs, [:organization_id, :program_id]))
    create(index(:app_guard_research_programs, [:organization_id]))
    create(index(:app_guard_research_programs, [:status]))
    create(index(:app_guard_research_programs, [:visibility]))

    create table(:app_guard_research_submissions, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(
        :research_program_id,
        references(:app_guard_research_programs, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:submission_id, :string, null: false)
      add(:program_id, :string, null: false)
      add(:researcher_id, :string, null: false)
      add(:title, :string, null: false)
      add(:description, :text)
      add(:severity, :string, null: false)
      add(:status, :string, null: false, default: "submitted")
      add(:cvss, :map, null: false, default: %{})
      add(:technical_details, :map, null: false, default: %{})
      add(:evidence_links, :map, null: false, default: %{})
      add(:attachments, {:array, :map}, null: false, default: [])
      add(:validation, :map, null: false, default: %{})
      add(:reward, :map, null: false, default: %{})
      add(:submitted_at, :utc_datetime_usec, null: false)

      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:app_guard_research_submissions, [:organization_id, :submission_id]))
    create(index(:app_guard_research_submissions, [:organization_id]))
    create(index(:app_guard_research_submissions, [:research_program_id]))
    create(index(:app_guard_research_submissions, [:program_id]))
    create(index(:app_guard_research_submissions, [:status]))
    create(index(:app_guard_research_submissions, [:severity]))
  end
end
