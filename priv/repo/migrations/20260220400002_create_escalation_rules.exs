defmodule TamanduaServer.Repo.Migrations.CreateEscalationRules do
  use Ecto.Migration

  def change do
    create table(:escalation_rules, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :enabled, :boolean, default: true, null: false

      # Matching conditions
      add :severity_filter, {:array, :string}, default: []
      add :mitre_techniques, {:array, :string}, default: []
      add :mitre_tactics, {:array, :string}, default: []
      add :agent_ids, {:array, :binary_id}, default: []

      # Escalation configuration
      add :escalation_delay_minutes, :integer, null: false, default: 30
      add :escalate_to, {:array, :binary_id}, default: []
      add :escalation_channels, {:array, :string}, default: ["email"]

      # Multi-tier escalation (JSONB array of tier configs)
      add :tiers, {:array, :map}, default: []

      # Business rules
      add :business_hours_only, :boolean, default: false, null: false
      add :business_hours_start, :time
      add :business_hours_end, :time
      add :business_days, {:array, :integer}, default: [1, 2, 3, 4, 5]

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :created_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      timestamps(type: :utc_datetime_usec)
    end

    create index(:escalation_rules, [:enabled])
    create index(:escalation_rules, [:organization_id])
    create index(:escalation_rules, [:escalation_delay_minutes])
  end
end
