defmodule TamanduaServer.Repo.Migrations.AddSigmaRuleTemplates do
  use Ecto.Migration

  def change do
    # Add fields to sigma_rules table
    alter table(:sigma_rules) do
      add :is_system_template, :boolean, default: false
      add :copied_from_template_id, references(:sigma_rules, type: :binary_id, on_delete: :nilify_all)
    end

    # Make organization_id nullable for system templates
    # System templates have is_system_template=true and organization_id=nil

    create index(:sigma_rules, [:is_system_template])
    create index(:sigma_rules, [:copied_from_template_id])
  end
end
