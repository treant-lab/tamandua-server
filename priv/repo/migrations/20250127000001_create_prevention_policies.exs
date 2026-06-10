defmodule TamanduaServer.Repo.Migrations.CreatePreventionPolicies do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:prevention_policies, primary_key: false) do
      add :id, :binary_id, primary_key: true, default: fragment("gen_random_uuid()")
      add :name, :string, null: false
      add :description, :text
      add :is_default, :boolean, default: false
      add :is_enabled, :boolean, default: true

      add :category_settings, :map, default: %{}
      add :global_mode, :string, default: "detect_and_prevent"
      add :global_aggressiveness, :string, default: "moderate"

      add :assigned_groups, {:array, :string}, default: []
      add :assigned_agents, {:array, :string}, default: []

      add :excluded_paths, {:array, :string}, default: []
      add :excluded_processes, {:array, :string}, default: []
      add :excluded_hashes, {:array, :string}, default: []
      add :excluded_users, {:array, :string}, default: []

      timestamps()
    end

    create_if_not_exists unique_index(:prevention_policies, [:name])
    create_if_not_exists index(:prevention_policies, [:is_default])
    create_if_not_exists index(:prevention_policies, [:is_enabled])
  end
end
