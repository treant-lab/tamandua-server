defmodule TamanduaServer.Repo.Migrations.CreateK8sAdmissionPolicies do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:k8s_admission_policies, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :action, :string, null: false
      add :target, :string, null: false, default: "pod"
      add :conditions, :map, default: %{}
      add :mutation, :map, default: %{}
      add :enabled, :boolean, default: true, null: false
      add :priority, :integer, default: 100, null: false
      add :namespaces, {:array, :string}, default: []
      add :namespace_selector, :map, default: %{}
      add :rules, {:array, :map}, default: []
      add :labels, :map, default: %{}
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :nilify_all)

      timestamps()
    end

    create_if_not_exists unique_index(:k8s_admission_policies, [:name])
    create_if_not_exists index(:k8s_admission_policies, [:enabled])
    create_if_not_exists index(:k8s_admission_policies, [:action])
    create_if_not_exists index(:k8s_admission_policies, [:priority])
    create_if_not_exists index(:k8s_admission_policies, [:organization_id])

    # Admission event log for audit trail
    create_if_not_exists table(:k8s_admission_logs, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :uid, :string, null: false
      add :namespace, :string
      add :name, :string
      add :resource_kind, :string
      add :operation, :string
      add :decision, :string, null: false
      add :reason, :string
      add :warnings, {:array, :string}, default: []
      add :policy_names, {:array, :string}, default: []
      add :patches_applied, :integer, default: 0
      add :requesting_user, :string
      add :requesting_groups, {:array, :string}, default: []
      add :dry_run, :boolean, default: false
      add :duration_us, :integer
      add :metadata, :map, default: %{}

      timestamps(updated_at: false)
    end

    create_if_not_exists index(:k8s_admission_logs, [:namespace])
    create_if_not_exists index(:k8s_admission_logs, [:decision])
    create_if_not_exists index(:k8s_admission_logs, [:inserted_at])
    create_if_not_exists index(:k8s_admission_logs, [:resource_kind])
  end
end
