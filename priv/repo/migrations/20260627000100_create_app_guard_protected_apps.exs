defmodule TamanduaServer.Repo.Migrations.CreateAppGuardProtectedApps do
  use Ecto.Migration

  def change do
    create table(:app_guard_protected_apps, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :app_id, :string, null: false
      add :display_name, :string, null: false
      add :platform, :string, null: false
      add :package_or_bundle_id, :string, null: false
      add :status, :string, null: false, default: "draft"

      add :ingestion, :map, null: false, default: %{}
      add :policy, :map, null: false, default: %{}
      add :manifest_created_at, :utc_datetime_usec, null: false

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:app_guard_protected_apps, [:organization_id, :app_id])
    create index(:app_guard_protected_apps, [:organization_id])
    create index(:app_guard_protected_apps, [:platform])
    create index(:app_guard_protected_apps, [:status])
    create index(:app_guard_protected_apps, [:package_or_bundle_id])

    create table(:app_guard_build_manifests, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :protected_app_id,
          references(:app_guard_protected_apps, type: :binary_id, on_delete: :delete_all),
          null: false

      add :build_id, :string, null: false
      add :app_id, :string, null: false
      add :platform, :string, null: false
      add :version, :map, null: false, default: %{}
      add :artifact, :map, null: false, default: %{}
      add :signing, :map, null: false, default: %{}
      add :sdk, :map, null: false, default: %{}
      add :policy_id, :string, null: false
      add :manifest_created_at, :utc_datetime_usec, null: false

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:app_guard_build_manifests, [:organization_id, :build_id])
    create index(:app_guard_build_manifests, [:organization_id])
    create index(:app_guard_build_manifests, [:protected_app_id])
    create index(:app_guard_build_manifests, [:app_id])
    create index(:app_guard_build_manifests, [:platform])
  end
end
