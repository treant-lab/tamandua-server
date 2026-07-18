defmodule TamanduaServer.Repo.Migrations.CreateUpdateTables do
  use Ecto.Migration

  def change do
    # Version manifests
    create table(:update_versions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :version, :string, null: false
      add :platform, :string, null: false
      add :arch, :string, null: false
      add :binary_url, :text, null: false
      add :checksum_sha256, :string, null: false
      add :signature_ed25519, :text, null: false
      add :size_bytes, :bigint, null: false
      add :min_version, :string
      add :release_notes, :text
      add :critical, :boolean, default: false
      add :released_at, :utc_datetime, null: false
      add :deprecated_at, :utc_datetime

      timestamps()
    end

    create unique_index(:update_versions, [:version, :platform, :arch])
    create index(:update_versions, [:platform, :arch, :released_at])
    create index(:update_versions, [:deprecated_at])

    # Delta patches
    create table(:update_delta_patches, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :from_version, :string, null: false
      add :to_version, :string, null: false
      add :platform, :string, null: false
      add :arch, :string, null: false
      add :patch_url, :text, null: false
      add :checksum_sha256, :string, null: false
      add :signature_ed25519, :text, null: false
      add :size_bytes, :bigint, null: false
      add :algorithm, :string, default: "bsdiff"

      timestamps()
    end

    create unique_index(:update_delta_patches, [:from_version, :to_version, :platform, :arch])
    create index(:update_delta_patches, [:platform, :arch])

    # Rollout states
    create table(:update_rollouts, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :rollout_id, :string, null: false
      add :version, :string, null: false
      add :platform, :string, null: false
      add :arch, :string, null: false
      add :strategy, :string, null: false
      add :current_phase, :string, null: false
      add :phase_configs, :map
      add :failure_threshold, :float, default: 0.05
      add :started_at, :utc_datetime, null: false
      add :completed_at, :utc_datetime

      timestamps()
    end

    create unique_index(:update_rollouts, [:rollout_id])
    create index(:update_rollouts, [:platform, :arch, :current_phase])
    create index(:update_rollouts, [:started_at])

    # Update health tracking
    create table(:update_health, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :rollout_id, :string, null: false
      add :agent_id, :string, null: false
      add :status, :string, null: false
      add :metadata, :map
      add :created_at, :utc_datetime, null: false
    end

    create index(:update_health, [:rollout_id, :created_at])
    create index(:update_health, [:agent_id])
    create index(:update_health, [:status])
  end
end
