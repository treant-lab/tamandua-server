defmodule TamanduaServer.Repo.Migrations.CreateUpdateManagement do
  @moduledoc """
  Creates the update management tables: update_packages, rollouts, and agent_updates.

  These tables support the full agent self-update lifecycle including versioned
  releases, canary/staged rollout strategies, and per-agent update tracking.
  """

  use Ecto.Migration

  def change do
    # ------------------------------------------------------------------
    # update_packages: versioned release binaries per platform
    # ------------------------------------------------------------------
    create_if_not_exists table(:update_packages, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :version, :string, null: false
      add :platform, :string, null: false
      add :architecture, :string, null: false
      add :download_url, :string
      add :sha256_hash, :string, null: false
      add :signature, :text
      add :release_notes, :text
      add :size_bytes, :bigint
      add :min_agent_version, :string
      add :is_critical, :boolean, default: false, null: false
      add :released_at, :utc_datetime_usec

      add :organization_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all),
          null: false

      timestamps()
    end

    create_if_not_exists unique_index(:update_packages, [:version, :platform, :architecture],
             name: :update_packages_version_platform_arch_idx
           )

    create_if_not_exists index(:update_packages, [:organization_id])
    create_if_not_exists index(:update_packages, [:platform])
    create_if_not_exists index(:update_packages, [:released_at])
    create_if_not_exists index(:update_packages, [:is_critical])

    # ------------------------------------------------------------------
    # rollouts: controls how an update is distributed to agents
    # ------------------------------------------------------------------
    create_if_not_exists table(:rollouts, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :strategy, :string, null: false, default: "staged"
      add :canary_percentage, :integer, default: 10
      add :stages, {:array, :map}, default: []
      add :current_stage, :integer, default: 0
      add :status, :string, null: false, default: "pending"
      add :started_at, :utc_datetime_usec
      add :completed_at, :utc_datetime_usec
      add :rollback_reason, :text

      add :update_package_id,
          references(:update_packages, type: :binary_id, on_delete: :delete_all),
          null: false

      add :organization_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all),
          null: false

      timestamps()
    end

    create_if_not_exists index(:rollouts, [:update_package_id])
    create_if_not_exists index(:rollouts, [:organization_id])
    create_if_not_exists index(:rollouts, [:status])
    create_if_not_exists index(:rollouts, [:strategy])

    # ------------------------------------------------------------------
    # agent_updates: per-agent update tracking
    # ------------------------------------------------------------------
    create_if_not_exists table(:agent_updates, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :status, :string, null: false, default: "pending"
      add :started_at, :utc_datetime_usec
      add :completed_at, :utc_datetime_usec
      add :error_message, :text
      add :previous_version, :string
      add :new_version, :string

      add :agent_id,
          references(:agents, type: :binary_id, on_delete: :delete_all),
          null: false

      add :rollout_id,
          references(:rollouts, type: :binary_id, on_delete: :delete_all)

      add :update_package_id,
          references(:update_packages, type: :binary_id, on_delete: :delete_all),
          null: false

      timestamps()
    end

    create_if_not_exists unique_index(:agent_updates, [:agent_id, :rollout_id],
             name: :agent_updates_agent_rollout_idx
           )

    create_if_not_exists index(:agent_updates, [:agent_id])
    create_if_not_exists index(:agent_updates, [:rollout_id])
    create_if_not_exists index(:agent_updates, [:update_package_id])
    create_if_not_exists index(:agent_updates, [:status])
  end
end
