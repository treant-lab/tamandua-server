defmodule TamanduaServer.Repo.Migrations.CreateBreadcrumbDeploymentsAndAccessLog do
  use Ecto.Migration

  def change do
    # Breadcrumb deployments table (tracks deployed decoys)
    create table(:breadcrumb_deployments, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, :string, null: false
      add :type, :string, null: false
      add :path, :string, null: false
      add :content_hash, :string, null: false
      add :canary_token, :string, null: false
      add :deployed_at, :utc_datetime, null: false
      add :last_rotated_at, :utc_datetime
      add :status, :string, default: "active", null: false
      add :access_count, :integer, default: 0, null: false
      add :metadata, :map, default: %{}

      timestamps()
    end

    create index(:breadcrumb_deployments, [:agent_id])
    create index(:breadcrumb_deployments, [:canary_token])
    create unique_index(:breadcrumb_deployments, [:agent_id, :path])
    create index(:breadcrumb_deployments, [:status])
    create index(:breadcrumb_deployments, [:type])

    # Breadcrumb access log table (tracks access events)
    create table(:breadcrumb_access_log, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :breadcrumb_id, references(:breadcrumb_deployments, type: :binary_id, on_delete: :delete_all)
      add :agent_id, :string, null: false
      add :accessed_at, :utc_datetime, null: false
      add :process_name, :string
      add :pid, :integer
      add :user, :string
      add :access_type, :string, null: false
      add :alert_id, references(:alerts, type: :binary_id, on_delete: :nilify_all)
      add :tamper_detected, :boolean, default: false
      add :original_hash, :string
      add :new_hash, :string
      add :additional_data, :map, default: %{}

      timestamps()
    end

    create index(:breadcrumb_access_log, [:breadcrumb_id])
    create index(:breadcrumb_access_log, [:agent_id])
    create index(:breadcrumb_access_log, [:accessed_at])
    create index(:breadcrumb_access_log, [:alert_id])
    create index(:breadcrumb_access_log, [:tamper_detected])
  end
end
