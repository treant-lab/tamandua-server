defmodule TamanduaServer.Repo.Migrations.CreateAPIUsageMetrics do
  use Ecto.Migration

  def change do
    create table(:api_usage_metrics, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :version, :string, null: false
      add :method, :string, null: false
      add :path, :text, null: false
      add :endpoint, :string, null: false
      add :status_code, :integer, null: false
      add :latency_ms, :integer
      add :deprecated, :boolean, default: false, null: false
      add :user_agent, :text
      add :client_ip, :string
      add :timestamp, :utc_datetime_usec, null: false

      add :organization_id, references(:organizations, on_delete: :delete_all, type: :binary_id)
      add :user_id, references(:users, on_delete: :nilify_all, type: :binary_id)

      timestamps()
    end

    create index(:api_usage_metrics, [:version])
    create index(:api_usage_metrics, [:endpoint])
    create index(:api_usage_metrics, [:deprecated])
    create index(:api_usage_metrics, [:timestamp])
    create index(:api_usage_metrics, [:organization_id])
    create index(:api_usage_metrics, [:user_id])
    create index(:api_usage_metrics, [:version, :endpoint])
    create index(:api_usage_metrics, [:version, :timestamp])

    # Composite index for common analytics queries
    create index(:api_usage_metrics, [:version, :deprecated, :timestamp])
  end
end
