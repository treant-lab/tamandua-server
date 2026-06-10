defmodule TamanduaServer.Repo.Migrations.CreateWebhooks do
  use Ecto.Migration

  def change do
    create table(:webhooks, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :url, :string, null: false
      add :enabled, :boolean, default: true, null: false
      add :secret, :string
      add :description, :text

      # Event filtering
      add :events, {:array, :string}, default: [], null: false

      # Authentication
      add :auth_type, :string, default: "none", null: false
      add :auth_username, :string
      add :auth_password, :string
      add :auth_token, :string
      add :custom_headers, :map, default: %{}

      # Retry policy
      add :max_retries, :integer, default: 3, null: false
      add :backoff_strategy, :string, default: "exponential", null: false
      add :timeout_seconds, :integer, default: 10, null: false

      # Statistics
      add :total_deliveries, :integer, default: 0, null: false
      add :successful_deliveries, :integer, default: 0, null: false
      add :failed_deliveries, :integer, default: 0, null: false
      add :last_delivery_at, :utc_datetime
      add :last_delivery_status, :string

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false

      timestamps()
    end

    create index(:webhooks, [:organization_id])
    create index(:webhooks, [:enabled])
    create index(:webhooks, [:events], using: :gin)
  end
end
