defmodule TamanduaServer.Repo.Migrations.CreateWebhookDeliveries do
  use Ecto.Migration

  def change do
    create table(:webhook_deliveries, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :event_type, :string, null: false
      add :event_id, :binary_id

      # Request details
      add :request_url, :string, null: false
      add :request_method, :string, default: "POST", null: false
      add :request_headers, :map
      add :request_body, :map

      # Response details
      add :response_status, :integer
      add :response_headers, :map
      add :response_body, :text
      add :response_time_ms, :integer

      # Delivery status
      add :status, :string, null: false
      add :error_message, :text
      add :retry_count, :integer, default: 0, null: false
      add :next_retry_at, :utc_datetime

      add :webhook_id, references(:webhooks, type: :binary_id, on_delete: :delete_all),
        null: false

      timestamps(updated_at: false)
    end

    create index(:webhook_deliveries, [:webhook_id])
    create index(:webhook_deliveries, [:event_type])
    create index(:webhook_deliveries, [:status])
    create index(:webhook_deliveries, [:inserted_at])
    create index(:webhook_deliveries, [:next_retry_at])
  end
end
