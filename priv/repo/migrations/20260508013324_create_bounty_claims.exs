defmodule TamanduaServer.Repo.Migrations.CreateBountyClaims do
  use Ecto.Migration

  def change do
    create table(:bounty_claims, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :submission_id, references(:submissions, type: :uuid, on_delete: :delete_all), null: false
      add :alert_id, references(:alerts, type: :uuid, on_delete: :nilify_all)
      add :amount_lamports, :bigint, null: false
      add :status, :string, null: false, default: "pending"
      add :tx_id, :string
      add :failure_reason, :text
      add :paid_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:bounty_claims, [:submission_id])
    create index(:bounty_claims, [:alert_id])
    create index(:bounty_claims, [:status])
    create index(:bounty_claims, [:tx_id])
  end
end
