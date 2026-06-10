defmodule TamanduaServer.Repo.Migrations.AddBlockchainAttestationToAlerts do
  @moduledoc """
  Add blockchain attestation fields to alerts table.

  Part of Tamanduá Sentinel Hackathon MVP:
  - blockchain_tx_id: Solana transaction signature for incident attestation
  - blockchain_attested_at: When the attestation was submitted
  - bounty_tx_id: Transaction signature for detection bounty payment
  - bounty_amount_lamports: Bounty amount in lamports
  - bounty_paid_at: When the bounty was paid
  - rule_author_pubkey: Solana public key of the rule author
  """
  use Ecto.Migration

  def change do
    alter table(:alerts) do
      # Solana blockchain attestation
      add :blockchain_tx_id, :string
      add :blockchain_attested_at, :utc_datetime_usec

      # Detection bounty tracking
      add :bounty_tx_id, :string
      add :bounty_amount_lamports, :bigint
      add :bounty_paid_at, :utc_datetime_usec

      # Rule author for bounty payment
      add :rule_author_pubkey, :string
    end

    # Index for querying attested alerts
    create index(:alerts, [:blockchain_tx_id], where: "blockchain_tx_id IS NOT NULL")

    # Index for bounty analytics
    create index(:alerts, [:bounty_paid_at], where: "bounty_paid_at IS NOT NULL")
  end
end
