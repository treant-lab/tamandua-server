defmodule TamanduaServer.Repo.Migrations.AddAuthorPubkeyToSigmaRules do
  use Ecto.Migration

  @doc """
  Adds author_pubkey field to sigma_rules for Solana bounty payments.

  The author_pubkey is a Solana base58 address (32-44 characters) that
  identifies the rule author for automatic bounty payments when their
  detection rule generates a validated alert.

  Format: Valid Solana base58 public key (e.g., "TamDevBounty1111111111111111111111111111111")
  """
  def change do
    alter table(:sigma_rules) do
      add :author_pubkey, :string, size: 64
    end

    # Index for efficient lookups by pubkey (for leaderboard, wallet history)
    create index(:sigma_rules, [:author_pubkey])
  end
end
