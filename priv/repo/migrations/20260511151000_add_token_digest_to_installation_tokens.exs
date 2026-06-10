defmodule TamanduaServer.Repo.Migrations.AddTokenDigestToInstallationTokens do
  use Ecto.Migration

  def change do
    alter table(:installation_tokens) do
      add(:token_digest, :string)
    end

    create(
      unique_index(:installation_tokens, [:token_digest],
        where: "token_digest IS NOT NULL",
        name: :installation_tokens_token_digest_index
      )
    )
  end
end
