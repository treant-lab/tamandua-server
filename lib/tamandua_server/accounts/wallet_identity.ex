defmodule TamanduaServer.Accounts.WalletIdentity do
  @moduledoc """
  Verified blockchain wallet linked to a Tamandua user.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @chains ~w(solana)
  @providers ~w(phantom backpack solflare metamask unknown)

  schema "wallet_identities" do
    field :chain, :string, default: "solana"
    field :wallet_address, :string
    field :provider, :string
    field :verified_at, :utc_datetime_usec
    field :last_used_at, :utc_datetime_usec

    belongs_to :user, TamanduaServer.Accounts.User

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(identity, attrs) do
    identity
    |> cast(attrs, [:user_id, :chain, :wallet_address, :provider, :verified_at, :last_used_at])
    |> validate_required([:user_id, :chain, :wallet_address, :verified_at])
    |> validate_inclusion(:chain, @chains)
    |> validate_inclusion(:provider, @providers)
    |> validate_format(:wallet_address, ~r/^[1-9A-HJ-NP-Za-km-z]{32,44}$/)
    |> foreign_key_constraint(:user_id)
    |> unique_constraint([:chain, :wallet_address])
  end
end
