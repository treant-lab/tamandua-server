defmodule TamanduaServer.Accounts.WalletAuthEvent do
  @moduledoc """
  Audit trail for wallet authentication attempts and wallet account linking.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @event_types ~w(challenge_issued login_succeeded login_failed wallet_linked)

  schema "wallet_auth_events" do
    field :chain, :string, default: "solana"
    field :wallet_address, :string
    field :provider, :string
    field :event_type, :string
    field :ip_address, :string
    field :user_agent, :string
    field :metadata, :map, default: %{}

    belongs_to :user, TamanduaServer.Accounts.User

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(event, attrs) do
    event
    |> cast(attrs, [
      :user_id,
      :chain,
      :wallet_address,
      :provider,
      :event_type,
      :ip_address,
      :user_agent,
      :metadata
    ])
    |> validate_required([:chain, :wallet_address, :event_type])
    |> validate_inclusion(:chain, ["solana"])
    |> validate_inclusion(:event_type, @event_types)
    |> foreign_key_constraint(:user_id)
  end
end
