defmodule TamanduaServer.DarkWeb.Credential do
  @moduledoc """
  Schema for compromised credentials found on dark web.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "dark_web_credentials" do
    field :email, :string
    field :username, :string
    field :password, :string
    field :password_hash, :string
    field :domain, :string
    field :severity, :string
    field :status, :string
    field :matched_at, :utc_datetime
    field :first_seen, :utc_datetime
    field :last_seen, :utc_datetime
    field :source, :string
    field :response_taken, :string
    field :response_at, :utc_datetime
    field :notes, :string
    field :metadata, :map

    belongs_to :breach, TamanduaServer.DarkWeb.Breach
    belongs_to :user, TamanduaServer.Accounts.User

    has_many :workflows, TamanduaServer.DarkWeb.ResponseWorkflow

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(email severity status source)a
  @optional_fields ~w(breach_id user_id username password password_hash domain
                     matched_at first_seen last_seen response_taken response_at notes metadata)a

  def changeset(credential, attrs) do
    credential
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:severity, ["critical", "high", "medium", "low"])
    |> validate_inclusion(:status, ["new", "investigating", "resolved", "false_positive"])
    |> validate_format(:email, ~r/@/)
  end
end
