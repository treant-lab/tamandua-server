defmodule TamanduaServer.UBA.UserBehavior do
  @moduledoc """
  Schema for user behavior events.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "user_behaviors" do
    field :behavior_type, :string
    field :timestamp, :utc_datetime_usec
    field :metadata, :map
    field :value, :float
    field :location, :string
    field :device, :string
    field :source, :string

    belongs_to :user, TamanduaServer.Accounts.User
    belongs_to :agent, TamanduaServer.Agents.Agent
    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(behavior, attrs) do
    behavior
    |> cast(attrs, [
      :user_id,
      :behavior_type,
      :timestamp,
      :metadata,
      :value,
      :location,
      :device,
      :source,
      :agent_id,
      :organization_id
    ])
    |> validate_required([:user_id, :behavior_type, :timestamp])
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:agent_id)
    |> foreign_key_constraint(:organization_id)
  end
end
