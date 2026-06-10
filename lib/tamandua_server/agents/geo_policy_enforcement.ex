defmodule TamanduaServer.Agents.GeoPolicyEnforcement do
  @moduledoc """
  Log of policy enforcement actions taken based on agent location.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Agents.{Agent, GeoPolicy, AgentLocation}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]
  schema "geo_policy_enforcements" do
    field :enforcement_type, :string
    field :enforcement_details, :map, default: %{}
    field :success, :boolean, default: true
    field :error_message, :string
    field :enforced_at, :utc_datetime_usec

    belongs_to :organization, Organization
    belongs_to :agent, Agent
    belongs_to :policy, GeoPolicy
    belongs_to :location, AgentLocation

    timestamps()
  end

  @doc false
  def changeset(enforcement, attrs) do
    enforcement
    |> cast(attrs, [
      :organization_id,
      :agent_id,
      :policy_id,
      :location_id,
      :enforcement_type,
      :enforcement_details,
      :success,
      :error_message,
      :enforced_at
    ])
    |> validate_required([:organization_id, :agent_id, :enforcement_type, :enforced_at])
    |> validate_inclusion(:enforcement_type, ~w(
      mfa_required
      feature_disabled
      file_restricted
      isolated
      alert_sent
      monitoring_enhanced
    ))
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:agent_id)
  end
end
