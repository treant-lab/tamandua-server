defmodule TamanduaServer.Hunting.HuntSession do
  @moduledoc """
  Schema for NLHunter hunt sessions.

  Represents a threat hunting session created through the natural language
  hunting interface. Stores the original query, parsed query structure,
  findings, hypotheses, and session status.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @statuses ~w(active completed cancelled)

  schema "hunt_sessions" do
    field :query, :string
    field :parsed_query, :map
    field :findings, {:array, :map}, default: []
    field :hypotheses, {:array, :map}, default: []
    field :status, :string, default: "active"
    field :created_by, :string

    timestamps()
  end

  @required_fields ~w(query)a
  @optional_fields ~w(parsed_query findings hypotheses status created_by)a

  @doc false
  def changeset(hunt_session, attrs) do
    hunt_session
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:status, @statuses)
  end
end
