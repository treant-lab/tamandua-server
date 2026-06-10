defmodule TamanduaServer.Hunting.QueryParameterValue do
  @moduledoc """
  Schema for storing parameter values for scheduled queries.
  """
  use Ecto.Schema
  import Ecto.Changeset

  schema "query_parameter_values" do
    belongs_to :query_schedule, TamanduaServer.Hunting.QuerySchedule

    field :parameter_name, :string
    field :parameter_value, :string

    timestamps()
  end

  @doc false
  def changeset(param_value, attrs) do
    param_value
    |> cast(attrs, [:query_schedule_id, :parameter_name, :parameter_value])
    |> validate_required([:query_schedule_id, :parameter_name, :parameter_value])
  end
end
