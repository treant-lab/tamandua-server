defmodule TamanduaServer.Response.Action do
  @moduledoc """
  Schema for tracking response actions executed on agents.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @status_values ~w(pending executing success failed timeout cancelled rolled_back unauthorized)

  schema "response_actions" do
    field :action_type, :string
    field :parameters, :map, default: %{}
    field :status, :string, default: "pending"
    field :result, :map
    field :error_message, :string
    field :executed_at, :utc_datetime_usec

    belongs_to :agent, TamanduaServer.Agents.Agent
    belongs_to :alert, TamanduaServer.Alerts.Alert
    belongs_to :executed_by, TamanduaServer.Accounts.User
    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(agent_id action_type)a
  @optional_fields ~w(parameters status result error_message executed_at alert_id executed_by_id organization_id)a

  def changeset(action, attrs) do
    action
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:status, @status_values)
  end

  def result_changeset(action, attrs) do
    action
    |> cast(attrs, [:status, :result, :error_message, :executed_at])
    |> validate_inclusion(:status, @status_values)
  end
end
