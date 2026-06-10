defmodule TamanduaServer.Agents.PolicyDeploymentResult do
  @moduledoc """
  Schema for tracking deployment results per agent.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Agents.{PolicyDeployment, Agent}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @statuses ~w(pending in_progress success failed skipped)

  schema "agent_policy_deployment_results" do
    field :status, :string, default: "pending"
    field :phase_number, :integer
    field :error_message, :string
    field :error_details, :map
    field :started_at, :utc_datetime
    field :completed_at, :utc_datetime
    field :failed_at, :utc_datetime
    field :previous_policy_snapshot, :map

    belongs_to :deployment, PolicyDeployment
    belongs_to :agent, Agent

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(result, attrs) do
    result
    |> cast(attrs, [
      :deployment_id,
      :agent_id,
      :status,
      :phase_number,
      :error_message,
      :error_details,
      :started_at,
      :completed_at,
      :failed_at,
      :previous_policy_snapshot
    ])
    |> validate_required([:deployment_id, :agent_id])
    |> validate_inclusion(:status, @statuses)
    |> foreign_key_constraint(:deployment_id)
    |> foreign_key_constraint(:agent_id)
    |> unique_constraint([:deployment_id, :agent_id])
  end
end
