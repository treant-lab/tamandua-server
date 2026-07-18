defmodule TamanduaServer.FleetQueries.FleetQueryTarget do
  @moduledoc """
  Per-agent target state for a fleet query run.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Agents.{Agent, AgentCommand}
  alias TamanduaServer.FleetQueries.FleetQueryRun

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @statuses ~w(queued sent acknowledged completed failed skipped)

  schema "fleet_query_targets" do
    field :hostname, :string
    field :os_type, :string
    field :status, :string, default: "queued"
    field :skip_reason, :string
    field :result_summary, :map
    field :error, :string
    field :completed_at, :utc_datetime

    belongs_to :fleet_query_run, FleetQueryRun
    belongs_to :agent, Agent
    belongs_to :agent_command, AgentCommand

    timestamps(type: :utc_datetime)
  end

  def statuses, do: @statuses

  def changeset(target, attrs) do
    target
    |> cast(attrs, [
      :fleet_query_run_id,
      :agent_id,
      :hostname,
      :os_type,
      :status,
      :agent_command_id,
      :skip_reason,
      :result_summary,
      :error,
      :completed_at
    ])
    |> validate_required([:fleet_query_run_id, :status])
    |> validate_inclusion(:status, @statuses)
    |> foreign_key_constraint(:fleet_query_run_id)
    |> foreign_key_constraint(:agent_id)
    |> foreign_key_constraint(:agent_command_id)
    |> unique_constraint([:fleet_query_run_id, :agent_id])
  end
end
