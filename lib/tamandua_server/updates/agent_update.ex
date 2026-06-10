defmodule TamanduaServer.Updates.AgentUpdate do
  @moduledoc """
  Schema for tracking per-agent update status.

  Each record represents one agent's journey through an update: from the
  moment it is assigned (pending) through download, installation, and
  eventual completion or failure. The `previous_version` / `new_version`
  pair makes rollback auditing straightforward.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Updates.Rollout
  alias TamanduaServer.Updates.UpdatePackage

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "agent_updates" do
    field :status, :string, default: "pending"
    field :started_at, :utc_datetime_usec
    field :completed_at, :utc_datetime_usec
    field :error_message, :string
    field :previous_version, :string
    field :new_version, :string

    belongs_to :agent, Agent
    belongs_to :rollout, Rollout
    belongs_to :update_package, UpdatePackage

    timestamps()
  end

  @required_fields ~w(agent_id update_package_id)a
  @optional_fields ~w(rollout_id status started_at completed_at error_message previous_version new_version)a

  @valid_statuses ~w(pending downloading installing completed failed rolled_back)

  @doc false
  def changeset(agent_update, attrs) do
    agent_update
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:status, @valid_statuses,
      message: "must be one of: #{Enum.join(@valid_statuses, ", ")}"
    )
    |> foreign_key_constraint(:agent_id)
    |> foreign_key_constraint(:rollout_id)
    |> foreign_key_constraint(:update_package_id)
    |> unique_constraint([:agent_id, :rollout_id],
      name: :agent_updates_agent_rollout_idx,
      message: "agent already has an update record for this rollout"
    )
  end

  @doc """
  Changeset for agent-reported status updates.
  """
  def report_changeset(agent_update, attrs) do
    agent_update
    |> cast(attrs, [:status, :started_at, :completed_at, :error_message])
    |> validate_inclusion(:status, @valid_statuses)
  end
end
