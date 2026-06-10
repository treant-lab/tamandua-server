defmodule TamanduaServer.Updates.Rollout do
  @moduledoc """
  Schema for update rollouts.

  A rollout controls how an update package is distributed to agents. It
  supports multiple strategies:

  - **immediate** -- Push to all agents at once.
  - **canary** -- Push to a random N% of agents first; if failure rate stays
    below threshold, automatically promote to 100%.
  - **staged** -- Roll out through explicitly defined stages (e.g. 10% -> 50% -> 100%)
    with configurable success criteria at each stage.
  - **manual** -- Admin manually triggers each promotion step.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Updates.UpdatePackage
  alias TamanduaServer.Updates.AgentUpdate

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "rollouts" do
    field :strategy, :string, default: "staged"
    field :canary_percentage, :integer, default: 10
    field :stages, {:array, :map}, default: []
    field :current_stage, :integer, default: 0
    field :status, :string, default: "pending"
    field :started_at, :utc_datetime_usec
    field :completed_at, :utc_datetime_usec
    field :rollback_reason, :string

    belongs_to :update_package, UpdatePackage
    belongs_to :organization, Organization
    has_many :agent_updates, AgentUpdate

    timestamps()
  end

  @required_fields ~w(update_package_id organization_id)a
  @optional_fields ~w(strategy canary_percentage stages current_stage status started_at completed_at rollback_reason)a

  @valid_strategies ~w(immediate canary staged manual)
  @valid_statuses ~w(pending rolling_out paused completed failed rolled_back)

  @doc false
  def changeset(rollout, attrs) do
    rollout
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:strategy, @valid_strategies,
      message: "must be one of: #{Enum.join(@valid_strategies, ", ")}"
    )
    |> validate_inclusion(:status, @valid_statuses,
      message: "must be one of: #{Enum.join(@valid_statuses, ", ")}"
    )
    |> validate_number(:canary_percentage,
      greater_than_or_equal_to: 1,
      less_than_or_equal_to: 100,
      message: "must be between 1 and 100"
    )
    |> validate_number(:current_stage, greater_than_or_equal_to: 0)
    |> validate_stages()
    |> foreign_key_constraint(:update_package_id)
    |> foreign_key_constraint(:organization_id)
  end

  @doc """
  Changeset for status transitions only. Used by rollout lifecycle operations.
  """
  def status_changeset(rollout, attrs) do
    rollout
    |> cast(attrs, [:status, :current_stage, :started_at, :completed_at, :rollback_reason])
    |> validate_inclusion(:status, @valid_statuses)
  end

  defp validate_stages(changeset) do
    case get_change(changeset, :stages) do
      nil ->
        changeset

      stages when is_list(stages) ->
        if Enum.all?(stages, &valid_stage?/1) do
          changeset
        else
          add_error(changeset, :stages,
            "each stage must have 'percentage' (1-100) and optionally 'min_success_rate' (0-100)"
          )
        end

      _ ->
        add_error(changeset, :stages, "must be a list of stage maps")
    end
  end

  defp valid_stage?(%{"percentage" => p}) when is_integer(p) and p >= 1 and p <= 100, do: true
  defp valid_stage?(%{percentage: p}) when is_integer(p) and p >= 1 and p <= 100, do: true
  defp valid_stage?(_), do: false
end
