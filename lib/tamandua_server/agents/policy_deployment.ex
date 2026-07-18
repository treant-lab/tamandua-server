defmodule TamanduaServer.Agents.PolicyDeployment do
  @moduledoc """
  Schema for policy deployments with phased rollout support.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.Agents.{Policy, PolicyDeploymentResult}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @strategies ~w(immediate scheduled phased)
  @statuses ~w(pending in_progress completed failed rolled_back cancelled)

  schema "agent_policy_deployments" do
    field :strategy, :string, default: "immediate"
    field :status, :string, default: "pending"
    field :scheduled_at, :utc_datetime
    field :rollout_phases, {:array, :map}, default: []
    field :current_phase, :integer, default: 0
    field :current_phase_percentage, :integer, default: 0

    field :auto_rollback_enabled, :boolean, default: true
    field :rollback_threshold_percent, :integer, default: 10
    field :rollback_reason, :string

    field :total_agents, :integer, default: 0
    field :successful_agents, :integer, default: 0
    field :failed_agents, :integer, default: 0
    field :pending_agents, :integer, default: 0

    field :started_at, :utc_datetime
    field :completed_at, :utc_datetime
    field :failed_at, :utc_datetime
    field :rolled_back_at, :utc_datetime

    field :error_summary, :map, default: %{}
    field :deployment_log, {:array, :map}, default: []

    belongs_to :policy, Policy
    belongs_to :organization, Organization
    belongs_to :deployed_by, User, foreign_key: :deployed_by_id

    # The results table column is `deployment_id` (see the
    # agent_policy_deployment_results migration), not Ecto's default
    # `policy_deployment_id`.
    has_many :deployment_results, PolicyDeploymentResult, foreign_key: :deployment_id

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(deployment, attrs) do
    deployment
    |> cast(attrs, [
      :policy_id,
      :strategy,
      :status,
      :scheduled_at,
      :rollout_phases,
      :current_phase,
      :current_phase_percentage,
      :auto_rollback_enabled,
      :rollback_threshold_percent,
      :rollback_reason,
      :total_agents,
      :successful_agents,
      :failed_agents,
      :pending_agents,
      :started_at,
      :completed_at,
      :failed_at,
      :rolled_back_at,
      :error_summary,
      :deployment_log,
      :organization_id,
      :deployed_by_id
    ])
    |> validate_required([:policy_id, :organization_id, :strategy])
    |> validate_inclusion(:strategy, @strategies)
    |> validate_inclusion(:status, @statuses)
    |> validate_number(:rollback_threshold_percent, greater_than_or_equal_to: 0, less_than_or_equal_to: 100)
    |> validate_scheduled_deployment()
    |> validate_phased_deployment()
    |> foreign_key_constraint(:policy_id)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:deployed_by_id)
  end

  defp validate_scheduled_deployment(changeset) do
    if get_field(changeset, :strategy) == "scheduled" do
      case get_field(changeset, :scheduled_at) do
        nil ->
          add_error(changeset, :scheduled_at, "must be set for scheduled deployments")

        scheduled_at ->
          if DateTime.compare(scheduled_at, DateTime.utc_now()) == :lt do
            add_error(changeset, :scheduled_at, "must be in the future")
          else
            changeset
          end
      end
    else
      changeset
    end
  end

  defp validate_phased_deployment(changeset) do
    if get_field(changeset, :strategy) == "phased" do
      case get_field(changeset, :rollout_phases) do
        [] ->
          add_error(changeset, :rollout_phases, "must be defined for phased deployments")

        phases when is_list(phases) ->
          if valid_phases?(phases) do
            changeset
          else
            add_error(changeset, :rollout_phases, "invalid phase configuration")
          end

        _ ->
          add_error(changeset, :rollout_phases, "must be a list")
      end
    else
      changeset
    end
  end

  defp valid_phases?(phases) do
    percentages = Enum.map(phases, & &1["percentage"])

    # Check all phases have percentage field
    Enum.all?(percentages, &is_integer/1) and
      # Check percentages are in ascending order
      percentages == Enum.sort(percentages) and
      # Check last phase is 100%
      List.last(percentages) == 100
  end

  @doc """
  Returns default phased rollout configuration.
  """
  def default_phased_rollout do
    [
      %{percentage: 5, status: "pending", started_at: nil, completed_at: nil},
      %{percentage: 25, status: "pending", started_at: nil, completed_at: nil},
      %{percentage: 50, status: "pending", started_at: nil, completed_at: nil},
      %{percentage: 100, status: "pending", started_at: nil, completed_at: nil}
    ]
  end

  @doc """
  Calculates the failure rate as a percentage.
  """
  def failure_rate(%__MODULE__{} = deployment) do
    total = deployment.successful_agents + deployment.failed_agents

    if total > 0 do
      (deployment.failed_agents / total * 100) |> Float.round(2)
    else
      0.0
    end
  end

  @doc """
  Determines if deployment should be rolled back based on failure rate.
  """
  def should_rollback?(%__MODULE__{} = deployment) do
    deployment.auto_rollback_enabled and
      failure_rate(deployment) > deployment.rollback_threshold_percent
  end
end
