defmodule TamanduaServer.AI.CostBudget do
  @moduledoc """
  Schema for AI workload cost budgets.

  Defines spending limits for AI inference workloads with:
  - Multiple limit types (daily, hourly, tokens/min, inferences/hour)
  - Alert thresholds for early warnings
  - Automated enforcement actions

  ## Budget Types

  - `:model` - Limits on a specific AI model
  - `:user` - Limits on a specific user
  - `:process` - Limits on a specific process/session
  - `:team` - Limits on a team/group
  - `:agent` - Limits on a specific EDR agent

  ## Enforcement Actions

  Actions are triggered when usage reaches threshold percentages:

  - `:alert` - Send notification via PubSub
  - `:throttle` - Apply rate limiting
  - `:block` - Block further requests (via ModelPolicy for models)
  - `:kill_process` - Terminate the process on the endpoint

  ## Example

      %CostBudget{
        entity_type: :team,
        entity_id: "engineering",
        daily_usd: 500.0,
        hourly_usd: 50.0,
        tokens_per_min: 100_000,
        inferences_per_hour: 5000,
        alert_thresholds: [50, 75, 90, 100],
        actions: %{
          50 => "alert",
          75 => "alert",
          90 => "throttle",
          100 => "block"
        }
      }
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Repo

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @entity_types ~w(model user process team agent)
  @actions ~w(alert throttle block kill_process)

  schema "ai_cost_budgets" do
    field :entity_type, :string
    field :entity_id, :string
    field :name, :string
    field :description, :string

    # Spending limits
    field :daily_usd, :decimal
    field :hourly_usd, :decimal
    field :tokens_per_min, :integer
    field :inferences_per_hour, :integer

    # Alert configuration
    field :alert_thresholds, {:array, :integer}, default: [50, 75, 90, 100]
    field :actions, :map, default: %{50 => "alert", 75 => "alert", 90 => "throttle", 100 => "block"}

    # State
    field :active, :boolean, default: true
    field :notified_thresholds, {:array, :integer}, default: []

    belongs_to :organization, TamanduaServer.Accounts.Organization
    belongs_to :created_by, TamanduaServer.Accounts.User

    timestamps(type: :utc_datetime)
  end

  @required_fields [:entity_type, :entity_id]
  @optional_fields [
    :name, :description, :daily_usd, :hourly_usd, :tokens_per_min,
    :inferences_per_hour, :alert_thresholds, :actions, :active,
    :notified_thresholds, :organization_id, :created_by_id
  ]

  @doc false
  def changeset(budget, attrs) do
    budget
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:entity_type, @entity_types)
    |> validate_number(:daily_usd, greater_than: 0)
    |> validate_number(:hourly_usd, greater_than: 0)
    |> validate_number(:tokens_per_min, greater_than: 0)
    |> validate_number(:inferences_per_hour, greater_than: 0)
    |> validate_thresholds()
    |> validate_actions()
    |> unique_constraint([:entity_type, :entity_id], name: :ai_cost_budgets_entity_idx)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:created_by_id)
  end

  defp validate_thresholds(changeset) do
    case get_field(changeset, :alert_thresholds) do
      nil -> changeset
      thresholds when is_list(thresholds) ->
        if Enum.all?(thresholds, &(&1 > 0 and &1 <= 100)) do
          changeset
        else
          add_error(changeset, :alert_thresholds, "all thresholds must be between 1 and 100")
        end
      _ ->
        add_error(changeset, :alert_thresholds, "must be a list of integers")
    end
  end

  defp validate_actions(changeset) do
    case get_field(changeset, :actions) do
      nil -> changeset
      actions when is_map(actions) ->
        valid = Enum.all?(actions, fn {_threshold, action} ->
          action in @actions
        end)
        if valid do
          changeset
        else
          add_error(changeset, :actions, "all actions must be one of: #{Enum.join(@actions, ", ")}")
        end
      _ ->
        add_error(changeset, :actions, "must be a map of threshold => action")
    end
  end

  @doc """
  Create a new budget.
  """
  def create(attrs) do
    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update an existing budget.
  """
  def update(%__MODULE__{} = budget, attrs) do
    budget
    |> changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Get budget for an entity.
  """
  def get(entity_type, entity_id) do
    query = from b in __MODULE__,
      where: b.entity_type == ^to_string(entity_type),
      where: b.entity_id == ^entity_id,
      where: b.active == true

    Repo.one(query)
  end

  @doc """
  Get all active budgets.
  """
  def list_active do
    query = from b in __MODULE__,
      where: b.active == true,
      order_by: [asc: b.entity_type, asc: b.entity_id]

    Repo.all(query)
  end

  @doc """
  Get all budgets for an organization.
  """
  def list_for_organization(organization_id) do
    query = from b in __MODULE__,
      where: b.organization_id == ^organization_id,
      order_by: [asc: b.entity_type, asc: b.entity_id]

    Repo.all(query)
  end

  @doc """
  Delete a budget.
  """
  def delete(%__MODULE__{} = budget) do
    Repo.delete(budget)
  end

  @doc """
  Mark thresholds as notified to prevent duplicate alerts.
  """
  def mark_notified(%__MODULE__{} = budget, threshold) do
    notified = Enum.uniq([threshold | budget.notified_thresholds])
    __MODULE__.update(budget, %{notified_thresholds: notified})
  end

  @doc """
  Reset notified thresholds (e.g., at start of new day).
  """
  def reset_notified(%__MODULE__{} = budget) do
    __MODULE__.update(budget, %{notified_thresholds: []})
  end

  @doc """
  Load budget configuration into CostGovernor.
  """
  def load_into_governor do
    budgets = list_active()

    for budget <- budgets do
      limits = %{
        daily_usd: if(budget.daily_usd, do: Decimal.to_float(budget.daily_usd)),
        hourly_usd: if(budget.hourly_usd, do: Decimal.to_float(budget.hourly_usd)),
        tokens_per_min: budget.tokens_per_min,
        inferences_per_hour: budget.inferences_per_hour,
        alert_thresholds: budget.alert_thresholds,
        actions: Map.new(budget.actions, fn {k, v} ->
          {String.to_integer(to_string(k)), String.to_atom(v)}
        end)
      }
      |> Enum.reject(fn {_k, v} -> is_nil(v) end)
      |> Map.new()

      TamanduaServer.AI.CostGovernor.set_budget(
        String.to_atom(budget.entity_type),
        budget.entity_id,
        limits
      )
    end

    {:ok, length(budgets)}
  end

  def entity_types, do: @entity_types
  def actions, do: @actions
end
