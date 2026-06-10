defmodule TamanduaServer.Cost.CostBudget do
  @moduledoc """
  Schema for cost budgets.
  Defines spending limits with alerts and optional auto-throttling.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @budget_types ~w(monthly quarterly annual)

  schema "cost_budgets" do
    field :name, :string
    field :budget_type, :string
    field :amount_usd, :decimal
    field :start_date, :date
    field :end_date, :date
    field :alert_thresholds, {:array, :integer}
    field :auto_throttle_enabled, :boolean, default: false
    field :throttle_threshold, :integer
    field :tags, :map
    field :active, :boolean, default: true

    belongs_to :organization, TamanduaServer.Accounts.Organization
    has_many :alerts, TamanduaServer.Cost.CostBudgetAlert, foreign_key: :budget_id

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(budget, attrs) do
    budget
    |> cast(attrs, [:organization_id, :name, :budget_type, :amount_usd, :start_date, :end_date,
                    :alert_thresholds, :auto_throttle_enabled, :throttle_threshold, :tags, :active])
    |> validate_required([:organization_id, :name, :budget_type, :amount_usd, :start_date])
    |> validate_inclusion(:budget_type, @budget_types)
    |> validate_number(:amount_usd, greater_than: 0)
    |> validate_number(:throttle_threshold, greater_than: 0, less_than_or_equal_to: 100)
    |> validate_thresholds()
    |> foreign_key_constraint(:organization_id)
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

  def budget_types, do: @budget_types
end
