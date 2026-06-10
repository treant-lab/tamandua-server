defmodule TamanduaServer.Cost.CostBudgetAlert do
  @moduledoc """
  Schema for budget alert notifications.
  Tracks when budgets exceed thresholds.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "cost_budget_alerts" do
    field :threshold_percent, :integer
    field :current_spend, :decimal
    field :budget_amount, :decimal
    field :forecast_overrun, :boolean, default: false
    field :forecast_amount, :decimal
    field :acknowledged, :boolean, default: false
    field :acknowledged_at, :utc_datetime

    belongs_to :budget, TamanduaServer.Cost.CostBudget
    belongs_to :organization, TamanduaServer.Accounts.Organization
    belongs_to :acknowledged_by_user, TamanduaServer.Accounts.User, foreign_key: :acknowledged_by

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(alert, attrs) do
    alert
    |> cast(attrs, [:budget_id, :organization_id, :threshold_percent, :current_spend, :budget_amount,
                    :forecast_overrun, :forecast_amount, :acknowledged, :acknowledged_by, :acknowledged_at])
    |> validate_required([:budget_id, :organization_id, :threshold_percent, :current_spend, :budget_amount])
    |> validate_number(:threshold_percent, greater_than: 0, less_than_or_equal_to: 100)
    |> foreign_key_constraint(:budget_id)
    |> foreign_key_constraint(:organization_id)
  end
end
