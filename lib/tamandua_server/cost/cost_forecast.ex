defmodule TamanduaServer.Cost.CostForecast do
  @moduledoc """
  Schema for cost forecasts.
  Predicts future spending based on historical trends and growth scenarios.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "cost_forecasts" do
    field :forecast_month, :date
    field :base_forecast, :decimal
    field :growth_10_forecast, :decimal
    field :growth_25_forecast, :decimal
    field :growth_50_forecast, :decimal
    field :seasonal_adjustment, :decimal
    field :confidence_level, :decimal
    field :forecast_breakdown, :map
    field :metadata, :map

    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(forecast, attrs) do
    forecast
    |> cast(attrs, [:organization_id, :forecast_month, :base_forecast, :growth_10_forecast,
                    :growth_25_forecast, :growth_50_forecast, :seasonal_adjustment,
                    :confidence_level, :forecast_breakdown, :metadata])
    |> validate_required([:organization_id, :forecast_month, :base_forecast])
    |> validate_number(:confidence_level, greater_than_or_equal_to: 0, less_than_or_equal_to: 1)
    |> unique_constraint([:organization_id, :forecast_month])
    |> foreign_key_constraint(:organization_id)
  end
end
