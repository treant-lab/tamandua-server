defmodule TamanduaServer.Cost.Forecaster do
  @moduledoc """
  Cost forecasting service.

  Predicts future costs based on:
  - Historical trends (moving averages)
  - Growth scenarios (10%, 25%, 50%)
  - Seasonal adjustments
  - Resource utilization trends

  Uses linear regression and exponential smoothing for predictions.
  """
  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Cost.{CostEntry, CostForecast}
  import Ecto.Query

  @forecast_interval :timer.hours(24) # Generate forecasts daily
  @lookback_days 90 # Use 90 days of history for forecasting

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    Logger.info("[Cost.Forecaster] Starting cost forecasting service")

    # Schedule periodic forecast generation
    schedule_forecast()

    {:ok, %{}}
  end

  ## Public API

  @doc """
  Generate forecast for the next N months.
  """
  def generate_forecast(organization_id, months_ahead \\ 3) do
    GenServer.call(__MODULE__, {:generate_forecast, organization_id, months_ahead}, :infinity)
  end

  @doc """
  Get existing forecasts for an organization.
  """
  def get_forecasts(organization_id, opts \\ []) do
    months = Keyword.get(opts, :months, 6)
    today = Date.utc_today()

    query = from f in CostForecast,
      where: f.organization_id == ^organization_id,
      where: f.forecast_month >= ^today,
      order_by: [asc: f.forecast_month],
      limit: ^months

    Repo.all(query)
  end

  @doc """
  Get forecast for a specific month.
  """
  def get_forecast_for_month(organization_id, date) do
    # Get first day of month
    month_start = Date.beginning_of_month(date)

    Repo.get_by(CostForecast, organization_id: organization_id, forecast_month: month_start)
  end

  ## GenServer Callbacks

  @impl true
  def handle_call({:generate_forecast, organization_id, months_ahead}, _from, state) do
    result = do_generate_forecast(organization_id, months_ahead)
    {:reply, result, state}
  end

  @impl true
  def handle_info(:generate_forecasts, state) do
    Logger.info("[Cost.Forecaster] Generating forecasts for all organizations")

    # Get all organizations and generate forecasts
    generate_all_forecasts()

    schedule_forecast()
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  def handle_info(_msg, state), do: {:noreply, state}

  ## Private Functions

  defp schedule_forecast do
    Process.send_after(self(), :generate_forecasts, @forecast_interval)
  end

  defp generate_all_forecasts do
    # Get all organizations
    query = from o in TamanduaServer.Accounts.Organization, select: o.id

    Repo.all(query)
    |> Enum.each(fn org_id ->
      Task.start(fn ->
        do_generate_forecast(org_id, 3)
      end)
    end)
  end

  defp do_generate_forecast(organization_id, months_ahead) do
    # Get historical costs
    to_date = Date.utc_today()
    from_date = Date.add(to_date, -@lookback_days)

    historical_costs = get_historical_daily_costs(organization_id, from_date, to_date)

    if length(historical_costs) < 30 do
      Logger.warning("[Cost.Forecaster] Insufficient data for org #{organization_id}, need at least 30 days")
      {:error, :insufficient_data}
    else
      # Calculate trend
      trend = calculate_trend(historical_costs)
      seasonality = calculate_seasonality(historical_costs)

      # Generate forecasts for each month
      results = for month_offset <- 1..months_ahead do
        target_month = Date.beginning_of_month(Date.add(to_date, month_offset * 30))

        base_forecast = calculate_base_forecast(historical_costs, trend, month_offset)
        seasonal_adj = get_seasonal_adjustment(seasonality, target_month.month)

        # Apply seasonal adjustment
        adjusted_base = base_forecast * (1 + seasonal_adj)

        # Calculate growth scenarios
        growth_10 = adjusted_base * 1.10
        growth_25 = adjusted_base * 1.25
        growth_50 = adjusted_base * 1.50

        # Get forecast breakdown by resource type
        breakdown = calculate_forecast_breakdown(organization_id, adjusted_base, historical_costs)

        # Calculate confidence level (decreases with distance)
        confidence = max(0.5, 1.0 - (month_offset * 0.1))

        forecast_attrs = %{
          organization_id: organization_id,
          forecast_month: target_month,
          base_forecast: Decimal.from_float(adjusted_base),
          growth_10_forecast: Decimal.from_float(growth_10),
          growth_25_forecast: Decimal.from_float(growth_25),
          growth_50_forecast: Decimal.from_float(growth_50),
          seasonal_adjustment: Decimal.from_float(seasonal_adj),
          confidence_level: Decimal.from_float(confidence),
          forecast_breakdown: breakdown
        }

        # Upsert forecast
        case Repo.get_by(CostForecast, organization_id: organization_id, forecast_month: target_month) do
          nil ->
            %CostForecast{}
            |> CostForecast.changeset(forecast_attrs)
            |> Repo.insert()

          existing ->
            existing
            |> CostForecast.changeset(forecast_attrs)
            |> Repo.update()
        end
      end

      successful = Enum.count(results, fn
        {:ok, _} -> true
        _ -> false
      end)

      Logger.info("[Cost.Forecaster] Generated #{successful}/#{months_ahead} forecasts for org #{organization_id}")
      {:ok, successful}
    end
  end

  defp get_historical_daily_costs(organization_id, from_date, to_date) do
    query = from c in CostEntry,
      where: c.organization_id == ^organization_id,
      where: c.date >= ^from_date and c.date <= ^to_date,
      select: %{
        date: c.date,
        cost: sum(c.cost_usd),
        resource_type: c.resource_type
      },
      group_by: [c.date, c.resource_type],
      order_by: c.date

    costs_by_type = Repo.all(query)
      |> Enum.group_by(& &1.date)

    # Sum across resource types for each day
    costs_by_type
    |> Enum.map(fn {date, entries} ->
      total = entries
        |> Enum.map(&Decimal.to_float(&1.cost || Decimal.new(0)))
        |> Enum.sum()

      {date, total}
    end)
    |> Enum.sort_by(fn {date, _cost} -> date end)
  end

  defp calculate_trend(historical_costs) do
    # Simple linear regression
    n = length(historical_costs)

    if n == 0, do: 0.0

    indexed_costs = Enum.with_index(historical_costs, 1)

    sum_x = Enum.sum(1..n)
    sum_y = indexed_costs |> Enum.map(fn {{_date, cost}, _idx} -> cost end) |> Enum.sum()
    sum_xy = indexed_costs |> Enum.map(fn {{_date, cost}, idx} -> idx * cost end) |> Enum.sum()
    sum_x2 = Enum.sum(Enum.map(1..n, &(&1 * &1)))

    # Calculate slope (trend)
    numerator = (n * sum_xy) - (sum_x * sum_y)
    denominator = (n * sum_x2) - (sum_x * sum_x)

    if denominator == 0 do
      0.0
    else
      numerator / denominator
    end
  end

  defp calculate_seasonality(historical_costs) do
    # Group by month and calculate average
    costs_by_month = historical_costs
      |> Enum.group_by(fn {date, _cost} -> date.month end)
      |> Enum.map(fn {month, costs} ->
        avg = costs |> Enum.map(fn {_date, cost} -> cost end) |> Enum.sum() |> Kernel./(length(costs))
        {month, avg}
      end)
      |> Map.new()

    # Calculate overall average
    overall_avg = if map_size(costs_by_month) > 0 do
      costs_by_month |> Map.values() |> Enum.sum() |> Kernel./(map_size(costs_by_month))
    else
      1.0
    end

    # Calculate seasonal factors (deviation from average)
    costs_by_month
    |> Enum.map(fn {month, avg} ->
      factor = if overall_avg > 0, do: (avg - overall_avg) / overall_avg, else: 0.0
      {month, factor}
    end)
    |> Map.new()
  end

  defp get_seasonal_adjustment(seasonality, month) do
    Map.get(seasonality, month, 0.0)
  end

  defp calculate_base_forecast(historical_costs, trend, months_ahead) do
    # Get average of last 30 days
    recent_costs = historical_costs |> Enum.take(-30)
    recent_avg = if length(recent_costs) > 0 do
      recent_costs |> Enum.map(fn {_date, cost} -> cost end) |> Enum.sum() |> Kernel./(length(recent_costs))
    else
      0.0
    end

    # Project forward based on trend
    days_ahead = months_ahead * 30
    daily_forecast = recent_avg + (trend * days_ahead / length(historical_costs))

    # Convert to monthly cost
    max(0.0, daily_forecast * 30)
  end

  defp calculate_forecast_breakdown(organization_id, total_forecast, _historical_costs) do
    # Get recent distribution by resource type (last 30 days)
    to_date = Date.utc_today()
    from_date = Date.add(to_date, -30)

    query = from c in CostEntry,
      where: c.organization_id == ^organization_id,
      where: c.date >= ^from_date and c.date <= ^to_date,
      select: %{
        resource_type: c.resource_type,
        total_cost: sum(c.cost_usd)
      },
      group_by: c.resource_type

    breakdown = Repo.all(query)
      |> Enum.map(fn row -> {row.resource_type, Decimal.to_float(row.total_cost || Decimal.new(0))} end)
      |> Map.new()

    total = Map.values(breakdown) |> Enum.sum()

    if total > 0 do
      # Apply same distribution to forecast
      breakdown
      |> Enum.map(fn {type, cost} ->
        proportion = cost / total
        {type, proportion * total_forecast}
      end)
      |> Map.new()
    else
      %{}
    end
  end
end
