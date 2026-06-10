defmodule TamanduaServer.Cost.BudgetMonitor do
  @moduledoc """
  Budget monitoring and alerting service.

  Monitors spending against budgets and:
  - Triggers alerts at configured thresholds (50%, 75%, 90%, 100%)
  - Forecasts budget overruns
  - Optionally throttles resources when limits are exceeded
  - Sends notifications to administrators
  """
  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Cost.{CostBudget, CostBudgetAlert, CostEntry, Forecaster}
  import Ecto.Query

  @check_interval :timer.minutes(15) # Check budgets every 15 minutes

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    Logger.info("[Cost.BudgetMonitor] Starting budget monitoring service")

    # Schedule periodic checks
    schedule_check()

    {:ok, %{}}
  end

  ## Public API

  @doc """
  Create a new budget.
  """
  def create_budget(organization_id, attrs) do
    attrs = Map.put(attrs, :organization_id, organization_id)

    %CostBudget{}
    |> CostBudget.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update a budget.
  """
  def update_budget(budget_id, attrs) do
    budget = Repo.get!(CostBudget, budget_id)

    budget
    |> CostBudget.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Get budgets for an organization.
  """
  def list_budgets(organization_id, opts \\ []) do
    active_only = Keyword.get(opts, :active_only, false)

    query = from b in CostBudget,
      where: b.organization_id == ^organization_id,
      order_by: [desc: b.inserted_at]

    query = if active_only do
      from b in query, where: b.active == true
    else
      query
    end

    Repo.all(query)
  end

  @doc """
  Get budget status (current spend vs budget).
  """
  def get_budget_status(budget_id) do
    budget = Repo.get!(CostBudget, budget_id)
      |> Repo.preload(:alerts)

    current_spend = calculate_current_spend(budget)
    percent_used = if Decimal.compare(budget.amount_usd, 0) == :gt do
      Decimal.div(current_spend, budget.amount_usd)
      |> Decimal.mult(100)
      |> Decimal.to_float()
    else
      0.0
    end

    forecast_overrun = check_forecast_overrun(budget, current_spend)

    %{
      budget: budget,
      current_spend: current_spend,
      budget_amount: budget.amount_usd,
      percent_used: percent_used,
      forecast_overrun: forecast_overrun,
      recent_alerts: Enum.take(budget.alerts, 5)
    }
  end

  @doc """
  Check all budgets and trigger alerts if needed.
  """
  def check_budgets do
    GenServer.cast(__MODULE__, :check_budgets)
  end

  ## GenServer Callbacks

  @impl true
  def handle_cast(:check_budgets, state) do
    do_check_budgets()
    {:noreply, state}
  end

  @impl true
  def handle_info(:check_budgets, state) do
    do_check_budgets()
    schedule_check()
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  def handle_info(_msg, state), do: {:noreply, state}

  ## Private Functions

  defp schedule_check do
    Process.send_after(self(), :check_budgets, @check_interval)
  end

  defp do_check_budgets do
    # Get all active budgets
    query = from b in CostBudget,
      where: b.active == true

    budgets = Repo.all(query)

    Enum.each(budgets, fn budget ->
      check_budget(budget)
    end)
  end

  defp check_budget(budget) do
    current_spend = calculate_current_spend(budget)
    percent_used = if Decimal.compare(budget.amount_usd, 0) == :gt do
      Decimal.div(current_spend, budget.amount_usd)
      |> Decimal.mult(100)
      |> Decimal.to_float()
    else
      0.0
    end

    # Check each threshold
    Enum.each(budget.alert_thresholds, fn threshold ->
      if percent_used >= threshold do
        # Check if we already have an alert for this threshold
        existing_alert = Repo.get_by(CostBudgetAlert,
          budget_id: budget.id,
          threshold_percent: threshold,
          acknowledged: false
        )

        unless existing_alert do
          # Create new alert
          create_budget_alert(budget, threshold, current_spend)
        end
      end
    end)

    # Check for forecast overrun
    if check_forecast_overrun(budget, current_spend) do
      # Check if we already have a forecast overrun alert
      existing_forecast_alert = Repo.get_by(CostBudgetAlert,
        budget_id: budget.id,
        forecast_overrun: true,
        acknowledged: false
      )

      unless existing_forecast_alert do
        create_forecast_overrun_alert(budget, current_spend)
      end
    end

    # Check for auto-throttling
    if budget.auto_throttle_enabled && percent_used >= budget.throttle_threshold do
      Logger.warning("[Cost.BudgetMonitor] Budget #{budget.name} exceeded throttle threshold, throttling resources")
      apply_throttling(budget)
    end
  end

  defp calculate_current_spend(budget) do
    # Calculate spend for the current budget period
    {from_date, to_date} = get_budget_period(budget)

    query = from c in CostEntry,
      where: c.organization_id == ^budget.organization_id,
      where: c.date >= ^from_date and c.date <= ^to_date

    # Apply tag filters if specified
    query = if map_size(budget.tags) > 0 do
      Enum.reduce(budget.tags, query, fn {key, value}, q ->
        from c in q, where: fragment("?->>? = ?", c.metadata, ^to_string(key), ^value)
      end)
    else
      query
    end

    query = from c in query, select: sum(c.cost_usd)

    case Repo.one(query) do
      nil -> Decimal.new(0)
      amount -> amount
    end
  end

  defp get_budget_period(budget) do
    today = Date.utc_today()

    case budget.budget_type do
      "monthly" ->
        # Current month
        start_of_month = Date.beginning_of_month(today)
        end_of_month = Date.end_of_month(today)
        {start_of_month, end_of_month}

      "quarterly" ->
        # Current quarter
        quarter = div(today.month - 1, 3)
        start_month = quarter * 3 + 1
        start_date = Date.new!(today.year, start_month, 1)
        end_date = Date.add(start_date, 90) |> Date.end_of_month()
        {start_date, end_date}

      "annual" ->
        # Current year
        start_date = Date.new!(today.year, 1, 1)
        end_date = Date.new!(today.year, 12, 31)
        {start_date, end_date}

      _ ->
        # Use explicit start/end dates
        {budget.start_date, budget.end_date || today}
    end
  end

  defp check_forecast_overrun(budget, current_spend) do
    # Get forecast for next month
    next_month = Date.utc_today() |> Date.add(30)
    forecast = Forecaster.get_forecast_for_month(budget.organization_id, next_month)

    case forecast do
      nil -> false
      %{base_forecast: forecast_amount} ->
        # Check if current spend + forecast exceeds budget
        projected_total = Decimal.add(current_spend, forecast_amount)
        Decimal.compare(projected_total, budget.amount_usd) == :gt
    end
  end

  defp create_budget_alert(budget, threshold, current_spend) do
    %CostBudgetAlert{}
    |> CostBudgetAlert.changeset(%{
      budget_id: budget.id,
      organization_id: budget.organization_id,
      threshold_percent: threshold,
      current_spend: current_spend,
      budget_amount: budget.amount_usd,
      forecast_overrun: false
    })
    |> Repo.insert()
    |> case do
      {:ok, alert} ->
        Logger.warning("[Cost.BudgetMonitor] Budget alert: #{budget.name} at #{threshold}% (#{current_spend}/#{budget.amount_usd})")
        send_budget_notification(budget, alert)
        {:ok, alert}

      {:error, changeset} ->
        Logger.error("[Cost.BudgetMonitor] Failed to create budget alert: #{inspect(changeset.errors)}")
        {:error, changeset}
    end
  end

  defp create_forecast_overrun_alert(budget, current_spend) do
    next_month = Date.utc_today() |> Date.add(30)
    forecast = Forecaster.get_forecast_for_month(budget.organization_id, next_month)
    forecast_amount = forecast && forecast.base_forecast || Decimal.new(0)

    %CostBudgetAlert{}
    |> CostBudgetAlert.changeset(%{
      budget_id: budget.id,
      organization_id: budget.organization_id,
      threshold_percent: 100,
      current_spend: current_spend,
      budget_amount: budget.amount_usd,
      forecast_overrun: true,
      forecast_amount: forecast_amount
    })
    |> Repo.insert()
    |> case do
      {:ok, alert} ->
        Logger.warning("[Cost.BudgetMonitor] Forecast overrun alert: #{budget.name} projected to exceed budget")
        send_budget_notification(budget, alert)
        {:ok, alert}

      {:error, changeset} ->
        Logger.error("[Cost.BudgetMonitor] Failed to create forecast overrun alert: #{inspect(changeset.errors)}")
        {:error, changeset}
    end
  end

  defp send_budget_notification(budget, alert) do
    # Send notification via PubSub
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "org:#{budget.organization_id}:budget_alerts",
      {:budget_alert, alert}
    )

    # TODO: Send email notification to admins
  end

  defp apply_throttling(budget) do
    # Throttle resources for this organization
    # This could:
    # - Reduce agent collection frequency
    # - Pause ML inference
    # - Disable expensive integrations
    # - Archive older data

    Logger.info("[Cost.BudgetMonitor] Applying throttling for budget #{budget.name}")

    # Broadcast throttling event
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "org:#{budget.organization_id}:throttle",
      {:throttle_resources, budget.id}
    )
  end
end
