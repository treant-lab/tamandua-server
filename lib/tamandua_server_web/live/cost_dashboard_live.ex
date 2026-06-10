defmodule TamanduaServerWeb.CostDashboardLive do
  use TamanduaServerWeb, :live_view
  import Ecto.Query

  alias TamanduaServer.Cost.{Tracker, Forecaster, Optimizer, BudgetMonitor}

  @refresh_interval 60_000 # Refresh every minute

  @impl true
  def mount(_params, _session, socket) do
    organization_id = get_organization_id(socket)

    if connected?(socket) do
      # Subscribe to budget alerts
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "org:#{organization_id}:budget_alerts")
      # Schedule periodic refresh
      :timer.send_interval(@refresh_interval, :refresh)
    end

    {:ok,
     socket
     |> assign(:organization_id, organization_id)
     |> assign(:period, "30d")
     |> load_cost_data()}
  end

  @impl true
  def handle_event("change_period", %{"period" => period}, socket) do
    {:noreply,
     socket
     |> assign(:period, period)
     |> load_cost_data()}
  end

  def handle_event("navigate_to_analysis", _params, socket) do
    {:noreply, push_navigate(socket, to: "/cost/analysis")}
  end

  def handle_event("navigate_to_optimization", _params, socket) do
    {:noreply, push_navigate(socket, to: "/cost/optimization")}
  end

  @impl true
  def handle_info(:refresh, socket) do
    {:noreply, load_cost_data(socket)}
  end

  def handle_info({:budget_alert, _alert}, socket) do
    # Reload budget status when new alert arrives
    {:noreply, load_cost_data(socket)}
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  ## Private Functions

  defp load_cost_data(socket) do
    org_id = socket.assigns.organization_id
    period = socket.assigns.period

    # Calculate date range
    {from_date, to_date} = get_date_range(period)

    # Get cost summary
    summary = Tracker.get_summary(org_id, from_date: from_date, to_date: to_date)

    # Get budgets
    budgets = BudgetMonitor.list_budgets(org_id, active_only: true)
    budget_status = Enum.map(budgets, fn budget ->
      BudgetMonitor.get_budget_status(budget.id)
    end)

    # Get forecasts
    forecasts = Forecaster.get_forecasts(org_id, months: 3)

    # Get potential savings
    potential_savings = Optimizer.get_potential_savings(org_id)
      |> Decimal.to_float()

    # Get top recommendations
    top_recommendations = Optimizer.get_recommendations(org_id, status: "new")
      |> Enum.take(5)

    # Calculate KPIs
    current_month_spend = get_current_month_spend(org_id)
    avg_daily_cost = if summary.total_cost > 0 do
      summary.total_cost / length(summary.daily_costs)
    else
      0.0
    end

    # Budget burn rate
    burn_rate = calculate_burn_rate(budget_status)

    socket
    |> assign(:summary, summary)
    |> assign(:budgets, budgets)
    |> assign(:budget_status, budget_status)
    |> assign(:forecasts, forecasts)
    |> assign(:potential_savings, potential_savings)
    |> assign(:top_recommendations, top_recommendations)
    |> assign(:current_month_spend, current_month_spend)
    |> assign(:avg_daily_cost, avg_daily_cost)
    |> assign(:burn_rate, burn_rate)
  end

  defp get_date_range(period) do
    to_date = Date.utc_today()

    from_date = case period do
      "7d" -> Date.add(to_date, -7)
      "30d" -> Date.add(to_date, -30)
      "90d" -> Date.add(to_date, -90)
      "6m" -> Date.add(to_date, -180)
      _ -> Date.add(to_date, -30)
    end

    {from_date, to_date}
  end

  defp get_current_month_spend(org_id) do
    today = Date.utc_today()
    start_of_month = Date.beginning_of_month(today)

    summary = Tracker.get_summary(org_id, from_date: start_of_month, to_date: today)
    summary.total_cost
  end

  defp calculate_burn_rate([]), do: 0.0
  defp calculate_burn_rate(budget_status) do
    # Average burn rate across all budgets
    rates = Enum.map(budget_status, fn status ->
      status.percent_used
    end)

    if length(rates) > 0 do
      Enum.sum(rates) / length(rates)
    else
      0.0
    end
  end

  defp get_organization_id(socket) do
    # Get from session or default org
    socket.assigns[:current_user]
    |> case do
      %{organization_id: org_id} when not is_nil(org_id) -> org_id
      _ ->
        # Get first organization as fallback
        case TamanduaServer.Repo.one(from o in TamanduaServer.Accounts.Organization, limit: 1) do
          nil -> nil
          org -> org.id
        end
    end
  end

  defp format_currency(amount) when is_float(amount) do
    "$#{:erlang.float_to_binary(amount, decimals: 2)}"
  end
  defp format_currency(%Decimal{} = amount) do
    format_currency(Decimal.to_float(amount))
  end
  defp format_currency(_), do: "$0.00"

  defp severity_color(percent) when percent >= 90, do: "text-red-600 dark:text-red-400"
  defp severity_color(percent) when percent >= 75, do: "text-orange-600 dark:text-orange-400"
  defp severity_color(percent) when percent >= 50, do: "text-yellow-600 dark:text-yellow-400"
  defp severity_color(_), do: "text-green-600 dark:text-green-400"

  defp progress_color(percent) when percent >= 90, do: "bg-red-500"
  defp progress_color(percent) when percent >= 75, do: "bg-orange-500"
  defp progress_color(percent) when percent >= 50, do: "bg-yellow-500"
  defp progress_color(_), do: "bg-green-500"

  @impl true
  def render(assigns) do
    ~H"""
    <div class="min-h-screen bg-gray-50 dark:bg-gray-900">
      <!-- Header -->
      <div class="bg-white dark:bg-gray-800 shadow">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div class="flex items-center justify-between">
            <div>
              <h1 class="text-3xl font-bold text-gray-900 dark:text-white">
                Cost Management
              </h1>
              <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
                Monitor spending, budgets, and optimization opportunities
              </p>
            </div>
            <div class="flex gap-2">
              <button
                phx-click="change_period"
                phx-value-period="7d"
                class={"px-3 py-1 rounded text-sm font-medium #{if @period == "7d", do: "bg-blue-600 text-white", else: "bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300"}"}
              >
                7d
              </button>
              <button
                phx-click="change_period"
                phx-value-period="30d"
                class={"px-3 py-1 rounded text-sm font-medium #{if @period == "30d", do: "bg-blue-600 text-white", else: "bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300"}"}
              >
                30d
              </button>
              <button
                phx-click="change_period"
                phx-value-period="90d"
                class={"px-3 py-1 rounded text-sm font-medium #{if @period == "90d", do: "bg-blue-600 text-white", else: "bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300"}"}
              >
                90d
              </button>
            </div>
          </div>
        </div>
      </div>

      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <!-- KPI Cards -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <!-- Current Month Spend -->
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-sm font-medium text-gray-600 dark:text-gray-400">
                  Current Month
                </p>
                <p class="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                  <%= format_currency(@current_month_spend) %>
                </p>
              </div>
              <div class="p-3 bg-blue-100 dark:bg-blue-900 rounded-full">
                <.icon name="hero-currency-dollar" class="w-8 h-8 text-blue-600 dark:text-blue-300" />
              </div>
            </div>
          </div>

          <!-- Avg Daily Cost -->
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-sm font-medium text-gray-600 dark:text-gray-400">
                  Avg Daily Cost
                </p>
                <p class="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                  <%= format_currency(@avg_daily_cost) %>
                </p>
              </div>
              <div class="p-3 bg-purple-100 dark:bg-purple-900 rounded-full">
                <.icon name="hero-chart-bar" class="w-8 h-8 text-purple-600 dark:text-purple-300" />
              </div>
            </div>
          </div>

          <!-- Budget Burn Rate -->
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-sm font-medium text-gray-600 dark:text-gray-400">
                  Budget Burn Rate
                </p>
                <p class={"text-3xl font-bold mt-2 #{severity_color(@burn_rate)}"}>
                  <%= Float.round(@burn_rate, 1) %>%
                </p>
              </div>
              <div class="p-3 bg-orange-100 dark:bg-orange-900 rounded-full">
                <.icon name="hero-fire" class="w-8 h-8 text-orange-600 dark:text-orange-300" />
              </div>
            </div>
          </div>

          <!-- Potential Savings -->
          <div
            class="bg-white dark:bg-gray-800 rounded-lg shadow p-6 cursor-pointer hover:shadow-lg transition-shadow"
            phx-click="navigate_to_optimization"
          >
            <div class="flex items-center justify-between">
              <div>
                <p class="text-sm font-medium text-gray-600 dark:text-gray-400">
                  Potential Savings
                </p>
                <p class="text-3xl font-bold text-green-600 dark:text-green-400 mt-2">
                  <%= format_currency(@potential_savings) %>
                </p>
                <p class="text-xs text-gray-500 dark:text-gray-500 mt-1">
                  Click to view recommendations
                </p>
              </div>
              <div class="p-3 bg-green-100 dark:bg-green-900 rounded-full">
                <.icon name="hero-arrow-trending-down" class="w-8 h-8 text-green-600 dark:text-green-300" />
              </div>
            </div>
          </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          <!-- Cost Breakdown -->
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow">
            <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h2 class="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                <.icon name="hero-chart-pie" class="w-5 h-5" />
                Cost by Resource Type
              </h2>
            </div>
            <div class="p-6">
              <%= if map_size(@summary.breakdown_by_type) > 0 do %>
                <div class="space-y-4">
                  <%= for {type, cost} <- Enum.sort_by(@summary.breakdown_by_type, fn {_, c} -> c end, :desc) do %>
                    <div>
                      <div class="flex items-center justify-between mb-1">
                        <span class="text-sm font-medium text-gray-700 dark:text-gray-300 capitalize">
                          <%= type %>
                        </span>
                        <span class="text-sm font-bold text-gray-900 dark:text-white">
                          <%= format_currency(cost) %>
                        </span>
                      </div>
                      <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                        <div
                          class="bg-blue-500 h-2 rounded-full"
                          style={"width: #{min(cost / @summary.total_cost * 100, 100)}%"}
                        >
                        </div>
                      </div>
                    </div>
                  <% end %>
                </div>
              <% else %>
                <div class="text-center text-gray-500 dark:text-gray-400 py-8">
                  <.icon name="hero-chart-pie" class="w-12 h-12 mx-auto mb-3 text-gray-400" />
                  <p class="text-sm">No cost data available</p>
                </div>
              <% end %>
            </div>
          </div>

          <!-- Budgets -->
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow">
            <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h2 class="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                <.icon name="hero-banknotes" class="w-5 h-5" />
                Budget Status
              </h2>
            </div>
            <div class="p-6">
              <%= if length(@budget_status) > 0 do %>
                <div class="space-y-4">
                  <%= for status <- @budget_status do %>
                    <div class="border dark:border-gray-700 rounded-lg p-4">
                      <div class="flex items-center justify-between mb-2">
                        <span class="text-sm font-medium text-gray-900 dark:text-white">
                          <%= status.budget.name %>
                        </span>
                        <span class={"text-sm font-bold #{severity_color(status.percent_used)}"}>
                          <%= Float.round(status.percent_used, 1) %>%
                        </span>
                      </div>
                      <div class="flex items-center justify-between text-xs text-gray-500 dark:text-gray-400 mb-2">
                        <span><%= format_currency(status.current_spend) %> of <%= format_currency(status.budget_amount) %></span>
                      </div>
                      <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                        <div
                          class={"h-2 rounded-full #{progress_color(status.percent_used)}"}
                          style={"width: #{min(status.percent_used, 100)}%"}
                        >
                        </div>
                      </div>
                      <%= if status.forecast_overrun do %>
                        <div class="mt-2 text-xs text-red-600 dark:text-red-400 flex items-center gap-1">
                          <.icon name="hero-exclamation-triangle" class="w-4 h-4" />
                          <span>Forecast overrun detected</span>
                        </div>
                      <% end %>
                    </div>
                  <% end %>
                </div>
              <% else %>
                <div class="text-center text-gray-500 dark:text-gray-400 py-8">
                  <.icon name="hero-banknotes" class="w-12 h-12 mx-auto mb-3 text-gray-400" />
                  <p class="text-sm">No budgets configured</p>
                  <button class="mt-2 text-sm text-blue-600 dark:text-blue-400 hover:underline">
                    Create Budget
                  </button>
                </div>
              <% end %>
            </div>
          </div>
        </div>

        <!-- Cost Trend Chart -->
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow mb-8">
          <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
            <h2 class="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
              <.icon name="hero-chart-bar" class="w-5 h-5" />
              Cost Trend
            </h2>
          </div>
          <div class="p-6">
            <div class="h-64">
              <!-- Simple SVG chart -->
              <%= if length(@summary.daily_costs) > 0 do %>
                <% max_cost = @summary.daily_costs |> Enum.map(fn {_, cost} -> cost end) |> Enum.max() %>
                <% max_cost = if max_cost > 0, do: max_cost, else: 1 %>
                <svg viewBox="0 0 800 256" class="w-full h-full">
                  <!-- Grid lines -->
                  <%= for i <- 0..4 do %>
                    <line x1="40" y1={64 * i} x2="800" y2={64 * i} stroke="#e5e7eb" stroke-width="1" />
                  <% end %>

                  <!-- Line chart -->
                  <% points = @summary.daily_costs
                    |> Enum.with_index()
                    |> Enum.map(fn {{_date, cost}, idx} ->
                      x = 40 + (idx * (760 / max(length(@summary.daily_costs) - 1, 1)))
                      y = 256 - (cost / max_cost * 240)
                      {x, y}
                    end) %>

                  <% path_d = points
                    |> Enum.with_index()
                    |> Enum.map(fn {{x, y}, idx} ->
                      "#{if idx == 0, do: "M", else: "L"}#{x},#{y}"
                    end)
                    |> Enum.join(" ") %>

                  <path d={path_d} stroke="#3b82f6" stroke-width="2" fill="none" />

                  <!-- Points -->
                  <%= for {x, y} <- points do %>
                    <circle cx={x} cy={y} r="3" fill="#3b82f6" />
                  <% end %>
                </svg>
              <% else %>
                <div class="h-full flex items-center justify-center text-gray-500 dark:text-gray-400">
                  <p class="text-sm">No trend data available</p>
                </div>
              <% end %>
            </div>
          </div>
        </div>

        <!-- Top Cost Drivers & Recommendations -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <!-- Top Cost Drivers -->
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow">
            <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h2 class="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                <.icon name="hero-arrow-trending-up" class="w-5 h-5" />
                Top Cost Drivers
              </h2>
            </div>
            <div class="divide-y divide-gray-200 dark:divide-gray-700">
              <%= if length(@summary.top_resources) > 0 do %>
                <%= for resource <- @summary.top_resources do %>
                  <div class="px-6 py-4 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                    <div class="flex items-center justify-between">
                      <div class="flex-1 min-w-0">
                        <p class="text-sm font-medium text-gray-900 dark:text-white truncate">
                          <%= resource.resource_id %>
                        </p>
                        <p class="text-xs text-gray-500 dark:text-gray-400 capitalize">
                          <%= resource.resource_type %>
                        </p>
                      </div>
                      <span class="text-sm font-bold text-gray-900 dark:text-white ml-4">
                        <%= format_currency(resource.cost) %>
                      </span>
                    </div>
                  </div>
                <% end %>
              <% else %>
                <div class="px-6 py-12 text-center text-gray-500 dark:text-gray-400">
                  <.icon name="hero-server" class="w-12 h-12 mx-auto mb-3 text-gray-400" />
                  <p class="text-sm">No cost data available</p>
                </div>
              <% end %>
            </div>
          </div>

          <!-- Top Recommendations -->
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow">
            <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <div class="flex items-center justify-between">
                <h2 class="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                  <.icon name="hero-light-bulb" class="w-5 h-5" />
                  Cost Optimization
                </h2>
                <button
                  phx-click="navigate_to_optimization"
                  class="text-sm text-blue-600 dark:text-blue-400 hover:underline"
                >
                  View All
                </button>
              </div>
            </div>
            <div class="divide-y divide-gray-200 dark:divide-gray-700">
              <%= if length(@top_recommendations) > 0 do %>
                <%= for rec <- @top_recommendations do %>
                  <div class="px-6 py-4 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                    <div class="flex items-start justify-between gap-3">
                      <div class="flex-1 min-w-0">
                        <p class="text-sm font-medium text-gray-900 dark:text-white">
                          <%= rec.title %>
                        </p>
                        <p class="text-xs text-gray-500 dark:text-gray-400 mt-1 line-clamp-2">
                          <%= rec.description %>
                        </p>
                      </div>
                      <span class="text-sm font-bold text-green-600 dark:text-green-400 whitespace-nowrap">
                        <%= format_currency(rec.estimated_savings_usd) %>
                      </span>
                    </div>
                  </div>
                <% end %>
              <% else %>
                <div class="px-6 py-12 text-center text-gray-500 dark:text-gray-400">
                  <.icon name="hero-check-circle" class="w-12 h-12 mx-auto mb-3 text-green-400" />
                  <p class="text-sm">No optimization opportunities found</p>
                  <p class="text-xs mt-1">Your infrastructure is well optimized!</p>
                </div>
              <% end %>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
