defmodule TamanduaServerWeb.CostAnalysisLive do
  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Cost.{Tracker, Forecaster}
  import Ecto.Query

  @impl true
  def mount(_params, _session, socket) do
    organization_id = get_organization_id(socket)

    {:ok,
     socket
     |> assign(:organization_id, organization_id)
     |> assign(:view_mode, "breakdown") # "breakdown", "chargeback", "forecast"
     |> assign(:period, "30d")
     |> assign(:selected_tag_key, nil)
     |> load_analysis_data()}
  end

  @impl true
  def handle_event("change_view", %{"view" => view}, socket) do
    {:noreply,
     socket
     |> assign(:view_mode, view)
     |> load_analysis_data()}
  end

  def handle_event("change_period", %{"period" => period}, socket) do
    {:noreply,
     socket
     |> assign(:period, period)
     |> load_analysis_data()}
  end

  def handle_event("select_tag", %{"key" => key}, socket) do
    {:noreply,
     socket
     |> assign(:selected_tag_key, key)
     |> load_analysis_data()}
  end

  def handle_event("export_csv", _params, socket) do
    # Generate CSV export
    csv_data = generate_csv_export(socket)

    {:noreply,
     socket
     |> push_event("download", %{
       filename: "cost_analysis_#{Date.utc_today()}.csv",
       content: csv_data,
       mime_type: "text/csv"
     })}
  end

  ## Private Functions

  defp load_analysis_data(socket) do
    org_id = socket.assigns.organization_id
    period = socket.assigns.period
    view_mode = socket.assigns.view_mode

    {from_date, to_date} = get_date_range(period)

    socket = case view_mode do
      "breakdown" ->
        load_breakdown_data(socket, org_id, from_date, to_date)

      "chargeback" ->
        load_chargeback_data(socket, org_id, from_date, to_date)

      "forecast" ->
        load_forecast_data(socket, org_id)

      _ ->
        socket
    end

    socket
  end

  defp load_breakdown_data(socket, org_id, from_date, to_date) do
    summary = Tracker.get_summary(org_id, from_date: from_date, to_date: to_date)

    # Get detailed breakdown
    costs = Tracker.get_costs(org_id, from_date: from_date, to_date: to_date)

    # Group by resource type and resource id
    resource_breakdown = costs
      |> Enum.group_by(& &1.resource_type)
      |> Enum.map(fn {type, entries} ->
        total_cost = entries
          |> Enum.map(&Decimal.to_float(&1.cost_usd))
          |> Enum.sum()

        resources = entries
          |> Enum.group_by(& &1.resource_id)
          |> Enum.map(fn {res_id, res_entries} ->
            cost = res_entries
              |> Enum.map(&Decimal.to_float(&1.cost_usd))
              |> Enum.sum()

            %{
              resource_id: res_id,
              cost: cost,
              entries: length(res_entries)
            }
          end)
          |> Enum.sort_by(& &1.cost, :desc)

        %{
          type: type,
          total_cost: total_cost,
          resources: resources
        }
      end)
      |> Enum.sort_by(& &1.total_cost, :desc)

    socket
    |> assign(:summary, summary)
    |> assign(:resource_breakdown, resource_breakdown)
  end

  defp load_chargeback_data(socket, org_id, from_date, to_date) do
    # Get available tag keys
    tag_keys = get_available_tag_keys(org_id, from_date, to_date)

    selected_tag_key = socket.assigns.selected_tag_key || List.first(tag_keys) || "department"

    # Get costs by tag
    costs_by_tag = Tracker.get_costs_by_tag(org_id, selected_tag_key,
      from_date: from_date, to_date: to_date)

    socket
    |> assign(:tag_keys, tag_keys)
    |> assign(:selected_tag_key, selected_tag_key)
    |> assign(:costs_by_tag, costs_by_tag)
  end

  defp load_forecast_data(socket, org_id) do
    forecasts = Forecaster.get_forecasts(org_id, months: 6)

    socket
    |> assign(:forecasts, forecasts)
  end

  defp get_available_tag_keys(org_id, from_date, to_date) do
    # Query distinct tag keys from cost entries
    query = from c in TamanduaServer.Cost.CostEntry,
      where: c.organization_id == ^org_id,
      where: c.date >= ^from_date and c.date <= ^to_date,
      select: fragment("jsonb_object_keys(?)", c.metadata)

    TamanduaServer.Repo.all(query)
    |> Enum.uniq()
    |> Enum.sort()
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

  defp get_organization_id(socket) do
    socket.assigns[:current_user]
    |> case do
      %{organization_id: org_id} when not is_nil(org_id) -> org_id
      _ ->
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

  defp format_date(%Date{} = date) do
    Calendar.strftime(date, "%b %Y")
  end
  defp format_date(_), do: "N/A"

  defp generate_csv_export(socket) do
    # Generate CSV based on current view
    "Cost Analysis Export - #{Date.utc_today()}\n"
  end

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
                Cost Analysis
              </h1>
              <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
                Detailed cost breakdown and chargeback reports
              </p>
            </div>
            <div class="flex gap-3">
              <div class="flex gap-2">
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
                <button
                  phx-click="change_period"
                  phx-value-period="6m"
                  class={"px-3 py-1 rounded text-sm font-medium #{if @period == "6m", do: "bg-blue-600 text-white", else: "bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300"}"}
                >
                  6m
                </button>
              </div>
              <button
                phx-click="export_csv"
                class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 text-sm font-medium"
              >
                <.icon name="hero-arrow-down-tray" class="w-4 h-4 inline mr-1" />
                Export CSV
              </button>
            </div>
          </div>
        </div>
      </div>

      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <!-- View Mode Tabs -->
        <div class="mb-6 border-b border-gray-200 dark:border-gray-700">
          <nav class="-mb-px flex space-x-8">
            <button
              phx-click="change_view"
              phx-value-view="breakdown"
              class={"px-1 pb-4 text-sm font-medium border-b-2 #{if @view_mode == "breakdown", do: "border-blue-500 text-blue-600 dark:text-blue-400", else: "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300"}"}
            >
              Resource Breakdown
            </button>
            <button
              phx-click="change_view"
              phx-value-view="chargeback"
              class={"px-1 pb-4 text-sm font-medium border-b-2 #{if @view_mode == "chargeback", do: "border-blue-500 text-blue-600 dark:text-blue-400", else: "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300"}"}
            >
              Chargeback Reports
            </button>
            <button
              phx-click="change_view"
              phx-value-view="forecast"
              class={"px-1 pb-4 text-sm font-medium border-b-2 #{if @view_mode == "forecast", do: "border-blue-500 text-blue-600 dark:text-blue-400", else: "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300"}"}
            >
              Forecasts
            </button>
          </nav>
        </div>

        <!-- Content based on view mode -->
        <%= case @view_mode do %>
          <% "breakdown" -> %>
            <div class="space-y-6">
              <%= if @resource_breakdown && length(@resource_breakdown) > 0 do %>
                <%= for type_data <- @resource_breakdown do %>
                  <div class="bg-white dark:bg-gray-800 rounded-lg shadow">
                    <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                      <div class="flex items-center justify-between">
                        <h3 class="text-lg font-semibold text-gray-900 dark:text-white capitalize">
                          <%= type_data.type %>
                        </h3>
                        <span class="text-lg font-bold text-gray-900 dark:text-white">
                          <%= format_currency(type_data.total_cost) %>
                        </span>
                      </div>
                    </div>
                    <div class="divide-y divide-gray-200 dark:divide-gray-700">
                      <%= for resource <- Enum.take(type_data.resources, 10) do %>
                        <div class="px-6 py-3 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                          <div class="flex items-center justify-between">
                            <div class="flex-1 min-w-0">
                              <p class="text-sm font-medium text-gray-900 dark:text-white truncate">
                                <%= resource.resource_id || "Unallocated" %>
                              </p>
                              <p class="text-xs text-gray-500 dark:text-gray-400">
                                <%= resource.entries %> entries
                              </p>
                            </div>
                            <span class="text-sm font-bold text-gray-900 dark:text-white ml-4">
                              <%= format_currency(resource.cost) %>
                            </span>
                          </div>
                        </div>
                      <% end %>
                    </div>
                  </div>
                <% end %>
              <% else %>
                <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-12 text-center">
                  <.icon name="hero-chart-pie" class="w-16 h-16 mx-auto mb-4 text-gray-400" />
                  <p class="text-gray-500 dark:text-gray-400">No cost data available for this period</p>
                </div>
              <% end %>
            </div>

          <% "chargeback" -> %>
            <div>
              <!-- Tag selector -->
              <%= if @tag_keys && length(@tag_keys) > 0 do %>
                <div class="mb-6">
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Group by Tag
                  </label>
                  <div class="flex gap-2">
                    <%= for key <- @tag_keys do %>
                      <button
                        phx-click="select_tag"
                        phx-value-key={key}
                        class={"px-3 py-1 rounded text-sm font-medium #{if @selected_tag_key == key, do: "bg-blue-600 text-white", else: "bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300"}"}
                      >
                        <%= key %>
                      </button>
                    <% end %>
                  </div>
                </div>

                <!-- Chargeback table -->
                <div class="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
                  <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                    <thead class="bg-gray-50 dark:bg-gray-900">
                      <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                          <%= @selected_tag_key %>
                        </th>
                        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                          Total Cost
                        </th>
                        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                          Agent
                        </th>
                        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                          Storage
                        </th>
                        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                          Network
                        </th>
                        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                          ML
                        </th>
                        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                          Other
                        </th>
                      </tr>
                    </thead>
                    <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                      <%= for entry <- @costs_by_tag do %>
                        <tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
                          <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-white">
                            <%= entry.tag_value %>
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap text-sm font-bold text-gray-900 dark:text-white text-right">
                            <%= format_currency(entry.total_cost) %>
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400 text-right">
                            <%= format_currency(Map.get(entry.breakdown, "agent", 0)) %>
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400 text-right">
                            <%= format_currency(Map.get(entry.breakdown, "storage", 0)) %>
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400 text-right">
                            <%= format_currency(Map.get(entry.breakdown, "network", 0)) %>
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400 text-right">
                            <%= format_currency(Map.get(entry.breakdown, "ml", 0)) %>
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400 text-right">
                            <%= format_currency(Map.get(entry.breakdown, "other", 0)) %>
                          </td>
                        </tr>
                      <% end %>
                    </tbody>
                  </table>
                </div>
              <% else %>
                <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-12 text-center">
                  <.icon name="hero-tag" class="w-16 h-16 mx-auto mb-4 text-gray-400" />
                  <p class="text-gray-500 dark:text-gray-400">No tagged costs available</p>
                  <p class="text-sm text-gray-400 dark:text-gray-500 mt-2">
                    Add tags to cost entries to enable chargeback reporting
                  </p>
                </div>
              <% end %>
            </div>

          <% "forecast" -> %>
            <div class="space-y-6">
              <%= if @forecasts && length(@forecasts) > 0 do %>
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                  <%= for forecast <- @forecasts do %>
                    <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                      <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                        <%= format_date(forecast.forecast_month) %>
                      </h3>
                      <div class="space-y-3">
                        <div>
                          <p class="text-xs text-gray-500 dark:text-gray-400">Base Forecast</p>
                          <p class="text-2xl font-bold text-gray-900 dark:text-white">
                            <%= format_currency(forecast.base_forecast) %>
                          </p>
                        </div>
                        <div class="pt-3 border-t border-gray-200 dark:border-gray-700">
                          <p class="text-xs text-gray-500 dark:text-gray-400 mb-2">Growth Scenarios</p>
                          <div class="space-y-1 text-sm">
                            <div class="flex justify-between">
                              <span class="text-gray-600 dark:text-gray-400">+10%:</span>
                              <span class="font-medium"><%= format_currency(forecast.growth_10_forecast) %></span>
                            </div>
                            <div class="flex justify-between">
                              <span class="text-gray-600 dark:text-gray-400">+25%:</span>
                              <span class="font-medium"><%= format_currency(forecast.growth_25_forecast) %></span>
                            </div>
                            <div class="flex justify-between">
                              <span class="text-gray-600 dark:text-gray-400">+50%:</span>
                              <span class="font-medium"><%= format_currency(forecast.growth_50_forecast) %></span>
                            </div>
                          </div>
                        </div>
                        <div class="pt-3 border-t border-gray-200 dark:border-gray-700">
                          <div class="flex items-center justify-between text-xs">
                            <span class="text-gray-500 dark:text-gray-400">Confidence</span>
                            <span class="font-medium text-gray-900 dark:text-white">
                              <%= Float.round(Decimal.to_float(forecast.confidence_level) * 100, 0) %>%
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  <% end %>
                </div>
              <% else %>
                <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-12 text-center">
                  <.icon name="hero-chart-bar" class="w-16 h-16 mx-auto mb-4 text-gray-400" />
                  <p class="text-gray-500 dark:text-gray-400">No forecasts available</p>
                  <p class="text-sm text-gray-400 dark:text-gray-500 mt-2">
                    Forecasts require at least 30 days of historical data
                  </p>
                </div>
              <% end %>
            </div>
        <% end %>
      </div>
    </div>
    """
  end
end
