defmodule TamanduaServerWeb.CostOptimizationLive do
  use TamanduaServerWeb, :live_view
  import Ecto.Query

  alias TamanduaServer.Cost.Optimizer

  @impl true
  def mount(_params, _session, socket) do
    organization_id = get_organization_id(socket)

    {:ok,
     socket
     |> assign(:organization_id, organization_id)
     |> assign(:filter_status, "new")
     |> assign(:selected_recommendation, nil)
     |> load_recommendations()}
  end

  @impl true
  def handle_event("filter_by_status", %{"status" => status}, socket) do
    {:noreply,
     socket
     |> assign(:filter_status, status)
     |> load_recommendations()}
  end

  def handle_event("select_recommendation", %{"id" => id}, socket) do
    recommendation = Enum.find(socket.assigns.recommendations, &(&1.id == id))

    {:noreply, assign(socket, :selected_recommendation, recommendation)}
  end

  def handle_event("close_detail", _params, socket) do
    {:noreply, assign(socket, :selected_recommendation, nil)}
  end

  def handle_event("implement_recommendation", %{"id" => id}, socket) do
    user_id = socket.assigns[:current_user][:id]

    case Optimizer.implement_recommendation(id, user_id) do
      {:ok, _recommendation} ->
        {:noreply,
         socket
         |> put_flash(:info, "Recommendation implemented successfully")
         |> assign(:selected_recommendation, nil)
         |> load_recommendations()}

      {:error, reason} ->
        {:noreply,
         socket
         |> put_flash(:error, "Failed to implement recommendation: #{inspect(reason)}")}
    end
  end

  def handle_event("dismiss_recommendation", %{"id" => id}, socket) do
    {:noreply, assign(socket, :dismissing_id, id)}
  end

  def handle_event("confirm_dismiss", %{"id" => id, "reason" => reason}, socket) do
    user_id = socket.assigns[:current_user][:id]

    case Optimizer.dismiss_recommendation(id, user_id, reason) do
      {:ok, _recommendation} ->
        {:noreply,
         socket
         |> put_flash(:info, "Recommendation dismissed")
         |> assign(:dismissing_id, nil)
         |> load_recommendations()}

      {:error, _changeset} ->
        {:noreply,
         socket
         |> put_flash(:error, "Failed to dismiss recommendation")}
    end
  end

  def handle_event("cancel_dismiss", _params, socket) do
    {:noreply, assign(socket, :dismissing_id, nil)}
  end

  def handle_event("refresh_recommendations", _params, socket) do
    org_id = socket.assigns.organization_id

    # Trigger background generation
    Task.start(fn ->
      Optimizer.generate_recommendations(org_id)
    end)

    {:noreply,
     socket
     |> put_flash(:info, "Refreshing recommendations...")
     |> load_recommendations()}
  end

  ## Private Functions

  defp load_recommendations(socket) do
    org_id = socket.assigns.organization_id
    status = socket.assigns.filter_status

    recommendations = Optimizer.get_recommendations(org_id, status: status)
    potential_savings = Optimizer.get_potential_savings(org_id) |> Decimal.to_float()

    # Group by severity
    grouped = Enum.group_by(recommendations, & &1.severity)

    socket
    |> assign(:recommendations, recommendations)
    |> assign(:potential_savings, potential_savings)
    |> assign(:high_priority, Map.get(grouped, "high", []))
    |> assign(:medium_priority, Map.get(grouped, "medium", []))
    |> assign(:low_priority, Map.get(grouped, "low", []))
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

  defp severity_badge_color("high"), do: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300"
  defp severity_badge_color("medium"), do: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300"
  defp severity_badge_color("low"), do: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300"
  defp severity_badge_color(_), do: "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300"

  defp effort_badge_color("one_click"), do: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300"
  defp effort_badge_color("easy"), do: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300"
  defp effort_badge_color("moderate"), do: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300"
  defp effort_badge_color("complex"), do: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300"
  defp effort_badge_color(_), do: "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300"

  defp effort_label("one_click"), do: "One Click"
  defp effort_label("easy"), do: "Easy"
  defp effort_label("moderate"), do: "Moderate"
  defp effort_label("complex"), do: "Complex"
  defp effort_label(_), do: "Unknown"

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
                Cost Optimization
              </h1>
              <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
                Identify and implement cost-saving opportunities
              </p>
            </div>
            <button
              phx-click="refresh_recommendations"
              class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 text-sm font-medium"
            >
              <.icon name="hero-arrow-path" class="w-4 h-4 inline mr-1" />
              Refresh
            </button>
          </div>
        </div>
      </div>

      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <!-- Savings Summary -->
        <div class="bg-gradient-to-r from-green-500 to-green-600 rounded-lg shadow-lg p-8 mb-8 text-white">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-sm font-medium opacity-90 uppercase tracking-wide">
                Total Potential Savings
              </p>
              <p class="text-5xl font-bold mt-2">
                <%= format_currency(@potential_savings) %>
              </p>
              <p class="text-sm opacity-90 mt-2">
                <%= length(@recommendations) %> optimization opportunities identified
              </p>
            </div>
            <div class="p-6 bg-white bg-opacity-20 rounded-full">
              <.icon name="hero-arrow-trending-down" class="w-16 h-16" />
            </div>
          </div>
        </div>

        <!-- Status Filter -->
        <div class="mb-6">
          <div class="flex gap-2">
            <button
              phx-click="filter_by_status"
              phx-value-status="new"
              class={"px-4 py-2 rounded-md text-sm font-medium #{if @filter_status == "new", do: "bg-blue-600 text-white", else: "bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 border border-gray-300 dark:border-gray-600"}"}
            >
              New (<%= length(@recommendations) %>)
            </button>
            <button
              phx-click="filter_by_status"
              phx-value-status="acknowledged"
              class={"px-4 py-2 rounded-md text-sm font-medium #{if @filter_status == "acknowledged", do: "bg-blue-600 text-white", else: "bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 border border-gray-300 dark:border-gray-600"}"}
            >
              Acknowledged
            </button>
            <button
              phx-click="filter_by_status"
              phx-value-status="implemented"
              class={"px-4 py-2 rounded-md text-sm font-medium #{if @filter_status == "implemented", do: "bg-blue-600 text-white", else: "bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 border border-gray-300 dark:border-gray-600"}"}
            >
              Implemented
            </button>
            <button
              phx-click="filter_by_status"
              phx-value-status="dismissed"
              class={"px-4 py-2 rounded-md text-sm font-medium #{if @filter_status == "dismissed", do: "bg-blue-600 text-white", else: "bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 border border-gray-300 dark:border-gray-600"}"}
            >
              Dismissed
            </button>
          </div>
        </div>

        <!-- Recommendations by Priority -->
        <div class="space-y-8">
          <!-- High Priority -->
          <%= if length(@high_priority) > 0 do %>
            <div>
              <h2 class="text-xl font-bold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                <.icon name="hero-exclamation-triangle" class="w-6 h-6 text-red-600" />
                High Priority
              </h2>
              <div class="space-y-4">
                <%= for rec <- @high_priority do %>
                  <div class="bg-white dark:bg-gray-800 rounded-lg shadow hover:shadow-lg transition-shadow">
                    <div class="p-6">
                      <div class="flex items-start justify-between gap-4">
                        <div class="flex-1 min-w-0">
                          <div class="flex items-center gap-2 mb-2">
                            <span class={"inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium #{severity_badge_color(rec.severity)}"}>
                              <%= String.upcase(rec.severity) %>
                            </span>
                            <span class={"inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium #{effort_badge_color(rec.implementation_effort)}"}>
                              <%= effort_label(rec.implementation_effort) %>
                            </span>
                            <span class="text-xs text-gray-500 dark:text-gray-400 capitalize">
                              <%= rec.resource_type %>
                            </span>
                          </div>
                          <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                            <%= rec.title %>
                          </h3>
                          <p class="text-sm text-gray-600 dark:text-gray-400 line-clamp-2">
                            <%= rec.description %>
                          </p>
                        </div>
                        <div class="flex-shrink-0 text-right">
                          <p class="text-sm text-gray-500 dark:text-gray-400">Estimated Savings</p>
                          <p class="text-2xl font-bold text-green-600 dark:text-green-400">
                            <%= format_currency(rec.estimated_savings_usd) %>
                          </p>
                          <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                            <%= if rec.savings_percent do %>
                              <%= Float.round(Decimal.to_float(rec.savings_percent), 0) %>% savings
                            <% end %>
                          </p>
                        </div>
                      </div>
                      <div class="mt-4 flex items-center gap-2">
                        <button
                          phx-click="select_recommendation"
                          phx-value-id={rec.id}
                          class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 text-sm font-medium"
                        >
                          View Details
                        </button>
                        <%= if rec.implementation_effort == "one_click" do %>
                          <button
                            phx-click="implement_recommendation"
                            phx-value-id={rec.id}
                            class="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 text-sm font-medium"
                          >
                            <.icon name="hero-bolt" class="w-4 h-4 inline mr-1" />
                            Implement Now
                          </button>
                        <% end %>
                        <button
                          phx-click="dismiss_recommendation"
                          phx-value-id={rec.id}
                          class="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-md hover:bg-gray-300 dark:hover:bg-gray-600 text-sm font-medium"
                        >
                          Dismiss
                        </button>
                      </div>
                    </div>
                  </div>
                <% end %>
              </div>
            </div>
          <% end %>

          <!-- Medium Priority -->
          <%= if length(@medium_priority) > 0 do %>
            <div>
              <h2 class="text-xl font-bold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                <.icon name="hero-exclamation-circle" class="w-6 h-6 text-yellow-600" />
                Medium Priority
              </h2>
              <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <%= for rec <- @medium_priority do %>
                  <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4 hover:shadow-lg transition-shadow">
                    <div class="flex items-center gap-2 mb-2">
                      <span class={"inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium #{severity_badge_color(rec.severity)}"}>
                        <%= String.upcase(rec.severity) %>
                      </span>
                      <span class={"inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium #{effort_badge_color(rec.implementation_effort)}"}>
                        <%= effort_label(rec.implementation_effort) %>
                      </span>
                    </div>
                    <h3 class="text-base font-semibold text-gray-900 dark:text-white mb-1">
                      <%= rec.title %>
                    </h3>
                    <p class="text-xs text-gray-600 dark:text-gray-400 line-clamp-2 mb-3">
                      <%= rec.description %>
                    </p>
                    <div class="flex items-center justify-between">
                      <span class="text-lg font-bold text-green-600 dark:text-green-400">
                        <%= format_currency(rec.estimated_savings_usd) %>
                      </span>
                      <button
                        phx-click="select_recommendation"
                        phx-value-id={rec.id}
                        class="text-sm text-blue-600 dark:text-blue-400 hover:underline"
                      >
                        View
                      </button>
                    </div>
                  </div>
                <% end %>
              </div>
            </div>
          <% end %>

          <!-- Low Priority -->
          <%= if length(@low_priority) > 0 do %>
            <div>
              <h2 class="text-xl font-bold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                <.icon name="hero-information-circle" class="w-6 h-6 text-blue-600" />
                Low Priority
              </h2>
              <div class="bg-white dark:bg-gray-800 rounded-lg shadow">
                <div class="divide-y divide-gray-200 dark:divide-gray-700">
                  <%= for rec <- @low_priority do %>
                    <div class="p-4 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                      <div class="flex items-center justify-between gap-4">
                        <div class="flex-1 min-w-0">
                          <h3 class="text-sm font-medium text-gray-900 dark:text-white">
                            <%= rec.title %>
                          </h3>
                          <p class="text-xs text-gray-500 dark:text-gray-400 capitalize">
                            <%= rec.resource_type %> • <%= effort_label(rec.implementation_effort) %>
                          </p>
                        </div>
                        <div class="flex items-center gap-4">
                          <span class="text-sm font-bold text-green-600 dark:text-green-400">
                            <%= format_currency(rec.estimated_savings_usd) %>
                          </span>
                          <button
                            phx-click="select_recommendation"
                            phx-value-id={rec.id}
                            class="text-sm text-blue-600 dark:text-blue-400 hover:underline"
                          >
                            View
                          </button>
                        </div>
                      </div>
                    </div>
                  <% end %>
                </div>
              </div>
            </div>
          <% end %>

          <%= if length(@recommendations) == 0 do %>
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-12 text-center">
              <.icon name="hero-check-circle" class="w-20 h-20 mx-auto mb-4 text-green-500" />
              <h3 class="text-xl font-bold text-gray-900 dark:text-white mb-2">
                No Recommendations Available
              </h3>
              <p class="text-gray-500 dark:text-gray-400">
                <%= if @filter_status == "new" do %>
                  Great job! Your infrastructure is well optimized.
                <% else %>
                  No <%= @filter_status %> recommendations found.
                <% end %>
              </p>
            </div>
          <% end %>
        </div>
      </div>

      <!-- Recommendation Detail Modal -->
      <%= if @selected_recommendation do %>
        <div
          class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50"
          phx-click="close_detail"
        >
          <div
            class="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto"
            phx-click={JS.stop_propagation()}
          >
            <div class="p-6">
              <div class="flex items-start justify-between mb-4">
                <h2 class="text-2xl font-bold text-gray-900 dark:text-white">
                  <%= @selected_recommendation.title %>
                </h2>
                <button
                  phx-click="close_detail"
                  class="text-gray-400 hover:text-gray-500 dark:hover:text-gray-300"
                >
                  <.icon name="hero-x-mark" class="w-6 h-6" />
                </button>
              </div>

              <div class="flex items-center gap-2 mb-4">
                <span class={"inline-flex items-center px-3 py-1 rounded-full text-sm font-medium #{severity_badge_color(@selected_recommendation.severity)}"}>
                  <%= String.upcase(@selected_recommendation.severity) %>
                </span>
                <span class={"inline-flex items-center px-3 py-1 rounded-full text-sm font-medium #{effort_badge_color(@selected_recommendation.implementation_effort)}"}>
                  <%= effort_label(@selected_recommendation.implementation_effort) %>
                </span>
              </div>

              <div class="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4 mb-6">
                <div class="flex items-center justify-between">
                  <div>
                    <p class="text-sm text-green-800 dark:text-green-300 font-medium">
                      Estimated Monthly Savings
                    </p>
                    <p class="text-3xl font-bold text-green-600 dark:text-green-400 mt-1">
                      <%= format_currency(@selected_recommendation.estimated_savings_usd) %>
                    </p>
                  </div>
                  <%= if @selected_recommendation.savings_percent do %>
                    <div class="text-right">
                      <p class="text-sm text-green-800 dark:text-green-300 font-medium">
                        Savings
                      </p>
                      <p class="text-3xl font-bold text-green-600 dark:text-green-400 mt-1">
                        <%= Float.round(Decimal.to_float(@selected_recommendation.savings_percent), 0) %>%
                      </p>
                    </div>
                  <% end %>
                </div>
              </div>

              <div class="mb-6">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                  Description
                </h3>
                <div class="prose dark:prose-invert max-w-none text-sm text-gray-600 dark:text-gray-400 whitespace-pre-wrap">
                  <%= @selected_recommendation.description %>
                </div>
              </div>

              <div class="mb-6">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                  Details
                </h3>
                <dl class="grid grid-cols-2 gap-4">
                  <div>
                    <dt class="text-sm text-gray-500 dark:text-gray-400">Resource Type</dt>
                    <dd class="text-sm font-medium text-gray-900 dark:text-white capitalize">
                      <%= @selected_recommendation.resource_type %>
                    </dd>
                  </div>
                  <%= if @selected_recommendation.resource_id do %>
                    <div>
                      <dt class="text-sm text-gray-500 dark:text-gray-400">Resource ID</dt>
                      <dd class="text-sm font-medium text-gray-900 dark:text-white">
                        <%= @selected_recommendation.resource_id %>
                      </dd>
                    </div>
                  <% end %>
                  <div>
                    <dt class="text-sm text-gray-500 dark:text-gray-400">Current Cost</dt>
                    <dd class="text-sm font-medium text-gray-900 dark:text-white">
                      <%= format_currency(@selected_recommendation.current_cost_usd) %>
                    </dd>
                  </div>
                  <div>
                    <dt class="text-sm text-gray-500 dark:text-gray-400">Implementation</dt>
                    <dd class="text-sm font-medium text-gray-900 dark:text-white">
                      <%= effort_label(@selected_recommendation.implementation_effort) %>
                    </dd>
                  </div>
                </dl>
              </div>

              <div class="flex items-center justify-end gap-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                <button
                  phx-click="close_detail"
                  class="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-md hover:bg-gray-300 dark:hover:bg-gray-600 font-medium"
                >
                  Close
                </button>
                <button
                  phx-click="dismiss_recommendation"
                  phx-value-id={@selected_recommendation.id}
                  class="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-md hover:bg-gray-300 dark:hover:bg-gray-600 font-medium"
                >
                  Dismiss
                </button>
                <%= if @selected_recommendation.implementation_effort == "one_click" do %>
                  <button
                    phx-click="implement_recommendation"
                    phx-value-id={@selected_recommendation.id}
                    class="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 font-medium"
                  >
                    <.icon name="hero-bolt" class="w-4 h-4 inline mr-1" />
                    Implement Now
                  </button>
                <% end %>
              </div>
            </div>
          </div>
        </div>
      <% end %>
    </div>
    """
  end
end
