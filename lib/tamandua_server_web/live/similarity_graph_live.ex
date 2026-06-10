defmodule TamanduaServerWeb.SimilarityGraphLive do
  @moduledoc """
  LiveView for alert similarity visualization.

  Features:
  - 2D scatter plot of alerts (t-SNE/UMAP projection)
  - Color-coded by similarity cluster
  - Interactive: click to view alert details
  - Filtering by severity, time range, organization
  - Cluster summaries
  """

  use TamanduaServerWeb, :live_view

  import Ecto.Query
  alias TamanduaServer.Alerts.{Alert, SimilarityDetector}
  alias TamanduaServer.Repo

  require Logger

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      # Load initial data
      send(self(), :load_alerts)
    end

    {:ok,
     assign(socket,
       alerts: [],
       embeddings: nil,
       cluster_labels: nil,
       cluster_info: nil,
       cluster_summaries: [],
       visualization_data: nil,
       loading: true,
       error: nil,
       # Filters
       days_back: 7,
       min_severity: "low",
       projection_method: "tsne",
       min_cluster_size: 2,
       # UI state
       selected_alert: nil,
       selected_cluster: nil
     )}
  end

  @impl true
  def handle_event("update_filters", params, socket) do
    days_back = String.to_integer(params["days_back"] || "7")
    min_severity = params["min_severity"] || "low"
    projection_method = params["projection_method"] || "tsne"
    min_cluster_size = String.to_integer(params["min_cluster_size"] || "2")

    socket =
      socket
      |> assign(
        days_back: days_back,
        min_severity: min_severity,
        projection_method: projection_method,
        min_cluster_size: min_cluster_size,
        loading: true
      )

    send(self(), :load_alerts)

    {:noreply, socket}
  end

  @impl true
  def handle_event("select_alert", %{"alert_id" => alert_id}, socket) do
    alert = Enum.find(socket.assigns.alerts, fn a -> a.id == alert_id end)

    {:noreply, assign(socket, selected_alert: alert)}
  end

  @impl true
  def handle_event("select_cluster", %{"cluster_id" => cluster_id}, socket) do
    cluster_id = String.to_integer(cluster_id)

    {:noreply, assign(socket, selected_cluster: cluster_id)}
  end

  @impl true
  def handle_event("deselect", _params, socket) do
    {:noreply, assign(socket, selected_alert: nil, selected_cluster: nil)}
  end

  @impl true
  def handle_info(:load_alerts, socket) do
    # Query alerts based on filters
    alerts = query_alerts(socket.assigns)

    if Enum.empty?(alerts) do
      {:noreply,
       assign(socket,
         alerts: [],
         loading: false,
         error: "No alerts found for the selected filters"
       )}
    else
      # Compute embeddings and clustering in background
      send(self(), {:compute_similarity, alerts})
      {:noreply, assign(socket, alerts: alerts, loading: true, error: nil)}
    end
  end

  @impl true
  def handle_info({:compute_similarity, alerts}, socket) do
    # Generate embeddings
    case SimilarityDetector.embed_alerts(alerts) do
      {:ok, %{embeddings: embeddings, alert_ids: alert_ids}} ->
        # Cluster alerts
        case SimilarityDetector.cluster_alerts(
               embeddings,
               alert_ids,
               alert_timestamps: Enum.map(alerts, &format_timestamp/1),
               min_cluster_size: socket.assigns.min_cluster_size
             ) do
          {:ok, clustering_result} ->
            # Generate visualization
            case SimilarityDetector.generate_visualization(
                   embeddings,
                   alert_ids,
                   cluster_labels: clustering_result.cluster_labels,
                   method: socket.assigns.projection_method
                 ) do
              {:ok, viz_data} ->
                {:noreply,
                 assign(socket,
                   embeddings: embeddings,
                   cluster_labels: clustering_result.cluster_labels,
                   cluster_info: clustering_result.cluster_info,
                   cluster_summaries: clustering_result.cluster_summaries,
                   visualization_data: viz_data,
                   loading: false,
                   error: nil
                 )}

              {:error, reason} ->
                Logger.error("Visualization generation failed: #{inspect(reason)}")

                {:noreply,
                 assign(socket, loading: false, error: "Failed to generate visualization")}
            end

          {:error, reason} ->
            Logger.error("Clustering failed: #{inspect(reason)}")
            {:noreply, assign(socket, loading: false, error: "Failed to cluster alerts")}
        end

      {:error, reason} ->
        Logger.error("Embedding generation failed: #{inspect(reason)}")
        {:noreply, assign(socket, loading: false, error: "Failed to generate embeddings")}
    end
  end

  @impl true
  def handle_info(_msg, socket), do: {:noreply, socket}

  @impl true
  def render(assigns) do
    ~H"""
    <div class="similarity-graph-container">
      <div class="page-header">
        <h1>Alert Similarity Visualization</h1>
        <p class="text-gray-600">
          Interactive visualization of alert similarities using ML embeddings
        </p>
      </div>

      <!-- Filters -->
      <div class="filters-panel bg-white rounded-lg shadow p-6 mb-6">
        <form phx-change="update_filters">
          <div class="grid grid-cols-4 gap-4">
            <div>
              <label class="block text-sm font-medium text-gray-700">Time Range</label>
              <select name="days_back" class="mt-1 block w-full rounded-md border-gray-300">
                <option value="1" selected={@days_back == 1}>Last 24 hours</option>
                <option value="7" selected={@days_back == 7}>Last 7 days</option>
                <option value="30" selected={@days_back == 30}>Last 30 days</option>
                <option value="90" selected={@days_back == 90}>Last 90 days</option>
              </select>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700">Min Severity</label>
              <select name="min_severity" class="mt-1 block w-full rounded-md border-gray-300">
                <option value="info" selected={@min_severity == "info"}>Info</option>
                <option value="low" selected={@min_severity == "low"}>Low</option>
                <option value="medium" selected={@min_severity == "medium"}>Medium</option>
                <option value="high" selected={@min_severity == "high"}>High</option>
                <option value="critical" selected={@min_severity == "critical"}>Critical</option>
              </select>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700">Projection Method</label>
              <select name="projection_method" class="mt-1 block w-full rounded-md border-gray-300">
                <option value="tsne" selected={@projection_method == "tsne"}>t-SNE</option>
                <option value="umap" selected={@projection_method == "umap"}>UMAP</option>
              </select>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700">Min Cluster Size</label>
              <select name="min_cluster_size" class="mt-1 block w-full rounded-md border-gray-300">
                <option value="2" selected={@min_cluster_size == 2}>2</option>
                <option value="3" selected={@min_cluster_size == 3}>3</option>
                <option value="5" selected={@min_cluster_size == 5}>5</option>
                <option value="10" selected={@min_cluster_size == 10}>10</option>
              </select>
            </div>
          </div>
        </form>
      </div>

      <!-- Loading State -->
      <%= if @loading do %>
        <div class="loading-state bg-white rounded-lg shadow p-12 text-center">
          <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600 mx-auto"></div>
          <p class="mt-4 text-gray-600">Computing alert similarities...</p>
        </div>
      <% end %>

      <!-- Error State -->
      <%= if @error do %>
        <div class="error-state bg-red-50 border border-red-200 rounded-lg p-4">
          <p class="text-red-800"><%= @error %></p>
        </div>
      <% end %>

      <!-- Visualization -->
      <%= if !@loading and @visualization_data do %>
        <div class="visualization-panel grid grid-cols-3 gap-6">
          <!-- Main Graph -->
          <div class="col-span-2 bg-white rounded-lg shadow p-6">
            <h2 class="text-lg font-semibold mb-4">Alert Similarity Graph</h2>
            <div id="similarity-plot" phx-hook="SimilarityPlot" data-visualization={Jason.encode!(@visualization_data)} data-alerts={Jason.encode!(@alerts)} data-cluster-labels={Jason.encode!(@cluster_labels)}>
              <!-- Plotly will render here -->
            </div>
          </div>

          <!-- Sidebar -->
          <div class="col-span-1 space-y-6">
            <!-- Cluster Summary -->
            <div class="bg-white rounded-lg shadow p-6">
              <h2 class="text-lg font-semibold mb-4">Cluster Summary</h2>

              <%= if @cluster_info do %>
                <div class="stats space-y-2">
                  <div class="stat">
                    <span class="text-gray-600">Total Alerts:</span>
                    <span class="font-semibold"><%= length(@alerts) %></span>
                  </div>
                  <div class="stat">
                    <span class="text-gray-600">Clusters Found:</span>
                    <span class="font-semibold"><%= @cluster_info["num_clusters"] %></span>
                  </div>
                  <div class="stat">
                    <span class="text-gray-600">Outliers:</span>
                    <span class="font-semibold"><%= @cluster_info["num_noise"] %></span>
                  </div>
                </div>

                <div class="mt-4">
                  <h3 class="text-sm font-medium text-gray-700 mb-2">Clusters:</h3>
                  <div class="space-y-2">
                    <%= for summary <- Enum.take(@cluster_summaries, 10) do %>
                      <div class="cluster-item p-2 border rounded hover:bg-gray-50 cursor-pointer" phx-click="select_cluster" phx-value-cluster_id={summary["cluster_id"]}>
                        <div class="flex justify-between items-center">
                          <span class="text-sm font-medium">Cluster <%= summary["cluster_id"] %></span>
                          <span class="text-xs bg-indigo-100 text-indigo-800 px-2 py-1 rounded">
                            <%= summary["size"] %> alerts
                          </span>
                        </div>
                      </div>
                    <% end %>
                  </div>
                </div>
              <% end %>
            </div>

            <!-- Selected Alert Details -->
            <%= if @selected_alert do %>
              <div class="bg-white rounded-lg shadow p-6">
                <div class="flex justify-between items-start mb-4">
                  <h2 class="text-lg font-semibold">Alert Details</h2>
                  <button phx-click="deselect" class="text-gray-400 hover:text-gray-600">
                    <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                      <path
                        fill-rule="evenodd"
                        d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z"
                        clip-rule="evenodd"
                      />
                    </svg>
                  </button>
                </div>

                <div class="space-y-3">
                  <div>
                    <span class="text-xs text-gray-500">Title</span>
                    <p class="text-sm font-medium"><%= @selected_alert.title %></p>
                  </div>

                  <div>
                    <span class="text-xs text-gray-500">Severity</span>
                    <p class="text-sm">
                      <span class={"badge badge-#{@selected_alert.severity}"}>
                        <%= String.upcase(@selected_alert.severity) %>
                      </span>
                    </p>
                  </div>

                  <div>
                    <span class="text-xs text-gray-500">MITRE Tactics</span>
                    <div class="flex flex-wrap gap-1 mt-1">
                      <%= for tactic <- @selected_alert.mitre_tactics || [] do %>
                        <span class="text-xs bg-blue-100 text-blue-800 px-2 py-1 rounded">
                          <%= tactic %>
                        </span>
                      <% end %>
                    </div>
                  </div>

                  <div>
                    <span class="text-xs text-gray-500">Time</span>
                    <p class="text-sm"><%= format_time(@selected_alert.inserted_at) %></p>
                  </div>

                  <div class="pt-3 border-t">
                    <.link
                      navigate={~p"/alerts/#{@selected_alert.id}"}
                      class="text-sm text-indigo-600 hover:text-indigo-800"
                    >
                      View Full Details →
                    </.link>
                  </div>
                </div>
              </div>
            <% end %>
          </div>
        </div>
      <% end %>
    </div>
    """
  end

  # ==================== Helper Functions ====================

  defp query_alerts(assigns) do
    import Ecto.Query

    severity_order = %{
      "critical" => 5,
      "high" => 4,
      "medium" => 3,
      "low" => 2,
      "info" => 1
    }

    min_severity_value = Map.get(severity_order, assigns.min_severity, 1)

    from(a in Alert,
      where: a.inserted_at >= ago(^assigns.days_back, "day"),
      where:
        fragment(
          "CASE ? WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END >= ?",
          a.severity,
          ^min_severity_value
        ),
      order_by: [desc: a.inserted_at],
      limit: 500,
      preload: [:agent]
    )
    |> Repo.all()
  end

  defp format_timestamp(alert) do
    DateTime.to_iso8601(alert.inserted_at)
  end

  defp format_time(%DateTime{} = dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S UTC")
  end

  defp format_time(%NaiveDateTime{} = ndt) do
    Calendar.strftime(ndt, "%Y-%m-%d %H:%M:%S")
  end

  defp format_time(_), do: "N/A"
end
