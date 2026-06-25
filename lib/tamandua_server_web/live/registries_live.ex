defmodule TamanduaServerWeb.RegistriesLive do
  @moduledoc """
  LiveView dashboard for unified model registry management.

  Displays models from all connected registries (HuggingFace, MLflow, W&B, Ollama)
  with health status, sync information, and ability to block high-risk models.

  ## Features

  - Unified model listing from all registries
  - Registry health status cards (healthy/degraded/unhealthy)
  - Real-time updates via PubSub on health changes and model scans
  - Risk score display with color coding
  - Block/unblock model actions
  - Registry filtering
  - Provenance statistics
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Registries.RegistryManager
  alias TamanduaServer.Policies.ModelPolicy

  @refresh_interval 30_000

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      # Subscribe to health updates
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "registries:health")
      # Subscribe to scan events
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "registries:downloads")
      # Subscribe to Ollama model pulls
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "registries:ollama")
      # Schedule periodic refresh
      :timer.send_interval(@refresh_interval, :refresh)
    end

    {:ok,
     socket
     |> assign_page_title()
     |> assign_registry_filter(nil)
     |> assign_sync_status()
     |> assign_models()
     |> assign_blocked_count()
     |> assign_provenance_stats()}
  end

  @impl true
  def handle_info(:refresh, socket) do
    {:noreply, assign_sync_status(socket)}
  end

  # Health status change - degraded
  @impl true
  def handle_info({:health_degraded, _registry, _error}, socket) do
    {:noreply, assign_sync_status(socket)}
  end

  # Health status change - unhealthy
  @impl true
  def handle_info({:health_unhealthy, _registry, _error}, socket) do
    {:noreply, assign_sync_status(socket)}
  end

  # Health status change - recovered
  @impl true
  def handle_info({:health_recovered, _registry}, socket) do
    {:noreply, assign_sync_status(socket)}
  end

  # Model scanned event
  @impl true
  def handle_info({:model_scanned, _model_id, _status, _risk_score}, socket) do
    {:noreply,
     socket
     |> assign_models()
     |> assign_blocked_count()
     |> assign_provenance_stats()}
  end

  # Model pulled (Ollama)
  @impl true
  def handle_info({:model_pulled, _model_id, _metadata}, socket) do
    {:noreply,
     socket
     |> assign_models()
     |> assign_sync_status()}
  end

  # Alert created
  @impl true
  def handle_info({:alert_created, _alert_id}, socket) do
    {:noreply, assign_blocked_count(socket)}
  end

  # Scan error
  @impl true
  def handle_info({:scan_error, _model_id, _reason}, socket) do
    {:noreply, assign_provenance_stats(socket)}
  end

  # Catch-all for other messages
  @impl true
  def handle_info(_, socket), do: {:noreply, socket}

  @impl true
  def handle_event("filter_registry", %{"registry" => registry}, socket) do
    case parse_registry_filter(registry) do
      :unknown ->
        {:noreply, put_flash(socket, :error, "Unknown registry filter")}

      registry_atom ->
        {:noreply,
         socket
         |> assign_registry_filter(registry_atom)
         |> assign_models()}
    end
  end

  @impl true
  def handle_event("block_model", %{"model_id" => model_id}, socket) do
    ModelPolicy.block_model(model_id, "manual_block")

    {:noreply,
     socket
     |> assign_models()
     |> assign_blocked_count()}
  end

  @impl true
  def handle_event("unblock_model", %{"model_id" => model_id}, socket) do
    ModelPolicy.unblock_model(model_id)

    {:noreply,
     socket
     |> assign_models()
     |> assign_blocked_count()}
  end

  @impl true
  def handle_event("refresh_all", _params, socket) do
    {:noreply,
     socket
     |> assign_sync_status()
     |> assign_models()
     |> assign_blocked_count()
     |> assign_provenance_stats()}
  end

  # Private functions

  defp parse_registry_filter(nil), do: nil
  defp parse_registry_filter("all"), do: nil
  defp parse_registry_filter(:huggingface), do: :huggingface
  defp parse_registry_filter(:mlflow), do: :mlflow
  defp parse_registry_filter(:wandb), do: :wandb
  defp parse_registry_filter(:ollama), do: :ollama
  defp parse_registry_filter("huggingface"), do: :huggingface
  defp parse_registry_filter("mlflow"), do: :mlflow
  defp parse_registry_filter("wandb"), do: :wandb
  defp parse_registry_filter("ollama"), do: :ollama
  defp parse_registry_filter(_), do: :unknown

  defp assign_page_title(socket) do
    assign(socket, page_title: "Model Registries")
  end

  defp assign_registry_filter(socket, registry) do
    assign(socket, registry_filter: registry)
  end

  defp assign_sync_status(socket) do
    status = RegistryManager.get_sync_status()
    assign(socket, sync_status: status)
  end

  defp assign_models(socket) do
    registry = socket.assigns[:registry_filter]
    models = RegistryManager.list_all_models(registry: registry, limit: 100)

    # Enrich with trust status
    enriched =
      Enum.map(models, fn model ->
        can_load = ModelPolicy.can_load?(model.id)
        Map.put(model, :can_load, can_load)
      end)

    assign(socket, models: enriched)
  end

  defp assign_blocked_count(socket) do
    blocked = ModelPolicy.list_blocked()
    assign(socket, blocked_count: length(blocked), blocked_models: blocked)
  end

  defp assign_provenance_stats(socket) do
    stats = RegistryManager.get_provenance_status()
    assign(socket, provenance_stats: stats)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="min-h-screen bg-gray-50 dark:bg-gray-900 py-6">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <!-- Header -->
        <div class="flex justify-between items-center mb-6">
          <div>
            <h1 class="text-2xl font-semibold text-gray-900 dark:text-white">
              Model Registries
            </h1>
            <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
              Monitor and manage AI models from connected registries
            </p>
          </div>
          <div class="flex items-center space-x-3">
            <span class="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">
              {@blocked_count} blocked
            </span>
            <button
              phx-click="refresh_all"
              class="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-sky-500"
            >
              <svg class="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              Refresh
            </button>
          </div>
        </div>

        <!-- Registry Health Cards -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <%= for status <- @sync_status do %>
            <.registry_card status={status} />
          <% end %>
        </div>

        <!-- Provenance Summary -->
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4 mb-6">
          <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-3">Scan Statistics</h3>
          <div class="grid grid-cols-2 md:grid-cols-5 gap-4">
            <.stat_badge label="Clean" count={count_status(@provenance_stats, :clean)} color="green" />
            <.stat_badge label="Suspicious" count={count_status(@provenance_stats, :suspicious)} color="yellow" />
            <.stat_badge label="Malicious" count={count_status(@provenance_stats, :malicious)} color="red" />
            <.stat_badge label="Pending" count={count_status(@provenance_stats, :pending)} color="gray" />
            <.stat_badge label="Scanning" count={count_status(@provenance_stats, :scanning)} color="blue" />
          </div>
        </div>

        <!-- Registry Filter Tabs -->
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow mb-6">
          <div class="border-b border-gray-200 dark:border-gray-700">
            <nav class="-mb-px flex space-x-8 px-4" aria-label="Tabs">
              <button
                phx-click="filter_registry"
                phx-value-registry="all"
                class={"whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm #{if @registry_filter == nil, do: "border-sky-500 text-sky-600 dark:text-sky-400", else: "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-200"}"}
              >
                All Registries
              </button>
              <button
                phx-click="filter_registry"
                phx-value-registry="huggingface"
                class={"whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm #{if @registry_filter == :huggingface, do: "border-sky-500 text-sky-600 dark:text-sky-400", else: "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-200"}"}
              >
                HuggingFace
              </button>
              <button
                phx-click="filter_registry"
                phx-value-registry="mlflow"
                class={"whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm #{if @registry_filter == :mlflow, do: "border-sky-500 text-sky-600 dark:text-sky-400", else: "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-200"}"}
              >
                MLflow
              </button>
              <button
                phx-click="filter_registry"
                phx-value-registry="wandb"
                class={"whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm #{if @registry_filter == :wandb, do: "border-sky-500 text-sky-600 dark:text-sky-400", else: "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-200"}"}
              >
                W&B
              </button>
              <button
                phx-click="filter_registry"
                phx-value-registry="ollama"
                class={"whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm #{if @registry_filter == :ollama, do: "border-sky-500 text-sky-600 dark:text-sky-400", else: "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-200"}"}
              >
                Ollama
              </button>
            </nav>
          </div>

          <!-- Model Table -->
          <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead class="bg-gray-50 dark:bg-gray-700">
                <tr>
                  <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Model ID
                  </th>
                  <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Registry
                  </th>
                  <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Author
                  </th>
                  <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Last Modified
                  </th>
                  <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Status
                  </th>
                  <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                <%= if Enum.empty?(@models) do %>
                  <tr>
                    <td colspan="6" class="px-6 py-8 text-center text-gray-500 dark:text-gray-400">
                      <%= if @registry_filter do %>
                        No models found in <%= @registry_filter %> registry. Ensure the registry is connected and accessible.
                      <% else %>
                        No models found. Ensure at least one registry is configured and accessible.
                      <% end %>
                    </td>
                  </tr>
                <% else %>
                  <%= for model <- @models do %>
                    <tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
                      <td class="px-6 py-4 whitespace-nowrap">
                        <div class="text-sm font-medium text-gray-900 dark:text-white">
                          <%= model.id %>
                        </div>
                        <div class="text-sm text-gray-500 dark:text-gray-400">
                          <%= truncate(model.sha, 12) %>
                        </div>
                      </td>
                      <td class="px-6 py-4 whitespace-nowrap">
                        <.registry_badge registry={model.registry} />
                      </td>
                      <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                        <%= model.author %>
                      </td>
                      <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                        <%= format_datetime(model.last_modified) %>
                      </td>
                      <td class="px-6 py-4 whitespace-nowrap">
                        <.trust_status can_load={model.can_load} />
                      </td>
                      <td class="px-6 py-4 whitespace-nowrap text-sm">
                        <%= case model.can_load do %>
                          <% {:ok, true} -> %>
                            <button
                              phx-click="block_model"
                              phx-value-model_id={model.id}
                              class="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
                            >
                              Block
                            </button>
                          <% {:ok, false, "explicitly_blocked"} -> %>
                            <button
                              phx-click="unblock_model"
                              phx-value-model_id={model.id}
                              class="text-green-600 hover:text-green-900 dark:text-green-400 dark:hover:text-green-300"
                            >
                              Unblock
                            </button>
                          <% _ -> %>
                            <span class="text-gray-400">-</span>
                        <% end %>
                      </td>
                    </tr>
                  <% end %>
                <% end %>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Blocked Models Section -->
        <%= if @blocked_count > 0 do %>
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
            <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-3">
              Blocked Models ({@blocked_count})
            </h3>
            <div class="space-y-2">
              <%= for blocked <- @blocked_models do %>
                <div class="flex items-center justify-between p-3 bg-red-50 dark:bg-red-900/20 rounded-md">
                  <div>
                    <span class="font-medium text-red-800 dark:text-red-200"><%= blocked.model_id %></span>
                    <span class="ml-2 text-sm text-red-600 dark:text-red-400"><%= blocked.registry %></span>
                  </div>
                  <div class="flex items-center space-x-4">
                    <span class="text-sm text-red-600 dark:text-red-400">
                      Risk: <%= Float.round(blocked.risk_score || 0.0, 2) %>
                    </span>
                    <span class={"px-2 py-1 text-xs rounded-full #{status_color(blocked.status)}"}>
                      <%= blocked.status %>
                    </span>
                  </div>
                </div>
              <% end %>
            </div>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  # Components

  defp registry_card(assigns) do
    ~H"""
    <div class={"bg-white dark:bg-gray-800 rounded-lg shadow p-4 border-l-4 #{health_border_color(@status.health_status)}"}>
      <div class="flex items-center justify-between mb-2">
        <h3 class="text-sm font-medium text-gray-900 dark:text-white capitalize">
          <%= @status.registry %>
        </h3>
        <.health_indicator status={@status.health_status} />
      </div>
      <div class="text-xs text-gray-500 dark:text-gray-400 space-y-1">
        <div>Last Check: <%= format_datetime(@status.last_check) %></div>
        <div>Last Sync: <%= format_datetime(@status.last_sync) %></div>
        <%= if @status.consecutive_failures > 0 do %>
          <div class="text-red-500">Failures: <%= @status.consecutive_failures %></div>
        <% end %>
        <%= if @status.last_error do %>
          <div class="text-red-500 truncate" title={inspect(@status.last_error)}>
            Error: <%= truncate(inspect(@status.last_error), 30) %>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  defp health_indicator(assigns) do
    ~H"""
    <span class={"inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium #{health_badge_color(@status)}"}>
      <span class={"w-2 h-2 mr-1.5 rounded-full #{health_dot_color(@status)}"}></span>
      <%= @status %>
    </span>
    """
  end

  defp registry_badge(assigns) do
    colors = %{
      huggingface: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
      mlflow: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
      wandb: "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200",
      ollama: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
    }

    color = Map.get(colors, assigns.registry, "bg-gray-100 text-gray-800")

    assigns = assign(assigns, :color, color)

    ~H"""
    <span class={"inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium #{@color}"}>
      <%= @registry %>
    </span>
    """
  end

  defp trust_status(assigns) do
    ~H"""
    <%= case @can_load do %>
      <% {:ok, true} -> %>
        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
          Allowed
        </span>
      <% {:ok, false, "explicitly_blocked"} -> %>
        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">
          Blocked
        </span>
      <% {:ok, false, "unscanned"} -> %>
        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200">
          Unscanned
        </span>
      <% {:ok, false, "malicious_model"} -> %>
        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">
          Malicious
        </span>
      <% {:ok, false, "high_risk_score"} -> %>
        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200">
          High Risk
        </span>
      <% {:ok, false, "scan_pending"} -> %>
        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">
          Pending
        </span>
      <% {:ok, false, "scan_in_progress"} -> %>
        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
          Scanning
        </span>
      <% _ -> %>
        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200">
          Unknown
        </span>
    <% end %>
    """
  end

  defp stat_badge(assigns) do
    colors = %{
      "green" => "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
      "yellow" => "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
      "red" => "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
      "gray" => "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200",
      "blue" => "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
    }

    color_class = Map.get(colors, assigns.color, colors["gray"])
    assigns = assign(assigns, :color_class, color_class)

    ~H"""
    <div class={"flex items-center justify-between p-3 rounded-lg #{@color_class}"}>
      <span class="text-sm font-medium"><%= @label %></span>
      <span class="text-lg font-bold"><%= @count %></span>
    </div>
    """
  end

  # Helper functions

  defp health_border_color(:healthy), do: "border-green-500"
  defp health_border_color(:degraded), do: "border-yellow-500"
  defp health_border_color(:unhealthy), do: "border-red-500"
  defp health_border_color(_), do: "border-gray-300"

  defp health_badge_color(:healthy), do: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
  defp health_badge_color(:degraded), do: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
  defp health_badge_color(:unhealthy), do: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
  defp health_badge_color(_), do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"

  defp health_dot_color(:healthy), do: "bg-green-400"
  defp health_dot_color(:degraded), do: "bg-yellow-400"
  defp health_dot_color(:unhealthy), do: "bg-red-400"
  defp health_dot_color(_), do: "bg-gray-400"

  defp status_color("clean"), do: "bg-green-100 text-green-800"
  defp status_color("suspicious"), do: "bg-yellow-100 text-yellow-800"
  defp status_color("malicious"), do: "bg-red-100 text-red-800"
  defp status_color(_), do: "bg-gray-100 text-gray-800"

  defp format_datetime(nil), do: "-"

  defp format_datetime(%DateTime{} = dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M")
  end

  defp format_datetime(_), do: "-"

  defp truncate(nil, _), do: "-"
  defp truncate(str, len) when is_binary(str) do
    if String.length(str) > len do
      String.slice(str, 0, len) <> "..."
    else
      str
    end
  end
  defp truncate(_, _), do: "-"

  defp count_status(stats, status) when is_map(stats) do
    stats
    |> Enum.reduce(0, fn {_registry, counts}, acc ->
      acc + Map.get(counts, status, 0)
    end)
  end

  defp count_status(_, _), do: 0
end
