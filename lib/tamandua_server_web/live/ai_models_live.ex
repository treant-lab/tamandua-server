defmodule TamanduaServerWeb.AIModelsLive do
  @moduledoc """
  LiveView for the AI Models dashboard.

  Displays AI models discovered across all monitored endpoints, grouped by hostname.
  Supports filtering, searching, expandable rows, and manual re-scan triggers.
  """
  use TamanduaServerWeb, :live_view

  alias TamanduaServer.AISecurity.AIInventory
  alias TamanduaServer.AISecurity.KnownGood
  alias TamanduaServer.AISecurity.BackdoorAnalysis
  alias TamanduaServer.AISecurity.MLClient

  @refresh_interval 30_000  # 30 seconds for stats refresh

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "ai_security:discovery")
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "ai_security:scan_results")
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "ai_security:response_actions")
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "ai_security:backdoor_analysis")
      :timer.send_interval(@refresh_interval, :refresh_stats)
    end

    models = try do
      case AIInventory.list_inventory(limit: 500) do
        {:ok, inventory} -> inventory
        _ -> []
      end
    catch
      _kind, _reason -> []
    end

    stats = try do
      AIInventory.stats()
    catch
      _kind, _reason -> %{}
    end

    grouped = group_by_endpoint(models)
    known_good_hashes = load_known_good_hashes(models)
    backdoor_analyses = load_backdoor_analyses(models)

    {:ok,
     socket
     |> assign(:page_title, "AI Models")
     |> assign(:models, models)
     |> assign(:grouped_models, grouped)
     |> assign(:stats, stats)
     |> assign(:known_good_hashes, known_good_hashes)
     |> assign(:backdoor_analyses, backdoor_analyses)
     |> assign(:expanded_endpoints, MapSet.new())
     |> assign(:expanded_model_id, nil)
     |> assign(:scan_history, [])
     |> assign(:current_chart_data, nil)
     |> assign(:selected_ids, MapSet.new())
     |> assign(:scanning_ids, MapSet.new())
     |> assign(:analyzing_ids, MapSet.new())
     |> assign(:action_in_progress, MapSet.new())
     |> assign(:show_confirm_modal, nil)
     |> assign(:filters, %{status: nil, type: nil, agent_id: nil, search: nil})
     |> assign(:sort_by, :last_seen_at)
     |> assign(:sort_order, :desc)}
  end

  @impl true
  def handle_params(params, _url, socket) do
    filters = build_filters(params)
    {:noreply, apply_filters(socket, filters)}
  end

  # ------------------------------------------------------------------
  # Event Handlers
  # ------------------------------------------------------------------

  @impl true
  def handle_event("toggle_endpoint", %{"hostname" => hostname}, socket) do
    expanded = socket.assigns.expanded_endpoints

    expanded = if MapSet.member?(expanded, hostname) do
      MapSet.delete(expanded, hostname)
    else
      MapSet.put(expanded, hostname)
    end

    {:noreply, assign(socket, :expanded_endpoints, expanded)}
  end

  @impl true
  def handle_event("expand_all", _params, socket) do
    all_hostnames = Map.keys(socket.assigns.grouped_models) |> MapSet.new()
    {:noreply, assign(socket, :expanded_endpoints, all_hostnames)}
  end

  @impl true
  def handle_event("collapse_all", _params, socket) do
    {:noreply, assign(socket, :expanded_endpoints, MapSet.new())}
  end

  @impl true
  def handle_event("toggle_expand", %{"id" => model_id}, socket) do
    current = socket.assigns.expanded_model_id

    {new_expanded, scan_history, chart_data} =
      if current == model_id do
        {nil, [], nil}
      else
        # Load scan history for the expanded model
        history = load_scan_history(model_id)

        # Load chart data from backdoor analysis if available
        analysis = socket.assigns.backdoor_analyses[model_id]
        charts = if analysis do
          BackdoorAnalysis.format_for_charts(analysis)
        else
          nil
        end

        {model_id, history, charts}
      end

    {:noreply,
     socket
     |> assign(:expanded_model_id, new_expanded)
     |> assign(:scan_history, scan_history)
     |> assign(:current_chart_data, chart_data)}
  end

  @impl true
  def handle_event("filter", params, socket) do
    filters = build_filters(params)
    path = build_path(filters)
    {:noreply, push_patch(socket, to: path)}
  end

  @impl true
  def handle_event("clear_filters", _params, socket) do
    {:noreply, push_patch(socket, to: ~p"/live/ai-security/models")}
  end

  @impl true
  def handle_event("toggle_selection", %{"id" => model_id}, socket) do
    selected = socket.assigns.selected_ids

    selected = if MapSet.member?(selected, model_id) do
      MapSet.delete(selected, model_id)
    else
      MapSet.put(selected, model_id)
    end

    {:noreply, assign(socket, :selected_ids, selected)}
  end

  @impl true
  def handle_event("select_all", _params, socket) do
    all_ids = Enum.map(socket.assigns.models, & &1.id) |> MapSet.new()
    {:noreply, assign(socket, :selected_ids, all_ids)}
  end

  @impl true
  def handle_event("deselect_all", _params, socket) do
    {:noreply, assign(socket, :selected_ids, MapSet.new())}
  end

  @impl true
  def handle_event("scan_model", %{"id" => model_id}, socket) do
    scanning_ids = MapSet.put(socket.assigns.scanning_ids, model_id)

    Task.start(fn ->
      case trigger_scan(model_id) do
        {:ok, _} -> :ok
        {:error, reason} ->
          Phoenix.PubSub.broadcast(
            TamanduaServer.PubSub,
            "ai_security:scan_results",
            {:scan_error, %{model_id: model_id, reason: reason}}
          )
      end
    end)

    {:noreply, assign(socket, :scanning_ids, scanning_ids)}
  end

  @impl true
  def handle_event("scan_selected", _params, socket) do
    selected_ids = MapSet.to_list(socket.assigns.selected_ids)
    scanning_ids = Enum.reduce(selected_ids, socket.assigns.scanning_ids, &MapSet.put(&2, &1))

    Task.start(fn ->
      Enum.each(selected_ids, &trigger_scan/1)
    end)

    {:noreply,
     socket
     |> assign(:scanning_ids, scanning_ids)
     |> put_flash(:info, "Scanning #{length(selected_ids)} model(s)...")}
  end

  @impl true
  def handle_event("deep_analyze", %{"id" => model_id}, socket) do
    analyzing_ids = MapSet.put(socket.assigns.analyzing_ids, model_id)

    Task.start(fn ->
      case trigger_deep_analysis(model_id) do
        {:ok, result} ->
          Phoenix.PubSub.broadcast(
            TamanduaServer.PubSub,
            "ai_security:backdoor_analysis",
            {:analysis_completed, %{model_id: model_id, result: result}}
          )
        {:error, reason} ->
          Phoenix.PubSub.broadcast(
            TamanduaServer.PubSub,
            "ai_security:backdoor_analysis",
            {:analysis_error, %{model_id: model_id, reason: reason}}
          )
      end
    end)

    {:noreply,
     socket
     |> assign(:analyzing_ids, analyzing_ids)
     |> put_flash(:info, "Running deep backdoor analysis...")}
  end

  # ===========================================================================
  # Response Action Event Handlers
  # ===========================================================================

  alias TamanduaServer.AISecurity.ResponseActions

  @impl true
  def handle_event("request_quarantine", %{"id" => model_id}, socket) do
    {:noreply, assign(socket, :show_confirm_modal, %{action: :quarantine, model_id: model_id})}
  end

  @impl true
  def handle_event("request_block", %{"id" => model_id}, socket) do
    {:noreply, assign(socket, :show_confirm_modal, %{action: :block, model_id: model_id})}
  end

  @impl true
  def handle_event("request_unblock", %{"id" => model_id}, socket) do
    # Unblock doesn't need confirmation - execute directly
    execute_unblock(socket, model_id)
  end

  @impl true
  def handle_event("request_restore", %{"id" => model_id}, socket) do
    {:noreply, assign(socket, :show_confirm_modal, %{action: :restore, model_id: model_id})}
  end

  @impl true
  def handle_event("request_bulk_quarantine", _params, socket) do
    model_ids = MapSet.to_list(socket.assigns.selected_ids)
    {:noreply, assign(socket, :show_confirm_modal, %{action: :bulk_quarantine, model_ids: model_ids})}
  end

  @impl true
  def handle_event("request_bulk_block", _params, socket) do
    model_ids = MapSet.to_list(socket.assigns.selected_ids)
    {:noreply, assign(socket, :show_confirm_modal, %{action: :bulk_block, model_ids: model_ids})}
  end

  @impl true
  def handle_event("cancel_action", _params, socket) do
    {:noreply, assign(socket, :show_confirm_modal, nil)}
  end

  @impl true
  def handle_event("confirm_action", _params, socket) do
    case socket.assigns.show_confirm_modal do
      %{action: :quarantine, model_id: model_id} ->
        execute_quarantine(socket, model_id)

      %{action: :block, model_id: model_id} ->
        execute_block(socket, model_id)

      %{action: :restore, model_id: model_id} ->
        execute_restore(socket, model_id)

      %{action: :bulk_quarantine, model_ids: model_ids} ->
        execute_bulk_quarantine(socket, model_ids)

      %{action: :bulk_block, model_ids: model_ids} ->
        execute_bulk_block(socket, model_ids)

      _ ->
        {:noreply, assign(socket, :show_confirm_modal, nil)}
    end
  end

  defp execute_quarantine(socket, model_id) do
    user_id = get_user_id(socket)
    action_in_progress = MapSet.put(socket.assigns.action_in_progress, model_id)

    Task.start(fn ->
      case ResponseActions.quarantine_model(model_id, user_id) do
        {:ok, _} -> :ok
        {:error, reason} ->
          Phoenix.PubSub.broadcast(
            TamanduaServer.PubSub,
            "ai_security:response_actions",
            {:action_error, %{model_id: model_id, action: :quarantine, reason: reason}}
          )
      end
    end)

    {:noreply,
     socket
     |> assign(:action_in_progress, action_in_progress)
     |> assign(:show_confirm_modal, nil)
     |> put_flash(:info, "Quarantining model...")}
  end

  defp execute_block(socket, model_id) do
    user_id = get_user_id(socket)
    action_in_progress = MapSet.put(socket.assigns.action_in_progress, model_id)

    Task.start(fn ->
      case ResponseActions.block_model(model_id, user_id) do
        {:ok, _} -> :ok
        {:error, reason} ->
          Phoenix.PubSub.broadcast(
            TamanduaServer.PubSub,
            "ai_security:response_actions",
            {:action_error, %{model_id: model_id, action: :block, reason: reason}}
          )
      end
    end)

    {:noreply,
     socket
     |> assign(:action_in_progress, action_in_progress)
     |> assign(:show_confirm_modal, nil)
     |> put_flash(:info, "Blocking model...")}
  end

  defp execute_unblock(socket, model_id) do
    user_id = get_user_id(socket)
    action_in_progress = MapSet.put(socket.assigns.action_in_progress, model_id)

    Task.start(fn ->
      case ResponseActions.unblock_model(model_id, user_id) do
        {:ok, _} -> :ok
        {:error, reason} ->
          Phoenix.PubSub.broadcast(
            TamanduaServer.PubSub,
            "ai_security:response_actions",
            {:action_error, %{model_id: model_id, action: :unblock, reason: reason}}
          )
      end
    end)

    {:noreply,
     socket
     |> assign(:action_in_progress, action_in_progress)
     |> put_flash(:info, "Unblocking model...")}
  end

  defp execute_restore(socket, model_id) do
    user_id = get_user_id(socket)
    action_in_progress = MapSet.put(socket.assigns.action_in_progress, model_id)

    Task.start(fn ->
      case ResponseActions.restore_model(model_id, user_id, acknowledge_risk: true) do
        {:ok, _} -> :ok
        {:error, reason} ->
          Phoenix.PubSub.broadcast(
            TamanduaServer.PubSub,
            "ai_security:response_actions",
            {:action_error, %{model_id: model_id, action: :restore, reason: reason}}
          )
      end
    end)

    {:noreply,
     socket
     |> assign(:action_in_progress, action_in_progress)
     |> assign(:show_confirm_modal, nil)
     |> put_flash(:info, "Restoring model...")}
  end

  defp execute_bulk_quarantine(socket, model_ids) do
    user_id = get_user_id(socket)
    action_in_progress = Enum.reduce(model_ids, socket.assigns.action_in_progress, &MapSet.put(&2, &1))

    Task.start(fn ->
      Enum.each(model_ids, fn model_id ->
        ResponseActions.quarantine_model(model_id, user_id)
      end)
    end)

    {:noreply,
     socket
     |> assign(:action_in_progress, action_in_progress)
     |> assign(:show_confirm_modal, nil)
     |> assign(:selected_ids, MapSet.new())
     |> put_flash(:info, "Quarantining #{length(model_ids)} model(s)...")}
  end

  defp execute_bulk_block(socket, model_ids) do
    user_id = get_user_id(socket)
    action_in_progress = Enum.reduce(model_ids, socket.assigns.action_in_progress, &MapSet.put(&2, &1))

    Task.start(fn ->
      Enum.each(model_ids, fn model_id ->
        ResponseActions.block_model(model_id, user_id)
      end)
    end)

    {:noreply,
     socket
     |> assign(:action_in_progress, action_in_progress)
     |> assign(:show_confirm_modal, nil)
     |> assign(:selected_ids, MapSet.new())
     |> put_flash(:info, "Blocking #{length(model_ids)} model(s)...")}
  end

  defp get_user_id(socket) do
    case socket.assigns[:current_user] do
      %{id: id} -> id
      _ -> nil
    end
  end

  # ------------------------------------------------------------------
  # PubSub Handlers
  # ------------------------------------------------------------------

  @impl true
  def handle_info(:refresh_stats, socket) do
    stats = try do
      AIInventory.stats()
    catch
      _kind, _reason -> %{}
    end

    {:noreply, assign(socket, :stats, stats)}
  end

  @impl true
  def handle_info({:ai_component_discovered, component}, socket) do
    # Update or add the component to the list
    models = socket.assigns.models
    |> Enum.reject(&(&1.id == component.id))
    |> List.insert_at(0, component)

    grouped = group_by_endpoint(models)
    stats = try do
      AIInventory.stats()
    catch
      _kind, _reason -> %{}
    end

    known_good_hashes = load_known_good_hashes(models)

    {:noreply,
     socket
     |> assign(:models, models)
     |> assign(:grouped_models, grouped)
     |> assign(:stats, stats)
     |> assign(:known_good_hashes, known_good_hashes)}
  end

  @impl true
  def handle_info({:scan_started, %{model_id: model_id}}, socket) do
    scanning_ids = MapSet.put(socket.assigns.scanning_ids, model_id)
    {:noreply, assign(socket, :scanning_ids, scanning_ids)}
  end

  @impl true
  def handle_info({:model_scan_completed, %{model_id: model_id} = result}, socket) do
    scanning_ids = MapSet.delete(socket.assigns.scanning_ids, model_id)

    models = Enum.map(socket.assigns.models, fn model ->
      if model.id == model_id do
        Map.merge(model, %{
          scan_status: result[:scan_status],
          scan_result: result[:scan_result],
          last_scanned_at: DateTime.utc_now()
        })
      else
        model
      end
    end)

    grouped = group_by_endpoint(models)

    {:noreply,
     socket
     |> assign(:scanning_ids, scanning_ids)
     |> assign(:models, models)
     |> assign(:grouped_models, grouped)
     |> put_flash(:info, "Scan completed for #{model_id}")}
  end

  @impl true
  def handle_info({:scan_error, %{model_id: model_id, reason: reason}}, socket) do
    scanning_ids = MapSet.delete(socket.assigns.scanning_ids, model_id)

    {:noreply,
     socket
     |> assign(:scanning_ids, scanning_ids)
     |> put_flash(:error, "Scan failed for #{model_id}: #{inspect(reason)}")}
  end

  @impl true
  def handle_info({:bulk_scan_started, _}, socket), do: {:noreply, socket}

  @impl true
  def handle_info({:model_status_changed, %{model_id: model_id, status: status}}, socket) do
    action_in_progress = MapSet.delete(socket.assigns.action_in_progress, model_id)

    # Update model status in the list
    models = Enum.map(socket.assigns.models, fn model ->
      if model.id == model_id do
        Map.put(model, :response_status, status)
      else
        model
      end
    end)

    grouped = group_by_endpoint(models)

    flash_message = case status do
      "quarantined" -> "Model #{model_id} quarantined successfully"
      "blocked" -> "Model #{model_id} blocked successfully"
      "unblocked" -> "Model #{model_id} unblocked successfully"
      "restored" -> "Model #{model_id} restored successfully"
      _ -> "Action completed for #{model_id}"
    end

    {:noreply,
     socket
     |> assign(:action_in_progress, action_in_progress)
     |> assign(:models, models)
     |> assign(:grouped_models, grouped)
     |> put_flash(:info, flash_message)}
  end

  @impl true
  def handle_info({:action_error, %{model_id: model_id, action: action, reason: reason}}, socket) do
    action_in_progress = MapSet.delete(socket.assigns.action_in_progress, model_id)
    error_msg = "#{action} failed for #{model_id}: #{inspect(reason)}"

    {:noreply,
     socket
     |> assign(:action_in_progress, action_in_progress)
     |> put_flash(:error, error_msg)}
  end

  @impl true
  def handle_info({:analysis_completed, %{model_id: model_id, result: result}}, socket) do
    analyzing_ids = MapSet.delete(socket.assigns.analyzing_ids, model_id)

    # Update backdoor_analyses map with the new result
    backdoor_analyses = Map.put(socket.assigns.backdoor_analyses, model_id, result)

    # Also update chart data if this model is currently expanded
    chart_data =
      if socket.assigns.expanded_model_id == model_id do
        BackdoorAnalysis.format_for_charts(result)
      else
        socket.assigns.current_chart_data
      end

    {:noreply,
     socket
     |> assign(:analyzing_ids, analyzing_ids)
     |> assign(:backdoor_analyses, backdoor_analyses)
     |> assign(:current_chart_data, chart_data)
     |> put_flash(:info, "Deep analysis completed")}
  end

  @impl true
  def handle_info({:analysis_error, %{model_id: model_id, reason: reason}}, socket) do
    analyzing_ids = MapSet.delete(socket.assigns.analyzing_ids, model_id)

    {:noreply,
     socket
     |> assign(:analyzing_ids, analyzing_ids)
     |> put_flash(:error, "Analysis failed: #{inspect(reason)}")}
  end

  @impl true
  def handle_info(_, socket), do: {:noreply, socket}

  # ------------------------------------------------------------------
  # Render
  # ------------------------------------------------------------------

  @impl true
  def render(assigns) do
    ~H"""
    <div class="min-h-screen bg-gray-100 dark:bg-gray-900">
      <div class="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
        <!-- Header -->
        <div class="flex items-center justify-between mb-6">
          <div>
            <h1 class="text-2xl font-bold text-gray-900 dark:text-white">AI Models</h1>
            <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
              Discovered AI/ML models across all monitored endpoints
            </p>
          </div>
          <div class="flex items-center space-x-4">
            <button
              phx-click="expand_all"
              class="text-sm text-indigo-600 dark:text-indigo-400 hover:text-indigo-800"
            >
              Expand All
            </button>
            <button
              phx-click="collapse_all"
              class="text-sm text-gray-600 dark:text-gray-400 hover:text-gray-800"
            >
              Collapse All
            </button>
          </div>
        </div>

        <!-- Stats Cards -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <.stat_card label="Total Models" value={@stats[:total_components] || length(@models)} />
          <.stat_card label="Safe" value={@stats[:by_scan_status]["safe"] || 0} color="green" />
          <.stat_card label="Threats" value={@stats[:by_scan_status]["threats"] || 0} color="red" />
          <.stat_card label="Unscanned" value={@stats[:by_scan_status]["unscanned"] || count_unscanned(@models)} color="gray" />
        </div>

        <!-- Filter Bar -->
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4 mb-6">
          <form phx-change="filter" class="grid grid-cols-1 md:grid-cols-5 gap-4">
            <!-- Search -->
            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Search</label>
              <input
                type="text"
                name="search"
                value={@filters[:search] || ""}
                placeholder="Name, path, or hostname..."
                phx-debounce="300"
                class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
              />
            </div>

            <!-- Status Filter -->
            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Status</label>
              <select
                name="status"
                class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
              >
                <option value="">All Statuses</option>
                <option value="verified" selected={@filters[:status] == "verified"}>Verified</option>
                <option value="safe" selected={@filters[:status] == "safe"}>Safe</option>
                <option value="threats" selected={@filters[:status] == "threats"}>Threats</option>
                <option value="suspicious" selected={@filters[:status] == "suspicious"}>Suspicious</option>
                <option value="unscanned" selected={@filters[:status] == "unscanned"}>Unscanned</option>
              </select>
            </div>

            <!-- Type Filter -->
            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">File Type</label>
              <select
                name="type"
                class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
              >
                <option value="">All Types</option>
                <option value="pickle" selected={@filters[:type] == "pickle"}>Pickle (.pkl, .pt, .pth)</option>
                <option value="gguf" selected={@filters[:type] == "gguf"}>GGUF (.gguf)</option>
                <option value="safetensors" selected={@filters[:type] == "safetensors"}>Safetensors (.safetensors)</option>
              </select>
            </div>

            <!-- Agent Filter -->
            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Endpoint</label>
              <select
                name="agent_id"
                class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
              >
                <option value="">All Endpoints</option>
                <%= for {hostname, models_for_host} <- @grouped_models do %>
                  <% agent_id = get_agent_id_for_hostname(hostname, models_for_host) %>
                  <option value={agent_id} selected={@filters[:agent_id] == agent_id}>
                    <%= hostname %>
                  </option>
                <% end %>
              </select>
            </div>

            <!-- Clear Filters -->
            <div class="flex items-end">
              <button
                type="button"
                phx-click="clear_filters"
                class="px-4 py-2 text-sm text-indigo-600 hover:text-indigo-800 dark:text-indigo-400"
              >
                Clear filters
              </button>
            </div>
          </form>
        </div>

        <!-- Results count -->
        <div class="mb-4 text-sm text-gray-600 dark:text-gray-400">
          Showing <%= length(@models) %> model(s)
          <%= if any_filters_active?(@filters) do %>
            (filtered)
          <% end %>
        </div>

        <!-- Bulk Actions Toolbar -->
        <%= if MapSet.size(@selected_ids) > 0 do %>
          <div class="bg-indigo-50 dark:bg-indigo-900 border border-indigo-200 dark:border-indigo-700 rounded-lg p-4 mb-4">
            <div class="flex items-center justify-between">
              <div class="flex items-center space-x-4">
                <span class="text-sm font-medium text-indigo-900 dark:text-indigo-100">
                  <%= MapSet.size(@selected_ids) %> model(s) selected
                </span>
                <button
                  phx-click="deselect_all"
                  class="text-sm text-indigo-600 dark:text-indigo-300 hover:text-indigo-800"
                >
                  Clear selection
                </button>
              </div>

              <div class="flex items-center space-x-2">
                <button
                  phx-click="scan_selected"
                  class="inline-flex items-center px-3 py-1.5 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700"
                >
                  <.icon name="hero-magnifying-glass" class="w-4 h-4 mr-1" />
                  Scan
                </button>
                <button
                  phx-click="request_bulk_quarantine"
                  class="inline-flex items-center px-3 py-1.5 border border-transparent text-sm font-medium rounded-md text-white bg-yellow-600 hover:bg-yellow-700"
                >
                  <.icon name="hero-archive-box" class="w-4 h-4 mr-1" />
                  Quarantine
                </button>
                <button
                  phx-click="request_bulk_block"
                  class="inline-flex items-center px-3 py-1.5 border border-transparent text-sm font-medium rounded-md text-white bg-red-600 hover:bg-red-700"
                >
                  <.icon name="hero-no-symbol" class="w-4 h-4 mr-1" />
                  Block
                </button>
              </div>
            </div>
          </div>
        <% end %>

        <!-- Models Table (Grouped by Endpoint) -->
        <div class="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
          <%= if length(@models) == 0 do %>
            <div class="p-8 text-center text-gray-500 dark:text-gray-400">
              <.icon name="hero-cube-transparent" class="w-12 h-12 mx-auto mb-4 text-gray-400" />
              <p class="text-lg font-medium">No AI models discovered</p>
              <p class="mt-1 text-sm">Models will appear here once agents detect AI/ML components.</p>
            </div>
          <% else %>
            <%= for {hostname, models_for_host} <- @grouped_models do %>
              <div class="border-b border-gray-200 dark:border-gray-700 last:border-b-0">
                <!-- Endpoint Header (Collapsible) -->
                <button
                  phx-click="toggle_endpoint"
                  phx-value-hostname={hostname}
                  class="w-full px-6 py-4 flex items-center justify-between bg-gray-50 dark:bg-gray-700 hover:bg-gray-100 dark:hover:bg-gray-600 transition-colors"
                >
                  <div class="flex items-center space-x-3">
                    <.icon
                      name={if MapSet.member?(@expanded_endpoints, hostname), do: "hero-chevron-down", else: "hero-chevron-right"}
                      class="w-5 h-5 text-gray-500 dark:text-gray-400"
                    />
                    <.icon name="hero-server" class="w-5 h-5 text-gray-500 dark:text-gray-400" />
                    <span class="font-medium text-gray-900 dark:text-white"><%= hostname %></span>
                    <span class="text-sm text-gray-500 dark:text-gray-400">
                      (<%= length(models_for_host) %> model<%= if length(models_for_host) != 1, do: "s" %>)
                    </span>
                  </div>
                  <div class="flex items-center space-x-2">
                    <.endpoint_status_badges models={models_for_host} known_good_hashes={@known_good_hashes} />
                  </div>
                </button>

                <!-- Models Table for this Endpoint -->
                <%= if MapSet.member?(@expanded_endpoints, hostname) do %>
                  <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                    <thead class="bg-gray-50 dark:bg-gray-900">
                      <tr>
                        <th scope="col" class="px-6 py-3 text-left w-10">
                          <input
                            type="checkbox"
                            phx-click={if all_selected_for_host?(models_for_host, @selected_ids), do: "deselect_all", else: "select_all"}
                            checked={all_selected_for_host?(models_for_host, @selected_ids)}
                            class="rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                          />
                        </th>
                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                          Model Name
                        </th>
                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                          Type
                        </th>
                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                          Path
                        </th>
                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                          Status
                        </th>
                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                          Backdoor Risk
                        </th>
                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                          Last Scanned
                        </th>
                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                          Actions
                        </th>
                      </tr>
                    </thead>
                    <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                      <%= for model <- models_for_host do %>
                        <!-- Model Row -->
                        <tr
                          class={"hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer #{if @expanded_model_id == model.id, do: "bg-blue-50 dark:bg-blue-900/20"}"}
                          phx-click="toggle_expand"
                          phx-value-id={model.id}
                        >
                          <td class="px-6 py-4 whitespace-nowrap" phx-click="toggle_selection" phx-value-id={model.id}>
                            <input
                              type="checkbox"
                              checked={MapSet.member?(@selected_ids, model.id)}
                              class="rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                              onclick="event.stopPropagation();"
                            />
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap">
                            <div class="flex items-center">
                              <.icon name="hero-cube" class="w-5 h-5 text-gray-400 mr-2" />
                              <span class="text-sm font-medium text-gray-900 dark:text-white">
                                <%= model[:name] || Path.basename(model[:path] || model[:install_path] || "Unknown") %>
                              </span>
                            </div>
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap">
                            <span class="text-sm text-gray-500 dark:text-gray-400">
                              <%= get_file_type(model) %>
                            </span>
                          </td>
                          <td class="px-6 py-4">
                            <span class="text-sm text-gray-500 dark:text-gray-400 font-mono text-xs truncate max-w-xs block">
                              <%= truncate_path(model[:path] || model[:install_path] || "N/A", 50) %>
                            </span>
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap">
                            <.status_badge status={get_display_status(model, @known_good_hashes)} />
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap">
                            <.backdoor_risk_badge
                              analysis={@backdoor_analyses[model.id]}
                              analyzing={MapSet.member?(@analyzing_ids, model.id)}
                            />
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                            <%= format_timestamp(model[:last_scanned_at]) %>
                          </td>
                          <td class="px-6 py-4 whitespace-nowrap text-sm">
                            <%= if MapSet.member?(@scanning_ids, model.id) or MapSet.member?(@analyzing_ids, model.id) or MapSet.member?(@action_in_progress, model.id) do %>
                              <span class="inline-flex items-center text-blue-600 dark:text-blue-400">
                                <svg class="animate-spin h-4 w-4 mr-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                </svg>
                                Processing...
                              </span>
                            <% else %>
                              <div class="relative inline-block text-left" x-data="{ open: false }">
                                <button
                                  x-on:click.stop="open = !open"
                                  x-on:click.away="open = false"
                                  class="inline-flex items-center px-3 py-1 border border-gray-300 dark:border-gray-600 rounded-md text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"
                                >
                                  Actions
                                  <.icon name="hero-chevron-down" class="w-4 h-4 ml-1" />
                                </button>

                                <div
                                  x-show="open"
                                  x-transition
                                  class="origin-top-right absolute right-0 mt-2 w-48 rounded-md shadow-lg bg-white dark:bg-gray-800 ring-1 ring-black ring-opacity-5 z-50"
                                  style="display: none;"
                                >
                                  <div class="py-1" role="menu">
                                    <button
                                      phx-click="scan_model"
                                      phx-value-id={model.id}
                                      x-on:click="open = false"
                                      class="block w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                                    >
                                      <.icon name="hero-magnifying-glass" class="w-4 h-4 inline mr-2" />
                                      Scan
                                    </button>

                                    <button
                                      phx-click="deep_analyze"
                                      phx-value-id={model.id}
                                      x-on:click="open = false"
                                      class="block w-full text-left px-4 py-2 text-sm text-purple-700 dark:text-purple-400 hover:bg-gray-100 dark:hover:bg-gray-700"
                                    >
                                      <.icon name="hero-cpu-chip" class="w-4 h-4 inline mr-2" />
                                      Deep Analysis
                                    </button>

                                    <%= if model[:response_status] != "quarantined" do %>
                                      <button
                                        phx-click="request_quarantine"
                                        phx-value-id={model.id}
                                        x-on:click="open = false"
                                        class="block w-full text-left px-4 py-2 text-sm text-yellow-700 dark:text-yellow-400 hover:bg-gray-100 dark:hover:bg-gray-700"
                                      >
                                        <.icon name="hero-archive-box" class="w-4 h-4 inline mr-2" />
                                        Quarantine
                                      </button>
                                    <% else %>
                                      <button
                                        phx-click="request_restore"
                                        phx-value-id={model.id}
                                        x-on:click="open = false"
                                        class="block w-full text-left px-4 py-2 text-sm text-green-700 dark:text-green-400 hover:bg-gray-100 dark:hover:bg-gray-700"
                                      >
                                        <.icon name="hero-arrow-uturn-left" class="w-4 h-4 inline mr-2" />
                                        Restore
                                      </button>
                                    <% end %>

                                    <%= if model[:response_status] != "blocked" do %>
                                      <button
                                        phx-click="request_block"
                                        phx-value-id={model.id}
                                        x-on:click="open = false"
                                        class="block w-full text-left px-4 py-2 text-sm text-red-700 dark:text-red-400 hover:bg-gray-100 dark:hover:bg-gray-700"
                                      >
                                        <.icon name="hero-no-symbol" class="w-4 h-4 inline mr-2" />
                                        Block
                                      </button>
                                    <% else %>
                                      <button
                                        phx-click="request_unblock"
                                        phx-value-id={model.id}
                                        x-on:click="open = false"
                                        class="block w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                                      >
                                        <.icon name="hero-check-circle" class="w-4 h-4 inline mr-2" />
                                        Unblock
                                      </button>
                                    <% end %>
                                  </div>
                                </div>
                              </div>
                            <% end %>
                          </td>
                        </tr>

                        <!-- Expanded Details Row -->
                        <%= if @expanded_model_id == model.id do %>
                          <tr>
                            <td colspan="8" class="px-6 py-4 bg-gray-50 dark:bg-gray-900">
                              <div class="grid grid-cols-2 gap-6">
                                <!-- Left: Model Details -->
                                <div>
                                  <h4 class="text-sm font-semibold text-gray-900 dark:text-white mb-3">Model Details</h4>
                                  <dl class="space-y-2 text-sm">
                                    <div class="flex justify-between">
                                      <dt class="text-gray-500 dark:text-gray-400">Full Path</dt>
                                      <dd class="text-gray-900 dark:text-white font-mono text-xs"><%= model[:path] || model[:install_path] || "N/A" %></dd>
                                    </div>
                                    <div class="flex justify-between">
                                      <dt class="text-gray-500 dark:text-gray-400">File Hash</dt>
                                      <dd class="text-gray-900 dark:text-white font-mono text-xs"><%= model[:file_hash] || "N/A" %></dd>
                                    </div>
                                    <div class="flex justify-between">
                                      <dt class="text-gray-500 dark:text-gray-400">Risk Score</dt>
                                      <dd class="text-gray-900 dark:text-white"><%= model[:risk_score] || 0 %>/100</dd>
                                    </div>
                                    <%= if model[:risk_factors] && length(model[:risk_factors]) > 0 do %>
                                      <div class="flex justify-between">
                                        <dt class="text-gray-500 dark:text-gray-400">Risk Factors</dt>
                                        <dd class="text-gray-900 dark:text-white">
                                          <%= for factor <- model[:risk_factors] do %>
                                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300 mr-1">
                                              <%= factor %>
                                            </span>
                                          <% end %>
                                        </dd>
                                      </div>
                                    <% end %>
                                  </dl>

                                  <!-- Threats Section (if any) -->
                                  <%= if model[:scan_result] && model[:scan_result][:threats] && length(model[:scan_result][:threats]) > 0 do %>
                                    <h4 class="text-sm font-semibold text-red-600 dark:text-red-400 mt-4 mb-2">Detected Threats</h4>
                                    <ul class="list-disc list-inside text-sm text-red-600 dark:text-red-400">
                                      <%= for threat <- model[:scan_result][:threats] do %>
                                        <li><%= threat %></li>
                                      <% end %>
                                    </ul>
                                  <% end %>
                                </div>

                                <!-- Right: Scan History -->
                                <div>
                                  <h4 class="text-sm font-semibold text-gray-900 dark:text-white mb-3">Scan History</h4>
                                  <%= if length(@scan_history) > 0 do %>
                                    <table class="min-w-full text-sm">
                                      <thead>
                                        <tr class="text-left text-gray-500 dark:text-gray-400">
                                          <th class="pb-2">Timestamp</th>
                                          <th class="pb-2">Status</th>
                                          <th class="pb-2">Score</th>
                                          <th class="pb-2">Duration</th>
                                        </tr>
                                      </thead>
                                      <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                                        <%= for scan <- @scan_history do %>
                                          <tr>
                                            <td class="py-2 text-gray-900 dark:text-white"><%= format_timestamp(scan.scanned_at) %></td>
                                            <td class="py-2">
                                              <.status_badge status={scan.scan_status} />
                                            </td>
                                            <td class="py-2 text-gray-900 dark:text-white"><%= scan.threat_score || "N/A" %></td>
                                            <td class="py-2 text-gray-500"><%= format_duration(scan.scan_duration_ms) %></td>
                                          </tr>
                                        <% end %>
                                      </tbody>
                                    </table>
                                  <% else %>
                                    <p class="text-gray-500 dark:text-gray-400 text-sm">No scan history available</p>
                                  <% end %>
                                </div>
                              </div>

                              <!-- Backdoor Analysis Section -->
                              <div class="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                                <div x-data="{ analysisOpen: false }">
                                  <button
                                    x-on:click="analysisOpen = !analysisOpen"
                                    class="flex items-center justify-between w-full text-left"
                                  >
                                    <h4 class="text-sm font-semibold text-gray-900 dark:text-white flex items-center">
                                      <.icon name="hero-cpu-chip" class="w-4 h-4 mr-2 text-purple-500" />
                                      Backdoor Analysis
                                      <%= if @current_chart_data do %>
                                        <span class={"ml-2 px-2 py-0.5 rounded text-xs #{score_badge_class(@current_chart_data.scores.combined)}"}>
                                          Score: <%= Float.round((@current_chart_data.scores.combined || 0) * 100, 1) %>%
                                        </span>
                                      <% end %>
                                    </h4>
                                    <.icon
                                      name="hero-chevron-down"
                                      x-bind:class="analysisOpen ? 'rotate-180' : ''"
                                      class="w-4 h-4 text-gray-500 transition-transform"
                                    />
                                  </button>

                                  <div x-show="analysisOpen" x-collapse class="mt-4">
                                    <%= if @current_chart_data do %>
                                      <!-- Score Summary -->
                                      <div class="grid grid-cols-3 gap-4 mb-4">
                                        <div class="bg-gray-50 dark:bg-gray-800 rounded p-3 text-center">
                                          <p class="text-xs text-gray-500 dark:text-gray-400">Weight Score</p>
                                          <p class={"text-lg font-bold #{score_text_class(@current_chart_data.scores.weight)}"}>
                                            <%= Float.round((@current_chart_data.scores.weight || 0) * 100, 1) %>%
                                          </p>
                                        </div>
                                        <div class="bg-gray-50 dark:bg-gray-800 rounded p-3 text-center">
                                          <p class="text-xs text-gray-500 dark:text-gray-400">Spectral Score</p>
                                          <p class={"text-lg font-bold #{score_text_class(@current_chart_data.scores.spectral)}"}>
                                            <%= Float.round((@current_chart_data.scores.spectral || 0) * 100, 1) %>%
                                          </p>
                                        </div>
                                        <div class="bg-gray-50 dark:bg-gray-800 rounded p-3 text-center">
                                          <p class="text-xs text-gray-500 dark:text-gray-400">Combined Risk</p>
                                          <p class={"text-lg font-bold #{score_text_class(@current_chart_data.scores.combined)}"}>
                                            <%= Float.round((@current_chart_data.scores.combined || 0) * 100, 1) %>%
                                          </p>
                                        </div>
                                      </div>

                                      <!-- Charts Side by Side -->
                                      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                                        <div>
                                          <.weight_distribution_chart data={@current_chart_data.weight_chart} />
                                        </div>
                                        <div>
                                          <.spectral_chart data={@current_chart_data.spectral_chart} />
                                        </div>
                                      </div>

                                      <!-- Outlier Layers List -->
                                      <%= if length(@current_chart_data.outlier_layers || []) > 0 do %>
                                        <div class="mt-4 p-3 bg-red-50 dark:bg-red-900/20 rounded border border-red-200 dark:border-red-800">
                                          <h5 class="text-xs font-semibold text-red-700 dark:text-red-400 mb-2">
                                            Suspicious Layers Detected
                                          </h5>
                                          <ul class="list-disc list-inside text-xs text-red-600 dark:text-red-400">
                                            <%= for layer <- @current_chart_data.outlier_layers do %>
                                              <li><%= layer %></li>
                                            <% end %>
                                          </ul>
                                        </div>
                                      <% end %>
                                    <% else %>
                                      <div class="text-center py-6 text-gray-500 dark:text-gray-400">
                                        <.icon name="hero-cpu-chip" class="w-8 h-8 mx-auto mb-2 opacity-50" />
                                        <p class="text-sm">No backdoor analysis available</p>
                                        <p class="text-xs mt-1">Click "Deep Analysis" in the Actions menu to analyze this model</p>
                                      </div>
                                    <% end %>
                                  </div>
                                </div>
                              </div>
                            </td>
                          </tr>
                        <% end %>
                      <% end %>
                    </tbody>
                  </table>
                <% end %>
              </div>
            <% end %>
          <% end %>
        </div>

        <!-- Confirmation Modal -->
        <%= if @show_confirm_modal do %>
          <div class="fixed inset-0 z-50 overflow-y-auto" aria-labelledby="modal-title" role="dialog" aria-modal="true">
            <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
              <!-- Background overlay -->
              <div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" phx-click="cancel_action"></div>

              <!-- Modal panel -->
              <div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
                <div class="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                  <div class="sm:flex sm:items-start">
                    <div class={"mx-auto flex-shrink-0 flex items-center justify-center h-12 w-12 rounded-full sm:mx-0 sm:h-10 sm:w-10 #{modal_icon_bg(@show_confirm_modal.action)}"}>
                      <.icon name={modal_icon(@show_confirm_modal.action)} class={"h-6 w-6 #{modal_icon_color(@show_confirm_modal.action)}"} />
                    </div>
                    <div class="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left">
                      <h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white" id="modal-title">
                        <%= modal_title(@show_confirm_modal) %>
                      </h3>
                      <div class="mt-2">
                        <p class="text-sm text-gray-500 dark:text-gray-400">
                          <%= modal_description(@show_confirm_modal) %>
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
                <div class="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
                  <button
                    type="button"
                    phx-click="confirm_action"
                    class={"w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 text-base font-medium text-white focus:outline-none focus:ring-2 focus:ring-offset-2 sm:ml-3 sm:w-auto sm:text-sm #{modal_confirm_button_class(@show_confirm_modal.action)}"}
                  >
                    <%= modal_confirm_text(@show_confirm_modal.action) %>
                  </button>
                  <button
                    type="button"
                    phx-click="cancel_action"
                    class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 dark:border-gray-600 shadow-sm px-4 py-2 bg-white dark:bg-gray-800 text-base font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            </div>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  # ------------------------------------------------------------------
  # Function Components
  # ------------------------------------------------------------------

  defp stat_card(assigns) do
    color_class = case assigns[:color] do
      "green" -> "text-green-600 dark:text-green-400"
      "red" -> "text-red-600 dark:text-red-400"
      "yellow" -> "text-yellow-600 dark:text-yellow-400"
      _ -> "text-gray-900 dark:text-white"
    end

    assigns = assign(assigns, :color_class, color_class)

    ~H"""
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
      <p class="text-sm text-gray-500 dark:text-gray-400"><%= @label %></p>
      <p class={"text-2xl font-bold #{@color_class}"}><%= @value %></p>
    </div>
    """
  end

  defp status_badge(assigns) do
    {bg_class, text, icon} = case assigns.status do
      "verified" -> {
        "bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-300",
        "Verified",
        "hero-shield-check"
      }
      "safe" -> {"bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300", "Safe", nil}
      "threats" -> {"bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300", "Threats", nil}
      "suspicious" -> {"bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300", "Suspicious", nil}
      "scanning" -> {"bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300", "Scanning", nil}
      "error" -> {"bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300", "Error", nil}
      "quarantined" -> {"bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300", "Quarantined", nil}
      "blocked" -> {"bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300", "Blocked", nil}
      _ -> {"bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300", "Unscanned", nil}
    end

    assigns = assigns
    |> assign(:bg_class, bg_class)
    |> assign(:text, text)
    |> assign(:icon, icon)

    ~H"""
    <span class={"inline-flex items-center px-2 py-0.5 rounded text-xs font-medium #{@bg_class}"}>
      <%= if @icon do %>
        <.icon name={@icon} class="w-3 h-3 mr-1" />
      <% end %>
      <%= @text %>
    </span>
    """
  end

  defp backdoor_risk_badge(assigns) do
    cond do
      # Show spinner if currently analyzing
      assigns[:analyzing] ->
        ~H"""
        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-300">
          <svg class="animate-spin h-3 w-3 mr-1" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          Analyzing...
        </span>
        """

      # Show risk badge if analysis exists
      assigns[:analysis] && (assigns[:analysis].backdoor_score || assigns[:analysis][:backdoor_score]) ->
        analysis = assigns[:analysis]
        score = analysis.backdoor_score || analysis[:backdoor_score] || 0.0

        {bg_class, label} = cond do
          score < 0.3 -> {"bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300", "Low"}
          score < 0.6 -> {"bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300", "Medium"}
          score < 0.8 -> {"bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300", "High"}
          true -> {"bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300", "Critical"}
        end

        assigns = assigns
        |> assign(:bg_class, bg_class)
        |> assign(:label, label)
        |> assign(:score, score)

        ~H"""
        <span class={"inline-flex items-center px-2 py-0.5 rounded text-xs font-medium #{@bg_class}"}>
          <.icon name="hero-shield-exclamation" class="w-3 h-3 mr-1" />
          <%= @label %> (<%= Float.round(@score * 100, 1) %>%)
        </span>
        """

      # No analysis yet
      true ->
        ~H"""
        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400">
          Not Analyzed
        </span>
        """
    end
  end

  defp endpoint_status_badges(assigns) do
    models = assigns.models
    known_good = assigns[:known_good_hashes] || MapSet.new()

    verified_count = Enum.count(models, fn m ->
      m[:file_hash] && MapSet.member?(known_good, m[:file_hash])
    end)
    safe_count = Enum.count(models, fn m ->
      m[:scan_status] == "safe" && !MapSet.member?(known_good, m[:file_hash] || "")
    end)
    threat_count = Enum.count(models, &(&1[:scan_status] == "threats"))
    unscanned_count = Enum.count(models, &(&1[:scan_status] in [nil, "unscanned"]))

    assigns = assigns
    |> assign(:verified_count, verified_count)
    |> assign(:safe_count, safe_count)
    |> assign(:threat_count, threat_count)
    |> assign(:unscanned_count, unscanned_count)

    ~H"""
    <div class="flex items-center space-x-2">
      <%= if @verified_count > 0 do %>
        <span class="px-2 py-0.5 rounded text-xs font-medium bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-300">
          <.icon name="hero-shield-check" class="w-3 h-3 inline mr-1" />
          <%= @verified_count %> verified
        </span>
      <% end %>
      <%= if @safe_count > 0 do %>
        <span class="px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300">
          <%= @safe_count %> safe
        </span>
      <% end %>
      <%= if @threat_count > 0 do %>
        <span class="px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300">
          <%= @threat_count %> threats
        </span>
      <% end %>
      <%= if @unscanned_count > 0 do %>
        <span class="px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300">
          <%= @unscanned_count %> unscanned
        </span>
      <% end %>
    </div>
    """
  end

  # Weight distribution bar chart component
  defp weight_distribution_chart(assigns) do
    chart_data = assigns[:data] || []

    if Enum.empty?(chart_data) do
      assigns = assign(assigns, :empty, true)

      ~H"""
      <div class="text-sm text-gray-500 dark:text-gray-400">
        No weight analysis data available
      </div>
      """
    else
      assigns = assign(assigns, :chart_data, chart_data)

      ~H"""
      <div class="space-y-2">
        <h5 class="text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wide">
          Weight Distribution Anomaly by Layer
        </h5>
        <div class="space-y-1">
          <%= for layer <- @chart_data do %>
            <div class="flex items-center gap-2 text-xs">
              <span class="w-24 truncate text-gray-600 dark:text-gray-400" title={layer[:full_name] || layer.name}>
                <%= layer.name %>
              </span>
              <div class="flex-1 bg-gray-200 dark:bg-gray-700 rounded h-3 overflow-hidden">
                <div
                  class={"h-3 rounded transition-all #{if layer.is_outlier, do: "bg-red-500", else: "bg-blue-500"}"}
                  style={"width: #{min(layer.score * 100, 100)}%"}
                >
                </div>
              </div>
              <span class={"w-10 text-right font-mono #{if layer.is_outlier, do: "text-red-600 dark:text-red-400 font-bold", else: "text-gray-600 dark:text-gray-400"}"}>
                <%= Float.round(layer.score || 0.0, 2) %>
              </span>
              <%= if layer.is_outlier do %>
                <span class="text-red-500" title="Outlier">*</span>
              <% end %>
            </div>
          <% end %>
        </div>
        <p class="text-xs text-gray-500 dark:text-gray-400 mt-2">
          * Outlier layers (z-score > 3.0) may indicate backdoor poisoning
        </p>
      </div>
      """
    end
  end

  # Singular value spectrum chart component
  defp spectral_chart(assigns) do
    chart_data = assigns[:data] || []

    if Enum.empty?(chart_data) do
      assigns = assign(assigns, :empty, true)

      ~H"""
      <div class="text-sm text-gray-500 dark:text-gray-400">
        No spectral analysis data available
      </div>
      """
    else
      assigns = assign(assigns, :chart_data, chart_data)

      ~H"""
      <div class="space-y-3">
        <h5 class="text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wide">
          Singular Value Spectrum by Layer
        </h5>
        <%= for layer <- @chart_data do %>
          <div class="border border-gray-200 dark:border-gray-700 rounded p-2">
            <div class="flex items-center justify-between mb-1">
              <span class="text-xs font-medium text-gray-700 dark:text-gray-300" title={layer[:full_name] || layer.name}>
                <%= layer.name %>
              </span>
              <span class={"text-xs font-mono #{if layer.score > 0.5, do: "text-red-600 dark:text-red-400", else: "text-gray-600 dark:text-gray-400"}"}>
                Score: <%= Float.round(layer.score || 0.0, 2) %>
              </span>
            </div>
            <%= if length(layer.singular_values || []) > 0 do %>
              <% max_sv = Enum.max(layer.singular_values, fn -> 1 end) %>
              <div class="flex items-end gap-0.5 h-12">
                <%= for {sv, idx} <- Enum.with_index(layer.singular_values) do %>
                  <% is_outlier = idx in (layer.sv_outlier_indices || []) %>
                  <% height_pct = if max_sv > 0, do: (sv / max_sv) * 100, else: 0 %>
                  <div
                    class={"flex-1 rounded-t transition-all #{if is_outlier, do: "bg-red-500", else: "bg-purple-500"}"}
                    style={"height: #{height_pct}%"}
                    title={"SV#{idx}: #{Float.round(sv * 1.0, 3)}#{if is_outlier, do: " (outlier)", else: ""}"}
                  >
                  </div>
                <% end %>
              </div>
              <%= if length(layer.sv_outlier_indices || []) > 0 do %>
                <p class="text-xs text-red-500 mt-1">
                  Outlier SVs at indices: <%= Enum.join(layer.sv_outlier_indices, ", ") %>
                </p>
              <% end %>
            <% else %>
              <p class="text-xs text-gray-400 italic">No singular values available</p>
            <% end %>
          </div>
        <% end %>
        <p class="text-xs text-gray-500 dark:text-gray-400">
          Dominant singular values (red) may indicate backdoor neurons
        </p>
      </div>
      """
    end
  end

  # Score badge class helper for backdoor analysis panel
  defp score_badge_class(score) when is_number(score) do
    cond do
      score < 0.3 -> "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300"
      score < 0.6 -> "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300"
      score < 0.8 -> "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300"
      true -> "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300"
    end
  end

  defp score_badge_class(_), do: "bg-gray-100 text-gray-800"

  # Score text class helper for individual score displays
  defp score_text_class(score) when is_number(score) do
    cond do
      score < 0.3 -> "text-green-600 dark:text-green-400"
      score < 0.6 -> "text-yellow-600 dark:text-yellow-400"
      score < 0.8 -> "text-orange-600 dark:text-orange-400"
      true -> "text-red-600 dark:text-red-400"
    end
  end

  defp score_text_class(_), do: "text-gray-600 dark:text-gray-400"

  # ------------------------------------------------------------------
  # Private Helpers
  # ------------------------------------------------------------------

  defp group_by_endpoint(models) do
    models
    |> Enum.group_by(fn model -> model[:hostname] || "Unknown" end)
    |> Enum.sort_by(fn {hostname, _} -> hostname end)
  end

  # Modal helper functions
  defp modal_title(%{action: :quarantine, model_id: _}), do: "Quarantine Model"
  defp modal_title(%{action: :block, model_id: _}), do: "Block Model"
  defp modal_title(%{action: :restore, model_id: _}), do: "Restore Model"
  defp modal_title(%{action: :bulk_quarantine, model_ids: ids}), do: "Quarantine #{length(ids)} Models"
  defp modal_title(%{action: :bulk_block, model_ids: ids}), do: "Block #{length(ids)} Models"
  defp modal_title(_), do: "Confirm Action"

  defp modal_description(%{action: :quarantine, model_id: id}) do
    "Are you sure you want to quarantine model #{id}? The model will be moved to an encrypted vault and cannot be executed."
  end
  defp modal_description(%{action: :block, model_id: id}) do
    "Are you sure you want to block model #{id}? The model will be prevented from loading or executing."
  end
  defp modal_description(%{action: :restore, model_id: id}) do
    "Are you sure you want to restore model #{id}? This will move the model back to its original location. A re-scan will be performed after restoration."
  end
  defp modal_description(%{action: :bulk_quarantine, model_ids: ids}) do
    "Are you sure you want to quarantine #{length(ids)} models? They will be moved to encrypted vaults and cannot be executed."
  end
  defp modal_description(%{action: :bulk_block, model_ids: ids}) do
    "Are you sure you want to block #{length(ids)} models? They will be prevented from loading or executing."
  end
  defp modal_description(_), do: "Are you sure you want to proceed?"

  defp modal_icon(:quarantine), do: "hero-archive-box"
  defp modal_icon(:bulk_quarantine), do: "hero-archive-box"
  defp modal_icon(:block), do: "hero-no-symbol"
  defp modal_icon(:bulk_block), do: "hero-no-symbol"
  defp modal_icon(:restore), do: "hero-arrow-uturn-left"
  defp modal_icon(_), do: "hero-exclamation-triangle"

  defp modal_icon_bg(:quarantine), do: "bg-yellow-100 dark:bg-yellow-900"
  defp modal_icon_bg(:bulk_quarantine), do: "bg-yellow-100 dark:bg-yellow-900"
  defp modal_icon_bg(:block), do: "bg-red-100 dark:bg-red-900"
  defp modal_icon_bg(:bulk_block), do: "bg-red-100 dark:bg-red-900"
  defp modal_icon_bg(:restore), do: "bg-green-100 dark:bg-green-900"
  defp modal_icon_bg(_), do: "bg-yellow-100 dark:bg-yellow-900"

  defp modal_icon_color(:quarantine), do: "text-yellow-600 dark:text-yellow-400"
  defp modal_icon_color(:bulk_quarantine), do: "text-yellow-600 dark:text-yellow-400"
  defp modal_icon_color(:block), do: "text-red-600 dark:text-red-400"
  defp modal_icon_color(:bulk_block), do: "text-red-600 dark:text-red-400"
  defp modal_icon_color(:restore), do: "text-green-600 dark:text-green-400"
  defp modal_icon_color(_), do: "text-yellow-600 dark:text-yellow-400"

  defp modal_confirm_button_class(:quarantine), do: "bg-yellow-600 hover:bg-yellow-700 focus:ring-yellow-500"
  defp modal_confirm_button_class(:bulk_quarantine), do: "bg-yellow-600 hover:bg-yellow-700 focus:ring-yellow-500"
  defp modal_confirm_button_class(:block), do: "bg-red-600 hover:bg-red-700 focus:ring-red-500"
  defp modal_confirm_button_class(:bulk_block), do: "bg-red-600 hover:bg-red-700 focus:ring-red-500"
  defp modal_confirm_button_class(:restore), do: "bg-green-600 hover:bg-green-700 focus:ring-green-500"
  defp modal_confirm_button_class(_), do: "bg-indigo-600 hover:bg-indigo-700 focus:ring-indigo-500"

  defp modal_confirm_text(:quarantine), do: "Quarantine"
  defp modal_confirm_text(:bulk_quarantine), do: "Quarantine All"
  defp modal_confirm_text(:block), do: "Block"
  defp modal_confirm_text(:bulk_block), do: "Block All"
  defp modal_confirm_text(:restore), do: "Restore"
  defp modal_confirm_text(_), do: "Confirm"

  defp build_filters(params) do
    %{}
    |> maybe_add_filter(:status, params["status"])
    |> maybe_add_filter(:type, params["type"])
    |> maybe_add_filter(:agent_id, params["agent_id"])
    |> maybe_add_filter(:search, params["search"])
  end

  defp maybe_add_filter(filters, _key, nil), do: filters
  defp maybe_add_filter(filters, _key, ""), do: filters
  defp maybe_add_filter(filters, key, value), do: Map.put(filters, key, value)

  defp apply_filters(socket, filters) do
    all_models = try do
      case AIInventory.list_inventory(limit: 500) do
        {:ok, inventory} -> inventory
        _ -> socket.assigns[:models] || []
      end
    catch
      _kind, _reason -> socket.assigns[:models] || []
    end

    known_good_hashes = load_known_good_hashes(all_models)

    filtered = all_models
    |> filter_by_status(filters[:status], known_good_hashes)
    |> filter_by_type(filters[:type])
    |> filter_by_agent(filters[:agent_id])
    |> filter_by_search(filters[:search])

    grouped = group_by_endpoint(filtered)

    socket
    |> assign(:models, filtered)
    |> assign(:grouped_models, grouped)
    |> assign(:known_good_hashes, known_good_hashes)
    |> assign(:filters, filters)
  end

  defp filter_by_status(models, nil, _known_good_hashes), do: models
  defp filter_by_status(models, "verified", known_good_hashes) do
    Enum.filter(models, fn m ->
      file_hash = m[:file_hash]
      file_hash && MapSet.member?(known_good_hashes, file_hash)
    end)
  end
  defp filter_by_status(models, status, _known_good_hashes) do
    Enum.filter(models, fn m ->
      scan_status = m[:scan_status] || "unscanned"
      scan_status == status
    end)
  end

  defp filter_by_type(models, nil), do: models
  defp filter_by_type(models, type) do
    extensions = case type do
      "pickle" -> [".pkl", ".pickle", ".pt", ".pth"]
      "gguf" -> [".gguf"]
      "safetensors" -> [".safetensors"]
      _ -> []
    end

    Enum.filter(models, fn m ->
      path = m[:path] || m[:install_path] || ""
      Enum.any?(extensions, &String.ends_with?(String.downcase(path), &1))
    end)
  end

  defp filter_by_agent(models, nil), do: models
  defp filter_by_agent(models, agent_id), do: Enum.filter(models, &(&1[:agent_id] == agent_id))

  defp filter_by_search(models, nil), do: models
  defp filter_by_search(models, ""), do: models
  defp filter_by_search(models, search) do
    search_lower = String.downcase(search)
    Enum.filter(models, fn m ->
      name = String.downcase(m[:name] || "")
      path = String.downcase(m[:path] || m[:install_path] || "")
      hostname = String.downcase(m[:hostname] || "")

      String.contains?(name, search_lower) or
      String.contains?(path, search_lower) or
      String.contains?(hostname, search_lower)
    end)
  end

  defp build_path(filters) do
    query_params = filters
    |> Enum.filter(fn {_, v} -> v != nil and v != "" end)
    |> Enum.into(%{})

    if map_size(query_params) == 0 do
      ~p"/live/ai-security/models"
    else
      "/live/ai-security/models?" <> URI.encode_query(query_params)
    end
  end

  defp get_agent_id_for_hostname(_hostname, []), do: nil
  defp get_agent_id_for_hostname(_hostname, [model | _]), do: model[:agent_id]

  defp any_filters_active?(filters) do
    Enum.any?(filters, fn {_k, v} -> v != nil and v != "" end)
  end

  defp all_selected_for_host?(models, selected_ids) do
    model_ids = Enum.map(models, & &1.id) |> MapSet.new()
    MapSet.subset?(model_ids, selected_ids) and MapSet.size(model_ids) > 0
  end

  defp count_unscanned(models) do
    Enum.count(models, &(&1[:scan_status] in [nil, "unscanned"]))
  end

  defp get_file_type(model) do
    path = model[:path] || model[:install_path] || ""
    cond do
      String.ends_with?(String.downcase(path), ".gguf") -> "GGUF"
      String.ends_with?(String.downcase(path), ".safetensors") -> "Safetensors"
      String.ends_with?(String.downcase(path), ".pkl") or
        String.ends_with?(String.downcase(path), ".pickle") or
        String.ends_with?(String.downcase(path), ".pt") or
        String.ends_with?(String.downcase(path), ".pth") -> "Pickle"
      model[:component_type] -> model[:component_type]
      true -> "Unknown"
    end
  end

  defp truncate_path(path, max_length) when byte_size(path) > max_length do
    String.slice(path, 0, max_length - 3) <> "..."
  end
  defp truncate_path(path, _max_length), do: path

  defp format_timestamp(nil), do: "Never"
  defp format_timestamp(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M")
  defp format_timestamp(%NaiveDateTime{} = ndt), do: Calendar.strftime(ndt, "%Y-%m-%d %H:%M")
  defp format_timestamp(_), do: "N/A"

  defp format_duration(nil), do: "N/A"
  defp format_duration(ms) when ms < 1000, do: "#{ms}ms"
  defp format_duration(ms), do: "#{Float.round(ms / 1000, 1)}s"

  defp load_scan_history(model_id) do
    # Try to load from ScanHistory module if it exists
    try do
      TamanduaServer.AISecurity.ScanHistory.list_history(model_id, limit: 5)
    rescue
      _ -> []
    end
  end

  defp trigger_scan(model_id) do
    case AIInventory.assess_risk(model_id) do
      {:ok, %{component: model}} ->
        agent_id = model[:agent_id]
        path = model[:path] || model[:install_path]

        try do
          TamanduaServer.Agents.send_command(agent_id, %{
            type: "scan_model",
            payload: %{model_id: model_id, path: path, force: true}
          })
        rescue
          e -> {:error, e}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Returns the display status for a model, checking known-good database first
  defp get_display_status(model, known_good_hashes) do
    file_hash = model[:file_hash]

    cond do
      # Check if model hash is in known-good database
      file_hash && MapSet.member?(known_good_hashes, file_hash) ->
        "verified"

      # Response status takes precedence (quarantined, blocked, etc.)
      model[:response_status] ->
        model[:response_status]

      # Fall back to scan status
      model[:scan_status] ->
        model[:scan_status]

      # Default to unscanned
      true ->
        "unscanned"
    end
  end

  # Loads known-good hashes for the given models from the database
  defp load_known_good_hashes(models) do
    # Extract all unique file hashes from models
    hashes =
      models
      |> Enum.map(& &1[:file_hash])
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    # Return empty set if no hashes to check
    if Enum.empty?(hashes) do
      MapSet.new()
    else
      # Query known-good database for these hashes
      known =
        hashes
        |> Enum.filter(fn hash ->
          case KnownGood.is_known_good?(hash) do
            {:ok, _entry} -> true
            {:error, :not_found} -> false
          end
        end)

      MapSet.new(known)
    end
  end

  # Loads the latest backdoor analysis for each model from the database
  defp load_backdoor_analyses(models) do
    model_ids = Enum.map(models, & &1.id)

    model_ids
    |> Enum.map(fn id ->
      case BackdoorAnalysis.get_latest_analysis(id) do
        nil -> nil
        analysis -> {id, analysis}
      end
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.into(%{})
  end

  # Triggers deep backdoor analysis via ML service
  # Uses the detailed version to get per-layer data for visualization
  defp trigger_deep_analysis(model_id) do
    case AIInventory.assess_risk(model_id) do
      {:ok, %{component: model}} ->
        file_path = model[:path] || model[:install_path]

        # Use the detailed version that fetches per-layer data for charts
        case MLClient.analyze_backdoor_detailed(file_path) do
          {:ok, result} ->
            # Store the analysis result in database with detailed layer data
            attrs = %{
              model_id: model_id,
              agent_id: model[:agent_id],
              file_hash: model[:file_hash],
              weight_score: result.weight_score,
              spectral_score: result.spectral_score,
              backdoor_score: result.combined_score,
              is_suspicious: result.is_suspicious,
              weight_outlier_layers: result.weight_outlier_layers,
              spectral_outlier_layers: result.spectral_outlier_layers,
              weight_details: result[:weight_details] || %{},
              spectral_details: result[:spectral_details] || %{},
              analysis_time_ms: result.analysis_time_ms
            }

            case BackdoorAnalysis.record_analysis(attrs) do
              {:ok, record} -> {:ok, record}
              {:error, _changeset} -> {:ok, result}  # Return result even if DB fails
            end

          {:error, reason} ->
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end
end
