defmodule TamanduaServerWeb.AlertsLive do
  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Alerts

  on_mount {TamanduaServerWeb.UserAuth, :ensure_authenticated}

  @impl true
  def mount(_params, _session, socket) do
    # Extract organization_id from the authenticated current_user
    organization_id = socket.assigns.current_user.organization_id
    current_user = socket.assigns.current_user

    socket =
      socket
      |> assign(:page_title, "Alerts")
      |> assign(:organization_id, organization_id)
      |> assign(:current_user, current_user)
      |> assign(:selected_alert_ids, MapSet.new())
      |> assign(:show_bulk_actions, false)
      |> assign(:bulk_operation_in_progress, false)
      |> assign(:show_confirmation_modal, false)
      |> assign(:confirmation_action, nil)
      |> assign(:bulk_result, nil)

    {:ok, socket}
  end

  @impl true
  def handle_params(params, _url, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end

  defp apply_action(socket, :index, params) do
    filters = build_filters(params)
    sort_by = parse_sort_by(params["sort_by"])
    sort_order = parse_sort_order(params["sort_order"])
    organization_id = socket.assigns.organization_id

    alerts = Alerts.search_alerts(filters,
      sort_by: sort_by,
      sort_order: sort_order,
      limit: 100,
      organization_id: organization_id
    )

    socket
    |> assign(:page_title, "Alerts")
    |> assign(:alerts, alerts)
    |> assign(:alert, nil)
    |> assign(:filters, filters)
    |> assign(:sort_by, sort_by)
    |> assign(:sort_order, sort_order)
    |> assign(:selected_alert_ids, MapSet.new())
    |> assign(:show_bulk_actions, false)
    |> assign(:bulk_result, nil)
  end

  defp apply_action(socket, :show, %{"id" => id}) do
    # Redirect to the detailed alert view
    socket
    |> redirect(to: ~p"/alerts/detail/#{id}")
  end

  @impl true
  def handle_event("filter", params, socket) do
    filters = build_filters(params)
    path = build_path(filters, socket.assigns.sort_by, socket.assigns.sort_order)
    {:noreply, push_patch(socket, to: path)}
  end

  @impl true
  def handle_event("sort", %{"field" => field}, socket) do
    new_sort_by = parse_sort_by(field)
    new_sort_order = if socket.assigns.sort_by == new_sort_by and socket.assigns.sort_order == :asc, do: :desc, else: :asc
    path = build_path(socket.assigns.filters, new_sort_by, new_sort_order)
    {:noreply, push_patch(socket, to: path)}
  end

  @impl true
  def handle_event("clear_filters", _params, socket) do
    {:noreply, push_patch(socket, to: ~p"/alerts")}
  end

  @impl true
  def handle_event("toggle_alert_selection", %{"id" => alert_id}, socket) do
    selected = socket.assigns.selected_alert_ids

    selected =
      if MapSet.member?(selected, alert_id) do
        MapSet.delete(selected, alert_id)
      else
        MapSet.put(selected, alert_id)
      end

    {:noreply,
     socket
     |> assign(:selected_alert_ids, selected)
     |> assign(:show_bulk_actions, MapSet.size(selected) > 0)}
  end

  @impl true
  def handle_event("select_all", _params, socket) do
    all_ids = Enum.map(socket.assigns.alerts, & &1.id) |> MapSet.new()

    {:noreply,
     socket
     |> assign(:selected_alert_ids, all_ids)
     |> assign(:show_bulk_actions, MapSet.size(all_ids) > 0)}
  end

  @impl true
  def handle_event("deselect_all", _params, socket) do
    {:noreply,
     socket
     |> assign(:selected_alert_ids, MapSet.new())
     |> assign(:show_bulk_actions, false)}
  end

  @impl true
  def handle_event("bulk_action", %{"action" => action}, socket) do
    {:noreply,
     socket
     |> assign(:show_confirmation_modal, true)
     |> assign(:confirmation_action, action)}
  end

  @impl true
  def handle_event("cancel_confirmation", _params, socket) do
    {:noreply,
     socket
     |> assign(:show_confirmation_modal, false)
     |> assign(:confirmation_action, nil)}
  end

  @impl true
  def handle_event("confirm_bulk_action", params, socket) do
    action = socket.assigns.confirmation_action
    selected_ids = MapSet.to_list(socket.assigns.selected_alert_ids)

    socket =
      socket
      |> assign(:bulk_operation_in_progress, true)
      |> assign(:show_confirmation_modal, false)

    # Perform bulk operation
    result = case action do
      "update_status" ->
        status = params["status"]
        perform_bulk_status_update(selected_ids, status, socket)

      "assign" ->
        user_id = params["user_id"]
        perform_bulk_assign(selected_ids, user_id, socket)

      "delete" ->
        perform_bulk_delete(selected_ids, socket)

      "add_tags" ->
        tags = String.split(params["tags"] || "", ",") |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == ""))
        perform_bulk_add_tags(selected_ids, tags, socket)

      "remove_tags" ->
        tags = String.split(params["tags"] || "", ",") |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == ""))
        perform_bulk_remove_tags(selected_ids, tags, socket)

      _ ->
        {:error, :unknown_action}
    end

    # Reload alerts and clear selection
    filters = socket.assigns.filters
    sort_by = socket.assigns.sort_by
    sort_order = socket.assigns.sort_order
    organization_id = socket.assigns.organization_id

    alerts = Alerts.search_alerts(filters,
      sort_by: sort_by,
      sort_order: sort_order,
      limit: 100,
      organization_id: organization_id
    )

    {:noreply,
     socket
     |> assign(:alerts, alerts)
     |> assign(:selected_alert_ids, MapSet.new())
     |> assign(:show_bulk_actions, false)
     |> assign(:bulk_operation_in_progress, false)
     |> assign(:bulk_result, result)
     |> put_flash_for_result(result)}
  end

  defp perform_bulk_status_update(alert_ids, status, socket) do
    organization_id = socket.assigns.organization_id

    case Alerts.bulk_update_status(alert_ids, status, organization_id: organization_id) do
      {:ok, count} ->
        # Audit log
        Alerts.bulk_update(alert_ids, %{status: status}, organization_id: organization_id)
        {:ok, %{action: :status_update, count: count}}
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp perform_bulk_assign(alert_ids, user_id, socket) do
    organization_id = socket.assigns.organization_id

    case Alerts.bulk_assign(alert_ids, user_id, organization_id: organization_id) do
      {:ok, count} ->
        {:ok, %{action: :assign, count: count}}
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp perform_bulk_delete(alert_ids, socket) do
    user = socket.assigns.current_user
    organization_id = socket.assigns.organization_id

    case Alerts.bulk_delete(alert_ids, user, organization_id: organization_id) do
      {:ok, count} ->
        {:ok, %{action: :delete, count: count}}
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp perform_bulk_add_tags(alert_ids, tags, socket) do
    user = socket.assigns.current_user
    organization_id = socket.assigns.organization_id

    case Alerts.bulk_add_tags(alert_ids, tags, user, organization_id: organization_id) do
      {:ok, count} ->
        {:ok, %{action: :add_tags, count: count, tags: tags}}
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp perform_bulk_remove_tags(alert_ids, tags, socket) do
    user = socket.assigns.current_user
    organization_id = socket.assigns.organization_id

    case Alerts.bulk_remove_tags(alert_ids, tags, user, organization_id: organization_id) do
      {:ok, count} ->
        {:ok, %{action: :remove_tags, count: count, tags: tags}}
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp put_flash_for_result(socket, {:ok, %{action: action, count: count} = result}) do
    message = case action do
      :status_update -> "Successfully updated #{count} alert(s)"
      :assign -> "Successfully assigned #{count} alert(s)"
      :delete -> "Successfully deleted #{count} alert(s)"
      :add_tags -> "Successfully added tags to #{count} alert(s): #{Enum.join(result[:tags] || [], ", ")}"
      :remove_tags -> "Successfully removed tags from #{count} alert(s): #{Enum.join(result[:tags] || [], ", ")}"
      _ -> "Operation completed: #{count} alert(s) affected"
    end

    put_flash(socket, :info, message)
  end

  defp put_flash_for_result(socket, {:error, reason}) do
    put_flash(socket, :error, "Operation failed: #{inspect(reason)}")
  end

  defp put_flash_for_result(socket, _), do: socket

  defp build_filters(params) do
    %{}
    |> maybe_add_filter(:severity, params["severity"])
    |> maybe_add_filter(:status, params["status"])
    |> maybe_add_filter(:search, params["search"])
    |> maybe_add_filter(:date_from, params["date_from"])
    |> maybe_add_filter(:date_to, params["date_to"])
    |> maybe_add_filter(:mitre_technique, params["mitre_technique"])
    |> maybe_add_filter(:patch_pattern, params["patch_pattern"])
    |> maybe_add_filter(:target_function, params["target_function"])
    |> maybe_add_filter(:verdict, params["verdict"])
  end

  defp maybe_add_filter(filters, _key, nil), do: filters
  defp maybe_add_filter(filters, _key, ""), do: filters
  defp maybe_add_filter(filters, key, value), do: Map.put(filters, key, value)

  defp parse_sort_by(:severity), do: :severity
  defp parse_sort_by(:status), do: :status
  defp parse_sort_by(:inserted_at), do: :inserted_at
  defp parse_sort_by("severity"), do: :severity
  defp parse_sort_by("status"), do: :status
  defp parse_sort_by("inserted_at"), do: :inserted_at
  defp parse_sort_by(_), do: :inserted_at

  defp parse_sort_order(:asc), do: :asc
  defp parse_sort_order(:desc), do: :desc
  defp parse_sort_order("asc"), do: :asc
  defp parse_sort_order("desc"), do: :desc
  defp parse_sort_order(_), do: :desc

  defp build_path(filters, sort_by, sort_order) do
    query_params =
      filters
      |> Map.put(:sort_by, sort_by)
      |> Map.put(:sort_order, sort_order)
      |> Enum.filter(fn {_, v} -> v != nil and v != "" end)
      |> Enum.into(%{})

    if map_size(query_params) == 0 do
      ~p"/alerts"
    else
      ~p"/alerts?#{query_params}"
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-2xl font-bold"><%= @page_title %></h1>
        <%= if @live_action == :show do %>
          <.link navigate={~p"/alerts"} class="text-blue-600 hover:underline">
            &larr; Back to Alerts
          </.link>
        <% end %>
      </div>

      <%= if @live_action == :index do %>
        <!-- Search and Filter Form -->
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4 mb-6">
          <form phx-change="filter" class="grid grid-cols-1 md:grid-cols-5 gap-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Search</label>
              <input
                type="text"
                name="search"
                value={Map.get(@filters, :search, "")}
                placeholder="Search title or description..."
                class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
              />
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Severity</label>
              <select
                name="severity"
                class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
              >
                <option value="">All Severities</option>
                <option value="critical" selected={Map.get(@filters, :severity) == "critical"}>Critical</option>
                <option value="high" selected={Map.get(@filters, :severity) == "high"}>High</option>
                <option value="medium" selected={Map.get(@filters, :severity) == "medium"}>Medium</option>
                <option value="low" selected={Map.get(@filters, :severity) == "low"}>Low</option>
              </select>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Status</label>
              <select
                name="status"
                class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
              >
                <option value="">All Statuses</option>
                <option value="new" selected={Map.get(@filters, :status) == "new"}>New</option>
                <option value="investigating" selected={Map.get(@filters, :status) == "investigating"}>Investigating</option>
                <option value="resolved" selected={Map.get(@filters, :status) == "resolved"}>Resolved</option>
                <option value="false_positive" selected={Map.get(@filters, :status) == "false_positive"}>False Positive</option>
              </select>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Verdict</label>
              <select
                name="verdict"
                class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
              >
                <option value="">All Verdicts</option>
                <option value="unconfirmed" selected={Map.get(@filters, :verdict) == "unconfirmed"}>Unconfirmed</option>
                <option value="true_positive" selected={Map.get(@filters, :verdict) == "true_positive"}>True Positive</option>
                <option value="false_positive" selected={Map.get(@filters, :verdict) == "false_positive"}>False Positive</option>
                <option value="benign" selected={Map.get(@filters, :verdict) == "benign"}>Benign</option>
                <option value="suspicious" selected={Map.get(@filters, :verdict) == "suspicious"}>Suspicious</option>
              </select>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">From Date</label>
              <input
                type="date"
                name="date_from"
                value={Map.get(@filters, :date_from, "")}
                class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
              />
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">To Date</label>
              <input
                type="date"
                name="date_to"
                value={Map.get(@filters, :date_to, "")}
                class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
              />
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">MITRE Technique</label>
              <select
                name="mitre_technique"
                class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
              >
                <option value="">All Techniques</option>
                <option value="T1562.006" selected={Map.get(@filters, :mitre_technique) == "T1562.006"}>T1562.006 - ETW Tampering</option>
                <option value="T1059.001" selected={Map.get(@filters, :mitre_technique) == "T1059.001"}>T1059.001 - PowerShell</option>
                <option value="T1055" selected={Map.get(@filters, :mitre_technique) == "T1055"}>T1055 - Process Injection</option>
              </select>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">ETW Patch Pattern</label>
              <select
                name="patch_pattern"
                class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
              >
                <option value="">All Patterns</option>
                <option value="ret" selected={Map.get(@filters, :patch_pattern) == "ret"}>RET (0xC3)</option>
                <option value="xor_eax_ret" selected={Map.get(@filters, :patch_pattern) == "xor_eax_ret"}>XOR EAX, EAX; RET</option>
                <option value="jmp_rel32" selected={Map.get(@filters, :patch_pattern) == "jmp_rel32"}>JMP rel32</option>
                <option value="jmp_abs" selected={Map.get(@filters, :patch_pattern) == "jmp_abs"}>JMP absolute</option>
                <option value="nop_sled" selected={Map.get(@filters, :patch_pattern) == "nop_sled"}>NOP sled</option>
              </select>
            </div>
          </form>
          <div class="mt-4">
            <button
              phx-click="clear_filters"
              class="text-sm text-indigo-600 hover:text-indigo-800 dark:text-indigo-400"
            >
              Clear all filters
            </button>
          </div>
        </div>

        <!-- Bulk Actions Toolbar -->
        <%= if @show_bulk_actions do %>
          <div class="bg-indigo-50 dark:bg-indigo-900 border border-indigo-200 dark:border-indigo-700 rounded-lg p-4 mb-4">
            <div class="flex items-center justify-between">
              <div class="flex items-center space-x-4">
                <span class="text-sm font-medium text-indigo-900 dark:text-indigo-100">
                  <%= MapSet.size(@selected_alert_ids) %> alert(s) selected
                </span>
                <button
                  phx-click="deselect_all"
                  class="text-sm text-indigo-600 dark:text-indigo-300 hover:text-indigo-800 dark:hover:text-indigo-100"
                >
                  Clear selection
                </button>
              </div>

              <div class="flex items-center space-x-2">
                <%= if @bulk_operation_in_progress do %>
                  <div class="flex items-center space-x-2 text-indigo-700 dark:text-indigo-300">
                    <svg class="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                      <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    <span class="text-sm">Processing...</span>
                  </div>
                <% else %>
                  <button
                    phx-click="bulk_action"
                    phx-value-action="update_status"
                    class="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                  >
                    Update Status
                  </button>

                  <button
                    phx-click="bulk_action"
                    phx-value-action="assign"
                    class="inline-flex items-center px-3 py-2 border border-gray-300 dark:border-gray-600 text-sm leading-4 font-medium rounded-md text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                  >
                    Assign
                  </button>

                  <button
                    phx-click="bulk_action"
                    phx-value-action="add_tags"
                    class="inline-flex items-center px-3 py-2 border border-gray-300 dark:border-gray-600 text-sm leading-4 font-medium rounded-md text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                  >
                    Add Tags
                  </button>

                  <button
                    phx-click="bulk_action"
                    phx-value-action="remove_tags"
                    class="inline-flex items-center px-3 py-2 border border-gray-300 dark:border-gray-600 text-sm leading-4 font-medium rounded-md text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                  >
                    Remove Tags
                  </button>

                  <button
                    phx-click="bulk_action"
                    phx-value-action="delete"
                    class="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
                  >
                    Delete
                  </button>
                <% end %>
              </div>
            </div>
          </div>
        <% end %>

        <div class="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
          <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead class="bg-gray-50 dark:bg-gray-700">
              <tr>
                <th scope="col" class="px-6 py-3 text-left">
                  <input
                    type="checkbox"
                    phx-click={if MapSet.size(@selected_alert_ids) == length(@alerts) and length(@alerts) > 0, do: "deselect_all", else: "select_all"}
                    checked={MapSet.size(@selected_alert_ids) == length(@alerts) and length(@alerts) > 0}
                    class="rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                  />
                </th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer" phx-click="sort" phx-value-field="severity">
                  Severity
                  <%= if @sort_by == :severity do %>
                    <span class="ml-1"><%= if @sort_order == :asc, do: "▲", else: "▼" %></span>
                  <% end %>
                </th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Title</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer" phx-click="sort" phx-value-field="status">
                  Status
                  <%= if @sort_by == :status do %>
                    <span class="ml-1"><%= if @sort_order == :asc, do: "▲", else: "▼" %></span>
                  <% end %>
                </th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer" phx-click="sort" phx-value-field="inserted_at">
                  Created At
                  <%= if @sort_by == :inserted_at do %>
                    <span class="ml-1"><%= if @sort_order == :asc, do: "▲", else: "▼" %></span>
                  <% end %>
                </th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              <%= for alert <- @alerts do %>
                <tr class={if MapSet.member?(@selected_alert_ids, alert.id), do: "bg-indigo-50 dark:bg-indigo-900", else: ""}>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <input
                      type="checkbox"
                      phx-click="toggle_alert_selection"
                      phx-value-id={alert.id}
                      checked={MapSet.member?(@selected_alert_ids, alert.id)}
                      class="rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                    />
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <span class={"px-2 inline-flex text-xs leading-5 font-semibold rounded-full #{severity_color(alert.severity)}"}>
                      <%= alert.severity %>
                    </span>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <div class="flex items-center gap-2">
                      <div class="text-sm font-medium text-gray-900 dark:text-white"><%= alert.title %></div>
                      <%= if alert.blockchain_tx_id do %>
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300"
                              title={"Attested: #{alert.blockchain_tx_id}"}>
                          <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                            <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                          </svg>
                          On-Chain
                        </span>
                      <% end %>
                    </div>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <span class={"px-2 inline-flex text-xs leading-5 font-semibold rounded-full #{status_color(alert.status)}"}>
                      <%= alert.status %>
                    </span>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                    <%= alert.inserted_at %>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <.link navigate={~p"/alerts/#{alert.id}"} class="text-indigo-600 hover:text-indigo-900">View</.link>
                  </td>
                </tr>
              <% end %>
            </tbody>
          </table>
        </div>

        <!-- Confirmation Modal -->
        <%= if @show_confirmation_modal do %>
          <div class="fixed z-10 inset-0 overflow-y-auto" aria-labelledby="modal-title" role="dialog" aria-modal="true">
            <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
              <div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" aria-hidden="true"></div>
              <span class="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">&#8203;</span>
              <div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
                <div class="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                  <div class="sm:flex sm:items-start">
                    <div class="mx-auto flex-shrink-0 flex items-center justify-center h-12 w-12 rounded-full bg-red-100 sm:mx-0 sm:h-10 sm:w-10">
                      <svg class="h-6 w-6 text-red-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                      </svg>
                    </div>
                    <div class="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left w-full">
                      <h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white" id="modal-title">
                        <%= confirmation_title(@confirmation_action) %>
                      </h3>
                      <div class="mt-2">
                        <p class="text-sm text-gray-500 dark:text-gray-400">
                          You are about to perform this action on <%= MapSet.size(@selected_alert_ids) %> alert(s). This action <%= if @confirmation_action == "delete", do: "cannot be undone", else: "will update the alerts" %>.
                        </p>

                        <%= case @confirmation_action do %>
                          <% "update_status" -> %>
                            <div class="mt-4">
                              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">New Status</label>
                              <select id="status-select" name="status" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white">
                                <option value="investigating">Investigating</option>
                                <option value="resolved">Resolved</option>
                                <option value="false_positive">False Positive</option>
                              </select>
                            </div>

                          <% "assign" -> %>
                            <div class="mt-4">
                              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Assign To</label>
                              <input
                                type="text"
                                id="user-id-input"
                                name="user_id"
                                placeholder="User ID"
                                class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                              />
                            </div>

                          <% "add_tags" -> %>
                            <div class="mt-4">
                              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Tags (comma-separated)</label>
                              <input
                                type="text"
                                id="tags-input"
                                name="tags"
                                placeholder="tag1, tag2, tag3"
                                class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                              />
                            </div>

                          <% "remove_tags" -> %>
                            <div class="mt-4">
                              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Tags to Remove (comma-separated)</label>
                              <input
                                type="text"
                                id="tags-input"
                                name="tags"
                                placeholder="tag1, tag2, tag3"
                                class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                              />
                            </div>

                          <% _ -> %>
                            <div></div>
                        <% end %>
                      </div>
                    </div>
                  </div>
                </div>
                <div class="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
                  <button
                    type="button"
                    phx-click="confirm_bulk_action"
                    phx-value-status={case @confirmation_action do "update_status" -> "investigating"; _ -> "" end}
                    phx-value-user_id=""
                    phx-value-tags=""
                    id="confirm-button"
                    class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-red-600 text-base font-medium text-white hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 sm:ml-3 sm:w-auto sm:text-sm"
                  >
                    Confirm
                  </button>
                  <button
                    type="button"
                    phx-click="cancel_confirmation"
                    class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm dark:bg-gray-600 dark:text-gray-200 dark:border-gray-500 dark:hover:bg-gray-500"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            </div>
          </div>
        <% end %>
      <% end %>

      <%= if @live_action == :show do %>
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div class="mb-6">
            <h2 class="text-xl font-bold mb-2"><%= @alert.title %></h2>
            <div class="flex gap-2 mb-4">
              <span class={"px-2 inline-flex text-xs leading-5 font-semibold rounded-full #{severity_color(@alert.severity)}"}>
                <%= @alert.severity %>
              </span>
              <span class={"px-2 inline-flex text-xs leading-5 font-semibold rounded-full #{status_color(@alert.status)}"}>
                <%= @alert.status %>
              </span>
            </div>
            <p class="text-gray-700 dark:text-gray-300 whitespace-pre-wrap"><%= @alert.description %></p>
          </div>

          <div class="border-t border-gray-200 dark:border-gray-700 pt-4">
            <h3 class="text-lg font-medium mb-2">Details</h3>
            <dl class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <dt class="text-sm font-medium text-gray-500">Agent ID</dt>
                <dd class="text-sm text-gray-900 dark:text-white"><%= @alert.agent_id %></dd>
              </div>
              <div>
                <dt class="text-sm font-medium text-gray-500">Event IDs</dt>
                <dd class="text-sm text-gray-900 dark:text-white"><%= Enum.join(@alert.event_ids || [], ", ") %></dd>
              </div>
              <div>
                <dt class="text-sm font-medium text-gray-500">MITRE Tactics</dt>
                <dd class="text-sm text-gray-900 dark:text-white"><%= Enum.join(@alert.mitre_tactics || [], ", ") %></dd>
              </div>
              <div>
                <dt class="text-sm font-medium text-gray-500">MITRE Techniques</dt>
                <dd class="text-sm text-gray-900 dark:text-white"><%= Enum.join(@alert.mitre_techniques || [], ", ") %></dd>
              </div>
            </dl>
          </div>
        </div>
      <% end %>
    </div>
    """
  end

  defp severity_color("critical"), do: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
  defp severity_color("high"), do: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200"
  defp severity_color("medium"), do: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
  defp severity_color("low"), do: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
  defp severity_color(_), do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"

  defp status_color("new"), do: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
  defp status_color("investigating"), do: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
  defp status_color("resolved"), do: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
  defp status_color("false_positive"), do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"
  defp status_color(_), do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"

  defp confirmation_title("update_status"), do: "Update Alert Status"
  defp confirmation_title("assign"), do: "Assign Alerts"
  defp confirmation_title("delete"), do: "Delete Alerts"
  defp confirmation_title("add_tags"), do: "Add Tags to Alerts"
  defp confirmation_title("remove_tags"), do: "Remove Tags from Alerts"
  defp confirmation_title(_), do: "Confirm Action"
end
