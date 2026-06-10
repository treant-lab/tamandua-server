defmodule TamanduaServerWeb.EventsLiveFiltered do
  @moduledoc """
  COMPLETE IMPLEMENTATION with filtering for Events page.
  Rename this file to events_live.ex to use.
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Telemetry
  import TamanduaServerWeb.PaginationComponent

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(page_title: "Events")
     |> assign(page: 1)
     |> assign(per_page: 50)
     |> assign(total_count: 0)
     |> assign(filters: %{})}
  end

  @impl true
  def handle_params(params, _url, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end

  defp apply_action(socket, :index, params) do
    page = params["page"] |> parse_page()
    per_page = socket.assigns.per_page
    filters = build_filters(params)

    # Apply filters with pagination
    query_filters = Map.put(filters, :limit, per_page) |> Map.put(:offset, (page - 1) * per_page)
    events = Telemetry.list_events(query_filters)
    total_count = Telemetry.count_events(filters)

    socket
    |> assign(:page_title, "Events")
    |> assign(:events, events)
    |> assign(:page, page)
    |> assign(:total_count, total_count)
    |> assign(:filters, filters)
  end

  defp parse_page(nil), do: 1
  defp parse_page(page) when is_binary(page) do
    case Integer.parse(page) do
      {num, _} when num > 0 -> num
      _ -> 1
    end
  end
  defp parse_page(_), do: 1

  @impl true
  def handle_event("paginate", %{"page" => page}, socket) do
    path = build_path(socket.assigns.filters, page)
    {:noreply, push_patch(socket, to: path)}
  end

  @impl true
  def handle_event("filter", params, socket) do
    filters = build_filters(params)
    path = build_path(filters, 1)
    {:noreply, push_patch(socket, to: path)}
  end

  @impl true
  def handle_event("clear_filters", _params, socket) do
    {:noreply, push_patch(socket, to: ~p"/events")}
  end

  defp build_filters(params) do
    %{}
    |> maybe_add_filter(:event_type, params["event_type"])
    |> maybe_add_filter(:agent_id, params["agent_id"])
    |> maybe_add_filter(:since, parse_datetime(params["from_timestamp"]))
  end

  defp maybe_add_filter(filters, _key, nil), do: filters
  defp maybe_add_filter(filters, _key, ""), do: filters
  defp maybe_add_filter(filters, key, value), do: Map.put(filters, key, value)

  defp parse_datetime(nil), do: nil
  defp parse_datetime(""), do: nil
  defp parse_datetime(value) when is_binary(value) do
    case NaiveDateTime.from_iso8601(value) do
      {:ok, dt} -> dt
      _ -> nil
    end
  end

  defp build_path(filters, page) do
    query_params =
      filters
      |> Map.put(:page, page)
      |> Enum.filter(fn {_, v} -> v != nil and v != "" end)
      |> Enum.map(fn {k, v} ->
        # Convert NaiveDateTime back to string for URL
        case v do
          %NaiveDateTime{} = dt -> {k, NaiveDateTime.to_iso8601(dt)}
          other -> {k, other}
        end
      end)
      |> Enum.into(%{})

    if map_size(query_params) == 0 do
      ~p"/events"
    else
      ~p"/events?#{query_params}"
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6">
      <h1 class="text-2xl font-bold mb-6">Events</h1>

      <!-- Search and Filter Form -->
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4 mb-6">
        <form phx-change="filter" class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Event Type</label>
            <select
              name="event_type"
              class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
            >
              <option value="">All Types</option>
              <option value="process_create" selected={Map.get(@filters, :event_type) == "process_create"}>Process Create</option>
              <option value="process_terminate" selected={Map.get(@filters, :event_type) == "process_terminate"}>Process Terminate</option>
              <option value="file_create" selected={Map.get(@filters, :event_type) == "file_create"}>File Create</option>
              <option value="file_modify" selected={Map.get(@filters, :event_type) == "file_modify"}>File Modify</option>
              <option value="network_connect" selected={Map.get(@filters, :event_type) == "network_connect"}>Network Connect</option>
              <option value="dns_query" selected={Map.get(@filters, :event_type) == "dns_query"}>DNS Query</option>
              <option value="registry_modify" selected={Map.get(@filters, :event_type) == "registry_modify"}>Registry Modify</option>
            </select>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Agent ID</label>
            <input
              type="text"
              name="agent_id"
              value={Map.get(@filters, :agent_id, "")}
              placeholder="Filter by agent UUID..."
              class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
            />
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">From Timestamp</label>
            <input
              type="datetime-local"
              name="from_timestamp"
              value={format_datetime(Map.get(@filters, :since))}
              class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
            />
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

      <div class="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
        <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead class="bg-gray-50 dark:bg-gray-700">
            <tr>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Timestamp</th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Type</th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Agent ID</th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Details</th>
            </tr>
          </thead>
          <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
            <%= for event <- @events do %>
              <tr>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                  <%= event.timestamp %>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-blue-100 text-blue-800">
                    <%= event.event_type %>
                  </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                  <%= String.slice(event.agent_id, 0..7) %>...
                </td>
                <td class="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">
                  <pre class="text-xs overflow-x-auto max-w-xs"><%= inspect(event.payload) %></pre>
                </td>
              </tr>
            <% end %>
            <%= if length(@events) == 0 do %>
              <tr>
                <td colspan="4" class="px-6 py-4 text-center text-gray-500">No events found</td>
              </tr>
            <% end %>
          </tbody>
        </table>

        <!-- Pagination -->
        <.pagination
          page={@page}
          per_page={@per_page}
          total_count={@total_count}
          event_name="paginate"
        />
      </div>
    </div>
    """
  end

  defp format_datetime(nil), do: ""
  defp format_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt) |> String.slice(0, 16)
  defp format_datetime(_), do: ""
end
