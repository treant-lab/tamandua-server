defmodule TamanduaServerWeb.EventsLive do
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
     |> assign(total_count: 0)}
  end

  @impl true
  def handle_params(params, _url, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end

  defp apply_action(socket, :index, params) do
    page = params["page"] |> parse_page()
    per_page = socket.assigns.per_page

    {events, total_count} = Telemetry.list_events_paginated(page, per_page)

    socket
    |> assign(:page_title, "Events")
    |> assign(:events, events)
    |> assign(:page, page)
    |> assign(:total_count, total_count)
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
    {:noreply, push_patch(socket, to: ~p"/events?page=#{page}")}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6">
      <h1 class="text-2xl font-bold mb-6">Events</h1>

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
                  <%= event.agent_id %>
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
end
