defmodule TamanduaServerWeb.HuntingLive do
  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Telemetry
  import TamanduaServerWeb.PaginationComponent

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(page_title: "Threat Hunting")
     |> assign(results: [])
     |> assign(total_count: 0)
     |> assign(page: 1)
     |> assign(per_page: 50)
     |> assign(search_params: %{})
     |> assign(form: to_form(%{"per_page" => "50"}))
    }
  end

  @impl true
  def handle_event("search", params, socket) do
    per_page = String.to_integer(params["per_page"] || "50")

    search_params = %{
      agent_id: params["agent_id"],
      event_type: params["event_type"],
      query: params["query"],
      page: 1,
      per_page: per_page
    }

    # Filter out empty params (but keep page and per_page)
    search_params =
      search_params
      |> Enum.reject(fn {k, v} -> k not in [:page, :per_page] and (v == "" or v == nil) end)
      |> Map.new()

    {results, total_count} = Telemetry.search_events_paginated(search_params)

    {:noreply,
     socket
     |> assign(results: results)
     |> assign(total_count: total_count)
     |> assign(page: 1)
     |> assign(per_page: per_page)
     |> assign(search_params: search_params)}
  end

  @impl true
  def handle_event("paginate", %{"page" => page_str}, socket) do
    page = String.to_integer(page_str)
    search_params = Map.put(socket.assigns.search_params, :page, page)

    {results, total_count} = Telemetry.search_events_paginated(search_params)

    {:noreply,
     socket
     |> assign(results: results)
     |> assign(total_count: total_count)
     |> assign(page: page)}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6">
      <h1 class="text-2xl font-bold mb-6">Threat Hunting</h1>

      <!-- Search Form -->
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6 mb-6">
        <form phx-submit="search" class="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
          <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Agent ID</label>
            <input type="text" name="agent_id" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600" placeholder="UUID" />
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Event Type</label>
            <select name="event_type" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600">
              <option value="">All Types</option>
              <optgroup label="Process">
                <option value="process_create">Process Create</option>
                <option value="process_terminate">Process Terminate</option>
                <option value="process_inject">Process Inject</option>
              </optgroup>
              <optgroup label="File">
                <option value="file_create">File Create</option>
                <option value="file_modify">File Modify</option>
                <option value="file_delete">File Delete</option>
              </optgroup>
              <optgroup label="Network">
                <option value="network_connect">Network Connect</option>
                <option value="dns_query">DNS Query</option>
              </optgroup>
              <optgroup label="Defense Evasion">
                <option value="etw_tampering">ETW Tampering (Generic)</option>
                <option value="etw_prologue_patched">ETW Prologue Patched</option>
                <option value="ntdll_stub_modified">NTDLL Stub Modified</option>
                <option value="fresh_ntdll_mapping">Fresh NTDLL Mapping</option>
                <option value="ntdll_write_detected">NTDLL Write Detected</option>
                <option value="syscall_region_tampered">Syscall Region Tampered</option>
              </optgroup>
            </select>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Query (Payload)</label>
            <input type="text" name="query" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600" placeholder="Text search..." />
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Per Page</label>
            <select name="per_page" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600">
              <option value="50">50</option>
              <option value="100">100</option>
              <option value="500">500</option>
            </select>
          </div>

          <div class="md:col-span-4">
            <button type="submit" class="w-full bg-indigo-600 text-white px-4 py-2 rounded hover:bg-indigo-700">Search</button>
          </div>
        </form>
      </div>

      <!-- Results -->
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
        <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <h3 class="text-lg font-medium">Results (<%= @total_count %>)</h3>
        </div>

        <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead class="bg-gray-50 dark:bg-gray-700">
            <tr>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Timestamp</th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Type</th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Agent</th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Details</th>
            </tr>
          </thead>
          <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
            <%= for event <- @results do %>
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
            <%= if length(@results) == 0 do %>
              <tr>
                <td colspan="4" class="px-6 py-4 text-center text-gray-500">No results found</td>
              </tr>
            <% end %>
          </tbody>
        </table>

        <%= if @total_count > 0 do %>
          <.pagination
            page={@page}
            per_page={@per_page}
            total_count={@total_count}
            event_name="paginate"
          />
        <% end %>
      </div>
    </div>
    """
  end
end
