defmodule TamanduaServerWeb.IOCsLive do
  use TamanduaServerWeb, :live_view

  alias TamanduaServer.ThreatIntel
  import TamanduaServerWeb.PaginationComponent

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(page_title: "Indicators of Compromise")
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

    {iocs, total_count} = ThreatIntel.list_active_iocs_paginated(page: page, per_page: per_page)
    stats = ThreatIntel.get_stats()

    socket
    |> assign(:page_title, "IOCs")
    |> assign(:iocs, iocs)
    |> assign(:stats, stats)
    |> assign(:page, page)
    |> assign(:total_count, total_count)
    |> assign(:show_add_modal, false)
    |> assign(:show_delete_modal, false)
    |> assign(:ioc_to_delete, nil)
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
  def render(assigns) do
    ~H"""
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-2xl font-bold"><%= @page_title %></h1>
        <button phx-click="show_add_modal" class="bg-indigo-600 text-white px-4 py-2 rounded hover:bg-indigo-700">Add IOC</button>
      </div>

      <!-- Stats Cards -->
      <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 class="text-gray-500 text-sm font-medium uppercase">Total IOCs</h3>
          <p class="text-3xl font-bold mt-2"><%= @stats.total %></p>
        </div>
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 class="text-gray-500 text-sm font-medium uppercase">Active</h3>
          <p class="text-3xl font-bold mt-2 text-green-600"><%= @stats.active %></p>
        </div>
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 class="text-gray-500 text-sm font-medium uppercase">Hashes</h3>
          <p class="text-3xl font-bold mt-2"><%= Map.get(@stats.by_type, :sha256, 0) + Map.get(@stats.by_type, :md5, 0) %></p>
        </div>
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 class="text-gray-500 text-sm font-medium uppercase">Network</h3>
          <p class="text-3xl font-bold mt-2"><%= Map.get(@stats.by_type, :ip, 0) + Map.get(@stats.by_type, :domain, 0) %></p>
        </div>
      </div>

      <div class="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
        <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead class="bg-gray-50 dark:bg-gray-700">
            <tr>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Type</th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Value</th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Confidence</th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Source</th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
            <%= for ioc <- @iocs do %>
              <tr>
                <td class="px-6 py-4 whitespace-nowrap">
                  <span class={"px-2 inline-flex text-xs leading-5 font-semibold rounded-full #{type_color(ioc.type)}"}>
                    <%= ioc.type %>
                  </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap font-mono text-sm text-gray-900 dark:text-white">
                  <%= ioc.value %>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  <%= ioc.confidence %>%
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  <%= ioc.source || "Manual" %>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                  <button phx-click="show_delete_modal" phx-value-id={ioc.id} phx-value-type={ioc.type} phx-value-value={ioc.value} class="text-red-600 hover:text-red-900">Delete</button>
                </td>
              </tr>
            <% end %>
            <%= if length(@iocs) == 0 do %>
              <tr>
                <td colspan="5" class="px-6 py-4 text-center text-gray-500">No active IOCs found</td>
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

      <%= if @show_add_modal do %>
        <div class="fixed z-10 inset-0 overflow-y-auto">
          <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" phx-click="hide_add_modal"></div>
            <div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
              <form phx-submit="add_ioc">
                <div class="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                  <h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white mb-4">Add New IOC</h3>

                  <div class="space-y-4">
                    <div>
                      <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Type</label>
                      <select name="type" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white" required>
                        <option value="ip">IP Address</option>
                        <option value="domain">Domain</option>
                        <option value="hash_sha256">SHA256 Hash</option>
                        <option value="hash_md5">MD5 Hash</option>
                        <option value="hash_sha1">SHA1 Hash</option>
                        <option value="url">URL</option>
                        <option value="email">Email</option>
                      </select>
                    </div>

                    <div>
                      <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Value</label>
                      <input type="text" name="value" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white" required />
                    </div>

                    <div>
                      <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Confidence (0-100)</label>
                      <input type="number" name="confidence" min="0" max="100" value="80" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white" required />
                    </div>

                    <div>
                      <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Source</label>
                      <input type="text" name="source" value="Manual" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white" required />
                    </div>

                    <div>
                      <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Description</label>
                      <textarea name="description" rows="3" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"></textarea>
                    </div>
                  </div>
                </div>
                <div class="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
                  <button type="submit" class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-indigo-600 text-base font-medium text-white hover:bg-indigo-700 focus:outline-none sm:ml-3 sm:w-auto sm:text-sm">Add IOC</button>
                  <button phx-click="hide_add_modal" type="button" class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm">Cancel</button>
                </div>
              </form>
            </div>
          </div>
        </div>
      <% end %>

      <%= if @show_delete_modal do %>
        <div class="fixed z-10 inset-0 overflow-y-auto">
          <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" phx-click="hide_delete_modal"></div>
            <div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
              <div class="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                <div class="sm:flex sm:items-start">
                  <div class="mx-auto flex-shrink-0 flex items-center justify-center h-12 w-12 rounded-full bg-red-100 sm:mx-0 sm:h-10 sm:w-10">
                    <span class="text-red-600 text-2xl">!</span>
                  </div>
                  <div class="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left">
                    <h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white">Delete IOC</h3>
                    <div class="mt-2">
                      <p class="text-sm text-gray-500 dark:text-gray-400">
                        Are you sure you want to delete this IOC? This action cannot be undone.
                      </p>
                      <%= if @ioc_to_delete do %>
                        <p class="text-sm text-gray-700 dark:text-gray-300 mt-2 font-mono">
                          <%= @ioc_to_delete.type %>: <%= @ioc_to_delete.value %>
                        </p>
                      <% end %>
                    </div>
                  </div>
                </div>
              </div>
              <div class="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
                <button phx-click="delete_ioc" type="button" class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-red-600 text-base font-medium text-white hover:bg-red-700 focus:outline-none sm:ml-3 sm:w-auto sm:text-sm">Delete</button>
                <button phx-click="hide_delete_modal" type="button" class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm">Cancel</button>
              </div>
            </div>
          </div>
        </div>
      <% end %>
    </div>
    """
  end

  @impl true
  def handle_event("paginate", %{"page" => page}, socket) do
    {:noreply, push_patch(socket, to: ~p"/iocs?page=#{page}")}
  end

  @impl true
  def handle_event("show_add_modal", _params, socket) do
    {:noreply, assign(socket, :show_add_modal, true)}
  end

  @impl true
  def handle_event("hide_add_modal", _params, socket) do
    {:noreply, assign(socket, :show_add_modal, false)}
  end

  @impl true
  def handle_event("show_delete_modal", %{"id" => id, "type" => type, "value" => value}, socket) do
    socket =
      socket
      |> assign(:show_delete_modal, true)
      |> assign(:ioc_to_delete, %{id: id, type: type, value: value})

    {:noreply, socket}
  end

  @impl true
  def handle_event("hide_delete_modal", _params, socket) do
    socket =
      socket
      |> assign(:show_delete_modal, false)
      |> assign(:ioc_to_delete, nil)

    {:noreply, socket}
  end

  @impl true
  def handle_event("add_ioc", params, socket) do
    ioc_params = %{
      type: params["type"],
      value: params["value"],
      confidence: String.to_integer(params["confidence"]),
      source: params["source"],
      description: params["description"]
    }

    case ThreatIntel.add_ioc(ioc_params) do
      {:ok, _ioc} ->
        # Reload data with current pagination
        page = socket.assigns.page
        per_page = socket.assigns.per_page
        {iocs, total_count} = ThreatIntel.list_active_iocs_paginated(page: page, per_page: per_page)
        stats = ThreatIntel.get_stats()

        socket =
          socket
          |> put_flash(:info, "IOC added successfully")
          |> assign(:show_add_modal, false)
          |> assign(:iocs, iocs)
          |> assign(:total_count, total_count)
          |> assign(:stats, stats)

        {:noreply, socket}

      {:error, reason} ->
        socket =
          socket
          |> put_flash(:error, "Failed to add IOC: #{inspect(reason)}")

        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("delete_ioc", _params, socket) do
    ioc_to_delete = socket.assigns.ioc_to_delete

    if ioc_to_delete do
      # The ThreatIntel module uses ETS, so we need to use the Detection.IOCs module
      case TamanduaServer.Detection.IOCs.remove(ioc_to_delete.id) do
        {:ok, _ioc} ->
          # Reload data with current pagination
          page = socket.assigns.page
          per_page = socket.assigns.per_page
          {iocs, total_count} = ThreatIntel.list_active_iocs_paginated(page: page, per_page: per_page)
          stats = ThreatIntel.get_stats()

          socket =
            socket
            |> put_flash(:info, "IOC deleted successfully")
            |> assign(:show_delete_modal, false)
            |> assign(:ioc_to_delete, nil)
            |> assign(:iocs, iocs)
            |> assign(:total_count, total_count)
            |> assign(:stats, stats)

          {:noreply, socket}

        {:error, reason} ->
          socket =
            socket
            |> put_flash(:error, "Failed to delete IOC: #{inspect(reason)}")
            |> assign(:show_delete_modal, false)
            |> assign(:ioc_to_delete, nil)

          {:noreply, socket}
      end
    else
      {:noreply, socket}
    end
  end

  defp type_color(:sha256), do: "bg-purple-100 text-purple-800"
  defp type_color(:md5), do: "bg-purple-100 text-purple-800"
  defp type_color(:ip), do: "bg-blue-100 text-blue-800"
  defp type_color(:domain), do: "bg-green-100 text-green-800"
  defp type_color(:url), do: "bg-yellow-100 text-yellow-800"
  defp type_color(_), do: "bg-gray-100 text-gray-800"
end
