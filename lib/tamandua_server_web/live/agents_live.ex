defmodule TamanduaServerWeb.AgentsLive do
  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Agents
  alias TamanduaServer.Detection.Correlator

  @impl true
  def mount(_params, session, socket) do
    organization_id = session["organization_id"] || get_default_org_id()

    {:ok,
     socket
     |> assign(:organization_id, organization_id)
     |> assign(:page_title, "Agents")}
  end

  @impl true
  def handle_params(params, _url, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end

  defp apply_action(socket, :index, _params) do
    org_id = socket.assigns.organization_id
    agents = Agents.list_agents_for_org(org_id)

    socket
    |> assign(:page_title, "Agents")
    |> assign(:agents, agents)
    |> assign(:agent, nil)
  end

  defp apply_action(socket, :show, %{"id" => id}) do
    org_id = socket.assigns.organization_id

    case Agents.get_agent_for_org(org_id, id) do
      {:ok, agent} ->
        apply_show_action(socket, id, agent)

      {:error, :not_found} ->
        socket
        |> put_flash(:error, "Agent not found")
        |> redirect(to: ~p"/agents")
    end
  end

  defp apply_show_action(socket, id, agent) do
    # Fetch process tree graph
    graph = case Correlator.get_process_tree(id) do
      {:ok, g} -> g
      _ -> nil
    end

    socket
    |> assign(:page_title, "Agent Details: #{agent.hostname}")
    |> assign(:agent_id, id)
    |> assign(:agent, agent)
    |> assign(:graph, graph)
    |> assign(:show_isolate_modal, false)
    |> assign(:show_scan_modal, false)
  end

  defp get_default_org_id, do: nil

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-2xl font-bold"><%= @page_title %></h1>
        <%= if @live_action == :show do %>
          <.link navigate={~p"/agents"} class="text-blue-600 hover:underline">
            &larr; Back to Agents
          </.link>
        <% end %>
      </div>

      <%= if @live_action == :index do %>
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
          <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead class="bg-gray-50 dark:bg-gray-700">
              <tr>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Hostname</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">OS</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Status</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Last Seen</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              <%= for agent <- @agents do %>
                <tr>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <div class="text-sm font-medium text-gray-900 dark:text-white"><%= agent.hostname %></div>
                    <div class="text-sm text-gray-500"><%= agent.agent_version %></div>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <div class="text-sm text-gray-900 dark:text-white"><%= agent.os_type %></div>
                    <div class="text-sm text-gray-500"><%= agent.os_version %></div>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <span class={"px-2 inline-flex text-xs leading-5 font-semibold rounded-full #{status_color(agent.status)}"}>
                      <%= agent.status %>
                    </span>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                    <%= agent.last_seen_at %>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <.link navigate={~p"/agents/#{agent.id}"} class="text-indigo-600 hover:text-indigo-900 mr-4">View</.link>
                  </td>
                </tr>
              <% end %>
            </tbody>
          </table>
        </div>
      <% end %>

      <%= if @live_action == :show do %>
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <!-- Agent Info -->
          <div class="lg:col-span-1 space-y-6">
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <h3 class="text-lg font-medium mb-4">System Information</h3>
              <dl class="space-y-2">
                <div class="flex justify-between">
                  <dt class="text-gray-500">Hostname</dt>
                  <dd class="font-medium"><%= @agent.hostname %></dd>
                </div>
                <div class="flex justify-between">
                  <dt class="text-gray-500">OS</dt>
                  <dd class="font-medium"><%= @agent.os_type %> <%= @agent.os_version %></dd>
                </div>
                <div class="flex justify-between">
                  <dt class="text-gray-500">Agent Version</dt>
                  <dd class="font-medium"><%= @agent.agent_version %></dd>
                </div>
                <div class="flex justify-between">
                  <dt class="text-gray-500">Status</dt>
                  <dd>
                    <span class={"px-2 inline-flex text-xs leading-5 font-semibold rounded-full #{status_color(@agent.status)}"}>
                      <%= @agent.status %>
                    </span>
                  </dd>
                </div>
              </dl>
            </div>

            <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <h3 class="text-lg font-medium mb-4">Actions</h3>
              <div class="space-y-2">
                <button phx-click="show_isolate_modal" class="w-full bg-red-600 text-white px-4 py-2 rounded hover:bg-red-700">Isolate Host</button>
                <button phx-click="show_scan_modal" class="w-full bg-gray-600 text-white px-4 py-2 rounded hover:bg-gray-700">Scan Filesystem</button>
              </div>
            </div>
          </div>

          <!-- Process Tree -->
          <div class="lg:col-span-2">
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <.live_component module={TamanduaServerWeb.Components.ProcessTreeComponent} id="process-tree" graph={@graph} />
            </div>
          </div>
        </div>
      <% end %>

      <%= if @show_isolate_modal do %>
        <div class="fixed z-10 inset-0 overflow-y-auto">
          <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" phx-click="hide_isolate_modal"></div>
            <div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
              <div class="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                <div class="sm:flex sm:items-start">
                  <div class="mx-auto flex-shrink-0 flex items-center justify-center h-12 w-12 rounded-full bg-red-100 sm:mx-0 sm:h-10 sm:w-10">
                    <span class="text-red-600 text-2xl">!</span>
                  </div>
                  <div class="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left">
                    <h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white">Isolate Host</h3>
                    <div class="mt-2">
                      <p class="text-sm text-gray-500 dark:text-gray-400">
                        Are you sure you want to isolate this host from the network? This will block all network traffic except management connections.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
              <div class="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
                <button phx-click="isolate_host" type="button" class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-red-600 text-base font-medium text-white hover:bg-red-700 focus:outline-none sm:ml-3 sm:w-auto sm:text-sm">Isolate</button>
                <button phx-click="hide_isolate_modal" type="button" class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm">Cancel</button>
              </div>
            </div>
          </div>
        </div>
      <% end %>

      <%= if @show_scan_modal do %>
        <div class="fixed z-10 inset-0 overflow-y-auto">
          <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" phx-click="hide_scan_modal"></div>
            <div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
              <form phx-submit="scan_filesystem">
                <div class="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                  <div class="sm:flex sm:items-start">
                    <div class="mt-3 text-center sm:mt-0 sm:text-left w-full">
                      <h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white">Scan Filesystem</h3>
                      <div class="mt-4">
                        <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Path to scan</label>
                        <input type="text" name="path" value={scan_path_default(@agent.os_type)} class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white" required />
                        <p class="mt-2 text-sm text-gray-500 dark:text-gray-400">Enter the path to scan for threats</p>
                      </div>
                    </div>
                  </div>
                </div>
                <div class="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
                  <button type="submit" class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-indigo-600 text-base font-medium text-white hover:bg-indigo-700 focus:outline-none sm:ml-3 sm:w-auto sm:text-sm">Start Scan</button>
                  <button phx-click="hide_scan_modal" type="button" class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm">Cancel</button>
                </div>
              </form>
            </div>
          </div>
        </div>
      <% end %>
    </div>
    """
  end

  @impl true
  def handle_event("show_isolate_modal", _params, socket) do
    {:noreply, assign(socket, :show_isolate_modal, true)}
  end

  @impl true
  def handle_event("hide_isolate_modal", _params, socket) do
    {:noreply, assign(socket, :show_isolate_modal, false)}
  end

  @impl true
  def handle_event("show_scan_modal", _params, socket) do
    {:noreply, assign(socket, :show_scan_modal, true)}
  end

  @impl true
  def handle_event("hide_scan_modal", _params, socket) do
    {:noreply, assign(socket, :show_scan_modal, false)}
  end

  @impl true
  def handle_event("isolate_host", _params, socket) do
    agent_id = socket.assigns.agent_id

    case TamanduaServer.Response.Executor.isolate_host(agent_id) do
      {:ok, _response} ->
        socket =
          socket
          |> put_flash(:info, "Host isolation initiated successfully")
          |> assign(:show_isolate_modal, false)

        {:noreply, socket}

      {:error, reason} ->
        socket =
          socket
          |> put_flash(:error, "Failed to isolate host: #{inspect(reason)}")
          |> assign(:show_isolate_modal, false)

        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("scan_filesystem", %{"path" => path}, socket) do
    agent_id = socket.assigns.agent_id

    case TamanduaServer.Response.Executor.scan_path(agent_id, path, recursive: true) do
      {:ok, _response} ->
        socket =
          socket
          |> put_flash(:info, "Filesystem scan initiated for path: #{path}")
          |> assign(:show_scan_modal, false)

        {:noreply, socket}

      {:error, reason} ->
        socket =
          socket
          |> put_flash(:error, "Failed to start scan: #{inspect(reason)}")
          |> assign(:show_scan_modal, false)

        {:noreply, socket}
    end
  end

  defp status_color("online"), do: "bg-green-100 text-green-800"
  defp status_color("offline"), do: "bg-gray-100 text-gray-800"
  defp status_color("isolated"), do: "bg-red-100 text-red-800"
  defp status_color(_), do: "bg-gray-100 text-gray-800"

  defp scan_path_default("windows"), do: "C:\\"
  defp scan_path_default("linux"), do: "/"
  defp scan_path_default("macos"), do: "/"
  defp scan_path_default(_), do: "/"
end
