defmodule TamanduaServerWeb.AgentsLiveEnhanced do
  @moduledoc """
  Enhanced AgentsLive with group filtering and batch action support.

  This is an enhanced version of the existing AgentsLive that adds:
  - Group filtering in the sidebar
  - Multi-select for batch operations
  - Batch action toolbar
  - Group assignment modal

  To use this enhanced version, rename the existing agents_live.ex
  and rename this file to agents_live.ex.
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Agents
  alias TamanduaServer.Agents.GroupManager
  alias TamanduaServer.Detection.Correlator

  @impl true
  def mount(_params, session, socket) do
    organization_id = session["organization_id"] || get_default_org_id()

    {:ok,
     socket
     |> assign(:organization_id, organization_id)
     |> assign(:page_title, "Agents")
     |> assign(:groups, [])
     |> assign(:selected_group_id, nil)
     |> assign(:selected_agent_ids, MapSet.new())
     |> assign(:show_batch_toolbar, false)
     |> assign(:show_group_assignment_modal, false)
     |> load_groups()}
  end

  @impl true
  def handle_params(params, _url, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end

  defp apply_action(socket, :index, params) do
    group_id = params["group"]
    org_id = socket.assigns.organization_id

    agents = if group_id do
      GroupManager.list_group_agents(group_id)
    else
      Agents.list_agents_for_org(org_id)
    end

    socket
    |> assign(:page_title, "Agents")
    |> assign(:agents, agents)
    |> assign(:agent, nil)
    |> assign(:selected_group_id, group_id)
  end

  defp apply_action(socket, :show, %{"id" => id}) do
    org_id = socket.assigns.organization_id

    case Agents.get_agent_for_org(org_id, id) do
      {:ok, agent} ->
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

      {:error, :not_found} ->
        socket
        |> put_flash(:error, "Agent not found")
        |> push_navigate(to: ~p"/agents")
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="flex h-screen">
      <%= if @live_action == :index do %>
        <!-- Sidebar with group filter -->
        <div class="w-64 bg-white dark:bg-gray-800 border-r dark:border-gray-700 overflow-y-auto">
          <div class="p-4">
            <h3 class="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">
              Filter by Group
            </h3>
            <ul class="space-y-1">
              <li>
                <.link
                  navigate={~p"/agents"}
                  class={"block px-3 py-2 rounded-md text-sm #{if @selected_group_id == nil, do: "bg-indigo-100 dark:bg-indigo-900 text-indigo-700 dark:text-indigo-200", else: "text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"}"}
                >
                  All Agents
                </.link>
              </li>
              <%= for group <- @groups do %>
                <li>
                  <.link
                    navigate={~p"/agents?group=#{group.id}"}
                    class={"block px-3 py-2 rounded-md text-sm #{if @selected_group_id == group.id, do: "bg-indigo-100 dark:bg-indigo-900 text-indigo-700 dark:text-indigo-200", else: "text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"}"}
                  >
                    <div class="flex items-center">
                      <%= if group.color do %>
                        <div
                          class="w-3 h-3 rounded-full mr-2"
                          style={"background-color: #{group.color}"}
                        >
                        </div>
                      <% end %>
                      <span class="flex-1"><%= group.name %></span>
                      <span class="text-xs text-gray-500">
                        <%= GroupManager.count_group_agents(group.id) %>
                      </span>
                    </div>
                  </.link>
                </li>
              <% end %>
            </ul>
          </div>
          <div class="border-t dark:border-gray-700 p-4">
            <.link
              navigate={~p"/agent_groups"}
              class="block w-full text-center px-3 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 text-sm"
            >
              Manage Groups
            </.link>
          </div>
        </div>
      <% end %>

      <!-- Main content -->
      <div class="flex-1 overflow-auto">
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
            <!-- Batch action toolbar -->
            <%= if @show_batch_toolbar do %>
              <div class="bg-indigo-50 dark:bg-indigo-900/20 border border-indigo-200 dark:border-indigo-800 rounded-lg p-4 mb-4">
                <div class="flex items-center justify-between">
                  <div class="flex items-center space-x-4">
                    <span class="text-sm font-medium text-indigo-900 dark:text-indigo-200">
                      <%= MapSet.size(@selected_agent_ids) %> agent(s) selected
                    </span>
                    <button
                      phx-click="clear_selection"
                      class="text-sm text-indigo-600 dark:text-indigo-400 hover:underline"
                    >
                      Clear
                    </button>
                  </div>
                  <div class="flex space-x-2">
                    <button
                      phx-click="batch_assign_group"
                      class="px-3 py-1 bg-green-600 text-white rounded hover:bg-green-700 text-sm"
                    >
                      Assign to Group
                    </button>
                    <button
                      phx-click="batch_isolate_selected"
                      class="px-3 py-1 bg-red-600 text-white rounded hover:bg-red-700 text-sm"
                    >
                      Isolate
                    </button>
                    <button
                      phx-click="batch_scan_selected"
                      class="px-3 py-1 bg-blue-600 text-white rounded hover:bg-blue-700 text-sm"
                    >
                      Scan
                    </button>
                  </div>
                </div>
              </div>
            <% end %>

            <!-- Agents table -->
            <%= render_agents_table(assigns) %>
          <% end %>

          <%= if @live_action == :show do %>
            <%= render_agent_detail(assigns) %>
          <% end %>

          <%= if @show_group_assignment_modal do %>
            <%= render_group_assignment_modal(assigns) %>
          <% end %>
        </div>
      </div>
    </div>
    """
  end

  defp render_agents_table(assigns) do
    ~H"""
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
      <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
        <thead class="bg-gray-50 dark:bg-gray-700">
          <tr>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300">
              <input
                type="checkbox"
                phx-click="toggle_all"
                checked={@selected_agent_ids != MapSet.new() && length(@agents) == MapSet.size(@selected_agent_ids)}
                class="rounded border-gray-300"
              />
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
              Hostname
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
              OS
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
              Status
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
              Last Seen
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
              Actions
            </th>
          </tr>
        </thead>
        <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
          <%= for agent <- @agents do %>
            <tr class={if MapSet.member?(@selected_agent_ids, get_agent_id(agent)), do: "bg-indigo-50 dark:bg-indigo-900/20"}>
              <td class="px-6 py-4 whitespace-nowrap">
                <input
                  type="checkbox"
                  phx-click="toggle_agent"
                  phx-value-id={get_agent_id(agent)}
                  checked={MapSet.member?(@selected_agent_ids, get_agent_id(agent))}
                  class="rounded border-gray-300"
                />
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <div class="text-sm font-medium text-gray-900 dark:text-white">
                  <%= get_agent_field(agent, :hostname) %>
                </div>
                <div class="text-sm text-gray-500">
                  <%= get_agent_field(agent, :agent_version) %>
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <div class="text-sm text-gray-900 dark:text-white">
                  <%= get_agent_field(agent, :os_type) %>
                </div>
                <div class="text-sm text-gray-500">
                  <%= get_agent_field(agent, :os_version) %>
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <span class={"px-2 inline-flex text-xs leading-5 font-semibold rounded-full #{status_color(get_agent_field(agent, :status))}"}>
                  <%= get_agent_field(agent, :status) %>
                </span>
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                <%= get_agent_field(agent, :last_seen_at) %>
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                <.link
                  navigate={~p"/agents/#{get_agent_id(agent)}"}
                  class="text-indigo-600 hover:text-indigo-900 mr-4"
                >
                  View
                </.link>
              </td>
            </tr>
          <% end %>
        </tbody>
      </table>
    </div>
    """
  end

  defp render_agent_detail(assigns) do
    ~H"""
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
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
          <h3 class="text-lg font-medium mb-4">Group Membership</h3>
          <%= render_agent_groups(assigns) %>
        </div>

        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 class="text-lg font-medium mb-4">Actions</h3>
          <div class="space-y-2">
            <button
              phx-click="show_isolate_modal"
              class="w-full bg-red-600 text-white px-4 py-2 rounded hover:bg-red-700"
            >
              Isolate Host
            </button>
            <button
              phx-click="show_scan_modal"
              class="w-full bg-gray-600 text-white px-4 py-2 rounded hover:bg-gray-700"
            >
              Scan Filesystem
            </button>
          </div>
        </div>
      </div>

      <div class="lg:col-span-2">
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <.live_component
            module={TamanduaServerWeb.Components.ProcessTreeComponent}
            id="process-tree"
            graph={@graph}
          />
        </div>
      </div>
    </div>
    """
  end

  defp render_agent_groups(assigns) do
    agent_id = assigns.agent.id
    groups = GroupManager.list_agent_groups(agent_id)

    assigns = assign(assigns, :agent_groups, groups)

    ~H"""
    <%= if @agent_groups == [] do %>
      <p class="text-sm text-gray-500 dark:text-gray-400">Not in any groups</p>
    <% else %>
      <ul class="space-y-2">
        <%= for group <- @agent_groups do %>
          <li class="flex items-center justify-between">
            <div class="flex items-center">
              <%= if group.color do %>
                <div
                  class="w-3 h-3 rounded-full mr-2"
                  style={"background-color: #{group.color}"}
                >
                </div>
              <% end %>
              <span class="text-sm"><%= group.name %></span>
            </div>
            <.link navigate={~p"/agent_groups/#{group.id}"} class="text-xs text-indigo-600 hover:underline">
              View
            </.link>
          </li>
        <% end %>
      </ul>
    <% end %>
    """
  end

  defp render_group_assignment_modal(assigns) do
    ~H"""
    <div class="fixed z-10 inset-0 overflow-y-auto">
      <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
        <div
          class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity"
          phx-click="hide_group_assignment_modal"
        >
        </div>
        <div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
          <div class="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
            <h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white mb-4">
              Assign to Group
            </h3>
            <p class="text-sm text-gray-500 dark:text-gray-400 mb-4">
              Select a group to assign <%= MapSet.size(@selected_agent_ids) %> agent(s) to:
            </p>
            <div class="space-y-2">
              <%= for group <- @groups do %>
                <button
                  phx-click="assign_to_group"
                  phx-value-group-id={group.id}
                  class="w-full flex items-center justify-between px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
                >
                  <div class="flex items-center">
                    <%= if group.color do %>
                      <div
                        class="w-4 h-4 rounded-full mr-3"
                        style={"background-color: #{group.color}"}
                      >
                      </div>
                    <% end %>
                    <span class="text-sm font-medium"><%= group.name %></span>
                  </div>
                  <span class="text-xs text-gray-500">
                    <%= GroupManager.count_group_agents(group.id) %> agents
                  </span>
                </button>
              <% end %>
            </div>
          </div>
          <div class="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
            <button
              phx-click="hide_group_assignment_modal"
              type="button"
              class="w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none sm:ml-3 sm:w-auto sm:text-sm"
            >
              Cancel
            </button>
          </div>
        </div>
      </div>
    </div>
    """
  end

  @impl true
  def handle_event("toggle_agent", %{"id" => id}, socket) do
    selected = if MapSet.member?(socket.assigns.selected_agent_ids, id) do
      MapSet.delete(socket.assigns.selected_agent_ids, id)
    else
      MapSet.put(socket.assigns.selected_agent_ids, id)
    end

    {:noreply,
     socket
     |> assign(:selected_agent_ids, selected)
     |> assign(:show_batch_toolbar, MapSet.size(selected) > 0)}
  end

  @impl true
  def handle_event("toggle_all", _params, socket) do
    agent_ids = Enum.map(socket.assigns.agents, &get_agent_id/1) |> MapSet.new()

    selected = if MapSet.size(socket.assigns.selected_agent_ids) == MapSet.size(agent_ids) do
      MapSet.new()
    else
      agent_ids
    end

    {:noreply,
     socket
     |> assign(:selected_agent_ids, selected)
     |> assign(:show_batch_toolbar, MapSet.size(selected) > 0)}
  end

  @impl true
  def handle_event("clear_selection", _params, socket) do
    {:noreply,
     socket
     |> assign(:selected_agent_ids, MapSet.new())
     |> assign(:show_batch_toolbar, false)}
  end

  @impl true
  def handle_event("batch_assign_group", _params, socket) do
    {:noreply, assign(socket, :show_group_assignment_modal, true)}
  end

  @impl true
  def handle_event("hide_group_assignment_modal", _params, socket) do
    {:noreply, assign(socket, :show_group_assignment_modal, false)}
  end

  @impl true
  def handle_event("assign_to_group", %{"group-id" => group_id}, socket) do
    agent_ids = MapSet.to_list(socket.assigns.selected_agent_ids)

    case GroupManager.add_agents_to_group(agent_ids, group_id) do
      {:ok, count} ->
        {:noreply,
         socket
         |> put_flash(:info, "Added #{count} agent(s) to group")
         |> assign(:show_group_assignment_modal, false)
         |> assign(:selected_agent_ids, MapSet.new())
         |> assign(:show_batch_toolbar, false)}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Failed to assign agents to group")}
    end
  end

  @impl true
  def handle_event("batch_isolate_selected", _params, socket) do
    agent_ids = MapSet.to_list(socket.assigns.selected_agent_ids)

    case GroupManager.execute_batch_command_on_agents(
           socket.assigns.organization_id,
           agent_ids,
           "isolate_network",
           %{},
           initiated_by: "admin"
         ) do
      {:ok, batch} ->
        {:noreply,
         socket
         |> put_flash(:info, "Batch isolation initiated (#{batch.total_count} agents)")
         |> push_navigate(to: ~p"/batch_commands/#{batch.id}")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to initiate batch command: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("batch_scan_selected", _params, socket) do
    agent_ids = MapSet.to_list(socket.assigns.selected_agent_ids)

    case GroupManager.execute_batch_command_on_agents(
           socket.assigns.organization_id,
           agent_ids,
           "scan_path",
           %{path: "/", recursive: true},
           initiated_by: "admin"
         ) do
      {:ok, batch} ->
        {:noreply,
         socket
         |> put_flash(:info, "Batch scan initiated (#{batch.total_count} agents)")
         |> push_navigate(to: ~p"/batch_commands/#{batch.id}")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to initiate batch command: #{inspect(reason)}")}
    end
  end

  # Keep existing event handlers from original AgentsLive
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

  defp load_groups(socket) do
    groups = GroupManager.list_groups(socket.assigns.organization_id)
    assign(socket, :groups, groups)
  end

  defp status_color("online"), do: "bg-green-100 text-green-800"
  defp status_color("offline"), do: "bg-gray-100 text-gray-800"
  defp status_color("isolated"), do: "bg-red-100 text-red-800"
  defp status_color(_), do: "bg-gray-100 text-gray-800"

  defp get_default_org_id, do: "default-org-id"

  # Helper to handle both Agent structs and group agent maps
  defp get_agent_id(%{agent_id: id}), do: id
  defp get_agent_id(%{id: id}), do: id

  defp get_agent_field(%{agent_id: _} = agent, :hostname), do: agent.hostname
  defp get_agent_field(%{id: _} = agent, :hostname), do: agent.hostname
  defp get_agent_field(%{agent_id: _} = agent, :os_type), do: agent.os_type
  defp get_agent_field(%{id: _} = agent, :os_type), do: agent.os_type
  defp get_agent_field(%{agent_id: _} = agent, :os_version), do: agent.os_version
  defp get_agent_field(%{id: _} = agent, :os_version), do: agent.os_version
  defp get_agent_field(%{agent_id: _} = agent, :status), do: agent.status
  defp get_agent_field(%{id: _} = agent, :status), do: agent.status
  defp get_agent_field(%{agent_id: _} = agent, :last_seen_at), do: agent.last_seen_at
  defp get_agent_field(%{id: _} = agent, :last_seen_at), do: agent.last_seen_at
  defp get_agent_field(%{agent_id: _} = agent, :agent_version), do: Map.get(agent, :agent_version, "N/A")
  defp get_agent_field(%{id: _} = agent, :agent_version), do: agent.agent_version
end
