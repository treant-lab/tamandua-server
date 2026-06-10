defmodule TamanduaServerWeb.AgentGroupsLive do
  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Agents.{GroupManager, Group}

  @impl true
  def mount(_params, session, socket) do
    organization_id = session["organization_id"] || get_default_org_id()

    {:ok,
     socket
     |> assign(:organization_id, organization_id)
     |> assign(:page_title, "Agent Groups")
     |> assign(:groups, [])
     |> assign(:selected_group, nil)
     |> assign(:show_create_modal, false)
     |> assign(:show_edit_modal, false)
     |> assign(:show_delete_modal, false)
     |> assign(:show_add_agents_modal, false)
     |> assign(:form, nil)
     |> load_groups()}
  end

  @impl true
  def handle_params(params, _url, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end

  defp apply_action(socket, :index, _params) do
    socket
    |> assign(:page_title, "Agent Groups")
    |> assign(:selected_group, nil)
  end

  defp apply_action(socket, :show, %{"id" => id}) do
    case GroupManager.get_group(socket.assigns.organization_id, id) do
      {:ok, group} ->
        socket
        |> assign(:page_title, "Group: #{group.name}")
        |> assign(:selected_group, group)
        |> assign(:group_agents, GroupManager.list_group_agents(id))
        |> assign(:group_stats, GroupManager.get_group_stats(id))

      {:error, :not_found} ->
        socket
        |> put_flash(:error, "Group not found")
        |> push_navigate(to: ~p"/agent_groups")
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-2xl font-bold"><%= @page_title %></h1>
        <%= if @live_action == :show do %>
          <.link navigate={~p"/agent_groups"} class="text-blue-600 hover:underline">
            &larr; Back to Groups
          </.link>
        <% else %>
          <button
            phx-click="show_create_modal"
            class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
          >
            Create Group
          </button>
        <% end %>
      </div>

      <%= if @live_action == :index do %>
        <%= render_groups_list(assigns) %>
      <% end %>

      <%= if @live_action == :show and @selected_group do %>
        <%= render_group_detail(assigns) %>
      <% end %>

      <%= if @show_create_modal do %>
        <%= render_create_modal(assigns) %>
      <% end %>

      <%= if @show_edit_modal do %>
        <%= render_edit_modal(assigns) %>
      <% end %>

      <%= if @show_delete_modal do %>
        <%= render_delete_modal(assigns) %>
      <% end %>

      <%= if @show_add_agents_modal do %>
        <%= render_add_agents_modal(assigns) %>
      <% end %>
    </div>
    """
  end

  defp render_groups_list(assigns) do
    ~H"""
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
      <%= for group <- @groups do %>
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6 hover:shadow-lg transition-shadow">
          <div class="flex items-start justify-between mb-4">
            <div class="flex items-center">
              <%= if group.color do %>
                <div
                  class="w-4 h-4 rounded-full mr-3"
                  style={"background-color: #{group.color}"}
                >
                </div>
              <% end %>
              <h3 class="text-lg font-semibold text-gray-900 dark:text-white">
                <%= group.name %>
              </h3>
            </div>
            <div class="flex space-x-2">
              <button
                phx-click="edit_group"
                phx-value-id={group.id}
                class="text-gray-500 hover:text-indigo-600"
              >
                <svg
                  class="w-5 h-5"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"
                  />
                </svg>
              </button>
              <button
                phx-click="delete_group"
                phx-value-id={group.id}
                class="text-gray-500 hover:text-red-600"
              >
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                  />
                </svg>
              </button>
            </div>
          </div>

          <%= if group.description do %>
            <p class="text-sm text-gray-600 dark:text-gray-400 mb-4">
              <%= group.description %>
            </p>
          <% end %>

          <%= if group.tags && length(group.tags) > 0 do %>
            <div class="flex flex-wrap gap-2 mb-4">
              <%= for tag <- group.tags do %>
                <span class="px-2 py-1 text-xs bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded">
                  <%= tag %>
                </span>
              <% end %>
            </div>
          <% end %>

          <div class="border-t dark:border-gray-700 pt-4 mt-4">
            <div class="grid grid-cols-3 gap-4 text-center mb-4">
              <div>
                <div class="text-2xl font-bold text-gray-900 dark:text-white">
                  <%= count_group_agents(group.id, @organization_id) %>
                </div>
                <div class="text-xs text-gray-500 dark:text-gray-400">Agents</div>
              </div>
              <div>
                <div class="text-2xl font-bold text-green-600">
                  <%= count_group_agents(group.id, @organization_id, status: "online") %>
                </div>
                <div class="text-xs text-gray-500 dark:text-gray-400">Online</div>
              </div>
              <div>
                <div class="text-2xl font-bold text-red-600">
                  <%= count_group_agents(group.id, @organization_id, status: "isolated") %>
                </div>
                <div class="text-xs text-gray-500 dark:text-gray-400">Isolated</div>
              </div>
            </div>

            <.link
              navigate={~p"/agent_groups/#{group.id}"}
              class="block w-full text-center px-4 py-2 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-200 dark:hover:bg-gray-600"
            >
              View Details
            </.link>
          </div>
        </div>
      <% end %>

      <%= if @groups == [] do %>
        <div class="col-span-3 text-center py-12">
          <p class="text-gray-500 dark:text-gray-400 mb-4">No groups created yet</p>
          <button
            phx-click="show_create_modal"
            class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
          >
            Create Your First Group
          </button>
        </div>
      <% end %>
    </div>
    """
  end

  defp render_group_detail(assigns) do
    ~H"""
    <div class="space-y-6">
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
        <div class="flex items-center justify-between mb-6">
          <div class="flex items-center">
            <%= if @selected_group.color do %>
              <div
                class="w-6 h-6 rounded-full mr-4"
                style={"background-color: #{@selected_group.color}"}
              >
              </div>
            <% end %>
            <div>
              <h2 class="text-2xl font-bold text-gray-900 dark:text-white">
                <%= @selected_group.name %>
              </h2>
              <%= if @selected_group.description do %>
                <p class="text-gray-600 dark:text-gray-400 mt-1">
                  <%= @selected_group.description %>
                </p>
              <% end %>
            </div>
          </div>
          <div class="flex space-x-2">
            <button
              phx-click="add_agents"
              class="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700"
            >
              Add Agents
            </button>
            <button
              phx-click="edit_group"
              phx-value-id={@selected_group.id}
              class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
            >
              Edit Group
            </button>
          </div>
        </div>

        <div class="grid grid-cols-4 gap-4 mb-6">
          <div class="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
            <div class="text-3xl font-bold text-gray-900 dark:text-white">
              <%= @group_stats.total %>
            </div>
            <div class="text-sm text-gray-500 dark:text-gray-400">Total Agents</div>
          </div>
          <div class="bg-green-50 dark:bg-green-900/20 rounded-lg p-4">
            <div class="text-3xl font-bold text-green-600">
              <%= @group_stats.online %>
            </div>
            <div class="text-sm text-gray-500 dark:text-gray-400">Online</div>
          </div>
          <div class="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
            <div class="text-3xl font-bold text-gray-600">
              <%= @group_stats.offline %>
            </div>
            <div class="text-sm text-gray-500 dark:text-gray-400">Offline</div>
          </div>
          <div class="bg-red-50 dark:bg-red-900/20 rounded-lg p-4">
            <div class="text-3xl font-bold text-red-600">
              <%= @group_stats.isolated %>
            </div>
            <div class="text-sm text-gray-500 dark:text-gray-400">Isolated</div>
          </div>
        </div>

        <div class="border-t dark:border-gray-700 pt-6">
          <h3 class="text-lg font-semibold mb-4">Batch Actions</h3>
          <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
            <button
              phx-click="batch_isolate"
              class="px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700"
            >
              Isolate All
            </button>
            <button
              phx-click="batch_scan"
              class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
            >
              Scan All
            </button>
            <button
              phx-click="batch_collect_forensics"
              class="px-4 py-2 bg-purple-600 text-white rounded hover:bg-purple-700"
            >
              Collect Forensics
            </button>
            <button
              phx-click="batch_update_config"
              class="px-4 py-2 bg-gray-600 text-white rounded hover:bg-gray-700"
            >
              Update Config
            </button>
          </div>
        </div>
      </div>

      <div class="bg-white dark:bg-gray-800 rounded-lg shadow-md overflow-hidden">
        <div class="px-6 py-4 border-b dark:border-gray-700">
          <h3 class="text-lg font-semibold">Group Members</h3>
        </div>
        <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead class="bg-gray-50 dark:bg-gray-700">
            <tr>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
                Hostname
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
                IP Address
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
                OS
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
                Status
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
                Added
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
                Actions
              </th>
            </tr>
          </thead>
          <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
            <%= for agent <- @group_agents do %>
              <tr>
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-white">
                  <%= agent.hostname %>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                  <%= agent.ip_address %>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                  <%= agent.os_type %>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <span class={"px-2 inline-flex text-xs leading-5 font-semibold rounded-full #{status_color(agent.status)}"}>
                    <%= agent.status %>
                  </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                  <%= format_datetime(agent.added_to_group_at) %>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                  <button
                    phx-click="remove_agent"
                    phx-value-agent-id={agent.agent_id}
                    class="text-red-600 hover:text-red-900"
                  >
                    Remove
                  </button>
                </td>
              </tr>
            <% end %>
          </tbody>
        </table>
      </div>
    </div>
    """
  end

  defp render_create_modal(assigns) do
    ~H"""
    <div class="fixed z-10 inset-0 overflow-y-auto">
      <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
        <div
          class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity"
          phx-click="hide_create_modal"
        >
        </div>
        <div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
          <form phx-submit="create_group">
            <div class="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
              <h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white mb-4">
                Create Agent Group
              </h3>
              <div class="space-y-4">
                <div>
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Name
                  </label>
                  <input
                    type="text"
                    name="name"
                    required
                    class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
                  />
                </div>
                <div>
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Description
                  </label>
                  <textarea
                    name="description"
                    rows="3"
                    class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
                  ></textarea>
                </div>
                <div>
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Color
                  </label>
                  <input
                    type="color"
                    name="color"
                    class="w-full h-10 border border-gray-300 dark:border-gray-600 rounded-md"
                  />
                </div>
                <div>
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Tags (comma-separated)
                  </label>
                  <input
                    type="text"
                    name="tags"
                    placeholder="e.g., production, critical, windows"
                    class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
                  />
                </div>
              </div>
            </div>
            <div class="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
              <button
                type="submit"
                class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-indigo-600 text-base font-medium text-white hover:bg-indigo-700 focus:outline-none sm:ml-3 sm:w-auto sm:text-sm"
              >
                Create
              </button>
              <button
                phx-click="hide_create_modal"
                type="button"
                class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
    """
  end

  defp render_edit_modal(assigns) do
    ~H"""
    <div class="fixed z-10 inset-0 overflow-y-auto">
      <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
        <div
          class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity"
          phx-click="hide_edit_modal"
        >
        </div>
        <div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
          <form phx-submit="update_group">
            <div class="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
              <h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white mb-4">
                Edit Agent Group
              </h3>
              <div class="space-y-4">
                <div>
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Name
                  </label>
                  <input
                    type="text"
                    name="name"
                    value={@selected_group && @selected_group.name}
                    required
                    class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
                  />
                </div>
                <div>
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Description
                  </label>
                  <textarea
                    name="description"
                    rows="3"
                    class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
                  ><%= @selected_group && @selected_group.description %></textarea>
                </div>
                <div>
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Color
                  </label>
                  <input
                    type="color"
                    name="color"
                    value={@selected_group && @selected_group.color || "#3B82F6"}
                    class="w-full h-10 border border-gray-300 dark:border-gray-600 rounded-md"
                  />
                </div>
                <div>
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Tags (comma-separated)
                  </label>
                  <input
                    type="text"
                    name="tags"
                    value={@selected_group && Enum.join(@selected_group.tags || [], ", ")}
                    class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
                  />
                </div>
              </div>
            </div>
            <div class="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
              <button
                type="submit"
                class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-indigo-600 text-base font-medium text-white hover:bg-indigo-700 focus:outline-none sm:ml-3 sm:w-auto sm:text-sm"
              >
                Update
              </button>
              <button
                phx-click="hide_edit_modal"
                type="button"
                class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
    """
  end

  defp render_delete_modal(assigns) do
    ~H"""
    <div class="fixed z-10 inset-0 overflow-y-auto">
      <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
        <div
          class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity"
          phx-click="hide_delete_modal"
        >
        </div>
        <div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
          <div class="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
            <div class="sm:flex sm:items-start">
              <div class="mx-auto flex-shrink-0 flex items-center justify-center h-12 w-12 rounded-full bg-red-100 sm:mx-0 sm:h-10 sm:w-10">
                <span class="text-red-600 text-2xl">!</span>
              </div>
              <div class="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left">
                <h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white">
                  Delete Group
                </h3>
                <div class="mt-2">
                  <p class="text-sm text-gray-500 dark:text-gray-400">
                    Are you sure you want to delete this group? This action cannot be undone.
                    Agents will not be deleted, only removed from this group.
                  </p>
                </div>
              </div>
            </div>
          </div>
          <div class="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
            <button
              phx-click="confirm_delete"
              type="button"
              class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-red-600 text-base font-medium text-white hover:bg-red-700 focus:outline-none sm:ml-3 sm:w-auto sm:text-sm"
            >
              Delete
            </button>
            <button
              phx-click="hide_delete_modal"
              type="button"
              class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
            >
              Cancel
            </button>
          </div>
        </div>
      </div>
    </div>
    """
  end

  defp render_add_agents_modal(assigns) do
    ~H"""
    <div class="fixed z-10 inset-0 overflow-y-auto">
      <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
        <div
          class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity"
          phx-click="hide_add_agents_modal"
        >
        </div>
        <div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-2xl sm:w-full">
          <div class="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
            <h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white mb-4">
              Add Agents to Group
            </h3>
            <p class="text-sm text-gray-500 dark:text-gray-400 mb-4">
              Select agents to add to this group. Coming soon: multi-select interface.
            </p>
          </div>
          <div class="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
            <button
              phx-click="hide_add_agents_modal"
              type="button"
              class="w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none sm:ml-3 sm:w-auto sm:text-sm"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
    """
  end

  @impl true
  def handle_event("show_create_modal", _params, socket) do
    {:noreply, assign(socket, :show_create_modal, true)}
  end

  @impl true
  def handle_event("hide_create_modal", _params, socket) do
    {:noreply, assign(socket, :show_create_modal, false)}
  end

  @impl true
  def handle_event("create_group", params, socket) do
    tags =
      params["tags"]
      |> String.split(",")
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&(&1 == ""))

    attrs = %{
      name: params["name"],
      description: params["description"],
      color: params["color"],
      tags: tags
    }

    case GroupManager.create_group(socket.assigns.organization_id, attrs) do
      {:ok, _group} ->
        {:noreply,
         socket
         |> put_flash(:info, "Group created successfully")
         |> assign(:show_create_modal, false)
         |> load_groups()}

      {:error, changeset} ->
        {:noreply,
         socket
         |> put_flash(:error, "Failed to create group: #{format_errors(changeset)}")}
    end
  end

  @impl true
  def handle_event("edit_group", %{"id" => id}, socket) do
    case GroupManager.get_group(socket.assigns.organization_id, id) do
      {:ok, group} ->
        {:noreply,
         socket
         |> assign(:selected_group, group)
         |> assign(:show_edit_modal, true)}

      {:error, :not_found} ->
        {:noreply, put_flash(socket, :error, "Group not found")}
    end
  end

  @impl true
  def handle_event("hide_edit_modal", _params, socket) do
    {:noreply, assign(socket, :show_edit_modal, false)}
  end

  @impl true
  def handle_event("update_group", params, socket) do
    tags =
      params["tags"]
      |> String.split(",")
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&(&1 == ""))

    attrs = %{
      name: params["name"],
      description: params["description"],
      color: params["color"],
      tags: tags
    }

    case GroupManager.update_group(socket.assigns.selected_group, attrs) do
      {:ok, _group} ->
        {:noreply,
         socket
         |> put_flash(:info, "Group updated successfully")
         |> assign(:show_edit_modal, false)
         |> load_groups()}

      {:error, changeset} ->
        {:noreply,
         socket
         |> put_flash(:error, "Failed to update group: #{format_errors(changeset)}")}
    end
  end

  @impl true
  def handle_event("delete_group", %{"id" => id}, socket) do
    case GroupManager.get_group(socket.assigns.organization_id, id) do
      {:ok, group} ->
        {:noreply,
         socket
         |> assign(:selected_group, group)
         |> assign(:show_delete_modal, true)}

      {:error, :not_found} ->
        {:noreply, put_flash(socket, :error, "Group not found")}
    end
  end

  @impl true
  def handle_event("hide_delete_modal", _params, socket) do
    {:noreply, assign(socket, :show_delete_modal, false)}
  end

  @impl true
  def handle_event("confirm_delete", _params, socket) do
    case GroupManager.delete_group(socket.assigns.selected_group) do
      {:ok, _} ->
        {:noreply,
         socket
         |> put_flash(:info, "Group deleted successfully")
         |> assign(:show_delete_modal, false)
         |> load_groups()}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Failed to delete group")}
    end
  end

  @impl true
  def handle_event("add_agents", _params, socket) do
    {:noreply, assign(socket, :show_add_agents_modal, true)}
  end

  @impl true
  def handle_event("hide_add_agents_modal", _params, socket) do
    {:noreply, assign(socket, :show_add_agents_modal, false)}
  end

  @impl true
  def handle_event("remove_agent", %{"agent-id" => agent_id}, socket) do
    case GroupManager.remove_agent_from_group(agent_id, socket.assigns.selected_group.id) do
      {:ok, _} ->
        {:noreply,
         socket
         |> put_flash(:info, "Agent removed from group")
         |> assign(:group_agents, GroupManager.list_group_agents(socket.assigns.selected_group.id))
         |> assign(:group_stats, GroupManager.get_group_stats(socket.assigns.selected_group.id))}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Failed to remove agent")}
    end
  end

  @impl true
  def handle_event("batch_isolate", _params, socket) do
    group_id = socket.assigns.selected_group.id

    case GroupManager.execute_batch_command_on_group(
           group_id,
           "isolate_network",
           %{},
           initiated_by: "admin"
         ) do
      {:ok, batch} ->
        {:noreply,
         socket
         |> put_flash(:info, "Batch isolation command initiated (#{batch.total_count} agents)")
         |> push_navigate(to: ~p"/batch_commands/#{batch.id}")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to initiate batch command: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("batch_scan", _params, socket) do
    group_id = socket.assigns.selected_group.id
    os_type = get_primary_os_type(socket.assigns.group_agents)
    default_path = get_default_scan_path(os_type)

    case GroupManager.execute_batch_command_on_group(
           group_id,
           "scan_path",
           %{path: default_path, recursive: true},
           initiated_by: "admin"
         ) do
      {:ok, batch} ->
        {:noreply,
         socket
         |> put_flash(:info, "Batch scan command initiated (#{batch.total_count} agents)")
         |> push_navigate(to: ~p"/batch_commands/#{batch.id}")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to initiate batch command: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("batch_collect_forensics", _params, socket) do
    group_id = socket.assigns.selected_group.id

    case GroupManager.execute_batch_command_on_group(
           group_id,
           "collect_forensics",
           %{process_list: true, network_connections: true},
           initiated_by: "admin"
         ) do
      {:ok, batch} ->
        {:noreply,
         socket
         |> put_flash(:info, "Batch forensics collection initiated (#{batch.total_count} agents)")
         |> push_navigate(to: ~p"/batch_commands/#{batch.id}")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to initiate batch command: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("batch_update_config", _params, socket) do
    {:noreply, put_flash(socket, :info, "Batch config update coming soon")}
  end

  defp load_groups(socket) do
    groups = GroupManager.list_groups(socket.assigns.organization_id)
    assign(socket, :groups, groups)
  end

  defp count_group_agents(group_id, _organization_id, opts \\ []) do
    GroupManager.count_group_agents(group_id, opts)
  end

  defp status_color("online"), do: "bg-green-100 text-green-800"
  defp status_color("offline"), do: "bg-gray-100 text-gray-800"
  defp status_color("isolated"), do: "bg-red-100 text-red-800"
  defp status_color(_), do: "bg-gray-100 text-gray-800"

  defp format_datetime(nil), do: "N/A"

  defp format_datetime(datetime) do
    Calendar.strftime(datetime, "%Y-%m-%d %H:%M")
  end

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, _opts} -> msg end)
    |> Enum.map(fn {field, errors} -> "#{field}: #{Enum.join(errors, ", ")}" end)
    |> Enum.join("; ")
  end

  defp get_default_org_id do
    # In a real implementation, this would come from session or user context
    "default-org-id"
  end

  defp get_primary_os_type(agents) do
    agents
    |> Enum.frequencies_by(& &1.os_type)
    |> Enum.max_by(fn {_os, count} -> count end, fn -> {"windows", 0} end)
    |> elem(0)
  end

  defp get_default_scan_path("windows"), do: "C:\\"
  defp get_default_scan_path("linux"), do: "/"
  defp get_default_scan_path("macos"), do: "/"
  defp get_default_scan_path(_), do: "/"
end
