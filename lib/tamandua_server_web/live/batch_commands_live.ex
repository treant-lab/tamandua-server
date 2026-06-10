defmodule TamanduaServerWeb.BatchCommandsLive do
  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Agents.GroupManager

  @impl true
  def mount(_params, session, socket) do
    organization_id = session["organization_id"] || get_default_org_id()

    {:ok,
     socket
     |> assign(:organization_id, organization_id)
     |> assign(:page_title, "Batch Commands")
     |> assign(:batch_commands, [])
     |> assign(:selected_batch, nil)
     |> load_batch_commands()}
  end

  @impl true
  def handle_params(params, _url, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end

  defp apply_action(socket, :index, _params) do
    socket
    |> assign(:page_title, "Batch Commands")
    |> assign(:selected_batch, nil)
  end

  defp apply_action(socket, :show, %{"id" => id}) do
    case GroupManager.get_batch_command(id) do
      {:ok, batch} ->
        # Set up auto-refresh if batch is still running
        if batch.status in ["pending", "running"] do
          Process.send_after(self(), :refresh, 2000)
        end

        socket
        |> assign(:page_title, "Batch Command: #{batch.command_type}")
        |> assign(:selected_batch, batch)
        |> assign(:results, batch.results)

      {:error, :not_found} ->
        socket
        |> put_flash(:error, "Batch command not found")
        |> push_navigate(to: ~p"/batch_commands")
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-2xl font-bold"><%= @page_title %></h1>
        <%= if @live_action == :show do %>
          <.link navigate={~p"/batch_commands"} class="text-blue-600 hover:underline">
            &larr; Back to Batch Commands
          </.link>
        <% end %>
      </div>

      <%= if @live_action == :index do %>
        <%= render_batch_list(assigns) %>
      <% end %>

      <%= if @live_action == :show and @selected_batch do %>
        <%= render_batch_detail(assigns) %>
      <% end %>
    </div>
    """
  end

  defp render_batch_list(assigns) do
    ~H"""
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
      <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
        <thead class="bg-gray-50 dark:bg-gray-700">
          <tr>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
              Command Type
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
              Target
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
              Status
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
              Progress
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
              Initiated
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
              Actions
            </th>
          </tr>
        </thead>
        <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
          <%= for batch <- @batch_commands do %>
            <tr>
              <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-white">
                <%= format_command_type(batch.command_type) %>
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                <%= format_target(batch) %>
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <span class={"px-2 inline-flex text-xs leading-5 font-semibold rounded-full #{status_color(batch.status)}"}>
                  <%= batch.status %>
                </span>
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                <%= render_progress(batch) %>
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                <%= format_datetime(batch.inserted_at) %>
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                <.link navigate={~p"/batch_commands/#{batch.id}"} class="text-indigo-600 hover:text-indigo-900 mr-4">
                  View
                </.link>
                <%= if batch.status in ["pending", "running"] do %>
                  <button phx-click="cancel_batch" phx-value-id={batch.id} class="text-red-600 hover:text-red-900">
                    Cancel
                  </button>
                <% end %>
              </td>
            </tr>
          <% end %>
        </tbody>
      </table>

      <%= if @batch_commands == [] do %>
        <div class="text-center py-12">
          <p class="text-gray-500 dark:text-gray-400">No batch commands executed yet</p>
        </div>
      <% end %>
    </div>
    """
  end

  defp render_batch_detail(assigns) do
    ~H"""
    <div class="space-y-6">
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
        <div class="flex items-center justify-between mb-6">
          <div>
            <h2 class="text-2xl font-bold text-gray-900 dark:text-white">
              <%= format_command_type(@selected_batch.command_type) %>
            </h2>
            <p class="text-gray-600 dark:text-gray-400 mt-1">
              Initiated by <%= @selected_batch.initiated_by || "Unknown" %> on <%= format_datetime(@selected_batch.inserted_at) %>
            </p>
          </div>
          <span class={"px-4 py-2 text-sm font-semibold rounded-full #{status_color(@selected_batch.status)}"}>
            <%= @selected_batch.status %>
          </span>
        </div>

        <div class="grid grid-cols-4 gap-4 mb-6">
          <div class="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
            <div class="text-3xl font-bold text-gray-900 dark:text-white">
              <%= @selected_batch.total_count %>
            </div>
            <div class="text-sm text-gray-500 dark:text-gray-400">Total Agents</div>
          </div>
          <div class="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-4">
            <div class="text-3xl font-bold text-blue-600">
              <%= @selected_batch.completed_count %>
            </div>
            <div class="text-sm text-gray-500 dark:text-gray-400">Completed</div>
          </div>
          <div class="bg-green-50 dark:bg-green-900/20 rounded-lg p-4">
            <div class="text-3xl font-bold text-green-600">
              <%= @selected_batch.success_count %>
            </div>
            <div class="text-sm text-gray-500 dark:text-gray-400">Successful</div>
          </div>
          <div class="bg-red-50 dark:bg-red-900/20 rounded-lg p-4">
            <div class="text-3xl font-bold text-red-600">
              <%= @selected_batch.failed_count %>
            </div>
            <div class="text-sm text-gray-500 dark:text-gray-400">Failed</div>
          </div>
        </div>

        <div class="mb-6">
          <div class="flex items-center justify-between mb-2">
            <span class="text-sm font-medium text-gray-700 dark:text-gray-300">Progress</span>
            <span class="text-sm font-medium text-gray-700 dark:text-gray-300">
              <%= percentage(@selected_batch.completed_count, @selected_batch.total_count) %>%
            </span>
          </div>
          <div class="w-full bg-gray-200 rounded-full h-2.5 dark:bg-gray-700">
            <div
              class="bg-blue-600 h-2.5 rounded-full transition-all duration-500"
              style={"width: #{percentage(@selected_batch.completed_count, @selected_batch.total_count)}%"}
            >
            </div>
          </div>
        </div>

        <%= if @selected_batch.command_params && map_size(@selected_batch.command_params) > 0 do %>
          <div class="border-t dark:border-gray-700 pt-4">
            <h3 class="text-sm font-semibold mb-2">Command Parameters</h3>
            <pre class="bg-gray-50 dark:bg-gray-900 p-3 rounded text-xs overflow-x-auto"><%= Jason.encode!(@selected_batch.command_params, pretty: true) %></pre>
          </div>
        <% end %>
      </div>

      <div class="bg-white dark:bg-gray-800 rounded-lg shadow-md overflow-hidden">
        <div class="px-6 py-4 border-b dark:border-gray-700">
          <h3 class="text-lg font-semibold">Agent Results</h3>
        </div>
        <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead class="bg-gray-50 dark:bg-gray-700">
            <tr>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
                Agent ID
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
                Status
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
                Started
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
                Completed
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
                Result
              </th>
            </tr>
          </thead>
          <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
            <%= for result <- @results do %>
              <tr>
                <td class="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900 dark:text-white">
                  <%= String.slice(result.agent_id, 0..7) %>...
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <span class={"px-2 inline-flex text-xs leading-5 font-semibold rounded-full #{result_status_color(result.status)}"}>
                    <%= result.status %>
                  </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                  <%= format_datetime(result.started_at) %>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                  <%= format_datetime(result.completed_at) %>
                </td>
                <td class="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">
                  <%= if result.status == "failed" do %>
                    <span class="text-red-600"><%= result.error %></span>
                  <% else %>
                    <%= if result.result do %>
                      <span class="text-green-600">Success</span>
                    <% else %>
                      -
                    <% end %>
                  <% end %>
                </td>
              </tr>
            <% end %>
          </tbody>
        </table>
      </div>
    </div>
    """
  end

  @impl true
  def handle_event("cancel_batch", %{"id" => id}, socket) do
    case GroupManager.cancel_batch_command(id) do
      {:ok, _} ->
        {:noreply,
         socket
         |> put_flash(:info, "Batch command cancelled")
         |> load_batch_commands()}

      {:error, :cannot_cancel} ->
        {:noreply, put_flash(socket, :error, "Cannot cancel batch command in current state")}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Failed to cancel batch command")}
    end
  end

  @impl true
  def handle_info(:refresh, socket) do
    if socket.assigns.selected_batch do
      case GroupManager.get_batch_command(socket.assigns.selected_batch.id) do
        {:ok, batch} ->
          # Schedule next refresh if still running
          if batch.status in ["pending", "running"] do
            Process.send_after(self(), :refresh, 2000)
          end

          {:noreply,
           socket
           |> assign(:selected_batch, batch)
           |> assign(:results, batch.results)}

        {:error, _} ->
          {:noreply, socket}
      end
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_info(_msg, socket), do: {:noreply, socket}

  defp load_batch_commands(socket) do
    batch_commands = GroupManager.list_batch_commands(socket.assigns.organization_id, limit: 50)
    assign(socket, :batch_commands, batch_commands)
  end

  defp format_command_type(type) do
    type
    |> String.replace("_", " ")
    |> String.split()
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  defp format_target(%{target_type: "group", group: group}) when not is_nil(group) do
    "Group: #{group.name}"
  end

  defp format_target(%{target_type: "agents", total_count: count}) do
    "#{count} Agents"
  end

  defp format_target(%{target_type: type}) do
    String.capitalize(type)
  end

  defp render_progress(batch) do
    if batch.total_count > 0 do
      pct = percentage(batch.completed_count, batch.total_count)
      "#{batch.completed_count}/#{batch.total_count} (#{pct}%)"
    else
      "0/0"
    end
  end

  defp percentage(0, _), do: 0
  defp percentage(_, 0), do: 0
  defp percentage(part, total), do: Float.round(part / total * 100, 1)

  defp status_color("pending"), do: "bg-gray-100 text-gray-800"
  defp status_color("running"), do: "bg-blue-100 text-blue-800"
  defp status_color("completed"), do: "bg-green-100 text-green-800"
  defp status_color("partial_failure"), do: "bg-yellow-100 text-yellow-800"
  defp status_color("failed"), do: "bg-red-100 text-red-800"
  defp status_color("cancelled"), do: "bg-gray-100 text-gray-800"
  defp status_color(_), do: "bg-gray-100 text-gray-800"

  defp result_status_color("pending"), do: "bg-gray-100 text-gray-800"
  defp result_status_color("running"), do: "bg-blue-100 text-blue-800"
  defp result_status_color("completed"), do: "bg-green-100 text-green-800"
  defp result_status_color("failed"), do: "bg-red-100 text-red-800"
  defp result_status_color(_), do: "bg-gray-100 text-gray-800"

  defp format_datetime(nil), do: "-"

  defp format_datetime(datetime) do
    Calendar.strftime(datetime, "%Y-%m-%d %H:%M:%S")
  end

  defp get_default_org_id do
    "default-org-id"
  end
end
