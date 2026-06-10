defmodule TamanduaServerWeb.BreachDetailLive do
  @moduledoc """
  LiveView for displaying breach details and credential management.

  Features:
  - Breach information display
  - List of compromised credentials
  - Response workflow management
  - Manual response action triggers
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServer.DarkWeb
  alias TamanduaServer.DarkWeb.BreachResponder
  alias Phoenix.PubSub

  @impl true
  def mount(%{"id" => credential_id}, _session, socket) do
    if connected?(socket) do
      PubSub.subscribe(TamanduaServer.PubSub, "dark_web:credential:#{credential_id}")
    end

    case DarkWeb.get_credential!(credential_id) do
      nil ->
        {:ok,
         socket
         |> put_flash(:error, "Credential not found")
         |> redirect(to: ~p"/dark-web")}

      credential ->
        workflows = DarkWeb.list_workflows(credential_id: credential.id)

        {:ok,
         socket
         |> assign(:page_title, "Breach Detail")
         |> assign(:credential, credential)
         |> assign(:workflows, workflows)
         |> assign(:selected_actions, [])}
    end
  end

  @impl true
  def handle_params(_params, _url, socket) do
    {:noreply, socket}
  end

  @impl true
  def handle_event("toggle_action", %{"action" => action}, socket) do
    action_atom = String.to_atom(action)
    selected = socket.assigns.selected_actions

    new_selected =
      if action_atom in selected do
        List.delete(selected, action_atom)
      else
        [action_atom | selected]
      end

    {:noreply, assign(socket, :selected_actions, new_selected)}
  end

  @impl true
  def handle_event("execute_actions", _params, socket) do
    %{credential: credential, selected_actions: actions} = socket.assigns

    if Enum.empty?(actions) do
      {:noreply, put_flash(socket, :error, "Please select at least one action")}
    else
      case BreachResponder.handle_compromise(credential, actions: actions) do
        {:ok, _workflows} ->
          workflows = DarkWeb.list_workflows(credential_id: credential.id)

          {:noreply,
           socket
           |> put_flash(:info, "Response actions executed successfully")
           |> assign(:workflows, workflows)
           |> assign(:selected_actions, [])}

        {:error, reason} ->
          {:noreply, put_flash(socket, :error, "Failed to execute actions: #{inspect(reason)}")}
      end
    end
  end

  @impl true
  def handle_event("update_status", %{"status" => status}, socket) do
    credential = socket.assigns.credential

    case DarkWeb.update_credential(credential, %{status: status}) do
      {:ok, updated_credential} ->
        {:noreply,
         socket
         |> put_flash(:info, "Status updated to #{status}")
         |> assign(:credential, updated_credential)}

      {:error, _changeset} ->
        {:noreply, put_flash(socket, :error, "Failed to update status")}
    end
  end

  @impl true
  def handle_info({:credential_updated, credential}, socket) do
    {:noreply, assign(socket, :credential, credential)}
  end

  @impl true
  def handle_info(_msg, socket), do: {:noreply, socket}

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6 max-w-7xl mx-auto">
      <!-- Header -->
      <div class="flex items-center justify-between mb-6">
        <div class="flex items-center gap-4">
          <.link navigate={~p"/dark-web"} class="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" />
            </svg>
          </.link>
          <h1 class="text-2xl font-bold text-gray-900 dark:text-white">Compromised Credential</h1>
        </div>

        <div class="flex gap-2">
          <span class={[
            "px-3 py-1 text-sm font-semibold rounded-full",
            severity_badge_class(@credential.severity)
          ]}>
            <%= String.upcase(@credential.severity) %>
          </span>
          <span class={[
            "px-3 py-1 text-sm font-semibold rounded-full",
            status_badge_class(@credential.status)
          ]}>
            <%= format_status(@credential.status) %>
          </span>
        </div>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Main Content -->
        <div class="lg:col-span-2 space-y-6">
          <!-- Credential Information -->
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <h2 class="text-xl font-bold mb-4 text-gray-900 dark:text-white">Credential Information</h2>

            <div class="grid grid-cols-2 gap-4">
              <div>
                <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Email</dt>
                <dd class="mt-1 text-sm text-gray-900 dark:text-white font-mono">
                  <%= @credential.email %>
                </dd>
              </div>

              <%= if @credential.username do %>
                <div>
                  <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Username</dt>
                  <dd class="mt-1 text-sm text-gray-900 dark:text-white font-mono">
                    <%= @credential.username %>
                  </dd>
                </div>
              <% end %>

              <div>
                <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Domain</dt>
                <dd class="mt-1 text-sm text-gray-900 dark:text-white">
                  <%= @credential.domain %>
                </dd>
              </div>

              <div>
                <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Source</dt>
                <dd class="mt-1 text-sm text-gray-900 dark:text-white">
                  <%= String.upcase(@credential.source) %>
                </dd>
              </div>

              <div>
                <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">First Seen</dt>
                <dd class="mt-1 text-sm text-gray-900 dark:text-white">
                  <%= format_datetime(@credential.first_seen) %>
                </dd>
              </div>

              <%= if @credential.last_seen do %>
                <div>
                  <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Last Seen</dt>
                  <dd class="mt-1 text-sm text-gray-900 dark:text-white">
                    <%= format_datetime(@credential.last_seen) %>
                  </dd>
                </div>
              <% end %>
            </div>

            <%= if @credential.user do %>
              <div class="mt-6 pt-6 border-t border-gray-200 dark:border-gray-700">
                <h3 class="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Matched User</h3>
                <div class="flex items-center gap-3">
                  <div class="w-10 h-10 bg-blue-100 dark:bg-blue-900/30 rounded-full flex items-center justify-center">
                    <span class="text-blue-600 dark:text-blue-400 font-semibold">
                      <%= String.first(@credential.user.name || @credential.user.email) %>
                    </span>
                  </div>
                  <div>
                    <div class="text-sm font-medium text-gray-900 dark:text-white">
                      <%= @credential.user.name || @credential.user.email %>
                    </div>
                    <div class="text-xs text-gray-500 dark:text-gray-400">
                      Role: <%= @credential.user.role %>
                    </div>
                  </div>
                </div>
              </div>
            <% end %>
          </div>

          <!-- Breach Information -->
          <%= if @credential.breach do %>
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <h2 class="text-xl font-bold mb-4 text-gray-900 dark:text-white">Breach Information</h2>

              <div class="space-y-4">
                <div>
                  <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Breach Name</dt>
                  <dd class="mt-1 text-lg font-semibold text-gray-900 dark:text-white">
                    <%= @credential.breach.breach_name %>
                  </dd>
                </div>

                <%= if @credential.breach.description do %>
                  <div>
                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Description</dt>
                    <dd class="mt-1 text-sm text-gray-700 dark:text-gray-300">
                      <%= @credential.breach.description %>
                    </dd>
                  </div>
                <% end %>

                <div class="grid grid-cols-2 gap-4">
                  <%= if @credential.breach.breach_date do %>
                    <div>
                      <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Breach Date</dt>
                      <dd class="mt-1 text-sm text-gray-900 dark:text-white">
                        <%= format_datetime(@credential.breach.breach_date) %>
                      </dd>
                    </div>
                  <% end %>

                  <%= if @credential.breach.pwn_count do %>
                    <div>
                      <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Pwn Count</dt>
                      <dd class="mt-1 text-sm text-gray-900 dark:text-white">
                        <%= Number.Delimiters.number_to_delimited(@credential.breach.pwn_count) %>
                      </dd>
                    </div>
                  <% end %>
                </div>

                <%= if @credential.breach.data_classes && length(@credential.breach.data_classes) > 0 do %>
                  <div>
                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Data Exposed</dt>
                    <dd class="flex flex-wrap gap-2">
                      <%= for data_class <- @credential.breach.data_classes do %>
                        <span class="px-2 py-1 text-xs bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300 rounded-full">
                          <%= data_class %>
                        </span>
                      <% end %>
                    </dd>
                  </div>
                <% end %>
              </div>
            </div>
          <% end %>

          <!-- Response Workflows -->
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <h2 class="text-xl font-bold mb-4 text-gray-900 dark:text-white">Response History</h2>

            <%= if Enum.empty?(@workflows) do %>
              <p class="text-gray-600 dark:text-gray-400 text-sm">No response actions taken yet.</p>
            <% else %>
              <div class="space-y-3">
                <%= for workflow <- @workflows do %>
                  <div class="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <div class="flex items-center justify-between mb-2">
                      <div class="text-sm font-medium text-gray-900 dark:text-white">
                        <%= format_workflow_type(workflow.workflow_type) %>
                      </div>
                      <span class={[
                        "px-2 py-1 text-xs font-semibold rounded-full",
                        workflow_status_class(workflow.status)
                      ]}>
                        <%= String.upcase(workflow.status) %>
                      </span>
                    </div>
                    <div class="text-xs text-gray-500 dark:text-gray-400">
                      Triggered: <%= format_datetime(workflow.triggered_at) %>
                      <%= if workflow.completed_at do %>
                        • Completed: <%= format_datetime(workflow.completed_at) %>
                      <% end %>
                    </div>
                    <%= if workflow.error_message do %>
                      <div class="mt-2 text-xs text-red-600 dark:text-red-400">
                        Error: <%= workflow.error_message %>
                      </div>
                    <% end %>
                  </div>
                <% end %>
              </div>
            <% end %>
          </div>
        </div>

        <!-- Sidebar -->
        <div class="space-y-6">
          <!-- Status Update -->
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <h3 class="text-lg font-semibold mb-4 text-gray-900 dark:text-white">Update Status</h3>

            <div class="space-y-2">
              <%= for status <- ["new", "investigating", "resolved", "false_positive"] do %>
                <button
                  phx-click="update_status"
                  phx-value-status={status}
                  class={[
                    "w-full px-4 py-2 text-sm font-medium rounded-lg text-left transition-colors",
                    if(@credential.status == status,
                      do: "bg-blue-600 text-white",
                      else: "bg-gray-100 dark:bg-gray-700 text-gray-900 dark:text-white hover:bg-gray-200 dark:hover:bg-gray-600"
                    )
                  ]}
                >
                  <%= format_status(status) %>
                </button>
              <% end %>
            </div>
          </div>

          <!-- Response Actions -->
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <h3 class="text-lg font-semibold mb-4 text-gray-900 dark:text-white">Response Actions</h3>

            <div class="space-y-2 mb-4">
              <%= for action <- [:password_reset, :account_disable, :mfa_enforce, :user_notify, :security_team_notify, :create_incident] do %>
                <label class="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    phx-click="toggle_action"
                    phx-value-action={action}
                    checked={action in @selected_actions}
                    class="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                  <span class="text-sm text-gray-900 dark:text-white">
                    <%= format_workflow_type(Atom.to_string(action)) %>
                  </span>
                </label>
              <% end %>
            </div>

            <button
              phx-click="execute_actions"
              disabled={Enum.empty?(@selected_actions)}
              class={[
                "w-full px-4 py-2 rounded-lg font-medium transition-colors",
                if(Enum.empty?(@selected_actions),
                  do: "bg-gray-300 dark:bg-gray-600 text-gray-500 dark:text-gray-400 cursor-not-allowed",
                  else: "bg-blue-600 hover:bg-blue-700 text-white"
                )
              ]}
            >
              Execute Selected Actions
            </button>
          </div>
        </div>
      </div>
    </div>
    """
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp severity_badge_class("critical"), do: "bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300"
  defp severity_badge_class("high"), do: "bg-orange-100 dark:bg-orange-900/30 text-orange-800 dark:text-orange-300"
  defp severity_badge_class("medium"), do: "bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300"
  defp severity_badge_class("low"), do: "bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300"
  defp severity_badge_class(_), do: "bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300"

  defp status_badge_class("new"), do: "bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300"
  defp status_badge_class("investigating"), do: "bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300"
  defp status_badge_class("resolved"), do: "bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300"
  defp status_badge_class("false_positive"), do: "bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300"
  defp status_badge_class(_), do: "bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300"

  defp workflow_status_class("pending"), do: "bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300"
  defp workflow_status_class("in_progress"), do: "bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300"
  defp workflow_status_class("completed"), do: "bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300"
  defp workflow_status_class("failed"), do: "bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300"
  defp workflow_status_class(_), do: "bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300"

  defp format_status(status) do
    status
    |> String.replace("_", " ")
    |> String.capitalize()
  end

  defp format_workflow_type(type) do
    type
    |> String.replace("_", " ")
    |> String.capitalize()
  end

  defp format_datetime(nil), do: "N/A"

  defp format_datetime(datetime) do
    Calendar.strftime(datetime, "%Y-%m-%d %H:%M")
  end
end
