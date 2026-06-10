defmodule TamanduaServerWeb.Components.RemediationActions do
  @moduledoc """
  LiveView component for one-click remediation actions in alert detail view.

  Provides action buttons for:
  - Kill Process (high-risk - requires SecureConfirmation)
  - Quarantine File
  - Isolate Host (high-risk - requires SecureConfirmation)
  - Collect Forensics

  Each action includes:
  - Confirmation modal with impact warnings
  - Password verification for high-risk actions
  - Progress indicators for async operations
  - Success/error notifications
  """
  use TamanduaServerWeb, :live_component

  alias TamanduaServer.Response.Executor
  alias Phoenix.PubSub

  # Actions that require password confirmation via SecureConfirmation
  @high_risk_actions ~w(kill_process isolate_host)

  @impl true
  def mount(socket) do
    {:ok,
     socket
     |> assign(:show_modal, nil)
     |> assign(:executing_action, nil)
     |> assign(:forensics_collection_id, nil)
     |> assign(:pending_secure_action, nil)}
  end

  @impl true
  def update(assigns, socket) do
    socket = assign(socket, assigns)

    # Subscribe to forensics collection updates if we have a collection ID
    if socket.assigns[:forensics_collection_id] do
      PubSub.subscribe(TamanduaServer.PubSub, "forensics:#{socket.assigns.forensics_collection_id}")
    end

    {:ok, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="remediation-actions">
      <div class="flex items-center justify-between mb-4">
        <h3 class="text-lg font-semibold text-[var(--color-foreground)]">Remediation Actions</h3>
        <%= if @executing_action do %>
          <div class="flex items-center text-sm text-[var(--color-primary-500)]">
            <svg class="animate-spin h-4 w-4 mr-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            Executing <%= @executing_action %>...
          </div>
        <% end %>
      </div>

      <div class="grid grid-cols-2 gap-3">
        <!-- Kill Process Button (High Risk) -->
        <%= if has_process_info?(@alert) do %>
          <button
            phx-click="request_secure_action"
            phx-value-action="kill_process"
            phx-target={@myself}
            disabled={@executing_action != nil}
            class="flex items-center justify-center gap-2 px-4 py-3 bg-[var(--color-error-600)] text-white rounded-lg hover:bg-[var(--color-error-700)] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
            Kill Process
            <svg class="w-4 h-4 ml-1 opacity-75" fill="none" stroke="currentColor" viewBox="0 0 24 24" title="Requires password confirmation">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </button>
        <% end %>

        <!-- Quarantine File Button (Standard) -->
        <%= if has_file_info?(@alert) do %>
          <button
            phx-click="show_confirm_modal"
            phx-value-action="quarantine_file"
            phx-target={@myself}
            disabled={@executing_action != nil}
            class="flex items-center justify-center gap-2 px-4 py-3 bg-[var(--color-warning-600)] text-white rounded-lg hover:bg-[var(--color-warning-700)] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
            Quarantine File
          </button>
        <% end %>

        <!-- Isolate Host Button (High Risk) -->
        <button
          phx-click="request_secure_action"
          phx-value-action="isolate_host"
          phx-target={@myself}
          disabled={@executing_action != nil}
          class="flex items-center justify-center gap-2 px-4 py-3 bg-[var(--color-primary-600)] text-white rounded-lg hover:bg-[var(--color-primary-700)] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 5.636a9 9 0 010 12.728m0 0l-2.829-2.829m2.829 2.829L21 21M15.536 8.464a5 5 0 010 7.072m0 0l-2.829-2.829m-4.243 2.829a4.978 4.978 0 01-1.414-2.83m-1.414 5.658a9 9 0 01-2.167-9.238m7.824 2.167a1 1 0 111.414 1.414m-1.414-1.414L3 3" />
          </svg>
          Isolate Host
          <svg class="w-4 h-4 ml-1 opacity-75" fill="none" stroke="currentColor" viewBox="0 0 24 24" title="Requires password confirmation">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
        </button>

        <!-- Collect Forensics Button (Standard) -->
        <button
          phx-click="show_confirm_modal"
          phx-value-action="collect_forensics"
          phx-target={@myself}
          disabled={@executing_action != nil}
          class="flex items-center justify-center gap-2 px-4 py-3 bg-[var(--color-primary-600)] text-white rounded-lg hover:bg-[var(--color-primary-700)] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          Collect Forensics
        </button>
      </div>

      <!-- Standard Confirmation Modal (for non-high-risk actions) -->
      <%= if @show_modal do %>
        <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" phx-window-keydown="close_modal" phx-key="Escape" phx-target={@myself}>
          <div class="bg-[var(--color-neutral-50)] dark:bg-[var(--color-neutral-900)] rounded-lg shadow-xl max-w-md w-full mx-4 border border-[var(--color-border)]">
            <div class="p-6">
              <div class="flex items-center mb-4">
                <%= action_icon(@show_modal) %>
                <h3 class="text-lg font-semibold ml-3 text-[var(--color-foreground)]">
                  Confirm <%= action_title(@show_modal) %>
                </h3>
              </div>

              <div class="mb-6">
                <div class="warning-message mb-4">
                  <div class="flex">
                    <svg class="h-5 w-5 text-[var(--color-warning-400)]" fill="currentColor" viewBox="0 0 20 20">
                      <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                    </svg>
                    <div class="ml-3">
                      <p class="text-sm">
                        <%= action_warning(@show_modal) %>
                      </p>
                    </div>
                  </div>
                </div>

                <p class="text-sm text-[var(--color-muted)]">
                  <%= action_description(@show_modal, @alert) %>
                </p>
              </div>

              <div class="flex gap-3">
                <button
                  phx-click="close_modal"
                  phx-target={@myself}
                  class="btn-outline flex-1"
                >
                  Cancel
                </button>
                <button
                  phx-click="execute_action"
                  phx-value-action={@show_modal}
                  phx-target={@myself}
                  class={"flex-1 px-4 py-2 rounded-lg text-white transition-colors #{action_button_color(@show_modal)}"}
                >
                  Confirm
                </button>
              </div>
            </div>
          </div>
        </div>
      <% end %>

      <!-- SecureConfirmation for high-risk actions -->
      <%= if @pending_secure_action do %>
        <.live_component
          module={TamanduaServerWeb.Components.SecureConfirmation}
          id={"secure-confirm-#{@pending_secure_action}"}
          action={@pending_secure_action}
          title={action_title(@pending_secure_action)}
          warning={action_warning(@pending_secure_action)}
          danger_level={action_danger_level(@pending_secure_action)}
          current_user={@current_user}
          action_label="Confirm"
          confirm_button_text="Confirm with Password"
          on_confirm={fn -> send(self(), {:secure_action_confirmed, @pending_secure_action, @alert}) end}
        />
        <!-- Auto-open the SecureConfirmation modal -->
        <script>
          setTimeout(function() {
            document.querySelector('[phx-click="open_modal"]')?.click();
          }, 50);
        </script>
      <% end %>
    </div>
    """
  end

  @impl true
  def handle_event("request_secure_action", %{"action" => action}, socket) do
    # For high-risk actions, show SecureConfirmation modal
    {:noreply, assign(socket, :pending_secure_action, action)}
  end

  @impl true
  def handle_event("show_confirm_modal", %{"action" => action}, socket) do
    {:noreply, assign(socket, :show_modal, action)}
  end

  @impl true
  def handle_event("close_modal", _params, socket) do
    {:noreply,
     socket
     |> assign(:show_modal, nil)
     |> assign(:pending_secure_action, nil)}
  end

  @impl true
  def handle_event("execute_action", %{"action" => action}, socket) do
    alert = socket.assigns.alert
    agent_id = alert.agent_id

    socket =
      socket
      |> assign(:show_modal, nil)
      |> assign(:executing_action, action)

    # Execute the action asynchronously
    task =
      Task.async(fn ->
        execute_remediation_action(action, alert, agent_id)
      end)

    send(self(), {:action_task_started, task.ref, action})

    {:noreply, socket}
  end

  @impl true
  def handle_info({:secure_action_confirmed, action, alert}, socket) do
    # SecureConfirmation verified the password, now execute the action
    agent_id = alert.agent_id

    socket =
      socket
      |> assign(:pending_secure_action, nil)
      |> assign(:executing_action, action)

    # Execute the action asynchronously
    task =
      Task.async(fn ->
        execute_remediation_action(action, alert, agent_id)
      end)

    send(self(), {:action_task_started, task.ref, action})

    {:noreply, socket}
  end

  @impl true
  def handle_info({ref, result}, socket) when is_reference(ref) do
    # Task completed
    Process.demonitor(ref, [:flush])

    socket =
      case result do
        {:ok, _response} ->
          handle_action_success(socket)

        {:ok, :forensics, collection_id} ->
          socket
          |> assign(:forensics_collection_id, collection_id)
          |> assign(:executing_action, nil)
          |> put_flash(:info, "Forensics collection started. Collection ID: #{collection_id}")

        {:error, reason} ->
          socket
          |> assign(:executing_action, nil)
          |> put_flash(:error, "Action failed: #{format_error(reason)}")
      end

    # Notify parent to refresh action history
    send(self(), {:action_completed, socket.assigns.executing_action})

    {:noreply, socket}
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, _pid, _reason}, socket) do
    # Task crashed
    socket =
      socket
      |> assign(:executing_action, nil)
      |> put_flash(:error, "Action execution failed")

    {:noreply, socket}
  end

  @impl true
  def handle_info(_msg, socket) do
    {:noreply, socket}
  end

  # Private helper functions

  defp execute_remediation_action("kill_process", alert, agent_id) do
    evidence = alert.evidence || %{}
    process = evidence["process"] || evidence[:process] || %{}
    pid = process["pid"] || process[:pid]

    if pid do
      Executor.kill_process(agent_id, pid)
    else
      {:error, :no_process_info}
    end
  end

  defp execute_remediation_action("quarantine_file", alert, agent_id) do
    evidence = alert.evidence || %{}
    file = evidence["file"] || evidence[:file] || %{}
    process = evidence["process"] || evidence[:process] || %{}
    path = file["path"] || file[:path] || process["path"] || process[:path]

    if path do
      Executor.quarantine_file(agent_id, path)
    else
      {:error, :no_file_path}
    end
  end

  defp execute_remediation_action("isolate_host", _alert, agent_id) do
    Executor.isolate_host(agent_id)
  end

  defp execute_remediation_action("collect_forensics", _alert, agent_id) do
    case Executor.collect_forensics(agent_id, %{
           process_list: true,
           network_connections: true,
           event_logs: true,
           memory_dump: false
         }) do
      {:ok, collection_id} -> {:ok, :forensics, collection_id}
      error -> error
    end
  end

  defp handle_action_success(socket) do
    action = socket.assigns.executing_action
    message = "#{action_title(action)} completed successfully"

    socket
    |> assign(:executing_action, nil)
    |> put_flash(:info, message)
  end

  defp has_process_info?(alert) do
    evidence = alert.evidence || %{}
    process = evidence["process"] || evidence[:process] || %{}
    (process["pid"] || process[:pid]) != nil
  end

  defp has_file_info?(alert) do
    evidence = alert.evidence || %{}
    file = evidence["file"] || evidence[:file] || %{}
    process = evidence["process"] || evidence[:process] || %{}
    (file["path"] || file[:path] || process["path"] || process[:path]) != nil
  end

  defp action_title("kill_process"), do: "Kill Process"
  defp action_title("quarantine_file"), do: "Quarantine File"
  defp action_title("isolate_host"), do: "Isolate Host"
  defp action_title("collect_forensics"), do: "Collect Forensics"
  defp action_title(_), do: "Action"

  defp action_warning("kill_process"),
    do: "This will terminate the process immediately and may cause data loss or system instability."

  defp action_warning("quarantine_file"),
    do: "This will move the file to a secure quarantine location and may break application functionality."

  defp action_warning("isolate_host"),
    do: "This will disconnect the host from the network, blocking all communication except with the EDR server."

  defp action_warning("collect_forensics"),
    do: "This will collect forensic data from the host. The collection process may take several minutes."

  defp action_description("kill_process", alert) do
    evidence = alert.evidence || %{}
    process = evidence["process"] || evidence[:process] || %{}
    name = process["name"] || process[:name] || "unknown"
    pid = process["pid"] || process[:pid] || "unknown"
    "Process: #{name} (PID: #{pid})"
  end

  defp action_description("quarantine_file", alert) do
    evidence = alert.evidence || %{}
    file = evidence["file"] || evidence[:file] || %{}
    process = evidence["process"] || evidence[:process] || %{}
    path = file["path"] || file[:path] || process["path"] || process[:path] || "unknown"
    "File: #{path}"
  end

  defp action_description("isolate_host", alert) do
    "Agent: #{alert.agent_id}"
  end

  defp action_description("collect_forensics", alert) do
    "This will collect process list, network connections, and event logs from agent #{alert.agent_id}."
  end

  defp action_danger_level("kill_process"), do: :high
  defp action_danger_level("isolate_host"), do: :critical
  defp action_danger_level(_), do: :high

  defp action_icon("kill_process") do
    assigns = %{}

    ~H"""
    <div class="flex-shrink-0 w-12 h-12 bg-[var(--color-error-500)]/10 rounded-full flex items-center justify-center">
      <svg class="w-6 h-6 text-[var(--color-error-500)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
      </svg>
    </div>
    """
  end

  defp action_icon("quarantine_file") do
    assigns = %{}

    ~H"""
    <div class="flex-shrink-0 w-12 h-12 bg-[var(--color-warning-500)]/10 rounded-full flex items-center justify-center">
      <svg class="w-6 h-6 text-[var(--color-warning-500)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
      </svg>
    </div>
    """
  end

  defp action_icon("isolate_host") do
    assigns = %{}

    ~H"""
    <div class="flex-shrink-0 w-12 h-12 bg-[var(--color-primary-500)]/10 rounded-full flex items-center justify-center">
      <svg class="w-6 h-6 text-[var(--color-primary-500)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 5.636a9 9 0 010 12.728m0 0l-2.829-2.829m2.829 2.829L21 21M15.536 8.464a5 5 0 010 7.072m0 0l-2.829-2.829m-4.243 2.829a4.978 4.978 0 01-1.414-2.83m-1.414 5.658a9 9 0 01-2.167-9.238m7.824 2.167a1 1 0 111.414 1.414m-1.414-1.414L3 3" />
      </svg>
    </div>
    """
  end

  defp action_icon("collect_forensics") do
    assigns = %{}

    ~H"""
    <div class="flex-shrink-0 w-12 h-12 bg-[var(--color-primary-500)]/10 rounded-full flex items-center justify-center">
      <svg class="w-6 h-6 text-[var(--color-primary-500)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
      </svg>
    </div>
    """
  end

  defp action_icon(_) do
    assigns = %{}

    ~H"""
    <div class="flex-shrink-0 w-12 h-12 bg-[var(--color-neutral-500)]/10 rounded-full flex items-center justify-center">
      <svg class="w-6 h-6 text-[var(--color-neutral-500)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
      </svg>
    </div>
    """
  end

  defp action_button_color("kill_process"), do: "bg-[var(--color-error-600)] hover:bg-[var(--color-error-700)]"
  defp action_button_color("quarantine_file"), do: "bg-[var(--color-warning-600)] hover:bg-[var(--color-warning-700)]"
  defp action_button_color("isolate_host"), do: "bg-[var(--color-primary-600)] hover:bg-[var(--color-primary-700)]"
  defp action_button_color("collect_forensics"), do: "bg-[var(--color-primary-600)] hover:bg-[var(--color-primary-700)]"
  defp action_button_color(_), do: "bg-[var(--color-neutral-600)] hover:bg-[var(--color-neutral-700)]"

  defp format_error(:agent_not_found), do: "Agent not found or offline"
  defp format_error(:agent_offline), do: "Agent is offline"
  defp format_error(:agent_disconnected), do: "Agent disconnected during execution"
  defp format_error(:timeout), do: "Action timed out"
  defp format_error(:no_process_info), do: "No process information available in alert"
  defp format_error(:no_file_path), do: "No file path available in alert"
  defp format_error(reason) when is_atom(reason), do: to_string(reason)
  defp format_error(reason) when is_binary(reason), do: reason
  defp format_error(reason), do: inspect(reason)
end
