defmodule TamanduaServerWeb.Components.SeverityAdjuster do
  @moduledoc """
  LiveView component for adjusting alert severity.

  Features:
  - Severity dropdown with confirmation
  - Required justification field
  - Approval workflow for critical downgrades
  - Adjustment history viewer
  """

  use TamanduaServerWeb, :live_component

  alias TamanduaServer.Alerts.SeverityManager
  alias TamanduaServer.Alerts.SeverityAdjustment

  @impl true
  def mount(socket) do
    socket =
      socket
      |> assign(:show_adjustment_modal, false)
      |> assign(:show_history_modal, false)
      |> assign(:selected_severity, nil)
      |> assign(:adjustment_reason, "")
      |> assign(:adjustment_notes, "")
      |> assign(:adjustment_history, [])
      |> assign(:requires_approval, false)

    {:ok, socket}
  end

  @impl true
  def update(assigns, socket) do
    socket =
      socket
      |> assign(assigns)
      |> load_adjustment_history()

    {:ok, socket}
  end

  @impl true
  def handle_event("open_adjustment_modal", %{"severity" => severity}, socket) do
    current_severity = socket.assigns.current_severity
    requires_approval = SeverityAdjustment.requires_approval?(current_severity, severity)

    socket =
      socket
      |> assign(:show_adjustment_modal, true)
      |> assign(:selected_severity, severity)
      |> assign(:requires_approval, requires_approval)

    {:noreply, socket}
  end

  @impl true
  def handle_event("close_adjustment_modal", _params, socket) do
    socket =
      socket
      |> assign(:show_adjustment_modal, false)
      |> assign(:selected_severity, nil)
      |> assign(:adjustment_reason, "")
      |> assign(:adjustment_notes, "")
      |> assign(:requires_approval, false)

    {:noreply, socket}
  end

  @impl true
  def handle_event("submit_adjustment", params, socket) do
    alert_id = socket.assigns.alert_id
    new_severity = socket.assigns.selected_severity
    reason = params["reason"]
    notes = params["notes"]
    user = socket.assigns.current_user
    organization_id = socket.assigns.organization_id

    opts = [notes: notes, organization_id: organization_id]

    case SeverityManager.adjust_severity(alert_id, new_severity, reason, user, opts) do
      {:ok, {_adjustment, :pending_approval}} ->
        socket =
          socket
          |> assign(:show_adjustment_modal, false)
          |> put_flash(
            :info,
            "Severity adjustment submitted for approval. Critical downgrades require manager approval."
          )
          |> load_adjustment_history()

        send(self(), {:severity_adjustment_pending, alert_id})

        {:noreply, socket}

      {:ok, {_adjustment, _updated_alert}} ->
        socket =
          socket
          |> assign(:show_adjustment_modal, false)
          |> put_flash(:info, "Severity adjusted successfully")
          |> load_adjustment_history()

        send(self(), {:severity_adjusted, alert_id, new_severity})

        {:noreply, socket}

      {:error, :same_severity} ->
        {:noreply, put_flash(socket, :error, "New severity must be different from current severity")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to adjust severity: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("show_history", _params, socket) do
    {:noreply, assign(socket, :show_history_modal, true)}
  end

  @impl true
  def handle_event("close_history", _params, socket) do
    {:noreply, assign(socket, :show_history_modal, false)}
  end

  @impl true
  def handle_event("approve_adjustment", %{"adjustment_id" => adjustment_id}, socket) do
    user = socket.assigns.current_user
    organization_id = socket.assigns.organization_id

    case SeverityManager.approve_adjustment(adjustment_id, user, organization_id) do
      {:ok, {_adjustment, _alert}} ->
        socket =
          socket
          |> put_flash(:info, "Severity adjustment approved")
          |> load_adjustment_history()

        send(self(), {:severity_adjustment_approved, adjustment_id})

        {:noreply, socket}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to approve adjustment: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("reject_adjustment", params, socket) do
    adjustment_id = params["adjustment_id"]
    rejection_reason = params["reason"]
    user = socket.assigns.current_user
    organization_id = socket.assigns.organization_id

    case SeverityManager.reject_adjustment(adjustment_id, rejection_reason, user, organization_id) do
      {:ok, _adjustment} ->
        socket =
          socket
          |> put_flash(:info, "Severity adjustment rejected")
          |> load_adjustment_history()

        send(self(), {:severity_adjustment_rejected, adjustment_id})

        {:noreply, socket}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to reject adjustment: #{inspect(reason)}")}
    end
  end

  defp load_adjustment_history(socket) do
    alert_id = socket.assigns.alert_id
    history = SeverityManager.list_alert_adjustments(alert_id, limit: 20)

    assign(socket, :adjustment_history, history)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id={@id} class="severity-adjuster">
      <!-- Severity Selector -->
      <div class="flex items-center gap-2">
        <span class={"px-3 py-1 rounded-full text-xs font-semibold #{severity_badge_class(@current_severity)}"}>
          <%= String.upcase(@current_severity) %>
        </span>

        <%= if @show_adjusted_indicator && @severity_adjusted do %>
          <span class="text-xs text-gray-500 dark:text-gray-400" title="Severity has been manually adjusted">
            (adjusted from <%= @original_severity %>)
          </span>
        <% end %>

        <!-- Severity Change Dropdown -->
        <div class="relative inline-block">
          <button
            type="button"
            class="text-sm text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300"
            phx-click={JS.toggle(to: "#severity-menu-#{@id}")}
          >
            Change Severity
          </button>

          <div id={"severity-menu-#{@id}"} class="hidden absolute left-0 mt-2 w-48 bg-white dark:bg-gray-800 rounded-md shadow-lg border border-gray-200 dark:border-gray-700 z-10">
            <%= for severity <- ["critical", "high", "medium", "low", "info"] do %>
              <%= if severity != @current_severity do %>
                <button
                  type="button"
                  phx-target={@myself}
                  phx-click="open_adjustment_modal"
                  phx-value-severity={severity}
                  class="w-full text-left px-4 py-2 text-sm hover:bg-gray-100 dark:hover:bg-gray-700 flex items-center gap-2"
                >
                  <span class={"inline-block px-2 py-1 rounded text-xs font-semibold #{severity_badge_class(severity)}"}>
                    <%= String.upcase(severity) %>
                  </span>
                </button>
              <% end %>
            <% end %>
          </div>
        </div>

        <!-- History Button -->
        <%= if length(@adjustment_history) > 0 do %>
          <button
            type="button"
            phx-target={@myself}
            phx-click="show_history"
            class="text-sm text-gray-600 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-300"
          >
            View History (<%= length(@adjustment_history) %>)
          </button>
        <% end %>
      </div>

      <!-- Adjustment Modal -->
      <%= if @show_adjustment_modal do %>
        <div class="fixed z-50 inset-0 overflow-y-auto" phx-target={@myself}>
          <div class="flex items-center justify-center min-h-screen px-4">
            <div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" phx-click="close_adjustment_modal"></div>

            <div class="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-lg w-full p-6">
              <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-4">
                Adjust Alert Severity
              </h3>

              <!-- Warning for Critical Downgrade -->
              <%= if @requires_approval do %>
                <div class="mb-4 p-4 bg-yellow-50 dark:bg-yellow-900 border border-yellow-200 dark:border-yellow-700 rounded-md">
                  <div class="flex items-start">
                    <svg class="w-5 h-5 text-yellow-600 dark:text-yellow-400 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                      <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                    </svg>
                    <p class="ml-3 text-sm text-yellow-700 dark:text-yellow-300">
                      This is a critical severity downgrade and will require manager approval before taking effect.
                    </p>
                  </div>
                </div>
              <% end %>

              <form phx-target={@myself} phx-submit="submit_adjustment">
                <!-- Current and New Severity -->
                <div class="mb-4 flex items-center justify-between bg-gray-50 dark:bg-gray-700 p-4 rounded-md">
                  <div class="text-center">
                    <p class="text-xs text-gray-500 dark:text-gray-400 mb-1">Current</p>
                    <span class={"px-3 py-1 rounded-full text-xs font-semibold #{severity_badge_class(@current_severity)}"}>
                      <%= String.upcase(@current_severity) %>
                    </span>
                  </div>
                  <svg class="w-6 h-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 8l4 4m0 0l-4 4m4-4H3" />
                  </svg>
                  <div class="text-center">
                    <p class="text-xs text-gray-500 dark:text-gray-400 mb-1">New</p>
                    <span class={"px-3 py-1 rounded-full text-xs font-semibold #{severity_badge_class(@selected_severity)}"}>
                      <%= String.upcase(@selected_severity) %>
                    </span>
                  </div>
                </div>

                <!-- Reason (Required) -->
                <div class="mb-4">
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Reason for Adjustment <span class="text-red-500">*</span>
                  </label>
                  <textarea
                    name="reason"
                    required
                    minlength="10"
                    maxlength="1000"
                    rows="3"
                    placeholder="Explain why this severity adjustment is necessary..."
                    class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                  ></textarea>
                  <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">Minimum 10 characters required</p>
                </div>

                <!-- Additional Notes (Optional) -->
                <div class="mb-4">
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Additional Notes
                  </label>
                  <textarea
                    name="notes"
                    maxlength="2000"
                    rows="2"
                    placeholder="Optional additional context..."
                    class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                  ></textarea>
                </div>

                <!-- Actions -->
                <div class="flex justify-end gap-2 mt-6">
                  <button
                    type="button"
                    phx-target={@myself}
                    phx-click="close_adjustment_modal"
                    class="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-600"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    class="px-4 py-2 text-sm font-medium text-white bg-indigo-600 rounded-md hover:bg-indigo-700"
                  >
                    <%= if @requires_approval, do: "Submit for Approval", else: "Adjust Severity" %>
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      <% end %>

      <!-- History Modal -->
      <%= if @show_history_modal do %>
        <div class="fixed z-50 inset-0 overflow-y-auto" phx-target={@myself}>
          <div class="flex items-center justify-center min-h-screen px-4">
            <div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" phx-click="close_history"></div>

            <div class="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-3xl w-full p-6 max-h-[80vh] overflow-y-auto">
              <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-4">
                Severity Adjustment History
              </h3>

              <div class="space-y-4">
                <%= for adjustment <- @adjustment_history do %>
                  <div class="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <div class="flex items-start justify-between mb-2">
                      <div class="flex items-center gap-3">
                        <span class={"px-2 py-1 rounded text-xs font-semibold #{severity_badge_class(adjustment.old_severity)}"}>
                          <%= String.upcase(adjustment.old_severity) %>
                        </span>
                        <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 8l4 4m0 0l-4 4m4-4H3" />
                        </svg>
                        <span class={"px-2 py-1 rounded text-xs font-semibold #{severity_badge_class(adjustment.new_severity)}"}>
                          <%= String.upcase(adjustment.new_severity) %>
                        </span>

                        <%= if adjustment.requires_approval do %>
                          <%= cond do %>
                            <% is_nil(adjustment.approved) -> %>
                              <span class="px-2 py-1 bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300 rounded text-xs font-medium">
                                Pending Approval
                              </span>
                            <% adjustment.approved -> %>
                              <span class="px-2 py-1 bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300 rounded text-xs font-medium">
                                Approved
                              </span>
                            <% true -> %>
                              <span class="px-2 py-1 bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300 rounded text-xs font-medium">
                                Rejected
                              </span>
                          <% end %>
                        <% end %>
                      </div>

                      <span class="text-xs text-gray-500 dark:text-gray-400">
                        <%= format_datetime(adjustment.inserted_at) %>
                      </span>
                    </div>

                    <div class="text-sm">
                      <p class="text-gray-900 dark:text-white mb-1">
                        <strong>Reason:</strong> <%= adjustment.reason %>
                      </p>

                      <%= if adjustment.notes do %>
                        <p class="text-gray-700 dark:text-gray-300 mb-1">
                          <strong>Notes:</strong> <%= adjustment.notes %>
                        </p>
                      <% end %>

                      <p class="text-gray-600 dark:text-gray-400">
                        <strong>Adjusted by:</strong>
                        <%= if adjustment.adjusted_by do %>
                          <%= adjustment.adjusted_by.email %>
                        <% else %>
                          System
                        <% end %>
                      </p>

                      <%= if adjustment.approved_by do %>
                        <p class="text-gray-600 dark:text-gray-400">
                          <strong>Approved by:</strong> <%= adjustment.approved_by.email %>
                          at <%= format_datetime(adjustment.approved_at) %>
                        </p>
                      <% end %>

                      <%= if adjustment.rejection_reason do %>
                        <p class="text-red-600 dark:text-red-400 mt-2">
                          <strong>Rejection reason:</strong> <%= adjustment.rejection_reason %>
                        </p>
                      <% end %>
                    </div>

                    <!-- Approval Actions for Pending Adjustments -->
                    <%= if adjustment.requires_approval && is_nil(adjustment.approved) && @can_approve do %>
                      <div class="mt-3 flex gap-2">
                        <button
                          type="button"
                          phx-target={@myself}
                          phx-click="approve_adjustment"
                          phx-value-adjustment_id={adjustment.id}
                          class="px-3 py-1 text-xs font-medium text-white bg-green-600 rounded hover:bg-green-700"
                        >
                          Approve
                        </button>
                        <button
                          type="button"
                          phx-click={JS.show(to: "#reject-form-#{adjustment.id}")}
                          class="px-3 py-1 text-xs font-medium text-white bg-red-600 rounded hover:bg-red-700"
                        >
                          Reject
                        </button>
                      </div>

                      <div id={"reject-form-#{adjustment.id}"} class="hidden mt-2">
                        <form phx-target={@myself} phx-submit="reject_adjustment">
                          <input type="hidden" name="adjustment_id" value={adjustment.id} />
                          <textarea
                            name="reason"
                            required
                            minlength="10"
                            rows="2"
                            placeholder="Reason for rejection..."
                            class="block w-full text-sm rounded-md border-gray-300 dark:bg-gray-700 dark:border-gray-600 mb-2"
                          ></textarea>
                          <button type="submit" class="px-3 py-1 text-xs font-medium text-white bg-red-600 rounded hover:bg-red-700">
                            Confirm Rejection
                          </button>
                        </form>
                      </div>
                    <% end %>
                  </div>
                <% end %>
              </div>

              <div class="flex justify-end mt-6">
                <button
                  type="button"
                  phx-target={@myself}
                  phx-click="close_history"
                  class="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-600"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      <% end %>
    </div>
    """
  end

  defp severity_badge_class("critical"), do: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300"
  defp severity_badge_class("high"), do: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300"
  defp severity_badge_class("medium"), do: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300"
  defp severity_badge_class("low"), do: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300"
  defp severity_badge_class("info"), do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300"
  defp severity_badge_class(_), do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300"

  defp format_datetime(nil), do: "N/A"

  defp format_datetime(datetime) do
    Calendar.strftime(datetime, "%Y-%m-%d %H:%M:%S UTC")
  end
end
