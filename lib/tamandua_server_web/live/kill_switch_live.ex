defmodule TamanduaServerWeb.KillSwitchLive do
  @moduledoc """
  LiveView dashboard for Kill Switch management.

  Provides real-time monitoring and control of model isolation state,
  including arm/disarm controls, manual trigger capability, and trigger history.

  ## Features

  - Real-time model status updates via PubSub
  - Arm/disarm controls per model
  - Manual trigger with password confirmation
  - Release isolated models
  - Bulk operations (arm all, disarm all)
  - Trigger history with latency metrics
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Runtime.KillSwitch
  alias TamanduaServer.Runtime.ModelIsolation
  alias Phoenix.PubSub

  @refresh_interval_ms 30_000

  @impl true
  def mount(_params, session, socket) do
    if connected?(socket) do
      PubSub.subscribe(TamanduaServer.PubSub, "kill_switch:all")
      PubSub.subscribe(TamanduaServer.PubSub, "model_isolation:all")
      :timer.send_interval(@refresh_interval_ms, self(), :refresh)
    end

    current_user = get_current_user(session)

    {:ok,
     socket
     |> assign(:page_title, "Kill Switch Management")
     |> assign(:current_user, current_user)
     |> assign(:models, [])
     |> assign(:history, [])
     |> assign(:loading, true)
     |> assign(:selected_model, nil)
     |> assign(:pending_action, nil)
     |> assign(:show_bulk_confirm, nil)
     |> load_data()}
  end

  @impl true
  def handle_params(_params, _uri, socket) do
    {:noreply, socket}
  end

  @impl true
  def handle_info(:refresh, socket) do
    {:noreply, load_data(socket)}
  end

  @impl true
  def handle_info({:kill_switch, model_id, event}, socket) do
    # Update the specific model in our list
    models = update_model_in_list(socket.assigns.models, model_id, event)
    {:noreply, assign(socket, :models, models) |> maybe_update_history()}
  end

  @impl true
  def handle_info({:model_isolation, _model_id, _event, _state}, socket) do
    # Reload data on isolation state changes
    {:noreply, load_data(socket)}
  end

  @impl true
  def handle_info({:confirmed_action, {:arm, model_id}}, socket) do
    KillSwitch.arm(model_id)
    {:noreply, socket |> put_flash(:info, "Kill switch armed for #{model_id}") |> load_data()}
  end

  @impl true
  def handle_info({:confirmed_action, {:disarm, model_id}}, socket) do
    KillSwitch.disarm(model_id)
    {:noreply, socket |> put_flash(:info, "Kill switch disarmed for #{model_id}") |> load_data()}
  end

  @impl true
  def handle_info({:confirmed_action, {:trigger, model_id}}, socket) do
    current_user = socket.assigns.current_user
    triggered_by = if current_user, do: current_user.email, else: "manual"

    case KillSwitch.trigger(model_id, "Manual trigger via dashboard", triggered_by: triggered_by) do
      {:ok, result} ->
        {:noreply,
         socket
         |> put_flash(:info, "Kill switch triggered for #{model_id} (#{result.latency_ms}ms)")
         |> load_data()}

      {:error, reason} ->
        {:noreply, socket |> put_flash(:error, "Failed to trigger: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_info({:confirmed_action, {:release, model_id}}, socket) do
    case KillSwitch.release(model_id) do
      {:ok, _} ->
        {:noreply, socket |> put_flash(:info, "Model #{model_id} released") |> load_data()}

      {:error, reason} ->
        {:noreply, socket |> put_flash(:error, "Failed to release: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_info({:confirmed_action, :arm_all}, socket) do
    Enum.each(socket.assigns.models, fn model ->
      KillSwitch.arm(model.model_id)
    end)

    {:noreply,
     socket
     |> put_flash(:info, "All kill switches armed")
     |> assign(:show_bulk_confirm, nil)
     |> load_data()}
  end

  @impl true
  def handle_info({:confirmed_action, :disarm_all}, socket) do
    Enum.each(socket.assigns.models, fn model ->
      KillSwitch.disarm(model.model_id)
    end)

    {:noreply,
     socket
     |> put_flash(:info, "All kill switches disarmed")
     |> assign(:show_bulk_confirm, nil)
     |> load_data()}
  end

  @impl true
  def handle_info(_msg, socket) do
    {:noreply, socket}
  end

  @impl true
  def handle_event("arm", %{"model_id" => model_id}, socket) do
    # Arm doesn't require confirmation
    KillSwitch.arm(model_id)
    {:noreply, socket |> put_flash(:info, "Kill switch armed for #{model_id}") |> load_data()}
  end

  @impl true
  def handle_event("request_disarm", %{"model_id" => model_id}, socket) do
    {:noreply, assign(socket, :pending_action, {:disarm, model_id})}
  end

  @impl true
  def handle_event("request_trigger", %{"model_id" => model_id}, socket) do
    {:noreply, assign(socket, :pending_action, {:trigger, model_id})}
  end

  @impl true
  def handle_event("request_release", %{"model_id" => model_id}, socket) do
    {:noreply, assign(socket, :pending_action, {:release, model_id})}
  end

  @impl true
  def handle_event("cancel_action", _params, socket) do
    {:noreply, assign(socket, :pending_action, nil)}
  end

  @impl true
  def handle_event("show_bulk_confirm", %{"action" => action}, socket) do
    case parse_bulk_action(action) do
      nil ->
        {:noreply, put_flash(socket, :error, "Unknown bulk action")}

      bulk_action ->
        {:noreply, assign(socket, :show_bulk_confirm, bulk_action)}
    end
  end

  @impl true
  def handle_event("cancel_bulk", _params, socket) do
    {:noreply, assign(socket, :show_bulk_confirm, nil)}
  end

  @impl true
  def handle_event("refresh_data", _params, socket) do
    {:noreply, load_data(socket) |> put_flash(:info, "Data refreshed")}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="kill-switch-dashboard p-6 space-y-6">
      <!-- Header -->
      <header class="flex justify-between items-center">
        <div>
          <h1 class="text-2xl font-bold text-[var(--color-foreground)]">
            Kill Switch Management
          </h1>
          <p class="text-sm text-[var(--color-muted)]">
            Emergency model isolation controls for AI/ML runtime protection
          </p>
        </div>
        <button
          phx-click="refresh_data"
          class="px-4 py-2 text-sm font-medium text-white bg-[var(--color-primary-600)] hover:bg-[var(--color-primary-700)] rounded-lg transition-colors"
        >
          Refresh
        </button>
      </header>

      <!-- Stats Cards -->
      <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div class="bg-[var(--color-background)] border border-[var(--color-border)] rounded-lg p-4">
          <h3 class="text-sm font-medium text-[var(--color-muted)]">Total Models</h3>
          <p class="text-2xl font-bold text-[var(--color-foreground)]"><%= length(@models) %></p>
        </div>
        <div class="bg-[var(--color-background)] border border-[var(--color-border)] rounded-lg p-4">
          <h3 class="text-sm font-medium text-[var(--color-muted)]">Armed</h3>
          <p class="text-2xl font-bold text-[var(--color-warning-500)]">
            <%= Enum.count(@models, & &1.armed) %>
          </p>
        </div>
        <div class="bg-[var(--color-background)] border border-[var(--color-border)] rounded-lg p-4">
          <h3 class="text-sm font-medium text-[var(--color-muted)]">Triggered</h3>
          <p class="text-2xl font-bold text-[var(--color-error-500)]">
            <%= Enum.count(@models, & &1.triggered) %>
          </p>
        </div>
        <div class="bg-[var(--color-background)] border border-[var(--color-border)] rounded-lg p-4">
          <h3 class="text-sm font-medium text-[var(--color-muted)]">Active (Safe)</h3>
          <p class="text-2xl font-bold text-[var(--color-success-500)]">
            <%= Enum.count(@models, fn m -> not m.triggered and not m.armed end) %>
          </p>
        </div>
      </div>

      <!-- Bulk Actions -->
      <div class="flex gap-3">
        <button
          phx-click="show_bulk_confirm"
          phx-value-action="arm_all"
          class="px-4 py-2 text-sm font-medium text-[var(--color-warning-700)] bg-[var(--color-warning-100)] hover:bg-[var(--color-warning-200)] dark:text-[var(--color-warning-300)] dark:bg-[var(--color-warning-900)]/30 dark:hover:bg-[var(--color-warning-900)]/50 rounded-lg transition-colors"
        >
          Arm All
        </button>
        <button
          phx-click="show_bulk_confirm"
          phx-value-action="disarm_all"
          class="px-4 py-2 text-sm font-medium text-[var(--color-foreground)] bg-[var(--color-neutral-100)] hover:bg-[var(--color-neutral-200)] dark:bg-[var(--color-neutral-800)] dark:hover:bg-[var(--color-neutral-700)] rounded-lg transition-colors"
        >
          Disarm All
        </button>
      </div>

      <!-- Models Table -->
      <div class="bg-[var(--color-background)] border border-[var(--color-border)] rounded-lg overflow-hidden">
        <div class="px-4 py-3 border-b border-[var(--color-border)]">
          <h2 class="text-lg font-semibold text-[var(--color-foreground)]">Tracked Models</h2>
        </div>

        <%= if @loading do %>
          <div class="p-8 text-center text-[var(--color-muted)]">
            <svg class="animate-spin h-8 w-8 mx-auto mb-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            Loading models...
          </div>
        <% else %>
          <%= if Enum.empty?(@models) do %>
            <div class="p-8 text-center text-[var(--color-muted)]">
              <svg class="w-12 h-12 mx-auto mb-3 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              <p>No models currently tracked</p>
              <p class="text-sm mt-1">Models will appear here when they are registered with the isolation system</p>
            </div>
          <% else %>
            <div class="overflow-x-auto">
              <table class="w-full">
                <thead class="bg-[var(--color-neutral-50)] dark:bg-[var(--color-neutral-900)]">
                  <tr>
                    <th class="px-4 py-3 text-left text-xs font-medium text-[var(--color-muted)] uppercase tracking-wider">Model ID</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-[var(--color-muted)] uppercase tracking-wider">Agent ID</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-[var(--color-muted)] uppercase tracking-wider">Status</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-[var(--color-muted)] uppercase tracking-wider">Last Updated</th>
                    <th class="px-4 py-3 text-right text-xs font-medium text-[var(--color-muted)] uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-[var(--color-border)]">
                  <%= for model <- @models do %>
                    <tr class="hover:bg-[var(--color-neutral-50)] dark:hover:bg-[var(--color-neutral-900)]/50">
                      <td class="px-4 py-3 text-sm font-mono text-[var(--color-foreground)]">
                        <%= truncate_id(model.model_id) %>
                      </td>
                      <td class="px-4 py-3 text-sm text-[var(--color-muted)]">
                        <%= model.agent_id || "N/A" %>
                      </td>
                      <td class="px-4 py-3">
                        <%= status_badge(model) %>
                      </td>
                      <td class="px-4 py-3 text-sm text-[var(--color-muted)]">
                        <%= format_timestamp(model.updated_at) %>
                      </td>
                      <td class="px-4 py-3 text-right">
                        <div class="flex items-center justify-end gap-2">
                          <%= if model.triggered do %>
                            <button
                              phx-click="request_release"
                              phx-value-model_id={model.model_id}
                              class="px-3 py-1 text-xs font-medium text-[var(--color-success-700)] bg-[var(--color-success-100)] hover:bg-[var(--color-success-200)] dark:text-[var(--color-success-300)] dark:bg-[var(--color-success-900)]/30 rounded transition-colors"
                            >
                              Release
                            </button>
                          <% else %>
                            <%= if model.armed do %>
                              <button
                                phx-click="request_disarm"
                                phx-value-model_id={model.model_id}
                                class="px-3 py-1 text-xs font-medium text-[var(--color-foreground)] bg-[var(--color-neutral-100)] hover:bg-[var(--color-neutral-200)] dark:bg-[var(--color-neutral-800)] rounded transition-colors"
                              >
                                Disarm
                              </button>
                            <% else %>
                              <button
                                phx-click="arm"
                                phx-value-model_id={model.model_id}
                                class="px-3 py-1 text-xs font-medium text-[var(--color-warning-700)] bg-[var(--color-warning-100)] hover:bg-[var(--color-warning-200)] dark:text-[var(--color-warning-300)] dark:bg-[var(--color-warning-900)]/30 rounded transition-colors"
                              >
                                Arm
                              </button>
                            <% end %>
                            <button
                              phx-click="request_trigger"
                              phx-value-model_id={model.model_id}
                              class="px-3 py-1 text-xs font-medium text-white bg-[var(--color-error-600)] hover:bg-[var(--color-error-700)] rounded transition-colors"
                            >
                              Trigger
                            </button>
                          <% end %>
                        </div>
                      </td>
                    </tr>
                  <% end %>
                </tbody>
              </table>
            </div>
          <% end %>
        <% end %>
      </div>

      <!-- Trigger History -->
      <div class="bg-[var(--color-background)] border border-[var(--color-border)] rounded-lg overflow-hidden">
        <div class="px-4 py-3 border-b border-[var(--color-border)]">
          <h2 class="text-lg font-semibold text-[var(--color-foreground)]">Trigger History</h2>
        </div>

        <%= if Enum.empty?(@history) do %>
          <div class="p-6 text-center text-[var(--color-muted)]">
            No triggers recorded yet
          </div>
        <% else %>
          <div class="overflow-x-auto">
            <table class="w-full">
              <thead class="bg-[var(--color-neutral-50)] dark:bg-[var(--color-neutral-900)]">
                <tr>
                  <th class="px-4 py-3 text-left text-xs font-medium text-[var(--color-muted)] uppercase tracking-wider">Timestamp</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-[var(--color-muted)] uppercase tracking-wider">Model ID</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-[var(--color-muted)] uppercase tracking-wider">Triggered By</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-[var(--color-muted)] uppercase tracking-wider">Reason</th>
                  <th class="px-4 py-3 text-right text-xs font-medium text-[var(--color-muted)] uppercase tracking-wider">Latency</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-[var(--color-border)]">
                <%= for entry <- @history do %>
                  <tr class="hover:bg-[var(--color-neutral-50)] dark:hover:bg-[var(--color-neutral-900)]/50">
                    <td class="px-4 py-3 text-sm text-[var(--color-muted)]">
                      <%= format_timestamp(entry.triggered_at) %>
                    </td>
                    <td class="px-4 py-3 text-sm font-mono text-[var(--color-foreground)]">
                      <%= truncate_id(entry.model_id) %>
                    </td>
                    <td class="px-4 py-3 text-sm text-[var(--color-muted)]">
                      <%= entry.triggered_by || "system" %>
                    </td>
                    <td class="px-4 py-3 text-sm text-[var(--color-muted)] max-w-xs truncate">
                      <%= entry.reason || "-" %>
                    </td>
                    <td class="px-4 py-3 text-sm text-right">
                      <%= if entry.latency_ms do %>
                        <span class={latency_class(entry.latency_ms)}>
                          <%= entry.latency_ms %>ms
                        </span>
                      <% else %>
                        -
                      <% end %>
                    </td>
                  </tr>
                <% end %>
              </tbody>
            </table>
          </div>
        <% end %>
      </div>

      <!-- Secure Confirmation Modal for pending actions -->
      <%= if @pending_action do %>
        <.live_component
          module={TamanduaServerWeb.Components.SecureConfirmation}
          id={"confirm-#{elem(@pending_action, 0)}"}
          action={elem(@pending_action, 0)}
          title={action_title(@pending_action)}
          warning={action_warning(@pending_action)}
          danger_level={action_danger_level(@pending_action)}
          current_user={@current_user}
          action_label="Confirm"
          confirm_button_text="Confirm Action"
          on_confirm={fn -> send(self(), {:confirmed_action, @pending_action}) end}
        />
        <!-- Auto-open the modal -->
        <script>
          setTimeout(function() {
            document.querySelector('[phx-click="open_modal"]')?.click();
          }, 50);
        </script>
      <% end %>

      <!-- Bulk Confirm Modal -->
      <%= if @show_bulk_confirm do %>
        <.live_component
          module={TamanduaServerWeb.Components.SecureConfirmation}
          id="confirm-bulk"
          action={@show_bulk_confirm}
          title={bulk_action_title(@show_bulk_confirm)}
          warning={bulk_action_warning(@show_bulk_confirm, length(@models))}
          danger_level={:high}
          current_user={@current_user}
          action_label="Confirm"
          confirm_button_text="Confirm Bulk Action"
          on_confirm={fn -> send(self(), {:confirmed_action, @show_bulk_confirm}) end}
        />
        <script>
          setTimeout(function() {
            document.querySelector('[phx-click="open_modal"]')?.click();
          }, 50);
        </script>
      <% end %>
    </div>
    """
  end

  # Data loading

  defp load_data(socket) do
    models = load_models()
    history = load_history()

    socket
    |> assign(:models, models)
    |> assign(:history, history)
    |> assign(:loading, false)
  end

  defp load_models do
    # Get all models from ModelIsolation ETS table
    try do
      :ets.tab2list(:model_isolation_state)
      |> Enum.map(fn {_id, state} ->
        # Enrich with kill switch state
        {status, ks_state} = KillSwitch.status(state.model_id)

        %{
          model_id: state.model_id,
          agent_id: state.agent_id,
          status: state.status,
          isolation_mode: state.isolation_mode,
          armed: ks_state[:armed] || false,
          triggered: status == :triggered,
          triggered_at: ks_state[:triggered_at],
          triggered_by: ks_state[:triggered_by],
          reason: ks_state[:reason],
          updated_at: state.isolated_at || DateTime.utc_now()
        }
      end)
      |> Enum.sort_by(& &1.model_id)
    rescue
      _ -> []
    end
  end

  defp load_history do
    # Aggregate history from all models
    try do
      :ets.tab2list(:kill_switch_history)
      |> Enum.flat_map(fn {model_id, entries} ->
        Enum.map(entries, &Map.put(&1, :model_id, model_id))
      end)
      |> Enum.sort_by(& &1.triggered_at, {:desc, DateTime})
      |> Enum.take(50)
    rescue
      _ -> []
    end
  end

  defp maybe_update_history(socket) do
    history = load_history()
    assign(socket, :history, history)
  end

  defp update_model_in_list(models, model_id, event) do
    Enum.map(models, fn model ->
      if model.model_id == model_id do
        case event do
          :armed -> %{model | armed: true}
          :disarmed -> %{model | armed: false}
          :triggered -> %{model | triggered: true, updated_at: DateTime.utc_now()}
          :released -> %{model | triggered: false, updated_at: DateTime.utc_now()}
          _ -> model
        end
      else
        model
      end
    end)
  end

  # Helpers

  defp get_current_user(session) do
    case session["current_user"] || session[:current_user] do
      %{id: _id} = user -> user
      _ -> nil
    end
  end

  defp truncate_id(id) when is_binary(id) and byte_size(id) > 20 do
    String.slice(id, 0, 8) <> "..." <> String.slice(id, -8, 8)
  end

  defp truncate_id(id), do: id

  defp format_timestamp(nil), do: "-"

  defp format_timestamp(%DateTime{} = dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S UTC")
  end

  defp format_timestamp(_), do: "-"

  defp status_badge(model) do
    cond do
      model.triggered ->
        Phoenix.HTML.raw("""
        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300">
          <span class="w-2 h-2 mr-1.5 rounded-full bg-red-500 animate-pulse"></span>
          Triggered
        </span>
        """)

      model.armed ->
        Phoenix.HTML.raw("""
        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300">
          <span class="w-2 h-2 mr-1.5 rounded-full bg-yellow-500"></span>
          Armed
        </span>
        """)

      true ->
        Phoenix.HTML.raw("""
        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300">
          <span class="w-2 h-2 mr-1.5 rounded-full bg-green-500"></span>
          Disarmed
        </span>
        """)
    end
  end

  defp latency_class(ms) when ms < 100, do: "text-[var(--color-success-500)] font-medium"
  defp latency_class(ms) when ms < 500, do: "text-[var(--color-warning-500)] font-medium"
  defp latency_class(_ms), do: "text-[var(--color-error-500)] font-medium"

  # Action helpers

  defp action_title({:disarm, model_id}), do: "Disarm Kill Switch for #{truncate_id(model_id)}"
  defp action_title({:trigger, model_id}), do: "Trigger Kill Switch for #{truncate_id(model_id)}"
  defp action_title({:release, model_id}), do: "Release Model #{truncate_id(model_id)}"
  defp action_title(_), do: "Confirm Action"

  defp action_warning({:disarm, _model_id}) do
    "Disarming the kill switch will prevent automatic isolation on critical alerts. The model will continue operating without emergency protection."
  end

  defp action_warning({:trigger, _model_id}) do
    "This will immediately isolate the model, blocking all inference requests. The agent will stop processing requests for this model until manually released."
  end

  defp action_warning({:release, _model_id}) do
    "Releasing the model will allow it to resume normal operation. Ensure the threat has been mitigated before proceeding."
  end

  defp action_warning(_), do: "This action requires confirmation."

  defp action_danger_level({:trigger, _}), do: :critical
  defp action_danger_level({:release, _}), do: :critical
  defp action_danger_level({:disarm, _}), do: :high
  defp action_danger_level(_), do: :high

  defp bulk_action_title(:arm_all), do: "Arm All Kill Switches"
  defp bulk_action_title(:disarm_all), do: "Disarm All Kill Switches"
  defp bulk_action_title(_), do: "Confirm Bulk Action"

  defp bulk_action_warning(:arm_all, count) do
    "This will arm kill switches for all #{count} tracked models. Armed models will be automatically isolated on critical security alerts."
  end

  defp bulk_action_warning(:disarm_all, count) do
    "This will disarm kill switches for all #{count} tracked models. Models will no longer be automatically isolated on critical alerts."
  end

  defp bulk_action_warning(_, _), do: "This action affects multiple models."

  defp parse_bulk_action(:arm_all), do: :arm_all
  defp parse_bulk_action(:disarm_all), do: :disarm_all
  defp parse_bulk_action("arm_all"), do: :arm_all
  defp parse_bulk_action("disarm_all"), do: :disarm_all
  defp parse_bulk_action(_), do: nil
end
