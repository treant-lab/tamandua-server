defmodule TamanduaServerWeb.Components.SecureConfirmation do
  @moduledoc """
  Reusable LiveView component that requires password re-entry for critical actions.

  For high-risk operations like kill switch management, host isolation, or process
  termination, this component provides an additional layer of security by requiring
  the user to re-authenticate with their password.

  ## Features

  - Password verification against current user session
  - Configurable danger levels (:high, :critical)
  - Max 3 failed attempts before 30-second lockout
  - Callback on successful confirmation

  ## Usage

      <.live_component
        module={TamanduaServerWeb.Components.SecureConfirmation}
        id="confirm-kill-switch"
        action="trigger_kill_switch"
        title="Trigger Kill Switch"
        warning="This will immediately isolate the model and block all inference requests."
        danger_level={:critical}
        current_user={@current_user}
        on_confirm={fn -> send(self(), {:confirmed_action, :trigger_kill_switch}) end}
      />
  """

  use TamanduaServerWeb, :live_component

  alias TamanduaServer.Accounts.User

  @max_attempts 3
  @lockout_seconds 30

  @impl true
  def mount(socket) do
    {:ok,
     socket
     |> assign(:show_modal, false)
     |> assign(:password, "")
     |> assign(:error, nil)
     |> assign(:attempts, 0)
     |> assign(:locked_until, nil)
     |> assign(:submitting, false)}
  end

  @impl true
  def update(assigns, socket) do
    # Default values for optional props
    assigns = Map.put_new(assigns, :danger_level, :high)
    assigns = Map.put_new(assigns, :warning, "This action requires password confirmation.")
    assigns = Map.put_new(assigns, :confirm_button_text, "Confirm")

    {:ok, assign(socket, assigns)}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="secure-confirmation">
      <!-- Trigger Button -->
      <button
        type="button"
        phx-click="open_modal"
        phx-target={@myself}
        disabled={locked?(@locked_until)}
        class={trigger_button_class(@danger_level, locked?(@locked_until))}
      >
        <%= if locked?(@locked_until) do %>
          Locked (<%= remaining_seconds(@locked_until) %>s)
        <% else %>
          <%= @action_label || @title %>
        <% end %>
      </button>

      <!-- Confirmation Modal -->
      <%= if @show_modal do %>
        <div
          class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
          phx-window-keydown="close_modal"
          phx-key="Escape"
          phx-target={@myself}
        >
          <div class={modal_container_class(@danger_level)}>
            <!-- Header -->
            <div class="p-6 border-b border-[var(--color-border)]">
              <div class="flex items-center gap-4">
                <%= danger_icon(@danger_level) %>
                <div>
                  <h3 class="text-lg font-semibold text-[var(--color-foreground)]">
                    <%= @title %>
                  </h3>
                  <p class="text-sm text-[var(--color-muted)]">
                    Password confirmation required
                  </p>
                </div>
              </div>
            </div>

            <!-- Body -->
            <div class="p-6">
              <!-- Warning Message -->
              <div class={warning_box_class(@danger_level)}>
                <div class="flex items-start gap-3">
                  <svg class="w-5 h-5 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                  </svg>
                  <p class="text-sm"><%= @warning %></p>
                </div>
              </div>

              <!-- Password Form -->
              <form phx-submit="verify_password" phx-target={@myself} class="mt-6">
                <label class="block">
                  <span class="text-sm font-medium text-[var(--color-foreground)]">
                    Enter your password to continue
                  </span>
                  <input
                    type="password"
                    name="password"
                    value={@password}
                    phx-change="update_password"
                    phx-target={@myself}
                    placeholder="Your password"
                    autocomplete="current-password"
                    class="mt-2 w-full px-4 py-2 border border-[var(--color-border)] rounded-lg bg-[var(--color-background)] text-[var(--color-foreground)] focus:ring-2 focus:ring-[var(--color-primary-500)] focus:border-transparent"
                    disabled={@submitting || locked?(@locked_until)}
                    autofocus
                  />
                </label>

                <!-- Error Message -->
                <%= if @error do %>
                  <div class="mt-3 flex items-center gap-2 text-[var(--color-error-500)]">
                    <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                      <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                    </svg>
                    <span class="text-sm"><%= @error %></span>
                  </div>
                <% end %>

                <!-- Attempts Warning -->
                <%= if @attempts > 0 and @attempts < @max_attempts do %>
                  <p class="mt-2 text-sm text-[var(--color-warning-500)]">
                    <%= @max_attempts - @attempts %> attempt(s) remaining before lockout
                  </p>
                <% end %>

                <!-- Lockout Message -->
                <%= if locked?(@locked_until) do %>
                  <div class="mt-3 p-3 bg-[var(--color-error-50)] dark:bg-[var(--color-error-900)]/20 rounded-lg">
                    <p class="text-sm text-[var(--color-error-600)] dark:text-[var(--color-error-400)]">
                      Too many failed attempts. Try again in <%= remaining_seconds(@locked_until) %> seconds.
                    </p>
                  </div>
                <% end %>
              </form>
            </div>

            <!-- Footer -->
            <div class="px-6 py-4 bg-[var(--color-neutral-50)] dark:bg-[var(--color-neutral-900)]/50 border-t border-[var(--color-border)] flex gap-3 justify-end">
              <button
                type="button"
                phx-click="close_modal"
                phx-target={@myself}
                class="px-4 py-2 text-sm font-medium text-[var(--color-foreground)] bg-[var(--color-background)] border border-[var(--color-border)] rounded-lg hover:bg-[var(--color-neutral-100)] dark:hover:bg-[var(--color-neutral-800)] transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                form="verify_password"
                phx-click="verify_password"
                phx-target={@myself}
                disabled={@submitting || locked?(@locked_until) || String.trim(@password) == ""}
                class={confirm_button_class(@danger_level, @submitting || locked?(@locked_until))}
              >
                <%= if @submitting do %>
                  <svg class="animate-spin -ml-1 mr-2 h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Verifying...
                <% else %>
                  <%= @confirm_button_text %>
                <% end %>
              </button>
            </div>
          </div>
        </div>
      <% end %>
    </div>
    """
  end

  @impl true
  def handle_event("open_modal", _params, socket) do
    # Check if still locked
    if locked?(socket.assigns.locked_until) do
      {:noreply, socket}
    else
      {:noreply,
       socket
       |> assign(:show_modal, true)
       |> assign(:password, "")
       |> assign(:error, nil)}
    end
  end

  @impl true
  def handle_event("close_modal", _params, socket) do
    {:noreply,
     socket
     |> assign(:show_modal, false)
     |> assign(:password, "")
     |> assign(:error, nil)}
  end

  @impl true
  def handle_event("update_password", %{"password" => password}, socket) do
    {:noreply, assign(socket, :password, password)}
  end

  @impl true
  def handle_event("verify_password", _params, socket) do
    password = socket.assigns.password
    current_user = socket.assigns.current_user

    # Check if locked
    if locked?(socket.assigns.locked_until) do
      {:noreply, assign(socket, :error, "Account temporarily locked")}
    else
      socket = assign(socket, :submitting, true)

      # Verify password
      case verify_user_password(current_user, password) do
        true ->
          # Success - call the callback
          on_confirm = socket.assigns.on_confirm

          if is_function(on_confirm, 0) do
            on_confirm.()
          end

          {:noreply,
           socket
           |> assign(:show_modal, false)
           |> assign(:password, "")
           |> assign(:error, nil)
           |> assign(:attempts, 0)
           |> assign(:submitting, false)}

        false ->
          new_attempts = socket.assigns.attempts + 1

          socket =
            if new_attempts >= @max_attempts do
              locked_until = DateTime.add(DateTime.utc_now(), @lockout_seconds, :second)

              socket
              |> assign(:locked_until, locked_until)
              |> assign(:error, "Too many failed attempts. Locked for #{@lockout_seconds} seconds.")
              |> schedule_unlock_check()
            else
              socket
              |> assign(:error, "Invalid password. Please try again.")
            end

          {:noreply,
           socket
           |> assign(:attempts, new_attempts)
           |> assign(:password, "")
           |> assign(:submitting, false)}
      end
    end
  end

  # Private functions

  defp verify_user_password(user, password) when is_binary(password) and byte_size(password) > 0 do
    User.valid_password?(user, password)
  end

  defp verify_user_password(_user, _password), do: false

  defp locked?(nil), do: false

  defp locked?(locked_until) do
    DateTime.compare(DateTime.utc_now(), locked_until) == :lt
  end

  defp remaining_seconds(nil), do: 0

  defp remaining_seconds(locked_until) do
    DateTime.diff(locked_until, DateTime.utc_now(), :second)
    |> max(0)
  end

  defp schedule_unlock_check(socket) do
    # Schedule a message to check if we should unlock
    Process.send_after(self(), {:check_unlock, socket.assigns.id}, @lockout_seconds * 1000 + 100)
    socket
  end

  # Style helpers

  defp trigger_button_class(:critical, true) do
    "px-4 py-2 text-sm font-medium text-[var(--color-neutral-400)] bg-[var(--color-neutral-200)] dark:bg-[var(--color-neutral-700)] rounded-lg cursor-not-allowed"
  end

  defp trigger_button_class(:critical, false) do
    "px-4 py-2 text-sm font-medium text-white bg-[var(--color-error-600)] hover:bg-[var(--color-error-700)] rounded-lg transition-colors"
  end

  defp trigger_button_class(:high, true) do
    "px-4 py-2 text-sm font-medium text-[var(--color-neutral-400)] bg-[var(--color-neutral-200)] dark:bg-[var(--color-neutral-700)] rounded-lg cursor-not-allowed"
  end

  defp trigger_button_class(:high, false) do
    "px-4 py-2 text-sm font-medium text-white bg-[var(--color-warning-600)] hover:bg-[var(--color-warning-700)] rounded-lg transition-colors"
  end

  defp modal_container_class(:critical) do
    "bg-[var(--color-neutral-50)] dark:bg-[var(--color-neutral-900)] rounded-lg shadow-xl max-w-md w-full mx-4 border-2 border-[var(--color-error-500)]"
  end

  defp modal_container_class(:high) do
    "bg-[var(--color-neutral-50)] dark:bg-[var(--color-neutral-900)] rounded-lg shadow-xl max-w-md w-full mx-4 border border-[var(--color-warning-500)]"
  end

  defp warning_box_class(:critical) do
    "p-4 bg-[var(--color-error-50)] dark:bg-[var(--color-error-900)]/20 text-[var(--color-error-700)] dark:text-[var(--color-error-300)] rounded-lg"
  end

  defp warning_box_class(:high) do
    "p-4 bg-[var(--color-warning-50)] dark:bg-[var(--color-warning-900)]/20 text-[var(--color-warning-700)] dark:text-[var(--color-warning-300)] rounded-lg"
  end

  defp confirm_button_class(:critical, true) do
    "inline-flex items-center px-4 py-2 text-sm font-medium text-white bg-[var(--color-neutral-400)] rounded-lg cursor-not-allowed"
  end

  defp confirm_button_class(:critical, false) do
    "inline-flex items-center px-4 py-2 text-sm font-medium text-white bg-[var(--color-error-600)] hover:bg-[var(--color-error-700)] rounded-lg transition-colors"
  end

  defp confirm_button_class(:high, true) do
    "inline-flex items-center px-4 py-2 text-sm font-medium text-white bg-[var(--color-neutral-400)] rounded-lg cursor-not-allowed"
  end

  defp confirm_button_class(:high, false) do
    "inline-flex items-center px-4 py-2 text-sm font-medium text-white bg-[var(--color-warning-600)] hover:bg-[var(--color-warning-700)] rounded-lg transition-colors"
  end

  defp danger_icon(:critical) do
    assigns = %{}

    ~H"""
    <div class="flex-shrink-0 w-12 h-12 bg-[var(--color-error-500)]/10 rounded-full flex items-center justify-center">
      <svg class="w-6 h-6 text-[var(--color-error-500)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
    </div>
    """
  end

  defp danger_icon(:high) do
    assigns = %{}

    ~H"""
    <div class="flex-shrink-0 w-12 h-12 bg-[var(--color-warning-500)]/10 rounded-full flex items-center justify-center">
      <svg class="w-6 h-6 text-[var(--color-warning-500)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
    </div>
    """
  end
end
