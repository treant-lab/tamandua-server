defmodule TamanduaServerWeb.Components.QuarantineList do
  @moduledoc """
  Displays list of quarantined items with filtering and actions.
  Uses shared design system tokens for visual consistency.
  """
  use TamanduaServerWeb, :live_component

  @impl true
  def render(assigns) do
    ~H"""
    <div class="quarantine-list">
      <div class="flex items-center justify-between mb-4">
        <h3 class="text-lg font-semibold text-[var(--color-foreground)]">Quarantined Items</h3>
        <span class="text-sm text-[var(--color-muted)]"><%= length(@items) %> items</span>
      </div>

      <%= if Enum.empty?(@items) do %>
        <div class="card text-center py-12">
          <svg class="mx-auto h-12 w-12 text-[var(--color-muted)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          <h4 class="mt-4 text-lg font-medium text-[var(--color-foreground)]">No quarantined files</h4>
          <p class="mt-2 text-sm text-[var(--color-muted)]">Files that have been quarantined will appear here.</p>
        </div>
      <% else %>
        <div class="space-y-2">
          <%= for item <- @items do %>
            <div
              class="flex items-center justify-between p-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-neutral-900)] hover:bg-[var(--color-neutral-800)] cursor-pointer transition-colors"
              phx-click="select_item"
              phx-value-id={item.id}
              phx-target={@myself}
            >
              <div class="flex items-center gap-3">
                <div class="w-10 h-10 rounded-lg bg-[var(--color-warning-500)]/10 flex items-center justify-center">
                  <svg class="w-5 h-5 text-[var(--color-warning-500)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                  </svg>
                </div>
                <div>
                  <p class="font-medium text-[var(--color-foreground)]"><%= item.file_name %></p>
                  <p class="text-sm text-[var(--color-muted)]"><%= format_date(item.quarantined_at) %></p>
                </div>
              </div>
              <div class="flex items-center gap-2">
                <span class={"badge #{severity_class(item.severity)}"}>
                  <%= item.severity %>
                </span>
                <button class="p-2 text-[var(--color-muted)] hover:text-[var(--color-foreground)]">
                  <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
                  </svg>
                </button>
              </div>
            </div>
          <% end %>
        </div>
      <% end %>
    </div>
    """
  end

  @impl true
  def handle_event("select_item", %{"id" => id}, socket) do
    send(self(), {:show_quarantine_detail, id})
    {:noreply, socket}
  end

  defp severity_class(:critical), do: "badge-error"
  defp severity_class(:high), do: "badge-warning"
  defp severity_class(:medium), do: "badge-default"
  defp severity_class(_), do: "badge-secondary"

  defp format_date(nil), do: "Unknown"
  defp format_date(datetime) do
    Calendar.strftime(datetime, "%Y-%m-%d %H:%M")
  end
end
