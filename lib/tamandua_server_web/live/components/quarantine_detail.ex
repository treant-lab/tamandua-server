defmodule TamanduaServerWeb.Components.QuarantineDetail do
  @moduledoc """
  Modal component displaying detailed information about a quarantined file.
  Provides actions to restore, delete, or download the file.
  Uses shared design system tokens for visual consistency.
  """
  use TamanduaServerWeb, :live_component

  @impl true
  def render(assigns) do
    ~H"""
    <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" phx-window-keydown="close_modal" phx-key="Escape" phx-target={@myself}>
      <div class="card max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
        <div class="flex items-center justify-between mb-6">
          <div class="flex items-center gap-3">
            <div class="w-12 h-12 rounded-lg bg-[var(--color-warning-500)]/10 flex items-center justify-center">
              <svg class="w-6 h-6 text-[var(--color-warning-500)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <div>
              <h3 class="text-lg font-semibold text-[var(--color-foreground)]">Quarantined File</h3>
              <p class="text-sm text-[var(--color-muted)]"><%= @item.file_name %></p>
            </div>
          </div>
          <button
            phx-click="close_modal"
            phx-target={@myself}
            class="p-2 text-[var(--color-muted)] hover:text-[var(--color-foreground)] rounded-lg hover:bg-[var(--color-neutral-800)]"
          >
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <!-- File Metadata -->
        <div class="space-y-4 mb-6">
          <h4 class="text-sm font-semibold text-[var(--color-muted)] uppercase tracking-wider">File Information</h4>
          <dl class="grid grid-cols-2 gap-4">
            <div>
              <dt class="text-sm text-[var(--color-muted)]">Original Path</dt>
              <dd class="font-mono text-sm text-[var(--color-foreground)] break-all"><%= @item.original_path %></dd>
            </div>
            <div>
              <dt class="text-sm text-[var(--color-muted)]">File Size</dt>
              <dd class="text-sm text-[var(--color-foreground)]"><%= format_size(@item.file_size) %></dd>
            </div>
            <div>
              <dt class="text-sm text-[var(--color-muted)]">SHA-256 Hash</dt>
              <dd class="font-mono text-xs text-[var(--color-foreground)] break-all"><%= @item.sha256 %></dd>
            </div>
            <div>
              <dt class="text-sm text-[var(--color-muted)]">Quarantined At</dt>
              <dd class="text-sm text-[var(--color-foreground)]"><%= format_datetime(@item.quarantined_at) %></dd>
            </div>
          </dl>
        </div>

        <!-- Detection Details -->
        <div class="space-y-4 mb-6">
          <h4 class="text-sm font-semibold text-[var(--color-muted)] uppercase tracking-wider">Detection Details</h4>
          <div class="p-4 rounded-lg bg-[var(--color-neutral-800)] border border-[var(--color-border)]">
            <div class="flex items-center justify-between mb-2">
              <span class="text-sm text-[var(--color-muted)]">Threat Type</span>
              <span class={"badge #{severity_class(@item.severity)}"}><%= @item.threat_type %></span>
            </div>
            <div class="flex items-center justify-between mb-2">
              <span class="text-sm text-[var(--color-muted)]">Rule Matched</span>
              <span class="text-sm text-[var(--color-foreground)]"><%= @item.rule_name || "N/A" %></span>
            </div>
            <div class="flex items-center justify-between">
              <span class="text-sm text-[var(--color-muted)]">Confidence Score</span>
              <span class="text-sm text-[var(--color-foreground)]"><%= format_score(@item.confidence) %></span>
            </div>
          </div>
        </div>

        <!-- Warning -->
        <div class="warning-message mb-6">
          <div class="flex">
            <svg class="h-5 w-5 text-[var(--color-warning-400)]" fill="currentColor" viewBox="0 0 20 20">
              <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
            </svg>
            <div class="ml-3">
              <p class="text-sm">
                Restoring this file will return it to its original location and may pose a security risk.
              </p>
            </div>
          </div>
        </div>

        <!-- Actions -->
        <div class="flex gap-3">
          <button
            phx-click="restore_file"
            phx-value-id={@item.id}
            phx-target={@myself}
            class="btn-outline flex-1"
          >
            <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6" />
            </svg>
            Restore
          </button>
          <button
            phx-click="download_encrypted"
            phx-value-id={@item.id}
            phx-target={@myself}
            class="btn-secondary flex-1"
          >
            <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            Download
          </button>
          <button
            phx-click="delete_permanently"
            phx-value-id={@item.id}
            phx-target={@myself}
            class="btn-destructive flex-1"
          >
            <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
            </svg>
            Delete
          </button>
        </div>
      </div>
    </div>
    """
  end

  @impl true
  def handle_event("close_modal", _params, socket) do
    send(self(), :close_quarantine_detail)
    {:noreply, socket}
  end

  @impl true
  def handle_event("restore_file", %{"id" => id}, socket) do
    send(self(), {:restore_quarantined_file, id})
    {:noreply, socket}
  end

  @impl true
  def handle_event("download_encrypted", %{"id" => id}, socket) do
    send(self(), {:download_quarantined_file, id})
    {:noreply, socket}
  end

  @impl true
  def handle_event("delete_permanently", %{"id" => id}, socket) do
    send(self(), {:delete_quarantined_file, id})
    {:noreply, socket}
  end

  defp severity_class(:critical), do: "badge-error"
  defp severity_class(:high), do: "badge-warning"
  defp severity_class(:medium), do: "badge-default"
  defp severity_class(_), do: "badge-secondary"

  defp format_datetime(nil), do: "Unknown"
  defp format_datetime(datetime) do
    Calendar.strftime(datetime, "%Y-%m-%d %H:%M:%S UTC")
  end

  defp format_size(nil), do: "Unknown"
  defp format_size(bytes) when is_integer(bytes) do
    cond do
      bytes >= 1_073_741_824 -> "#{Float.round(bytes / 1_073_741_824, 2)} GB"
      bytes >= 1_048_576 -> "#{Float.round(bytes / 1_048_576, 2)} MB"
      bytes >= 1024 -> "#{Float.round(bytes / 1024, 2)} KB"
      true -> "#{bytes} B"
    end
  end

  defp format_score(nil), do: "N/A"
  defp format_score(score) when is_float(score), do: "#{Float.round(score * 100, 1)}%"
  defp format_score(score), do: "#{score}"
end
