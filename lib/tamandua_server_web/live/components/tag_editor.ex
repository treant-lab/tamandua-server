defmodule TamanduaServerWeb.Components.TagEditor do
  @moduledoc """
  LiveView component for managing alert tags.

  Features:
  - Create new tags with custom colors
  - Autocomplete tag suggestions
  - Tag pills with color coding
  - Bulk tag operations
  """

  use TamanduaServerWeb, :live_component

  alias TamanduaServer.Alerts.TagManager

  @impl true
  def mount(socket) do
    socket =
      socket
      |> assign(:tag_input, "")
      |> assign(:tag_suggestions, [])
      |> assign(:show_color_picker, false)
      |> assign(:selected_color, "#6B7280")
      |> assign(:show_create_tag_modal, false)
      |> assign(:new_tag_name, "")
      |> assign(:new_tag_description, "")
      |> assign(:new_tag_category, nil)

    {:ok, socket}
  end

  @impl true
  def update(assigns, socket) do
    socket =
      socket
      |> assign(assigns)
      |> load_tags()

    {:ok, socket}
  end

  @impl true
  def handle_event("tag_input_changed", %{"value" => value}, socket) do
    socket =
      socket
      |> assign(:tag_input, value)
      |> update_tag_suggestions(value)

    {:noreply, socket}
  end

  @impl true
  def handle_event("add_tag", %{"tag_name" => tag_name}, socket) do
    alert_ids = socket.assigns.alert_ids
    organization_id = socket.assigns.organization_id
    user = socket.assigns.current_user

    case TagManager.bulk_assign_tags(alert_ids, [tag_name], organization_id, user) do
      {:ok, _count} ->
        socket =
          socket
          |> assign(:tag_input, "")
          |> assign(:tag_suggestions, [])
          |> load_tags()
          |> put_flash(:info, "Tag added successfully")

        send(self(), {:tags_updated, alert_ids})

        {:noreply, socket}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to add tag")}
    end
  end

  @impl true
  def handle_event("remove_tag", %{"tag_id" => tag_id}, socket) do
    alert_ids = socket.assigns.alert_ids
    organization_id = socket.assigns.organization_id

    case TagManager.bulk_unassign_tag_ids(alert_ids, [tag_id]) do
      {:ok, _count} ->
        socket =
          socket
          |> load_tags()
          |> put_flash(:info, "Tag removed successfully")

        send(self(), {:tags_updated, alert_ids})

        {:noreply, socket}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to remove tag")}
    end
  end

  @impl true
  def handle_event("open_create_tag_modal", _params, socket) do
    {:noreply, assign(socket, :show_create_tag_modal, true)}
  end

  @impl true
  def handle_event("close_create_tag_modal", _params, socket) do
    socket =
      socket
      |> assign(:show_create_tag_modal, false)
      |> assign(:new_tag_name, "")
      |> assign(:new_tag_description, "")
      |> assign(:new_tag_category, nil)
      |> assign(:selected_color, "#6B7280")

    {:noreply, socket}
  end

  @impl true
  def handle_event("create_tag", params, socket) do
    organization_id = socket.assigns.organization_id
    user = socket.assigns.current_user

    attrs = %{
      name: params["name"],
      description: params["description"],
      color: socket.assigns.selected_color,
      category: params["category"]
    }

    case TagManager.create_tag(organization_id, attrs, user) do
      {:ok, _tag} ->
        socket =
          socket
          |> assign(:show_create_tag_modal, false)
          |> assign(:new_tag_name, "")
          |> assign(:new_tag_description, "")
          |> assign(:new_tag_category, nil)
          |> assign(:selected_color, "#6B7280")
          |> load_tags()
          |> put_flash(:info, "Tag created successfully")

        {:noreply, socket}

      {:error, changeset} ->
        errors = Ecto.Changeset.traverse_errors(changeset, fn {msg, _opts} -> msg end)
        error_message = errors |> Map.values() |> List.flatten() |> Enum.join(", ")

        {:noreply, put_flash(socket, :error, "Failed to create tag: #{error_message}")}
    end
  end

  @impl true
  def handle_event("select_color", %{"color" => color}, socket) do
    {:noreply, assign(socket, :selected_color, color)}
  end

  defp load_tags(socket) do
    organization_id = socket.assigns.organization_id
    tags = TagManager.list_tags(organization_id)

    assign(socket, :available_tags, tags)
  end

  defp update_tag_suggestions(socket, query) when byte_size(query) >= 2 do
    organization_id = socket.assigns.organization_id
    suggestions = TagManager.autocomplete_tags(organization_id, query)

    assign(socket, :tag_suggestions, suggestions)
  end

  defp update_tag_suggestions(socket, _query) do
    assign(socket, :tag_suggestions, [])
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id={@id} class="tag-editor">
      <!-- Tag Input with Autocomplete -->
      <div class="mb-4">
        <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          Add Tags
        </label>
        <div class="relative">
          <input
            type="text"
            phx-target={@myself}
            phx-change="tag_input_changed"
            phx-debounce="300"
            value={@tag_input}
            placeholder="Type to search or create tags..."
            class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
          />

          <!-- Autocomplete Suggestions -->
          <%= if length(@tag_suggestions) > 0 do %>
            <div class="absolute z-10 mt-1 w-full bg-white dark:bg-gray-800 shadow-lg rounded-md border border-gray-200 dark:border-gray-700 max-h-60 overflow-auto">
              <%= for suggestion <- @tag_suggestions do %>
                <button
                  type="button"
                  phx-target={@myself}
                  phx-click="add_tag"
                  phx-value-tag_name={suggestion.name}
                  class="w-full text-left px-4 py-2 hover:bg-gray-100 dark:hover:bg-gray-700 flex items-center gap-2"
                >
                  <span class="inline-block w-3 h-3 rounded-full" style={"background-color: #{suggestion.color}"}></span>
                  <span class="text-sm text-gray-900 dark:text-white"><%= suggestion.name %></span>
                  <%= if suggestion.category do %>
                    <span class="text-xs text-gray-500 dark:text-gray-400">(<%= suggestion.category %>)</span>
                  <% end %>
                </button>
              <% end %>
            </div>
          <% end %>
        </div>

        <!-- Create New Tag Button -->
        <button
          type="button"
          phx-target={@myself}
          phx-click="open_create_tag_modal"
          class="mt-2 text-sm text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300"
        >
          + Create new tag
        </button>
      </div>

      <!-- Current Tags -->
      <div class="mb-4">
        <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          Current Tags
        </label>
        <div class="flex flex-wrap gap-2">
          <%= if length(@available_tags) == 0 do %>
            <p class="text-sm text-gray-500 dark:text-gray-400">No tags available. Create one above!</p>
          <% else %>
            <%= for tag <- @available_tags do %>
              <span
                class="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-medium text-white"
                style={"background-color: #{tag.color}"}
              >
                <%= tag.name %>
                <button
                  type="button"
                  phx-target={@myself}
                  phx-click="remove_tag"
                  phx-value-tag_id={tag.id}
                  class="ml-1 hover:bg-white hover:bg-opacity-20 rounded-full p-0.5"
                >
                  <svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
                  </svg>
                </button>
              </span>
            <% end %>
          <% end %>
        </div>
      </div>

      <!-- Create Tag Modal -->
      <%= if @show_create_tag_modal do %>
        <div class="fixed z-50 inset-0 overflow-y-auto" phx-target={@myself}>
          <div class="flex items-center justify-center min-h-screen px-4">
            <div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" phx-click="close_create_tag_modal"></div>

            <div class="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full p-6">
              <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-4">Create New Tag</h3>

              <form phx-target={@myself} phx-submit="create_tag">
                <!-- Tag Name -->
                <div class="mb-4">
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Tag Name <span class="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="name"
                    required
                    maxlength="50"
                    class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                  />
                </div>

                <!-- Description -->
                <div class="mb-4">
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Description
                  </label>
                  <textarea
                    name="description"
                    rows="2"
                    maxlength="500"
                    class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                  ></textarea>
                </div>

                <!-- Category -->
                <div class="mb-4">
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Category
                  </label>
                  <select
                    name="category"
                    class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                  >
                    <option value="">None</option>
                    <%= for category <- TamanduaServer.Alerts.Tag.predefined_categories() do %>
                      <option value={category}><%= category |> String.replace("_", " ") |> String.capitalize() %></option>
                    <% end %>
                  </select>
                </div>

                <!-- Color Picker -->
                <div class="mb-4">
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Color
                  </label>
                  <div class="flex flex-wrap gap-2">
                    <%= for color <- TamanduaServer.Alerts.Tag.color_palette() do %>
                      <button
                        type="button"
                        phx-target={@myself}
                        phx-click="select_color"
                        phx-value-color={color}
                        class={"w-8 h-8 rounded-full border-2 #{if @selected_color == color, do: "border-gray-900 dark:border-white", else: "border-transparent"}"}
                        style={"background-color: #{color}"}
                      >
                      </button>
                    <% end %>
                  </div>
                </div>

                <!-- Actions -->
                <div class="flex justify-end gap-2 mt-6">
                  <button
                    type="button"
                    phx-target={@myself}
                    phx-click="close_create_tag_modal"
                    class="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-600"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    class="px-4 py-2 text-sm font-medium text-white bg-indigo-600 rounded-md hover:bg-indigo-700"
                  >
                    Create Tag
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      <% end %>
    </div>
    """
  end
end
