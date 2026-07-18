defmodule TamanduaServerWeb.ReportDesignerLive do
  @moduledoc """
  LiveView for drag-and-drop report template designer.

  Features:
  - Drag-and-drop widget placement
  - Widget configuration panel
  - Live preview
  - Template save/load/export
  - Branding customization
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Reports.{WidgetRegistry, TemplateManager}

  @impl true
  def mount(%{"id" => template_id}, _session, socket) do
    # Load existing template
    case TemplateManager.get_template(template_id) do
      {:ok, template} ->
        {:ok, assign_template(socket, template)}

      {:error, :not_found} ->
        {:ok, socket
        |> put_flash(:error, "Template not found")
        |> push_navigate(to: ~p"/reports/designer")}
    end
  end

  @impl true
  def mount(_params, _session, socket) do
    # New template
    socket = socket
    |> assign(:page_title, "Report Designer")
    |> assign(:template, nil)
    |> assign(:template_id, nil)
    |> assign(:name, "New Report Template")
    |> assign(:description, "")
    |> assign(:category, "custom")
    |> assign(:widgets, [])
    |> assign(:selected_widget, nil)
    |> assign(:available_widgets, WidgetRegistry.list_widgets())
    |> assign(:layout, default_layout())
    |> assign(:branding, default_branding())
    |> assign(:preview_mode, false)
    |> assign(:save_status, nil)

    {:ok, socket}
  end

  @impl true
  def handle_event("add_widget", %{"type" => widget_type}, socket) do
    case WidgetRegistry.get_default_config(widget_type) do
      {:ok, widget_config} ->
        # Position new widget at next available spot
        position = calculate_next_position(socket.assigns.widgets, socket.assigns.layout)
        widget_config = put_in(widget_config, ["position"], position)

        widgets = socket.assigns.widgets ++ [widget_config]

        {:noreply, assign(socket, :widgets, widgets)}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Failed to add widget")}
    end
  end

  @impl true
  def handle_event("select_widget", %{"id" => widget_id}, socket) do
    selected = Enum.find(socket.assigns.widgets, &(&1["id"] == widget_id))
    {:noreply, assign(socket, :selected_widget, selected)}
  end

  @impl true
  def handle_event("update_widget", %{"id" => widget_id, "params" => params}, socket) do
    widgets = Enum.map(socket.assigns.widgets, fn widget ->
      if widget["id"] == widget_id do
        put_in(widget, ["params"], params)
      else
        widget
      end
    end)

    selected = if socket.assigns.selected_widget && socket.assigns.selected_widget["id"] == widget_id do
      Enum.find(widgets, &(&1["id"] == widget_id))
    else
      socket.assigns.selected_widget
    end

    {:noreply, socket |> assign(:widgets, widgets) |> assign(:selected_widget, selected)}
  end

  @impl true
  def handle_event("move_widget", %{"id" => widget_id, "position" => position}, socket) do
    widgets = Enum.map(socket.assigns.widgets, fn widget ->
      if widget["id"] == widget_id do
        put_in(widget, ["position"], position)
      else
        widget
      end
    end)

    {:noreply, assign(socket, :widgets, widgets)}
  end

  @impl true
  def handle_event("resize_widget", %{"id" => widget_id, "size" => size}, socket) do
    widgets = Enum.map(socket.assigns.widgets, fn widget ->
      if widget["id"] == widget_id do
        put_in(widget, ["size"], size)
      else
        widget
      end
    end)

    {:noreply, assign(socket, :widgets, widgets)}
  end

  @impl true
  def handle_event("delete_widget", %{"id" => widget_id}, socket) do
    widgets = Enum.reject(socket.assigns.widgets, &(&1["id"] == widget_id))

    selected = if socket.assigns.selected_widget && socket.assigns.selected_widget["id"] == widget_id do
      nil
    else
      socket.assigns.selected_widget
    end

    {:noreply, socket |> assign(:widgets, widgets) |> assign(:selected_widget, selected)}
  end

  @impl true
  def handle_event("update_template_info", params, socket) do
    {:noreply, socket
    |> assign(:name, params["name"] || socket.assigns.name)
    |> assign(:description, params["description"] || socket.assigns.description)
    |> assign(:category, params["category"] || socket.assigns.category)}
  end

  @impl true
  def handle_event("update_branding", params, socket) do
    branding = Map.merge(socket.assigns.branding, params)
    {:noreply, assign(socket, :branding, branding)}
  end

  @impl true
  def handle_event("toggle_preview", _, socket) do
    {:noreply, assign(socket, :preview_mode, !socket.assigns.preview_mode)}
  end

  @impl true
  def handle_event("save_template", _, socket) do
    attrs = %{
      name: socket.assigns.name,
      description: socket.assigns.description,
      category: socket.assigns.category,
      widgets: socket.assigns.widgets,
      layout: socket.assigns.layout,
      branding: socket.assigns.branding
    }

    result = if socket.assigns.template_id do
      TemplateManager.update_template(socket.assigns.template_id, attrs)
    else
      TemplateManager.create_template(attrs)
    end

    case result do
      {:ok, template} ->
        {:noreply, socket
        |> assign(:template_id, template.id)
        |> assign(:template, template)
        |> assign(:save_status, :success)
        |> put_flash(:info, "Template saved successfully")}

      {:error, _changeset} ->
        {:noreply, socket
        |> assign(:save_status, :error)
        |> put_flash(:error, "Failed to save template")}
    end
  end

  @impl true
  def handle_event("export_template", _, socket) do
    if socket.assigns.template_id do
      case TemplateManager.export_template(socket.assigns.template_id) do
        {:ok, json} ->
          # Trigger download in the browser
          {:noreply, push_event(socket, "download", %{
            filename: "#{socket.assigns.name}.json",
            content: json,
            mime_type: "application/json"
          })}

        {:error, _} ->
          {:noreply, put_flash(socket, :error, "Failed to export template")}
      end
    else
      {:noreply, put_flash(socket, :error, "Please save the template first")}
    end
  end

  @impl true
  def handle_event("duplicate_widget", %{"id" => widget_id}, socket) do
    original = Enum.find(socket.assigns.widgets, &(&1["id"] == widget_id))

    if original do
      duplicated = original
      |> Map.put("id", Ecto.UUID.generate())
      |> update_in(["position", "x"], &(&1 + 1))
      |> update_in(["position", "y"], &(&1 + 1))

      widgets = socket.assigns.widgets ++ [duplicated]
      {:noreply, assign(socket, :widgets, widgets)}
    else
      {:noreply, socket}
    end
  end

  # ============================================================================
  # Render
  # ============================================================================

  @impl true
  def render(assigns) do
    ~H"""
    <div class="report-designer h-screen flex flex-col bg-gray-50">
      <!-- Header -->
      <div class="bg-white border-b border-gray-200 px-6 py-4 flex items-center justify-between">
        <div class="flex items-center space-x-4">
          <h1 class="text-2xl font-bold text-gray-900"><%= @name %></h1>
          <span class="px-2 py-1 text-xs font-medium bg-blue-100 text-blue-800 rounded">
            <%= String.capitalize(@category) %>
          </span>
        </div>

        <div class="flex items-center space-x-2">
          <button
            phx-click="toggle_preview"
            class="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
          >
            <%= if @preview_mode, do: "Edit Mode", else: "Preview Mode" %>
          </button>

          <button
            phx-click="export_template"
            class="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
          >
            Export
          </button>

          <button
            phx-click="save_template"
            class="px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-md hover:bg-blue-700"
          >
            Save Template
          </button>
        </div>
      </div>

      <!-- Main Content -->
      <div class="flex flex-1 overflow-hidden">
        <!-- Sidebar - Widget Library -->
        <div :if={!@preview_mode} class="w-64 bg-white border-r border-gray-200 overflow-y-auto">
          <div class="p-4">
            <h2 class="text-sm font-semibold text-gray-900 uppercase tracking-wide mb-4">
              Widget Library
            </h2>

            <div class="space-y-2">
              <%= for widget <- @available_widgets do %>
                <button
                  phx-click="add_widget"
                  phx-value-type={widget.type}
                  class="w-full flex items-center p-3 text-left border border-gray-200 rounded-lg hover:border-blue-500 hover:shadow-md transition-all"
                >
                  <div class="flex-shrink-0 h-10 w-10 flex items-center justify-center bg-blue-100 rounded-lg">
                    <.icon name={widget.icon} class="h-6 w-6 text-blue-600" />
                  </div>
                  <div class="ml-3 flex-1">
                    <div class="text-sm font-medium text-gray-900"><%= widget.name %></div>
                    <div class="text-xs text-gray-500"><%= widget.description %></div>
                  </div>
                </button>
              <% end %>
            </div>
          </div>

          <!-- Template Settings -->
          <div class="p-4 border-t border-gray-200">
            <h2 class="text-sm font-semibold text-gray-900 uppercase tracking-wide mb-4">
              Template Settings
            </h2>

            <form phx-change="update_template_info" class="space-y-4">
              <div>
                <label class="block text-sm font-medium text-gray-700">Name</label>
                <input
                  type="text"
                  name="name"
                  value={@name}
                  class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                />
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-700">Description</label>
                <textarea
                  name="description"
                  rows="3"
                  class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                ><%= @description %></textarea>
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-700">Category</label>
                <select
                  name="category"
                  class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                >
                  <option value="security" selected={@category == "security"}>Security</option>
                  <option value="compliance" selected={@category == "compliance"}>Compliance</option>
                  <option value="operations" selected={@category == "operations"}>Operations</option>
                  <option value="executive" selected={@category == "executive"}>Executive</option>
                  <option value="custom" selected={@category == "custom"}>Custom</option>
                </select>
              </div>
            </form>
          </div>
        </div>

        <!-- Canvas -->
        <div class="flex-1 overflow-auto p-6">
          <div class="max-w-5xl mx-auto">
            <%= if @preview_mode do %>
              <.preview_canvas widgets={@widgets} branding={@branding} />
            <% else %>
              <.design_canvas widgets={@widgets} selected={@selected_widget} />
            <% end %>
          </div>
        </div>

        <!-- Properties Panel -->
        <div :if={!@preview_mode && @selected_widget} class="w-80 bg-white border-l border-gray-200 overflow-y-auto">
          <div class="p-4">
            <div class="flex items-center justify-between mb-4">
              <h2 class="text-sm font-semibold text-gray-900 uppercase tracking-wide">
                Widget Properties
              </h2>
              <button
                phx-click="select_widget"
                phx-value-id=""
                class="text-gray-400 hover:text-gray-500"
              >
                <.icon name="x-mark" class="h-5 w-5" />
              </button>
            </div>

            <.widget_properties widget={@selected_widget} />
          </div>
        </div>
      </div>
    </div>
    """
  end

  defp design_canvas(assigns) do
    ~H"""
    <div class="bg-white rounded-lg shadow-sm border-2 border-dashed border-gray-300 min-h-[800px] p-8 grid grid-cols-12 gap-4">
      <%= if Enum.empty?(@widgets) do %>
        <div class="col-span-12 flex items-center justify-center h-96">
          <div class="text-center">
            <.icon name="document-plus" class="mx-auto h-12 w-12 text-gray-400" />
            <h3 class="mt-2 text-sm font-medium text-gray-900">No widgets yet</h3>
            <p class="mt-1 text-sm text-gray-500">Get started by adding widgets from the library.</p>
          </div>
        </div>
      <% else %>
        <%= for widget <- @widgets do %>
          <.widget_card widget={widget} selected={@selected && @selected["id"] == widget["id"]} />
        <% end %>
      <% end %>
    </div>
    """
  end

  defp preview_canvas(assigns) do
    ~H"""
    <div class="bg-white rounded-lg shadow-lg p-8">
      <div class="mb-6 pb-6 border-b border-gray-200">
        <div class="flex items-center space-x-2 mb-4">
          <div class="h-8 w-8 bg-blue-600 rounded flex items-center justify-center">
            <span class="text-white font-bold text-sm"><%= String.first(@branding["company_name"] || "T") %></span>
          </div>
          <span class="text-lg font-bold text-gray-900"><%= @branding["company_name"] || "Tamandua EDR" %></span>
        </div>
      </div>

      <%= for widget <- @widgets do %>
        <div class="mb-6">
          <.widget_preview widget={widget} />
        </div>
      <% end %>
    </div>
    """
  end

  defp widget_card(assigns) do
    ~H"""
    <div
      phx-click="select_widget"
      phx-value-id={@widget["id"]}
      class={"col-span-#{@widget["size"]["width"]} row-span-#{@widget["size"]["height"]} p-4 border-2 rounded-lg cursor-pointer transition-all #{if @selected, do: "border-blue-500 shadow-lg", else: "border-gray-200 hover:border-gray-300"}"}
    >
      <div class="flex items-center justify-between mb-2">
        <span class="text-sm font-medium text-gray-900"><%= @widget["title"] %></span>
        <div class="flex items-center space-x-1">
          <button
            phx-click="duplicate_widget"
            phx-value-id={@widget["id"]}
            class="p-1 text-gray-400 hover:text-gray-600"
          >
            <.icon name="document-duplicate" class="h-4 w-4" />
          </button>
          <button
            phx-click="delete_widget"
            phx-value-id={@widget["id"]}
            class="p-1 text-gray-400 hover:text-red-600"
          >
            <.icon name="trash" class="h-4 w-4" />
          </button>
        </div>
      </div>
      <div class="text-xs text-gray-500">
        <%= String.capitalize(@widget["type"]) %> Widget
      </div>
    </div>
    """
  end

  defp widget_properties(assigns) do
    ~H"""
    <div class="space-y-4">
      <div>
        <label class="block text-sm font-medium text-gray-700">Title</label>
        <input
          type="text"
          value={@widget["title"]}
          phx-blur="update_widget"
          phx-value-id={@widget["id"]}
          class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
        />
      </div>

      <div class="grid grid-cols-2 gap-4">
        <div>
          <label class="block text-sm font-medium text-gray-700">Width</label>
          <input
            type="number"
            min="1"
            max="12"
            value={@widget["size"]["width"]}
            class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
          />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700">Height</label>
          <input
            type="number"
            min="1"
            max="12"
            value={@widget["size"]["height"]}
            class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
          />
        </div>
      </div>

      <div class="pt-4 border-t border-gray-200">
        <h3 class="text-sm font-medium text-gray-900 mb-3">Widget Configuration</h3>
        <!-- Widget-specific parameters would be rendered here -->
        <div class="text-sm text-gray-500">
          Configure <%= @widget["type"] %> widget parameters
        </div>
      </div>
    </div>
    """
  end

  defp widget_preview(assigns) do
    ~H"""
    <div class="p-4 bg-gray-50 rounded-lg">
      <h3 class="text-lg font-semibold text-gray-900 mb-2"><%= @widget["title"] %></h3>
      <div class="text-sm text-gray-600">
        <%= @widget["type"] |> String.capitalize() %> widget preview
      </div>
    </div>
    """
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp assign_template(socket, template) do
    socket
    |> assign(:page_title, "Edit Report Template")
    |> assign(:template, template)
    |> assign(:template_id, template.id)
    |> assign(:name, template.name)
    |> assign(:description, template.description)
    |> assign(:category, template.category)
    |> assign(:widgets, template.widgets)
    |> assign(:selected_widget, nil)
    |> assign(:available_widgets, WidgetRegistry.list_widgets())
    |> assign(:layout, template.layout)
    |> assign(:branding, template.branding)
    |> assign(:preview_mode, false)
    |> assign(:save_status, nil)
  end

  defp default_layout do
    %{
      "orientation" => "portrait",
      "page_size" => "A4",
      "columns" => 12,
      "row_height" => 50
    }
  end

  defp default_branding do
    %{
      "logo_url" => nil,
      "primary_color" => "#0066cc",
      "company_name" => "Tamandua EDR"
    }
  end

  defp calculate_next_position(widgets, layout) do
    columns = layout["columns"]

    if Enum.empty?(widgets) do
      %{"x" => 0, "y" => 0}
    else
      # Find the last widget and place new one after it
      last = List.last(widgets)
      x = last["position"]["x"] + last["size"]["width"]

      if x + 4 > columns do
        %{"x" => 0, "y" => last["position"]["y"] + last["size"]["height"]}
      else
        %{"x" => x, "y" => last["position"]["y"]}
      end
    end
  end
end
