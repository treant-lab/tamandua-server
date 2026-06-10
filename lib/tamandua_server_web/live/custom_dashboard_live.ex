defmodule TamanduaServerWeb.CustomDashboardLive do
  @moduledoc """
  Customizable dashboard with drag-and-drop widgets.

  This provides a flexible, widget-based dashboard system where users can:
  - Create multiple custom dashboards
  - Add/remove widgets from a library
  - Drag and drop widgets to rearrange
  - Configure widget settings
  - Save layouts and preferences
  - Use pre-built templates (SOC analyst, executive, incident responder, etc.)
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Dashboards.{Manager, Layout, Widget}
  alias Phoenix.PubSub

  require Logger

  # Simple modal component
  attr :id, :string, required: true
  attr :show, :boolean, default: false
  attr :on_cancel, :any, default: nil
  slot :inner_block, required: true

  def modal(assigns) do
    ~H"""
    <div
      id={@id}
      class="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50"
      phx-click={@on_cancel}
    >
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow-lg max-w-lg w-full mx-4 p-6" phx-click-away={@on_cancel}>
        <%= render_slot(@inner_block) %>
      </div>
    </div>
    """
  end

  @impl true
  def mount(_params, session, socket) do
    user_id = session["user_id"] || (socket.assigns[:current_user] && socket.assigns[:current_user].id)

    if user_id do
      if connected?(socket) do
        # Subscribe to real-time updates
        PubSub.subscribe(TamanduaServer.PubSub, "alerts:new")
        PubSub.subscribe(TamanduaServer.PubSub, "agents:status")
        PubSub.subscribe(TamanduaServer.PubSub, "dashboard:#{user_id}")
      end

      # Get or create default layout
      {:ok, layout} = Manager.get_or_create_default_layout(user_id)

      # Fetch initial widget data
      widget_data = fetch_all_widget_data(layout.widgets)

      {:ok,
       socket
       |> assign(page_title: "Custom Dashboard")
       |> assign(user_id: user_id)
       |> assign(layout: layout)
       |> assign(widgets: layout.widgets)
       |> assign(widget_data: widget_data)
       |> assign(editing: false)
       |> assign(show_widget_library: false)
       |> assign(selected_widget: nil)
       |> assign(show_settings_modal: false)
       |> assign(show_layout_selector: false)
       |> assign(available_layouts: Manager.list_user_layouts(user_id))
       |> assign(templates: Manager.list_template_layouts())}
    else
      {:ok,
       socket
       |> put_flash(:error, "You must be logged in to view dashboards")
       |> redirect(to: "/login")}
    end
  end

  @impl true
  def handle_params(params, _url, socket) do
    case params["layout_id"] do
      nil ->
        {:noreply, socket}

      layout_id ->
        case Manager.get_layout(layout_id) do
          nil ->
            {:noreply,
             socket
             |> put_flash(:error, "Layout not found")
             |> push_patch(to: "/dashboard/custom")}

          layout ->
            if layout.user_id == socket.assigns.user_id do
              widget_data = fetch_all_widget_data(layout.widgets)

              {:noreply,
               socket
               |> assign(layout: layout)
               |> assign(widgets: layout.widgets)
               |> assign(widget_data: widget_data)}
            else
              {:noreply,
               socket
               |> put_flash(:error, "Unauthorized")
               |> push_patch(to: "/dashboard/custom")}
            end
        end
    end
  end

  @impl true
  def handle_event("toggle_edit_mode", _params, socket) do
    {:noreply, assign(socket, editing: !socket.assigns.editing)}
  end

  def handle_event("show_widget_library", _params, socket) do
    {:noreply, assign(socket, show_widget_library: true)}
  end

  def handle_event("hide_widget_library", _params, socket) do
    {:noreply, assign(socket, show_widget_library: false)}
  end

  def handle_event("add_widget", %{"type" => widget_type}, socket) do
    # Find next available position
    next_position = calculate_next_position(socket.assigns.widgets)

    attrs = %{
      dashboard_layout_id: socket.assigns.layout.id,
      widget_type: widget_type,
      title: Widget.widget_type_name(widget_type),
      position_x: next_position.x,
      position_y: next_position.y,
      width: 4,
      height: 3,
      config: Widget.default_config(widget_type)
    }

    case Manager.create_widget(attrs) do
      {:ok, widget} ->
        widgets = socket.assigns.widgets ++ [widget]
        widget_data = Map.put(socket.assigns.widget_data, widget.id, %{loading: true})

        # Fetch data for new widget asynchronously
        send(self(), {:fetch_widget_data, widget.id})

        {:noreply,
         socket
         |> assign(widgets: widgets)
         |> assign(widget_data: widget_data)
         |> assign(show_widget_library: false)
         |> put_flash(:info, "Widget added successfully")}

      {:error, changeset} ->
        {:noreply,
         socket
         |> put_flash(:error, "Failed to add widget: #{inspect(changeset.errors)}")}
    end
  end

  def handle_event("delete_widget", %{"widget-id" => widget_id}, socket) do
    widget = Manager.get_widget(widget_id)

    case Manager.delete_widget(widget) do
      {:ok, _} ->
        widgets = Enum.reject(socket.assigns.widgets, &(&1.id == widget_id))
        widget_data = Map.delete(socket.assigns.widget_data, widget_id)

        {:noreply,
         socket
         |> assign(widgets: widgets)
         |> assign(widget_data: widget_data)
         |> put_flash(:info, "Widget deleted")}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Failed to delete widget")}
    end
  end

  def handle_event("update_layout", %{"layout" => layout_data}, socket) do
    # Parse widget positions from grid layout
    widgets_positions =
      Enum.map(layout_data, fn {widget_id, position} ->
        %{
          "id" => widget_id,
          "position_x" => position["x"],
          "position_y" => position["y"],
          "width" => position["w"],
          "height" => position["h"]
        }
      end)

    case Manager.update_widget_positions(widgets_positions) do
      {:ok, _} ->
        {:noreply, put_flash(socket, :info, "Layout saved")}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Failed to save layout")}
    end
  end

  def handle_event("show_widget_settings", %{"widget-id" => widget_id}, socket) do
    widget = Enum.find(socket.assigns.widgets, &(&1.id == widget_id))

    {:noreply,
     socket
     |> assign(show_settings_modal: true)
     |> assign(selected_widget: widget)}
  end

  def handle_event("hide_widget_settings", _params, socket) do
    {:noreply,
     socket
     |> assign(show_settings_modal: false)
     |> assign(selected_widget: nil)}
  end

  def handle_event("update_widget_settings", %{"widget" => widget_params}, socket) do
    widget = socket.assigns.selected_widget

    case Manager.update_widget(widget, widget_params) do
      {:ok, updated_widget} ->
        widgets =
          Enum.map(socket.assigns.widgets, fn w ->
            if w.id == updated_widget.id, do: updated_widget, else: w
          end)

        # Refresh widget data
        send(self(), {:fetch_widget_data, updated_widget.id})

        {:noreply,
         socket
         |> assign(widgets: widgets)
         |> assign(show_settings_modal: false)
         |> assign(selected_widget: nil)
         |> put_flash(:info, "Widget settings updated")}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Failed to update widget settings")}
    end
  end

  def handle_event("refresh_widget", %{"widget-id" => widget_id}, socket) do
    send(self(), {:fetch_widget_data, widget_id})
    {:noreply, socket}
  end

  def handle_event("show_layout_selector", _params, socket) do
    {:noreply, assign(socket, show_layout_selector: true)}
  end

  def handle_event("hide_layout_selector", _params, socket) do
    {:noreply, assign(socket, show_layout_selector: false)}
  end

  def handle_event("switch_layout", %{"layout-id" => layout_id}, socket) do
    {:noreply,
     socket
     |> assign(show_layout_selector: false)
     |> push_patch(to: "/dashboard/custom?layout_id=#{layout_id}")}
  end

  def handle_event("create_from_template", %{"template-type" => template_type}, socket) do
    case Manager.create_from_template(socket.assigns.user_id, template_type) do
      {:ok, layout} ->
        available_layouts = Manager.list_user_layouts(socket.assigns.user_id)

        {:noreply,
         socket
         |> assign(available_layouts: available_layouts)
         |> assign(show_layout_selector: false)
         |> push_patch(to: "/dashboard/custom?layout_id=#{layout.id}")
         |> put_flash(:info, "Dashboard created from template")}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Failed to create dashboard")}
    end
  end

  def handle_event("set_default_layout", %{"layout-id" => layout_id}, socket) do
    case Manager.set_default_layout(layout_id, socket.assigns.user_id) do
      {:ok, _} ->
        {:noreply, put_flash(socket, :info, "Default dashboard updated")}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Failed to set default dashboard")}
    end
  end

  def handle_event("delete_layout", %{"layout-id" => layout_id}, socket) do
    layout = Manager.get_layout(layout_id)

    if layout && layout.user_id == socket.assigns.user_id do
      case Manager.delete_layout(layout) do
        {:ok, _} ->
          available_layouts = Manager.list_user_layouts(socket.assigns.user_id)

          {:noreply,
           socket
           |> assign(available_layouts: available_layouts)
           |> push_patch(to: "/dashboard/custom")
           |> put_flash(:info, "Dashboard deleted")}

        {:error, _} ->
          {:noreply, put_flash(socket, :error, "Failed to delete dashboard")}
      end
    else
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    end
  end

  def handle_event("export_layout", _params, socket) do
    case Manager.export_layout(socket.assigns.layout) do
      {:ok, json} ->
        # Send download command to client
        {:noreply,
         push_event(socket, "download", %{
           filename: "dashboard_#{socket.assigns.layout.id}.json",
           content: json
         })}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Failed to export dashboard")}
    end
  end

  @impl true
  def handle_info({:fetch_widget_data, widget_id}, socket) do
    widget = Enum.find(socket.assigns.widgets, &(&1.id == widget_id))

    if widget do
      case Manager.fetch_widget_data(widget) do
        {:ok, data} ->
          widget_data = Map.put(socket.assigns.widget_data, widget_id, data)
          {:noreply, assign(socket, widget_data: widget_data)}

        {:error, error} ->
          Logger.error("Failed to fetch widget data: #{inspect(error)}")
          widget_data = Map.put(socket.assigns.widget_data, widget_id, %{error: true})
          {:noreply, assign(socket, widget_data: widget_data)}
      end
    else
      {:noreply, socket}
    end
  end

  # Handle real-time PubSub events
  def handle_info({:alert_created, _alert}, socket) do
    # Refresh relevant widgets
    alert_widget_types = ["threat_level_gauge", "recent_alerts", "top_detections", "timeline"]

    socket.assigns.widgets
    |> Enum.filter(&(&1.widget_type in alert_widget_types))
    |> Enum.each(&send(self(), {:fetch_widget_data, &1.id}))

    {:noreply, socket}
  end

  def handle_info({:agent_status_changed, _agent}, socket) do
    # Refresh agent status widgets
    socket.assigns.widgets
    |> Enum.filter(&(&1.widget_type == "agent_status_overview"))
    |> Enum.each(&send(self(), {:fetch_widget_data, &1.id}))

    {:noreply, socket}
  end

  def handle_info(_, socket), do: {:noreply, socket}

  # ========================
  # Helpers
  # ========================

  defp fetch_all_widget_data(widgets) do
    widgets
    |> Enum.map(fn widget ->
      case Manager.fetch_widget_data(widget) do
        {:ok, data} -> {widget.id, data}
        {:error, _} -> {widget.id, %{error: true}}
      end
    end)
    |> Map.new()
  end

  defp calculate_next_position(widgets) do
    if Enum.empty?(widgets) do
      %{x: 0, y: 0}
    else
      # Find the bottom-most widget and place below it
      max_y =
        widgets
        |> Enum.map(&(&1.position_y + &1.height))
        |> Enum.max()

      %{x: 0, y: max_y}
    end
  end

  # ========================
  # Render
  # ========================

  @impl true
  def render(assigns) do
    ~H"""
    <div class="h-full flex flex-col bg-gray-50 dark:bg-gray-900">
      <%!-- Header --%>
      <div class="bg-white dark:bg-gray-800 shadow px-6 py-4 flex items-center justify-between">
        <div class="flex items-center gap-4">
          <h1 class="text-2xl font-bold text-gray-900 dark:text-gray-100">
            <%= @layout.name %>
          </h1>
          <button
            phx-click="show_layout_selector"
            class="text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400"
          >
            Switch Dashboard
          </button>
        </div>

        <div class="flex items-center gap-3">
          <%= if @editing do %>
            <button
              phx-click="show_widget_library"
              class="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-md text-sm font-medium transition-colors"
            >
              Add Widget
            </button>
          <% end %>

          <button
            phx-click="toggle_edit_mode"
            class={"px-4 py-2 rounded-md text-sm font-medium transition-colors #{if @editing, do: "bg-blue-600 hover:bg-blue-700 text-white", else: "bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-900 dark:text-gray-100"}"}
          >
            <%= if @editing, do: "Done Editing", else: "Edit Dashboard" %>
          </button>

          <button
            phx-click="export_layout"
            class="px-4 py-2 bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-900 dark:text-gray-100 rounded-md text-sm font-medium transition-colors"
          >
            Export
          </button>
        </div>
      </div>

      <%!-- Dashboard Grid --%>
      <div class="flex-1 overflow-auto p-6">
        <div
          id="dashboard-grid"
          phx-hook="DashboardGrid"
          data-editing={@editing}
          class="dashboard-grid"
        >
          <%= for widget <- @widgets do %>
            <div
              id={"widget-#{widget.id}"}
              class="dashboard-widget bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700"
              data-widget-id={widget.id}
              data-x={widget.position_x}
              data-y={widget.position_y}
              data-w={widget.width}
              data-h={widget.height}
            >
              <%!-- Widget Header --%>
              <div class="widget-header flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
                <h3 class="font-semibold text-gray-900 dark:text-gray-100 cursor-move">
                  <%= widget.title %>
                </h3>
                <div class="flex items-center gap-2">
                  <button
                    phx-click="refresh_widget"
                    phx-value-widget-id={widget.id}
                    class="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
                    title="Refresh"
                  >
                    <.icon name="hero-arrow-path" class="h-4 w-4" />
                  </button>

                  <%= if @editing do %>
                    <button
                      phx-click="show_widget_settings"
                      phx-value-widget-id={widget.id}
                      class="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
                      title="Settings"
                    >
                      <.icon name="hero-cog-6-tooth" class="h-4 w-4" />
                    </button>
                    <button
                      phx-click="delete_widget"
                      phx-value-widget-id={widget.id}
                      class="text-red-500 hover:text-red-700 dark:text-red-400"
                      data-confirm="Are you sure you want to delete this widget?"
                      title="Delete"
                    >
                      <.icon name="hero-trash" class="h-4 w-4" />
                    </button>
                  <% end %>
                </div>
              </div>

              <%!-- Widget Content --%>
              <div class="widget-content p-4">
                <%= render_widget_content(widget, Map.get(@widget_data, widget.id, %{})) %>
              </div>
            </div>
          <% end %>
        </div>
      </div>

      <%!-- Widget Library Modal --%>
      <%= if @show_widget_library do %>
        <.modal id="widget-library-modal" show on_cancel={JS.push("hide_widget_library")}>
          <h2 class="text-xl font-bold mb-4">Add Widget</h2>
          <div class="grid grid-cols-2 gap-3 max-h-96 overflow-y-auto">
            <%= for widget_type <- Widget.widget_types() do %>
              <button
                phx-click="add_widget"
                phx-value-type={widget_type}
                class="p-4 border border-gray-300 dark:border-gray-600 rounded-lg hover:border-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900 transition-colors text-left"
              >
                <div class="font-semibold text-gray-900 dark:text-gray-100">
                  <%= Widget.widget_type_name(widget_type) %>
                </div>
                <div class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  <%= widget_type %>
                </div>
              </button>
            <% end %>
          </div>
        </.modal>
      <% end %>

      <%!-- Widget Settings Modal --%>
      <%= if @show_settings_modal && @selected_widget do %>
        <.modal id="widget-settings-modal" show on_cancel={JS.push("hide_widget_settings")}>
          <h2 class="text-xl font-bold mb-4">Widget Settings</h2>
          <.form
            for={%{}}
            phx-submit="update_widget_settings"
            as={:widget}
            class="space-y-4"
          >
            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Title
              </label>
              <input
                type="text"
                name="widget[title]"
                value={@selected_widget.title}
                class="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 px-3 py-2"
              />
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Refresh Interval (ms)
              </label>
              <input
                type="number"
                name="widget[refresh_interval]"
                value={@selected_widget.refresh_interval}
                min="1000"
                step="1000"
                class="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 px-3 py-2"
              />
            </div>

            <%!-- Widget-specific settings would go here --%>

            <div class="flex justify-end gap-3 mt-6">
              <button
                type="button"
                phx-click="hide_widget_settings"
                class="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
              >
                Cancel
              </button>
              <button
                type="submit"
                class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md"
              >
                Save
              </button>
            </div>
          </.form>
        </.modal>
      <% end %>

      <%!-- Layout Selector Modal --%>
      <%= if @show_layout_selector do %>
        <.modal id="layout-selector-modal" show on_cancel={JS.push("hide_layout_selector")}>
          <h2 class="text-xl font-bold mb-4">Switch Dashboard</h2>

          <div class="space-y-6">
            <%!-- User Layouts --%>
            <div>
              <h3 class="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
                My Dashboards
              </h3>
              <div class="space-y-2">
                <%= for layout <- @available_layouts do %>
                  <div class="flex items-center justify-between p-3 border border-gray-300 dark:border-gray-600 rounded-md">
                    <div class="flex-1">
                      <div class="font-medium text-gray-900 dark:text-gray-100">
                        <%= layout.name %>
                        <%= if layout.is_default do %>
                          <span class="ml-2 text-xs bg-blue-100 text-blue-800 px-2 py-0.5 rounded">
                            Default
                          </span>
                        <% end %>
                      </div>
                      <%= if layout.description do %>
                        <div class="text-sm text-gray-500 dark:text-gray-400">
                          <%= layout.description %>
                        </div>
                      <% end %>
                    </div>
                    <div class="flex items-center gap-2 ml-4">
                      <button
                        phx-click="switch_layout"
                        phx-value-layout-id={layout.id}
                        class="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm"
                      >
                        Open
                      </button>
                      <%= if !layout.is_default do %>
                        <button
                          phx-click="set_default_layout"
                          phx-value-layout-id={layout.id}
                          class="px-3 py-1 border border-gray-300 dark:border-gray-600 rounded text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
                          title="Set as default"
                        >
                          Set Default
                        </button>
                      <% end %>
                      <button
                        phx-click="delete_layout"
                        phx-value-layout-id={layout.id}
                        data-confirm="Are you sure you want to delete this dashboard?"
                        class="text-red-500 hover:text-red-700"
                        title="Delete"
                      >
                        <.icon name="hero-trash" class="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                <% end %>
              </div>
            </div>

            <%!-- Templates --%>
            <div>
              <h3 class="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
                Create from Template
              </h3>
              <div class="grid grid-cols-2 gap-2">
                <%= for template_type <- Layout.template_types() do %>
                  <button
                    phx-click="create_from_template"
                    phx-value-template-type={template_type}
                    class="p-3 border border-gray-300 dark:border-gray-600 rounded-md hover:border-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900 transition-colors text-left"
                  >
                    <div class="font-medium text-gray-900 dark:text-gray-100">
                      <%= template_type |> String.replace("_", " ") |> String.capitalize() %>
                    </div>
                  </button>
                <% end %>
              </div>
            </div>
          </div>
        </.modal>
      <% end %>
    </div>
    """
  end

  # ========================
  # Widget Rendering
  # ========================

  defp render_widget_content(%{widget_type: "threat_level_gauge"}, data) do
    assigns = %{data: data}

    ~H"""
    <div class="flex items-center justify-around h-full">
      <%= if Map.has_key?(@data, :error) do %>
        <div class="text-red-500">Error loading data</div>
      <% else %>
        <div class="text-center">
          <div class="text-3xl font-bold text-red-600"><%= @data[:critical] || 0 %></div>
          <div class="text-sm text-gray-500">Critical</div>
        </div>
        <div class="text-center">
          <div class="text-3xl font-bold text-orange-600"><%= @data[:high] || 0 %></div>
          <div class="text-sm text-gray-500">High</div>
        </div>
        <div class="text-center">
          <div class="text-3xl font-bold text-yellow-600"><%= @data[:medium] || 0 %></div>
          <div class="text-sm text-gray-500">Medium</div>
        </div>
        <div class="text-center">
          <div class="text-3xl font-bold text-blue-600"><%= @data[:low] || 0 %></div>
          <div class="text-sm text-gray-500">Low</div>
        </div>
      <% end %>
    </div>
    """
  end

  defp render_widget_content(%{widget_type: "agent_status_overview"}, data) do
    assigns = %{data: data}

    ~H"""
    <div class="flex items-center justify-around h-full">
      <%= if Map.has_key?(@data, :error) do %>
        <div class="text-red-500">Error loading data</div>
      <% else %>
        <div class="text-center">
          <div class="text-3xl font-bold text-gray-900 dark:text-gray-100">
            <%= @data[:total] || 0 %>
          </div>
          <div class="text-sm text-gray-500">Total</div>
        </div>
        <div class="text-center">
          <div class="text-3xl font-bold text-green-600"><%= @data[:online] || 0 %></div>
          <div class="text-sm text-gray-500">Online</div>
        </div>
        <div class="text-center">
          <div class="text-3xl font-bold text-gray-600"><%= @data[:offline] || 0 %></div>
          <div class="text-sm text-gray-500">Offline</div>
        </div>
        <div class="text-center">
          <div class="text-3xl font-bold text-red-600"><%= @data[:error] || 0 %></div>
          <div class="text-sm text-gray-500">Error</div>
        </div>
      <% end %>
    </div>
    """
  end

  defp render_widget_content(%{widget_type: "top_detections"}, data) do
    assigns = %{data: data}

    ~H"""
    <div class="space-y-2 overflow-y-auto max-h-full">
      <%= if Map.has_key?(@data, :error) do %>
        <div class="text-red-500">Error loading data</div>
      <% else %>
        <%= for detection <- @data[:detections] || [] do %>
          <div class="flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-700 rounded">
            <span class="text-sm text-gray-900 dark:text-gray-100">
              <%= detection.technique %>
            </span>
            <span class="text-sm font-semibold text-gray-700 dark:text-gray-300">
              <%= detection.count %>
            </span>
          </div>
        <% end %>
        <%= if Enum.empty?(@data[:detections] || []) do %>
          <div class="text-center text-gray-500 py-8">No detections</div>
        <% end %>
      <% end %>
    </div>
    """
  end

  defp render_widget_content(%{widget_type: "recent_alerts"}, data) do
    assigns = %{data: data}

    ~H"""
    <div class="space-y-2 overflow-y-auto max-h-full">
      <%= if Map.has_key?(@data, :error) do %>
        <div class="text-red-500">Error loading data</div>
      <% else %>
        <%= for alert <- @data[:alerts] || [] do %>
          <div class="p-3 border border-gray-200 dark:border-gray-600 rounded">
            <div class="flex items-center justify-between mb-1">
              <span class="text-sm font-semibold text-gray-900 dark:text-gray-100">
                <%= alert.title %>
              </span>
              <span class={"text-xs px-2 py-0.5 rounded #{severity_class(alert.severity)}"}>
                <%= alert.severity %>
              </span>
            </div>
            <%= if alert.mitre_technique do %>
              <div class="text-xs text-gray-500"><%= alert.mitre_technique %></div>
            <% end %>
            <div class="text-xs text-gray-400 mt-1">
              <%= Calendar.strftime(alert.inserted_at, "%Y-%m-%d %H:%M:%S") %>
            </div>
          </div>
        <% end %>
        <%= if Enum.empty?(@data[:alerts] || []) do %>
          <div class="text-center text-gray-500 py-8">No recent alerts</div>
        <% end %>
      <% end %>
    </div>
    """
  end

  defp render_widget_content(%{widget_type: "timeline"}, data) do
    assigns = %{data: data}

    ~H"""
    <div class="h-full">
      <%= if Map.has_key?(@data, :error) do %>
        <div class="text-red-500">Error loading data</div>
      <% else %>
        <div class="text-sm text-gray-500 text-center py-8">
          Timeline chart would render here
          <br />
          (Requires Chart.js integration)
        </div>
      <% end %>
    </div>
    """
  end

  defp render_widget_content(widget, _data) do
    assigns = %{widget: widget}

    ~H"""
    <div class="text-center text-gray-500 py-8">
      Widget type "<%= @widget.widget_type %>" not yet implemented
    </div>
    """
  end

  defp severity_class("critical"), do: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
  defp severity_class("high"), do: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200"
  defp severity_class("medium"), do: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
  defp severity_class("low"), do: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
  defp severity_class(_), do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"
end
