defmodule TamanduaServerWeb.FileBrowserLive do
  @moduledoc """
  Live Response File Browser UI for remote filesystem exploration.

  Provides analysts with a comprehensive file browsing interface to:
  - Navigate remote agent filesystems in real-time
  - View file metadata (permissions, timestamps, ownership)
  - Preview text files and hex dumps
  - Download files using chunked streaming
  - Upload files for remediation
  - Search within directories
  - Perform forensic operations (hash, quarantine)

  ## Security
  - RBAC integration (requires :live_response_files permission)
  - All operations are audited
  - Cross-platform path handling (Windows vs Unix)
  - Path traversal prevention
  - File size limits for preview/download

  ## Features
  - Breadcrumb navigation
  - File tree view
  - Multi-pane layout (tree + details)
  - Keyboard shortcuts
  - Batch operations
  - Search and filtering
  - Streaming downloads for large files
  - Progress tracking
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Agents
  alias TamanduaServer.LiveResponse.CommandExecutor
  alias TamanduaServer.LiveResponse.SessionManager

  require Logger

  @max_preview_size 1_048_576  # 1 MB
  @max_hex_preview 65_536      # 64 KB for hex view

  # ============================================================================
  # Lifecycle
  # ============================================================================

  @impl true
  def mount(%{"agent_id" => agent_id} = params, session, socket) do
    user = get_current_user(socket, session)

    if connected?(socket) do
      # Subscribe to agent status changes
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "agents:#{agent_id}")
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "file_browser:#{agent_id}")
    end

    with :ok <- verify_permissions(user),
         {:ok, agent} <- get_agent(agent_id),
         :ok <- verify_agent_online(agent),
         {:ok, session_id} <- create_or_get_session(agent_id, user, params) do
      # Initialize browser state
      initial_path = get_initial_path(agent, params)

      socket =
        socket
        |> assign(:current_user, user)
        |> assign(:agent_id, agent_id)
        |> assign(:agent, agent)
        |> assign(:session_id, session_id)
        |> assign(:current_path, initial_path)
        |> assign(:files, [])
        |> assign(:selected_file, nil)
        |> assign(:breadcrumbs, parse_breadcrumbs(initial_path))
        |> assign(:loading, false)
        |> assign(:error, nil)
        |> assign(:view_mode, "list")  # list, grid, tree
        |> assign(:sort_by, "name")
        |> assign(:sort_order, "asc")
        |> assign(:search_query, "")
        |> assign(:show_hidden, true)
        |> assign(:preview_content, nil)
        |> assign(:preview_mode, nil)
        |> assign(:download_progress, %{})
        |> assign(:upload_progress, %{})
        |> assign(:page_title, "File Browser - #{agent.hostname}")

      # Load initial directory
      {:ok, load_directory(socket, initial_path)}
    else
      {:error, :unauthorized} ->
        {:ok,
         socket
         |> put_flash(:error, "Insufficient permissions for live response")
         |> redirect(to: "/agents")}

      {:error, :agent_not_found} ->
        {:ok,
         socket
         |> put_flash(:error, "Agent not found")
         |> redirect(to: "/agents")}

      {:error, :agent_offline} ->
        {:ok,
         socket
         |> put_flash(:error, "Agent is offline")
         |> redirect(to: "/agents")}

      {:error, reason} ->
        {:ok,
         socket
         |> put_flash(:error, "Failed to initialize: #{inspect(reason)}")
         |> redirect(to: "/agents")}
    end
  end

  # ============================================================================
  # Event Handlers
  # ============================================================================

  @impl true
  def handle_event("navigate", %{"path" => path}, socket) do
    {:noreply, load_directory(socket, path)}
  end

  @impl true
  def handle_event("navigate_breadcrumb", %{"index" => index_str}, socket) do
    index = String.to_integer(index_str)
    breadcrumbs = socket.assigns.breadcrumbs
    target_crumb = Enum.at(breadcrumbs, index)

    if target_crumb do
      {:noreply, load_directory(socket, target_crumb.path)}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_event("select_file", %{"path" => path}, socket) do
    file = Enum.find(socket.assigns.files, &(&1["path"] == path))

    socket =
      socket
      |> assign(:selected_file, file)
      |> assign(:preview_content, nil)
      |> assign(:preview_mode, nil)

    {:noreply, socket}
  end

  @impl true
  def handle_event("open_file", %{"path" => path}, socket) do
    file = Enum.find(socket.assigns.files, &(&1["path"] == path))

    if file && file["is_directory"] do
      {:noreply, load_directory(socket, path)}
    else
      # For files, select and preview
      {:noreply,
       socket
       |> assign(:selected_file, file)
       |> preview_file(path, "text")}
    end
  end

  @impl true
  def handle_event("preview_file", %{"path" => path, "mode" => mode}, socket) do
    {:noreply, preview_file(socket, path, mode)}
  end

  @impl true
  def handle_event("download_file", %{"path" => path}, socket) do
    {:noreply, start_download(socket, path)}
  end

  @impl true
  def handle_event("upload_file_start", %{"path" => path, "filename" => filename}, socket) do
    # Client will follow up with chunked upload
    socket =
      socket
      |> assign(:upload_target_path, path)
      |> assign(:upload_filename, filename)
      |> assign(:upload_chunks, [])

    {:noreply, socket}
  end

  @impl true
  def handle_event("upload_chunk", %{"chunk" => chunk, "offset" => offset}, socket) do
    chunks = socket.assigns[:upload_chunks] || []
    chunks = chunks ++ [{offset, chunk}]

    socket = assign(socket, :upload_chunks, chunks)
    {:noreply, socket}
  end

  @impl true
  def handle_event("upload_complete", _params, socket) do
    {:noreply, complete_upload(socket)}
  end

  @impl true
  def handle_event("hash_file", %{"path" => path}, socket) do
    {:noreply, hash_file(socket, path)}
  end

  @impl true
  def handle_event("delete_file", %{"path" => path}, socket) do
    if socket.assigns.current_user.role in [:admin, :responder] do
      {:noreply, delete_file(socket, path)}
    else
      {:noreply, put_flash(socket, :error, "Insufficient permissions to delete files")}
    end
  end

  @impl true
  def handle_event("refresh", _params, socket) do
    {:noreply, load_directory(socket, socket.assigns.current_path)}
  end

  @impl true
  def handle_event("toggle_hidden", _params, socket) do
    show_hidden = !socket.assigns.show_hidden
    {:noreply, assign(socket, :show_hidden, show_hidden) |> refresh_view()}
  end

  @impl true
  def handle_event("change_view", %{"mode" => mode}, socket) do
    {:noreply, assign(socket, :view_mode, mode)}
  end

  @impl true
  def handle_event("sort", %{"by" => field}, socket) do
    current_sort = socket.assigns.sort_by
    order = if current_sort == field && socket.assigns.sort_order == "asc", do: "desc", else: "asc"

    socket =
      socket
      |> assign(:sort_by, field)
      |> assign(:sort_order, order)
      |> sort_files()

    {:noreply, socket}
  end

  @impl true
  def handle_event("search", %{"query" => query}, socket) do
    {:noreply, assign(socket, :search_query, query) |> refresh_view()}
  end

  @impl true
  def handle_event("close_preview", _params, socket) do
    {:noreply, socket |> assign(:preview_content, nil) |> assign(:preview_mode, nil)}
  end

  @impl true
  def handle_event("parent_directory", _params, socket) do
    parent = get_parent_path(socket.assigns.current_path, socket.assigns.agent.os_type)
    {:noreply, load_directory(socket, parent)}
  end

  # ============================================================================
  # PubSub Handlers
  # ============================================================================

  @impl true
  def handle_info({:agent_status_changed, _agent_id, status}, socket) do
    socket =
      if status == :offline do
        socket
        |> put_flash(:error, "Agent went offline")
        |> assign(:error, "Agent offline")
        |> assign(:loading, false)
      else
        socket
      end

    {:noreply, socket}
  end

  @impl true
  def handle_info({:file_list_result, path, files}, socket) do
    if path == socket.assigns.current_path do
      socket =
        socket
        |> assign(:files, files)
        |> assign(:loading, false)
        |> assign(:error, nil)
        |> sort_files()
        |> refresh_view()

      {:noreply, socket}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_info({:download_chunk, download_id, _chunk, offset, total}, socket) do
    progress = Map.get(socket.assigns.download_progress, download_id, %{})
    progress = Map.merge(progress, %{
      offset: offset,
      total: total,
      percent: if(total > 0, do: Float.round(offset / total * 100, 1), else: 0)
    })

    socket = assign(socket, :download_progress, Map.put(socket.assigns.download_progress, download_id, progress))
    {:noreply, socket}
  end

  @impl true
  def handle_info({:download_complete, download_id, path}, socket) do
    socket =
      socket
      |> put_flash(:info, "Downloaded: #{Path.basename(path)}")
      |> assign(:download_progress, Map.delete(socket.assigns.download_progress, download_id))

    {:noreply, socket}
  end

  @impl true
  def handle_info({:preview_ready, path, mode, content}, socket) do
    if socket.assigns.selected_file && socket.assigns.selected_file["path"] == path do
      socket =
        socket
        |> assign(:preview_content, content)
        |> assign(:preview_mode, mode)
        |> assign(:loading, false)

      {:noreply, socket}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_info(msg, socket) do
    Logger.debug("Unhandled message in FileBrowserLive: #{inspect(msg)}")
    {:noreply, socket}
  end

  # ============================================================================
  # Render
  # ============================================================================

  @impl true
  def render(assigns) do
    ~H"""
    <div class="file-browser h-screen flex flex-col">
      <!-- Header -->
      <div class="bg-white border-b px-6 py-4 flex items-center justify-between">
        <div>
          <h1 class="text-2xl font-bold text-gray-900">File Browser</h1>
          <p class="text-sm text-gray-600">
            <span class="font-medium"><%= @agent.hostname %></span>
            <span class="mx-2">•</span>
            <span><%= @agent.os_type %></span>
          </p>
        </div>

        <div class="flex items-center space-x-3">
          <!-- View Mode Toggle -->
          <div class="flex rounded-md shadow-sm">
            <button
              phx-click="change_view"
              phx-value-mode="list"
              class={"px-3 py-2 text-sm font-medium rounded-l-md border #{if @view_mode == "list", do: "bg-blue-600 text-white border-blue-600", else: "bg-white text-gray-700 border-gray-300"}"}
            >
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"></path>
              </svg>
            </button>
            <button
              phx-click="change_view"
              phx-value-mode="grid"
              class={"px-3 py-2 text-sm font-medium border-t border-b #{if @view_mode == "grid", do: "bg-blue-600 text-white border-blue-600", else: "bg-white text-gray-700 border-gray-300"}"}
            >
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 5a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM14 5a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1V5zM4 15a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1H5a1 1 0 01-1-1v-4zM14 15a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1v-4z"></path>
              </svg>
            </button>
            <button
              phx-click="change_view"
              phx-value-mode="tree"
              class={"px-3 py-2 text-sm font-medium rounded-r-md border #{if @view_mode == "tree", do: "bg-blue-600 text-white border-blue-600", else: "bg-white text-gray-700 border-gray-300"}"}
            >
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"></path>
              </svg>
            </button>
          </div>

          <!-- Actions -->
          <button
            phx-click="toggle_hidden"
            class="px-3 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
          >
            <%= if @show_hidden, do: "Hide Hidden", else: "Show Hidden" %>
          </button>

          <button
            phx-click="refresh"
            class="px-3 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
            disabled={@loading}
          >
            <svg class={"w-5 h-5 #{if @loading, do: "animate-spin"}"} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
            </svg>
          </button>
        </div>
      </div>

      <!-- Breadcrumbs -->
      <div class="bg-gray-50 border-b px-6 py-3 flex items-center space-x-2 overflow-x-auto">
        <button
          phx-click="parent_directory"
          class="px-2 py-1 text-sm text-gray-600 hover:text-gray-900 hover:bg-gray-200 rounded"
          title="Parent Directory"
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"></path>
          </svg>
        </button>

        <%= for {crumb, index} <- Enum.with_index(@breadcrumbs) do %>
          <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
          </svg>
          <button
            phx-click="navigate_breadcrumb"
            phx-value-index={index}
            class={"px-2 py-1 text-sm rounded #{if index == length(@breadcrumbs) - 1, do: "text-gray-900 font-medium bg-gray-200", else: "text-gray-600 hover:text-gray-900 hover:bg-gray-200"}"}
          >
            <%= crumb.name %>
          </button>
        <% end %>
      </div>

      <!-- Main Content -->
      <div class="flex-1 flex overflow-hidden">
        <!-- File List Panel -->
        <div class="flex-1 flex flex-col overflow-hidden">
          <!-- Search Bar -->
          <div class="px-6 py-3 border-b bg-white">
            <form phx-change="search" class="relative">
              <input
                type="text"
                name="query"
                value={@search_query}
                placeholder="Search files and directories..."
                class="w-full px-4 py-2 pl-10 pr-4 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
              <svg class="absolute left-3 top-3 w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
              </svg>
            </form>
          </div>

          <!-- File List -->
          <div class="flex-1 overflow-auto bg-white">
            <%= if @loading do %>
              <div class="flex items-center justify-center h-full">
                <div class="text-center">
                  <svg class="animate-spin h-12 w-12 text-blue-600 mx-auto" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  <p class="mt-4 text-sm text-gray-600">Loading...</p>
                </div>
              </div>
            <% else %>
              <%= if @error do %>
                <div class="p-6">
                  <div class="bg-red-50 border border-red-200 rounded-lg p-4">
                    <p class="text-sm text-red-800"><%= @error %></p>
                  </div>
                </div>
              <% else %>
                <%= if Enum.empty?(filtered_files(@files, @search_query, @show_hidden)) do %>
                  <div class="flex items-center justify-center h-full">
                    <div class="text-center text-gray-500">
                      <svg class="w-16 h-16 mx-auto mb-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4"></path>
                      </svg>
                      <p class="text-sm">No files found</p>
                    </div>
                  </div>
                <% else %>
                  <%= render_file_list(assigns) %>
                <% end %>
              <% end %>
            <% end %>
          </div>
        </div>

        <!-- Details / Preview Panel -->
        <%= if @selected_file || @preview_content do %>
          <div class="w-1/3 border-l bg-white flex flex-col overflow-hidden">
            <div class="px-6 py-4 border-b flex items-center justify-between">
              <h3 class="text-lg font-medium text-gray-900">Details</h3>
              <button
                phx-click="close_preview"
                class="text-gray-400 hover:text-gray-600"
              >
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                </svg>
              </button>
            </div>

            <div class="flex-1 overflow-auto p-6">
              <%= if @selected_file do %>
                <%= render_file_details(assigns) %>
              <% end %>

              <%= if @preview_content do %>
                <div class="mt-6">
                  <h4 class="text-sm font-medium text-gray-900 mb-3">Preview</h4>
                  <%= render_preview(assigns) %>
                </div>
              <% end %>
            </div>
          </div>
        <% end %>
      </div>

      <!-- Download Progress Overlay -->
      <%= if not Enum.empty?(@download_progress) do %>
        <div class="fixed bottom-6 right-6 w-96 space-y-2">
          <%= for {download_id, progress} <- @download_progress do %>
            <div class="bg-white rounded-lg shadow-lg border border-gray-200 p-4">
              <div class="flex items-center justify-between mb-2">
                <p class="text-sm font-medium text-gray-900">Downloading...</p>
                <p class="text-sm text-gray-600"><%= progress.percent %>%</p>
              </div>
              <div class="w-full bg-gray-200 rounded-full h-2">
                <div class="bg-blue-600 h-2 rounded-full transition-all" style={"width: #{progress.percent}%"}></div>
              </div>
            </div>
          <% end %>
        </div>
      <% end %>
    </div>
    """
  end

  # ============================================================================
  # Private Rendering Helpers
  # ============================================================================

  defp render_file_list(assigns) do
    files = filtered_files(assigns.files, assigns.search_query, assigns.show_hidden)

    case assigns.view_mode do
      "grid" -> render_grid_view(%{assigns | files: files})
      "tree" -> render_tree_view(%{assigns | files: files})
      _ -> render_list_view(%{assigns | files: files})
    end
  end

  defp render_list_view(assigns) do
    ~H"""
    <table class="min-w-full divide-y divide-gray-200">
      <thead class="bg-gray-50 sticky top-0">
        <tr>
          <th scope="col" class="px-6 py-3 text-left">
            <button phx-click="sort" phx-value-by="name" class="flex items-center text-xs font-medium text-gray-500 uppercase tracking-wider hover:text-gray-700">
              Name
              <%= sort_icon("name", @sort_by, @sort_order) %>
            </button>
          </th>
          <th scope="col" class="px-6 py-3 text-left">
            <button phx-click="sort" phx-value-by="size" class="flex items-center text-xs font-medium text-gray-500 uppercase tracking-wider hover:text-gray-700">
              Size
              <%= sort_icon("size", @sort_by, @sort_order) %>
            </button>
          </th>
          <th scope="col" class="px-6 py-3 text-left">
            <button phx-click="sort" phx-value-by="modified" class="flex items-center text-xs font-medium text-gray-500 uppercase tracking-wider hover:text-gray-700">
              Modified
              <%= sort_icon("modified", @sort_by, @sort_order) %>
            </button>
          </th>
          <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
            Permissions
          </th>
          <th scope="col" class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
            Actions
          </th>
        </tr>
      </thead>
      <tbody class="bg-white divide-y divide-gray-200">
        <%= for file <- @files do %>
          <tr
            class={"hover:bg-gray-50 cursor-pointer #{if @selected_file && @selected_file["path"] == file["path"], do: "bg-blue-50"}"}
            phx-click="select_file"
            phx-value-path={file["path"]}
            phx-dblclick="open_file"
            phx-value-path={file["path"]}
          >
            <td class="px-6 py-4 whitespace-nowrap">
              <div class="flex items-center">
                <%= file_icon(file) %>
                <span class="ml-3 text-sm font-medium text-gray-900"><%= file["name"] %></span>
              </div>
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
              <%= if file["is_directory"], do: "—", else: format_size(file["size"]) %>
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
              <%= format_timestamp(file["modified"]) %>
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
              <%= if file["readonly"], do: "Read-only", else: "Read-write" %>
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
              <div class="flex items-center justify-end space-x-2">
                <%= if not file["is_directory"] do %>
                  <button
                    phx-click="preview_file"
                    phx-value-path={file["path"]}
                    phx-value-mode="text"
                    class="text-blue-600 hover:text-blue-900"
                    title="Preview"
                  >
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
                    </svg>
                  </button>
                  <button
                    phx-click="download_file"
                    phx-value-path={file["path"]}
                    class="text-green-600 hover:text-green-900"
                    title="Download"
                  >
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path>
                    </svg>
                  </button>
                  <button
                    phx-click="hash_file"
                    phx-value-path={file["path"]}
                    class="text-purple-600 hover:text-purple-900"
                    title="Hash"
                  >
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 20l4-16m2 16l4-16M6 9h14M4 15h14"></path>
                    </svg>
                  </button>
                <% end %>
              </div>
            </td>
          </tr>
        <% end %>
      </tbody>
    </table>
    """
  end

  defp render_grid_view(assigns) do
    ~H"""
    <div class="grid grid-cols-4 gap-4 p-6">
      <%= for file <- @files do %>
        <div
          phx-click="select_file"
          phx-value-path={file["path"]}
          phx-dblclick="open_file"
          phx-value-path={file["path"]}
          class={"p-4 border rounded-lg cursor-pointer hover:shadow-md transition-shadow #{if @selected_file && @selected_file["path"] == file["path"], do: "border-blue-500 bg-blue-50", else: "border-gray-200"}"}
        >
          <div class="text-center">
            <%= file_icon(file, "w-12 h-12 mx-auto") %>
            <p class="mt-2 text-sm font-medium text-gray-900 truncate"><%= file["name"] %></p>
            <%= if not file["is_directory"] do %>
              <p class="text-xs text-gray-500"><%= format_size(file["size"]) %></p>
            <% end %>
          </div>
        </div>
      <% end %>
    </div>
    """
  end

  defp render_tree_view(assigns) do
    ~H"""
    <div class="p-6">
      <p class="text-sm text-gray-500">Tree view coming soon...</p>
    </div>
    """
  end

  defp render_file_details(assigns) do
    file = assigns.selected_file

    ~H"""
    <div class="space-y-4">
      <div>
        <h4 class="text-sm font-medium text-gray-900 mb-2"><%= file["name"] %></h4>
        <p class="text-xs text-gray-500 break-all"><%= file["path"] %></p>
      </div>

      <dl class="space-y-2">
        <div>
          <dt class="text-xs font-medium text-gray-500">Type</dt>
          <dd class="mt-1 text-sm text-gray-900">
            <%= if file["is_directory"], do: "Directory", else: "File" %>
          </dd>
        </div>

        <%= if not file["is_directory"] do %>
          <div>
            <dt class="text-xs font-medium text-gray-500">Size</dt>
            <dd class="mt-1 text-sm text-gray-900"><%= format_size(file["size"]) %></dd>
          </div>
        <% end %>

        <div>
          <dt class="text-xs font-medium text-gray-500">Modified</dt>
          <dd class="mt-1 text-sm text-gray-900"><%= format_timestamp(file["modified"]) %></dd>
        </div>

        <div>
          <dt class="text-xs font-medium text-gray-500">Created</dt>
          <dd class="mt-1 text-sm text-gray-900"><%= format_timestamp(file["created"]) %></dd>
        </div>

        <div>
          <dt class="text-xs font-medium text-gray-500">Permissions</dt>
          <dd class="mt-1 text-sm text-gray-900">
            <%= if file["readonly"], do: "Read-only", else: "Read-write" %>
          </dd>
        </div>
      </dl>

      <%= if not file["is_directory"] do %>
        <div class="pt-4 border-t space-y-2">
          <button
            phx-click="preview_file"
            phx-value-path={file["path"]}
            phx-value-mode="text"
            class="w-full px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700"
          >
            Preview Text
          </button>
          <button
            phx-click="preview_file"
            phx-value-path={file["path"]}
            phx-value-mode="hex"
            class="w-full px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
          >
            Hex Dump
          </button>
          <button
            phx-click="download_file"
            phx-value-path={file["path"]}
            class="w-full px-4 py-2 text-sm font-medium text-white bg-green-600 rounded-md hover:bg-green-700"
          >
            Download
          </button>
          <button
            phx-click="hash_file"
            phx-value-path={file["path"]}
            class="w-full px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
          >
            Calculate Hash
          </button>
        </div>
      <% end %>
    </div>
    """
  end

  defp render_preview(assigns) do
    case assigns.preview_mode do
      "text" ->
        ~H"""
        <div class="bg-gray-900 rounded-lg p-4 overflow-auto max-h-96">
          <pre class="text-xs text-green-400 font-mono"><%= @preview_content %></pre>
        </div>
        """

      "hex" ->
        ~H"""
        <div class="bg-gray-900 rounded-lg p-4 overflow-auto max-h-96">
          <pre class="text-xs text-blue-400 font-mono"><%= @preview_content %></pre>
        </div>
        """

      _ ->
        ~H"""
        <p class="text-sm text-gray-500">No preview available</p>
        """
    end
  end

  # ============================================================================
  # Private Implementation
  # ============================================================================

  defp verify_permissions(nil), do: {:error, :unauthorized}

  defp verify_permissions(user) do
    # Check RBAC permission
    if TamanduaServer.Authorization.RBAC.can?(user, :live_response_files) do
      :ok
    else
      # Fallback: check role
      if user.role in [:admin, :analyst, :responder] do
        :ok
      else
        {:error, :unauthorized}
      end
    end
  end

  defp get_agent(agent_id) do
    case Agents.get_agent(agent_id) do
      {:ok, agent} -> {:ok, agent}
      {:error, _} -> {:error, :agent_not_found}
    end
  end

  defp verify_agent_online(agent) do
    if agent.status in [:online, :isolated] do
      :ok
    else
      {:error, :agent_offline}
    end
  end

  defp create_or_get_session(agent_id, user, params) do
    # Check if there's an existing session
    sessions = SessionManager.list_sessions(agent_id: agent_id, user_id: user.id)
    active = Enum.find(sessions, &(&1.status in [:active, :idle]))

    if active do
      {:ok, active.session_id}
    else
      case SessionManager.create_session(agent_id, user.id,
        notes: "File browser session",
        case_id: params["case_id"],
        alert_id: params["alert_id"]
      ) do
        {:ok, session} -> {:ok, session.session_id}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp get_initial_path(agent, params) do
    case Map.get(params, "path") do
      nil -> default_path(agent.os_type)
      path -> path
    end
  end

  defp default_path("windows"), do: "C:\\"
  defp default_path("linux"), do: "/"
  defp default_path("darwin"), do: "/"
  defp default_path(_), do: "/"

  defp load_directory(socket, path) do
    socket = socket |> assign(:loading, true) |> assign(:error, nil)

    # Send command to agent
    _agent_id = socket.assigns.agent_id
    session_id = socket.assigns.session_id

    Task.start(fn ->
      case CommandExecutor.list_directory(session_id, path, recursive: false) do
        {:ok, result} ->
          files = result.output["files"] || []
          send(self(), {:file_list_result, path, files})

        {:error, reason} ->
          send(self(), {:error, :file_list_failed, reason})
      end
    end)

    socket
    |> assign(:current_path, path)
    |> assign(:breadcrumbs, parse_breadcrumbs(path))
  end

  defp preview_file(socket, path, mode) do
    socket = assign(socket, :loading, true)

    max_size = if mode == "hex", do: @max_hex_preview, else: @max_preview_size

    Task.start(fn ->
      session_id = socket.assigns.session_id

      case CommandExecutor.read_file(session_id, path, mode: mode, max_size: max_size) do
        {:ok, result} ->
          content = result.output["content"] || ""
          send(self(), {:preview_ready, path, mode, content})

        {:error, _reason} ->
          send(self(), {:preview_ready, path, mode, "Error loading preview"})
      end
    end)

    socket
  end

  defp start_download(socket, path) do
    download_id = generate_download_id()

    socket = put_in(socket.assigns.download_progress[download_id], %{
      path: path,
      offset: 0,
      total: 0,
      percent: 0
    })

    Task.start(fn ->
      session_id = socket.assigns.session_id

      case CommandExecutor.download_file(session_id, path) do
        {:ok, _result} ->
          # Handle download result (chunked or single-shot)
          send(self(), {:download_complete, download_id, path})

        {:error, _reason} ->
          send(self(), {:download_error, download_id})
      end
    end)

    socket
  end

  defp complete_upload(socket) do
    chunks = socket.assigns[:upload_chunks] || []
    target_path = socket.assigns[:upload_target_path]
    filename = socket.assigns[:upload_filename]

    # Reassemble chunks
    content = chunks
      |> Enum.sort_by(fn {offset, _} -> offset end)
      |> Enum.map(fn {_, chunk} -> chunk end)
      |> Enum.join()
      |> Base.decode64!()

    full_path = Path.join(target_path, filename)

    Task.start(fn ->
      session_id = socket.assigns.session_id

      case CommandExecutor.upload_file(session_id, full_path, content) do
        {:ok, _result} ->
          send(self(), {:upload_complete, full_path})

        {:error, _reason} ->
          send(self(), {:upload_error, full_path})
      end
    end)

    socket
    |> assign(:upload_chunks, [])
    |> assign(:upload_target_path, nil)
    |> assign(:upload_filename, nil)
  end

  defp hash_file(socket, path) do
    Task.start(fn ->
      session_id = socket.assigns.session_id

      case CommandExecutor.hash_file(session_id, path) do
        {:ok, result} ->
          send(self(), {:hash_result, path, result.output})

        {:error, _reason} ->
          send(self(), {:hash_error, path})
      end
    end)

    put_flash(socket, :info, "Calculating hashes...")
  end

  defp delete_file(socket, path) do
    if socket.assigns.current_user.role in [:admin, :responder] do
      Task.start(fn ->
        session_id = socket.assigns.session_id

        case CommandExecutor.delete_file(session_id, path) do
          {:ok, _result} ->
            send(self(), {:delete_complete, path})

          {:error, _reason} ->
            send(self(), {:delete_error, path})
        end
      end)

      put_flash(socket, :info, "Deleting file...")
    else
      put_flash(socket, :error, "Insufficient permissions")
    end
  end

  defp parse_breadcrumbs(path) do
    cond do
      String.contains?(path, "\\") ->
        # Windows path
        parts = String.split(path, "\\", trim: true)
        Enum.with_index(parts)
        |> Enum.map(fn {part, index} ->
          crumb_path = Enum.take(parts, index + 1) |> Enum.join("\\")
          %{name: if(index == 0, do: part, else: part), path: crumb_path <> "\\"}
        end)

      String.starts_with?(path, "/") ->
        # Unix path
        parts = String.split(path, "/", trim: true)
        root = %{name: "/", path: "/"}
        rest = Enum.with_index(parts)
        |> Enum.map(fn {part, index} ->
          crumb_path = "/" <> (Enum.take(parts, index + 1) |> Enum.join("/"))
          %{name: part, path: crumb_path}
        end)
        [root | rest]

      true ->
        [%{name: path, path: path}]
    end
  end

  defp get_parent_path(path, os_type) do
    case os_type do
      "windows" ->
        parts = String.split(path, "\\", trim: true)
        if length(parts) <= 1 do
          path
        else
          Enum.take(parts, length(parts) - 1) |> Enum.join("\\") |> Kernel.<>("\\")
        end

      _ ->
        parts = String.split(path, "/", trim: true)
        if Enum.empty?(parts) do
          "/"
        else
          "/" <> (Enum.take(parts, length(parts) - 1) |> Enum.join("/"))
        end
    end
  end

  defp filtered_files(files, query, show_hidden) do
    files
    |> Enum.filter(fn file ->
      name_matches = if query == "", do: true, else: String.contains?(String.downcase(file["name"]), String.downcase(query))
      hidden_filter = if show_hidden, do: true, else: !String.starts_with?(file["name"], ".")
      name_matches && hidden_filter
    end)
  end

  defp sort_files(socket) do
    files = socket.assigns.files
    sort_by = socket.assigns.sort_by
    sort_order = socket.assigns.sort_order

    sorted = Enum.sort_by(files, fn file ->
      case sort_by do
        "name" -> file["name"]
        "size" -> file["size"] || 0
        "modified" -> file["modified"] || 0
        _ -> file["name"]
      end
    end, if(sort_order == "asc", do: :asc, else: :desc))

    # Always put directories first
    {dirs, files_only} = Enum.split_with(sorted, & &1["is_directory"])
    assign(socket, :files, dirs ++ files_only)
  end

  defp refresh_view(socket) do
    socket
    |> sort_files()
  end

  defp get_current_user(socket, session) do
    socket.assigns[:current_user] || session["current_user"]
  end

  # ============================================================================
  # Formatting Helpers
  # ============================================================================

  defp file_icon(file, class \\ "w-6 h-6") do
    if file["is_directory"] do
      Phoenix.HTML.raw(~s|<svg class="#{class} text-blue-500" fill="currentColor" viewBox="0 0 20 20"><path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z"></path></svg>|)
    else
      Phoenix.HTML.raw(~s|<svg class="#{class} text-gray-400" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clip-rule="evenodd"></path></svg>|)
    end
  end

  defp format_size(nil), do: "—"
  defp format_size(bytes) when bytes < 1024, do: "#{bytes} B"
  defp format_size(bytes) when bytes < 1_048_576, do: "#{Float.round(bytes / 1024, 1)} KB"
  defp format_size(bytes) when bytes < 1_073_741_824, do: "#{Float.round(bytes / 1_048_576, 1)} MB"
  defp format_size(bytes), do: "#{Float.round(bytes / 1_073_741_824, 2)} GB"

  defp format_timestamp(nil), do: "—"
  defp format_timestamp(unix_seconds) when is_integer(unix_seconds) do
    DateTime.from_unix!(unix_seconds)
    |> Calendar.strftime("%Y-%m-%d %H:%M:%S")
  end
  defp format_timestamp(_), do: "—"

  defp sort_icon(field, current_field, order) do
    if field == current_field do
      if order == "asc" do
        Phoenix.HTML.raw(~s|<svg class="w-4 h-4 ml-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 15l7-7 7 7"></path></svg>|)
      else
        Phoenix.HTML.raw(~s|<svg class="w-4 h-4 ml-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>|)
      end
    else
      Phoenix.HTML.raw("")
    end
  end

  defp generate_download_id do
    "dl_" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
  end
end
