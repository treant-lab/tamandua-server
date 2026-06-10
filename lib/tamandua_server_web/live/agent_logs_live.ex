defmodule TamanduaServerWeb.AgentLogsLive do
  @moduledoc """
  Real-time agent logs viewer with advanced filtering and search.

  Features:
  - Real-time log streaming via WebSocket
  - Multi-agent log aggregation
  - Advanced filtering (level, component, keyword, regex, time range)
  - Syntax highlighting by severity
  - Auto-scroll toggle
  - Log context expansion
  - Export (JSON, CSV, TXT)
  - Error pattern detection
  - Performance metrics
  """

  use TamanduaServerWeb, :live_view
  require Logger

  alias TamanduaServer.Agents
  alias TamanduaServer.Logs.Storage

  @default_tail_lines 100
  @max_logs_display 1000

  @impl true
  def mount(_params, session, socket) do
    if connected?(socket) do
      # Subscribe to log channel
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "logs:updates")
    end

    # Get current user and organization
    user = get_user_from_session(session)
    organization_id = user && user.organization_id

    # Get list of agents for filter
    agents = if organization_id, do: Agents.list_agents_for_organization(organization_id), else: []

    socket =
      socket
      |> assign(:user, user)
      |> assign(:organization_id, organization_id)
      |> assign(:agents, agents)
      |> assign(:logs, [])
      |> assign(:filtered_logs, [])
      |> assign(:selected_agents, [])
      |> assign(:selected_levels, ["info", "warn", "error"])
      |> assign(:selected_components, [])
      |> assign(:keyword_filter, "")
      |> assign(:regex_filter, "")
      |> assign(:time_range, "1h")
      |> assign(:auto_scroll, true)
      |> assign(:show_line_numbers, true)
      |> assign(:connected, false)
      |> assign(:log_stats, %{})
      |> assign(:error_patterns, [])
      |> assign(:expanded_logs, MapSet.new())
      |> assign(:loading, true)

    # Load initial logs
    send(self(), :load_initial_logs)

    {:ok, socket}
  end

  @impl true
  def handle_info(:load_initial_logs, socket) do
    filters = build_filters(socket.assigns)

    case Storage.fetch_logs(filters, @default_tail_lines) do
      {:ok, logs} ->
        socket =
          socket
          |> assign(:logs, Enum.reverse(logs))
          |> assign(:filtered_logs, Enum.reverse(logs))
          |> assign(:loading, false)
          |> connect_to_stream()

        {:noreply, socket}

      {:error, reason} ->
        Logger.error("Failed to load initial logs: #{inspect(reason)}")

        socket =
          socket
          |> assign(:loading, false)
          |> put_flash(:error, "Failed to load logs: #{inspect(reason)}")

        {:noreply, socket}
    end
  end

  @impl true
  def handle_info({:log_entry, log}, socket) do
    # New real-time log entry
    if matches_current_filters?(log, socket.assigns) do
      logs = [log | socket.assigns.logs]
      # Keep only last N logs in memory
      logs = Enum.take(logs, @max_logs_display)

      socket =
        socket
        |> assign(:logs, logs)
        |> assign(:filtered_logs, logs)

      {:noreply, socket}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_info({:log_batch, logs}, socket) do
    # Batch of real-time log entries
    filtered = Enum.filter(logs, &matches_current_filters?(&1, socket.assigns))

    if not Enum.empty?(filtered) do
      new_logs = filtered ++ socket.assigns.logs
      new_logs = Enum.take(new_logs, @max_logs_display)

      socket =
        socket
        |> assign(:logs, new_logs)
        |> assign(:filtered_logs, new_logs)

      {:noreply, socket}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_info(_msg, socket), do: {:noreply, socket}

  @impl true
  def handle_event("update_agent_filter", %{"agents" => agents}, socket) do
    selected = if is_list(agents), do: agents, else: [agents]

    socket =
      socket
      |> assign(:selected_agents, selected)
      |> assign(:loading, true)
      |> reconnect_stream()

    {:noreply, socket}
  end

  @impl true
  def handle_event("update_level_filter", %{"levels" => levels}, socket) do
    selected = if is_list(levels), do: levels, else: [levels]

    socket =
      socket
      |> assign(:selected_levels, selected)
      |> apply_filters()

    {:noreply, socket}
  end

  @impl true
  def handle_event("update_component_filter", %{"components" => components}, socket) do
    selected = if is_list(components), do: components, else: [components]

    socket =
      socket
      |> assign(:selected_components, selected)
      |> apply_filters()

    {:noreply, socket}
  end

  @impl true
  def handle_event("update_keyword", %{"keyword" => keyword}, socket) do
    socket =
      socket
      |> assign(:keyword_filter, keyword)
      |> apply_filters()

    {:noreply, socket}
  end

  @impl true
  def handle_event("update_regex", %{"regex" => regex}, socket) do
    socket =
      socket
      |> assign(:regex_filter, regex)
      |> apply_filters()

    {:noreply, socket}
  end

  @impl true
  def handle_event("toggle_auto_scroll", _params, socket) do
    {:noreply, assign(socket, :auto_scroll, not socket.assigns.auto_scroll)}
  end

  @impl true
  def handle_event("toggle_line_numbers", _params, socket) do
    {:noreply, assign(socket, :show_line_numbers, not socket.assigns.show_line_numbers)}
  end

  @impl true
  def handle_event("expand_log", %{"log_id" => log_id}, socket) do
    expanded = MapSet.put(socket.assigns.expanded_logs, log_id)
    {:noreply, assign(socket, :expanded_logs, expanded)}
  end

  @impl true
  def handle_event("collapse_log", %{"log_id" => log_id}, socket) do
    expanded = MapSet.delete(socket.assigns.expanded_logs, log_id)
    {:noreply, assign(socket, :expanded_logs, expanded)}
  end

  @impl true
  def handle_event("copy_log", %{"log_id" => log_id}, socket) do
    # Client-side copy handled via JavaScript
    {:noreply, socket}
  end

  @impl true
  def handle_event("export_logs", %{"format" => format}, socket) do
    filters = build_filters(socket.assigns)

    case Storage.fetch_logs(filters, 10_000) do
      {:ok, logs} ->
        exported_data = export_logs(logs, format)
        filename = "agent_logs_#{DateTime.utc_now() |> DateTime.to_unix()}.#{format}"

        socket =
          socket
          |> push_event("download", %{
            data: exported_data,
            filename: filename,
            mimetype: mimetype_for_format(format)
          })

        {:noreply, socket}

      {:error, reason} ->
        socket = put_flash(socket, :error, "Export failed: #{inspect(reason)}")
        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("clear_logs", _params, socket) do
    socket =
      socket
      |> assign(:logs, [])
      |> assign(:filtered_logs, [])

    {:noreply, socket}
  end

  @impl true
  def handle_event("load_stats", _params, socket) do
    filters = build_filters(socket.assigns)

    case Storage.get_log_stats(filters) do
      {:ok, stats} ->
        {:noreply, assign(socket, :log_stats, stats)}

      {:error, _reason} ->
        {:noreply, socket}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="h-screen flex flex-col bg-gray-900">
      <!-- Header -->
      <div class="bg-gray-800 border-b border-gray-700 px-6 py-4">
        <div class="flex items-center justify-between">
          <h1 class="text-2xl font-bold text-white">Agent Logs Viewer</h1>
          <div class="flex items-center space-x-4">
            <button
              phx-click="toggle_auto_scroll"
              class={"px-3 py-2 rounded text-sm font-medium transition " <>
                if(@auto_scroll, do: "bg-blue-600 text-white", else: "bg-gray-700 text-gray-300 hover:bg-gray-600")}
            >
              <%= if @auto_scroll, do: "Auto-scroll: ON", else: "Auto-scroll: OFF" %>
            </button>
            <button
              phx-click="toggle_line_numbers"
              class="px-3 py-2 rounded text-sm font-medium bg-gray-700 text-gray-300 hover:bg-gray-600"
            >
              <%= if @show_line_numbers, do: "Hide", else: "Show" %> Line #
            </button>
            <button
              phx-click="clear_logs"
              class="px-3 py-2 rounded text-sm font-medium bg-gray-700 text-gray-300 hover:bg-gray-600"
            >
              Clear
            </button>
            <div class="relative">
              <button
                id="export-button"
                class="px-3 py-2 rounded text-sm font-medium bg-gray-700 text-gray-300 hover:bg-gray-600"
              >
                Export ▾
              </button>
              <div id="export-menu" class="hidden absolute right-0 mt-2 w-32 bg-gray-800 rounded shadow-lg z-10">
                <button phx-click="export_logs" phx-value-format="json" class="block w-full text-left px-4 py-2 text-sm text-gray-300 hover:bg-gray-700">JSON</button>
                <button phx-click="export_logs" phx-value-format="csv" class="block w-full text-left px-4 py-2 text-sm text-gray-300 hover:bg-gray-700">CSV</button>
                <button phx-click="export_logs" phx-value-format="txt" class="block w-full text-left px-4 py-2 text-sm text-gray-300 hover:bg-gray-700">TXT</button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Filters -->
      <div class="bg-gray-800 border-b border-gray-700 px-6 py-3">
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <!-- Agent Filter -->
          <div>
            <label class="block text-xs font-medium text-gray-400 mb-1">Agents</label>
            <select
              multiple
              phx-change="update_agent_filter"
              name="agents"
              class="w-full bg-gray-700 border border-gray-600 text-gray-300 rounded px-3 py-2 text-sm"
            >
              <%= for agent <- @agents do %>
                <option value={agent.id} selected={agent.id in @selected_agents}>
                  <%= agent.hostname %> (<%= agent.id %>)
                </option>
              <% end %>
            </select>
          </div>

          <!-- Level Filter -->
          <div>
            <label class="block text-xs font-medium text-gray-400 mb-1">Log Levels</label>
            <div class="space-y-1">
              <%= for level <- ["trace", "debug", "info", "warn", "error"] do %>
                <label class="flex items-center text-sm text-gray-300">
                  <input
                    type="checkbox"
                    phx-change="update_level_filter"
                    name="levels"
                    value={level}
                    checked={level in @selected_levels}
                    class="mr-2"
                  />
                  <span class={level_color_class(level)}><%= String.upcase(level) %></span>
                </label>
              <% end %>
            </div>
          </div>

          <!-- Keyword Filter -->
          <div>
            <label class="block text-xs font-medium text-gray-400 mb-1">Keyword</label>
            <input
              type="text"
              phx-change="update_keyword"
              phx-debounce="300"
              name="keyword"
              value={@keyword_filter}
              placeholder="Search keyword..."
              class="w-full bg-gray-700 border border-gray-600 text-gray-300 rounded px-3 py-2 text-sm"
            />
          </div>

          <!-- Regex Filter -->
          <div>
            <label class="block text-xs font-medium text-gray-400 mb-1">Regex</label>
            <input
              type="text"
              phx-change="update_regex"
              phx-debounce="300"
              name="regex"
              value={@regex_filter}
              placeholder="Regex pattern..."
              class="w-full bg-gray-700 border border-gray-600 text-gray-300 rounded px-3 py-2 text-sm"
            />
          </div>
        </div>
      </div>

      <!-- Stats Bar -->
      <div class="bg-gray-800 border-b border-gray-700 px-6 py-2 text-xs text-gray-400">
        <div class="flex items-center space-x-6">
          <span>Total: <strong class="text-gray-300"><%= length(@filtered_logs) %></strong></span>
          <%= if @log_stats != %{} do %>
            <span>Errors: <strong class="text-red-400"><%= @log_stats[:error] || 0 %></strong></span>
            <span>Warnings: <strong class="text-yellow-400"><%= @log_stats[:warn] || 0 %></strong></span>
            <span>Info: <strong class="text-blue-400"><%= @log_stats[:info] || 0 %></strong></span>
            <span>Agents: <strong class="text-gray-300"><%= @log_stats[:agents] || 0 %></strong></span>
          <% end %>
          <%= if @connected do %>
            <span class="flex items-center">
              <span class="h-2 w-2 bg-green-500 rounded-full mr-2 animate-pulse"></span>
              Live
            </span>
          <% end %>
        </div>
      </div>

      <!-- Logs Display -->
      <div
        id="logs-container"
        phx-hook="LogsScroll"
        class="flex-1 overflow-y-auto bg-gray-900 font-mono text-sm"
      >
        <%= if @loading do %>
          <div class="flex items-center justify-center h-full">
            <div class="text-gray-500">Loading logs...</div>
          </div>
        <% else %>
          <%= if Enum.empty?(@filtered_logs) do %>
            <div class="flex items-center justify-center h-full">
              <div class="text-gray-500">No logs to display</div>
            </div>
          <% else %>
            <div class="p-4 space-y-1">
              <%= for {log, index} <- Enum.with_index(@filtered_logs) do %>
                <.log_entry
                  log={log}
                  index={index}
                  show_line_numbers={@show_line_numbers}
                  expanded={MapSet.member?(@expanded_logs, log_id(log))}
                />
              <% end %>
            </div>
          <% end %>
        <% end %>
      </div>
    </div>
    """
  end

  # Component for individual log entry
  defp log_entry(assigns) do
    ~H"""
    <div class={"log-entry flex hover:bg-gray-800 px-2 py-1 rounded " <> log_bg_class(@log.level)}>
      <%= if @show_line_numbers do %>
        <div class="text-gray-600 mr-4 select-none w-12 text-right flex-shrink-0">
          <%= @index + 1 %>
        </div>
      <% end %>
      <div class="flex-1 min-w-0">
        <div class="flex items-start space-x-3">
          <div class="text-gray-500 text-xs flex-shrink-0 w-40">
            <%= format_timestamp(@log.timestamp) %>
          </div>
          <div class={"font-semibold flex-shrink-0 w-16 " <> level_color_class(@log.level)}>
            <%= String.upcase(@log.level) %>
          </div>
          <div class="text-purple-400 flex-shrink-0 w-32 truncate" title={@log.component}>
            <%= @log.component %>
          </div>
          <div class="text-gray-300 flex-1 break-words">
            <%= @log.message %>
          </div>
          <div class="flex-shrink-0 flex items-center space-x-2">
            <%= if @log.file do %>
              <span class="text-xs text-gray-600" title={@log.file}>
                <%= Path.basename(@log.file) %>:<%= @log.line %>
              </span>
            <% end %>
            <button
              phx-click={if @expanded, do: "collapse_log", else: "expand_log"}
              phx-value-log_id={log_id(@log)}
              class="text-gray-600 hover:text-gray-400 text-xs"
            >
              <%= if @expanded, do: "−", else: "+" %>
            </button>
          </div>
        </div>
        <%= if @expanded and @log.fields do %>
          <div class="mt-2 ml-48 p-2 bg-gray-800 rounded text-xs">
            <pre class="text-gray-400"><%= Jason.encode!(@log.fields, pretty: true) %></pre>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  ## Private Functions

  defp connect_to_stream(socket) do
    # In production, this would establish WebSocket connection to LogsChannel
    # For now, just mark as connected
    assign(socket, :connected, true)
  end

  defp reconnect_stream(socket) do
    # Reload logs with new filters
    send(self(), :load_initial_logs)
    socket
  end

  defp apply_filters(socket) do
    filtered = Enum.filter(socket.assigns.logs, &matches_current_filters?(&1, socket.assigns))
    assign(socket, :filtered_logs, filtered)
  end

  defp build_filters(assigns) do
    %{
      agent_ids: assigns.selected_agents,
      levels: assigns.selected_levels,
      components: assigns.selected_components,
      keyword: if(assigns.keyword_filter != "", do: assigns.keyword_filter, else: nil),
      regex: if(assigns.regex_filter != "", do: assigns.regex_filter, else: nil),
      time_start: time_range_start(assigns.time_range),
      time_end: nil
    }
  end

  defp matches_current_filters?(log, assigns) do
    agent_match = Enum.empty?(assigns.selected_agents) or log.agent_id in assigns.selected_agents
    level_match = log.level in assigns.selected_levels
    component_match = Enum.empty?(assigns.selected_components) or log.component in assigns.selected_components

    keyword_match = assigns.keyword_filter == "" or String.contains?(log.message, assigns.keyword_filter)

    regex_match =
      if assigns.regex_filter != "" do
        case Regex.compile(assigns.regex_filter) do
          {:ok, regex} -> Regex.match?(regex, log.message)
          _ -> true
        end
      else
        true
      end

    agent_match and level_match and component_match and keyword_match and regex_match
  end

  defp time_range_start("15m"), do: System.system_time(:millisecond) - 15 * 60 * 1000
  defp time_range_start("1h"), do: System.system_time(:millisecond) - 60 * 60 * 1000
  defp time_range_start("6h"), do: System.system_time(:millisecond) - 6 * 60 * 60 * 1000
  defp time_range_start("24h"), do: System.system_time(:millisecond) - 24 * 60 * 60 * 1000
  defp time_range_start(_), do: nil

  defp level_color_class("trace"), do: "text-gray-500"
  defp level_color_class("debug"), do: "text-gray-400"
  defp level_color_class("info"), do: "text-blue-400"
  defp level_color_class("warn"), do: "text-yellow-400"
  defp level_color_class("error"), do: "text-red-400"
  defp level_color_class(_), do: "text-gray-400"

  defp log_bg_class("error"), do: "bg-red-900 bg-opacity-10"
  defp log_bg_class("warn"), do: "bg-yellow-900 bg-opacity-10"
  defp log_bg_class(_), do: ""

  defp format_timestamp(timestamp) do
    DateTime.from_unix!(timestamp, :millisecond)
    |> Calendar.strftime("%Y-%m-%d %H:%M:%S.%f")
    |> String.slice(0..-4)
  end

  defp log_id(log) do
    "#{log.agent_id}:#{log.timestamp}:#{:erlang.phash2(log.message)}"
  end

  defp export_logs(logs, "json"), do: Jason.encode!(logs, pretty: true)

  defp export_logs(logs, "csv") do
    headers = "timestamp,agent_id,level,component,message,file,line\n"
    rows =
      logs
      |> Enum.map(fn log ->
        [
          log.timestamp,
          log.agent_id,
          log.level,
          log.component,
          escape_csv(log.message),
          log.file || "",
          log.line || ""
        ]
        |> Enum.join(",")
      end)
      |> Enum.join("\n")

    headers <> rows
  end

  defp export_logs(logs, "txt") do
    logs
    |> Enum.map(fn log ->
      ts = format_timestamp(log.timestamp)
      "[#{ts}] [#{log.level}] [#{log.component}] #{log.message}"
    end)
    |> Enum.join("\n")
  end

  defp escape_csv(text) do
    "\"#{String.replace(text, "\"", "\"\"")}\""
  end

  defp mimetype_for_format("json"), do: "application/json"
  defp mimetype_for_format("csv"), do: "text/csv"
  defp mimetype_for_format("txt"), do: "text/plain"
  defp mimetype_for_format(_), do: "application/octet-stream"

  defp get_user_from_session(session) do
    case {session["user_id"], session["organization_id"]} do
      {user_id, organization_id} when is_binary(user_id) and is_binary(organization_id) ->
        %{id: user_id, organization_id: organization_id, email: session["email"]}

      _ ->
        %{id: nil, organization_id: nil, email: nil}
    end
  end
end
