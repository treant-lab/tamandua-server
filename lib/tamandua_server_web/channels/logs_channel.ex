defmodule TamanduaServerWeb.LogsChannel do
  @moduledoc """
  WebSocket channel for real-time agent log streaming.

  Topic: "logs:viewer"

  Join with authentication token and optional filters:
  ```
  channel.join("logs:viewer", {
    token: "jwt_token",
    agent_ids: ["agent-123", "agent-456"],
    levels: ["info", "warn", "error"],
    components: ["collectors", "transport"],
    keyword: "process",
    regex: "error.*timeout",
    tail: 100  // number of historical logs to fetch
  })
  ```

  Pushed events:
  - "log" - New log entry from agent
  - "logs:batch" - Batch of historical logs
  - "logs:error" - Stream error
  """

  use TamanduaServerWeb, :channel
  require Logger

  alias TamanduaServer.Agents.LogAggregator
  alias TamanduaServer.Logs.Storage

  @impl true
  def join("logs:viewer", params, socket) do
    # Authenticate user (already done in socket connect)
    unless socket.assigns[:current_user] do
      {:error, %{reason: "unauthorized"}}
    else
      # Parse filters
      filters = parse_filters(params)

      # Validate agent access (RBAC)
      organization_id = get_organization_id(socket)
      agent_ids = validate_agent_access(filters.agent_ids, organization_id)

      if Enum.empty?(agent_ids) and not Enum.empty?(filters.agent_ids) do
        {:error, %{reason: "no_authorized_agents"}}
      else
        # Update filters with validated agent IDs
        filters = %{filters | agent_ids: agent_ids}

        # Generate stream ID
        stream_id = generate_stream_id(socket)

        # Register with LogAggregator for real-time streaming
        :ok = LogAggregator.register_stream(stream_id, self(), filters)

        # Fetch historical logs if requested
        tail_count = params["tail"] || 0
        if tail_count > 0 do
          send(self(), {:fetch_historical, tail_count, filters})
        end

        # Store state in socket
        socket =
          socket
          |> assign(:stream_id, stream_id)
          |> assign(:filters, filters)
          |> assign(:log_count, 0)
          |> assign(:auto_scroll, params["auto_scroll"] || true)

        Logger.info("Logs stream joined: #{stream_id} (user: #{socket.assigns.user_id})")

        {:ok, %{stream_id: stream_id, filters: filters}, socket}
      end
    end
  end

  @impl true
  def handle_info({:fetch_historical, count, filters}, socket) do
    # Fetch historical logs from storage
    case Storage.fetch_logs(filters, count) do
      {:ok, logs} ->
        push(socket, "logs:batch", %{
          logs: logs,
          count: length(logs),
          historical: true
        })

      {:error, reason} ->
        Logger.warning("Failed to fetch historical logs: #{inspect(reason)}")
    end

    {:noreply, socket}
  end

  @impl true
  def handle_info({:log_entry, log}, socket) do
    # Real-time log entry from agent
    if matches_filter?(log, socket.assigns.filters) do
      push(socket, "log", format_log_entry(log))

      # Update log count
      socket = assign(socket, :log_count, socket.assigns.log_count + 1)
      {:noreply, socket}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_info({:log_batch, logs}, socket) do
    # Batch of log entries
    filtered_logs =
      logs
      |> Enum.filter(&matches_filter?(&1, socket.assigns.filters))
      |> Enum.map(&format_log_entry/1)

    if not Enum.empty?(filtered_logs) do
      push(socket, "logs:batch", %{
        logs: filtered_logs,
        count: length(filtered_logs),
        historical: false
      })

      socket = assign(socket, :log_count, socket.assigns.log_count + length(filtered_logs))
      {:noreply, socket}
    else
      {:noreply, socket}
    end
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  @impl true
  def handle_in("update_filters", %{"filters" => new_filters}, socket) do
    # Allow dynamic filter updates
    stream_id = socket.assigns.stream_id
    organization_id = get_organization_id(socket)

    filters = parse_filters(new_filters)
    agent_ids = validate_agent_access(filters.agent_ids, organization_id)
    filters = %{filters | agent_ids: agent_ids}

    # Update registration
    :ok = LogAggregator.update_stream(stream_id, filters)

    # Update socket state
    socket = assign(socket, :filters, filters)

    Logger.info("Logs stream filters updated: #{stream_id}")

    {:reply, {:ok, %{filters: filters}}, socket}
  end

  @impl true
  def handle_in("fetch_context", %{"log_id" => log_id, "lines" => lines}, socket) do
    # Fetch log context (lines before/after)
    context_lines = max(1, min(lines, 50))

    case Storage.fetch_log_context(log_id, context_lines) do
      {:ok, context} ->
        {:reply, {:ok, %{
          before: context.before,
          target: context.target,
          after: context.after
        }}, socket}

      {:error, reason} ->
        {:reply, {:error, %{reason: inspect(reason)}}, socket}
    end
  end

  @impl true
  def handle_in("export", %{"format" => format}, socket) do
    # Export current filtered logs
    filters = socket.assigns.filters
    max_export = 10_000

    case Storage.fetch_logs(filters, max_export) do
      {:ok, logs} ->
        exported_data = export_logs(logs, format)

        {:reply, {:ok, %{
          data: exported_data,
          count: length(logs),
          format: format
        }}, socket}

      {:error, reason} ->
        {:reply, {:error, %{reason: inspect(reason)}}, socket}
    end
  end

  @impl true
  def handle_in("stats", _params, socket) do
    # Get log statistics
    filters = socket.assigns.filters

    case Storage.get_log_stats(filters) do
      {:ok, stats} ->
        {:reply, {:ok, stats}, socket}

      {:error, reason} ->
        {:reply, {:error, %{reason: inspect(reason)}}, socket}
    end
  end

  @impl true
  def terminate(reason, socket) do
    stream_id = socket.assigns[:stream_id]

    if stream_id do
      LogAggregator.unregister_stream(stream_id)
      Logger.info("Logs stream terminated: #{stream_id} (reason: #{inspect(reason)})")
    end

    :ok
  end

  # Private Functions

  defp parse_filters(params) do
    %{
      agent_ids: parse_list(params["agent_ids"]),
      levels: parse_list(params["levels"]),
      components: parse_list(params["components"]),
      keyword: params["keyword"],
      regex: params["regex"],
      time_start: parse_timestamp(params["time_start"]),
      time_end: parse_timestamp(params["time_end"])
    }
  end

  defp parse_list(nil), do: []
  defp parse_list(list) when is_list(list), do: list
  defp parse_list(item) when is_binary(item), do: [item]
  defp parse_list(_), do: []

  defp parse_timestamp(nil), do: nil
  defp parse_timestamp(ts) when is_integer(ts), do: ts
  defp parse_timestamp(ts) when is_binary(ts) do
    case Integer.parse(ts) do
      {parsed, ""} -> parsed
      _ -> nil
    end
  end
  defp parse_timestamp(_), do: nil

  defp validate_agent_access(agent_ids, organization_id) do
    # Filter to only agents that belong to the user's organization
    if Enum.empty?(agent_ids) do
      # No specific agents requested - get all for org
      TamanduaServer.Agents.list_agents_for_org(organization_id)
      |> Enum.map(& &1.id)
    else
      # Validate each agent belongs to org
      agent_ids
      |> Enum.filter(fn agent_id ->
        case TamanduaServer.Agents.Registry.get(agent_id) do
          {:ok, agent} -> agent.organization_id == organization_id
          _ -> false
        end
      end)
    end
  end

  defp get_organization_id(socket) do
    socket.assigns[:organization_id] ||
      socket.assigns[:current_user][:organization_id] ||
      get_user_organization(socket.assigns[:user_id])
  end

  defp get_user_organization(user_id) do
    case TamanduaServer.Accounts.get_user(user_id) do
      nil -> nil
      user -> user.organization_id
    end
  end

  defp generate_stream_id(socket) do
    user_id = socket.assigns[:user_id] || "unknown"
    "logs_#{user_id}_#{:erlang.unique_integer([:positive])}"
  end

  defp matches_filter?(log, filters) do
    # Check agent ID
    agent_match = Enum.empty?(filters.agent_ids) or log.agent_id in filters.agent_ids

    # Check level
    level_match = Enum.empty?(filters.levels) or log.level in filters.levels

    # Check component
    component_match = Enum.empty?(filters.components) or log.component in filters.components

    # Check keyword
    keyword_match = is_nil(filters.keyword) or String.contains?(log.message, filters.keyword)

    # Check regex
    regex_match =
      if filters.regex do
        case Regex.compile(filters.regex) do
          {:ok, regex} -> Regex.match?(regex, log.message)
          _ -> true
        end
      else
        true
      end

    # Check time range
    time_match =
      (is_nil(filters.time_start) or log.timestamp >= filters.time_start) and
      (is_nil(filters.time_end) or log.timestamp <= filters.time_end)

    agent_match and level_match and component_match and keyword_match and regex_match and time_match
  end

  defp format_log_entry(log) do
    %{
      id: log.id || generate_log_id(log),
      timestamp: log.timestamp,
      agent_id: log.agent_id,
      level: log.level,
      component: log.component,
      message: log.message,
      fields: log.fields,
      file: log.file,
      line: log.line,
      thread: log.thread
    }
  end

  defp generate_log_id(log) do
    # Generate deterministic ID from log data
    data = "#{log.agent_id}:#{log.timestamp}:#{log.message}"
    :crypto.hash(:sha256, data) |> Base.encode16(case: :lower) |> String.slice(0, 16)
  end

  defp export_logs(logs, "json") do
    Jason.encode!(logs)
  end

  defp export_logs(logs, "csv") do
    # CSV export
    headers = ["timestamp", "agent_id", "level", "component", "message", "file", "line"]
    rows = Enum.map(logs, fn log ->
      [
        log.timestamp,
        log.agent_id,
        log.level,
        log.component,
        log.message,
        log.file || "",
        log.line || ""
      ]
    end)

    [headers | rows]
    |> CSV.encode()
    |> Enum.to_list()
    |> Enum.join()
  end

  defp export_logs(logs, "txt") do
    # Plain text export
    logs
    |> Enum.map(fn log ->
      timestamp = format_timestamp(log.timestamp)
      "[#{timestamp}] [#{log.level}] [#{log.component}] #{log.message}"
    end)
    |> Enum.join("\n")
  end

  defp export_logs(logs, _), do: export_logs(logs, "json")

  defp format_timestamp(timestamp) do
    DateTime.from_unix!(timestamp, :millisecond)
    |> DateTime.to_iso8601()
  end
end
