defmodule TamanduaServerWeb.MLProcessLive do
  @moduledoc """
  Live dashboard for ML runtime processes tracked from endpoint telemetry.
  """

  use TamanduaServerWeb, :live_view

  alias Phoenix.PubSub
  alias TamanduaServer.Agents
  alias TamanduaServer.Detection.MLProcessTracker

  @refresh_interval 5_000
  @runtime_filters ~w(all python ollama llama_cpp vllm)

  @impl true
  def mount(params, _session, socket) do
    {agents, agents_error} = safe_list_agents()
    agent_id = params["agent_id"] || first_agent_id(agents)
    {processes, processes_error} = safe_get_processes(agent_id)

    if connected?(socket) do
      subscribe_agent(agent_id)
      Process.send_after(self(), :refresh, @refresh_interval)
    end

    {:ok,
     assign(socket,
       page_title: "ML Processes",
       agents: agents,
       agents_error: agents_error,
       agent_id: agent_id,
       processes: processes,
       processes_error: processes_error,
       search_query: "",
       runtime_filter: "all",
       auto_refresh: true,
       selected_process: List.first(processes)
     )}
  end

  @impl true
  def handle_params(%{"agent_id" => agent_id}, _uri, socket) do
    if connected?(socket) and socket.assigns[:agent_id] != agent_id do
      unsubscribe_agent(socket.assigns[:agent_id])
      subscribe_agent(agent_id)
    end

    {processes, processes_error} = safe_get_processes(agent_id)

    {:noreply,
     assign(socket,
       agent_id: agent_id,
       processes: processes,
       processes_error: processes_error,
       selected_process: List.first(processes)
     )}
  end

  def handle_params(_params, _uri, socket), do: {:noreply, socket}

  @impl true
  def handle_event("select_agent", %{"agent_id" => agent_id}, socket) do
    unsubscribe_agent(socket.assigns[:agent_id])
    subscribe_agent(agent_id)

    {processes, processes_error} = safe_get_processes(agent_id)

    {:noreply,
     assign(socket,
       agent_id: agent_id,
       processes: processes,
       processes_error: processes_error,
       selected_process: List.first(processes)
     )}
  end

  def handle_event("filter_runtime", %{"runtime" => runtime}, socket) do
    runtime = if runtime in @runtime_filters, do: runtime, else: "all"
    {:noreply, assign(socket, runtime_filter: runtime)}
  end

  def handle_event("search", %{"query" => query}, socket) do
    {:noreply, assign(socket, search_query: query || "")}
  end

  def handle_event("select_process", %{"pid" => pid}, socket) do
    process = Enum.find(socket.assigns.processes, &(to_string(field(&1, :pid)) == pid))
    {:noreply, assign(socket, selected_process: process)}
  end

  def handle_event("manual_refresh", _params, socket) do
    {processes, processes_error} = safe_get_processes(socket.assigns.agent_id)

    {:noreply,
     assign(socket,
       processes: processes,
       processes_error: processes_error,
       selected_process: keep_selected(processes, socket.assigns.selected_process)
     )}
  end

  def handle_event("toggle_refresh", _params, socket) do
    auto_refresh = !socket.assigns.auto_refresh

    if auto_refresh do
      Process.send_after(self(), :refresh, @refresh_interval)
    end

    {:noreply, assign(socket, auto_refresh: auto_refresh)}
  end

  @impl true
  def handle_info({:ml_process_update, :new, process_context}, socket) do
    processes =
      [process_context | reject_pid(socket.assigns.processes, field(process_context, :pid))]
      |> Enum.take(100)

    {:noreply, assign(socket, processes: processes, processes_error: nil, selected_process: process_context)}
  end

  def handle_info({:ml_process_update, :terminated, pid}, socket) do
    processes = reject_pid(socket.assigns.processes, pid)

    {:noreply,
     assign(socket,
       processes: processes,
       processes_error: nil,
       selected_process: keep_selected(processes, socket.assigns.selected_process)
     )}
  end

  def handle_info({:ml_process_update, :model_file, %{pid: pid, file: file}}, socket) do
    processes =
      Enum.map(socket.assigns.processes, fn process ->
        if to_string(field(process, :pid)) == to_string(pid) do
          Map.update(process, :model_files, [file], fn files -> Enum.uniq([file | List.wrap(files)]) end)
        else
          process
        end
      end)

    {:noreply,
     assign(socket,
       processes: processes,
       processes_error: nil,
       selected_process: keep_selected(processes, socket.assigns.selected_process)
     )}
  end

  def handle_info(:refresh, socket) do
    if socket.assigns.auto_refresh do
      {processes, processes_error} = safe_get_processes(socket.assigns.agent_id)
      Process.send_after(self(), :refresh, @refresh_interval)

      {:noreply,
       assign(socket,
         processes: processes,
         processes_error: processes_error,
         selected_process: keep_selected(processes, socket.assigns.selected_process)
       )}
    else
      {:noreply, socket}
    end
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  @impl true
  def render(assigns) do
    assigns = assign(assigns, filtered_processes: filter_processes(assigns.processes, assigns.runtime_filter, assigns.search_query))

    ~H"""
    <div class="max-w-7xl mx-auto p-6 space-y-6">
      <div class="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <h1 class="text-3xl font-bold">ML Processes</h1>
          <p class="text-gray-600 dark:text-gray-400">Runtime visibility for Python, Ollama, llama.cpp, and vLLM processes seen by agents.</p>
        </div>

        <div class="flex flex-wrap gap-2">
          <button phx-click="manual_refresh" class="btn btn-secondary">Refresh</button>
          <button phx-click="toggle_refresh" class={["btn", if(@auto_refresh, do: "btn-primary", else: "btn-secondary")]}>
            Auto: <%= if @auto_refresh, do: "ON", else: "OFF" %>
          </button>
        </div>
      </div>

      <div class="stats shadow bg-white dark:bg-gray-800">
        <div class="stat">
          <div class="stat-title">Tracked Processes</div>
          <div class="stat-value text-primary"><%= length(@processes) %></div>
          <div class="stat-desc">current agent</div>
        </div>
        <div class="stat">
          <div class="stat-title">Model Files</div>
          <div class="stat-value"><%= total_model_files(@processes) %></div>
        </div>
        <div class="stat">
          <div class="stat-title">Runtime Types</div>
          <div class="stat-value"><%= runtime_count(@processes) %></div>
        </div>
        <div class="stat">
          <div class="stat-title">Agents</div>
          <div class="stat-value"><%= length(@agents) %></div>
        </div>
      </div>

      <%= if @agents_error || @processes_error do %>
        <div class="alert alert-warning shadow-sm">
          <div>
            <h2 class="font-semibold">ML process telemetry is degraded</h2>
            <p class="text-sm">
              <%= @agents_error || @processes_error %>
            </p>
          </div>
        </div>
      <% end %>

      <div class="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <div>
          <label class="block text-sm font-medium mb-1">Agent</label>
          <select phx-change="select_agent" name="agent_id" class="select select-bordered w-full" disabled={length(@agents) == 0}>
            <%= if length(@agents) == 0 do %>
              <option value="">No agents available</option>
            <% else %>
              <%= for agent <- @agents do %>
                <option value={agent_id(agent)} selected={agent_id(agent) == @agent_id}><%= agent_name(agent) %></option>
              <% end %>
            <% end %>
          </select>
        </div>

        <div>
          <label class="block text-sm font-medium mb-1">Runtime</label>
          <select phx-change="filter_runtime" name="runtime" class="select select-bordered w-full">
            <option value="all" selected={@runtime_filter == "all"}>All runtimes</option>
            <option value="python" selected={@runtime_filter == "python"}>Python</option>
            <option value="ollama" selected={@runtime_filter == "ollama"}>Ollama</option>
            <option value="llama_cpp" selected={@runtime_filter == "llama_cpp"}>llama.cpp</option>
            <option value="vllm" selected={@runtime_filter == "vllm"}>vLLM</option>
          </select>
        </div>

        <div class="lg:col-span-2">
          <label class="block text-sm font-medium mb-1">Search</label>
          <input type="text" phx-change="search" phx-debounce="300" name="query" value={@search_query} placeholder="Process name, path, command line, framework..." class="input input-bordered w-full" />
        </div>
      </div>

      <div class="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div class="xl:col-span-2 bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
          <div class="overflow-x-auto">
            <table class="table table-zebra w-full">
              <thead>
                <tr>
                  <th>Process</th>
                  <th>Runtime</th>
                  <th>Framework</th>
                  <th>Model Files</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                <%= for process <- @filtered_processes do %>
                  <tr phx-click="select_process" phx-value-pid={field(process, :pid)} class="cursor-pointer hover:bg-base-200">
                    <td>
                      <div class="font-medium"><%= process_name(process) %></div>
                      <div class="text-xs text-gray-500">PID <%= value_or_dash(field(process, :pid)) %></div>
                    </td>
                    <td><span class="badge badge-outline"><%= runtime_label(field(process, :runtime_type)) %></span></td>
                    <td><%= value_or_dash(field(process, :framework)) %></td>
                    <td><%= length(List.wrap(field(process, :model_files))) %></td>
                    <td><%= format_time(field(process, :last_seen)) %></td>
                  </tr>
                <% end %>
              </tbody>
            </table>
          </div>

          <%= if length(@filtered_processes) == 0 do %>
            <div class="p-10 text-center text-gray-500 dark:text-gray-400">
              <%= if @processes_error do %>
                <p class="text-lg font-medium">ML process data did not load cleanly</p>
                <p class="text-sm mt-2">The tracker query failed. Existing endpoint telemetry may still be present, but this view cannot verify it right now.</p>
              <% else %>
                <p class="text-lg font-medium">No ML processes tracked</p>
                <p class="text-sm mt-2">Python, Ollama, llama.cpp, and vLLM process events will appear here when reported by the selected agent.</p>
              <% end %>
            </div>
          <% end %>
        </div>

        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-5">
          <%= if @selected_process do %>
            <h2 class="text-lg font-semibold mb-4"><%= process_name(@selected_process) %></h2>
            <dl class="space-y-3 text-sm">
              <div>
                <dt class="text-gray-500">Runtime</dt>
                <dd class="font-medium"><%= runtime_label(field(@selected_process, :runtime_type)) %></dd>
              </div>
              <div>
                <dt class="text-gray-500">Path</dt>
                <dd class="break-all"><%= value_or_dash(field(@selected_process, :path)) %></dd>
              </div>
              <div>
                <dt class="text-gray-500">Command Line</dt>
                <dd class="break-all"><%= value_or_dash(field(@selected_process, :cmdline)) %></dd>
              </div>
              <div>
                <dt class="text-gray-500">Started</dt>
                <dd><%= format_time(field(@selected_process, :started_at)) %></dd>
              </div>
            </dl>

            <div class="divider">Model Files</div>
            <%= if length(List.wrap(field(@selected_process, :model_files))) > 0 do %>
              <ul class="space-y-2 text-sm">
                <%= for file <- List.wrap(field(@selected_process, :model_files)) do %>
                  <li class="break-all rounded bg-base-200 px-3 py-2"><%= file %></li>
                <% end %>
              </ul>
            <% else %>
              <p class="text-sm text-gray-500">No correlated model files yet.</p>
            <% end %>
          <% else %>
            <h2 class="text-lg font-semibold mb-2">Process Context</h2>
            <p class="text-sm text-gray-500">Select a tracked ML process to inspect runtime context, command line, and correlated model files.</p>
          <% end %>
        </div>
      </div>
    </div>
    """
  end

  defp safe_list_agents do
    {Agents.list_agents(), nil}
  rescue
    exception -> {[], "Agent inventory failed to load: #{Exception.message(exception)}"}
  catch
    :exit, reason -> {[], "Agent inventory failed to load: #{inspect(reason)}"}
  end

  defp safe_get_processes(nil), do: {[], nil}
  defp safe_get_processes(""), do: {[], nil}

  defp safe_get_processes(agent_id) do
    {MLProcessTracker.get_ml_processes(agent_id), nil}
  rescue
    exception -> {[], "ML process tracker failed to load: #{Exception.message(exception)}"}
  catch
    :exit, reason -> {[], "ML process tracker failed to load: #{inspect(reason)}"}
  end

  defp subscribe_agent(nil), do: :ok
  defp subscribe_agent(""), do: :ok
  defp subscribe_agent(agent_id), do: PubSub.subscribe(TamanduaServer.PubSub, "ml_process:#{agent_id}")

  defp unsubscribe_agent(nil), do: :ok
  defp unsubscribe_agent(""), do: :ok
  defp unsubscribe_agent(agent_id), do: PubSub.unsubscribe(TamanduaServer.PubSub, "ml_process:#{agent_id}")

  defp first_agent_id([]), do: nil
  defp first_agent_id([agent | _]), do: agent_id(agent)

  defp agent_id(agent), do: to_string(field(agent, :agent_id) || field(agent, :id) || "")
  defp agent_name(agent), do: field(agent, :hostname) || field(agent, :name) || agent_id(agent)

  defp field(map, key) when is_map(map), do: Map.get(map, key) || Map.get(map, to_string(key))
  defp field(_, _), do: nil

  defp filter_processes(processes, runtime_filter, search_query) do
    query = String.downcase(search_query || "")

    processes
    |> Enum.filter(fn process ->
      runtime_filter == "all" or to_string(field(process, :runtime_type)) == runtime_filter
    end)
    |> Enum.filter(fn process ->
      query == "" or
        Enum.any?([:name, :path, :cmdline, :framework], fn key ->
          field(process, key)
          |> to_string()
          |> String.downcase()
          |> String.contains?(query)
        end)
    end)
  end

  defp reject_pid(processes, pid) do
    Enum.reject(processes, &(to_string(field(&1, :pid)) == to_string(pid)))
  end

  defp keep_selected(processes, nil), do: List.first(processes)

  defp keep_selected(processes, selected) do
    Enum.find(processes, &(to_string(field(&1, :pid)) == to_string(field(selected, :pid)))) || List.first(processes)
  end

  defp process_name(process), do: value_or_dash(field(process, :name))
  defp value_or_dash(nil), do: "-"
  defp value_or_dash(""), do: "-"
  defp value_or_dash(value), do: to_string(value)

  defp runtime_label(nil), do: "-"
  defp runtime_label(:llama_cpp), do: "llama.cpp"
  defp runtime_label("llama_cpp"), do: "llama.cpp"
  defp runtime_label(value), do: value |> to_string() |> String.replace("_", " ")

  defp total_model_files(processes) do
    Enum.reduce(processes, 0, fn process, acc -> acc + length(List.wrap(field(process, :model_files))) end)
  end

  defp runtime_count(processes) do
    processes
    |> Enum.map(&field(&1, :runtime_type))
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
    |> length()
  end

  defp format_time(nil), do: "-"
  defp format_time(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S UTC")
  defp format_time(value), do: to_string(value)
end
