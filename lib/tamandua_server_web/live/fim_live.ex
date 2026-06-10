defmodule TamanduaServerWeb.FimLive do
  @moduledoc """
  FIM Dashboard - File Integrity Monitoring overview.

  Shows:
  - Baseline statistics
  - Recent file changes
  - Compliance status
  - Policy violations
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Fim.BaselineManager

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "fim:changes")
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "fim:baselines")

      # Refresh stats every 30 seconds
      :timer.send_interval(30_000, self(), :refresh_stats)
    end

    {:ok,
     socket
     |> assign(:page_title, "File Integrity Monitoring")
     |> assign(:stats, load_stats())
     |> assign(:recent_changes, load_recent_changes())
     |> assign(:compliance_summary, load_compliance_summary())
     |> assign(:violations_24h, load_violations_24h())
     |> assign(:selected_tab, "overview")}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    tab = params["tab"] || "overview"
    {:noreply, assign(socket, :selected_tab, tab)}
  end

  @impl true
  def handle_info({:new_fim_change, change}, socket) do
    recent_changes = [change | Enum.take(socket.assigns.recent_changes, 19)]
    violations_24h = if change.severity in ["high", "critical"] and not change.whitelisted do
      socket.assigns.violations_24h + 1
    else
      socket.assigns.violations_24h
    end

    {:noreply,
     socket
     |> assign(:recent_changes, recent_changes)
     |> assign(:violations_24h, violations_24h)}
  end

  @impl true
  def handle_info(:refresh_stats, socket) do
    {:noreply, assign(socket, :stats, load_stats())}
  end

  @impl true
  def handle_info(_msg, socket), do: {:noreply, socket}

  @impl true
  def render(assigns) do
    ~H"""
    <div class="fim-dashboard p-6">
      <div class="flex justify-between items-center mb-6">
        <h1 class="text-2xl font-bold text-gray-900 dark:text-white">File Integrity Monitoring</h1>
        <div class="flex space-x-2">
          <.link
            patch={~p"/fim?tab=overview"}
            class={"px-3 py-2 rounded-md text-sm font-medium " <> tab_class(@selected_tab, "overview")}
          >
            Overview
          </.link>
          <.link
            patch={~p"/fim?tab=baseline"}
            class={"px-3 py-2 rounded-md text-sm font-medium " <> tab_class(@selected_tab, "baseline")}
          >
            Baseline
          </.link>
          <.link
            patch={~p"/fim?tab=changes"}
            class={"px-3 py-2 rounded-md text-sm font-medium " <> tab_class(@selected_tab, "changes")}
          >
            Changes
          </.link>
          <.link
            patch={~p"/fim?tab=compliance"}
            class={"px-3 py-2 rounded-md text-sm font-medium " <> tab_class(@selected_tab, "compliance")}
          >
            Compliance
          </.link>
        </div>
      </div>

      <!-- Stats Cards -->
      <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <.stat_card title="Monitored Files" value={@stats.total_files} icon="document" />
        <.stat_card title="Changes (24h)" value={@stats.changes_24h} icon="arrow-path" />
        <.stat_card
          title="Violations (24h)"
          value={@violations_24h}
          icon="exclamation-triangle"
          severity={if @violations_24h > 0, do: "high", else: "info"}
        />
        <.stat_card
          title="Compliance Score"
          value={"#{@compliance_summary.score}%"}
          icon="shield-check"
          severity={compliance_severity(@compliance_summary.score)}
        />
      </div>

      <!-- Tab Content -->
      <%= case @selected_tab do %>
        <% "overview" -> %>
          <.overview_tab changes={@recent_changes} stats={@stats} />
        <% "baseline" -> %>
          <.baseline_tab stats={@stats} />
        <% "changes" -> %>
          <.changes_tab changes={@recent_changes} />
        <% "compliance" -> %>
          <.compliance_tab summary={@compliance_summary} />
        <% _ -> %>
          <.overview_tab changes={@recent_changes} stats={@stats} />
      <% end %>
    </div>
    """
  end

  # Component: Stat Card
  defp stat_card(assigns) do
    severity_class = case assigns[:severity] do
      "critical" -> "border-red-500 bg-red-50 dark:bg-red-900/20"
      "high" -> "border-orange-500 bg-orange-50 dark:bg-orange-900/20"
      "medium" -> "border-yellow-500 bg-yellow-50 dark:bg-yellow-900/20"
      _ -> "border-gray-200 dark:border-gray-700"
    end

    assigns = assign(assigns, :severity_class, severity_class)

    ~H"""
    <div class={"bg-white dark:bg-gray-800 rounded-lg border-l-4 p-4 shadow-sm #{@severity_class}"}>
      <div class="text-sm text-gray-500 dark:text-gray-400"><%= @title %></div>
      <div class="text-2xl font-bold text-gray-900 dark:text-white mt-1"><%= @value %></div>
    </div>
    """
  end

  # Component: Overview Tab
  defp overview_tab(assigns) do
    ~H"""
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-4">
        <h2 class="text-lg font-semibold mb-4 text-gray-900 dark:text-white">Recent Changes</h2>
        <.changes_table changes={Enum.take(@changes, 10)} compact={true} />
      </div>

      <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-4">
        <h2 class="text-lg font-semibold mb-4 text-gray-900 dark:text-white">Category Breakdown</h2>
        <div class="space-y-2">
          <%= for {category, count} <- @stats.by_category do %>
            <div class="flex justify-between items-center">
              <span class="text-gray-600 dark:text-gray-300"><%= humanize(category) %></span>
              <span class="font-medium text-gray-900 dark:text-white"><%= count %></span>
            </div>
          <% end %>
          <%= if @stats.by_category == %{} do %>
            <div class="text-gray-500 dark:text-gray-400">No baseline data yet</div>
          <% end %>
        </div>
      </div>
    </div>
    """
  end

  # Component: Baseline Tab
  defp baseline_tab(assigns) do
    ~H"""
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-4">
      <h2 class="text-lg font-semibold mb-4 text-gray-900 dark:text-white">Baseline Summary</h2>
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div>
          <div class="text-sm text-gray-500 dark:text-gray-400">Total Files</div>
          <div class="text-xl font-bold text-gray-900 dark:text-white"><%= @stats.total_files %></div>
        </div>
        <div>
          <div class="text-sm text-gray-500 dark:text-gray-400">Total Size</div>
          <div class="text-xl font-bold text-gray-900 dark:text-white"><%= format_bytes(@stats.total_size) %></div>
        </div>
        <div>
          <div class="text-sm text-gray-500 dark:text-gray-400">Last Scan</div>
          <div class="text-xl font-bold text-gray-900 dark:text-white"><%= relative_time(@stats.last_scan) %></div>
        </div>
        <div>
          <div class="text-sm text-gray-500 dark:text-gray-400">Agents</div>
          <div class="text-xl font-bold text-gray-900 dark:text-white"><%= @stats.agent_count %></div>
        </div>
      </div>
    </div>
    """
  end

  # Component: Changes Tab
  defp changes_tab(assigns) do
    ~H"""
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-4">
      <h2 class="text-lg font-semibold mb-4 text-gray-900 dark:text-white">Change History</h2>
      <.changes_table changes={@changes} compact={false} />
    </div>
    """
  end

  # Component: Changes Table
  defp changes_table(assigns) do
    ~H"""
    <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
      <thead>
        <tr>
          <th class="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Time</th>
          <th class="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Path</th>
          <th class="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Change</th>
          <th class="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Severity</th>
          <%= unless @compact do %>
            <th class="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Agent</th>
          <% end %>
        </tr>
      </thead>
      <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
        <%= for change <- @changes do %>
          <tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
            <td class="px-3 py-2 text-sm text-gray-500 dark:text-gray-400"><%= relative_time(change.detected_at) %></td>
            <td class="px-3 py-2 text-sm font-mono truncate max-w-xs text-gray-900 dark:text-white" title={change.path}><%= change.path %></td>
            <td class="px-3 py-2 text-sm text-gray-600 dark:text-gray-300"><%= humanize(change.change_type) %></td>
            <td class="px-3 py-2"><.severity_badge severity={change.severity} /></td>
            <%= unless @compact do %>
              <td class="px-3 py-2 text-sm text-gray-500 dark:text-gray-400"><%= change.agent_id %></td>
            <% end %>
          </tr>
        <% end %>
        <%= if @changes == [] do %>
          <tr>
            <td colspan={if @compact, do: 4, else: 5} class="px-3 py-4 text-center text-gray-500 dark:text-gray-400">
              No changes recorded
            </td>
          </tr>
        <% end %>
      </tbody>
    </table>
    """
  end

  # Component: Compliance Tab
  defp compliance_tab(assigns) do
    ~H"""
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-4">
      <h2 class="text-lg font-semibold mb-4 text-gray-900 dark:text-white">Compliance Status</h2>
      <div class="space-y-4">
        <%= for {framework, data} <- @summary.frameworks do %>
          <div class="border dark:border-gray-700 rounded-lg p-4">
            <div class="flex justify-between items-center mb-2">
              <span class="font-medium text-gray-900 dark:text-white"><%= framework %></span>
              <span class={"px-2 py-1 rounded text-sm #{compliance_badge_class(data.score)}"}><%= data.score %>%</span>
            </div>
            <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
              <div class="bg-blue-600 h-2 rounded-full" style={"width: #{data.score}%"}></div>
            </div>
            <div class="text-sm text-gray-500 dark:text-gray-400 mt-1"><%= data.covered %>/<%= data.total %> controls covered</div>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  # Component: Severity Badge
  defp severity_badge(assigns) do
    class = case assigns.severity do
      "critical" -> "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
      "high" -> "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200"
      "medium" -> "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
      "low" -> "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
      _ -> "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"
    end
    assigns = assign(assigns, :class, class)

    ~H"""
    <span class={"px-2 py-0.5 rounded-full text-xs font-medium #{@class}"}><%= @severity %></span>
    """
  end

  # Helpers
  defp load_stats do
    %{
      total_files: safe_call(fn -> BaselineManager.count_baselines() end, 0),
      total_size: safe_call(fn -> BaselineManager.total_baseline_size() end, 0),
      changes_24h: safe_call(fn -> BaselineManager.count_changes_since(hours_ago(24)) end, 0),
      by_category: safe_call(fn -> BaselineManager.baselines_by_category() end, %{}),
      last_scan: safe_call(fn -> BaselineManager.last_scan_time() end, nil),
      agent_count: safe_call(fn -> BaselineManager.agent_count() end, 0)
    }
  end

  defp load_recent_changes do
    safe_call(fn -> BaselineManager.get_global_recent_changes(limit: 20) end, [])
  end

  defp load_compliance_summary do
    %{
      score: 85,
      frameworks: %{
        "PCI-DSS" => %{score: 90, covered: 18, total: 20},
        "HIPAA" => %{score: 85, covered: 17, total: 20},
        "CIS" => %{score: 80, covered: 16, total: 20}
      }
    }
  end

  defp load_violations_24h do
    safe_call(fn -> BaselineManager.count_violations_since(hours_ago(24)) end, 0)
  end

  defp safe_call(fun, default) do
    fun.()
  rescue
    _ -> default
  catch
    :exit, _ -> default
  end

  defp hours_ago(hours), do: DateTime.add(DateTime.utc_now(), -hours * 3600, :second)

  defp tab_class(selected_tab, tab) do
    if selected_tab == tab do
      "bg-blue-600 text-white"
    else
      "bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300"
    end
  end

  defp humanize(atom) when is_atom(atom), do: atom |> Atom.to_string() |> humanize()
  defp humanize(string) when is_binary(string) do
    string
    |> String.replace("_", " ")
    |> String.split(" ")
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  defp format_bytes(nil), do: "0 B"
  defp format_bytes(bytes) when bytes < 1024, do: "#{bytes} B"
  defp format_bytes(bytes) when bytes < 1024 * 1024, do: "#{Float.round(bytes / 1024, 1)} KB"
  defp format_bytes(bytes) when bytes < 1024 * 1024 * 1024, do: "#{Float.round(bytes / 1024 / 1024, 1)} MB"
  defp format_bytes(bytes), do: "#{Float.round(bytes / 1024 / 1024 / 1024, 1)} GB"

  defp relative_time(nil), do: "Never"
  defp relative_time(datetime) do
    diff = DateTime.diff(DateTime.utc_now(), datetime, :second)
    cond do
      diff < 60 -> "#{diff}s ago"
      diff < 3600 -> "#{div(diff, 60)}m ago"
      diff < 86400 -> "#{div(diff, 3600)}h ago"
      true -> "#{div(diff, 86400)}d ago"
    end
  end

  defp compliance_severity(score) when score >= 90, do: "info"
  defp compliance_severity(score) when score >= 70, do: "medium"
  defp compliance_severity(score) when score >= 50, do: "high"
  defp compliance_severity(_), do: "critical"

  defp compliance_badge_class(score) when score >= 90, do: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
  defp compliance_badge_class(score) when score >= 70, do: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
  defp compliance_badge_class(_), do: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
end
