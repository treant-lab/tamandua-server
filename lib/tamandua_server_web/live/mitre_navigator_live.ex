defmodule TamanduaServerWeb.MitreNavigatorLive do
  @moduledoc """
  LiveView for MITRE ATT&CK Navigator integration.

  Features:
  - Interactive coverage heatmap
  - Alert frequency visualization
  - Gap analysis
  - Technique drill-down with alert history
  - Navigator JSON export
  - Saved layer management
  - Threat actor mapping
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Mitre.{Navigator, AttackFramework, TechniqueMapper}
  alias TamanduaServer.Detection.Mitre
  alias TamanduaServer.Alerts

  @tactics [
    {"TA0043", "Reconnaissance"},
    {"TA0042", "Resource Development"},
    {"TA0001", "Initial Access"},
    {"TA0002", "Execution"},
    {"TA0003", "Persistence"},
    {"TA0004", "Privilege Escalation"},
    {"TA0005", "Defense Evasion"},
    {"TA0006", "Credential Access"},
    {"TA0007", "Discovery"},
    {"TA0008", "Lateral Movement"},
    {"TA0009", "Collection"},
    {"TA0011", "Command and Control"},
    {"TA0010", "Exfiltration"},
    {"TA0040", "Impact"}
  ]

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      # Load initial data
      coverage_data = load_coverage_data(socket.assigns.current_user)
      tactic_summary = build_tactic_summary(coverage_data)

      {:ok,
       assign(socket,
         page_title: "MITRE ATT&CK Navigator",
         view: "heatmap",
         selected_tactic: nil,
         selected_technique: nil,
         time_range: 30,
         coverage_data: coverage_data,
         tactic_summary: tactic_summary,
         layer_type: "coverage",
         saved_layers: [],
         search_query: "",
         show_gaps_only: false,
         threat_actors: []
       )}
    else
      {:ok,
       assign(socket,
         page_title: "MITRE ATT&CK Navigator",
         view: "heatmap",
         selected_tactic: nil,
         selected_technique: nil,
         time_range: 30,
         coverage_data: %{},
         tactic_summary: [],
         layer_type: "coverage",
         saved_layers: [],
         search_query: "",
         show_gaps_only: false,
         threat_actors: []
       )}
    end
  end

  @impl true
  def handle_params(params, _uri, socket) do
    view = Map.get(params, "view", "heatmap")
    technique_id = Map.get(params, "technique")

    socket =
      socket
      |> assign(:view, view)
      |> maybe_load_technique(technique_id)

    {:noreply, socket}
  end

  @impl true
  def handle_event("change_view", %{"view" => view}, socket) do
    {:noreply, push_patch(socket, to: ~p"/mitre?view=#{view}")}
  end

  @impl true
  def handle_event("change_layer_type", %{"layer_type" => layer_type}, socket) do
    coverage_data = case layer_type do
      "coverage" -> load_coverage_data(socket.assigns.current_user)
      "frequency" -> load_frequency_data(socket.assigns.current_user, socket.assigns.time_range)
      "gaps" -> load_gap_data(socket.assigns.current_user)
      _ -> socket.assigns.coverage_data
    end

    {:noreply, assign(socket, layer_type: layer_type, coverage_data: coverage_data)}
  end

  @impl true
  def handle_event("change_time_range", %{"days" => days}, socket) do
    time_range = String.to_integer(days)

    coverage_data = if socket.assigns.layer_type == "frequency" do
      load_frequency_data(socket.assigns.current_user, time_range)
    else
      socket.assigns.coverage_data
    end

    {:noreply, assign(socket, time_range: time_range, coverage_data: coverage_data)}
  end

  @impl true
  def handle_event("select_tactic", %{"tactic_id" => tactic_id}, socket) do
    techniques = get_techniques_for_tactic(tactic_id, socket.assigns.coverage_data)

    {:noreply,
     assign(socket,
       selected_tactic: tactic_id,
       selected_technique: nil,
       tactic_techniques: techniques
     )}
  end

  @impl true
  def handle_event("select_technique", %{"technique_id" => technique_id}, socket) do
    {:noreply, push_patch(socket, to: ~p"/mitre?technique=#{technique_id}")}
  end

  @impl true
  def handle_event("export_layer", %{"format" => format}, socket) do
    layer_data = case socket.assigns.layer_type do
      "coverage" ->
        Navigator.generate_coverage_layer(
          organization_id: get_org_id(socket.assigns.current_user)
        )
      "frequency" ->
        Navigator.generate_frequency_layer(
          organization_id: get_org_id(socket.assigns.current_user),
          time_range: socket.assigns.time_range
        )
      "gaps" ->
        Navigator.generate_gap_layer(
          organization_id: get_org_id(socket.assigns.current_user)
        )
    end

    case format do
      "json" ->
        json_data = Navigator.export_layer_json(layer_data)
        filename = "tamandua-#{socket.assigns.layer_type}-#{Date.utc_today()}.json"

        {:noreply,
         socket
         |> push_event("download", %{
           data: json_data,
           filename: filename,
           mime_type: "application/json"
         })}

      "save" ->
        case Navigator.save_layer(
          layer_data,
          "#{layer_data.name} - #{DateTime.utc_now()}",
          layer_type: socket.assigns.layer_type,
          organization_id: get_org_id(socket.assigns.current_user),
          created_by_id: socket.assigns.current_user.id
        ) do
          {:ok, _layer} ->
            {:noreply,
             socket
             |> put_flash(:info, "Layer saved successfully")
             |> reload_saved_layers()}

          {:error, _changeset} ->
            {:noreply, put_flash(socket, :error, "Failed to save layer")}
        end
    end
  end

  @impl true
  def handle_event("search_techniques", %{"query" => query}, socket) do
    results = if String.length(query) >= 2 do
      AttackFramework.search_techniques(query)
    else
      []
    end

    {:noreply, assign(socket, search_query: query, search_results: results)}
  end

  @impl true
  def handle_event("toggle_gaps_only", _params, socket) do
    {:noreply, update(socket, :show_gaps_only, &(!&1))}
  end

  @impl true
  def handle_event("sync_mappings", _params, socket) do
    org_id = get_org_id(socket.assigns.current_user)

    case TechniqueMapper.sync_all_mappings(org_id) do
      {:ok, counts} ->
        coverage_data = load_coverage_data(socket.assigns.current_user)

        {:noreply,
         socket
         |> put_flash(:info, "Synced #{counts.sigma + counts.yara} rule mappings")
         |> assign(coverage_data: coverage_data)}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to sync mappings")}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="mitre-navigator">
      <div class="flex justify-between items-center mb-6">
        <h1 class="text-3xl font-bold">MITRE ATT&CK Navigator</h1>

        <div class="flex gap-4">
          <button phx-click="sync_mappings" class="btn-secondary">
            Sync Mappings
          </button>

          <button phx-click="export_layer" phx-value-format="json" class="btn-secondary">
            Export JSON
          </button>

          <button phx-click="export_layer" phx-value-format="save" class="btn-primary">
            Save Layer
          </button>
        </div>
      </div>

      <!-- View Tabs -->
      <div class="tabs mb-6">
        <button
          class={["tab", @view == "heatmap" && "tab-active"]}
          phx-click="change_view"
          phx-value-view="heatmap"
        >
          Heatmap
        </button>
        <button
          class={["tab", @view == "timeline" && "tab-active"]}
          phx-click="change_view"
          phx-value-view="timeline"
        >
          Timeline
        </button>
        <button
          class={["tab", @view == "actors" && "tab-active"]}
          phx-click="change_view"
          phx-value-view="actors"
        >
          Threat Actors
        </button>
        <button
          class={["tab", @view == "gaps" && "tab-active"]}
          phx-click="change_view"
          phx-value-view="gaps"
        >
          Gap Analysis
        </button>
      </div>

      <!-- Layer Type Selector -->
      <div class="flex gap-4 mb-6">
        <div class="form-group">
          <label>Layer Type</label>
          <select phx-change="change_layer_type" name="layer_type" class="select">
            <option value="coverage" selected={@layer_type == "coverage"}>Detection Coverage</option>
            <option value="frequency" selected={@layer_type == "frequency"}>Alert Frequency</option>
            <option value="gaps" selected={@layer_type == "gaps"}>Coverage Gaps</option>
          </select>
        </div>

        <div :if={@layer_type == "frequency"} class="form-group">
          <label>Time Range</label>
          <select phx-change="change_time_range" name="days" class="select">
            <option value="7" selected={@time_range == 7}>Last 7 days</option>
            <option value="30" selected={@time_range == 30}>Last 30 days</option>
            <option value="90" selected={@time_range == 90}>Last 90 days</option>
            <option value="365" selected={@time_range == 365}>Last year</option>
          </select>
        </div>

        <div class="form-group">
          <label>Search Techniques</label>
          <input
            type="text"
            phx-change="search_techniques"
            phx-debounce="300"
            name="query"
            value={@search_query}
            placeholder="Search by name or ID..."
            class="input"
          />
        </div>
      </div>

      <!-- Main Content -->
      <div class="grid grid-cols-12 gap-6">
        <!-- Left Sidebar: Tactic Summary -->
        <div class="col-span-3">
          <div class="card">
            <h3 class="font-semibold mb-4">Tactics</h3>
            <div class="space-y-2">
              <%= for {tactic_id, tactic_name} <- @tactics do %>
                <div
                  class={[
                    "tactic-item p-3 rounded cursor-pointer hover:bg-gray-100",
                    @selected_tactic == tactic_id && "bg-blue-50 border-l-4 border-blue-500"
                  ]}
                  phx-click="select_tactic"
                  phx-value-tactic_id={tactic_id}
                >
                  <div class="flex justify-between items-center">
                    <span class="font-medium text-sm"><%= tactic_name %></span>
                    <%= if stats = get_tactic_stats(@tactic_summary, tactic_id) do %>
                      <span class="text-xs text-gray-500">
                        <%= stats.covered %>/<%= stats.total %>
                      </span>
                      <div class="w-16 bg-gray-200 rounded-full h-2">
                        <div
                          class="bg-blue-500 h-2 rounded-full"
                          style={"width: #{stats.coverage_pct}%"}
                        >
                        </div>
                      </div>
                    <% end %>
                  </div>
                </div>
              <% end %>
            </div>
          </div>
        </div>

        <!-- Center: Heatmap/Visualization -->
        <div class="col-span-6">
          <%= if @view == "heatmap" do %>
            <.render_heatmap
              coverage_data={@coverage_data}
              selected_tactic={@selected_tactic}
              layer_type={@layer_type}
            />
          <% end %>

          <%= if @view == "timeline" do %>
            <.render_timeline time_range={@time_range} />
          <% end %>

          <%= if @view == "actors" do %>
            <.render_threat_actors actors={@threat_actors} />
          <% end %>

          <%= if @view == "gaps" do %>
            <.render_gap_analysis coverage_data={@coverage_data} />
          <% end %>
        </div>

        <!-- Right Sidebar: Technique Details -->
        <div class="col-span-3">
          <%= if @selected_technique do %>
            <.render_technique_details technique={@selected_technique} />
          <% else %>
            <div class="card">
              <p class="text-gray-500 text-sm">Select a technique to view details</p>
            </div>
          <% end %>
        </div>
      </div>
    </div>
    """
  end

  # Component: Heatmap
  defp render_heatmap(assigns) do
    ~H"""
    <div class="card">
      <h3 class="font-semibold mb-4">Coverage Heatmap</h3>

      <div class="heatmap-grid">
        <%= for {tactic_id, tactic_name} <- @tactics do %>
          <div class="tactic-column">
            <div class="tactic-header bg-gray-100 p-2 font-semibold text-sm">
              <%= tactic_name %>
            </div>

            <div class="techniques space-y-1">
              <%= for technique <- get_techniques_for_tactic(tactic_id, @coverage_data) do %>
                <div
                  class={[
                    "technique-cell p-2 rounded cursor-pointer border",
                    coverage_class(technique, @layer_type)
                  ]}
                  phx-click="select_technique"
                  phx-value-technique_id={technique.id}
                  title={technique.name}
                >
                  <div class="text-xs font-mono"><%= technique.id %></div>
                  <%= if @layer_type == "coverage" do %>
                    <div class="text-xs"><%= technique.rule_count %> rules</div>
                  <% end %>
                  <%= if @layer_type == "frequency" do %>
                    <div class="text-xs"><%= technique.alert_count %> alerts</div>
                  <% end %>
                </div>
              <% end %>
            </div>
          </div>
        <% end %>
      </div>

      <!-- Legend -->
      <div class="mt-4 flex gap-4 text-xs">
        <%= if @layer_type == "coverage" do %>
          <div class="flex items-center gap-2">
            <div class="w-4 h-4 bg-gray-100 border"></div>
            <span>No coverage</span>
          </div>
          <div class="flex items-center gap-2">
            <div class="w-4 h-4 bg-blue-100 border"></div>
            <span>1 rule</span>
          </div>
          <div class="flex items-center gap-2">
            <div class="w-4 h-4 bg-blue-300 border"></div>
            <span>2-3 rules</span>
          </div>
          <div class="flex items-center gap-2">
            <div class="w-4 h-4 bg-blue-500 border"></div>
            <span>4+ rules</span>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  # Component: Technique Details
  defp render_technique_details(assigns) do
    ~H"""
    <div class="card">
      <h3 class="font-semibold mb-2"><%= @technique.name %></h3>
      <p class="text-xs text-gray-500 mb-4"><%= @technique.id %></p>

      <div class="mb-4">
        <h4 class="text-sm font-semibold mb-2">Description</h4>
        <p class="text-sm text-gray-700"><%= @technique.description %></p>
      </div>

      <div class="mb-4">
        <h4 class="text-sm font-semibold mb-2">Detection Rules</h4>
        <div class="space-y-1">
          <%= for rule <- @technique.rules || [] do %>
            <div class="text-sm p-2 bg-gray-50 rounded">
              <div class="font-medium"><%= rule.name %></div>
              <div class="text-xs text-gray-500"><%= rule.type %></div>
            </div>
          <% end %>
        </div>
      </div>

      <div>
        <h4 class="text-sm font-semibold mb-2">Recent Alerts</h4>
        <%= if @technique.recent_alerts && length(@technique.recent_alerts) > 0 do %>
          <div class="space-y-1">
            <%= for alert <- @technique.recent_alerts do %>
              <div class="text-sm p-2 bg-gray-50 rounded">
                <div class="flex justify-between">
                  <span class="font-medium"><%= alert.title %></span>
                  <span class={"badge badge-#{alert.severity}"}><%= alert.severity %></span>
                </div>
                <div class="text-xs text-gray-500">
                  <%= Calendar.strftime(alert.inserted_at, "%Y-%m-%d %H:%M") %>
                </div>
              </div>
            <% end %>
          </div>
        <% else %>
          <p class="text-sm text-gray-500">No recent alerts</p>
        <% end %>
      </div>
    </div>
    """
  end

  # Helper Functions

  defp load_coverage_data(user) do
    org_id = get_org_id(user)
    Mitre.get_coverage(organization_id: org_id)
  end

  defp load_frequency_data(user, time_range) do
    org_id = get_org_id(user)
    Mitre.calculate_coverage(organization_id: org_id, days: time_range)
  end

  defp load_gap_data(user) do
    org_id = get_org_id(user)
    Navigator.generate_gap_layer(organization_id: org_id)
  end

  defp build_tactic_summary(coverage_data) do
    coverage_data[:by_tactic] || []
  end

  defp get_org_id(%{organization_id: org_id}), do: org_id
  defp get_org_id(_), do: nil

  defp get_techniques_for_tactic(tactic_id, coverage_data) do
    coverage_data
    |> Map.get(:techniques, %{})
    |> Enum.filter(fn {_id, tech} -> tactic_id in (tech[:tactics] || []) end)
    |> Enum.map(fn {_id, tech} -> tech end)
  end

  defp get_tactic_stats(summary, tactic_id) do
    Enum.find(summary, fn tactic -> tactic.tactic_id == tactic_id end)
  end

  defp coverage_class(technique, "coverage") do
    case technique.rule_count || 0 do
      0 -> "bg-gray-50 border-gray-200"
      1 -> "bg-blue-100 border-blue-200"
      2..3 -> "bg-blue-300 border-blue-400"
      _ -> "bg-blue-500 border-blue-600 text-white"
    end
  end

  defp coverage_class(technique, "frequency") do
    case technique.alert_count || 0 do
      0 -> "bg-gray-50 border-gray-200"
      1..5 -> "bg-yellow-100 border-yellow-200"
      6..20 -> "bg-orange-300 border-orange-400"
      _ -> "bg-red-500 border-red-600 text-white"
    end
  end

  defp coverage_class(_technique, "gaps") do
    "bg-red-100 border-red-300"
  end

  defp maybe_load_technique(socket, nil), do: socket

  defp maybe_load_technique(socket, technique_id) do
    case AttackFramework.get_technique(technique_id) do
      nil ->
        socket

      technique ->
        # Load additional data
        coverage = TechniqueMapper.get_technique_coverage(technique_id)
        recent_alerts = load_recent_alerts_for_technique(technique_id, socket.assigns.current_user)

        technique_data = Map.merge(technique, %{
          rules: coverage.rules,
          recent_alerts: recent_alerts
        })

        assign(socket, selected_technique: technique_data)
    end
  end

  defp load_recent_alerts_for_technique(technique_id, user) do
    org_id = get_org_id(user)

    Alerts.list_alerts(
      organization_id: org_id,
      mitre_technique: technique_id,
      limit: 10,
      order_by: [desc: :inserted_at]
    )
  end

  defp reload_saved_layers(socket) do
    org_id = get_org_id(socket.assigns.current_user)
    layers = Navigator.list_layers(org_id)
    assign(socket, saved_layers: layers)
  end

  # Placeholder components
  defp render_timeline(assigns), do: ~H"<div class='card'><p>Timeline view coming soon</p></div>"
  defp render_threat_actors(assigns), do: ~H"<div class='card'><p>Threat actors view coming soon</p></div>"
  defp render_gap_analysis(assigns), do: ~H"<div class='card'><p>Gap analysis view coming soon</p></div>"
end
