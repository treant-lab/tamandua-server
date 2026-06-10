# Configuration Drift Detection - Route Configuration

## LiveView Routes

Add these routes to your Phoenix router to enable the drift detection UI.

### Basic Routes

```elixir
# In your router.ex
scope "/", TamanduaServerWeb do
  pipe_through [:browser, :require_authenticated_user]

  # Drift Detection Routes
  live "/agents/drift", DriftDashboardLive, :index
  live "/agents/drift/:agent_id", DriftDetailLive, :show
end
```

### With Role-Based Access Control

```elixir
scope "/", TamanduaServerWeb do
  pipe_through [:browser, :require_authenticated_user]

  # Drift Dashboard (all authenticated users)
  live "/agents/drift", DriftDashboardLive, :index

  # Drift Details with remediation (requires security analyst role)
  live "/agents/drift/:agent_id", DriftDetailLive, :show,
    metadata: %{required_role: "security_analyst"}
end

# Admin-only routes for baseline management
scope "/admin", TamanduaServerWeb do
  pipe_through [:browser, :require_authenticated_user, :require_admin]

  live "/baselines", BaselineManagementLive, :index
  live "/baselines/:baseline_id", BaselineEditorLive, :edit
end
```

### API Routes (Optional)

For programmatic access to drift detection:

```elixir
scope "/api/v1", TamanduaServerWeb.API.V1 do
  pipe_through [:api, :require_api_token]

  # Drift Detection Endpoints
  get "/agents/:agent_id/drifts", DriftController, :list_drifts
  get "/agents/:agent_id/compliance", DriftController, :compliance_status
  post "/agents/:agent_id/scan", DriftController, :trigger_scan
  post "/drifts/:drift_id/remediate", DriftController, :remediate

  # Baseline Management
  get "/agents/:agent_id/baselines", BaselineController, :list
  get "/baselines/:baseline_id", BaselineController, :show
  post "/agents/:agent_id/baselines", BaselineController, :create
  put "/baselines/:baseline_id/activate", BaselineController, :activate
end
```

## Navigation Integration

Add drift detection to your main navigation:

```heex
<!-- In your navigation template -->
<nav class="main-nav">
  <.link navigate={~p"/dashboard"}>Dashboard</.link>
  <.link navigate={~p"/agents"}>Agents</.link>
  <.link navigate={~p"/alerts"}>Alerts</.link>

  <!-- Drift Detection -->
  <.link navigate={~p"/agents/drift"} class="nav-item">
    <.icon name="shield-check" />
    Configuration Drift
    <%= if @drift_count > 0 do %>
      <span class="badge badge-warning"><%= @drift_count %></span>
    <% end %>
  </.link>

  <.link navigate={~p"/reports"}>Reports</.link>
</nav>
```

## Breadcrumb Integration

```heex
<!-- In drift_dashboard_live.ex -->
<div class="breadcrumbs">
  <.link navigate={~p"/"}>Home</.link>
  <span>/</span>
  <.link navigate={~p"/agents"}>Agents</.link>
  <span>/</span>
  <span class="current">Configuration Drift</span>
</div>

<!-- In drift_detail_live.ex -->
<div class="breadcrumbs">
  <.link navigate={~p"/"}>Home</.link>
  <span>/</span>
  <.link navigate={~p"/agents"}>Agents</.link>
  <span>/</span>
  <.link navigate={~p"/agents/drift"}>Configuration Drift</.link>
  <span>/</span>
  <span class="current"><%= @agent.hostname %></span>
</div>
```

## Menu Integration with Badge

Show drift count in the main menu:

```elixir
# In your layout LiveView or component
def mount(_params, session, socket) do
  if connected?(socket) do
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "agents:drift")
  end

  org_id = session["organization_id"]
  drift_count = get_unresolved_drift_count(org_id)

  {:ok, assign(socket, drift_count: drift_count)}
end

def handle_info({:drift_detected, _}, socket) do
  org_id = socket.assigns.organization_id
  drift_count = get_unresolved_drift_count(org_id)
  {:noreply, assign(socket, drift_count: drift_count)}
end

defp get_unresolved_drift_count(org_id) do
  import Ecto.Query

  TamanduaServer.Repo.one(
    from d in TamanduaServer.Agents.ConfigurationDrift,
      where: d.organization_id == ^org_id,
      where: d.status == "detected",
      where: d.severity in ["critical", "high"],
      select: count(d.id)
  )
end
```

## Dashboard Widget Integration

Add a drift summary widget to your main dashboard:

```heex
<!-- In dashboard_live.ex -->
<div class="dashboard-grid">
  <!-- Existing widgets -->
  <div class="widget-agents">...</div>
  <div class="widget-alerts">...</div>

  <!-- Drift Summary Widget -->
  <div class="widget widget-drift-summary">
    <div class="widget-header">
      <h3>Configuration Compliance</h3>
      <.link navigate={~p"/agents/drift"} class="widget-link">
        View All →
      </.link>
    </div>

    <div class="widget-content">
      <div class="compliance-score">
        <div class="score-circle" style={"background: conic-gradient(#22c55e 0% #{@compliance_summary.avg_compliance_score}%, #e5e7eb #{@compliance_summary.avg_compliance_score}% 100%)"}>
          <span class="score-value">
            <%= Float.round(@compliance_summary.avg_compliance_score || 100.0, 1) %>%
          </span>
        </div>
        <div class="score-label">Compliance Score</div>
      </div>

      <div class="drift-stats">
        <div class="stat">
          <span class="stat-label">Compliant</span>
          <span class="stat-value text-green">
            <%= @compliance_summary.compliant || 0 %>
          </span>
        </div>
        <div class="stat">
          <span class="stat-label">Non-Compliant</span>
          <span class="stat-value text-red">
            <%= @compliance_summary.non_compliant || 0 %>
          </span>
        </div>
      </div>

      <%= if @compliance_summary.total_critical_drifts > 0 do %>
        <div class="alert alert-critical">
          <.icon name="alert-triangle" />
          <%= @compliance_summary.total_critical_drifts %> critical drifts detected
        </div>
      <% end %>
    </div>
  </div>
</div>
```

## Agent Detail Page Integration

Add drift status to the agent detail page:

```heex
<!-- In agent detail view -->
<div class="agent-details">
  <div class="agent-header">
    <h1><%= @agent.hostname %></h1>
    <div class="agent-status">
      <span class={"status-badge status-#{@agent.status}"}>
        <%= @agent.status %>
      </span>

      <!-- Drift Status Badge -->
      <%= if @compliance_status && !@compliance_status.is_compliant do %>
        <.link
          navigate={~p"/agents/drift/#{@agent.id}"}
          class="drift-badge drift-warning"
          title="Configuration drift detected"
        >
          <.icon name="alert-triangle" />
          <%= @compliance_status.drift_count %> Drifts
        </.link>
      <% end %>
    </div>
  </div>

  <!-- Rest of agent details -->
</div>
```

## Alert Integration

Link drift alerts to the drift detail page:

```elixir
# In alert creation
TamanduaServer.Alerts.create_alert(%{
  organization_id: org_id,
  agent_id: agent_id,
  type: "configuration_drift",
  severity: "critical",
  title: "Critical configuration drift detected",
  description: "Agent #{hostname} has critical configuration drift",
  metadata: %{
    drift_count: 3,
    critical_drifts: 1,
    # Link to drift detail page
    action_url: "/agents/drift/#{agent_id}"
  }
})
```

## Search Integration

Add drift results to global search:

```elixir
def search(query, organization_id) do
  # ... existing search logic

  # Search in drift records
  drift_results = from(d in ConfigurationDrift,
    join: a in assoc(d, :agent),
    where: d.organization_id == ^organization_id,
    where: ilike(a.hostname, ^"%#{query}%") or
           ilike(d.drift_type, ^"%#{query}%") or
           ilike(d.field_path, ^"%#{query}%"),
    select: %{
      type: "drift",
      title: a.hostname,
      description: d.drift_type,
      url: "/agents/drift/" <> a.id,
      severity: d.severity
    },
    limit: 5
  )
  |> Repo.all()

  # Combine with other results
  agents ++ alerts ++ drift_results
end
```

## Permission Guards

```elixir
# In live views
defmodule TamanduaServerWeb.DriftDashboardLive do
  use TamanduaServerWeb, :live_view

  on_mount {TamanduaServerWeb.UserAuth, :ensure_authenticated}

  def mount(_params, session, socket) do
    user = socket.assigns.current_user

    if authorized?(user, :view_drift) do
      # ... load data
      {:ok, socket}
    else
      {:ok, redirect(socket, to: "/unauthorized")}
    end
  end

  defp authorized?(user, :view_drift) do
    user.role in ["admin", "security_analyst", "operator"]
  end

  defp authorized?(user, :remediate_drift) do
    user.role in ["admin", "security_analyst"]
  end
end
```

## WebSocket Authentication

Ensure agents can report configuration:

```elixir
# In agent_channel.ex
def handle_in("config_report", payload, socket) do
  agent_id = socket.assigns.agent_id

  # Store current config
  update_agent_config(agent_id, payload["config"])

  # Optionally trigger drift scan
  if payload["trigger_scan"] do
    Task.start(fn ->
      TamanduaServer.Agents.DriftDetector.scan_agent(agent_id,
        scan_type: "agent_report"
      )
    end)
  end

  {:reply, :ok, socket}
end
```

## Complete Route Example

```elixir
defmodule TamanduaServerWeb.Router do
  use TamanduaServerWeb, :router

  # ... existing pipelines

  scope "/", TamanduaServerWeb do
    pipe_through [:browser, :require_authenticated_user]

    # Main dashboard
    live "/", DashboardLive, :index

    # Agents
    live "/agents", AgentsLive, :index
    live "/agents/:id", AgentDetailLive, :show

    # Configuration Drift Detection
    live "/agents/drift", DriftDashboardLive, :index
    live "/agents/drift/:agent_id", DriftDetailLive, :show

    # Alerts
    live "/alerts", AlertsLive, :index
    live "/alerts/:id", AlertDetailLive, :show
  end

  # Admin routes
  scope "/admin", TamanduaServerWeb.Admin do
    pipe_through [:browser, :require_authenticated_user, :require_admin]

    # Baseline management
    live "/baselines", BaselineListLive, :index
    live "/baselines/new", BaselineNewLive, :new
    live "/baselines/:id", BaselineShowLive, :show
    live "/baselines/:id/edit", BaselineEditLive, :edit

    # Drift policies
    live "/drift-policies", DriftPolicyLive, :index
  end

  # API routes
  scope "/api/v1", TamanduaServerWeb.API.V1 do
    pipe_through [:api, :require_api_token]

    resources "/drifts", DriftController, only: [:index, :show]
    post "/agents/:agent_id/scan", DriftController, :scan
    post "/drifts/:id/remediate", DriftController, :remediate

    resources "/baselines", BaselineController, except: [:new, :edit]
    put "/baselines/:id/activate", BaselineController, :activate
  end
end
```

This provides complete routing integration for the drift detection system!
