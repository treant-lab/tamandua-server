# Dashboard Custom Widgets System

A comprehensive, customizable dashboard system for Tamandua EDR that allows users to create, configure, and manage personalized security dashboards with drag-and-drop widgets.

## Features

### Core Functionality
- **Customizable Layouts**: Create multiple dashboard layouts with different widget configurations
- **Drag-and-Drop**: Rearrange widgets using an intuitive drag-and-drop interface (GridStack.js)
- **Widget Library**: 17+ pre-built widget types for various security metrics and visualizations
- **Real-time Updates**: Widgets automatically refresh via Phoenix PubSub
- **User Preferences**: Save and load custom layouts, set default dashboards
- **Dashboard Templates**: Pre-configured layouts for different user roles
- **Import/Export**: Share dashboard configurations via JSON

### Widget Types

#### Security Widgets
1. **Threat Level Gauge** - Critical/High/Medium/Low alert counts
2. **Top Detections** - Most frequent MITRE ATT&CK techniques
3. **Recent Alerts** - Latest security alerts with filtering
4. **Top Threats** - Malware families and attacker IPs
5. **MITRE ATT&CK Heatmap** - Technique coverage visualization

#### Agent & System Widgets
6. **Agent Status Overview** - Online/Offline/Error counts
7. **System Health** - CPU, memory, latency metrics
8. **Detection Performance** - Precision, recall, F1 score metrics

#### Timeline & Analytics
9. **Timeline** - Events over time with configurable grouping
10. **Alert Trend** - Severity-based alert trends
11. **Geo Map** - Agent locations and threat density

#### Response & Investigation
12. **Response Actions** - Recent response action status
13. **Process Tree** - Process hierarchy visualization
14. **Network Traffic** - Network activity metrics
15. **File Events** - File system changes
16. **Registry Events** - Windows registry modifications

#### Advanced
17. **Custom Query** - User-defined queries with custom visualizations

### Dashboard Templates

Pre-built dashboard layouts optimized for different roles:

- **SOC Analyst**: Real-time threat monitoring and alert triage
- **Executive**: High-level metrics and summary statistics
- **Incident Responder**: Alert investigation and response tracking
- **Threat Hunter**: Threat intelligence and detection analytics
- **Compliance**: Detection performance and system health metrics

## Architecture

### Database Schema

```
dashboard_layouts
├── id (UUID)
├── user_id (FK to users)
├── organization_id (FK to organizations)
├── name (string)
├── description (text)
├── is_default (boolean)
├── is_template (boolean)
├── template_type (string)
├── layout_config (jsonb)
├── shared_with_users (array of UUIDs)
└── timestamps

dashboard_widgets
├── id (UUID)
├── dashboard_layout_id (FK to dashboard_layouts)
├── widget_type (string)
├── title (string)
├── position_x (integer)
├── position_y (integer)
├── width (integer)
├── height (integer)
├── config (jsonb)
├── refresh_interval (integer)
├── is_visible (boolean)
├── order (integer)
└── timestamps

widget_data_cache
├── id (UUID)
├── widget_id (FK to dashboard_widgets)
├── cache_key (string)
├── data (jsonb)
├── expires_at (timestamp)
└── timestamps
```

### Module Structure

```
lib/tamandua_server/dashboards/
├── layout.ex              # Layout schema
├── widget.ex              # Widget schema
├── widget_data_cache.ex   # Cache schema
├── manager.ex             # Business logic
└── README.md              # This file

lib/tamandua_server_web/live/
└── custom_dashboard_live.ex  # LiveView UI

assets/js/hooks/
└── dashboard_grid.js      # Drag-and-drop grid
```

## Usage

### Creating a Dashboard

```elixir
# Get or create default dashboard
{:ok, layout} = TamanduaServer.Dashboards.get_or_create_default_layout(user_id)

# Create from template
{:ok, layout} = TamanduaServer.Dashboards.create_from_template(user_id, "soc_analyst")

# Create custom dashboard
{:ok, layout} = TamanduaServer.Dashboards.create_layout(%{
  user_id: user_id,
  name: "My Custom Dashboard",
  description: "Custom security dashboard",
  template_type: "custom"
})
```

### Adding Widgets

```elixir
# Add a widget
{:ok, widget} = TamanduaServer.Dashboards.create_widget(%{
  dashboard_layout_id: layout.id,
  widget_type: "threat_level_gauge",
  title: "Current Threat Level",
  position_x: 0,
  position_y: 0,
  width: 4,
  height: 3,
  config: %{
    "show_counts" => true,
    "show_percentage" => true
  }
})
```

### Fetching Widget Data

```elixir
# Fetch real-time data for a widget
{:ok, data} = TamanduaServer.Dashboards.fetch_widget_data(widget)

# Example response for threat_level_gauge:
# %{
#   critical: 5,
#   high: 12,
#   medium: 23,
#   low: 8,
#   total: 48
# }
```

### Exporting/Importing Layouts

```elixir
# Export layout to JSON
{:ok, json} = TamanduaServer.Dashboards.export_layout(layout)

# Import layout from JSON
{:ok, imported_layout} = TamanduaServer.Dashboards.import_layout(user_id, json)
```

### Setting Default Dashboard

```elixir
# Set a layout as the user's default
{:ok, _} = TamanduaServer.Dashboards.set_default_layout(layout.id, user_id)
```

## Widget Configuration

Each widget type supports specific configuration options:

### Threat Level Gauge
```elixir
config: %{
  "show_counts" => true,      # Show numeric counts
  "show_percentage" => true,  # Show percentages
  "animate" => true          # Animate changes
}
```

### Top Detections
```elixir
config: %{
  "limit" => 10,              # Number of items to show
  "group_by" => "technique",  # Group by technique, tactic, or rule
  "time_range" => "24h",      # Time range: 1h, 6h, 24h, 7d, 30d
  "show_mitre_id" => true     # Show MITRE ATT&CK IDs
}
```

### Recent Alerts
```elixir
config: %{
  "limit" => 20,                      # Number of alerts
  "severity_filter" => [],            # Filter by severity
  "status_filter" => [],              # Filter by status
  "show_pagination" => true,          # Enable pagination
  "auto_refresh" => true              # Auto-refresh data
}
```

### Timeline
```elixir
config: %{
  "time_range" => "24h",              # Time range
  "chart_type" => "line",             # line, area, bar
  "group_by" => "hour",               # minute, hour, day
  "show_legend" => true,              # Show legend
  "show_grid" => true                 # Show grid lines
}
```

### Geo Map
```elixir
config: %{
  "zoom" => 2,                        # Map zoom level (1-20)
  "center" => [0, 0],                 # Map center [lat, lng]
  "show_heatmap" => true,             # Show threat heatmap
  "show_agent_markers" => true,       # Show agent markers
  "cluster_markers" => true           # Cluster nearby markers
}
```

## Real-time Updates

Widgets automatically refresh when relevant events occur via Phoenix PubSub:

```elixir
# In your application, broadcast events:
Phoenix.PubSub.broadcast(
  TamanduaServer.PubSub,
  "alerts:new",
  {:alert_created, alert}
)

Phoenix.PubSub.broadcast(
  TamanduaServer.PubSub,
  "agents:status",
  {:agent_status_changed, agent}
)
```

The dashboard LiveView subscribes to these events and refreshes affected widgets:

```elixir
# Alert widgets refresh on new alerts
def handle_info({:alert_created, _alert}, socket) do
  alert_widget_types = ["threat_level_gauge", "recent_alerts", "top_detections", "timeline"]
  # Refresh widgets...
end

# Agent widgets refresh on status changes
def handle_info({:agent_status_changed, _agent}, socket) do
  # Refresh agent_status_overview widgets...
end
```

## Performance Optimization

### Widget Data Caching

Widget data is cached to improve dashboard load times and reduce database queries:

```elixir
# Data is automatically cached with configurable TTL
config: %{
  "refresh_interval" => 30000  # Cache for 30 seconds
}
```

### Lazy Loading

Widgets fetch their data asynchronously after the page loads:

```elixir
# In mount/3
widget_data = fetch_all_widget_data(layout.widgets)

# Asynchronously fetch data for new widgets
send(self(), {:fetch_widget_data, widget.id})
```

## Frontend Integration

### LiveView Hook

The `DashboardGrid` Phoenix LiveView hook integrates GridStack.js for drag-and-drop:

```javascript
// Automatically loads GridStack.js from CDN
// Initializes grid with 12-column layout
// Handles drag events and saves layout changes
// Toggles between edit/view modes
```

### CSS Grid Alternative

For environments without external dependencies, a lightweight CSS Grid implementation is available:

```javascript
// Uses native CSS Grid
// Plain JavaScript drag-and-drop
// No external dependencies
```

## API Routes

Add to your router:

```elixir
scope "/dashboard", TamanduaServerWeb do
  pipe_through [:browser, :require_authenticated_user]

  live "/custom", CustomDashboardLive, :index
  live "/custom/:layout_id", CustomDashboardLive, :show
end
```

## Testing

Comprehensive test coverage for:

- Layout CRUD operations
- Widget management
- Template creation
- Data fetching
- Export/Import
- Permission checks

Run tests:

```bash
mix test test/tamandua_server/dashboards/
```

## Extending the System

### Adding New Widget Types

1. Add widget type to `@widget_types` in `widget.ex`:

```elixir
@widget_types ~w(
  ...
  your_new_widget
)
```

2. Add default configuration:

```elixir
def default_config("your_new_widget") do
  %{
    "option1" => "value1",
    "option2" => true
  }
end
```

3. Add data fetching logic in `manager.ex`:

```elixir
defp fetch_fresh_widget_data(%Widget{widget_type: "your_new_widget"} = widget) do
  # Fetch your data
  data = %{...}
  {:ok, data}
end
```

4. Add rendering in `custom_dashboard_live.ex`:

```elixir
defp render_widget_content(%{widget_type: "your_new_widget"}, data) do
  assigns = %{data: data}
  ~H"""
  <!-- Your widget HTML -->
  """
end
```

### Adding New Templates

Add template configuration in `layout.ex`:

```elixir
def default_template_config("your_template") do
  %{
    "cols" => 12,
    "rowHeight" => 80,
    "widgets" => [
      %{"type" => "widget_type", "x" => 0, "y" => 0, "w" => 4, "h" => 3}
    ]
  }
end
```

## Roadmap

### Planned Features
- [ ] PDF/PNG dashboard export
- [ ] Dashboard sharing with other users
- [ ] Widget drill-down (click for detailed view)
- [ ] Chart.js/D3.js integration for advanced visualizations
- [ ] Custom widget creation UI
- [ ] Dashboard versioning
- [ ] Mobile-responsive layouts
- [ ] Dark mode widget themes
- [ ] Scheduled dashboard snapshots
- [ ] Widget data export (CSV, JSON)

### Known Limitations
- GridStack.js loaded from CDN (consider bundling for offline use)
- Maximum 12-column grid (configurable in code)
- Some widget types require Chart.js integration (planned)
- Geo map requires GeoIP database integration (planned)

## Security Considerations

- Dashboard layouts are user-scoped (no cross-user access)
- Organization-level isolation for multi-tenant deployments
- Widget data respects existing RBAC permissions
- Exported JSON contains no sensitive credentials
- Layout sharing requires explicit user permissions

## License

This dashboard system is part of Tamandua EDR and follows the same license.
