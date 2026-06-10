# Alert Timeline - Quick Start Guide

Get the interactive alert timeline visualization up and running in 5 minutes.

## Installation

### 1. Install vis.js Timeline

```bash
cd apps/tamandua_server_web/assets
npm install vis-timeline
```

### 2. Import CSS

Add to `apps/tamandua_server_web/assets/css/app.css`:

```css
@import "vis-timeline/styles/vis-timeline-graph2d.min.css";
@import "./alert_timeline.css";
```

### 3. Register JavaScript Hook

Add to `apps/tamandua_server_web/assets/js/app.js`:

```javascript
import { AlertTimeline } from "./hooks/alert_timeline";

let Hooks = {
  AlertTimeline: AlertTimeline,
  // ... other hooks
};

let liveSocket = new LiveSocket("/live", Socket, {
  params: { _csrf_token: csrfToken },
  hooks: Hooks,
});
```

## Basic Usage

### Add Timeline to Alert Detail Page

Update `apps/tamandua_server_web/lib/tamandua_server_web/live/alert_detail_live.ex`:

```elixir
defmodule TamanduaServerWeb.AlertDetailLive do
  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Alerts.Alert
  alias TamanduaServerWeb.Components.AlertTimeline

  @impl true
  def mount(%{"id" => alert_id}, _session, socket) do
    alert = load_alert(alert_id)

    {:ok,
     socket
     |> assign(:alert, alert)
     |> assign(:active_tab, "timeline")}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="alert-detail-page">
      <!-- Alert Header -->
      <div class="alert-header">
        <h1><%= @alert.title %></h1>
      </div>

      <!-- Tabs -->
      <div class="tabs">
        <button phx-click="switch_tab" phx-value-tab="details">Details</button>
        <button phx-click="switch_tab" phx-value-tab="timeline">Timeline</button>
        <button phx-click="switch_tab" phx-value-tab="evidence">Evidence</button>
      </div>

      <!-- Tab Content -->
      <%= if @active_tab == "timeline" do %>
        <.live_component
          module={AlertTimeline}
          id="alert-timeline"
          alert={@alert}
        />
      <% end %>
    </div>
    """
  end

  @impl true
  def handle_event("switch_tab", %{"tab" => tab}, socket) do
    {:noreply, assign(socket, :active_tab, tab)}
  end

  defp load_alert(alert_id) do
    Alert
    |> Repo.get!(alert_id)
    |> Repo.preload([
      :organization, :agent, :assigned_to, :assigned_by,
      :state_changed_by, :acknowledged_by, :escalated_to,
      :verdict_by, :severity_adjusted_by
    ])
  end
end
```

## Test It Out

### 1. Start the Server

```bash
cd apps/tamandua_server
mix phx.server
```

### 2. Navigate to an Alert

Open your browser to `http://localhost:4000/alerts/{alert_id}` and click the "Timeline" tab.

### 3. Interact with the Timeline

- **Zoom**: Scroll with mouse wheel
- **Pan**: Click and drag the timeline
- **Search**: Use the search box to filter events
- **Filter**: Select event categories to show/hide
- **Playback**: Click "Replay" to watch the investigation unfold
- **Export**: Click "Export" to save as PNG, SVG, or JSON

## What's Included?

The timeline automatically displays:

- ✅ Alert creation and updates
- ✅ Status changes (new → investigating → resolved)
- ✅ Assignments and acknowledgments
- ✅ Escalations and verdicts
- ✅ Severity adjustments
- ✅ Response actions (kill process, quarantine, isolate)
- ✅ Comments and analyst notes
- ✅ System events (ML analysis, enrichment, correlation)
- ✅ Deduplication events

## Common Scenarios

### Show Only Critical Events

```elixir
# In your LiveView
timeline_data = TimelineBuilder.export_timeline_json(alert,
  include_comments: false,  # Hide comments
  include_system: false     # Hide system events
)
```

### Limit Timeline Size

```elixir
# Show only last 100 events
timeline_data = TimelineBuilder.export_timeline_json(alert, limit: 100)
```

### Handle Event Clicks

```elixir
@impl true
def handle_info({:timeline_event_clicked, event_id}, socket) do
  IO.puts("User clicked event: #{event_id}")
  {:noreply, socket}
end
```

## Troubleshooting

### Timeline Not Showing?

1. Check browser console for JavaScript errors
2. Verify vis.js is installed: `npm list vis-timeline`
3. Ensure hook is registered in app.js
4. Check that alert has events (try updating alert status)

### Performance Issues?

1. Reduce event limit: `limit: 50`
2. Disable unused categories: `include_system: false`
3. Cache timeline data using Cachex

### Events Missing?

1. Verify alert associations are preloaded
2. Check event inclusion options
3. Review event timestamps (must be valid DateTime)

## Next Steps

- Read the [Full Documentation](./ALERT_TIMELINE_GUIDE.md)
- Customize event styling in `alert_timeline.css`
- Add custom event types
- Implement timeline caching
- Export timeline data for reporting

## Example: Complete Implementation

```elixir
defmodule TamanduaServerWeb.AlertDetailLive do
  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Alerts.{Alert, TimelineBuilder}
  alias TamanduaServer.Repo
  alias TamanduaServerWeb.Components.AlertTimeline

  @impl true
  def mount(%{"id" => alert_id}, _session, socket) do
    if connected?(socket) do
      # Subscribe to alert updates
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alert:#{alert_id}")
    end

    alert = load_alert(alert_id)

    {:ok,
     socket
     |> assign(:alert, alert)
     |> assign(:active_tab, "timeline")}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="max-w-7xl mx-auto px-4 py-8">
      <div class="bg-white shadow rounded-lg">
        <!-- Alert Header -->
        <div class="px-6 py-4 border-b">
          <h1 class="text-2xl font-bold"><%= @alert.title %></h1>
          <p class="text-gray-600"><%= @alert.description %></p>
        </div>

        <!-- Timeline -->
        <.live_component
          module={AlertTimeline}
          id="alert-timeline"
          alert={@alert}
        />
      </div>
    </div>
    """
  end

  @impl true
  def handle_info({:alert_updated, updated_alert}, socket) do
    # Reload alert when it's updated
    alert = load_alert(updated_alert.id)
    {:noreply, assign(socket, :alert, alert)}
  end

  def handle_info({:timeline_event_clicked, event_id}, socket) do
    # Handle timeline event clicks
    IO.inspect(event_id, label: "Timeline event clicked")
    {:noreply, socket}
  end

  defp load_alert(alert_id) do
    Alert
    |> Repo.get!(alert_id)
    |> Repo.preload([
      :organization, :agent, :assigned_to, :assigned_by,
      :state_changed_by, :acknowledged_by, :escalated_to,
      :verdict_by, :severity_adjusted_by
    ])
  end
end
```

That's it! You now have a fully functional interactive timeline for alert investigation.

For advanced features and customization, see the [Full Documentation](./ALERT_TIMELINE_GUIDE.md).
