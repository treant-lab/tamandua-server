# Alert Timeline Visualization Guide

## Overview

The Alert Timeline feature provides an interactive, visual representation of all events that occur during an alert investigation. Using the vis.js Timeline library, it displays a comprehensive chronological view of:

- **Detection Events** - Alert creation and triggering
- **Response Actions** - Process kills, file quarantines, network isolations
- **Analyst Actions** - Status changes, comments, assignments, verdicts
- **System Events** - Enrichment, ML analysis, correlation, deduplication
- **External Events** - SIEM exports, ticket creation, webhook notifications

## Features

### 1. Interactive Timeline

- **Zoom and Pan** - Navigate through the timeline with mouse wheel (zoom) and drag (pan)
- **Event Grouping** - Events are organized into categorical groups for easy visualization
- **Event Details** - Hover over events to see full details, click to navigate to related resources
- **Current Time Indicator** - Visual marker showing the current time

### 2. Search and Filter

- **Full-Text Search** - Search events by title, content, or metadata
- **Group Filtering** - Show/hide specific event categories
- **Smart Highlighting** - Matching search results are highlighted

### 3. Playback Mode

- **Investigation Replay** - Watch the investigation unfold chronologically
- **Progress Tracking** - Visual progress bar shows replay position
- **Automatic Pacing** - Events appear one by one at configurable intervals

### 4. Export Capabilities

- **PNG Export** - Save timeline as an image
- **SVG Export** - Export as scalable vector graphics
- **JSON Export** - Download raw timeline data for external analysis

## Usage

### Adding Timeline to Alert Detail Page

```elixir
# In your alert_detail_live.ex

defmodule MyAppWeb.AlertDetailLive do
  use MyAppWeb, :live_view

  alias TamanduaServerWeb.Components.AlertTimeline

  def render(assigns) do
    ~H"""
    <div class="alert-detail-page">
      <!-- Other alert details... -->

      <div class="mt-8">
        <.live_component
          module={AlertTimeline}
          id="alert-timeline"
          alert={@alert}
        />
      </div>
    </div>
    """
  end
end
```

### Programmatic Timeline Building

```elixir
alias TamanduaServer.Alerts.{Alert, TimelineBuilder}

# Build timeline for an alert
alert = Repo.get!(Alert, alert_id) |> Repo.preload([:organization, :agent, :assigned_to])
timeline = TimelineBuilder.build_timeline(alert)

# Build timeline with options
timeline = TimelineBuilder.build_timeline(alert,
  include_comments: true,
  include_responses: true,
  include_system: true,
  include_external: false,
  limit: 500
)

# Export timeline as JSON for vis.js
json_data = TimelineBuilder.export_timeline_json(alert)
```

### JavaScript Integration

```javascript
import { AlertTimeline } from "./hooks/alert_timeline";

// Register hook in app.js
let liveSocket = new LiveSocket("/live", Socket, {
  hooks: {
    AlertTimeline: AlertTimeline,
    // ... other hooks
  },
});
```

## Event Types

### Detection Events

| Event | Description | Color |
|-------|-------------|-------|
| `alert_created` | Initial alert creation | Purple |
| `detection_triggered` | Rule or ML detection triggered | Purple |

### Response Actions

| Event | Description | Color |
|-------|-------------|-------|
| `kill_process` | Process terminated | Green |
| `quarantine_file` | File quarantined | Green |
| `isolate_network` | Network isolation applied | Green |
| `unisolate_network` | Network isolation removed | Green |
| `collect_forensics` | Forensic data collection | Green |
| `scan_path` | Path scan initiated | Green |

### Analyst Actions

| Event | Description | Color |
|-------|-------------|-------|
| `status_changed` | Alert status updated | Blue |
| `assignment_changed` | Alert assigned to analyst | Blue |
| `acknowledged` | Alert acknowledged | Blue |
| `escalated` | Alert escalated to higher tier | Orange |
| `verdict_changed` | Analyst verdict assigned | Blue/Red/Green |
| `severity_adjusted` | Severity level changed | Purple |
| `resolved` | Alert resolved | Green |
| `comment_added` | Comment added to alert | Blue |
| `comment_edited` | Comment edited | Orange |

### System Events

| Event | Description | Color |
|-------|-------------|-------|
| `ml_analysis` | ML model analysis completed | Purple |
| `enrichment_completed` | External enrichment data added | Cyan |
| `correlation` | Alert correlated to storyline | Teal |
| `deduplication` | Duplicate alert detected | Gray |

### External Events

| Event | Description | Color |
|-------|-------------|-------|
| `siem_export` | Alert exported to SIEM | Gray |
| `ticket_created` | Ticket created in ticketing system | Gray |
| `webhook_notification` | Webhook notification sent | Gray |

## Customization

### Custom Event Types

Extend the timeline with custom event types:

```elixir
# In timeline_builder.ex

defp build_custom_events(alert) do
  [
    %{
      id: "custom_event_#{alert.id}",
      type: "custom",
      subtype: "my_event",
      title: "Custom Event",
      content: "Custom event occurred",
      timestamp: DateTime.utc_now(),
      user_id: nil,
      user_name: "System",
      metadata: %{custom_data: "value"},
      severity: "info",
      group: "system",
      className: "timeline-event-custom",
      style: "background-color: #ff6b6b;"
    }
  ]
end
```

### Custom Styling

Override default styles in your CSS:

```css
/* Custom event styling */
.timeline-event-custom {
  background-color: #ff6b6b !important;
  border-color: #ff0000;
}

/* Custom group styling */
.timeline-group-custom {
  background-color: #ffe0e0;
}
```

## API Reference

### TimelineBuilder Module

#### `build_timeline/2`

Build a complete timeline for an alert.

**Parameters:**
- `alert` (Alert) - The alert to build timeline for
- `opts` (keyword) - Options:
  - `:include_comments` - Include comment events (default: true)
  - `:include_responses` - Include response action events (default: true)
  - `:include_system` - Include system events (default: true)
  - `:include_external` - Include external events (default: true)
  - `:limit` - Maximum number of events (default: 1000)

**Returns:** List of timeline event maps

#### `export_timeline_json/2`

Export timeline data in vis.js format.

**Parameters:**
- `alert` (Alert) - The alert to export timeline for
- `opts` (keyword) - Same as `build_timeline/2`

**Returns:** Map with `:items`, `:groups`, and `:options` keys

### AlertTimeline LiveComponent

#### Events

**Client to Server:**
- `search` - Search timeline events
- `filter_groups` - Filter by event groups
- `zoom_in` - Zoom in on timeline
- `zoom_out` - Zoom out on timeline
- `fit_timeline` - Fit timeline to view
- `toggle_playback` - Start/stop playback mode
- `export_png` - Export as PNG
- `export_svg` - Export as SVG
- `export_json` - Export as JSON

**Server to Client:**
- `timeline:search` - Apply search filter
- `timeline:filter` - Apply group filter
- `timeline:zoom_in` - Trigger zoom in
- `timeline:zoom_out` - Trigger zoom out
- `timeline:fit` - Trigger fit to view
- `timeline:start_playback` - Start playback
- `timeline:stop_playback` - Stop playback
- `timeline:export` - Trigger export

## Performance Considerations

### Large Timelines

For alerts with many events (1000+):

1. **Use Pagination** - Limit events using the `:limit` option
2. **Lazy Loading** - Load events on-demand as user zooms
3. **Virtual Scrolling** - Only render visible events

```elixir
# Load first 100 events
timeline = TimelineBuilder.build_timeline(alert, limit: 100)

# Load more on demand
timeline = TimelineBuilder.build_timeline(alert,
  limit: 100,
  offset: 100
)
```

### Caching

Cache timeline data to improve performance:

```elixir
# Cache timeline data
cached_timeline =
  Cachex.fetch(:timeline_cache, "alert_#{alert.id}", fn ->
    {:commit, TimelineBuilder.export_timeline_json(alert)}
  end)
```

## Best Practices

1. **Preload Associations** - Always preload related data before building timeline
   ```elixir
   alert = Repo.preload(alert, [
     :organization, :agent, :assigned_to, :assigned_by,
     :state_changed_by, :acknowledged_by, :escalated_to,
     :verdict_by, :severity_adjusted_by
   ])
   ```

2. **Use Appropriate Limits** - Don't load more events than needed
   ```elixir
   # For dashboard preview
   timeline = TimelineBuilder.build_timeline(alert, limit: 50)

   # For full investigation view
   timeline = TimelineBuilder.build_timeline(alert, limit: 1000)
   ```

3. **Filter by Category** - Show only relevant event types
   ```elixir
   # Show only analyst and response actions
   timeline = TimelineBuilder.build_timeline(alert,
     include_system: false,
     include_external: false
   )
   ```

4. **Handle Missing Data** - Timeline gracefully handles missing associations
   ```elixir
   # Works even if user associations are nil
   timeline = TimelineBuilder.build_timeline(alert)
   ```

## Troubleshooting

### Timeline Not Rendering

**Issue:** Timeline component doesn't appear on page

**Solutions:**
- Verify vis.js is installed: `npm install vis-timeline`
- Check JavaScript console for errors
- Ensure hook is registered in app.js
- Verify data is passed correctly: `data-timeline={Jason.encode!(@timeline_data)}`

### Events Not Appearing

**Issue:** Some events are missing from timeline

**Solutions:**
- Check event inclusion options (include_comments, include_responses, etc.)
- Verify associations are preloaded
- Check event timestamps are valid DateTime values
- Review limit option - may be cutting off events

### Performance Issues

**Issue:** Timeline is slow with many events

**Solutions:**
- Reduce event limit: `limit: 100`
- Disable unused event types: `include_system: false`
- Implement pagination or lazy loading
- Cache timeline data with Cachex

### Export Not Working

**Issue:** Export buttons don't download files

**Solutions:**
- Check browser console for JavaScript errors
- Verify export handlers are implemented
- Ensure blob/download APIs are supported in browser
- Check CORS settings for external resources

## Examples

### Basic Timeline

```elixir
<.live_component
  module={AlertTimeline}
  id="alert-timeline"
  alert={@alert}
/>
```

### Timeline with Custom Options

```elixir
# In your LiveView

def render(assigns) do
  ~H"""
  <.live_component
    module={AlertTimeline}
    id="alert-timeline"
    alert={@alert}
  />
  """
end

def mount(%{"id" => alert_id}, _session, socket) do
  alert = load_alert(alert_id)

  # Build custom timeline
  timeline_data = TimelineBuilder.export_timeline_json(alert,
    include_comments: false,  # Exclude comments
    include_system: true,     # Include system events
    limit: 200               # Limit to 200 events
  )

  {:ok, assign(socket, alert: alert, timeline_data: timeline_data)}
end
```

### Handling Timeline Events

```elixir
def handle_info({:timeline_event_clicked, event_id}, socket) do
  case parse_event_id(event_id) do
    {"comment", comment_id} ->
      # Navigate to comment
      {:noreply, push_navigate(socket, to: "/comments/#{comment_id}")}

    {"response", action_id} ->
      # Show response action details
      {:noreply, assign(socket, :selected_action, action_id)}

    _ ->
      {:noreply, socket}
  end
end
```

## Related Documentation

- [vis.js Timeline Documentation](https://visjs.github.io/vis-timeline/docs/timeline/)

Alert management, response action, and comment system runbooks are maintained in the
private monorepo release materials and are published only after review.

## Support

For issues or questions about the timeline feature:

1. Check the [Troubleshooting](#troubleshooting) section
2. Review [vis.js documentation](https://visjs.github.io/vis-timeline/)
3. Open an issue on GitHub
4. Contact the development team
