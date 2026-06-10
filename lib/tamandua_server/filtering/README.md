# Advanced Filter Builder

Comprehensive filtering system for Tamandua EDR with visual query builder, 30+ operators, and multiple modes.

## Features

### Visual Query Builder
- Drag-and-drop filter construction
- Nested AND/OR/NOT logic with visual grouping
- Real-time validation with inline error messages
- Field auto-suggest with type-ahead search
- Value auto-suggest from database
- Popular fields marked with star (★)

### 30+ Operators

#### Comparison Operators (6)
- `eq` (=) - Equals
- `ne` (!=) - Not equals
- `gt` (>) - Greater than
- `gte` (>=) - Greater than or equal
- `lt` (<) - Less than
- `lte` (<=) - Less than or equal

#### String Operators (7)
- `contains` - String contains substring
- `not_contains` - String does not contain substring
- `starts_with` - String starts with prefix
- `ends_with` - String ends with suffix
- `regex` - Regular expression match
- `in` - Value in list
- `not_in` - Value not in list

#### Numeric Operators (3)
- `between` - Value between min and max (inclusive)
- `in_range` - Value in numeric range
- `modulo` - Value modulo N equals result

#### Date/Time Operators (6)
- `before` - Date before specified date
- `after` - Date after specified date
- `date_between` - Date between two dates
- `last_n_days` - Date within last N days
- `last_n_hours` - Date within last N hours
- `last_n_minutes` - Date within last N minutes

#### Array Operators (6)
- `array_contains` - Array contains value
- `array_contains_all` - Array contains all values
- `array_contains_any` - Array contains any value
- `array_overlaps` - Arrays have common elements
- `array_empty` - Array is empty
- `array_not_empty` - Array is not empty

#### Geospatial Operators (3)
- `within_radius` - Point within radius (lat, lon, radius_km)
- `in_polygon` - Point within polygon
- `bbox` - Point within bounding box

#### Null Operators (2)
- `is_null` - Field is null
- `is_not_null` - Field is not null

#### Network Operators (2)
- `cidr` - IP in CIDR range
- `ip_range` - IP in range

#### Special Operators (3)
- `exists` - Field exists in document
- `json_path` - JSONPath query
- `fuzzy` - Fuzzy string match (Levenshtein distance)

### Filter Modes

1. **Visual Mode** - Drag-and-drop builder with visual grouping
2. **Code Mode** - JSON editor with syntax validation
3. **SQL Mode** - SQL preview (read-only)
4. **Quick Mode** - Text-based quick search

### Saved Filters

- Save filters with name and description
- Organize by category (alerts, agents, events, threats, etc.)
- Pin favorite filters
- Share filters with team or make public
- Filter templates for common patterns
- Version tracking
- Usage analytics

## Usage

### Basic Example

```elixir
# Create a filter
filter = %{
  "logic" => "AND",
  "conditions" => [
    %{"field" => "severity", "operator" => "in", "value" => ["critical", "high"]},
    %{"field" => "status", "operator" => "eq", "value" => "new"}
  ]
}

# Validate filter
{:ok, validated} = TamanduaServer.Filtering.validate_filter(filter)

# Build query
query = TamanduaServer.Filtering.build_query(Alert, validated)

# Execute query
alerts = TamanduaServer.Repo.all(query)
```

### Nested Logic Example

```elixir
filter = %{
  "logic" => "AND",
  "conditions" => [
    %{"field" => "severity", "operator" => "in", "value" => ["critical", "high"]},
    %{
      "logic" => "OR",
      "conditions" => [
        %{"field" => "status", "operator" => "eq", "value" => "new"},
        %{"field" => "assigned_to_id", "operator" => "is_null"}
      ]
    }
  ]
}
```

### Date Range Example

```elixir
filter = %{
  "logic" => "AND",
  "conditions" => [
    %{"field" => "created_at", "operator" => "last_n_days", "value" => 7},
    %{"field" => "severity", "operator" => "eq", "value" => "critical"}
  ]
}
```

### Geospatial Example

```elixir
filter = %{
  "logic" => "AND",
  "conditions" => [
    %{
      "field" => "agent_location",
      "operator" => "within_radius",
      "value" => %{
        "lat" => 37.7749,
        "lon" => -122.4194,
        "radius_km" => 50
      }
    }
  ]
}
```

### Using LiveView Component

```elixir
# In your LiveView
defmodule MyAppWeb.AlertsLive do
  use MyAppWeb, :live_view
  alias TamanduaServerWeb.Components.FilterBuilder

  def render(assigns) do
    ~H"""
    <FilterBuilder.advanced_filter_builder
      filter={@filter}
      field_metadata={@field_metadata}
      mode={@filter_mode}
      scope="alerts"
      result_count={@result_count}
    />
    """
  end

  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:filter, initial_filter())
      |> assign(:field_metadata, Filtering.get_field_metadata("alerts"))
      |> assign(:filter_mode, "visual")
      |> assign(:result_count, nil)

    {:ok, socket}
  end

  def handle_event("add_condition", %{"path" => path}, socket) do
    # Handle adding condition
    {:noreply, socket}
  end

  # ... more event handlers
end
```

## Saved Filters Management

### Create Saved Filter

```elixir
{:ok, saved_filter} = TamanduaServer.Filtering.create_saved_filter(%{
  name: "Critical Unresolved Alerts",
  description: "High priority alerts that need attention",
  filter_json: filter,
  category: "alerts",
  scope: "alerts",
  user_id: user_id,
  organization_id: org_id,
  is_pinned: true
})
```

### List Saved Filters

```elixir
# All filters for user
filters = TamanduaServer.Filtering.list_saved_filters(user_id, org_id)

# Pinned filters only
pinned = TamanduaServer.Filtering.list_saved_filters(user_id, org_id, pinned_only: true)

# Templates only
templates = TamanduaServer.Filtering.list_saved_filters(user_id, org_id, templates_only: true)

# By scope
alert_filters = TamanduaServer.Filtering.list_saved_filters(user_id, org_id, scope: "alerts")
```

### Filter Templates

```elixir
# Get default templates
templates = TamanduaServer.Filtering.list_filter_templates("alerts")

# Templates include:
# - Unresolved High Severity
# - Last 24 Hours
# - Unassigned
# - MITRE ATT&CK: Persistence
# - ML Detections
# - Threat Score > 0.8
```

## Field Metadata

Field metadata provides information about available fields, their types, and supported operators.

```elixir
field_metadata = TamanduaServer.Filtering.get_field_metadata("alerts")

# Returns:
[
  %{
    name: "severity",
    display_name: "Severity",
    type: :enum,
    operators: ["eq", "ne", "in", "not_in"],
    values: ["critical", "high", "medium", "low", "info"],
    popular: true
  },
  %{
    name: "threat_score",
    display_name: "Threat Score",
    type: :float,
    operators: ["eq", "ne", "gt", "gte", "lt", "lte", "between"],
    popular: true
  },
  # ... more fields
]
```

## API Endpoints

### Get Field Metadata
```
GET /api/v1/filtering/field_metadata?scope=alerts
```

### Get Value Suggestions
```
GET /api/v1/filtering/value_suggestions?field=severity&scope=alerts
```

### Validate Filter
```
POST /api/v1/filtering/validate
Content-Type: application/json

{
  "filter": {
    "logic": "AND",
    "conditions": [...]
  }
}
```

### Save Filter
```
POST /api/v1/filtering/saved_filters
Content-Type: application/json

{
  "name": "My Filter",
  "description": "...",
  "filter_json": {...},
  "category": "alerts",
  "scope": "alerts"
}
```

## Quick Filter Syntax

Quick mode supports simple text-based filtering:

```
severity:critical status:new           # Field:value pairs
severity:critical,high                 # Multiple values
threat_score>0.8                       # Comparison operators
created_at:last_7d                     # Time shortcuts
"malicious process"                    # Free text search
```

## Performance Considerations

### Indexing

Ensure proper database indexes for filtered fields:

```sql
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_created_at ON alerts(inserted_at);
CREATE INDEX idx_alerts_threat_score ON alerts(threat_score);
```

### Query Optimization

- Filters are converted to optimized Ecto dynamic queries
- PostgreSQL query planner handles complex nested conditions
- Use EXPLAIN ANALYZE to check query performance
- Consider materialized views for frequently used filters

### Caching

- Field metadata is cached in-memory
- Value suggestions are cached for 5 minutes
- Popular filters can be pre-computed

## Testing

```bash
# Run filter tests
mix test test/tamandua_server/filtering/

# Run specific test
mix test test/tamandua_server/filtering/filter_parser_test.exs
```

## Examples by Use Case

### Security Operations

```elixir
# Unresolved critical alerts in last 24h
%{
  "logic" => "AND",
  "conditions" => [
    %{"field" => "severity", "operator" => "eq", "value" => "critical"},
    %{"field" => "status", "operator" => "in", "value" => ["new", "investigating"]},
    %{"field" => "created_at", "operator" => "last_n_hours", "value" => 24}
  ]
}
```

### Threat Hunting

```elixir
# Suspicious lateral movement patterns
%{
  "logic" => "AND",
  "conditions" => [
    %{"field" => "mitre_tactic", "operator" => "array_contains", "value" => "lateral-movement"},
    %{"field" => "threat_score", "operator" => "gte", "value" => 0.7},
    %{
      "logic" => "OR",
      "conditions" => [
        %{"field" => "process_name", "operator" => "regex", "value" => "psexec|wmiprvse"},
        %{"field" => "network_connections", "operator" => "array_not_empty"}
      ]
    }
  ]
}
```

### Compliance

```elixir
# Failed login attempts from external IPs
%{
  "logic" => "AND",
  "conditions" => [
    %{"field" => "event_type", "operator" => "eq", "value" => "authentication"},
    %{"field" => "result", "operator" => "eq", "value" => "failed"},
    %{"field" => "ip_address", "operator" => "cidr", "value" => "0.0.0.0/0"},
    %{
      "logic" => "NOT",
      "conditions" => [
        %{"field" => "ip_address", "operator" => "cidr", "value" => "10.0.0.0/8"}
      ]
    }
  ]
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    LiveView Component                        │
│  ┌─────────────┐ ┌──────────────┐ ┌─────────────────────┐  │
│  │ Visual Mode │ │  Code Mode   │ │     SQL Preview     │  │
│  └─────────────┘ └──────────────┘ └─────────────────────┘  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
         ┌───────────────────────────────┐
         │    FilterParser (Validation)   │
         └───────────────┬───────────────┘
                         │
                         ▼
         ┌───────────────────────────────┐
         │   QueryBuilder (Ecto Queries) │
         └───────────────┬───────────────┘
                         │
                         ▼
         ┌───────────────────────────────┐
         │      PostgreSQL Database       │
         └───────────────────────────────┘
```

## Browser Support

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+

Requires:
- JavaScript ES6+
- CSS Grid
- Drag and Drop API

## Accessibility

- ARIA labels for all interactive elements
- Keyboard navigation support (Tab, Enter, Escape)
- Screen reader compatible
- High contrast mode support

## Security

- All filters are validated server-side
- SQL injection protection via parameterized queries
- XSS protection via Phoenix HTML escaping
- CSRF protection via Phoenix tokens

## Troubleshooting

### Filter validation fails
- Check that all required fields have values
- Verify operator is supported for field type
- Ensure nested groups are properly formed

### Slow query performance
- Check database indexes
- Use EXPLAIN ANALYZE to identify bottlenecks
- Consider simplifying complex nested filters

### Value suggestions not loading
- Check API endpoint is responding
- Verify field name is correct
- Check browser console for errors

## Contributing

See main CONTRIBUTING.md for guidelines.

## License

See main LICENSE file.
