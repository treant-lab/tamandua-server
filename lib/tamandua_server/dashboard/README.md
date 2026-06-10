# Dashboard Sharing & Embedding

Complete implementation of public dashboard sharing with advanced access controls, embedding capabilities, and comprehensive analytics tracking.

## Features

### 1. Public Sharing
- **UUID-based Share Tokens**: Secure, unpredictable URLs for sharing
- **Password Protection**: Optional password requirement for accessing shared dashboards
- **Expiry Dates**: Configure expiration (1 day, 7 days, 30 days, or never)
- **Access Control**: IP address and domain whitelisting
- **Share Types**: Full dashboard or specific widgets only
- **Revocation**: Instantly revoke access to shared dashboards

### 2. Embed Codes
- **iframe Generation**: Auto-generated embed code with customizable dimensions
- **Responsive Design**: Configurable width/height (%, px, rem)
- **Transparent Background**: Optional transparent background for seamless embedding
- **Header/Footer Control**: Show or hide header and footer elements
- **Auto-refresh**: Configurable refresh interval for real-time data

### 3. Customization
- **Custom Branding**: Add custom logo, company name, colors
- **Custom Title**: Override dashboard title for shared views
- **Watermark**: Optional "Powered by Tamandua EDR" branding
- **Support Links**: Add custom support/contact URLs

### 4. Analytics
- **View Tracking**: Total views and unique visitors
- **Time Series**: Views by date for trend analysis
- **Referrer Tracking**: Top referral sources
- **Geographic Data**: Country and city tracking (with GeoIP integration)
- **Session Duration**: Average time spent viewing dashboard
- **User Analytics**: Aggregate analytics across all user shares

## Architecture

### Database Schema

```sql
-- Dashboard Shares
CREATE TABLE dashboard_shares (
  id UUID PRIMARY KEY,
  share_token VARCHAR UNIQUE NOT NULL,
  dashboard_layout_id UUID REFERENCES dashboard_layouts,
  created_by_user_id UUID REFERENCES users,

  -- Access Control
  is_active BOOLEAN DEFAULT TRUE,
  password_hash VARCHAR,
  expires_at TIMESTAMP,
  allowed_ips VARCHAR[],
  allowed_domains VARCHAR[],

  -- Sharing Options
  share_type VARCHAR NOT NULL, -- 'full_dashboard' or 'specific_widgets'
  widget_ids UUID[],

  -- Customization
  custom_title VARCHAR,
  show_header BOOLEAN DEFAULT FALSE,
  show_footer BOOLEAN DEFAULT TRUE,
  show_watermark BOOLEAN DEFAULT TRUE,
  branding_config JSONB,
  refresh_interval INTEGER DEFAULT 30000,

  -- Embed Options
  embed_width VARCHAR DEFAULT '100%',
  embed_height VARCHAR DEFAULT '600px',
  transparent_background BOOLEAN DEFAULT FALSE,

  -- Metadata
  description TEXT,
  last_accessed_at TIMESTAMP,
  revoked_at TIMESTAMP,

  inserted_at TIMESTAMP,
  updated_at TIMESTAMP
);

-- Dashboard Share Views (Analytics)
CREATE TABLE dashboard_share_views (
  id UUID PRIMARY KEY,
  dashboard_share_id UUID REFERENCES dashboard_shares,
  viewed_at TIMESTAMP NOT NULL,
  ip_address VARCHAR,
  user_agent VARCHAR,
  referrer VARCHAR,
  country VARCHAR,
  city VARCHAR,
  session_id VARCHAR,
  duration_seconds INTEGER,

  inserted_at TIMESTAMP,
  updated_at TIMESTAMP
);
```

### Core Modules

```
lib/tamandua_server/
├── dashboard/
│   ├── share.ex                 # Share schema with access validation
│   ├── share_view.ex            # View tracking schema
│   └── share_manager.ex         # CRUD operations and analytics
└── dashboard.ex                 # Public API context

lib/tamandua_server_web/
├── controllers/
│   ├── dashboard_share_controller.ex     # Public share endpoint
│   ├── dashboard_share_html.ex           # HTML views
│   └── dashboard_share_html/
│       ├── show.html.heex                # Public dashboard view
│       └── password_prompt.html.heex     # Password challenge
└── live/
    └── dashboard_share_live.ex           # Share management UI

lib/tamandua_server/workers/
└── share_cleanup_worker.ex      # Automatic expiry cleanup
```

## Usage

### Creating a Share

```elixir
# Basic share (full dashboard, no restrictions)
{:ok, share} = TamanduaServer.Dashboard.create_share(%{
  dashboard_layout_id: "dashboard-uuid",
  created_by_user_id: "user-uuid",
  share_type: "full_dashboard"
})

# Share with password protection
{:ok, share} = TamanduaServer.Dashboard.create_share(%{
  dashboard_layout_id: "dashboard-uuid",
  created_by_user_id: "user-uuid",
  share_type: "full_dashboard",
  password: "secret123"
})

# Share with expiry
{:ok, share} = TamanduaServer.Dashboard.create_share(%{
  dashboard_layout_id: "dashboard-uuid",
  created_by_user_id: "user-uuid",
  share_type: "full_dashboard",
  expires_at: DateTime.add(DateTime.utc_now(), 7, :day)
})

# Share specific widgets only
{:ok, share} = TamanduaServer.Dashboard.create_share(%{
  dashboard_layout_id: "dashboard-uuid",
  created_by_user_id: "user-uuid",
  share_type: "specific_widgets",
  widget_ids: ["widget1-uuid", "widget2-uuid"]
})

# Share with IP restrictions
{:ok, share} = TamanduaServer.Dashboard.create_share(%{
  dashboard_layout_id: "dashboard-uuid",
  created_by_user_id: "user-uuid",
  share_type: "full_dashboard",
  allowed_ips: ["192.168.1.1", "10.0.0.0/24"]
})

# Share with domain restrictions (for embedding)
{:ok, share} = TamanduaServer.Dashboard.create_share(%{
  dashboard_layout_id: "dashboard-uuid",
  created_by_user_id: "user-uuid",
  share_type: "full_dashboard",
  allowed_domains: ["example.com", "*.trusted.com"]
})

# Fully customized share
{:ok, share} = TamanduaServer.Dashboard.create_share(%{
  dashboard_layout_id: "dashboard-uuid",
  created_by_user_id: "user-uuid",
  share_type: "full_dashboard",
  custom_title: "Q4 Security Overview",
  show_header: true,
  show_footer: true,
  show_watermark: false,
  branding_config: %{
    "logo_url" => "https://example.com/logo.png",
    "company_name" => "ACME Corp",
    "support_url" => "https://example.com/support"
  },
  refresh_interval: 60000,
  embed_width: "100%",
  embed_height: "800px",
  transparent_background: false
})
```

### Managing Shares

```elixir
# List all shares for a dashboard
shares = Dashboard.list_shares_for_dashboard("dashboard-uuid")

# List all shares by a user
shares = Dashboard.list_shares_by_user("user-uuid")

# Get share by token
share = Dashboard.get_share_by_token("share-token-uuid")

# Update share
{:ok, updated} = Dashboard.update_share(share, %{
  custom_title: "Updated Title",
  expires_at: DateTime.add(DateTime.utc_now(), 30, :day)
})

# Toggle active status
{:ok, toggled} = Dashboard.toggle_active(share)

# Revoke share
{:ok, revoked} = Dashboard.revoke_share(share)

# Regenerate share token (creates new URL)
{:ok, new_share} = Dashboard.regenerate_token(share)

# Delete share permanently
{:ok, deleted} = Dashboard.delete_share(share)
```

### Validating Access

```elixir
# Basic validation
case Dashboard.validate_access(token) do
  {:ok, share} ->
    # Access granted
  {:error, :not_found} ->
    # Invalid token
  {:error, :not_accessible} ->
    # Expired, revoked, or inactive
end

# With password
case Dashboard.validate_access(token, password: "secret123") do
  {:ok, share} ->
    # Access granted
  {:error, :password_required} ->
    # Password needed
  {:error, :invalid_password} ->
    # Wrong password
end

# With IP and domain restrictions
case Dashboard.validate_access(token,
  ip_address: "192.168.1.1",
  domain: "example.com"
) do
  {:ok, share} ->
    # Access granted
  {:error, :ip_not_allowed} ->
    # IP not whitelisted
  {:error, :domain_not_allowed} ->
    # Domain not whitelisted
end
```

### Recording Views

```elixir
# Manual view recording
{:ok, view} = Dashboard.record_view(share.id, %{
  viewed_at: DateTime.utc_now(),
  ip_address: "192.168.1.1",
  user_agent: "Mozilla/5.0...",
  referrer: "https://google.com",
  session_id: "unique-session-id"
})

# From Plug.Conn (automatically extracts IP, user agent, referrer)
{:ok, view} = Dashboard.record_view_from_conn(conn, share.id)
```

### Analytics

```elixir
# Get analytics for a specific share
analytics = Dashboard.get_share_analytics(share.id, time_range: :last_30_days)

# Returns:
# %{
#   total_views: 156,
#   unique_visitors: 89,
#   views_by_date: [
#     %{date: ~D[2026-01-01], count: 12},
#     %{date: ~D[2026-01-02], count: 15},
#     ...
#   ],
#   top_referrers: [
#     %{referrer: "https://google.com", count: 45},
#     %{referrer: "https://twitter.com", count: 23},
#     ...
#   ],
#   top_countries: [
#     %{country: "US", count: 67},
#     %{country: "UK", count: 34},
#     ...
#   ],
#   avg_duration_seconds: 145.5
# }

# Get aggregate analytics for all user shares
user_analytics = Dashboard.get_user_analytics(user_id, time_range: :last_7_days)

# Returns:
# %{
#   total_shares: 5,
#   total_views: 234,
#   unique_visitors: 156,
#   shares: [
#     %Share{view_count: 89, ...},
#     %Share{view_count: 67, ...},
#     ...
#   ]
# }
```

### Generating URLs and Embed Codes

```elixir
# Get public share URL
url = TamanduaServer.Dashboard.Share.share_url(share, "https://tamandua.example.com")
# => "https://tamandua.example.com/shared/dashboard/abc-123-def-456"

# Generate embed code
embed_code = TamanduaServer.Dashboard.Share.generate_embed_code(share, "https://tamandua.example.com")
# => "<iframe src='...' width='100%' height='600px' ...></iframe>"
```

## Public Routes

Add to `router.ex`:

```elixir
scope "/shared", TamanduaServerWeb do
  pipe_through :browser

  get "/dashboard/:token", DashboardShareController, :show
  post "/dashboard/:token/authenticate", DashboardShareController, :authenticate
end
```

## Management UI Routes

Add to authenticated routes:

```elixir
scope "/dashboard", TamanduaServerWeb do
  pipe_through [:browser, :require_authenticated_user]

  live "/shares", DashboardShareLive, :index
  live "/shares/new", DashboardShareLive, :new
  live "/shares/:id/analytics", DashboardShareLive, :analytics
end
```

## Background Jobs

The `ShareCleanupWorker` runs hourly to automatically deactivate expired shares:

```elixir
# Add to application.ex supervision tree
children = [
  # ...
  TamanduaServer.Workers.ShareCleanupWorker
]

# Manual trigger
TamanduaServer.Workers.ShareCleanupWorker.trigger_cleanup()
```

## Security Considerations

### Access Control
- **Share Tokens**: UUIDs are cryptographically secure and unpredictable
- **Password Hashing**: Uses Bcrypt for password protection
- **IP Whitelisting**: Restricts access to specific IP addresses or CIDR ranges
- **Domain Whitelisting**: Prevents unauthorized embedding
- **Expiration**: Automatic deactivation of expired shares
- **Revocation**: Instant invalidation of share URLs

### Rate Limiting
Consider adding rate limiting to public share endpoints:

```elixir
plug :rate_limit, max_requests: 100, interval: :timer.minutes(1)
```

### HTTPS Only
Public shares should only be served over HTTPS in production:

```elixir
# config/prod.exs
config :tamandua_server, TamanduaServerWeb.Endpoint,
  force_ssl: [hsts: true]
```

## Integration with GeoIP

To enable geographic tracking, integrate with a GeoIP service:

```elixir
# lib/tamandua_server/dashboard/share_manager.ex
defp lookup_geo(ip_address) do
  case Geolix.lookup(ip_address) do
    %{country: %{name: country}, city: %{name: city}} ->
      {:ok, %{country: country, city: city}}
    _ ->
      {:ok, %{country: nil, city: nil}}
  end
end
```

Add Geolix to dependencies:

```elixir
# mix.exs
{:geolix, "~> 2.0"},
{:geolix_adapter_mmdb2, "~> 0.6.0"}
```

## Customization Examples

### Custom Branding

```elixir
branding_config = %{
  "logo_url" => "https://cdn.example.com/logo.png",
  "company_name" => "ACME Security",
  "primary_color" => "#0066cc",
  "support_url" => "https://support.example.com",
  "show_last_updated" => true
}
```

### Responsive Embedding

```elixir
# Full width, fixed height
embed_width: "100%"
embed_height: "600px"

# Fixed dimensions
embed_width: "800px"
embed_height: "600px"

# Relative units
embed_width: "80vw"
embed_height: "60vh"
```

## Performance Optimization

### Caching Widget Data
Widget data is fetched on-demand. Consider implementing caching:

```elixir
# In DashboardShareController
defp fetch_widget_data(widgets) do
  widgets
  |> Task.async_stream(fn widget ->
    case TamanduaServer.Cache.fetch("widget_data:#{widget.id}", ttl: 30_000) do
      {:ok, cached_data} ->
        {widget.id, cached_data}
      :miss ->
        {:ok, data} = Dashboards.fetch_widget_data(widget)
        TamanduaServer.Cache.put("widget_data:#{widget.id}", data)
        {widget.id, data}
    end
  end, max_concurrency: 10)
  |> Enum.map(fn {:ok, result} -> result end)
  |> Map.new()
end
```

### View Aggregation
Consider batching view inserts for high-traffic shares:

```elixir
# Use Broadway pipeline for async view recording
defmodule TamanduaServer.Dashboard.ViewRecorder do
  use Broadway

  def start_link(_opts) do
    Broadway.start_link(__MODULE__,
      name: __MODULE__,
      producer: [
        module: {BroadwayRabbitMQ.Producer, queue: "dashboard_views"}
      ],
      processors: [
        default: [concurrency: 10]
      ]
    )
  end

  def handle_message(_, message, _) do
    view_data = Jason.decode!(message.data)
    Dashboard.record_view(view_data)
    message
  end
end
```

## Testing

Run the comprehensive test suite:

```bash
mix test test/tamandua_server/dashboard/share_manager_test.exs
```

Tests cover:
- Share creation with all options
- Access validation (password, IP, domain, expiry)
- View recording and analytics
- Bulk operations
- Edge cases and error handling

## API Documentation

Generate API docs:

```bash
mix docs
```

View at `doc/TamanduaServer.Dashboard.html`

## Future Enhancements

1. **Email Notifications**: Alert share creator when share is accessed
2. **Usage Quotas**: Limit views per share or per user
3. **Scheduled Shares**: Auto-activate/deactivate at specific times
4. **Share Templates**: Pre-configured share settings
5. **Webhook Integration**: Trigger webhooks on share events
6. **Advanced Analytics**: Heatmaps, scroll depth, interaction tracking
7. **Multi-language Support**: Localized public dashboard views
8. **PDF Export**: Generate PDF snapshots of shared dashboards
9. **Social Sharing**: One-click sharing to Twitter, LinkedIn, etc.
10. **Collaborative Commenting**: Allow viewers to leave comments (opt-in)

## License

Copyright © 2026 Tamandua EDR. All rights reserved.
