# Dashboard Sharing - Quick Start Guide

Get started with dashboard sharing in 5 minutes.

## Setup

### 1. Run Migration

```bash
cd apps/tamandua_server
mix ecto.migrate
```

This creates the `dashboard_shares` and `dashboard_share_views` tables.

### 2. Add Routes

Edit `lib/tamandua_server_web/router.ex`:

```elixir
# Public share routes (no authentication)
scope "/shared", TamanduaServerWeb do
  pipe_through :browser

  get "/dashboard/:token", DashboardShareController, :show
  post "/dashboard/:token/authenticate", DashboardShareController, :authenticate
end

# Share management routes (authenticated)
scope "/dashboard", TamanduaServerWeb do
  pipe_through [:browser, :require_authenticated_user]

  live "/shares", DashboardShareLive, :index
  live "/shares/:id/analytics", DashboardShareLive, :analytics
end
```

### 3. Add Worker to Supervision Tree

Edit `lib/tamandua_server/application.ex`:

```elixir
children = [
  # ... existing children ...
  TamanduaServer.Workers.ShareCleanupWorker
]
```

### 4. Start Server

```bash
mix phx.server
```

## Basic Usage

### Create a Share (UI)

1. Navigate to `/dashboard/shares`
2. Click "Share" on any dashboard card
3. Configure sharing options:
   - Share type (full dashboard or specific widgets)
   - Password protection (optional)
   - Expiry date
   - Display options
4. Click "Create Share"
5. Copy the share URL or embed code

### Create a Share (Code)

```elixir
# In IEx or your application code
alias TamanduaServer.{Dashboard, Dashboards}

# Get a dashboard
{:ok, layout} = Dashboards.get_or_create_default_layout(user.id)

# Create a simple share
{:ok, share} = Dashboard.create_share(%{
  dashboard_layout_id: layout.id,
  created_by_user_id: user.id,
  share_type: "full_dashboard"
})

# Get the public URL
url = "#{TamanduaServerWeb.Endpoint.url()}/shared/dashboard/#{share.share_token}"
IO.puts("Share URL: #{url}")
```

### Access the Share

Open the share URL in any browser (no authentication required):

```
https://your-domain.com/shared/dashboard/abc-123-def-456
```

## Common Scenarios

### Password-Protected Share

```elixir
{:ok, share} = Dashboard.create_share(%{
  dashboard_layout_id: layout.id,
  created_by_user_id: user.id,
  share_type: "full_dashboard",
  password: "secret123",
  expires_at: DateTime.add(DateTime.utc_now(), 7, :day)
})
```

Users will see a password prompt before accessing the dashboard.

### Embed in Website

After creating a share, get the embed code:

```elixir
embed_code = TamanduaServer.Dashboard.Share.generate_embed_code(
  share,
  TamanduaServerWeb.Endpoint.url()
)

IO.puts(embed_code)
```

Paste the iframe code into your HTML:

```html
<iframe
  src="https://your-domain.com/shared/dashboard/abc-123"
  width="100%"
  height="600px"
  frameborder="0"
  allowfullscreen>
</iframe>
```

### Share with Domain Restrictions

Prevent unauthorized embedding:

```elixir
{:ok, share} = Dashboard.create_share(%{
  dashboard_layout_id: layout.id,
  created_by_user_id: user.id,
  share_type: "full_dashboard",
  allowed_domains: ["example.com", "*.mycompany.com"]
})
```

Only pages on `example.com` or subdomains of `mycompany.com` can embed this dashboard.

### View Analytics

```elixir
# Get analytics for a specific share
analytics = Dashboard.get_share_analytics(share.id)

IO.inspect(analytics, label: "Analytics")

# Output:
# %{
#   total_views: 42,
#   unique_visitors: 28,
#   views_by_date: [...],
#   top_referrers: [...],
#   top_countries: [...],
#   avg_duration_seconds: 127.5
# }
```

Or view in the UI at `/dashboard/shares/:id/analytics`.

## Management

### Revoke a Share

```elixir
# Instantly revoke access
{:ok, revoked} = Dashboard.revoke_share(share)
```

Or click "Revoke" in the UI.

### Regenerate URL

If a share URL is compromised, generate a new token:

```elixir
{:ok, new_share} = Dashboard.regenerate_token(share)

# Old URL no longer works
# New URL: /shared/dashboard/#{new_share.share_token}
```

### List Active Shares

```elixir
# All shares by a user
shares = Dashboard.list_shares_by_user(user.id)

# All shares for a specific dashboard
shares = Dashboard.list_shares_for_dashboard(layout.id)
```

## Customization

### Custom Branding

```elixir
{:ok, share} = Dashboard.create_share(%{
  dashboard_layout_id: layout.id,
  created_by_user_id: user.id,
  share_type: "full_dashboard",
  custom_title: "Q4 2026 Security Report",
  show_header: true,
  show_footer: true,
  branding_config: %{
    "logo_url" => "https://cdn.example.com/logo.png",
    "company_name" => "ACME Security",
    "support_url" => "https://support.acme.com"
  }
})
```

### Auto-Refresh

Set the refresh interval (in milliseconds):

```elixir
{:ok, share} = Dashboard.create_share(%{
  dashboard_layout_id: layout.id,
  created_by_user_id: user.id,
  share_type: "full_dashboard",
  refresh_interval: 60000  # Refresh every 60 seconds
})
```

## Testing

Test the implementation:

```bash
# Run all share-related tests
mix test test/tamandua_server/dashboard/share_manager_test.exs

# Test with coverage
mix test --cover
```

## Troubleshooting

### Share URL Returns 404

**Problem**: Visiting share URL shows "Page not found"

**Solution**: Check that routes are added to `router.ex` and server is restarted.

### Password Prompt Doesn't Appear

**Problem**: Password-protected share shows dashboard directly

**Solution**: Ensure `password_hash` is set in database. Check share creation:

```elixir
share = Dashboard.get_share_by_token(token)
IO.inspect(share.password_hash)  # Should not be nil
```

### Analytics Show Zero Views

**Problem**: Views aren't being recorded

**Solution**: Ensure `record_view_from_conn/3` is called in controller:

```elixir
# In DashboardShareController.show/2
Dashboard.record_view_from_conn(conn, share.id, session_id)
```

### Expired Shares Still Accessible

**Problem**: Shares work past expiry date

**Solution**: Ensure `ShareCleanupWorker` is running:

```elixir
# Check if worker is in supervision tree
Process.whereis(TamanduaServer.Workers.ShareCleanupWorker)

# Manually trigger cleanup
TamanduaServer.Workers.ShareCleanupWorker.trigger_cleanup()
```

## Next Steps

- **Read Full Documentation**: See `README.md` for advanced features
- **Explore UI**: Visit `/dashboard/shares` to manage shares visually
- **Configure GeoIP**: Add geographic tracking (see README.md)
- **Set Up Webhooks**: Get notified of share events
- **Customize Templates**: Create reusable share configurations

## Support

For questions or issues:
- Check the full documentation in `README.md`
- Review test cases in `test/tamandua_server/dashboard/`
- Open an issue on GitHub

---

**Happy Sharing! 🎉**
