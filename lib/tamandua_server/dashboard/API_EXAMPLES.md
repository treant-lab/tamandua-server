# Dashboard Sharing API Examples

REST API examples for programmatic dashboard share management.

## Authentication

All API requests require authentication with a valid API key or JWT token:

```bash
# Set your API key
export API_KEY="your-api-key-here"
export BASE_URL="https://tamandua.example.com"
```

## List All Shares

```bash
curl -X GET "${BASE_URL}/api/v1/dashboard_shares" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json"
```

Response:
```json
{
  "data": [
    {
      "id": "share-uuid-1",
      "dashboard_layout_id": "layout-uuid",
      "share_token": "token-uuid",
      "share_type": "full_dashboard",
      "custom_title": "Q4 Security Dashboard",
      "is_active": true,
      "expires_at": "2026-03-01T00:00:00Z",
      "revoked_at": null,
      "last_accessed_at": "2026-02-26T10:30:00Z",
      "status": "active",
      "inserted_at": "2026-02-20T12:00:00Z",
      "updated_at": "2026-02-26T10:30:00Z"
    }
  ]
}
```

## Create a Share

### Basic Share

```bash
curl -X POST "${BASE_URL}/api/v1/dashboard_shares" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "share": {
      "dashboard_layout_id": "layout-uuid",
      "share_type": "full_dashboard"
    }
  }'
```

### Share with Password Protection

```bash
curl -X POST "${BASE_URL}/api/v1/dashboard_shares" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "share": {
      "dashboard_layout_id": "layout-uuid",
      "share_type": "full_dashboard",
      "password": "secret123",
      "expiry_preset": "7_days"
    }
  }'
```

### Share with IP Restrictions

```bash
curl -X POST "${BASE_URL}/api/v1/dashboard_shares" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "share": {
      "dashboard_layout_id": "layout-uuid",
      "share_type": "full_dashboard",
      "allowed_ips": ["192.168.1.1", "10.0.0.0/24"],
      "expiry_preset": "30_days"
    }
  }'
```

### Share Specific Widgets

```bash
curl -X POST "${BASE_URL}/api/v1/dashboard_shares" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "share": {
      "dashboard_layout_id": "layout-uuid",
      "share_type": "specific_widgets",
      "widget_ids": ["widget-1-uuid", "widget-2-uuid"]
    }
  }'
```

### Fully Customized Share

```bash
curl -X POST "${BASE_URL}/api/v1/dashboard_shares" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "share": {
      "dashboard_layout_id": "layout-uuid",
      "share_type": "full_dashboard",
      "custom_title": "Q4 Security Overview",
      "password": "secure-password",
      "expiry_preset": "30_days",
      "allowed_ips": ["192.168.1.0/24"],
      "allowed_domains": ["example.com", "*.trusted.com"],
      "show_header": true,
      "show_footer": true,
      "show_watermark": false,
      "branding_config": {
        "logo_url": "https://cdn.example.com/logo.png",
        "company_name": "ACME Security",
        "support_url": "https://support.example.com"
      },
      "refresh_interval": 60000,
      "embed_width": "100%",
      "embed_height": "800px",
      "transparent_background": false,
      "description": "Shared with external partners"
    }
  }'
```

Response:
```json
{
  "data": {
    "id": "share-uuid",
    "dashboard_layout_id": "layout-uuid",
    "dashboard_layout": {
      "id": "layout-uuid",
      "name": "Security Dashboard",
      "description": "Main security dashboard"
    },
    "share_token": "generated-token-uuid",
    "share_type": "full_dashboard",
    "custom_title": "Q4 Security Overview",
    "is_active": true,
    "password_protected": true,
    "expires_at": "2026-03-26T00:00:00Z",
    "status": "active",
    "share_url": "https://tamandua.example.com/shared/dashboard/generated-token-uuid",
    "embed_code": "<iframe src='https://tamandua.example.com/shared/dashboard/generated-token-uuid' width='100%' height='800px' frameborder='0' allowfullscreen></iframe>",
    "inserted_at": "2026-02-26T12:00:00Z",
    "updated_at": "2026-02-26T12:00:00Z"
  }
}
```

## Get Share Details

```bash
curl -X GET "${BASE_URL}/api/v1/dashboard_shares/share-uuid" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json"
```

## Update a Share

```bash
curl -X PUT "${BASE_URL}/api/v1/dashboard_shares/share-uuid" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "share": {
      "custom_title": "Updated Title",
      "expiry_preset": "never",
      "show_watermark": false
    }
  }'
```

## Revoke a Share

```bash
curl -X POST "${BASE_URL}/api/v1/dashboard_shares/share-uuid/revoke" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json"
```

## Activate a Share

```bash
curl -X POST "${BASE_URL}/api/v1/dashboard_shares/share-uuid/activate" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json"
```

## Regenerate Share Token

Creates a new share URL (invalidates the old one):

```bash
curl -X POST "${BASE_URL}/api/v1/dashboard_shares/share-uuid/regenerate_token" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json"
```

## Delete a Share

```bash
curl -X DELETE "${BASE_URL}/api/v1/dashboard_shares/share-uuid" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json"
```

Response: `204 No Content`

## Get Share Analytics

### Last 30 Days (default)

```bash
curl -X GET "${BASE_URL}/api/v1/dashboard_shares/share-uuid/analytics" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json"
```

### Custom Time Range

```bash
curl -X GET "${BASE_URL}/api/v1/dashboard_shares/share-uuid/analytics?time_range=last_7_days" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json"
```

Available time ranges:
- `last_7_days`
- `last_30_days`
- `last_90_days`
- `all_time`

Response:
```json
{
  "data": {
    "total_views": 156,
    "unique_visitors": 89,
    "avg_duration_seconds": 127.5,
    "views_by_date": [
      {
        "date": "2026-02-01",
        "count": 12
      },
      {
        "date": "2026-02-02",
        "count": 15
      }
    ],
    "top_referrers": [
      {
        "referrer": "https://google.com",
        "count": 45
      },
      {
        "referrer": "https://twitter.com",
        "count": 23
      }
    ],
    "top_countries": [
      {
        "country": "US",
        "count": 67
      },
      {
        "country": "UK",
        "count": 34
      }
    ]
  }
}
```

## Get User Analytics

Aggregate analytics across all user shares:

```bash
curl -X GET "${BASE_URL}/api/v1/dashboard_shares/analytics/user?time_range=last_30_days" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json"
```

Response:
```json
{
  "data": {
    "total_shares": 5,
    "total_views": 234,
    "unique_visitors": 156,
    "shares": [
      {
        "id": "share-1-uuid",
        "dashboard_layout_id": "layout-uuid",
        "share_token": "token-1",
        "share_type": "full_dashboard",
        "custom_title": "Dashboard 1",
        "is_active": true,
        "view_count": 89,
        "status": "active"
      },
      {
        "id": "share-2-uuid",
        "dashboard_layout_id": "layout-uuid",
        "share_token": "token-2",
        "share_type": "full_dashboard",
        "custom_title": "Dashboard 2",
        "is_active": true,
        "view_count": 67,
        "status": "active"
      }
    ]
  }
}
```

## Batch Operations

### Create Multiple Shares

```bash
#!/bin/bash

DASHBOARD_IDS=("layout-1-uuid" "layout-2-uuid" "layout-3-uuid")

for DASHBOARD_ID in "${DASHBOARD_IDS[@]}"; do
  curl -X POST "${BASE_URL}/api/v1/dashboard_shares" \
    -H "Authorization: Bearer ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d "{
      \"share\": {
        \"dashboard_layout_id\": \"${DASHBOARD_ID}\",
        \"share_type\": \"full_dashboard\",
        \"expiry_preset\": \"30_days\"
      }
    }"
done
```

### Revoke All Shares for a Dashboard

```bash
#!/bin/bash

DASHBOARD_ID="layout-uuid"

# Get all shares for dashboard
SHARES=$(curl -s -X GET "${BASE_URL}/api/v1/dashboard_shares" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" | jq -r ".data[] | select(.dashboard_layout_id == \"${DASHBOARD_ID}\") | .id")

# Revoke each share
for SHARE_ID in $SHARES; do
  curl -X POST "${BASE_URL}/api/v1/dashboard_shares/${SHARE_ID}/revoke" \
    -H "Authorization: Bearer ${API_KEY}" \
    -H "Content-Type: application/json"
done
```

## Error Responses

### 400 Bad Request

```json
{
  "errors": {
    "share_type": ["can't be blank"],
    "widget_ids": ["must specify at least one widget when share_type is specific_widgets"]
  }
}
```

### 401 Unauthorized

```json
{
  "error": "Unauthorized",
  "message": "Invalid or missing authentication token"
}
```

### 403 Forbidden

```json
{
  "error": "Forbidden",
  "message": "You don't have permission to access this resource"
}
```

### 404 Not Found

```json
{
  "error": "Not Found",
  "message": "Share not found"
}
```

## SDK Examples

### Python

```python
import requests
import json

class TamanduaShareClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

    def create_share(self, dashboard_layout_id, **kwargs):
        """Create a new dashboard share."""
        payload = {
            "share": {
                "dashboard_layout_id": dashboard_layout_id,
                "share_type": kwargs.get("share_type", "full_dashboard"),
                **kwargs
            }
        }

        response = requests.post(
            f"{self.base_url}/api/v1/dashboard_shares",
            headers=self.headers,
            json=payload
        )
        response.raise_for_status()
        return response.json()["data"]

    def list_shares(self):
        """List all shares."""
        response = requests.get(
            f"{self.base_url}/api/v1/dashboard_shares",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()["data"]

    def get_analytics(self, share_id, time_range="last_30_days"):
        """Get analytics for a share."""
        response = requests.get(
            f"{self.base_url}/api/v1/dashboard_shares/{share_id}/analytics",
            headers=self.headers,
            params={"time_range": time_range}
        )
        response.raise_for_status()
        return response.json()["data"]

    def revoke_share(self, share_id):
        """Revoke a share."""
        response = requests.post(
            f"{self.base_url}/api/v1/dashboard_shares/{share_id}/revoke",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()["data"]

# Usage
client = TamanduaShareClient(
    base_url="https://tamandua.example.com",
    api_key="your-api-key"
)

# Create a share
share = client.create_share(
    dashboard_layout_id="layout-uuid",
    custom_title="API Created Share",
    password="secret123",
    expiry_preset="7_days"
)

print(f"Share URL: {share['share_url']}")

# Get analytics
analytics = client.get_analytics(share["id"])
print(f"Total views: {analytics['total_views']}")
```

### JavaScript/Node.js

```javascript
const axios = require('axios');

class TamanduaShareClient {
  constructor(baseUrl, apiKey) {
    this.client = axios.create({
      baseURL: `${baseUrl}/api/v1`,
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      }
    });
  }

  async createShare(dashboardLayoutId, options = {}) {
    const response = await this.client.post('/dashboard_shares', {
      share: {
        dashboard_layout_id: dashboardLayoutId,
        share_type: options.share_type || 'full_dashboard',
        ...options
      }
    });
    return response.data.data;
  }

  async listShares() {
    const response = await this.client.get('/dashboard_shares');
    return response.data.data;
  }

  async getAnalytics(shareId, timeRange = 'last_30_days') {
    const response = await this.client.get(
      `/dashboard_shares/${shareId}/analytics`,
      { params: { time_range: timeRange } }
    );
    return response.data.data;
  }

  async revokeShare(shareId) {
    const response = await this.client.post(
      `/dashboard_shares/${shareId}/revoke`
    );
    return response.data.data;
  }
}

// Usage
const client = new TamanduaShareClient(
  'https://tamandua.example.com',
  'your-api-key'
);

(async () => {
  // Create a share
  const share = await client.createShare('layout-uuid', {
    custom_title: 'API Created Share',
    password: 'secret123',
    expiry_preset: '7_days'
  });

  console.log(`Share URL: ${share.share_url}`);

  // Get analytics
  const analytics = await client.getAnalytics(share.id);
  console.log(`Total views: ${analytics.total_views}`);
})();
```

## Webhooks

Configure webhooks to receive notifications for share events (future feature):

```bash
curl -X POST "${BASE_URL}/api/v1/webhooks" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "webhook": {
      "url": "https://your-app.com/webhooks/tamandua",
      "events": ["share.viewed", "share.expired", "share.revoked"],
      "secret": "webhook-secret"
    }
  }'
```

Webhook payload example:
```json
{
  "event": "share.viewed",
  "timestamp": "2026-02-26T12:00:00Z",
  "data": {
    "share_id": "share-uuid",
    "dashboard_layout_id": "layout-uuid",
    "viewer_ip": "192.168.1.1",
    "referrer": "https://google.com"
  }
}
```

## Rate Limits

API endpoints are rate limited:
- **Anonymous**: 10 requests/minute
- **Authenticated**: 100 requests/minute
- **Premium**: 1000 requests/minute

Rate limit headers:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1709038800
```

## Best Practices

1. **Store share tokens securely**: Never expose share tokens in public repositories
2. **Use password protection**: For sensitive dashboards
3. **Set expiry dates**: Don't create shares that never expire
4. **Monitor analytics**: Track who's viewing your dashboards
5. **Revoke compromised shares**: Use regenerate_token if a URL is leaked
6. **Use IP restrictions**: Limit access to known IP ranges
7. **Implement retry logic**: Handle rate limits gracefully
8. **Cache responses**: Don't fetch analytics on every request

## Support

For API issues or questions:
- Documentation: https://docs.treantlab.org/api
- Support: contato@treantlab.org
- GitHub: https://github.com/treant-lab/tamandua-server
