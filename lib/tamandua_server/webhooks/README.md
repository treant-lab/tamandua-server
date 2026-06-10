# Webhook Management System

The webhook management system allows Tamandua EDR to send real-time notifications to external systems when important events occur.

## Features

- **CRUD Operations**: Create, read, update, and delete webhooks via LiveView UI
- **Event Filtering**: Subscribe to specific event types (alerts, agents, detections, etc.)
- **Authentication**: Support for multiple auth methods (None, Basic, Bearer, Custom Headers, HMAC)
- **Retry Logic**: Configurable retry policies with exponential or linear backoff
- **Delivery Logs**: Complete audit trail of all webhook deliveries
- **Statistics**: Success rates, delivery counts, and performance metrics
- **Testing**: Send test events to verify webhook configuration

## Supported Event Types

- `alert.created` - Triggered when a new alert is created
- `alert.updated` - Triggered when an alert is modified
- `alert.resolved` - Triggered when an alert is resolved
- `agent.connected` - Triggered when an agent connects
- `agent.disconnected` - Triggered when an agent disconnects
- `detection.triggered` - Triggered when a detection rule matches
- `response.executed` - Triggered when a response action is executed
- `system.health_changed` - Triggered when system health status changes

## Authentication Methods

### None
No authentication. Use only for testing or internal endpoints.

### Basic Auth
Standard HTTP Basic Authentication with username and password.

```elixir
%{
  auth_type: "basic",
  auth_username: "user",
  auth_password: "password"
}
```

### Bearer Token
OAuth 2.0 Bearer token authentication.

```elixir
%{
  auth_type: "bearer",
  auth_token: "your-api-token-here"
}
```

### Custom Headers
Send custom HTTP headers with each request.

```elixir
%{
  auth_type: "custom_headers",
  custom_headers: %{
    "X-API-Key" => "secret-key",
    "X-Client-ID" => "tamandua-edr"
  }
}
```

### HMAC Signature
HMAC-SHA256 signature sent in `X-Tamandua-Signature` header.

```elixir
%{
  auth_type: "hmac",
  secret: "auto-generated-or-custom-secret"
}
```

To verify the signature on your endpoint:

```python
import hmac
import hashlib

def verify_signature(payload, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
```

## Retry Policies

### Exponential Backoff
Delays increase exponentially: 60s, 120s, 240s, 480s, etc.

Formula: `2^(retry-1) * 60 seconds`

Best for: Temporary network issues, rate limiting

### Linear Backoff
Delays increase linearly: 120s, 240s, 360s, etc.

Formula: `retry * 120 seconds`

Best for: Predictable retry intervals

### Configuration

```elixir
%{
  max_retries: 3,          # 0-10 retries
  backoff_strategy: "exponential",  # or "linear"
  timeout_seconds: 10      # 1-60 seconds
}
```

## Webhook Payload Format

All webhooks receive a JSON payload with this structure:

```json
{
  "event": "alert.created",
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2026-02-20T12:00:00Z",
  "data": {
    "alert": {
      "id": "123",
      "title": "Malware Detected",
      "severity": "critical",
      "threat_score": 95.5,
      "mitre_tactics": ["TA0002"],
      "mitre_techniques": ["T1059"]
    }
  }
}
```

## Usage Examples

### Creating a Webhook (API)

```elixir
alias TamanduaServer.Webhooks

{:ok, webhook} = Webhooks.create_webhook(%{
  name: "Slack Alerts",
  url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
  description: "Send critical alerts to #security channel",
  events: ["alert.created", "alert.updated"],
  auth_type: "none",
  max_retries: 5,
  backoff_strategy: "exponential",
  timeout_seconds: 15,
  organization_id: org_id
})
```

### Dispatching Events

```elixir
alias TamanduaServer.Webhooks.Integration

# When an alert is created
Integration.dispatch_alert_created(alert)

# When an agent connects
Integration.dispatch_agent_connected(agent)

# Custom event
Webhooks.dispatch_event(
  "detection.triggered",
  event_id,
  payload,
  organization_id: org_id
)
```

### Viewing Delivery Logs

```elixir
# Get recent deliveries for a webhook
logs = Webhooks.list_delivery_logs(webhook_id, limit: 50)

# Count total deliveries
count = Webhooks.count_delivery_logs(webhook_id)

# Get webhook statistics
stats = Webhooks.get_webhook_stats(organization_id)
```

### Testing a Webhook

```elixir
# Send a test event
Webhooks.send_test_event(webhook)
```

The test event payload:

```json
{
  "event": "system.test",
  "event_id": "webhook-id",
  "timestamp": "2026-02-20T12:00:00Z",
  "data": {
    "message": "This is a test webhook from Tamandua EDR",
    "webhook_id": "550e8400-e29b-41d4-a716-446655440000",
    "webhook_name": "My Webhook"
  }
}
```

## Building a Webhook Receiver

Example Python Flask receiver:

```python
from flask import Flask, request, jsonify
import hmac
import hashlib

app = Flask(__name__)

@app.route('/webhook', methods=['POST'])
def receive_webhook():
    # Verify HMAC signature if using HMAC auth
    signature = request.headers.get('X-Tamandua-Signature')
    if signature:
        secret = "your-webhook-secret"
        payload = request.get_data()
        expected = hmac.new(
            secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected, signature):
            return jsonify({"error": "Invalid signature"}), 401

    # Process webhook payload
    data = request.json
    event_type = data['event']
    event_data = data['data']

    if event_type == 'alert.created':
        handle_alert_created(event_data['alert'])
    elif event_type == 'agent.connected':
        handle_agent_connected(event_data['agent'])

    return jsonify({"status": "received"}), 200

def handle_alert_created(alert):
    # Send to Slack, PagerDuty, etc.
    print(f"Alert: {alert['title']} ({alert['severity']})")

if __name__ == '__main__':
    app.run(port=5000)
```

## Performance Considerations

- **Async Delivery**: All webhooks are delivered asynchronously via Oban background jobs
- **Timeout**: Configure appropriate timeouts (default 10s) for your endpoints
- **Retries**: Failed deliveries are automatically retried based on your policy
- **Cleanup**: Old delivery logs (30+ days) are automatically cleaned up

## Monitoring

### Webhook Statistics

```elixir
stats = Webhooks.get_webhook_stats(organization_id)
# Returns:
# %{
#   total_webhooks: 5,
#   enabled_webhooks: 4,
#   total_deliveries: 1523,
#   successful_deliveries: 1489,
#   failed_deliveries: 34,
#   success_rate: 97.77
# }
```

### Individual Webhook Stats

Each webhook tracks:
- `total_deliveries` - Total delivery attempts
- `successful_deliveries` - Successful deliveries
- `failed_deliveries` - Failed deliveries
- `last_delivery_at` - Timestamp of last delivery
- `last_delivery_status` - "success" or "failure"

## Security Best Practices

1. **Use HTTPS**: Always use HTTPS URLs for production webhooks
2. **HMAC Signatures**: Enable HMAC authentication for sensitive data
3. **IP Whitelisting**: Configure your endpoint to only accept requests from Tamandua servers
4. **Rotate Secrets**: Periodically rotate webhook secrets
5. **Monitor Logs**: Review delivery logs for unusual patterns
6. **Rate Limiting**: Implement rate limiting on your webhook endpoints

## Troubleshooting

### Webhook Not Triggering

1. Check webhook is enabled
2. Verify event type is in webhook's events list
3. Check delivery logs for errors
4. Ensure organization_id matches

### Authentication Failures

1. Verify credentials are correct
2. Check auth_type matches your endpoint
3. For HMAC, verify signature computation
4. Review request headers in delivery logs

### Timeout Issues

1. Increase `timeout_seconds` if endpoint is slow
2. Optimize your webhook receiver
3. Check network connectivity
4. Review retry policy

## API Reference

See module documentation:
- `TamanduaServer.Webhooks` - Main context module
- `TamanduaServer.Webhooks.Webhook` - Schema
- `TamanduaServer.Webhooks.DeliveryLog` - Delivery log schema
- `TamanduaServer.Webhooks.Dispatcher` - Event dispatching
- `TamanduaServer.Webhooks.Integration` - Integration helpers
- `TamanduaServer.Workers.WebhookWorker` - Background worker
