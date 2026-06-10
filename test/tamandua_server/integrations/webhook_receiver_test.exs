defmodule TamanduaServer.Integrations.WebhookReceiverTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Integrations.{WebhookReceiver, Config, WebhookDelivery}
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Accounts.Organization

  setup do
    {:ok, org} = create_organization()
    {:ok, integration} = create_integration(org, :jira)
    {:ok, alert} = create_alert(org)

    %{org: org, integration: integration, alert: alert}
  end

  describe "process_webhook/4" do
    test "processes Jira status change webhook", %{integration: integration, alert: alert} do
      payload = %{
        "webhookEvent" => "jira:issue_updated",
        "issue" => %{
          "key" => "TEST-123",
          "fields" => %{
            "summary" => alert.title,
            "status" => %{"name" => "Done"},
            "description" => "Tamandua Alert ID: #{alert.id}"
          }
        },
        "changelog" => %{
          "items" => [
            %{"field" => "status", "fromString" => "Open", "toString" => "Done"}
          ]
        },
        "user" => %{"displayName" => "John Doe"}
      }

      {:ok, result} = WebhookReceiver.process_webhook(:jira, integration.id, payload, [])

      assert result.action == :status_updated

      # Verify alert status was updated
      updated_alert = Repo.get(Alert, alert.id)
      assert updated_alert.status == "resolved"
    end

    test "processes ServiceNow incident resolved webhook", %{integration: integration, alert: alert} do
      # Create ServiceNow integration
      {:ok, servicenow_integration} = create_integration(integration.organization_id, :servicenow)

      payload = %{
        "current" => %{
          "sys_id" => "abc123",
          "number" => "INC0001234",
          "state" => "6", # Resolved
          "short_description" => "Security Alert",
          "description" => "Tamandua Alert ID: #{alert.id}",
          "close_notes" => "Investigated and resolved"
        },
        "previous" => %{
          "state" => "2" # In Progress
        }
      }

      {:ok, result} = WebhookReceiver.process_webhook(:servicenow, servicenow_integration.id, payload, [])

      assert result.action == :status_updated

      # Verify alert was updated
      updated_alert = Repo.get(Alert, alert.id)
      assert updated_alert.status == "resolved"
    end

    test "processes PagerDuty incident acknowledged webhook", %{integration: integration, alert: alert} do
      {:ok, pagerduty_integration} = create_integration(integration.organization_id, :pagerduty)

      payload = %{
        "event" => %{
          "event_type" => "incident.acknowledged",
          "data" => %{
            "id" => "PD123",
            "incident_number" => 42,
            "status" => "acknowledged",
            "title" => "Security Alert - #{alert.id}",
            "html_url" => "https://example.pagerduty.com/incidents/PD123",
            "urgency" => "high",
            "service" => %{"summary" => "Security Monitoring"}
          }
        }
      }

      {:ok, result} = WebhookReceiver.process_webhook(:pagerduty, pagerduty_integration.id, payload, [])

      assert result.action == :status_updated

      updated_alert = Repo.get(Alert, alert.id)
      assert updated_alert.status == "investigating"
    end

    test "rejects duplicate webhooks", %{integration: integration} do
      payload = %{
        "webhookEvent" => "jira:issue_updated",
        "issue" => %{
          "key" => "TEST-123",
          "fields" => %{"summary" => "Test", "status" => %{"name" => "Done"}}
        }
      }

      # First webhook should succeed
      {:ok, _} = WebhookReceiver.process_webhook(:jira, integration.id, payload, [])

      # Second identical webhook should be rejected
      assert {:error, :duplicate_webhook} = WebhookReceiver.process_webhook(:jira, integration.id, payload, [])
    end

    test "verifies HMAC signature", %{integration: integration} do
      # Update integration with webhook secret
      {:ok, integration} = Config.update_integration(integration, %{
        config: Map.put(integration.config, "webhook_secret", "test-secret-123")
      })

      payload = %{"test" => "data"}
      raw_body = Jason.encode!(payload)

      # Compute valid signature
      signature = compute_test_signature(raw_body, "test-secret-123")

      opts = [
        raw_body: raw_body,
        headers: %{"x-signature" => signature}
      ]

      {:ok, _} = WebhookReceiver.process_webhook(:generic, integration.id, payload, opts)

      # Try with invalid signature
      opts_invalid = [
        raw_body: raw_body,
        headers: %{"x-signature" => "sha256=invalid"}
      ]

      assert {:error, :invalid_signature} = WebhookReceiver.process_webhook(:generic, integration.id, payload, opts_invalid)
    end

    test "enforces rate limiting", %{integration: integration} do
      payload = %{"test" => "data"}

      # Make many requests quickly
      results = for i <- 1..130 do
        WebhookReceiver.process_webhook(:generic, integration.id, Map.put(payload, "id", "req-#{i}"), [])
      end

      # Some should be rate limited
      rate_limited = Enum.filter(results, fn
        {:error, :rate_limited} -> true
        _ -> false
      end)

      assert length(rate_limited) > 0
    end
  end

  describe "webhook parsers" do
    test "Splunk parser extracts alert reference" do
      payload = %{
        "result" => %{
          "event_id" => "evt-123",
          "sid" => "search-456",
          "search_name" => "Malware Detection",
          "status" => "5",
          "tamandua_alert_id" => "550e8400-e29b-41d4-a716-446655440000"
        }
      }

      {:ok, parsed} = TamanduaServer.Integrations.WebhookParsers.Splunk.parse(payload, [])

      assert parsed.action_type == :alert_status_update
      assert parsed.external_id == "evt-123"
      assert parsed.alert_reference.alert_id == "550e8400-e29b-41d4-a716-446655440000"
    end

    test "Slack parser handles button interactions" do
      payload = %{
        "type" => "block_actions",
        "user" => %{"name" => "alice"},
        "channel" => %{"name" => "security-alerts"},
        "callback_id" => "alert_550e8400-e29b-41d4-a716-446655440000",
        "actions" => [
          %{"name" => "resolve_alert", "value" => "resolved", "text" => %{"text" => "Resolve"}}
        ]
      }

      {:ok, parsed} = TamanduaServer.Integrations.WebhookParsers.Slack.parse(payload, [])

      assert parsed.action_type == :interactive_response
      assert parsed.alert_reference.alert_id == "550e8400-e29b-41d4-a716-446655440000"
    end
  end

  describe "get_webhook_history/2" do
    test "returns webhook delivery history", %{integration: integration} do
      # Create some webhook deliveries
      for i <- 1..5 do
        create_webhook_delivery(integration, %{
          direction: "inbound",
          status: "delivered",
          event_type: "test-#{i}"
        })
      end

      {:ok, deliveries, total} = WebhookReceiver.get_webhook_history(integration.id, [])

      assert length(deliveries) == 5
      assert total == 5
    end

    test "filters by status", %{integration: integration} do
      create_webhook_delivery(integration, %{status: "delivered"})
      create_webhook_delivery(integration, %{status: "failed"})
      create_webhook_delivery(integration, %{status: "delivered"})

      {:ok, deliveries, _} = WebhookReceiver.get_webhook_history(integration.id, status: "delivered")

      assert length(deliveries) == 2
    end
  end

  # ============================================================================
  # Test Helpers
  # ============================================================================

  defp create_organization do
    {:ok, org} = %Organization{}
    |> Organization.changeset(%{
      name: "Test Org",
      slug: "test-org-#{:rand.uniform(10000)}"
    })
    |> Repo.insert()

    {:ok, org}
  end

  defp create_integration(org_or_org_id, type) when is_struct(org_or_org_id) do
    create_integration(org_or_org_id.id, type)
  end

  defp create_integration(org_id, type) do
    config = case type do
      :jira ->
        %{"url" => "https://example.atlassian.net", "project_key" => "TEST"}
      :servicenow ->
        %{"instance" => "example"}
      :pagerduty ->
        %{"routing_key" => "test-key"}
      :splunk ->
        %{"hec_url" => "https://example.splunk.com", "hec_token" => "test"}
      _ ->
        %{}
    end

    Config.create_integration(%{
      type: type,
      name: "Test #{type}",
      organization_id: org_id,
      config: config,
      enabled: true
    })
  end

  defp create_alert(org) do
    {:ok, alert} = %Alert{}
    |> Alert.changeset(%{
      organization_id: org.id,
      title: "Test Alert",
      description: "Test alert for webhook testing",
      severity: "high",
      status: "new"
    })
    |> Repo.insert()

    {:ok, alert}
  end

  defp create_webhook_delivery(integration, attrs) do
    default_attrs = %{
      integration_id: integration.id,
      integration_type: to_string(integration.type),
      direction: "inbound",
      status: "delivered",
      event_type: "test",
      payload_size: 100
    }

    %WebhookDelivery{}
    |> WebhookDelivery.changeset(Map.merge(default_attrs, attrs))
    |> Repo.insert!()
  end

  defp compute_test_signature(body, secret) do
    mac = :crypto.mac(:hmac, :sha256, secret, body)
    hash = Base.encode16(mac, case: :lower)
    "sha256=#{hash}"
  end
end
