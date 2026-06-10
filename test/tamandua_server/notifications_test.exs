defmodule TamanduaServer.NotificationsTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Notifications
  alias TamanduaServer.Notifications.Integration

  describe "integrations" do
    setup do
      org = insert(:organization)
      {:ok, organization: org}
    end

    test "list_integrations/1 returns all integrations for an organization", %{organization: org} do
      integration1 = insert(:notification_integration, organization_id: org.id, provider: "slack")
      integration2 = insert(:notification_integration, organization_id: org.id, provider: "teams")
      other_org = insert(:organization)
      _other_integration = insert(:notification_integration, organization_id: other_org.id)

      integrations = Notifications.list_integrations(org.id)

      assert length(integrations) == 2
      assert Enum.any?(integrations, &(&1.id == integration1.id))
      assert Enum.any?(integrations, &(&1.id == integration2.id))
    end

    test "create_integration/1 with valid data creates an integration", %{organization: org} do
      attrs = %{
        name: "Test Slack",
        provider: "slack",
        config: %{webhook_url: "https://hooks.slack.com/services/test"},
        organization_id: org.id
      }

      assert {:ok, %Integration{} = integration} = Notifications.create_integration(attrs)
      assert integration.name == "Test Slack"
      assert integration.provider == "slack"
      assert integration.enabled == true
    end

    test "create_integration/1 with invalid data returns error changeset", %{organization: org} do
      attrs = %{
        name: "Test",
        provider: "invalid_provider",
        organization_id: org.id
      }

      assert {:error, %Ecto.Changeset{}} = Notifications.create_integration(attrs)
    end

    test "update_integration/2 updates the integration", %{organization: org} do
      integration = insert(:notification_integration, organization_id: org.id, name: "Original")

      assert {:ok, %Integration{} = updated} = Notifications.update_integration(integration, %{name: "Updated"})
      assert updated.name == "Updated"
    end

    test "delete_integration/1 deletes the integration", %{organization: org} do
      integration = insert(:notification_integration, organization_id: org.id)

      assert {:ok, %Integration{}} = Notifications.delete_integration(integration)
      assert_raise Ecto.NoResultsError, fn ->
        Notifications.get_integration!(integration.id, org.id)
      end
    end
  end

  describe "routing" do
    setup do
      org = insert(:organization)
      agent = insert(:agent, organization_id: org.id)

      {:ok, organization: org, agent: agent}
    end

    test "route_alert/2 returns integrations matching severity filter", %{organization: org, agent: agent} do
      # Integration that accepts critical and high
      integration1 = insert(:notification_integration,
        organization_id: org.id,
        enabled: true,
        routing_rules: %{severity: ["critical", "high"]}
      )

      # Integration that accepts all
      integration2 = insert(:notification_integration,
        organization_id: org.id,
        enabled: true,
        routing_rules: %{}
      )

      # Integration that only accepts low
      _integration3 = insert(:notification_integration,
        organization_id: org.id,
        enabled: true,
        routing_rules: %{severity: ["low"]}
      )

      alert = insert(:alert, organization_id: org.id, agent_id: agent.id, severity: "critical")

      matching = Notifications.Router.route_alert(alert, org.id)

      assert length(matching) == 2
      assert Enum.any?(matching, &(&1.id == integration1.id))
      assert Enum.any?(matching, &(&1.id == integration2.id))
    end

    test "route_alert/2 excludes disabled integrations", %{organization: org, agent: agent} do
      _disabled = insert(:notification_integration,
        organization_id: org.id,
        enabled: false
      )

      alert = insert(:alert, organization_id: org.id, agent_id: agent.id)

      matching = Notifications.Router.route_alert(alert, org.id)

      assert matching == []
    end
  end

  describe "throttling" do
    test "throttled?/1 returns false when throttling is disabled" do
      integration = %{id: "test", throttle_enabled: false}

      refute Notifications.Throttler.throttled?(integration)
    end

    test "throttled?/1 returns true when limit is exceeded" do
      integration = %{id: "test-throttle", throttle_enabled: true, throttle_max_per_hour: 2}

      # Record 3 notifications
      Notifications.Throttler.record(integration.id)
      Notifications.Throttler.record(integration.id)
      Notifications.Throttler.record(integration.id)

      assert Notifications.Throttler.throttled?(integration)
    end
  end

  describe "delivery" do
    setup do
      org = insert(:organization)
      agent = insert(:agent, organization_id: org.id)
      alert = insert(:alert, organization_id: org.id, agent_id: agent.id)

      {:ok, organization: org, agent: agent, alert: alert}
    end

    test "get_delivery_stats/1 returns statistics", %{organization: org} do
      integration = insert(:notification_integration, organization_id: org.id)

      # Insert some logs
      insert(:delivery_log, integration_id: integration.id, organization_id: org.id, status: "sent")
      insert(:delivery_log, integration_id: integration.id, organization_id: org.id, status: "sent")
      insert(:delivery_log, integration_id: integration.id, organization_id: org.id, status: "failed")

      stats = Notifications.get_delivery_stats(integration.id)

      assert stats.total == 3
      assert stats.sent == 2
      assert stats.failed == 1
    end
  end
end
