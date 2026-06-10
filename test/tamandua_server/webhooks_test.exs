defmodule TamanduaServer.WebhooksTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Webhooks
  alias TamanduaServer.Webhooks.{Webhook, DeliveryLog}

  describe "list_webhooks/1" do
    test "returns all webhooks for an organization" do
      org = insert(:organization)
      webhook1 = insert(:webhook, organization: org)
      webhook2 = insert(:webhook, organization: org)
      other_org_webhook = insert(:webhook)

      webhooks = Webhooks.list_webhooks(org.id)

      assert length(webhooks) == 2
      assert Enum.any?(webhooks, &(&1.id == webhook1.id))
      assert Enum.any?(webhooks, &(&1.id == webhook2.id))
      refute Enum.any?(webhooks, &(&1.id == other_org_webhook.id))
    end

    test "returns empty list when no webhooks exist" do
      org = insert(:organization)
      assert Webhooks.list_webhooks(org.id) == []
    end
  end

  describe "get_webhook/1" do
    test "returns webhook when it exists" do
      webhook = insert(:webhook)
      assert {:ok, fetched} = Webhooks.get_webhook(webhook.id)
      assert fetched.id == webhook.id
    end

    test "returns error when webhook does not exist" do
      assert {:error, :not_found} = Webhooks.get_webhook(Ecto.UUID.generate())
    end
  end

  describe "create_webhook/1" do
    test "creates webhook with valid attributes" do
      org = insert(:organization)

      attrs = %{
        name: "Test Webhook",
        url: "https://example.com/webhook",
        events: ["alert.created", "agent.connected"],
        organization_id: org.id
      }

      assert {:ok, webhook} = Webhooks.create_webhook(attrs)
      assert webhook.name == "Test Webhook"
      assert webhook.url == "https://example.com/webhook"
      assert webhook.events == ["alert.created", "agent.connected"]
      assert webhook.enabled == true
    end

    test "returns error with invalid URL" do
      org = insert(:organization)

      attrs = %{
        name: "Invalid Webhook",
        url: "not-a-url",
        events: ["alert.created"],
        organization_id: org.id
      }

      assert {:error, changeset} = Webhooks.create_webhook(attrs)
      assert "must be a valid HTTP or HTTPS URL" in errors_on(changeset).url
    end

    test "returns error with invalid event types" do
      org = insert(:organization)

      attrs = %{
        name: "Invalid Events",
        url: "https://example.com/webhook",
        events: ["invalid.event"],
        organization_id: org.id
      }

      assert {:error, changeset} = Webhooks.create_webhook(attrs)
      assert "contains invalid event types" in Enum.join(errors_on(changeset).events)
    end

    test "validates basic auth credentials" do
      org = insert(:organization)

      attrs = %{
        name: "Basic Auth Webhook",
        url: "https://example.com/webhook",
        events: ["alert.created"],
        auth_type: "basic",
        organization_id: org.id
      }

      assert {:error, changeset} = Webhooks.create_webhook(attrs)
      assert "can't be blank" in errors_on(changeset).auth_username
    end

    test "validates bearer token" do
      org = insert(:organization)

      attrs = %{
        name: "Bearer Webhook",
        url: "https://example.com/webhook",
        events: ["alert.created"],
        auth_type: "bearer",
        organization_id: org.id
      }

      assert {:error, changeset} = Webhooks.create_webhook(attrs)
      assert "can't be blank" in errors_on(changeset).auth_token
    end

    test "generates secret for HMAC auth" do
      org = insert(:organization)

      attrs = %{
        name: "HMAC Webhook",
        url: "https://example.com/webhook",
        events: ["alert.created"],
        auth_type: "hmac",
        organization_id: org.id
      }

      assert {:ok, webhook} = Webhooks.create_webhook(attrs)
      assert webhook.secret != nil
      assert String.length(webhook.secret) > 0
    end

    test "validates max_retries range" do
      org = insert(:organization)

      attrs = %{
        name: "Webhook",
        url: "https://example.com/webhook",
        events: ["alert.created"],
        max_retries: 15,
        organization_id: org.id
      }

      assert {:error, changeset} = Webhooks.create_webhook(attrs)
      assert "must be less than or equal to 10" in errors_on(changeset).max_retries
    end
  end

  describe "update_webhook/2" do
    test "updates webhook with valid attributes" do
      webhook = insert(:webhook, name: "Old Name")

      assert {:ok, updated} = Webhooks.update_webhook(webhook, %{name: "New Name"})
      assert updated.name == "New Name"
    end

    test "returns error with invalid attributes" do
      webhook = insert(:webhook)

      assert {:error, changeset} = Webhooks.update_webhook(webhook, %{url: "invalid"})
      assert "must be a valid HTTP or HTTPS URL" in errors_on(changeset).url
    end
  end

  describe "delete_webhook/1" do
    test "deletes the webhook" do
      webhook = insert(:webhook)

      assert {:ok, _deleted} = Webhooks.delete_webhook(webhook)
      assert {:error, :not_found} = Webhooks.get_webhook(webhook.id)
    end
  end

  describe "toggle_enabled/1" do
    test "toggles webhook enabled status" do
      webhook = insert(:webhook, enabled: true)

      assert {:ok, disabled} = Webhooks.toggle_enabled(webhook)
      assert disabled.enabled == false

      assert {:ok, enabled} = Webhooks.toggle_enabled(disabled)
      assert enabled.enabled == true
    end
  end

  describe "list_delivery_logs/2" do
    test "returns delivery logs for a webhook" do
      webhook = insert(:webhook)
      log1 = insert(:delivery_log, webhook: webhook)
      log2 = insert(:delivery_log, webhook: webhook)
      other_webhook_log = insert(:delivery_log)

      logs = Webhooks.list_delivery_logs(webhook.id)

      assert length(logs) == 2
      assert Enum.any?(logs, &(&1.id == log1.id))
      assert Enum.any?(logs, &(&1.id == log2.id))
      refute Enum.any?(logs, &(&1.id == other_webhook_log.id))
    end

    test "respects limit and offset" do
      webhook = insert(:webhook)
      insert_list(10, :delivery_log, webhook: webhook)

      logs = Webhooks.list_delivery_logs(webhook.id, limit: 5, offset: 0)
      assert length(logs) == 5

      logs = Webhooks.list_delivery_logs(webhook.id, limit: 5, offset: 5)
      assert length(logs) == 5
    end
  end

  describe "count_delivery_logs/1" do
    test "counts delivery logs for a webhook" do
      webhook = insert(:webhook)
      insert_list(5, :delivery_log, webhook: webhook)

      assert Webhooks.count_delivery_logs(webhook.id) == 5
    end
  end

  describe "update_webhook_stats/2" do
    test "increments stats on success" do
      webhook = insert(:webhook, total_deliveries: 0, successful_deliveries: 0)

      assert {:ok, updated} = Webhooks.update_webhook_stats(webhook.id, success: true)
      assert updated.total_deliveries == 1
      assert updated.successful_deliveries == 1
      assert updated.failed_deliveries == 0
      assert updated.last_delivery_status == "success"
    end

    test "increments stats on failure" do
      webhook = insert(:webhook, total_deliveries: 0, failed_deliveries: 0)

      assert {:ok, updated} = Webhooks.update_webhook_stats(webhook.id, success: false)
      assert updated.total_deliveries == 1
      assert updated.successful_deliveries == 0
      assert updated.failed_deliveries == 1
      assert updated.last_delivery_status == "failure"
    end
  end

  describe "get_webhook_stats/1" do
    test "returns statistics for an organization" do
      org = insert(:organization)

      insert(:webhook,
        organization: org,
        enabled: true,
        total_deliveries: 100,
        successful_deliveries: 90,
        failed_deliveries: 10
      )

      insert(:webhook,
        organization: org,
        enabled: false,
        total_deliveries: 50,
        successful_deliveries: 40,
        failed_deliveries: 10
      )

      stats = Webhooks.get_webhook_stats(org.id)

      assert stats.total_webhooks == 2
      assert stats.enabled_webhooks == 1
      assert stats.total_deliveries == 150
      assert stats.successful_deliveries == 130
      assert stats.failed_deliveries == 20
      assert_in_delta stats.success_rate, 86.67, 0.1
    end
  end

  describe "cleanup_old_logs/1" do
    test "deletes logs older than specified days" do
      webhook = insert(:webhook)

      # Recent log
      insert(:delivery_log, webhook: webhook)

      # Old log (31 days ago)
      old_log =
        insert(:delivery_log,
          webhook: webhook,
          inserted_at: DateTime.utc_now() |> DateTime.add(-31 * 24 * 3600, :second)
        )

      assert {:ok, count} = Webhooks.cleanup_old_logs(30)
      assert count == 1

      # Old log should be deleted
      assert {:error, :not_found} = Webhooks.get_delivery_log(old_log.id)
    end
  end

  # Factory helpers
  defp insert(schema, attrs \\ %{}) do
    case schema do
      :organization ->
        %TamanduaServer.Accounts.Organization{}
        |> TamanduaServer.Accounts.Organization.changeset(
          Map.merge(%{name: "Test Org", slug: "test-org-#{:rand.uniform(10000)}"}, attrs)
        )
        |> Repo.insert!()

      :webhook ->
        org = Map.get(attrs, :organization) || insert(:organization)

        %Webhook{}
        |> Webhook.changeset(
          Map.merge(
            %{
              name: "Test Webhook",
              url: "https://example.com/webhook",
              events: ["alert.created"],
              organization_id: org.id
            },
            Map.delete(attrs, :organization)
          )
        )
        |> Repo.insert!()

      :delivery_log ->
        webhook = Map.get(attrs, :webhook) || insert(:webhook)

        %DeliveryLog{}
        |> DeliveryLog.changeset(
          Map.merge(
            %{
              webhook_id: webhook.id,
              event_type: "alert.created",
              request_url: "https://example.com/webhook",
              status: "success"
            },
            Map.delete(attrs, :webhook)
          )
        )
        |> Repo.insert!()
    end
  end

  defp insert_list(count, schema, attrs \\ %{}) do
    Enum.map(1..count, fn _ -> insert(schema, attrs) end)
  end
end
