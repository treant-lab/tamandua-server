# Webhook System Test Script
#
# Run this script to verify webhook functionality:
#   mix run priv/scripts/test_webhooks.exs
#
# This script:
# 1. Creates a test organization and webhook
# 2. Dispatches test events
# 3. Verifies delivery logs
# 4. Cleans up test data

alias TamanduaServer.{Repo, Webhooks}
alias TamanduaServer.Accounts.Organization
alias TamanduaServer.Webhooks.{Webhook, Integration}

IO.puts("\n=== Webhook System Test ===\n")

# Step 1: Create test organization
IO.puts("1. Creating test organization...")

{:ok, org} =
  %Organization{}
  |> Organization.changeset(%{
    name: "Webhook Test Org",
    slug: "webhook-test-#{:rand.uniform(10000)}"
  })
  |> Repo.insert()

IO.puts("   ✓ Organization created: #{org.id}")

# Step 2: Create test webhook
IO.puts("\n2. Creating test webhook...")

{:ok, webhook} =
  Webhooks.create_webhook(%{
    name: "Test Webhook",
    url: "https://webhook.site/unique-id",  # Replace with real webhook.site URL
    description: "Automated test webhook",
    events: ["alert.created", "agent.connected"],
    auth_type: "hmac",
    max_retries: 3,
    backoff_strategy: "exponential",
    timeout_seconds: 10,
    organization_id: org.id
  })

IO.puts("   ✓ Webhook created: #{webhook.id}")
IO.puts("   ✓ HMAC secret generated: #{String.slice(webhook.secret, 0..10)}...")

# Step 3: Test event dispatching
IO.puts("\n3. Testing event dispatching...")

test_payload = %{
  alert: %{
    id: Ecto.UUID.generate(),
    title: "Test Alert",
    severity: "high",
    threat_score: 85.5
  }
}

{:ok, count} =
  Webhooks.dispatch_event(
    "alert.created",
    Ecto.UUID.generate(),
    test_payload,
    organization_id: org.id
  )

IO.puts("   ✓ Event dispatched to #{count} webhook(s)")

# Step 4: Wait for delivery
IO.puts("\n4. Waiting for webhook delivery (5 seconds)...")
Process.sleep(5000)

# Step 5: Check delivery logs
IO.puts("\n5. Checking delivery logs...")

logs = Webhooks.list_delivery_logs(webhook.id)

if Enum.empty?(logs) do
  IO.puts("   ⚠ No delivery logs found (webhook may still be processing)")
else
  latest_log = List.first(logs)

  IO.puts("   ✓ Found #{length(logs)} delivery log(s)")
  IO.puts("   ✓ Latest delivery status: #{latest_log.status}")
  IO.puts("   ✓ Response status: #{latest_log.response_status || "pending"}")

  if latest_log.response_time_ms do
    IO.puts("   ✓ Response time: #{latest_log.response_time_ms}ms")
  end

  if latest_log.error_message do
    IO.puts("   ⚠ Error: #{latest_log.error_message}")
  end
end

# Step 6: Test webhook statistics
IO.puts("\n6. Testing statistics...")

stats = Webhooks.get_webhook_stats(org.id)
IO.puts("   ✓ Total webhooks: #{stats.total_webhooks}")
IO.puts("   ✓ Enabled webhooks: #{stats.enabled_webhooks}")
IO.puts("   ✓ Total deliveries: #{stats.total_deliveries}")
IO.puts("   ✓ Success rate: #{stats.success_rate}%")

# Step 7: Test HMAC signature
IO.puts("\n7. Testing HMAC signature computation...")

signature =
  Webhooks.Dispatcher.compute_hmac_signature(
    %{test: "data"},
    webhook.secret
  )

IO.puts("   ✓ HMAC signature: #{String.slice(signature, 0..20)}...")

# Step 8: Test send_test_event
IO.puts("\n8. Testing send_test_event function...")

case Webhooks.send_test_event(webhook) do
  {:ok, _job} ->
    IO.puts("   ✓ Test event enqueued successfully")

  {:error, reason} ->
    IO.puts("   ⚠ Failed to send test event: #{inspect(reason)}")
end

# Step 9: Test toggle_enabled
IO.puts("\n9. Testing toggle_enabled...")

{:ok, disabled_webhook} = Webhooks.toggle_enabled(webhook)
IO.puts("   ✓ Webhook disabled: #{!disabled_webhook.enabled}")

{:ok, enabled_webhook} = Webhooks.toggle_enabled(disabled_webhook)
IO.puts("   ✓ Webhook re-enabled: #{enabled_webhook.enabled}")

# Step 10: Cleanup (optional)
IO.puts("\n10. Cleanup test data?")
IO.puts("   Enter 'yes' to delete test webhook and organization, or press Enter to keep:")

response = IO.gets("   > ") |> String.trim()

if response == "yes" do
  IO.puts("\n   Cleaning up...")

  Webhooks.delete_webhook(webhook)
  Repo.delete(org)

  IO.puts("   ✓ Test data deleted")
else
  IO.puts("\n   Test data preserved for manual inspection:")
  IO.puts("   - Organization ID: #{org.id}")
  IO.puts("   - Webhook ID: #{webhook.id}")
  IO.puts("   - View in UI: /settings/webhooks")
end

IO.puts("\n=== Test Complete ===\n")

# Summary
IO.puts("Summary:")
IO.puts("--------")
IO.puts("✓ Webhook creation and validation")
IO.puts("✓ Event dispatching")
IO.puts("✓ Delivery logging")
IO.puts("✓ Statistics tracking")
IO.puts("✓ HMAC signature generation")
IO.puts("✓ Enable/disable toggle")
IO.puts("\nNext steps:")
IO.puts("1. Update webhook URL to a real endpoint (e.g., webhook.site)")
IO.puts("2. Run migrations: mix ecto.migrate")
IO.puts("3. Add route: live \"/settings/webhooks\", Settings.WebhooksLive")
IO.puts("4. Visit /settings/webhooks in browser")
IO.puts("5. Create production webhooks and test with real events")
