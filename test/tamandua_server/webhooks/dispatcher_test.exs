defmodule TamanduaServer.Webhooks.DispatcherTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Webhooks.{Webhook, Dispatcher}

  describe "find_matching_webhooks/2" do
    test "finds webhooks matching event type" do
      org = insert(:organization)

      webhook1 = insert(:webhook, organization: org, events: ["alert.created", "alert.updated"])
      webhook2 = insert(:webhook, organization: org, events: ["agent.connected"])
      insert(:webhook, organization: org, events: ["detection.triggered"])

      webhooks = Dispatcher.find_matching_webhooks("alert.created", org.id)

      assert length(webhooks) == 1
      assert hd(webhooks).id == webhook1.id
    end

    test "only returns enabled webhooks" do
      org = insert(:organization)

      insert(:webhook, organization: org, events: ["alert.created"], enabled: true)
      insert(:webhook, organization: org, events: ["alert.created"], enabled: false)

      webhooks = Dispatcher.find_matching_webhooks("alert.created", org.id)

      assert length(webhooks) == 1
      assert hd(webhooks).enabled == true
    end

    test "filters by organization" do
      org1 = insert(:organization)
      org2 = insert(:organization)

      insert(:webhook, organization: org1, events: ["alert.created"])
      insert(:webhook, organization: org2, events: ["alert.created"])

      webhooks = Dispatcher.find_matching_webhooks("alert.created", org1.id)

      assert length(webhooks) == 1
      assert hd(webhooks).organization_id == org1.id
    end
  end

  describe "build_payload/3" do
    test "builds payload with event metadata" do
      event_id = Ecto.UUID.generate()
      data = %{alert: %{id: "123", severity: "high"}}

      payload = Dispatcher.build_payload("alert.created", event_id, data)

      assert payload.event == "alert.created"
      assert payload.event_id == event_id
      assert payload.data == data
      assert payload.timestamp != nil
    end
  end

  describe "compute_hmac_signature/2" do
    test "computes HMAC-SHA256 signature for map payload" do
      payload = %{event: "test", data: %{value: 123}}
      secret = "test-secret"

      signature = Dispatcher.compute_hmac_signature(payload, secret)

      assert is_binary(signature)
      assert String.length(signature) == 64 # SHA256 hex length
    end

    test "computes HMAC-SHA256 signature for string payload" do
      payload = "{\"event\":\"test\"}"
      secret = "test-secret"

      signature = Dispatcher.compute_hmac_signature(payload, secret)

      assert is_binary(signature)
      assert String.length(signature) == 64
    end

    test "produces consistent signatures" do
      payload = %{event: "test"}
      secret = "secret"

      sig1 = Dispatcher.compute_hmac_signature(payload, secret)
      sig2 = Dispatcher.compute_hmac_signature(payload, secret)

      assert sig1 == sig2
    end

    test "produces different signatures for different secrets" do
      payload = %{event: "test"}

      sig1 = Dispatcher.compute_hmac_signature(payload, "secret1")
      sig2 = Dispatcher.compute_hmac_signature(payload, "secret2")

      assert sig1 != sig2
    end
  end

  # Factory helper
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
              enabled: true,
              organization_id: org.id
            },
            Map.delete(attrs, :organization)
          )
        )
        |> Repo.insert!()
    end
  end
end
