defmodule TamanduaServer.Collaboration.PresenceTrackerTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Collaboration.PresenceTracker
  alias TamanduaServerWeb.Presence

  describe "presence_topic/2" do
    test "generates correct topic for alert" do
      assert PresenceTracker.presence_topic("alert", "123") == "alert:123:presence"
    end

    test "generates correct topic for investigation" do
      assert PresenceTracker.presence_topic("investigation", "456") == "investigation:456:presence"
    end

    test "generates correct topic for any resource type" do
      assert PresenceTracker.presence_topic("custom", "789") == "custom:789:presence"
    end
  end

  describe "record_activity/3" do
    test "records user activity on a resource" do
      user_id = Ecto.UUID.generate()

      assert :ok = PresenceTracker.record_activity(user_id, "alert", "alert-123")
    end
  end

  describe "get_viewers/2" do
    setup do
      user_id = Ecto.UUID.generate()
      alert_id = "alert-123"

      {:ok, user_id: user_id, alert_id: alert_id}
    end

    test "returns empty list when no viewers", %{alert_id: alert_id} do
      viewers = PresenceTracker.get_viewers("alert", alert_id)
      assert viewers == []
    end
  end

  describe "viewer_count/2" do
    test "returns 0 when no viewers" do
      count = PresenceTracker.viewer_count("alert", "alert-123")
      assert count == 0
    end
  end

  describe "broadcast_presence_change/4" do
    test "broadcasts presence event to topic" do
      user_meta = %{
        user_id: Ecto.UUID.generate(),
        name: "Test User",
        status: "online"
      }

      topic = PresenceTracker.presence_topic("alert", "alert-123")
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, topic)

      PresenceTracker.broadcast_presence_change("alert", "alert-123", :joined, user_meta)

      assert_receive {:presence_event, :joined, ^user_meta}
    end
  end
end
