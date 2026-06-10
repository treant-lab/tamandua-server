defmodule TamanduaServer.UBA.BehaviorTrackerTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.UBA.{BehaviorTracker, UserBehavior}
  alias TamanduaServer.Repo

  describe "track_behavior/3" do
    test "tracks a behavior event" do
      user = insert(:user)

      BehaviorTracker.track_behavior(user.id, "login", %{
        location: "192.168.1.1",
        device: "Windows"
      })

      # Give async task time to complete
      Process.sleep(100)

      behaviors = Repo.all(from b in UserBehavior, where: b.user_id == ^user.id)
      assert length(behaviors) == 1

      behavior = List.first(behaviors)
      assert behavior.behavior_type == "login"
      assert behavior.location == "192.168.1.1"
      assert behavior.device == "Windows"
    end
  end

  describe "track_login/4" do
    test "tracks login with device extraction" do
      user = insert(:user)

      BehaviorTracker.track_login(
        user.id,
        "203.0.113.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        %{}
      )

      Process.sleep(100)

      behaviors = Repo.all(from b in UserBehavior, where: b.user_id == ^user.id)
      behavior = List.first(behaviors)

      assert behavior.behavior_type == "login"
      assert behavior.location == "203.0.113.1"
      assert behavior.device == "Windows"
    end
  end

  describe "track_data_transfer/4" do
    test "tracks data transfer with MB conversion" do
      user = insert(:user)

      BehaviorTracker.track_data_transfer(user.id, "download", 5_000_000, %{})

      Process.sleep(100)

      behaviors = Repo.all(from b in UserBehavior, where: b.user_id == ^user.id)
      behavior = List.first(behaviors)

      assert behavior.behavior_type == "data_download"
      assert behavior.value == 5.0  # 5MB
    end
  end

  describe "get_behavior_stats/3" do
    test "calculates behavior statistics" do
      user = insert(:user)

      # Insert multiple behaviors
      for i <- 1..10 do
        insert(:user_behavior, user_id: user.id, behavior_type: "file_access", value: i * 1.0)
      end

      stats = BehaviorTracker.get_behavior_stats(user.id, "file_access", 30)

      assert stats.count == 10
      assert stats.avg == 5.5
      assert stats.min == 1.0
      assert stats.max == 10.0
    end
  end

  describe "get_user_locations/2" do
    test "returns unique locations" do
      user = insert(:user)

      insert(:user_behavior, user_id: user.id, location: "192.168.1.1")
      insert(:user_behavior, user_id: user.id, location: "192.168.1.1")
      insert(:user_behavior, user_id: user.id, location: "10.0.0.1")

      locations = BehaviorTracker.get_user_locations(user.id, 30)

      assert length(locations) == 2
      assert "192.168.1.1" in locations
      assert "10.0.0.1" in locations
    end
  end
end
