defmodule TamanduaServer.UBA.AnomalyDetectorTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.UBA.{AnomalyDetector, UserAnomaly, UserBaseline}

  describe "statistical outlier detection" do
    test "detects z-score > 3 as anomaly" do
      user = insert(:user)

      # Create baseline: mean=10, stddev=2
      insert(:user_baseline,
        user_id: user.id,
        behavior_type: "file_access",
        mean: 10.0,
        stddev: 2.0,
        is_complete: true
      )

      # Create behavior with value 20 (z-score = 5)
      behavior = insert(:user_behavior,
        user_id: user.id,
        behavior_type: "file_access",
        value: 20.0
      )

      # Manually trigger check
      AnomalyDetector.check_anomalies(user.id, "file_access")

      Process.sleep(100)

      anomalies = Repo.all(from a in UserAnomaly, where: a.user_id == ^user.id)
      assert length(anomalies) > 0

      anomaly = List.first(anomalies)
      assert anomaly.anomaly_type == "statistical_outlier"
      assert anomaly.severity in ["high", "critical"]
    end
  end

  describe "location anomaly detection" do
    test "detects new location as anomaly" do
      user = insert(:user)

      # Create baseline with known locations
      insert(:user_baseline,
        user_id: user.id,
        behavior_type: "login",
        common_locations: ["192.168.1.1", "10.0.0.1"],
        is_complete: true
      )

      # Create behavior from new location
      behavior = insert(:user_behavior,
        user_id: user.id,
        behavior_type: "login",
        location: "203.0.113.1"
      )

      AnomalyDetector.check_anomalies(user.id, "login")

      Process.sleep(100)

      anomalies = Repo.all(from a in UserAnomaly,
        where: a.user_id == ^user.id,
        where: a.anomaly_type == "location_anomaly"
      )

      assert length(anomalies) > 0
    end
  end

  describe "acknowledge_anomaly/3" do
    test "acknowledges an anomaly" do
      user = insert(:user)
      analyst = insert(:user)
      anomaly = insert(:user_anomaly, user_id: user.id)

      {:ok, updated} = AnomalyDetector.acknowledge_anomaly(anomaly.id, analyst.id, "False positive")

      assert updated.is_acknowledged == true
      assert updated.acknowledged_by == analyst.id
      assert updated.notes == "False positive"
    end
  end
end
