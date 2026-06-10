defmodule TamanduaServer.Agents.HealthAnalyzerTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.Agents.{HealthMetrics, HealthAnalyzer}
  alias TamanduaServer.Repo

  describe "analyze_metrics/1" do
    setup do
      agent = insert(:agent)

      # Insert normal baseline metrics
      base_time = DateTime.utc_now() |> DateTime.add(-3600, :second)

      for i <- 0..50 do
        timestamp = DateTime.add(base_time, i * 60, :second)

        %HealthMetrics{}
        |> HealthMetrics.changeset(%{
          agent_id: agent.id,
          timestamp: timestamp,
          cpu_usage: 50.0 + :rand.uniform(10) - 5,
          memory_usage: 60.0 + :rand.uniform(10) - 5,
          disk_usage: 70.0 + :rand.uniform(5) - 2.5,
          network_rx_bytes_per_sec: 1000 + :rand.uniform(500),
          events_per_sec: 100.0,
          events_processed: 6000,
          events_queued: 50,
          events_dropped: 0,
          error_count: 2,
          errors_per_min: 0.1,
          health_score: 95,
          uptime_seconds: i * 60
        })
        |> Repo.insert!()
      end

      %{agent: agent}
    end

    test "detects CPU spike anomalies", %{agent: agent} do
      # Insert anomalous CPU spike
      %HealthMetrics{}
      |> HealthMetrics.changeset(%{
        agent_id: agent.id,
        timestamp: DateTime.utc_now(),
        cpu_usage: 98.0,  # Spike
        memory_usage: 60.0,
        disk_usage: 70.0,
        events_per_sec: 100.0,
        events_processed: 6000,
        error_count: 2,
        health_score: 60
      })
      |> Repo.insert!()

      anomalies = HealthAnalyzer.analyze_metrics(agent.id)

      assert Enum.any?(anomalies, fn a -> a.type == :cpu_spike end)
    end

    test "detects memory spike anomalies", %{agent: agent} do
      # Insert anomalous memory spike
      %HealthMetrics{}
      |> HealthMetrics.changeset(%{
        agent_id: agent.id,
        timestamp: DateTime.utc_now(),
        cpu_usage: 50.0,
        memory_usage: 95.0,  # Spike
        disk_usage: 70.0,
        events_per_sec: 100.0,
        events_processed: 6000,
        error_count: 2,
        health_score: 60
      })
      |> Repo.insert!()

      anomalies = HealthAnalyzer.analyze_metrics(agent.id)

      assert Enum.any?(anomalies, fn a -> a.type == :memory_spike end)
    end

    test "detects events dropped", %{agent: agent} do
      # Insert metrics with dropped events
      %HealthMetrics{}
      |> HealthMetrics.changeset(%{
        agent_id: agent.id,
        timestamp: DateTime.utc_now(),
        cpu_usage: 50.0,
        memory_usage: 60.0,
        disk_usage: 70.0,
        events_per_sec: 100.0,
        events_processed: 6000,
        events_queued: 500,
        events_dropped: 150,  # Dropping events
        error_count: 2,
        health_score: 50
      })
      |> Repo.insert!()

      anomalies = HealthAnalyzer.analyze_metrics(agent.id)

      assert Enum.any?(anomalies, fn a -> a.type == :events_dropped end)
    end

    test "detects high error rate", %{agent: agent} do
      # Insert metrics with high error count
      %HealthMetrics{}
      |> HealthMetrics.changeset(%{
        agent_id: agent.id,
        timestamp: DateTime.utc_now(),
        cpu_usage: 50.0,
        memory_usage: 60.0,
        disk_usage: 70.0,
        events_per_sec: 100.0,
        events_processed: 6000,
        error_count: 100,  # High error count
        errors_per_min: 5.0,
        health_score: 60
      })
      |> Repo.insert!()

      anomalies = HealthAnalyzer.analyze_metrics(agent.id)

      assert Enum.any?(anomalies, fn a -> a.type == :high_error_rate end)
    end

    test "returns empty list with insufficient data" do
      new_agent = insert(:agent)

      # Only insert 5 metrics (< 10 required)
      for i <- 1..5 do
        %HealthMetrics{}
        |> HealthMetrics.changeset(%{
          agent_id: new_agent.id,
          timestamp: DateTime.utc_now() |> DateTime.add(-i * 60, :second),
          cpu_usage: 50.0,
          memory_usage: 60.0,
          health_score: 90
        })
        |> Repo.insert!()
      end

      anomalies = HealthAnalyzer.analyze_metrics(new_agent.id)

      assert anomalies == []
    end
  end

  describe "detect_memory_leak/1" do
    setup do
      agent = insert(:agent)
      %{agent: agent}
    end

    test "detects memory leak with sustained growth", %{agent: agent} do
      # Insert metrics showing sustained memory growth
      base_time = DateTime.utc_now() |> DateTime.add(-3600, :second)

      for i <- 0..60 do
        timestamp = DateTime.add(base_time, i * 60, :second)

        # Memory growing at 10 MB/min (exceeds threshold of 5 MB/min)
        memory_used = 1_000_000_000 + (i * 10 * 1024 * 1024)

        %HealthMetrics{}
        |> HealthMetrics.changeset(%{
          agent_id: agent.id,
          timestamp: timestamp,
          cpu_usage: 50.0,
          memory_usage: 60.0,
          memory_total: 16_000_000_000,
          memory_used: memory_used,
          health_score: 80
        })
        |> Repo.insert!()
      end

      result = HealthAnalyzer.detect_memory_leak(agent.id)

      assert result != nil
      assert result.type == :memory_leak
      assert result.severity == :critical
      assert result.growth_rate_mb_per_min > 5.0
    end

    test "does not detect leak with stable memory", %{agent: agent} do
      # Insert metrics with stable memory usage
      base_time = DateTime.utc_now() |> DateTime.add(-3600, :second)

      for i <- 0..60 do
        timestamp = DateTime.add(base_time, i * 60, :second)

        # Stable memory with minor fluctuations
        memory_used = 1_000_000_000 + :rand.uniform(10_000_000) - 5_000_000

        %HealthMetrics{}
        |> HealthMetrics.changeset(%{
          agent_id: agent.id,
          timestamp: timestamp,
          cpu_usage: 50.0,
          memory_usage: 60.0,
          memory_total: 16_000_000_000,
          memory_used: memory_used,
          health_score: 90
        })
        |> Repo.insert!()
      end

      result = HealthAnalyzer.detect_memory_leak(agent.id)

      assert result == nil
    end

    test "returns nil with insufficient data", %{agent: agent} do
      # Only 5 data points
      base_time = DateTime.utc_now() |> DateTime.add(-300, :second)

      for i <- 0..4 do
        timestamp = DateTime.add(base_time, i * 60, :second)

        %HealthMetrics{}
        |> HealthMetrics.changeset(%{
          agent_id: agent.id,
          timestamp: timestamp,
          memory_used: 1_000_000_000
        })
        |> Repo.insert!()
      end

      result = HealthAnalyzer.detect_memory_leak(agent.id)

      assert result == nil
    end
  end

  describe "calculate_health_trend/2" do
    setup do
      agent = insert(:agent)
      %{agent: agent}
    end

    test "detects improving trend", %{agent: agent} do
      base_time = DateTime.utc_now() |> DateTime.add(-3600, :second)

      # Health score improving over time
      for i <- 0..20 do
        timestamp = DateTime.add(base_time, i * 180, :second)
        health_score = 50 + i * 2  # Increasing

        %HealthMetrics{}
        |> HealthMetrics.changeset(%{
          agent_id: agent.id,
          timestamp: timestamp,
          health_score: min(health_score, 100)
        })
        |> Repo.insert!()
      end

      trend = HealthAnalyzer.calculate_health_trend(agent.id, 60)

      assert trend == :improving
    end

    test "detects degrading trend", %{agent: agent} do
      base_time = DateTime.utc_now() |> DateTime.add(-3600, :second)

      # Health score degrading over time
      for i <- 0..20 do
        timestamp = DateTime.add(base_time, i * 180, :second)
        health_score = 90 - i * 2  # Decreasing

        %HealthMetrics{}
        |> HealthMetrics.changeset(%{
          agent_id: agent.id,
          timestamp: timestamp,
          health_score: max(health_score, 0)
        })
        |> Repo.insert!()
      end

      trend = HealthAnalyzer.calculate_health_trend(agent.id, 60)

      assert trend == :degrading
    end

    test "detects stable trend", %{agent: agent} do
      base_time = DateTime.utc_now() |> DateTime.add(-3600, :second)

      # Stable health score
      for i <- 0..20 do
        timestamp = DateTime.add(base_time, i * 180, :second)
        health_score = 85 + :rand.uniform(5) - 2.5  # Minor fluctuations

        %HealthMetrics{}
        |> HealthMetrics.changeset(%{
          agent_id: agent.id,
          timestamp: timestamp,
          health_score: health_score
        })
        |> Repo.insert!()
      end

      trend = HealthAnalyzer.calculate_health_trend(agent.id, 60)

      assert trend == :stable
    end

    test "returns insufficient_data with too few samples", %{agent: agent} do
      # Only 3 data points
      for i <- 0..2 do
        timestamp = DateTime.utc_now() |> DateTime.add(-i * 300, :second)

        %HealthMetrics{}
        |> HealthMetrics.changeset(%{
          agent_id: agent.id,
          timestamp: timestamp,
          health_score: 90
        })
        |> Repo.insert!()
      end

      trend = HealthAnalyzer.calculate_health_trend(agent.id, 60)

      assert trend == :insufficient_data
    end
  end

  describe "compare_to_fleet/1" do
    setup do
      org = insert(:organization)
      agent1 = insert(:agent, organization_id: org.id)
      agent2 = insert(:agent, organization_id: org.id)
      agent3 = insert(:agent, organization_id: org.id)

      # Insert normal metrics for fleet
      base_time = DateTime.utc_now() |> DateTime.add(-3600, :second)

      for agent <- [agent2, agent3] do
        for i <- 0..10 do
          timestamp = DateTime.add(base_time, i * 360, :second)

          %HealthMetrics{}
          |> HealthMetrics.changeset(%{
            agent_id: agent.id,
            timestamp: timestamp,
            cpu_usage: 50.0 + :rand.uniform(10) - 5,
            memory_usage: 60.0 + :rand.uniform(10) - 5,
            health_score: 90
          })
          |> Repo.insert!()
        end
      end

      # Insert anomalous metrics for agent1
      for i <- 0..10 do
        timestamp = DateTime.add(base_time, i * 360, :second)

        %HealthMetrics{}
        |> HealthMetrics.changeset(%{
          agent_id: agent1.id,
          timestamp: timestamp,
          cpu_usage: 90.0,  # Much higher than fleet
          memory_usage: 95.0,  # Much higher than fleet
          health_score: 40  # Much lower than fleet
        })
        |> Repo.insert!()
      end

      %{agent1: agent1, agent2: agent2, agent3: agent3}
    end

    test "detects CPU deviation from fleet", %{agent1: agent1} do
      anomalies = HealthAnalyzer.compare_to_fleet(agent1.id)

      assert Enum.any?(anomalies, fn a -> a.type == :cpu_deviation end)
    end

    test "detects memory deviation from fleet", %{agent1: agent1} do
      anomalies = HealthAnalyzer.compare_to_fleet(agent1.id)

      assert Enum.any?(anomalies, fn a -> a.type == :memory_deviation end)
    end

    test "detects health score deviation from fleet", %{agent1: agent1} do
      anomalies = HealthAnalyzer.compare_to_fleet(agent1.id)

      assert Enum.any?(anomalies, fn a -> a.type == :health_score_deviation end)

      health_anomaly = Enum.find(anomalies, fn a -> a.type == :health_score_deviation end)
      assert health_anomaly.severity == :critical
    end

    test "returns empty list for normal agent", %{agent2: agent2} do
      anomalies = HealthAnalyzer.compare_to_fleet(agent2.id)

      # Should be empty or have minimal deviations
      assert length(anomalies) == 0
    end
  end

  # Test helper
  defp insert(schema, attrs \\ %{}) do
    case schema do
      :agent ->
        org = insert(:organization)

        %TamanduaServer.Agents.Agent{}
        |> TamanduaServer.Agents.Agent.changeset(
          Map.merge(
            %{
              hostname: "test-host-#{:rand.uniform(10000)}",
              ip_address: "192.168.1.#{:rand.uniform(255)}",
              os_type: "linux",
              machine_id: :crypto.strong_rand_bytes(32),
              organization_id: org.id
            },
            attrs
          )
        )
        |> Repo.insert!()

      :organization ->
        %TamanduaServer.Accounts.Organization{}
        |> TamanduaServer.Accounts.Organization.changeset(
          Map.merge(
            %{
              name: "Test Org #{:rand.uniform(10000)}",
              slug: "test-org-#{:rand.uniform(10000)}"
            },
            attrs
          )
        )
        |> Repo.insert!()
    end
  end
end
