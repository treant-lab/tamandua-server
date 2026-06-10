defmodule TamanduaServer.Agents.HealthScorerTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.Agents.{Agent, HealthScorer, HealthMetrics}

  describe "calculate_health_score/2" do
    setup do
      # Create test agent
      org = insert(:organization)
      agent = insert(:agent, organization_id: org.id)

      # Insert test metrics
      now = DateTime.utc_now()

      for i <- 0..60 do
        insert(:health_metrics, %{
          agent_id: agent.id,
          timestamp: DateTime.add(now, -i * 60, :second),
          cpu_usage: 45.0,
          memory_usage: 65.0,
          disk_usage: 75.0,
          events_per_sec: 10.0,
          events_processed: 600,
          error_count: 2,
          health_score: 85,
          collector_metrics: %{
            "process" => %{"enabled" => true},
            "file" => %{"enabled" => true},
            "network" => %{"enabled" => true},
            "dns" => %{"enabled" => true},
            "registry" => %{"enabled" => true}
          }
        })
      end

      {:ok, agent: agent}
    end

    test "calculates perfect health score", %{agent: agent} do
      {:ok, result} = HealthScorer.calculate_health_score(agent.id)

      assert result.score == 100
      assert result.category == :excellent
      assert result.breakdown.uptime == 20
      assert result.breakdown.cpu == 15
      assert result.breakdown.memory == 15
      assert result.breakdown.coverage == 10
      assert length(result.issues) == 0
    end

    test "detects high CPU usage", %{agent: agent} do
      # Update latest metric with high CPU
      latest = HealthMetrics.get_latest(agent.id)

      HealthMetrics.changeset(latest, %{cpu_usage: 85.0})
      |> Repo.update()

      {:ok, result} = HealthScorer.calculate_health_score(agent.id)

      assert result.breakdown.cpu == 0
      assert result.score < 100
      assert Enum.any?(result.issues, &(&1.component == :cpu))
    end

    test "detects high memory usage", %{agent: agent} do
      latest = HealthMetrics.get_latest(agent.id)

      HealthMetrics.changeset(latest, %{memory_usage: 92.0})
      |> Repo.update()

      {:ok, result} = HealthScorer.calculate_health_score(agent.id)

      assert result.breakdown.memory == 0
      assert Enum.any?(result.issues, &(&1.component == :memory))
    end

    test "detects high error rate", %{agent: agent} do
      # Create metrics with high error rate
      now = DateTime.utc_now()

      for i <- 0..10 do
        insert(:health_metrics, %{
          agent_id: agent.id,
          timestamp: DateTime.add(now, -i * 60, :second),
          events_processed: 100,
          error_count: 10 # 10% error rate
        })
      end

      {:ok, result} = HealthScorer.calculate_health_score(agent.id)

      assert result.breakdown.error_rate == 0
      assert Enum.any?(result.issues, &(&1.component == :error_rate))
    end

    test "detects incomplete collector coverage", %{agent: agent} do
      latest = HealthMetrics.get_latest(agent.id)

      # Disable some collectors
      HealthMetrics.changeset(latest, %{
        collector_metrics: %{
          "process" => %{"enabled" => true},
          "file" => %{"enabled" => false},
          "network" => %{"enabled" => true}
        }
      })
      |> Repo.update()

      {:ok, result} = HealthScorer.calculate_health_score(agent.id)

      assert result.breakdown.coverage < 10
      assert Enum.any?(result.issues, &(&1.component == :coverage))
    end
  end

  describe "categorize_health/1" do
    test "categorizes excellent health" do
      assert HealthScorer.categorize_health(95) == :excellent
      assert HealthScorer.categorize_health(90) == :excellent
    end

    test "categorizes good health" do
      assert HealthScorer.categorize_health(85) == :good
      assert HealthScorer.categorize_health(70) == :good
    end

    test "categorizes fair health" do
      assert HealthScorer.categorize_health(65) == :fair
      assert HealthScorer.categorize_health(50) == :fair
    end

    test "categorizes poor health" do
      assert HealthScorer.categorize_health(45) == :poor
      assert HealthScorer.categorize_health(0) == :poor
    end
  end

  describe "score_uptime/3" do
    test "awards full points for >99% uptime" do
      agent = %Agent{}
      metrics = create_metrics_list(60, %{}) # All metrics present = 100% uptime

      score = HealthScorer.score_uptime(agent, metrics, 60)
      assert score == 20
    end

    test "awards partial points for 95-99% uptime" do
      agent = %Agent{}
      # Missing 5% of metrics = ~95% uptime
      metrics = create_metrics_list(57, %{})

      score = HealthScorer.score_uptime(agent, metrics, 60)
      assert score == 15
    end

    test "awards zero points for <95% uptime" do
      agent = %Agent{}
      metrics = create_metrics_list(50, %{}) # <90% uptime

      score = HealthScorer.score_uptime(agent, metrics, 60)
      assert score == 0
    end
  end

  describe "score_cpu_usage/1" do
    test "awards full points for <50% CPU" do
      metrics = %{cpu_usage: 45.0}
      assert HealthScorer.score_cpu_usage(metrics) == 15
    end

    test "awards partial points for 50-80% CPU" do
      metrics = %{cpu_usage: 65.0}
      assert HealthScorer.score_cpu_usage(metrics) == 10
    end

    test "awards zero points for >80% CPU" do
      metrics = %{cpu_usage: 85.0}
      assert HealthScorer.score_cpu_usage(metrics) == 0
    end
  end

  describe "score_memory_usage/1" do
    test "awards full points for <70% memory" do
      metrics = %{memory_usage: 65.0}
      assert HealthScorer.score_memory_usage(metrics) == 15
    end

    test "awards partial points for 70-90% memory" do
      metrics = %{memory_usage: 80.0}
      assert HealthScorer.score_memory_usage(metrics) == 10
    end

    test "awards zero points for >90% memory" do
      metrics = %{memory_usage: 92.0}
      assert HealthScorer.score_memory_usage(metrics) == 0
    end
  end

  describe "score_event_throughput/2" do
    test "awards full points when within baseline ±20%" do
      metrics = %{events_per_sec: 10.0}
      baseline = 10.0

      assert HealthScorer.score_event_throughput(metrics, baseline) == 15
    end

    test "awards full points when 20% below baseline" do
      metrics = %{events_per_sec: 8.5}
      baseline = 10.0

      assert HealthScorer.score_event_throughput(metrics, baseline) == 15
    end

    test "awards full points when 20% above baseline" do
      metrics = %{events_per_sec: 11.5}
      baseline = 10.0

      assert HealthScorer.score_event_throughput(metrics, baseline) == 15
    end

    test "awards zero points when outside baseline range" do
      metrics = %{events_per_sec: 15.0}
      baseline = 10.0

      assert HealthScorer.score_event_throughput(metrics, baseline) == 0
    end

    test "awards full points when no baseline exists" do
      metrics = %{events_per_sec: 10.0}
      baseline = 0

      assert HealthScorer.score_event_throughput(metrics, baseline) == 15
    end
  end

  describe "score_error_rate/2" do
    test "awards full points for <1% error rate" do
      latest = %{error_count: 1, events_processed: 200}
      all = [latest]

      assert HealthScorer.score_error_rate(latest, all) == 15
    end

    test "awards partial points for 1-5% error rate" do
      latest = %{error_count: 3, events_processed: 100}
      all = [latest]

      assert HealthScorer.score_error_rate(latest, all) == 10
    end

    test "awards zero points for >5% error rate" do
      latest = %{error_count: 10, events_processed: 100}
      all = [latest]

      assert HealthScorer.score_error_rate(latest, all) == 0
    end
  end

  describe "score_detection_coverage/1" do
    test "awards full points when all collectors active" do
      metrics = %{
        collector_metrics: %{
          "process" => %{"enabled" => true},
          "file" => %{"enabled" => true},
          "network" => %{"enabled" => true},
          "dns" => %{"enabled" => true},
          "registry" => %{"enabled" => true}
        }
      }

      assert HealthScorer.score_detection_coverage(metrics) == 10
    end

    test "awards partial points for some collectors active" do
      metrics = %{
        collector_metrics: %{
          "process" => %{"enabled" => true},
          "file" => %{"enabled" => true},
          "network" => %{"enabled" => false}
        }
      }

      score = HealthScorer.score_detection_coverage(metrics)
      assert score < 10
      assert score > 0
    end

    test "awards zero points when no collectors active" do
      metrics = %{collector_metrics: %{}}

      assert HealthScorer.score_detection_coverage(metrics) == 0
    end
  end

  # Helper functions

  defp create_metrics_list(count, base_attrs) do
    now = DateTime.utc_now()

    for i <- 0..(count - 1) do
      Map.merge(
        %{
          timestamp: DateTime.add(now, -i * 60, :second),
          cpu_usage: 50.0,
          memory_usage: 60.0,
          events_per_sec: 10.0,
          events_processed: 600,
          error_count: 1
        },
        base_attrs
      )
    end
  end
end
