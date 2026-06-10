defmodule TamanduaServer.AI.CostGovernorTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.AI.CostGovernor

  setup do
    # Ensure CostGovernor is running
    case Process.whereis(CostGovernor) do
      nil ->
        {:ok, _pid} = CostGovernor.start_link([])
      _pid ->
        # Clear ETS tables for clean state
        :ets.delete_all_objects(:ai_cost_budgets)
        :ets.delete_all_objects(:ai_cost_usage)
        :ets.delete_all_objects(:ai_cost_inferences)
    end

    :ok
  end

  describe "track_inference/6" do
    test "tracks inference with cost calculation" do
      agent_id = "agent-#{System.unique_integer()}"
      model_id = "gpt-4"

      {:ok, record} = CostGovernor.track_inference(
        agent_id,
        model_id,
        1000,  # tokens_in
        500,   # tokens_out
        2500   # latency_ms
      )

      assert record.agent_id == agent_id
      assert record.model_id == model_id
      assert record.tokens_in == 1000
      assert record.tokens_out == 500
      assert record.latency_ms == 2500
      assert record.cost_usd > 0
      assert is_binary(record.id)
      assert %DateTime{} = record.timestamp
    end

    test "tracks inference with optional parameters" do
      agent_id = "agent-#{System.unique_integer()}"

      {:ok, record} = CostGovernor.track_inference(
        agent_id,
        "claude-3-opus",
        2000,
        1000,
        3000,
        user_id: "user-123",
        process_id: "12345",
        team_id: "engineering",
        session_id: "session-abc"
      )

      assert record.user_id == "user-123"
      assert record.process_id == "12345"
      assert record.team_id == "engineering"
      assert record.session_id == "session-abc"
    end

    test "calculates cost correctly for different models" do
      agent_id = "agent-#{System.unique_integer()}"

      # GPT-4: $30/$60 per 1M tokens
      {:ok, gpt4} = CostGovernor.track_inference(agent_id, "gpt-4", 1_000_000, 1_000_000, 1000)
      assert_in_delta gpt4.cost_usd, 90.0, 0.01  # 30 + 60

      # GPT-3.5-turbo: $0.5/$1.5 per 1M tokens
      {:ok, gpt35} = CostGovernor.track_inference(agent_id, "gpt-3.5-turbo", 1_000_000, 1_000_000, 1000)
      assert_in_delta gpt35.cost_usd, 2.0, 0.01  # 0.5 + 1.5

      # Local model (llama): $0/$0 per 1M tokens
      {:ok, llama} = CostGovernor.track_inference(agent_id, "llama-3-70b", 1_000_000, 1_000_000, 1000)
      assert_in_delta llama.cost_usd, 0.0, 0.01
    end
  end

  describe "set_budget/3 and get_budget/2" do
    test "sets and retrieves budget limits" do
      limits = %{
        daily_usd: 100.0,
        hourly_usd: 10.0,
        tokens_per_min: 10_000,
        inferences_per_hour: 500
      }

      :ok = CostGovernor.set_budget(:user, "user-budget-test", limits)

      {:ok, retrieved} = CostGovernor.get_budget(:user, "user-budget-test")

      assert retrieved.daily_usd == 100.0
      assert retrieved.hourly_usd == 10.0
      assert retrieved.tokens_per_min == 10_000
      assert retrieved.inferences_per_hour == 500
    end

    test "returns error for non-existent budget" do
      assert {:error, :not_found} = CostGovernor.get_budget(:user, "non-existent")
    end

    test "sets budget with custom actions" do
      limits = %{
        daily_usd: 50.0,
        actions: %{
          50 => :alert,
          80 => :throttle,
          100 => :kill_process
        }
      }

      :ok = CostGovernor.set_budget(:team, "team-with-actions", limits)

      {:ok, retrieved} = CostGovernor.get_budget(:team, "team-with-actions")

      assert retrieved.actions[50] == :alert
      assert retrieved.actions[80] == :throttle
      assert retrieved.actions[100] == :kill_process
    end
  end

  describe "remove_budget/2" do
    test "removes existing budget" do
      :ok = CostGovernor.set_budget(:model, "test-model", %{daily_usd: 100.0})
      {:ok, _} = CostGovernor.get_budget(:model, "test-model")

      :ok = CostGovernor.remove_budget(:model, "test-model")

      assert {:error, :not_found} = CostGovernor.get_budget(:model, "test-model")
    end
  end

  describe "check_budget/2" do
    test "returns ok with remaining limits when under budget" do
      :ok = CostGovernor.set_budget(:user, "under-budget", %{
        daily_usd: 100.0,
        tokens_per_min: 10_000
      })

      # Track some usage
      {:ok, _} = CostGovernor.track_inference("agent-1", "gpt-4", 100, 50, 1000, user_id: "under-budget")

      {:ok, remaining} = CostGovernor.check_budget(:user, "under-budget")

      assert remaining.daily_usd != nil
      assert remaining.daily_usd < 100.0
    end

    test "returns unlimited when no budget is set" do
      {:ok, remaining} = CostGovernor.check_budget(:user, "no-budget-set")

      assert remaining.unlimited == true
    end

    test "returns exceeded when over budget" do
      :ok = CostGovernor.set_budget(:user, "over-budget", %{
        tokens_per_min: 100  # Very low limit
      })

      # Track usage that exceeds limit
      {:ok, _} = CostGovernor.track_inference("agent-1", "gpt-4", 200, 100, 1000, user_id: "over-budget")

      {:exceeded, action} = CostGovernor.check_budget(:user, "over-budget")

      assert action in [:alert, :throttle, :block, :kill_process]
    end
  end

  describe "get_usage/3" do
    test "returns usage report for entity" do
      user_id = "usage-report-user-#{System.unique_integer()}"

      # Track multiple inferences
      {:ok, _} = CostGovernor.track_inference("agent-1", "gpt-4", 1000, 500, 2000, user_id: user_id)
      {:ok, _} = CostGovernor.track_inference("agent-1", "claude-3-opus", 800, 400, 1500, user_id: user_id)
      {:ok, _} = CostGovernor.track_inference("agent-2", "gpt-4", 500, 250, 1000, user_id: user_id)

      report = CostGovernor.get_usage(:user, user_id, :hour)

      assert report.entity_type == :user
      assert report.entity_id == user_id
      assert report.total_inferences == 3
      assert report.total_tokens_in == 2300
      assert report.total_tokens_out == 1150
      assert report.total_cost_usd > 0
      assert length(report.models_used) == 2
      assert "gpt-4" in report.models_used
      assert "claude-3-opus" in report.models_used
    end

    test "returns usage for different time periods" do
      agent_id = "period-test-agent-#{System.unique_integer()}"

      {:ok, _} = CostGovernor.track_inference(agent_id, "gpt-4", 1000, 500, 1000)

      hour_report = CostGovernor.get_usage(:agent, agent_id, :hour)
      day_report = CostGovernor.get_usage(:agent, agent_id, :day)
      week_report = CostGovernor.get_usage(:agent, agent_id, :week)

      # All should include the same inference since it was just tracked
      assert hour_report.total_inferences == 1
      assert day_report.total_inferences == 1
      assert week_report.total_inferences == 1
    end
  end

  describe "get_metrics/0" do
    test "returns aggregated metrics" do
      agent_id = "metrics-test-#{System.unique_integer()}"

      {:ok, _} = CostGovernor.track_inference(agent_id, "gpt-4", 1000, 500, 1000)
      {:ok, _} = CostGovernor.track_inference(agent_id, "claude-3-haiku", 500, 250, 500)

      metrics = CostGovernor.get_metrics()

      assert metrics.total_inferences >= 2
      assert metrics.total_cost_usd_hour >= 0
      assert metrics.total_cost_usd_day >= 0
      assert metrics.total_tokens_hour >= 2250
      assert metrics.models_tracked >= 1
    end
  end

  describe "get_pricing/0 and set_model_pricing/3" do
    test "returns default pricing" do
      pricing = CostGovernor.get_pricing()

      assert is_map(pricing)
      assert Map.has_key?(pricing, "gpt-4")
      assert Map.has_key?(pricing, "claude-3-opus")
      assert pricing["gpt-4"].input == 30.0
      assert pricing["gpt-4"].output == 60.0
    end

    test "allows setting custom model pricing" do
      :ok = CostGovernor.set_model_pricing("custom-model", 5.0, 10.0)

      pricing = CostGovernor.get_pricing()

      assert pricing["custom-model"].input == 5.0
      assert pricing["custom-model"].output == 10.0
    end
  end

  describe "get_top_consumers/2" do
    test "returns top consumers by cost" do
      # Track inferences for multiple entities
      for i <- 1..5 do
        agent_id = "consumer-#{i}"
        # Each agent has different cost levels
        for _ <- 1..i do
          {:ok, _} = CostGovernor.track_inference(agent_id, "gpt-4", 1000, 500, 1000)
        end
      end

      top = CostGovernor.get_top_consumers(:day, 3)

      assert length(top) == 3
      # Verify sorted by cost descending
      costs = Enum.map(top, fn {_type, _id, cost} -> cost end)
      assert costs == Enum.sort(costs, :desc)
    end
  end

  describe "subscribe/0" do
    test "subscribes to cost governor events" do
      assert :ok = CostGovernor.subscribe()

      # Track an inference to trigger an event
      agent_id = "subscribe-test-#{System.unique_integer()}"
      {:ok, _} = CostGovernor.track_inference(agent_id, "gpt-4", 100, 50, 500)

      # Should receive the broadcast
      assert_receive {:inference_tracked, record}, 1000
      assert record.agent_id == agent_id
    end
  end

  describe "budget enforcement" do
    test "broadcasts alert when budget threshold is reached" do
      :ok = CostGovernor.subscribe()

      # Set a very low budget
      :ok = CostGovernor.set_budget(:user, "alert-test-user", %{
        tokens_per_min: 50,
        actions: %{100 => :alert}
      })

      # Exceed the budget
      {:ok, _} = CostGovernor.track_inference(
        "agent-1",
        "gpt-4",
        100,
        50,
        1000,
        user_id: "alert-test-user"
      )

      # Should receive budget alert
      assert_receive {:budget_alert, :user, "alert-test-user", _action, _context}, 1000
    end
  end
end
