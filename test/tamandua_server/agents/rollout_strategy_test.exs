defmodule TamanduaServer.Agents.RolloutStrategyTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Agents.RolloutStrategy

  describe "get_stage_config/1" do
    test "returns canary strategy stages" do
      stages = RolloutStrategy.get_stage_config("canary")

      assert length(stages) == 4
      assert Enum.at(stages, 0).percentage == 5
      assert Enum.at(stages, 1).percentage == 25
      assert Enum.at(stages, 2).percentage == 50
      assert Enum.at(stages, 3).percentage == 100
    end

    test "returns phased strategy stages" do
      stages = RolloutStrategy.get_stage_config("phased")

      assert length(stages) == 5
      assert Enum.at(stages, 0).group_filter == ["dev", "test"]
      assert Enum.at(stages, 4).group_filter == []
    end

    test "returns blue-green strategy stages" do
      stages = RolloutStrategy.get_stage_config("blue_green")

      assert length(stages) == 3
      assert Enum.at(stages, 0).name == "Deploy Green"
      assert Enum.at(stages, 2).name == "Switch to Green"
    end

    test "returns immediate strategy stages" do
      stages = RolloutStrategy.get_stage_config("immediate")

      assert length(stages) == 1
      assert Enum.at(stages, 0).percentage == 100
    end
  end

  describe "calculate_target_agents/4 - canary strategy" do
    test "selects 5% for first stage" do
      agents = build_test_agents(100)

      target_ids = RolloutStrategy.calculate_target_agents(agents, "canary", 0)

      # 5% of 100 = 5 agents
      assert length(target_ids) == 5
    end

    test "prioritizes canary-tagged agents" do
      agents = [
        build_agent("1", tags: ["canary"]),
        build_agent("2", tags: ["canary"]),
        build_agent("3", tags: [])
      ]

      target_ids = RolloutStrategy.calculate_target_agents(agents, "canary", 0)

      # Should select canary-tagged agents first
      assert "1" in target_ids
      assert "2" in target_ids
    end

    test "selects 25% for second stage" do
      agents = build_test_agents(100)

      target_ids = RolloutStrategy.calculate_target_agents(agents, "canary", 1)

      assert length(target_ids) == 25
    end

    test "selects all agents for final stage" do
      agents = build_test_agents(20)

      target_ids = RolloutStrategy.calculate_target_agents(agents, "canary", 3)

      assert length(target_ids) == 20
    end
  end

  describe "calculate_target_agents/4 - phased strategy" do
    test "selects dev/test agents for first stage" do
      agents = [
        build_agent("1", tags: ["dev"]),
        build_agent("2", tags: ["test"]),
        build_agent("3", tags: ["prod-a"])
      ]

      target_ids = RolloutStrategy.calculate_target_agents(agents, "phased", 0)

      assert "1" in target_ids
      assert "2" in target_ids
      refute "3" in target_ids
    end

    test "selects all remaining agents for final stage" do
      agents = build_test_agents(10)

      target_ids = RolloutStrategy.calculate_target_agents(agents, "phased", 4)

      assert length(target_ids) == 10
    end
  end

  describe "calculate_target_agents/4 - immediate strategy" do
    test "selects all agents immediately" do
      agents = build_test_agents(50)

      target_ids = RolloutStrategy.calculate_target_agents(agents, "immediate", 0)

      assert length(target_ids) == 50
    end
  end

  describe "select_canary_agents/2" do
    test "prioritizes canary-tagged agents" do
      agents = [
        build_agent("1", tags: ["canary"]),
        build_agent("2", tags: []),
        build_agent("3", tags: ["canary"])
      ]

      selected = RolloutStrategy.select_canary_agents(agents, 2)

      assert "1" in selected
      assert "3" in selected
    end

    test "falls back to dev/test agents" do
      agents = [
        build_agent("1", tags: ["dev"]),
        build_agent("2", tags: ["prod"]),
        build_agent("3", tags: ["test"])
      ]

      selected = RolloutStrategy.select_canary_agents(agents, 2)

      assert "1" in selected
      assert "3" in selected
    end

    test "respects count limit" do
      agents = build_test_agents(100)

      selected = RolloutStrategy.select_canary_agents(agents, 10)

      assert length(selected) == 10
    end
  end

  describe "can_advance?/3" do
    test "allows advance when all conditions met" do
      rollout = %{
        started_at: DateTime.add(DateTime.utc_now(), -7200, :second), # 2 hours ago
        current_stage: 0
      }

      stage_config = %{
        wait_time: 3600, # 1 hour
        health_check_threshold: 0.9,
        auto_advance: true
      }

      agent_updates = [
        %{status: "completed"},
        %{status: "completed"},
        %{status: "completed"}
      ]

      assert {:ok, :advance} = RolloutStrategy.can_advance?(rollout, stage_config, agent_updates)
    end

    test "blocks advance if wait time not met" do
      rollout = %{
        started_at: DateTime.utc_now(), # Just started
        current_stage: 0
      }

      stage_config = %{
        wait_time: 3600,
        health_check_threshold: 0.9,
        auto_advance: true
      }

      agent_updates = [%{status: "completed"}]

      assert {:error, :wait_time_not_met} =
               RolloutStrategy.can_advance?(rollout, stage_config, agent_updates)
    end

    test "blocks advance if health check fails" do
      rollout = %{
        started_at: DateTime.add(DateTime.utc_now(), -7200, :second),
        current_stage: 0
      }

      stage_config = %{
        wait_time: 3600,
        health_check_threshold: 0.9,
        auto_advance: true
      }

      # Only 50% success rate
      agent_updates = [
        %{status: "completed"},
        %{status: "failed"}
      ]

      assert {:error, :health_check_failed} =
               RolloutStrategy.can_advance?(rollout, stage_config, agent_updates)
    end

    test "blocks advance if stage incomplete" do
      rollout = %{
        started_at: DateTime.add(DateTime.utc_now(), -7200, :second),
        current_stage: 0
      }

      stage_config = %{
        wait_time: 3600,
        health_check_threshold: 0.9,
        auto_advance: true
      }

      agent_updates = [
        %{status: "completed"},
        %{status: "in_progress"}
      ]

      assert {:error, :stage_incomplete} =
               RolloutStrategy.can_advance?(rollout, stage_config, agent_updates)
    end

    test "blocks advance if manual approval required" do
      rollout = %{
        started_at: DateTime.add(DateTime.utc_now(), -7200, :second),
        current_stage: 0,
        manual_approval_granted: false
      }

      stage_config = %{
        wait_time: 3600,
        health_check_threshold: 0.9,
        auto_advance: false # Requires manual approval
      }

      agent_updates = [%{status: "completed"}]

      assert {:error, :manual_approval_required} =
               RolloutStrategy.can_advance?(rollout, stage_config, agent_updates)
    end
  end

  describe "should_rollback?/2" do
    test "triggers rollback on high failure rate" do
      agent_updates = [
        %{status: "completed"},
        %{status: "failed"},
        %{status: "failed"}
      ]

      # 66% failure rate (> 15% threshold)
      assert {:rollback, reason} = RolloutStrategy.should_rollback?(agent_updates, %{})
      assert reason =~ "Failure rate exceeded"
    end

    test "continues when failure rate is acceptable" do
      agent_updates = [
        %{status: "completed"},
        %{status: "completed"},
        %{status: "completed"},
        %{status: "failed"}
      ]

      # 25% failure rate but only in absolute count
      # This is a 25% failure rate, should not trigger
      assert :continue = RolloutStrategy.should_rollback?(agent_updates, %{})
    end

    test "triggers rollback on critical errors" do
      agent_updates = [
        %{status: "failed", error_message: "Kernel panic detected"},
        %{status: "completed"}
      ]

      assert {:rollback, reason} = RolloutStrategy.should_rollback?(agent_updates, %{})
      assert reason =~ "Critical errors"
    end

    test "continues when no agents" do
      assert :continue = RolloutStrategy.should_rollback?([], %{})
    end
  end

  # Helper Functions

  defp build_test_agents(count) do
    Enum.map(1..count, fn i ->
      build_agent("agent-#{i}", tags: [])
    end)
  end

  defp build_agent(id, opts \\ []) do
    %{
      id: id,
      hostname: "host-#{id}",
      tags: Keyword.get(opts, :tags, [])
    }
  end
end
