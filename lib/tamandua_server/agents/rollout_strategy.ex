defmodule TamanduaServer.Agents.RolloutStrategy do
  @moduledoc """
  Implements various rollout strategies for agent updates.

  Strategies:
  - **Canary**: Progressive rollout (5% → 25% → 50% → 100%)
  - **Phased**: Group-based or time-based phased deployment
  - **Blue-Green**: Parallel deployment with instant switchover
  - **Immediate**: All agents at once (risky, for emergency patches)
  """

  alias TamanduaServer.Agents.Agent
  import Ecto.Query

  @doc """
  Calculate which agents should receive an update in the current stage.

  Returns a list of agent IDs to update.
  """
  @spec calculate_target_agents(list(Agent.t()), String.t(), integer(), map()) :: list(binary())
  def calculate_target_agents(agents, strategy, current_stage, opts \\ %{})

  def calculate_target_agents(agents, "canary", current_stage, _opts) do
    execute_canary_strategy(agents, current_stage)
  end

  def calculate_target_agents(agents, "phased", current_stage, opts) do
    execute_phased_strategy(agents, current_stage, opts)
  end

  def calculate_target_agents(agents, "blue_green", current_stage, opts) do
    execute_blue_green_strategy(agents, current_stage, opts)
  end

  def calculate_target_agents(agents, "immediate", _current_stage, _opts) do
    # Return all agents immediately
    Enum.map(agents, & &1.id)
  end

  @doc """
  Get stage configuration for a strategy.

  Returns list of stages with their properties:
  - name: Human-readable stage name
  - percentage: Percentage of fleet (for canary)
  - wait_time: Time to wait before next stage (seconds)
  - health_check_threshold: Required success rate to proceed
  """
  @spec get_stage_config(String.t()) :: list(map())
  def get_stage_config("canary") do
    [
      %{
        name: "Canary (5%)",
        percentage: 5,
        wait_time: 3600,
        # 1 hour
        health_check_threshold: 0.95,
        # 95% success rate
        auto_advance: false
        # Require manual approval
      },
      %{
        name: "Early Adopters (25%)",
        percentage: 25,
        wait_time: 7200,
        # 2 hours
        health_check_threshold: 0.90,
        auto_advance: true
      },
      %{
        name: "Half Fleet (50%)",
        percentage: 50,
        wait_time: 14400,
        # 4 hours
        health_check_threshold: 0.90,
        auto_advance: true
      },
      %{
        name: "Full Rollout (100%)",
        percentage: 100,
        wait_time: 0,
        health_check_threshold: 0.85,
        auto_advance: true
      }
    ]
  end

  def get_stage_config("phased") do
    [
      %{name: "Development Group", group_filter: ["dev", "test"], wait_time: 3600},
      %{name: "Staging Group", group_filter: ["staging", "qa"], wait_time: 7200},
      %{name: "Production Group A", group_filter: ["prod-a"], wait_time: 14400},
      %{name: "Production Group B", group_filter: ["prod-b"], wait_time: 14400},
      %{name: "All Remaining", group_filter: [], wait_time: 0}
    ]
  end

  def get_stage_config("blue_green") do
    [
      %{name: "Deploy Green", percentage: 100, wait_time: 1800},
      %{name: "Validate Green", wait_time: 1800},
      %{name: "Switch to Green", wait_time: 0}
    ]
  end

  def get_stage_config("immediate") do
    [%{name: "Immediate Rollout", percentage: 100, wait_time: 0}]
  end

  @doc """
  Determine if a rollout can advance to the next stage.

  Checks:
  - Health check success rate
  - Wait time elapsed
  - Manual approval (if required)
  """
  @spec can_advance?(map(), map(), list(map())) :: {:ok, :advance} | {:error, atom()}
  def can_advance?(rollout, current_stage_config, agent_updates) do
    # Check wait time (only if the rollout has started)
    wait_time_elapsed? =
      if rollout.started_at do
        stage_started_at = get_stage_start_time(rollout, rollout.current_stage)
        elapsed = DateTime.diff(DateTime.utc_now(), stage_started_at)
        elapsed >= current_stage_config.wait_time
      else
        true
      end

    success_rate = calculate_success_rate(agent_updates)
    pending_count = Enum.count(agent_updates, &(&1.status == "pending"))
    in_progress_count = Enum.count(agent_updates, &(&1.status == "in_progress"))

    manual_approval_required? =
      not current_stage_config.auto_advance and
        not Map.get(rollout, :manual_approval_granted, false)

    cond do
      not wait_time_elapsed? ->
        {:error, :wait_time_not_met}

      success_rate < current_stage_config.health_check_threshold ->
        {:error, :health_check_failed}

      pending_count > 0 or in_progress_count > 0 ->
        {:error, :stage_incomplete}

      manual_approval_required? ->
        {:error, :manual_approval_required}

      true ->
        {:ok, :advance}
    end
  end

  @doc """
  Check if rollout should be automatically rolled back.

  Triggers rollback if:
  - Failure rate exceeds threshold (>15%)
  - Critical errors detected
  - Too many agents stuck in failed state
  """
  @spec should_rollback?(list(map()), map()) :: {:rollback, String.t()} | :continue
  def should_rollback?(agent_updates, _stage_config) do
    total = length(agent_updates)

    if total == 0 do
      :continue
    else
      failed = Enum.count(agent_updates, &(&1.status == "failed"))
      failure_rate = failed / total

      cond do
        failure_rate > 0.15 ->
          {:rollback, "Failure rate exceeded 15% (#{Float.round(failure_rate * 100, 1)}%)"}

        has_critical_errors?(agent_updates) ->
          {:rollback, "Critical errors detected in agent updates"}

        too_many_stuck_agents?(agent_updates) ->
          {:rollback, "Too many agents stuck in failed state"}

        true ->
          :continue
      end
    end
  end

  @doc """
  Select agents for canary deployment based on various criteria.

  Prioritizes:
  1. Agents with "canary" tag
  2. Development/test environments
  3. Agents with lower criticality
  4. Random selection from remaining pool
  """
  @spec select_canary_agents(list(Agent.t()), integer()) :: list(binary())
  def select_canary_agents(agents, count) do
    # Priority 1: Tagged canary agents
    canary_tagged =
      agents
      |> Enum.filter(&("canary" in (&1.tags || [])))

    # Priority 2: Dev/test agents
    dev_test =
      agents
      |> Enum.filter(&(has_tag?(&1, ["dev", "test", "staging"])))
      |> Enum.reject(&(&1 in canary_tagged))

    # Priority 3: Low criticality agents
    low_priority =
      agents
      |> Enum.filter(&(has_tag?(&1, ["low-priority"])))
      |> Enum.reject(&(&1 in canary_tagged or &1 in dev_test))

    # Remaining agents
    remaining =
      agents
      |> Enum.reject(&(&1 in canary_tagged or &1 in dev_test or &1 in low_priority))

    # Combine and take requested count
    (canary_tagged ++ dev_test ++ low_priority ++ Enum.shuffle(remaining))
    |> Enum.take(count)
    |> Enum.map(& &1.id)
  end

  # Private Functions

  defp execute_canary_strategy(agents, current_stage) do
    stages = get_stage_config("canary")
    stage = Enum.at(stages, current_stage)

    if is_nil(stage) do
      []
    else
      count = ceil(length(agents) * stage.percentage / 100)

      # For first stage, use smart canary selection
      # For subsequent stages, take remaining agents up to percentage
      if current_stage == 0 do
        select_canary_agents(agents, count)
      else
        agents
        |> Enum.take(count)
        |> Enum.map(& &1.id)
      end
    end
  end

  defp execute_phased_strategy(agents, current_stage, _opts) do
    stages = get_stage_config("phased")
    stage = Enum.at(stages, current_stage)

    if is_nil(stage) do
      []
    else
      # Filter by group tags
      group_filter = Map.get(stage, :group_filter, [])

      if Enum.empty?(group_filter) do
        # Last stage: all remaining agents
        Enum.map(agents, & &1.id)
      else
        agents
        |> Enum.filter(&has_tag?(&1, group_filter))
        |> Enum.map(& &1.id)
      end
    end
  end

  defp execute_blue_green_strategy(agents, current_stage, _opts) do
    stages = get_stage_config("blue_green")
    stage = Enum.at(stages, current_stage)

    if is_nil(stage) do
      []
    else
      case stage.name do
        "Deploy Green" ->
          # Deploy to all agents but don't activate yet
          Enum.map(agents, & &1.id)

        "Validate Green" ->
          # No new deployments, just validation
          []

        "Switch to Green" ->
          # Activate new version on all agents
          Enum.map(agents, & &1.id)

        _ ->
          []
      end
    end
  end

  defp has_tag?(agent, tag_list) do
    agent_tags = agent.tags || []
    Enum.any?(tag_list, &(&1 in agent_tags))
  end

  defp calculate_success_rate(agent_updates) do
    total = length(agent_updates)

    if total == 0 do
      1.0
    else
      completed = Enum.count(agent_updates, &(&1.status == "completed"))
      completed / total
    end
  end

  defp get_stage_start_time(rollout, current_stage) do
    # In production, this would come from a stage_history field
    # For now, use rollout started_at as approximation
    rollout.started_at || DateTime.utc_now()
  end

  defp has_critical_errors?(agent_updates) do
    # Check for critical error patterns
    critical_keywords = ["kernel panic", "boot failure", "authentication failed", "certificate invalid"]

    Enum.any?(agent_updates, fn update ->
      update.status == "failed" and
        update.error_message &&
        Enum.any?(critical_keywords, &String.contains?(String.downcase(update.error_message), &1))
    end)
  end

  defp too_many_stuck_agents?(agent_updates) do
    # Consider "stuck" if in pending/in_progress for > 30 minutes
    now = DateTime.utc_now()
    stuck_threshold = 30 * 60

    stuck_count =
      Enum.count(agent_updates, fn update ->
        update.status in ["pending", "in_progress"] and
          update.started_at &&
          DateTime.diff(now, update.started_at) > stuck_threshold
      end)

    stuck_count > length(agent_updates) * 0.1
  end
end
