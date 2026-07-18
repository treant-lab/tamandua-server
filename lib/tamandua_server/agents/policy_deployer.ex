defmodule TamanduaServer.Agents.PolicyDeployer do
  @moduledoc """
  Orchestrates policy deployments with support for immediate, scheduled, and phased rollouts.

  Handles:
  - Immediate deployments
  - Scheduled deployments (via Oban)
  - Phased rollouts (5% → 25% → 50% → 100%)
  - Automatic rollback on errors
  - Progress tracking
  """

  import Ecto.Query
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Agents.{
    PolicyDeployment,
    PolicyDeploymentResult,
    PolicyManager,
    Agent
  }

  alias TamanduaServer.Agents.Worker, as: AgentWorker

  @doc """
  Creates and starts a new policy deployment.
  """
  def deploy_policy(policy_id, opts \\ []) do
    policy = PolicyManager.get_policy(policy_id)

    if policy && policy.status == "active" do
      # Determine target agents
      target_agents = get_target_agents(policy, opts)

      # Create deployment
      deployment_attrs = %{
        policy_id: policy_id,
        organization_id: policy.organization_id,
        strategy: opts[:strategy] || "immediate",
        scheduled_at: opts[:scheduled_at],
        rollout_phases: opts[:rollout_phases] || PolicyDeployment.default_phased_rollout(),
        auto_rollback_enabled: opts[:auto_rollback] != false,
        rollback_threshold_percent: opts[:rollback_threshold] || 10,
        deployed_by_id: opts[:deployed_by_id],
        total_agents: length(target_agents),
        pending_agents: length(target_agents)
      }

      case create_deployment(deployment_attrs, target_agents) do
        {:ok, deployment} ->
          # Start deployment based on strategy
          case deployment.strategy do
            "immediate" ->
              start_immediate_deployment(deployment)

            "scheduled" ->
              schedule_deployment(deployment)

            "phased" ->
              start_phased_deployment(deployment)
          end

          {:ok, deployment}

        error ->
          error
      end
    else
      {:error, :invalid_policy}
    end
  end

  @doc """
  Continues a phased deployment to the next phase.
  """
  def continue_phased_deployment(deployment_id) do
    deployment = get_deployment(deployment_id)

    if deployment && deployment.strategy == "phased" && deployment.status == "in_progress" do
      case evaluate_health_gates(deployment) do
        {:rollback, reason} ->
          rollback_deployment(deployment, reason)

        :continue ->
        # Move to next phase
        next_phase = deployment.current_phase + 1

        if next_phase < length(deployment.rollout_phases) do
          phases = deployment.rollout_phases

          updated_phases =
            List.update_at(phases, next_phase, fn phase ->
              Map.merge(phase, %{
                "status" => "in_progress",
                "started_at" => DateTime.utc_now()
              })
            end)

          deployment
          |> Ecto.Changeset.change(%{
            current_phase: next_phase,
            current_phase_percentage: Enum.at(phases, next_phase)["percentage"],
            rollout_phases: updated_phases
          })
          |> Repo.update()
          |> case do
            {:ok, updated_deployment} ->
              # Deploy to next phase agents
              deploy_to_phase(updated_deployment, next_phase)
              {:ok, updated_deployment}

            error ->
              error
          end
        else
          # All phases complete
          complete_deployment(deployment)
        end
      end
    else
      {:error, :invalid_deployment}
    end
  end

  @doc """
  Rolls back a deployment.
  """
  def rollback_deployment(deployment_id, reason \\ nil) when is_binary(deployment_id) do
    deployment = get_deployment(deployment_id)
    rollback_deployment(deployment, reason)
  end

  def rollback_deployment(%PolicyDeployment{} = deployment, reason) do
    Logger.warning("Rolling back deployment #{deployment.id}: #{reason || "manual rollback"}")

    # Get all successfully deployed agents
    successful_results =
      from(r in PolicyDeploymentResult,
        where: r.deployment_id == ^deployment.id,
        where: r.status == "success",
        preload: [:agent]
      )
      |> Repo.all()

    # Restore previous policies
    Enum.each(successful_results, fn result ->
      if result.previous_policy_snapshot do
        send_policy_to_agent(result.agent, result.previous_policy_snapshot)
      end
    end)

    # Update deployment status
    deployment
    |> Ecto.Changeset.change(%{
      status: "rolled_back",
      rolled_back_at: DateTime.utc_now(),
      rollback_reason: reason
    })
    |> Repo.update()
  end

  @doc """
  Cancels a pending or in-progress deployment.
  """
  def cancel_deployment(deployment_id) do
    deployment = get_deployment(deployment_id)

    if deployment && deployment.status in ["pending", "in_progress"] do
      deployment
      |> Ecto.Changeset.change(%{
        status: "cancelled",
        completed_at: DateTime.utc_now()
      })
      |> Repo.update()
    else
      {:error, :cannot_cancel}
    end
  end

  @doc """
  Gets deployment status and progress.
  """
  def get_deployment_status(deployment_id) do
    deployment = get_deployment(deployment_id)

    if deployment do
      results =
        from(r in PolicyDeploymentResult,
          where: r.deployment_id == ^deployment_id,
          select: %{
            status: r.status,
            phase: r.phase_number,
            agent_id: r.agent_id
          }
        )
        |> Repo.all()

      {:ok,
       %{
         deployment: deployment,
         progress: %{
           total: deployment.total_agents,
           successful: deployment.successful_agents,
           failed: deployment.failed_agents,
           pending: deployment.pending_agents,
           percentage:
             if(deployment.total_agents > 0,
               do: deployment.successful_agents / deployment.total_agents * 100,
               else: 0
             )
         },
         results: results,
         failure_rate: PolicyDeployment.failure_rate(deployment)
       }}
    else
      {:error, :not_found}
    end
  end

  @doc """
  Lists all deployments for an organization.
  """
  def list_deployments(organization_id, opts \\ []) do
    query =
      from d in PolicyDeployment,
        where: d.organization_id == ^organization_id,
        order_by: [desc: d.inserted_at],
        preload: [:policy, :deployed_by]

    query =
      if opts[:status] do
        where(query, [d], d.status == ^opts[:status])
      else
        query
      end

    Repo.all(query)
  end

  ## Private Functions

  defp create_deployment(attrs, target_agents) do
    Repo.transaction(fn ->
      # Create deployment
      deployment =
        %PolicyDeployment{}
        |> PolicyDeployment.changeset(attrs)
        |> Repo.insert!()

      # Create deployment results for each agent
      Enum.each(target_agents, fn agent ->
        %PolicyDeploymentResult{}
        |> PolicyDeploymentResult.changeset(%{
          deployment_id: deployment.id,
          agent_id: agent.id,
          status: "pending",
          previous_policy_snapshot: get_agent_current_policy(agent.id)
        })
        |> Repo.insert!()
      end)

      deployment
    end)
  end

  defp get_target_agents(policy, opts) do
    base_query =
      from a in Agent,
        where: a.organization_id == ^policy.organization_id,
        where: a.status == "online"

    query =
      cond do
        # Specific agent IDs provided
        opts[:agent_ids] ->
          where(base_query, [a], a.id in ^opts[:agent_ids])

        # Specific group IDs provided
        opts[:group_ids] ->
          from a in base_query,
            join: gm in "group_members",
            on: gm.agent_id == a.id,
            where: gm.group_id in ^opts[:group_ids],
            distinct: true

        # Deploy to all agents in organization
        true ->
          base_query
      end

    Repo.all(query)
  end

  defp start_immediate_deployment(deployment) do
    deployment
    |> Ecto.Changeset.change(%{
      status: "in_progress",
      started_at: DateTime.utc_now()
    })
    |> Repo.update!()

    # Deploy to all agents
    deploy_to_all_agents(deployment)

    # Complete deployment
    complete_deployment(deployment)
  end

  defp schedule_deployment(deployment) do
    # Use Oban to schedule the deployment
    %{deployment_id: deployment.id}
    |> TamanduaServer.Jobs.PolicyDeploymentJob.new(scheduled_at: deployment.scheduled_at)
    |> Oban.insert()

    Logger.info("Scheduled deployment #{deployment.id} for #{deployment.scheduled_at}")
  end

  defp start_phased_deployment(deployment) do
    deployment
    |> Ecto.Changeset.change(%{
      status: "in_progress",
      started_at: DateTime.utc_now(),
      current_phase: 0,
      current_phase_percentage: Enum.at(deployment.rollout_phases, 0)["percentage"]
    })
    |> Repo.update!()
    |> then(fn updated_deployment ->
      # Start first phase
      deploy_to_phase(updated_deployment, 0)
      updated_deployment
    end)
  end

  defp deploy_to_phase(deployment, phase_number) do
    phase = Enum.at(deployment.rollout_phases, phase_number)
    percentage = phase["percentage"]

    # Get agents for this phase
    agents_for_phase = get_agents_for_phase(deployment, phase_number, percentage)

    Logger.info(
      "Deploying phase #{phase_number} (#{percentage}%) to #{length(agents_for_phase)} agents"
    )

    # Deploy to each agent in this phase
    Enum.each(agents_for_phase, fn result ->
      deploy_to_agent(deployment, result, phase_number)
    end)

    # Update phase status
    phases = deployment.rollout_phases

    updated_phases =
      List.update_at(phases, phase_number, fn p ->
        Map.merge(p, %{
          "status" => "completed",
          "completed_at" => DateTime.utc_now(),
          "health_gates" => phase_health_summary(deployment, phase_number)
        })
      end)

    deployment
    |> Ecto.Changeset.change(%{rollout_phases: updated_phases})
    |> Repo.update!()
  end

  defp get_agents_for_phase(deployment, phase_number, percentage) do
    # Get all pending results
    all_pending =
      from(r in PolicyDeploymentResult,
        where: r.deployment_id == ^deployment.id,
        where: r.status == "pending",
        order_by: fragment("RANDOM()")
      )
      |> Repo.all()

    # Calculate number of agents for this phase
    previous_percentage =
      if phase_number > 0 do
        Enum.at(deployment.rollout_phases, phase_number - 1)["percentage"]
      else
        0
      end

    agents_for_phase =
      ((percentage - previous_percentage) / 100 * deployment.total_agents)
      |> round()
      |> max(1)

    Enum.take(all_pending, agents_for_phase)
  end

  defp deploy_to_all_agents(deployment) do
    from(r in PolicyDeploymentResult,
      where: r.deployment_id == ^deployment.id,
      where: r.status == "pending"
    )
    |> Repo.all()
    |> Enum.each(fn result ->
      deploy_to_agent(deployment, result, nil)
    end)
  end

  defp deploy_to_agent(deployment, result, phase_number) do
    # Update result status
    result
    |> Ecto.Changeset.change(%{
      status: "in_progress",
      phase_number: phase_number,
      started_at: DateTime.utc_now()
    })
    |> Repo.update!()

    # Get policy and agent
    _policy = PolicyManager.get_policy(deployment.policy_id)
    agent = Repo.get(Agent, result.agent_id)

    # Compute effective policy for this agent
    case PolicyManager.compute_effective_policy(agent.id) do
      {:ok, effective_policy} ->
        # Send policy to agent via WebSocket
        case send_policy_to_agent(agent, effective_policy) do
          :ok ->
            # Mark as successful
            result
            |> Ecto.Changeset.change(%{
              status: "success",
              completed_at: DateTime.utc_now()
            })
            |> Repo.update!()

            # Update deployment counters
            update_deployment_counters(deployment, :success)

          {:error, reason} ->
            # Mark as failed
            result
            |> Ecto.Changeset.change(%{
              status: "failed",
              failed_at: DateTime.utc_now(),
              error_message: to_string(reason),
              error_details: %{reason: reason}
            })
            |> Repo.update!()

            # Update deployment counters
            update_deployment_counters(deployment, :failure)
        end

      {:error, reason} ->
        # Mark as failed
        result
        |> Ecto.Changeset.change(%{
          status: "failed",
          failed_at: DateTime.utc_now(),
          error_message: "Failed to compute effective policy",
          error_details: %{reason: reason}
        })
        |> Repo.update!()

        update_deployment_counters(deployment, :failure)
    end
  end

  defp evaluate_health_gates(deployment) do
    deployment = Repo.get(PolicyDeployment, deployment.id) |> Repo.preload(:policy)
    phase_number = deployment.current_phase
    gates = get_in(deployment.policy.policy_data, ["rollout", "health_gates"]) || %{}
    summary = phase_health_summary(deployment, phase_number)

    failure_rate = summary["failure_rate_percent"]
    max_failure_rate = gates["max_failure_rate_percent"] || deployment.rollback_threshold_percent || 10
    offline_rate = summary["offline_rate_percent"]
    max_offline_rate = gates["max_offline_rate_percent"] || 10
    success_rate = summary["success_rate_percent"]
    min_success_rate = gates["min_success_rate_percent"] || 85
    cpu_p95 = summary["agent_cpu_p95_percent"]
    max_cpu = gates["max_agent_cpu_percent"] || 30

    cond do
      PolicyDeployment.should_rollback?(deployment) ->
        {:rollback, "failure rate exceeded deployment threshold"}

      failure_rate > max_failure_rate ->
        {:rollback, "failure rate #{failure_rate}% exceeded health gate #{max_failure_rate}%"}

      offline_rate > max_offline_rate ->
        {:rollback, "offline rate #{offline_rate}% exceeded health gate #{max_offline_rate}%"}

      success_rate < min_success_rate ->
        {:rollback, "success rate #{success_rate}% below health gate #{min_success_rate}%"}

      cpu_p95 && cpu_p95 > max_cpu ->
        {:rollback, "agent CPU p95 #{cpu_p95}% exceeded health gate #{max_cpu}%"}

      true ->
        :continue
    end
  end

  defp phase_health_summary(deployment, phase_number) do
    results =
      from(r in PolicyDeploymentResult,
        where: r.deployment_id == ^deployment.id and r.phase_number == ^phase_number,
        select: %{agent_id: r.agent_id, status: r.status}
      )
      |> Repo.all()

    total = max(length(results), 1)
    success = Enum.count(results, &(&1.status == "success"))
    failed = Enum.count(results, &(&1.status == "failed"))
    agent_ids = Enum.map(results, & &1.agent_id)
    agents =
      Repo.all(
        from(a in Agent,
          where: a.id in ^agent_ids,
          select: %{
            id: a.id,
            status: a.status,
            last_seen_at: a.last_seen_at,
            config: a.config
          }
        )
      )

    offline = Enum.count(agents, &agent_offline?/1)
    cpu_values = agents |> Enum.map(&agent_cpu_usage/1) |> Enum.filter(&is_number/1)

    %{
      "total_agents" => length(results),
      "success_rate_percent" => percent(success, total),
      "failure_rate_percent" => percent(failed, total),
      "offline_rate_percent" => percent(offline, total),
      "agent_cpu_p95_percent" => percentile(cpu_values, 0.95)
    }
  rescue
    _ ->
      %{
        "total_agents" => 0,
        "success_rate_percent" => 100.0,
        "failure_rate_percent" => 0.0,
        "offline_rate_percent" => 0.0,
        "agent_cpu_p95_percent" => nil
      }
  end

  defp agent_offline?(agent) do
    stale? =
      case agent.last_seen_at do
        nil -> true
        %DateTime{} = dt -> DateTime.diff(DateTime.utc_now(), dt, :second) > 600
        %NaiveDateTime{} = ndt ->
          DateTime.diff(DateTime.utc_now(), DateTime.from_naive!(ndt, "Etc/UTC"), :second) > 600

        _ -> false
      end

    agent.status in ["offline", "disconnected"] or stale?
  end

  defp agent_cpu_usage(agent) do
    get_in(agent.config || %{}, ["health", "cpu_usage"]) ||
      get_in(agent.config || %{}, ["metrics", "cpu_usage"]) ||
      get_in(agent.config || %{}, ["resource_usage", "cpu_percent"])
  end

  defp percent(value, total), do: Float.round(value / max(total, 1) * 100, 2)

  defp percentile([], _), do: nil
  defp percentile(values, percentile) do
    sorted = Enum.sort(values)
    index = max(ceil(length(sorted) * percentile) - 1, 0)
    Enum.at(sorted, index)
  end

  defp send_policy_to_agent(agent, policy_data) do
    # Send policy update command via WebSocket
    case AgentWorker.send_command(agent.id, %{
           type: "update_policy",
           policy: policy_data
         }) do
      :ok ->
        # Update agent's config field
        agent
        |> Ecto.Changeset.change(%{config: policy_data})
        |> Repo.update()

        :ok

      error ->
        Logger.error("Failed to send policy to agent #{agent.id}: #{inspect(error)}")
        error
    end
  rescue
    error ->
      Logger.error("Exception sending policy to agent #{agent.id}: #{inspect(error)}")
      {:error, :send_failed}
  end

  defp update_deployment_counters(deployment, result_type) do
    deployment = Repo.get(PolicyDeployment, deployment.id)

    updates =
      case result_type do
        :success ->
          %{
            successful_agents: deployment.successful_agents + 1,
            pending_agents: deployment.pending_agents - 1
          }

        :failure ->
          %{
            failed_agents: deployment.failed_agents + 1,
            pending_agents: deployment.pending_agents - 1
          }
      end

    deployment
    |> Ecto.Changeset.change(updates)
    |> Repo.update!()
  end

  defp complete_deployment(deployment) do
    deployment = Repo.get(PolicyDeployment, deployment.id)

    status = if deployment.failed_agents > 0, do: "completed", else: "completed"

    deployment
    |> Ecto.Changeset.change(%{
      status: status,
      completed_at: DateTime.utc_now()
    })
    |> Repo.update()
  end

  defp get_deployment(deployment_id) do
    Repo.get(PolicyDeployment, deployment_id)
    |> Repo.preload([:policy, :deployed_by])
  end

  defp get_agent_current_policy(agent_id) do
    case PolicyManager.compute_effective_policy(agent_id) do
      {:ok, policy} -> policy
      _ -> %{}
    end
  end
end
