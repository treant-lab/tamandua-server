defmodule TamanduaServer.Agents.PolicyDeployerTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Agents.{PolicyDeployer, PolicyManager, PolicyDeployment}

  describe "deploy_policy/2" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      policy = create_active_policy(org.id, user.id)
      agent1 = insert(:agent, organization: org, status: "online")
      agent2 = insert(:agent, organization: org, status: "online")
      %{organization: org, user: user, policy: policy, agents: [agent1, agent2]}
    end

    test "creates immediate deployment", %{policy: policy, user: user} do
      assert {:ok, deployment} =
               PolicyDeployer.deploy_policy(policy.id,
                 strategy: "immediate",
                 deployed_by_id: user.id
               )

      assert deployment.strategy == "immediate"
      assert deployment.status == "in_progress"
      assert deployment.total_agents > 0
    end

    test "creates scheduled deployment", %{policy: policy, user: user} do
      scheduled_at = DateTime.add(DateTime.utc_now(), 3600, :second)

      assert {:ok, deployment} =
               PolicyDeployer.deploy_policy(policy.id,
                 strategy: "scheduled",
                 scheduled_at: scheduled_at,
                 deployed_by_id: user.id
               )

      assert deployment.strategy == "scheduled"
      assert deployment.status == "pending"
      assert deployment.scheduled_at == scheduled_at
    end

    test "creates phased deployment", %{policy: policy, user: user} do
      phases = [
        %{percentage: 25, status: "pending"},
        %{percentage: 50, status: "pending"},
        %{percentage: 100, status: "pending"}
      ]

      assert {:ok, deployment} =
               PolicyDeployer.deploy_policy(policy.id,
                 strategy: "phased",
                 rollout_phases: phases,
                 deployed_by_id: user.id
               )

      assert deployment.strategy == "phased"
      assert length(deployment.rollout_phases) == 3
    end

    test "creates deployment results for all target agents", %{
      policy: policy,
      user: user,
      agents: agents
    } do
      {:ok, deployment} =
        PolicyDeployer.deploy_policy(policy.id,
          strategy: "immediate",
          deployed_by_id: user.id
        )

      results =
        Repo.all(
          from r in TamanduaServer.Agents.PolicyDeploymentResult,
            where: r.deployment_id == ^deployment.id
        )

      assert length(results) == length(agents)
    end

    test "returns error for inactive policy", %{organization: org, user: user} do
      inactive_policy = create_test_policy(org.id, user.id, %{status: "inactive"})

      assert {:error, :invalid_policy} =
               PolicyDeployer.deploy_policy(inactive_policy.id, deployed_by_id: user.id)
    end
  end

  describe "continue_phased_deployment/1" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      policy = create_active_policy(org.id, user.id)
      _agent1 = insert(:agent, organization: org, status: "online")
      _agent2 = insert(:agent, organization: org, status: "online")
      _agent3 = insert(:agent, organization: org, status: "online")
      _agent4 = insert(:agent, organization: org, status: "online")

      {:ok, deployment} =
        PolicyDeployer.deploy_policy(policy.id,
          strategy: "phased",
          deployed_by_id: user.id
        )

      %{deployment: deployment}
    end

    test "advances to next phase", %{deployment: deployment} do
      current_phase = deployment.current_phase

      assert {:ok, updated_deployment} =
               PolicyDeployer.continue_phased_deployment(deployment.id)

      assert updated_deployment.current_phase == current_phase + 1
    end

    test "completes deployment after final phase", %{deployment: deployment} do
      # Advance through all phases
      phases_count = length(deployment.rollout_phases)

      Enum.each(0..(phases_count - 2), fn _ ->
        PolicyDeployer.continue_phased_deployment(deployment.id)
      end)

      {:ok, final_deployment} = PolicyDeployer.continue_phased_deployment(deployment.id)
      assert final_deployment.status == "completed"
    end
  end

  describe "rollback_deployment/2" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      policy = create_active_policy(org.id, user.id)
      agent = insert(:agent, organization: org, status: "online")

      {:ok, deployment} =
        PolicyDeployer.deploy_policy(policy.id,
          strategy: "immediate",
          deployed_by_id: user.id
        )

      %{deployment: deployment, agent: agent}
    end

    test "rolls back deployment", %{deployment: deployment} do
      assert {:ok, rolled_back_deployment} =
               PolicyDeployer.rollback_deployment(deployment.id, "Test rollback")

      assert rolled_back_deployment.status == "rolled_back"
      assert rolled_back_deployment.rollback_reason == "Test rollback"
    end
  end

  describe "cancel_deployment/1" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      policy = create_active_policy(org.id, user.id)
      scheduled_at = DateTime.add(DateTime.utc_now(), 3600, :second)

      {:ok, deployment} =
        PolicyDeployer.deploy_policy(policy.id,
          strategy: "scheduled",
          scheduled_at: scheduled_at,
          deployed_by_id: user.id
        )

      %{deployment: deployment}
    end

    test "cancels pending deployment", %{deployment: deployment} do
      assert {:ok, cancelled_deployment} = PolicyDeployer.cancel_deployment(deployment.id)
      assert cancelled_deployment.status == "cancelled"
    end

    test "cannot cancel completed deployment" do
      org = insert(:organization)
      user = insert(:user, organization: org)
      policy = create_active_policy(org.id, user.id)

      {:ok, deployment} =
        PolicyDeployer.deploy_policy(policy.id,
          strategy: "immediate",
          deployed_by_id: user.id
        )

      # Wait for deployment to complete
      deployment =
        Repo.get(PolicyDeployment, deployment.id)
        |> Ecto.Changeset.change(%{status: "completed"})
        |> Repo.update!()

      assert {:error, :cannot_cancel} = PolicyDeployer.cancel_deployment(deployment.id)
    end
  end

  describe "get_deployment_status/1" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      policy = create_active_policy(org.id, user.id)
      _agent = insert(:agent, organization: org, status: "online")

      {:ok, deployment} =
        PolicyDeployer.deploy_policy(policy.id,
          strategy: "immediate",
          deployed_by_id: user.id
        )

      %{deployment: deployment}
    end

    test "returns deployment status and progress", %{deployment: deployment} do
      assert {:ok, status} = PolicyDeployer.get_deployment_status(deployment.id)
      assert Map.has_key?(status, :deployment)
      assert Map.has_key?(status, :progress)
      assert Map.has_key?(status, :results)
      assert Map.has_key?(status, :failure_rate)
    end
  end

  describe "list_deployments/2" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      policy = create_active_policy(org.id, user.id)

      {:ok, deployment1} =
        PolicyDeployer.deploy_policy(policy.id,
          strategy: "immediate",
          deployed_by_id: user.id
        )

      {:ok, deployment2} =
        PolicyDeployer.deploy_policy(policy.id,
          strategy: "immediate",
          deployed_by_id: user.id
        )

      %{organization: org, deployments: [deployment1, deployment2]}
    end

    test "lists all deployments for organization", %{organization: org, deployments: deployments} do
      listed = PolicyDeployer.list_deployments(org.id)
      assert length(listed) == length(deployments)
    end

    test "filters deployments by status", %{organization: org} do
      pending_deployments = PolicyDeployer.list_deployments(org.id, status: "pending")
      assert Enum.all?(pending_deployments, &(&1.status == "pending"))
    end
  end

  describe "automatic rollback" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      policy = create_active_policy(org.id, user.id)
      %{organization: org, user: user, policy: policy}
    end

    test "triggers rollback when failure rate exceeds threshold", %{policy: policy, user: user} do
      # Create deployment with 10% rollback threshold
      {:ok, deployment} =
        PolicyDeployer.deploy_policy(policy.id,
          strategy: "immediate",
          auto_rollback: true,
          rollback_threshold: 10,
          deployed_by_id: user.id
        )

      # Simulate high failure rate
      deployment =
        Repo.get(PolicyDeployment, deployment.id)
        |> Ecto.Changeset.change(%{
          successful_agents: 8,
          failed_agents: 3,
          total_agents: 11
        })
        |> Repo.update!()

      assert PolicyDeployment.should_rollback?(deployment) == true
      assert PolicyDeployment.failure_rate(deployment) > 10
    end
  end

  ## Helper Functions

  defp create_test_policy(org_id, user_id, attrs \\ %{}) do
    default_attrs = %{
      name: "Test Policy",
      organization_id: org_id,
      policy_data: valid_policy_data()
    }

    attrs = Map.merge(default_attrs, attrs)
    {:ok, policy} = PolicyManager.create_policy(attrs, user_id)
    policy
  end

  defp create_active_policy(org_id, user_id) do
    policy = create_test_policy(org_id, user_id, %{status: "draft"})
    {:ok, active_policy} = PolicyManager.activate_policy(policy, user_id)
    active_policy
  end

  defp valid_policy_data do
    %{
      "collectors" => %{
        "process" => %{"enabled" => true, "interval_ms" => 5000}
      },
      "resource_limits" => %{
        "max_cpu_percent" => 10,
        "max_memory_mb" => 500,
        "max_disk_mb" => 1000
      },
      "detection" => %{
        "yara_enabled" => true,
        "sigma_enabled" => true,
        "ml_enabled" => true
      },
      "response" => %{
        "allowed_actions" => ["isolate"],
        "auto_response_enabled" => false,
        "max_actions_per_hour" => 10
      }
    }
  end
end
