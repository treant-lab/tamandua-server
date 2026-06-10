defmodule TamanduaServer.Agents.PolicyManagerTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Agents.{PolicyManager, Policy}
  alias TamanduaServer.Accounts.Organization

  describe "list_policies/2" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      %{organization: org, user: user}
    end

    test "lists all policies for an organization", %{organization: org, user: user} do
      policy1 = create_test_policy(org.id, user.id, %{name: "Policy 1"})
      policy2 = create_test_policy(org.id, user.id, %{name: "Policy 2"})

      policies = PolicyManager.list_policies(org.id)

      assert length(policies) == 2
      assert Enum.any?(policies, &(&1.id == policy1.id))
      assert Enum.any?(policies, &(&1.id == policy2.id))
    end

    test "filters policies by status", %{organization: org, user: user} do
      _active_policy = create_test_policy(org.id, user.id, %{name: "Active", status: "active"})
      _draft_policy = create_test_policy(org.id, user.id, %{name: "Draft", status: "draft"})

      active_policies = PolicyManager.list_policies(org.id, status: "active")
      assert length(active_policies) == 1
      assert hd(active_policies).status == "active"
    end
  end

  describe "create_policy/2" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      %{organization: org, user: user}
    end

    test "creates a policy with valid attributes", %{organization: org, user: user} do
      attrs = %{
        name: "Test Policy",
        description: "A test policy",
        organization_id: org.id,
        policy_data: valid_policy_data()
      }

      assert {:ok, %Policy{} = policy} = PolicyManager.create_policy(attrs, user.id)
      assert policy.name == "Test Policy"
      assert policy.organization_id == org.id
      assert policy.created_by_id == user.id
    end

    test "returns error with invalid policy data", %{organization: org, user: user} do
      attrs = %{
        name: "Invalid Policy",
        organization_id: org.id,
        policy_data: %{"invalid" => "data"}
      }

      assert {:error, %Ecto.Changeset{}} = PolicyManager.create_policy(attrs, user.id)
    end
  end

  describe "create_from_template/4" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      %{organization: org, user: user}
    end

    test "creates policy from baseline template", %{organization: org, user: user} do
      attrs = %{
        name: "Baseline Policy",
        description: "Created from template"
      }

      assert {:ok, policy} =
               PolicyManager.create_from_template(org.id, "baseline", attrs, user.id)

      assert policy.name == "Baseline Policy"
      assert policy.template_name == "baseline"
      assert policy.policy_type == "template"
      assert policy.policy_data["collectors"]["process"]["enabled"] == true
    end

    test "creates policy from high_security template", %{organization: org, user: user} do
      attrs = %{name: "High Security Policy"}

      assert {:ok, policy} =
               PolicyManager.create_from_template(org.id, "high_security", attrs, user.id)

      assert policy.template_name == "high_security"
      assert policy.policy_data["collectors"]["kernel_events"]["enabled"] == true
    end

    test "returns error for invalid template", %{organization: org, user: user} do
      attrs = %{name: "Invalid Template Policy"}

      assert {:error, :template_not_found} =
               PolicyManager.create_from_template(org.id, "invalid_template", attrs, user.id)
    end
  end

  describe "update_policy/3" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      policy = create_test_policy(org.id, user.id)
      %{organization: org, user: user, policy: policy}
    end

    test "updates policy attributes", %{policy: policy, user: user} do
      attrs = %{name: "Updated Policy", description: "Updated description"}

      assert {:ok, updated_policy} = PolicyManager.update_policy(policy, attrs, user.id)
      assert updated_policy.name == "Updated Policy"
      assert updated_policy.description == "Updated description"
    end

    test "increments version when updating active policy", %{organization: org, user: user} do
      policy = create_test_policy(org.id, user.id, %{status: "active", version: 1})

      attrs = %{
        policy_data: %{
          policy.policy_data
          | "collectors" => %{
              "process" => %{"enabled" => false, "interval_ms" => 10000}
            }
        }
      }

      assert {:ok, updated_policy} = PolicyManager.update_policy(policy, attrs, user.id)
      assert updated_policy.version == 2
    end
  end

  describe "activate_policy/2 and deactivate_policy/2" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      policy = create_test_policy(org.id, user.id, %{status: "draft"})
      %{organization: org, user: user, policy: policy}
    end

    test "activates a draft policy", %{policy: policy, user: user} do
      assert {:ok, activated_policy} = PolicyManager.activate_policy(policy, user.id)
      assert activated_policy.status == "active"
    end

    test "deactivates an active policy", %{organization: org, user: user} do
      policy = create_test_policy(org.id, user.id, %{status: "active"})
      assert {:ok, deactivated_policy} = PolicyManager.deactivate_policy(policy, user.id)
      assert deactivated_policy.status == "inactive"
    end
  end

  describe "assign_to_group/3" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      policy = create_test_policy(org.id, user.id)
      group = insert(:agent_group, organization: org)
      %{organization: org, user: user, policy: policy, group: group}
    end

    test "assigns policy to a group", %{policy: policy, group: group, user: user} do
      assert {:ok, assignment} =
               PolicyManager.assign_to_group(policy.id, group.id, assigned_by_id: user.id)

      assert assignment.policy_id == policy.id
      assert assignment.group_id == group.id
    end

    test "assigns policy with overrides", %{policy: policy, group: group} do
      overrides = %{"collectors" => %{"process" => %{"interval_ms" => 15000}}}

      assert {:ok, assignment} =
               PolicyManager.assign_to_group(policy.id, group.id, overrides: overrides)

      assert assignment.overrides == overrides
    end
  end

  describe "assign_to_agent/3" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      policy = create_test_policy(org.id, user.id)
      agent = insert(:agent, organization: org)
      %{organization: org, user: user, policy: policy, agent: agent}
    end

    test "assigns policy to an agent", %{policy: policy, agent: agent, user: user} do
      assert {:ok, assignment} =
               PolicyManager.assign_to_agent(policy.id, agent.id, assigned_by_id: user.id)

      assert assignment.policy_id == policy.id
      assert assignment.agent_id == agent.id
    end
  end

  describe "compute_effective_policy/1" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      agent = insert(:agent, organization: org)
      %{organization: org, user: user, agent: agent}
    end

    test "computes effective policy with organization policy only", %{
      organization: org,
      user: user,
      agent: agent
    } do
      org_policy =
        create_test_policy(org.id, user.id, %{scope: "organization", status: "active"})

      assert {:ok, effective_policy} = PolicyManager.compute_effective_policy(agent.id)
      assert effective_policy == org_policy.policy_data
    end

    test "merges group and organization policies", %{
      organization: org,
      user: user,
      agent: agent
    } do
      org_policy =
        create_test_policy(org.id, user.id, %{
          scope: "organization",
          status: "active",
          policy_data: %{
            "collectors" => %{"process" => %{"enabled" => true, "interval_ms" => 5000}}
          }
        })

      group = insert(:agent_group, organization: org)
      insert(:group_member, agent: agent, group: group)

      group_policy =
        create_test_policy(org.id, user.id, %{scope: "group", status: "active"})

      PolicyManager.assign_to_group(group_policy.id, group.id,
        overrides: %{"collectors" => %{"process" => %{"interval_ms" => 10000}}}
      )

      assert {:ok, effective_policy} = PolicyManager.compute_effective_policy(agent.id)
      assert effective_policy["collectors"]["process"]["interval_ms"] == 10000
    end
  end

  describe "compare_policies/2" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      %{organization: org, user: user}
    end

    test "compares two policies and returns diff", %{organization: org, user: user} do
      policy1 =
        create_test_policy(org.id, user.id, %{
          policy_data: %{"collectors" => %{"process" => %{"interval_ms" => 5000}}}
        })

      policy2 =
        create_test_policy(org.id, user.id, %{
          policy_data: %{"collectors" => %{"process" => %{"interval_ms" => 10000}}}
        })

      assert {:ok, diff} = PolicyManager.compare_policies(policy1.id, policy2.id)
      assert diff["collectors"]["process"]["interval_ms"]["old"] == 5000
      assert diff["collectors"]["process"]["interval_ms"]["new"] == 10000
    end
  end

  describe "simulate_policy/2" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      agent = insert(:agent, organization: org)
      policy = create_test_policy(org.id, user.id, %{status: "active"})
      %{organization: org, user: user, agent: agent, policy: policy}
    end

    test "simulates policy on agent", %{agent: agent, policy: policy} do
      assert {:ok, simulation} = PolicyManager.simulate_policy(agent.id, policy.id)
      assert Map.has_key?(simulation, :current)
      assert Map.has_key?(simulation, :simulated)
      assert Map.has_key?(simulation, :diff)
    end
  end

  describe "get_policy_history/1" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      policy = create_test_policy(org.id, user.id)
      %{organization: org, user: user, policy: policy}
    end

    test "returns policy history", %{policy: policy, user: user} do
      # Update policy to create history
      PolicyManager.update_policy(policy, %{description: "Updated"}, user.id)

      history = PolicyManager.get_policy_history(policy.id)
      assert length(history) >= 1
    end
  end

  ## Helper Functions

  defp create_test_policy(org_id, user_id, attrs \\ %{}) do
    default_attrs = %{
      name: "Test Policy",
      description: "A test policy",
      organization_id: org_id,
      policy_data: valid_policy_data(),
      status: "draft"
    }

    attrs = Map.merge(default_attrs, attrs)
    {:ok, policy} = PolicyManager.create_policy(attrs, user_id)
    policy
  end

  defp valid_policy_data do
    %{
      "collectors" => %{
        "process" => %{"enabled" => true, "interval_ms" => 5000},
        "file" => %{"enabled" => true, "interval_ms" => 10000}
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
        "allowed_actions" => ["isolate", "kill_process"],
        "auto_response_enabled" => false,
        "max_actions_per_hour" => 10
      }
    }
  end
end
