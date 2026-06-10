defmodule TamanduaServer.Agents.GroupManagerTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.Agents.{GroupManager, Group}
  alias TamanduaServer.Accounts

  setup do
    # Create test organization
    {:ok, org} = Accounts.create_organization(%{
      name: "Test Org",
      subdomain: "test-#{System.unique_integer([:positive])}"
    })

    # Create test agents
    agents = for i <- 1..5 do
      {:ok, agent} = TamanduaServer.Agents.create_agent(%{
        hostname: "agent-#{i}",
        os_type: if(rem(i, 2) == 0, do: "windows", else: "linux"),
        os_version: "10.0",
        machine_id: <<i::64>>,
        organization_id: org.id
      })
      agent
    end

    %{organization_id: org.id, agents: agents}
  end

  describe "create_group/2" do
    test "creates a group with valid attributes", %{organization_id: org_id} do
      attrs = %{
        name: "Production Servers",
        description: "All production servers",
        color: "#FF5733",
        tags: ["production", "critical"]
      }

      assert {:ok, %Group{} = group} = GroupManager.create_group(org_id, attrs)
      assert group.name == "Production Servers"
      assert group.description == "All production servers"
      assert group.color == "#FF5733"
      assert group.tags == ["production", "critical"]
      assert group.organization_id == org_id
    end

    test "returns error with invalid color", %{organization_id: org_id} do
      attrs = %{
        name: "Test Group",
        color: "invalid-color"
      }

      assert {:error, changeset} = GroupManager.create_group(org_id, attrs)
      assert %{color: ["must be a valid hex color (e.g. #FF5733)"]} = errors_on(changeset)
    end

    test "requires unique name per organization", %{organization_id: org_id} do
      attrs = %{name: "Unique Group"}

      assert {:ok, _} = GroupManager.create_group(org_id, attrs)
      assert {:error, changeset} = GroupManager.create_group(org_id, attrs)
      assert %{name: ["Group name must be unique within organization"]} = errors_on(changeset)
    end
  end

  describe "update_group/2" do
    test "updates a group with valid attributes", %{organization_id: org_id} do
      {:ok, group} = GroupManager.create_group(org_id, %{name: "Original"})

      assert {:ok, updated} = GroupManager.update_group(group, %{
        name: "Updated",
        description: "New description"
      })

      assert updated.name == "Updated"
      assert updated.description == "New description"
    end
  end

  describe "delete_group/2" do
    test "deletes a group", %{organization_id: org_id} do
      {:ok, group} = GroupManager.create_group(org_id, %{name: "To Delete"})

      assert {:ok, _} = GroupManager.delete_group(group)
      assert {:error, :not_found} = GroupManager.get_group(org_id, group.id)
    end

    test "reassigns children to new parent", %{organization_id: org_id} do
      {:ok, parent} = GroupManager.create_group(org_id, %{name: "Parent"})
      {:ok, child} = GroupManager.create_group(org_id, %{name: "Child", parent_id: parent.id})
      {:ok, new_parent} = GroupManager.create_group(org_id, %{name: "New Parent"})

      assert {:ok, _} = GroupManager.delete_group(parent, reassign_to: new_parent.id)

      {:ok, updated_child} = GroupManager.get_group(org_id, child.id)
      assert updated_child.parent_id == new_parent.id
    end

    test "cascades delete to children", %{organization_id: org_id} do
      {:ok, parent} = GroupManager.create_group(org_id, %{name: "Parent"})
      {:ok, child} = GroupManager.create_group(org_id, %{name: "Child", parent_id: parent.id})

      assert {:ok, _} = GroupManager.delete_group(parent, cascade: true)

      assert {:error, :not_found} = GroupManager.get_group(org_id, child.id)
    end
  end

  describe "group membership" do
    test "adds agent to group", %{organization_id: org_id, agents: [agent | _]} do
      {:ok, group} = GroupManager.create_group(org_id, %{name: "Test Group"})

      assert {:ok, _member} = GroupManager.add_agent_to_group(agent.id, group.id)

      agents = GroupManager.list_group_agents(group.id)
      assert length(agents) == 1
      assert hd(agents).agent_id == agent.id
    end

    test "removes agent from group", %{organization_id: org_id, agents: [agent | _]} do
      {:ok, group} = GroupManager.create_group(org_id, %{name: "Test Group"})
      {:ok, _} = GroupManager.add_agent_to_group(agent.id, group.id)

      assert {:ok, _} = GroupManager.remove_agent_from_group(agent.id, group.id)

      agents = GroupManager.list_group_agents(group.id)
      assert length(agents) == 0
    end

    test "adds multiple agents to group", %{organization_id: org_id, agents: agents} do
      {:ok, group} = GroupManager.create_group(org_id, %{name: "Test Group"})
      agent_ids = Enum.map(agents, & &1.id)

      assert {:ok, count} = GroupManager.add_agents_to_group(agent_ids, group.id)
      assert count == length(agents)

      group_agents = GroupManager.list_group_agents(group.id)
      assert length(group_agents) == length(agents)
    end

    test "removes multiple agents from group", %{organization_id: org_id, agents: agents} do
      {:ok, group} = GroupManager.create_group(org_id, %{name: "Test Group"})
      agent_ids = Enum.map(agents, & &1.id)

      {:ok, _} = GroupManager.add_agents_to_group(agent_ids, group.id)

      assert {:ok, count} = GroupManager.remove_agents_from_group(agent_ids, group.id)
      assert count == length(agents)

      group_agents = GroupManager.list_group_agents(group.id)
      assert length(group_agents) == 0
    end

    test "lists agents in group with filters", %{organization_id: org_id, agents: agents} do
      {:ok, group} = GroupManager.create_group(org_id, %{name: "Test Group"})
      agent_ids = Enum.map(agents, & &1.id)
      {:ok, _} = GroupManager.add_agents_to_group(agent_ids, group.id)

      # No filter - all agents
      all_agents = GroupManager.list_group_agents(group.id)
      assert length(all_agents) == length(agents)

      # Filter by status
      online_agents = GroupManager.list_group_agents(group.id, status: "online")
      assert length(online_agents) == 0  # No agents are online in test setup
    end
  end

  describe "group statistics" do
    test "calculates group stats correctly", %{organization_id: org_id, agents: agents} do
      {:ok, group} = GroupManager.create_group(org_id, %{name: "Test Group"})
      agent_ids = Enum.map(agents, & &1.id)
      {:ok, _} = GroupManager.add_agents_to_group(agent_ids, group.id)

      stats = GroupManager.get_group_stats(group.id)

      assert stats.total == length(agents)
      assert stats.online == 0
      assert stats.offline == length(agents)
      assert stats.isolated == 0
    end

    test "counts agents by status", %{organization_id: org_id, agents: [agent | _]} do
      {:ok, group} = GroupManager.create_group(org_id, %{name: "Test Group"})
      {:ok, _} = GroupManager.add_agent_to_group(agent.id, group.id)

      # Update agent status
      TamanduaServer.Agents.update_agent(agent, %{status: "online"})

      count = GroupManager.count_group_agents(group.id, status: "online")
      assert count == 1
    end
  end

  describe "group hierarchy" do
    test "creates nested groups", %{organization_id: org_id} do
      {:ok, parent} = GroupManager.create_group(org_id, %{name: "Parent"})
      {:ok, child} = GroupManager.create_group(org_id, %{
        name: "Child",
        parent_id: parent.id
      })

      assert child.parent_id == parent.id
    end

    test "lists root groups only", %{organization_id: org_id} do
      {:ok, root1} = GroupManager.create_group(org_id, %{name: "Root 1"})
      {:ok, root2} = GroupManager.create_group(org_id, %{name: "Root 2"})
      {:ok, _child} = GroupManager.create_group(org_id, %{
        name: "Child",
        parent_id: root1.id
      })

      roots = GroupManager.list_root_groups(org_id)
      assert length(roots) == 2
      assert Enum.any?(roots, &(&1.id == root1.id))
      assert Enum.any?(roots, &(&1.id == root2.id))
    end

    test "gets descendant groups", %{organization_id: org_id} do
      {:ok, parent} = GroupManager.create_group(org_id, %{name: "Parent"})
      {:ok, child1} = GroupManager.create_group(org_id, %{
        name: "Child 1",
        parent_id: parent.id
      })
      {:ok, _grandchild} = GroupManager.create_group(org_id, %{
        name: "Grandchild",
        parent_id: child1.id
      })

      descendants = GroupManager.get_descendant_groups(parent.id)
      assert length(descendants) == 2
    end

    test "gets all agents in group tree recursively", %{
      organization_id: org_id,
      agents: [agent1, agent2, agent3 | _]
    } do
      {:ok, parent} = GroupManager.create_group(org_id, %{name: "Parent"})
      {:ok, child} = GroupManager.create_group(org_id, %{
        name: "Child",
        parent_id: parent.id
      })

      {:ok, _} = GroupManager.add_agent_to_group(agent1.id, parent.id)
      {:ok, _} = GroupManager.add_agent_to_group(agent2.id, child.id)
      {:ok, _} = GroupManager.add_agent_to_group(agent3.id, child.id)

      all_agent_ids = GroupManager.get_all_group_agents_recursive(parent.id)
      assert length(all_agent_ids) == 3
      assert agent1.id in all_agent_ids
      assert agent2.id in all_agent_ids
      assert agent3.id in all_agent_ids
    end
  end

  describe "batch commands" do
    test "executes batch command on group", %{organization_id: org_id, agents: agents} do
      {:ok, group} = GroupManager.create_group(org_id, %{name: "Test Group"})
      agent_ids = Enum.map(agents, & &1.id)
      {:ok, _} = GroupManager.add_agents_to_group(agent_ids, group.id)

      assert {:ok, batch} = GroupManager.execute_batch_command_on_group(
        group.id,
        "kill_process",
        %{pid: 1234},
        initiated_by: "test_user",
        timeout_seconds: 60
      )

      assert batch.command_type == "kill_process"
      assert batch.total_count == length(agents)
      assert batch.status in ["pending", "running"]
      assert batch.initiated_by == "test_user"
    end

    test "executes batch command on agent list", %{organization_id: org_id, agents: agents} do
      agent_ids = Enum.map(agents, & &1.id) |> Enum.take(3)

      assert {:ok, batch} = GroupManager.execute_batch_command_on_agents(
        org_id,
        agent_ids,
        "scan_path",
        %{path: "/", recursive: true}
      )

      assert batch.command_type == "scan_path"
      assert batch.total_count == 3
      assert batch.target_type == "agents"
    end

    test "returns error for empty agent list", %{organization_id: org_id} do
      assert {:error, :no_targets} = GroupManager.execute_batch_command_on_agents(
        org_id,
        [],
        "kill_process",
        %{pid: 1234}
      )
    end

    test "lists batch commands for organization", %{organization_id: org_id, agents: agents} do
      {:ok, group} = GroupManager.create_group(org_id, %{name: "Test Group"})
      agent_ids = Enum.map(agents, & &1.id)
      {:ok, _} = GroupManager.add_agents_to_group(agent_ids, group.id)

      {:ok, _batch1} = GroupManager.execute_batch_command_on_group(
        group.id,
        "kill_process",
        %{pid: 1234}
      )

      {:ok, _batch2} = GroupManager.execute_batch_command_on_group(
        group.id,
        "scan_path",
        %{path: "/"}
      )

      batches = GroupManager.list_batch_commands(org_id)
      assert length(batches) == 2
    end

    test "gets batch command by id", %{organization_id: org_id, agents: agents} do
      {:ok, group} = GroupManager.create_group(org_id, %{name: "Test Group"})
      agent_ids = Enum.map(agents, & &1.id)
      {:ok, _} = GroupManager.add_agents_to_group(agent_ids, group.id)

      {:ok, batch} = GroupManager.execute_batch_command_on_group(
        group.id,
        "kill_process",
        %{pid: 1234}
      )

      assert {:ok, fetched} = GroupManager.get_batch_command(batch.id)
      assert fetched.id == batch.id
      assert fetched.command_type == "kill_process"
    end

    test "cancels pending batch command", %{organization_id: org_id, agents: agents} do
      {:ok, group} = GroupManager.create_group(org_id, %{name: "Test Group"})
      agent_ids = Enum.map(agents, & &1.id)
      {:ok, _} = GroupManager.add_agents_to_group(agent_ids, group.id)

      {:ok, batch} = GroupManager.execute_batch_command_on_group(
        group.id,
        "kill_process",
        %{pid: 1234}
      )

      # Small delay to let async task start
      Process.sleep(100)

      assert {:ok, cancelled} = GroupManager.cancel_batch_command(batch.id)
      assert cancelled.status == "cancelled"
    end
  end

  describe "import/export" do
    test "exports groups to JSON", %{organization_id: org_id, agents: [agent | _]} do
      {:ok, group1} = GroupManager.create_group(org_id, %{
        name: "Group 1",
        description: "First group",
        tags: ["tag1", "tag2"]
      })

      {:ok, group2} = GroupManager.create_group(org_id, %{
        name: "Group 2",
        parent_id: group1.id
      })

      {:ok, _} = GroupManager.add_agent_to_group(agent.id, group1.id)

      assert {:ok, exported} = GroupManager.export_groups(org_id)

      assert length(exported) == 2
      assert Enum.any?(exported, &(&1.name == "Group 1"))
      assert Enum.any?(exported, &(&1.name == "Group 2"))

      group1_export = Enum.find(exported, &(&1.name == "Group 1"))
      assert group1_export.description == "First group"
      assert group1_export.tags == ["tag1", "tag2"]
      assert agent.id in group1_export.agent_ids
    end

    test "exports groups to CSV", %{organization_id: org_id} do
      {:ok, _} = GroupManager.create_group(org_id, %{
        name: "Test Group",
        description: "Test description",
        color: "#FF5733",
        tags: ["tag1", "tag2"]
      })

      assert {:ok, csv} = GroupManager.export_groups_csv(org_id)
      assert String.contains?(csv, "name,description,color,tags,parent,agent_count")
      assert String.contains?(csv, "Test Group")
      assert String.contains?(csv, "#FF5733")
    end

    test "imports groups from JSON", %{organization_id: org_id, agents: [agent | _]} do
      groups_data = [
        %{
          "name" => "Imported Group 1",
          "description" => "First imported",
          "color" => "#FF5733",
          "tags" => ["tag1"],
          "agent_ids" => [agent.id]
        },
        %{
          "name" => "Imported Group 2",
          "description" => "Second imported",
          "parent_name" => "Imported Group 1"
        }
      ]

      assert {:ok, imported} = GroupManager.import_groups(org_id, groups_data)
      assert length(imported) == 2

      # Verify groups were created
      groups = GroupManager.list_groups(org_id)
      assert length(groups) == 2

      group1 = Enum.find(groups, &(&1.name == "Imported Group 1"))
      assert group1.description == "First imported"
      assert group1.color == "#FF5733"

      # Verify membership
      agents = GroupManager.list_group_agents(group1.id)
      assert length(agents) == 1
      assert hd(agents).agent_id == agent.id

      # Verify parent-child relationship
      group2 = Enum.find(groups, &(&1.name == "Imported Group 2"))
      assert group2.parent_id == group1.id
    end
  end
end
