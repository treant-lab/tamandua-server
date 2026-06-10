defmodule TamanduaServer.Alerts.WorkflowTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.Alerts.{Alert, Workflow, StateTransition}
  alias TamanduaServer.Accounts.{User, Organization}

  describe "workflow states and transitions" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      agent = insert(:agent, organization: org)
      alert = insert(:alert, organization: org, agent: agent, workflow_state: "new")

      {:ok, alert: alert, user: user, org: org}
    end

    test "valid state transitions succeed", %{alert: alert, user: user} do
      # new -> assigned
      {:ok, updated_alert} = Workflow.transition_state(alert, "assigned", user_id: user.id)
      assert updated_alert.workflow_state == "assigned"
      assert updated_alert.previous_state == "new"
      assert updated_alert.state_changed_by_id == user.id

      # assigned -> investigating
      {:ok, updated_alert} = Workflow.transition_state(updated_alert, "investigating", user_id: user.id)
      assert updated_alert.workflow_state == "investigating"
      assert updated_alert.previous_state == "assigned"

      # investigating -> resolved
      {:ok, updated_alert} = Workflow.transition_state(updated_alert, "resolved",
        user_id: user.id,
        reason: "Issue fixed"
      )
      assert updated_alert.workflow_state == "resolved"
      assert updated_alert.previous_state == "investigating"
    end

    test "invalid state transitions fail", %{alert: alert, user: user} do
      # new -> pending_info is not valid
      {:error, :invalid_transition} = Workflow.transition_state(alert, "pending_info", user_id: user.id)
    end

    test "transitions requiring reason fail without reason", %{alert: alert, user: user} do
      {:ok, updated_alert} = Workflow.transition_state(alert, "investigating", user_id: user.id)

      # resolved requires reason
      {:error, :reason_required} = Workflow.transition_state(updated_alert, "resolved", user_id: user.id)

      # But succeeds with reason
      {:ok, _} = Workflow.transition_state(updated_alert, "resolved",
        user_id: user.id,
        reason: "Fixed"
      )
    end

    test "state transitions create audit log", %{alert: alert, user: user} do
      {:ok, _} = Workflow.transition_state(alert, "investigating", user_id: user.id, notes: "Starting investigation")

      transitions = Workflow.get_transition_history(alert.id)
      assert length(transitions) == 1

      transition = List.first(transitions)
      assert transition.from_state == "new"
      assert transition.to_state == "investigating"
      assert transition.transition_notes == "Starting investigation"
      assert transition.transitioned_by_id == user.id
    end

    test "can reopen resolved alerts", %{alert: alert, user: user} do
      {:ok, updated_alert} = Workflow.transition_state(alert, "investigating", user_id: user.id)
      {:ok, updated_alert} = Workflow.transition_state(updated_alert, "resolved",
        user_id: user.id,
        reason: "Fixed"
      )

      # Reopen
      {:ok, updated_alert} = Workflow.transition_state(updated_alert, "investigating", user_id: user.id)
      assert updated_alert.workflow_state == "investigating"
      assert updated_alert.previous_state == "resolved"
    end

    test "valid_transition? checks transition validity" do
      assert Workflow.valid_transition?("new", "assigned")
      assert Workflow.valid_transition?("investigating", "resolved")
      refute Workflow.valid_transition?("new", "pending_info")
      refute Workflow.valid_transition?("resolved", "assigned")
    end

    test "valid_next_states returns possible transitions" do
      states = Workflow.valid_next_states("investigating")
      assert "resolved" in states
      assert "false_positive" in states
      assert "escalated" in states
      assert "closed" in states
      refute "new" in states
    end

    test "get_state_distribution returns alert counts by state", %{alert: alert, user: user, org: org, agent: agent} do
      # Create alerts in different states
      insert(:alert, organization: org, agent: agent, workflow_state: "new")
      insert(:alert, organization: org, agent: agent, workflow_state: "investigating")
      insert(:alert, organization: org, agent: agent, workflow_state: "investigating")

      distribution = Workflow.get_state_distribution(organization_id: org.id)

      new_count = Enum.find(distribution, fn d -> d.state == "new" end)
      investigating_count = Enum.find(distribution, fn d -> d.state == "investigating" end)

      assert new_count.count >= 2 # Original + 1
      assert investigating_count.count == 2
    end

    test "bulk_transition transitions multiple alerts", %{alert: alert, user: user, org: org, agent: agent} do
      alert2 = insert(:alert, organization: org, agent: agent, workflow_state: "new")
      alert3 = insert(:alert, organization: org, agent: agent, workflow_state: "new")

      {success, failure} = Workflow.bulk_transition(
        [alert.id, alert2.id, alert3.id],
        "investigating",
        user_id: user.id
      )

      assert success == 3
      assert failure == 0

      # Verify all were transitioned
      {:ok, updated1} = TamanduaServer.Alerts.get_alert(alert.id)
      {:ok, updated2} = TamanduaServer.Alerts.get_alert(alert2.id)
      {:ok, updated3} = TamanduaServer.Alerts.get_alert(alert3.id)

      assert updated1.workflow_state == "investigating"
      assert updated2.workflow_state == "investigating"
      assert updated3.workflow_state == "investigating"
    end

    test "get_transition_stats returns transition metrics", %{alert: alert, user: user, org: org} do
      {:ok, updated_alert} = Workflow.transition_state(alert, "investigating", user_id: user.id)
      {:ok, _} = Workflow.transition_state(updated_alert, "resolved",
        user_id: user.id,
        reason: "Fixed"
      )

      stats = Workflow.get_transition_stats(organization_id: org.id, days: 1)

      assert length(stats) >= 2

      new_to_investigating = Enum.find(stats, fn s ->
        s.from_state == "new" && s.to_state == "investigating"
      end)

      assert new_to_investigating.count >= 1
    end
  end

  # Helper factories (you may need to adjust based on your actual factories)
  defp insert(:organization) do
    %Organization{
      id: Ecto.UUID.generate(),
      name: "Test Org",
      slug: "test-org"
    }
    |> Repo.insert!()
  end

  defp insert(:user, opts) do
    %User{
      id: Ecto.UUID.generate(),
      email: "user#{System.unique_integer()}@example.com",
      password_hash: Bcrypt.hash_pwd_salt("password"),
      organization_id: opts[:organization].id
    }
    |> Repo.insert!()
  end

  defp insert(:agent, opts) do
    %TamanduaServer.Agents.Agent{
      id: Ecto.UUID.generate(),
      hostname: "test-host",
      organization_id: opts[:organization].id
    }
    |> Repo.insert!()
  end

  defp insert(:alert, opts) do
    %Alert{
      id: Ecto.UUID.generate(),
      title: "Test Alert",
      severity: "high",
      workflow_state: opts[:workflow_state] || "new",
      organization_id: opts[:organization].id,
      agent_id: opts[:agent].id
    }
    |> Repo.insert!()
  end
end
