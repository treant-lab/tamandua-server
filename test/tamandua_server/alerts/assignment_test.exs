defmodule TamanduaServer.Alerts.AssignmentTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.Alerts.{Alert, Assignment, AnalystWorkload, AutoAssignmentRule}
  alias TamanduaServer.Accounts.{User, Organization}

  describe "manual assignment" do
    setup do
      org = insert(:organization)
      admin = insert(:user, organization: org, role: "admin")
      analyst = insert(:user, organization: org, role: "analyst")
      agent = insert(:agent, organization: org)
      alert = insert(:alert, organization: org, agent: agent, workflow_state: "new")

      {:ok, alert: alert, admin: admin, analyst: analyst, org: org, agent: agent}
    end

    test "assign alert to analyst", %{alert: alert, admin: admin, analyst: analyst} do
      {:ok, updated_alert} = Assignment.assign(alert, analyst.id,
        assigned_by_id: admin.id,
        notes: "Best person for this"
      )

      assert updated_alert.assigned_to_id == analyst.id
      assert updated_alert.assigned_by_id == admin.id
      assert updated_alert.assignment_notes == "Best person for this"
      assert updated_alert.workflow_state == "assigned"
      assert updated_alert.assigned_at != nil
    end

    test "assignment updates analyst workload", %{alert: alert, admin: admin, analyst: analyst} do
      {:ok, _} = Assignment.assign(alert, analyst.id, assigned_by_id: admin.id)

      workload = Assignment.get_analyst_workload(analyst.id, alert.organization_id)

      assert workload.assigned_count == 1
      assert workload.high_count == 1 # alert is "high" severity
      assert workload.total_workload_score == 2.0 # high = 2 points
    end

    test "assignment creates history record", %{alert: alert, admin: admin, analyst: analyst} do
      {:ok, updated_alert} = Assignment.assign(alert, analyst.id,
        assigned_by_id: admin.id,
        notes: "You got this"
      )

      history = Assignment.get_assignment_history(updated_alert.id)
      assert length(history) == 1

      assignment = List.first(history)
      assert assignment.assigned_to_id == analyst.id
      assert assignment.assigned_by_id == admin.id
      assert assignment.assignment_type == "manual"
      assert assignment.handoff_notes == "You got this"
    end

    test "cannot assign to analyst at capacity", %{alert: alert, admin: admin, analyst: analyst, org: org} do
      # Set analyst capacity to 0
      workload = Assignment.get_analyst_workload(analyst.id, org.id)
      Repo.update!(Ecto.Changeset.change(workload, %{max_capacity: 0}))

      {:error, :analyst_at_capacity} = Assignment.assign(alert, analyst.id, assigned_by_id: admin.id)
    end

    test "cannot assign to unavailable analyst", %{alert: alert, admin: admin, analyst: analyst, org: org} do
      # Set analyst as unavailable
      {:ok, _} = Assignment.set_analyst_availability(analyst.id, false, org.id)

      {:error, :analyst_unavailable} = Assignment.assign(alert, analyst.id, assigned_by_id: admin.id)
    end

    test "unassign alert", %{alert: alert, admin: admin, analyst: analyst} do
      {:ok, updated_alert} = Assignment.assign(alert, analyst.id, assigned_by_id: admin.id)

      {:ok, unassigned_alert} = Assignment.unassign(updated_alert,
        unassigned_by_id: admin.id,
        reason: "Reassigning to someone else"
      )

      assert unassigned_alert.assigned_to_id == nil
      assert unassigned_alert.assigned_at == nil

      # Check workload was decremented
      workload = Assignment.get_analyst_workload(analyst.id, alert.organization_id)
      assert workload.assigned_count == 0
    end

    test "reassign alert to different analyst", %{alert: alert, admin: admin, analyst: analyst, org: org} do
      analyst2 = insert(:user, organization: org, role: "analyst")

      {:ok, updated_alert} = Assignment.assign(alert, analyst.id, assigned_by_id: admin.id)

      {:ok, reassigned_alert} = Assignment.reassign(updated_alert, analyst2.id,
        assigned_by_id: admin.id,
        handoff_notes: "You take over"
      )

      assert reassigned_alert.assigned_to_id == analyst2.id

      # Check workloads
      workload1 = Assignment.get_analyst_workload(analyst.id, org.id)
      workload2 = Assignment.get_analyst_workload(analyst2.id, org.id)

      assert workload1.assigned_count == 0
      assert workload2.assigned_count == 1
    end
  end

  describe "auto-assignment" do
    setup do
      org = insert(:organization)
      analyst1 = insert(:user, organization: org, role: "analyst")
      analyst2 = insert(:user, organization: org, role: "analyst")
      analyst3 = insert(:user, organization: org, role: "analyst")
      agent = insert(:agent, organization: org)

      {:ok, org: org, analysts: [analyst1, analyst2, analyst3], agent: agent}
    end

    test "round-robin auto-assignment", %{org: org, analysts: analysts, agent: agent} do
      # Create round-robin rule
      {:ok, rule} = Assignment.create_auto_assignment_rule(%{
        name: "Round Robin Critical",
        organization_id: org.id,
        strategy: "round_robin",
        severity_filter: ["critical"],
        analyst_pool: Enum.map(analysts, & &1.id)
      })

      # Create critical alerts
      alert1 = insert(:alert, organization: org, agent: agent, severity: "critical")
      alert2 = insert(:alert, organization: org, agent: agent, severity: "critical")
      alert3 = insert(:alert, organization: org, agent: agent, severity: "critical")

      # Auto-assign
      {:ok, assigned1} = Assignment.auto_assign(alert1)
      {:ok, assigned2} = Assignment.auto_assign(alert2)
      {:ok, assigned3} = Assignment.auto_assign(alert3)

      # Should be assigned to different analysts (round-robin)
      assigned_ids = [assigned1.assigned_to_id, assigned2.assigned_to_id, assigned3.assigned_to_id]
      assert length(Enum.uniq(assigned_ids)) == 3 # All different
    end

    test "least-busy auto-assignment", %{org: org, analysts: [analyst1, analyst2, analyst3], agent: agent} do
      # Give analyst1 some workload
      alert0 = insert(:alert, organization: org, agent: agent, severity: "high")
      {:ok, _} = Assignment.assign(alert0, analyst1.id, assigned_by_id: analyst1.id)

      # Create least-busy rule
      {:ok, rule} = Assignment.create_auto_assignment_rule(%{
        name: "Least Busy",
        organization_id: org.id,
        strategy: "least_busy",
        analyst_pool: Enum.map([analyst1, analyst2, analyst3], & &1.id)
      })

      # Create new alert
      alert = insert(:alert, organization: org, agent: agent, severity: "high")

      # Auto-assign should pick analyst2 or analyst3 (not analyst1)
      {:ok, assigned} = Assignment.auto_assign(alert)
      assert assigned.assigned_to_id in [analyst2.id, analyst3.id]
    end

    test "expertise-based auto-assignment", %{org: org, analysts: [analyst1, analyst2, _], agent: agent} do
      # Create expertise rule
      {:ok, rule} = Assignment.create_auto_assignment_rule(%{
        name: "Expertise T1059",
        organization_id: org.id,
        strategy: "expertise",
        analyst_pool: Enum.map([analyst1, analyst2], & &1.id),
        expertise_map: %{
          "T1059" => [analyst1.id], # analyst1 is expert in T1059
          "T1566" => [analyst2.id]  # analyst2 is expert in T1566
        }
      })

      # Create alert with T1059 technique
      alert = insert(:alert,
        organization: org,
        agent: agent,
        severity: "high",
        mitre_techniques: ["T1059"]
      )

      # Auto-assign should pick analyst1
      {:ok, assigned} = Assignment.auto_assign(alert)
      assert assigned.assigned_to_id == analyst1.id
    end

    test "no matching rule returns :no_matching_rule", %{org: org, agent: agent} do
      # Create alert with no matching rules
      alert = insert(:alert, organization: org, agent: agent, severity: "low")

      {:ok, :no_matching_rule} = Assignment.auto_assign(alert)
    end

    test "bulk auto-assign", %{org: org, analysts: analysts, agent: agent} do
      # Create rule
      {:ok, rule} = Assignment.create_auto_assignment_rule(%{
        name: "Bulk Test",
        organization_id: org.id,
        strategy: "round_robin",
        analyst_pool: Enum.map(analysts, & &1.id)
      })

      # Create multiple alerts
      alerts = for _ <- 1..5 do
        insert(:alert, organization: org, agent: agent, severity: "medium")
      end

      alert_ids = Enum.map(alerts, & &1.id)

      {assigned, failed} = Assignment.bulk_auto_assign(alert_ids)

      assert assigned == 5
      assert failed == 0
    end
  end

  describe "workload management" do
    setup do
      org = insert(:organization)
      analyst = insert(:user, organization: org, role: "analyst")

      {:ok, org: org, analyst: analyst}
    end

    test "workload tracks severity counts", %{org: org, analyst: analyst, agent: agent} do
      agent = insert(:agent, organization: org)

      # Assign alerts of different severities
      critical = insert(:alert, organization: org, agent: agent, severity: "critical")
      high = insert(:alert, organization: org, agent: agent, severity: "high")
      medium = insert(:alert, organization: org, agent: agent, severity: "medium")

      {:ok, _} = Assignment.assign(critical, analyst.id, assigned_by_id: analyst.id)
      {:ok, _} = Assignment.assign(high, analyst.id, assigned_by_id: analyst.id)
      {:ok, _} = Assignment.assign(medium, analyst.id, assigned_by_id: analyst.id)

      workload = Assignment.get_analyst_workload(analyst.id, org.id)

      assert workload.assigned_count == 3
      assert workload.critical_count == 1
      assert workload.high_count == 1
      assert workload.medium_count == 1
      # critical=4, high=2, medium=1
      assert workload.total_workload_score == 7.0
    end

    test "set analyst availability", %{org: org, analyst: analyst} do
      {:ok, workload} = Assignment.set_analyst_availability(analyst.id, false, org.id)
      assert workload.is_available == false

      {:ok, workload} = Assignment.set_analyst_availability(analyst.id, true, org.id)
      assert workload.is_available == true
    end

    test "list analyst workloads for organization", %{org: org} do
      analyst1 = insert(:user, organization: org, role: "analyst")
      analyst2 = insert(:user, organization: org, role: "analyst")

      # Initialize workloads
      Assignment.get_analyst_workload(analyst1.id, org.id)
      Assignment.get_analyst_workload(analyst2.id, org.id)

      workloads = Assignment.list_analyst_workloads(org.id)

      assert length(workloads) >= 2
    end

    test "get assigned alerts for analyst", %{org: org, analyst: analyst} do
      agent = insert(:agent, organization: org)

      # Assign some alerts
      alert1 = insert(:alert, organization: org, agent: agent, workflow_state: "new")
      alert2 = insert(:alert, organization: org, agent: agent, workflow_state: "new")

      {:ok, _} = Assignment.assign(alert1, analyst.id, assigned_by_id: analyst.id)
      {:ok, _} = Assignment.assign(alert2, analyst.id, assigned_by_id: analyst.id)

      assigned = Assignment.get_assigned_alerts(analyst.id, organization_id: org.id)

      assert length(assigned) == 2
    end
  end

  # Helper factories
  defp insert(:organization) do
    %Organization{
      id: Ecto.UUID.generate(),
      name: "Test Org",
      slug: "test-org-#{System.unique_integer()}"
    }
    |> Repo.insert!()
  end

  defp insert(:user, opts) do
    %User{
      id: Ecto.UUID.generate(),
      email: "user#{System.unique_integer()}@example.com",
      password_hash: Bcrypt.hash_pwd_salt("password"),
      role: opts[:role] || "analyst",
      organization_id: opts[:organization].id
    }
    |> Repo.insert!()
  end

  defp insert(:agent, opts) do
    %TamanduaServer.Agents.Agent{
      id: Ecto.UUID.generate(),
      hostname: "test-host-#{System.unique_integer()}",
      organization_id: opts[:organization].id
    }
    |> Repo.insert!()
  end

  defp insert(:alert, opts) do
    %Alert{
      id: Ecto.UUID.generate(),
      title: "Test Alert",
      severity: opts[:severity] || "high",
      workflow_state: opts[:workflow_state] || "new",
      mitre_techniques: opts[:mitre_techniques] || [],
      organization_id: opts[:organization].id,
      agent_id: opts[:agent].id
    }
    |> Repo.insert!()
  end
end
