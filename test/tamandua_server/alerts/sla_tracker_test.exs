defmodule TamanduaServer.Alerts.SLATrackerTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.Alerts.{Alert, SLATracker, SLAPolicy}
  alias TamanduaServer.Accounts.{User, Organization}

  describe "SLA deadline setting" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      agent = insert(:agent, organization: org)

      {:ok, org: org, user: user, agent: agent}
    end

    test "sets default deadlines for critical alert", %{org: org, agent: agent} do
      alert = insert(:alert, organization: org, agent: agent, severity: "critical")

      {:ok, updated_alert} = SLATracker.set_sla_deadlines(alert)

      assert updated_alert.sla_acknowledge_deadline != nil
      assert updated_alert.sla_resolve_deadline != nil

      # Critical: 15min ack, 240min (4h) resolve
      ack_diff = DateTime.diff(updated_alert.sla_acknowledge_deadline, updated_alert.inserted_at, :minute)
      resolve_diff = DateTime.diff(updated_alert.sla_resolve_deadline, updated_alert.inserted_at, :minute)

      assert ack_diff == 15
      assert resolve_diff == 240
    end

    test "uses custom SLA policy when available", %{org: org, agent: agent} do
      # Create custom policy
      {:ok, policy} = SLATracker.create_policy(%{
        name: "Custom Policy",
        organization_id: org.id,
        enabled: true,
        critical_acknowledge_minutes: 5,
        critical_resolve_minutes: 60
      })

      alert = insert(:alert, organization: org, agent: agent, severity: "critical")

      {:ok, updated_alert} = SLATracker.set_sla_deadlines(alert)

      ack_diff = DateTime.diff(updated_alert.sla_acknowledge_deadline, updated_alert.inserted_at, :minute)
      resolve_diff = DateTime.diff(updated_alert.sla_resolve_deadline, updated_alert.inserted_at, :minute)

      assert ack_diff == 5
      assert resolve_diff == 60
    end

    test "sets different deadlines by severity", %{org: org, agent: agent} do
      critical = insert(:alert, organization: org, agent: agent, severity: "critical")
      high = insert(:alert, organization: org, agent: agent, severity: "high")
      medium = insert(:alert, organization: org, agent: agent, severity: "medium")

      {:ok, critical} = SLATracker.set_sla_deadlines(critical)
      {:ok, high} = SLATracker.set_sla_deadlines(high)
      {:ok, medium} = SLATracker.set_sla_deadlines(medium)

      # Critical should have shorter deadline than high, which is shorter than medium
      assert DateTime.compare(critical.sla_acknowledge_deadline, high.sla_acknowledge_deadline) == :lt
      assert DateTime.compare(high.sla_acknowledge_deadline, medium.sla_acknowledge_deadline) == :lt
    end
  end

  describe "SLA acknowledgment and resolution" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      agent = insert(:agent, organization: org)
      alert = insert(:alert, organization: org, agent: agent, severity: "critical")

      {:ok, alert} = SLATracker.set_sla_deadlines(alert)

      {:ok, org: org, user: user, alert: alert}
    end

    test "mark acknowledged within SLA", %{alert: alert, user: user} do
      {:ok, updated_alert} = SLATracker.mark_acknowledged(alert, user.id)

      assert updated_alert.acknowledged_at != nil
      assert updated_alert.acknowledged_by_id == user.id
      assert updated_alert.sla_acknowledge_breached == false
    end

    test "mark acknowledged after SLA breach", %{alert: alert, user: user} do
      # Set deadline in the past
      past_deadline = DateTime.add(DateTime.utc_now(), -60, :second)
      alert = Repo.update!(Ecto.Changeset.change(alert, %{sla_acknowledge_deadline: past_deadline}))

      {:ok, updated_alert} = SLATracker.mark_acknowledged(alert, user.id)

      assert updated_alert.acknowledged_at != nil
      assert updated_alert.sla_acknowledge_breached == true
    end

    test "mark resolved within SLA", %{alert: alert} do
      {:ok, updated_alert} = SLATracker.mark_resolved(alert)

      assert updated_alert.resolved_at != nil
      assert updated_alert.sla_resolve_breached == false
    end

    test "mark resolved after SLA breach", %{alert: alert} do
      # Set deadline in the past
      past_deadline = DateTime.add(DateTime.utc_now(), -60, :second)
      alert = Repo.update!(Ecto.Changeset.change(alert, %{sla_resolve_deadline: past_deadline}))

      {:ok, updated_alert} = SLATracker.mark_resolved(alert)

      assert updated_alert.resolved_at != nil
      assert updated_alert.sla_resolve_breached == true
    end

    test "mark closed also marks as resolved if needed", %{alert: alert} do
      {:ok, updated_alert} = SLATracker.mark_closed(alert)

      assert updated_alert.resolved_at != nil
    end
  end

  describe "SLA breach checking" do
    setup do
      org = insert(:organization)
      agent = insert(:agent, organization: org)

      {:ok, org: org, agent: agent}
    end

    test "detects alerts approaching acknowledge deadline", %{org: org, agent: agent} do
      # Create alert with deadline in 10 minutes
      alert = insert(:alert, organization: org, agent: agent, severity: "critical")
      {:ok, alert} = SLATracker.set_sla_deadlines(alert)

      # Update deadline to be 10 minutes from now
      future_deadline = DateTime.add(DateTime.utc_now(), 10 * 60, :second)
      Repo.update!(Ecto.Changeset.change(alert, %{sla_acknowledge_deadline: future_deadline}))

      # Check with 15 minute warning threshold
      result = SLATracker.check_sla_breaches(
        organization_id: org.id,
        warning_threshold_minutes: 15
      )

      assert result.approaching_acknowledge >= 1
    end

    test "detects breached acknowledge SLA", %{org: org, agent: agent} do
      # Create alert with deadline in the past
      alert = insert(:alert, organization: org, agent: agent, severity: "critical")
      {:ok, alert} = SLATracker.set_sla_deadlines(alert)

      past_deadline = DateTime.add(DateTime.utc_now(), -60, :second)
      Repo.update!(Ecto.Changeset.change(alert, %{sla_acknowledge_deadline: past_deadline}))

      result = SLATracker.check_sla_breaches(organization_id: org.id)

      assert result.breached_acknowledge >= 1
    end

    test "updates breach flags during check", %{org: org, agent: agent} do
      alert = insert(:alert, organization: org, agent: agent, severity: "critical")
      {:ok, alert} = SLATracker.set_sla_deadlines(alert)

      # Set deadline in past
      past_deadline = DateTime.add(DateTime.utc_now(), -60, :second)
      alert = Repo.update!(Ecto.Changeset.change(alert, %{sla_acknowledge_deadline: past_deadline}))

      assert alert.sla_acknowledge_breached == false

      SLATracker.check_sla_breaches(organization_id: org.id)

      # Reload alert
      updated_alert = Repo.get!(Alert, alert.id)
      assert updated_alert.sla_acknowledge_breached == true
    end
  end

  describe "SLA metrics and reporting" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      agent = insert(:agent, organization: org)

      {:ok, org: org, user: user, agent: agent}
    end

    test "get_sla_metrics returns compliance rates", %{org: org, user: user, agent: agent} do
      # Create and acknowledge some alerts
      alert1 = insert(:alert, organization: org, agent: agent, severity: "high")
      alert2 = insert(:alert, organization: org, agent: agent, severity: "high")
      alert3 = insert(:alert, organization: org, agent: agent, severity: "high")

      {:ok, alert1} = SLATracker.set_sla_deadlines(alert1)
      {:ok, alert2} = SLATracker.set_sla_deadlines(alert2)
      {:ok, alert3} = SLATracker.set_sla_deadlines(alert3)

      # Acknowledge 2 within SLA, 1 breached
      {:ok, _} = SLATracker.mark_acknowledged(alert1, user.id)
      {:ok, _} = SLATracker.mark_acknowledged(alert2, user.id)

      # Breach alert3
      past_deadline = DateTime.add(DateTime.utc_now(), -60, :second)
      alert3 = Repo.update!(Ecto.Changeset.change(alert3, %{sla_acknowledge_deadline: past_deadline}))
      {:ok, _} = SLATracker.mark_acknowledged(alert3, user.id)

      metrics = SLATracker.get_sla_metrics(organization_id: org.id, days: 1)

      assert metrics.total_alerts >= 3
      assert metrics.acknowledged_count >= 3
      assert metrics.breached_acknowledge >= 1
      # 2 out of 3 = 0.67 compliance
      assert metrics.acknowledge_compliance_rate >= 0.6
      assert metrics.acknowledge_compliance_rate <= 0.7
    end

    test "get_sla_metrics_by_severity breaks down by severity", %{org: org, user: user, agent: agent} do
      # Create alerts of different severities
      critical = insert(:alert, organization: org, agent: agent, severity: "critical")
      high = insert(:alert, organization: org, agent: agent, severity: "high")
      medium = insert(:alert, organization: org, agent: agent, severity: "medium")

      {:ok, critical} = SLATracker.set_sla_deadlines(critical)
      {:ok, high} = SLATracker.set_sla_deadlines(high)
      {:ok, medium} = SLATracker.set_sla_deadlines(medium)

      by_severity = SLATracker.get_sla_metrics_by_severity(organization_id: org.id, days: 1)

      critical_metrics = Enum.find(by_severity, fn m -> m.severity == "critical" end)
      high_metrics = Enum.find(by_severity, fn m -> m.severity == "high" end)
      medium_metrics = Enum.find(by_severity, fn m -> m.severity == "medium" end)

      assert critical_metrics != nil
      assert high_metrics != nil
      assert medium_metrics != nil
    end

    test "filters metrics by analyst", %{org: org, user: user, agent: agent} do
      # Create alert assigned to user
      alert = insert(:alert,
        organization: org,
        agent: agent,
        severity: "high",
        assigned_to_id: user.id
      )

      {:ok, alert} = SLATracker.set_sla_deadlines(alert)
      {:ok, _} = SLATracker.mark_acknowledged(alert, user.id)

      metrics = SLATracker.get_sla_metrics(
        analyst_id: user.id,
        organization_id: org.id,
        days: 1
      )

      assert metrics.total_alerts >= 1
    end
  end

  describe "SLA policies" do
    setup do
      org = insert(:organization)
      {:ok, org: org}
    end

    test "create SLA policy", %{org: org} do
      {:ok, policy} = SLATracker.create_policy(%{
        name: "Test Policy",
        organization_id: org.id,
        critical_acknowledge_minutes: 10,
        critical_resolve_minutes: 120
      })

      assert policy.name == "Test Policy"
      assert policy.critical_acknowledge_minutes == 10
      assert policy.critical_resolve_minutes == 120
    end

    test "get_active_policy returns highest priority enabled policy", %{org: org} do
      {:ok, policy1} = SLATracker.create_policy(%{
        name: "Policy 1",
        organization_id: org.id,
        enabled: true,
        priority: 1
      })

      {:ok, policy2} = SLATracker.create_policy(%{
        name: "Policy 2",
        organization_id: org.id,
        enabled: true,
        priority: 10
      })

      active = SLATracker.get_active_policy(org.id)

      assert active.id == policy2.id # Higher priority
    end

    test "disabled policies are not returned as active", %{org: org} do
      {:ok, policy} = SLATracker.create_policy(%{
        name: "Disabled",
        organization_id: org.id,
        enabled: false
      })

      active = SLATracker.get_active_policy(org.id)

      assert active == nil
    end

    test "list policies with filters", %{org: org} do
      {:ok, enabled} = SLATracker.create_policy(%{
        name: "Enabled",
        organization_id: org.id,
        enabled: true
      })

      {:ok, disabled} = SLATracker.create_policy(%{
        name: "Disabled",
        organization_id: org.id,
        enabled: false
      })

      all = SLATracker.list_policies(organization_id: org.id)
      assert length(all) == 2

      enabled_only = SLATracker.list_policies(organization_id: org.id, enabled_only: true)
      assert length(enabled_only) == 1
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
      assigned_to_id: opts[:assigned_to_id],
      organization_id: opts[:organization].id,
      agent_id: opts[:agent].id
    }
    |> Repo.insert!()
  end
end
