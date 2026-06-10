defmodule TamanduaServer.Workers.RemediationEscalationWorkerTest do
  use TamanduaServer.DataCase
  use Oban.Testing, repo: TamanduaServer.Repo

  alias TamanduaServer.Workers.RemediationEscalationWorker
  alias TamanduaServer.Remediation.{Workflow, Policy, AuditTrail}
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Repo

  describe "perform/1" do
    setup do
      organization_id = Ecto.UUID.generate()

      {:ok, alert} = create_test_alert(%{organization_id: organization_id})
      {:ok, policy} = create_test_policy(%{
        organization_id: organization_id,
        escalation_timeout_minutes: 1  # 1 minute for testing
      })

      %{organization_id: organization_id, alert: alert, policy: policy}
    end

    test "finds workflows past escalation_timeout without approval", %{
      organization_id: organization_id,
      alert: alert,
      policy: policy
    } do
      # Create workflow that is past its timeout
      past_time = DateTime.add(DateTime.utc_now(), -120, :second)  # 2 minutes ago

      {:ok, workflow} = create_test_workflow(%{
        alert_id: alert.id,
        policy_id: policy.id,
        organization_id: organization_id,
        execution_mode: "pending_approval",
        state: "pending",
        escalation_timeout_minutes: 1,
        inserted_at: past_time
      })

      stale = RemediationEscalationWorker.find_stale_workflows(DateTime.utc_now())

      assert length(stale) >= 1
      assert Enum.any?(stale, &(&1.id == workflow.id))
    end

    test "increments escalation_level on workflow", %{
      organization_id: organization_id,
      alert: alert,
      policy: policy
    } do
      # Create workflow past timeout at level 0
      past_time = DateTime.add(DateTime.utc_now(), -120, :second)

      {:ok, workflow} = create_test_workflow(%{
        alert_id: alert.id,
        policy_id: policy.id,
        organization_id: organization_id,
        execution_mode: "pending_approval",
        state: "pending",
        escalation_timeout_minutes: 1,
        escalation_level: 0,
        inserted_at: past_time
      })

      # Run the worker
      assert :ok = perform_job(RemediationEscalationWorker, %{})

      # Check workflow was escalated
      updated = Repo.get(Workflow, workflow.id)
      assert updated.escalation_level == 1
      assert updated.last_escalated_at != nil
    end

    test "workflow with max escalations (security_director) auto-rejects", %{
      organization_id: organization_id,
      alert: alert,
      policy: policy
    } do
      # Create workflow at max escalation level (3 = security_director)
      past_time = DateTime.add(DateTime.utc_now(), -120, :second)

      {:ok, workflow} = create_test_workflow(%{
        alert_id: alert.id,
        policy_id: policy.id,
        organization_id: organization_id,
        execution_mode: "pending_approval",
        state: "pending",
        escalation_timeout_minutes: 1,
        escalation_level: 3,  # Already at security_director
        last_escalated_at: past_time,
        inserted_at: past_time
      })

      # Run the worker
      assert :ok = perform_job(RemediationEscalationWorker, %{})

      # Check workflow was auto-rejected
      updated = Repo.get(Workflow, workflow.id)
      assert updated.state == "cancelled"
      assert updated.approval_notes =~ "Auto-rejected"
    end

    test "audit event logged for each escalation", %{
      organization_id: organization_id,
      alert: alert,
      policy: policy
    } do
      # Create workflow past timeout
      past_time = DateTime.add(DateTime.utc_now(), -120, :second)

      {:ok, workflow} = create_test_workflow(%{
        alert_id: alert.id,
        policy_id: policy.id,
        organization_id: organization_id,
        execution_mode: "pending_approval",
        state: "pending",
        escalation_timeout_minutes: 1,
        escalation_level: 0,
        inserted_at: past_time
      })

      # Run the worker
      assert :ok = perform_job(RemediationEscalationWorker, %{})

      # Allow time for async audit event
      Process.sleep(100)

      # Check audit event was created
      events = AuditTrail.list_events(workflow.id)
      escalation_events = Enum.filter(events, &(&1.event_type == "escalated"))

      assert length(escalation_events) >= 1
      event = hd(escalation_events)
      assert event.details["from_tier"] == "analyst"
      assert event.details["to_tier"] == "senior_analyst"
    end
  end

  describe "escalation_tiers/0" do
    test "returns the correct tier order" do
      tiers = RemediationEscalationWorker.escalation_tiers()

      assert tiers == ["analyst", "senior_analyst", "manager", "security_director"]
    end
  end

  # Helper functions

  defp create_test_alert(attrs) do
    default_attrs = %{
      title: "Test Alert",
      description: "Test alert description",
      severity: "high",
      status: "new",
      threat_score: 0.85,
      agent_id: Ecto.UUID.generate(),
      organization_id: Ecto.UUID.generate()
    }

    merged_attrs = Map.merge(default_attrs, attrs)

    %Alert{}
    |> Alert.changeset(merged_attrs)
    |> Repo.insert()
  end

  defp create_test_policy(attrs) do
    default_attrs = %{
      name: "Test Policy",
      description: "Test policy description",
      action_type: "quarantine",
      auto_threshold: 0.3,
      manual_threshold: 0.7,
      is_enabled: true,
      escalation_timeout_minutes: 60,
      organization_id: Ecto.UUID.generate()
    }

    merged_attrs = Map.merge(default_attrs, attrs)

    %Policy{}
    |> Policy.changeset(merged_attrs)
    |> Repo.insert()
  end

  defp create_test_workflow(attrs) do
    # Remove inserted_at from cast since it's set by Ecto
    inserted_at = Map.get(attrs, :inserted_at)
    attrs = Map.delete(attrs, :inserted_at)

    default_attrs = %{
      state: "pending",
      execution_mode: "pending_approval",
      action_type: "quarantine",
      action_config: %{},
      escalation_level: 0,
      escalation_timeout_minutes: 60,
      organization_id: Ecto.UUID.generate()
    }

    merged_attrs = Map.merge(default_attrs, attrs)

    %Workflow{}
    |> Workflow.changeset(merged_attrs)
    |> Repo.insert()
    |> case do
      {:ok, workflow} when not is_nil(inserted_at) ->
        # Update inserted_at directly for testing
        workflow
        |> Ecto.Changeset.change(%{inserted_at: inserted_at})
        |> Repo.update()

      result ->
        result
    end
  end
end
