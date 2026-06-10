defmodule TamanduaServer.Remediation.AuditTrailTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.Remediation.{AuditTrail, Workflow, Policy}
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Repo

  describe "log_event/4" do
    setup do
      organization_id = Ecto.UUID.generate()

      {:ok, alert} = create_test_alert(%{organization_id: organization_id})
      {:ok, policy} = create_test_policy(%{organization_id: organization_id})
      {:ok, workflow} = create_test_workflow(%{
        alert_id: alert.id,
        policy_id: policy.id,
        organization_id: organization_id
      })

      user = %User{
        id: Ecto.UUID.generate(),
        email: "analyst@example.com"
      }

      %{workflow: workflow, organization_id: organization_id, user: user}
    end

    test "creates audit event with all required fields", %{workflow: workflow, user: user} do
      {:ok, event} = AuditTrail.log_event(workflow, :created, :system, %{note: "Initial creation"})

      assert event.workflow_id == workflow.id
      assert event.organization_id == workflow.organization_id
      assert event.event_type == "created"
      assert event.actor_type == "system"
      assert event.actor_email == "system"
      assert event.details == %{note: "Initial creation"}
      assert event.inserted_at != nil
    end

    test "logs event with user actor", %{workflow: workflow, user: user} do
      {:ok, event} = AuditTrail.log_event(workflow, :approved, user, %{notes: "Approved after investigation"})

      assert event.actor_type == "user"
      assert event.actor_id == user.id
      assert event.actor_email == user.email
      assert event.event_type == "approved"
    end

    test "logs event with system actor", %{workflow: workflow} do
      {:ok, event} = AuditTrail.log_event(workflow, :started, :system)

      assert event.actor_type == "system"
      assert event.actor_id == nil
      assert event.actor_email == "system"
    end

    test "logs event with oban worker actor", %{workflow: workflow} do
      {:ok, event} = AuditTrail.log_event(workflow, :completed, {:oban, 12345}, %{result: "success"})

      assert event.actor_type == "oban_worker"
      assert event.actor_id == "12345"
      assert event.actor_email == "Oban job #12345"
    end

    test "includes actor_id, actor_type, and metadata", %{workflow: workflow, user: user} do
      details = %{
        reason: "High confidence threat",
        threat_score: 0.95,
        action_config: %{timeout: 30}
      }

      {:ok, event} = AuditTrail.log_event(workflow, :approved, user, details)

      assert event.actor_id == user.id
      assert event.actor_type == "user"
      assert event.details["reason"] == "High confidence threat"
      assert event.details["threat_score"] == 0.95
    end
  end

  describe "list_events/2" do
    setup do
      organization_id = Ecto.UUID.generate()
      {:ok, alert} = create_test_alert(%{organization_id: organization_id})
      {:ok, policy} = create_test_policy(%{organization_id: organization_id})
      {:ok, workflow} = create_test_workflow(%{
        alert_id: alert.id,
        policy_id: policy.id,
        organization_id: organization_id
      })

      # Create multiple events
      {:ok, _} = AuditTrail.log_event(workflow, :created, :system)
      Process.sleep(10)
      {:ok, _} = AuditTrail.log_event(workflow, :approved, :system)
      Process.sleep(10)
      {:ok, _} = AuditTrail.log_event(workflow, :started, :system)

      %{workflow: workflow}
    end

    test "returns events for workflow in chronological order", %{workflow: workflow} do
      events = AuditTrail.list_events(workflow.id)

      assert length(events) == 3
      assert Enum.at(events, 0).event_type == "created"
      assert Enum.at(events, 1).event_type == "approved"
      assert Enum.at(events, 2).event_type == "started"
    end

    test "respects limit option", %{workflow: workflow} do
      events = AuditTrail.list_events(workflow.id, limit: 2)

      assert length(events) == 2
    end

    test "supports descending order", %{workflow: workflow} do
      events = AuditTrail.list_events(workflow.id, order: :desc)

      assert length(events) == 3
      assert Enum.at(events, 0).event_type == "started"
      assert Enum.at(events, 2).event_type == "created"
    end
  end

  describe "get_workflow_history/1" do
    setup do
      organization_id = Ecto.UUID.generate()
      {:ok, alert} = create_test_alert(%{organization_id: organization_id})
      {:ok, policy} = create_test_policy(%{organization_id: organization_id})
      {:ok, workflow} = create_test_workflow(%{
        alert_id: alert.id,
        policy_id: policy.id,
        organization_id: organization_id
      })

      # Create events
      {:ok, _} = AuditTrail.log_event(workflow, :created, :system)
      {:ok, _} = AuditTrail.log_event(workflow, :approved, :system, %{notes: "Approved"})
      {:ok, _} = AuditTrail.log_event(workflow, :completed, :system, %{result: "success"})

      %{workflow: workflow}
    end

    test "returns complete timeline with formatted events", %{workflow: workflow} do
      history = AuditTrail.get_workflow_history(workflow.id)

      assert length(history) == 3

      first = Enum.at(history, 0)
      assert first.event_type == "created"
      assert first.actor_email == "system"
      assert first.timestamp != nil
      assert first.formatted_time != nil
    end
  end

  describe "immutability" do
    setup do
      organization_id = Ecto.UUID.generate()
      {:ok, alert} = create_test_alert(%{organization_id: organization_id})
      {:ok, policy} = create_test_policy(%{organization_id: organization_id})
      {:ok, workflow} = create_test_workflow(%{
        alert_id: alert.id,
        policy_id: policy.id,
        organization_id: organization_id
      })

      %{workflow: workflow}
    end

    test "audit events are immutable - no update/delete functions", %{workflow: workflow} do
      {:ok, event} = AuditTrail.log_event(workflow, :created, :system)

      # Verify the module doesn't expose update/delete functions
      refute function_exported?(AuditTrail, :update_event, 2)
      refute function_exported?(AuditTrail, :delete_event, 1)

      # Schema doesn't have updated_at field (append-only)
      refute Map.has_key?(event, :updated_at)
    end
  end

  # Helper functions

  defp create_test_alert(attrs) do
    default_attrs = %{
      title: "Test Alert",
      description: "Test alert description",
      severity: "medium",
      status: "new",
      threat_score: 0.5,
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
      organization_id: Ecto.UUID.generate()
    }

    merged_attrs = Map.merge(default_attrs, attrs)

    %Policy{}
    |> Policy.changeset(merged_attrs)
    |> Repo.insert()
  end

  defp create_test_workflow(attrs) do
    default_attrs = %{
      state: "pending",
      execution_mode: "pending_approval",
      action_type: "quarantine",
      action_config: %{},
      organization_id: Ecto.UUID.generate()
    }

    merged_attrs = Map.merge(default_attrs, attrs)

    %Workflow{}
    |> Workflow.changeset(merged_attrs)
    |> Repo.insert()
  end
end
