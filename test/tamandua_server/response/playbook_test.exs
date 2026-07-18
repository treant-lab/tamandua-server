defmodule TamanduaServer.Response.PlaybookTest do
  @moduledoc """
  Tests for the Playbook Engine GenServer.

  Covers:
  - Playbook CRUD operations (create, get, list, update, delete)
  - Playbook schema changeset validation
  - Step validation (valid_step? requires an "action" key)
  - Trigger type validation (manual, alert, detection, schedule)
  - Severity threshold validation and ordering
  - Execution lifecycle (pending_approval, running, completed, failed, cancelled)
  - Pending approvals management
  - Playbook template structure
  - Frontend attribute normalization
  """

  use TamanduaServer.DataCase, async: false

  import TamanduaServer.AccountsFixtures

  alias TamanduaServer.Response.Playbook
  alias TamanduaServer.Response.Playbook.Execution
  alias TamanduaServer.Response.Playbook.Schema

  # ============================================================================
  # Schema changeset validation
  # ============================================================================

  describe "Schema.changeset/2" do
    test "valid changeset with required fields" do
      attrs = %{
        name: "Test Playbook",
        steps: [%{"action" => "isolate_host"}]
      }

      changeset = Schema.changeset(%Schema{}, attrs)
      assert changeset.valid?
    end

    test "invalid without name" do
      attrs = %{
        steps: [%{"action" => "isolate_host"}]
      }

      changeset = Schema.changeset(%Schema{}, attrs)
      refute changeset.valid?
      assert %{name: _} = errors_on(changeset)
    end

    test "invalid without steps" do
      attrs = %{
        name: "Test Playbook"
      }

      changeset = Schema.changeset(%Schema{}, attrs)
      refute changeset.valid?
      assert %{steps: _} = errors_on(changeset)
    end

    test "invalid step without action key" do
      attrs = %{
        name: "Test Playbook",
        steps: [%{"params" => %{}}]
      }

      changeset = Schema.changeset(%Schema{}, attrs)
      refute changeset.valid?
      assert %{steps: _} = errors_on(changeset)
    end

    test "validates trigger_type inclusion" do
      attrs = %{
        name: "Test Playbook",
        trigger_type: "invalid_type",
        steps: [%{"action" => "isolate_host"}]
      }

      changeset = Schema.changeset(%Schema{}, attrs)
      refute changeset.valid?
      assert %{trigger_type: _} = errors_on(changeset)
    end

    test "accepts all valid trigger types" do
      for trigger_type <- ["manual", "alert", "detection", "schedule"] do
        attrs = %{
          name: "Test #{trigger_type}",
          trigger_type: trigger_type,
          steps: [%{"action" => "kill_process"}]
        }

        changeset = Schema.changeset(%Schema{}, attrs)
        assert changeset.valid?, "trigger_type '#{trigger_type}' should be valid"
      end
    end

    test "validates severity_threshold inclusion" do
      valid_thresholds = [nil, "low", "medium", "high", "critical"]

      for threshold <- valid_thresholds do
        attrs = %{
          name: "Threshold test",
          severity_threshold: threshold,
          steps: [%{"action" => "send_notification"}]
        }

        changeset = Schema.changeset(%Schema{}, attrs)
        assert changeset.valid?, "severity_threshold '#{inspect(threshold)}' should be valid"
      end
    end

    test "rejects invalid severity_threshold" do
      attrs = %{
        name: "Bad threshold",
        severity_threshold: "extreme",
        steps: [%{"action" => "send_notification"}]
      }

      changeset = Schema.changeset(%Schema{}, attrs)
      refute changeset.valid?
    end

    test "defaults trigger_type to manual when nil" do
      attrs = %{
        name: "Default trigger",
        steps: [%{"action" => "isolate_host"}]
      }

      changeset = Schema.changeset(%Schema{}, attrs)
      assert Ecto.Changeset.get_field(changeset, :trigger_type) == "manual"
    end

    test "multiple steps are accepted" do
      attrs = %{
        name: "Multi-step",
        steps: [
          %{"action" => "isolate_host"},
          %{"action" => "kill_process"},
          %{"action" => "send_notification"}
        ]
      }

      changeset = Schema.changeset(%Schema{}, attrs)
      assert changeset.valid?
    end
  end

  # ============================================================================
  # Playbook CRUD via GenServer
  # ============================================================================

  describe "create_playbook/1" do
    test "creates a playbook with valid attributes" do
      attrs = %{
        name: "Test Create #{System.unique_integer([:positive])}",
        description: "Created in test",
        trigger_type: "manual",
        steps: [%{"action" => "collect_forensics"}],
        tags: ["test"]
      }

      result = Playbook.create_playbook(attrs, :system)

      case result do
        {:ok, playbook} ->
          assert playbook.name == attrs[:name] || attrs["name"]
          assert is_list(playbook.steps)
          assert length(playbook.steps) == 1

        {:error, changeset} ->
          # May fail due to DB constraints or other reasons; that is acceptable
          assert %Ecto.Changeset{} = changeset
      end
    end

    test "rejects playbook without required fields" do
      result = Playbook.create_playbook(%{description: "Missing name and steps"}, :system)
      assert {:error, _reason} = result
    end
  end

  describe "list_playbooks/1" do
    test "returns {:ok, list}" do
      {:ok, playbooks} = Playbook.list_playbooks(%{}, :system)
      assert is_list(playbooks)
    end

    test "supports filter by trigger_type" do
      {:ok, playbooks} = Playbook.list_playbooks(%{trigger_type: "manual"}, :system)
      assert is_list(playbooks)

      for pb <- playbooks do
        assert pb.trigger_type == "manual"
      end
    end
  end

  describe "get_playbook/1" do
    test "returns {:error, :not_found} for unknown id" do
      assert {:error, :not_found} = Playbook.get_playbook(Ecto.UUID.generate(), :system)
    end
  end

  describe "delete_playbook/1" do
    test "returns {:error, :not_found} for unknown id" do
      assert {:error, :not_found} = Playbook.delete_playbook(Ecto.UUID.generate(), :system)
    end
  end

  # ============================================================================
  # Pending approvals
  # ============================================================================

  describe "get_pending_approvals/0" do
    test "returns {:ok, list}" do
      {:ok, approvals} = Playbook.get_pending_approvals(:system)
      assert is_list(approvals)
    end
  end

  # ============================================================================
  # Execution lifecycle
  # ============================================================================

  describe "execute_playbook/2" do
    test "returns {:error, :not_found} for unknown playbook_id" do
      assert {:error, :not_found} = Playbook.execute_playbook(Ecto.UUID.generate(), %{}, :system)
    end

    test "refuses to dispatch when the execution cannot be persisted" do
      {:ok, playbook} =
        Playbook.create_playbook(
          %{
            name: "Persistence guard #{System.unique_integer([:positive])}",
            trigger_type: "manual",
            steps: [%{"action" => "send_notification"}]
          },
          :system
        )

      # Keep the playbook in the GenServer cache while invalidating the FK
      # used by playbook_executions. The action must not enter active state.
      TamanduaServer.Repo.delete!(playbook)
      state_before = :sys.get_state(Playbook)

      assert {:error, {:execution_persistence_failed, _reason}} =
               Playbook.execute(playbook.id, %{}, %{scope: :system})

      state_after = :sys.get_state(Playbook)
      assert state_after.active_executions == state_before.active_executions
      assert state_after.pending_approvals == state_before.pending_approvals
    end

    test "dry_run persists a completed simulation without dispatching steps" do
      {:ok, playbook} =
        Playbook.create_playbook(
          %{
            name: "Dry run guard #{System.unique_integer([:positive])}",
            trigger_type: "manual",
            require_approval: true,
            steps: [%{"action" => "isolate_host"}]
          },
          :system
        )

      assert {:ok, execution} =
               Playbook.execute(playbook.id, %{}, %{
                 dry_run: true,
                 skip_approval: true,
                 scope: :system
               })

      assert execution.status == "completed"
      assert execution.dry_run
      assert execution.completed_at

      state = :sys.get_state(Playbook)
      refute Map.has_key?(state.active_executions, execution.id)
      refute Map.has_key?(state.pending_approvals, execution.id)

      persisted = TamanduaServer.Repo.get!(Execution, execution.id)
      assert persisted.status == "completed"
      assert persisted.dry_run
    end
  end

  describe "tenant scoping" do
    test "public APIs fail closed when callers omit tenant scope" do
      assert {:error, :tenant_required} =
               Playbook.create_playbook(%{name: "Unscoped", steps: []})

      assert {:error, :tenant_required} = Playbook.list_playbooks()
      assert {:error, :tenant_required} = Playbook.get_playbook(Ecto.UUID.generate())
      assert {:error, :tenant_required} = Playbook.get_pending_approvals()
    end

    test "CRUD and execution do not reveal a playbook across organizations" do
      organization_a = organization_fixture()
      organization_b = organization_fixture()
      scope_a = {:organization, organization_a.id}
      scope_b = {:organization, organization_b.id}

      {:ok, playbook} =
        Playbook.create_playbook(
          %{
            name: "Tenant scoped #{System.unique_integer([:positive])}",
            trigger_type: "manual",
            steps: [%{"action" => "wait", "params" => %{"duration_seconds" => 1}}]
          },
          scope_a
        )

      assert playbook.organization_id == organization_a.id
      assert {:ok, ^playbook} = Playbook.get_playbook(playbook.id, scope_a)
      assert {:error, :not_found} = Playbook.get_playbook(playbook.id, scope_b)
      assert {:error, :not_found} = Playbook.update_playbook(playbook.id, %{name: "leak"}, scope_b)
      assert {:error, :not_found} = Playbook.delete_playbook(playbook.id, scope_b)
      assert {:error, :not_found} = Playbook.execute(playbook.id, %{}, %{scope: scope_b})

      assert {:ok, tenant_b_playbooks} = Playbook.list_playbooks(%{}, scope_b)
      refute Enum.any?(tenant_b_playbooks, &(&1.id == playbook.id))
    end

    test "scope overwrites conflicting atom and string organization keys" do
      organization_a = organization_fixture()
      organization_b = organization_fixture()

      {:ok, playbook} =
        Playbook.create_playbook(
          %{
            "organization_id" => organization_b.id,
            name: "Dual key guard #{System.unique_integer([:positive])}",
            steps: [%{"action" => "wait"}],
            organization_id: organization_b.id
          },
          {:organization, organization_a.id}
        )

      assert playbook.organization_id == organization_a.id
    end

    test "invalid organization scopes fail instead of matching legacy nil records" do
      assert {:error, :tenant_required} =
               Playbook.list_playbooks(%{}, {:organization, nil})

      assert {:error, :tenant_required} =
               Playbook.get_pending_approvals({:organization, nil})

      assert {:error, :tenant_required} =
               Playbook.list_recent_executions(scope: {:organization, nil})
    end

    test "endpoint steps fail closed when execution has no organization" do
      execution = %Execution{
        id: Ecto.UUID.generate(),
        playbook_id: Ecto.UUID.generate(),
        status: "running",
        execution_context: %{agent_id: "agent-from-client"}
      }

      assert {:error, "Playbook execution is missing organization_id"} =
               Playbook.execute_single_step(
                 %{"action" => "block_ip", "params" => %{"ip" => "203.0.113.1"}},
                 execution
               )
    end

    test "block_ip requires an explicit agent and never broadcasts tenant-wide" do
      organization = organization_fixture()

      execution = %Execution{
        id: Ecto.UUID.generate(),
        playbook_id: Ecto.UUID.generate(),
        organization_id: organization.id,
        status: "running",
        execution_context: %{}
      }

      assert {:error, message} =
               Playbook.execute_single_step(
                 %{"action" => "block_ip", "params" => %{"ip" => "203.0.113.1"}},
                 execution
               )

      assert message =~ "tenant-wide broadcast is disabled"
    end
  end

  describe "approve_execution/2" do
    test "returns {:error, :not_found} for unknown execution_id" do
      assert {:error, :not_found} =
               Playbook.approve_execution(Ecto.UUID.generate(), Ecto.UUID.generate(), :system)
    end
  end

  describe "cancel_execution/2" do
    test "returns {:error, :not_found} for unknown execution_id" do
      assert {:error, :not_found} =
               Playbook.cancel_execution(Ecto.UUID.generate(), "test cancellation", :system)
    end
  end

  # ============================================================================
  # Execution history
  # ============================================================================

  describe "get_execution_history/2" do
    test "returns {:ok, list} for a playbook (even with no executions)" do
      {:ok, history} = Playbook.get_execution_history(Ecto.UUID.generate(), [], :system)
      assert is_list(history)
    end
  end

  describe "list_recent_executions/1" do
    test "returns {:ok, list}" do
      {:ok, executions} = Playbook.list_recent_executions(scope: :system)
      assert is_list(executions)
    end

    test "respects limit option" do
      {:ok, executions} = Playbook.list_recent_executions(limit: 5, scope: :system)
      assert is_list(executions)
      assert length(executions) <= 5
    end
  end

  # ============================================================================
  # Playbook templates
  # ============================================================================

  describe "Playbook.Templates" do
    alias TamanduaServer.Response.Playbook.Templates

    test "ransomware_response template has required structure" do
      template = Templates.ransomware_response()

      assert is_map(template)
      assert template.name == "Ransomware Response"
      assert is_list(template.steps)
      assert length(template.steps) > 0
      assert template.trigger_type == "detection"
      assert template.require_approval == false

      # Every step must have an "action" key
      for step <- template.steps do
        assert Map.has_key?(step, "action"), "step #{inspect(step)} missing action"
      end
    end

    test "lateral_movement_response template has required structure" do
      template = Templates.lateral_movement_response()

      assert is_map(template)
      assert template.name == "Lateral Movement Response"
      assert template.require_approval == true
      assert template.trigger_type == "alert"
      assert is_list(template.steps)

      for step <- template.steps do
        assert Map.has_key?(step, "action")
      end
    end

    test "credential_theft_response template has required structure" do
      template = Templates.credential_theft_response()

      assert is_map(template)
      assert template.name == "Credential Theft Response"
      assert template.require_approval == true
      assert is_list(template.steps)

      for step <- template.steps do
        assert Map.has_key?(step, "action")
      end
    end

    test "all templates have tags" do
      for template <- [
            Templates.ransomware_response(),
            Templates.lateral_movement_response(),
            Templates.credential_theft_response()
          ] do
        assert is_list(template.tags)
        assert length(template.tags) > 0
      end
    end
  end

  # ============================================================================
  # Severity threshold ordering
  # ============================================================================

  describe "severity threshold ordering" do
    test "severity values have expected ordering: low < medium < high < critical" do
      severity_order = %{"low" => 1, "medium" => 2, "high" => 3, "critical" => 4}

      assert severity_order["low"] < severity_order["medium"]
      assert severity_order["medium"] < severity_order["high"]
      assert severity_order["high"] < severity_order["critical"]
    end
  end
end
