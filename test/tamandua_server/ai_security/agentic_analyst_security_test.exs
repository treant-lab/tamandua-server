defmodule TamanduaServer.AISecurity.AgenticAnalystSecurityTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.AISecurity.AgenticAnalyst
  alias TamanduaServerWeb.API.V1.AnalystController
  alias TamanduaServerWeb.API.V1.ApprovalExecutionController

  describe "tenant scoping" do
    test "public triage entrypoints fail closed without an organization" do
      assert {:error, :organization_required} = AgenticAnalyst.triage_alert("alert-id")
      assert {:error, :organization_required} = AgenticAnalyst.triage_batch(["alert-id"])
      assert {:error, :organization_required} = AgenticAnalyst.auto_triage("alert-id")
      assert {:error, :organization_required} = AgenticAnalyst.get_investigation("inv-id")
      assert {:error, :organization_required} = AgenticAnalyst.get_investigation("inv-id", [])
      assert {:error, :organization_required} = AgenticAnalyst.start_investigation(%{})
      assert {:error, :organization_required} = AgenticAnalyst.submit_feedback("inv-id", %{})
      assert {:error, :organization_required} = AgenticAnalyst.approve_action("inv-id", "rec-id")

      assert {:error, :approver_required} =
               AgenticAnalyst.approve_action("inv-id", "rec-id", Ecto.UUID.generate())

      assert {:error, :approver_required} =
               AgenticAnalyst.approve_action(
                 "inv-id",
                 "rec-id",
                 Ecto.UUID.generate(),
                 nil
               )

      assert {:error, :organization_required} =
               AgenticAnalyst.reject_action("inv-id", "rec-id", "no")

      assert {:error, :organization_required} = AgenticAnalyst.explain_investigation("inv-id")

      assert {:error, :organization_required} =
               AgenticAnalyst.resolve_investigation("inv-id", %{status: :closed})

      assert {:error, :organization_required} = AgenticAnalyst.get_stats()
      assert {:error, :organization_required} = AgenticAnalyst.get_stats(nil)
      assert {:error, :organization_required} = AgenticAnalyst.get_insights()
      assert {:error, :organization_required} = AgenticAnalyst.get_insights("inv-id")
      assert {:error, :organization_required} = AgenticAnalyst.get_insights([])
      assert {:error, :organization_required} = AgenticAnalyst.get_chat_history()
      assert {:error, :organization_required} = AgenticAnalyst.get_chat_history("inv-id")
      assert {:error, :organization_required} = AgenticAnalyst.get_chat_history([])

      assert {:error, :organization_required} =
               AgenticAnalyst.add_chat_message("inv-id", %{content: "legacy"})

      assert [] = AgenticAnalyst.list_investigations()
    end

    test "same investigation id remains independently addressable across tenants" do
      organization_id = Ecto.UUID.generate()
      other_organization_id = Ecto.UUID.generate()
      investigation_id = "inv_collision_regression"
      now = DateTime.utc_now()

      first = %AgenticAnalyst.Investigation{
        id: investigation_id,
        organization_id: organization_id,
        alert_id: Ecto.UUID.generate(),
        alert: %{title: "first tenant"},
        state: :pending,
        updated_at: now
      }

      second = %AgenticAnalyst.Investigation{
        id: investigation_id,
        organization_id: other_organization_id,
        alert_id: Ecto.UUID.generate(),
        alert: %{title: "second tenant"},
        state: :triaging,
        updated_at: now
      }

      :sys.replace_state(AgenticAnalyst, fn state ->
        :ets.insert(:agentic_investigations, {
          {organization_id, investigation_id},
          first
        })

        :ets.insert(:agentic_investigations, {
          {other_organization_id, investigation_id},
          second
        })

        state
      end)

      on_exit(fn ->
        :sys.replace_state(AgenticAnalyst, fn state ->
          :ets.delete(:agentic_investigations, {organization_id, investigation_id})
          :ets.delete(:agentic_investigations, {other_organization_id, investigation_id})
          state
        end)
      end)

      assert {:ok, %{alert: %{title: "first tenant"}}} =
               AgenticAnalyst.get_investigation(investigation_id,
                 organization_id: organization_id
               )

      assert {:ok, %{alert: %{title: "second tenant"}}} =
               AgenticAnalyst.get_investigation(investigation_id,
                 organization_id: other_organization_id
               )

      assert [first_listed] =
               AgenticAnalyst.list_investigations(organization_id: organization_id)

      assert first_listed.alert.title == "first tenant"
    end
  end

  describe "automatic response approval gate" do
    test "disabled auto-action policy preserves eligible recommendations for review" do
      organization_id = Ecto.UUID.generate()
      investigation_id = "inv_auto_action_disabled_#{System.unique_integer([:positive])}"

      recommendation = %AgenticAnalyst.Recommendation{
        id: "rec-auto-disabled",
        action_type: :escalate_to_soc,
        target: :investigation,
        parameters: %{},
        confidence: 1.0,
        rationale: "policy gate regression",
        risk_level: :low,
        requires_approval: false,
        auto_executable: true
      }

      investigation = %AgenticAnalyst.Investigation{
        id: investigation_id,
        organization_id: organization_id,
        alert_id: Ecto.UUID.generate(),
        alert: %{title: "policy gate", severity: "critical", agent_id: "offline-agent"},
        state: :action_recommendation,
        updated_at: DateTime.utc_now(),
        triage_result: %{priority: :critical, confidence: 1.0},
        hypotheses: [],
        evidence: [],
        correlations: [],
        recommendations: [recommendation],
        confidence: 1.0
      }

      :sys.replace_state(AgenticAnalyst, fn state ->
        :ets.insert(
          :agentic_investigations,
          {{organization_id, investigation_id}, investigation}
        )

        %{state | config: Map.put(state.config, :auto_action_enabled, false)}
      end)

      on_exit(fn ->
        :sys.replace_state(AgenticAnalyst, fn state ->
          :ets.delete(:agentic_investigations, {organization_id, investigation_id})
          state
        end)
      end)

      send(AgenticAnalyst, {:continue_investigation, organization_id, investigation_id})

      assert {:ok, updated} =
               AgenticAnalyst.get_investigation(investigation_id,
                 organization_id: organization_id
               )

      assert updated.state == :awaiting_review
      assert [%{id: "rec-auto-disabled"}] = updated.recommendations
      assert AgenticAnalyst.get_stats(organization_id).actions_executed == 0
    end

    test "never auto-executes a recommendation requiring approval" do
      recommendation = %{
        requires_approval: true,
        auto_executable: true,
        confidence: 1.0
      }

      refute AgenticAnalyst.auto_executable_recommendation?(recommendation)
    end

    test "a rejected recommendation is never eligible for automatic execution" do
      recommendation = %{
        rejected: true,
        requires_approval: false,
        auto_executable: true,
        confidence: 1.0
      }

      refute AgenticAnalyst.auto_executable_recommendation?(recommendation)
    end

    test "configuration alone cannot unlock automatic response execution" do
      organization_id = Ecto.UUID.generate()
      investigation_id = "inv_auto_action_locked_#{System.unique_integer([:positive])}"

      recommendation = %AgenticAnalyst.Recommendation{
        id: "rec-auto-locked",
        action_type: :escalate_to_soc,
        target: :investigation,
        parameters: %{},
        confidence: 1.0,
        rationale: "automatic response product lock regression",
        risk_level: :low,
        requires_approval: false,
        auto_executable: true
      }

      investigation = %AgenticAnalyst.Investigation{
        id: investigation_id,
        organization_id: organization_id,
        alert_id: Ecto.UUID.generate(),
        alert: %{title: "product lock", severity: "critical", agent_id: "offline-agent"},
        state: :action_recommendation,
        updated_at: DateTime.utc_now(),
        triage_result: %{priority: :critical, confidence: 1.0},
        hypotheses: [],
        evidence: [],
        correlations: [],
        recommendations: [recommendation],
        confidence: 1.0
      }

      :sys.replace_state(AgenticAnalyst, fn state ->
        :ets.insert(
          :agentic_investigations,
          {{organization_id, investigation_id}, investigation}
        )

        %{state | config: Map.put(state.config, :auto_action_enabled, true)}
      end)

      on_exit(fn ->
        :sys.replace_state(AgenticAnalyst, fn state ->
          :ets.delete(:agentic_investigations, {organization_id, investigation_id})
          %{state | config: Map.put(state.config, :auto_action_enabled, false)}
        end)
      end)

      send(AgenticAnalyst, {:continue_investigation, organization_id, investigation_id})

      assert {:ok, updated} =
               AgenticAnalyst.get_investigation(investigation_id,
                 organization_id: organization_id
               )

      assert updated.state == :awaiting_review
      assert [%{id: "rec-auto-locked"}] = updated.recommendations
      assert AgenticAnalyst.get_stats(organization_id).actions_executed == 0
    end

    test "fails closed when the approval field is absent" do
      recommendation = %{auto_executable: true, confidence: 1.0}

      refute AgenticAnalyst.auto_executable_recommendation?(recommendation)
    end

    test "only accepts an explicit no-approval high-confidence recommendation" do
      recommendation = %{
        requires_approval: false,
        auto_executable: true,
        confidence: 0.99
      }

      assert AgenticAnalyst.auto_executable_recommendation?(recommendation)
    end
  end

  describe "HTTP response approval authorization" do
    test "approval route is registered in the authenticated API router" do
      route =
        Phoenix.Router.route_info(
          TamanduaServerWeb.Router,
          "POST",
          "/api/v1/analyst/investigations/inv-id/recommendations/rec-id/approve",
          "localhost"
        )

      assert route.plug == AnalystController
      assert route.plug_opts == :approve_action
    end

    test "controller fails closed when the authenticated member lacks response approval" do
      conn =
        Plug.Test.conn(
          "POST",
          "/api/v1/analyst/investigations/inv-id/recommendations/rec-id/approve"
        )
        |> Plug.Conn.assign(:current_user, %{
          id: Ecto.UUID.generate(),
          organization_id: Ecto.UUID.generate()
        })

      assert {:error, :unauthorized} =
               AnalystController.approve_action(conn, %{
                 "id" => "inv-id",
                 "recommendation_id" => "rec-id"
               })
    end

    test "execution status and reconciliation fail closed without RBAC permission" do
      conn =
        Plug.Test.conn("GET", "/api/v1/analyst/approval-executions/execution-id")
        |> Plug.Conn.assign(:current_user, %{
          id: Ecto.UUID.generate(),
          organization_id: Ecto.UUID.generate()
        })

      assert {:error, :unauthorized} =
               ApprovalExecutionController.index(conn, %{})

      assert {:error, :unauthorized} =
               ApprovalExecutionController.show(conn, %{"id" => Ecto.UUID.generate()})

      assert {:error, :unauthorized} =
               ApprovalExecutionController.reconcile(conn, %{
                 "id" => Ecto.UUID.generate(),
                 "outcome" => "succeeded",
                 "evidence_ref" => %{
                   "type" => "agent_command",
                   "id" => Ecto.UUID.generate()
                 }
               })
    end

    test "reconciliation queue route is registered before the dynamic execution route" do
      route =
        Phoenix.Router.route_info(
          TamanduaServerWeb.Router,
          "GET",
          "/api/v1/analyst/approval-executions",
          "localhost"
        )

      assert route.plug == ApprovalExecutionController
      assert route.plug_opts == :index
    end
  end
end
