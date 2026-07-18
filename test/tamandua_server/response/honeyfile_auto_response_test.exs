defmodule TamanduaServer.Response.HoneyfileAutoResponseTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Response.HoneyfileAutoResponse

  describe "plan/4" do
    test "defaults to dry-run containment plan for honeyfile access" do
      plan =
        HoneyfileAutoResponse.plan(
          %{id: "breadcrumb-1", agent_id: "agent-1", type: "credential", path: "/tmp/decoy.txt"},
          %{agent_id: "agent-1", process_name: "suspicious.exe", pid: 4242, user: "alice"},
          %{id: "alert-1"},
          %{}
        )

      assert plan.trigger == :honeyfile_access
      assert plan.confidence == 1.0
      assert plan.dry_run == true
      assert plan.policy_gate == :dry_run
      refute HoneyfileAutoResponse.executable?(plan)

      assert Enum.map(plan.actions, & &1.action_type) == [
               "kill_process",
               "isolate_network",
               "collect_forensics"
             ]

      assert plan.metadata.alert_id == "alert-1"
      assert plan.metadata.agent_id == "agent-1"
      assert plan.metadata.pid == 4242
    end

    test "requires explicit autonomous containment opt-in before execution" do
      base_config = %{
        mode: :auto_execute,
        dry_run: false,
        allow_autonomous_containment: false
      }

      plan =
        HoneyfileAutoResponse.plan(
          %{id: "breadcrumb-1", agent_id: "agent-1", type: "document", path: "/tmp/decoy.txt"},
          %{agent_id: "agent-1", pid: 4242},
          %{id: "alert-1"},
          base_config
        )

      assert plan.dry_run == true
      assert plan.policy_gate == :dry_run
      refute HoneyfileAutoResponse.executable?(plan)

      executable_plan =
        HoneyfileAutoResponse.plan(
          %{id: "breadcrumb-1", agent_id: "agent-1", type: "document", path: "/tmp/decoy.txt"},
          %{agent_id: "agent-1", pid: 4242},
          %{id: "alert-1"},
          %{base_config | allow_autonomous_containment: true}
        )

      assert executable_plan.dry_run == false
      assert executable_plan.policy_gate == :auto_execute
      assert HoneyfileAutoResponse.executable?(executable_plan)
    end

    test "does not plan process kill without a pid" do
      plan =
        HoneyfileAutoResponse.plan(
          %{id: "breadcrumb-1", agent_id: "agent-1", type: "api_token", path: "/tmp/token"},
          %{agent_id: "agent-1", process_name: "curl"},
          nil,
          %{create_snapshot: false}
        )

      assert Enum.map(plan.actions, & &1.action_type) == ["isolate_network"]
      assert plan.dry_run == true
    end
  end
end
