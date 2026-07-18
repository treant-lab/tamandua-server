defmodule TamanduaServer.Remediation.ExecutorLiveSafetyTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Remediation.Executor

  describe "live_execution_admission/2" do
    test "admits only approval-required dry runs without bypass" do
      playbook = %{require_approval: true}

      assert :ok =
               Executor.live_execution_admission(playbook,
                 dry_run: true,
                 skip_approval: false
               )

      assert {:error, :live_execution_disabled} =
               Executor.live_execution_admission(playbook,
                 dry_run: false,
                 skip_approval: false
               )

      assert {:error, :approval_bypass_not_allowed} =
               Executor.live_execution_admission(playbook,
                 dry_run: true,
                 skip_approval: true
               )

      assert {:error, :approval_required} =
               Executor.live_execution_admission(%{require_approval: false},
                 dry_run: true,
                 skip_approval: false
               )
    end

    test "concurrent callers cannot race the live lock" do
      results =
        1..100
        |> Task.async_stream(
          fn _ ->
            Executor.live_execution_admission(%{require_approval: true},
              dry_run: false,
              skip_approval: false
            )
          end,
          max_concurrency: 20,
          ordered: false
        )
        |> Enum.to_list()

      assert Enum.all?(results, &(&1 == {:ok, {:error, :live_execution_disabled}}))
    end
  end

  test "every action crosses the dry-run-only final boundary" do
    source =
      File.read!(Path.expand("../../../lib/tamandua_server/remediation/executor.ex", __DIR__))

    assert source =~
             "defp execute_step_action(action, params, context, true)"

    assert source =~
             "defp execute_step_action(_action, _params, _context, _dry_run)"

    assert source =~
             "do: {:error, :live_execution_disabled}"

    refute Regex.match?(~r/defp execute_step_action\("[^"]+"/, source)
  end

  test "admission happens before execution persistence or task creation" do
    source =
      File.read!(Path.expand("../../../lib/tamandua_server/remediation/executor.ex", __DIR__))

    assert Regex.match?(
             ~r/def execute_playbook.*?live_execution_admission\(playbook, opts\).*?create_execution_record\(playbook, scoped_context, opts, scope\).*?Task\.start/s,
             source
           )

    assert Regex.match?(
             ~r/def approve_execution.*?validate_persisted_execution_admission\(execution\).*?execution_scope\(execution\).*?load_playbook\(execution\.playbook_id, execution_scope\).*?validate_playbook_for_execution\(playbook, execution\).*?validate_approver\(execution, approver_id\).*?Execution\.update_execution.*?Task\.start/s,
             source
           )
  end

  test "the public single-action path fails closed before any dispatch" do
    assert {:error, :live_execution_disabled} =
             Executor.execute_action(
               "isolate_network",
               %{"agent_id" => "agent-never-dispatched"},
               %{},
               {:organization, "tenant-command-spy"}
             )

    source =
      File.read!(Path.expand("../../../lib/tamandua_server/remediation/executor.ex", __DIR__))

    assert Regex.match?(
             ~r/def execute_action\(.*?execute_step_action\(action_type, params, scoped_context, false\)/s,
             source
           )
  end

  test "notification simulation does not claim a send" do
    source =
      File.read!(Path.expand("../../../lib/tamandua_server/remediation/executor.ex", __DIR__))

    assert Regex.match?(
             ~r/defp do_execute_step_action\("send_notification".*?sent: false.*?dry_run: dry_run/s,
             source
           )
  end

  test "worker and rollback paths recheck persisted dry-run admission" do
    source =
      File.read!(Path.expand("../../../lib/tamandua_server/remediation/executor.ex", __DIR__))

    assert Regex.match?(
             ~r/defp run_execution.*?get_execution\(execution\.id, scope\).*?validate_persisted_worker_admission\(execution\).*?load_playbook\(execution\.playbook_id, scope\).*?validate_playbook_for_execution\(playbook, execution\)/s,
             source
           )

    assert Regex.match?(
             ~r/defp validate_persisted_worker_admission\(%Execution\{.*?execution_mode: "dry_run".*?require_approval: true.*?status: "approved".*?approval_status: "approved"/s,
             source
           )

    assert Regex.match?(
             ~r/defp validate_playbook_for_execution\(.*?id: playbook_id.*?organization_id: organization_id.*?version: version.*?enabled: true.*?require_approval: true.*?playbook_id: playbook_id.*?organization_id: organization_id.*?playbook_version: version/s,
             source
           )

    assert Regex.match?(
             ~r/def rollback_execution.*?validate_persisted_execution_admission\(execution\).*?validate_rollback_available\(execution\)/s,
             source
           )

    assert Regex.match?(
             ~r/defp perform_rollback.*?validate_persisted_execution_admission\(execution\).*?defp do_perform_rollback.*?execute_step_action\(.*?true\s*\)/s,
             source
           )
  end
end
