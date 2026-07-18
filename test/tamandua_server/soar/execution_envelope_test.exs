defmodule TamanduaServer.SOAR.ExecutionEnvelopeTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Playbooks.Executor
  alias TamanduaServer.SOAR.ExecutionEnvelope

  test "wraps a real local playbook dry-run with approval and audit controls" do
    playbook = %{
      "name" => "Notify analyst",
      "trigger" => %{},
      "actions" => [%{"action" => "send_notification", "params" => %{"channel" => "slack"}}]
    }

    assert {:ok, result} = Executor.execute(playbook, %{alert_id: "alert-1"}, dry_run: true)

    envelope =
      ExecutionEnvelope.wrap(:playbook, {:ok, result},
        execution_id: "exec-1",
        idempotency_key: "alert-1:notify:v1",
        approval_required: true
      )

    assert envelope.schema == "tamandua.soar.execution/v1"
    assert envelope.engine == "playbook"
    assert envelope.status == "pending_approval"
    assert envelope.dry_run

    assert envelope.approval == %{
             required: true,
             status: "pending",
             approved_by: nil,
             rejected_by: nil
           }

    assert envelope.idempotency.enforced
    assert envelope.controls.auditable
    refute envelope.controls.ready_to_execute
    assert [%{action: "send_notification", status: "completed"}] = envelope.evidence
  end

  test "normalizes external SOAR failure, retry and rollback metadata" do
    execution = %{
      id: "soar-22",
      platform: :xsoar,
      playbook_name: "Contain endpoint",
      status: "failed",
      retry_count: 1,
      error_message: "upstream timeout"
    }

    envelope =
      ExecutionEnvelope.wrap(:soar, execution,
        idempotency_key: "incident-7:contain:v2",
        max_retries: 3,
        rollback_policy: :rollback,
        evidence: [%{action: "dispatch", status: "failed", result: %{http_status: 504}}]
      )

    assert envelope.status == "failed"
    assert envelope.target.platform == :xsoar
    assert envelope.retry == %{attempt: 1, max_attempts: 3, retryable: true, next_retry_at: nil}
    assert envelope.rollback.available
    assert envelope.rollback.status == "not_started"
    assert envelope.error == "upstream timeout"
    assert envelope.controls.auditable
  end

  test "normalizes DAG step maps and records an approved gate" do
    dag = %{
      id: "dag-1",
      status: :completed,
      steps: %{
        "isolate" => %{
          action: :network_isolate,
          status: :completed,
          result: %{agent_id: "agent-1"}
        }
      }
    }

    envelope =
      ExecutionEnvelope.wrap(:dag, dag,
        approval_required: true,
        approved_by: "analyst-1",
        idempotency_key: "alert-1:dag:v1"
      )

    assert envelope.status == "completed"
    assert envelope.approval.status == "approved"
    assert envelope.controls.ready_to_execute
    assert [%{action: :network_isolate, status: "completed"}] = envelope.evidence
  end

  test "rejects unknown engine labels instead of silently degrading" do
    assert_raise ArgumentError, ~r/unsupported SOAR execution engine/, fn ->
      ExecutionEnvelope.wrap(:unknown, %{})
    end
  end
end
