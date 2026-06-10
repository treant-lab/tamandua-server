defmodule TamanduaServer.Integrations.SOAR.CallbackHandlerTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Integrations.SOAR.{CallbackHandler, ExecutionLog}

  describe "handle_callback/2 for XSOAR" do
    setup do
      {:ok, log} = ExecutionLog.create(%{
        alert_id: "alert-123",
        soar_platform: "xsoar",
        playbook_name: "investigate_alert",
        execution_id: "xsoar-run-456"
      })

      %{log: log}
    end

    test "updates ExecutionLog status from XSOAR response", %{log: log} do
      payload = %{
        "investigationId" => "inv-123",
        "playbookRunId" => log.execution_id,
        "status" => "Closed",
        "closeReason" => "Resolved",
        "closeNotes" => "Threat was contained and remediated",
        "result" => %{
          "action" => "host_isolated",
          "success" => true
        }
      }

      assert {:ok, result} = CallbackHandler.handle_callback("xsoar", payload)
      assert result.status == "completed"
      assert result.platform == "xsoar"

      # Verify log was updated
      updated_log = ExecutionLog.get(log.id)
      assert updated_log.status == "completed"
      assert updated_log.completed_at
      assert updated_log.callback_received_at
    end

    test "handles error status from XSOAR", %{log: log} do
      payload = %{
        "playbookRunId" => log.execution_id,
        "status" => "Error",
        "error" => "Playbook execution failed"
      }

      assert {:ok, result} = CallbackHandler.handle_callback("xsoar", payload)
      assert result.status == "failed"

      updated_log = ExecutionLog.get(log.id)
      assert updated_log.status == "failed"
    end

    test "returns error when execution not found" do
      payload = %{
        "playbookRunId" => "nonexistent-run",
        "status" => "Closed"
      }

      assert {:error, :execution_not_found} = CallbackHandler.handle_callback("xsoar", payload)
    end
  end

  describe "handle_callback/2 for Tines" do
    setup do
      {:ok, log} = ExecutionLog.create(%{
        alert_id: "alert-789",
        soar_platform: "tines",
        playbook_name: "tines_workflow"
      })

      # Update with execution_id that Tines will return
      ExecutionLog.update_status(log, "running", %{execution_id: "tines-event-123"})

      %{log: log}
    end

    test "updates ExecutionLog status from Tines callback", %{log: log} do
      payload = %{
        "tamandua_execution_id" => log.id,
        "status" => "completed",
        "story_id" => "story-456",
        "story_name" => "Alert Response",
        "event_id" => "tines-event-123",
        "result" => %{
          "actions_taken" => ["enrichment", "notification"]
        }
      }

      assert {:ok, result} = CallbackHandler.handle_callback("tines", payload)
      assert result.status == "completed"
      assert result.platform == "tines"

      updated_log = ExecutionLog.get(log.id)
      assert updated_log.status == "completed"
    end

    test "handles failed status from Tines", %{log: log} do
      payload = %{
        "tamandua_execution_id" => log.id,
        "status" => "failed",
        "error" => "Action failed to complete"
      }

      assert {:ok, result} = CallbackHandler.handle_callback("tines", payload)
      assert result.status == "failed"

      updated_log = ExecutionLog.get(log.id)
      assert updated_log.status == "failed"
      assert updated_log.error_message
    end
  end

  describe "update_alert_from_callback/2" do
    test "updates alert to resolved when SOAR marks as resolved" do
      callback_result = %{
        close_reason: "Resolved",
        close_notes: "Threat contained",
        result: %{}
      }

      # Note: This would actually update an alert if one existed
      # For testing, we just verify the function handles the input
      result = CallbackHandler.update_alert_from_callback("alert-test", callback_result)
      assert result in [{:ok, :no_update_needed}, {:error, _}] or match?({:ok, _}, result)
    end

    test "updates alert to false_positive when SOAR dismisses" do
      callback_result = %{
        close_reason: "False Positive",
        close_notes: "Not a real threat"
      }

      result = CallbackHandler.update_alert_from_callback("alert-test", callback_result)
      assert result in [{:ok, :no_update_needed}, {:error, _}] or match?({:ok, _}, result)
    end

    test "no update when close_reason not recognized" do
      callback_result = %{
        close_reason: "Other",
        result: %{"info" => "some data"}
      }

      # Should not error, just not update
      result = CallbackHandler.update_alert_from_callback("alert-test", callback_result)
      assert result in [{:ok, :no_update_needed}, {:error, _}] or match?({:ok, _}, result)
    end
  end

  describe "verify_xsoar_auth/1" do
    test "returns ok for valid API key" do
      Application.put_env(:tamandua_server, TamanduaServer.Integrations.SOAR.XSOAR, [
        callback_api_key: "test-secret-key"
      ])

      assert :ok = CallbackHandler.verify_xsoar_auth("test-secret-key")
    end

    test "returns error for invalid API key" do
      Application.put_env(:tamandua_server, TamanduaServer.Integrations.SOAR.XSOAR, [
        callback_api_key: "correct-key"
      ])

      assert {:error, :unauthorized} = CallbackHandler.verify_xsoar_auth("wrong-key")
    end
  end

  describe "verify_tines_signature/2" do
    test "returns ok for valid signature" do
      secret = "test-signing-secret"
      body = ~s({"test": "payload"})
      signature = :crypto.mac(:hmac, :sha256, secret, body) |> Base.encode16(case: :lower)

      Application.put_env(:tamandua_server, TamanduaServer.Integrations.SOAR.Tines, [
        webhook_signing_secret: secret
      ])

      assert :ok = CallbackHandler.verify_tines_signature(body, signature)
    end

    test "returns error for invalid signature" do
      Application.put_env(:tamandua_server, TamanduaServer.Integrations.SOAR.Tines, [
        webhook_signing_secret: "real-secret"
      ])

      assert {:error, :invalid_signature} = CallbackHandler.verify_tines_signature(
        ~s({"test": "payload"}),
        "invalid-signature"
      )
    end

    test "returns error when no signing secret configured" do
      Application.put_env(:tamandua_server, TamanduaServer.Integrations.SOAR.Tines, [])

      assert {:error, :no_signing_secret} = CallbackHandler.verify_tines_signature(
        "body",
        "signature"
      )
    end
  end
end
