defmodule TamanduaServerWeb.Api.V1.SoarWebhookControllerTest do
  use TamanduaServerWeb.ConnCase, async: true

  alias TamanduaServer.Integrations.SOAR.ExecutionLog

  setup do
    # Create an execution log for testing
    {:ok, log} = ExecutionLog.create(%{
      alert_id: "alert-test",
      soar_platform: "xsoar",
      playbook_name: "test_playbook",
      execution_id: "test-run-123"
    })

    # Configure auth secrets
    Application.put_env(:tamandua_server, TamanduaServer.Integrations.SOAR.XSOAR, [
      callback_api_key: "xsoar-test-key"
    ])

    Application.put_env(:tamandua_server, TamanduaServer.Integrations.SOAR.Tines, [
      webhook_signing_secret: "tines-test-secret",
      require_signature_verification: false
    ])

    %{log: log}
  end

  describe "POST /api/v1/integrations/soar/callback/:platform" do
    test "accepts XSOAR callback with valid API key", %{conn: conn, log: log} do
      payload = %{
        "playbookRunId" => log.execution_id,
        "status" => "Closed",
        "closeReason" => "Resolved"
      }

      conn = conn
      |> put_req_header("x-xsoar-auth", "xsoar-test-key")
      |> put_req_header("content-type", "application/json")
      |> post("/api/v1/integrations/soar/callback/xsoar", payload)

      assert json_response(conn, 200)["status"] == "ok"

      # Verify log was updated
      updated = ExecutionLog.get(log.id)
      assert updated.status == "completed"
    end

    test "rejects XSOAR callback with invalid API key", %{conn: conn, log: log} do
      payload = %{
        "playbookRunId" => log.execution_id,
        "status" => "Closed"
      }

      conn = conn
      |> put_req_header("x-xsoar-auth", "wrong-key")
      |> put_req_header("content-type", "application/json")
      |> post("/api/v1/integrations/soar/callback/xsoar", payload)

      assert json_response(conn, 401)["error"] == "Unauthorized"
    end

    test "accepts Tines callback", %{conn: conn} do
      # Create a Tines execution log
      {:ok, tines_log} = ExecutionLog.create(%{
        alert_id: "alert-tines",
        soar_platform: "tines",
        playbook_name: "tines_workflow"
      })

      payload = %{
        "tamandua_execution_id" => tines_log.id,
        "status" => "completed",
        "story_id" => "story-123"
      }

      conn = conn
      |> put_req_header("content-type", "application/json")
      |> post("/api/v1/integrations/soar/callback/tines", payload)

      assert json_response(conn, 200)["status"] == "ok"

      updated = ExecutionLog.get(tines_log.id)
      assert updated.status == "completed"
    end

    test "verifies Tines signature when configured", %{conn: conn} do
      # Enable signature verification
      Application.put_env(:tamandua_server, TamanduaServer.Integrations.SOAR.Tines, [
        webhook_signing_secret: "test-secret",
        require_signature_verification: true
      ])

      {:ok, tines_log} = ExecutionLog.create(%{
        soar_platform: "tines",
        playbook_name: "test"
      })

      body = Jason.encode!(%{
        "tamandua_execution_id" => tines_log.id,
        "status" => "completed"
      })

      # Generate valid signature
      signature = :crypto.mac(:hmac, :sha256, "test-secret", body)
      |> Base.encode16(case: :lower)

      conn = conn
      |> put_req_header("content-type", "application/json")
      |> put_req_header("x-tines-signature", signature)
      |> post("/api/v1/integrations/soar/callback/tines", body)

      # Note: This may fail in test due to body parsing
      # In real scenario, the CacheBodyReader plug would preserve raw body
      response = json_response(conn, 200)
      assert response["status"] == "ok"

      # Reset config
      Application.put_env(:tamandua_server, TamanduaServer.Integrations.SOAR.Tines, [
        require_signature_verification: false
      ])
    end

    test "returns 404 when execution not found", %{conn: conn} do
      payload = %{
        "playbookRunId" => "nonexistent-run",
        "status" => "Closed"
      }

      conn = conn
      |> put_req_header("x-xsoar-auth", "xsoar-test-key")
      |> put_req_header("content-type", "application/json")
      |> post("/api/v1/integrations/soar/callback/xsoar", payload)

      assert json_response(conn, 404)["error"] == "Not Found"
    end

    test "returns 400 for unknown platform", %{conn: conn} do
      conn = conn
      |> put_req_header("content-type", "application/json")
      |> post("/api/v1/integrations/soar/callback/unknown", %{})

      assert json_response(conn, 400)["error"] == "Bad Request"
    end
  end

  describe "GET /api/v1/integrations/soar/callback/health" do
    test "returns healthy status", %{conn: conn} do
      conn = get(conn, "/api/v1/integrations/soar/callback/health")

      response = json_response(conn, 200)
      assert response["status"] == "healthy"
      assert response["timestamp"]
    end
  end
end
