defmodule TamanduaServer.Integrations.SOAR.PlaybookRouterTest do
  use TamanduaServer.DataCase, async: true

  import Mox

  alias TamanduaServer.Integrations.SOAR.{PlaybookRouter, ExecutionLog}

  setup :verify_on_exit!

  @test_alert %{
    id: "alert-123",
    title: "Critical Malware",
    severity: "critical",
    hostname: "workstation-1",
    agent_id: "agent-456",
    threat_score: 0.9,
    mitre_tactics: ["execution"],
    mitre_techniques: ["T1204"]
  }

  describe "route_to_playbook/3" do
    test "dispatches to XSOAR when platform='xsoar'" do
      # Mock XSOAR responses
      TamanduaServer.HTTPMock
      |> expect(:request, fn _request, _finch, _opts ->
        # create_incident response
        {:ok, %Finch.Response{
          status: 200,
          body: Jason.encode!(%{"id" => "incident-789"})
        }}
      end)
      |> expect(:request, fn _request, _finch, _opts ->
        # trigger_playbook response
        {:ok, %Finch.Response{
          status: 200,
          body: Jason.encode!(%{"id" => "run-123"})
        }}
      end)

      assert {:ok, [result]} = PlaybookRouter.route_to_playbook(
        "xsoar",
        @test_alert,
        playbook_name: "investigate_alert"
      )

      assert result.platform == "xsoar"
      assert result.log_id
      assert result.execution_id

      # Verify execution log was created
      log = ExecutionLog.get(result.log_id)
      assert log.soar_platform == "xsoar"
      assert log.playbook_name == "investigate_alert"
      assert log.status == "running"
    end

    test "dispatches to Tines when platform='tines'" do
      webhook_url = "https://app.tines.com/webhook/test"

      TamanduaServer.HTTPMock
      |> expect(:request, fn _request, _finch, _opts ->
        {:ok, %Finch.Response{
          status: 200,
          body: Jason.encode!(%{"event_id" => "event-456"})
        }}
      end)

      assert {:ok, [result]} = PlaybookRouter.route_to_playbook(
        "tines",
        @test_alert,
        playbook_name: "tines_workflow",
        webhook_url: webhook_url
      )

      assert result.platform == "tines"
      assert result.log_id
      assert result.execution_id

      log = ExecutionLog.get(result.log_id)
      assert log.soar_platform == "tines"
      assert log.playbook_name == "tines_workflow"
    end

    test "dispatches to both when platform='both'" do
      # Mock both XSOAR and Tines
      TamanduaServer.HTTPMock
      |> expect(:request, 2, fn request, _finch, _opts ->
        # XSOAR create_incident
        {:ok, %Finch.Response{
          status: 200,
          body: Jason.encode!(%{"id" => "incident-#{:rand.uniform(1000)}"})
        }}
      end)
      |> expect(:request, 2, fn _request, _finch, _opts ->
        # Trigger responses
        {:ok, %Finch.Response{
          status: 200,
          body: Jason.encode!(%{"id" => "run-#{:rand.uniform(1000)}"})
        }}
      end)

      assert {:ok, results} = PlaybookRouter.route_to_playbook(
        "both",
        @test_alert,
        playbook_name: "critical_response",
        webhook_url: "https://tines.test/webhook"
      )

      assert length(results) == 2
      platforms = Enum.map(results, & &1.platform)
      assert "xsoar" in platforms
      assert "tines" in platforms
    end

    test "execution is logged with alert_id, playbook, platform, status" do
      TamanduaServer.HTTPMock
      |> expect(:request, fn _request, _finch, _opts ->
        {:ok, %Finch.Response{
          status: 200,
          body: Jason.encode!(%{"id" => "incident-test"})
        }}
      end)
      |> expect(:request, fn _request, _finch, _opts ->
        {:ok, %Finch.Response{
          status: 200,
          body: Jason.encode!(%{"id" => "run-test"})
        }}
      end)

      {:ok, [result]} = PlaybookRouter.route_to_playbook(
        "xsoar",
        @test_alert,
        playbook_name: "test_playbook",
        rule_id: "rule-123"
      )

      log = ExecutionLog.get(result.log_id)
      assert log.alert_id == @test_alert.id
      assert log.playbook_name == "test_playbook"
      assert log.soar_platform == "xsoar"
      assert log.status in ["pending", "running"]
      assert log.trigger_rule_id == "rule-123"
    end

    test "returns error when playbook_name not provided" do
      assert_raise KeyError, fn ->
        PlaybookRouter.route_to_playbook("xsoar", @test_alert, [])
      end
    end
  end

  describe "get_enabled_soar_integrations/0" do
    test "returns configured platforms with health status" do
      integrations = PlaybookRouter.get_enabled_soar_integrations()

      assert is_list(integrations)
      assert length(integrations) >= 2

      platforms = Enum.map(integrations, & &1.platform)
      assert "xsoar" in platforms
      assert "tines" in platforms

      # Each should have status field
      Enum.each(integrations, fn i ->
        assert i.status in [:healthy, :unhealthy, :disabled, :unknown]
      end)
    end
  end

  describe "ExecutionLog" do
    test "create/1 creates a new log entry" do
      {:ok, log} = ExecutionLog.create(%{
        alert_id: "alert-test",
        soar_platform: "xsoar",
        playbook_name: "test_playbook"
      })

      assert log.id
      assert log.alert_id == "alert-test"
      assert log.soar_platform == "xsoar"
      assert log.playbook_name == "test_playbook"
      assert log.status == "pending"
      assert log.started_at
    end

    test "update_status/3 updates execution status" do
      {:ok, log} = ExecutionLog.create(%{
        soar_platform: "tines",
        playbook_name: "test"
      })

      {:ok, updated} = ExecutionLog.update_status(log, "running", %{
        execution_id: "run-123"
      })

      assert updated.status == "running"
      assert updated.execution_id == "run-123"
    end

    test "update_from_callback/2 processes SOAR callback" do
      {:ok, log} = ExecutionLog.create(%{
        soar_platform: "xsoar",
        playbook_name: "test"
      })

      callback_data = %{
        status: "completed",
        result: %{"action_taken" => "isolated_host"},
        execution_id: "run-456"
      }

      {:ok, updated} = ExecutionLog.update_from_callback(log, callback_data)

      assert updated.status == "completed"
      assert updated.result == %{"action_taken" => "isolated_host"}
      assert updated.callback_received_at
      assert updated.completed_at
    end

    test "list_for_alert/1 returns logs for an alert" do
      {:ok, log1} = ExecutionLog.create(%{
        alert_id: "alert-multi",
        soar_platform: "xsoar",
        playbook_name: "play1"
      })

      {:ok, log2} = ExecutionLog.create(%{
        alert_id: "alert-multi",
        soar_platform: "tines",
        playbook_name: "play2"
      })

      {:ok, _log3} = ExecutionLog.create(%{
        alert_id: "alert-other",
        soar_platform: "xsoar",
        playbook_name: "play3"
      })

      logs = ExecutionLog.list_for_alert("alert-multi")
      assert length(logs) == 2

      log_ids = Enum.map(logs, & &1.id)
      assert log1.id in log_ids
      assert log2.id in log_ids
    end
  end
end
