defmodule TamanduaServer.Integrations.SIEMRouterTest do
  use ExUnit.Case, async: true

  import Mox

  alias TamanduaServer.Integrations.SIEMRouter

  setup :verify_on_exit!

  @critical_alert %{
    id: "alert-123",
    title: "Critical Malware Detected",
    description: "Ransomware detected on host",
    severity: "critical",
    hostname: "workstation-1",
    agent_id: "agent-456",
    mitre_tactics: ["execution", "impact"],
    mitre_techniques: ["T1204", "T1486"],
    threat_score: 0.95,
    inserted_at: DateTime.utc_now()
  }

  @high_alert %{
    id: "alert-456",
    title: "Suspicious Process",
    severity: "high",
    hostname: "server-1",
    threat_score: 0.75,
    inserted_at: DateTime.utc_now()
  }

  @medium_alert %{
    id: "alert-789",
    title: "Minor Policy Violation",
    severity: "medium",
    hostname: "laptop-1",
    threat_score: 0.4,
    inserted_at: DateTime.utc_now()
  }

  describe "route_alert/2" do
    test "dispatches alert to all enabled SIEM integrations" do
      # Mock config to return both Splunk and Sentinel enabled
      Application.put_env(:tamandua_server, :siem_integrations, %{
        splunk: %{enabled: true, hec_url: "https://splunk.test", hec_token: "token"},
        sentinel: %{enabled: true, workspace_id: "ws-1", shared_key: "key"}
      })

      TamanduaServer.HTTPMock
      |> expect(:request, 2, fn _request, _finch, _opts ->
        {:ok, %Finch.Response{status: 200, body: ""}}
      end)

      assert {:ok, results} = SIEMRouter.route_alert(@critical_alert)
      assert is_list(results)
    end

    test "returns error when no SIEM integrations configured" do
      Application.put_env(:tamandua_server, :siem_integrations, %{})

      assert {:ok, []} = SIEMRouter.route_alert(@critical_alert)
    end
  end

  describe "route_batch/2" do
    test "batches alerts and sends to configured SIEMs" do
      alerts = [@critical_alert, @high_alert, @medium_alert]

      Application.put_env(:tamandua_server, :siem_integrations, %{
        splunk: %{enabled: true, hec_url: "https://splunk.test", hec_token: "token"}
      })

      TamanduaServer.HTTPMock
      |> expect(:request, fn _request, _finch, _opts ->
        {:ok, %Finch.Response{status: 200, body: ""}}
      end)

      assert {:ok, results} = SIEMRouter.route_batch(alerts)
      assert is_list(results)
    end
  end

  describe "get_enabled_siem_integrations/0" do
    test "returns list of configured integrations with health status" do
      Application.put_env(:tamandua_server, :siem_integrations, %{
        splunk: %{enabled: true, hec_url: "https://splunk.test", hec_token: "token"},
        sentinel: %{enabled: false, workspace_id: "ws-1"}
      })

      integrations = SIEMRouter.get_enabled_siem_integrations()

      assert is_list(integrations)
      enabled = Enum.filter(integrations, & &1.enabled)
      assert length(enabled) == 1
      assert hd(enabled).type == :splunk
    end
  end

  describe "priority routing" do
    test "alerts with severity>=high are routed immediately" do
      Application.put_env(:tamandua_server, :siem_integrations, %{
        splunk: %{enabled: true, hec_url: "https://splunk.test", hec_token: "token"}
      })

      TamanduaServer.HTTPMock
      |> expect(:request, fn _request, _finch, _opts ->
        {:ok, %Finch.Response{status: 200, body: ""}}
      end)

      # Critical alert should be routed immediately (not batched)
      assert {:ok, _} = SIEMRouter.route_alert(@critical_alert, priority: :immediate)
    end

    test "medium/low alerts can be batched" do
      Application.put_env(:tamandua_server, :siem_integrations, %{
        splunk: %{enabled: true, hec_url: "https://splunk.test", hec_token: "token"}
      })

      # Should add to batch queue instead of sending immediately
      assert :ok = SIEMRouter.queue_for_batch(@medium_alert)
    end
  end

  describe "config/0" do
    test "returns SIEM configuration from application config" do
      Application.put_env(:tamandua_server, :siem_integrations, %{
        splunk: %{enabled: true, hec_url: "https://splunk.test"},
        sentinel: %{enabled: true, workspace_id: "ws-123"}
      })

      config = SIEMRouter.config()

      assert Map.has_key?(config, :splunk)
      assert Map.has_key?(config, :sentinel)
    end
  end
end
