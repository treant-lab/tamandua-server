defmodule TamanduaServer.Deception.BreadcrumbMonitorTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Deception.{BreadcrumbMonitor, BreadcrumbDeployment, BreadcrumbAccessLog}
  alias TamanduaServer.Alerts

  describe "breadcrumb access monitoring" do
    setup do
      # Create a test breadcrumb deployment
      {:ok, deployment} =
        %BreadcrumbDeployment{}
        |> BreadcrumbDeployment.changeset(%{
          agent_id: "test-agent-001",
          type: "ssh_key",
          path: "/home/user/.ssh/id_rsa_fake",
          content_hash: "abc123def456",
          canary_token: "TAMANDUA-TEST-TOKEN-001",
          deployed_at: DateTime.utc_now(),
          status: "active",
          access_count: 0,
          metadata: %{test: true}
        })
        |> Repo.insert()

      %{deployment: deployment}
    end

    test "handles file access event and creates alert", %{deployment: deployment} do
      # Simulate file access event
      access_event = %{
        file_path: deployment.path,
        agent_id: deployment.agent_id,
        process_name: "mimikatz.exe",
        pid: 1234,
        user: "SYSTEM",
        access_type: "read",
        timestamp: DateTime.utc_now(),
        file_hash: deployment.content_hash
      }

      # Process the access
      BreadcrumbMonitor.handle_file_access(access_event)

      # Allow async processing
      Process.sleep(100)

      # Verify access log was created
      access_logs = Repo.all(BreadcrumbAccessLog)
      assert length(access_logs) > 0

      log = List.first(access_logs)
      assert log.breadcrumb_id == deployment.id
      assert log.agent_id == deployment.agent_id
      assert log.process_name == "mimikatz.exe"
      assert log.pid == 1234
      assert log.access_type == "read"
      assert log.tamper_detected == false

      # Verify alert was created
      alerts = Alerts.list_alerts()
      assert length(alerts) > 0

      alert = List.first(alerts)
      assert alert.severity == "high"
      assert alert.agent_id == deployment.agent_id
      assert "T1083" in alert.mitre_techniques
      assert alert.evidence.file_path == deployment.path
      assert alert.evidence.process == "mimikatz.exe"
      assert alert.evidence.breadcrumb_type == "ssh_key"
    end

    test "detects file tampering", %{deployment: deployment} do
      # Simulate file modification event
      access_event = %{
        file_path: deployment.path,
        agent_id: deployment.agent_id,
        process_name: "attacker.exe",
        pid: 5678,
        user: "attacker",
        access_type: "write",
        timestamp: DateTime.utc_now(),
        file_hash: "MODIFIED_HASH_999"
      }

      BreadcrumbMonitor.handle_file_access(access_event)
      Process.sleep(100)

      # Verify tamper detection
      access_logs = Repo.all(BreadcrumbAccessLog)
      log = List.first(access_logs)
      assert log.tamper_detected == true
      assert log.new_hash == "MODIFIED_HASH_999"
      assert log.original_hash == deployment.content_hash

      # Verify alert mentions tampering
      alerts = Alerts.list_alerts()
      alert = List.first(alerts)
      assert alert.evidence.tamper_detected == true
      assert String.contains?(alert.description, "TAMPER DETECTED")
    end

    test "handles file deletion", %{deployment: deployment} do
      access_event = %{
        file_path: deployment.path,
        agent_id: deployment.agent_id,
        process_name: "del.exe",
        pid: 9999,
        user: "admin",
        access_type: "delete",
        timestamp: DateTime.utc_now()
      }

      BreadcrumbMonitor.handle_file_access(access_event)
      Process.sleep(100)

      access_logs = Repo.all(BreadcrumbAccessLog)
      log = List.first(access_logs)
      assert log.tamper_detected == true
      assert log.access_type == "delete"
    end

    test "tracks access statistics", %{deployment: deployment} do
      # Simulate multiple accesses
      for i <- 1..3 do
        access_event = %{
          file_path: deployment.path,
          agent_id: deployment.agent_id,
          process_name: "process_#{i}",
          pid: 1000 + i,
          user: "user_#{i}",
          access_type: "read",
          timestamp: DateTime.utc_now()
        }

        BreadcrumbMonitor.handle_file_access(access_event)
        Process.sleep(50)
      end

      {:ok, stats} = BreadcrumbMonitor.get_statistics()
      assert stats.total_accesses >= 3
      assert stats.accesses_by_agent[deployment.agent_id] >= 3
      assert stats.accesses_by_type[:ssh_key] >= 3
    end
  end

  describe "response configuration" do
    test "updates response configuration" do
      new_config = %{
        isolate_agent: true,
        kill_process: true,
        create_snapshot: true,
        escalate_to_soc: true,
        trigger_playbook_id: "pb_test_123"
      }

      {:ok, config} = BreadcrumbMonitor.configure_response(new_config)
      assert config.isolate_agent == true
      assert config.create_snapshot == true
      assert config.trigger_playbook_id == "pb_test_123"
    end
  end

  describe "access history" do
    setup do
      {:ok, deployment} =
        %BreadcrumbDeployment{}
        |> BreadcrumbDeployment.changeset(%{
          agent_id: "test-agent-002",
          type: "api_token",
          path: "/etc/api_keys.txt",
          content_hash: "xyz789",
          canary_token: "TAMANDUA-TEST-TOKEN-002",
          deployed_at: DateTime.utc_now(),
          status: "active"
        })
        |> Repo.insert()

      # Create some access logs
      for i <- 1..5 do
        {:ok, _log} =
          %BreadcrumbAccessLog{}
          |> BreadcrumbAccessLog.changeset(%{
            breadcrumb_id: deployment.id,
            agent_id: deployment.agent_id,
            accessed_at: DateTime.add(DateTime.utc_now(), -i * 60, :second),
            process_name: "process_#{i}",
            pid: 2000 + i,
            user: "user",
            access_type: "read"
          })
          |> Repo.insert()
      end

      %{deployment: deployment}
    end

    test "retrieves access history for breadcrumb", %{deployment: deployment} do
      {:ok, history} = BreadcrumbMonitor.get_access_history(deployment.id)
      assert length(history) == 5

      # Verify they're ordered by time (most recent first)
      timestamps = Enum.map(history, & &1.accessed_at)
      assert timestamps == Enum.sort(timestamps, {:desc, DateTime})
    end

    test "limits access history results", %{deployment: deployment} do
      {:ok, history} = BreadcrumbMonitor.get_access_history(deployment.id, limit: 3)
      assert length(history) == 3
    end
  end

  describe "effectiveness reporting" do
    setup do
      # Deploy multiple breadcrumbs of different types
      types = [:ssh_key, :api_token, :credential, :document]

      deployments =
        Enum.map(types, fn type ->
          {:ok, deployment} =
            %BreadcrumbDeployment{}
            |> BreadcrumbDeployment.changeset(%{
              agent_id: "test-agent-003",
              type: to_string(type),
              path: "/fake/#{type}",
              content_hash: "hash_#{type}",
              canary_token: "TOKEN_#{type}",
              deployed_at: DateTime.utc_now(),
              status: if(type in [:ssh_key, :api_token], do: "accessed", else: "active")
            })
            |> Repo.insert()

          deployment
        end)

      %{deployments: deployments}
    end

    test "generates effectiveness report" do
      {:ok, report} = BreadcrumbMonitor.get_effectiveness_report()

      assert report.total_deployed == 4
      assert report.total_accessed == 2
      assert report.overall_effectiveness == 50.0

      # Find ssh_key in the report
      ssh_key_stats = Enum.find(report.by_type, fn stat -> stat.type == "ssh_key" end)
      assert ssh_key_stats
      assert ssh_key_stats.accessed == 1
      assert ssh_key_stats.deployed == 1
      assert ssh_key_stats.effectiveness_rate == 100.0
      assert ssh_key_stats.status == "high"
    end
  end

  describe "canary token access" do
    test "handles direct canary token access" do
      {:ok, deployment} =
        %BreadcrumbDeployment{}
        |> BreadcrumbDeployment.changeset(%{
          agent_id: "test-agent-004",
          type: "cloud_credential",
          path: "/home/user/.aws/credentials",
          content_hash: "aws123",
          canary_token: "TAMANDUA-CANARY-AWS",
          deployed_at: DateTime.utc_now(),
          status: "active"
        })
        |> Repo.insert()

      access_event = %{
        canary_token: deployment.canary_token,
        agent_id: deployment.agent_id,
        process_name: "aws-cli",
        pid: 7777,
        user: "developer",
        access_type: "read",
        timestamp: DateTime.utc_now()
      }

      BreadcrumbMonitor.handle_breadcrumb_access(access_event)
      Process.sleep(100)

      # Verify access was logged
      access_logs = Repo.all(BreadcrumbAccessLog)
      assert length(access_logs) > 0

      log = List.first(access_logs)
      assert log.breadcrumb_id == deployment.id

      # Verify alert was created
      alerts = Alerts.list_alerts()
      assert length(alerts) > 0

      alert = List.first(alerts)
      assert alert.evidence.canary_token == deployment.canary_token
    end
  end
end
