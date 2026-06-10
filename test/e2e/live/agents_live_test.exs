defmodule TamanduaServerWeb.E2E.AgentsLiveTest do
  use TamanduaServer.LiveViewCase, async: false
  alias TamanduaServer.Agents

  describe "agent list real-time" do
    test "agent comes online", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent, status: :offline)

      {:ok, view, _html} = live(conn, "/agents")

      # Simulate agent connecting
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "agents:status",
        {:status_changed, agent.id, :online}
      )

      :timer.sleep(100)

      assert has_element?(view, "[data-agent-id='#{agent.id}'] .status-online")
      refute has_element?(view, "[data-agent-id='#{agent.id}'] .status-offline")
    end

    test "agent goes offline", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent, status: :online)

      {:ok, view, _html} = live(conn, "/agents")

      # Simulate agent disconnecting
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "agents:status",
        {:status_changed, agent.id, :offline}
      )

      :timer.sleep(100)

      assert has_element?(view, "[data-agent-id='#{agent.id}'] .status-offline")
    end

    test "agent health score updates", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent, health_score: 85)

      {:ok, view, _html} = live(conn, "/agents/#{agent.id}")

      assert has_element?(view, ".health-good")

      # Simulate health degradation
      {:ok, updated_agent} = Agents.update_health_score(agent, 45)

      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "agents:#{agent.id}",
        {:health_changed, updated_agent}
      )

      :timer.sleep(100)

      assert has_element?(view, ".health-warning")
      assert render(view) =~ "45"
    end

    test "agent CPU usage updates in real-time", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent, status: :online)

      {:ok, view, _html} = live(conn, "/agents/#{agent.id}")

      # Simulate CPU metrics update
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "agents:#{agent.id}:metrics",
        {:metrics_update, %{cpu: 75.5, memory: 60.2, disk: 80.0}}
      )

      :timer.sleep(100)

      assert render(view) =~ "75.5"
      assert has_element?(view, ".cpu-usage")
    end

    test "agent filtering by status", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      online_agent = insert(:agent, status: :online, hostname: "server1")
      offline_agent = insert(:agent, status: :offline, hostname: "server2")
      isolated_agent = insert(:agent, status: :isolated, hostname: "server3")

      {:ok, view, _html} = live(conn, "/agents")

      # Filter to online only
      view
      |> element("#filter-form")
      |> render_change(%{filter: %{status: ["online"]}})

      assert has_element?(view, "[data-agent-id='#{online_agent.id}']")
      refute has_element?(view, "[data-agent-id='#{offline_agent.id}']")
      refute has_element?(view, "[data-agent-id='#{isolated_agent.id}']")
    end

    test "agent search by hostname", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      agent1 = insert(:agent, hostname: "web-server-01")
      agent2 = insert(:agent, hostname: "db-server-01")
      agent3 = insert(:agent, hostname: "cache-server-01")

      {:ok, view, _html} = live(conn, "/agents")

      # Search for "web"
      view
      |> element("#search-form")
      |> render_change(%{search: %{query: "web"}})

      assert has_element?(view, "[data-agent-id='#{agent1.id}']")
      refute has_element?(view, "[data-agent-id='#{agent2.id}']")
      refute has_element?(view, "[data-agent-id='#{agent3.id}']")
    end
  end

  describe "agent details" do
    test "displays agent information", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent,
        hostname: "test-server",
        os: "Windows 10",
        os_version: "10.0.19045",
        ip_address: "192.168.1.100"
      )

      {:ok, view, _html} = live(conn, "/agents/#{agent.id}")

      assert render(view) =~ "test-server"
      assert render(view) =~ "Windows 10"
      assert render(view) =~ "10.0.19045"
      assert render(view) =~ "192.168.1.100"
    end

    test "displays running processes", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent)

      process1 = insert(:process, agent: agent, name: "chrome.exe", pid: 1234)
      process2 = insert(:process, agent: agent, name: "notepad.exe", pid: 5678)

      {:ok, view, _html} = live(conn, "/agents/#{agent.id}/processes")

      assert has_element?(view, "[data-process-pid='1234']", "chrome.exe")
      assert has_element?(view, "[data-process-pid='5678']", "notepad.exe")
    end

    test "displays active connections", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent)

      connection1 = insert(:connection, agent: agent, remote_ip: "8.8.8.8", remote_port: 443)
      connection2 = insert(:connection, agent: agent, remote_ip: "1.1.1.1", remote_port: 80)

      {:ok, view, _html} = live(conn, "/agents/#{agent.id}/connections")

      assert render(view) =~ "8.8.8.8:443"
      assert render(view) =~ "1.1.1.1:80"
    end

    test "displays installed software", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent)

      software1 = insert(:software, agent: agent, name: "Chrome", version: "120.0.1")
      software2 = insert(:software, agent: agent, name: "Firefox", version: "121.0")

      {:ok, view, _html} = live(conn, "/agents/#{agent.id}/software")

      assert render(view) =~ "Chrome"
      assert render(view) =~ "120.0.1"
      assert render(view) =~ "Firefox"
    end
  end

  describe "remote shell" do
    test "terminal renders and accepts input", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)
      agent = insert(:agent, status: :online)

      {:ok, view, _html} = live(conn, "/agents/#{agent.id}/shell")

      # Type command
      view
      |> element(".terminal-input")
      |> render_keydown(%{key: "Enter", value: "ps aux"})

      # Mock response from agent
      send(view.pid, {:shell_output, "USER       PID %CPU %MEM    VSZ   RSS TTY\nroot         1  0.0  0.1  12345  6789 ?"})

      :timer.sleep(100)

      assert render(view) =~ "USER"
      assert render(view) =~ "PID"
    end

    test "command history navigation", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)
      agent = insert(:agent, status: :online)

      {:ok, view, _html} = live(conn, "/agents/#{agent.id}/shell")

      # Execute commands
      view |> element(".terminal-input") |> render_keydown(%{key: "Enter", value: "ls -la"})
      view |> element(".terminal-input") |> render_keydown(%{key: "Enter", value: "pwd"})
      view |> element(".terminal-input") |> render_keydown(%{key: "Enter", value: "whoami"})

      # Navigate history with up arrow
      view |> element(".terminal-input") |> render_keydown(%{key: "ArrowUp"})

      assert view |> element(".terminal-input") |> render() =~ "whoami"
    end

    test "shell session timeout", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)
      agent = insert(:agent, status: :online)

      {:ok, view, _html} = live(conn, "/agents/#{agent.id}/shell")

      # Simulate timeout
      send(view.pid, {:shell_timeout, "Session timed out after 30 minutes of inactivity"})

      :timer.sleep(100)

      assert render(view) =~ "Session timed out"
      assert has_element?(view, ".session-expired")
    end

    test "unauthorized user cannot access shell", %{conn: conn} do
      user = insert(:user, role: :viewer)
      conn = log_in_user(conn, user)
      agent = insert(:agent, status: :online)

      assert {:error, {:redirect, %{to: "/unauthorized"}}} = live(conn, "/agents/#{agent.id}/shell")
    end
  end

  describe "agent commands" do
    test "kill process command", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)
      agent = insert(:agent, status: :online)
      process = insert(:process, agent: agent, pid: 1234, name: "malware.exe")

      {:ok, view, _html} = live(conn, "/agents/#{agent.id}/processes")

      # Kill process
      view
      |> element("[data-process-pid='1234'] .kill-button")
      |> render_click()

      # Confirm dialog
      view
      |> element("#confirm-kill")
      |> render_click()

      # Verify command sent
      assert has_element?(view, ".command-pending")
    end

    test "isolate agent command", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)
      agent = insert(:agent, status: :online)

      {:ok, view, _html} = live(conn, "/agents/#{agent.id}")

      # Isolate agent
      view
      |> element("#isolate-button")
      |> render_click()

      # Confirm
      view
      |> element("#confirm-isolate")
      |> render_click()

      # Verify status change
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "agents:#{agent.id}",
        {:status_changed, :isolated}
      )

      :timer.sleep(100)

      assert has_element?(view, ".status-isolated")
    end

    test "quarantine file command", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)
      agent = insert(:agent, status: :online)
      file = insert(:file, agent: agent, path: "C:\\Windows\\Temp\\malware.exe")

      {:ok, view, _html} = live(conn, "/agents/#{agent.id}/files")

      # Quarantine file
      view
      |> element("[data-file-id='#{file.id}'] .quarantine-button")
      |> render_click()

      assert has_element?(view, ".command-sent")
    end

    test "update configuration command", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)
      agent = insert(:agent, status: :online)

      {:ok, view, _html} = live(conn, "/agents/#{agent.id}/config")

      # Update config
      view
      |> element("#config-form")
      |> render_submit(%{config: %{poll_interval: 30, upload_batch_size: 500}})

      assert render(view) =~ "Configuration updated"
    end

    test "restart agent command", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)
      agent = insert(:agent, status: :online)

      {:ok, view, _html} = live(conn, "/agents/#{agent.id}")

      # Restart agent
      view
      |> element("#restart-button")
      |> render_click()

      # Confirm
      view
      |> element("#confirm-restart")
      |> render_click()

      # Agent should go offline then online
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "agents:#{agent.id}",
        {:status_changed, :offline}
      )

      :timer.sleep(100)
      assert has_element?(view, ".status-offline")

      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "agents:#{agent.id}",
        {:status_changed, :online}
      )

      :timer.sleep(100)
      assert has_element?(view, ".status-online")
    end
  end

  describe "agent groups" do
    test "create agent group", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/agents/groups")

      # Create group
      view
      |> element("#new-group-form")
      |> render_submit(%{group: %{name: "Production Servers", description: "All prod servers"}})

      assert has_element?(view, ".group-name", "Production Servers")
    end

    test "add agents to group", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)
      group = insert(:agent_group, name: "Web Servers")
      agent1 = insert(:agent, hostname: "web-01")
      agent2 = insert(:agent, hostname: "web-02")

      {:ok, view, _html} = live(conn, "/agents/groups/#{group.id}")

      # Add agents
      view
      |> element("#add-agents-form")
      |> render_submit(%{agents: [agent1.id, agent2.id]})

      assert has_element?(view, "[data-agent-id='#{agent1.id}']")
      assert has_element?(view, "[data-agent-id='#{agent2.id}']")
    end

    test "bulk command to group", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)
      group = insert(:agent_group, name: "Test Group")
      agent1 = insert(:agent, status: :online, group: group)
      agent2 = insert(:agent, status: :online, group: group)

      {:ok, view, _html} = live(conn, "/agents/groups/#{group.id}")

      # Send bulk update command
      view
      |> element("#bulk-update-button")
      |> render_click()

      view
      |> element("#bulk-command-form")
      |> render_submit(%{command: %{type: "update_config", config: %{poll_interval: 60}}})

      assert render(view) =~ "Command sent to 2 agents"
    end
  end

  describe "agent metrics dashboard" do
    test "displays aggregate metrics", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      insert(:agent, status: :online, health_score: 95)
      insert(:agent, status: :online, health_score: 80)
      insert(:agent, status: :offline, health_score: 0)

      {:ok, view, _html} = live(conn, "/agents/metrics")

      assert has_element?(view, ".total-agents", "3")
      assert has_element?(view, ".online-agents", "2")
      assert has_element?(view, ".offline-agents", "1")
    end

    test "metrics chart updates in real-time", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/agents/metrics")

      # Simulate metrics update
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "agents:metrics",
        {:metrics_update, %{
          total: 10,
          online: 8,
          offline: 2,
          avg_health: 85.5
        }}
      )

      :timer.sleep(100)

      assert render(view) =~ "85.5"
    end
  end

  describe "agent timeline" do
    test "displays agent activity timeline", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent)

      insert(:agent_event, agent: agent, type: :connected, timestamp: ~U[2024-01-01 10:00:00Z])
      insert(:agent_event, agent: agent, type: :disconnected, timestamp: ~U[2024-01-01 11:00:00Z])
      insert(:agent_event, agent: agent, type: :connected, timestamp: ~U[2024-01-01 12:00:00Z])

      {:ok, view, _html} = live(conn, "/agents/#{agent.id}/timeline")

      assert has_element?(view, ".event-connected")
      assert has_element?(view, ".event-disconnected")
    end

    test "new events appear in real-time", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent)

      {:ok, view, _html} = live(conn, "/agents/#{agent.id}/timeline")

      # Add new event
      event = insert(:agent_event, agent: agent, type: :config_updated)

      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "agents:#{agent.id}:timeline",
        {:new_event, event}
      )

      :timer.sleep(100)

      assert has_element?(view, ".event-config_updated")
    end
  end

  describe "agent deployment" do
    test "deploy new agent", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/agents/deploy")

      # Fill deployment form
      view
      |> element("#deploy-form")
      |> render_submit(%{
        deployment: %{
          hostname: "new-server-01",
          os: "linux",
          group_id: nil
        }
      })

      # Should generate deployment package
      assert has_element?(view, ".deployment-token")
      assert has_element?(view, ".installation-command")
    end

    test "generate deployment token", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/agents/deploy")

      # Generate token
      view
      |> element("#generate-token")
      |> render_click()

      assert has_element?(view, ".token-value")
      assert render(view) =~ ~r/[A-Za-z0-9-_]{32,}/
    end
  end

  describe "agent performance" do
    test "displays performance graphs", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent)

      # Insert performance metrics
      for i <- 1..10 do
        insert(:agent_metric,
          agent: agent,
          cpu: 50 + i,
          memory: 60 + i,
          disk: 70 + i,
          timestamp: DateTime.add(DateTime.utc_now(), -i * 60, :second)
        )
      end

      {:ok, view, _html} = live(conn, "/agents/#{agent.id}/performance")

      assert has_element?(view, "#cpu-chart")
      assert has_element?(view, "#memory-chart")
      assert has_element?(view, "#disk-chart")
    end

    test "performance alerts trigger warnings", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent)

      {:ok, view, _html} = live(conn, "/agents/#{agent.id}/performance")

      # Simulate high CPU
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "agents:#{agent.id}:metrics",
        {:metrics_update, %{cpu: 95.0, memory: 60.0, disk: 70.0}}
      )

      :timer.sleep(100)

      assert has_element?(view, ".alert-high-cpu")
    end
  end
end
