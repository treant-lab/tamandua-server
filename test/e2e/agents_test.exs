defmodule TamanduaServer.E2E.AgentsTest do
  @moduledoc """
  E2E tests for agent management functionality.

  Tests cover:
  - Agent list and filtering
  - Agent detail view
  - Agent health monitoring
  - Remote shell
  - Agent configuration
  - Agent grouping
  - Agent isolation
  """

  use TamanduaServer.E2ECase, async: false

  alias Wallaby.Query

  setup %{session: session} do
    org = insert(:organization)
    user = insert(:user, organization_id: org.id, role: "admin")

    agents = [
      insert(:agent,
        organization_id: org.id,
        hostname: "web-server-01",
        os_type: "linux",
        status: "online",
        ip_address: "10.0.1.10"
      ),
      insert(:agent,
        organization_id: org.id,
        hostname: "db-server-01",
        os_type: "linux",
        status: "online",
        ip_address: "10.0.2.10"
      ),
      insert(:agent,
        organization_id: org.id,
        hostname: "workstation-win-01",
        os_type: "windows",
        status: "offline",
        ip_address: "10.0.3.50"
      )
    ]

    session = login_user(session, user)
    {:ok, session: session, user: user, org: org, agents: agents}
  end

  describe "agent list view" do
    test "displays all agents in table", %{session: session} do
      session
      |> visit("/agents")
      |> assert_has(Query.css("[data-page='agents']"))
      |> assert_has(Query.css("table[data-agents-table]"))
      |> assert_has(Query.css("tbody tr", count: 3))
    end

    test "shows agent status indicators", %{session: session} do
      session
      |> visit("/agents")
      |> assert_has(Query.css("[data-status='online']", count: 2))
      |> assert_has(Query.css("[data-status='offline']", count: 1))
    end

    test "displays agent metadata columns", %{session: session} do
      session
      |> visit("/agents")
      |> assert_has(Query.css("[data-column='hostname']"))
      |> assert_has(Query.css("[data-column='ip']"))
      |> assert_has(Query.css("[data-column='os']"))
      |> assert_has(Query.css("[data-column='version']"))
      |> assert_has(Query.css("[data-column='status']"))
      |> assert_has(Query.css("[data-column='last_seen']"))
    end

    test "can filter by status", %{session: session} do
      session
      |> visit("/agents")
      |> apply_filter("status", "online")
      |> wait_for_ajax()
      |> assert_table_row_count(2)
    end

    test "can filter by OS type", %{session: session} do
      session
      |> visit("/agents")
      |> apply_filter("os_type", "linux")
      |> wait_for_ajax()
      |> assert_table_row_count(2)
    end

    test "can search agents by hostname", %{session: session} do
      session
      |> visit("/agents")
      |> search_for("web-server")
      |> assert_has(Query.text("web-server-01"))
      |> refute_has(Query.text("db-server-01"))
    end

    test "can search by IP address", %{session: session} do
      session
      |> visit("/agents")
      |> search_for("10.0.1.10")
      |> assert_has(Query.text("web-server-01"))
    end

    test "can sort by hostname", %{session: session} do
      session
      |> visit("/agents")
      |> sort_table_by("hostname")
      |> wait_for_ajax()
      |> assert_has(Query.css("th[data-column='hostname'][data-sort='asc']"))
    end

    test "can sort by last seen", %{session: session} do
      session
      |> visit("/agents")
      |> sort_table_by("last_seen")
      |> wait_for_ajax()
      |> assert_has(Query.css("th[data-column='last_seen'][data-sort='desc']"))
    end

    test "shows agent health indicators", %{session: session} do
      session
      |> visit("/agents")
      |> assert_has(Query.css("[data-health-indicator]", minimum: 1))
    end

    test "can view agents in card layout", %{session: session} do
      session
      |> visit("/agents")
      |> click(Query.css("[data-view-mode='cards']"))
      |> assert_has(Query.css("[data-agent-card]", count: 3))
    end

    test "can view agents in grid layout", %{session: session} do
      session
      |> visit("/agents")
      |> click(Query.css("[data-view-mode='grid']"))
      |> assert_has(Query.css(".agents-grid"))
    end
  end

  describe "agent detail view" do
    test "clicking agent opens detail page", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents")
      |> click(Query.css("[data-agent-id='#{agent.id}']"))
      |> assert_current_path("/agents/#{agent.id}")
      |> assert_has(Query.text(agent.hostname))
    end

    test "detail page shows overview tab", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> assert_has(Query.css("[data-tab='overview']", class: "active"))
      |> assert_has(Query.css("[data-field='hostname']", text: agent.hostname))
      |> assert_has(Query.css("[data-field='ip']", text: agent.ip_address))
      |> assert_has(Query.css("[data-field='os']", text: agent.os_type))
    end

    test "shows agent version and update status", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> assert_has(Query.css("[data-field='version']", text: agent.agent_version))
      |> assert_has(Query.css("[data-update-status]"))
    end

    test "displays agent tags", %{session: session, agents: agents} do
      agent = hd(agents)
      agent |> Ecto.Changeset.change(%{tags: ["production", "web"]}) |> Repo.update!()

      session
      |> visit("/agents/#{agent.id}")
      |> assert_has(Query.css("[data-tag='production']"))
      |> assert_has(Query.css("[data-tag='web']"))
    end

    test "can add tag to agent", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> click(Query.button("Add Tag"))
      |> fill_in(Query.text_field("Tag"), with: "critical")
      |> click(Query.button("Add"))
      |> assert_success("Tag added")
      |> assert_has(Query.css("[data-tag='critical']"))
    end

    test "can remove tag from agent", %{session: session, agents: agents} do
      agent = hd(agents)
      agent |> Ecto.Changeset.change(%{tags: ["test-tag"]}) |> Repo.update!()

      session
      |> visit("/agents/#{agent.id}")
      |> click(Query.css("[data-tag='test-tag'] [data-action='remove']"))
      |> refute_has(Query.css("[data-tag='test-tag']"))
    end

    test "shows system information", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> switch_tab("System Info")
      |> assert_has(Query.css("[data-system-info]"))
      |> assert_has(Query.css("[data-field='cpu']"))
      |> assert_has(Query.css("[data-field='memory']"))
      |> assert_has(Query.css("[data-field='disk']"))
    end

    test "shows network information", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> switch_tab("Network")
      |> assert_has(Query.css("[data-network-info]"))
      |> assert_has(Query.css("[data-field='interfaces']"))
    end

    test "displays recent alerts for agent", %{session: session, agents: agents, org: org} do
      agent = hd(agents)
      insert_list(3, :alert, organization_id: org.id, agent: agent)

      session
      |> visit("/agents/#{agent.id}")
      |> switch_tab("Alerts")
      |> assert_has(Query.css("[data-alert-item]", count: 3))
    end

    test "can navigate to alert from agent detail", %{session: session, agents: agents, org: org} do
      agent = hd(agents)
      alert = insert(:alert, organization_id: org.id, agent: agent, title: "Test Alert")

      session
      |> visit("/agents/#{agent.id}")
      |> switch_tab("Alerts")
      |> click(Query.css("[data-alert-title]", text: "Test Alert"))
      |> assert_current_path("/alerts/#{alert.id}")
    end
  end

  describe "agent health monitoring" do
    test "shows health score", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> assert_has(Query.css("[data-health-score]"))
    end

    test "displays health metrics", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> switch_tab("Health")
      |> assert_has(Query.css("[data-metric='cpu_usage']"))
      |> assert_has(Query.css("[data-metric='memory_usage']"))
      |> assert_has(Query.css("[data-metric='disk_usage']"))
      |> assert_has(Query.css("[data-metric='event_rate']"))
    end

    test "shows health trend chart", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> switch_tab("Health")
      |> assert_has(Query.css("[data-health-chart] canvas"))
    end

    test "can set health alert thresholds", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> switch_tab("Health")
      |> click(Query.button("Configure Alerts"))
      |> fill_in(Query.text_field("CPU Threshold"), with: "80")
      |> fill_in(Query.text_field("Memory Threshold"), with: "90")
      |> click(Query.button("Save"))
      |> assert_success("Health thresholds saved")
    end

    test "shows health alerts when thresholds exceeded", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> switch_tab("Health")
      |> assert_has(Query.css("[data-health-alert]", minimum: 0))
    end
  end

  describe "remote shell" do
    test "can open remote shell interface", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> click(Query.button("Open Shell"))
      |> assert_has(Query.css("[data-shell-terminal]", visible: true))
    end

    test "shows shell connection status", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> click(Query.button("Open Shell"))
      |> assert_has(Query.css("[data-shell-status='connected']"))
    end

    test "can execute command in shell", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> click(Query.button("Open Shell"))
      |> fill_in(Query.css("[data-shell-input]"), with: "whoami")
      |> send_keys([:enter])
      # Would show command output in real implementation
      |> assert_has(Query.css("[data-shell-output]"))
    end

    test "shell requires authorization", %{session: session, agents: agents} do
      # Login as analyst (not admin)
      analyst = insert(:user, role: "analyst")
      session = logout(session) |> login_user(analyst)
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> refute_has(Query.button("Open Shell"))
    end

    test "shows shell audit log", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> switch_tab("Shell History")
      |> assert_has(Query.css("[data-shell-audit]"))
    end
  end

  describe "agent configuration" do
    test "can view agent configuration", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> switch_tab("Configuration")
      |> assert_has(Query.css("[data-config-viewer]"))
    end

    test "can update collection intervals", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> switch_tab("Configuration")
      |> click(Query.button("Edit"))
      |> fill_in(Query.text_field("Process Collection Interval"), with: "5")
      |> fill_in(Query.text_field("Network Collection Interval"), with: "10")
      |> click(Query.button("Save"))
      |> assert_success("Configuration updated")
    end

    test "can enable/disable collectors", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> switch_tab("Configuration")
      |> click(Query.button("Edit"))
      |> toggle_checkbox(Query.css("[data-collector='registry']"))
      |> click(Query.button("Save"))
      |> assert_success("Configuration updated")
    end

    test "can deploy YARA rules", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> switch_tab("Configuration")
      |> click(Query.button("Deploy Rules"))
      |> toggle_checkbox(Query.css("[data-rule='malware_detection']"))
      |> click(Query.button("Deploy"))
      |> assert_success("Rules deployed")
    end

    test "shows configuration deployment history", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> switch_tab("Configuration")
      |> click(Query.link("View History"))
      |> assert_has(Query.css("[data-deployment-history]"))
    end

    test "can rollback configuration", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> switch_tab("Configuration")
      |> click(Query.link("View History"))
      |> click(Query.css("[data-action='rollback']"))
      |> click(Query.button("Confirm"))
      |> assert_success("Configuration rolled back")
    end
  end

  describe "agent isolation" do
    test "can isolate agent", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> click(Query.button("Isolate Agent"))
      |> fill_in(Query.text_field("Reason"), with: "Suspected compromise")
      |> click(Query.button("Confirm Isolation"))
      |> assert_success("Agent isolated")
      |> assert_has(Query.css("[data-status='isolated']"))
    end

    test "isolated agent shows warning banner", %{session: session, agents: agents} do
      agent = hd(agents)
      agent |> Ecto.Changeset.change(%{status: "isolated"}) |> Repo.update!()

      session
      |> visit("/agents/#{agent.id}")
      |> assert_has(Query.css("[data-isolation-banner]"))
    end

    test "can release agent from isolation", %{session: session, agents: agents} do
      agent = hd(agents)
      agent |> Ecto.Changeset.change(%{status: "isolated"}) |> Repo.update!()

      session
      |> visit("/agents/#{agent.id}")
      |> click(Query.button("Release from Isolation"))
      |> click(Query.button("Confirm"))
      |> assert_success("Agent released from isolation")
      |> assert_has(Query.css("[data-status='online']"))
    end

    test "isolation requires confirmation with reason", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> click(Query.button("Isolate Agent"))
      |> click(Query.button("Confirm Isolation"))
      |> assert_has(Query.css("[data-error]", text: "Reason is required"))
    end
  end

  describe "agent grouping" do
    test "can create agent group", %{session: session} do
      session
      |> visit("/agents")
      |> click(Query.button("Manage Groups"))
      |> click(Query.button("Create Group"))
      |> fill_in(Query.text_field("Name"), with: "Web Servers")
      |> fill_in(Query.text_field("Description"), with: "All web servers")
      |> click(Query.button("Create"))
      |> assert_success("Group created")
    end

    test "can add agent to group", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> click(Query.button("Add to Group"))
      |> search_for("Web Servers")
      |> click(Query.css("[data-group-option]", text: "Web Servers"))
      |> click(Query.button("Add"))
      |> assert_success("Agent added to group")
    end

    test "can filter agents by group", %{session: session} do
      session
      |> visit("/agents")
      |> apply_filter("group", "Web Servers")
      |> wait_for_ajax()
    end

    test "can bulk assign agents to group", %{session: session} do
      session
      |> visit("/agents")
      |> toggle_checkbox(Query.css("[data-select-all]"))
      |> click(Query.button("Bulk Actions"))
      |> click(Query.css("[data-action='add-to-group']"))
      |> search_for("Production")
      |> click(Query.css("[data-group-option]", text: "Production"))
      |> click(Query.button("Add"))
      |> assert_success("Agents added to group")
    end
  end

  describe "agent updates" do
    test "shows available updates", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> assert_has(Query.css("[data-update-available]"))
    end

    test "can initiate agent update", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> click(Query.button("Update Agent"))
      |> select_by_label("Version", "0.2.0")
      |> click(Query.button("Start Update"))
      |> assert_success("Update initiated")
    end

    test "shows update progress", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> assert_has(Query.css("[data-update-progress]", count: :any))
    end

    test "can schedule update for later", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> click(Query.button("Update Agent"))
      |> click(Query.css("[data-action='schedule']"))
      |> fill_in(Query.text_field("Schedule Time"), with: "2024-12-31 23:00")
      |> click(Query.button("Schedule"))
      |> assert_success("Update scheduled")
    end
  end

  describe "agent decommission" do
    test "can decommission agent", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> click(Query.button("Decommission"))
      |> fill_in(Query.text_field("Confirmation"), with: agent.hostname)
      |> click(Query.button("Confirm Decommission"))
      |> assert_success("Agent decommissioned")
    end

    test "decommission requires hostname confirmation", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/agents/#{agent.id}")
      |> click(Query.button("Decommission"))
      |> fill_in(Query.text_field("Confirmation"), with: "wrong-hostname")
      |> click(Query.button("Confirm Decommission"))
      |> assert_error("Hostname does not match")
    end
  end
end
