defmodule TamanduaServer.E2E.ThreatHuntingTest do
  @moduledoc """
  E2E tests for threat hunting functionality.

  Tests cover:
  - Query builder interface
  - Saved queries management
  - Query execution
  - Results visualization
  - Pivot operations
  - Hunt campaigns
  """

  use TamanduaServer.E2ECase, async: false

  alias Wallaby.Query

  setup %{session: session} do
    org = insert(:organization)
    user = insert(:user, organization_id: org.id, role: "hunter")
    agent = insert(:agent, organization_id: org.id)

    # Create test events for hunting
    for _ <- 1..20 do
      insert(:event,
        agent: agent,
        event_type: Enum.random(["process_create", "network_connect", "file_create"]),
        timestamp: DateTime.add(DateTime.utc_now(), -:rand.uniform(86400), :second)
      )
    end

    session = login_user(session, user)
    {:ok, session: session, user: user, org: org, agent: agent}
  end

  describe "threat hunting page" do
    test "displays hunting interface", %{session: session} do
      session
      |> visit("/hunt")
      |> assert_has(Query.css("[data-page='hunt']"))
      |> assert_has(Query.css("[data-query-builder]"))
      |> assert_has(Query.css("[data-results-panel]"))
    end

    test "shows quick hunt templates", %{session: session} do
      session
      |> visit("/hunt")
      |> assert_has(Query.css("[data-hunt-templates]"))
      |> assert_has(Query.css("[data-template='suspicious_processes']"))
      |> assert_has(Query.css("[data-template='lateral_movement']"))
      |> assert_has(Query.css("[data-template='privilege_escalation']"))
    end

    test "can select hunt template", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.css("[data-template='suspicious_processes']"))
      |> assert_has(Query.css("[data-query-populated='true']"))
    end
  end

  describe "query builder" do
    test "can build simple query", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> select_by_label("Field", "event_type")
      |> select_by_label("Operator", "equals")
      |> fill_in(Query.text_field("Value"), with: "process_create")
      |> assert_has(Query.css("[data-condition]"))
    end

    test "can add multiple conditions", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> select_by_label("Field", "event_type")
      |> select_by_label("Operator", "equals")
      |> fill_in(Query.text_field("Value"), with: "process_create")
      |> click(Query.button("Add Condition"))
      |> select_by_label("Field", "payload.is_elevated")
      |> select_by_label("Operator", "equals")
      |> select_by_label("Value", "true")
      |> assert_has(Query.css("[data-condition]", count: 2))
    end

    test "can change logical operator between conditions", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> click(Query.button("Add Condition"))
      |> click(Query.css("[data-logic-operator='AND']"))
      |> select_dropdown_option("[data-logic-dropdown]", "OR")
      |> assert_has(Query.css("[data-logic-operator='OR']"))
    end

    test "can remove condition", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> click(Query.css("[data-condition] [data-action='remove']"))
      |> refute_has(Query.css("[data-condition]"))
    end

    test "can set time range", %{session: session} do
      session
      |> visit("/hunt")
      |> select_by_label("Time Range", "Last 24 hours")
      |> assert_has(Query.css("[data-timerange='24h']"))
    end

    test "can set custom time range", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Custom Range"))
      |> fill_in(Query.css("[data-start-time]"), with: "2024-01-01 00:00")
      |> fill_in(Query.css("[data-end-time]"), with: "2024-01-31 23:59")
      |> click(Query.button("Apply"))
      |> assert_has(Query.css("[data-timerange='custom']"))
    end

    test "can filter by agent or agent group", %{session: session, agent: agent} do
      session
      |> visit("/hunt")
      |> click(Query.button("Filter Agents"))
      |> search_for(agent.hostname)
      |> click(Query.css("[data-agent-option='#{agent.id}']"))
      |> assert_has(Query.css("[data-filtered-agent='#{agent.id}']"))
    end

    test "shows query validation errors", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Run Query"))
      # No conditions added
      |> assert_error("Query must have at least one condition")
    end

    test "can view query in raw SQL", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> select_by_label("Field", "event_type")
      |> select_by_label("Operator", "equals")
      |> fill_in(Query.text_field("Value"), with: "process_create")
      |> click(Query.button("View SQL"))
      |> assert_has(Query.css("[data-sql-viewer]"))
      |> assert_has(Query.text("SELECT"))
    end
  end

  describe "query execution" do
    test "can execute query", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> select_by_label("Field", "event_type")
      |> select_by_label("Operator", "equals")
      |> fill_in(Query.text_field("Value"), with: "process_create")
      |> click(Query.button("Run Query"))
      |> wait_for_ajax()
      |> assert_has(Query.css("[data-query-results]"))
    end

    test "shows execution progress", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> select_by_label("Field", "event_type")
      |> fill_in(Query.text_field("Value"), with: "process_create")
      |> click(Query.button("Run Query"))
      |> assert_has(Query.css("[data-query-status='running']"))
    end

    test "displays query results count", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> select_by_label("Field", "event_type")
      |> fill_in(Query.text_field("Value"), with: "process_create")
      |> click(Query.button("Run Query"))
      |> wait_for_ajax()
      |> assert_has(Query.css("[data-results-count]"))
    end

    test "can cancel running query", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> click(Query.button("Run Query"))
      |> click(Query.button("Cancel"))
      |> assert_has(Query.css("[data-query-status='cancelled']"))
    end

    test "shows query execution time", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> select_by_label("Field", "event_type")
      |> fill_in(Query.text_field("Value"), with: "process_create")
      |> click(Query.button("Run Query"))
      |> wait_for_ajax()
      |> assert_has(Query.css("[data-execution-time]"))
    end
  end

  describe "results visualization" do
    test "displays results in table view", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> select_by_label("Field", "event_type")
      |> fill_in(Query.text_field("Value"), with: "process_create")
      |> click(Query.button("Run Query"))
      |> wait_for_ajax()
      |> assert_has(Query.css("[data-view='table']"))
      |> assert_has(Query.css("table"))
    end

    test "can switch to timeline view", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> click(Query.button("Run Query"))
      |> wait_for_ajax()
      |> click(Query.css("[data-view-mode='timeline']"))
      |> assert_has(Query.css("[data-timeline-chart]"))
    end

    test "can switch to chart view", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> click(Query.button("Run Query"))
      |> wait_for_ajax()
      |> click(Query.css("[data-view-mode='chart']"))
      |> assert_has(Query.css("canvas"))
    end

    test "can group results by field", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> click(Query.button("Run Query"))
      |> wait_for_ajax()
      |> select_by_label("Group By", "agent")
      |> wait_for_ajax()
      |> assert_has(Query.css("[data-grouped-results]"))
    end

    test "can sort results", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> click(Query.button("Run Query"))
      |> wait_for_ajax()
      |> sort_table_by("timestamp")
      |> assert_has(Query.css("th[data-column='timestamp'][data-sort='desc']"))
    end

    test "can paginate through results", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> click(Query.button("Run Query"))
      |> wait_for_ajax()
      |> next_page()
      |> assert_has(Query.css("[data-page='2']"))
    end

    test "can export results as CSV", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> click(Query.button("Run Query"))
      |> wait_for_ajax()
      |> click(Query.button("Export"))
      |> click(Query.css("[data-format='csv']"))
      |> wait_for_notification("Export started")
    end

    test "can export results as JSON", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> click(Query.button("Run Query"))
      |> wait_for_ajax()
      |> click(Query.button("Export"))
      |> click(Query.css("[data-format='json']"))
      |> wait_for_notification("Export started")
    end
  end

  describe "pivot operations" do
    test "can pivot from result to related events", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> click(Query.button("Run Query"))
      |> wait_for_ajax()
      |> hover(Query.css("tr[data-result]:first-child"))
      |> click(Query.css("tr[data-result]:first-child [data-action='pivot']"))
      |> assert_has(Query.css("[data-pivot-menu]"))
    end

    test "can pivot to process tree", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> click(Query.button("Run Query"))
      |> wait_for_ajax()
      |> click(Query.css("tr[data-result]:first-child [data-action='pivot']"))
      |> click(Query.css("[data-pivot='process_tree']"))
      |> assert_has(Query.css("[data-process-tree]"))
    end

    test "can pivot to agent timeline", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> click(Query.button("Run Query"))
      |> wait_for_ajax()
      |> click(Query.css("tr[data-result]:first-child [data-action='pivot']"))
      |> click(Query.css("[data-pivot='agent_timeline']"))
      |> assert_current_path("/agents/")
    end

    test "can create alert from hunt result", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> click(Query.button("Run Query"))
      |> wait_for_ajax()
      |> toggle_checkbox(Query.css("tr[data-result]:first-child [data-checkbox]"))
      |> click(Query.button("Create Alert"))
      |> fill_in(Query.text_field("Title"), with: "Suspicious Activity Found")
      |> select_by_label("Severity", "High")
      |> click(Query.button("Create"))
      |> assert_success("Alert created")
    end

    test "can add results to existing investigation", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> click(Query.button("Run Query"))
      |> wait_for_ajax()
      |> toggle_checkbox(Query.css("[data-select-all]"))
      |> click(Query.button("Add to Investigation"))
      |> select_by_label("Investigation", "Ongoing Campaign Investigation")
      |> click(Query.button("Add"))
      |> assert_success("Results added to investigation")
    end
  end

  describe "saved queries" do
    test "can save query", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> select_by_label("Field", "event_type")
      |> fill_in(Query.text_field("Value"), with: "process_create")
      |> click(Query.button("Save Query"))
      |> fill_in(Query.text_field("Name"), with: "Process Creation Events")
      |> fill_in(Query.text_field("Description"), with: "Hunt for process creation")
      |> click(Query.button("Save"))
      |> assert_success("Query saved")
    end

    test "can load saved query", %{session: session, user: user} do
      # Create saved query
      insert(:saved_search,
        user: user,
        name: "My Hunt Query",
        category: "hunt"
      )

      session
      |> visit("/hunt")
      |> click(Query.button("Load Query"))
      |> click(Query.text("My Hunt Query"))
      |> assert_has(Query.css("[data-query-loaded='true']"))
    end

    test "can edit saved query", %{session: session, user: user} do
      insert(:saved_search,
        user: user,
        name: "Old Query Name",
        category: "hunt"
      )

      session
      |> visit("/hunt")
      |> click(Query.button("Manage Queries"))
      |> click(Query.css("[data-query='Old Query Name'] [data-action='edit']"))
      |> fill_in(Query.text_field("Name"), with: "Updated Query Name")
      |> click(Query.button("Save"))
      |> assert_success("Query updated")
    end

    test "can delete saved query", %{session: session, user: user} do
      insert(:saved_search,
        user: user,
        name: "Query to Delete",
        category: "hunt"
      )

      session
      |> visit("/hunt")
      |> click(Query.button("Manage Queries"))
      |> click(Query.css("[data-query='Query to Delete'] [data-action='delete']"))
      |> click(Query.button("Confirm"))
      |> assert_success("Query deleted")
    end

    test "can share query with team", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("Add Condition"))
      |> click(Query.button("Save Query"))
      |> fill_in(Query.text_field("Name"), with: "Shared Query")
      |> toggle_checkbox(Query.css("[data-shared]"))
      |> click(Query.button("Save"))
      |> assert_success("Query saved and shared")
    end
  end

  describe "hunt campaigns" do
    test "can create hunt campaign", %{session: session} do
      session
      |> visit("/hunt/campaigns")
      |> click(Query.button("New Campaign"))
      |> fill_in(Query.text_field("Name"), with: "APT Investigation")
      |> fill_in(Query.text_field("Description"), with: "Investigate APT indicators")
      |> click(Query.button("Create"))
      |> assert_success("Campaign created")
    end

    test "can add queries to campaign", %{session: session} do
      session
      |> visit("/hunt/campaigns")
      |> click(Query.button("New Campaign"))
      |> fill_in(Query.text_field("Name"), with: "Campaign 1")
      |> click(Query.button("Create"))
      |> click(Query.button("Add Query"))
      |> click(Query.button("Add Condition"))
      |> click(Query.button("Add to Campaign"))
      |> assert_success("Query added to campaign")
    end

    test "can run all queries in campaign", %{session: session} do
      session
      |> visit("/hunt/campaigns")
      |> click(Query.css("[data-campaign]:first-child"))
      |> click(Query.button("Run All Queries"))
      |> assert_has(Query.css("[data-campaign-status='running']"))
    end

    test "shows campaign progress", %{session: session} do
      session
      |> visit("/hunt/campaigns")
      |> click(Query.css("[data-campaign]:first-child"))
      |> assert_has(Query.css("[data-campaign-progress]"))
    end

    test "can view campaign results summary", %{session: session} do
      session
      |> visit("/hunt/campaigns")
      |> click(Query.css("[data-campaign]:first-child"))
      |> assert_has(Query.css("[data-results-summary]"))
      |> assert_has(Query.css("[data-total-hits]"))
    end

    test "can schedule recurring campaign", %{session: session} do
      session
      |> visit("/hunt/campaigns")
      |> click(Query.css("[data-campaign]:first-child [data-action='schedule']"))
      |> select_by_label("Frequency", "Daily")
      |> fill_in(Query.text_field("Time"), with: "02:00")
      |> click(Query.button("Schedule"))
      |> assert_success("Campaign scheduled")
    end
  end

  describe "hunt history" do
    test "shows recent hunt queries", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("History"))
      |> assert_has(Query.css("[data-hunt-history]"))
    end

    test "can re-run query from history", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("History"))
      |> click(Query.css("[data-history-item]:first-child [data-action='rerun']"))
      |> assert_has(Query.css("[data-query-populated='true']"))
      |> click(Query.button("Run Query"))
    end

    test "history shows query metadata", %{session: session} do
      session
      |> visit("/hunt")
      |> click(Query.button("History"))
      |> assert_has(Query.css("[data-history-item] [data-timestamp]"))
      |> assert_has(Query.css("[data-history-item] [data-results-count]"))
      |> assert_has(Query.css("[data-history-item] [data-execution-time]"))
    end
  end
end
