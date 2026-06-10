defmodule TamanduaServer.E2EHelpers do
  @moduledoc """
  Helper functions for E2E tests.

  Provides utilities for:
  - User authentication
  - Data setup
  - WebSocket simulation
  - Common test actions
  """

  use Wallaby.DSL

  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts.{User, Organization}
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Factory
  alias Wallaby.Query

  @doc """
  Create and login a user with the given role.
  """
  def login_as(session, role \\ "analyst") do
    user = create_user(role)
    login_user(session, user)
  end

  @doc """
  Create a user with the given role.
  """
  def create_user(role \\ "analyst", attrs \\ %{}) do
    org = Factory.insert!(:organization)

    Factory.insert!(:user,
      Map.merge(%{
        email: "test_#{System.unique_integer([:positive])}@example.com",
        password: "password123",
        role: role,
        organization_id: org.id,
        is_active: true
      }, attrs)
    )
  end

  @doc """
  Login an existing user.
  """
  def login_user(session, user) do
    session
    |> Wallaby.Browser.visit("/login")
    |> Wallaby.Browser.fill_in(Query.text_field("Email"), with: user.email)
    |> Wallaby.Browser.fill_in(Query.text_field("Password"), with: "password123")
    |> Wallaby.Browser.click(Query.button("Sign in"))
    |> Wallaby.Browser.assert_has(Query.css(".dashboard, [data-page='dashboard']", count: :any))
  end

  @doc """
  Logout the current user.
  """
  def logout(session) do
    session
    |> Wallaby.Browser.click(Query.css("[data-action='logout']"))
    |> Wallaby.Browser.assert_has(Query.css(".login-page, [data-page='login']"))
  end

  @doc """
  Create an organization with users and agents.
  """
  def setup_organization(opts \\ []) do
    org = Factory.insert!(:organization)

    users = for _ <- 1..(opts[:user_count] || 3) do
      Factory.insert!(:user, organization_id: org.id)
    end

    agents = for _ <- 1..(opts[:agent_count] || 5) do
      Factory.insert!(:agent, organization_id: org.id)
    end

    %{
      organization: org,
      users: users,
      agents: agents
    }
  end

  @doc """
  Create test alerts for an organization.
  """
  def create_test_alerts(org_id, agent_id, count \\ 10) do
    for i <- 1..count do
      severity = Enum.at(["low", "medium", "high", "critical"], rem(i, 4))
      status = Enum.at(["new", "investigating", "resolved", "false_positive"], rem(i, 4))

      Factory.insert!(:alert,
        organization_id: org_id,
        agent_id: agent_id,
        severity: severity,
        status: status,
        title: "Test Alert #{i}",
        inserted_at: DateTime.add(DateTime.utc_now(), -i * 3600, :second)
      )
    end
  end

  @doc """
  Simulate agent sending telemetry event via WebSocket.
  """
  def simulate_agent_event(agent_id, event_type, payload) do
    # In a real E2E test, this would send via WebSocket
    # For now, we'll insert directly into the database
    Factory.insert!(:event,
      agent_id: agent_id,
      event_type: event_type,
      payload: payload,
      timestamp: DateTime.utc_now()
    )
  end

  @doc """
  Simulate multiple events to trigger a detection.
  """
  def trigger_detection(agent_id, detection_type \\ :brute_force) do
    case detection_type do
      :brute_force ->
        # Simulate 10 failed login attempts
        for _ <- 1..10 do
          simulate_agent_event(agent_id, "auth_failure", %{
            "username" => "admin",
            "source_ip" => "192.168.1.100"
          })
        end

      :suspicious_process ->
        # Create a suspicious PowerShell execution
        simulate_agent_event(agent_id, "process_create", %{
          "name" => "powershell.exe",
          "cmdline" => "-enc <base64_encoded_malicious_command>",
          "is_elevated" => true
        })

      :lateral_movement ->
        # Simulate lateral movement indicators
        simulate_agent_event(agent_id, "network_connect", %{
          "remote_ip" => "10.0.0.50",
          "remote_port" => 445,
          "process_name" => "cmd.exe"
        })
    end
  end

  @doc """
  Wait for LiveView to process an event.
  """
  def wait_for_live_view_event(session, event_name, timeout \\ 5000) do
    session
    |> Wallaby.Browser.execute_script("""
      return new Promise((resolve) => {
        let handler = (e) => {
          if (e.detail && e.detail.event === '#{event_name}') {
            window.removeEventListener('phx:live-view-event', handler);
            resolve(true);
          }
        };
        window.addEventListener('phx:live-view-event', handler);
        setTimeout(() => resolve(false), #{timeout});
      });
    """)

    session
  end

  @doc """
  Open a modal by clicking a button.
  """
  def open_modal(session, button_text) do
    session
    |> Wallaby.Browser.click(Query.button(button_text))
    |> Wallaby.Browser.assert_has(Query.css("[data-modal], .modal", visible: true))
  end

  @doc """
  Close a modal.
  """
  def close_modal(session) do
    session
    |> Wallaby.Browser.click(Query.css("[data-dismiss='modal'], .modal-close"))
    |> Wallaby.Browser.refute_has(Query.css("[data-modal], .modal", visible: true))
  end

  @doc """
  Fill in a search field and wait for results.
  """
  def search_for(session, query_text, search_field_selector \\ "[data-search]") do
    session
    |> Wallaby.Browser.fill_in(Query.css(search_field_selector), with: query_text)
    |> wait_for_search_results()
  end

  @doc """
  Wait for search results to load.
  """
  def wait_for_search_results(session, timeout \\ 3000) do
    session
    |> Wallaby.Browser.assert_has(
      Query.css("[data-search-results], .search-results", count: :any),
      timeout: timeout
    )
  end

  @doc """
  Select an item from a dropdown.
  """
  def select_dropdown_option(session, dropdown_selector, option_text) do
    session
    |> Wallaby.Browser.click(Query.css(dropdown_selector))
    |> Wallaby.Browser.click(Query.css("[data-option]", text: option_text))
  end

  @doc """
  Toggle a checkbox.
  """
  def toggle_checkbox(session, checkbox_selector) do
    session
    |> Wallaby.Browser.click(Query.css(checkbox_selector))
  end

  @doc """
  Submit a form by clicking the submit button.
  """
  def submit_form(session, form_selector \\ "form") do
    session
    |> Wallaby.Browser.click(Query.css("#{form_selector} button[type='submit']"))
  end

  @doc """
  Navigate using breadcrumbs.
  """
  def navigate_breadcrumb(session, breadcrumb_text) do
    session
    |> Wallaby.Browser.click(Query.css(".breadcrumb a, [data-breadcrumb]", text: breadcrumb_text))
  end

  @doc """
  Switch to a different tab in a tabbed interface.
  """
  def switch_tab(session, tab_name) do
    session
    |> Wallaby.Browser.click(Query.css("[data-tab], .tab", text: tab_name))
    |> Wallaby.Browser.assert_has(Query.css("[data-tab-panel], .tab-panel", visible: true))
  end

  @doc """
  Apply a filter in a filterable list.
  """
  def apply_filter(session, filter_name, filter_value) do
    session
    |> Wallaby.Browser.click(Query.css("[data-filter='#{filter_name}']"))
    |> Wallaby.Browser.click(Query.css("[data-filter-option='#{filter_value}']"))
  end

  @doc """
  Sort a table by clicking a column header.
  """
  def sort_table_by(session, column_name) do
    session
    |> Wallaby.Browser.click(Query.css("th[data-column='#{column_name}']"))
  end

  @doc """
  Change page size in a paginated list.
  """
  def change_page_size(session, size) do
    session
    |> Wallaby.Browser.select(Query.select("Page size"), option: "#{size}")
  end

  @doc """
  Go to next page in pagination.
  """
  def next_page(session) do
    session
    |> Wallaby.Browser.click(Query.button("Next"))
  end

  @doc """
  Go to previous page in pagination.
  """
  def previous_page(session) do
    session
    |> Wallaby.Browser.click(Query.button("Previous"))
  end

  @doc """
  Assert that a table has a specific number of rows.
  """
  def assert_table_row_count(session, count) do
    session
    |> Wallaby.Browser.assert_has(Query.css("tbody tr", count: count))
  end

  @doc """
  Assert that a specific alert is visible in the list.
  """
  def assert_alert_visible(session, alert_title) do
    session
    |> Wallaby.Browser.assert_has(Query.css("[data-alert-title]", text: alert_title))
  end

  @doc """
  Click on an alert to view details.
  """
  def view_alert_details(session, alert_title) do
    session
    |> Wallaby.Browser.click(Query.css("[data-alert-title]", text: alert_title))
    |> Wallaby.Browser.assert_has(Query.css("[data-alert-detail]"))
  end

  @doc """
  Change alert status.
  """
  def change_alert_status(session, new_status) do
    session
    |> Wallaby.Browser.click(Query.css("[data-action='change-status']"))
    |> select_dropdown_option("[data-status-dropdown]", new_status)
    |> Wallaby.Browser.click(Query.button("Save"))
  end

  @doc """
  Assign alert to user.
  """
  def assign_alert_to(session, user_name) do
    session
    |> Wallaby.Browser.click(Query.css("[data-action='assign']"))
    |> select_dropdown_option("[data-user-dropdown]", user_name)
    |> Wallaby.Browser.click(Query.button("Assign"))
  end

  @doc """
  Add a comment to an alert.
  """
  def add_alert_comment(session, comment_text) do
    session
    |> Wallaby.Browser.fill_in(Query.css("[data-comment-input]"), with: comment_text)
    |> Wallaby.Browser.click(Query.button("Add Comment"))
    |> Wallaby.Browser.assert_has(Query.css("[data-comment]", text: comment_text))
  end

  @doc """
  Navigate to a specific section using the sidebar.
  """
  def navigate_to(session, section_name) do
    session
    |> Wallaby.Browser.click(Query.css("[data-nav='#{section_name}']"))
  end

  @doc """
  Assert that an element is visible.
  """
  def assert_visible(session, selector) do
    session
    |> Wallaby.Browser.assert_has(Query.css(selector, visible: true))
  end

  @doc """
  Assert that an element is not visible.
  """
  def refute_visible(session, selector) do
    session
    |> Wallaby.Browser.refute_has(Query.css(selector, visible: true))
  end

  @doc """
  Wait for a notification to appear.
  """
  def wait_for_notification(session, message, timeout \\ 5000) do
    session
    |> Wallaby.Browser.assert_has(
      Query.css("[data-notification], .notification", text: message),
      timeout: timeout
    )
  end

  @doc """
  Dismiss a notification.
  """
  def dismiss_notification(session) do
    session
    |> Wallaby.Browser.click(Query.css("[data-notification-close], .notification-close"))
  end
end
