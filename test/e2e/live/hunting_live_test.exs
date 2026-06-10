defmodule TamanduaServerWeb.E2E.HuntingLiveTest do
  use TamanduaServer.LiveViewCase, async: false
  alias TamanduaServer.Hunting

  describe "query builder" do
    test "build simple query", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/hunting")

      # Add condition
      view
      |> element("#add-condition")
      |> render_click()

      # Fill condition
      view
      |> element("#condition-0")
      |> render_change(%{
        condition: %{
          field: "process.name",
          operator: "equals",
          value: "powershell.exe"
        }
      })

      assert has_element?(view, ".condition-field", "process.name")
      assert has_element?(view, ".condition-value", "powershell.exe")
    end

    test "build complex query with AND/OR", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/hunting")

      # Add first condition
      view |> element("#add-condition") |> render_click()
      view
      |> element("#condition-0")
      |> render_change(%{
        condition: %{field: "process.name", operator: "equals", value: "powershell.exe"}
      })

      # Add OR operator
      view |> element("#add-operator") |> render_click(%{operator: "or"})

      # Add second condition
      view |> element("#add-condition") |> render_click()
      view
      |> element("#condition-1")
      |> render_change(%{
        condition: %{field: "process.name", operator: "equals", value: "cmd.exe"}
      })

      assert has_element?(view, ".operator-or")
      assert render(view) =~ "powershell.exe"
      assert render(view) =~ "cmd.exe"
    end

    test "nested query groups", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/hunting")

      # Create nested group
      view |> element("#add-group") |> render_click()

      assert has_element?(view, ".query-group-nested")

      # Add condition to nested group
      view
      |> element(".query-group-nested #add-condition")
      |> render_click()

      assert has_element?(view, ".query-group-nested .condition")
    end

    test "query validation", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/hunting")

      # Try to execute empty query
      view
      |> element("#execute-query")
      |> render_click()

      assert has_element?(view, ".error", "Query cannot be empty")
    end
  end

  describe "auto-complete" do
    test "field name auto-complete", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/hunting")

      view |> element("#add-condition") |> render_click()

      # Type partial field name
      view
      |> element("#condition-0 .field-input")
      |> render_keyup(%{value: "proc"})

      assert has_element?(view, ".autocomplete-suggestion", "process.name")
      assert has_element?(view, ".autocomplete-suggestion", "process.pid")
      assert has_element?(view, ".autocomplete-suggestion", "process.path")
    end

    test "operator suggestions", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/hunting")

      view |> element("#add-condition") |> render_click()

      # Select field
      view
      |> element("#condition-0 .field-input")
      |> render_change(%{field: "process.name"})

      # Check operator options
      operators = view |> element("#condition-0 .operator-select") |> render()

      assert operators =~ "equals"
      assert operators =~ "contains"
      assert operators =~ "matches"
      assert operators =~ "startswith"
    end

    test "value suggestions based on field", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      # Create some historical data
      insert(:telemetry_event, event_type: "process_create", data: %{"name" => "powershell.exe"})
      insert(:telemetry_event, event_type: "process_create", data: %{"name" => "cmd.exe"})

      {:ok, view, _html} = live(conn, "/hunting")

      view |> element("#add-condition") |> render_click()

      # Select field and operator
      view
      |> element("#condition-0")
      |> render_change(%{
        condition: %{field: "process.name", operator: "equals"}
      })

      # Start typing value
      view
      |> element("#condition-0 .value-input")
      |> render_keyup(%{value: "pow"})

      assert has_element?(view, ".autocomplete-suggestion", "powershell.exe")
    end
  end

  describe "query execution" do
    test "execute query and display results", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      # Create test data
      agent = insert(:agent)
      insert(:telemetry_event,
        agent: agent,
        event_type: "process_create",
        data: %{"name" => "powershell.exe", "pid" => 1234}
      )

      {:ok, view, _html} = live(conn, "/hunting")

      # Build query
      view |> element("#add-condition") |> render_click()
      view
      |> element("#condition-0")
      |> render_change(%{
        condition: %{field: "process.name", operator: "equals", value: "powershell.exe"}
      })

      # Execute
      view |> element("#execute-query") |> render_click()

      # Wait for results
      :timer.sleep(200)

      assert has_element?(view, ".result-row")
      assert render(view) =~ "powershell.exe"
      assert render(view) =~ "1234"
    end

    test "query execution with progress indicator", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/hunting")

      # Build and execute query
      view |> element("#add-condition") |> render_click()
      view
      |> element("#condition-0")
      |> render_change(%{
        condition: %{field: "process.name", operator: "equals", value: "test.exe"}
      })

      view |> element("#execute-query") |> render_click()

      # Should show progress
      assert has_element?(view, ".query-executing")
      assert has_element?(view, ".progress-bar")
    end

    test "query timeout handling", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/hunting")

      # Simulate timeout
      send(view.pid, {:query_timeout, "Query exceeded 60 second timeout"})

      :timer.sleep(100)

      assert has_element?(view, ".error", "Query exceeded 60 second timeout")
    end

    test "cancel running query", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/hunting")

      # Start query
      view |> element("#add-condition") |> render_click()
      view
      |> element("#condition-0")
      |> render_change(%{
        condition: %{field: "process.name", operator: "equals", value: "test.exe"}
      })

      view |> element("#execute-query") |> render_click()

      # Cancel
      view |> element("#cancel-query") |> render_click()

      assert has_element?(view, ".query-cancelled")
    end
  end

  describe "results display" do
    test "results pagination", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent)

      # Create 100 events
      for i <- 1..100 do
        insert(:telemetry_event,
          agent: agent,
          event_type: "process_create",
          data: %{"name" => "process-#{i}.exe", "pid" => i}
        )
      end

      {:ok, view, _html} = live(conn, "/hunting")

      # Execute query that matches all
      view |> element("#add-condition") |> render_click()
      view
      |> element("#condition-0")
      |> render_change(%{
        condition: %{field: "event_type", operator: "equals", value: "process_create"}
      })

      view |> element("#execute-query") |> render_click()
      :timer.sleep(200)

      # Should show first page (25 results)
      results = view |> element(".results-table") |> render()
      assert results =~ "process-1.exe"
      refute results =~ "process-50.exe"

      # Go to next page
      view |> element(".next-page") |> render_click()

      results = view |> element(".results-table") |> render()
      assert results =~ "process-26.exe"
    end

    test "sort results by column", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent)

      insert(:telemetry_event, agent: agent, data: %{"name" => "z-process.exe"})
      insert(:telemetry_event, agent: agent, data: %{"name" => "a-process.exe"})
      insert(:telemetry_event, agent: agent, data: %{"name" => "m-process.exe"})

      {:ok, view, _html} = live(conn, "/hunting")

      # Execute query
      view |> element("#add-condition") |> render_click()
      view
      |> element("#condition-0")
      |> render_change(%{
        condition: %{field: "event_type", operator: "equals", value: "process_create"}
      })

      view |> element("#execute-query") |> render_click()
      :timer.sleep(200)

      # Sort by name
      view |> element(".column-header-name") |> render_click()

      # Check order
      html = render(view)
      a_pos = :binary.match(html, "a-process.exe") |> elem(0)
      m_pos = :binary.match(html, "m-process.exe") |> elem(0)
      z_pos = :binary.match(html, "z-process.exe") |> elem(0)

      assert a_pos < m_pos
      assert m_pos < z_pos
    end

    test "filter results", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent)

      insert(:telemetry_event, agent: agent, data: %{"name" => "chrome.exe"})
      insert(:telemetry_event, agent: agent, data: %{"name" => "firefox.exe"})

      {:ok, view, _html} = live(conn, "/hunting")

      # Execute query
      view |> element("#add-condition") |> render_click()
      view
      |> element("#condition-0")
      |> render_change(%{
        condition: %{field: "event_type", operator: "equals", value: "process_create"}
      })

      view |> element("#execute-query") |> render_click()
      :timer.sleep(200)

      # Apply filter
      view
      |> element("#results-filter")
      |> render_change(%{filter: "chrome"})

      assert render(view) =~ "chrome.exe"
      refute render(view) =~ "firefox.exe"
    end

    test "expand result details", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent)

      event = insert(:telemetry_event,
        agent: agent,
        data: %{
          "name" => "powershell.exe",
          "command_line" => "powershell.exe -enc AAABBBCCC",
          "parent_name" => "explorer.exe"
        }
      )

      {:ok, view, _html} = live(conn, "/hunting")

      # Execute query
      view |> element("#add-condition") |> render_click()
      view
      |> element("#condition-0")
      |> render_change(%{
        condition: %{field: "process.name", operator: "equals", value: "powershell.exe"}
      })

      view |> element("#execute-query") |> render_click()
      :timer.sleep(200)

      # Expand details
      view
      |> element("[data-event-id='#{event.id}'] .expand-button")
      |> render_click()

      assert has_element?(view, ".event-details")
      assert render(view) =~ "powershell.exe -enc AAABBBCCC"
      assert render(view) =~ "explorer.exe"
    end
  end

  describe "saved queries" do
    test "save query", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/hunting")

      # Build query
      view |> element("#add-condition") |> render_click()
      view
      |> element("#condition-0")
      |> render_change(%{
        condition: %{field: "process.name", operator: "equals", value: "powershell.exe"}
      })

      # Save query
      view |> element("#save-query") |> render_click()

      view
      |> element("#save-query-form")
      |> render_submit(%{
        query: %{
          name: "Suspicious PowerShell",
          description: "Detects PowerShell execution"
        }
      })

      assert has_element?(view, ".saved-query", "Suspicious PowerShell")
    end

    test "load saved query", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      saved_query = insert(:saved_query,
        user: user,
        name: "Test Query",
        query: %{
          conditions: [
            %{field: "process.name", operator: "equals", value: "test.exe"}
          ]
        }
      )

      {:ok, view, _html} = live(conn, "/hunting")

      # Load saved query
      view
      |> element("[data-query-id='#{saved_query.id}'] .load-button")
      |> render_click()

      assert has_element?(view, ".condition-value", "test.exe")
    end

    test "delete saved query", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      saved_query = insert(:saved_query, user: user, name: "Old Query")

      {:ok, view, _html} = live(conn, "/hunting/saved")

      # Delete query
      view
      |> element("[data-query-id='#{saved_query.id}'] .delete-button")
      |> render_click()

      # Confirm
      view |> element("#confirm-delete") |> render_click()

      refute has_element?(view, "[data-query-id='#{saved_query.id}']")
    end

    test "share saved query", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      saved_query = insert(:saved_query, user: user, name: "Shared Query", shared: false)

      {:ok, view, _html} = live(conn, "/hunting/saved")

      # Share query
      view
      |> element("[data-query-id='#{saved_query.id}'] .share-button")
      |> render_click()

      assert has_element?(view, ".query-shared-badge")
    end
  end

  describe "export functionality" do
    test "export results as CSV", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent)

      insert(:telemetry_event, agent: agent, data: %{"name" => "test.exe"})

      {:ok, view, _html} = live(conn, "/hunting")

      # Execute query
      view |> element("#add-condition") |> render_click()
      view
      |> element("#condition-0")
      |> render_change(%{
        condition: %{field: "process.name", operator: "equals", value: "test.exe"}
      })

      view |> element("#execute-query") |> render_click()
      :timer.sleep(200)

      # Export as CSV
      view |> element("#export-csv") |> render_click()

      assert_push_event(view, "download", %{format: "csv"})
    end

    test "export results as JSON", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent)

      insert(:telemetry_event, agent: agent, data: %{"name" => "test.exe"})

      {:ok, view, _html} = live(conn, "/hunting")

      # Execute query
      view |> element("#add-condition") |> render_click()
      view
      |> element("#condition-0")
      |> render_change(%{
        condition: %{field: "process.name", operator: "equals", value: "test.exe"}
      })

      view |> element("#execute-query") |> render_click()
      :timer.sleep(200)

      # Export as JSON
      view |> element("#export-json") |> render_click()

      assert_push_event(view, "download", %{format: "json"})
    end

    test "export query as Sigma rule", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/hunting")

      # Build query
      view |> element("#add-condition") |> render_click()
      view
      |> element("#condition-0")
      |> render_change(%{
        condition: %{field: "process.name", operator: "equals", value: "powershell.exe"}
      })

      # Export as Sigma
      view |> element("#export-sigma") |> render_click()

      assert_push_event(view, "download", %{format: "sigma"})
    end
  end

  describe "query templates" do
    test "use predefined template", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/hunting")

      # Select template
      view
      |> element("#template-select")
      |> render_change(%{template: "suspicious_powershell"})

      # Template should populate query builder
      assert has_element?(view, ".condition-field", "process.name")
      assert has_element?(view, ".condition-value", "powershell.exe")
    end

    test "customize template parameters", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/hunting")

      # Select template with parameters
      view
      |> element("#template-select")
      |> render_change(%{template: "process_by_name"})

      # Fill parameter
      view
      |> element("#template-params")
      |> render_change(%{params: %{process_name: "custom.exe"}})

      assert has_element?(view, ".condition-value", "custom.exe")
    end
  end

  describe "query history" do
    test "displays recent queries", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      # Create query history
      insert(:query_history, user: user, query: %{conditions: []}, executed_at: DateTime.utc_now())

      {:ok, view, _html} = live(conn, "/hunting/history")

      assert has_element?(view, ".query-history-item")
    end

    test "rerun query from history", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      history = insert(:query_history,
        user: user,
        query: %{
          conditions: [
            %{field: "process.name", operator: "equals", value: "test.exe"}
          ]
        }
      )

      {:ok, view, _html} = live(conn, "/hunting/history")

      # Rerun query
      view
      |> element("[data-history-id='#{history.id}'] .rerun-button")
      |> render_click()

      # Should navigate to hunting page with query loaded
      assert_redirect(view, "/hunting")
    end
  end

  describe "collaborative hunting" do
    test "share hunt session", %{conn: conn} do
      user1 = insert(:user)
      user2 = insert(:user)
      conn = log_in_user(conn, user1)

      {:ok, view, _html} = live(conn, "/hunting")

      # Create shared session
      view |> element("#create-shared-session") |> render_click()

      session_id = view.assigns.session_id

      # User2 joins
      conn2 = log_in_user(conn, user2)
      {:ok, view2, _html} = live(conn2, "/hunting?session=#{session_id}")

      # User1 adds condition
      view |> element("#add-condition") |> render_click()

      :timer.sleep(100)

      # User2 should see the update
      assert has_element?(view2, ".condition")
    end
  end
end
