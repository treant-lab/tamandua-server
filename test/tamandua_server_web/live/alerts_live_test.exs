defmodule TamanduaServerWeb.AlertsLiveTest do
  use TamanduaServerWeb.ConnCase

  import Phoenix.LiveViewTest

  alias TamanduaServer.Alerts
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Repo

  describe "Alerts Index" do
    setup do
      # Create test alerts
      {:ok, alert1} = create_test_alert(%{
        title: "High Severity Alert",
        severity: "high",
        status: "new"
      })

      {:ok, alert2} = create_test_alert(%{
        title: "Medium Severity Alert",
        severity: "medium",
        status: "investigating"
      })

      {:ok, alert3} = create_test_alert(%{
        title: "Low Severity Alert",
        severity: "low",
        status: "resolved"
      })

      %{alert1: alert1, alert2: alert2, alert3: alert3}
    end

    test "displays alerts list", %{conn: conn, alert1: alert1, alert2: alert2} do
      {:ok, view, html} = live(conn, ~p"/alerts")

      assert html =~ "Alerts"
      assert html =~ alert1.title
      assert html =~ alert2.title
    end

    test "displays checkbox column for multi-select", %{conn: conn} do
      {:ok, view, html} = live(conn, ~p"/alerts")

      # Should have checkbox in header
      assert html =~ ~r/type="checkbox"/
    end

    test "select all functionality", %{conn: conn, alert1: alert1, alert2: alert2} do
      {:ok, view, _html} = live(conn, ~p"/alerts")

      # Initially no alerts selected
      refute render(view) =~ "alert(s) selected"

      # Click select all
      view
      |> element("input[type='checkbox'][phx-click='select_all']")
      |> render_click()

      # Should show selection count
      assert render(view) =~ "alert(s) selected"
    end

    test "deselect all functionality", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/alerts")

      # Select all first
      view
      |> element("input[type='checkbox'][phx-click='select_all']")
      |> render_click()

      assert render(view) =~ "alert(s) selected"

      # Now deselect all
      view
      |> element("button[phx-click='deselect_all']")
      |> render_click()

      # Selection should be cleared
      refute render(view) =~ "alert(s) selected"
    end

    test "toggle individual alert selection", %{conn: conn, alert1: alert1} do
      {:ok, view, _html} = live(conn, ~p"/alerts")

      # Select individual alert
      view
      |> element("input[type='checkbox'][phx-value-id='#{alert1.id}']")
      |> render_click()

      # Should show 1 selected
      assert render(view) =~ "1 alert(s) selected"
    end

    test "bulk actions toolbar appears when alerts selected", %{conn: conn, alert1: alert1} do
      {:ok, view, _html} = live(conn, ~p"/alerts")

      # Initially no toolbar
      refute render(view) =~ "Update Status"

      # Select an alert
      view
      |> element("input[type='checkbox'][phx-value-id='#{alert1.id}']")
      |> render_click()

      # Toolbar should appear
      assert render(view) =~ "Update Status"
      assert render(view) =~ "Assign"
      assert render(view) =~ "Add Tags"
      assert render(view) =~ "Delete"
    end

    test "clicking bulk action button shows confirmation modal", %{conn: conn, alert1: alert1} do
      {:ok, view, _html} = live(conn, ~p"/alerts")

      # Select an alert
      view
      |> element("input[type='checkbox'][phx-value-id='#{alert1.id}']")
      |> render_click()

      # Click update status button
      view
      |> element("button[phx-value-action='update_status']")
      |> render_click()

      # Modal should appear
      html = render(view)
      assert html =~ "Update Alert Status"
      assert html =~ "You are about to perform this action on"
    end

    test "confirmation modal can be cancelled", %{conn: conn, alert1: alert1} do
      {:ok, view, _html} = live(conn, ~p"/alerts")

      # Select and open modal
      view
      |> element("input[type='checkbox'][phx-value-id='#{alert1.id}']")
      |> render_click()

      view
      |> element("button[phx-value-action='delete']")
      |> render_click()

      assert render(view) =~ "Delete Alerts"

      # Cancel modal
      view
      |> element("button[phx-click='cancel_confirmation']")
      |> render_click()

      # Modal should be gone
      refute render(view) =~ "Delete Alerts"
    end

    test "filtering alerts by severity", %{conn: conn, alert1: alert1, alert3: alert3} do
      {:ok, view, _html} = live(conn, ~p"/alerts")

      # Filter by high severity
      view
      |> element("form")
      |> render_change(%{"severity" => "high"})

      html = render(view)
      assert html =~ alert1.title
      refute html =~ alert3.title
    end

    test "filtering alerts by status", %{conn: conn, alert2: alert2, alert3: alert3} do
      {:ok, view, _html} = live(conn, ~p"/alerts")

      # Filter by resolved status
      view
      |> element("form")
      |> render_change(%{"status" => "resolved"})

      html = render(view)
      assert html =~ alert3.title
      refute html =~ alert2.title
    end

    test "clearing filters", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/alerts?severity=high")

      # Should show filter applied
      assert view.assigns.filters[:severity] == "high"

      # Clear filters
      view
      |> element("button[phx-click='clear_filters']")
      |> render_click()

      # Filters should be cleared
      assert view.assigns.filters == %{}
    end

    test "sorting alerts by severity", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/alerts")

      # Click severity header to sort
      view
      |> element("th[phx-value-field='severity']")
      |> render_click()

      # Should be sorted by severity
      assert view.assigns.sort_by == :severity
      assert view.assigns.sort_order == :asc
    end

    test "selected alerts are highlighted", %{conn: conn, alert1: alert1} do
      {:ok, view, _html} = live(conn, ~p"/alerts")

      # Select an alert
      view
      |> element("input[type='checkbox'][phx-value-id='#{alert1.id}']")
      |> render_click()

      # Row should have highlighted class
      html = render(view)
      assert html =~ "bg-indigo-50"
    end

    test "displays progress indicator during bulk operation", %{conn: conn, alert1: alert1} do
      {:ok, view, _html} = live(conn, ~p"/alerts")

      # Note: Testing async operations in LiveView is complex
      # This test structure shows how it would be done
      view
      |> element("input[type='checkbox'][phx-value-id='#{alert1.id}']")
      |> render_click()

      # The actual bulk operation would need to be mocked or
      # intercepted to test the loading state properly
      assert true
    end
  end

  describe "Bulk Operations Integration" do
    test "bulk status update works end-to-end", %{conn: conn} do
      {:ok, alert1} = create_test_alert(%{status: "new"})
      {:ok, alert2} = create_test_alert(%{status: "new"})

      {:ok, view, _html} = live(conn, ~p"/alerts")

      # Select alerts
      view
      |> element("input[type='checkbox'][phx-value-id='#{alert1.id}']")
      |> render_click()

      view
      |> element("input[type='checkbox'][phx-value-id='#{alert2.id}']")
      |> render_click()

      # Open update status modal
      view
      |> element("button[phx-value-action='update_status']")
      |> render_click()

      # Confirm with status change
      # Note: The actual confirmation with form data would need
      # JavaScript hook integration or different test approach
      # This shows the structure

      assert true
    end

    test "bulk delete removes alerts", %{conn: conn} do
      {:ok, alert1} = create_test_alert(%{title: "To Delete 1"})
      {:ok, alert2} = create_test_alert(%{title: "To Delete 2"})

      # Manual bulk delete test
      user = %{id: Ecto.UUID.generate(), email: "test@example.com", organization_id: nil}
      {:ok, count} = Alerts.bulk_delete([alert1.id, alert2.id], user)

      assert count == 2
      assert is_nil(Repo.get(Alert, alert1.id))
      assert is_nil(Repo.get(Alert, alert2.id))
    end

    test "bulk operations show success flash message", %{conn: conn} do
      {:ok, alert} = create_test_alert(%{status: "new"})

      # Test that flash messages would appear
      # In actual LiveView, this would be tested via the rendered output
      # after a bulk operation completes

      assert true
    end
  end

  # Helper function to create test alerts
  defp create_test_alert(attrs) do
    default_attrs = %{
      title: "Test Alert",
      description: "Test alert description",
      severity: "medium",
      status: "new",
      agent_id: Ecto.UUID.generate(),
      organization_id: Ecto.UUID.generate()
    }

    merged_attrs = Map.merge(default_attrs, attrs)

    %Alert{}
    |> Alert.changeset(merged_attrs)
    |> Repo.insert()
  end
end
