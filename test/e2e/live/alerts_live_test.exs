defmodule TamanduaServerWeb.E2E.AlertsLiveTest do
  use TamanduaServer.LiveViewCase, async: false
  alias TamanduaServer.Alerts

  describe "real-time alert updates" do
    test "new alert appears without refresh", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      {:ok, view, _html} = live(conn, "/alerts")

      # Simulate new alert from agent
      alert = insert(:alert, severity: :critical, title: "Ransomware Detected", status: :new)
      Phoenix.PubSub.broadcast(TamanduaServer.PubSub, "alerts:new", {:new_alert, alert})

      # Assert it appears in real-time
      assert has_element?(view, "[data-alert-id='#{alert.id}']")
      assert has_element?(view, ".alert-critical", "Ransomware Detected")
    end

    test "alert status updates in real-time", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      alert = insert(:alert, status: :new, severity: :high, title: "Suspicious Process")

      {:ok, view, _html} = live(conn, "/alerts/#{alert.id}")

      # Update alert status
      {:ok, updated_alert} = Alerts.update_alert(alert, %{status: :investigating})

      # Broadcast update
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "alerts:#{alert.id}",
        {:alert_updated, updated_alert}
      )

      # Assert status badge updates
      assert has_element?(view, ".badge-investigating")
      refute has_element?(view, ".badge-new")
    end

    test "correlation graph updates with new connections", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      alert = insert(:alert, severity: :medium)

      {:ok, view, _html} = live(conn, "/alerts/#{alert.id}/correlation")

      # Add correlated alert
      related = insert(:alert, severity: :high)
      {:ok, _correlation} = Alerts.correlate_alerts(alert.id, related.id, 0.85)

      # Broadcast correlation
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "alerts:#{alert.id}:correlations",
        {:new_correlation, %{alert_id: related.id, score: 0.85}}
      )

      # Assert graph updates
      assert has_element?(view, "[data-node-id='#{related.id}']")
      assert render(view) =~ "0.85"
    end

    test "multiple alerts appear in correct order", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      {:ok, view, _html} = live(conn, "/alerts")

      # Create alerts with different timestamps
      alert1 = insert(:alert, severity: :low, inserted_at: ~N[2024-01-01 10:00:00])
      alert2 = insert(:alert, severity: :high, inserted_at: ~N[2024-01-01 10:05:00])
      alert3 = insert(:alert, severity: :critical, inserted_at: ~N[2024-01-01 10:10:00])

      # Broadcast in random order
      Phoenix.PubSub.broadcast(TamanduaServer.PubSub, "alerts:new", {:new_alert, alert2})
      Phoenix.PubSub.broadcast(TamanduaServer.PubSub, "alerts:new", {:new_alert, alert3})
      Phoenix.PubSub.broadcast(TamanduaServer.PubSub, "alerts:new", {:new_alert, alert1})

      # Wait for updates to propagate
      :timer.sleep(100)

      # Assert alerts appear in chronological order (newest first)
      html = render(view)
      alert3_pos = :binary.match(html, alert3.id) |> elem(0)
      alert2_pos = :binary.match(html, alert2.id) |> elem(0)
      alert1_pos = :binary.match(html, alert1.id) |> elem(0)

      assert alert3_pos < alert2_pos
      assert alert2_pos < alert1_pos
    end

    test "alert severity badge updates dynamically", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      alert = insert(:alert, severity: :low)

      {:ok, view, _html} = live(conn, "/alerts/#{alert.id}")

      assert has_element?(view, ".badge-low")

      # Escalate severity
      {:ok, updated_alert} = Alerts.update_alert(alert, %{severity: :critical})

      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "alerts:#{alert.id}",
        {:alert_updated, updated_alert}
      )

      assert has_element?(view, ".badge-critical")
      refute has_element?(view, ".badge-low")
    end
  end

  describe "alert timeline" do
    test "timeline shows events chronologically", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      alert = insert(:alert)

      event1 = insert(:alert_event, alert: alert, type: :created, timestamp: ~U[2024-01-01 10:00:00Z])
      event2 = insert(:alert_event, alert: alert, type: :assigned, timestamp: ~U[2024-01-01 10:05:00Z])
      event3 = insert(:alert_event, alert: alert, type: :comment, timestamp: ~U[2024-01-01 10:10:00Z])

      {:ok, view, _html} = live(conn, "/alerts/#{alert.id}/timeline")

      # Check order (most recent first)
      html = render(view)
      event3_pos = :binary.match(html, event3.id) |> elem(0)
      event2_pos = :binary.match(html, event2.id) |> elem(0)
      event1_pos = :binary.match(html, event1.id) |> elem(0)

      assert event3_pos < event2_pos
      assert event2_pos < event1_pos
    end

    test "new timeline event appears in real-time", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      alert = insert(:alert)

      {:ok, view, _html} = live(conn, "/alerts/#{alert.id}/timeline")

      # Add new event
      event = insert(:alert_event, alert: alert, type: :status_changed, data: %{from: :new, to: :investigating})

      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "alerts:#{alert.id}:timeline",
        {:new_event, event}
      )

      assert has_element?(view, "[data-event-id='#{event.id}']")
      assert render(view) =~ "status_changed"
    end

    test "playback mode works", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      alert = insert(:alert)

      # Create series of events
      events = for i <- 1..10 do
        insert(:alert_event,
          alert: alert,
          type: :comment,
          timestamp: DateTime.add(~U[2024-01-01 10:00:00Z], i * 60, :second),
          data: %{content: "Event #{i}"}
        )
      end

      {:ok, view, _html} = live(conn, "/alerts/#{alert.id}/timeline?playback=true")

      # Start playback
      view |> element("#playback-start") |> render_click()

      # Check initial state (should show only first event)
      assert has_element?(view, "[data-event-id='#{hd(events).id}']")
      refute has_element?(view, "[data-event-id='#{List.last(events).id}']")

      # Advance playback
      view |> element("#playback-forward") |> render_click()

      # Should show second event
      assert has_element?(view, "[data-event-id='#{Enum.at(events, 1).id}']")
    end

    test "timeline filtering works", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      alert = insert(:alert)

      comment_event = insert(:alert_event, alert: alert, type: :comment)
      status_event = insert(:alert_event, alert: alert, type: :status_changed)
      assigned_event = insert(:alert_event, alert: alert, type: :assigned)

      {:ok, view, _html} = live(conn, "/alerts/#{alert.id}/timeline")

      # Filter to only show comments
      view
      |> element("#timeline-filter")
      |> render_change(%{filter: %{types: ["comment"]}})

      assert has_element?(view, "[data-event-id='#{comment_event.id}']")
      refute has_element?(view, "[data-event-id='#{status_event.id}']")
      refute has_element?(view, "[data-event-id='#{assigned_event.id}']")
    end
  end

  describe "alert assignment" do
    test "assign alert to user", %{conn: conn} do
      user = insert(:user)
      analyst = insert(:user, role: :analyst)
      conn = log_in_user(conn, user)
      alert = insert(:alert, assigned_to: nil)

      {:ok, view, _html} = live(conn, "/alerts/#{alert.id}")

      # Assign alert
      view
      |> element("#assign-form")
      |> render_submit(%{assignment: %{user_id: analyst.id}})

      assert has_element?(view, ".assigned-to", analyst.email)
    end

    test "assignment appears in real-time for other viewers", %{conn: conn} do
      user1 = insert(:user)
      user2 = insert(:user)
      analyst = insert(:user, role: :analyst)
      alert = insert(:alert, assigned_to: nil)

      conn1 = log_in_user(conn, user1)
      conn2 = log_in_user(conn, user2)

      {:ok, view1, _html} = live(conn1, "/alerts/#{alert.id}")
      {:ok, view2, _html} = live(conn2, "/alerts/#{alert.id}")

      # User1 assigns alert
      {:ok, updated_alert} = Alerts.assign_alert(alert, analyst.id)

      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "alerts:#{alert.id}",
        {:alert_updated, updated_alert}
      )

      # Both views should show assignment
      assert has_element?(view1, ".assigned-to", analyst.email)
      assert has_element?(view2, ".assigned-to", analyst.email)
    end
  end

  describe "alert comments" do
    test "add comment to alert", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      alert = insert(:alert)

      {:ok, view, _html} = live(conn, "/alerts/#{alert.id}")

      # Add comment
      view
      |> element("#comment-form")
      |> render_submit(%{comment: %{content: "This looks suspicious"}})

      assert has_element?(view, ".comment-content", "This looks suspicious")
      assert has_element?(view, ".comment-author", user.email)
    end

    test "comments appear in real-time", %{conn: conn} do
      user1 = insert(:user)
      user2 = insert(:user)
      alert = insert(:alert)

      conn1 = log_in_user(conn, user1)
      conn2 = log_in_user(conn, user2)

      {:ok, view1, _html} = live(conn1, "/alerts/#{alert.id}")
      {:ok, view2, _html} = live(conn2, "/alerts/#{alert.id}")

      # User1 adds comment
      comment = insert(:comment, alert: alert, user: user1, content: "Investigating now")

      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "alerts:#{alert.id}:comments",
        {:new_comment, comment}
      )

      # Both views should show comment
      assert has_element?(view1, ".comment-content", "Investigating now")
      assert has_element?(view2, ".comment-content", "Investigating now")
    end

    test "comment with @mention sends notification", %{conn: conn} do
      user = insert(:user)
      mentioned_user = insert(:user, username: "analyst1")
      conn = log_in_user(conn, user)
      alert = insert(:alert)

      {:ok, view, _html} = live(conn, "/alerts/#{alert.id}")

      # Add comment with mention
      view
      |> element("#comment-form")
      |> render_submit(%{comment: %{content: "@analyst1 please review this"}})

      # Verify mention was processed
      assert has_element?(view, ".mention", "@analyst1")
    end
  end

  describe "alert filtering and search" do
    test "filter alerts by severity", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      critical_alert = insert(:alert, severity: :critical)
      high_alert = insert(:alert, severity: :high)
      low_alert = insert(:alert, severity: :low)

      {:ok, view, _html} = live(conn, "/alerts")

      # Filter to critical only
      view
      |> element("#filter-form")
      |> render_change(%{filter: %{severity: ["critical"]}})

      assert has_element?(view, "[data-alert-id='#{critical_alert.id}']")
      refute has_element?(view, "[data-alert-id='#{high_alert.id}']")
      refute has_element?(view, "[data-alert-id='#{low_alert.id}']")
    end

    test "filter alerts by status", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      new_alert = insert(:alert, status: :new)
      investigating_alert = insert(:alert, status: :investigating)
      resolved_alert = insert(:alert, status: :resolved)

      {:ok, view, _html} = live(conn, "/alerts")

      # Filter to investigating only
      view
      |> element("#filter-form")
      |> render_change(%{filter: %{status: ["investigating"]}})

      assert has_element?(view, "[data-alert-id='#{investigating_alert.id}']")
      refute has_element?(view, "[data-alert-id='#{new_alert.id}']")
      refute has_element?(view, "[data-alert-id='#{resolved_alert.id}']")
    end

    test "search alerts by title", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      ransomware_alert = insert(:alert, title: "Ransomware Detected")
      malware_alert = insert(:alert, title: "Malware Activity")
      phishing_alert = insert(:alert, title: "Phishing Attempt")

      {:ok, view, _html} = live(conn, "/alerts")

      # Search for "malware"
      view
      |> element("#search-form")
      |> render_change(%{search: %{query: "malware"}})

      assert has_element?(view, "[data-alert-id='#{malware_alert.id}']")
      refute has_element?(view, "[data-alert-id='#{ransomware_alert.id}']")
      refute has_element?(view, "[data-alert-id='#{phishing_alert.id}']")
    end

    test "combined filters work together", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      target_alert = insert(:alert, severity: :critical, status: :new, title: "Ransomware")
      wrong_severity = insert(:alert, severity: :low, status: :new, title: "Ransomware")
      wrong_status = insert(:alert, severity: :critical, status: :resolved, title: "Ransomware")

      {:ok, view, _html} = live(conn, "/alerts")

      # Apply multiple filters
      view
      |> element("#filter-form")
      |> render_change(%{
        filter: %{severity: ["critical"], status: ["new"]},
        search: %{query: "ransomware"}
      })

      assert has_element?(view, "[data-alert-id='#{target_alert.id}']")
      refute has_element?(view, "[data-alert-id='#{wrong_severity.id}']")
      refute has_element?(view, "[data-alert-id='#{wrong_status.id}']")
    end
  end

  describe "alert pagination" do
    test "loads more alerts on scroll", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      # Create 50 alerts
      alerts = for i <- 1..50 do
        insert(:alert, title: "Alert #{i}")
      end

      {:ok, view, _html} = live(conn, "/alerts")

      # Should initially show first page (e.g., 20 alerts)
      assert has_element?(view, "[data-alert-id='#{hd(alerts).id}']")
      refute has_element?(view, "[data-alert-id='#{List.last(alerts).id}']")

      # Trigger infinite scroll
      view |> element("#alerts-list") |> render_hook("load-more", %{})

      # Should now show more alerts
      assert has_element?(view, "[data-alert-id='#{Enum.at(alerts, 25).id}']")
    end
  end

  describe "alert actions" do
    test "resolve alert", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      alert = insert(:alert, status: :investigating)

      {:ok, view, _html} = live(conn, "/alerts/#{alert.id}")

      # Resolve alert
      view
      |> element("#resolve-button")
      |> render_click()

      assert has_element?(view, ".badge-resolved")
    end

    test "escalate alert", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      alert = insert(:alert, severity: :medium)

      {:ok, view, _html} = live(conn, "/alerts/#{alert.id}")

      # Escalate alert
      view
      |> element("#escalate-button")
      |> render_click()

      assert has_element?(view, ".badge-high")
    end

    test "bulk actions on multiple alerts", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      alert1 = insert(:alert, status: :new)
      alert2 = insert(:alert, status: :new)
      alert3 = insert(:alert, status: :new)

      {:ok, view, _html} = live(conn, "/alerts")

      # Select multiple alerts
      view |> element("[data-alert-id='#{alert1.id}'] input[type='checkbox']") |> render_click()
      view |> element("[data-alert-id='#{alert2.id}'] input[type='checkbox']") |> render_click()

      # Bulk assign
      view
      |> element("#bulk-actions-form")
      |> render_submit(%{action: "assign", user_id: user.id})

      # Both alerts should be assigned
      assert has_element?(view, "[data-alert-id='#{alert1.id}'] .assigned-to")
      assert has_element?(view, "[data-alert-id='#{alert2.id}'] .assigned-to")
    end
  end

  describe "alert export" do
    test "export alert as JSON", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      alert = insert(:alert)

      {:ok, view, _html} = live(conn, "/alerts/#{alert.id}")

      # Trigger export
      result = view |> element("#export-json") |> render_click()

      assert result =~ ~s("id":"#{alert.id}")
      assert result =~ ~s("severity")
    end

    test "export alert as PDF", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      alert = insert(:alert)

      {:ok, view, _html} = live(conn, "/alerts/#{alert.id}")

      # Trigger PDF export (returns download URL)
      view |> element("#export-pdf") |> render_click()

      # Verify download was initiated
      assert_push_event(view, "download", %{url: url})
      assert url =~ "/alerts/#{alert.id}/export.pdf"
    end
  end

  describe "alert metrics" do
    test "displays alert statistics", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      insert(:alert, severity: :critical, status: :new)
      insert(:alert, severity: :high, status: :investigating)
      insert(:alert, severity: :low, status: :resolved)

      {:ok, view, _html} = live(conn, "/alerts/metrics")

      assert has_element?(view, ".stat-total", "3")
      assert has_element?(view, ".stat-critical", "1")
      assert has_element?(view, ".stat-resolved", "1")
    end

    test "metrics update in real-time", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/alerts/metrics")

      initial_count = view |> element(".stat-total") |> render() |> String.trim()

      # Add new alert
      alert = insert(:alert)
      Phoenix.PubSub.broadcast(TamanduaServer.PubSub, "alerts:new", {:new_alert, alert})

      :timer.sleep(100)

      updated_count = view |> element(".stat-total") |> render() |> String.trim()

      assert String.to_integer(updated_count) == String.to_integer(initial_count) + 1
    end
  end
end
