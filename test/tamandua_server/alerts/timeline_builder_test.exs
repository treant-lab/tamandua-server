defmodule TamanduaServer.Alerts.TimelineBuilderTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.Alerts.{Alert, TimelineBuilder, CommentManager}
  alias TamanduaServer.Response
  alias TamanduaServer.Accounts.User

  describe "build_timeline/2" do
    setup do
      # Create test user
      {:ok, user} =
        %User{}
        |> User.changeset(%{
          email: "analyst@test.com",
          name: "Test Analyst",
          password: "SecurePassword123!"
        })
        |> Repo.insert()

      # Create test alert
      {:ok, alert} =
        %Alert{}
        |> Alert.changeset(%{
          severity: "high",
          title: "Suspicious Process Detected",
          description: "Malicious process detected",
          status: "new"
        })
        |> Repo.insert()

      %{alert: alert, user: user}
    end

    test "includes alert creation event", %{alert: alert} do
      timeline = TimelineBuilder.build_timeline(alert)

      assert Enum.any?(timeline, fn event ->
               event.type == "detection" &&
                 event.subtype == "alert_created" &&
                 event.title == "Alert Created"
             end)
    end

    test "includes status change events", %{alert: alert, user: user} do
      # Update alert status
      {:ok, alert} =
        alert
        |> Alert.changeset(%{
          status: "investigating",
          state_changed_by_id: user.id,
          state_changed_at: DateTime.utc_now()
        })
        |> Repo.update()

      alert = Repo.preload(alert, [:state_changed_by])

      timeline = TimelineBuilder.build_timeline(alert)

      assert Enum.any?(timeline, fn event ->
               event.type == "analyst" &&
                 event.subtype == "status_changed" &&
                 event.metadata.status == "investigating"
             end)
    end

    test "includes assignment events", %{alert: alert, user: user} do
      {:ok, alert} =
        alert
        |> Alert.changeset(%{
          assigned_to_id: user.id,
          assigned_by_id: user.id,
          assigned_at: DateTime.utc_now()
        })
        |> Repo.update()

      alert = Repo.preload(alert, [:assigned_to, :assigned_by])

      timeline = TimelineBuilder.build_timeline(alert)

      assert Enum.any?(timeline, fn event ->
               event.type == "analyst" &&
                 event.subtype == "assignment_changed" &&
                 event.metadata.assigned_to_id == user.id
             end)
    end

    test "includes acknowledgment events", %{alert: alert, user: user} do
      {:ok, alert} =
        alert
        |> Alert.changeset(%{
          acknowledged_at: DateTime.utc_now(),
          acknowledged_by_id: user.id
        })
        |> Repo.update()

      alert = Repo.preload(alert, [:acknowledged_by])

      timeline = TimelineBuilder.build_timeline(alert)

      assert Enum.any?(timeline, fn event ->
               event.type == "analyst" && event.subtype == "acknowledged"
             end)
    end

    test "includes escalation events", %{alert: alert, user: user} do
      {:ok, alert} =
        alert
        |> Alert.changeset(%{
          escalated_at: DateTime.utc_now(),
          escalated_to_id: user.id,
          escalation_level: 2,
          escalation_reason: "High severity threat"
        })
        |> Repo.update()

      alert = Repo.preload(alert, [:escalated_to])

      timeline = TimelineBuilder.build_timeline(alert)

      assert Enum.any?(timeline, fn event ->
               event.type == "analyst" &&
                 event.subtype == "escalated" &&
                 event.metadata.escalation_level == 2
             end)
    end

    test "includes verdict events", %{alert: alert, user: user} do
      {:ok, alert} =
        alert
        |> Alert.changeset(%{
          verdict: "true_positive",
          verdict_by_id: user.id,
          verdict_at: DateTime.utc_now(),
          verdict_notes: "Confirmed malware"
        })
        |> Repo.update()

      alert = Repo.preload(alert, [:verdict_by])

      timeline = TimelineBuilder.build_timeline(alert)

      assert Enum.any?(timeline, fn event ->
               event.type == "analyst" &&
                 event.subtype == "verdict_changed" &&
                 event.metadata.verdict == "true_positive"
             end)
    end

    test "includes severity adjustment events", %{alert: alert, user: user} do
      {:ok, alert} =
        alert
        |> Alert.changeset(%{
          original_severity: "high",
          severity: "critical",
          severity_adjusted: true,
          severity_adjusted_at: DateTime.utc_now(),
          severity_adjusted_by_id: user.id
        })
        |> Repo.update()

      alert = Repo.preload(alert, [:severity_adjusted_by])

      timeline = TimelineBuilder.build_timeline(alert)

      assert Enum.any?(timeline, fn event ->
               event.type == "analyst" &&
                 event.subtype == "severity_adjusted" &&
                 event.metadata.original_severity == "high" &&
                 event.metadata.new_severity == "critical"
             end)
    end

    test "includes resolution events", %{alert: alert} do
      {:ok, alert} =
        alert
        |> Alert.changeset(%{
          status: "resolved",
          resolved_at: DateTime.utc_now(),
          resolution_notes: "False positive - known good software"
        })
        |> Repo.update()

      timeline = TimelineBuilder.build_timeline(alert)

      assert Enum.any?(timeline, fn event ->
               event.type == "analyst" &&
                 event.subtype == "resolved" &&
                 event.metadata.resolution_notes == "False positive - known good software"
             end)
    end

    test "includes ML analysis events", %{alert: alert} do
      {:ok, alert} =
        alert
        |> Alert.changeset(%{
          detection_metadata: %{
            "ml_score" => 0.95,
            "model_version" => "v2.1.0"
          }
        })
        |> Repo.update()

      timeline = TimelineBuilder.build_timeline(alert)

      assert Enum.any?(timeline, fn event ->
               event.type == "system" &&
                 event.subtype == "ml_analysis" &&
                 event.metadata.ml_score == 0.95
             end)
    end

    test "includes enrichment events", %{alert: alert} do
      {:ok, alert} =
        alert
        |> Alert.changeset(%{
          enrichment: %{
            "virustotal" => %{"positives" => 45},
            "reputation" => %{"score" => 0.1}
          }
        })
        |> Repo.update()

      timeline = TimelineBuilder.build_timeline(alert)

      assert Enum.any?(timeline, fn event ->
               event.type == "system" &&
                 event.subtype == "enrichment_completed" &&
                 event.metadata.enrichment_count == 2
             end)
    end

    test "includes correlation events", %{alert: alert} do
      {:ok, alert} =
        alert
        |> Alert.changeset(%{
          storyline_id: "storyline_123",
          correlation_data: %{"related_alerts" => 5}
        })
        |> Repo.update()

      timeline = TimelineBuilder.build_timeline(alert)

      assert Enum.any?(timeline, fn event ->
               event.type == "system" &&
                 event.subtype == "correlation" &&
                 event.metadata.storyline_id == "storyline_123"
             end)
    end

    test "includes deduplication events", %{alert: alert} do
      {:ok, alert} =
        alert
        |> Alert.changeset(%{
          occurrence_count: 5,
          last_seen_at: DateTime.utc_now(),
          dedup_key: "dedup_123"
        })
        |> Repo.update()

      timeline = TimelineBuilder.build_timeline(alert)

      assert Enum.any?(timeline, fn event ->
               event.type == "system" &&
                 event.subtype == "deduplication" &&
                 event.metadata.occurrence_count == 5
             end)
    end

    test "sorts events chronologically", %{alert: alert, user: user} do
      # Create events with different timestamps
      now = DateTime.utc_now()

      {:ok, alert} =
        alert
        |> Alert.changeset(%{
          assigned_at: DateTime.add(now, 10, :second),
          assigned_to_id: user.id,
          acknowledged_at: DateTime.add(now, 20, :second),
          acknowledged_by_id: user.id,
          escalated_at: DateTime.add(now, 30, :second),
          escalated_to_id: user.id,
          escalation_level: 1
        })
        |> Repo.update()

      alert = Repo.preload(alert, [:assigned_to, :acknowledged_by, :escalated_to])

      timeline = TimelineBuilder.build_timeline(alert)

      # Verify chronological order
      timestamps = Enum.map(timeline, & &1.timestamp)
      assert timestamps == Enum.sort(timestamps, {:asc, DateTime})
    end

    test "respects limit option", %{alert: alert, user: user} do
      # Create multiple events
      {:ok, alert} =
        alert
        |> Alert.changeset(%{
          assigned_to_id: user.id,
          assigned_at: DateTime.utc_now(),
          acknowledged_at: DateTime.utc_now(),
          acknowledged_by_id: user.id,
          escalated_at: DateTime.utc_now(),
          escalated_to_id: user.id,
          escalation_level: 1
        })
        |> Repo.update()

      alert = Repo.preload(alert, [:assigned_to, :acknowledged_by, :escalated_to])

      timeline = TimelineBuilder.build_timeline(alert, limit: 2)

      assert length(timeline) == 2
    end

    test "excludes comments when option is false", %{alert: alert, user: user} do
      # Add a comment
      CommentManager.create_comment(
        %{"content" => "Test comment"},
        user,
        alert
      )

      timeline_with_comments = TimelineBuilder.build_timeline(alert, include_comments: true)
      timeline_without_comments = TimelineBuilder.build_timeline(alert, include_comments: false)

      assert length(timeline_with_comments) > length(timeline_without_comments)
    end
  end

  describe "export_timeline_json/2" do
    setup do
      {:ok, alert} =
        %Alert{}
        |> Alert.changeset(%{
          severity: "high",
          title: "Test Alert",
          description: "Test description",
          status: "new"
        })
        |> Repo.insert()

      %{alert: alert}
    end

    test "exports timeline in vis.js format", %{alert: alert} do
      export = TimelineBuilder.export_timeline_json(alert)

      assert is_map(export)
      assert Map.has_key?(export, :items)
      assert Map.has_key?(export, :groups)
      assert Map.has_key?(export, :options)
    end

    test "items have required vis.js fields", %{alert: alert} do
      export = TimelineBuilder.export_timeline_json(alert)

      [first_item | _] = export.items

      assert Map.has_key?(first_item, :id)
      assert Map.has_key?(first_item, :group)
      assert Map.has_key?(first_item, :content)
      assert Map.has_key?(first_item, :start)
      assert Map.has_key?(first_item, :type)
    end

    test "groups contain all event categories", %{alert: alert} do
      export = TimelineBuilder.export_timeline_json(alert)

      group_ids = Enum.map(export.groups, & &1.id)

      assert "detection" in group_ids
      assert "response" in group_ids
      assert "analyst" in group_ids
      assert "system" in group_ids
      assert "external" in group_ids
    end

    test "includes recommended vis.js options", %{alert: alert} do
      export = TimelineBuilder.export_timeline_json(alert)

      assert export.options.stack == false
      assert export.options.showCurrentTime == true
      assert export.options.editable == false
    end
  end
end
