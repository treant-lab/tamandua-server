defmodule TamanduaServer.Collaboration.ConflictResolverTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Collaboration.ConflictResolver
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Accounts.User

  describe "detect_conflicts/2" do
    test "returns :no_conflict when no fields changed" do
      current = %Alert{
        id: Ecto.UUID.generate(),
        status: "new",
        severity: "high"
      }

      changeset = Alert.changeset(current, %{title: "Same title"})

      assert ConflictResolver.detect_conflicts(current, changeset) == :no_conflict
    end
  end

  describe "auto_merge/3" do
    test "merges non-conflicting changes" do
      base = %{
        status: "new",
        severity: "high",
        assigned_to: nil
      }

      theirs = %{
        status: "investigating",
        severity: "high",
        assigned_to: nil
      }

      ours = %{
        status: "new",
        severity: "high",
        assigned_to: "user-123"
      }

      assert {:ok, merged} = ConflictResolver.auto_merge(base, theirs, ours)
      assert merged.status == "investigating"
      assert merged.assigned_to == "user-123"
    end

    test "detects conflicts when same field changed" do
      base = %{
        status: "new",
        severity: "high"
      }

      theirs = %{
        status: "investigating",
        severity: "high"
      }

      ours = %{
        status: "resolved",
        severity: "high"
      }

      assert {:conflict, details} = ConflictResolver.auto_merge(base, theirs, ours)
      assert :status in details.conflicting_fields
    end
  end

  describe "update_with_conflict_detection/4" do
    setup do
      user = insert(:user)
      alert = insert(:alert, lock_version: 1)

      {:ok, user: user, alert: alert}
    end

    test "updates successfully when no conflict", %{user: user, alert: alert} do
      attrs = %{
        status: "investigating",
        lock_version: 1
      }

      assert {:ok, updated} =
               ConflictResolver.update_with_conflict_detection(
                 Alert,
                 alert.id,
                 attrs,
                 user
               )

      assert updated.status == "investigating"
      assert updated.lock_version == 2
    end

    test "detects version conflict", %{user: user, alert: alert} do
      attrs = %{
        status: "investigating",
        lock_version: 0
      }

      assert {:conflict, details} =
               ConflictResolver.update_with_conflict_detection(
                 Alert,
                 alert.id,
                 attrs,
                 user,
                 strategy: :first_write_wins
               )

      assert details.details.current_version == 1
      assert details.details.expected_version == 0
    end

    test "last-write-wins strategy overrides conflict", %{user: user, alert: alert} do
      attrs = %{
        status: "investigating",
        lock_version: 0
      }

      assert {:ok, updated} =
               ConflictResolver.update_with_conflict_detection(
                 Alert,
                 alert.id,
                 attrs,
                 user,
                 strategy: :last_write_wins
               )

      assert updated.status == "investigating"
    end
  end

  describe "create_conflict_record/3" do
    test "creates conflict record with correct structure" do
      conflict_data = %{
        field: "status",
        old_value: "new",
        new_value: "investigating",
        conflicting_value: "resolved"
      }

      record =
        ConflictResolver.create_conflict_record("alert", "alert-123", conflict_data)

      assert record.resource_type == "alert"
      assert record.resource_id == "alert-123"
      assert record.conflict_data == conflict_data
      assert record.status == :pending
      assert record.created_at
    end
  end

  describe "notify_conflict/3" do
    test "broadcasts conflict notification" do
      topic = "alert:alert-123"
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, topic)

      conflict_details = %{
        field: "status",
        message: "Conflict detected"
      }

      ConflictResolver.notify_conflict("alert", "alert-123", conflict_details)

      assert_receive {:conflict_detected, ^conflict_details}
    end
  end

  # Helper functions for test fixtures
  defp insert(:user) do
    %User{
      id: Ecto.UUID.generate(),
      email: "test@example.com",
      name: "Test User",
      role: "analyst"
    }
  end

  defp insert(:alert, attrs \\ []) do
    base_alert = %Alert{
      id: Ecto.UUID.generate(),
      title: "Test Alert",
      severity: "high",
      status: "new",
      description: "Test alert description",
      lock_version: 0
    }

    struct(base_alert, attrs)
  end
end
