defmodule TamanduaServer.AlertsBulkOperationsTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.Alerts
  alias TamanduaServer.Alerts.Alert

  describe "bulk_update/3" do
    test "updates multiple alerts successfully" do
      # Create test alerts
      {:ok, alert1} = create_test_alert(%{title: "Alert 1", severity: "high", status: "new"})
      {:ok, alert2} = create_test_alert(%{title: "Alert 2", severity: "medium", status: "new"})
      {:ok, alert3} = create_test_alert(%{title: "Alert 3", severity: "low", status: "new"})

      alert_ids = [alert1.id, alert2.id, alert3.id]

      # Bulk update status
      {:ok, count} = Alerts.bulk_update(alert_ids, %{status: "investigating"})

      assert count == 3

      # Verify all alerts were updated
      updated_alert1 = Repo.get!(Alert, alert1.id)
      updated_alert2 = Repo.get!(Alert, alert2.id)
      updated_alert3 = Repo.get!(Alert, alert3.id)

      assert updated_alert1.status == "investigating"
      assert updated_alert2.status == "investigating"
      assert updated_alert3.status == "investigating"
    end

    test "handles empty alert list" do
      {:ok, count} = Alerts.bulk_update([], %{status: "resolved"})
      assert count == 0
    end

    test "handles non-existent alert IDs" do
      fake_id = Ecto.UUID.generate()
      {:ok, count} = Alerts.bulk_update([fake_id], %{status: "resolved"})
      assert count == 0
    end

    test "respects organization scoping" do
      org_id_1 = Ecto.UUID.generate()
      org_id_2 = Ecto.UUID.generate()

      {:ok, alert1} = create_test_alert(%{title: "Org 1 Alert", organization_id: org_id_1})
      {:ok, alert2} = create_test_alert(%{title: "Org 2 Alert", organization_id: org_id_2})

      # Try to update both, but scope to org_id_1
      {:ok, count} = Alerts.bulk_update(
        [alert1.id, alert2.id],
        %{status: "resolved"},
        organization_id: org_id_1
      )

      # Only 1 alert should be updated
      assert count == 1

      updated_alert1 = Repo.get!(Alert, alert1.id)
      updated_alert2 = Repo.get!(Alert, alert2.id)

      assert updated_alert1.status == "resolved"
      assert updated_alert2.status == "new"
    end
  end

  describe "bulk_update_status/3" do
    test "updates status for multiple alerts" do
      {:ok, alert1} = create_test_alert(%{title: "Alert 1", status: "new"})
      {:ok, alert2} = create_test_alert(%{title: "Alert 2", status: "new"})

      {:ok, count} = Alerts.bulk_update_status([alert1.id, alert2.id], "investigating")

      assert count == 2

      updated_alert1 = Repo.get!(Alert, alert1.id)
      updated_alert2 = Repo.get!(Alert, alert2.id)

      assert updated_alert1.status == "investigating"
      assert updated_alert2.status == "investigating"
    end

    test "rejects invalid status" do
      {:ok, alert} = create_test_alert(%{title: "Alert", status: "new"})

      assert {:error, :invalid_status} = Alerts.bulk_update_status([alert.id], "invalid_status")

      # Alert should not be updated
      unchanged_alert = Repo.get!(Alert, alert.id)
      assert unchanged_alert.status == "new"
    end
  end

  describe "bulk_assign/3" do
    test "assigns multiple alerts to a user" do
      user_id = Ecto.UUID.generate()

      {:ok, alert1} = create_test_alert(%{title: "Alert 1", status: "new"})
      {:ok, alert2} = create_test_alert(%{title: "Alert 2", status: "new"})

      {:ok, count} = Alerts.bulk_assign([alert1.id, alert2.id], user_id)

      assert count == 2

      updated_alert1 = Repo.get!(Alert, alert1.id)
      updated_alert2 = Repo.get!(Alert, alert2.id)

      assert updated_alert1.assigned_to_id == user_id
      assert updated_alert2.assigned_to_id == user_id
      # Should also change status to investigating
      assert updated_alert1.status == "investigating"
      assert updated_alert2.status == "investigating"
    end
  end

  describe "bulk_resolve/3" do
    test "resolves multiple alerts" do
      {:ok, alert1} = create_test_alert(%{title: "Alert 1", status: "investigating"})
      {:ok, alert2} = create_test_alert(%{title: "Alert 2", status: "investigating"})

      {:ok, count} = Alerts.bulk_resolve([alert1.id, alert2.id], "Investigated and resolved")

      assert count == 2

      updated_alert1 = Repo.get!(Alert, alert1.id)
      updated_alert2 = Repo.get!(Alert, alert2.id)

      assert updated_alert1.status == "resolved"
      assert updated_alert2.status == "resolved"
      assert updated_alert1.resolution_notes == "Investigated and resolved"
      assert updated_alert2.resolution_notes == "Investigated and resolved"
    end

    test "resolves without notes" do
      {:ok, alert} = create_test_alert(%{title: "Alert", status: "investigating"})

      {:ok, count} = Alerts.bulk_resolve([alert.id])

      assert count == 1

      updated_alert = Repo.get!(Alert, alert.id)
      assert updated_alert.status == "resolved"
      assert is_nil(updated_alert.resolution_notes)
    end
  end

  describe "bulk_false_positive/3" do
    test "marks multiple alerts as false positive" do
      {:ok, alert1} = create_test_alert(%{title: "Alert 1", status: "investigating"})
      {:ok, alert2} = create_test_alert(%{title: "Alert 2", status: "investigating"})

      {:ok, count} = Alerts.bulk_false_positive([alert1.id, alert2.id], "Benign process")

      assert count == 2

      updated_alert1 = Repo.get!(Alert, alert1.id)
      updated_alert2 = Repo.get!(Alert, alert2.id)

      assert updated_alert1.status == "false_positive"
      assert updated_alert2.status == "false_positive"
      assert updated_alert1.resolution_notes == "Benign process"
      assert updated_alert2.resolution_notes == "Benign process"
    end
  end

  describe "bulk_delete/3" do
    test "deletes multiple alerts" do
      {:ok, alert1} = create_test_alert(%{title: "Alert 1"})
      {:ok, alert2} = create_test_alert(%{title: "Alert 2"})
      {:ok, alert3} = create_test_alert(%{title: "Alert 3"})

      alert_ids = [alert1.id, alert2.id, alert3.id]

      user = %{id: Ecto.UUID.generate(), email: "test@example.com", organization_id: nil}

      {:ok, count} = Alerts.bulk_delete(alert_ids, user)

      assert count == 3

      # Verify alerts are deleted
      assert is_nil(Repo.get(Alert, alert1.id))
      assert is_nil(Repo.get(Alert, alert2.id))
      assert is_nil(Repo.get(Alert, alert3.id))
    end

    test "respects organization scoping when deleting" do
      org_id_1 = Ecto.UUID.generate()
      org_id_2 = Ecto.UUID.generate()

      {:ok, alert1} = create_test_alert(%{title: "Org 1 Alert", organization_id: org_id_1})
      {:ok, alert2} = create_test_alert(%{title: "Org 2 Alert", organization_id: org_id_2})

      user = %{id: Ecto.UUID.generate(), email: "test@example.com", organization_id: org_id_1}

      {:ok, count} = Alerts.bulk_delete([alert1.id, alert2.id], user, organization_id: org_id_1)

      # Only 1 alert should be deleted
      assert count == 1

      assert is_nil(Repo.get(Alert, alert1.id))
      assert not is_nil(Repo.get(Alert, alert2.id))
    end
  end

  describe "bulk_add_tags/4" do
    test "adds tags to multiple alerts" do
      {:ok, alert1} = create_test_alert(%{title: "Alert 1"})
      {:ok, alert2} = create_test_alert(%{title: "Alert 2"})

      user = %{id: Ecto.UUID.generate(), email: "test@example.com", organization_id: nil}
      tags = ["ransomware", "lateral-movement"]

      {:ok, count} = Alerts.bulk_add_tags([alert1.id, alert2.id], tags, user)

      assert count == 2

      updated_alert1 = Repo.get!(Alert, alert1.id)
      updated_alert2 = Repo.get!(Alert, alert2.id)

      assert "ransomware" in Map.get(updated_alert1.enrichment, "tags", [])
      assert "lateral-movement" in Map.get(updated_alert1.enrichment, "tags", [])
      assert "ransomware" in Map.get(updated_alert2.enrichment, "tags", [])
      assert "lateral-movement" in Map.get(updated_alert2.enrichment, "tags", [])
    end

    test "merges with existing tags" do
      enrichment = %{"tags" => ["existing-tag"]}
      {:ok, alert} = create_test_alert(%{title: "Alert", enrichment: enrichment})

      user = %{id: Ecto.UUID.generate(), email: "test@example.com", organization_id: nil}
      new_tags = ["new-tag"]

      {:ok, count} = Alerts.bulk_add_tags([alert.id], new_tags, user)

      assert count == 1

      updated_alert = Repo.get!(Alert, alert.id)
      tags = Map.get(updated_alert.enrichment, "tags", [])

      assert "existing-tag" in tags
      assert "new-tag" in tags
    end

    test "avoids duplicate tags" do
      enrichment = %{"tags" => ["tag1", "tag2"]}
      {:ok, alert} = create_test_alert(%{title: "Alert", enrichment: enrichment})

      user = %{id: Ecto.UUID.generate(), email: "test@example.com", organization_id: nil}
      tags_to_add = ["tag2", "tag3"]

      {:ok, count} = Alerts.bulk_add_tags([alert.id], tags_to_add, user)

      assert count == 1

      updated_alert = Repo.get!(Alert, alert.id)
      tags = Map.get(updated_alert.enrichment, "tags", [])

      # Should have tag1, tag2, tag3 (no duplicate tag2)
      assert length(tags) == 3
      assert "tag1" in tags
      assert "tag2" in tags
      assert "tag3" in tags
    end
  end

  describe "bulk_remove_tags/4" do
    test "removes tags from multiple alerts" do
      enrichment1 = %{"tags" => ["ransomware", "lateral-movement", "persistence"]}
      enrichment2 = %{"tags" => ["ransomware", "exfiltration"]}

      {:ok, alert1} = create_test_alert(%{title: "Alert 1", enrichment: enrichment1})
      {:ok, alert2} = create_test_alert(%{title: "Alert 2", enrichment: enrichment2})

      user = %{id: Ecto.UUID.generate(), email: "test@example.com", organization_id: nil}
      tags_to_remove = ["ransomware"]

      {:ok, count} = Alerts.bulk_remove_tags([alert1.id, alert2.id], tags_to_remove, user)

      assert count == 2

      updated_alert1 = Repo.get!(Alert, alert1.id)
      updated_alert2 = Repo.get!(Alert, alert2.id)

      tags1 = Map.get(updated_alert1.enrichment, "tags", [])
      tags2 = Map.get(updated_alert2.enrichment, "tags", [])

      refute "ransomware" in tags1
      assert "lateral-movement" in tags1
      assert "persistence" in tags1

      refute "ransomware" in tags2
      assert "exfiltration" in tags2
    end

    test "handles alerts without tags" do
      {:ok, alert} = create_test_alert(%{title: "Alert"})

      user = %{id: Ecto.UUID.generate(), email: "test@example.com", organization_id: nil}

      {:ok, count} = Alerts.bulk_remove_tags([alert.id], ["nonexistent"], user)

      assert count == 1

      updated_alert = Repo.get!(Alert, alert.id)
      tags = Map.get(updated_alert.enrichment, "tags", [])
      assert tags == []
    end
  end

  describe "bulk_update_transactional/4" do
    test "updates alerts in a transaction" do
      {:ok, alert1} = create_test_alert(%{title: "Alert 1", status: "new"})
      {:ok, alert2} = create_test_alert(%{title: "Alert 2", status: "new"})

      user = %{id: Ecto.UUID.generate(), email: "test@example.com", organization_id: nil}

      {:ok, updated, failed} = Alerts.bulk_update_transactional(
        [alert1.id, alert2.id],
        %{status: "resolved"},
        user
      )

      assert updated == 2
      assert failed == []

      updated_alert1 = Repo.get!(Alert, alert1.id)
      updated_alert2 = Repo.get!(Alert, alert2.id)

      assert updated_alert1.status == "resolved"
      assert updated_alert2.status == "resolved"
    end

    test "handles partial failures" do
      {:ok, alert1} = create_test_alert(%{title: "Alert 1", status: "new"})
      fake_id = Ecto.UUID.generate()

      user = %{id: Ecto.UUID.generate(), email: "test@example.com", organization_id: nil}

      {:ok, updated, failed} = Alerts.bulk_update_transactional(
        [alert1.id, fake_id],
        %{status: "resolved"},
        user
      )

      assert updated == 1
      assert fake_id in failed

      updated_alert1 = Repo.get!(Alert, alert1.id)
      assert updated_alert1.status == "resolved"
    end
  end

  describe "get_alerts_by_ids/2" do
    test "retrieves multiple alerts by IDs" do
      {:ok, alert1} = create_test_alert(%{title: "Alert 1"})
      {:ok, alert2} = create_test_alert(%{title: "Alert 2"})
      {:ok, alert3} = create_test_alert(%{title: "Alert 3"})

      alerts = Alerts.get_alerts_by_ids([alert1.id, alert2.id, alert3.id])

      assert length(alerts) == 3
      alert_ids = Enum.map(alerts, & &1.id)
      assert alert1.id in alert_ids
      assert alert2.id in alert_ids
      assert alert3.id in alert_ids
    end

    test "returns empty list for non-existent IDs" do
      fake_ids = [Ecto.UUID.generate(), Ecto.UUID.generate()]
      alerts = Alerts.get_alerts_by_ids(fake_ids)

      assert alerts == []
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
