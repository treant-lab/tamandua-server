defmodule TamanduaServer.BatchOperationsTest do
  use TamanduaServer.DataCase

  import TamanduaServer.Factory

  alias TamanduaServer.BatchOperations
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Detection.IOC
  alias TamanduaServer.Repo

  describe "batch_close_alerts/3" do
    test "closes multiple alerts successfully" do
      org_id = Ecto.UUID.generate()
      user_id = Ecto.UUID.generate()

      alerts = insert_list(3, :alert, organization_id: org_id, status: "new")
      alert_ids = Enum.map(alerts, & &1.id)

      {:ok, result} = BatchOperations.batch_close_alerts(
        org_id,
        alert_ids,
        user_id: user_id,
        resolution_notes: "Test batch close"
      )

      assert result.success_count == 3
      assert result.failed == []

      # Verify all alerts are closed
      Enum.each(alert_ids, fn id ->
        alert = Repo.get!(Alert, id)
        assert alert.status == "resolved"
        assert alert.resolution_notes == "Test batch close"
      end)
    end

    test "respects organization scoping" do
      org_id_1 = Ecto.UUID.generate()
      org_id_2 = Ecto.UUID.generate()
      user_id = Ecto.UUID.generate()

      alert1 = insert(:alert, organization_id: org_id_1, status: "new")
      alert2 = insert(:alert, organization_id: org_id_2, status: "new")

      # Try to close both alerts but scoped to org_id_1
      {:ok, result} = BatchOperations.batch_close_alerts(
        org_id_1,
        [alert1.id, alert2.id],
        user_id: user_id
      )

      # Should only close the org_id_1 alert
      assert result.success_count == 1

      updated_alert1 = Repo.get!(Alert, alert1.id)
      updated_alert2 = Repo.get!(Alert, alert2.id)

      assert updated_alert1.status == "resolved"
      assert updated_alert2.status == "new"
    end

    test "rejects batches exceeding 1000 items" do
      org_id = Ecto.UUID.generate()
      user_id = Ecto.UUID.generate()

      # Create 1001 alert IDs
      alert_ids = for _ <- 1..1001, do: Ecto.UUID.generate()

      {:error, {:batch_too_large, max}} = BatchOperations.batch_close_alerts(
        org_id,
        alert_ids,
        user_id: user_id
      )

      assert max == 1000
    end

    test "handles empty alert list" do
      org_id = Ecto.UUID.generate()
      user_id = Ecto.UUID.generate()

      {:ok, result} = BatchOperations.batch_close_alerts(
        org_id,
        [],
        user_id: user_id
      )

      assert result.success_count == 0
      assert result.failed == []
    end
  end

  describe "batch_assign_alerts/4" do
    test "assigns multiple alerts to a user" do
      org_id = Ecto.UUID.generate()
      user_id = Ecto.UUID.generate()
      assigned_to_id = Ecto.UUID.generate()

      alerts = insert_list(5, :alert, organization_id: org_id, assigned_to_id: nil)
      alert_ids = Enum.map(alerts, & &1.id)

      {:ok, result} = BatchOperations.batch_assign_alerts(
        org_id,
        alert_ids,
        assigned_to_id,
        user_id: user_id
      )

      assert result.success_count == 5

      # Verify all alerts are assigned
      Enum.each(alert_ids, fn id ->
        alert = Repo.get!(Alert, id)
        assert alert.assigned_to_id == assigned_to_id
      end)
    end
  end

  describe "batch_tag_alerts/3" do
    test "adds tags to multiple alerts" do
      org_id = Ecto.UUID.generate()
      user_id = Ecto.UUID.generate()

      alerts = insert_list(3, :alert, organization_id: org_id, enrichment: %{})
      alert_ids = Enum.map(alerts, & &1.id)

      {:ok, result} = BatchOperations.batch_tag_alerts(
        org_id,
        alert_ids,
        user_id: user_id,
        add_tags: ["false_positive", "reviewed"]
      )

      assert result.success_count == 3

      # Verify tags were added
      Enum.each(alert_ids, fn id ->
        alert = Repo.get!(Alert, id)
        tags = get_in(alert.enrichment, ["tags"]) || []
        assert "false_positive" in tags
        assert "reviewed" in tags
      end)
    end

    test "removes tags from multiple alerts" do
      org_id = Ecto.UUID.generate()
      user_id = Ecto.UUID.generate()

      alerts = insert_list(2, :alert,
        organization_id: org_id,
        enrichment: %{"tags" => ["tag1", "tag2", "tag3"]}
      )
      alert_ids = Enum.map(alerts, & &1.id)

      {:ok, result} = BatchOperations.batch_tag_alerts(
        org_id,
        alert_ids,
        user_id: user_id,
        remove_tags: ["tag2"]
      )

      assert result.success_count == 2

      # Verify tag was removed
      Enum.each(alert_ids, fn id ->
        alert = Repo.get!(Alert, id)
        tags = get_in(alert.enrichment, ["tags"]) || []
        assert "tag1" in tags
        assert "tag3" in tags
        refute "tag2" in tags
      end)
    end

    test "adds and removes tags in single operation" do
      org_id = Ecto.UUID.generate()
      user_id = Ecto.UUID.generate()

      alert = insert(:alert,
        organization_id: org_id,
        enrichment: %{"tags" => ["old_tag"]}
      )

      {:ok, result} = BatchOperations.batch_tag_alerts(
        org_id,
        [alert.id],
        user_id: user_id,
        add_tags: ["new_tag"],
        remove_tags: ["old_tag"]
      )

      assert result.success_count == 1

      updated_alert = Repo.get!(Alert, alert.id)
      tags = get_in(updated_alert.enrichment, ["tags"]) || []

      assert "new_tag" in tags
      refute "old_tag" in tags
    end
  end

  describe "batch_delete_alerts/3" do
    test "deletes multiple alerts" do
      org_id = Ecto.UUID.generate()
      user_id = Ecto.UUID.generate()

      alerts = insert_list(4, :alert, organization_id: org_id)
      alert_ids = Enum.map(alerts, & &1.id)

      {:ok, result} = BatchOperations.batch_delete_alerts(
        org_id,
        alert_ids,
        user_id: user_id
      )

      assert result.success_count == 4

      # Verify alerts are deleted
      Enum.each(alert_ids, fn id ->
        assert Repo.get(Alert, id) == nil
      end)
    end
  end

  describe "batch_import_iocs/3" do
    test "imports IOCs synchronously for small batches" do
      org_id = Ecto.UUID.generate()

      iocs = [
        %{"type" => "hash_sha256", "value" => "abc123", "severity" => "high"},
        %{"type" => "ip", "value" => "192.168.1.1", "severity" => "medium"},
        %{"type" => "domain", "value" => "evil.com", "severity" => "critical"}
      ]

      {:ok, result} = BatchOperations.batch_import_iocs(
        org_id,
        iocs,
        source: "test_import",
        async: false
      )

      assert result.imported == 3
      assert result.skipped == 0
      assert result.failed == []

      # Verify IOCs were created
      ioc_count = Repo.aggregate(
        from(i in IOC, where: i.organization_id == ^org_id),
        :count
      )
      assert ioc_count == 3
    end

    test "deduplicates IOCs during import" do
      org_id = Ecto.UUID.generate()

      # Pre-insert an IOC
      insert(:ioc, organization_id: org_id, type: "hash_sha256", value: "duplicate123")

      iocs = [
        %{"type" => "hash_sha256", "value" => "duplicate123", "severity" => "high"},
        %{"type" => "hash_sha256", "value" => "unique123", "severity" => "high"}
      ]

      {:ok, result} = BatchOperations.batch_import_iocs(
        org_id,
        iocs,
        deduplicate: true,
        async: false
      )

      assert result.imported == 1
      assert result.skipped == 1
    end

    test "imports without deduplication when requested" do
      org_id = Ecto.UUID.generate()

      iocs = [
        %{"type" => "hash_sha256", "value" => "abc123", "severity" => "high"},
        %{"type" => "hash_sha256", "value" => "abc123", "severity" => "high"}
      ]

      {:ok, result} = BatchOperations.batch_import_iocs(
        org_id,
        iocs,
        deduplicate: false,
        async: false
      )

      # Without deduplication, it will attempt to import both
      # But the second will fail due to DB unique constraint
      assert result.imported >= 1
    end

    test "creates background job for large imports" do
      org_id = Ecto.UUID.generate()

      # Create 1500 IOCs (exceeds 1000 threshold)
      iocs = for i <- 1..1500 do
        %{
          "type" => "hash_sha256",
          "value" => "hash#{i}",
          "severity" => "medium"
        }
      end

      {:ok, %{job_id: job_id}} = BatchOperations.batch_import_iocs(
        org_id,
        iocs,
        source: "large_import"
      )

      assert is_integer(job_id)
    end
  end

  describe "batch_delete_iocs/3" do
    test "deletes multiple IOCs" do
      org_id = Ecto.UUID.generate()

      iocs = insert_list(5, :ioc, organization_id: org_id)
      ioc_ids = Enum.map(iocs, & &1.id)

      {:ok, result} = BatchOperations.batch_delete_iocs(org_id, ioc_ids)

      assert result.success_count == 5

      # Verify IOCs are deleted
      Enum.each(ioc_ids, fn id ->
        assert Repo.get(IOC, id) == nil
      end)
    end

    test "respects organization scoping" do
      org_id_1 = Ecto.UUID.generate()
      org_id_2 = Ecto.UUID.generate()

      ioc1 = insert(:ioc, organization_id: org_id_1)
      ioc2 = insert(:ioc, organization_id: org_id_2)

      {:ok, result} = BatchOperations.batch_delete_iocs(
        org_id_1,
        [ioc1.id, ioc2.id]
      )

      # Only org_id_1's IOC should be deleted
      assert result.success_count == 1

      assert Repo.get(IOC, ioc1.id) == nil
      assert Repo.get(IOC, ioc2.id) != nil
    end
  end

  describe "batch_update_iocs/4" do
    test "updates expiration for multiple IOCs" do
      org_id = Ecto.UUID.generate()
      new_expiration = ~U[2027-12-31 23:59:59Z]

      iocs = insert_list(3, :ioc, organization_id: org_id, expires_at: nil)
      ioc_ids = Enum.map(iocs, & &1.id)

      {:ok, result} = BatchOperations.batch_update_iocs(
        org_id,
        ioc_ids,
        %{expires_at: new_expiration}
      )

      assert result.success_count == 3

      # Verify expiration was updated
      Enum.each(ioc_ids, fn id ->
        ioc = Repo.get!(IOC, id)
        assert DateTime.compare(ioc.expires_at, new_expiration) == :eq
      end)
    end

    test "adds tags to multiple IOCs" do
      org_id = Ecto.UUID.generate()

      iocs = insert_list(2, :ioc, organization_id: org_id, tags: [])
      ioc_ids = Enum.map(iocs, & &1.id)

      {:ok, result} = BatchOperations.batch_update_iocs(
        org_id,
        ioc_ids,
        %{add_tags: ["confirmed", "apt29"]}
      )

      assert result.success_count == 2

      # Verify tags were added
      Enum.each(ioc_ids, fn id ->
        ioc = Repo.get!(IOC, id)
        assert "confirmed" in ioc.tags
        assert "apt29" in ioc.tags
      end)
    end

    test "removes tags from multiple IOCs" do
      org_id = Ecto.UUID.generate()

      iocs = insert_list(2, :ioc,
        organization_id: org_id,
        tags: ["unconfirmed", "pending"]
      )
      ioc_ids = Enum.map(iocs, & &1.id)

      {:ok, result} = BatchOperations.batch_update_iocs(
        org_id,
        ioc_ids,
        %{remove_tags: ["unconfirmed"]}
      )

      assert result.success_count == 2

      # Verify tag was removed
      Enum.each(ioc_ids, fn id ->
        ioc = Repo.get!(IOC, id)
        refute "unconfirmed" in ioc.tags
        assert "pending" in ioc.tags
      end)
    end
  end

  describe "batch_isolate_agents/3" do
    test "creates background job for agent isolation" do
      org_id = Ecto.UUID.generate()
      user_id = Ecto.UUID.generate()

      agent_ids = for _ <- 1..5, do: Ecto.UUID.generate()

      {:ok, %{job_id: job_id}} = BatchOperations.batch_isolate_agents(
        org_id,
        agent_ids,
        user_id: user_id,
        reason: "Test isolation"
      )

      assert is_integer(job_id)
    end
  end

  describe "batch_scan_agents/3" do
    test "creates background job for agent scans" do
      org_id = Ecto.UUID.generate()
      user_id = Ecto.UUID.generate()

      agent_ids = for _ <- 1..10, do: Ecto.UUID.generate()

      {:ok, %{job_id: job_id}} = BatchOperations.batch_scan_agents(
        org_id,
        agent_ids,
        user_id: user_id
      )

      assert is_integer(job_id)
    end
  end

  describe "batch_collect_forensics/3" do
    test "creates background job for forensics collection" do
      org_id = Ecto.UUID.generate()
      user_id = Ecto.UUID.generate()

      agent_ids = for _ <- 1..3, do: Ecto.UUID.generate()

      {:ok, %{job_id: job_id}} = BatchOperations.batch_collect_forensics(
        org_id,
        agent_ids,
        user_id: user_id
      )

      assert is_integer(job_id)
    end
  end
end
