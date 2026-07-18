defmodule TamanduaServerWeb.API.V1.BatchControllerTest do
  use TamanduaServerWeb.ConnCase

  import TamanduaServer.Factory

  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Detection.IOC
  alias TamanduaServer.Repo

  setup %{conn: conn} do
    # Create test organization and user
    org = insert(:organization)
    user = insert(:user, organization_id: org.id)

    admin_role =
      Repo.insert!(%TamanduaServer.Accounts.Role{
        name: "Batch test admin",
        slug: "admin",
        builtin: true,
        priority: 100,
        organization_id: org.id
      })

    Repo.insert!(%TamanduaServer.Accounts.UserRole{
      user_id: user.id,
      role_id: admin_role.id,
      granted_at: DateTime.utc_now() |> DateTime.truncate(:microsecond)
    })

    # Authenticate connection
    conn =
      conn
      |> put_req_header("accept", "application/json")
      |> put_req_header("content-type", "application/json")
      |> assign(:current_organization_id, org.id)
      |> assign(:current_user, user)

    {:ok, conn: conn, org: org, user: user}
  end

  describe "POST /api/v1/alerts/batch/close" do
    test "closes multiple alerts", %{conn: conn, org: org, user: user} do
      alerts = insert_list(5, :alert, organization_id: org.id, status: "new")
      alert_ids = Enum.map(alerts, & &1.id)

      params = %{
        "alert_ids" => alert_ids,
        "resolution_notes" => "Batch closed via API"
      }

      conn = post(conn, "/api/v1/alerts/batch/close", params)

      assert %{
        "success_count" => 5,
        "failed" => []
      } = json_response(conn, 200)

      # Verify alerts are closed
      Enum.each(alert_ids, fn id ->
        alert = Repo.get!(Alert, id)
        assert alert.status == "resolved"
        assert alert.resolution_notes == "Batch closed via API"
      end)
    end

    test "returns error for batch exceeding 1000 items", %{conn: conn} do
      alert_ids = for _ <- 1..1001, do: Ecto.UUID.generate()

      params = %{"alert_ids" => alert_ids}

      conn = post(conn, "/api/v1/alerts/batch/close", params)

      assert %{"error" => error} = json_response(conn, 400)
      assert error =~ "maximum of 1000"
    end

    test "respects organization scoping", %{conn: conn, org: org} do
      other_org = insert(:organization)

      alert1 = insert(:alert, organization_id: org.id, status: "new")
      alert2 = insert(:alert, organization_id: other_org.id, status: "new")

      params = %{"alert_ids" => [alert1.id, alert2.id]}

      conn = post(conn, "/api/v1/alerts/batch/close", params)

      assert %{"success_count" => 1} = json_response(conn, 200)

      # Only org's alert should be closed
      assert Repo.get!(Alert, alert1.id).status == "resolved"
      assert Repo.get!(Alert, alert2.id).status == "new"
    end
  end

  describe "POST /api/v1/alerts/batch/assign" do
    test "assigns multiple alerts to a user", %{conn: conn, org: org, user: user} do
      analyst = insert(:user, organization_id: org.id)
      alerts = insert_list(3, :alert, organization_id: org.id, assigned_to_id: nil)
      alert_ids = Enum.map(alerts, & &1.id)

      params = %{
        "alert_ids" => alert_ids,
        "assigned_to_id" => analyst.id
      }

      conn = post(conn, "/api/v1/alerts/batch/assign", params)

      assert %{"success_count" => 3} = json_response(conn, 200)

      # Verify alerts are assigned
      Enum.each(alert_ids, fn id ->
        alert = Repo.get!(Alert, id)
        assert alert.assigned_to_id == analyst.id
      end)
    end
  end

  describe "POST /api/v1/alerts/batch/tag" do
    test "adds tags to multiple alerts", %{conn: conn, org: org} do
      alerts = insert_list(4, :alert, organization_id: org.id, enrichment: %{})
      alert_ids = Enum.map(alerts, & &1.id)

      params = %{
        "alert_ids" => alert_ids,
        "add_tags" => ["false_positive", "reviewed"]
      }

      conn = post(conn, "/api/v1/alerts/batch/tag", params)

      assert %{"success_count" => 4} = json_response(conn, 200)

      # Verify tags were added
      Enum.each(alert_ids, fn id ->
        alert = Repo.get!(Alert, id)
        tags = get_in(alert.enrichment, ["tags"]) || []
        assert "false_positive" in tags
        assert "reviewed" in tags
      end)
    end

    test "removes tags from multiple alerts", %{conn: conn, org: org} do
      alerts = insert_list(2, :alert,
        organization_id: org.id,
        enrichment: %{"tags" => ["tag1", "tag2"]}
      )
      alert_ids = Enum.map(alerts, & &1.id)

      params = %{
        "alert_ids" => alert_ids,
        "remove_tags" => ["tag1"]
      }

      conn = post(conn, "/api/v1/alerts/batch/tag", params)

      assert %{"success_count" => 2} = json_response(conn, 200)

      # Verify tag was removed
      Enum.each(alert_ids, fn id ->
        alert = Repo.get!(Alert, id)
        tags = get_in(alert.enrichment, ["tags"]) || []
        refute "tag1" in tags
        assert "tag2" in tags
      end)
    end
  end

  describe "POST /api/v1/alerts/batch/delete" do
    test "deletes multiple alerts", %{conn: conn, org: org} do
      alerts = insert_list(6, :alert, organization_id: org.id)
      alert_ids = Enum.map(alerts, & &1.id)

      params = %{"alert_ids" => alert_ids}

      conn = post(conn, "/api/v1/alerts/batch/delete", params)

      assert %{"success_count" => 6} = json_response(conn, 200)

      # Verify alerts are deleted
      Enum.each(alert_ids, fn id ->
        assert Repo.get(Alert, id) == nil
      end)
    end
  end

  describe "POST /api/v1/iocs/batch/import" do
    test "imports IOCs synchronously for small batches", %{conn: conn, org: org} do
      iocs = [
        %{
          "type" => "hash_sha256",
          "value" => "abc123def456",
          "severity" => "high",
          "description" => "Malware hash"
        },
        %{
          "type" => "ip",
          "value" => "10.0.0.1",
          "severity" => "medium"
        },
        %{
          "type" => "domain",
          "value" => "evil.example.com",
          "severity" => "critical"
        }
      ]

      params = %{
        "iocs" => iocs,
        "source" => "api_test",
        "deduplicate" => true
      }

      conn = post(conn, "/api/v1/iocs/batch/import", params)

      assert %{
        "imported" => 3,
        "skipped" => 0,
        "failed" => []
      } = json_response(conn, 200)

      # Verify IOCs were created
      ioc_count = Repo.aggregate(
        from(i in IOC, where: i.organization_id == ^org.id),
        :count
      )
      assert ioc_count == 3
    end

    test "returns job_id for large batches", %{conn: conn} do
      # Create 1500 IOCs
      iocs = for i <- 1..1500 do
        %{
          "type" => "hash_sha256",
          "value" => "hash#{i}",
          "severity" => "medium"
        }
      end

      params = %{"iocs" => iocs}

      conn = post(conn, "/api/v1/iocs/batch/import", params)

      assert %{
        "job_id" => job_id,
        "message" => message,
        "status_url" => status_url
      } = json_response(conn, 202)

      assert is_integer(job_id)
      assert message =~ "queued"
      assert status_url =~ "/api/v1/jobs/"
    end

    test "deduplicates IOCs during import", %{conn: conn, org: org} do
      # Pre-insert an IOC
      insert(:ioc, organization_id: org.id, type: "hash_sha256", value: "duplicate123")

      iocs = [
        %{"type" => "hash_sha256", "value" => "duplicate123"},
        %{"type" => "hash_sha256", "value" => "unique123"}
      ]

      params = %{
        "iocs" => iocs,
        "deduplicate" => true
      }

      conn = post(conn, "/api/v1/iocs/batch/import", params)

      assert %{
        "imported" => 1,
        "skipped" => 1
      } = json_response(conn, 200)
    end
  end

  describe "POST /api/v1/iocs/batch/delete" do
    test "deletes multiple IOCs", %{conn: conn, org: org} do
      iocs = insert_list(7, :ioc, organization_id: org.id)
      ioc_ids = Enum.map(iocs, & &1.id)

      params = %{"ioc_ids" => ioc_ids}

      conn = post(conn, "/api/v1/iocs/batch/delete", params)

      assert %{"success_count" => 7} = json_response(conn, 200)

      # Verify IOCs are deleted
      Enum.each(ioc_ids, fn id ->
        assert Repo.get(IOC, id) == nil
      end)
    end
  end

  describe "POST /api/v1/iocs/batch/update" do
    test "updates expiration for multiple IOCs", %{conn: conn, org: org} do
      iocs = insert_list(3, :ioc, organization_id: org.id, expires_at: nil)
      ioc_ids = Enum.map(iocs, & &1.id)

      params = %{
        "ioc_ids" => ioc_ids,
        "updates" => %{
          "expires_at" => "2027-12-31T23:59:59Z"
        }
      }

      conn = post(conn, "/api/v1/iocs/batch/update", params)

      assert %{"success_count" => 3} = json_response(conn, 200)

      # Verify expiration was updated
      Enum.each(ioc_ids, fn id ->
        ioc = Repo.get!(IOC, id)
        assert ioc.expires_at != nil
      end)
    end

    test "adds tags to multiple IOCs", %{conn: conn, org: org} do
      iocs = insert_list(2, :ioc, organization_id: org.id, tags: [])
      ioc_ids = Enum.map(iocs, & &1.id)

      params = %{
        "ioc_ids" => ioc_ids,
        "updates" => %{
          "add_tags" => ["confirmed", "apt29"]
        }
      }

      conn = post(conn, "/api/v1/iocs/batch/update", params)

      assert %{"success_count" => 2} = json_response(conn, 200)

      # Verify tags were added
      Enum.each(ioc_ids, fn id ->
        ioc = Repo.get!(IOC, id)
        assert "confirmed" in ioc.tags
        assert "apt29" in ioc.tags
      end)
    end
  end

  describe "POST /api/v1/agents/batch/isolate" do
    test "creates job for isolating multiple agents", %{conn: conn} do
      agent_ids = for _ <- 1..5, do: Ecto.UUID.generate()

      params = %{
        "agent_ids" => agent_ids,
        "reason" => "Suspected compromise"
      }

      conn = post(conn, "/api/v1/agents/batch/isolate", params)

      assert %{
        "job_id" => job_id,
        "message" => message,
        "status_url" => status_url
      } = json_response(conn, 202)

      assert is_integer(job_id)
      assert message =~ "queued"
      assert status_url =~ "/api/v1/jobs/"
    end
  end

  describe "POST /api/v1/agents/batch/scan" do
    test "creates job for scanning multiple agents", %{conn: conn} do
      agent_ids = for _ <- 1..10, do: Ecto.UUID.generate()

      params = %{"agent_ids" => agent_ids}

      conn = post(conn, "/api/v1/agents/batch/scan", params)

      assert %{
        "job_id" => job_id,
        "message" => message
      } = json_response(conn, 202)

      assert is_integer(job_id)
      assert message =~ "queued"
    end
  end

  describe "POST /api/v1/agents/batch/collect-forensics" do
    test "creates job for collecting forensics from multiple agents", %{conn: conn} do
      agent_ids = for _ <- 1..3, do: Ecto.UUID.generate()

      params = %{"agent_ids" => agent_ids}

      conn = post(conn, "/api/v1/agents/batch/collect-forensics", params)

      assert %{
        "job_id" => job_id,
        "message" => message
      } = json_response(conn, 202)

      assert is_integer(job_id)
      assert message =~ "forensics"
    end
  end

  describe "GET /api/v1/jobs/:id" do
    test "returns job status", %{conn: conn, org: org} do
      # Create a job
      {:ok, job} = TamanduaServer.Workers.BatchJobWorker.new(%{
        organization_id: org.id,
        operation: "import_iocs",
        data: []
      })
      |> Oban.insert()

      conn = get(conn, "/api/v1/jobs/#{job.id}")

      assert %{
        "id" => _,
        "state" => state,
        "queue" => "batch_operations",
        "worker" => "TamanduaServer.Workers.BatchJobWorker",
        "progress" => 0,
        "attempt" => 0,
        "max_attempts" => 3
      } = json_response(conn, 200)

      assert state in ["scheduled", "available", "executing", "completed"]
    end

    test "returns 404 for non-existent job", %{conn: conn} do
      conn = get(conn, "/api/v1/jobs/999999")

      assert %{"error" => "Job not found"} = json_response(conn, 404)
    end
  end
end
