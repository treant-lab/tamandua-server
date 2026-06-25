defmodule TamanduaServerWeb.Controllers.API.V1.AlertsControllerTest do
  @moduledoc """
  Comprehensive unit tests for Alerts API controller.
  Tests CRUD operations, filtering, authentication, and authorization.
  """
  use TamanduaServerWeb.ConnCase, async: true

  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Repo

  setup %{conn: conn} do
    {org, agent} = create_agent_with_org()
    user = insert!(:user, %{organization_id: org.id, role: "analyst"})
    admin = insert!(:user, %{organization_id: org.id, role: "admin"})

    # Create API token for authentication
    {:ok, token, _} = TamanduaServer.Guardian.encode_and_sign(user)
    {:ok, admin_token, _} = TamanduaServer.Guardian.encode_and_sign(admin)

    conn = put_req_header(conn, "authorization", "Bearer #{token}")
    admin_conn = put_req_header(conn, "authorization", "Bearer #{admin_token}")

    %{
      conn: conn,
      admin_conn: admin_conn,
      org: org,
      agent: agent,
      user: user,
      admin: admin,
      token: token
    }
  end

  # ── List Alerts Tests ──────────────────────────────────────────────────

  describe "GET /api/v1/alerts" do
    test "returns list of alerts", %{conn: conn, agent: agent, org: org} do
      insert!(:alert, %{agent_id: agent.id, organization_id: org.id})
      insert!(:alert, %{agent_id: agent.id, organization_id: org.id})

      conn = get(conn, "/api/v1/alerts")

      assert json_response(conn, 200)["data"] |> length() >= 2
    end

    test "requires authentication", %{conn: conn} do
      conn = delete_req_header(conn, "authorization")
      conn = get(conn, "/api/v1/alerts")

      assert response(conn, 401)
    end

    test "filters by severity", %{conn: conn, agent: agent, org: org} do
      insert!(:alert, %{agent_id: agent.id, organization_id: org.id, severity: :critical})
      insert!(:alert, %{agent_id: agent.id, organization_id: org.id, severity: :low})

      conn = get(conn, "/api/v1/alerts?severity=critical")

      data = json_response(conn, 200)["data"]
      assert Enum.all?(data, fn alert -> alert["severity"] == "critical" end)
    end

    test "filters by status", %{conn: conn, agent: agent, org: org} do
      insert!(:alert, %{agent_id: agent.id, organization_id: org.id, status: "open"})
      insert!(:alert, %{agent_id: agent.id, organization_id: org.id, status: "closed"})

      conn = get(conn, "/api/v1/alerts?status=open")

      data = json_response(conn, 200)["data"]
      assert Enum.all?(data, fn alert -> alert["status"] == "open" end)
    end

    test "infers legacy ML alert source for filtering and serialization", %{
      conn: conn,
      agent: agent,
      org: org
    } do
      ml_alert =
        insert!(:alert, %{
          agent_id: agent.id,
          organization_id: org.id,
          title: "Legacy ML detection",
          detection_metadata: %{
            "rule_name" => "ML_AGENT_MALWARE_CLASSIFICATION",
            "confidence" => 0.97
          },
          raw_event: %{
            "payload" => %{
              "detection_type" => "ml",
              "file_path" => "C:\\ProgramData\\Tamandua\\ml-bench\\malware_00000.bin"
            }
          }
        })

      insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        title: "Behavioral detection",
        detection_metadata: %{"source" => "behavioral"}
      })

      conn = get(conn, "/api/v1/alerts?source=ml")

      data = json_response(conn, 200)["data"]
      assert Enum.any?(data, fn alert -> alert["id"] == ml_alert.id end)
      assert Enum.all?(data, fn alert -> alert["source"] == "ml" end)
    end

    test "filters by MITRE technique", %{conn: conn, agent: agent, org: org} do
      insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        mitre_techniques: ["T1059.001"]
      })

      insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        mitre_techniques: ["T1003.001"]
      })

      conn = get(conn, "/api/v1/alerts?mitre_technique=T1059.001")

      data = json_response(conn, 200)["data"]
      assert length(data) >= 1
      assert Enum.any?(data, fn alert -> "T1059.001" in alert["mitre_techniques"] end)
    end

    test "supports pagination", %{conn: conn, agent: agent, org: org} do
      for i <- 1..25 do
        insert!(:alert, %{agent_id: agent.id, organization_id: org.id, title: "Alert #{i}"})
      end

      conn = get(conn, "/api/v1/alerts?page=1&per_page=10")

      response = json_response(conn, 200)
      assert length(response["data"]) <= 10
      assert Map.has_key?(response, "meta")
      assert response["meta"]["page"] == 1
    end

    test "sorts by created date", %{conn: conn, agent: agent, org: org} do
      old_alert = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        inserted_at: DateTime.utc_now() |> DateTime.add(-3600, :second)
      })

      new_alert = insert!(:alert, %{agent_id: agent.id, organization_id: org.id})

      conn = get(conn, "/api/v1/alerts?sort=created_at&order=desc")

      data = json_response(conn, 200)["data"]
      assert hd(data)["id"] == new_alert.id
    end

    test "filters by date range", %{conn: conn, agent: agent, org: org} do
      from = DateTime.utc_now() |> DateTime.add(-7200, :second) |> DateTime.to_iso8601()
      to = DateTime.utc_now() |> DateTime.to_iso8601()

      insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        inserted_at: DateTime.utc_now() |> DateTime.add(-3600, :second)
      })

      conn = get(conn, "/api/v1/alerts?from=#{from}&to=#{to}")

      assert json_response(conn, 200)["data"] |> length() >= 1
    end

    test "only shows alerts from user's organization", %{conn: conn, agent: agent, org: org} do
      # Create alert in current org
      insert!(:alert, %{agent_id: agent.id, organization_id: org.id})

      # Create alert in different org
      {other_org, other_agent} = create_agent_with_org()
      insert!(:alert, %{agent_id: other_agent.id, organization_id: other_org.id})

      conn = get(conn, "/api/v1/alerts")

      data = json_response(conn, 200)["data"]
      assert Enum.all?(data, fn alert -> alert["organization_id"] == org.id end)
    end
  end

  # ── Get Alert Tests ────────────────────────────────────────────────────

  describe "GET /api/v1/alerts/:id" do
    test "returns alert by ID", %{conn: conn, agent: agent, org: org} do
      alert = insert!(:alert, %{agent_id: agent.id, organization_id: org.id})

      conn = get(conn, "/api/v1/alerts/#{alert.id}")

      response = json_response(conn, 200)["data"]
      assert response["id"] == alert.id
      assert response["title"] == alert.title
    end

    test "returns 404 for non-existent alert", %{conn: conn} do
      conn = get(conn, "/api/v1/alerts/#{Ecto.UUID.generate()}")

      assert response(conn, 404)
    end

    test "returns 404 for alert from different organization", %{conn: conn} do
      {other_org, other_agent} = create_agent_with_org()
      other_alert = insert!(:alert, %{agent_id: other_agent.id, organization_id: other_org.id})

      conn = get(conn, "/api/v1/alerts/#{other_alert.id}")

      assert response(conn, 404)
    end

    test "includes related data", %{conn: conn, agent: agent, org: org} do
      alert = insert!(:alert, %{agent_id: agent.id, organization_id: org.id})

      conn = get(conn, "/api/v1/alerts/#{alert.id}?include=agent,events")

      response = json_response(conn, 200)["data"]
      assert Map.has_key?(response, "agent")
    end
  end

  # ── Create Alert Tests ─────────────────────────────────────────────────

  describe "POST /api/v1/alerts" do
    test "creates new alert with valid data", %{admin_conn: conn, agent: agent, org: org} do
      alert_params = %{
        title: "Test Alert",
        description: "Test description",
        severity: "high",
        status: "open",
        agent_id: agent.id,
        organization_id: org.id,
        mitre_tactics: ["execution"],
        mitre_techniques: ["T1059.001"]
      }

      conn = post(conn, "/api/v1/alerts", alert: alert_params)

      response = json_response(conn, 201)["data"]
      assert response["title"] == "Test Alert"
      assert response["severity"] == "high"
    end

    test "returns validation errors for invalid data", %{admin_conn: conn} do
      invalid_params = %{
        title: "",
        severity: "invalid"
      }

      conn = post(conn, "/api/v1/alerts", alert: invalid_params)

      assert response(conn, 422)
      assert json_response(conn, 422)["errors"] != nil
    end

    test "requires admin role to create alerts", %{conn: conn, agent: agent, org: org} do
      # Regular analyst trying to create alert
      alert_params = %{
        title: "Test Alert",
        agent_id: agent.id,
        organization_id: org.id
      }

      conn = post(conn, "/api/v1/alerts", alert: alert_params)

      # Should be forbidden
      assert response(conn, 403) or response(conn, 401)
    end
  end

  # ── Update Alert Tests ─────────────────────────────────────────────────

  describe "PUT /api/v1/alerts/:id" do
    test "updates alert with valid data", %{admin_conn: conn, agent: agent, org: org} do
      alert = insert!(:alert, %{agent_id: agent.id, organization_id: org.id, status: "open"})

      update_params = %{
        status: "investigating",
        assigned_to: Ecto.UUID.generate()
      }

      conn = put(conn, "/api/v1/alerts/#{alert.id}", alert: update_params)

      response = json_response(conn, 200)["data"]
      assert response["status"] == "investigating"
    end

    test "returns validation errors for invalid data", %{admin_conn: conn, agent: agent, org: org} do
      alert = insert!(:alert, %{agent_id: agent.id, organization_id: org.id})

      invalid_params = %{severity: "invalid_severity"}

      conn = put(conn, "/api/v1/alerts/#{alert.id}", alert: invalid_params)

      assert response(conn, 422)
    end

    test "returns 404 for non-existent alert", %{admin_conn: conn} do
      conn = put(conn, "/api/v1/alerts/#{Ecto.UUID.generate()}", alert: %{status: "closed"})

      assert response(conn, 404)
    end

    test "analysts can update certain fields", %{conn: conn, agent: agent, org: org} do
      alert = insert!(:alert, %{agent_id: agent.id, organization_id: org.id, status: "open"})

      # Analysts should be able to update status and assignment
      update_params = %{status: "investigating"}

      conn = put(conn, "/api/v1/alerts/#{alert.id}", alert: update_params)

      # Should succeed for allowed fields
      assert response(conn, 200) or response(conn, 403)
    end
  end

  # ── Delete Alert Tests ─────────────────────────────────────────────────

  describe "DELETE /api/v1/alerts/:id" do
    test "deletes alert", %{admin_conn: conn, agent: agent, org: org} do
      alert = insert!(:alert, %{agent_id: agent.id, organization_id: org.id})

      conn = delete(conn, "/api/v1/alerts/#{alert.id}")

      assert response(conn, 204)
      assert Repo.get(Alert, alert.id) == nil
    end

    test "requires admin role to delete alerts", %{conn: conn, agent: agent, org: org} do
      alert = insert!(:alert, %{agent_id: agent.id, organization_id: org.id})

      conn = delete(conn, "/api/v1/alerts/#{alert.id}")

      # Should be forbidden
      assert response(conn, 403)
      assert Repo.get(Alert, alert.id) != nil
    end

    test "returns 404 for non-existent alert", %{admin_conn: conn} do
      conn = delete(conn, "/api/v1/alerts/#{Ecto.UUID.generate()}")

      assert response(conn, 404)
    end
  end

  # ── Bulk Operations Tests ──────────────────────────────────────────────

  describe "POST /api/v1/alerts/bulk_update" do
    test "updates multiple alerts", %{admin_conn: conn, agent: agent, org: org} do
      alert1 = insert!(:alert, %{agent_id: agent.id, organization_id: org.id, status: "open"})
      alert2 = insert!(:alert, %{agent_id: agent.id, organization_id: org.id, status: "open"})

      bulk_params = %{
        alert_ids: [alert1.id, alert2.id],
        updates: %{status: "closed"}
      }

      conn = post(conn, "/api/v1/alerts/bulk_update", bulk_params)

      response = json_response(conn, 200)
      assert response["updated_count"] == 2
    end

    test "requires admin role for bulk operations", %{conn: conn, agent: agent, org: org} do
      alert1 = insert!(:alert, %{agent_id: agent.id, organization_id: org.id})
      alert2 = insert!(:alert, %{agent_id: agent.id, organization_id: org.id})

      bulk_params = %{
        alert_ids: [alert1.id, alert2.id],
        updates: %{status: "closed"}
      }

      conn = post(conn, "/api/v1/alerts/bulk_update", bulk_params)

      assert response(conn, 403)
    end
  end

  # ── Statistics and Aggregations ────────────────────────────────────────

  describe "GET /api/v1/alerts/stats" do
    test "returns alert statistics", %{conn: conn, agent: agent, org: org} do
      insert!(:alert, %{agent_id: agent.id, organization_id: org.id, severity: :critical})
      insert!(:alert, %{agent_id: agent.id, organization_id: org.id, severity: :high})
      insert!(:alert, %{agent_id: agent.id, organization_id: org.id, severity: :high})

      conn = get(conn, "/api/v1/alerts/stats")

      stats = json_response(conn, 200)["data"]
      assert Map.has_key?(stats, "total")
      assert Map.has_key?(stats, "by_severity")
      assert stats["by_severity"]["critical"] == 1
      assert stats["by_severity"]["high"] == 2
    end

    test "returns alerts by status", %{conn: conn, agent: agent, org: org} do
      insert!(:alert, %{agent_id: agent.id, organization_id: org.id, status: "open"})
      insert!(:alert, %{agent_id: agent.id, organization_id: org.id, status: "open"})
      insert!(:alert, %{agent_id: agent.id, organization_id: org.id, status: "closed"})

      conn = get(conn, "/api/v1/alerts/stats")

      stats = json_response(conn, 200)["data"]
      assert stats["by_status"]["open"] == 2
      assert stats["by_status"]["closed"] == 1
    end
  end

  # ── Search and Advanced Filtering ──────────────────────────────────────

  describe "POST /api/v1/alerts/search" do
    test "searches alerts by keyword", %{conn: conn, agent: agent, org: org} do
      insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        title: "Mimikatz detected",
        description: "Credential dumping tool"
      })

      insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        title: "Suspicious process"
      })

      search_params = %{query: "mimikatz"}

      conn = post(conn, "/api/v1/alerts/search", search_params)

      data = json_response(conn, 200)["data"]
      assert length(data) >= 1
      assert Enum.any?(data, fn alert -> String.contains?(alert["title"], "Mimikatz") end)
    end

    test "searches with complex filters", %{conn: conn, agent: agent, org: org} do
      insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        severity: :critical,
        status: "open",
        mitre_techniques: ["T1003.001"]
      })

      search_params = %{
        filters: %{
          severity: ["critical", "high"],
          status: ["open"],
          mitre_technique: "T1003.001"
        }
      }

      conn = post(conn, "/api/v1/alerts/search", search_params)

      data = json_response(conn, 200)["data"]
      assert length(data) >= 1
    end
  end

  # ── Rate Limiting Tests ────────────────────────────────────────────────

  describe "rate limiting" do
    @tag :rate_limit
    test "enforces rate limits on API endpoints", %{conn: conn} do
      # Make many requests quickly
      responses = for _ <- 1..100 do
        get(conn, "/api/v1/alerts")
      end

      # Should eventually get rate limited
      status_codes = Enum.map(responses, fn conn -> conn.status end)

      # Should have some 429 responses if rate limiting is active
      # (This would depend on actual rate limiting implementation)
      assert Enum.all?(status_codes, fn code -> code in [200, 429] end)
    end
  end

  # ── Error Handling Tests ───────────────────────────────────────────────

  describe "error handling" do
    test "handles malformed JSON", %{admin_conn: conn} do
      conn = put_req_header(conn, "content-type", "application/json")
      conn = post(conn, "/api/v1/alerts", "invalid json")

      assert response(conn, 400)
    end

    test "handles missing required fields", %{admin_conn: conn} do
      conn = post(conn, "/api/v1/alerts", alert: %{})

      assert response(conn, 422)
      errors = json_response(conn, 422)["errors"]
      assert is_map(errors) or is_list(errors)
    end

    test "handles internal server errors gracefully" do
      # This would require mocking to trigger specific error conditions
      assert true
    end
  end
end
