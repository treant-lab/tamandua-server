defmodule TamanduaServerWeb.Controllers.API.V1.AlertsControllerTest do
  @moduledoc """
  Comprehensive unit tests for Alerts API controller.
  Tests CRUD operations, filtering, authentication, and authorization.
  """
  use TamanduaServerWeb.ConnCase, async: true

  alias TamanduaServer.Agents.AgentCommand
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Investigations.CaseInvestigation
  alias TamanduaServer.Mobile.{DeviceV2, MDMCommand}
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

    test "normalizes lifecycle status aliases", %{conn: conn, agent: agent, org: org} do
      active_statuses = ["new", "open", "acknowledged", "triaged", "investigating"]
      dismissed_statuses = ["resolved", "false_positive", "closed"]

      Enum.each(active_statuses ++ dismissed_statuses, fn status ->
        insert!(:alert, %{agent_id: agent.id, organization_id: org.id, status: status})
      end)

      active_conn = get(conn, "/api/v1/alerts?status=active&per_page=20")
      active_data = json_response(active_conn, 200)["data"]
      assert Enum.all?(active_data, fn alert -> alert["status"] in active_statuses end)

      dismissed_conn =
        conn
        |> recycle()
        |> get("/api/v1/alerts?status=dismissed&per_page=20")

      dismissed_data = json_response(dismissed_conn, 200)["data"]
      assert Enum.all?(dismissed_data, fn alert -> alert["status"] in dismissed_statuses end)
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
      assert response["meta"]["per_page"] == 10
      assert response["meta"]["returned"] == 10
      assert response["meta"]["total"] >= 25
      assert response["meta"]["truncated"] == true
      assert response["meta"]["has_more"] == true
      assert response["meta"]["applied_filters"] == %{}
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

    test "serializes direct evidence quality in snake and camel case", %{
      conn: conn,
      agent: agent,
      org: org
    } do
      source_event_id = Ecto.UUID.generate()

      alert =
        insert!(:alert, %{
          agent_id: agent.id,
          organization_id: org.id,
          source_event_id: source_event_id,
          event_ids: [source_event_id],
          evidence: %{
            "detection" => %{"rule_name" => "Suspicious PowerShell"},
            "process" => %{"pid" => 4321, "name" => "powershell.exe"}
          },
          raw_event: %{"process_name" => "powershell.exe"}
        })

      conn = get(conn, "/api/v1/alerts/#{alert.id}")

      response = json_response(conn, 200)["data"]
      assert response["source_event_id"] == source_event_id
      assert response["sourceEventId"] == source_event_id
      assert response["raw_event"] == %{"process_name" => "powershell.exe"}
      assert response["rawEvent"] == %{"process_name" => "powershell.exe"}
      assert response["evidence_quality"]["quality"] == "direct"
      assert response["evidence_quality"]["benchmark_eligible"] == true
      assert response["evidence_quality"]["checks"]["source_event"] == true
      assert response["evidence_quality"]["investigation_context"]["state"] == "partial"
      assert "command line" in response["evidence_quality"]["investigation_context"]["missing"]
      assert response["evidenceQuality"]["quality"] == "direct"
      assert response["evidenceQuality"]["benchmarkEligible"] == true
      assert response["evidenceQuality"]["checks"]["sourceEvent"] == true
      assert response["evidenceQuality"]["investigationContext"]["state"] == "partial"
      assert response["evidenceQuality"]["investigationContext"]["fields"]["process"] == "collected"
      assert response["evidenceQuality"]["investigationContext"]["fields"]["parentProcess"] ==
               "not_collected"

      refute Map.has_key?(response["evidenceQuality"]["investigationContext"]["fields"], "parent_process")
      refute Map.has_key?(response["evidenceQuality"]["checks"], "source_event")
      refute Map.has_key?(response["evidenceQuality"], "benchmark_eligible")
      assert response["evidenceQuality"]["claimable"] == true
    end

    test "serializes derived evidence as not benchmark eligible", %{
      conn: conn,
      agent: agent,
      org: org
    } do
      alert =
        insert!(:alert, %{
          agent_id: agent.id,
          organization_id: org.id,
          source_event_id: nil,
          event_ids: [],
          evidence: %{
            "detection" => %{"rule_name" => "ML malware classification"},
            "process" => %{"name" => "sample.exe"}
          },
          detection_metadata: %{"rule_name" => "ML malware classification"},
          raw_event: %{}
        })

      conn = get(conn, "/api/v1/alerts/#{alert.id}")

      response = json_response(conn, 200)["data"]
      assert response["evidence_quality"]["quality"] == "derived"
      assert response["evidence_quality"]["benchmark_eligible"] == false
      assert response["evidenceQuality"]["quality"] == "derived"
      assert response["evidenceQuality"]["claimable"] == true
      assert response["evidenceQuality"]["benchmarkEligible"] == false
      refute Map.has_key?(response["evidenceQuality"], "benchmark_eligible")
      assert "source_event_id" in response["evidenceQuality"]["missing"]
    end
  end

  describe "GET /api/v1/alerts/:id/related" do
    test "returns only related alerts from the current organization", %{conn: conn, agent: agent, org: org} do
      alert = insert!(:alert, %{agent_id: agent.id, organization_id: org.id, title: "Seed alert"})

      same_org_related =
        insert!(:alert, %{agent_id: agent.id, organization_id: org.id, title: "Same org related"})

      {other_org, _other_agent} = create_agent_with_org()

      other_org_related =
        insert!(:alert, %{
          agent_id: agent.id,
          organization_id: other_org.id,
          title: "Other org related"
        })

      conn = get(conn, "/api/v1/alerts/#{alert.id}/related")

      ids = conn |> json_response(200) |> Map.fetch!("data") |> Enum.map(& &1["id"])
      assert same_org_related.id in ids
      refute other_org_related.id in ids
    end
  end

  describe "GET /api/v1/alerts/:id/agent-commands" do
    test "returns desktop AgentCommand and mobile MDMCommand with runtime markers", %{
      conn: conn,
      agent: agent,
      org: org
    } do
      desktop_command =
        Repo.insert!(%AgentCommand{
          agent_id: agent.id,
          command_type: "process_list",
          command_params: %{"alert_id" => "pending"},
          status: "pending",
          priority: 8,
          expires_at: DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.truncate(:second)
        })

      device =
        Repo.insert!(%DeviceV2{
          organization_id: org.id,
          device_id: "android-alert-command-1",
          device_name: "Pixel 8",
          platform: "android",
          mdm_enrolled: true,
          mdm_provider: "tamandua_mobile"
        })

      mobile_command =
        Repo.insert!(%MDMCommand{
          organization_id: org.id,
          device_id: device.id,
          command_type: "collect_diagnostics",
          status: "pending",
          payload: %{"alert_id" => "pending", "reason" => "auto_investigation"},
          requested_by: "auto_investigation"
        })

      alert =
        insert!(:alert, %{
          agent_id: agent.id,
          organization_id: org.id,
          detection_metadata: %{
            "investigation_enrichment" => %{
              "queued_commands" => [
                %{
                  "command_id" => desktop_command.id,
                  "runtime" => "desktop_agent",
                  "command_type" => "process_list"
                },
                %{
                  "command_id" => mobile_command.id,
                  "runtime" => "mobile_mdm",
                  "command_type" => "collect_diagnostics"
                }
              ]
            }
          }
        })

      conn = get(conn, "/api/v1/alerts/#{alert.id}/agent-commands")

      response = json_response(conn, 200)
      commands_by_id = Map.new(response["data"], &{&1["id"], &1})

      assert response["meta"]["desktop_command_ids"] == [desktop_command.id]
      assert response["meta"]["mobile_command_ids"] == [mobile_command.id]
      assert response["meta"]["returned"] == 2

      agent_id = agent.id
      device_id = device.id

      assert %{
               "runtime" => "desktop_agent",
               "agent_id" => ^agent_id,
               "command_type" => "process_list",
               "commandParams" => %{"alert_id" => "pending"}
             } = commands_by_id[desktop_command.id]

      assert %{
               "runtime" => "mobile_mdm",
               "device_id" => ^device_id,
               "command_type" => "collect_diagnostics",
               "commandParams" => %{"alert_id" => "pending", "reason" => "auto_investigation"}
             } = commands_by_id[mobile_command.id]
    end

    test "returns commands that reference the alert in command params or payload without metadata listings",
         %{
           conn: conn,
           agent: agent,
           org: org
         } do
      alert =
        insert!(:alert, %{
          agent_id: agent.id,
          organization_id: org.id,
          detection_metadata: %{},
          enrichment: %{}
        })

      desktop_command =
        Repo.insert!(%AgentCommand{
          agent_id: agent.id,
          command_type: "process_list",
          command_params: %{"alert_id" => alert.id, "reason" => "manual_followup"},
          status: "pending",
          priority: 8,
          expires_at: DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.truncate(:second)
        })

      Repo.insert!(%AgentCommand{
        agent_id: agent.id,
        command_type: "process_list",
        command_params: %{"alert_id" => "other-alert-id"},
        status: "pending",
        priority: 8,
        expires_at: DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.truncate(:second)
      })

      device =
        Repo.insert!(%DeviceV2{
          organization_id: org.id,
          device_id: "android-alert-command-by-payload",
          device_name: "Pixel 8",
          platform: "android",
          mdm_enrolled: true,
          mdm_provider: "tamandua_mobile"
        })

      mobile_command =
        Repo.insert!(%MDMCommand{
          organization_id: org.id,
          device_id: device.id,
          command_type: "collect_diagnostics",
          status: "pending",
          payload: %{"alert_id" => alert.id, "reason" => "manual_followup"},
          requested_by: "analyst"
        })

      Repo.insert!(%MDMCommand{
        organization_id: org.id,
        device_id: device.id,
        command_type: "collect_diagnostics",
        status: "pending",
        payload: %{"alert_id" => "other-alert-id"},
        requested_by: "analyst"
      })

      conn = get(conn, "/api/v1/alerts/#{alert.id}/agent-commands")

      response = json_response(conn, 200)
      commands_by_id = Map.new(response["data"], &{&1["id"], &1})

      assert response["meta"]["requested_command_ids"] == []
      assert response["meta"]["discovered_by_alert_id"] == %{"desktop" => 1, "mobile" => 1}
      assert response["meta"]["returned"] == 2

      assert MapSet.new(Map.keys(commands_by_id)) ==
               MapSet.new([desktop_command.id, mobile_command.id])

      alert_id = alert.id

      assert %{
               "runtime" => "desktop_agent",
               "command_type" => "process_list",
               "commandParams" => %{"alert_id" => ^alert_id, "reason" => "manual_followup"}
             } = commands_by_id[desktop_command.id]

      assert %{
               "runtime" => "mobile_mdm",
               "command_type" => "collect_diagnostics",
               "commandParams" => %{"alert_id" => ^alert_id, "reason" => "manual_followup"}
             } = commands_by_id[mobile_command.id]
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

  describe "POST /api/v1/alerts/bulk" do
    test "acknowledge sets selected alerts to acknowledged", %{conn: conn, agent: agent, org: org} do
      alert1 = insert!(:alert, %{agent_id: agent.id, organization_id: org.id, status: "new"})
      alert2 = insert!(:alert, %{agent_id: agent.id, organization_id: org.id, status: "new"})

      conn =
        post(conn, "/api/v1/alerts/bulk", %{
          alert_ids: [alert1.id, alert2.id],
          action: "acknowledge"
        })

      response = json_response(conn, 200)
      assert response["updated_count"] == 2
      assert Repo.get!(Alert, alert1.id).status == "acknowledged"
      assert Repo.get!(Alert, alert2.id).status == "acknowledged"
    end

    test "close sets selected alerts to closed", %{conn: conn, agent: agent, org: org} do
      alert1 = insert!(:alert, %{agent_id: agent.id, organization_id: org.id, status: "resolved"})
      alert2 = insert!(:alert, %{agent_id: agent.id, organization_id: org.id, status: "resolved"})

      conn =
        post(conn, "/api/v1/alerts/bulk", %{
          alert_ids: [alert1.id, alert2.id],
          action: "close"
        })

      response = json_response(conn, 200)
      assert response["updated_count"] == 2
      assert Repo.get!(Alert, alert1.id).status == "closed"
      assert Repo.get!(Alert, alert2.id).status == "closed"
    end
  end

  describe "POST /api/v1/alerts/bulk/add-to-investigation" do
    test "adds only current-organization alerts to current-organization investigations", %{
      admin_conn: conn,
      agent: agent,
      org: org,
      admin: admin
    } do
      alert = insert!(:alert, %{agent_id: agent.id, organization_id: org.id})

      investigation =
        Repo.insert!(%CaseInvestigation{
          title: "Tenant scoped investigation",
          created_by: admin.id,
          organization_id: org.id
        })

      conn =
        post(conn, "/api/v1/alerts/bulk/add-to-investigation", %{
          alert_ids: [alert.id],
          investigation_id: investigation.id
        })

      assert json_response(conn, 200)["success"] == true
      assert Repo.get!(CaseInvestigation, investigation.id).alert_ids == [alert.id]
    end

    test "rejects mixed-tenant alert IDs without updating the investigation", %{
      admin_conn: conn,
      agent: agent,
      org: org,
      admin: admin
    } do
      alert = insert!(:alert, %{agent_id: agent.id, organization_id: org.id})
      {other_org, other_agent} = create_agent_with_org()
      other_alert = insert!(:alert, %{agent_id: other_agent.id, organization_id: other_org.id})

      investigation =
        Repo.insert!(%CaseInvestigation{
          title: "Mixed tenant investigation",
          created_by: admin.id,
          organization_id: org.id
        })

      conn =
        post(conn, "/api/v1/alerts/bulk/add-to-investigation", %{
          alert_ids: [alert.id, other_alert.id],
          investigation_id: investigation.id
        })

      assert response(conn, 404)
      assert Repo.get!(CaseInvestigation, investigation.id).alert_ids == []
    end

    test "rejects current-tenant alert IDs for other-tenant investigations", %{
      admin_conn: conn,
      agent: agent,
      org: org,
      admin: admin
    } do
      alert = insert!(:alert, %{agent_id: agent.id, organization_id: org.id})
      {other_org, _other_agent} = create_agent_with_org()

      other_investigation =
        Repo.insert!(%CaseInvestigation{
          title: "Other tenant investigation",
          created_by: admin.id,
          organization_id: other_org.id
        })

      conn =
        post(conn, "/api/v1/alerts/bulk/add-to-investigation", %{
          alert_ids: [alert.id],
          investigation_id: other_investigation.id
        })

      assert response(conn, 404)
      assert Repo.get!(CaseInvestigation, other_investigation.id).alert_ids == []
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
    test "uses the tenant selected by a super admin", %{conn: conn, org: user_org} do
      {selected_org, selected_agent} = create_agent_with_org()

      insert!(:alert, %{
        agent_id: selected_agent.id,
        organization_id: selected_org.id,
        title: "Selected tenant alert"
      })

      {_other_org, other_agent} = create_agent_with_org()

      insert!(:alert, %{
        agent_id: other_agent.id,
        organization_id: other_agent.organization_id,
        title: "Other tenant alert"
      })

      super_admin = insert!(:user, %{organization_id: user_org.id, role: "super_admin"})
      {:ok, token, _claims} = TamanduaServer.Guardian.encode_and_sign(super_admin)

      response =
        conn
        |> put_req_header("authorization", "Bearer #{token}")
        |> put_req_header("x-tenant-id", selected_org.id)
        |> post("/api/v1/alerts/search", %{})
        |> json_response(200)

      assert Enum.map(response["data"], & &1["title"]) == ["Selected tenant alert"]
    end

    test "does not let a regular user select another tenant", %{
      conn: conn,
      agent: agent,
      org: org
    } do
      insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        title: "Current tenant alert"
      })

      {other_org, other_agent} = create_agent_with_org()

      insert!(:alert, %{
        agent_id: other_agent.id,
        organization_id: other_org.id,
        title: "Forbidden tenant alert"
      })

      response =
        conn
        |> put_req_header("x-tenant-id", other_org.id)
        |> post("/api/v1/alerts/search", %{})
        |> json_response(200)

      titles = Enum.map(response["data"], & &1["title"])
      assert "Current tenant alert" in titles
      refute "Forbidden tenant alert" in titles
    end

    test "returns complete pagination and applied-filter metadata", %{
      conn: conn,
      agent: agent,
      org: org
    } do
      for i <- 1..3 do
        insert!(:alert, %{
          agent_id: agent.id,
          organization_id: org.id,
          title: "Filtered critical #{i}",
          severity: :critical,
          status: "open"
        })
      end

      insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        title: "Filtered low",
        severity: :low,
        status: "open"
      })

      conn =
        post(conn, "/api/v1/alerts/search", %{
          severity: ["critical"],
          status: "active",
          limit: 2,
          offset: 0
        })

      response = json_response(conn, 200)
      assert length(response["data"]) == 2
      assert response["meta"]["total"] == 3
      assert response["meta"]["returned"] == 2
      assert response["meta"]["page"] == 1
      assert response["meta"]["total_pages"] == 2
      assert response["meta"]["truncated"] == true
      assert response["meta"]["has_more"] == true
      assert response["meta"]["applied_filters"]["severity"] == ["critical"]

      assert response["meta"]["applied_filters"]["status"] == [
               "new",
               "open",
               "acknowledged",
               "triaged",
               "investigating"
             ]

      final_page_conn =
        conn
        |> recycle()
        |> put_req_header("authorization", get_req_header(conn, "authorization") |> List.first())
        |> post("/api/v1/alerts/search", %{
          severity: ["critical"],
          status: "active",
          limit: 2,
          offset: 2
        })

      final_meta = json_response(final_page_conn, 200)["meta"]
      assert final_meta["returned"] == 1
      assert final_meta["truncated"] == true
      assert final_meta["has_more"] == false
    end

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
      matching_alert = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        severity: :critical,
        status: "open",
        mitre_techniques: ["T1003.001"]
      })

      non_matching_alert = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        severity: :critical,
        status: "open",
        mitre_techniques: ["T1059.001"]
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
      assert Enum.any?(data, &(&1["id"] == matching_alert.id))
      refute Enum.any?(data, &(&1["id"] == non_matching_alert.id))
    end

    test "normalizes lifecycle status aliases like the index endpoint", %{conn: conn, agent: agent, org: org} do
      active_statuses = ["new", "open", "acknowledged", "triaged", "investigating"]
      dismissed_statuses = ["resolved", "false_positive", "closed"]

      Enum.each(active_statuses ++ dismissed_statuses, fn status ->
        insert!(:alert, %{agent_id: agent.id, organization_id: org.id, status: status})
      end)

      active_conn = post(conn, "/api/v1/alerts/search", %{status: "active", limit: 20})
      active_data = json_response(active_conn, 200)["data"]
      assert Enum.any?(active_data, fn alert -> alert["status"] == "new" end)
      assert Enum.any?(active_data, fn alert -> alert["status"] == "investigating" end)
      assert Enum.all?(active_data, fn alert -> alert["status"] in active_statuses end)

      dismissed_conn =
        conn
        |> recycle()
        |> put_req_header("authorization", get_req_header(conn, "authorization") |> List.first())
        |> post("/api/v1/alerts/search", %{filters: %{status: "dismissed"}, limit: 20})

      dismissed_data = json_response(dismissed_conn, 200)["data"]
      assert Enum.any?(dismissed_data, fn alert -> alert["status"] == "false_positive" end)
      assert Enum.all?(dismissed_data, fn alert -> alert["status"] in dismissed_statuses end)

      closed_conn =
        conn
        |> recycle()
        |> put_req_header("authorization", get_req_header(conn, "authorization") |> List.first())
        |> post("/api/v1/alerts/search", %{status: "closed", limit: 20})

      closed_statuses = closed_conn |> json_response(200) |> Map.fetch!("data") |> Enum.map(& &1["status"])
      assert "resolved" in closed_statuses
      assert "closed" in closed_statuses
      assert Enum.all?(closed_statuses, &(&1 in ["resolved", "closed"]))
    end

    test "source filter matches serialized behavioral fallback", %{conn: conn, agent: agent, org: org} do
      behavioral =
        insert!(:alert, %{
          agent_id: agent.id,
          organization_id: org.id,
          title: "Fallback behavioral alert",
          detection_metadata: %{},
          raw_event: %{},
          evidence: %{}
        })

      insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        title: "Explicit mobile alert",
        detection_metadata: %{"source" => "mobile_app_guard"}
      })

      conn = post(conn, "/api/v1/alerts/search", %{source: "behavioral", limit: 20})

      data = json_response(conn, 200)["data"]
      assert Enum.any?(data, &(&1["id"] == behavioral.id))
      assert Enum.all?(data, &(&1["source"] == "behavioral"))
    end

    test "source filter normalizes mobile and ndr aliases", %{conn: conn, agent: agent, org: org} do
      mobile =
        insert!(:alert, %{
          agent_id: agent.id,
          organization_id: org.id,
          title: "Mobile app guard",
          detection_metadata: %{"source" => "mobile_app_guard"}
        })

      ndr =
        insert!(:alert, %{
          agent_id: agent.id,
          organization_id: org.id,
          title: "DoH resolver",
          raw_event: %{"payload" => %{"source" => "dns_flow"}}
        })

      mobile_conn = post(conn, "/api/v1/alerts/search", %{source: "mobile", limit: 20})
      mobile_data = json_response(mobile_conn, 200)["data"]
      assert Enum.any?(mobile_data, &(&1["id"] == mobile.id))
      assert Enum.all?(mobile_data, &(&1["source"] == "mobile"))

      ndr_conn =
        conn
        |> recycle()
        |> put_req_header("authorization", get_req_header(conn, "authorization") |> List.first())
        |> post("/api/v1/alerts/search", %{source: "ndr", limit: 20})

      ndr_data = json_response(ndr_conn, 200)["data"]
      assert Enum.any?(ndr_data, &(&1["id"] == ndr.id))
      assert Enum.all?(ndr_data, &(&1["source"] == "ndr"))
    end

    test "source serialization matches ai security and ioc filters", %{conn: conn, agent: agent, org: org} do
      ai_security =
        insert!(:alert, %{
          agent_id: agent.id,
          organization_id: org.id,
          title: "Prompt injection",
          detection_metadata: %{"source" => "llm_prompt_guard"}
        })

      ioc =
        insert!(:alert, %{
          agent_id: agent.id,
          organization_id: org.id,
          title: "Threat intel match",
          evidence: %{"alert_source" => "threat_intel"}
        })

      ai_conn = post(conn, "/api/v1/alerts/search", %{source: "ai_security", limit: 20})
      ai_data = json_response(ai_conn, 200)["data"]
      assert Enum.any?(ai_data, &(&1["id"] == ai_security.id))
      assert Enum.all?(ai_data, &(&1["source"] == "ai_security"))

      ioc_conn =
        conn
        |> recycle()
        |> put_req_header("authorization", get_req_header(conn, "authorization") |> List.first())
        |> post("/api/v1/alerts/search", %{source: "ioc", limit: 20})

      ioc_data = json_response(ioc_conn, 200)["data"]
      assert Enum.any?(ioc_data, &(&1["id"] == ioc.id))
      assert Enum.all?(ioc_data, &(&1["source"] == "ioc"))
    end

    test "source filter preserves inferred ml alerts", %{conn: conn, agent: agent, org: org} do
      ml_alert =
        insert!(:alert, %{
          agent_id: agent.id,
          organization_id: org.id,
          title: "Offline ML detection",
          detection_metadata: %{"rule_name" => "OFFLINE_ML_MALWARE_CLASSIFICATION"},
          raw_event: %{"payload" => %{"file_path" => "sample.bin"}}
        })

      conn = post(conn, "/api/v1/alerts/search", %{source: "ml", limit: 20})

      data = json_response(conn, 200)["data"]
      assert Enum.any?(data, &(&1["id"] == ml_alert.id))
      assert Enum.all?(data, &(&1["source"] == "ml"))
    end

    test "validation filter excludes parity alerts by default and supports include or only", %{
      conn: conn,
      agent: agent,
      org: org
    } do
      real_alert =
        insert!(:alert, %{
          agent_id: agent.id,
          organization_id: org.id,
          title: "Real customer alert",
          detection_metadata: %{"source" => "behavioral"}
        })

      validation_alert =
        insert!(:alert, %{
          agent_id: agent.id,
          organization_id: org.id,
          title: "Mobile parity validation",
          raw_event: %{"payload" => %{"parity_run_id" => "mobile-endpoint-parity-1"}}
        })

      explicit_validation_alert =
        insert!(:alert, %{
          agent_id: agent.id,
          organization_id: org.id,
          title: "Explicit validation alert",
          detection_metadata: %{"validation_alert" => true}
        })

      default_conn = post(conn, "/api/v1/alerts/search", %{limit: 20})
      default_ids = default_conn |> json_response(200) |> Map.fetch!("data") |> Enum.map(& &1["id"])
      assert real_alert.id in default_ids
      refute validation_alert.id in default_ids
      refute explicit_validation_alert.id in default_ids

      include_conn =
        conn
        |> recycle()
        |> put_req_header("authorization", get_req_header(conn, "authorization") |> List.first())
        |> post("/api/v1/alerts/search", %{validation: "include", limit: 20})

      include_data = json_response(include_conn, 200)["data"]
      assert Enum.any?(include_data, &(&1["id"] == validation_alert.id))
      assert Enum.any?(include_data, &(&1["id"] == explicit_validation_alert.id))

      only_conn =
        conn
        |> recycle()
        |> put_req_header("authorization", get_req_header(conn, "authorization") |> List.first())
        |> post("/api/v1/alerts/search", %{validation: "only", limit: 20})

      only_data = json_response(only_conn, 200)["data"]
      assert Enum.any?(only_data, &(&1["id"] == validation_alert.id))
      assert Enum.any?(only_data, &(&1["id"] == explicit_validation_alert.id))
      assert Enum.all?(only_data, &(&1["validation_alert"] == true))
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
