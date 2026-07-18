defmodule TamanduaServerWeb.API.V1.LiveResponseScreenCaptureControllerTest do
  use TamanduaServerWeb.ConnCase, async: false

  import Ecto.Query

  alias TamanduaServer.Agents.{AgentCommand, Policy, Registry}
  alias TamanduaServer.Audit.AuditLog
  alias TamanduaServer.LiveResponse.ScreenCaptureArtifacts
  alias TamanduaServer.LiveResponse.ScreenCaptureArtifact
  alias TamanduaServer.Mobile.{DeviceV2, MDMCommand}
  alias TamanduaServer.Repo

  setup %{conn: conn} do
    organization = insert(:organization)
    agent = insert(:agent, organization: organization, os_type: "windows", status: "online")
    admin = insert(:user, organization: organization, role: "admin")
    analyst = insert(:user, organization: organization, role: "analyst")

    policy =
      Repo.insert!(%Policy{
        name: "Screen capture test policy",
        organization_id: organization.id,
        created_by_id: admin.id,
        status: "active",
        scope: "organization",
        policy_data: %{
          "response" => %{
            "screen_capture" => %{"mode" => "silent"}
          }
        }
      })

    {:ok, admin_token, _claims} = TamanduaServer.Guardian.encode_and_sign(admin)
    {:ok, analyst_token, _claims} = TamanduaServer.Guardian.encode_and_sign(analyst)

    :ok =
      Registry.register(agent.id, %{
        hostname: agent.hostname,
        os_type: agent.os_type,
        organization_id: organization.id,
        worker_pid: self(),
        capabilities: ["screen_capture"]
      })

    on_exit(fn -> Registry.unregister(agent.id) end)

    %{
      conn: conn,
      organization: organization,
      agent: agent,
      policy: policy,
      admin_conn: put_req_header(conn, "authorization", "Bearer #{admin_token}"),
      analyst_conn: put_req_header(conn, "authorization", "Bearer #{analyst_token}")
    }
  end

  test "queues a tenant-scoped one-shot capture and writes an audit entry", %{
    admin_conn: conn,
    organization: organization,
    agent: agent,
    policy: policy
  } do
    policy
    |> Ecto.Changeset.change(
      policy_data: %{
        "response" => %{
          "screen_capture" => %{
            "mode" => "silent",
            "allowed_scopes" => ["virtual_desktop", "active_window"],
            "redaction_required" => true
          }
        }
      }
    )
    |> Repo.update!()

    register_policy_v2_runtime(agent)

    canonical =
      "mode=silent;notify_timing=none;allowed_scopes=active_window,virtual_desktop;redaction_required=true"

    expected_policy_hash =
      "feb822dec838c6655ea791ea9b5cfb87552e5fd233e995fe8cb0578d6b798d4c"

    assert byte_size(canonical) == 99

    assert :crypto.hash(:sha256, canonical) |> Base.encode16(case: :lower) ==
             expected_policy_hash

    conn =
      post(conn, "/api/v1/live-response/#{agent.id}/screen-capture", %{
        "reason" => "Validate ransomware desktop state",
        "ttl_seconds" => 120,
        "display" => "all"
      })

    body = json_response(conn, 202)["data"]
    assert body["schema_version"] == "tamandua.screen_capture/v1"
    assert body["command_type"] == "screen_capture"
    assert body["status"] == "queued"
    assert body["capability_state"] == "supported"
    assert body["continuous"] == false
    assert body["input_control"] == false
    assert body["policy_mode"] == "silent"
    assert body["policy"]["source"] == "effective_agent_policy"
    assert body["policy"]["allowed_scopes"] == ["active_window", "virtual_desktop"]
    assert body["policy"]["hash"] == expected_policy_hash

    assert body["policy"]["hash_algorithm"] ==
             "screen_capture_policy_hash_sha256_lexical_v2"

    assert body["artifact"]["status"] == "pending"

    assert body["artifact"]["status_url"] ==
             "/api/v1/live-response/#{agent.id}/screen-captures/#{body["artifact"]["id"]}"

    refute Map.has_key?(body["artifact"], "upload")
    refute Map.has_key?(body["artifact"], "token")

    command = Repo.get!(AgentCommand, body["command_id"])
    upload_token = get_in(command.command_params, ["upload", "token"])
    assert is_binary(upload_token)
    assert command.command_params["reason"] == "Validate ransomware desktop state"
    assert command.command_params["schema_version"] == "tamandua.screen_capture/v1"
    assert command.command_params["policy_mode"] == "silent"
    assert command.command_params["policy"]["id"] == "effective:#{agent.id}"
    assert command.command_params["policy"]["mode"] == "silent"

    assert command.command_params["policy"]["allowed_scopes"] == [
             "active_window",
             "virtual_desktop"
           ]

    assert command.command_params["policy"]["hash"] == expected_policy_hash

    assert command.command_params["policy"]["hash_algorithm"] ==
             "screen_capture_policy_hash_sha256_lexical_v2"

    refute command.command_params["policy"]["hash"] ==
             "8558dc260906d9e0e7a782fa671bf00c30bd70fdb8c3bf6508308de6bec9b1d3"

    refute command.command_params["policy"]["hash"] ==
             "699ca90ac1bda3c2ee510b006cbf473019f693da2eb32fde68f4d51aa5e49aa9"

    assert command.command_params["policy"]["expires_at_ms"] -
             command.command_params["policy"]["issued_at_ms"] == 120_000

    refute Map.has_key?(command.command_params, "content")
    refute Map.has_key?(command.command_params, "base64")
    refute Jason.encode!(body) =~ upload_token

    audit =
      Repo.one!(
        from(entry in AuditLog,
          where:
            entry.organization_id == ^organization.id and
              entry.action == "screen_capture_request",
          order_by: [desc: entry.inserted_at],
          limit: 1
        )
      )

    assert audit.resource_id == agent.id
    assert audit.details["status"] == "queued"
    assert audit.details["policy_mode"] == "silent"
    refute Map.has_key?(audit.details, "artifact")
    refute Jason.encode!(audit.details) =~ upload_token
  end

  test "upload ack is idempotent only for the same ready artifact digest and size", %{
    admin_conn: admin_conn,
    agent: agent
  } do
    request_conn =
      post(admin_conn, "/api/v1/live-response/#{agent.id}/screen-capture", %{
        "reason" => "Confirm visible ransomware impact"
      })

    request = json_response(request_conn, 202)["data"]
    artifact_id = request["artifact"]["id"]
    command = Repo.get!(AgentCommand, request["command_id"])
    upload_token = get_in(command.command_params, ["upload", "token"])
    png = <<137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82>>
    sha256 = :crypto.hash(:sha256, png) |> Base.encode16(case: :lower)

    upload_conn =
      build_conn()
      |> put_req_header("authorization", "Bearer #{upload_token}")
      |> put_req_header("content-type", "image/png")
      |> put_req_header("content-length", Integer.to_string(byte_size(png)))
      |> put_req_header("x-tamandua-sha256", sha256)
      |> put_req_header("x-tamandua-captured-at", DateTime.utc_now() |> DateTime.to_iso8601())
      |> put("/api/v1/agent-artifacts/screen-captures/#{artifact_id}", png)

    assert json_response(upload_conn, 201)["data"]["status"] == "ready"

    command = Repo.get!(AgentCommand, command.id)
    refute get_in(command.command_params, ["upload", "token"])

    status_conn =
      get(
        admin_conn,
        "/api/v1/live-response/#{agent.id}/screen-captures/#{artifact_id}"
      )

    status = json_response(status_conn, 200)["data"]
    assert status["artifact"]["status"] == "ready"
    assert status["artifact"]["sha256"] == sha256
    assert get_resp_header(status_conn, "cache-control") == ["no-store, private"]

    content_conn =
      get(
        admin_conn,
        "/api/v1/live-response/#{agent.id}/screen-captures/#{artifact_id}/content"
      )

    assert response(content_conn, 200) == png
    assert get_resp_header(content_conn, "content-type") |> hd() =~ "image/png"
    assert get_resp_header(content_conn, "cache-control") |> hd() =~ "no-store"

    replay_conn =
      build_conn()
      |> put_req_header("authorization", "Bearer #{upload_token}")
      |> put_req_header("content-type", "image/png")
      |> put_req_header("content-length", Integer.to_string(byte_size(png)))
      |> put_req_header("x-tamandua-sha256", sha256)
      |> put_req_header("x-tamandua-captured-at", DateTime.utc_now() |> DateTime.to_iso8601())
      |> put("/api/v1/agent-artifacts/screen-captures/#{artifact_id}", png)

    replay_data = json_response(replay_conn, 201)["data"]
    assert replay_data["status"] == "ready"
    assert replay_data["artifact_id"] == artifact_id
    assert replay_data["sha256"] == sha256
    assert replay_data["size"] == byte_size(png)

    divergent_png = binary_part(png, 0, byte_size(png) - 1) <> <<83>>
    divergent_sha256 = :crypto.hash(:sha256, divergent_png) |> Base.encode16(case: :lower)

    divergent_conn =
      build_conn()
      |> put_req_header("authorization", "Bearer #{upload_token}")
      |> put_req_header("content-type", "image/png")
      |> put_req_header("content-length", Integer.to_string(byte_size(divergent_png)))
      |> put_req_header("x-tamandua-sha256", divergent_sha256)
      |> put_req_header("x-tamandua-captured-at", DateTime.utc_now() |> DateTime.to_iso8601())
      |> put("/api/v1/agent-artifacts/screen-captures/#{artifact_id}", divergent_png)

    assert json_response(divergent_conn, 409)["error"] == "Upload credential already consumed"
  end

  test "queues iOS capture through tenant-scoped MDM and binds the artifact to mobile_command_id",
       %{
         admin_conn: conn,
         organization: organization,
         policy: policy
       } do
    policy
    |> Ecto.Changeset.change(
      policy_data: %{
        "response" => %{
          "screen_capture" => %{
            "mode" => "consent_required",
            "allowed_scopes" => ["active_window"]
          }
        }
      }
    )
    |> Repo.update!()

    external_id = "ios-#{System.unique_integer([:positive])}"

    device =
      Repo.insert!(%DeviceV2{
        organization_id: organization.id,
        device_id: external_id,
        platform: "ios",
        device_name: "iPhone test"
      })

    ios_agent =
      insert(:agent,
        organization: organization,
        os_type: "ios",
        status: "online",
        machine_id: external_id,
        config: %{
          "source" => "tamandua_mobile_v2",
          "capabilities" => %{
            "screen_capture" => %{"available" => true, "native_method_available" => true}
          }
        }
      )

    response =
      post(conn, "/api/v1/live-response/#{ios_agent.id}/screen-capture", %{
        "reason" => "Capture current app evidence",
        "scope" => "active_window",
        "watermark" => true,
        "ttl_seconds" => 120
      })
      |> json_response(202)
      |> Map.fetch!("data")

    assert response["capability_state"] == "consent_required"
    assert response["consent_model"] == "user_initiated"
    assert response["capture_coverage"] == "current_tamandua_app_screen_single_frame"

    command = Repo.get!(MDMCommand, response["command_id"])
    assert command.device_id == device.id
    assert command.command_type == "screen_capture"
    assert command.status == "pending"
    assert command.payload["scope"] == "active_window"
    assert is_binary(get_in(command.payload, ["upload", "token"]))

    artifact = Repo.get_by!(ScreenCaptureArtifact, mobile_command_id: command.id)
    assert artifact.command_id == nil
    assert artifact.agent_id == ios_agent.id

    assert :ok = ScreenCaptureArtifacts.scrub_command_credential(organization.id, command.id)
    command = Repo.get!(MDMCommand, command.id)
    refute get_in(command.payload, ["upload", "token"])
    assert get_in(command.payload, ["upload", "credential_status"]) == "consumed_or_expired"
  end

  test "upload-before-command-attach scrubs the credential after association", %{
    organization: organization,
    agent: agent
  } do
    {:ok, artifact, upload_token} =
      ScreenCaptureArtifacts.create(organization.id, agent.id, 300)

    png = <<137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82>>
    sha256 = :crypto.hash(:sha256, png) |> Base.encode16(case: :lower)

    assert {:ok, ready_artifact} =
             ScreenCaptureArtifacts.upload(
               artifact.id,
               upload_token,
               "image/png",
               sha256,
               DateTime.utc_now() |> DateTime.to_iso8601(),
               png
             )

    assert ready_artifact.command_id == nil

    assert {:ok, command} =
             AgentCommand.insert_new(%{
               agent_id: agent.id,
               command_type: "screen_capture",
               command_params: %{"upload" => %{"token" => upload_token}}
             })

    assert {:ok, attached} = ScreenCaptureArtifacts.attach_command(ready_artifact, command.id)
    assert attached.command_id == command.id

    command = Repo.get!(AgentCommand, command.id)
    refute get_in(command.command_params, ["upload", "token"])
  end

  test "requires the dedicated screen RBAC permission", %{analyst_conn: conn, agent: agent} do
    conn =
      post(conn, "/api/v1/live-response/#{agent.id}/screen-capture", %{
        "reason" => "Investigate alert"
      })

    assert json_response(conn, 403)["error"] == "Insufficient permissions"
    assert Repo.aggregate(AgentCommand, :count) == 0
  end

  test "requires an operator reason", %{admin_conn: conn, agent: agent} do
    conn = post(conn, "/api/v1/live-response/#{agent.id}/screen-capture", %{})

    assert json_response(conn, 422)["error"] == "reason is required"
    assert Repo.aggregate(AgentCommand, :count) == 0
  end

  test "disabled effective policy denies before command or artifact creation and audits", %{
    admin_conn: conn,
    organization: organization,
    agent: agent,
    policy: policy
  } do
    policy
    |> Ecto.Changeset.change(
      policy_data: %{
        "response" => %{"screen_capture" => %{"mode" => "disabled"}}
      }
    )
    |> Repo.update!()

    conn =
      post(conn, "/api/v1/live-response/#{agent.id}/screen-capture", %{
        "reason" => "Investigate alert",
        "display" => "all"
      })

    body = json_response(conn, 403)
    assert body["data"]["status"] == "policy_denied"
    assert body["data"]["policy_mode"] == "disabled"
    assert Repo.aggregate(AgentCommand, :count) == 0
    assert Repo.aggregate(TamanduaServer.LiveResponse.ScreenCaptureArtifact, :count) == 0

    audit =
      Repo.one!(
        from(entry in AuditLog,
          where:
            entry.organization_id == ^organization.id and
              entry.action == "screen_capture_request",
          order_by: [desc: entry.inserted_at],
          limit: 1
        )
      )

    assert audit.details["status"] == "policy_denied"
    assert audit.details["policy_mode"] == "disabled"
    assert audit.details["command_id"] == nil
  end

  test "multi-scope negotiation denial creates neither command nor artifact", %{
    admin_conn: conn,
    agent: agent,
    policy: policy
  } do
    policy
    |> Ecto.Changeset.change(
      policy_data: %{
        "response" => %{
          "screen_capture" => %{
            "mode" => "silent",
            "allowed_scopes" => ["virtual_desktop", "active_window"]
          }
        }
      }
    )
    |> Repo.update!()

    conn =
      post(conn, "/api/v1/live-response/#{agent.id}/screen-capture", %{
        "reason" => "Investigate alert",
        "display" => "all"
      })

    body = json_response(conn, 409)
    assert body["code"] == "screen_capture_policy_hash_contract_not_negotiated"
    assert Repo.aggregate(AgentCommand, :count) == 0
    assert Repo.aggregate(TamanduaServer.LiveResponse.ScreenCaptureArtifact, :count) == 0
  end

  test "malformed runtime tenant denies before desktop command, artifact, or MDM creation", %{
    admin_conn: conn,
    organization: organization,
    agent: agent
  } do
    [{agent_id, runtime}] = :ets.lookup(:tamandua_agents, agent.id)

    :ets.insert(
      :tamandua_agents,
      {agent_id, %{runtime | organization_id: String.to_atom(organization.id)}}
    )

    conn =
      post(conn, "/api/v1/live-response/#{agent.id}/screen-capture", %{
        "reason" => "Investigate malformed runtime tenant"
      })

    assert json_response(conn, 404)["error"] == "Agent not found"
    assert Repo.aggregate(AgentCommand, :count) == 0
    assert Repo.aggregate(ScreenCaptureArtifact, :count) == 0
    assert Repo.aggregate(MDMCommand, :count) == 0
  end

  test "returns unsupported explicitly when capability is not reported", %{
    admin_conn: conn,
    agent: agent
  } do
    :ok = Registry.unregister(agent.id)

    :ok =
      Registry.register(agent.id, %{
        hostname: agent.hostname,
        os_type: agent.os_type,
        organization_id: agent.organization_id,
        worker_pid: self(),
        capabilities: []
      })

    conn =
      post(conn, "/api/v1/live-response/#{agent.id}/screen-capture", %{
        "reason" => "Investigate alert"
      })

    body = json_response(conn, 422)["data"]
    assert body["status"] == "unsupported"
    assert body["capability_state"] == "unsupported"
    assert body["unsupported_reason"] == "agent_did_not_report_screen_capture_capability"
    assert Repo.aggregate(AgentCommand, :count) == 0
  end

  defp register_policy_v2_runtime(agent) do
    algorithm = "screen_capture_policy_hash_sha256_lexical_v2"
    epoch = Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)

    :ok = Registry.unregister(agent.id)

    :ok =
      Registry.register(agent.id, %{
        hostname: agent.hostname,
        os_type: agent.os_type,
        organization_id: agent.organization_id,
        worker_pid: self(),
        socket_pid: self(),
        connection_epoch: epoch,
        capabilities: ["screen_capture", algorithm]
      })

    :ok =
      Registry.update_runtime_snapshot(
        agent.id,
        agent.organization_id,
        self(),
        self(),
        epoch,
        %{
          capabilities: ["screen_capture", algorithm],
          screen_session_broker: %{
            "schema_version" => "tamandua.screen_session_broker/v1",
            "state" => "ready",
            "ready" => true,
            "capabilities" => ["screen_capture"],
            "policy_hash_algorithms" => [algorithm],
            "observed_at" => DateTime.utc_now() |> DateTime.to_iso8601()
          }
        }
      )
  end
end
