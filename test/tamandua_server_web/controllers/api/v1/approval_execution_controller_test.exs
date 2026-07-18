defmodule TamanduaServerWeb.API.V1.ApprovalExecutionControllerTest do
  use TamanduaServerWeb.ConnCase, async: false

  alias TamanduaServer.Accounts.{Permission, Role, RolePermission, UserRole}
  alias TamanduaServer.AISecurity.ApprovalExecution
  alias TamanduaServer.Agents.AgentCommand
  alias TamanduaServer.Authorization.RBAC
  alias TamanduaServer.Repo

  setup do
    organization = insert(:organization)
    other_organization = insert(:organization)
    viewer = insert(:user, organization: organization, role: "viewer")
    responder = insert(:user, organization: organization, role: "viewer")
    other_responder = insert(:user, organization: other_organization, role: "viewer")

    grant_permissions!(viewer, organization, [:response_view])
    grant_permissions!(responder, organization, [:response_approve])

    grant_permissions!(
      other_responder,
      other_organization,
      [:response_approve]
    )

    {:ok, viewer_token, _} = TamanduaServer.Guardian.encode_and_sign(viewer)
    {:ok, responder_token, _} = TamanduaServer.Guardian.encode_and_sign(responder)

    {:ok, other_responder_token, _} =
      TamanduaServer.Guardian.encode_and_sign(other_responder)

    %{
      organization: organization,
      other_organization: other_organization,
      viewer: viewer,
      viewer_token: viewer_token,
      responder: responder,
      responder_token: responder_token,
      other_responder: other_responder,
      other_responder_token: other_responder_token
    }
  end

  test "queue route requires authentication", %{conn: conn} do
    response = get(conn, "/api/v1/analyst/approval-executions")

    assert json_response(response, 401)["error"] ==
             "Missing authorization header or session"
  end

  test "queue route requires response_approve and is not exposed by response_view", %{
    conn: conn,
    viewer_token: token
  } do
    response =
      conn
      |> bearer(token)
      |> get("/api/v1/analyst/approval-executions")

    assert %{
             "error" => "forbidden",
             "required_permission" => "response_approve"
           } = json_response(response, 403)
  end

  test "single execution status remains response_view scoped", %{
    conn: conn,
    organization: organization,
    viewer: viewer,
    viewer_token: viewer_token,
    responder_token: approver_only_token
  } do
    execution = insert_reconciliation!(organization, viewer, "status-view")
    path = "/api/v1/analyst/approval-executions/#{execution.id}"

    viewed =
      conn
      |> bearer(viewer_token)
      |> get(path)
      |> json_response(200)

    assert viewed["data"]["execution_id"] == execution.id
    assert viewed["data"]["status"] == "reconciliation_required"
    refute Map.has_key?(viewed["data"], "target")
    refute Map.has_key?(viewed["data"], "result")
    refute Map.has_key?(viewed["data"], "error")

    denied =
      build_conn()
      |> bearer(approver_only_token)
      |> get(path)

    assert %{
             "error" => "forbidden",
             "required_permission" => "response_view"
           } = json_response(denied, 403)
  end

  test "queue is tenant scoped, limit bounded, and serialized without execution payloads", %{
    conn: conn,
    organization: organization,
    other_organization: other_organization,
    responder: responder,
    responder_token: token,
    other_responder: other_responder
  } do
    first = insert_reconciliation!(organization, responder, "first")
    second = insert_reconciliation!(organization, responder, "second")
    foreign = insert_reconciliation!(other_organization, other_responder, "foreign")

    limited =
      conn
      |> bearer(token)
      |> get("/api/v1/analyst/approval-executions?limit=1")
      |> json_response(200)

    assert limited["status"] == "success"
    assert limited["meta"] == %{"count" => 1}
    assert [queued] = limited["data"]
    assert queued["execution_id"] in [first.id, second.id]
    refute queued["execution_id"] == foreign.id

    assert MapSet.new(Map.keys(queued)) ==
             MapSet.new(~w(
               execution_id investigation_id recommendation_id status action_type
               target_agent_id started_at lease_expires_at completed_at inserted_at updated_at
             ))

    refute Map.has_key?(queued, "target")
    refute Map.has_key?(queued, "result")
    refute Map.has_key?(queued, "error")
    refute Map.has_key?(queued, "approver_id")
    refute Map.has_key?(queued, "idempotency_key")

    clamped =
      build_conn()
      |> bearer(token)
      |> get("/api/v1/analyst/approval-executions?limit=0")
      |> json_response(200)

    assert clamped["meta"] == %{"count" => 1}

    defaulted =
      build_conn()
      |> bearer(token)
      |> get("/api/v1/analyst/approval-executions?limit=not-an-integer")
      |> json_response(200)

    assert defaulted["meta"] == %{"count" => 2}
    refute Enum.any?(defaulted["data"], &(&1["execution_id"] == foreign.id))
  end

  test "reconcile route requires response_approve even when response_view is granted", %{
    conn: conn,
    organization: organization,
    viewer: viewer,
    viewer_token: token
  } do
    execution = insert_reconciliation!(organization, viewer, "view-only")

    response =
      conn
      |> bearer(token)
      |> post("/api/v1/analyst/approval-executions/#{execution.id}/reconcile", %{
        "outcome" => "succeeded",
        "evidence_ref" => %{"type" => "agent_command", "id" => Ecto.UUID.generate()}
      })

    assert %{
             "error" => "forbidden",
             "required_permission" => "response_approve"
           } = json_response(response, 403)
  end

  test "queue caps caller-controlled limits at 200", %{
    conn: conn,
    organization: organization,
    responder: responder,
    responder_token: token
  } do
    agent = insert(:agent, organization: organization)

    for index <- 1..201 do
      insert_reconciliation!(organization, responder, "upper-bound-#{index}", agent_id: agent.id)
    end

    response =
      conn
      |> bearer(token)
      |> get("/api/v1/analyst/approval-executions?limit=1000000")
      |> json_response(200)

    assert response["meta"] == %{"count" => 200}
    assert length(response["data"]) == 200
  end

  test "reconciliation is tenant scoped and returns only status serialization", %{
    conn: conn,
    organization: organization,
    responder: responder,
    responder_token: token,
    other_responder_token: other_token
  } do
    agent = insert(:agent, organization: organization)

    execution =
      insert_reconciliation!(organization, responder, "success", agent_id: agent.id)

    command =
      Repo.insert!(%AgentCommand{
        agent_id: agent.id,
        command_type: "isolate_network",
        status: "completed",
        completed_at: DateTime.utc_now() |> DateTime.truncate(:second)
      })

    path = "/api/v1/analyst/approval-executions/#{execution.id}/reconcile"

    payload = %{
      "outcome" => "succeeded",
      "evidence_ref" => %{"type" => "agent_command", "id" => command.id}
    }

    build_conn()
    |> bearer(other_token)
    |> post(path, payload)
    |> json_response(404)

    response =
      conn
      |> bearer(token)
      |> post(path, payload)
      |> json_response(200)

    assert response["status"] == "success"
    assert response["data"]["execution_id"] == execution.id
    assert response["data"]["status"] == "succeeded"

    refute Map.has_key?(response["data"], "target")
    refute Map.has_key?(response["data"], "target_agent_id")
    refute Map.has_key?(response["data"], "action_type")
    refute Map.has_key?(response["data"], "result")
    refute Map.has_key?(response["data"], "error")
    refute Map.has_key?(response["data"], "reconciled_by_id")

    transition_conflict =
      build_conn()
      |> bearer(token)
      |> post(path, payload)
      |> json_response(409)

    assert transition_conflict["code"] == "unauthorized_or_invalid_transition"

    second_execution =
      insert_reconciliation!(organization, responder, "reused-evidence", agent_id: agent.id)

    evidence_conflict =
      build_conn()
      |> bearer(token)
      |> post(
        "/api/v1/analyst/approval-executions/#{second_execution.id}/reconcile",
        payload
      )
      |> json_response(409)

    assert evidence_conflict["code"] == "evidence_already_used"
  end

  test "reconciliation route rejects an incomplete evidence contract", %{
    conn: conn,
    responder_token: token
  } do
    response =
      conn
      |> bearer(token)
      |> post("/api/v1/analyst/approval-executions/#{Ecto.UUID.generate()}/reconcile", %{
        "outcome" => "succeeded"
      })

    assert %{
             "status" => "error",
             "message" => "outcome and typed evidence_ref are required"
           } = json_response(response, 400)
  end

  test "reconciliation maps malformed typed evidence to a client error", %{
    conn: conn,
    organization: organization,
    responder: responder,
    responder_token: token
  } do
    execution = insert_reconciliation!(organization, responder, "invalid-evidence")
    path = "/api/v1/analyst/approval-executions/#{execution.id}/reconcile"

    invalid_evidence =
      conn
      |> bearer(token)
      |> post(path, %{
        "outcome" => "succeeded",
        "evidence_ref" => %{
          "type" => "agent_command",
          "id" => Ecto.UUID.generate()
        }
      })
      |> json_response(400)

    assert invalid_evidence["code"] == "invalid_evidence_ref"

    invalid_outcome =
      build_conn()
      |> bearer(token)
      |> post(path, %{
        "outcome" => "running",
        "evidence_ref" => %{
          "type" => "agent_command",
          "id" => Ecto.UUID.generate()
        }
      })
      |> json_response(400)

    assert invalid_outcome["code"] == "invalid_reconciliation"
  end

  test "persistence failures are exposed as unavailable rather than internal faults", %{
    conn: conn
  } do
    response =
      TamanduaServerWeb.FallbackController.call(
        conn,
        {:error, :persistence_unavailable}
      )

    assert json_response(response, 503)["code"] == "persistence_unavailable"
  end

  test "static routes are not shadowed by the dynamic show route" do
    index_route =
      Phoenix.Router.route_info(
        TamanduaServerWeb.Router,
        "GET",
        "/api/v1/analyst/approval-executions",
        "localhost"
      )

    reconcile_route =
      Phoenix.Router.route_info(
        TamanduaServerWeb.Router,
        "POST",
        "/api/v1/analyst/approval-executions/#{Ecto.UUID.generate()}/reconcile",
        "localhost"
      )

    assert index_route.plug == TamanduaServerWeb.API.V1.ApprovalExecutionController
    assert index_route.plug_opts == :index
    assert reconcile_route.plug == TamanduaServerWeb.API.V1.ApprovalExecutionController
    assert reconcile_route.plug_opts == :reconcile
  end

  defp insert_reconciliation!(organization, approver, suffix, opts \\ []) do
    agent_id =
      Keyword.get_lazy(opts, :agent_id, fn ->
        insert(:agent, organization: organization).id
      end)

    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    %ApprovalExecution{}
    |> ApprovalExecution.create_changeset(%{
      organization_id: organization.id,
      investigation_id: "investigation-#{suffix}",
      recommendation_id: "recommendation-#{suffix}",
      approver_id: approver.id,
      idempotency_key:
        :crypto.hash(:sha256, "#{organization.id}:#{suffix}")
        |> Base.encode16(case: :lower),
      status: "reconciliation_required",
      action_type: "isolate_network",
      target: %{"agent_id" => agent_id},
      started_at: DateTime.add(now, -600, :second),
      lease_expires_at: DateTime.add(now, -300, :second),
      completed_at: now
    })
    |> Repo.insert!()
  end

  defp bearer(conn, token),
    do: put_req_header(conn, "authorization", "Bearer #{token}")

  defp grant_permissions!(user, organization, permission_slugs) do
    role =
      %Role{}
      |> Role.changeset(%{
        name: "Approval execution test role",
        slug: "approval_execution_test_#{user.id}",
        builtin: false,
        priority: 80,
        organization_id: organization.id
      })
      |> Repo.insert!()

    Enum.each(permission_slugs, fn permission_slug ->
      slug = Atom.to_string(permission_slug)

      permission =
        Repo.get_by(Permission, slug: slug) ||
          %Permission{}
          |> Permission.changeset(%{
            name: slug,
            slug: slug,
            description: slug,
            category: "response"
          })
          |> Repo.insert!()

      %RolePermission{}
      |> RolePermission.changeset(%{role_id: role.id, permission_id: permission.id})
      |> Repo.insert!()
    end)

    %UserRole{}
    |> UserRole.changeset(%{
      user_id: user.id,
      role_id: role.id,
      granted_at: DateTime.utc_now() |> DateTime.truncate(:microsecond)
    })
    |> Repo.insert!()

    RBAC.invalidate_cache(user)
  end
end
