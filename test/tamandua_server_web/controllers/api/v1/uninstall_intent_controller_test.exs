defmodule TamanduaServerWeb.API.V1.UninstallIntentControllerTest do
  use TamanduaServerWeb.ConnCase, async: false

  alias TamanduaServer.Accounts
  alias TamanduaServer.Accounts.{Role, UserRole}
  alias TamanduaServer.Agents.{AgentUninstallBreakglassIssuance, TokenManager}
  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant

  setup %{conn: conn} do
    organization = insert(:organization)
    admin = insert(:user, organization: organization)
    viewer = insert(:user, organization: organization)
    agent = insert(:agent, organization: organization)

    role =
      Repo.insert!(%Role{
        name: "Uninstall intent admin",
        slug: "admin",
        builtin: true,
        priority: 100,
        organization_id: organization.id
      })

    Repo.insert!(%UserRole{
      user_id: admin.id,
      role_id: role.id,
      granted_at: DateTime.utc_now() |> DateTime.truncate(:microsecond)
    })

    {:ok, agent_jwt, token_record} = TokenManager.issue_token(agent.id, organization.id)

    base =
      conn
      |> put_req_header("accept", "application/json")
      |> put_req_header("content-type", "application/json")

    admin_conn =
      base
      |> put_req_header("authorization", "Bearer #{Accounts.generate_api_token(admin)}")
      |> assign(:current_user, admin)
      |> assign(:current_organization_id, organization.id)

    viewer_conn =
      base
      |> put_req_header("authorization", "Bearer #{Accounts.generate_api_token(viewer)}")
      |> assign(:current_user, viewer)
      |> assign(:current_organization_id, organization.id)

    %{
      conn: viewer_conn,
      admin_conn: admin_conn,
      agent: agent,
      organization: organization,
      agent_jwt: agent_jwt,
      token_generation: token_record.token_generation
    }
  end

  test "offline break-glass issuance requires agents_uninstall and remains no-store", %{
    conn: conn,
    agent: agent
  } do
    response =
      post(conn, "/api/v1/agents/#{agent.id}/uninstall-breakglass", %{
        "reason" => "Approved maintenance window",
        "platform" => "windows",
        "consumer" => "windows_msi"
      })

    assert %{"required_permission" => "agents_uninstall"} = json_response(response, 403)
    assert get_resp_header(response, "cache-control") == ["no-store"]
  end

  test "offline break-glass is tenant-bound and does not reflect request material", %{
    admin_conn: admin_conn
  } do
    configure_breakglass_key!()
    other_organization = insert(:organization)
    other_agent = insert(:agent, organization: other_organization)
    sentinel = "Cross tenant breakglass sentinel"

    response =
      post(admin_conn, "/api/v1/agents/#{other_agent.id}/uninstall-breakglass", %{
        "reason" => sentinel,
        "platform" => "linux",
        "consumer" => "native_cli"
      })

    assert %{"error" => %{"code" => "uninstall_breakglass_agent_not_found"}} =
             json_response(response, 404)

    refute response.resp_body =~ sentinel
    assert get_resp_header(response, "cache-control") == ["no-store"]
  end

  test "offline break-glass fails closed with a stable no-store category when signer is absent", %{
    admin_conn: admin_conn,
    agent: agent
  } do
    env = "TAMANDUA_UNINSTALL_BREAKGLASS_ED25519_PRIVATE_KEYS_JSON"
    previous = System.get_env(env)
    System.delete_env(env)

    on_exit(fn ->
      if previous, do: System.put_env(env, previous), else: System.delete_env(env)
    end)

    response =
      post(admin_conn, "/api/v1/agents/#{agent.id}/uninstall-breakglass", %{
        "reason" => "Approved maintenance window",
        "platform" => "linux",
        "consumer" => "native_cli"
      })

    assert %{"error" => %{"code" => "uninstall_breakglass_signer_unavailable"}} =
             json_response(response, 503)

    assert get_resp_header(response, "cache-control") == ["no-store"]
  end

  test "offline break-glass rejects unknown fields before signing without reflection", %{
    admin_conn: admin_conn,
    agent: agent
  } do
    sentinel = "Unknown breakglass request sentinel"

    response =
      post(admin_conn, "/api/v1/agents/#{agent.id}/uninstall-breakglass", %{
        "reason" => "Approved maintenance window",
        "platform" => "linux",
        "consumer" => "native_cli",
        "private_key" => sentinel
      })

    assert %{"error" => %{"code" => "uninstall_breakglass_request_invalid"}} =
             json_response(response, 400)

    refute response.resp_body =~ sentinel
    assert get_resp_header(response, "cache-control") == ["no-store"]
  end

  test "offline break-glass rejects windows_msi bound to a non-Windows platform", %{
    admin_conn: admin_conn,
    agent: agent,
    organization: organization
  } do
    response =
      post(admin_conn, "/api/v1/agents/#{agent.id}/uninstall-breakglass", %{
        "reason" => "Approved maintenance window",
        "platform" => "linux",
        "consumer" => "windows_msi"
      })

    assert %{"error" => %{"code" => "uninstall_breakglass_request_invalid"}} =
             json_response(response, 400)

    assert get_resp_header(response, "cache-control") == ["no-store"]
    refute MultiTenant.with_organization(organization.id, fn ->
             Repo.exists?(AgentUninstallBreakglassIssuance)
           end)
  end

  test "offline break-glass emits exact envelope after append-only authoritative issuance", %{
    admin_conn: admin_conn,
    agent: agent,
    organization: organization
  } do
    seed = configure_breakglass_key!()

    response =
      post(admin_conn, "/api/v1/agents/#{agent.id}/uninstall-breakglass", %{
        "reason" => "Approved maintenance window",
        "platform" => "windows",
        "consumer" => "windows_msi",
        "ttl_seconds" => 3_600
      })

    assert response.status == 201
    assert get_resp_header(response, "cache-control") == ["no-store"]
    assert String.starts_with?(response.resp_body, ~s({"payload":"))
    assert response.resp_body =~ ~s(","signature":")

    %{"payload" => encoded_payload, "signature" => encoded_signature} =
      Jason.decode!(response.resp_body)

    {:ok, payload_bytes} = Base.url_decode64(encoded_payload, padding: false)
    {:ok, signature} = Base.url_decode64(encoded_signature, padding: false)
    payload = Jason.decode!(payload_bytes)

    assert payload["organization_id"] == organization.id
    assert payload["agent_id"] == agent.id
    assert payload["authorization_mode"] == "offline_breakglass"
    assert payload["consumer"] == "windows_msi"
    assert payload["platform"] == "windows"
    assert payload["reason"] == "Approved maintenance window"
    assert DateTime.diff(parse_time!(payload["expires_at"]), parse_time!(payload["issued_at"])) ==
             3_600

    {public_key, _derived_private} = :crypto.generate_key(:eddsa, :ed25519, seed)

    assert :crypto.verify(
             :eddsa,
             :none,
             TamanduaServer.Agents.UninstallBreakglass.domain_prefix() <> payload_bytes,
             signature,
             [public_key, :ed25519]
           )

    issuance =
      MultiTenant.with_organization(organization.id, fn ->
        Repo.get_by!(AgentUninstallBreakglassIssuance,
          organization_id: organization.id,
          agent_id: agent.id,
          intent_id: payload["intent_id"]
        )
      end)

    assert issuance.issued_by_user_id == payload["issued_by_user_id"]
    assert issuance.reason == payload["reason"]
    assert issuance.key_id == payload["key_id"]
    assert issuance.platform == payload["platform"]
    assert issuance.consumer == payload["consumer"]
    assert byte_size(issuance.payload_sha256) == 32
    assert byte_size(issuance.nonce_sha256) == 32
    refute inspect(issuance) =~ encoded_payload
    refute inspect(issuance) =~ encoded_signature
    refute inspect(issuance) =~ payload["nonce"]
  end

  test "issuance requires the dedicated agents_uninstall permission", %{conn: conn, agent: agent} do
    response =
      post(conn, "/api/v1/agents/#{agent.id}/uninstall-intents", %{
        "reason" => "operator_requested"
      })

    assert %{"required_permission" => "agents_uninstall"} = json_response(response, 403)
    assert get_resp_header(response, "cache-control") == ["no-store"]
  end

  test "consume requires an agent bearer and returns only a stable category" do
    nonce = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

    response =
      post(build_conn(), "/api/v1/agents/uninstall-intents/consume", %{
        "nonce" => nonce,
        "verifier_version" => "uninstall_intent_v1",
        "platform" => "windows",
        "consumer" => "native_cli"
      })

    assert %{"error" => %{"code" => "uninstall_intent_unauthorized"}} =
             json_response(response, 401)

    assert get_resp_header(response, "cache-control") == ["no-store"]
    refute response.resp_body =~ nonce
  end

  test "consume rejects extra fields before authentication without reflection" do
    sentinel = "loop66-secret-reflection-sentinel"

    response =
      post(build_conn(), "/api/v1/agents/uninstall-intents/consume", %{
        "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
        "verifier_version" => "uninstall_intent_v1",
        "platform" => "linux",
        "consumer" => "native_cli",
        "unexpected" => sentinel
      })

    assert %{"error" => %{"code" => "uninstall_intent_request_invalid"}} =
             json_response(response, 400)

    refute response.resp_body =~ sentinel
    assert get_resp_header(response, "cache-control") == ["no-store"]
  end

  test "successful issue, idempotent replay, conflict and consume return exact no-store receipt", %{
    admin_conn: admin_conn,
    agent: agent,
    organization: organization,
    agent_jwt: agent_jwt,
    token_generation: token_generation
  } do
    issue_body = %{
      "reason" => "operator_requested",
      "idempotency_key" => "controller-idempotency-0001"
    }

    created = post(admin_conn, "/api/v1/agents/#{agent.id}/uninstall-intents", issue_body)
    created_data = json_response(created, 201)["data"]
    assert created_data["state"] == "pending"
    assert get_resp_header(created, "cache-control") == ["no-store"]

    replay = post(admin_conn, "/api/v1/agents/#{agent.id}/uninstall-intents", issue_body)
    assert json_response(replay, 200)["data"]["id"] == created_data["id"]
    assert get_resp_header(replay, "cache-control") == ["no-store"]

    conflict =
      post(admin_conn, "/api/v1/agents/#{agent.id}/uninstall-intents", %{
        "reason" => "incident_response",
        "idempotency_key" => issue_body["idempotency_key"]
      })

    assert %{"error" => %{"code" => "uninstall_intent_idempotency_conflict"}} =
             json_response(conflict, 409)

    nonce = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

    consumed =
      build_conn()
      |> put_req_header("authorization", "Bearer #{agent_jwt}")
      |> post("/api/v1/agents/uninstall-intents/consume", %{
        "nonce" => nonce,
        "verifier_version" => "uninstall_intent_v1",
        "platform" => "windows",
        "consumer" => "native_cli"
      })

    receipt = json_response(consumed, 200)["data"]

    assert receipt == %{
             "id" => created_data["id"],
             "organization_id" => organization.id,
             "agent_id" => agent.id,
             "action" => "agent_uninstall",
             "state" => "consumed",
             "expires_at" => created_data["expires_at"],
             "consumed_at" => receipt["consumed_at"],
             "nonce" => nonce,
             "token_generation" => token_generation,
             "verifier_version" => "uninstall_intent_v1",
             "platform" => "windows",
             "consumer" => "native_cli"
           }

    assert get_resp_header(consumed, "cache-control") == ["no-store"]

    consumed_replay =
      post(admin_conn, "/api/v1/agents/#{agent.id}/uninstall-intents", issue_body)

    assert %{"error" => %{"code" => "uninstall_intent_idempotency_conflict"}} =
             json_response(consumed_replay, 409)
  end

  defp configure_breakglass_key! do
    seed = :erlang.list_to_binary(Enum.to_list(0..31))

    keyring =
      Jason.encode!(%{
        "active_key_id" => "breakglass-controller-2026-07",
        "keys" => [
          %{
            "key_id" => "breakglass-controller-2026-07",
            "private_key" => Base.url_encode64(seed, padding: false)
          }
        ]
      })

    previous = System.get_env("TAMANDUA_UNINSTALL_BREAKGLASS_ED25519_PRIVATE_KEYS_JSON")
    System.put_env("TAMANDUA_UNINSTALL_BREAKGLASS_ED25519_PRIVATE_KEYS_JSON", keyring)

    on_exit(fn ->
      if previous,
        do:
          System.put_env(
            "TAMANDUA_UNINSTALL_BREAKGLASS_ED25519_PRIVATE_KEYS_JSON",
            previous
          ),
        else: System.delete_env("TAMANDUA_UNINSTALL_BREAKGLASS_ED25519_PRIVATE_KEYS_JSON")
    end)

    seed
  end

  defp parse_time!(value) do
    {:ok, timestamp, 0} = DateTime.from_iso8601(value)
    timestamp
  end
end
