defmodule TamanduaServerWeb.InertiaResponseControllerTest do
  use TamanduaServerWeb.ConnCase, async: true

  alias TamanduaServer.Accounts
  alias TamanduaServer.Response
  alias TamanduaServer.ShellSessions

  describe "GET /app/response" do
    test "returns recent response actions only for the signed-in user's organization", %{conn: conn} do
      org_a = insert!(:organization)
      org_b = insert!(:organization)
      user_a = insert!(:user, organization: org_a)
      agent_a = insert!(:agent, organization: org_a)
      agent_b = insert!(:agent, organization: org_b)

      {:ok, action_a} =
        Response.create_action(%{
          agent_id: agent_a.id,
          action_type: "scan_path",
          organization_id: org_a.id,
          status: "success"
        })

      {:ok, action_b} =
        Response.create_action(%{
          agent_id: agent_b.id,
          action_type: "kill_process",
          organization_id: org_b.id,
          status: "success"
        })

      props = conn |> log_in_user(user_a) |> inertia_get_response_props()
      action_ids = Enum.map(props["recentActions"], & &1["id"])

      assert action_a.id in action_ids
      refute action_b.id in action_ids
    end

    test "fails closed with no recent actions when the signed-in user has no organization", %{
      conn: conn
    } do
      org = insert!(:organization)
      agent = insert!(:agent, organization: org)
      user_without_org = insert!(:user, organization: nil, organization_id: nil)

      {:ok, _action} =
        Response.create_action(%{
          agent_id: agent.id,
          action_type: "scan_path",
          organization_id: org.id,
          status: "success"
        })

      props = conn |> log_in_user(user_without_org) |> inertia_get_response_props()

      assert props["recentActions"] == []
    end
  end

  describe "GET /app/live-response" do
    test "returns recent shell sessions only for the signed-in user's organization", %{conn: conn} do
      org_a = insert!(:organization)
      org_b = insert!(:organization)
      user_a = insert!(:user, organization: org_a)
      user_b = insert!(:user, organization: org_b)
      agent_a = insert!(:agent, organization: org_a)
      agent_b = insert!(:agent, organization: org_b)

      {:ok, session_a} =
        ShellSessions.create_session(%{
          session_id: "shell-org-a",
          user_id: user_a.id,
          agent_id: agent_a.id,
          started_at: DateTime.utc_now() |> DateTime.truncate(:second)
        })

      {:ok, session_b} =
        ShellSessions.create_session(%{
          session_id: "shell-org-b",
          user_id: user_b.id,
          agent_id: agent_b.id,
          started_at: DateTime.utc_now() |> DateTime.truncate(:second)
        })

      props = conn |> log_in_user(user_a) |> inertia_get_live_response_props()
      session_ids = Enum.map(props["recentSessions"], & &1["id"])

      assert session_a.id in session_ids
      refute session_b.id in session_ids
    end

    test "does not starve tenant sessions behind newer cross-tenant sessions", %{conn: conn} do
      org_a = insert!(:organization)
      org_b = insert!(:organization)
      user_a = insert!(:user, organization: org_a)
      user_b = insert!(:user, organization: org_b)
      agent_a = insert!(:agent, organization: org_a)
      agent_b = insert!(:agent, organization: org_b)
      now = DateTime.utc_now() |> DateTime.truncate(:second)

      {:ok, session_a} =
        ShellSessions.create_session(%{
          session_id: "shell-org-a-starvation",
          user_id: user_a.id,
          agent_id: agent_a.id,
          started_at: DateTime.add(now, -120, :second)
        })

      for index <- 1..60 do
        {:ok, _session_b} =
          ShellSessions.create_session(%{
            session_id: "shell-org-b-newer-#{index}",
            user_id: user_b.id,
            agent_id: agent_b.id,
            started_at: DateTime.add(now, index, :second)
          })
      end

      props = conn |> log_in_user(user_a) |> inertia_get_live_response_props()
      session_ids = Enum.map(props["recentSessions"], & &1["id"])

      assert session_a.id in session_ids
    end

    test "does not expose a selected cross-tenant agent", %{conn: conn} do
      org_a = insert!(:organization)
      org_b = insert!(:organization)
      user_a = insert!(:user, organization: org_a)
      agent_b = insert!(:agent, organization: org_b)

      props = conn |> log_in_user(user_a) |> inertia_get_live_response_props(agent_b.id)

      assert props["selectedAgent"] == nil
      assert props["agents"] == []
      assert props["recentSessions"] == []
      assert props["error"] == "Agent not found or offline"
    end
  end

  defp log_in_user(conn, user) do
    token = Accounts.generate_user_session_token(user)

    conn
    |> init_test_session(%{})
    |> put_session(:user_token, token)
  end

  defp inertia_get_response_props(conn) do
    conn
    |> put_req_header("x-inertia", "true")
    |> get("/app/response")
    |> json_response(200)
    |> Map.fetch!("props")
  end

  defp inertia_get_live_response_props(conn, agent_id \\ nil) do
    path = if agent_id, do: "/app/live-response/#{agent_id}", else: "/app/live-response"

    conn
    |> put_req_header("x-inertia", "true")
    |> get(path)
    |> json_response(200)
    |> Map.fetch!("props")
  end
end
