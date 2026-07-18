defmodule TamanduaServerWeb.API.V1.AgentControllerSecurityTest do
  use TamanduaServerWeb.ConnCase

  import TamanduaServer.Factory

  alias TamanduaServer.Accounts.{Role, UserRole}
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Repo

  setup %{conn: conn} do
    org = insert(:organization)
    user = insert(:user, organization_id: org.id)
    viewer = insert(:user, organization_id: org.id)

    admin_role =
      Repo.insert!(%Role{
        name: ~s(Agent security test admin),
        slug: ~s(admin),
        builtin: true,
        priority: 100,
        organization_id: org.id
      })

    Repo.insert!(%UserRole{
      user_id: user.id,
      role_id: admin_role.id,
      granted_at: DateTime.utc_now() |> DateTime.truncate(:microsecond)
    })

    agent =
      insert(:agent,
        organization_id: org.id,
        certificate_fingerprint: ~s(trusted-fingerprint),
        certificate_subject: ~s(trusted-subject),
        token_rotation_enabled: true,
        token_ttl_hours: 720,
        token_refresh_window_percent: 60,
        current_token_generation: 7
      )

    conn =
      conn
      |> put_req_header(~s(accept), ~s(application/json))
      |> put_req_header(~s(content-type), ~s(application/json))
      |> assign(:current_organization_id, org.id)
      |> assign(:current_user, user)

    viewer_conn = assign(conn, :current_user, viewer)

    {:ok, conn: conn, viewer_conn: viewer_conn, org: org, agent: agent}
  end

  test ~s(update requires agents_update), %{viewer_conn: conn, agent: agent} do
    response =
      put(conn, ~s(/api/v1/agents/#{agent.id}), %{
        ~s(hostname) => ~s(unauthorized-hostname)
      })

    assert %{
             ~s(error) => ~s(forbidden),
             ~s(required_permission) => ~s(agents_update)
           } = json_response(response, 403)

    assert Repo.get!(Agent, agent.id).hostname == agent.hostname
  end

  test ~s(delete requires agents_delete), %{viewer_conn: conn, agent: agent} do
    response = delete(conn, ~s(/api/v1/agents/#{agent.id}))

    assert %{
             ~s(error) => ~s(forbidden),
             ~s(required_permission) => ~s(agents_delete)
           } = json_response(response, 403)

    assert Repo.get!(Agent, agent.id)
  end

  test ~s(public update ignores tenant identity credential and runtime fields), %{
    conn: conn,
    agent: agent
  } do
    other_org = insert(:organization)

    response =
      put(conn, ~s(/api/v1/agents/#{agent.id}), %{
        ~s(hostname) => ~s(renamed-endpoint),
        ~s(status) => ~s(isolated),
        ~s(config) => %{~s(log_level) => ~s(off)},
        ~s(organization_id) => other_org.id,
        ~s(machine_id) => ~s(attacker-machine),
        ~s(last_seen_at) => ~s(2035-01-01T00:00:00),
        ~s(isolation_status) => %{~s(state) => ~s(disabled)},
        ~s(certificate_fingerprint) => ~s(attacker-fingerprint),
        ~s(certificate_subject) => ~s(attacker-subject),
        ~s(token_rotation_enabled) => false,
        ~s(token_ttl_hours) => 1,
        ~s(token_refresh_window_percent) => 1,
        ~s(current_token_generation) => 1
      })

    assert %{~s(data) => %{~s(hostname) => ~s(renamed-endpoint)}} =
             json_response(response, 200)

    updated = Repo.get!(Agent, agent.id)
    assert updated.hostname == ~s(renamed-endpoint)
    assert updated.status == agent.status
    assert updated.config == agent.config
    assert updated.organization_id == agent.organization_id
    assert updated.machine_id == agent.machine_id
    assert updated.last_seen_at == agent.last_seen_at
    assert updated.isolation_status == agent.isolation_status
    assert updated.certificate_fingerprint == ~s(trusted-fingerprint)
    assert updated.certificate_subject == ~s(trusted-subject)
    assert updated.token_rotation_enabled
    assert updated.token_ttl_hours == 720
    assert updated.token_refresh_window_percent == 60
    assert updated.current_token_generation == 7
  end

  test ~s(show retains the latest AI discovery runtime beyond the recent event window), %{
    conn: conn,
    org: org,
    agent: agent
  } do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    insert(:event,
      agent: agent,
      organization_id: org.id,
      event_type: ~s(ai_discovery),
      timestamp: DateTime.add(now, -120, :second),
      payload: %{
        ~s(ai_discovery) => true,
        ~s(runtime_lane) => ~s(local_service),
        ~s(model_contract_id) => ~s(tamandua.byte-histogram-256.v1),
        ~s(decision_mode) => ~s(detect_only),
        ~s(model_observations) => [
          %{
            ~s(detector_id) => ~s(lightgbm_local),
            ~s(status) => ~s(completed),
            ~s(score) => 0.2,
            ~s(threshold_met) => false,
            ~s(runtime_lane) => ~s(local_service),
            ~s(model_contract_id) => ~s(tamandua.byte-histogram-256.v1)
          }
        ]
      }
    )

    for offset <- 1..25 do
      insert(:event,
        agent: agent,
        organization_id: org.id,
        event_type: ~s(process_start),
        timestamp: DateTime.add(now, -offset, :second),
        payload: %{}
      )
    end

    response = conn |> get(~s(/api/v1/agents/#{agent.id})) |> json_response(200)

    assert length(response[~s(data)][~s(events)]) == 20

    assert [observation] =
             response[~s(data)][~s(model_scan_runtime)][~s(model_observations)]

    assert observation[~s(detector_id)] == ~s(lightgbm_local)
    assert observation[~s(threshold_met)] == false
    assert observation[~s(claim_boundary)] == ~s(shadow_observation_no_verdict)
    refute Map.has_key?(observation, ~s(decision))
  end
end
