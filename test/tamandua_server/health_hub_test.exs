defmodule TamanduaServer.HealthHubTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.HealthHub
  alias TamanduaServer.LiveResponse.EvidenceSession
  alias TamanduaServer.Repo

  test "ignores telemetry timestamps beyond the allowed future clock skew" do
    {org, agent} = create_agent_with_org()

    insert!(:event, %{
      agent: agent,
      organization_id: org.id,
      event_type: "dns_query",
      created_at: DateTime.utc_now() |> DateTime.to_naive() |> NaiveDateTime.truncate(:second),
      timestamp: DateTime.add(DateTime.utc_now(), 86_400, :second)
    })

    summary = HealthHub.summary(org.id)
    parser = item(summary, "parser_ingest")
    dns = item(summary, "dns_collector")

    assert parser.status == "degraded"
    assert parser.last_seen == nil
    assert parser.metrics.events_in_window == 0
    assert dns.status == "not_configured"
  end

  test "uses only recent valid telemetry for counts and last seen" do
    {org, agent} = create_agent_with_org()
    recent = DateTime.add(DateTime.utc_now(), -60, :second)

    insert!(:event, %{
      agent: agent,
      organization_id: org.id,
      event_type: "dns_query",
      created_at: DateTime.utc_now() |> DateTime.to_naive() |> NaiveDateTime.truncate(:second),
      timestamp: recent
    })

    insert!(:event, %{
      agent: agent,
      organization_id: org.id,
      event_type: "dns_query",
      created_at: DateTime.utc_now() |> DateTime.to_naive() |> NaiveDateTime.truncate(:second),
      timestamp: DateTime.add(DateTime.utc_now(), 86_400, :second)
    })

    summary = HealthHub.summary(org.id)
    parser = item(summary, "parser_ingest")
    dns = item(summary, "dns_collector")

    assert parser.status == "healthy"
    assert parser.metrics.events_in_window == 1
    assert parser.last_seen == DateTime.to_iso8601(recent)
    assert dns.status == "healthy"
    assert dns.metrics.events_in_window == 1
  end

  test "serializes naive agent heartbeat timestamps explicitly as UTC" do
    {org, agent} = create_agent_with_org()

    summary = HealthHub.summary(org.id)
    endpoint = item(summary, "endpoint_agents")

    assert endpoint.last_seen ==
             agent.last_seen_at
             |> DateTime.from_naive!("Etc/UTC")
             |> DateTime.to_iso8601()
  end

  test "reports evidence-session outcomes and latency by observed platform" do
    {org, agent} = create_agent_with_org()
    now = DateTime.utc_now()

    insert_evidence_session!(org.id, agent.id, %{
      status: "completed",
      platform: "windows",
      started_at: DateTime.add(now, -4, :second),
      completed_at: now
    })

    insert_evidence_session!(org.id, agent.id, %{
      status: "failed",
      platform: "linux",
      started_at: DateTime.add(now, -2, :second),
      completed_at: now
    })

    evidence = HealthHub.summary(org.id) |> item("evidence_sessions")

    assert evidence.status == "degraded"
    assert evidence.coverage.covered == 1
    assert evidence.coverage.total == 2
    assert evidence.metrics.requested == 2
    assert evidence.metrics.completed == 1
    assert evidence.metrics.failed == 1
    assert evidence.metrics.completion_percent == 50.0
    assert evidence.metrics.average_latency_ms >= 2_000
    assert evidence.metrics.by_platform["windows"].completed == 1
    assert evidence.metrics.by_platform["linux"].failed == 1
  end

  defp insert_evidence_session!(organization_id, agent_id, attrs) do
    platform = Map.fetch!(attrs, :platform)
    status = Map.fetch!(attrs, :status)

    session =
      %EvidenceSession{}
      |> EvidenceSession.create_changeset(%{
        organization_id: organization_id,
        agent_id: agent_id,
        status: status,
        reason: "Health Hub operational metrics test",
        capture_request: %{"platform" => platform},
        frame_count: 2,
        interval_seconds: 5,
        expires_at: DateTime.add(DateTime.utc_now(), 300, :second),
        approval_status: "not_required"
      })
      |> Repo.insert!()

    session
    |> Ecto.Changeset.change(
      started_at: attrs.started_at,
      completed_at: attrs.completed_at,
      failure_reason: if(status == "failed", do: "test_failure")
    )
    |> Repo.update!()
  end

  defp item(summary, id), do: Enum.find(summary.items, &(&1.id == id))
end
