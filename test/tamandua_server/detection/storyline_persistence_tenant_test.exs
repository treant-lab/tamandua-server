defmodule TamanduaServer.Detection.StorylinePersistenceTenantTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Detection.{StorylinePersistence, StorylineRecord}

  test "DB recovery rebuilds PID mappings with organization in the key" do
    organization = insert!(:organization)
    other_organization = insert!(:organization)
    agent = insert!(:agent, organization: organization)
    storyline_id = Ecto.UUID.generate()
    pid = 42_424
    now = DateTime.utc_now()

    StorylineRecord.upsert!(%{
      id: storyline_id,
      agent_id: agent.id,
      organization_id: organization.id,
      status: "active",
      severity: "high",
      total_score: 75.0,
      process_pids: [pid],
      first_seen_at: now,
      last_seen_at: now
    })

    :ets.delete(:tamandua_storylines, storyline_id)
    :ets.delete(:tamandua_pid_to_storyline, {organization.id, agent.id, pid})

    persistence = Process.whereis(StorylinePersistence)
    assert is_pid(persistence)

    send(persistence, :recover)
    state = :sys.get_state(persistence)
    assert state.recovered >= 1

    assert [{{organization_id, agent_id, ^pid}, ^storyline_id}] =
             :ets.lookup(:tamandua_pid_to_storyline, {organization.id, agent.id, pid})

    assert organization_id == organization.id
    assert agent_id == agent.id

    assert [] =
             :ets.lookup(
               :tamandua_pid_to_storyline,
               {other_organization.id, agent.id, pid}
             )
  end
end
