defmodule TamanduaServer.Investigations.StorylinePubSubTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Investigations.Storyline
  alias TamanduaServerWeb.Broadcaster

  setup do
    for table <- [
          :investigation_story_events,
          :investigation_story_index,
          :investigation_stories
        ] do
      :ets.delete_all_objects(table)
    end

    :ok
  end

  test "the production alert broadcast auto-correlates under the canonical database tenant" do
    organization = insert!(:organization)
    agent = insert!(:agent, organization: organization)

    alert =
      insert!(:alert, %{
        organization: organization,
        organization_id: organization.id,
        agent: agent,
        agent_id: agent.id,
        raw_event: %{}
      })

    Broadcaster.broadcast_new_alert(alert)

    assert_eventually(fn ->
      case Storyline.get_active_stories(organization.id, []) do
        {:ok, [%{organization_id: organization_id, alert_ids: alert_ids}]} ->
          organization_id == organization.id and alert.id in alert_ids

        _ ->
          false
      end
    end)
  end

  defp assert_eventually(predicate, attempts \\ 50)

  defp assert_eventually(predicate, attempts) when attempts > 0 do
    if predicate.() do
      :ok
    else
      Process.sleep(20)
      assert_eventually(predicate, attempts - 1)
    end
  end

  defp assert_eventually(_predicate, 0), do: flunk("condition did not become true")
end
