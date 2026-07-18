defmodule TamanduaServer.FleetQueriesTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Agents.{AgentCommand, Registry}
  alias TamanduaServer.FleetQueries
  alias TamanduaServer.Repo

  describe "create_osquery_run/3" do
    test "persists a run, queues osquery commands, and records skipped targets" do
      org = insert!(:organization)
      capable = insert!(:agent, organization: org, hostname: "capable-1", os_type: "linux")
      unsupported = insert!(:agent, organization: org, hostname: "unsupported-1", os_type: "linux")

      register_agent(capable, ["live_response", "osquery_query"])
      register_agent(unsupported, ["live_response"])

      assert {:ok, run} =
               FleetQueries.create_osquery_run(org.id, %{
                 "query" => "select pid, name from processes limit 5;",
                 "max_rows" => 5
               })

      assert run.organization_id == org.id
      assert run.status == "running"
      assert run.target_count == 2
      assert run.queued_count == 1
      assert run.skipped_count == 1

      assert {:ok, targets} = FleetQueries.list_targets(org.id, run.id)
      assert targets |> Enum.map(& &1.hostname) |> Enum.sort() == ["capable-1", "unsupported-1"]

      queued = Enum.find(targets, &(&1.agent_id == capable.id))
      skipped = Enum.find(targets, &(&1.agent_id == unsupported.id))

      assert queued.status == "queued"
      assert queued.agent_command_id
      assert skipped.status == "skipped"
      assert skipped.skip_reason == "missing_osquery_capability"

      command = Repo.get!(AgentCommand, queued.agent_command_id)
      assert command.command_type == "osquery_query"
      assert command.command_params["query"] == "select pid, name from processes limit 5;"
      assert command.command_params["fleet_query_run_id"] == run.id
    end

    test "refreshes target and run status from completed agent commands" do
      org = insert!(:organization)
      agent = insert!(:agent, organization: org, hostname: "query-host", os_type: "windows")
      register_agent(agent, ["osquery_query"])

      assert {:ok, run} =
               FleetQueries.create_osquery_run(org.id, %{
                 "query" => "select * from os_version;",
                 "agent_ids" => [agent.id]
               })

      assert {:ok, [target]} = FleetQueries.list_targets(org.id, run.id)
      command = Repo.get!(AgentCommand, target.agent_command_id)

      command
      |> AgentCommand.mark_completed(%{"rows" => [%{"name" => "Windows"}]})
      |> Repo.update!()

      refreshed = FleetQueries.refresh_run!(run.id)
      assert refreshed.status == "completed"
      assert refreshed.completed_count == 1
      assert refreshed.queued_count == 0

      assert {:ok, [target]} = FleetQueries.list_targets(org.id, run.id)
      assert target.status == "completed"
      assert target.result_summary["row_count"] == 1
    end

    test "cancels only targets whose commands have not been dispatched" do
      org = insert!(:organization)
      pending_agent = insert!(:agent, organization: org, hostname: "pending-host", os_type: "linux")
      sent_agent = insert!(:agent, organization: org, hostname: "sent-host", os_type: "linux")
      register_agent(pending_agent, ["osquery_query"])
      register_agent(sent_agent, ["osquery_query"])

      assert {:ok, run} =
               FleetQueries.create_osquery_run(org.id, %{
                 "query" => "select * from processes limit 10;",
                 "agent_ids" => [pending_agent.id, sent_agent.id]
               })

      assert {:ok, targets} = FleetQueries.list_targets(org.id, run.id)
      sent_target = Enum.find(targets, &(&1.agent_id == sent_agent.id))

      AgentCommand
      |> Repo.get!(sent_target.agent_command_id)
      |> AgentCommand.mark_sent()
      |> Repo.update!()

      assert {:ok, refreshed_run, result} = FleetQueries.cancel_run(org.id, run.id)

      assert length(result.cancelled) == 1
      assert length(result.already_sent) == 1
      assert refreshed_run.status == "running"
      assert refreshed_run.failed_count == 1
      assert refreshed_run.queued_count == 1

      assert {:ok, targets} = FleetQueries.list_targets(org.id, run.id)
      cancelled_target = Enum.find(targets, &(&1.agent_id == pending_agent.id))
      already_sent_target = Enum.find(targets, &(&1.agent_id == sent_agent.id))

      assert cancelled_target.status == "failed"
      assert cancelled_target.error == "Cancelled by user"
      assert already_sent_target.status == "sent"
    end

    test "caps fleet fan-out and records targets skipped by max target guardrail" do
      org = insert!(:organization)
      agent_1 = insert!(:agent, organization: org, hostname: "query-1", os_type: "linux")
      agent_2 = insert!(:agent, organization: org, hostname: "query-2", os_type: "linux")
      agent_3 = insert!(:agent, organization: org, hostname: "query-3", os_type: "linux")

      Enum.each([agent_1, agent_2, agent_3], &register_agent(&1, ["osquery_query"]))

      assert {:ok, run} =
               FleetQueries.create_osquery_run(org.id, %{
                 "query" => "select * from os_version;",
                 "max_targets" => 1
               })

      assert run.status == "running"
      assert run.target_count == 3
      assert run.queued_count == 1
      assert run.skipped_count == 2
      assert run.options["max_targets"] == 1

      assert {:ok, targets} = FleetQueries.list_targets(org.id, run.id)
      assert Enum.count(targets, &(&1.status == "queued")) == 1

      skipped_reasons =
        targets
        |> Enum.filter(&(&1.status == "skipped"))
        |> Enum.map(& &1.skip_reason)

      assert skipped_reasons == ["max_targets_exceeded", "max_targets_exceeded"]
    end

    test "marks expired non-terminal commands as failed during refresh" do
      org = insert!(:organization)
      agent = insert!(:agent, organization: org, hostname: "expired-host", os_type: "linux")
      register_agent(agent, ["osquery_query"])

      assert {:ok, run} =
               FleetQueries.create_osquery_run(org.id, %{
                 "query" => "select * from processes limit 1;",
                 "agent_ids" => [agent.id]
               })

      assert {:ok, [target]} = FleetQueries.list_targets(org.id, run.id)
      command = Repo.get!(AgentCommand, target.agent_command_id)

      expired_at =
        AgentCommand.utc_now_second()
        |> DateTime.add(-60, :second)

      command
      |> Ecto.Changeset.change(expires_at: expired_at)
      |> Repo.update!()

      refreshed = FleetQueries.refresh_run!(run.id)

      assert refreshed.status == "completed_with_errors"
      assert refreshed.failed_count == 1
      assert refreshed.queued_count == 0

      assert {:ok, [target]} = FleetQueries.list_targets(org.id, run.id)
      assert target.status == "failed"
      assert target.error == "Command expired before completion"
      assert target.completed_at

      command = Repo.get!(AgentCommand, command.id)
      assert command.status == "failed"
      assert command.error == "Command expired before completion"
    end

    test "does not expose runs across organizations" do
      org_a = insert!(:organization)
      org_b = insert!(:organization)
      agent = insert!(:agent, organization: org_a, hostname: "tenant-a-host")
      register_agent(agent, ["osquery_query"])

      assert {:ok, run} =
               FleetQueries.create_osquery_run(org_a.id, %{
                 "query" => "select * from os_version;"
               })

      assert {:error, :not_found} = FleetQueries.get_run(org_b.id, run.id)
      assert {:error, :not_found} = FleetQueries.list_targets(org_b.id, run.id)
    end
  end

  defp register_agent(agent, capabilities) do
    Registry.register(agent.id, %{
      hostname: agent.hostname,
      os_type: agent.os_type,
      organization_id: agent.organization_id,
      worker_pid: self(),
      capabilities: capabilities
    })
  end
end
