defmodule TamanduaServer.Agents.CommandDeliveryTest do
  @moduledoc """
  Command-delivery reliability tests:

  - `pending_for_agent/2` offers both "pending" and stranded "sent" commands
    for redelivery on reconnect
  - `dispatch_decision/2` guards redelivery loops (attempt cap + cooldown)
  - worker redelivery marks exhausted commands failed
  - idempotency_key makes command creation retry-safe
  - command reply callbacks live in GenServer state (not the process
    dictionary) and preserve reply semantics
  """

  # async: false so the SQL sandbox runs in shared mode and the Worker
  # GenServer (a separate process) can use the test's DB connection.
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Agents.{AgentCommand, Worker}
  alias TamanduaServer.Repo

  defp unique_agent_id, do: "test-agent-#{System.unique_integer([:positive])}"

  defp now_second, do: DateTime.utc_now() |> DateTime.truncate(:second)

  defp seconds_ago(seconds), do: DateTime.add(now_second(), -seconds, :second)

  defp insert_command!(agent_id, attrs \\ %{}) do
    defaults = %{
      agent_id: agent_id,
      command_type: "kill_process",
      command_params: %{"pid" => 1},
      status: "pending"
    }

    AgentCommand
    |> struct(Map.merge(defaults, Map.new(attrs)))
    |> Repo.insert!()
  end

  defp start_worker(agent_id, socket_pid) do
    org = insert(:organization)

    {:ok, pid} =
      Worker.start_link(
        agent_id: agent_id,
        socket_pid: socket_pid,
        agent_info: %{
          hostname: "test-host",
          os_type: "linux",
          organization_id: org.id
        }
      )

    pid
  end

  defp wait_until(fun, attempts \\ 100)

  defp wait_until(_fun, 0), do: flunk("condition not met in time")

  defp wait_until(fun, attempts) do
    if fun.() do
      :ok
    else
      Process.sleep(20)
      wait_until(fun, attempts - 1)
    end
  end

  describe "AgentCommand.pending_for_agent/2" do
    test "returns pending and sent commands, excludes terminal/acknowledged ones" do
      agent_id = unique_agent_id()

      pending = insert_command!(agent_id, %{status: "pending"})
      sent = insert_command!(agent_id, %{status: "sent"})
      _acked = insert_command!(agent_id, %{status: "acknowledged"})
      _completed = insert_command!(agent_id, %{status: "completed"})
      _failed = insert_command!(agent_id, %{status: "failed"})
      _other_agent = insert_command!(unique_agent_id(), %{status: "pending"})

      results = AgentCommand.pending_for_agent(agent_id) |> Repo.all()

      assert MapSet.new(results, & &1.id) == MapSet.new([pending.id, sent.id])
    end

    test "excludes expired pending and sent commands" do
      agent_id = unique_agent_id()

      fresh = insert_command!(agent_id, %{status: "pending", expires_at: DateTime.add(now_second(), 60, :second)})
      _expired = insert_command!(agent_id, %{status: "sent", expires_at: DateTime.add(now_second(), -60, :second)})

      results = AgentCommand.pending_for_agent(agent_id) |> Repo.all()

      assert Enum.map(results, & &1.id) == [fresh.id]
    end

    test "orders by priority desc then insertion time, and honors the limit" do
      agent_id = unique_agent_id()

      _low = insert_command!(agent_id, %{priority: 1})
      high = insert_command!(agent_id, %{priority: 9, status: "sent"})

      assert [%AgentCommand{id: id}] = AgentCommand.pending_for_agent(agent_id, 1) |> Repo.all()
      assert id == high.id
    end
  end

  describe "AgentCommand.dispatch_decision/2" do
    test "dispatches a fresh command" do
      cmd = %AgentCommand{dispatch_count: 0, last_dispatched_at: nil}
      assert AgentCommand.dispatch_decision(cmd) == :dispatch
    end

    test "dispatches a stale sent command past the cooldown" do
      cmd = %AgentCommand{dispatch_count: 2, last_dispatched_at: seconds_ago(300)}
      assert AgentCommand.dispatch_decision(cmd) == :dispatch
    end

    test "skips a command dispatched within the cooldown window" do
      cmd = %AgentCommand{dispatch_count: 1, last_dispatched_at: seconds_ago(5)}
      assert AgentCommand.dispatch_decision(cmd) == :skip_recently_dispatched
    end

    test "fails a command at the attempt cap" do
      cmd = %AgentCommand{dispatch_count: 5, last_dispatched_at: seconds_ago(300)}
      assert {:fail, reason} = AgentCommand.dispatch_decision(cmd)
      assert reason =~ "Dispatch limit reached"
    end

    test "honors option overrides" do
      cmd = %AgentCommand{dispatch_count: 2, last_dispatched_at: seconds_ago(60)}

      assert {:fail, _} = AgentCommand.dispatch_decision(cmd, max_attempts: 2)

      assert AgentCommand.dispatch_decision(cmd, cooldown_seconds: 120) ==
               :skip_recently_dispatched
    end
  end

  describe "AgentCommand.mark_dispatched/1" do
    test "increments dispatch_count, stamps last_dispatched_at, keeps first sent_at" do
      agent_id = unique_agent_id()
      first_sent_at = seconds_ago(600)

      cmd =
        insert_command!(agent_id, %{
          status: "sent",
          sent_at: first_sent_at,
          dispatch_count: 1,
          last_dispatched_at: seconds_ago(600)
        })

      updated = Repo.update!(AgentCommand.mark_dispatched(cmd))

      assert updated.status == "sent"
      assert updated.dispatch_count == 2
      assert DateTime.compare(updated.sent_at, first_sent_at) == :eq
      assert DateTime.diff(now_second(), updated.last_dispatched_at, :second) < 5
    end

    test "sets sent_at on first dispatch of a pending command" do
      cmd = insert_command!(unique_agent_id())

      updated = Repo.update!(AgentCommand.mark_dispatched(cmd))

      assert updated.status == "sent"
      assert updated.dispatch_count == 1
      assert updated.sent_at != nil
      assert updated.last_dispatched_at != nil
    end
  end

  describe "AgentCommand.insert_new/1 creation contract" do
    test "allows auto-investigation process memory network and dns command types" do
      agent_id = unique_agent_id()

      command_types = ~w(
        process_list
        process_tree_list
        process_list_handles
        process_dump
        process_create_dump
        memory_scan
        memory_strings
        network_connections
        dns_cache
        list_loaded_modules
        osquery_query
      )

      for command_type <- command_types do
        assert {:ok, %AgentCommand{} = command} =
                 AgentCommand.insert_new(%{
                   agent_id: agent_id,
                   command_type: command_type,
                   command_params: %{
                     alert_id: "alert-1",
                     process: %{pid: 1234},
                     paths: [%{path: "/tmp/suspect"}]
                   },
                   priority: 8,
                   status: "pending",
                   idempotency_key: "auto-investigation-#{command_type}"
                 })

        assert command.command_type == command_type
        assert command.command_params == %{
                 "alert_id" => "alert-1",
                 "process" => %{"pid" => 1234},
                 "paths" => [%{"path" => "/tmp/suspect"}]
               }
      end
    end

    test "enforces allowed command_type values" do
      attrs = %{
        agent_id: unique_agent_id(),
        command_type: "arbitrary_shell",
        command_params: %{},
        status: "pending"
      }

      assert {:error, changeset} = AgentCommand.insert_new(attrs)
      assert {"is invalid", _} = changeset.errors[:command_type]
    end

    test "persists queue metadata and stringifies command parameter keys" do
      expires_at = DateTime.add(now_second(), 3600, :second)

      attrs = %{
        agent_id: unique_agent_id(),
        command_type: "collect_forensics",
        command_params: %{
          alert_id: "alert-1",
          nested: %{pid: 123},
          artifacts: [%{path: "/tmp/a"}]
        },
        priority: 9,
        status: "pending",
        idempotency_key: "auto-investigation-#{System.unique_integer([:positive])}",
        expires_at: expires_at
      }

      assert {:ok, command} = AgentCommand.insert_new(attrs)
      assert command.command_type == "collect_forensics"
      assert command.priority == 9
      assert command.idempotency_key == attrs.idempotency_key
      assert DateTime.compare(command.expires_at, expires_at) == :eq

      assert command.command_params == %{
               "alert_id" => "alert-1",
               "nested" => %{"pid" => 123},
               "artifacts" => [%{"path" => "/tmp/a"}]
             }
    end

    test "rejects priorities outside the queue range" do
      high_priority_attrs = %{
        agent_id: unique_agent_id(),
        command_type: "process_list",
        command_params: %{},
        priority: 11,
        status: "pending"
      }

      low_priority_attrs = %{high_priority_attrs | priority: -1}

      assert {:error, high_changeset} = AgentCommand.insert_new(high_priority_attrs)
      assert {"must be less than or equal to %{number}", _} = high_changeset.errors[:priority]

      assert {:error, low_changeset} = AgentCommand.insert_new(low_priority_attrs)
      assert {"must be greater than or equal to %{number}", _} = low_changeset.errors[:priority]
    end
  end

  describe "AgentCommand.insert_new/1 idempotency" do
    test "returns the existing command on an idempotency_key conflict" do
      agent_id = unique_agent_id()

      attrs = %{
        agent_id: agent_id,
        command_type: "kill_process",
        command_params: %{"pid" => 42},
        status: "pending",
        idempotency_key: "op-#{System.unique_integer([:positive])}"
      }

      assert {:ok, %AgentCommand{} = original} = AgentCommand.insert_new(attrs)
      assert {:existing, %AgentCommand{id: existing_id}} = AgentCommand.insert_new(attrs)
      assert existing_id == original.id

      assert Repo.aggregate(
               from(c in AgentCommand, where: c.agent_id == ^agent_id),
               :count
             ) == 1
    end

    test "the same key on a different agent creates an independent command" do
      key = "shared-key-#{System.unique_integer([:positive])}"

      base = %{
        command_type: "kill_process",
        command_params: %{},
        status: "pending",
        idempotency_key: key
      }

      assert {:ok, a} = AgentCommand.insert_new(Map.put(base, :agent_id, unique_agent_id()))
      assert {:ok, b} = AgentCommand.insert_new(Map.put(base, :agent_id, unique_agent_id()))
      assert a.id != b.id
    end

    test "commands without an idempotency_key are never deduplicated" do
      agent_id = unique_agent_id()

      attrs = %{
        agent_id: agent_id,
        command_type: "kill_process",
        command_params: %{},
        status: "pending"
      }

      assert {:ok, a} = AgentCommand.insert_new(attrs)
      assert {:ok, b} = AgentCommand.insert_new(attrs)
      assert a.id != b.id
    end
  end

  describe "Worker redelivery on start/reconnect" do
    test "re-delivers pending and stranded sent commands, skips recent, fails exhausted" do
      agent_id = unique_agent_id()

      pending = insert_command!(agent_id, %{status: "pending"})

      stranded_sent =
        insert_command!(agent_id, %{
          status: "sent",
          dispatch_count: 1,
          last_dispatched_at: seconds_ago(300)
        })

      recently_sent =
        insert_command!(agent_id, %{
          status: "sent",
          dispatch_count: 1,
          last_dispatched_at: now_second()
        })

      exhausted =
        insert_command!(agent_id, %{
          status: "sent",
          dispatch_count: 5,
          last_dispatched_at: seconds_ago(300)
        })

      _worker = start_worker(agent_id, self())

      # Only the pending and stranded-sent commands get pushed to the socket
      assert_receive {:send_command, %{command_id: id_a}}, 2_000
      assert_receive {:send_command, %{command_id: id_b}}, 2_000
      assert MapSet.new([id_a, id_b]) == MapSet.new([pending.id, stranded_sent.id])
      refute_receive {:send_command, _}, 300

      # Dispatch bookkeeping recorded for the redelivered commands
      assert %{status: "sent", dispatch_count: 1} = Repo.get(AgentCommand, pending.id)
      assert %{status: "sent", dispatch_count: 2} = Repo.get(AgentCommand, stranded_sent.id)

      # Cooldown: the recent in-flight attempt is left alone
      assert %{status: "sent", dispatch_count: 1} = Repo.get(AgentCommand, recently_sent.id)

      # Cap: the exhausted command is marked failed with an explanatory reason
      failed = Repo.get(AgentCommand, exhausted.id)
      assert failed.status == "failed"
      assert failed.error =~ "Dispatch limit reached"
    end
  end

  describe "Worker command callbacks in GenServer state" do
    test "send_command tracks the caller in state and replies on command_response" do
      agent_id = unique_agent_id()
      worker = start_worker(agent_id, self())

      task =
        Task.async(fn ->
          Worker.send_command(worker, %{type: "kill_process", params: %{"pid" => 123}})
        end)

      assert_receive {:send_command, %{command_id: command_id}}, 2_000

      # Callback is visible in GenServer state...
      assert %{command_callbacks: callbacks} = :sys.get_state(worker)
      assert Map.has_key?(callbacks, command_id)

      # ...and nothing lives in the process dictionary anymore
      {:dictionary, dict} = Process.info(worker, :dictionary)
      refute Enum.any?(dict, fn {key, _} -> match?({:command_callback, _}, key) end)

      Worker.command_response(worker, %{
        "command_id" => command_id,
        "status" => "completed",
        "result" => %{"ok" => true}
      })

      assert {:ok, %{"ok" => true}} = Task.await(task, 2_000)

      # Cleaned up after reply
      assert :sys.get_state(worker).command_callbacks == %{}
      assert %{status: "completed"} = Repo.get(AgentCommand, command_id)
    end

    test "success false marks command failed instead of completed" do
      agent_id = unique_agent_id()
      worker = start_worker(agent_id, self())

      task =
        Task.async(fn ->
          Worker.send_command(worker, %{type: "kill_process", params: %{"pid" => 404}})
        end)

      assert_receive {:send_command, %{command_id: command_id}}, 2_000

      Worker.command_response(worker, %{
        "command_id" => command_id,
        "success" => false,
        "error_message" => "Process not found"
      })

      assert {:error, "Process not found"} = Task.await(task, 2_000)
      assert %{status: "failed", error: "Process not found"} = Repo.get(AgentCommand, command_id)
    end

    test "acknowledged keeps the caller waiting until terminal completion" do
      agent_id = unique_agent_id()
      worker = start_worker(agent_id, self())

      task =
        Task.async(fn ->
          Worker.send_command(worker, %{type: "kill_process", params: %{"pid" => 42}})
        end)

      assert_receive {:send_command, %{command_id: command_id}}, 2_000

      Worker.command_response(worker, %{
        "command_id" => command_id,
        "status" => "acknowledged"
      })

      wait_until(fn -> Repo.get(AgentCommand, command_id).status == "acknowledged" end)
      assert Task.yield(task, 0) == nil
      assert Map.has_key?(:sys.get_state(worker).command_callbacks, command_id)

      Worker.command_response(worker, %{
        "command_id" => command_id,
        "status" => "completed",
        "result" => %{"killed" => true}
      })

      assert {:ok, %{"killed" => true}} = Task.await(task, 2_000)
    end

    test "command_response preserves ok degraded and unsupported result_status as audit fields" do
      agent_id = unique_agent_id()
      worker = start_worker(agent_id, self())

      for result_status <- ~w(ok degraded unsupported) do
        command = insert_command!(agent_id, %{command_type: "process_list", status: "sent"})

        Worker.command_response(worker, %{
          "command_id" => command.id,
          "command_type" => "process_list",
          "result_status" => result_status,
          "result" => %{
            "processes" => [],
            "warnings" => ["partial process metadata"]
          }
        })

        wait_until(fn ->
          case Repo.get(AgentCommand, command.id) do
            %{status: "completed", result: result} when is_map(result) ->
              result["command_type"] == "process_list" and result["result_status"] == result_status

            _ ->
              false
          end
        end)

        updated = Repo.get(AgentCommand, command.id)
        assert updated.result["warnings"] == ["partial process metadata"]
      end
    end

    test "command_response treats failed result_status as failed when lifecycle status is absent" do
      agent_id = unique_agent_id()
      worker = start_worker(agent_id, self())
      command = insert_command!(agent_id, %{command_type: "memory_scan", status: "sent"})

      Worker.command_response(worker, %{
        "command_id" => command.id,
        "command_type" => "memory_scan",
        "result_status" => "failed",
        "result" => %{"error" => "scanner unavailable"}
      })

      wait_until(fn ->
        case Repo.get(AgentCommand, command.id) do
          %{status: "failed", result: result} when is_map(result) ->
            result["command_type"] == "memory_scan" and result["result_status"] == "failed"

          _ ->
            false
        end
      end)

      assert %{error: "scanner unavailable"} = Repo.get(AgentCommand, command.id)
    end

    test "command_response persists delivery audit and agent response evidence" do
      agent_id = unique_agent_id()
      worker = start_worker(agent_id, self())
      command = insert_command!(agent_id, %{command_type: "network_connections", status: "sent"})

      Worker.command_response(worker, %{
        "command_id" => command.id,
        "command_type" => "network_connections",
        "success" => true,
        "result_status" => "degraded",
        "executed_at" => 1_234_567,
        "result" => %{
          "connections" => [],
          "response_audit" => %{
            "schema_version" => "tamandua.command_response_audit/v1",
            "target_context" => %{"network" => %{"remote_ip" => "203.0.113.10"}}
          }
        }
      })

      wait_until(fn ->
        case Repo.get(AgentCommand, command.id) do
          %{status: "completed", result: %{"command_delivery" => delivery}} ->
            delivery["agent_reported_status"] == "degraded" and
              delivery["executed_at"] == 1_234_567 and
              get_in(delivery, ["agent_response_audit", "target_context", "network", "remote_ip"]) ==
                "203.0.113.10"

          _ ->
            false
        end
      end)
    end

    test "wrong agent cannot complete another agent command" do
      owner_agent_id = unique_agent_id()
      other_agent_id = unique_agent_id()
      worker = start_worker(other_agent_id, self())
      command = insert_command!(owner_agent_id, %{status: "sent"})

      Worker.command_response(worker, %{
        "command_id" => command.id,
        "status" => "completed",
        "result" => %{"ok" => true}
      })

      Process.sleep(50)

      assert %{status: "sent", result: nil} = Repo.get(AgentCommand, command.id)
    end

    test "command_timeout replies {:error, :timeout} and clears the callback" do
      agent_id = unique_agent_id()
      worker = start_worker(agent_id, self())

      task =
        Task.async(fn ->
          Worker.send_command(worker, %{type: "kill_process", params: %{}})
        end)

      assert_receive {:send_command, %{command_id: command_id}}, 2_000

      send(worker, {:command_timeout, command_id})

      assert {:error, :timeout} = Task.await(task, 2_000)
      assert :sys.get_state(worker).command_callbacks == %{}

      failed = Repo.get(AgentCommand, command_id)
      assert failed.status == "failed"
      assert failed.error == "Command timeout"
    end

    test "socket disconnect replies {:error, :disconnected} to waiting callers" do
      agent_id = unique_agent_id()
      socket = spawn(fn -> receive(do: (:stop -> :ok)) end)
      worker = start_worker(agent_id, socket)

      task =
        Task.async(fn ->
          Worker.send_command(worker, %{type: "kill_process", params: %{}})
        end)

      wait_until(fn -> map_size(:sys.get_state(worker).command_callbacks) == 1 end)

      Process.exit(socket, :kill)

      assert {:error, :disconnected} = Task.await(task, 2_000)
    end

    test "duplicate send_command reports the in-flight command without re-dispatch" do
      agent_id = unique_agent_id()
      worker = start_worker(agent_id, self())
      key = "ui-retry-#{System.unique_integer([:positive])}"

      task =
        Task.async(fn ->
          Worker.send_command(worker, %{
            type: "kill_process",
            params: %{"pid" => 7},
            idempotency_key: key
          })
        end)

      assert_receive {:send_command, %{command_id: command_id}}, 2_000

      # A UI/API retry does not insert or dispatch a second command
      assert {:error, {:command_in_progress, ^command_id}} =
               Worker.send_command(worker, %{
                 type: "kill_process",
                 params: %{"pid" => 7},
                 idempotency_key: key
               })

      refute_receive {:send_command, _}, 300

      assert Repo.aggregate(
               from(c in AgentCommand, where: c.agent_id == ^agent_id),
               :count
             ) == 1

      # The original caller still gets the agent's reply
      Worker.command_response(worker, %{
        "command_id" => command_id,
        "status" => "completed",
        "result" => %{"killed" => true}
      })

      assert {:ok, %{"killed" => true}} = Task.await(task, 2_000)
    end
  end
end
