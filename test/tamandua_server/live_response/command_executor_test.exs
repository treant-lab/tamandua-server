defmodule TamanduaServer.LiveResponse.CommandExecutorTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.LiveResponse.CommandExecutor

  describe "supported_commands/0" do
    test "includes shell_execute for agent live response shell commands" do
      assert "shell_execute" in CommandExecutor.supported_commands()
    end

    test "announces only commands with an explicit server-to-agent contract" do
      assert Enum.sort(CommandExecutor.supported_commands()) ==
               CommandExecutor.command_contracts()
               |> Map.keys()
               |> Enum.sort()
    end

    test "includes direct memory endpoints backed by agent wire commands" do
      supported = CommandExecutor.supported_commands()

      assert "memory_yara_scan" in supported
      assert "memory_strings" in supported
      assert "list_loaded_modules" in supported
    end

    test "includes osquery_query as a typed live response command" do
      assert "osquery_query" in CommandExecutor.supported_commands()
    end

    test "covers commands sent by direct live response controller endpoints" do
      direct_endpoint_commands = ~w(
        list_processes
        kill_process
        dump_process_memory
        memory_yara_scan
        memory_strings
        list_directory
        download_file
        hash_file
        list_connections
        dns_cache
        list_keys
        services
        scheduled_tasks
        autoruns
      )

      assert Enum.all?(direct_endpoint_commands, &(&1 in CommandExecutor.supported_commands()))
    end
  end

  describe "command_contracts/0" do
    test "documents list_loaded_modules PID payload contract" do
      # The agent expects command_type "list_loaded_modules" and a payload with pid.
      assert %{
               "list_loaded_modules" => %{
                 agent_command_type: "list_loaded_modules",
                 required: [:pid]
               }
             } = CommandExecutor.command_contracts()
    end

    test "documents osquery_query payload contract" do
      assert %{
               "osquery_query" => %{
                 agent_command_type: "osquery_query",
                 required: [:query]
               }
             } = CommandExecutor.command_contracts()
    end

    test "does not expose commands without an agent wire command" do
      refute "delete_file" in CommandExecutor.supported_commands()
      refute "get_file_metadata" in CommandExecutor.supported_commands()
      refute "get_process_details" in CommandExecutor.supported_commands()
    end
  end

  describe "command_allowed?/2" do
    test "allows shell_execute only for elevated response roles" do
      assert CommandExecutor.command_allowed?("shell_execute", :admin)
      assert CommandExecutor.command_allowed?("shell_execute", :supervisor)
      assert CommandExecutor.command_allowed?("shell_execute", :responder)

      refute CommandExecutor.command_allowed?("shell_execute", :analyst)
      refute CommandExecutor.command_allowed?("shell_execute", :viewer)
    end

    test "allows list_loaded_modules for non-elevated responder workflows" do
      assert CommandExecutor.command_allowed?("list_loaded_modules", :analyst)
      assert CommandExecutor.command_allowed?("list_loaded_modules", :viewer)
    end

    test "allows osquery_query for non-elevated read-only workflows" do
      assert CommandExecutor.command_allowed?("osquery_query", :analyst)
      assert CommandExecutor.command_allowed?("osquery_query", :viewer)
    end
  end

  describe "elevated_commands/0" do
    test "treats shell execution as elevated" do
      assert "shell_execute" in CommandExecutor.elevated_commands()
    end
  end

  describe "wire contract with the persistent command queue" do
    test "every agent_command_type is accepted by the AgentCommand allowlist" do
      # dispatch_to_agent/4 routes through Worker.send_command/3, which
      # persists via AgentCommand.insert_new/1. Any contract type missing
      # from the allowlist fails validate_inclusion before dispatch and the
      # live response command silently degrades to :command_insert_failed.
      valid_types = TamanduaServer.Agents.AgentCommand.valid_command_types()

      contract_types =
        CommandExecutor.command_contracts()
        |> Map.values()
        |> Enum.map(& &1.agent_command_type)
        |> Enum.uniq()

      assert Enum.sort(contract_types -- valid_types) == []
    end
  end
end
