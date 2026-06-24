defmodule TamanduaServer.LiveResponse.CommandExecutorTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.LiveResponse.CommandExecutor

  describe "supported_commands/0" do
    test "includes shell_execute for agent live response shell commands" do
      assert "shell_execute" in CommandExecutor.supported_commands()
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
  end

  describe "elevated_commands/0" do
    test "treats shell execution as elevated" do
      assert "shell_execute" in CommandExecutor.elevated_commands()
    end
  end
end
