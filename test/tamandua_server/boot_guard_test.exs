defmodule TamanduaServer.BootGuardTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.BootGuard

  test "returns a successful supervisor start and records readiness" do
    assert {:ok, pid} = BootGuard.start(fn -> Agent.start_link(fn -> :ready end) end, 500)
    assert Process.alive?(pid)
    assert {:links, links} = Process.info(self(), :links)
    assert pid in links
    assert %{state: :ready, timeout_ms: 500} = BootGuard.status()
    GenServer.stop(pid)
  end

  test "terminates a blocked starter and records an explicit timeout" do
    parent = self()

    assert {:error, {:boot_timeout, 20}} =
             BootGuard.start(
               fn ->
                 send(parent, {:starter, self()})
                 Process.sleep(:infinity)
               end,
               20
             )

    assert_received {:starter, starter_pid}
    refute Process.alive?(starter_pid)
    assert %{state: :timed_out, timeout_ms: 20} = BootGuard.status()
  end

  test "preserves a starter failure" do
    assert {:error, :dependency_unavailable} =
             BootGuard.start(fn -> {:error, :dependency_unavailable} end, 500)

    assert %{state: :failed} = BootGuard.status()
  end
end
