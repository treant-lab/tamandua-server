defmodule TamanduaServer.Resilience.FuseTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Resilience.Fuse

  @moduletag :unit

  describe "install/2" do
    test "installs fuse with default options" do
      fuse_name = :test_fuse_install
      assert :ok = Fuse.install(fuse_name)
      assert Fuse.status(fuse_name) == :ok

      # Cleanup
      :fuse.remove(fuse_name)
    end

    test "installs fuse with custom options" do
      fuse_name = :test_fuse_custom
      opts = {{:standard, 3, 5000}, {:reset, 10_000}}
      assert :ok = Fuse.install(fuse_name, opts)
      assert Fuse.status(fuse_name) == :ok

      # Cleanup
      :fuse.remove(fuse_name)
    end
  end

  describe "run/3" do
    setup do
      fuse_name = :test_fuse_run
      Fuse.install(fuse_name)
      on_exit(fn -> :fuse.remove(fuse_name) end)
      {:ok, fuse_name: fuse_name}
    end

    test "executes function when fuse is ok", %{fuse_name: fuse_name} do
      result = Fuse.run(fuse_name, fn -> {:ok, :success} end)
      assert {:ok, :success} = result
    end

    test "returns error when function raises", %{fuse_name: fuse_name} do
      result = Fuse.run(fuse_name, fn -> raise "boom" end)
      assert {:error, _reason} = result
    end
  end

  describe "circuit breaker behavior" do
    setup do
      # Use aggressive thresholds for testing
      fuse_name = :test_fuse_breaker
      opts = {{:standard, 5, 10_000}, {:reset, 1_000}}
      Fuse.install(fuse_name, opts)
      on_exit(fn -> :fuse.remove(fuse_name) end)
      {:ok, fuse_name: fuse_name}
    end

    test "trips fuse after threshold failures", %{fuse_name: fuse_name} do
      # Trigger 5 failures
      for _i <- 1..5 do
        Fuse.run(fuse_name, fn -> raise "error" end)
      end

      # Should be blown now
      assert Fuse.status(fuse_name) == :blown
    end

    test "resets fuse after cooldown period", %{fuse_name: fuse_name} do
      # Trip the fuse
      for _i <- 1..5 do
        Fuse.run(fuse_name, fn -> raise "error" end)
      end

      assert Fuse.status(fuse_name) == :blown

      # Wait for reset (1 second + buffer)
      :timer.sleep(1200)

      # Should be ok again (half-open, ready to test)
      # Actually, status might still show :blown until a probe succeeds
      # so we test by running a successful operation
      result = Fuse.run(fuse_name, fn -> {:ok, :recovered} end)
      assert {:ok, :recovered} = result
    end

    test "melt/1 manually trips the fuse", %{fuse_name: fuse_name} do
      assert Fuse.status(fuse_name) == :ok
      Fuse.melt(fuse_name)
      assert Fuse.status(fuse_name) == :blown
    end

    test "reset/1 manually resets the fuse", %{fuse_name: fuse_name} do
      Fuse.melt(fuse_name)
      assert Fuse.status(fuse_name) == :blown
      Fuse.reset(fuse_name)
      assert Fuse.status(fuse_name) == :ok
    end
  end

  describe "ask/2" do
    setup do
      fuse_name = :test_fuse_ask
      Fuse.install(fuse_name)
      on_exit(fn -> :fuse.remove(fuse_name) end)
      {:ok, fuse_name: fuse_name}
    end

    test "returns :ok when fuse is healthy", %{fuse_name: fuse_name} do
      assert Fuse.ask(fuse_name) == :ok
    end

    test "returns :blown when fuse is tripped", %{fuse_name: fuse_name} do
      Fuse.melt(fuse_name)
      assert Fuse.ask(fuse_name) == :blown
    end
  end
end
