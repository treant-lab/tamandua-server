defmodule TamanduaServer.Detection.RuleLoaderTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Detection.{IOCGenerationOwner, RuleLoader}

  @moduletag :detection

  setup do
    unless Process.whereis(IOCGenerationOwner) do
      start_supervised!(IOCGenerationOwner)
    end

    :ok
  end

  describe "init_tables/0" do
    test "creates double-buffered rule tables and an immutable IOC generation" do
      # Clean up any existing tables from previous test runs
      cleanup_tables()

      # Initialize tables
      assert :ok = RuleLoader.init_tables()

      # Verify version table exists
      assert :ets.whereis(:detection_rule_versions) != :undefined

      # Verify Sigma tables (v0 and v1)
      assert :ets.whereis(:detection_sigma_rules_v0) != :undefined
      assert :ets.whereis(:detection_sigma_rules_v1) != :undefined

      # IOC snapshots use unnamed immutable generations (no atom per epoch).
      ioc_table = RuleLoader.get_active_table(:ioc)
      assert is_reference(ioc_table)
      assert :ets.info(ioc_table) != :undefined

      # Verify YARA tables
      assert :ets.whereis(:detection_yara_rules_v0) != :undefined
      assert :ets.whereis(:detection_yara_rules_v1) != :undefined

      # Verify initial versions are 0
      assert [{:sigma, 0}] = :ets.lookup(:detection_rule_versions, :sigma)
      assert [{:ioc, ^ioc_table, -1}] = :ets.lookup(:detection_rule_versions, :ioc)
      assert [{:yara, 0}] = :ets.lookup(:detection_rule_versions, :yara)
    end

    test "is idempotent (can be called multiple times)" do
      cleanup_tables()

      assert :ok = RuleLoader.init_tables()
      # Should not raise
      assert :ok = RuleLoader.init_tables()
      # Still fine
      assert :ok = RuleLoader.init_tables()
    end
  end

  describe "get_active_table/1" do
    setup do
      cleanup_tables()
      RuleLoader.init_tables()
      :ok
    end

    test "returns v0 table initially for sigma" do
      assert RuleLoader.get_active_table(:sigma) == :detection_sigma_rules_v0
    end

    test "returns an unnamed immutable generation initially for ioc" do
      table = RuleLoader.get_active_table(:ioc)
      assert is_reference(table)
      assert :ets.info(table) != :undefined
    end

    test "returns v0 table initially for yara" do
      assert RuleLoader.get_active_table(:yara) == :detection_yara_rules_v0
    end
  end

  describe "reload_sigma_rules_atomic/1" do
    setup do
      cleanup_tables()
      RuleLoader.init_tables()
      :ok
    end

    test "loads rules into the inactive table and swaps version" do
      rules = [
        {1, %{id: 1, name: "Test Rule 1", detection: %{}}},
        {2, %{id: 2, name: "Test Rule 2", detection: %{}}},
        {3, %{id: 3, name: "Test Rule 3", detection: %{}}}
      ]

      # Initially at v0
      assert RuleLoader.get_active_table(:sigma) == :detection_sigma_rules_v0

      # Reload rules
      assert {:ok, 3} = RuleLoader.reload_sigma_rules_atomic(rules)

      # Should now be at v1
      assert RuleLoader.get_active_table(:sigma) == :detection_sigma_rules_v1

      # v1 should have the rules
      v1_rules = :ets.tab2list(:detection_sigma_rules_v1)
      assert length(v1_rules) == 3
    end

    test "second reload swaps back to v0" do
      rules1 = [{1, %{id: 1, name: "Rule A"}}]
      rules2 = [{1, %{id: 1, name: "Rule B"}}, {2, %{id: 2, name: "Rule C"}}]

      # First reload: v0 -> v1
      assert {:ok, 1} = RuleLoader.reload_sigma_rules_atomic(rules1)
      assert RuleLoader.get_active_table(:sigma) == :detection_sigma_rules_v1

      # Second reload: v1 -> v0
      assert {:ok, 2} = RuleLoader.reload_sigma_rules_atomic(rules2)
      assert RuleLoader.get_active_table(:sigma) == :detection_sigma_rules_v0

      # v0 should have the new rules
      v0_rules = :ets.tab2list(:detection_sigma_rules_v0)
      assert length(v0_rules) == 2
    end

    test "readers never see empty table during reload" do
      # Pre-load some rules
      initial_rules = for i <- 1..100, do: {i, %{id: i, name: "Rule #{i}"}}
      RuleLoader.reload_sigma_rules_atomic(initial_rules)

      # Start multiple reader processes
      readers =
        for _ <- 1..10 do
          Task.async(fn ->
            # Each reader will check rules 1000 times during the reload
            for _ <- 1..1000 do
              table = RuleLoader.get_active_table(:sigma)
              rules = :ets.tab2list(table)
              # Should never be empty
              assert length(rules) > 0, "Reader saw empty rules during reload!"
            end

            :ok
          end)
        end

      # Perform reload while readers are active
      new_rules = for i <- 1..200, do: {i, %{id: i, name: "New Rule #{i}"}}
      assert {:ok, 200} = RuleLoader.reload_sigma_rules_atomic(new_rules)

      # Wait for all readers to complete
      results = Task.await_many(readers, 5000)
      assert Enum.all?(results, &(&1 == :ok))
    end

    test "concurrent reloads are serialized correctly" do
      # Start multiple reload processes concurrently
      reloaders =
        for batch <- 1..5 do
          rules = for i <- 1..(batch * 10), do: {i, %{id: i, batch: batch}}

          Task.async(fn ->
            RuleLoader.reload_sigma_rules_atomic(rules)
          end)
        end

      # All should complete without error
      results = Task.await_many(reloaders, 5000)

      assert Enum.all?(results, fn
               {:ok, _count} -> true
               _ -> false
             end)

      # Final state should be consistent (one of the batches won)
      table = RuleLoader.get_active_table(:sigma)
      rules = :ets.tab2list(table)
      assert length(rules) > 0
    end
  end

  describe "reload_ioc_rules_atomic/2" do
    setup do
      cleanup_tables()
      RuleLoader.init_tables()
      :ok
    end

    test "loads IOCs and publishes a fresh immutable generation" do
      iocs = [
        {1, %{type: :sha256, value: "abc123", confidence: 90}},
        {2, %{type: :ip, value: "10.0.0.1", confidence: 85}}
      ]

      previous = RuleLoader.get_active_table(:ioc)
      assert {:ok, 2} = RuleLoader.reload_ioc_rules_atomic(iocs, 1)
      current = RuleLoader.get_active_table(:ioc)
      assert is_reference(current)
      refute current == previous
      assert :ets.info(current, :size) == 2
    end

    test "a pinned reader survives two newer publications without partial reads" do
      first = for i <- 1..1_000, do: {i, %{id: i, generation: :first}}
      second = for i <- 1..1_000, do: {i, %{id: i, generation: :second}}
      third = for i <- 1..1_000, do: {i, %{id: i, generation: :third}}

      assert {:ok, 1_000} = RuleLoader.reload_ioc_rules_atomic(first, 1)
      parent = self()

      reader =
        Task.async(fn ->
          RuleLoader.with_ioc_snapshot(fn table ->
            send(parent, {:generation_pinned, table})
            receive do: (:continue_reader -> :ok)
            :ets.tab2list(table)
          end)
        end)

      assert_receive {:generation_pinned, pinned}
      assert {:ok, 1_000} = RuleLoader.reload_ioc_rules_atomic(second, 2)
      assert {:ok, 1_000} = RuleLoader.reload_ioc_rules_atomic(third, 3)
      assert :ets.info(pinned, :size) == 1_000

      send(reader.pid, :continue_reader)
      result = Task.await(reader)
      assert length(result) == 1_000
      assert Enum.all?(result, fn {_id, ioc} -> ioc.generation == :first end)

      assert eventually(fn -> :ets.info(pinned) == :undefined end)
    end

    test "nested pins by one reader release the retired generation exactly once" do
      assert {:ok, 1} =
               RuleLoader.reload_ioc_rules_atomic([old: %{generation: :old}], 1)

      owner = IOCGenerationOwner
      pinned = RuleLoader.get_active_table(:ioc)

      assert :outer_complete =
               RuleLoader.with_ioc_snapshot(fn outer ->
                 assert outer == pinned

                 assert :inner_complete =
                          RuleLoader.with_ioc_snapshot(fn inner ->
                            assert inner == outer
                            state = :sys.get_state(owner)
                            assert get_in(state, [:readers, self(), :pins, outer]) == 2
                            assert get_in(state, [:generations, outer, :pin_count]) == 2
                            :inner_complete
                          end)

                 state = :sys.get_state(owner)
                 assert get_in(state, [:readers, self(), :pins, outer]) == 1
                 assert get_in(state, [:generations, outer, :pin_count]) == 1

                 assert {:ok, 1} =
                          RuleLoader.reload_ioc_rules_atomic([new: %{generation: :new}], 2)

                 assert :ets.info(outer) != :undefined
                 :outer_complete
               end)

      assert eventually(fn -> :ets.info(pinned) == :undefined end)
    end

    test "killing pinned readers retires their generation without leaking owner state" do
      assert {:ok, 1} =
               RuleLoader.reload_ioc_rules_atomic([old: %{generation: :old}], 1)

      owner = TamanduaServer.Detection.IOCGenerationOwner
      baseline_generation_count = map_size(:sys.get_state(owner).generations)
      parent = self()

      readers =
        for _ <- 1..100 do
          spawn(fn ->
            RuleLoader.with_ioc_snapshot(fn table ->
              send(parent, {:kill_reader_pinned, self(), table})
              receive do: (:hold_killed_reader -> :ok)
            end)
          end)
        end

      pinned_tables =
        for _ <- readers do
          assert_receive {:kill_reader_pinned, _reader, table}, 5_000
          table
        end

      assert [pinned] = Enum.uniq(pinned_tables)
      assert {:ok, 1} = RuleLoader.reload_ioc_rules_atomic([new: %{generation: :new}], 2)
      assert :ets.info(pinned) != :undefined

      Enum.each(readers, &Process.exit(&1, :kill))

      assert eventually(fn -> :ets.info(pinned) == :undefined end)

      assert eventually(fn ->
               map_size(:sys.get_state(owner).generations) == baseline_generation_count
             end)
    end

    test "generation-owner restart cannot deadlock publication or reader release" do
      assert {:ok, 1} =
               RuleLoader.reload_ioc_rules_atomic([first: %{generation: :first}], 1)

      parent = self()

      reader =
        Task.async(fn ->
          RuleLoader.with_ioc_snapshot(fn _table ->
            send(parent, :restart_reader_pinned)
            receive do: (:release_restart_reader -> :released)
          end)
        end)

      assert_receive :restart_reader_pinned
      owner = Process.whereis(TamanduaServer.Detection.IOCGenerationOwner)
      monitor = Process.monitor(owner)
      Process.exit(owner, :kill)
      assert_receive {:DOWN, ^monitor, :process, ^owner, :killed}

      assert eventually(fn ->
               case Process.whereis(IOCGenerationOwner) do
                 pid when is_pid(pid) -> pid != owner
                 _ -> false
               end
             end)

      publisher =
        Task.async(fn ->
          RuleLoader.reload_ioc_rules_atomic([second: %{generation: :second}], 2)
        end)

      assert {:ok, 1} = Task.await(publisher, 5_000)
      send(reader.pid, :release_restart_reader)
      assert :released = Task.await(reader, 5_000)
      assert RuleLoader.published_ioc_epoch() == 2
    end

    test "generation owner is never self-started outside its supervisor" do
      source = File.read!("lib/tamandua_server/detection/ioc_generation_owner.ex")

      refute source =~ "GenServer.start(__MODULE__, :ok, name: __MODULE__)"
      assert :ok = IOCGenerationOwner.ensure_started()
      assert is_pid(Process.whereis(IOCGenerationOwner))
    end
  end

  describe "stats/0" do
    setup do
      cleanup_tables()
      RuleLoader.init_tables()
      :ok
    end

    test "returns statistics for all rule types" do
      # Load some rules
      sigma_rules = for i <- 1..10, do: {i, %{id: i}}
      ioc_rules = for i <- 1..5, do: {i, %{id: i}}

      RuleLoader.reload_sigma_rules_atomic(sigma_rules)
      RuleLoader.reload_ioc_rules_atomic(ioc_rules, 1)

      stats = RuleLoader.stats()

      assert stats[:sigma][:active_count] == 10
      assert stats[:ioc][:active_count] == 5
      assert stats[:sigma][:active_version] in [0, 1]
    end
  end

  describe "read_all/1" do
    setup do
      cleanup_tables()
      RuleLoader.init_tables()
      :ok
    end

    test "returns all rules from active table" do
      rules = [{1, %{a: 1}}, {2, %{b: 2}}]
      RuleLoader.reload_sigma_rules_atomic(rules)

      result = RuleLoader.read_all(:sigma)
      assert length(result) == 2
    end

    test "returns empty list for empty table" do
      result = RuleLoader.read_all(:sigma)
      assert result == []
    end
  end

  describe "legacy compatibility" do
    setup do
      cleanup_tables()
      RuleLoader.init_tables()
      :ok
    end

    test "get_sigma_rules/0 returns list of rules" do
      rules = [{1, %{name: "Test"}}, {2, %{name: "Test2"}}]
      RuleLoader.reload_sigma_rules_atomic(rules)

      result = RuleLoader.get_sigma_rules()
      assert length(result) == 2
      assert Enum.all?(result, &is_map/1)
    end

    test "get_iocs/0 returns list of IOCs" do
      iocs = [{1, %{type: :ip, value: "1.2.3.4"}}]
      RuleLoader.reload_ioc_rules_atomic(iocs, 1)

      result = RuleLoader.get_iocs()
      assert length(result) == 1
    end
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  defp cleanup_tables do
    tables = [
      :detection_rule_versions,
      :detection_sigma_rules_v0,
      :detection_sigma_rules_v1,
      :detection_ioc_rules_v0,
      :detection_ioc_rules_v1,
      :detection_yara_rules_v0,
      :detection_yara_rules_v1
    ]

    for table <- tables do
      try do
        :ets.delete(table)
      rescue
        _ -> :ok
      end
    end
  end

  defp eventually(fun, attempts \\ 100)
  defp eventually(fun, 0), do: fun.()

  defp eventually(fun, attempts) do
    if fun.() do
      true
    else
      Process.sleep(5)
      eventually(fun, attempts - 1)
    end
  end
end
