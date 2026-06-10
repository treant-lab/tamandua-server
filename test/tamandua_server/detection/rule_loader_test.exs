defmodule TamanduaServer.Detection.RuleLoaderTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Detection.RuleLoader

  @moduletag :detection

  describe "init_tables/0" do
    test "creates all double-buffered ETS tables" do
      # Clean up any existing tables from previous test runs
      cleanup_tables()

      # Initialize tables
      assert :ok = RuleLoader.init_tables()

      # Verify version table exists
      assert :ets.whereis(:detection_rule_versions) != :undefined

      # Verify Sigma tables (v0 and v1)
      assert :ets.whereis(:detection_sigma_rules_v0) != :undefined
      assert :ets.whereis(:detection_sigma_rules_v1) != :undefined

      # Verify IOC tables
      assert :ets.whereis(:detection_ioc_rules_v0) != :undefined
      assert :ets.whereis(:detection_ioc_rules_v1) != :undefined

      # Verify YARA tables
      assert :ets.whereis(:detection_yara_rules_v0) != :undefined
      assert :ets.whereis(:detection_yara_rules_v1) != :undefined

      # Verify initial versions are 0
      assert [{:sigma, 0}] = :ets.lookup(:detection_rule_versions, :sigma)
      assert [{:ioc, 0}] = :ets.lookup(:detection_rule_versions, :ioc)
      assert [{:yara, 0}] = :ets.lookup(:detection_rule_versions, :yara)
    end

    test "is idempotent (can be called multiple times)" do
      cleanup_tables()

      assert :ok = RuleLoader.init_tables()
      assert :ok = RuleLoader.init_tables()  # Should not raise
      assert :ok = RuleLoader.init_tables()  # Still fine
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

    test "returns v0 table initially for ioc" do
      assert RuleLoader.get_active_table(:ioc) == :detection_ioc_rules_v0
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
      readers = for _ <- 1..10 do
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
      assert Enum.all?(results, & &1 == :ok)
    end

    test "concurrent reloads are serialized correctly" do
      # Start multiple reload processes concurrently
      reloaders = for batch <- 1..5 do
        rules = for i <- 1..(batch * 10), do: {i, %{id: i, batch: batch}}
        Task.async(fn ->
          RuleLoader.reload_sigma_rules_atomic(rules)
        end)
      end

      # All should complete without error
      results = Task.await_many(reloaders, 5000)
      assert Enum.all?(results, fn {:ok, _count} -> true; _ -> false end)

      # Final state should be consistent (one of the batches won)
      table = RuleLoader.get_active_table(:sigma)
      rules = :ets.tab2list(table)
      assert length(rules) > 0
    end
  end

  describe "reload_ioc_rules_atomic/1" do
    setup do
      cleanup_tables()
      RuleLoader.init_tables()
      :ok
    end

    test "loads IOCs and swaps version" do
      iocs = [
        {1, %{type: :sha256, value: "abc123", confidence: 90}},
        {2, %{type: :ip, value: "10.0.0.1", confidence: 85}}
      ]

      assert {:ok, 2} = RuleLoader.reload_ioc_rules_atomic(iocs)
      assert RuleLoader.get_active_table(:ioc) == :detection_ioc_rules_v1
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
      RuleLoader.reload_ioc_rules_atomic(ioc_rules)

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
      RuleLoader.reload_ioc_rules_atomic(iocs)

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
end
