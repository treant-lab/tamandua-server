defmodule TamanduaServer.Cache.ETSCacheTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Cache.ETSCache

  setup do
    # Clear cache before each test
    on_exit(fn ->
      Enum.each(ETSCache.cache_types(), fn cache_type ->
        ETSCache.clear(cache_type)
      end)
    end)

    :ok
  end

  describe "get/put" do
    test "stores and retrieves a value" do
      assert :ok = ETSCache.put(:yara_rules, "rule_1", %{name: "test_rule"})
      assert {:ok, %{name: "test_rule"}} = ETSCache.get(:yara_rules, "rule_1")
    end

    test "returns :miss for non-existent key" do
      assert :miss = ETSCache.get(:yara_rules, "nonexistent")
    end

    test "expires after custom TTL" do
      assert :ok = ETSCache.put(:yara_rules, "rule_1", %{name: "test"}, ttl: 100)
      assert {:ok, %{name: "test"}} = ETSCache.get(:yara_rules, "rule_1")

      # Wait for expiration
      Process.sleep(150)
      assert :miss = ETSCache.get(:yara_rules, "rule_1")
    end

    test "uses default TTL from cache config" do
      # yara_rules has 1 hour TTL by default
      assert :ok = ETSCache.put(:yara_rules, "rule_1", %{name: "test"})
      assert {:ok, %{name: "test"}} = ETSCache.get(:yara_rules, "rule_1")

      # Should still be cached after short wait
      Process.sleep(100)
      assert {:ok, %{name: "test"}} = ETSCache.get(:yara_rules, "rule_1")
    end
  end

  describe "delete" do
    test "deletes a key" do
      ETSCache.put(:sigma_rules, "rule_1", %{name: "test"})
      assert {:ok, %{name: "test"}} = ETSCache.get(:sigma_rules, "rule_1")

      assert :ok = ETSCache.delete(:sigma_rules, "rule_1")
      assert :miss = ETSCache.get(:sigma_rules, "rule_1")
    end
  end

  describe "clear" do
    test "clears all entries in cache type" do
      ETSCache.put(:iocs, "ioc_1", %{value: "1.2.3.4"})
      ETSCache.put(:iocs, "ioc_2", %{value: "5.6.7.8"})

      assert :ok = ETSCache.clear(:iocs)
      assert :miss = ETSCache.get(:iocs, "ioc_1")
      assert :miss = ETSCache.get(:iocs, "ioc_2")
    end
  end

  describe "all" do
    test "returns all non-expired entries" do
      ETSCache.put(:threat_intel, "intel_1", %{data: "a"})
      ETSCache.put(:threat_intel, "intel_2", %{data: "b"})
      ETSCache.put(:threat_intel, "intel_3", %{data: "c"}, ttl: 50)

      # Wait for one to expire
      Process.sleep(100)

      entries = ETSCache.all(:threat_intel)
      assert length(entries) == 2
      assert {"intel_1", %{data: "a"}} in entries
      assert {"intel_2", %{data: "b"}} in entries
    end
  end

  describe "size" do
    test "returns number of entries" do
      assert 0 = ETSCache.size(:detection_config)

      ETSCache.put(:detection_config, "key1", "value1")
      ETSCache.put(:detection_config, "key2", "value2")

      assert 2 = ETSCache.size(:detection_config)
    end
  end

  describe "fetch" do
    test "returns cached value if present" do
      ETSCache.put(:ml_predictions, "hash_1", %{score: 0.95})

      result = ETSCache.fetch(:ml_predictions, "hash_1", fn ->
        {:ok, %{score: 0.50}}
      end)

      assert {:ok, %{score: 0.95}} = result
    end

    test "fetches and caches if missing" do
      result = ETSCache.fetch(:ml_predictions, "hash_1", fn ->
        {:ok, %{score: 0.95}}
      end)

      assert {:ok, %{score: 0.95}} = result
      assert {:ok, %{score: 0.95}} = ETSCache.get(:ml_predictions, "hash_1")
    end

    test "handles raw value return" do
      result = ETSCache.fetch(:ml_predictions, "hash_1", fn ->
        %{score: 0.95}
      end)

      assert {:ok, %{score: 0.95}} = result
    end
  end

  describe "warm" do
    test "bulk loads cache entries" do
      entries = [
        {"rule_1", %{name: "rule_1"}},
        {"rule_2", %{name: "rule_2"}},
        {"rule_3", %{name: "rule_3"}}
      ]

      assert {:ok, 3} = ETSCache.warm(:yara_rules, fn -> entries end)

      assert {:ok, %{name: "rule_1"}} = ETSCache.get(:yara_rules, "rule_1")
      assert {:ok, %{name: "rule_2"}} = ETSCache.get(:yara_rules, "rule_2")
      assert {:ok, %{name: "rule_3"}} = ETSCache.get(:yara_rules, "rule_3")
    end

    test "handles warming errors" do
      result = ETSCache.warm(:yara_rules, fn -> {:error, :db_error} end)
      assert {:error, :db_error} = result
    end
  end

  describe "stats" do
    test "returns statistics for cache type" do
      ETSCache.put(:agent_metadata, "agent_1", %{hostname: "test"})

      # Generate some hits and misses
      ETSCache.get(:agent_metadata, "agent_1")
      ETSCache.get(:agent_metadata, "agent_1")
      ETSCache.get(:agent_metadata, "nonexistent")

      stats = ETSCache.stats(:agent_metadata)

      assert stats.cache_type == :agent_metadata
      assert stats.size == 1
      assert stats.hits == 2
      assert stats.misses == 1
      assert stats.total_requests == 3
      assert stats.hit_rate_percent == 66.67
    end

    test "stats_all returns all cache type statistics" do
      ETSCache.put(:yara_rules, "rule_1", %{})
      ETSCache.put(:sigma_rules, "rule_2", %{})

      stats = ETSCache.stats_all()

      assert is_list(stats)
      assert length(stats) > 0
      assert Enum.any?(stats, fn s -> s.cache_type == :yara_rules end)
      assert Enum.any?(stats, fn s -> s.cache_type == :sigma_rules end)
    end
  end

  describe "exists?" do
    test "returns true for initialized cache" do
      assert true = ETSCache.exists?(:yara_rules)
    end

    test "returns false for non-existent cache" do
      assert false = ETSCache.exists?(:nonexistent_cache)
    end
  end

  describe "cache_types" do
    test "returns all configured cache types" do
      types = ETSCache.cache_types()

      assert is_list(types)
      assert :yara_rules in types
      assert :sigma_rules in types
      assert :iocs in types
      assert :detection_config in types
      assert :threat_intel in types
    end
  end
end
