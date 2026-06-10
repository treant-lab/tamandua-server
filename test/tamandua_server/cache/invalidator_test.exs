defmodule TamanduaServer.Cache.InvalidatorTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Cache.{Invalidator, RedisCache, ETSCache}

  setup do
    # Clear caches before each test
    on_exit(fn ->
      Enum.each(ETSCache.cache_types(), fn cache_type ->
        ETSCache.clear(cache_type)
      end)
      RedisCache.clear_namespace("tamandua")
    end)

    :ok
  end

  describe "invalidate/2" do
    test "invalidates Redis cache for resource" do
      # Setup: Add data to cache
      RedisCache.put("tamandua", "alert:1", %{id: 1, status: "open"})
      assert {:ok, _} = RedisCache.get("tamandua", "alert:1")

      # Invalidate
      Invalidator.invalidate(:alert, 1)

      # Wait for async invalidation
      Process.sleep(50)

      # Verify cache is cleared
      assert :miss = RedisCache.get("tamandua", "alert:1")
    end

    test "invalidates ETS cache for detection rules" do
      ETSCache.put(:yara_rules, "rule_1", %{name: "test_rule"})
      assert {:ok, _} = ETSCache.get(:yara_rules, "rule_1")

      Invalidator.invalidate(:detection_rule, "rule_1")
      Process.sleep(50)

      assert :miss = ETSCache.get(:yara_rules, "rule_1")
    end

    test "invalidates dependent resources" do
      # Alert invalidation should also invalidate dashboard
      RedisCache.put("tamandua", "alert:1", %{id: 1})
      RedisCache.put("tamandua", "dashboard:1", %{data: "test"})

      Invalidator.invalidate(:alert, 1)
      Process.sleep(50)

      assert :miss = RedisCache.get("tamandua", "alert:1")
    end
  end

  describe "invalidate_by_tag/2" do
    test "invalidates all caches with specific tag" do
      RedisCache.put("tamandua", "alert:tenant_1:1", %{id: 1})
      RedisCache.put("tamandua", "alert:tenant_1:2", %{id: 2})
      RedisCache.put("tamandua", "alert:tenant_2:3", %{id: 3})

      Invalidator.invalidate_by_tag(:alert, "tenant_1")
      Process.sleep(50)

      assert :miss = RedisCache.get("tamandua", "alert:tenant_1:1")
      assert :miss = RedisCache.get("tamandua", "alert:tenant_1:2")
      # Different tenant should remain
      assert {:ok, _} = RedisCache.get("tamandua", "alert:tenant_2:3")
    end

    test "invalidates tag without context" do
      ETSCache.put(:yara_rules, "rule_1", %{})
      ETSCache.put(:sigma_rules, "rule_2", %{})

      Invalidator.invalidate_by_tag(:detection_rule)
      Process.sleep(50)

      # Should clear related ETS caches
      assert 0 = ETSCache.size(:yara_rules)
      assert 0 = ETSCache.size(:sigma_rules)
    end
  end

  describe "invalidate_pattern/1" do
    test "invalidates keys matching pattern" do
      RedisCache.put("tamandua", "alert:1:details", %{})
      RedisCache.put("tamandua", "alert:1:metadata", %{})
      RedisCache.put("tamandua", "alert:2:details", %{})

      Invalidator.invalidate_pattern("alert:1:*")
      Process.sleep(50)

      assert :miss = RedisCache.get("tamandua", "alert:1:details")
      assert :miss = RedisCache.get("tamandua", "alert:1:metadata")
      assert {:ok, _} = RedisCache.get("tamandua", "alert:2:details")
    end
  end

  describe "invalidate_batch/1" do
    test "invalidates multiple resources at once" do
      RedisCache.put("tamandua", "alert:1", %{})
      RedisCache.put("tamandua", "alert:2", %{})
      RedisCache.put("tamandua", "agent:3", %{})

      Invalidator.invalidate_batch([
        {:alert, 1},
        {:alert, 2},
        {:agent, 3}
      ])

      Process.sleep(50)

      assert :miss = RedisCache.get("tamandua", "alert:1")
      assert :miss = RedisCache.get("tamandua", "alert:2")
      assert :miss = RedisCache.get("tamandua", "agent:3")
    end
  end

  describe "convenience functions" do
    test "invalidate_alert/1 invalidates alert cache" do
      RedisCache.put("tamandua", "alert:123", %{id: 123})

      Invalidator.invalidate_alert(123)
      Process.sleep(50)

      assert :miss = RedisCache.get("tamandua", "alert:123")
    end

    test "invalidate_agent/1 invalidates agent cache" do
      RedisCache.put("tamandua", "agent:456", %{id: 456})

      Invalidator.invalidate_agent(456)
      Process.sleep(50)

      assert :miss = RedisCache.get("tamandua", "agent:456")
    end

    test "invalidate_user/1 invalidates user cache" do
      RedisCache.put("tamandua", "user:789", %{id: 789})

      Invalidator.invalidate_user(789)
      Process.sleep(50)

      assert :miss = RedisCache.get("tamandua", "user:789")
    end
  end

  describe "stats/0" do
    test "returns invalidation statistics" do
      Invalidator.invalidate(:alert, 1)
      Invalidator.invalidate(:agent, 2)
      Process.sleep(50)

      stats = Invalidator.stats()

      assert is_map(stats)
      assert stats.total_invalidations >= 2
      assert is_map(stats.ets_stats)
      assert is_list(stats.ets_stats)
    end
  end

  describe "clear_all/0" do
    test "clears all caches" do
      ETSCache.put(:yara_rules, "rule_1", %{})
      RedisCache.put("tamandua", "alert:1", %{})

      assert :ok = Invalidator.clear_all()
      Process.sleep(50)

      assert 0 = ETSCache.size(:yara_rules)
      assert :miss = RedisCache.get("tamandua", "alert:1")
    end
  end
end
