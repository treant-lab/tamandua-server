defmodule TamanduaServer.Cache.RedisCacheTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Cache.RedisCache

  setup do
    # Clear cache before each test
    on_exit(fn ->
      RedisCache.clear_namespace("test")
    end)

    :ok
  end

  describe "get/put" do
    test "stores and retrieves a value" do
      assert :ok = RedisCache.put("test", "key1", "value1")
      assert {:ok, "value1"} = RedisCache.get("test", "key1")
    end

    test "returns :miss for non-existent key" do
      assert :miss = RedisCache.get("test", "nonexistent")
    end

    test "expires after TTL" do
      assert :ok = RedisCache.put("test", "key1", "value1", ttl: 100)
      assert {:ok, "value1"} = RedisCache.get("test", "key1")

      # Wait for expiration
      Process.sleep(150)
      assert :miss = RedisCache.get("test", "key1")
    end

    test "handles complex data structures" do
      data = %{
        id: 1,
        name: "test",
        nested: %{a: 1, b: 2},
        list: [1, 2, 3]
      }

      assert :ok = RedisCache.put("test", "complex", data)
      assert {:ok, ^data} = RedisCache.get("test", "complex")
    end
  end

  describe "delete" do
    test "deletes a key" do
      RedisCache.put("test", "key1", "value1")
      assert {:ok, "value1"} = RedisCache.get("test", "key1")

      assert :ok = RedisCache.delete("test", "key1")
      assert :miss = RedisCache.get("test", "key1")
    end
  end

  describe "delete_pattern" do
    test "deletes all keys matching pattern" do
      RedisCache.put("test", "alert:1", %{id: 1})
      RedisCache.put("test", "alert:2", %{id: 2})
      RedisCache.put("test", "agent:1", %{id: 1})

      assert {:ok, 2} = RedisCache.delete_pattern("test", "alert:*")

      assert :miss = RedisCache.get("test", "alert:1")
      assert :miss = RedisCache.get("test", "alert:2")
      assert {:ok, %{id: 1}} = RedisCache.get("test", "agent:1")
    end
  end

  describe "fetch" do
    test "returns cached value if present" do
      RedisCache.put("test", "key1", "cached_value")

      result = RedisCache.fetch("test", "key1", [], fn ->
        {:ok, "fresh_value"}
      end)

      assert {:ok, "cached_value"} = result
    end

    test "fetches and caches if missing" do
      result = RedisCache.fetch("test", "key1", [ttl: 1000], fn ->
        {:ok, "fresh_value"}
      end)

      assert {:ok, "fresh_value"} = result
      assert {:ok, "fresh_value"} = RedisCache.get("test", "key1")
    end

    test "handles fetch function returning raw value" do
      result = RedisCache.fetch("test", "key1", [], fn ->
        "raw_value"
      end)

      assert {:ok, "raw_value"} = result
    end

    test "propagates fetch errors" do
      result = RedisCache.fetch("test", "key1", [], fn ->
        {:error, :db_error}
      end)

      assert {:error, :db_error} = result
      assert :miss = RedisCache.get("test", "key1")
    end
  end

  describe "exists?" do
    test "returns true for existing key" do
      RedisCache.put("test", "key1", "value1")
      assert true = RedisCache.exists?("test", "key1")
    end

    test "returns false for non-existent key" do
      assert false = RedisCache.exists?("test", "nonexistent")
    end
  end

  describe "ttl" do
    test "returns remaining TTL" do
      RedisCache.put("test", "key1", "value1", ttl: 5000)
      assert {:ok, ttl} = RedisCache.ttl("test", "key1")
      assert ttl > 0 and ttl <= 5
    end

    test "returns :miss for non-existent key" do
      assert :miss = RedisCache.ttl("test", "nonexistent")
    end
  end

  describe "incr" do
    test "increments a counter" do
      assert {:ok, 1} = RedisCache.incr("test", "counter", 1)
      assert {:ok, 2} = RedisCache.incr("test", "counter", 1)
      assert {:ok, 7} = RedisCache.incr("test", "counter", 5)
    end
  end

  describe "predefined TTLs" do
    test "ttl_5min returns 5 minutes in milliseconds" do
      assert RedisCache.ttl_5min() == 300_000
    end

    test "ttl_1hour returns 1 hour in milliseconds" do
      assert RedisCache.ttl_1hour() == 3_600_000
    end

    test "ttl_1day returns 1 day in milliseconds" do
      assert RedisCache.ttl_1day() == 86_400_000
    end
  end
end
