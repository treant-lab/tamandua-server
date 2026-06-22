defmodule TamanduaServer.Detection.AgentRiskScoreStoreTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Detection.AgentRiskScoreStore

  setup do
    # The GenServer is started by the application supervisor in real
    # runs. For tests we just ensure the ETS table exists (the API
    # auto-creates it on first call) and clear it.
    start_supervised!(AgentRiskScoreStore)
    AgentRiskScoreStore.reset()
    :ok
  end

  defp snap(opts \\ []) do
    %{
      process_key: opts[:process_key] || "powershell.exe",
      pid: opts[:pid],
      score_0_1: opts[:score_0_1] || 0.5,
      score_raw: (opts[:score_0_1] || 0.5) * 100,
      last_update_ms: opts[:last_update_ms] || System.system_time(:millisecond),
      snapshot_at_ms: opts[:snapshot_at_ms] || System.system_time(:millisecond),
      factors: opts[:factors] || []
    }
  end

  describe "put/2 + get/2" do
    test "round-trips a snapshot" do
      AgentRiskScoreStore.put("agent-a", snap(score_0_1: 0.75))
      result = AgentRiskScoreStore.get("agent-a", "powershell.exe")
      assert result.score_0_1 == 0.75
    end

    test "is case-insensitive on process_key lookup" do
      AgentRiskScoreStore.put("agent-a", snap(process_key: "cmd.exe", score_0_1: 0.3))
      assert %{score_0_1: 0.3} = AgentRiskScoreStore.get("agent-a", "CMD.EXE")
    end

    test "returns nil for missing entries" do
      assert AgentRiskScoreStore.get("agent-a", "missing.exe") == nil
    end

    test "isolates by agent_id (tenant boundary)" do
      AgentRiskScoreStore.put("agent-a", snap(process_key: "x.exe", score_0_1: 0.9))
      assert AgentRiskScoreStore.get("agent-b", "x.exe") == nil
      assert %{score_0_1: 0.9} = AgentRiskScoreStore.get("agent-a", "x.exe")
    end

    test "put/2 no-ops when agent_id is nil" do
      assert AgentRiskScoreStore.put(nil, snap()) == :ok
      assert AgentRiskScoreStore.size() == 0
    end

    test "get/2 no-ops when agent_id is nil" do
      AgentRiskScoreStore.put("agent-a", snap())
      assert AgentRiskScoreStore.get(nil, "powershell.exe") == nil
    end

    test "get/2 no-ops when process_key is nil or empty" do
      AgentRiskScoreStore.put("agent-a", snap())
      assert AgentRiskScoreStore.get("agent-a", nil) == nil
      assert AgentRiskScoreStore.get("agent-a", "") == nil
    end

    test "upsert replaces previous snapshot" do
      AgentRiskScoreStore.put("agent-a", snap(score_0_1: 0.1))
      AgentRiskScoreStore.put("agent-a", snap(score_0_1: 0.9))
      assert %{score_0_1: 0.9} = AgentRiskScoreStore.get("agent-a", "powershell.exe")
    end
  end

  describe "cleanup/1" do
    test "evicts entries older than max_age" do
      now = System.system_time(:millisecond)
      old = now - 60 * 60 * 1000

      AgentRiskScoreStore.put("agent-old", snap(process_key: "old.exe", snapshot_at_ms: old))
      AgentRiskScoreStore.put("agent-new", snap(process_key: "new.exe", snapshot_at_ms: now))

      assert AgentRiskScoreStore.size() == 2
      evicted = AgentRiskScoreStore.cleanup(now)
      assert evicted == 1
      assert AgentRiskScoreStore.get("agent-old", "old.exe") == nil
      assert AgentRiskScoreStore.get("agent-new", "new.exe") != nil
    end
  end
end
