defmodule TamanduaServer.Detection.RiskScoreSnapshotTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Detection.RiskScoreSnapshot

  describe "from_event/1" do
    test "decodes a full payload with atom keys" do
      event = %{
        event_id: "evt-1",
        event_type: "behavioral_risk_score",
        payload: %{
          process_key: "Powershell.exe",
          pid: 1234,
          score: 47.5,
          last_update: 1_719_000_000_000,
          snapshot_at: 1_719_000_000_010,
          factors: [%{name: "office_shell_spawn", score: 25.0}]
        }
      }

      assert {:ok, snap} = RiskScoreSnapshot.from_event(event)
      assert snap.process_key == "powershell.exe"
      assert snap.pid == 1234
      assert_in_delta snap.score_0_1, 0.475, 1.0e-6
      assert snap.score_raw == 47.5
      assert snap.last_update_ms == 1_719_000_000_000
      assert snap.snapshot_at_ms == 1_719_000_000_010
      assert length(snap.factors) == 1
    end

    test "decodes a full payload with string keys" do
      event = %{
        "event_type" => "behavioral_risk_score",
        "payload" => %{
          "process_key" => "PWSH.EXE",
          "pid" => 9999,
          "score" => 12.0,
          "last_update" => 100,
          "snapshot_at" => 101,
          "factors" => []
        }
      }

      assert {:ok, snap} = RiskScoreSnapshot.from_event(event)
      assert snap.process_key == "pwsh.exe"
      assert snap.pid == 9999
      assert_in_delta snap.score_0_1, 0.12, 1.0e-6
    end

    test "treats missing pid as nil (agent emits this; expected)" do
      event = %{payload: %{process_key: "cmd.exe", score: 30.0}}
      assert {:ok, %{pid: nil}} = RiskScoreSnapshot.from_event(event)
    end

    test "returns :error on missing process_key" do
      event = %{payload: %{score: 50.0}}
      assert :error = RiskScoreSnapshot.from_event(event)
    end

    test "returns :error on blank process_key" do
      event = %{payload: %{process_key: "   ", score: 50.0}}
      assert :error = RiskScoreSnapshot.from_event(event)
    end

    test "returns :error on missing score" do
      event = %{payload: %{process_key: "x.exe"}}
      assert :error = RiskScoreSnapshot.from_event(event)
    end

    test "returns :error on non-numeric score" do
      event = %{payload: %{process_key: "x.exe", score: "not-a-number"}}
      assert :error = RiskScoreSnapshot.from_event(event)
    end

    test "accepts integer score (Broadway may coerce floats)" do
      event = %{payload: %{process_key: "x.exe", score: 80}}
      assert {:ok, snap} = RiskScoreSnapshot.from_event(event)
      assert_in_delta snap.score_0_1, 0.80, 1.0e-6
    end

    test "clamps scores above 100 to 1.0" do
      event = %{payload: %{process_key: "x.exe", score: 200.0}}
      assert {:ok, %{score_0_1: 1.0}} = RiskScoreSnapshot.from_event(event)
    end

    test "clamps negative scores to 0.0" do
      event = %{payload: %{process_key: "x.exe", score: -10.0}}
      assert {:ok, %{score_0_1: 0.0}} = RiskScoreSnapshot.from_event(event)
    end

    test "defaults missing timestamps to 0 (downstream treats 0 as never)" do
      event = %{payload: %{process_key: "x.exe", score: 50.0}}
      assert {:ok, %{last_update_ms: 0, snapshot_at_ms: 0}} = RiskScoreSnapshot.from_event(event)
    end

    test "returns :error on non-map input" do
      assert :error = RiskScoreSnapshot.from_event(nil)
      assert :error = RiskScoreSnapshot.from_event("not a map")
      assert :error = RiskScoreSnapshot.from_event(123)
    end
  end

  describe "stale?/3" do
    setup do
      now = 1_719_000_000_000
      {:ok, %{now: now}}
    end

    test "false when snapshot is within threshold", %{now: now} do
      snap = %{snapshot_at_ms: now - 10_000}
      refute RiskScoreSnapshot.stale?(snap, now)
    end

    test "true when snapshot is older than default threshold (60s)", %{now: now} do
      snap = %{snapshot_at_ms: now - 70_000}
      assert RiskScoreSnapshot.stale?(snap, now)
    end

    test "false when snapshot_at_ms is 0 (never seen — not stale, just empty)", %{now: now} do
      snap = %{snapshot_at_ms: 0}
      refute RiskScoreSnapshot.stale?(snap, now)
    end

    test "honors custom threshold", %{now: now} do
      snap = %{snapshot_at_ms: now - 30_000}
      refute RiskScoreSnapshot.stale?(snap, now, 60_000)
      assert RiskScoreSnapshot.stale?(snap, now, 10_000)
    end
  end
end
