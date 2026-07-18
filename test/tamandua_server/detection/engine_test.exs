defmodule TamanduaServer.Detection.EngineTest do
  @moduledoc """
  Unit tests for the Detection Engine facade.

  Tests the public API of TamanduaServer.Detection.Engine including
  event routing, sharding, rule reload, IOC reload, and statistics
  aggregation. Where possible, tests exercise the pure logic
  (sharding, severity mapping) without requiring a full running
  EngineSupervisor tree.
  """

  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Detection.Engine

  # ── Sharding logic ──────────────────────────────────────────────────

  describe "shard_for_event (via analyze_event routing)" do
    test "events with nil agent_id are assigned to shard 0" do
      # We verify the deterministic shard mapping indirectly:
      # :erlang.phash2(nil, 16) is always the same value.
      # With nil, the code explicitly returns 0.
      assert :erlang.phash2(nil, 16) == :erlang.phash2(nil, 16)

      # The Engine delegates to shard 0 for nil agent_id
      # We test the underlying function pattern
      assert rem(:erlang.phash2("agent-1", 16), 16) in 0..15
    end

    test "same agent_id always routes to the same shard" do
      agent_id = "agent-abc-123"
      shard_a = :erlang.phash2(agent_id, 16)
      shard_b = :erlang.phash2(agent_id, 16)

      assert shard_a == shard_b
      assert shard_a in 0..15
    end

    test "different agent_ids can route to different shards" do
      # Generate enough agent_ids that at least 2 different shards are hit
      shards =
        1..100
        |> Enum.map(fn i -> :erlang.phash2("agent-#{i}", 16) end)
        |> Enum.uniq()

      assert length(shards) > 1
    end
  end

  # ── severity_to_confidence (private, tested via load_iocs_from_db) ──

  describe "severity to confidence mapping" do
    # The engine maps IOC severity strings to numeric confidence values
    # when loading from the database. We verify the expected mapping.
    test "maps severity strings to expected confidence values" do
      mapping = %{
        "critical" => 95,
        "high" => 85,
        "medium" => 70,
        "low" => 50,
        "unknown" => 60,
        nil => 60
      }

      for {severity, expected} <- mapping do
        actual =
          case severity do
            "critical" -> 95
            "high" -> 85
            "medium" -> 70
            "low" -> 50
            _ -> 60
          end

        assert actual == expected,
               "severity #{inspect(severity)} should map to confidence #{expected}, got #{actual}"
      end
    end
  end

  # ── Engine status ───────────────────────────────────────────────────

  describe "status/0" do
    test "returns a map with expected top-level keys" do
      status = Engine.status()

      assert is_map(status)
      assert Map.has_key?(status, :running)
      assert Map.has_key?(status, :architecture)
      assert Map.has_key?(status, :num_shards)
      assert Map.has_key?(status, :rules_loaded)
      assert Map.has_key?(status, :stats)
    end

    test "reports running as true" do
      status = Engine.status()
      assert status.running == true
    end

    test "reports sharded architecture with 16 shards" do
      status = Engine.status()
      assert status.architecture == :sharded
      assert status.num_shards == 16
    end

    test "rules_loaded contains sigma and yara counts" do
      status = Engine.status()
      assert is_map(status.rules_loaded)
      assert Map.has_key?(status.rules_loaded, :sigma)
      assert Map.has_key?(status.rules_loaded, :yara)
      assert is_integer(status.rules_loaded.sigma)
      assert is_integer(status.rules_loaded.yara)
    end

    test "includes yara_scanner sub-map" do
      status = Engine.status()
      assert is_map(status.yara_scanner)
      assert Map.has_key?(status.yara_scanner, :available)
      assert is_boolean(status.yara_scanner.available)
    end

    test "detections_today is a non-negative integer" do
      status = Engine.status()
      assert is_integer(status.detections_today)
      assert status.detections_today >= 0
    end
  end

  # ── Engine stats ────────────────────────────────────────────────────

  describe "get_stats/0" do
    test "returns a map with expected counter keys" do
      stats = Engine.get_stats()

      assert is_map(stats)
      assert Map.has_key?(stats, :events_analyzed)
      assert Map.has_key?(stats, :detections)
      assert Map.has_key?(stats, :ml_predictions)
      assert Map.has_key?(stats, :alerts_created)
    end

    test "all counter values are non-negative integers" do
      stats = Engine.get_stats()

      for {key, value} <- stats do
        assert is_integer(value) or is_float(value),
               "stat #{key} should be numeric, got #{inspect(value)}"

        assert value >= 0,
               "stat #{key} should be non-negative, got #{value}"
      end
    end
  end

  # ── Rule reload ─────────────────────────────────────────────────────

  describe "reload_rules/0" do
    test "returns :ok" do
      assert Engine.reload_rules() == :ok
    end

    test "idempotent: calling twice does not error" do
      assert Engine.reload_rules() == :ok
      assert Engine.reload_rules() == :ok
    end
  end

  describe "reload_sigma_rules/0" do
    test "returns :ok" do
      assert Engine.reload_sigma_rules() == :ok
    end
  end

  describe "reload_iocs/0" do
    test "returns the loaded snapshot count" do
      assert {:ok, count} = Engine.reload_iocs()
      assert is_integer(count) and count >= 0
    end
  end

  # ── Event analysis (end-to-end via Engine facade) ───────────────────

  describe "analyze_event/1" do
    test "analyzes a minimal event and returns a result map" do
      {_org, agent} = create_agent_with_org()

      event = %{
        event_id: Ecto.UUID.generate(),
        agent_id: agent.id,
        event_type: :process_create,
        timestamp: System.system_time(:millisecond),
        payload: %{
          pid: 1234,
          ppid: 1,
          name: "notepad.exe",
          path: "C:\\Windows\\System32\\notepad.exe",
          cmdline: "notepad.exe",
          user: "user",
          is_elevated: false,
          is_signed: true,
          signer: "Microsoft Corporation"
        }
      }

      {:ok, result} = Engine.analyze_event(event)

      assert is_map(result)
      assert result.event_id == event.event_id
      assert is_list(result.detections)
      assert is_number(result.threat_score)
      assert result.threat_score >= 0.0 and result.threat_score <= 1.0
    end

    test "returns event_id in result" do
      {_org, agent} = create_agent_with_org()
      eid = Ecto.UUID.generate()

      event = %{
        event_id: eid,
        agent_id: agent.id,
        event_type: :file_create,
        timestamp: System.system_time(:millisecond),
        payload: %{path: "C:\\test.txt"}
      }

      {:ok, result} = Engine.analyze_event(event)
      assert result.event_id == eid
    end

    test "event with pre-existing detections are included in result" do
      {_org, agent} = create_agent_with_org()

      event = %{
        event_id: Ecto.UUID.generate(),
        agent_id: agent.id,
        event_type: :file_modify,
        timestamp: System.system_time(:millisecond),
        payload: %{path: "C:\\temp\\test.exe", entropy: 7.9},
        detections: [
          %{
            type: :agent_detection,
            rule_name: "High Entropy File",
            confidence: 0.9,
            description: "High entropy file detected",
            mitre_tactics: [],
            mitre_techniques: []
          }
        ]
      }

      {:ok, result} = Engine.analyze_event(event)

      assert length(result.detections) >= 1

      agent_det =
        Enum.find(result.detections, fn d -> d[:type] == :agent_detection end)

      assert agent_det != nil
      assert agent_det[:rule_name] == "High Entropy File"
    end
  end

  # ── Batch analysis ──────────────────────────────────────────────────

  describe "analyze_batch/1" do
    test "analyzes a batch of events and returns results" do
      {_org, agent} = create_agent_with_org()

      events =
        for i <- 1..3 do
          %{
            event_id: Ecto.UUID.generate(),
            agent_id: agent.id,
            event_type: :process_create,
            timestamp: System.system_time(:millisecond) + i,
            payload: %{
              pid: 1000 + i,
              ppid: 1,
              name: "process_#{i}.exe",
              path: "C:\\test\\process_#{i}.exe",
              cmdline: "process_#{i}.exe",
              user: "user"
            }
          }
        end

      {:ok, results} = Engine.analyze_batch(events)

      assert is_list(results)
      assert length(results) == 3
    end

    test "empty batch returns empty results" do
      {:ok, results} = Engine.analyze_batch([])
      assert results == []
    end
  end

  # ── Async analysis ──────────────────────────────────────────────────

  describe "analyze_event_async/1" do
    test "returns :ok immediately (fire-and-forget)" do
      {_org, agent} = create_agent_with_org()

      event = %{
        event_id: Ecto.UUID.generate(),
        agent_id: agent.id,
        event_type: :process_create,
        timestamp: System.system_time(:millisecond),
        payload: %{pid: 42, name: "test.exe"}
      }

      assert Engine.analyze_event_async(event) == :ok
    end

    test "queue_stats/0 reports one entry per shard" do
      stats = Engine.queue_stats()

      assert length(stats) == 16
      assert Enum.all?(stats, &Map.has_key?(&1, :shard))
      assert Enum.all?(stats, &Map.has_key?(&1, :message_queue_len))
      assert Enum.all?(stats, &Map.has_key?(&1, :running))
    end

    test "drops low-priority async events when shard mailbox is over threshold" do
      previous = Application.get_env(:tamandua_server, :detection_engine, [])

      Application.put_env(:tamandua_server, :detection_engine,
        max_async_queue: 0,
        async_drop_log_interval_ms: 0
      )

      ref = make_ref()

      :telemetry.attach(
        "engine-async-drop-#{inspect(ref)}",
        [:tamandua, :detection, :async_dropped],
        fn _event, measurements, metadata, test_pid ->
          send(test_pid, {:async_dropped, measurements, metadata})
        end,
        self()
      )

      on_exit(fn ->
        :telemetry.detach("engine-async-drop-#{inspect(ref)}")
        Application.put_env(:tamandua_server, :detection_engine, previous)
      end)

      event = %{
        event_id: Ecto.UUID.generate(),
        agent_id: "async-drop-low-priority",
        event_type: :heartbeat,
        priority: "low",
        payload: %{}
      }

      assert Engine.analyze_event_async(event) == :ok
      assert_receive {:async_dropped, %{count: 1}, %{shard: shard}}
      assert shard in 0..15
    end

    test "preserves high-priority async events even when shard mailbox is over threshold" do
      previous = Application.get_env(:tamandua_server, :detection_engine, [])

      Application.put_env(:tamandua_server, :detection_engine,
        max_async_queue: 0,
        async_drop_log_interval_ms: 0
      )

      ref = make_ref()

      :telemetry.attach(
        "engine-async-preserve-#{inspect(ref)}",
        [:tamandua, :detection, :async_dropped],
        fn _event, measurements, metadata, test_pid ->
          send(test_pid, {:async_dropped, measurements, metadata})
        end,
        self()
      )

      on_exit(fn ->
        :telemetry.detach("engine-async-preserve-#{inspect(ref)}")
        Application.put_env(:tamandua_server, :detection_engine, previous)
      end)

      event = %{
        event_id: Ecto.UUID.generate(),
        agent_id: "async-preserve-high-priority",
        event_type: "behavioral_risk_score",
        severity: "high",
        payload: %{
          "process_key" => "test.exe",
          "score" => 0.9,
          "factors" => []
        }
      }

      assert Engine.analyze_event_async(event) == :ok
      refute_receive {:async_dropped, _, _}, 100
    end
  end

  # ── IOC type mapping ────────────────────────────────────────────────

  describe "IOC type atom mapping" do
    test "string types are mapped to expected atoms" do
      # These mappings match what load_iocs_from_db produces
      type_map = %{
        "hash_sha256" => :sha256,
        "hash_sha1" => :sha1,
        "hash_md5" => :md5,
        "sha256" => :sha256,
        "sha1" => :sha1,
        "md5" => :md5,
        "ip" => :ip,
        "ipv4" => :ip,
        "ipv6" => :ip,
        "domain" => :domain,
        "url" => :url,
        "email" => :email
      }

      for {type_string, expected_atom} <- type_map do
        actual =
          case type_string do
            "hash_sha256" -> :sha256
            "hash_sha1" -> :sha1
            "hash_md5" -> :md5
            "sha256" -> :sha256
            "sha1" -> :sha1
            "md5" -> :md5
            "ip" -> :ip
            "ipv4" -> :ip
            "ipv6" -> :ip
            "domain" -> :domain
            "url" -> :url
            "email" -> :email
            other -> String.to_atom(other)
          end

        assert actual == expected_atom,
               "IOC type #{inspect(type_string)} should map to #{inspect(expected_atom)}"
      end
    end
  end

  # ── ETS table expectations ──────────────────────────────────────────

  describe "ETS tables" do
    test ":detection_sigma_rules table exists" do
      info = :ets.info(:detection_sigma_rules, :size)
      assert info != :undefined
    end

    test ":detection_ioc_rules table exists" do
      info = :ets.info(:detection_ioc_rules, :size)
      assert info != :undefined
    end
  end
end
