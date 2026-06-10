defmodule TamanduaServer.Hunting.QueryBuilderTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.Hunting.QueryBuilder
  alias TamanduaServer.Telemetry.Event
  alias TamanduaServer.Agents.Agent

  describe "parse/1" do
    test "parses simple SELECT query" do
      query = "SELECT event_type, timestamp FROM events WHERE event_type = 'process_create' LIMIT 10"

      assert {:ok, parsed} = QueryBuilder.parse(query)
      assert parsed.select == ["event_type", "timestamp"]
      assert parsed.from == :events
      assert parsed.limit == 10
      assert parsed.distinct == false
    end

    test "parses SELECT with DISTINCT" do
      query = "SELECT DISTINCT event_type FROM events LIMIT 100"

      assert {:ok, parsed} = QueryBuilder.parse(query)
      assert parsed.distinct == true
      assert parsed.select == ["event_type"]
    end

    test "parses SELECT with COUNT(*)" do
      query = "SELECT COUNT(*) FROM events WHERE event_type = 'process_create'"

      assert {:ok, parsed} = QueryBuilder.parse(query)
      assert length(parsed.aggregations) == 1
      assert hd(parsed.aggregations).type == :count
    end

    test "parses SELECT with GROUP BY" do
      query = "SELECT event_type, COUNT(*) as count FROM events GROUP BY event_type ORDER BY count DESC"

      assert {:ok, parsed} = QueryBuilder.parse(query)
      assert parsed.select == ["event_type"]
      assert parsed.group_by == ["event_type"]
      assert length(parsed.aggregations) == 1
      assert length(parsed.order_by) == 1
    end

    test "parses WHERE with multiple conditions" do
      query = "SELECT * FROM events WHERE event_type = 'process_create' AND severity = 'high'"

      assert {:ok, parsed} = QueryBuilder.parse(query)
      assert parsed.where != nil
    end

    test "parses WHERE with IN clause" do
      query = "SELECT * FROM events WHERE event_type IN ('process_create', 'file_write')"

      assert {:ok, parsed} = QueryBuilder.parse(query)
      assert parsed.where != nil
    end

    test "parses WHERE with LIKE" do
      query = "SELECT * FROM events WHERE event_type LIKE '%process%'"

      assert {:ok, parsed} = QueryBuilder.parse(query)
      assert parsed.where != nil
    end

    test "parses WHERE with time interval" do
      query = "SELECT * FROM events WHERE timestamp > NOW() - INTERVAL '1 hour'"

      assert {:ok, parsed} = QueryBuilder.parse(query)
      assert parsed.where != nil
    end

    test "parses ORDER BY with direction" do
      query = "SELECT * FROM events ORDER BY timestamp DESC LIMIT 50"

      assert {:ok, parsed} = QueryBuilder.parse(query)
      assert parsed.order_by == [{"timestamp", :desc}]
    end

    test "parses COUNT(DISTINCT field)" do
      query = "SELECT COUNT(DISTINCT event_type) as unique_types FROM events"

      assert {:ok, parsed} = QueryBuilder.parse(query)
      assert length(parsed.aggregations) == 1

      agg = hd(parsed.aggregations)
      assert agg.type == :count
      assert agg.distinct == true
      assert agg.field == "event_type"
    end

    test "parses GROUP BY with HAVING clause" do
      query = "SELECT agent_id, COUNT(*) as cnt FROM events WHERE event_type = 'process_create' GROUP BY agent_id HAVING COUNT(*) > 100"

      assert {:ok, parsed} = QueryBuilder.parse(query)
      assert parsed.select == ["agent_id"]
      assert parsed.group_by == ["agent_id"]
      assert length(parsed.aggregations) == 1
      assert parsed.having != nil
    end

    test "parses HAVING with aggregate alias" do
      query = "SELECT event_type, COUNT(*) as count FROM events GROUP BY event_type HAVING count > 5"

      assert {:ok, parsed} = QueryBuilder.parse(query)
      assert parsed.having != nil
      assert parsed.group_by == ["event_type"]
    end

    test "parses HAVING with SUM function" do
      query = "SELECT agent_id, SUM(payload->>'size') as total_size FROM events GROUP BY agent_id HAVING SUM(payload->>'size') > 1000000"

      assert {:ok, parsed} = QueryBuilder.parse(query)
      assert parsed.having != nil
    end

    test "parses HAVING with multiple conditions" do
      query = "SELECT agent_id, COUNT(*) as cnt, AVG(severity) as avg_sev FROM events GROUP BY agent_id HAVING COUNT(*) > 10 AND AVG(severity) > 2"

      assert {:ok, parsed} = QueryBuilder.parse(query)
      assert parsed.having != nil
    end

    test "returns error for invalid syntax" do
      query = "SELECT FROM WHERE"

      assert {:error, _} = QueryBuilder.parse(query)
    end
  end

  describe "build_query/1" do
    test "builds basic SELECT query" do
      parsed = %{
        select: ["event_type"],
        distinct: false,
        aggregations: [],
        from: :events,
        where: nil,
        group_by: [],
        having: nil,
        order_by: [],
        limit: 10
      }

      assert {:ok, ecto_query} = QueryBuilder.build_query(parsed)
      assert %Ecto.Query{} = ecto_query
    end

    test "builds query with WHERE clause" do
      parsed = %{
        select: ["*"],
        distinct: false,
        aggregations: [],
        from: :events,
        where: {:eq, "event_type", "process_create"},
        group_by: [],
        having: nil,
        order_by: [],
        limit: 10
      }

      assert {:ok, ecto_query} = QueryBuilder.build_query(parsed)
      assert %Ecto.Query{} = ecto_query
    end

    test "builds query with GROUP BY and aggregations" do
      parsed = %{
        select: ["event_type"],
        distinct: false,
        aggregations: [
          %{type: :count, field: nil, distinct: false, alias: :count}
        ],
        from: :events,
        where: nil,
        group_by: ["event_type"],
        having: nil,
        order_by: [],
        limit: 100
      }

      assert {:ok, ecto_query} = QueryBuilder.build_query(parsed)
      assert %Ecto.Query{} = ecto_query
    end

    test "builds query with HAVING clause" do
      parsed = %{
        select: ["event_type"],
        distinct: false,
        aggregations: [
          %{type: :count, field: nil, distinct: false, alias: :count}
        ],
        from: :events,
        where: nil,
        group_by: ["event_type"],
        having: {:gt, "COUNT(*)", 10},
        order_by: [],
        limit: 100
      }

      assert {:ok, ecto_query} = QueryBuilder.build_query(parsed)
      assert %Ecto.Query{} = ecto_query
    end

    test "builds query with HAVING using aggregate alias" do
      parsed = %{
        select: ["agent_id"],
        distinct: false,
        aggregations: [
          %{type: :count, field: nil, distinct: false, alias: :cnt}
        ],
        from: :events,
        where: {:eq, "event_type", "process_create"},
        group_by: ["agent_id"],
        having: {:gt, "cnt", 100},
        order_by: [],
        limit: 50
      }

      assert {:ok, ecto_query} = QueryBuilder.build_query(parsed)
      assert %Ecto.Query{} = ecto_query
    end

    test "rejects non-events table" do
      parsed = %{
        select: ["*"],
        distinct: false,
        aggregations: [],
        from: :alerts,
        where: nil,
        group_by: [],
        having: nil,
        order_by: [],
        limit: 10
      }

      assert {:error, msg} = QueryBuilder.build_query(parsed)
      assert msg =~ "Only 'events' table is supported"
    end
  end

  describe "execute/1 integration" do
    setup do
      # Create test agent
      agent = %Agent{
        agent_id: "test-agent-#{System.unique_integer([:positive])}",
        hostname: "test-host",
        os_type: "windows",
        status: "online"
      }
      |> Repo.insert!()

      # Create test events
      events = [
        %Event{
          agent_id: agent.id,
          event_type: "process_create",
          timestamp: DateTime.utc_now() |> DateTime.add(-3600, :second),
          payload: %{"process_name" => "powershell.exe", "pid" => 1234},
          severity: "medium"
        },
        %Event{
          agent_id: agent.id,
          event_type: "process_create",
          timestamp: DateTime.utc_now() |> DateTime.add(-1800, :second),
          payload: %{"process_name" => "cmd.exe", "pid" => 5678},
          severity: "low"
        },
        %Event{
          agent_id: agent.id,
          event_type: "file_write",
          timestamp: DateTime.utc_now() |> DateTime.add(-900, :second),
          payload: %{"file_path" => "C:\\test.exe", "size" => 102400},
          severity: "high"
        },
        %Event{
          agent_id: agent.id,
          event_type: "network_connect",
          timestamp: DateTime.utc_now() |> DateTime.add(-300, :second),
          payload: %{"dst_ip" => "192.168.1.1", "dst_port" => 443},
          severity: "medium"
        }
      ]
      |> Enum.map(&Repo.insert!/1)

      %{agent: agent, events: events}
    end

    test "executes simple SELECT query", %{events: _events} do
      query = "SELECT * FROM events WHERE event_type = 'process_create' LIMIT 10"

      assert {:ok, result} = QueryBuilder.execute(query)
      assert is_list(result.data)
      assert result.meta.total >= 0
      assert is_integer(result.meta.execution_time_ms)
      assert is_binary(result.meta.sql)
    end

    test "executes COUNT aggregation", %{events: _events} do
      query = "SELECT COUNT(*) as count FROM events WHERE event_type = 'process_create'"

      assert {:ok, result} = QueryBuilder.execute(query)
      assert is_list(result.data)
      assert result.meta.total >= 0
    end

    test "executes GROUP BY query", %{events: _events} do
      query = "SELECT event_type, COUNT(*) as count FROM events GROUP BY event_type ORDER BY count DESC"

      assert {:ok, result} = QueryBuilder.execute(query)
      assert is_list(result.data)
      assert result.meta.total >= 0
    end

    test "executes DISTINCT query", %{events: _events} do
      query = "SELECT DISTINCT event_type FROM events"

      assert {:ok, result} = QueryBuilder.execute(query)
      assert is_list(result.data)
    end

    test "executes time-based WHERE clause", %{events: _events} do
      query = "SELECT * FROM events WHERE timestamp > NOW() - INTERVAL '2 hours' LIMIT 100"

      assert {:ok, result} = QueryBuilder.execute(query)
      assert is_list(result.data)
      assert result.meta.total >= 0
    end

    test "executes IN clause", %{events: _events} do
      query = "SELECT * FROM events WHERE event_type IN ('process_create', 'file_write') LIMIT 10"

      assert {:ok, result} = QueryBuilder.execute(query)
      assert is_list(result.data)
    end

    test "executes severity filter", %{events: _events} do
      query = "SELECT * FROM events WHERE severity = 'high' LIMIT 10"

      assert {:ok, result} = QueryBuilder.execute(query)
      assert is_list(result.data)
    end

    test "executes HAVING clause with COUNT", %{events: _events} do
      query = "SELECT agent_id, COUNT(*) as cnt FROM events GROUP BY agent_id HAVING COUNT(*) > 1"

      assert {:ok, result} = QueryBuilder.execute(query)
      assert is_list(result.data)
      # Should return agents with more than 1 event
      assert result.meta.total >= 0
    end

    test "executes HAVING with aggregate alias", %{events: _events} do
      query = "SELECT event_type, COUNT(*) as count FROM events GROUP BY event_type HAVING count >= 1 ORDER BY count DESC"

      assert {:ok, result} = QueryBuilder.execute(query)
      assert is_list(result.data)
      assert result.meta.total >= 0
    end

    test "executes complex query with WHERE, GROUP BY, HAVING, ORDER BY", %{events: _events} do
      query = """
      SELECT event_type, COUNT(*) as event_count
      FROM events
      WHERE timestamp > NOW() - INTERVAL '1 day'
      GROUP BY event_type
      HAVING COUNT(*) > 0
      ORDER BY event_count DESC
      LIMIT 10
      """

      assert {:ok, result} = QueryBuilder.execute(query)
      assert is_list(result.data)
      assert result.meta.total >= 0
    end
  end
end
