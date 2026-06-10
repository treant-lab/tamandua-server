defmodule TamanduaServer.Hunting.QueryDSLTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Hunting.QueryDSL

  describe "parse_query/2 - visual format" do
    test "parses simple visual query" do
      query = %{
        "conditions" => [
          %{
            "field" => "event.type",
            "operator" => "eq",
            "value" => "process"
          }
        ],
        "logic" => "AND"
      }

      assert {:ok, dsl} = QueryDSL.parse_query(query, :visual)
      assert dsl.source == "events"
      assert [{:condition, "event.type", :eq, "process"}] = dsl.filters
    end

    test "parses nested visual query with AND/OR logic" do
      query = %{
        "conditions" => [
          %{
            "field" => "event.type",
            "operator" => "eq",
            "value" => "process"
          },
          %{
            "logic" => "OR",
            "conditions" => [
              %{
                "field" => "process.name",
                "operator" => "eq",
                "value" => "powershell.exe"
              },
              %{
                "field" => "process.name",
                "operator" => "eq",
                "value" => "cmd.exe"
              }
            ]
          }
        ],
        "logic" => "AND"
      }

      assert {:ok, dsl} = QueryDSL.parse_query(query, :visual)
      assert is_list(dsl.filters)
      assert length(dsl.filters) == 1
    end

    test "parses visual query with aggregations" do
      query = %{
        "conditions" => [],
        "logic" => "AND",
        "aggregations" => [
          %{
            "function" => "count",
            "field" => nil,
            "alias" => "event_count"
          },
          %{
            "function" => "dcount",
            "field" => "agent.hostname",
            "alias" => "unique_hosts"
          }
        ],
        "grouping" => ["event.type"]
      }

      assert {:ok, dsl} = QueryDSL.parse_query(query, :visual)
      assert length(dsl.aggregations) == 2
      assert dsl.grouping == ["event.type"]
    end

    test "parses visual query with time range" do
      query = %{
        "conditions" => [],
        "logic" => "AND",
        "time_range" => %{
          "preset" => "last_24h"
        }
      }

      assert {:ok, dsl} = QueryDSL.parse_query(query, :visual)
      assert dsl.time_range == %{"preset" => "last_24h"}
    end
  end

  describe "parse_query/2 - TQL format" do
    test "parses simple TQL query" do
      tql = "events | where event.type == \"process\" | limit 100"

      assert {:ok, dsl} = QueryDSL.parse_query(tql, :tql)
      assert dsl.source == "events"
      assert dsl.limit == 100
    end

    test "parses TQL with multiple where clauses" do
      tql = """
      events
      | where event.type == "process"
      | where process.name == "powershell.exe"
      | where process.cmdline contains "-enc"
      | limit 50
      """

      assert {:ok, dsl} = QueryDSL.parse_query(tql, :tql)
      assert dsl.source == "events"
      assert length(dsl.filters) == 3
      assert dsl.limit == 50
    end

    test "parses TQL with aggregations" do
      tql = """
      events
      | where event.type == "network"
      | summarize connection_count = count(), unique_ips = dcount(network.remote_ip) by agent.hostname
      | sort connection_count desc
      """

      assert {:ok, dsl} = QueryDSL.parse_query(tql, :tql)
      assert length(dsl.aggregations) == 2
      assert dsl.grouping == ["agent.hostname"]
    end

    test "parses TQL with complex boolean logic" do
      tql = """
      events
      | where event.type == "process"
         and (process.name == "powershell.exe" or process.name == "cmd.exe")
         and process.is_elevated == true
      | limit 100
      """

      assert {:ok, dsl} = QueryDSL.parse_query(tql, :tql)
      assert is_list(dsl.filters)
    end

    test "returns error for invalid TQL syntax" do
      tql = "events | where invalid syntax here"

      assert {:error, message} = QueryDSL.parse_query(tql, :tql)
      assert message =~ "parse error"
    end
  end

  describe "parse_query/2 - YAML format" do
    test "parses Sigma-like YAML query" do
      yaml = """
      title: Test Detection
      description: A test query
      detection:
        selection:
          event.type: process
          process.name: powershell.exe
        condition: selection
      level: medium
      """

      assert {:ok, dsl} = QueryDSL.parse_query(yaml, :yaml)
      assert dsl.source == "events"
      assert dsl.metadata.title == "Test Detection"
    end

    test "parses YAML with wildcard values" do
      yaml = """
      detection:
        selection:
          process.cmdline:
            - "*-enc*"
            - "*EncodedCommand*"
        condition: selection
      """

      assert {:ok, dsl} = QueryDSL.parse_query(yaml, :yaml)
      assert is_list(dsl.filters)
    end
  end

  describe "compile/2" do
    test "compiles simple DSL to Ecto query" do
      dsl = %{
        source: "events",
        filters: [
          {:condition, "event.type", :eq, "process"}
        ],
        aggregations: [],
        grouping: [],
        sorting: [],
        limit: 100
      }

      assert {:ok, query} = QueryDSL.compile(dsl)
      assert %Ecto.Query{} = query
    end

    test "compiles DSL with aggregations" do
      dsl = %{
        source: "events",
        filters: [],
        aggregations: [
          %{function: :count, field: nil, alias: "count_"},
          %{function: :dcount, field: "agent.hostname", alias: "unique_hosts"}
        ],
        grouping: ["event.type"],
        sorting: [],
        limit: nil
      }

      assert {:ok, query} = QueryDSL.compile(dsl)
      assert %Ecto.Query{} = query
    end

    test "compiles DSL with organization scope" do
      org_id = Ecto.UUID.generate()

      dsl = %{
        source: "events",
        filters: [],
        aggregations: [],
        grouping: [],
        sorting: [],
        limit: 100
      }

      assert {:ok, query} = QueryDSL.compile(dsl, organization_id: org_id)
      assert %Ecto.Query{} = query
    end

    test "returns error for unknown source" do
      dsl = %{
        source: "unknown_table",
        filters: [],
        aggregations: [],
        grouping: [],
        sorting: [],
        limit: 100
      }

      assert {:error, message} = QueryDSL.compile(dsl)
      assert message =~ "Unknown query source"
    end
  end

  describe "validate/2" do
    test "validates correct TQL query" do
      tql = "events | where event.type == \"process\" | limit 100"

      assert {:ok, warnings} = QueryDSL.validate(tql, :tql)
      assert is_list(warnings)
    end

    test "returns warnings for overly broad query" do
      tql = "events | limit 10000"

      assert {:ok, warnings} = QueryDSL.validate(tql, :tql)
      assert Enum.any?(warnings, fn w -> w.type == :warning end)
    end

    test "returns error for invalid query" do
      tql = "invalid query syntax"

      assert {:error, errors} = QueryDSL.validate(tql, :tql)
      assert is_list(errors)
      assert Enum.any?(errors, fn e -> e.type == :error end)
    end

    test "warns about missing time range" do
      visual_query = %{
        "conditions" => [
          %{"field" => "event.type", "operator" => "eq", "value" => "process"}
        ],
        "logic" => "AND"
      }

      assert {:ok, warnings} = QueryDSL.validate(visual_query, :visual)

      assert Enum.any?(warnings, fn w ->
               w.message =~ "time range"
             end)
    end
  end

  describe "autocomplete_field/3" do
    test "returns suggestions for event.type" do
      assert {:ok, suggestions} = QueryDSL.autocomplete_field("event.type", "pro", [])
      assert "process" in suggestions
    end

    test "returns suggestions for agent.os" do
      assert {:ok, suggestions} = QueryDSL.autocomplete_field("agent.os", "", [])
      assert "windows" in suggestions
      assert "linux" in suggestions
      assert "macos" in suggestions
    end

    test "returns empty list for unknown fields" do
      assert {:ok, []} = QueryDSL.autocomplete_field("unknown.field", "test", [])
    end
  end

  describe "to_visual_format/1" do
    test "converts DSL to visual format" do
      dsl = %{
        source: "events",
        filters: [
          {:condition, "event.type", :eq, "process"}
        ],
        aggregations: [],
        grouping: [],
        sorting: [],
        limit: 100,
        time_range: nil
      }

      visual = QueryDSL.to_visual_format(dsl)

      assert visual["conditions"] == [
               %{"field" => "event.type", "operator" => "eq", "value" => "process"}
             ]

      assert visual["logic"] == "AND"
      assert visual["limit"] == 100
    end

    test "converts complex nested logic" do
      dsl = %{
        source: "events",
        filters: [
          {:logic, :and, [
            {:condition, "event.type", :eq, "process"},
            {:logic, :or, [
              {:condition, "process.name", :eq, "powershell.exe"},
              {:condition, "process.name", :eq, "cmd.exe"}
            ]}
          ]}
        ],
        aggregations: [],
        grouping: [],
        sorting: [],
        limit: nil,
        time_range: nil
      }

      visual = QueryDSL.to_visual_format(dsl)
      assert is_list(visual["conditions"])
    end
  end

  describe "to_tql/1" do
    test "converts DSL to TQL string" do
      dsl = %{
        source: "events",
        filters: [
          {:condition, "event.type", :eq, "process"}
        ],
        aggregations: [],
        grouping: [],
        sorting: [],
        limit: 100
      }

      tql = QueryDSL.to_tql(dsl)

      assert tql =~ "events"
      assert tql =~ "where event.type == \"process\""
      assert tql =~ "limit 100"
    end

    test "converts aggregations to TQL" do
      dsl = %{
        source: "events",
        filters: [],
        aggregations: [
          %{function: :count, field: nil, alias: "count_"},
          %{function: :sum, field: "network.bytes_sent", alias: "total_bytes"}
        ],
        grouping: ["agent.hostname"],
        sorting: [],
        limit: nil
      }

      tql = QueryDSL.to_tql(dsl)

      assert tql =~ "summarize"
      assert tql =~ "count_()"
      assert tql =~ "total_bytes = sum(network.bytes_sent)"
      assert tql =~ "by agent.hostname"
    end

    test "converts sorting to TQL" do
      dsl = %{
        source: "events",
        filters: [],
        aggregations: [],
        grouping: [],
        sorting: [
          {"agent.hostname", :asc},
          {"inserted_at", :desc}
        ],
        limit: nil
      }

      tql = QueryDSL.to_tql(dsl)

      assert tql =~ "sort agent.hostname asc, inserted_at desc"
    end
  end
end
