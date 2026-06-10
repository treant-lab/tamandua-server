defmodule TamanduaServer.Hunting.QueryLanguageTest do
  @moduledoc """
  Unit tests for the Tamandua Query Language (TQL).

  Covers three layers:
  1. **Lexer** -- tokenization of query strings
  2. **Parser** -- AST construction from tokens
  3. **Compiler** -- SQL generation from ASTs

  Also tests:
  - Duration parsing (ago())
  - Public helpers (keywords, field_mappings, operators)
  - Error paths (unterminated strings, unknown operators)
  """

  use ExUnit.Case, async: true

  alias TamanduaServer.Hunting.QueryLanguage

  # ============================================================================
  # Lexer Tests
  # ============================================================================

  describe "tokenize/1" do
    test "tokenizes a simple equality comparison" do
      {:ok, tokens} = QueryLanguage.tokenize(~s(process.name = "cmd.exe"))

      types = Enum.map(tokens, &elem(&1, 0))

      assert :ident in types
      assert :dot in types
      assert :op in types
      assert :string in types
      assert :eof in types
    end

    test "tokenizes comparison operators" do
      {:ok, tokens} = QueryLanguage.tokenize("a != b")
      ops = tokens |> Enum.filter(fn {t, _, _} -> t == :op end) |> Enum.map(&elem(&1, 1))
      assert :neq in ops

      {:ok, tokens} = QueryLanguage.tokenize("a >= b")
      ops = tokens |> Enum.filter(fn {t, _, _} -> t == :op end) |> Enum.map(&elem(&1, 1))
      assert :gte in ops

      {:ok, tokens} = QueryLanguage.tokenize("a <= b")
      ops = tokens |> Enum.filter(fn {t, _, _} -> t == :op end) |> Enum.map(&elem(&1, 1))
      assert :lte in ops
    end

    test "tokenizes keywords case-insensitively" do
      {:ok, tokens} = QueryLanguage.tokenize("AND Or nOt WHERE limit")

      keyword_values =
        tokens
        |> Enum.reject(fn {t, _, _} -> t == :eof end)
        |> Enum.map(&elem(&1, 1))

      assert :and in keyword_values
      assert :or in keyword_values
      assert :not in keyword_values
      assert :where in keyword_values
      assert :limit in keyword_values
    end

    test "tokenizes string literals (double quotes)" do
      {:ok, tokens} = QueryLanguage.tokenize(~s(name = "hello world"))

      strings =
        tokens
        |> Enum.filter(fn {t, _, _} -> t == :string end)
        |> Enum.map(&elem(&1, 1))

      assert "hello world" in strings
    end

    test "tokenizes string literals (single quotes)" do
      {:ok, tokens} = QueryLanguage.tokenize("name = 'hello world'")

      strings =
        tokens
        |> Enum.filter(fn {t, _, _} -> t == :string end)
        |> Enum.map(&elem(&1, 1))

      assert "hello world" in strings
    end

    test "handles escape sequences in strings" do
      {:ok, tokens} = QueryLanguage.tokenize(~s(path = "C:\\\\Windows"))

      strings =
        tokens
        |> Enum.filter(fn {t, _, _} -> t == :string end)
        |> Enum.map(&elem(&1, 1))

      assert "C:\\Windows" in strings
    end

    test "tokenizes integer literals" do
      {:ok, tokens} = QueryLanguage.tokenize("port = 443")

      integers =
        tokens
        |> Enum.filter(fn {t, _, _} -> t == :integer end)
        |> Enum.map(&elem(&1, 1))

      assert 443 in integers
    end

    test "tokenizes float literals" do
      {:ok, tokens} = QueryLanguage.tokenize("score = 7.5")

      floats =
        tokens
        |> Enum.filter(fn {t, _, _} -> t == :float end)
        |> Enum.map(&elem(&1, 1))

      assert 7.5 in floats
    end

    test "tokenizes pipe operator" do
      {:ok, tokens} = QueryLanguage.tokenize("process.name = \"x\" | limit 10")

      pipe_tokens = Enum.filter(tokens, fn {t, _, _} -> t == :pipe end)
      assert length(pipe_tokens) == 1
    end

    test "tokenizes parentheses and commas" do
      {:ok, tokens} = QueryLanguage.tokenize("port IN (80, 443)")

      types = Enum.map(tokens, &elem(&1, 0))
      assert :lparen in types
      assert :rparen in types
      assert :comma in types
    end

    test "skips line comments" do
      {:ok, tokens} = QueryLanguage.tokenize("process.name = \"x\" // this is a comment")

      # Should not contain the comment text
      all_values = Enum.map(tokens, &elem(&1, 1))
      refute "comment" in all_values
      refute "this" in all_values
    end

    test "returns error for unterminated string" do
      assert {:error, msg} = QueryLanguage.tokenize(~s(name = "unterminated))
      assert String.contains?(msg, "Unterminated string")
    end

    test "recognizes aggregation keywords" do
      {:ok, tokens} = QueryLanguage.tokenize("count sum avg min max distinct_count")

      agg_types = tokens |> Enum.filter(fn {t, _, _} -> t == :kw_agg end) |> Enum.map(&elem(&1, 1))

      assert :count in agg_types
      assert :sum in agg_types
      assert :avg in agg_types
      assert :min in agg_types
      assert :max in agg_types
      assert :distinct_count in agg_types
    end

    test "recognizes sort direction keywords" do
      {:ok, tokens} = QueryLanguage.tokenize("asc desc")

      dir_values =
        tokens
        |> Enum.filter(fn {t, _, _} -> t == :kw_dir end)
        |> Enum.map(&elem(&1, 1))

      assert :asc in dir_values
      assert :desc in dir_values
    end

    test "tokenizes ago keyword" do
      {:ok, tokens} = QueryLanguage.tokenize("ago")

      has_ago = Enum.any?(tokens, fn {t, _, _} -> t == :kw_ago end)
      assert has_ago
    end
  end

  # ============================================================================
  # Parser Tests
  # ============================================================================

  describe "parse/1 (via tokenize + parse)" do
    defp parse_query(str) do
      with {:ok, tokens} <- QueryLanguage.tokenize(str),
           {:ok, ast} <- QueryLanguage.parse(tokens) do
        {:ok, ast}
      end
    end

    test "parses a simple equality filter" do
      {:ok, ast} = parse_query(~s(process.name = "cmd.exe"))

      assert ast.filter == {:comp, "process.name", :eq, {:literal, "cmd.exe"}}
      assert ast.pipes == []
    end

    test "parses inequality operator" do
      {:ok, ast} = parse_query(~s(process.name != "system"))

      assert {:comp, "process.name", :neq, {:literal, "system"}} = ast.filter
    end

    test "parses AND expressions" do
      {:ok, ast} =
        parse_query(~s(process.name = "cmd.exe" AND process.user = "SYSTEM"))

      assert {:and, left, right} = ast.filter
      assert {:comp, "process.name", :eq, {:literal, "cmd.exe"}} = left
      assert {:comp, "process.user", :eq, {:literal, "SYSTEM"}} = right
    end

    test "parses OR expressions" do
      {:ok, ast} =
        parse_query(~s(process.name = "cmd.exe" OR process.name = "powershell.exe"))

      assert {:or, _left, _right} = ast.filter
    end

    test "parses NOT expressions" do
      {:ok, ast} = parse_query(~s(NOT process.is_signed = "true"))

      assert {:not, {:comp, "process.is_signed", :eq, {:literal, "true"}}} = ast.filter
    end

    test "parses parenthesised expressions" do
      {:ok, ast} =
        parse_query(
          ~s((process.name = "cmd.exe" OR process.name = "powershell.exe") AND process.user = "SYSTEM")
        )

      assert {:and, {:or, _, _}, {:comp, "process.user", :eq, _}} = ast.filter
    end

    test "parses IN list" do
      {:ok, ast} = parse_query(~s(network.dst_port IN (80, 443, 8080)))

      assert {:in_list, "network.dst_port", values} = ast.filter
      assert length(values) == 3

      nums = Enum.map(values, fn {:literal, n} -> n end)
      assert 80 in nums
      assert 443 in nums
      assert 8080 in nums
    end

    test "parses NOT IN list" do
      {:ok, ast} = parse_query(~s(network.dst_port NOT IN (53, 123)))

      assert {:not_in_list, "network.dst_port", values} = ast.filter
      assert length(values) == 2
    end

    test "parses IN CIDR" do
      {:ok, ast} = parse_query(~s(network.dst_ip IN CIDR "10.0.0.0/8"))

      assert {:in_cidr, "network.dst_ip", "10.0.0.0/8"} = ast.filter
    end

    test "parses CONTAINS operator" do
      {:ok, ast} = parse_query(~s(process.command_line CONTAINS "mimikatz"))

      assert {:comp, "process.command_line", :contains, {:literal, "mimikatz"}} = ast.filter
    end

    test "parses STARTS_WITH operator" do
      {:ok, ast} = parse_query(~s(file.path STARTS_WITH "C:\\\\Temp"))

      assert {:comp, "file.path", :starts_with, _} = ast.filter
    end

    test "parses ENDS_WITH operator" do
      {:ok, ast} = parse_query(~s(file.path ENDS_WITH ".exe"))

      assert {:comp, "file.path", :ends_with, {:literal, ".exe"}} = ast.filter
    end

    test "parses MATCHES (glob) operator" do
      {:ok, ast} = parse_query(~s(dns.query MATCHES "*.xyz"))

      assert {:comp, "dns.query", :matches, {:literal, "*.xyz"}} = ast.filter
    end

    test "parses REGEX operator" do
      {:ok, ast} = parse_query(~s(process.name REGEX "^powershell"))

      assert {:comp, "process.name", :regex, {:literal, "^powershell"}} = ast.filter
    end

    test "parses greater-than comparison" do
      {:ok, ast} = parse_query("network.bytes_sent > 1000000")

      assert {:comp, "network.bytes_sent", :gt, {:literal, 1_000_000}} = ast.filter
    end

    test "parses less-than-or-equal comparison" do
      {:ok, ast} = parse_query("network.dst_port <= 1024")

      assert {:comp, "network.dst_port", :lte, {:literal, 1024}} = ast.filter
    end

    test "parses ago() function as value" do
      {:ok, ast} = parse_query("timestamp > ago(24h)")

      assert {:comp, "timestamp", :gt, {:ago, _duration}} = ast.filter
    end

    test "parses filter with no explicit expression (pipes only)" do
      {:ok, ast} = parse_query("| limit 10")

      assert ast.filter == nil
      assert [{:pipe_limit, 10}] = ast.pipes
    end
  end

  # ============================================================================
  # Pipe Operator Parser Tests
  # ============================================================================

  describe "pipe operators" do
    defp parse_query(str) do
      with {:ok, tokens} <- QueryLanguage.tokenize(str),
           {:ok, ast} <- QueryLanguage.parse(tokens) do
        {:ok, ast}
      end
    end

    test "parses | limit N" do
      {:ok, ast} = parse_query(~s(process.name = "x" | limit 50))

      assert [{:pipe_limit, 50}] = ast.pipes
    end

    test "parses | sort field desc" do
      {:ok, ast} = parse_query(~s(process.name = "x" | sort timestamp desc))

      assert [{:pipe_sort, [{"timestamp", :desc}]}] = ast.pipes
    end

    test "parses | sort field asc" do
      {:ok, ast} = parse_query(~s(process.name = "x" | sort process.pid asc))

      assert [{:pipe_sort, [{"process.pid", :asc}]}] = ast.pipes
    end

    test "default sort direction is desc" do
      {:ok, ast} = parse_query(~s(process.name = "x" | sort timestamp))

      assert [{:pipe_sort, [{"timestamp", :desc}]}] = ast.pipes
    end

    test "parses | count by field" do
      {:ok, ast} = parse_query(~s(process.name = "x" | count by process.name))

      assert [{:pipe_count, ["process.name"]}] = ast.pipes
    end

    test "parses | count by multiple fields" do
      {:ok, ast} = parse_query(~s(process.name = "x" | count by process.name, agent_id))

      assert [{:pipe_count, fields}] = ast.pipes
      assert "process.name" in fields
      assert "agent_id" in fields
    end

    test "parses | where (post-aggregation HAVING)" do
      {:ok, ast} =
        parse_query(~s(process.name = "x" | count by process.name | where count > 5))

      assert [{:pipe_count, _}, {:pipe_where, {:comp, "count", :gt, {:literal, 5}}}] = ast.pipes
    end

    test "parses | timeline field" do
      {:ok, ast} = parse_query(~s(process.name = "x" | timeline agent_id))

      assert [{:pipe_timeline, "agent_id"}] = ast.pipes
    end

    test "parses | stats agg(field) by group_field" do
      {:ok, ast} =
        parse_query(~s(process.name = "x" | stats sum(network.bytes_sent) by agent_id))

      assert [{:pipe_stats, [{:sum, "network.bytes_sent", _alias}], ["agent_id"]}] = ast.pipes
    end

    test "parses | stats count() by group_field" do
      {:ok, ast} =
        parse_query(~s(process.name = "x" | stats count() by process.name))

      assert [{:pipe_stats, [{:count, nil, "count"}], ["process.name"]}] = ast.pipes
    end

    test "parses multiple pipes" do
      {:ok, ast} =
        parse_query(
          ~s(process.name = "powershell.exe" | count by process.name, agent_id | where count > 5 | sort count desc | limit 20)
        )

      assert length(ast.pipes) == 4
    end

    test "returns error for unknown pipe operator" do
      assert {:error, _msg} =
               parse_query(~s(process.name = "x" | bogus_operator))
    end

    test "returns error for limit without integer" do
      assert {:error, _msg} =
               parse_query(~s(process.name = "x" | limit))
    end
  end

  # ============================================================================
  # Compiler Tests (AST -> SQL)
  # ============================================================================

  describe "compile/2 (AST -> SQL)" do
    defp compile_query(str, opts \\ []) do
      with {:ok, tokens} <- QueryLanguage.tokenize(str),
           {:ok, ast} <- QueryLanguage.parse(tokens),
           {:ok, sql} <- QueryLanguage.compile(ast, opts) do
        {:ok, sql}
      end
    end

    test "simple equality produces correct SQL" do
      {:ok, sql} = compile_query(~s(process.name = "cmd.exe"))

      assert String.contains?(sql, "SELECT *")
      assert String.contains?(sql, "FROM tamandua.process_events")
      assert String.contains?(sql, "process_name = 'cmd.exe'")
      assert String.contains?(sql, "FORMAT JSON")
    end

    test "AND produces SQL with AND" do
      {:ok, sql} =
        compile_query(~s(process.name = "cmd.exe" AND process.user = "SYSTEM"))

      assert String.contains?(sql, " AND ")
      assert String.contains?(sql, "process_name = 'cmd.exe'")
      assert String.contains?(sql, "user_name = 'SYSTEM'")
    end

    test "OR produces SQL with OR" do
      {:ok, sql} =
        compile_query(~s(process.name = "cmd.exe" OR process.name = "powershell.exe"))

      assert String.contains?(sql, " OR ")
    end

    test "NOT produces SQL with NOT" do
      {:ok, sql} = compile_query(~s(NOT process.name = "explorer.exe"))

      assert String.contains?(sql, "NOT")
    end

    test "CONTAINS generates LIKE with wildcards" do
      {:ok, sql} = compile_query(~s(process.command_line CONTAINS "mimikatz"))

      assert String.contains?(sql, "LIKE")
      assert String.contains?(sql, "%mimikatz%")
    end

    test "STARTS_WITH generates LIKE with trailing wildcard" do
      {:ok, sql} = compile_query(~s(file.path STARTS_WITH "C:\\\\Temp"))

      assert String.contains?(sql, "LIKE")
    end

    test "ENDS_WITH generates LIKE with leading wildcard" do
      {:ok, sql} = compile_query(~s(file.path ENDS_WITH ".exe"))

      assert String.contains?(sql, "LIKE")
      assert String.contains?(sql, ".exe")
    end

    test "MATCHES generates glob-to-LIKE conversion" do
      {:ok, sql} = compile_query(~s(dns.query MATCHES "*.xyz"))

      assert String.contains?(sql, "LIKE")
      assert String.contains?(sql, "%.xyz")
    end

    test "REGEX generates match() function" do
      {:ok, sql} = compile_query(~s(process.name REGEX "^powershell"))

      assert String.contains?(sql, "match(")
    end

    test "IN list generates IN clause" do
      {:ok, sql} = compile_query(~s(network.dst_port IN (80, 443, 8080)))

      assert String.contains?(sql, "IN (80, 443, 8080)")
    end

    test "NOT IN list generates NOT IN clause" do
      {:ok, sql} = compile_query(~s(network.dst_port NOT IN (53, 123)))

      assert String.contains?(sql, "NOT IN (53, 123)")
    end

    test "IN CIDR generates isIPAddressInRange" do
      {:ok, sql} = compile_query(~s(network.dst_ip IN CIDR "10.0.0.0/8"))

      assert String.contains?(sql, "isIPAddressInRange")
      assert String.contains?(sql, "10.0.0.0/8")
    end

    test "limit pipe adds LIMIT clause" do
      {:ok, sql} = compile_query(~s(process.name = "x" | limit 25))

      assert String.contains?(sql, "LIMIT 25")
    end

    test "sort pipe adds ORDER BY clause" do
      {:ok, sql} = compile_query(~s(process.name = "x" | sort timestamp desc))

      assert String.contains?(sql, "ORDER BY")
      assert String.contains?(sql, "DESC")
    end

    test "count by pipe generates GROUP BY with count()" do
      {:ok, sql} =
        compile_query(~s(process.name = "x" | count by process.name))

      assert String.contains?(sql, "GROUP BY")
      assert String.contains?(sql, "count()")
    end

    test "organization_id option injects scope filter" do
      {:ok, sql} =
        compile_query(
          ~s(process.name = "cmd.exe"),
          organization_id: "org-123"
        )

      assert String.contains?(sql, "organization_id = 'org-123'")
    end

    test "default LIMIT 1000 when no limit pipe" do
      {:ok, sql} = compile_query(~s(process.name = "x"))

      assert String.contains?(sql, "LIMIT 1000")
    end

    test "ago() compiles to ClickHouse interval" do
      {:ok, sql} = compile_query(~s(timestamp > ago(24h)))

      assert String.contains?(sql, "now()")
      assert String.contains?(sql, "INTERVAL")
      assert String.contains?(sql, "HOUR")
    end

    test "field mapping resolves table-prefixed fields" do
      {:ok, sql} = compile_query(~s(network.src_ip = "192.168.1.1"))

      # network.src_ip should resolve to source_ip column
      assert String.contains?(sql, "source_ip")
      assert String.contains?(sql, "tamandua.network_flows")
    end

    test "shared columns are kept as-is" do
      {:ok, sql} = compile_query(~s(process.name = "x" AND timestamp > ago(1h)))

      assert String.contains?(sql, "timestamp >")
    end

    test "returns error for unknown table" do
      # Field "foo.bar" does not map to any known table
      assert {:error, msg} = compile_query(~s(foo.bar = "x"))
      assert String.contains?(msg, "Cannot determine target table")
    end
  end

  # ============================================================================
  # to_sql (full pipeline shortcut)
  # ============================================================================

  describe "to_sql/1" do
    test "returns {:ok, sql_string} for valid query" do
      {:ok, sql} = QueryLanguage.to_sql(~s(process.name = "cmd.exe" | limit 10))

      assert is_binary(sql)
      assert String.contains?(sql, "SELECT")
      assert String.contains?(sql, "LIMIT 10")
    end

    test "returns error for invalid query" do
      assert {:error, _msg} = QueryLanguage.to_sql(~s(| bogus))
    end
  end

  # ============================================================================
  # validate/1
  # ============================================================================

  describe "validate/1" do
    test "returns :ok for valid query" do
      assert :ok = QueryLanguage.validate(~s(process.name = "cmd.exe" | limit 10))
    end

    test "returns error for invalid query" do
      assert {:error, _msg} = QueryLanguage.validate(~s(name = "unterminated))
    end
  end

  # ============================================================================
  # Duration Parsing
  # ============================================================================

  describe "parse_duration/1" do
    test "parses hours" do
      assert {:ok, 86400} = QueryLanguage.parse_duration("24h")
    end

    test "parses days" do
      assert {:ok, 604_800} = QueryLanguage.parse_duration("7d")
    end

    test "parses minutes" do
      assert {:ok, 1800} = QueryLanguage.parse_duration("30m")
    end

    test "parses seconds" do
      assert {:ok, 60} = QueryLanguage.parse_duration("60s")
    end

    test "parses weeks" do
      assert {:ok, 604_800} = QueryLanguage.parse_duration("1w")
    end

    test "parses compound duration" do
      {:ok, seconds} = QueryLanguage.parse_duration("1h30m")
      assert seconds == 3600 + 1800
    end

    test "returns error for invalid duration" do
      assert :error = QueryLanguage.parse_duration("invalid")
    end
  end

  # ============================================================================
  # Public Helpers
  # ============================================================================

  describe "keywords/0" do
    test "returns a list of lowercase keyword strings" do
      keywords = QueryLanguage.keywords()

      assert is_list(keywords)
      assert length(keywords) > 0

      for kw <- keywords do
        assert is_binary(kw)
        assert kw == String.downcase(kw)
      end
    end

    test "includes expected keywords" do
      keywords = QueryLanguage.keywords()

      assert "and" in keywords
      assert "or" in keywords
      assert "not" in keywords
      assert "where" in keywords
      assert "limit" in keywords
      assert "sort" in keywords
      assert "count" in keywords
    end
  end

  describe "table_sources/0" do
    test "returns map of table prefixes to ClickHouse table names" do
      sources = QueryLanguage.table_sources()

      assert is_map(sources)
      assert sources["process"] == "tamandua.process_events"
      assert sources["network"] == "tamandua.network_flows"
      assert sources["dns"] == "tamandua.dns_queries"
      assert sources["file"] == "tamandua.file_events"
      assert sources["registry"] == "tamandua.registry_events"
      assert sources["alert"] == "tamandua.alert_events"
    end
  end

  describe "operators/0" do
    test "returns map of operator strings to atoms" do
      ops = QueryLanguage.operators()

      assert is_map(ops)
      assert ops["="] == :eq
      assert ops["!="] == :neq
      assert ops[">"] == :gt
      assert ops["<"] == :lt
      assert ops[">="] == :gte
      assert ops["<="] == :lte
      assert ops["CONTAINS"] == :contains
      assert ops["MATCHES"] == :matches
      assert ops["IN"] == :in
    end
  end

  describe "aggregation_functions/0" do
    test "returns list of supported aggregation function names" do
      funcs = QueryLanguage.aggregation_functions()

      assert is_list(funcs)
      assert "count" in funcs
      assert "sum" in funcs
      assert "avg" in funcs
      assert "min" in funcs
      assert "max" in funcs
      assert "distinct_count" in funcs
    end
  end

  describe "field_mappings/0" do
    test "returns map of TQL field names to {table, column} tuples" do
      mappings = QueryLanguage.field_mappings()

      assert is_map(mappings)

      # Check a sample of known mappings
      assert {"tamandua.process_events", "process_name"} = mappings["process.name"]
      assert {"tamandua.network_flows", "dest_ip"} = mappings["network.dst_ip"]
      assert {"tamandua.dns_queries", "query_name"} = mappings["dns.query"]
      assert {"tamandua.file_events", "file_path"} = mappings["file.path"]
    end
  end

  # ============================================================================
  # func_ago / func_now / func_datetime
  # ============================================================================

  describe "func_ago/1" do
    test "returns a DateTime in the past" do
      result = QueryLanguage.func_ago("1h")
      now = DateTime.utc_now()

      diff = DateTime.diff(now, result, :second)
      # Should be approximately 3600 seconds (1 hour)
      assert diff >= 3590 and diff <= 3610
    end

    test "handles compound durations" do
      result = QueryLanguage.func_ago("1h30m")
      now = DateTime.utc_now()

      diff = DateTime.diff(now, result, :second)
      # 1h30m = 5400 seconds
      assert diff >= 5390 and diff <= 5410
    end

    test "returns 24h default for invalid duration" do
      result = QueryLanguage.func_ago("invalid")
      now = DateTime.utc_now()

      diff = DateTime.diff(now, result, :second)
      # Should fall back to 24h = 86400 seconds
      assert diff >= 86390 and diff <= 86410
    end
  end

  describe "func_now/0" do
    test "returns a DateTime close to current time" do
      result = QueryLanguage.func_now()
      now = DateTime.utc_now()

      diff = abs(DateTime.diff(now, result, :second))
      assert diff <= 2
    end
  end

  describe "func_datetime/1" do
    test "parses ISO-8601 datetime with timezone" do
      result = QueryLanguage.func_datetime("2025-01-15T10:30:00Z")

      assert %DateTime{} = result
      assert result.year == 2025
      assert result.month == 1
      assert result.day == 15
      assert result.hour == 10
      assert result.minute == 30
    end

    test "parses ISO-8601 naive datetime" do
      result = QueryLanguage.func_datetime("2025-01-15T10:30:00")

      assert %DateTime{} = result
      assert result.year == 2025
    end

    test "returns nil for invalid datetime" do
      result = QueryLanguage.func_datetime("not-a-date")
      assert result == nil
    end

    test "passes through non-string values" do
      assert QueryLanguage.func_datetime(42) == 42
    end
  end
end
