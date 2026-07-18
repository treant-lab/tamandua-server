defmodule TamanduaServerWeb.API.V1.HuntingController do
  use TamanduaServerWeb, :controller

  alias TamanduaServer.AuditLog
  alias TamanduaServer.Telemetry
  alias TamanduaServer.Hunting.{HuntSchema, SavedQueries, QueryExecutor, QueryParser, QueryLanguage}

  action_fallback TamanduaServerWeb.FallbackController

  # ============================================================================
  # TQL/ClickHouse Hunting Endpoint  (POST /api/v1/hunting/query)
  # ============================================================================

  @doc """
  POST /api/v1/hunting/query
  Execute a TQL (Tamandua Query Language) query against ClickHouse.

  TQL uses `table.field` references and pipe operators to compile directly
  to ClickHouse SQL for high-performance threat hunting.

  ## Request body
    - `query` (required): The TQL query string
    - `timeout`: Query timeout in ms (default 30000, max 300000)

  ## TQL syntax examples

      process.name = "powershell.exe" AND process.parent_name = "cmd.exe"
        | where timestamp > ago(24h)

      network.dst_port IN (4444, 5555, 8888) | count by network.dst_ip | where count > 5

      file.action = "modify" AND file.path MATCHES "C:\\\\Windows\\\\System32\\\\*"
        | sort timestamp desc | limit 100

      dns.query MATCHES "*.xyz" OR dns.query MATCHES "*.top"
        | count by dns.query, agent_id | where count > 10

      process.name = "psexec.exe" OR (network.dst_port = 445 AND process.name = "svchost.exe")
        | timeline agent_id
  """
  def tql_clickhouse(conn, params) do
    query = params["query"] || ""
    timeout = parse_int(params["timeout"], 30_000)

    if String.trim(query) == "" do
      conn
      |> put_status(400)
      |> json(%{error: "Query is required"})
    else
      user = conn.assigns[:current_user]
      AuditLog.log_data_access(user, "clickhouse", nil, "tql_clickhouse_query",
        query: query,
        ip_address: get_client_ip(conn),
        user_agent: get_user_agent(conn)
      )

      opts = [
        timeout: min(timeout, 300_000),
        organization_id: get_organization_id(conn)
      ]

      case QueryLanguage.execute(query, opts) do
        {:ok, result} ->
          json(conn, %{
            data: result.data,
            meta: result.meta
          })

        {:error, message} ->
          conn
          |> put_status(400)
          |> json(%{error: message, query: query})
      end
    end
  end

  @doc """
  POST /api/v1/hunting/query/validate
  Validate a TQL/ClickHouse query without executing it.
  Optionally returns the compiled SQL for inspection.
  """
  def validate_tql_clickhouse(conn, params) do
    query = params["query"] || ""

    case QueryLanguage.validate(query) do
      :ok ->
        # Also compile to SQL for inspection
        sql_result = case QueryLanguage.to_sql(query) do
          {:ok, sql} -> sql
          {:error, _} -> nil
        end

        json(conn, %{
          valid: true,
          message: "Query is valid",
          compiled_sql: sql_result
        })

      {:error, message} ->
        json(conn, %{
          valid: false,
          message: message,
          errors: [%{message: message}]
        })
    end
  end

  @doc """
  GET /api/v1/hunting/query/schema
  Returns the TQL/ClickHouse query language schema.
  """
  def tql_clickhouse_schema(conn, _params) do
    json(conn, %{
      data: %{
        version: "2.0",
        name: "Tamandua Query Language (TQL) - ClickHouse",
        description: "EDR threat hunting query language that compiles to ClickHouse SQL",
        table_prefixes: QueryLanguage.table_sources(),
        field_mappings: QueryLanguage.field_mappings(),
        operators: QueryLanguage.operators(),
        aggregation_functions: QueryLanguage.aggregation_functions(),
        keywords: QueryLanguage.keywords(),
        pipe_operators: [
          %{name: "where", syntax: "| where <expression>", description: "Post-aggregation filter (HAVING) or additional WHERE"},
          %{name: "count by", syntax: "| count by field1, field2", description: "Group and count"},
          %{name: "stats", syntax: "| stats agg(field) by field1", description: "Arbitrary aggregations (sum, avg, min, max, distinct_count)"},
          %{name: "sort", syntax: "| sort field [asc|desc]", description: "Order results"},
          %{name: "limit", syntax: "| limit N", description: "Limit result count"},
          %{name: "timeline", syntax: "| timeline field", description: "Chronological view grouped by field"}
        ],
        comparison_operators: [
          %{op: "=", description: "Equal"},
          %{op: "!=", description: "Not equal"},
          %{op: ">", description: "Greater than"},
          %{op: ">=", description: "Greater or equal"},
          %{op: "<", description: "Less than"},
          %{op: "<=", description: "Less or equal"},
          %{op: "CONTAINS", description: "String contains (LIKE %...%)"},
          %{op: "STARTS_WITH", description: "String starts with (LIKE ...%)"},
          %{op: "ENDS_WITH", description: "String ends with (LIKE %...)"},
          %{op: "MATCHES", description: "Glob pattern match (* and ?)"},
          %{op: "REGEX", description: "Regular expression match"},
          %{op: "IN (...)", description: "Value in set"},
          %{op: "NOT IN (...)", description: "Value not in set"},
          %{op: "IN CIDR", description: "IP in CIDR range (isIPAddressInRange)"}
        ],
        time_functions: [
          %{name: "ago(duration)", description: "Relative time: ago(24h), ago(7d), ago(1h30m)"},
        ],
        examples: [
          %{
            name: "PowerShell spawned by cmd.exe (last 24h)",
            query: "process.name = \"powershell.exe\" AND process.parent_name = \"cmd.exe\" | where timestamp > ago(24h)"
          },
          %{
            name: "Suspicious ports with count",
            query: "network.dst_port IN (4444, 5555, 8888) | count by network.dst_ip | where count > 5"
          },
          %{
            name: "System32 file modifications",
            query: "file.action = \"modify\" AND file.path MATCHES \"C:\\\\Windows\\\\System32\\\\*\" | sort timestamp desc | limit 100"
          },
          %{
            name: "Suspicious TLD DNS queries",
            query: "dns.query MATCHES \"*.xyz\" OR dns.query MATCHES \"*.top\" | count by dns.query, agent_id | where count > 10"
          },
          %{
            name: "Lateral movement hunt",
            query: "process.name = \"psexec.exe\" OR (network.dst_port = 445 AND process.name = \"svchost.exe\") | timeline agent_id"
          },
          %{
            name: "CIDR exclusion",
            query: "network.dst_ip NOT IN CIDR \"10.0.0.0/8\" AND network.dst_port = 443 | count by network.dst_ip | sort count desc | limit 20"
          },
          %{
            name: "Registry persistence",
            query: "registry.key CONTAINS \"\\\\Run\" AND registry.action = \"modify\" | sort timestamp desc | limit 50"
          },
          %{
            name: "Critical alerts by technique",
            query: "alert.severity = \"critical\" | count by alert.mitre_technique | sort count desc"
          }
        ]
      }
    })
  end

  @doc """
  Execute a search query across telemetry data.

  Supports two query syntaxes:
  1. Simple syntax (field:value) - for basic searches
  2. TQL (Tamandua Query Language) - for advanced queries (pipe-based)

  Simple syntax:
    - `field:value` — exact match on event payload or top-level fields
    - `field:*value*` — contains match (wildcards)
    - Multiple conditions joined by AND/OR

  TQL syntax (when query starts with table name and contains '|'):
    - `events | where event_type == "process" | limit 100`
    - See /api/v1/hunting/tql-schema for full syntax reference
  """
  def search(conn, params) do
    query = params["query"] || ""
    time_range = params["time_range"] || "24h"
    limit = parse_int(params["limit"], 100)
    page = parse_int(params["page"], 1)
    page_size = parse_int(params["page_size"], limit)
    agent_ids = params["agent_ids"]

    user = conn.assigns[:current_user]
    AuditLog.log_data_access(user, "telemetry", nil, "hunt_query",
      query: query,
      ip_address: get_client_ip(conn),
      user_agent: get_user_agent(conn)
    )

    # Detect if this is a TQL query (contains pipe operator and starts with table)
    is_tql = is_tql_query?(query)

    if is_tql do
      execute_tql_query(conn, query, %{
        page: page,
        page_size: page_size,
        organization_id: get_organization_id(conn)
      })
    else
      execute_simple_query(conn, query, time_range, limit, agent_ids)
    end
  end

  defp is_tql_query?(query) do
    trimmed = String.trim(query)
    String.contains?(trimmed, "|") and
      Regex.match?(~r/^(events|alerts|agents)\s*\|/i, trimmed)
  end

  defp execute_simple_query(conn, query, time_range, limit, agent_ids) do
    try do
      results = Telemetry.hunt_search(query, time_range, limit, agent_ids: agent_ids)

      json(conn, %{
        data: Enum.map(results, &serialize_event/1),
        meta: %{
          query: query,
          time_range: time_range,
          total: length(results),
          query_type: "simple"
        }
      })
    rescue
      e ->
        conn
        |> put_status(500)
        |> json(%{error: "Search failed: #{Exception.message(e)}"})
    end
  end

  defp execute_tql_query(conn, query, opts) do
    start_time = System.monotonic_time(:millisecond)

    case QueryExecutor.execute(query, opts) do
      {:ok, result} ->
        execution_time = System.monotonic_time(:millisecond) - start_time

        json(conn, %{
          data: Enum.map(result.data, &serialize_event/1),
          meta: %{
            query: query,
            query_type: "tql",
            total: result.meta.total,
            page: result.meta.page,
            page_size: result.meta.page_size,
            has_more: result.meta.has_more,
            execution_time_ms: execution_time
          }
        })

      {:error, message} ->
        conn
        |> put_status(400)
        |> json(%{
          error: message,
          query_type: "tql"
        })
    end
  end

  @doc """
  POST /api/v1/hunting/tql
  Execute a TQL (Tamandua Query Language) query.

  This endpoint specifically handles the advanced TQL syntax for complex queries.

  Request body:
    - query: The TQL query string
    - page: Page number (default: 1)
    - page_size: Results per page (default: 100, max: 10000)
    - timeout: Query timeout in ms (default: 30000, max: 300000)

  Example queries:
    events | where event_type == "process" | where command_line contains "-enc" | limit 100
    events | where timestamp > ago(24h) | summarize count() by event_type | top 10 by count_
    alerts | where severity == "critical" | sort timestamp desc | limit 50
  """
  def tql(conn, params) do
    query = params["query"] || ""
    page = parse_int(params["page"], 1)
    page_size = parse_int(params["page_size"], 100)
    timeout = parse_int(params["timeout"], 30_000)

    if String.trim(query) == "" do
      conn
      |> put_status(400)
      |> json(%{error: "Query is required"})
    else
      user = conn.assigns[:current_user]
      AuditLog.log_data_access(user, "telemetry", nil, "tql_query",
        query: query,
        ip_address: get_client_ip(conn),
        user_agent: get_user_agent(conn)
      )

      opts = %{
        page: page,
        page_size: page_size,
        timeout: timeout,
        organization_id: get_organization_id(conn)
      }

      execute_tql_query(conn, query, opts)
    end
  end

  @doc """
  POST /api/v1/hunting/tql/validate
  Validate a TQL query without executing it.

  Returns syntax errors or confirmation that the query is valid.
  """
  def validate_tql(conn, params) do
    query = params["query"] || ""

    case QueryParser.parse_with_errors(query) do
      {:ok, ast} ->
        json(conn, %{
          valid: true,
          ast: sanitize_ast(ast),
          message: "Query is valid"
        })

      {:error, errors} ->
        json(conn, %{
          valid: false,
          errors: errors,
          message: "Query has syntax errors"
        })
    end
  end

  @doc """
  POST /api/v1/hunting/tql/explain
  Get execution plan for a TQL query without running it.

  Returns estimated row count and query plan information.
  """
  def explain_tql(conn, params) do
    query = params["query"] || ""

    case QueryExecutor.explain(query) do
      {:ok, explanation} ->
        json(conn, %{
          data: explanation
        })

      {:error, message} ->
        conn
        |> put_status(400)
        |> json(%{error: message})
    end
  end

  @doc """
  GET /api/v1/hunting/tql-schema
  Returns the TQL language schema including syntax, operators, functions, and examples.
  """
  def tql_schema(conn, _params) do
    json(conn, %{
      data: %{
        version: "1.0",
        name: "Tamandua Query Language (TQL)",
        description: "A powerful EDR query language for threat hunting",
        table_sources: Map.keys(QueryLanguage.table_sources()),
        operators: QueryLanguage.operators(),
        aggregation_functions: QueryLanguage.aggregation_functions(),
        scalar_functions: Map.keys(QueryLanguage.scalar_functions()),
        keywords: QueryLanguage.keywords(),
        field_mappings: %{
          events: Map.keys(QueryLanguage.field_mappings().events),
          alerts: Map.keys(QueryLanguage.field_mappings().alerts),
          agents: Map.keys(QueryLanguage.field_mappings().agents)
        },
        syntax: %{
          basic_structure: "table | operator1 | operator2 | ...",
          operators: [
            %{name: "where", syntax: "| where <expression>", description: "Filter rows based on condition"},
            %{name: "has", syntax: "| has \"keyword\"", description: "Full-text search across payload"},
            %{name: "project", syntax: "| project field1, field2", description: "Select specific fields"},
            %{name: "project-away", syntax: "| project-away field1", description: "Exclude specific fields"},
            %{name: "extend", syntax: "| extend new_field = expression", description: "Add computed fields"},
            %{name: "summarize", syntax: "| summarize agg() by field", description: "Aggregate data"},
            %{name: "sort", syntax: "| sort field desc", description: "Sort results"},
            %{name: "top", syntax: "| top N by field", description: "Get top N by field"},
            %{name: "limit", syntax: "| limit N", description: "Limit result count"},
            %{name: "join", syntax: "| join (subquery) on field", description: "Join with another table"},
            %{name: "lookup", syntax: "| lookup table on field", description: "Lookup in reference table"}
          ],
          comparison_operators: [
            %{op: "==", description: "Equal"},
            %{op: "!=", description: "Not equal"},
            %{op: ">", description: "Greater than"},
            %{op: ">=", description: "Greater or equal"},
            %{op: "<", description: "Less than"},
            %{op: "<=", description: "Less or equal"},
            %{op: "contains", description: "String contains (case-insensitive)"},
            %{op: "startswith", description: "String starts with"},
            %{op: "endswith", description: "String ends with"},
            %{op: "matches", description: "Regex match"},
            %{op: "in", description: "Value in list"},
            %{op: "between", description: "Value in range"}
          ],
          logical_operators: ["and", "or", "not"]
        },
        examples: [
          %{
            name: "Encoded PowerShell",
            query: "events | where event_type == \"process\" | where command_line contains \"-enc\" | limit 100"
          },
          %{
            name: "Network connections summary",
            query: "events | where timestamp > ago(24h) | where event_type == \"network\" | summarize count() by remote_ip | top 20 by count_"
          },
          %{
            name: "Critical alerts",
            query: "alerts | where severity == \"critical\" | sort timestamp desc | limit 50"
          },
          %{
            name: "Lateral movement tools",
            query: "events | where process_name in (\"psexec.exe\", \"wmic.exe\", \"winrs.exe\") | project timestamp, hostname, user, command_line"
          },
          %{
            name: "High entropy files",
            query: "events | where event_type == \"file\" | where entropy > 7.5 | limit 50"
          }
        ]
      }
    })
  end

  @doc """
  Execute a structured query for threat hunting (legacy endpoint).
  """
  def query(conn, params) do
    query_ast = params["query"]
    time_range = params["time_range"] || "24h"
    limit = parse_int(params["limit"], 100)

    user = conn.assigns[:current_user]
    AuditLog.log_data_access(user, "telemetry", nil, "hunt_query",
      query: inspect(query_ast),
      ip_address: get_client_ip(conn),
      user_agent: get_user_agent(conn)
    )

    try do
      case Telemetry.execute_hunting_query(query_ast, time_range, limit) do
        {:ok, results, stats} ->
          json(conn, %{
            data: Enum.map(results, &serialize_event/1),
            meta: %{
              time_range: time_range,
              total: length(results),
              stats: stats
            }
          })

        {:error, reason} ->
          conn
          |> put_status(400)
          |> json(%{error: reason})
      end
    rescue
      e ->
        conn
        |> put_status(500)
        |> json(%{error: "Query failed: #{Exception.message(e)}"})
    end
  end

  @doc """
  GET /api/v1/hunting/schema
  Returns the hunt query schema including field definitions, operators, and categories.
  This is the single source of truth - frontend fetches from here.
  """
  def schema(conn, _params) do
    json(conn, %{
      data: HuntSchema.full_schema()
    })
  end

  @doc """
  GET /api/v1/hunting/templates
  Returns all MITRE ATT&CK query templates grouped by category.
  Templates can be either from database (if seeded) or from static definitions.
  """
  def templates(conn, params) do
    category = params["category"]
    organization_id = get_organization_id(conn)

    # Try to get templates from database first
    db_templates = case category do
      nil ->
        SavedQueries.list_saved_queries(
          templates_only: true,
          organization_id: organization_id,
          include_global_templates: true,
          limit: 100
        )

      cat ->
        SavedQueries.get_templates_by_category(
          cat,
          organization_id: organization_id,
          include_global_templates: true
        )
    end

    if Enum.empty?(db_templates) do
      # Fall back to static templates if database is empty
      static_templates = if category do
        SavedQueries.default_templates()
        |> Enum.filter(&(&1.category == category))
      else
        SavedQueries.default_templates()
      end

      templates_by_category =
        static_templates
        |> Enum.map(&serialize_static_template/1)
        |> Enum.group_by(& &1.category)
        |> Enum.sort_by(fn {cat, _} ->
          category_order()
          |> Enum.find_index(&(&1 == cat)) || 99
        end)
        |> Enum.into(%{})

      json(conn, %{
        data: %{
          templates: templates_by_category,
          categories: category_order(),
          source: "static",
          static: true,
          degraded: true
        }
      })
    else
      # Use database templates
      templates_by_category =
        db_templates
        |> Enum.map(&serialize_template/1)
        |> Enum.group_by(& &1.category)
        |> Enum.sort_by(fn {cat, _} ->
          category_order()
          |> Enum.find_index(&(&1 == cat)) || 99
        end)
        |> Enum.into(%{})

      json(conn, %{
        data: %{
          templates: templates_by_category,
          categories: category_order(),
          source: "database",
          static: false,
          degraded: false
        }
      })
    end
  end

  defp category_order do
    [
      "Initial Access", "Execution", "Persistence", "Privilege Escalation",
      "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
      "Collection", "Command and Control", "Exfiltration", "Impact"
    ]
  end

  defp serialize_template(%TamanduaServer.Hunting.SavedQuery{} = template) do
    %{
      id: template.id,
      name: template.name,
      query: template.query,
      description: template.description,
      category: template.category,
      use_count: template.use_count || 0,
      source: "database",
      static: false,
      degraded: false
    }
  end

  defp serialize_static_template(template) do
    template
    |> serialize_template()
    |> Map.merge(%{
      source: "static",
      static: true,
      degraded: true
    })
  end

  defp serialize_template(%{} = template) do
    %{
      name: template[:name] || template["name"],
      query: template[:query] || template["query"],
      description: template[:description] || template["description"],
      category: template[:category] || template["category"]
    }
  end

  defp serialize_event(event) do
    %{
      id: event.id,
      agent_id: event.agent_id,
      agent_hostname: Map.get(event, :agent_hostname, "Unknown"),
      event_type: event.event_type,
      timestamp: format_timestamp(event.timestamp),
      payload: event.payload || %{}
    }
  end

  defp format_timestamp(%NaiveDateTime{} = ts), do: NaiveDateTime.to_iso8601(ts)
  defp format_timestamp(%DateTime{} = ts), do: DateTime.to_iso8601(ts)
  defp format_timestamp(ts) when is_binary(ts), do: ts
  defp format_timestamp(_), do: nil

  defp parse_int(nil, default), do: default
  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(value, _default) when is_integer(value), do: value

  defp get_organization_id(conn) do
    case conn.assigns[:current_user] do
      %{organization_id: org_id} -> org_id
      _ -> nil
    end
  end

  defp sanitize_ast(ast) when is_map(ast) do
    # Convert AST to JSON-serializable format
    ast
    |> Map.new(fn {k, v} -> {to_string(k), sanitize_ast(v)} end)
  end

  defp sanitize_ast(ast) when is_list(ast) do
    Enum.map(ast, &sanitize_ast/1)
  end

  defp sanitize_ast({a, b}) do
    %{"type" => "tuple", "values" => [sanitize_ast(a), sanitize_ast(b)]}
  end

  defp sanitize_ast({a, b, c}) do
    %{"type" => "tuple", "values" => [sanitize_ast(a), sanitize_ast(b), sanitize_ast(c)]}
  end

  defp sanitize_ast(ast) when is_atom(ast), do: to_string(ast)
  defp sanitize_ast(ast), do: ast

  defp get_client_ip(conn) do
    case Plug.Conn.get_req_header(conn, "x-forwarded-for") do
      [forwarded | _] -> forwarded |> String.split(",") |> List.first() |> String.trim()
      [] -> conn.remote_ip |> :inet.ntoa() |> to_string()
    end
  end

  defp get_user_agent(conn) do
    case Plug.Conn.get_req_header(conn, "user-agent") do
      [ua | _] -> ua
      [] -> nil
    end
  end
end
