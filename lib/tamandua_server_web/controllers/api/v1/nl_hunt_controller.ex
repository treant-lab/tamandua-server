defmodule TamanduaServerWeb.API.V1.NLHuntController do
  @moduledoc """
  Natural Language Hunting API controller.

  Provides endpoints for AI-powered threat hunting using natural language
  queries. Translates human-readable hunting questions into structured
  queries against telemetry data.
  """
  use TamanduaServerWeb, :controller
  require Logger

  alias TamanduaServer.Hunting.NLHunter
  alias TamanduaServer.Telemetry

  action_fallback TamanduaServerWeb.FallbackController

  def action(conn, _opts) do
    apply(__MODULE__, action_name(conn), [conn, conn.params])
  rescue
    exception ->
      Logger.warning("NL hunting action #{action_name(conn)} failed: #{Exception.message(exception)}")

      conn
      |> put_status(:service_unavailable)
      |> json(%{
        error: "nl_hunter_unavailable",
        message: "Natural language hunting service is unavailable",
        detail: Exception.message(exception)
      })
  catch
    :exit, {:noproc, _} ->
      conn
      |> put_status(:service_unavailable)
      |> json(%{error: "nl_hunter_unavailable", message: "Natural language hunting service is not running"})

    :exit, {:timeout, _} ->
      conn
      |> put_status(:gateway_timeout)
      |> json(%{error: "nl_hunter_timeout", message: "Natural language hunting service timed out"})

    kind, reason ->
      Logger.warning("NL hunting action #{action_name(conn)} failed: #{inspect(kind)} #{inspect(reason)}")

      conn
      |> put_status(:service_unavailable)
      |> json(%{error: "nl_hunter_unavailable", message: "Natural language hunting service is unavailable"})
  end

  @doc """
  Execute a natural language hunting query.

  Translates a natural language question into a structured hunt query
  and executes it against the telemetry database.

  ## Parameters
    - query: Natural language query string
    - time_range: Optional time range (default: last 24 hours)
    - limit: Maximum results to return

  ## Examples
      POST /api/v1/hunting/nl/query
      {"query": "Show me all PowerShell executions with encoded commands in the last hour"}
  """
  def natural_language_query(conn, %{"query" => query, "execute" => true} = params) do
    translated_query = params["translated_query"] |> present_string()
    executable_query = direct_hunt_query(translated_query) || direct_hunt_query(query)

    if is_nil(executable_query) do
      execute_natural_language_query(conn, query,
        meta: %{translated_query_not_executed: translated_query}
      )
    else
      execute_direct_hunt_query(conn, query, executable_query, params, translated_query)
    end
  end

  def natural_language_query(conn, %{"query" => query} = _params) do
    execute_natural_language_query(conn, query)
  end

  def natural_language_query(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameter: query"})
  end

  defp execute_direct_hunt_query(conn, query, executable_query, params, translated_query) do
    time_range = params["time_range"] || "24h"
    limit = parse_int(params["limit"], 100)

    results =
      Telemetry.hunt_search(executable_query, time_range, limit,
        agent_ids: params["agent_ids"],
        organization_id: organization_id(conn)
      )

    json(conn, %{
      data: %{
        query: query,
        translated_query: executable_query,
        translation_source: if(translated_query, do: "provided", else: "natural_language"),
        results: Enum.map(results, &serialize_event/1),
        result_count: length(results)
      },
      meta: %{
        total_matches: length(results),
        executed_query: executable_query,
        execution_mode: "simple_hunt",
        time_range: time_range
      }
    })
  end

  defp execute_natural_language_query(conn, query, opts \\ []) do
    # Pass nil as session_id to create a new session for this query
    case NLHunter.execute_query(nil, query) do
      {:ok, results} ->
        extra_meta = Keyword.get(opts, :meta, %{})

        json(conn, %{
          data: %{
            query: query,
            session_id: results[:session_id],
            translated_query: results[:tql_query] || results[:generated_sigma_rule],
            translation_source: results[:translation_source] || "pattern",
            results: results[:results] || [],
            result_count: results[:result_count] || 0
          },
          meta:
            %{
              total_matches: results[:result_count] || 0,
              execution_mode: "nl_hunter"
            }
            |> Map.merge(extra_meta)
        })

      {:error, :invalid_query, details} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{
          error: "Invalid query",
          details: details,
          suggestions: NLHunter.query_suggestions(%{query: query})
        })

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc """
  Generate hunting hypotheses based on current threat landscape.

  Uses AI to analyze current alerts, IOCs, and threat intelligence
  to suggest proactive hunting hypotheses.

  ## Parameters
    - context: Optional context (alerts, iocs, mitre_techniques)
    - focus_areas: Optional list of areas to focus on
  """
  def generate_hypothesis(conn, params) do
    context = %{
      include_alerts: Map.get(params, "include_alerts", true),
      include_iocs: Map.get(params, "include_iocs", true),
      mitre_techniques: Map.get(params, "mitre_techniques", []),
      focus_areas: Map.get(params, "focus_areas", [])
    }

    case NLHunter.generate_hypotheses(context) do
      {:ok, hypotheses} ->
        json(conn, %{
          data: hypotheses,
          meta: %{
            count: length(hypotheses),
            generated_at: DateTime.utc_now() |> DateTime.to_iso8601()
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc """
  List all hunting sessions.

  Returns a paginated list of hunting sessions with their status
  and summary information.
  """
  def hunt_sessions(conn, params) do
    options = %{
      page: Map.get(params, "page", 1),
      per_page: Map.get(params, "per_page", 20),
      status: Map.get(params, "status"),
      created_by: Map.get(params, "created_by")
    }

    case NLHunter.list_sessions(options) do
      {:ok, sessions} ->
        json(conn, %{
          data: Enum.map(sessions, &serialize_session/1),
          meta: %{
            total: length(sessions),
            page: options.page,
            per_page: options.per_page
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc """
  Get details of a specific hunting session.

  Returns complete information about a hunting session including
  all queries executed, results found, and analyst notes.
  """
  def session_detail(conn, %{"id" => id}) do
    case NLHunter.get_session(id) do
      {:ok, session} ->
        json(conn, %{
          data: serialize_session_detail(session)
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Session not found"})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc """
  Execute a query within an existing hunting session.

  Adds the query to the session's timeline and aggregates findings.
  """
  def session_query(conn, %{"id" => session_id, "query" => query}) do
    case NLHunter.execute_query(session_id, query) do
      {:ok, results} ->
        json(conn, %{
          data: %{
            session_id: results[:session_id] || session_id,
            query: query,
            translated_query: results[:tql_query] || results[:generated_sigma_rule],
            translation_source: results[:translation_source] || "pattern",
            results: results[:results] || [],
            result_count: results[:result_count] || 0,
            total_findings: results[:total_findings],
            generated_sigma_rule: results[:generated_sigma_rule]
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: to_string(reason)})
    end
  end

  def session_query(conn, %{"id" => _session_id}) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameter: query"})
  end

  # Private functions

  defp serialize_session(session) when is_map(session) do
    %{
      id: session[:id] || session.id,
      name: session[:name] || session[:original_query] || "Unnamed Session",
      status: session[:status] || "active",
      query_count: session[:query_count] || length(session[:timeline] || []),
      findings_count: session[:findings_count] || length(session[:findings] || []),
      created_by: session[:created_by] || session[:analyst_id],
      created_at: format_datetime(session[:created_at] || session[:inserted_at]),
      updated_at: format_datetime(session[:updated_at] || session[:created_at])
    }
  end

  defp serialize_session_detail(session) when is_map(session) do
    %{
      id: session[:id] || session.id,
      name: session[:name] || session[:original_query] || "Unnamed Session",
      description: session[:description] || session[:original_query],
      status: session[:status] || "active",
      queries: session[:queries] || session[:timeline] || [],
      findings: session[:findings] || [],
      notes: session[:notes] || [],
      hypotheses: session[:hypotheses] || [],
      created_by: session[:created_by] || session[:analyst_id],
      created_at: format_datetime(session[:created_at] || session[:inserted_at]),
      updated_at: format_datetime(session[:updated_at] || session[:created_at])
    }
  end

  defp format_datetime(nil), do: nil
  defp format_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)

  defp present_string(value) when is_binary(value) do
    value = String.trim(value)
    if value == "", do: nil, else: value
  end

  defp present_string(_), do: nil

  defp direct_hunt_query(nil), do: nil

  defp direct_hunt_query(query) when is_binary(query) do
    trimmed = String.trim(query)

    cond do
      trimmed == "" ->
        nil

      String.contains?(trimmed, "|") or String.contains?(trimmed, "\n") ->
        nil

      Regex.match?(~r/\b(select|from|where|match|fields|title|detection|condition):?\b/i, trimmed) ->
        nil

      Regex.match?(~r/(^|\s|\()[-A-Za-z0-9_.]+:(~|!|\*|>|<|>=|<=|in|!in)?\S+/, trimmed) ->
        trimmed

      true ->
        nil
    end
  end

  defp direct_hunt_query(_), do: nil

  defp parse_int(nil, default), do: default

  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_int(value, _default) when is_integer(value), do: value
  defp parse_int(_, default), do: default

  defp organization_id(conn) do
    case conn.assigns[:current_user] do
      %{organization_id: org_id} -> org_id
      _ -> nil
    end
  end

  defp serialize_event(event) do
    %{
      id: event.id,
      agent_id: event.agent_id,
      agent_hostname: Map.get(event, :agent_hostname, "Unknown"),
      event_type: event.event_type,
      timestamp: format_datetime(event.timestamp),
      payload: event.payload || %{}
    }
  end
end
