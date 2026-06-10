defmodule TamanduaServerWeb.API.V1.BaselineController do
  @moduledoc """
  API controller for baseline learning endpoints.

  Provides REST endpoints for:
  - Getting baseline status for an agent
  - Starting/ending learning periods
  - Viewing learned patterns
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Detection.Baseline
  alias TamanduaServer.Detection.BaselinePatterns
  alias TamanduaServer.Agents

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  GET /api/v1/agents/:id/baseline/status

  Get the baseline learning status for an agent.
  """
  def status(conn, %{"id" => agent_id}) do
    org_id = get_current_organization_id(conn)

    # Verify agent exists and belongs to the current organization (BOLA/IDOR protection)
    case Agents.get_agent_for_org(org_id, agent_id) do
      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Agent not found"})

      {:ok, _agent} ->
        stats = Baseline.get_stats(agent_id)

        json(conn, %{
          data: %{
            agent_id: agent_id,
            status: stats.learning_status || "not_started",
            learning_started_at: format_datetime(stats.learning_started_at),
            learning_completed_at: format_datetime(stats.learning_completed_at),
            learning_days: stats.learning_days,
            events_processed: stats.events_processed,
            patterns_learned: stats.patterns_learned,
            is_learning: stats.learning_status == "learning",
            pattern_breakdown: stats.pattern_breakdown,
            common_patterns_count: stats.common_patterns,
            rare_patterns_count: stats.rare_patterns
          }
        })
    end
  end

  @doc """
  POST /api/v1/agents/:id/baseline/start

  Start baseline learning for an agent.

  Optional body params:
  - learning_days: Number of days for learning period (default: 7)
  """
  def start(conn, %{"id" => agent_id} = params) do
    org_id = get_current_organization_id(conn)

    # Verify agent exists and belongs to the current organization (BOLA/IDOR protection)
    case Agents.get_agent_for_org(org_id, agent_id) do
      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Agent not found"})

      {:ok, agent} ->
        opts = [
          learning_days: parse_int(params["learning_days"], 7),
          organization_id: agent.organization_id
        ]

        case Baseline.start_learning(agent_id, opts) do
          {:ok, status} ->
            conn
            |> put_status(:created)
            |> json(%{
              data: %{
                agent_id: agent_id,
                status: status.status,
                started_at: format_datetime(status.started_at),
                learning_days: status.learning_days,
                message: "Baseline learning started"
              }
            })

          {:error, changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Failed to start learning", details: format_errors(changeset)})
        end
    end
  end

  @doc """
  POST /api/v1/agents/:id/baseline/end

  Force end the baseline learning period for an agent.
  """
  def end_learning(conn, %{"id" => agent_id}) do
    org_id = get_current_organization_id(conn)

    # Verify agent exists and belongs to the current organization (BOLA/IDOR protection)
    case Agents.get_agent_for_org(org_id, agent_id) do
      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Agent not found"})

      {:ok, _agent} ->
        case Baseline.end_learning(agent_id) do
          {:ok, status} ->
            json(conn, %{
              data: %{
                agent_id: agent_id,
                status: status.status,
                completed_at: format_datetime(status.completed_at),
                patterns_learned: status.patterns_learned,
                message: "Baseline learning completed"
              }
            })

          {:error, :not_found} ->
            conn
            |> put_status(:not_found)
            |> json(%{error: "No learning session found for this agent"})

          {:error, reason} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Failed to end learning", details: inspect(reason)})
        end
    end
  end

  @doc """
  GET /api/v1/agents/:id/baseline/patterns

  Get learned patterns for an agent.

  Query params:
  - type: Filter by pattern type (process, network, file, schedule)
  - limit: Maximum number of patterns to return (default: 100)
  - filter: "common" or "rare" to filter by occurrence frequency
  """
  def patterns(conn, %{"id" => agent_id} = params) do
    org_id = get_current_organization_id(conn)

    # Verify agent exists and belongs to the current organization (BOLA/IDOR protection)
    case Agents.get_agent_for_org(org_id, agent_id) do
      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Agent not found"})

      {:ok, _agent} ->
        type = params["type"]
        limit = parse_int(params["limit"], 100)
        filter = params["filter"]

        patterns = case filter do
          "common" ->
            BaselinePatterns.get_common_patterns(agent_id, type: type)

          "rare" ->
            BaselinePatterns.get_rare_patterns(agent_id, type: type)

          _ ->
            BaselinePatterns.list_patterns(agent_id, type: type, limit: limit)
        end

        json(conn, %{
          data: Enum.map(patterns, &serialize_pattern/1),
          meta: %{
            total: length(patterns),
            type_filter: type,
            frequency_filter: filter
          }
        })
    end
  end

  @doc """
  GET /api/v1/agents/:id/baseline/score

  Get the baseline match score for a specific event.
  Useful for testing baseline matches.

  Body params:
  - event: The event to check against the baseline
  """
  def score(conn, %{"id" => agent_id, "event" => event}) do
    org_id = get_current_organization_id(conn)

    # Verify agent exists and belongs to the current organization (BOLA/IDOR protection)
    case Agents.get_agent_for_org(org_id, agent_id) do
      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Agent not found"})

      {:ok, _agent} ->
        score = Baseline.get_baseline_score(agent_id, event)

        json(conn, %{
          data: %{
            agent_id: agent_id,
            baseline_score: score,
            is_normal: score >= 0.5,
            confidence_reduction: calculate_reduction_preview(score)
          }
        })
    end
  end

  def score(conn, %{"id" => _agent_id}) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing 'event' parameter in request body"})
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp get_current_organization_id(conn) do
    conn.assigns[:current_organization_id] ||
      (conn.assigns[:current_user] && conn.assigns[:current_user].organization_id)
  end

  defp serialize_pattern(pattern) do
    %{
      id: pattern.id,
      type: pattern.baseline_type,
      pattern: pattern.pattern,
      occurrence_count: pattern.occurrence_count,
      first_seen: format_datetime(pattern.first_seen),
      last_seen: format_datetime(pattern.last_seen),
      confidence_weight: pattern.confidence_weight
    }
  end

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)

  defp parse_int(nil, default), do: default
  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(value, _default) when is_integer(value), do: value

  defp format_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end

  defp format_errors(other), do: inspect(other)

  defp calculate_reduction_preview(score) do
    cond do
      score >= 0.8 -> %{reduction: "50%", description: "High confidence baseline match"}
      score >= 0.5 -> %{reduction: "25%", description: "Medium confidence baseline match"}
      score >= 0.2 -> %{reduction: "10%", description: "Low confidence baseline match"}
      true -> %{reduction: "0%", description: "No baseline match"}
    end
  end
end
