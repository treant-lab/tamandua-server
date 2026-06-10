defmodule TamanduaServerWeb.HealthController do
  use TamanduaServerWeb, :controller
  import Plug.Conn, only: [halt: 1, put_status: 2]

  alias TamanduaServer.Repo
  alias TamanduaServer.Telemetry.ClickHouse
  alias TamanduaServer.Telemetry.ClickHouseWriter
  alias TamanduaServer.Telemetry.ClickHouseQuery

  @doc """
  Basic health check - returns 200 if the app is running.
  Includes ClickHouse status when enabled.
  """
  def index(conn, _params) do
    clickhouse_status = check_clickhouse_status()

    json(conn, %{
      status: "healthy",
      clickhouse: clickhouse_status,
      timestamp: DateTime.utc_now()
    })
  end

  @doc """
  Readiness check - verifies database and ClickHouse connectivity.
  """
  def ready(conn, _params) do
    db_check = check_database()
    ch_check = check_clickhouse()

    checks = %{
      database: if(db_check == :ok, do: "ok", else: elem(db_check, 1)),
      clickhouse: ch_check
    }

    all_ok = db_check == :ok

    if all_ok do
      json(conn, %{
        status: "ready",
        checks: checks,
        timestamp: DateTime.utc_now()
      })
    else
      conn
      |> put_status(503)
      |> json(%{
        status: "not_ready",
        checks: checks,
        timestamp: DateTime.utc_now()
      })
    end
  end

  @doc """
  Liveness check - simple ping to verify the app is responding.
  """
  def live(conn, _params) do
    json(conn, %{status: "alive", timestamp: DateTime.utc_now()})
  end

  @doc """
  Detailed ClickHouse health endpoint.

  Returns writer stats (events/sec, queue depth, error count, circuit breaker
  state) and storage usage (total rows, disk bytes per table).
  """
  def clickhouse(conn, _params) do
    if ClickHouse.enabled?() do
      writer_stats = ClickHouseWriter.get_stats()
      connection_healthy = ClickHouse.healthy?()

      storage_stats =
        case ClickHouseQuery.storage_stats() do
          {:ok, data} -> data
          {:error, _} -> []
        end

      json(conn, %{
        status: if(connection_healthy, do: "healthy", else: "degraded"),
        enabled: true,
        connection_healthy: connection_healthy,
        writer: writer_stats,
        storage: storage_stats,
        timestamp: DateTime.utc_now()
      })
    else
      json(conn, %{
        status: "disabled",
        enabled: false,
        timestamp: DateTime.utc_now()
      })
    end
  end

  defp check_database do
    case Repo.query("SELECT 1") do
      {:ok, _} -> :ok
      {:error, _} -> {:error, "connection_failed"}
    end
  rescue
    _ -> {:error, "connection_failed"}
  end

  defp check_clickhouse do
    if ClickHouse.enabled?() do
      if ClickHouse.healthy?() do
        writer_stats = ClickHouseWriter.get_stats()
        circuit = writer_stats[:circuit] || :unknown

        case circuit do
          :closed -> "ok"
          :half_open -> "recovering"
          :open -> "circuit_open"
          _ -> "ok"
        end
      else
        "connection_failed"
      end
    else
      "disabled"
    end
  rescue
    _ -> "unavailable"
  catch
    :exit, _ -> "unavailable"
  end

  defp check_clickhouse_status do
    if ClickHouse.enabled?() do
      writer_stats = ClickHouseWriter.get_stats()

      %{
        enabled: true,
        healthy: ClickHouse.healthy?(),
        circuit: writer_stats[:circuit] || :unknown,
        queue_depth: writer_stats[:queue_depth] || 0,
        events_written: writer_stats[:events_written] || 0,
        events_dropped: writer_stats[:events_dropped] || 0,
        flush_errors: writer_stats[:flush_errors] || 0
      }
    else
      %{enabled: false}
    end
  rescue
    _ -> %{enabled: false, error: "unavailable"}
  catch
    :exit, _ -> %{enabled: false, error: "process_down"}
  end

  @doc """
  Debug endpoint to check session tokens ETS table (DEV ONLY).

  WARNING: This endpoint exposes raw session tokens and should NEVER
  be accessible in production without proper authentication.
  """
  def debug_sessions(conn, _params) do
    tokens = :ets.tab2list(:user_session_tokens) |> Enum.map(fn {token, user_id, created_at} ->
      %{token: token, user_id: user_id, created_at: to_string(created_at)}
    end)

    json(conn, %{
      session_tokens: tokens,
      count: length(tokens),
      timestamp: DateTime.utc_now()
    })
  end

  @doc """
  Secured debug endpoint for session statistics (PROD - admin only).

  Returns session count and metadata WITHOUT exposing actual tokens.
  Requires admin authentication via the api_auth pipeline.
  """
  def debug_sessions_secured(conn, _params) do
    user = conn.assigns[:current_user]

    # Verify admin role
    unless user && user.role in ["admin", :admin] do
      conn
      |> put_status(:forbidden)
      |> json(%{error: "Admin access required"})
      |> halt()
    else
      # Return sanitized stats - NEVER return raw tokens
      tokens = :ets.tab2list(:user_session_tokens)

      stats = %{
        active_sessions: length(tokens),
        # Group by user for admin insight, but no tokens exposed
        sessions_by_user:
          tokens
          |> Enum.group_by(fn {_token, user_id, _created_at} -> user_id end)
          |> Enum.map(fn {user_id, sessions} ->
            %{
              user_id: user_id,
              session_count: length(sessions),
              oldest_session:
                sessions
                |> Enum.map(fn {_, _, created_at} -> created_at end)
                |> Enum.min(DateTime, fn -> nil end)
                |> to_string()
            }
          end),
        timestamp: DateTime.utc_now()
      }

      json(conn, stats)
    end
  end

  @doc """
  Debug endpoint to check network events structure (DEV ONLY).
  """
  def debug_network_events(conn, _params) do
    import Ecto.Query
    alias TamanduaServer.Telemetry

    # Get total event count
    total_count = Repo.aggregate(TamanduaServer.Telemetry.Event, :count, :id)

    # Get event type distribution
    event_types = Repo.all(
      from e in TamanduaServer.Telemetry.Event,
      select: e.event_type,
      distinct: true
    )

    # Get network_connect count
    network_count = Repo.one(
      from e in TamanduaServer.Telemetry.Event,
      where: e.event_type == "network_connect",
      select: count()
    )

    # Get sample network events (raw from DB)
    raw_events = Repo.all(
      from e in TamanduaServer.Telemetry.Event,
      where: e.event_type == "network_connect",
      limit: 3,
      order_by: [desc: e.timestamp]
    )

    # Transform using the same logic as InertiaController
    transformed_events = Enum.map(raw_events, fn event ->
      payload = event.payload || %{}

      # Helper to get value with both atom and string key fallbacks
      get_val = fn keys, default ->
        Enum.find_value(keys, default, fn key ->
          payload[key] || payload[to_string(key)]
        end)
      end

      %{
        id: event.id,
        agentId: event.agent_id,
        sourceIp: get_val.([:local_ip, :source_ip, "local_ip", "source_ip"], nil),
        sourcePort: get_val.([:local_port, :source_port, "local_port", "source_port"], 0),
        destIp: get_val.([:remote_ip, :dest_ip, :destination_ip, "remote_ip", "dest_ip", "destination_ip"], nil),
        destPort: get_val.([:remote_port, :dest_port, :destination_port, "remote_port", "dest_port", "destination_port"], 0),
        protocol: get_val.([:protocol, "protocol"], "tcp"),
        processName: get_val.([:process_name, :name, "process_name", "name"], "unknown"),
        processPid: get_val.([:pid, "pid"], 0),
        direction: get_val.([:direction, "direction"], "outbound"),
        status: get_val.([:status, "status"], "established"),
        # Debug: show raw payload
        _raw_payload: payload
      }
    end)

    json(conn, %{
      total_events: total_count,
      event_types: event_types,
      network_connect_count: network_count || 0,
      transformed_for_inertia: transformed_events,
      timestamp: DateTime.utc_now()
    })
  end

  @doc """
  Secured debug endpoint for network event statistics (PROD - admin only).

  Returns aggregate stats WITHOUT exposing raw event payloads.
  Requires admin authentication via the api_auth pipeline.
  """
  def debug_network_events_secured(conn, _params) do
    import Ecto.Query

    user = conn.assigns[:current_user]

    # Verify admin role
    unless user && user.role in ["admin", :admin] do
      conn
      |> put_status(:forbidden)
      |> json(%{error: "Admin access required"})
      |> halt()
    else
      # Return aggregated stats only - no raw payloads
      total_count = Repo.aggregate(TamanduaServer.Telemetry.Event, :count, :id)

      event_type_counts =
        Repo.all(
          from e in TamanduaServer.Telemetry.Event,
            group_by: e.event_type,
            select: {e.event_type, count(e.id)}
        )
        |> Map.new()

      json(conn, %{
        total_events: total_count,
        event_type_distribution: event_type_counts,
        # No raw payloads exposed in production
        timestamp: DateTime.utc_now()
      })
    end
  end
end
