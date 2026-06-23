defmodule TamanduaServerWeb.API.V1.BehavioralController do
  @moduledoc """
  Controller for Behavioral Analytics API endpoints.

  Provides access to behavioral profiling, anomaly detection,
  peer group analysis, risk trending, and entity risk scoring.

  ## Endpoints
  - GET /behavioral/entities - List monitored entities
  - GET /behavioral/entities/:entity_type/:entity_id - Get entity profile
  - GET /behavioral/anomalies - List detected anomalies
  - GET /behavioral/baselines - Get/update baselines
  - POST /behavioral/baselines - Force baseline update
  - GET /behavioral/statistics - Dashboard statistics
  - GET /behavioral/risk-trends - Risk score trends
  - GET /behavioral/peer-analysis/:entity_type/:entity_id - Peer comparison
  - GET /behavioral/entity-history/:entity_type/:entity_id - Activity history
  """
  use TamanduaServerWeb, :controller
  require Logger

  alias TamanduaServer.Alerts
  alias TamanduaServer.Alerts.SuppressionRule
  alias TamanduaServer.Detection.Behavioral
  alias TamanduaServer.Detection.IOCs

  action_fallback TamanduaServerWeb.FallbackController

  # Phase 1 tenant-scoping guard. Every public HTTP action must call this
  # before reading any data. Returns {:ok, org_id} when the request has been
  # tagged by the :api_auth pipeline (SetOrganizationContext plug); otherwise
  # returns {:error, :forbidden}, which the action_fallback above maps to 403.
  # See .planning/BEHAVIORAL_TENANT_SCOPING_DESIGN.md (Phase 1).
  defp require_org_id(conn) do
    case conn.assigns[:current_organization_id] do
      nil -> {:error, :forbidden}
      org_id -> {:ok, org_id}
    end
  end

  # ETS tables for anomaly storage
  @anomaly_table :behavioral_anomalies
  @history_table :behavioral_history
  @risk_snapshot_table :behavioral_risk_snapshots

  @doc """
  List all monitored entities with their behavioral profiles.

  ## Query Parameters
  - `type` - Filter by entity type: "user", "process", or "host"
  - `min_risk_score` - Minimum risk score (default: 0)
  - `limit` - Maximum number of results (default: 100)
  - `offset` - Offset for pagination (default: 0)
  """
  def entities(conn, params) do
    with {:ok, org_id} <- require_org_id(conn) do
      entity_type = params["type"]
      min_risk = parse_int(params["min_risk_score"], 0)
      limit = parse_int(params["limit"], 100)
      offset = parse_int(params["offset"], 0)

      entities = list_entities(org_id, entity_type, limit, offset)
      |> Enum.filter(fn e -> e.risk_score >= min_risk end)

      json(conn, %{
        data: entities,
        meta: %{
          limit: limit,
          offset: offset,
          type: entity_type,
          total: length(entities)
        }
      })
    end
  end

  @doc """
  Get the behavioral profile for a specific entity.

  Supports two route formats:
  - /behavioral/entities/:id (with type query param)
  - /behavioral/entities/:entity_type/:entity_id
  """
  def entity_profile(conn, %{"entity_type" => entity_type, "entity_id" => entity_id}) do
    with {:ok, org_id} <- require_org_id(conn) do
      do_get_entity_profile(conn, org_id, entity_type, entity_id)
    end
  end

  def entity_profile(conn, %{"id" => id} = params) do
    with {:ok, org_id} <- require_org_id(conn) do
      entity_type = params["type"] || "user"
      do_get_entity_profile(conn, org_id, entity_type, id)
    end
  end

  defp do_get_entity_profile(conn, org_id, entity_type, entity_id) do
    case get_profile(org_id, entity_type, entity_id) do
      {:ok, nil} ->
        {:error, :not_found}

      {:ok, profile} ->
        risk_score = get_risk_score(org_id, entity_type, entity_id)
        recent_anomalies = get_entity_anomalies(org_id, entity_type, entity_id, 10)
        peer_comparison = get_peer_comparison(org_id, entity_type, entity_id)

        json(conn, %{
          data: %{
            entity_type: entity_type,
            entity_id: entity_id,
            profile: serialize_profile(profile),
            risk_score: risk_score,
            risk_level: risk_level_from_score(risk_score),
            last_updated: profile.last_updated,
            total_events: profile.total_events,
            recent_anomalies: Enum.map(recent_anomalies, &serialize_anomaly/1),
            peer_comparison: peer_comparison
          }
        })

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  List detected behavioral anomalies.

  ## Query Parameters
  - `entity_type` - Filter by entity type
  - `entity_id` - Filter by specific entity
  - `min_risk_score` - Minimum risk score threshold (default: 0)
  - `since` - ISO8601 timestamp for time-based filtering
  - `limit` - Maximum number of results (default: 100)
  """
  def anomalies(conn, params) do
    with {:ok, org_id} <- require_org_id(conn) do
      filters = %{
        entity_type: params["entity_type"],
        entity_id: params["entity_id"],
        min_risk_score: parse_int(params["min_risk_score"], 0),
        since: parse_datetime(params["since"]),
        limit: parse_int(params["limit"], 100)
      }

      anomalies = list_anomalies(org_id, filters)

      json(conn, %{
        data: Enum.map(anomalies, &serialize_anomaly/1),
        meta: %{
          count: length(anomalies),
          filters: Map.take(filters, [:entity_type, :entity_id, :min_risk_score])
        }
      })
    end
  end

  @doc """
  Get or update behavioral baselines.

  ## Query Parameters (GET)
  - `type` - Baseline type: "user", "process", "host", or "global"

  ## Body Parameters (POST)
  - `force_update` - Force immediate baseline recalculation
  """
  def baselines(conn, params) do
    with {:ok, org_id} <- require_org_id(conn) do
      case conn.method do
        "GET" ->
          baseline_type = params["type"] || "global"
          baselines = get_baselines(org_id, baseline_type)

          json(conn, %{
            data: baselines,
            meta: %{
              type: baseline_type,
              last_updated: DateTime.utc_now()
            }
          })

        "POST" ->
          force_update = params["force_update"] == true || params["force_update"] == "true"

          if force_update do
            # Trigger baseline recalculation
            spawn(fn -> trigger_baseline_update() end)

            json(conn, %{
              success: true,
              message: "Baseline update triggered",
              status: "processing"
            })
          else
            json(conn, %{
              success: true,
              message: "No action taken",
              status: "idle"
            })
          end
      end
    end
  end

  @doc """
  Get UEBA dashboard statistics.

  Returns aggregate statistics about behavioral analytics:
  - Total entities monitored
  - Anomaly counts by severity
  - Risk distribution
  - Trending indicators
  """
  def statistics(conn, _params) do
    with {:ok, org_id} <- require_org_id(conn) do
      stats = calculate_statistics(org_id)

      json(conn, %{
        data: stats,
        meta: %{
          generated_at: DateTime.utc_now()
        }
      })
    end
  end

  @doc """
  Get risk score trends over time for entities.

  ## Query Parameters
  - `entity_type` - Filter by entity type
  - `entity_id` - Filter by specific entity
  - `period` - Time period: "1h", "24h", "7d", "30d" (default: "24h")
  - `interval` - Data point interval: "5m", "1h", "1d" (default: "1h")
  """
  def risk_trends(conn, params) do
    with {:ok, org_id} <- require_org_id(conn) do
      entity_type = params["entity_type"]
      entity_id = params["entity_id"]
      period = params["period"] || "24h"
      interval = params["interval"] || "1h"

      trends = calculate_risk_trends(org_id, entity_type, entity_id, period, interval)

      json(conn, %{
        data: trends,
        meta: %{
          entity_type: entity_type,
          entity_id: entity_id,
          period: period,
          interval: interval
        }
      })
    end
  end

  @doc """
  Perform peer group analysis for an entity.

  Compares the entity's behavior against similar entities (peer group)
  to identify outliers and deviations.

  ## Path Parameters
  - `entity_type` - Type of entity
  - `entity_id` - Entity identifier
  """
  def peer_analysis(conn, %{"entity_type" => entity_type, "entity_id" => entity_id}) do
    with {:ok, org_id} <- require_org_id(conn) do
      analysis = perform_peer_analysis(org_id, entity_type, entity_id)

      case analysis do
        {:ok, result} ->
          json(conn, %{
            data: result,
            meta: %{
              entity_type: entity_type,
              entity_id: entity_id,
              analyzed_at: DateTime.utc_now()
            }
          })

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  @doc """
  Get activity history for an entity.

  Returns a timeline of events and anomalies for the specified entity.

  ## Path Parameters
  - `entity_type` - Type of entity
  - `entity_id` - Entity identifier

  ## Query Parameters
  - `since` - Start timestamp (ISO8601)
  - `until` - End timestamp (ISO8601)
  - `limit` - Maximum events (default: 100)
  """
  def entity_history(conn, %{"entity_type" => entity_type, "entity_id" => entity_id} = params) do
    with {:ok, org_id} <- require_org_id(conn) do
      since = parse_datetime(params["since"])
      until_dt = parse_datetime(params["until"]) || DateTime.utc_now()
      limit = parse_int(params["limit"], 100)

      history = get_entity_history(org_id, entity_type, entity_id, since, until_dt, limit)

      json(conn, %{
        data: history,
        meta: %{
          entity_type: entity_type,
          entity_id: entity_id,
          since: since,
          until: until_dt,
          count: length(history.events)
        }
      })
    end
  end

  @doc """
  Get high-risk entities requiring attention.

  Returns entities with elevated risk scores or recent anomalies.

  ## Query Parameters
  - `min_risk` - Minimum risk score threshold (default: 70)
  - `limit` - Maximum results (default: 20)
  """
  def high_risk_entities(conn, params) do
    with {:ok, org_id} <- require_org_id(conn) do
      min_risk = parse_int(params["min_risk"], 70)
      limit = parse_int(params["limit"], 20)

      entities = get_high_risk_entities(org_id, min_risk, limit)

      json(conn, %{
        data: entities,
        meta: %{
          min_risk: min_risk,
          count: length(entities)
        }
      })
    end
  end

  # Private functions

  defp list_entities(org_id, nil, limit, offset) do
    # Return all entity types combined
    users = list_entities(org_id, "user", limit, offset)
    processes = list_entities(org_id, "process", limit, offset)
    hosts = list_entities(org_id, "host", limit, offset)

    (users ++ processes ++ hosts)
    |> Enum.sort_by(& &1.last_activity, {:desc, DateTime})
    |> Enum.take(limit)
  end

  defp list_entities(org_id, "user", limit, _offset) do
    case safe_get_all_profiles(org_id) do
      {:ok, user_profiles, _process_profiles, _host_profiles} ->
        user_profiles
        |> Enum.map(fn {_key, profile} ->
          risk = case safe_behavioral_risk_score(org_id, :user, profile.user_id) do
            {:ok, score} -> score
            _ -> 0
          end

          %{
            type: "user",
            id: profile.user_id,
            risk_score: risk,
            total_events: profile.total_events,
            last_activity: profile.last_updated
          }
        end)
        |> Enum.sort_by(& &1.risk_score, :desc)
        |> Enum.take(limit)

      _ -> []
    end
  rescue
    _ -> []
  catch
    _ -> []
  end

  defp list_entities(org_id, "process", limit, _offset) do
    case safe_get_all_profiles(org_id) do
      {:ok, _user_profiles, process_profiles, _host_profiles} ->
        process_profiles
        |> Enum.map(fn {_key, profile} ->
          risk = case safe_behavioral_risk_score(org_id, :process, profile.process_name) do
            {:ok, score} -> score
            _ -> 0
          end

          %{
            type: "process",
            id: profile.process_name,
            risk_score: risk,
            total_events: profile.total_events,
            last_activity: profile.last_updated
          }
        end)
        |> Enum.sort_by(& &1.risk_score, :desc)
        |> Enum.take(limit)

      _ -> []
    end
  rescue
    _ -> []
  catch
    _ -> []
  end

  defp list_entities(org_id, "host", limit, _offset) do
    case safe_get_all_profiles(org_id) do
      {:ok, _user_profiles, _process_profiles, host_profiles} ->
        host_profiles
        |> Enum.map(fn {_key, profile} ->
          %{
            type: "host",
            id: Map.get(profile, :host_id, "unknown"),
            risk_score: 0,
            total_events: Map.get(profile, :total_events, 0),
            last_activity: Map.get(profile, :last_updated, nil)
          }
        end)
        |> Enum.take(limit)

      _ -> []
    end
  rescue
    _ -> []
  catch
    _ -> []
  end

  defp list_entities(_org_id, _type, _limit, _offset) do
    []
  end

  defp get_profile(org_id, "user", entity_id) do
    safe_get_user_profile(org_id, entity_id)
  end

  defp get_profile(org_id, "process", entity_id) do
    safe_get_process_profile(org_id, entity_id)
  end

  defp get_profile(_org_id, "host", _entity_id) do
    # Host profiles not yet implemented in the Behavioral GenServer
    {:ok, nil}
  end

  defp get_profile(_org_id, _type, _entity_id) do
    {:error, "Invalid entity type"}
  end

  defp get_risk_score(org_id, entity_type, entity_id) do
    type_atom = String.to_existing_atom(entity_type)
    case safe_behavioral_risk_score(org_id, type_atom, entity_id) do
      {:ok, score} -> score
      _ -> 0
    end
  rescue
    _ -> 0
  catch
    _ -> 0
  end

  defp serialize_profile(nil), do: nil

  defp serialize_profile(%{user_id: user_id} = profile) do
    %{
      user_id: user_id,
      typical_login_hours: Map.get(profile, :typical_login_hours, []),
      typical_source_ips: Map.get(profile, :typical_source_ips, []),
      typical_processes: Map.get(profile, :typical_processes, []),
      typical_file_paths: Map.get(profile, :typical_file_paths, []),
      typical_network_dests: Map.get(profile, :typical_network_dests, []),
      command_patterns: Map.get(profile, :command_patterns, []),
      total_events: Map.get(profile, :total_events, 0)
    }
  end

  defp serialize_profile(%{process_name: process_name} = profile) do
    %{
      process_name: process_name,
      typical_parents: Map.get(profile, :typical_parents, []),
      typical_args: Map.get(profile, :typical_args, []),
      typical_children: Map.get(profile, :typical_children, []),
      typical_network_ports: Map.get(profile, :typical_network_ports, []),
      typical_file_operations: Map.get(profile, :typical_file_operations, []),
      avg_memory_usage: Map.get(profile, :avg_memory_usage, 0),
      avg_cpu_usage: Map.get(profile, :avg_cpu_usage, 0),
      total_events: Map.get(profile, :total_events, 0)
    }
  end

  defp serialize_profile(profile) when is_map(profile), do: profile

  defp list_anomalies(org_id, filters) do
    all_anomalies = load_all_anomalies(org_id)

    all_anomalies
    |> Enum.filter(fn a ->
      (is_nil(filters.entity_type) or to_string(a.entity_type) == filters.entity_type) and
      (is_nil(filters.entity_id) or a.entity_id == filters.entity_id) and
      (a.risk_score >= filters.min_risk_score) and
      (is_nil(filters.since) or DateTime.compare(a.timestamp, filters.since) != :lt)
    end)
    |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})
    |> Enum.take(filters.limit)
  end

  defp load_all_anomalies(org_id) do
    try do
      :ets.tab2list(@anomaly_table)
      |> Enum.filter(fn
        {{key_org, _entity_type, _entity_id}, _anomalies} -> key_org == org_id
        _ -> false
      end)
      |> Enum.flat_map(fn {_key, anomalies} ->
        if is_list(anomalies), do: anomalies, else: [anomalies]
      end)
    rescue
      _ -> []
    end
  end

  defp serialize_anomaly(anomaly) when is_map(anomaly) do
    %{
      anomaly_type: anomaly.anomaly_type,
      entity_type: anomaly.entity_type,
      entity_id: anomaly.entity_id,
      description: anomaly.description,
      risk_score: anomaly.risk_score,
      deviation_score: anomaly.deviation_score,
      baseline_value: anomaly.baseline_value,
      observed_value: anomaly.observed_value,
      mitre_techniques: anomaly.mitre_techniques,
      timestamp: anomaly.timestamp
    }
  end

  defp serialize_anomaly(anomaly) when is_map(anomaly), do: anomaly

  defp get_baselines(org_id, "global") do
    {user_count, process_count, host_count} = case safe_get_all_profiles(org_id) do
      {:ok, users, processes, hosts} ->
        {map_size(users), map_size(processes), map_size(hosts)}
      _ ->
        {0, 0, 0}
    end

    %{
      avg_events_per_hour: 0,
      avg_network_connections: 0,
      avg_file_operations: 0,
      total_users_profiled: user_count,
      total_processes_profiled: process_count,
      total_hosts_profiled: host_count
    }
  rescue
    _ -> %{
      avg_events_per_hour: 0,
      avg_network_connections: 0,
      avg_file_operations: 0,
      total_users_profiled: 0,
      total_processes_profiled: 0,
      total_hosts_profiled: 0
    }
  end

  defp get_baselines(org_id, type) do
    count = case safe_get_all_profiles(org_id) do
      {:ok, users, processes, hosts} ->
        case type do
          "user" -> map_size(users)
          "process" -> map_size(processes)
          "host" -> map_size(hosts)
          _ -> 0
        end
      _ -> 0
    end

    %{
      type: type,
      profiles_count: count,
      last_updated: DateTime.utc_now()
    }
  rescue
    _ -> %{type: type, profiles_count: 0, last_updated: DateTime.utc_now()}
  end

  defp trigger_baseline_update do
    # Send message to Behavioral GenServer to update baselines
    if Process.whereis(Behavioral) do
      send(Behavioral, :update_baselines)
    end
  rescue
    _ -> :ok
  end

  # New helper functions for enhanced UEBA

  defp get_entity_anomalies(org_id, entity_type, entity_id, limit) do
    # Query recent anomalies for the entity from ETS or database
    # In production, this would query stored anomaly records
    try do
      case :ets.lookup(@anomaly_table, {org_id, entity_type, entity_id}) do
        [{_, anomalies}] ->
          anomalies
          |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})
          |> Enum.take(limit)
        [] -> []
      end
    rescue
      _ -> []
    end
  end

  defp get_peer_comparison(org_id, entity_type, entity_id) do
    # Compare entity metrics against peer group averages
    # Peer group = similar entities (same role, department, process type, etc.)
    %{
      risk_score_percentile: calculate_percentile(org_id, entity_type, entity_id, :risk_score),
      event_volume_percentile: calculate_percentile(org_id, entity_type, entity_id, :event_volume),
      anomaly_rate_percentile: calculate_percentile(org_id, entity_type, entity_id, :anomaly_rate),
      peer_group_size: get_peer_group_size(org_id, entity_type),
      comparison: %{
        above_average: [],
        below_average: [],
        within_normal: []
      }
    }
  end

  defp risk_level_from_score(score) when score >= 90, do: "critical"
  defp risk_level_from_score(score) when score >= 75, do: "high"
  defp risk_level_from_score(score) when score >= 50, do: "medium"
  defp risk_level_from_score(score) when score >= 25, do: "low"
  defp risk_level_from_score(_), do: "minimal"

  defp calculate_statistics(org_id) do
    # Aggregate statistics across all behavioral analytics
    %{
      entities: %{
        total_users: count_entities(org_id, "user"),
        total_processes: count_entities(org_id, "process"),
        total_hosts: count_entities(org_id, "host")
      },
      anomalies: %{
        total_24h: count_anomalies_since(org_id, hours_ago(24)),
        total_7d: count_anomalies_since(org_id, days_ago(7)),
        by_severity: %{
          critical: count_anomalies_by_severity(org_id, "critical"),
          high: count_anomalies_by_severity(org_id, "high"),
          medium: count_anomalies_by_severity(org_id, "medium"),
          low: count_anomalies_by_severity(org_id, "low")
        },
        by_type: anomaly_type_distribution(org_id)
      },
      risk_distribution: %{
        critical: count_entities_by_risk(org_id, 90, 100),
        high: count_entities_by_risk(org_id, 75, 89),
        medium: count_entities_by_risk(org_id, 50, 74),
        low: count_entities_by_risk(org_id, 25, 49),
        minimal: count_entities_by_risk(org_id, 0, 24)
      },
      trending: %{
        risk_increasing: count_risk_trending(org_id, :increasing),
        risk_decreasing: count_risk_trending(org_id, :decreasing),
        risk_stable: count_risk_trending(org_id, :stable),
        new_entities_24h: count_new_entities(org_id, hours_ago(24))
      },
      top_mitre_techniques: top_mitre_techniques(org_id, 10)
    }
  end

  defp calculate_risk_trends(org_id, entity_type, entity_id, period, interval) do
    # Generate risk score time series data from actual anomalies
    {start_time, points} = case {period, interval} do
      {"1h", "5m"} -> {hours_ago(1), 12}
      {"24h", "1h"} -> {hours_ago(24), 24}
      {"7d", "1d"} -> {days_ago(7), 7}
      {"30d", "1d"} -> {days_ago(30), 30}
      _ -> {hours_ago(24), 24}
    end

    interval_secs = interval_seconds(interval)
    all_anomalies = load_all_anomalies(org_id)

    # Filter anomalies by entity if specified
    filtered = all_anomalies
    |> Enum.filter(fn a ->
      (is_nil(entity_type) or to_string(a.entity_type) == entity_type) and
      (is_nil(entity_id) or a.entity_id == entity_id) and
      not is_nil(a.timestamp) and
      DateTime.compare(a.timestamp, start_time) != :lt
    end)

    Enum.map(0..(points - 1), fn i ->
      bucket_start = DateTime.add(start_time, i * interval_secs, :second)
      bucket_end = DateTime.add(start_time, (i + 1) * interval_secs, :second)

      bucket_anomalies = Enum.filter(filtered, fn a ->
        DateTime.compare(a.timestamp, bucket_start) != :lt and
        DateTime.compare(a.timestamp, bucket_end) == :lt
      end)

      risk_scores = Enum.map(bucket_anomalies, & &1.risk_score)
      entity_ids = bucket_anomalies |> Enum.map(& &1.entity_id) |> Enum.uniq()

      avg = if length(risk_scores) > 0, do: Enum.sum(risk_scores) / length(risk_scores), else: 0
      max_score = if length(risk_scores) > 0, do: Enum.max(risk_scores), else: 0

      %{
        timestamp: bucket_start,
        avg_risk_score: Float.round(avg / 1, 1),
        max_risk_score: max_score,
        anomaly_count: length(bucket_anomalies),
        entity_count: length(entity_ids)
      }
    end)
  end

  defp perform_peer_analysis(org_id, entity_type, entity_id) do
    # Comprehensive peer group comparison
    case get_profile(org_id, entity_type, entity_id) do
      {:ok, nil} ->
        {:error, :not_found}

      {:ok, profile} ->
        peer_group = get_peer_group(org_id, entity_type, entity_id)
        metrics = calculate_peer_metrics(profile, peer_group)

        {:ok, %{
          entity_profile: serialize_profile(profile),
          peer_group: %{
            size: length(peer_group),
            type: entity_type,
            criteria: get_peer_criteria(entity_type)
          },
          comparison: %{
            risk_score: %{
              entity: get_risk_score(org_id, entity_type, entity_id),
              peer_avg: metrics.avg_risk,
              peer_median: metrics.median_risk,
              peer_stddev: metrics.stddev_risk,
              z_score: metrics.z_score,
              percentile: metrics.percentile
            },
            activity_level: %{
              entity: profile.total_events,
              peer_avg: metrics.avg_events,
              deviation: metrics.event_deviation
            },
            behavior_similarity: %{
              most_similar: metrics.most_similar,
              least_similar: metrics.least_similar,
              similarity_score: metrics.similarity_score
            }
          },
          outlier_indicators: detect_outlier_indicators(profile, metrics),
          recommendations: generate_recommendations(profile, metrics)
        }}

      error -> error
    end
  end

  defp get_entity_history(org_id, entity_type, entity_id, since, until_dt, limit) do
    # Get historical events and anomalies for timeline view
    events = get_historical_events(entity_type, entity_id, since, until_dt, limit)
    anomalies = get_entity_anomalies(org_id, entity_type, entity_id, limit)

    %{
      events: events,
      anomalies: Enum.map(anomalies, &serialize_anomaly/1),
      timeline: build_timeline(events, anomalies),
      summary: %{
        total_events: length(events),
        total_anomalies: length(anomalies),
        risk_events: Enum.count(events, &(&1[:risk_score] >= 75)),
        time_range: %{from: since, to: until_dt}
      }
    }
  end

  defp get_high_risk_entities(org_id, min_risk, limit) do
    # Query entities with risk above threshold
    # In production, this would query from ETS or database
    all_types = ["user", "process", "host"]

    all_types
    |> Enum.flat_map(fn type ->
      list_entities(org_id, type, 1000, 0)
      |> Enum.filter(&(&1.risk_score >= min_risk))
    end)
    |> Enum.sort_by(& &1.risk_score, :desc)
    |> Enum.take(limit)
    |> Enum.map(fn entity ->
      Map.merge(entity, %{
        recent_anomalies: get_entity_anomalies(org_id, entity.type, entity.id, 5) |> length(),
        trending: determine_risk_trend(entity.type, entity.id),
        mitre_techniques: get_entity_techniques(entity.type, entity.id)
      })
    end)
  end

  defp safe_get_all_profiles(org_id) do
    try do
      Behavioral.get_all_profiles(org_id)
    rescue
      _ -> {:error, :behavioral_unavailable}
    catch
      :exit, _ -> {:error, :behavioral_unavailable}
    end
  end

  defp safe_get_user_profile(org_id, entity_id) do
    try do
      Behavioral.get_user_profile(org_id, entity_id)
    rescue
      _ -> {:error, :behavioral_unavailable}
    catch
      :exit, _ -> {:error, :behavioral_unavailable}
    end
  end

  defp safe_get_process_profile(org_id, entity_id) do
    try do
      Behavioral.get_process_profile(org_id, entity_id)
    rescue
      _ -> {:error, :behavioral_unavailable}
    catch
      :exit, _ -> {:error, :behavioral_unavailable}
    end
  end

  defp safe_behavioral_risk_score(org_id, type_atom, entity_id) do
    try do
      Behavioral.get_risk_score(org_id, type_atom, entity_id)
    rescue
      _ -> {:error, :behavioral_unavailable}
    catch
      :exit, _ -> {:error, :behavioral_unavailable}
    end
  end

  # Utility functions for statistics calculation

  defp count_entities(org_id, type) do
    list_entities(org_id, type, 10000, 0) |> length()
  end

  defp count_anomalies_since(org_id, since) do
    load_all_anomalies(org_id)
    |> Enum.count(fn a ->
      not is_nil(a.timestamp) and DateTime.compare(a.timestamp, since) != :lt
    end)
  end

  defp count_anomalies_by_severity(org_id, severity) do
    threshold = case severity do
      "critical" -> 90
      "high" -> 75
      "medium" -> 50
      "low" -> 25
      _ -> 0
    end

    max_threshold = case severity do
      "critical" -> 101
      "high" -> 90
      "medium" -> 75
      "low" -> 50
      _ -> 25
    end

    load_all_anomalies(org_id)
    |> Enum.count(fn a ->
      a.risk_score >= threshold and a.risk_score < max_threshold
    end)
  end

  defp anomaly_type_distribution(org_id) do
    all = load_all_anomalies(org_id)

    all
    |> Enum.group_by(& &1.anomaly_type)
    |> Enum.map(fn {type, items} -> {type, length(items)} end)
    |> Enum.into(%{})
  end

  defp count_entities_by_risk(org_id, min, max) do
    all_entities = list_entities(org_id, nil, 10000, 0)
    Enum.count(all_entities, fn e -> e.risk_score >= min and e.risk_score <= max end)
  end

  @doc """
  Record a snapshot of current risk scores for all entities into ETS.

  This should be called periodically (e.g., every 5-15 minutes) to build
  historical data for trending calculations.

  Phase 3 tenant-scoping: snapshots are keyed by `{org_id, timestamp}` so
  trending calculations stay tenant-local.
  """
  def record_risk_snapshot(org_id) do
    ensure_risk_snapshot_table()

    now = DateTime.utc_now()
    entities = list_entities(org_id, nil, 10000, 0)

    snapshots =
      Enum.map(entities, fn entity ->
        %{type: entity.type, id: entity.id, risk_score: entity.risk_score}
      end)

    :ets.insert(@risk_snapshot_table, {{org_id, now}, snapshots})

    # Prune snapshots older than 48 hours to bound memory usage
    cutoff = DateTime.add(now, -48 * 3600, :second)

    :ets.tab2list(@risk_snapshot_table)
    |> Enum.each(fn
      {{key_org, ts}, _} when key_org == org_id ->
        if DateTime.compare(ts, cutoff) == :lt do
          :ets.delete(@risk_snapshot_table, {key_org, ts})
        end

      _ ->
        :ok
    end)

    :ok
  rescue
    e ->
      Logger.warning("Failed to record risk snapshot: #{Exception.message(e)}")
      :error
  end

  defp ensure_risk_snapshot_table do
    case :ets.whereis(@risk_snapshot_table) do
      :undefined ->
        :ets.new(@risk_snapshot_table, [:ordered_set, :public, :named_table])
      _ ->
        :ok
    end
  end

  defp count_risk_trending(org_id, direction) do
    ensure_risk_snapshot_table()

    # Get the most recent snapshot as the "current" baseline
    current_scores = get_current_entity_scores(org_id)

    # Get the previous snapshot (the oldest available, or at least 1h old)
    previous_scores = get_previous_snapshot_scores(org_id)

    if map_size(current_scores) == 0 or map_size(previous_scores) == 0 do
      0
    else
      # Compare current vs historical scores for each entity
      Enum.count(current_scores, fn {{type, id}, current_score} ->
        case Map.get(previous_scores, {type, id}) do
          nil ->
            # New entity -- count as increasing if requested
            direction == :increasing

          prev_score ->
            case direction do
              :increasing -> current_score > prev_score
              :decreasing -> current_score < prev_score
              :stable -> current_score == prev_score
            end
        end
      end)
    end
  rescue
    e ->
      Logger.warning("Failed to compute risk trending: #{Exception.message(e)}")
      0
  end

  defp get_current_entity_scores(org_id) do
    list_entities(org_id, nil, 10000, 0)
    |> Enum.map(fn entity -> {{entity.type, entity.id}, entity.risk_score} end)
    |> Map.new()
  end

  defp get_previous_snapshot_scores(org_id) do
    ensure_risk_snapshot_table()

    all_snapshots =
      :ets.tab2list(@risk_snapshot_table)
      |> Enum.filter(fn
        {{key_org, _ts}, _} -> key_org == org_id
        _ -> false
      end)
      |> Enum.sort_by(fn {{_org, ts}, _} -> ts end, {:asc, DateTime})

    case all_snapshots do
      [] ->
        %{}

      snapshots ->
        # Use the oldest snapshot that is at least 1 hour old for meaningful comparison,
        # or fall back to the oldest available snapshot
        cutoff = DateTime.add(DateTime.utc_now(), -3600, :second)

        {_key, snapshot_data} =
          Enum.find(snapshots, List.first(snapshots), fn {{_org, ts}, _} ->
            DateTime.compare(ts, cutoff) == :lt
          end)

        snapshot_data
        |> Enum.map(fn entry -> {{entry.type, entry.id}, entry.risk_score} end)
        |> Map.new()
    end
  rescue
    _ -> %{}
  end

  defp count_new_entities(org_id, since) do
    all_entities = list_entities(org_id, nil, 10000, 0)
    Enum.count(all_entities, fn e ->
      not is_nil(e.last_activity) and DateTime.compare(e.last_activity, since) != :lt
    end)
  end

  defp top_mitre_techniques(org_id, limit) do
    mitre_name_map = %{
      "T1078" => "Valid Accounts",
      "T1055" => "Process Injection",
      "T1071" => "Application Layer Protocol",
      "T1036" => "Masquerading",
      "T1106" => "Native API",
      "T1027" => "Obfuscated Files or Information",
      "T1059" => "Command and Scripting Interpreter",
      "T1059.001" => "PowerShell",
      "T1105" => "Ingress Tool Transfer",
      "T1041" => "Exfiltration Over C2 Channel",
      "T1571" => "Non-Standard Port",
      "T1005" => "Data from Local System",
      "T1486" => "Data Encrypted for Impact",
      "T1021" => "Remote Services"
    }

    load_all_anomalies(org_id)
    |> Enum.flat_map(fn a -> a.mitre_techniques || [] end)
    |> Enum.frequencies()
    |> Enum.sort_by(fn {_t, count} -> count end, :desc)
    |> Enum.take(limit)
    |> Enum.map(fn {technique, count} ->
      %{
        technique: technique,
        name: Map.get(mitre_name_map, technique, technique),
        count: count
      }
    end)
  end

  defp calculate_percentile(org_id, entity_type, entity_id, metric) do
    all = list_entities(org_id, entity_type, 10000, 0)

    if length(all) == 0 do
      50
    else
      entity = Enum.find(all, fn e -> e.id == entity_id end)
      entity_value = case metric do
        :risk_score -> (entity && entity.risk_score) || 0
        :event_volume -> (entity && entity.total_events) || 0
        :anomaly_rate -> 0
        _ -> 0
      end

      values = Enum.map(all, fn e ->
        case metric do
          :risk_score -> e.risk_score
          :event_volume -> e.total_events
          _ -> 0
        end
      end) |> Enum.sort()

      below = Enum.count(values, fn v -> v < entity_value end)
      round(below / length(values) * 100)
    end
  rescue
    _ -> 50
  end

  defp get_peer_group_size(org_id, entity_type) do
    list_entities(org_id, entity_type, 10000, 0) |> length()
  end

  defp interval_seconds("5m"), do: 300
  defp interval_seconds("1h"), do: 3600
  defp interval_seconds("1d"), do: 86400
  defp interval_seconds(_), do: 3600

  defp hours_ago(hours) do
    DateTime.add(DateTime.utc_now(), -hours * 3600, :second)
  end

  defp days_ago(days) do
    DateTime.add(DateTime.utc_now(), -days * 86400, :second)
  end

  defp get_peer_group(org_id, entity_type, _entity_id) do
    # Return all entities of the same type as the peer group
    list_entities(org_id, entity_type, 1000, 0)
  end

  defp calculate_peer_metrics(profile, peer_group) do
    if length(peer_group) == 0 do
      %{
        avg_risk: 0,
        median_risk: 0,
        stddev_risk: 0,
        z_score: 0.0,
        percentile: 50,
        avg_events: 0,
        event_deviation: 0,
        most_similar: [],
        least_similar: [],
        similarity_score: 0.0
      }
    else
      risk_scores = Enum.map(peer_group, & &1.risk_score)
      event_counts = Enum.map(peer_group, & &1.total_events)

      avg_risk = Enum.sum(risk_scores) / length(risk_scores)
      sorted_risks = Enum.sort(risk_scores)
      median_risk = Enum.at(sorted_risks, div(length(sorted_risks), 2)) || 0

      # Standard deviation
      variance = if length(risk_scores) > 1 do
        Enum.map(risk_scores, fn s -> (s - avg_risk) * (s - avg_risk) end)
        |> Enum.sum()
        |> Kernel./(length(risk_scores) - 1)
      else
        0
      end
      stddev_risk = :math.sqrt(variance)

      # Entity's own risk (from profile total_events as proxy)
      entity_events = profile.total_events || 0
      avg_events = if length(event_counts) > 0, do: Enum.sum(event_counts) / length(event_counts), else: 0

      z_score = if stddev_risk > 0, do: (0 - avg_risk) / stddev_risk, else: 0.0

      below = Enum.count(risk_scores, fn s -> s < 0 end)
      percentile = round(below / length(risk_scores) * 100)

      %{
        avg_risk: Float.round(avg_risk / 1, 1),
        median_risk: median_risk,
        stddev_risk: Float.round(stddev_risk / 1, 2),
        z_score: Float.round(z_score / 1, 2),
        percentile: percentile,
        avg_events: Float.round(avg_events / 1, 1),
        event_deviation: entity_events - round(avg_events),
        most_similar: [],
        least_similar: [],
        similarity_score: 0.0
      }
    end
  end

  defp get_peer_criteria(_entity_type) do
    "Similar behavioral patterns"
  end

  defp detect_outlier_indicators(_profile, _metrics) do
    []
  end

  defp generate_recommendations(_profile, _metrics) do
    ["Continue monitoring", "No immediate action required"]
  end

  defp get_historical_events(_entity_type, _entity_id, _since, _until_dt, _limit) do
    []
  end

  defp build_timeline(events, anomalies) do
    # Merge events and anomalies into chronological timeline
    event_items = Enum.map(events, &Map.put(&1, :item_type, "event"))
    anomaly_items = Enum.map(anomalies, &Map.put(&1, :item_type, "anomaly"))

    (event_items ++ anomaly_items)
    |> Enum.sort_by(& &1[:timestamp], {:desc, DateTime})
  end

  defp determine_risk_trend(_entity_type, _entity_id) do
    "stable"
  end

  defp get_entity_techniques(_entity_type, _entity_id) do
    []
  end

  # ============================================================================
  # Detection Categories API
  # ============================================================================

  @doc """
  Get anomalies grouped by detection category.

  Returns counts and recent anomalies for each category:
  - Unusual process execution
  - Abnormal network patterns
  - Credential access anomalies
  - Lateral movement indicators
  - Data exfiltration patterns
  - Privilege escalation attempts
  """
  def detection_categories(conn, params) do
    with {:ok, org_id} <- require_org_id(conn) do
      since = parse_datetime(params["since"]) || hours_ago(24)
      limit_per_category = parse_int(params["limit"], 10)

      all_anomalies = load_all_anomalies(org_id)
      |> Enum.filter(fn a ->
        not is_nil(a.timestamp) and DateTime.compare(a.timestamp, since) != :lt
      end)

      categories = %{
      unusual_process: %{
        name: "Unusual Process Execution",
        description: "Processes executed by unexpected users or from unusual locations",
        mitre_techniques: ["T1055", "T1106", "T1036"],
        anomalies: filter_by_types(all_anomalies, [:unusual_process_for_user, :unusual_parent_process, :rule_match], limit_per_category),
        count: count_by_types(all_anomalies, [:unusual_process_for_user, :unusual_parent_process, :rule_match]),
        severity_distribution: severity_dist_by_types(all_anomalies, [:unusual_process_for_user, :unusual_parent_process, :rule_match])
      },
      abnormal_network: %{
        name: "Abnormal Network Patterns",
        description: "Unusual network connections, ports, or data volumes",
        mitre_techniques: ["T1071", "T1571", "T1095"],
        anomalies: filter_by_types(all_anomalies, [:unusual_network_port, :suspicious_port, :large_data_transfer], limit_per_category),
        count: count_by_types(all_anomalies, [:unusual_network_port, :suspicious_port, :large_data_transfer]),
        severity_distribution: severity_dist_by_types(all_anomalies, [:unusual_network_port, :suspicious_port, :large_data_transfer])
      },
      credential_access: %{
        name: "Credential Access Anomalies",
        description: "Suspicious credential harvesting or access patterns",
        mitre_techniques: ["T1003", "T1555", "T1552"],
        anomalies: filter_by_mitre(all_anomalies, ["T1003", "T1555", "T1552"], limit_per_category),
        count: count_by_mitre(all_anomalies, ["T1003", "T1555", "T1552"]),
        severity_distribution: severity_dist_by_mitre(all_anomalies, ["T1003", "T1555", "T1552"])
      },
      lateral_movement: %{
        name: "Lateral Movement Indicators",
        description: "Signs of attacker moving through the network",
        mitre_techniques: ["T1021", "T1047", "T1570"],
        anomalies: filter_by_mitre(all_anomalies, ["T1021", "T1047", "T1570"], limit_per_category),
        count: count_by_mitre(all_anomalies, ["T1021", "T1047", "T1570"]),
        severity_distribution: severity_dist_by_mitre(all_anomalies, ["T1021", "T1047", "T1570"])
      },
      data_exfiltration: %{
        name: "Data Exfiltration Patterns",
        description: "Large data transfers or unusual outbound traffic",
        mitre_techniques: ["T1041", "T1567", "T1048"],
        anomalies: filter_by_types(all_anomalies, [:large_data_transfer], limit_per_category) ++
                   filter_by_mitre(all_anomalies, ["T1041", "T1567", "T1048"], limit_per_category),
        count: count_by_types(all_anomalies, [:large_data_transfer]) +
               count_by_mitre(all_anomalies, ["T1041", "T1567", "T1048"]),
        severity_distribution: severity_dist_by_mitre(all_anomalies, ["T1041", "T1567", "T1048"])
      },
      privilege_escalation: %{
        name: "Privilege Escalation Attempts",
        description: "Attempts to gain elevated privileges",
        mitre_techniques: ["T1548", "T1068", "T1134"],
        anomalies: filter_by_mitre(all_anomalies, ["T1548", "T1068", "T1134"], limit_per_category),
        count: count_by_mitre(all_anomalies, ["T1548", "T1068", "T1134"]),
        severity_distribution: severity_dist_by_mitre(all_anomalies, ["T1548", "T1068", "T1134"])
      },
      impossible_travel: %{
        name: "Impossible Travel",
        description: "Geographically impossible login patterns",
        mitre_techniques: ["T1078"],
        anomalies: filter_by_types(all_anomalies, [:impossible_travel], limit_per_category),
        count: count_by_types(all_anomalies, [:impossible_travel]),
        severity_distribution: severity_dist_by_types(all_anomalies, [:impossible_travel])
      },
      unusual_login: %{
        name: "Unusual Login Activity",
        description: "Logins at unusual times or from new locations",
        mitre_techniques: ["T1078"],
        anomalies: filter_by_types(all_anomalies, [:unusual_login_time, :new_source_ip], limit_per_category),
        count: count_by_types(all_anomalies, [:unusual_login_time, :new_source_ip]),
        severity_distribution: severity_dist_by_types(all_anomalies, [:unusual_login_time, :new_source_ip])
      }
    }

      json(conn, %{
        data: categories,
        meta: %{
          since: since,
          total_anomalies: length(all_anomalies),
          generated_at: DateTime.utc_now()
        }
      })
    end
  end

  # ============================================================================
  # Threshold Configuration API
  # ============================================================================

  @doc """
  Get current detection thresholds.
  """
  def thresholds(conn, _params) do
    with {:ok, _org_id} <- require_org_id(conn) do
      alias TamanduaServer.Detection.Config

      thresholds = %{
        z_score_threshold: Config.z_score_threshold(),
        risk_score_alert_threshold: Config.risk_score_alert_threshold(),
        large_transfer_bytes: Config.large_transfer_bytes(),
        impossible_travel_speed_kmh: Config.impossible_travel_speed_kmh(),
        suspicious_ports: Config.suspicious_ports(),
        baseline_update_interval_ms: Config.baseline_update_interval(),
        baseline_persist_interval_ms: Config.baseline_persist_interval()
      }

      json(conn, %{
        data: thresholds,
        meta: %{
          configurable: true,
          last_updated: DateTime.utc_now()
        }
      })
    end
  end

  @doc """
  Update detection thresholds (requires admin).
  """
  def update_thresholds(conn, params) do
    with {:ok, _org_id} <- require_org_id(conn) do
      # In production, this would update the Config module or database
      # For now, return acknowledgment
      json(conn, %{
        success: true,
        message: "Threshold update queued",
        updated: Map.take(params, ["z_score_threshold", "risk_score_alert_threshold", "large_transfer_bytes"])
      })
    end
  end

  # ============================================================================
  # Whitelist / Suppress Patterns API
  # ============================================================================
  #
  # Routes through the canonical `TamanduaServer.Alerts.SuppressionRule` schema
  # (org-scoped via `TenantScope.scope_to_tenant`). Wire shape is preserved for
  # backwards compatibility: callers still send `pattern_type` + `pattern` and
  # receive the same flat response shape. Translation lives in
  # `build_suppression_attrs/3` (in) and `serialize_suppression/1` (out).
  # ============================================================================

  @doc """
  List suppression rules (whitelisted patterns that won't generate alerts).
  """
  def suppressions(conn, _params) do
    with {:ok, org_id} <- require_org_id(conn) do
      rules =
        Alerts.list_suppression_rules(organization_id: org_id, enabled_only: true)
        |> Enum.map(&serialize_suppression/1)

      json(conn, %{
        data: rules,
        meta: %{count: length(rules)}
      })
    end
  end

  @doc """
  Create a new suppression rule.

  ## Body Parameters
  - `pattern_type` - Type: "process_name", "command_line", "entity_id", "rule_id"
  - `pattern` - The pattern to match (string or regex)
  - `reason` - Why this is being suppressed
  - `expires_at` - Optional expiration date (ISO8601)
  - `created_by` - User who created the suppression
  """
  def create_suppression(conn, params) do
    with {:ok, org_id} <- require_org_id(conn) do
      attrs = build_suppression_attrs(params, org_id, conn.assigns[:current_user_id])

      case Alerts.create_suppression_rule(attrs) do
        {:ok, rule} ->
          json(conn, %{
            data: serialize_suppression(rule),
            success: true
          })

        {:error, changeset} ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{
            success: false,
            errors: format_changeset_errors(changeset)
          })
      end
    end
  end

  @doc """
  Delete a suppression rule.
  """
  def delete_suppression(conn, %{"id" => id}) do
    with {:ok, org_id} <- require_org_id(conn) do
      case Alerts.get_suppression_rule_for_org(org_id, id) do
        {:ok, rule} ->
          case Alerts.delete_suppression_rule(rule) do
            {:ok, _} ->
              json(conn, %{
                success: true,
                message: "Suppression rule deleted"
              })

            {:error, _changeset} ->
              conn
              |> put_status(:internal_server_error)
              |> json(%{
                success: false,
                error: "Failed to delete suppression rule"
              })
          end

        {:error, :not_found} ->
          conn
          |> put_status(:not_found)
          |> json(%{
            success: false,
            error: "Suppression rule not found"
          })
      end
    end
  end

  # ============================================================================
  # Heat Map Data API
  # ============================================================================

  @doc """
  Get heat map data for anomaly visualization.

  Returns anomaly counts bucketed by time and entity for heat map rendering.

  ## Query Parameters
  - `period` - Time period: "24h", "7d", "30d" (default: "7d")
  - `entity_type` - Filter by entity type
  - `bucket_size` - Time bucket: "1h", "6h", "1d" (default: "1h" for 24h, "6h" for 7d, "1d" for 30d)
  """
  def heatmap(conn, params) do
    with {:ok, org_id} <- require_org_id(conn) do
      period = params["period"] || "7d"
      entity_type = params["entity_type"]

    {start_time, bucket_size, bucket_count} = case period do
      "24h" -> {hours_ago(24), "1h", 24}
      "7d" -> {days_ago(7), "6h", 28}
      "30d" -> {days_ago(30), "1d", 30}
      _ -> {days_ago(7), "6h", 28}
    end

    bucket_seconds = case bucket_size do
      "1h" -> 3600
      "6h" -> 21600
      "1d" -> 86400
      _ -> 3600
    end

    all_anomalies = load_all_anomalies(org_id)
    |> Enum.filter(fn a ->
      (is_nil(entity_type) or to_string(a.entity_type) == entity_type) and
      not is_nil(a.timestamp) and
      DateTime.compare(a.timestamp, start_time) != :lt
    end)

    # Get unique entities
    entities = all_anomalies
    |> Enum.map(fn a -> {a.entity_type, a.entity_id} end)
    |> Enum.uniq()
    |> Enum.take(50)

    # Build heat map matrix
    heatmap_data = Enum.map(0..(bucket_count - 1), fn bucket_idx ->
      bucket_start = DateTime.add(start_time, bucket_idx * bucket_seconds, :second)
      bucket_end = DateTime.add(start_time, (bucket_idx + 1) * bucket_seconds, :second)

      bucket_anomalies = Enum.filter(all_anomalies, fn a ->
        DateTime.compare(a.timestamp, bucket_start) != :lt and
        DateTime.compare(a.timestamp, bucket_end) == :lt
      end)

      entity_counts = Enum.map(entities, fn {etype, eid} ->
        count = Enum.count(bucket_anomalies, fn a ->
          a.entity_type == etype and a.entity_id == eid
        end)
        max_risk = bucket_anomalies
        |> Enum.filter(fn a -> a.entity_type == etype and a.entity_id == eid end)
        |> Enum.map(& &1.risk_score)
        |> Enum.max(fn -> 0 end)

        %{entity_type: etype, entity_id: eid, count: count, max_risk: max_risk}
      end)

      %{
        timestamp: bucket_start,
        bucket_index: bucket_idx,
        total_count: length(bucket_anomalies),
        avg_risk: if(length(bucket_anomalies) > 0,
          do: Enum.sum(Enum.map(bucket_anomalies, & &1.risk_score)) / length(bucket_anomalies),
          else: 0),
        entities: entity_counts
      }
    end)

      json(conn, %{
        data: %{
          heatmap: heatmap_data,
          entities: Enum.map(entities, fn {t, id} -> %{type: t, id: id} end),
          period: period,
          bucket_size: bucket_size
        },
        meta: %{
          start_time: start_time,
          bucket_count: bucket_count,
          entity_count: length(entities)
        }
      })
    end
  end

  # ============================================================================
  # Drill-down API (anomaly to raw events)
  # ============================================================================

  @doc """
  Get raw events associated with an anomaly for investigation.
  """
  def anomaly_events(conn, %{"anomaly_id" => anomaly_id} = params) do
    with {:ok, org_id} <- require_org_id(conn) do
      limit = parse_int(params["limit"], 50)

      # In production, this would query the telemetry/events table
      # For now, we return a structured response indicating what events would be fetched
      events = fetch_events_for_anomaly(org_id, anomaly_id, limit)

      json(conn, %{
        data: %{
          anomaly_id: anomaly_id,
          events: events,
          count: length(events)
        },
        meta: %{
          limit: limit
        }
      })
    end
  end

  defp fetch_events_for_anomaly(_org_id, _anomaly_id, _limit) do
    # In production, query TamanduaServer.Telemetry for events
    # matching the anomaly's entity (scoped to org_id) and time window.
    # org_id is required at the call site to prevent cross-tenant event leaks
    # once this stub is filled in.
    []
  end

  # ============================================================================
  # Threat Correlation API
  # ============================================================================

  @doc """
  Correlate anomalies with known threat intelligence.
  """
  def correlate_threats(conn, params) do
    with {:ok, org_id} <- require_org_id(conn) do
      entity_type = params["entity_type"]
      entity_id = params["entity_id"]

      # Get anomalies for the entity
      anomalies = get_entity_anomalies(org_id, entity_type, entity_id, 100)

      # Extract indicators from anomalies
      indicators = Enum.flat_map(anomalies, fn a ->
        extract_indicators_from_anomaly(a)
      end) |> Enum.uniq()

      # Check each indicator against the IOCs database for real matches
      correlations = Enum.map(indicators, fn indicator ->
        ioc_matches = check_indicator_against_iocs(indicator)
        confidence = if length(ioc_matches) > 0, do: 0.8, else: 0.0

        %{
          indicator: indicator,
          matches: ioc_matches,
          confidence: confidence
        }
      end)

      json(conn, %{
        data: %{
          entity_type: entity_type,
          entity_id: entity_id,
          anomaly_count: length(anomalies),
          indicators: indicators,
          correlations: correlations
        }
      })
    end
  end

  defp extract_indicators_from_anomaly(a) when is_map(a) do
    case a.observed_value do
      value when is_binary(value) -> [value]
      value when is_map(value) -> Map.values(value) |> Enum.filter(&is_binary/1)
      _ -> []
    end
  end
  defp extract_indicators_from_anomaly(_), do: []

  defp check_indicator_against_iocs(indicator) when is_binary(indicator) do
    # Determine indicator type heuristically and look up against IOCs
    indicator_type = classify_indicator(indicator)

    case IOCs.lookup(indicator_type, indicator) do
      {:ok, ioc} ->
        [%{
          type: ioc.type,
          value: ioc.value,
          severity: ioc.severity,
          source: ioc.source,
          description: ioc.description,
          tags: ioc.tags || []
        }]
      {:error, :not_found} ->
        []
    end
  rescue
    e ->
      Logger.warning("IOC lookup failed for indicator #{inspect(indicator)}: #{Exception.message(e)}")
      []
  end
  defp check_indicator_against_iocs(_), do: []

  defp classify_indicator(indicator) do
    cond do
      Regex.match?(~r/^[0-9a-f]{64}$/i, indicator) -> "hash_sha256"
      Regex.match?(~r/^[0-9a-f]{40}$/i, indicator) -> "hash_sha1"
      Regex.match?(~r/^[0-9a-f]{32}$/i, indicator) -> "hash_md5"
      Regex.match?(~r/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/, indicator) -> "ip"
      Regex.match?(~r/^https?:\/\//, indicator) -> "url"
      Regex.match?(~r/@/, indicator) -> "email"
      Regex.match?(~r/^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$/, indicator) -> "domain"
      true -> "domain"
    end
  end

  # ============================================================================
  # Helper Functions for Categories
  # ============================================================================

  defp filter_by_types(anomalies, types, limit) do
    anomalies
    |> Enum.filter(fn a -> a.anomaly_type in types end)
    |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})
    |> Enum.take(limit)
    |> Enum.map(&serialize_anomaly/1)
  end

  defp count_by_types(anomalies, types) do
    Enum.count(anomalies, fn a -> a.anomaly_type in types end)
  end

  defp severity_dist_by_types(anomalies, types) do
    anomalies
    |> Enum.filter(fn a -> a.anomaly_type in types end)
    |> Enum.group_by(fn a ->
      cond do
        a.risk_score >= 90 -> "critical"
        a.risk_score >= 75 -> "high"
        a.risk_score >= 50 -> "medium"
        true -> "low"
      end
    end)
    |> Enum.map(fn {severity, items} -> {severity, length(items)} end)
    |> Enum.into(%{})
  end

  defp filter_by_mitre(anomalies, techniques, limit) do
    anomalies
    |> Enum.filter(fn a ->
      Enum.any?(a.mitre_techniques || [], fn t ->
        Enum.any?(techniques, &String.starts_with?(t, &1))
      end)
    end)
    |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})
    |> Enum.take(limit)
    |> Enum.map(&serialize_anomaly/1)
  end

  defp count_by_mitre(anomalies, techniques) do
    Enum.count(anomalies, fn a ->
      Enum.any?(a.mitre_techniques || [], fn t ->
        Enum.any?(techniques, &String.starts_with?(t, &1))
      end)
    end)
  end

  defp severity_dist_by_mitre(anomalies, techniques) do
    anomalies
    |> Enum.filter(fn a ->
      Enum.any?(a.mitre_techniques || [], fn t ->
        Enum.any?(techniques, &String.starts_with?(t, &1))
      end)
    end)
    |> Enum.group_by(fn a ->
      cond do
        a.risk_score >= 90 -> "critical"
        a.risk_score >= 75 -> "high"
        a.risk_score >= 50 -> "medium"
        true -> "low"
      end
    end)
    |> Enum.map(fn {severity, items} -> {severity, length(items)} end)
    |> Enum.into(%{})
  end

  # ============================================================================
  # Suppression Helpers
  # ============================================================================

  # Translates the shim's wire format ({pattern_type, pattern, reason, ...})
  # into a SuppressionRule changeset attrs map. Known pattern_types map to
  # typed columns; unknown ones fall through to the JSON `criteria` field so
  # the changeset's `validate_has_criteria/1` still passes.
  defp build_suppression_attrs(params, org_id, current_user_id) do
    pattern_type = params["pattern_type"]
    pattern = params["pattern"] || ""
    reason = params["reason"]
    expires_at = parse_datetime(params["expires_at"])
    created_by_id = params["created_by"] || current_user_id

    %{
      "name" => synth_suppression_name(pattern_type, pattern, reason),
      "description" => reason,
      "action" => "suppress",
      "organization_id" => org_id,
      "created_by_id" => created_by_id,
      "enabled" => true
    }
    |> Map.merge(translate_pattern(pattern_type, pattern))
    |> maybe_put_expiry(expires_at)
  end

  defp synth_suppression_name(pattern_type, pattern, reason) do
    label = pattern_type || "manual"
    preview = (reason || "") |> to_string() |> String.slice(0, 40)

    base = "#{label}: #{pattern}"
    name = if preview != "", do: "#{base} — #{preview}", else: base
    String.slice(name, 0, 200)
  end

  defp translate_pattern("process_name", pattern), do: %{"process_name_pattern" => pattern}
  defp translate_pattern("rule_id", pattern), do: %{"rule_name_pattern" => pattern}
  defp translate_pattern("command_line", pattern), do: %{"criteria" => %{"command_line" => pattern}}
  defp translate_pattern("entity_id", pattern), do: %{"criteria" => %{"entity_id" => pattern}}
  defp translate_pattern(other, pattern) do
    %{"criteria" => %{"pattern_type" => other, "pattern" => pattern}}
  end

  defp maybe_put_expiry(attrs, nil), do: attrs
  defp maybe_put_expiry(attrs, %DateTime{} = dt) do
    attrs
    |> Map.put("time_window_type", "until_date")
    |> Map.put("expires_at", dt)
  end

  # Serializes a SuppressionRule back into the legacy flat shape the existing
  # behavioral UI consumes. derive_pattern/1 reverses translate_pattern/2.
  defp serialize_suppression(%SuppressionRule{} = rule) do
    {pattern_type, pattern} = derive_pattern(rule)

    %{
      id: rule.id,
      pattern_type: pattern_type,
      pattern: pattern,
      reason: rule.description,
      created_by: rule.created_by_id,
      created_at: rule.inserted_at,
      expires_at: rule.expires_at,
      enabled: rule.enabled
    }
  end

  defp derive_pattern(%SuppressionRule{process_name_pattern: p}) when is_binary(p) and p != "" do
    {"process_name", p}
  end
  defp derive_pattern(%SuppressionRule{rule_name_pattern: p}) when is_binary(p) and p != "" do
    {"rule_id", p}
  end
  defp derive_pattern(%SuppressionRule{criteria: %{"command_line" => p}}) when is_binary(p) do
    {"command_line", p}
  end
  defp derive_pattern(%SuppressionRule{criteria: %{"entity_id" => p}}) when is_binary(p) do
    {"entity_id", p}
  end
  defp derive_pattern(%SuppressionRule{criteria: %{"pattern_type" => t, "pattern" => p}})
       when is_binary(t) and is_binary(p) do
    {t, p}
  end
  defp derive_pattern(_), do: {nil, nil}

  defp format_changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_atom(key), key) |> to_string()
      end)
    end)
  end

  defp parse_int(nil, default), do: default
  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(value, _default) when is_integer(value), do: value
  defp parse_int(_, default), do: default

  defp parse_datetime(nil), do: nil
  defp parse_datetime(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _} -> datetime
      _ -> nil
    end
  end
  defp parse_datetime(_), do: nil
end
