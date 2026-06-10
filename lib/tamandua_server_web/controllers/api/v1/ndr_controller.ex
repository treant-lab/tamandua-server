defmodule TamanduaServerWeb.API.V1.NDRController do
  @moduledoc """
  API Controller for Network Detection and Response (NDR) capabilities.

  Provides endpoints for:
  - Flow queries and statistics
  - Protocol analysis
  - Lateral movement detection
  - Encrypted traffic analysis
  - Network topology
  - Anomaly alerts
  """

  use TamanduaServerWeb, :controller
  import Ecto.Query, warn: false
  require Logger

  alias TamanduaServer.NDR.{FlowAnalyzer, ProtocolAnalyzer, LateralDetector, EncryptedTraffic}
  alias TamanduaServer.Repo
  alias TamanduaServer.Telemetry.{ClickHouse, ClickHouseQuery, ClickHouseWriter}

  # ============================================================================
  # Flow Endpoints
  # ============================================================================

  @doc """
  GET /api/v1/ndr/flows

  Get active network flows with optional filtering.

  Query params:
  - agent_id: Filter by agent
  - protocol: Filter by protocol (TCP, UDP, etc.)
  - limit: Maximum results (default 100)
  """
  def list_flows(conn, params) do
    opts = build_flow_opts(params)

    flows = FlowAnalyzer.get_flows(opts)
    |> Enum.map(&serialize_flow/1)

    json(conn, %{
      data: flows,
      meta: %{
        count: length(flows),
        filters: opts
      }
    })
  end

  @doc """
  GET /api/v1/ndr/flows/stats

  Get aggregated flow statistics.

  Query params:
  - agent_id: Filter by agent
  - time_range: minute, hour, day (default hour)
  """
  def flow_stats(conn, params) do
    opts = [
      agent_id: params["agent_id"],
      protocol: params["protocol"] |> normalize_protocol(),
      time_range: parse_time_range(params["time_range"]),
      mode: parse_data_mode(params["mode"] || params["source"])
    ]
    |> Enum.reject(fn {_, v} -> is_nil(v) end)

    stats = FlowAnalyzer.get_flow_stats(opts)

    json(conn, %{data: serialize_flow_stats(stats)})
  end

  @doc """
  GET /api/v1/ndr/top-talkers

  Get hosts with highest traffic volumes.

  Query params:
  - agent_id: Filter by agent
  - sort_by: total_bytes, bytes_sent, bytes_received (default total_bytes)
  - limit: Maximum results (default 20)
  """
  def top_talkers(conn, params) do
    opts = [
      agent_id: params["agent_id"],
      sort_by: parse_sort_by(params["sort_by"]),
      limit: parse_limit(params["limit"], 20),
      mode: parse_data_mode(params["mode"] || params["source"])
    ]
    |> Enum.reject(fn {_, v} -> is_nil(v) end)

    talkers = FlowAnalyzer.get_top_talkers(opts)
    |> Enum.map(&serialize_top_talker/1)

    json(conn, %{
      data: talkers,
      meta: %{count: length(talkers)}
    })
  end

  # ============================================================================
  # Topology and Visualization
  # ============================================================================

  @doc """
  GET /api/v1/ndr/topology

  Get network topology data for visualization.

  Query params:
  - agent_id: Filter by agent
  """
  def topology(conn, params) do
    opts = [
      agent_id: params["agent_id"],
      mode: parse_data_mode(params["mode"] || params["source"])
    ]
    |> Enum.reject(fn {_, v} -> is_nil(v) end)

    topology = FlowAnalyzer.get_topology(opts)

    json(conn, %{
      data: %{
        nodes: topology.nodes,
        edges: Enum.map(topology.edges, &serialize_edge/1),
        summary: topology.summary
      }
    })
  end

  @doc """
  GET /api/v1/ndr/connection-graph

  Get lateral movement connection graph.

  Query params:
  - agent_id: Filter by agent
  """
  def connection_graph(conn, params) do
    opts =
      [agent_id: params["agent_id"]]
      |> Enum.reject(fn {_, v} -> is_nil(v) end)

    graph = LateralDetector.get_connection_graph(opts)

    json(conn, %{
      data: %{
        nodes: graph.nodes,
        edges: Enum.map(graph.edges, &serialize_lateral_edge/1),
        summary: graph.summary
      }
    })
  end

  # ============================================================================
  # Protocol Analysis
  # ============================================================================

  @doc """
  GET /api/v1/ndr/protocols

  Get protocol distribution statistics.

  Query params:
  - agent_id: Filter by agent
  """
  def protocol_distribution(conn, params) do
    opts =
      [
        agent_id: params["agent_id"],
        mode: parse_data_mode(params["mode"] || params["source"])
      ]
      |> Enum.reject(fn {_, v} -> is_nil(v) end)

    distribution = FlowAnalyzer.get_protocol_distribution(opts)

    json(conn, %{
      data: distribution,
      meta: %{total_protocols: length(distribution)}
    })
  end

  @doc """
  GET /api/v1/ndr/protocols/stats

  Get detailed protocol statistics.
  """
  def protocol_stats(conn, params) do
    opts = [agent_id: params["agent_id"]]
    |> Enum.reject(fn {_, v} -> is_nil(v) end)

    stats = ProtocolAnalyzer.get_protocol_stats(opts)
    |> Enum.map(&serialize_protocol_stats/1)

    json(conn, %{data: stats})
  end

  @doc """
  GET /api/v1/ndr/smb

  Get SMB activity analysis.

  Query params:
  - agent_id: Filter by agent
  - limit: Maximum results (default 100)
  """
  def smb_activity(conn, params) do
    opts = [
      agent_id: params["agent_id"],
      limit: parse_limit(params["limit"], 100)
    ]
    |> Enum.reject(fn {_, v} -> is_nil(v) end)

    activity = ProtocolAnalyzer.get_smb_activity(opts)
    |> Enum.map(&serialize_smb_activity/1)

    json(conn, %{
      data: activity,
      meta: %{count: length(activity)}
    })
  end

  @doc """
  GET /api/v1/ndr/rdp

  Get RDP session information.

  Query params:
  - agent_id: Filter by agent
  - limit: Maximum results (default 50)
  """
  def rdp_sessions(conn, params) do
    opts = [
      agent_id: params["agent_id"],
      limit: parse_limit(params["limit"], 50)
    ]
    |> Enum.reject(fn {_, v} -> is_nil(v) end)

    sessions = ProtocolAnalyzer.get_rdp_sessions(opts)
    |> Enum.map(&serialize_remote_session/1)

    json(conn, %{
      data: sessions,
      meta: %{count: length(sessions)}
    })
  end

  @doc """
  GET /api/v1/ndr/ssh

  Get SSH session information.

  Query params:
  - agent_id: Filter by agent
  - limit: Maximum results (default 50)
  """
  def ssh_sessions(conn, params) do
    opts = [
      agent_id: params["agent_id"],
      limit: parse_limit(params["limit"], 50)
    ]
    |> Enum.reject(fn {_, v} -> is_nil(v) end)

    sessions = ProtocolAnalyzer.get_ssh_sessions(opts)
    |> Enum.map(&serialize_remote_session/1)

    json(conn, %{
      data: sessions,
      meta: %{count: length(sessions)}
    })
  end

  # ============================================================================
  # Lateral Movement
  # ============================================================================

  @doc """
  GET /api/v1/ndr/lateral-movement

  Get detected lateral movement patterns.

  Query params:
  - agent_id: Filter by agent
  - type: port_scan, host_scan, credential_spread, etc.
  - limit: Maximum results (default 100)
  """
  def lateral_movement(conn, params) do
    opts = [
      agent_id: params["agent_id"],
      type: parse_lateral_type(params["type"]),
      limit: parse_limit(params["limit"], 100)
    ]
    |> Enum.reject(fn {_, v} -> is_nil(v) end)

    movements = LateralDetector.get_lateral_movement(opts)
    |> Enum.map(&serialize_lateral_movement/1)

    json(conn, %{
      data: movements,
      meta: %{count: length(movements)}
    })
  end

  @doc """
  GET /api/v1/ndr/scan-activity

  Get port/host scan activity.

  Query params:
  - agent_id: Filter by agent
  - limit: Maximum results (default 50)
  """
  def scan_activity(conn, params) do
    opts = [
      agent_id: params["agent_id"],
      limit: parse_limit(params["limit"], 50)
    ]
    |> Enum.reject(fn {_, v} -> is_nil(v) end)

    activity = LateralDetector.get_scan_activity(opts)
    |> Enum.map(&serialize_scan_activity/1)

    json(conn, %{
      data: activity,
      meta: %{count: length(activity)}
    })
  end

  @doc """
  GET /api/v1/ndr/credential-activity

  Get credential spread tracking.

  Query params:
  - agent_id: Filter by agent
  - limit: Maximum results (default 50)
  """
  def credential_activity(conn, params) do
    opts = [
      agent_id: params["agent_id"],
      limit: parse_limit(params["limit"], 50)
    ]
    |> Enum.reject(fn {_, v} -> is_nil(v) end)

    activity = LateralDetector.get_credential_activity(opts)
    |> Enum.map(&serialize_credential_activity/1)

    json(conn, %{
      data: activity,
      meta: %{count: length(activity)}
    })
  end

  @doc """
  GET /api/v1/ndr/host-risk/:ip

  Get lateral movement risk score for a specific host.
  """
  def host_risk(conn, %{"ip" => ip}) do
    risk = LateralDetector.get_host_risk_score(ip)

    json(conn, %{data: risk})
  end

  # ============================================================================
  # Encrypted Traffic
  # ============================================================================

  @doc """
  GET /api/v1/ndr/ja3

  Get JA3 fingerprint statistics.

  Query params:
  - limit: Maximum results (default 50)
  - sort_by: occurrence_count, unique_agents (default occurrence_count)
  """
  def ja3_stats(conn, params) do
    opts = [
      limit: parse_limit(params["limit"], 50),
      sort_by: parse_ja3_sort(params["sort_by"])
    ]
    |> Enum.reject(fn {_, v} -> is_nil(v) end)

    stats = EncryptedTraffic.get_ja3_stats(opts)
    |> Enum.map(&serialize_ja3_stats/1)

    json(conn, %{
      data: stats,
      meta: %{count: length(stats)}
    })
  end

  @doc """
  POST /api/v1/ndr/ja3/check

  Check a JA3 fingerprint against known signatures.

  Body:
  - ja3_hash: The JA3 hash to check
  """
  def check_ja3(conn, %{"ja3_hash" => ja3_hash}) do
    result = case EncryptedTraffic.check_ja3(ja3_hash) do
      {:match, info} ->
        %{
          status: "malicious",
          ja3_hash: ja3_hash,
          matched: true,
          signature: info
        }
      {:ok, :clean} ->
        %{
          status: "clean",
          ja3_hash: ja3_hash,
          matched: false
        }
    end

    json(conn, %{data: result})
  end

  @doc """
  POST /api/v1/ndr/ja3/add

  Add a custom JA3 signature to the detection database.

  Body:
  - ja3_hash: The JA3 hash
  - name: Signature name
  - type: c2, malware, suspicious
  """
  def add_ja3_signature(conn, %{"ja3_hash" => ja3_hash} = params) do
    metadata = %{
      name: params["name"] || "Custom Signature",
      type: parse_ja3_type(params["type"]),
      description: params["description"]
    }

    EncryptedTraffic.add_ja3_signature(ja3_hash, metadata)

    json(conn, %{
      data: %{
        status: "added",
        ja3_hash: ja3_hash,
        metadata: metadata
      }
    })
  end

  @doc """
  GET /api/v1/ndr/certificates

  Get certificate analysis results.

  Query params:
  - agent_id: Filter by agent
  - limit: Maximum results (default 50)
  """
  def certificate_analysis(conn, params) do
    opts = [
      agent_id: params["agent_id"],
      limit: parse_limit(params["limit"], 50)
    ]
    |> Enum.reject(fn {_, v} -> is_nil(v) end)

    analysis = EncryptedTraffic.get_certificate_analysis(opts)
    |> Enum.map(&serialize_certificate/1)

    json(conn, %{
      data: analysis,
      meta: %{count: length(analysis)}
    })
  end

  @doc """
  GET /api/v1/ndr/tls-sessions

  Get TLS session information.

  Query params:
  - agent_id: Filter by agent
  - limit: Maximum results (default 100)
  """
  def tls_sessions(conn, params) do
    opts = [
      agent_id: params["agent_id"],
      limit: parse_limit(params["limit"], 100)
    ]
    |> Enum.reject(fn {_, v} -> is_nil(v) end)

    sessions = EncryptedTraffic.get_tls_sessions(opts)
    |> Enum.map(&serialize_tls_session/1)

    json(conn, %{
      data: sessions,
      meta: %{count: length(sessions)}
    })
  end

  # ============================================================================
  # Anomalies and Alerts
  # ============================================================================

  @doc """
  GET /api/v1/ndr/anomalies

  Get detected network anomalies.

  Query params:
  - agent_id: Filter by agent
  - limit: Maximum results (default 50)
  """
  def anomalies(conn, params) do
    opts = [
      agent_id: params["agent_id"],
      limit: parse_limit(params["limit"], 50)
    ]
    |> Enum.reject(fn {_, v} -> is_nil(v) end)

    anomalies = FlowAnalyzer.detect_anomalies(opts)
    |> Enum.map(&serialize_anomaly/1)

    json(conn, %{
      data: anomalies,
      meta: %{count: length(anomalies)}
    })
  end

  # ============================================================================
  # Stats and Health
  # ============================================================================

  @doc """
  GET /api/v1/ndr/stats

  Get overall NDR statistics from all modules.
  """
  def stats(conn, _params) do
    flow_stats = try do
      FlowAnalyzer.get_stats()
    rescue
      _ -> %{}
    catch
      _, _ -> %{}
    end

    protocol_stats = try do
      ProtocolAnalyzer.get_stats()
    rescue
      _ -> %{}
    catch
      _, _ -> %{}
    end

    lateral_stats = try do
      LateralDetector.get_stats()
    rescue
      _ -> %{}
    catch
      _, _ -> %{}
    end

    encrypted_stats = try do
      EncryptedTraffic.get_stats()
    rescue
      _ -> %{}
    catch
      _, _ -> %{}
    end

    combined_stats = %{
      flow_analyzer: flow_stats,
      protocol_analyzer: protocol_stats,
      lateral_detector: lateral_stats,
      encrypted_traffic: encrypted_stats,
      summary: %{
        total_flows_processed: flow_stats[:flows_processed] || 0,
        total_events_analyzed: (protocol_stats[:events_analyzed] || 0) +
                               (lateral_stats[:events_analyzed] || 0) +
                               (encrypted_stats[:events_analyzed] || 0),
        total_anomalies: (flow_stats[:anomalies_detected] || 0) +
                         (lateral_stats[:lateral_movements_detected] || 0),
        total_alerts: (flow_stats[:alerts_created] || 0) +
                      (protocol_stats[:alerts_created] || 0) +
                      (lateral_stats[:alerts_created] || 0) +
                      (encrypted_stats[:alerts_created] || 0)
      }
    }

    json(conn, %{
      data: combined_stats,
      meta: %{
        data_sources: data_source_status()
      }
    })
  end

  @doc """
  GET /api/v1/ndr/data-sources

  Get NDR live and historical data source availability.
  """
  def data_sources(conn, _params) do
    json(conn, %{
      data: data_source_status(),
      timestamp: DateTime.utc_now()
    })
  end

  # ============================================================================
  # Serialization Helpers
  # ============================================================================

  defp serialize_flow(flow) do
    %{
      id: flow[:flow_key],
      agent_id: flow[:agent_id],
      src_ip: flow[:src_ip],
      src_port: flow[:src_port],
      dst_ip: flow[:dst_ip],
      dst_port: flow[:dst_port],
      protocol: flow[:protocol],
      bytes_sent: flow[:bytes_sent],
      bytes_received: flow[:bytes_received],
      total_bytes: flow[:total_bytes],
      packet_count: flow[:packet_count],
      process_name: flow[:process_name],
      process_pid: flow[:process_pid],
      first_seen: format_timestamp(flow[:first_timestamp]),
      last_seen: format_timestamp(flow[:last_timestamp]),
      duration_ms: flow_duration_ms(flow)
    }
  end

  defp serialize_flow_stats(stats) do
    %{
      total_flows: stats[:total_flows] || 0,
      total_bytes: stats[:total_bytes] || 0,
      total_packets: stats[:total_packets] || 0,
      bytes_per_second: stats[:bytes_per_second] || 0,
      unique_sources: stats[:unique_sources] || 0,
      unique_destinations: stats[:unique_destinations] || 0,
      avg_flow_duration: stats[:avg_flow_duration] || 0,
      time_range: stats[:time_range] || :hour
    }
  end

  defp serialize_top_talker(talker) do
    %{
      agent_id: talker[:agent_id],
      ip: talker[:ip],
      bytes_sent: talker[:bytes_sent] || 0,
      bytes_received: talker[:bytes_received] || 0,
      total_bytes: talker[:total_bytes] || 0,
      connection_count: talker[:connection_count] || 0,
      first_seen: format_datetime(talker[:first_seen]),
      last_seen: format_datetime(talker[:last_seen])
    }
  end

  defp serialize_edge(edge) do
    %{
      source: edge[:source],
      target: edge[:target],
      protocol: edge[:protocol],
      bytes: edge[:bytes],
      packet_count: edge[:packet_count]
    }
  end

  defp serialize_lateral_edge(edge) do
    %{
      source: edge[:source],
      target: edge[:target],
      weight: edge[:weight],
      ports: edge[:ports],
      is_lateral: edge[:is_lateral]
    }
  end

  defp serialize_protocol_stats(stats) do
    %{
      protocol: stats[:protocol],
      connection_count: stats[:connection_count],
      total_bytes: stats[:total_bytes],
      first_seen: format_datetime(stats[:first_seen]),
      last_seen: format_datetime(stats[:last_seen])
    }
  end

  defp serialize_smb_activity(activity) do
    %{
      src_ip: activity[:src_ip],
      dst_ip: activity[:dst_ip],
      command: activity[:command],
      share: activity[:share],
      file: activity[:file],
      timestamp: format_datetime(activity[:timestamp])
    }
  end

  defp serialize_remote_session(session) do
    %{
      agent_id: session[:agent_id],
      src_ip: session[:src_ip],
      dst_ip: session[:dst_ip],
      connection_count: session[:connection_count],
      first_seen: format_datetime(session[:first_seen]),
      last_seen: format_datetime(session[:last_seen])
    }
  end

  defp serialize_lateral_movement(movement) do
    %{
      type: movement[:type],
      src_ip: movement[:src_ip],
      dst_ip: movement[:dst_ip],
      port: movement[:port],
      ports_scanned: movement[:ports_scanned],
      hosts_scanned: movement[:hosts_scanned],
      username: movement[:username],
      target_hosts: movement[:target_hosts],
      timestamp: format_datetime(movement[:timestamp])
    }
  end

  defp serialize_scan_activity(activity) do
    %{
      agent_id: activity[:agent_id],
      source_ip: activity[:source_ip],
      target: activity[:target],
      type: activity[:type],
      count: activity[:count],
      first_seen: activity[:first_seen],
      last_seen: activity[:last_seen]
    }
  end

  defp serialize_credential_activity(activity) do
    %{
      username: activity[:username],
      source_ip: activity[:source_ip],
      target_hosts: activity[:target_hosts],
      host_count: activity[:host_count],
      first_seen: format_datetime(activity[:first_seen]),
      last_seen: format_datetime(activity[:last_seen])
    }
  end

  defp serialize_ja3_stats(stats) do
    %{
      agent_id: stats[:agent_id],
      organization_id: stats[:organization_id],
      ja3_hash: stats[:ja3_hash],
      ja3s_hash: stats[:ja3s_hash],
      occurrence_count: stats[:occurrence_count],
      unique_agents: stats[:unique_agents],
      unique_destinations: stats[:unique_destinations],
      destinations: stats[:destinations],
      is_malicious: stats[:is_malicious],
      malware_info: stats[:malware_info],
      metadata: stats[:metadata],
      first_seen: format_datetime(stats[:first_seen]),
      last_seen: format_datetime(stats[:last_seen])
    }
    |> reject_empty_values()
  end

  defp serialize_certificate(cert) do
    %{
      agent_id: cert[:agent_id],
      organization_id: cert[:organization_id],
      remote_ip: cert[:remote_ip],
      remote_port: cert[:remote_port],
      domain: cert[:domain],
      fingerprint: cert[:fingerprint],
      subject: cert[:subject],
      issuer: cert[:issuer],
      not_before: format_datetime(cert[:not_before]) || cert[:not_before],
      not_after: format_datetime(cert[:not_after]) || cert[:not_after],
      is_self_signed: cert[:is_self_signed],
      risk_score: cert[:risk_score],
      analysis: cert[:analysis],
      cached_at: format_datetime(cert[:cached_at])
    }
    |> reject_empty_values()
  end

  defp serialize_tls_session(session) do
    %{
      agent_id: session[:agent_id],
      organization_id: session[:organization_id],
      event_id: session[:event_id],
      local_ip: session[:local_ip],
      local_port: session[:local_port],
      remote_ip: session[:remote_ip],
      remote_port: session[:remote_port],
      protocol: session[:protocol],
      domain: session[:domain],
      ja3: session[:ja3],
      ja3s: session[:ja3s],
      sni: session[:sni],
      tls_version: session[:tls_version],
      certificate_fingerprint: session[:certificate_fingerprint],
      certificate_risk: session[:certificate_risk],
      process: session[:process],
      enrichment: session[:enrichment],
      timestamp: format_datetime(session[:timestamp])
    }
    |> reject_empty_values()
  end

  defp serialize_anomaly(anomaly) do
    %{
      type: anomaly[:type],
      confidence: anomaly[:confidence],
      description: anomaly[:description],
      mitre_techniques: anomaly[:mitre_techniques],
      flow_key: anomaly[:flow_key],
      metadata: anomaly[:metadata]
    }
  end

  # ============================================================================
  # Parsing Helpers
  # ============================================================================

  defp build_flow_opts(params) do
    [
      agent_id: params["agent_id"],
      protocol: params["protocol"] |> normalize_protocol(),
      limit: parse_limit(params["limit"], 100),
      mode: parse_data_mode(params["mode"] || params["source"])
    ]
    |> Enum.reject(fn {_, v} -> is_nil(v) end)
  end

  defp normalize_protocol(nil), do: nil
  defp normalize_protocol(p), do: String.upcase(p)

  defp parse_time_range("minute"), do: :minute
  defp parse_time_range("hour"), do: :hour
  defp parse_time_range("day"), do: :day
  defp parse_time_range(_), do: :hour

  defp parse_sort_by("bytes_sent"), do: :bytes_sent
  defp parse_sort_by("bytes_received"), do: :bytes_received
  defp parse_sort_by("connection_count"), do: :connection_count
  defp parse_sort_by(_), do: :total_bytes

  defp parse_data_mode("live"), do: :live
  defp parse_data_mode("historical"), do: :historical
  defp parse_data_mode("combined"), do: :combined
  defp parse_data_mode(_), do: :combined

  defp parse_limit(nil, default), do: default
  defp parse_limit(limit, default) when is_binary(limit) do
    case Integer.parse(limit) do
      {n, _} when n > 0 and n <= 1000 -> n
      _ -> default
    end
  end
  defp parse_limit(limit, _default) when is_integer(limit) and limit > 0 and limit <= 1000, do: limit
  defp parse_limit(_, default), do: default

  defp parse_lateral_type("port_scan"), do: :port_scan
  defp parse_lateral_type("host_scan"), do: :host_scan
  defp parse_lateral_type("credential_spread"), do: :credential_spread
  defp parse_lateral_type("lateral_movement"), do: :lateral_movement
  defp parse_lateral_type("smb_lateral_movement"), do: :smb_lateral_movement
  defp parse_lateral_type(_), do: nil

  defp parse_ja3_sort("unique_agents"), do: :unique_agents
  defp parse_ja3_sort("unique_destinations"), do: :unique_destinations
  defp parse_ja3_sort(_), do: :occurrence_count

  defp parse_ja3_type("c2"), do: :c2
  defp parse_ja3_type("malware"), do: :malware
  defp parse_ja3_type("suspicious"), do: :suspicious
  defp parse_ja3_type(_), do: :suspicious

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_datetime(other), do: other

  defp format_timestamp(nil), do: nil
  defp format_timestamp(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_timestamp(ts) when is_integer(ts) do
    case DateTime.from_unix(ts, :millisecond) do
      {:ok, dt} -> DateTime.to_iso8601(dt)
      _ -> nil
    end
  end
  defp format_timestamp(other), do: other

  defp flow_duration_ms(flow) do
    first = timestamp_ms(flow[:first_seen] || flow[:first_timestamp])
    last = timestamp_ms(flow[:last_seen] || flow[:last_timestamp])
    max(last - first, 0)
  end

  defp timestamp_ms(nil), do: 0
  defp timestamp_ms(value) when is_integer(value), do: value
  defp timestamp_ms(%DateTime{} = dt), do: DateTime.to_unix(dt, :millisecond)
  defp timestamp_ms(%NaiveDateTime{} = ndt) do
    ndt
    |> DateTime.from_naive!("Etc/UTC")
    |> DateTime.to_unix(:millisecond)
  end
  defp timestamp_ms(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, dt, _} -> DateTime.to_unix(dt, :millisecond)
      _ -> 0
    end
  end
  defp timestamp_ms(_), do: 0

  defp reject_empty_values(map) do
    map
    |> Enum.reject(fn
      {_key, nil} -> true
      {_key, ""} -> true
      {_key, []} -> true
      {_key, value} when is_map(value) -> map_size(value) == 0
      _ -> false
    end)
    |> Map.new()
  end

  defp data_source_status do
    live_modules = %{
      flow_analyzer: module_status(FlowAnalyzer),
      protocol_analyzer: module_status(ProtocolAnalyzer),
      lateral_detector: module_status(LateralDetector),
      encrypted_traffic: module_status(EncryptedTraffic)
    }

    live_ready? = Enum.all?(live_modules, fn {_name, status} -> status.status == "available" end)

    %{
      live: %{
        status: if(live_ready?, do: "available", else: "degraded"),
        source: "memory",
        retention: "active lab window",
        modules: live_modules
      },
      historical: historical_status()
    }
  end

  defp module_status(module) do
    case Process.whereis(module) do
      nil ->
        %{
          status: "unavailable",
          reason: "process_not_started"
        }

      pid when is_pid(pid) ->
        %{
          status: "available",
          pid: inspect(pid)
        }
    end
  end

  defp historical_status do
    postgres_tables = postgres_ndr_table_coverage()

    cond do
      postgres_ndr_present?(postgres_tables) ->
        postgres_rows = postgres_ndr_row_count(postgres_tables)
        clickhouse = clickhouse_status()
        clickhouse_available? = clickhouse.available == true
        available? = postgres_rows > 0 or clickhouse_available?

        %{
          status: historical_status_label(postgres_rows, clickhouse_available?),
          source: if(clickhouse_available?, do: "postgres+clickhouse", else: "postgres"),
          available: available?,
          retention: postgres_ndr_retention_summary(postgres_tables),
          tables: postgres_ndr_table_counts(postgres_tables),
          coverage: postgres_tables,
          clickhouse: clickhouse
        }

      not ClickHouse.enabled?() ->
        %{
          status: "disabled",
          source: "clickhouse",
          available: false,
          reason: "clickhouse_disabled"
        }

      ClickHouse.healthy?() ->
        clickhouse_available_status()

      true ->
        %{
          status: "unavailable",
          source: "clickhouse",
          available: false,
          reason: "connection_failed",
          writer: ClickHouseWriter.get_stats()
        }
    end
  rescue
    e ->
      %{
        status: "unavailable",
        source: "clickhouse",
        available: false,
        reason: Exception.message(e)
      }
  catch
    :exit, reason ->
      %{
        status: "unavailable",
        source: "clickhouse",
        available: false,
        reason: inspect(reason)
      }
  end

  defp historical_status_label(postgres_rows, _clickhouse_available?) when postgres_rows > 0,
    do: "available"

  defp historical_status_label(_postgres_rows, true), do: "available"
  defp historical_status_label(_postgres_rows, false), do: "empty"

  defp clickhouse_available_status do
    coverage = clickhouse_ndr_coverage()

    %{
      status: "available",
      source: "clickhouse",
      available: true,
      retention: clickhouse_retention_summary(coverage),
      coverage: coverage,
      writer: ClickHouseWriter.get_stats()
    }
  end

  defp clickhouse_ndr_coverage do
    case ClickHouseQuery.storage_stats() do
      {:ok, rows} when is_list(rows) ->
        rows
        |> Enum.filter(fn row -> (row["table"] || row[:table]) in ["network_flows"] end)
        |> Map.new(fn row ->
          table = row["table"] || row[:table]
          oldest = row["oldest_data"] || row[:oldest_data]
          newest = row["newest_data"] || row[:newest_data]
          row_count = normalize_count(row["total_rows"] || row[:total_rows] || 0)

          {String.to_atom(table),
           %{
             status: if(row_count > 0, do: "available", else: "empty"),
             exists: true,
             label: "ClickHouse network flows",
             row_count: row_count,
             first_seen: oldest,
             last_seen: newest,
             retention: clickhouse_table_retention(oldest, newest)
           }}
        end)

      _ ->
        %{}
    end
  rescue
    _ -> %{}
  end

  defp clickhouse_retention_summary(coverage) when map_size(coverage) == 0,
    do: "coverage unavailable"

  defp clickhouse_retention_summary(coverage) do
    rows =
      coverage
      |> Enum.map(fn {_table, table} -> table.row_count || 0 end)
      |> Enum.sum()

    if rows > 0 do
      "ClickHouse network_flows, #{rows} rows retained"
    else
      "ClickHouse NDR tables present, no rows retained"
    end
  end

  defp clickhouse_table_retention(nil, nil), do: "no rows retained"
  defp clickhouse_table_retention(nil, _newest), do: "oldest timestamp unavailable"
  defp clickhouse_table_retention(_oldest, nil), do: "newest timestamp unavailable"
  defp clickhouse_table_retention(oldest, newest), do: "#{oldest} to #{newest}"

  defp normalize_count(value) when is_integer(value), do: value
  defp normalize_count(value) when is_float(value), do: trunc(value)
  defp normalize_count(value) when is_binary(value) do
    case Integer.parse(value) do
      {count, _} -> count
      :error -> 0
    end
  end
  defp normalize_count(_), do: 0

  defp clickhouse_status do
    cond do
      not ClickHouse.enabled?() ->
        %{
          status: "disabled",
          source: "clickhouse",
          available: false,
          reason: "clickhouse_disabled"
        }

      ClickHouse.healthy?() ->
        clickhouse_available_status()

      true ->
        %{
          status: "unavailable",
          source: "clickhouse",
          available: false,
          reason: "connection_failed",
          writer: ClickHouseWriter.get_stats()
        }
    end
  rescue
    e ->
      %{
        status: "unavailable",
        source: "clickhouse",
        available: false,
        reason: Exception.message(e)
      }
  catch
    :exit, reason ->
      %{
        status: "unavailable",
        source: "clickhouse",
        available: false,
        reason: inspect(reason)
      }
  end

  defp postgres_ndr_present?(tables) do
    Enum.any?(tables, fn {_table, coverage} -> coverage.exists end)
  end

  defp postgres_ndr_row_count(tables) do
    tables
    |> Enum.map(fn {_table, coverage} -> coverage.row_count || 0 end)
    |> Enum.sum()
  end

  defp postgres_ndr_table_counts(tables) do
    Map.new(tables, fn {table, coverage} -> {table, coverage.row_count} end)
  end

  defp postgres_ndr_table_coverage do
    Map.new(postgres_ndr_table_specs(), fn spec ->
      {spec.name, postgres_table_coverage(spec)}
    end)
  end

  defp postgres_ndr_table_specs do
    [
      %{name: :ndr_flows, label: "Network flows", time_field: :last_seen},
      %{name: :ndr_lateral_movements, label: "Lateral movement detections", time_field: :timestamp},
      %{name: :ndr_protocol_stats, label: "Protocol statistics", time_field: :last_seen},
      %{name: :ndr_protocol_observations, label: "Protocol observations", time_field: :last_seen},
      %{name: :ndr_tls_sessions, label: "TLS sessions", time_field: :timestamp},
      %{name: :ndr_ja3_stats, label: "JA3 fingerprints", time_field: :last_seen},
      %{name: :ndr_certificate_analyses, label: "Certificate analyses", time_field: :inserted_at}
    ]
  end

  defp postgres_table_exists?(table) do
    case Ecto.Adapters.SQL.query(Repo, "SELECT to_regclass($1) IS NOT NULL", ["public.#{table}"]) do
      {:ok, %{rows: [[exists?]]}} -> exists?
      _ -> false
    end
  rescue
    _ -> false
  end

  defp postgres_table_coverage(%{name: table, label: label, time_field: time_field}) do
    table_name = Atom.to_string(table)

    if postgres_table_exists?(table_name) do
      stats =
        Repo.one(coverage_query(table_name, time_field)) ||
          %{row_count: 0, first_seen: nil, last_seen: nil}

      first_seen = stats.first_seen
      last_seen = stats.last_seen
      row_count = stats.row_count || 0

      %{
        status: if(row_count > 0, do: "available", else: "empty"),
        exists: true,
        label: label,
        row_count: row_count,
        first_seen: format_datetime(first_seen),
        last_seen: format_datetime(last_seen),
        retention: postgres_table_retention(first_seen, last_seen)
      }
    else
      %{
        status: "missing",
        exists: false,
        label: label,
        row_count: nil,
        first_seen: nil,
        last_seen: nil,
        retention: "table not present"
      }
    end
  rescue
    e ->
      %{
        status: "unavailable",
        exists: true,
        label: label,
        row_count: nil,
        first_seen: nil,
        last_seen: nil,
        retention: "coverage query failed",
        reason: Exception.message(e)
      }
  end

  defp coverage_query(table, time_field) do
    from(r in table,
      select: %{
        row_count: count(),
        first_seen: min(field(r, ^time_field)),
        last_seen: max(field(r, ^time_field))
      }
    )
  end

  defp postgres_ndr_retention_summary(tables) do
    existing_tables = Enum.filter(tables, fn {_table, coverage} -> coverage.exists end)
    row_count = existing_tables |> Enum.map(fn {_table, coverage} -> coverage.row_count || 0 end) |> Enum.sum()

    timestamps =
      existing_tables
      |> Enum.flat_map(fn {_table, coverage} -> [coverage.first_seen, coverage.last_seen] end)
      |> Enum.reject(&is_nil/1)
      |> Enum.map(&DateTime.from_iso8601/1)
      |> Enum.flat_map(fn
        {:ok, dt, _offset} -> [dt]
        _ -> []
      end)

    case {length(existing_tables), row_count, timestamps} do
      {0, _, _} ->
        "no Postgres NDR tables present"

      {table_count, 0, _} ->
        "#{table_count} Postgres NDR tables present, no rows retained"

      {table_count, rows, []} ->
        "#{table_count} Postgres NDR tables, #{rows} rows retained"

      {table_count, rows, timestamps} ->
        first_seen = Enum.min_by(timestamps, &DateTime.to_unix(&1, :microsecond))
        last_seen = Enum.max_by(timestamps, &DateTime.to_unix(&1, :microsecond))

        "#{table_count} Postgres NDR tables, #{rows} rows retained across #{format_duration(first_seen, last_seen)}"
    end
  end

  defp postgres_table_retention(nil, nil), do: "no rows retained"
  defp postgres_table_retention(nil, _last_seen), do: "oldest timestamp unavailable"
  defp postgres_table_retention(_first_seen, nil), do: "newest timestamp unavailable"
  defp postgres_table_retention(first_seen, last_seen), do: format_duration(first_seen, last_seen)

  defp format_duration(%DateTime{} = first_seen, %DateTime{} = last_seen) do
    seconds = max(DateTime.diff(last_seen, first_seen, :second), 0)

    cond do
      seconds == 0 -> "single timestamp"
      seconds < 3_600 -> "#{div(seconds, 60)}m"
      seconds < 86_400 -> "#{Float.round(seconds / 3_600, 1)}h"
      true -> "#{Float.round(seconds / 86_400, 1)}d"
    end
  end
end
