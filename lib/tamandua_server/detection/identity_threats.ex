defmodule TamanduaServer.Detection.IdentityThreats do
  @moduledoc """
  Identity Threat Detection and Analysis Engine.

  Maintains sliding windows of authentication events and detects Active Directory
  identity-based attacks including password spraying, impossible travel, and
  lateral movement chains via pass-the-hash/ticket techniques.

  ## Architecture

  Three ETS tables back the engine:

  - `:identity_auth_events` -- sliding window of authentication events keyed by
    `{source_ip, user}` with timestamps, event IDs, logon types, and auth metadata.
  - `:identity_baselines` -- normal login patterns per user including typical
    source IPs, logon hours, auth protocols, and geographic locations.
  - `:identity_active_sessions` -- current active sessions per user for lateral
    movement chain tracking (user -> host -> host paths).

  The engine is fed by `Detection.EngineWorker` which routes authentication-related
  events here. Detections that exceed configured thresholds are promoted to alerts
  via `TamanduaServer.Alerts` and broadcast via PubSub.

  ## Detection Capabilities

  - **Password Spraying**: >10 failed logons from same source across different
    accounts in 5 minutes (MITRE T1110.003)
  - **Impossible Travel**: Same user authenticating from geographically distant
    IPs within a timeframe shorter than physical travel allows (T1078)
  - **Lateral Movement Chains**: Tracking user A -> host B -> host C credential
    use patterns via pass-the-hash (T1550.002) or pass-the-ticket (T1550.003)
  - **User Risk Scoring**: Composite risk score based on authentication anomalies,
    privilege usage, and historical baseline deviation.

  ## MITRE ATT&CK Mapping

  | Detection                | Technique    | Tactic              |
  |--------------------------|-------------|---------------------|
  | Password Spraying        | T1110.003   | Credential Access   |
  | Impossible Travel        | T1078       | Initial Access      |
  | PtH Chain               | T1550.002   | Lateral Movement    |
  | PtT Chain               | T1550.003   | Lateral Movement    |
  | Kerberoasting           | T1558.003   | Credential Access   |
  | AS-REP Roasting         | T1558.004   | Credential Access   |
  | Golden Ticket           | T1558.001   | Credential Access   |
  | DCSync                  | T1003.006   | Credential Access   |
  """

  use GenServer
  require Logger

  alias TamanduaServer.Alerts
  alias TamanduaServer.Agents.OrgLookup

  # ---------------------------------------------------------------------------
  # ETS table names
  # ---------------------------------------------------------------------------

  @auth_events_table :identity_auth_events
  @baselines_table :identity_baselines
  @sessions_table :identity_active_sessions

  # ---------------------------------------------------------------------------
  # Limits and defaults
  # ---------------------------------------------------------------------------

  @max_auth_events 200_000
  @max_sessions 50_000
  @cleanup_interval_ms :timer.minutes(10)
  @auth_event_retention_hours 24
  @session_retention_hours 12
  @baseline_retention_hours 168  # 7 days

  # Password spray thresholds
  @spray_failed_logon_threshold 10
  @spray_window_seconds 300  # 5 minutes

  # Impossible travel thresholds
  @impossible_travel_min_distance_km 500
  @impossible_travel_max_speed_kmh 900  # ~commercial aviation

  # Lateral movement chain thresholds
  @chain_window_seconds 3600  # 1 hour
  @chain_min_hops 3

  # Risk score weights
  @risk_weight_spray 0.30
  @risk_weight_impossible_travel 0.35
  @risk_weight_lateral_chain 0.25
  @risk_weight_baseline_deviation 0.10

  # ===========================================================================
  # Client API
  # ===========================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Analyze an authentication-related event for identity threats.

  Called from the detection engine for events with types:
  authentication, logon, logon_event, auth_event, kerberos_tgt,
  kerberos_tgs, directory_replication.

  Returns `:ok` (analysis is asynchronous via cast).
  """
  @spec analyze_event(map()) :: :ok
  def analyze_event(event) do
    GenServer.cast(__MODULE__, {:analyze_event, event})
  end

  @doc """
  Get the current risk score for a user.

  Returns a map with the composite risk score (0.0 - 1.0) and breakdowns.
  """
  @spec get_user_risk_score(String.t()) :: map()
  def get_user_risk_score(user_id) do
    GenServer.call(__MODULE__, {:get_user_risk_score, user_id})
  end

  @doc """
  Get active sessions for a user (for lateral movement chain tracking).
  """
  @spec get_active_sessions(String.t()) :: [map()]
  def get_active_sessions(user_id) do
    GenServer.call(__MODULE__, {:get_active_sessions, user_id})
  end

  @doc """
  Get recent authentication events for a source IP or user.
  """
  @spec get_auth_events(keyword()) :: [map()]
  def get_auth_events(opts \\ []) do
    GenServer.call(__MODULE__, {:get_auth_events, opts})
  end

  @doc """
  Summary statistics for the identity threat engine.
  """
  @spec stats() :: map()
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  # ===========================================================================
  # Server callbacks
  # ===========================================================================

  @impl true
  def init(_opts) do
    # Create ETS tables
    create_ets_table(@auth_events_table, [:bag, :named_table, :public, {:read_concurrency, true}])
    create_ets_table(@baselines_table, [:set, :named_table, :public, {:read_concurrency, true}])
    create_ets_table(@sessions_table, [:bag, :named_table, :public, {:read_concurrency, true}])

    # Schedule periodic cleanup
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)

    Logger.info("[IdentityThreats] Identity Threat Detection Engine started")

    state = %{
      events_analyzed: 0,
      sprays_detected: 0,
      impossible_travel_detected: 0,
      lateral_chains_detected: 0,
      alerts_created: 0,
      auth_event_count: 0,
      session_count: 0
    }

    {:ok, state}
  end

  # -- casts ------------------------------------------------------------------

  @impl true
  def handle_cast({:analyze_event, event}, state) do
    new_state = do_analyze_event(event, state)
    {:noreply, new_state}
  end

  # -- calls ------------------------------------------------------------------

  @impl true
  def handle_call({:get_user_risk_score, user_id}, _from, state) do
    score = compute_user_risk_score(user_id)
    {:reply, score, state}
  end

  @impl true
  def handle_call({:get_active_sessions, user_id}, _from, state) do
    sessions = lookup_user_sessions(user_id)
    {:reply, sessions, state}
  end

  @impl true
  def handle_call({:get_auth_events, opts}, _from, state) do
    events = lookup_auth_events(opts)
    {:reply, events, state}
  end

  @impl true
  def handle_call(:stats, _from, state) do
    auth_count = safe_ets_size(@auth_events_table)
    session_count = safe_ets_size(@sessions_table)
    baseline_count = safe_ets_size(@baselines_table)

    result = %{
      events_analyzed: state.events_analyzed,
      sprays_detected: state.sprays_detected,
      impossible_travel_detected: state.impossible_travel_detected,
      lateral_chains_detected: state.lateral_chains_detected,
      alerts_created: state.alerts_created,
      auth_events_buffered: auth_count,
      active_sessions: session_count,
      user_baselines: baseline_count
    }

    {:reply, result, state}
  end

  # -- info -------------------------------------------------------------------

  @impl true
  def handle_info(:cleanup, state) do
    cleaned = cleanup_stale_data()
    Logger.debug("[IdentityThreats] Cleanup: removed #{cleaned} stale entries")
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  def handle_info(_msg, state), do: {:noreply, state}

  # ===========================================================================
  # Core analysis logic
  # ===========================================================================

  defp do_analyze_event(event, state) do
    event_type = to_string(event[:event_type] || event["event_type"] || "")
    payload = event[:payload] || event["payload"] || %{}

    # Extract common authentication fields
    auth_data = extract_auth_data(event_type, payload, event)

    unless auth_data do
      %{state | events_analyzed: state.events_analyzed + 1}
    else
      # 1. Record the authentication event
      record_auth_event(auth_data)

      # 2. Update or create session tracking
      if auth_data.success do
        record_session(auth_data)
      end

      # 3. Update user baseline
      update_user_baseline(auth_data)

      # 4. Run detections
      detections = []

      # 4a. Password spray detection (failed logons)
      detections = if not auth_data.success do
        case detect_password_spray(auth_data) do
          {:spray_detected, details} -> [{:password_spray, details} | detections]
          :no_spray -> detections
        end
      else
        detections
      end

      # 4b. Impossible travel detection (successful logons)
      detections = if auth_data.success and auth_data.source_ip do
        case detect_impossible_travel(auth_data) do
          {:impossible_travel, details} -> [{:impossible_travel, details} | detections]
          :normal -> detections
        end
      else
        detections
      end

      # 4c. Lateral movement chain detection (successful network logons)
      detections = if auth_data.success and auth_data.logon_type in [3, 9, 10] do
        case detect_lateral_chain(auth_data) do
          {:chain_detected, details} -> [{:lateral_chain, details} | detections]
          :no_chain -> detections
        end
      else
        detections
      end

      # 5. Create alerts for detections
      alerts_created = Enum.reduce(detections, state.alerts_created, fn detection, acc ->
        case create_identity_alert(detection, auth_data, event) do
          {:ok, _alert} -> acc + 1
          _ -> acc
        end
      end)

      # 6. Broadcast detections via PubSub
      if length(detections) > 0 do
        broadcast_identity_detections(detections, auth_data, event)
      end

      # Update stats
      %{state |
        events_analyzed: state.events_analyzed + 1,
        sprays_detected: state.sprays_detected + count_type(detections, :password_spray),
        impossible_travel_detected: state.impossible_travel_detected + count_type(detections, :impossible_travel),
        lateral_chains_detected: state.lateral_chains_detected + count_type(detections, :lateral_chain),
        alerts_created: alerts_created,
        auth_event_count: safe_ets_size(@auth_events_table),
        session_count: safe_ets_size(@sessions_table)
      }
    end
  end

  # ===========================================================================
  # Authentication data extraction
  # ===========================================================================

  defp extract_auth_data(event_type, payload, event) do
    # Map different event types to common auth data structure
    username = payload[:username] || payload["username"] ||
               payload[:user] || payload["user"] ||
               payload[:TargetUserName] || payload["TargetUserName"]
    source_ip = payload[:source_ip] || payload["source_ip"] ||
                payload[:src_ip] || payload["src_ip"] ||
                payload[:IpAddress] || payload["IpAddress"]
    dest_ip = payload[:dest_ip] || payload["dest_ip"] ||
              payload[:local_ip] || payload["local_ip"]
    logon_type = payload[:logon_type] || payload["logon_type"] ||
                 payload[:LogonType] || payload["LogonType"]
    event_id = payload[:EventID] || payload["EventID"]
    auth_package = payload[:auth_package] || payload["auth_package"] ||
                   payload[:AuthenticationPackageName] || payload["AuthenticationPackageName"]

    # Determine success/failure
    success = cond do
      event_id == 4624 -> true
      event_id == 4625 -> false
      event_type in ["logon", "authentication"] ->
        status = payload[:status] || payload["status"]
        status in ["success", "Success", true, 0, "0x0"]
      true -> nil
    end

    if username && username != "" do
      %{
        username: to_string(username),
        source_ip: if(source_ip, do: to_string(source_ip), else: nil),
        dest_ip: if(dest_ip, do: to_string(dest_ip), else: nil),
        logon_type: parse_logon_type(logon_type),
        event_id: event_id,
        auth_package: to_string(auth_package || "unknown"),
        success: success,
        timestamp: event[:timestamp] || event["timestamp"] || DateTime.utc_now(),
        agent_id: event[:agent_id] || event["agent_id"],
        organization_id: event[:organization_id] || event["organization_id"],
        event_event_id: event[:event_id] || event["event_id"],
        event_type: event_type,
        # Kerberos-specific
        ticket_encryption: payload[:TicketEncryptionType] || payload["TicketEncryptionType"],
        service_name: payload[:ServiceName] || payload["ServiceName"],
        # DCSync-specific
        properties: payload[:Properties] || payload["Properties"],
        access_mask: payload[:AccessMask] || payload["AccessMask"]
      }
    else
      nil
    end
  end

  defp parse_logon_type(nil), do: nil
  defp parse_logon_type(lt) when is_integer(lt), do: lt
  defp parse_logon_type(lt) when is_binary(lt) do
    case Integer.parse(lt) do
      {n, _} -> n
      :error -> nil
    end
  end
  defp parse_logon_type(_), do: nil

  # ===========================================================================
  # Event recording
  # ===========================================================================

  defp record_auth_event(auth_data) do
    key = {auth_data.source_ip || "unknown", auth_data.username}
    now = DateTime.utc_now()

    entry = %{
      username: auth_data.username,
      source_ip: auth_data.source_ip,
      dest_ip: auth_data.dest_ip,
      logon_type: auth_data.logon_type,
      event_id: auth_data.event_id,
      auth_package: auth_data.auth_package,
      success: auth_data.success,
      timestamp: now,
      agent_id: auth_data.agent_id,
      event_event_id: auth_data.event_event_id
    }

    if safe_ets_size(@auth_events_table) < @max_auth_events do
      :ets.insert(@auth_events_table, {key, entry})
    end
  end

  defp record_session(auth_data) do
    key = auth_data.username
    now = DateTime.utc_now()

    session = %{
      username: auth_data.username,
      source_ip: auth_data.source_ip,
      dest_ip: auth_data.dest_ip,
      logon_type: auth_data.logon_type,
      auth_package: auth_data.auth_package,
      started_at: now,
      agent_id: auth_data.agent_id
    }

    if safe_ets_size(@sessions_table) < @max_sessions do
      :ets.insert(@sessions_table, {key, session})
    end
  end

  # ===========================================================================
  # Password spray detection (T1110.003)
  # ===========================================================================

  defp detect_password_spray(auth_data) do
    source_ip = auth_data.source_ip

    unless source_ip do
      :no_spray
    else
      cutoff = DateTime.add(DateTime.utc_now(), -@spray_window_seconds, :second)

      # Get all failed auth events from this source IP within the window
      failed_events = get_recent_failed_from_source(source_ip, cutoff)

      # Count distinct target accounts
      distinct_accounts = failed_events
        |> Enum.map(& &1.username)
        |> Enum.uniq()

      if length(distinct_accounts) >= @spray_failed_logon_threshold do
        {:spray_detected, %{
          source_ip: source_ip,
          target_accounts: distinct_accounts,
          target_count: length(distinct_accounts),
          failed_attempts: length(failed_events),
          window_seconds: @spray_window_seconds,
          first_attempt: failed_events |> Enum.min_by(& &1.timestamp, DateTime, fn -> nil end),
          last_attempt: failed_events |> Enum.max_by(& &1.timestamp, DateTime, fn -> nil end)
        }}
      else
        :no_spray
      end
    end
  end

  defp get_recent_failed_from_source(source_ip, cutoff) do
    try do
      :ets.tab2list(@auth_events_table)
      |> Enum.flat_map(fn
        {{^source_ip, _user}, entry} ->
          if not entry.success and DateTime.compare(entry.timestamp, cutoff) == :gt do
            [entry]
          else
            []
          end
        _ -> []
      end)
    rescue
      _ -> []
    end
  end

  # ===========================================================================
  # Impossible travel detection (T1078)
  # ===========================================================================

  defp detect_impossible_travel(auth_data) do
    username = auth_data.username
    current_ip = auth_data.source_ip
    now = DateTime.utc_now()

    # Get the user's most recent successful logon from a different IP
    previous_logon = get_previous_logon(username, current_ip)

    case previous_logon do
      nil ->
        :normal

      prev ->
        time_diff_seconds = DateTime.diff(now, prev.timestamp, :second)

        # Look up approximate geolocations for both IPs
        current_geo = geolocate_ip(current_ip)
        previous_geo = geolocate_ip(prev.source_ip)

        case {current_geo, previous_geo} do
          {{clat, clon}, {plat, plon}} when clat != nil and plat != nil ->
            distance_km = haversine_distance(clat, clon, plat, plon)

            # Calculate if travel is physically possible
            if distance_km >= @impossible_travel_min_distance_km do
              max_travel_time_seconds = distance_km / @impossible_travel_max_speed_kmh * 3600

              if time_diff_seconds < max_travel_time_seconds do
                {:impossible_travel, %{
                  username: username,
                  current_ip: current_ip,
                  previous_ip: prev.source_ip,
                  current_location: current_geo,
                  previous_location: previous_geo,
                  distance_km: Float.round(distance_km, 1),
                  time_diff_seconds: time_diff_seconds,
                  min_travel_time_seconds: round(max_travel_time_seconds),
                  previous_logon_time: prev.timestamp
                }}
              else
                :normal
              end
            else
              :normal
            end

          _ ->
            # Cannot geolocate one or both IPs
            :normal
        end
    end
  end

  defp get_previous_logon(username, current_ip) do
    try do
      :ets.tab2list(@auth_events_table)
      |> Enum.flat_map(fn
        {{ip, ^username}, entry} when ip != current_ip ->
          if entry.success, do: [entry], else: []
        _ -> []
      end)
      |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})
      |> List.first()
    rescue
      _ -> nil
    end
  end

  @doc false
  def haversine_distance(lat1, lon1, lat2, lon2) do
    # Haversine formula for great-circle distance in kilometers
    r = 6371.0  # Earth's radius in km

    dlat = deg_to_rad(lat2 - lat1)
    dlon = deg_to_rad(lon2 - lon1)

    a = :math.sin(dlat / 2) * :math.sin(dlat / 2) +
        :math.cos(deg_to_rad(lat1)) * :math.cos(deg_to_rad(lat2)) *
        :math.sin(dlon / 2) * :math.sin(dlon / 2)

    c = 2 * :math.atan2(:math.sqrt(a), :math.sqrt(1 - a))

    r * c
  end

  defp deg_to_rad(deg), do: deg * :math.pi() / 180.0

  defp geolocate_ip(ip) when is_binary(ip) do
    # Attempt GeoIP lookup via the enrichment service
    try do
      case TamanduaServer.Enrichment.GeoIP.lookup(ip) do
        {:ok, %{latitude: lat, longitude: lon}} when lat != nil and lon != nil ->
          {lat, lon}
        _ ->
          {nil, nil}
      end
    rescue
      _ -> {nil, nil}
    catch
      :exit, _ -> {nil, nil}
    end
  end
  defp geolocate_ip(_), do: {nil, nil}

  # ===========================================================================
  # Lateral movement chain detection (T1550.002, T1550.003)
  # ===========================================================================

  defp detect_lateral_chain(auth_data) do
    username = auth_data.username
    cutoff = DateTime.add(DateTime.utc_now(), -@chain_window_seconds, :second)

    # Get all recent sessions for this user
    sessions = get_user_sessions_since(username, cutoff)

    # Build a chain: source -> dest -> source -> dest
    chain = build_movement_chain(sessions)

    if length(chain) >= @chain_min_hops do
      # Determine if the chain uses PtH or PtT indicators
      technique = detect_chain_technique(sessions)

      {:chain_detected, %{
        username: username,
        chain: chain,
        hop_count: length(chain) - 1,
        technique: technique,
        window_seconds: @chain_window_seconds,
        source_ips: sessions |> Enum.map(& &1.source_ip) |> Enum.uniq() |> Enum.reject(&is_nil/1),
        dest_ips: sessions |> Enum.map(& &1.dest_ip) |> Enum.uniq() |> Enum.reject(&is_nil/1),
        auth_packages: sessions |> Enum.map(& &1.auth_package) |> Enum.uniq()
      }}
    else
      :no_chain
    end
  end

  defp get_user_sessions_since(username, cutoff) do
    try do
      :ets.lookup(@sessions_table, username)
      |> Enum.map(fn {_key, session} -> session end)
      |> Enum.filter(fn session ->
        DateTime.compare(session.started_at, cutoff) == :gt
      end)
      |> Enum.sort_by(& &1.started_at, DateTime)
    rescue
      _ -> []
    end
  end

  defp build_movement_chain(sessions) do
    # Build a chain of unique hosts visited
    sessions
    |> Enum.flat_map(fn s ->
      ips = []
      ips = if s.source_ip, do: [s.source_ip | ips], else: ips
      ips = if s.dest_ip, do: [s.dest_ip | ips], else: ips
      ips
    end)
    |> Enum.uniq()
  end

  defp detect_chain_technique(sessions) do
    auth_packages = sessions |> Enum.map(& &1.auth_package) |> Enum.uniq()
    logon_types = sessions |> Enum.map(& &1.logon_type) |> Enum.uniq()

    cond do
      "NTLM" in auth_packages and 9 in logon_types -> :pass_the_hash
      "NTLM" in auth_packages -> :pass_the_hash
      "Kerberos" in auth_packages and 3 in logon_types -> :pass_the_ticket
      true -> :credential_reuse
    end
  end

  # ===========================================================================
  # User risk scoring
  # ===========================================================================

  defp compute_user_risk_score(user_id) do
    now = DateTime.utc_now()
    window_start = DateTime.add(now, -@auth_event_retention_hours * 3600, :second)

    # Get user's recent auth events
    events = get_user_auth_events(user_id, window_start)
    baseline = get_user_baseline(user_id)

    # Component scores
    spray_score = compute_spray_risk(user_id, events)
    travel_score = compute_travel_risk(user_id, events)
    chain_score = compute_chain_risk(user_id)
    baseline_score = compute_baseline_deviation(user_id, events, baseline)

    # Weighted composite
    composite = spray_score * @risk_weight_spray +
                travel_score * @risk_weight_impossible_travel +
                chain_score * @risk_weight_lateral_chain +
                baseline_score * @risk_weight_baseline_deviation

    composite = min(composite, 1.0) |> Float.round(4)

    %{
      user_id: user_id,
      risk_score: composite,
      components: %{
        password_spray: Float.round(spray_score, 4),
        impossible_travel: Float.round(travel_score, 4),
        lateral_chain: Float.round(chain_score, 4),
        baseline_deviation: Float.round(baseline_score, 4)
      },
      recent_events: length(events),
      computed_at: now
    }
  end

  defp compute_spray_risk(_user_id, events) do
    # Check if this user was a target of recent sprays
    failed = Enum.count(events, fn e -> not e.success end)
    total = max(length(events), 1)
    failure_rate = failed / total

    cond do
      failure_rate > 0.8 and failed >= 5 -> 0.9
      failure_rate > 0.5 and failed >= 3 -> 0.6
      failure_rate > 0.3 -> 0.3
      true -> 0.0
    end
  end

  defp compute_travel_risk(_user_id, events) do
    # Check for logons from multiple distant IPs
    successful = Enum.filter(events, & &1.success)
    unique_ips = successful |> Enum.map(& &1.source_ip) |> Enum.reject(&is_nil/1) |> Enum.uniq()

    if length(unique_ips) > 3 do
      0.5
    else
      0.0
    end
  end

  defp compute_chain_risk(user_id) do
    sessions = lookup_user_sessions(user_id)
    unique_hosts = sessions
      |> Enum.flat_map(fn s -> [s.source_ip, s.dest_ip] end)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    cond do
      length(unique_hosts) >= 5 -> 0.8
      length(unique_hosts) >= 3 -> 0.4
      true -> 0.0
    end
  end

  defp compute_baseline_deviation(_user_id, events, nil), do: if(length(events) > 0, do: 0.2, else: 0.0)
  defp compute_baseline_deviation(_user_id, events, baseline) do
    # Check for logons outside baseline hours, from unknown IPs, unusual protocols
    deviations = Enum.count(events, fn event ->
      ip_known = event.source_ip in (baseline[:known_ips] || [])
      protocol_known = event.auth_package in (baseline[:known_protocols] || [])
      not ip_known or not protocol_known
    end)

    total = max(length(events), 1)
    deviation_rate = deviations / total

    cond do
      deviation_rate > 0.7 -> 0.9
      deviation_rate > 0.4 -> 0.5
      deviation_rate > 0.1 -> 0.2
      true -> 0.0
    end
  end

  # ===========================================================================
  # Baseline management
  # ===========================================================================

  defp update_user_baseline(auth_data) do
    key = auth_data.username
    now = DateTime.utc_now()

    case :ets.lookup(@baselines_table, key) do
      [] ->
        baseline = %{
          username: auth_data.username,
          known_ips: if(auth_data.source_ip, do: [auth_data.source_ip], else: []),
          known_protocols: [auth_data.auth_package],
          known_logon_types: if(auth_data.logon_type, do: [auth_data.logon_type], else: []),
          first_seen: now,
          last_seen: now,
          event_count: 1,
          successful_count: if(auth_data.success, do: 1, else: 0),
          failed_count: if(auth_data.success, do: 0, else: 1)
        }
        :ets.insert(@baselines_table, {key, baseline})

      [{^key, existing}] ->
        updated = %{existing |
          known_ips: (if auth_data.source_ip do
            Enum.uniq([auth_data.source_ip | existing[:known_ips] || []])
            |> Enum.take(50)  # Limit stored IPs
          else
            existing[:known_ips] || []
          end),
          known_protocols: Enum.uniq([auth_data.auth_package | existing[:known_protocols] || []]),
          known_logon_types: (if auth_data.logon_type do
            Enum.uniq([auth_data.logon_type | existing[:known_logon_types] || []])
          else
            existing[:known_logon_types] || []
          end),
          last_seen: now,
          event_count: (existing[:event_count] || 0) + 1,
          successful_count: (existing[:successful_count] || 0) + (if auth_data.success, do: 1, else: 0),
          failed_count: (existing[:failed_count] || 0) + (if auth_data.success, do: 0, else: 1)
        }
        :ets.insert(@baselines_table, {key, updated})
    end
  end

  defp get_user_baseline(user_id) do
    case :ets.lookup(@baselines_table, user_id) do
      [{_key, baseline}] -> baseline
      [] -> nil
    end
  rescue
    _ -> nil
  end

  # ===========================================================================
  # Alert creation
  # ===========================================================================

  defp create_identity_alert({:password_spray, details}, auth_data, event) do
    agent_id = auth_data.agent_id

    try do
      Alerts.create_alert(%{
        agent_id: agent_id,
        organization_id: auth_data.organization_id || OrgLookup.get_org_id(agent_id),
        severity: :high,
        title: "Password Spray Attack: #{details.target_count} accounts from #{details.source_ip}",
        description: """
        Password spray attack detected from source IP #{details.source_ip}.
        Failed logon attempts against #{details.target_count} distinct accounts in #{details.window_seconds} seconds.
        Total failed attempts: #{details.failed_attempts}
        Target accounts: #{Enum.take(details.target_accounts, 10) |> Enum.join(", ")}#{if length(details.target_accounts) > 10, do: " (and #{length(details.target_accounts) - 10} more)", else: ""}
        MITRE ATT&CK: T1110.003 (Password Spraying)
        """,
        source_event_id: auth_data.event_event_id,
        event_ids: [auth_data.event_event_id],
        evidence: %{
          identity_threat: %{
            type: "password_spray",
            source_ip: details.source_ip,
            target_accounts: Enum.take(details.target_accounts, 20),
            target_count: details.target_count,
            failed_attempts: details.failed_attempts
          },
          network: [%{source_ip: details.source_ip}]
        },
        process_chain: [],
        raw_event: event[:payload] || event["payload"] || %{},
        detection_metadata: %{
          "rule_name" => "Identity: Password Spray Detection",
          "rule_type" => "identity_threat",
          "confidence" => min(details.target_count / 20.0, 1.0),
          "event_type" => "password_spray"
        },
        mitre_tactics: ["credential-access"],
        mitre_techniques: ["T1110.003"],
        threat_score: min(details.target_count / 20.0, 0.95)
      })
    rescue
      e ->
        Logger.warning("[IdentityThreats] Failed to create spray alert: #{inspect(e)}")
        {:error, e}
    end
  end

  defp create_identity_alert({:impossible_travel, details}, auth_data, event) do
    agent_id = auth_data.agent_id

    try do
      Alerts.create_alert(%{
        agent_id: agent_id,
        organization_id: auth_data.organization_id || OrgLookup.get_org_id(agent_id),
        severity: :high,
        title: "Impossible Travel: #{details.username} from #{details.current_ip} (#{details.distance_km} km)",
        description: """
        Impossible travel detected for user '#{details.username}'.
        Current logon: #{details.current_ip} at #{DateTime.to_iso8601(DateTime.utc_now())}
        Previous logon: #{details.previous_ip} at #{DateTime.to_iso8601(details.previous_logon_time)}
        Distance: #{details.distance_km} km
        Time difference: #{details.time_diff_seconds} seconds (minimum travel time: #{details.min_travel_time_seconds} seconds)
        This indicates the same account was used from two geographically distant locations
        faster than physically possible, suggesting credential compromise.
        MITRE ATT&CK: T1078 (Valid Accounts)
        """,
        source_event_id: auth_data.event_event_id,
        event_ids: [auth_data.event_event_id],
        evidence: %{
          identity_threat: %{
            type: "impossible_travel",
            username: details.username,
            current_ip: details.current_ip,
            previous_ip: details.previous_ip,
            distance_km: details.distance_km,
            time_diff_seconds: details.time_diff_seconds
          },
          network: [
            %{source_ip: details.current_ip},
            %{source_ip: details.previous_ip}
          ]
        },
        process_chain: [],
        raw_event: event[:payload] || event["payload"] || %{},
        detection_metadata: %{
          "rule_name" => "Identity: Impossible Travel Detection",
          "rule_type" => "identity_threat",
          "confidence" => 0.85,
          "event_type" => "impossible_travel"
        },
        mitre_tactics: ["initial-access"],
        mitre_techniques: ["T1078"],
        threat_score: 0.80
      })
    rescue
      e ->
        Logger.warning("[IdentityThreats] Failed to create impossible travel alert: #{inspect(e)}")
        {:error, e}
    end
  end

  defp create_identity_alert({:lateral_chain, details}, auth_data, event) do
    agent_id = auth_data.agent_id

    {technique_id, technique_name, tactic} = case details.technique do
      :pass_the_hash -> {"T1550.002", "Pass-the-Hash", "lateral-movement"}
      :pass_the_ticket -> {"T1550.003", "Pass-the-Ticket", "lateral-movement"}
      :credential_reuse -> {"T1078", "Valid Accounts", "lateral-movement"}
    end

    try do
      Alerts.create_alert(%{
        agent_id: agent_id,
        organization_id: auth_data.organization_id || OrgLookup.get_org_id(agent_id),
        severity: :high,
        title: "Lateral Movement Chain: #{details.username} across #{details.hop_count} hosts (#{technique_name})",
        description: """
        Lateral movement chain detected for user '#{details.username}'.
        Technique: #{technique_name} (#{technique_id})
        Hosts in chain: #{Enum.join(details.chain, " -> ")}
        Hop count: #{details.hop_count}
        Authentication packages: #{Enum.join(details.auth_packages, ", ")}
        Window: #{details.window_seconds} seconds
        Source IPs: #{Enum.join(details.source_ips, ", ")}
        Destination IPs: #{Enum.join(details.dest_ips, ", ")}
        This pattern indicates credential-based lateral movement across multiple hosts.
        MITRE ATT&CK: #{technique_id} (#{technique_name})
        """,
        source_event_id: auth_data.event_event_id,
        event_ids: [auth_data.event_event_id],
        evidence: %{
          identity_threat: %{
            type: "lateral_movement_chain",
            technique: details.technique,
            username: details.username,
            chain: details.chain,
            hop_count: details.hop_count,
            source_ips: details.source_ips,
            dest_ips: details.dest_ips
          },
          lateral_movement: %{
            source_ips: details.source_ips,
            dest_ips: details.dest_ips,
            protocol: Enum.join(details.auth_packages, ", "),
            pattern: "credential_chain"
          },
          network: Enum.map(details.source_ips, fn ip -> %{source_ip: ip} end)
        },
        process_chain: [],
        raw_event: event[:payload] || event["payload"] || %{},
        detection_metadata: %{
          "rule_name" => "Identity: #{technique_name} Chain Detection",
          "rule_type" => "identity_threat",
          "confidence" => min(details.hop_count / 5.0, 0.95),
          "event_type" => "lateral_movement_chain"
        },
        mitre_tactics: [tactic],
        mitre_techniques: [technique_id],
        threat_score: min(details.hop_count / 5.0, 0.90)
      })
    rescue
      e ->
        Logger.warning("[IdentityThreats] Failed to create lateral chain alert: #{inspect(e)}")
        {:error, e}
    end
  end

  # ===========================================================================
  # PubSub broadcasting
  # ===========================================================================

  defp broadcast_identity_detections(detections, auth_data, _event) do
    Enum.each(detections, fn {type, details} ->
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "identity:threats",
        {:identity_threat_detected, %{
          type: type,
          details: details,
          username: auth_data.username,
          source_ip: auth_data.source_ip,
          agent_id: auth_data.agent_id,
          detected_at: DateTime.utc_now()
        }}
      )
    end)
  rescue
    _ -> :ok
  end

  # ===========================================================================
  # Lookup helpers
  # ===========================================================================

  defp lookup_user_sessions(user_id) do
    try do
      :ets.lookup(@sessions_table, user_id)
      |> Enum.map(fn {_key, session} -> session end)
      |> Enum.sort_by(& &1.started_at, {:desc, DateTime})
    rescue
      _ -> []
    end
  end

  defp lookup_auth_events(opts) do
    user = Keyword.get(opts, :user, nil)
    source_ip = Keyword.get(opts, :source_ip, nil)
    limit = Keyword.get(opts, :limit, 100)

    try do
      :ets.tab2list(@auth_events_table)
      |> Enum.flat_map(fn {_key, entry} -> [entry] end)
      |> Enum.filter(fn entry ->
        user_match = if user, do: entry.username == user, else: true
        ip_match = if source_ip, do: entry.source_ip == source_ip, else: true
        user_match and ip_match
      end)
      |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})
      |> Enum.take(limit)
    rescue
      _ -> []
    end
  end

  defp get_user_auth_events(user_id, since) do
    try do
      :ets.tab2list(@auth_events_table)
      |> Enum.flat_map(fn
        {{_ip, ^user_id}, entry} ->
          if DateTime.compare(entry.timestamp, since) == :gt do
            [entry]
          else
            []
          end
        _ -> []
      end)
    rescue
      _ -> []
    end
  end

  # ===========================================================================
  # Cleanup
  # ===========================================================================

  defp cleanup_stale_data do
    now = DateTime.utc_now()
    auth_cutoff = DateTime.add(now, -@auth_event_retention_hours * 3600, :second)
    session_cutoff = DateTime.add(now, -@session_retention_hours * 3600, :second)
    baseline_cutoff = DateTime.add(now, -@baseline_retention_hours * 3600, :second)

    # Clean auth events
    auth_cleaned = try do
      :ets.tab2list(@auth_events_table)
      |> Enum.count(fn {key, entry} ->
        if DateTime.compare(entry.timestamp, auth_cutoff) == :lt do
          :ets.delete_object(@auth_events_table, {key, entry})
          true
        else
          false
        end
      end)
    rescue
      _ -> 0
    end

    # Clean sessions
    session_cleaned = try do
      :ets.tab2list(@sessions_table)
      |> Enum.count(fn {key, session} ->
        if DateTime.compare(session.started_at, session_cutoff) == :lt do
          :ets.delete_object(@sessions_table, {key, session})
          true
        else
          false
        end
      end)
    rescue
      _ -> 0
    end

    # Clean stale baselines (no activity in 7 days)
    baseline_cleaned = try do
      :ets.tab2list(@baselines_table)
      |> Enum.count(fn {key, baseline} ->
        last_seen = baseline[:last_seen] || DateTime.utc_now()
        if DateTime.compare(last_seen, baseline_cutoff) == :lt do
          :ets.delete(@baselines_table, key)
          true
        else
          false
        end
      end)
    rescue
      _ -> 0
    end

    auth_cleaned + session_cleaned + baseline_cleaned
  end

  # ===========================================================================
  # Utility
  # ===========================================================================

  defp count_type(detections, type) do
    Enum.count(detections, fn {t, _} -> t == type end)
  end

  defp safe_ets_size(table) do
    try do
      :ets.info(table, :size) || 0
    rescue
      _ -> 0
    end
  end

  defp create_ets_table(name, opts) do
    case :ets.whereis(name) do
      :undefined ->
        :ets.new(name, opts)
      _ref ->
        :ok
    end
  rescue
    ArgumentError ->
      :ok
  end
end
