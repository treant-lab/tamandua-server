defmodule TamanduaServer.Identity.RiskScoring do
  @moduledoc """
  User and entity risk scoring for identity protection.

  Calculates risk scores based on multiple factors:
  - Failed login attempts
  - Impossible travel
  - New device/location
  - Privilege escalation
  - Off-hours activity
  - Anomalous behavior vs baseline
  - External threat intelligence
  - Azure AD Identity Protection signals

  Risk scores are calculated on a 0-100 scale:
  - 0-29: Low risk
  - 30-59: Medium risk
  - 60-79: High risk
  - 80-100: Critical risk

  ## Architecture

  Uses ETS tables for fast lookups and persistence:
  - `identity_risk_scores` - Current risk scores per user/entity
  - `identity_baselines` - Learned behavioral baselines
  - `identity_events` - Recent events for correlation
  """

  use GenServer
  require Logger

  alias TamanduaServer.Enrichment.GeoIP

  @ets_risk_scores :identity_risk_scores
  @ets_baselines :identity_baselines
  @ets_events :identity_events

  # Risk score thresholds
  @low_risk_threshold 30
  @medium_risk_threshold 60
  @high_risk_threshold 80

  # Risk factor weights (sum should be manageable for 0-100 scale)
  @weights %{
    failed_logins: 15,
    impossible_travel: 25,
    new_device: 10,
    new_location: 15,
    privilege_escalation: 20,
    off_hours: 10,
    anomalous_behavior: 15,
    azure_ad_risk: 20,
    threat_intel_match: 25,
    mfa_bypass: 20,
    password_spray_target: 15,
    credential_stuffing_target: 15
  }

  # Time windows for analysis
  @failed_login_window_hours 24
  @failed_login_threshold 5
  @travel_speed_threshold_kph 800 # Faster than commercial flights
  @off_hours_start 22 # 10 PM
  @off_hours_end 6   # 6 AM
  @baseline_learning_days 30

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get the current risk score and details for a user.

  Returns:
    %{
      score: 0-100,
      level: :low | :medium | :high | :critical,
      factors: [%{name: string, contribution: integer, details: string}],
      last_updated: DateTime.t(),
      trend: :increasing | :decreasing | :stable
    }
  """
  def get_risk_score(user_id) when is_binary(user_id) do
    GenServer.call(__MODULE__, {:get_risk_score, user_id})
  end

  @doc """
  Record an identity event for risk calculation.
  """
  def record_identity_event(user_id, event) when is_binary(user_id) do
    GenServer.cast(__MODULE__, {:record_event, user_id, event})
  end

  @doc """
  Update user risk based on external signals (e.g., Azure AD).
  """
  def update_user_risk(user_id, risk_data) when is_binary(user_id) do
    GenServer.cast(__MODULE__, {:update_external_risk, user_id, risk_data})
  end

  @doc """
  Get all users with risk scores above a threshold.

  ## Options
    - :min_score - Minimum risk score (default: 60)
    - :limit - Maximum results (default: 100)
    - :sort - :score_desc | :score_asc | :updated_desc (default: :score_desc)
  """
  def get_high_risk_users(opts \\ []) do
    GenServer.call(__MODULE__, {:get_high_risk_users, opts})
  end

  @doc """
  Get recent risky sign-ins across all users.

  ## Options
    - :limit - Maximum results (default: 50)
    - :min_risk - Minimum risk level filter
    - :since - DateTime filter
  """
  def get_risky_sign_ins(opts \\ []) do
    GenServer.call(__MODULE__, {:get_risky_sign_ins, opts})
  end

  @doc """
  Get the baseline profile for a user.
  """
  def get_baseline(user_id) when is_binary(user_id) do
    GenServer.call(__MODULE__, {:get_baseline, user_id})
  end

  @doc """
  Record a successful login to update baselines.
  """
  def record_successful_login(user_id, login_data) when is_binary(user_id) do
    GenServer.cast(__MODULE__, {:record_login, user_id, login_data})
  end

  @doc """
  Get risk trends over time for a user.
  """
  def get_risk_trends(user_id, opts \\ []) when is_binary(user_id) do
    GenServer.call(__MODULE__, {:get_risk_trends, user_id, opts})
  end

  @doc """
  Get aggregated statistics.
  """
  def get_statistics do
    GenServer.call(__MODULE__, :get_statistics)
  end

  @doc """
  Manually recalculate risk score for a user.
  """
  def recalculate_risk(user_id) when is_binary(user_id) do
    GenServer.call(__MODULE__, {:recalculate_risk, user_id})
  end

  @doc """
  Reset/clear risk data for a user (e.g., after remediation).
  """
  def reset_user_risk(user_id) when is_binary(user_id) do
    GenServer.cast(__MODULE__, {:reset_risk, user_id})
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Create ETS tables (idempotent — survives supervisor restarts)
    if :ets.whereis(@ets_risk_scores) == :undefined,
      do: :ets.new(@ets_risk_scores, [:named_table, :set, :public, read_concurrency: true])
    if :ets.whereis(@ets_baselines) == :undefined,
      do: :ets.new(@ets_baselines, [:named_table, :set, :public, read_concurrency: true])
    if :ets.whereis(@ets_events) == :undefined,
      do: :ets.new(@ets_events, [:named_table, :bag, :public, read_concurrency: true])

    # Schedule periodic cleanup
    schedule_cleanup()
    schedule_risk_recalculation()

    Logger.info("Identity risk scoring system initialized")

    {:ok, %{}}
  end

  @impl true
  def handle_call({:get_risk_score, user_id}, _from, state) do
    result = case :ets.lookup(@ets_risk_scores, user_id) do
      [{^user_id, risk_data}] -> {:ok, risk_data}
      [] -> {:ok, default_risk_score()}
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_high_risk_users, opts}, _from, state) do
    min_score = Keyword.get(opts, :min_score, @medium_risk_threshold)
    limit = Keyword.get(opts, :limit, 100)
    sort = Keyword.get(opts, :sort, :score_desc)

    users = :ets.tab2list(@ets_risk_scores)
    |> Enum.filter(fn {_user_id, risk_data} -> risk_data.score >= min_score end)
    |> Enum.map(fn {user_id, risk_data} -> Map.put(risk_data, :user_id, user_id) end)
    |> sort_users(sort)
    |> Enum.take(limit)

    {:reply, {:ok, users}, state}
  end

  @impl true
  def handle_call({:get_risky_sign_ins, opts}, _from, state) do
    limit = Keyword.get(opts, :limit, 50)
    min_risk = Keyword.get(opts, :min_risk, :medium)
    since = Keyword.get(opts, :since, DateTime.add(DateTime.utc_now(), -24, :hour))

    min_score = case min_risk do
      :low -> 0
      :medium -> @low_risk_threshold
      :high -> @medium_risk_threshold
      :critical -> @high_risk_threshold
      _ -> @low_risk_threshold
    end

    events = :ets.tab2list(@ets_events)
    |> Enum.flat_map(fn {_user_id, event_list} when is_list(event_list) -> event_list; _ -> [] end)
    |> Enum.filter(fn event ->
      event_time = Map.get(event, :timestamp) || Map.get(event, "timestamp")
      event_score = calculate_event_risk_score(event)

      event_score >= min_score and
      (is_nil(event_time) or DateTime.compare(event_time, since) != :lt)
    end)
    |> Enum.sort_by(& &1[:timestamp], {:desc, DateTime})
    |> Enum.take(limit)

    {:reply, {:ok, events}, state}
  end

  @impl true
  def handle_call({:get_baseline, user_id}, _from, state) do
    result = case :ets.lookup(@ets_baselines, user_id) do
      [{^user_id, baseline}] -> {:ok, baseline}
      [] -> {:ok, nil}
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_risk_trends, user_id, opts}, _from, state) do
    days = Keyword.get(opts, :days, 7)
    trends = calculate_trends(user_id, days)
    {:reply, {:ok, trends}, state}
  end

  @impl true
  def handle_call(:get_statistics, _from, state) do
    risk_scores = :ets.tab2list(@ets_risk_scores)

    stats = %{
      total_users: length(risk_scores),
      critical_risk: Enum.count(risk_scores, fn {_, d} -> d.score >= @high_risk_threshold end),
      high_risk: Enum.count(risk_scores, fn {_, d} -> d.score >= @medium_risk_threshold and d.score < @high_risk_threshold end),
      medium_risk: Enum.count(risk_scores, fn {_, d} -> d.score >= @low_risk_threshold and d.score < @medium_risk_threshold end),
      low_risk: Enum.count(risk_scores, fn {_, d} -> d.score < @low_risk_threshold end),
      average_score: if(length(risk_scores) > 0, do: Enum.sum(Enum.map(risk_scores, fn {_, d} -> d.score end)) / length(risk_scores), else: 0)
    }

    {:reply, {:ok, stats}, state}
  end

  @impl true
  def handle_call({:recalculate_risk, user_id}, _from, state) do
    risk_data = do_calculate_risk(user_id)
    :ets.insert(@ets_risk_scores, {user_id, risk_data})
    {:reply, {:ok, risk_data}, state}
  end

  @impl true
  def handle_cast({:record_event, user_id, event}, state) do
    # Store event with timestamp
    event_with_meta = event
    |> Map.put(:recorded_at, DateTime.utc_now())
    |> Map.put(:user_id, user_id)

    # Get existing events and add new one
    existing = case :ets.lookup(@ets_events, user_id) do
      [{^user_id, events}] when is_list(events) -> events
      _ -> []
    end

    # Keep last 1000 events per user
    updated = [event_with_meta | existing] |> Enum.take(1000)
    :ets.insert(@ets_events, {user_id, updated})

    # Recalculate risk score
    risk_data = do_calculate_risk(user_id)
    :ets.insert(@ets_risk_scores, {user_id, risk_data})

    # Broadcast risk update
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "identity:risk_updates",
      {:risk_updated, user_id, risk_data}
    )

    {:noreply, state}
  end

  @impl true
  def handle_cast({:update_external_risk, user_id, risk_data}, state) do
    # Get current risk data
    current = case :ets.lookup(@ets_risk_scores, user_id) do
      [{^user_id, data}] -> data
      [] -> default_risk_score()
    end

    # Merge external risk signals
    updated = Map.merge(current, %{
      external_signals: Map.merge(current[:external_signals] || %{}, risk_data),
      last_updated: DateTime.utc_now()
    })

    # Recalculate with new signals
    risk_data_final = do_calculate_risk(user_id, updated)
    :ets.insert(@ets_risk_scores, {user_id, risk_data_final})

    {:noreply, state}
  end

  @impl true
  def handle_cast({:record_login, user_id, login_data}, state) do
    update_baseline(user_id, login_data)
    {:noreply, state}
  end

  @impl true
  def handle_cast({:reset_risk, user_id}, state) do
    :ets.delete(@ets_risk_scores, user_id)
    :ets.delete(@ets_events, user_id)
    Logger.info("Reset risk data for user: #{user_id}")
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_old_events()
    schedule_cleanup()
    {:noreply, state}
  end

  @impl true
  def handle_info(:recalculate_all, state) do
    recalculate_all_risks()
    schedule_risk_recalculation()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions - Risk Calculation
  # ============================================================================

  defp default_risk_score do
    %{
      score: 0,
      level: :low,
      factors: [],
      last_updated: DateTime.utc_now(),
      trend: :stable,
      external_signals: %{}
    }
  end

  defp do_calculate_risk(user_id, existing_data \\ nil) do
    # Get events for this user
    events = case :ets.lookup(@ets_events, user_id) do
      [{^user_id, e}] when is_list(e) -> e
      _ -> []
    end

    # Get baseline
    baseline = case :ets.lookup(@ets_baselines, user_id) do
      [{^user_id, b}] -> b
      _ -> nil
    end

    # Get external signals
    external = if existing_data, do: existing_data[:external_signals] || %{}, else: %{}

    # Calculate individual risk factors
    factors = []
    |> calculate_failed_login_factor(user_id, events)
    |> calculate_impossible_travel_factor(user_id, events, baseline)
    |> calculate_new_device_factor(user_id, events, baseline)
    |> calculate_new_location_factor(user_id, events, baseline)
    |> calculate_privilege_escalation_factor(user_id, events)
    |> calculate_off_hours_factor(user_id, events, baseline)
    |> calculate_anomalous_behavior_factor(user_id, events, baseline)
    |> calculate_azure_ad_risk_factor(external)
    |> calculate_threat_intel_factor(user_id, events)

    # Calculate total score
    total_score = factors
    |> Enum.map(& &1.contribution)
    |> Enum.sum()
    |> min(100)
    |> max(0)

    # Determine risk level
    level = cond do
      total_score >= @high_risk_threshold -> :critical
      total_score >= @medium_risk_threshold -> :high
      total_score >= @low_risk_threshold -> :medium
      true -> :low
    end

    # Calculate trend
    previous_score = if existing_data, do: existing_data[:score] || 0, else: 0
    trend = cond do
      total_score > previous_score + 5 -> :increasing
      total_score < previous_score - 5 -> :decreasing
      true -> :stable
    end

    %{
      score: total_score,
      level: level,
      factors: factors,
      last_updated: DateTime.utc_now(),
      trend: trend,
      external_signals: external
    }
  end

  defp calculate_failed_login_factor(factors, _user_id, events) do
    window_start = DateTime.add(DateTime.utc_now(), -@failed_login_window_hours, :hour)

    failed_logins = events
    |> Enum.filter(fn event ->
      is_failed_login?(event) and
      event_in_window?(event, window_start)
    end)
    |> length()

    if failed_logins >= @failed_login_threshold do
      contribution = min(failed_logins * 3, @weights.failed_logins)
      [%{
        name: "Failed Logins",
        contribution: contribution,
        details: "#{failed_logins} failed login attempts in last #{@failed_login_window_hours} hours"
      } | factors]
    else
      factors
    end
  end

  defp calculate_impossible_travel_factor(factors, _user_id, events, baseline) do
    # Get recent login locations
    recent_logins = events
    |> Enum.filter(&is_login_event?/1)
    |> Enum.sort_by(& &1[:timestamp], {:desc, DateTime})
    |> Enum.take(10)

    # Check for impossible travel
    impossible_travel = detect_impossible_travel(recent_logins)

    if impossible_travel do
      [%{
        name: "Impossible Travel",
        contribution: @weights.impossible_travel,
        details: "Login from #{impossible_travel.location1} followed by #{impossible_travel.location2} (#{impossible_travel.distance_km} km in #{impossible_travel.time_hours} hours)"
      } | factors]
    else
      factors
    end
  end

  defp calculate_new_device_factor(factors, _user_id, events, baseline) do
    if baseline do
      known_devices = baseline[:devices] || []

      new_devices = events
      |> Enum.filter(&is_login_event?/1)
      |> Enum.filter(fn event ->
        device_id = get_device_id(event)
        device_id && device_id not in known_devices
      end)
      |> Enum.take(1)

      if length(new_devices) > 0 do
        device = hd(new_devices)
        [%{
          name: "New Device",
          contribution: @weights.new_device,
          details: "Login from unrecognized device: #{get_device_info(device)}"
        } | factors]
      else
        factors
      end
    else
      factors
    end
  end

  defp calculate_new_location_factor(factors, _user_id, events, baseline) do
    if baseline do
      known_locations = baseline[:locations] || []

      new_locations = events
      |> Enum.filter(&is_login_event?/1)
      |> Enum.filter(fn event ->
        location = get_location(event)
        location && location not in known_locations
      end)
      |> Enum.take(1)

      if length(new_locations) > 0 do
        event = hd(new_locations)
        location = get_location(event)
        [%{
          name: "New Location",
          contribution: @weights.new_location,
          details: "Login from new location: #{location}"
        } | factors]
      else
        factors
      end
    else
      factors
    end
  end

  defp calculate_privilege_escalation_factor(factors, _user_id, events) do
    privilege_events = events
    |> Enum.filter(fn event ->
      event_type = Map.get(event, :event_type) || Map.get(event, "event_type")
      event_type in ["special_privileges", "user_added_to_global_group", "user_added_to_local_group",
                     "privilege_escalation", "Add member to role", "Add owner to service principal"]
    end)
    |> Enum.take(5)

    if length(privilege_events) > 0 do
      [%{
        name: "Privilege Escalation",
        contribution: @weights.privilege_escalation,
        details: "#{length(privilege_events)} privilege-related events detected"
      } | factors]
    else
      factors
    end
  end

  defp calculate_off_hours_factor(factors, _user_id, events, baseline) do
    # Determine user's typical working hours (or use defaults)
    typical_hours = if baseline do
      baseline[:typical_hours] || {@off_hours_end, @off_hours_start}
    else
      {@off_hours_end, @off_hours_start}
    end

    {work_start, work_end} = typical_hours

    off_hours_events = events
    |> Enum.filter(&is_login_event?/1)
    |> Enum.filter(fn event ->
      timestamp = event[:timestamp] || event["timestamp"]
      if timestamp do
        hour = timestamp.hour
        hour < work_start or hour >= work_end
      else
        false
      end
    end)
    |> length()

    if off_hours_events >= 3 do
      [%{
        name: "Off-Hours Activity",
        contribution: @weights.off_hours,
        details: "#{off_hours_events} login attempts outside normal working hours"
      } | factors]
    else
      factors
    end
  end

  defp calculate_anomalous_behavior_factor(factors, _user_id, events, baseline) do
    if baseline do
      # Compare current behavior to baseline
      anomalies = []

      # Check login frequency
      recent_count = events
      |> Enum.filter(&is_login_event?/1)
      |> Enum.filter(&event_in_window?(&1, DateTime.add(DateTime.utc_now(), -24, :hour)))
      |> length()

      baseline_avg = baseline[:avg_daily_logins] || 5
      anomalies = if recent_count > baseline_avg * 3 do
        ["High login frequency (#{recent_count} vs avg #{baseline_avg})" | anomalies]
      else
        anomalies
      end

      # Check unusual apps
      apps_used = events
      |> Enum.filter(&is_login_event?/1)
      |> Enum.map(fn e -> e[:app_display_name] || e["app_display_name"] end)
      |> Enum.filter(& &1)
      |> Enum.uniq()

      known_apps = baseline[:known_apps] || []
      new_apps = apps_used -- known_apps
      anomalies = if length(new_apps) > 2 do
        ["Access to #{length(new_apps)} new applications" | anomalies]
      else
        anomalies
      end

      if length(anomalies) > 0 do
        [%{
          name: "Anomalous Behavior",
          contribution: min(length(anomalies) * 5, @weights.anomalous_behavior),
          details: Enum.join(anomalies, "; ")
        } | factors]
      else
        factors
      end
    else
      factors
    end
  end

  defp calculate_azure_ad_risk_factor(factors, external_signals) do
    azure_risk = Map.get(external_signals, :azure_ad_risk_level)

    if azure_risk && azure_risk != "none" do
      contribution = case azure_risk do
        "high" -> @weights.azure_ad_risk
        "medium" -> div(@weights.azure_ad_risk, 2)
        "low" -> div(@weights.azure_ad_risk, 4)
        _ -> 0
      end

      if contribution > 0 do
        [%{
          name: "Azure AD Risk",
          contribution: contribution,
          details: "Azure AD Identity Protection: #{azure_risk} risk"
        } | factors]
      else
        factors
      end
    else
      factors
    end
  end

  defp calculate_threat_intel_factor(factors, _user_id, events) do
    # Check if any source IPs match threat intel
    threat_matches = events
    |> Enum.filter(fn event ->
      ip = event[:ip_address] || event["ip_address"] || event[:source_ip]
      if ip do
        case GeoIP.lookup(ip) do
          {:ok, %{is_tor: true}} -> true
          {:ok, %{is_proxy: true}} -> true
          {:ok, %{is_high_risk_country: true}} -> true
          _ -> false
        end
      else
        false
      end
    end)
    |> length()

    if threat_matches > 0 do
      [%{
        name: "Threat Intelligence Match",
        contribution: min(threat_matches * 10, @weights.threat_intel_match),
        details: "#{threat_matches} events from suspicious IP addresses (Tor/proxy/high-risk)"
      } | factors]
    else
      factors
    end
  end

  # ============================================================================
  # Private Functions - Baseline Management
  # ============================================================================

  defp update_baseline(user_id, login_data) do
    current = case :ets.lookup(@ets_baselines, user_id) do
      [{^user_id, baseline}] -> baseline
      [] -> %{
        devices: [],
        locations: [],
        known_apps: [],
        login_times: [],
        avg_daily_logins: 0,
        typical_hours: {@off_hours_end, @off_hours_start},
        first_seen: DateTime.utc_now(),
        last_updated: DateTime.utc_now()
      }
    end

    # Extract data from login
    device_id = get_device_id(login_data)
    location = get_location(login_data)
    app = login_data[:app_display_name] || login_data["app_display_name"]
    timestamp = login_data[:timestamp] || DateTime.utc_now()

    # Update baseline
    updated = current
    |> update_device_baseline(device_id)
    |> update_location_baseline(location)
    |> update_app_baseline(app)
    |> update_time_baseline(timestamp)
    |> Map.put(:last_updated, DateTime.utc_now())

    :ets.insert(@ets_baselines, {user_id, updated})
  end

  defp update_device_baseline(baseline, nil), do: baseline
  defp update_device_baseline(baseline, device_id) do
    devices = [device_id | (baseline[:devices] || [])] |> Enum.uniq() |> Enum.take(50)
    Map.put(baseline, :devices, devices)
  end

  defp update_location_baseline(baseline, nil), do: baseline
  defp update_location_baseline(baseline, location) do
    locations = [location | (baseline[:locations] || [])] |> Enum.uniq() |> Enum.take(20)
    Map.put(baseline, :locations, locations)
  end

  defp update_app_baseline(baseline, nil), do: baseline
  defp update_app_baseline(baseline, app) do
    apps = [app | (baseline[:known_apps] || [])] |> Enum.uniq() |> Enum.take(100)
    Map.put(baseline, :known_apps, apps)
  end

  defp update_time_baseline(baseline, timestamp) do
    times = [timestamp.hour | (baseline[:login_times] || [])] |> Enum.take(1000)
    Map.put(baseline, :login_times, times)
  end

  # ============================================================================
  # Private Functions - Helpers
  # ============================================================================

  defp is_failed_login?(event) do
    event_type = Map.get(event, :event_type) || Map.get(event, "event_type")
    status = Map.get(event, :status_error_code) || Map.get(event, "status_error_code") || 0

    event_type in ["logon_failure", "failed_sign_in", "azure_ad_sign_in"] and
    (status != 0 or event_type == "logon_failure")
  end

  defp is_login_event?(event) do
    event_type = Map.get(event, :event_type) || Map.get(event, "event_type")
    event_type in ["logon_success", "logon_failure", "azure_ad_sign_in", "sign_in"]
  end

  defp event_in_window?(event, window_start) do
    timestamp = event[:timestamp] || event["timestamp"]
    timestamp && DateTime.compare(timestamp, window_start) != :lt
  end

  defp get_device_id(event) do
    device_detail = event[:device_detail] || event["device_detail"] || %{}
    device_id = device_detail["deviceId"] || device_detail[:device_id]

    if device_id do
      device_id
    else
      # Generate a pseudo-ID from browser + OS
      browser = device_detail["browser"] || device_detail[:browser] || ""
      os = device_detail["operatingSystem"] || device_detail[:operating_system] || ""
      if browser != "" or os != "" do
        :crypto.hash(:sha256, "#{browser}:#{os}") |> Base.encode16(case: :lower) |> String.slice(0, 16)
      else
        nil
      end
    end
  end

  defp get_device_info(event) do
    device_detail = event[:device_detail] || event["device_detail"] || %{}
    browser = device_detail["browser"] || device_detail[:browser] || "Unknown"
    os = device_detail["operatingSystem"] || device_detail[:operating_system] || "Unknown"
    "#{browser} on #{os}"
  end

  defp get_location(event) do
    location = event[:location] || event["location"] || %{}
    city = location["city"] || location[:city]
    country = location["countryOrRegion"] || location[:country] || location["country"]

    if city || country do
      "#{city || "Unknown"}, #{country || "Unknown"}"
    else
      nil
    end
  end

  defp detect_impossible_travel(logins) when length(logins) < 2, do: nil
  defp detect_impossible_travel(logins) do
    logins
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.find_value(fn [login1, login2] ->
      location1 = login1[:location] || login1["location"]
      location2 = login2[:location] || login2["location"]
      timestamp1 = login1[:timestamp] || login1["timestamp"]
      timestamp2 = login2[:timestamp] || login2["timestamp"]

      if location1 && location2 && timestamp1 && timestamp2 do
        lat1 = location1["latitude"] || location1[:latitude]
        lon1 = location1["longitude"] || location1[:longitude]
        lat2 = location2["latitude"] || location2[:latitude]
        lon2 = location2["longitude"] || location2[:longitude]

        if lat1 && lon1 && lat2 && lon2 do
          distance_km = haversine_distance(lat1, lon1, lat2, lon2)
          time_diff = DateTime.diff(timestamp1, timestamp2, :second) |> abs()
          time_hours = time_diff / 3600

          if time_hours > 0 do
            speed_kph = distance_km / time_hours

            if speed_kph > @travel_speed_threshold_kph and distance_km > 500 do
              %{
                location1: get_location(login1),
                location2: get_location(login2),
                distance_km: round(distance_km),
                time_hours: Float.round(time_hours, 1),
                speed_kph: round(speed_kph)
              }
            else
              nil
            end
          else
            nil
          end
        else
          nil
        end
      else
        nil
      end
    end)
  end

  defp haversine_distance(lat1, lon1, lat2, lon2) do
    r = 6371 # Earth's radius in km

    lat1_rad = lat1 * :math.pi() / 180
    lat2_rad = lat2 * :math.pi() / 180
    delta_lat = (lat2 - lat1) * :math.pi() / 180
    delta_lon = (lon2 - lon1) * :math.pi() / 180

    a = :math.sin(delta_lat / 2) * :math.sin(delta_lat / 2) +
        :math.cos(lat1_rad) * :math.cos(lat2_rad) *
        :math.sin(delta_lon / 2) * :math.sin(delta_lon / 2)

    c = 2 * :math.atan2(:math.sqrt(a), :math.sqrt(1 - a))

    r * c
  end

  defp calculate_event_risk_score(event) do
    risk_level = event[:risk_level_during_sign_in] || event["risk_level_during_sign_in"]
    status = event[:status_error_code] || event["status_error_code"] || 0

    base_score = case risk_level do
      "high" -> 80
      "medium" -> 50
      "low" -> 20
      _ -> 0
    end

    # Add points for failed logins
    base_score = if status != 0, do: base_score + 10, else: base_score

    min(base_score, 100)
  end

  defp sort_users(users, :score_desc) do
    Enum.sort_by(users, & &1.score, :desc)
  end
  defp sort_users(users, :score_asc) do
    Enum.sort_by(users, & &1.score, :asc)
  end
  defp sort_users(users, :updated_desc) do
    Enum.sort_by(users, & &1.last_updated, {:desc, DateTime})
  end

  defp calculate_trends(_user_id, _days) do
    # Placeholder for trend calculation
    # Would query historical data from a time-series store
    []
  end

  defp cleanup_old_events do
    cutoff = DateTime.add(DateTime.utc_now(), -7, :day)

    :ets.tab2list(@ets_events)
    |> Enum.each(fn {user_id, events} when is_list(events) ->
      filtered = Enum.filter(events, fn event ->
        timestamp = event[:timestamp] || event["timestamp"] || event[:recorded_at]
        is_nil(timestamp) or DateTime.compare(timestamp, cutoff) != :lt
      end)
      :ets.insert(@ets_events, {user_id, filtered})
    end)

    Logger.debug("Cleaned up old identity events")
  end

  defp recalculate_all_risks do
    :ets.tab2list(@ets_risk_scores)
    |> Enum.each(fn {user_id, _} ->
      risk_data = do_calculate_risk(user_id)
      :ets.insert(@ets_risk_scores, {user_id, risk_data})
    end)

    Logger.debug("Recalculated all identity risk scores")
  end

  defp schedule_cleanup do
    # Run cleanup every hour
    Process.send_after(self(), :cleanup, :timer.hours(1))
  end

  defp schedule_risk_recalculation do
    # Recalculate all risks every 15 minutes
    Process.send_after(self(), :recalculate_all, :timer.minutes(15))
  end
end
