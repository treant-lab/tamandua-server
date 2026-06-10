defmodule TamanduaServer.Identity.UserProfiler do
  @moduledoc """
  User Behavior Profiling Engine.

  Builds and maintains behavioral profiles for individual users based on
  telemetry data. Profiles capture typical patterns across multiple dimensions
  and flag deviations that may indicate compromised accounts or insider threats.

  ## Profile Dimensions

  - **Login patterns**: Time-of-day distribution, day-of-week activity
  - **Process execution**: Frequency map of launched processes
  - **Network destinations**: IP/domain frequency (typical vs unusual)
  - **File access patterns**: Common paths, extensions, and volumes
  - **Authentication patterns**: Success/failure ratios, source locations
  - **Privilege usage**: sudo/runas frequency, admin actions

  ## Anomaly Types

  - `:unusual_login_time`     - Activity outside normal working hours
  - `:unusual_process`        - Launching a never-before-seen process
  - `:unusual_destination`    - Connecting to an unfamiliar IP/domain
  - `:privilege_escalation`   - Sudden increase in privilege usage
  - `:impossible_travel`      - Login from geographically distant locations

  ## ETS Tables

  - `:user_profiles`        - Per-user profile data (frequency maps, distributions)
  - `:user_profile_meta`    - Profile metadata (creation time, update counts)

  ## PubSub Integration

  Subscribes to `"telemetry:events"` for real-time profile updates.
  Publishes deviations to `"identity:deviations"`.
  """

  use GenServer
  require Logger

  # ---------------------------------------------------------------------------
  # Constants
  # ---------------------------------------------------------------------------

  @profiles_table :user_profiles
  @meta_table :user_profile_meta

  # Minimum events before deviation checks are meaningful
  @min_profile_events 50
  # Earth radius in km for Haversine distance
  @earth_radius_km 6371.0
  # Impossible travel speed threshold (km/h)
  @impossible_travel_kph 900

  # Periodic intervals
  @cleanup_interval :timer.hours(12)

  # Maximum entries in frequency maps
  @max_process_entries 200
  @max_destination_entries 300
  @max_file_path_entries 200

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Build or rebuild the profile for a user from scratch.

  In practice this would query historical telemetry from ClickHouse/PostgreSQL.
  Here it initializes a fresh profile structure.
  """
  @spec build_profile(String.t()) :: {:ok, map()}
  def build_profile(user_id) when is_binary(user_id) do
    GenServer.call(__MODULE__, {:build_profile, user_id})
  end

  @doc """
  Update the user profile with a new event. Called on every relevant
  telemetry event for the user.
  """
  @spec update_profile(String.t(), map()) :: :ok
  def update_profile(user_id, event) when is_binary(user_id) and is_map(event) do
    GenServer.cast(__MODULE__, {:update_profile, user_id, event})
  end

  @doc """
  Check if an event deviates from the user's established profile.

  Returns `{deviation_type, confidence, details}` or `:normal`.

  ## Examples

      check_deviation("user@example.com", %{event_type: "logon_success", ...})
      # => {:unusual_login_time, 0.85, %{hour: 3, typical_range: {8, 18}}}
  """
  @spec check_deviation(String.t(), map()) ::
          :normal | {atom(), float(), map()}
  def check_deviation(user_id, event) when is_binary(user_id) and is_map(event) do
    GenServer.call(__MODULE__, {:check_deviation, user_id, event})
  end

  @doc """
  Retrieve the full profile for a user.
  """
  @spec get_profile(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_profile(user_id) when is_binary(user_id) do
    case :ets.lookup(@profiles_table, user_id) do
      [{^user_id, profile}] -> {:ok, profile}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Get the peer group assignment for a user.
  Delegates to the PeerClustering module if available.
  """
  @spec get_peer_group(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_peer_group(user_id) when is_binary(user_id) do
    case TamanduaServer.Identity.PeerClustering.get_cluster_for_user(user_id) do
      nil -> {:error, :not_found}
      cluster -> {:ok, cluster}
    end
  end

  @doc """
  Get statistics about user profiles.
  """
  @spec stats() :: map()
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  # ---------------------------------------------------------------------------
  # GenServer Callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    :ets.new(@profiles_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@meta_table, [:named_table, :set, :public, read_concurrency: true])

    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "telemetry:events")

    schedule_cleanup()

    Logger.info("[UserProfiler] Initialized")
    {:ok, %{events_processed: 0}}
  end

  @impl true
  def handle_call({:build_profile, user_id}, _from, state) do
    profile = create_empty_profile()
    :ets.insert(@profiles_table, {user_id, profile})

    meta = %{
      created_at: DateTime.utc_now(),
      last_updated: DateTime.utc_now(),
      event_count: 0,
      deviation_count: 0
    }

    :ets.insert(@meta_table, {user_id, meta})
    {:reply, {:ok, profile}, state}
  end

  @impl true
  def handle_call({:check_deviation, user_id, event}, _from, state) do
    result =
      case :ets.lookup(@profiles_table, user_id) do
        [{^user_id, profile}] ->
          meta = lookup_meta(user_id)

          if meta && meta.event_count >= @min_profile_events do
            do_check_deviation(profile, event)
          else
            :normal
          end

        [] ->
          :normal
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call(:stats, _from, state) do
    profiles = :ets.info(@profiles_table, :size)
    metas = ets_safe_tab2list(@meta_table)

    total_events =
      Enum.reduce(metas, 0, fn {_uid, meta}, acc -> acc + meta.event_count end)

    total_deviations =
      Enum.reduce(metas, 0, fn {_uid, meta}, acc -> acc + meta.deviation_count end)

    result = %{
      total_profiles: profiles,
      total_events_processed: total_events,
      total_deviations_detected: total_deviations,
      gen_server_events: state.events_processed
    }

    {:reply, result, state}
  end

  @impl true
  def handle_cast({:update_profile, user_id, event}, state) do
    do_update_profile(user_id, event)
    {:noreply, %{state | events_processed: state.events_processed + 1}}
  end

  # Handle PubSub telemetry events
  @impl true
  def handle_info({:telemetry_event, event}, state) do
    user_id = extract_user_id(event)

    if user_id do
      do_update_profile(user_id, event)
    end

    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    do_cleanup()
    schedule_cleanup()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ---------------------------------------------------------------------------
  # Private - Profile Updates
  # ---------------------------------------------------------------------------

  defp do_update_profile(user_id, event) do
    profile =
      case :ets.lookup(@profiles_table, user_id) do
        [{^user_id, p}] -> p
        [] -> create_empty_profile()
      end

    event_type = extract_field(event, :event_type)
    updated = profile

    # Update login time distribution
    updated =
      if event_type in ~w(logon_success logon_failure authentication login sign_in) do
        update_login_times(updated, event)
      else
        updated
      end

    # Update process frequency
    updated =
      case extract_field(event, :process_name) do
        nil -> updated
        name -> update_process_frequency(updated, name)
      end

    # Update network destinations
    updated =
      case extract_field(event, :dest_ip) || extract_field(event, :destination_ip) ||
             extract_field(event, :domain) do
        nil -> updated
        dest -> update_destination_frequency(updated, dest)
      end

    # Update file access patterns
    updated =
      case extract_field(event, :file_path) || extract_field(event, :path) do
        nil -> updated
        path -> update_file_patterns(updated, path)
      end

    # Update authentication patterns
    updated =
      if event_type in ~w(logon_success logon_failure authentication) do
        update_auth_patterns(updated, event)
      else
        updated
      end

    # Update privilege usage
    updated =
      if event_type in ~w(privilege_escalation special_privileges sudo runas) do
        update_privilege_patterns(updated)
      else
        updated
      end

    # Update last login location for travel checks
    updated =
      if event_type in ~w(logon_success login sign_in) do
        update_login_location(updated, event)
      else
        updated
      end

    :ets.insert(@profiles_table, {user_id, updated})

    # Update metadata
    meta = lookup_meta(user_id) || %{created_at: DateTime.utc_now(), last_updated: nil, event_count: 0, deviation_count: 0}
    updated_meta = %{meta | last_updated: DateTime.utc_now(), event_count: meta.event_count + 1}
    :ets.insert(@meta_table, {user_id, updated_meta})
  end

  defp update_login_times(profile, event) do
    timestamp = extract_field(event, :timestamp) || DateTime.utc_now()

    hour =
      case timestamp do
        %DateTime{hour: h} -> h
        _ -> DateTime.utc_now().hour
      end

    hour_dist = Map.update(profile.login_hours, hour, 1, &(&1 + 1))
    %{profile | login_hours: hour_dist}
  end

  defp update_process_frequency(profile, process_name) do
    freq = profile.process_frequency
    count = Map.get(freq, process_name, 0) + 1

    updated =
      if map_size(freq) >= @max_process_entries and not Map.has_key?(freq, process_name) do
        {min_key, _} = Enum.min_by(freq, fn {_k, v} -> v end)
        freq |> Map.delete(min_key) |> Map.put(process_name, count)
      else
        Map.put(freq, process_name, count)
      end

    %{profile | process_frequency: updated}
  end

  defp update_destination_frequency(profile, destination) do
    freq = profile.network_destinations
    count = Map.get(freq, destination, 0) + 1

    updated =
      if map_size(freq) >= @max_destination_entries and not Map.has_key?(freq, destination) do
        {min_key, _} = Enum.min_by(freq, fn {_k, v} -> v end)
        freq |> Map.delete(min_key) |> Map.put(destination, count)
      else
        Map.put(freq, destination, count)
      end

    %{profile | network_destinations: updated}
  end

  defp update_file_patterns(profile, path) do
    ext = Path.extname(path)
    ext_freq = Map.update(profile.file_extensions, ext, 1, &(&1 + 1))

    path_freq = profile.file_paths
    count = Map.get(path_freq, path, 0) + 1

    updated_paths =
      if map_size(path_freq) >= @max_file_path_entries and not Map.has_key?(path_freq, path) do
        {min_key, _} = Enum.min_by(path_freq, fn {_k, v} -> v end)
        path_freq |> Map.delete(min_key) |> Map.put(path, count)
      else
        Map.put(path_freq, path, count)
      end

    %{profile | file_extensions: ext_freq, file_paths: updated_paths}
  end

  defp update_auth_patterns(profile, event) do
    event_type = extract_field(event, :event_type)

    is_success = event_type in ~w(logon_success login sign_in)

    auth = profile.auth_patterns
    updated_auth =
      if is_success do
        %{auth | successes: auth.successes + 1}
      else
        %{auth | failures: auth.failures + 1}
      end

    # Track source location
    location = extract_field(event, :source_ip) || extract_field(event, :ip_address)

    updated_auth =
      if location do
        locations = [location | updated_auth.locations] |> Enum.uniq() |> Enum.take(50)
        %{updated_auth | locations: locations}
      else
        updated_auth
      end

    %{profile | auth_patterns: updated_auth}
  end

  defp update_privilege_patterns(profile) do
    priv = profile.privilege_usage
    %{profile | privilege_usage: %{priv | count: priv.count + 1, last_at: DateTime.utc_now()}}
  end

  defp update_login_location(profile, event) do
    lat = extract_field(event, :latitude)
    lon = extract_field(event, :longitude)

    if lat && lon do
      timestamp = extract_field(event, :timestamp) || DateTime.utc_now()

      new_login = %{
        latitude: lat,
        longitude: lon,
        timestamp: timestamp
      }

      %{profile | last_login_location: new_login}
    else
      profile
    end
  end

  # ---------------------------------------------------------------------------
  # Private - Deviation Checks
  # ---------------------------------------------------------------------------

  defp do_check_deviation(profile, event) do
    checks = [
      &check_login_time_deviation/2,
      &check_process_deviation/2,
      &check_destination_deviation/2,
      &check_privilege_deviation/2,
      &check_travel_deviation/2
    ]

    # Return first significant deviation found
    Enum.find_value(checks, :normal, fn check_fn ->
      case check_fn.(profile, event) do
        :normal -> nil
        deviation -> deviation
      end
    end)
  end

  defp check_login_time_deviation(profile, event) do
    event_type = extract_field(event, :event_type)

    if event_type in ~w(logon_success login sign_in) do
      timestamp = extract_field(event, :timestamp) || DateTime.utc_now()

      hour =
        case timestamp do
          %DateTime{hour: h} -> h
          _ -> DateTime.utc_now().hour
        end

      total = Enum.sum(Map.values(profile.login_hours))

      if total > 0 do
        hour_count = Map.get(profile.login_hours, hour, 0)
        frequency = hour_count / total

        # If this hour has less than 2% of all logins and fewer than 3 observed
        if frequency < 0.02 and hour_count < 3 do
          # Find typical hour range
          sorted_hours =
            profile.login_hours
            |> Enum.sort_by(fn {_h, c} -> c end, :desc)
            |> Enum.take(4)
            |> Enum.map(fn {h, _c} -> h end)
            |> Enum.sort()

          typical_range =
            if sorted_hours != [] do
              {List.first(sorted_hours), List.last(sorted_hours)}
            else
              {8, 18}
            end

          confidence = min(1.0, (1.0 - frequency) * 0.9)

          {:unusual_login_time, confidence,
           %{
             hour: hour,
             hour_frequency: Float.round(frequency, 4),
             typical_range: typical_range,
             total_logins: total
           }}
        else
          :normal
        end
      else
        :normal
      end
    else
      :normal
    end
  end

  defp check_process_deviation(profile, event) do
    process_name = extract_field(event, :process_name)

    if process_name && map_size(profile.process_frequency) > 0 do
      total = Enum.sum(Map.values(profile.process_frequency))

      if total >= @min_profile_events and not Map.has_key?(profile.process_frequency, process_name) do
        {:unusual_process, 0.75,
         %{
           process_name: process_name,
           known_processes: map_size(profile.process_frequency),
           total_observations: total
         }}
      else
        :normal
      end
    else
      :normal
    end
  end

  defp check_destination_deviation(profile, event) do
    dest =
      extract_field(event, :dest_ip) || extract_field(event, :destination_ip) ||
        extract_field(event, :domain)

    if dest && map_size(profile.network_destinations) > 0 do
      total = Enum.sum(Map.values(profile.network_destinations))

      if total >= @min_profile_events and not Map.has_key?(profile.network_destinations, dest) do
        {:unusual_destination, 0.65,
         %{
           destination: dest,
           known_destinations: map_size(profile.network_destinations),
           total_observations: total
         }}
      else
        :normal
      end
    else
      :normal
    end
  end

  defp check_privilege_deviation(profile, event) do
    event_type = extract_field(event, :event_type)

    if event_type in ~w(privilege_escalation special_privileges sudo runas) do
      priv = profile.privilege_usage

      if priv.count == 0 do
        {:privilege_escalation, 0.8,
         %{
           note: "First privilege usage detected for this user",
           event_type: event_type
         }}
      else
        :normal
      end
    else
      :normal
    end
  end

  defp check_travel_deviation(profile, event) do
    event_type = extract_field(event, :event_type)

    if event_type in ~w(logon_success login sign_in) and profile.last_login_location do
      new_lat = extract_field(event, :latitude)
      new_lon = extract_field(event, :longitude)
      new_time = extract_field(event, :timestamp) || DateTime.utc_now()

      prev = profile.last_login_location

      if new_lat && new_lon && prev.latitude && prev.longitude do
        distance_km = haversine_distance(prev.latitude, prev.longitude, new_lat, new_lon)

        time_diff_hours =
          case prev.timestamp do
            %DateTime{} = prev_time ->
              abs(DateTime.diff(new_time, prev_time, :second)) / 3600.0

            _ ->
              24.0
          end

        if time_diff_hours > 0 do
          speed_kph = distance_km / time_diff_hours

          if speed_kph > @impossible_travel_kph and distance_km > 500 do
            confidence = min(1.0, speed_kph / (@impossible_travel_kph * 3))

            {:impossible_travel, confidence,
             %{
               distance_km: round(distance_km),
               time_hours: Float.round(time_diff_hours, 1),
               speed_kph: round(speed_kph),
               from: %{lat: prev.latitude, lon: prev.longitude},
               to: %{lat: new_lat, lon: new_lon}
             }}
          else
            :normal
          end
        else
          :normal
        end
      else
        :normal
      end
    else
      :normal
    end
  end

  # ---------------------------------------------------------------------------
  # Private - Utilities
  # ---------------------------------------------------------------------------

  defp create_empty_profile do
    %{
      login_hours: %{},
      process_frequency: %{},
      network_destinations: %{},
      file_extensions: %{},
      file_paths: %{},
      auth_patterns: %{
        successes: 0,
        failures: 0,
        locations: []
      },
      privilege_usage: %{
        count: 0,
        last_at: nil
      },
      last_login_location: nil
    }
  end

  defp lookup_meta(user_id) do
    case :ets.lookup(@meta_table, user_id) do
      [{^user_id, meta}] -> meta
      [] -> nil
    end
  end

  defp extract_user_id(event) do
    extract_field(event, :user) || extract_field(event, :user_name) ||
      extract_field(event, :user_id) || extract_field(event, :username)
  end

  defp extract_field(event, key) when is_atom(key) do
    Map.get(event, key) || Map.get(event, to_string(key))
  end

  defp haversine_distance(lat1, lon1, lat2, lon2) do
    lat1_rad = lat1 * :math.pi() / 180
    lat2_rad = lat2 * :math.pi() / 180
    delta_lat = (lat2 - lat1) * :math.pi() / 180
    delta_lon = (lon2 - lon1) * :math.pi() / 180

    a =
      :math.sin(delta_lat / 2) * :math.sin(delta_lat / 2) +
        :math.cos(lat1_rad) * :math.cos(lat2_rad) *
          :math.sin(delta_lon / 2) * :math.sin(delta_lon / 2)

    c = 2 * :math.atan2(:math.sqrt(a), :math.sqrt(1 - a))
    @earth_radius_km * c
  end

  defp do_cleanup do
    cutoff = DateTime.add(DateTime.utc_now(), -90, :day)

    ets_safe_tab2list(@meta_table)
    |> Enum.each(fn {user_id, meta} ->
      if meta.last_updated && DateTime.compare(meta.last_updated, cutoff) == :lt do
        :ets.delete(@profiles_table, user_id)
        :ets.delete(@meta_table, user_id)
      end
    end)

    Logger.debug("[UserProfiler] Cleanup completed")
  end

  defp ets_safe_tab2list(table) do
    try do
      :ets.tab2list(table)
    rescue
      ArgumentError -> []
    end
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end
end
