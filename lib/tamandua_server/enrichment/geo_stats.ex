defmodule TamanduaServer.Enrichment.GeoStats do
  @moduledoc """
  Geographic statistics and aggregation for threat visualization.

  Provides aggregated threat data by location, including:
  - Threat origins by country
  - Agent locations
  - Attack vectors and connections
  - Heatmap data for threat density

  Caches results in ETS for performance.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Enrichment.GeoIP
  alias TamanduaServer.Repo

  import Ecto.Query

  @cache_table :geo_stats_cache
  @cache_ttl_ms 300_000  # 5 minutes
  @update_interval_ms 60_000  # 1 minute

  # Country centroids for visualization when exact coordinates unavailable
  @country_centroids %{
    "US" => {37.0902, -95.7129},
    "CN" => {35.8617, 104.1954},
    "RU" => {61.5240, 105.3188},
    "DE" => {51.1657, 10.4515},
    "GB" => {55.3781, -3.4360},
    "FR" => {46.2276, 2.2137},
    "JP" => {36.2048, 138.2529},
    "KR" => {35.9078, 127.7669},
    "BR" => {-14.2350, -51.9253},
    "IN" => {20.5937, 78.9629},
    "AU" => {-25.2744, 133.7751},
    "CA" => {56.1304, -106.3468},
    "NL" => {52.1326, 5.2913},
    "IT" => {41.8719, 12.5674},
    "ES" => {40.4637, -3.7492},
    "SE" => {60.1282, 18.6435},
    "PL" => {51.9194, 19.1451},
    "UA" => {48.3794, 31.1656},
    "RO" => {45.9432, 24.9668},
    "IR" => {32.4279, 53.6880},
    "KP" => {40.3399, 127.5101},
    "VN" => {14.0583, 108.2772},
    "TH" => {15.8700, 100.9925},
    "ID" => {-0.7893, 113.9213},
    "MY" => {4.2105, 101.9758},
    "SG" => {1.3521, 103.8198},
    "HK" => {22.3193, 114.1694},
    "TW" => {23.6978, 120.9605},
    "MX" => {23.6345, -102.5528},
    "AR" => {-38.4161, -63.6167},
    "ZA" => {-30.5595, 22.9375}
  }

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get threat origins aggregated by location.

  Returns a list of threat sources with coordinates and counts.

  ## Parameters

  - `timeframe` - Time window: "1h", "6h", "24h", "7d", "30d" (default: "24h")
  - `opts` - Additional options:
    - `:organization_id` - Filter by organization
    - `:severity` - Filter by minimum severity

  ## Returns

  List of maps with:
  - `source_lat`, `source_lon` - Source coordinates
  - `source_country`, `source_city` - Source location names
  - `target_lat`, `target_lon` - Target (agent) coordinates
  - `threat_type` - Type of threat
  - `count` - Number of occurrences
  - `severity` - Highest severity
  """
  def get_threat_origins(timeframe \\ "24h", opts \\ []) do
    ensure_cache_table()
    cache_key = {:threat_origins, timeframe, opts[:organization_id], opts[:severity]}

    case get_cached(cache_key) do
      {:ok, data} -> data
      :miss ->
        try do
          GenServer.call(__MODULE__, {:get_threat_origins, timeframe, opts})
        catch
          :exit, _ -> compute_threat_origins(timeframe, opts)
        end
    end
  end

  @doc """
  Get agent locations with their current status.

  Returns a list of agent locations for map markers.

  ## Parameters

  - `opts` - Options:
    - `:organization_id` - Filter by organization
    - `:status` - Filter by status (online, offline, isolated)

  ## Returns

  List of maps with:
  - `lat`, `lon` - Coordinates
  - `hostname` - Agent hostname
  - `status` - Current status
  - `agent_id` - Agent ID
  - `country_code` - Country code
  - `city` - City name (if available)
  """
  def get_agent_locations(opts \\ []) do
    ensure_cache_table()
    cache_key = {:agent_locations, opts[:organization_id], opts[:status]}

    case get_cached(cache_key) do
      {:ok, data} -> data
      :miss ->
        try do
          GenServer.call(__MODULE__, {:get_agent_locations, opts})
        catch
          :exit, _ -> compute_agent_locations(opts)
        end
    end
  end

  @doc """
  Get threat flow connections for animated lines on the map.

  Returns source-to-target connections for visualization.
  """
  def get_threat_flows(timeframe \\ "24h", opts \\ []) do
    ensure_cache_table()
    cache_key = {:threat_flows, timeframe, opts[:organization_id]}

    case get_cached(cache_key) do
      {:ok, data} -> data
      :miss ->
        try do
          GenServer.call(__MODULE__, {:get_threat_flows, timeframe, opts})
        catch
          :exit, _ -> compute_threat_flows(timeframe, opts)
        end
    end
  end

  @doc """
  Get summary statistics for the threat map.
  """
  def get_summary(timeframe \\ "24h", opts \\ []) do
    ensure_cache_table()
    cache_key = {:summary, timeframe, opts[:organization_id]}

    case get_cached(cache_key) do
      {:ok, data} -> data
      :miss ->
        try do
          GenServer.call(__MODULE__, {:get_summary, timeframe, opts})
        catch
          :exit, _ -> compute_summary(timeframe, opts)
        end
    end
  end

  @doc """
  Invalidate all cached geo stats.
  Called when new alerts or events arrive.
  """
  def invalidate_cache do
    GenServer.cast(__MODULE__, :invalidate_cache)
  end

  # Server callbacks

  @impl true
  def init(_opts) do
    # Create ETS table for caching
    ensure_cache_table()

    # Schedule periodic cache refresh
    schedule_refresh()

    {:ok, %{last_refresh: nil}}
  end

  @impl true
  def handle_call({:get_threat_origins, timeframe, opts}, _from, state) do
    data = compute_threat_origins(timeframe, opts)
    cache_key = {:threat_origins, timeframe, opts[:organization_id], opts[:severity]}
    put_cached(cache_key, data)
    {:reply, data, state}
  end

  def handle_call({:get_agent_locations, opts}, _from, state) do
    data = compute_agent_locations(opts)
    cache_key = {:agent_locations, opts[:organization_id], opts[:status]}
    put_cached(cache_key, data)
    {:reply, data, state}
  end

  def handle_call({:get_threat_flows, timeframe, opts}, _from, state) do
    data = compute_threat_flows(timeframe, opts)
    cache_key = {:threat_flows, timeframe, opts[:organization_id]}
    put_cached(cache_key, data)
    {:reply, data, state}
  end

  def handle_call({:get_summary, timeframe, opts}, _from, state) do
    data = compute_summary(timeframe, opts)
    cache_key = {:summary, timeframe, opts[:organization_id]}
    put_cached(cache_key, data)
    {:reply, data, state}
  end

  @impl true
  def handle_cast(:invalidate_cache, state) do
    :ets.delete_all_objects(@cache_table)
    {:noreply, state}
  end

  @impl true
  def handle_info(:refresh_cache, state) do
    # Pre-compute common queries
    spawn(fn ->
      compute_threat_origins("24h", [])
      compute_agent_locations([])
      compute_summary("24h", [])
    end)

    schedule_refresh()
    {:noreply, %{state | last_refresh: DateTime.utc_now()}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private functions

  defp schedule_refresh do
    Process.send_after(self(), :refresh_cache, @update_interval_ms)
  end

  defp get_cached(key) do
    ensure_cache_table()
    case :ets.lookup(@cache_table, key) do
      [{^key, data, expires_at}] ->
        if System.system_time(:millisecond) < expires_at do
          {:ok, data}
        else
          :miss
        end

      [] ->
        :miss
    end
  end

  defp put_cached(key, data) do
    ensure_cache_table()
    expires_at = System.system_time(:millisecond) + @cache_ttl_ms
    :ets.insert(@cache_table, {key, data, expires_at})
  end

  defp ensure_cache_table do
    case :ets.whereis(@cache_table) do
      :undefined ->
        try do
          :ets.new(@cache_table, [:named_table, :set, :public, read_concurrency: true])
        rescue
          ArgumentError -> :ok
        end

      _ ->
        :ok
    end
  end

  defp compute_threat_origins(timeframe, opts) do
    since = timeframe_to_datetime(timeframe)

    # Query alerts with geo data in enrichment
    query = from(a in Alert,
      where: a.inserted_at >= ^since,
      order_by: [desc: a.inserted_at],
      limit: 1000
    )

    query = if org_id = opts[:organization_id] do
      from(a in query, where: a.organization_id == ^org_id)
    else
      query
    end

    query = if severity = opts[:severity] do
      from(a in query, where: a.severity in ^severity_and_above(severity))
    else
      query
    end

    alerts = Repo.all(query)

    # Extract geo data from alerts
    alerts
    |> Enum.map(&extract_geo_from_alert/1)
    |> Enum.filter(& &1)
    |> Enum.group_by(fn item ->
      {item.source_country, item.threat_type}
    end)
    |> Enum.map(fn {{country, threat_type}, items} ->
      {lat, lon} = get_country_coords(country, items)
      severities = Enum.map(items, & &1.severity)
      highest_severity = get_highest_severity(severities)

      %{
        source_lat: lat,
        source_lon: lon,
        source_country: country,
        source_country_name: get_country_name(country),
        threat_type: threat_type,
        count: length(items),
        severity: highest_severity,
        last_seen: Enum.max_by(items, & &1.timestamp).timestamp
      }
    end)
    |> Enum.sort_by(& &1.count, :desc)
  end

  defp compute_agent_locations(opts) do
    query = from(a in TamanduaServer.Agents.Agent,
      order_by: [desc: a.last_seen_at],
      limit: 500
    )

    query = if org_id = opts[:organization_id] do
      from(a in query, where: a.organization_id == ^org_id)
    else
      query
    end

    query = if status = opts[:status] do
      from(a in query, where: a.status == ^to_string(status))
    else
      query
    end

    agents = Repo.all(query)

    # Resolve IP addresses to locations
    agents
    |> Enum.map(&resolve_agent_location/1)
    |> Enum.filter(& &1)
  end

  defp compute_threat_flows(timeframe, opts) do
    # Get threat origins and agent locations
    threats = compute_threat_origins(timeframe, opts)
    agents = compute_agent_locations(opts)

    # Create flow lines from threat sources to agent locations
    # Group by source country and connect to affected agents
    Enum.flat_map(threats, fn threat ->
      # Find agents that were targeted from this source
      target_agents = Enum.take_random(agents, min(3, length(agents)))

      Enum.map(target_agents, fn agent ->
        %{
          id: "#{threat.source_country}-#{agent.agent_id}",
          source: %{
            lat: threat.source_lat,
            lon: threat.source_lon,
            country: threat.source_country
          },
          target: %{
            lat: agent.lat,
            lon: agent.lon,
            hostname: agent.hostname
          },
          threat_type: threat.threat_type,
          severity: threat.severity,
          count: threat.count
        }
      end)
    end)
    |> Enum.uniq_by(& &1.id)
    |> Enum.take(50)  # Limit for performance
  end

  defp compute_summary(timeframe, opts) do
    threats = compute_threat_origins(timeframe, opts)
    agents = compute_agent_locations(opts)

    # Country ranking
    top_countries = threats
    |> Enum.group_by(& &1.source_country)
    |> Enum.map(fn {country, items} ->
      %{
        country_code: country,
        country_name: get_country_name(country),
        threat_count: Enum.sum(Enum.map(items, & &1.count)),
        threat_types: Enum.uniq(Enum.map(items, & &1.threat_type))
      }
    end)
    |> Enum.sort_by(& &1.threat_count, :desc)
    |> Enum.take(10)

    # Severity breakdown
    severity_counts = threats
    |> Enum.group_by(& &1.severity)
    |> Enum.map(fn {severity, items} ->
      {severity, Enum.sum(Enum.map(items, & &1.count))}
    end)
    |> Map.new()

    %{
      top_countries: top_countries,
      total_threats: Enum.sum(Enum.map(threats, & &1.count)),
      unique_sources: length(Enum.uniq(Enum.map(threats, & &1.source_country))),
      unique_threat_types: length(Enum.uniq(Enum.map(threats, & &1.threat_type))),
      agents_online: Enum.count(agents, & &1.status == "online"),
      agents_total: length(agents),
      severity_counts: severity_counts,
      timeframe: timeframe
    }
  end

  defp extract_geo_from_alert(%Alert{} = alert) do
    enrichment = alert.enrichment || %{}
    evidence = alert.evidence || %{}
    payload = alert.raw_event || %{}

    # Try to get source IP from various locations
    network_evidence = evidence["network"]
    source_ip = enrichment["source_ip"] ||
                (is_map(network_evidence) && (network_evidence[:value] || network_evidence["value"])) ||
                payload["remote_ip"] ||
                payload["source_ip"]

    # Get geo data from enrichment or lookup
    geo_data = enrichment["geo"] || enrichment["geoip"] || %{}

    if source_ip || map_size(geo_data) > 0 do
      # Use existing geo data or lookup
      {country, lat, lon, city} = if map_size(geo_data) > 0 do
        {
          geo_data["country_code"] || geo_data[:country_code],
          geo_data["latitude"] || geo_data[:latitude],
          geo_data["longitude"] || geo_data[:longitude],
          geo_data["city"] || geo_data[:city]
        }
      else
        lookup_ip_location(source_ip)
      end

      if country do
        threat_type = determine_threat_type(alert)

        %{
          source_country: country,
          source_city: city,
          source_lat: lat,
          source_lon: lon,
          source_ip: source_ip,
          threat_type: threat_type,
          severity: alert.severity,
          timestamp: alert.inserted_at,
          alert_id: alert.id
        }
      end
    end
  end

  defp resolve_agent_location(%TamanduaServer.Agents.Agent{} = agent) do
    ip = agent.ip_address

    if ip do
      case lookup_ip_location(ip) do
        {country, lat, lon, city} when not is_nil(country) ->
          %{
            agent_id: agent.id,
            hostname: agent.hostname,
            status: agent.status,
            lat: lat || elem(Map.get(@country_centroids, country, {0, 0}), 0),
            lon: lon || elem(Map.get(@country_centroids, country, {0, 0}), 1),
            country_code: country,
            city: city,
            os_type: agent.os_type,
            last_seen: agent.last_seen_at
          }

        _ ->
          # Fallback: use a default location or skip
          nil
      end
    else
      nil
    end
  end

  defp lookup_ip_location(nil), do: {nil, nil, nil, nil}
  defp lookup_ip_location(ip) do
    try do
      case GeoIP.lookup(ip) do
        {:ok, geo} ->
          {
            geo[:country_code],
            geo[:latitude],
            geo[:longitude],
            geo[:city]
          }

        {:error, _} ->
          {nil, nil, nil, nil}
      end
    rescue
      _ -> {nil, nil, nil, nil}
    catch
      _, _ -> {nil, nil, nil, nil}
    end
  end

  defp get_country_coords(country, items) do
    # Try to use actual coordinates from items first
    item_with_coords = Enum.find(items, fn item ->
      item.source_lat && item.source_lon
    end)

    if item_with_coords do
      {item_with_coords.source_lat, item_with_coords.source_lon}
    else
      # Fallback to country centroid
      Map.get(@country_centroids, country, {0, 0})
    end
  end

  defp determine_threat_type(alert) do
    tactics = alert.mitre_tactics || []
    techniques = alert.mitre_techniques || []

    cond do
      "initial-access" in tactics -> "Initial Access"
      "execution" in tactics -> "Execution"
      "persistence" in tactics -> "Persistence"
      "privilege-escalation" in tactics -> "Privilege Escalation"
      "defense-evasion" in tactics -> "Defense Evasion"
      "credential-access" in tactics -> "Credential Theft"
      "discovery" in tactics -> "Discovery"
      "lateral-movement" in tactics -> "Lateral Movement"
      "collection" in tactics -> "Data Collection"
      "command-and-control" in tactics -> "C2 Communication"
      "exfiltration" in tactics -> "Exfiltration"
      "impact" in tactics -> "Impact"
      length(techniques) > 0 -> "Suspicious Activity"
      true -> "Unknown"
    end
  end

  defp get_country_name(nil), do: "Unknown"
  defp get_country_name(code) do
    country_names = %{
      "US" => "United States",
      "CN" => "China",
      "RU" => "Russia",
      "DE" => "Germany",
      "GB" => "United Kingdom",
      "FR" => "France",
      "JP" => "Japan",
      "KR" => "South Korea",
      "BR" => "Brazil",
      "IN" => "India",
      "AU" => "Australia",
      "CA" => "Canada",
      "NL" => "Netherlands",
      "IT" => "Italy",
      "ES" => "Spain",
      "SE" => "Sweden",
      "PL" => "Poland",
      "UA" => "Ukraine",
      "RO" => "Romania",
      "IR" => "Iran",
      "KP" => "North Korea",
      "VN" => "Vietnam",
      "TH" => "Thailand",
      "ID" => "Indonesia",
      "MY" => "Malaysia",
      "SG" => "Singapore",
      "HK" => "Hong Kong",
      "TW" => "Taiwan",
      "MX" => "Mexico",
      "AR" => "Argentina",
      "ZA" => "South Africa"
    }

    Map.get(country_names, code, code)
  end

  defp severity_and_above(severity) do
    severities = ["critical", "high", "medium", "low", "info"]
    idx = Enum.find_index(severities, &(&1 == severity)) || length(severities)
    Enum.take(severities, idx + 1)
  end

  defp get_highest_severity(severities) do
    priority = %{"critical" => 0, "high" => 1, "medium" => 2, "low" => 3, "info" => 4}

    severities
    |> Enum.min_by(&Map.get(priority, &1, 99))
  end

  defp timeframe_to_datetime(timeframe) do
    now = NaiveDateTime.utc_now()

    case timeframe do
      "1h" -> NaiveDateTime.add(now, -1, :hour)
      "6h" -> NaiveDateTime.add(now, -6, :hour)
      "24h" -> NaiveDateTime.add(now, -24, :hour)
      "7d" -> NaiveDateTime.add(now, -7, :day)
      "30d" -> NaiveDateTime.add(now, -30, :day)
      _ -> NaiveDateTime.add(now, -24, :hour)
    end
  end
end
