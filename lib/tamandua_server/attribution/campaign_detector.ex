defmodule TamanduaServer.Attribution.CampaignDetector do
  @moduledoc """
  Campaign Detector

  Clusters alerts into campaigns using DBSCAN algorithm.
  Correlates alerts based on temporal, spatial, IOC, and TTP similarity.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Alerts
  alias TamanduaServer.Repo

  @scan_interval 300_000  # 5 minutes
  @time_window_hours 24
  @min_alerts_for_campaign 3

  # DBSCAN parameters
  @epsilon 0.3  # Distance threshold
  @min_points 3  # Minimum points for cluster

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Detect campaigns from recent alerts
  """
  def detect_campaigns(opts \\ []) do
    GenServer.call(__MODULE__, {:detect_campaigns, opts}, 60_000)
  end

  @doc """
  Get campaign by ID
  """
  def get_campaign(campaign_id) do
    GenServer.call(__MODULE__, {:get_campaign, campaign_id})
  end

  @doc """
  List all active campaigns
  """
  def list_campaigns do
    GenServer.call(__MODULE__, :list_campaigns)
  end

  @doc """
  Add alert to existing campaign
  """
  def add_to_campaign(alert_id, campaign_id) do
    GenServer.cast(__MODULE__, {:add_to_campaign, alert_id, campaign_id})
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    Logger.info("Starting Campaign Detector")

    state = %{
      campaigns: %{},
      campaign_index: %{}  # alert_id -> campaign_id
    }

    # Schedule periodic detection
    schedule_detection()

    {:ok, state}
  end

  @impl true
  def handle_call({:detect_campaigns, opts}, _from, state) do
    time_window = Keyword.get(opts, :time_window_hours, @time_window_hours)

    case do_detect_campaigns(time_window) do
      {:ok, campaigns} ->
        new_state = merge_campaigns(state, campaigns)
        {:reply, {:ok, campaigns}, new_state}

      {:error, reason} = error ->
        Logger.error("Campaign detection failed: #{inspect(reason)}")
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:get_campaign, campaign_id}, _from, state) do
    campaign = Map.get(state.campaigns, campaign_id)
    {:reply, campaign, state}
  end

  @impl true
  def handle_call(:list_campaigns, _from, state) do
    campaigns = Map.values(state.campaigns)
    {:reply, campaigns, state}
  end

  @impl true
  def handle_cast({:add_to_campaign, alert_id, campaign_id}, state) do
    new_state = add_alert_to_campaign(state, alert_id, campaign_id)
    {:noreply, new_state}
  end

  @impl true
  def handle_info(:detect_campaigns, state) do
    Task.start(fn ->
      detect_campaigns(time_window_hours: @time_window_hours)
    end)

    schedule_detection()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp do_detect_campaigns(time_window_hours) do
    cutoff_time = DateTime.add(DateTime.utc_now(), -time_window_hours * 3600, :second)

    with {:ok, alerts} <- load_recent_alerts(cutoff_time),
         {:ok, distance_matrix} <- compute_distance_matrix(alerts),
         {:ok, clusters} <- dbscan_clustering(distance_matrix, @epsilon, @min_points) do
      campaigns = build_campaigns(alerts, clusters)
      {:ok, campaigns}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp load_recent_alerts(cutoff_time) do
    # Load alerts from DB
    # This is a simplified version - in production, use Ecto query
    alerts = []  # Placeholder

    {:ok, alerts}
  end

  defp compute_distance_matrix(alerts) do
    n = length(alerts)
    matrix = for i <- 0..(n-1), j <- 0..(n-1), into: %{} do
      {{i, j}, compute_alert_distance(Enum.at(alerts, i), Enum.at(alerts, j))}
    end

    {:ok, matrix}
  end

  defp compute_alert_distance(alert1, alert2) do
    # Compute similarity distance (0 = identical, 1 = completely different)

    # Temporal distance (normalized)
    temporal_dist = temporal_distance(alert1, alert2)

    # Spatial distance (same organization/region)
    spatial_dist = spatial_distance(alert1, alert2)

    # IOC overlap (IPs, domains, hashes)
    ioc_dist = ioc_distance(alert1, alert2)

    # TTP overlap (MITRE techniques)
    ttp_dist = ttp_distance(alert1, alert2)

    # Tool overlap
    tool_dist = tool_distance(alert1, alert2)

    # Weighted combination
    weights = %{
      temporal: 0.15,
      spatial: 0.15,
      ioc: 0.30,
      ttp: 0.25,
      tool: 0.15
    }

    weights.temporal * temporal_dist +
    weights.spatial * spatial_dist +
    weights.ioc * ioc_dist +
    weights.ttp * ttp_dist +
    weights.tool * tool_dist
  end

  defp temporal_distance(alert1, alert2) do
    # Distance based on time difference
    time_diff_seconds = abs(DateTime.diff(alert1.inserted_at, alert2.inserted_at, :second))
    max_time_diff = @time_window_hours * 3600

    # Normalize to [0, 1]
    min(time_diff_seconds / max_time_diff, 1.0)
  end

  defp spatial_distance(alert1, alert2) do
    cond do
      alert1.agent_id == alert2.agent_id -> 0.0  # Same endpoint
      alert1.organization_id == alert2.organization_id -> 0.3  # Same org
      alert1.organization_region == alert2.organization_region -> 0.6  # Same region
      true -> 1.0  # Different
    end
  end

  defp ioc_distance(alert1, alert2) do
    # Compute Jaccard distance for IOC sets

    iocs1 = extract_iocs(alert1)
    iocs2 = extract_iocs(alert2)

    if MapSet.size(iocs1) == 0 and MapSet.size(iocs2) == 0 do
      1.0  # No IOCs to compare
    else
      intersection = MapSet.intersection(iocs1, iocs2) |> MapSet.size()
      union = MapSet.union(iocs1, iocs2) |> MapSet.size()

      # Jaccard distance = 1 - Jaccard similarity
      1.0 - (intersection / union)
    end
  end

  defp extract_iocs(alert) do
    iocs = MapSet.new()

    # Add IPs
    iocs = if alert.src_ip, do: MapSet.put(iocs, {:ip, alert.src_ip}), else: iocs
    iocs = if alert.dst_ip, do: MapSet.put(iocs, {:ip, alert.dst_ip}), else: iocs

    # Add domains
    iocs = if alert.domain, do: MapSet.put(iocs, {:domain, alert.domain}), else: iocs

    # Add hashes
    iocs = if alert.file_hash, do: MapSet.put(iocs, {:hash, alert.file_hash}), else: iocs

    # Add registry keys
    iocs = if alert.registry_key, do: MapSet.put(iocs, {:registry, alert.registry_key}), else: iocs

    iocs
  end

  defp ttp_distance(alert1, alert2) do
    ttps1 = MapSet.new(alert1.mitre_techniques || [])
    ttps2 = MapSet.new(alert2.mitre_techniques || [])

    if MapSet.size(ttps1) == 0 and MapSet.size(ttps2) == 0 do
      1.0
    else
      intersection = MapSet.intersection(ttps1, ttps2) |> MapSet.size()
      union = MapSet.union(ttps1, ttps2) |> MapSet.size()
      1.0 - (intersection / union)
    end
  end

  defp tool_distance(alert1, alert2) do
    # Extract tools from process names and command lines
    tools1 = extract_tools(alert1)
    tools2 = extract_tools(alert2)

    if MapSet.size(tools1) == 0 and MapSet.size(tools2) == 0 do
      1.0
    else
      intersection = MapSet.intersection(tools1, tools2) |> MapSet.size()
      union = MapSet.union(tools1, tools2) |> MapSet.size()
      1.0 - (intersection / union)
    end
  end

  defp extract_tools(alert) do
    tools = MapSet.new()

    if alert.process_name do
      process_lower = String.downcase(alert.process_name)
      known_tools = ["mimikatz", "powershell", "psexec", "wmic", "cmd"]

      tools = Enum.reduce(known_tools, tools, fn tool, acc ->
        if String.contains?(process_lower, tool), do: MapSet.put(acc, tool), else: acc
      end)
    end

    tools
  end

  defp dbscan_clustering(distance_matrix, epsilon, min_points) do
    n = distance_matrix |> Map.keys() |> Enum.map(&elem(&1, 0)) |> Enum.max() |> Kernel.+(1)

    # Initialize all points as unvisited
    visited = MapSet.new()
    clusters = []
    noise = []
    current_cluster_id = 0

    {clusters, _noise, _visited} =
      Enum.reduce(0..(n-1), {clusters, noise, visited}, fn point_idx, {cls, nse, vis} ->
        if MapSet.member?(vis, point_idx) do
          {cls, nse, vis}
        else
          vis = MapSet.put(vis, point_idx)
          neighbors = find_neighbors(point_idx, distance_matrix, epsilon, n)

          if length(neighbors) < min_points do
            # Mark as noise
            {cls, [point_idx | nse], vis}
          else
            # Start new cluster
            {cluster, vis_new} = expand_cluster(
              point_idx,
              neighbors,
              distance_matrix,
              epsilon,
              min_points,
              vis,
              n
            )

            {[%{id: current_cluster_id, points: cluster} | cls], nse, vis_new}
          end
        end
      end)

    {:ok, clusters}
  end

  defp find_neighbors(point_idx, distance_matrix, epsilon, n) do
    Enum.filter(0..(n-1), fn other_idx ->
      point_idx != other_idx and Map.get(distance_matrix, {point_idx, other_idx}, 1.0) <= epsilon
    end)
  end

  defp expand_cluster(point_idx, neighbors, distance_matrix, epsilon, min_points, visited, n) do
    cluster = [point_idx]

    {cluster, visited} =
      Enum.reduce(neighbors, {cluster, visited}, fn neighbor_idx, {cls, vis} ->
        if MapSet.member?(vis, neighbor_idx) do
          {cls, vis}
        else
          vis = MapSet.put(vis, neighbor_idx)
          neighbor_neighbors = find_neighbors(neighbor_idx, distance_matrix, epsilon, n)

          if length(neighbor_neighbors) >= min_points do
            # Add to cluster and continue expansion
            {[neighbor_idx | cls], vis}
          else
            {[neighbor_idx | cls], vis}
          end
        end
      end)

    {cluster, visited}
  end

  defp build_campaigns(alerts, clusters) do
    Enum.map(clusters, fn cluster ->
      alert_indices = cluster.points
      campaign_alerts = Enum.map(alert_indices, &Enum.at(alerts, &1))

      %{
        id: UUID.uuid4(),
        cluster_id: cluster.id,
        alerts: campaign_alerts,
        alert_ids: Enum.map(campaign_alerts, & &1.id),
        alert_count: length(campaign_alerts),
        start_time: campaign_alerts |> Enum.map(& &1.inserted_at) |> Enum.min(DateTime),
        end_time: campaign_alerts |> Enum.map(& &1.inserted_at) |> Enum.max(DateTime),
        ttps: campaign_alerts |> Enum.flat_map(& &1.mitre_techniques || []) |> Enum.uniq(),
        affected_agents: campaign_alerts |> Enum.map(& &1.agent_id) |> Enum.uniq(),
        threat_actor: nil,  # Will be filled by attribution
        confidence: nil,
        created_at: DateTime.utc_now()
      }
    end)
    |> Enum.filter(&(&1.alert_count >= @min_alerts_for_campaign))
  end

  defp merge_campaigns(state, new_campaigns) do
    # Merge new campaigns with existing ones
    campaigns_map =
      Enum.reduce(new_campaigns, state.campaigns, fn campaign, acc ->
        Map.put(acc, campaign.id, campaign)
      end)

    # Update campaign index
    campaign_index =
      Enum.reduce(new_campaigns, state.campaign_index, fn campaign, acc ->
        Enum.reduce(campaign.alert_ids, acc, fn alert_id, idx ->
          Map.put(idx, alert_id, campaign.id)
        end)
      end)

    %{state | campaigns: campaigns_map, campaign_index: campaign_index}
  end

  defp add_alert_to_campaign(state, alert_id, campaign_id) do
    campaign = Map.get(state.campaigns, campaign_id)

    if campaign do
      updated_campaign = %{
        campaign
        | alert_ids: [alert_id | campaign.alert_ids],
          alert_count: campaign.alert_count + 1
      }

      campaigns = Map.put(state.campaigns, campaign_id, updated_campaign)
      campaign_index = Map.put(state.campaign_index, alert_id, campaign_id)

      %{state | campaigns: campaigns, campaign_index: campaign_index}
    else
      state
    end
  end

  defp schedule_detection do
    Process.send_after(self(), :detect_campaigns, @scan_interval)
  end
end
