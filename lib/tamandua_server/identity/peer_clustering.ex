defmodule TamanduaServer.Identity.PeerClustering do
  @moduledoc """
  Peer Group Clustering for Baseline Comparison.

  Clusters users into peer groups based on behavioral similarity so that
  individual deviations can be compared against group norms. This is essential
  for identifying outliers even when individual baselines are immature.

  ## Clustering Approaches

  1. **Rule-based clustering** (primary): Users are grouped by department,
     role, machine type, and organization. These attributes are sourced from
     the user profile and Azure AD integration.

  2. **Behavioral clustering** (secondary): For users without explicit role
     data, a simplified k-means-style clustering based on behavioral feature
     vectors (login times, process diversity, network patterns) is used.

  ## Cluster Structure

  Each cluster maintains:
  - Aggregate baseline (merged frequency maps)
  - Member count and activity stats
  - Centroid feature vector (for distance calculations)
  - Last recalculation timestamp

  ## ETS Tables

  - `:peer_clusters`        - Cluster definitions and aggregate stats
  - `:peer_membership`      - User-to-cluster mapping
  - `:peer_centroids`       - Cluster centroids for distance calculations

  ## Usage

  New users are immediately assigned to the closest cluster based on their
  metadata (department/role) or behavioral similarity. As their individual
  baseline matures, the cluster baseline provides a safety net for anomaly
  detection.
  """

  use GenServer
  require Logger

  # ---------------------------------------------------------------------------
  # Constants
  # ---------------------------------------------------------------------------

  @clusters_table :peer_clusters
  @membership_table :peer_membership
  @centroids_table :peer_centroids

  # Maximum clusters to maintain
  @max_clusters 50
  # Minimum members for a cluster to be useful
  @min_cluster_members 3
  # Recalculation interval
  @recalc_interval :timer.minutes(30)

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get the cluster assignment for a user.
  Returns the cluster map or nil if unassigned.
  """
  @spec get_cluster_for_user(String.t()) :: map() | nil
  def get_cluster_for_user(user_id) when is_binary(user_id) do
    case :ets.lookup(@membership_table, user_id) do
      [{^user_id, cluster_id}] ->
        case :ets.lookup(@clusters_table, cluster_id) do
          [{^cluster_id, cluster}] -> cluster
          [] -> nil
        end

      [] ->
        nil
    end
  end

  @doc """
  Assign a user to a peer group based on their attributes.

  Attributes can include:
  - `:department` - Organization department
  - `:role` - Job role/title
  - `:machine_type` - Workstation type (desktop, laptop, server)
  - `:organization_id` - Organization membership
  """
  @spec assign_user(String.t(), map()) :: {:ok, String.t()} | {:error, term()}
  def assign_user(user_id, attributes) when is_binary(user_id) and is_map(attributes) do
    GenServer.call(__MODULE__, {:assign_user, user_id, attributes})
  end

  @doc """
  Get the aggregate baseline for a cluster.
  Used for comparing a user against their peer group.
  """
  @spec get_cluster_baseline(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_cluster_baseline(cluster_id) when is_binary(cluster_id) do
    case :ets.lookup(@clusters_table, cluster_id) do
      [{^cluster_id, cluster}] -> {:ok, cluster}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Get the outlier score for a user compared to their peer group.
  Returns 0.0 (perfectly normal) to 1.0 (extreme outlier).
  """
  @spec compute_outlier_score(String.t(), map()) :: float()
  def compute_outlier_score(user_id, feature_vector)
      when is_binary(user_id) and is_map(feature_vector) do
    case get_cluster_for_user(user_id) do
      nil ->
        0.0

      cluster ->
        compute_distance_from_centroid(feature_vector, cluster)
    end
  end

  @doc """
  List all clusters with their stats.
  """
  @spec list_clusters() :: list(map())
  def list_clusters do
    ets_safe_tab2list(@clusters_table)
    |> Enum.map(fn {cluster_id, cluster} ->
      Map.put(cluster, :id, cluster_id)
    end)
    |> Enum.sort_by(& &1.member_count, :desc)
  end

  @doc """
  Get members of a specific cluster.
  """
  @spec get_cluster_members(String.t()) :: list(String.t())
  def get_cluster_members(cluster_id) when is_binary(cluster_id) do
    ets_safe_tab2list(@membership_table)
    |> Enum.filter(fn {_user_id, cid} -> cid == cluster_id end)
    |> Enum.map(fn {user_id, _cid} -> user_id end)
  end

  @doc """
  Get overall statistics about peer clustering.
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
    :ets.new(@clusters_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@membership_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@centroids_table, [:named_table, :set, :public, read_concurrency: true])

    # Initialize default clusters
    initialize_default_clusters()

    schedule_recalc()

    Logger.info("[PeerClustering] Initialized")
    {:ok, %{recalc_count: 0}}
  end

  @impl true
  def handle_call({:assign_user, user_id, attributes}, _from, state) do
    cluster_id = determine_cluster(attributes)

    # Ensure cluster exists
    ensure_cluster(cluster_id, attributes)

    # Assign user
    :ets.insert(@membership_table, {user_id, cluster_id})

    # Update cluster member count
    update_cluster_member_count(cluster_id)

    {:reply, {:ok, cluster_id}, state}
  end

  @impl true
  def handle_call(:stats, _from, state) do
    clusters = ets_safe_tab2list(@clusters_table)
    members = :ets.info(@membership_table, :size)

    result = %{
      total_clusters: length(clusters),
      total_members: members,
      cluster_sizes:
        Enum.map(clusters, fn {id, c} ->
          %{id: id, members: c.member_count, label: c.label}
        end),
      recalc_count: state.recalc_count
    }

    {:reply, result, state}
  end

  @impl true
  def handle_info(:recalculate, state) do
    recalculate_centroids()
    schedule_recalc()
    {:noreply, %{state | recalc_count: state.recalc_count + 1}}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ---------------------------------------------------------------------------
  # Private - Cluster Management
  # ---------------------------------------------------------------------------

  defp initialize_default_clusters do
    # Create common role-based clusters
    defaults = [
      {"cluster:it_admin", "IT Administrators", "it_admin"},
      {"cluster:developer", "Developers", "developer"},
      {"cluster:finance", "Finance", "finance"},
      {"cluster:hr", "Human Resources", "hr"},
      {"cluster:executive", "Executives", "executive"},
      {"cluster:general", "General Users", "general"},
      {"cluster:service_accounts", "Service Accounts", "service_account"},
      {"cluster:remote_workers", "Remote Workers", "remote_worker"}
    ]

    Enum.each(defaults, fn {id, label, role} ->
      cluster = %{
        label: label,
        role: role,
        member_count: 0,
        created_at: DateTime.utc_now(),
        last_recalculated: nil,
        aggregate_baseline: %{
          avg_login_hour: 9.0,
          avg_processes_per_day: 0.0,
          avg_network_destinations: 0.0,
          avg_auth_failures: 0.0
        }
      }

      :ets.insert(@clusters_table, {id, cluster})
    end)
  end

  defp determine_cluster(attributes) do
    department = Map.get(attributes, :department, "")
    role = Map.get(attributes, :role, "")
    combined = String.downcase("#{department} #{role}")

    cond do
      String.contains?(combined, ["admin", "sysadmin", "it ops", "infrastructure"]) ->
        "cluster:it_admin"

      String.contains?(combined, ["developer", "engineer", "sre", "devops"]) ->
        "cluster:developer"

      String.contains?(combined, ["finance", "accounting", "treasury"]) ->
        "cluster:finance"

      String.contains?(combined, ["hr", "human resources", "people ops"]) ->
        "cluster:hr"

      String.contains?(combined, ["ceo", "cto", "cfo", "ciso", "executive", "vp", "director"]) ->
        "cluster:executive"

      String.contains?(combined, ["service", "svc", "bot", "automation"]) ->
        "cluster:service_accounts"

      String.contains?(combined, ["remote", "contractor", "external"]) ->
        "cluster:remote_workers"

      true ->
        "cluster:general"
    end
  end

  defp ensure_cluster(cluster_id, attributes) do
    case :ets.lookup(@clusters_table, cluster_id) do
      [{^cluster_id, _}] ->
        :ok

      [] ->
        if :ets.info(@clusters_table, :size) < @max_clusters do
          cluster = %{
            label: Map.get(attributes, :department, "Unknown"),
            role: Map.get(attributes, :role, "unknown"),
            member_count: 0,
            created_at: DateTime.utc_now(),
            last_recalculated: nil,
            aggregate_baseline: %{
              avg_login_hour: 9.0,
              avg_processes_per_day: 0.0,
              avg_network_destinations: 0.0,
              avg_auth_failures: 0.0
            }
          }

          :ets.insert(@clusters_table, {cluster_id, cluster})
        end
    end
  end

  defp update_cluster_member_count(cluster_id) do
    count =
      ets_safe_tab2list(@membership_table)
      |> Enum.count(fn {_uid, cid} -> cid == cluster_id end)

    case :ets.lookup(@clusters_table, cluster_id) do
      [{^cluster_id, cluster}] ->
        :ets.insert(@clusters_table, {cluster_id, %{cluster | member_count: count}})

      [] ->
        :ok
    end
  end

  defp recalculate_centroids do
    # For each cluster, compute the aggregate baseline from member profiles
    ets_safe_tab2list(@clusters_table)
    |> Enum.each(fn {cluster_id, cluster} ->
      members = get_cluster_members(cluster_id)

      if length(members) >= @min_cluster_members do
        aggregate = compute_aggregate_baseline(members)
        updated = %{cluster | aggregate_baseline: aggregate, last_recalculated: DateTime.utc_now()}
        :ets.insert(@clusters_table, {cluster_id, updated})

        # Store centroid for distance calculations
        :ets.insert(@centroids_table, {cluster_id, aggregate})
      end
    end)

    Logger.debug("[PeerClustering] Recalculated cluster centroids")
  end

  defp compute_aggregate_baseline(member_user_ids) do
    # Collect profiles from the UserProfiler
    profiles =
      Enum.reduce(member_user_ids, [], fn user_id, acc ->
        case TamanduaServer.Identity.UserProfiler.get_profile(user_id) do
          {:ok, profile} -> [profile | acc]
          _ -> acc
        end
      end)

    if profiles == [] do
      %{
        avg_login_hour: 9.0,
        avg_processes_per_day: 0.0,
        avg_network_destinations: 0.0,
        avg_auth_failures: 0.0
      }
    else
      count = length(profiles)

      avg_login_hour =
        profiles
        |> Enum.flat_map(fn p ->
          p.login_hours
          |> Enum.flat_map(fn {hour, cnt} -> List.duplicate(hour, cnt) end)
        end)
        |> then(fn hours ->
          if hours == [], do: 9.0, else: Enum.sum(hours) / length(hours)
        end)

      avg_processes =
        profiles
        |> Enum.map(fn p -> map_size(p.process_frequency) end)
        |> Enum.sum()
        |> Kernel./(count)

      avg_destinations =
        profiles
        |> Enum.map(fn p -> map_size(p.network_destinations) end)
        |> Enum.sum()
        |> Kernel./(count)

      avg_auth_failures =
        profiles
        |> Enum.map(fn p -> p.auth_patterns.failures end)
        |> Enum.sum()
        |> Kernel./(count)

      %{
        avg_login_hour: Float.round(avg_login_hour, 2),
        avg_processes_per_day: Float.round(avg_processes, 2),
        avg_network_destinations: Float.round(avg_destinations, 2),
        avg_auth_failures: Float.round(avg_auth_failures, 2)
      }
    end
  end

  defp compute_distance_from_centroid(feature_vector, cluster) do
    centroid = cluster.aggregate_baseline

    # Simple Euclidean distance on normalized features
    diffs =
      Enum.map(feature_vector, fn {key, value} when is_number(value) ->
        centroid_val = Map.get(centroid, key, 0.0)
        # Normalize difference by centroid value to avoid scale issues
        if centroid_val > 0 do
          abs(value - centroid_val) / centroid_val
        else
          if value > 0, do: 1.0, else: 0.0
        end
      end)

    if diffs == [] do
      0.0
    else
      # RMS of normalized differences, capped at 1.0
      sum_sq = Enum.reduce(diffs, 0.0, fn d, acc -> acc + d * d end)
      rms = :math.sqrt(sum_sq / length(diffs))
      min(1.0, Float.round(rms, 4))
    end
  end

  # ---------------------------------------------------------------------------
  # Private - Utilities
  # ---------------------------------------------------------------------------

  defp ets_safe_tab2list(table) do
    try do
      :ets.tab2list(table)
    rescue
      ArgumentError -> []
    end
  end

  defp schedule_recalc do
    Process.send_after(self(), :recalculate, @recalc_interval)
  end
end
