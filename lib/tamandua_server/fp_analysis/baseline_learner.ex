defmodule TamanduaServer.FPAnalysis.BaselineLearner do
  @moduledoc """
  Environment Baseline Learner for FP Analysis.

  Learns what is "normal" for an organization, agent group, or specific agent
  to help distinguish false positives from true positives.

  Unlike the behavioral baseline learner in Detection, this module focuses on
  detection-specific baselines:

  - Which rules commonly fire (expected detections)
  - What severity distribution is normal
  - What time patterns are normal for alerts
  - Which processes/paths commonly trigger detections

  ## Usage

      # Start learning baseline for an organization
      BaselineLearner.start_learning("org-123", :organization)

      # Check if a detection is expected based on baseline
      BaselineLearner.is_expected_detection?("org-123", rule_id, context)

      # Get anomaly score for a detection
      score = BaselineLearner.get_detection_anomaly_score("org-123", detection)
  """

  use GenServer
  require Logger

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.FPAnalysis.BaselineProfile

  # Learning period
  @default_learning_days 7

  # Update interval
  @update_interval :timer.hours(1)

  # ETS table for fast baseline lookups
  @baseline_cache :fp_baseline_cache

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Start learning baseline for an entity.
  """
  @spec start_learning(String.t(), atom(), String.t() | nil) ::
          {:ok, BaselineProfile.t()} | {:error, term()}
  def start_learning(entity_key, entity_type, organization_id \\ nil) do
    GenServer.call(__MODULE__, {:start_learning, entity_key, entity_type, organization_id})
  end

  @doc """
  Get the baseline profile for an entity.
  """
  @spec get_baseline(String.t(), atom(), String.t() | nil) :: BaselineProfile.t() | nil
  def get_baseline(entity_key, entity_type, organization_id \\ nil) do
    cache_key = {organization_id, entity_type, entity_key}

    case :ets.lookup(@baseline_cache, cache_key) do
      [{^cache_key, profile}] -> profile
      [] -> fetch_and_cache_baseline(organization_id, entity_type, entity_key)
    end
  rescue
    _ -> nil
  end

  @doc """
  Check if a detection is expected based on the baseline.
  """
  @spec is_expected_detection?(String.t(), String.t(), map()) :: boolean()
  def is_expected_detection?(organization_id, rule_id, _context \\ %{}) do
    # Check organization baseline
    case get_baseline(organization_id, :organization, organization_id) do
      nil ->
        false

      profile ->
        # Rule is in expected rules list
        BaselineProfile.rule_expected?(profile, rule_id)
    end
  end

  @doc """
  Get anomaly score for a detection (0.0 = normal, 1.0 = highly anomalous).
  """
  @spec get_detection_anomaly_score(String.t(), map()) :: float()
  def get_detection_anomaly_score(organization_id, detection) do
    profile = get_baseline(organization_id, :organization, organization_id)

    if profile && profile.status == "active" do
      scores = []

      # Check if rule is expected
      rule_id = detection[:rule_id] || detection["rule_id"]

      scores =
        if rule_id do
          rule_score = if BaselineProfile.rule_expected?(profile, rule_id), do: 0.0, else: 0.6
          [rule_score | scores]
        else
          scores
        end

      # Check if process is normal
      process_name = detection[:process_name] || detection["process_name"]

      scores =
        if process_name do
          process_score = if BaselineProfile.process_in_baseline?(profile, process_name), do: 0.0, else: 0.5
          [process_score | scores]
        else
          scores
        end

      # Check time of day
      hour = DateTime.utc_now().hour
      time_score = calculate_time_anomaly(profile, hour)
      scores = [time_score | scores]

      # Average scores
      if length(scores) > 0 do
        Enum.sum(scores) / length(scores)
      else
        0.5
      end
    else
      0.5  # Neutral score when no baseline
    end
  end

  @doc """
  Update baseline with a new detection event.
  """
  @spec record_detection(String.t(), map()) :: :ok
  def record_detection(organization_id, detection) do
    GenServer.cast(__MODULE__, {:record_detection, organization_id, detection})
  end

  @doc """
  Manually complete learning for an entity.
  """
  @spec complete_learning(String.t(), atom(), String.t() | nil) ::
          {:ok, BaselineProfile.t()} | {:error, term()}
  def complete_learning(entity_key, entity_type, organization_id \\ nil) do
    GenServer.call(__MODULE__, {:complete_learning, entity_key, entity_type, organization_id})
  end

  @doc """
  Get baseline statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ---------------------------------------------------------------------------
  # GenServer Callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    # Create ETS cache table
    :ets.new(@baseline_cache, [:named_table, :set, :public, {:read_concurrency, true}])

    # Load existing baselines into cache
    load_baselines_to_cache()

    # Schedule periodic updates
    schedule_baseline_update()

    Logger.info("[FP.BaselineLearner] Initialized")
    {:ok, %{}}
  end

  @impl true
  def handle_call({:start_learning, entity_key, entity_type, organization_id}, _from, state) do
    result = do_start_learning(entity_key, entity_type, organization_id)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:complete_learning, entity_key, entity_type, organization_id}, _from, state) do
    result = do_complete_learning(entity_key, entity_type, organization_id)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = calculate_stats()
    {:reply, stats, state}
  end

  @impl true
  def handle_cast({:record_detection, organization_id, detection}, state) do
    do_record_detection(organization_id, detection)
    {:noreply, state}
  end

  @impl true
  def handle_info(:update_baselines, state) do
    update_all_baselines()
    check_learning_completions()
    schedule_baseline_update()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ---------------------------------------------------------------------------
  # Private - Learning Management
  # ---------------------------------------------------------------------------

  defp do_start_learning(entity_key, entity_type, organization_id) do
    attrs = %{
      organization_id: organization_id,
      profile_type: to_string(entity_type),
      profile_key: entity_key,
      profile_name: "#{entity_type}: #{entity_key}",
      status: "learning",
      learning_started_at: DateTime.utc_now(),
      learning_days: @default_learning_days
    }

    case %BaselineProfile{}
         |> BaselineProfile.changeset(attrs)
         |> Repo.insert(
           on_conflict: :nothing,
           conflict_target: [:organization_id, :profile_type, :profile_key]
         ) do
      {:ok, profile} ->
        cache_baseline(profile)
        {:ok, profile}

      {:error, changeset} ->
        # Might already exist
        case fetch_baseline(organization_id, entity_type, entity_key) do
          nil -> {:error, changeset}
          profile -> {:ok, profile}
        end
    end
  end

  defp do_complete_learning(entity_key, entity_type, organization_id) do
    case fetch_baseline(organization_id, entity_type, entity_key) do
      nil ->
        {:error, :not_found}

      profile ->
        profile
        |> BaselineProfile.changeset(%{
          status: "active",
          learning_completed_at: DateTime.utc_now()
        })
        |> Repo.update()
        |> case do
          {:ok, updated} ->
            cache_baseline(updated)
            {:ok, updated}

          error ->
            error
        end
    end
  end

  defp do_record_detection(organization_id, detection) do
    profile = get_baseline(organization_id, :organization, organization_id)

    if profile && profile.status == "learning" do
      # Extract detection info
      rule_id = detection[:rule_id] || detection["rule_id"]
      rule_name = detection[:rule_name] || detection["rule_name"]
      process_name = detection[:process_name] || detection["process_name"]
      severity = detection[:severity] || detection["severity"]

      updates = %{
        total_events_processed: (profile.total_events_processed || 0) + 1,
        last_updated_at: DateTime.utc_now()
      }

      # Update expected rules
      updates = if rule_id do
        expected_rules = Enum.uniq([rule_id | (profile.expected_rules || [])])
        rule_freqs = Map.update(profile.rule_frequencies || %{}, rule_id, 1, &(&1 + 1))
        Map.merge(updates, %{expected_rules: expected_rules, rule_frequencies: rule_freqs})
      else
        updates
      end

      # Update normal processes
      updates = if process_name do
        normal_procs = Enum.uniq([process_name | (profile.normal_processes || [])]) |> Enum.take(500)
        proc_freqs = Map.update(profile.process_frequencies || %{}, process_name, 1, &(&1 + 1))
        Map.merge(updates, %{normal_processes: normal_procs, process_frequencies: proc_freqs})
      else
        updates
      end

      # Update time histogram
      hour = DateTime.utc_now().hour
      hour_hist = Map.update(profile.events_per_hour_histogram || %{}, to_string(hour), 1, &(&1 + 1))
      updates = Map.put(updates, :events_per_hour_histogram, hour_hist)

      profile
      |> BaselineProfile.changeset(updates)
      |> Repo.update()
      |> case do
        {:ok, updated} -> cache_baseline(updated)
        _ -> :ok
      end
    end
  rescue
    e ->
      Logger.warning("[FP.BaselineLearner] Failed to record detection: #{Exception.message(e)}")
  end

  # ---------------------------------------------------------------------------
  # Private - Baseline Management
  # ---------------------------------------------------------------------------

  defp fetch_baseline(organization_id, entity_type, entity_key) do
    Repo.get_by(BaselineProfile,
      organization_id: organization_id,
      profile_type: to_string(entity_type),
      profile_key: entity_key
    )
  end

  defp fetch_and_cache_baseline(organization_id, entity_type, entity_key) do
    case fetch_baseline(organization_id, entity_type, entity_key) do
      nil -> nil
      profile ->
        cache_baseline(profile)
        profile
    end
  end

  defp cache_baseline(%BaselineProfile{} = profile) do
    cache_key = {profile.organization_id, String.to_atom(profile.profile_type), profile.profile_key}
    :ets.insert(@baseline_cache, {cache_key, profile})
  rescue
    _ -> :ok
  end

  defp load_baselines_to_cache do
    Repo.all(BaselineProfile)
    |> Enum.each(&cache_baseline/1)

    Logger.info("[FP.BaselineLearner] Loaded #{:ets.info(@baseline_cache, :size)} baselines to cache")
  rescue
    e ->
      Logger.warning("[FP.BaselineLearner] Failed to load baselines: #{Exception.message(e)}")
  end

  defp update_all_baselines do
    # Update event averages for active baselines
    from(p in BaselineProfile, where: p.status in ["learning", "active"])
    |> Repo.all()
    |> Enum.each(fn profile ->
      if profile.learning_started_at do
        days_elapsed = max(1, DateTime.diff(DateTime.utc_now(), profile.learning_started_at, :day))
        events_per_day = (profile.total_events_processed || 0) / days_elapsed

        profile
        |> BaselineProfile.changeset(%{events_per_day_avg: events_per_day})
        |> Repo.update()
        |> case do
          {:ok, updated} -> cache_baseline(updated)
          _ -> :ok
        end
      end
    end)
  rescue
    e ->
      Logger.warning("[FP.BaselineLearner] Failed to update baselines: #{Exception.message(e)}")
  end

  defp check_learning_completions do
    # Find baselines that have completed learning
    from(p in BaselineProfile,
      where: p.status == "learning"
    )
    |> Repo.all()
    |> Enum.each(fn profile ->
      if BaselineProfile.learning_complete?(profile) do
        profile
        |> BaselineProfile.changeset(%{
          status: "active",
          learning_completed_at: DateTime.utc_now()
        })
        |> Repo.update()
        |> case do
          {:ok, updated} ->
            cache_baseline(updated)
            Logger.info("[FP.BaselineLearner] Baseline completed: #{profile.profile_type}/#{profile.profile_key}")

          _ ->
            :ok
        end
      end
    end)
  rescue
    _ -> :ok
  end

  # ---------------------------------------------------------------------------
  # Private - Anomaly Calculation
  # ---------------------------------------------------------------------------

  defp calculate_time_anomaly(profile, hour) do
    histogram = profile.events_per_hour_histogram || %{}
    total = Enum.sum(Map.values(histogram))

    if total > 100 do
      hour_count = Map.get(histogram, to_string(hour), 0)
      expected = total / 24
      ratio = hour_count / max(expected, 1)

      cond do
        ratio < 0.1 -> 0.8  # Very unusual hour
        ratio < 0.3 -> 0.5  # Somewhat unusual
        true -> 0.1         # Normal hour
      end
    else
      0.3  # Not enough data
    end
  end

  defp calculate_stats do
    profiles = from(p in BaselineProfile) |> Repo.all()

    learning = Enum.count(profiles, & &1.status == "learning")
    active = Enum.count(profiles, & &1.status == "active")
    frozen = Enum.count(profiles, & &1.status == "frozen")

    total_events = Enum.sum(Enum.map(profiles, & &1.total_events_processed || 0))

    %{
      total_profiles: length(profiles),
      by_status: %{
        learning: learning,
        active: active,
        frozen: frozen
      },
      total_events_processed: total_events,
      cached_profiles: :ets.info(@baseline_cache, :size)
    }
  end

  defp schedule_baseline_update do
    Process.send_after(self(), :update_baselines, @update_interval)
  end
end
