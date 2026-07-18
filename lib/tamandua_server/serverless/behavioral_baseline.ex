defmodule TamanduaServer.Serverless.BehavioralBaseline do
  @moduledoc """
  Serverless Behavioral Baseline Module.

  Learns normal behavior patterns for serverless functions and detects anomalies:

  - Execution duration patterns (normal ranges, p50/p95/p99)
  - Memory usage baselines
  - Invocation frequency patterns (hourly/daily)
  - Error rate baselines
  - Cold start patterns
  - Network connection patterns
  - File operation patterns

  ## MITRE ATT&CK Coverage
  - T1496: Resource Hijacking (anomalous resource usage)
  - T1041: Exfiltration Over C2 Channel (unusual network patterns)
  - T1059: Command and Scripting Interpreter (unusual process patterns)

  ## Algorithm
  Uses exponential moving average (EMA) with adaptive thresholds based on
  standard deviation. Anomaly detection uses z-scores with configurable
  sensitivity.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Alerts

  @baselines_table :serverless_baselines
  @anomalies_table :serverless_anomalies
  @execution_history_table :serverless_execution_history

  # Baseline configuration
  @learning_period_hours 168  # 7 days
  @min_samples_for_baseline 100
  @ema_alpha 0.1  # Smoothing factor for EMA
  @anomaly_sensitivity 2.5  # Z-score threshold

  # Types
  defmodule Baseline do
    @moduledoc "Behavioral baseline for a serverless function"
    defstruct [
      :function_id,
      :provider,
      :learning_started_at,
      :learning_completed_at,
      :status,  # learning, active, stale
      :sample_count,
      # Duration metrics
      :duration_mean,
      :duration_std,
      :duration_p50,
      :duration_p95,
      :duration_p99,
      # Memory metrics
      :memory_mean,
      :memory_std,
      :memory_max,
      # Invocation patterns
      :invocations_per_hour,
      :invocations_per_day,
      :invocation_variance,
      # Error metrics
      :error_rate,
      :error_rate_std,
      # Cold start metrics
      :cold_start_rate,
      :cold_start_duration_mean,
      # Network patterns
      :typical_outbound_hosts,
      :typical_outbound_ports,
      :max_outbound_connections,
      # Time patterns
      :peak_hours,
      :typical_day_of_week,
      :last_updated
    ]
  end

  defmodule Anomaly do
    @moduledoc "Detected anomaly in function behavior"
    defstruct [
      :id,
      :function_id,
      :provider,
      :execution_id,
      :anomaly_type,
      :severity,  # low, medium, high, critical
      :description,
      :expected_value,
      :actual_value,
      :z_score,
      :confidence,
      :mitre_technique,
      :detected_at,
      :acknowledged
    ]
  end

  defmodule ExecutionSample do
    @moduledoc "Sample execution data for baseline learning"
    defstruct [
      :function_id,
      :timestamp,
      :duration_ms,
      :memory_used_mb,
      :status,
      :is_cold_start,
      :outbound_connections,
      :error_type
    ]
  end

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Start learning baseline for a function.
  """
  @spec start_learning(String.t(), atom()) :: :ok
  def start_learning(function_id, provider) do
    GenServer.cast(__MODULE__, {:start_learning, function_id, provider})
  end

  @doc """
  Record an execution sample for baseline learning.
  """
  @spec record_execution(map()) :: :ok
  def record_execution(execution_data) do
    GenServer.cast(__MODULE__, {:record_execution, execution_data})
  end

  @doc """
  Analyze an execution against the baseline.
  """
  @spec analyze_execution(map()) :: {:ok, [Anomaly.t()]} | {:error, :no_baseline}
  def analyze_execution(execution_data) do
    GenServer.call(__MODULE__, {:analyze_execution, execution_data})
  end

  @doc """
  Get baseline for a function.
  """
  @spec get_baseline(String.t()) :: {:ok, Baseline.t()} | {:error, :not_found}
  def get_baseline(function_id) do
    GenServer.call(__MODULE__, {:get_baseline, function_id})
  end

  @doc """
  List all baselines.
  """
  @spec list_baselines(map()) :: [Baseline.t()]
  def list_baselines(filters \\ %{}) do
    GenServer.call(__MODULE__, {:list_baselines, filters})
  end

  @doc """
  Get anomalies for a function.
  """
  @spec get_anomalies(String.t(), keyword()) :: [Anomaly.t()]
  def get_anomalies(function_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_anomalies, function_id, opts})
  end

  @doc """
  Get recent anomalies across all functions.
  """
  @spec get_recent_anomalies(integer()) :: [Anomaly.t()]
  def get_recent_anomalies(limit \\ 100) do
    GenServer.call(__MODULE__, {:get_recent_anomalies, limit})
  end

  @doc """
  Acknowledge an anomaly (mark as reviewed).
  """
  @spec acknowledge_anomaly(String.t()) :: :ok | {:error, :not_found}
  def acknowledge_anomaly(anomaly_id) do
    GenServer.call(__MODULE__, {:acknowledge_anomaly, anomaly_id})
  end

  @doc """
  Reset baseline for a function (start fresh learning).
  """
  @spec reset_baseline(String.t()) :: :ok
  def reset_baseline(function_id) do
    GenServer.cast(__MODULE__, {:reset_baseline, function_id})
  end

  @doc """
  Get statistics across all baselines.
  """
  @spec get_statistics() :: map()
  def get_statistics do
    GenServer.call(__MODULE__, :get_statistics)
  end

  @doc """
  Manually update baseline thresholds.
  """
  @spec update_baseline_thresholds(String.t(), map()) :: :ok | {:error, term()}
  def update_baseline_thresholds(function_id, thresholds) do
    GenServer.call(__MODULE__, {:update_thresholds, function_id, thresholds})
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    :ets.new(@baselines_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@anomalies_table, [:ordered_set, :named_table, :public, read_concurrency: true])
    :ets.new(@execution_history_table, [:bag, :named_table, :public, read_concurrency: true])

    # Schedule periodic baseline updates
    :timer.send_interval(:timer.hours(1), :update_baselines)

    # Schedule cleanup of old data
    :timer.send_interval(:timer.hours(24), :cleanup_old_data)

    Logger.info("Serverless Behavioral Baseline service started")
    {:ok, %{}}
  end

  @impl true
  def handle_cast({:start_learning, function_id, provider}, state) do
    baseline = %Baseline{
      function_id: function_id,
      provider: provider,
      learning_started_at: DateTime.utc_now(),
      status: :learning,
      sample_count: 0,
      invocations_per_hour: [],
      invocations_per_day: [],
      typical_outbound_hosts: MapSet.new(),
      typical_outbound_ports: MapSet.new(),
      peak_hours: [],
      typical_day_of_week: [],
      last_updated: DateTime.utc_now()
    }

    :ets.insert(@baselines_table, {function_id, baseline})
    Logger.info("Started baseline learning for function #{function_id}")
    {:noreply, state}
  end

  @impl true
  def handle_cast({:record_execution, execution_data}, state) do
    function_id = execution_data["function_id"] || execution_data[:function_id]

    if function_id do
      sample = build_execution_sample(execution_data)
      :ets.insert(@execution_history_table, {function_id, sample})

      # Update baseline if in learning mode
      update_baseline_from_sample(function_id, sample)
    end

    {:noreply, state}
  end

  @impl true
  def handle_cast({:reset_baseline, function_id}, state) do
    # Get existing provider info
    provider = case :ets.lookup(@baselines_table, function_id) do
      [{^function_id, baseline}] -> baseline.provider
      [] -> :unknown
    end

    # Delete old baseline and history
    :ets.delete(@baselines_table, function_id)
    :ets.match_delete(@execution_history_table, {function_id, :_})

    # Start fresh learning
    if provider != :unknown do
      baseline = %Baseline{
        function_id: function_id,
        provider: provider,
        learning_started_at: DateTime.utc_now(),
        status: :learning,
        sample_count: 0,
        invocations_per_hour: [],
        invocations_per_day: [],
        typical_outbound_hosts: MapSet.new(),
        typical_outbound_ports: MapSet.new(),
        peak_hours: [],
        typical_day_of_week: [],
        last_updated: DateTime.utc_now()
      }
      :ets.insert(@baselines_table, {function_id, baseline})
    end

    Logger.info("Reset baseline for function #{function_id}")
    {:noreply, state}
  end

  @impl true
  def handle_call({:analyze_execution, execution_data}, _from, state) do
    function_id = execution_data["function_id"] || execution_data[:function_id]

    case :ets.lookup(@baselines_table, function_id) do
      [{^function_id, baseline}] when baseline.status == :active ->
        anomalies = detect_anomalies(execution_data, baseline)

        # Store anomalies
        Enum.each(anomalies, fn anomaly ->
          ts = DateTime.to_unix(anomaly.detected_at, :millisecond)
          :ets.insert(@anomalies_table, {{ts, anomaly.id}, anomaly})

          # Generate alerts for high/critical anomalies
          if anomaly.severity in [:high, :critical] do
            generate_anomaly_alert(anomaly, baseline)
          end
        end)

        {:reply, {:ok, anomalies}, state}

      _ ->
        {:reply, {:error, :no_baseline}, state}
    end
  end

  @impl true
  def handle_call({:get_baseline, function_id}, _from, state) do
    result = case :ets.lookup(@baselines_table, function_id) do
      [{^function_id, baseline}] -> {:ok, baseline}
      [] -> {:error, :not_found}
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call({:list_baselines, filters}, _from, state) do
    baselines = :ets.foldl(
      fn {_id, baseline}, acc -> [baseline | acc] end,
      [],
      @baselines_table
    )
    |> apply_baseline_filters(filters)
    {:reply, baselines, state}
  end

  @impl true
  def handle_call({:get_anomalies, function_id, opts}, _from, state) do
    limit = Keyword.get(opts, :limit, 100)

    anomalies = :ets.foldl(
      fn {{_ts, _id}, anomaly}, acc ->
        if anomaly.function_id == function_id do
          [anomaly | acc]
        else
          acc
        end
      end,
      [],
      @anomalies_table
    )
    |> Enum.sort_by(& &1.detected_at, {:desc, DateTime})
    |> Enum.take(limit)

    {:reply, anomalies, state}
  end

  @impl true
  def handle_call({:get_recent_anomalies, limit}, _from, state) do
    anomalies = :ets.foldl(
      fn {{_ts, _id}, anomaly}, acc -> [anomaly | acc] end,
      [],
      @anomalies_table
    )
    |> Enum.sort_by(& &1.detected_at, {:desc, DateTime})
    |> Enum.take(limit)

    {:reply, anomalies, state}
  end

  @impl true
  def handle_call({:acknowledge_anomaly, anomaly_id}, _from, state) do
    result = :ets.foldl(
      fn {key, anomaly}, acc ->
        if anomaly.id == anomaly_id do
          updated = %{anomaly | acknowledged: true}
          :ets.insert(@anomalies_table, {key, updated})
          :ok
        else
          acc
        end
      end,
      {:error, :not_found},
      @anomalies_table
    )
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_statistics, _from, state) do
    stats = compute_statistics()
    {:reply, stats, state}
  end

  @impl true
  def handle_call({:update_thresholds, function_id, thresholds}, _from, state) do
    result = case :ets.lookup(@baselines_table, function_id) do
      [{^function_id, baseline}] ->
        updated = struct(baseline, thresholds)
        :ets.insert(@baselines_table, {function_id, updated})
        :ok

      [] ->
        {:error, :not_found}
    end
    {:reply, result, state}
  end

  @impl true
  def handle_info(:update_baselines, state) do
    # Recalculate all baselines
    :ets.foldl(
      fn {function_id, baseline}, _acc ->
        if baseline.status == :learning do
          recalculate_baseline(function_id)
        end
        :ok
      end,
      :ok,
      @baselines_table
    )
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup_old_data, state) do
    # Remove anomalies older than 30 days
    cutoff = DateTime.add(DateTime.utc_now(), -30 * 24 * 60 * 60, :second)
    cutoff_ts = DateTime.to_unix(cutoff, :millisecond)

    :ets.select_delete(@anomalies_table, [
      {{{:"$1", :_}, :_}, [{:<, :"$1", cutoff_ts}], [true]}
    ])

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp build_execution_sample(data) do
    %ExecutionSample{
      function_id: data["function_id"] || data[:function_id],
      timestamp: parse_timestamp(data["timestamp"] || data[:timestamp]),
      duration_ms: data["duration_ms"] || data[:duration_ms],
      memory_used_mb: data["memory_used_mb"] || data[:memory_used_mb],
      status: data["status"] || data[:status],
      is_cold_start: !is_nil(data["init_duration_ms"] || data[:init_duration_ms]),
      outbound_connections: data["outbound_connections"] || data[:outbound_connections] || [],
      error_type: data["error_type"] || data[:error_type]
    }
  end

  defp parse_timestamp(nil), do: DateTime.utc_now()
  defp parse_timestamp(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end
  defp parse_timestamp(%DateTime{} = dt), do: dt

  defp update_baseline_from_sample(function_id, sample) do
    case :ets.lookup(@baselines_table, function_id) do
      [{^function_id, baseline}] when baseline.status == :learning ->
        # Update statistics with new sample
        new_count = (baseline.sample_count || 0) + 1

        # Update duration metrics using EMA
        new_duration_mean = update_ema(baseline.duration_mean, sample.duration_ms, @ema_alpha)
        new_duration_std = update_running_std(baseline.duration_std, baseline.duration_mean, sample.duration_ms, new_count)

        # Update memory metrics
        new_memory_mean = update_ema(baseline.memory_mean, sample.memory_used_mb, @ema_alpha)

        # Update cold start rate
        cold_start_count = if sample.is_cold_start, do: 1, else: 0
        new_cold_start_rate = update_ema(baseline.cold_start_rate, cold_start_count, @ema_alpha)

        # Update error rate
        error_count = if sample.status == :error, do: 1, else: 0
        new_error_rate = update_ema(baseline.error_rate, error_count, @ema_alpha)

        # Update outbound hosts and ports
        new_hosts = sample.outbound_connections
        |> Enum.map(& &1["host"] || &1[:host])
        |> Enum.reject(&is_nil/1)
        |> MapSet.new()
        |> MapSet.union(baseline.typical_outbound_hosts || MapSet.new())

        new_ports = sample.outbound_connections
        |> Enum.map(& &1["port"] || &1[:port])
        |> Enum.reject(&is_nil/1)
        |> MapSet.new()
        |> MapSet.union(baseline.typical_outbound_ports || MapSet.new())

        # Update hour tracking
        hour = sample.timestamp.hour
        new_peak_hours = [hour | baseline.peak_hours || []] |> Enum.take(1000)

        # Check if learning period is complete
        hours_elapsed = DateTime.diff(DateTime.utc_now(), baseline.learning_started_at, :hour)
        new_status = if hours_elapsed >= @learning_period_hours && new_count >= @min_samples_for_baseline do
          :active
        else
          :learning
        end

        updated_baseline = %{baseline |
          sample_count: new_count,
          duration_mean: new_duration_mean,
          duration_std: new_duration_std,
          memory_mean: new_memory_mean,
          cold_start_rate: new_cold_start_rate,
          error_rate: new_error_rate,
          typical_outbound_hosts: new_hosts,
          typical_outbound_ports: new_ports,
          peak_hours: new_peak_hours,
          status: new_status,
          learning_completed_at: if(new_status == :active && baseline.status == :learning, do: DateTime.utc_now(), else: baseline.learning_completed_at),
          last_updated: DateTime.utc_now()
        }

        :ets.insert(@baselines_table, {function_id, updated_baseline})

      _ ->
        # No baseline or not in learning mode - auto-start learning
        start_learning(function_id, :unknown)
    end
  end

  defp update_ema(nil, new_value, _alpha), do: new_value
  defp update_ema(_old_value, nil, _alpha), do: nil
  defp update_ema(old_value, new_value, alpha) do
    alpha * new_value + (1 - alpha) * old_value
  end

  defp update_running_std(nil, _mean, _new_value, _count), do: 0.0
  defp update_running_std(_std, nil, _new_value, _count), do: 0.0
  defp update_running_std(_std, _mean, nil, _count), do: 0.0
  defp update_running_std(old_std, mean, new_value, count) when count > 1 do
    # Welford's online algorithm approximation
    variance = old_std * old_std
    diff = new_value - mean
    new_variance = variance + (diff * diff - variance) / count
    :math.sqrt(max(0, new_variance))
  end
  defp update_running_std(_, _, _, _), do: 0.0

  defp detect_anomalies(execution_data, baseline) do
    anomalies = []

    # Check duration anomaly
    duration = execution_data["duration_ms"] || execution_data[:duration_ms]
    if duration && baseline.duration_mean && baseline.duration_std && baseline.duration_std > 0 do
      z_score = (duration - baseline.duration_mean) / baseline.duration_std
      if abs(z_score) > @anomaly_sensitivity do
        _anomalies = [create_anomaly(
          execution_data,
          baseline,
          :duration,
          z_score,
          baseline.duration_mean,
          duration,
          "Execution duration (#{round(duration)}ms) deviates significantly from baseline (#{round(baseline.duration_mean)}ms)"
        ) | anomalies]
      end
    end

    # Check memory anomaly
    memory = execution_data["memory_used_mb"] || execution_data[:memory_used_mb]
    if memory && baseline.memory_mean && baseline.memory_std && baseline.memory_std > 0 do
      z_score = (memory - baseline.memory_mean) / baseline.memory_std
      if abs(z_score) > @anomaly_sensitivity do
        _anomalies = [create_anomaly(
          execution_data,
          baseline,
          :memory,
          z_score,
          baseline.memory_mean,
          memory,
          "Memory usage (#{round(memory)}MB) deviates significantly from baseline (#{round(baseline.memory_mean)}MB)"
        ) | anomalies]
      end
    end

    # Check for new outbound hosts
    outbound = execution_data["outbound_connections"] || execution_data[:outbound_connections] || []
    new_hosts = outbound
    |> Enum.map(& &1["host"] || &1[:host])
    |> Enum.reject(&is_nil/1)
    |> MapSet.new()
    |> MapSet.difference(baseline.typical_outbound_hosts || MapSet.new())

    if MapSet.size(new_hosts) > 0 do
      _anomalies = [create_anomaly(
        execution_data,
        baseline,
        :new_outbound_host,
        3.0,  # High confidence
        "Known hosts",
        MapSet.to_list(new_hosts) |> Enum.join(", "),
        "Function connected to previously unseen host(s): #{MapSet.to_list(new_hosts) |> Enum.join(", ")}"
      ) | anomalies]
    end

    # Check for new outbound ports
    new_ports = outbound
    |> Enum.map(& &1["port"] || &1[:port])
    |> Enum.reject(&is_nil/1)
    |> MapSet.new()
    |> MapSet.difference(baseline.typical_outbound_ports || MapSet.new())

    if MapSet.size(new_ports) > 0 do
      _anomalies = [create_anomaly(
        execution_data,
        baseline,
        :new_outbound_port,
        2.5,
        "Known ports",
        MapSet.to_list(new_ports) |> Enum.join(", "),
        "Function connected to previously unseen port(s): #{MapSet.to_list(new_ports) |> Enum.join(", ")}"
      ) | anomalies]
    end

    # Check for unusual time of execution
    timestamp = parse_timestamp(execution_data["timestamp"] || execution_data[:timestamp])
    hour = timestamp.hour
    typical_hours = get_typical_hours(baseline.peak_hours || [])

    if typical_hours != [] && hour not in typical_hours do
      _anomalies = [create_anomaly(
        execution_data,
        baseline,
        :unusual_time,
        2.0,
        "Typical hours: #{Enum.join(typical_hours, ", ")}",
        hour,
        "Function executed at unusual hour (#{hour}:00)"
      ) | anomalies]
    end

    anomalies
  end

  defp create_anomaly(execution_data, baseline, type, z_score, expected, actual, description) do
    severity = determine_severity(type, z_score)

    %Anomaly{
      id: Ecto.UUID.generate(),
      function_id: execution_data["function_id"] || execution_data[:function_id],
      provider: baseline.provider,
      execution_id: execution_data["request_id"] || execution_data["execution_id"] || execution_data[:request_id],
      anomaly_type: type,
      severity: severity,
      description: description,
      expected_value: expected,
      actual_value: actual,
      z_score: z_score,
      confidence: min(abs(z_score) / 3.0, 1.0),  # Confidence 0-1
      mitre_technique: get_mitre_technique(type),
      detected_at: DateTime.utc_now(),
      acknowledged: false
    }
  end

  defp determine_severity(type, z_score) do
    base_severity = case type do
      :new_outbound_host -> :high
      :new_outbound_port -> :medium
      :unusual_time -> :low
      _ -> :medium
    end

    # Increase severity for extreme z-scores
    cond do
      abs(z_score) > 5.0 -> max_severity(base_severity, :critical)
      abs(z_score) > 4.0 -> max_severity(base_severity, :high)
      abs(z_score) > 3.0 -> max_severity(base_severity, :medium)
      true -> base_severity
    end
  end

  defp max_severity(a, b) do
    severity_order = %{low: 0, medium: 1, high: 2, critical: 3}
    if severity_order[a] >= severity_order[b], do: a, else: b
  end

  defp get_mitre_technique(:duration), do: "T1496"  # Resource Hijacking
  defp get_mitre_technique(:memory), do: "T1496"
  defp get_mitre_technique(:new_outbound_host), do: "T1041"  # Exfiltration
  defp get_mitre_technique(:new_outbound_port), do: "T1041"
  defp get_mitre_technique(:unusual_time), do: nil
  defp get_mitre_technique(_), do: nil

  defp get_typical_hours([]), do: []
  defp get_typical_hours(hours) do
    # Get hours that appear in more than 10% of samples
    freq = Enum.frequencies(hours)
    threshold = length(hours) * 0.1

    freq
    |> Enum.filter(fn {_hour, count} -> count >= threshold end)
    |> Enum.map(fn {hour, _count} -> hour end)
    |> Enum.sort()
  end

  defp recalculate_baseline(function_id) do
    samples = :ets.lookup(@execution_history_table, function_id)
    |> Enum.map(fn {_id, sample} -> sample end)

    if length(samples) >= @min_samples_for_baseline do
      case :ets.lookup(@baselines_table, function_id) do
        [{^function_id, baseline}] ->
          # Calculate percentiles for duration
          durations = Enum.map(samples, & &1.duration_ms) |> Enum.reject(&is_nil/1) |> Enum.sort()

          updated_baseline = %{baseline |
            duration_p50: percentile(durations, 50),
            duration_p95: percentile(durations, 95),
            duration_p99: percentile(durations, 99),
            memory_max: samples |> Enum.map(& &1.memory_used_mb) |> Enum.reject(&is_nil/1) |> Enum.max(fn -> nil end),
            last_updated: DateTime.utc_now()
          }

          :ets.insert(@baselines_table, {function_id, updated_baseline})

        [] ->
          :ok
      end
    end
  end

  defp percentile([], _p), do: nil
  defp percentile(sorted_list, p) do
    k = length(sorted_list) * p / 100
    index = trunc(k) |> min(length(sorted_list) - 1) |> max(0)
    Enum.at(sorted_list, index)
  end

  defp apply_baseline_filters(baselines, filters) do
    baselines
    |> filter_by_provider(filters[:provider])
    |> filter_by_status(filters[:status])
  end

  defp filter_by_provider(baselines, nil), do: baselines
  defp filter_by_provider(baselines, provider) do
    Enum.filter(baselines, &(&1.provider == provider))
  end

  defp filter_by_status(baselines, nil), do: baselines
  defp filter_by_status(baselines, status) do
    Enum.filter(baselines, &(&1.status == status))
  end

  defp generate_anomaly_alert(anomaly, baseline) do
    Alerts.create_alert(%{
      title: "Serverless Behavior Anomaly: #{anomaly.anomaly_type}",
      description: """
      Function: #{anomaly.function_id}
      Provider: #{baseline.provider}

      #{anomaly.description}

      Expected: #{anomaly.expected_value}
      Actual: #{anomaly.actual_value}
      Z-Score: #{Float.round(anomaly.z_score, 2)}
      Confidence: #{Float.round(anomaly.confidence * 100, 1)}%
      """,
      severity: to_string(anomaly.severity),
      category: "serverless_anomaly",
      source: "behavioral_baseline",
      mitre_techniques: if(anomaly.mitre_technique, do: [anomaly.mitre_technique], else: []),
      metadata: %{
        function_id: anomaly.function_id,
        provider: baseline.provider,
        anomaly_id: anomaly.id,
        anomaly_type: anomaly.anomaly_type,
        z_score: anomaly.z_score,
        confidence: anomaly.confidence
      }
    })
  end

  defp compute_statistics do
    baselines = :ets.tab2list(@baselines_table)
    |> Enum.map(fn {_id, baseline} -> baseline end)

    anomalies = :ets.tab2list(@anomalies_table)
    |> Enum.map(fn {{_ts, _id}, anomaly} -> anomaly end)

    recent_anomalies = anomalies
    |> Enum.filter(fn a ->
      DateTime.diff(DateTime.utc_now(), a.detected_at, :hour) < 24
    end)

    %{
      total_baselines: length(baselines),
      active_baselines: Enum.count(baselines, &(&1.status == :active)),
      learning_baselines: Enum.count(baselines, &(&1.status == :learning)),
      total_anomalies_24h: length(recent_anomalies),
      critical_anomalies_24h: Enum.count(recent_anomalies, &(&1.severity == :critical)),
      high_anomalies_24h: Enum.count(recent_anomalies, &(&1.severity == :high)),
      unacknowledged_anomalies: Enum.count(anomalies, &(!&1.acknowledged)),
      anomalies_by_type: group_anomalies_by_type(recent_anomalies),
      anomalies_by_provider: group_anomalies_by_provider(recent_anomalies)
    }
  end

  defp group_anomalies_by_type(anomalies) do
    anomalies
    |> Enum.group_by(& &1.anomaly_type)
    |> Enum.map(fn {type, items} -> {type, length(items)} end)
    |> Map.new()
  end

  defp group_anomalies_by_provider(anomalies) do
    anomalies
    |> Enum.group_by(& &1.provider)
    |> Enum.map(fn {provider, items} -> {provider, length(items)} end)
    |> Map.new()
  end
end
