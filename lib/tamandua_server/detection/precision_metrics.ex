defmodule TamanduaServer.Detection.PrecisionMetrics do
  @moduledoc """
  In-memory precision and health counters for detection telemetry.

  The module intentionally owns no process. Metrics live in a named ETS table so
  EngineWorker or other callers can record observations without supervision
  changes. Values are best-effort runtime counters and are reset when the VM
  restarts or the table is deleted.
  """

  @table :tamandua_detection_precision_metrics
  @unknown "unknown"

  @type filters :: map() | keyword()
  @type dims :: {String.t(), String.t(), String.t()}

  @doc "Create the metrics ETS table if it does not already exist."
  @spec ensure_table() :: :ok
  def ensure_table do
    case :ets.whereis(@table) do
      :undefined ->
        try do
          :ets.new(@table, [
            :named_table,
            :public,
            :set,
            read_concurrency: true,
            write_concurrency: true
          ])

          :ok
        rescue
          ArgumentError -> :ok
        end

      _tid ->
        :ok
    end
  end

  @doc "Record one event that was accepted for detection analysis."
  @spec record_event(atom() | map(), map() | keyword() | nil) :: :ok
  def record_event(kind, sample) when is_atom(kind) and is_map(sample) do
    dims = dimensions(sample, sample[:metadata])

    case kind do
      :event_received ->
        increment(dims, :events_received)

      :detection_completed ->
        increment(dims, :events_analyzed)
        record_latency(dims, duration_ms(value(sample[:metadata], :duration_us)))
        add_if_present(dims, :detections, numeric_value(sample[:metadata], [:detection_count]))

      :event_lost ->
        increment(dims, :lost_events)

      _other ->
        increment(dims, :events_observed)
    end

    record_loss_estimate(dims, sample[:metadata])
    :ok
  end

  def record_event(event, context) when is_map(event) do
    dims = dimensions(event, context)

    increment(dims, :events_analyzed)
    record_loss_estimate(dims, context)

    :ok
  end

  def record_event(_event, _context), do: :ok

  @doc "Record a detection emitted for an event with its analysis latency in milliseconds."
  @spec record_detection(map(), map(), number() | nil) :: :ok
  def record_detection(event, detection, latency_ms) when is_map(event) and is_map(detection) do
    dims = dimensions(event, detection)

    increment(dims, :detections)
    record_latency(dims, latency_ms)

    :ok
  end

  def record_detection(_event, _detection, _latency_ms), do: :ok

  @doc """
  Record the reviewed outcome for an alert.

  Outcomes such as `:true_positive`, `"confirmed"`, or `"malicious"` count
  toward precision. Outcomes such as `:false_positive`, `"benign"`, or
  `"suppressed"` count toward the false-positive rate. Unknown outcomes are
  retained separately.
  """
  @spec record_alert_outcome(map(), atom() | String.t()) :: :ok
  def record_alert_outcome(alert, outcome) when is_map(alert) do
    dims = dimensions(alert, nil)

    increment(dims, :alerts_total)

    case normalize_outcome(outcome) do
      :true_positive -> increment(dims, :true_positives)
      :false_positive -> increment(dims, :false_positives)
      :unknown -> increment(dims, :unknown_alert_outcomes)
    end

    :ok
  end

  def record_alert_outcome(_alert, _outcome), do: :ok

  @doc """
  Record collector health and degradation impact.

  `health` may include `:status`, `:degraded`, `:health_score`, `:impact_score`,
  and loss fields such as `:expected_events`, `:received_events`, or
  `:lost_events`.
  """
  @spec record_collector_health(String.t() | atom(), map() | keyword() | nil) :: :ok
  def record_collector_health(collector, health) do
    health = mapify(health)
    dims = dimensions(%{collector: collector}, health)

    increment(dims, :health_samples)

    if degraded?(health) do
      increment(dims, :degraded_samples)
    end

    if score = numeric_value(health, [:health_score, :score]) do
      add(dims, :health_score_sum, score)
      increment(dims, :health_score_count)
    end

    if impact = numeric_value(health, [:impact_score, :degradation_impact, :impact]) do
      add(dims, :degradation_impact_sum, impact)
      increment(dims, :degradation_impact_count)
    end

    record_loss_estimate(dims, health)

    :ok
  end

  @doc """
  Return aggregate metrics for optional `collector`, `profile`, and `family` filters.
  """
  @spec summary(filters()) :: map()
  def summary(filters) do
    ensure_table()

    filters = normalize_filters(filters)
    rows = matching_rows(filters)
    dims = rows |> Enum.map(fn {{:metric, dims, _metric}, _value} -> dims end) |> Enum.uniq()

    %{
      filters: filters,
      totals: metric_summary(rows),
      by_collector: group_summary(rows, dims, 0),
      by_profile: group_summary(rows, dims, 1),
      by_family: group_summary(rows, dims, 2)
    }
  end

  defp matching_rows(filters) do
    @table
    |> :ets.tab2list()
    |> Enum.filter(fn
      {{:metric, dims, _metric}, _value} -> matches_filters?(dims, filters)
      _other -> false
    end)
  end

  defp matches_filters?({collector, profile, family}, filters) do
    matches_filter?(collector, filters[:collector]) and
      matches_filter?(profile, filters[:profile]) and
      matches_filter?(family, filters[:family])
  end

  defp matches_filter?(_actual, nil), do: true
  defp matches_filter?(actual, expected), do: actual == expected

  defp group_summary(rows, dims, position) do
    dims
    |> Enum.map(&elem(&1, position))
    |> Enum.uniq()
    |> Enum.sort()
    |> Map.new(fn value ->
      grouped_rows =
        Enum.filter(rows, fn {{:metric, dims, _metric}, _count} ->
          elem(dims, position) == value
        end)

      {value, metric_summary(grouped_rows)}
    end)
  end

  defp metric_summary(rows) do
    metrics =
      Enum.reduce(rows, %{}, fn {{:metric, _dims, metric}, value}, acc ->
        Map.update(acc, metric, value, &(&1 + value))
      end)

    events_received = get(metrics, :events_received)
    events = get(metrics, :events_analyzed)
    detections = get(metrics, :detections)
    alerts_total = get(metrics, :alerts_total)
    true_positives = get(metrics, :true_positives)
    false_positives = get(metrics, :false_positives)
    unknown_outcomes = get(metrics, :unknown_alert_outcomes)
    latency_count = get(metrics, :latency_count)
    health_samples = get(metrics, :health_samples)
    health_score_count = get(metrics, :health_score_count)
    degradation_impact_count = get(metrics, :degradation_impact_count)
    degraded_samples = get(metrics, :degraded_samples)
    expected_events = get(metrics, :expected_events)
    received_events = get(metrics, :received_events)
    lost_events = get(metrics, :lost_events)

    %{
      events_received: events_received,
      events_analyzed: events,
      events_observed: get(metrics, :events_observed),
      detections: detections,
      detection_rate: ratio(detections, events),
      latency: %{
        count: latency_count,
        avg_ms: ratio(get(metrics, :latency_sum_ms), latency_count),
        max_ms: get(metrics, :latency_max_ms)
      },
      alerts: %{
        total: alerts_total,
        true_positives: true_positives,
        false_positives: false_positives,
        unknown: unknown_outcomes,
        precision: ratio(true_positives, true_positives + false_positives),
        false_positive_rate: ratio(false_positives, alerts_total)
      },
      event_loss: %{
        expected: expected_events,
        received: received_events,
        lost: lost_events,
        loss_rate: ratio(lost_events, expected_events)
      },
      collector_health: %{
        samples: health_samples,
        degraded_samples: degraded_samples,
        degraded_rate: ratio(degraded_samples, health_samples),
        avg_score: ratio(get(metrics, :health_score_sum), health_score_count),
        avg_degradation_impact:
          ratio(get(metrics, :degradation_impact_sum), degradation_impact_count)
      }
    }
  end

  defp record_latency(_dims, nil), do: :ok

  defp record_latency(dims, latency_ms) when is_number(latency_ms) do
    latency_ms = max(latency_ms, 0)

    increment(dims, :latency_count)
    add(dims, :latency_sum_ms, latency_ms)
    put_max(dims, :latency_max_ms, latency_ms)

    :ok
  end

  defp record_latency(_dims, _latency_ms), do: :ok

  defp duration_ms(duration_us) when is_number(duration_us), do: duration_us / 1_000
  defp duration_ms(_duration_us), do: nil

  defp record_loss_estimate(dims, source) do
    source = mapify(source)
    expected = numeric_value(source, [:expected_events, :expected_count])
    received = numeric_value(source, [:received_events, :received_count])
    lost = numeric_value(source, [:lost_events, :dropped_events, :estimated_lost_events])

    inferred_lost =
      case {expected, received, lost} do
        {expected, received, nil} when is_number(expected) and is_number(received) ->
          max(expected - received, 0)

        {_expected, _received, lost} ->
          lost
      end

    add_if_present(dims, :expected_events, expected)
    add_if_present(dims, :received_events, received)
    add_if_present(dims, :lost_events, inferred_lost)
  end

  defp dimensions(primary, secondary) do
    primary = mapify(primary)
    secondary = mapify(secondary)

    {
      dimension_value(primary, secondary, :collector),
      dimension_value(primary, secondary, :profile),
      dimension_value(primary, secondary, :family)
    }
  end

  defp dimension_value(primary, secondary, key) do
    primary
    |> first_value(secondary, [key, to_string(key)])
    |> fallback_nested_dimension(primary, key)
    |> normalize_dimension()
  end

  defp fallback_nested_dimension(nil, source, key) do
    metadata = nested_metadata(source)

    value(metadata, key) ||
      case key do
        :profile -> value(metadata, :collector_profile)
        :family -> value(metadata, :collector_family)
        _ -> nil
      end
  end

  defp fallback_nested_dimension(value, _source, _key), do: value

  defp nested_metadata(source) do
    value(source, :detection_metadata) || value(source, :metadata) || %{}
  end

  defp first_value(primary, secondary, keys) do
    Enum.find_value(keys, fn key -> Map.get(primary, key) || Map.get(secondary, key) end)
  end

  defp increment(dims, metric), do: add(dims, metric, 1)

  defp add(dims, metric, value) when is_integer(value) do
    ensure_table()
    :ets.update_counter(@table, {:metric, dims, metric}, value, {{:metric, dims, metric}, 0})
    :ok
  end

  defp add(dims, metric, value) when is_number(value) do
    ensure_table()
    key = {:metric, dims, metric}

    new_value =
      case :ets.lookup(@table, key) do
        [{^key, current}] -> current + value
        [] -> value
      end

    :ets.insert(@table, {key, new_value})
    :ok
  end

  defp add_if_present(_dims, _metric, nil), do: :ok

  defp add_if_present(dims, metric, value) when is_number(value),
    do: add(dims, metric, max(value, 0))

  defp put_max(dims, metric, value) do
    ensure_table()
    key = {:metric, dims, metric}

    case :ets.lookup(@table, key) do
      [{^key, current}] when current >= value -> :ok
      _ -> :ets.insert(@table, {key, value})
    end
  end

  defp degraded?(health) do
    truthy?(value(health, :degraded)) or
      normalize_status(value(health, :status)) in ["degraded", "down", "impaired", "unhealthy"]
  end

  defp normalize_status(nil), do: nil
  defp normalize_status(status), do: status |> to_string() |> String.downcase()

  defp normalize_outcome(outcome) do
    case outcome |> to_string() |> String.downcase() do
      outcome when outcome in ["true_positive", "confirmed", "malicious", "valid", "tp"] ->
        :true_positive

      outcome when outcome in ["false_positive", "benign", "suppressed", "dismissed", "fp"] ->
        :false_positive

      _other ->
        :unknown
    end
  end

  defp normalize_filters(filters) do
    filters = mapify(filters)

    [:collector, :profile, :family]
    |> Map.new(fn key -> {key, normalize_optional_filter(value(filters, key))} end)
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Map.new()
  end

  defp normalize_optional_filter(nil), do: nil
  defp normalize_optional_filter(value), do: normalize_dimension(value)

  defp normalize_dimension(nil), do: @unknown

  defp normalize_dimension(value) when is_binary(value),
    do: value |> String.trim() |> blank_to_unknown()

  defp normalize_dimension(value), do: value |> to_string() |> normalize_dimension()

  defp blank_to_unknown(""), do: @unknown
  defp blank_to_unknown(value), do: value

  defp numeric_value(map, keys) do
    Enum.find_value(keys, fn key ->
      case value(map, key) do
        number when is_number(number) -> number
        _other -> nil
      end
    end)
  end

  defp value(map, key) when is_map(map), do: Map.get(map, key) || Map.get(map, to_string(key))
  defp value(_map, _key), do: nil

  defp mapify(nil), do: %{}
  defp mapify(value) when is_map(value), do: value
  defp mapify(value) when is_list(value), do: Map.new(value)
  defp mapify(_value), do: %{}

  defp truthy?(value), do: value in [true, "true", "yes", "1", 1]

  defp get(metrics, key), do: Map.get(metrics, key, 0)

  defp ratio(_numerator, 0), do: 0.0
  defp ratio(numerator, denominator), do: numerator / denominator
end
