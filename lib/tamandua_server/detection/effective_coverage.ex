defmodule TamanduaServer.Detection.EffectiveCoverage do
  @moduledoc """
  Combines declared collector coverage with runtime precision metrics.

  CollectorCoverage answers what the platform can see. PrecisionMetrics answers
  what is actually flowing through the detection runtime right now. This module
  joins both views so the UI/API can distinguish possible, configured, and
  active ATT&CK coverage.
  """

  alias TamanduaServer.Detection.{CollectorCoverage, PrecisionMetrics}

  @type filters :: map() | keyword()

  @doc "Return declared and runtime-effective coverage for collectors/profiles."
  @spec summary(filters()) :: map()
  def summary(filters \\ %{}) do
    filters = normalize_filters(filters)
    declared_entries = filtered_entries(filters)
    precision = PrecisionMetrics.summary(runtime_filters(filters))
    active_collectors = active_collectors(precision)
    configured_collectors = configured_collectors(filters)

    entries =
      Enum.map(declared_entries, fn entry ->
        status = entry_status(entry.collector, active_collectors, configured_collectors)
        Map.put(entry, :runtime_status, status)
      end)

    %{
      filters: filters,
      summary: coverage_summary(entries, precision),
      collectors: collector_rollups(entries, precision, active_collectors, configured_collectors),
      techniques: technique_rollups(entries),
      runtime: precision
    }
  end

  defp filtered_entries(filters) do
    CollectorCoverage.matrix()
    |> filter_by_collectors(filters[:collectors])
    |> filter_by_profile(filters[:profile])
  end

  defp filter_by_collectors(entries, []), do: entries

  defp filter_by_collectors(entries, collectors) do
    collectors = MapSet.new(collectors)
    Enum.filter(entries, &(collector_name(&1.collector) in collectors))
  end

  defp filter_by_profile(entries, nil), do: entries

  defp filter_by_profile(entries, profile) do
    profile = normalize_dimension(profile)
    Enum.filter(entries, fn entry -> profile in Enum.map(entry.profiles, &collector_name/1) end)
  end

  defp runtime_filters(filters) do
    [:collector, :profile, :family]
    |> Enum.reduce(%{}, fn key, acc ->
      case Map.get(filters, key) do
        nil -> acc
        value -> Map.put(acc, key, value)
      end
    end)
  end

  defp active_collectors(%{by_collector: by_collector}) when is_map(by_collector) do
    by_collector
    |> Enum.filter(fn {_collector, metrics} -> runtime_seen?(metrics) end)
    |> Enum.map(fn {collector, _metrics} -> normalize_dimension(collector) end)
    |> MapSet.new()
  end

  defp active_collectors(_precision), do: MapSet.new()

  defp runtime_seen?(metrics) when is_map(metrics) do
    totals = [
      get(metrics, :events_received),
      get(metrics, :events_analyzed),
      get(metrics, :events_observed),
      get(metrics, :detections),
      get_in(metrics, [:alerts, :total])
    ]

    Enum.any?(totals, &(&1 > 0))
  end

  defp configured_collectors(%{enabled_collectors: collectors}), do: MapSet.new(collectors)
  defp configured_collectors(_filters), do: MapSet.new()

  defp entry_status(collector, active_collectors, configured_collectors) do
    collector = collector_name(collector)

    cond do
      MapSet.member?(active_collectors, collector) -> :active
      MapSet.member?(configured_collectors, collector) -> :configured
      true -> :possible
    end
  end

  defp coverage_summary(entries, precision) do
    declared_techniques = entries |> Enum.map(& &1.technique_id) |> Enum.uniq()
    active_techniques = techniques_by_status(entries, :active)
    configured_techniques = techniques_by_status(entries, :configured)

    %{
      declared_collectors: entries |> Enum.map(& &1.collector) |> Enum.uniq() |> length(),
      active_collectors: entries |> collectors_by_status(:active) |> length(),
      configured_collectors: entries |> collectors_by_status(:configured) |> length(),
      declared_techniques: length(declared_techniques),
      active_techniques: length(active_techniques),
      configured_techniques: length(configured_techniques),
      effective_coverage_percent: percent(length(active_techniques), length(declared_techniques)),
      configured_coverage_percent:
        percent(length(active_techniques) + length(configured_techniques), length(declared_techniques)),
      runtime_events_analyzed: get_in(precision, [:totals, :events_analyzed]) || 0,
      runtime_detections: get_in(precision, [:totals, :detections]) || 0,
      runtime_false_positive_rate:
        get_in(precision, [:totals, :alerts, :false_positive_rate]) || 0.0,
      runtime_precision: get_in(precision, [:totals, :alerts, :precision]) || 0.0,
      runtime_event_loss_rate: get_in(precision, [:totals, :event_loss, :loss_rate]) || 0.0
    }
  end

  defp collectors_by_status(entries, status) do
    entries
    |> Enum.filter(&(&1.runtime_status == status))
    |> Enum.map(&collector_name(&1.collector))
    |> Enum.uniq()
  end

  defp techniques_by_status(entries, status) do
    entries
    |> Enum.filter(&(&1.runtime_status == status))
    |> Enum.map(& &1.technique_id)
    |> Enum.uniq()
  end

  defp collector_rollups(entries, precision, active_collectors, configured_collectors) do
    entries
    |> Enum.group_by(&collector_name(&1.collector))
    |> Enum.map(fn {collector, collector_entries} ->
      %{
        collector: collector,
        status: collector_status(collector, active_collectors, configured_collectors),
        profiles:
          collector_entries
          |> Enum.flat_map(& &1.profiles)
          |> Enum.map(&collector_name/1)
          |> Enum.uniq()
          |> Enum.sort(),
        tactics: collector_entries |> Enum.map(& &1.tactic_id) |> Enum.uniq() |> Enum.sort(),
        techniques: collector_entries |> Enum.map(& &1.technique_id) |> Enum.uniq() |> Enum.sort(),
        technique_count: collector_entries |> Enum.map(& &1.technique_id) |> Enum.uniq() |> length(),
        coverage_levels: coverage_levels(collector_entries),
        runtime: get_in(precision, [:by_collector, collector]) || empty_metrics()
      }
    end)
    |> Enum.sort_by(fn rollup -> {status_order(rollup.status), rollup.collector} end)
  end

  defp collector_status(collector, active_collectors, configured_collectors) do
    cond do
      MapSet.member?(active_collectors, collector) -> :active
      MapSet.member?(configured_collectors, collector) -> :configured
      true -> :possible
    end
  end

  defp technique_rollups(entries) do
    entries
    |> Enum.group_by(& &1.technique_id)
    |> Enum.map(fn {technique_id, technique_entries} ->
      %{
        technique_id: technique_id,
        technique: technique_entries |> List.first() |> Map.fetch!(:technique),
        tactic_id: technique_entries |> List.first() |> Map.fetch!(:tactic_id),
        tactic: technique_entries |> List.first() |> Map.fetch!(:tactic),
        status: strongest_status(technique_entries),
        collectors: technique_entries |> Enum.map(&collector_name(&1.collector)) |> Enum.uniq() |> Enum.sort(),
        coverage_levels: coverage_levels(technique_entries),
        telemetry_requirements:
          technique_entries
          |> Enum.flat_map(& &1.telemetry_requirements)
          |> Enum.map(&collector_name/1)
          |> Enum.uniq()
          |> Enum.sort()
      }
    end)
    |> Enum.sort_by(fn technique -> {status_order(technique.status), technique.technique_id} end)
  end

  defp strongest_status(entries) do
    entries
    |> Enum.map(& &1.runtime_status)
    |> Enum.min_by(&status_order/1, fn -> :possible end)
  end

  defp coverage_levels(entries) do
    entries
    |> Enum.frequencies_by(& &1.coverage_level)
    |> Map.merge(%{strong: 0, moderate: 0, partial: 0}, fn _key, value, _default -> value end)
  end

  defp empty_metrics do
    %{
      events_received: 0,
      events_analyzed: 0,
      events_observed: 0,
      lost_events: 0,
      detections: 0,
      detection_rate: 0.0,
      latency: %{count: 0, avg_ms: 0.0, max_ms: 0},
      alerts: %{
        total: 0,
        true_positives: 0,
        false_positives: 0,
        unknown: 0,
        precision: 0.0,
        false_positive_rate: 0.0
      },
      event_loss: %{expected: 0, received: 0, lost: 0, loss_rate: 0.0},
      collector_health: %{
        samples: 0,
        degraded_samples: 0,
        degraded_rate: 0.0,
        avg_score: 0.0,
        avg_degradation_impact: 0.0
      }
    }
  end

  defp normalize_filters(filters) do
    filters = mapify(filters)
    collector = normalize_optional(filters[:collector] || filters["collector"])
    profile = normalize_optional(filters[:profile] || filters["profile"])
    family = normalize_optional(filters[:family] || filters["family"])

    enabled_collectors =
      (filters[:enabled_collectors] || filters["enabled_collectors"] || filters[:collectors] ||
         filters["collectors"] || collector || [])
      |> List.wrap()
      |> Enum.flat_map(&split_csv/1)
      |> Enum.map(&normalize_dimension/1)
      |> Enum.reject(&(&1 == "unknown"))
      |> Enum.uniq()

    %{
      collector: collector,
      collectors: enabled_collectors,
      enabled_collectors: enabled_collectors,
      profile: profile,
      family: family
    }
    |> Enum.reject(fn {_key, value} -> value in [nil, []] end)
    |> Map.new()
  end

  defp normalize_optional(nil), do: nil
  defp normalize_optional(value), do: normalize_dimension(value)

  defp split_csv(value) when is_binary(value) do
    value
    |> String.split(",", trim: true)
  end

  defp split_csv(value), do: [value]

  defp normalize_dimension(value) when is_atom(value), do: value |> Atom.to_string() |> normalize_dimension()

  defp normalize_dimension(value) when is_binary(value) do
    value
    |> String.trim()
    |> String.downcase()
    |> String.replace("-", "_")
    |> blank_to_unknown()
  end

  defp normalize_dimension(value), do: value |> to_string() |> normalize_dimension()

  defp collector_name(value), do: normalize_dimension(value)

  defp status_order(:active), do: 0
  defp status_order(:configured), do: 1
  defp status_order(:possible), do: 2
  defp status_order(_status), do: 3

  defp percent(_numerator, 0), do: 0.0
  defp percent(numerator, denominator), do: numerator / denominator * 100

  defp blank_to_unknown(""), do: "unknown"
  defp blank_to_unknown(value), do: value

  defp get(map, key) when is_map(map), do: Map.get(map, key) || Map.get(map, to_string(key)) || 0
  defp get(_map, _key), do: 0

  defp mapify(value) when is_map(value), do: value
  defp mapify(value) when is_list(value), do: Map.new(value)
  defp mapify(_value), do: %{}
end
