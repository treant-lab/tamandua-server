defmodule TamanduaServer.Detection.EffectiveCoverageTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Detection.{EffectiveCoverage, PrecisionMetrics}

  setup do
    if :ets.whereis(:tamandua_detection_precision_metrics) != :undefined do
      :ets.delete(:tamandua_detection_precision_metrics)
    end

    PrecisionMetrics.ensure_table()
    :ok
  end

  test "returns declared coverage when runtime has not observed collector telemetry" do
    result = EffectiveCoverage.summary(%{})

    assert result.summary.declared_collectors > 0
    assert result.summary.declared_techniques > 0
    assert result.summary.active_collectors == 0
    assert result.summary.effective_coverage_percent == 0.0
    assert Enum.any?(result.collectors, &(&1.collector == "ebpf"))
  end

  test "marks collector and techniques active from runtime precision metrics" do
    PrecisionMetrics.record_event(:detection_completed, %{
      collector: "ebpf",
      metadata: %{duration_us: 2_000, detection_count: 2}
    })

    result = EffectiveCoverage.summary(%{collector: "ebpf"})
    ebpf = Enum.find(result.collectors, &(&1.collector == "ebpf"))

    assert ebpf.status == :active
    assert ebpf.runtime.events_analyzed == 1
    assert ebpf.runtime.detections == 2
    assert result.summary.active_collectors == 1
    assert result.summary.active_techniques == result.summary.declared_techniques
    assert result.summary.effective_coverage_percent == 100.0
  end

  test "marks explicitly enabled collectors configured before runtime telemetry arrives" do
    result = EffectiveCoverage.summary(%{enabled_collectors: ["network_dpi"]})
    network_dpi = Enum.find(result.collectors, &(&1.collector == "network_dpi"))

    assert network_dpi.status == :configured
    assert result.summary.configured_collectors == 1
    assert result.summary.configured_coverage_percent > 0.0
  end

  test "filters by profile" do
    result = EffectiveCoverage.summary(%{profile: "windows"})

    assert result.summary.declared_collectors > 0
    assert Enum.all?(result.collectors, fn collector ->
             "windows" in collector.profiles or "endpoint" in collector.profiles or
               "full" in collector.profiles
           end)
  end
end
