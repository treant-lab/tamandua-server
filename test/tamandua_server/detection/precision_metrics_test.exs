defmodule TamanduaServer.Detection.PrecisionMetricsTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Detection.PrecisionMetrics

  setup do
    case :ets.whereis(:tamandua_detection_precision_metrics) do
      :undefined -> :ok
      _tid -> :ets.delete(:tamandua_detection_precision_metrics)
    end

    PrecisionMetrics.ensure_table()

    :ok
  end

  test "records analyzed events and detection latency by collector/profile/family" do
    event = %{collector: "amsi", profile: "endpoint", family: "script"}

    PrecisionMetrics.record_event(event, %{expected_events: 10, received_events: 8})
    PrecisionMetrics.record_event(event, %{})
    PrecisionMetrics.record_detection(event, %{rule_name: "encoded command"}, 25)
    PrecisionMetrics.record_detection(event, %{rule_name: "download cradle"}, 75)

    summary = PrecisionMetrics.summary(%{collector: "amsi"})

    assert summary.totals.events_analyzed == 2
    assert summary.totals.detections == 2
    assert summary.totals.detection_rate == 1.0
    assert summary.totals.latency.count == 2
    assert summary.totals.latency.avg_ms == 50.0
    assert summary.totals.latency.max_ms == 75
    assert summary.totals.event_loss.expected == 10
    assert summary.totals.event_loss.received == 8
    assert summary.totals.event_loss.lost == 2
    assert summary.totals.event_loss.loss_rate == 0.2
    assert summary.by_collector["amsi"].events_analyzed == 2
    assert summary.by_profile["endpoint"].detections == 2
    assert summary.by_family["script"].latency.max_ms == 75
  end

  test "records alert precision and false positive outcomes" do
    alert = %{"collector" => "edr", "profile" => "prod", "family" => "process"}

    PrecisionMetrics.record_alert_outcome(alert, :true_positive)
    PrecisionMetrics.record_alert_outcome(alert, "benign")
    PrecisionMetrics.record_alert_outcome(alert, "needs_review")

    summary = PrecisionMetrics.summary(collector: :edr, profile: "prod")

    assert summary.totals.alerts.total == 3
    assert summary.totals.alerts.true_positives == 1
    assert summary.totals.alerts.false_positives == 1
    assert summary.totals.alerts.unknown == 1
    assert summary.totals.alerts.precision == 0.5
    assert summary.totals.alerts.false_positive_rate == 1 / 3
  end

  test "records collector degradation impact and loss estimates" do
    PrecisionMetrics.record_collector_health(:etw, %{
      profile: "prod",
      family: "kernel",
      status: :degraded,
      health_score: 0.4,
      impact_score: 0.7,
      expected_events: 100,
      received_events: 70
    })

    PrecisionMetrics.record_collector_health("etw", %{
      profile: "prod",
      family: "kernel",
      status: :healthy,
      health_score: 0.8,
      impact_score: 0.1,
      lost_events: 5
    })

    summary = PrecisionMetrics.summary(%{collector: "etw", family: "kernel"})

    assert summary.totals.collector_health.samples == 2
    assert summary.totals.collector_health.degraded_samples == 1
    assert summary.totals.collector_health.degraded_rate == 0.5
    assert summary.totals.collector_health.avg_score == 0.6
    assert summary.totals.collector_health.avg_degradation_impact == 0.4
    assert summary.totals.event_loss.expected == 100
    assert summary.totals.event_loss.received == 70
    assert summary.totals.event_loss.lost == 35
  end

  test "summary filters isolate dimensions" do
    PrecisionMetrics.record_event(%{collector: "dns", profile: "prod", family: "network"}, %{})
    PrecisionMetrics.record_event(%{collector: "dns", profile: "dev", family: "network"}, %{})
    PrecisionMetrics.record_event(%{collector: "auth", profile: "prod", family: "identity"}, %{})

    prod_dns = PrecisionMetrics.summary(%{collector: "dns", profile: "prod"})
    all_prod = PrecisionMetrics.summary(%{profile: "prod"})

    assert prod_dns.totals.events_analyzed == 1
    assert Map.keys(prod_dns.by_profile) == ["prod"]
    assert all_prod.totals.events_analyzed == 2
    assert all_prod.by_collector["auth"].events_analyzed == 1
    assert all_prod.by_collector["dns"].events_analyzed == 1
  end
end
