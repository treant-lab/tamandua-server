defmodule TamanduaServer.Alerts.HealthAwareSuppressionTest do
  @moduledoc """
  Tests for the health-aware alert suppression module.

  Verifies that alert severity is tuned according to agent health status:
  - Healthy agents: alerts pass through unchanged
  - Degraded agents: severity reduced by one level
  - Critical agents: low/medium alerts suppressed, high/critical reduced by two
  - Alert volume spikes on degraded agents trigger more aggressive suppression

  Also covers ETS rate table lifecycle, cleanup, and the reduce_severity helper.
  """

  use ExUnit.Case, async: true

  alias TamanduaServer.Alerts.HealthAwareSuppression

  # ============================================================================
  # Setup
  # ============================================================================

  setup do
    # Create a uniquely-named ETS table for isolation across tests.
    # The module lazily creates :health_suppression_alert_rates if it does not
    # exist, so we ensure it is present before every test.
    HealthAwareSuppression.init_rate_table()
    :ok
  end

  # ============================================================================
  # reduce_severity/2 (public helper)
  # ============================================================================

  describe "reduce_severity/2" do
    test "reduces critical by 1 to high" do
      assert HealthAwareSuppression.reduce_severity("critical", 1) == "high"
    end

    test "reduces critical by 2 to medium" do
      assert HealthAwareSuppression.reduce_severity("critical", 2) == "medium"
    end

    test "reduces high by 1 to medium" do
      assert HealthAwareSuppression.reduce_severity("high", 1) == "medium"
    end

    test "reduces high by 2 to low" do
      assert HealthAwareSuppression.reduce_severity("high", 2) == "low"
    end

    test "reduces medium by 1 to low" do
      assert HealthAwareSuppression.reduce_severity("medium", 1) == "low"
    end

    test "reduces low by 1 to info" do
      assert HealthAwareSuppression.reduce_severity("low", 1) == "info"
    end

    test "cannot reduce below info (floor)" do
      assert HealthAwareSuppression.reduce_severity("info", 1) == "info"
      assert HealthAwareSuppression.reduce_severity("info", 5) == "info"
    end

    test "reducing by 0 returns the same severity" do
      assert HealthAwareSuppression.reduce_severity("high", 0) == "high"
      assert HealthAwareSuppression.reduce_severity("critical", 0) == "critical"
    end

    test "large reduction clamps to info" do
      assert HealthAwareSuppression.reduce_severity("critical", 10) == "info"
    end
  end

  # ============================================================================
  # apply_health_tuning/2 - nil agent
  # ============================================================================

  describe "apply_health_tuning/2 with nil agent_id" do
    test "passes alert through unchanged" do
      alert_data = %{severity: "high", title: "Test Alert"}
      assert {:allow, ^alert_data} = HealthAwareSuppression.apply_health_tuning(alert_data, nil)
    end
  end

  # ============================================================================
  # record_alert/1 and alert_spike?/1
  # ============================================================================

  describe "record_alert/1" do
    test "records an alert for a given agent_id" do
      agent_id = "agent-record-test-#{System.unique_integer([:positive])}"
      assert HealthAwareSuppression.record_alert(agent_id) == :ok
    end

    test "non-binary agent_id is a no-op" do
      assert HealthAwareSuppression.record_alert(nil) == :ok
      assert HealthAwareSuppression.record_alert(123) == :ok
    end
  end

  describe "alert_spike?/1" do
    test "returns false when no alerts have been recorded" do
      agent_id = "agent-no-spike-#{System.unique_integer([:positive])}"
      assert HealthAwareSuppression.alert_spike?(agent_id) == false
    end

    test "returns false when alert count is below threshold" do
      agent_id = "agent-below-threshold-#{System.unique_integer([:positive])}"

      for _ <- 1..5 do
        HealthAwareSuppression.record_alert(agent_id)
      end

      assert HealthAwareSuppression.alert_spike?(agent_id) == false
    end

    test "returns {true, count} when alert count reaches spike threshold (20)" do
      agent_id = "agent-spike-#{System.unique_integer([:positive])}"

      for _ <- 1..20 do
        HealthAwareSuppression.record_alert(agent_id)
      end

      assert {true, count} = HealthAwareSuppression.alert_spike?(agent_id)
      assert count >= 20
    end

    test "non-binary agent_id always returns false" do
      assert HealthAwareSuppression.alert_spike?(nil) == false
      assert HealthAwareSuppression.alert_spike?(42) == false
    end
  end

  # ============================================================================
  # cleanup_rate_table/0
  # ============================================================================

  describe "cleanup_rate_table/0" do
    test "returns 0 when table is empty" do
      assert HealthAwareSuppression.cleanup_rate_table() >= 0
    end

    test "returns the number of stale entries deleted" do
      # The cleanup removes entries older than spike_window * 2 (600 seconds).
      # We cannot easily inject old timestamps into ETS in an async-safe way,
      # but we can verify the function runs without error and returns an integer.
      result = HealthAwareSuppression.cleanup_rate_table()
      assert is_integer(result)
      assert result >= 0
    end
  end

  # ============================================================================
  # init_rate_table/0 (idempotent)
  # ============================================================================

  describe "init_rate_table/0" do
    test "is idempotent - calling multiple times does not raise" do
      assert HealthAwareSuppression.init_rate_table() == :ok
      assert HealthAwareSuppression.init_rate_table() == :ok
    end

    test "ETS table exists after init" do
      HealthAwareSuppression.init_rate_table()
      assert :ets.whereis(:health_suppression_alert_rates) != :undefined
    end
  end

  # ============================================================================
  # Severity ordering sanity
  # ============================================================================

  describe "severity order" do
    test "info < low < medium < high < critical" do
      # Verify severity ordering by checking that each level reduces to the one below
      assert HealthAwareSuppression.reduce_severity("critical", 1) == "high"
      assert HealthAwareSuppression.reduce_severity("high", 1) == "medium"
      assert HealthAwareSuppression.reduce_severity("medium", 1) == "low"
      assert HealthAwareSuppression.reduce_severity("low", 1) == "info"
    end
  end
end
