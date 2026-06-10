defmodule TamanduaServer.Detection.CollectorCoverageTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Detection.CollectorCoverage

  describe "matrix/0" do
    test "contains required collector-specific and core collectors" do
      collectors =
        CollectorCoverage.matrix()
        |> Enum.map(& &1.collector)
        |> MapSet.new()

      required_collectors =
        ~w(
          ebpf
          auditd
          endpoint_security
          network_dpi
          identity
          amsi
          etw
          process
          file
          registry
          network
          dns
        )a

      assert MapSet.subset?(MapSet.new(required_collectors), collectors)
    end

    test "returns deterministic entries with coverage metadata" do
      matrix = CollectorCoverage.matrix()

      assert matrix == Enum.sort_by(matrix, &{to_string(&1.collector), &1.tactic_id, &1.technique_id})

      assert Enum.all?(matrix, fn entry ->
               is_atom(entry.collector) and
                 is_list(entry.profiles) and
                 entry.coverage_level in [:strong, :moderate, :partial] and
                 is_binary(entry.tactic_id) and
                 String.starts_with?(entry.tactic_id, "TA") and
                 is_binary(entry.technique_id) and
                 String.starts_with?(entry.technique_id, "T") and
                 is_list(entry.telemetry_requirements) and
                 entry.telemetry_requirements != []
             end)
    end
  end

  describe "for_collector/1" do
    test "filters by normalized collector name" do
      assert CollectorCoverage.for_collector("network-dpi") ==
               CollectorCoverage.for_collector(:network_dpi)

      entries = CollectorCoverage.for_collector("NETWORK_DPI")

      assert Enum.map(entries, & &1.collector) |> Enum.uniq() == [:network_dpi]
      assert Enum.any?(entries, &(&1.technique_id == "T1071.001"))
      assert Enum.any?(entries, &(:tls_fingerprint in &1.telemetry_requirements))
    end

    test "returns an empty list for unknown collectors" do
      assert CollectorCoverage.for_collector(:unknown_collector) == []
      assert CollectorCoverage.for_collector("missing-collector") == []
    end
  end

  describe "for_profile/1" do
    test "returns collectors enabled by a profile" do
      entries = CollectorCoverage.for_profile("windows")
      collectors = entries |> Enum.map(& &1.collector) |> MapSet.new()

      assert :amsi in collectors
      assert :etw in collectors
      assert :identity in collectors
      refute :ebpf in collectors
    end

    test "full profile includes every static entry" do
      assert CollectorCoverage.for_profile(:full) == CollectorCoverage.matrix()
    end
  end

  describe "summary/1" do
    test "summarizes a collector scope" do
      summary = CollectorCoverage.summary({:collector, :amsi})

      assert summary.collectors == [:amsi]
      assert summary.collector_count == 1
      assert summary.entry_count == 2
      assert summary.technique_count == 2
      assert "TA0002" in summary.tactics
      assert "T1059.001" in summary.techniques
      assert summary.by_coverage_level.strong == 1
      assert summary.by_coverage_level.moderate == 1
      assert summary.by_coverage_level.partial == 0
    end

    test "summarizes a profile scope from maps" do
      summary = CollectorCoverage.summary(%{"profile" => "identity"})

      assert :identity in summary.profiles
      assert :identity in summary.collectors
      assert :ad_monitor in summary.collectors
      assert "TA0006" in summary.tactics
      assert summary.entry_count == length(CollectorCoverage.for_profile(:identity))
    end

    test "summarizes all coverage by default" do
      summary = CollectorCoverage.summary()

      assert summary.entry_count == length(CollectorCoverage.matrix())
      assert summary.collector_count > 10
      assert summary.profile_count > 1
      assert summary.technique_count <= summary.entry_count
    end
  end
end
