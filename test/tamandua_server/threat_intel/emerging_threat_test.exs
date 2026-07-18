defmodule TamanduaServer.ThreatIntel.EmergingThreatTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.ThreatIntel.EmergingThreat
  alias TamanduaServer.ThreatIntel.EmergingThreats

  @valid_attrs %{
    "id" => "ET-2026-0001",
    "title" => "Active exploitation of exposed inference gateway",
    "summary" => "Multiple sources report active exploitation against public gateway deployments.",
    "category" => "ai_runtime",
    "status" => "monitoring",
    "severity" => "high",
    "confidence" => 0.82,
    "sources" => [
      %{name: "internal", active_exploitation: true},
      %{name: "vendor-advisory", tags: ["observed in the wild"]},
      %{name: "osint"}
    ],
    "iocs" => [%{type: "domain", value: "example-c2.test"}],
    "ttps" => ["T1190"],
    "affected_products" => ["Tamandua Gateway"],
    "first_seen" => "2026-07-10T00:00:00Z",
    "last_seen" => "2026-07-13T00:00:00Z",
    "exploit_maturity" => "exploited",
    "local_relevance_score" => 90,
    "recommended_hunts" => ["Search gateway logs for anomalous tool calls"],
    "recommended_actions" => ["Restrict public gateway exposure"],
    "coverage_gaps" => ["No endpoint rule for suspicious gateway child processes"]
  }

  describe "new/1" do
    test "normalizes a pure serializable contract" do
      assert {:ok, threat} = EmergingThreat.new(@valid_attrs)

      assert threat.id == "ET-2026-0001"
      assert threat.status == "monitoring"
      assert threat.confidence == 0.82
      assert length(threat.sources) == 3

      assert MapSet.new(EmergingThreat.fields()) ==
               MapSet.new(Map.keys(EmergingThreat.to_map(threat)))
    end

    test "validates required fields and bounded scoring inputs" do
      assert {:error, errors} =
               EmergingThreat.new(%{
                 id: "",
                 title: "Missing body",
                 summary: nil,
                 category: "ai_runtime",
                 confidence: 1.4,
                 local_relevance_score: 120,
                 exploit_maturity: "rumored"
               })

      assert errors.id == "is required"
      assert errors.summary == "is required"
      assert errors.confidence == "must be between 0.0 and 1.0"
      assert errors.local_relevance_score == "must be between 0 and 100"
      assert String.starts_with?(errors.exploit_maturity, "must be one of:")
    end
  end

  describe "score/1" do
    test "combines maturity, confidence, local relevance, source count, and active hints" do
      {:ok, threat} = EmergingThreat.new(@valid_attrs)

      assert %{
               score: 85,
               score_breakdown: %{
                 exploit_maturity: 85,
                 confidence: 82,
                 local_relevance: 90,
                 source_count: 60,
                 active_exploitation_hints: 100
               }
             } = EmergingThreat.score(threat)
    end

    test "is deterministic for the same normalized input" do
      {:ok, threat} = EmergingThreat.new(@valid_attrs)

      assert EmergingThreat.score(threat) == EmergingThreat.score(threat)
    end

    test "can serialize with score without adding score fields to the struct" do
      {:ok, threat} = EmergingThreat.new(@valid_attrs)

      serialized = EmergingThreat.to_json_map(threat, include_score: true)

      assert serialized["score"] == 85
      assert serialized["score_breakdown"]["weights"]["confidence"] == 0.2
      refute Map.has_key?(threat, :score)
    end
  end

  describe "EmergingThreats context" do
    test "normalizes many records and reports invalid indexes" do
      assert {:error, [%{index: 1, errors: errors}]} =
               EmergingThreats.normalize_many([@valid_attrs, Map.delete(@valid_attrs, "id")])

      assert errors.id == "is required"
    end

    test "ranks highest score first with stable id tie-breaker" do
      lower =
        @valid_attrs
        |> Map.merge(%{
          "id" => "ET-2026-0002",
          "summary" => "Proof of concept only.",
          "sources" => [%{name: "osint"}],
          "exploit_maturity" => "poc",
          "local_relevance_score" => 20,
          "confidence" => 0.4
        })

      assert [%{id: "ET-2026-0001"}, %{id: "ET-2026-0002"}] =
               EmergingThreats.rank([lower, @valid_attrs])
    end
  end
end
