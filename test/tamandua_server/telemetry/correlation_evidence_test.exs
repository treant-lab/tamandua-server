defmodule TamanduaServer.Telemetry.CorrelationEvidenceTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Telemetry.CorrelationEvidence
  alias TamanduaServer.Telemetry.CorrelationScoringPolicy
  alias TamanduaServer.Telemetry.EventContract
  alias TamanduaServer.CorrelationDatasets

  test "temporal-only proximity does not create correlation" do
    left = event("process_create", %{pid: 100, process_name: "cmd.exe"}, "agent-a")
    right = event("process_create", %{pid: 200, process_name: "powershell.exe"}, "agent-b")

    assert %{score: 0, sharedEntities: []} = CorrelationEvidence.score_pair(left, right)
  end

  test "same severity does not create correlation" do
    left = event("file_create", %{path: "/tmp/a"}, "agent-a")
    right = event("network_connect", %{remote_ip: "8.8.8.8"}, "agent-b")

    assert %{score: 0, sharedEntities: []} = CorrelationEvidence.score_pair(left, right)
  end

  test "MITRE-only overlap does not create correlation" do
    left = event("alert", %{mitre_techniques: ["T1059"]}, "agent-a")
    right = event("alert", %{mitre_techniques: ["T1059"]}, "agent-b")

    assert %{score: 0, sharedEntities: []} = CorrelationEvidence.score_pair(left, right)
  end

  test "versioned scoring suppresses context-only evidence" do
    scoring =
      CorrelationScoringPolicy.score([
        %{type: "temporal", score: 10, reason: "within 5 minutes"},
        %{type: "mitre", score: 15, reason: "same MITRE technique"},
        %{type: "remote_ip_private", score: 15, reason: "same private remote ip on same agent"}
      ])

    assert scoring.version == "correlation-scoring/v2"
    assert scoring.rawScore == 40
    assert scoring.score == 0
    assert scoring.decision == "context_only"
    assert scoring.suppressedEvidence != []
  end

  test "score_pair exposes the scoring version" do
    [left, right] = CorrelationDatasets.strong_hash()

    assert %{scoringVersion: "correlation-scoring/v2"} =
             CorrelationEvidence.score_pair(left, right)
  end

  test "common SaaS domains do not create strong correlation by themselves" do
    [left, right] = CorrelationDatasets.benign_saas()

    assert %{score: score, sharedEntities: entities} = CorrelationEvidence.score_pair(left, right)
    assert score < 40
    assert entities in [[], ["domain"]]
    assert CorrelationEvidence.correlate_events([left, right]).correlations == []
  end

  test "noisy temp paths are weak context below default correlation threshold" do
    [left, right] = CorrelationDatasets.noisy_temp()

    assert %{score: score, sharedEntities: entities} = CorrelationEvidence.score_pair(left, right)
    assert score < 40
    assert "file_path" in entities
    assert CorrelationEvidence.correlate_events([left, right]).correlations == []
  end

  test "rare shared domain remains correlation evidence" do
    [left, right] = CorrelationDatasets.strong_domain()

    assert %{score: score, sharedEntities: entities} = CorrelationEvidence.score_pair(left, right)
    assert score >= 40
    assert "domain" in entities
  end

  test "private remote ip is weak cross-agent context only" do
    left = event("network_connect", %{remote_ip: "192.168.1.10", remote_port: 443}, "agent-a")
    right = event("network_connect", %{remote_ip: "192.168.1.10", remote_port: 443}, "agent-b")

    assert %{score: 0, sharedEntities: []} = CorrelationEvidence.score_pair(left, right)
  end

  test "same private remote ip on same agent does not become strong evidence" do
    left = event("network_connect", %{remote_ip: "192.168.1.10", remote_port: 443}, "agent-a")
    right = event("network_connect", %{remote_ip: "192.168.1.10", remote_port: 443}, "agent-a")

    assert %{score: 0, sharedEntities: [], relationTypes: relation_types} =
             CorrelationEvidence.score_pair(left, right)

    assert "remote_ip_private" in relation_types
  end

  test "sha256 remains strong correlation evidence" do
    [left, right] = CorrelationDatasets.strong_hash()

    assert %{score: score, sharedEntities: entities} = CorrelationEvidence.score_pair(left, right)
    assert score >= 50
    assert "file_hash" in entities
  end

  test "same-agent parent child process chain is strong correlation evidence" do
    [left, right] = CorrelationDatasets.process_chain()

    assert %{score: score, sharedEntities: entities, relationTypes: relation_types} =
             CorrelationEvidence.score_pair(left, right)

    assert score >= 40
    assert "process_tree" in entities
    assert "process_tree" in relation_types
  end

  test "correlate_events filters weak pairs and keeps strong evidence" do
    result = CorrelationEvidence.correlate_events(CorrelationDatasets.mixed())

    linked_ids =
      result.correlations
      |> Enum.flat_map(fn link -> [link.source, link.target] end)
      |> MapSet.new()

    assert Enum.any?(result.correlations, &("file_hash" in &1.sharedEntities))
    assert Enum.any?(result.correlations, &("process_tree" in &1.sharedEntities))
    refute "saas-1" in linked_ids
    refute "saas-2" in linked_ids
    refute "temp-1" in linked_ids
    refute "temp-2" in linked_ids
    refute "mitre-1" in linked_ids
    refute "mitre-2" in linked_ids
  end

  test "correlate_events returns scoring metadata and a lightweight entity graph" do
    [left, right] = CorrelationDatasets.strong_hash()
    sha256 = left.payload.sha256

    result = CorrelationEvidence.correlate_events([left, right])

    assert result.scoring_version == "correlation-scoring/v2"
    assert result.entity_graph.scoringVersion == "correlation-scoring/v2"
    assert Enum.any?(result.entity_graph.nodes, &(&1.id == "entity:file_hash:#{sha256}"))

    assert Enum.count(result.entity_graph.edges, &(&1.target == "entity:file_hash:#{sha256}")) ==
             2
  end

  test "correlate_events builds incident and campaign candidates from strong components" do
    sha256 = String.duplicate("e", 64)

    events = [
      event("file_create", %{sha256: sha256}, "agent-a"),
      event("file_create", %{sha256: sha256}, "agent-b"),
      event("file_create", %{sha256: sha256}, "agent-c")
    ]

    result = CorrelationEvidence.correlate_events(events)

    assert [%{eventCount: 3, supportingEntities: ["file_hash"]}] = result.incident_candidates
    assert [%{eventCount: 3, campaignSignals: signals}] = result.campaign_candidates
    assert "multi_event_cluster" in signals
  end

  test "event contract marks network telemetry as correlation ready when core fields exist" do
    summary =
      event("network_connect", %{
        remote_ip: "8.8.8.8",
        remote_port: 443,
        protocol: "tcp",
        pid: 123,
        process_name: "curl"
      })
      |> EventContract.summarize()

    assert summary["schema_version"] == "telemetry-contract/v1"
    assert summary["category"] == "network"
    assert summary["correlation_ready"] == true
    assert summary["quality"].level in ["good", "partial"]
  end

  test "event contract exposes missing fields for incomplete telemetry" do
    summary = event("network_connect", %{remote_ip: "8.8.8.8"}) |> EventContract.summarize()

    assert summary["category"] == "network"
    assert summary["correlation_ready"] == false
    assert "network.remote_port" in summary["quality"].missing
    assert "process.pid" in summary["quality"].missing
  end

  defp event(event_type, payload, agent_id \\ "agent-a") do
    %{
      id: Ecto.UUID.generate(),
      agent_id: agent_id,
      event_type: event_type,
      timestamp: DateTime.utc_now(),
      severity: "info",
      payload: payload,
      enrichment: %{},
      detections: []
    }
  end
end
