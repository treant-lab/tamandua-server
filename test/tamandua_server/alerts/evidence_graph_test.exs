defmodule TamanduaServer.Alerts.EvidenceGraphTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Alerts.EvidenceGraph

  test "builds canonical entities, lineage edges and executable pivots" do
    alert = %{
      id: "alert-1",
      title: "Suspicious process tree",
      severity: "high",
      source_event_id: "event-1",
      agent_id: "agent-1",
      detection_metadata: %{rule_id: "rule-7", rule_name: "Encoded PowerShell"},
      evidence: %{
        process: %{pid: 200, ppid: 100, name: "powershell.exe", sha256: "proc-hash"},
        user: %{name: "alice", sid: "S-1-5-21"},
        file: %{path: "C:\\Temp\\payload.ps1", sha256: "file-hash"},
        network: [%{remote_ip: "203.0.113.9", domain: "c2.example"}],
        detection: %{rule_id: "rule-7"}
      },
      process_chain: [
        %{pid: 100, name: "cmd.exe"},
        %{pid: 200, ppid: 100, name: "powershell.exe", sha256: "proc-hash"}
      ],
      raw_event: %{event_type: "process_start"}
    }

    graph = EvidenceGraph.build(alert)

    assert graph.schema == "tamandua.alert.evidence_graph/v1"
    assert graph.claimable
    assert Enum.any?(graph.nodes, &(&1.id == "asset:agent-1"))
    assert Enum.any?(graph.nodes, &(&1.id == "process:200"))
    assert Enum.any?(graph.nodes, &(&1.id == "network:203.0.113.9"))

    assert Enum.any?(
             graph.edges,
             &(&1.from == "process:100" and &1.to == "process:200" and
                 &1.relationship == "spawned")
           )

    assert Enum.any?(graph.pivots, &(&1.field == "remote_ip" and &1.value == "203.0.113.9"))
    assert Enum.any?(graph.pivots, &(&1.field == "file_sha256" and &1.value == "file-hash"))
  end

  test "keeps synthetic sparse alerts explicit and does not invent pivots" do
    graph = EvidenceGraph.build(%{id: "alert-sparse", raw_event: %{payload: "display-only"}})

    refute graph.claimable
    assert graph.evidence_quality.quality == "synthetic"

    assert graph.nodes == [
             %{
               id: "alert:alert-sparse",
               type: "alert",
               label: "alert-sparse",
               attributes: %{title: nil, severity: nil}
             }
           ]

    assert graph.pivots == []
    assert "source_event_id" in graph.gaps
  end
end
