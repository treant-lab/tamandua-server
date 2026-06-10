defmodule TamanduaServer.CorrelationDatasets do
  @moduledoc """
  Pure telemetry datasets for correlation false-positive guard tests.
  """

  @base_time ~U[2026-05-15 12:00:00Z]
  @sha256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

  def benign_saas do
    [
      event("saas-1", "dns_query", %{domain: "api.spotify.com"}, "agent-a", 0),
      event("saas-2", "dns_query", %{domain: "api.spotify.com"}, "agent-b", 20)
    ]
  end

  def noisy_temp do
    [
      event("temp-1", "file_create", %{file_path: "/tmp/cache/session.bin"}, "agent-a", 0),
      event("temp-2", "file_create", %{file_path: "/tmp/cache/session.bin"}, "agent-a", 20)
    ]
  end

  def shared_mitre_only do
    [
      event("mitre-1", "alert", %{mitre_techniques: ["T1059"]}, "agent-a", 0),
      event("mitre-2", "alert", %{mitre_techniques: ["T1059"]}, "agent-b", 20)
    ]
  end

  def strong_hash do
    [
      event("hash-1", "file_create", %{sha256: @sha256}, "agent-a", 0),
      event("hash-2", "file_create", %{sha256: @sha256}, "agent-b", 20)
    ]
  end

  def strong_domain do
    [
      event("domain-1", "dns_query", %{domain: "c2.example-malware.test"}, "agent-a", 0),
      event("domain-2", "dns_query", %{domain: "c2.example-malware.test"}, "agent-b", 2)
    ]
  end

  def process_chain do
    [
      event(
        "chain-1",
        "process_create",
        %{pid: 4_200, ppid: 100, process_name: "cmd.exe", user: "alice"},
        "agent-a",
        0
      ),
      event(
        "chain-2",
        "process_create",
        %{pid: 4_300, ppid: 4_200, process_name: "powershell.exe", user: "alice"},
        "agent-a",
        2
      )
    ]
  end

  def mixed do
    benign_saas() ++ noisy_temp() ++ shared_mitre_only() ++ strong_hash() ++ process_chain()
  end

  def sha256, do: @sha256

  def event(id, event_type, payload, agent_id \\ "agent-a", offset_minutes \\ 0) do
    %{
      id: id,
      agent_id: agent_id,
      event_type: event_type,
      timestamp: DateTime.add(@base_time, offset_minutes, :minute),
      severity: "info",
      payload: payload,
      enrichment: %{},
      detections: []
    }
  end
end
