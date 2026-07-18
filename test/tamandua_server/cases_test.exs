defmodule TamanduaServer.CasesTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Cases
  alias TamanduaServer.Investigations.CaseInvestigation

  test "projects linked alert evidence and SLA into a canonical case" do
    due_at = DateTime.add(DateTime.utc_now(), 3_600, :second)

    investigation = %CaseInvestigation{
      id: Ecto.UUID.generate(),
      title: "Credential compromise",
      status: "in_progress",
      severity: "high",
      assigned_to: Ecto.UUID.generate(),
      assigned_user: nil,
      created_by: Ecto.UUID.generate(),
      creator: nil,
      alert_ids: [],
      event_ids: [],
      timeline: %{},
      tags: ["identity"],
      mitre_tactics: ["credential-access"],
      mitre_techniques: ["T1003"]
    }

    alert = %Alert{
      id: Ecto.UUID.generate(),
      title: "Credential dumping",
      status: "new",
      severity: "high",
      evidence: %{"process" => %{"name" => "procdump.exe"}},
      process_chain: [%{"pid" => 42}],
      event_ids: [Ecto.UUID.generate()],
      sla_resolve_deadline: due_at,
      sla_resolve_breached: false
    }

    view = Cases.build_view(investigation, [alert])

    assert view.kind == "security_case"
    assert view.owner == %{id: investigation.assigned_to}
    assert [%{source_type: "alert", source_id: alert_id, evidence: evidence}] = view.evidence
    assert alert_id == alert.id
    assert evidence == alert.evidence
    assert view.sla.state == "derived_from_alerts"
    assert view.sla.due_at == due_at
  end

  test "marks capabilities without durable storage as unavailable" do
    investigation = %CaseInvestigation{
      id: Ecto.UUID.generate(),
      title: "Unscoped malware case",
      status: "open",
      severity: "medium",
      assigned_user: nil,
      creator: nil,
      alert_ids: [],
      event_ids: [],
      timeline: %{}
    }

    view = Cases.build_view(investigation, [])

    assert view.tasks == %{state: "unavailable", reason: "case_tasks_not_persisted", items: []}
    assert view.audit.state == "unavailable"
    assert view.sla.state == "unavailable"
  end
end
