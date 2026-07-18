defmodule TamanduaServer.LiveResponse.EvidenceSessionTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.LiveResponse.EvidenceSession

  @valid %{
    organization_id: "c9af14e1-b4ba-44f4-b2f6-bc813268f03d",
    agent_id: "a3a2ff20-dd9f-4894-934d-97e7bcccf2e8",
    status: "scheduled",
    reason: "IR-42 visual evidence",
    capture_request: %{"scope" => "virtual_desktop"},
    frame_count: 3,
    interval_seconds: 10,
    expires_at: ~U[2026-07-15 12:20:00.000000Z]
  }

  test "accepts only bounded snapshot sequences" do
    assert EvidenceSession.create_changeset(%EvidenceSession{}, @valid).valid?

    refute EvidenceSession.create_changeset(%EvidenceSession{}, %{@valid | frame_count: 1}).valid?

    refute EvidenceSession.create_changeset(%EvidenceSession{}, %{@valid | frame_count: 11}).valid?

    refute EvidenceSession.create_changeset(%EvidenceSession{}, %{
             @valid
             | interval_seconds: 61
           }).valid?
  end

  test "supports an honest partial terminal state" do
    changeset =
      EvidenceSession.create_changeset(%EvidenceSession{}, %{@valid | status: "partial"})

    assert changeset.valid?
  end

  test "allows a conservatively bounded long session only in the approval lane" do
    long =
      Map.merge(@valid, %{
        status: "pending_approval",
        approval_status: "pending",
        approval_expires_at: ~U[2026-07-15 12:15:00.000000Z],
        frame_count: 30,
        interval_seconds: 60
      })

    assert EvidenceSession.create_changeset(%EvidenceSession{}, long).valid?

    refute EvidenceSession.create_changeset(%EvidenceSession{}, %{
             long
             | frame_count: 31
           }).valid?

    refute EvidenceSession.create_changeset(%EvidenceSession{}, %{
             long
             | frame_count: 30,
               interval_seconds: 61
           }).valid?
  end
end
