defmodule TamanduaServer.LiveResponse.EvidenceSessionTenantConstraintsTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.LiveResponse.{
    EvidenceSession,
    EvidenceSessionDiff,
    EvidenceSessionExport,
    ScreenCaptureArtifact
  }

  @now ~U[2026-07-15 18:00:00.000000Z]

  test "database rejects an alert link owned by another tenant" do
    owner = insert(:organization)
    other = insert(:organization)
    agent = insert(:agent, organization: owner)
    alert = insert(:alert, organization: other)

    error =
      assert_raise Postgrex.Error, fn ->
        Repo.insert_all(EvidenceSession, [
          session_row(owner.id, agent.id, alert_id: alert.id)
        ])
      end

    assert error.postgres.constraint == "evidence_sessions_alert_tenant_fkey"
  end

  test "database rejects an artifact whose tenant or agent differs from its session" do
    owner = insert(:organization)
    other = insert(:organization)
    owner_agent = insert(:agent, organization: owner)
    other_agent = insert(:agent, organization: other)
    session = insert_session(owner.id, owner_agent.id)

    error =
      assert_raise Postgrex.Error, fn ->
        Repo.insert_all(ScreenCaptureArtifact, [
          artifact_row(other.id, other_agent.id, session.id, 0)
        ])
      end

    assert error.postgres.constraint ==
             "screen_capture_artifacts_session_tenant_agent_fkey"
  end

  test "database rejects an export assigned to a different tenant than its session" do
    owner = insert(:organization)
    other = insert(:organization)
    agent = insert(:agent, organization: owner)
    session = insert_session(owner.id, agent.id)

    error =
      assert_raise Postgrex.Error, fn ->
        Repo.insert_all(EvidenceSessionExport, [
          %{
            id: Ecto.UUID.generate(),
            organization_id: other.id,
            evidence_session_id: session.id,
            sha256: String.duplicate("a", 64),
            size: 1,
            content: <<0>>,
            expires_at: DateTime.add(@now, 3_600),
            inserted_at: @now,
            updated_at: @now
          }
        ])
      end

    assert error.postgres.constraint == "evidence_session_exports_session_tenant_fkey"
  end

  test "database rejects a diff containing an artifact from another evidence session" do
    organization = insert(:organization)
    agent = insert(:agent, organization: organization)
    left_session = insert_session(organization.id, agent.id)
    right_session = insert_session(organization.id, agent.id)
    left = insert_artifact(organization.id, agent.id, left_session.id, 0)
    right = insert_artifact(organization.id, agent.id, right_session.id, 0)

    error =
      assert_raise Postgrex.Error, fn ->
        Repo.insert_all(EvidenceSessionDiff, [
          %{
            id: Ecto.UUID.generate(),
            organization_id: organization.id,
            evidence_session_id: left_session.id,
            left_artifact_id: left.id,
            right_artifact_id: right.id,
            metrics: %{"changed_pixel_ratio" => 0.0},
            expires_at: DateTime.add(@now, 3_600),
            inserted_at: @now,
            updated_at: @now
          }
        ])
      end

    assert error.postgres.constraint == "evidence_session_diffs_right_artifact_scope_fkey"
  end

  test "session artifacts require session id and frame index together" do
    organization = insert(:organization)
    agent = insert(:agent, organization: organization)
    session = insert_session(organization.id, agent.id)

    error =
      assert_raise Postgrex.Error, fn ->
        Repo.insert_all(ScreenCaptureArtifact, [
          artifact_row(organization.id, agent.id, session.id, nil)
        ])
      end

    assert error.postgres.constraint == "screen_capture_artifacts_session_frame_pair_check"
  end

  defp insert_session(organization_id, agent_id) do
    %EvidenceSession{}
    |> EvidenceSession.create_changeset(session_row(organization_id, agent_id))
    |> Repo.insert!()
  end

  defp insert_artifact(organization_id, agent_id, session_id, frame_index) do
    %ScreenCaptureArtifact{}
    |> ScreenCaptureArtifact.create_changeset(
      artifact_row(organization_id, agent_id, session_id, frame_index)
    )
    |> Repo.insert!()
  end

  defp session_row(organization_id, agent_id, extra \\ []) do
    Map.merge(
      %{
        id: Ecto.UUID.generate(),
        organization_id: organization_id,
        agent_id: agent_id,
        status: "scheduled",
        reason: "Tenant relationship validation",
        capture_request: %{"display" => "all"},
        frame_count: 2,
        interval_seconds: 5,
        next_frame_index: 0,
        approval_status: "not_required",
        expires_at: DateTime.add(@now, 900),
        inserted_at: @now,
        updated_at: @now
      },
      Map.new(extra)
    )
  end

  defp artifact_row(organization_id, agent_id, session_id, frame_index) do
    %{
      id: Ecto.UUID.generate(),
      organization_id: organization_id,
      agent_id: agent_id,
      evidence_session_id: session_id,
      frame_index: frame_index,
      status: "pending",
      display: "all",
      expires_at: DateTime.add(@now, 900),
      upload_token_hash: :crypto.hash(:sha256, Ecto.UUID.generate()),
      inserted_at: @now,
      updated_at: @now
    }
  end
end
