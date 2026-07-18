defmodule TamanduaServer.Workers.ScreenCaptureRetentionWorkerTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.LiveResponse.{ScreenCaptureArtifact, ScreenCaptureArtifacts}
  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.Workers.ScreenCaptureRetentionWorker

  @png <<137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82>>

  test "scheduled cleanup erases expired bytes and upload credentials tenant by tenant" do
    organization = insert(:organization)
    agent = insert(:agent, organization: organization)

    {:ok, artifact, upload_token} =
      ScreenCaptureArtifacts.create(organization.id, agent.id, 300)

    sha256 = :crypto.hash(:sha256, @png) |> Base.encode16(case: :lower)

    assert {:ok, ready} =
             ScreenCaptureArtifacts.upload(
               artifact.id,
               upload_token,
               "image/png",
               sha256,
               DateTime.utc_now() |> DateTime.to_iso8601(),
               @png
             )

    MultiTenant.with_organization(organization.id, fn ->
      ready
      |> Ecto.Changeset.change(expires_at: DateTime.add(DateTime.utc_now(), -1, :second))
      |> Repo.update!()
    end)

    assert {:ok, organization_ids} =
             ScreenCaptureRetentionWorker.organizations_due_for_cleanup()

    assert organization.id in organization_ids
    assert :ok = ScreenCaptureRetentionWorker.perform(%Oban.Job{args: %{}})

    cleaned =
      MultiTenant.with_bypass(fn -> Repo.get!(ScreenCaptureArtifact, artifact.id) end)

    assert cleaned.status == "expired"
    assert cleaned.content == nil
    assert cleaned.upload_token_hash == nil
    assert cleaned.failure_reason == "artifact_ttl_expired"
  end

  test "rejects jobs with arguments so artifacts and credentials never enter job payloads" do
    assert {:discard, :unexpected_arguments} =
             ScreenCaptureRetentionWorker.perform(%Oban.Job{args: %{"artifact_id" => "nope"}})
  end
end
