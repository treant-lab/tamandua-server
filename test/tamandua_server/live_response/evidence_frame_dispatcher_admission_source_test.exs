defmodule TamanduaServer.LiveResponse.EvidenceFrameDispatcherAdmissionSourceTest do
  use ExUnit.Case, async: true

  @source Path.expand(
            "../../../lib/tamandua_server/live_response/evidence_frame_dispatcher.ex",
            __DIR__
          )

  test "uses the shared admission authority before creating an artifact" do
    source = File.read!(@source)
    admission = :binary.match(source, "ScreenCaptureAdmission.authorize")
    artifact = :binary.match(source, "ScreenCaptureArtifacts.create(")

    assert admission != :nomatch
    assert artifact != :nomatch
    assert elem(admission, 0) < elem(artifact, 0)
    assert source =~ "Registry.same_canonical_organization_id?("
    refute source =~ "to_string(runtime[:organization_id])"
  end
end
