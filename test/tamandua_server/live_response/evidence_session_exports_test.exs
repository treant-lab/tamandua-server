defmodule TamanduaServer.LiveResponse.EvidenceSessionExportsTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.LiveResponse.{
    EvidenceSession,
    EvidenceSessionExports,
    ScreenCaptureArtifact
  }

  test "package manifest has entry hashes and excludes capture credentials" do
    content = <<137, 80, 78, 71, 13, 10, 26, 10, 1, 2, 3>>
    digest = :crypto.hash(:sha256, content) |> Base.encode16(case: :lower)

    session = %EvidenceSession{
      id: Ecto.UUID.generate(),
      organization_id: Ecto.UUID.generate(),
      agent_id: Ecto.UUID.generate(),
      reason: "IR evidence",
      status: "completed",
      frame_count: 2,
      interval_seconds: 5,
      capture_request: %{"upload" => %{"token" => "must-not-export"}},
      artifacts: [
        %ScreenCaptureArtifact{
          id: Ecto.UUID.generate(),
          frame_index: 0,
          status: "ready",
          content: content,
          size: byte_size(content),
          sha256: digest,
          captured_at: ~U[2026-07-15 12:00:00.000000Z]
        }
      ]
    }

    assert {:ok, zip} =
             EvidenceSessionExports.build_package(session, %{process: %{state: "not_observed"}})

    assert {:ok, entries} = :zip.extract(zip, [:memory])
    manifest = entries |> Map.new() |> Map.fetch!(~c"manifest.json") |> Jason.decode!()

    assert get_in(manifest, ["frames", Access.at(0), "sha256"]) == digest
    refute inspect(manifest) =~ "must-not-export"
    assert Map.has_key?(Map.fetch!(manifest, "session"), "alert_id")
  end
end
