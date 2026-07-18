defmodule TamanduaServer.LiveResponse.ScreenCaptureArtifactsTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.LiveResponse.ScreenCaptureArtifacts

  @png <<137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82>>

  test "accepts only bounded image/png with exact signature and matching sha256" do
    sha256 = :crypto.hash(:sha256, @png) |> Base.encode16(case: :lower)

    assert :ok = ScreenCaptureArtifacts.validate_payload("image/png", sha256, @png)

    assert {:error, :unsupported_mime} =
             ScreenCaptureArtifacts.validate_payload("image/jpeg", sha256, @png)

    assert {:error, :invalid_png} =
             ScreenCaptureArtifacts.validate_payload("image/png", sha256, "not-a-png")

    assert {:error, :sha256_mismatch} =
             ScreenCaptureArtifacts.validate_payload("image/png", String.duplicate("0", 64), @png)
  end

  test "rejects an upload above 8 MiB before accepting its digest" do
    oversized = <<137, 80, 78, 71, 13, 10, 26, 10>> <> :binary.copy(<<0>>, 8_388_601)
    sha256 = :crypto.hash(:sha256, oversized) |> Base.encode16(case: :lower)

    assert {:error, :upload_too_large} =
             ScreenCaptureArtifacts.validate_payload("image/png", sha256, oversized)
  end

  test "idempotent ready retry requires the exact digest and size" do
    sha256 = :crypto.hash(:sha256, @png) |> Base.encode16(case: :lower)
    artifact = %{sha256: sha256, size: byte_size(@png)}

    assert ScreenCaptureArtifacts.idempotent_ready_match?(artifact, sha256, @png)

    refute ScreenCaptureArtifacts.idempotent_ready_match?(
             artifact,
             String.duplicate("0", 64),
             @png
           )

    refute ScreenCaptureArtifacts.idempotent_ready_match?(
             %{artifact | size: byte_size(@png) + 1},
             sha256,
             @png
           )
  end

  test "accepts only a configured HTTPS or loopback HTTP upload base URL" do
    previous = System.get_env("TAMANDUA_SCREEN_CAPTURE_UPLOAD_BASE_URL")

    on_exit(fn ->
      if previous do
        System.put_env("TAMANDUA_SCREEN_CAPTURE_UPLOAD_BASE_URL", previous)
      else
        System.delete_env("TAMANDUA_SCREEN_CAPTURE_UPLOAD_BASE_URL")
      end
    end)

    System.put_env("TAMANDUA_SCREEN_CAPTURE_UPLOAD_BASE_URL", "http://remote.example.test")
    assert {:error, :unsafe_screen_capture_upload_url} = ScreenCaptureArtifacts.upload_base_url()

    System.put_env(
      "TAMANDUA_SCREEN_CAPTURE_UPLOAD_BASE_URL",
      "https://attacker@example.test"
    )

    assert {:error, :unsafe_screen_capture_upload_url} = ScreenCaptureArtifacts.upload_base_url()

    System.put_env(
      "TAMANDUA_SCREEN_CAPTURE_UPLOAD_BASE_URL",
      "https://agents.example.test/#unexpected-fragment"
    )

    assert {:error, :unsafe_screen_capture_upload_url} = ScreenCaptureArtifacts.upload_base_url()

    System.put_env(
      "TAMANDUA_SCREEN_CAPTURE_UPLOAD_BASE_URL",
      "https://agents.example.test:8443/untrusted/path?ignored=true"
    )

    assert {:ok, "https://agents.example.test:8443"} =
             ScreenCaptureArtifacts.upload_base_url()

    System.put_env("TAMANDUA_SCREEN_CAPTURE_UPLOAD_BASE_URL", "http://127.0.0.1:4000")
    assert {:ok, "http://127.0.0.1:4000"} = ScreenCaptureArtifacts.upload_base_url()
  end
end
