defmodule TamanduaServer.LiveResponse.EvidenceSessionAndroidMobileTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Agents.Policy

  alias TamanduaServer.LiveResponse.{
    EvidenceFrameDispatcher,
    EvidenceSession,
    EvidenceSessions,
    ScreenCaptureArtifact,
    ScreenCaptureArtifacts
  }

  alias TamanduaServer.Mobile.{DeviceV2, MDMCommand}

  setup do
    previous_url = System.get_env("TAMANDUA_SCREEN_CAPTURE_UPLOAD_BASE_URL")
    System.put_env("TAMANDUA_SCREEN_CAPTURE_UPLOAD_BASE_URL", "http://127.0.0.1:4000")

    on_exit(fn ->
      if previous_url,
        do: System.put_env("TAMANDUA_SCREEN_CAPTURE_UPLOAD_BASE_URL", previous_url),
        else: System.delete_env("TAMANDUA_SCREEN_CAPTURE_UPLOAD_BASE_URL")
    end)

    organization = insert(:organization)
    actor = insert(:user, organization: organization, role: "admin")
    external_id = "android-evidence-#{System.unique_integer([:positive])}"

    device =
      Repo.insert!(%DeviceV2{
        organization_id: organization.id,
        device_id: external_id,
        platform: "android",
        device_name: "Android evidence test"
      })

    agent =
      insert(:agent,
        organization: organization,
        os_type: "android",
        status: "online",
        machine_id: external_id,
        config: %{
          "source" => "tamandua_mobile_v2",
          "capabilities" => %{
            "screen_capture" => %{"available" => true, "native_method_available" => true},
            "evidence_session" => %{"available" => true, "native_method_available" => true}
          }
        }
      )

    Repo.insert!(%Policy{
      name: "Android evidence test policy",
      organization_id: organization.id,
      created_by_id: actor.id,
      status: "active",
      scope: "organization",
      policy_data: %{
        "response" => %{
          "screen_capture" => %{
            "mode" => "consent_required",
            "allowed_scopes" => ["virtual_desktop"]
          }
        }
      }
    })

    session =
      %EvidenceSession{}
      |> EvidenceSession.create_changeset(%{
        organization_id: organization.id,
        agent_id: agent.id,
        status: "scheduled",
        reason: "Bounded Android visual evidence",
        capture_request: %{
          "reason" => "Bounded Android visual evidence",
          "display" => "all",
          "scope" => "virtual_desktop",
          "ttl_seconds" => 300,
          "watermark" => true,
          "redactions" => [],
          "platform" => "android"
        },
        frame_count: 3,
        interval_seconds: 5,
        expires_at: DateTime.add(DateTime.utc_now(), 900, :second)
      })
      |> Repo.insert!()

    %{organization: organization, actor: actor, agent: agent, device: device, session: session}
  end

  test "queues one Android MDM command with independent frame uploads", %{session: session} do
    assert {:ok, {:mobile_aggregate, artifacts, command}} =
             EvidenceFrameDispatcher.dispatch(session, 0)

    assert length(artifacts) == session.frame_count
    assert command.command_type == "evidence_session"
    assert Repo.aggregate(MDMCommand, :count) == 1

    command = Repo.get!(MDMCommand, command.id)
    assert command.payload["schema_version"] == "tamandua.screen_evidence_session/v1"
    assert command.payload["session_id"] == session.id
    assert command.payload["frame_count"] == 3
    assert command.payload["interval_seconds"] == 5
    assert length(command.payload["frames"]) == 3

    artifact_ids = Enum.map(artifacts, fn {artifact, _token} -> artifact.id end)
    payload_artifact_ids = Enum.map(command.payload["frames"], & &1["artifact_id"])
    assert payload_artifact_ids == artifact_ids

    Enum.each(command.payload["frames"], fn frame ->
      assert frame["upload"]["method"] == "PUT"
      assert frame["upload"]["content_type"] == "image/png"
      assert is_binary(frame["upload"]["token"])
    end)

    persisted =
      Repo.all(from(a in ScreenCaptureArtifact, where: a.evidence_session_id == ^session.id))

    assert length(persisted) == 3
    assert Enum.all?(persisted, &is_nil(&1.mobile_command_id))

    advanced = EvidenceSessions.advance_mobile_aggregate(session, command.id)
    assert advanced.mobile_command_id == command.id
    assert advanced.next_frame_index == 3
    assert advanced.status == "running"

    [{first_artifact, first_token} | _] = artifacts
    png = <<137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82>>
    sha256 = :crypto.hash(:sha256, png) |> Base.encode16(case: :lower)

    assert {:ok, _ready} =
             ScreenCaptureArtifacts.upload(
               first_artifact.id,
               first_token,
               "image/png",
               sha256,
               DateTime.utc_now() |> DateTime.to_iso8601(),
               png
             )

    command = Repo.get!(MDMCommand, command.id)
    [first_frame | remaining_frames] = command.payload["frames"]
    refute first_frame["upload"]["token"]
    assert first_frame["upload"]["credential_status"] == "consumed_or_expired"
    assert Enum.all?(remaining_frames, &is_binary(&1["upload"]["token"]))
  end

  test "cancellation of a sent aggregate command queues one token-free cancel command", %{
    organization: organization,
    actor: actor,
    session: session
  } do
    assert {:ok, {:mobile_aggregate, _artifacts, command}} =
             EvidenceFrameDispatcher.dispatch(session, 0)

    session = EvidenceSessions.advance_mobile_aggregate(session, command.id)
    command = command |> Ecto.Changeset.change(status: "sent") |> Repo.update!()

    assert {:ok, cancelled} = EvidenceSessions.cancel(organization.id, session.id, actor)
    assert cancelled.status == "cancelled"
    assert Repo.get!(MDMCommand, command.id).status == "sent"

    cancel = Repo.get_by!(MDMCommand, command_type: "cancel_evidence_session")
    assert cancel.device_id == command.device_id
    assert cancel.payload["session_id"] == session.id
    refute Jason.encode!(cancel.payload) =~ "token"

    original = Repo.get!(MDMCommand, command.id)
    refute Jason.encode!(original.payload) =~ "one-time-upload-token"
    refute Enum.any?(original.payload["frames"], &get_in(&1, ["upload", "token"]))

    artifacts =
      Repo.all(from(a in ScreenCaptureArtifact, where: a.evidence_session_id == ^session.id))

    assert Enum.all?(artifacts, &(&1.status == "failed"))
    assert Enum.all?(artifacts, &is_nil(&1.upload_token_hash))
  end

  test "terminal aggregate reconciliation is idempotent and does not wait for a GET", %{
    session: session
  } do
    assert {:ok, {:mobile_aggregate, _artifacts, command}} =
             EvidenceFrameDispatcher.dispatch(session, 0)

    session = EvidenceSessions.advance_mobile_aggregate(session, command.id)
    command = command |> Ecto.Changeset.change(status: "failed") |> Repo.update!()

    assert {:ok, failed} = EvidenceSessions.reconcile_mobile_command(command)
    assert failed.status == "failed"
    assert failed.completed_at

    assert {:ok, repeated} = EvidenceSessions.reconcile_mobile_command(command)
    assert repeated.id == failed.id
    assert repeated.status == "failed"

    artifacts =
      Repo.all(from(a in ScreenCaptureArtifact, where: a.evidence_session_id == ^session.id))

    assert Enum.all?(artifacts, &(&1.status == "failed"))
  end

  test "mobile command whitelist accepts aggregate and cancellation contracts", %{device: device} do
    for command_type <- ["evidence_session", "cancel_evidence_session"] do
      assert %Ecto.Changeset{valid?: true} =
               MDMCommand.changeset(%MDMCommand{}, %{
                 command_type: command_type,
                 device_id: device.id,
                 organization_id: device.organization_id,
                 payload: %{}
               })
    end
  end

  test "rejects Android long sessions above the native ten-frame bound before scheduling", %{
    organization: organization,
    actor: actor,
    agent: agent
  } do
    assert {:error, :android_evidence_session_frame_count_unsupported} =
             EvidenceSessions.create(
               organization.id,
               agent.id,
               %{
                 "reason" => "Too many Android frames",
                 "frame_count" => 11,
                 "interval_seconds" => 5,
                 "long_session" => true,
                 "scope" => "virtual_desktop"
               },
               actor
             )
  end
end

defmodule TamanduaServerWeb.API.V1.MobileEvidenceSessionCredentialTest do
  use TamanduaServerWeb.ConnCase, async: false

  alias TamanduaServer.Mobile.{DeviceV2, MDMCommand}
  alias TamanduaServer.Repo

  test "keeps aggregate upload tokens for sent retry and scrubs all on terminal status", %{
    conn: conn
  } do
    organization = insert(:organization)
    user = insert(:user, organization: organization, role: "admin")
    {:ok, token, _claims} = TamanduaServer.Guardian.encode_and_sign(user)
    conn = put_req_header(conn, "authorization", "Bearer #{token}")

    device =
      Repo.insert!(%DeviceV2{
        organization_id: organization.id,
        device_id: "android-terminal-scrub-#{System.unique_integer([:positive])}",
        platform: "android",
        device_name: "Android terminal scrub"
      })

    command =
      Repo.insert!(%MDMCommand{
        organization_id: organization.id,
        device_id: device.id,
        command_type: "evidence_session",
        status: "pending",
        payload: %{
          "frames" => [
            %{"artifact_id" => Ecto.UUID.generate(), "upload" => %{"token" => "token-a"}},
            %{"artifact_id" => Ecto.UUID.generate(), "upload" => %{"token" => "token-b"}}
          ]
        },
        requested_by: "test"
      })

    sent =
      patch(conn, "/api/v1/mobile/v2/commands/#{command.id}/status", %{
        "device_id" => device.id,
        "status" => "sent",
        "result" => %{"ok" => true}
      })
      |> json_response(200)

    assert get_in(sent, ["data", "payload", "frames", Access.at(0), "upload", "token"]) ==
             "token-a"

    completed =
      patch(conn, "/api/v1/mobile/v2/commands/#{command.id}/status", %{
        "device_id" => device.id,
        "status" => "completed",
        "result" => %{"ok" => true, "state" => "completed"}
      })
      |> json_response(200)

    refute get_in(completed, ["data", "payload", "frames", Access.at(0), "upload", "token"])
    refute get_in(completed, ["data", "payload", "frames", Access.at(1), "upload", "token"])

    assert get_in(completed, [
             "data",
             "payload",
             "frames",
             Access.at(0),
             "upload",
             "credential_status"
           ]) == "consumed_or_expired"
  end
end
