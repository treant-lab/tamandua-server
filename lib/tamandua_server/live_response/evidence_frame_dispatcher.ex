defmodule TamanduaServer.LiveResponse.EvidenceFrameDispatcher do
  @moduledoc false
  alias TamanduaServer.Agents
  alias TamanduaServer.Agents.{Agent, CommandManager, Registry}

  alias TamanduaServer.LiveResponse.{
    ScreenCapture,
    ScreenCaptureAdmission,
    ScreenCaptureArtifacts,
    ScreenCapturePolicy
  }

  alias TamanduaServer.Mobile.{DeviceV2, MDMCommand}
  alias TamanduaServer.Repo

  def dispatch(session, frame_index) do
    with {:ok, agent} <- Agents.get_agent_for_org(session.organization_id, session.agent_id),
         {:ok, request} <- ScreenCapture.validate_request(session.capture_request),
         policy <-
           ScreenCapturePolicy.resolve(agent.id)
           |> ScreenCapturePolicy.for_command(request.ttl_seconds),
         :ok <- valid_policy(policy, request),
         {:ok, delivery} <- delivery(agent, session.organization_id),
         :ok <-
           ScreenCaptureAdmission.authorize(agent, session.organization_id, delivery, policy),
         capability <- ScreenCapture.capability_state(agent.os_type, delivery.capabilities),
         :ok <- supported(capability),
         {:ok, base} <- ScreenCaptureArtifacts.upload_base_url() do
      if android_mobile?(delivery) do
        dispatch_android_session(
          session,
          frame_index,
          agent,
          delivery,
          request,
          policy,
          capability,
          base
        )
      else
        dispatch_single_frame(
          session,
          frame_index,
          agent,
          delivery,
          request,
          policy,
          capability,
          base
        )
      end
    end
  end

  defp dispatch_single_frame(
         session,
         frame_index,
         agent,
         delivery,
         request,
         policy,
         capability,
         base
       ) do
    upload_expires_at = DateTime.add(DateTime.utc_now(), request.ttl_seconds, :second)

    with {:ok, artifact, token} <-
           ScreenCaptureArtifacts.create(
             session.organization_id,
             agent.id,
             retention_ttl(session, request),
             evidence_session_id: session.id,
             frame_index: frame_index
           ) do
      upload = %{
        url: base <> "/api/v1/agent-artifacts/screen-captures/#{artifact.id}",
        token: token,
        method: "PUT",
        content_type: ScreenCaptureArtifacts.allowed_mime(),
        max_bytes: ScreenCaptureArtifacts.max_bytes(),
        expires_at: DateTime.to_iso8601(upload_expires_at)
      }

      params = %{
        schema_version: ScreenCapture.schema_version(),
        reason: request.reason,
        display: request.display,
        scope: request.scope,
        monitor_id: request.monitor_id,
        watermark: request.watermark,
        redactions: request.redactions,
        artifact_id: artifact.id,
        upload: upload,
        expires_at: upload.expires_at,
        nonce: Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false),
        consent_required: capability.consent_required,
        policy_mode: policy.mode,
        notify_timing: policy.notify_timing,
        policy: policy.policy,
        continuous: false,
        input_control: false,
        evidence_session: %{
          id: session.id,
          frame_index: frame_index,
          frame_count: session.frame_count
        }
      }

      case queue(agent, delivery, params, request.ttl_seconds) do
        {:ok, command} ->
          case attach(artifact, command, delivery) do
            {:ok, attached} ->
              {:ok, attached}

            {:error, reason} ->
              cancel_queued(command, delivery, session.organization_id)
              ScreenCaptureArtifacts.mark_failed(artifact, reason)
              {:error, reason}
          end

        {:error, reason} ->
          ScreenCaptureArtifacts.mark_failed(artifact, reason)
          {:error, reason}
      end
    end
  end

  defp dispatch_android_session(
         session,
         0,
         agent,
         delivery,
         request,
         policy,
         capability,
         base
       ) do
    duration_seconds = (session.frame_count - 1) * session.interval_seconds
    aggregate_ttl = min(duration_seconds + request.ttl_seconds, 900)

    cond do
      session.frame_count > 10 ->
        {:error, :android_evidence_session_frame_count_unsupported}

      "evidence_session" not in delivery.capabilities ->
        {:error, :agent_did_not_report_evidence_session_capability}

      request.scope != "virtual_desktop" ->
        {:error, :unsupported_mobile_capture_scope}

      true ->
        with {:ok, artifacts} <-
               create_android_artifacts(session, agent, retention_ttl(session, request)),
             {:ok, command} <-
               queue_android_session(
                 session,
                 agent,
                 delivery,
                 request,
                 policy,
                 capability,
                 base,
                 artifacts,
                 aggregate_ttl
               ) do
          session
          |> Ecto.Changeset.change(mobile_command_id: command.id)
          |> Repo.update!()

          {:ok, {:mobile_aggregate, artifacts, command}}
        else
          {:error, {reason, artifacts}} ->
            fail_artifacts(artifacts, reason)
            {:error, reason}

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp dispatch_android_session(
         _session,
         _frame_index,
         _agent,
         _delivery,
         _request,
         _policy,
         _capability,
         _base
       ),
       do: {:error, :android_evidence_session_must_start_at_frame_zero}

  defp create_android_artifacts(session, agent, ttl_seconds) do
    Enum.reduce_while(0..(session.frame_count - 1), {:ok, []}, fn frame_index, {:ok, created} ->
      case ScreenCaptureArtifacts.create(session.organization_id, agent.id, ttl_seconds,
             evidence_session_id: session.id,
             frame_index: frame_index
           ) do
        {:ok, artifact, token} ->
          {:cont, {:ok, [{artifact, token} | created]}}

        {:error, reason} ->
          {:halt, {:error, {reason, Enum.map(created, &elem(&1, 0))}}}
      end
    end)
    |> case do
      {:ok, created} -> {:ok, Enum.reverse(created)}
      error -> error
    end
  end

  defp queue_android_session(
         session,
         agent,
         %{device: device},
         request,
         policy,
         capability,
         base,
         artifacts,
         ttl_seconds
       ) do
    expires_at = DateTime.add(DateTime.utc_now(), ttl_seconds, :second)

    frames =
      Enum.map(artifacts, fn {artifact, token} ->
        %{
          artifact_id: artifact.id,
          upload: upload_contract(base, artifact, token, expires_at)
        }
      end)

    params = %{
      schema_version: "tamandua.screen_evidence_session/v1",
      session_id: session.id,
      reason: request.reason,
      display: request.display,
      scope: request.scope,
      monitor_id: request.monitor_id,
      watermark: request.watermark,
      redactions: request.redactions,
      frame_count: session.frame_count,
      interval_seconds: session.interval_seconds,
      frames: frames,
      expires_at: DateTime.to_iso8601(expires_at),
      nonce: Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false),
      consent_required: capability.consent_required,
      policy_mode: policy.mode,
      notify_timing: policy.notify_timing,
      policy: policy.policy,
      continuous: false,
      input_control: false
    }

    %MDMCommand{}
    |> MDMCommand.changeset(%{
      command_type: "evidence_session",
      device_id: device.id,
      organization_id: device.organization_id,
      requested_by: "evidence_session:#{agent.id}",
      status: "pending",
      payload: params
    })
    |> Repo.insert()
    |> case do
      {:ok, command} -> {:ok, command}
      {:error, reason} -> {:error, {reason, Enum.map(artifacts, &elem(&1, 0))}}
    end
  end

  defp upload_contract(base, artifact, token, expires_at) do
    %{
      url: base <> "/api/v1/agent-artifacts/screen-captures/#{artifact.id}",
      token: token,
      method: "PUT",
      content_type: ScreenCaptureArtifacts.allowed_mime(),
      max_bytes: ScreenCaptureArtifacts.max_bytes(),
      expires_at: DateTime.to_iso8601(expires_at)
    }
  end

  defp retention_ttl(session, request) do
    remaining = DateTime.diff(session.expires_at, DateTime.utc_now(), :second)
    remaining |> max(request.ttl_seconds) |> min(3_600)
  end

  defp fail_artifacts(artifacts, reason) do
    Enum.each(artifacts, &ScreenCaptureArtifacts.mark_failed(&1, reason))
  end

  defp valid_policy(%{mode: mode} = policy, request)
       when mode in ["silent", "notify", "consent_required"] do
    cond do
      not ScreenCapturePolicy.usable?(policy) -> {:error, :policy_unusable}
      request.scope not in policy.allowed_scopes -> {:error, :scope_not_allowed}
      policy.redaction_required and request.redactions == [] -> {:error, :redaction_required}
      true -> :ok
    end
  end

  defp valid_policy(_, _), do: {:error, :policy_disabled}
  defp supported(%{state: "unsupported"}), do: {:error, :unsupported}
  defp supported(_), do: :ok

  defp delivery(%Agent{} = agent, organization_id) do
    if mobile?(agent.os_type) do
      case Repo.get_by(DeviceV2, organization_id: organization_id, device_id: agent.machine_id) do
        nil ->
          {:error, :mobile_device_not_found}

        device ->
          {:ok,
           %{
             kind: :mobile,
             platform: normalized_platform(agent.os_type),
             device: device,
             capabilities: mobile_capabilities(agent.config)
           }}
      end
    else
      case Registry.get(agent.id) do
        {:ok, runtime} ->
          if Registry.same_canonical_organization_id?(
               runtime[:organization_id],
               organization_id
             ) do
            {:ok,
             %{
               kind: :desktop,
               capabilities: runtime[:capabilities] || [],
               runtime_snapshot: runtime[:runtime_snapshot]
             }}
          else
            {:error, :tenant_mismatch}
          end

        _ ->
          {:error, :agent_offline}
      end
    end
  end

  defp queue(agent, %{kind: :desktop}, params, ttl),
    do: CommandManager.queue_command(agent.id, :screen_capture, params, priority: 2, timeout: ttl)

  defp queue(agent, %{kind: :mobile, device: device}, params, _ttl) do
    %MDMCommand{}
    |> MDMCommand.changeset(%{
      command_type: "screen_capture",
      device_id: device.id,
      organization_id: device.organization_id,
      requested_by: "evidence_session:#{agent.id}",
      status: "pending",
      payload: params
    })
    |> Repo.insert()
  end

  defp attach(artifact, %MDMCommand{} = command, _),
    do: ScreenCaptureArtifacts.attach_mobile_command(artifact, command.id)

  defp attach(artifact, command, _),
    do: ScreenCaptureArtifacts.attach_command(artifact, command.id)

  defp cancel_queued(%MDMCommand{} = command, %{kind: :mobile}, _organization_id) do
    Repo.delete(command)
  end

  defp cancel_queued(command, %{kind: :desktop}, organization_id) do
    CommandManager.cancel_command(command.id)
    ScreenCaptureArtifacts.scrub_command_credential(organization_id, command.id)
  end

  defp mobile?(os) do
    normalized_platform(os) in ~w(android ios iphone ipad ipados)
  end

  defp normalized_platform(os),
    do: os |> to_string() |> String.downcase() |> String.replace(~r/[^a-z0-9]/, "")

  defp android_mobile?(%{kind: :mobile, platform: "android"}), do: true
  defp android_mobile?(_), do: false

  defp mobile_capabilities(config) do
    capabilities = get_in(config || %{}, ["capabilities"]) || %{}
    capture = capabilities["screen_capture"]
    evidence = capabilities["evidence_session"]

    reported =
      if capture == true or
           (is_map(capture) and
              (capture["available"] == true or capture["native_method_available"] == true)),
         do: ["screen_capture", "screen_capture_consent_required"],
         else: []

    if evidence == true or
         (is_map(evidence) and
            (evidence["available"] == true or evidence["native_method_available"] == true)),
       do: ["evidence_session" | reported],
       else: reported
  end
end
