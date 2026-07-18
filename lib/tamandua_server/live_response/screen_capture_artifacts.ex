defmodule TamanduaServer.LiveResponse.ScreenCaptureArtifacts do
  @moduledoc """
  Secure lifecycle for screen-capture artifacts.

  Upload credentials are signed, artifact-specific and one-time. Image bytes
  are stored only after MIME, size, PNG signature and SHA-256 verification.

  Expiry cleanup runs opportunistically on create/status/content and every
  five minutes through `ScreenCaptureRetentionWorker`.
  """

  import Ecto.Query
  require Logger

  alias TamanduaServer.LiveResponse.{EvidenceSession, ScreenCaptureArtifact}
  alias TamanduaServer.Agents.AgentCommand
  alias TamanduaServer.Mobile.MDMCommand
  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServerWeb.Endpoint

  @upload_salt "screen_capture_artifact_upload/v1"
  @max_bytes 8_388_608
  @mime "image/png"
  @png_signature <<137, 80, 78, 71, 13, 10, 26, 10>>

  def max_bytes, do: @max_bytes
  def allowed_mime, do: @mime

  @doc "Return the trusted, agent-reachable base URL used for artifact uploads."
  def upload_base_url do
    configured =
      case System.get_env("TAMANDUA_SCREEN_CAPTURE_UPLOAD_BASE_URL") do
        value when is_binary(value) and value != "" -> value
        _ -> Endpoint.url()
      end

    validate_upload_base_url(configured)
  end

  def create(organization_id, agent_id, ttl_seconds, opts \\ []) do
    MultiTenant.with_organization(organization_id, fn ->
      cleanup_expired_in_context()

      artifact_id = Ecto.UUID.generate()
      expires_at = DateTime.add(DateTime.utc_now(), ttl_seconds, :second)

      token =
        Phoenix.Token.sign(Endpoint, @upload_salt, %{
          artifact_id: artifact_id,
          organization_id: organization_id,
          agent_id: agent_id,
          nonce: Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)
        })

      attrs = %{
        organization_id: organization_id,
        agent_id: agent_id,
        status: "pending",
        display: "all",
        expires_at: expires_at,
        upload_token_hash: token_hash(token),
        evidence_session_id: Keyword.get(opts, :evidence_session_id),
        frame_index: Keyword.get(opts, :frame_index)
      }

      %ScreenCaptureArtifact{id: artifact_id}
      |> ScreenCaptureArtifact.create_changeset(attrs)
      |> Repo.insert()
      |> case do
        {:ok, artifact} -> {:ok, artifact, token}
        error -> error
      end
    end)
  end

  def attach_command(%ScreenCaptureArtifact{} = artifact, command_id) do
    MultiTenant.with_organization(artifact.organization_id, fn ->
      artifact
      |> ScreenCaptureArtifact.attach_command_changeset(command_id)
      |> Repo.update()
      |> case do
        {:ok, attached} = result ->
          # The worker is notified by CommandManager before this association is
          # written. If an exceptionally fast agent already consumed the upload
          # token, scrub the just-attached command now. Keep it while pending so
          # normal worker redelivery still has a usable credential.
          if attached.status != "pending" or is_nil(attached.upload_token_hash) do
            scrub_command_upload_token(command_id)
          end

          result

        error ->
          error
      end
    end)
  end

  def attach_mobile_command(%ScreenCaptureArtifact{} = artifact, command_id) do
    MultiTenant.with_organization(artifact.organization_id, fn ->
      artifact
      |> ScreenCaptureArtifact.attach_mobile_command_changeset(command_id)
      |> Repo.update()
      |> case do
        {:ok, attached} = result ->
          if attached.status != "pending" or is_nil(attached.upload_token_hash) do
            scrub_mobile_command_upload_token(command_id)
          end

          result

        error ->
          error
      end
    end)
  end

  def mark_failed(%ScreenCaptureArtifact{} = artifact, reason) do
    MultiTenant.with_organization(artifact.organization_id, fn ->
      result =
        artifact
        |> ScreenCaptureArtifact.terminal_changeset("failed", normalize_failure(reason))
        |> Repo.update()

      scrub_artifact_command_upload_tokens(artifact)
      result
    end)
  end

  def scrub_command_credential(organization_id, command_id) do
    MultiTenant.with_organization(organization_id, fn ->
      scrub_command_upload_token(command_id)
    end)
  end

  def get_for_tenant(organization_id, agent_id, artifact_id) do
    MultiTenant.with_organization(organization_id, fn ->
      cleanup_expired_in_context()

      ScreenCaptureArtifact
      |> ScreenCaptureArtifact.for_tenant_agent(organization_id, agent_id)
      |> where([artifact], artifact.id == ^artifact_id)
      |> Repo.one()
      |> case do
        nil -> {:error, :not_found}
        artifact -> expire_if_needed(artifact)
      end
    end)
  end

  def upload(artifact_id, signed_token, mime, claimed_sha256, captured_at, body)
      when is_binary(artifact_id) and is_binary(signed_token) and is_binary(body) do
    with {:ok, claims} <- verify_upload_token(signed_token),
         :ok <- verify_claim_artifact(claims, artifact_id),
         {:ok, captured_at} <- parse_captured_at(captured_at),
         :ok <- validate_payload(mime, claimed_sha256, body) do
      organization_id = claims.organization_id

      MultiTenant.with_organization(organization_id, fn ->
        consume_upload(artifact_id, claims, signed_token, claimed_sha256, captured_at, body)
      end)
    end
  end

  def upload(_artifact_id, _signed_token, _mime, _claimed_sha256, _captured_at, _body),
    do: {:error, :invalid_upload}

  defp consume_upload(artifact_id, claims, signed_token, claimed_sha256, captured_at, body) do
    organization_id = claims.organization_id

    artifact =
      ScreenCaptureArtifact
      |> where(
        [artifact],
        artifact.id == ^artifact_id and artifact.organization_id == ^organization_id
      )
      |> lock("FOR UPDATE")
      |> Repo.one()

    cond do
      is_nil(artifact) ->
        {:error, :not_found}

      not claim_matches_agent?(claims, artifact.agent_id) ->
        audit_idempotency_denial(artifact, "agent_claim_mismatch")
        {:error, :invalid_token}

      DateTime.compare(artifact.expires_at, DateTime.utc_now()) != :gt ->
        artifact
        |> ScreenCaptureArtifact.terminal_changeset("expired", "artifact_ttl_expired")
        |> Repo.update()

        scrub_artifact_command_upload_tokens(artifact)

        {:error, :expired}

      artifact.status == "ready" ->
        idempotent_ready_upload(artifact, claimed_sha256, body)

      artifact.status != "pending" ->
        {:error, :upload_not_pending}

      not token_matches?(artifact.upload_token_hash, signed_token) ->
        {:error, :invalid_token}

      not valid_capture_time?(captured_at, artifact.expires_at) ->
        {:error, :invalid_captured_at}

      true ->
        result =
          artifact
          |> ScreenCaptureArtifact.ready_changeset(%{
            mime: @mime,
            size: byte_size(body),
            sha256: claimed_sha256,
            captured_at: captured_at,
            content: body
          })
          |> Repo.update()

        scrub_artifact_command_upload_tokens(artifact)
        result
    end
  end

  defp idempotent_ready_upload(artifact, claimed_sha256, body) do
    if idempotent_ready_match?(artifact, claimed_sha256, body) do
      Logger.info("screen_capture_upload_idempotent_ack",
        organization_id: artifact.organization_id,
        agent_id: artifact.agent_id,
        artifact_id: artifact.id
      )

      {:ok, artifact}
    else
      audit_idempotency_denial(artifact, "ready_artifact_digest_or_size_mismatch")
      {:error, :upload_not_pending}
    end
  end

  @doc false
  def idempotent_ready_match?(artifact, claimed_sha256, body) when is_binary(body) do
    is_binary(artifact.sha256) and is_binary(claimed_sha256) and
      byte_size(artifact.sha256) == byte_size(claimed_sha256) and
      Plug.Crypto.secure_compare(artifact.sha256, claimed_sha256) and
      artifact.size == byte_size(body)
  end

  def idempotent_ready_match?(_artifact, _claimed_sha256, _body), do: false

  defp audit_idempotency_denial(artifact, reason) do
    Logger.warning("screen_capture_upload_idempotency_denied",
      organization_id: artifact.organization_id,
      agent_id: artifact.agent_id,
      artifact_id: artifact.id,
      reason: reason
    )
  end

  defp expire_if_needed(%ScreenCaptureArtifact{status: "pending"} = artifact) do
    if DateTime.compare(artifact.expires_at, DateTime.utc_now()) == :gt do
      {:ok, artifact}
    else
      result =
        artifact
        |> ScreenCaptureArtifact.terminal_changeset("expired", "artifact_ttl_expired")
        |> Repo.update()

      scrub_artifact_command_upload_tokens(artifact)
      result
    end
  end

  defp expire_if_needed(artifact), do: {:ok, artifact}

  @doc """
  Opportunistically expire artifacts for one tenant and erase image/token
  material. The scheduled retention worker invokes the same tenant-scoped path.
  """
  def cleanup_expired(organization_id) do
    MultiTenant.with_organization(organization_id, fn ->
      cleanup_expired_in_context()
    end)
  end

  defp cleanup_expired_in_context do
    now = DateTime.utc_now()

    expired_command_ids =
      ScreenCaptureArtifact
      |> where(
        [artifact],
        artifact.expires_at <= ^now and artifact.status in ["pending", "ready"]
      )
      |> select([artifact], {artifact.command_id, artifact.mobile_command_id})
      |> Repo.all()

    {count, _} =
      ScreenCaptureArtifact
      |> where(
        [artifact],
        artifact.expires_at <= ^now and artifact.status in ["pending", "ready"]
      )
      |> Repo.update_all(
        set: [
          status: "expired",
          failure_reason: "artifact_ttl_expired",
          content: nil,
          upload_token_hash: nil,
          updated_at: now
        ]
      )

    Enum.each(expired_command_ids, fn {command_id, mobile_command_id} ->
      scrub_command_upload_token(command_id)
      scrub_mobile_command_upload_token(mobile_command_id)
    end)

    {:ok, count}
  end

  defp verify_upload_token(token) do
    case Phoenix.Token.verify(Endpoint, @upload_salt, token, max_age: 900) do
      {:ok,
       %{
         artifact_id: artifact_id,
         organization_id: organization_id,
         agent_id: agent_id
       } = claims}
      when is_binary(artifact_id) and is_binary(organization_id) and is_binary(agent_id) ->
        {:ok, claims}

      _ ->
        {:error, :invalid_token}
    end
  end

  defp verify_claim_artifact(%{artifact_id: artifact_id}, artifact_id), do: :ok
  defp verify_claim_artifact(_claims, _artifact_id), do: {:error, :invalid_token}

  defp claim_matches_agent?(%{agent_id: agent_id}, agent_id), do: true
  defp claim_matches_agent?(_claims, _agent_id), do: false

  @doc "Validate MIME, bounded size, exact PNG signature, and claimed SHA-256."
  def validate_payload(@mime, claimed_sha256, body) when is_binary(body) do
    actual_sha256 = :crypto.hash(:sha256, body) |> Base.encode16(case: :lower)

    cond do
      byte_size(body) == 0 -> {:error, :empty_upload}
      byte_size(body) > @max_bytes -> {:error, :upload_too_large}
      not png?(body) -> {:error, :invalid_png}
      not valid_sha256?(claimed_sha256) -> {:error, :invalid_sha256}
      not Plug.Crypto.secure_compare(actual_sha256, claimed_sha256) -> {:error, :sha256_mismatch}
      true -> :ok
    end
  end

  def validate_payload(_mime, _claimed_sha256, _body), do: {:error, :unsupported_mime}

  defp png?(<<@png_signature, _rest::binary>>), do: true
  defp png?(_body), do: false

  defp valid_sha256?(sha256) when is_binary(sha256),
    do: String.match?(sha256, ~r/\A[0-9a-f]{64}\z/)

  defp valid_sha256?(_sha256), do: false

  defp parse_captured_at(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, captured_at, _offset} -> {:ok, captured_at}
      _ -> {:error, :invalid_captured_at}
    end
  end

  defp parse_captured_at(_value), do: {:error, :invalid_captured_at}

  defp valid_capture_time?(captured_at, expires_at) do
    future_limit = DateTime.add(DateTime.utc_now(), 300, :second)

    DateTime.compare(captured_at, future_limit) != :gt and
      DateTime.compare(captured_at, expires_at) != :gt
  end

  defp validate_upload_base_url(url) when is_binary(url) do
    uri = URI.parse(String.trim_trailing(url, "/"))

    cond do
      not is_nil(uri.userinfo) or not is_nil(uri.fragment) ->
        {:error, :unsafe_screen_capture_upload_url}

      uri.scheme == "https" and is_binary(uri.host) and uri.host != "" ->
        {:ok, URI.to_string(%{uri | path: nil, query: nil, fragment: nil, userinfo: nil})}

      uri.scheme == "http" and loopback_host?(uri.host) ->
        {:ok, URI.to_string(%{uri | path: nil, query: nil, fragment: nil, userinfo: nil})}

      true ->
        {:error, :unsafe_screen_capture_upload_url}
    end
  end

  defp validate_upload_base_url(_url), do: {:error, :unsafe_screen_capture_upload_url}

  # Keep this exactly aligned with the Rust agent's URL policy.
  defp loopback_host?(host), do: host in ["localhost", "127.0.0.1", "::1"]

  defp token_matches?(stored_hash, token) when is_binary(stored_hash) do
    Plug.Crypto.secure_compare(stored_hash, token_hash(token))
  end

  defp token_matches?(_stored_hash, _token), do: false
  defp token_hash(token), do: :crypto.hash(:sha256, token)

  defp scrub_artifact_command_upload_tokens(artifact) do
    scrub_command_upload_token(Map.get(artifact, :command_id))
    scrub_mobile_command_upload_token(Map.get(artifact, :mobile_command_id))
    scrub_aggregate_frame_upload_token(artifact)
    :ok
  end

  defp scrub_aggregate_frame_upload_token(%{
         evidence_session_id: session_id,
         id: artifact_id
       })
       when is_binary(session_id) and is_binary(artifact_id) do
    case Repo.get(EvidenceSession, session_id) do
      %EvidenceSession{mobile_command_id: command_id} when is_binary(command_id) ->
        Repo.transaction(fn ->
          command =
            MDMCommand
            |> where([command], command.id == ^command_id)
            |> lock("FOR UPDATE")
            |> Repo.one()

          if command do
            redacted = redact_aggregate_frame(command.payload || %{}, artifact_id)
            command |> Ecto.Changeset.change(payload: redacted) |> Repo.update!()
          end
        end)

        :ok

      _ ->
        :ok
    end
  end

  defp scrub_aggregate_frame_upload_token(_artifact), do: :ok

  defp redact_aggregate_frame(params, artifact_id) do
    params
    |> redact_matching_frame("frames", artifact_id)
    |> redact_matching_frame(:frames, artifact_id)
  end

  defp redact_matching_frame(params, key, artifact_id) do
    case Map.fetch(params, key) do
      {:ok, frames} when is_list(frames) ->
        Map.put(params, key, Enum.map(frames, &maybe_redact_matching_frame(&1, artifact_id)))

      _ ->
        params
    end
  end

  defp maybe_redact_matching_frame(frame, artifact_id) when is_map(frame) do
    if Map.get(frame, "artifact_id") == artifact_id or
         Map.get(frame, :artifact_id) == artifact_id,
       do: redact_frame_upload_token(frame),
       else: frame
  end

  defp maybe_redact_matching_frame(frame, _artifact_id), do: frame

  defp scrub_command_upload_token(nil), do: :ok

  defp scrub_command_upload_token(command_id) do
    case Repo.get(AgentCommand, command_id) do
      nil ->
        scrub_mobile_command_upload_token(command_id)

      command ->
        redacted =
          Map.update(command.command_params || %{}, "upload", %{}, fn
            upload when is_map(upload) ->
              upload
              |> Map.delete("token")
              |> Map.delete(:token)
              |> Map.put("credential_status", "consumed_or_expired")

            _ ->
              %{"credential_status" => "consumed_or_expired"}
          end)

        command
        |> Ecto.Changeset.change(command_params: redacted)
        |> Repo.update()

        :ok
    end
  end

  defp scrub_mobile_command_upload_token(command_id) do
    case Repo.get(MDMCommand, command_id) do
      nil ->
        :ok

      command ->
        command
        |> Ecto.Changeset.change(payload: redact_mobile_command_payload(command.payload || %{}))
        |> Repo.update()

        :ok
    end
  end

  def redact_mobile_command_payload(params) when is_map(params) do
    params
    |> redact_upload_token()
    |> redact_frame_upload_tokens("frames")
    |> redact_frame_upload_tokens(:frames)
  end

  def redact_mobile_command_payload(_params), do: %{}

  defp redact_frame_upload_tokens(params, key) do
    case Map.fetch(params, key) do
      {:ok, frames} when is_list(frames) ->
        Map.put(params, key, Enum.map(frames, &redact_frame_upload_token/1))

      _ ->
        params
    end
  end

  defp redact_frame_upload_token(frame) when is_map(frame) do
    frame
    |> redact_frame_upload_token_for_key("upload")
    |> redact_frame_upload_token_for_key(:upload)
  end

  defp redact_frame_upload_token(frame), do: frame

  defp redact_frame_upload_token_for_key(frame, key) do
    case Map.fetch(frame, key) do
      {:ok, upload} when is_map(upload) -> Map.put(frame, key, redact_upload_map(upload))
      _ -> frame
    end
  end

  defp redact_upload_token(params) do
    Map.update(params, "upload", %{}, fn
      upload when is_map(upload) ->
        redact_upload_map(upload)

      _ ->
        %{"credential_status" => "consumed_or_expired"}
    end)
  end

  defp redact_upload_map(upload) do
    upload
    |> Map.delete("token")
    |> Map.delete(:token)
    |> Map.put("credential_status", "consumed_or_expired")
  end

  defp normalize_failure(reason) do
    reason
    |> inspect(limit: 20, printable_limit: 200)
    |> String.slice(0, 500)
  end
end
