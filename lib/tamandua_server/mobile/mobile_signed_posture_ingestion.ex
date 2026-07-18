defmodule TamanduaServer.Mobile.MobileSignedPostureIngestion do
  @moduledoc "PostgreSQL-only one-shot issuance and atomic signed-posture ingestion."

  import Ecto.Query

  alias TamanduaServer.Mobile.{
    MobileDeviceIdentityKey,
    MobileDeviceIdentityRecovery,
    MobileSignedPostureProjection,
    MobileSignedPostureReceipt,
    MobileSignedPostureRequest,
    SignedPosture
  }

  alias TamanduaServer.Repo

  @max_ttl 300
  @request_domain "tamandua.mobile.signed-posture.request-id/v1"
  @challenge_domain "tamandua.mobile.signed-posture.challenge-id/v1"
  @nonce_domain "tamandua.mobile.signed-posture.nonce/v1"
  @installation_lock_domain "tamandua.mobile.installation-lock/v1"

  @spec issue(Ecto.UUID.t(), String.t(), keyword()) ::
          {:ok, map()} | {:error, atom() | Ecto.Changeset.t()}
  def issue(organization_id, installation_id, opts \\ []) do
    store_call(fn ->
      ttl = Keyword.get(opts, :ttl_seconds, @max_ttl)

      if not (is_integer(ttl) and ttl > 0 and ttl <= @max_ttl) do
        {:error, :invalid_ttl}
      else
        now = truncate(Keyword.get(opts, :now, DateTime.utc_now()))

        transaction(fn ->
          lock_installation(organization_id, installation_id)

          with {:ok, key} <- active_key(organization_id, installation_id, true),
               :ok <- ensure_no_pending_recovery(organization_id, installation_id, now) do
            request_id = Ecto.UUID.generate()
            challenge_id = distinct_uuid(request_id)
            nonce = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
            expires_at = DateTime.add(now, ttl, :second)

            attrs = %{
              organization_id: organization_id,
              identity_key_id: key.id,
              requested_by_id: Keyword.get(opts, :requested_by_id),
              installation_id: installation_id,
              device_key_id: key.device_key_id,
              key_scope_id: key.key_scope_id,
              request_id_digest: digest(@request_domain, request_id),
              challenge_id_digest: digest(@challenge_domain, challenge_id),
              nonce_digest: digest(@nonce_domain, nonce),
              state: "pending",
              auth_method: Keyword.get(opts, :auth_method, "authenticated_api"),
              issued_at: now,
              expires_at: expires_at
            }

            with {:ok, _request} <-
                   Repo.insert(
                     MobileSignedPostureRequest.changeset(%MobileSignedPostureRequest{}, attrs)
                   ) do
              {:ok,
               %{
                 request_id: request_id,
                 challenge_id: challenge_id,
                 nonce: nonce,
                 organization_id: organization_id,
                 installation_id: installation_id,
                 platform: key.platform,
                 device_key_id: key.device_key_id,
                 key_scope_id: key.key_scope_id,
                 issued_at: canonical_millisecond_utc(now),
                 expires_at: canonical_millisecond_utc(expires_at)
               }}
            end
          end
        end)
      end
    end)
  end

  @spec verify(Ecto.UUID.t(), map(), map(), keyword()) ::
          {:ok, map()} | {:error, atom() | Ecto.Changeset.t()}
  def verify(organization_id, envelope, posture, opts \\ []) do
    store_call(fn ->
      now = truncate(Keyword.get(opts, :now, DateTime.utc_now()))

      with {:ok, bindings} <- binding_digests(envelope) do
        transaction(fn ->
          verify_transaction(organization_id, envelope, posture, bindings, now)
        end)
      end
    end)
  end

  @spec request_status(Ecto.UUID.t(), String.t(), keyword()) ::
          {:ok, %{state: String.t()}} | {:error, atom()}
  def request_status(organization_id, request_id, opts \\ []) when is_binary(request_id) do
    store_call(fn ->
      request_id_digest = digest(@request_domain, request_id)
      now = truncate(Keyword.get(opts, :now, DateTime.utc_now()))

      transaction(fn ->
        request =
          from(r in MobileSignedPostureRequest,
            where:
              r.organization_id == ^organization_id and r.request_id_digest == ^request_id_digest,
            lock: "FOR UPDATE"
          )
          |> Repo.one()

        with %MobileSignedPostureRequest{} = request <- request,
             :ok <- pending_and_fresh(request, now),
             :ok <- lock_installation(organization_id, request.installation_id),
             :ok <- ensure_no_pending_recovery(organization_id, request.installation_id, now) do
          {:ok, %{state: "pending"}}
        else
          nil ->
            {:ok, %{state: "unavailable"}}

          {:error, :identity_recovery_in_progress} ->
            {:ok, %{state: "blocked", reason: "identity_recovery_in_progress"}}

          {:error, _reason} ->
            {:ok, %{state: "unavailable"}}
        end
      end)
    end)
  end

  def request_status(_organization_id, _request_id, _opts), do: {:ok, %{state: "unavailable"}}

  defp verify_transaction(organization_id, envelope, posture, bindings, now) do
    request =
      from(r in MobileSignedPostureRequest,
        where:
          r.organization_id == ^organization_id and r.request_id_digest == ^bindings.request and
            r.challenge_id_digest == ^bindings.challenge and r.nonce_digest == ^bindings.nonce,
        lock: "FOR UPDATE"
      )
      |> Repo.one()

    with %MobileSignedPostureRequest{} = request <- request,
         :ok <- pending_and_fresh(request, now),
         :ok <- lock_installation(organization_id, request.installation_id),
         {:ok, key} <- active_key(organization_id, request.installation_id, true),
         :ok <- snapshot_matches(request, key),
         :ok <- ensure_no_pending_recovery(organization_id, request.installation_id, now),
         {:ok, verified} <-
           SignedPosture.verify(envelope, posture, key.public_key_spki,
             now: now,
             expected_context: expected_context(request, envelope)
           ),
         {:ok, signature} <- decode_signature(envelope["signature"]),
         {:ok, observed_at, _} <- DateTime.from_iso8601(posture["observed_at"]),
         {:ok, receipt} <-
           insert_receipt(request, key, envelope, posture, signature, observed_at, now),
         {:ok, projection} <-
           upsert_projection(request, key, receipt, envelope, posture, observed_at, now),
         {:ok, _consumed} <- consume(request, now) do
      {:ok, %{receipt: receipt, projection: projection, verification: verified}}
    else
      nil -> {:error, :request_unavailable}
      {:error, reason} -> {:error, reason}
      _ -> {:error, :signed_posture_invalid}
    end
  end

  defp active_key(organization_id, installation_id, lock?) do
    query =
      from(k in MobileDeviceIdentityKey,
        where:
          k.organization_id == ^organization_id and k.installation_id == ^installation_id and
            k.lifecycle_state == "active" and k.proof_state == "verified"
      )

    query = if lock?, do: from(k in query, lock: "FOR UPDATE"), else: query

    case Repo.all(query) do
      [key] -> {:ok, key}
      [] -> {:error, :active_identity_required}
      _ -> {:error, :active_identity_ambiguous}
    end
  end

  defp ensure_no_pending_recovery(organization_id, installation_id, now),
    do:
      MobileDeviceIdentityRecovery.enforce_signed_posture_barrier(
        organization_id,
        installation_id,
        now
      )

  defp pending_and_fresh(%{state: "pending", issued_at: issued, expires_at: expires}, now) do
    cond do
      DateTime.compare(now, issued) == :lt -> {:error, :request_not_yet_valid}
      DateTime.compare(now, expires) != :lt -> {:error, :request_expired}
      true -> :ok
    end
  end

  defp pending_and_fresh(_request, _now), do: {:error, :request_unavailable}

  defp snapshot_matches(request, key) do
    if request.identity_key_id == key.id and request.device_key_id == key.device_key_id and
         request.key_scope_id == key.key_scope_id,
       do: :ok,
       else: {:error, :active_identity_changed}
  end

  defp expected_context(request, envelope) do
    %{
      "organization_id" => request.organization_id,
      "installation_id" => request.installation_id,
      "device_key_id" => request.device_key_id,
      "key_scope_id" => request.key_scope_id,
      "request_id" => envelope["request_id"],
      "challenge_id" => envelope["challenge_id"],
      "nonce" => envelope["nonce"]
    }
  end

  defp insert_receipt(request, key, envelope, posture, signature, observed_at, now) do
    attrs = %{
      organization_id: request.organization_id,
      request_id: request.id,
      identity_key_id: key.id,
      installation_id: request.installation_id,
      device_key_id: key.device_key_id,
      key_scope_id: key.key_scope_id,
      posture: posture,
      posture_sha256: envelope["posture_sha256"],
      signed_payload_sha256: envelope["signed_payload_sha256"],
      signature_sha256: :crypto.hash(:sha256, signature),
      observed_at: observed_at,
      verified_at: now
    }

    Repo.insert(MobileSignedPostureReceipt.changeset(%MobileSignedPostureReceipt{}, attrs))
  end

  defp upsert_projection(request, key, receipt, envelope, posture, observed_at, now) do
    attrs = %{
      organization_id: request.organization_id,
      receipt_id: receipt.id,
      identity_key_id: key.id,
      installation_id: request.installation_id,
      device_key_id: key.device_key_id,
      key_scope_id: key.key_scope_id,
      posture: posture,
      posture_sha256: envelope["posture_sha256"],
      observed_at: observed_at,
      verified_at: now
    }

    %MobileSignedPostureProjection{}
    |> MobileSignedPostureProjection.changeset(attrs)
    |> Repo.insert(
      on_conflict:
        from(p in MobileSignedPostureProjection,
          update: [
            set: [
              receipt_id: fragment("EXCLUDED.receipt_id"),
              identity_key_id: fragment("EXCLUDED.identity_key_id"),
              device_key_id: fragment("EXCLUDED.device_key_id"),
              key_scope_id: fragment("EXCLUDED.key_scope_id"),
              posture: fragment("EXCLUDED.posture"),
              posture_sha256: fragment("EXCLUDED.posture_sha256"),
              observed_at: fragment("EXCLUDED.observed_at"),
              verified_at: fragment("EXCLUDED.verified_at"),
              updated_at: fragment("EXCLUDED.updated_at")
            ]
          ],
          where: p.verified_at <= fragment("EXCLUDED.verified_at")
        ),
      conflict_target: [:organization_id, :installation_id],
      returning: true
    )
  end

  defp consume(request, now) do
    request
    |> MobileSignedPostureRequest.changeset(%{state: "consumed", consumed_at: now})
    |> Repo.update()
  end

  defp binding_digests(envelope) when is_map(envelope) do
    with request when is_binary(request) <- envelope["request_id"],
         challenge when is_binary(challenge) <- envelope["challenge_id"],
         nonce when is_binary(nonce) <- envelope["nonce"] do
      {:ok,
       %{
         request: digest(@request_domain, request),
         challenge: digest(@challenge_domain, challenge),
         nonce: digest(@nonce_domain, nonce)
       }}
    else
      _ -> {:error, :invalid_request_binding}
    end
  end

  defp binding_digests(_envelope), do: {:error, :invalid_request_binding}

  defp decode_signature(value) when is_binary(value) do
    case Base.url_decode64(value, padding: false) do
      {:ok, signature} -> {:ok, signature}
      :error -> {:error, :invalid_signature}
    end
  end

  defp decode_signature(_value), do: {:error, :invalid_signature}

  defp digest(domain, clear), do: :crypto.hash(:sha256, domain <> <<0>> <> clear)

  defp distinct_uuid(previous) do
    uuid = Ecto.UUID.generate()
    if uuid == previous, do: distinct_uuid(previous), else: uuid
  end

  defp lock_installation(organization_id, installation_id) do
    <<first::signed-32, second::signed-32, _::binary>> =
      :crypto.hash(
        :sha256,
        @installation_lock_domain <> <<0>> <> organization_id <> <<0>> <> installation_id
      )

    Repo.query!("SELECT pg_advisory_xact_lock($1, $2)", [first, second])
    :ok
  end

  defp transaction(callback) do
    case Repo.transaction(fn ->
           case callback.() do
             {:ok, value} -> value
             {:error, reason} -> Repo.rollback(reason)
           end
         end) do
      {:ok, value} -> {:ok, value}
      {:error, reason} -> {:error, reason}
    end
  end

  defp store_call(callback) do
    callback.()
  rescue
    _error in DBConnection.ConnectionError ->
      {:error, :signed_posture_store_unavailable}

    error in Postgrex.Error ->
      if unavailable_schema?(error),
        do: {:error, :signed_posture_store_unavailable},
        else: reraise(error, __STACKTRACE__)
  end

  defp unavailable_schema?(%Postgrex.Error{postgres: %{code: code}})
       when code in [:undefined_table, :undefined_column],
       do: true

  defp unavailable_schema?(_error), do: false
  defp truncate(datetime), do: DateTime.truncate(datetime, :microsecond)

  defp canonical_millisecond_utc(%DateTime{} = datetime) do
    datetime = DateTime.shift_zone!(datetime, "Etc/UTC")

    {{year, month, day}, {hour, minute, second}} =
      datetime
      |> DateTime.to_naive()
      |> NaiveDateTime.to_erl()

    {microsecond, _precision} = datetime.microsecond
    millisecond = div(microsecond, 1000)

    "#{pad(year, 4)}-#{pad(month, 2)}-#{pad(day, 2)}T#{pad(hour, 2)}:#{pad(minute, 2)}:#{pad(second, 2)}.#{pad(millisecond, 3)}Z"
  end

  defp pad(value, size) do
    value
    |> Integer.to_string()
    |> String.pad_leading(size, "0")
  end
end
