defmodule TamanduaServer.Mobile.MobileDeviceIdentity do
  @moduledoc """
  Server-owned mobile device proof-of-possession protocol.

  The protocol deliberately keeps installation identity, cryptographic proof,
  and platform attestation as separate facts. This module verifies P-256 proof
  of possession and upgrades Android Key Attestation only when the server can
  validate the signed evidence against explicitly configured trust roots.

  Route/controller integration is intentionally separate. Callers must use the
  returned, server-owned installation and tenant values when registering the
  mobile endpoint.
  """

  import Ecto.Query

  alias TamanduaServer.Mobile.{
    MobileDeviceIdentityCandidateLock,
    MobileDeviceIdentityChallenge,
    MobileDeviceIdentityAndroidAttestation,
    MobileDeviceIdentityKey,
    MobileDeviceIdentityProviderKey,
    MobileDeviceIdentityRecovery
  }

  alias TamanduaServer.Repo

  @protocol "tamandua.mobile.device-pop/v1"
  @algorithm "ecdsa-p256-sha256"
  @challenge_bytes 32
  @default_ttl_seconds 300
  @minimum_ttl_seconds 30
  @maximum_ttl_seconds 600
  @device_key_domain "tamandua.mobile.device-key/v1"
  @key_scope_domain "tamandua.mobile.key-scope/v1"
  @installation_lock_domain "tamandua.mobile.installation-lock/v1"

  # Canonical DER prefix for an uncompressed prime256v1 SubjectPublicKeyInfo.
  # Restricting the accepted algorithm identifier prevents an RSA or another
  # EC curve from being accepted under the P-256 protocol label.
  @p256_spki_prefix <<
    0x30,
    0x59,
    0x30,
    0x13,
    0x06,
    0x07,
    0x2A,
    0x86,
    0x48,
    0xCE,
    0x3D,
    0x02,
    0x01,
    0x06,
    0x08,
    0x2A,
    0x86,
    0x48,
    0xCE,
    0x3D,
    0x03,
    0x01,
    0x07,
    0x03,
    0x42,
    0x00,
    0x04
  >>

  @type issue_result :: %{
          algorithm: String.t(),
          challenge: String.t(),
          challenge_id: Ecto.UUID.t(),
          expires_at: String.t(),
          installation_id: String.t(),
          issued_at: String.t(),
          key_scope_id: String.t(),
          organization_id: Ecto.UUID.t(),
          platform: String.t(),
          protocol: String.t(),
          purpose: String.t()
        }

  @doc """
  Issues a 256-bit one-time challenge and stores only its SHA-256 digest.

  `:now` is injectable for deterministic tests. TTL is bounded to 30..600
  seconds so a caller cannot accidentally create long-lived bearer material.
  """
  @spec issue_challenge(Ecto.UUID.t(), map(), keyword()) ::
          {:ok, issue_result()} | {:error, Ecto.Changeset.t() | :invalid_ttl}
  def issue_challenge(organization_id, attrs, opts \\ []) do
    with {:ok, ttl_seconds} <- challenge_ttl(opts) do
      now = opts |> Keyword.get(:now, DateTime.utc_now()) |> truncate_datetime()
      token = @challenge_bytes |> :crypto.strong_rand_bytes() |> base64url()
      installation_id = value(attrs, :installation_id)

      challenge_attrs = %{
        organization_id: organization_id,
        installation_id: installation_id,
        platform: normalize_string(value(attrs, :platform)),
        purpose: normalize_string(value(attrs, :purpose, "enroll")),
        key_scope_id: derive_key_scope_id(organization_id, installation_id),
        challenge_digest: :crypto.hash(:sha256, token),
        state: "pending",
        issued_at: now,
        expires_at: DateTime.add(now, ttl_seconds, :second)
      }

      case %MobileDeviceIdentityChallenge{}
           |> MobileDeviceIdentityChallenge.changeset(challenge_attrs)
           |> Repo.insert() do
        {:ok, challenge} -> {:ok, issue_response(challenge, token)}
        {:error, changeset} -> {:error, changeset}
      end
    end
  end

  @doc """
  Verifies and consumes a challenge, then binds or rotates a P-256 key.

  Required proof fields are `challenge_id`, `challenge`, `public_key_spki`,
  `device_key_id`, `signature`, and `algorithm`. Binary values use unpadded
  base64url. Rotation additionally requires `previous_device_key_id` and
  `previous_signature`; both old and new keys sign the same transition payload.
  """
  @spec verify_and_bind(Ecto.UUID.t(), map(), keyword()) ::
          {:ok, MobileDeviceIdentityKey.t()} | {:error, atom() | Ecto.Changeset.t()}
  def verify_and_bind(organization_id, proof, opts \\ []) do
    now = opts |> Keyword.get(:now, DateTime.utc_now()) |> truncate_datetime()

    Repo.transaction(fn ->
      case verify_and_bind_transaction(organization_id, proof, now) do
        {:ok, key} -> key
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  @doc """
  Builds the exact bytes signed by the mobile key.

  Dynamic values are base64url encoded and fields have a fixed order. This
  avoids JSON ordering, escaping, locale, and newline ambiguity across Kotlin,
  Swift, JavaScript, and Elixir implementations.
  """
  @spec canonical_payload(
          MobileDeviceIdentityChallenge.t(),
          String.t(),
          String.t(),
          String.t()
        ) :: binary()
  def canonical_payload(challenge, cleartext_challenge, device_key_id, algorithm \\ @algorithm) do
    [
      {"protocol", @protocol},
      {"challenge_id", challenge.id},
      {"challenge", cleartext_challenge},
      {"organization_id", challenge.organization_id},
      {"installation_id", challenge.installation_id},
      {"platform", challenge.platform},
      {"purpose", challenge.purpose},
      {"key_scope_id", challenge.key_scope_id},
      {"device_key_id", device_key_id},
      {"algorithm", algorithm},
      {"issued_at", DateTime.to_iso8601(challenge.issued_at)},
      {"expires_at", DateTime.to_iso8601(challenge.expires_at)}
    ]
    |> Enum.map_join("\n", fn {name, field_value} ->
      name <> "=" <> base64url(to_string(field_value))
    end)
  end

  @doc false
  def key_scope_id(organization_id, installation_id),
    do: derive_key_scope_id(organization_id, installation_id)

  @doc false
  def activate_apple_app_attest(context, challenge, assertion_result, now) do
    public_key_spki = Map.fetch!(context, :public_key_spki)
    device_key_id = derive_device_key_id(context.organization_id, public_key_spki)

    proof = %{
      server_attestation: %{
        state: "verified_app_attest",
        metadata: Map.fetch!(assertion_result, :metadata),
        provider_binding: Map.fetch!(assertion_result, :provider_binding)
      }
    }

    with :ok <- lock_installations(context.organization_id, [context.installation_id]),
         :ok <-
           MobileDeviceIdentityCandidateLock.lock_keys(context.organization_id, device_key_id),
         nil <- active_key_for_update(context.organization_id, context.installation_id),
         false <- identity_history?(context.organization_id, context.installation_id),
         :ok <-
           ensure_candidate_not_reserved_elsewhere(
             context.organization_id,
             context.installation_id,
             device_key_id,
             now
           ),
         {:ok, key} <-
           insert_verified_key(challenge, proof, public_key_spki, device_key_id, nil, now),
         {:ok, _consumed} <- consume_challenge(challenge, now) do
      {:ok, key}
    else
      %MobileDeviceIdentityKey{} -> {:error, :rotation_required}
      true -> {:error, :re_enrollment_authorization_required}
      {:error, _reason} = error -> error
    end
  end

  @doc "Server-derived, tenant-scoped public identifier for an SPKI key."
  @spec derive_device_key_id(Ecto.UUID.t(), binary()) :: String.t()
  def derive_device_key_id(organization_id, public_key_spki)
      when is_binary(organization_id) and is_binary(public_key_spki) do
    digest =
      :crypto.hash(
        :sha256,
        @device_key_domain <> <<0>> <> organization_id <> <<0>> <> public_key_spki
      )

    "tmdk_v1_" <> base64url(digest)
  end

  @doc "Returns true when legacy registration must not update a bound install."
  @spec proof_required?(Ecto.UUID.t(), String.t()) :: boolean()
  def proof_required?(organization_id, installation_id) do
    identity_history?(organization_id, installation_id)
  end

  @doc """
  Serializes a legacy mutation with device-key bind, rotation, and revocation.

  The callback runs inside the same database transaction that owns ordered,
  tenant-scoped PostgreSQL advisory locks. It is deliberately restricted to a
  zero-arity database callback; callers must keep network calls and other
  irreversible effects outside it and must supply every installation ID that
  the callback can mutate.
  """
  @spec with_legacy_unbound(
          Ecto.UUID.t(),
          String.t() | [String.t()],
          (-> {:ok, term()} | {:error, term()})
        ) ::
          {:ok, term()} | {:error, term()}
  def with_legacy_unbound(organization_id, installation_ids, callback)
      when is_binary(organization_id) and is_function(callback, 0) do
    with {:ok, installation_ids} <- normalize_installation_ids(installation_ids) do
      Repo.transaction(fn ->
        lock_installations(organization_id, installation_ids)

        if Enum.any?(installation_ids, &identity_history?(organization_id, &1)) do
          Repo.rollback(:device_identity_proof_required)
        else
          case callback.() do
            {:ok, result} -> result
            {:error, reason} -> Repo.rollback(reason)
            _other -> Repo.rollback(:invalid_callback_result)
          end
        end
      end)
    end
  end

  def with_legacy_unbound(_organization_id, _installation_ids, _callback),
    do: {:error, :invalid_installation_ids}

  @doc """
  Serializes a registration decision and its database mutation.

  Every installation is locked in canonical order before its legacy-unbound or
  verified-proof decision is evaluated. The callback then runs in that same
  transaction, preventing an identity bind, rotation, or revocation from
  racing between authorization and the Device/Agent mutation.
  """
  @spec with_registration_mutation(
          Ecto.UUID.t(),
          [{String.t(), map() | nil}],
          (-> {:ok, term()} | {:error, term()})
        ) :: {:ok, term()} | {:error, term()}
  def with_registration_mutation(organization_id, registrations, callback)
      when is_binary(organization_id) and is_function(callback, 0) do
    with {:ok, registrations} <- normalize_registration_requests(registrations) do
      installation_ids = Enum.map(registrations, &elem(&1, 0))

      Repo.transaction(fn ->
        lock_installations(organization_id, installation_ids)

        Enum.each(registrations, fn {installation_id, proof_context} ->
          case registration_decision(organization_id, installation_id, proof_context) do
            {:allow, _mode} -> :ok
            {:deny, reason} -> Repo.rollback(reason)
          end
        end)

        case callback.() do
          {:ok, result} -> result
          {:error, reason} -> Repo.rollback(reason)
          _other -> Repo.rollback(:invalid_callback_result)
        end
      end)
    end
  end

  def with_registration_mutation(_organization_id, _registrations, _callback),
    do: {:error, :invalid_installation_ids}

  @doc "Revokes the active key without silently creating a replacement."
  @spec revoke_active(Ecto.UUID.t(), String.t(), keyword()) ::
          {:ok, MobileDeviceIdentityKey.t()}
          | {:error, :active_key_not_found | Ecto.Changeset.t()}
  def revoke_active(organization_id, installation_id, opts \\ []) do
    now = opts |> Keyword.get(:now, DateTime.utc_now()) |> truncate_datetime()

    Repo.transaction(fn ->
      lock_installations(organization_id, [installation_id])

      case active_key_for_update(organization_id, installation_id) do
        nil ->
          Repo.rollback(:active_key_not_found)

        active ->
          case active
               |> MobileDeviceIdentityKey.changeset(%{
                 lifecycle_state: "revoked",
                 revoked_at: now
               })
               |> Repo.update() do
            {:ok, revoked} -> revoked
            {:error, changeset} -> Repo.rollback(changeset)
          end
      end
    end)
  end

  @doc """
  Explicit compatibility/downgrade decision for registration callers.

  Unbound installations may use the existing compatibility path. Once an
  active key exists, only the matching verified proof context may proceed.
  """
  @spec registration_decision(Ecto.UUID.t(), String.t(), map() | nil) ::
          {:allow, :legacy_unbound | :verified_device_proof}
          | {:deny, :device_identity_proof_required}
  def registration_decision(organization_id, installation_id, proof_context \\ nil) do
    case active_key(organization_id, installation_id) do
      nil ->
        if identity_history?(organization_id, installation_id) do
          {:deny, :device_identity_proof_required}
        else
          {:allow, :legacy_unbound}
        end

      %MobileDeviceIdentityKey{} = active ->
        if matching_verified_context?(active, proof_context) do
          {:allow, :verified_device_proof}
        else
          {:deny, :device_identity_proof_required}
        end
    end
  end

  defp verify_and_bind_transaction(organization_id, proof, now) do
    challenge_id = value(proof, :challenge_id)

    challenge =
      MobileDeviceIdentityChallenge
      |> MobileDeviceIdentityChallenge.pending_for_organization(organization_id, challenge_id)
      |> lock("FOR UPDATE")
      |> Repo.one()

    with %MobileDeviceIdentityChallenge{} = challenge <- challenge,
         :ok <- ensure_not_expired(challenge, now),
         {:ok, cleartext_challenge} <- required_string(proof, :challenge),
         :ok <- verify_challenge_digest(challenge, cleartext_challenge),
         :ok <- verify_optional_binding(challenge, proof),
         :ok <- verify_algorithm(proof),
         {:ok, public_key_spki} <- decode_public_key(value(proof, :public_key_spki)),
         :ok <- validate_p256_spki(public_key_spki),
         device_key_id <- derive_device_key_id(organization_id, public_key_spki),
         :ok <- verify_claimed_device_key_id(proof, device_key_id),
         payload <- canonical_payload(challenge, cleartext_challenge, device_key_id),
         {:ok, signature} <- decode_signature(value(proof, :signature)),
         :ok <- verify_p256_signature(public_key_spki, payload, signature),
         :ok <- lock_installations(challenge.organization_id, [challenge.installation_id]),
         :ok <-
           MobileDeviceIdentityCandidateLock.lock_keys(challenge.organization_id, device_key_id),
         :ok <-
           ensure_candidate_not_reserved_elsewhere(
             challenge.organization_id,
             challenge.installation_id,
             device_key_id,
             now
           ),
         {:ok, key} <-
           bind_for_purpose(
             challenge,
             proof,
             public_key_spki,
             device_key_id,
             payload,
             cleartext_challenge,
             now
           ),
         {:ok, _consumed} <- consume_challenge(challenge, now) do
      {:ok, key}
    else
      nil -> {:error, :challenge_unavailable}
      {:error, _reason} = error -> error
    end
  end

  defp bind_for_purpose(
         challenge,
         proof,
         public_key_spki,
         device_key_id,
         payload,
         cleartext_challenge,
         now
       ) do
    active = active_key_for_update(challenge.organization_id, challenge.installation_id)

    case {challenge.purpose, active} do
      {"enroll", nil} ->
        if identity_history?(challenge.organization_id, challenge.installation_id) do
          {:error, :re_enrollment_authorization_required}
        else
          with {:ok, proof} <-
                 verify_new_key_attestation(
                   challenge,
                   proof,
                   cleartext_challenge,
                   public_key_spki,
                   payload,
                   now
                 ) do
            insert_verified_key(challenge, proof, public_key_spki, device_key_id, nil, now)
          end
        end

      {"enroll", %MobileDeviceIdentityKey{device_key_id: ^device_key_id} = existing} ->
        with {:ok, proof} <-
               verify_existing_key_attestation(existing, challenge, proof, public_key_spki, now) do
          refresh_existing_key(existing, challenge, proof, now)
        end

      {"enroll", %MobileDeviceIdentityKey{}} ->
        {:error, :rotation_required}

      {"rotate", nil} ->
        {:error, :active_key_not_found}

      {"rotate", %MobileDeviceIdentityKey{device_key_id: ^device_key_id}} ->
        {:error, :replacement_key_must_differ}

      {"rotate", %MobileDeviceIdentityKey{} = previous} ->
        with {:ok, proof} <-
               verify_new_key_attestation(
                 challenge,
                 proof,
                 cleartext_challenge,
                 public_key_spki,
                 payload,
                 now
               ),
             :ok <-
               ensure_attestation_not_downgraded(
                 previous.attestation_state,
                 presented_attestation_state(proof)
               ) do
          rotate_key(previous, challenge, proof, public_key_spki, device_key_id, payload, now)
        end
    end
  end

  defp verify_new_key_attestation(
         challenge,
         proof,
         cleartext_challenge,
         public_key_spki,
         assertion_client_data,
         now
       ) do
    with {:ok, server_attestation} <-
           verify_platform_attestation(
             challenge,
             proof,
             cleartext_challenge,
             public_key_spki,
             assertion_client_data,
             now
           ) do
      {:ok, Map.put(proof, :server_attestation, server_attestation)}
    end
  end

  defp verify_existing_key_attestation(existing, challenge, proof, public_key_spki, now) do
    evidence = value(proof, :attestation_evidence)

    if useful_attestation_evidence?(evidence) do
      with {:ok, challenge_digest} <- stored_attestation_challenge_digest(existing),
           {:ok, server_attestation} <-
             verify_platform_attestation(
               challenge,
               proof,
               {:sha256, challenge_digest},
               public_key_spki,
               nil,
               now,
               if(verified_attestation?(existing.attestation_state), do: :strict, else: :policy)
             ) do
        {:ok, Map.put(proof, :server_attestation, server_attestation)}
      end
    else
      if verified_attestation?(existing.attestation_state) do
        {:error, :attestation_revalidation_required}
      else
        {:ok,
         Map.put(proof, :server_attestation, %{
           state: "not_requested",
           metadata: %{
             "attestation_evidence_present" => false,
             "attestation_revalidation" => "not_requested",
             "attestation_freshness" => "historical_not_revalidated"
           }
         })}
      end
    end
  end

  defp stored_attestation_challenge_digest(existing) do
    case get_in(existing.metadata || %{}, ["attestation_challenge_sha256"]) do
      value when is_binary(value) and byte_size(value) == 64 ->
        case Base.decode16(value, case: :lower) do
          {:ok, digest} when byte_size(digest) == 32 -> {:ok, digest}
          _ -> {:error, :attestation_revalidation_context_missing}
        end

      _ ->
        {:error, :attestation_revalidation_context_missing}
    end
  end

  defp ensure_attestation_not_downgraded(previous, candidate) do
    if attestation_rank(candidate) < attestation_rank(previous) and
         verified_attestation?(previous),
       do: {:error, :attestation_downgrade_forbidden},
       else: :ok
  end

  defp rotate_key(previous, challenge, proof, public_key_spki, device_key_id, payload, now) do
    with {:ok, previous_key_id} <- required_string(proof, :previous_device_key_id),
         true <- previous_key_id == previous.device_key_id || {:error, :previous_key_mismatch},
         {:ok, previous_signature} <- decode_signature(value(proof, :previous_signature)),
         :ok <- verify_p256_signature(previous.public_key_spki, payload, previous_signature),
         {:ok, rotated} <-
           previous
           |> MobileDeviceIdentityKey.changeset(%{
             lifecycle_state: "rotated",
             rotated_at: now,
             revoked_at: now,
             last_proof_at: now
           })
           |> Repo.update(),
         {:ok, replacement} <-
           insert_verified_key(
             challenge,
             proof,
             public_key_spki,
             device_key_id,
             rotated.id,
             now
           ) do
      {:ok, replacement}
    else
      false -> {:error, :previous_key_mismatch}
      {:error, _reason} = error -> error
    end
  end

  defp insert_verified_key(
         challenge,
         proof,
         public_key_spki,
         device_key_id,
         rotated_from_id,
         now
       ) do
    attrs = %{
      organization_id: challenge.organization_id,
      proof_challenge_id: challenge.id,
      rotated_from_id: rotated_from_id,
      installation_id: challenge.installation_id,
      platform: challenge.platform,
      key_scope_id: challenge.key_scope_id,
      device_key_id: device_key_id,
      public_key_spki: public_key_spki,
      algorithm: @algorithm,
      proof_state: "verified",
      attestation_state: presented_attestation_state(proof),
      lifecycle_state: "active",
      activated_at: now,
      last_proof_at: now,
      metadata: attestation_metadata(proof)
    }

    with {:ok, key} <- insert_identity_key(attrs),
         :ok <- persist_provider_binding(key, proof, now) do
      {:ok, key}
    end
  end

  defp insert_identity_key(attrs) do
    case %MobileDeviceIdentityKey{}
         |> MobileDeviceIdentityKey.changeset(attrs)
         |> Repo.insert() do
      {:ok, key} ->
        {:ok, key}

      {:error, changeset} ->
        if unique_constraint_error?(changeset),
          do: {:error, :device_identity_conflict},
          else: {:error, changeset}
    end
  end

  defp unique_constraint_error?(%Ecto.Changeset{errors: errors}) do
    Enum.any?(errors, fn {_field, {_message, metadata}} ->
      Keyword.get(metadata, :constraint) == :unique
    end)
  end

  defp persist_provider_binding(key, proof, now) do
    case value(proof, :server_attestation) do
      %{provider_binding: binding} when is_map(binding) ->
        attrs = %{
          organization_id: key.organization_id,
          identity_key_id: key.id,
          installation_id: key.installation_id,
          provider: Map.fetch!(binding, :provider),
          profile_id: Map.fetch!(binding, :profile_id),
          environment: Map.fetch!(binding, :environment),
          team_id: Map.fetch!(binding, :team_id),
          bundle_id: Map.fetch!(binding, :bundle_id),
          credential_id: Map.fetch!(binding, :credential_id),
          public_key_spki: Map.fetch!(binding, :public_key_spki),
          receipt_sha256: Map.fetch!(binding, :receipt_sha256),
          sign_count: Map.fetch!(binding, :sign_count),
          last_asserted_at: now
        }

        case %MobileDeviceIdentityProviderKey{}
             |> MobileDeviceIdentityProviderKey.changeset(attrs)
             |> Repo.insert() do
          {:ok, _binding} -> :ok
          {:error, _changeset} -> {:error, :device_identity_conflict}
        end

      _ ->
        :ok
    end
  rescue
    KeyError -> {:error, :apple_app_attest_provider_binding_invalid}
  end

  defp refresh_existing_key(existing, challenge, proof, now) do
    existing
    |> MobileDeviceIdentityKey.changeset(%{
      proof_challenge_id: challenge.id,
      last_proof_at: now,
      proof_state: "verified",
      attestation_state:
        strongest_attestation(existing.attestation_state, presented_attestation_state(proof)),
      metadata: Map.merge(existing.metadata || %{}, attestation_metadata(proof))
    })
    |> Repo.update()
  end

  defp consume_challenge(challenge, now) do
    challenge
    |> MobileDeviceIdentityChallenge.changeset(%{state: "consumed", consumed_at: now})
    |> Repo.update()
  end

  defp active_key(organization_id, installation_id) do
    MobileDeviceIdentityKey
    |> MobileDeviceIdentityKey.active_for_installation(organization_id, installation_id)
    |> Repo.one()
  end

  defp active_key_for_update(organization_id, installation_id) do
    MobileDeviceIdentityKey
    |> MobileDeviceIdentityKey.active_for_installation(organization_id, installation_id)
    |> lock("FOR UPDATE")
    |> Repo.one()
  end

  defp identity_history?(organization_id, installation_id) do
    MobileDeviceIdentityKey
    |> where(
      [key],
      key.organization_id == ^organization_id and key.installation_id == ^installation_id
    )
    |> Repo.exists?()
  end

  defp normalize_installation_ids(installation_id) when is_binary(installation_id),
    do: normalize_installation_ids([installation_id])

  defp normalize_installation_ids(installation_ids) when is_list(installation_ids) do
    if installation_ids != [] and Enum.all?(installation_ids, &canonical_installation_id?/1) do
      {:ok, installation_ids |> Enum.uniq() |> Enum.sort()}
    else
      {:error, :invalid_installation_ids}
    end
  end

  defp normalize_installation_ids(_installation_ids), do: {:error, :invalid_installation_ids}

  defp normalize_registration_requests(registrations)
       when is_list(registrations) and registrations != [] do
    valid? =
      Enum.all?(registrations, fn
        {installation_id, proof_context} ->
          canonical_installation_id?(installation_id) and
            (is_nil(proof_context) or is_map(proof_context))

        _other ->
          false
      end)

    if valid? do
      registrations
      |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
      |> Enum.reduce_while([], fn {installation_id, contexts}, acc ->
        case Enum.uniq(contexts) do
          [proof_context] -> {:cont, [{installation_id, proof_context} | acc]}
          _conflicting_contexts -> {:halt, :error}
        end
      end)
      |> case do
        :error -> {:error, :invalid_installation_ids}
        normalized -> {:ok, Enum.sort_by(normalized, &elem(&1, 0))}
      end
    else
      {:error, :invalid_installation_ids}
    end
  end

  defp normalize_registration_requests(_registrations),
    do: {:error, :invalid_installation_ids}

  defp canonical_installation_id?(installation_id) when is_binary(installation_id) do
    byte_size(installation_id) <= 255 and installation_id == String.trim(installation_id) and
      installation_id != ""
  end

  defp canonical_installation_id?(_installation_id), do: false

  defp lock_installations(organization_id, installation_ids) do
    Enum.each(installation_ids, fn installation_id ->
      {key_one, key_two} = installation_lock_keys(organization_id, installation_id)

      Ecto.Adapters.SQL.query!(
        Repo,
        "SELECT pg_advisory_xact_lock($1, $2)",
        [key_one, key_two]
      )
    end)

    :ok
  end

  defp installation_lock_keys(organization_id, installation_id) do
    digest =
      :crypto.hash(
        :sha256,
        @installation_lock_domain <> <<0>> <> organization_id <> <<0>> <> installation_id
      )

    <<key_one::signed-32, key_two::signed-32, _rest::binary>> = digest
    {key_one, key_two}
  end

  defp ensure_candidate_not_reserved_elsewhere(
         organization_id,
         installation_id,
         device_key_id,
         now
       ) do
    reserved_elsewhere? =
      MobileDeviceIdentityRecovery
      |> where(
        [intent],
        intent.organization_id == ^organization_id and
          intent.candidate_device_key_id == ^device_key_id and intent.state == "pending" and
          intent.expires_at > ^now and intent.installation_id != ^installation_id
      )
      |> Repo.exists?()

    if reserved_elsewhere?, do: {:error, :candidate_key_reserved}, else: :ok
  end

  defp matching_verified_context?(active, %MobileDeviceIdentityKey{} = proof) do
    proof.organization_id == active.organization_id and
      proof.installation_id == active.installation_id and
      proof.device_key_id == active.device_key_id and proof.proof_state == "verified" and
      proof.lifecycle_state == "active"
  end

  defp matching_verified_context?(active, proof) when is_map(proof) do
    key_scope_id = value(proof, :key_scope_id)

    value(proof, :installation_id) == active.installation_id and
      value(proof, :device_key_id) == active.device_key_id and
      value(proof, :proof_state) == "verified" and
      value(proof, :proof_required) in [true, "true"] and
      (key_scope_id in [nil, ""] or key_scope_id == active.key_scope_id)
  end

  defp matching_verified_context?(_active, _proof), do: false

  defp verify_challenge_digest(challenge, cleartext_challenge) do
    candidate = :crypto.hash(:sha256, cleartext_challenge)

    if byte_size(candidate) == byte_size(challenge.challenge_digest) and
         Plug.Crypto.secure_compare(candidate, challenge.challenge_digest) do
      :ok
    else
      {:error, :challenge_mismatch}
    end
  end

  defp ensure_not_expired(challenge, now) do
    if DateTime.compare(now, challenge.expires_at) == :lt do
      :ok
    else
      {:error, :challenge_expired}
    end
  end

  defp verify_optional_binding(challenge, proof) do
    bindings = [
      installation_id: challenge.installation_id,
      platform: challenge.platform,
      purpose: challenge.purpose,
      key_scope_id: challenge.key_scope_id
    ]

    if Enum.all?(bindings, fn {field, expected} ->
         case value(proof, field) do
           nil -> true
           supplied -> supplied == expected
         end
       end) do
      :ok
    else
      {:error, :challenge_binding_mismatch}
    end
  end

  defp verify_algorithm(proof) do
    if value(proof, :algorithm) == @algorithm, do: :ok, else: {:error, :unsupported_algorithm}
  end

  defp verify_claimed_device_key_id(proof, calculated) do
    if value(proof, :device_key_id) == calculated,
      do: :ok,
      else: {:error, :device_key_id_mismatch}
  end

  defp decode_public_key(encoded), do: decode_base64url(encoded, 64, 512, :invalid_public_key)
  defp decode_signature(encoded), do: decode_base64url(encoded, 8, 128, :invalid_signature)

  defp decode_base64url(encoded, minimum, maximum, error) when is_binary(encoded) do
    with {:ok, decoded} <- Base.url_decode64(encoded, padding: false),
         true <- byte_size(decoded) >= minimum and byte_size(decoded) <= maximum do
      {:ok, decoded}
    else
      _ -> {:error, error}
    end
  end

  defp decode_base64url(_encoded, _minimum, _maximum, error), do: {:error, error}

  defp validate_p256_spki(
         <<prefix::binary-size(27), _x_coordinate::binary-size(32),
           _y_coordinate::binary-size(32)>> =
           spki
       )
       when byte_size(spki) == 91 and prefix == @p256_spki_prefix,
       do: :ok

  defp validate_p256_spki(_spki), do: {:error, :invalid_p256_public_key}

  defp verify_p256_signature(public_key_spki, payload, signature) do
    public_key =
      :public_key.pem_entry_decode({:SubjectPublicKeyInfo, public_key_spki, :not_encrypted})

    if :public_key.verify(payload, :sha256, signature, public_key) do
      :ok
    else
      {:error, :invalid_signature}
    end
  rescue
    _ -> {:error, :invalid_public_key}
  catch
    _, _ -> {:error, :invalid_public_key}
  end

  defp verify_platform_attestation(
         challenge,
         proof,
         expected_challenge,
         public_key_spki,
         _assertion_client_data,
         now,
         failure_mode \\ :policy
       ) do
    evidence = value(proof, :attestation_evidence)

    cond do
      not useful_attestation_evidence?(evidence) ->
        {:ok, unverified_attestation_result(false, "not_requested")}

      challenge.platform == "ios" ->
        {:error, :apple_app_attest_staged_flow_required}

      challenge.platform != "android" ->
        {:ok, unverified_attestation_result(true, "unsupported_platform")}

      true ->
        with {:ok, challenge_verifier} <- attestation_challenge_verifier(expected_challenge),
             {:ok, result} <-
               MobileDeviceIdentityAndroidAttestation.verify(
                 evidence,
                 challenge_verifier,
                 public_key_spki,
                 now: now
               ) do
          {:ok, result}
        else
          {:error, reason} ->
            preserve_or_reject_android_attestation(reason, expected_challenge, failure_mode)

          _ ->
            preserve_or_reject_android_attestation(
              :android_attestation_invalid,
              expected_challenge,
              failure_mode
            )
        end
    end
  end

  defp attestation_challenge_verifier({:sha256, digest}) when byte_size(digest) == 32,
    do: {:ok, {:sha256, digest}}

  defp attestation_challenge_verifier(cleartext) when is_binary(cleartext) do
    Base.url_decode64(cleartext, padding: false)
  end

  defp attestation_challenge_verifier(_value), do: {:error, :android_attestation_invalid}

  defp preserve_or_reject_android_attestation(reason, expected_challenge, failure_mode) do
    policy = MobileDeviceIdentityAndroidAttestation.unverified_evidence_policy()

    case {failure_mode, policy} do
      {:strict, _policy} ->
        {:error, :android_key_attestation_revalidation_failed}

      {_failure_mode, :preserve} ->
        result = unverified_attestation_result(true, Atom.to_string(reason))

        {:ok,
         update_in(result, [:metadata], fn metadata ->
           Map.put(
             metadata,
             "attestation_challenge_sha256",
             expected_challenge_sha256(expected_challenge)
           )
         end)}

      {_failure_mode, :reject} ->
        {:error, :android_key_attestation_invalid}
    end
  end

  defp expected_challenge_sha256({:sha256, digest}), do: Base.encode16(digest, case: :lower)

  defp expected_challenge_sha256(cleartext) do
    case Base.url_decode64(cleartext, padding: false) do
      {:ok, challenge} ->
        :crypto.hash(:sha256, challenge) |> Base.encode16(case: :lower)

      _ ->
        "invalid"
    end
  end

  defp unverified_attestation_result(evidence_present, verification) do
    %{
      state: if(evidence_present, do: "present_unverified", else: "not_requested"),
      metadata: %{
        "attestation_evidence_present" => evidence_present,
        "attestation_verification" => verification
      }
    }
  end

  defp presented_attestation_state(proof) do
    case value(proof, :server_attestation) do
      %{state: state} when is_binary(state) -> state
      _ -> "not_requested"
    end
  end

  defp useful_attestation_evidence?(value) when is_binary(value), do: String.trim(value) != ""
  defp useful_attestation_evidence?(value) when is_list(value), do: value != []
  defp useful_attestation_evidence?(value) when is_map(value), do: map_size(value) > 0
  defp useful_attestation_evidence?(_value), do: false

  defp attestation_metadata(proof) do
    server_metadata =
      case value(proof, :server_attestation) do
        %{metadata: metadata} when is_map(metadata) -> metadata
        _ -> %{}
      end

    Map.put(
      server_metadata,
      "client_attestation_claim_ignored",
      not is_nil(value(proof, :attestation_state))
    )
  end

  defp strongest_attestation(existing, candidate) do
    if attestation_rank(candidate) > attestation_rank(existing),
      do: candidate,
      else: existing
  end

  defp verified_attestation?(state), do: attestation_rank(state) >= 2

  defp attestation_rank("not_requested"), do: 0
  defp attestation_rank("present_unverified"), do: 1
  defp attestation_rank("verified_software"), do: 2
  defp attestation_rank("verified_tee"), do: 3
  defp attestation_rank("verified_strongbox"), do: 4
  defp attestation_rank("verified_app_attest"), do: 4
  defp attestation_rank(_state), do: -1

  defp issue_response(challenge, token) do
    %{
      protocol: @protocol,
      algorithm: @algorithm,
      challenge_id: challenge.id,
      challenge: token,
      organization_id: challenge.organization_id,
      installation_id: challenge.installation_id,
      platform: challenge.platform,
      purpose: challenge.purpose,
      key_scope_id: challenge.key_scope_id,
      issued_at: DateTime.to_iso8601(challenge.issued_at),
      expires_at: DateTime.to_iso8601(challenge.expires_at)
    }
  end

  defp derive_key_scope_id(organization_id, installation_id)
       when is_binary(organization_id) and is_binary(installation_id) do
    digest =
      :crypto.hash(
        :sha256,
        @key_scope_domain <> <<0>> <> organization_id <> <<0>> <> installation_id
      )

    "tmdks_v1_" <> base64url(digest)
  end

  defp derive_key_scope_id(_organization_id, _installation_id), do: nil

  defp challenge_ttl(opts) do
    ttl_seconds = Keyword.get(opts, :ttl_seconds, @default_ttl_seconds)

    if is_integer(ttl_seconds) and ttl_seconds >= @minimum_ttl_seconds and
         ttl_seconds <= @maximum_ttl_seconds do
      {:ok, ttl_seconds}
    else
      {:error, :invalid_ttl}
    end
  end

  defp required_string(map, field) do
    case value(map, field) do
      supplied when is_binary(supplied) ->
        supplied = String.trim(supplied)
        if supplied == "", do: {:error, :missing_proof_field}, else: {:ok, supplied}

      _ ->
        {:error, :missing_proof_field}
    end
  end

  defp value(map, key, default \\ nil)

  defp value(map, key, default) when is_map(map),
    do: Map.get(map, key, Map.get(map, to_string(key), default))

  defp value(_map, _key, default), do: default

  defp normalize_string(value) when is_binary(value),
    do: value |> String.trim() |> String.downcase()

  defp normalize_string(value), do: value

  defp truncate_datetime(%DateTime{} = datetime), do: DateTime.truncate(datetime, :microsecond)

  defp base64url(value), do: Base.url_encode64(value, padding: false)
end
