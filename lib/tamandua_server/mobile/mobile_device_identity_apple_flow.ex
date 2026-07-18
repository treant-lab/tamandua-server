defmodule TamanduaServer.Mobile.MobileDeviceIdentityAppleFlow do
  @moduledoc false

  import Ecto.Query

  alias TamanduaServer.Mobile.{
    MobileDeviceIdentity,
    MobileDeviceIdentityAppleAppAttest,
    MobileDeviceIdentityAppleContext,
    MobileDeviceIdentityChallenge
  }

  alias TamanduaServer.Repo

  @protocol "tamandua.mobile.app-attest/v1"
  @provider "apple_app_attest"
  @ttl_seconds 300
  @challenge_bytes 32

  def issue_challenge(organization_id, params, opts \\ []) do
    now = now(opts)
    profile_id = value(params, "profile_id")

    with :ok <- validate_request_binding(params, organization_id, nil),
         {:ok, profile} <- MobileDeviceIdentityAppleAppAttest.configured_profile(profile_id),
         installation_id when is_binary(installation_id) <- value(params, "installation_id"),
         true <- canonical_string?(installation_id, 255) do
      payload = :crypto.strong_rand_bytes(@challenge_bytes)

      attrs = %{
        organization_id: organization_id,
        installation_id: installation_id,
        profile_id: profile.id,
        environment: profile.environment,
        team_id: profile.team_id,
        bundle_id: profile.bundle_id,
        state: "attest_pending",
        attestation_challenge_digest: :crypto.hash(:sha256, payload),
        expires_at: DateTime.add(now, @ttl_seconds, :second)
      }

      case %MobileDeviceIdentityAppleContext{}
           |> MobileDeviceIdentityAppleContext.changeset(attrs)
           |> Repo.insert() do
        {:ok, context} -> {:ok, challenge_response(context, "attest", payload, now)}
        {:error, changeset} -> {:error, changeset}
      end
    else
      {:error, _reason} = error -> error
      _ -> {:error, :invalid_app_attest_request}
    end
  end

  def submit_attestation(organization_id, params, opts \\ []) do
    now = now(opts)

    Repo.transaction(fn ->
      context = locked_context(organization_id, value(params, "challenge_id"))

      with %MobileDeviceIdentityAppleContext{state: "attest_pending"} <- context,
           :ok <- ensure_fresh(context, now),
           :ok <- validate_request_binding(params, organization_id, context),
           {:ok, client_data} <-
             verify_client_data(
               value(params, "client_data"),
               context.attestation_challenge_digest
             ),
           {:ok, key_id} <- canonical_base64url(value(params, "key_id_base64url"), 32, 32),
           {:ok, verified} <-
             MobileDeviceIdentityAppleAppAttest.verify_attestation(
               %{
                 "provider" => @provider,
                 "profile_id" => context.profile_id,
                 "key_id_base64url" => Base.url_encode64(key_id, padding: false),
                 "attestation_object_base64url" => value(params, "attestation_object_base64url")
               },
               client_data
             ),
           assertion_payload <- :crypto.strong_rand_bytes(@challenge_bytes),
           {:ok, assertion_challenge} <-
             insert_assertion_challenge(context, assertion_payload, now),
           receipt_id <- Ecto.UUID.generate(),
           {:ok, staged} <-
             context
             |> MobileDeviceIdentityAppleContext.changeset(%{
               state: "assert_pending",
               assertion_challenge_id: assertion_challenge.id,
               receipt_id: receipt_id,
               credential_id: verified.credential_id,
               public_key_spki: verified.public_key_spki,
               receipt_sha256: verified.receipt_sha256,
               validation_category: verified.validation_category,
               bundle_version: verified.bundle_version,
               metadata: verified.metadata,
               expires_at: assertion_challenge.expires_at
             })
             |> Repo.update() do
        %{
          protocol: @protocol,
          provider: @provider,
          phase: "attest",
          challenge_id: staged.id,
          receipt_id: receipt_id,
          organization_id: staged.organization_id,
          installation_id: staged.installation_id,
          key_id_base64url: Base.url_encode64(staged.credential_id, padding: false),
          profile: public_profile(staged),
          state: "verified",
          attestation_state: "verified_app_attest",
          assertion_challenge:
            challenge_response(assertion_challenge, staged, "assert", assertion_payload, now)
        }
      else
        nil -> Repo.rollback(:app_attest_context_unavailable)
        {:error, reason} -> Repo.rollback(reason)
        _ -> Repo.rollback(:invalid_app_attest_request)
      end
    end)
  end

  def submit_assertion(organization_id, params, opts \\ []) do
    now = now(opts)

    Repo.transaction(fn ->
      context = locked_context(organization_id, value(params, "parent_attestation_challenge_id"))

      challenge =
        if context && context.assertion_challenge_id do
          MobileDeviceIdentityChallenge
          |> MobileDeviceIdentityChallenge.pending_for_organization(
            organization_id,
            context.assertion_challenge_id
          )
          |> lock("FOR UPDATE")
          |> Repo.one()
        end

      with %MobileDeviceIdentityAppleContext{state: "assert_pending"} <- context,
           %MobileDeviceIdentityChallenge{} <- challenge,
           :ok <- ensure_fresh(context, now),
           :ok <- ensure_fresh(challenge, now),
           :ok <- validate_assertion_binding(params, organization_id, context, challenge),
           {:ok, client_data} <-
             verify_client_data(value(params, "client_data"), challenge.challenge_digest),
           {:ok, verified} <-
             MobileDeviceIdentityAppleAppAttest.verify_first_assertion(
               %{
                 "provider" => @provider,
                 "key_id_base64url" => value(params, "key_id_base64url"),
                 "assertion_base64url" => value(params, "assertion_base64url")
               },
               client_data,
               stored_context(context)
             ),
           {:ok, identity} <-
             MobileDeviceIdentity.activate_apple_app_attest(context, challenge, verified, now),
           {:ok, consumed} <-
             context
             |> MobileDeviceIdentityAppleContext.changeset(%{
               state: "consumed",
               consumed_at: now
             })
             |> Repo.update() do
        %{
          protocol: @protocol,
          provider: @provider,
          phase: "assert",
          challenge_id: challenge.id,
          receipt_id: Ecto.UUID.generate(),
          parent_attestation_receipt_id: consumed.receipt_id,
          parent_attestation_challenge_id: consumed.id,
          organization_id: consumed.organization_id,
          installation_id: consumed.installation_id,
          key_id_base64url: Base.url_encode64(consumed.credential_id, padding: false),
          profile: public_profile(consumed),
          state: "verified",
          attestation_state: "verified_app_attest",
          assertion_state: "verified",
          device_key_id: identity.device_key_id
        }
      else
        nil -> Repo.rollback(:app_attest_context_unavailable)
        {:error, reason} -> Repo.rollback(reason)
        _ -> Repo.rollback(:invalid_app_attest_request)
      end
    end)
  end

  defp locked_context(organization_id, id) do
    MobileDeviceIdentityAppleContext
    |> MobileDeviceIdentityAppleContext.pending_for_tenant(organization_id, id)
    |> lock("FOR UPDATE")
    |> Repo.one()
  end

  defp insert_assertion_challenge(context, payload, now) do
    %MobileDeviceIdentityChallenge{}
    |> MobileDeviceIdentityChallenge.changeset(%{
      organization_id: context.organization_id,
      installation_id: context.installation_id,
      platform: "ios",
      purpose: "enroll",
      key_scope_id:
        MobileDeviceIdentity.key_scope_id(context.organization_id, context.installation_id),
      challenge_digest: :crypto.hash(:sha256, payload),
      state: "pending",
      issued_at: now,
      expires_at: DateTime.add(now, @ttl_seconds, :second)
    })
    |> Repo.insert()
  end

  defp validate_request_binding(params, organization_id, context) do
    expected_installation = context && context.installation_id

    phase_binding_valid =
      if is_nil(context) do
        value(params, "platform") == "ios" and value(params, "purpose") == "bind"
      else
        true
      end

    valid =
      value(params, "protocol") == @protocol and value(params, "provider") == @provider and
        value(params, "organization_id") == organization_id and phase_binding_valid and
        (is_nil(expected_installation) or
           value(params, "installation_id") == expected_installation) and
        (is_nil(context) or profile_matches?(value(params, "profile"), context))

    if valid, do: :ok, else: {:error, :app_attest_binding_mismatch}
  end

  defp validate_assertion_binding(params, organization_id, context, challenge) do
    valid =
      value(params, "protocol") == @protocol and value(params, "provider") == @provider and
        value(params, "organization_id") == organization_id and
        value(params, "installation_id") == context.installation_id and
        value(params, "challenge_id") == challenge.id and
        value(params, "parent_attestation_receipt_id") == context.receipt_id and
        value(params, "parent_attestation_challenge_id") == context.id and
        profile_matches?(value(params, "profile"), context)

    if valid, do: :ok, else: {:error, :app_attest_binding_mismatch}
  end

  defp profile_matches?(profile, context) when is_map(profile) do
    value(profile, "team_id") == context.team_id and
      value(profile, "bundle_id") == context.bundle_id and
      value(profile, "environment") == context.environment
  end

  defp profile_matches?(_profile, _context), do: false

  defp verify_client_data(client_data, expected_digest) when is_map(client_data) do
    with {:ok, payload} <- canonical_base64url(value(client_data, "payload_base64url"), 1, 8_192),
         {:ok, claimed_hash} <-
           canonical_base64url(value(client_data, "sha256_base64url"), 32, 32),
         digest <- :crypto.hash(:sha256, payload),
         true <- digest == claimed_hash and digest == expected_digest do
      {:ok, payload}
    else
      _ -> {:error, :app_attest_client_data_mismatch}
    end
  end

  defp verify_client_data(_client_data, _digest), do: {:error, :app_attest_client_data_mismatch}

  defp challenge_response(context, phase, payload, now) do
    %{
      protocol: @protocol,
      provider: @provider,
      phase: phase,
      challenge_id: context.id,
      organization_id: context.organization_id,
      installation_id: context.installation_id,
      platform: "ios",
      purpose: "bind",
      profile: public_profile(context),
      client_data: client_data(payload),
      issued_at: DateTime.to_iso8601(now),
      expires_at: DateTime.to_iso8601(context.expires_at)
    }
  end

  defp challenge_response(challenge, context, phase, payload, now) do
    challenge_response(
      %{context | id: challenge.id, expires_at: challenge.expires_at},
      phase,
      payload,
      now
    )
    |> Map.put(:parent_attestation_receipt_id, context.receipt_id)
    |> Map.put(:parent_attestation_challenge_id, context.id)
  end

  defp client_data(payload) do
    %{
      payload_base64url: Base.url_encode64(payload, padding: false),
      sha256_base64url: Base.url_encode64(:crypto.hash(:sha256, payload), padding: false)
    }
  end

  defp public_profile(context) do
    %{team_id: context.team_id, bundle_id: context.bundle_id, environment: context.environment}
  end

  defp stored_context(context) do
    %{
      profile_id: context.profile_id,
      environment: context.environment,
      team_id: context.team_id,
      bundle_id: context.bundle_id,
      credential_id: context.credential_id,
      public_key_spki: context.public_key_spki,
      receipt_sha256: context.receipt_sha256,
      validation_category: context.validation_category,
      bundle_version: context.bundle_version,
      metadata: context.metadata
    }
  end

  defp ensure_fresh(record, now) do
    if DateTime.compare(now, record.expires_at) == :lt,
      do: :ok,
      else: {:error, :app_attest_context_expired}
  end

  defp canonical_base64url(value, minimum, maximum) when is_binary(value) do
    maximum_encoded = div(maximum * 4 + 2, 3)

    with true <- byte_size(value) <= maximum_encoded,
         {:ok, decoded} <- Base.url_decode64(value, padding: false),
         true <- byte_size(decoded) in minimum..maximum,
         true <- Base.url_encode64(decoded, padding: false) == value do
      {:ok, decoded}
    else
      _ -> {:error, :invalid_app_attest_request}
    end
  end

  defp canonical_base64url(_value, _minimum, _maximum),
    do: {:error, :invalid_app_attest_request}

  defp canonical_string?(value, maximum) do
    is_binary(value) and byte_size(value) in 1..maximum and value == String.trim(value)
  end

  defp value(map, key) when is_map(map) do
    Map.get(map, key) ||
      Enum.find_value(map, fn
        {candidate, value} when is_atom(candidate) ->
          if Atom.to_string(candidate) == key, do: value

        _ ->
          nil
      end)
  end

  defp value(_map, _key), do: nil

  defp now(opts),
    do: opts |> Keyword.get(:now, DateTime.utc_now()) |> DateTime.truncate(:microsecond)
end
