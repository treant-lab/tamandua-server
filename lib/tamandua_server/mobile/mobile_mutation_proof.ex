defmodule TamanduaServer.Mobile.MobileMutationProof do
  @moduledoc """
  Issues and consumes fresh proof-of-possession authorizations for mobile V2
  device upserts.

  `consume/6` deliberately requires an already-open transaction and locks both
  the authorization and its identity key. The caller can therefore include the
  authorization consume and its DeviceV2/Agent writes in one atomic database
  transaction.
  """

  import Ecto.Query

  alias TamanduaServer.Mobile.{
    MobileDeviceIdentityKey,
    MobileDeviceIdentityRecovery,
    MobileMutationAuthorization
  }

  alias TamanduaServer.Repo

  @protocol "tamandua.mobile.device-mutation/v1"
  @message_type "mobile_device_v2_mutation"
  @message_version "1"
  @operation "mobile_device_v2_upsert"
  @http_method "POST"
  @route_id "mobile_v2_devices_upsert"
  @algorithm "ecdsa-p256-sha256"
  @default_ttl 120
  @maximum_ttl 300
  @maximum_body_bytes 65_536
  @maximum_json_depth 16
  @maximum_json_nodes 2_048
  @maximum_safe_integer 9_007_199_254_740_991
  @installation_lock_domain "tamandua.mobile.installation-lock/v1"

  @canonical_fields ~w(
    protocol message_type message_version organization_id actor_id
    installation_id platform device_key_id key_scope_id request_id
    challenge_id nonce operation http_method route_id resource_id
    body_sha256 algorithm issued_at expires_at
  )

  @type issued :: %{
          authorization_id: Ecto.UUID.t(),
          request_id: String.t(),
          challenge_id: String.t(),
          nonce: String.t(),
          payload: binary(),
          signed_fields: %{required(String.t()) => String.t()},
          algorithm: String.t(),
          expires_at: DateTime.t()
        }

  @doc """
  Issues an internal authorization result.

  HTTP adapters must project exactly `authorization_id` and `signed_fields`
  into the authorization object. Challenge, nonce, algorithm, and expiry are
  already inside `signed_fields`; callers must never reconstruct or accept
  signed fields from request data.
  """
  @spec issue(binary(), map(), keyword()) :: {:ok, issued()} | {:error, term()}
  def issue(organization_id, attrs, opts \\ []) do
    repo = Keyword.get(opts, :repo, Repo)
    now = opts |> Keyword.get(:now, DateTime.utc_now()) |> normalize_time()
    ttl = Keyword.get(opts, :ttl, @default_ttl)

    with :ok <- validate_ttl(ttl),
         {:ok, actor_id} <- required_string(attrs, :actor_id),
         {:ok, installation_id} <- required_string(attrs, :installation_id),
         {:ok, resource_id} <- required_string(attrs, :resource_id),
         {:ok, body_sha256} <- request_body_sha256(value(attrs, :body)) do
      repo.transaction(fn ->
        with :ok <- lock_installation(repo, organization_id, installation_id),
             :ok <-
               MobileDeviceIdentityRecovery.enforce_signed_posture_barrier(
                 organization_id,
                 installation_id,
                 now
               ) do
          key =
            repo.one(
              from(key in MobileDeviceIdentityKey,
                where:
                  key.organization_id == ^organization_id and
                    key.installation_id == ^installation_id and
                    key.lifecycle_state == "active" and key.proof_state == "verified",
                lock: "FOR UPDATE"
              )
            )

          if key do
            persist_issued(repo, key, actor_id, resource_id, body_sha256, now, ttl)
          else
            repo.rollback(:active_identity_key_not_found)
          end
        else
          {:error, reason} -> repo.rollback(reason)
        end
      end)
      |> unwrap_transaction()
    end
  end

  @spec consume(module(), binary(), binary(), map(), map(), keyword()) ::
          {:ok, MobileMutationAuthorization.t()} | {:error, term()}
  @doc false
  def consume(repo, organization_id, authorization_id, proof, expected, opts \\ []) do
    now = opts |> Keyword.get(:now, DateTime.utc_now()) |> normalize_time()

    if repo.in_transaction?() do
      with {:ok, installation_id} <-
             authorization_installation(repo, organization_id, authorization_id),
           :ok <- lock_installation(repo, organization_id, installation_id),
           {:ok, authorization} <-
             locked_authorization(repo, organization_id, authorization_id),
           true <- authorization.installation_id == installation_id,
           :ok <-
             MobileDeviceIdentityRecovery.enforce_signed_posture_barrier(
               organization_id,
               authorization.installation_id,
               now
             ),
           :ok <- available(authorization, now),
           {:ok, body_sha256} <- request_body_sha256(value(expected, :body)),
           :ok <- verify_binding(authorization, expected, body_sha256),
           {:ok, challenge_id} <- required_string(proof, :challenge_id),
           {:ok, nonce} <- required_string(proof, :nonce),
           :ok <- verify_secret_digest(challenge_id, authorization.challenge_digest, "challenge"),
           :ok <- verify_secret_digest(nonce, authorization.nonce_digest, "nonce"),
           {:ok, signature} <- decode_signature(value(proof, :signature)),
           {:ok, key} <- locked_active_key(repo, authorization),
           payload <- canonical_payload(authorization, challenge_id, nonce),
           :ok <- verify_signature(key.public_key_spki, payload, signature),
           {1, _} <-
             repo.update_all(
               from(candidate in MobileMutationAuthorization,
                 where: candidate.id == ^authorization.id and is_nil(candidate.consumed_at)
               ),
               set: [consumed_at: now, updated_at: now]
             ) do
        {:ok, %{authorization | consumed_at: now, updated_at: now}}
      else
        {0, _} -> {:error, :authorization_already_consumed}
        {:error, _reason} = error -> error
        _ -> {:error, :authorization_unavailable}
      end
    else
      {:error, :transaction_required}
    end
  end

  @doc """
  Consumes a proof, executes the mutation callback, and stores its durable
  result in the caller's transaction. Any callback or finalization failure
  rolls the transaction back, leaving the authorization retryable.

  The callback receives the consumed authorization and must return
  `{:ok, outcome, result_resource_id, result}` where outcome is `:created` or
  `:updated`.
  """
  def consume_and_run(
        repo,
        organization_id,
        authorization_id,
        proof,
        expected,
        callback,
        opts \\ []
      )
      when is_function(callback, 1) do
    if repo.in_transaction?() do
      with {:ok, authorization} <-
             consume(repo, organization_id, authorization_id, proof, expected, opts),
           {:ok, outcome, result_resource_id, result} <- callback.(authorization),
           {:ok, finalized} <-
             finalize_result(repo, authorization, outcome, result_resource_id, opts) do
        {:ok, finalized, result}
      else
        {:error, reason} -> repo.rollback(reason)
        _ -> repo.rollback(:invalid_mutation_callback_result)
      end
    else
      {:error, :transaction_required}
    end
  end

  @doc "Stores the mutation result on an already-consumed authorization."
  def finalize_result(repo, authorization, outcome, result_resource_id, opts \\ []) do
    now = opts |> Keyword.get(:now, DateTime.utc_now()) |> normalize_time()
    normalized_outcome = if is_atom(outcome), do: Atom.to_string(outcome), else: outcome

    cond do
      not repo.in_transaction?() ->
        {:error, :transaction_required}

      normalized_outcome not in ~w(created updated) ->
        {:error, :invalid_result_outcome}

      not is_binary(result_resource_id) or result_resource_id == "" ->
        {:error, :invalid_result_resource_id}

      true ->
        query =
          from(candidate in MobileMutationAuthorization,
            where:
              candidate.id == ^authorization.id and not is_nil(candidate.consumed_at) and
                is_nil(candidate.result_outcome)
          )

        case repo.update_all(query,
               set: [
                 result_outcome: normalized_outcome,
                 result_resource_id: result_resource_id,
                 updated_at: now
               ]
             ) do
          {1, _} ->
            {:ok,
             %{
               authorization
               | result_outcome: normalized_outcome,
                 result_resource_id: result_resource_id,
                 updated_at: now
             }}

          {0, _} ->
            {:error, :authorization_result_unavailable}
        end
    end
  end

  @doc "Returns the deterministic SHA-256 digest of a canonical JSON body."
  @spec request_body_sha256(term()) :: {:ok, binary()} | {:error, :invalid_request_body}
  def request_body_sha256(body) do
    with true <- is_map(body),
         false <- Map.has_key?(body, "mutation_authorization"),
         {:ok, encoded, _entries} <- canonical_json(body, 0, 0),
         true <- byte_size(encoded) <= @maximum_body_bytes do
      {:ok, :crypto.hash(:sha256, encoded)}
    else
      _ -> {:error, :invalid_request_body}
    end
  rescue
    _ -> {:error, :invalid_request_body}
  end

  @doc "Reconstructs the exact LF-delimited payload signed by the device key."
  @spec canonical_payload(MobileMutationAuthorization.t(), String.t(), String.t()) :: binary()
  def canonical_payload(authorization, challenge_id, nonce) do
    values = signed_fields(authorization, challenge_id, nonce)

    Enum.map_join(@canonical_fields, "\n", fn field ->
      field <> "=" <> base64url(Map.fetch!(values, field))
    end)
  end

  @doc "Returns the exact 20 values that a client canonicalizes and signs."
  def signed_fields(authorization, challenge_id, nonce) do
    %{
      "protocol" => @protocol,
      "message_type" => @message_type,
      "message_version" => @message_version,
      "organization_id" => authorization.organization_id,
      "actor_id" => authorization.actor_id,
      "installation_id" => authorization.installation_id,
      "platform" => authorization.platform,
      "device_key_id" => authorization.device_key_id,
      "key_scope_id" => authorization.key_scope_id,
      "request_id" => authorization.request_id,
      "challenge_id" => challenge_id,
      "nonce" => nonce,
      "operation" => authorization.operation,
      "http_method" => authorization.http_method,
      "route_id" => authorization.route_id,
      "resource_id" => authorization.resource_id,
      "body_sha256" => base64url(authorization.body_sha256),
      "algorithm" => authorization.algorithm,
      "issued_at" => DateTime.to_iso8601(authorization.issued_at),
      "expires_at" => DateTime.to_iso8601(authorization.expires_at)
    }
  end

  defp persist_issued(repo, key, actor_id, resource_id, body_sha256, now, ttl) do
    request_id = "tmmr_v1_" <> random_token()
    challenge_id = random_token()
    nonce = random_token()
    expires_at = DateTime.add(now, ttl, :second)

    attrs = %{
      organization_id: key.organization_id,
      identity_key_id: key.id,
      actor_id: actor_id,
      installation_id: key.installation_id,
      platform: key.platform,
      device_key_id: key.device_key_id,
      key_scope_id: key.key_scope_id,
      request_id: request_id,
      challenge_digest: secret_digest("challenge", challenge_id),
      nonce_digest: secret_digest("nonce", nonce),
      operation: @operation,
      http_method: @http_method,
      route_id: @route_id,
      resource_id: resource_id,
      body_sha256: body_sha256,
      algorithm: @algorithm,
      issued_at: now,
      expires_at: expires_at
    }

    case %MobileMutationAuthorization{}
         |> MobileMutationAuthorization.changeset(attrs)
         |> repo.insert() do
      {:ok, authorization} ->
        %{
          authorization_id: authorization.id,
          request_id: request_id,
          challenge_id: challenge_id,
          nonce: nonce,
          payload: canonical_payload(authorization, challenge_id, nonce),
          signed_fields: signed_fields(authorization, challenge_id, nonce),
          algorithm: @algorithm,
          expires_at: expires_at
        }

      {:error, changeset} ->
        repo.rollback(changeset)
    end
  end

  defp authorization_installation(repo, organization_id, authorization_id) do
    case Ecto.UUID.cast(authorization_id) do
      {:ok, id} ->
        case repo.one(
               from(authorization in MobileMutationAuthorization,
                 where:
                   authorization.id == ^id and authorization.organization_id == ^organization_id,
                 select: authorization.installation_id
               )
             ) do
          nil -> {:error, :authorization_unavailable}
          installation_id -> {:ok, installation_id}
        end

      :error ->
        {:error, :authorization_unavailable}
    end
  end

  defp locked_authorization(repo, organization_id, authorization_id) do
    case Ecto.UUID.cast(authorization_id) do
      {:ok, id} ->
        case repo.one(
               from(authorization in MobileMutationAuthorization,
                 where:
                   authorization.id == ^id and authorization.organization_id == ^organization_id,
                 lock: "FOR UPDATE"
               )
             ) do
          nil -> {:error, :authorization_unavailable}
          authorization -> {:ok, authorization}
        end

      :error ->
        {:error, :authorization_unavailable}
    end
  end

  defp locked_active_key(repo, authorization) do
    key =
      repo.one(
        from(candidate in MobileDeviceIdentityKey,
          where:
            candidate.id == ^authorization.identity_key_id and
              candidate.organization_id == ^authorization.organization_id,
          lock: "FOR UPDATE"
        )
      )

    if key && key.lifecycle_state == "active" && key.proof_state == "verified" &&
         key.installation_id == authorization.installation_id &&
         key.device_key_id == authorization.device_key_id &&
         key.key_scope_id == authorization.key_scope_id && key.platform == authorization.platform do
      {:ok, key}
    else
      {:error, :identity_key_snapshot_inactive}
    end
  end

  defp available(%{consumed_at: consumed_at}, _now) when not is_nil(consumed_at),
    do: {:error, :authorization_already_consumed}

  defp available(authorization, now) do
    cond do
      DateTime.compare(now, authorization.issued_at) == :lt ->
        {:error, :authorization_not_yet_valid}

      DateTime.compare(now, authorization.expires_at) != :lt ->
        {:error, :authorization_expired}

      true ->
        :ok
    end
  end

  defp verify_binding(authorization, expected, body_sha256) do
    bindings = [
      {authorization.actor_id, value(expected, :actor_id)},
      {authorization.installation_id, value(expected, :installation_id)},
      {authorization.resource_id, value(expected, :resource_id)},
      {authorization.operation, value(expected, :operation) || @operation},
      {authorization.http_method, value(expected, :http_method) || @http_method},
      {authorization.route_id, value(expected, :route_id) || @route_id},
      {authorization.body_sha256, body_sha256}
    ]

    if Enum.all?(bindings, fn {stored, supplied} -> secure_compare(stored, supplied) end),
      do: :ok,
      else: {:error, :authorization_binding_mismatch}
  end

  defp required_string(map, key) do
    case value(map, key) do
      value when is_binary(value) ->
        if canonical_string?(value), do: {:ok, value}, else: {:error, {:invalid_field, key}}

      _ ->
        {:error, {:invalid_field, key}}
    end
  end

  defp canonical_string?(value) do
    byte_size(value) in 1..255 and String.valid?(value) and value == String.trim(value) and
      not String.match?(value, ~r/[\x{0000}-\x{001F}\x{007F}-\x{009F}]/u)
  end

  defp decode_signature(encoded) when is_binary(encoded) do
    with {:ok, signature} <- Base.url_decode64(encoded, padding: false),
         true <- byte_size(signature) >= 8 and byte_size(signature) <= 72,
         true <- Base.url_encode64(signature, padding: false) == encoded do
      {:ok, signature}
    else
      _ -> {:error, :invalid_signature}
    end
  end

  defp decode_signature(_encoded), do: {:error, :invalid_signature}

  defp verify_signature(public_key_spki, payload, signature) do
    public_key =
      :public_key.pem_entry_decode({:SubjectPublicKeyInfo, public_key_spki, :not_encrypted})

    if :public_key.verify(payload, :sha256, signature, public_key),
      do: :ok,
      else: {:error, :invalid_signature}
  rescue
    _ -> {:error, :invalid_public_key}
  catch
    _, _ -> {:error, :invalid_public_key}
  end

  defp verify_secret_digest(cleartext, stored, domain) do
    digest = secret_digest(domain, cleartext)

    if secure_compare(digest, stored),
      do: :ok,
      else: {:error, :authorization_secret_mismatch}
  end

  defp secret_digest(domain, cleartext),
    do: :crypto.hash(:sha256, @protocol <> "\0" <> domain <> "\0" <> cleartext)

  defp canonical_json(_value, depth, _nodes) when depth > @maximum_json_depth,
    do: {:error, :invalid_request_body}

  defp canonical_json(value, depth, entries) when is_map(value) do
    next_entries = entries + map_size(value)

    if next_entries <= @maximum_json_nodes and Enum.all?(Map.keys(value), &valid_json_key?/1) do
      value
      |> Enum.sort_by(fn {key, _value} -> key end)
      |> Enum.reduce_while({:ok, [], next_entries}, fn {key, item}, {:ok, acc, used} ->
        case canonical_json(item, depth + 1, used) do
          {:ok, encoded, next_used} ->
            {:cont, {:ok, [Jason.encode!(key) <> ":" <> encoded | acc], next_used}}

          error ->
            {:halt, error}
        end
      end)
      |> case do
        {:ok, reversed, used} ->
          {:ok, "{" <> Enum.join(Enum.reverse(reversed), ",") <> "}", used}

        error ->
          error
      end
    else
      {:error, :invalid_request_body}
    end
  end

  defp canonical_json(value, depth, entries) when is_list(value) do
    next_entries = entries + length(value)

    if next_entries <= @maximum_json_nodes do
      value
      |> Enum.reduce_while({:ok, [], next_entries}, fn item, {:ok, acc, used} ->
        case canonical_json(item, depth + 1, used) do
          {:ok, encoded, next_used} -> {:cont, {:ok, [encoded | acc], next_used}}
          error -> {:halt, error}
        end
      end)
      |> case do
        {:ok, reversed, used} ->
          {:ok, "[" <> Enum.join(Enum.reverse(reversed), ",") <> "]", used}

        error ->
          error
      end
    else
      {:error, :invalid_request_body}
    end
  end

  defp canonical_json(value, _depth, entries)
       when is_integer(value) and value >= -@maximum_safe_integer and
              value <= @maximum_safe_integer,
       do: {:ok, Jason.encode!(value), entries}

  defp canonical_json(value, _depth, nodes)
       when is_binary(value) or is_boolean(value) or is_nil(value),
       do:
         if(is_binary(value) and not String.valid?(value),
           do: {:error, :invalid_request_body},
           else: {:ok, Jason.encode!(value), nodes}
         )

  defp canonical_json(_value, _depth, _nodes), do: {:error, :invalid_request_body}

  defp valid_json_key?(key) when is_binary(key) do
    String.valid?(key) and key not in ~w(__proto__ constructor prototype) and
      not String.match?(key, ~r/[\x{0000}-\x{001F}\x{007F}-\x{009F}]/u)
  end

  defp valid_json_key?(_key), do: false

  defp validate_ttl(ttl) when is_integer(ttl) and ttl > 0 and ttl <= @maximum_ttl, do: :ok
  defp validate_ttl(_ttl), do: {:error, :invalid_ttl}

  defp unwrap_transaction({:ok, issued}), do: {:ok, issued}
  defp unwrap_transaction({:error, reason}), do: {:error, reason}

  defp normalize_time(%DateTime{} = time), do: DateTime.truncate(time, :microsecond)

  # Must remain byte-for-byte compatible with MobileDeviceIdentity and its
  # recovery protocol so bind/rotate/revoke/recovery and mutation authorization
  # serialize for the same tenant installation.
  defp lock_installation(repo, organization_id, installation_id) do
    digest =
      :crypto.hash(
        :sha256,
        @installation_lock_domain <> <<0>> <> organization_id <> <<0>> <> installation_id
      )

    <<key_one::signed-32, key_two::signed-32, _rest::binary>> = digest

    Ecto.Adapters.SQL.query!(
      repo,
      "SELECT pg_advisory_xact_lock($1, $2)",
      [key_one, key_two]
    )

    :ok
  end

  defp random_token, do: 32 |> :crypto.strong_rand_bytes() |> base64url()
  defp base64url(value), do: Base.url_encode64(value, padding: false)

  defp secure_compare(left, right) when is_binary(left) and is_binary(right),
    do: byte_size(left) == byte_size(right) and Plug.Crypto.secure_compare(left, right)

  defp secure_compare(_left, _right), do: false
  defp value(map, key), do: Map.get(map, key) || Map.get(map, Atom.to_string(key))
end
