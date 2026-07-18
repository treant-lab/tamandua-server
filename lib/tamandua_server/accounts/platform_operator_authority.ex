defmodule TamanduaServer.Accounts.PlatformOperatorAuthority do
  @moduledoc """
  Disabled-by-default foundation for exact, one-shot platform authority.

  It is intentionally not wired to HTTP, GraphQL, plugs, or UI. Tamandua's
  current ETS user sessions are not accepted. A future integration must supply
  a server-owned persistent session store and keep every decision in one DB
  transaction.
  """

  import Ecto.Query

  require Logger

  alias TamanduaServer.Accounts

  alias TamanduaServer.Accounts.{
    PlatformOperatorAuthorization,
    PlatformOperatorCapabilities,
    PlatformOperatorDBPreflight,
    PlatformOperatorElevationProof,
    PlatformOperatorEvent,
    PlatformOperatorExternalReceipt,
    PlatformOperatorGrant,
    PlatformOperatorSession,
    User
  }

  alias TamanduaServer.Repo

  @max_elevation_ttl_seconds 5 * 60
  @max_external_receipt_ttl_seconds 60 * 60
  @max_external_receipt_token_bytes 128
  @max_worker_identity_bytes 256
  @max_clock_skew_seconds 30
  @advisory_lock_key 8_207_151_604_000

  @type session_reference :: %{
          required(:session_id) => binary(),
          required(:session_binding) => binary(),
          optional(:auth_method) => atom() | binary()
        }

  @doc "Legacy arbitrary provisioning is permanently fail-closed."
  def provision_grant(_attrs, _opts \\ []), do: {:error, :two_person_ceremony_required}

  @doc "Legacy arbitrary revocation is permanently fail-closed."
  def revoke_grant(_grant, _actor_user_id, _reason, _opts \\ []),
    do: {:error, :two_person_ceremony_required}

  @doc """
  Create a grant only after two distinct persistent-session operators approve.

  This offline ceremony is disabled unless `:platform_operator_ceremony_enabled`
  is explicitly true. Neither approver may be the subject.
  """
  def approve_grant(subject_user_id, attrs, requester_ref, approver_ref, opts \\ []) do
    now = Keyword.get(opts, :now, DateTime.utc_now())
    supplied_secret = Keyword.get(opts, :ceremony_secret)

    with :ok <- ceremony_enabled?(),
         :ok <- verify_offline_secret(:bootstrap, supplied_secret),
         :ok <- PlatformOperatorDBPreflight.check(Repo) do
      Repo.transaction(fn ->
        advisory_lock!()
        Repo.query!("LOCK TABLE platform_operator_grants IN SHARE ROW EXCLUSIVE MODE")
        ceremony_operation_id = ceremony_operation_id(:bootstrap, supplied_secret)

        with 0 <- Repo.aggregate(PlatformOperatorGrant, :count, :id),
             {:ok, requester} <- trusted_session(requester_ref, now),
             {:ok, approver} <- trusted_session(approver_ref, now),
             :ok <- distinct_approvers(subject_user_id, requester, approver),
             {:ok, subject} <- active_user_for_update(subject_user_id),
             grant_attrs <-
               attrs
               |> atomize_grant_attrs()
               |> Map.merge(%{user_id: subject.id, granted_by_user_id: approver.user_id}),
             {:ok, grant} <-
               %PlatformOperatorGrant{}
               |> PlatformOperatorGrant.create_changeset(grant_attrs, now)
               |> Repo.insert(),
             {:ok, _} <-
               insert_event(%{
                 event_type: "grant_created",
                 actor_user_id: approver.user_id,
                 subject_user_id: subject.id,
                 grant_id: grant.id,
                 operation_id: ceremony_operation_id,
                 outcome: "success",
                 reason: sanitize_reason(grant.reason),
                 metadata: %{requester_user_id: requester.user_id},
                 occurred_at: now
               }) do
          grant
        else
          count when is_integer(count) and count > 0 ->
            Repo.rollback(:bootstrap_already_completed)

          {:error, reason} ->
            Repo.rollback(reason)
        end
      end)
    end
  end

  @doc "Revoke a grant and every outstanding proof under a two-person ceremony."
  def approve_revoke(grant_id, reason, requester_ref, approver_ref, opts \\ []) do
    now = Keyword.get(opts, :now, DateTime.utc_now())
    supplied_secret = Keyword.get(opts, :ceremony_secret)

    with :ok <- ceremony_enabled?(),
         :ok <- verify_offline_secret(:revoke, supplied_secret),
         :ok <- PlatformOperatorDBPreflight.check(Repo) do
      Repo.transaction(fn ->
        advisory_lock!()

        ceremony_operation_id = ceremony_operation_id(:revoke, supplied_secret)

        with {:ok, requester} <- trusted_session(requester_ref, now),
             {:ok, approver} <- trusted_session(approver_ref, now),
             :ok <- distinct_approvers(nil, requester, approver),
             %PlatformOperatorGrant{} = grant <- grant_for_update(grant_id),
             true <- is_nil(grant.revoked_at),
             :ok <- ensure_not_subject(grant.user_id, requester, approver),
             :ok <- ensure_ceremony_unused(ceremony_operation_id),
             {:ok, revoked} <-
               grant
               |> PlatformOperatorGrant.revoke_changeset(
                 %{revoked_by_user_id: approver.user_id, revoke_reason: sanitize_reason(reason)},
                 now
               )
               |> Repo.update(),
             {_count, _} <-
               from(proof in PlatformOperatorElevationProof,
                 where:
                   proof.grant_id == ^grant.id and is_nil(proof.consumed_at) and
                     is_nil(proof.revoked_at)
               )
               |> Repo.update_all(set: [revoked_at: now]),
             {:ok, _} <-
               insert_event(%{
                 event_type: "grant_revoked",
                 actor_user_id: approver.user_id,
                 subject_user_id: revoked.user_id,
                 grant_id: revoked.id,
                 operation_id: ceremony_operation_id,
                 outcome: "success",
                 reason: sanitize_reason(reason),
                 metadata: %{requester_user_id: requester.user_id},
                 occurred_at: now
               }) do
          revoked
        else
          false -> Repo.rollback(:grant_already_revoked)
          nil -> Repo.rollback(:grant_not_found)
          {:error, reason} -> Repo.rollback(reason)
        end
      end)
    end
  end

  @doc "Issue a short one-shot proof bound to a persistent server session."
  def issue_elevation(session_ref, capability, mfa_code, opts \\ []) do
    now = Keyword.get(opts, :now, DateTime.utc_now())
    ttl = Keyword.get(opts, :ttl_seconds, @max_elevation_ttl_seconds)

    with :ok <- PlatformOperatorDBPreflight.check(Repo) do
    Repo.transaction(fn ->
      with {:ok, capability} <- PlatformOperatorCapabilities.normalize(capability),
           :ok <- validate_ttl(ttl),
           {:ok, session} <- trusted_session(session_ref, now),
           {:ok, user} <- active_user_for_update(session.user_id),
           :ok <- validate_elevation_user(user),
           {:ok, verified_mfa_counter} <-
             Accounts.verify_totp_with_counter(user.mfa_secret, mfa_code,
               unix_time: DateTime.to_unix(now)
             ),
           %PlatformOperatorGrant{} = grant <- active_grant_for_update(user.id, capability, now) do
        raw_proof = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
        expires_at = DateTime.add(now, ttl, :second)

        timestep_hash =
          mfa_timestep_hash(
            user.id,
            session.binding_hash,
            capability,
            verified_mfa_counter
          )

        from(proof in PlatformOperatorElevationProof,
          where:
            proof.user_id == ^user.id and proof.session_binding_hash == ^session.binding_hash and
              proof.audience == ^capability and is_nil(proof.consumed_at) and
              is_nil(proof.revoked_at)
        )
        |> Repo.update_all(set: [revoked_at: now])

        attrs = %{
          user_id: user.id,
          grant_id: grant.id,
          proof_hash: digest(raw_proof),
          session_binding_hash: session.binding_hash,
          mfa_timestep_hash: timestep_hash,
          audience: capability,
          purpose: PlatformOperatorElevationProof.purpose(),
          issued_at: now,
          expires_at: expires_at
        }

        with {:ok, proof} <-
               %PlatformOperatorElevationProof{}
               |> PlatformOperatorElevationProof.changeset(attrs)
               |> Repo.insert(),
             {:ok, _} <-
               insert_event(%{
                 event_type: "elevation_issued",
                 actor_user_id: user.id,
                 subject_user_id: user.id,
                 grant_id: grant.id,
                 elevation_proof_id: proof.id,
                 capability: capability,
                 outcome: "success",
                 reason: "mfa_verified",
                 occurred_at: now
               }) do
          %{proof: raw_proof, elevation_proof_id: proof.id, expires_at: expires_at}
        else
          {:error, reason} -> Repo.rollback(reason)
        end
      else
        {:error, :invalid_totp} -> Repo.rollback(:mfa_verification_failed)
        {:error, :rate_limited} -> Repo.rollback(:mfa_rate_limited)
        nil -> Repo.rollback(:active_grant_missing)
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
    end
  end

  @doc "Arbitrary callbacks are permanently unavailable at the authority boundary."
  def authorize_and_execute(_actor, _capability, _operation, _callback, _opts \\ []),
    do: {:error, :declarative_authority_operation_required}

  @doc "Consume a proof and record an external-operation intent; execution happens later."
  def authorize_external_intent(actor, capability, operation, opts \\ []) do
    now = Keyword.get(opts, :now, DateTime.utc_now())
    receipt_ttl = Keyword.get(opts, :receipt_ttl_seconds, @max_external_receipt_ttl_seconds)
    worker_identity = actor_value(operation, :worker_identity)

    with :ok <- PlatformOperatorDBPreflight.check(Repo),
         {:ok, operation} <- validate_operation(operation),
         :ok <- validate_worker_identity(worker_identity),
         :ok <- validate_receipt_ttl(receipt_ttl) do
      raw_receipt = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

      result =
        Repo.transaction(fn ->
          with {:ok, normalized} <- PlatformOperatorCapabilities.normalize(capability),
               {:ok, session} <- trusted_session(actor, now),
               {:ok, user} <- active_user_for_update(session.user_id),
               %PlatformOperatorGrant{} = grant <-
                 active_grant_for_update(user.id, normalized, now),
               %PlatformOperatorElevationProof{} = proof <-
                 proof_for_update(actor_value(actor, :elevation_proof)),
               resolved_actor <- resolved_actor(actor, user, session),
               {:ok, decision} <-
                 PlatformOperatorAuthorization.evaluate(
                   resolved_actor,
                   normalized,
                   grant,
                   proof,
                   now
                 ),
               :ok <- lock_new_operation(operation.id),
               :ok <- consume_once(proof, operation.id, now),
               {:ok, intent} <- insert_event(intent_event(decision, operation, now)),
               {:ok, _receipt} <-
                 insert_external_receipt(
                   intent,
                   operation.id,
                   raw_receipt,
                   worker_identity,
                   now,
                   receipt_ttl
                 ),
               {:ok, _} <-
                 insert_event(allowed_event(user.id, normalized, decision, operation, now)) do
            %{
              intent_recorded: true,
              operation_id: operation.id,
              receipt_token: raw_receipt,
              receipt_expires_at: DateTime.add(now, receipt_ttl, :second)
            }
          else
            nil -> Repo.rollback(:authority_material_missing)
            {:error, reason} -> Repo.rollback(reason)
          end
        end)

      case result do
        {:ok, value} -> {:ok, value}
        {:error, reason} -> deny_observably(actor, capability, operation, reason, now)
      end
    end
  end

  @doc "Record an idempotent terminal outcome for a previously audited external intent."
  def record_external_outcome(
        operation_id,
        receipt_token,
        worker_identity,
        outcome,
        reason,
        opts \\ []
      )

  def record_external_outcome(operation_id, receipt_token, worker_identity, outcome, reason, opts)
      when is_binary(operation_id) and byte_size(operation_id) in 8..128 and
             is_binary(receipt_token) and
             byte_size(receipt_token) in 32..@max_external_receipt_token_bytes and
             is_binary(worker_identity) and
             byte_size(worker_identity) in 16..@max_worker_identity_bytes and
             outcome in [:succeeded, :failed] do
    now = Keyword.get(opts, :now, DateTime.utc_now())

    with :ok <- PlatformOperatorDBPreflight.check(Repo) do
    Repo.transaction(fn ->
      Repo.query!("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [operation_id])

      receipt =
        from(receipt in PlatformOperatorExternalReceipt,
          where: receipt.operation_id == ^operation_id,
          lock: "FOR UPDATE"
        )
        |> Repo.one()

      intent =
        from(event in PlatformOperatorEvent,
          where:
            event.operation_id == ^operation_id and
              event.event_type == "authorization_intent",
          lock: "FOR UPDATE"
        )
        |> Repo.one()

      terminal_type =
        if outcome == :succeeded, do: "operation_succeeded", else: "operation_failed"

      existing =
        from(event in PlatformOperatorEvent,
          where:
            event.operation_id == ^operation_id and
              event.event_type in ["operation_succeeded", "operation_failed"],
          order_by: [asc: event.occurred_at],
          limit: 1
        )
        |> Repo.one()

      cond do
        is_nil(receipt) ->
          Repo.rollback(:invalid_external_receipt)

        not secure_equal?(receipt.token_hash, digest(receipt_token)) or
            not secure_equal?(receipt.worker_identity_hash, digest(worker_identity)) ->
          Repo.rollback(:invalid_external_receipt)

        is_nil(intent) ->
          Repo.rollback(:external_intent_not_found)

        not is_nil(existing) and existing.event_type == terminal_type and
            receipt.terminal_outcome == Atom.to_string(outcome) ->
          %{operation_id: operation_id, outcome: outcome, idempotent_replay: true}

        not is_nil(existing) or not is_nil(receipt.terminal_at) ->
          Repo.rollback(:external_outcome_conflict)

        DateTime.compare(receipt.expires_at, now) != :gt ->
          Repo.rollback(:external_receipt_expired)

        true ->
          with {:ok, _event} <-
                 insert_event(%{
                   event_type: terminal_type,
                   actor_user_id: intent.actor_user_id,
                   subject_user_id: intent.subject_user_id,
                   grant_id: intent.grant_id,
                   elevation_proof_id: intent.elevation_proof_id,
                   capability: intent.capability,
                   operation_id: operation_id,
                   request_id: intent.request_id,
                   target: intent.target,
                   outcome: if(outcome == :succeeded, do: "success", else: "failed"),
                   reason: sanitize_reason(reason),
                   occurred_at: now
                 }),
               {:ok, _receipt} <-
                 receipt
                 |> PlatformOperatorExternalReceipt.terminal_changeset(outcome, now)
                 |> Repo.update() do
            %{operation_id: operation_id, outcome: outcome, idempotent_replay: false}
          else
            {:error, error} -> Repo.rollback(error)
          end
      end
    end)
    end
  end

  def record_external_outcome(
        _operation_id,
        _receipt_token,
        _worker_identity,
        _outcome,
        _reason,
        _opts
      ),
      do: {:error, :invalid_external_outcome}

  defp trusted_session(ref, now) when is_map(ref) do
    if ref[:auth_method] in [:api_key, "api_key", :bearer, "bearer"] do
      {:error, :api_keys_forbidden}
    else
      session_id = ref[:session_id] || ref["session_id"]
      binding = ref[:session_binding] || ref["session_binding"]

      with true <- is_binary(session_id) and byte_size(session_id) >= 16,
           true <- is_binary(binding) and byte_size(binding) >= 32,
           {:ok, %PlatformOperatorSession{} = session} <-
             fetch_trusted_session(session_id, binding),
           :ok <- valid_session(session, binding, now) do
        {:ok, session}
      else
        false -> {:error, :persistent_session_required}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp trusted_session(_ref, _now), do: {:error, :persistent_session_required}

  defp valid_session(session, binding, now) do
    cond do
      session.auth_method != :session ->
        {:error, :session_auth_required}

      not is_nil(session.revoked_at) ->
        {:error, :session_revoked}

      not match?(%DateTime{}, session.authenticated_at) or
          not match?(%DateTime{}, session.expires_at) ->
        {:error, :invalid_persistent_session}

      DateTime.compare(
        session.authenticated_at,
        DateTime.add(now, @max_clock_skew_seconds, :second)
      ) ==
          :gt ->
        {:error, :session_issued_in_future}

      DateTime.compare(session.expires_at, now) != :gt ->
        {:error, :session_expired}

      not secure_equal?(session.binding_hash, digest(binding)) ->
        {:error, :session_binding_mismatch}

      true ->
        :ok
    end
  end

  defp session_store do
    Application.get_env(
      :tamandua_server,
      :platform_operator_session_store,
      PlatformOperatorSession.UnavailableStore
    )
  end

  defp fetch_trusted_session(session_id, binding) do
    store = session_store()
    store.fetch_for_update(Repo, session_id, binding)
  end

  defp active_user_for_update(user_id) when is_binary(user_id) do
    case from(user in User, where: user.id == ^user_id, lock: "FOR UPDATE") |> Repo.one() do
      %User{is_active: true} = user -> {:ok, user}
      %User{} -> {:error, :inactive_user}
      nil -> {:error, :user_not_found}
    end
  end

  defp active_user_for_update(_), do: {:error, :user_not_found}

  defp active_grant_for_update(user_id, capability, now) do
    from(grant in PlatformOperatorGrant,
      where:
        grant.user_id == ^user_id and is_nil(grant.revoked_at) and grant.expires_at > ^now and
          fragment("? = ANY(?)", ^capability, grant.capabilities),
      order_by: [desc: grant.expires_at],
      limit: 1,
      lock: "FOR UPDATE"
    )
    |> Repo.one()
  end

  defp grant_for_update(id),
    do:
      from(grant in PlatformOperatorGrant, where: grant.id == ^id, lock: "FOR UPDATE")
      |> Repo.one()

  defp proof_for_update(raw) when is_binary(raw) and byte_size(raw) >= 32 do
    from(proof in PlatformOperatorElevationProof,
      where: proof.proof_hash == ^digest(raw),
      lock: "FOR UPDATE"
    )
    |> Repo.one()
  end

  defp proof_for_update(_), do: nil

  defp consume_once(proof, operation_id, now) do
    {count, _} =
      from(item in PlatformOperatorElevationProof,
        where: item.id == ^proof.id and is_nil(item.consumed_at) and is_nil(item.revoked_at)
      )
      |> Repo.update_all(set: [consumed_at: now, consumed_operation_id: operation_id])

    if count == 1, do: :ok, else: {:error, :elevation_already_consumed}
  end

  defp lock_new_operation(operation_id) do
    Repo.query!("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [operation_id])

    consumed? =
      from(item in PlatformOperatorElevationProof,
        where: item.consumed_operation_id == ^operation_id,
        select: 1,
        limit: 1
      )
      |> Repo.one()

    if consumed?, do: {:error, :operation_already_consumed}, else: :ok
  end

  defp resolved_actor(actor, user, session) do
    %{
      user: user,
      session: session,
      session_binding: actor_value(actor, :session_binding),
      elevation_proof: actor_value(actor, :elevation_proof)
    }
  end

  defp intent_event(decision, operation, now) do
    %{
      event_type: "authorization_intent",
      actor_user_id: decision.user_id,
      subject_user_id: decision.user_id,
      grant_id: decision.grant_id,
      elevation_proof_id: decision.elevation_proof_id,
      capability: decision.capability,
      operation_id: operation.id,
      request_id: operation.request_id,
      target: operation.target,
      outcome: "pending",
      reason: "external_operation_intent",
      occurred_at: now
    }
  end

  defp insert_external_receipt(
         intent,
         operation_id,
         raw_receipt,
         worker_identity,
         now,
         receipt_ttl
       ) do
    %PlatformOperatorExternalReceipt{}
    |> PlatformOperatorExternalReceipt.changeset(%{
      operation_id: operation_id,
      token_hash: digest(raw_receipt),
      worker_identity_hash: digest(worker_identity),
      intent_event_id: intent.id,
      issued_at: now,
      expires_at: DateTime.add(now, receipt_ttl, :second)
    })
    |> Repo.insert()
  end

  defp allowed_event(user_id, capability, decision, operation, now) do
    %{
      event_type: "authorization_allowed",
      actor_user_id: user_id,
      subject_user_id: user_id,
      grant_id: decision.grant_id,
      elevation_proof_id: decision.elevation_proof_id,
      capability: capability,
      operation_id: operation.id,
      request_id: operation.request_id,
      target: operation.target,
      outcome: "pending",
      reason: "external_execution_authorized_pending_outcome",
      occurred_at: now
    }
  end

  defp deny_observably(actor, capability, operation, reason, now) do
    actor_user_id = trusted_actor_user_id(actor, now)

    attrs = %{
      event_type: "authorization_denied",
      actor_user_id: actor_user_id,
      subject_user_id: actor_user_id,
      capability: normalized_capability(capability),
      operation_id: operation.id,
      request_id: operation.request_id,
      target: operation.target,
      outcome: "denied",
      reason: reason_code(reason),
      occurred_at: now
    }

    case insert_event(attrs) do
      {:ok, _} ->
        {:error, reason}

      {:error, audit_error} ->
        :telemetry.execute(
          [:tamandua, :platform_operator, :denied_audit_failed],
          %{count: 1},
          %{reason: reason_code(reason), operation_id: operation.id}
        )

        Logger.error("platform operator denied-audit persistence failed",
          operation_id: operation.id,
          error: inspect(audit_error)
        )

        {:error, {:authorization_denied, reason, :audit_failed}}
    end
  end

  defp insert_event(attrs) do
    %PlatformOperatorEvent{}
    |> PlatformOperatorEvent.changeset(attrs)
    |> Repo.insert()
  end

  defp validate_operation(operation) when is_map(operation) do
    id = operation[:id] || operation["id"]
    request_id = operation[:request_id] || operation["request_id"]
    target = sanitize_target(operation[:target] || operation["target"])

    if is_binary(id) and byte_size(id) in 8..128 and
         (is_nil(request_id) or (is_binary(request_id) and byte_size(request_id) <= 128)) and
         is_binary(target) and byte_size(target) in 1..256 do
      {:ok, %{id: id, request_id: request_id, target: target}}
    else
      {:error, :invalid_operation_contract}
    end
  end

  defp validate_operation(_), do: {:error, :invalid_operation_contract}

  defp distinct_approvers(subject_id, requester, approver) do
    ids = [requester.user_id, approver.user_id]

    cond do
      requester.user_id == approver.user_id -> {:error, :two_person_approval_required}
      not is_nil(subject_id) and subject_id in ids -> {:error, :self_grant_forbidden}
      true -> :ok
    end
  end

  defp ceremony_enabled? do
    if Application.get_env(:tamandua_server, :platform_operator_ceremony_enabled, false),
      do: :ok,
      else: {:error, :platform_operator_ceremony_disabled}
  end

  defp verify_offline_secret(purpose, supplied_secret)
       when is_binary(supplied_secret) and byte_size(supplied_secret) >= 32 do
    config_key =
      case purpose do
        :bootstrap -> :platform_operator_bootstrap_secret_hash
        :revoke -> :platform_operator_revoke_secret_hash
      end

    with encoded when is_binary(encoded) <- Application.get_env(:tamandua_server, config_key),
         {:ok, expected_hash} <- Base.decode16(encoded, case: :mixed),
         true <- byte_size(expected_hash) == 32,
         true <- secure_equal?(expected_hash, digest(supplied_secret)) do
      :ok
    else
      _ -> {:error, :offline_ceremony_secret_required}
    end
  end

  defp verify_offline_secret(_purpose, _supplied_secret),
    do: {:error, :offline_ceremony_secret_required}

  defp ceremony_operation_id(purpose, secret) do
    suffix = secret |> digest() |> Base.encode16(case: :lower) |> String.slice(0, 32)
    "offline-#{purpose}-#{suffix}"
  end

  defp ceremony_consumed?(operation_id) do
    from(event in PlatformOperatorEvent,
      where: event.operation_id == ^operation_id,
      select: 1,
      limit: 1
    )
    |> Repo.one()
    |> is_integer()
  end

  defp ensure_ceremony_unused(operation_id) do
    if ceremony_consumed?(operation_id),
      do: {:error, :offline_ceremony_secret_consumed},
      else: :ok
  end

  defp ensure_not_subject(subject_id, requester, approver) do
    if subject_id in [requester.user_id, approver.user_id],
      do: {:error, :self_revoke_forbidden},
      else: :ok
  end

  defp advisory_lock!, do: Repo.query!("SELECT pg_advisory_xact_lock($1)", [@advisory_lock_key])

  defp validate_elevation_user(%User{mfa_enabled: true, mfa_secret: secret})
       when is_binary(secret),
       do: :ok

  defp validate_elevation_user(_), do: {:error, :mfa_required}

  defp validate_ttl(ttl) when is_integer(ttl) and ttl > 0 and ttl <= @max_elevation_ttl_seconds,
    do: :ok

  defp validate_ttl(_), do: {:error, :invalid_elevation_ttl}

  defp validate_receipt_ttl(ttl)
       when is_integer(ttl) and ttl > 0 and ttl <= @max_external_receipt_ttl_seconds,
       do: :ok

  defp validate_receipt_ttl(_), do: {:error, :invalid_external_receipt_ttl}

  defp validate_worker_identity(identity)
       when is_binary(identity) and byte_size(identity) in 16..@max_worker_identity_bytes,
       do: :ok

  defp validate_worker_identity(_), do: {:error, :trusted_worker_identity_required}

  defp atomize_grant_attrs(attrs) when is_map(attrs) do
    %{
      capabilities: attrs[:capabilities] || attrs["capabilities"],
      reason: sanitize_reason(attrs[:reason] || attrs["reason"]),
      expires_at: attrs[:expires_at] || attrs["expires_at"]
    }
  end

  defp sanitize_reason(value) when is_binary(value),
    do: value |> String.replace(~r/[\x00-\x1F\x7F]/u, " ") |> String.slice(0, 1_000)

  defp sanitize_reason(_), do: "invalid_reason"

  defp sanitize_target(value) when is_binary(value),
    do: value |> String.replace(~r/[\x00-\x1F\x7F]/u, "_") |> String.slice(0, 256)

  defp sanitize_target(_), do: ""

  defp normalized_capability(capability) do
    case PlatformOperatorCapabilities.normalize(capability) do
      {:ok, value} -> value
      _ -> nil
    end
  end

  defp trusted_actor_user_id(actor, now) do
    case Repo.transaction(fn -> trusted_session(actor, now) end) do
      {:ok, {:ok, %PlatformOperatorSession{user_id: user_id}}} -> user_id
      _ -> nil
    end
  end

  defp actor_value(actor, key) when is_map(actor),
    do: Map.get(actor, key) || Map.get(actor, Atom.to_string(key))

  defp actor_value(_actor, _key), do: nil

  defp mfa_timestep_hash(user_id, session_binding_hash, capability, verified_counter),
    do:
      digest(
        :erlang.term_to_binary({user_id, session_binding_hash, capability, verified_counter})
      )

  defp reason_code(reason) when is_atom(reason), do: Atom.to_string(reason)
  defp reason_code(reason) when is_binary(reason), do: sanitize_reason(reason)
  defp reason_code(_), do: "authorization_failed"

  defp digest(value), do: :crypto.hash(:sha256, value)

  defp secure_equal?(left, right)
       when is_binary(left) and is_binary(right) and byte_size(left) == byte_size(right),
       do: Plug.Crypto.secure_compare(left, right)

  defp secure_equal?(_left, _right), do: false
end
