defmodule TamanduaServer.Mobile.MobileDeviceIdentityRecovery do
  @moduledoc """
  Server-owned, one-shot recovery intents for mobile device identity.

  A recovery token authorizes only inspection of the intent it belongs to. It
  never authorizes key activation, deletion, rotation, or rebind. Rotation
  reconciliation compares the current server-owned active key with the intent's
  old and candidate public identifiers. Rebind intents remain pending until a
  separate, privileged executor is implemented.
  """

  use Ecto.Schema

  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.Mobile.{MobileDeviceIdentityCandidateLock, MobileDeviceIdentityKey}
  alias TamanduaServer.Repo

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @purposes ~w(reconcile_rotation rebind)
  @states ~w(pending consumed denied expired)
  @authorization_states ~w(not_required pending_authorization)
  @resolutions ~w(previous_key_confirmed replacement_key_confirmed active_key_unknown)
  @token_bytes 32
  @token_digest_domain "tamandua.mobile.identity-recovery-token/v1"
  @installation_lock_domain "tamandua.mobile.installation-lock/v1"
  @default_ttl_seconds 300
  @minimum_ttl_seconds 60
  @maximum_ttl_seconds 900
  @key_id_format ~r/^tmdk_v1_[A-Za-z0-9_-]{43}$/

  schema "mobile_device_identity_recovery_intents" do
    field(:installation_id, :string)
    field(:purpose, :string)
    field(:state, :string, default: "pending")
    field(:old_device_key_id, :string)
    field(:candidate_device_key_id, :string)
    field(:reason, :string)
    field(:token_digest, :binary)
    field(:step_up_required, :boolean, default: false)
    field(:authorization_state, :string)
    field(:authorization_provenance, :map, default: %{})
    field(:resolution, :string)
    field(:issued_at, :utc_datetime_usec)
    field(:expires_at, :utc_datetime_usec)
    field(:token_consumed_at, :utc_datetime_usec)
    field(:last_checked_at, :utc_datetime_usec)
    field(:consumed_at, :utc_datetime_usec)
    field(:denied_at, :utc_datetime_usec)
    field(:expired_at, :utc_datetime_usec)

    belongs_to(:organization, Organization)
    belongs_to(:requested_by, User)

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @required_fields ~w(
    organization_id installation_id purpose state old_device_key_id candidate_device_key_id reason
    token_digest step_up_required authorization_state authorization_provenance
    issued_at expires_at
  )a

  @optional_fields ~w(
    requested_by_id resolution token_consumed_at
    last_checked_at consumed_at denied_at expired_at
  )a

  def changeset(intent, attrs) do
    intent
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_length(:installation_id, min: 1, max: 255)
    |> validate_format(:installation_id, ~r/\S/)
    |> validate_length(:reason, min: 1, max: 255)
    |> validate_format(:old_device_key_id, @key_id_format)
    |> validate_optional_key_id(:candidate_device_key_id)
    |> validate_inclusion(:purpose, @purposes)
    |> validate_inclusion(:state, @states)
    |> validate_inclusion(:authorization_state, @authorization_states)
    |> validate_optional_inclusion(:resolution, @resolutions)
    |> validate_binary_size(:token_digest, 32)
    |> validate_expiry_after_issue()
    |> validate_purpose_contract()
    |> unique_constraint([:organization_id, :token_digest])
    |> unique_constraint([:organization_id, :installation_id],
      name: :mobile_recovery_one_pending_installation_index
    )
    |> unique_constraint([:organization_id, :candidate_device_key_id],
      name: :mobile_recovery_one_pending_candidate_index
    )
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:requested_by_id)
  end

  @doc "Issues a tenant/install/purpose-bound intent and returns its token once."
  @spec issue(Ecto.UUID.t(), map(), keyword()) ::
          {:ok, %{intent: t(), recovery_token: String.t()}}
          | {:error, atom() | Ecto.Changeset.t()}
  def issue(organization_id, attrs, opts \\ [])
      when is_binary(organization_id) and is_map(attrs) do
    with {:ok, ttl_seconds} <- ttl_seconds(opts),
         {:ok, purpose} <- normalize_purpose(value(attrs, :purpose)),
         {:ok, installation_id} <- required_string(value(attrs, :installation_id)),
         {:ok, old_device_key_id} <- required_string(value(attrs, :old_device_key_id)),
         {:ok, candidate_device_key_id} <-
           normalize_candidate(value(attrs, :candidate_device_key_id)) do
      now = opts |> Keyword.get(:now, DateTime.utc_now()) |> truncate_datetime()
      token = @token_bytes |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)

      intent_attrs = %{
        organization_id: organization_id,
        requested_by_id: Keyword.get(opts, :requested_by_id),
        installation_id: installation_id,
        purpose: purpose,
        state: "pending",
        old_device_key_id: old_device_key_id,
        candidate_device_key_id: candidate_device_key_id,
        reason: normalize_reason(value(attrs, :reason), purpose),
        token_digest: token_digest(token),
        step_up_required: purpose == "rebind",
        authorization_state:
          if(purpose == "rebind", do: "pending_authorization", else: "not_required"),
        authorization_provenance:
          opts
          |> Keyword.get(:authorization_provenance, %{})
          |> sanitize_provenance(Keyword.get(opts, :requested_by_id)),
        issued_at: now,
        expires_at: DateTime.add(now, ttl_seconds, :second)
      }

      transaction_result(fn ->
        with :ok <- lock_installation(organization_id, installation_id),
             :ok <-
               MobileDeviceIdentityCandidateLock.lock_keys(
                 organization_id,
                 candidate_device_key_id
               ),
             :ok <- ensure_no_live_pending_recovery(organization_id, installation_id, now),
             :ok <- ensure_key_binding(organization_id, installation_id, old_device_key_id),
             :ok <-
               ensure_candidate_binding(
                 organization_id,
                 installation_id,
                 old_device_key_id,
                 candidate_device_key_id
               ),
             {:ok, intent} <- %__MODULE__{} |> changeset(intent_attrs) |> Repo.insert() do
          {:ok, %{intent: intent, recovery_token: token}}
        end
      end)
    end
  end

  def issue(_organization_id, _attrs, _opts), do: {:error, :invalid_request}

  @doc """
  Expires stale recovery leases and enforces the signed-posture barrier.

  The caller must already hold the canonical tenant/installation advisory lock
  and must call this function inside the same transaction as the posture
  decision. This keeps expiry persistence, live-intent detection, and posture
  commit or rollback in one serialization point.
  """
  @spec enforce_signed_posture_barrier(Ecto.UUID.t(), String.t(), DateTime.t()) ::
          :ok
          | {:error, :identity_recovery_in_progress | :invalid_server_time | Ecto.Changeset.t()}
  def enforce_signed_posture_barrier(organization_id, installation_id, %DateTime{} = now)
      when is_binary(organization_id) and is_binary(installation_id) do
    now = truncate_datetime(now)

    intents =
      __MODULE__
      |> where(
        [intent],
        intent.organization_id == ^organization_id and
          intent.installation_id == ^installation_id and intent.state == "pending"
      )
      |> order_by([intent], asc: intent.expires_at, asc: intent.id)
      |> lock("FOR UPDATE")
      |> Repo.all()

    with {:ok, live_pending?} <- expire_stale_pending(intents, now) do
      if live_pending?, do: {:error, :identity_recovery_in_progress}, else: :ok
    end
  end

  def enforce_signed_posture_barrier(_organization_id, _installation_id, _now),
    do: {:error, :invalid_server_time}

  @doc "Returns a tenant-bound intent, persisting expiry when its TTL elapsed."
  @spec status(Ecto.UUID.t(), Ecto.UUID.t(), keyword()) ::
          {:ok, t()} | {:error, :intent_unavailable}
  def status(organization_id, intent_id, opts \\ []) do
    now = opts |> Keyword.get(:now, DateTime.utc_now()) |> truncate_datetime()

    transaction_result(fn ->
      case locked_intent(organization_id, intent_id) do
        nil -> {:error, :intent_unavailable}
        intent -> expire_if_needed(intent, now)
      end
    end)
  end

  @doc "Presents the one-shot token and resolves only server-observable state."
  @spec resolve(Ecto.UUID.t(), Ecto.UUID.t(), String.t(), keyword()) ::
          {:ok, t()} | {:error, atom() | Ecto.Changeset.t()}
  def resolve(organization_id, intent_id, token, opts \\ []) do
    now = opts |> Keyword.get(:now, DateTime.utc_now()) |> truncate_datetime()

    transaction_result(fn ->
      with %{installation_id: installation_id} <- intent_locator(organization_id, intent_id),
           :ok <- lock_installation(organization_id, installation_id),
           %__MODULE__{} = intent <- locked_intent(organization_id, intent_id),
           :ok <- ensure_same_installation(intent, installation_id),
           {:ok, intent} <- expire_if_needed(intent, now),
           :ok <- ensure_resolvable(intent),
           :ok <- verify_token(intent, token) do
        resolve_intent(intent, now)
      else
        nil -> {:error, :intent_unavailable}
        {:error, _reason} = error -> error
      end
    end)
  end

  defp resolve_intent(%__MODULE__{purpose: "rebind"} = intent, now) do
    intent
    |> changeset(%{
      token_consumed_at: now,
      last_checked_at: now,
      authorization_state: "pending_authorization",
      step_up_required: true
    })
    |> Repo.update()
  end

  defp resolve_intent(%__MODULE__{purpose: "reconcile_rotation"} = intent, now) do
    :ok = lock_installation(intent.organization_id, intent.installation_id)

    active_key_id =
      MobileDeviceIdentityKey
      |> MobileDeviceIdentityKey.active_for_installation(
        intent.organization_id,
        intent.installation_id
      )
      |> select([key], key.device_key_id)
      |> Repo.one()

    case active_key_id do
      key_id when key_id == intent.old_device_key_id ->
        consume_reconciliation(intent, "previous_key_confirmed", now)

      key_id when key_id == intent.candidate_device_key_id ->
        consume_reconciliation(intent, "replacement_key_confirmed", now)

      _unknown ->
        intent
        |> changeset(%{
          state: "denied",
          resolution: "active_key_unknown",
          token_consumed_at: now,
          last_checked_at: now,
          denied_at: now
        })
        |> Repo.update()
    end
  end

  defp consume_reconciliation(intent, resolution, now) do
    intent
    |> changeset(%{
      state: "consumed",
      resolution: resolution,
      token_consumed_at: now,
      last_checked_at: now,
      consumed_at: now
    })
    |> Repo.update()
  end

  defp locked_intent(organization_id, intent_id) do
    __MODULE__
    |> where(
      [intent],
      intent.organization_id == ^organization_id and intent.id == ^intent_id
    )
    |> lock("FOR UPDATE")
    |> Repo.one()
  end

  defp intent_locator(organization_id, intent_id) do
    __MODULE__
    |> where(
      [intent],
      intent.organization_id == ^organization_id and intent.id == ^intent_id
    )
    |> select([intent], %{installation_id: intent.installation_id})
    |> Repo.one()
  end

  defp ensure_same_installation(%__MODULE__{installation_id: installation_id}, installation_id),
    do: :ok

  defp ensure_same_installation(_intent, _installation_id), do: {:error, :intent_unavailable}

  # Must remain byte-for-byte compatible with MobileDeviceIdentity's lock
  # domain so reconciliation serializes with bind, rotate, revoke, and legacy
  # downgrade checks for the same tenant installation.
  defp lock_installation(organization_id, installation_id) do
    digest =
      :crypto.hash(
        :sha256,
        @installation_lock_domain <> <<0>> <> organization_id <> <<0>> <> installation_id
      )

    <<key_one::signed-32, key_two::signed-32, _rest::binary>> = digest

    Ecto.Adapters.SQL.query!(
      Repo,
      "SELECT pg_advisory_xact_lock($1, $2)",
      [key_one, key_two]
    )

    :ok
  end

  defp expire_if_needed(%__MODULE__{state: "pending"} = intent, now) do
    if DateTime.compare(now, intent.expires_at) in [:eq, :gt] do
      intent
      |> changeset(%{state: "expired", expired_at: now, last_checked_at: now})
      |> Repo.update()
      |> case do
        {:ok, _expired} -> {:error, :intent_expired}
        {:error, changeset} -> {:error, changeset}
      end
    else
      {:ok, intent}
    end
  end

  defp expire_if_needed(intent, _now), do: {:ok, intent}

  defp expire_stale_pending(intents, now) do
    Enum.reduce_while(intents, {:ok, false}, fn intent, {:ok, live_pending?} ->
      if DateTime.compare(now, intent.expires_at) in [:eq, :gt] do
        intent
        |> changeset(%{state: "expired", expired_at: now, last_checked_at: now})
        |> Repo.update()
        |> case do
          {:ok, _expired} -> {:cont, {:ok, live_pending?}}
          {:error, changeset} -> Repo.rollback(changeset)
        end
      else
        {:cont, {:ok, true}}
      end
    end)
  end

  defp ensure_resolvable(%__MODULE__{state: "pending", token_consumed_at: nil}), do: :ok
  defp ensure_resolvable(%__MODULE__{state: "expired"}), do: {:error, :intent_expired}
  defp ensure_resolvable(_intent), do: {:error, :intent_unavailable}

  defp verify_token(intent, token) when is_binary(token) do
    supplied = token_digest(token)

    if byte_size(supplied) == byte_size(intent.token_digest) and
         Plug.Crypto.secure_compare(supplied, intent.token_digest) do
      :ok
    else
      {:error, :invalid_recovery_token}
    end
  end

  defp verify_token(_intent, _token), do: {:error, :invalid_recovery_token}

  defp token_digest(token), do: :crypto.hash(:sha256, @token_digest_domain <> <<0>> <> token)

  defp ensure_key_binding(organization_id, installation_id, device_key_id) do
    if key_belongs?(organization_id, installation_id, device_key_id) do
      :ok
    else
      {:error, :identity_not_found}
    end
  end

  defp ensure_candidate_binding(_organization_id, _installation_id, old_key_id, old_key_id),
    do: {:error, :candidate_key_must_differ}

  defp ensure_candidate_binding(organization_id, installation_id, _old_key_id, candidate_key_id) do
    case Repo.get_by(MobileDeviceIdentityKey,
           organization_id: organization_id,
           device_key_id: candidate_key_id
         ) do
      nil -> :ok
      %MobileDeviceIdentityKey{installation_id: ^installation_id} -> :ok
      %MobileDeviceIdentityKey{} -> {:error, :candidate_key_binding_invalid}
    end
  end

  defp ensure_no_live_pending_recovery(organization_id, installation_id, now) do
    enforce_signed_posture_barrier(organization_id, installation_id, now)
  end

  defp key_belongs?(organization_id, installation_id, device_key_id) do
    MobileDeviceIdentityKey
    |> where(
      [key],
      key.organization_id == ^organization_id and key.installation_id == ^installation_id and
        key.device_key_id == ^device_key_id
    )
    |> Repo.exists?()
  end

  defp transaction_result(callback) do
    case Repo.transaction(callback) do
      {:ok, {:ok, result}} -> {:ok, result}
      {:ok, {:error, reason}} -> {:error, reason}
      {:error, reason} -> {:error, reason}
    end
  end

  defp ttl_seconds(opts) do
    case Keyword.get(opts, :ttl_seconds, @default_ttl_seconds) do
      ttl when is_integer(ttl) and ttl >= @minimum_ttl_seconds and ttl <= @maximum_ttl_seconds ->
        {:ok, ttl}

      _invalid ->
        {:error, :invalid_ttl}
    end
  end

  defp normalize_purpose(purpose) when purpose in @purposes, do: {:ok, purpose}
  defp normalize_purpose(_purpose), do: {:error, :invalid_purpose}

  defp normalize_candidate(nil), do: {:error, :candidate_key_required}
  defp normalize_candidate(""), do: {:error, :candidate_key_required}
  defp normalize_candidate(value), do: required_string(value)

  defp normalize_reason(nil, purpose), do: purpose
  defp normalize_reason("", purpose), do: purpose
  defp normalize_reason(reason, _purpose) when is_binary(reason), do: String.trim(reason)
  defp normalize_reason(_reason, purpose), do: purpose

  defp required_string(value) when is_binary(value) do
    case String.trim(value) do
      "" -> {:error, :invalid_request}
      normalized -> {:ok, normalized}
    end
  end

  defp required_string(_value), do: {:error, :invalid_request}

  defp sanitize_provenance(provenance, requested_by_id) when is_map(provenance) do
    provenance
    |> Map.take(["authentication_source", "requested_via"])
    |> Map.put("actor_user_id", requested_by_id)
    |> Map.put("step_up_evidence", "not_verified")
  end

  defp sanitize_provenance(_provenance, requested_by_id) do
    %{"actor_user_id" => requested_by_id, "step_up_evidence" => "not_verified"}
  end

  defp validate_purpose_contract(changeset) do
    purpose = get_field(changeset, :purpose)
    old_key_id = get_field(changeset, :old_device_key_id)
    candidate_key_id = get_field(changeset, :candidate_device_key_id)
    step_up_required = get_field(changeset, :step_up_required)
    authorization_state = get_field(changeset, :authorization_state)

    changeset =
      if purpose in @purposes and is_nil(candidate_key_id) do
        add_error(changeset, :candidate_device_key_id, "is required for identity recovery")
      else
        changeset
      end

    changeset =
      if old_key_id && candidate_key_id && old_key_id == candidate_key_id do
        add_error(changeset, :candidate_device_key_id, "must differ from old device key")
      else
        changeset
      end

    expected =
      if purpose == "rebind",
        do: {true, "pending_authorization"},
        else: {false, "not_required"}

    if {step_up_required, authorization_state} == expected do
      changeset
    else
      add_error(changeset, :authorization_state, "does not match server-owned purpose policy")
    end
  end

  defp validate_optional_key_id(changeset, field) do
    validate_change(changeset, field, fn ^field, value ->
      if is_nil(value) or (is_binary(value) and Regex.match?(@key_id_format, value)) do
        []
      else
        [{field, "has invalid device key format"}]
      end
    end)
  end

  defp validate_optional_inclusion(changeset, field, allowed) do
    validate_change(changeset, field, fn ^field, value ->
      if is_nil(value) or value in allowed, do: [], else: [{field, "is invalid"}]
    end)
  end

  defp validate_binary_size(changeset, field, expected_size) do
    validate_change(changeset, field, fn ^field, value ->
      if is_binary(value) and byte_size(value) == expected_size,
        do: [],
        else: [{field, "must be #{expected_size} bytes"}]
    end)
  end

  defp validate_expiry_after_issue(changeset) do
    issued_at = get_field(changeset, :issued_at)
    expires_at = get_field(changeset, :expires_at)

    if issued_at && expires_at && DateTime.compare(expires_at, issued_at) != :gt do
      add_error(changeset, :expires_at, "must be after issued_at")
    else
      changeset
    end
  end

  defp value(attrs, field, default \\ nil) do
    Map.get(attrs, field, Map.get(attrs, Atom.to_string(field), default))
  end

  defp truncate_datetime(%DateTime{} = datetime), do: DateTime.truncate(datetime, :microsecond)
end
