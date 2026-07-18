defmodule TamanduaServer.Enrollment.CSRIntent do
  @moduledoc """
  Persistence contract for a fenced, issue-once CSR enrollment intent.

  This schema does not reserve tokens, contact a signer, or issue credentials.
  Those operations remain unavailable until later Phase 2 slices are approved.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @states ~w(reserved signing committed failed reconciliation_required)
  @terminal_states ~w(committed failed)

  schema "enrollment_csr_intents" do
    field(:organization_id, :binary_id)
    field(:installation_token_id, :binary_id)
    field(:state, :string)

    field(:fingerprint_key_version, :integer)
    field(:idempotency_key_hash, :binary)
    field(:request_fingerprint, :binary)
    field(:csr_der, :binary)
    field(:csr_sha256, :binary)
    field(:public_key_spki_der, :binary)
    field(:public_key_sha256, :binary)
    field(:agent_info_canonical, :binary)

    field(:reserved_agent_id, :binary_id)
    field(:signer_request_id, :binary_id)
    field(:committed_agent_id, :binary_id)
    field(:capacity_slot, :integer)
    field(:fencing_token, :integer)
    field(:lease_owner_hash, :binary)
    field(:lease_expires_at, :utc_datetime_usec)
    field(:attempt_count, :integer, default: 0)

    field(:signer_receipt_hash, :binary)
    field(:certificate_sha256, :binary)
    field(:certificate_response, :binary)
    field(:recovery_code, :string)
    field(:last_error_code, :string)

    field(:reserved_at, :utc_datetime_usec)
    field(:signing_started_at, :utc_datetime_usec)
    field(:committed_at, :utc_datetime_usec)
    field(:failed_at, :utc_datetime_usec)
    field(:reconciliation_required_at, :utc_datetime_usec)
    field(:redacted_at, :utc_datetime_usec)
    field(:expires_at, :utc_datetime_usec)

    timestamps(type: :utc_datetime_usec)
  end

  def states, do: @states
  def terminal?(%__MODULE__{state: state}), do: state in @terminal_states

  def reservation_changeset(intent \\ %__MODULE__{}, attrs)

  def reservation_changeset(%__MODULE__{state: nil} = intent, attrs) do
    intent
    |> cast(attrs, [
      :organization_id,
      :installation_token_id,
      :fingerprint_key_version,
      :idempotency_key_hash,
      :request_fingerprint,
      :csr_der,
      :csr_sha256,
      :public_key_spki_der,
      :public_key_sha256,
      :agent_info_canonical,
      :reserved_agent_id,
      :capacity_slot,
      :fencing_token,
      :reserved_at,
      :expires_at
    ])
    |> put_change(:state, "reserved")
    |> put_change(:attempt_count, 0)
    |> validate_required([
      :organization_id,
      :installation_token_id,
      :fingerprint_key_version,
      :idempotency_key_hash,
      :request_fingerprint,
      :csr_der,
      :csr_sha256,
      :public_key_spki_der,
      :public_key_sha256,
      :agent_info_canonical,
      :reserved_agent_id,
      :capacity_slot,
      :fencing_token,
      :reserved_at,
      :expires_at
    ])
    |> validate_number(:fingerprint_key_version, greater_than: 0, less_than_or_equal_to: 32_767)
    |> validate_number(:capacity_slot, greater_than_or_equal_to: 0)
    |> validate_number(:fencing_token, greater_than: 0)
    |> validate_datetime_order(:reserved_at, :expires_at, false)
    |> validate_hashes()
    |> validate_payloads()
    |> unique_constraint(:idempotency_key_hash,
      name: :enrollment_csr_intents_org_idempotency_uidx
    )
    |> foreign_key_constraint(:installation_token_id,
      name: :enrollment_csr_intents_installation_token_tenant_fkey
    )
  end

  def reservation_changeset(%__MODULE__{} = intent, _attrs),
    do: invalid_transition(intent, "reserved")

  def transition_changeset(%__MODULE__{} = intent, next_state, attrs) do
    case {intent.state, next_state} do
      {"reserved", "signing"} ->
        signing_changeset(intent, attrs)

      {state, "committed"} when state in ["signing", "reconciliation_required"] ->
        committed_changeset(intent, attrs)

      {"signing", "reconciliation_required"} ->
        reconciliation_changeset(intent, attrs)

      {state, "failed"} when state in ["reserved", "signing"] ->
        failed_changeset(intent, attrs)

      _ ->
        invalid_transition(intent, next_state)
    end
  end

  def redact_changeset(%__MODULE__{redacted_at: nil} = intent, %DateTime{} = redacted_at) do
    if terminal?(intent) do
      terminal_at = if intent.state == "committed", do: :committed_at, else: :failed_at

      intent
      |> change(
        csr_der: <<0>>,
        public_key_spki_der: <<0>>,
        agent_info_canonical: "{}",
        certificate_response: if(intent.state == "committed", do: <<0>>, else: nil),
        redacted_at: redacted_at
      )
      |> validate_datetime_order(terminal_at, :redacted_at, true)
    else
      invalid_transition(intent, "redacted")
    end
  end

  def redact_changeset(%__MODULE__{} = intent, _redacted_at),
    do: invalid_transition(intent, "redacted")

  defp signing_changeset(intent, attrs) do
    intent
    |> cast(attrs, [
      :signer_request_id,
      :lease_owner_hash,
      :lease_expires_at,
      :attempt_count,
      :fencing_token,
      :signing_started_at
    ])
    |> put_change(:state, "signing")
    |> validate_required([
      :signer_request_id,
      :lease_owner_hash,
      :lease_expires_at,
      :attempt_count,
      :fencing_token,
      :signing_started_at
    ])
    |> validate_number(:attempt_count, greater_than: 0, less_than_or_equal_to: 10)
    |> validate_number(:fencing_token, greater_than: intent.fencing_token)
    |> validate_exact_bytes(:lease_owner_hash, 32)
    |> validate_datetime_order(:reserved_at, :signing_started_at, true)
    |> validate_datetime_order(:signing_started_at, :lease_expires_at, false)
    |> validate_datetime_order(:lease_expires_at, :expires_at, true)
    |> unique_constraint(:signer_request_id,
      name: :enrollment_csr_intents_signer_request_uidx
    )
  end

  defp committed_changeset(intent, attrs) do
    intent
    |> cast(attrs, [
      :committed_agent_id,
      :signer_receipt_hash,
      :certificate_sha256,
      :certificate_response,
      :committed_at,
      :fencing_token
    ])
    |> put_change(:state, "committed")
    |> put_change(:lease_owner_hash, nil)
    |> put_change(:lease_expires_at, nil)
    |> put_change(:recovery_code, nil)
    |> put_change(:reconciliation_required_at, nil)
    |> validate_required([
      :committed_agent_id,
      :signer_receipt_hash,
      :certificate_sha256,
      :certificate_response,
      :committed_at,
      :fencing_token
    ])
    |> validate_inclusion(:committed_agent_id, [intent.reserved_agent_id])
    |> validate_commit_fence(intent)
    |> validate_exact_bytes(:signer_receipt_hash, 32)
    |> validate_exact_bytes(:certificate_sha256, 32)
    |> validate_length(:certificate_response, min: 1, max: 131_072, count: :bytes)
    |> validate_datetime_order(:signing_started_at, :committed_at, true)
  end

  defp reconciliation_changeset(intent, attrs) do
    intent
    |> cast(attrs, [:recovery_code, :reconciliation_required_at, :fencing_token])
    |> put_change(:state, "reconciliation_required")
    |> put_change(:lease_owner_hash, nil)
    |> put_change(:lease_expires_at, nil)
    |> validate_required([:recovery_code, :reconciliation_required_at, :fencing_token])
    |> validate_length(:recovery_code, min: 1, max: 64)
    |> validate_number(:fencing_token, greater_than_or_equal_to: intent.fencing_token)
    |> validate_datetime_order(:signing_started_at, :reconciliation_required_at, true)
  end

  defp failed_changeset(intent, attrs) do
    intent
    |> cast(attrs, [:last_error_code, :failed_at, :fencing_token])
    |> put_change(:state, "failed")
    |> put_change(:lease_owner_hash, nil)
    |> put_change(:lease_expires_at, nil)
    |> validate_required([:last_error_code, :failed_at, :fencing_token])
    |> validate_length(:last_error_code, min: 1, max: 64)
    |> validate_number(:fencing_token, greater_than_or_equal_to: intent.fencing_token)
    |> validate_datetime_order(:reserved_at, :failed_at, true)
    |> validate_datetime_order(:signing_started_at, :failed_at, true)
  end

  defp validate_commit_fence(changeset, %{state: "reconciliation_required"} = intent),
    do: validate_number(changeset, :fencing_token, greater_than: intent.fencing_token)

  defp validate_commit_fence(changeset, intent),
    do: validate_number(changeset, :fencing_token, greater_than_or_equal_to: intent.fencing_token)

  defp validate_datetime_order(changeset, earlier_field, later_field, allow_equal) do
    earlier = get_field(changeset, earlier_field)
    later = get_field(changeset, later_field)

    case {earlier, later} do
      {%DateTime{} = earlier, %DateTime{} = later} ->
        comparison = DateTime.compare(later, earlier)
        valid? = comparison == :gt or (allow_equal and comparison == :eq)

        if valid?,
          do: changeset,
          else: add_error(changeset, later_field, "must not precede #{earlier_field}")

      _ ->
        changeset
    end
  end

  defp validate_hashes(changeset) do
    Enum.reduce(
      [:idempotency_key_hash, :request_fingerprint, :csr_sha256, :public_key_sha256],
      changeset,
      &validate_exact_bytes(&2, &1, 32)
    )
  end

  defp validate_payloads(changeset) do
    changeset
    |> validate_length(:csr_der, min: 1, max: 32_768, count: :bytes)
    |> validate_length(:public_key_spki_der, min: 1, max: 2_048, count: :bytes)
    |> validate_length(:agent_info_canonical, min: 2, max: 16_384, count: :bytes)
  end

  defp validate_exact_bytes(changeset, field, expected) do
    validate_change(changeset, field, fn ^field, value ->
      if is_binary(value) and byte_size(value) == expected,
        do: [],
        else: [{field, "must be exactly #{expected} bytes"}]
    end)
  end

  defp invalid_transition(intent, next_state) do
    intent
    |> change()
    |> add_error(
      :state,
      "transition from #{intent.state || "uninitialized"} to #{next_state} is forbidden"
    )
  end
end
