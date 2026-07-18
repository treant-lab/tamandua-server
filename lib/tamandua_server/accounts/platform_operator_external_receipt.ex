defmodule TamanduaServer.Accounts.PlatformOperatorExternalReceipt do
  @moduledoc false

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.PlatformOperatorEvent

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "platform_operator_external_receipts" do
    field(:operation_id, :string)
    field(:token_hash, :binary, redact: true)
    field(:worker_identity_hash, :binary, redact: true)
    field(:issued_at, :utc_datetime_usec)
    field(:expires_at, :utc_datetime_usec)
    field(:terminal_at, :utc_datetime_usec)
    field(:terminal_outcome, :string)

    belongs_to(:intent_event, PlatformOperatorEvent)

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  def changeset(receipt, attrs) do
    receipt
    |> cast(attrs, [
      :operation_id,
      :token_hash,
      :worker_identity_hash,
      :intent_event_id,
      :issued_at,
      :expires_at,
      :terminal_at,
      :terminal_outcome
    ])
    |> validate_required([
      :operation_id,
      :token_hash,
      :worker_identity_hash,
      :intent_event_id,
      :issued_at,
      :expires_at
    ])
    |> validate_length(:operation_id, min: 8, max: 128)
    |> validate_digest(:token_hash)
    |> validate_digest(:worker_identity_hash)
    |> validate_inclusion(:terminal_outcome, ["succeeded", "failed"])
    |> validate_expiry()
    |> validate_terminal_state()
    |> unique_constraint(:operation_id)
    |> unique_constraint(:intent_event_id)
    |> foreign_key_constraint(:intent_event_id)
  end

  def terminal_changeset(receipt, outcome, now) when outcome in [:succeeded, :failed] do
    receipt
    |> change(terminal_at: now, terminal_outcome: Atom.to_string(outcome))
    |> validate_terminal_state()
  end

  defp validate_digest(changeset, field) do
    validate_change(changeset, field, fn ^field, value ->
      if is_binary(value) and byte_size(value) == 32,
        do: [],
        else: [{field, "must be a 32-byte digest"}]
    end)
  end

  defp validate_expiry(changeset) do
    issued_at = get_field(changeset, :issued_at)
    expires_at = get_field(changeset, :expires_at)

    if match?(%DateTime{}, issued_at) and match?(%DateTime{}, expires_at) and
         DateTime.compare(expires_at, issued_at) == :gt do
      changeset
    else
      add_error(changeset, :expires_at, "must be after issued_at")
    end
  end

  defp validate_terminal_state(changeset) do
    terminal_at = get_field(changeset, :terminal_at)
    outcome = get_field(changeset, :terminal_outcome)

    if (is_nil(terminal_at) and is_nil(outcome)) or
         (match?(%DateTime{}, terminal_at) and outcome in ["succeeded", "failed"]) do
      changeset
    else
      add_error(changeset, :terminal_at, "must be paired with a terminal outcome")
    end
  end
end
