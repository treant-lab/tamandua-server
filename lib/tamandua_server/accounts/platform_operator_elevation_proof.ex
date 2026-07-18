defmodule TamanduaServer.Accounts.PlatformOperatorElevationProof do
  @moduledoc false

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{
    PlatformOperatorCapabilities,
    PlatformOperatorGrant,
    User
  }

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @purpose "platform_operation"

  schema "platform_operator_elevation_proofs" do
    field(:proof_hash, :binary, redact: true)
    field(:session_binding_hash, :binary, redact: true)
    field(:mfa_timestep_hash, :binary, redact: true)
    field(:audience, :string)
    field(:purpose, :string, default: @purpose)
    field(:issued_at, :utc_datetime_usec)
    field(:expires_at, :utc_datetime_usec)
    field(:consumed_at, :utc_datetime_usec)
    field(:consumed_operation_id, :string)
    field(:revoked_at, :utc_datetime_usec)

    belongs_to(:user, User)
    belongs_to(:grant, PlatformOperatorGrant)

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  def changeset(proof, attrs) do
    proof
    |> cast(attrs, [
      :user_id,
      :grant_id,
      :proof_hash,
      :session_binding_hash,
      :mfa_timestep_hash,
      :audience,
      :purpose,
      :issued_at,
      :expires_at,
      :consumed_at,
      :consumed_operation_id,
      :revoked_at
    ])
    |> validate_required([
      :user_id,
      :grant_id,
      :proof_hash,
      :session_binding_hash,
      :mfa_timestep_hash,
      :audience,
      :purpose,
      :issued_at,
      :expires_at
    ])
    |> validate_digest(:proof_hash)
    |> validate_digest(:session_binding_hash)
    |> validate_digest(:mfa_timestep_hash)
    |> validate_inclusion(:audience, PlatformOperatorCapabilities.all())
    |> validate_inclusion(:purpose, [@purpose])
    |> validate_expiry()
    |> validate_consumption_state()
    |> unique_constraint(:proof_hash)
    |> unique_constraint([:user_id, :session_binding_hash, :audience, :mfa_timestep_hash],
      name: :platform_operator_elevation_proofs_mfa_step_uidx,
      error_key: :mfa_timestep_hash
    )
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:grant_id)
  end

  def purpose, do: @purpose

  def consume_changeset(proof, operation_id, now) do
    proof
    |> change(consumed_at: now, consumed_operation_id: operation_id)
    |> validate_required([:consumed_at, :consumed_operation_id])
  end

  def revoke_changeset(proof, now), do: change(proof, revoked_at: now)

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

  defp validate_consumption_state(changeset) do
    consumed_at = get_field(changeset, :consumed_at)
    operation_id = get_field(changeset, :consumed_operation_id)

    if (is_nil(consumed_at) and is_nil(operation_id)) or
         (match?(%DateTime{}, consumed_at) and is_binary(operation_id) and
            byte_size(operation_id) in 8..128) do
      changeset
    else
      add_error(changeset, :consumed_at, "must be paired with a bounded operation id")
    end
  end
end
