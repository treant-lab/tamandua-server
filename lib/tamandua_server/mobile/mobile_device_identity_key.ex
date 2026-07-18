defmodule TamanduaServer.Mobile.MobileDeviceIdentityKey do
  @moduledoc """
  Server-verified mobile device proof-of-possession key.

  Attestation state is deliberately separate from proof state. A valid ECDSA
  signature proves possession, but an attestation supplied by a client remains
  `present_unverified` until a platform verifier validates it off-device.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Mobile.{Device, MobileDeviceIdentityChallenge}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @algorithm "ecdsa-p256-sha256"
  @platforms ~w(android ios)
  @proof_states ~w(verified invalid not_provided)
  @attestation_states ~w(
    not_requested unsupported unavailable present_unverified
    verified_software verified_tee verified_strongbox verified_app_attest
    invalid revoked error
  )
  @lifecycle_states ~w(active revoked rotated)

  schema "mobile_device_identity_keys" do
    field(:installation_id, :string)
    field(:platform, :string)
    field(:key_scope_id, :string)
    field(:device_key_id, :string)
    field(:public_key_spki, :binary)
    field(:algorithm, :string, default: @algorithm)
    field(:proof_state, :string)
    field(:attestation_state, :string)
    field(:lifecycle_state, :string)
    field(:activated_at, :utc_datetime_usec)
    field(:last_proof_at, :utc_datetime_usec)
    field(:revoked_at, :utc_datetime_usec)
    field(:rotated_at, :utc_datetime_usec)
    field(:metadata, :map, default: %{})

    belongs_to(:organization, Organization)
    belongs_to(:mobile_device, Device)
    belongs_to(:proof_challenge, MobileDeviceIdentityChallenge)
    belongs_to(:rotated_from, __MODULE__)

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @required_fields ~w(
    organization_id proof_challenge_id installation_id platform key_scope_id
    device_key_id public_key_spki algorithm proof_state attestation_state
    lifecycle_state activated_at last_proof_at
  )a

  def changeset(key, attrs) do
    key
    |> cast(attrs, @required_fields ++ optional_fields())
    |> validate_required(@required_fields)
    |> validate_length(:installation_id, min: 1, max: 255)
    |> validate_format(:installation_id, ~r/\S/)
    |> validate_length(:key_scope_id, min: 16, max: 96)
    |> validate_format(:device_key_id, ~r/^tmdk_v1_[A-Za-z0-9_-]{43}$/)
    |> validate_binary_size(:public_key_spki, 64, 512)
    |> validate_inclusion(:platform, @platforms)
    |> validate_inclusion(:algorithm, [@algorithm])
    |> validate_inclusion(:proof_state, @proof_states)
    |> validate_inclusion(:attestation_state, @attestation_states)
    |> validate_inclusion(:lifecycle_state, @lifecycle_states)
    |> unique_constraint([:organization_id, :device_key_id])
    |> unique_constraint([:organization_id, :installation_id],
      name: :mobile_device_identity_keys_one_active_installation_index
    )
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:mobile_device_id)
    |> foreign_key_constraint(:proof_challenge_id)
    |> foreign_key_constraint(:rotated_from_id)
  end

  def active_for_installation(query \\ __MODULE__, organization_id, installation_id) do
    from(key in query,
      where:
        key.organization_id == ^organization_id and key.installation_id == ^installation_id and
          key.lifecycle_state == "active"
    )
  end

  defp optional_fields do
    ~w(mobile_device_id rotated_from_id revoked_at rotated_at metadata)a
  end

  defp validate_binary_size(changeset, field, minimum, maximum) do
    validate_change(changeset, field, fn ^field, value ->
      if is_binary(value) and byte_size(value) >= minimum and byte_size(value) <= maximum do
        []
      else
        [{field, "must be a binary of #{minimum}..#{maximum} bytes"}]
      end
    end)
  end
end
