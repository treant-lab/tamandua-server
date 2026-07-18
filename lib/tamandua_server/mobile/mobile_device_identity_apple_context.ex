defmodule TamanduaServer.Mobile.MobileDeviceIdentityAppleContext do
  @moduledoc false

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Mobile.MobileDeviceIdentityChallenge

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "mobile_device_identity_apple_contexts" do
    field(:installation_id, :string)
    field(:profile_id, :string)
    field(:environment, :string)
    field(:team_id, :string)
    field(:bundle_id, :string)
    field(:state, :string, default: "attest_pending")
    field(:attestation_challenge_digest, :binary)
    field(:receipt_id, :binary_id)
    field(:credential_id, :binary)
    field(:public_key_spki, :binary)
    field(:receipt_sha256, :binary)
    field(:validation_category, :integer)
    field(:bundle_version, :string)
    field(:metadata, :map, default: %{})
    field(:expires_at, :utc_datetime_usec)
    field(:consumed_at, :utc_datetime_usec)

    belongs_to(:organization, Organization)
    belongs_to(:assertion_challenge, MobileDeviceIdentityChallenge)
    timestamps(type: :utc_datetime_usec)
  end

  @required ~w(
    organization_id installation_id profile_id environment team_id bundle_id state
    attestation_challenge_digest expires_at
  )a

  def changeset(context, attrs) do
    context
    |> cast(attrs, @required ++ optional_fields())
    |> validate_required(@required)
    |> validate_inclusion(:state, ~w(attest_pending assert_pending consumed))
    |> validate_inclusion(:environment, ~w(development production))
    |> validate_format(:team_id, ~r/^[A-Z0-9]{10}$/)
    |> validate_length(:installation_id, min: 1, max: 255)
    |> validate_length(:profile_id, min: 1, max: 128)
    |> validate_length(:bundle_id, min: 3, max: 255)
    |> validate_length(:bundle_version, max: 64)
    |> validate_binary_size(:attestation_challenge_digest, 32)
    |> validate_optional_binary_size(:credential_id, 32)
    |> validate_optional_binary_size(:public_key_spki, 91)
    |> validate_optional_binary_size(:receipt_sha256, 32)
    |> unique_constraint(:receipt_id, name: :mobile_identity_apple_contexts_receipt_idx)
    |> unique_constraint(:assertion_challenge_id,
      name: :mobile_identity_apple_contexts_assertion_challenge_idx
    )
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:assertion_challenge_id)
  end

  def pending_for_tenant(query \\ __MODULE__, organization_id, id) do
    from(context in query,
      where:
        context.organization_id == ^organization_id and context.id == ^id and
          context.state in ["attest_pending", "assert_pending"]
    )
  end

  defp optional_fields do
    ~w(
      assertion_challenge_id receipt_id credential_id public_key_spki receipt_sha256
      validation_category bundle_version metadata consumed_at
    )a
  end

  defp validate_binary_size(changeset, field, expected) do
    validate_change(changeset, field, fn ^field, value ->
      if is_binary(value) and byte_size(value) == expected,
        do: [],
        else: [{field, "must be exactly #{expected} bytes"}]
    end)
  end

  defp validate_optional_binary_size(changeset, field, expected) do
    validate_change(changeset, field, fn ^field, value ->
      if is_nil(value) or (is_binary(value) and byte_size(value) == expected),
        do: [],
        else: [{field, "must be exactly #{expected} bytes"}]
    end)
  end
end
