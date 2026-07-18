defmodule TamanduaServer.Mobile.MobileDeviceIdentityProviderKey do
  @moduledoc false

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Mobile.MobileDeviceIdentityKey

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "mobile_device_identity_provider_keys" do
    field(:provider, :string)
    field(:profile_id, :string)
    field(:environment, :string)
    field(:team_id, :string)
    field(:bundle_id, :string)
    field(:installation_id, :string)
    field(:credential_id, :binary)
    field(:public_key_spki, :binary)
    field(:receipt_sha256, :binary)
    field(:sign_count, :integer, default: 0)
    field(:last_asserted_at, :utc_datetime_usec)

    belongs_to(:organization, Organization)
    belongs_to(:identity_key, MobileDeviceIdentityKey)

    timestamps(type: :utc_datetime_usec)
  end

  @required ~w(
    organization_id identity_key_id provider profile_id environment team_id bundle_id
    installation_id credential_id public_key_spki receipt_sha256 sign_count last_asserted_at
  )a

  def changeset(record, attrs) do
    record
    |> cast(attrs, @required)
    |> validate_required(@required)
    |> validate_inclusion(:provider, ["apple_app_attest"])
    |> validate_inclusion(:environment, ["development", "production"])
    |> validate_format(:team_id, ~r/^[A-Z0-9]{10}$/)
    |> validate_length(:profile_id, min: 1, max: 128)
    |> validate_length(:bundle_id, min: 3, max: 255)
    |> validate_length(:installation_id, min: 1, max: 255)
    |> validate_number(:sign_count, greater_than: 0)
    |> validate_binary_size(:credential_id, 32)
    |> validate_binary_size(:public_key_spki, 91)
    |> validate_binary_size(:receipt_sha256, 32)
    |> unique_constraint(:identity_key_id, name: :mobile_identity_provider_keys_identity_idx)
    |> unique_constraint([:provider, :environment, :credential_id],
      name: :mobile_identity_provider_keys_global_credential_idx
    )
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:identity_key_id)
  end

  def for_identity(query \\ __MODULE__, organization_id, identity_key_id) do
    from(record in query,
      where:
        record.organization_id == ^organization_id and record.identity_key_id == ^identity_key_id
    )
  end

  defp validate_binary_size(changeset, field, expected) do
    validate_change(changeset, field, fn ^field, value ->
      if is_binary(value) and byte_size(value) == expected,
        do: [],
        else: [{field, "must be exactly #{expected} bytes"}]
    end)
  end
end
