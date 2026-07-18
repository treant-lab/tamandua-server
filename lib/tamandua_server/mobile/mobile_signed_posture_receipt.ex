defmodule TamanduaServer.Mobile.MobileSignedPostureReceipt do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec, updated_at: false]

  schema "mobile_signed_posture_receipts" do
    field(:installation_id, :string)
    field(:device_key_id, :string)
    field(:key_scope_id, :string)
    field(:posture, :map)
    field(:posture_sha256, :string)
    field(:signed_payload_sha256, :string)
    field(:signature_sha256, :binary)
    field(:observed_at, :utc_datetime_usec)
    field(:verified_at, :utc_datetime_usec)
    belongs_to(:organization, TamanduaServer.Accounts.Organization)
    belongs_to(:request, TamanduaServer.Mobile.MobileSignedPostureRequest)
    belongs_to(:identity_key, TamanduaServer.Mobile.MobileDeviceIdentityKey)
    timestamps()
  end

  @required ~w(organization_id request_id identity_key_id installation_id device_key_id key_scope_id posture posture_sha256 signed_payload_sha256 signature_sha256 observed_at verified_at)a
  def changeset(record, attrs),
    do:
      record
      |> cast(attrs, @required)
      |> validate_required(@required)
      |> validate_length(:installation_id, min: 1, max: 255)
      |> validate_format(:installation_id, ~r/\S/)
      |> validate_format(:device_key_id, ~r/^tmdk_v1_[A-Za-z0-9_-]{43}$/)
      |> validate_format(:key_scope_id, ~r/^tmdks_v1_[A-Za-z0-9_-]{43}$/)
      |> validate_format(:posture_sha256, ~r/^[A-Za-z0-9_-]{43}$/)
      |> validate_format(:signed_payload_sha256, ~r/^[A-Za-z0-9_-]{43}$/)
      |> validate_length(:signature_sha256, is: 32)
      |> unique_constraint(:request_id)
      |> check_constraint(:device_key_id, name: :signed_posture_receipt_key_formats)
      |> check_constraint(:posture_sha256, name: :signed_posture_receipt_hash_formats)
      |> check_constraint(:signature_sha256, name: :signed_posture_receipt_signature_digest)
      |> foreign_key_constraint(:organization_id)
      |> foreign_key_constraint(:request_id)
      |> foreign_key_constraint(:identity_key_id)
end
