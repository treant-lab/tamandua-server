defmodule TamanduaServer.Mobile.MobileSignedPostureProjection do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "mobile_signed_posture_projections" do
    field(:installation_id, :string)
    field(:device_key_id, :string)
    field(:key_scope_id, :string)
    field(:posture, :map)
    field(:posture_sha256, :string)
    field(:observed_at, :utc_datetime_usec)
    field(:verified_at, :utc_datetime_usec)
    belongs_to(:organization, TamanduaServer.Accounts.Organization)
    belongs_to(:receipt, TamanduaServer.Mobile.MobileSignedPostureReceipt)
    belongs_to(:identity_key, TamanduaServer.Mobile.MobileDeviceIdentityKey)
    timestamps(type: :utc_datetime_usec)
  end

  @required ~w(organization_id receipt_id identity_key_id installation_id device_key_id key_scope_id posture posture_sha256 observed_at verified_at)a
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
      |> unique_constraint([:organization_id, :installation_id])
      |> check_constraint(:device_key_id, name: :signed_posture_projection_key_formats)
      |> check_constraint(:posture_sha256, name: :signed_posture_projection_hash_format)
      |> foreign_key_constraint(:organization_id)
      |> foreign_key_constraint(:receipt_id)
      |> foreign_key_constraint(:identity_key_id)
end
