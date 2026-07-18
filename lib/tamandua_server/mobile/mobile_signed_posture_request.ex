defmodule TamanduaServer.Mobile.MobileSignedPostureRequest do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "mobile_signed_posture_requests" do
    field(:installation_id, :string)
    field(:device_key_id, :string)
    field(:key_scope_id, :string)
    field(:request_id_digest, :binary)
    field(:challenge_id_digest, :binary)
    field(:nonce_digest, :binary)
    field(:state, :string, default: "pending")
    field(:auth_method, :string)
    field(:issued_at, :utc_datetime_usec)
    field(:expires_at, :utc_datetime_usec)
    field(:consumed_at, :utc_datetime_usec)
    belongs_to(:organization, TamanduaServer.Accounts.Organization)
    belongs_to(:identity_key, TamanduaServer.Mobile.MobileDeviceIdentityKey)
    belongs_to(:requested_by, TamanduaServer.Accounts.User)
    timestamps(type: :utc_datetime_usec)
  end

  @required ~w(organization_id identity_key_id installation_id device_key_id key_scope_id request_id_digest challenge_id_digest nonce_digest state auth_method issued_at expires_at)a

  def changeset(record, attrs) do
    record
    |> cast(attrs, @required ++ [:requested_by_id, :consumed_at])
    |> validate_required(@required)
    |> validate_length(:installation_id, min: 1, max: 255)
    |> validate_format(:installation_id, ~r/\S/)
    |> validate_inclusion(:state, ~w(pending consumed))
    |> validate_length(:auth_method, min: 1, max: 64)
    |> validate_format(:device_key_id, ~r/^tmdk_v1_[A-Za-z0-9_-]{43}$/)
    |> validate_format(:key_scope_id, ~r/^tmdks_v1_[A-Za-z0-9_-]{43}$/)
    |> validate_length(:request_id_digest, is: 32)
    |> validate_length(:challenge_id_digest, is: 32)
    |> validate_length(:nonce_digest, is: 32)
    |> unique_constraint([:organization_id, :request_id_digest])
    |> unique_constraint([:organization_id, :challenge_id_digest])
    |> unique_constraint([:organization_id, :nonce_digest])
    |> check_constraint(:request_id_digest, name: :signed_posture_request_digest_sizes)
    |> check_constraint(:request_id_digest, name: :signed_posture_request_distinct_bindings)
    |> check_constraint(:device_key_id, name: :signed_posture_request_key_formats)
    |> check_constraint(:expires_at, name: :signed_posture_request_ttl)
    |> check_constraint(:state, name: :signed_posture_request_state)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:identity_key_id)
    |> foreign_key_constraint(:requested_by_id)
  end
end
