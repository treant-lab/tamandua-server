defmodule TamanduaServer.Auth.MFA.Credential do
  @moduledoc """
  Schema for MFA credentials (TOTP, SMS, Email, WebAuthn).
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @credential_types ~w(totp sms email webauthn)

  schema "mfa_credentials" do
    field :type, :string
    field :name, :string
    field :is_primary, :boolean, default: false
    field :is_verified, :boolean, default: false

    # TOTP
    field :totp_secret, :string

    # SMS/Email
    field :phone_number, :string
    field :email, :string
    field :last_code, :string
    field :last_code_sent_at, :utc_datetime_usec

    # WebAuthn
    field :credential_id, :binary
    field :public_key, :binary
    field :counter, :integer, default: 0
    field :aaguid, :binary
    field :transports, {:array, :string}

    # Metadata
    field :last_used_at, :utc_datetime_usec
    field :created_ip, :string

    belongs_to :user, TamanduaServer.Accounts.User

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(credential, attrs) do
    credential
    |> cast(attrs, [
      :user_id,
      :type,
      :name,
      :is_primary,
      :is_verified,
      :totp_secret,
      :phone_number,
      :email,
      :last_code,
      :last_code_sent_at,
      :credential_id,
      :public_key,
      :counter,
      :aaguid,
      :transports,
      :last_used_at,
      :created_ip
    ])
    |> validate_required([:user_id, :type])
    |> validate_inclusion(:type, @credential_types)
    |> validate_credential_fields()
    |> unique_constraint(:credential_id)
  end

  defp validate_credential_fields(changeset) do
    type = get_field(changeset, :type)

    case type do
      "totp" ->
        validate_required(changeset, [:totp_secret])

      "sms" ->
        validate_required(changeset, [:phone_number])
        |> validate_format(:phone_number, ~r/^\+[1-9]\d{1,14}$/, message: "must be in E.164 format")

      "email" ->
        validate_required(changeset, [:email])
        |> validate_format(:email, ~r/@/)

      "webauthn" ->
        validate_required(changeset, [:credential_id, :public_key])

      _ ->
        changeset
    end
  end

  @doc """
  Update last used timestamp.
  """
  def touch_last_used(credential) do
    credential
    |> change(last_used_at: DateTime.utc_now())
  end
end
