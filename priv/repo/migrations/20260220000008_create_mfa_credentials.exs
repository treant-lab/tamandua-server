defmodule TamanduaServer.Repo.Migrations.CreateMfaCredentials do
  use Ecto.Migration

  def change do
    create table(:mfa_credentials, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, on_delete: :delete_all, type: :binary_id), null: false
      add :type, :string, null: false  # "totp", "sms", "email", "webauthn"
      add :name, :string  # User-friendly name for the credential
      add :is_primary, :boolean, default: false  # Primary MFA method
      add :is_verified, :boolean, default: false

      # TOTP fields
      add :totp_secret, :string  # Base32-encoded secret

      # SMS/Email fields
      add :phone_number, :string  # For SMS
      add :email, :string  # For email codes (can differ from user email)
      add :last_code, :string  # Last sent code (hashed)
      add :last_code_sent_at, :utc_datetime_usec

      # WebAuthn fields
      add :credential_id, :binary  # WebAuthn credential ID
      add :public_key, :binary  # Public key
      add :counter, :bigint, default: 0  # Signature counter for replay protection
      add :aaguid, :binary  # Authenticator AAGUID
      add :transports, {:array, :string}  # ["usb", "nfc", "ble", "internal"]

      # Metadata
      add :last_used_at, :utc_datetime_usec
      add :created_ip, :string

      timestamps(type: :utc_datetime_usec)
    end

    create index(:mfa_credentials, [:user_id])
    create index(:mfa_credentials, [:user_id, :type])
    create index(:mfa_credentials, [:user_id, :is_primary])
    create unique_index(:mfa_credentials, [:credential_id], where: "type = 'webauthn'")
  end
end
