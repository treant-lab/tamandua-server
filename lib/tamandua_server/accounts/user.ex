defmodule TamanduaServer.Accounts.User do
  @moduledoc """
  Schema for user accounts.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  # Legacy role field - kept for backward compatibility
  # Use the RBAC system (user_roles association) for proper role management
  @roles ~w(admin analyst viewer responder hunter compliance_officer api_only)

  schema "users" do
    field :email, :string
    field :password, :string, virtual: true
    field :password_hash, :string
    field :role, :string, default: "analyst"
    field :name, :string
    field :mfa_secret, :string
    field :mfa_enabled, :boolean, default: false
    field :is_active, :boolean, default: true
    field :last_login_at, :utc_datetime_usec
    field :locale, :string, default: "en"
    field :timezone, :string, default: "UTC"

    belongs_to :organization, TamanduaServer.Accounts.Organization

    has_many :user_roles, TamanduaServer.Accounts.UserRole, on_delete: :delete_all
    has_many :roles, through: [:user_roles, :role]
    has_many :wallet_identities, TamanduaServer.Accounts.WalletIdentity, on_delete: :delete_all

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(email password_hash)a
  @optional_fields ~w(role name mfa_secret mfa_enabled is_active last_login_at organization_id locale timezone)a

  def changeset(user, attrs) do
    user
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_format(:email, ~r/@/)
    |> validate_inclusion(:role, @roles)
    |> unique_constraint(:email)
  end

  @doc """
  Changeset for user registration with password hashing.
  """
  def registration_changeset(user, attrs) do
    user
    |> cast(attrs, [:email, :name, :password, :role, :organization_id])
    |> validate_required([:email, :password])
    |> validate_format(:email, ~r/@/)
    |> validate_length(:password, min: 8)
    |> validate_inclusion(:role, @roles)
    |> unique_constraint(:email)
    |> hash_password()
  end

  defp hash_password(changeset) do
    case get_change(changeset, :password) do
      nil ->
        changeset

      password ->
        changeset
        |> put_change(:password_hash, Bcrypt.hash_pwd_salt(password))
        |> delete_change(:password)
    end
  end

  @doc """
  Verifies if the given password matches the user's password hash.
  """
  def valid_password?(%__MODULE__{password_hash: hash}, password)
      when is_binary(hash) and byte_size(password) > 0 do
    Bcrypt.verify_pass(password, hash)
  end

  def valid_password?(_, _), do: Bcrypt.no_user_verify()
end
