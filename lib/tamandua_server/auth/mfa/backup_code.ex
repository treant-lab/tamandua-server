defmodule TamanduaServer.Auth.MFA.BackupCode do
  @moduledoc """
  Schema for MFA backup codes.
  Each user gets 10 single-use backup codes.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "mfa_backup_codes" do
    field :code_hash, :string
    field :used_at, :utc_datetime_usec
    field :used_ip, :string

    belongs_to :user, TamanduaServer.Accounts.User

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(backup_code, attrs) do
    backup_code
    |> cast(attrs, [:user_id, :code_hash, :used_at, :used_ip])
    |> validate_required([:user_id, :code_hash])
  end

  @doc """
  Generate a random backup code (8 characters, alphanumeric).
  """
  def generate_code do
    :crypto.strong_rand_bytes(6)
    |> Base.encode32(padding: false)
    |> binary_part(0, 8)
  end

  @doc """
  Hash a backup code for storage.
  """
  def hash_code(code) do
    Bcrypt.hash_pwd_salt(code)
  end

  @doc """
  Verify a backup code against its hash.
  """
  def verify_code(code, hash) do
    Bcrypt.verify_pass(code, hash)
  end

  @doc """
  Mark a backup code as used.
  """
  def mark_used(backup_code, ip_address) do
    backup_code
    |> change(used_at: DateTime.utc_now(), used_ip: ip_address)
  end

  @doc """
  Check if a backup code has been used.
  """
  def used?(%__MODULE__{used_at: nil}), do: false
  def used?(%__MODULE__{used_at: _}), do: true
end
