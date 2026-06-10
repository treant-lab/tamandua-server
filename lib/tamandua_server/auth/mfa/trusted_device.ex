defmodule TamanduaServer.Auth.MFA.TrustedDevice do
  @moduledoc """
  Schema for trusted devices (remember me for 30 days).
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @trust_duration_days 30

  schema "mfa_trusted_devices" do
    field :token_hash, :string
    field :name, :string
    field :fingerprint, :string
    field :ip_address, :string
    field :user_agent, :string
    field :expires_at, :utc_datetime_usec
    field :last_used_at, :utc_datetime_usec
    field :revoked_at, :utc_datetime_usec

    belongs_to :user, TamanduaServer.Accounts.User

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(device, attrs) do
    device
    |> cast(attrs, [
      :user_id,
      :token_hash,
      :name,
      :fingerprint,
      :ip_address,
      :user_agent,
      :expires_at,
      :last_used_at,
      :revoked_at
    ])
    |> validate_required([:user_id, :token_hash])
    |> put_expires_at()
  end

  defp put_expires_at(changeset) do
    if get_change(changeset, :expires_at) do
      changeset
    else
      expires_at = DateTime.utc_now() |> DateTime.add(@trust_duration_days * 24 * 3600, :second)
      put_change(changeset, :expires_at, expires_at)
    end
  end

  @doc """
  Generate a random device token.
  """
  def generate_token do
    :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  end

  @doc """
  Hash a device token for storage.
  """
  def hash_token(token) do
    Bcrypt.hash_pwd_salt(token)
  end

  @doc """
  Verify a device token against its hash.
  """
  def verify_token(token, hash) do
    Bcrypt.verify_pass(token, hash)
  end

  @doc """
  Update last used timestamp.
  """
  def touch_last_used(device) do
    device
    |> change(last_used_at: DateTime.utc_now())
  end

  @doc """
  Revoke a trusted device.
  """
  def revoke(device) do
    device
    |> change(revoked_at: DateTime.utc_now())
  end

  @doc """
  Check if a device is valid (not expired, not revoked).
  """
  def valid?(%__MODULE__{revoked_at: nil, expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :lt
  end

  def valid?(_), do: false

  @doc """
  Generate device fingerprint from user agent and IP.
  """
  def generate_fingerprint(user_agent, ip_address) do
    :crypto.hash(:sha256, "#{user_agent}#{ip_address}")
    |> Base.encode16(case: :lower)
  end
end
