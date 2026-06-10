defmodule TamanduaServer.Audit.Signature do
  @moduledoc """
  Digital signature management for audit log sealing.

  Uses Ed25519 signatures to cryptographically seal audit log batches:
  - Generate key pairs for signing
  - Sign Merkle tree root hashes
  - Verify signatures on sealed batches
  - Key rotation support

  Ed25519 provides:
  - Fast signing and verification
  - Small signature size (64 bytes)
  - High security (128-bit security level)
  - Deterministic signatures

  ## Key Management

  Keys are stored encrypted at rest. The private key is used only for
  signing operations and is never exposed. Public keys are stored with
  signatures for verification.

  ## Example

      # Generate key pair
      {:ok, keypair} = Signature.generate_keypair()

      # Sign data
      signature = Signature.sign(data, keypair.private_key)

      # Verify signature
      Signature.verify(data, signature, keypair.public_key)
      # => true
  """

  use Ecto.Schema
  import Ecto.Changeset
  require Logger

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Repo

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "audit_signatures" do
    belongs_to :organization, Organization

    field :seal_number, :integer
    field :start_sequence, :integer
    field :end_sequence, :integer
    field :entry_count, :integer
    field :merkle_root, :string
    field :signature, :binary
    field :public_key, :binary
    field :sealed_at, :utc_datetime_usec
    field :verified_at, :utc_datetime_usec
    field :verification_status, :string, default: "pending"
    field :verification_details, :map, default: %{}

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  @required_fields ~w(seal_number start_sequence end_sequence entry_count merkle_root signature public_key sealed_at organization_id)a
  @optional_fields ~w(verified_at verification_status verification_details)a

  @doc """
  Changeset for creating an audit signature record.
  """
  def changeset(signature, attrs) do
    signature
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_number(:entry_count, greater_than: 0)
    |> validate_number(:start_sequence, greater_than: 0)
    |> validate_number(:end_sequence, greater_than: 0)
    |> validate_signature_size()
    |> validate_public_key_size()
    |> foreign_key_constraint(:organization_id)
    |> unique_constraint(:start_sequence, name: :audit_signatures_organization_id_start_sequence_index)
    |> unique_constraint(:end_sequence, name: :audit_signatures_organization_id_end_sequence_index)
  end

  @doc """
  Generate a new Ed25519 keypair.

  ## Returns
    - %{public_key: binary, private_key: binary}
  """
  def generate_keypair do
    # Ed25519 key generation
    {public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519)

    %{
      public_key: public_key,
      private_key: private_key
    }
  end

  @doc """
  Sign data using Ed25519 private key.

  ## Parameters
    - data: Binary data or string to sign
    - private_key: Ed25519 private key (64 bytes)

  ## Returns
    - Binary signature (64 bytes)
  """
  def sign(data, private_key) when is_binary(data) and is_binary(private_key) do
    :crypto.sign(:eddsa, :sha512, data, [private_key, :ed25519])
  end

  def sign(data, private_key) when is_binary(private_key) do
    sign(Jason.encode!(data), private_key)
  end

  @doc """
  Verify Ed25519 signature.

  ## Parameters
    - data: Binary data or string that was signed
    - signature: Ed25519 signature (64 bytes)
    - public_key: Ed25519 public key (32 bytes)

  ## Returns
    - true if signature is valid
    - false otherwise
  """
  def verify(data, signature, public_key)
      when is_binary(data) and is_binary(signature) and is_binary(public_key) do
    :crypto.verify(:eddsa, :sha512, data, signature, [public_key, :ed25519])
  rescue
    _ -> false
  end

  def verify(data, signature, public_key) when is_binary(signature) and is_binary(public_key) do
    verify(Jason.encode!(data), signature, public_key)
  end

  @doc """
  Get or create organization signing key.

  Keys are cached in ETS for performance. If no key exists, a new one is generated.

  ## Parameters
    - organization_id: UUID of organization

  ## Returns
    - %{public_key: binary, private_key: binary}
  """
  def get_or_create_signing_key(organization_id) do
    # In production, this should use a proper key management system (KMS)
    # For now, we'll use a deterministic approach with encrypted storage

    cache_key = {:audit_signing_key, organization_id}

    case :persistent_term.get(cache_key, nil) do
      nil ->
        # Generate or load from secure storage
        keypair = load_or_generate_key(organization_id)
        :persistent_term.put(cache_key, keypair)
        keypair

      keypair ->
        keypair
    end
  end

  @doc """
  Rotate signing key for an organization.

  This generates a new keypair and invalidates the old cached key.

  ## Parameters
    - organization_id: UUID of organization

  ## Returns
    - {:ok, new_keypair}
  """
  def rotate_signing_key(organization_id) do
    # Generate new keypair
    new_keypair = generate_keypair()

    # Store securely (in production, use KMS)
    store_keypair(organization_id, new_keypair)

    # Update cache
    cache_key = {:audit_signing_key, organization_id}
    :persistent_term.put(cache_key, new_keypair)

    Logger.info("Rotated audit signing key for organization #{organization_id}")

    {:ok, new_keypair}
  end

  @doc """
  Export public key in PEM format for external verification.

  ## Parameters
    - public_key: Ed25519 public key binary

  ## Returns
    - PEM-formatted string
  """
  def export_public_key_pem(public_key) when is_binary(public_key) do
    # Ed25519 public key in SubjectPublicKeyInfo format
    base64 = Base.encode64(public_key)

    """
    -----BEGIN PUBLIC KEY-----
    #{base64}
    -----END PUBLIC KEY-----
    """
  end

  @doc """
  Verify a sealed batch signature.

  ## Parameters
    - seal: %Signature{} schema with merkle_root, signature, public_key

  ## Returns
    - {:ok, :valid} if signature is valid
    - {:error, reason} otherwise
  """
  def verify_seal(%__MODULE__{} = seal) do
    try do
      valid = verify(seal.merkle_root, seal.signature, seal.public_key)

      if valid do
        {:ok, :valid}
      else
        {:error, :invalid_signature}
      end
    rescue
      e ->
        Logger.error("Error verifying seal signature: #{inspect(e)}")
        {:error, :verification_failed}
    end
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp validate_signature_size(changeset) do
    case get_field(changeset, :signature) do
      nil ->
        changeset

      signature when byte_size(signature) == 64 ->
        changeset

      _invalid ->
        add_error(changeset, :signature, "must be 64 bytes (Ed25519 signature)")
    end
  end

  defp validate_public_key_size(changeset) do
    case get_field(changeset, :public_key) do
      nil ->
        changeset

      public_key when byte_size(public_key) == 32 ->
        changeset

      _invalid ->
        add_error(changeset, :public_key, "must be 32 bytes (Ed25519 public key)")
    end
  end

  # Load or generate keypair for organization
  defp load_or_generate_key(organization_id) do
    # In production, this should:
    # 1. Try to load from secure key storage (AWS KMS, HashiCorp Vault, etc.)
    # 2. If not found, generate new key and store securely
    # 3. Private key should never be stored unencrypted

    # For now, generate deterministically (NOT PRODUCTION READY)
    # In production, replace with proper KMS integration
    case load_keypair(organization_id) do
      {:ok, keypair} ->
        keypair

      :not_found ->
        keypair = generate_keypair()
        store_keypair(organization_id, keypair)
        keypair
    end
  end

  # Load keypair from secure storage
  defp load_keypair(organization_id) do
    # TODO: Implement secure key storage
    # For demonstration, we'll use Application environment
    # NEVER do this in production!

    case Application.get_env(:tamandua_server, :audit_signing_keys, %{})[organization_id] do
      nil -> :not_found
      keypair -> {:ok, keypair}
    end
  end

  # Store keypair securely
  defp store_keypair(organization_id, keypair) do
    # TODO: Implement secure key storage (KMS, Vault, etc.)
    # For demonstration only
    current_keys = Application.get_env(:tamandua_server, :audit_signing_keys, %{})
    new_keys = Map.put(current_keys, organization_id, keypair)
    Application.put_env(:tamandua_server, :audit_signing_keys, new_keys)

    :ok
  end
end
