defmodule TamanduaServer.EmailSecurity.DurableRuntimeConfigVersion do
  @moduledoc false

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "email_integration_config_versions" do
    field(:provider, :string)
    field(:revision, :integer)
    field(:base_revision, :integer)
    field(:status, :string, default: "pending")
    field(:public_config, :map, default: %{})
    field(:secret_ciphertext, :string, redact: true)
    field(:vault_key_name, :string)
    field(:vault_ciphertext_version, :integer)
    field(:secret_schema_version, :integer, default: 2)
    field(:operation_id, Ecto.UUID)
    field(:created_by, :string)
    field(:lease_expires_at, :utc_datetime_usec)
    field(:request_fingerprint, :binary, redact: true)
    field(:request_fingerprint_key_version, :integer)
    field(:ciphertext_sha256, :binary, redact: true)
    field(:committed_at, :utc_datetime_usec)
    field(:aborted_at, :utc_datetime_usec)
    field(:abort_reason_code, :string)

    belongs_to(:head, TamanduaServer.EmailSecurity.DurableRuntimeConfigHead)
    belongs_to(:organization, TamanduaServer.Accounts.Organization)

    timestamps(type: :utc_datetime_usec)
  end

  def pending_changeset(version, attrs) do
    version
    |> cast(attrs, [
      :head_id,
      :organization_id,
      :provider,
      :revision,
      :base_revision,
      :public_config,
      :secret_ciphertext,
      :vault_key_name,
      :vault_ciphertext_version,
      :secret_schema_version,
      :operation_id,
      :created_by,
      :lease_expires_at,
      :request_fingerprint,
      :request_fingerprint_key_version,
      :ciphertext_sha256
    ])
    |> validate_required([
      :head_id,
      :organization_id,
      :provider,
      :revision,
      :base_revision,
      :secret_ciphertext,
      :vault_key_name,
      :vault_ciphertext_version,
      :secret_schema_version,
      :operation_id,
      :created_by,
      :lease_expires_at,
      :request_fingerprint,
      :request_fingerprint_key_version,
      :ciphertext_sha256
    ])
    |> validate_inclusion(:provider, ["microsoft365", "google_workspace"])
    |> validate_number(:revision, greater_than: 0)
    |> validate_number(:base_revision, greater_than_or_equal_to: 0)
    |> validate_number(:vault_ciphertext_version, greater_than: 0)
    |> validate_number(:secret_schema_version, greater_than: 0)
    |> validate_format(:secret_ciphertext, ~r/^vault:v\d+:/)
    |> unique_constraint([:organization_id, :provider, :revision],
      name: :email_integration_config_versions_org_provider_revision_idx
    )
    |> validate_number(:request_fingerprint_key_version, greater_than: 0)
    |> validate_length(:request_fingerprint, is: 32)
    |> validate_length(:ciphertext_sha256, is: 32)
    |> unique_constraint([:organization_id, :provider, :operation_id],
      name: :email_integration_config_versions_operation_idx
    )
    |> foreign_key_constraint(:head_id, name: :email_config_versions_head_scope_fkey)
  end

  def lifecycle_changeset(version, attrs) do
    cast(version, attrs, [:status, :committed_at, :aborted_at, :abort_reason_code])
  end
end
