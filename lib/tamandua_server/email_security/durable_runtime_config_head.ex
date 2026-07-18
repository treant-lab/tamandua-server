defmodule TamanduaServer.EmailSecurity.DurableRuntimeConfigHead do
  @moduledoc false

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "email_integration_config_heads" do
    field(:provider, :string)
    field(:committed_revision, :integer, default: 0)
    field(:pending_revision, :integer)
    field(:pending_operation_id, Ecto.UUID)
    field(:pending_owner_id, :string)
    field(:pending_expires_at, :utc_datetime_usec)
    field(:applied_revision, :integer, default: 0)
    field(:apply_status, :string, default: "never_applied")
    field(:last_apply_error_code, :string)
    field(:last_applied_at, :utc_datetime_usec)

    belongs_to(:organization, TamanduaServer.Accounts.Organization)

    has_many(:versions, TamanduaServer.EmailSecurity.DurableRuntimeConfigVersion,
      foreign_key: :head_id
    )

    timestamps(type: :utc_datetime_usec)
  end

  def create_changeset(head, attrs) do
    head
    |> cast(attrs, [:organization_id, :provider])
    |> validate_required([:organization_id, :provider])
    |> validate_inclusion(:provider, ["microsoft365", "google_workspace"])
    |> unique_constraint([:organization_id, :provider],
      name: :email_integration_config_heads_org_provider_idx
    )
  end

  def pending_changeset(head, attrs) do
    head
    |> cast(attrs, [
      :pending_revision,
      :pending_operation_id,
      :pending_owner_id,
      :pending_expires_at
    ])
    |> validate_required([
      :pending_revision,
      :pending_operation_id,
      :pending_owner_id,
      :pending_expires_at
    ])
  end

  def clear_pending_changeset(head, attrs) do
    cast(head, attrs, [
      :committed_revision,
      :pending_revision,
      :pending_operation_id,
      :pending_owner_id,
      :pending_expires_at,
      :apply_status,
      :last_apply_error_code
    ])
  end
end
