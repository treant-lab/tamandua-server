defmodule TamanduaServer.Audit.AuditArchive do
  @moduledoc """
  Schema for archived audit log entries.

  Stores compressed batches of audit logs for long-term retention.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "audit_archives" do
    belongs_to :organization, Organization

    field :date_from, :utc_datetime_usec
    field :date_to, :utc_datetime_usec
    field :entry_count, :integer
    field :compressed_data, :binary
    field :checksum, :string
    field :storage_tier, :string, default: "warm"  # warm or cold

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(organization_id date_from date_to entry_count checksum)a
  @optional_fields ~w(compressed_data storage_tier)a

  def changeset(archive, attrs) do
    archive
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_number(:entry_count, greater_than: 0)
    |> foreign_key_constraint(:organization_id)
  end
end
