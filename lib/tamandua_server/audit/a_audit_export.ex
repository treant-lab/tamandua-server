defmodule TamanduaServer.Audit.AuditExport do
  @moduledoc """
  Schema for audit export jobs.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "audit_exports" do
    field :export_type, :string
    field :filters, :map
    field :status, :string
    field :progress, :integer
    field :total_records, :integer
    field :file_path, :string
    field :file_size, :integer
    field :download_url, :string
    field :expires_at, :utc_datetime_usec
    field :error_message, :string
    field :schedule, :string
    field :next_run_at, :utc_datetime_usec
    field :is_recurring, :boolean

    belongs_to :user, TamanduaServer.Accounts.User
    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(export, attrs) do
    export
    |> cast(attrs, [
      :export_type, :filters, :user_id, :organization_id,
      :schedule, :is_recurring, :next_run_at
    ])
    |> validate_required([:export_type, :organization_id])
    |> validate_inclusion(:export_type, ~w(csv json pdf))
    |> put_change(:status, "pending")
    |> put_change(:progress, 0)
  end
end
