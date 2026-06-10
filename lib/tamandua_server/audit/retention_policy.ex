defmodule TamanduaServer.Audit.RetentionPolicy do
  @moduledoc """
  Schema for audit log retention policies.

  Defines how long audit logs are kept and archived:
  - Hot storage: Fast queries (default: 90 days)
  - Warm storage: Compressed, indexed (default: 1 year)
  - Cold storage: Archived for compliance (default: 7 years)
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "audit_retention_policies" do
    belongs_to :organization, Organization

    # Retention periods
    field :hot_retention_days, :integer, default: 90
    field :warm_retention_days, :integer, default: 365
    field :cold_retention_years, :integer, default: 7

    # Archival settings
    field :auto_archive, :boolean, default: true
    field :compress_archives, :boolean, default: true
    field :archive_storage_path, :string

    # Compliance requirements
    field :compliance_framework, :string  # SOC2, HIPAA, GDPR, etc.
    field :legal_hold, :boolean, default: false
    field :legal_hold_until, :utc_datetime_usec

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(organization_id)a
  @optional_fields ~w(
    hot_retention_days warm_retention_days cold_retention_years
    auto_archive compress_archives archive_storage_path
    compliance_framework legal_hold legal_hold_until
  )a

  def changeset(policy, attrs) do
    policy
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_number(:hot_retention_days, greater_than: 0, less_than_or_equal_to: 365)
    |> validate_number(:warm_retention_days, greater_than: 0, less_than_or_equal_to: 2555)
    |> validate_number(:cold_retention_years, greater_than: 0, less_than_or_equal_to: 25)
    |> validate_retention_order()
    |> unique_constraint(:organization_id)
    |> foreign_key_constraint(:organization_id)
  end

  defp validate_retention_order(changeset) do
    hot = get_field(changeset, :hot_retention_days) || 90
    warm = get_field(changeset, :warm_retention_days) || 365

    if hot > warm do
      add_error(changeset, :hot_retention_days, "must be less than or equal to warm retention")
    else
      changeset
    end
  end
end
