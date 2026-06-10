defmodule TamanduaServer.Licensing.LicenseKey do
  @moduledoc """
  Schema for license keys.

  Stores activated license keys with their terms and status.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @tiers [:trial, :pro, :enterprise, :mssp]

  @derive {Jason.Encoder, only: [
    :id, :organization_id, :tier, :agent_limit, :features,
    :issued_at, :expires_at, :is_active, :inserted_at
  ]}

  schema "license_keys" do
    belongs_to :organization, Organization

    field :license_key, :string  # The actual JWT token (encrypted at rest)
    field :tier, Ecto.Enum, values: @tiers
    field :agent_limit, :integer
    field :features, {:array, :string}, default: []

    field :issued_at, :utc_datetime_usec
    field :expires_at, :utc_datetime_usec
    field :activated_at, :utc_datetime_usec
    field :deactivated_at, :utc_datetime_usec

    field :is_active, :boolean, default: true

    # Billing info
    field :billing_cycle, :string  # monthly, annual
    field :auto_renew, :boolean, default: true
    field :payment_method_id, :string

    # Audit
    field :activated_by, :binary_id
    field :activation_ip, :string

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(organization_id tier agent_limit expires_at)a
  @optional_fields ~w(
    license_key features issued_at activated_at deactivated_at
    is_active billing_cycle auto_renew payment_method_id
    activated_by activation_ip
  )a

  def changeset(license, attrs) do
    license
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:tier, @tiers)
    |> validate_number(:agent_limit, greater_than: 0)
    |> set_activated_at()
    |> foreign_key_constraint(:organization_id)
  end

  defp set_activated_at(changeset) do
    if get_field(changeset, :is_active) && !get_field(changeset, :activated_at) do
      put_change(changeset, :activated_at, DateTime.utc_now())
    else
      changeset
    end
  end

  @doc """
  Returns the list of valid tiers.
  """
  def tiers, do: @tiers
end
