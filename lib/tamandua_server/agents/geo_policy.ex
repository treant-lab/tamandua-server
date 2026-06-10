defmodule TamanduaServer.Agents.GeoPolicy do
  @moduledoc """
  Region-based policy enforcement.
  Defines what happens when an agent is in specific regions.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "geo_policies" do
    field :name, :string
    field :description, :string
    field :region_ids, {:array, :binary_id}, default: []
    field :apply_to_unexpected, :boolean, default: false
    field :apply_to_restricted, :boolean, default: true
    field :require_mfa, :boolean, default: false
    field :disable_features, {:array, :string}, default: []
    field :restrict_file_downloads, :boolean, default: false
    field :restrict_file_uploads, :boolean, default: false
    field :enhanced_monitoring, :boolean, default: false
    field :auto_isolate, :boolean, default: false
    field :send_alert, :boolean, default: true
    field :alert_severity, :string, default: "high"
    field :priority, :integer, default: 0
    field :is_enabled, :boolean, default: true

    belongs_to :organization, Organization

    timestamps()
  end

  @doc false
  def changeset(policy, attrs) do
    policy
    |> cast(attrs, [
      :organization_id,
      :name,
      :description,
      :region_ids,
      :apply_to_unexpected,
      :apply_to_restricted,
      :require_mfa,
      :disable_features,
      :restrict_file_downloads,
      :restrict_file_uploads,
      :enhanced_monitoring,
      :auto_isolate,
      :send_alert,
      :alert_severity,
      :priority,
      :is_enabled
    ])
    |> validate_required([:organization_id, :name])
    |> validate_inclusion(:alert_severity, ~w(low medium high critical))
    |> foreign_key_constraint(:organization_id)
  end
end
