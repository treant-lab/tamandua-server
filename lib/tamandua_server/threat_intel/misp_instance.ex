defmodule TamanduaServer.ThreatIntel.MISPInstance do
  @moduledoc """
  Ecto schema for MISP instance configuration.

  Stores connection details for MISP servers including:
  - URL: Base URL of the MISP instance
  - API Key: Authentication key (encrypted at rest)
  - Organization: MISP organization ID for publishing
  - Sharing Groups: Allowed sharing group IDs
  - Trust Level: Priority weighting for IOCs from this instance
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "misp_instances" do
    field :name, :string
    field :url, :string
    field :api_key, :string
    field :verify_ssl, :boolean, default: true
    field :enabled, :boolean, default: true

    # MISP organization config
    field :misp_org_id, :string
    field :misp_org_name, :string

    # Sharing configuration
    field :sharing_group_ids, {:array, :integer}, default: []
    field :pull_enabled, :boolean, default: true
    field :push_enabled, :boolean, default: false

    # Trust and priority
    field :trust_level, :integer, default: 50  # 0-100, higher = more trusted
    field :priority, :integer, default: 0      # Sync order priority

    # Sync configuration
    field :sync_interval_hours, :integer, default: 4
    field :last_sync, :utc_datetime
    field :last_sync_status, :string
    field :last_sync_error, :string
    field :events_synced, :integer, default: 0
    field :iocs_imported, :integer, default: 0

    # Filter configuration
    field :tags_filter, {:array, :string}, default: []  # Only sync events with these tags
    field :threat_level_filter, {:array, :integer}, default: []  # Only sync certain threat levels
    field :published_only, :boolean, default: true

    # Capabilities (detected from server)
    field :server_version, :string
    field :can_publish, :boolean, default: false
    field :can_sighting, :boolean, default: false

    belongs_to :organization, Organization

    timestamps()
  end

  @required_fields ~w(name url api_key)a
  @optional_fields ~w(
    verify_ssl enabled misp_org_id misp_org_name sharing_group_ids
    pull_enabled push_enabled trust_level priority sync_interval_hours
    last_sync last_sync_status last_sync_error events_synced iocs_imported
    tags_filter threat_level_filter published_only
    server_version can_publish can_sighting organization_id
  )a

  @doc false
  def changeset(instance, attrs) do
    instance
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_url(:url)
    |> validate_number(:trust_level, greater_than_or_equal_to: 0, less_than_or_equal_to: 100)
    |> validate_number(:sync_interval_hours, greater_than: 0, less_than_or_equal_to: 168)
    |> unique_constraint(:url, name: :misp_instances_url_org_index)
    |> unique_constraint(:name, name: :misp_instances_name_org_index)
    |> foreign_key_constraint(:organization_id)
  end

  defp validate_url(changeset, field) do
    validate_change(changeset, field, fn _, value ->
      uri = URI.parse(value)

      cond do
        uri.scheme not in ["http", "https"] ->
          [{field, "must be a valid HTTP(S) URL"}]

        is_nil(uri.host) or uri.host == "" ->
          [{field, "must include a host"}]

        true ->
          []
      end
    end)
  end
end
