defmodule TamanduaServer.ThreatIntel.TaxiiServer do
  @moduledoc """
  Schema for TAXII 2.1 server configuration.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "taxii_servers" do
    field :name, :string
    field :url, :string
    field :description, :string

    # Authentication
    field :auth_type, :string  # basic, api_key, bearer
    field :auth_config, :map, default: %{}

    # Discovery
    field :api_roots, {:array, :string}, default: []
    field :default_api_root, :string

    # Sync config
    field :poll_enabled, :boolean, default: true
    field :poll_interval_minutes, :integer, default: 60
    field :auto_import, :boolean, default: true

    # Status
    field :last_poll_at, :utc_datetime
    field :last_success_at, :utc_datetime
    field :last_error, :string
    field :status, :string, default: "pending"

    # Stats
    field :total_polls, :integer, default: 0
    field :total_objects_imported, :integer, default: 0
    field :total_errors, :integer, default: 0

    field :enabled, :boolean, default: true

    has_many :collections, TamanduaServer.ThreatIntel.TaxiiCollection

    timestamps()
  end

  @doc false
  def changeset(server, attrs) do
    server
    |> cast(attrs, [
      :name, :url, :description, :auth_type, :auth_config,
      :poll_enabled, :poll_interval_minutes, :auto_import,
      :enabled, :api_roots, :default_api_root
    ])
    |> validate_required([:name, :url])
    |> validate_url(:url)
    |> validate_inclusion(:auth_type, ["basic", "api_key", "bearer", nil])
    |> validate_number(:poll_interval_minutes, greater_than: 0)
    |> unique_constraint(:url)
  end

  defp validate_url(changeset, field) do
    validate_change(changeset, field, fn _, url ->
      uri = URI.parse(url)
      if uri.scheme in ["http", "https"] and uri.host do
        []
      else
        [{field, "must be a valid HTTP(S) URL"}]
      end
    end)
  end
end
