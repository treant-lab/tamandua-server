defmodule TamanduaServer.Plugins.Marketplace do
  @moduledoc """
  Plugin Marketplace - Repository for third-party plugins

  Provides plugin discovery, distribution, and management capabilities.

  ## Features

  - Plugin repository with metadata
  - Version management and dependency tracking
  - Plugin ratings and reviews
  - Download statistics
  - Security scanning integration
  - Plugin update notifications
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query
  alias TamanduaServer.Repo

  @type t :: %__MODULE__{}

  schema "plugin_marketplace" do
    field :plugin_id, :string
    field :name, :string
    field :description, :string
    field :author, :string
    field :version, :string
    field :plugin_type, :string
    field :api_version, :string

    # Metadata
    field :homepage_url, :string
    field :repository_url, :string
    field :documentation_url, :string
    field :license, :string
    field :tags, {:array, :string}

    # Distribution
    field :wasm_url, :string
    field :signature_url, :string
    field :public_key, :string
    field :checksum_sha256, :string

    # Dependencies
    field :dependencies, {:array, :string}
    field :required_capabilities, {:array, :string}

    # Metrics
    field :download_count, :integer, default: 0
    field :rating_average, :float, default: 0.0
    field :rating_count, :integer, default: 0

    # Security
    field :security_scan_status, :string
    field :security_scan_results, :map
    field :verified, :boolean, default: false

    # Status
    field :published, :boolean, default: false
    field :deprecated, :boolean, default: false

    timestamps()
  end

  @doc """
  Changeset for creating/updating marketplace entries
  """
  def changeset(marketplace, attrs) do
    marketplace
    |> cast(attrs, [
      :plugin_id,
      :name,
      :description,
      :author,
      :version,
      :plugin_type,
      :api_version,
      :homepage_url,
      :repository_url,
      :documentation_url,
      :license,
      :tags,
      :wasm_url,
      :signature_url,
      :public_key,
      :checksum_sha256,
      :dependencies,
      :required_capabilities,
      :download_count,
      :rating_average,
      :rating_count,
      :security_scan_status,
      :security_scan_results,
      :verified,
      :published,
      :deprecated
    ])
    |> validate_required([
      :plugin_id,
      :name,
      :description,
      :author,
      :version,
      :plugin_type,
      :api_version,
      :wasm_url,
      :signature_url,
      :public_key,
      :checksum_sha256
    ])
    |> validate_inclusion(:plugin_type, ["collector", "analyzer", "response"])
    |> unique_constraint([:plugin_id, :version])
  end

  @doc """
  List all published plugins
  """
  def list_plugins do
    __MODULE__
    |> where([p], p.published == true and p.deprecated == false)
    |> order_by([p], desc: p.download_count)
    |> Repo.all()
  end

  @doc """
  Search plugins by query
  """
  def search_plugins(query) do
    pattern = "%#{query}%"

    __MODULE__
    |> where([p], p.published == true and p.deprecated == false)
    |> where(
      [p],
      ilike(p.name, ^pattern) or
        ilike(p.description, ^pattern) or
        ^query in p.tags
    )
    |> order_by([p], desc: p.rating_average)
    |> Repo.all()
  end

  @doc """
  Get plugin by ID and version
  """
  def get_plugin(plugin_id, version) do
    __MODULE__
    |> where([p], p.plugin_id == ^plugin_id and p.version == ^version)
    |> Repo.one()
  end

  @doc """
  Get latest version of plugin
  """
  def get_latest_version(plugin_id) do
    __MODULE__
    |> where([p], p.plugin_id == ^plugin_id and p.published == true)
    |> order_by([p], desc: p.version)
    |> limit(1)
    |> Repo.one()
  end

  @doc """
  Increment download count
  """
  def increment_downloads(plugin_id, version) do
    with {:ok, plugin} <- get_plugin(plugin_id, version) do
      plugin
      |> changeset(%{download_count: plugin.download_count + 1})
      |> Repo.update()
    end
  end

  @doc """
  Add rating to plugin
  """
  def add_rating(plugin_id, version, rating) when rating >= 1 and rating <= 5 do
    with {:ok, plugin} <- get_plugin(plugin_id, version) do
      new_count = plugin.rating_count + 1
      new_average = (plugin.rating_average * plugin.rating_count + rating) / new_count

      plugin
      |> changeset(%{
        rating_count: new_count,
        rating_average: new_average
      })
      |> Repo.update()
    end
  end

  @doc """
  Submit plugin for review
  """
  def submit_plugin(attrs) do
    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Publish plugin (after review)
  """
  def publish_plugin(plugin_id, version) do
    with {:ok, plugin} <- get_plugin(plugin_id, version) do
      plugin
      |> changeset(%{published: true})
      |> Repo.update()
    end
  end

  @doc """
  Deprecate plugin
  """
  def deprecate_plugin(plugin_id, version) do
    with {:ok, plugin} <- get_plugin(plugin_id, version) do
      plugin
      |> changeset(%{deprecated: true})
      |> Repo.update()
    end
  end

  @doc """
  Update security scan results
  """
  def update_security_scan(plugin_id, version, status, results) do
    with {:ok, plugin} <- get_plugin(plugin_id, version) do
      plugin
      |> changeset(%{
        security_scan_status: status,
        security_scan_results: results
      })
      |> Repo.update()
    end
  end

  @doc """
  Verify plugin (mark as trusted)
  """
  def verify_plugin(plugin_id, version) do
    with {:ok, plugin} <- get_plugin(plugin_id, version) do
      plugin
      |> changeset(%{verified: true})
      |> Repo.update()
    end
  end
end
