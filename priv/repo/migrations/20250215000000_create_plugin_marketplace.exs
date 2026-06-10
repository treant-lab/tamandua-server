defmodule TamanduaServer.Repo.Migrations.CreatePluginMarketplace do
  use Ecto.Migration

  def change do
    create table(:plugin_marketplace) do
      add :plugin_id, :string, null: false
      add :name, :string, null: false
      add :description, :text, null: false
      add :author, :string, null: false
      add :version, :string, null: false
      add :plugin_type, :string, null: false
      add :api_version, :string, null: false

      # Metadata
      add :homepage_url, :string
      add :repository_url, :string
      add :documentation_url, :string
      add :license, :string
      add :tags, {:array, :string}, default: []

      # Distribution
      add :wasm_url, :string, null: false
      add :signature_url, :string, null: false
      add :public_key, :string, null: false
      add :checksum_sha256, :string, null: false

      # Dependencies
      add :dependencies, {:array, :string}, default: []
      add :required_capabilities, {:array, :string}, default: []

      # Metrics
      add :download_count, :integer, default: 0
      add :rating_average, :float, default: 0.0
      add :rating_count, :integer, default: 0

      # Security
      add :security_scan_status, :string
      add :security_scan_results, :map
      add :verified, :boolean, default: false

      # Status
      add :published, :boolean, default: false
      add :deprecated, :boolean, default: false

      timestamps()
    end

    create unique_index(:plugin_marketplace, [:plugin_id, :version])
    create index(:plugin_marketplace, [:plugin_type])
    create index(:plugin_marketplace, [:published])
    create index(:plugin_marketplace, [:tags], using: :gin)
    create index(:plugin_marketplace, [:download_count])
    create index(:plugin_marketplace, [:rating_average])

    # Plugin reviews table
    create table(:plugin_reviews) do
      add :plugin_marketplace_id, references(:plugin_marketplace, on_delete: :delete_all), null: false
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :rating, :integer, null: false
      add :review_text, :text
      add :verified_purchase, :boolean, default: false
      add :helpful_count, :integer, default: 0

      timestamps()
    end

    create index(:plugin_reviews, [:plugin_marketplace_id])
    create index(:plugin_reviews, [:user_id])
    create unique_index(:plugin_reviews, [:plugin_marketplace_id, :user_id])

    # Plugin downloads tracking
    create table(:plugin_downloads) do
      add :plugin_marketplace_id, references(:plugin_marketplace, on_delete: :delete_all), null: false
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all)
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all)
      add :ip_address, :string
      add :user_agent, :string
      add :downloaded_at, :utc_datetime, null: false

      timestamps()
    end

    create index(:plugin_downloads, [:plugin_marketplace_id])
    create index(:plugin_downloads, [:agent_id])
    create index(:plugin_downloads, [:downloaded_at])

    # Plugin security scans
    create table(:plugin_security_scans) do
      add :plugin_marketplace_id, references(:plugin_marketplace, on_delete: :delete_all), null: false
      add :scan_type, :string, null: false
      add :status, :string, null: false
      add :findings, {:array, :map}, default: []
      add :severity, :string
      add :scanned_at, :utc_datetime, null: false

      timestamps()
    end

    create index(:plugin_security_scans, [:plugin_marketplace_id])
    create index(:plugin_security_scans, [:status])
    create index(:plugin_security_scans, [:scanned_at])
  end
end
