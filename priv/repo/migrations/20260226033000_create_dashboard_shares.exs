defmodule TamanduaServer.Repo.Migrations.CreateDashboardShares do
  use Ecto.Migration

  def change do
    # Dashboard shares table for public sharing
    create table(:dashboard_shares, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :share_token, :string, null: false # UUID for public URL
      add :dashboard_layout_id, references(:dashboard_layouts, on_delete: :delete_all, type: :binary_id), null: false
      add :created_by_user_id, references(:users, on_delete: :nilify_all, type: :binary_id)

      # Access control
      add :is_active, :boolean, default: true
      add :password_hash, :string # Optional password protection
      add :expires_at, :utc_datetime_usec # Optional expiration
      add :allowed_ips, {:array, :string}, default: [] # IP whitelist
      add :allowed_domains, {:array, :string}, default: [] # Domain whitelist (for embedding)

      # Sharing scope
      add :share_type, :string, null: false # "full_dashboard", "specific_widgets"
      add :widget_ids, {:array, :binary_id}, default: [] # If share_type is "specific_widgets"

      # Customization
      add :custom_title, :string # Override dashboard title
      add :show_header, :boolean, default: false
      add :show_footer, :boolean, default: true
      add :show_watermark, :boolean, default: true
      add :branding_config, :map, default: %{} # Custom logo, colors
      add :refresh_interval, :integer, default: 30000 # Auto-refresh interval in ms

      # Embed options
      add :embed_width, :string, default: "100%" # e.g., "100%", "800px"
      add :embed_height, :string, default: "600px"
      add :transparent_background, :boolean, default: false

      # Metadata
      add :description, :text
      add :last_accessed_at, :utc_datetime_usec
      add :revoked_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:dashboard_shares, [:share_token])
    create index(:dashboard_shares, [:dashboard_layout_id])
    create index(:dashboard_shares, [:created_by_user_id])
    create index(:dashboard_shares, [:is_active])
    create index(:dashboard_shares, [:expires_at])

    # Dashboard share views (analytics)
    create table(:dashboard_share_views, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :dashboard_share_id, references(:dashboard_shares, on_delete: :delete_all, type: :binary_id), null: false
      add :viewed_at, :utc_datetime_usec, null: false
      add :ip_address, :string
      add :user_agent, :string
      add :referrer, :string
      add :country, :string # Geographic data
      add :city, :string
      add :session_id, :string # For unique visitor tracking
      add :duration_seconds, :integer # How long they stayed

      timestamps(type: :utc_datetime_usec)
    end

    create index(:dashboard_share_views, [:dashboard_share_id])
    create index(:dashboard_share_views, [:viewed_at])
    create index(:dashboard_share_views, [:session_id])
    create index(:dashboard_share_views, [:country])
  end
end
