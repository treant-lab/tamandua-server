defmodule TamanduaServer.Repo.Migrations.CreateBrandingTables do
  use Ecto.Migration

  def change do
    # Branding configuration table
    create_if_not_exists table(:branding_configs, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      # Logos
      add :logo_url, :string
      add :favicon_url, :string
      add :email_header_logo_url, :string
      add :login_background_url, :string

      # Branding
      add :company_name, :string
      add :color_scheme, :map, default: %{}
      add :color_preset, :string

      # Custom domain
      add :custom_domain, :string
      add :domain_status, :string  # pending_verification, verified, failed, expired
      add :domain_verification_token, :string
      add :domain_ssl_certificate, :text
      add :domain_ssl_key_encrypted, :text

      # Login page customization
      add :login_page_config, :map, default: %{}

      # Footer and support
      add :footer_text, :string
      add :support_email, :string
      add :support_url, :string

      # Advanced settings
      add :custom_css, :text
      add :custom_js, :text
      add :meta_tags, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists unique_index(:branding_configs, [:organization_id])
    create_if_not_exists unique_index(:branding_configs, [:custom_domain], where: "custom_domain IS NOT NULL")

    # Email templates table
    create_if_not_exists table(:email_templates, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :template_type, :string, null: false
      add :name, :string
      add :subject, :string, null: false
      add :body_html, :text, null: false
      add :body_text, :text
      add :is_active, :boolean, default: true, null: false

      # Template metadata
      add :description, :text
      add :available_variables, {:array, :string}, default: []

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists unique_index(:email_templates, [:organization_id, :template_type])
    create_if_not_exists index(:email_templates, [:organization_id])
    create_if_not_exists index(:email_templates, [:template_type])
  end
end
