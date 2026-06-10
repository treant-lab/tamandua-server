defmodule TamanduaServer.Branding.BrandingConfig do
  @moduledoc """
  Schema for white-label branding configuration.

  Each organization can have custom branding including:
  - Logos (primary, favicon, email header)
  - Color schemes
  - Custom domains
  - Login page customization
  - Footer text
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @domain_statuses [:pending_verification, :verified, :failed, :expired]

  @derive {Jason.Encoder, only: [
    :id, :organization_id, :logo_url, :favicon_url, :email_header_logo_url,
    :login_background_url, :company_name, :color_scheme, :color_preset,
    :custom_domain, :domain_status, :login_page_config, :footer_text,
    :support_email, :inserted_at, :updated_at
  ]}

  schema "branding_configs" do
    belongs_to :organization, Organization

    # Logos
    field :logo_url, :string
    field :favicon_url, :string
    field :email_header_logo_url, :string
    field :login_background_url, :string

    # Branding
    field :company_name, :string
    field :color_scheme, :map, default: %{}
    field :color_preset, :string

    # Custom domain
    field :custom_domain, :string
    field :domain_status, Ecto.Enum, values: @domain_statuses
    field :domain_verification_token, :string
    field :domain_ssl_certificate, :string
    field :domain_ssl_key_encrypted, :string

    # Login page customization
    field :login_page_config, :map, default: %{}

    # Footer and support
    field :footer_text, :string
    field :support_email, :string
    field :support_url, :string

    # Advanced settings
    field :custom_css, :string
    field :custom_js, :string
    field :meta_tags, :map, default: %{}

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(organization_id)a
  @optional_fields ~w(
    logo_url favicon_url email_header_logo_url login_background_url
    company_name color_scheme color_preset
    custom_domain domain_status domain_verification_token
    domain_ssl_certificate domain_ssl_key_encrypted
    login_page_config footer_text support_email support_url
    custom_css custom_js meta_tags
  )a

  @doc """
  Changeset for creating or updating branding configuration.
  """
  def changeset(config, attrs) do
    config
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_length(:company_name, max: 255)
    |> validate_length(:custom_domain, max: 255)
    |> validate_format(:support_email, ~r/@/, message: "must be a valid email")
    |> validate_custom_domain()
    |> validate_color_scheme()
    |> unique_constraint(:organization_id)
    |> unique_constraint(:custom_domain)
    |> foreign_key_constraint(:organization_id)
  end

  defp validate_custom_domain(changeset) do
    case get_change(changeset, :custom_domain) do
      nil ->
        changeset

      domain ->
        if valid_domain_format?(domain) do
          changeset
        else
          add_error(changeset, :custom_domain, "is not a valid domain format")
        end
    end
  end

  defp valid_domain_format?(domain) when is_binary(domain) do
    Regex.match?(~r/^[a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9][a-zA-Z0-9-]*)+$/, domain)
  end

  defp valid_domain_format?(_), do: false

  defp validate_color_scheme(changeset) do
    case get_change(changeset, :color_scheme) do
      nil ->
        changeset

      colors when is_map(colors) ->
        invalid_colors = colors
        |> Enum.filter(fn {_key, value} -> not valid_hex_color?(value) end)
        |> Enum.map(fn {key, _} -> key end)

        if Enum.empty?(invalid_colors) do
          changeset
        else
          add_error(changeset, :color_scheme, "contains invalid hex colors: #{Enum.join(invalid_colors, ", ")}")
        end

      _ ->
        add_error(changeset, :color_scheme, "must be a map of color names to hex values")
    end
  end

  defp valid_hex_color?(color) when is_binary(color) do
    Regex.match?(~r/^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$/, color)
  end

  defp valid_hex_color?(_), do: false

  @doc """
  Returns the list of valid domain statuses.
  """
  def domain_statuses, do: @domain_statuses
end
