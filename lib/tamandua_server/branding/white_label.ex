defmodule TamanduaServer.Branding.WhiteLabel do
  @moduledoc """
  White-labeling module for MSSP and enterprise deployments.

  Supports complete customization of the Tamandua platform including:

  - Custom logos (primary, favicon, email header)
  - Custom color schemes with CSS variable generation
  - Custom domain mapping with SSL support
  - Custom email templates
  - Custom login page branding
  - Custom dashboard themes

  ## Usage

      # Get branding for organization
      branding = WhiteLabel.get_branding(organization_id)

      # Update branding
      WhiteLabel.update_branding(organization_id, %{
        logo_url: "https://cdn.example.com/logo.png",
        primary_color: "#4F46E5"
      })

      # Generate CSS variables
      WhiteLabel.generate_css_variables(branding)
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Branding.{BrandingConfig, EmailTemplate}

  import Ecto.Query

  @cache_table :branding_cache
  @cache_ttl_seconds 300
  @default_primary_color "#4F46E5"
  @default_accent_color "#06B6D4"

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get branding configuration for an organization.

  Returns the organization's custom branding or falls back to defaults.
  """
  def get_branding(organization_id) when is_binary(organization_id) do
    case get_cached_branding(organization_id) do
      nil -> default_branding(organization_id)
      branding -> branding
    end
  end

  def get_branding(nil), do: default_branding(nil)

  @doc """
  Get branding by custom domain.
  """
  def get_branding_by_domain(domain) when is_binary(domain) do
    case Repo.one(from b in BrandingConfig, where: b.custom_domain == ^domain, limit: 1) do
      nil -> nil
      branding -> branding
    end
  end

  @doc """
  Update branding configuration for an organization.
  """
  def update_branding(organization_id, attrs) do
    branding = get_or_create_branding(organization_id)

    branding
    |> BrandingConfig.changeset(attrs)
    |> Repo.update()
    |> case do
      {:ok, updated} ->
        invalidate_cache(organization_id)
        {:ok, updated}

      error ->
        error
    end
  end

  @doc """
  Upload a logo for an organization.

  Supported types: :primary, :favicon, :email_header, :login_background
  """
  def upload_logo(organization_id, type, %Plug.Upload{} = upload) do
    # Validate file type
    allowed_types = ~w(image/png image/jpeg image/gif image/svg+xml image/webp)

    unless upload.content_type in allowed_types do
      {:error, :invalid_file_type}
    else
      # Generate storage path
      ext = Path.extname(upload.filename)
      filename = "#{organization_id}_#{type}#{ext}"
      storage_path = Path.join(["uploads", "branding", filename])

      # Ensure directory exists
      File.mkdir_p!(Path.dirname(storage_path))

      # Copy file
      File.cp!(upload.path, storage_path)

      # Update branding config with logo URL
      logo_field = logo_field_for_type(type)
      url = "/uploads/branding/#{filename}"

      update_branding(organization_id, %{logo_field => url})
    end
  end

  @doc """
  Delete a logo for an organization.
  """
  def delete_logo(organization_id, type) do
    branding = get_branding(organization_id)
    logo_field = logo_field_for_type(type)
    current_url = Map.get(branding, logo_field)

    if current_url do
      # Delete file if it exists
      path = Path.join("priv/static", current_url)
      File.rm(path)

      # Update branding
      update_branding(organization_id, %{logo_field => nil})
    else
      {:ok, branding}
    end
  end

  @doc """
  Generate CSS variables from branding configuration.

  Returns a string of CSS custom properties that can be injected into the page.
  """
  def generate_css_variables(branding) do
    colors = branding.color_scheme || %{}

    """
    :root {
      --brand-primary: #{colors["primary"] || @default_primary_color};
      --brand-primary-hover: #{darken_color(colors["primary"] || @default_primary_color, 10)};
      --brand-primary-light: #{lighten_color(colors["primary"] || @default_primary_color, 40)};
      --brand-accent: #{colors["accent"] || @default_accent_color};
      --brand-accent-hover: #{darken_color(colors["accent"] || @default_accent_color, 10)};
      --brand-background: #{colors["background"] || "#0F172A"};
      --brand-surface: #{colors["surface"] || "#1E293B"};
      --brand-surface-hover: #{colors["surface_hover"] || "#334155"};
      --brand-text: #{colors["text"] || "#F8FAFC"};
      --brand-text-secondary: #{colors["text_secondary"] || "#94A3B8"};
      --brand-border: #{colors["border"] || "#334155"};
      --brand-success: #{colors["success"] || "#22C55E"};
      --brand-warning: #{colors["warning"] || "#EAB308"};
      --brand-error: #{colors["error"] || "#EF4444"};
      --brand-info: #{colors["info"] || "#3B82F6"};
    }
    """
  end

  @doc """
  Get available color presets.
  """
  def color_presets do
    %{
      "default" => %{
        "name" => "Default",
        "primary" => "#4F46E5",
        "accent" => "#06B6D4",
        "background" => "#0F172A",
        "surface" => "#1E293B"
      },
      "corporate_blue" => %{
        "name" => "Corporate Blue",
        "primary" => "#2563EB",
        "accent" => "#0EA5E9",
        "background" => "#0C1222",
        "surface" => "#1A2744"
      },
      "forest_green" => %{
        "name" => "Forest Green",
        "primary" => "#059669",
        "accent" => "#14B8A6",
        "background" => "#0A1510",
        "surface" => "#132D1B"
      },
      "royal_purple" => %{
        "name" => "Royal Purple",
        "primary" => "#7C3AED",
        "accent" => "#A855F7",
        "background" => "#120B1F",
        "surface" => "#1F1535"
      },
      "crimson_red" => %{
        "name" => "Crimson Red",
        "primary" => "#DC2626",
        "accent" => "#F97316",
        "background" => "#1A0A0A",
        "surface" => "#2D1515"
      },
      "midnight" => %{
        "name" => "Midnight",
        "primary" => "#6366F1",
        "accent" => "#8B5CF6",
        "background" => "#030712",
        "surface" => "#111827"
      },
      "light_mode" => %{
        "name" => "Light Mode",
        "primary" => "#4F46E5",
        "accent" => "#0891B2",
        "background" => "#F8FAFC",
        "surface" => "#FFFFFF",
        "text" => "#0F172A",
        "text_secondary" => "#475569",
        "border" => "#E2E8F0"
      }
    }
  end

  @doc """
  Apply a color preset to an organization.
  """
  def apply_color_preset(organization_id, preset_name) do
    case Map.get(color_presets(), preset_name) do
      nil ->
        {:error, :invalid_preset}

      preset ->
        color_scheme = Map.drop(preset, ["name"])
        update_branding(organization_id, %{color_scheme: color_scheme, color_preset: preset_name})
    end
  end

  @doc """
  Set custom domain for an organization.

  This requires DNS validation and SSL certificate provisioning.
  """
  def set_custom_domain(organization_id, domain) do
    # Validate domain format
    unless valid_domain?(domain) do
      {:error, :invalid_domain}
    else
      # Check if domain is already in use
      existing = Repo.one(from b in BrandingConfig,
        where: b.custom_domain == ^domain and b.organization_id != ^organization_id,
        limit: 1
      )

      if existing do
        {:error, :domain_in_use}
      else
        update_branding(organization_id, %{
          custom_domain: domain,
          domain_status: :pending_verification
        })
      end
    end
  end

  @doc """
  Verify custom domain ownership via DNS TXT record.
  """
  def verify_custom_domain(organization_id) do
    branding = get_branding(organization_id)

    unless branding.custom_domain do
      {:error, :no_domain_set}
    else
      verification_token = branding.domain_verification_token ||
        generate_verification_token(organization_id)

      # Check DNS for verification record
      expected_record = "_tamandua-verify.#{branding.custom_domain}"

      case :inet_res.lookup(String.to_charlist(expected_record), :in, :txt) do
        [[^verification_token | _] | _] ->
          update_branding(organization_id, %{domain_status: :verified})
          {:ok, :verified}

        _ ->
          update_branding(organization_id, %{domain_verification_token: verification_token})
          {:pending, verification_token}
      end
    end
  end

  @doc """
  Get or create email template for organization.
  """
  def get_email_template(organization_id, template_type) do
    case Repo.one(from t in EmailTemplate,
      where: t.organization_id == ^organization_id and t.template_type == ^template_type,
      limit: 1
    ) do
      nil -> default_email_template(template_type)
      template -> template
    end
  end

  @doc """
  Update email template for organization.
  """
  def update_email_template(organization_id, template_type, attrs) do
    template = get_or_create_email_template(organization_id, template_type)

    template
    |> EmailTemplate.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Render email template with variables.
  """
  def render_email_template(organization_id, template_type, variables) do
    template = get_email_template(organization_id, template_type)
    branding = get_branding(organization_id)

    # Merge branding variables
    all_variables = Map.merge(variables, %{
      "logo_url" => branding.logo_url || default_logo_url(),
      "company_name" => branding.company_name || "Tamandua EDR",
      "primary_color" => branding.color_scheme["primary"] || @default_primary_color,
      "support_email" => branding.support_email || "contato@treantlab.org"
    })

    # Render subject and body
    subject = render_template_string(template.subject, all_variables)
    body = render_template_string(template.body_html, all_variables)
    plain_text = render_template_string(template.body_text, all_variables)

    %{
      subject: subject,
      html_body: body,
      text_body: plain_text
    }
  end

  @doc """
  List all email templates for an organization.
  """
  def list_email_templates(organization_id) do
    from(t in EmailTemplate,
      where: t.organization_id == ^organization_id,
      order_by: [asc: t.template_type]
    )
    |> Repo.all()
  end

  @doc """
  Reset branding to defaults.
  """
  def reset_branding(organization_id) do
    case Repo.get_by(BrandingConfig, organization_id: organization_id) do
      nil ->
        {:ok, default_branding(organization_id)}

      branding ->
        Repo.delete(branding)
        invalidate_cache(organization_id)
        {:ok, default_branding(organization_id)}
    end
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    :ets.new(@cache_table, [:set, :public, :named_table, read_concurrency: true])

    # Schedule periodic cache cleanup
    :timer.send_interval(60_000, :cleanup_expired)

    Logger.info("White-label branding service started")
    {:ok, %{}}
  end

  @impl true
  def handle_cast({:invalidate, org_id}, state) do
    :ets.delete(@cache_table, org_id)
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup_expired, state) do
    now = System.system_time(:second)

    expired = :ets.foldl(
      fn
        {key, _data, cached_at}, acc when is_integer(cached_at) ->
          if now - cached_at > @cache_ttl_seconds, do: [key | acc], else: acc
        _, acc ->
          acc
      end,
      [],
      @cache_table
    )

    Enum.each(expired, &:ets.delete(@cache_table, &1))

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp get_cached_branding(organization_id) do
    case :ets.lookup(@cache_table, organization_id) do
      [{^organization_id, branding, cached_at}] ->
        if System.system_time(:second) - cached_at < @cache_ttl_seconds do
          branding
        else
          load_and_cache_branding(organization_id)
        end

      [] ->
        load_and_cache_branding(organization_id)
    end
  end

  defp load_and_cache_branding(organization_id) do
    case Repo.get_by(BrandingConfig, organization_id: organization_id) do
      nil ->
        nil

      branding ->
        :ets.insert(@cache_table, {organization_id, branding, System.system_time(:second)})
        branding
    end
  end

  defp invalidate_cache(organization_id) do
    GenServer.cast(__MODULE__, {:invalidate, organization_id})
  end

  defp get_or_create_branding(organization_id) do
    case Repo.get_by(BrandingConfig, organization_id: organization_id) do
      nil ->
        {:ok, branding} = %BrandingConfig{}
        |> BrandingConfig.changeset(%{organization_id: organization_id})
        |> Repo.insert()
        branding

      branding ->
        branding
    end
  end

  defp get_or_create_email_template(organization_id, template_type) do
    case Repo.one(from t in EmailTemplate,
      where: t.organization_id == ^organization_id and t.template_type == ^template_type,
      limit: 1
    ) do
      nil ->
        default = default_email_template(template_type)
        {:ok, template} = %EmailTemplate{}
        |> EmailTemplate.changeset(%{
          organization_id: organization_id,
          template_type: template_type,
          subject: default.subject,
          body_html: default.body_html,
          body_text: default.body_text
        })
        |> Repo.insert()
        template

      template ->
        template
    end
  end

  defp default_branding(organization_id) do
    %BrandingConfig{
      organization_id: organization_id,
      logo_url: nil,
      favicon_url: nil,
      company_name: "Tamandua EDR",
      color_scheme: %{
        "primary" => @default_primary_color,
        "accent" => @default_accent_color,
        "background" => "#0F172A",
        "surface" => "#1E293B"
      },
      color_preset: "default",
      custom_domain: nil,
      domain_status: nil,
      login_page_config: %{
        "show_logo" => true,
        "show_company_name" => true,
        "background_style" => "gradient"
      },
      footer_text: nil,
      support_email: nil
    }
  end

  defp default_email_template(:welcome) do
    %{
      subject: "Welcome to {{company_name}}",
      body_html: """
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { text-align: center; margin-bottom: 30px; }
          .logo { max-width: 200px; }
          .button { display: inline-block; padding: 12px 24px; background: {{primary_color}}; color: #fff; text-decoration: none; border-radius: 6px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <img src="{{logo_url}}" alt="{{company_name}}" class="logo">
          </div>
          <h1>Welcome to {{company_name}}!</h1>
          <p>Hello {{user_name}},</p>
          <p>Your account has been created successfully. You can now access the security dashboard.</p>
          <p><a href="{{login_url}}" class="button">Login to Dashboard</a></p>
          <p>If you have any questions, please contact us at {{support_email}}.</p>
        </div>
      </body>
      </html>
      """,
      body_text: """
      Welcome to {{company_name}}!

      Hello {{user_name}},

      Your account has been created successfully. You can now access the security dashboard.

      Login at: {{login_url}}

      If you have any questions, please contact us at {{support_email}}.
      """
    }
  end

  defp default_email_template(:alert_notification) do
    %{
      subject: "[{{severity}}] Security Alert: {{alert_title}}",
      body_html: """
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { text-align: center; margin-bottom: 30px; }
          .logo { max-width: 150px; }
          .alert-box { border-left: 4px solid {{severity_color}}; background: #f8f9fa; padding: 15px; margin: 20px 0; }
          .button { display: inline-block; padding: 12px 24px; background: {{primary_color}}; color: #fff; text-decoration: none; border-radius: 6px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <img src="{{logo_url}}" alt="{{company_name}}" class="logo">
          </div>
          <h2>Security Alert</h2>
          <div class="alert-box">
            <strong>{{alert_title}}</strong>
            <p>Severity: {{severity}}</p>
            <p>Agent: {{agent_hostname}}</p>
            <p>Time: {{alert_time}}</p>
          </div>
          <p>{{alert_description}}</p>
          <p><a href="{{alert_url}}" class="button">View Alert Details</a></p>
        </div>
      </body>
      </html>
      """,
      body_text: """
      Security Alert from {{company_name}}

      Title: {{alert_title}}
      Severity: {{severity}}
      Agent: {{agent_hostname}}
      Time: {{alert_time}}

      {{alert_description}}

      View details: {{alert_url}}
      """
    }
  end

  defp default_email_template(:password_reset) do
    %{
      subject: "Reset your {{company_name}} password",
      body_html: """
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { text-align: center; margin-bottom: 30px; }
          .logo { max-width: 150px; }
          .button { display: inline-block; padding: 12px 24px; background: {{primary_color}}; color: #fff; text-decoration: none; border-radius: 6px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <img src="{{logo_url}}" alt="{{company_name}}" class="logo">
          </div>
          <h2>Password Reset Request</h2>
          <p>Hello {{user_name}},</p>
          <p>We received a request to reset your password. Click the button below to set a new password.</p>
          <p><a href="{{reset_url}}" class="button">Reset Password</a></p>
          <p>This link will expire in 24 hours.</p>
          <p>If you didn't request this, please ignore this email or contact support.</p>
        </div>
      </body>
      </html>
      """,
      body_text: """
      Password Reset Request

      Hello {{user_name}},

      We received a request to reset your password.

      Reset your password: {{reset_url}}

      This link will expire in 24 hours.

      If you didn't request this, please ignore this email or contact support.
      """
    }
  end

  defp default_email_template(:mfa_setup) do
    %{
      subject: "Set up two-factor authentication for {{company_name}}",
      body_html: """
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { text-align: center; margin-bottom: 30px; }
          .logo { max-width: 150px; }
          .button { display: inline-block; padding: 12px 24px; background: {{primary_color}}; color: #fff; text-decoration: none; border-radius: 6px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <img src="{{logo_url}}" alt="{{company_name}}" class="logo">
          </div>
          <h2>Set Up Two-Factor Authentication</h2>
          <p>Hello {{user_name}},</p>
          <p>Two-factor authentication adds an extra layer of security to your account.</p>
          <p><a href="{{setup_url}}" class="button">Set Up 2FA</a></p>
        </div>
      </body>
      </html>
      """,
      body_text: """
      Set Up Two-Factor Authentication

      Hello {{user_name}},

      Two-factor authentication adds an extra layer of security to your account.

      Set up 2FA: {{setup_url}}
      """
    }
  end

  defp default_email_template(_), do: default_email_template(:welcome)

  defp render_template_string(template, variables) when is_binary(template) do
    Enum.reduce(variables, template, fn {key, value}, acc ->
      String.replace(acc, "{{#{key}}}", to_string(value))
    end)
  end

  defp render_template_string(nil, _variables), do: ""

  defp logo_field_for_type(:primary), do: :logo_url
  defp logo_field_for_type(:favicon), do: :favicon_url
  defp logo_field_for_type(:email_header), do: :email_header_logo_url
  defp logo_field_for_type(:login_background), do: :login_background_url
  defp logo_field_for_type(_), do: :logo_url

  defp default_logo_url do
    "/images/tamandua-logo.svg"
  end

  defp valid_domain?(domain) when is_binary(domain) do
    # Basic domain validation
    Regex.match?(~r/^[a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9][a-zA-Z0-9-]*)+$/, domain)
  end

  defp valid_domain?(_), do: false

  defp generate_verification_token(organization_id) do
    :crypto.hash(:sha256, "#{organization_id}#{System.system_time()}")
    |> Base.encode16(case: :lower)
    |> String.slice(0, 32)
  end

  # Color manipulation functions
  defp darken_color(hex, percent) do
    manipulate_color(hex, -percent)
  end

  defp lighten_color(hex, percent) do
    manipulate_color(hex, percent)
  end

  defp manipulate_color(hex, percent) do
    hex = String.replace(hex, "#", "")

    {r, g, b} = case String.length(hex) do
      6 ->
        {
          String.slice(hex, 0, 2) |> String.to_integer(16),
          String.slice(hex, 2, 2) |> String.to_integer(16),
          String.slice(hex, 4, 2) |> String.to_integer(16)
        }
      3 ->
        {
          String.slice(hex, 0, 1) |> String.duplicate(2) |> String.to_integer(16),
          String.slice(hex, 1, 1) |> String.duplicate(2) |> String.to_integer(16),
          String.slice(hex, 2, 1) |> String.duplicate(2) |> String.to_integer(16)
        }
      _ ->
        {79, 70, 229}  # Default indigo
    end

    adjust = fn val ->
      new_val = val + round(val * percent / 100)
      max(0, min(255, new_val))
    end

    r_hex = Integer.to_string(adjust.(r), 16) |> String.pad_leading(2, "0")
    g_hex = Integer.to_string(adjust.(g), 16) |> String.pad_leading(2, "0")
    b_hex = Integer.to_string(adjust.(b), 16) |> String.pad_leading(2, "0")
    "#" <> r_hex <> g_hex <> b_hex
  end
end
