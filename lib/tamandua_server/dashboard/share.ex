defmodule TamanduaServer.Dashboard.Share do
  @moduledoc """
  Schema for dashboard sharing.
  Enables public sharing of dashboards with access control and analytics.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @share_types ~w(full_dashboard specific_widgets)

  schema "dashboard_shares" do
    field :share_token, :string
    field :is_active, :boolean, default: true
    field :password_hash, :string
    field :expires_at, :utc_datetime_usec
    field :allowed_ips, {:array, :string}, default: []
    field :allowed_domains, {:array, :string}, default: []

    field :share_type, :string
    field :widget_ids, {:array, :binary_id}, default: []

    field :custom_title, :string
    field :show_header, :boolean, default: false
    field :show_footer, :boolean, default: true
    field :show_watermark, :boolean, default: true
    field :branding_config, :map, default: %{}
    field :refresh_interval, :integer, default: 30000

    field :embed_width, :string, default: "100%"
    field :embed_height, :string, default: "600px"
    field :transparent_background, :boolean, default: false

    field :description, :string
    field :last_accessed_at, :utc_datetime_usec
    field :revoked_at, :utc_datetime_usec

    # Virtual field for password (not stored)
    field :password, :string, virtual: true

    belongs_to :dashboard_layout, TamanduaServer.Dashboards.Layout
    belongs_to :created_by_user, TamanduaServer.Accounts.User

    has_many :views, TamanduaServer.Dashboard.ShareView, foreign_key: :dashboard_share_id

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(dashboard_layout_id share_type)a
  @optional_fields ~w(
    created_by_user_id share_token is_active password_hash expires_at
    allowed_ips allowed_domains widget_ids custom_title show_header
    show_footer show_watermark branding_config refresh_interval
    embed_width embed_height transparent_background description
    last_accessed_at revoked_at
  )a

  def changeset(share, attrs) do
    share
    |> cast(attrs, @required_fields ++ @optional_fields ++ [:password])
    |> validate_required(@required_fields)
    |> validate_inclusion(:share_type, @share_types)
    |> validate_number(:refresh_interval, greater_than_or_equal_to: 5000)
    |> validate_widget_ids()
    |> validate_expiry()
    |> put_share_token()
    |> hash_password()
    |> foreign_key_constraint(:dashboard_layout_id)
    |> foreign_key_constraint(:created_by_user_id)
    |> unique_constraint(:share_token)
  end

  defp validate_widget_ids(changeset) do
    share_type = get_field(changeset, :share_type)
    widget_ids = get_field(changeset, :widget_ids)

    if share_type == "specific_widgets" && Enum.empty?(widget_ids) do
      add_error(changeset, :widget_ids, "must specify at least one widget when share_type is specific_widgets")
    else
      changeset
    end
  end

  defp validate_expiry(changeset) do
    case get_change(changeset, :expires_at) do
      nil ->
        changeset

      expires_at ->
        if DateTime.compare(expires_at, DateTime.utc_now()) == :lt do
          add_error(changeset, :expires_at, "must be in the future")
        else
          changeset
        end
    end
  end

  defp put_share_token(changeset) do
    if get_field(changeset, :share_token) do
      changeset
    else
      put_change(changeset, :share_token, generate_share_token())
    end
  end

  defp hash_password(changeset) do
    case get_change(changeset, :password) do
      nil ->
        changeset

      password when byte_size(password) > 0 ->
        changeset
        |> put_change(:password_hash, Bcrypt.hash_pwd_salt(password))
        |> delete_change(:password)

      _ ->
        changeset
    end
  end

  @doc """
  Generates a unique share token (UUID).
  """
  def generate_share_token do
    Ecto.UUID.generate()
  end

  @doc """
  Verifies a password against the stored hash.
  """
  def verify_password(share, password) do
    if share.password_hash do
      Bcrypt.verify_pass(password, share.password_hash)
    else
      true
    end
  end

  @doc """
  Checks if a share is accessible (active, not expired, not revoked).
  """
  def accessible?(%__MODULE__{} = share) do
    share.is_active &&
      is_nil(share.revoked_at) &&
      (is_nil(share.expires_at) || DateTime.compare(share.expires_at, DateTime.utc_now()) == :gt)
  end

  @doc """
  Checks if an IP address is allowed to access the share.
  """
  def ip_allowed?(%__MODULE__{} = share, ip_address) do
    if Enum.empty?(share.allowed_ips) do
      true
    else
      ip_address in share.allowed_ips
    end
  end

  @doc """
  Checks if a domain is allowed to embed the share.
  """
  def domain_allowed?(%__MODULE__{} = share, domain) do
    if Enum.empty?(share.allowed_domains) do
      true
    else
      # Check for exact match or wildcard match (e.g., "*.example.com")
      Enum.any?(share.allowed_domains, fn allowed ->
        domain_matches?(domain, allowed)
      end)
    end
  end

  defp domain_matches?(domain, allowed) do
    cond do
      domain == allowed ->
        true

      String.starts_with?(allowed, "*.") ->
        suffix = String.slice(allowed, 2..-1//1)
        String.ends_with?(domain, suffix)

      true ->
        false
    end
  end

  @doc """
  Returns preset expiry options.
  """
  def expiry_presets do
    now = DateTime.utc_now()

    %{
      "1_day" => DateTime.add(now, 1, :day),
      "7_days" => DateTime.add(now, 7, :day),
      "30_days" => DateTime.add(now, 30, :day),
      "never" => nil
    }
  end

  @doc """
  Generates an iframe embed code for the share.
  """
  def generate_embed_code(share, base_url) do
    url = "#{base_url}/shared/dashboard/#{share.share_token}"

    ~s"""
    <iframe
      src="#{url}"
      width="#{share.embed_width}"
      height="#{share.embed_height}"
      frameborder="0"
      style="border: 0;#{if share.transparent_background, do: " background: transparent;", else: ""}"
      allowfullscreen>
    </iframe>
    """
  end

  @doc """
  Returns a public share URL.
  """
  def share_url(share, base_url) do
    "#{base_url}/shared/dashboard/#{share.share_token}"
  end
end
