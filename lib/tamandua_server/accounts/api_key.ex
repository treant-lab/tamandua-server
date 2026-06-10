defmodule TamanduaServer.Accounts.APIKey do
  @moduledoc """
  Schema for API keys used for programmatic access.

  API keys provide authenticated access to the Tamandua API without
  requiring a user session. Each key is scoped to an organization and
  can have custom permissions and rate limits.

  ## Key Format

  API keys are generated in the format: `tam_<env>_<random>`
  - `tam_` - Prefix identifying Tamandua keys
  - `<env>` - Environment identifier (live, test, dev)
  - `<random>` - 32 bytes of random data, base64 encoded

  Example: `tam_live_abc123def456...`

  ## Security

  - Keys are hashed using bcrypt before storage
  - Only the key prefix is stored in plaintext for identification
  - Keys can be restricted to specific IP addresses
  - Keys can have expiration dates
  - Keys can be deactivated without deletion for audit purposes
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Bitwise

  alias TamanduaServer.Accounts.{Organization, User}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @scopes ~w(full read_only custom)

  schema "api_keys" do
    field :name, :string
    field :description, :string
    field :key_prefix, :string
    field :key_hash, :string

    # Permissions
    field :permissions, {:array, :string}, default: []
    field :scope, :string, default: "full"

    # Rate limiting
    field :rate_limit_per_minute, :integer, default: 1000
    field :rate_limit_per_hour, :integer, default: 50000

    # Lifecycle
    field :expires_at, :utc_datetime_usec
    field :last_used_at, :utc_datetime_usec
    field :is_active, :boolean, default: true

    # IP restrictions
    field :allowed_ips, {:array, :string}, default: []

    # Virtual field for the raw key (only available at creation time)
    field :raw_key, :string, virtual: true

    belongs_to :organization, Organization
    belongs_to :created_by, User, foreign_key: :created_by_id

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(name organization_id)a
  @optional_fields ~w(description permissions scope rate_limit_per_minute
                      rate_limit_per_hour expires_at is_active allowed_ips
                      created_by_id)a

  @doc """
  Creates a changeset for a new API key.

  This generates a new random key and hashes it.
  The raw key is available in the `raw_key` virtual field only at creation time.
  """
  def create_changeset(api_key, attrs, opts \\ []) do
    env = Keyword.get(opts, :env, "live")
    {raw_key, key_prefix, key_hash} = generate_key(env)

    api_key
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_length(:name, min: 1, max: 255)
    |> validate_inclusion(:scope, @scopes)
    |> validate_number(:rate_limit_per_minute, greater_than: 0, less_than_or_equal_to: 100_000)
    |> validate_number(:rate_limit_per_hour, greater_than: 0, less_than_or_equal_to: 1_000_000)
    |> validate_expires_at()
    |> validate_allowed_ips()
    |> put_change(:key_prefix, key_prefix)
    |> put_change(:key_hash, key_hash)
    |> put_change(:raw_key, raw_key)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:created_by_id)
  end

  @doc """
  Creates a changeset for updating an existing API key.

  Cannot change the key itself - only metadata and settings.
  """
  def update_changeset(api_key, attrs) do
    api_key
    |> cast(attrs, [:name, :description, :permissions, :scope,
                    :rate_limit_per_minute, :rate_limit_per_hour,
                    :expires_at, :is_active, :allowed_ips])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_inclusion(:scope, @scopes)
    |> validate_number(:rate_limit_per_minute, greater_than: 0, less_than_or_equal_to: 100_000)
    |> validate_number(:rate_limit_per_hour, greater_than: 0, less_than_or_equal_to: 1_000_000)
    |> validate_expires_at()
    |> validate_allowed_ips()
  end

  @doc """
  Updates the last_used_at timestamp.
  """
  def touch_changeset(api_key) do
    change(api_key, last_used_at: DateTime.utc_now())
  end

  @doc """
  Generates a new API key.

  Returns `{raw_key, key_prefix, key_hash}`.
  """
  def generate_key(env \\ "live") do
    random_bytes = :crypto.strong_rand_bytes(32)
    random_part = Base.url_encode64(random_bytes, padding: false)
    raw_key = "tam_#{env}_#{random_part}"
    key_prefix = "tam_#{env}_"
    key_hash = Bcrypt.hash_pwd_salt(raw_key)

    {raw_key, key_prefix, key_hash}
  end

  @doc """
  Verifies a raw API key against its hash.
  """
  def verify_key(raw_key, key_hash) when is_binary(raw_key) and is_binary(key_hash) do
    Bcrypt.verify_pass(raw_key, key_hash)
  end

  def verify_key(_, _), do: false

  @doc """
  Extracts the prefix from a raw API key.
  """
  def extract_prefix(raw_key) when is_binary(raw_key) do
    case String.split(raw_key, "_", parts: 3) do
      ["tam", env, _rest] -> "tam_#{env}_"
      _ -> nil
    end
  end

  def extract_prefix(_), do: nil

  @doc """
  Checks if the API key is currently valid (active, not expired).
  """
  def valid?(%__MODULE__{is_active: false}), do: false
  def valid?(%__MODULE__{expires_at: nil}), do: true
  def valid?(%__MODULE__{expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :lt
  end

  @doc """
  Checks if the request IP is allowed for this key.
  """
  def ip_allowed?(%__MODULE__{allowed_ips: []}, _ip), do: true
  def ip_allowed?(%__MODULE__{allowed_ips: nil}, _ip), do: true
  def ip_allowed?(%__MODULE__{allowed_ips: allowed_ips}, ip) when is_binary(ip) do
    ip in allowed_ips || matches_cidr?(allowed_ips, ip)
  end
  def ip_allowed?(_, _), do: false

  @doc """
  Checks if the key has a specific permission.
  """
  def has_permission?(%__MODULE__{scope: "full"}, _permission), do: true
  def has_permission?(%__MODULE__{scope: "read_only"}, permission) do
    String.ends_with?(to_string(permission), "_read") ||
    String.ends_with?(to_string(permission), "_list")
  end
  def has_permission?(%__MODULE__{permissions: permissions}, permission) do
    to_string(permission) in permissions
  end

  @doc """
  Returns the list of available scopes.
  """
  def scopes, do: @scopes

  # Private helpers

  defp validate_expires_at(changeset) do
    case get_change(changeset, :expires_at) do
      nil ->
        changeset

      expires_at ->
        if DateTime.compare(expires_at, DateTime.utc_now()) == :gt do
          changeset
        else
          add_error(changeset, :expires_at, "must be in the future")
        end
    end
  end

  defp validate_allowed_ips(changeset) do
    case get_change(changeset, :allowed_ips) do
      nil ->
        changeset

      ips when is_list(ips) ->
        if Enum.all?(ips, &valid_ip_or_cidr?/1) do
          changeset
        else
          add_error(changeset, :allowed_ips, "contains invalid IP addresses")
        end

      _ ->
        add_error(changeset, :allowed_ips, "must be a list of IP addresses")
    end
  end

  defp valid_ip_or_cidr?(ip) when is_binary(ip) do
    case String.split(ip, "/") do
      [ip_part, _cidr] -> valid_ip?(ip_part)
      [ip_part] -> valid_ip?(ip_part)
      _ -> false
    end
  end
  defp valid_ip_or_cidr?(_), do: false

  defp valid_ip?(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, _} -> true
      _ -> false
    end
  end

  defp matches_cidr?(allowed_ips, ip) do
    Enum.any?(allowed_ips, fn allowed ->
      case String.split(allowed, "/") do
        [network, bits] ->
          try do
            bits_int = String.to_integer(bits)
            ip_in_cidr?(ip, network, bits_int)
          rescue
            _ -> false
          end

        _ ->
          false
      end
    end)
  end

  defp ip_in_cidr?(ip, network, bits) do
    with {:ok, ip_tuple} <- :inet.parse_address(String.to_charlist(ip)),
         {:ok, network_tuple} <- :inet.parse_address(String.to_charlist(network)) do
      ip_int = tuple_to_int(ip_tuple)
      network_int = tuple_to_int(network_tuple)
      mask = bsl(-1, 32 - bits)

      band(ip_int, mask) == band(network_int, mask)
    else
      _ -> false
    end
  end

  defp tuple_to_int({a, b, c, d}), do: bsl(a, 24) + bsl(b, 16) + bsl(c, 8) + d
  defp tuple_to_int(_), do: 0
end
