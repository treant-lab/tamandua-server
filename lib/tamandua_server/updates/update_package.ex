defmodule TamanduaServer.Updates.UpdatePackage do
  @moduledoc """
  Schema for agent update packages.

  An update package represents a versioned release binary for a specific
  platform and architecture. Each package carries its SHA-256 hash and
  cryptographic signature so agents can verify integrity before installing.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Updates.Rollout

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "update_packages" do
    field :version, :string
    field :platform, :string
    field :architecture, :string
    field :download_url, :string
    field :sha256_hash, :string
    field :signature, :string
    field :release_notes, :string
    field :size_bytes, :integer
    field :min_agent_version, :string
    field :is_critical, :boolean, default: false
    field :released_at, :utc_datetime_usec

    belongs_to :organization, Organization
    has_many :rollouts, Rollout

    timestamps()
  end

  @required_fields ~w(version platform architecture sha256_hash organization_id)a
  @optional_fields ~w(download_url signature release_notes size_bytes min_agent_version is_critical released_at)a

  @valid_platforms ~w(windows linux macos)
  @valid_architectures ~w(x86_64 aarch64)

  @semver_regex ~r/^\d+\.\d+\.\d+(-[a-zA-Z0-9\.\-]+)?(\+[a-zA-Z0-9\.\-]+)?$/

  @doc false
  def changeset(package, attrs) do
    package
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_format(:version, @semver_regex, message: "must be valid semver (e.g. 1.2.3)")
    |> validate_inclusion(:platform, @valid_platforms,
      message: "must be one of: #{Enum.join(@valid_platforms, ", ")}"
    )
    |> validate_inclusion(:architecture, @valid_architectures,
      message: "must be one of: #{Enum.join(@valid_architectures, ", ")}"
    )
    |> validate_format(:sha256_hash, ~r/^[a-fA-F0-9]{64}$/,
      message: "must be a 64-character hex SHA-256 hash"
    )
    |> validate_min_agent_version()
    |> validate_macos_product_installer_download_url()
    |> validate_number(:size_bytes, greater_than: 0)
    |> unique_constraint([:version, :platform, :architecture],
      name: :update_packages_version_platform_arch_idx,
      message: "version already exists for this platform and architecture"
    )
    |> foreign_key_constraint(:organization_id)
  end

  defp validate_min_agent_version(changeset) do
    case get_change(changeset, :min_agent_version) do
      nil ->
        changeset

      version ->
        if Regex.match?(@semver_regex, version) do
          changeset
        else
          add_error(changeset, :min_agent_version, "must be valid semver (e.g. 1.0.0)")
      end
    end
  end

  defp validate_macos_product_installer_download_url(changeset) do
    platform = changeset |> get_field(:platform) |> to_string() |> String.downcase()

    if platform == "macos" do
      download_url = get_field(changeset, :download_url)
      normalized_url = download_url |> to_string() |> String.downcase()

      cond do
        is_nil(download_url) or String.trim(to_string(download_url)) == "" ->
          add_error(
            changeset,
            :download_url,
            "is required for macOS packages and must point to a signed/notarized DMG or Cask with EndpointSecurity System Extension"
          )

        macos_standalone_download_url?(normalized_url) ->
          add_error(
            changeset,
            :download_url,
            "must not point to a bare macOS agent/watchdog binary; use a signed/notarized DMG or Cask with EndpointSecurity System Extension"
          )

        not macos_product_installer_download_url?(normalized_url) ->
          add_error(
            changeset,
            :download_url,
            "must point to a signed/notarized macOS DMG or Tamandua EDR Cask"
          )

        true ->
          changeset
      end
    else
      changeset
    end
  end

  defp macos_standalone_download_url?(url) do
    String.contains?(url, "tamandua-agent-macos") or
      String.contains?(url, "aarch64-apple-darwin") or
      String.contains?(url, "x86_64-apple-darwin") or
      String.contains?(url, "tamandua-watchdog") or
      String.contains?(url, "tamandua%20edr_0.1.0") or
      String.contains?(url, "tamandua edr_0.1.0") or
      String.contains?(url, "tamandua_edr_0.1.0") or
      String.contains?(url, "macos-sha256sums")
  end

  defp macos_product_installer_download_url?(url) do
    String.contains?(url, ".dmg") or
      (String.contains?(url, "cask") and String.contains?(url, "tamandua-edr"))
  end
end
