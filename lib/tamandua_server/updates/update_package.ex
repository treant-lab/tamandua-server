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
end
