defmodule TamanduaServer.Agents.UpdatePackage do
  @moduledoc """
  Represents an agent update package for a specific platform/architecture.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query
  alias TamanduaServer.Repo

  @type t :: %__MODULE__{}

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

    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps()
  end

  @doc false
  def changeset(package, attrs) do
    package
    |> cast(attrs, [
      :version,
      :platform,
      :architecture,
      :download_url,
      :sha256_hash,
      :signature,
      :release_notes,
      :size_bytes,
      :min_agent_version,
      :is_critical,
      :released_at,
      :organization_id
    ])
    |> validate_required([
      :version,
      :platform,
      :architecture,
      :sha256_hash,
      :organization_id
    ])
    |> validate_inclusion(:platform, ["windows", "linux", "macos"])
    |> validate_inclusion(:architecture, ["x86_64", "aarch64", "arm64"])
    |> validate_macos_product_installer_download_url()
    |> unique_constraint([:version, :platform, :architecture],
      name: :update_packages_version_platform_arch_idx
    )
  end

  @doc """
  List all update packages for an organization.
  """
  @spec list_packages(binary(), keyword()) :: list(__MODULE__.t())
  def list_packages(organization_id, opts \\ []) do
    __MODULE__
    |> where([p], p.organization_id == ^organization_id)
    |> maybe_filter_platform(opts[:platform])
    |> maybe_filter_critical(opts[:critical])
    |> order_by([p], desc: p.released_at)
    |> limit(^Keyword.get(opts, :limit, 100))
    |> Repo.all()
  end

  @doc """
  Get the latest package for a platform.
  """
  @spec get_latest(binary(), String.t(), String.t()) ::
          {:ok, __MODULE__.t()} | {:error, :not_found}
  def get_latest(organization_id, platform, architecture) do
    __MODULE__
    |> where([p], p.organization_id == ^organization_id)
    |> where([p], p.platform == ^platform)
    |> where([p], p.architecture == ^architecture)
    |> order_by([p], desc: p.released_at)
    |> limit(1)
    |> Repo.one()
    |> case do
      nil -> {:error, :not_found}
      package -> {:ok, package}
    end
  end

  @doc """
  Create a new update package.
  """
  @spec create(map()) :: {:ok, __MODULE__.t()} | {:error, Ecto.Changeset.t()}
  def create(attrs) do
    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  # Private Functions

  defp maybe_filter_platform(query, nil), do: query

  defp maybe_filter_platform(query, platform) do
    where(query, [p], p.platform == ^platform)
  end

  defp maybe_filter_critical(query, nil), do: query

  defp maybe_filter_critical(query, true) do
    where(query, [p], p.is_critical == true)
  end

  defp maybe_filter_critical(query, false) do
    where(query, [p], p.is_critical == false)
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
