defmodule Tamandua.Updates.VersionManager do
  @moduledoc """
  Version manifest management for agent updates.

  Manages version metadata, binary URLs, checksums, signatures, and rollout status.
  Supports full and delta updates for bandwidth optimization.
  """

  use GenServer
  require Logger
  alias Tamandua.Repo
  alias Tamandua.Updates.{Version, DeltaPatch, RolloutState}
  import Ecto.Query

  @type version_string :: String.t()
  @type platform :: :windows | :linux | :macos
  @type arch :: :x86_64 | :aarch64 | :arm | :x86

  @type manifest :: %{
    version: version_string(),
    platform: platform(),
    arch: arch(),
    binary_url: String.t(),
    checksum_sha256: String.t(),
    signature_ed25519: String.t(),
    size_bytes: non_neg_integer(),
    min_version: version_string() | nil,
    delta_from: [version_string()],
    release_notes: String.t(),
    critical: boolean(),
    released_at: DateTime.t(),
    deprecated_at: DateTime.t() | nil
  }

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Publish a new version manifest.
  """
  @spec publish_version(manifest()) :: {:ok, Version.t()} | {:error, term()}
  def publish_version(manifest) do
    GenServer.call(__MODULE__, {:publish_version, manifest})
  end

  @doc """
  Get the latest version for a platform/arch combination.
  """
  @spec get_latest_version(platform(), arch()) :: {:ok, Version.t()} | {:error, :not_found}
  def get_latest_version(platform, arch) do
    GenServer.call(__MODULE__, {:get_latest_version, platform, arch})
  end

  @doc """
  Get specific version manifest.
  """
  @spec get_version(version_string(), platform(), arch()) :: {:ok, Version.t()} | {:error, :not_found}
  def get_version(version, platform, arch) do
    GenServer.call(__MODULE__, {:get_version, version, platform, arch})
  end

  @doc """
  Check if an update is available for an agent.
  """
  @spec check_update(version_string(), platform(), arch()) ::
    {:update_available, Version.t(), :full | {:delta, String.t()}} | :up_to_date
  def check_update(current_version, platform, arch) do
    GenServer.call(__MODULE__, {:check_update, current_version, platform, arch})
  end

  @doc """
  Get delta patch if available between two versions.
  """
  @spec get_delta_patch(version_string(), version_string(), platform(), arch()) ::
    {:ok, DeltaPatch.t()} | {:error, :not_found}
  def get_delta_patch(from_version, to_version, platform, arch) do
    GenServer.call(__MODULE__, {:get_delta_patch, from_version, to_version, platform, arch})
  end

  @doc """
  List all versions for a platform/arch.
  """
  @spec list_versions(platform(), arch(), keyword()) :: [Version.t()]
  def list_versions(platform, arch, opts \\ []) do
    GenServer.call(__MODULE__, {:list_versions, platform, arch, opts})
  end

  @doc """
  Deprecate a version (mark as no longer recommended).
  """
  @spec deprecate_version(version_string(), platform(), arch()) :: :ok | {:error, term()}
  def deprecate_version(version, platform, arch) do
    GenServer.call(__MODULE__, {:deprecate_version, version, platform, arch})
  end

  @doc """
  Create a delta patch manifest between two versions.
  """
  @spec create_delta_patch(version_string(), version_string(), platform(), arch(), map()) ::
    {:ok, DeltaPatch.t()} | {:error, term()}
  def create_delta_patch(from_version, to_version, platform, arch, patch_info) do
    GenServer.call(__MODULE__, {:create_delta_patch, from_version, to_version, platform, arch, patch_info})
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    Logger.info("Version Manager started")
    {:ok, %{cache: %{}}}
  end

  @impl true
  def handle_call({:publish_version, manifest}, _from, state) do
    case validate_manifest(manifest) do
      :ok ->
        changeset = Version.changeset(%Version{}, manifest)
        case Repo.insert(changeset) do
          {:ok, version} ->
            Logger.info("Published version #{version.version} for #{version.platform}/#{version.arch}")
            state = invalidate_cache(state, version.platform, version.arch)
            {:reply, {:ok, version}, state}
          {:error, changeset} ->
            {:reply, {:error, changeset}, state}
        end
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_latest_version, platform, arch}, _from, state) do
    cache_key = {:latest, platform, arch}

    case get_cached(state, cache_key) do
      {:ok, version} ->
        {:reply, {:ok, version}, state}
      :miss ->
        query = from v in Version,
          where: v.platform == ^platform and v.arch == ^arch and is_nil(v.deprecated_at),
          order_by: [desc: v.released_at],
          limit: 1

        case Repo.one(query) do
          nil -> {:reply, {:error, :not_found}, state}
          version ->
            state = put_cache(state, cache_key, version)
            {:reply, {:ok, version}, state}
        end
    end
  end

  @impl true
  def handle_call({:get_version, version, platform, arch}, _from, state) do
    query = from v in Version,
      where: v.version == ^version and v.platform == ^platform and v.arch == ^arch

    case Repo.one(query) do
      nil -> {:reply, {:error, :not_found}, state}
      version -> {:reply, {:ok, version}, state}
    end
  end

  @impl true
  def handle_call({:check_update, current_version, platform, arch}, _from, state) do
    with {:ok, latest} <- get_latest_version(platform, arch) do
      cond do
        Version.compare(latest.version, current_version) == :gt ->
          # Check if delta patch is available
          case get_delta_patch(current_version, latest.version, platform, arch) do
            {:ok, delta} ->
              {:reply, {:update_available, latest, {:delta, delta.patch_url}}, state}
            {:error, :not_found} ->
              {:reply, {:update_available, latest, :full}, state}
          end
        true ->
          {:reply, :up_to_date, state}
      end
    else
      {:error, :not_found} ->
        {:reply, :up_to_date, state}
    end
  end

  @impl true
  def handle_call({:get_delta_patch, from_version, to_version, platform, arch}, _from, state) do
    query = from d in DeltaPatch,
      where: d.from_version == ^from_version and
             d.to_version == ^to_version and
             d.platform == ^platform and
             d.arch == ^arch

    case Repo.one(query) do
      nil -> {:reply, {:error, :not_found}, state}
      delta -> {:reply, {:ok, delta}, state}
    end
  end

  @impl true
  def handle_call({:list_versions, platform, arch, opts}, _from, state) do
    query = from v in Version,
      where: v.platform == ^platform and v.arch == ^arch

    query = if opts[:include_deprecated] do
      query
    else
      from v in query, where: is_nil(v.deprecated_at)
    end

    query = from v in query, order_by: [desc: v.released_at]

    query = if limit = opts[:limit] do
      from v in query, limit: ^limit
    else
      query
    end

    versions = Repo.all(query)
    {:reply, versions, state}
  end

  @impl true
  def handle_call({:deprecate_version, version, platform, arch}, _from, state) do
    query = from v in Version,
      where: v.version == ^version and v.platform == ^platform and v.arch == ^arch

    case Repo.one(query) do
      nil ->
        {:reply, {:error, :not_found}, state}
      version_record ->
        changeset = Version.changeset(version_record, %{deprecated_at: DateTime.utc_now()})
        case Repo.update(changeset) do
          {:ok, _} ->
            Logger.info("Deprecated version #{version} for #{platform}/#{arch}")
            state = invalidate_cache(state, platform, arch)
            {:reply, :ok, state}
          {:error, changeset} ->
            {:reply, {:error, changeset}, state}
        end
    end
  end

  @impl true
  def handle_call({:create_delta_patch, from_version, to_version, platform, arch, patch_info}, _from, state) do
    # Verify both versions exist
    with {:ok, _from} <- get_version(from_version, platform, arch),
         {:ok, _to} <- get_version(to_version, platform, arch) do

      attrs = Map.merge(patch_info, %{
        from_version: from_version,
        to_version: to_version,
        platform: platform,
        arch: arch
      })

      changeset = DeltaPatch.changeset(%DeltaPatch{}, attrs)
      case Repo.insert(changeset) do
        {:ok, delta} ->
          Logger.info("Created delta patch #{from_version} -> #{to_version} for #{platform}/#{arch}")
          {:reply, {:ok, delta}, state}
        {:error, changeset} ->
          {:reply, {:error, changeset}, state}
      end
    else
      {:error, :not_found} ->
        {:reply, {:error, :version_not_found}, state}
    end
  end

  # Private Helpers

  defp validate_manifest(manifest) do
    required_keys = [:version, :platform, :arch, :binary_url, :checksum_sha256,
                     :signature_ed25519, :size_bytes, :released_at]

    missing = Enum.filter(required_keys, fn key -> not Map.has_key?(manifest, key) end)

    if Enum.empty?(missing) do
      :ok
    else
      {:error, {:missing_fields, missing}}
    end
  end

  defp get_cached(state, key) do
    case Map.get(state.cache, key) do
      {value, expires_at} ->
        if DateTime.compare(DateTime.utc_now(), expires_at) == :lt do
          {:ok, value}
        else
          :miss
        end
      nil -> :miss
    end
  end

  defp put_cache(state, key, value) do
    # Cache for 5 minutes
    expires_at = DateTime.add(DateTime.utc_now(), 300, :second)
    put_in(state.cache[key], {value, expires_at})
  end

  defp invalidate_cache(state, platform, arch) do
    cache_key = {:latest, platform, arch}
    update_in(state.cache, &Map.delete(&1, cache_key))
  end
end
