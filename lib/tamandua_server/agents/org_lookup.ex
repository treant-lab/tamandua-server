defmodule TamanduaServer.Agents.OrgLookup do
  @moduledoc """
  Cached lookup for agent_id -> organization_id mapping.

  Uses ETS for fast in-memory lookups with a configurable TTL so we avoid
  hitting the database on every telemetry event. Entries are lazily evicted
  when they are accessed past their TTL.
  """

  use GenServer
  require Logger

  import Ecto.Query, only: [from: 2]

  alias TamanduaServer.Repo
  alias TamanduaServer.Agents.Agent

  @table :agent_org_lookup
  @ttl_ms :timer.minutes(5)

  # ============================================================================
  # Public API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Returns the organization_id for a given agent_id.

  Looks up the ETS cache first; on miss (or stale entry) queries the DB and
  caches the result.  Returns `nil` when the agent cannot be found.
  """
  @spec get_org_id(String.t() | nil) :: String.t() | nil
  def get_org_id(nil), do: nil

  def get_org_id(agent_id) do
    case :ets.lookup(@table, agent_id) do
      [{^agent_id, org_id, inserted_at}] ->
        if System.monotonic_time(:millisecond) - inserted_at < @ttl_ms do
          org_id
        else
          # Stale — refresh
          fetch_and_cache(agent_id)
        end

      [] ->
        fetch_and_cache(agent_id)
    end
  rescue
    ArgumentError ->
      # ETS table doesn't exist yet (GenServer not started or crashed)
      nil
  end

  @doc """
  Returns the cached `os_type` ("windows"/"linux"/"macos") for an agent_id.

  Looks up the ETS cache first (under a dedicated key namespace so it never
  collides with the org_id entry); on miss or stale entry queries the DB and
  caches the result. Returns `nil` when the agent or its os_type is unknown.
  """
  @spec get_os_type(String.t() | nil) :: String.t() | nil
  def get_os_type(nil), do: nil

  def get_os_type(agent_id) do
    key = {:os, agent_id}

    case :ets.lookup(@table, key) do
      [{^key, os_type, inserted_at}] ->
        if System.monotonic_time(:millisecond) - inserted_at < @ttl_ms do
          os_type
        else
          fetch_and_cache_os(agent_id)
        end

      [] ->
        fetch_and_cache_os(agent_id)
    end
  rescue
    ArgumentError ->
      nil
  end

  @doc """
  Explicitly cache an agent_id -> organization_id mapping.

  Useful when the caller already knows the mapping (e.g. during agent
  registration) and wants to warm the cache.
  """
  @spec put(String.t(), String.t()) :: :ok
  def put(agent_id, organization_id) do
    :ets.insert(@table, {agent_id, organization_id, System.monotonic_time(:millisecond)})
    :ok
  rescue
    ArgumentError -> :ok
  end

  @doc """
  Invalidate a cached entry (e.g. when an agent changes organization).
  """
  @spec invalidate(String.t()) :: :ok
  def invalidate(agent_id) do
    :ets.delete(@table, agent_id)
    :ok
  rescue
    ArgumentError -> :ok
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    table = :ets.new(@table, [:named_table, :set, :public, read_concurrency: true])
    Logger.info("OrgLookup cache started")
    {:ok, %{table: table}}
  end

  # ============================================================================
  # Internal
  # ============================================================================

  defp fetch_and_cache(agent_id) do
    org_id =
      Repo.one(
        from a in Agent,
          where: a.id == ^agent_id,
          select: a.organization_id
      )

    if org_id do
      :ets.insert(@table, {agent_id, org_id, System.monotonic_time(:millisecond)})
    end

    org_id
  rescue
    e ->
      Logger.error("OrgLookup DB query failed for agent #{agent_id}: #{inspect(e)}")
      nil
  end

  defp fetch_and_cache_os(agent_id) do
    os_type =
      Repo.one(
        from a in Agent,
          where: a.id == ^agent_id,
          select: a.os_type
      )

    if os_type do
      :ets.insert(@table, {{:os, agent_id}, os_type, System.monotonic_time(:millisecond)})
    end

    os_type
  rescue
    e ->
      Logger.error("OrgLookup os_type query failed for agent #{agent_id}: #{inspect(e)}")
      nil
  end
end
