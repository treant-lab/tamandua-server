defmodule TamanduaServer.AuthorityGuard do
  @moduledoc false

  use GenServer

  alias TamanduaServer.{AuthorityAccess, AuthorityRepo, Repo}

  @identity_sql "SELECT session_user, current_database(), system_identifier FROM pg_catalog.pg_control_system()"

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    with :ok <- verify_distinct_database_identities(),
         :ok <- AuthorityAccess.startup_preflight() do
      {:ok, %{preflight: :passed}}
    else
      {:error, reason} -> {:stop, {:authority_repository_preflight_failed, reason}}
    end
  end

  @doc false
  def validate_pool_boundary(
        {authority_user, database, system_identifier},
        {ordinary_user, database, system_identifier}
      )
      when is_binary(authority_user) and is_binary(ordinary_user) and
             authority_user != ordinary_user and not is_nil(system_identifier),
      do: :ok

  def validate_pool_boundary(_authority_identity, _ordinary_identity),
    do: {:error, :authority_database_boundary_mismatch}

  defp verify_distinct_database_identities do
    with {:ok, authority_identity} <- database_identity(AuthorityRepo),
         {:ok, ordinary_identity} <- database_identity(Repo) do
      validate_pool_boundary(authority_identity, ordinary_identity)
    else
      _other -> {:error, :authority_repository_unavailable}
    end
  catch
    :exit, _reason -> {:error, :authority_repository_unavailable}
  end

  defp database_identity(repo) do
    case repo.query(@identity_sql) do
      {:ok, %{rows: [[session_user, database, system_identifier]]}} ->
        {:ok, {session_user, database, system_identifier}}

      _other ->
        {:error, :authority_repository_unavailable}
    end
  end
end
