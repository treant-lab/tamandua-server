defmodule TamanduaServer.Repo.MultiTenant do
  @moduledoc """
  Multi-tenancy utilities for Row-Level Security (RLS) in PostgreSQL.

  This module provides functions to set and manage the organization context
  for database queries, enabling defense-in-depth data isolation at the
  database level.

  ## Architecture

  PostgreSQL RLS policies use session variables to determine which rows are
  visible to the current connection. This module manages the session variable
  `app.current_organization_id` which is used by RLS policies.

  ## Usage

      # Set organization context for all queries in this process
      MultiTenant.put_organization_id(conn, org_id)

      # Execute queries within an organization context
      MultiTenant.with_organization(org_id, fn ->
        Repo.all(Alert)  # Only returns alerts for this organization
      end)

      # System operations that need to bypass RLS
      MultiTenant.with_bypass(fn ->
        # Can access all organizations (use with caution!)
        Repo.all(Alert)
      end)

  ## Security Considerations

  - Always set organization_id in authenticated requests
  - Use with_bypass() only for trusted system operations
  - Never expose bypass functionality to user-facing APIs
  - Audit all bypass usage via logs
  - RLS is defense-in-depth: application-level auth is still primary

  ## Performance

  - Session variables are cached per connection
  - Minimal overhead (<1%) for setting variables
  - RLS policies use indexed columns for efficiency
  - Connection pooling maintains isolation between requests
  """

  alias TamanduaServer.Repo

  require Logger

  @doc """
  Sets the organization context for the current database connection.

  This function executes a SQL command to set the session variable
  `app.current_organization_id` which is used by RLS policies to
  filter rows.

  ## Parameters

  - conn: Ecto.Repo connection or Ecto.Multi (optional, uses Repo if nil)
  - organization_id: UUID binary or string of the organization

  ## Returns

  - :ok on success
  - {:error, reason} on failure

  ## Examples

      iex> put_organization_id(nil, "123e4567-e89b-12d3-a456-426614174000")
      :ok

      iex> put_organization_id(conn, organization_id)
      :ok
  """
  def put_organization_id(conn \\ nil, organization_id) when is_binary(organization_id) do
    org_id_string = canonical_organization_id!(organization_id)

    case Repo.get_organization_id() do
      nil -> :ok
      ^org_id_string -> :ok
      _different -> raise ArgumentError, "nested organization context switch is not allowed"
    end

    sql = """
    SELECT CASE
      WHEN NULLIF(current_setting('app.current_organization_id', TRUE), '') IS NULL
        OR current_setting('app.current_organization_id', TRUE) = $1
      THEN set_config('app.current_organization_id', $1, TRUE)
      ELSE NULL
    END
    """

    case execute_sql(conn, sql, [org_id_string]) do
      {:ok, %{rows: [[^org_id_string]]}} ->
        Logger.debug("Set organization context to #{org_id_string}")
        :ok

      {:ok, %{rows: [[nil]]}} ->
        {:error, :nested_organization_context_switch}

      {:ok, _unexpected} ->
        {:error, :unexpected_tenant_context_result}

      {:error, reason} ->
        Logger.error("Failed to set organization context: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Clears the organization context for the current database connection.

  This resets the session variable to NULL, effectively denying access
  to all organization-scoped data (unless bypass is enabled).

  ## Examples

      iex> clear_organization_id()
      :ok
  """
  def clear_organization_id(conn \\ nil) do
    if Repo.get_organization_id() != nil do
      {:error, :active_tenant_context}
    else
      sql = "SELECT set_config('app.current_organization_id', '', TRUE)"

      case execute_sql(conn, sql) do
        {:ok, %{rows: [[""]]}} ->
          Logger.debug("Cleared organization context")
          :ok

        {:ok, _unexpected} ->
          {:error, :unexpected_tenant_context_result}

        {:error, reason} ->
          Logger.error("Failed to clear organization context: #{inspect(reason)}")
          {:error, reason}
      end
    end
  end

  @doc """
  Gets the current organization ID from the session variable.

  ## Returns

  - {:ok, organization_id} if set
  - {:ok, nil} if not set
  - {:error, reason} on database error

  ## Examples

      iex> get_organization_id()
      {:ok, "123e4567-e89b-12d3-a456-426614174000"}
  """
  def get_organization_id(conn \\ nil) do
    sql = "SELECT current_setting('app.current_organization_id', TRUE)"

    case execute_sql(conn, sql) do
      {:ok, %{rows: [[nil]]}} ->
        {:ok, nil}

      {:ok, %{rows: [[""]]}} ->
        {:ok, nil}

      {:ok, %{rows: [[org_id]]}} when is_binary(org_id) ->
        {:ok, org_id}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Executes a function within an organization context.

  The organization context is set before executing the function and
  automatically cleared afterward (even if the function raises an error).

  ## Parameters

  - organization_id: UUID of the organization
  - fun: Function to execute within the organization context

  ## Returns

  The return value of the provided function.

  ## Examples

      result = with_organization(org_id, fn ->
        Repo.all(Alert)
      end)
  """
  def with_organization(organization_id, fun)
      when is_binary(organization_id) and is_function(fun, 0) do
    organization_id = canonical_organization_id!(organization_id)
    previous_organization_id = Repo.get_organization_id()

    if previous_organization_id != nil and previous_organization_id != organization_id do
      raise ArgumentError, "nested organization context switch is not allowed"
    end

    Repo.put_organization_id(organization_id)

    try do
      Repo.transaction(fn ->
        case put_organization_id(organization_id) do
          :ok -> fun.()
          {:error, reason} -> Repo.rollback({:tenant_context_unavailable, reason})
        end
      end)
      |> case do
        {:ok, result} -> result
        {:error, reason} -> raise "Transaction failed: #{inspect(reason)}"
      end
    after
      case previous_organization_id do
        nil -> Repo.clear_organization_id()
        previous -> Repo.put_organization_id(previous)
      end
    end
  end

  @doc """
  Executes an Ecto.Multi in one transaction with transaction-local tenant
  context. This avoids nesting `Repo.transaction/1` inside
  `with_organization/2` when a workflow must atomically combine RLS-scoped
  writes with other resources such as an Oban job.
  """
  @spec transaction(String.t(), Ecto.Multi.t()) ::
          {:ok, map()} | {:error, Ecto.Multi.name(), term(), map()}
  def transaction(organization_id, %Ecto.Multi{} = multi) when is_binary(organization_id) do
    organization_id = canonical_organization_id!(organization_id)
    previous_organization_id = Repo.get_organization_id()

    if previous_organization_id != nil and previous_organization_id != organization_id do
      raise ArgumentError, "nested organization context switch is not allowed"
    end

    Repo.put_organization_id(organization_id)

    try do
      Ecto.Multi.new()
      |> Ecto.Multi.run(:tenant_context, fn _repo, _changes ->
        case put_organization_id(organization_id) do
          :ok -> {:ok, organization_id}
          {:error, reason} -> {:error, reason}
        end
      end)
      |> Ecto.Multi.append(multi)
      |> Repo.transaction()
    after
      case previous_organization_id do
        nil -> Repo.clear_organization_id()
        previous -> Repo.put_organization_id(previous)
      end
    end
  end

  @doc """
  Enables RLS bypass for the current connection and executes a function.

  **WARNING**: This should only be used for trusted system operations such as:
  - Database migrations
  - Background jobs that operate across organizations
  - Admin tools that need cross-organization visibility
  - System health checks

  **NEVER** expose this to user-facing APIs or untrusted code.

  ## Parameters

  - fun: Function to execute with bypass enabled

  ## Returns

  The return value of the provided function.

  ## Examples

      # System operation that needs to see all organizations
      with_bypass(fn ->
        Repo.aggregate(Alert, :count, :id)
      end)

  ## Auditing

  All bypass usage is automatically logged at WARNING level for security auditing.
  """
  def with_bypass(fun) when is_function(fun, 0) do
    Logger.warning("RLS bypass enabled - ensure this is a trusted system operation")

    Repo.transaction(fn ->
      case Repo.query("SET LOCAL app.rls_bypass = TRUE") do
        {:ok, _} ->
          result = fun.()
          # Explicitly clear bypass flag
          Repo.query("SET LOCAL app.rls_bypass = FALSE")
          result

        {:error, reason} ->
          Repo.rollback(reason)
      end
    end)
    |> case do
      {:ok, result} -> result
      {:error, reason} -> raise "Bypass transaction failed: #{inspect(reason)}"
    end
  end

  @doc """
  Checks if RLS bypass is currently enabled.

  ## Returns

  - {:ok, true} if bypass is enabled
  - {:ok, false} if bypass is disabled
  - {:error, reason} on database error

  ## Examples

      iex> bypass_enabled?()
      {:ok, false}
  """
  def bypass_enabled?(conn \\ nil) do
    sql = "SELECT COALESCE(current_setting('app.rls_bypass', TRUE)::BOOLEAN, FALSE)"

    case execute_sql(conn, sql) do
      {:ok, %{rows: [[enabled]]}} when is_boolean(enabled) ->
        {:ok, enabled}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Validates that RLS is properly configured for a given table.

  This checks:
  1. RLS is enabled on the table
  2. Policies exist for the table
  3. organization_id column exists

  ## Parameters

  - table: Atom or string of the table name

  ## Returns

  - :ok if RLS is properly configured
  - {:error, reason} if configuration is invalid

  ## Examples

      iex> validate_rls_config(:alerts)
      :ok
  """
  def validate_rls_config(table) when is_atom(table) or is_binary(table) do
    table_name = to_string(table)

    with {:ok, rls_enabled} <- check_rls_enabled(table_name),
         {:ok, policies} <- check_policies_exist(table_name),
         {:ok, has_org_id} <- check_organization_column(table_name) do
      cond do
        not rls_enabled ->
          {:error, "RLS not enabled on table #{table_name}"}

        Enum.empty?(policies) ->
          {:error, "No RLS policies found for table #{table_name}"}

        not has_org_id ->
          {:error, "Table #{table_name} does not have organization_id column"}

        true ->
          :ok
      end
    end
  end

  @doc """
  Returns statistics about RLS configuration across all tables.

  ## Returns

  A map with:
  - total_tables: Total number of tenant-scoped tables
  - rls_enabled: Number of tables with RLS enabled
  - policies_count: Total number of RLS policies
  - tables_without_rls: List of tables missing RLS

  ## Examples

      iex> rls_stats()
      %{
        total_tables: 85,
        rls_enabled: 85,
        policies_count: 170,
        tables_without_rls: []
      }
  """
  def rls_stats do
    # Query to get all tables with organization_id column
    tables_query = """
    SELECT table_name
    FROM information_schema.columns
    WHERE table_schema = 'public'
    AND column_name = 'organization_id'
    """

    # Query to get RLS status for all tables
    rls_query = """
    SELECT
      tablename,
      COUNT(policyname) as policy_count,
      BOOL_OR(relrowsecurity) as rls_enabled
    FROM pg_policies
    JOIN pg_class ON pg_class.relname = pg_policies.tablename
    WHERE schemaname = 'public'
    GROUP BY tablename, relrowsecurity
    """

    with {:ok, %{rows: tables}} <- Repo.query(tables_query),
         {:ok, %{rows: rls_status}} <- Repo.query(rls_query) do
      table_list = Enum.map(tables, fn [name] -> name end)
      rls_map = Map.new(rls_status, fn [table, count, enabled] -> {table, {count, enabled}} end)

      tables_with_rls = Enum.filter(table_list, fn t -> Map.has_key?(rls_map, t) end)
      tables_without_rls = Enum.filter(table_list, fn t -> not Map.has_key?(rls_map, t) end)

      total_policies = rls_status
      |> Enum.map(fn [_table, count, _enabled] -> count end)
      |> Enum.sum()

      %{
        total_tables: length(table_list),
        rls_enabled: length(tables_with_rls),
        policies_count: total_policies,
        tables_without_rls: tables_without_rls
      }
    else
      {:error, reason} ->
        Logger.error("Failed to get RLS stats: #{inspect(reason)}")
        %{error: reason}
    end
  end

  ## Private Functions

  defp execute_sql(conn, sql), do: execute_sql(conn, sql, [])
  defp execute_sql(nil, sql, params), do: Repo.query(sql, params)
  defp execute_sql(conn, sql, params), do: Ecto.Adapters.SQL.query(conn, sql, params)

  defp canonical_organization_id!(uuid) when is_binary(uuid) do
    case Ecto.UUID.cast(uuid) do
      {:ok, uuid_string} -> uuid_string
      :error -> raise ArgumentError, "organization_id must be a valid UUID"
    end
  end

  defp check_rls_enabled(table_name) do
    sql = """
    SELECT relrowsecurity
    FROM pg_class
    WHERE relname = '#{table_name}'
    AND relnamespace = 'public'::regnamespace
    """

    case Repo.query(sql) do
      {:ok, %{rows: [[enabled]]}} -> {:ok, enabled}
      {:ok, %{rows: []}} -> {:ok, false}
      {:error, reason} -> {:error, reason}
    end
  end

  defp check_policies_exist(table_name) do
    sql = """
    SELECT policyname
    FROM pg_policies
    WHERE schemaname = 'public'
    AND tablename = '#{table_name}'
    """

    case Repo.query(sql) do
      {:ok, %{rows: policies}} -> {:ok, Enum.map(policies, fn [name] -> name end)}
      {:error, reason} -> {:error, reason}
    end
  end

  defp check_organization_column(table_name) do
    sql = """
    SELECT EXISTS (
      SELECT 1
      FROM information_schema.columns
      WHERE table_schema = 'public'
      AND table_name = '#{table_name}'
      AND column_name = 'organization_id'
    )
    """

    case Repo.query(sql) do
      {:ok, %{rows: [[exists]]}} -> {:ok, exists}
      {:error, reason} -> {:error, reason}
    end
  end
end
