defmodule TamanduaServerWeb.API.V1.SavedQueriesController do
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Hunting.SavedQueries
  alias TamanduaServer.Hunting.SavedQuery

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  GET /api/v1/queries
  List saved queries with optional filters.
  """
  def index(conn, params) do
    organization_id = current_organization_id(conn)

    opts = [
      query_type: params["type"],
      category: params["category"],
      templates_only: params["templates"] == "true",
      public_only: params["public"] == "true",
      organization_id: organization_id,
      limit: parse_int(params["limit"], 50)
    ]

    # Add user context if available
    opts = case conn.assigns[:current_user] do
      nil -> opts
      user -> Keyword.put(opts, :user_id, user.id)
    end

    queries = SavedQueries.list_saved_queries(opts)
    json(conn, %{data: Enum.map(queries, &serialize/1)})
  end

  @doc """
  GET /api/v1/queries/:id
  Get a single saved query.
  """
  def show(conn, %{"id" => id}) do
    case SavedQueries.get_saved_query(id, scoped_query_opts(conn, include_global_templates: true)) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Query not found"})

      query ->
        json(conn, %{data: serialize(query)})
    end
  end

  @doc """
  POST /api/v1/queries
  Create a new saved query.
  """
  def create(conn, params) do
    attrs = %{
      name: params["name"],
      description: params["description"],
      query: params["query"],
      query_type: params["type"] || "hunt",
      category: params["category"],
      tags: params["tags"] || [],
      is_template: params["is_template"] || false,
      is_public: params["is_public"] || false
    }

    # Add user context
    attrs = case conn.assigns[:current_user] do
      nil -> attrs
      user -> Map.merge(attrs, %{created_by: user.id, organization_id: user.organization_id})
    end

    case SavedQueries.create_saved_query(attrs) do
      {:ok, query} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize(query), message: "Query saved successfully"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: format_errors(changeset)})
    end
  end

  @doc """
  PUT /api/v1/queries/:id
  Update a saved query.
  """
  def update(conn, %{"id" => id} = params) do
    case SavedQueries.get_saved_query(id, scoped_query_opts(conn)) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Query not found"})

      query ->
        attrs = %{
          name: params["name"],
          description: params["description"],
          query: params["query"],
          category: params["category"],
          tags: params["tags"],
          is_public: params["is_public"]
        }
        |> Enum.reject(fn {_k, v} -> is_nil(v) end)
        |> Map.new()

        case SavedQueries.update_saved_query(query, attrs) do
          {:ok, updated} ->
            json(conn, %{data: serialize(updated), message: "Query updated"})

          {:error, changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: format_errors(changeset)})
        end
    end
  end

  @doc """
  DELETE /api/v1/queries/:id
  Delete a saved query.
  """
  def delete(conn, %{"id" => id}) do
    case SavedQueries.get_saved_query(id, scoped_query_opts(conn)) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Query not found"})

      query ->
        case SavedQueries.delete_saved_query(query) do
          {:ok, _} ->
            json(conn, %{message: "Query deleted"})

          {:error, _} ->
            conn
            |> put_status(:internal_server_error)
            |> json(%{error: "Failed to delete query"})
        end
    end
  end

  @doc """
  POST /api/v1/queries/:id/use
  Record that a query was used (increments counter).
  """
  def record_use(conn, %{"id" => id}) do
    case SavedQueries.get_saved_query(id, scoped_query_opts(conn, include_global_templates: true)) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Query not found"})

      query ->
        {:ok, updated} = SavedQueries.record_query_use(query)
        json(conn, %{data: serialize(updated)})
    end
  end

  @doc """
  GET /api/v1/queries/search
  Search saved queries.
  """
  def search(conn, %{"q" => search_term} = params) do
    opts = [organization_id: current_organization_id(conn), limit: parse_int(params["limit"], 20)]

    # Add user context
    opts = case conn.assigns[:current_user] do
      nil -> opts
      user -> Keyword.put(opts, :user_id, user.id)
    end

    queries = SavedQueries.search_saved_queries(search_term, opts)
    json(conn, %{data: Enum.map(queries, &serialize/1)})
  end

  @doc """
  GET /api/v1/queries/templates
  Get query templates by category.
  """
  def templates(conn, params) do
    organization_id = current_organization_id(conn)

    queries = case params["category"] do
      nil ->
        SavedQueries.list_saved_queries(
          templates_only: true,
          organization_id: organization_id,
          include_global_templates: true,
          limit: 50
        )

      category ->
        SavedQueries.get_templates_by_category(
          category,
          organization_id: organization_id,
          include_global_templates: true
        )
    end

    json(conn, %{data: Enum.map(queries, &serialize/1)})
  end

  @doc """
  GET /api/v1/queries/popular
  Get popular public queries.
  """
  def popular(conn, params) do
    limit = parse_int(params["limit"], 10)
    queries = SavedQueries.get_popular_queries(limit, organization_id: current_organization_id(conn))
    json(conn, %{data: Enum.map(queries, &serialize/1)})
  end

  @doc """
  GET /api/v1/queries/history
  Get user's query history.
  """
  def history(conn, params) do
    case conn.assigns[:current_user] do
      nil ->
        json(conn, %{data: []})

      user ->
        limit = parse_int(params["limit"], 20)

        history = if params["unique"] == "true" do
          SavedQueries.get_unique_recent_queries(user.id, limit)
        else
          SavedQueries.get_recent_history(user.id, limit)
          |> Enum.map(&serialize_history/1)
        end

        json(conn, %{data: history})
    end
  end

  @doc """
  POST /api/v1/queries/history
  Record a query execution.
  """
  def record_history(conn, params) do
    attrs = %{
      query: params["query"],
      query_type: params["type"] || "hunt",
      result_count: params["result_count"],
      execution_time_ms: params["execution_time_ms"],
      agent_id: params["agent_id"]
    }

    # Add user context
    attrs = case conn.assigns[:current_user] do
      nil -> attrs
      user -> Map.put(attrs, :user_id, user.id)
    end

    case SavedQueries.record_query_history(attrs) do
      {:ok, _} -> json(conn, %{message: "History recorded"})
      {:error, _} -> json(conn, %{message: "History recording failed"})
    end
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp serialize(%SavedQuery{} = query) do
    %{
      id: query.id,
      name: query.name,
      description: query.description,
      query: query.query,
      type: query.query_type,
      category: query.category,
      tags: query.tags || [],
      is_template: query.is_template,
      is_public: query.is_public,
      use_count: query.use_count,
      last_used_at: format_datetime(query.last_used_at),
      created_by: query.created_by,
      created_at: format_datetime(query.inserted_at),
      updated_at: format_datetime(query.updated_at)
    }
  end

  defp current_organization_id(conn) do
    case conn.assigns[:current_user] do
      nil -> nil
      user -> user.organization_id
    end
  end

  defp scoped_query_opts(conn, extra \\ []) do
    [organization_id: current_organization_id(conn)]
    |> Keyword.merge(extra)
  end

  defp serialize_history(history) do
    %{
      id: history.id,
      query: history.query,
      type: history.query_type,
      result_count: history.result_count,
      execution_time_ms: history.execution_time_ms,
      executed_at: format_datetime(history.inserted_at)
    }
  end

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)

  defp parse_int(nil, default), do: default
  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(val, _default) when is_integer(val), do: val

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
