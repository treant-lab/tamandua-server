defmodule TamanduaServer.Hunting.QueryLibrary do
  @moduledoc """
  Context for managing the threat hunting query library with advanced features:
  - Saved query management with categorization and tagging
  - Query sharing (private, organization, public/community)
  - Favorites and ratings
  - Import/export
  - Community marketplace features
  - Performance analytics
  """

  import Ecto.Query, warn: false
  alias TamanduaServer.Repo
  alias TamanduaServer.Hunting.{
    SavedQuery,
    QueryRating,
    QueryComment,
    QuerySchedule,
    QueryResultHistory
  }

  # ============================================================================
  # Query Library Management
  # ============================================================================

  @doc """
  Lists queries with advanced filtering options.
  """
  def list_queries(opts \\ []) do
    query = from(sq in SavedQuery, order_by: [desc: sq.rating, desc: sq.use_count])

    query
    |> filter_by_visibility(opts[:visibility])
    |> filter_by_category(opts[:category])
    |> filter_by_tags(opts[:tags])
    |> filter_by_mitre_tactic(opts[:mitre_tactic])
    |> filter_by_mitre_technique(opts[:mitre_technique])
    |> filter_by_user(opts[:user_id])
    |> filter_by_organization(opts[:organization_id])
    |> filter_favorites_only(opts[:favorites_only], opts[:user_id])
    |> filter_templates_only(opts[:templates_only])
    |> search_text(opts[:search])
    |> maybe_limit(opts[:limit])
    |> Repo.all()
    |> preload_associations(opts[:preload])
  end

  @doc """
  Gets a single query by ID.
  """
  def get_query(id, opts \\ []) do
    SavedQuery
    |> Repo.get(id)
    |> preload_query(opts[:preload])
  end

  @doc """
  Gets a single query by ID, raises if not found.
  """
  def get_query!(id, opts \\ []) do
    SavedQuery
    |> Repo.get!(id)
    |> preload_query(opts[:preload])
  end

  @doc """
  Creates a new saved query.
  """
  def create_query(attrs) do
    %SavedQuery{}
    |> SavedQuery.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a saved query.
  """
  def update_query(%SavedQuery{} = query, attrs) do
    query
    |> SavedQuery.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a saved query.
  """
  def delete_query(%SavedQuery{} = query) do
    Repo.delete(query)
  end

  @doc """
  Duplicates a query (fork).
  """
  def duplicate_query(%SavedQuery{} = query, attrs \\ %{}) do
    new_attrs =
      query
      |> Map.from_struct()
      |> Map.drop([:id, :inserted_at, :updated_at, :__meta__])
      |> Map.merge(%{
        parent_id: query.id,
        name: "#{query.name} (Copy)",
        use_count: 0,
        last_used_at: nil,
        upvotes: 0,
        downvotes: 0,
        rating: 0.0,
        download_count: 0
      })
      |> Map.merge(attrs)

    create_query(new_attrs)
  end

  # ============================================================================
  # Favorites
  # ============================================================================

  @doc """
  Marks a query as favorite for a user.
  """
  def add_favorite(query_id, user_id) do
    case get_query(query_id) do
      nil ->
        {:error, :not_found}

      query ->
        # Create a duplicate marked as favorite for this user
        duplicate_query(query, %{
          created_by: user_id,
          is_favorite: true,
          visibility: "private"
        })
    end
  end

  @doc """
  Removes a query from favorites.
  """
  def remove_favorite(query_id) do
    case get_query(query_id) do
      nil -> {:error, :not_found}
      query -> update_query(query, %{is_favorite: false})
    end
  end

  @doc """
  Lists favorite queries for a user.
  """
  def list_favorites(user_id) do
    list_queries(user_id: user_id, favorites_only: true)
  end

  # ============================================================================
  # Ratings & Reviews
  # ============================================================================

  @doc """
  Adds or updates a rating for a query.
  """
  def rate_query(query_id, user_id, vote: vote) when vote in [-1, 1] do
    attrs = %{
      saved_query_id: query_id,
      user_id: user_id,
      vote: vote
    }

    case Repo.get_by(QueryRating, saved_query_id: query_id, user_id: user_id) do
      nil ->
        %QueryRating{}
        |> QueryRating.changeset(attrs)
        |> Repo.insert()

      existing ->
        existing
        |> QueryRating.changeset(attrs)
        |> Repo.update()
    end
    |> case do
      {:ok, _rating} ->
        update_query_rating_stats(query_id)

      error ->
        error
    end
  end

  def rate_query(query_id, user_id, rating: rating) when rating in 1..5 do
    attrs = %{
      saved_query_id: query_id,
      user_id: user_id,
      rating: rating
    }

    case Repo.get_by(QueryRating, saved_query_id: query_id, user_id: user_id) do
      nil ->
        %QueryRating{}
        |> QueryRating.changeset(attrs)
        |> Repo.insert()

      existing ->
        existing
        |> QueryRating.changeset(attrs)
        |> Repo.update()
    end
    |> case do
      {:ok, _rating} ->
        update_query_rating_stats(query_id)

      error ->
        error
    end
  end

  @doc """
  Gets the current user's rating for a query.
  """
  def get_user_rating(query_id, user_id) do
    Repo.get_by(QueryRating, saved_query_id: query_id, user_id: user_id)
  end

  defp update_query_rating_stats(query_id) do
    stats =
      from(r in QueryRating,
        where: r.saved_query_id == ^query_id,
        select: %{
          upvotes: fragment("COUNT(CASE WHEN vote = 1 THEN 1 END)"),
          downvotes: fragment("COUNT(CASE WHEN vote = -1 THEN 1 END)"),
          avg_rating: fragment("AVG(CASE WHEN rating IS NOT NULL THEN rating END)")
        }
      )
      |> Repo.one()

    case get_query(query_id) do
      nil ->
        {:error, :not_found}

      query ->
        update_query(query, %{
          upvotes: stats.upvotes || 0,
          downvotes: stats.downvotes || 0,
          rating: stats.avg_rating || 0.0
        })
    end
  end

  # ============================================================================
  # Comments
  # ============================================================================

  @doc """
  Adds a comment to a query.
  """
  def add_comment(query_id, user_id, comment_text, parent_id \\ nil) do
    %QueryComment{}
    |> QueryComment.changeset(%{
      saved_query_id: query_id,
      user_id: user_id,
      comment: comment_text,
      parent_id: parent_id
    })
    |> Repo.insert()
  end

  @doc """
  Lists comments for a query.
  """
  def list_comments(query_id) do
    from(c in QueryComment,
      where: c.saved_query_id == ^query_id and is_nil(c.parent_id),
      order_by: [desc: c.inserted_at],
      preload: [:user, replies: [:user]]
    )
    |> Repo.all()
  end

  # ============================================================================
  # Community Marketplace
  # ============================================================================

  @doc """
  Lists popular public queries (marketplace).
  """
  def list_marketplace_queries(opts \\ []) do
    sort_by = opts[:sort_by] || :rating

    query =
      from(sq in SavedQuery,
        where: sq.visibility == "public"
      )

    query =
      case sort_by do
        :rating -> order_by(query, [sq], desc: sq.rating, desc: sq.upvotes)
        :downloads -> order_by(query, [sq], desc: sq.download_count)
        :recent -> order_by(query, [sq], desc: sq.inserted_at)
        :trending -> order_by(query, [sq], desc: sq.use_count)
        _ -> order_by(query, [sq], desc: sq.rating)
      end

    query
    |> filter_by_category(opts[:category])
    |> filter_by_mitre_tactic(opts[:mitre_tactic])
    |> search_text(opts[:search])
    |> maybe_limit(opts[:limit] || 50)
    |> Repo.all()
  end

  @doc """
  Downloads/imports a query from marketplace.
  """
  def download_query(query_id, user_id, organization_id \\ nil) do
    with {:ok, query} <- get_public_query(query_id),
         {:ok, _} <- increment_download_count(query) do
      duplicate_query(query, %{
        created_by: user_id,
        organization_id: organization_id,
        visibility: "private",
        parent_id: query_id
      })
    end
  end

  defp get_public_query(query_id) do
    case Repo.get_by(SavedQuery, id: query_id, visibility: "public") do
      nil -> {:error, :not_found}
      query -> {:ok, query}
    end
  end

  defp increment_download_count(query) do
    query
    |> SavedQuery.increment_download_changeset()
    |> Repo.update()
  end

  # ============================================================================
  # Import/Export
  # ============================================================================

  @doc """
  Exports a query to JSON format.
  """
  def export_query(query_id) do
    case get_query(query_id, preload: [:ratings, :comments]) do
      nil ->
        {:error, :not_found}

      query ->
        data = %{
          version: "1.0",
          query: %{
            name: query.name,
            description: query.description,
            query: query.query,
            query_type: query.query_type,
            category: query.category,
            tags: query.tags,
            parameters: query.parameters,
            mitre_tactics: query.mitre_tactics,
            mitre_techniques: query.mitre_techniques,
            author_name: query.author_name,
            author_organization: query.author_organization,
            version: query.version
          },
          metadata: %{
            use_count: query.use_count,
            rating: query.rating,
            upvotes: query.upvotes,
            downvotes: query.downvotes,
            exported_at: DateTime.utc_now()
          }
        }

        {:ok, Jason.encode!(data, pretty: true)}
    end
  end

  @doc """
  Imports a query from JSON format.
  """
  def import_query(json_data, user_id, organization_id \\ nil) do
    with {:ok, data} <- Jason.decode(json_data),
         {:ok, query_data} <- validate_import_data(data) do
      create_query(
        Map.merge(query_data["query"], %{
          created_by: user_id,
          organization_id: organization_id,
          visibility: "private",
          use_count: 0,
          rating: 0.0,
          upvotes: 0,
          downvotes: 0
        })
      )
    end
  end

  defp validate_import_data(%{"version" => _version, "query" => query}) do
    {:ok, %{"query" => query}}
  end

  defp validate_import_data(_), do: {:error, :invalid_format}

  @doc """
  Exports multiple queries to a collection JSON.
  """
  def export_collection(query_ids, collection_name \\ "Query Collection") do
    queries = Enum.map(query_ids, &get_query/1) |> Enum.reject(&is_nil/1)

    data = %{
      version: "1.0",
      collection: %{
        name: collection_name,
        exported_at: DateTime.utc_now(),
        query_count: length(queries)
      },
      queries:
        Enum.map(queries, fn q ->
          %{
            name: q.name,
            description: q.description,
            query: q.query,
            query_type: q.query_type,
            category: q.category,
            tags: q.tags,
            parameters: q.parameters,
            mitre_tactics: q.mitre_tactics,
            mitre_techniques: q.mitre_techniques
          }
        end)
    }

    {:ok, Jason.encode!(data, pretty: true)}
  end

  @doc """
  Imports a collection of queries.
  """
  def import_collection(json_data, user_id, organization_id \\ nil) do
    with {:ok, data} <- Jason.decode(json_data),
         {:ok, queries} <- validate_collection_data(data) do
      results =
        Enum.map(queries, fn query_data ->
          create_query(
            Map.merge(query_data, %{
              "created_by" => user_id,
              "organization_id" => organization_id,
              "visibility" => "private"
            })
          )
        end)

      success_count = Enum.count(results, &match?({:ok, _}, &1))
      {:ok, %{imported: success_count, total: length(queries)}}
    end
  end

  defp validate_collection_data(%{"version" => _version, "queries" => queries})
       when is_list(queries) do
    {:ok, queries}
  end

  defp validate_collection_data(_), do: {:error, :invalid_format}

  # ============================================================================
  # Performance Analytics
  # ============================================================================

  @doc """
  Records query execution performance.
  """
  def record_execution(query_id, execution_time_ms, result_count) do
    case get_query(query_id) do
      nil ->
        {:error, :not_found}

      query ->
        query
        |> SavedQuery.increment_use_changeset()
        |> SavedQuery.update_performance_changeset(execution_time_ms)
        |> Repo.update()
    end
  end

  @doc """
  Gets performance statistics for a query.
  """
  def get_query_performance(query_id) do
    case get_query(query_id) do
      nil ->
        {:error, :not_found}

      query ->
        {:ok,
         %{
           avg_execution_time_ms: query.avg_execution_time_ms,
           last_execution_time_ms: query.last_execution_time_ms,
           use_count: query.use_count,
           last_used_at: query.last_used_at
         }}
    end
  end

  @doc """
  Lists slow queries (above threshold).
  """
  def list_slow_queries(threshold_ms \\ 5000, limit \\ 10) do
    from(sq in SavedQuery,
      where: sq.avg_execution_time_ms > ^threshold_ms,
      order_by: [desc: sq.avg_execution_time_ms],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Suggests query optimizations based on performance.
  """
  def suggest_optimizations(query_id) do
    case get_query_performance(query_id) do
      {:ok, stats} ->
        suggestions =
          []
          |> maybe_suggest_indexing(stats)
          |> maybe_suggest_time_range(stats)
          |> maybe_suggest_field_reduction(stats)

        {:ok, suggestions}

      error ->
        error
    end
  end

  defp maybe_suggest_indexing(suggestions, %{avg_execution_time_ms: time})
       when time > 10_000 do
    [
      "Consider adding database indexes on frequently queried fields"
      | suggestions
    ]
  end

  defp maybe_suggest_indexing(suggestions, _), do: suggestions

  defp maybe_suggest_time_range(suggestions, %{avg_execution_time_ms: time})
       when time > 5000 do
    [
      "Add a time range filter to reduce the data scanned"
      | suggestions
    ]
  end

  defp maybe_suggest_time_range(suggestions, _), do: suggestions

  defp maybe_suggest_field_reduction(suggestions, %{avg_execution_time_ms: time})
       when time > 3000 do
    [
      "Select only the fields you need instead of using SELECT *"
      | suggestions
    ]
  end

  defp maybe_suggest_field_reduction(suggestions, _), do: suggestions

  # ============================================================================
  # Categorization & Search
  # ============================================================================

  @doc """
  Lists all unique categories.
  """
  def list_categories do
    from(sq in SavedQuery, distinct: true, select: sq.category, where: not is_nil(sq.category))
    |> Repo.all()
    |> Enum.sort()
  end

  @doc """
  Lists all unique tags.
  """
  def list_tags do
    from(sq in SavedQuery, select: sq.tags)
    |> Repo.all()
    |> List.flatten()
    |> Enum.uniq()
    |> Enum.sort()
  end

  @doc """
  Lists queries grouped by MITRE tactic.
  """
  def list_by_mitre_tactic do
    queries = list_queries(templates_only: true)

    queries
    |> Enum.flat_map(fn q ->
      Enum.map(q.mitre_tactics || [], fn tactic -> {tactic, q} end)
    end)
    |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
  end

  # ============================================================================
  # Private Filters
  # ============================================================================

  defp filter_by_visibility(query, nil), do: query
  defp filter_by_visibility(query, visibility), do: where(query, [sq], sq.visibility == ^visibility)

  defp filter_by_category(query, nil), do: query
  defp filter_by_category(query, category), do: where(query, [sq], sq.category == ^category)

  defp filter_by_tags(query, nil), do: query
  defp filter_by_tags(query, tags) when is_list(tags) do
    where(query, [sq], fragment("? && ?", sq.tags, ^tags))
  end

  defp filter_by_mitre_tactic(query, nil), do: query
  defp filter_by_mitre_tactic(query, tactic) do
    where(query, [sq], ^tactic in sq.mitre_tactics)
  end

  defp filter_by_mitre_technique(query, nil), do: query
  defp filter_by_mitre_technique(query, technique) do
    where(query, [sq], ^technique in sq.mitre_techniques)
  end

  defp filter_by_user(query, nil), do: query
  defp filter_by_user(query, user_id), do: where(query, [sq], sq.created_by == ^user_id)

  defp filter_by_organization(query, nil), do: query

  defp filter_by_organization(query, org_id),
    do: where(query, [sq], sq.organization_id == ^org_id)

  defp filter_favorites_only(query, true, user_id) when not is_nil(user_id) do
    where(query, [sq], sq.is_favorite == true and sq.created_by == ^user_id)
  end

  defp filter_favorites_only(query, _, _), do: query

  defp filter_templates_only(query, true), do: where(query, [sq], sq.is_template == true)
  defp filter_templates_only(query, _), do: query

  defp search_text(query, nil), do: query
  defp search_text(query, ""), do: query

  defp search_text(query, search_term) do
    search_pattern = "%#{search_term}%"

    where(
      query,
      [sq],
      ilike(sq.name, ^search_pattern) or
        ilike(sq.description, ^search_pattern) or
        ilike(sq.query, ^search_pattern)
    )
  end

  defp maybe_limit(query, nil), do: query
  defp maybe_limit(query, limit), do: limit(query, ^limit)

  defp preload_associations(queries, nil), do: queries
  defp preload_associations(queries, preload) when is_list(preload) do
    Repo.preload(queries, preload)
  end

  defp preload_query(nil, _), do: nil
  defp preload_query(query, nil), do: query
  defp preload_query(query, preload) when is_list(preload) do
    Repo.preload(query, preload)
  end
end
