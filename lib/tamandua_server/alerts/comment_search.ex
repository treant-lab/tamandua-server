defmodule TamanduaServer.Alerts.CommentSearch do
  @moduledoc """
  Advanced search functionality for comments with full-text search,
  filtering, and sorting capabilities.
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.Comment
  alias TamanduaServer.Accounts.User

  @doc """
  Searches comments with advanced filtering options.

  ## Options

    * `:query` - Full-text search query
    * `:author_id` - Filter by comment author
    * `:mentioned_user_id` - Filter by mentioned user
    * `:alert_id` - Filter by alert
    * `:date_from` - Filter comments after this date
    * `:date_to` - Filter comments before this date
    * `:has_attachments` - Filter comments with/without attachments
    * `:is_pinned` - Filter pinned comments
    * `:sort_by` - Sort field (:inserted_at, :updated_at, :relevance)
    * `:sort_order` - Sort order (:asc, :desc)
    * `:limit` - Maximum results (default: 50)
    * `:offset` - Pagination offset

  ## Examples

      CommentSearch.search(org_id, query: "malware", author_id: user_id)
      CommentSearch.search(org_id, mentioned_user_id: user_id, date_from: ~U[2024-01-01 00:00:00Z])

  """
  def search(organization_id, opts \\ []) do
    query = from c in Comment, where: c.organization_id == ^organization_id

    query
    |> apply_search_query(opts[:query])
    |> apply_author_filter(opts[:author_id])
    |> apply_mentioned_filter(opts[:mentioned_user_id])
    |> apply_alert_filter(opts[:alert_id])
    |> apply_date_range_filter(opts[:date_from], opts[:date_to])
    |> apply_attachment_filter(opts[:has_attachments])
    |> apply_pinned_filter(opts[:is_pinned])
    |> apply_deleted_filter(opts[:include_deleted])
    |> apply_sorting(opts[:sort_by], opts[:sort_order])
    |> apply_pagination(opts[:limit], opts[:offset])
    |> preload([:user, :alert, :attachments, :reactions])
    |> Repo.all()
  end

  @doc """
  Searches comments within a specific alert.
  """
  def search_alert_comments(alert_id, opts \\ []) do
    query = from c in Comment, where: c.alert_id == ^alert_id

    query
    |> apply_search_query(opts[:query])
    |> apply_author_filter(opts[:author_id])
    |> apply_deleted_filter(opts[:include_deleted])
    |> apply_sorting(opts[:sort_by], opts[:sort_order])
    |> apply_pagination(opts[:limit], opts[:offset])
    |> preload([:user, :attachments, :reactions])
    |> Repo.all()
  end

  @doc """
  Searches for comments mentioning a specific user.
  """
  def search_mentions(user_id, opts \\ []) do
    user = Repo.get!(User, user_id)

    query =
      from c in Comment,
        where: c.organization_id == ^user.organization_id,
        where: ^user_id in c.mentioned_user_ids or ilike(c.content, ^"%@#{user.email}%")

    query
    |> apply_search_query(opts[:query])
    |> apply_date_range_filter(opts[:date_from], opts[:date_to])
    |> apply_deleted_filter(false)
    |> apply_sorting(opts[:sort_by] || :inserted_at, opts[:sort_order] || :desc)
    |> apply_pagination(opts[:limit], opts[:offset])
    |> preload([:user, :alert])
    |> Repo.all()
  end

  @doc """
  Gets comment statistics for an organization.
  """
  def get_stats(organization_id) do
    base_query = from c in Comment, where: c.organization_id == ^organization_id

    %{
      total_comments: get_count(base_query),
      comments_today: get_count(where(base_query, [c], c.inserted_at >= ^today())),
      comments_this_week: get_count(where(base_query, [c], c.inserted_at >= ^week_ago())),
      pinned_comments: get_count(where(base_query, [c], c.is_pinned == true)),
      deleted_comments: get_count(where(base_query, [c], c.is_deleted == true)),
      total_reactions: get_reaction_count(organization_id),
      top_commenters: get_top_commenters(organization_id, limit: 5),
      comments_by_day: get_comments_by_day(organization_id, days: 30)
    }
  end

  @doc """
  Exports search results to various formats.
  """
  def export(comments, format \\ :json)

  def export(comments, :json) do
    comments
    |> Enum.map(&format_comment_for_export/1)
    |> Jason.encode!()
  end

  def export(comments, :csv) do
    headers = ["Timestamp", "Author", "Alert", "Content", "Reactions", "Attachments"]

    rows =
      Enum.map(comments, fn comment ->
        [
          DateTime.to_iso8601(comment.inserted_at),
          comment.user.email,
          comment.alert.title,
          String.slice(comment.content, 0..200),
          length(comment.reactions),
          length(comment.attachments)
        ]
      end)

    NimbleCSV.RFC4180.dump_to_iodata([headers | rows])
  end

  ## Private Functions

  defp apply_search_query(query, nil), do: query

  defp apply_search_query(query, search_term) when is_binary(search_term) do
    # Use PostgreSQL full-text search with trigram similarity
    from c in query,
      where:
        fragment(
          "? % ?",
          c.content,
          ^search_term
        ) or
          ilike(c.content, ^"%#{search_term}%")
  end

  defp apply_author_filter(query, nil), do: query
  defp apply_author_filter(query, author_id), do: where(query, [c], c.user_id == ^author_id)

  defp apply_mentioned_filter(query, nil), do: query

  defp apply_mentioned_filter(query, user_id) do
    where(query, [c], ^user_id in c.mentioned_user_ids)
  end

  defp apply_alert_filter(query, nil), do: query
  defp apply_alert_filter(query, alert_id), do: where(query, [c], c.alert_id == ^alert_id)

  defp apply_date_range_filter(query, nil, nil), do: query

  defp apply_date_range_filter(query, date_from, nil) when not is_nil(date_from) do
    where(query, [c], c.inserted_at >= ^date_from)
  end

  defp apply_date_range_filter(query, nil, date_to) when not is_nil(date_to) do
    where(query, [c], c.inserted_at <= ^date_to)
  end

  defp apply_date_range_filter(query, date_from, date_to) do
    where(query, [c], c.inserted_at >= ^date_from and c.inserted_at <= ^date_to)
  end

  defp apply_attachment_filter(query, nil), do: query
  defp apply_attachment_filter(query, true), do: where(query, [c], fragment("? > 0", c.attachments))
  defp apply_attachment_filter(query, false), do: where(query, [c], fragment("? = 0", c.attachments))

  defp apply_pinned_filter(query, nil), do: query
  defp apply_pinned_filter(query, is_pinned), do: where(query, [c], c.is_pinned == ^is_pinned)

  defp apply_deleted_filter(query, true), do: query
  defp apply_deleted_filter(query, _), do: where(query, [c], c.is_deleted == false)

  defp apply_sorting(query, nil, _), do: order_by(query, [c], desc: c.inserted_at)
  defp apply_sorting(query, :inserted_at, :asc), do: order_by(query, [c], asc: c.inserted_at)
  defp apply_sorting(query, :inserted_at, _), do: order_by(query, [c], desc: c.inserted_at)
  defp apply_sorting(query, :updated_at, :asc), do: order_by(query, [c], asc: c.edited_at)
  defp apply_sorting(query, :updated_at, _), do: order_by(query, [c], desc: c.edited_at)

  defp apply_sorting(query, :relevance, _) do
    # Sort by trigram similarity when search query is present
    order_by(query, [c], desc: fragment("word_similarity(?, ?)", c.content, ""))
  end

  defp apply_pagination(query, nil, nil), do: limit(query, 50)
  defp apply_pagination(query, limit, nil) when is_integer(limit), do: limit(query, ^limit)

  defp apply_pagination(query, nil, offset) when is_integer(offset) do
    query |> offset(^offset) |> limit(50)
  end

  defp apply_pagination(query, limit, offset) when is_integer(limit) and is_integer(offset) do
    query |> offset(^offset) |> limit(^limit)
  end

  defp get_count(query) do
    Repo.aggregate(query, :count)
  end

  defp get_reaction_count(organization_id) do
    from(r in TamanduaServer.Alerts.CommentReaction,
      join: c in Comment,
      on: r.comment_id == c.id,
      where: c.organization_id == ^organization_id
    )
    |> Repo.aggregate(:count)
  end

  defp get_top_commenters(organization_id, opts) do
    limit = Keyword.get(opts, :limit, 5)

    from(c in Comment,
      where: c.organization_id == ^organization_id,
      where: c.is_deleted == false,
      group_by: c.user_id,
      select: {c.user_id, count(c.id)},
      order_by: [desc: count(c.id)],
      limit: ^limit
    )
    |> Repo.all()
    |> Enum.map(fn {user_id, count} ->
      user = Repo.get!(User, user_id)
      %{user: user, comment_count: count}
    end)
  end

  defp get_comments_by_day(organization_id, opts) do
    days = Keyword.get(opts, :days, 30)
    start_date = DateTime.utc_now() |> DateTime.add(-days, :day)

    from(c in Comment,
      where: c.organization_id == ^organization_id,
      where: c.inserted_at >= ^start_date,
      where: c.is_deleted == false,
      select: %{
        date: fragment("DATE(?)", c.inserted_at),
        count: count(c.id)
      },
      group_by: fragment("DATE(?)", c.inserted_at),
      order_by: [asc: fragment("DATE(?)", c.inserted_at)]
    )
    |> Repo.all()
  end

  defp format_comment_for_export(comment) do
    %{
      id: comment.id,
      content: comment.content,
      author: %{
        id: comment.user.id,
        email: comment.user.email,
        name: comment.user.name
      },
      alert: %{
        id: comment.alert.id,
        title: comment.alert.title
      },
      reactions: Enum.map(comment.reactions, & &1.reaction_type),
      attachments:
        Enum.map(comment.attachments, fn a ->
          %{filename: a.filename, type: a.attachment_type}
        end),
      is_pinned: comment.is_pinned,
      is_deleted: comment.is_deleted,
      edit_count: comment.edit_count,
      inserted_at: comment.inserted_at,
      edited_at: comment.edited_at
    }
  end

  defp today do
    DateTime.utc_now()
    |> DateTime.to_date()
    |> DateTime.new!(~T[00:00:00])
  end

  defp week_ago do
    DateTime.utc_now() |> DateTime.add(-7, :day)
  end
end
