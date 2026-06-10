defmodule TamanduaServer.Dashboard.ShareManager do
  @moduledoc """
  Manager for dashboard sharing operations.
  Handles creating, updating, revoking shares and tracking analytics.
  """

  import Ecto.Query, warn: false
  alias TamanduaServer.Repo
  alias TamanduaServer.Dashboard.{Share, ShareView}
  alias TamanduaServer.Dashboards.Layout

  require Logger

  # Share CRUD Operations

  @doc """
  Lists all shares for a specific dashboard layout.
  """
  def list_shares_for_dashboard(dashboard_layout_id) do
    Share
    |> where([s], s.dashboard_layout_id == ^dashboard_layout_id)
    |> order_by([s], desc: s.inserted_at)
    |> Repo.all()
  end

  @doc """
  Lists all shares created by a user.
  """
  def list_shares_by_user(user_id) do
    Share
    |> where([s], s.created_by_user_id == ^user_id)
    |> order_by([s], desc: s.inserted_at)
    |> preload(:dashboard_layout)
    |> Repo.all()
  end

  @doc """
  Gets a share by its token.
  """
  def get_share_by_token(token) do
    Share
    |> where([s], s.share_token == ^token)
    |> preload([:dashboard_layout, :created_by_user])
    |> Repo.one()
  end

  @doc """
  Gets a share by ID.
  """
  def get_share(id) do
    Share
    |> preload([:dashboard_layout, :created_by_user])
    |> Repo.get(id)
  end

  @doc """
  Creates a new dashboard share.
  """
  def create_share(attrs \\ %{}) do
    %Share{}
    |> Share.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a dashboard share.
  """
  def update_share(%Share{} = share, attrs) do
    share
    |> Share.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a dashboard share.
  """
  def delete_share(%Share{} = share) do
    Repo.delete(share)
  end

  @doc """
  Revokes a share by setting revoked_at timestamp.
  """
  def revoke_share(%Share{} = share) do
    share
    |> Ecto.Changeset.change(revoked_at: DateTime.utc_now())
    |> Repo.update()
  end

  @doc """
  Activates a previously revoked share.
  """
  def activate_share(%Share{} = share) do
    share
    |> Ecto.Changeset.change(revoked_at: nil, is_active: true)
    |> Repo.update()
  end

  @doc """
  Toggles share active status.
  """
  def toggle_active(%Share{} = share) do
    share
    |> Ecto.Changeset.change(is_active: !share.is_active)
    |> Repo.update()
  end

  @doc """
  Updates last accessed timestamp.
  """
  def update_last_accessed(%Share{} = share) do
    share
    |> Ecto.Changeset.change(last_accessed_at: DateTime.utc_now())
    |> Repo.update()
  end

  @doc """
  Regenerates the share token (creates a new URL).
  """
  def regenerate_token(%Share{} = share) do
    share
    |> Ecto.Changeset.change(share_token: Share.generate_share_token())
    |> Repo.update()
  end

  # Access Validation

  @doc """
  Validates access to a share based on password, IP, expiry, etc.
  """
  def validate_access(share_token, opts \\ []) do
    password = Keyword.get(opts, :password)
    ip_address = Keyword.get(opts, :ip_address)
    domain = Keyword.get(opts, :domain)

    with {:ok, share} <- fetch_share(share_token),
         :ok <- check_accessible(share),
         :ok <- check_password(share, password),
         :ok <- check_ip(share, ip_address),
         :ok <- check_domain(share, domain) do
      {:ok, share}
    end
  end

  defp fetch_share(token) do
    case get_share_by_token(token) do
      nil -> {:error, :not_found}
      share -> {:ok, share}
    end
  end

  defp check_accessible(share) do
    if Share.accessible?(share) do
      :ok
    else
      {:error, :not_accessible}
    end
  end

  defp check_password(share, nil) do
    if share.password_hash do
      {:error, :password_required}
    else
      :ok
    end
  end

  defp check_password(share, password) do
    if Share.verify_password(share, password) do
      :ok
    else
      {:error, :invalid_password}
    end
  end

  defp check_ip(share, nil), do: :ok

  defp check_ip(share, ip_address) do
    if Share.ip_allowed?(share, ip_address) do
      :ok
    else
      {:error, :ip_not_allowed}
    end
  end

  defp check_domain(share, nil), do: :ok

  defp check_domain(share, domain) do
    if Share.domain_allowed?(share, domain) do
      :ok
    else
      {:error, :domain_not_allowed}
    end
  end

  # Analytics

  @doc """
  Records a view of a shared dashboard.
  """
  def record_view(dashboard_share_id, attrs \\ %{}) do
    attrs = Map.put(attrs, :dashboard_share_id, dashboard_share_id)

    %ShareView{}
    |> ShareView.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Records a view from a Plug.Conn.
  """
  def record_view_from_conn(conn, dashboard_share_id, session_id \\ nil) do
    view_changeset = ShareView.from_conn(conn, dashboard_share_id, session_id)

    # Attempt geographic lookup in background
    case Repo.insert(view_changeset) do
      {:ok, view} ->
        Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
          enrich_view_geo(view)
        end)

        {:ok, view}

      error ->
        error
    end
  end

  defp enrich_view_geo(%ShareView{} = view) do
    if view.ip_address do
      case lookup_geo(view.ip_address) do
        {:ok, geo_data} ->
          view
          |> Ecto.Changeset.change(geo_data)
          |> Repo.update()

        {:error, reason} ->
          Logger.debug("Failed to lookup geo for IP #{view.ip_address}: #{inspect(reason)}")
          :ok
      end
    end
  end

  defp lookup_geo(_ip_address) do
    # TODO: Integrate with GeoIP service (MaxMind, ipstack, etc.)
    # For now, return empty
    {:ok, %{country: nil, city: nil}}
  end

  @doc """
  Gets analytics for a specific share.
  """
  def get_share_analytics(share_id, opts \\ []) do
    time_range = Keyword.get(opts, :time_range, :last_30_days)

    {from, to} = get_time_range(time_range)

    views_query =
      from v in ShareView,
        where: v.dashboard_share_id == ^share_id,
        where: v.viewed_at >= ^from and v.viewed_at <= ^to

    total_views = Repo.aggregate(views_query, :count, :id)

    unique_visitors =
      views_query
      |> select([v], v.session_id)
      |> distinct(true)
      |> Repo.aggregate(:count, :session_id)

    views_by_date =
      views_query
      |> group_by([v], fragment("DATE(?)", v.viewed_at))
      |> select([v], %{
        date: fragment("DATE(?)", v.viewed_at),
        count: count(v.id)
      })
      |> order_by([v], fragment("DATE(?)", v.viewed_at))
      |> Repo.all()

    top_referrers =
      views_query
      |> where([v], not is_nil(v.referrer))
      |> group_by([v], v.referrer)
      |> select([v], %{referrer: v.referrer, count: count(v.id)})
      |> order_by([v], desc: count(v.id))
      |> limit(10)
      |> Repo.all()

    top_countries =
      views_query
      |> where([v], not is_nil(v.country))
      |> group_by([v], v.country)
      |> select([v], %{country: v.country, count: count(v.id)})
      |> order_by([v], desc: count(v.id))
      |> limit(10)
      |> Repo.all()

    avg_duration =
      views_query
      |> where([v], not is_nil(v.duration_seconds))
      |> Repo.aggregate(:avg, :duration_seconds)

    %{
      total_views: total_views,
      unique_visitors: unique_visitors,
      views_by_date: views_by_date,
      top_referrers: top_referrers,
      top_countries: top_countries,
      avg_duration_seconds: avg_duration
    }
  end

  @doc """
  Gets aggregate analytics for all shares by a user.
  """
  def get_user_analytics(user_id, opts \\ []) do
    time_range = Keyword.get(opts, :time_range, :last_30_days)
    {from, to} = get_time_range(time_range)

    shares = list_shares_by_user(user_id)
    share_ids = Enum.map(shares, & &1.id)

    views_query =
      from v in ShareView,
        where: v.dashboard_share_id in ^share_ids,
        where: v.viewed_at >= ^from and v.viewed_at <= ^to

    total_views = Repo.aggregate(views_query, :count, :id)
    unique_visitors = views_query |> distinct([v], v.session_id) |> Repo.aggregate(:count, :session_id)

    shares_with_stats =
      Enum.map(shares, fn share ->
        share_views =
          from(v in ShareView,
            where: v.dashboard_share_id == ^share.id,
            where: v.viewed_at >= ^from and v.viewed_at <= ^to
          )
          |> Repo.aggregate(:count, :id)

        Map.put(share, :view_count, share_views)
      end)
      |> Enum.sort_by(& &1.view_count, :desc)

    %{
      total_shares: length(shares),
      total_views: total_views,
      unique_visitors: unique_visitors,
      shares: shares_with_stats
    }
  end

  defp get_time_range(:last_7_days) do
    to = DateTime.utc_now()
    from = DateTime.add(to, -7, :day)
    {from, to}
  end

  defp get_time_range(:last_30_days) do
    to = DateTime.utc_now()
    from = DateTime.add(to, -30, :day)
    {from, to}
  end

  defp get_time_range(:last_90_days) do
    to = DateTime.utc_now()
    from = DateTime.add(to, -90, :day)
    {from, to}
  end

  defp get_time_range(:all_time) do
    from = DateTime.from_unix!(0)
    to = DateTime.utc_now()
    {from, to}
  end

  defp get_time_range(_), do: get_time_range(:last_30_days)

  # Bulk Operations

  @doc """
  Revokes all shares for a dashboard layout.
  """
  def revoke_all_shares_for_dashboard(dashboard_layout_id) do
    now = DateTime.utc_now()

    from(s in Share,
      where: s.dashboard_layout_id == ^dashboard_layout_id,
      where: is_nil(s.revoked_at)
    )
    |> Repo.update_all(set: [revoked_at: now])
  end

  @doc """
  Cleans up expired shares (sets is_active to false).
  """
  def cleanup_expired_shares do
    now = DateTime.utc_now()

    from(s in Share,
      where: s.is_active == true,
      where: not is_nil(s.expires_at),
      where: s.expires_at < ^now
    )
    |> Repo.update_all(set: [is_active: false])
  end
end
