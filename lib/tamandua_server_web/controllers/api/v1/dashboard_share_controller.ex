defmodule TamanduaServerWeb.API.V1.DashboardShareController do
  @moduledoc """
  REST API for programmatic dashboard share management.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.{Dashboard, Dashboards}
  alias TamanduaServer.Dashboard.Share

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Lists all shares for the authenticated user.
  """
  def index(conn, _params) do
    user = conn.assigns.current_user
    shares = Dashboard.list_shares_by_user(user.id)

    render(conn, :index, shares: shares)
  end

  @doc """
  Creates a new dashboard share.
  """
  def create(conn, %{"share" => share_params}) do
    user = conn.assigns.current_user

    attrs =
      share_params
      |> Map.put("created_by_user_id", user.id)
      |> parse_expiry()

    with {:ok, share} <- Dashboard.create_share(attrs) do
      share_url = Share.share_url(share, TamanduaServerWeb.Endpoint.url())
      embed_code = Share.generate_embed_code(share, TamanduaServerWeb.Endpoint.url())

      conn
      |> put_status(:created)
      |> render(:show,
        share: share,
        share_url: share_url,
        embed_code: embed_code
      )
    end
  end

  @doc """
  Shows a specific share.
  """
  def show(conn, %{"id" => id}) do
    user = conn.assigns.current_user

    with {:ok, share} <- fetch_user_share(id, user.id) do
      share_url = Share.share_url(share, TamanduaServerWeb.Endpoint.url())
      embed_code = Share.generate_embed_code(share, TamanduaServerWeb.Endpoint.url())

      render(conn, :show,
        share: share,
        share_url: share_url,
        embed_code: embed_code
      )
    end
  end

  @doc """
  Updates a share.
  """
  def update(conn, %{"id" => id, "share" => share_params}) do
    user = conn.assigns.current_user

    with {:ok, share} <- fetch_user_share(id, user.id),
         attrs <- parse_expiry(share_params),
         {:ok, updated_share} <- Dashboard.update_share(share, attrs) do
      share_url = Share.share_url(updated_share, TamanduaServerWeb.Endpoint.url())
      embed_code = Share.generate_embed_code(updated_share, TamanduaServerWeb.Endpoint.url())

      render(conn, :show,
        share: updated_share,
        share_url: share_url,
        embed_code: embed_code
      )
    end
  end

  @doc """
  Deletes a share.
  """
  def delete(conn, %{"id" => id}) do
    user = conn.assigns.current_user

    with {:ok, share} <- fetch_user_share(id, user.id),
         {:ok, _share} <- Dashboard.delete_share(share) do
      send_resp(conn, :no_content, "")
    end
  end

  @doc """
  Revokes a share.
  """
  def revoke(conn, %{"id" => id}) do
    user = conn.assigns.current_user

    with {:ok, share} <- fetch_user_share(id, user.id),
         {:ok, revoked_share} <- Dashboard.revoke_share(share) do
      render(conn, :show,
        share: revoked_share,
        share_url: nil,
        embed_code: nil
      )
    end
  end

  @doc """
  Activates a previously revoked share.
  """
  def activate(conn, %{"id" => id}) do
    user = conn.assigns.current_user

    with {:ok, share} <- fetch_user_share(id, user.id),
         {:ok, activated_share} <- Dashboard.activate_share(share) do
      share_url = Share.share_url(activated_share, TamanduaServerWeb.Endpoint.url())
      embed_code = Share.generate_embed_code(activated_share, TamanduaServerWeb.Endpoint.url())

      render(conn, :show,
        share: activated_share,
        share_url: share_url,
        embed_code: embed_code
      )
    end
  end

  @doc """
  Regenerates the share token (creates a new URL).
  """
  def regenerate_token(conn, %{"id" => id}) do
    user = conn.assigns.current_user

    with {:ok, share} <- fetch_user_share(id, user.id),
         {:ok, new_share} <- Dashboard.regenerate_token(share) do
      share_url = Share.share_url(new_share, TamanduaServerWeb.Endpoint.url())
      embed_code = Share.generate_embed_code(new_share, TamanduaServerWeb.Endpoint.url())

      render(conn, :show,
        share: new_share,
        share_url: share_url,
        embed_code: embed_code
      )
    end
  end

  @doc """
  Gets analytics for a specific share.
  """
  def analytics(conn, %{"id" => id, "time_range" => time_range}) do
    user = conn.assigns.current_user
    time_range_atom = String.to_existing_atom(time_range)

    with {:ok, share} <- fetch_user_share(id, user.id) do
      analytics = Dashboard.get_share_analytics(share.id, time_range: time_range_atom)

      render(conn, :analytics, analytics: analytics)
    end
  end

  def analytics(conn, %{"id" => id}) do
    analytics(conn, %{"id" => id, "time_range" => "last_30_days"})
  end

  @doc """
  Gets aggregate analytics for all user shares.
  """
  def user_analytics(conn, %{"time_range" => time_range}) do
    user = conn.assigns.current_user
    time_range_atom = String.to_existing_atom(time_range)

    analytics = Dashboard.get_user_analytics(user.id, time_range: time_range_atom)

    render(conn, :user_analytics, analytics: analytics)
  end

  def user_analytics(conn, _params) do
    user_analytics(conn, %{"time_range" => "last_30_days"})
  end

  # Private functions

  defp fetch_user_share(share_id, user_id) do
    case Dashboard.get_share(share_id) do
      nil ->
        {:error, :not_found}

      share ->
        if share.created_by_user_id == user_id do
          {:ok, share}
        else
          {:error, :forbidden}
        end
    end
  end

  defp parse_expiry(%{"expiry_preset" => preset} = params) when preset in ["1_day", "7_days", "30_days", "never"] do
    expires_at =
      case preset do
        "1_day" -> DateTime.add(DateTime.utc_now(), 1, :day)
        "7_days" -> DateTime.add(DateTime.utc_now(), 7, :day)
        "30_days" -> DateTime.add(DateTime.utc_now(), 30, :day)
        "never" -> nil
      end

    params
    |> Map.delete("expiry_preset")
    |> Map.put("expires_at", expires_at)
  end

  defp parse_expiry(params), do: params
end
