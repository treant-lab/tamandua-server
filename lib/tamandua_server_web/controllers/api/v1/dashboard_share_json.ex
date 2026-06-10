defmodule TamanduaServerWeb.API.V1.DashboardShareJSON do
  @moduledoc """
  JSON views for dashboard share API.
  """

  alias TamanduaServer.Dashboard.Share

  def index(%{shares: shares}) do
    %{
      data: Enum.map(shares, &share_summary/1)
    }
  end

  def show(%{share: share, share_url: share_url, embed_code: embed_code}) do
    %{
      data:
        share
        |> share_detail()
        |> maybe_add_urls(share_url, embed_code)
    }
  end

  def analytics(%{analytics: analytics}) do
    %{
      data: %{
        total_views: analytics.total_views,
        unique_visitors: analytics.unique_visitors,
        avg_duration_seconds: analytics.avg_duration_seconds,
        views_by_date:
          Enum.map(analytics.views_by_date, fn view ->
            %{
              date: view.date,
              count: view.count
            }
          end),
        top_referrers:
          Enum.map(analytics.top_referrers, fn ref ->
            %{
              referrer: ref.referrer,
              count: ref.count
            }
          end),
        top_countries:
          Enum.map(analytics.top_countries, fn country ->
            %{
              country: country.country,
              count: country.count
            }
          end)
      }
    }
  end

  def user_analytics(%{analytics: analytics}) do
    %{
      data: %{
        total_shares: analytics.total_shares,
        total_views: analytics.total_views,
        unique_visitors: analytics.unique_visitors,
        shares: Enum.map(analytics.shares, &share_with_views/1)
      }
    }
  end

  # Private functions

  defp share_summary(share) do
    %{
      id: share.id,
      dashboard_layout_id: share.dashboard_layout_id,
      share_token: share.share_token,
      share_type: share.share_type,
      custom_title: share.custom_title,
      is_active: share.is_active,
      expires_at: share.expires_at,
      revoked_at: share.revoked_at,
      last_accessed_at: share.last_accessed_at,
      status: share_status(share),
      inserted_at: share.inserted_at,
      updated_at: share.updated_at
    }
  end

  defp share_detail(share) do
    %{
      id: share.id,
      dashboard_layout_id: share.dashboard_layout_id,
      dashboard_layout: dashboard_layout_summary(share.dashboard_layout),
      share_token: share.share_token,
      share_type: share.share_type,
      widget_ids: share.widget_ids,
      custom_title: share.custom_title,
      is_active: share.is_active,
      password_protected: !is_nil(share.password_hash),
      expires_at: share.expires_at,
      allowed_ips: share.allowed_ips,
      allowed_domains: share.allowed_domains,
      show_header: share.show_header,
      show_footer: share.show_footer,
      show_watermark: share.show_watermark,
      branding_config: share.branding_config,
      refresh_interval: share.refresh_interval,
      embed_width: share.embed_width,
      embed_height: share.embed_height,
      transparent_background: share.transparent_background,
      description: share.description,
      last_accessed_at: share.last_accessed_at,
      revoked_at: share.revoked_at,
      status: share_status(share),
      inserted_at: share.inserted_at,
      updated_at: share.updated_at
    }
  end

  defp share_with_views(share) do
    share
    |> share_summary()
    |> Map.put(:view_count, share.view_count)
  end

  defp maybe_add_urls(share_data, nil, nil), do: share_data

  defp maybe_add_urls(share_data, share_url, embed_code) do
    share_data
    |> Map.put(:share_url, share_url)
    |> Map.put(:embed_code, embed_code)
  end

  defp dashboard_layout_summary(nil), do: nil

  defp dashboard_layout_summary(layout) do
    %{
      id: layout.id,
      name: layout.name,
      description: layout.description
    }
  end

  defp share_status(share) do
    cond do
      !is_nil(share.revoked_at) -> "revoked"
      !share.is_active -> "inactive"
      Share.accessible?(share) -> "active"
      true -> "expired"
    end
  end
end
