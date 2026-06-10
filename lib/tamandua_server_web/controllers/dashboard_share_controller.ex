defmodule TamanduaServerWeb.DashboardShareController do
  use TamanduaServerWeb, :controller

  alias TamanduaServer.{Dashboard, Dashboards}
  alias TamanduaServer.Dashboard.Share

  plug :put_layout, html: {TamanduaServerWeb.Layouts, :shared_dashboard}

  @doc """
  Shows a public shared dashboard.
  """
  def show(conn, %{"token" => token} = params) do
    with {:ok, share} <- validate_and_fetch_share(conn, token, params) do
      # Record the view
      session_id = get_or_create_session_id(conn)
      Dashboard.record_view_from_conn(conn, share.id, session_id)

      # Update last accessed timestamp
      Dashboard.update_last_accessed(share)

      # Fetch dashboard data
      dashboard_layout = Dashboards.get_layout(share.dashboard_layout_id)
      widgets = get_widgets_for_share(share, dashboard_layout)

      # Fetch widget data
      widget_data = fetch_widget_data(widgets)

      conn
      |> put_session(:shared_dashboard_session_id, session_id)
      |> render(:show,
        share: share,
        dashboard_layout: dashboard_layout,
        widgets: widgets,
        widget_data: widget_data,
        page_title: share.custom_title || dashboard_layout.name
      )
    else
      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> put_view(html: TamanduaServerWeb.ErrorHTML)
        |> render(:"404")

      {:error, :password_required} ->
        render(conn, :password_prompt, token: token)

      {:error, :invalid_password} ->
        conn
        |> put_flash(:error, "Invalid password")
        |> render(:password_prompt, token: token)

      {:error, :not_accessible} ->
        conn
        |> put_status(:forbidden)
        |> put_view(html: TamanduaServerWeb.ErrorHTML)
        |> render(:"403", message: "This dashboard share has expired or been revoked")

      {:error, :ip_not_allowed} ->
        conn
        |> put_status(:forbidden)
        |> put_view(html: TamanduaServerWeb.ErrorHTML)
        |> render(:"403", message: "Your IP address is not allowed to access this dashboard")

      {:error, :domain_not_allowed} ->
        conn
        |> put_status(:forbidden)
        |> put_view(html: TamanduaServerWeb.ErrorHTML)
        |> render(:"403", message: "This domain is not allowed to embed this dashboard")
    end
  end

  @doc """
  Handles password submission for protected shares.
  """
  def authenticate(conn, %{"token" => token, "password" => password}) do
    ip_address = get_client_ip(conn)

    case Dashboard.validate_access(token, password: password, ip_address: ip_address) do
      {:ok, _share} ->
        redirect(conn, to: ~p"/shared/dashboard/#{token}")

      {:error, _reason} ->
        conn
        |> put_flash(:error, "Invalid password")
        |> render(:password_prompt, token: token)
    end
  end

  defp validate_and_fetch_share(conn, token, params) do
    password = params["password"]
    ip_address = get_client_ip(conn)
    domain = get_referer_domain(conn)

    Dashboard.validate_access(token,
      password: password,
      ip_address: ip_address,
      domain: domain
    )
  end

  defp get_widgets_for_share(%Share{share_type: "full_dashboard"} = _share, dashboard_layout) do
    Dashboards.list_layout_widgets(dashboard_layout.id)
  end

  defp get_widgets_for_share(%Share{share_type: "specific_widgets", widget_ids: widget_ids}, _dashboard_layout) do
    Enum.map(widget_ids, fn widget_id ->
      Dashboards.get_widget(widget_id)
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp fetch_widget_data(widgets) do
    widgets
    |> Enum.map(fn widget ->
      case Dashboards.fetch_widget_data(widget) do
        {:ok, data} -> {widget.id, data}
        {:error, _} -> {widget.id, %{error: "Failed to load data"}}
      end
    end)
    |> Map.new()
  end

  defp get_or_create_session_id(conn) do
    case get_session(conn, :shared_dashboard_session_id) do
      nil ->
        :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)

      session_id ->
        session_id
    end
  end

  defp get_client_ip(conn) do
    case Plug.Conn.get_req_header(conn, "x-forwarded-for") do
      [ip | _] ->
        ip |> String.split(",") |> List.first() |> String.trim()

      [] ->
        case conn.remote_ip do
          {a, b, c, d} -> "#{a}.#{b}.#{c}.#{d}"
          _ -> "unknown"
        end
    end
  end

  defp get_referer_domain(conn) do
    case Plug.Conn.get_req_header(conn, "referer") do
      [referer | _] ->
        case URI.parse(referer) do
          %URI{host: host} when not is_nil(host) -> host
          _ -> nil
        end

      [] ->
        nil
    end
  end
end
