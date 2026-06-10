defmodule TamanduaServerWeb.PageController do
  use TamanduaServerWeb, :controller

  # Use raw layout for landing page (no sidebar/header)
  plug :put_layout, false

  def home(conn, _params) do
    # Redirect to app dashboard if logged in, otherwise show landing
    if conn.assigns[:current_user] do
      redirect(conn, to: ~p"/app/dashboard")
    else
      render(conn, :home)
    end
  end

  def not_found(conn, _params) do
    conn
    |> put_status(:not_found)
    |> put_view(html: TamanduaServerWeb.ErrorHTML)
    |> render(:"404")
  end
end
