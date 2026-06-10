defmodule TamanduaServerWeb.Plugs.CSRFCookie do
  @moduledoc """
  Plug that sets CSRF token as a cookie for Inertia.js/React to use.
  """

  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    token = Plug.CSRFProtection.get_csrf_token()

    conn
    |> put_resp_cookie("XSRF-TOKEN", token,
      http_only: false,
      same_site: "Lax"
    )
  end
end
