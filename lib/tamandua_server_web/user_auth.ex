defmodule TamanduaServerWeb.UserAuth do
  @moduledoc """
  Authentication helpers for the web interface.
  """

  use TamanduaServerWeb, :verified_routes

  import Plug.Conn
  import Phoenix.Controller, except: [redirect: 2]
  require Logger

  alias TamanduaServer.Accounts

  @doc """
  Used for LiveView authentication via on_mount callback.
  """
  def on_mount(:ensure_authenticated, _params, session, socket) do
    socket = mount_current_user(socket, session)

    if socket.assigns.current_user do
      {:cont, socket}
    else
      socket =
        socket
        |> Phoenix.LiveView.put_flash(:error, "You must log in to access this page.")
        |> Phoenix.LiveView.redirect(to: ~p"/login")

      {:halt, socket}
    end
  end

  def on_mount(:mount_current_user, _params, session, socket) do
    {:cont, mount_current_user(socket, session)}
  end

  def on_mount(:redirect_if_user_is_authenticated, _params, session, socket) do
    socket = mount_current_user(socket, session)

    if socket.assigns.current_user do
      {:halt, Phoenix.LiveView.redirect(socket, to: ~p"/app/dashboard")}
    else
      {:cont, socket}
    end
  end

  defp mount_current_user(socket, session) do
    Phoenix.Component.assign_new(socket, :current_user, fn ->
      if user_token = session["user_token"] do
        Accounts.get_user_by_session_token(user_token)
      end
    end)
  end

  @doc """
  Logs the user in by storing the user token in the session.
  """
  def log_in_user(conn, user, _params \\ %{}) do
    touch_last_login(user)
    token = Accounts.generate_user_session_token(user)

    conn
    |> renew_session()
    |> put_token_in_session(token)
    |> Phoenix.Controller.redirect(to: signed_in_path(conn))
  end

  defp renew_session(conn) do
    delete_csrf_token()

    conn
    |> configure_session(renew: true)
    |> clear_session()
  end

  @doc """
  Logs the user out.
  """
  def log_out_user(conn) do
    user_token = get_session(conn, :user_token)
    user_token && Accounts.delete_user_session_token(user_token)

    if live_socket_id = get_session(conn, :live_socket_id) do
      TamanduaServerWeb.Endpoint.broadcast(live_socket_id, "disconnect", %{})
    end

    conn
    |> renew_session()
    |> Phoenix.Controller.redirect(to: ~p"/login")
  end

  @doc """
  Authenticates the user by looking into the session.
  """
  def fetch_current_user(conn, _opts) do
    {user_token, conn} = ensure_user_token(conn)
    user = user_token && Accounts.get_user_by_session_token(user_token)
    assign(conn, :current_user, user)
  end

  defp ensure_user_token(conn) do
    if token = get_session(conn, :user_token) do
      {token, conn}
    else
      {nil, conn}
    end
  end

  @doc """
  Plug that requires the user to be authenticated.
  """
  def require_authenticated_user(conn, _opts) do
    if conn.assigns[:current_user] do
      conn
    else
      conn
      |> put_flash(:error, "You must log in to access this page.")
      |> Phoenix.Controller.redirect(to: ~p"/login")
      |> halt()
    end
  end

  @doc """
  Plug that redirects authenticated users away from auth pages.
  """
  def redirect_if_user_is_authenticated(conn, _opts) do
    if conn.assigns[:current_user] do
      conn
      |> Phoenix.Controller.redirect(to: signed_in_path(conn))
      |> halt()
    else
      conn
    end
  end

  defp put_token_in_session(conn, token) do
    conn
    |> put_session(:user_token, token)
    |> put_session(:live_socket_id, "users_sessions:#{Base.url_encode64(token)}")
  end

  defp touch_last_login(user) do
    case Accounts.update_last_login(user) do
      {:ok, _user} ->
        :ok

      {:error, reason} ->
        Logger.warning(
          "Unable to update last_login_at for user #{inspect(user.id)}: #{inspect(reason)}"
        )

        :ok
    end
  rescue
    exception ->
      Logger.warning(
        "Unable to update last_login_at for user #{inspect(user.id)}: #{Exception.message(exception)}"
      )

      :ok
  end

  defp signed_in_path(_conn), do: ~p"/app/dashboard"
end
