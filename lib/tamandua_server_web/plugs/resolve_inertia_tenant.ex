defmodule TamanduaServerWeb.Plugs.ResolveInertiaTenant do
  @moduledoc """
  Proves the single active tenant bound to the authenticated Inertia user.

  Request-controlled tenant candidates (session values, headers, params and
  unrelated assigns) are deliberately ignored.
  """

  import Plug.Conn

  alias TamanduaServer.Accounts
  alias TamanduaServer.Accounts.User

  def init(opts), do: opts

  def call(%Plug.Conn{assigns: %{current_user: %User{} = current_user}} = conn, _opts) do
    case Accounts.resolve_active_user_organization(
           current_user.id,
           current_user.organization_id
         ) do
      {:ok, %User{} = canonical_user, organization} ->
        conn
        |> assign(:current_user, canonical_user)
        |> assign(:current_organization, organization)
        |> assign(:current_organization_id, organization.id)

      _ ->
        forbid(conn)
    end
  end

  def call(conn, _opts), do: forbid(conn)

  defp forbid(conn) do
    conn
    |> put_resp_content_type("text/plain")
    |> send_resp(:forbidden, "Forbidden")
    |> halt()
  end
end
