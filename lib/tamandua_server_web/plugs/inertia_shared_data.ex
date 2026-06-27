defmodule TamanduaServerWeb.Plugs.InertiaSharedData do
  @moduledoc """
  Plug to share common data with all Inertia responses.
  This data is available in every React component via usePage().
  """

  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    user = conn.assigns[:current_user]

    shared_data = %{
      auth: build_auth(user),
      is_super_admin: super_admin?(user),
      flash: build_flash(conn),
      csrf_token: Plug.CSRFProtection.get_csrf_token(),
      app: %{
        name: "Tamandua EDR",
        version: Application.spec(:tamandua_server, :vsn) |> to_string()
      }
    }

    # Put shared data directly in conn.private[:inertia_shared]
    existing = conn.private[:inertia_shared] || %{}
    put_private(conn, :inertia_shared, Map.merge(existing, shared_data))
  end

  defp build_auth(nil), do: %{user: nil, socket_token: nil, socketToken: nil}

  defp build_auth(user) do
    socket_token = build_socket_token(user)

    %{
      user: %{
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        is_super_admin: super_admin?(user)
      },
      socket_token: socket_token,
      socketToken: socket_token
    }
  end

  defp build_socket_token(user) do
    case TamanduaServer.Guardian.encode_and_sign(
           user,
           %{"scope" => "dashboard_socket"},
           ttl: {2, :hour}
         ) do
      {:ok, token, _claims} -> token
      _ -> nil
    end
  end

  defp super_admin?(nil), do: false

  defp super_admin?(user) do
    user.role == "super_admin" or Map.get(user, :is_super_admin) == true
  end

  defp build_flash(conn) do
    flash = conn.assigns[:flash] || %{}

    %{
      success: Phoenix.Flash.get(flash, :info),
      error: Phoenix.Flash.get(flash, :error)
    }
  end
end
