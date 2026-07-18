defmodule TamanduaServerWeb.Plugs.SystemOperator do
  @moduledoc "Requires an explicitly provisioned platform operator identity."

  @behaviour Plug

  import Phoenix.Controller
  import Plug.Conn

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(conn, _opts) do
    if system_operator?(conn.assigns[:current_user]) do
      conn
    else
      conn
      |> put_status(:forbidden)
      |> put_view(json: TamanduaServerWeb.ErrorJSON)
      |> render(:error, %{
        error: "forbidden",
        message: "System operator authorization required"
      })
      |> halt()
    end
  end

  @doc false
  def system_operator?(user) when is_map(user) do
    Map.get(user, :is_super_admin) == true or Map.get(user, :role) == "super_admin"
  end

  def system_operator?(_user), do: false
end
