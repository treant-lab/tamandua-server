defmodule TamanduaServerWeb.API.V1.HealthHubController do
  use TamanduaServerWeb, :controller

  alias TamanduaServer.HealthHub

  def index(conn, params) do
    org_id = current_organization_id(conn)
    window_hours = parse_window_hours(params["hours"])

    json(conn, HealthHub.summary(org_id, window_hours: window_hours))
  end

  defp current_organization_id(conn) do
    conn.assigns[:current_organization_id] ||
      (conn.assigns[:current_user] && conn.assigns.current_user.organization_id)
  end

  defp parse_window_hours(value) when is_binary(value) do
    case Integer.parse(value) do
      {hours, ""} when hours in 1..168 -> hours
      _ -> 24
    end
  end

  defp parse_window_hours(_), do: 24
end
