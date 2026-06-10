defmodule TamanduaServer.Dashboard.ShareView do
  @moduledoc """
  Schema for tracking dashboard share views (analytics).
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "dashboard_share_views" do
    field :viewed_at, :utc_datetime_usec
    field :ip_address, :string
    field :user_agent, :string
    field :referrer, :string
    field :country, :string
    field :city, :string
    field :session_id, :string
    field :duration_seconds, :integer

    belongs_to :dashboard_share, TamanduaServer.Dashboard.Share

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(dashboard_share_id viewed_at)a
  @optional_fields ~w(ip_address user_agent referrer country city session_id duration_seconds)a

  def changeset(view, attrs) do
    view
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> foreign_key_constraint(:dashboard_share_id)
  end

  @doc """
  Creates a new view record from a Plug.Conn.
  """
  def from_conn(conn, dashboard_share_id, session_id \\ nil) do
    %__MODULE__{}
    |> changeset(%{
      dashboard_share_id: dashboard_share_id,
      viewed_at: DateTime.utc_now(),
      ip_address: get_client_ip(conn),
      user_agent: get_user_agent(conn),
      referrer: get_referrer(conn),
      session_id: session_id || generate_session_id()
    })
  end

  defp get_client_ip(conn) do
    # Check for X-Forwarded-For header first (proxy/load balancer)
    case Plug.Conn.get_req_header(conn, "x-forwarded-for") do
      [ip | _] ->
        ip |> String.split(",") |> List.first() |> String.trim()
      [] ->
        case conn.remote_ip do
          {a, b, c, d} -> "#{a}.#{b}.#{c}.#{d}"
          {a, b, c, d, e, f, g, h} ->
            "#{Integer.to_string(a, 16)}:#{Integer.to_string(b, 16)}:#{Integer.to_string(c, 16)}:#{Integer.to_string(d, 16)}:#{Integer.to_string(e, 16)}:#{Integer.to_string(f, 16)}:#{Integer.to_string(g, 16)}:#{Integer.to_string(h, 16)}"
          _ -> "unknown"
        end
    end
  end

  defp get_user_agent(conn) do
    case Plug.Conn.get_req_header(conn, "user-agent") do
      [ua | _] -> String.slice(ua, 0, 500)
      [] -> nil
    end
  end

  defp get_referrer(conn) do
    case Plug.Conn.get_req_header(conn, "referer") do
      [ref | _] -> String.slice(ref, 0, 500)
      [] -> nil
    end
  end

  defp generate_session_id do
    :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)
  end
end
