defmodule TamanduaServerWeb.StreamSocket do
  @moduledoc """
  Socket for external streaming consumers.

  This socket handles WebSocket connections for real-time event streaming,
  providing a dedicated endpoint separate from the dashboard socket.
  """
  use Phoenix.Socket, log: false

  # Channels for streaming
  channel "stream:alerts", TamanduaServerWeb.AlertStreamChannel
  channel "stream:events", TamanduaServerWeb.EventStreamChannel
  channel "stream:detections", TamanduaServerWeb.DetectionStreamChannel

  @impl true
  def connect(%{"token" => token}, socket, _connect_info) do
    # Authenticate using JWT token
    case TamanduaServer.Guardian.decode_and_verify(token) do
      {:ok, claims} ->
        user_id = claims["sub"]

        # Fetch the full user
        user = case TamanduaServer.Accounts.get_user(user_id) do
          nil -> nil
          user -> user
        end

        if user && user.active do
          socket =
            socket
            |> assign(:user_id, user_id)
            |> assign(:current_user, user)
            |> assign(:organization_id, user.organization_id)

          {:ok, socket}
        else
          :error
        end

      {:error, _reason} ->
        :error
    end
  end

  def connect(_params, _socket, _connect_info) do
    # No anonymous connections allowed for streaming
    :error
  end

  @impl true
  def id(socket), do: "stream:#{socket.assigns.user_id}"
end
