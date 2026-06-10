defmodule TamanduaServerWeb.Presence do
  @moduledoc """
  Phoenix Presence for tracking agent and user connections.
  """
  use Phoenix.Presence,
    otp_app: :tamandua_server,
    pubsub_server: TamanduaServer.PubSub
end
