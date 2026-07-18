defmodule TamanduaServerWeb.AIRuntimeAlertsLive do
  @moduledoc """
  Backward-compatible LiveView entrypoint for AI runtime alerts.

  The unified AI runtime dashboard owns the implementation. This module keeps
  the existing `/live/ai-runtime-alerts` route renderable while opening the
  detections-focused tab by default.
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServerWeb.AIRuntimeLive

  @impl true
  def mount(params, session, socket) do
    params
    |> Map.put_new("tab", "detections")
    |> AIRuntimeLive.mount(session, socket)
  end

  @impl true
  defdelegate handle_params(params, uri, socket), to: AIRuntimeLive

  @impl true
  defdelegate handle_info(message, socket), to: AIRuntimeLive

  @impl true
  defdelegate handle_event(event, params, socket), to: AIRuntimeLive

  @impl true
  defdelegate render(assigns), to: AIRuntimeLive
end
