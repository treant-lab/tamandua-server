defmodule TamanduaServer.Alerts.AlertBroadcastRelay do
  @moduledoc """
  Relays alert broadcasts across independent Phoenix runtimes that share the
  same PostgreSQL database.

  Endpoint broadcasts are process-local unless the BEAM nodes are clustered.
  Lab and self-hosted deployments can run the agent mTLS listener and the web
  dashboard in separate runtimes, so alert creation in one runtime must notify
  the others to rebroadcast locally.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Alerts
  alias TamanduaServer.Repo
  alias TamanduaServerWeb.Broadcaster

  @channel "tamandua_alert_broadcasts"
  @origin_key {__MODULE__, :origin_id}

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def notify_new_alert(alert) do
    payload =
      Jason.encode!(%{
        "event" => "new_alert",
        "alert_id" => to_string(alert.id),
        "origin_id" => origin_id()
      })

    notify(payload)
  end

  def notify_alert_updated(alert) do
    payload =
      Jason.encode!(%{
        "event" => "alert_updated",
        "alert_id" => to_string(alert.id),
        "origin_id" => origin_id()
      })

    notify(payload)
  end

  @impl true
  def init(_opts) do
    :persistent_term.put(@origin_key, build_origin_id())

    case Postgrex.Notifications.start_link(Repo.config()) do
      {:ok, listener} ->
        case Postgrex.Notifications.listen(listener, @channel) do
          {:ok, ref} ->
            Logger.info("[AlertBroadcastRelay] Listening on #{@channel}")
            {:ok, %{listener: listener, ref: ref}}

          {:error, reason} ->
            Logger.warning("[AlertBroadcastRelay] LISTEN failed: #{inspect(reason)}")
            {:ok, %{listener: listener, ref: nil}}
        end

      {:error, reason} ->
        Logger.warning("[AlertBroadcastRelay] notification connection failed: #{inspect(reason)}")
        {:ok, %{listener: nil, ref: nil}}
    end
  end

  @impl true
  def handle_info({:notification, _listener, _ref, @channel, payload}, state) do
    Logger.debug("[AlertBroadcastRelay] received notification on #{@channel}")

    payload
    |> Jason.decode()
    |> handle_notification_payload()

    {:noreply, state}
  end

  def handle_info({:notification, _listener, @channel, payload}, state) do
    Logger.debug("[AlertBroadcastRelay] received notification on #{@channel}")

    payload
    |> Jason.decode()
    |> handle_notification_payload()

    {:noreply, state}
  end

  def handle_info({:notification, _listener, _ref, channel, _payload}, state) do
    Logger.debug("[AlertBroadcastRelay] ignored notification from #{channel}")
    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp handle_notification_payload({:ok, %{"origin_id" => origin} = payload}) do
    if origin == origin_id() do
      :ok
    else
      handle_remote_notification(payload)
    end
  end

  defp handle_notification_payload({:ok, payload}) do
    Logger.debug("[AlertBroadcastRelay] ignored notification payload: #{inspect(payload)}")
  end

  defp handle_notification_payload({:error, error}) do
    Logger.warning("[AlertBroadcastRelay] invalid notification payload: #{inspect(error)}")
  end

  defp handle_remote_notification(%{"event" => "new_alert", "alert_id" => alert_id}) do
    case Alerts.get_alert(alert_id) do
      {:ok, alert} ->
        Logger.info("[AlertBroadcastRelay] rebroadcasting new alert #{alert_id}")
        Broadcaster.broadcast_new_alert(alert)
        Broadcaster.broadcast_geo_update()

      {:error, reason} ->
        Logger.warning("[AlertBroadcastRelay] alert #{alert_id} lookup failed: #{inspect(reason)}")
    end
  rescue
    error ->
      Logger.warning("[AlertBroadcastRelay] failed to rebroadcast new alert: #{Exception.message(error)}")
  end

  defp handle_remote_notification(%{"event" => "alert_updated", "alert_id" => alert_id}) do
    case Alerts.get_alert(alert_id) do
      {:ok, alert} ->
        Logger.info("[AlertBroadcastRelay] rebroadcasting alert update #{alert_id}")
        Broadcaster.broadcast_alert_updated(alert)

      {:error, reason} ->
        Logger.warning("[AlertBroadcastRelay] alert #{alert_id} lookup failed: #{inspect(reason)}")
    end
  rescue
    error ->
      Logger.warning(
        "[AlertBroadcastRelay] failed to rebroadcast alert update: #{Exception.message(error)}"
      )
  end

  defp handle_remote_notification(payload) do
    Logger.debug("[AlertBroadcastRelay] ignored notification payload: #{inspect(payload)}")
  end

  defp notify(payload) do
    case Repo.query("select pg_notify($1, $2)", [@channel, payload]) do
      {:ok, _result} ->
        :ok

      {:error, reason} ->
        Logger.warning("[AlertBroadcastRelay] NOTIFY failed: #{inspect(reason)}")
        :ok
    end
  rescue
    error ->
      Logger.warning("[AlertBroadcastRelay] NOTIFY failed: #{Exception.message(error)}")
      :ok
  end

  defp origin_id do
    :persistent_term.get(@origin_key, build_origin_id())
  end

  defp build_origin_id do
    "#{node()}:#{:os.getpid()}"
  end
end
