defmodule TamanduaServer.Collaboration.PresenceTracker do
  @moduledoc """
  Server-side presence tracking and activity monitoring for collaborative features.

  Handles:
  - Activity heartbeats
  - Away detection (idle timeout)
  - Presence change notifications
  - Cross-LiveView presence coordination
  """

  use GenServer
  require Logger

  alias TamanduaServerWeb.Presence

  @idle_timeout :timer.minutes(5)
  @sweep_interval :timer.minutes(1)

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Record user activity on a resource.
  """
  def record_activity(user_id, resource_type, resource_id) do
    GenServer.cast(__MODULE__, {:activity, user_id, resource_type, resource_id})
  end

  @doc """
  Get active viewers for a resource.
  """
  def get_viewers(resource_type, resource_id) do
    topic = presence_topic(resource_type, resource_id)
    Presence.list_viewers(topic, resource_id)
  end

  @doc """
  Get viewer count for a resource.
  """
  def viewer_count(resource_type, resource_id) do
    topic = presence_topic(resource_type, resource_id)
    Presence.viewer_count(topic, resource_id)
  end

  @doc """
  Broadcast a presence change notification.
  """
  def broadcast_presence_change(resource_type, resource_id, event, user_meta) do
    topic = presence_topic(resource_type, resource_id)

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      topic,
      {:presence_event, event, user_meta}
    )
  end

  @doc """
  Get presence topic for a resource.
  """
  def presence_topic("alert", alert_id), do: "alert:#{alert_id}:presence"
  def presence_topic("investigation", investigation_id), do: "investigation:#{investigation_id}:presence"
  def presence_topic("playbook", playbook_id), do: "playbook:#{playbook_id}:presence"
  def presence_topic(type, id), do: "#{type}:#{id}:presence"

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Schedule periodic sweep for idle users
    schedule_sweep()

    state = %{
      activities: %{},
      last_seen: %{}
    }

    Logger.info("PresenceTracker started")
    {:ok, state}
  end

  @impl true
  def handle_cast({:activity, user_id, resource_type, resource_id}, state) do
    now = System.system_time(:second)

    activities =
      Map.put(state.activities, {user_id, resource_type, resource_id}, now)

    last_seen = Map.put(state.last_seen, user_id, now)

    # Update presence metadata
    topic = presence_topic(resource_type, resource_id)

    # Check if user status should change from away to online
    case get_current_status(state, user_id) do
      :away ->
        Phoenix.PubSub.broadcast(
          TamanduaServer.PubSub,
          topic,
          {:presence_status_change, user_id, :online}
        )

      _ ->
        :ok
    end

    {:noreply, %{state | activities: activities, last_seen: last_seen}}
  end

  @impl true
  def handle_info(:sweep_idle_users, state) do
    now = System.system_time(:second)

    # Find users who have been idle
    idle_users =
      Enum.filter(state.last_seen, fn {_user_id, last_seen} ->
        now - last_seen > div(@idle_timeout, 1000)
      end)

    # Update their status to away
    Enum.each(idle_users, fn {user_id, _last_seen} ->
      # Find all resources this user is viewing
      user_activities =
        Enum.filter(state.activities, fn {{uid, _type, _id}, _time} ->
          uid == user_id
        end)

      Enum.each(user_activities, fn {{_uid, resource_type, resource_id}, _time} ->
        topic = presence_topic(resource_type, resource_id)

        Phoenix.PubSub.broadcast(
          TamanduaServer.PubSub,
          topic,
          {:presence_status_change, user_id, :away}
        )
      end)
    end)

    schedule_sweep()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp get_current_status(state, user_id) do
    now = System.system_time(:second)

    case Map.get(state.last_seen, user_id) do
      nil -> :offline
      last_seen when now - last_seen > div(@idle_timeout, 1000) -> :away
      _ -> :online
    end
  end

  defp schedule_sweep do
    Process.send_after(self(), :sweep_idle_users, @sweep_interval)
  end
end
