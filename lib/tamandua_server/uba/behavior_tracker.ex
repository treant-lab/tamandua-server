defmodule TamanduaServer.UBA.BehaviorTracker do
  @moduledoc """
  Tracks user behaviors across the platform for User Behavior Analytics.

  Monitors 10+ behavior types:
  - Login patterns (times, locations, devices)
  - Resource access (files, folders, applications)
  - Data transfers (uploads, downloads, emails)
  - Privilege usage (sudo, UAC elevations)
  - Application usage (hours per app, app switches)
  - Network activity (connections, bandwidth)
  - Failed authentications
  - Permission changes
  - Admin console access
  - Off-hours activity
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.UBA.{UserBehavior, BaselineLearner}
  import Ecto.Query

  # Behavior types
  @behavior_types [
    "login",
    "logout",
    "file_access",
    "file_create",
    "file_modify",
    "file_delete",
    "data_upload",
    "data_download",
    "email_sent",
    "sudo_usage",
    "uac_elevation",
    "app_launch",
    "app_switch",
    "network_connection",
    "failed_auth",
    "permission_change",
    "admin_console_access",
    "off_hours_activity"
  ]

  # Off-hours: weekdays 10pm-6am, weekends all day
  @off_hours_weekday_start 22
  @off_hours_weekday_end 6

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    Logger.info("BehaviorTracker started")
    {:ok, %{}}
  end

  ## Public API

  @doc """
  Tracks a user behavior event.
  """
  def track_behavior(user_id, behavior_type, metadata \\ %{}) do
    GenServer.cast(__MODULE__, {:track, user_id, behavior_type, metadata})
  end

  @doc """
  Tracks login behavior with location and device info.
  """
  def track_login(user_id, ip_address, user_agent, metadata \\ %{}) do
    behavior = %{
      location: ip_address,
      device: extract_device(user_agent),
      user_agent: user_agent
    }
    |> Map.merge(metadata)

    track_behavior(user_id, "login", behavior)
  end

  @doc """
  Tracks file access behavior.
  """
  def track_file_access(user_id, file_path, operation, agent_id \\ nil) do
    track_behavior(user_id, "file_#{operation}", %{
      file_path: file_path,
      operation: operation,
      agent_id: agent_id
    })
  end

  @doc """
  Tracks data transfer (upload/download).
  """
  def track_data_transfer(user_id, direction, bytes, metadata \\ %{}) do
    track_behavior(user_id, "data_#{direction}", %{
      direction: direction,
      bytes: bytes,
      value: bytes / 1_000_000  # Convert to MB
    }
    |> Map.merge(metadata))
  end

  @doc """
  Tracks privilege escalation (sudo/UAC).
  """
  def track_privilege_usage(user_id, privilege_type, command, agent_id \\ nil) do
    track_behavior(user_id, privilege_type, %{
      command: command,
      agent_id: agent_id,
      value: 1
    })
  end

  @doc """
  Tracks application usage.
  """
  def track_app_usage(user_id, app_name, duration_seconds, agent_id \\ nil) do
    track_behavior(user_id, "app_launch", %{
      app_name: app_name,
      duration: duration_seconds,
      value: duration_seconds / 3600,  # Convert to hours
      agent_id: agent_id
    })
  end

  @doc """
  Tracks network connection.
  """
  def track_network_connection(user_id, dest_ip, dest_port, bytes, agent_id \\ nil) do
    track_behavior(user_id, "network_connection", %{
      dest_ip: dest_ip,
      dest_port: dest_port,
      bytes: bytes,
      value: bytes / 1_000_000,  # Convert to MB
      agent_id: agent_id
    })
  end

  @doc """
  Tracks failed authentication attempt.
  """
  def track_failed_auth(user_id, reason, location, metadata \\ %{}) do
    track_behavior(user_id, "failed_auth", %{
      reason: reason,
      location: location,
      value: 1
    }
    |> Map.merge(metadata))
  end

  @doc """
  Gets behavior history for a user.
  """
  def get_behavior_history(user_id, behavior_type, opts \\ []) do
    days = Keyword.get(opts, :days, 30)
    limit = Keyword.get(opts, :limit, 1000)

    cutoff = DateTime.utc_now() |> DateTime.add(-days * 24 * 3600, :second)

    from(b in UserBehavior,
      where: b.user_id == ^user_id,
      where: b.behavior_type == ^behavior_type,
      where: b.timestamp >= ^cutoff,
      order_by: [desc: b.timestamp],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Gets behavior statistics for a user.
  """
  def get_behavior_stats(user_id, behavior_type, days \\ 30) do
    cutoff = DateTime.utc_now() |> DateTime.add(-days * 24 * 3600, :second)

    query = from(b in UserBehavior,
      where: b.user_id == ^user_id,
      where: b.behavior_type == ^behavior_type,
      where: b.timestamp >= ^cutoff,
      where: not is_nil(b.value),
      select: %{
        count: count(b.id),
        sum: sum(b.value),
        avg: avg(b.value),
        min: min(b.value),
        max: max(b.value)
      }
    )

    Repo.one(query) || %{count: 0, sum: 0, avg: 0, min: 0, max: 0}
  end

  @doc """
  Gets unique locations for a user.
  """
  def get_user_locations(user_id, days \\ 30) do
    cutoff = DateTime.utc_now() |> DateTime.add(-days * 24 * 3600, :second)

    from(b in UserBehavior,
      where: b.user_id == ^user_id,
      where: not is_nil(b.location),
      where: b.timestamp >= ^cutoff,
      select: b.location,
      distinct: true
    )
    |> Repo.all()
  end

  @doc """
  Gets unique devices for a user.
  """
  def get_user_devices(user_id, days \\ 30) do
    cutoff = DateTime.utc_now() |> DateTime.add(-days * 24 * 3600, :second)

    from(b in UserBehavior,
      where: b.user_id == ^user_id,
      where: not is_nil(b.device),
      where: b.timestamp >= ^cutoff,
      select: b.device,
      distinct: true
    )
    |> Repo.all()
  end

  ## GenServer Callbacks

  @impl true
  def handle_cast({:track, user_id, behavior_type, metadata}, state) do
    Task.start(fn ->
      track_behavior_async(user_id, behavior_type, metadata)
    end)

    {:noreply, state}
  end

  ## Private Functions

  defp track_behavior_async(user_id, behavior_type, metadata) do
    timestamp = DateTime.utc_now()

    # Check if this is off-hours activity
    metadata = if is_off_hours?(timestamp) do
      Map.put(metadata, :off_hours, true)
    else
      metadata
    end

    attrs = %{
      user_id: user_id,
      behavior_type: behavior_type,
      timestamp: timestamp,
      metadata: metadata,
      value: metadata[:value],
      location: metadata[:location],
      device: metadata[:device],
      source: metadata[:source],
      agent_id: metadata[:agent_id],
      organization_id: get_user_organization(user_id)
    }

    case UserBehavior.changeset(%UserBehavior{}, attrs) |> Repo.insert() do
      {:ok, behavior} ->
        Logger.debug("Tracked behavior: #{behavior_type} for user #{user_id}")

        # Trigger baseline update if needed
        BaselineLearner.update_baseline(user_id, behavior_type)

        # Check for immediate anomalies
        check_immediate_anomalies(behavior)

      {:error, changeset} ->
        Logger.error("Failed to track behavior: #{inspect(changeset.errors)}")
    end
  end

  defp is_off_hours?(timestamp) do
    day_of_week = Date.day_of_week(timestamp)
    hour = timestamp.hour

    # Weekend (Saturday=6, Sunday=7)
    if day_of_week in [6, 7] do
      true
    else
      # Weekday off-hours (10pm-6am)
      hour >= @off_hours_weekday_start or hour < @off_hours_weekday_end
    end
  end

  defp extract_device(user_agent) do
    cond do
      String.contains?(user_agent, "iPhone") -> "iPhone"
      String.contains?(user_agent, "iPad") -> "iPad"
      String.contains?(user_agent, "Android") -> "Android"
      String.contains?(user_agent, "Windows") -> "Windows"
      String.contains?(user_agent, "Macintosh") -> "macOS"
      String.contains?(user_agent, "Linux") -> "Linux"
      true -> "Unknown"
    end
  end

  defp get_user_organization(user_id) do
    from(u in TamanduaServer.Accounts.User,
      where: u.id == ^user_id,
      select: u.organization_id
    )
    |> Repo.one()
  end

  defp check_immediate_anomalies(behavior) do
    # Check for specific high-priority anomalies
    cond do
      # Failed auth spike
      behavior.behavior_type == "failed_auth" ->
        check_failed_auth_spike(behavior.user_id)

      # Off-hours admin access
      behavior.behavior_type == "admin_console_access" and behavior.metadata[:off_hours] ->
        trigger_off_hours_alert(behavior)

      # New location
      behavior.behavior_type == "login" and behavior.location ->
        check_new_location(behavior.user_id, behavior.location)

      true ->
        :ok
    end
  end

  defp check_failed_auth_spike(user_id) do
    # Check if there are 5+ failed auths in last 5 minutes
    cutoff = DateTime.utc_now() |> DateTime.add(-5 * 60, :second)

    count = from(b in UserBehavior,
      where: b.user_id == ^user_id,
      where: b.behavior_type == "failed_auth",
      where: b.timestamp >= ^cutoff,
      select: count(b.id)
    )
    |> Repo.one()

    if count >= 5 do
      Logger.warn("Failed auth spike detected for user #{user_id}: #{count} attempts")
      # Trigger alert (to be implemented with AnomalyDetector)
    end
  end

  defp trigger_off_hours_alert(behavior) do
    Logger.warn("Off-hours admin access by user #{behavior.user_id} at #{behavior.timestamp}")
    # Trigger alert (to be implemented with AnomalyDetector)
  end

  defp check_new_location(user_id, location) do
    known_locations = get_user_locations(user_id, 30)

    if location not in known_locations do
      Logger.info("New location detected for user #{user_id}: #{location}")
      # Trigger alert (to be implemented with AnomalyDetector)
    end
  end
end
