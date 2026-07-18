defmodule TamanduaServer.Telemetry.PackageInstallCorrelator do
  @moduledoc """
  Tracks package manager installation processes and correlates child process events.

  Monitors package manager processes (npm, pip, cargo, gem, go) and collects all
  descendant processes, network connections, and file operations during a 60-second
  install window for behavioral analysis.
  """

  use GenServer
  require Logger

  @install_window_seconds 60

  # Orphaned sessions (where stop_tracking is never delivered — agent
  # disconnect, crash, or process exit mid-install) would otherwise live in the
  # ETS table forever. Sweep sessions older than this generous TTL periodically.
  @session_ttl_seconds 600
  @sweep_interval_ms :timer.minutes(5)

  defp package_manager_patterns do
    [
      {~r/npm(\.cmd|\.exe)?$/i, :npm},
      {~r/pip[3]?(\.exe)?$/i, :pip},
      {~r/python[3]?(\.exe)?$/i, :pip},
      {~r/cargo(\.exe)?$/i, :cargo},
      {~r/gem(\.cmd)?$/i, :gem},
      {~r/ruby(\.exe)?$/i, :gem},
      {~r/go(\.exe)?$/i, :go}
    ]
  end

  # Client API

  @doc """
  Start the correlator GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Start tracking a package manager installation process.

  ## Parameters
    - agent_id: The agent identifier
    - event: Process creation event for the package manager

  ## Returns
    :ok
  """
  def start_tracking(agent_id, %{"type" => "process_creation"} = event) do
    GenServer.call(__MODULE__, {:start_tracking, agent_id, event})
  end

  @doc """
  Process an event and add to tracked sessions if relevant.

  ## Parameters
    - event: Any telemetry event (process_creation, network_connection, file_write)

  ## Returns
    :ok
  """
  def process_event(event) do
    GenServer.cast(__MODULE__, {:process_event, event})
  end

  @doc """
  Stop tracking a session and return all collected events.

  ## Parameters
    - agent_id: The agent identifier
    - root_pid: The root package manager PID

  ## Returns
    Session map with ecosystem, events, tracked_pids, etc., or nil if not found
  """
  def stop_tracking(agent_id, root_pid) do
    GenServer.call(__MODULE__, {:stop_tracking, agent_id, root_pid})
  end

  @doc """
  Get install events for an active tracking session without stopping it.

  ## Parameters
    - agent_id: The agent identifier
    - root_pid: The root package manager PID

  ## Returns
    Session map or nil if not found
  """
  def get_install_events(agent_id, root_pid) do
    GenServer.call(__MODULE__, {:get_install_events, agent_id, root_pid})
  end

  # Server callbacks

  @impl true
  def init(_opts) do
    # Create ETS table for tracking sessions
    table = :ets.new(:package_install_sessions, [
      :set,
      :named_table,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    schedule_sweep()

    {:ok, %{table: table}}
  end

  @impl true
  def handle_call({:start_tracking, agent_id, event}, _from, state) do
    pid = event["pid"]
    image = event["image"] || ""
    timestamp = event["timestamp"]
    environment = event["environment"] || %{}

    case detect_package_manager(image) do
      nil ->
        {:reply, :ok, state}

      ecosystem ->
        package_name = extract_package_name(environment)
        start_time = parse_timestamp(timestamp)

        session = %{
          ecosystem: ecosystem,
          start_time: start_time,
          tracked_pids: MapSet.new([pid]),
          events: [],
          package_name: package_name
        }

        :ets.insert(:package_install_sessions, {{agent_id, pid}, session})
        Logger.debug("Started tracking #{ecosystem} install: agent=#{agent_id}, pid=#{pid}")

        {:reply, :ok, state}
    end
  end

  @impl true
  def handle_call({:stop_tracking, agent_id, root_pid}, _from, state) do
    key = {agent_id, root_pid}

    result = case :ets.lookup(:package_install_sessions, key) do
      [{^key, session}] ->
        :ets.delete(:package_install_sessions, key)
        Logger.debug("Stopped tracking: agent=#{agent_id}, pid=#{root_pid}")
        session

      [] ->
        nil
    end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_install_events, agent_id, root_pid}, _from, state) do
    key = {agent_id, root_pid}

    result = case :ets.lookup(:package_install_sessions, key) do
      [{^key, session}] -> session
      [] -> nil
    end

    {:reply, result, state}
  end

  @impl true
  def handle_cast({:process_event, event}, state) do
    agent_id = event["agent_id"] || event[:agent_id]
    event_type = event["type"] || event[:type]
    timestamp = event["timestamp"] || event[:timestamp]

    if agent_id do
      case event_type do
        "process_creation" ->
          handle_process_creation(agent_id, event, timestamp)

        "network_connection" ->
          handle_network_connection(agent_id, event, timestamp)

        "file_write" ->
          handle_file_write(agent_id, event, timestamp)

        _ ->
          :ok
      end
    end

    {:noreply, state}
  end

  @impl true
  def handle_info(:sweep, state) do
    sweep_stale_sessions()
    schedule_sweep()
    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # Private functions

  defp schedule_sweep do
    Process.send_after(self(), :sweep, @sweep_interval_ms)
  end

  # Delete sessions whose start_time is older than the TTL. These are orphans
  # left behind when stop_tracking was never delivered.
  defp sweep_stale_sessions do
    cutoff = DateTime.add(DateTime.utc_now(), -@session_ttl_seconds, :second)

    :ets.foldl(fn {key, session}, acc ->
      if DateTime.compare(session.start_time, cutoff) == :lt do
        :ets.delete(:package_install_sessions, key)
      end

      acc
    end, nil, :package_install_sessions)
  end

  defp detect_package_manager(image_path) when is_binary(image_path) do
    basename = Path.basename(image_path)
    Enum.find_value(package_manager_patterns(), fn {pattern, ecosystem} ->
      if Regex.match?(pattern, basename), do: ecosystem
    end)
  end
  defp detect_package_manager(_), do: nil

  defp extract_package_name(env) when is_map(env) do
    env["npm_package_name"] ||
    env["CARGO_PKG_NAME"] ||
    env["GEM_NAME"] ||
    env["PIP_PACKAGE"]
  end
  defp extract_package_name(_), do: nil

  defp parse_timestamp(timestamp) when is_binary(timestamp) do
    case DateTime.from_iso8601(timestamp) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end
  defp parse_timestamp(_), do: DateTime.utc_now()

  defp within_window?(event_time, session_start) do
    event_dt = parse_timestamp(event_time)
    diff = DateTime.diff(event_dt, session_start, :second)
    diff >= 0 and diff <= @install_window_seconds
  end

  defp handle_process_creation(agent_id, event, timestamp) do
    parent_pid = event["parent_pid"]

    if parent_pid do
      # Find all sessions where this parent_pid is tracked
      :ets.foldl(fn {key, session}, acc ->
        {session_agent_id, _root_pid} = key

        if session_agent_id == agent_id and MapSet.member?(session.tracked_pids, parent_pid) do
          # Check time window
          if within_window?(timestamp, session.start_time) do
            child_pid = event["pid"]

            # Add child PID to tracked set and add event
            updated_session = session
            |> Map.update!(:tracked_pids, &MapSet.put(&1, child_pid))
            |> Map.update!(:events, &[event | &1])

            :ets.insert(:package_install_sessions, {key, updated_session})
          end
        end

        acc
      end, nil, :package_install_sessions)
    end
  end

  defp handle_network_connection(agent_id, event, timestamp) do
    source_pid = event["source_pid"]

    if source_pid do
      :ets.foldl(fn {key, session}, acc ->
        {session_agent_id, _root_pid} = key

        if session_agent_id == agent_id and MapSet.member?(session.tracked_pids, source_pid) do
          if within_window?(timestamp, session.start_time) do
            updated_session = Map.update!(session, :events, &[event | &1])
            :ets.insert(:package_install_sessions, {key, updated_session})
          end
        end

        acc
      end, nil, :package_install_sessions)
    end
  end

  defp handle_file_write(agent_id, event, timestamp) do
    pid = event["pid"]

    if pid do
      :ets.foldl(fn {key, session}, acc ->
        {session_agent_id, _root_pid} = key

        if session_agent_id == agent_id and MapSet.member?(session.tracked_pids, pid) do
          if within_window?(timestamp, session.start_time) do
            updated_session = Map.update!(session, :events, &[event | &1])
            :ets.insert(:package_install_sessions, {key, updated_session})
          end
        end

        acc
      end, nil, :package_install_sessions)
    end
  end
end
