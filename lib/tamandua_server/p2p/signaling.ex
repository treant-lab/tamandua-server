defmodule TamanduaServer.P2P.Signaling do
  @moduledoc """
  WebSocket signaling server for P2P connection establishment.

  Exchanges ICE candidates and WireGuard public keys between analysts and agents.

  ## Architecture

  ```
  [Analyst] <-- WS --> [Signaling Server] <-- WS --> [Agent]
       |                                                |
       +---- ICE Candidate Exchange -------------------+
       |                                                |
       +---- Direct P2P Connection (encrypted) --------+
  ```

  ## Usage

      # Initiate connection
      {:ok, session_id} = Signaling.initiate_connection(analyst_id, agent_id)

      # Handle ICE candidate
      :ok = Signaling.handle_ice_candidate(session_id, candidate)

      # Get connection status
      {:ok, status} = Signaling.get_session_status(session_id)
  """

  use GenServer
  require Logger

  alias TamanduaServer.P2P.Session

  # Client API

  @doc """
  Start the signaling server.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Initiate a P2P connection between analyst and agent.

  Returns `{:ok, session_id}` on success.
  """
  def initiate_connection(analyst_id, agent_id) do
    GenServer.call(__MODULE__, {:initiate, analyst_id, agent_id})
  end

  @doc """
  Handle an ICE candidate from a peer.
  """
  def handle_ice_candidate(session_id, peer_id, candidate) do
    GenServer.call(__MODULE__, {:ice_candidate, session_id, peer_id, candidate})
  end

  @doc """
  Handle a connection offer.
  """
  def handle_offer(session_id, peer_id, offer) do
    GenServer.call(__MODULE__, {:offer, session_id, peer_id, offer})
  end

  @doc """
  Handle a connection answer.
  """
  def handle_answer(session_id, peer_id, answer) do
    GenServer.call(__MODULE__, {:answer, session_id, peer_id, answer})
  end

  @doc """
  Get session status.
  """
  def get_session_status(session_id) do
    GenServer.call(__MODULE__, {:get_status, session_id})
  end

  @doc """
  Close a session.
  """
  def close_session(session_id) do
    GenServer.call(__MODULE__, {:close, session_id})
  end

  @doc """
  List all active sessions.
  """
  def list_sessions do
    GenServer.call(__MODULE__, :list_sessions)
  end

  # Server callbacks

  @impl true
  def init(_opts) do
    Logger.info("P2P Signaling server started")

    state = %{
      # session_id => Session struct
      sessions: %{},
      # peer_id => session_id (for reverse lookup)
      peer_sessions: %{},
      # Statistics
      total_sessions: 0,
      active_connections: 0
    }

    # Schedule cleanup
    schedule_cleanup()

    {:ok, state}
  end

  @impl true
  def handle_call({:initiate, analyst_id, agent_id}, _from, state) do
    session_id = generate_session_id()

    session = Session.new(session_id, analyst_id, agent_id)

    Logger.info("Initiating P2P session #{session_id}: #{analyst_id} <-> #{agent_id}")

    state =
      state
      |> put_in([:sessions, session_id], session)
      |> put_in([:peer_sessions, analyst_id], session_id)
      |> put_in([:peer_sessions, agent_id], session_id)
      |> update_in([:total_sessions], &(&1 + 1))

    # Notify both peers via their channels
    broadcast_to_peer(analyst_id, "session_initiated", %{
      session_id: session_id,
      remote_peer_id: agent_id
    })

    broadcast_to_peer(agent_id, "session_initiated", %{
      session_id: session_id,
      remote_peer_id: analyst_id
    })

    {:reply, {:ok, session_id}, state}
  end

  @impl true
  def handle_call({:ice_candidate, session_id, peer_id, candidate}, _from, state) do
    case get_in(state, [:sessions, session_id]) do
      nil ->
        {:reply, {:error, :session_not_found}, state}

      session ->
        Logger.debug("ICE candidate from #{peer_id} in session #{session_id}")

        # Add candidate to session
        session = Session.add_candidate(session, peer_id, candidate)

        # Forward to remote peer
        remote_peer_id = Session.get_remote_peer(session, peer_id)

        broadcast_to_peer(remote_peer_id, "ice_candidate", %{
          session_id: session_id,
          peer_id: peer_id,
          candidate: candidate
        })

        state = put_in(state, [:sessions, session_id], session)
        {:reply, :ok, state}
    end
  end

  @impl true
  def handle_call({:offer, session_id, peer_id, offer}, _from, state) do
    case get_in(state, [:sessions, session_id]) do
      nil ->
        {:reply, {:error, :session_not_found}, state}

      session ->
        Logger.info("Connection offer from #{peer_id} in session #{session_id}")

        # Store offer
        session = Session.set_offer(session, offer)

        # Forward to remote peer
        remote_peer_id = Session.get_remote_peer(session, peer_id)

        broadcast_to_peer(remote_peer_id, "connection_offer", %{
          session_id: session_id,
          peer_id: peer_id,
          offer: offer
        })

        state = put_in(state, [:sessions, session_id], session)
        {:reply, :ok, state}
    end
  end

  @impl true
  def handle_call({:answer, session_id, peer_id, answer}, _from, state) do
    case get_in(state, [:sessions, session_id]) do
      nil ->
        {:reply, {:error, :session_not_found}, state}

      session ->
        Logger.info("Connection answer from #{peer_id} in session #{session_id}")

        # Store answer
        session = Session.set_answer(session, answer)

        # Forward to remote peer
        remote_peer_id = Session.get_remote_peer(session, peer_id)

        broadcast_to_peer(remote_peer_id, "connection_answer", %{
          session_id: session_id,
          peer_id: peer_id,
          answer: answer
        })

        # Mark session as negotiated
        session = Session.mark_negotiated(session)

        state = put_in(state, [:sessions, session_id], session)
        {:reply, :ok, state}
    end
  end

  @impl true
  def handle_call({:get_status, session_id}, _from, state) do
    case get_in(state, [:sessions, session_id]) do
      nil ->
        {:reply, {:error, :session_not_found}, state}

      session ->
        status = Session.get_status(session)
        {:reply, {:ok, status}, state}
    end
  end

  @impl true
  def handle_call({:close, session_id}, _from, state) do
    case get_in(state, [:sessions, session_id]) do
      nil ->
        {:reply, {:error, :session_not_found}, state}

      session ->
        Logger.info("Closing P2P session #{session_id}")

        # Notify peers
        broadcast_to_peer(session.analyst_id, "session_closed", %{session_id: session_id})
        broadcast_to_peer(session.agent_id, "session_closed", %{session_id: session_id})

        # Remove from state
        state =
          state
          |> update_in([:sessions], &Map.delete(&1, session_id))
          |> update_in([:peer_sessions], &Map.delete(&1, session.analyst_id))
          |> update_in([:peer_sessions], &Map.delete(&1, session.agent_id))

        {:reply, :ok, state}
    end
  end

  @impl true
  def handle_call(:list_sessions, _from, state) do
    sessions =
      state.sessions
      |> Map.values()
      |> Enum.map(&Session.to_map/1)

    {:reply, {:ok, sessions}, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    # Remove stale sessions (older than 10 minutes)
    now = System.system_time(:second)
    timeout = 600 # 10 minutes

    {stale_sessions, active_sessions} =
      Enum.split_with(state.sessions, fn {_id, session} ->
        now - session.created_at > timeout
      end)

    if length(stale_sessions) > 0 do
      Logger.info("Cleaning up #{length(stale_sessions)} stale P2P sessions")

      state =
        Enum.reduce(stale_sessions, state, fn {session_id, session}, acc ->
          # Notify peers
          broadcast_to_peer(session.analyst_id, "session_timeout", %{session_id: session_id})
          broadcast_to_peer(session.agent_id, "session_timeout", %{session_id: session_id})

          # Remove from state
          acc
          |> update_in([:peer_sessions], &Map.delete(&1, session.analyst_id))
          |> update_in([:peer_sessions], &Map.delete(&1, session.agent_id))
        end)

      state = %{state | sessions: Map.new(active_sessions)}

      schedule_cleanup()
      {:noreply, state}
    else
      schedule_cleanup()
      {:noreply, state}
    end
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private functions

  defp generate_session_id do
    UUID.uuid4()
  end

  defp broadcast_to_peer(peer_id, event, payload) do
    TamanduaServerWeb.Endpoint.broadcast(
      "p2p:#{peer_id}",
      event,
      payload
    )
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, 60_000) # Every minute
  end
end
