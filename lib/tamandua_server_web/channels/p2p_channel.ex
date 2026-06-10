defmodule TamanduaServerWeb.P2PChannel do
  @moduledoc """
  Phoenix channel for P2P signaling.

  Handles WebSocket communication for ICE candidate exchange,
  offer/answer negotiation, and connection state management.

  ## Channel Topics

  - `p2p:analyst_id` - Analyst's personal signaling channel
  - `p2p:agent_id` - Agent's personal signaling channel

  ## Events

  ### Inbound (from client)

  - `initiate_connection` - Start P2P connection to remote peer
  - `ice_candidate` - Send ICE candidate
  - `connection_offer` - Send connection offer
  - `connection_answer` - Send connection answer
  - `close_session` - Close P2P session

  ### Outbound (to client)

  - `session_initiated` - Session created, ready for signaling
  - `ice_candidate` - Received ICE candidate from remote peer
  - `connection_offer` - Received connection offer from remote peer
  - `connection_answer` - Received connection answer from remote peer
  - `session_closed` - Session closed by remote peer
  - `session_timeout` - Session timed out
  - `error` - Error occurred

  ## Usage

      // JavaScript client
      let channel = socket.channel("p2p:analyst_123", {})

      channel.join()
        .receive("ok", () => console.log("Joined P2P channel"))
        .receive("error", err => console.error("Join failed", err))

      // Initiate connection
      channel.push("initiate_connection", {remote_peer_id: "agent_456"})
        .receive("ok", ({session_id}) => {
          console.log("Session initiated:", session_id)
        })

      // Send ICE candidate
      channel.push("ice_candidate", {
        session_id: session_id,
        candidate: {
          foundation: "1",
          component: 1,
          protocol: "udp",
          priority: 2130706431,
          address: "192.168.1.100",
          port: 5000,
          type: "host"
        }
      })

      // Listen for remote ICE candidates
      channel.on("ice_candidate", ({session_id, peer_id, candidate}) => {
        console.log("Received ICE candidate from", peer_id)
        peerConnection.addIceCandidate(candidate)
      })
  """

  use TamanduaServerWeb, :channel
  require Logger

  alias TamanduaServer.P2P.Signaling

  @impl true
  def join("p2p:" <> peer_id, _params, socket) do
    Logger.info("Peer #{peer_id} joined P2P signaling channel")

    socket = assign(socket, :peer_id, peer_id)

    {:ok, %{peer_id: peer_id}, socket}
  end

  @impl true
  def handle_in("initiate_connection", %{"remote_peer_id" => remote_peer_id}, socket) do
    peer_id = socket.assigns.peer_id

    Logger.info("#{peer_id} initiating P2P connection to #{remote_peer_id}")

    case Signaling.initiate_connection(peer_id, remote_peer_id) do
      {:ok, session_id} ->
        {:reply, {:ok, %{session_id: session_id}}, socket}

      {:error, reason} ->
        Logger.error("Failed to initiate P2P connection: #{inspect(reason)}")
        {:reply, {:error, %{reason: reason}}, socket}
    end
  end

  @impl true
  def handle_in(
        "ice_candidate",
        %{"session_id" => session_id, "candidate" => candidate},
        socket
      ) do
    peer_id = socket.assigns.peer_id

    Logger.debug("ICE candidate from #{peer_id} for session #{session_id}")

    case Signaling.handle_ice_candidate(session_id, peer_id, candidate) do
      :ok ->
        {:reply, :ok, socket}

      {:error, reason} ->
        Logger.error("Failed to handle ICE candidate: #{inspect(reason)}")
        {:reply, {:error, %{reason: reason}}, socket}
    end
  end

  @impl true
  def handle_in(
        "connection_offer",
        %{"session_id" => session_id, "offer" => offer},
        socket
      ) do
    peer_id = socket.assigns.peer_id

    Logger.info("Connection offer from #{peer_id} for session #{session_id}")

    case Signaling.handle_offer(session_id, peer_id, offer) do
      :ok ->
        {:reply, :ok, socket}

      {:error, reason} ->
        Logger.error("Failed to handle offer: #{inspect(reason)}")
        {:reply, {:error, %{reason: reason}}, socket}
    end
  end

  @impl true
  def handle_in(
        "connection_answer",
        %{"session_id" => session_id, "answer" => answer},
        socket
      ) do
    peer_id = socket.assigns.peer_id

    Logger.info("Connection answer from #{peer_id} for session #{session_id}")

    case Signaling.handle_answer(session_id, peer_id, answer) do
      :ok ->
        {:reply, :ok, socket}

      {:error, reason} ->
        Logger.error("Failed to handle answer: #{inspect(reason)}")
        {:reply, {:error, %{reason: reason}}, socket}
    end
  end

  @impl true
  def handle_in("close_session", %{"session_id" => session_id}, socket) do
    peer_id = socket.assigns.peer_id

    Logger.info("#{peer_id} closing session #{session_id}")

    case Signaling.close_session(session_id) do
      :ok ->
        {:reply, :ok, socket}

      {:error, reason} ->
        {:reply, {:error, %{reason: reason}}, socket}
    end
  end

  @impl true
  def handle_in("get_session_status", %{"session_id" => session_id}, socket) do
    case Signaling.get_session_status(session_id) do
      {:ok, status} ->
        {:reply, {:ok, status}, socket}

      {:error, reason} ->
        {:reply, {:error, %{reason: reason}}, socket}
    end
  end

  @impl true
  def handle_in("list_sessions", _params, socket) do
    case Signaling.list_sessions() do
      {:ok, sessions} ->
        {:reply, {:ok, %{sessions: sessions}}, socket}

      {:error, reason} ->
        {:reply, {:error, %{reason: reason}}, socket}
    end
  end

  @impl true
  def handle_in(event, _params, socket) do
    Logger.warn("Unknown P2P event: #{event}")
    {:reply, {:error, %{reason: :unknown_event}}, socket}
  end

  @impl true
  def terminate(reason, socket) do
    peer_id = socket.assigns.peer_id
    Logger.info("Peer #{peer_id} left P2P signaling channel: #{inspect(reason)}")
    :ok
  end
end
