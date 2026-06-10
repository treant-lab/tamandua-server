defmodule TamanduaServer.P2P.Session do
  @moduledoc """
  P2P session state management.

  Tracks ICE candidates, offers, answers, and connection state
  for a single P2P session between analyst and agent.
  """

  @type t :: %__MODULE__{
          id: String.t(),
          analyst_id: String.t(),
          agent_id: String.t(),
          state: atom(),
          offer: map() | nil,
          answer: map() | nil,
          analyst_candidates: list(map()),
          agent_candidates: list(map()),
          created_at: integer(),
          updated_at: integer()
        }

  defstruct [
    :id,
    :analyst_id,
    :agent_id,
    :state,
    :offer,
    :answer,
    :created_at,
    :updated_at,
    analyst_candidates: [],
    agent_candidates: []
  ]

  @doc """
  Create a new P2P session.
  """
  def new(id, analyst_id, agent_id) do
    now = System.system_time(:second)

    %__MODULE__{
      id: id,
      analyst_id: analyst_id,
      agent_id: agent_id,
      state: :initiated,
      offer: nil,
      answer: nil,
      analyst_candidates: [],
      agent_candidates: [],
      created_at: now,
      updated_at: now
    }
  end

  @doc """
  Add an ICE candidate to the session.
  """
  def add_candidate(session, peer_id, candidate) do
    now = System.system_time(:second)

    cond do
      peer_id == session.analyst_id ->
        %{session | analyst_candidates: [candidate | session.analyst_candidates], updated_at: now}

      peer_id == session.agent_id ->
        %{session | agent_candidates: [candidate | session.agent_candidates], updated_at: now}

      true ->
        session
    end
  end

  @doc """
  Set the connection offer.
  """
  def set_offer(session, offer) do
    %{session | offer: offer, state: :offer_sent, updated_at: System.system_time(:second)}
  end

  @doc """
  Set the connection answer.
  """
  def set_answer(session, answer) do
    %{session | answer: answer, state: :answer_sent, updated_at: System.system_time(:second)}
  end

  @doc """
  Mark session as negotiated (ICE complete).
  """
  def mark_negotiated(session) do
    %{session | state: :negotiated, updated_at: System.system_time(:second)}
  end

  @doc """
  Get the remote peer ID for a given peer.
  """
  def get_remote_peer(session, peer_id) do
    if peer_id == session.analyst_id do
      session.agent_id
    else
      session.analyst_id
    end
  end

  @doc """
  Get session status.
  """
  def get_status(session) do
    %{
      id: session.id,
      state: session.state,
      analyst_id: session.analyst_id,
      agent_id: session.agent_id,
      analyst_candidates_count: length(session.analyst_candidates),
      agent_candidates_count: length(session.agent_candidates),
      has_offer: session.offer != nil,
      has_answer: session.answer != nil,
      created_at: session.created_at,
      updated_at: session.updated_at
    }
  end

  @doc """
  Convert session to map for serialization.
  """
  def to_map(session) do
    %{
      id: session.id,
      state: session.state,
      analyst_id: session.analyst_id,
      agent_id: session.agent_id,
      analyst_candidates_count: length(session.analyst_candidates),
      agent_candidates_count: length(session.agent_candidates),
      created_at: session.created_at,
      updated_at: session.updated_at
    }
  end
end
