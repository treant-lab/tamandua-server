defmodule TamanduaServer.ShellSessions.Session do
  @moduledoc """
  Schema for shell session records.

  Tracks live response shell sessions including:
  - User and agent association
  - Session timing and duration
  - Status and termination reason
  - Command statistics
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "shell_sessions" do
    # External session ID (used by frontend/agent)
    field :session_id, :string

    # Associations
    belongs_to :user, TamanduaServer.Accounts.User
    belongs_to :agent, TamanduaServer.Agents.Agent

    # Agent info snapshot (in case agent is deleted)
    field :agent_hostname, :string
    field :agent_os, :string

    # Timing
    field :started_at, :utc_datetime
    field :ended_at, :utc_datetime

    # Status
    field :status, Ecto.Enum, values: [:active, :ended], default: :active
    field :end_reason, :string

    # Statistics
    field :command_count, :integer, default: 0
    field :bytes_sent, :integer, default: 0
    field :bytes_received, :integer, default: 0

    # Recording
    field :recording_path, :string
    field :has_recording, :boolean, default: false

    # Client info
    field :client_ip, :string
    field :user_agent, :string

    timestamps()
  end

  @required_fields [:session_id, :user_id, :agent_id, :started_at]
  @optional_fields [
    :agent_hostname,
    :agent_os,
    :ended_at,
    :status,
    :end_reason,
    :command_count,
    :bytes_sent,
    :bytes_received,
    :recording_path,
    :has_recording,
    :client_ip,
    :user_agent
  ]

  def changeset(session, attrs) do
    session
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> unique_constraint(:session_id)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:agent_id)
  end

  @doc """
  Calculates session duration in seconds.
  """
  def duration(%__MODULE__{started_at: start, ended_at: nil}) do
    DateTime.diff(DateTime.utc_now(), start, :second)
  end

  def duration(%__MODULE__{started_at: start, ended_at: ended}) do
    DateTime.diff(ended, start, :second)
  end
end
