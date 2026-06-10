defmodule TamanduaServer.Repo.Migrations.CreateShellSessions do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:shell_sessions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :session_id, :string, null: false

      # User who initiated the session
      add :user_id, references(:users, on_delete: :nilify_all, type: :binary_id)

      # Target agent
      add :agent_id, references(:agents, on_delete: :nilify_all, type: :binary_id)

      # Agent info snapshot
      add :agent_hostname, :string
      add :agent_os, :string

      # Timing
      add :started_at, :utc_datetime, null: false
      add :ended_at, :utc_datetime

      # Status
      add :status, :string, default: "active"
      add :end_reason, :string

      # Statistics
      add :command_count, :integer, default: 0
      add :bytes_sent, :bigint, default: 0
      add :bytes_received, :bigint, default: 0

      # Recording
      add :recording_path, :string
      add :has_recording, :boolean, default: false

      # Client info
      add :client_ip, :string
      add :user_agent, :string

      timestamps()
    end

    create_if_not_exists unique_index(:shell_sessions, [:session_id])
    create_if_not_exists index(:shell_sessions, [:user_id])
    create_if_not_exists index(:shell_sessions, [:agent_id])
    create_if_not_exists index(:shell_sessions, [:status])
    create_if_not_exists index(:shell_sessions, [:started_at])
  end
end
