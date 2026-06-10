defmodule TamanduaServer.Hunting.QueryHistory do
  @moduledoc """
  Schema for tracking query execution history.
  Used for recent searches and analytics.
  """
  use Ecto.Schema
  import Ecto.Changeset

  schema "query_history" do
    field :query, :string
    field :query_type, :string, default: "hunt"
    field :result_count, :integer
    field :execution_time_ms, :integer

    belongs_to :user, TamanduaServer.Accounts.User
    belongs_to :agent, TamanduaServer.Agents.Agent

    timestamps(updated_at: false)
  end

  @doc false
  def changeset(query_history, attrs) do
    query_history
    |> cast(attrs, [:query, :query_type, :result_count, :execution_time_ms, :user_id, :agent_id])
    |> validate_required([:query])
    |> validate_length(:query, min: 1, max: 10_000)
  end
end
