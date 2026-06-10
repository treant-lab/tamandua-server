defmodule TamanduaServer.Hunting.QueryResultHistory do
  @moduledoc """
  Schema for tracking query execution results over time.
  """
  use Ecto.Schema
  import Ecto.Changeset

  schema "query_result_history" do
    belongs_to :query_schedule, TamanduaServer.Hunting.QuerySchedule
    belongs_to :saved_query, TamanduaServer.Hunting.SavedQuery
    belongs_to :user, TamanduaServer.Accounts.User

    field :query_text, :string
    field :result_count, :integer
    field :execution_time_ms, :integer
    field :status, :string
    field :error_message, :string
    field :results_summary, :map

    timestamps(updated_at: false)
  end

  @doc false
  def changeset(history, attrs) do
    history
    |> cast(attrs, [
      :query_schedule_id, :saved_query_id, :user_id,
      :query_text, :result_count, :execution_time_ms,
      :status, :error_message, :results_summary
    ])
    |> validate_required([:query_text, :status])
    |> validate_inclusion(:status, ~w(success error timeout))
  end
end
