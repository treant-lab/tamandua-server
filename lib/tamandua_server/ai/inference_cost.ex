defmodule TamanduaServer.AI.InferenceCost do
  @moduledoc """
  Schema for AI inference cost tracking records.

  Stores individual inference events with full cost attribution:
  - Model identification and pricing
  - Token usage (input/output)
  - Entity attribution (agent, user, process, team)
  - Calculated costs in USD

  ## Fields

  - `model_id` - AI model identifier (e.g., "gpt-4", "claude-3-opus")
  - `tokens_in` - Input token count
  - `tokens_out` - Output token count
  - `cost_usd` - Calculated cost in USD
  - `latency_ms` - Request latency in milliseconds
  - `agent_id` - Associated EDR agent
  - `user_id` - User who initiated the request
  - `process_id` - Process identifier on the endpoint
  - `team_id` - Team/group for cost allocation
  - `session_id` - InferenceTracker session correlation ID
  - `metadata` - Additional context (API endpoint, model version, etc.)
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Repo

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "ai_inference_costs" do
    field :model_id, :string
    field :tokens_in, :integer
    field :tokens_out, :integer
    field :cost_usd, :decimal
    field :latency_ms, :integer
    field :agent_id, :string
    field :user_id, :binary_id
    field :process_id, :string
    field :team_id, :string
    field :session_id, :string
    field :metadata, :map, default: %{}

    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps(type: :utc_datetime)
  end

  @required_fields [:model_id, :tokens_in, :tokens_out, :cost_usd, :agent_id]
  @optional_fields [:latency_ms, :user_id, :process_id, :team_id, :session_id, :metadata, :organization_id]

  @doc false
  def changeset(inference_cost, attrs) do
    inference_cost
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_number(:tokens_in, greater_than_or_equal_to: 0)
    |> validate_number(:tokens_out, greater_than_or_equal_to: 0)
    |> validate_number(:cost_usd, greater_than_or_equal_to: 0)
    |> validate_number(:latency_ms, greater_than_or_equal_to: 0)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:user_id)
  end

  @doc """
  Create a new inference cost record.
  """
  def create(attrs) do
    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Get total cost for an entity within a time range.

  ## Parameters

  - `entity_type` - One of :agent, :user, :process, :team, :model
  - `entity_id` - Entity identifier
  - `start_time` - Start of time range
  - `end_time` - End of time range (defaults to now)

  ## Returns

  Map with aggregated metrics:

      %{
        total_cost_usd: Decimal.t(),
        total_inferences: integer(),
        total_tokens_in: integer(),
        total_tokens_out: integer(),
        avg_latency_ms: float() | nil
      }
  """
  def get_cost_for_entity(entity_type, entity_id, start_time, end_time \\ nil) do
    end_time = end_time || DateTime.utc_now()

    query = base_query()
    |> where([c], c.inserted_at >= ^start_time and c.inserted_at <= ^end_time)
    |> filter_by_entity(entity_type, entity_id)
    |> select([c], %{
      total_cost_usd: sum(c.cost_usd),
      total_inferences: count(c.id),
      total_tokens_in: sum(c.tokens_in),
      total_tokens_out: sum(c.tokens_out),
      avg_latency_ms: avg(c.latency_ms)
    })

    Repo.one(query) || %{
      total_cost_usd: Decimal.new(0),
      total_inferences: 0,
      total_tokens_in: 0,
      total_tokens_out: 0,
      avg_latency_ms: nil
    }
  end

  @doc """
  Get cost breakdown by model for an entity.
  """
  def get_cost_by_model(entity_type, entity_id, start_time, end_time \\ nil) do
    end_time = end_time || DateTime.utc_now()

    query = base_query()
    |> where([c], c.inserted_at >= ^start_time and c.inserted_at <= ^end_time)
    |> filter_by_entity(entity_type, entity_id)
    |> group_by([c], c.model_id)
    |> select([c], {c.model_id, sum(c.cost_usd), count(c.id)})

    Repo.all(query)
    |> Enum.map(fn {model, cost, count} -> {model, cost, count} end)
  end

  @doc """
  Get daily cost trend for an entity.
  """
  def get_daily_trend(entity_type, entity_id, days \\ 30) do
    start_time = DateTime.add(DateTime.utc_now(), -days * 86400, :second)

    query = base_query()
    |> where([c], c.inserted_at >= ^start_time)
    |> filter_by_entity(entity_type, entity_id)
    |> group_by([c], fragment("DATE(?)", c.inserted_at))
    |> order_by([c], fragment("DATE(?)", c.inserted_at))
    |> select([c], {fragment("DATE(?)", c.inserted_at), sum(c.cost_usd), count(c.id)})

    Repo.all(query)
    |> Enum.map(fn {date, cost, count} -> %{date: date, cost_usd: cost, inferences: count} end)
  end

  @doc """
  Get top consumers by cost for a period.
  """
  def get_top_consumers(entity_type, start_time, end_time \\ nil, limit \\ 10) do
    end_time = end_time || DateTime.utc_now()

    field_name = entity_field(entity_type)

    query = base_query()
    |> where([c], c.inserted_at >= ^start_time and c.inserted_at <= ^end_time)
    |> where([c], not is_nil(field(c, ^field_name)))
    |> group_by([c], field(c, ^field_name))
    |> order_by([c], desc: sum(c.cost_usd))
    |> limit(^limit)
    |> select([c], {field(c, ^field_name), sum(c.cost_usd), count(c.id)})

    Repo.all(query)
    |> Enum.map(fn {entity_id, cost, count} ->
      %{entity_id: entity_id, cost_usd: cost, inferences: count}
    end)
  end

  @doc """
  Persist an inference record from CostGovernor.
  """
  def persist_inference(record) when is_map(record) do
    attrs = %{
      model_id: record.model_id,
      tokens_in: record.tokens_in,
      tokens_out: record.tokens_out,
      cost_usd: Decimal.from_float(record.cost_usd),
      latency_ms: record.latency_ms,
      agent_id: record.agent_id,
      user_id: record[:user_id],
      process_id: record[:process_id],
      team_id: record[:team_id],
      session_id: record[:session_id],
      metadata: record[:metadata] || %{}
    }

    create(attrs)
  end

  # Private

  defp base_query do
    from(c in __MODULE__)
  end

  defp filter_by_entity(query, :agent, entity_id) do
    where(query, [c], c.agent_id == ^entity_id)
  end

  defp filter_by_entity(query, :user, entity_id) do
    where(query, [c], c.user_id == ^entity_id)
  end

  defp filter_by_entity(query, :process, entity_id) do
    where(query, [c], c.process_id == ^entity_id)
  end

  defp filter_by_entity(query, :team, entity_id) do
    where(query, [c], c.team_id == ^entity_id)
  end

  defp filter_by_entity(query, :model, entity_id) do
    where(query, [c], c.model_id == ^entity_id)
  end

  defp filter_by_entity(query, :organization, entity_id) do
    where(query, [c], c.organization_id == ^entity_id)
  end

  defp entity_field(:agent), do: :agent_id
  defp entity_field(:user), do: :user_id
  defp entity_field(:process), do: :process_id
  defp entity_field(:team), do: :team_id
  defp entity_field(:model), do: :model_id
end
