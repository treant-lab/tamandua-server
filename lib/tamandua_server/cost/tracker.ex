defmodule TamanduaServer.Cost.Tracker do
  @moduledoc """
  Cost tracking service.

  Tracks costs by resource type, enabling granular cost analysis:
  - Agent infrastructure (compute, memory)
  - Storage (telemetry, logs, artifacts)
  - Network bandwidth (agent<->server, exports)
  - ML inference (GPU, API calls)
  - Third-party integrations (API costs)

  Provides cost allocation by department, project, and other tags.
  """
  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Cost.{CostEntry, CostAllocationRule}
  alias TamanduaServer.Agents
  import Ecto.Query

  @collection_interval :timer.hours(1) # Collect costs hourly
  @daily_rollup_time {23, 0, 0} # Roll up daily costs at 11 PM

  # Cost rates (USD per unit)
  @cost_rates %{
    agent_cpu_hour: 0.05,        # $0.05 per CPU hour
    agent_memory_gb_hour: 0.01,  # $0.01 per GB-hour
    storage_gb_month: 0.10,      # $0.10 per GB/month
    bandwidth_gb: 0.05,          # $0.05 per GB transferred
    ml_inference_call: 0.001,    # $0.001 per ML inference
    integration_api_call: 0.0001 # $0.0001 per integration API call
  }

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    Logger.info("[Cost.Tracker] Starting cost tracking service")

    # Schedule periodic cost collection
    schedule_collection()
    schedule_daily_rollup()

    state = %{
      hourly_metrics: %{},
      last_collection: DateTime.utc_now()
    }

    {:ok, state}
  end

  ## Public API

  @doc """
  Record a cost entry.
  """
  def record_cost(organization_id, attrs) do
    GenServer.call(__MODULE__, {:record_cost, organization_id, attrs})
  end

  @doc """
  Get costs for a date range.
  """
  def get_costs(organization_id, opts \\ []) do
    from_date = Keyword.get(opts, :from_date, Date.utc_today() |> Date.add(-30))
    to_date = Keyword.get(opts, :to_date, Date.utc_today())
    resource_type = Keyword.get(opts, :resource_type)
    tags = Keyword.get(opts, :tags, %{})

    query = from c in CostEntry,
      where: c.organization_id == ^organization_id,
      where: c.date >= ^from_date and c.date <= ^to_date,
      order_by: [desc: c.date]

    query = if resource_type do
      from c in query, where: c.resource_type == ^resource_type
    else
      query
    end

    query = if map_size(tags) > 0 do
      Enum.reduce(tags, query, fn {key, value}, q ->
        from c in q, where: fragment("?->>? = ?", c.metadata, ^to_string(key), ^value)
      end)
    else
      query
    end

    Repo.all(query)
  end

  @doc """
  Get cost summary for a date range.
  """
  def get_summary(organization_id, opts \\ []) do
    from_date = Keyword.get(opts, :from_date, Date.utc_today() |> Date.add(-30))
    to_date = Keyword.get(opts, :to_date, Date.utc_today())

    # Total costs
    total_query = from c in CostEntry,
      where: c.organization_id == ^organization_id,
      where: c.date >= ^from_date and c.date <= ^to_date,
      select: %{
        total_cost: sum(c.cost_usd),
        resource_type: c.resource_type
      },
      group_by: c.resource_type

    breakdown = Repo.all(total_query)
      |> Enum.map(fn row -> {row.resource_type, Decimal.to_float(row.total_cost || Decimal.new(0))} end)
      |> Map.new()

    total_cost = Map.values(breakdown) |> Enum.sum()

    # Daily trend
    daily_query = from c in CostEntry,
      where: c.organization_id == ^organization_id,
      where: c.date >= ^from_date and c.date <= ^to_date,
      select: %{
        date: c.date,
        cost: sum(c.cost_usd)
      },
      group_by: c.date,
      order_by: c.date

    daily_costs = Repo.all(daily_query)
      |> Enum.map(fn row ->
        {row.date, Decimal.to_float(row.cost || Decimal.new(0))}
      end)

    # Top cost drivers
    top_resources_query = from c in CostEntry,
      where: c.organization_id == ^organization_id,
      where: c.date >= ^from_date and c.date <= ^to_date,
      where: not is_nil(c.resource_id),
      select: %{
        resource_id: c.resource_id,
        resource_type: c.resource_type,
        total_cost: sum(c.cost_usd)
      },
      group_by: [c.resource_id, c.resource_type],
      order_by: [desc: sum(c.cost_usd)],
      limit: 10

    top_resources = Repo.all(top_resources_query)
      |> Enum.map(fn row ->
        %{
          resource_id: row.resource_id,
          resource_type: row.resource_type,
          cost: Decimal.to_float(row.total_cost || Decimal.new(0))
        }
      end)

    %{
      total_cost: total_cost,
      breakdown_by_type: breakdown,
      daily_costs: daily_costs,
      top_resources: top_resources,
      period: %{from: from_date, to: to_date}
    }
  end

  @doc """
  Get costs by tag (for chargeback reports).
  """
  def get_costs_by_tag(organization_id, tag_key, opts \\ []) do
    from_date = Keyword.get(opts, :from_date, Date.utc_today() |> Date.add(-30))
    to_date = Keyword.get(opts, :to_date, Date.utc_today())

    query = from c in CostEntry,
      where: c.organization_id == ^organization_id,
      where: c.date >= ^from_date and c.date <= ^to_date,
      where: fragment("? \\? ?", c.metadata, ^tag_key),
      select: %{
        tag_value: fragment("?->>?", c.metadata, ^tag_key),
        total_cost: sum(c.cost_usd),
        resource_type: c.resource_type
      },
      group_by: [fragment("?->>?", c.metadata, ^tag_key), c.resource_type]

    Repo.all(query)
    |> Enum.group_by(& &1.tag_value)
    |> Enum.map(fn {tag_value, rows} ->
      breakdown = rows
        |> Enum.map(fn row -> {row.resource_type, Decimal.to_float(row.total_cost || Decimal.new(0))} end)
        |> Map.new()

      total = Map.values(breakdown) |> Enum.sum()

      %{
        tag_value: tag_value,
        total_cost: total,
        breakdown: breakdown
      }
    end)
    |> Enum.sort_by(& &1.total_cost, :desc)
  end

  ## GenServer Callbacks

  @impl true
  def handle_call({:record_cost, organization_id, attrs}, _from, state) do
    attrs = Map.put(attrs, :organization_id, organization_id)

    result = %CostEntry{}
    |> CostEntry.changeset(attrs)
    |> Repo.insert()

    {:reply, result, state}
  end

  @impl true
  def handle_info(:collect_costs, state) do
    Logger.debug("[Cost.Tracker] Collecting hourly costs")

    # Collect costs from all organizations
    collect_all_costs()

    schedule_collection()
    {:noreply, %{state | last_collection: DateTime.utc_now()}}
  end

  def handle_info(:daily_rollup, state) do
    Logger.info("[Cost.Tracker] Running daily cost rollup")

    # Perform daily aggregation and cleanup
    run_daily_rollup()

    schedule_daily_rollup()
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  def handle_info(_msg, state), do: {:noreply, state}

  ## Private Functions

  defp schedule_collection do
    Process.send_after(self(), :collect_costs, @collection_interval)
  end

  defp schedule_daily_rollup do
    # Calculate time until next 11 PM
    now = DateTime.utc_now()
    {hours, minutes, _seconds} = @daily_rollup_time

    target = DateTime.new!(Date.utc_today(), Time.new!(hours, minutes, 0))
    target = if DateTime.compare(now, target) == :gt do
      DateTime.add(target, 1, :day)
    else
      target
    end

    milliseconds_until = DateTime.diff(target, now, :millisecond)
    Process.send_after(self(), :daily_rollup, milliseconds_until)
  end

  defp collect_all_costs do
    # This would normally query from various sources
    # For now, we'll collect agent infrastructure costs
    collect_agent_costs()
    collect_storage_costs()
    collect_ml_costs()
  end

  defp collect_agent_costs do
    # Get all agents and their resource usage
    agents = Agents.Registry.list_all()
    today = Date.utc_today()

    Enum.each(agents, fn agent ->
      # Get agent health metrics (CPU, memory usage)
      case Agents.Registry.get_health(agent.agent_id) do
        {:ok, health} ->
          # Calculate hourly cost based on resource usage
          cpu_hours = (health[:cpu_usage] || 0) / 100.0 # normalize to hours
          memory_gb_hours = (health[:memory_usage] || 0) / 1024.0 # convert MB to GB

          cpu_cost = cpu_hours * @cost_rates.agent_cpu_hour
          memory_cost = memory_gb_hours * @cost_rates.agent_memory_gb_hour
          total_cost = cpu_cost + memory_cost

          if total_cost > 0 do
            # Apply allocation rules to determine tags
            tags = apply_allocation_rules(agent)

            %CostEntry{}
            |> CostEntry.changeset(%{
              organization_id: agent.organization_id || get_default_org_id(),
              date: today,
              resource_type: "agent",
              resource_id: agent.agent_id,
              cost_usd: Decimal.from_float(total_cost),
              usage_amount: Decimal.from_float(cpu_hours + memory_gb_hours),
              usage_unit: "resource_hours",
              metadata: tags
            })
            |> Repo.insert()
          end

        _ -> :ok
      end
    end)
  end

  defp collect_storage_costs do
    # Query storage usage from ClickHouse or telemetry store
    # For now, this is a placeholder
    :ok
  end

  defp collect_ml_costs do
    # Query ML inference counts from ML service
    # For now, this is a placeholder
    :ok
  end

  defp apply_allocation_rules(agent) do
    # Get allocation rules for this organization
    # and apply matching rules to generate tags
    %{
      "hostname" => agent.hostname,
      "os_type" => agent.os_type
    }
  end

  defp run_daily_rollup do
    # Aggregate hourly entries into daily summaries
    # Clean up old detailed entries if needed
    :ok
  end

  defp get_default_org_id do
    # Get or create default organization
    case Repo.one(from o in TamanduaServer.Accounts.Organization, limit: 1) do
      nil ->
        Logger.warning("[Cost.Tracker] No organizations found, skipping cost tracking")
        nil
      org -> org.id
    end
  end
end
