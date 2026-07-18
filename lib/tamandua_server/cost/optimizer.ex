defmodule TamanduaServer.Cost.Optimizer do
  @moduledoc """
  Cost optimization recommendation engine.

  Analyzes resource usage and identifies cost-saving opportunities:
  - Over-provisioned agents (low CPU/memory usage)
  - Excessive log retention
  - Unused integrations
  - Inefficient queries
  - Storage optimization (compression, archival)

  Provides actionable recommendations with estimated savings.
  """
  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Cost.{CostEntry, CostRecommendation}
  alias TamanduaServer.Agents
  import Ecto.Query

  @analysis_interval :timer.hours(6) # Run analysis every 6 hours
  @low_cpu_threshold 20.0 # CPU usage below 20% is considered underutilized
  @low_memory_threshold 40.0 # Memory usage below 40% is considered underutilized
  @idle_agent_days 7 # Agent not seen in 7 days is idle

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    Logger.info("[Cost.Optimizer] Starting cost optimization service")

    # Schedule periodic analysis
    schedule_analysis()

    {:ok, %{}}
  end

  ## Public API

  @doc """
  Generate optimization recommendations for an organization.
  """
  def generate_recommendations(organization_id) do
    GenServer.call(__MODULE__, {:generate_recommendations, organization_id}, :infinity)
  end

  @doc """
  Get active recommendations for an organization.
  """
  def get_recommendations(organization_id, opts \\ []) do
    status = Keyword.get(opts, :status, "new")

    query = from r in CostRecommendation,
      where: r.organization_id == ^organization_id,
      where: r.status == ^status,
      order_by: [desc: r.estimated_savings_usd]

    Repo.all(query)
  end

  @doc """
  Implement a recommendation (if it supports one-click implementation).
  """
  def implement_recommendation(recommendation_id, user_id) do
    GenServer.call(__MODULE__, {:implement_recommendation, recommendation_id, user_id})
  end

  @doc """
  Dismiss a recommendation.
  """
  def dismiss_recommendation(recommendation_id, user_id, reason) do
    recommendation = Repo.get!(CostRecommendation, recommendation_id)

    recommendation
    |> CostRecommendation.changeset(%{
      status: "dismissed",
      dismissed_by: user_id,
      dismissed_at: DateTime.utc_now(),
      dismissal_reason: reason
    })
    |> Repo.update()
  end

  @doc """
  Get total potential savings for an organization.
  """
  def get_potential_savings(organization_id) do
    query = from r in CostRecommendation,
      where: r.organization_id == ^organization_id,
      where: r.status in ["new", "acknowledged"],
      select: sum(r.estimated_savings_usd)

    Repo.one(query) |> case do
      nil -> Decimal.new(0)
      amount -> amount
    end
  end

  ## GenServer Callbacks

  @impl true
  def handle_call({:generate_recommendations, organization_id}, _from, state) do
    result = do_generate_recommendations(organization_id)
    {:reply, result, state}
  end

  def handle_call({:implement_recommendation, recommendation_id, user_id}, _from, state) do
    result = do_implement_recommendation(recommendation_id, user_id)
    {:reply, result, state}
  end

  @impl true
  def handle_info(:analyze_costs, state) do
    Logger.info("[Cost.Optimizer] Running cost optimization analysis")

    # Analyze all organizations
    analyze_all_organizations()

    schedule_analysis()
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  def handle_info(_msg, state), do: {:noreply, state}

  ## Private Functions

  defp schedule_analysis do
    Process.send_after(self(), :analyze_costs, @analysis_interval)
  end

  defp analyze_all_organizations do
    query = from o in TamanduaServer.Accounts.Organization, select: o.id

    Repo.all(query)
    |> Enum.each(fn org_id ->
      Task.start(fn ->
        do_generate_recommendations(org_id)
      end)
    end)
  end

  defp do_generate_recommendations(organization_id) do
    recommendations = []

    # Run various analyzers
    recommendations = recommendations ++ analyze_underutilized_agents(organization_id)
    recommendations = recommendations ++ analyze_idle_agents(organization_id)
    recommendations = recommendations ++ analyze_storage_usage(organization_id)
    recommendations = recommendations ++ analyze_excessive_retention(organization_id)
    recommendations = recommendations ++ analyze_ml_usage(organization_id)

    # Save recommendations
    saved = Enum.map(recommendations, fn rec_attrs ->
      # Check if similar recommendation already exists
      existing = Repo.get_by(CostRecommendation,
        organization_id: organization_id,
        recommendation_type: rec_attrs.recommendation_type,
        resource_id: rec_attrs.resource_id,
        status: "new"
      )

      case existing do
        nil ->
          %CostRecommendation{}
          |> CostRecommendation.changeset(Map.put(rec_attrs, :organization_id, organization_id))
          |> Repo.insert()

        rec ->
          # Update existing recommendation
          rec
          |> CostRecommendation.changeset(rec_attrs)
          |> Repo.update()
      end
    end)

    successful = Enum.count(saved, fn
      {:ok, _} -> true
      _ -> false
    end)

    Logger.info("[Cost.Optimizer] Generated #{successful} recommendations for org #{organization_id}")
    {:ok, successful}
  end

  defp analyze_underutilized_agents(organization_id) do
    # Find agents with consistently low resource usage
    agents = Agents.Registry.list_all()
      |> Enum.filter(fn agent ->
        agent.organization_id == organization_id || is_nil(agent.organization_id)
      end)

    Enum.flat_map(agents, fn agent ->
      case Agents.Registry.get_health(agent.agent_id) do
        {:ok, health} ->
          cpu_usage = health[:cpu_usage] || 0
          memory_usage = health[:memory_usage] || 0

          cond do
            cpu_usage < @low_cpu_threshold && memory_usage < @low_memory_threshold ->
              # Get cost for this agent (last 30 days)
              agent_cost = get_agent_cost(organization_id, agent.agent_id, 30)

              if agent_cost > 0 do
                # Estimate 30% savings from downsizing or consolidation
                estimated_savings = agent_cost * 0.3

                [%{
                  recommendation_type: "overprovisioned_agent",
                  severity: "medium",
                  title: "Underutilized agent: #{agent.hostname}",
                  description: """
                  Agent #{agent.hostname} (#{agent.agent_id}) is consistently underutilized:
                  - CPU usage: #{Float.round(cpu_usage, 1)}% (below #{@low_cpu_threshold}%)
                  - Memory usage: #{Float.round(memory_usage, 1)}% (below #{@low_memory_threshold}%)

                  Consider:
                  1. Consolidating workloads from this agent to other agents
                  2. Reducing agent collection frequency
                  3. Decommissioning if no longer needed

                  Current monthly cost: $#{Float.round(agent_cost, 2)}
                  Potential savings: $#{Float.round(estimated_savings, 2)}/month (30%)
                  """,
                  resource_type: "agent",
                  resource_id: agent.agent_id,
                  current_cost_usd: Decimal.from_float(agent_cost),
                  estimated_savings_usd: Decimal.from_float(estimated_savings),
                  savings_percent: Decimal.from_float(30.0),
                  implementation_effort: "moderate",
                  action_payload: %{
                    "action" => "reduce_collection_frequency",
                    "agent_id" => agent.agent_id,
                    "current_cpu" => cpu_usage,
                    "current_memory" => memory_usage
                  }
                }]
              else
                []
              end

            true -> []
          end

        _ -> []
      end
    end)
  end

  defp analyze_idle_agents(organization_id) do
    # Find agents that haven't been seen recently
    cutoff_date = DateTime.utc_now() |> DateTime.add(-@idle_agent_days, :day)

    agents = Agents.Registry.list_all()
      |> Enum.filter(fn agent ->
        (agent.organization_id == organization_id || is_nil(agent.organization_id)) &&
        agent.last_seen_at && DateTime.compare(agent.last_seen_at, cutoff_date) == :lt
      end)

    Enum.map(agents, fn agent ->
      # Get cost for this agent (last 30 days)
      agent_cost = get_agent_cost(organization_id, agent.agent_id, 30)

      %{
        recommendation_type: "idle_agent",
        severity: "high",
        title: "Idle agent incurring costs: #{agent.hostname}",
        description: """
        Agent #{agent.hostname} (#{agent.agent_id}) has not been active for #{@idle_agent_days} days.
        Last seen: #{format_datetime(agent.last_seen_at)}

        This agent is incurring ongoing costs without providing value.

        Recommendation: Decommission this agent to eliminate costs.

        Current monthly cost: $#{Float.round(agent_cost, 2)}
        Potential savings: $#{Float.round(agent_cost, 2)}/month (100%)
        """,
        resource_type: "agent",
        resource_id: agent.agent_id,
        current_cost_usd: Decimal.from_float(agent_cost),
        estimated_savings_usd: Decimal.from_float(agent_cost),
        savings_percent: Decimal.from_float(100.0),
        implementation_effort: "easy",
        action_payload: %{
          "action" => "decommission_agent",
          "agent_id" => agent.agent_id,
          "last_seen" => DateTime.to_iso8601(agent.last_seen_at)
        }
      }
    end)
  end

  defp analyze_storage_usage(_organization_id) do
    # Analyze storage costs and identify optimization opportunities
    # Placeholder for now
    []
  end

  defp analyze_excessive_retention(_organization_id) do
    # Analyze retention policies and identify excessive retention
    # Placeholder for now
    []
  end

  defp analyze_ml_usage(_organization_id) do
    # Analyze ML inference usage and identify optimization opportunities
    # Placeholder for now
    []
  end

  defp get_agent_cost(organization_id, agent_id, days) do
    from_date = Date.utc_today() |> Date.add(-days)
    to_date = Date.utc_today()

    query = from c in CostEntry,
      where: c.organization_id == ^organization_id,
      where: c.resource_type == "agent",
      where: c.resource_id == ^agent_id,
      where: c.date >= ^from_date and c.date <= ^to_date,
      select: sum(c.cost_usd)

    case Repo.one(query) do
      nil -> 0.0
      amount -> Decimal.to_float(amount)
    end
  end

  defp do_implement_recommendation(recommendation_id, user_id) do
    case Repo.get(CostRecommendation, recommendation_id) do
      nil ->
        {:error, :not_found}

      recommendation ->
        apply_recommendation(recommendation, user_id)
    end
  end

  defp apply_recommendation(recommendation, user_id) do
    case recommendation.implementation_effort do
      "one_click" ->
        # Execute the action
        result = execute_recommendation_action(recommendation)

        case result do
          :ok ->
            recommendation
            |> CostRecommendation.changeset(%{
              status: "implemented",
              implemented_by: user_id,
              implemented_at: DateTime.utc_now()
            })
            |> Repo.update()

          {:error, reason} ->
            {:error, reason}
        end

      _ ->
        # Mark as acknowledged
        recommendation
        |> CostRecommendation.changeset(%{status: "acknowledged"})
        |> Repo.update()
    end
  end

  defp execute_recommendation_action(recommendation) do
    # Execute the action based on action_payload
    # Placeholder for now
    Logger.info("[Cost.Optimizer] Executing recommendation action: #{recommendation.recommendation_type}")
    :ok
  end

  defp format_datetime(nil), do: "Never"
  defp format_datetime(dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S UTC")
  end
end
