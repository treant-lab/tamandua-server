defmodule TamanduaServerWeb.API.V1.AIPostureController do
  @moduledoc """
  AI Agent Posture endpoints for monitoring and managing the security
  posture of AI agents deployed across the organization.
  """
  use TamanduaServerWeb, :controller

  alias TamanduaServer.AISecurity.AgentPosture

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  List all registered AI agents with their current posture status.

  ## Parameters
    - status: Filter by status (active, inactive, degraded, unknown)
    - risk_level: Filter by risk level (low, medium, high, critical)
    - agent_type: Filter by agent type
    - limit: Number of results (default 50)
    - offset: Pagination offset
  """
  def list_agents(conn, params) do
    # Build keyword list filters for list_agents/1
    filters = []
    filters = if status = Map.get(params, "status") do
      [{:status, safe_to_existing_atom(status, ~w(active inactive degraded unknown))} | filters]
    else
      filters
    end
    filters = if risk_level = Map.get(params, "risk_level") do
      [{:risk_level, safe_to_existing_atom(risk_level, ~w(low medium high critical))} | filters]
    else
      filters
    end
    filters = if vendor = Map.get(params, "vendor") do
      [{:vendor, vendor} | filters]
    else
      filters
    end

    # list_agents/1 returns a list directly (not wrapped in {:ok, ...})
    agents = AgentPosture.list_agents(filters)

    # Calculate summary stats
    total_active = Enum.count(agents, &(&1.status == :active))
    high_risk_count = Enum.count(agents, fn a -> a.risk_score >= 0.7 end)

    json(conn, %{
      status: "success",
      data: %{
        agents: agents,
        total: length(agents),
        summary: %{
          total_active: total_active,
          high_risk_count: high_risk_count
        }
      }
    })
  end

  @doc """
  Get detailed posture information for a specific AI agent.

  ## Parameters
    - id: The agent ID (path parameter)
    - include_history: Whether to include posture history
    - include_permissions: Whether to include detailed permission analysis
  """
  def agent_detail(conn, %{"id" => agent_id}) do
    # get_agent_posture/1 returns the full posture report for an agent
    case AgentPosture.get_agent_posture(agent_id) do
      {:ok, posture} ->
        json(conn, %{
          status: "success",
          data: %{
            agent_id: posture.agent_id,
            agent_name: posture.agent_name,
            status: posture.status,
            risk_score: posture.risk_score,
            risk_level: posture.risk_level,
            approved: posture.approved,
            permissions_summary: posture.permissions_summary,
            data_access_summary: posture.data_access_summary,
            last_assessment: posture.last_assessment,
            recommendations_count: posture.recommendations_count,
            last_seen_at: posture.last_seen_at
          }
        })

      {:error, :not_found} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  def agent_detail(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{status: "error", message: "agent id is required"})
  end

  @doc """
  Get compliance status of AI agents against security policies and frameworks.

  ## Parameters
    - agent_id: Required - the agent ID to check compliance for
    - framework: Compliance framework filter (optional)
  """
  def compliance_status(conn, params) do
    agent_id = Map.get(params, "agent_id")

    if is_nil(agent_id) do
      conn
      |> put_status(:bad_request)
      |> json(%{status: "error", message: "agent_id is required"})
    else
      # compliance_status/1 takes agent_id and returns compliance across all frameworks
      case AgentPosture.compliance_status(agent_id) do
        {:ok, compliance} ->
          json(conn, %{
            status: "success",
            data: %{
              agent_id: compliance.agent_id,
              frameworks: compliance.frameworks,
              summary: compliance.summary,
              overall_compliant: compliance.overall_compliant,
              checked_at: compliance.checked_at
            }
          })

        {:error, :not_found} ->
          {:error, :not_found}

        {:error, reason} ->
          {:error, to_string(reason)}
      end
    end
  end

  @doc """
  Get data flow analysis for AI agents showing data access patterns and risks.

  ## Parameters
    - agent_id: Required - the agent ID to analyze
  """
  def data_flows(conn, params) do
    agent_id = Map.get(params, "agent_id")

    if is_nil(agent_id) do
      conn
      |> put_status(:bad_request)
      |> json(%{status: "error", message: "agent_id is required"})
    else
      # data_flows/1 takes agent_id and returns list of data flow events
      case AgentPosture.data_flows(agent_id) do
        {:ok, flows} ->
          json(conn, %{
            status: "success",
            data: %{
              agent_id: agent_id,
              flows: flows,
              total_flows: length(flows)
            }
          })

        {:error, :not_found} ->
          {:error, :not_found}

        {:error, reason} ->
          {:error, to_string(reason)}
      end
    end
  end

end
