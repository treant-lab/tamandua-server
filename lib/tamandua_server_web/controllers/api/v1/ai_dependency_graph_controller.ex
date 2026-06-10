defmodule TamanduaServerWeb.API.V1.AIDependencyGraphController do
  @moduledoc """
  API endpoints for AI Model Dependency Graph analysis.

  Provides access to:
  - Model consumer/process model queries
  - Model lineage tracking
  - Risk propagation analysis
  - Critical model identification
  - Unusual chain detection
  - Graph export (DOT/JSON)
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.AI.DependencyGraph

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Get graph statistics.

  ## Response
  - node_count: Total number of nodes
  - edge_count: Total number of edges
  - model_count: Number of model nodes
  - process_count: Number of process nodes
  """
  def stats(conn, _params) do
    stats = DependencyGraph.stats()
    json(conn, %{status: "success", data: stats})
  end

  @doc """
  Get all processes that consume (load) a given model.

  ## Parameters
  - model_id: The model identifier

  ## Response
  - consumers: List of process info with relationship type (direct/indirect)
  """
  def model_consumers(conn, %{"model_id" => model_id}) do
    consumers = DependencyGraph.get_model_consumers(model_id)

    json(conn, %{
      status: "success",
      data: %{
        model_id: model_id,
        consumers: consumers,
        consumer_count: length(consumers)
      }
    })
  end

  @doc """
  Get all models loaded by a given process.

  ## Parameters
  - process_id: The process identifier (typically agent_id:pid)

  ## Response
  - models: List of model info with edge data
  """
  def process_models(conn, %{"process_id" => process_id}) do
    models = DependencyGraph.get_process_models(process_id)

    json(conn, %{
      status: "success",
      data: %{
        process_id: process_id,
        models: models,
        model_count: length(models)
      }
    })
  end

  @doc """
  Get the lineage (parent chain) of a model.

  Traces back through fine-tuning and distillation relationships.

  ## Parameters
  - model_id: The model identifier

  ## Response
  - lineage: List of parent models with derivation type
  """
  def model_lineage(conn, %{"model_id" => model_id}) do
    lineage = DependencyGraph.get_model_lineage(model_id)

    json(conn, %{
      status: "success",
      data: %{
        model_id: model_id,
        lineage: lineage,
        depth: length(lineage)
      }
    })
  end

  @doc """
  Get all derivatives (child models) of a model.

  ## Parameters
  - model_id: The model identifier

  ## Response
  - derivatives: List of child models
  """
  def model_derivatives(conn, %{"model_id" => model_id}) do
    derivatives = DependencyGraph.get_model_derivatives(model_id)

    json(conn, %{
      status: "success",
      data: %{
        model_id: model_id,
        derivatives: derivatives,
        count: length(derivatives)
      }
    })
  end

  @doc """
  Propagate risk through the dependency graph.

  When a model is identified as compromised or vulnerable, calculates
  the impact on all dependent models and processes.

  ## Parameters
  - model_id: The model with known risk
  - risk_score: Risk score from 0.0 to 1.0

  ## Response
  - affected_models: Models with propagated risk
  - affected_processes: Processes with propagated risk
  - total_impact_score: Aggregate impact
  - critical_paths: Highest-risk dependency paths
  """
  def propagate_risk(conn, %{"model_id" => model_id} = params) do
    risk_score = parse_float(params["risk_score"], 0.8)

    if risk_score < 0.0 or risk_score > 1.0 do
      conn
      |> put_status(:bad_request)
      |> json(%{status: "error", message: "risk_score must be between 0.0 and 1.0"})
    else
      result = DependencyGraph.propagate_risk(model_id, risk_score)
      json(conn, %{status: "success", data: result})
    end
  end

  @doc """
  Find critical models - models with the most dependents.

  ## Parameters
  - limit: Maximum results (default: 10)
  - min_dependents: Minimum dependents to be considered critical (default: 3)

  ## Response
  - critical_models: List of models with dependency counts and criticality scores
  """
  def critical_models(conn, params) do
    limit = parse_int(params["limit"], 10)
    min_dependents = parse_int(params["min_dependents"], 3)

    critical = DependencyGraph.find_critical_models(limit: limit, min_dependents: min_dependents)

    json(conn, %{
      status: "success",
      data: %{
        critical_models: critical,
        count: length(critical),
        query: %{limit: limit, min_dependents: min_dependents}
      }
    })
  end

  @doc """
  Detect unusual dependency chains that may indicate supply chain attacks.

  Looks for:
  - Unusually long derivation chains
  - Models loaded from many different processes
  - Circular dependencies

  ## Response
  - anomalies: List of detected anomalies with severity and description
  """
  def unusual_chains(conn, _params) do
    anomalies = DependencyGraph.detect_unusual_chains()

    json(conn, %{
      status: "success",
      data: %{
        anomalies: anomalies,
        count: length(anomalies),
        severity_summary: summarize_severities(anomalies)
      }
    })
  end

  @doc """
  Export the dependency graph in a specified format.

  ## Parameters
  - format: "dot" for Graphviz or "json" for D3.js

  ## Response
  - For DOT: text/vnd.graphviz content
  - For JSON: application/json content
  """
  def export(conn, %{"format" => "dot"}) do
    dot_content = DependencyGraph.export_graph(:dot)

    conn
    |> put_resp_content_type("text/vnd.graphviz")
    |> put_resp_header("content-disposition", "attachment; filename=\"ai-dependencies.dot\"")
    |> send_resp(200, dot_content)
  end

  def export(conn, %{"format" => "json"}) do
    json_content = DependencyGraph.export_graph(:json)

    conn
    |> put_resp_content_type("application/json")
    |> put_resp_header("content-disposition", "attachment; filename=\"ai-dependencies.json\"")
    |> send_resp(200, json_content)
  end

  def export(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{status: "error", message: "format must be 'dot' or 'json'"})
  end

  @doc """
  Get a subgraph centered on a specific node.

  ## Parameters
  - node_id: The center node ID
  - depth: Maximum depth to traverse (default: 3)

  ## Response
  - Subgraph with nodes and edges within the specified depth
  """
  def subgraph(conn, %{"node_id" => node_id} = params) do
    depth = parse_int(params["depth"], 3)
    depth = min(depth, 10)  # Cap at 10 for performance

    subgraph = DependencyGraph.get_subgraph(node_id, depth)

    json(conn, %{status: "success", data: subgraph})
  end

  @doc """
  Add a dependency relationship.

  ## Parameters
  - source_id: Source node ID
  - target_id: Target node ID
  - dependency_type: "loads", "derived_from", or "distilled_from"
  - attributes: Optional additional attributes
  """
  def add_dependency(conn, params) do
    with {:ok, source_id} <- fetch_required(params, "source_id"),
         {:ok, target_id} <- fetch_required(params, "target_id"),
         {:ok, dep_type_str} <- fetch_required(params, "dependency_type"),
         {:ok, dep_type} <- parse_dependency_type(dep_type_str) do

      attrs = params["attributes"] || %{}
      DependencyGraph.add_dependency(source_id, target_id, dep_type, attrs)

      json(conn, %{
        status: "success",
        message: "Dependency added",
        data: %{
          source_id: source_id,
          target_id: target_id,
          dependency_type: dep_type
        }
      })
    else
      {:error, message} ->
        conn
        |> put_status(:bad_request)
        |> json(%{status: "error", message: message})
    end
  end

  @doc """
  Remove a dependency relationship.

  ## Parameters
  - source_id: Source node ID
  - target_id: Target node ID
  - dependency_type: "loads", "derived_from", or "distilled_from"
  """
  def remove_dependency(conn, params) do
    with {:ok, source_id} <- fetch_required(params, "source_id"),
         {:ok, target_id} <- fetch_required(params, "target_id"),
         {:ok, dep_type_str} <- fetch_required(params, "dependency_type"),
         {:ok, dep_type} <- parse_dependency_type(dep_type_str) do

      DependencyGraph.remove_dependency(source_id, target_id, dep_type)

      json(conn, %{
        status: "success",
        message: "Dependency removed"
      })
    else
      {:error, message} ->
        conn
        |> put_status(:bad_request)
        |> json(%{status: "error", message: message})
    end
  end

  # ---------------------------------------------------------------------------
  # Private Helpers
  # ---------------------------------------------------------------------------

  defp fetch_required(params, key) do
    case Map.get(params, key) do
      nil -> {:error, "#{key} is required"}
      "" -> {:error, "#{key} is required"}
      value -> {:ok, value}
    end
  end

  defp parse_dependency_type("loads"), do: {:ok, :loads}
  defp parse_dependency_type("derived_from"), do: {:ok, :derived_from}
  defp parse_dependency_type("distilled_from"), do: {:ok, :distilled_from}
  defp parse_dependency_type(_), do: {:error, "dependency_type must be 'loads', 'derived_from', or 'distilled_from'"}

  defp parse_int(nil, default), do: default
  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {n, _} -> n
      :error -> default
    end
  end
  defp parse_int(value, _default) when is_integer(value), do: value

  defp parse_float(nil, default), do: default
  defp parse_float(value, default) when is_binary(value) do
    case Float.parse(value) do
      {f, _} -> f
      :error -> default
    end
  end
  defp parse_float(value, _default) when is_float(value), do: value
  defp parse_float(value, _default) when is_integer(value), do: value / 1

  defp summarize_severities(anomalies) do
    Enum.reduce(anomalies, %{high: 0, medium: 0, low: 0}, fn anomaly, acc ->
      severity = anomaly[:severity] || :low
      Map.update(acc, severity, 1, &(&1 + 1))
    end)
  end
end
