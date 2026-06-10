defmodule TamanduaServerWeb.API.V1.CloudController do
  @moduledoc """
  Controller for Cloud Workloads API endpoints.

  Provides visibility and security monitoring for cloud-native
  infrastructure including containers, Kubernetes clusters,
  and serverless workloads.
  """
  use TamanduaServerWeb, :controller

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  List all monitored cloud workloads.

  ## Query Parameters
  - `provider` - Filter by cloud provider: "aws", "azure", "gcp"
  - `type` - Filter by workload type: "vm", "container", "serverless"
  - `status` - Filter by status: "running", "stopped", "unknown"
  - `limit` - Maximum number of results (default: 100)
  - `offset` - Offset for pagination (default: 0)
  """
  def workloads(conn, params) do
    filters = %{
      provider: params["provider"],
      type: params["type"],
      status: params["status"],
      limit: parse_int(params["limit"], 100),
      offset: parse_int(params["offset"], 0)
    }

    workloads = list_workloads(filters)

    json(conn, %{
      data: workloads,
      meta: %{
        count: length(workloads),
        filters: Map.take(filters, [:provider, :type, :status])
      }
    })
  end

  @doc """
  List and monitor container instances.

  ## Query Parameters
  - `host` - Filter by host agent ID
  - `runtime` - Filter by container runtime: "docker", "containerd", "cri-o"
  - `image` - Filter by image name (partial match)
  - `status` - Filter by container status
  - `limit` - Maximum number of results (default: 100)
  """
  def containers(conn, params) do
    filters = %{
      host: params["host"],
      runtime: params["runtime"],
      image: params["image"],
      status: params["status"],
      limit: parse_int(params["limit"], 100)
    }

    containers = list_containers(filters)

    json(conn, %{
      data: containers,
      meta: %{
        count: length(containers),
        total_running: count_by_status(containers, "running"),
        total_stopped: count_by_status(containers, "stopped"),
        filters: Map.take(filters, [:host, :runtime, :status])
      }
    })
  end

  @doc """
  Get Kubernetes cluster information and security status.

  ## Path Parameters
  - `cluster_id` - Kubernetes cluster identifier (optional, lists all if not provided)

  ## Query Parameters
  - `namespace` - Filter by namespace
  - `resource_type` - Filter by resource: "pods", "deployments", "services", "secrets"
  """
  def kubernetes(conn, params) do
    cluster_id = params["cluster_id"]
    namespace = params["namespace"]
    resource_type = params["resource_type"]

    data =
      if cluster_id do
        get_cluster_details(cluster_id, namespace, resource_type)
      else
        list_kubernetes_clusters()
      end

    case data do
      {:error, reason} ->
        {:error, reason}

      clusters_or_details ->
        json(conn, %{
          data: clusters_or_details,
          meta: %{
            cluster_id: cluster_id,
            namespace: namespace,
            resource_type: resource_type
          }
        })
    end
  end

  @doc """
  Get cloud security posture assessment.

  ## Query Parameters
  - `provider` - Cloud provider to assess
  - `scope` - Assessment scope: "all", "network", "iam", "storage", "compute"
  - `severity` - Minimum severity: "critical", "high", "medium", "low"
  """
  def security_posture(conn, params) do
    filters = %{
      provider: params["provider"],
      scope: params["scope"] || "all",
      severity: params["severity"]
    }

    assessment = assess_security_posture(filters)

    json(conn, %{
      data: assessment,
      meta: %{
        assessed_at: DateTime.utc_now(),
        filters: filters
      }
    })
  end

  # Private functions

  # ETS tables for cloud workload data reported by agents
  @workloads_table :cloud_workloads
  @containers_table :cloud_containers
  @k8s_clusters_table :cloud_k8s_clusters
  @security_findings_table :cloud_security_findings

  defp ensure_cloud_table(table) do
    case :ets.whereis(table) do
      :undefined -> :ets.new(table, [:set, :public, :named_table])
      _ -> :ok
    end
  end

  defp list_workloads(filters) do
    # Query workloads from ETS (populated by agent telemetry)
    ensure_cloud_table(@workloads_table)

    try do
      :ets.tab2list(@workloads_table)
      |> Enum.map(fn {_id, workload} -> workload end)
      |> filter_by(:provider, filters.provider)
      |> filter_by(:type, filters.type)
      |> filter_by(:status, filters.status)
      |> Enum.take(filters.limit)
    rescue
      _ -> []
    end
  end

  defp list_containers(filters) do
    # Query containers from ETS (populated by agent container runtime collectors)
    ensure_cloud_table(@containers_table)

    try do
      :ets.tab2list(@containers_table)
      |> Enum.map(fn {_id, container} -> container end)
      |> filter_by(:runtime, filters.runtime)
      |> filter_by(:status, filters.status)
      |> filter_by_partial(:image, filters.image)
      |> then(fn containers ->
        if filters.host do
          Enum.filter(containers, fn c -> c[:host_agent_id] == filters.host end)
        else
          containers
        end
      end)
      |> Enum.take(filters.limit)
    rescue
      _ -> []
    end
  end

  defp list_kubernetes_clusters do
    # Query Kubernetes clusters from ETS
    ensure_cloud_table(@k8s_clusters_table)

    try do
      :ets.tab2list(@k8s_clusters_table)
      |> Enum.map(fn {_id, cluster} -> cluster end)
    rescue
      _ -> []
    end
  end

  defp get_cluster_details(cluster_id, namespace, resource_type) do
    ensure_cloud_table(@k8s_clusters_table)

    case :ets.lookup(@k8s_clusters_table, cluster_id) do
      [{^cluster_id, cluster}] ->
        %{
          id: cluster_id,
          name: Map.get(cluster, :name, cluster_id),
          version: Map.get(cluster, :version, "unknown"),
          nodes: list_nodes(cluster_id),
          resources: list_resources(cluster_id, namespace, resource_type),
          security_findings: list_security_findings(cluster_id, namespace),
          network_policies: list_network_policies(cluster_id, namespace)
        }

      [] ->
        %{
          id: cluster_id,
          name: cluster_id,
          version: "unknown",
          nodes: [],
          resources: list_resources(cluster_id, namespace, resource_type),
          security_findings: [],
          network_policies: []
        }
    end
  rescue
    _ ->
      %{id: cluster_id, name: cluster_id, version: "unknown",
        nodes: [], resources: %{}, security_findings: [], network_policies: []}
  end

  defp list_nodes(cluster_id) do
    ensure_cloud_table(@k8s_clusters_table)

    case :ets.lookup(@k8s_clusters_table, cluster_id) do
      [{^cluster_id, cluster}] -> Map.get(cluster, :nodes, [])
      [] -> []
    end
  rescue
    _ -> []
  end

  defp list_resources(cluster_id, _namespace, nil) do
    ensure_cloud_table(@k8s_clusters_table)

    case :ets.lookup(@k8s_clusters_table, cluster_id) do
      [{^cluster_id, cluster}] ->
        Map.get(cluster, :resource_summary, %{
          pods: 0, deployments: 0, services: 0, configmaps: 0, secrets: 0
        })
      [] ->
        %{pods: 0, deployments: 0, services: 0, configmaps: 0, secrets: 0}
    end
  rescue
    _ -> %{pods: 0, deployments: 0, services: 0, configmaps: 0, secrets: 0}
  end

  defp list_resources(cluster_id, _namespace, resource_type) do
    ensure_cloud_table(@k8s_clusters_table)

    case :ets.lookup(@k8s_clusters_table, cluster_id) do
      [{^cluster_id, cluster}] ->
        resources = Map.get(cluster, :resources, %{})
        Map.get(resources, resource_type, [])
      [] -> []
    end
  rescue
    _ -> []
  end

  defp list_security_findings(cluster_id, _namespace) do
    ensure_cloud_table(@security_findings_table)

    try do
      case :ets.lookup(@security_findings_table, cluster_id) do
        [{^cluster_id, findings}] -> findings
        [] -> []
      end
    rescue
      _ -> []
    end
  end

  defp list_network_policies(cluster_id, _namespace) do
    ensure_cloud_table(@k8s_clusters_table)

    case :ets.lookup(@k8s_clusters_table, cluster_id) do
      [{^cluster_id, cluster}] -> Map.get(cluster, :network_policies, [])
      [] -> []
    end
  rescue
    _ -> []
  end

  defp assess_security_posture(filters) do
    # Aggregate security findings from all cloud sources
    ensure_cloud_table(@security_findings_table)

    all_findings = try do
      :ets.tab2list(@security_findings_table)
      |> Enum.flat_map(fn {_id, findings} ->
        if is_list(findings), do: findings, else: [findings]
      end)
      |> then(fn findings ->
        if filters.provider do
          Enum.filter(findings, fn f -> Map.get(f, :provider) == filters.provider end)
        else
          findings
        end
      end)
      |> then(fn findings ->
        if filters.severity do
          severity_rank = %{"critical" => 4, "high" => 3, "medium" => 2, "low" => 1}
          min_rank = Map.get(severity_rank, filters.severity, 0)
          Enum.filter(findings, fn f ->
            Map.get(severity_rank, Map.get(f, :severity, "low"), 0) >= min_rank
          end)
        else
          findings
        end
      end)
    rescue
      _ -> []
    end

    # Categorize findings
    categorized = Enum.group_by(all_findings, fn f -> Map.get(f, :category, "other") end)

    category_score = fn category_findings ->
      total = length(category_findings)
      if total == 0 do
        100
      else
        critical = Enum.count(category_findings, fn f -> f[:severity] == "critical" end)
        high = Enum.count(category_findings, fn f -> f[:severity] == "high" end)
        medium = Enum.count(category_findings, fn f -> f[:severity] == "medium" end)
        max(0, 100 - critical * 15 - high * 8 - medium * 3)
      end
    end

    build_category = fn cat_name ->
      findings = Map.get(categorized, cat_name, [])
      %{
        score: category_score.(findings),
        findings: length(findings),
        critical: Enum.count(findings, fn f -> f[:severity] == "critical" end),
        high: Enum.count(findings, fn f -> f[:severity] == "high" end),
        medium: Enum.count(findings, fn f -> f[:severity] == "medium" end)
      }
    end

    categories = %{
      identity_and_access: build_category.("identity_and_access"),
      network_security: build_category.("network_security"),
      data_protection: build_category.("data_protection"),
      compute_security: build_category.("compute_security"),
      logging_monitoring: build_category.("logging_monitoring")
    }

    scores = Enum.map(Map.values(categories), & &1.score)
    overall = if length(scores) > 0, do: round(Enum.sum(scores) / length(scores)), else: 100

    top_findings = all_findings
    |> Enum.sort_by(fn f ->
      case Map.get(f, :severity, "low") do
        "critical" -> 0
        "high" -> 1
        "medium" -> 2
        _ -> 3
      end
    end)
    |> Enum.take(10)

    %{
      overall_score: overall,
      provider: filters.provider || "all",
      categories: categories,
      top_findings: top_findings,
      compliance: %{
        cis_benchmark: %{passed: 0, failed: 0, not_applicable: 0, percentage: 0},
        pci_dss: %{passed: 0, failed: 0, not_applicable: 0, percentage: 0}
      }
    }
  end

  defp filter_by(list, _key, nil), do: list
  defp filter_by(list, key, value) do
    Enum.filter(list, fn item -> Map.get(item, key) == value end)
  end

  defp filter_by_partial(list, _key, nil), do: list
  defp filter_by_partial(list, key, value) do
    Enum.filter(list, fn item ->
      item_value = Map.get(item, key) || ""
      String.contains?(String.downcase(item_value), String.downcase(value))
    end)
  end

  defp count_by_status(containers, status) do
    Enum.count(containers, fn c -> c.status == status end)
  end

  defp parse_int(nil, default), do: default
  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(value, _default) when is_integer(value), do: value
  defp parse_int(_, default), do: default
end
