defmodule TamanduaServerWeb.API.V1.ContainerSecurityController do
  @moduledoc """
  Container Runtime Security API Controller.

  Provides endpoints for:
  - Container inventory and monitoring
  - Security policy management
  - Image vulnerability scanning
  - Kubernetes workload security
  - Container escape detection
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.ContainerSecurity

  action_fallback TamanduaServerWeb.FallbackController

  # -------------------------------------------------------------------
  # Container Inventory
  # -------------------------------------------------------------------

  @doc """
  List all containers with optional filters.

  ## Query Parameters
  - agent_id: Filter by agent
  - runtime: Filter by container runtime (docker, containerd, cri-o, podman)
  - image: Filter by image name (partial match)
  - status: Filter by status (running, stopped, paused)
  - namespace: Filter by Kubernetes namespace
  - privileged: Filter by privileged flag (true/false)
  - limit: Maximum results (default: 100)
  """
  def index(conn, params) do
    filters = %{
      agent_id: params["agent_id"],
      runtime: params["runtime"],
      image: params["image"],
      status: params["status"],
      namespace: params["namespace"],
      privileged: parse_bool(params["privileged"])
    }

    containers = ContainerSecurity.list_containers(filters)

    json(conn, %{
      data: Enum.map(containers, &serialize_container/1),
      meta: %{
        total: length(containers),
        filters: Map.reject(filters, fn {_, v} -> is_nil(v) end)
      }
    })
  end

  @doc """
  Get container details.
  """
  def show(conn, %{"id" => container_id}) do
    case ContainerSecurity.get_container(container_id) do
      {:ok, container} ->
        json(conn, %{data: serialize_container(container)})

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  @doc """
  Get containers for a specific agent.
  """
  def agent_containers(conn, %{"agent_id" => agent_id}) do
    containers = ContainerSecurity.containers_for_agent(agent_id)

    json(conn, %{
      data: Enum.map(containers, &serialize_container/1),
      meta: %{agent_id: agent_id, count: length(containers)}
    })
  end

  @doc """
  Get high-risk containers.
  """
  def high_risk(conn, params) do
    limit = parse_int(params["limit"], 20)
    containers = ContainerSecurity.high_risk_containers(limit)

    json(conn, %{
      data: Enum.map(containers, &serialize_container/1),
      meta: %{limit: limit}
    })
  end

  # -------------------------------------------------------------------
  # Images
  # -------------------------------------------------------------------

  @doc """
  List all container images.
  """
  def images(conn, params) do
    filters = %{
      name: params["name"],
      tag: params["tag"]
    }

    images = ContainerSecurity.list_images(filters)

    json(conn, %{
      data: Enum.map(images, &serialize_image/1),
      meta: %{count: length(images)}
    })
  end

  @doc """
  Get image vulnerabilities.
  """
  def image_vulnerabilities(conn, %{"image" => image} = params) do
    tag = params["tag"] || "latest"

    case ContainerSecurity.get_image_vulnerabilities(image, tag) do
      {:ok, vulns} ->
        json(conn, %{data: serialize_vulnerabilities(vulns)})

      {:error, :not_found} ->
        # Image not scanned yet, trigger scan
        case ContainerSecurity.scan_image(image, tag) do
          {:ok, vulns} ->
            json(conn, %{data: serialize_vulnerabilities(vulns)})

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  @doc """
  Trigger image vulnerability scan.
  """
  def scan_image(conn, %{"image" => image} = params) do
    tag = params["tag"] || "latest"

    case ContainerSecurity.scan_image(image, tag) do
      {:ok, vulns} ->
        json(conn, %{
          data: serialize_vulnerabilities(vulns),
          message: "Scan completed"
        })

      {:error, reason} ->
        {:error, reason}
    end
  end

  # -------------------------------------------------------------------
  # Security Policies
  # -------------------------------------------------------------------

  @doc """
  List security policies.
  """
  def list_policies(conn, params) do
    scope = case params["scope"] do
      "global" -> :global
      "namespace" -> :namespace
      "agent_group" -> :agent_group
      _ -> nil
    end

    policies = ContainerSecurity.list_policies(scope)

    json(conn, %{
      data: Enum.map(policies, &serialize_policy/1),
      meta: %{count: length(policies)}
    })
  end

  @doc """
  Create or update a security policy.
  """
  def upsert_policy(conn, params) do
    attrs = %{
      id: params["id"],
      name: params["name"],
      description: params["description"],
      scope: parse_scope(params["scope"]),
      scope_value: params["scope_value"],
      enabled: params["enabled"] != false,
      rules: parse_rules(params["rules"] || []),
      actions: parse_actions(params["actions"] || ["alert"])
    }

    case ContainerSecurity.upsert_policy(attrs) do
      {:ok, policy} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize_policy(policy), message: "Policy saved"})

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Delete a security policy.
  """
  def delete_policy(conn, %{"id" => policy_id}) do
    ContainerSecurity.delete_policy(policy_id)
    json(conn, %{message: "Policy deleted"})
  end

  # -------------------------------------------------------------------
  # Kubernetes Workloads
  # -------------------------------------------------------------------

  @doc """
  List Kubernetes workloads.
  """
  def k8s_workloads(conn, params) do
    filters = %{
      namespace: params["namespace"],
      kind: params["kind"]
    }

    workloads = ContainerSecurity.list_k8s_workloads(filters)

    json(conn, %{
      data: Enum.map(workloads, &serialize_k8s_workload/1),
      meta: %{count: length(workloads)}
    })
  end

  @doc """
  Get Kubernetes namespace summary.
  """
  def k8s_namespaces(conn, _params) do
    workloads = ContainerSecurity.list_k8s_workloads(%{})

    namespaces = workloads
    |> Enum.group_by(& &1.namespace)
    |> Enum.map(fn {namespace, ws} ->
      %{
        namespace: namespace,
        workload_count: length(ws),
        total_containers: Enum.sum(Enum.map(ws, &length(&1.containers))),
        avg_security_score: calculate_avg_score(ws),
        violation_count: Enum.sum(Enum.map(ws, &length(&1.violations)))
      }
    end)

    json(conn, %{data: namespaces})
  end

  # -------------------------------------------------------------------
  # Statistics & Dashboard
  # -------------------------------------------------------------------

  @doc """
  Get container security statistics.
  """
  def statistics(conn, _params) do
    stats = ContainerSecurity.get_statistics()
    json(conn, %{data: stats})
  end

  @doc """
  Get runtime distribution.
  """
  def runtime_distribution(conn, _params) do
    distribution = ContainerSecurity.runtime_distribution()
    json(conn, %{data: distribution})
  end

  @doc """
  Get container security dashboard data.
  """
  def dashboard(conn, _params) do
    stats = ContainerSecurity.get_statistics()
    high_risk = ContainerSecurity.high_risk_containers(10)
    runtime_dist = ContainerSecurity.runtime_distribution()

    json(conn, %{
      data: %{
        statistics: stats,
        high_risk_containers: Enum.map(high_risk, &serialize_container_summary/1),
        runtime_distribution: runtime_dist,
        recent_violations: get_recent_violations(),
        policy_compliance: get_policy_compliance()
      }
    })
  end

  # -------------------------------------------------------------------
  # Private Helpers
  # -------------------------------------------------------------------

  defp serialize_container(container) do
    %{
      id: container.id,
      container_id: container.container_id,
      name: container.name,
      image: container.image,
      image_tag: container.image_tag,
      runtime: container.runtime,
      agent_id: container.agent_id,
      status: container.status,
      pid: container.pid,
      user: container.user,
      command: container.command,
      created_at: container.created_at,
      security: %{
        privileged: container.privileged,
        host_network: container.host_network,
        host_pid: container.host_pid,
        host_ipc: container.host_ipc,
        capabilities: container.capabilities,
        read_only_rootfs: container.read_only_rootfs,
        run_as_root: container.run_as_root,
        sensitive_mounts: length(container.sensitive_mounts)
      },
      kubernetes: if container.k8s_namespace do
        %{
          namespace: container.k8s_namespace,
          pod: container.k8s_pod,
          service_account: container.k8s_service_account
        }
      else
        nil
      end,
      security_score: container.security_score,
      violations: container.security_violations,
      last_seen: container.last_seen
    }
  end

  defp serialize_container_summary(container) do
    %{
      id: container.id,
      name: container.name,
      image: "#{container.image}:#{container.image_tag}",
      agent_id: container.agent_id,
      security_score: container.security_score,
      privileged: container.privileged,
      violation_count: length(container.security_violations)
    }
  end

  defp serialize_image(image) do
    %{
      image: image.image,
      tag: image.tag,
      digest: image.digest,
      first_seen: image.first_seen,
      last_seen: image.last_seen,
      container_count: image.container_count,
      agents: image.agents
    }
  end

  defp serialize_vulnerabilities(vulns) do
    %{
      image: vulns.image,
      tag: vulns.tag,
      digest: vulns.digest,
      scan_time: vulns.scan_time,
      scanner: vulns.scanner,
      summary: %{
        critical: vulns.critical_count,
        high: vulns.high_count,
        medium: vulns.medium_count,
        low: vulns.low_count,
        total: vulns.critical_count + vulns.high_count + vulns.medium_count + vulns.low_count
      },
      vulnerabilities: vulns.vulnerabilities
    }
  end

  defp serialize_policy(policy) do
    %{
      id: policy.id,
      name: policy.name,
      description: policy.description,
      scope: policy.scope,
      scope_value: policy.scope_value,
      enabled: policy.enabled,
      rules: policy.rules,
      actions: policy.actions,
      created_at: policy.created_at,
      updated_at: policy.updated_at
    }
  end

  defp serialize_k8s_workload(workload) do
    %{
      id: workload.id,
      cluster_id: workload.cluster_id,
      namespace: workload.namespace,
      name: workload.name,
      kind: workload.kind,
      replicas: workload.replicas,
      containers: workload.containers,
      service_account: workload.service_account,
      security_context: workload.security_context,
      security_score: workload.security_score,
      violations: workload.violations,
      last_updated: workload.last_updated
    }
  end

  defp parse_scope(nil), do: :global
  defp parse_scope("global"), do: :global
  defp parse_scope("namespace"), do: :namespace
  defp parse_scope("agent_group"), do: :agent_group
  defp parse_scope(_), do: :global

  defp parse_rules(rules) when is_list(rules) do
    Enum.map(rules, fn rule ->
      %{
        type: safe_to_existing_atom(rule["type"] || "unknown", ~w(syscall file network process capability unknown)) || :unknown,
        name: rule["name"],
        severity: rule["severity"] || "medium",
        description: rule["description"],
        mitre_technique: rule["mitre_technique"],
        capabilities: rule["capabilities"]
      }
    end)
  end
  defp parse_rules(_), do: []

  defp parse_actions(actions) when is_list(actions) do
    Enum.map(actions, fn
      "alert" -> :alert
      "block" -> :block
      "audit" -> :audit
      a when is_atom(a) -> a
      _ -> :audit
    end)
  end
  defp parse_actions(_), do: [:alert]

  defp parse_int(nil, default), do: default
  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(val, _) when is_integer(val), do: val
  defp parse_int(_, default), do: default

  defp parse_bool(nil), do: nil
  defp parse_bool("true"), do: true
  defp parse_bool("false"), do: false
  defp parse_bool(val) when is_boolean(val), do: val
  defp parse_bool(_), do: nil

  defp calculate_avg_score([]), do: 0
  defp calculate_avg_score(workloads) do
    total = Enum.reduce(workloads, 0, &(&1.security_score + &2))
    Float.round(total / length(workloads), 1)
  end

  # -------------------------------------------------------------------
  # Container Escape Detection
  # -------------------------------------------------------------------

  alias TamanduaServer.ContainerSecurity.EscapeDetector

  @doc """
  Get container escape detection statistics.
  """
  def escape_stats(conn, _params) do
    stats = EscapeDetector.stats()
    json(conn, %{data: stats})
  end

  @doc """
  Get recent container escape detection events.
  """
  def escape_events(conn, params) do
    limit = parse_int(params["limit"], 50)
    events = EscapeDetector.recent_events(limit)

    json(conn, %{
      data: Enum.map(events, &serialize_escape_event/1),
      meta: %{count: length(events)}
    })
  end

  @doc """
  Get containers with high escape risk scores.
  """
  def escape_high_risk(conn, params) do
    threshold = parse_int(params["threshold"], 50)
    containers = EscapeDetector.high_risk_containers(threshold)

    json(conn, %{
      data: containers,
      meta: %{threshold: threshold, count: length(containers)}
    })
  end

  @doc """
  Get active privilege escalation chains.
  """
  def escape_escalation_chains(conn, _params) do
    chains = EscapeDetector.active_escalation_chains()

    json(conn, %{
      data: Enum.map(chains, &serialize_escalation_chain/1),
      meta: %{count: length(chains)}
    })
  end

  @doc """
  Get escape risk score for a specific container.
  """
  def escape_risk_score(conn, %{"container_id" => container_id}) do
    score = EscapeDetector.get_risk_score(container_id)

    json(conn, %{
      data: %{
        container_id: container_id,
        risk_score: score,
        risk_level: risk_level_from_score(score)
      }
    })
  end

  defp serialize_escape_event(event) do
    %{
      type: to_string_escape_type(event.type),
      cve: event.cve,
      name: event.name,
      description: event.description,
      severity: event.severity,
      confidence: event.confidence,
      agent_id: event.agent_id,
      container_id: event.container_id,
      mitre_techniques: event.mitre_techniques,
      matched_indicators: event.matched_indicators,
      timestamp: event.timestamp
    }
  end

  defp serialize_escalation_chain(chain) do
    %{
      container_id: chain.container_id,
      agent_id: chain.agent_id,
      current_level: chain.current_level,
      steps: Enum.map(chain.steps, fn step ->
        %{
          level: step.level,
          event_type: step.event_type,
          uid: step.uid,
          euid: step.euid,
          is_host: step.is_host,
          timestamp: step.timestamp
        }
      end),
      last_updated: chain.last_updated
    }
  end

  defp to_string_escape_type({:generic, category}), do: "generic_#{category}"
  defp to_string_escape_type(type) when is_atom(type), do: Atom.to_string(type)
  defp to_string_escape_type(type), do: to_string(type)

  defp risk_level_from_score(score) do
    cond do
      score >= 80 -> "critical"
      score >= 60 -> "high"
      score >= 40 -> "medium"
      score >= 20 -> "low"
      true -> "none"
    end
  end

  # -------------------------------------------------------------------
  # Private Helpers
  # -------------------------------------------------------------------

  defp get_recent_violations do
    # Get recent container violations from high-risk containers
    ContainerSecurity.high_risk_containers(50)
    |> Enum.flat_map(fn c ->
      Enum.map(c.security_violations, fn v ->
        Map.merge(v, %{
          container_id: c.container_id,
          container_name: c.name,
          image: c.image
        })
      end)
    end)
    |> Enum.take(20)
  end

  defp get_policy_compliance do
    policies = ContainerSecurity.list_policies(nil)
    containers = ContainerSecurity.list_containers(%{})

    enabled_policies = Enum.filter(policies, & &1.enabled)

    Enum.map(enabled_policies, fn policy ->
      # Count containers violating this policy
      violations = Enum.count(containers, fn c ->
        Enum.any?(c.security_violations, fn v ->
          Enum.any?(policy.rules, &(&1[:name] == v[:rule_name]))
        end)
      end)

      %{
        policy_id: policy.id,
        policy_name: policy.name,
        total_containers: length(containers),
        violations: violations,
        compliance_rate: if(length(containers) > 0,
          do: Float.round((length(containers) - violations) / length(containers) * 100, 1),
          else: 100.0
        )
      }
    end)
  end

end
