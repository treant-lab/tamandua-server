defmodule TamanduaServer.Kubernetes.RuntimeProtection do
  @moduledoc """
  Kubernetes runtime security monitoring and detection.

  Provides rule-based detection for dangerous runtime behaviours in
  containerised workloads, including:

  - Container escape detection (nsenter, chroot, mount, ptrace, etc.)
  - Privileged container monitoring
  - Host path mount detection
  - Sensitive volume mount detection (secrets, configmaps with sensitive names)
  - Network policy violation detection

  ## Usage

  The primary entry point is `evaluate_runtime_event/1`, which takes a telemetry
  event map and returns a list of findings. Each finding is a map with:

  - `:rule` - The rule identifier (e.g. `"container_escape_attempt"`)
  - `:severity` - `"critical"`, `"high"`, `"medium"`, or `"low"`
  - `:description` - Human-readable description
  - `:mitre_technique` - Relevant MITRE ATT&CK technique ID
  - `:metadata` - Additional context about the detection

  ## Integration

  Findings are intended to be fed into the alert pipeline via
  `TamanduaServer.Alerts.create_alert/1`.
  """

  require Logger

  # -------------------------------------------------------------------
  # Container Escape Detection
  # -------------------------------------------------------------------

  @escape_binaries [
    "nsenter",
    "chroot",
    "unshare",
    "runc",
    "crun",
    "containerd-shim"
  ]

  @escape_syscalls [
    "ptrace",
    "mount",
    "umount",
    "pivot_root",
    "clone",
    "unshare",
    "setns"
  ]

  @escape_paths [
    "/proc/1/root",
    "/proc/sysrq-trigger",
    "/proc/sys/kernel/core_pattern",
    "/sys/fs/cgroup",
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/var/run/crio/crio.sock"
  ]

  # Capabilities that enable container escape
  @dangerous_capabilities [
    "CAP_SYS_ADMIN",
    "CAP_SYS_PTRACE",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_DAC_OVERRIDE",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW"
  ]

  # -------------------------------------------------------------------
  # Sensitive Volume Mounts
  # -------------------------------------------------------------------

  @sensitive_host_paths [
    "/etc/shadow",
    "/etc/passwd",
    "/etc/kubernetes",
    "/etc/cni",
    "/var/lib/kubelet",
    "/var/lib/etcd",
    "/var/run/docker.sock",
    "/run/containerd",
    "/var/run/crio",
    "/root/.kube",
    "/home",
    "/proc",
    "/sys"
  ]

  defp sensitive_secret_patterns do
    [
      ~r/password/i,
      ~r/credential/i,
      ~r/token/i,
      ~r/secret/i,
      ~r/api[_-]?key/i,
      ~r/private[_-]?key/i,
      ~r/tls[_-]?cert/i,
      ~r/ssh[_-]?key/i,
      ~r/kubeconfig/i,
      ~r/service[_-]?account/i
    ]
  end

  # -------------------------------------------------------------------
  # Public API
  # -------------------------------------------------------------------

  @doc """
  Evaluate a runtime telemetry event for container security violations.

  The event map should contain contextual information about the container activity.
  Recognized keys include:

  - `"type"` - Event type (e.g. `"process"`, `"file"`, `"network"`, `"syscall"`)
  - `"container_id"` - Container identifier
  - `"pod_name"` - Kubernetes pod name
  - `"namespace"` - Kubernetes namespace
  - `"process_name"` - Name of the process
  - `"command_line"` - Full command line
  - `"file_path"` - File being accessed
  - `"syscall"` - System call name
  - `"capabilities"` - List of Linux capabilities
  - `"security_context"` - Pod/container security context
  - `"volumes"` - List of volume mount specifications
  - `"network"` - Network event details

  Returns a list of finding maps. An empty list means no violations detected.
  """
  @spec evaluate_runtime_event(map()) :: [map()]
  def evaluate_runtime_event(event) when is_map(event) do
    findings = []

    findings = findings ++ check_container_escape(event)
    findings = findings ++ check_privileged_container(event)
    findings = findings ++ check_host_path_mounts(event)
    findings = findings ++ check_sensitive_volume_mounts(event)
    findings = findings ++ check_network_policy_violations(event)

    findings
  end

  @doc """
  Check a pod specification for static security issues before deployment.

  Takes a pod spec map (the `spec` field of a Pod resource) and returns
  a list of findings for any security concerns.
  """
  @spec evaluate_pod_spec(map()) :: [map()]
  def evaluate_pod_spec(pod_spec) when is_map(pod_spec) do
    findings = []

    findings = findings ++ check_privileged_pod_spec(pod_spec)
    findings = findings ++ check_host_namespace_pod_spec(pod_spec)
    findings = findings ++ check_host_path_volumes(pod_spec)
    findings = findings ++ check_sensitive_volumes(pod_spec)
    findings = findings ++ check_dangerous_capabilities_pod_spec(pod_spec)

    findings
  end

  @doc """
  Return all detection rules with their metadata.

  Useful for displaying available rules in the UI or for configuration.
  """
  @spec list_rules() :: [map()]
  def list_rules do
    [
      %{
        id: "container_escape_attempt",
        name: "Container Escape Attempt",
        description: "Detects processes and syscalls commonly used to escape container isolation",
        severity: "critical",
        mitre_technique: "T1611",
        enabled: true
      },
      %{
        id: "privileged_container",
        name: "Privileged Container",
        description: "Detects containers running in privileged mode",
        severity: "high",
        mitre_technique: "T1611",
        enabled: true
      },
      %{
        id: "host_path_mount",
        name: "Host Path Mount",
        description: "Detects containers mounting sensitive host filesystem paths",
        severity: "high",
        mitre_technique: "T1611",
        enabled: true
      },
      %{
        id: "sensitive_volume_mount",
        name: "Sensitive Volume Mount",
        description: "Detects mounts of secrets or configmaps with sensitive names",
        severity: "medium",
        mitre_technique: "T1552",
        enabled: true
      },
      %{
        id: "network_policy_violation",
        name: "Network Policy Violation",
        description: "Detects network traffic that violates expected pod network policies",
        severity: "medium",
        mitre_technique: "T1046",
        enabled: true
      },
      %{
        id: "host_namespace_access",
        name: "Host Namespace Access",
        description: "Detects pods with hostNetwork, hostPID, or hostIPC enabled",
        severity: "high",
        mitre_technique: "T1611",
        enabled: true
      },
      %{
        id: "dangerous_capabilities",
        name: "Dangerous Linux Capabilities",
        description: "Detects containers with dangerous Linux capabilities (SYS_ADMIN, SYS_PTRACE, etc.)",
        severity: "high",
        mitre_technique: "T1611",
        enabled: true
      }
    ]
  end

  # -------------------------------------------------------------------
  # Container Escape Detection
  # -------------------------------------------------------------------

  defp check_container_escape(event) do
    findings = []

    # Check for escape-related process execution
    findings =
      case Map.get(event, "process_name") do
        nil ->
          findings

        process_name ->
          if Enum.any?(@escape_binaries, &(String.downcase(process_name) == String.downcase(&1))) do
            [
              %{
                rule: "container_escape_attempt",
                severity: "critical",
                description: "Container escape binary detected: #{process_name}",
                mitre_technique: "T1611",
                metadata: %{
                  "process_name" => process_name,
                  "command_line" => Map.get(event, "command_line"),
                  "container_id" => Map.get(event, "container_id"),
                  "pod_name" => Map.get(event, "pod_name"),
                  "namespace" => Map.get(event, "namespace")
                }
              }
              | findings
            ]
          else
            findings
          end
      end

    # Check for escape-related command line patterns
    findings =
      case Map.get(event, "command_line") do
        nil ->
          findings

        cmd ->
          cmd_lower = String.downcase(cmd)

          cond do
            String.contains?(cmd_lower, "nsenter") and String.contains?(cmd_lower, "-t 1") ->
              [
                %{
                  rule: "container_escape_attempt",
                  severity: "critical",
                  description: "nsenter targeting PID 1 detected (container breakout attempt)",
                  mitre_technique: "T1611",
                  metadata: %{
                    "command_line" => cmd,
                    "container_id" => Map.get(event, "container_id"),
                    "pod_name" => Map.get(event, "pod_name"),
                    "namespace" => Map.get(event, "namespace")
                  }
                }
                | findings
              ]

            String.contains?(cmd_lower, "docker.sock") or
                String.contains?(cmd_lower, "containerd.sock") ->
              [
                %{
                  rule: "container_escape_attempt",
                  severity: "critical",
                  description: "Container runtime socket access detected",
                  mitre_technique: "T1611",
                  metadata: %{
                    "command_line" => cmd,
                    "container_id" => Map.get(event, "container_id"),
                    "pod_name" => Map.get(event, "pod_name"),
                    "namespace" => Map.get(event, "namespace")
                  }
                }
                | findings
              ]

            true ->
              findings
          end
      end

    # Check for escape-related syscalls
    findings =
      case Map.get(event, "syscall") do
        nil ->
          findings

        syscall ->
          if String.downcase(syscall) in Enum.map(@escape_syscalls, &String.downcase/1) do
            [
              %{
                rule: "container_escape_attempt",
                severity: "high",
                description: "Suspicious syscall in container: #{syscall}",
                mitre_technique: "T1611",
                metadata: %{
                  "syscall" => syscall,
                  "container_id" => Map.get(event, "container_id"),
                  "pod_name" => Map.get(event, "pod_name"),
                  "namespace" => Map.get(event, "namespace")
                }
              }
              | findings
            ]
          else
            findings
          end
      end

    # Check for escape-related file access
    findings =
      case Map.get(event, "file_path") do
        nil ->
          findings

        path ->
          matching_escape_path =
            Enum.find(@escape_paths, fn escape_path ->
              String.starts_with?(path, escape_path)
            end)

          if matching_escape_path do
            [
              %{
                rule: "container_escape_attempt",
                severity: "critical",
                description: "Access to sensitive host path from container: #{path}",
                mitre_technique: "T1611",
                metadata: %{
                  "file_path" => path,
                  "matched_pattern" => matching_escape_path,
                  "container_id" => Map.get(event, "container_id"),
                  "pod_name" => Map.get(event, "pod_name"),
                  "namespace" => Map.get(event, "namespace")
                }
              }
              | findings
            ]
          else
            findings
          end
      end

    findings
  end

  # -------------------------------------------------------------------
  # Privileged Container Monitoring
  # -------------------------------------------------------------------

  defp check_privileged_container(event) do
    security_context = Map.get(event, "security_context") || %{}

    cond do
      security_context["privileged"] == true ->
        [
          %{
            rule: "privileged_container",
            severity: "high",
            description: "Container running in privileged mode",
            mitre_technique: "T1611",
            metadata: %{
              "container_id" => Map.get(event, "container_id"),
              "pod_name" => Map.get(event, "pod_name"),
              "namespace" => Map.get(event, "namespace"),
              "security_context" => security_context
            }
          }
        ]

      has_dangerous_capability?(security_context) ->
        caps = get_added_capabilities(security_context)
        dangerous = Enum.filter(caps, &(&1 in @dangerous_capabilities))

        [
          %{
            rule: "dangerous_capabilities",
            severity: "high",
            description: "Container has dangerous capabilities: #{Enum.join(dangerous, ", ")}",
            mitre_technique: "T1611",
            metadata: %{
              "container_id" => Map.get(event, "container_id"),
              "pod_name" => Map.get(event, "pod_name"),
              "namespace" => Map.get(event, "namespace"),
              "dangerous_capabilities" => dangerous
            }
          }
        ]

      true ->
        []
    end
  end

  defp has_dangerous_capability?(security_context) do
    caps = get_added_capabilities(security_context)
    Enum.any?(caps, &(&1 in @dangerous_capabilities))
  end

  defp get_added_capabilities(security_context) do
    security_context
    |> get_in(["capabilities", "add"])
    |> case do
      nil -> []
      caps when is_list(caps) -> Enum.map(caps, &String.upcase(to_string(&1)))
      _ -> []
    end
  end

  # -------------------------------------------------------------------
  # Host Path Mount Detection
  # -------------------------------------------------------------------

  defp check_host_path_mounts(event) do
    volumes = Map.get(event, "volumes") || []

    volumes
    |> Enum.flat_map(fn vol ->
      host_path = get_in(vol, ["hostPath", "path"]) || vol["host_path"]

      if host_path do
        matching =
          Enum.find(@sensitive_host_paths, fn sensitive ->
            String.starts_with?(host_path, sensitive)
          end)

        if matching do
          [
            %{
              rule: "host_path_mount",
              severity: "high",
              description: "Sensitive host path mounted: #{host_path}",
              mitre_technique: "T1611",
              metadata: %{
                "volume_name" => vol["name"] || "unknown",
                "host_path" => host_path,
                "matched_pattern" => matching,
                "pod_name" => Map.get(event, "pod_name"),
                "namespace" => Map.get(event, "namespace")
              }
            }
          ]
        else
          []
        end
      else
        []
      end
    end)
  end

  # -------------------------------------------------------------------
  # Sensitive Volume Mount Detection
  # -------------------------------------------------------------------

  defp check_sensitive_volume_mounts(event) do
    volumes = Map.get(event, "volumes") || []

    volumes
    |> Enum.flat_map(fn vol ->
      findings = []

      # Check secret volumes
      findings =
        case Map.get(vol, "secret") do
          nil ->
            findings

          secret ->
            secret_name = secret["secretName"] || ""

            if matches_sensitive_pattern?(secret_name) do
              [
                %{
                  rule: "sensitive_volume_mount",
                  severity: "medium",
                  description: "Sensitive secret mounted: #{secret_name}",
                  mitre_technique: "T1552",
                  metadata: %{
                    "volume_name" => vol["name"] || "unknown",
                    "secret_name" => secret_name,
                    "pod_name" => Map.get(event, "pod_name"),
                    "namespace" => Map.get(event, "namespace")
                  }
                }
                | findings
              ]
            else
              findings
            end
        end

      # Check configmap volumes
      findings =
        case Map.get(vol, "configMap") do
          nil ->
            findings

          cm ->
            cm_name = cm["name"] || ""

            if matches_sensitive_pattern?(cm_name) do
              [
                %{
                  rule: "sensitive_volume_mount",
                  severity: "medium",
                  description: "ConfigMap with sensitive name mounted: #{cm_name}",
                  mitre_technique: "T1552",
                  metadata: %{
                    "volume_name" => vol["name"] || "unknown",
                    "configmap_name" => cm_name,
                    "pod_name" => Map.get(event, "pod_name"),
                    "namespace" => Map.get(event, "namespace")
                  }
                }
                | findings
              ]
            else
              findings
            end
        end

      findings
    end)
  end

  defp matches_sensitive_pattern?(name) when is_binary(name) do
    Enum.any?(sensitive_secret_patterns(), fn pattern ->
      Regex.match?(pattern, name)
    end)
  end

  defp matches_sensitive_pattern?(_), do: false

  # -------------------------------------------------------------------
  # Network Policy Violation Detection
  # -------------------------------------------------------------------

  defp check_network_policy_violations(event) do
    network = Map.get(event, "network") || %{}

    cond do
      # Detect traffic to Kubernetes API server from unexpected pods
      api_server_access?(network) ->
        [
          %{
            rule: "network_policy_violation",
            severity: "medium",
            description: "Unexpected access to Kubernetes API server",
            mitre_technique: "T1046",
            metadata: %{
              "destination_ip" => network["destination_ip"],
              "destination_port" => network["destination_port"],
              "pod_name" => Map.get(event, "pod_name"),
              "namespace" => Map.get(event, "namespace"),
              "protocol" => network["protocol"]
            }
          }
        ]

      # Detect DNS exfiltration patterns (unusually long DNS queries)
      dns_exfiltration?(network) ->
        [
          %{
            rule: "network_policy_violation",
            severity: "high",
            description: "Possible DNS exfiltration detected: unusually long DNS query",
            mitre_technique: "T1048",
            metadata: %{
              "query" => network["dns_query"],
              "query_length" => String.length(network["dns_query"] || ""),
              "pod_name" => Map.get(event, "pod_name"),
              "namespace" => Map.get(event, "namespace")
            }
          }
        ]

      # Detect connections to external IPs on unusual ports
      suspicious_egress?(network) ->
        [
          %{
            rule: "network_policy_violation",
            severity: "medium",
            description:
              "Suspicious egress traffic to #{network["destination_ip"]}:#{network["destination_port"]}",
            mitre_technique: "T1046",
            metadata: %{
              "destination_ip" => network["destination_ip"],
              "destination_port" => network["destination_port"],
              "pod_name" => Map.get(event, "pod_name"),
              "namespace" => Map.get(event, "namespace"),
              "protocol" => network["protocol"]
            }
          }
        ]

      true ->
        []
    end
  end

  defp api_server_access?(network) do
    port = network["destination_port"]
    ip = network["destination_ip"] || ""

    # K8s API server typically runs on port 6443 or 443
    port in [6443, 443, "6443", "443"] and
      (String.starts_with?(ip, "10.") or
         String.starts_with?(ip, "172.") or
         ip == "kubernetes.default.svc")
  end

  defp dns_exfiltration?(network) do
    query = network["dns_query"] || ""
    # DNS exfiltration typically uses very long subdomain names
    String.length(query) > 100
  end

  defp suspicious_egress?(network) do
    port = to_port_int(network["destination_port"])
    ip = network["destination_ip"] || ""

    # Skip internal cluster IPs
    is_external = not is_cluster_ip?(ip) and ip != "" and ip != "127.0.0.1"

    # Common suspicious ports
    suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345, 54321]

    is_external and port != nil and port in suspicious_ports
  end

  defp is_cluster_ip?(ip) do
    String.starts_with?(ip, "10.") or
      String.starts_with?(ip, "172.16.") or
      String.starts_with?(ip, "172.17.") or
      String.starts_with?(ip, "172.18.") or
      String.starts_with?(ip, "172.19.") or
      String.starts_with?(ip, "172.2") or
      String.starts_with?(ip, "172.3") or
      String.starts_with?(ip, "192.168.")
  end

  defp to_port_int(port) when is_integer(port), do: port

  defp to_port_int(port) when is_binary(port) do
    case Integer.parse(port) do
      {n, _} -> n
      :error -> nil
    end
  end

  defp to_port_int(_), do: nil

  # -------------------------------------------------------------------
  # Pod Spec Static Checks
  # -------------------------------------------------------------------

  defp check_privileged_pod_spec(pod_spec) do
    containers = get_all_pod_containers(pod_spec)

    containers
    |> Enum.flat_map(fn container ->
      if get_in(container, ["securityContext", "privileged"]) == true do
        [
          %{
            rule: "privileged_container",
            severity: "high",
            description: "Container '#{container["name"] || "unnamed"}' runs in privileged mode",
            mitre_technique: "T1611",
            metadata: %{"container_name" => container["name"] || "unnamed"}
          }
        ]
      else
        []
      end
    end)
  end

  defp check_host_namespace_pod_spec(pod_spec) do
    findings = []

    findings =
      if pod_spec["hostNetwork"] == true do
        [
          %{
            rule: "host_namespace_access",
            severity: "high",
            description: "Pod uses hostNetwork",
            mitre_technique: "T1611",
            metadata: %{"namespace_type" => "hostNetwork"}
          }
          | findings
        ]
      else
        findings
      end

    findings =
      if pod_spec["hostPID"] == true do
        [
          %{
            rule: "host_namespace_access",
            severity: "high",
            description: "Pod uses hostPID",
            mitre_technique: "T1611",
            metadata: %{"namespace_type" => "hostPID"}
          }
          | findings
        ]
      else
        findings
      end

    findings =
      if pod_spec["hostIPC"] == true do
        [
          %{
            rule: "host_namespace_access",
            severity: "high",
            description: "Pod uses hostIPC",
            mitre_technique: "T1611",
            metadata: %{"namespace_type" => "hostIPC"}
          }
          | findings
        ]
      else
        findings
      end

    findings
  end

  defp check_host_path_volumes(pod_spec) do
    volumes = pod_spec["volumes"] || []

    volumes
    |> Enum.flat_map(fn vol ->
      case Map.get(vol, "hostPath") do
        nil ->
          []

        host_path ->
          path = host_path["path"] || ""

          matching =
            Enum.find(@sensitive_host_paths, fn sensitive ->
              String.starts_with?(path, sensitive)
            end)

          if matching do
            [
              %{
                rule: "host_path_mount",
                severity: "high",
                description: "Sensitive host path in volume '#{vol["name"]}': #{path}",
                mitre_technique: "T1611",
                metadata: %{
                  "volume_name" => vol["name"] || "unknown",
                  "host_path" => path,
                  "matched_pattern" => matching
                }
              }
            ]
          else
            []
          end
      end
    end)
  end

  defp check_sensitive_volumes(pod_spec) do
    volumes = pod_spec["volumes"] || []

    volumes
    |> Enum.flat_map(fn vol ->
      findings = []

      findings =
        case Map.get(vol, "secret") do
          nil ->
            findings

          secret ->
            name = secret["secretName"] || ""

            if matches_sensitive_pattern?(name) do
              [
                %{
                  rule: "sensitive_volume_mount",
                  severity: "medium",
                  description: "Sensitive secret '#{name}' mounted in volume '#{vol["name"]}'",
                  mitre_technique: "T1552",
                  metadata: %{"volume_name" => vol["name"], "secret_name" => name}
                }
                | findings
              ]
            else
              findings
            end
        end

      findings =
        case Map.get(vol, "configMap") do
          nil ->
            findings

          cm ->
            name = cm["name"] || ""

            if matches_sensitive_pattern?(name) do
              [
                %{
                  rule: "sensitive_volume_mount",
                  severity: "medium",
                  description: "ConfigMap '#{name}' with sensitive name mounted in volume '#{vol["name"]}'",
                  mitre_technique: "T1552",
                  metadata: %{"volume_name" => vol["name"], "configmap_name" => name}
                }
                | findings
              ]
            else
              findings
            end
        end

      findings
    end)
  end

  defp check_dangerous_capabilities_pod_spec(pod_spec) do
    containers = get_all_pod_containers(pod_spec)

    containers
    |> Enum.flat_map(fn container ->
      caps =
        container
        |> get_in(["securityContext", "capabilities", "add"])
        |> case do
          nil -> []
          list when is_list(list) -> Enum.map(list, &String.upcase(to_string(&1)))
          _ -> []
        end

      dangerous = Enum.filter(caps, &(&1 in @dangerous_capabilities))

      if dangerous != [] do
        [
          %{
            rule: "dangerous_capabilities",
            severity: "high",
            description:
              "Container '#{container["name"] || "unnamed"}' has dangerous capabilities: #{Enum.join(dangerous, ", ")}",
            mitre_technique: "T1611",
            metadata: %{
              "container_name" => container["name"] || "unnamed",
              "dangerous_capabilities" => dangerous
            }
          }
        ]
      else
        []
      end
    end)
  end

  defp get_all_pod_containers(pod_spec) do
    containers = pod_spec["containers"] || []
    init_containers = pod_spec["initContainers"] || []
    containers ++ init_containers
  end
end
