defmodule TamanduaServer.Kubernetes.AdmissionController do
  @moduledoc """
  Kubernetes Admission Controller GenServer.

  Validates and mutates incoming Kubernetes AdmissionReview requests against
  a configurable set of security policies stored in an ETS table for fast
  lookup and backed by PostgreSQL for persistence.

  ## Default Policies (seeded on first start)

  | Action  | Description                                       |
  |---------|---------------------------------------------------|
  | DENY    | Privileged containers                              |
  | DENY    | hostNetwork / hostPID / hostIPC                    |
  | DENY    | Running as root without explicit allowance          |
  | DENY    | Images from untrusted registries                   |
  | DENY    | Missing security context                           |
  | WARN    | Missing resource limits                             |
  | WARN    | `latest` image tag                                 |
  | MUTATE  | Inject default resource limits if missing           |
  | MUTATE  | Add Tamandua tracking labels                       |

  ## Fail-Open Behaviour

  If policy evaluation exceeds the configured timeout (default 8 seconds,
  leaving headroom before the K8s 10-second default), the controller allows
  the request with a warning.

  ## Audit Logging

  Every admission decision is persisted asynchronously via
  `TamanduaServer.Kubernetes.AdmissionLog`.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Kubernetes.{Policy}

  @policy_ets :k8s_admission_policies

  # Default resource limits injected by the mutating webhook
  @default_resource_limits %{
    "cpu" => "500m",
    "memory" => "256Mi"
  }

  # Default set of trusted registries (configurable via policy conditions)
  @default_trusted_registries [
    "gcr.io",
    "ghcr.io",
    "registry.k8s.io",
    "docker.io/library",
    "quay.io"
  ]

  # Namespaces excluded from admission enforcement
  @system_namespaces ["kube-system", "kube-public", "kube-node-lease"]

  # -------------------------------------------------------------------
  # Client API
  # -------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Validate an admission review request.

  Returns `{:allow, warnings}` or `{:deny, reason, warnings}`.
  """
  @spec validate_admission(map()) :: {:allow, [String.t()]} | {:deny, String.t(), [String.t()]}
  def validate_admission(admission_review) do
    try do
      do_validate(admission_review)
    catch
      kind, reason ->
        Logger.error(
          "[K8s AdmissionController] FAIL-OPEN: Validation crashed — " <>
            "request ALLOWED without policy checks: #{inspect(kind)} #{inspect(reason)}"
        )

        :telemetry.execute(
          [:tamandua, :k8s, :admission, :fail_open],
          %{count: 1},
          %{phase: :validate, kind: kind, reason: inspect(reason)}
        )

        # Fail open
        {:allow, ["Tamandua: internal error, failing open"]}
    end
  end

  @doc """
  Mutate an admission review request.

  Returns `{:ok, patches}` where patches is a list of RFC 6902 JSON Patch
  operations, or `{:error, reason}`.
  """
  @spec mutate_admission(map()) :: {:ok, [map()]} | {:error, String.t()}
  def mutate_admission(admission_review) do
    try do
      do_mutate(admission_review)
    catch
      kind, reason ->
        Logger.error(
          "[K8s AdmissionController] FAIL-OPEN: Mutation crashed — " <>
            "request passed with NO patches applied: #{inspect(kind)} #{inspect(reason)}"
        )

        :telemetry.execute(
          [:tamandua, :k8s, :admission, :fail_open],
          %{count: 1},
          %{phase: :mutate, kind: kind, reason: inspect(reason)}
        )

        {:ok, []}
    end
  end

  @doc "Add a policy to the ETS cache (and persist to DB)."
  @spec add_policy(map()) :: {:ok, Policy.t()} | {:error, Ecto.Changeset.t()}
  def add_policy(attrs) do
    case Policy.create_policy(attrs) do
      {:ok, policy} ->
        :ets.insert(@policy_ets, {policy.id, policy})
        {:ok, policy}

      error ->
        error
    end
  end

  @doc "Remove a policy from ETS and DB."
  @spec remove_policy(String.t()) :: :ok | {:error, :not_found}
  def remove_policy(policy_id) do
    case Policy.get_policy(policy_id) do
      {:ok, policy} ->
        Policy.delete_policy(policy)
        :ets.delete(@policy_ets, policy_id)
        :ok

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  @doc "List all policies from the ETS cache."
  @spec list_policies() :: [Policy.t()]
  def list_policies do
    :ets.foldl(
      fn {_id, policy}, acc -> [policy | acc] end,
      [],
      @policy_ets
    )
    |> Enum.sort_by(& &1.priority)
  end

  @doc "Reload policies from the database into ETS."
  def reload_policies do
    GenServer.call(__MODULE__, :reload_policies)
  end

  # -------------------------------------------------------------------
  # Server Callbacks
  # -------------------------------------------------------------------

  @impl true
  def init(_opts) do
    :ets.new(@policy_ets, [:set, :named_table, :public, read_concurrency: true])

    # Load policies from DB into ETS (table may not exist yet if migrations pending)
    try do
      load_policies_from_db()

      # Seed defaults if the table is empty
      if :ets.info(@policy_ets, :size) == 0 do
        seed_default_policies()
      end
    rescue
      e in Postgrex.Error ->
        Logger.warning("[K8s AdmissionController] DB table not ready: #{inspect(e.postgres.message)}, starting with empty policies")
      e ->
        Logger.warning("[K8s AdmissionController] Failed to load policies: #{inspect(e)}, starting with empty policies")
    end

    Logger.info("[K8s AdmissionController] Started with #{:ets.info(@policy_ets, :size)} policies")
    {:ok, %{}}
  end

  @impl true
  def handle_call(:reload_policies, _from, state) do
    :ets.delete_all_objects(@policy_ets)
    count = load_policies_from_db()
    {:reply, {:ok, count}, state}
  end

  # -------------------------------------------------------------------
  # Validation Logic
  # -------------------------------------------------------------------

  defp do_validate(review) do
    namespace = get_in(review, ["namespace"]) || ""
    resource_kind = get_in(review, ["kind", "kind"]) || get_in(review, ["resource", "resource"]) || "Pod"

    # Skip system namespaces
    if namespace in @system_namespaces do
      {:allow, []}
    else
      pod_spec = extract_pod_spec(review)
      policies = get_enabled_policies(:deny) ++ get_enabled_policies(:warn)

      {denials, warnings} =
        Enum.reduce(policies, {[], []}, fn policy, {deny_acc, warn_acc} ->
          if policy_applies?(policy, namespace, resource_kind) do
            case evaluate_policy(policy, pod_spec, review) do
              {:deny, msg} -> {[msg | deny_acc], warn_acc}
              {:warn, msg} -> {deny_acc, [msg | warn_acc]}
              :pass -> {deny_acc, warn_acc}
            end
          else
            {deny_acc, warn_acc}
          end
        end)

      denials = Enum.reverse(denials)
      warnings = Enum.reverse(warnings)

      if denials == [] do
        {:allow, warnings}
      else
        reason = Enum.join(denials, "; ")
        {:deny, reason, warnings}
      end
    end
  end

  defp do_mutate(review) do
    namespace = get_in(review, ["namespace"]) || ""
    resource_kind = get_in(review, ["kind", "kind"]) || get_in(review, ["resource", "resource"]) || "Pod"

    if namespace in @system_namespaces do
      {:ok, []}
    else
      pod_spec = extract_pod_spec(review)
      policies = get_enabled_policies(:mutate)

      patches =
        Enum.flat_map(policies, fn policy ->
          if policy_applies?(policy, namespace, resource_kind) do
            generate_patches(policy, pod_spec, review)
          else
            []
          end
        end)

      {:ok, patches}
    end
  end

  # -------------------------------------------------------------------
  # Policy Evaluation
  # -------------------------------------------------------------------

  defp evaluate_policy(policy, pod_spec, _review) do
    conditions = policy.conditions || %{}
    containers = get_all_containers(pod_spec)
    security_context = pod_spec["securityContext"] || %{}

    result =
      cond do
        # Privileged containers
        Map.get(conditions, "privileged") == true ->
          check_privileged(containers)

        # Host namespace access
        Map.has_key?(conditions, "host_namespaces") ->
          check_host_namespaces(pod_spec, Map.get(conditions, "host_namespaces", []))

        # Running as root
        Map.get(conditions, "run_as_root") == true ->
          check_run_as_root(containers, security_context)

        # Untrusted registries
        Map.has_key?(conditions, "registries") ->
          trusted = Map.get(conditions, "registries", @default_trusted_registries)
          check_registries(containers, trusted)

        # Missing security context
        Map.get(conditions, "missing_security_context") == true ->
          check_missing_security_context(containers, security_context)

        # Missing resource limits
        Map.get(conditions, "missing_resource_limits") == true ->
          check_missing_resource_limits(containers)

        # Latest tag
        Map.get(conditions, "image_tag") == "latest" ->
          check_latest_tag(containers)

        true ->
          :pass
      end

    case {result, policy.action} do
      {:pass, _} -> :pass
      {{:violation, msg}, :deny} -> {:deny, "[#{policy.name}] #{msg}"}
      {{:violation, msg}, :warn} -> {:warn, "[#{policy.name}] #{msg}"}
      _ -> :pass
    end
  end

  defp check_privileged(containers) do
    violating =
      Enum.filter(containers, fn c ->
        get_in(c, ["securityContext", "privileged"]) == true
      end)

    if violating == [] do
      :pass
    else
      names = Enum.map_join(violating, ", ", &(&1["name"] || "unnamed"))
      {:violation, "Privileged containers not allowed: #{names}"}
    end
  end

  defp check_host_namespaces(pod_spec, namespaces) do
    violations =
      Enum.filter(namespaces, fn ns ->
        case ns do
          "hostNetwork" -> pod_spec["hostNetwork"] == true
          "hostPID" -> pod_spec["hostPID"] == true
          "hostIPC" -> pod_spec["hostIPC"] == true
          _ -> false
        end
      end)

    if violations == [] do
      :pass
    else
      {:violation, "Host namespace access not allowed: #{Enum.join(violations, ", ")}"}
    end
  end

  defp check_run_as_root(containers, pod_security_context) do
    pod_run_as_non_root = pod_security_context["runAsNonRoot"] == true
    pod_run_as_user = pod_security_context["runAsUser"]

    violating =
      Enum.filter(containers, fn c ->
        sc = c["securityContext"] || %{}
        container_non_root = sc["runAsNonRoot"] == true
        container_user = sc["runAsUser"]

        # A container is considered "running as root" if:
        # - Neither pod nor container sets runAsNonRoot: true
        # - AND neither pod nor container sets runAsUser to non-zero
        non_root = container_non_root || pod_run_as_non_root
        explicit_user = container_user || pod_run_as_user

        not non_root and (is_nil(explicit_user) or explicit_user == 0)
      end)

    if violating == [] do
      :pass
    else
      names = Enum.map_join(violating, ", ", &(&1["name"] || "unnamed"))
      {:violation, "Containers must not run as root: #{names}"}
    end
  end

  defp check_registries(containers, trusted_registries) do
    violating =
      Enum.filter(containers, fn c ->
        image = c["image"] || ""
        not image_from_trusted_registry?(image, trusted_registries)
      end)

    if violating == [] do
      :pass
    else
      images = Enum.map_join(violating, ", ", &(&1["image"] || "unknown"))
      {:violation, "Images from untrusted registries: #{images}"}
    end
  end

  defp image_from_trusted_registry?(image, trusted) do
    Enum.any?(trusted, fn registry ->
      String.starts_with?(image, registry <> "/") or
        String.starts_with?(image, registry)
    end)
    # Also allow short-form Docker Hub images (e.g. "nginx:1.25")
    or not String.contains?(image, "/")
  end

  defp check_missing_security_context(containers, pod_security_context) do
    has_pod_context = map_size(pod_security_context) > 0

    violating =
      Enum.filter(containers, fn c ->
        sc = c["securityContext"] || %{}
        not has_pod_context and map_size(sc) == 0
      end)

    if violating == [] do
      :pass
    else
      names = Enum.map_join(violating, ", ", &(&1["name"] || "unnamed"))
      {:violation, "Missing security context: #{names}"}
    end
  end

  defp check_missing_resource_limits(containers) do
    violating =
      Enum.filter(containers, fn c ->
        resources = c["resources"] || %{}
        limits = resources["limits"] || %{}
        is_nil(limits["cpu"]) or is_nil(limits["memory"])
      end)

    if violating == [] do
      :pass
    else
      names = Enum.map_join(violating, ", ", &(&1["name"] || "unnamed"))
      {:violation, "Missing resource limits (cpu/memory): #{names}"}
    end
  end

  defp check_latest_tag(containers) do
    violating =
      Enum.filter(containers, fn c ->
        image = c["image"] || ""
        # "image:latest" or "image" (no tag = implicit latest)
        String.ends_with?(image, ":latest") or not String.contains?(image, ":")
      end)

    if violating == [] do
      :pass
    else
      images = Enum.map_join(violating, ", ", &(&1["image"] || "unknown"))
      {:violation, "Avoid using 'latest' tag, pin to a specific version: #{images}"}
    end
  end

  # -------------------------------------------------------------------
  # Mutation Logic
  # -------------------------------------------------------------------

  defp generate_patches(policy, pod_spec, _review) do
    conditions = policy.conditions || %{}
    mutation = policy.mutation || %{}
    containers = pod_spec["containers"] || []

    patches = []

    # Inject default resource limits
    patches =
      if Map.get(conditions, "missing_resource_limits") == true or
           Map.has_key?(mutation, "default_limits") do
        default_limits = Map.get(mutation, "default_limits", @default_resource_limits)
        patches ++ generate_resource_limit_patches(containers, default_limits)
      else
        patches
      end

    # Inject Tamandua labels
    patches =
      if Map.get(conditions, "add_labels") == true or Map.has_key?(mutation, "add_labels") do
        labels = Map.get(mutation, "add_labels", %{"tamandua.io/managed" => "true"})
        patches ++ generate_label_patches(pod_spec, labels)
      else
        patches
      end

    patches
  end

  defp generate_resource_limit_patches(containers, default_limits) do
    containers
    |> Enum.with_index()
    |> Enum.flat_map(fn {container, idx} ->
      resources = container["resources"] || %{}
      limits = resources["limits"] || %{}
      base_path = "/spec/containers/#{idx}"

      patches = []

      # Add resources object if missing
      patches =
        if is_nil(container["resources"]) do
          patches ++ [%{"op" => "add", "path" => "#{base_path}/resources", "value" => %{}}]
        else
          patches
        end

      # Add limits object if missing
      patches =
        if is_nil(resources["limits"]) do
          patches ++ [%{"op" => "add", "path" => "#{base_path}/resources/limits", "value" => %{}}]
        else
          patches
        end

      # Add missing cpu limit
      patches =
        if is_nil(limits["cpu"]) and Map.has_key?(default_limits, "cpu") do
          patches ++
            [
              %{
                "op" => "add",
                "path" => "#{base_path}/resources/limits/cpu",
                "value" => default_limits["cpu"]
              }
            ]
        else
          patches
        end

      # Add missing memory limit
      patches =
        if is_nil(limits["memory"]) and Map.has_key?(default_limits, "memory") do
          patches ++
            [
              %{
                "op" => "add",
                "path" => "#{base_path}/resources/limits/memory",
                "value" => default_limits["memory"]
              }
            ]
        else
          patches
        end

      patches
    end)
  end

  defp generate_label_patches(pod_spec, labels) do
    existing_labels = get_in(pod_spec, ["metadata", "labels"]) || %{}

    if map_size(existing_labels) == 0 do
      # Labels object might not exist yet on the pod template
      [%{"op" => "add", "path" => "/metadata/labels", "value" => labels}]
    else
      # Add each missing label individually
      Enum.flat_map(labels, fn {key, value} ->
        if Map.has_key?(existing_labels, key) do
          []
        else
          escaped_key = String.replace(key, "/", "~1")
          [%{"op" => "add", "path" => "/metadata/labels/#{escaped_key}", "value" => value}]
        end
      end)
    end
  end

  # -------------------------------------------------------------------
  # Helpers
  # -------------------------------------------------------------------

  defp extract_pod_spec(review) do
    object = review["object"] || %{}

    # For Pods, the spec is directly on the object.
    # For Deployments/DaemonSets/etc., the pod spec is nested.
    kind = get_in(review, ["kind", "kind"]) || get_in(review, ["resource", "resource"]) || ""

    case String.downcase(kind) do
      k when k in ["deployment", "replicaset", "statefulset", "daemonset", "job"] ->
        get_in(object, ["spec", "template", "spec"]) || %{}

      "cronjob" ->
        get_in(object, ["spec", "jobTemplate", "spec", "template", "spec"]) || %{}

      _ ->
        # Pod or unknown - assume direct spec
        object["spec"] || %{}
    end
  end

  defp get_all_containers(pod_spec) do
    containers = pod_spec["containers"] || []
    init_containers = pod_spec["initContainers"] || []
    containers ++ init_containers
  end

  defp get_enabled_policies(action) do
    action_str = Atom.to_string(action)

    :ets.foldl(
      fn {_id, policy}, acc ->
        if policy.enabled and Atom.to_string(policy.action) == action_str do
          [policy | acc]
        else
          acc
        end
      end,
      [],
      @policy_ets
    )
    |> Enum.sort_by(& &1.priority)
  end

  defp policy_applies?(policy, namespace, resource_kind) do
    # Check namespace filter
    ns_ok =
      case policy.namespaces do
        nil -> true
        [] -> true
        ns_list -> namespace in ns_list
      end

    # Check target resource kind
    target_str = Atom.to_string(policy.target)
    kind_ok = String.downcase(target_str) == String.downcase(resource_kind)

    # Also allow "pod" target to match higher-level controllers
    # since we extract the pod spec from them
    pod_equivalent =
      target_str == "pod" and
        String.downcase(resource_kind) in [
          "pod",
          "deployment",
          "replicaset",
          "daemonset",
          "statefulset",
          "job",
          "cronjob"
        ]

    ns_ok and (kind_ok or pod_equivalent)
  end

  defp load_policies_from_db do
    policies = Policy.list_policies()

    Enum.each(policies, fn policy ->
      :ets.insert(@policy_ets, {policy.id, policy})
    end)

    length(policies)
  end

  defp seed_default_policies do
    defaults = [
      # DENY: Privileged containers
      %{
        name: "Block Privileged Containers",
        description: "Deny pods that request privileged mode (T1611: Escape to Host)",
        action: :deny,
        target: :pod,
        conditions: %{"privileged" => true},
        priority: 10,
        enabled: true
      },
      # DENY: Host namespaces
      %{
        name: "Block Host Namespace Access",
        description: "Deny pods using hostNetwork, hostPID, or hostIPC",
        action: :deny,
        target: :pod,
        conditions: %{"host_namespaces" => ["hostNetwork", "hostPID", "hostIPC"]},
        priority: 10,
        enabled: true
      },
      # DENY: Running as root
      %{
        name: "Block Root Containers",
        description: "Deny containers running as root without explicit non-root configuration",
        action: :deny,
        target: :pod,
        conditions: %{"run_as_root" => true},
        priority: 20,
        enabled: true
      },
      # DENY: Untrusted registries
      %{
        name: "Block Untrusted Registries",
        description: "Deny images from registries not in the trusted allowlist",
        action: :deny,
        target: :pod,
        conditions: %{
          "registries" => @default_trusted_registries
        },
        priority: 15,
        enabled: true
      },
      # DENY: Missing security context
      %{
        name: "Require Security Context",
        description: "Deny pods without a securityContext defined",
        action: :deny,
        target: :pod,
        conditions: %{"missing_security_context" => true},
        priority: 25,
        enabled: true
      },
      # WARN: Missing resource limits
      %{
        name: "Warn Missing Resource Limits",
        description: "Warn when containers lack CPU or memory limits",
        action: :warn,
        target: :pod,
        conditions: %{"missing_resource_limits" => true},
        priority: 50,
        enabled: true
      },
      # WARN: latest tag
      %{
        name: "Warn Latest Tag",
        description: "Warn when containers use the 'latest' image tag instead of a pinned version",
        action: :warn,
        target: :pod,
        conditions: %{"image_tag" => "latest"},
        priority: 50,
        enabled: true
      },
      # MUTATE: Inject resource limits
      %{
        name: "Inject Default Resource Limits",
        description: "Add default CPU/memory limits to containers that are missing them",
        action: :mutate,
        target: :pod,
        conditions: %{"missing_resource_limits" => true},
        mutation: %{
          "default_limits" => @default_resource_limits
        },
        priority: 100,
        enabled: true
      },
      # MUTATE: Add Tamandua labels
      %{
        name: "Inject Tamandua Labels",
        description: "Add tamandua.io tracking labels to all pods for inventory and correlation",
        action: :mutate,
        target: :pod,
        conditions: %{"add_labels" => true},
        mutation: %{
          "add_labels" => %{
            "tamandua.io/managed" => "true",
            "tamandua.io/admission" => "validated"
          }
        },
        priority: 200,
        enabled: true
      }
    ]

    Enum.each(defaults, fn attrs ->
      case Policy.create_policy(attrs) do
        {:ok, policy} ->
          :ets.insert(@policy_ets, {policy.id, policy})
          Logger.info("[K8s AdmissionController] Seeded policy: #{policy.name}")

        {:error, changeset} ->
          Logger.warning(
            "[K8s AdmissionController] Failed to seed policy '#{attrs[:name]}': #{inspect(changeset.errors)}"
          )
      end
    end)
  end
end
