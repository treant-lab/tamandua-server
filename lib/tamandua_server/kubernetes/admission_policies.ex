defmodule TamanduaServer.Kubernetes.AdmissionPolicies do
  @moduledoc """
  Context module for managing Kubernetes admission control policies.

  Provides CRUD operations, namespace-scoped policy lookup, and admission
  request evaluation against active policies.

  ## Multi-Tenancy

  All listing and lookup functions accept an optional `organization_id` to
  scope results to a single tenant. Pass `nil` to query across all tenants.

  ## Evaluation Flow

      AdmissionReview request
        |
        v
      Parse request (kind, namespace, operation, object)
        |
        v
      Load active policies matching namespace + resource type
        |
        v
      Evaluate each policy in priority order
        |
        v
      Return {:allow, warnings} | {:deny, reason, warnings}
  """

  import Ecto.Query, warn: false
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Kubernetes.AdmissionPolicy

  # -------------------------------------------------------------------
  # CRUD Operations
  # -------------------------------------------------------------------

  @doc """
  List all admission policies, ordered by priority.

  ## Options
  - `:organization_id` - Scope to a specific organization
  - `:enabled` - Filter by enabled status (boolean)
  - `:action` - Filter by action type
  - `:limit` - Maximum number of results
  - `:offset` - Pagination offset
  """
  @spec list(keyword()) :: [AdmissionPolicy.t()]
  def list(opts \\ []) do
    AdmissionPolicy
    |> order_by([p], asc: p.priority, asc: p.name)
    |> maybe_filter_org(opts[:organization_id])
    |> maybe_filter_enabled(opts[:enabled])
    |> maybe_filter_action(opts[:action])
    |> maybe_limit(opts[:limit])
    |> maybe_offset(opts[:offset])
    |> Repo.all()
  end

  @doc """
  Get a single admission policy by ID.

  Returns `{:ok, policy}` or `{:error, :not_found}`.
  """
  @spec get(String.t()) :: {:ok, AdmissionPolicy.t()} | {:error, :not_found}
  def get(id) do
    case Repo.get(AdmissionPolicy, id) do
      nil -> {:error, :not_found}
      policy -> {:ok, policy}
    end
  end

  @doc """
  Get a single admission policy by ID, raises if not found.
  """
  @spec get!(String.t()) :: AdmissionPolicy.t()
  def get!(id), do: Repo.get!(AdmissionPolicy, id)

  @doc """
  Create a new admission policy.

  Returns `{:ok, policy}` or `{:error, changeset}`.
  """
  @spec create(map()) :: {:ok, AdmissionPolicy.t()} | {:error, Ecto.Changeset.t()}
  def create(attrs) do
    %AdmissionPolicy{}
    |> AdmissionPolicy.changeset(normalize_attrs(attrs))
    |> Repo.insert()
  end

  @doc """
  Update an existing admission policy.

  Returns `{:ok, updated_policy}` or `{:error, changeset}`.
  """
  @spec update(AdmissionPolicy.t(), map()) ::
          {:ok, AdmissionPolicy.t()} | {:error, Ecto.Changeset.t()}
  def update(%AdmissionPolicy{} = policy, attrs) do
    policy
    |> AdmissionPolicy.changeset(normalize_attrs(attrs))
    |> Repo.update()
  end

  @doc """
  Delete an admission policy.

  Returns `{:ok, deleted_policy}` or `{:error, changeset}`.
  """
  @spec delete(AdmissionPolicy.t()) :: {:ok, AdmissionPolicy.t()} | {:error, Ecto.Changeset.t()}
  def delete(%AdmissionPolicy{} = policy) do
    Repo.delete(policy)
  end

  @doc """
  Delete an admission policy by ID.

  Returns `:ok` or `{:error, :not_found}`.
  """
  @spec delete_by_id(String.t()) :: :ok | {:error, :not_found}
  def delete_by_id(id) do
    case get(id) do
      {:ok, policy} ->
        case delete(policy) do
          {:ok, _} -> :ok
          {:error, _} = err -> err
        end

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  # -------------------------------------------------------------------
  # Active Policy Lookup
  # -------------------------------------------------------------------

  @doc """
  Get all enabled policies that apply to a given namespace.

  Policies match a namespace if:
  - Their `namespaces` list is empty (cluster-wide)
  - The namespace is present in their `namespaces` list
  - Their `namespace_selector` matches the namespace labels (when labels are provided)

  ## Parameters
  - `namespace` - Kubernetes namespace name
  - `opts` - Keyword list with optional `:organization_id` and `:namespace_labels`
  """
  @spec list_active_policies(String.t(), keyword()) :: [AdmissionPolicy.t()]
  def list_active_policies(namespace, opts \\ []) do
    org_id = Keyword.get(opts, :organization_id)
    namespace_labels = Keyword.get(opts, :namespace_labels, %{})

    AdmissionPolicy.list_active()
    |> AdmissionPolicy.by_namespace(namespace)
    |> maybe_filter_org(org_id)
    |> Repo.all()
    |> Enum.filter(&namespace_selector_matches?(&1, namespace_labels))
  end

  # -------------------------------------------------------------------
  # Admission Evaluation
  # -------------------------------------------------------------------

  @doc """
  Evaluate a Kubernetes admission request against all active policies.

  The admission request should be the `request` field from an AdmissionReview,
  containing at minimum: `namespace`, `kind`, `operation`, and `object`.

  Returns:
  - `{:allow, warnings}` when no policy denies the request
  - `{:deny, reason, warnings}` when one or more policies deny the request

  Each warning is a string describing which policy triggered and why.
  """
  @spec evaluate_admission(map(), keyword()) ::
          {:allow, [String.t()]} | {:deny, String.t(), [String.t()]}
  def evaluate_admission(admission_request, opts \\ []) do
    namespace = admission_request["namespace"] || ""
    resource_kind = extract_resource_kind(admission_request)
    operation = admission_request["operation"] || "CREATE"
    object = admission_request["object"] || %{}

    # Load applicable policies
    policies = list_active_policies(namespace, opts)

    # Filter to policies that match the resource type and operation
    applicable =
      policies
      |> Enum.filter(&policy_matches_request?(&1, resource_kind, operation))
      |> Enum.sort_by(& &1.priority)

    # Evaluate each policy
    {denials, warnings} =
      Enum.reduce(applicable, {[], []}, fn policy, {deny_acc, warn_acc} ->
        case evaluate_single_policy(policy, object, admission_request) do
          {:deny, message} ->
            {["[#{policy.name}] #{message}" | deny_acc], warn_acc}

          {:audit, message} ->
            {deny_acc, ["[#{policy.name}] #{message}" | warn_acc]}

          {:warn, message} ->
            {deny_acc, ["[#{policy.name}] #{message}" | warn_acc]}

          :allow ->
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

  # -------------------------------------------------------------------
  # Policy Matching Logic
  # -------------------------------------------------------------------

  @doc false
  def policy_matches_request?(policy, resource_kind, operation) do
    rules = policy.rules || []

    # If no rules are defined, fall back to target-based matching
    if rules == [] do
      target_matches?(policy, resource_kind)
    else
      Enum.any?(rules, fn rule ->
        resource_matches?(rule, resource_kind) and operation_matches?(rule, operation)
      end)
    end
  end

  # Match via the legacy `target` field when no structured rules exist
  defp target_matches?(policy, resource_kind) do
    case policy.target do
      nil ->
        true

      target ->
        target_str = if is_atom(target), do: Atom.to_string(target), else: to_string(target)
        kind_lower = String.downcase(resource_kind)

        String.downcase(target_str) == kind_lower or
          (String.downcase(target_str) == "pod" and
             kind_lower in ["pod", "deployment", "replicaset", "daemonset", "statefulset", "job", "cronjob"])
    end
  end

  defp resource_matches?(rule, resource_kind) do
    resources = rule["resources"] || []

    if resources == [] do
      # Empty resources list = match all
      true
    else
      kind_lower = String.downcase(resource_kind)
      Enum.any?(resources, fn r -> String.downcase(r) == kind_lower end)
    end
  end

  defp operation_matches?(rule, operation) do
    operations = rule["operations"] || []

    if operations == [] do
      # Empty operations list = match all
      true
    else
      op_upper = String.upcase(operation)
      Enum.any?(operations, fn o -> String.upcase(o) == op_upper or o == "*" end)
    end
  end

  # -------------------------------------------------------------------
  # Namespace Selector Matching
  # -------------------------------------------------------------------

  defp namespace_selector_matches?(policy, namespace_labels) do
    selector = policy.namespace_selector || %{}

    # Empty selector matches everything
    if map_size(selector) == 0 do
      true
    else
      match_labels_ok?(selector, namespace_labels) and
        match_expressions_ok?(selector, namespace_labels)
    end
  end

  defp match_labels_ok?(selector, namespace_labels) do
    case Map.get(selector, "matchLabels") do
      nil ->
        true

      match_labels when is_map(match_labels) ->
        Enum.all?(match_labels, fn {key, value} ->
          Map.get(namespace_labels, key) == value
        end)

      _ ->
        true
    end
  end

  defp match_expressions_ok?(selector, namespace_labels) do
    case Map.get(selector, "matchExpressions") do
      nil ->
        true

      expressions when is_list(expressions) ->
        Enum.all?(expressions, &evaluate_expression(&1, namespace_labels))

      _ ->
        true
    end
  end

  defp evaluate_expression(expr, labels) when is_map(expr) do
    key = expr["key"] || ""
    operator = expr["operator"] || ""
    values = expr["values"] || []
    label_value = Map.get(labels, key)

    case operator do
      "In" ->
        label_value != nil and label_value in values

      "NotIn" ->
        label_value == nil or label_value not in values

      "Exists" ->
        Map.has_key?(labels, key)

      "DoesNotExist" ->
        not Map.has_key?(labels, key)

      _ ->
        # Unknown operator, fail open
        true
    end
  end

  defp evaluate_expression(_, _labels), do: true

  # -------------------------------------------------------------------
  # Single Policy Evaluation
  # -------------------------------------------------------------------

  defp evaluate_single_policy(policy, object, request) do
    conditions = policy.conditions || %{}
    pod_spec = extract_pod_spec(request)

    # If conditions are empty, there is nothing to check, so pass
    if map_size(conditions) == 0 do
      :allow
    else
      violations = collect_condition_violations(conditions, pod_spec, object)

      case {violations, policy.action} do
        {[], _} -> :allow
        {violations, :deny} -> {:deny, Enum.join(violations, "; ")}
        {violations, :audit} -> {:audit, Enum.join(violations, "; ")}
        {violations, :warn} -> {:warn, Enum.join(violations, "; ")}
        _ -> :allow
      end
    end
  end

  defp collect_condition_violations(conditions, pod_spec, _object) do
    containers = get_all_containers(pod_spec)
    security_context = pod_spec["securityContext"] || %{}

    violations = []

    # Privileged container check
    violations =
      if Map.get(conditions, "privileged") == true do
        case check_privileged(containers) do
          {:violation, msg} -> [msg | violations]
          :pass -> violations
        end
      else
        violations
      end

    # Host namespace access
    violations =
      if Map.has_key?(conditions, "host_namespaces") do
        namespaces = Map.get(conditions, "host_namespaces", [])

        case check_host_namespaces(pod_spec, namespaces) do
          {:violation, msg} -> [msg | violations]
          :pass -> violations
        end
      else
        violations
      end

    # Run as root
    violations =
      if Map.get(conditions, "run_as_root") == true do
        case check_run_as_root(containers, security_context) do
          {:violation, msg} -> [msg | violations]
          :pass -> violations
        end
      else
        violations
      end

    # Untrusted registries
    violations =
      if Map.has_key?(conditions, "registries") do
        trusted = Map.get(conditions, "registries", [])

        case check_registries(containers, trusted) do
          {:violation, msg} -> [msg | violations]
          :pass -> violations
        end
      else
        violations
      end

    # Missing security context
    violations =
      if Map.get(conditions, "missing_security_context") == true do
        case check_missing_security_context(containers, security_context) do
          {:violation, msg} -> [msg | violations]
          :pass -> violations
        end
      else
        violations
      end

    # Missing resource limits
    violations =
      if Map.get(conditions, "missing_resource_limits") == true do
        case check_missing_resource_limits(containers) do
          {:violation, msg} -> [msg | violations]
          :pass -> violations
        end
      else
        violations
      end

    # Latest image tag
    violations =
      if Map.get(conditions, "image_tag") == "latest" do
        case check_latest_tag(containers) do
          {:violation, msg} -> [msg | violations]
          :pass -> violations
        end
      else
        violations
      end

    Enum.reverse(violations)
  end

  # -------------------------------------------------------------------
  # Condition Checkers
  # -------------------------------------------------------------------

  defp check_privileged(containers) do
    violating =
      Enum.filter(containers, fn c ->
        get_in(c, ["securityContext", "privileged"]) == true
      end)

    if violating == [] do
      :pass
    else
      names = Enum.map_join(violating, ", ", &(Map.get(&1, "name") || "unnamed"))
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
    pod_non_root = pod_security_context["runAsNonRoot"] == true
    pod_user = pod_security_context["runAsUser"]

    violating =
      Enum.filter(containers, fn c ->
        sc = c["securityContext"] || %{}
        container_non_root = sc["runAsNonRoot"] == true
        container_user = sc["runAsUser"]

        non_root = container_non_root || pod_non_root
        explicit_user = container_user || pod_user

        not non_root and (is_nil(explicit_user) or explicit_user == 0)
      end)

    if violating == [] do
      :pass
    else
      names = Enum.map_join(violating, ", ", &(Map.get(&1, "name") || "unnamed"))
      {:violation, "Containers must not run as root: #{names}"}
    end
  end

  defp check_registries(containers, trusted_registries) do
    violating =
      Enum.filter(containers, fn c ->
        image = c["image"] || ""

        not (Enum.any?(trusted_registries, fn registry ->
               String.starts_with?(image, registry <> "/") or
                 String.starts_with?(image, registry)
             end) or not String.contains?(image, "/"))
      end)

    if violating == [] do
      :pass
    else
      images = Enum.map_join(violating, ", ", &(Map.get(&1, "image") || "unknown"))
      {:violation, "Images from untrusted registries: #{images}"}
    end
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
      names = Enum.map_join(violating, ", ", &(Map.get(&1, "name") || "unnamed"))
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
      names = Enum.map_join(violating, ", ", &(Map.get(&1, "name") || "unnamed"))
      {:violation, "Missing resource limits (cpu/memory): #{names}"}
    end
  end

  defp check_latest_tag(containers) do
    violating =
      Enum.filter(containers, fn c ->
        image = c["image"] || ""
        String.ends_with?(image, ":latest") or not String.contains?(image, ":")
      end)

    if violating == [] do
      :pass
    else
      images = Enum.map_join(violating, ", ", &(Map.get(&1, "image") || "unknown"))
      {:violation, "Avoid using 'latest' tag: #{images}"}
    end
  end

  # -------------------------------------------------------------------
  # Pod Spec Extraction Helpers
  # -------------------------------------------------------------------

  defp extract_resource_kind(request) do
    get_in(request, ["kind", "kind"]) ||
      get_in(request, ["resource", "resource"]) ||
      "Pod"
  end

  defp extract_pod_spec(request) do
    object = request["object"] || %{}
    kind = extract_resource_kind(request)

    case String.downcase(kind) do
      k when k in ["deployment", "replicaset", "statefulset", "daemonset", "job"] ->
        get_in(object, ["spec", "template", "spec"]) || %{}

      "cronjob" ->
        get_in(object, ["spec", "jobTemplate", "spec", "template", "spec"]) || %{}

      _ ->
        object["spec"] || %{}
    end
  end

  defp get_all_containers(pod_spec) do
    containers = pod_spec["containers"] || []
    init_containers = pod_spec["initContainers"] || []
    containers ++ init_containers
  end

  # -------------------------------------------------------------------
  # Query Helpers (private)
  # -------------------------------------------------------------------

  defp maybe_filter_org(query, nil), do: query

  defp maybe_filter_org(query, org_id) do
    from(p in query, where: p.organization_id == ^org_id)
  end

  defp maybe_filter_enabled(query, nil), do: query

  defp maybe_filter_enabled(query, enabled) when is_boolean(enabled) do
    from(p in query, where: p.enabled == ^enabled)
  end

  defp maybe_filter_action(query, nil), do: query

  defp maybe_filter_action(query, action) when is_atom(action) do
    from(p in query, where: p.action == ^action)
  end

  defp maybe_filter_action(query, action) when is_binary(action) do
    try do
      atom_action = String.to_existing_atom(action)
      from(p in query, where: p.action == ^atom_action)
    rescue
      ArgumentError -> query
    end
  end

  defp maybe_limit(query, nil), do: query
  defp maybe_limit(query, limit) when is_integer(limit), do: limit(query, ^limit)

  defp maybe_offset(query, nil), do: query
  defp maybe_offset(query, offset) when is_integer(offset), do: offset(query, ^offset)

  # -------------------------------------------------------------------
  # Attribute Normalization
  # -------------------------------------------------------------------

  defp normalize_attrs(attrs) when is_map(attrs) do
    attrs
    |> maybe_convert_atom_key("action")
    |> maybe_convert_atom_key("target")
  end

  defp maybe_convert_atom_key(attrs, key) do
    case Map.get(attrs, key) do
      val when is_binary(val) ->
        try do
          Map.put(attrs, key, String.to_existing_atom(val))
        rescue
          ArgumentError -> attrs
        end

      _ ->
        attrs
    end
  end
end
