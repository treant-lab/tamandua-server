defmodule TamanduaServer.Kubernetes.AdmissionWebhook do
  @moduledoc """
  Kubernetes Admission Control Webhook Engine.

  A GenServer that provides a full-featured admission webhook evaluation pipeline:

  1. **Pod Security Policy Evaluation** -- checks pod specs against configurable
     policies (privileged containers, host namespace usage, image whitelist/blacklist
     with regex, resource limits enforcement, seccomp/AppArmor profiles, volume type
     restrictions, run-as-non-root enforcement, capability dropping).

  2. **Webhook Request Handling** -- parses AdmissionReview v1 requests and returns
     properly structured AdmissionReview responses with allow/deny verdicts, warnings,
     JSON Patch mutation operations for auto-remediation, and audit annotations.

  3. **Policy Management (ETS-backed)** -- CRUD for admission policies with versioning,
     audit trail, namespace-scoped and cluster-wide policies, and dry-run mode.

  4. **Integration** -- creates alerts for policy violations via `TamanduaServer.Alerts`,
     broadcasts real-time updates over PubSub, and tracks allowed/denied/warned stats.

  ## ETS Tables

  - `:k8s_webhook_policies`  -- active policy cache (key: policy_id)
  - `:k8s_webhook_stats`     -- counters for admission decisions
  - `:k8s_webhook_versions`  -- policy version history

  ## Fail-Open

  All evaluation paths are wrapped in try/catch so a crash never blocks a
  Kubernetes deployment.  When a failure is detected, the request is allowed
  with a warning and the incident is recorded.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Kubernetes.{Policy, AdmissionLog}

  # -------------------------------------------------------------------
  # ETS table names
  # -------------------------------------------------------------------
  @policy_ets :k8s_webhook_policies
  @stats_ets :k8s_webhook_stats
  @versions_ets :k8s_webhook_versions

  # The upstream AdmissionController ETS table -- we also keep it in sync
  @upstream_policy_ets :k8s_admission_policies

  # System namespaces excluded from enforcement
  @system_namespaces ["kube-system", "kube-public", "kube-node-lease"]

  # Default dangerous capabilities that should be dropped
  @dangerous_capabilities [
    "NET_RAW",
    "SYS_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "SYS_RAWIO",
    "NET_ADMIN",
    "DAC_OVERRIDE",
    "FOWNER",
    "SETUID",
    "SETGID"
  ]

  # Volume types considered unsafe in production
  @unsafe_volume_types ["hostPath", "nfs", "iscsi", "fc"]

  # Maximum evaluation timeout (fail-open after this)
  @evaluation_timeout_ms 8_000

  # PubSub topic
  @pubsub_topic "k8s:admission"

  # -------------------------------------------------------------------
  # Client API
  # -------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Evaluate an AdmissionReview v1 request through the full policy pipeline.

  Returns a complete AdmissionReview v1 response map ready for JSON encoding.

  Options:
    - `:dry_run` -- if true, no side-effects (alerts, stats) are produced
  """
  @spec evaluate(map(), keyword()) :: map()
  def evaluate(admission_review, opts \\ []) do
    try do
      task =
        Task.async(fn ->
          do_evaluate(admission_review, opts)
        end)

      case Task.yield(task, @evaluation_timeout_ms) || Task.shutdown(task, :brutal_kill) do
        {:ok, result} ->
          result

        nil ->
          Logger.error("[K8s Webhook] Evaluation timed out after #{@evaluation_timeout_ms}ms -- failing open")
          increment_stat(:timeout)
          build_allow_response(admission_review, ["Tamandua: evaluation timed out, failing open"])
      end
    catch
      kind, reason ->
        Logger.error("[K8s Webhook] Evaluation crashed: #{inspect(kind)} #{inspect(reason)} -- failing open")
        increment_stat(:error)
        build_allow_response(admission_review, ["Tamandua: internal error, failing open"])
    end
  end

  @doc """
  Add a new admission policy. Persists to DB, caches in ETS, records version.
  """
  @spec add_policy(map()) :: {:ok, map()} | {:error, term()}
  def add_policy(attrs) do
    GenServer.call(__MODULE__, {:add_policy, attrs})
  end

  @doc """
  Update an existing policy by ID. Bumps version, records audit trail.
  """
  @spec update_policy(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def update_policy(policy_id, attrs) do
    GenServer.call(__MODULE__, {:update_policy, policy_id, attrs})
  end

  @doc """
  Remove a policy by ID.
  """
  @spec remove_policy(String.t()) :: :ok | {:error, :not_found}
  def remove_policy(policy_id) do
    GenServer.call(__MODULE__, {:remove_policy, policy_id})
  end

  @doc """
  Get a single policy by ID from the ETS cache.
  """
  @spec get_policy(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_policy(policy_id) do
    case :ets.lookup(@policy_ets, policy_id) do
      [{^policy_id, policy}] -> {:ok, policy}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  List all policies from ETS, sorted by priority.
  """
  @spec list_policies() :: [map()]
  def list_policies do
    :ets.foldl(
      fn {_id, policy}, acc -> [policy | acc] end,
      [],
      @policy_ets
    )
    |> Enum.sort_by(& &1.priority)
  end

  @doc """
  Get the version history for a given policy.
  """
  @spec policy_versions(String.t()) :: [map()]
  def policy_versions(policy_id) do
    case :ets.lookup(@versions_ets, policy_id) do
      [{^policy_id, versions}] -> versions
      [] -> []
    end
  end

  @doc """
  Return current stats (allowed, denied, warned, mutated, error, timeout counts).
  """
  @spec stats() :: map()
  def stats do
    counts =
      :ets.foldl(
        fn {key, val}, acc -> Map.put(acc, key, val) end,
        %{},
        @stats_ets
      )

    Map.merge(
      %{allowed: 0, denied: 0, warned: 0, mutated: 0, error: 0, timeout: 0, total: 0},
      counts
    )
  end

  @doc """
  Reload all policies from the database into ETS.
  """
  @spec reload_policies() :: {:ok, non_neg_integer()}
  def reload_policies do
    GenServer.call(__MODULE__, :reload_policies)
  end

  @doc """
  Toggle dry-run mode for a specific policy.
  """
  @spec set_dry_run(String.t(), boolean()) :: {:ok, map()} | {:error, :not_found}
  def set_dry_run(policy_id, dry_run) do
    GenServer.call(__MODULE__, {:set_dry_run, policy_id, dry_run})
  end

  # -------------------------------------------------------------------
  # GenServer callbacks
  # -------------------------------------------------------------------

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@policy_ets, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@stats_ets, [:set, :named_table, :public, write_concurrency: true])
    :ets.new(@versions_ets, [:set, :named_table, :public, read_concurrency: true])

    # Initialize stat counters
    for key <- [:allowed, :denied, :warned, :mutated, :error, :timeout, :total] do
      :ets.insert(@stats_ets, {key, 0})
    end

    # Load policies from DB
    policy_count =
      try do
        load_policies_from_db()
      rescue
        e ->
          Logger.warning("[K8s Webhook] Failed to load policies from DB: #{inspect(e)}, starting empty")
          0
      end

    Logger.info("[K8s Webhook] Started with #{policy_count} policies loaded")

    {:ok, %{started_at: DateTime.utc_now()}}
  end

  @impl true
  def handle_call({:add_policy, attrs}, _from, state) do
    case Policy.create_policy(attrs) do
      {:ok, policy} ->
        enriched = enrich_policy(policy)
        :ets.insert(@policy_ets, {policy.id, enriched})
        sync_to_upstream(policy)
        record_version(policy.id, enriched, :created)
        broadcast(:policy_created, enriched)
        {:reply, {:ok, enriched}, state}

      {:error, changeset} ->
        {:reply, {:error, changeset}, state}
    end
  end

  def handle_call({:update_policy, policy_id, attrs}, _from, state) do
    case Policy.get_policy(policy_id) do
      {:ok, policy} ->
        case Policy.update_policy(policy, attrs) do
          {:ok, updated} ->
            enriched = enrich_policy(updated)
            :ets.insert(@policy_ets, {updated.id, enriched})
            sync_to_upstream(updated)
            record_version(updated.id, enriched, :updated)
            broadcast(:policy_updated, enriched)
            {:reply, {:ok, enriched}, state}

          {:error, changeset} ->
            {:reply, {:error, changeset}, state}
        end

      {:error, :not_found} ->
        {:reply, {:error, :not_found}, state}
    end
  end

  def handle_call({:remove_policy, policy_id}, _from, state) do
    case Policy.get_policy(policy_id) do
      {:ok, policy} ->
        Policy.delete_policy(policy)
        :ets.delete(@policy_ets, policy_id)
        delete_from_upstream(policy_id)
        record_version(policy_id, %{id: policy_id, name: policy.name}, :deleted)
        broadcast(:policy_deleted, %{id: policy_id})
        {:reply, :ok, state}

      {:error, :not_found} ->
        {:reply, {:error, :not_found}, state}
    end
  end

  def handle_call(:reload_policies, _from, state) do
    :ets.delete_all_objects(@policy_ets)
    count = load_policies_from_db()
    Logger.info("[K8s Webhook] Reloaded #{count} policies")
    {:reply, {:ok, count}, state}
  end

  def handle_call({:set_dry_run, policy_id, dry_run}, _from, state) do
    case :ets.lookup(@policy_ets, policy_id) do
      [{^policy_id, policy}] ->
        updated = Map.put(policy, :dry_run, dry_run)
        :ets.insert(@policy_ets, {policy_id, updated})
        broadcast(:policy_updated, updated)
        {:reply, {:ok, updated}, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  # -------------------------------------------------------------------
  # Core evaluation pipeline
  # -------------------------------------------------------------------

  defp do_evaluate(admission_review, opts) do
    start_us = System.monotonic_time(:microsecond)
    request = admission_review["request"] || admission_review
    uid = request["uid"] || ""
    dry_run = Keyword.get(opts, :dry_run, request["dryRun"] || false)

    namespace = request["namespace"] || ""
    resource_kind = extract_resource_kind(request)
    pod_spec = extract_pod_spec(request)
    containers = get_all_containers(pod_spec)

    # Skip system namespaces
    if namespace in @system_namespaces do
      increment_stat(:allowed)
      increment_stat(:total)
      build_allow_response(admission_review, [])
    else
      # Collect all applicable policies
      policies = get_applicable_policies(namespace, resource_kind)

      # Run evaluation
      {denials, warnings, patches, annotations} =
        evaluate_policies(policies, pod_spec, containers, request)

      duration_us = System.monotonic_time(:microsecond) - start_us

      # Build response
      response =
        cond do
          denials != [] ->
            reason = Enum.join(denials, "; ")
            update_stats_and_alert(:denied, denials, request, namespace, resource_kind, duration_us, dry_run)
            build_deny_response(uid, reason, warnings, annotations)

          patches != [] ->
            update_stats_and_alert(:mutated, warnings, request, namespace, resource_kind, duration_us, dry_run)
            build_mutate_response(uid, patches, warnings, annotations)

          true ->
            if warnings != [] do
              update_stats_and_alert(:warned, warnings, request, namespace, resource_kind, duration_us, dry_run)
            else
              increment_stat(:allowed)
              increment_stat(:total)
            end

            build_allow_response_with_details(uid, warnings, annotations)
        end

      # Async audit log
      unless dry_run do
        log_decision(request, namespace, resource_kind, denials, warnings, patches, duration_us)
      end

      response
    end
  end

  defp evaluate_policies(policies, pod_spec, containers, request) do
    security_context = pod_spec["securityContext"] || %{}

    Enum.reduce(policies, {[], [], [], %{}}, fn policy, {deny_acc, warn_acc, patch_acc, ann_acc} ->
      # Skip disabled policies
      if not Map.get(policy, :enabled, true) do
        {deny_acc, warn_acc, patch_acc, ann_acc}
      else
        dry_run = Map.get(policy, :dry_run, false)

        case evaluate_single_policy(policy, pod_spec, containers, security_context, request) do
          {:deny, msg} ->
            if dry_run do
              annotation_key = "tamandua.io/dry-run-deny-#{policy.id}"
              {deny_acc, ["[DRY-RUN] #{msg}" | warn_acc], patch_acc, Map.put(ann_acc, annotation_key, msg)}
            else
              {[msg | deny_acc], warn_acc, patch_acc, ann_acc}
            end

          {:warn, msg} ->
            {deny_acc, [msg | warn_acc], patch_acc, ann_acc}

          {:mutate, new_patches} ->
            if dry_run do
              annotation_key = "tamandua.io/dry-run-mutate-#{policy.id}"
              {deny_acc, warn_acc, patch_acc, Map.put(ann_acc, annotation_key, "#{length(new_patches)} patches")}
            else
              {deny_acc, warn_acc, patch_acc ++ new_patches, ann_acc}
            end

          :pass ->
            {deny_acc, warn_acc, patch_acc, ann_acc}
        end
      end
    end)
    |> then(fn {d, w, p, a} -> {Enum.reverse(d), Enum.reverse(w), p, a} end)
  end

  # -------------------------------------------------------------------
  # Individual policy evaluators
  # -------------------------------------------------------------------

  defp evaluate_single_policy(policy, pod_spec, containers, security_context, request) do
    conditions = policy.conditions || %{}
    action = policy.action

    violations = collect_violations(conditions, pod_spec, containers, security_context, request)

    case {violations, action} do
      {[], _} ->
        :pass

      {violations, :deny} ->
        {:deny, "[#{policy.name}] " <> Enum.join(violations, "; ")}

      {violations, :warn} ->
        {:warn, "[#{policy.name}] " <> Enum.join(violations, "; ")}

      {_violations, :mutate} ->
        patches = generate_mutation_patches(policy, pod_spec, containers)
        if patches == [], do: :pass, else: {:mutate, patches}

      _ ->
        :pass
    end
  end

  defp collect_violations(conditions, pod_spec, containers, security_context, _request) do
    violations = []

    # 1. Privileged containers
    violations =
      if Map.get(conditions, "privileged") == true do
        case check_privileged(containers) do
          {:violation, msg} -> [msg | violations]
          :pass -> violations
        end
      else
        violations
      end

    # 2. Host namespace usage
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

    # 3. Image whitelist/blacklist with regex
    violations =
      cond do
        Map.has_key?(conditions, "image_whitelist") ->
          patterns = Map.get(conditions, "image_whitelist", [])
          case check_image_whitelist(containers, patterns) do
            {:violation, msg} -> [msg | violations]
            :pass -> violations
          end

        Map.has_key?(conditions, "image_blacklist") ->
          patterns = Map.get(conditions, "image_blacklist", [])
          case check_image_blacklist(containers, patterns) do
            {:violation, msg} -> [msg | violations]
            :pass -> violations
          end

        Map.has_key?(conditions, "registries") ->
          trusted = Map.get(conditions, "registries", [])
          case check_registries(containers, trusted) do
            {:violation, msg} -> [msg | violations]
            :pass -> violations
          end

        true ->
          violations
      end

    # 4. Resource limits enforcement
    violations =
      if Map.get(conditions, "missing_resource_limits") == true or
           Map.get(conditions, "require_resource_limits") == true do
        case check_resource_limits(containers) do
          {:violation, msg} -> [msg | violations]
          :pass -> violations
        end
      else
        violations
      end

    # 5. Seccomp profile requirements
    violations =
      if Map.get(conditions, "require_seccomp") == true do
        case check_seccomp_profile(containers, security_context) do
          {:violation, msg} -> [msg | violations]
          :pass -> violations
        end
      else
        violations
      end

    # 6. AppArmor profile requirements
    violations =
      if Map.get(conditions, "require_apparmor") == true do
        case check_apparmor_profile(containers, pod_spec) do
          {:violation, msg} -> [msg | violations]
          :pass -> violations
        end
      else
        violations
      end

    # 7. Volume type restrictions
    violations =
      if Map.get(conditions, "restrict_volumes") == true do
        forbidden = Map.get(conditions, "forbidden_volume_types", @unsafe_volume_types)
        case check_volume_types(pod_spec, forbidden) do
          {:violation, msg} -> [msg | violations]
          :pass -> violations
        end
      else
        violations
      end

    # 8. Run-as-non-root enforcement
    violations =
      if Map.get(conditions, "run_as_root") == true or
           Map.get(conditions, "require_non_root") == true do
        case check_run_as_non_root(containers, security_context) do
          {:violation, msg} -> [msg | violations]
          :pass -> violations
        end
      else
        violations
      end

    # 9. Capability dropping
    violations =
      if Map.get(conditions, "drop_capabilities") == true do
        required_drops = Map.get(conditions, "required_drop_capabilities", @dangerous_capabilities)
        case check_capabilities(containers, required_drops) do
          {:violation, msg} -> [msg | violations]
          :pass -> violations
        end
      else
        violations
      end

    # 10. Missing security context
    violations =
      if Map.get(conditions, "missing_security_context") == true do
        case check_security_context(containers, security_context) do
          {:violation, msg} -> [msg | violations]
          :pass -> violations
        end
      else
        violations
      end

    # 11. Latest image tag
    violations =
      if Map.get(conditions, "image_tag") == "latest" or
           Map.get(conditions, "deny_latest_tag") == true do
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
  # Check functions
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

  defp check_image_whitelist(containers, patterns) do
    compiled =
      Enum.map(patterns, fn p ->
        case Regex.compile(p) do
          {:ok, re} -> re
          _ -> nil
        end
      end)
      |> Enum.reject(&is_nil/1)

    violating =
      Enum.filter(containers, fn c ->
        image = c["image"] || ""
        not Enum.any?(compiled, fn re -> Regex.match?(re, image) end)
      end)

    if violating == [] do
      :pass
    else
      images = Enum.map_join(violating, ", ", &(Map.get(&1, "image") || "unknown"))
      {:violation, "Images not matching whitelist: #{images}"}
    end
  end

  defp check_image_blacklist(containers, patterns) do
    compiled =
      Enum.map(patterns, fn p ->
        case Regex.compile(p) do
          {:ok, re} -> re
          _ -> nil
        end
      end)
      |> Enum.reject(&is_nil/1)

    violating =
      Enum.filter(containers, fn c ->
        image = c["image"] || ""
        Enum.any?(compiled, fn re -> Regex.match?(re, image) end)
      end)

    if violating == [] do
      :pass
    else
      images = Enum.map_join(violating, ", ", &(Map.get(&1, "image") || "unknown"))
      {:violation, "Images matching blacklist: #{images}"}
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
      images = Enum.map_join(violating, ", ", &(Map.get(&1, "image") || "unknown"))
      {:violation, "Images from untrusted registries: #{images}"}
    end
  end

  defp image_from_trusted_registry?(image, trusted) do
    Enum.any?(trusted, fn registry ->
      String.starts_with?(image, registry <> "/") or
        String.starts_with?(image, registry)
    end) or not String.contains?(image, "/")
  end

  defp check_resource_limits(containers) do
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

  defp check_seccomp_profile(containers, pod_security_context) do
    pod_seccomp = get_in(pod_security_context, ["seccompProfile", "type"])

    violating =
      Enum.filter(containers, fn c ->
        container_seccomp = get_in(c, ["securityContext", "seccompProfile", "type"])
        effective = container_seccomp || pod_seccomp
        is_nil(effective) or effective == "Unconfined"
      end)

    if violating == [] do
      :pass
    else
      names = Enum.map_join(violating, ", ", &(Map.get(&1, "name") || "unnamed"))
      {:violation, "Seccomp profile required (RuntimeDefault or Localhost): #{names}"}
    end
  end

  defp check_apparmor_profile(containers, pod_spec) do
    annotations = get_in(pod_spec, ["metadata", "annotations"]) || %{}

    violating =
      Enum.filter(containers, fn c ->
        name = c["name"] || ""
        key = "container.apparmor.security.beta.kubernetes.io/#{name}"
        profile = Map.get(annotations, key)
        is_nil(profile) or profile == "unconfined"
      end)

    if violating == [] do
      :pass
    else
      names = Enum.map_join(violating, ", ", &(Map.get(&1, "name") || "unnamed"))
      {:violation, "AppArmor profile required: #{names}"}
    end
  end

  defp check_volume_types(pod_spec, forbidden_types) do
    volumes = pod_spec["volumes"] || []

    violating =
      Enum.filter(volumes, fn vol ->
        Enum.any?(forbidden_types, fn vtype ->
          Map.has_key?(vol, vtype)
        end)
      end)

    if violating == [] do
      :pass
    else
      names = Enum.map_join(violating, ", ", &(Map.get(&1, "name") || "unnamed"))
      types =
        Enum.flat_map(violating, fn vol ->
          Enum.filter(forbidden_types, &Map.has_key?(vol, &1))
        end)
        |> Enum.uniq()
        |> Enum.join(", ")

      {:violation, "Forbidden volume types (#{types}) used by: #{names}"}
    end
  end

  defp check_run_as_non_root(containers, pod_security_context) do
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

  defp check_capabilities(containers, required_drops) do
    violating =
      Enum.filter(containers, fn c ->
        sc = c["securityContext"] || %{}
        capabilities = sc["capabilities"] || %{}
        drops = capabilities["drop"] || []

        # Check that all required capabilities are dropped
        drops_upper = Enum.map(drops, &String.upcase/1)
        missing = Enum.reject(required_drops, fn cap -> String.upcase(cap) in drops_upper end)
        missing != []
      end)

    if violating == [] do
      :pass
    else
      names = Enum.map_join(violating, ", ", &(Map.get(&1, "name") || "unnamed"))
      {:violation, "Required capability drops missing: #{names} (need: #{Enum.join(required_drops, ", ")})"}
    end
  end

  defp check_security_context(containers, pod_security_context) do
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
      {:violation, "Avoid using 'latest' tag, pin to a specific version: #{images}"}
    end
  end

  # -------------------------------------------------------------------
  # Mutation patch generation
  # -------------------------------------------------------------------

  defp generate_mutation_patches(policy, pod_spec, containers) do
    conditions = policy.conditions || %{}
    mutation = policy.mutation || %{}
    patches = []

    # Resource limit injection
    patches =
      if Map.get(conditions, "missing_resource_limits") == true or
           Map.has_key?(mutation, "default_limits") do
        default_limits = Map.get(mutation, "default_limits", %{"cpu" => "500m", "memory" => "256Mi"})
        patches ++ build_resource_limit_patches(containers, default_limits)
      else
        patches
      end

    # Label injection
    patches =
      if Map.get(conditions, "add_labels") == true or Map.has_key?(mutation, "add_labels") do
        labels = Map.get(mutation, "add_labels", %{"tamandua.io/managed" => "true"})
        patches ++ build_label_patches(pod_spec, labels)
      else
        patches
      end

    # Run-as-non-root enforcement via mutation
    patches =
      if Map.get(mutation, "enforce_non_root") == true do
        patches ++ build_non_root_patches(pod_spec)
      else
        patches
      end

    # Drop dangerous capabilities via mutation
    patches =
      if Map.get(mutation, "drop_capabilities") == true do
        caps = Map.get(mutation, "capabilities_to_drop", @dangerous_capabilities)
        patches ++ build_capability_patches(containers, caps)
      else
        patches
      end

    # Seccomp profile injection
    patches =
      if Map.get(mutation, "inject_seccomp") == true do
        profile = Map.get(mutation, "seccomp_profile", "RuntimeDefault")
        patches ++ build_seccomp_patches(pod_spec, profile)
      else
        patches
      end

    patches
  end

  defp build_resource_limit_patches(containers, default_limits) do
    containers
    |> Enum.with_index()
    |> Enum.flat_map(fn {container, idx} ->
      resources = container["resources"] || %{}
      limits = resources["limits"] || %{}
      base = "/spec/containers/#{idx}"

      p = []

      p =
        if is_nil(container["resources"]) do
          p ++ [%{"op" => "add", "path" => "#{base}/resources", "value" => %{}}]
        else
          p
        end

      p =
        if is_nil(resources["limits"]) do
          p ++ [%{"op" => "add", "path" => "#{base}/resources/limits", "value" => %{}}]
        else
          p
        end

      p =
        if is_nil(limits["cpu"]) and Map.has_key?(default_limits, "cpu") do
          p ++ [%{"op" => "add", "path" => "#{base}/resources/limits/cpu", "value" => default_limits["cpu"]}]
        else
          p
        end

      p =
        if is_nil(limits["memory"]) and Map.has_key?(default_limits, "memory") do
          p ++ [%{"op" => "add", "path" => "#{base}/resources/limits/memory", "value" => default_limits["memory"]}]
        else
          p
        end

      p
    end)
  end

  defp build_label_patches(pod_spec, labels) do
    existing = get_in(pod_spec, ["metadata", "labels"]) || %{}

    if map_size(existing) == 0 do
      [%{"op" => "add", "path" => "/metadata/labels", "value" => labels}]
    else
      Enum.flat_map(labels, fn {key, value} ->
        if Map.has_key?(existing, key) do
          []
        else
          escaped = String.replace(key, "/", "~1")
          [%{"op" => "add", "path" => "/metadata/labels/#{escaped}", "value" => value}]
        end
      end)
    end
  end

  defp build_non_root_patches(pod_spec) do
    sc = pod_spec["securityContext"] || %{}

    if sc["runAsNonRoot"] == true do
      []
    else
      if is_nil(pod_spec["securityContext"]) do
        [%{"op" => "add", "path" => "/spec/securityContext", "value" => %{"runAsNonRoot" => true, "runAsUser" => 65534}}]
      else
        [
          %{"op" => "add", "path" => "/spec/securityContext/runAsNonRoot", "value" => true},
          %{"op" => "add", "path" => "/spec/securityContext/runAsUser", "value" => 65534}
        ]
      end
    end
  end

  defp build_capability_patches(containers, caps_to_drop) do
    containers
    |> Enum.with_index()
    |> Enum.flat_map(fn {container, idx} ->
      sc = container["securityContext"] || %{}
      capabilities = sc["capabilities"] || %{}
      existing_drops = capabilities["drop"] || []
      base = "/spec/containers/#{idx}"

      existing_upper = Enum.map(existing_drops, &String.upcase/1)
      missing = Enum.reject(caps_to_drop, fn cap -> String.upcase(cap) in existing_upper end)

      if missing == [] do
        []
      else
        new_drops = existing_drops ++ missing
        p = []

        p =
          if is_nil(container["securityContext"]) do
            p ++ [%{"op" => "add", "path" => "#{base}/securityContext", "value" => %{}}]
          else
            p
          end

        p =
          if is_nil(sc["capabilities"]) do
            p ++ [%{"op" => "add", "path" => "#{base}/securityContext/capabilities", "value" => %{}}]
          else
            p
          end

        p ++ [%{"op" => "replace", "path" => "#{base}/securityContext/capabilities/drop", "value" => new_drops}]
      end
    end)
  end

  defp build_seccomp_patches(pod_spec, profile_type) do
    sc = pod_spec["securityContext"] || %{}

    if get_in(sc, ["seccompProfile", "type"]) != nil do
      []
    else
      if is_nil(pod_spec["securityContext"]) do
        [%{"op" => "add", "path" => "/spec/securityContext", "value" => %{"seccompProfile" => %{"type" => profile_type}}}]
      else
        [%{"op" => "add", "path" => "/spec/securityContext/seccompProfile", "value" => %{"type" => profile_type}}]
      end
    end
  end

  # -------------------------------------------------------------------
  # Response builders (AdmissionReview v1 format)
  # -------------------------------------------------------------------

  defp build_allow_response(admission_review, warnings) do
    request = admission_review["request"] || admission_review
    uid = request["uid"] || ""
    build_allow_response_with_details(uid, warnings, %{})
  end

  defp build_allow_response_with_details(uid, warnings, annotations) do
    response = %{
      "uid" => uid,
      "allowed" => true
    }

    response =
      if warnings != [] do
        Map.put(response, "warnings", warnings)
      else
        response
      end

    response =
      if map_size(annotations) > 0 do
        Map.put(response, "auditAnnotations", annotations)
      else
        response
      end

    %{
      "apiVersion" => "admission.k8s.io/v1",
      "kind" => "AdmissionReview",
      "response" => response
    }
  end

  defp build_deny_response(uid, reason, warnings, annotations) do
    response = %{
      "uid" => uid,
      "allowed" => false,
      "status" => %{
        "code" => 403,
        "message" => reason
      }
    }

    response =
      if warnings != [] do
        Map.put(response, "warnings", warnings)
      else
        response
      end

    response =
      if map_size(annotations) > 0 do
        Map.put(response, "auditAnnotations", annotations)
      else
        response
      end

    %{
      "apiVersion" => "admission.k8s.io/v1",
      "kind" => "AdmissionReview",
      "response" => response
    }
  end

  defp build_mutate_response(uid, patches, warnings, annotations) do
    patch_json = Jason.encode!(patches)
    patch_base64 = Base.encode64(patch_json)

    response = %{
      "uid" => uid,
      "allowed" => true,
      "patchType" => "JSONPatch",
      "patch" => patch_base64
    }

    response =
      if warnings != [] do
        Map.put(response, "warnings", warnings)
      else
        response
      end

    response =
      if map_size(annotations) > 0 do
        Map.put(response, "auditAnnotations", annotations)
      else
        response
      end

    %{
      "apiVersion" => "admission.k8s.io/v1",
      "kind" => "AdmissionReview",
      "response" => response
    }
  end

  # -------------------------------------------------------------------
  # Stats, alerting, and broadcasting
  # -------------------------------------------------------------------

  defp update_stats_and_alert(decision, messages, request, namespace, resource_kind, duration_us, dry_run) do
    increment_stat(decision)
    increment_stat(:total)

    unless dry_run do
      # Create alert for denials
      if decision == :denied do
        create_violation_alert(messages, request, namespace, resource_kind)
      end

      # PubSub broadcast
      broadcast(:admission_decision, %{
        decision: decision,
        namespace: namespace,
        resource_kind: resource_kind,
        messages: messages,
        duration_us: duration_us,
        timestamp: DateTime.utc_now()
      })
    end
  end

  defp create_violation_alert(denials, request, namespace, resource_kind) do
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      object_name =
        get_in(request, ["object", "metadata", "name"]) ||
          request["name"] ||
          "unknown"

      user = get_in(request, ["userInfo", "username"]) || "unknown"

      attrs = %{
        severity: "high",
        title: "K8s Admission Policy Violation: #{resource_kind}/#{object_name}",
        description:
          "Kubernetes admission webhook denied #{resource_kind} '#{object_name}' " <>
            "in namespace '#{namespace}' requested by '#{user}'. " <>
            "Violations: #{Enum.join(denials, "; ")}",
        mitre_tactics: ["Execution", "Privilege Escalation"],
        mitre_techniques: ["T1610", "T1611"],
        status: "new",
        enrichment: %{
          "source" => "k8s_admission_webhook",
          "namespace" => namespace,
          "resource_kind" => resource_kind,
          "object_name" => object_name,
          "requesting_user" => user,
          "violations" => denials
        }
      }

      case TamanduaServer.Alerts.create_alert(attrs) do
        {:ok, alert} ->
          Logger.info("[K8s Webhook] Created alert #{alert.id} for admission violation")

        {:error, reason} ->
          Logger.warning("[K8s Webhook] Failed to create violation alert: #{inspect(reason)}")
      end
    end)
  end

  defp increment_stat(key) do
    try do
      :ets.update_counter(@stats_ets, key, {2, 1})
    rescue
      ArgumentError ->
        :ets.insert(@stats_ets, {key, 1})
    end
  end

  defp broadcast(event, payload) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      @pubsub_topic,
      {event, payload}
    )
  end

  # -------------------------------------------------------------------
  # Audit logging
  # -------------------------------------------------------------------

  defp log_decision(request, namespace, resource_kind, denials, warnings, patches, duration_us) do
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      user_info = request["userInfo"] || %{}

      decision =
        cond do
          denials != [] -> "deny"
          patches != [] -> "mutate"
          warnings != [] -> "allow"
          true -> "allow"
        end

      attrs = %{
        uid: request["uid"] || "",
        namespace: namespace,
        name: get_in(request, ["object", "metadata", "name"]) || request["name"] || "unknown",
        resource_kind: resource_kind,
        operation: request["operation"],
        decision: decision,
        reason: if(denials != [], do: Enum.join(denials, "; "), else: nil),
        warnings: warnings,
        policy_names: [],
        patches_applied: length(patches),
        requesting_user: user_info["username"],
        requesting_groups: user_info["groups"] || [],
        dry_run: request["dryRun"] || false,
        duration_us: duration_us,
        metadata: %{
          "resource_version" => get_in(request, ["object", "metadata", "resourceVersion"]),
          "patch_count" => length(patches)
        }
      }

      case AdmissionLog.record(attrs) do
        {:ok, _} -> :ok
        {:error, changeset} ->
          Logger.warning("[K8s Webhook] Failed to record audit log: #{inspect(changeset.errors)}")
      end
    end)
  end

  # -------------------------------------------------------------------
  # Policy helpers
  # -------------------------------------------------------------------

  defp get_applicable_policies(namespace, resource_kind) do
    :ets.foldl(
      fn {_id, policy}, acc ->
        if Map.get(policy, :enabled, true) and policy_applies?(policy, namespace, resource_kind) do
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
    # Namespace scope
    ns_ok =
      case policy.namespaces do
        nil -> true
        [] -> true
        ns_list -> namespace in ns_list
      end

    # Resource kind matching
    target_str = if is_atom(policy.target), do: Atom.to_string(policy.target), else: to_string(policy.target)

    kind_ok = String.downcase(target_str) == String.downcase(resource_kind)

    pod_equivalent =
      String.downcase(target_str) == "pod" and
        String.downcase(resource_kind) in [
          "pod", "deployment", "replicaset", "daemonset", "statefulset", "job", "cronjob"
        ]

    ns_ok and (kind_ok or pod_equivalent)
  end

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

  defp load_policies_from_db do
    policies = Policy.list_policies()

    Enum.each(policies, fn policy ->
      enriched = enrich_policy(policy)
      :ets.insert(@policy_ets, {policy.id, enriched})
    end)

    length(policies)
  end

  defp enrich_policy(policy) do
    # Add computed fields for the webhook engine
    Map.merge(
      Map.from_struct(policy),
      %{dry_run: false}
    )
  end

  defp sync_to_upstream(policy) do
    # Keep the upstream AdmissionController ETS in sync if it exists
    try do
      if :ets.info(@upstream_policy_ets) != :undefined do
        :ets.insert(@upstream_policy_ets, {policy.id, policy})
      end
    rescue
      _ -> :ok
    end
  end

  defp delete_from_upstream(policy_id) do
    try do
      if :ets.info(@upstream_policy_ets) != :undefined do
        :ets.delete(@upstream_policy_ets, policy_id)
      end
    rescue
      _ -> :ok
    end
  end

  # -------------------------------------------------------------------
  # Policy versioning
  # -------------------------------------------------------------------

  defp record_version(policy_id, policy_data, action) do
    version_entry = %{
      version: :os.system_time(:millisecond),
      action: action,
      snapshot: policy_data,
      timestamp: DateTime.utc_now()
    }

    existing =
      case :ets.lookup(@versions_ets, policy_id) do
        [{^policy_id, versions}] -> versions
        [] -> []
      end

    # Keep last 50 versions per policy
    updated = Enum.take([version_entry | existing], 50)
    :ets.insert(@versions_ets, {policy_id, updated})
  end
end
