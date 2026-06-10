defmodule TamanduaServer.Fim.BaselineManager do
  @moduledoc """
  Manages FIM baselines for all agents.

  Features:
  - Store and retrieve file baselines
  - Track baseline history and versioning
  - Detect deviations from baseline
  - Generate compliance reports
  - Manage whitelist rules
  """

  use GenServer
  require Logger
  alias TamanduaServer.Repo
  alias TamanduaServer.Fim.{Baseline, BaselineHistory, Change, Policy, WhitelistRule}
  import Ecto.Query

  # ============================================================================
  # Public API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Store a baseline snapshot from an agent.
  """
  def store_baseline(agent_id, path, baseline_data) do
    GenServer.call(__MODULE__, {:store_baseline, agent_id, path, baseline_data})
  end

  @doc """
  Get the current baseline for a file.
  """
  def get_baseline(agent_id, path) do
    GenServer.call(__MODULE__, {:get_baseline, agent_id, path})
  end

  @doc """
  Record a file integrity change.
  """
  def record_change(agent_id, change_data) do
    GenServer.cast(__MODULE__, {:record_change, agent_id, change_data})
  end

  @doc """
  Get recent changes for an agent.
  """
  def get_recent_changes(agent_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    since = Keyword.get(opts, :since)

    query =
      from c in Change,
        where: c.agent_id == ^agent_id,
        order_by: [desc: c.detected_at],
        limit: ^limit

    query =
      if since do
        from c in query, where: c.detected_at >= ^since
      else
        query
      end

    Repo.all(query)
  end

  @doc """
  Generate compliance report for an agent.
  """
  def generate_compliance_report(agent_id, framework) do
    GenServer.call(__MODULE__, {:generate_compliance_report, agent_id, framework})
  end

  @doc """
  Add a whitelist rule.
  """
  def add_whitelist_rule(agent_id, rule_data) do
    GenServer.call(__MODULE__, {:add_whitelist_rule, agent_id, rule_data})
  end

  @doc """
  Check if a change is whitelisted.
  """
  def is_whitelisted?(agent_id, path, change_type) do
    GenServer.call(__MODULE__, {:is_whitelisted, agent_id, path, change_type})
  end

  @doc """
  Get baseline statistics for an agent.
  """
  def get_stats(agent_id) do
    GenServer.call(__MODULE__, {:get_stats, agent_id})
  end

  # ============================================================================
  # Dashboard Helper Functions (Direct DB queries, no GenServer)
  # ============================================================================

  @doc "Count total baselines across all agents"
  def count_baselines do
    Repo.aggregate(Baseline, :count)
  end

  @doc "Get total size of all baselined files"
  def total_baseline_size do
    Repo.aggregate(Baseline, :sum, :size) || 0
  end

  @doc "Count changes since a datetime"
  def count_changes_since(since) do
    from(c in Change, where: c.detected_at >= ^since)
    |> Repo.aggregate(:count)
  end

  @doc "Count violations (non-whitelisted high/critical) since a datetime"
  def count_violations_since(since) do
    from(c in Change,
      where: c.detected_at >= ^since,
      where: c.whitelisted == false,
      where: c.severity in ["high", "critical"]
    )
    |> Repo.aggregate(:count)
  end

  @doc "Get baseline counts by category"
  def baselines_by_category do
    from(b in Baseline,
      group_by: b.category,
      select: {b.category, count(b.id)}
    )
    |> Repo.all()
    |> Map.new()
  end

  @doc "Get last scan time (most recent baseline update)"
  def last_scan_time do
    from(b in Baseline, order_by: [desc: b.updated_at], limit: 1, select: b.updated_at)
    |> Repo.one()
  end

  @doc "Count unique agents with baselines"
  def agent_count do
    from(b in Baseline, select: count(b.agent_id, :distinct))
    |> Repo.one()
  end

  @doc "Get recent changes across all agents"
  def get_global_recent_changes(opts \\ []) when is_list(opts) do
    limit = Keyword.get(opts, :limit, 100)

    from(c in Change,
      order_by: [desc: c.detected_at],
      limit: ^limit
    )
    |> Repo.all()
  end

  # ============================================================================
  # Policy Management API
  # ============================================================================

  @doc """
  Create or update a FIM policy.
  """
  def upsert_policy(attrs) do
    GenServer.call(__MODULE__, {:upsert_policy, attrs})
  end

  @doc """
  Delete a FIM policy.
  """
  def delete_policy(policy_id) do
    GenServer.call(__MODULE__, {:delete_policy, policy_id})
  end

  @doc """
  Sync policies to an agent.
  """
  def sync_policies_to_agent(agent_id) do
    GenServer.cast(__MODULE__, {:sync_policies, agent_id})
  end

  @doc """
  Get all policies for an agent (including global).
  """
  def get_policies(agent_id) do
    GenServer.call(__MODULE__, {:get_policies, agent_id})
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("FIM Baseline Manager started")
    {:ok, %{}}
  end

  @impl true
  def handle_call({:store_baseline, agent_id, path, baseline_data}, _from, state) do
    result =
      case Repo.get_by(Baseline, agent_id: agent_id, path: path) do
        nil ->
          # Create new baseline
          %Baseline{}
          |> Baseline.changeset(%{
            agent_id: agent_id,
            path: path,
            hash: baseline_data["hash"],
            size: baseline_data["size"],
            permissions: baseline_data["permissions"],
            owner: baseline_data["owner"],
            group: baseline_data["group"],
            mtime: baseline_data["mtime"],
            ctime: baseline_data["ctime"],
            attributes: baseline_data["attributes"] || [],
            category: baseline_data["category"] || "custom",
            known_good: baseline_data["known_good"] || false,
            baseline_version: 1
          })
          |> Repo.insert()

        existing ->
          # Update existing baseline and record history
          with {:ok, _history} <- record_baseline_history(existing),
               {:ok, updated} <-
                 existing
                 |> Baseline.changeset(%{
                   hash: baseline_data["hash"],
                   size: baseline_data["size"],
                   permissions: baseline_data["permissions"],
                   owner: baseline_data["owner"],
                   group: baseline_data["group"],
                   mtime: baseline_data["mtime"],
                   ctime: baseline_data["ctime"],
                   attributes: baseline_data["attributes"] || [],
                   baseline_version: existing.baseline_version + 1
                 })
                 |> Repo.update() do
            {:ok, updated}
          end
      end

    case result do
      {:ok, baseline} ->
        {:reply, {:ok, baseline}, state}

      {:error, changeset} ->
        Logger.error("Failed to store baseline: #{inspect(changeset)}")
        {:reply, {:error, changeset}, state}
    end
  end

  @impl true
  def handle_call({:get_baseline, agent_id, path}, _from, state) do
    baseline = Repo.get_by(Baseline, agent_id: agent_id, path: path)
    {:reply, {:ok, baseline}, state}
  end

  @impl true
  def handle_call({:generate_compliance_report, agent_id, framework}, _from, state) do
    report = build_compliance_report(agent_id, framework)
    {:reply, {:ok, report}, state}
  end

  @impl true
  def handle_call({:add_whitelist_rule, agent_id, rule_data}, _from, state) do
    result =
      %WhitelistRule{}
      |> WhitelistRule.changeset(%{
        agent_id: agent_id,
        pattern: rule_data["pattern"],
        allowed_changes: rule_data["allowed_changes"] || [],
        reason: rule_data["reason"],
        expires: rule_data["expires"],
        added_by: rule_data["added_by"]
      })
      |> Repo.insert()

    case result do
      {:ok, rule} ->
        {:reply, {:ok, rule}, state}

      {:error, changeset} ->
        Logger.error("Failed to add whitelist rule: #{inspect(changeset)}")
        {:reply, {:error, changeset}, state}
    end
  end

  @impl true
  def handle_call({:is_whitelisted, agent_id, path, change_type}, _from, state) do
    now = DateTime.utc_now() |> DateTime.to_unix()

    whitelisted =
      from(r in WhitelistRule,
        where: r.agent_id == ^agent_id,
        where: r.expires == 0 or r.expires > ^now
      )
      |> Repo.all()
      |> Enum.any?(fn rule ->
        path_matches_pattern?(path, rule.pattern) and
          (rule.allowed_changes == [] or change_type in rule.allowed_changes)
      end)

    {:reply, whitelisted, state}
  end

  @impl true
  def handle_call({:get_stats, agent_id}, _from, state) do
    stats =
      from(b in Baseline,
        where: b.agent_id == ^agent_id,
        select: %{
          total_files: count(b.id),
          total_size: sum(b.size),
          oldest_baseline: min(b.updated_at),
          newest_baseline: max(b.updated_at)
        }
      )
      |> Repo.one()

    categories =
      from(b in Baseline,
        where: b.agent_id == ^agent_id,
        group_by: b.category,
        select: {b.category, count(b.id)}
      )
      |> Repo.all()
      |> Map.new()

    result = Map.put(stats || %{}, :categories, categories)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:upsert_policy, attrs}, _from, state) do
    result = case attrs[:id] do
      nil ->
        %Policy{}
        |> Policy.changeset(attrs)
        |> Repo.insert()

      id ->
        case Repo.get(Policy, id) do
          nil ->
            %Policy{}
            |> Policy.changeset(Map.put(attrs, :id, id))
            |> Repo.insert()

          existing ->
            existing
            |> Policy.changeset(attrs)
            |> Repo.update()
        end
    end

    case result do
      {:ok, policy} ->
        # Sync to affected agents
        sync_policy_to_agents(policy)
        {:reply, {:ok, policy}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:delete_policy, policy_id}, _from, state) do
    case Repo.get(Policy, policy_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      policy ->
        agent_id = policy.agent_id
        result = Repo.delete(policy)
        case result do
          {:ok, _} ->
            # Re-sync to affected agents
            if agent_id == "*" do
              sync_all_agents()
            else
              sync_policies_to_agent(agent_id)
            end
            {:reply, :ok, state}
          error ->
            {:reply, error, state}
        end
    end
  end

  @impl true
  def handle_call({:get_policies, agent_id}, _from, state) do
    policies = Policy.policies_for_agent(agent_id) |> Repo.all()
    {:reply, {:ok, policies}, state}
  end

  @impl true
  def handle_cast({:sync_policies, agent_id}, state) do
    policies = Policy.policies_for_agent(agent_id) |> Repo.all()
    policy_data = Enum.map(policies, &Policy.to_agent_format/1)

    # Send via agent channel
    case TamanduaServer.Agents.Registry.lookup(agent_id) do
      {:ok, pid} ->
        send(pid, {:push_config, %{type: "fim_policies", policies: policy_data}})
        Logger.info("Synced #{length(policies)} FIM policies to agent #{agent_id}")
      _ ->
        Logger.debug("Agent #{agent_id} not connected, skipping policy sync")
    end

    {:noreply, state}
  end

  @impl true
  def handle_cast({:record_change, agent_id, change_data}, state) do
    # Check if whitelisted
    whitelisted =
      is_whitelisted?(
        agent_id,
        change_data["path"],
        change_data["change_type"]
      )

    # Determine severity
    severity =
      determine_severity(
        change_data["change_type"],
        change_data["category"],
        whitelisted
      )

    # Record change
    %Change{}
    |> Change.changeset(%{
      agent_id: agent_id,
      path: change_data["path"],
      change_type: change_data["change_type"],
      previous_hash: change_data["previous_hash"],
      current_hash: change_data["current_hash"],
      previous_size: change_data["previous_size"],
      current_size: change_data["current_size"],
      previous_permissions: change_data["previous_permissions"],
      current_permissions: change_data["current_permissions"],
      previous_owner: change_data["previous_owner"],
      current_owner: change_data["current_owner"],
      category: change_data["category"],
      compliance_impact: change_data["compliance_impact"] || [],
      whitelisted: whitelisted,
      whitelist_reason: change_data["whitelist_reason"],
      modifier_pid: change_data["modifier_pid"],
      modifier_process: change_data["modifier_process"],
      entropy: change_data["entropy"],
      severity: severity,
      detected_at: DateTime.utc_now()
    })
    |> Repo.insert()
    |> case do
      {:ok, change} ->
        Logger.info("FIM change recorded: #{change.path} (#{change.change_type})")

        # If critical and not whitelisted, trigger alert and check for remediation
        if severity in ["critical", "high"] and not whitelisted do
          trigger_fim_alert(agent_id, change)
          maybe_trigger_fim_remediation(agent_id, change)
        end

        # Broadcast to dashboard
        Phoenix.PubSub.broadcast(
          TamanduaServer.PubSub,
          "fim:changes",
          {:new_fim_change, change}
        )

      {:error, changeset} ->
        Logger.error("Failed to record FIM change: #{inspect(changeset)}")
    end

    {:noreply, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp record_baseline_history(baseline) do
    %BaselineHistory{}
    |> BaselineHistory.changeset(%{
      baseline_id: baseline.id,
      agent_id: baseline.agent_id,
      path: baseline.path,
      hash: baseline.hash,
      size: baseline.size,
      permissions: baseline.permissions,
      owner: baseline.owner,
      group: baseline.group,
      mtime: baseline.mtime,
      ctime: baseline.ctime,
      attributes: baseline.attributes,
      baseline_version: baseline.baseline_version,
      archived_at: DateTime.utc_now()
    })
    |> Repo.insert()
  end

  defp path_matches_pattern?(path, pattern) do
    # Simple glob pattern matching
    cond do
      String.contains?(pattern, "*") ->
        parts = String.split(pattern, "*", parts: 2)

        case parts do
          [prefix, suffix] ->
            String.starts_with?(path, prefix) and String.ends_with?(path, suffix)

          [prefix] ->
            if String.starts_with?(pattern, "*") do
              String.ends_with?(path, prefix)
            else
              String.starts_with?(path, prefix)
            end

          _ ->
            false
        end

      true ->
        path == pattern
    end
  end

  defp determine_severity(change_type, category, whitelisted) do
    if whitelisted do
      "info"
    else
      case {change_type, category} do
        {"content_modified", "security"} -> "critical"
        {"deleted", "security"} -> "critical"
        {"content_modified", "boot"} -> "critical"
        {"deleted", "boot"} -> "critical"
        {"content_modified", "system"} -> "high"
        {"deleted", "system"} -> "high"
        {"permissions_changed", "system"} -> "high"
        {"content_modified", "config"} -> "medium"
        {"permissions_changed", "config"} -> "medium"
        {"ownership_changed", "config"} -> "medium"
        {"created", _} -> "low"
        {"baseline_established", _} -> "info"
        _ -> "medium"
      end
    end
  end

  defp build_compliance_report(agent_id, framework) do
    baselines =
      from(b in Baseline,
        where: b.agent_id == ^agent_id,
        where: fragment("? @> ARRAY[?]::varchar[]", b.compliance_frameworks, ^framework)
      )
      |> Repo.all()

    changes =
      from(c in Change,
        where: c.agent_id == ^agent_id,
        where: fragment("? @> ARRAY[?]::varchar[]", c.compliance_impact, ^framework),
        where: c.detected_at >= ago(30, "day"),
        where: not c.whitelisted
      )
      |> Repo.all()

    %{
      framework: framework,
      generated_at: DateTime.utc_now(),
      total_monitored_files: length(baselines),
      compliant_files: length(baselines) - length(changes),
      non_compliant_files: length(changes),
      recent_changes: length(changes),
      critical_changes: Enum.count(changes, &(&1.severity == "critical")),
      high_severity_changes: Enum.count(changes, &(&1.severity == "high")),
      status:
        if length(changes) == 0 do
          "compliant"
        else
          if Enum.any?(changes, &(&1.severity in ["critical", "high"])) do
            "non_compliant"
          else
            "needs_review"
          end
        end
    }
  end

  defp trigger_fim_alert(agent_id, change) do
    # Create an alert for critical FIM violations
    alert_data = %{
      agent_id: agent_id,
      alert_type: "file_integrity_violation",
      severity: change.severity,
      title: "File Integrity Violation: #{change.change_type}",
      description: """
      File integrity change detected on monitored file:

      Path: #{change.path}
      Change Type: #{change.change_type}
      Category: #{change.category}
      Compliance Impact: #{Enum.join(change.compliance_impact, ", ")}

      Previous Hash: #{change.previous_hash}
      Current Hash: #{change.current_hash}
      """,
      metadata: %{
        fim_change_id: change.id,
        path: change.path,
        change_type: change.change_type,
        category: change.category,
        modifier_process: change.modifier_process,
        modifier_pid: change.modifier_pid
      },
      mitre_tactics: ["persistence", "defense_evasion"],
      mitre_techniques: ["T1565", "T1565.001"]
    }

    # Use the alerts module to create alert
    case TamanduaServer.Alerts.create_alert(alert_data) do
      {:ok, alert} ->
        Logger.info("FIM alert created: #{alert.id}")

      {:error, reason} ->
        Logger.error("Failed to create FIM alert: #{inspect(reason)}")
    end
  end

  # Check if FIM change should trigger remediation workflow based on policy
  defp maybe_trigger_fim_remediation(agent_id, change) do
    case find_matching_policy(agent_id, change.path, change.severity) do
      %Policy{action: "block", auto_response: "quarantine"} = policy ->
        create_fim_remediation_workflow(change, policy, "quarantine")

      %Policy{action: "block", auto_response: "notify"} = policy ->
        create_fim_remediation_workflow(change, policy, "notify")

      %Policy{action: "alert"} = policy ->
        # Alert already generated, log for audit
        Logger.info("FIM alert for #{change.path} - policy: #{policy.id}")
        :ok

      _ ->
        # No policy match or allow action
        :ok
    end
  end

  defp find_matching_policy(agent_id, path, severity) do
    Policy.policies_for_agent(agent_id)
    |> Repo.all()
    |> Enum.find(fn policy ->
      pattern_matches_path?(policy.pattern, path) &&
        severity_meets_threshold?(severity, policy.severity_threshold)
    end)
  end

  defp pattern_matches_path?(pattern, path) do
    cond do
      String.contains?(pattern, "*") ->
        regex = pattern
          |> String.replace(".", "\\.")
          |> String.replace("*", ".*")
        case Regex.compile(regex) do
          {:ok, re} -> Regex.match?(re, path)
          _ -> false
        end

      true ->
        String.starts_with?(path, pattern) || path == pattern
    end
  end

  defp severity_meets_threshold?(actual, nil), do: true
  defp severity_meets_threshold?(actual, threshold) do
    order = %{"info" => 0, "low" => 1, "medium" => 2, "high" => 3, "critical" => 4}
    Map.get(order, actual, 0) >= Map.get(order, threshold, 0)
  end

  defp create_fim_remediation_workflow(change, policy, action_type) do
    alias TamanduaServer.Remediation.Workflow

    Workflow.create_workflow(%{
      execution_mode: if(action_type == "quarantine", do: "auto", else: "pending_approval"),
      action_type: "fim_#{action_type}",
      action_config: %{
        agent_id: change.agent_id,
        path: change.path,
        change_id: change.id,
        policy_id: policy.id,
        reason: "FIM policy violation: #{policy.reason}"
      }
    })
  end

  # Sync policy to affected agents
  defp sync_policy_to_agents(%Policy{agent_id: "*"} = _policy) do
    # Global policy - sync to all connected agents
    sync_all_agents()
  end

  defp sync_policy_to_agents(%Policy{agent_id: agent_id}) do
    sync_policies_to_agent(agent_id)
  end

  # Sync policies to all connected agents
  defp sync_all_agents do
    case TamanduaServer.Agents.Registry.list_agents() do
      agents when is_list(agents) ->
        for {agent_id, _pid} <- agents do
          sync_policies_to_agent(agent_id)
        end
      _ ->
        Logger.debug("No agents connected for policy sync")
    end
  end
end
