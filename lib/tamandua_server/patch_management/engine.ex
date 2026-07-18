defmodule TamanduaServer.PatchManagement.Engine do
  @moduledoc """
  Patch Management Engine for Tamandua EDR.

  Orchestrates patch deployment across managed endpoints with risk-based
  prioritization, canary rollouts, maintenance windows, and automatic rollback.

  ## Architecture

  1. **Scan Phase** - Agents report missing patches via `PatchStatus` telemetry
  2. **Prioritize** - Risk score = EPSS x asset_criticality x exploit_availability
  3. **Approve** - Auto-approve per policy or queue for manual review
  4. **Deploy** - Canary group first, then production in severity waves
  5. **Monitor** - Watch for BSOD, service failures, application breakage
  6. **Verify** - Confirm patches installed, update compliance state
  7. **Report** - Per-org patch compliance dashboard and audit trail

  ## Integration

  - Reads CVE/EPSS/KEV data from `TamanduaServer.Vulnerability.*`
  - Sends patch commands to agents via `Agents.CommandManager` (persistent
    queue -> agent worker -> channel push, same path as breadcrumb deploys)
  - Alerts generated through `TamanduaServer.Alerts`
  - Multi-tenant: all operations scoped to `org_id`

  ## Patch Policy

  Each organization can define policies controlling:
  - Auto-approval thresholds by severity
  - Maintenance windows (day-of-week + hour range)
  - Maximum concurrent patching agents
  - Reboot behaviour
  - KB exclusions
  - Canary (test) group
  """

  use GenServer
  require Logger

  alias TamanduaServer.Agents.CommandManager
  alias TamanduaServer.Repo
  alias TamanduaServer.Vulnerability.{CVE, EPSS}

  import Ecto.Query

  # ETS tables
  @ets_policies :patch_policies
  @ets_deployments :patch_deployments
  @ets_agent_status :patch_agent_status
  @ets_compliance :patch_compliance

  # Deployment wave ordering
  @severity_waves [:critical, :high, :medium, :low]

  # Monitoring window after canary deployment (minutes)
  @canary_soak_minutes 30

  # Default scan interval
  @scan_interval :timer.hours(4)

  # Maximum history entries per org

  # ============================================================================
  # Type Definitions
  # ============================================================================

  @type reboot_policy :: :immediate | :deferred | :user_choice | :never
  @type auto_approve :: :critical | :high | :medium | :none

  @type maintenance_window :: %{
          day: 0..6,
          start_hour: 0..23,
          end_hour: 0..23
        }

  @type patch_policy :: %{
          id: String.t(),
          name: String.t(),
          org_id: String.t(),
          auto_approve_severity: auto_approve(),
          maintenance_windows: [maintenance_window()],
          max_concurrent_agents: pos_integer(),
          reboot_policy: reboot_policy(),
          rollback_on_failure: boolean(),
          exclude_kbs: [String.t()],
          test_group_ids: [String.t()],
          enabled: boolean(),
          created_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  @type patch_info :: %{
          kb_id: String.t(),
          title: String.t(),
          severity: String.t(),
          cve_ids: [String.t()],
          size_bytes: non_neg_integer(),
          requires_reboot: boolean(),
          release_date: Date.t() | nil
        }

  @type deployment :: %{
          id: String.t(),
          org_id: String.t(),
          policy_id: String.t(),
          status: String.t(),
          wave: atom(),
          patches: [patch_info()],
          target_agents: [String.t()],
          completed_agents: [String.t()],
          failed_agents: [String.t()],
          canary_agents: [String.t()],
          canary_passed: boolean(),
          created_at: DateTime.t(),
          started_at: DateTime.t() | nil,
          completed_at: DateTime.t() | nil,
          error_log: [map()]
        }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Create or update a patch policy for an organization.
  """
  @spec upsert_policy(map()) :: {:ok, patch_policy()} | {:error, term()}
  def upsert_policy(attrs) do
    GenServer.call(__MODULE__, {:upsert_policy, attrs})
  end

  @doc """
  Get a patch policy by ID.
  """
  @spec get_policy(String.t()) :: {:ok, patch_policy()} | {:error, :not_found}
  def get_policy(policy_id) do
    GenServer.call(__MODULE__, {:get_policy, policy_id})
  end

  @doc """
  List all patch policies for an organization.
  """
  @spec list_policies(String.t()) :: [patch_policy()]
  def list_policies(org_id) do
    GenServer.call(__MODULE__, {:list_policies, org_id})
  end

  @doc """
  Delete a patch policy.
  """
  @spec delete_policy(String.t()) :: :ok | {:error, :not_found}
  def delete_policy(policy_id) do
    GenServer.call(__MODULE__, {:delete_policy, policy_id})
  end

  @doc """
  Report patch status from an agent. Called when agent telemetry arrives
  with a `patch_status` event payload.
  """
  @spec report_agent_patch_status(String.t(), String.t(), map()) :: :ok
  def report_agent_patch_status(agent_id, org_id, status) do
    GenServer.cast(__MODULE__, {:agent_patch_status, agent_id, org_id, status})
  end

  @doc """
  Trigger a patch scan for an organization. Identifies missing patches
  across all agents and creates a prioritized deployment plan.
  """
  @spec trigger_scan(String.t()) :: {:ok, map()} | {:error, term()}
  def trigger_scan(org_id) do
    GenServer.call(__MODULE__, {:trigger_scan, org_id}, 60_000)
  end

  @doc """
  Approve a pending deployment (for manual-approval policies).
  """
  @spec approve_deployment(String.t()) :: :ok | {:error, term()}
  def approve_deployment(deployment_id) do
    GenServer.call(__MODULE__, {:approve_deployment, deployment_id})
  end

  @doc """
  Reject a pending deployment.
  """
  @spec reject_deployment(String.t(), String.t()) :: :ok | {:error, term()}
  def reject_deployment(deployment_id, reason) do
    GenServer.call(__MODULE__, {:reject_deployment, deployment_id, reason})
  end

  @doc """
  Report deployment result from an agent (success or failure).
  """
  @spec report_deployment_result(String.t(), String.t(), map()) :: :ok
  def report_deployment_result(deployment_id, agent_id, result) do
    GenServer.cast(__MODULE__, {:deployment_result, deployment_id, agent_id, result})
  end

  @doc """
  Rollback a deployment (abort remaining agents, rollback if possible).
  """
  @spec rollback_deployment(String.t(), String.t()) :: :ok | {:error, term()}
  def rollback_deployment(deployment_id, reason) do
    GenServer.call(__MODULE__, {:rollback_deployment, deployment_id, reason})
  end

  @doc """
  Get compliance summary for an organization.
  Returns patch coverage percentages by severity.
  """
  @spec get_compliance(String.t()) :: map()
  def get_compliance(org_id) do
    GenServer.call(__MODULE__, {:get_compliance, org_id})
  end

  @doc """
  Get deployment status.
  """
  @spec get_deployment(String.t()) :: {:ok, deployment()} | {:error, :not_found}
  def get_deployment(deployment_id) do
    GenServer.call(__MODULE__, {:get_deployment, deployment_id})
  end

  @doc """
  List deployments for an organization.
  """
  @spec list_deployments(String.t(), keyword()) :: [deployment()]
  def list_deployments(org_id, opts \\ []) do
    GenServer.call(__MODULE__, {:list_deployments, org_id, opts})
  end

  @doc """
  Get engine statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(_opts) do
    :ets.new(@ets_policies, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_deployments, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_agent_status, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_compliance, [:named_table, :set, :public, read_concurrency: true])

    state = %{
      stats: %{
        scans_run: 0,
        deployments_created: 0,
        deployments_completed: 0,
        deployments_failed: 0,
        deployments_rolled_back: 0,
        patches_installed: 0,
        patches_failed: 0
      },
      scan_timer: nil
    }

    # Load policies from database
    load_policies_from_db()

    # Schedule periodic scanning
    timer_ref = schedule_periodic_scan()

    Logger.info("[PatchManagement] Engine initialized")
    {:ok, %{state | scan_timer: timer_ref}}
  end

  # -- Policy management ---------------------------------------------------

  @impl true
  def handle_call({:upsert_policy, attrs}, _from, state) do
    policy = build_policy(attrs)
    :ets.insert(@ets_policies, {policy.id, policy})
    persist_policy(policy)
    {:reply, {:ok, policy}, state}
  end

  @impl true
  def handle_call({:get_policy, policy_id}, _from, state) do
    case :ets.lookup(@ets_policies, policy_id) do
      [{^policy_id, policy}] -> {:reply, {:ok, policy}, state}
      [] -> {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:list_policies, org_id}, _from, state) do
    policies =
      :ets.tab2list(@ets_policies)
      |> Enum.map(fn {_id, p} -> p end)
      |> Enum.filter(&(&1.org_id == org_id))
      |> Enum.sort_by(& &1.name)

    {:reply, policies, state}
  end

  @impl true
  def handle_call({:delete_policy, policy_id}, _from, state) do
    case :ets.lookup(@ets_policies, policy_id) do
      [{^policy_id, _policy}] ->
        :ets.delete(@ets_policies, policy_id)
        delete_policy_from_db(policy_id)
        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  # -- Scanning & deployment -----------------------------------------------

  @impl true
  def handle_call({:trigger_scan, org_id}, _from, state) do
    result = do_scan(org_id)
    new_stats = %{state.stats | scans_run: state.stats.scans_run + 1}
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:approve_deployment, deployment_id}, _from, state) do
    case get_deployment_from_ets(deployment_id) do
      {:ok, deployment} when deployment.status == "pending_approval" ->
        updated = %{deployment | status: "approved"}
        :ets.insert(@ets_deployments, {deployment_id, updated})
        schedule_deployment(updated)
        {:reply, :ok, state}

      {:ok, _} ->
        {:reply, {:error, :invalid_status}, state}

      {:error, _} = err ->
        {:reply, err, state}
    end
  end

  @impl true
  def handle_call({:reject_deployment, deployment_id, reason}, _from, state) do
    case get_deployment_from_ets(deployment_id) do
      {:ok, deployment} when deployment.status == "pending_approval" ->
        updated = %{deployment | status: "rejected", error_log: [{DateTime.utc_now(), reason} | deployment.error_log]}
        :ets.insert(@ets_deployments, {deployment_id, updated})
        {:reply, :ok, state}

      {:ok, _} ->
        {:reply, {:error, :invalid_status}, state}

      {:error, _} = err ->
        {:reply, err, state}
    end
  end

  @impl true
  def handle_call({:rollback_deployment, deployment_id, reason}, _from, state) do
    case get_deployment_from_ets(deployment_id) do
      {:ok, deployment} when deployment.status in ["in_progress", "canary"] ->
        do_rollback(deployment, reason)
        new_stats = %{state.stats | deployments_rolled_back: state.stats.deployments_rolled_back + 1}
        {:reply, :ok, %{state | stats: new_stats}}

      {:ok, _} ->
        {:reply, {:error, :cannot_rollback}, state}

      {:error, _} = err ->
        {:reply, err, state}
    end
  end

  # -- Queries -------------------------------------------------------------

  @impl true
  def handle_call({:get_compliance, org_id}, _from, state) do
    compliance = calculate_compliance(org_id)
    {:reply, compliance, state}
  end

  @impl true
  def handle_call({:get_deployment, deployment_id}, _from, state) do
    {:reply, get_deployment_from_ets(deployment_id), state}
  end

  @impl true
  def handle_call({:list_deployments, org_id, opts}, _from, state) do
    status_filter = Keyword.get(opts, :status)
    limit = Keyword.get(opts, :limit, 50)

    deployments =
      :ets.tab2list(@ets_deployments)
      |> Enum.map(fn {_id, d} -> d end)
      |> Enum.filter(&(&1.org_id == org_id))
      |> then(fn ds ->
        if status_filter, do: Enum.filter(ds, &(&1.status == status_filter)), else: ds
      end)
      |> Enum.sort_by(& &1.created_at, {:desc, DateTime})
      |> Enum.take(limit)

    {:reply, deployments, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  # -- Agent status reports ------------------------------------------------

  @impl true
  def handle_cast({:agent_patch_status, agent_id, org_id, status}, state) do
    entry = %{
      agent_id: agent_id,
      org_id: org_id,
      installed_patches: Map.get(status, "installed_patches", []),
      missing_patches: Map.get(status, "missing_patches", []),
      pending_reboot: Map.get(status, "pending_reboot", false),
      last_scan: DateTime.utc_now()
    }

    :ets.insert(@ets_agent_status, {agent_id, entry})
    update_compliance_cache(org_id)

    {:noreply, state}
  end

  @impl true
  def handle_cast({:deployment_result, deployment_id, agent_id, result}, state) do
    case get_deployment_from_ets(deployment_id) do
      {:ok, deployment} ->
        {updated_deployment, new_stats} = process_deployment_result(deployment, agent_id, result, state.stats)
        :ets.insert(@ets_deployments, {deployment_id, updated_deployment})
        persist_deployment(updated_deployment)
        {:noreply, %{state | stats: new_stats}}

      {:error, _} ->
        {:noreply, state}
    end
  end

  # -- Periodic scan -------------------------------------------------------

  @impl true
  def handle_info(:periodic_scan, state) do
    # Scan all organizations
    orgs = get_all_org_ids()

    Enum.each(orgs, fn org_id ->
      try do
        do_scan(org_id)
      rescue
        e -> Logger.error("[PatchManagement] Scan failed for org #{org_id}: #{Exception.message(e)}")
      end
    end)

    timer_ref = schedule_periodic_scan()
    new_stats = %{state.stats | scans_run: state.stats.scans_run + length(orgs)}
    {:noreply, %{state | scan_timer: timer_ref, stats: new_stats}}
  end

  @impl true
  def handle_info({:start_deployment, deployment_id}, state) do
    case get_deployment_from_ets(deployment_id) do
      {:ok, deployment} when deployment.status == "approved" ->
        do_start_deployment(deployment)
        new_stats = %{state.stats | deployments_created: state.stats.deployments_created + 1}
        {:noreply, %{state | stats: new_stats}}

      _ ->
        {:noreply, state}
    end
  end

  @impl true
  def handle_info({:canary_check, deployment_id}, state) do
    case get_deployment_from_ets(deployment_id) do
      {:ok, deployment} when deployment.status == "canary" ->
        check_canary_result(deployment)

      _ ->
        :ok
    end

    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ============================================================================
  # Private - Scanning & Prioritization
  # ============================================================================

  defp do_scan(org_id) do
    Logger.info("[PatchManagement] Starting patch scan for org #{org_id}")

    # Gather all agent patch statuses for this org
    agent_statuses =
      :ets.tab2list(@ets_agent_status)
      |> Enum.map(fn {_id, s} -> s end)
      |> Enum.filter(&(&1.org_id == org_id))

    if agent_statuses == [] do
      {:ok, %{org_id: org_id, agents_scanned: 0, missing_patches: 0, deployments: 0}}
    else
      # Collect all missing patches across agents
      all_missing =
        agent_statuses
        |> Enum.flat_map(fn s -> Enum.map(s.missing_patches, &Map.put(&1, "agent_id", s.agent_id)) end)

      # Group by KB/patch ID
      grouped = Enum.group_by(all_missing, & &1["kb_id"])

      # Prioritize using risk scoring
      prioritized = prioritize_patches(grouped, org_id)

      # Get applicable policies
      policies = list_org_policies(org_id)

      # Create deployments per wave
      deployments =
        Enum.flat_map(@severity_waves, fn wave ->
          wave_patches = Enum.filter(prioritized, fn {_kb, info} -> info.severity == Atom.to_string(wave) end)

          if wave_patches != [] do
            create_wave_deployment(org_id, wave, wave_patches, policies)
          else
            []
          end
        end)

      Logger.info("[PatchManagement] Scan complete for org #{org_id}: #{length(deployments)} deployments created")

      {:ok, %{
        org_id: org_id,
        agents_scanned: length(agent_statuses),
        missing_patches: map_size(grouped),
        deployments: length(deployments)
      }}
    end
  rescue
    e ->
      Logger.error("[PatchManagement] Scan error: #{Exception.message(e)}")
      {:error, Exception.message(e)}
  end

  defp prioritize_patches(grouped_patches, org_id) do
    Enum.map(grouped_patches, fn {kb_id, patches} ->
      # Look up CVEs for this patch
      cve_ids = patches |> Enum.flat_map(&(Map.get(&1, "cve_ids", []))) |> Enum.uniq()

      # Get EPSS scores for CVEs
      epss_score = get_max_epss_score(cve_ids)

      # Check KEV status
      in_kev = check_kev_status(cve_ids)

      # Get asset criticality for affected agents
      agent_ids = Enum.map(patches, & &1["agent_id"]) |> Enum.uniq()
      asset_criticality = get_max_asset_criticality(agent_ids, org_id)

      # Calculate composite risk score
      # Risk = EPSS * asset_criticality * exploit_availability_multiplier
      exploit_multiplier = if in_kev, do: 2.0, else: 1.0
      risk_score = (epss_score || 0.5) * (asset_criticality / 100.0) * exploit_multiplier

      severity = determine_severity(risk_score, epss_score, in_kev)

      patch_info = %{
        kb_id: kb_id,
        title: List.first(patches)["title"] || kb_id,
        severity: severity,
        cve_ids: cve_ids,
        risk_score: Float.round(risk_score, 4),
        epss_score: epss_score,
        in_kev: in_kev,
        agent_ids: agent_ids,
        requires_reboot: Enum.any?(patches, &Map.get(&1, "requires_reboot", false)),
        size_bytes: List.first(patches)["size_bytes"] || 0,
        release_date: List.first(patches)["release_date"]
      }

      {kb_id, patch_info}
    end)
    |> Enum.sort_by(fn {_kb, info} -> -info.risk_score end)
  end

  defp get_max_epss_score([]), do: nil
  defp get_max_epss_score(cve_ids) do
    try do
      case EPSS.get_scores(cve_ids) do
        {:ok, scores} ->
          scores
          |> Enum.map(& &1[:epss])
          |> Enum.reject(&is_nil/1)
          |> Enum.max(fn -> nil end)

        _ ->
          nil
      end
    rescue
      _ -> nil
    end
  end

  defp check_kev_status([]), do: false
  defp check_kev_status(cve_ids) do
    try do
      Repo.exists?(
        from(c in CVE,
          where: c.cve_id in ^cve_ids and c.in_kev == true
        )
      )
    rescue
      _ -> false
    end
  end

  defp get_max_asset_criticality(agent_ids, _org_id) do
    # `Assets.Criticality` assessments carry a 0-100 `score`; 50 is that
    # module's "unknown agent" neutral default, reused here when the batch is
    # empty or the criticality service is unavailable. GenServer.call failure
    # is an exit, not a raise, so we catch :exit in addition to rescue.
    try do
      case TamanduaServer.Assets.Criticality.get_criticality_for_agents(agent_ids) do
        assessments when is_list(assessments) ->
          assessments
          |> Enum.map(& &1.score)
          |> Enum.max(fn -> 50 end)

        _ ->
          50
      end
    rescue
      _ -> 50
    catch
      :exit, _ -> 50
    end
  end

  defp determine_severity(risk_score, epss_score, in_kev) do
    cond do
      in_kev -> "critical"
      risk_score >= 0.7 -> "critical"
      (epss_score || 0) >= 0.5 -> "critical"
      risk_score >= 0.4 -> "high"
      risk_score >= 0.2 -> "medium"
      true -> "low"
    end
  end

  # ============================================================================
  # Private - Deployment Creation & Execution
  # ============================================================================

  defp create_wave_deployment(org_id, wave, wave_patches, policies) do
    policy = find_applicable_policy(policies, wave)

    # Check auto-approve
    auto_approved = should_auto_approve?(policy, wave)

    # Filter out excluded KBs
    excluded_kbs = (policy && policy.exclude_kbs) || []
    filtered_patches =
      wave_patches
      |> Enum.reject(fn {kb_id, _info} -> kb_id in excluded_kbs end)

    if filtered_patches == [] do
      []
    else
      all_agent_ids =
        filtered_patches
        |> Enum.flat_map(fn {_kb, info} -> info.agent_ids end)
        |> Enum.uniq()

      # Separate canary agents
      test_group_ids = (policy && policy.test_group_ids) || []
      {canary_agents, prod_agents} =
        Enum.split_with(all_agent_ids, fn aid -> aid in test_group_ids end)

      deployment = %{
        id: Ecto.UUID.generate(),
        org_id: org_id,
        policy_id: policy && policy.id,
        status: if(auto_approved, do: "approved", else: "pending_approval"),
        wave: wave,
        patches: Enum.map(filtered_patches, fn {_kb, info} -> info end),
        target_agents: prod_agents,
        completed_agents: [],
        failed_agents: [],
        canary_agents: canary_agents,
        canary_passed: false,
        max_concurrent: (policy && policy.max_concurrent_agents) || 10,
        reboot_policy: (policy && policy.reboot_policy) || :deferred,
        rollback_on_failure: (policy && policy.rollback_on_failure) || true,
        maintenance_windows: (policy && policy.maintenance_windows) || [],
        created_at: DateTime.utc_now(),
        started_at: nil,
        completed_at: nil,
        error_log: []
      }

      :ets.insert(@ets_deployments, {deployment.id, deployment})
      persist_deployment(deployment)

      # If auto-approved, schedule for deployment
      if auto_approved do
        schedule_deployment(deployment)
      end

      [deployment]
    end
  end

  defp find_applicable_policy(policies, _wave) do
    # Use the first enabled policy (could be more sophisticated)
    Enum.find(policies, &(&1.enabled))
  end

  defp should_auto_approve?(nil, _wave), do: false
  defp should_auto_approve?(policy, wave) do
    case policy.auto_approve_severity do
      :critical -> wave == :critical
      :high -> wave in [:critical, :high]
      :medium -> wave in [:critical, :high, :medium]
      :none -> false
      _ -> false
    end
  end

  defp schedule_deployment(deployment) do
    # Check if we are within a maintenance window
    if in_maintenance_window?(deployment.maintenance_windows) do
      send(self(), {:start_deployment, deployment.id})
    else
      # Calculate delay until next maintenance window
      delay = time_until_next_window(deployment.maintenance_windows)
      if delay > 0 do
        Process.send_after(self(), {:start_deployment, deployment.id}, delay)
      else
        # No windows configured; deploy immediately
        send(self(), {:start_deployment, deployment.id})
      end
    end
  end

  defp do_start_deployment(deployment) do
    Logger.info("[PatchManagement] Starting deployment #{deployment.id} (wave=#{deployment.wave})")

    updated =
      if deployment.canary_agents != [] do
        # Start with canary group
        dispatch_patches(deployment.canary_agents, deployment)

        %{deployment |
          status: "canary",
          started_at: DateTime.utc_now()
        }
      else
        # No canary group; go straight to production
        dispatch_patches_in_waves(deployment)

        %{deployment |
          status: "in_progress",
          started_at: DateTime.utc_now()
        }
      end

    :ets.insert(@ets_deployments, {deployment.id, updated})
    persist_deployment(updated)

    # Schedule canary check if applicable
    if updated.status == "canary" do
      Process.send_after(self(), {:canary_check, deployment.id}, @canary_soak_minutes * 60_000)
    end
  end

  defp dispatch_patches(agent_ids, deployment) do
    # Dispatch via CommandManager (Postgres queue -> Agents.Worker ->
    # channel push). The previous Phoenix.PubSub broadcast of a raw
    # {:command, ...} tuple on "agent:<id>" was a runtime no-op: no
    # handle_info({:command, ...}) exists anywhere in the server, so the
    # message fell into AgentChannel's silent catch-all.
    #
    # Payload shape matches the Rust agent contract for install_patches
    # (apps/tamandua_agent/src/response/patch_manager.rs, handle_install_patches):
    # deployment_id, patches[].kb_id, reboot_policy.
    patch_command = %{
      deployment_id: deployment.id,
      patches: Enum.map(deployment.patches, fn p ->
        %{
          kb_id: p.kb_id,
          title: p.title,
          severity: p.severity,
          requires_reboot: p.requires_reboot
        }
      end),
      reboot_policy: Atom.to_string(deployment.reboot_policy)
    }

    Enum.each(agent_ids, fn agent_id ->
      case CommandManager.queue_command(agent_id, :install_patches, patch_command, priority: 3) do
        {:ok, _command} ->
          :ok

        {:error, reason} ->
          Logger.warning(
            "[PatchManagement] Failed to queue install_patches for agent #{agent_id} " <>
              "(deployment #{deployment.id}): #{inspect(reason)}"
          )
      end
    end)
  end

  defp dispatch_patches_in_waves(deployment) do
    # Dispatch in batches respecting max_concurrent
    deployment.target_agents
    |> Enum.chunk_every(deployment.max_concurrent)
    |> Enum.with_index()
    |> Enum.each(fn {batch, idx} ->
      # Stagger batches by 5 minutes each
      delay = idx * 5 * 60_000

      if delay == 0 do
        dispatch_patches(batch, deployment)
      else
        Task.start(fn ->
          Process.sleep(delay)
          dispatch_patches(batch, deployment)
        end)
      end
    end)
  end

  defp check_canary_result(deployment) do
    canary_count = length(deployment.canary_agents)
    canary_completed = Enum.count(deployment.canary_agents, &(&1 in deployment.completed_agents))
    canary_failed = Enum.count(deployment.canary_agents, &(&1 in deployment.failed_agents))

    cond do
      canary_failed > 0 ->
        # Canary failed: rollback
        Logger.warning("[PatchManagement] Canary failed for deployment #{deployment.id}")
        do_rollback(deployment, "Canary deployment failed: #{canary_failed}/#{canary_count} agents failed")

      canary_completed == canary_count ->
        # All canary agents succeeded: promote to production
        Logger.info("[PatchManagement] Canary passed for deployment #{deployment.id}, promoting to production")
        updated = %{deployment | status: "in_progress", canary_passed: true}
        :ets.insert(@ets_deployments, {deployment.id, updated})
        dispatch_patches_in_waves(updated)

      true ->
        # Still waiting; recheck in a few minutes
        Process.send_after(self(), {:canary_check, deployment.id}, 5 * 60_000)
    end
  end

  # ============================================================================
  # Private - Deployment Results
  # ============================================================================

  defp process_deployment_result(deployment, agent_id, result, stats) do
    success = Map.get(result, "success", false)

    updated =
      if success do
        %{deployment | completed_agents: Enum.uniq([agent_id | deployment.completed_agents])}
      else
        error_entry = %{
          agent_id: agent_id,
          error: Map.get(result, "error", "Unknown error"),
          timestamp: DateTime.utc_now()
        }

        %{deployment |
          failed_agents: Enum.uniq([agent_id | deployment.failed_agents]),
          error_log: [error_entry | deployment.error_log]
        }
      end

    new_stats =
      if success do
        %{stats | patches_installed: stats.patches_installed + length(deployment.patches)}
      else
        %{stats | patches_failed: stats.patches_failed + 1}
      end

    # Check if deployment is complete
    total = length(deployment.target_agents) + length(deployment.canary_agents)
    done = length(updated.completed_agents) + length(updated.failed_agents)

    updated =
      if done >= total do
        Logger.info("[PatchManagement] Deployment #{deployment.id} complete: #{length(updated.completed_agents)} succeeded, #{length(updated.failed_agents)} failed")

        _new_stats_completed = %{new_stats | deployments_completed: new_stats.deployments_completed + 1}

        # Check if failure threshold exceeded and rollback is enabled
        failure_rate = length(updated.failed_agents) / max(total, 1)
        if failure_rate > 0.2 and deployment.rollback_on_failure do
          do_rollback(updated, "Failure rate #{Float.round(failure_rate * 100, 1)}% exceeded 20% threshold")
          %{updated | status: "rolled_back", completed_at: DateTime.utc_now()}
        else
          %{updated | status: "completed", completed_at: DateTime.utc_now()}
        end
      else
        updated
      end

    # Check for high failure rate mid-deployment
    if not success and deployment.rollback_on_failure do
      failure_count = length(updated.failed_agents)

      if failure_count >= 3 and failure_count / max(done, 1) > 0.5 do
        do_rollback(updated, "High failure rate during deployment: #{failure_count} failures in #{done} attempts")
      end
    end

    {updated, new_stats}
  end

  # ============================================================================
  # Private - Rollback
  # ============================================================================

  defp do_rollback(deployment, reason) do
    Logger.warning("[PatchManagement] Rolling back deployment #{deployment.id}: #{reason}")

    updated = %{deployment |
      status: "rolled_back",
      completed_at: DateTime.utc_now(),
      error_log: [%{type: "rollback", reason: reason, timestamp: DateTime.utc_now()} | deployment.error_log]
    }

    :ets.insert(@ets_deployments, {deployment.id, updated})
    persist_deployment(updated)

    # Send rollback command to agents that received patches, via
    # CommandManager (the raw PubSub {:command, ...} broadcast this replaced
    # was silently dropped by AgentChannel's handle_info catch-all).
    # Payload matches the Rust agent contract for rollback_patches
    # (apps/tamandua_agent/src/response/mod.rs, CommandType::RollbackPatches):
    # patches is a flat list of kb_id strings.
    rollback_agents = deployment.completed_agents ++ deployment.canary_agents

    Enum.each(rollback_agents, fn agent_id ->
      rollback_payload = %{
        deployment_id: deployment.id,
        patches: Enum.map(deployment.patches, & &1.kb_id),
        reason: reason
      }

      case CommandManager.queue_command(agent_id, :rollback_patches, rollback_payload, priority: 5) do
        {:ok, _command} ->
          :ok

        {:error, queue_error} ->
          Logger.warning(
            "[PatchManagement] Failed to queue rollback_patches for agent #{agent_id} " <>
              "(deployment #{deployment.id}): #{inspect(queue_error)}"
          )
      end
    end)

    # Generate alert
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alerts:feed",
      {:patch_deployment_rollback, %{
        org_id: deployment.org_id,
        deployment_id: deployment.id,
        reason: reason,
        affected_agents: length(rollback_agents)
      }}
    )
  end

  # ============================================================================
  # Private - Compliance
  # ============================================================================

  defp calculate_compliance(org_id) do
    agents =
      :ets.tab2list(@ets_agent_status)
      |> Enum.map(fn {_id, s} -> s end)
      |> Enum.filter(&(&1.org_id == org_id))

    total_agents = length(agents)

    if total_agents == 0 do
      %{
        org_id: org_id,
        total_agents: 0,
        compliant_agents: 0,
        compliance_rate: 0.0,
        by_severity: %{},
        pending_reboots: 0,
        last_updated: DateTime.utc_now()
      }
    else
      fully_patched = Enum.count(agents, fn a -> a.missing_patches == [] end)
      pending_reboots = Enum.count(agents, fn a -> a.pending_reboot end)

      # Group missing patches by severity
      all_missing =
        agents
        |> Enum.flat_map(fn a -> a.missing_patches end)

      severity_counts =
        all_missing
        |> Enum.group_by(& &1["severity"])
        |> Enum.map(fn {sev, patches} -> {sev, length(patches)} end)
        |> Map.new()

      %{
        org_id: org_id,
        total_agents: total_agents,
        compliant_agents: fully_patched,
        compliance_rate: Float.round(fully_patched / total_agents * 100, 1),
        by_severity: severity_counts,
        total_missing: length(all_missing),
        pending_reboots: pending_reboots,
        last_updated: DateTime.utc_now()
      }
    end
  end

  defp update_compliance_cache(org_id) do
    compliance = calculate_compliance(org_id)
    :ets.insert(@ets_compliance, {org_id, compliance})
  end

  # ============================================================================
  # Private - Maintenance Windows
  # ============================================================================

  defp in_maintenance_window?([]), do: true
  defp in_maintenance_window?(windows) do
    now = DateTime.utc_now()
    day_of_week = Date.day_of_week(DateTime.to_date(now)) - 1
    hour = now.hour

    Enum.any?(windows, fn window ->
      window_day = Map.get(window, :day, Map.get(window, "day"))
      start_h = Map.get(window, :start_hour, Map.get(window, "start_hour"))
      end_h = Map.get(window, :end_hour, Map.get(window, "end_hour"))

      day_of_week == window_day and hour >= start_h and hour < end_h
    end)
  end

  defp time_until_next_window([]), do: 0
  defp time_until_next_window(windows) do
    now = DateTime.utc_now()
    current_day = Date.day_of_week(DateTime.to_date(now)) - 1

    # Find the next upcoming window
    windows
    |> Enum.map(fn window ->
      window_day = Map.get(window, :day, Map.get(window, "day", 0))
      start_h = Map.get(window, :start_hour, Map.get(window, "start_hour", 0))

      days_ahead =
        if window_day > current_day do
          window_day - current_day
        else
          if window_day == current_day and start_h > now.hour do
            0
          else
            7 - current_day + window_day
          end
        end

      target = DateTime.add(now, days_ahead * 86_400, :second)
      target = %{target | hour: start_h, minute: 0, second: 0}
      DateTime.diff(target, now, :millisecond)
    end)
    |> Enum.filter(&(&1 > 0))
    |> Enum.min(fn -> 0 end)
  end

  # ============================================================================
  # Private - Persistence
  # ============================================================================

  defp build_policy(attrs) do
    %{
      id: Map.get(attrs, :id, Map.get(attrs, "id", Ecto.UUID.generate())),
      name: Map.get(attrs, :name, Map.get(attrs, "name", "Default")),
      org_id: Map.get(attrs, :org_id, Map.get(attrs, "org_id")),
      auto_approve_severity: parse_auto_approve(Map.get(attrs, :auto_approve_severity, Map.get(attrs, "auto_approve_severity", :none))),
      maintenance_windows: Map.get(attrs, :maintenance_windows, Map.get(attrs, "maintenance_windows", [])),
      max_concurrent_agents: Map.get(attrs, :max_concurrent_agents, Map.get(attrs, "max_concurrent_agents", 10)),
      reboot_policy: parse_reboot_policy(Map.get(attrs, :reboot_policy, Map.get(attrs, "reboot_policy", :deferred))),
      rollback_on_failure: Map.get(attrs, :rollback_on_failure, Map.get(attrs, "rollback_on_failure", true)),
      exclude_kbs: Map.get(attrs, :exclude_kbs, Map.get(attrs, "exclude_kbs", [])),
      test_group_ids: Map.get(attrs, :test_group_ids, Map.get(attrs, "test_group_ids", [])),
      enabled: Map.get(attrs, :enabled, Map.get(attrs, "enabled", true)),
      created_at: DateTime.utc_now(),
      updated_at: DateTime.utc_now()
    }
  end

  defp parse_auto_approve(val) when val in [:critical, :high, :medium, :none], do: val
  defp parse_auto_approve("critical"), do: :critical
  defp parse_auto_approve("high"), do: :high
  defp parse_auto_approve("medium"), do: :medium
  defp parse_auto_approve(_), do: :none

  defp parse_reboot_policy(val) when val in [:immediate, :deferred, :user_choice, :never], do: val
  defp parse_reboot_policy("immediate"), do: :immediate
  defp parse_reboot_policy("deferred"), do: :deferred
  defp parse_reboot_policy("user_choice"), do: :user_choice
  defp parse_reboot_policy("never"), do: :never
  defp parse_reboot_policy(_), do: :deferred

  defp persist_policy(policy) do
    Task.start(fn ->
      try do
        attrs = %{
          id: policy.id,
          name: policy.name,
          org_id: policy.org_id,
          config: %{
            auto_approve_severity: Atom.to_string(policy.auto_approve_severity),
            maintenance_windows: policy.maintenance_windows,
            max_concurrent_agents: policy.max_concurrent_agents,
            reboot_policy: Atom.to_string(policy.reboot_policy),
            rollback_on_failure: policy.rollback_on_failure,
            exclude_kbs: policy.exclude_kbs,
            test_group_ids: policy.test_group_ids
          },
          enabled: policy.enabled
        }

        Repo.insert_all("patch_policies", [attrs],
          on_conflict: {:replace, [:name, :config, :enabled, :updated_at]},
          conflict_target: [:id]
        )
      rescue
        _ -> :ok
      end
    end)
  end

  defp persist_deployment(deployment) do
    Task.start(fn ->
      try do
        attrs = %{
          id: deployment.id,
          org_id: deployment.org_id,
          policy_id: deployment.policy_id,
          status: deployment.status,
          wave: Atom.to_string(deployment.wave),
          patches: deployment.patches,
          target_agent_ids: deployment.target_agents,
          completed_agent_ids: deployment.completed_agents,
          failed_agent_ids: deployment.failed_agents,
          canary_agent_ids: deployment.canary_agents,
          canary_passed: deployment.canary_passed,
          started_at: deployment.started_at,
          completed_at: deployment.completed_at,
          error_log: deployment.error_log
        }

        Repo.insert_all("patch_deployments", [Map.put(attrs, :inserted_at, DateTime.utc_now()) |> Map.put(:updated_at, DateTime.utc_now())],
          on_conflict: {:replace, [:status, :completed_agent_ids, :failed_agent_ids, :canary_passed, :started_at, :completed_at, :error_log, :updated_at]},
          conflict_target: [:id]
        )
      rescue
        _ -> :ok
      end
    end)
  end

  defp delete_policy_from_db(policy_id) do
    Task.start(fn ->
      try do
        Repo.delete_all(from(p in "patch_policies", where: p.id == ^policy_id))
      rescue
        _ -> :ok
      end
    end)
  end

  defp load_policies_from_db do
    try do
      policies = Repo.all(from(p in "patch_policies", select: %{
        id: p.id,
        name: p.name,
        org_id: p.org_id,
        config: p.config,
        enabled: p.enabled
      }))

      Enum.each(policies, fn row ->
        config = row.config || %{}
        policy = %{
          id: row.id,
          name: row.name,
          org_id: row.org_id,
          auto_approve_severity: parse_auto_approve(config["auto_approve_severity"]),
          maintenance_windows: config["maintenance_windows"] || [],
          max_concurrent_agents: config["max_concurrent_agents"] || 10,
          reboot_policy: parse_reboot_policy(config["reboot_policy"]),
          rollback_on_failure: config["rollback_on_failure"] || true,
          exclude_kbs: config["exclude_kbs"] || [],
          test_group_ids: config["test_group_ids"] || [],
          enabled: row.enabled,
          created_at: DateTime.utc_now(),
          updated_at: DateTime.utc_now()
        }
        :ets.insert(@ets_policies, {policy.id, policy})
      end)
    rescue
      _ -> :ok
    end
  end

  defp get_deployment_from_ets(deployment_id) do
    case :ets.lookup(@ets_deployments, deployment_id) do
      [{^deployment_id, deployment}] -> {:ok, deployment}
      [] -> {:error, :not_found}
    end
  end

  defp list_org_policies(org_id) do
    :ets.tab2list(@ets_policies)
    |> Enum.map(fn {_id, p} -> p end)
    |> Enum.filter(&(&1.org_id == org_id))
  end

  defp get_all_org_ids do
    :ets.tab2list(@ets_agent_status)
    |> Enum.map(fn {_id, s} -> s.org_id end)
    |> Enum.uniq()
  end

  defp schedule_periodic_scan do
    Process.send_after(self(), :periodic_scan, @scan_interval)
  end
end
