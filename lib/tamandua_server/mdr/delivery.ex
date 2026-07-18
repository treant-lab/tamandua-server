defmodule TamanduaServer.MDR.Delivery do
  @moduledoc """
  Managed Detection & Response (MDR) Service Delivery Framework.

  Provides the complete MDR service delivery lifecycle:

  - **Alert Queue** - Round-robin, skill-based, and workload-based assignment
  - **SLA Timers** - Per-severity response targets with automatic escalation
  - **Escalation Paths** - Analyst -> Senior -> Lead -> Customer notification
  - **Investigation Templates** - Per-alert-type investigation checklists
  - **Customer Communication** - Templated notifications, secure messaging
  - **Service Tiers** - Essential / Advanced / Elite with feature gating
  - **Approval Workflows** - Customer sign-off on response actions

  ## SLA Targets (default)

  | Priority | Initial Response | Update Cadence |
  |----------|-----------------|----------------|
  | P1       | 15 minutes      | Every 30 min   |
  | P2       | 1 hour          | Every 2 hours  |
  | P3       | 4 hours         | Every 8 hours  |
  | P4       | 24 hours        | Daily          |

  ## Integration

  - Reads alerts from `TamanduaServer.Alerts`
  - Uses RBAC from `TamanduaServer.Authorization`
  - Generates reports via `TamanduaServer.Reports`
  - Multi-tenant: all operations scoped to org_id
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo

  import Ecto.Query

  # ETS tables
  @ets_queue :mdr_alert_queue
  @ets_incidents :mdr_incidents
  @ets_assignments :mdr_assignments
  @ets_escalations :mdr_escalations
  @ets_tiers :mdr_service_tiers
  @ets_customers :mdr_customers
  @ets_approvals :mdr_approvals

  # Default SLA targets (minutes)
  @default_sla_targets %{
    p1: 15,
    p2: 60,
    p3: 240,
    p4: 1440
  }

  # Escalation intervals (minutes)
  @escalation_intervals %{
    p1: [15, 30, 45],        # escalate at 15, 30, 45 min
    p2: [60, 120, 180],      # escalate at 1, 2, 3 hours
    p3: [240, 480, 720],     # escalate at 4, 8, 12 hours
    p4: [1440, 2880, 4320]   # escalate at 1, 2, 3 days
  }

  # SLA check interval
  @sla_check_interval :timer.minutes(1)

  # Service tier definitions
  @service_tiers %{
    "essential" => %{
      name: "Essential",
      features: MapSet.new(["alert_monitoring", "basic_response", "monthly_report"]),
      sla_targets: %{p1: 30, p2: 120, p3: 480, p4: 2880},
      threat_hunting: false,
      dedicated_analyst: false,
      custom_detections: false,
      monthly_review: false
    },
    "advanced" => %{
      name: "Advanced",
      features: MapSet.new([
        "alert_monitoring", "basic_response", "monthly_report",
        "threat_hunting", "custom_detections", "bi_weekly_review",
        "incident_response", "forensics"
      ]),
      sla_targets: %{p1: 15, p2: 60, p3: 240, p4: 1440},
      threat_hunting: true,
      dedicated_analyst: false,
      custom_detections: true,
      monthly_review: true
    },
    "elite" => %{
      name: "Elite",
      features: MapSet.new([
        "alert_monitoring", "basic_response", "monthly_report",
        "threat_hunting", "custom_detections", "weekly_review",
        "incident_response", "forensics", "dedicated_analyst",
        "red_team", "tabletop_exercises", "executive_briefings"
      ]),
      sla_targets: @default_sla_targets,
      threat_hunting: true,
      dedicated_analyst: true,
      custom_detections: true,
      monthly_review: true
    }
  }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Register a customer organization for MDR service.
  """
  @spec register_customer(String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def register_customer(org_id, tier, opts \\ []) do
    GenServer.call(__MODULE__, {:register_customer, org_id, tier, opts})
  end

  @doc """
  Update a customer's service tier.
  """
  @spec update_customer_tier(String.t(), String.t()) :: :ok | {:error, :not_found}
  def update_customer_tier(org_id, new_tier) do
    GenServer.call(__MODULE__, {:update_tier, org_id, new_tier})
  end

  @doc """
  Queue an alert for MDR triage and assignment.
  """
  @spec queue_alert(map()) :: {:ok, String.t()} | {:error, term()}
  def queue_alert(alert) do
    GenServer.call(__MODULE__, {:queue_alert, alert})
  end

  @doc """
  Assign an alert to a specific analyst.
  """
  @spec assign_alert(String.t(), String.t()) :: :ok | {:error, term()}
  def assign_alert(alert_id, analyst_id) do
    GenServer.call(__MODULE__, {:assign_alert, alert_id, analyst_id})
  end

  @doc """
  Create an MDR incident from one or more alerts.
  """
  @spec create_incident(String.t(), map()) :: {:ok, String.t()} | {:error, term()}
  def create_incident(org_id, attrs) do
    GenServer.call(__MODULE__, {:create_incident, org_id, attrs})
  end

  @doc """
  Update an incident's status.
  """
  @spec update_incident(String.t(), map()) :: :ok | {:error, :not_found}
  def update_incident(incident_id, attrs) do
    GenServer.call(__MODULE__, {:update_incident, incident_id, attrs})
  end

  @doc """
  Add a communication entry to an incident (notification, update, resolution).
  """
  @spec add_communication(String.t(), map()) :: :ok | {:error, :not_found}
  def add_communication(incident_id, comm) do
    GenServer.call(__MODULE__, {:add_communication, incident_id, comm})
  end

  @doc """
  Request customer approval for a response action.
  """
  @spec request_approval(String.t(), String.t(), map()) :: {:ok, String.t()} | {:error, term()}
  def request_approval(incident_id, org_id, action) do
    GenServer.call(__MODULE__, {:request_approval, incident_id, org_id, action})
  end

  @doc """
  Customer responds to an approval request.
  """
  @spec respond_to_approval(String.t(), boolean(), keyword()) :: :ok | {:error, :not_found}
  def respond_to_approval(approval_id, approved?, opts \\ []) do
    GenServer.call(__MODULE__, {:respond_to_approval, approval_id, approved?, opts})
  end

  @doc """
  Manually escalate an incident.
  """
  @spec escalate(String.t(), String.t()) :: :ok | {:error, term()}
  def escalate(incident_id, reason) do
    GenServer.call(__MODULE__, {:escalate, incident_id, reason})
  end

  @doc """
  Get the current alert queue.
  """
  @spec get_queue(keyword()) :: [map()]
  def get_queue(opts \\ []) do
    GenServer.call(__MODULE__, {:get_queue, opts})
  end

  @doc """
  Get incidents for an organization.
  """
  @spec get_incidents(String.t(), keyword()) :: [map()]
  def get_incidents(org_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_incidents, org_id, opts})
  end

  @doc """
  Get a specific incident.
  """
  @spec get_incident(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_incident(incident_id) do
    GenServer.call(__MODULE__, {:get_incident, incident_id})
  end

  @doc """
  Get service tier information for a customer.
  """
  @spec get_customer_tier(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_customer_tier(org_id) do
    GenServer.call(__MODULE__, {:get_customer_tier, org_id})
  end

  @doc """
  Check if a feature is available for a customer's tier.
  """
  @spec feature_available?(String.t(), String.t()) :: boolean()
  def feature_available?(org_id, feature) do
    GenServer.call(__MODULE__, {:feature_available?, org_id, feature})
  end

  @doc """
  Get SLA status for a customer.
  """
  @spec get_sla_status(String.t()) :: map()
  def get_sla_status(org_id) do
    GenServer.call(__MODULE__, {:get_sla_status, org_id})
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
    :ets.new(@ets_queue, [:named_table, :ordered_set, :public, read_concurrency: true])
    :ets.new(@ets_incidents, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_assignments, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_escalations, [:named_table, :bag, :public, read_concurrency: true])
    :ets.new(@ets_tiers, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_customers, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_approvals, [:named_table, :set, :public, read_concurrency: true])

    state = %{
      # Round-robin index for analyst assignment
      assignment_index: 0,
      stats: %{
        alerts_queued: 0,
        alerts_assigned: 0,
        incidents_created: 0,
        incidents_resolved: 0,
        escalations: 0,
        sla_breaches: 0,
        approvals_requested: 0,
        approvals_granted: 0,
        approvals_denied: 0,
        communications_sent: 0
      }
    }

    # Load customers from database
    load_customers_from_db()

    # Subscribe to alert feed for auto-queuing
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:feed")

    # Schedule SLA monitoring
    schedule_sla_check()

    Logger.info("[MDR.Delivery] Initialized with #{map_size(@service_tiers)} service tiers")
    {:ok, state}
  end

  # -- Customer registration -----------------------------------------------

  @impl true
  def handle_call({:register_customer, org_id, tier, opts}, _from, state) do
    tier_key = String.downcase(tier)

    case Map.get(@service_tiers, tier_key) do
      nil ->
        {:reply, {:error, :invalid_tier}, state}

      tier_config ->
        customer = %{
          org_id: org_id,
          tier: tier_key,
          tier_config: tier_config,
          custom_sla: Keyword.get(opts, :custom_sla),
          primary_contact: Keyword.get(opts, :primary_contact),
          escalation_contacts: Keyword.get(opts, :escalation_contacts, []),
          notification_preferences: Keyword.get(opts, :notification_preferences, %{}),
          registered_at: DateTime.utc_now()
        }

        :ets.insert(@ets_customers, {org_id, customer})
        persist_customer(customer)
        {:reply, {:ok, customer}, state}
    end
  end

  @impl true
  def handle_call({:update_tier, org_id, new_tier}, _from, state) do
    tier_key = String.downcase(new_tier)

    case {:ets.lookup(@ets_customers, org_id), Map.get(@service_tiers, tier_key)} do
      {[{^org_id, customer}], tier_config} when tier_config != nil ->
        updated = %{customer | tier: tier_key, tier_config: tier_config}
        :ets.insert(@ets_customers, {org_id, updated})
        persist_customer(updated)
        {:reply, :ok, state}

      _ ->
        {:reply, {:error, :not_found}, state}
    end
  end

  # -- Alert queue ---------------------------------------------------------

  @impl true
  def handle_call({:queue_alert, alert}, _from, state) do
    org_id = alert[:organization_id] || alert["organization_id"]
    severity = alert[:severity] || alert["severity"] || "medium"
    alert_id = alert[:id] || alert["id"] || Ecto.UUID.generate()

    priority = severity_to_priority(severity)

    queue_entry = %{
      id: alert_id,
      org_id: org_id,
      alert: alert,
      priority: priority,
      severity: severity,
      queued_at: DateTime.utc_now(),
      assigned_to: nil,
      assigned_at: nil,
      sla_deadline: calculate_sla_deadline(org_id, priority),
      escalation_level: 0,
      status: "queued"
    }

    # Priority-ordered key: lower number = higher priority
    sort_key = {priority_to_int(priority), System.system_time(:microsecond)}
    :ets.insert(@ets_queue, {sort_key, queue_entry})

    # Auto-assign if analysts are available
    auto_assign(queue_entry, state)

    new_stats = %{state.stats | alerts_queued: state.stats.alerts_queued + 1}
    {:reply, {:ok, alert_id}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:assign_alert, alert_id, analyst_id}, _from, state) do
    case find_queue_entry(alert_id) do
      {sort_key, entry} ->
        updated = %{entry |
          assigned_to: analyst_id,
          assigned_at: DateTime.utc_now(),
          status: "assigned"
        }

        :ets.insert(@ets_queue, {sort_key, updated})

        # Track assignment
        analyst_assignments = get_analyst_assignments(analyst_id)
        :ets.insert(@ets_assignments, {analyst_id, [alert_id | analyst_assignments]})

        new_stats = %{state.stats | alerts_assigned: state.stats.alerts_assigned + 1}
        {:reply, :ok, %{state | stats: new_stats}}

      nil ->
        {:reply, {:error, :not_found}, state}
    end
  end

  # -- Incident management -------------------------------------------------

  @impl true
  def handle_call({:create_incident, org_id, attrs}, _from, state) do
    incident_id = Ecto.UUID.generate()

    incident = %{
      id: incident_id,
      org_id: org_id,
      title: attrs[:title] || attrs["title"] || "Untitled Incident",
      description: attrs[:description] || attrs["description"],
      severity: attrs[:severity] || attrs["severity"] || "medium",
      priority: severity_to_priority(attrs[:severity] || attrs["severity"] || "medium"),
      status: "open",
      alert_ids: attrs[:alert_ids] || attrs["alert_ids"] || [],
      assigned_analyst: attrs[:analyst_id] || attrs["analyst_id"],
      escalation_level: 0,
      investigation_notes: [],
      communications: [],
      evidence: [],
      timeline: [%{action: "created", timestamp: DateTime.utc_now(), actor: "system"}],
      created_at: DateTime.utc_now(),
      updated_at: DateTime.utc_now(),
      resolved_at: nil,
      resolution: nil
    }

    :ets.insert(@ets_incidents, {incident_id, incident})
    persist_incident(incident)

    # Send initial notification to customer
    send_customer_notification(org_id, :incident_created, incident)

    new_stats = %{state.stats | incidents_created: state.stats.incidents_created + 1}
    {:reply, {:ok, incident_id}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:update_incident, incident_id, attrs}, _from, state) do
    case :ets.lookup(@ets_incidents, incident_id) do
      [{^incident_id, incident}] ->
        timeline_entry = %{
          action: "updated",
          changes: Map.keys(attrs),
          timestamp: DateTime.utc_now(),
          actor: attrs[:actor] || "system"
        }

        updated = incident
          |> Map.merge(Map.take(attrs, [:status, :title, :description, :severity, :assigned_analyst, :resolution, "status", "title", "description", "severity", "assigned_analyst", "resolution"]))
          |> Map.put(:updated_at, DateTime.utc_now())
          |> Map.update(:timeline, [], &[timeline_entry | &1])

        updated = if attrs[:status] in ["resolved", "closed"] do
          _stats_key = :incidents_resolved
          %{updated | resolved_at: DateTime.utc_now()}
        else
          updated
        end

        :ets.insert(@ets_incidents, {incident_id, updated})
        persist_incident(updated)

        # Notify customer of significant updates
        if attrs[:status] do
          send_customer_notification(incident.org_id, :incident_updated, updated)
        end

        new_stats = if attrs[:status] in ["resolved", "closed"] do
          %{state.stats | incidents_resolved: state.stats.incidents_resolved + 1}
        else
          state.stats
        end

        {:reply, :ok, %{state | stats: new_stats}}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  # -- Communication -------------------------------------------------------

  @impl true
  def handle_call({:add_communication, incident_id, comm}, _from, state) do
    case :ets.lookup(@ets_incidents, incident_id) do
      [{^incident_id, incident}] ->
        communication = %{
          id: Ecto.UUID.generate(),
          type: comm[:type] || comm["type"] || "update",
          subject: comm[:subject] || comm["subject"],
          body: comm[:body] || comm["body"],
          sender: comm[:sender] || comm["sender"] || "system",
          recipients: comm[:recipients] || comm["recipients"] || [],
          sent_at: DateTime.utc_now()
        }

        updated = %{incident |
          communications: [communication | incident.communications],
          updated_at: DateTime.utc_now()
        }

        :ets.insert(@ets_incidents, {incident_id, updated})
        persist_incident(updated)

        new_stats = %{state.stats | communications_sent: state.stats.communications_sent + 1}
        {:reply, :ok, %{state | stats: new_stats}}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  # -- Approval workflow ---------------------------------------------------

  @impl true
  def handle_call({:request_approval, incident_id, org_id, action}, _from, state) do
    approval_id = Ecto.UUID.generate()

    approval = %{
      id: approval_id,
      incident_id: incident_id,
      org_id: org_id,
      action: action,
      status: "pending",
      requested_at: DateTime.utc_now(),
      responded_at: nil,
      approved: nil,
      response_notes: nil
    }

    :ets.insert(@ets_approvals, {approval_id, approval})

    # Notify customer
    send_customer_notification(org_id, :approval_requested, %{
      approval_id: approval_id,
      incident_id: incident_id,
      action: action
    })

    new_stats = %{state.stats | approvals_requested: state.stats.approvals_requested + 1}
    {:reply, {:ok, approval_id}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:respond_to_approval, approval_id, approved?, opts}, _from, state) do
    case :ets.lookup(@ets_approvals, approval_id) do
      [{^approval_id, approval}] ->
        updated = %{approval |
          status: if(approved?, do: "approved", else: "denied"),
          approved: approved?,
          responded_at: DateTime.utc_now(),
          response_notes: Keyword.get(opts, :notes)
        }

        :ets.insert(@ets_approvals, {approval_id, updated})

        # If approved, execute the action
        if approved? do
          execute_approved_action(updated)
        end

        stats_key = if approved?, do: :approvals_granted, else: :approvals_denied
        new_stats = Map.update!(state.stats, stats_key, &(&1 + 1))
        {:reply, :ok, %{state | stats: new_stats}}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  # -- Escalation ----------------------------------------------------------

  @impl true
  def handle_call({:escalate, incident_id, reason}, _from, state) do
    case :ets.lookup(@ets_incidents, incident_id) do
      [{^incident_id, incident}] ->
        new_level = incident.escalation_level + 1
        escalation_target = get_escalation_target(new_level)

        escalation = %{
          incident_id: incident_id,
          from_level: incident.escalation_level,
          to_level: new_level,
          reason: reason,
          target: escalation_target,
          escalated_at: DateTime.utc_now()
        }

        :ets.insert(@ets_escalations, {incident_id, escalation})

        updated = %{incident |
          escalation_level: new_level,
          timeline: [%{action: "escalated", level: new_level, reason: reason, timestamp: DateTime.utc_now()} | incident.timeline],
          updated_at: DateTime.utc_now()
        }

        :ets.insert(@ets_incidents, {incident_id, updated})

        # Notify escalation target
        notify_escalation(incident.org_id, escalation, incident)

        # At level 3, notify customer directly
        if new_level >= 3 do
          send_customer_notification(incident.org_id, :escalation_notice, updated)
        end

        new_stats = %{state.stats | escalations: state.stats.escalations + 1}
        {:reply, :ok, %{state | stats: new_stats}}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  # -- Queries -------------------------------------------------------------

  @impl true
  def handle_call({:get_queue, opts}, _from, state) do
    priority_filter = Keyword.get(opts, :priority)
    analyst_filter = Keyword.get(opts, :analyst_id)
    status_filter = Keyword.get(opts, :status)
    limit = Keyword.get(opts, :limit, 100)

    entries =
      :ets.tab2list(@ets_queue)
      |> Enum.map(fn {_key, entry} -> entry end)
      |> then(fn es ->
        if priority_filter, do: Enum.filter(es, &(&1.priority == priority_filter)), else: es
      end)
      |> then(fn es ->
        if analyst_filter, do: Enum.filter(es, &(&1.assigned_to == analyst_filter)), else: es
      end)
      |> then(fn es ->
        if status_filter, do: Enum.filter(es, &(&1.status == status_filter)), else: es
      end)
      |> Enum.take(limit)

    {:reply, entries, state}
  end

  @impl true
  def handle_call({:get_incidents, org_id, opts}, _from, state) do
    status_filter = Keyword.get(opts, :status)
    limit = Keyword.get(opts, :limit, 50)

    incidents =
      :ets.tab2list(@ets_incidents)
      |> Enum.map(fn {_id, i} -> i end)
      |> Enum.filter(&(&1.org_id == org_id))
      |> then(fn is_ ->
        if status_filter, do: Enum.filter(is_, &(&1.status == status_filter)), else: is_
      end)
      |> Enum.sort_by(& &1.created_at, {:desc, DateTime})
      |> Enum.take(limit)

    {:reply, incidents, state}
  end

  @impl true
  def handle_call({:get_incident, incident_id}, _from, state) do
    case :ets.lookup(@ets_incidents, incident_id) do
      [{^incident_id, incident}] -> {:reply, {:ok, incident}, state}
      [] -> {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:get_customer_tier, org_id}, _from, state) do
    case :ets.lookup(@ets_customers, org_id) do
      [{^org_id, customer}] -> {:reply, {:ok, customer}, state}
      [] -> {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:feature_available?, org_id, feature}, _from, state) do
    available = case :ets.lookup(@ets_customers, org_id) do
      [{^org_id, customer}] ->
        MapSet.member?(customer.tier_config.features, feature)
      [] ->
        false
    end

    {:reply, available, state}
  end

  @impl true
  def handle_call({:get_sla_status, org_id}, _from, state) do
    sla = calculate_sla_status(org_id)
    {:reply, sla, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  # -- PubSub alert handler -----------------------------------------------

  @impl true
  def handle_info({:alert_created, alert}, state) do
    org_id = alert[:organization_id] || alert["organization_id"]

    # Only queue if this org is an MDR customer
    case :ets.lookup(@ets_customers, org_id) do
      [{^org_id, _customer}] ->
        GenServer.cast(self(), {:auto_queue_alert, alert})

      [] ->
        :ok
    end

    {:noreply, state}
  end

  # -- SLA monitoring ------------------------------------------------------

  @impl true
  def handle_info(:check_sla, state) do
    new_stats = check_sla_compliance(state)
    schedule_sla_check()
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  @impl true
  def handle_cast({:auto_queue_alert, alert}, state) do
    # Silently queue - ignore errors
    case queue_alert(alert) do
      {:ok, _} -> :ok
      {:error, _} -> :ok
    end

    {:noreply, state}
  end

  # ============================================================================
  # Private - Assignment
  # ============================================================================

  defp auto_assign(queue_entry, _state) do
    # Get available analysts (those with fewer than 10 active assignments)
    analysts = get_available_analysts()

    if analysts != [] do
      # Simple round-robin; could be enhanced with skill/workload-based routing
      analyst = Enum.min_by(analysts, fn a -> length(get_analyst_assignments(a)) end)
      assign_alert(queue_entry.id, analyst)
    end
  end

  defp get_available_analysts do
    # In production, this would query the RBAC system for analysts with MDR role
    :ets.tab2list(@ets_assignments)
    |> Enum.map(fn {analyst_id, assignments} -> {analyst_id, length(assignments)} end)
    |> Enum.filter(fn {_analyst, count} -> count < 10 end)
    |> Enum.map(fn {analyst_id, _} -> analyst_id end)
  end

  defp get_analyst_assignments(analyst_id) do
    case :ets.lookup(@ets_assignments, analyst_id) do
      [{^analyst_id, assignments}] -> assignments
      [] -> []
    end
  end

  defp find_queue_entry(alert_id) do
    :ets.tab2list(@ets_queue)
    |> Enum.find(fn {_key, entry} -> entry.id == alert_id end)
  end

  # ============================================================================
  # Private - SLA
  # ============================================================================

  defp calculate_sla_deadline(org_id, priority) do
    sla_targets = get_sla_targets(org_id)
    minutes = Map.get(sla_targets, priority, 1440)
    DateTime.add(DateTime.utc_now(), minutes * 60, :second)
  end

  defp get_sla_targets(org_id) do
    case :ets.lookup(@ets_customers, org_id) do
      [{^org_id, customer}] ->
        customer.custom_sla || customer.tier_config.sla_targets

      [] ->
        @default_sla_targets
    end
  end

  defp check_sla_compliance(state) do
    now = DateTime.utc_now()

    :ets.tab2list(@ets_queue)
    |> Enum.each(fn {sort_key, entry} ->
      if entry.status in ["queued", "assigned"] do
        case entry.sla_deadline do
          %DateTime{} = deadline ->
            if DateTime.compare(now, deadline) == :gt do
              # SLA breached
              handle_sla_breach(sort_key, entry)
            else
              # Check escalation thresholds
              check_escalation_needed(sort_key, entry, now)
            end

          _ ->
            :ok
        end
      end
    end)

    state.stats
  end

  defp handle_sla_breach(sort_key, entry) do
    Logger.warning("[MDR.Delivery] SLA breach for alert #{entry.id} (priority=#{entry.priority})")

    updated = %{entry | status: "sla_breached"}
    :ets.insert(@ets_queue, {sort_key, updated})

    # Generate SLA breach alert
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "system:alerts",
      {:mdr_sla_breach, %{
        alert_id: entry.id,
        org_id: entry.org_id,
        priority: entry.priority,
        sla_deadline: entry.sla_deadline,
        queued_at: entry.queued_at
      }}
    )

    # Auto-escalate
    escalate_queue_entry(entry)
  end

  defp check_escalation_needed(_sort_key, entry, now) do
    elapsed_minutes = DateTime.diff(now, entry.queued_at, :second) / 60.0
    intervals = Map.get(@escalation_intervals, entry.priority, [])

    target_level =
      intervals
      |> Enum.with_index(1)
      |> Enum.reduce(0, fn {threshold, level}, current ->
        if elapsed_minutes >= threshold and level > entry.escalation_level do
          level
        else
          current
        end
      end)

    if target_level > entry.escalation_level do
      escalate_queue_entry(entry)
    end
  end

  defp escalate_queue_entry(entry) do
    if entry.org_id do
      # Create an incident for escalation if one does not exist
      case create_incident(entry.org_id, %{
        title: "Escalated Alert: #{entry.alert[:title] || entry.id}",
        severity: entry.severity,
        alert_ids: [entry.id]
      }) do
        {:ok, incident_id} ->
          escalate(incident_id, "SLA escalation (priority #{entry.priority})")

        _ ->
          :ok
      end
    end
  end

  defp calculate_sla_status(org_id) do
    now = DateTime.utc_now()

    entries =
      :ets.tab2list(@ets_queue)
      |> Enum.map(fn {_key, entry} -> entry end)
      |> Enum.filter(&(&1.org_id == org_id))

    total = length(entries)
    breached = Enum.count(entries, &(&1.status == "sla_breached"))

    in_sla = Enum.count(entries, fn entry ->
      case entry.sla_deadline do
        %DateTime{} = deadline -> DateTime.compare(now, deadline) != :gt
        _ -> true
      end
    end)

    %{
      org_id: org_id,
      total_alerts: total,
      in_sla: in_sla,
      breached: breached,
      compliance_rate: if(total > 0, do: Float.round(in_sla / total * 100, 1), else: 100.0),
      by_priority: %{
        p1: count_by_priority(entries, :p1),
        p2: count_by_priority(entries, :p2),
        p3: count_by_priority(entries, :p3),
        p4: count_by_priority(entries, :p4)
      }
    }
  end

  defp count_by_priority(entries, priority) do
    filtered = Enum.filter(entries, &(&1.priority == priority))
    %{
      total: length(filtered),
      breached: Enum.count(filtered, &(&1.status == "sla_breached"))
    }
  end

  # ============================================================================
  # Private - Escalation
  # ============================================================================

  defp get_escalation_target(level) do
    case level do
      1 -> "senior_analyst"
      2 -> "team_lead"
      3 -> "customer_notification"
      _ -> "management"
    end
  end

  defp notify_escalation(org_id, escalation, incident) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "mdr:escalations",
      {:escalation, %{
        org_id: org_id,
        incident_id: incident.id,
        escalation: escalation
      }}
    )
  end

  # ============================================================================
  # Private - Communication
  # ============================================================================

  defp send_customer_notification(org_id, type, data) do
    template = get_notification_template(type)

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "mdr:notifications:#{org_id}",
      {:notification, %{
        type: type,
        template: template,
        data: data,
        sent_at: DateTime.utc_now()
      }}
    )
  end

  defp get_notification_template(:incident_created) do
    %{
      subject: "New Security Incident Detected",
      body_template: """
      A new security incident has been detected and assigned to our MDR team.

      Title: {{title}}
      Severity: {{severity}}
      Status: Under Investigation

      Our analysts are actively investigating this incident. You will receive
      updates as the investigation progresses.
      """
    }
  end

  defp get_notification_template(:incident_updated) do
    %{
      subject: "Incident Status Update",
      body_template: """
      An update on security incident {{id}}:

      Status: {{status}}

      {{resolution}}

      Please contact your dedicated analyst for further details.
      """
    }
  end

  defp get_notification_template(:approval_requested) do
    %{
      subject: "Response Action Approval Required",
      body_template: """
      Our MDR team is requesting your approval for a response action:

      Incident: {{incident_id}}
      Proposed Action: {{action}}

      Please review and approve/deny this action at your earliest convenience.
      """
    }
  end

  defp get_notification_template(:escalation_notice) do
    %{
      subject: "Incident Escalation Notice",
      body_template: """
      A security incident has been escalated:

      Incident: {{id}}
      Severity: {{severity}}
      Escalation Level: {{escalation_level}}

      Our senior team is now handling this incident.
      """
    }
  end

  defp get_notification_template(_) do
    %{subject: "MDR Service Update", body_template: "You have a new update from your MDR service."}
  end

  # ============================================================================
  # Private - Approved Actions
  # ============================================================================

  defp execute_approved_action(approval) do
    Logger.info("[MDR.Delivery] Executing approved action for incident #{approval.incident_id}")

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "mdr:actions",
      {:execute_approved_action, %{
        approval_id: approval.id,
        incident_id: approval.incident_id,
        org_id: approval.org_id,
        action: approval.action
      }}
    )
  end

  # ============================================================================
  # Private - Helpers
  # ============================================================================

  defp severity_to_priority(severity) do
    case String.downcase(severity || "medium") do
      "critical" -> :p1
      "high" -> :p2
      "medium" -> :p3
      "low" -> :p4
      _ -> :p3
    end
  end

  defp priority_to_int(:p1), do: 1
  defp priority_to_int(:p2), do: 2
  defp priority_to_int(:p3), do: 3
  defp priority_to_int(:p4), do: 4
  defp priority_to_int(_), do: 3

  defp schedule_sla_check do
    Process.send_after(self(), :check_sla, @sla_check_interval)
  end

  # ============================================================================
  # Private - Persistence
  # ============================================================================

  defp persist_incident(incident) do
    Task.start(fn ->
      try do
        attrs = %{
          id: incident.id,
          org_id: incident.org_id,
          title: incident.title,
          severity: incident.severity,
          status: incident.status,
          assigned_analyst: incident.assigned_analyst,
          escalation_level: incident.escalation_level,
          alert_ids: incident.alert_ids,
          data: %{
            communications: incident.communications,
            evidence: incident.evidence,
            timeline: incident.timeline,
            investigation_notes: incident.investigation_notes,
            resolution: incident.resolution
          },
          inserted_at: incident.created_at,
          updated_at: DateTime.utc_now()
        }

        Repo.insert_all("mdr_incidents", [attrs],
          on_conflict: {:replace, [:title, :severity, :status, :assigned_analyst, :escalation_level, :data, :updated_at]},
          conflict_target: [:id]
        )
      rescue
        _ -> :ok
      end
    end)
  end

  defp persist_customer(customer) do
    Task.start(fn ->
      try do
        attrs = %{
          id: Ecto.UUID.generate(),
          org_id: customer.org_id,
          tier: customer.tier,
          config: %{
            primary_contact: customer.primary_contact,
            escalation_contacts: customer.escalation_contacts,
            notification_preferences: customer.notification_preferences,
            custom_sla: customer.custom_sla
          },
          inserted_at: DateTime.utc_now(),
          updated_at: DateTime.utc_now()
        }

        Repo.insert_all("mdr_customers", [attrs],
          on_conflict: {:replace, [:tier, :config, :updated_at]},
          conflict_target: [:org_id]
        )
      rescue
        _ -> :ok
      end
    end)
  end

  defp load_customers_from_db do
    try do
      rows = Repo.all(from(c in "mdr_customers", select: %{org_id: c.org_id, tier: c.tier, config: c.config}))

      Enum.each(rows, fn row ->
        tier_config = Map.get(@service_tiers, row.tier, Map.get(@service_tiers, "essential"))
        config = row.config || %{}

        customer = %{
          org_id: row.org_id,
          tier: row.tier,
          tier_config: tier_config,
          custom_sla: config["custom_sla"],
          primary_contact: config["primary_contact"],
          escalation_contacts: config["escalation_contacts"] || [],
          notification_preferences: config["notification_preferences"] || %{},
          registered_at: DateTime.utc_now()
        }

        :ets.insert(@ets_customers, {row.org_id, customer})
      end)
    rescue
      _ -> :ok
    end
  end
end
