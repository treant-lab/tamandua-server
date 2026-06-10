defmodule TamanduaServerWeb.GraphQL.Schema do
  @moduledoc """
  GraphQL Schema for Tamandua EDR API v2.

  This schema provides a comprehensive GraphQL API for:
  - Querying agents, alerts, events, and threat intelligence
  - Executing response actions (kill, quarantine, isolate)
  - Managing playbooks and automation
  - Real-time subscriptions for alerts and events

  ## Authentication

  All queries and mutations require authentication via:
  - JWT token in Authorization header: `Bearer <token>`
  - API key in X-API-Key header

  ## Rate Limiting

  The API is rate-limited per organization:
  - 1000 requests/minute for standard tier
  - 5000 requests/minute for enterprise tier

  ## Example Queries

      # Get agents
      query {
        agents(filter: { status: "online" }) {
          id
          hostname
          status
          alerts { id title severity }
        }
      }

      # Get alert with timeline
      query {
        alert(id: "uuid") {
          id
          title
          severity
          timeline { timestamp eventType description }
          agent { hostname }
        }
      }

  ## Example Mutations

      # Kill a process
      mutation {
        killProcess(input: { agentId: "uuid", pid: 1234 }) {
          success
          message
        }
      }

      # Execute playbook
      mutation {
        executePlaybook(input: {
          playbookId: "uuid",
          context: { agentId: "uuid", alertId: "uuid" }
        }) {
          id
          status
        }
      }

  ## Subscriptions

      # Subscribe to new alerts
      subscription {
        alertCreated {
          id
          title
          severity
          agent { hostname }
        }
      }
  """

  use Absinthe.Schema

  @desc "ISO8601 datetime"
  scalar :datetime, name: "DateTime" do
    serialize &__MODULE__.serialize_datetime/1
    parse &__MODULE__.parse_datetime/1
  end

  @desc "JSON object"
  scalar :json, name: "JSON" do
    serialize &__MODULE__.serialize_json/1
    parse &__MODULE__.parse_json/1
  end

  # Import types
  import_types TamanduaServerWeb.GraphQL.Types.CommonTypes
  import_types TamanduaServerWeb.GraphQL.Types.AgentTypes
  import_types TamanduaServerWeb.GraphQL.Types.AlertTypes
  import_types TamanduaServerWeb.GraphQL.Types.EventTypes
  import_types TamanduaServerWeb.GraphQL.Types.UserTypes
  import_types TamanduaServerWeb.GraphQL.Types.PlaybookTypes
  import_types TamanduaServerWeb.GraphQL.Types.InvestigationTypes
  import_types TamanduaServerWeb.GraphQL.Types.ThreatIntelTypes
  import_types TamanduaServerWeb.GraphQL.Types.ResponseTypes

  alias TamanduaServerWeb.GraphQL.Resolvers.{
    AgentResolver,
    AlertResolver,
    EventResolver,
    PlaybookResolver,
    UserResolver,
    InvestigationResolver,
    ThreatIntelResolver,
    ResponseResolver
  }

  # ===========================================================================
  # Queries
  # ===========================================================================

  query do
    @desc "Get the currently authenticated user"
    field :me, :current_user do
      resolve &UserResolver.current_user/3
    end

    @desc "Get system health status"
    field :health, :health_status do
      resolve fn _, _, _ ->
        {:ok, %{
          status: "healthy",
          version: "1.0.0",
          uptime_seconds: System.os_time(:second) - Application.get_env(:tamandua_server, :started_at, System.os_time(:second)),
          database: %{status: "healthy", latency_ms: 1},
          redis: %{status: "healthy", latency_ms: 1},
          rabbitmq: %{status: "healthy", latency_ms: 1},
          ml_service: %{status: "healthy", latency_ms: 10}
        }}
      end
    end

    @desc "Get dashboard statistics"
    field :dashboard_stats, :dashboard_stats do
      resolve fn _, _, _ ->
        {:ok, %{
          agents: nil,
          alerts: nil,
          events: nil,
          threats: nil,
          response_actions: nil,
          detections_today: 0,
          mttr_hours: 0.0,
          mttd_minutes: 0.0
        }}
      end
    end

    # -------------------------------------------------------------------------
    # Agents
    # -------------------------------------------------------------------------

    @desc "List all agents with optional filtering"
    field :agents, list_of(:agent) do
      arg :filter, :agent_filter
      arg :pagination, :pagination_input
      arg :sort, :sort_input

      resolve &AgentResolver.list_agents/3
    end

    @desc "Get a single agent by ID"
    field :agent, :agent do
      arg :id, non_null(:id)

      resolve &AgentResolver.get_agent/3
    end

    @desc "Get agent statistics"
    field :agent_stats, :agent_stats do
      resolve &AgentResolver.agent_stats/3
    end

    # -------------------------------------------------------------------------
    # Alerts
    # -------------------------------------------------------------------------

    @desc "List all alerts with optional filtering"
    field :alerts, list_of(:alert) do
      arg :filter, :alert_filter
      arg :pagination, :pagination_input
      arg :sort, :sort_input

      resolve &AlertResolver.list_alerts/3
    end

    @desc "Get a single alert by ID"
    field :alert, :alert do
      arg :id, non_null(:id)

      resolve &AlertResolver.get_alert/3
    end

    @desc "Get alert statistics"
    field :alert_stats, :alert_stats do
      resolve &AlertResolver.alert_stats/3
    end

    # -------------------------------------------------------------------------
    # Events
    # -------------------------------------------------------------------------

    @desc "List telemetry events with optional filtering"
    field :events, list_of(:event) do
      arg :filter, :event_filter
      arg :pagination, :pagination_input
      arg :sort, :sort_input

      resolve &EventResolver.list_events/3
    end

    @desc "Get a single event by ID"
    field :event, :event do
      arg :id, non_null(:id)

      resolve &EventResolver.get_event/3
    end

    @desc "Get event statistics"
    field :event_stats, :event_stats do
      resolve &EventResolver.event_stats/3
    end

    @desc "Search events using TQL (Tamandua Query Language)"
    field :search_events, list_of(:event) do
      arg :input, non_null(:event_search_input)

      resolve &EventResolver.search_events/3
    end

    # -------------------------------------------------------------------------
    # Users & Organizations
    # -------------------------------------------------------------------------

    @desc "Get a user by ID"
    field :user, :user do
      arg :id, non_null(:id)

      resolve &UserResolver.get_user/3
    end

    @desc "List users in the organization"
    field :users, list_of(:user) do
      resolve &UserResolver.list_users/3
    end

    @desc "Get an organization by ID"
    field :organization, :organization do
      arg :id, non_null(:id)

      resolve &UserResolver.get_organization/3
    end

    @desc "List all organizations (admin only)"
    field :organizations, list_of(:organization) do
      resolve &UserResolver.list_organizations/3
    end

    # -------------------------------------------------------------------------
    # Playbooks
    # -------------------------------------------------------------------------

    @desc "List all playbooks"
    field :playbooks, list_of(:playbook) do
      arg :filter, :playbook_filter
      arg :pagination, :pagination_input

      resolve &PlaybookResolver.list_playbooks/3
    end

    @desc "Get a playbook by ID"
    field :playbook, :playbook do
      arg :id, non_null(:id)

      resolve &PlaybookResolver.get_playbook/3
    end

    @desc "Get playbook templates"
    field :playbook_templates, list_of(:playbook_template) do
      resolve &PlaybookResolver.playbook_templates/3
    end

    @desc "Get pending playbook approvals"
    field :pending_approvals, list_of(:pending_approval) do
      resolve &PlaybookResolver.pending_approvals/3
    end

    # -------------------------------------------------------------------------
    # Investigations
    # -------------------------------------------------------------------------

    @desc "List investigations"
    field :investigations, list_of(:investigation) do
      arg :filter, :investigation_filter
      arg :pagination, :pagination_input

      resolve &InvestigationResolver.list_investigations/3
    end

    @desc "Get an investigation by ID"
    field :investigation, :investigation do
      arg :id, non_null(:id)

      resolve &InvestigationResolver.get_investigation/3
    end

    @desc "Get investigation statistics"
    field :investigation_stats, :investigation_stats do
      resolve &InvestigationResolver.investigation_stats/3
    end

    # -------------------------------------------------------------------------
    # Threat Intelligence
    # -------------------------------------------------------------------------

    @desc "List IOCs (Indicators of Compromise)"
    field :iocs, list_of(:ioc) do
      arg :filter, :ioc_filter
      arg :pagination, :pagination_input

      resolve &ThreatIntelResolver.list_iocs/3
    end

    @desc "Get an IOC by ID"
    field :ioc, :ioc do
      arg :id, non_null(:id)

      resolve &ThreatIntelResolver.get_ioc/3
    end

    @desc "List threat actors"
    field :threat_actors, list_of(:threat_actor) do
      arg :pagination, :pagination_input

      resolve &ThreatIntelResolver.list_threat_actors/3
    end

    @desc "Get a threat actor by ID"
    field :threat_actor, :threat_actor do
      arg :id, non_null(:id)

      resolve &ThreatIntelResolver.get_threat_actor/3
    end

    @desc "List threat campaigns"
    field :campaigns, list_of(:campaign) do
      arg :pagination, :pagination_input

      resolve &ThreatIntelResolver.list_campaigns/3
    end

    @desc "Get threat intelligence summary"
    field :threat_intel_summary, :threat_intel_summary do
      resolve &ThreatIntelResolver.threat_intel_summary/3
    end

    @desc "Get MITRE ATT&CK coverage"
    field :mitre_coverage, list_of(:mitre_coverage) do
      resolve &ThreatIntelResolver.mitre_coverage/3
    end

    @desc "Get MITRE technique details"
    field :mitre_technique, :mitre_technique do
      arg :id, non_null(:string)

      resolve &ThreatIntelResolver.mitre_technique/3
    end

    # -------------------------------------------------------------------------
    # Response Actions
    # -------------------------------------------------------------------------

    @desc "Get response action audit log"
    field :response_audit, list_of(:response_audit_entry) do
      arg :filter, :response_audit_filter
      arg :pagination, :pagination_input

      resolve &ResponseResolver.response_audit/3
    end
  end

  # ===========================================================================
  # Mutations
  # ===========================================================================

  mutation do
    # -------------------------------------------------------------------------
    # Authentication
    # -------------------------------------------------------------------------

    @desc "Authenticate and get a JWT token"
    field :login, :auth_result do
      arg :input, non_null(:login_input)

      resolve &UserResolver.login/3
    end

    # -------------------------------------------------------------------------
    # Response Actions
    # -------------------------------------------------------------------------

    @desc "Kill a process on an agent"
    field :kill_process, :kill_process_result do
      arg :input, non_null(:kill_process_input)

      resolve &ResponseResolver.kill_process/3
    end

    @desc "Quarantine a file on an agent"
    field :quarantine_file, :quarantine_result do
      arg :input, non_null(:quarantine_file_input)

      resolve &ResponseResolver.quarantine_file/3
    end

    @desc "Isolate a host from the network"
    field :isolate_host, :isolate_result do
      arg :input, non_null(:isolate_host_input)

      resolve &ResponseResolver.isolate_host/3
    end

    @desc "Remove network isolation from a host"
    field :unisolate_host, :isolate_result do
      arg :agent_id, non_null(:id)

      resolve &ResponseResolver.unisolate_host/3
    end

    @desc "Block an IP address"
    field :block_ip, :block_result do
      arg :input, non_null(:block_ip_input)

      resolve &ResponseResolver.block_ip/3
    end

    @desc "Block a domain"
    field :block_domain, :block_result do
      arg :input, non_null(:block_domain_input)

      resolve &ResponseResolver.block_domain/3
    end

    @desc "Trigger a malware scan on a path"
    field :scan_path, :scan_result do
      arg :input, non_null(:scan_path_input)

      resolve &ResponseResolver.scan_path/3
    end

    @desc "Collect forensic artifacts from an agent"
    field :collect_forensics, :forensics_result do
      arg :input, non_null(:collect_forensics_input)

      resolve &ResponseResolver.collect_forensics/3
    end

    # -------------------------------------------------------------------------
    # Agent Management
    # -------------------------------------------------------------------------

    @desc "Isolate an agent"
    field :isolate_agent, :mutation_result do
      arg :input, non_null(:isolate_agent_input)

      resolve &AgentResolver.isolate_agent/3
    end

    @desc "Unisolate an agent"
    field :unisolate_agent, :mutation_result do
      arg :agent_id, non_null(:id)

      resolve &AgentResolver.unisolate_agent/3
    end

    @desc "Restart an agent"
    field :restart_agent, :mutation_result do
      arg :agent_id, non_null(:id)

      resolve &AgentResolver.restart_agent/3
    end

    # -------------------------------------------------------------------------
    # Alert Management
    # -------------------------------------------------------------------------

    @desc "Update an alert"
    field :update_alert, :alert do
      arg :id, non_null(:id)
      arg :input, non_null(:update_alert_input)

      resolve &AlertResolver.update_alert/3
    end

    @desc "Assign an alert to a user"
    field :assign_alert, :alert do
      arg :id, non_null(:id)
      arg :user_id, non_null(:id)

      resolve &AlertResolver.assign_alert/3
    end

    @desc "Resolve an alert"
    field :resolve_alert, :alert do
      arg :id, non_null(:id)
      arg :resolution_notes, :string

      resolve &AlertResolver.resolve_alert/3
    end

    @desc "Mark an alert as false positive"
    field :mark_false_positive, :alert do
      arg :id, non_null(:id)
      arg :reason, :string

      resolve &AlertResolver.mark_false_positive/3
    end

    @desc "Bulk update alerts"
    field :bulk_update_alerts, :mutation_result do
      arg :input, non_null(:bulk_alert_input)

      resolve &AlertResolver.bulk_update_alerts/3
    end

    # -------------------------------------------------------------------------
    # Playbook Management
    # -------------------------------------------------------------------------

    @desc "Create a new playbook"
    field :create_playbook, :playbook do
      arg :input, non_null(:create_playbook_input)

      resolve &PlaybookResolver.create_playbook/3
    end

    @desc "Update a playbook"
    field :update_playbook, :playbook do
      arg :id, non_null(:id)
      arg :input, non_null(:update_playbook_input)

      resolve &PlaybookResolver.update_playbook/3
    end

    @desc "Delete a playbook"
    field :delete_playbook, :delete_result do
      arg :id, non_null(:id)

      resolve &PlaybookResolver.delete_playbook/3
    end

    @desc "Execute a playbook"
    field :execute_playbook, :playbook_execution do
      arg :input, non_null(:execute_playbook_input)

      resolve &PlaybookResolver.execute_playbook/3
    end

    @desc "Clone a playbook"
    field :clone_playbook, :playbook do
      arg :id, non_null(:id)
      arg :new_name, non_null(:string)

      resolve &PlaybookResolver.clone_playbook/3
    end

    @desc "Approve a pending playbook execution"
    field :approve_execution, :playbook_execution do
      arg :execution_id, non_null(:id)

      resolve &PlaybookResolver.approve_execution/3
    end

    @desc "Cancel a playbook execution"
    field :cancel_execution, :playbook_execution do
      arg :execution_id, non_null(:id)
      arg :reason, :string

      resolve &PlaybookResolver.cancel_execution/3
    end

    # -------------------------------------------------------------------------
    # Investigation Management
    # -------------------------------------------------------------------------

    @desc "Create a new investigation"
    field :create_investigation, :investigation do
      arg :input, non_null(:create_investigation_input)

      resolve &InvestigationResolver.create_investigation/3
    end

    @desc "Update an investigation"
    field :update_investigation, :investigation do
      arg :id, non_null(:id)
      arg :input, non_null(:update_investigation_input)

      resolve &InvestigationResolver.update_investigation/3
    end

    @desc "Add a note to an investigation"
    field :add_investigation_note, :investigation_note do
      arg :input, non_null(:add_investigation_note_input)

      resolve &InvestigationResolver.add_investigation_note/3
    end

    @desc "Add alerts to an investigation"
    field :add_alerts_to_investigation, :investigation do
      arg :investigation_id, non_null(:id)
      arg :alert_ids, non_null(list_of(non_null(:id)))

      resolve &InvestigationResolver.add_alerts_to_investigation/3
    end

    @desc "Close an investigation"
    field :close_investigation, :investigation do
      arg :id, non_null(:id)
      arg :findings, :string
      arg :recommendations, :string

      resolve &InvestigationResolver.close_investigation/3
    end

    @desc "Build investigation graph from an alert"
    field :build_investigation_graph, :investigation_graph do
      arg :alert_id, :id
      arg :process_id, :integer
      arg :agent_id, :id

      resolve &InvestigationResolver.build_investigation_graph/3
    end

    @desc "Run AI analysis on an investigation"
    field :ai_analyze_investigation, :ai_investigation_analysis do
      arg :investigation_id, non_null(:id)

      resolve &InvestigationResolver.ai_analyze_investigation/3
    end

    # -------------------------------------------------------------------------
    # Threat Intelligence
    # -------------------------------------------------------------------------

    @desc "Create a new IOC"
    field :create_ioc, :ioc do
      arg :input, non_null(:create_ioc_input)

      resolve &ThreatIntelResolver.create_ioc/3
    end

    @desc "Bulk import IOCs"
    field :bulk_import_iocs, :mutation_result do
      arg :input, non_null(:bulk_ioc_input)

      resolve &ThreatIntelResolver.bulk_import_iocs/3
    end

    @desc "Delete an IOC"
    field :delete_ioc, :delete_result do
      arg :id, non_null(:id)

      resolve &ThreatIntelResolver.delete_ioc/3
    end

    @desc "Enrich an IOC with threat intelligence"
    field :enrich_ioc, :enrichment_result do
      arg :input, non_null(:enrich_ioc_input)

      resolve &ThreatIntelResolver.enrich_ioc/3
    end

    @desc "Create a threat actor profile"
    field :create_threat_actor, :threat_actor do
      arg :input, non_null(:create_threat_actor_input)

      resolve &ThreatIntelResolver.create_threat_actor/3
    end

    @desc "Sync all threat intelligence feeds"
    field :sync_threat_feeds, :mutation_result do
      resolve &ThreatIntelResolver.sync_threat_feeds/3
    end

    # -------------------------------------------------------------------------
    # User Management
    # -------------------------------------------------------------------------

    @desc "Create a new user"
    field :create_user, :user do
      arg :input, non_null(:create_user_input)

      resolve &UserResolver.create_user/3
    end

    @desc "Update a user"
    field :update_user, :user do
      arg :id, non_null(:id)
      arg :input, non_null(:update_user_input)

      resolve &UserResolver.update_user/3
    end

    @desc "Delete a user"
    field :delete_user, :delete_result do
      arg :id, non_null(:id)

      resolve &UserResolver.delete_user/3
    end

    @desc "Assign a role to a user"
    field :assign_role, :user do
      arg :user_id, non_null(:id)
      arg :role_id, non_null(:id)

      resolve &UserResolver.assign_role/3
    end

    @desc "Revoke a role from a user"
    field :revoke_role, :user do
      arg :user_id, non_null(:id)
      arg :role_id, non_null(:id)

      resolve &UserResolver.revoke_role/3
    end
  end

  # ===========================================================================
  # Subscriptions
  # ===========================================================================

  subscription do
    @desc "Subscribe to new alerts"
    field :alert_created, :alert do
      config fn _args, %{context: context} ->
        org_id = context[:organization_id]
        {:ok, topic: "alerts:#{org_id || "all"}"}
      end

      trigger :create_alert, topic: fn alert ->
        "alerts:#{alert.organization_id || "all"}"
      end
    end

    @desc "Subscribe to alert updates"
    field :alert_updated, :alert do
      arg :alert_id, :id

      config fn args, %{context: context} ->
        org_id = context[:organization_id]
        case args[:alert_id] do
          nil -> {:ok, topic: "alert_updates:#{org_id || "all"}"}
          id -> {:ok, topic: "alert:#{id}"}
        end
      end
    end

    @desc "Subscribe to agent status changes"
    field :agent_status_changed, :agent_live do
      arg :agent_id, :id

      config fn args, %{context: context} ->
        org_id = context[:organization_id]
        case args[:agent_id] do
          nil -> {:ok, topic: "agent_status:#{org_id || "all"}"}
          id -> {:ok, topic: "agent:#{id}"}
        end
      end
    end

    @desc "Subscribe to real-time events"
    field :event_stream, :event do
      arg :agent_id, :id
      arg :event_type, :string

      config fn args, %{context: context} ->
        org_id = context[:organization_id]
        topic = case {args[:agent_id], args[:event_type]} do
          {nil, nil} -> "events:#{org_id || "all"}"
          {agent_id, nil} -> "events:agent:#{agent_id}"
          {nil, event_type} -> "events:type:#{event_type}:#{org_id || "all"}"
          {agent_id, event_type} -> "events:agent:#{agent_id}:#{event_type}"
        end
        {:ok, topic: topic}
      end
    end

    @desc "Subscribe to playbook execution updates"
    field :playbook_execution_updated, :playbook_execution do
      arg :execution_id, :id

      config fn args, _context ->
        case args[:execution_id] do
          nil -> {:ok, topic: "playbook_executions:all"}
          id -> {:ok, topic: "playbook_execution:#{id}"}
        end
      end
    end

    @desc "Subscribe to threat intelligence updates"
    field :threat_intel_updated, :ioc do
      config fn _args, %{context: context} ->
        org_id = context[:organization_id]
        {:ok, topic: "threat_intel:#{org_id || "all"}"}
      end
    end
  end

  # ===========================================================================
  # Context & Middleware
  # ===========================================================================

  def context(ctx) do
    loader =
      Dataloader.new()
      |> Dataloader.add_source(:db, TamanduaServerWeb.GraphQL.DataLoader.data())

    Map.put(ctx, :loader, loader)
  end

  def plugins do
    [Absinthe.Middleware.Dataloader] ++ Absinthe.Plugin.defaults()
  end

  # Authentication middleware - exempt public operations
  # Login and register are public (used to obtain tokens)
  def middleware(middleware, %{identifier: identifier}, %{identifier: :mutation})
      when identifier in [:login, :register, :refresh_token] do
    middleware ++ [TamanduaServerWeb.GraphQL.Middleware.ErrorHandler]
  end

  # Health check is public
  def middleware(middleware, %{identifier: :health}, %{identifier: :query}) do
    middleware
  end

  # All other queries and mutations require authentication
  def middleware(middleware, _field, %{identifier: type})
      when type in [:query, :mutation] do
    [TamanduaServerWeb.GraphQL.Middleware.Authentication | middleware] ++
      [TamanduaServerWeb.GraphQL.Middleware.ErrorHandler]
  end

  # Field resolvers and other types don't need auth middleware
  def middleware(middleware, _field, _object) do
    middleware
  end

  def serialize_datetime(nil), do: nil
  def serialize_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  def serialize_datetime(%NaiveDateTime{} = ndt), do: NaiveDateTime.to_iso8601(ndt)
  def serialize_datetime(other), do: to_string(other)

  def parse_datetime(%Absinthe.Blueprint.Input.String{value: value}) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _offset} ->
        {:ok, datetime}

      {:error, _} ->
        case NaiveDateTime.from_iso8601(value) do
          {:ok, ndt} -> {:ok, ndt}
          {:error, _} -> :error
        end
    end
  end

  def parse_datetime(%Absinthe.Blueprint.Input.Null{}), do: {:ok, nil}
  def parse_datetime(_), do: :error

  def serialize_json(value), do: value

  def parse_json(%Absinthe.Blueprint.Input.String{value: value}) do
    case Jason.decode(value) do
      {:ok, decoded} -> {:ok, decoded}
      {:error, _} -> :error
    end
  end

  def parse_json(%Absinthe.Blueprint.Input.Object{} = obj) do
    {:ok, Absinthe.Blueprint.Input.Object.values(obj)}
  end

  def parse_json(%Absinthe.Blueprint.Input.Null{}), do: {:ok, nil}
  def parse_json(%{} = value), do: {:ok, value}
  def parse_json(_), do: :error
end
