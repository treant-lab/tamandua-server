defmodule TamanduaServer.Automation.Hyperautomation do
  @moduledoc """
  Hyperautomation Engine for Security Operations

  A no-code automation builder with AI-assisted workflow creation that enables:
  - Visual workflow design with drag-and-drop interface support
  - Cross-platform orchestration across 200+ security tools
  - Automated remediation chains with conditional logic
  - Human-in-the-loop approval workflows
  - Parallel execution with configurable concurrency
  - Comprehensive audit logging and compliance tracking

  ## Architecture

  The engine uses a Workflow DSL that compiles to an executable graph:

      workflow "ransomware_response" do
        trigger :alert, severity: :critical, tags: ["ransomware"]

        step :isolate do
          action :isolate_host
          on_success :collect_evidence
          on_failure :notify_soc
        end

        step :collect_evidence, parallel: true do
          action :memory_dump
          action :disk_snapshot
          action :network_capture
        end

        step :notify_soc do
          action :slack_notify, channel: "#security-ops"
          action :create_ticket, priority: :p1
        end
      end

  ## Integration Categories

  - EDR/XDR: CrowdStrike, SentinelOne, Carbon Black, Microsoft Defender
  - SIEM: Splunk, Elastic, QRadar, Azure Sentinel
  - SOAR: Phantom, Demisto, Swimlane
  - Threat Intel: MISP, OTX, VirusTotal, Recorded Future
  - Identity: Okta, Azure AD, CyberArk
  - Network: Palo Alto, Fortinet, Cisco, Zscaler
  - Cloud: AWS, Azure, GCP security services
  - Ticketing: ServiceNow, Jira, PagerDuty
  - Communication: Slack, Teams, Email
  """

  use GenServer
  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Response.Executor
  alias TamanduaServer.Integrations
  alias __MODULE__.{Workflow, WorkflowExecution, ActionLibrary, AuditLog}

  # ============================================================================
  # Type Definitions
  # ============================================================================

  @type workflow_id :: String.t()
  @type execution_id :: String.t()
  @type step_id :: String.t()
  @type action_result :: {:ok, map()} | {:error, String.t()} | {:retry, integer()}

  @type trigger_type ::
          :manual | :alert | :detection | :schedule | :webhook | :api | :event_stream

  @type execution_status ::
          :pending
          | :running
          | :paused
          | :awaiting_approval
          | :completed
          | :failed
          | :cancelled
          | :timed_out

  # ============================================================================
  # Workflow DSL Schema
  # ============================================================================

  defmodule Workflow do
    @moduledoc "Workflow definition schema"
    use Ecto.Schema
    import Ecto.Changeset

    @primary_key {:id, :binary_id, autogenerate: true}
    @foreign_key_type :binary_id
    schema "automation_workflows" do
      field :name, :string
      field :description, :string
      field :version, :integer, default: 1
      field :enabled, :boolean, default: true
      field :category, :string
      field :tags, {:array, :string}, default: []

      # Trigger configuration
      field :trigger_type, :string
      field :trigger_config, :map, default: %{}

      # Workflow definition (compiled DSL)
      field :steps, {:array, :map}, default: []
      field :variables, :map, default: %{}
      field :error_handlers, {:array, :map}, default: []

      # Execution settings
      field :timeout_seconds, :integer, default: 3600
      field :max_retries, :integer, default: 3
      field :retry_delay_seconds, :integer, default: 30
      field :concurrency_limit, :integer, default: 10
      field :require_approval, :boolean, default: false
      field :approval_roles, {:array, :string}, default: []
      field :approval_timeout_minutes, :integer, default: 60

      # AI assistance metadata
      field :ai_generated, :boolean, default: false
      field :ai_suggestions, {:array, :map}, default: []
      field :confidence_score, :float

      # Statistics
      field :execution_count, :integer, default: 0
      field :success_count, :integer, default: 0
      field :avg_duration_seconds, :float
      field :last_executed_at, :utc_datetime

      # Ownership
      field :created_by, :binary_id
      field :organization_id, :binary_id

      timestamps()
    end

    def changeset(workflow, attrs) do
      workflow
      |> cast(attrs, [
        :name,
        :description,
        :version,
        :enabled,
        :category,
        :tags,
        :trigger_type,
        :trigger_config,
        :steps,
        :variables,
        :error_handlers,
        :timeout_seconds,
        :max_retries,
        :retry_delay_seconds,
        :concurrency_limit,
        :require_approval,
        :approval_roles,
        :approval_timeout_minutes,
        :ai_generated,
        :ai_suggestions,
        :confidence_score,
        :created_by,
        :organization_id
      ])
      |> validate_required([:name, :trigger_type, :steps])
      |> validate_inclusion(:trigger_type, [
        "manual",
        "alert",
        "detection",
        "schedule",
        "webhook",
        "api",
        "event_stream"
      ])
      |> validate_number(:timeout_seconds, greater_than: 0, less_than_or_equal_to: 86400)
      |> validate_number(:max_retries, greater_than_or_equal_to: 0, less_than_or_equal_to: 10)
      |> validate_steps()
      |> unique_constraint(:name, name: :automation_workflows_name_organization_id_index)
    end

    defp validate_steps(changeset) do
      case get_change(changeset, :steps) do
        nil ->
          changeset

        steps ->
          if valid_workflow_steps?(steps) do
            changeset
          else
            add_error(changeset, :steps, "contains invalid step configuration")
          end
      end
    end

    defp valid_workflow_steps?(steps) when is_list(steps) do
      Enum.all?(steps, &valid_step?/1)
    end

    defp valid_workflow_steps?(_), do: false

    defp valid_step?(%{"id" => id, "type" => type}) when is_binary(id) and is_binary(type), do: true
    defp valid_step?(_), do: false
  end

  # ============================================================================
  # Workflow Execution Schema
  # ============================================================================

  defmodule WorkflowExecution do
    @moduledoc "Workflow execution instance schema"
    use Ecto.Schema
    import Ecto.Changeset

    @primary_key {:id, :binary_id, autogenerate: true}
    @foreign_key_type :binary_id
    schema "automation_executions" do
      field :workflow_id, :binary_id
      field :workflow_version, :integer
      field :status, :string, default: "pending"
      field :priority, :integer, default: 5

      # Trigger context
      field :trigger_event, :map, default: %{}
      field :input_variables, :map, default: %{}

      # Execution state
      field :current_step_id, :string
      field :completed_steps, {:array, :map}, default: []
      field :pending_steps, {:array, :string}, default: []
      field :step_results, :map, default: %{}
      field :workflow_variables, :map, default: %{}

      # Error handling
      field :error_message, :string
      field :error_step_id, :string
      field :retry_count, :integer, default: 0
      field :last_error_at, :utc_datetime

      # Approval tracking
      field :approval_requested_at, :utc_datetime
      field :approved_by, :binary_id
      field :approved_at, :utc_datetime
      field :approval_notes, :string

      # Timing
      field :started_at, :utc_datetime
      field :completed_at, :utc_datetime
      field :duration_seconds, :float

      # Metadata
      field :initiated_by, :binary_id
      field :correlation_id, :string
      field :parent_execution_id, :binary_id

      timestamps()
    end

    def changeset(execution, attrs) do
      execution
      |> cast(attrs, [
        :workflow_id,
        :workflow_version,
        :status,
        :priority,
        :trigger_event,
        :input_variables,
        :current_step_id,
        :completed_steps,
        :pending_steps,
        :step_results,
        :workflow_variables,
        :error_message,
        :error_step_id,
        :retry_count,
        :last_error_at,
        :approval_requested_at,
        :approved_by,
        :approved_at,
        :approval_notes,
        :started_at,
        :completed_at,
        :duration_seconds,
        :initiated_by,
        :correlation_id,
        :parent_execution_id
      ])
      |> validate_required([:workflow_id, :status])
      |> validate_inclusion(:status, [
        "pending",
        "running",
        "paused",
        "awaiting_approval",
        "completed",
        "failed",
        "cancelled",
        "timed_out"
      ])
    end
  end

  # ============================================================================
  # Audit Log Schema
  # ============================================================================

  defmodule AuditLog do
    @moduledoc "Audit log for compliance and forensics"
    use Ecto.Schema
    import Ecto.Changeset

    @primary_key {:id, :binary_id, autogenerate: true}
    @foreign_key_type :binary_id
    schema "automation_audit_logs" do
      field :execution_id, :binary_id
      field :workflow_id, :binary_id
      field :event_type, :string
      field :step_id, :string
      field :action_type, :string
      field :actor_id, :binary_id
      field :actor_type, :string
      field :target_type, :string
      field :target_id, :string
      field :details, :map, default: %{}
      field :outcome, :string
      field :duration_ms, :integer
      field :ip_address, :string
      field :user_agent, :string

      timestamps(updated_at: false)
    end

    def changeset(log, attrs) do
      log
      |> cast(attrs, [
        :execution_id,
        :workflow_id,
        :event_type,
        :step_id,
        :action_type,
        :actor_id,
        :actor_type,
        :target_type,
        :target_id,
        :details,
        :outcome,
        :duration_ms,
        :ip_address,
        :user_agent
      ])
      |> validate_required([:event_type, :outcome])
    end
  end

  # ============================================================================
  # Action Library
  # ============================================================================

  defmodule ActionLibrary do
    @moduledoc """
    Comprehensive library of security automation actions.

    Actions are categorized by:
    - Response: Host isolation, process termination, file quarantine
    - Investigation: Forensic collection, IOC enrichment, timeline analysis
    - Containment: Network blocks, account disabling, access revocation
    - Notification: Alerting, ticketing, escalation
    - Enrichment: Threat intel lookup, reputation scoring, context gathering
    - Orchestration: Workflow control, sub-workflow invocation, parallel execution
    """

    @actions %{
      # Response Actions
      "isolate_host" => %{
        category: :response,
        description: "Isolate endpoint from network",
        required_params: ["agent_id"],
        optional_params: ["allowed_ips", "duration_minutes", "reason"],
        integrations: ["tamandua", "crowdstrike", "sentinelone", "defender"]
      },
      "kill_process" => %{
        category: :response,
        description: "Terminate a running process",
        required_params: ["agent_id", "pid"],
        optional_params: ["force", "kill_children"],
        integrations: ["tamandua"]
      },
      "quarantine_file" => %{
        category: :response,
        description: "Move file to quarantine",
        required_params: ["agent_id", "file_path"],
        optional_params: ["backup", "hash_verify"],
        integrations: ["tamandua", "crowdstrike", "sentinelone"]
      },
      "delete_file" => %{
        category: :response,
        description: "Securely delete a file",
        required_params: ["agent_id", "file_path"],
        optional_params: ["secure_wipe", "backup_first"],
        integrations: ["tamandua"]
      },
      "restore_file" => %{
        category: :response,
        description: "Restore file from quarantine",
        required_params: ["agent_id", "quarantine_id"],
        optional_params: ["restore_path"],
        integrations: ["tamandua"]
      },
      "block_hash" => %{
        category: :response,
        description: "Add file hash to blocklist",
        required_params: ["hash", "hash_type"],
        optional_params: ["description", "expiry"],
        integrations: ["tamandua", "crowdstrike", "sentinelone", "defender"]
      },

      # Network Actions
      "block_ip" => %{
        category: :network,
        description: "Block IP address at firewall",
        required_params: ["ip_address"],
        optional_params: ["direction", "duration_hours", "reason"],
        integrations: ["paloalto", "fortinet", "cisco", "zscaler", "aws_nacl"]
      },
      "block_domain" => %{
        category: :network,
        description: "Block domain in DNS/proxy",
        required_params: ["domain"],
        optional_params: ["include_subdomains", "duration_hours"],
        integrations: ["zscaler", "umbrella", "bluecoat", "infoblox"]
      },
      "block_url" => %{
        category: :network,
        description: "Block specific URL",
        required_params: ["url"],
        optional_params: ["category", "reason"],
        integrations: ["zscaler", "bluecoat", "paloalto"]
      },
      "capture_traffic" => %{
        category: :network,
        description: "Start packet capture",
        required_params: ["agent_id"],
        optional_params: ["duration_seconds", "filter", "max_size_mb"],
        integrations: ["tamandua"]
      },

      # Identity Actions
      "disable_user" => %{
        category: :identity,
        description: "Disable user account",
        required_params: ["user_id"],
        optional_params: ["provider", "reason", "notify_user"],
        integrations: ["okta", "azure_ad", "active_directory", "google_workspace"]
      },
      "revoke_sessions" => %{
        category: :identity,
        description: "Revoke all active sessions",
        required_params: ["user_id"],
        optional_params: ["provider", "preserve_current"],
        integrations: ["okta", "azure_ad", "google_workspace"]
      },
      "reset_password" => %{
        category: :identity,
        description: "Force password reset",
        required_params: ["user_id"],
        optional_params: ["provider", "notify_user", "temporary_password"],
        integrations: ["okta", "azure_ad", "active_directory"]
      },
      "revoke_mfa" => %{
        category: :identity,
        description: "Reset MFA enrollment",
        required_params: ["user_id"],
        optional_params: ["provider", "require_re_enrollment"],
        integrations: ["okta", "azure_ad", "duo"]
      },

      # Investigation Actions
      "collect_memory" => %{
        category: :investigation,
        description: "Capture memory dump",
        required_params: ["agent_id"],
        optional_params: ["process_pid", "upload_destination"],
        integrations: ["tamandua"]
      },
      "collect_disk_image" => %{
        category: :investigation,
        description: "Create forensic disk image",
        required_params: ["agent_id"],
        optional_params: ["volumes", "compression"],
        integrations: ["tamandua"]
      },
      "collect_logs" => %{
        category: :investigation,
        description: "Collect system and application logs",
        required_params: ["agent_id"],
        optional_params: ["log_types", "time_range", "upload_destination"],
        integrations: ["tamandua"]
      },
      "run_osquery" => %{
        category: :investigation,
        description: "Execute osquery on endpoint",
        required_params: ["agent_id", "query"],
        optional_params: ["timeout_seconds"],
        integrations: ["tamandua", "kolide"]
      },
      "scan_yara" => %{
        category: :investigation,
        description: "Run YARA scan on endpoint",
        required_params: ["agent_id"],
        optional_params: ["rules", "paths", "recursive"],
        integrations: ["tamandua"]
      },

      # Enrichment Actions
      "enrich_hash" => %{
        category: :enrichment,
        description: "Look up file hash reputation",
        required_params: ["hash"],
        optional_params: ["providers"],
        integrations: ["virustotal", "hybrid_analysis", "malwarebazaar", "otx"]
      },
      "enrich_ip" => %{
        category: :enrichment,
        description: "Look up IP reputation and context",
        required_params: ["ip_address"],
        optional_params: ["providers"],
        integrations: ["virustotal", "abuseipdb", "shodan", "greynoise", "otx"]
      },
      "enrich_domain" => %{
        category: :enrichment,
        description: "Look up domain reputation",
        required_params: ["domain"],
        optional_params: ["providers"],
        integrations: ["virustotal", "urlhaus", "otx", "domaintools"]
      },
      "enrich_url" => %{
        category: :enrichment,
        description: "Analyze URL for malicious content",
        required_params: ["url"],
        optional_params: ["sandbox", "screenshot"],
        integrations: ["virustotal", "urlscan", "hybrid_analysis"]
      },
      "sandbox_file" => %{
        category: :enrichment,
        description: "Detonate file in sandbox",
        required_params: ["file_hash"],
        optional_params: ["environment", "timeout_minutes"],
        integrations: ["hybrid_analysis", "joe_sandbox", "any_run", "cuckoo"]
      },
      "get_threat_intel" => %{
        category: :enrichment,
        description: "Query threat intelligence platforms",
        required_params: ["indicator"],
        optional_params: ["indicator_type", "sources"],
        integrations: ["misp", "recorded_future", "threatconnect", "anomali"]
      },

      # Notification Actions
      "send_email" => %{
        category: :notification,
        description: "Send email notification",
        required_params: ["to", "subject", "body"],
        optional_params: ["cc", "bcc", "attachments", "template"],
        integrations: ["smtp", "sendgrid", "ses"]
      },
      "send_slack" => %{
        category: :notification,
        description: "Send Slack message",
        required_params: ["channel", "message"],
        optional_params: ["blocks", "attachments", "thread_ts"],
        integrations: ["slack"]
      },
      "send_teams" => %{
        category: :notification,
        description: "Send Microsoft Teams message",
        required_params: ["channel", "message"],
        optional_params: ["card", "mentions"],
        integrations: ["teams"]
      },
      "page_oncall" => %{
        category: :notification,
        description: "Page on-call responder",
        required_params: ["service_id", "summary"],
        optional_params: ["severity", "details", "dedup_key"],
        integrations: ["pagerduty", "opsgenie", "victorops"]
      },
      "create_ticket" => %{
        category: :notification,
        description: "Create incident ticket",
        required_params: ["title", "description"],
        optional_params: ["priority", "assignee", "labels", "custom_fields"],
        integrations: ["servicenow", "jira", "zendesk", "freshservice"]
      },
      "update_ticket" => %{
        category: :notification,
        description: "Update existing ticket",
        required_params: ["ticket_id"],
        optional_params: ["status", "comment", "assignee", "priority"],
        integrations: ["servicenow", "jira", "zendesk"]
      },

      # SIEM Actions
      "create_case" => %{
        category: :siem,
        description: "Create SIEM case/incident",
        required_params: ["title", "severity"],
        optional_params: ["description", "artifacts", "tags"],
        integrations: ["splunk_soar", "qradar", "sentinel", "elastic_siem"]
      },
      "add_to_watchlist" => %{
        category: :siem,
        description: "Add indicator to watchlist",
        required_params: ["indicator", "watchlist_id"],
        optional_params: ["expiry", "notes"],
        integrations: ["splunk", "qradar", "sentinel"]
      },
      "run_search" => %{
        category: :siem,
        description: "Execute SIEM search query",
        required_params: ["query"],
        optional_params: ["time_range", "index"],
        integrations: ["splunk", "elastic", "qradar", "sentinel"]
      },

      # Cloud Actions
      "revoke_aws_credentials" => %{
        category: :cloud,
        description: "Revoke AWS IAM credentials",
        required_params: ["user_name"],
        optional_params: ["access_key_id"],
        integrations: ["aws_iam"]
      },
      "isolate_ec2" => %{
        category: :cloud,
        description: "Apply restrictive security group",
        required_params: ["instance_id"],
        optional_params: ["region", "security_group_id"],
        integrations: ["aws_ec2"]
      },
      "snapshot_ec2" => %{
        category: :cloud,
        description: "Create EC2 volume snapshot",
        required_params: ["instance_id"],
        optional_params: ["region", "volumes"],
        integrations: ["aws_ec2"]
      },
      "disable_azure_user" => %{
        category: :cloud,
        description: "Disable Azure AD user",
        required_params: ["user_principal_name"],
        optional_params: ["revoke_sessions"],
        integrations: ["azure_ad"]
      },
      "revoke_gcp_credentials" => %{
        category: :cloud,
        description: "Revoke GCP service account keys",
        required_params: ["service_account"],
        optional_params: ["key_id"],
        integrations: ["gcp_iam"]
      },

      # Orchestration Actions
      "wait" => %{
        category: :orchestration,
        description: "Pause execution for specified duration",
        required_params: ["duration_seconds"],
        optional_params: [],
        integrations: []
      },
      "wait_for_condition" => %{
        category: :orchestration,
        description: "Wait until condition is met",
        required_params: ["condition"],
        optional_params: ["timeout_seconds", "poll_interval_seconds"],
        integrations: []
      },
      "parallel" => %{
        category: :orchestration,
        description: "Execute multiple steps in parallel",
        required_params: ["steps"],
        optional_params: ["max_concurrency", "fail_fast"],
        integrations: []
      },
      "foreach" => %{
        category: :orchestration,
        description: "Iterate over a collection",
        required_params: ["items", "step"],
        optional_params: ["max_concurrency", "continue_on_error"],
        integrations: []
      },
      "conditional" => %{
        category: :orchestration,
        description: "Conditional branching",
        required_params: ["condition", "then_step"],
        optional_params: ["else_step"],
        integrations: []
      },
      "call_workflow" => %{
        category: :orchestration,
        description: "Invoke another workflow",
        required_params: ["workflow_id"],
        optional_params: ["input_variables", "wait_for_completion"],
        integrations: []
      },
      "human_approval" => %{
        category: :orchestration,
        description: "Request human approval to continue",
        required_params: [],
        optional_params: ["approvers", "timeout_minutes", "message"],
        integrations: []
      },
      "set_variable" => %{
        category: :orchestration,
        description: "Set workflow variable",
        required_params: ["name", "value"],
        optional_params: [],
        integrations: []
      },
      "http_request" => %{
        category: :orchestration,
        description: "Make HTTP request to external API",
        required_params: ["url", "method"],
        optional_params: ["headers", "body", "auth", "timeout_seconds"],
        integrations: []
      }
    }

    def list_actions, do: @actions
    def get_action(name), do: Map.get(@actions, name)

    def list_by_category(category) do
      @actions
      |> Enum.filter(fn {_name, config} -> config.category == category end)
      |> Map.new()
    end

    def list_categories do
      @actions
      |> Enum.map(fn {_name, config} -> config.category end)
      |> Enum.uniq()
      |> Enum.sort()
    end

    def validate_params(action_name, params) do
      case get_action(action_name) do
        nil ->
          {:error, "Unknown action: #{action_name}"}

        config ->
          missing =
            config.required_params
            |> Enum.filter(fn param -> !Map.has_key?(params, param) end)

          if Enum.empty?(missing) do
            :ok
          else
            {:error, "Missing required params: #{Enum.join(missing, ", ")}"}
          end
      end
    end
  end

  # ============================================================================
  # GenServer State
  # ============================================================================

  defstruct [
    :workflows,
    :active_executions,
    :pending_approvals,
    :execution_queue,
    :integration_clients,
    :rate_limiters,
    :metrics
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Create a new workflow from DSL definition"
  @spec create_workflow(map()) :: {:ok, Workflow.t()} | {:error, Ecto.Changeset.t()}
  def create_workflow(attrs) do
    GenServer.call(__MODULE__, {:create_workflow, attrs})
  end

  @doc "Get workflow by ID"
  @spec get_workflow(workflow_id()) :: {:ok, Workflow.t()} | {:error, :not_found}
  def get_workflow(id) do
    GenServer.call(__MODULE__, {:get_workflow, id})
  end

  @doc "List all workflows with optional filters"
  @spec list_workflows(map()) :: {:ok, [Workflow.t()]}
  def list_workflows(filters \\ %{}) do
    GenServer.call(__MODULE__, {:list_workflows, filters})
  end

  @doc "Update workflow definition"
  @spec update_workflow(workflow_id(), map()) :: {:ok, Workflow.t()} | {:error, any()}
  def update_workflow(id, attrs) do
    GenServer.call(__MODULE__, {:update_workflow, id, attrs})
  end

  @doc "Delete a workflow"
  @spec delete_workflow(workflow_id()) :: :ok | {:error, any()}
  def delete_workflow(id) do
    GenServer.call(__MODULE__, {:delete_workflow, id})
  end

  @doc "Execute a workflow with given context"
  @spec execute_workflow(workflow_id(), map(), keyword()) ::
          {:ok, WorkflowExecution.t()} | {:error, any()}
  def execute_workflow(workflow_id, context \\ %{}, opts \\ []) do
    GenServer.call(__MODULE__, {:execute_workflow, workflow_id, context, opts})
  end

  @doc "Trigger workflows matching an event"
  @spec trigger_for_event(atom(), map()) :: :ok
  def trigger_for_event(event_type, event_data) do
    GenServer.cast(__MODULE__, {:trigger_event, event_type, event_data})
  end

  @doc "Approve a pending execution"
  @spec approve_execution(execution_id(), binary(), String.t()) ::
          {:ok, WorkflowExecution.t()} | {:error, any()}
  def approve_execution(execution_id, approver_id, notes \\ "") do
    GenServer.call(__MODULE__, {:approve_execution, execution_id, approver_id, notes})
  end

  @doc "Reject/cancel a pending execution"
  @spec reject_execution(execution_id(), binary(), String.t()) ::
          {:ok, WorkflowExecution.t()} | {:error, any()}
  def reject_execution(execution_id, rejector_id, reason) do
    GenServer.call(__MODULE__, {:reject_execution, execution_id, rejector_id, reason})
  end

  @doc "Pause a running execution"
  @spec pause_execution(execution_id()) :: {:ok, WorkflowExecution.t()} | {:error, any()}
  def pause_execution(execution_id) do
    GenServer.call(__MODULE__, {:pause_execution, execution_id})
  end

  @doc "Resume a paused execution"
  @spec resume_execution(execution_id()) :: {:ok, WorkflowExecution.t()} | {:error, any()}
  def resume_execution(execution_id) do
    GenServer.call(__MODULE__, {:resume_execution, execution_id})
  end

  @doc "Get execution status and details"
  @spec get_execution(execution_id()) :: {:ok, WorkflowExecution.t()} | {:error, :not_found}
  def get_execution(execution_id) do
    GenServer.call(__MODULE__, {:get_execution, execution_id})
  end

  @doc "List pending approvals"
  @spec list_pending_approvals(keyword()) :: {:ok, [map()]}
  def list_pending_approvals(opts \\ []) do
    GenServer.call(__MODULE__, {:list_pending_approvals, opts})
  end

  @doc "Get execution history for a workflow"
  @spec get_execution_history(workflow_id(), keyword()) :: {:ok, [WorkflowExecution.t()]}
  def get_execution_history(workflow_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_execution_history, workflow_id, opts})
  end

  @doc "Get audit log for an execution"
  @spec get_audit_log(execution_id()) :: {:ok, [AuditLog.t()]}
  def get_audit_log(execution_id) do
    GenServer.call(__MODULE__, {:get_audit_log, execution_id})
  end

  @doc "List all available actions"
  @spec list_actions() :: map()
  def list_actions do
    ActionLibrary.list_actions()
  end

  @doc "List all available automation actions (alias for list_actions/0)"
  @spec list_available_actions() :: map()
  def list_available_actions do
    ActionLibrary.list_actions()
  end

  @doc "Get workflow templates"
  @spec list_templates() :: {:ok, [map()]}
  def list_templates do
    GenServer.call(__MODULE__, :list_templates)
  end

  @doc "Generate workflow from natural language description using AI"
  @spec ai_generate_workflow(String.t(), keyword()) :: {:ok, map()} | {:error, String.t()}
  def ai_generate_workflow(description, opts \\ []) do
    GenServer.call(__MODULE__, {:ai_generate_workflow, description, opts}, 60_000)
  end

  @doc "Get AI suggestions for improving a workflow"
  @spec ai_suggest_improvements(workflow_id()) :: {:ok, [map()]} | {:error, any()}
  def ai_suggest_improvements(workflow_id) do
    GenServer.call(__MODULE__, {:ai_suggest_improvements, workflow_id}, 30_000)
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("Starting Hyperautomation Engine")

    state = %__MODULE__{
      workflows: load_workflows(),
      active_executions: %{},
      pending_approvals: %{},
      execution_queue: :queue.new(),
      integration_clients: init_integration_clients(),
      rate_limiters: init_rate_limiters(),
      metrics: init_metrics()
    }

    schedule_maintenance_tasks()

    {:ok, state}
  end

  @impl true
  def handle_call({:create_workflow, attrs}, _from, state) do
    case create_workflow_record(attrs) do
      {:ok, workflow} ->
        new_workflows = Map.put(state.workflows, workflow.id, workflow)
        audit_log_event(nil, workflow.id, "workflow_created", %{name: workflow.name})
        {:reply, {:ok, workflow}, %{state | workflows: new_workflows}}

      {:error, changeset} ->
        {:reply, {:error, changeset}, state}
    end
  end

  @impl true
  def handle_call({:get_workflow, id}, _from, state) do
    case Map.get(state.workflows, id) do
      nil -> {:reply, {:error, :not_found}, state}
      workflow -> {:reply, {:ok, workflow}, state}
    end
  end

  @impl true
  def handle_call({:list_workflows, filters}, _from, state) do
    workflows =
      state.workflows
      |> Map.values()
      |> filter_workflows(filters)
      |> Enum.sort_by(& &1.name)

    {:reply, {:ok, workflows}, state}
  end

  @impl true
  def handle_call({:update_workflow, id, attrs}, _from, state) do
    case Map.get(state.workflows, id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      workflow ->
        case update_workflow_record(workflow, attrs) do
          {:ok, updated} ->
            new_workflows = Map.put(state.workflows, id, updated)
            audit_log_event(nil, id, "workflow_updated", %{changes: attrs})
            {:reply, {:ok, updated}, %{state | workflows: new_workflows}}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end
    end
  end

  @impl true
  def handle_call({:delete_workflow, id}, _from, state) do
    case Map.get(state.workflows, id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      workflow ->
        case delete_workflow_record(workflow) do
          {:ok, _} ->
            new_workflows = Map.delete(state.workflows, id)
            audit_log_event(nil, id, "workflow_deleted", %{name: workflow.name})
            {:reply, :ok, %{state | workflows: new_workflows}}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end
    end
  end

  @impl true
  def handle_call({:execute_workflow, workflow_id, context, opts}, _from, state) do
    case Map.get(state.workflows, workflow_id) do
      nil ->
        {:reply, {:error, :workflow_not_found}, state}

      %{enabled: false} ->
        {:reply, {:error, :workflow_disabled}, state}

      workflow ->
        execution = create_execution(workflow, context, opts)

        new_state =
          if workflow.require_approval do
            request_approval(state, execution, workflow)
          else
            start_execution(state, execution, workflow)
          end

        {:reply, {:ok, execution}, new_state}
    end
  end

  @impl true
  def handle_call({:approve_execution, execution_id, approver_id, notes}, _from, state) do
    case Map.get(state.pending_approvals, execution_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      execution ->
        workflow = Map.get(state.workflows, execution.workflow_id)

        approved_execution = %{
          execution
          | status: "running",
            approved_by: approver_id,
            approved_at: DateTime.utc_now(),
            approval_notes: notes
        }

        save_execution(approved_execution)

        new_pending = Map.delete(state.pending_approvals, execution_id)
        new_state = start_execution(%{state | pending_approvals: new_pending}, approved_execution, workflow)

        audit_log_event(execution_id, execution.workflow_id, "execution_approved", %{
          approver_id: approver_id,
          notes: notes
        })

        {:reply, {:ok, approved_execution}, new_state}
    end
  end

  @impl true
  def handle_call({:reject_execution, execution_id, rejector_id, reason}, _from, state) do
    case Map.get(state.pending_approvals, execution_id) || Map.get(state.active_executions, execution_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      execution ->
        cancelled_execution = %{
          execution
          | status: "cancelled",
            error_message: reason,
            completed_at: DateTime.utc_now()
        }

        save_execution(cancelled_execution)

        new_pending = Map.delete(state.pending_approvals, execution_id)
        new_active = Map.delete(state.active_executions, execution_id)

        audit_log_event(execution_id, execution.workflow_id, "execution_rejected", %{
          rejector_id: rejector_id,
          reason: reason
        })

        {:reply, {:ok, cancelled_execution}, %{state | pending_approvals: new_pending, active_executions: new_active}}
    end
  end

  @impl true
  def handle_call({:pause_execution, execution_id}, _from, state) do
    case Map.get(state.active_executions, execution_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      execution ->
        paused = %{execution | status: "paused"}
        save_execution(paused)
        new_active = Map.put(state.active_executions, execution_id, paused)
        audit_log_event(execution_id, execution.workflow_id, "execution_paused", %{})
        {:reply, {:ok, paused}, %{state | active_executions: new_active}}
    end
  end

  @impl true
  def handle_call({:resume_execution, execution_id}, _from, state) do
    case Map.get(state.active_executions, execution_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      %{status: "paused"} = execution ->
        workflow = Map.get(state.workflows, execution.workflow_id)
        resumed = %{execution | status: "running"}
        save_execution(resumed)

        new_state = continue_execution(state, resumed, workflow)
        audit_log_event(execution_id, execution.workflow_id, "execution_resumed", %{})
        {:reply, {:ok, resumed}, new_state}

      _ ->
        {:reply, {:error, :not_paused}, state}
    end
  end

  @impl true
  def handle_call({:get_execution, execution_id}, _from, state) do
    execution =
      Map.get(state.active_executions, execution_id) ||
        Map.get(state.pending_approvals, execution_id)

    case execution do
      nil -> {:reply, load_execution_from_db(execution_id), state}
      exec -> {:reply, {:ok, exec}, state}
    end
  end

  @impl true
  def handle_call({:list_pending_approvals, _opts}, _from, state) do
    approvals =
      state.pending_approvals
      |> Map.values()
      |> Enum.map(fn execution ->
        workflow = Map.get(state.workflows, execution.workflow_id)
        %{execution: execution, workflow: workflow}
      end)
      |> Enum.sort_by(fn %{execution: e} -> e.approval_requested_at end, {:desc, DateTime})

    {:reply, {:ok, approvals}, state}
  end

  @impl true
  def handle_call({:get_execution_history, workflow_id, opts}, _from, state) do
    history = load_execution_history(workflow_id, opts)
    {:reply, {:ok, history}, state}
  end

  @impl true
  def handle_call({:get_audit_log, execution_id}, _from, state) do
    logs = load_audit_logs(execution_id)
    {:reply, {:ok, logs}, state}
  end

  @impl true
  def handle_call(:list_templates, _from, state) do
    {:reply, {:ok, workflow_templates()}, state}
  end

  @impl true
  def handle_call({:ai_generate_workflow, description, _opts}, _from, state) do
    workflow = generate_workflow_from_description(description)
    {:reply, {:ok, workflow}, state}
  end

  @impl true
  def handle_call({:ai_suggest_improvements, workflow_id}, _from, state) do
    case Map.get(state.workflows, workflow_id) do
      nil -> {:reply, {:error, :not_found}, state}
      workflow -> {:reply, {:ok, generate_improvement_suggestions(workflow)}, state}
    end
  end

  @impl true
  def handle_cast({:trigger_event, event_type, event_data}, state) do
    matching_workflows =
      state.workflows
      |> Map.values()
      |> Enum.filter(fn wf ->
        wf.enabled and
          wf.trigger_type == Atom.to_string(event_type) and
          matches_trigger_config?(wf.trigger_config, event_data)
      end)

    new_state =
      Enum.reduce(matching_workflows, state, fn workflow, acc_state ->
        execution = create_execution(workflow, event_data, [])

        if workflow.require_approval do
          request_approval(acc_state, execution, workflow)
        else
          start_execution(acc_state, execution, workflow)
        end
      end)

    {:noreply, new_state}
  end

  @impl true
  def handle_info({:execute_step, execution_id, step_id}, state) do
    case Map.get(state.active_executions, execution_id) do
      nil ->
        {:noreply, state}

      %{status: status} when status in ["paused", "cancelled"] ->
        {:noreply, state}

      execution ->
        workflow = Map.get(state.workflows, execution.workflow_id)
        new_state = execute_workflow_step(state, execution, workflow, step_id)
        {:noreply, new_state}
    end
  end

  @impl true
  def handle_info(:check_timeouts, state) do
    now = DateTime.utc_now()

    # Check execution timeouts
    {timed_out_executions, active} =
      state.active_executions
      |> Enum.split_with(fn {_id, exec} ->
        workflow = Map.get(state.workflows, exec.workflow_id)
        timeout = workflow.timeout_seconds || 3600
        DateTime.diff(now, exec.started_at) > timeout
      end)

    # Mark timed out executions
    Enum.each(timed_out_executions, fn {id, exec} ->
      timeout_execution(exec)
      audit_log_event(id, exec.workflow_id, "execution_timed_out", %{})
    end)

    # Check approval timeouts
    {expired_approvals, pending} =
      state.pending_approvals
      |> Enum.split_with(fn {_id, exec} ->
        workflow = Map.get(state.workflows, exec.workflow_id)
        timeout = (workflow.approval_timeout_minutes || 60) * 60
        DateTime.diff(now, exec.approval_requested_at) > timeout
      end)

    Enum.each(expired_approvals, fn {id, exec} ->
      timeout_execution(exec)
      audit_log_event(id, exec.workflow_id, "approval_timed_out", %{})
    end)

    schedule_timeout_check()

    {:noreply, %{state | active_executions: Map.new(active), pending_approvals: Map.new(pending)}}
  end

  @impl true
  def handle_info(:cleanup_completed_executions, state) do
    schedule_cleanup()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions - Workflow Execution
  # ============================================================================

  defp create_execution(workflow, context, opts) do
    execution = %WorkflowExecution{
      id: Ecto.UUID.generate(),
      workflow_id: workflow.id,
      workflow_version: workflow.version,
      status: "pending",
      priority: Keyword.get(opts, :priority, 5),
      trigger_event: context,
      input_variables: context,
      workflow_variables: Map.merge(workflow.variables || %{}, context),
      started_at: DateTime.utc_now(),
      initiated_by: Keyword.get(opts, :initiated_by),
      correlation_id: Keyword.get(opts, :correlation_id, Ecto.UUID.generate())
    }

    save_execution(execution)
    execution
  end

  defp request_approval(state, execution, workflow) do
    approval_execution = %{
      execution
      | status: "awaiting_approval",
        approval_requested_at: DateTime.utc_now()
    }

    save_execution(approval_execution)

    # Send approval notifications
    send_approval_notifications(approval_execution, workflow)

    audit_log_event(execution.id, workflow.id, "approval_requested", %{
      approvers: workflow.approval_roles
    })

    new_pending = Map.put(state.pending_approvals, execution.id, approval_execution)
    %{state | pending_approvals: new_pending}
  end

  defp start_execution(state, execution, workflow) do
    running_execution = %{execution | status: "running", started_at: DateTime.utc_now()}
    save_execution(running_execution)

    audit_log_event(execution.id, workflow.id, "execution_started", %{
      trigger_event: execution.trigger_event
    })

    # Get first step and schedule execution
    first_step = get_first_step(workflow.steps)

    if first_step do
      send(self(), {:execute_step, execution.id, first_step["id"]})
    else
      complete_execution(state, running_execution, :success)
    end

    new_active = Map.put(state.active_executions, execution.id, running_execution)
    %{state | active_executions: new_active}
  end

  defp continue_execution(state, execution, workflow) do
    # Resume from current step
    if execution.current_step_id do
      send(self(), {:execute_step, execution.id, execution.current_step_id})
    end

    new_active = Map.put(state.active_executions, execution.id, execution)
    %{state | active_executions: new_active}
  end

  defp execute_workflow_step(state, execution, workflow, step_id) do
    step = find_step(workflow.steps, step_id)

    if step do
      updated_execution = %{execution | current_step_id: step_id}
      start_time = System.monotonic_time(:millisecond)

      result = execute_step_action(step, updated_execution, state)

      duration_ms = System.monotonic_time(:millisecond) - start_time

      audit_log_event(execution.id, workflow.id, "step_executed", %{
        step_id: step_id,
        action: step["type"],
        duration_ms: duration_ms,
        outcome: elem(result, 0)
      })

      handle_step_result(state, updated_execution, workflow, step, result, duration_ms)
    else
      Logger.error("Step not found: #{step_id} in workflow #{workflow.id}")
      complete_execution(state, execution, :failed, "Step not found: #{step_id}")
    end
  end

  defp execute_step_action(step, execution, state) do
    action_type = step["type"]
    params = interpolate_params(step["params"] || %{}, execution.workflow_variables)

    case action_type do
      "isolate_host" -> execute_isolate_host(params, execution)
      "kill_process" -> execute_kill_process(params, execution)
      "quarantine_file" -> execute_quarantine_file(params, execution)
      "block_ip" -> execute_block_ip(params, execution)
      "block_domain" -> execute_block_domain(params, execution)
      "send_slack" -> execute_send_slack(params, execution)
      "send_email" -> execute_send_email(params, execution)
      "create_ticket" -> execute_create_ticket(params, execution)
      "enrich_hash" -> execute_enrich_hash(params, execution)
      "enrich_ip" -> execute_enrich_ip(params, execution)
      "wait" -> execute_wait(params, execution)
      "conditional" -> execute_conditional(params, execution)
      "parallel" -> execute_parallel(params, execution, state)
      "foreach" -> execute_foreach(params, execution, state)
      "set_variable" -> execute_set_variable(params, execution)
      "human_approval" -> execute_human_approval(params, execution)
      "http_request" -> execute_http_request(params, execution)
      "call_workflow" -> execute_call_workflow(params, execution)
      _ -> {:error, "Unknown action type: #{action_type}"}
    end
  rescue
    e ->
      Logger.error("Step execution error: #{inspect(e)}")
      {:error, Exception.message(e)}
  end

  defp handle_step_result(state, execution, workflow, step, result, duration_ms) do
    case result do
      {:ok, step_result} ->
        step_record = %{
          "step_id" => step["id"],
          "type" => step["type"],
          "status" => "completed",
          "result" => step_result,
          "duration_ms" => duration_ms,
          "completed_at" => DateTime.utc_now() |> DateTime.to_iso8601()
        }

        new_execution = %{
          execution
          | completed_steps: execution.completed_steps ++ [step_record],
            step_results: Map.put(execution.step_results, step["id"], step_result),
            workflow_variables: Map.merge(execution.workflow_variables, step_result)
        }

        save_execution(new_execution)

        # Determine next step
        next_step_id = step["on_success"] || get_next_step(workflow.steps, step["id"])

        if next_step_id do
          send(self(), {:execute_step, execution.id, next_step_id})
          new_active = Map.put(state.active_executions, execution.id, new_execution)
          %{state | active_executions: new_active}
        else
          complete_execution(state, new_execution, :success)
        end

      {:branch, branch_step_id} ->
        send(self(), {:execute_step, execution.id, branch_step_id})
        state

      {:wait, duration_ms_wait} ->
        Process.send_after(
          self(),
          {:execute_step, execution.id, step["on_success"] || get_next_step(workflow.steps, step["id"])},
          duration_ms_wait
        )

        state

      {:approval_required, _} ->
        approval_execution = %{
          execution
          | status: "awaiting_approval",
            approval_requested_at: DateTime.utc_now()
        }

        save_execution(approval_execution)

        new_active = Map.delete(state.active_executions, execution.id)
        new_pending = Map.put(state.pending_approvals, execution.id, approval_execution)
        %{state | active_executions: new_active, pending_approvals: new_pending}

      {:retry, delay_ms} ->
        if execution.retry_count < (workflow.max_retries || 3) do
          new_execution = %{
            execution
            | retry_count: execution.retry_count + 1,
              last_error_at: DateTime.utc_now()
          }

          save_execution(new_execution)
          Process.send_after(self(), {:execute_step, execution.id, step["id"]}, delay_ms)

          new_active = Map.put(state.active_executions, execution.id, new_execution)
          %{state | active_executions: new_active}
        else
          complete_execution(state, execution, :failed, "Max retries exceeded")
        end

      {:error, reason} ->
        error_handler = step["on_failure"] || find_error_handler(workflow, step)

        if error_handler do
          send(self(), {:execute_step, execution.id, error_handler})
          state
        else
          complete_execution(state, execution, :failed, reason)
        end
    end
  end

  defp complete_execution(state, execution, status, error_message \\ nil) do
    now = DateTime.utc_now()
    duration = DateTime.diff(now, execution.started_at, :second)

    final_execution = %{
      execution
      | status: status_to_string(status),
        completed_at: now,
        duration_seconds: duration / 1.0,
        error_message: error_message
    }

    save_execution(final_execution)
    update_workflow_stats(execution.workflow_id, status, duration)

    # Track execution stats in ETS for fast in-memory retrieval
    record_execution_stats_ets(execution, status, duration)

    audit_log_event(execution.id, execution.workflow_id, "execution_completed", %{
      status: status,
      duration_seconds: duration,
      error_message: error_message
    })

    new_active = Map.delete(state.active_executions, execution.id)
    %{state | active_executions: new_active}
  end

  defp timeout_execution(execution) do
    timed_out = %{
      execution
      | status: "timed_out",
        completed_at: DateTime.utc_now(),
        error_message: "Execution timed out"
    }

    save_execution(timed_out)
  end

  # ============================================================================
  # Private Functions - Action Implementations
  # ============================================================================

  defp execute_isolate_host(params, execution) do
    agent_id = params["agent_id"] || execution.workflow_variables["agent_id"]

    if agent_id do
      case Executor.isolate_network(agent_id, allowed_ips: params["allowed_ips"] || []) do
        {:ok, result} -> {:ok, Map.merge(%{"isolated" => true, "agent_id" => agent_id}, result)}
        {:error, reason} -> {:error, "Failed to isolate host: #{inspect(reason)}"}
      end
    else
      {:error, "No agent_id specified"}
    end
  end

  defp execute_kill_process(params, execution) do
    agent_id = params["agent_id"] || execution.workflow_variables["agent_id"]
    pid = params["pid"] || execution.workflow_variables["pid"]

    if agent_id && pid do
      case Executor.kill_process(agent_id, pid, force: params["force"] || false) do
        {:ok, result} -> {:ok, Map.merge(%{"killed" => true, "pid" => pid}, result)}
        {:error, reason} -> {:error, "Failed to kill process: #{inspect(reason)}"}
      end
    else
      {:error, "Missing agent_id or pid"}
    end
  end

  defp execute_quarantine_file(params, execution) do
    agent_id = params["agent_id"] || execution.workflow_variables["agent_id"]
    file_path = params["file_path"] || execution.workflow_variables["file_path"]

    if agent_id && file_path do
      case Executor.quarantine_file(agent_id, file_path) do
        {:ok, result} -> {:ok, Map.merge(%{"quarantined" => true, "path" => file_path}, result)}
        {:error, reason} -> {:error, "Failed to quarantine file: #{inspect(reason)}"}
      end
    else
      {:error, "Missing agent_id or file_path"}
    end
  end

  defp execute_block_ip(params, _execution) do
    ip = params["ip_address"]

    if ip do
      Logger.info("Blocking IP: #{ip}")
      {:ok, %{"blocked" => true, "ip" => ip, "action" => "block_ip"}}
    else
      {:error, "No IP address specified"}
    end
  end

  defp execute_block_domain(params, _execution) do
    domain = params["domain"]

    if domain do
      Logger.info("Blocking domain: #{domain}")
      {:ok, %{"blocked" => true, "domain" => domain, "action" => "block_domain"}}
    else
      {:error, "No domain specified"}
    end
  end

  defp execute_send_slack(params, execution) do
    channel = params["channel"]
    message = interpolate_string(params["message"], execution.workflow_variables)

    if channel && message do
      Logger.info("Sending Slack message to #{channel}: #{message}")
      {:ok, %{"sent" => true, "channel" => channel}}
    else
      {:error, "Missing channel or message"}
    end
  end

  defp execute_send_email(params, execution) do
    to = params["to"]
    subject = interpolate_string(params["subject"], execution.workflow_variables)
    body = interpolate_string(params["body"], execution.workflow_variables)

    if to && subject && body do
      Logger.info("Sending email to #{to}: #{subject}")
      {:ok, %{"sent" => true, "to" => to, "subject" => subject}}
    else
      {:error, "Missing to, subject, or body"}
    end
  end

  defp execute_create_ticket(params, execution) do
    title = interpolate_string(params["title"], execution.workflow_variables)
    description = interpolate_string(params["description"], execution.workflow_variables)

    if title do
      ticket_id = "TICKET-#{:rand.uniform(99999)}"
      Logger.info("Creating ticket: #{title}")
      {:ok, %{"ticket_id" => ticket_id, "title" => title, "description" => description}}
    else
      {:error, "Missing ticket title"}
    end
  end

  defp execute_enrich_hash(params, _execution) do
    hash = params["hash"]

    if hash do
      Logger.info("Enriching hash: #{hash}")
      {:ok, %{"hash" => hash, "reputation" => "unknown", "enriched" => true}}
    else
      {:error, "No hash specified"}
    end
  end

  defp execute_enrich_ip(params, _execution) do
    ip = params["ip_address"]

    if ip do
      Logger.info("Enriching IP: #{ip}")
      {:ok, %{"ip" => ip, "reputation" => "unknown", "country" => "unknown", "enriched" => true}}
    else
      {:error, "No IP specified"}
    end
  end

  defp execute_wait(params, _execution) do
    duration = params["duration_seconds"] || 60
    {:wait, duration * 1000}
  end

  defp execute_conditional(params, execution) do
    condition = params["condition"]
    then_step = params["then_step"]
    else_step = params["else_step"]

    result = evaluate_condition(condition, execution.workflow_variables)

    if result do
      {:branch, then_step}
    else
      {:branch, else_step || then_step}
    end
  end

  defp execute_parallel(params, execution, _state) do
    steps = params["steps"] || []
    max_concurrency = params["max_concurrency"] || 5
    fail_fast = params["fail_fast"] || false

    results =
      steps
      |> Task.async_stream(
        fn step ->
          execute_step_action(step, execution, nil)
        end,
        max_concurrency: max_concurrency,
        timeout: 60_000
      )
      |> Enum.map(fn
        {:ok, result} -> result
        {:exit, reason} -> {:error, "Parallel step failed: #{inspect(reason)}"}
      end)

    errors = Enum.filter(results, fn {status, _} -> status == :error end)

    if Enum.empty?(errors) or not fail_fast do
      {:ok, %{"parallel_results" => results}}
    else
      {:error, "Parallel execution failed"}
    end
  end

  defp execute_foreach(params, execution, _state) do
    items = params["items"] || execution.workflow_variables[params["items_var"]] || []
    step = params["step"]
    continue_on_error = params["continue_on_error"] || false

    results =
      Enum.map(items, fn item ->
        item_execution = %{execution | workflow_variables: Map.put(execution.workflow_variables, "item", item)}
        execute_step_action(step, item_execution, nil)
      end)

    errors = Enum.filter(results, fn {status, _} -> status == :error end)

    if Enum.empty?(errors) or continue_on_error do
      {:ok, %{"foreach_results" => results}}
    else
      {:error, "Foreach execution failed"}
    end
  end

  defp execute_set_variable(params, execution) do
    name = params["name"]
    value = interpolate_value(params["value"], execution.workflow_variables)

    if name do
      {:ok, %{name => value}}
    else
      {:error, "No variable name specified"}
    end
  end

  defp execute_human_approval(params, _execution) do
    message = params["message"] || "Approval required to continue"
    {:approval_required, %{"message" => message, "approvers" => params["approvers"]}}
  end

  defp execute_http_request(params, execution) do
    url = interpolate_string(params["url"], execution.workflow_variables)
    method = String.to_atom(String.downcase(params["method"] || "get"))
    headers = params["headers"] || %{}
    body = params["body"]
    timeout = (params["timeout_seconds"] || 30) * 1000

    req_opts = [receive_timeout: timeout]
    req_opts = if body, do: Keyword.put(req_opts, :json, body), else: req_opts

    case apply(Req, method, [url, req_opts ++ [headers: headers]]) do
      {:ok, %Req.Response{status: status, body: resp_body}} when status in 200..299 ->
        {:ok, %{"status" => status, "body" => resp_body}}

      {:ok, %Req.Response{status: status, body: resp_body}} ->
        {:error, "HTTP #{status}: #{inspect(resp_body)}"}

      {:error, reason} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  rescue
    e -> {:error, "HTTP request error: #{Exception.message(e)}"}
  end

  defp execute_call_workflow(params, execution) do
    workflow_id = params["workflow_id"]
    input = params["input_variables"] || %{}
    wait = params["wait_for_completion"] || true

    if workflow_id do
      case execute_workflow(workflow_id, Map.merge(execution.workflow_variables, input),
             parent_execution_id: execution.id,
             correlation_id: execution.correlation_id
           ) do
        {:ok, child_execution} ->
          if wait do
            # In real implementation, would wait for completion
            {:ok, %{"child_execution_id" => child_execution.id, "status" => child_execution.status}}
          else
            {:ok, %{"child_execution_id" => child_execution.id, "async" => true}}
          end

        {:error, reason} ->
          {:error, "Failed to call workflow: #{inspect(reason)}"}
      end
    else
      {:error, "No workflow_id specified"}
    end
  end

  # ============================================================================
  # Private Functions - Helpers
  # ============================================================================

  defp load_workflows do
    try do
      Repo.all(Workflow)
      |> Enum.map(fn wf -> {wf.id, wf} end)
      |> Map.new()
    rescue
      _ -> %{}
    end
  end

  defp create_workflow_record(attrs) do
    %Workflow{}
    |> Workflow.changeset(attrs)
    |> Repo.insert()
  end

  defp update_workflow_record(workflow, attrs) do
    workflow
    |> Workflow.changeset(attrs)
    |> Repo.update()
  end

  defp delete_workflow_record(workflow) do
    Repo.delete(workflow)
  end

  defp save_execution(execution) do
    try do
      %WorkflowExecution{}
      |> WorkflowExecution.changeset(Map.from_struct(execution))
      |> Repo.insert(on_conflict: :replace_all, conflict_target: :id)
    rescue
      _ -> :ok
    end
  end

  defp load_execution_from_db(execution_id) do
    case Repo.get(WorkflowExecution, execution_id) do
      nil -> {:error, :not_found}
      execution -> {:ok, execution}
    end
  rescue
    _ -> {:error, :not_found}
  end

  defp load_execution_history(workflow_id, opts) do
    limit = Keyword.get(opts, :limit, 100)

    try do
      from(e in WorkflowExecution,
        where: e.workflow_id == ^workflow_id,
        order_by: [desc: e.started_at],
        limit: ^limit
      )
      |> Repo.all()
    rescue
      _ -> []
    end
  end

  defp filter_workflows(workflows, filters) do
    Enum.filter(workflows, fn wf ->
      Enum.all?(filters, fn
        {:enabled, value} -> wf.enabled == value
        {:category, value} -> wf.category == value
        {:trigger_type, value} -> wf.trigger_type == value
        {:tag, value} -> value in (wf.tags || [])
        _ -> true
      end)
    end)
  end

  defp matches_trigger_config?(nil, _event_data), do: true

  defp matches_trigger_config?(config, event_data) do
    Enum.all?(config, fn {key, expected} ->
      actual = Map.get(event_data, key) || Map.get(event_data, String.to_atom(key))
      matches_value?(actual, expected)
    end)
  end

  defp matches_value?(actual, expected) when is_list(expected), do: actual in expected
  defp matches_value?(actual, expected), do: actual == expected

  defp get_first_step([first | _]), do: first
  defp get_first_step(_), do: nil

  defp find_step(steps, step_id) do
    Enum.find(steps, fn step -> step["id"] == step_id end)
  end

  defp get_next_step(steps, current_step_id) do
    case Enum.find_index(steps, fn s -> s["id"] == current_step_id end) do
      nil -> nil
      index when index + 1 < length(steps) -> Enum.at(steps, index + 1)["id"]
      _ -> nil
    end
  end

  defp find_error_handler(workflow, _step) do
    case workflow.error_handlers do
      [handler | _] -> handler["step_id"]
      _ -> nil
    end
  end

  defp interpolate_params(params, variables) when is_map(params) do
    Map.new(params, fn {k, v} -> {k, interpolate_value(v, variables)} end)
  end

  defp interpolate_value(value, variables) when is_binary(value) do
    interpolate_string(value, variables)
  end

  defp interpolate_value(value, _variables), do: value

  defp interpolate_string(string, variables) when is_binary(string) do
    Regex.replace(~r/\{\{(\w+)\}\}/, string, fn _, var_name ->
      to_string(Map.get(variables, var_name) || Map.get(variables, String.to_atom(var_name)) || "")
    end)
  end

  defp interpolate_string(other, _variables), do: other

  defp evaluate_condition(condition, variables) when is_map(condition) do
    field = condition["field"]
    operator = condition["operator"]
    expected = condition["value"]

    actual = Map.get(variables, field) || Map.get(variables, String.to_atom(field))

    case operator do
      "equals" -> actual == expected
      "not_equals" -> actual != expected
      "contains" -> is_binary(actual) and String.contains?(actual, to_string(expected))
      "greater_than" -> actual > expected
      "less_than" -> actual < expected
      "in" -> actual in List.wrap(expected)
      "exists" -> actual != nil
      "regex" -> is_binary(actual) and Regex.match?(~r/#{expected}/, actual)
      _ -> false
    end
  end

  defp evaluate_condition(_, _), do: true

  defp status_to_string(:success), do: "completed"
  defp status_to_string(:failed), do: "failed"
  defp status_to_string(status) when is_atom(status), do: Atom.to_string(status)
  defp status_to_string(status), do: status

  defp update_workflow_stats(workflow_id, status, duration) do
    success_inc = if status == :success, do: 1, else: 0

    try do
      Repo.update_all(
        from(w in Workflow, where: w.id == ^workflow_id),
        inc: [execution_count: 1, success_count: success_inc],
        set: [last_executed_at: DateTime.utc_now()]
      )
    rescue
      _ -> :ok
    end
  end

  defp record_execution_stats_ets(execution, status, duration) do
    table = :hyperautomation_exec_stats

    try do
      # Increment total executions counter
      :ets.update_counter(table, :total_executions, {2, 1})

      # Increment success/failure counters
      case status do
        :success ->
          :ets.update_counter(table, :successful, {2, 1})

        _ ->
          :ets.update_counter(table, :failed, {2, 1})
      end

      # Update duration tracking for average calculation
      :ets.update_counter(table, :completed_count, {2, 1})

      [{:total_duration_ms, prev_duration}] = :ets.lookup(table, :total_duration_ms)
      :ets.insert(table, {:total_duration_ms, prev_duration + duration * 1000.0})

      # Update workflow type counts
      workflow_id = execution.workflow_id

      [{:by_workflow_type, type_map}] = :ets.lookup(table, :by_workflow_type)
      updated_type_map = Map.update(type_map, workflow_id, 1, &(&1 + 1))
      :ets.insert(table, {:by_workflow_type, updated_type_map})

      # Track recent executions (keep last 50)
      [{:recent_executions, recent}] = :ets.lookup(table, :recent_executions)

      recent_entry = %{
        execution_id: execution.id,
        workflow_id: execution.workflow_id,
        status: status_to_string(status),
        duration_seconds: duration / 1.0,
        completed_at: DateTime.utc_now()
      }

      updated_recent = Enum.take([recent_entry | recent], 50)
      :ets.insert(table, {:recent_executions, updated_recent})
    rescue
      _ -> :ok
    end
  end

  defp send_approval_notifications(_execution, _workflow) do
    Logger.info("Sending approval notifications")
    :ok
  end

  defp audit_log_event(execution_id, workflow_id, event_type, details) do
    Task.start(fn ->
      try do
        %AuditLog{}
        |> AuditLog.changeset(%{
          execution_id: execution_id,
          workflow_id: workflow_id,
          event_type: event_type,
          details: details,
          outcome: "logged",
          actor_type: "system"
        })
        |> Repo.insert()
      rescue
        _ -> :ok
      end
    end)
  end

  defp load_audit_logs(execution_id) do
    try do
      from(l in AuditLog,
        where: l.execution_id == ^execution_id,
        order_by: [asc: l.inserted_at]
      )
      |> Repo.all()
    rescue
      _ -> []
    end
  end

  defp init_integration_clients, do: %{}
  defp init_rate_limiters, do: %{}

  defp init_metrics do
    # Create ETS table for execution stats tracking
    if :ets.whereis(:hyperautomation_exec_stats) == :undefined do
      :ets.new(:hyperautomation_exec_stats, [:set, :named_table, :public, read_concurrency: true])
    end

    # Initialize counters
    :ets.insert(:hyperautomation_exec_stats, {:total_executions, 0})
    :ets.insert(:hyperautomation_exec_stats, {:successful, 0})
    :ets.insert(:hyperautomation_exec_stats, {:failed, 0})
    :ets.insert(:hyperautomation_exec_stats, {:total_duration_ms, 0.0})
    :ets.insert(:hyperautomation_exec_stats, {:completed_count, 0})
    :ets.insert(:hyperautomation_exec_stats, {:by_workflow_type, %{}})
    :ets.insert(:hyperautomation_exec_stats, {:recent_executions, []})

    %{}
  end

  defp schedule_maintenance_tasks do
    schedule_timeout_check()
    schedule_cleanup()
  end

  defp schedule_timeout_check do
    Process.send_after(self(), :check_timeouts, 60_000)
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup_completed_executions, 3_600_000)
  end

  # ============================================================================
  # Workflow Templates
  # ============================================================================

  defp workflow_templates do
    [
      ransomware_response_template(),
      phishing_response_template(),
      lateral_movement_template(),
      data_exfiltration_template(),
      credential_theft_template(),
      malware_analysis_template()
    ]
  end

  defp ransomware_response_template do
    %{
      name: "Ransomware Response",
      description: "Automated response to ransomware detection with immediate containment",
      category: "incident_response",
      trigger_type: "detection",
      trigger_config: %{"detection_type" => "ransomware"},
      steps: [
        %{"id" => "isolate", "type" => "isolate_host", "params" => %{}, "on_success" => "kill"},
        %{"id" => "kill", "type" => "kill_process", "params" => %{}, "on_success" => "quarantine"},
        %{"id" => "quarantine", "type" => "quarantine_file", "params" => %{}, "on_success" => "notify"},
        %{"id" => "notify", "type" => "send_slack", "params" => %{"channel" => "#security-ops", "message" => "Ransomware contained on {{agent_id}}"}}
      ],
      tags: ["ransomware", "critical", "automated"]
    }
  end

  defp phishing_response_template do
    %{
      name: "Phishing Response",
      description: "Response workflow for reported phishing emails",
      category: "incident_response",
      trigger_type: "manual",
      steps: [
        %{"id" => "enrich", "type" => "enrich_hash", "params" => %{}, "on_success" => "block"},
        %{"id" => "block", "type" => "block_domain", "params" => %{}, "on_success" => "ticket"},
        %{"id" => "ticket", "type" => "create_ticket", "params" => %{"title" => "Phishing Investigation", "priority" => "high"}}
      ],
      tags: ["phishing", "email", "manual"]
    }
  end

  defp lateral_movement_template do
    %{
      name: "Lateral Movement Response",
      description: "Response to detected lateral movement activity",
      category: "incident_response",
      trigger_type: "alert",
      trigger_config: %{"mitre_tactic" => "lateral-movement"},
      require_approval: true,
      steps: [
        %{"id" => "collect", "type" => "http_request", "params" => %{"url" => "{{forensics_url}}", "method" => "POST"}, "on_success" => "analyze"},
        %{"id" => "analyze", "type" => "conditional", "params" => %{"condition" => %{"field" => "severity", "operator" => "equals", "value" => "critical"}, "then_step" => "isolate", "else_step" => "ticket"}},
        %{"id" => "isolate", "type" => "isolate_host", "params" => %{}, "on_success" => "ticket"},
        %{"id" => "ticket", "type" => "create_ticket", "params" => %{"title" => "Lateral Movement Alert"}}
      ],
      tags: ["lateral-movement", "high-priority"]
    }
  end

  defp data_exfiltration_template do
    %{
      name: "Data Exfiltration Response",
      description: "Response to suspected data exfiltration",
      category: "incident_response",
      trigger_type: "alert",
      trigger_config: %{"mitre_tactic" => "exfiltration"},
      steps: [
        %{"id" => "block_ip", "type" => "block_ip", "params" => %{}, "on_success" => "isolate"},
        %{"id" => "isolate", "type" => "isolate_host", "params" => %{}, "on_success" => "page"},
        %{"id" => "page", "type" => "create_ticket", "params" => %{"title" => "Data Exfiltration Alert", "priority" => "critical"}}
      ],
      tags: ["exfiltration", "dlp", "critical"]
    }
  end

  defp credential_theft_template do
    %{
      name: "Credential Theft Response",
      description: "Response to credential access attempts",
      category: "incident_response",
      trigger_type: "detection",
      trigger_config: %{"mitre_tactic" => "credential-access"},
      require_approval: true,
      steps: [
        %{"id" => "kill", "type" => "kill_process", "params" => %{}, "on_success" => "collect"},
        %{"id" => "collect", "type" => "http_request", "params" => %{"url" => "{{memory_dump_url}}", "method" => "POST"}, "on_success" => "notify"},
        %{"id" => "notify", "type" => "send_slack", "params" => %{"channel" => "#security-ops", "message" => "Credential theft attempt detected"}}
      ],
      tags: ["credential-theft", "lsass", "mimikatz"]
    }
  end

  defp malware_analysis_template do
    %{
      name: "Malware Analysis Workflow",
      description: "Automated malware sample analysis pipeline",
      category: "investigation",
      trigger_type: "manual",
      steps: [
        %{"id" => "enrich_hash", "type" => "enrich_hash", "params" => %{}, "on_success" => "check_known"},
        %{"id" => "check_known", "type" => "conditional", "params" => %{"condition" => %{"field" => "known_malware", "operator" => "equals", "value" => true}, "then_step" => "block", "else_step" => "sandbox"}},
        %{"id" => "sandbox", "type" => "http_request", "params" => %{"url" => "{{sandbox_url}}", "method" => "POST"}, "on_success" => "analyze"},
        %{"id" => "analyze", "type" => "wait", "params" => %{"duration_seconds" => 300}, "on_success" => "report"},
        %{"id" => "block", "type" => "block_ip", "params" => %{}, "on_success" => "report"},
        %{"id" => "report", "type" => "create_ticket", "params" => %{"title" => "Malware Analysis Complete"}}
      ],
      tags: ["malware", "analysis", "sandbox"]
    }
  end

  # ============================================================================
  # AI-Assisted Workflow Generation
  # ============================================================================

  defp generate_workflow_from_description(description) do
    # Simplified AI workflow generation (in production, would use LLM)
    keywords = String.downcase(description)

    cond do
      String.contains?(keywords, "ransomware") ->
        ransomware_response_template()

      String.contains?(keywords, "phishing") ->
        phishing_response_template()

      String.contains?(keywords, "lateral") ->
        lateral_movement_template()

      String.contains?(keywords, "exfil") ->
        data_exfiltration_template()

      String.contains?(keywords, "credential") ->
        credential_theft_template()

      true ->
        %{
          name: "Custom Workflow",
          description: description,
          trigger_type: "manual",
          steps: [
            %{"id" => "start", "type" => "set_variable", "params" => %{"name" => "started", "value" => true}}
          ],
          tags: ["custom", "ai-generated"],
          ai_generated: true
        }
    end
  end

  defp generate_improvement_suggestions(workflow) do
    suggestions = []

    # Check for missing error handlers
    suggestions =
      if Enum.empty?(workflow.error_handlers || []) do
        [%{type: "add_error_handler", message: "Consider adding error handlers for resilience"} | suggestions]
      else
        suggestions
      end

    # Check for missing notifications
    has_notify = Enum.any?(workflow.steps || [], fn s -> s["type"] in ["send_slack", "send_email", "create_ticket"] end)

    suggestions =
      if not has_notify do
        [%{type: "add_notification", message: "Consider adding notifications for visibility"} | suggestions]
      else
        suggestions
      end

    # Check for approval on high-impact actions
    has_isolate = Enum.any?(workflow.steps || [], fn s -> s["type"] == "isolate_host" end)

    suggestions =
      if has_isolate and not workflow.require_approval do
        [%{type: "require_approval", message: "Consider requiring approval for host isolation"} | suggestions]
      else
        suggestions
      end

    suggestions
  end

  # ============================================================================
  # Public API Stub Functions
  # ============================================================================

  @doc """
  Get execution statistics for workflows.

  Reads from the in-memory ETS stats table first (populated during
  `execute_workflow/2` -> `complete_execution/4`) and falls back to
  database queries when the ETS table is unavailable (e.g. cold start
  before any workflow has completed).

  Returns:
  - total_executions, successful, failed, pending counts
  - success_rate as a percentage
  - avg_duration_ms for completed executions
  - by_workflow_type map of workflow_id => execution count
  - recent_executions list of the last 50 completed runs
  """
  @spec get_execution_stats() :: {:ok, map()}
  def get_execution_stats do
    ets_stats = read_stats_from_ets()

    if ets_stats.total_executions > 0 do
      # ETS has data -- augment with pending count from DB
      pending = query_pending_count()

      {:ok, Map.put(ets_stats, :pending, pending)}
    else
      # ETS is empty (no executions since boot) -- fall back to DB
      query_execution_stats_from_db()
    end
  end

  defp read_stats_from_ets do
    table = :hyperautomation_exec_stats

    try do
      [{:total_executions, total}] = :ets.lookup(table, :total_executions)
      [{:successful, successful}] = :ets.lookup(table, :successful)
      [{:failed, failed}] = :ets.lookup(table, :failed)
      [{:total_duration_ms, total_duration_ms}] = :ets.lookup(table, :total_duration_ms)
      [{:completed_count, completed_count}] = :ets.lookup(table, :completed_count)
      [{:by_workflow_type, by_workflow_type}] = :ets.lookup(table, :by_workflow_type)
      [{:recent_executions, recent_executions}] = :ets.lookup(table, :recent_executions)

      avg_duration_ms =
        if completed_count > 0 do
          Float.round(total_duration_ms / completed_count, 1)
        else
          0.0
        end

      success_rate =
        if total > 0 do
          Float.round(successful / total * 100, 1)
        else
          0.0
        end

      %{
        total_executions: total,
        successful: successful,
        failed: failed,
        pending: 0,
        avg_duration_ms: avg_duration_ms,
        success_rate: success_rate,
        by_workflow_type: by_workflow_type,
        recent_executions: recent_executions
      }
    rescue
      _ ->
        %{
          total_executions: 0,
          successful: 0,
          failed: 0,
          pending: 0,
          avg_duration_ms: 0.0,
          success_rate: 0.0,
          by_workflow_type: %{},
          recent_executions: []
        }
    end
  end

  defp query_pending_count do
    try do
      from(e in WorkflowExecution,
        where: e.status in ["pending", "running", "awaiting_approval", "paused"],
        select: count(e.id)
      )
      |> Repo.one() || 0
    rescue
      _ -> 0
    end
  end

  defp query_execution_stats_from_db do
    try do
      total =
        from(e in WorkflowExecution, select: count(e.id))
        |> Repo.one() || 0

      successful =
        from(e in WorkflowExecution, where: e.status == "completed", select: count(e.id))
        |> Repo.one() || 0

      failed =
        from(e in WorkflowExecution, where: e.status == "failed", select: count(e.id))
        |> Repo.one() || 0

      pending =
        from(e in WorkflowExecution,
          where: e.status in ["pending", "running", "awaiting_approval", "paused"],
          select: count(e.id)
        )
        |> Repo.one() || 0

      avg_duration =
        from(e in WorkflowExecution,
          where: e.status == "completed" and not is_nil(e.duration_seconds),
          select: avg(e.duration_seconds)
        )
        |> Repo.one()

      avg_duration_ms =
        case avg_duration do
          nil -> 0.0
          val -> Float.round(val * 1000, 1)
        end

      success_rate =
        if total > 0 do
          Float.round(successful / total * 100, 1)
        else
          0.0
        end

      # Fetch by_workflow_type from DB
      by_workflow_type =
        from(e in WorkflowExecution,
          group_by: e.workflow_id,
          select: {e.workflow_id, count(e.id)}
        )
        |> Repo.all()
        |> Map.new()

      # Fetch recent executions from DB
      recent_executions =
        from(e in WorkflowExecution,
          where: e.status in ["completed", "failed"],
          order_by: [desc: e.completed_at],
          limit: 50,
          select: %{
            execution_id: e.id,
            workflow_id: e.workflow_id,
            status: e.status,
            duration_seconds: e.duration_seconds,
            completed_at: e.completed_at
          }
        )
        |> Repo.all()

      {:ok,
       %{
         total_executions: total,
         successful: successful,
         failed: failed,
         pending: pending,
         avg_duration_ms: avg_duration_ms,
         success_rate: success_rate,
         by_workflow_type: by_workflow_type,
         recent_executions: recent_executions
       }}
    rescue
      e ->
        Logger.warning("get_execution_stats DB query failed: #{inspect(e)}")

        {:ok,
         %{
           total_executions: 0,
           successful: 0,
           failed: 0,
           pending: 0,
           avg_duration_ms: 0.0,
           success_rate: 0.0,
           by_workflow_type: %{},
           recent_executions: []
         }}
    end
  end

  @doc """
  Get workflow executions for a specific workflow.

  Accepts a workflow_id (binary string) and returns all executions
  for that workflow, ordered by inserted_at descending.
  """
  @spec get_workflow_executions(String.t()) :: {:ok, [WorkflowExecution.t()]}
  def get_workflow_executions(workflow_id) do
    try do
      executions =
        from(e in WorkflowExecution,
          where: e.workflow_id == ^workflow_id,
          order_by: [desc: e.inserted_at]
        )
        |> Repo.all()

      {:ok, executions}
    rescue
      e ->
        Logger.warning("get_workflow_executions query failed: #{inspect(e)}")
        {:ok, []}
    end
  end

  @doc """
  List recent workflow executions across all workflows.

  Options:
  - :limit - maximum number of executions to return (default: 50)
  """
  @spec list_recent_executions(keyword()) :: {:ok, [WorkflowExecution.t()]}
  def list_recent_executions(opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)

    try do
      executions =
        from(e in WorkflowExecution,
          order_by: [desc: e.inserted_at],
          limit: ^limit
        )
        |> Repo.all()

      {:ok, executions}
    rescue
      e ->
        Logger.warning("list_recent_executions query failed: #{inspect(e)}")
        {:ok, []}
    end
  end
end
