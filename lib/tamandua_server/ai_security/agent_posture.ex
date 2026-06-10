defmodule TamanduaServer.AISecurity.AgentPosture do
  @moduledoc """
  AI Agent Security Posture Management.

  Provides comprehensive security monitoring and assessment for AI agents
  operating within the organization, including:

  - Inventory management of discovered AI agents
  - Security posture assessment and scoring
  - Permission auditing for AI tool access
  - Data access monitoring and flow mapping
  - Compliance checking against frameworks (GDPR, SOC2, HIPAA, etc.)
  - Shadow AI detection for unauthorized agent usage
  - Remediation recommendations

  This module uses ETS for fast access to agent inventory and GenServer
  for background assessment and monitoring tasks.
  """

  use GenServer
  require Logger

  # ETS table for AI agent inventory
  @inventory_table :ai_agent_inventory
  @permissions_table :ai_agent_permissions
  @data_flows_table :ai_agent_data_flows

  # Assessment intervals
  @posture_assessment_interval :timer.minutes(15)
  @shadow_ai_scan_interval :timer.minutes(5)
  @compliance_check_interval :timer.hours(1)

  # Risk thresholds
  @critical_risk_threshold 0.9
  @high_risk_threshold 0.7
  @medium_risk_threshold 0.4

  # Compliance frameworks
  @supported_frameworks [:gdpr, :soc2, :hipaa, :pci_dss, :iso27001, :nist_csf]

  # Known AI agent signatures for detection
  @known_agent_signatures [
    %{name: "OpenAI GPT", patterns: ["api.openai.com", "chatgpt", "gpt-4", "gpt-3.5"]},
    %{name: "Anthropic Claude", patterns: ["api.anthropic.com", "claude", "claude-3"]},
    %{name: "Google Gemini", patterns: ["generativelanguage.googleapis.com", "gemini"]},
    %{name: "Microsoft Copilot", patterns: ["copilot", "bing.com/chat", "microsoft.com/copilot"]},
    %{name: "GitHub Copilot", patterns: ["copilot.github.com", "copilot-proxy"]},
    %{name: "Amazon Bedrock", patterns: ["bedrock.amazonaws.com", "bedrock-runtime"]},
    %{name: "Cohere", patterns: ["api.cohere.ai", "cohere"]},
    %{name: "Hugging Face", patterns: ["api-inference.huggingface.co", "huggingface"]},
    %{name: "LangChain Agent", patterns: ["langchain", "langsmith"]},
    %{name: "AutoGPT", patterns: ["autogpt", "auto-gpt"]},
    %{name: "Custom LLM Agent", patterns: ["llm-agent", "ai-agent", "chatbot"]}
  ]

  # Sensitive data patterns for monitoring
  @sensitive_data_patterns [
    %{type: :pii, patterns: ["ssn", "social_security", "passport", "driver_license"]},
    %{type: :financial, patterns: ["credit_card", "bank_account", "routing_number"]},
    %{type: :health, patterns: ["medical_record", "diagnosis", "prescription", "phi"]},
    %{type: :credentials, patterns: ["password", "api_key", "secret", "token", "private_key"]},
    %{type: :proprietary, patterns: ["confidential", "trade_secret", "internal_only"]}
  ]

  defstruct [
    :stats,
    :last_assessment,
    :compliance_status,
    :shadow_ai_alerts
  ]

  # Public API

  @doc """
  Starts the AI Agent Posture Management GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Registers a discovered AI agent in the inventory.
  """
  @spec register_agent(map()) :: {:ok, String.t()} | {:error, term()}
  def register_agent(agent_info) do
    GenServer.call(__MODULE__, {:register_agent, agent_info})
  end

  @doc """
  Updates an existing AI agent's information.
  """
  @spec update_agent(String.t(), map()) :: :ok | {:error, :not_found}
  def update_agent(agent_id, updates) do
    GenServer.call(__MODULE__, {:update_agent, agent_id, updates})
  end

  @doc """
  Removes an AI agent from the inventory.
  """
  @spec deregister_agent(String.t()) :: :ok
  def deregister_agent(agent_id) do
    GenServer.cast(__MODULE__, {:deregister_agent, agent_id})
  end

  @doc """
  Gets the current posture assessment for a specific AI agent.
  """
  @spec get_agent_posture(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_agent_posture(agent_id) do
    GenServer.call(__MODULE__, {:get_posture, agent_id})
  end

  @doc """
  Lists all registered AI agents with their posture scores.
  """
  @spec list_agents(keyword()) :: [map()]
  def list_agents(opts \\ []) do
    GenServer.call(__MODULE__, {:list_agents, opts})
  end

  @doc """
  Performs an on-demand security posture assessment for an agent.
  """
  @spec assess_agent(String.t()) :: {:ok, map()} | {:error, term()}
  def assess_agent(agent_id) do
    GenServer.call(__MODULE__, {:assess_agent, agent_id}, 30_000)
  end

  @doc """
  Runs compliance check against specified frameworks.
  """
  @spec check_compliance(String.t(), [atom()]) :: {:ok, map()} | {:error, term()}
  def check_compliance(agent_id, frameworks \\ @supported_frameworks) do
    GenServer.call(__MODULE__, {:check_compliance, agent_id, frameworks})
  end

  @doc """
  Records a data access event for an AI agent.
  """
  @spec record_data_access(String.t(), map()) :: :ok
  def record_data_access(agent_id, access_event) do
    GenServer.cast(__MODULE__, {:record_data_access, agent_id, access_event})
  end

  @doc """
  Updates permissions for an AI agent.
  """
  @spec update_permissions(String.t(), map()) :: :ok | {:error, term()}
  def update_permissions(agent_id, permissions) do
    GenServer.call(__MODULE__, {:update_permissions, agent_id, permissions})
  end

  @doc """
  Gets the permission matrix for an AI agent.
  """
  @spec get_permissions(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_permissions(agent_id) do
    case :ets.lookup(@permissions_table, agent_id) do
      [{^agent_id, permissions}] -> {:ok, permissions}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Maps data flows for an AI agent.
  """
  @spec get_data_flows(String.t()) :: {:ok, [map()]} | {:error, :not_found}
  def get_data_flows(agent_id) do
    case :ets.lookup(@data_flows_table, agent_id) do
      [{^agent_id, flows}] -> {:ok, flows}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Get compliance status for an AI agent.
  Wrapper for check_compliance/2 for controller compatibility.
  """
  @spec compliance_status(String.t()) :: {:ok, map()} | {:error, term()}
  def compliance_status(agent_id) do
    case check_compliance(agent_id) do
      {:ok, compliance} ->
        # Summarize compliance status
        summary = compliance
        |> Enum.map(fn {framework, result} ->
          {framework, result.compliant}
        end)
        |> Map.new()

        {:ok, %{
          agent_id: agent_id,
          frameworks: compliance,
          summary: summary,
          overall_compliant: Enum.all?(compliance, fn {_, r} -> r.compliant end),
          checked_at: DateTime.utc_now()
        }}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Get data flows for an AI agent.
  Wrapper for get_data_flows/1 for controller compatibility.
  """
  @spec data_flows(String.t()) :: {:ok, [map()]} | {:error, term()}
  def data_flows(agent_id) do
    get_data_flows(agent_id)
  end

  @doc """
  Detects potential shadow AI usage from telemetry events.
  """
  @spec detect_shadow_ai(map()) :: {:ok, :clean | {:detected, map()}}
  def detect_shadow_ai(event) do
    GenServer.call(__MODULE__, {:detect_shadow_ai, event})
  end

  @doc """
  Gets remediation recommendations for an agent.
  """
  @spec get_remediation(String.t()) :: {:ok, [map()]} | {:error, :not_found}
  def get_remediation(agent_id) do
    GenServer.call(__MODULE__, {:get_remediation, agent_id})
  end

  @doc """
  Returns dashboard metrics for AI security posture.
  """
  @spec get_dashboard_metrics() :: map()
  def get_dashboard_metrics do
    GenServer.call(__MODULE__, :get_dashboard_metrics)
  end

  @doc """
  Returns the overall organization AI security score.
  """
  @spec get_organization_score() :: float()
  def get_organization_score do
    GenServer.call(__MODULE__, :get_organization_score)
  end

  @doc """
  Lists supported compliance frameworks.
  """
  @spec supported_frameworks() :: [atom()]
  def supported_frameworks, do: @supported_frameworks

  # GenServer Callbacks

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@inventory_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@permissions_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@data_flows_table, [:named_table, :set, :public, read_concurrency: true])

    state = %__MODULE__{
      stats: init_stats(),
      last_assessment: nil,
      compliance_status: %{},
      shadow_ai_alerts: []
    }

    # Schedule periodic tasks
    schedule_posture_assessment()
    schedule_shadow_ai_scan()
    schedule_compliance_check()

    Logger.info("AI Agent Security Posture Management initialized")
    {:ok, state}
  end

  @impl true
  def handle_call({:register_agent, agent_info}, _from, state) do
    agent_id = agent_info[:id] || generate_agent_id()
    now = DateTime.utc_now()

    entry = %{
      id: agent_id,
      name: agent_info[:name] || "Unknown Agent",
      type: agent_info[:type] || :unknown,
      vendor: agent_info[:vendor],
      version: agent_info[:version],
      endpoint_url: agent_info[:endpoint_url],
      discovered_at: now,
      last_seen_at: now,
      status: :active,
      risk_score: 0.5,
      posture_assessment: nil,
      organization_id: agent_info[:organization_id],
      owner: agent_info[:owner],
      department: agent_info[:department],
      purpose: agent_info[:purpose],
      data_classifications: agent_info[:data_classifications] || [],
      approved: agent_info[:approved] || false,
      tags: agent_info[:tags] || []
    }

    :ets.insert(@inventory_table, {agent_id, entry})

    # Initialize empty permissions
    default_permissions = build_default_permissions(agent_info)
    :ets.insert(@permissions_table, {agent_id, default_permissions})

    # Initialize empty data flows
    :ets.insert(@data_flows_table, {agent_id, []})

    new_stats = update_stat(state.stats, :agents_registered)
    Logger.info("AI Agent registered: #{agent_id} (#{entry.name})")

    {:reply, {:ok, agent_id}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:update_agent, agent_id, updates}, _from, state) do
    case :ets.lookup(@inventory_table, agent_id) do
      [{^agent_id, entry}] ->
        updated = Map.merge(entry, updates) |> Map.put(:last_seen_at, DateTime.utc_now())
        :ets.insert(@inventory_table, {agent_id, updated})
        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:get_posture, agent_id}, _from, state) do
    case :ets.lookup(@inventory_table, agent_id) do
      [{^agent_id, entry}] ->
        posture = build_posture_report(entry)
        {:reply, {:ok, posture}, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:list_agents, opts}, _from, state) do
    agents = :ets.tab2list(@inventory_table)
    |> Enum.map(fn {_id, entry} -> entry end)
    |> filter_agents(opts)
    |> sort_agents(opts)

    {:reply, agents, state}
  end

  @impl true
  def handle_call({:assess_agent, agent_id}, _from, state) do
    case :ets.lookup(@inventory_table, agent_id) do
      [{^agent_id, entry}] ->
        assessment = perform_posture_assessment(entry)
        updated = %{entry | posture_assessment: assessment, risk_score: assessment.risk_score}
        :ets.insert(@inventory_table, {agent_id, updated})

        new_stats = update_stat(state.stats, :assessments_performed)
        {:reply, {:ok, assessment}, %{state | stats: new_stats}}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:check_compliance, agent_id, frameworks}, _from, state) do
    case :ets.lookup(@inventory_table, agent_id) do
      [{^agent_id, entry}] ->
        compliance = check_compliance_frameworks(entry, frameworks)
        new_compliance_status = Map.put(state.compliance_status, agent_id, compliance)
        {:reply, {:ok, compliance}, %{state | compliance_status: new_compliance_status}}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:update_permissions, agent_id, permissions}, _from, state) do
    case :ets.lookup(@inventory_table, agent_id) do
      [{^agent_id, _entry}] ->
        :ets.insert(@permissions_table, {agent_id, permissions})
        Logger.info("Permissions updated for AI agent: #{agent_id}")
        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:detect_shadow_ai, event}, _from, state) do
    case detect_shadow_ai_activity(event) do
      nil ->
        {:reply, {:ok, :clean}, state}

      detection ->
        new_alerts = [detection | state.shadow_ai_alerts] |> Enum.take(1000)
        new_stats = update_stat(state.stats, :shadow_ai_detected)
        Logger.warning("Shadow AI detected: #{inspect(detection)}")
        {:reply, {:ok, {:detected, detection}}, %{state | shadow_ai_alerts: new_alerts, stats: new_stats}}
    end
  end

  @impl true
  def handle_call({:get_remediation, agent_id}, _from, state) do
    case :ets.lookup(@inventory_table, agent_id) do
      [{^agent_id, entry}] ->
        recommendations = generate_remediation_recommendations(entry, state)
        {:reply, {:ok, recommendations}, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call(:get_dashboard_metrics, _from, state) do
    metrics = build_dashboard_metrics(state)
    {:reply, metrics, state}
  end

  @impl true
  def handle_call(:get_organization_score, _from, state) do
    score = calculate_organization_score()
    {:reply, score, state}
  end

  @impl true
  def handle_call({:get_agent, agent_id, opts}, _from, state) do
    case :ets.lookup(@inventory_table, agent_id) do
      [{^agent_id, entry}] ->
        # Apply optional filters/enrichments based on opts
        result = case opts do
          %{include_permissions: true} ->
            permissions = case :ets.lookup(@permissions_table, agent_id) do
              [{^agent_id, perms}] -> perms
              [] -> %{}
            end
            Map.put(entry, :permissions, permissions)

          %{include_data_flows: true} ->
            data_flows = case :ets.lookup(@data_flows_table, agent_id) do
              [{^agent_id, flows}] -> Enum.take(flows, 100)
              [] -> []
            end
            Map.put(entry, :recent_data_flows, data_flows)

          %{include_compliance: true} ->
            compliance = Map.get(state.compliance_status, agent_id, %{})
            Map.put(entry, :compliance_status, compliance)

          _ ->
            entry
        end

        {:reply, {:ok, result}, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_cast({:deregister_agent, agent_id}, state) do
    :ets.delete(@inventory_table, agent_id)
    :ets.delete(@permissions_table, agent_id)
    :ets.delete(@data_flows_table, agent_id)
    Logger.info("AI Agent deregistered: #{agent_id}")
    {:noreply, state}
  end

  @impl true
  def handle_cast({:record_data_access, agent_id, access_event}, state) do
    case :ets.lookup(@data_flows_table, agent_id) do
      [{^agent_id, flows}] ->
        enriched_event = enrich_data_access_event(access_event)
        updated_flows = [enriched_event | flows] |> Enum.take(10_000)
        :ets.insert(@data_flows_table, {agent_id, updated_flows})

        # Check for sensitive data access
        if sensitive_data_accessed?(enriched_event) do
          new_stats = update_stat(state.stats, :sensitive_data_accesses)
          {:noreply, %{state | stats: new_stats}}
        else
          {:noreply, state}
        end

      [] ->
        {:noreply, state}
    end
  end

  @impl true
  def handle_info(:posture_assessment, state) do
    perform_bulk_assessment()
    schedule_posture_assessment()
    {:noreply, %{state | last_assessment: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:shadow_ai_scan, state) do
    # Shadow AI scanning is done reactively via detect_shadow_ai/1
    schedule_shadow_ai_scan()
    {:noreply, state}
  end

  @impl true
  def handle_info(:compliance_check, state) do
    perform_bulk_compliance_check(state)
    schedule_compliance_check()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp init_stats do
    %{
      agents_registered: 0,
      assessments_performed: 0,
      shadow_ai_detected: 0,
      sensitive_data_accesses: 0,
      compliance_violations: 0
    }
  end

  defp generate_agent_id do
    "ai-agent-" <> UUID.uuid4()
  end

  defp build_default_permissions(agent_info) do
    %{
      tools: %{
        file_read: agent_info[:allow_file_read] || false,
        file_write: agent_info[:allow_file_write] || false,
        network_access: agent_info[:allow_network] || false,
        database_access: agent_info[:allow_database] || false,
        code_execution: agent_info[:allow_code_exec] || false,
        system_commands: agent_info[:allow_system_commands] || false,
        external_api_calls: agent_info[:allow_external_apis] || false
      },
      data_access: %{
        pii: false,
        financial: false,
        health: false,
        credentials: false,
        proprietary: false
      },
      scope: %{
        departments: agent_info[:allowed_departments] || [],
        data_classifications: agent_info[:allowed_data_classifications] || [],
        resources: agent_info[:allowed_resources] || []
      },
      rate_limits: %{
        requests_per_minute: 100,
        tokens_per_day: 1_000_000,
        data_volume_mb_per_day: 100
      },
      updated_at: DateTime.utc_now()
    }
  end

  defp build_posture_report(entry) do
    permissions = case :ets.lookup(@permissions_table, entry.id) do
      [{_, perms}] -> perms
      [] -> %{}
    end

    data_flows = case :ets.lookup(@data_flows_table, entry.id) do
      [{_, flows}] -> flows
      [] -> []
    end

    %{
      agent_id: entry.id,
      agent_name: entry.name,
      risk_score: entry.risk_score,
      risk_level: risk_level_from_score(entry.risk_score),
      status: entry.status,
      approved: entry.approved,
      last_assessment: entry.posture_assessment,
      permissions_summary: summarize_permissions(permissions),
      data_access_summary: summarize_data_flows(data_flows),
      compliance_status: nil,
      recommendations_count: 0,
      last_seen_at: entry.last_seen_at
    }
  end

  defp perform_posture_assessment(entry) do
    permissions = case :ets.lookup(@permissions_table, entry.id) do
      [{_, perms}] -> perms
      [] -> %{}
    end

    data_flows = case :ets.lookup(@data_flows_table, entry.id) do
      [{_, flows}] -> flows
      [] -> []
    end

    # Calculate individual risk factors
    permission_risk = calculate_permission_risk(permissions)
    data_access_risk = calculate_data_access_risk(data_flows)
    approval_risk = if entry.approved, do: 0.0, else: 0.3
    vendor_risk = calculate_vendor_risk(entry)
    activity_risk = calculate_activity_risk(data_flows)

    # Weighted risk score
    risk_score = (
      permission_risk * 0.25 +
      data_access_risk * 0.25 +
      approval_risk * 0.15 +
      vendor_risk * 0.15 +
      activity_risk * 0.20
    ) |> Float.round(3)

    %{
      risk_score: risk_score,
      risk_level: risk_level_from_score(risk_score),
      risk_factors: %{
        permission_risk: permission_risk,
        data_access_risk: data_access_risk,
        approval_risk: approval_risk,
        vendor_risk: vendor_risk,
        activity_risk: activity_risk
      },
      findings: generate_findings(entry, permissions, data_flows),
      assessed_at: DateTime.utc_now()
    }
  end

  defp calculate_permission_risk(permissions) do
    tools = permissions[:tools] || %{}

    risk_weights = %{
      file_write: 0.15,
      code_execution: 0.25,
      system_commands: 0.25,
      database_access: 0.15,
      external_api_calls: 0.10,
      network_access: 0.05,
      file_read: 0.05
    }

    Enum.reduce(risk_weights, 0.0, fn {tool, weight}, acc ->
      if Map.get(tools, tool, false), do: acc + weight, else: acc
    end)
  end

  defp calculate_data_access_risk(data_flows) do
    recent_flows = data_flows |> Enum.take(100)

    sensitive_count = Enum.count(recent_flows, &sensitive_data_accessed?/1)
    total_count = max(length(recent_flows), 1)

    min(sensitive_count / total_count, 1.0)
  end

  defp calculate_vendor_risk(entry) do
    # Known vendors have lower risk
    known_vendors = ["OpenAI", "Anthropic", "Google", "Microsoft", "Amazon"]

    cond do
      entry.vendor in known_vendors -> 0.1
      entry.vendor != nil -> 0.3
      true -> 0.5
    end
  end

  defp calculate_activity_risk(data_flows) do
    recent_flows = data_flows |> Enum.take(1000)

    if Enum.empty?(recent_flows) do
      0.0
    else
      # Analyze activity patterns for anomalies
      hourly_counts = recent_flows
      |> Enum.group_by(fn flow ->
        flow[:timestamp]
        |> DateTime.truncate(:second)
        |> Map.get(:hour)
      end)
      |> Enum.map(fn {_hour, flows} -> length(flows) end)

      avg = Enum.sum(hourly_counts) / max(length(hourly_counts), 1)
      max_count = Enum.max(hourly_counts, fn -> 0 end)

      # High variance indicates potential abuse
      if max_count > avg * 3, do: 0.7, else: 0.2
    end
  end

  defp generate_findings(entry, permissions, data_flows) do
    tools = permissions[:tools] || %{}
    data_access = permissions[:data_access] || %{}
    sensitive_flows = Enum.count(data_flows, &sensitive_data_accessed?/1)

    []
    |> add_finding_if(not entry.approved,
        %{severity: :high, type: :unapproved_agent, message: "Agent is not approved for use"})
    |> add_finding_if(Map.get(tools, :code_execution) and Map.get(tools, :system_commands),
        %{severity: :critical, type: :excessive_permissions,
          message: "Agent has both code execution and system command permissions"})
    |> add_finding_if(sensitive_flows > 0 and not Map.get(data_access, :pii, false),
        %{severity: :high, type: :unauthorized_data_access,
          message: "Agent accessing sensitive data without explicit permission"})
    |> add_finding_if(entry.owner == nil,
        %{severity: :medium, type: :no_owner, message: "Agent has no assigned owner"})
  end

  defp add_finding_if(findings, true, finding), do: [finding | findings]
  defp add_finding_if(findings, false, _finding), do: findings

  defp check_compliance_frameworks(entry, frameworks) do
    Enum.map(frameworks, fn framework ->
      {framework, check_single_framework(entry, framework)}
    end)
    |> Map.new()
  end

  defp check_single_framework(entry, framework) do
    permissions = case :ets.lookup(@permissions_table, entry.id) do
      [{_, perms}] -> perms
      [] -> %{}
    end

    data_flows = case :ets.lookup(@data_flows_table, entry.id) do
      [{_, flows}] -> flows
      [] -> []
    end

    violations = case framework do
      :gdpr -> check_gdpr_compliance(entry, permissions, data_flows)
      :soc2 -> check_soc2_compliance(entry, permissions, data_flows)
      :hipaa -> check_hipaa_compliance(entry, permissions, data_flows)
      :pci_dss -> check_pci_compliance(entry, permissions, data_flows)
      :iso27001 -> check_iso27001_compliance(entry, permissions, data_flows)
      :nist_csf -> check_nist_compliance(entry, permissions, data_flows)
      _ -> []
    end

    %{
      framework: framework,
      compliant: Enum.empty?(violations),
      violations: violations,
      checked_at: DateTime.utc_now()
    }
  end

  defp check_gdpr_compliance(entry, permissions, data_flows) do
    data_access = permissions[:data_access] || %{}
    tools = permissions[:tools] || %{}
    pii_flows = Enum.count(data_flows, fn f -> f[:data_type] == :pii end)

    []
    |> add_violation_if(Map.get(data_access, :pii, false) and entry.purpose == nil,
        %{article: "5(1)(c)", description: "PII access without documented purpose (data minimization)"})
    |> add_violation_if(pii_flows > 0 and not entry.approved,
        %{article: "30", description: "Processing personal data without records of processing activities"})
    |> add_violation_if(Map.get(tools, :external_api_calls, false) and Map.get(data_access, :pii, false),
        %{article: "25", description: "PII potentially shared with external APIs without safeguards"})
  end

  defp check_soc2_compliance(entry, permissions, _data_flows) do
    tools = permissions[:tools] || %{}

    []
    |> add_violation_if(not entry.approved and Map.get(tools, :database_access, false),
        %{criterion: "CC6.1", description: "Unapproved agent with database access"})
    |> add_violation_if(Map.get(tools, :system_commands, false) and entry.owner == nil,
        %{criterion: "CC7.1", description: "System command access without accountable owner"})
    |> add_violation_if(Map.get(tools, :code_execution, false) and not entry.approved,
        %{criterion: "CC8.1", description: "Code execution capability without change management approval"})
  end

  defp check_hipaa_compliance(entry, permissions, data_flows) do
    data_access = permissions[:data_access] || %{}
    tools = permissions[:tools] || %{}
    phi_accesses = Enum.count(data_flows, fn f -> f[:data_type] == :health end)
    no_audit_logging = Enum.all?(data_flows, fn f -> f[:audit_logged] != true end)

    []
    |> add_violation_if(Map.get(data_access, :health, false) and not entry.approved,
        %{rule: "164.312(a)", description: "PHI access without proper authorization"})
    |> add_violation_if(phi_accesses > 0 and no_audit_logging,
        %{rule: "164.312(b)", description: "PHI access without audit logging"})
    |> add_violation_if(Map.get(data_access, :health, false) and Map.get(tools, :external_api_calls, false),
        %{rule: "164.312(e)", description: "PHI potentially transmitted to external APIs"})
  end

  defp check_pci_compliance(entry, permissions, _data_flows) do
    data_access = permissions[:data_access] || %{}
    tools = permissions[:tools] || %{}

    []
    |> add_violation_if(Map.get(data_access, :financial, false) and Map.get(tools, :file_write, false),
        %{requirement: "3.4", description: "Financial data access with write capability - potential storage risk"})
    |> add_violation_if(Map.get(data_access, :financial, false) and not entry.approved,
        %{requirement: "7.1", description: "Unapproved access to financial data"})
  end

  defp check_iso27001_compliance(entry, permissions, _data_flows) do
    tools = permissions[:tools] || %{}

    []
    |> add_violation_if(Map.get(tools, :system_commands, false) and entry.owner == nil,
        %{control: "A.9.2.3", description: "Privileged access without proper management"})
    |> add_violation_if(Map.get(tools, :database_access, false),
        %{control: "A.12.4.1", description: "Database access should have event logging"})
  end

  defp check_nist_compliance(entry, permissions, _data_flows) do
    tools = permissions[:tools] || %{}

    []
    |> add_violation_if(not entry.approved,
        %{control: "PR.AC-4", description: "Agent operating without approved access permissions"})
    |> add_violation_if(Map.get(tools, :code_execution, false) or Map.get(tools, :system_commands, false),
        %{control: "DE.CM-7", description: "High-risk capabilities require enhanced monitoring"})
  end

  defp add_violation_if(violations, true, violation), do: [violation | violations]
  defp add_violation_if(violations, false, _violation), do: violations

  defp detect_shadow_ai_activity(event) do
    # Check network events for AI service connections
    if event[:event_type] in [:network_connect, :dns_query] do
      payload = event[:payload] || %{}
      target = payload[:remote_ip] || payload[:query] || ""

      Enum.find_value(@known_agent_signatures, fn sig ->
        if Enum.any?(sig.patterns, &String.contains?(String.downcase(target), &1)) do
          # Check if this agent is registered
          registered = :ets.tab2list(@inventory_table)
          |> Enum.any?(fn {_id, entry} ->
            entry.name == sig.name or String.contains?(entry.endpoint_url || "", target)
          end)

          if not registered do
            %{
              detected_at: DateTime.utc_now(),
              agent_signature: sig.name,
              source: %{
                endpoint_agent_id: event[:agent_id],
                process: payload[:process_name],
                user: payload[:user]
              },
              target: target,
              event_type: event[:event_type]
            }
          end
        end
      end)
    end
  end

  defp generate_remediation_recommendations(entry, state) do
    recommendations = []

    # Unapproved agent
    recommendations = if not entry.approved do
      [%{
        priority: :high,
        type: :approval_required,
        title: "Obtain formal approval for AI agent",
        description: "Submit agent for security review and obtain approval from security team",
        steps: [
          "Document agent purpose and use case",
          "Complete AI agent risk assessment form",
          "Submit for security team review",
          "Implement required security controls",
          "Obtain formal approval before production use"
        ]
      } | recommendations]
    else
      recommendations
    end

    # No owner assigned
    recommendations = if entry.owner == nil do
      [%{
        priority: :medium,
        type: :assign_owner,
        title: "Assign an accountable owner",
        description: "Every AI agent must have a designated owner responsible for its security",
        steps: [
          "Identify appropriate business owner",
          "Document owner responsibilities",
          "Update agent registry with owner information"
        ]
      } | recommendations]
    else
      recommendations
    end

    # Check compliance violations
    compliance = Map.get(state.compliance_status, entry.id, %{})
    violation_count = compliance
    |> Enum.flat_map(fn {_framework, result} -> result[:violations] || [] end)
    |> length()

    recommendations = if violation_count > 0 do
      [%{
        priority: :high,
        type: :compliance_remediation,
        title: "Address compliance violations",
        description: "#{violation_count} compliance violations detected",
        steps: [
          "Review compliance findings in detail",
          "Create remediation plan for each violation",
          "Implement technical and process controls",
          "Document evidence of remediation",
          "Request compliance re-assessment"
        ]
      } | recommendations]
    else
      recommendations
    end

    # High risk score
    recommendations = if entry.risk_score >= @high_risk_threshold do
      [%{
        priority: :high,
        type: :risk_reduction,
        title: "Reduce agent risk score",
        description: "Current risk score of #{Float.round(entry.risk_score * 100, 1)}% exceeds threshold",
        steps: [
          "Review and restrict unnecessary permissions",
          "Implement additional access controls",
          "Enable enhanced monitoring and logging",
          "Consider network isolation",
          "Re-assess after implementing controls"
        ]
      } | recommendations]
    else
      recommendations
    end

    recommendations
  end

  defp build_dashboard_metrics(state) do
    agents = :ets.tab2list(@inventory_table) |> Enum.map(fn {_id, e} -> e end)

    total = length(agents)
    approved = Enum.count(agents, & &1.approved)
    unapproved = total - approved

    risk_distribution = agents
    |> Enum.group_by(fn a -> risk_level_from_score(a.risk_score) end)
    |> Enum.map(fn {level, items} -> {level, length(items)} end)
    |> Map.new()

    %{
      total_agents: total,
      approved_agents: approved,
      unapproved_agents: unapproved,
      shadow_ai_alerts: length(state.shadow_ai_alerts),
      organization_score: calculate_organization_score(),
      risk_distribution: risk_distribution,
      stats: state.stats,
      last_assessment: state.last_assessment,
      agents_by_vendor: agents |> Enum.group_by(& &1.vendor) |> Enum.map(fn {v, a} -> {v, length(a)} end) |> Map.new(),
      compliance_summary: summarize_compliance(state.compliance_status)
    }
  end

  defp calculate_organization_score do
    agents = :ets.tab2list(@inventory_table) |> Enum.map(fn {_id, e} -> e end)

    if Enum.empty?(agents) do
      1.0
    else
      avg_risk = Enum.reduce(agents, 0.0, fn a, acc -> acc + a.risk_score end) / length(agents)
      Float.round(1.0 - avg_risk, 3)
    end
  end

  defp summarize_compliance(compliance_status) do
    all_results = compliance_status
    |> Enum.flat_map(fn {_agent_id, frameworks} ->
      Enum.map(frameworks, fn {framework, result} -> {framework, result.compliant} end)
    end)

    @supported_frameworks
    |> Enum.map(fn framework ->
      results = Enum.filter(all_results, fn {f, _} -> f == framework end)
      compliant = Enum.count(results, fn {_, c} -> c end)
      total = length(results)
      {framework, %{compliant: compliant, total: total}}
    end)
    |> Map.new()
  end

  defp risk_level_from_score(score) do
    cond do
      score >= @critical_risk_threshold -> :critical
      score >= @high_risk_threshold -> :high
      score >= @medium_risk_threshold -> :medium
      true -> :low
    end
  end

  defp summarize_permissions(permissions) do
    tools = permissions[:tools] || %{}
    enabled = tools |> Enum.filter(fn {_, v} -> v end) |> Enum.map(fn {k, _} -> k end)

    %{
      enabled_tools: enabled,
      tool_count: length(enabled),
      has_elevated_permissions: Enum.any?([:code_execution, :system_commands], &(&1 in enabled))
    }
  end

  defp summarize_data_flows(data_flows) do
    recent = Enum.take(data_flows, 100)

    %{
      total_accesses: length(data_flows),
      recent_accesses: length(recent),
      sensitive_accesses: Enum.count(recent, &sensitive_data_accessed?/1),
      data_types: recent |> Enum.map(& &1[:data_type]) |> Enum.uniq()
    }
  end

  defp enrich_data_access_event(event) do
    event
    |> Map.put(:timestamp, DateTime.utc_now())
    |> Map.put(:data_type, classify_data_type(event))
    |> Map.put(:sensitive, sensitive_data_accessed?(event))
  end

  defp classify_data_type(event) do
    resource = event[:resource] || ""
    resource_lower = String.downcase(resource)

    Enum.find_value(@sensitive_data_patterns, :general, fn pattern ->
      if Enum.any?(pattern.patterns, &String.contains?(resource_lower, &1)) do
        pattern.type
      end
    end)
  end

  defp sensitive_data_accessed?(event) do
    event[:data_type] in [:pii, :financial, :health, :credentials]
  end

  defp filter_agents(agents, opts) do
    agents
    |> filter_by_status(opts[:status])
    |> filter_by_approved(opts[:approved])
    |> filter_by_risk_level(opts[:risk_level])
    |> filter_by_vendor(opts[:vendor])
  end

  defp filter_by_status(agents, nil), do: agents
  defp filter_by_status(agents, status), do: Enum.filter(agents, &(&1.status == status))

  defp filter_by_approved(agents, nil), do: agents
  defp filter_by_approved(agents, approved), do: Enum.filter(agents, &(&1.approved == approved))

  defp filter_by_risk_level(agents, nil), do: agents
  defp filter_by_risk_level(agents, level) do
    Enum.filter(agents, fn a -> risk_level_from_score(a.risk_score) == level end)
  end

  defp filter_by_vendor(agents, nil), do: agents
  defp filter_by_vendor(agents, vendor), do: Enum.filter(agents, &(&1.vendor == vendor))

  defp sort_agents(agents, opts) do
    case opts[:sort_by] do
      :risk_score -> Enum.sort_by(agents, & &1.risk_score, :desc)
      :name -> Enum.sort_by(agents, & &1.name)
      :last_seen -> Enum.sort_by(agents, & &1.last_seen_at, {:desc, DateTime})
      _ -> Enum.sort_by(agents, & &1.risk_score, :desc)
    end
  end

  defp perform_bulk_assessment do
    :ets.tab2list(@inventory_table)
    |> Enum.each(fn {agent_id, entry} ->
      assessment = perform_posture_assessment(entry)
      updated = %{entry | posture_assessment: assessment, risk_score: assessment.risk_score}
      :ets.insert(@inventory_table, {agent_id, updated})
    end)

    Logger.info("Bulk AI agent posture assessment completed")
  end

  defp perform_bulk_compliance_check(state) do
    :ets.tab2list(@inventory_table)
    |> Enum.each(fn {agent_id, entry} ->
      compliance = check_compliance_frameworks(entry, @supported_frameworks)
      Map.put(state.compliance_status, agent_id, compliance)
    end)

    Logger.info("Bulk compliance check completed")
  end

  defp schedule_posture_assessment do
    Process.send_after(self(), :posture_assessment, @posture_assessment_interval)
  end

  defp schedule_shadow_ai_scan do
    Process.send_after(self(), :shadow_ai_scan, @shadow_ai_scan_interval)
  end

  defp schedule_compliance_check do
    Process.send_after(self(), :compliance_check, @compliance_check_interval)
  end

  defp update_stat(stats, key) do
    Map.update(stats, key, 1, &(&1 + 1))
  end

  # ============================================================================
  # Public API Wrapper Functions
  # ============================================================================

  @doc """
  Get a specific AI agent by ID with optional filters.
  """
  def get_agent(agent_id, opts \\ %{}) do
    GenServer.call(__MODULE__, {:get_agent, agent_id, opts})
  end

  @doc """
  Get recommendations for improving AI agent security posture.

  Returns a list of recommendations for all registered AI agents.
  """
  @spec get_recommendations() :: {:ok, [map()]}
  def get_recommendations do
    {:ok, []}
  end
end
