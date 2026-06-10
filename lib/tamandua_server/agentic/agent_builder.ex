defmodule TamanduaServer.Agentic.AgentBuilder do
  @moduledoc """
  Agent Builder Engine - Custom AI Security Agent Creator

  Enables customers to create custom AI security agents via natural language
  descriptions. The builder parses descriptions into structured agent specifications
  including trigger conditions, data sources, reasoning steps, allowed actions,
  and guardrails.

  ## Architecture

  Agents are defined as structured specifications stored in ETS (hot cache) and
  persisted to the database. Each agent is scoped to an organization (multi-tenant)
  and validated against safety constraints before activation.

  ## Agent Lifecycle

      build_agent/4 -> validate -> store -> enable/disable -> execute (via Runtime)

  ## Usage

      # Create from natural language
      AgentBuilder.build_agent(
        "When a critical ransomware alert fires, isolate the host, kill the malicious
         process, snapshot memory, and notify the SOC team on Slack",
        [:isolate_host, :kill_process, :collect_memory, :send_slack],
        %{max_actions_per_hour: 10, require_approval_for: [:isolate_host]},
        org_id
      )

      # List agents for an org
      AgentBuilder.list_agents(org_id)

      # Enable/disable
      AgentBuilder.enable_agent(agent_id)
      AgentBuilder.disable_agent(agent_id)
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo

  # ETS table for fast agent definition lookups
  @agents_table :agentic_agent_definitions
  @agents_by_org_table :agentic_agents_by_org

  # ============================================================================
  # Type Definitions & Structs
  # ============================================================================

  defmodule Trigger do
    @moduledoc "Defines what activates an agent"
    defstruct [
      :type,
      :conditions
    ]

    @type t :: %__MODULE__{
      type: :alert | :schedule | :telemetry | :manual | :webhook | :threshold,
      conditions: map()
    }
  end

  defmodule ReasoningStep do
    @moduledoc "A single step in the agent's reasoning chain"
    defstruct [
      :id,
      :action,
      :params,
      :condition,
      :on_success,
      :on_failure,
      :timeout_ms
    ]

    @type t :: %__MODULE__{
      id: String.t(),
      action: atom(),
      params: map(),
      condition: map() | nil,
      on_success: String.t() | nil,
      on_failure: String.t() | nil,
      timeout_ms: pos_integer()
    }
  end

  defmodule Guardrails do
    @moduledoc "Safety constraints for agent execution"
    defstruct [
      max_actions_per_hour: 50,
      require_approval_for: [],
      scope_filter: %{},
      blocked_actions: [],
      max_concurrent_executions: 5,
      cooldown_seconds: 0,
      allowed_severity_levels: [:low, :medium, :high, :critical],
      max_blast_radius: :single_host
    ]

    @type t :: %__MODULE__{
      max_actions_per_hour: pos_integer(),
      require_approval_for: [atom()],
      scope_filter: map(),
      blocked_actions: [atom()],
      max_concurrent_executions: pos_integer(),
      cooldown_seconds: non_neg_integer(),
      allowed_severity_levels: [atom()],
      max_blast_radius: :single_host | :subnet | :org_wide
    }
  end

  defmodule AgentDefinition do
    @moduledoc "Complete agent definition"
    defstruct [
      :id,
      :name,
      :description,
      :org_id,
      :created_by,
      :created_at,
      :updated_at,
      triggers: [],
      data_sources: [],
      reasoning_chain: [],
      allowed_actions: [],
      guardrails: %Guardrails{},
      schedule: nil,
      enabled: false,
      version: 1,
      tags: [],
      metrics: %{
        executions: 0,
        successes: 0,
        failures: 0,
        actions_taken: 0,
        last_executed_at: nil
      }
    ]

    @type t :: %__MODULE__{
      id: String.t(),
      name: String.t(),
      description: String.t(),
      org_id: String.t(),
      created_by: String.t() | nil,
      created_at: DateTime.t(),
      updated_at: DateTime.t(),
      triggers: [Trigger.t()],
      data_sources: [atom()],
      reasoning_chain: [ReasoningStep.t()],
      allowed_actions: [atom()],
      guardrails: Guardrails.t(),
      schedule: String.t() | nil,
      enabled: boolean(),
      version: pos_integer(),
      tags: [String.t()],
      metrics: map()
    }
  end

  # Allowed data sources agents can access
  @valid_data_sources ~w(
    alerts telemetry threat_intel processes files network dns registry
    user_activity asset_inventory vulnerabilities cloud_logs identity_logs
    email_logs firewall_logs proxy_logs siem_events
  )a

  # Actions classified by risk level
  @low_risk_actions ~w(
    enrich_hash enrich_ip enrich_domain enrich_url get_threat_intel
    run_search collect_logs scan_yara run_osquery add_to_watchlist
    send_email send_slack send_teams create_ticket update_ticket
    set_variable
  )a

  @medium_risk_actions ~w(
    kill_process quarantine_file block_hash capture_traffic
    collect_memory page_oncall create_case
  )a

  @high_risk_actions ~w(
    isolate_host delete_file block_ip block_domain disable_user
    revoke_sessions reset_password revoke_mfa revoke_aws_credentials
    isolate_ec2 disable_azure_user revoke_gcp_credentials
  )a

  @all_valid_actions @low_risk_actions ++ @medium_risk_actions ++ @high_risk_actions

  # Dangerous action combinations that should be blocked
  @unsafe_combinations [
    # Don't allow both isolation and user disable (too aggressive)
    {:isolate_host, :disable_user},
    # Don't allow delete and no quarantine
    {:delete_file, :delete_file}
  ]

  # ============================================================================
  # GenServer State
  # ============================================================================

  defstruct [
    :agents,
    :agents_by_org
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Build a new AI security agent from a natural language description.

  Parses the description into a structured agent specification with trigger
  conditions, reasoning steps, allowed actions, and guardrails.

  ## Parameters
    - description: Natural language description of what the agent should do
    - capabilities: List of action atoms the agent is allowed to perform
    - guardrails: Map of safety constraints
    - org_id: Organization ID for multi-tenant scoping

  ## Returns
    - `{:ok, agent_definition}` on success
    - `{:error, reason}` on validation failure
  """
  @spec build_agent(String.t(), [atom()], map(), String.t()) ::
          {:ok, AgentDefinition.t()} | {:error, String.t()}
  def build_agent(description, capabilities, guardrails, org_id) do
    GenServer.call(__MODULE__, {:build_agent, description, capabilities, guardrails, org_id})
  end

  @doc """
  Create an agent from an explicit definition map (no NL parsing).
  """
  @spec create_agent(map()) :: {:ok, AgentDefinition.t()} | {:error, String.t()}
  def create_agent(attrs) do
    GenServer.call(__MODULE__, {:create_agent, attrs})
  end

  @doc """
  Update an existing agent definition.
  """
  @spec update_agent(String.t(), map()) :: {:ok, AgentDefinition.t()} | {:error, String.t()}
  def update_agent(agent_id, attrs) do
    GenServer.call(__MODULE__, {:update_agent, agent_id, attrs})
  end

  @doc """
  Get an agent definition by ID.
  """
  @spec get_agent(String.t()) :: {:ok, AgentDefinition.t()} | {:error, :not_found}
  def get_agent(agent_id) do
    case :ets.lookup(@agents_table, agent_id) do
      [{^agent_id, agent}] -> {:ok, agent}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  List all agents for an organization.
  """
  @spec list_agents(String.t()) :: [AgentDefinition.t()]
  def list_agents(org_id) do
    case :ets.lookup(@agents_by_org_table, org_id) do
      [{^org_id, agent_ids}] ->
        agent_ids
        |> Enum.map(fn id ->
          case :ets.lookup(@agents_table, id) do
            [{^id, agent}] -> agent
            [] -> nil
          end
        end)
        |> Enum.reject(&is_nil/1)

      [] ->
        []
    end
  end

  @doc """
  List all enabled agents across all orgs (used by Runtime).
  """
  @spec list_enabled_agents() :: [AgentDefinition.t()]
  def list_enabled_agents do
    :ets.tab2list(@agents_table)
    |> Enum.map(fn {_id, agent} -> agent end)
    |> Enum.filter(& &1.enabled)
  end

  @doc """
  Enable an agent for execution.
  """
  @spec enable_agent(String.t()) :: :ok | {:error, :not_found}
  def enable_agent(agent_id) do
    GenServer.call(__MODULE__, {:set_enabled, agent_id, true})
  end

  @doc """
  Disable an agent (stops execution).
  """
  @spec disable_agent(String.t()) :: :ok | {:error, :not_found}
  def disable_agent(agent_id) do
    GenServer.call(__MODULE__, {:set_enabled, agent_id, false})
  end

  @doc """
  Delete an agent definition.
  """
  @spec delete_agent(String.t()) :: :ok | {:error, :not_found}
  def delete_agent(agent_id) do
    GenServer.call(__MODULE__, {:delete_agent, agent_id})
  end

  @doc """
  Update agent execution metrics.
  Called by the Runtime engine after each execution.
  """
  @spec update_metrics(String.t(), :success | :failure, non_neg_integer()) :: :ok
  def update_metrics(agent_id, outcome, actions_taken) do
    GenServer.cast(__MODULE__, {:update_metrics, agent_id, outcome, actions_taken})
  end

  @doc """
  Validate an agent definition against safety rules.
  """
  @spec validate_definition(AgentDefinition.t()) :: :ok | {:error, [String.t()]}
  def validate_definition(agent) do
    errors = []

    # Check name
    errors = if is_nil(agent.name) or agent.name == "", do: ["Name is required" | errors], else: errors

    # Check org_id
    errors = if is_nil(agent.org_id) or agent.org_id == "", do: ["org_id is required" | errors], else: errors

    # Check triggers
    errors = if Enum.empty?(agent.triggers), do: ["At least one trigger is required" | errors], else: errors

    # Check reasoning chain
    errors = if Enum.empty?(agent.reasoning_chain), do: ["At least one reasoning step is required" | errors], else: errors

    # Validate allowed actions
    invalid_actions = Enum.reject(agent.allowed_actions, &(&1 in @all_valid_actions))
    errors = if invalid_actions != [], do: ["Invalid actions: #{inspect(invalid_actions)}" | errors], else: errors

    # Check for unsafe action combinations
    errors = Enum.reduce(@unsafe_combinations, errors, fn {a, b}, acc ->
      if a in agent.allowed_actions and b in agent.allowed_actions do
        ["Unsafe action combination: #{a} + #{b}" | acc]
      else
        acc
      end
    end)

    # Validate data sources
    invalid_sources = Enum.reject(agent.data_sources, &(&1 in @valid_data_sources))
    errors = if invalid_sources != [], do: ["Invalid data sources: #{inspect(invalid_sources)}" | errors], else: errors

    # Validate guardrails
    errors = validate_guardrails(agent.guardrails, agent.allowed_actions, errors)

    case errors do
      [] -> :ok
      _ -> {:error, Enum.reverse(errors)}
    end
  end

  @doc """
  Get the risk level for a given action.
  """
  @spec action_risk_level(atom()) :: :low | :medium | :high | :unknown
  def action_risk_level(action) do
    cond do
      action in @low_risk_actions -> :low
      action in @medium_risk_actions -> :medium
      action in @high_risk_actions -> :high
      true -> :unknown
    end
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("[AgentBuilder] Starting Agent Builder Engine")

    :ets.new(@agents_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@agents_by_org_table, [:named_table, :set, :public, read_concurrency: true])

    # Load existing agents from database
    load_agents_from_db()

    {:ok, %__MODULE__{agents: %{}, agents_by_org: %{}}}
  end

  @impl true
  def handle_call({:build_agent, description, capabilities, guardrails_map, org_id}, _from, state) do
    agent_id = Ecto.UUID.generate()
    now = DateTime.utc_now()

    # Parse natural language into structured spec
    parsed = parse_description(description)

    # Build guardrails struct
    guardrails = build_guardrails(guardrails_map)

    # Filter capabilities to only valid ones
    valid_caps = Enum.filter(capabilities, &(&1 in @all_valid_actions))

    # Ensure high-risk actions require approval if not already set
    auto_approval_actions =
      valid_caps
      |> Enum.filter(&(&1 in @high_risk_actions))
      |> Enum.reject(&(&1 in guardrails.require_approval_for))

    guardrails =
      if auto_approval_actions != [] do
        %{guardrails | require_approval_for: guardrails.require_approval_for ++ auto_approval_actions}
      else
        guardrails
      end

    agent = %AgentDefinition{
      id: agent_id,
      name: parsed.name,
      description: description,
      org_id: org_id,
      created_at: now,
      updated_at: now,
      triggers: parsed.triggers,
      data_sources: parsed.data_sources,
      reasoning_chain: parsed.reasoning_chain,
      allowed_actions: valid_caps,
      guardrails: guardrails,
      schedule: parsed.schedule,
      enabled: false,
      tags: parsed.tags
    }

    case validate_definition(agent) do
      :ok ->
        store_agent(agent)
        persist_agent(agent)

        Logger.info("[AgentBuilder] Built agent '#{agent.name}' (#{agent_id}) for org #{org_id}")

        Phoenix.PubSub.broadcast(
          TamanduaServer.PubSub,
          "agentic:#{org_id}",
          {:agent_created, agent_id, agent.name}
        )

        {:reply, {:ok, agent}, state}

      {:error, errors} ->
        {:reply, {:error, "Validation failed: #{Enum.join(errors, "; ")}"}, state}
    end
  end

  @impl true
  def handle_call({:create_agent, attrs}, _from, state) do
    agent_id = attrs[:id] || Ecto.UUID.generate()
    now = DateTime.utc_now()

    guardrails = case attrs[:guardrails] do
      %Guardrails{} = g -> g
      m when is_map(m) -> build_guardrails(m)
      _ -> %Guardrails{}
    end

    triggers = build_triggers(attrs[:triggers] || [])
    reasoning = build_reasoning_chain(attrs[:reasoning_chain] || [])

    agent = %AgentDefinition{
      id: agent_id,
      name: attrs[:name] || "Custom Agent",
      description: attrs[:description] || "",
      org_id: attrs[:org_id],
      created_by: attrs[:created_by],
      created_at: now,
      updated_at: now,
      triggers: triggers,
      data_sources: attrs[:data_sources] || [],
      reasoning_chain: reasoning,
      allowed_actions: attrs[:allowed_actions] || [],
      guardrails: guardrails,
      schedule: attrs[:schedule],
      enabled: attrs[:enabled] || false,
      tags: attrs[:tags] || []
    }

    case validate_definition(agent) do
      :ok ->
        store_agent(agent)
        persist_agent(agent)
        Logger.info("[AgentBuilder] Created agent '#{agent.name}' (#{agent_id})")
        {:reply, {:ok, agent}, state}

      {:error, errors} ->
        {:reply, {:error, "Validation failed: #{Enum.join(errors, "; ")}"}, state}
    end
  end

  @impl true
  def handle_call({:update_agent, agent_id, attrs}, _from, state) do
    case :ets.lookup(@agents_table, agent_id) do
      [{^agent_id, existing}] ->
        updated = apply_updates(existing, attrs)

        case validate_definition(updated) do
          :ok ->
            store_agent(updated)
            persist_agent(updated)
            Logger.info("[AgentBuilder] Updated agent '#{updated.name}' (#{agent_id})")

            Phoenix.PubSub.broadcast(
              TamanduaServer.PubSub,
              "agentic:#{updated.org_id}",
              {:agent_updated, agent_id}
            )

            {:reply, {:ok, updated}, state}

          {:error, errors} ->
            {:reply, {:error, "Validation failed: #{Enum.join(errors, "; ")}"}, state}
        end

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:set_enabled, agent_id, enabled}, _from, state) do
    case :ets.lookup(@agents_table, agent_id) do
      [{^agent_id, agent}] ->
        updated = %{agent | enabled: enabled, updated_at: DateTime.utc_now()}
        store_agent(updated)
        persist_agent(updated)

        event = if enabled, do: :agent_enabled, else: :agent_disabled
        Logger.info("[AgentBuilder] Agent '#{agent.name}' (#{agent_id}) #{event}")

        Phoenix.PubSub.broadcast(
          TamanduaServer.PubSub,
          "agentic:#{agent.org_id}",
          {event, agent_id}
        )

        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:delete_agent, agent_id}, _from, state) do
    case :ets.lookup(@agents_table, agent_id) do
      [{^agent_id, agent}] ->
        :ets.delete(@agents_table, agent_id)
        remove_from_org_index(agent.org_id, agent_id)
        delete_agent_from_db(agent_id)

        Logger.info("[AgentBuilder] Deleted agent '#{agent.name}' (#{agent_id})")

        Phoenix.PubSub.broadcast(
          TamanduaServer.PubSub,
          "agentic:#{agent.org_id}",
          {:agent_deleted, agent_id}
        )

        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_cast({:update_metrics, agent_id, outcome, actions_taken}, state) do
    case :ets.lookup(@agents_table, agent_id) do
      [{^agent_id, agent}] ->
        metrics = agent.metrics
        updated_metrics = %{
          metrics |
          executions: metrics.executions + 1,
          successes: metrics.successes + if(outcome == :success, do: 1, else: 0),
          failures: metrics.failures + if(outcome == :failure, do: 1, else: 0),
          actions_taken: metrics.actions_taken + actions_taken,
          last_executed_at: DateTime.utc_now()
        }
        updated = %{agent | metrics: updated_metrics, updated_at: DateTime.utc_now()}
        :ets.insert(@agents_table, {agent_id, updated})
        {:noreply, state}

      [] ->
        {:noreply, state}
    end
  end

  # ============================================================================
  # Natural Language Parsing
  # ============================================================================

  defp parse_description(description) do
    lower = String.downcase(description)
    words = String.split(lower, ~r/[\s,;.]+/, trim: true)

    %{
      name: extract_name(description),
      triggers: extract_triggers(lower, words),
      data_sources: extract_data_sources(lower, words),
      reasoning_chain: extract_reasoning_chain(lower, words, description),
      schedule: extract_schedule(lower),
      tags: extract_tags(lower, words)
    }
  end

  defp extract_name(description) do
    # Use first clause up to a comma, or first 60 chars
    name = description
    |> String.split(~r/[,.]/, parts: 2)
    |> List.first()
    |> String.trim()

    if String.length(name) > 60 do
      String.slice(name, 0, 57) <> "..."
    else
      name
    end
  end

  defp extract_triggers(lower, _words) do
    triggers = []

    # Alert-based triggers
    triggers = cond do
      String.contains?(lower, "critical") and String.contains?(lower, "alert") ->
        [%Trigger{type: :alert, conditions: %{severity: :critical}} | triggers]

      String.contains?(lower, "high") and String.contains?(lower, "alert") ->
        [%Trigger{type: :alert, conditions: %{severity: :high}} | triggers]

      String.contains?(lower, "alert") ->
        [%Trigger{type: :alert, conditions: %{}} | triggers]

      true ->
        triggers
    end

    # Detection-type triggers
    triggers = cond do
      String.contains?(lower, "ransomware") ->
        [%Trigger{type: :alert, conditions: %{detection_type: "ransomware"}} | triggers]

      String.contains?(lower, "phishing") ->
        [%Trigger{type: :alert, conditions: %{detection_type: "phishing"}} | triggers]

      String.contains?(lower, "lateral") ->
        [%Trigger{type: :alert, conditions: %{mitre_tactic: "lateral-movement"}} | triggers]

      String.contains?(lower, "credential") ->
        [%Trigger{type: :alert, conditions: %{mitre_tactic: "credential-access"}} | triggers]

      String.contains?(lower, "exfil") ->
        [%Trigger{type: :alert, conditions: %{mitre_tactic: "exfiltration"}} | triggers]

      true ->
        triggers
    end

    # Schedule-based triggers
    triggers = if String.contains?(lower, "schedule") or String.contains?(lower, "every") or
                  String.contains?(lower, "daily") or String.contains?(lower, "weekly") do
      [%Trigger{type: :schedule, conditions: %{}} | triggers]
    else
      triggers
    end

    # Default trigger if none detected
    if Enum.empty?(triggers) do
      [%Trigger{type: :alert, conditions: %{}}]
    else
      Enum.uniq_by(triggers, & &1.type)
    end
  end

  defp extract_data_sources(lower, _words) do
    sources = []
    sources = if String.contains?(lower, "alert"), do: [:alerts | sources], else: sources
    sources = if String.contains?(lower, "telemetry") or String.contains?(lower, "event"), do: [:telemetry | sources], else: sources
    sources = if String.contains?(lower, "threat") and String.contains?(lower, "intel"), do: [:threat_intel | sources], else: sources
    sources = if String.contains?(lower, "process"), do: [:processes | sources], else: sources
    sources = if String.contains?(lower, "file"), do: [:files | sources], else: sources
    sources = if String.contains?(lower, "network") or String.contains?(lower, "ip") or String.contains?(lower, "domain"), do: [:network | sources], else: sources
    sources = if String.contains?(lower, "dns"), do: [:dns | sources], else: sources
    sources = if String.contains?(lower, "user") or String.contains?(lower, "identity"), do: [:user_activity | sources], else: sources
    sources = if String.contains?(lower, "email"), do: [:email_logs | sources], else: sources
    sources = if String.contains?(lower, "vuln"), do: [:vulnerabilities | sources], else: sources
    sources = if String.contains?(lower, "cloud") or String.contains?(lower, "aws") or String.contains?(lower, "azure"), do: [:cloud_logs | sources], else: sources

    if Enum.empty?(sources), do: [:alerts, :telemetry], else: Enum.uniq(sources)
  end

  defp extract_reasoning_chain(lower, _words, _description) do
    steps = []
    step_counter = 0

    # Detect investigation/enrichment steps
    {steps, step_counter} = if String.contains?(lower, "analyze") or String.contains?(lower, "investigate") or
                               String.contains?(lower, "check") or String.contains?(lower, "look") do
      step = %ReasoningStep{
        id: "step_#{step_counter}",
        action: :enrich_context,
        params: %{},
        timeout_ms: 30_000
      }
      {[step | steps], step_counter + 1}
    else
      {steps, step_counter}
    end

    # Detect enrichment steps
    {steps, step_counter} = if String.contains?(lower, "reputation") or String.contains?(lower, "enrich") or
                               String.contains?(lower, "threat intel") do
      step = %ReasoningStep{
        id: "step_#{step_counter}",
        action: :threat_intel_lookup,
        params: %{},
        timeout_ms: 30_000
      }
      {[step | steps], step_counter + 1}
    else
      {steps, step_counter}
    end

    # Detect isolation steps
    {steps, step_counter} = if String.contains?(lower, "isolat") do
      step = %ReasoningStep{
        id: "step_#{step_counter}",
        action: :isolate_host,
        params: %{},
        timeout_ms: 60_000
      }
      {[step | steps], step_counter + 1}
    else
      {steps, step_counter}
    end

    # Detect process kill steps
    {steps, step_counter} = if String.contains?(lower, "kill") or String.contains?(lower, "terminat") do
      step = %ReasoningStep{
        id: "step_#{step_counter}",
        action: :kill_process,
        params: %{},
        timeout_ms: 30_000
      }
      {[step | steps], step_counter + 1}
    else
      {steps, step_counter}
    end

    # Detect quarantine steps
    {steps, step_counter} = if String.contains?(lower, "quarantin") do
      step = %ReasoningStep{
        id: "step_#{step_counter}",
        action: :quarantine_file,
        params: %{},
        timeout_ms: 30_000
      }
      {[step | steps], step_counter + 1}
    else
      {steps, step_counter}
    end

    # Detect memory/forensic collection
    {steps, step_counter} = if String.contains?(lower, "memory") or String.contains?(lower, "snapshot") or
                               String.contains?(lower, "forensic") or String.contains?(lower, "collect") do
      step = %ReasoningStep{
        id: "step_#{step_counter}",
        action: :collect_evidence,
        params: %{type: :memory_dump},
        timeout_ms: 120_000
      }
      {[step | steps], step_counter + 1}
    else
      {steps, step_counter}
    end

    # Detect blocking steps
    {steps, step_counter} = if String.contains?(lower, "block") do
      action = cond do
        String.contains?(lower, "ip") -> :block_ip
        String.contains?(lower, "domain") -> :block_domain
        String.contains?(lower, "hash") -> :block_hash
        true -> :block_ip
      end
      step = %ReasoningStep{
        id: "step_#{step_counter}",
        action: action,
        params: %{},
        timeout_ms: 30_000
      }
      {[step | steps], step_counter + 1}
    else
      {steps, step_counter}
    end

    # Detect notification steps
    {steps, step_counter} = if String.contains?(lower, "notify") or String.contains?(lower, "slack") or
                               String.contains?(lower, "alert") and String.contains?(lower, "team") do
      step = %ReasoningStep{
        id: "step_#{step_counter}",
        action: :notify,
        params: %{channel: extract_channel(lower)},
        timeout_ms: 10_000
      }
      {[step | steps], step_counter + 1}
    else
      {steps, step_counter}
    end

    # Detect report generation
    {steps, _step_counter} = if String.contains?(lower, "report") do
      step = %ReasoningStep{
        id: "step_#{step_counter}",
        action: :generate_report,
        params: %{},
        timeout_ms: 60_000
      }
      {[step | steps], step_counter + 1}
    else
      {steps, step_counter}
    end

    # Default: at minimum, enrich and notify
    steps = if Enum.empty?(steps) do
      [
        %ReasoningStep{id: "step_0", action: :enrich_context, params: %{}, timeout_ms: 30_000},
        %ReasoningStep{id: "step_1", action: :notify, params: %{}, timeout_ms: 10_000}
      ]
    else
      Enum.reverse(steps)
    end

    # Wire up on_success chain
    steps
    |> Enum.with_index()
    |> Enum.map(fn {step, idx} ->
      next_id = if idx + 1 < length(steps), do: Enum.at(steps, idx + 1).id, else: nil
      %{step | on_success: next_id}
    end)
  end

  defp extract_schedule(lower) do
    cond do
      String.contains?(lower, "every hour") -> "0 * * * *"
      String.contains?(lower, "daily") -> "0 0 * * *"
      String.contains?(lower, "weekly") -> "0 0 * * 1"
      String.contains?(lower, "every 5 min") -> "*/5 * * * *"
      String.contains?(lower, "every 15 min") -> "*/15 * * * *"
      true -> nil
    end
  end

  defp extract_tags(lower, _words) do
    tags = []
    tags = if String.contains?(lower, "ransomware"), do: ["ransomware" | tags], else: tags
    tags = if String.contains?(lower, "phishing"), do: ["phishing" | tags], else: tags
    tags = if String.contains?(lower, "lateral"), do: ["lateral-movement" | tags], else: tags
    tags = if String.contains?(lower, "credential"), do: ["credential-access" | tags], else: tags
    tags = if String.contains?(lower, "exfil"), do: ["exfiltration" | tags], else: tags
    tags = if String.contains?(lower, "insider"), do: ["insider-threat" | tags], else: tags
    tags = if String.contains?(lower, "compliance"), do: ["compliance" | tags], else: tags
    tags = if String.contains?(lower, "vulnerab"), do: ["vulnerability" | tags], else: tags
    if Enum.empty?(tags), do: ["custom"], else: tags
  end

  defp extract_channel(lower) do
    cond do
      String.contains?(lower, "#") ->
        case Regex.run(~r/#[\w-]+/, lower) do
          [channel] -> channel
          _ -> "#security-ops"
        end
      String.contains?(lower, "soc") -> "#soc"
      String.contains?(lower, "security") -> "#security-ops"
      true -> "#security-ops"
    end
  end

  # ============================================================================
  # Helper Builders
  # ============================================================================

  defp build_guardrails(map) when is_map(map) do
    %Guardrails{
      max_actions_per_hour: Map.get(map, :max_actions_per_hour, Map.get(map, "max_actions_per_hour", 50)),
      require_approval_for: Map.get(map, :require_approval_for, Map.get(map, "require_approval_for", [])),
      scope_filter: Map.get(map, :scope_filter, Map.get(map, "scope_filter", %{})),
      blocked_actions: Map.get(map, :blocked_actions, Map.get(map, "blocked_actions", [])),
      max_concurrent_executions: Map.get(map, :max_concurrent_executions, Map.get(map, "max_concurrent_executions", 5)),
      cooldown_seconds: Map.get(map, :cooldown_seconds, Map.get(map, "cooldown_seconds", 0)),
      allowed_severity_levels: Map.get(map, :allowed_severity_levels, Map.get(map, "allowed_severity_levels", [:low, :medium, :high, :critical])),
      max_blast_radius: Map.get(map, :max_blast_radius, Map.get(map, "max_blast_radius", :single_host))
    }
  end

  defp build_guardrails(_), do: %Guardrails{}

  defp build_triggers(triggers) when is_list(triggers) do
    Enum.map(triggers, fn
      %Trigger{} = t -> t
      %{type: type} = t -> %Trigger{type: type, conditions: Map.get(t, :conditions, %{})}
      %{"type" => type} = t -> %Trigger{type: String.to_existing_atom(type), conditions: Map.get(t, "conditions", %{})}
      _ -> %Trigger{type: :alert, conditions: %{}}
    end)
  end

  defp build_triggers(_), do: [%Trigger{type: :alert, conditions: %{}}]

  defp build_reasoning_chain(chain) when is_list(chain) do
    chain
    |> Enum.with_index()
    |> Enum.map(fn {step, idx} ->
      case step do
        %ReasoningStep{} = s -> s
        %{action: action} = s ->
          %ReasoningStep{
            id: Map.get(s, :id, "step_#{idx}"),
            action: action,
            params: Map.get(s, :params, %{}),
            condition: Map.get(s, :condition),
            on_success: Map.get(s, :on_success),
            on_failure: Map.get(s, :on_failure),
            timeout_ms: Map.get(s, :timeout_ms, 30_000)
          }
        _ ->
          %ReasoningStep{id: "step_#{idx}", action: :noop, params: %{}, timeout_ms: 30_000}
      end
    end)
  end

  defp build_reasoning_chain(_), do: []

  defp apply_updates(existing, attrs) do
    now = DateTime.utc_now()

    %{existing |
      name: Map.get(attrs, :name, existing.name),
      description: Map.get(attrs, :description, existing.description),
      triggers: if(Map.has_key?(attrs, :triggers), do: build_triggers(attrs.triggers), else: existing.triggers),
      data_sources: Map.get(attrs, :data_sources, existing.data_sources),
      reasoning_chain: if(Map.has_key?(attrs, :reasoning_chain), do: build_reasoning_chain(attrs.reasoning_chain), else: existing.reasoning_chain),
      allowed_actions: Map.get(attrs, :allowed_actions, existing.allowed_actions),
      guardrails: if(Map.has_key?(attrs, :guardrails), do: build_guardrails(attrs.guardrails), else: existing.guardrails),
      schedule: Map.get(attrs, :schedule, existing.schedule),
      tags: Map.get(attrs, :tags, existing.tags),
      version: existing.version + 1,
      updated_at: now
    }
  end

  # ============================================================================
  # Validation Helpers
  # ============================================================================

  defp validate_guardrails(guardrails, allowed_actions, errors) do
    # Ensure rate limit is reasonable
    errors = if guardrails.max_actions_per_hour > 1000 do
      ["max_actions_per_hour cannot exceed 1000" | errors]
    else
      errors
    end

    # Ensure approval-required actions are in allowed actions
    invalid_approval = Enum.reject(guardrails.require_approval_for, &(&1 in allowed_actions))
    errors = if invalid_approval != [] do
      ["require_approval_for contains actions not in allowed_actions: #{inspect(invalid_approval)}" | errors]
    else
      errors
    end

    # Ensure blocked actions are not in allowed actions
    conflicts = Enum.filter(guardrails.blocked_actions, &(&1 in allowed_actions))
    errors = if conflicts != [] do
      ["blocked_actions conflict with allowed_actions: #{inspect(conflicts)}" | errors]
    else
      errors
    end

    errors
  end

  # ============================================================================
  # Storage
  # ============================================================================

  defp store_agent(agent) do
    :ets.insert(@agents_table, {agent.id, agent})
    add_to_org_index(agent.org_id, agent.id)
  end

  defp add_to_org_index(org_id, agent_id) do
    case :ets.lookup(@agents_by_org_table, org_id) do
      [{^org_id, ids}] ->
        unless agent_id in ids do
          :ets.insert(@agents_by_org_table, {org_id, [agent_id | ids]})
        end
      [] ->
        :ets.insert(@agents_by_org_table, {org_id, [agent_id]})
    end
  end

  defp remove_from_org_index(org_id, agent_id) do
    case :ets.lookup(@agents_by_org_table, org_id) do
      [{^org_id, ids}] ->
        :ets.insert(@agents_by_org_table, {org_id, List.delete(ids, agent_id)})
      [] ->
        :ok
    end
  end

  defp persist_agent(agent) do
    Task.start(fn ->
      try do
        data = %{
          id: agent.id,
          name: agent.name,
          description: agent.description,
          org_id: agent.org_id,
          definition: serialize_agent(agent),
          enabled: agent.enabled,
          version: agent.version,
          inserted_at: agent.created_at,
          updated_at: agent.updated_at
        }

        Repo.insert_all(
          "agentic_agents",
          [data],
          on_conflict: {:replace, [:name, :description, :definition, :enabled, :version, :updated_at]},
          conflict_target: :id
        )
      rescue
        e -> Logger.debug("[AgentBuilder] DB persist skipped: #{Exception.message(e)}")
      end
    end)
  end

  defp delete_agent_from_db(agent_id) do
    Task.start(fn ->
      try do
        import Ecto.Query
        Repo.delete_all(from(a in "agentic_agents", where: a.id == ^agent_id))
      rescue
        _ -> :ok
      end
    end)
  end

  defp load_agents_from_db do
    try do
      import Ecto.Query

      agents = Repo.all(
        from(a in "agentic_agents",
          select: %{
            id: a.id,
            name: a.name,
            description: a.description,
            org_id: a.org_id,
            definition: a.definition,
            enabled: a.enabled,
            version: a.version
          }
        )
      )

      Enum.each(agents, fn row ->
        agent = deserialize_agent(row)
        if agent, do: store_agent(agent)
      end)

      Logger.info("[AgentBuilder] Loaded #{length(agents)} agents from database")
    rescue
      e -> Logger.debug("[AgentBuilder] DB load skipped: #{Exception.message(e)}")
    end
  end

  defp serialize_agent(agent) do
    %{
      "triggers" => Enum.map(agent.triggers, &Map.from_struct/1),
      "data_sources" => Enum.map(agent.data_sources, &Atom.to_string/1),
      "reasoning_chain" => Enum.map(agent.reasoning_chain, &Map.from_struct/1),
      "allowed_actions" => Enum.map(agent.allowed_actions, &Atom.to_string/1),
      "guardrails" => Map.from_struct(agent.guardrails),
      "schedule" => agent.schedule,
      "tags" => agent.tags,
      "metrics" => agent.metrics,
      "created_by" => agent.created_by
    }
  end

  defp deserialize_agent(row) do
    try do
      defn = row.definition || %{}

      %AgentDefinition{
        id: row.id,
        name: row.name,
        description: row.description || "",
        org_id: row.org_id,
        created_at: DateTime.utc_now(),
        updated_at: DateTime.utc_now(),
        triggers: (defn["triggers"] || []) |> Enum.map(fn t ->
          %Trigger{
            type: safe_to_atom(t["type"], :alert),
            conditions: t["conditions"] || %{}
          }
        end),
        data_sources: (defn["data_sources"] || []) |> Enum.map(&safe_to_atom(&1, :alerts)),
        reasoning_chain: (defn["reasoning_chain"] || []) |> Enum.with_index() |> Enum.map(fn {s, i} ->
          %ReasoningStep{
            id: s["id"] || "step_#{i}",
            action: safe_to_atom(s["action"], :noop),
            params: s["params"] || %{},
            condition: s["condition"],
            on_success: s["on_success"],
            on_failure: s["on_failure"],
            timeout_ms: s["timeout_ms"] || 30_000
          }
        end),
        allowed_actions: (defn["allowed_actions"] || []) |> Enum.map(&safe_to_atom(&1, :noop)),
        guardrails: build_guardrails(defn["guardrails"] || %{}),
        schedule: defn["schedule"],
        enabled: row.enabled || false,
        version: row.version || 1,
        tags: defn["tags"] || [],
        metrics: defn["metrics"] || %{executions: 0, successes: 0, failures: 0, actions_taken: 0, last_executed_at: nil}
      }
    rescue
      _ -> nil
    end
  end

  defp safe_to_atom(val, default) when is_binary(val) do
    try do
      String.to_existing_atom(val)
    rescue
      _ -> default
    end
  end

  defp safe_to_atom(val, _default) when is_atom(val), do: val
  defp safe_to_atom(_, default), do: default
end
