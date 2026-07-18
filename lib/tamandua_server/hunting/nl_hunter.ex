defmodule TamanduaServer.Hunting.NLHunter do
  @moduledoc """
  Natural Language Threat Hunting Engine

  Provides an advanced interface for security analysts to perform threat hunting
  using natural language queries. Translates human intent into detection queries,
  generates hypotheses, gathers evidence, and produces hunt playbooks.

  Features:
  - Natural language query parsing with entity extraction
  - LLM-powered query translation (GPT/Claude via LLMClient)
  - Intent detection and query translation
  - Hypothesis generation based on threat intelligence
  - Automated evidence gathering and correlation
  - Hunt playbook generation
  - Interactive query refinement
  - Learning from successful hunts
  - Hunt timeline tracking

  Example queries:
  - "Find all processes connecting to IPs in Russia after business hours"
  - "Show me lateral movement attempts using PsExec or WMI"
  - "Hunt for data exfiltration from finance department hosts"
  - "Investigate encoded PowerShell commands that bypass execution policy"
  """

  use GenServer
  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Telemetry.Event
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.AI.LLMClient

  @hunt_session_ttl :timer.hours(24)
  @max_results 1000
  @evidence_batch_size 100

  # Entity types for extraction
  defp entity_patterns do
    %{
    ip_address: ~r/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/,
    domain: ~r/\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/,
    hash_sha256: ~r/\b[a-fA-F0-9]{64}\b/,
    hash_md5: ~r/\b[a-fA-F0-9]{32}\b/,
    file_path: ~r/(?:[A-Za-z]:[\\\/][^\s:*?"<>|]+|\/[^\s:*?"<>|]+)/,
    username: ~r/\b(?:user|admin|administrator|root|system)\b/i,
    process_name: ~r/\b\w+\.exe\b/i,
    port: ~r/\bport\s*(?:number\s*)?(\d{1,5})\b/i,
    time_range: ~r/(?:last|past)\s+(\d+)\s*(hour|day|week|month)s?/i,
    mitre_technique: ~r/\bT\d{4}(?:\.\d{3})?\b/
    }
  end

  # Intent patterns for query classification
  defp intent_patterns do
    %{
    hunt_lateral_movement: [
      ~r/lateral\s*movement/i,
      ~r/spread|propagat/i,
      ~r/psexec|wmi|smb|winrm/i,
      ~r/remote\s*(?:execution|access)/i
    ],
    hunt_credential_theft: [
      ~r/credential|password|hash/i,
      ~r/mimikatz|lsass|sam|ntds/i,
      ~r/kerberos|golden\s*ticket/i,
      ~r/pass.the.hash/i
    ],
    hunt_persistence: [
      ~r/persist|autostart|startup/i,
      ~r/run\s*key|scheduled\s*task/i,
      ~r/service\s*(?:creation|install)/i,
      ~r/registry.+run/i
    ],
    hunt_exfiltration: [
      ~r/exfil|data\s*(?:theft|leak)/i,
      ~r/large\s*(?:upload|transfer)/i,
      ~r/unusual\s*(?:traffic|bandwidth)/i
    ],
    hunt_command_control: [
      ~r/c2|c&c|command.+control/i,
      ~r/beacon|callback|heartbeat/i,
      ~r/suspicious\s*(?:connection|traffic)/i
    ],
    hunt_malware: [
      ~r/malware|virus|trojan|ransomware/i,
      ~r/suspicious\s*(?:file|binary|executable)/i,
      ~r/dropper|loader|payload/i
    ],
    hunt_powershell: [
      ~r/powershell|pwsh/i,
      ~r/encoded\s*command|base64/i,
      ~r/script\s*block/i
    ],
    hunt_process_anomaly: [
      ~r/process\s*(?:injection|hollow)/i,
      ~r/suspicious\s*(?:parent|child)/i,
      ~r/unusual\s*process/i
    ],
    investigate_host: [
      ~r/investigate\s*(?:host|machine|endpoint)/i,
      ~r/what\s*happened\s*(?:on|to)/i,
      ~r/activity\s*(?:on|from)\s*host/i
    ],
    investigate_user: [
      ~r/investigate\s*user/i,
      ~r/user\s*activity/i,
      ~r/account\s*(?:compromise|suspicious)/i
    ]
    }
  end

  # MITRE ATT&CK mapping for hypothesis generation
  @mitre_hypothesis_map %{
    "T1059.001" => %{
      name: "PowerShell Execution",
      hypotheses: [
        "Attacker using encoded PowerShell for obfuscation",
        "Fileless malware execution via PowerShell",
        "Malicious script download and execution"
      ],
      evidence_queries: [:powershell_encoded, :powershell_download, :powershell_bypass]
    },
    "T1003" => %{
      name: "Credential Dumping",
      hypotheses: [
        "Attacker harvesting credentials for lateral movement",
        "Memory dump of LSASS for offline extraction",
        "Registry-based credential theft"
      ],
      evidence_queries: [:lsass_access, :sam_access, :credential_files]
    },
    "T1021" => %{
      name: "Remote Services",
      hypotheses: [
        "Lateral movement using stolen credentials",
        "Remote command execution via WMI/PSExec",
        "Attacker pivoting through the network"
      ],
      evidence_queries: [:remote_execution, :smb_connections, :admin_shares]
    },
    "T1486" => %{
      name: "Data Encrypted for Impact",
      hypotheses: [
        "Ransomware encrypting files",
        "Attacker destroying backup shadow copies",
        "Mass file modification indicating encryption"
      ],
      evidence_queries: [:file_encryption, :shadow_delete, :ransom_extensions]
    }
  }

  # TQL (Tamandua Query Language) schema context for LLM translation
  @tql_schema_context """
  TQL (Tamandua Query Language) Syntax:
  - Basic: field:value (e.g., process.name:cmd.exe)
  - Contains: field:*value* (e.g., process.cmdline:*mimikatz*)
  - Regex: field:~pattern (e.g., process.cmdline:~.*encoded.*)
  - Comparison: field:>value, field:<value
  - Logical: AND, OR, NOT, parentheses for grouping

  Available fields:
  - process.name, process.path, process.cmdline, process.pid, process.ppid, process.user, process.sha256, process.is_elevated
  - network.remote_ip, network.remote_port, network.local_port, network.protocol, network.direction
  - file.path, file.name, file.sha256, file.operation
  - dns.query, dns.query_type, dns.response
  - registry.path, registry.key, registry.value, registry.operation
  - event.type, agent.id, agent.hostname

  Time ranges: Use time_range parameter, not in query.

  Examples:
  - "Find encoded PowerShell" -> process.name:powershell.exe AND process.cmdline:*-enc*
  - "Lateral movement with PsExec" -> process.name:psexec.exe OR (process.cmdline:*\\\\* AND process.cmdline:*-s*)
  - "LSASS access" -> process.name:*lsass* OR file.path:*lsass*
  - "Suspicious DNS to .xyz domains" -> dns.query:~.*\\.xyz$
  - "Large network transfers" -> network.bytes_sent:>10000000
  - "Registry run key modifications" -> registry.path:*\\Run* AND registry.operation:write
  - "Processes connecting to external IPs" -> network.direction:outbound AND NOT network.remote_ip:10.*
  """

  # LLM timeout for translation requests
  @llm_timeout 30_000

  defstruct [
    :sessions,
    :successful_hunts,
    :stats
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Start a new hunting session with a natural language query.
  Returns a session ID for tracking and refinement.
  """
  @spec start_hunt(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def start_hunt(query, opts \\ []) do
    GenServer.call(__MODULE__, {:start_hunt, query, opts}, 60_000)
  end

  @doc """
  Continue an existing hunt session with a follow-up query.
  """
  @spec continue_hunt(String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def continue_hunt(session_id, follow_up_query, opts \\ []) do
    GenServer.call(__MODULE__, {:continue_hunt, session_id, follow_up_query, opts}, 60_000)
  end

  @doc """
  Get the current state of a hunt session including timeline.
  """
  @spec get_hunt_session(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_hunt_session(session_id) do
    GenServer.call(__MODULE__, {:get_session, session_id})
  end

  @doc """
  Generate hypotheses based on initial findings.
  """
  @spec generate_hypotheses(String.t()) :: {:ok, [map()]} | {:error, term()}
  def generate_hypotheses(session_id) do
    GenServer.call(__MODULE__, {:generate_hypotheses, session_id})
  end

  @doc """
  Gather evidence for a specific hypothesis.
  """
  @spec gather_evidence(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def gather_evidence(session_id, hypothesis_id) do
    GenServer.call(__MODULE__, {:gather_evidence, session_id, hypothesis_id}, 120_000)
  end

  @doc """
  Generate a hunt playbook from the session findings.
  """
  @spec generate_playbook(String.t()) :: {:ok, map()} | {:error, term()}
  def generate_playbook(session_id) do
    GenServer.call(__MODULE__, {:generate_playbook, session_id})
  end

  @doc """
  Mark a hunt as successful and learn from it.
  """
  @spec mark_hunt_successful(String.t(), map()) :: :ok
  def mark_hunt_successful(session_id, metadata \\ %{}) do
    GenServer.cast(__MODULE__, {:mark_successful, session_id, metadata})
  end

  @doc """
  Get hunting suggestions based on successful past hunts.
  """
  @spec get_hunt_suggestions(keyword()) :: [map()]
  def get_hunt_suggestions(opts \\ []) do
    GenServer.call(__MODULE__, {:get_suggestions, opts})
  end

  @doc """
  Parse a natural language query and return structured components.
  """
  @spec parse_query(String.t()) :: map()
  def parse_query(query) do
    GenServer.call(__MODULE__, {:parse_query, query})
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    state = %__MODULE__{
      sessions: %{},
      successful_hunts: load_successful_hunts(),
      stats: %{
        hunts_started: 0,
        hunts_completed: 0,
        hypotheses_generated: 0,
        evidence_gathered: 0,
        playbooks_created: 0
      }
    }

    schedule_session_cleanup()
    Logger.info("NL Hunter engine started")
    {:ok, state}
  end

  @impl true
  def handle_call({:start_hunt, query, opts}, _from, state) do
    organization_id = Keyword.get(opts, :organization_id)
    analyst_id = Keyword.get(opts, :analyst_id)

    # Parse the query
    parsed = do_parse_query(query)

    # Create session
    session_id = generate_session_id()
    session = %{
      id: session_id,
      original_query: query,
      parsed_query: parsed,
      organization_id: organization_id,
      analyst_id: analyst_id,
      created_at: DateTime.utc_now(),
      timeline: [
        %{
          timestamp: DateTime.utc_now(),
          action: :hunt_started,
          query: query,
          parsed: parsed
        }
      ],
      findings: [],
      hypotheses: [],
      evidence: %{},
      status: :active
    }

    # Execute initial hunt
    {results, sigma_rule} = execute_hunt_query(parsed, organization_id)

    session = session
    |> Map.put(:initial_results, results)
    |> Map.put(:generated_sigma_rule, sigma_rule)
    |> Map.put(:result_count, length(results))
    |> add_timeline_entry(:initial_results, %{count: length(results)})

    # Auto-generate initial hypotheses if results found
    session = if length(results) > 0 do
      hypotheses = generate_initial_hypotheses(parsed, results)
      Map.put(session, :hypotheses, hypotheses)
    else
      session
    end

    new_sessions = Map.put(state.sessions, session_id, session)
    new_stats = Map.update!(state.stats, :hunts_started, &(&1 + 1))

    response = %{
      session_id: session_id,
      parsed_query: parsed,
      result_count: length(results),
      results: Enum.take(results, 50),
      hypotheses: session.hypotheses,
      generated_sigma_rule: sigma_rule,
      suggested_refinements: suggest_refinements(parsed, results)
    }

    {:reply, {:ok, response}, %{state | sessions: new_sessions, stats: new_stats}}
  end

  @impl true
  def handle_call({:continue_hunt, session_id, follow_up, opts}, _from, state) do
    case Map.get(state.sessions, session_id) do
      nil ->
        {:reply, {:error, :session_not_found}, state}

      session ->
        # Parse follow-up in context of original
        parsed = do_parse_query(follow_up, session.parsed_query)

        # Execute refined query
        {results, sigma_rule} = execute_hunt_query(
          parsed,
          session.organization_id,
          Keyword.merge(opts, context: session)
        )

        session = session
        |> add_timeline_entry(:follow_up_query, %{query: follow_up, parsed: parsed})
        |> add_timeline_entry(:follow_up_results, %{count: length(results)})
        |> Map.update!(:findings, &(&1 ++ results))

        new_sessions = Map.put(state.sessions, session_id, session)

        response = %{
          session_id: session_id,
          parsed_query: parsed,
          result_count: length(results),
          results: Enum.take(results, 50),
          generated_sigma_rule: sigma_rule,
          total_findings: length(session.findings) + length(results)
        }

        {:reply, {:ok, response}, %{state | sessions: new_sessions}}
    end
  end

  @impl true
  def handle_call({:get_session, session_id}, _from, state) do
    case Map.get(state.sessions, session_id) do
      nil -> {:reply, {:error, :not_found}, state}
      session -> {:reply, {:ok, session}, state}
    end
  end

  @impl true
  def handle_call({:generate_hypotheses, session_id}, _from, state) do
    case Map.get(state.sessions, session_id) do
      nil ->
        {:reply, {:error, :session_not_found}, state}

      session ->
        hypotheses = generate_hypotheses_from_session(session)

        session = session
        |> Map.put(:hypotheses, hypotheses)
        |> add_timeline_entry(:hypotheses_generated, %{count: length(hypotheses)})

        new_sessions = Map.put(state.sessions, session_id, session)
        new_stats = Map.update!(state.stats, :hypotheses_generated, &(&1 + length(hypotheses)))

        {:reply, {:ok, hypotheses}, %{state | sessions: new_sessions, stats: new_stats}}
    end
  end

  @impl true
  def handle_call({:gather_evidence, session_id, hypothesis_id}, _from, state) do
    case Map.get(state.sessions, session_id) do
      nil ->
        {:reply, {:error, :session_not_found}, state}

      session ->
        hypothesis = Enum.find(session.hypotheses, &(&1.id == hypothesis_id))

        if hypothesis do
          evidence = gather_evidence_for_hypothesis(hypothesis, session)

          session = session
          |> Map.update!(:evidence, &Map.put(&1, hypothesis_id, evidence))
          |> add_timeline_entry(:evidence_gathered, %{
            hypothesis_id: hypothesis_id,
            evidence_count: map_size(evidence)
          })

          new_sessions = Map.put(state.sessions, session_id, session)
          new_stats = Map.update!(state.stats, :evidence_gathered, &(&1 + 1))

          {:reply, {:ok, evidence}, %{state | sessions: new_sessions, stats: new_stats}}
        else
          {:reply, {:error, :hypothesis_not_found}, state}
        end
    end
  end

  @impl true
  def handle_call({:generate_playbook, session_id}, _from, state) do
    case Map.get(state.sessions, session_id) do
      nil ->
        {:reply, {:error, :session_not_found}, state}

      session ->
        playbook = build_hunt_playbook(session)

        session = session
        |> Map.put(:playbook, playbook)
        |> Map.put(:status, :completed)
        |> add_timeline_entry(:playbook_generated, %{})

        new_sessions = Map.put(state.sessions, session_id, session)
        new_stats = state.stats
        |> Map.update!(:playbooks_created, &(&1 + 1))
        |> Map.update!(:hunts_completed, &(&1 + 1))

        {:reply, {:ok, playbook}, %{state | sessions: new_sessions, stats: new_stats}}
    end
  end

  @impl true
  def handle_call({:get_suggestions, opts}, _from, state) do
    suggestions = generate_suggestions(state.successful_hunts, opts)
    {:reply, suggestions, state}
  end

  @impl true
  def handle_call({:parse_query, query}, _from, state) do
    parsed = do_parse_query(query)
    {:reply, parsed, state}
  end

  @impl true
  def handle_call({:execute_query, session_id, query_text}, _from, state) do
    # First, try to translate the query using LLM, then fall back to pattern matching
    {tql_query, translation_source} = case translate_query(query_text) do
      {:ok, %{tql: tql, source: source}} ->
        {tql, source}
      {:error, _} ->
        # Final fallback - use basic pattern matching
        {translate_with_patterns(query_text), :fallback}
    end

    case Map.get(state.sessions, session_id) do
      nil ->
        # Create a new session for this query
        organization_id = nil  # Would be extracted from context
        analyst_id = nil

        parsed = do_parse_query(query_text)
        # Add the TQL translation to parsed query
        parsed = Map.merge(parsed, %{
          tql_query: tql_query,
          translation_source: translation_source
        })

        new_session_id = generate_session_id()

        session = %{
          id: new_session_id,
          original_query: query_text,
          parsed_query: parsed,
          organization_id: organization_id,
          analyst_id: analyst_id,
          created_at: DateTime.utc_now(),
          timeline: [],
          findings: [],
          hypotheses: [],
          evidence: %{},
          status: :active
        }

        {results, sigma_rule} = execute_hunt_query(parsed, organization_id)

        session = Map.merge(session, %{
          initial_results: results,
          generated_sigma_rule: sigma_rule,
          result_count: length(results),
          tql_query: tql_query,
          translation_source: translation_source
        })

        new_sessions = Map.put(state.sessions, new_session_id, session)

        response = %{
          session_id: new_session_id,
          result_count: length(results),
          results: Enum.take(results, 50),
          generated_sigma_rule: sigma_rule,
          tql_query: tql_query,
          translation_source: translation_source
        }

        {:reply, {:ok, response}, %{state | sessions: new_sessions}}

      session ->
        # Execute query within existing session
        parsed = do_parse_query(query_text, session.parsed_query)
        # Add the TQL translation
        parsed = Map.merge(parsed, %{
          tql_query: tql_query,
          translation_source: translation_source
        })

        {results, sigma_rule} = execute_hunt_query(parsed, session.organization_id)

        updated_session = session
        |> add_timeline_entry(:query_executed, %{
          query: query_text,
          count: length(results),
          tql_query: tql_query,
          translation_source: translation_source
        })
        |> Map.update!(:findings, &(&1 ++ results))

        new_sessions = Map.put(state.sessions, session_id, updated_session)

        response = %{
          session_id: session_id,
          result_count: length(results),
          results: Enum.take(results, 50),
          generated_sigma_rule: sigma_rule,
          total_findings: length(updated_session.findings),
          tql_query: tql_query,
          translation_source: translation_source
        }

        {:reply, {:ok, response}, %{state | sessions: new_sessions}}
    end
  end

  @impl true
  def handle_call({:list_sessions, filters}, _from, state) do
    sessions = state.sessions
    |> Map.values()
    |> filter_sessions(filters)
    |> Enum.sort_by(& &1.created_at, {:desc, DateTime})
    |> Enum.take(Map.get(filters, :limit, 100))

    {:reply, {:ok, sessions}, state}
  end

  @impl true
  def handle_call({:query_suggestions, context}, _from, state) do
    suggestions = generate_suggestions(state.successful_hunts, context)
    {:reply, {:ok, suggestions}, state}
  end

  defp filter_sessions(sessions, filters) do
    sessions
    |> maybe_filter_by_status(Map.get(filters, :status))
    |> maybe_filter_by_organization(Map.get(filters, :organization_id))
    |> maybe_filter_by_date(Map.get(filters, :since))
  end

  defp maybe_filter_by_status(sessions, nil), do: sessions
  defp maybe_filter_by_status(sessions, status) do
    Enum.filter(sessions, &(&1.status == status))
  end

  defp maybe_filter_by_organization(sessions, nil), do: sessions
  defp maybe_filter_by_organization(sessions, org_id) do
    Enum.filter(sessions, &(&1.organization_id == org_id))
  end

  defp maybe_filter_by_date(sessions, nil), do: sessions
  defp maybe_filter_by_date(sessions, since) do
    Enum.filter(sessions, &(DateTime.compare(&1.created_at, since) != :lt))
  end

  @impl true
  def handle_cast({:mark_successful, session_id, metadata}, state) do
    case Map.get(state.sessions, session_id) do
      nil ->
        {:noreply, state}

      session ->
        hunt_record = %{
          query: session.original_query,
          parsed: session.parsed_query,
          findings_count: length(session.findings),
          hypotheses: session.hypotheses,
          timestamp: DateTime.utc_now(),
          metadata: metadata
        }

        new_hunts = [hunt_record | Enum.take(state.successful_hunts, 99)]
        save_successful_hunt(hunt_record)

        {:noreply, %{state | successful_hunts: new_hunts}}
    end
  end

  @impl true
  def handle_info(:cleanup_sessions, state) do
    now = DateTime.utc_now()
    threshold = DateTime.add(now, -div(@hunt_session_ttl, 1000), :second)

    active_sessions = state.sessions
    |> Enum.filter(fn {_id, session} ->
      DateTime.compare(session.created_at, threshold) == :gt
    end)
    |> Map.new()

    schedule_session_cleanup()
    {:noreply, %{state | sessions: active_sessions}}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Query Parsing
  # ============================================================================

  defp do_parse_query(query, context \\ nil) do
    query_lower = String.downcase(query)

    %{
      original: query,
      entities: extract_entities(query),
      intent: detect_intent(query_lower),
      time_range: extract_time_range(query_lower, context),
      filters: extract_filters(query_lower),
      negations: extract_negations(query_lower),
      context_from_previous: context
    }
  end

  defp extract_entities(query) do
    entity_patterns()
    |> Enum.map(fn {type, pattern} ->
      matches = Regex.scan(pattern, query) |> List.flatten() |> Enum.uniq()
      {type, matches}
    end)
    |> Enum.filter(fn {_type, matches} -> length(matches) > 0 end)
    |> Map.new()
  end

  defp detect_intent(query_lower) do
    intent_patterns()
    |> Enum.find_value(fn {intent, patterns} ->
      if Enum.any?(patterns, &Regex.match?(&1, query_lower)) do
        intent
      end
    end) || :general_hunt
  end

  defp extract_time_range(query_lower, context) do
    case Regex.run(entity_patterns().time_range, query_lower) do
      [_, count, unit] ->
        count = String.to_integer(count)
        unit = String.downcase(unit)

        seconds = case unit do
          u when u in ["hour", "hours"] -> count * 3600
          u when u in ["day", "days"] -> count * 86400
          u when u in ["week", "weeks"] -> count * 604800
          u when u in ["month", "months"] -> count * 2592000
          _ -> 86400
        end

        DateTime.add(DateTime.utc_now(), -seconds, :second)

      nil ->
        # Use context or default to 24 hours
        if context && context[:time_range] do
          context.time_range
        else
          DateTime.add(DateTime.utc_now(), -86400, :second)
        end
    end
  end

  defp extract_filters(query_lower) do
    filters = %{}

    # Host/endpoint filter
    filters = case Regex.run(~r/(?:on|from)\s+(?:host|endpoint|machine)\s+(\S+)/i, query_lower) do
      [_, hostname] -> Map.put(filters, :hostname, hostname)
      nil -> filters
    end

    # User filter
    filters = case Regex.run(~r/(?:by|from)\s+user\s+(\S+)/i, query_lower) do
      [_, username] -> Map.put(filters, :username, username)
      nil -> filters
    end

    # Severity filter
    filters = cond do
      String.contains?(query_lower, "critical") -> Map.put(filters, :severity, "critical")
      String.contains?(query_lower, "high") -> Map.put(filters, :severity, "high")
      true -> filters
    end

    # Port filter
    filters = case Regex.run(entity_patterns().port, query_lower) do
      [_, port] -> Map.put(filters, :port, String.to_integer(port))
      nil -> filters
    end

    filters
  end

  defp extract_negations(query_lower) do
    negations = []

    # "not from", "excluding", "except"
    negations = case Regex.run(~r/(?:not\s+from|excluding|except)\s+(\S+)/i, query_lower) do
      [_, excluded] -> [{:exclude, excluded} | negations]
      nil -> negations
    end

    # "without"
    negations = case Regex.run(~r/without\s+(\S+)/i, query_lower) do
      [_, excluded] -> [{:without, excluded} | negations]
      nil -> negations
    end

    negations
  end

  # ============================================================================
  # Query Execution
  # ============================================================================

  defp execute_hunt_query(parsed, organization_id, _opts \\ []) do
    # Build Ecto query based on parsed intent
    base_query = build_base_query(parsed, organization_id)

    # Apply intent-specific filters
    query = apply_intent_filters(base_query, parsed.intent, parsed)

    # Apply entity filters
    query = apply_entity_filters(query, parsed.entities)

    # Apply explicit filters
    query = apply_explicit_filters(query, parsed.filters)

    # Apply negations
    query = apply_negations(query, parsed.negations)

    # Execute
    results = query
    |> limit(@max_results)
    |> Repo.all()
    |> Enum.map(&format_result/1)

    # Generate Sigma rule from query
    sigma_rule = generate_sigma_from_hunt(parsed)

    {results, sigma_rule}
  end

  defp build_base_query(parsed, organization_id) do
    query = from(e in Event,
      join: a in Agent, on: e.agent_id == a.id,
      where: e.timestamp >= ^parsed.time_range,
      order_by: [desc: e.timestamp],
      select: %{
        id: e.id,
        event_type: e.event_type,
        timestamp: e.timestamp,
        payload: e.payload,
        agent_id: e.agent_id,
        hostname: a.hostname
      }
    )

    if organization_id do
      from [e, a] in query, where: a.organization_id == ^organization_id
    else
      query
    end
  end

  defp apply_intent_filters(query, intent, parsed) do
    case intent do
      :hunt_lateral_movement ->
        from([e, a] in query,
          where: e.event_type in ["process_create", "network_connect"] and
            (fragment("?->>'name' ILIKE ANY(ARRAY['%psexec%', '%wmic%', '%winrm%', '%smbexec%'])", e.payload) or
             fragment("?->>'remote_port' IN ('445', '135', '5985', '5986')", e.payload))
        )

      :hunt_credential_theft ->
        from([e, a] in query,
          where: fragment("?->>'target_process' ILIKE '%lsass%' OR ?->>'name' ILIKE ANY(ARRAY['%mimikatz%', '%procdump%', '%sekurlsa%'])", e.payload, e.payload)
        )

      :hunt_persistence ->
        from([e, a] in query,
          where: e.event_type in ["registry_create", "registry_modify", "process_create"] and
            fragment("?->>'key_path' ILIKE ANY(ARRAY['%\\Run%', '%\\RunOnce%', '%\\Services%', '%Winlogon%']) OR ?->>'name' ILIKE '%schtasks%'", e.payload, e.payload)
        )

      :hunt_exfiltration ->
        from([e, a] in query,
          where: e.event_type == "network_connect" and
            fragment("(?->>'bytes_sent')::bigint > 10000000", e.payload)
        )

      :hunt_command_control ->
        from([e, a] in query,
          where: e.event_type in ["network_connect", "dns_query"] and
            fragment("?->>'remote_port' IN ('443', '8443', '4444', '53') OR ?->>'query_type' = 'TXT'", e.payload, e.payload)
        )

      :hunt_malware ->
        from([e, a] in query,
          where: e.event_type in ["file_create", "process_create"] and
            fragment("?->>'path' SIMILAR TO '%\\.(exe|dll|scr|bat|ps1|vbs)' OR ?->>'entropy' > '7.5'", e.payload, e.payload)
        )

      :hunt_powershell ->
        from([e, a] in query,
          where: e.event_type == "process_create" and
            fragment("?->>'name' ILIKE '%powershell%' OR ?->>'cmdline' ILIKE ANY(ARRAY['%-enc%', '%-encodedcommand%', '%-bypass%'])", e.payload, e.payload)
        )

      :hunt_process_anomaly ->
        from([e, a] in query,
          where: e.event_type in ["process_create", "process_inject"] and
            fragment("?->>'parent_name' IS DISTINCT FROM ?->>'expected_parent'", e.payload, e.payload)
        )

      :investigate_host ->
        hostname = parsed.filters[:hostname] || parsed.entities[:domain] |> List.first()
        if hostname do
          from([e, a] in query, where: a.hostname == ^hostname)
        else
          query
        end

      :investigate_user ->
        username = parsed.filters[:username] || parsed.entities[:username] |> List.first()
        if username do
          from([e, a] in query, where: fragment("?->>'user' ILIKE ?", e.payload, ^"%#{username}%"))
        else
          query
        end

      _ ->
        query
    end
  end

  defp apply_entity_filters(query, entities) do
    query = if ips = Map.get(entities, :ip_address) do
      ip_list = Enum.take(ips, 10)
      from([e, a] in query,
        where: fragment("?->>'remote_ip' = ANY(?)", e.payload, ^ip_list)
      )
    else
      query
    end

    query = if hashes = Map.get(entities, :hash_sha256) do
      hash_list = Enum.take(hashes, 10)
      from([e, a] in query,
        where: fragment("?->>'sha256' = ANY(?)", e.payload, ^hash_list)
      )
    else
      query
    end

    query = if processes = Map.get(entities, :process_name) do
      process_pattern = Enum.map_join(processes, "|", &Regex.escape/1)
      from([e, a] in query,
        where: fragment("?->>'name' ~* ?", e.payload, ^process_pattern)
      )
    else
      query
    end

    query
  end

  defp apply_explicit_filters(query, filters) do
    Enum.reduce(filters, query, fn
      {:hostname, hostname}, q ->
        from([e, a] in q, where: a.hostname == ^hostname)

      {:username, username}, q ->
        from([e, a] in q, where: fragment("?->>'user' ILIKE ?", e.payload, ^"%#{username}%"))

      {:port, port}, q ->
        port_str = to_string(port)
        from([e, a] in q, where: fragment("?->>'remote_port' = ?", e.payload, ^port_str))

      {:severity, _severity}, q ->
        q

      _, q ->
        q
    end)
  end

  defp apply_negations(query, negations) do
    Enum.reduce(negations, query, fn
      {:exclude, value}, q ->
        from([e, a] in q,
          where: not fragment("?::text ILIKE ?", e.payload, ^"%#{value}%")
        )

      {:without, value}, q ->
        from([e, a] in q,
          where: not fragment("?::text ILIKE ?", e.payload, ^"%#{value}%")
        )

      _, q ->
        q
    end)
  end

  defp format_result(result) do
    %{
      id: result.id,
      event_type: result.event_type,
      timestamp: result.timestamp,
      payload: result.payload,
      agent_id: result.agent_id,
      hostname: result.hostname
    }
  end

  # ============================================================================
  # Hypothesis Generation
  # ============================================================================

  defp generate_initial_hypotheses(parsed, results) do
    # Analyze results for patterns
    mitre_techniques = infer_mitre_techniques(parsed.intent, results)

    # Generate hypotheses based on MITRE mapping
    base_hypotheses = Enum.flat_map(mitre_techniques, fn tech ->
      case Map.get(@mitre_hypothesis_map, tech) do
        nil -> []
        mapping ->
          Enum.map(mapping.hypotheses, fn h ->
            %{
              id: generate_hypothesis_id(),
              technique: tech,
              technique_name: mapping.name,
              description: h,
              evidence_queries: mapping.evidence_queries,
              confidence: :medium,
              status: :untested
            }
          end)
      end
    end)

    # Add intent-based hypotheses
    intent_hypotheses = generate_intent_hypotheses(parsed.intent, results)

    (base_hypotheses ++ intent_hypotheses)
    |> Enum.uniq_by(& &1.description)
    |> Enum.take(10)
  end

  defp generate_hypotheses_from_session(session) do
    results = session.initial_results ++ session.findings

    if length(results) > 0 do
      generate_initial_hypotheses(session.parsed_query, results)
    else
      []
    end
  end

  defp infer_mitre_techniques(intent, results) do
    base_techniques = case intent do
      :hunt_lateral_movement -> ["T1021"]
      :hunt_credential_theft -> ["T1003"]
      :hunt_persistence -> ["T1547", "T1053"]
      :hunt_exfiltration -> ["T1041"]
      :hunt_command_control -> ["T1071"]
      :hunt_malware -> ["T1204"]
      :hunt_powershell -> ["T1059.001"]
      :hunt_process_anomaly -> ["T1055"]
      _ -> []
    end

    # Infer additional techniques from results
    result_techniques = results
    |> Enum.flat_map(fn r ->
      payload = r.payload || %{}
      name = payload["name"] || ""
      cmdline = payload["cmdline"] || ""

      cond do
        String.contains?(String.downcase(name), "powershell") -> ["T1059.001"]
        String.contains?(String.downcase(cmdline), "-enc") -> ["T1059.001", "T1027"]
        String.contains?(String.downcase(name), "mimikatz") -> ["T1003.001"]
        String.contains?(String.downcase(name), "psexec") -> ["T1021.002"]
        true -> []
      end
    end)

    (base_techniques ++ result_techniques) |> Enum.uniq()
  end

  defp generate_intent_hypotheses(intent, _results) do
    case intent do
      :hunt_lateral_movement ->
        [%{
          id: generate_hypothesis_id(),
          technique: "T1021",
          technique_name: "Remote Services",
          description: "Attacker moving laterally using remote admin tools",
          evidence_queries: [:remote_execution, :admin_share_access],
          confidence: :medium,
          status: :untested
        }]

      :hunt_credential_theft ->
        [%{
          id: generate_hypothesis_id(),
          technique: "T1003",
          technique_name: "Credential Access",
          description: "Credential harvesting for privilege escalation or persistence",
          evidence_queries: [:lsass_access, :credential_files],
          confidence: :medium,
          status: :untested
        }]

      _ ->
        []
    end
  end

  # ============================================================================
  # Evidence Gathering
  # ============================================================================

  defp gather_evidence_for_hypothesis(hypothesis, session) do
    evidence = %{
      supporting: [],
      contradicting: [],
      inconclusive: []
    }

    Enum.reduce(hypothesis.evidence_queries, evidence, fn query_type, acc ->
      results = execute_evidence_query(query_type, session)

      if length(results) > 0 do
        %{acc | supporting: acc.supporting ++ results}
      else
        acc
      end
    end)
  end

  defp execute_evidence_query(query_type, session) do
    org_id = session.organization_id
    time_range = session.parsed_query.time_range

    base_query = from(e in Event,
      join: a in Agent, on: e.agent_id == a.id,
      where: e.timestamp >= ^time_range,
      limit: @evidence_batch_size
    )

    # Add org filter if org_id is present
    base_query = if org_id do
      from [e, a] in base_query, where: a.organization_id == ^org_id
    else
      base_query
    end

    query = case query_type do
      :powershell_encoded ->
        from [e, a] in base_query,
          where: fragment("?->>'cmdline' ILIKE '%encodedcommand%' OR ?->>'cmdline' ILIKE '%-enc%'", e.payload, e.payload)

      :powershell_download ->
        from [e, a] in base_query,
          where: fragment("?->>'cmdline' ILIKE '%downloadstring%' OR ?->>'cmdline' ILIKE '%invoke-webrequest%'", e.payload, e.payload)

      :lsass_access ->
        from [e, a] in base_query,
          where: fragment("?->>'target_process' ILIKE '%lsass%'", e.payload)

      :remote_execution ->
        from [e, a] in base_query,
          where: fragment("?->>'name' ILIKE ANY(ARRAY['%psexec%', '%wmic%', '%winrm%'])", e.payload)

      :shadow_delete ->
        from [e, a] in base_query,
          where: fragment("?->>'cmdline' ILIKE '%vssadmin%delete%shadows%'", e.payload)

      _ ->
        nil
    end

    if query do
      Repo.all(query) |> Enum.map(&Map.from_struct/1)
    else
      []
    end
  end

  # ============================================================================
  # Playbook Generation
  # ============================================================================

  defp build_hunt_playbook(session) do
    %{
      id: session.id,
      title: generate_playbook_title(session),
      created_at: DateTime.utc_now(),
      original_query: session.original_query,
      summary: generate_playbook_summary(session),
      timeline: session.timeline,
      findings: %{
        total_events: length(session.initial_results) + length(session.findings),
        key_findings: extract_key_findings(session)
      },
      hypotheses: session.hypotheses,
      evidence: session.evidence,
      sigma_rule: session.generated_sigma_rule,
      recommendations: generate_recommendations(session),
      mitre_mapping: build_mitre_mapping(session),
      next_steps: suggest_next_steps(session),
      exportable_iocs: extract_iocs_from_session(session)
    }
  end

  defp generate_playbook_title(session) do
    intent = session.parsed_query.intent
    title_map = %{
      hunt_lateral_movement: "Lateral Movement Hunt",
      hunt_credential_theft: "Credential Theft Investigation",
      hunt_persistence: "Persistence Mechanism Hunt",
      hunt_exfiltration: "Data Exfiltration Hunt",
      hunt_command_control: "C2 Communication Hunt",
      hunt_malware: "Malware Hunt",
      hunt_powershell: "PowerShell Abuse Hunt",
      hunt_process_anomaly: "Process Anomaly Hunt"
    }

    Map.get(title_map, intent, "Threat Hunt")
  end

  defp generate_playbook_summary(session) do
    result_count = length(session.initial_results) + length(session.findings)
    hypothesis_count = length(session.hypotheses)
    evidence_count = map_size(session.evidence)

    "Hunt initiated with query: '#{session.original_query}'. " <>
    "Found #{result_count} relevant events. " <>
    "Generated #{hypothesis_count} hypotheses. " <>
    "Gathered evidence for #{evidence_count} hypotheses."
  end

  defp extract_key_findings(session) do
    all_results = session.initial_results ++ session.findings

    # Group by event type and get top findings
    all_results
    |> Enum.group_by(& &1.event_type)
    |> Enum.map(fn {type, events} ->
      %{
        event_type: type,
        count: length(events),
        sample: Enum.take(events, 3)
      }
    end)
    |> Enum.sort_by(& &1.count, :desc)
    |> Enum.take(5)
  end

  defp generate_recommendations(session) do
    base_recommendations = [
      "Review all flagged events for false positives",
      "Correlate findings with threat intelligence feeds"
    ]

    intent_recommendations = case session.parsed_query.intent do
      :hunt_lateral_movement ->
        ["Isolate affected hosts", "Reset compromised credentials", "Review network segmentation"]

      :hunt_credential_theft ->
        ["Force password reset for affected users", "Review privileged access", "Enable MFA"]

      :hunt_persistence ->
        ["Remove identified persistence mechanisms", "Scan for additional backdoors"]

      :hunt_exfiltration ->
        ["Identify scope of data exposure", "Preserve evidence for forensics"]

      _ ->
        []
    end

    base_recommendations ++ intent_recommendations
  end

  defp build_mitre_mapping(session) do
    techniques = session.hypotheses
    |> Enum.map(& &1.technique)
    |> Enum.uniq()

    %{
      techniques: techniques,
      tactics: infer_tactics_from_techniques(techniques)
    }
  end

  defp infer_tactics_from_techniques(techniques) do
    technique_to_tactics = %{
      "T1059.001" => ["execution"],
      "T1003" => ["credential-access"],
      "T1021" => ["lateral-movement"],
      "T1547" => ["persistence"],
      "T1053" => ["persistence", "execution"],
      "T1041" => ["exfiltration"],
      "T1071" => ["command-and-control"]
    }

    techniques
    |> Enum.flat_map(&Map.get(technique_to_tactics, &1, []))
    |> Enum.uniq()
  end

  defp suggest_next_steps(_session) do
    [
      "Export Sigma rule for automated detection",
      "Create alert for similar activity",
      "Schedule periodic re-hunt"
    ]
  end

  defp extract_iocs_from_session(session) do
    all_results = session.initial_results ++ session.findings

    %{
      ip_addresses: all_results
        |> Enum.map(& &1.payload["remote_ip"])
        |> Enum.filter(& &1)
        |> Enum.uniq(),
      file_hashes: all_results
        |> Enum.map(& &1.payload["sha256"])
        |> Enum.filter(& &1)
        |> Enum.uniq(),
      domains: all_results
        |> Enum.map(& &1.payload["query_name"])
        |> Enum.filter(& &1)
        |> Enum.uniq()
    }
  end

  # ============================================================================
  # Sigma Rule Generation
  # ============================================================================

  defp generate_sigma_from_hunt(parsed) do
    detection = build_sigma_detection(parsed)

    %{
      title: "Hunt: #{parsed.intent |> to_string() |> String.replace("_", " ") |> String.capitalize()}",
      id: UUID.uuid4(),
      status: "experimental",
      description: "Auto-generated from hunt query: #{parsed.original}",
      logsource: infer_logsource(parsed),
      detection: detection,
      level: "medium",
      tags: infer_sigma_tags(parsed)
    }
  end

  defp build_sigma_detection(parsed) do
    selection = case parsed.intent do
      :hunt_powershell ->
        %{
          "selection" => %{
            "Image|endswith" => ["\\powershell.exe", "\\pwsh.exe"],
            "CommandLine|contains" => ["-enc", "-encodedcommand", "-bypass"]
          },
          "condition" => "selection"
        }

      :hunt_lateral_movement ->
        %{
          "selection" => %{
            "Image|endswith" => ["\\psexec.exe", "\\wmic.exe", "\\winrs.exe"]
          },
          "condition" => "selection"
        }

      :hunt_credential_theft ->
        %{
          "selection" => %{
            "TargetImage|endswith" => "\\lsass.exe"
          },
          "condition" => "selection"
        }

      _ ->
        %{
          "selection" => %{},
          "condition" => "selection"
        }
    end

    selection
  end

  defp infer_logsource(parsed) do
    case parsed.intent do
      i when i in [:hunt_powershell, :hunt_process_anomaly, :hunt_lateral_movement] ->
        %{"category" => "process_creation", "product" => "windows"}

      :hunt_credential_theft ->
        %{"category" => "process_access", "product" => "windows"}

      :hunt_exfiltration ->
        %{"category" => "network_connection", "product" => "windows"}

      _ ->
        %{"product" => "windows"}
    end
  end

  defp infer_sigma_tags(parsed) do
    base_tags = ["attack.t1059"]

    intent_tags = case parsed.intent do
      :hunt_lateral_movement -> ["attack.lateral-movement", "attack.t1021"]
      :hunt_credential_theft -> ["attack.credential-access", "attack.t1003"]
      :hunt_persistence -> ["attack.persistence", "attack.t1547"]
      :hunt_exfiltration -> ["attack.exfiltration", "attack.t1041"]
      :hunt_command_control -> ["attack.command-and-control", "attack.t1071"]
      :hunt_powershell -> ["attack.execution", "attack.t1059.001"]
      _ -> []
    end

    Enum.uniq(base_tags ++ intent_tags)
  end

  # ============================================================================
  # Suggestions & Learning
  # ============================================================================

  defp suggest_refinements(parsed, results) do
    suggestions = []

    # Suggest time range adjustment
    suggestions = if length(results) > 500 do
      suggestions ++ ["Narrow time range to reduce results"]
    else
      suggestions
    end

    suggestions = if length(results) == 0 do
      suggestions ++ ["Expand time range", "Remove restrictive filters"]
    else
      suggestions
    end

    # Suggest entity-based refinements
    suggestions = if Enum.empty?(parsed.entities) do
      suggestions ++ ["Add specific IPs, hashes, or hostnames to focus hunt"]
    else
      suggestions
    end

    suggestions
  end

  defp generate_suggestions(successful_hunts, opts) do
    organization_id = get_opt(opts, :organization_id)

    # Get suggestions from successful hunts
    hunt_suggestions = successful_hunts
    |> Enum.filter(fn h ->
      is_nil(organization_id) || Map.get(h.metadata, :organization_id) == organization_id
    end)
    |> Enum.take(5)
    |> Enum.map(fn h ->
      %{
        query: h.query,
        reason: "Previously successful hunt with #{h.findings_count} findings",
        priority: :medium
      }
    end)

    # Add default suggestions
    default_suggestions = [
      %{query: "Find encoded PowerShell commands in last 24 hours", reason: "Common attack vector", priority: :high},
      %{query: "Hunt for lateral movement using PSExec or WMI", reason: "Lateral movement detection", priority: :high},
      %{query: "Show processes accessing LSASS memory", reason: "Credential theft detection", priority: :critical}
    ]

    (hunt_suggestions ++ default_suggestions) |> Enum.take(10)
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  defp generate_session_id do
    "hunt_" <> UUID.uuid4()
  end

  defp generate_hypothesis_id do
    "hyp_" <> :crypto.strong_rand_bytes(8) |> Base.url_encode64(padding: false)
  end

  defp add_timeline_entry(session, action, data) do
    entry = %{
      timestamp: DateTime.utc_now(),
      action: action,
      data: data
    }

    Map.update!(session, :timeline, &(&1 ++ [entry]))
  end

  defp schedule_session_cleanup do
    Process.send_after(self(), :cleanup_sessions, :timer.hours(1))
  end

  defp load_successful_hunts do
    # Load from persistent storage (simplified - in production would use DB)
    []
  end

  defp save_successful_hunt(_hunt_record) do
    # Save to persistent storage (simplified - in production would use DB)
    :ok
  end

  # Helper to get options from either a map or keyword list
  defp get_opt(opts, key) when is_map(opts), do: Map.get(opts, key)
  defp get_opt(opts, key) when is_list(opts), do: Keyword.get(opts, key)
  defp get_opt(_, _), do: nil

  # ============================================================================
  # LLM-Powered Query Translation
  # ============================================================================

  @doc """
  Translate a natural language query to TQL using LLM (GPT/Claude).

  Falls back to pattern matching if LLM is unavailable or fails.

  ## Parameters

  - `query` - Natural language query string

  ## Returns

  - `{:ok, tql_query}` - Successfully translated TQL query
  - `{:error, reason}` - Translation failed, caller should use pattern matching

  ## Example

      iex> translate_with_llm("Find encoded PowerShell commands")
      {:ok, "process.name:powershell.exe AND process.cmdline:*-enc*"}
  """
  @spec translate_with_llm(String.t()) :: {:ok, String.t()} | {:error, term()}
  def translate_with_llm(query) when is_binary(query) do
    # Check if LLM is enabled and available
    if llm_enabled?() do
      do_translate_with_llm(query)
    else
      Logger.debug("[NLHunter] LLM translation disabled or unavailable, using pattern matching")
      {:error, :llm_disabled}
    end
  end

  defp do_translate_with_llm(query) do
    start_time = System.monotonic_time(:millisecond)

    # Build the system prompt with TQL schema
    system_prompt = """
    You are a TQL (Tamandua Query Language) translator for an EDR system.
    Translate natural language queries into valid TQL queries.

    #{@tql_schema_context}

    RULES:
    1. Return ONLY the TQL query, no explanations or markdown
    2. Use proper field:value syntax
    3. Use wildcards (*) for partial matches
    4. Use ~ for regex patterns
    5. Combine with AND, OR, NOT as needed
    6. Keep queries concise and focused
    """

    user_prompt = """
    Translate this natural language query to TQL:

    "#{query}"

    Return ONLY the TQL query.
    """

    messages = [
      %{role: "system", content: system_prompt},
      %{role: "user", content: user_prompt}
    ]

    result = try do
      LLMClient.chat_completion(messages,
        temperature: 0.1,
        max_tokens: 500,
        timeout: @llm_timeout,
        agent_id: "nl_hunter"
      )
    rescue
      e ->
        Logger.warning("[NLHunter] LLM call failed with exception: #{inspect(e)}")
        {:error, :llm_exception}
    end

    latency_ms = System.monotonic_time(:millisecond) - start_time

    case result do
      {:ok, %{content: content, tokens_in: tokens_in, tokens_out: tokens_out}} ->
        # Clean up the response - remove markdown formatting if present
        tql = content
        |> String.trim()
        |> String.replace(~r/^```\w*\n?/, "")
        |> String.replace(~r/\n?```$/, "")
        |> String.trim()

        # Emit telemetry for cost tracking
        emit_llm_telemetry(:success, latency_ms, tokens_in, tokens_out)

        Logger.info("[NLHunter] LLM translated query in #{latency_ms}ms: \"#{String.slice(query, 0, 50)}...\" -> \"#{String.slice(tql, 0, 100)}\"")

        {:ok, tql}

      {:error, :api_key_not_configured} ->
        emit_llm_telemetry(:disabled, latency_ms, 0, 0)
        {:error, :llm_not_configured}

      {:error, :rate_limited} ->
        emit_llm_telemetry(:rate_limited, latency_ms, 0, 0)
        Logger.warning("[NLHunter] LLM rate limited, falling back to pattern matching")
        {:error, :rate_limited}

      {:error, :timeout} ->
        emit_llm_telemetry(:timeout, latency_ms, 0, 0)
        Logger.warning("[NLHunter] LLM request timed out after #{@llm_timeout}ms")
        {:error, :timeout}

      {:error, reason} ->
        emit_llm_telemetry(:error, latency_ms, 0, 0)
        Logger.warning("[NLHunter] LLM translation failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp emit_llm_telemetry(status, latency_ms, tokens_in, tokens_out) do
    :telemetry.execute(
      [:tamandua, :hunting, :llm_translation],
      %{
        latency_ms: latency_ms,
        tokens_in: tokens_in,
        tokens_out: tokens_out
      },
      %{
        status: status,
        component: :nl_hunter
      }
    )
  end

  @doc """
  Check if LLM translation is enabled.

  LLM is enabled if:
  1. Not explicitly disabled via config
  2. An API key is configured (OPENAI_API_KEY or ANTHROPIC_API_KEY)
  """
  @spec llm_enabled?() :: boolean()
  def llm_enabled? do
    # Check if explicitly disabled
    config = Application.get_env(:tamandua_server, __MODULE__, [])
    explicitly_disabled = Keyword.get(config, :llm_enabled, true) == false

    if explicitly_disabled do
      false
    else
      # Check if LLM client is available (has API key)
      case LLMClient.health_check() do
        {:ok, _provider} -> true
        {:error, _} -> false
      end
    end
  end

  @doc """
  Translate a natural language query to TQL with LLM fallback to pattern matching.

  This is the primary function to use for query translation. It will:
  1. Try LLM translation first (if enabled)
  2. Fall back to pattern-based translation if LLM fails
  3. Return the best available translation

  ## Parameters

  - `query` - Natural language query string
  - `opts` - Optional keyword list:
    - `:force_llm` - Skip pattern matching fallback (default: false)
    - `:force_pattern` - Skip LLM, use only patterns (default: false)

  ## Returns

  - `{:ok, %{tql: query, source: :llm | :pattern}}` - Translation result with source
  - `{:error, reason}` - Translation failed completely
  """
  @spec translate_query(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def translate_query(query, opts \\ []) when is_binary(query) do
    force_llm = Keyword.get(opts, :force_llm, false)
    force_pattern = Keyword.get(opts, :force_pattern, false)

    cond do
      force_pattern ->
        # Use pattern matching only
        tql = translate_with_patterns(query)
        {:ok, %{tql: tql, source: :pattern, query: query}}

      force_llm ->
        # Use LLM only, no fallback
        case translate_with_llm(query) do
          {:ok, tql} -> {:ok, %{tql: tql, source: :llm, query: query}}
          {:error, reason} -> {:error, reason}
        end

      true ->
        # Try LLM first, fall back to patterns
        case translate_with_llm(query) do
          {:ok, tql} ->
            {:ok, %{tql: tql, source: :llm, query: query}}

          {:error, _reason} ->
            tql = translate_with_patterns(query)
            {:ok, %{tql: tql, source: :pattern, query: query}}
        end
    end
  end

  # Pattern-based translation (existing logic)
  defp translate_with_patterns(query) do
    query_lower = String.downcase(query)

    # Build TQL from detected patterns
    conditions = []

    # PowerShell patterns
    conditions = if Regex.match?(~r/powershell|pwsh/i, query_lower) do
      cond do
        String.contains?(query_lower, "encoded") or String.contains?(query_lower, "-enc") ->
          conditions ++ ["process.name:powershell.exe AND process.cmdline:*-enc*"]
        String.contains?(query_lower, "download") ->
          conditions ++ ["process.name:powershell.exe AND (process.cmdline:*DownloadString* OR process.cmdline:*Invoke-WebRequest*)"]
        String.contains?(query_lower, "bypass") ->
          conditions ++ ["process.name:powershell.exe AND process.cmdline:*-bypass*"]
        true ->
          conditions ++ ["process.name:powershell.exe"]
      end
    else
      conditions
    end

    # Lateral movement patterns
    conditions = if Regex.match?(~r/lateral|psexec|wmi|smb|winrm/i, query_lower) do
      conditions ++ ["(process.name:psexec.exe OR process.name:wmic.exe OR network.remote_port:445 OR network.remote_port:5985)"]
    else
      conditions
    end

    # Credential theft patterns
    conditions = if Regex.match?(~r/credential|mimikatz|lsass|password|dump/i, query_lower) do
      conditions ++ ["(process.name:*mimikatz* OR file.path:*lsass* OR process.cmdline:*sekurlsa*)"]
    else
      conditions
    end

    # Persistence patterns
    conditions = if Regex.match?(~r/persist|registry.*run|scheduled.*task|startup/i, query_lower) do
      conditions ++ ["(registry.path:*\\\\Run* OR process.name:schtasks.exe)"]
    else
      conditions
    end

    # Data exfiltration patterns
    conditions = if Regex.match?(~r/exfil|large.*transfer|data.*theft/i, query_lower) do
      conditions ++ ["network.bytes_sent:>10000000"]
    else
      conditions
    end

    # C2 patterns
    conditions = if Regex.match?(~r/c2|c&c|command.*control|beacon/i, query_lower) do
      conditions ++ ["(network.remote_port:443 OR network.remote_port:4444 OR network.remote_port:8080)"]
    else
      conditions
    end

    # DNS patterns
    conditions = if Regex.match?(~r/dns|suspicious.*domain/i, query_lower) do
      conditions ++ ["dns.query:~.*\\.(xyz|top|tk|ml)$"]
    else
      conditions
    end

    # Process anomaly patterns
    conditions = if Regex.match?(~r/process.*inject|hollow|unusual.*parent/i, query_lower) do
      conditions ++ ["process.is_elevated:true AND process.cmdline:*inject*"]
    else
      conditions
    end

    # Extract specific entities
    conditions = extract_entity_conditions(query, conditions)

    # Join all conditions
    if Enum.empty?(conditions) do
      # Default: generic process query
      "event.type:process_create"
    else
      Enum.join(conditions, " AND ")
    end
  end

  defp extract_entity_conditions(query, conditions) do
    # Extract IP addresses
    ips = Regex.scan(entity_patterns().ip_address, query) |> List.flatten()
    conditions = if length(ips) > 0 do
      ip_condition = Enum.map_join(ips, " OR ", fn ip -> "network.remote_ip:#{ip}" end)
      conditions ++ ["(#{ip_condition})"]
    else
      conditions
    end

    # Extract file hashes
    hashes = Regex.scan(entity_patterns().hash_sha256, query) |> List.flatten()
    conditions = if length(hashes) > 0 do
      hash_condition = Enum.map_join(hashes, " OR ", fn h -> "process.sha256:#{h}" end)
      conditions ++ ["(#{hash_condition})"]
    else
      conditions
    end

    # Extract process names
    procs = Regex.scan(entity_patterns().process_name, query) |> List.flatten()
    conditions = if length(procs) > 0 do
      proc_condition = Enum.map_join(procs, " OR ", fn p -> "process.name:#{p}" end)
      conditions ++ ["(#{proc_condition})"]
    else
      conditions
    end

    # Extract ports
    ports = Regex.scan(entity_patterns().port, query) |> Enum.map(fn [_, port] -> port end)
    conditions = if length(ports) > 0 do
      port_condition = Enum.map_join(ports, " OR ", fn p -> "network.remote_port:#{p}" end)
      conditions ++ ["(#{port_condition})"]
    else
      conditions
    end

    conditions
  end

  # ============================================================================
  # Public API Wrapper Functions
  # ============================================================================

  @doc """
  Execute a natural language query and return results.
  """
  def execute_query(session_id, query_text) when is_binary(query_text) do
    GenServer.call(__MODULE__, {:execute_query, session_id, query_text}, 60_000)
  end

  @doc """
  Get a hunt session by ID.
  """
  def get_session(session_id) do
    GenServer.call(__MODULE__, {:get_session, session_id})
  end

  @doc """
  List all hunt sessions with optional filters.
  """
  def list_sessions(filters \\ %{}) do
    GenServer.call(__MODULE__, {:list_sessions, filters})
  end

  @doc """
  Get query suggestions based on current context.
  """
  def query_suggestions(context \\ %{}) do
    GenServer.call(__MODULE__, {:query_suggestions, context})
  end
end
