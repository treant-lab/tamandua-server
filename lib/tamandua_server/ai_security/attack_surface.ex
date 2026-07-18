defmodule TamanduaServer.AISecurity.AttackSurface do
  @moduledoc """
  AI Attack Surface Protection Module.

  Implements comprehensive AI/LLM security monitoring similar to CrowdStrike Falcon AIDR:

  - Monitor AI/LLM API usage across the organization
  - Detect prompt injection attacks
  - Monitor AI agent interactions
  - Track data flows to/from AI models
  - Identify shadow AI usage (unauthorized AI services)
  - Risk scoring for AI usage patterns

  This module provides real-time monitoring through a GenServer that tracks
  AI-related network traffic, API calls, and agent interactions, applying
  detection rules to identify potential attacks or misuse.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Alerts

  # Known AI API endpoints for monitoring
  @known_ai_endpoints %{
    openai: [
      "api.openai.com",
      "chat.openai.com",
      "chatgpt.com",
      "platform.openai.com"
    ],
    anthropic: [
      "api.anthropic.com",
      "claude.ai"
    ],
    google: [
      "generativelanguage.googleapis.com",
      "ai.google.dev",
      "bard.google.com",
      "gemini.google.com"
    ],
    microsoft: [
      "api.cognitive.microsoft.com",
      "openai.azure.com",
      "copilot.microsoft.com"
    ],
    meta: [
      "llama-api.meta.com",
      "ai.meta.com"
    ],
    cohere: [
      "api.cohere.ai",
      "cohere.com"
    ],
    huggingface: [
      "api-inference.huggingface.co",
      "huggingface.co"
    ],
    replicate: [
      "api.replicate.com",
      "replicate.com"
    ],
    mistral: [
      "api.mistral.ai"
    ],
    groq: [
      "api.groq.com",
      "console.groq.com"
    ],
    openrouter: [
      "openrouter.ai",
      "api.openrouter.ai"
    ],
    perplexity: [
      "api.perplexity.ai"
    ]
  }

  # Shadow AI indicators - unauthorized or potentially risky AI services
  @shadow_ai_indicators [
    # Ollama local
    "localhost:11434",
    "127.0.0.1:11434",
    # Text generation WebUI
    "oobabooga",
    "text-generation-webui",
    "koboldai",
    "localai",
    "gpt4all",
    "privateGPT",
    "llamacpp"
  ]

  # Prompt injection detection patterns
  defp prompt_injection_patterns do
    [
      # Direct injection attempts
      %{
        name: "ignore_previous_instructions",
        pattern:
          ~r/ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)/i,
        severity: :high,
        description: "Attempt to override system instructions"
      },
      %{
        name: "new_instructions",
        pattern: ~r/(forget|disregard|override)\s+.*(instructions|rules|guidelines)/i,
        severity: :high,
        description: "Attempt to replace existing instructions"
      },
      %{
        name: "system_prompt_extraction",
        pattern:
          ~r/(show|reveal|display|print|output|repeat)\s+.*(system\s+prompt|initial\s+instructions|hidden\s+instructions)/i,
        severity: :critical,
        description: "Attempt to extract system prompts"
      },
      %{
        name: "role_hijacking",
        pattern:
          ~r/(you\s+are\s+now|pretend\s+to\s+be|act\s+as|roleplay\s+as)\s+(a\s+)?(hacker|attacker|malicious|evil|unrestricted)/i,
        severity: :critical,
        description: "Attempt to hijack AI role/persona"
      },
      %{
        name: "jailbreak_dan",
        pattern: ~r/(DAN|do\s+anything\s+now|jailbreak|developer\s+mode)/i,
        severity: :critical,
        description: "Known jailbreak attempt (DAN-style)"
      },
      %{
        name: "base64_injection",
        pattern: ~r/base64[:\s]+(decode|encode|execute|eval)/i,
        severity: :high,
        description: "Potential encoded payload injection"
      },
      %{
        name: "code_execution",
        pattern: ~r/(execute|run|eval)\s+(this\s+)?(code|script|command|python|javascript)/i,
        severity: :high,
        description: "Code execution request through prompt"
      },
      %{
        name: "delimiter_escape",
        pattern: ~r/(```|<\|im_sep\|>|<\|endoftext\|>|\[INST\]|\[\/INST\]|<s>|<\/s>)/,
        severity: :medium,
        description: "Attempt to use model-specific delimiters"
      },
      %{
        name: "prompt_leaking",
        pattern:
          ~r/(what\s+is\s+your|tell\s+me\s+your|reveal\s+your)\s+(system\s+)?(prompt|instructions|guidelines)/i,
        severity: :medium,
        description: "Attempt to leak prompt information"
      },
      %{
        name: "indirect_injection",
        pattern:
          ~r/(when\s+you\s+see|if\s+you\s+read|upon\s+receiving)\s+this\s+(text|message|prompt)/i,
        severity: :medium,
        description: "Indirect prompt injection setup"
      },
      %{
        name: "context_manipulation",
        pattern: ~r/(new\s+conversation|start\s+over|reset\s+context|clear\s+history)/i,
        severity: :low,
        description: "Context manipulation attempt"
      },
      %{
        name: "translation_injection",
        pattern: ~r/translate\s+(the\s+following|this)\s+.{0,50}ignore/i,
        severity: :medium,
        description: "Injection hidden in translation request"
      },
      %{
        name: "unicode_obfuscation",
        pattern: ~r/[\x{200B}-\x{200D}\x{FEFF}\x{2060}]/u,
        severity: :high,
        description: "Unicode zero-width character obfuscation"
      }
    ]
  end

  # Data exfiltration patterns
  defp data_exfiltration_patterns do
    [
      %{
        name: "pii_extraction",
        pattern:
          ~r/(extract|list|show|give\s+me)\s+(all\s+)?(emails|phone\s+numbers|ssn|credit\s+cards?|passwords|api\s+keys?)/i,
        severity: :critical,
        description: "Attempt to extract PII via AI"
      },
      %{
        name: "database_query",
        pattern: ~r/(query|dump|export)\s+(the\s+)?(database|table|records|users)/i,
        severity: :critical,
        description: "Database exfiltration via AI"
      },
      %{
        name: "credential_extraction",
        pattern: ~r/(show|list|reveal)\s+(all\s+)?(credentials|secrets|tokens|keys)/i,
        severity: :critical,
        description: "Credential extraction attempt"
      },
      %{
        name: "file_access",
        pattern: ~r/(read|access|open|cat|type)\s+(the\s+)?(file|document|config|\.env)/i,
        severity: :high,
        description: "File access via AI"
      },
      %{
        name: "network_recon",
        pattern: ~r/(scan|enumerate|list)\s+(all\s+)?(hosts|ips|servers|ports|network)/i,
        severity: :high,
        description: "Network reconnaissance via AI"
      }
    ]
  end

  # Risk scoring weights
  @risk_weights %{
    shadow_ai_usage: 30,
    high_volume_api_calls: 20,
    prompt_injection_attempt: 40,
    data_exfiltration_attempt: 50,
    unusual_hours_access: 15,
    new_ai_service: 25,
    large_data_transfer: 35,
    unauthorized_model: 30
  }

  # State structure
  defstruct [
    # ETS table for usage tracking
    :ai_usage_log,
    # Recent injection attempts
    :injection_cache,
    # AI agent interaction log
    :agent_interactions,
    # Data flow monitoring
    :data_flow_tracker,
    # Shadow AI usage
    :shadow_ai_detections,
    # Per-agent/user risk scores
    :risk_scores,
    # Configuration
    :config,
    # Statistics
    :stats
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Analyze an outbound network request for AI API usage.
  Called from telemetry pipeline when network events are detected.
  """
  @spec analyze_network_event(map()) :: {:ok, map()} | {:error, term()}
  def analyze_network_event(event) do
    GenServer.call(__MODULE__, {:analyze_network, event})
  end

  @doc """
  Analyze a text prompt for injection attacks.
  Can be called directly for webhook integrations or internal AI services.
  """
  @spec analyze_prompt(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def analyze_prompt(prompt, context \\ %{}) do
    GenServer.call(__MODULE__, {:analyze_prompt, prompt, context})
  end

  @doc """
  Log an AI agent interaction for monitoring.
  """
  @spec log_agent_interaction(map()) :: :ok
  def log_agent_interaction(interaction) do
    GenServer.cast(__MODULE__, {:log_interaction, interaction})
  end

  @doc """
  Track data flow to/from AI models.
  """
  @spec track_data_flow(map()) :: :ok
  def track_data_flow(flow_event) do
    GenServer.cast(__MODULE__, {:track_flow, flow_event})
  end

  @doc """
  Report a potential shadow AI detection.
  """
  @spec report_shadow_ai(map()) :: :ok
  def report_shadow_ai(detection) do
    GenServer.cast(__MODULE__, {:shadow_ai, detection})
  end

  @doc """
  Get the current risk score for an agent or user.
  """
  @spec get_risk_score(String.t()) :: {:ok, float()} | {:error, :not_found}
  def get_risk_score(entity_id) do
    GenServer.call(__MODULE__, {:get_risk_score, entity_id})
  end

  @doc """
  Get AI usage statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Get recent AI security events.
  """
  @spec get_recent_events(keyword()) :: [map()]
  def get_recent_events(opts \\ []) do
    GenServer.call(__MODULE__, {:get_recent_events, opts})
  end

  @doc """
  Get shadow AI detections.
  """
  @spec get_shadow_ai_detections(keyword()) :: [map()]
  def get_shadow_ai_detections(opts \\ []) do
    GenServer.call(__MODULE__, {:get_shadow_ai, opts})
  end

  @doc """
  Get shadow AI inventory for an entity.
  Wrapper for get_shadow_ai_detections/0 for controller compatibility.
  """
  @spec shadow_ai_inventory(String.t() | nil) :: {:ok, [map()]}
  def shadow_ai_inventory(_entity_id \\ nil) do
    {:ok, get_shadow_ai_detections()}
  end

  @doc """
  Get risk assessment for an entity.
  Wrapper for get_risk_score/1 for controller compatibility.
  """
  @spec risk_assessment(String.t()) :: {:ok, map()} | {:error, term()}
  def risk_assessment(entity_id) do
    entity_id = risk_assessment_entity_id(entity_id)

    case get_risk_score(entity_id) do
      {:ok, score} ->
        {:ok,
         %{
           entity_id: entity_id,
           risk_score: score,
           assessed_at: DateTime.utc_now()
         }}

      {:error, :not_found} ->
        {:ok,
         %{
           entity_id: entity_id,
           risk_score: %{score: 0.0, factors: []},
           assessed_at: DateTime.utc_now()
         }}
    end
  end

  @doc """
  Register an authorized AI service for the organization.
  """
  @spec register_authorized_ai(String.t(), map()) :: :ok
  def register_authorized_ai(service_name, config) do
    GenServer.cast(__MODULE__, {:register_ai, service_name, config})
  end

  @doc """
  Block a specific AI service.
  """
  @spec block_ai_service(String.t()) :: :ok
  def block_ai_service(service_identifier) do
    GenServer.cast(__MODULE__, {:block_ai, service_identifier})
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    Logger.info("AI Attack Surface Protection module starting...")

    # Create ETS tables for high-performance tracking
    ai_usage_table = :ets.new(:ai_usage_log, [:named_table, :ordered_set, :public])

    state = %__MODULE__{
      ai_usage_log: ai_usage_table,
      injection_cache: %{},
      agent_interactions: [],
      data_flow_tracker: %{},
      shadow_ai_detections: [],
      risk_scores: %{},
      config: build_config(opts),
      stats: initial_stats()
    }

    # Schedule periodic cleanup
    schedule_cleanup()
    # Schedule risk score recalculation
    schedule_risk_recalculation()

    Logger.info(
      "AI Attack Surface Protection initialized with #{length(prompt_injection_patterns())} injection patterns"
    )

    {:ok, state}
  end

  @impl true
  def handle_call({:analyze_network, event}, _from, state) do
    {result, new_state} = do_analyze_network(event, state)
    {:reply, {:ok, result}, new_state}
  end

  @impl true
  def handle_call({:analyze_prompt, prompt, context}, _from, state) do
    {result, new_state} = do_analyze_prompt(prompt, context, state)
    {:reply, {:ok, result}, new_state}
  end

  @impl true
  def handle_call({:get_risk_score, entity_id}, _from, state) do
    case Map.get(state.risk_scores, entity_id) do
      nil -> {:reply, {:error, :not_found}, state}
      score -> {:reply, {:ok, score}, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_call({:analyze, opts}, _from, state) do
    opts = normalize_opts(opts)

    # Comprehensive attack surface analysis
    entity_id = Map.get(opts, :entity_id)
    include_shadow_ai = Map.get(opts, :include_shadow_ai, true)
    include_data_flows = Map.get(opts, :include_data_flows, true)

    analysis = %{
      timestamp: DateTime.utc_now(),
      entity_id: entity_id,
      overall_risk_score: calculate_overall_surface_risk(state),
      injection_threats: %{
        recent_detections: map_size(state.injection_cache || %{}),
        patterns_monitored: length(prompt_injection_patterns()),
        blocked_attempts: state.stats[:prompts_blocked] || 0
      },
      agent_activity: %{
        total_interactions: length(state.agent_interactions),
        unique_agents:
          state.agent_interactions |> Enum.map(& &1[:agent_id]) |> Enum.uniq() |> length()
      },
      shadow_ai:
        if(include_shadow_ai,
          do: %{
            detections: length(state.shadow_ai_detections),
            services: state.shadow_ai_detections |> Enum.map(& &1[:service]) |> Enum.uniq()
          },
          else: nil
        ),
      data_flows:
        if(include_data_flows,
          do: %{
            tracked_flows: map_size(state.data_flow_tracker),
            high_risk_flows: count_high_risk_flows(state.data_flow_tracker)
          },
          else: nil
        ),
      stats: state.stats,
      recommendations: generate_surface_recommendations(state)
    }

    {:reply, {:ok, analysis}, state}
  end

  @impl true
  def handle_call({:scan_prompt, prompt, opts}, _from, state) do
    opts = normalize_opts(opts)

    # Scan a prompt for injection attacks and return detailed analysis
    context = Map.get(opts, :context, %{})
    {result, new_state} = do_analyze_prompt(prompt, context, state)

    detailed_result =
      Map.merge(result, %{
        prompt_length: String.length(prompt),
        scan_timestamp: DateTime.utc_now(),
        context_provided: context != %{},
        cached: Map.has_key?(state.injection_cache, :crypto.hash(:sha256, prompt))
      })

    {:reply, {:ok, detailed_result}, new_state}
  end

  @impl true
  def handle_call({:get_recent_events, opts}, _from, state) do
    limit = Keyword.get(opts, :limit, 100)

    events =
      :ets.tab2list(state.ai_usage_log)
      |> Enum.sort_by(fn {ts, _} -> ts end, :desc)
      |> Enum.take(limit)
      |> Enum.map(fn {_ts, event} -> event end)

    {:reply, events, state}
  end

  @impl true
  def handle_call({:get_shadow_ai, opts}, _from, state) do
    limit = Keyword.get(opts, :limit, 50)
    detections = Enum.take(state.shadow_ai_detections, limit)
    {:reply, detections, state}
  end

  @impl true
  def handle_cast({:log_interaction, interaction}, state) do
    new_state = record_agent_interaction(interaction, state)
    {:noreply, new_state}
  end

  @impl true
  def handle_cast({:track_flow, flow_event}, state) do
    new_state = track_data_flow_event(flow_event, state)
    {:noreply, new_state}
  end

  @impl true
  def handle_cast({:shadow_ai, detection}, state) do
    new_state = handle_shadow_ai_detection(detection, state)
    {:noreply, new_state}
  end

  @impl true
  def handle_cast({:register_ai, service_name, config}, state) do
    new_config =
      Map.update(state.config, :authorized_services, %{}, fn services ->
        Map.put(services, service_name, config)
      end)

    {:noreply, %{state | config: new_config}}
  end

  @impl true
  def handle_cast({:block_ai, service_identifier}, state) do
    new_config =
      Map.update(state.config, :blocked_services, [], fn blocked ->
        [service_identifier | blocked] |> Enum.uniq()
      end)

    {:noreply, %{state | config: new_config}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    new_state = cleanup_old_data(state)
    schedule_cleanup()
    {:noreply, new_state}
  end

  @impl true
  def handle_info(:recalculate_risk, state) do
    new_state = recalculate_all_risk_scores(state)
    schedule_risk_recalculation()
    {:noreply, new_state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  defp calculate_overall_surface_risk(state) do
    # Calculate weighted risk based on various factors
    # injection_cache is a map, use map_size
    injection_risk = min(map_size(state.injection_cache || %{}) * 5, 30)
    # shadow_ai_detections and agent_interactions are lists
    shadow_ai_risk = min(length(state.shadow_ai_detections || []) * 10, 30)
    flow_risk = min(map_size(state.data_flow_tracker || %{}) * 2, 20)
    interaction_risk = min(length(state.agent_interactions || []), 20)

    total = injection_risk + shadow_ai_risk + flow_risk + interaction_risk
    Float.round(min(total, 100) * 1.0, 1)
  end

  defp generate_surface_recommendations(state) do
    recommendations = []

    # shadow_ai_detections is a list
    recommendations =
      if length(state.shadow_ai_detections || []) > 0 do
        ["Review and authorize or block detected shadow AI services" | recommendations]
      else
        recommendations
      end

    # injection_cache is a map, use map_size
    recommendations =
      if map_size(state.injection_cache || %{}) > 5 do
        ["Increase prompt sanitization for high-risk endpoints" | recommendations]
      else
        recommendations
      end

    high_risk_flows = count_high_risk_flows(state.data_flow_tracker)

    recommendations =
      if high_risk_flows > 0 do
        ["Review #{high_risk_flows} high-risk data flows" | recommendations]
      else
        recommendations
      end

    if Enum.empty?(recommendations) do
      ["Attack surface appears well-managed"]
    else
      recommendations
    end
  end

  defp count_high_risk_flows(data_flow_tracker) do
    data_flow_tracker
    |> Enum.flat_map(fn
      {_id, flows} when is_list(flows) -> flows
      {_id, flow} when is_map(flow) -> [flow]
      _ -> []
    end)
    |> Enum.count(fn flow ->
      (flow[:risk_score] || flow["risk_score"] || flow[:sensitivity_score] ||
         flow["sensitivity_score"] || 0) >= 0.7
    end)
  end

  # ============================================================================
  # Private Functions - Network Analysis
  # ============================================================================

  defp do_analyze_network(event, state) do
    domain = event[:remote_domain] || event[:remote_ip] || ""
    agent_id = event[:agent_id]
    timestamp = System.system_time(:millisecond)

    result = %{
      is_ai_traffic: false,
      ai_provider: nil,
      is_shadow_ai: false,
      risk_indicators: [],
      risk_score: 0.0
    }

    # Check if this is known AI traffic
    {is_ai, provider} = identify_ai_provider(domain)

    # Check for shadow AI
    is_shadow = is_shadow_ai?(domain)

    result = %{
      result
      | is_ai_traffic: is_ai || is_shadow,
        ai_provider: provider,
        is_shadow_ai: is_shadow
    }

    # Process AI traffic
    new_state =
      if result.is_ai_traffic do
        # Log the usage
        log_entry = %{
          timestamp: timestamp,
          agent_id: agent_id,
          domain: domain,
          provider: provider,
          is_shadow: is_shadow,
          bytes_sent: event[:bytes_sent] || 0,
          bytes_received: event[:bytes_received] || 0,
          process_name: event[:process_name],
          process_path: event[:process_path]
        }

        :ets.insert(state.ai_usage_log, {timestamp, log_entry})

        # Update stats
        new_stats = update_stats(state.stats, :ai_api_calls)

        # Check for anomalies
        risk_indicators = analyze_usage_anomalies(log_entry, state)

        # Handle shadow AI detection
        state =
          if is_shadow do
            handle_shadow_ai_detection(
              %{
                agent_id: agent_id,
                domain: domain,
                timestamp: timestamp,
                process_info: %{
                  name: event[:process_name],
                  path: event[:process_path]
                }
              },
              state
            )
          else
            state
          end

        # Create alert if risky
        if length(risk_indicators) > 0 do
          create_ai_alert(agent_id, :suspicious_ai_usage, %{
            domain: domain,
            provider: provider,
            indicators: risk_indicators
          })
        end

        %{state | stats: new_stats}
      else
        state
      end

    {result, new_state}
  end

  defp identify_ai_provider(domain) do
    Enum.find_value(@known_ai_endpoints, {false, nil}, fn {provider, domains} ->
      if Enum.any?(domains, &String.contains?(String.downcase(domain), &1)) do
        {true, provider}
      else
        nil
      end
    end)
  end

  defp is_shadow_ai?(domain) do
    domain_lower = String.downcase(domain)
    Enum.any?(@shadow_ai_indicators, &String.contains?(domain_lower, String.downcase(&1)))
  end

  defp analyze_usage_anomalies(log_entry, state) do
    indicators = []

    # Check for unusual hours (outside 6am-10pm local time)
    hour = DateTime.utc_now() |> Map.get(:hour)

    indicators =
      if hour < 6 or hour > 22 do
        [{:unusual_hours, "AI API access during unusual hours"} | indicators]
      else
        indicators
      end

    # Check for large data transfer (> 1MB)
    total_bytes = (log_entry.bytes_sent || 0) + (log_entry.bytes_received || 0)

    indicators =
      if total_bytes > 1_000_000 do
        [
          {:large_transfer, "Large data transfer to AI service: #{format_bytes(total_bytes)}"}
          | indicators
        ]
      else
        indicators
      end

    # Check for high volume (more than 100 calls in last hour from same agent)
    recent_count = count_recent_calls(state.ai_usage_log, log_entry.agent_id, :timer.hours(1))

    indicators =
      if recent_count > 100 do
        [{:high_volume, "High volume AI API usage: #{recent_count} calls/hour"} | indicators]
      else
        indicators
      end

    # Check if service is blocked
    indicators =
      if log_entry.domain in (state.config[:blocked_services] || []) do
        [{:blocked_service, "Access to blocked AI service"} | indicators]
      else
        indicators
      end

    indicators
  end

  # ============================================================================
  # Private Functions - Prompt Analysis
  # ============================================================================

  defp do_analyze_prompt(prompt, context, state) do
    timestamp = System.system_time(:millisecond)
    agent_id = context[:agent_id] || "unknown"

    # Run all detection patterns
    injection_results = detect_prompt_injection(prompt)
    exfiltration_results = detect_data_exfiltration(prompt)

    all_detections = injection_results ++ exfiltration_results

    # Calculate risk score for this prompt
    prompt_risk = calculate_prompt_risk(all_detections)

    result = %{
      is_malicious: length(all_detections) > 0,
      detections: all_detections,
      risk_score: prompt_risk,
      prompt_hash: hash_prompt(prompt),
      timestamp: timestamp
    }

    new_state =
      if result.is_malicious do
        # Update stats
        new_stats = update_stats(state.stats, :injection_attempts)

        # Update injection cache
        new_cache =
          Map.update(state.injection_cache, agent_id, [result], fn existing ->
            [result | Enum.take(existing, 99)]
          end)

        # Update risk score for entity
        new_risk_scores =
          update_risk_score(
            state.risk_scores,
            agent_id,
            :prompt_injection_attempt,
            prompt_risk
          )

        # Create alert for high severity detections
        high_severity = Enum.filter(all_detections, &(&1.severity in [:high, :critical]))

        if length(high_severity) > 0 do
          create_ai_alert(agent_id, :prompt_injection, %{
            detections: high_severity,
            prompt_preview: String.slice(prompt, 0, 200),
            context: context
          })
        end

        Logger.warning(
          "Prompt injection detected from #{agent_id}: #{inspect(Enum.map(all_detections, & &1.name))}"
        )

        %{state | stats: new_stats, injection_cache: new_cache, risk_scores: new_risk_scores}
      else
        state
      end

    {result, new_state}
  end

  defp detect_prompt_injection(prompt) do
    prompt_injection_patterns()
    |> Enum.filter(fn %{pattern: pattern} ->
      Regex.match?(pattern, prompt)
    end)
    |> Enum.map(fn detection ->
      %{
        type: :prompt_injection,
        name: detection.name,
        severity: detection.severity,
        description: detection.description,
        matched: true
      }
    end)
  end

  defp detect_data_exfiltration(prompt) do
    data_exfiltration_patterns()
    |> Enum.filter(fn %{pattern: pattern} ->
      Regex.match?(pattern, prompt)
    end)
    |> Enum.map(fn detection ->
      %{
        type: :data_exfiltration,
        name: detection.name,
        severity: detection.severity,
        description: detection.description,
        matched: true
      }
    end)
  end

  defp calculate_prompt_risk(detections) do
    if Enum.empty?(detections) do
      0.0
    else
      severity_scores =
        Enum.map(detections, fn d ->
          case d.severity do
            :critical -> 1.0
            :high -> 0.8
            :medium -> 0.5
            :low -> 0.2
            _ -> 0.1
          end
        end)

      # Take highest score and add diminishing returns for multiple detections
      max_score = Enum.max(severity_scores)
      additional = (length(severity_scores) - 1) * 0.05
      min(max_score + additional, 1.0)
    end
  end

  defp hash_prompt(prompt) do
    :crypto.hash(:sha256, prompt)
    |> Base.encode16(case: :lower)
    |> String.slice(0, 16)
  end

  # ============================================================================
  # Private Functions - Agent Interactions
  # ============================================================================

  defp record_agent_interaction(interaction, state) do
    timestamp = System.system_time(:millisecond)

    entry = %{
      timestamp: timestamp,
      agent_id: interaction[:agent_id],
      ai_service: interaction[:ai_service],
      action_type: interaction[:action_type],
      input_size: byte_size(interaction[:input] || ""),
      output_size: byte_size(interaction[:output] || ""),
      duration_ms: interaction[:duration_ms],
      success: interaction[:success],
      tool_calls: interaction[:tool_calls] || []
    }

    # Check for suspicious patterns
    suspicious = analyze_interaction_patterns(entry, state)

    if suspicious do
      create_ai_alert(entry.agent_id, :suspicious_agent_interaction, %{
        interaction: entry,
        reason: suspicious
      })
    end

    new_interactions = [entry | Enum.take(state.agent_interactions, 999)]
    new_stats = update_stats(state.stats, :agent_interactions)

    %{state | agent_interactions: new_interactions, stats: new_stats}
  end

  defp analyze_interaction_patterns(entry, state) do
    # Check for tool call abuse
    if length(entry.tool_calls) > 10 do
      "Excessive tool calls in single interaction: #{length(entry.tool_calls)}"
    else
      # Check for rapid-fire interactions from same agent
      recent =
        state.agent_interactions
        |> Enum.filter(fn i ->
          i.agent_id == entry.agent_id and
            entry.timestamp - i.timestamp < :timer.minutes(1)
        end)

      if length(recent) > 20 do
        "Rapid AI agent interactions: #{length(recent) + 1} in 1 minute"
      else
        nil
      end
    end
  end

  # ============================================================================
  # Private Functions - Data Flow Tracking
  # ============================================================================

  defp track_data_flow_event(flow_event, state) do
    agent_id = flow_event[:agent_id]
    timestamp = System.system_time(:millisecond)

    entry = %{
      timestamp: timestamp,
      # :to_ai or :from_ai
      direction: flow_event[:direction],
      ai_service: flow_event[:ai_service],
      data_type: flow_event[:data_type],
      size_bytes: flow_event[:size_bytes],
      contains_pii: flow_event[:contains_pii] || false,
      sensitivity_score: flow_event[:sensitivity_score] || 0.0
    }

    # Update flow tracker for this agent
    new_tracker =
      Map.update(state.data_flow_tracker, agent_id, [entry], fn existing ->
        [entry | Enum.take(existing, 499)]
      end)

    # Check for exfiltration patterns
    if entry.direction == :to_ai and (entry.contains_pii or entry.sensitivity_score > 0.7) do
      Logger.warning("Sensitive data flow to AI detected from #{agent_id}")

      create_ai_alert(agent_id, :sensitive_data_to_ai, %{
        flow: entry
      })

      update_risk_score(
        state.risk_scores,
        agent_id,
        :data_exfiltration_attempt,
        entry.sensitivity_score
      )
    end

    new_stats = update_stats(state.stats, :data_flows_tracked)

    %{state | data_flow_tracker: new_tracker, stats: new_stats}
  end

  # ============================================================================
  # Private Functions - Shadow AI Detection
  # ============================================================================

  defp handle_shadow_ai_detection(detection, state) do
    timestamp = System.system_time(:millisecond)

    entry = %{
      timestamp: timestamp,
      agent_id: detection[:agent_id],
      domain: detection[:domain],
      process_info: detection[:process_info],
      detected_at: DateTime.utc_now()
    }

    Logger.warning("Shadow AI detected: #{detection[:domain]} from agent #{detection[:agent_id]}")

    # Create alert
    create_ai_alert(detection[:agent_id], :shadow_ai_detected, %{
      domain: detection[:domain],
      process: detection[:process_info]
    })

    # Update risk score
    new_risk_scores =
      update_risk_score(
        state.risk_scores,
        detection[:agent_id],
        :shadow_ai_usage,
        0.8
      )

    new_detections = [entry | Enum.take(state.shadow_ai_detections, 499)]
    new_stats = update_stats(state.stats, :shadow_ai_detected)

    %{
      state
      | shadow_ai_detections: new_detections,
        risk_scores: new_risk_scores,
        stats: new_stats
    }
  end

  # ============================================================================
  # Private Functions - Risk Scoring
  # ============================================================================

  defp update_risk_score(risk_scores, entity_id, indicator, event_score) do
    weight = Map.get(@risk_weights, indicator, 10)
    contribution = weight / 100.0 * event_score

    Map.update(
      risk_scores,
      entity_id,
      %{score: contribution, factors: [indicator]},
      fn existing ->
        new_score = min(existing.score + contribution, 1.0)
        new_factors = [indicator | existing.factors] |> Enum.uniq() |> Enum.take(10)
        %{score: new_score, factors: new_factors}
      end
    )
  end

  defp recalculate_all_risk_scores(state) do
    # Apply decay to all risk scores (10% decay per cycle)
    new_scores =
      Map.new(state.risk_scores, fn {entity_id, data} ->
        decayed_score = data.score * 0.9
        {entity_id, %{data | score: decayed_score}}
      end)
      |> Enum.filter(fn {_, data} -> data.score > 0.01 end)
      |> Map.new()

    %{state | risk_scores: new_scores}
  end

  # ============================================================================
  # Private Functions - Alerts
  # ============================================================================

  defp create_ai_alert(agent_id, alert_type, details) do
    severity =
      case alert_type do
        :prompt_injection -> :high
        :shadow_ai_detected -> :medium
        :sensitive_data_to_ai -> :high
        :suspicious_ai_usage -> :medium
        :suspicious_agent_interaction -> :medium
        _ -> :low
      end

    title =
      case alert_type do
        :prompt_injection -> "Prompt Injection Attack Detected"
        :shadow_ai_detected -> "Shadow AI Usage Detected"
        :sensitive_data_to_ai -> "Sensitive Data Sent to AI Service"
        :suspicious_ai_usage -> "Suspicious AI API Usage"
        :suspicious_agent_interaction -> "Suspicious AI Agent Behavior"
        _ -> "AI Security Alert"
      end

    description = build_alert_description(alert_type, details)

    # Build evidence for AI security alerts
    evidence = build_ai_evidence(alert_type, details)

    case Alerts.create_alert(%{
           agent_id: agent_id,
           organization_id: TamanduaServer.Agents.OrgLookup.get_org_id(agent_id),
           severity: severity,
           title: title,
           description: description,
           # AI security alerts are not triggered by a single telemetry event
           source_event_id: nil,
           event_ids: [],
           evidence: evidence,
           mitre_tactics: get_mitre_tactics(alert_type),
           mitre_techniques: get_mitre_techniques(alert_type),
           threat_score: calculate_alert_threat_score(alert_type, details)
         }) do
      {:ok, alert} ->
        Logger.info("AI security alert created: #{alert.id} - #{title}")
        broadcast_ai_alert(alert)
        alert

      {:error, reason} ->
        Logger.error("Failed to create AI alert: #{inspect(reason)}")
        nil
    end
  end

  defp build_alert_description(:prompt_injection, details) do
    detections = details[:detections] || []

    """
    Prompt injection attack detected.

    Detections:
    #{Enum.map(detections, fn d -> "- #{d.name}: #{d.description}" end) |> Enum.join("\n")}

    Prompt preview: #{details[:prompt_preview] || "N/A"}
    """
  end

  defp build_alert_description(:shadow_ai_detected, details) do
    """
    Unauthorized AI service usage detected.

    Domain: #{details[:domain]}
    Process: #{inspect(details[:process])}

    This may indicate use of unapproved AI tools that could pose data leakage risks.
    """
  end

  defp build_alert_description(:sensitive_data_to_ai, details) do
    flow = details[:flow] || %{}

    """
    Sensitive data was sent to an AI service.

    AI Service: #{flow[:ai_service] || "Unknown"}
    Data Size: #{format_bytes(flow[:size_bytes] || 0)}
    Contains PII: #{flow[:contains_pii]}
    Sensitivity Score: #{Float.round((flow[:sensitivity_score] || 0) * 100, 1)}%
    """
  end

  defp build_alert_description(_type, details) do
    """
    AI security event detected.

    Details: #{inspect(details, pretty: true, limit: 500)}
    """
  end

  defp get_mitre_tactics(:prompt_injection), do: ["initial_access", "execution"]
  defp get_mitre_tactics(:shadow_ai_detected), do: ["exfiltration", "collection"]
  defp get_mitre_tactics(:sensitive_data_to_ai), do: ["exfiltration", "collection"]
  defp get_mitre_tactics(_), do: []

  defp get_mitre_techniques(:prompt_injection), do: ["T1059", "T1190"]
  defp get_mitre_techniques(:shadow_ai_detected), do: ["T1567", "T1041"]
  defp get_mitre_techniques(:sensitive_data_to_ai), do: ["T1567.002", "T1048"]
  defp get_mitre_techniques(_), do: []

  defp calculate_alert_threat_score(:prompt_injection, details) do
    detections = details[:detections] || []
    if Enum.any?(detections, &(&1.severity == :critical)), do: 0.95, else: 0.75
  end

  defp calculate_alert_threat_score(:sensitive_data_to_ai, _), do: 0.85
  defp calculate_alert_threat_score(:shadow_ai_detected, _), do: 0.65
  defp calculate_alert_threat_score(_, _), do: 0.5

  defp broadcast_ai_alert(alert) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "ai_security:alerts",
      {:ai_security_alert, alert}
    )
  end

  # ============================================================================
  # Private Functions - Utilities
  # ============================================================================

  defp build_config(opts) do
    %{
      authorized_services: Keyword.get(opts, :authorized_services, %{}),
      blocked_services: Keyword.get(opts, :blocked_services, []),
      enable_prompt_analysis: Keyword.get(opts, :enable_prompt_analysis, true),
      enable_shadow_ai_detection: Keyword.get(opts, :enable_shadow_ai_detection, true),
      alert_threshold: Keyword.get(opts, :alert_threshold, 0.6),
      # 7 days
      retention_hours: Keyword.get(opts, :retention_hours, 168)
    }
  end

  defp normalize_opts(opts) when is_map(opts), do: opts
  defp normalize_opts(opts) when is_list(opts), do: Map.new(opts)
  defp normalize_opts(_opts), do: %{}

  defp risk_assessment_entity_id(opts) when is_map(opts) do
    Map.get(opts, :entity_id) || Map.get(opts, "entity_id") || "organization"
  end

  defp risk_assessment_entity_id(opts) when is_list(opts) do
    opts
    |> normalize_opts()
    |> risk_assessment_entity_id()
  end

  defp risk_assessment_entity_id(nil), do: "organization"
  defp risk_assessment_entity_id(entity_id), do: to_string(entity_id)

  # Build structured evidence for AI security alerts
  defp build_ai_evidence(alert_type, details) do
    %{
      file_hashes: [],
      network: build_ai_network_evidence(details),
      process: build_ai_process_evidence(details),
      registry: [],
      detection: %{
        rule_name: "AI Security: #{alert_type}",
        rule_type: "ai_security",
        confidence: details[:confidence] || 0.7,
        matched_pattern: details[:matched_pattern] || to_string(alert_type)
      }
    }
  end

  defp build_ai_network_evidence(details) do
    indicators = []

    # Add domain if present
    indicators =
      if domain = details[:domain] do
        [%{type: "domain", value: domain, direction: "outbound"} | indicators]
      else
        indicators
      end

    # Add endpoint if present
    indicators =
      if endpoint = details[:endpoint] do
        [%{type: "url", value: endpoint, direction: "outbound"} | indicators]
      else
        indicators
      end

    indicators
  end

  defp build_ai_process_evidence(details) do
    process = details[:process] || %{}

    %{
      name: process[:name] || process["name"],
      path: process[:path] || process["path"],
      pid: process[:pid] || process["pid"]
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  defp initial_stats do
    %{
      ai_api_calls: 0,
      injection_attempts: 0,
      shadow_ai_detected: 0,
      agent_interactions: 0,
      data_flows_tracked: 0,
      alerts_created: 0,
      started_at: DateTime.utc_now()
    }
  end

  defp update_stats(stats, key) do
    Map.update(stats, key, 1, &(&1 + 1))
  end

  defp count_recent_calls(table, agent_id, window_ms) do
    now = System.system_time(:millisecond)
    threshold = now - window_ms

    :ets.tab2list(table)
    |> Enum.filter(fn {ts, event} ->
      ts > threshold and event.agent_id == agent_id
    end)
    |> length()
  end

  defp format_bytes(bytes) when bytes < 1024, do: "#{bytes} B"
  defp format_bytes(bytes) when bytes < 1_048_576, do: "#{Float.round(bytes / 1024, 1)} KB"
  defp format_bytes(bytes), do: "#{Float.round(bytes / 1_048_576, 2)} MB"

  defp cleanup_old_data(state) do
    retention_ms = (state.config[:retention_hours] || 168) * 3600 * 1000
    threshold = System.system_time(:millisecond) - retention_ms

    # Clean ETS table
    :ets.select_delete(state.ai_usage_log, [{{:"$1", :_}, [{:<, :"$1", threshold}], [true]}])

    # Clean in-memory lists
    new_interactions = Enum.filter(state.agent_interactions, &(&1.timestamp > threshold))
    new_shadow = Enum.filter(state.shadow_ai_detections, &(&1.timestamp > threshold))

    Logger.debug("AI security cleanup completed")

    %{state | agent_interactions: new_interactions, shadow_ai_detections: new_shadow}
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, :timer.hours(1))
  end

  defp schedule_risk_recalculation do
    Process.send_after(self(), :recalculate_risk, :timer.minutes(15))
  end

  # ============================================================================
  # Public API Wrapper Functions
  # ============================================================================

  @doc """
  Analyze AI attack surface for an organization or agent.
  """
  def analyze(opts \\ %{}) do
    GenServer.call(__MODULE__, {:analyze, opts}, 30_000)
  end

  @doc """
  Scan a prompt for potential injection attacks.
  """
  def scan_prompt(prompt, opts \\ %{}) do
    GenServer.call(__MODULE__, {:scan_prompt, prompt, opts})
  end
end
