defmodule TamanduaServer.Detection.EngineWorker do
  @moduledoc """
  Individual detection worker for one shard of the detection engine.

  Each worker handles events for a deterministic subset of agents (routed by
  `shard = :erlang.phash2(agent_id, num_shards)`). Workers read detection rules
  from shared ETS tables (:detection_sigma_rules, :detection_ioc_rules,
  :detection_yara_rules) and record per-shard statistics in :detection_stats.

  Workers never hold rule data in their GenServer state -- all rule reads go
  through the public ETS tables populated by `Engine.reload_rules/0`. This
  means rule reloads are instantaneous for all workers without message passing.

  ML calls are dispatched asynchronously via Task.Supervisor so they never
  block the event processing loop.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Detection.{Rules, Correlator, DNSAnalyzer, C2Detector, Config,
    CollectorRouter, EventContext, EventTypes, PreventionPolicy, Evidence, Mitre, YaraScanner, YaraGenerator, Baseline,
    TemporalScorer, Provenance, LateralMovement, IdentityThreats, Storyline,
    EngineSupervisor, PackageBehaviorAnalyzer, CredentialDetector, MLProcessTracker,
    ModelFileCorrelator, LLMRequestTracker, AIRuntimeAnalyzer, InferenceTracker,
    PromptInjectionClassifier}
  alias TamanduaServer.Detection.ThreatIntel.Feeds, as: ThreatIntelFeeds
  alias TamanduaServer.Telemetry.PackageInstallCorrelator
  alias TamanduaServer.Alerts
  alias TamanduaServer.Alerts.Suppression
  alias TamanduaServer.Alerts.HealthAwareSuppression
  alias TamanduaServer.Alerts.SupplyChainEnricher
  alias TamanduaServer.Repo
  alias TamanduaServer.Response.Executor
  alias TamanduaServer.Telemetry.Event
  alias TamanduaServer.Agents.OrgLookup
  alias TamanduaServer.ThreatIntel.Attribution
  alias TamanduaServer.Runtime.KillSwitch
  alias TamanduaServer.Detection.OutputValidator
  alias TamanduaServer.NDR.{FlowAnalyzer, ProtocolAnalyzer, LateralDetector, EncryptedTraffic, EventNormalizer}

  @trusted_domains [
    "microsoft.com", "windows.com", "windowsupdate.com", "office.com", "office365.com",
    "live.com", "outlook.com", "azure.com", "azureedge.net", "msedge.net",
    "google.com", "googleapis.com", "gstatic.com", "youtube.com", "googlevideo.com",
    "cloudflare.com", "cloudflare-dns.com",
    "amazonaws.com", "aws.amazon.com", "cloudfront.net",
    "github.com", "githubusercontent.com", "github.io",
    "akamai.net", "akamaized.net", "akadns.net",
    "apple.com", "icloud.com",
    "mozilla.org", "mozilla.net", "firefox.com",
    "digicert.com", "letsencrypt.org", "verisign.com",
    "ubuntu.com", "debian.org", "fedoraproject.org",
    "docker.com", "docker.io",
    "npmjs.org", "pypi.org", "crates.io", "hex.pm",
    "slack.com", "teams.microsoft.com"
  ]

  # ── Client API ─────────────────────────────────────────────────────

  def start_link(opts) do
    shard = Keyword.fetch!(opts, :shard)
    GenServer.start_link(__MODULE__, opts, name: via_shard(shard))
  end

  @doc "Analyze a single event (synchronous)."
  @spec analyze_event(non_neg_integer(), map()) :: {:ok, map()}
  def analyze_event(shard, event) do
    GenServer.call(via_shard(shard), {:analyze, event}, 15_000)
  end

  @doc "Analyze a single event asynchronously (fire-and-forget)."
  @spec analyze_event_async(non_neg_integer(), map()) :: :ok
  def analyze_event_async(shard, event) do
    GenServer.cast(via_shard(shard), {:analyze_async, event})
  end

  @doc "Analyze a batch of events (synchronous)."
  @spec analyze_batch(non_neg_integer(), [map()]) :: {:ok, [map()]}
  def analyze_batch(shard, events) do
    GenServer.call(via_shard(shard), {:analyze_batch, events}, 30_000)
  end

  @doc "Handle a critical event that requires immediate response."
  @spec handle_critical_event(non_neg_integer(), String.t(), map()) :: :ok
  def handle_critical_event(shard, agent_id, event) do
    GenServer.cast(via_shard(shard), {:critical_event, agent_id, event})
  end

  @doc "Submit a binary sample for ML analysis (synchronous)."
  @spec analyze_binary(non_neg_integer(), map()) :: {:ok, map()} | {:error, term()}
  def analyze_binary(shard, sample) do
    GenServer.call(via_shard(shard), {:analyze_binary, sample}, 60_000)
  end

  # ── Registry helpers ───────────────────────────────────────────────

  defp via_shard(shard) do
    {:via, Registry, {TamanduaServer.Detection.ShardRegistry, shard}}
  end

  # ── Server callbacks ───────────────────────────────────────────────

  @impl true
  def init(opts) do
    shard = Keyword.fetch!(opts, :shard)

    Logger.info("[EngineWorker] Shard #{shard} started")

    {:ok, %{shard: shard}}
  end

  @impl true
  def handle_call({:analyze, event}, _from, state) do
    result = do_analyze_event(event, state.shard)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:analyze_batch, events}, _from, state) do
    results = Enum.map(events, fn event -> do_analyze_event(event, state.shard) end)
    {:reply, {:ok, results}, state}
  end

  @impl true
  def handle_call({:analyze_binary, sample}, _from, state) do
    result = do_analyze_binary(sample, state.shard)
    {:reply, result, state}
  end

  @impl true
  def handle_cast({:analyze_async, event}, state) do
    do_analyze_event(event, state.shard)
    {:noreply, state}
  end

  @impl true
  def handle_cast({:critical_event, agent_id, event}, state) do
    do_handle_critical_event(agent_id, event)
    {:noreply, state}
  end

  # ── Core detection logic ───────────────────────────────────────────
  # This is the same logic that was in Engine.do_analyze_event/2, but
  # reads rules from ETS instead of GenServer state and records stats
  # via ETS counters instead of state mutation.

  defp do_analyze_event(event, shard) do
    start_time = System.monotonic_time(:microsecond)
    detection_context = EventContext.build(event)
    record_precision_event(:event_received, event, detection_context, %{})

    try do
      detections = []

      # 1. Check agent-side detections (already in event)
      agent_detections = List.wrap(event[:detections] || event["detections"] || [])
      detections = detections ++ agent_detections

      # 2. Sigma rule matching (read from ETS)
      sigma_rules = get_sigma_rules()
      sigma_matches = match_sigma_rules(event, sigma_rules)
      detections = detections ++ sigma_matches

      # 3. IOC matching (read from ETS)
      iocs = get_iocs()
      ioc_matches = match_iocs(event, iocs)
      detections = detections ++ ioc_matches

      # 3b. Threat Intel Feed matching
      feed_matches = match_threat_intel_feeds(event)
      detections = detections ++ feed_matches

      # 3c. Collector-aware routing catches high-signal telemetry that arrives
      # under generic event types and feeds side-effect engines for identity and
      # lateral movement collectors.
      collector_matches = CollectorRouter.analyze(event, detection_context)
      detections = merge_detections(detections, collector_matches)

      command_line_matches = command_line_detections(event, detection_context)
      detections = detections ++ command_line_matches

      # 4. DNS-specific analysis
      event_type = detection_context.event_type
      dns_detections = if event_type == "dns_query" do
        safe_call(fn -> DNSAnalyzer.analyze_dns_event(event) end, [])
      else
        []
      end
      detections = detections ++ dns_detections

      # 4b. DNS tunneling detection via C2 Detector
      dns_tunnel_detections = if event_type == "dns_query" do
        safe_call(fn -> C2Detector.analyze_dns_tunneling(event) end, [])
      else
        []
      end
      detections = detections ++ dns_tunnel_detections

      # 5. C2 detection for network connections. The detector tracks all
      # outbound flows for timing and composite scoring, but only emits an
      # alertable detection when multiple signals or a strong fingerprint exist.
      payload = event[:payload] || event["payload"] || %{}
      agent_id = event[:agent_id] || event["agent_id"]

      c2_detections = if event_type == "network_connect" do
        safe_call(fn -> C2Detector.analyze_connection(event) end, [])
      else
        []
      end
      detections = detections ++ c2_detections

      # 5b. Feed concrete network telemetry into the NDR analyzers. These
      # analyzers back the NDR dashboards and create their own high-confidence
      # alerts, so network events must pass through them even when no Sigma/IOC
      # rule matches the event.
      ndr_detections =
        if EventNormalizer.network_event?(event) do
          ndr_event = EventNormalizer.normalize_event(event)

          safe_call(fn -> FlowAnalyzer.process_event(ndr_event) end, :ok)

          safe_call(fn ->
            ProtocolAnalyzer.analyze_event(ndr_event) ++
              LateralDetector.analyze_event(ndr_event) ++
              EncryptedTraffic.analyze_event(ndr_event)
          end, [])
        else
          []
        end

      detections = detections ++ ndr_detections

      # 6. YARA scanning for file events
      yara_detections = if event_type in ["file_create", "file_modify", "process_create"] do
        scan_event_with_yara(event)
      else
        []
      end
      detections = detections ++ yara_detections

      # 7. Feed to correlator for behavioral analysis
      Correlator.add_event(event)

      # 7b. Build provenance graph
      prov_agent_id = event[:agent_id] || event["agent_id"]
      if prov_agent_id, do: safe_call(fn -> Provenance.record_event(prov_agent_id, event) end, :ok)

      # 7c-sl. Feed process lifecycle events into the Storyline engine
      storyline_agent_id = event[:agent_id] || event["agent_id"]
      if storyline_agent_id && event_type in ["process_create", "process", "process_terminate", "process_exit"] do
        safe_call(fn -> Storyline.ingest_process_event(storyline_agent_id, event) end, :ok)
      end

      # 7c. Feed authentication/network events to Lateral Movement engine
      lateral_event_types = ["authentication", "logon", "auth_event", "logon_event",
                             "network_connect", "network_connection", "network", "network_anomaly",
                             "service_create", "service_created", "service_install",
                             "scheduled_task", "task_create", "scheduled_task_create",
                             "wmi_event", "wmi_exec", "wmi_process",
                             "named_pipe", "pipe_connect"]

      if event_type in lateral_event_types do
        safe_call(fn -> LateralMovement.process_event(event) end, :ok)
      end

      # 7d. Feed authentication/identity events to Identity Threat engine
      identity_event_types = ["authentication", "logon", "auth_event", "logon_event",
                              "kerberos_tgt", "kerberos_tgs", "directory_replication",
                              "account_logon", "logon_failure"]

      if event_type in identity_event_types do
        safe_call(fn -> IdentityThreats.analyze_event(event) end, :ok)
      end

      # 7e. Supply chain behavioral analysis for package manager process exits
      supply_chain_detections = if event_type in ["process_terminate", "process_exit", :process_terminate, :process_exit] do
        analyze_package_install_completion(event)
      else
        []
      end
      detections = detections ++ supply_chain_detections

      # 7f. Credential/secret detection for process and file events
      credential_detections = if event_type in ["process_create", "process_creation", "file_create", "file_modify", "file_access"] do
        case CredentialDetector.detect_credentials(event) do
          {:ok, cred_detections} -> cred_detections
          _ -> []
        end
      else
        []
      end
      detections = detections ++ credential_detections

      # 7g. Track ML processes
      if event_type in ["process_create", "process_creation", "process"] do
        safe_call(fn -> MLProcessTracker.track_process(agent_id, event) end, :ok)
      end

      # 7h. Handle process termination
      if event_type in ["process_terminate", "process_exit", :process_terminate, :process_exit] do
        pid = payload[:pid] || payload["pid"]
        if pid, do: safe_call(fn -> MLProcessTracker.process_terminated(agent_id, pid) end, :ok)
      end

      # 7i. Correlate model file access
      if event_type in ["file_access", "file_read", "file_open", "file_create", "file_modify"] do
        safe_call(fn -> ModelFileCorrelator.correlate(agent_id, event) end, nil)
      end

      # 7j. Track LLM requests (legacy tracker for backward compatibility)
      if event_type in ["llm_request", "llm_api_request"] do
        safe_call(fn -> LLMRequestTracker.track_request(agent_id, payload) end, :ok)
      end

      # 7j-2. Track inference requests via new InferenceTracker (Phase 42)
      if event_type in ["inference_request", "llm_request", "llm_api_request"] do
        safe_call(fn -> InferenceTracker.track_request(agent_id, payload) end, :ok)
      end

      # 7j-3. Track inference responses via InferenceTracker (Phase 42)
      if event_type in ["inference_response", "llm_response", "llm_api_response"] do
        session_id = payload[:session_id] || payload["session_id"]
        if session_id do
          safe_call(fn -> InferenceTracker.track_response(agent_id, session_id, payload) end, :ok)
        end
      end

      # 7k. AI Runtime behavior analysis for LLM/inference requests
      ai_runtime_detections = if event_type in ["llm_request", "llm_api_request", "inference_request", "inference_response"] do
        case safe_call(fn -> AIRuntimeAnalyzer.analyze_llm_request(agent_id, payload) end, {:ok, []}) do
          {:ok, detections_list} ->
            Enum.map(detections_list, fn {rule, count} ->
              %{
                rule_id: rule["id"],
                rule_name: rule["title"],
                severity: rule["level"] || "medium",
                category: "ai_runtime",
                match_count: count
              }
            end)
          _ -> []
        end
      else
        []
      end
      detections = detections ++ ai_runtime_detections

      # 7l. Prompt injection classification for inference events (Phase 42)
      prompt_injection_detections = if event_type in ["inference_request", "llm_request", "llm_api_request"] do
        prompt = payload[:prompt_preview] || payload["prompt_preview"] || ""

        case safe_call(fn -> PromptInjectionClassifier.classify(prompt) end, {:ok, %{is_injection: false}}) do
          {:ok, %{is_injection: true} = result} ->
            # Create alert for prompt injection
            if agent_id do
              severity = PromptInjectionClassifier.severity_for_injection(result.injection_type)
              safe_call(fn ->
                Alerts.create_alert(%{
                  agent_id: agent_id,
                  severity: severity,
                  category: "prompt_injection",
                  title: "Prompt Injection Detected: #{result.injection_type || "unknown"}",
                  description: "Detected #{result.injection_type || "unknown"} prompt injection with #{round((result.confidence || 0.0) * 100)}% confidence",
                  tags: ["ai_security", "prompt_injection", to_string(result.injection_type || "unknown")],
                  threat_score: result.confidence || 0.0,
                  mitre_tactics: ["initial-access", "execution"],
                  mitre_techniques: ["T1203", "T1059"],
                  recommended_response: recommended_response_for("prompt_injection", severity),
                  detection_metadata: %{
                    "injection_type" => result.injection_type,
                    "confidence" => result.confidence,
                    "matched_patterns" => result.matched_patterns || [],
                    "analysis_method" => result.analysis_method,
                    "latency_ms" => result.latency_ms
                  }
                })
              end, :ok)
            end

            [%{
              type: :prompt_injection,
              rule_name: "Prompt Injection: #{result.injection_type || "unknown"}",
              confidence: result.confidence || 0.0,
              description: "Detected #{result.injection_type || "unknown"} prompt injection attack",
              mitre_tactics: ["initial-access", "execution"],
              mitre_techniques: ["T1203", "T1059"],
              injection_type: result.injection_type,
              matched_patterns: result.matched_patterns || [],
              analysis_method: result.analysis_method
            }]

          _ ->
            []
        end
      else
        []
      end
      detections = detections ++ prompt_injection_detections

      # 7m. Output validation and kill switch integration for inference responses (Phase 43)
      output_validation_detections = if event_type in ["inference_response", "llm_response", "llm_api_response"] do
        session_id = payload[:session_id] || payload["session_id"]
        output_text = payload[:output] || payload["output"] || payload[:response] || payload["response"] || ""

        case safe_call(fn -> OutputValidator.validate(session_id || "unknown", output_text, payload) end, {:ok, %{overall_risk: :low}}) do
          {:ok, %{overall_risk: risk_level} = validation_result} when risk_level in [:critical, :high] ->
            # Check if we should auto-trigger kill switch
            maybe_trigger_kill_switch(validation_result, agent_id, payload)

            # Return detection entry
            severity = if risk_level == :critical, do: "critical", else: "high"
            [%{
              type: :output_validation,
              rule_name: "Output Validation: #{risk_level}",
              confidence: Map.get(validation_result, :confidence, 0.8),
              description: build_output_validation_description(validation_result),
              mitre_tactics: ["impact", "exfiltration"],
              mitre_techniques: ["T1041", "T1567"],
              output_validation: validation_result
            }]

          _ ->
            []
        end
      else
        []
      end
      detections = detections ++ output_validation_detections

      detections = normalize_and_rank_detections(detections)

      # Calculate overall threat score
      threat_score = calculate_threat_score(detections)

      # 8. Apply temporal proximity boost
      {threat_score, temporal_metadata} = apply_temporal_adjustment(agent_id, event, threat_score, detections)

      # 9. Apply baseline adjustment
      {adjusted_threat_score, baseline_metadata} = apply_baseline_adjustment(agent_id, event, threat_score)
      baseline_metadata = Map.merge(baseline_metadata, temporal_metadata)
      {adjusted_threat_score, collector_metadata} =
        apply_collector_context_adjustment(adjusted_threat_score, detection_context)

      baseline_metadata = Map.merge(baseline_metadata, collector_metadata)

      # Update shard stats
      EngineSupervisor.update_shard_stat(shard, :events_analyzed)
      if length(detections) > 0, do: EngineSupervisor.update_shard_stat(shard, :detections)

      threat_score = adjusted_threat_score

      # Determine threat category
      threat_category = categorize_threat(event, detections)
      event = Map.put(event, :_detection_context, detection_context)

      # Evaluate against prevention policy
      policy_decision = PreventionPolicy.evaluate_event(
        event[:agent_id],
        event,
        threat_score,
        threat_category
      )

      result = apply_policy_decision(policy_decision, event, detections, threat_score, baseline_metadata, shard)
      persist_backend_detections(event, detections, threat_score, result)

      # Emit telemetry for per-shard latency tracking
      elapsed_us = System.monotonic_time(:microsecond) - start_time
      record_precision_event(:detection_completed, event, detection_context, %{
        duration_us: elapsed_us,
        detection_count: length(detections),
        threat_score: threat_score,
        policy_action: result[:policy_action],
        alert_id: result[:alert_id]
      })

      :telemetry.execute(
        [:tamandua, :detection, :engine_worker, :analyze],
        %{duration_us: elapsed_us, detection_count: length(detections)},
        %{shard: shard, agent_id: agent_id}
      )

      result
    rescue
      e ->
        Logger.error("[EngineWorker:#{shard}] analyze_event crashed: #{Exception.message(e)}")
        record_precision_event(:event_lost, event, detection_context, %{reason: Exception.message(e)})

        # Return a safe fallback so the caller never sees an exception
        %{
          event_id: event[:event_id],
          detections: [],
          threat_score: 0.0,
          alert_id: nil,
          policy_action: :error,
          error: Exception.message(e)
        }
    end
  end

  defp command_line_detections(event, detection_context) do
    event_type = detection_context.event_type

    if event_type in ["process_create", "process_creation", "process"] do
      payload = event[:payload] || event["payload"] || %{}
      process_name = payload[:process_name] || payload["process_name"] || payload[:name] || payload["name"] || ""
      command_line = payload[:command_line] || payload["command_line"] || payload[:cmdline] || payload["cmdline"] || ""
      path = payload[:path] || payload["path"] || payload[:image_path] || payload["image_path"] || ""
      process = process_name |> to_string() |> String.downcase()
      command = command_line |> to_string()
      command_lower = String.downcase(command)
      path_lower = path |> to_string() |> String.downcase()

      network_tool? =
        Enum.any?(
          ["curl.exe", "curl ", "powershell", "pwsh", "bitsadmin", "certutil", "wget", "python"],
          fn token -> String.contains?(process <> " " <> command_lower, token) end
        )

      beacon_path? =
        Regex.match?(~r/https?:\/\/[^\s"']+\/(?:beacon|gate|task|checkin)(?:[\/\?\s"']|$)/i, command)

      detections = []

      detections =
        if network_tool? and beacon_path? do
          [
            %{
              type: :command_line_c2_beacon,
              rule_name: "Command Line C2 Beacon Pattern",
              confidence: 0.78,
              severity: "medium",
              description:
                "Process command line contains a network utility request to a common C2 beacon URI path",
              evidence: %{
                process_name: process_name,
                command_line: command_line
              },
              mitre_tactics: ["command-and-control"],
              mitre_techniques: ["T1071.001"]
            }
          ]
        else
          detections
        end

      detections =
        if powershell_encoded_command?(process, path_lower, command_lower) do
          [
            %{
              type: :command_line_encoded_powershell,
              rule_name: "PowerShell Encoded Command",
              confidence: 0.72,
              severity: "medium",
              description:
                "PowerShell command line contains an encoded command switch",
              evidence: %{
                process_name: process_name,
                command_line: command_line
              },
              mitre_tactics: ["execution", "defense-evasion"],
              mitre_techniques: ["T1059.001", "T1027"]
            }
            | detections
          ]
        else
          detections
        end

      detections =
        if safe_lsass_probe?(process, path_lower, command_lower) do
          [
            %{
              type: :command_line_lsass_safe_probe,
              detection_type: "credential_access",
              category: "credential_theft",
              rule_name: "Safe LSASS Credential Access Probe",
              confidence: 0.8,
              severity: "high",
              description:
                "Process command line queries LSASS process metadata as a safe credential-access validation probe",
              evidence: %{
                process_name: process_name,
                path: path,
                command_line: command_line
              },
              mitre_tactics: ["credential-access"],
              mitre_techniques: ["T1003.001"],
              tags: ["credential", "lsass", "enterprise-safe"]
            }
            | detections
          ]
        else
          detections
        end

      detections =
        if safe_credential_canary_probe?(command_lower) do
          [
            %{
              type: :command_line_credential_canary_probe,
              detection_type: "credential_access",
              category: "credential_theft",
              rule_name: "Safe Credential Canary Probe",
              confidence: 0.78,
              severity: "high",
              description:
                "Process command line creates or searches a Tamandua credential canary used for safe credential-access validation",
              evidence: %{
                process_name: process_name,
                path: path,
                command_line: command_line
              },
              mitre_tactics: ["credential-access"],
              mitre_techniques: ["T1552.001"],
              tags: ["credential", "enterprise-safe"]
            }
            | detections
          ]
        else
          detections
        end

      if windows_temp_masquerade?(process, path_lower, command_lower) do
        [
          %{
            type: :command_line_masquerade,
            rule_name: "Windows Temp Masquerade Execution",
            confidence: 0.72,
            severity: "medium",
            description:
              "A Windows system binary name appears to execute from a user-writable temp path",
            evidence: %{
              process_name: process_name,
              path: path,
              command_line: command_line
            },
            mitre_tactics: ["defense-evasion"],
            mitre_techniques: ["T1036"]
          }
          | detections
        ]
      else
        detections
      end
    else
      []
    end
  end

  defp safe_lsass_probe?(process, path, command) do
    powershell? =
      String.contains?(process, "powershell") or
        String.contains?(process, "pwsh") or
        String.contains?(path, "powershell") or
        String.contains?(command, "get-process")

    powershell? and String.contains?(command, "get-process") and String.contains?(command, "lsass")
  end

  defp safe_credential_canary_probe?(command) do
    String.contains?(command, "tamanduacanary") or
      String.contains?(command, "tamandua-credential-canary") or
      (String.contains?(command, "password=") and String.contains?(command, "findstr"))
  end

  defp powershell_encoded_command?(process, path, command) do
    powershell? =
      String.contains?(process, "powershell") or
        String.contains?(process, "pwsh") or
        String.contains?(path, "powershell") or
        String.contains?(command, "powershell") or
        String.contains?(command, "pwsh")

    encoded_switch? =
      Regex.match?(~r/(^|\s)-(encodedcommand|enc|e)\s+[a-z0-9+\/=]{8,}/i, command)

    powershell? and encoded_switch?
  end

  defp windows_temp_masquerade?(process, path, command) do
    candidate_name =
      cond do
        process != "" -> process
        path != "" -> windows_path_basename(path)
        true -> ""
      end

    system_name? =
      candidate_name in [
        "svchost.exe",
        "lsass.exe",
        "conhost.exe",
        "services.exe",
        "spoolsv.exe",
        "rundll32.exe",
        "regsvr32.exe"
      ]

    temp_path? =
      String.contains?(path, "\\temp\\") or
        String.contains?(path, "/temp/") or
        String.contains?(command, "\\temp\\") or
        String.contains?(command, "%temp%")

    system_path? =
      String.contains?(path, "\\windows\\system32\\") or
        String.contains?(path, "\\windows\\syswow64\\") or
        String.contains?(path, "\\windows\\winsxs\\")

    system_name? and temp_path? and not system_path?
  end

  defp windows_path_basename(path) do
    path
    |> to_string()
    |> String.replace("/", "\\")
    |> String.split("\\")
    |> List.last()
    |> to_string()
    |> String.downcase()
  end

  # ── Policy decision handler ────────────────────────────────────────

  defp apply_policy_decision(policy_decision, event, detections, threat_score, baseline_metadata, shard) do
    case policy_decision.action do
      :ignore ->
        Logger.debug("Event ignored by prevention policy: #{policy_decision.reason}")

        %{
          event_id: event[:event_id],
          detections: detections,
          threat_score: threat_score,
          alert_id: nil,
          policy_action: :ignore,
          baseline: baseline_metadata
        }

      action when action in [:alert, :alert_and_block] ->
        # Build provisional alert for suppression check
        provisional_alert = build_provisional_alert(event, detections, threat_score)
        agent_id = event[:agent_id] || event["agent_id"]

        suppression_result = check_alert_suppression(provisional_alert, agent_id)

        case suppression_result do
          {:suppress, reason} ->
            EngineSupervisor.update_shard_stat(shard, :alerts_suppressed)
            Logger.debug("Alert suppressed: event=#{event[:event_id]}, agent=#{agent_id}, reason=#{reason}")
            Suppression.record_occurrence(provisional_alert, agent_id)

            %{
              event_id: event[:event_id],
              detections: detections,
              threat_score: threat_score,
              alert_id: nil,
              policy_action: :suppressed,
              suppression_reason: reason,
              baseline: baseline_metadata
            }

          {:auto_suppress, count, reason} ->
            EngineSupervisor.update_shard_stat(shard, :alerts_suppressed)
            Logger.debug("Alert auto-suppressed: event=#{event[:event_id]}, agent=#{agent_id}, count=#{count}")

            %{
              event_id: event[:event_id],
              detections: detections,
              threat_score: threat_score,
              alert_id: nil,
              policy_action: :auto_suppressed,
              suppression_reason: reason,
              suppression_count: count,
              baseline: baseline_metadata
            }

          {:reduce_severity, new_severity, reason} ->
            EngineSupervisor.update_shard_stat(shard, :alerts_severity_reduced)
            reduced_score = severity_to_reduced_score(new_severity, threat_score)
            reduced_alert = Map.put(provisional_alert, :severity, new_severity)

            handle_severity_reduction(
              reduced_alert, provisional_alert, event, detections,
              threat_score, reduced_score, new_severity, reason,
              action, agent_id, policy_decision, baseline_metadata, shard
            )

          :allow ->
            handle_allowed_alert(
              provisional_alert, event, detections, threat_score,
              action, policy_decision, baseline_metadata, shard
            )
        end
    end
  end

  # ── Severity reduction with health-aware tuning ────────────────────

  defp handle_severity_reduction(
    reduced_alert, provisional_alert, event, detections,
    original_threat_score, reduced_score, new_severity, reason,
    action, agent_id, policy_decision, baseline_metadata, shard
  ) do
    health_result = safe_health_tuning(reduced_alert, agent_id)

    case health_result do
      {:suppress, health_reason} ->
        EngineSupervisor.update_shard_stat(shard, :alerts_health_suppressed)
        Suppression.record_occurrence(provisional_alert, agent_id)

        %{
          event_id: event[:event_id],
          detections: detections,
          threat_score: reduced_score,
          original_threat_score: original_threat_score,
          alert_id: nil,
          policy_action: :health_suppressed,
          suppression_reason: "#{reason}; #{health_reason}",
          baseline: baseline_metadata
        }

      {:allow, health_tuned_alert} ->
        final_severity = health_tuned_alert[:severity] || new_severity
        final_score = severity_to_reduced_score(final_severity, reduced_score)

        if final_severity != new_severity do
          EngineSupervisor.update_shard_stat(shard, :alerts_health_adjusted)
        end

        alert_id = case create_alert_with_health_context(event, detections, final_score, health_tuned_alert, policy_decision) do
          {:ok, created_alert} ->
            EngineSupervisor.update_shard_stat(shard, :alerts_created)
            maybe_schedule_attribution(created_alert, event, detections)
            created_alert.id
          {:error, changeset_error} ->
            Logger.error("Failed to create severity-reduced alert: #{inspect(changeset_error)}")
            nil
        end

        Suppression.record_occurrence(provisional_alert, agent_id)
        HealthAwareSuppression.record_alert(agent_id)
        maybe_feed_storyline(event, detections, final_score)

        Logger.info("Alert severity reduced to #{final_severity}: #{reason}")

        if action == :alert_and_block do
          trigger_automatic_response(event, detections)
        end

        %{
          event_id: event[:event_id],
          detections: detections,
          threat_score: final_score,
          original_threat_score: original_threat_score,
          alert_id: alert_id,
          policy_action: action,
          severity_reduced: true,
          severity_reduction_reason: reason,
          agent_health_context: get_in(health_tuned_alert, [:detection_metadata, "agent_health_context"]),
          baseline: baseline_metadata
        }
    end
  end

  # ── Allowed alert (no suppression rule matched) ────────────────────

  defp handle_allowed_alert(
    provisional_alert, event, detections, threat_score,
    action, policy_decision, baseline_metadata, shard
  ) do
    agent_id = event[:agent_id] || event["agent_id"]
    health_result = safe_health_tuning(provisional_alert, agent_id)

    case health_result do
      {:suppress, health_reason} ->
        EngineSupervisor.update_shard_stat(shard, :alerts_health_suppressed)
        Suppression.record_occurrence(provisional_alert, agent_id)

        %{
          event_id: event[:event_id],
          detections: detections,
          threat_score: threat_score,
          alert_id: nil,
          policy_action: :health_suppressed,
          suppression_reason: health_reason,
          baseline: baseline_metadata
        }

      {:allow, health_tuned_alert} ->
        final_severity = health_tuned_alert[:severity] || provisional_alert[:severity]
        final_score = if to_string(final_severity) != to_string(provisional_alert[:severity]) do
          severity_to_reduced_score(to_string(final_severity), threat_score)
        else
          threat_score
        end

        if to_string(final_severity) != to_string(provisional_alert[:severity]) do
          EngineSupervisor.update_shard_stat(shard, :alerts_health_adjusted)
        end

        alert_id = case create_alert_with_health_context(event, detections, final_score, health_tuned_alert, policy_decision) do
          {:ok, created_alert} ->
            EngineSupervisor.update_shard_stat(shard, :alerts_created)
            maybe_schedule_attribution(created_alert, event, detections)
            created_alert.id
          {:error, changeset_error} ->
            Logger.error("Failed to create alert: #{inspect(changeset_error)}")
            nil
        end

        Suppression.record_occurrence(provisional_alert, agent_id)
        HealthAwareSuppression.record_alert(agent_id)
        maybe_feed_storyline(event, detections, final_score)

        if action == :alert_and_block do
          trigger_automatic_response(event, detections)
          Logger.warning("Alert + auto-response triggered: #{policy_decision.reason}")
        else
          Logger.info("Alert created (detect-only): #{policy_decision.reason}")
        end

        %{
          event_id: event[:event_id],
          detections: detections,
          threat_score: final_score,
          original_threat_score: if(final_score != threat_score, do: threat_score, else: nil),
          alert_id: alert_id,
          policy_action: action,
          agent_health_context: get_in(health_tuned_alert, [:detection_metadata, "agent_health_context"]),
          baseline: baseline_metadata
        }
    end
  end

  # ── ML binary analysis ─────────────────────────────────────────────

  defp do_analyze_binary(sample, shard) do
    alias TamanduaServer.Detection.ML
    alias TamanduaServer.Response.MLResponse

    case ML.Client.predict(sample) do
      {:ok, prediction} ->
        EngineSupervisor.update_shard_stat(shard, :ml_predictions)

        result = %{
          sha256: sample[:sha256],
          prediction: prediction,
          threat_score: calculate_ml_threat_score(prediction)
        }

        agent_id = sample[:agent_id] || sample["agent_id"]

        ml_response_result =
          if agent_id do
            MLResponse.handle_ml_detection(sample, prediction, agent_id)
          else
            if result.threat_score >= Config.threat_threshold() do
              case create_ml_alert(sample, prediction, result.threat_score) do
                {:ok, _alert} ->
                  {:ok, :alert_created, %{}}

                {:error, reason} ->
                  Logger.warning("Failed to create ML malware alert: #{inspect(reason)}")
                  {:error, :alert_failed}
              end
            else
              :no_action
            end
          end

        result = Map.put(result, :ml_response, ml_response_result)

        # Trigger YARA rule auto-generation asynchronously
        maybe_generate_yara_rule(sample, prediction)

        {:ok, result}

      {:error, reason} = error ->
        Logger.error("ML prediction failed: #{inspect(reason)}")
        error
    end
  end

  # ── Critical event handler ────────────────────────────────────────

  defp do_handle_critical_event(agent_id, event) do
    Logger.warning("Critical event from #{agent_id}: #{inspect(event[:event_type])}")

    case event[:event_type] do
      :honeyfile_access ->
        Executor.execute_action(agent_id, :isolate_network, %{
          reason: "Honeyfile access detected - potential ransomware",
          duration_seconds: 3600
        })

        if pid = event[:payload][:pid] do
          Executor.execute_action(agent_id, :kill_process, %{pid: pid, force: true})
        end

      :process_inject ->
        if pid = event[:payload][:pid] do
          Executor.execute_action(agent_id, :kill_process, %{pid: pid, force: true})
        end

      _ ->
        :ok
    end

    case create_critical_alert(agent_id, event) do
      {:ok, _alert} ->
        :ok

      {:error, reason} ->
        Logger.error(
          "Failed to create critical alert for #{agent_id} (#{inspect(event[:event_type])}): #{inspect(reason)}"
        )

        {:error, :alert_failed}
    end
  end

  # ── Supply Chain Analysis ─────────────────────────────────────────

  defp analyze_package_install_completion(event) do
    agent_id = event[:agent_id] || event["agent_id"]
    payload = event[:payload] || event["payload"] || %{}
    pid = payload[:pid] || payload["pid"]

    if agent_id && pid do
      # Check if this was a tracked package manager process
      case PackageInstallCorrelator.stop_tracking(agent_id, pid) do
        nil ->
          []

        session ->
          events = session.events || []
          ecosystem = session.ecosystem

          case PackageBehaviorAnalyzer.analyze_install_window(agent_id, pid, events) do
            {:anomalous, anomalies, risk_score} ->
              Logger.info("[EngineWorker] Supply chain anomaly detected: #{inspect(ecosystem)}, score=#{risk_score}")

              # Build and persist alert
              alert_attrs = PackageBehaviorAnalyzer.build_supply_chain_alert(agent_id, ecosystem, anomalies)

              case Alerts.create_alert(alert_attrs) do
                {:ok, alert} ->
                  enriched = SupplyChainEnricher.enrich(alert)
                  SupplyChainEnricher.broadcast_alert(enriched)

                  # Return detection for inclusion in response
                  [%{
                    type: :supply_chain,
                    rule_name: "Supply Chain Behavioral Anomaly",
                    confidence: risk_score,
                    description: alert_attrs[:description] || "Anomalous package install behavior",
                    mitre_tactics: ["initial_access"],
                    mitre_techniques: ["T1195.001", "T1059"]
                  }]

                {:error, reason} ->
                  Logger.error("[EngineWorker] Failed to create supply chain alert: #{inspect(reason)}")
                  []
              end

            :ok ->
              []
          end
      end
    else
      []
    end
  rescue
    e ->
      Logger.warning("[EngineWorker] Supply chain analysis failed: #{Exception.message(e)}")
      []
  catch
    :exit, _ ->
      []
  end

  # ── ETS rule readers ───────────────────────────────────────────────

  defp get_sigma_rules do
    rules =
      if Code.ensure_loaded?(TamanduaServer.Detection.RuleLoader) do
        TamanduaServer.Detection.RuleLoader.get_sigma_rules()
      else
        []
      end

    case rules do
      [] ->
        try do
          :ets.tab2list(:detection_sigma_rules) |> Enum.map(fn {_id, rule} -> rule end)
        rescue
          ArgumentError -> []
        end

      rules ->
        rules
    end
  end

  defp get_iocs do
    try do
      :ets.tab2list(:detection_ioc_rules) |> Enum.map(fn {_id, ioc} -> ioc end)
    rescue
      ArgumentError -> []
    end
  end

  defp persist_backend_detections(_event, [], _threat_score, _result), do: :ok

  defp persist_backend_detections(event, detections, threat_score, result) do
    event_id = event[:event_id] || event["event_id"] || event[:id] || event["id"]

    if is_binary(event_id) and event_id != "" do
      Task.start(fn ->
        retry_persist_backend_detections(event_id, detections, threat_score, result, 6)
      end)
    end

    :ok
  rescue
    _ -> :ok
  end

  defp retry_persist_backend_detections(_event_id, _detections, _threat_score, _result, 0), do: :ok

  defp retry_persist_backend_detections(event_id, detections, threat_score, result, attempts_left) do
    case Repo.get(Event, event_id) do
      nil ->
        Process.sleep(250)
        retry_persist_backend_detections(event_id, detections, threat_score, result, attempts_left - 1)

      %Event{} = persisted_event ->
        existing = List.wrap(persisted_event.detections)
        backend = Enum.map(detections, &json_safe_detection/1)
        merged = Enum.uniq_by(existing ++ backend, &detection_fingerprint/1)

        enrichment =
          persisted_event.enrichment
          |> ensure_map()
          |> Map.put("backend_detection", %{
            "detected" => true,
            "detection_count" => length(merged),
            "threat_score" => threat_score,
            "policy_action" => result[:policy_action] && to_string(result[:policy_action]),
            "alert_id" => result[:alert_id],
            "updated_at" => DateTime.utc_now() |> DateTime.to_iso8601()
          })

        persisted_event
        |> Event.changeset(%{detections: merged, enrichment: enrichment})
        |> Repo.update()
        |> case do
          {:ok, _} ->
            :ok

          {:error, reason} ->
            Logger.debug("[EngineWorker] Failed to persist backend detections for #{event_id}: #{inspect(reason)}")
            :ok
        end
    end
  rescue
    e ->
      Logger.debug("[EngineWorker] Backend detection persistence skipped for #{event_id}: #{Exception.message(e)}")
      :ok
  end

  defp json_safe_detection(detection) when is_map(detection) do
    detection
    |> Enum.map(fn {key, value} -> {to_string(key), json_safe_value(value)} end)
    |> Map.new()
    |> Map.put_new("source", "backend")
  end

  defp json_safe_value(value) when is_map(value), do: json_safe_detection(value)
  defp json_safe_value(value) when is_list(value), do: Enum.map(value, &json_safe_value/1)
  defp json_safe_value(value) when is_atom(value), do: Atom.to_string(value)
  defp json_safe_value(value), do: value

  defp detection_fingerprint(detection) when is_map(detection) do
    {
      Map.get(detection, "type") || Map.get(detection, :type),
      Map.get(detection, "rule_name") || Map.get(detection, :rule_name),
      Map.get(detection, "description") || Map.get(detection, :description)
    }
  end

  defp detection_fingerprint(other), do: other

  defp ensure_map(value) when is_map(value), do: value
  defp ensure_map(_), do: %{}

  # ── Detection matching functions ───────────────────────────────────
  # These are identical to the original Engine implementations.

  defp match_sigma_rules(event, rules) do
    instant_matches = Enum.flat_map(rules, fn rule ->
      sigma_rule = sigma_matcher_rule(rule)

      if Rules.Sigma.matches?(event, sigma_rule) do
        [%{
          type: :sigma,
          rule_name: sigma_rule["title"] || sigma_rule["name"] || Map.get(rule, :name) || "Sigma Rule",
          confidence: sigma_rule["level_score"] || Map.get(rule, :level_score) || sigma_level_score(sigma_rule["level"]),
          description: sigma_rule["description"] || Map.get(rule, :description),
          category: sigma_detection_category(sigma_rule),
          mitre_tactics: sigma_mitre_values(sigma_rule, :tactics),
          mitre_techniques: sigma_mitre_values(sigma_rule, :techniques),
          # Include author_pubkey for bounty payments (Solana base58 address)
          rule_author_pubkey: sigma_rule["author_pubkey"] || Map.get(rule, :author_pubkey)
        }]
      else
        []
      end
    end)

    # Aggregation-aware matching
    {_instant_parsed, agg_triggers} = Rules.Sigma.evaluate_with_aggregation(event)

    agg_matches = Enum.map(agg_triggers, fn {rule, count} ->
      %{
        type: :sigma_aggregation,
        rule_name: rule["title"] || "Aggregation Rule",
        confidence: Map.get(rule, "level_score", 0.7),
        description: "#{rule["description"] || "Aggregation threshold exceeded"} (count: #{count})",
        mitre_tactics: rule["tags"] |> List.wrap() |> Enum.filter(&String.starts_with?(to_string(&1), "attack.")),
        mitre_techniques: rule["tags"] |> List.wrap() |> Enum.filter(&String.starts_with?(to_string(&1), "attack.t")),
        # Include author_pubkey for bounty payments (Solana base58 address)
        rule_author_pubkey: rule["author_pubkey"]
      }
    end)

    instant_matches ++ agg_matches
  end

  defp sigma_matcher_rule(rule) when is_map(rule) do
    detection = Map.get(rule, :detection) || Map.get(rule, "detection") || %{}

    logsource =
      Map.get(rule, "logsource") ||
        %{
          "category" => Map.get(rule, :logsource_category) || Map.get(rule, "logsource_category"),
          "product" => Map.get(rule, :logsource_product) || Map.get(rule, "logsource_product"),
          "service" => Map.get(rule, :logsource_service) || Map.get(rule, "logsource_service")
        }
        |> Enum.reject(fn {_key, value} -> value in [nil, ""] end)
        |> Map.new()

    %{
      "title" => Map.get(rule, :title) || Map.get(rule, "title") || Map.get(rule, :name) || Map.get(rule, "name"),
      "name" => Map.get(rule, :name) || Map.get(rule, "name"),
      "description" => Map.get(rule, :description) || Map.get(rule, "description"),
      "level" => Map.get(rule, :level) || Map.get(rule, "level"),
      "level_score" => Map.get(rule, :level_score) || Map.get(rule, "level_score"),
      "logsource" => logsource,
      "detection" => detection,
      "tags" => Map.get(rule, :tags) || Map.get(rule, "tags") || [],
      "mitre_tactics" => Map.get(rule, :mitre_tactics) || Map.get(rule, "mitre_tactics") || [],
      "mitre_techniques" => Map.get(rule, :mitre_techniques) || Map.get(rule, "mitre_techniques") || [],
      "author_pubkey" => Map.get(rule, :author_pubkey) || Map.get(rule, "author_pubkey")
    }
  end

  defp sigma_mitre_values(rule, :tactics) do
    direct = Map.get(rule, "mitre_tactics") || []

    tags =
      rule
      |> Map.get("tags", [])
      |> List.wrap()
      |> Enum.map(&to_string/1)
      |> Enum.filter(&(String.starts_with?(&1, "attack.") and not String.starts_with?(&1, "attack.t")))

    Enum.uniq(direct ++ tags)
  end

  defp sigma_mitre_values(rule, :techniques) do
    direct = Map.get(rule, "mitre_techniques") || []

    tags =
      rule
      |> Map.get("tags", [])
      |> List.wrap()
      |> Enum.map(&to_string/1)
      |> Enum.filter(&String.starts_with?(&1, "attack.t"))

    (direct ++ tags)
    |> Enum.map(&canonical_mitre_technique/1)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end

  defp sigma_detection_category(rule) do
    tags =
      rule
      |> Map.get("tags", [])
      |> List.wrap()
      |> Enum.map(&to_string/1)

    cond do
      "attack.credential_access" in tags -> :credential_theft
      "attack.lateral_movement" in tags -> :lateral_movement
      "attack.command_and_control" in tags -> :command_and_control
      "attack.exfiltration" in tags -> :exfiltration
      "attack.defense_evasion" in tags -> :behavioral_ioa
      "attack.privilege_escalation" in tags -> :behavioral_ioa
      "attack.persistence" in tags -> :behavioral_ioa
      true -> :behavioral_ioa
    end
  end

  defp sigma_level_score("critical"), do: 0.95
  defp sigma_level_score("high"), do: 0.82
  defp sigma_level_score("medium"), do: 0.62
  defp sigma_level_score("low"), do: 0.35
  defp sigma_level_score(_), do: 0.5

  defp match_iocs(event, iocs) do
    observables = extract_observables(event)

    Enum.flat_map(iocs, fn ioc ->
      if observable_matches_ioc?(observables, ioc) do
        [%{
          type: :ioc,
          rule_name: "IOC: #{ioc.type}",
          confidence: ioc.confidence / 100,
          description: ioc.description,
          mitre_tactics: [],
          mitre_techniques: []
        }]
      else
        []
      end
    end)
  end

  defp match_threat_intel_feeds(event) do
    observables = extract_observables(event)
    detections = []

    # Check hash
    detections = if sha256 = observables.sha256 do
      hash_str = if is_binary(sha256), do: sha256, else: Base.encode16(sha256, case: :lower)
      case safe_feed_check(:hash, hash_str) do
        {:ok, %{found: true} = result} ->
          [feed_result_to_detection(result, :hash, hash_str) | detections]
        _ ->
          detections
      end
    else
      detections
    end

    # Check IP
    detections = if ip = observables.ip do
      case safe_feed_check(:ip, ip) do
        {:ok, %{found: true} = result} ->
          [feed_result_to_detection(result, :ip, ip) | detections]
        _ ->
          detections
      end
    else
      detections
    end

    # Check domain (skip trusted)
    detections = if domain = observables.domain do
      if not trusted_domain?(domain) do
        case safe_feed_check(:domain, domain) do
          {:ok, %{found: true} = result} ->
            [feed_result_to_detection(result, :domain, domain) | detections]
          _ ->
            detections
        end
      else
        detections
      end
    else
      detections
    end

    detections
  end

  # ── Helper functions (all carried over from Engine) ────────────────

  defp safe_call(fun, default) do
    try do
      fun.()
    rescue
      _ -> default
    catch
      :exit, _ -> default
    end
  end

  defp safe_health_tuning(provisional_alert, agent_id) do
    try do
      HealthAwareSuppression.apply_health_tuning(provisional_alert, agent_id)
    rescue
      e ->
        Logger.warning("Health-aware tuning failed for agent #{agent_id}: #{inspect(e)}")
        {:allow, provisional_alert}
    end
  end

  defp safe_feed_check(type, value) do
    try do
      case type do
        :hash -> ThreatIntelFeeds.check_hash(value)
        :ip -> ThreatIntelFeeds.check_ip(value)
        :domain -> ThreatIntelFeeds.check_domain(value)
        :url -> ThreatIntelFeeds.check_url(value)
      end
    rescue
      _ -> {:ok, %{found: false}}
    catch
      :exit, _ -> {:ok, %{found: false}}
    end
  end

  defp feed_result_to_detection(result, ioc_type, ioc_value) do
    confidence = result[:confidence] || 0.85

    %{
      type: :threat_intel_feed,
      rule_name: "Threat Intel: #{result[:source] || "external feed"}",
      confidence: confidence,
      description: "#{ioc_type} #{ioc_value} found in #{result[:source] || "threat feed"}: #{result[:threat_type] || "malicious"}" <>
        if(result[:malware_family], do: " (#{result[:malware_family]})", else: ""),
      mitre_tactics: feed_threat_type_to_tactics(result[:threat_type]),
      mitre_techniques: feed_threat_type_to_techniques(result[:threat_type]),
      feed_source: result[:source],
      threat_type: result[:threat_type],
      malware_family: result[:malware_family],
      tags: result[:tags] || []
    }
  end

  defp feed_threat_type_to_tactics(threat_type) do
    case threat_type do
      "botnet_cc" -> ["command-and-control"]
      "c2" -> ["command-and-control"]
      "malware" -> ["execution"]
      "malware_distribution" -> ["initial-access"]
      "phishing" -> ["initial-access"]
      "ransomware" -> ["impact"]
      _ -> []
    end
  end

  defp feed_threat_type_to_techniques(threat_type) do
    case threat_type do
      "botnet_cc" -> ["T1071"]
      "c2" -> ["T1071", "T1573"]
      "malware" -> ["T1204"]
      "malware_distribution" -> ["T1566"]
      "phishing" -> ["T1566"]
      "ransomware" -> ["T1486"]
      _ -> []
    end
  end

  defp extract_observables(event) do
    payload = event[:payload] || %{}

    %{
      sha256: payload[:sha256],
      sha1: payload[:sha1],
      md5: payload[:md5],
      ip: payload[:remote_ip],
      domain: extract_domain(payload),
      path: payload[:path],
      cmdline: payload[:cmdline]
    }
  end

  defp extract_domain(payload) do
    cond do
      payload[:query] -> payload[:query]
      payload[:domain] -> payload[:domain]
      payload[:url] ->
        case URI.parse(to_string(payload[:url])) do
          %URI{host: host} when is_binary(host) and host != "" -> host
          _ -> nil
        end
      payload[:hostname] -> payload[:hostname]
      payload[:remote_ip] -> nil
      true -> nil
    end
  end

  defp observable_matches_ioc?(observables, ioc) do
    case ioc.type do
      :sha256 -> observables.sha256 && Base.encode16(observables.sha256, case: :lower) == ioc.value
      :sha1 -> observables.sha1 && Base.encode16(observables.sha1, case: :lower) == ioc.value
      :md5 -> observables.md5 && Base.encode16(observables.md5, case: :lower) == ioc.value
      :ip -> observables.ip == ioc.value
      :domain ->
        domain = observables.domain
        domain != nil and
          not trusted_domain?(domain) and
          (domain == ioc.value or String.ends_with?(domain, "." <> ioc.value))
      _ -> false
    end
  end

  defp categorize_threat(event, detections) do
    event_type = event[:event_type] || event["event_type"]
    event_type_atom = safe_existing_atom(event_type)
    detection_types = Enum.map(detections, & &1[:category])
    detection_type_atoms = Enum.map(detections, & &1[:type])

    c2_types = [:c2_beacon_strong, :c2_beacon_moderate, :c2_ja3_match,
                :c2_suspicious_certificate, :c2_dga_https, :c2_domain_fronting_suspected,
                :c2_high_frequency, :c2_asymmetric_traffic, :c2_exfil_traffic]
    has_c2 = Enum.any?(detection_type_atoms, & &1 in c2_types)

    cond do
      :ransomware in detection_types -> :ransomware
      :credential_theft in detection_types -> :credential_theft
      :lateral_movement in detection_types -> :lateral_movement
      has_c2 -> :command_and_control
      event_type_atom in [:process_inject, :memory_scan, :shellcode] -> :fileless_attack
      event_type_atom in [:exploit_mitigation, :buffer_overflow, :rop_chain] -> :exploit_prevention
      event_type_atom in [:script_execution, :powershell, :amsi] -> :script_execution
      :ml in detection_type_atoms -> :malware_ml
      true -> :behavioral_ioa
    end
  end

  defp safe_existing_atom(value) when is_atom(value), do: value

  defp safe_existing_atom(value) when is_binary(value) do
    String.to_existing_atom(value)
  rescue
    _ -> :unknown
  end

  defp safe_existing_atom(_), do: :unknown

  defp calculate_threat_score(detections) do
    if Enum.empty?(detections) do
      0.0
    else
      {weighted_sum, total_weight} =
        Enum.reduce(detections, {0.0, 0.0}, fn d, {sum_acc, weight_acc} ->
          confidence = d[:confidence] || d["confidence"] || 0.5
          weight = detection_type_weight(d[:type] || d["type"])
          {sum_acc + confidence * weight, weight_acc + weight}
        end)

      if total_weight > 0.0, do: min(weighted_sum / total_weight, 1.0), else: 0.0
    end
  end

  defp detection_type_weight(type) when type in [:sigma, :sigma_aggregation], do: 1.5
  defp detection_type_weight(type) when type in ["sigma", "sigma_aggregation"], do: 1.5
  defp detection_type_weight(:yara), do: 1.4
  defp detection_type_weight("yara"), do: 1.4
  defp detection_type_weight(:threat_intel_feed), do: 1.4
  defp detection_type_weight("threat_intel_feed"), do: 1.4
  defp detection_type_weight(:ioc), do: 1.2
  defp detection_type_weight("ioc"), do: 1.2
  defp detection_type_weight(:ml), do: 1.0
  defp detection_type_weight("ml"), do: 1.0
  defp detection_type_weight(type) when type in [:c2_beacon_strong, :c2_ja3_match], do: 1.4
  defp detection_type_weight(type) when type in [:c2_beacon_moderate, :c2_suspicious_certificate, :c2_dga_https, :c2_domain_fronting_suspected], do: 1.2
  defp detection_type_weight(type) when type in [:c2_beacon_weak, :c2_high_frequency, :c2_asymmetric_traffic, :c2_exfil_traffic], do: 1.0
  defp detection_type_weight(_), do: 0.8

  defp merge_detections(existing, []), do: existing

  defp merge_detections(existing, extra) do
    (existing ++ extra)
    |> normalize_and_rank_detections()
    |> Enum.uniq_by(fn detection ->
      {detection[:type], detection[:rule_id], detection[:rule_name], detection[:description]}
    end)
  end

  defp normalize_and_rank_detections(detections) do
    detections
    |> List.wrap()
    |> Enum.map(&normalize_detection/1)
    |> Enum.reject(&Enum.empty?/1)
    |> Enum.sort_by(&detection_rank/1)
  end

  defp normalize_detection(detection) when is_map(detection) do
    type = detection[:type] || detection["type"] || detection[:detection_type] || detection["detection_type"]
    category = detection[:category] || detection["category"]
    rule_name = detection[:rule_name] || detection["rule_name"] || detection[:rule] || detection["rule"] || detection[:name] || detection["name"]
    description = detection[:description] || detection["description"] || detection[:matched_pattern] || detection["matched_pattern"]
    mitre_techniques =
      (detection[:mitre_techniques] || detection["mitre_techniques"] || List.wrap(detection[:mitre_technique] || detection["mitre_technique"]))
      |> List.wrap()
      |> Enum.map(&canonical_mitre_technique/1)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    detection
    |> atomize_known_detection_keys()
    |> Map.put(:type, normalize_detection_type(type))
    |> Map.put(:category, normalize_detection_category(category))
    |> Map.put(:rule_name, rule_name)
    |> Map.put(:description, description)
    |> Map.put(:confidence, normalize_confidence(detection[:confidence] || detection["confidence"]))
    |> Map.put(:mitre_techniques, mitre_techniques)
    |> Map.put(:detection_type, detection[:detection_type] || detection["detection_type"] || category || type)
  end

  defp normalize_detection(_), do: %{}

  defp atomize_known_detection_keys(detection) do
    Enum.reduce(
      [
        :rule_id, :severity, :mitre_tactics, :matched_pattern, :rule_author_pubkey,
        :feed_source, :threat_type, :malware_family, :tags
      ],
      %{},
      fn key, acc ->
        string_key = Atom.to_string(key)
        value = detection[key] || detection[string_key]
        if is_nil(value), do: acc, else: Map.put(acc, key, value)
      end
    )
  end

  defp normalize_detection_type(value) when is_atom(value), do: value
  defp normalize_detection_type(value) when is_binary(value) do
    case value do
      "sigma" -> :sigma
      "sigma_aggregation" -> :sigma_aggregation
      "yara" -> :yara
      "ioc" -> :ioc
      "ml" -> :ml
      "threat_intel_feed" -> :threat_intel_feed
      "prompt_injection" -> :prompt_injection
      "output_validation" -> :output_validation
      _ -> value
    end
  end
  defp normalize_detection_type(_), do: :unknown

  defp normalize_detection_category(value) when is_atom(value), do: value
  defp normalize_detection_category(value) when is_binary(value) do
    case value do
      "command_and_control" -> :command_and_control
      "credential_theft" -> :credential_theft
      "lateral_movement" -> :lateral_movement
      "exfiltration" -> :exfiltration
      "ransomware" -> :ransomware
      "behavioral_ioa" -> :behavioral_ioa
      _ -> value
    end
  end
  defp normalize_detection_category(_), do: :behavioral_ioa

  defp normalize_confidence(value) when is_float(value), do: value
  defp normalize_confidence(value) when is_integer(value), do: value / 1
  defp normalize_confidence(value) when is_binary(value) do
    case Float.parse(value) do
      {parsed, _} -> parsed
      _ -> 0.5
    end
  end
  defp normalize_confidence(_), do: 0.5

  defp detection_rank(detection) do
    {
      -category_rank(detection[:category]),
      -(detection[:confidence] || 0.0),
      to_string(detection[:rule_name] || "")
    }
  end

  defp category_rank(:ransomware), do: 100
  defp category_rank(:credential_theft), do: 95
  defp category_rank(:lateral_movement), do: 90
  defp category_rank(:command_and_control), do: 88
  defp category_rank(:exfiltration), do: 86
  defp category_rank(:behavioral_ioa), do: 50
  defp category_rank(_), do: 10

  defp canonical_mitre_technique(value) when is_atom(value), do: value |> Atom.to_string() |> canonical_mitre_technique()
  defp canonical_mitre_technique(value) when is_binary(value) do
    value
    |> String.trim()
    |> String.replace_prefix("attack.", "")
    |> String.upcase()
    |> case do
      "T" <> _ = technique -> technique
      _ -> nil
    end
  end
  defp canonical_mitre_technique(_), do: nil

  defp calculate_ml_threat_score(prediction) do
    case prediction[:prediction] do
      "malicious" -> prediction[:confidence]
      "suspicious" -> prediction[:confidence] * 0.7
      "benign" -> 1.0 - prediction[:confidence]
      _ -> 0.5
    end
  end

  # ── Alert creation ─────────────────────────────────────────────────

  defp create_alert_with_health_context(event, detections, threat_score, health_tuned_alert, policy_decision \\ nil) do
    severity = Config.severity_from_score(threat_score)
    severity = health_tuned_alert[:severity] || severity

    payload = event[:payload] || event["payload"] || %{}
    agent_id = event[:agent_id] || event["agent_id"]
    pid = payload[:pid] || payload["pid"]

    mitre_tactics = detections |> Enum.flat_map(& &1[:mitre_tactics] || []) |> Mitre.normalize_tactics()
    mitre_techniques = detections |> Enum.flat_map(& &1[:mitre_techniques] || []) |> Enum.uniq()

    evidence = Evidence.extract(event, detections)

    process_chain = if agent_id && pid do
      case Correlator.build_storyline(agent_id, pid) do
        {:ok, storyline} -> storyline.process_chain
        _ -> []
      end
    else
      []
    end

    title = generate_contextual_title(event, detections, evidence)

    detection_metadata = build_detection_metadata(event, detections)
    health_context = get_in(health_tuned_alert, [:detection_metadata, "agent_health_context"])

    detection_metadata = if health_context do
      Map.put(detection_metadata, "agent_health_context", health_context)
    else
      detection_metadata
    end

    detection_metadata =
      if policy_decision do
        Map.put(detection_metadata, "policy_decision", build_policy_decision_metadata(policy_decision))
      else
        detection_metadata
      end

    base_description = generate_alert_description(event, detections)
    health_description = health_tuned_alert[:description]
    description = if health_description && health_description != base_description do
      health_description
    else
      base_description
    end

    primary = List.first(detections) || %{}

    base_attrs = %{
      agent_id: agent_id,
      organization_id: event[:organization_id] || OrgLookup.get_org_id(agent_id),
      severity: severity,
      title: title,
      description: description,
      source_event_id: event[:event_id],
      event_ids: [event[:event_id]],
      contributing_events: [event[:event_id]] |> Enum.reject(&is_nil/1),
      evidence: evidence,
      process_chain: process_chain,
      raw_event: payload,
      detection_metadata: detection_metadata,
      mitre_tactics: mitre_tactics,
      mitre_techniques: mitre_techniques,
      recommended_response: recommended_response_for(detection_source(detections), severity),
      threat_score: threat_score
    }

    # Propagate the rule version from the primary detection only when it is
    # actually present; never fabricate a version on the synthetic path.
    attrs =
      case primary[:rule_version] do
        nil -> base_attrs
        rule_version -> Map.put(base_attrs, :rule_version, rule_version)
      end

    Alerts.create_alert(attrs)
  end

  defp create_critical_alert(agent_id, event) do
    payload = event[:payload] || event["payload"] || %{}
    pid = payload[:pid] || payload["pid"]

    evidence = Evidence.extract(event, [])

    process_chain = if agent_id && pid do
      case Correlator.build_storyline(agent_id, pid) do
        {:ok, storyline} -> storyline.process_chain
        _ -> []
      end
    else
      []
    end

    Alerts.create_alert(%{
      agent_id: agent_id,
      organization_id: event[:organization_id] || OrgLookup.get_org_id(agent_id),
      severity: :critical,
      title: "Critical: #{event[:event_type]}",
      description: "Critical security event detected requiring immediate attention",
      source_event_id: event[:event_id],
      event_ids: [event[:event_id]],
      evidence: evidence,
      process_chain: process_chain,
      raw_event: payload,
      detection_metadata: %{
        "rule_name" => "Critical Event: #{event[:event_type]}",
        "rule_type" => "critical_event",
        "confidence" => 1.0,
        "event_type" => to_string(event[:event_type] || "")
      },
      mitre_tactics: [],
      mitre_techniques: [],
      recommended_response: recommended_response_for("critical_event", :critical),
      threat_score: 1.0
    })
  end

  defp create_ml_alert(sample, prediction, threat_score) do
    agent_id = sample[:agent_id]
    pid = sample[:pid] || sample[:process_id]

    evidence = %{
      file_hashes: [%{sha256: sample[:sha256], path: sample[:path]}],
      network: [],
      process: %{name: sample[:process_name], path: sample[:path], pid: pid},
      registry: [],
      detection: %{
        rule_name: "ML Malware Detection",
        rule_type: "ml",
        confidence: prediction[:confidence],
        malware_family: prediction[:malware_family]
      }
    }

    process_chain = if agent_id && pid do
      case Correlator.build_storyline(agent_id, pid) do
        {:ok, storyline} -> storyline.process_chain
        _ -> []
      end
    else
      []
    end

    Alerts.create_alert(%{
      agent_id: agent_id,
      organization_id: sample[:organization_id] || OrgLookup.get_org_id(agent_id),
      severity: Config.severity_from_score(threat_score),
      title: "Malware detected: #{prediction[:malware_family] || "Unknown"}",
      description: "ML analysis detected malicious file with #{Float.round(prediction[:confidence] * 100, 1)}% confidence",
      source_event_id: sample[:event_id],
      event_ids: List.wrap(sample[:event_id]),
      evidence: evidence,
      process_chain: process_chain,
      raw_event: sample,
      detection_metadata: %{
        "rule_name" => "ML Malware Detection",
        "rule_type" => "ml",
        "confidence" => prediction[:confidence],
        "malware_family" => prediction[:malware_family],
        "prediction" => prediction[:prediction],
        "event_type" => "ml_detection"
      },
      mitre_tactics: [],
      mitre_techniques: [],
      recommended_response: recommended_response_for("ml", Config.severity_from_score(threat_score)),
      threat_score: threat_score
    })
  end

  # ── Metadata builders ──────────────────────────────────────────────

  defp build_detection_metadata(event, detections) do
    primary = List.first(detections) || %{}

    rule_names = detections
    |> Enum.map(& &1[:rule_name])
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()

    rule_types = detections
    |> Enum.map(& &1[:type])
    |> Enum.reject(&is_nil/1)
    |> Enum.map(&to_string/1)
    |> Enum.uniq()

    categories =
      detections
      |> Enum.map(& &1[:category])
      |> Enum.reject(&is_nil/1)
      |> Enum.map(&to_string/1)
      |> Enum.uniq()

    mitre_techniques =
      detections
      |> Enum.flat_map(&List.wrap(&1[:mitre_techniques]))
      |> Enum.map(&canonical_mitre_technique/1)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    mitre_tactics =
      detections
      |> Enum.flat_map(&List.wrap(&1[:mitre_tactics]))
      |> Mitre.normalize_tactics()

    %{
      "rule_name" => primary[:rule_name] || "",
      "rule_type" => primary[:type] && to_string(primary[:type]) || "",
      "detection_type" => primary[:detection_type] && to_string(primary[:detection_type]) || primary[:category] && to_string(primary[:category]) || primary[:type] && to_string(primary[:type]) || "",
      "category" => primary[:category] && to_string(primary[:category]) || "",
      "confidence" => primary[:confidence],
      "all_rule_names" => rule_names,
      "all_rule_types" => rule_types,
      "all_categories" => categories,
      "all_mitre_techniques" => mitre_techniques,
      "all_mitre_tactics" => mitre_tactics,
      "matched_pattern" => primary[:matched_pattern] || primary[:description],
      "event_type" => to_string(event[:event_type] || event["event_type"] || ""),
      "detection_count" => length(detections)
    }
    |> maybe_put_metadata("rule_id", primary[:rule_id])
    |> maybe_put_metadata("rule_version", primary[:rule_version])
    |> Map.merge(collector_context_metadata(event))
  end

  # Only inserts a metadata key when the source value is present, so we never
  # fabricate rule identifiers/versions that the detection did not carry.
  defp maybe_put_metadata(map, _key, nil), do: map
  defp maybe_put_metadata(map, key, value), do: Map.put(map, key, value)

  # Derive a stable detection-source string from the primary detection's type.
  # Used only to key the recommended_response lookup; falls back to "unknown".
  defp detection_source(detections) do
    case List.first(detections) do
      %{type: type} when not is_nil(type) -> to_string(type)
      %{} = primary -> to_string(primary[:detection_type] || primary[:category] || "unknown")
      _ -> "unknown"
    end
  end

  # Pure, conservative analyst guidance derived from the detection source and
  # severity already in scope at the creation site. Intentionally generic --
  # no specifics are invented that the alert data cannot support.
  defp recommended_response_for(source, severity) do
    sev = severity |> to_string() |> String.downcase()

    triage =
      case sev do
        "critical" -> "Triage immediately: isolate the affected host and preserve volatile evidence."
        "high" -> "Triage promptly: review the process chain and contain the host if confirmed."
        "medium" -> "Investigate the surrounding telemetry and validate against expected baseline activity."
        _ -> "Review the alert evidence and confirm whether the activity is expected."
      end

    specific =
      case to_string(source) do
        "ml" ->
          " Validate the flagged sample (hash/path) against threat intelligence before acting."

        "prompt_injection" ->
          " Inspect the offending prompt and consider revoking the session or model access."

        "critical_event" ->
          " Escalate to the on-call responder per critical-event runbook."

        _ ->
          ""
      end

    triage <> specific
  end

  defp build_policy_decision_metadata(policy_decision) do
    %{
      "action" => policy_decision.action && to_string(policy_decision.action),
      "severity" => policy_decision.severity,
      "reason" => policy_decision.reason,
      "policy_id" => policy_decision[:policy_id],
      "policy_name" => policy_decision[:policy_name],
      "mode" => policy_decision[:policy_mode],
      "aggressiveness" => policy_decision[:policy_aggressiveness],
      "threat_category" => policy_decision[:threat_category],
      "alert_threshold" => policy_decision[:alert_threshold],
      "block_threshold" => policy_decision[:block_threshold],
      "response_intent" => if(policy_decision.action == :alert_and_block, do: "automatic_response", else: "detect_only")
    }
  end

  defp build_provisional_alert(event, detections, threat_score) do
    payload = event[:payload] || event["payload"] || %{}
    agent_id = event[:agent_id] || event["agent_id"]

    mitre_tactics = detections |> Enum.flat_map(& &1[:mitre_tactics] || []) |> Mitre.normalize_tactics()
    mitre_techniques = detections |> Enum.flat_map(& &1[:mitre_techniques] || []) |> Enum.uniq()

    evidence = Evidence.extract(event, detections)
    title = generate_contextual_title(event, detections, evidence)
    severity = Config.severity_from_score(threat_score)

    detection_metadata = %{
      "rule_name" => detections |> List.first(%{}) |> Map.get(:rule_name, ""),
      "rule_type" => detections |> List.first(%{}) |> Map.get(:type, :unknown) |> to_string(),
      "event_type" => to_string(event[:event_type] || event["event_type"] || "")
    }
    |> Map.merge(collector_context_metadata(event))

    %{
      agent_id: agent_id,
      title: title,
      severity: to_string(severity),
      threat_score: threat_score,
      mitre_tactics: mitre_tactics,
      mitre_techniques: mitre_techniques,
      evidence: evidence,
      detection_metadata: detection_metadata,
      raw_event: payload
    }
  end

  defp generate_alert_description(event, detections) do
    """
    Event Type: #{event[:event_type]}
    Detections: #{length(detections)}
    #{Enum.map(detections, &format_detection_line/1) |> Enum.join("\n")}
    """
  end

  # Render a single detection line for the alert description, guarding against
  # nil fields so we never interpolate the literal string "nil". Falls back to
  # "unnamed rule" when no rule_name is present, and omits the ": description"
  # suffix entirely when no description is present.
  defp format_detection_line(d) do
    rule_name = d[:rule_name] || "unnamed rule"

    case d[:description] do
      nil -> "- #{rule_name}"
      description -> "- #{rule_name}: #{description}"
    end
  end

  defp generate_contextual_title(event, detections, _evidence) do
    Evidence.build_contextual_title(event, detections)
  end

  defp check_alert_suppression(provisional_alert, agent_id) do
    try do
      Alerts.should_suppress?(provisional_alert, agent_id)
    rescue
      e ->
        Logger.warning("Suppression check failed: #{inspect(e)}, allowing alert")
        :allow
    catch
      :exit, _ ->
        Logger.warning("Suppression check exit, allowing alert")
        :allow
    end
  end

  defp severity_to_reduced_score(new_severity, original_score) do
    target = case new_severity do
      "info" -> 0.1
      "low" -> 0.3
      "medium" -> 0.5
      "high" -> 0.7
      "critical" -> 0.9
      _ -> original_score
    end
    min(target, original_score)
  end

  defp trigger_automatic_response(event, _detections) do
    agent_id = event[:agent_id]

    if event[:event_type] in [:file_create, :file_modify, :file_execute] do
      if path = event[:payload][:path] do
        Executor.execute_action(agent_id, :quarantine_file, %{path: path})
      end
    end

    if event[:event_type] in [:process_create, :process_inject] do
      if pid = event[:payload][:pid] do
        Executor.execute_action(agent_id, :kill_process, %{pid: pid, force: true})
      end
    end
  end

  defp trusted_domain?(domain) when is_binary(domain) do
    domain_lower = String.downcase(domain)
    Enum.any?(@trusted_domains, fn trusted ->
      domain_lower == trusted or String.ends_with?(domain_lower, "." <> trusted)
    end)
  end
  defp trusted_domain?(_), do: false

  defp scan_event_with_yara(event) do
    unless YaraScanner.available?() do
      []
    else
      try do
        case YaraScanner.scan_event(event) do
          {:ok, matches} when matches != [] ->
            Logger.info("YARA scan found #{length(matches)} matches for event #{event[:event_id]}")
            YaraScanner.matches_to_detections(matches)
          {:ok, []} -> []
          {:error, reason} ->
            Logger.warning("YARA scan failed: #{inspect(reason)}")
            []
          :skip -> []
        end
      rescue
        e ->
          Logger.error("YARA scan error: #{Exception.message(e)}")
          []
      catch
        :exit, reason ->
          Logger.error("YARA scan exit: #{inspect(reason)}")
          []
      end
    end
  end

  defp apply_temporal_adjustment(nil, _event, threat_score, _detections) do
    {threat_score, %{}}
  end

  defp apply_temporal_adjustment(agent_id, event, threat_score, detections) do
    try do
      temporal_score = TemporalScorer.score_event(event, agent_id)
      event_type = EventTypes.normalize(event[:event_type] || event["event_type"])
      burst_score = TemporalScorer.get_burst_score(agent_id, event_type)

      boost = if length(detections) > 0 do
        temporal_boost = temporal_score * 0.10
        burst_boost = if burst_score >= 0.7, do: burst_score * 0.05, else: 0.0
        temporal_boost + burst_boost
      else
        0.0
      end

      adjusted = min(threat_score + boost, 1.0)

      metadata = %{
        temporal_score: Float.round(temporal_score, 4),
        burst_score: Float.round(burst_score, 4),
        temporal_boost: Float.round(boost, 4)
      }

      {adjusted, metadata}
    rescue
      e ->
        Logger.warning("Temporal adjustment failed: #{inspect(e)}")
        {threat_score, %{temporal_error: true}}
    catch
      :exit, _ ->
        {threat_score, %{temporal_error: true}}
    end
  end

  defp apply_baseline_adjustment(nil, _event, threat_score) do
    {threat_score, %{}}
  end

  defp apply_baseline_adjustment(agent_id, event, threat_score) do
    try do
      if Baseline.learning_mode?(agent_id) do
        Baseline.record_event(agent_id, event)
        {threat_score, %{learning_mode: true}}
      else
        baseline_score = Baseline.get_baseline_score(agent_id, event)

        if baseline_score > 0.0 do
          reduction_factor = cond do
            baseline_score >= 0.8 -> 0.5
            baseline_score >= 0.5 -> 0.25
            baseline_score >= 0.2 -> 0.1
            true -> 0.0
          end

          adjusted_score = threat_score * (1.0 - reduction_factor)

          metadata = %{
            baseline_adjusted: true,
            baseline_score: baseline_score,
            original_threat_score: threat_score,
            reduction_factor: reduction_factor
          }

          Logger.debug("Baseline adjustment for agent #{agent_id}: #{threat_score} -> #{adjusted_score}")
          {adjusted_score, metadata}
        else
          {threat_score, %{baseline_adjusted: false}}
        end
      end
    rescue
      e ->
        Logger.warning("Baseline adjustment failed: #{inspect(e)}")
        {threat_score, %{baseline_error: true}}
    catch
      :exit, _ ->
        {threat_score, %{baseline_error: true}}
    end
  end

  defp apply_collector_context_adjustment(threat_score, nil), do: {threat_score, %{}}

  defp apply_collector_context_adjustment(threat_score, context) do
    multiplier = context[:risk_multiplier] || 1.0
    adjusted_score = min(threat_score * multiplier, 1.0)

    metadata = %{
      collector_context_applied: true,
      collector: context[:collector],
      collector_source: context[:source],
      collector_profile: context[:profile],
      collector_family: context[:family],
      telemetry_quality: Float.round(context[:quality] || 0.0, 4),
      missing_telemetry_fields: context[:missing_fields] || [],
      collector_risk_multiplier: multiplier
    }

    {adjusted_score, metadata}
  end

  defp collector_context_metadata(%{_detection_context: context}) when is_map(context) do
    %{
      "collector" => context[:collector],
      "collector_source" => context[:source],
      "collector_profile" => context[:profile],
      "collector_family" => context[:family],
      "telemetry_quality" => Float.round(context[:quality] || 0.0, 4),
      "missing_telemetry_fields" => context[:missing_fields] || [],
      "collector_risk_multiplier" => context[:risk_multiplier] || 1.0
    }
  end

  defp collector_context_metadata(_event), do: %{}

  defp record_precision_event(kind, event, context, metadata) do
    if Code.ensure_loaded?(TamanduaServer.Detection.PrecisionMetrics) do
      safe_call(fn ->
        TamanduaServer.Detection.PrecisionMetrics.record_event(kind, %{
          event_id: event[:event_id] || event["event_id"],
          agent_id: event[:agent_id] || event["agent_id"],
          collector: context[:collector],
          profile: context[:profile],
          family: context[:family],
          event_type: context[:event_type],
          telemetry_quality: context[:quality],
          metadata: metadata
        })
      end, :ok)
    else
      :ok
    end
  end

  defp maybe_feed_storyline(event, detections, threat_score) do
    agent_id = event[:agent_id] || event["agent_id"]

    if agent_id do
      try do
        Storyline.ingest_detection(agent_id, %{
          event_id: event[:event_id],
          event_type: event[:event_type],
          payload: event[:payload] || event["payload"] || %{},
          detections: detections,
          threat_score: threat_score,
          mitre_tactics: detections |> Enum.flat_map(& &1[:mitre_tactics] || []),
          mitre_techniques: detections |> Enum.flat_map(& &1[:mitre_techniques] || []),
          title: detections |> Enum.map(& &1[:rule_name]) |> Enum.take(2) |> Enum.join(", ")
        })
      rescue
        _ -> :ok
      catch
        :exit, _ -> :ok
      end
    end
  end

  defp maybe_generate_yara_rule(sample, prediction) do
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      try do
        confidence = prediction[:confidence] || prediction["confidence"] || 0.0
        pred_label = prediction[:prediction] || prediction["prediction"]

        if pred_label in ["malicious", :malicious] and confidence >= 0.85 do
          event = %{
            event_type: :ml_detection,
            payload: sample,
            agent_id: sample[:agent_id] || sample["agent_id"],
            organization_id: sample[:organization_id] || sample["organization_id"]
          }

          case YaraGenerator.generate_rule(event, prediction) do
            {:ok, rule} ->
              Logger.info("YARA auto-generation succeeded: #{rule.name}")
            {:skip, reason} ->
              Logger.debug("YARA auto-generation skipped: #{reason}")
            {:error, reason} ->
              Logger.warning("YARA auto-generation failed: #{inspect(reason)}")
          end
        end
      rescue
        e ->
          Logger.warning("YARA auto-generation error: #{Exception.message(e)}")
      catch
        :exit, _ ->
          Logger.warning("YARA auto-generation exited unexpectedly")
      end
    end)
  end

  # ── Async threat attribution ────────────────────────────────────────
  # Only schedule attribution for high/critical alerts to avoid wasting
  # resources on low-confidence detections. Runs as a fire-and-forget
  # Task under the shared TaskSupervisor so it never blocks detection.

  defp maybe_schedule_attribution(alert, event, detections) do
    severity = to_string(alert.severity)

    if severity in ["high", "critical"] do
      Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
        try do
          # Build an enriched alert map for the attribution engine.
          # The Attribution module expects a map with :mitre_techniques,
          # :enrichment, and other fields it can extract IOCs/TTPs from.
          alert_data = %{
            id: alert.id,
            severity: alert.severity,
            title: alert.title,
            mitre_tactics: alert.mitre_tactics || [],
            mitre_techniques: alert.mitre_techniques || [],
            threat_score: alert.threat_score,
            enrichment: build_attribution_enrichment(alert, event, detections),
            evidence: alert.evidence || %{},
            detection_metadata: alert.detection_metadata || %{},
            agent_id: alert.agent_id
          }

          case Attribution.attribute_alert(alert_data) do
            {:ok, attributions} when is_list(attributions) and length(attributions) > 0 ->
              top = List.first(attributions)

              # Extract actor names from the top attributions
              actor_names = attributions
              |> Enum.take(3)
              |> Enum.map(fn a -> a[:actor_name] || a[:actor_id] || "unknown" end)

              # Build the details map from the top attribution
              details = %{
                "attributions" => Enum.take(attributions, 5) |> Enum.map(fn a ->
                  %{
                    "actor_name" => a[:actor_name],
                    "actor_id" => a[:actor_id],
                    "confidence" => a[:confidence],
                    "matching_iocs" => a[:matching_iocs] || [],
                    "matching_ttps" => a[:matching_ttps] || [],
                    "matching_malware" => a[:matching_malware] || [],
                    "evidence" => a[:evidence] || []
                  }
                end),
                "attributed_at" => DateTime.to_iso8601(DateTime.utc_now())
              }

              # Determine campaign_id from the top attribution if available
              campaign_id = top[:campaign_id]

              # Update the alert with attribution data
              Alerts.update_alert(alert, %{
                attributed_actors: actor_names,
                campaign_id: campaign_id,
                attribution_confidence: top[:confidence],
                attribution_details: details
              })

              # Notify the CampaignTracker about this attribution
              try do
                TamanduaServer.ThreatIntel.CampaignTracker.record_attribution(%{
                  alert_id: alert.id,
                  actor_names: actor_names,
                  confidence: top[:confidence],
                  timestamp: DateTime.utc_now()
                })
              rescue
                _ -> :ok
              catch
                :exit, _ -> :ok
              end

              Logger.info(
                "[Attribution] Alert #{alert.id} attributed to #{Enum.join(actor_names, ", ")} " <>
                "(confidence: #{Float.round(top[:confidence] || 0.0, 3)})"
              )

            {:ok, []} ->
              Logger.debug("[Attribution] No attribution match for alert #{alert.id}")

            {:error, reason} ->
              Logger.warning("[Attribution] Attribution failed for alert #{alert.id}: #{inspect(reason)}")
          end
        rescue
          e ->
            Logger.warning("[Attribution] Attribution error for alert #{alert.id}: #{Exception.message(e)}")
        catch
          :exit, reason ->
            Logger.warning("[Attribution] Attribution exited for alert #{alert.id}: #{inspect(reason)}")
        end
      end)
    end
  end

  # Build enrichment data from the event and detections for attribution lookups
  defp build_attribution_enrichment(alert, event, detections) do
    payload = event[:payload] || event["payload"] || %{}

    enrichment = %{}

    # Extract IPs
    enrichment = if ip = payload[:remote_ip] || payload["remote_ip"] do
      Map.put(enrichment, "source_ip", ip)
    else
      enrichment
    end

    # Extract domains
    enrichment = if domain = payload[:query] || payload["query"] || payload[:domain] || payload["domain"] do
      Map.put(enrichment, "domain", domain)
    else
      enrichment
    end

    # Extract file hashes
    enrichment = if hash = payload[:sha256] || payload["sha256"] do
      Map.put(enrichment, "file_hash", hash)
    else
      enrichment
    end

    # Extract malware family from detections
    malware_families = detections
    |> Enum.map(fn d -> d[:malware_family] || d[:yara_meta_malware] end)
    |> Enum.reject(&is_nil/1)

    enrichment = if length(malware_families) > 0 do
      Map.put(enrichment, "detected_malware", malware_families)
      |> Map.put("malware_family", List.first(malware_families))
    else
      enrichment
    end

    # Include MITRE techniques for TTP matching
    enrichment = Map.put(enrichment, "mitre_techniques", alert.mitre_techniques || [])

    enrichment
  end

  # ── Kill Switch Integration (Phase 43-02) ──────────────────────────

  defp maybe_trigger_kill_switch(validation_result, agent_id, payload) do
    if should_auto_trigger_kill_switch?(validation_result) do
      model_id = extract_model_id_from_payload(payload, agent_id)

      Task.start(fn ->
        try do
          case KillSwitch.status(model_id) do
            {:armed, _} ->
              reason = build_kill_switch_reason(validation_result)
              mode = determine_kill_switch_mode(validation_result)

              case KillSwitch.trigger(model_id, reason,
                     mode: mode,
                     triggered_by: "detection_engine"
                   ) do
                {:ok, result} ->
                  Logger.info(
                    "[EngineWorker] Kill switch triggered for model #{model_id}: " <>
                      "#{result.status} in #{result.latency_ms}ms"
                  )

                  # Emit telemetry
                  :telemetry.execute(
                    [:tamandua, :detection, :kill_switch_trigger],
                    %{latency_ms: result.latency_ms},
                    %{
                      model_id: model_id,
                      trigger_reason: validation_result.overall_risk,
                      detection_type: :output_validation,
                      auto_triggered: true
                    }
                  )

                {:error, reason} ->
                  Logger.warning("[EngineWorker] Kill switch trigger failed: #{inspect(reason)}")
              end

            _ ->
              Logger.debug("[EngineWorker] Kill switch not armed for model #{model_id}, skipping auto-trigger")
          end
        rescue
          e ->
            Logger.warning("[EngineWorker] Kill switch trigger error: #{Exception.message(e)}")
        catch
          :exit, _ ->
            Logger.warning("[EngineWorker] Kill switch trigger exited")
        end
      end)
    end
  end

  defp should_auto_trigger_kill_switch?(validation_result) do
    auto_trigger_enabled = Application.get_env(:tamandua_server, :kill_switch, [])
                           |> Keyword.get(:auto_trigger_enabled, true)

    auto_trigger_on_critical = Application.get_env(:tamandua_server, :kill_switch, [])
                               |> Keyword.get(:auto_trigger_on_critical, true)

    auto_trigger_on_high = Application.get_env(:tamandua_server, :kill_switch, [])
                           |> Keyword.get(:auto_trigger_on_high, false)

    cond do
      not auto_trigger_enabled -> false
      validation_result.overall_risk == :critical and auto_trigger_on_critical -> true
      validation_result.overall_risk == :high and auto_trigger_on_high -> true
      # Also trigger on specific high-confidence threats
      get_in(validation_result, [:harmful, :is_harmful]) and
        get_in(validation_result, [:harmful, :category]) in [:violence, :self_harm] -> true
      get_in(validation_result, [:pii, :has_pii]) and
        get_in(validation_result, [:pii, :pii_count]) >= 5 -> true
      get_in(validation_result, [:token_anomaly, :is_anomaly]) and
        get_in(validation_result, [:token_anomaly, :anomaly_score]) > 0.95 -> true
      true -> false
    end
  end

  defp extract_model_id_from_payload(payload, agent_id) do
    # Generate consistent model ID from payload components
    process_path = payload[:process_path] || payload["process_path"] || "unknown"
    api_endpoint = payload[:api_endpoint] || payload["api_endpoint"] || "unknown"
    model_name = payload[:model] || payload["model"] || "unknown"

    components = [process_path, api_endpoint, model_name]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(":")

    if components == "" do
      # Fallback to agent-based ID
      "agent:#{agent_id || "unknown"}"
    else
      :crypto.hash(:sha256, components) |> Base.encode16(case: :lower) |> String.slice(0, 16)
    end
  end

  defp build_kill_switch_reason(validation_result) do
    parts = []

    parts = if get_in(validation_result, [:harmful, :is_harmful]) do
      category = get_in(validation_result, [:harmful, :category])
      ["Harmful content: #{category}" | parts]
    else
      parts
    end

    parts = if get_in(validation_result, [:pii, :has_pii]) do
      count = get_in(validation_result, [:pii, :pii_count]) || 0
      ["PII detected: #{count} instances" | parts]
    else
      parts
    end

    parts = if get_in(validation_result, [:token_anomaly, :is_anomaly]) do
      score = get_in(validation_result, [:token_anomaly, :anomaly_score]) || 0.0
      ["Token anomaly: #{Float.round(score * 100, 1)}%" | parts]
    else
      parts
    end

    if parts == [] do
      "Output validation violation: #{validation_result.overall_risk}"
    else
      Enum.join(parts, "; ")
    end
  end

  defp determine_kill_switch_mode(validation_result) do
    case validation_result.overall_risk do
      :critical -> :full
      :high -> :network
      _ -> :network
    end
  end

  defp build_output_validation_description(validation_result) do
    parts = []

    parts = if get_in(validation_result, [:pii, :has_pii]) do
      types = get_in(validation_result, [:pii, :pii_types]) || []
      ["PII detected: #{Enum.join(types, ", ")}" | parts]
    else
      parts
    end

    parts = if get_in(validation_result, [:harmful, :is_harmful]) do
      category = get_in(validation_result, [:harmful, :category])
      confidence = get_in(validation_result, [:harmful, :confidence]) || 0.0
      ["Harmful content (#{category}): #{Float.round(confidence * 100, 1)}% confidence" | parts]
    else
      parts
    end

    parts = if get_in(validation_result, [:token_anomaly, :is_anomaly]) do
      score = get_in(validation_result, [:token_anomaly, :anomaly_score]) || 0.0
      ["Token anomaly score: #{Float.round(score, 3)}" | parts]
    else
      parts
    end

    if parts == [] do
      "Output validation flagged with risk level: #{validation_result.overall_risk}"
    else
      Enum.join(Enum.reverse(parts), ". ") <> ". Overall risk: #{validation_result.overall_risk}"
    end
  end
end
