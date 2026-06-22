defmodule TamanduaServer.Application do
  @moduledoc """
  The Tamandua Server OTP Application.

  Starts all supervision trees for the EDR backend:
  - Phoenix endpoint
  - Agent registry and supervisors
  - Broadway telemetry pipeline
  - Detection engine
  - Cache
  - Background jobs (Oban)
  """

  use Application

  @impl true
  def start(_type, _args) do
    # SECURITY: Check for dangerous LAB_LIGHT configuration in production
    check_lab_light_safety!()

    # SECURITY: Validate CORS configuration
    # Warns about insecure wildcard "*" origins in production
    check_cors_safety!()

    # SECURITY: Validate all credentials on startup
    # In production, weak/default credentials will cause startup to fail
    # In development, warnings are logged
    TamanduaServer.Credentials.validate_all!()

    children =
      if core_boot_profile?() do
        lab_light_children()
      else
        [
          # Start the Telemetry supervisor
          TamanduaServerWeb.Telemetry,

          # Initialize adaptive rate limiter ETS table (must be before Endpoint)
          %{
            id: :adaptive_rate_limiter_init,
            start:
              {Task, :start_link,
               [
                 fn ->
                   TamanduaServerWeb.Plugs.AdaptiveRateLimiter.ensure_table()

                   # Periodic cleanup every 5 minutes
                   spawn(fn ->
                     Stream.interval(300_000)
                     |> Stream.each(fn _ ->
                       TamanduaServerWeb.Plugs.AdaptiveRateLimiter.cleanup()
                     end)
                     |> Stream.run()
                   end)
                 end
               ]},
            restart: :temporary
          },

          # Start the Session Store (ETS tables for tokens)
          TamanduaServer.Accounts.SessionStore,
          TamanduaServer.CLIAuth,

          # Start the Ecto repository
          TamanduaServer.Repo,

          # Start PKI CA for CSR enrollment and mTLS agent certificates.
          TamanduaServer.PKI.CertificateAuthority,
          %{
            id: :pki_auto_init,
            start: {Task, :start_link, [fn -> maybe_auto_init_pki() end]},
            restart: :temporary
          },

          # Start the PubSub system
          {Phoenix.PubSub, name: TamanduaServer.PubSub},

          # Start web-facing processes early so health checks, static downloads,
          # and the console are available while heavier integrations initialize.
          TamanduaServerWeb.Presence,
          TamanduaServerWeb.Endpoint,

          # Start Finch for HTTP requests (with pool tuning)
          # Includes a dedicated connection pool for ClickHouse HTTP interface to
          # avoid contention with other outbound HTTP requests (ML service, TI feeds, etc.)
          {Finch,
           name: TamanduaServer.Finch,
           pools: %{
             :default => [size: 25, count: 4, conn_max_idle_time: 60_000],
             "http://localhost:8123" => [size: 10, count: 2, conn_max_idle_time: 120_000]
           }},

          # Start a Task.Supervisor for async background work
          # (used by ClickHouse flush, remediation, etc.)
          {Task.Supervisor, name: TamanduaServer.TaskSupervisor},

          # Start Solana Client for incident attestation (hackathon MVP)
          # Submits tamper-evident attestations to Solana devnet
          TamanduaServer.Solana.Client,

          # Batches self-hosted instance attestations for relay publication
          TamanduaServer.Solana.RelayBatch,

          # Start Fleet Health Attestation (Proof of Health - hackathon)
          # Publishes periodic aggregate fleet health proofs to Solana devnet
          TamanduaServer.Solana.FleetHealthAttestation,

          # Start the legacy ETS Cache (backward compatibility)
          TamanduaServer.Cache,

          # Start Redis connection pool
          {Redix,
           host: System.get_env("REDIS_HOST") || "localhost",
           port: String.to_integer(System.get_env("REDIS_PORT") || "6379"),
           name: :redix},

          # Start Redis Cache (distributed caching)
          TamanduaServer.Cache.RedisCache,

          # Start ETS Cache (in-memory hot lookups)
          TamanduaServer.Cache.ETSCache,

          # Start Cache Invalidator (coordinated invalidation)
          TamanduaServer.Cache.Invalidator,

          # Start Cache Warmer (background cache warming)
          TamanduaServer.Cache.Warmer,

          # Start Enrichment Cache (Nebulex cache for threat intel, GeoIP, etc.)
          TamanduaServer.Telemetry.Enrichment.Cache,

          # Start Enrichment Async Worker (background enrichment queue)
          TamanduaServer.Telemetry.Enrichment.AsyncWorker,

          # Start the Settings Manager
          TamanduaServer.Settings,

          # Start GeoIP enrichment service
          TamanduaServer.Enrichment.GeoIP,

          # Start Geo Stats service (threat map data)
          TamanduaServer.Enrichment.GeoStats,

          # Start Threat Intelligence service
          TamanduaServer.ThreatIntel,

          # Start MISP Integration (bidirectional sync with MISP servers)
          TamanduaServer.ThreatIntel.MISP,

          # Start MISP Publisher (queued batch publishing, conflict resolution, IOC sharing)
          TamanduaServer.ThreatIntel.MISPPublisher,

          # Start IOC Scoring Service (age-based decay, source reputation)
          TamanduaServer.ThreatIntel.IOCScoring,

          # Start RBAC Authorization service
          TamanduaServer.Authorization.RBAC,

          # Start License Management service
          TamanduaServer.Licensing.License,

          # Start White-labeling service
          TamanduaServer.Branding.WhiteLabel,

          # Start SSO service
          TamanduaServer.Auth.SSO,

          # Start Invitation Manager (ETS-backed invitation lifecycle)
          TamanduaServer.Auth.InvitationManager,

          # Start Audit service (tamper-proof logging)
          TamanduaServer.Audit,

          # Start Container Security service
          TamanduaServer.ContainerSecurity,

          # Start Container Escape Detection Correlation Engine
          # (CVE detection, namespace correlation, escalation chain tracking)
          TamanduaServer.ContainerSecurity.EscapeDetector,

          # Start Kubernetes Admission Controller (validates/mutates pod deployments)
          TamanduaServer.Kubernetes.AdmissionController,

          # Start Kubernetes Admission Webhook Engine (full pipeline: pod security,
          # mutation, alerting, stats, versioning, dry-run)
          TamanduaServer.Kubernetes.AdmissionWebhook,

          # Start Kubernetes Enricher (caches pod metadata for alert enrichment)
          TamanduaServer.Alerts.Enrichers.KubernetesEnricher,

          # Serverless Security Monitoring (AWS Lambda, Azure Functions, GCP Cloud Functions)
          TamanduaServer.Serverless.Lambda,
          TamanduaServer.Serverless.AzureFunctions,
          TamanduaServer.Serverless.CloudFunctions,
          TamanduaServer.Serverless.SecurityAnalyzer,
          TamanduaServer.Serverless.BehavioralBaseline,

          # Start Oban for background jobs
          {Oban, Application.fetch_env!(:tamandua_server, Oban)},

          # Start the Agent -> Organization lookup cache
          TamanduaServer.Agents.OrgLookup,

          # Start the Agent Registry (ETS-based tracking)
          TamanduaServer.Agents.Registry,

          # Start the Connector Registry (dynamic plugin system for integrations)
          TamanduaServer.Connectors.Registry,

          # Start the Connector Rate Limiter
          TamanduaServer.Connectors.Helpers.RateLimiter,

          # Start the Agent Health Monitor
          TamanduaServer.Agents.HealthMonitor,

          # Start the Agent Token Manager (JWT rotation and revocation)
          TamanduaServer.Agents.TokenManager,

          # Start the Agent Supervisor (dynamic supervisor for agent workers)
          {DynamicSupervisor,
           name: TamanduaServer.Agents.Supervisor,
           strategy: :one_for_one,
           max_restarts: 100,
           max_seconds: 60},

          # Start the EDR validation harness for Atomic Red Team coverage workflows
          TamanduaServer.Validation.EDRTester,

          # Start the Asset Manager for inventory tracking
          TamanduaServer.Inventory.AssetManager,

          # Start Asset Criticality Service
          TamanduaServer.Assets.Criticality,

          # Start the Sigma Aggregation Engine (timeframe-based rule evaluation)
          TamanduaServer.Detection.Rules.SigmaAggregator,

          # Start SigmaHQ Community Rules Synchronization (downloads Sigma rules from GitHub)
          {TamanduaServer.Detection.Rules.SigmaHQSync, [enabled: true, auto_sync: true]},

          # Start the DNS Analyzer (must start before Detection Engine)
          TamanduaServer.Detection.DNSAnalyzer,

          # Start the C2 Detector (encrypted traffic pattern analysis)
          TamanduaServer.Detection.C2Detector,

          # Start NDR (Network Detection and Response) modules
          TamanduaServer.NDR.FlowAnalyzer,
          TamanduaServer.NDR.ProtocolAnalyzer,
          TamanduaServer.NDR.LateralDetector,
          TamanduaServer.NDR.EncryptedTraffic,

          # Start Network Discovery modules (SentinelOne Ranger-style)
          # Device inventory must start first, then rogue detector and vuln scanner
          TamanduaServer.NetworkDiscovery.DeviceInventory,
          TamanduaServer.NetworkDiscovery.RogueDetector,
          TamanduaServer.NetworkDiscovery.DeviceVulnScanner,
          TamanduaServer.NetworkDiscovery.ScanPolicy,

          # Start ASM (Attack Surface Management) modules
          TamanduaServer.ASM.Discovery,
          TamanduaServer.ASM.Exposure,
          TamanduaServer.ASM.RiskScoring,
          TamanduaServer.ASM.Monitor,

          # Start Threat Intel Feed Synchronization
          TamanduaServer.Detection.ThreatIntelFeeds,

          # Start External Threat Intel Feeds (Abuse.ch, AlienVault OTX)
          TamanduaServer.Detection.ThreatIntel.Feeds,

          # Start Threat Intel Aggregator (deduplication, bloom filters, hot cache)
          TamanduaServer.ThreatIntel.Aggregator,

          # Start Threat Attribution Engine (IOC-to-actor correlation, campaigns)
          TamanduaServer.ThreatIntel.Attribution,

          # Start Campaign Tracker (auto-detects campaigns from attributed alerts)
          TamanduaServer.ThreatIntel.CampaignTracker,

          # Start Retroactive Scanner (scans historical telemetry for new IOCs)
          TamanduaServer.ThreatIntel.RetroactiveScanner,

          # Start IOC Relationship Graph (in-memory directed graph with confidence scoring)
          TamanduaServer.ThreatIntel.Graph,

          # Start TAXII Poller (scheduled polling of TAXII servers for new indicators)
          TamanduaServer.ThreatIntel.TaxiiPoller,

          # Start Commercial Threat Intel Feeds
          TamanduaServer.ThreatIntel.Feeds.RecordedFuture,
          TamanduaServer.ThreatIntel.Feeds.Mandiant,
          TamanduaServer.ThreatIntel.Feeds.CrowdStrikeIntel,
          TamanduaServer.ThreatIntel.Feeds.Proofpoint,

          # Start Additional Open Source Feeds
          TamanduaServer.ThreatIntel.Feeds.EmergingThreats,
          TamanduaServer.ThreatIntel.Feeds.FeodoTracker,
          TamanduaServer.ThreatIntel.Feeds.SSLBlacklist,
          TamanduaServer.ThreatIntel.Feeds.PhishTank,
          TamanduaServer.ThreatIntel.Feeds.OpenPhish,
          TamanduaServer.ThreatIntel.Feeds.Spamhaus,

          # Start Socket.dev Supply Chain Threat Intelligence Feed
          TamanduaServer.ThreatIntel.Feeds.SocketDev,

          # Start Threat Intel Enrichment Service
          TamanduaServer.Detection.ThreatIntelEnrichment,

          # Start VirusTotal Integration
          TamanduaServer.Detection.ThreatIntel.VirusTotal,

          # Start AlienVault OTX Integration
          TamanduaServer.Detection.ThreatIntel.AlienVault,

          # Start Shodan Integration
          TamanduaServer.Detection.ThreatIntel.Shodan,

          # Start Unified Threat Intel Enrichment
          TamanduaServer.Detection.ThreatIntel.UnifiedEnrichment,

          # Initialize YARA Scanner cache (ETS table, no supervision needed)
          %{
            id: :yara_scanner_init,
            start: {Task, :start_link, [fn -> TamanduaServer.Detection.YaraScanner.init() end]},
            restart: :temporary
          },

          # Initialize TyposquattingAnalyzer ETS tables (loads popular packages)
          %{
            id: :typosquatting_analyzer_init,
            start:
              {Task, :start_link,
               [fn -> TamanduaServer.Detection.TyposquattingAnalyzer.init() end]},
            restart: :temporary
          },

          # Start the Alert Suppression Engine (ETS-backed FP feedback loop)
          TamanduaServer.Alerts.Suppression,

          # Start the Enhanced Suppression Engine (Priority-based rule evaluation)
          TamanduaServer.Alerts.SuppressionEngine,

          # Start the Alert Deduplication Engine (ETS-backed sliding window dedup)
          TamanduaServer.Alerts.Deduplication,

          # Start Notification Deduplication (prevents notification spam)
          TamanduaServer.Alerts.NotificationDedup,

          # Start the Cross-Agent Alert Correlator (attack campaign detection)
          TamanduaServer.Alerts.CrossAgentCorrelator,

          # Start the Temporal Scorer (ETS-backed temporal proximity analysis)
          # Must start before Engine and Correlator so the :temporal_events table
          # is available when they begin processing events.
          TamanduaServer.Detection.TemporalScorer,

          # Start the Detection Analytics & Tuning Engine (ETS-backed metrics)
          TamanduaServer.Detection.Analytics,

          # Externalized detection thresholds + FP-budget preset overlay (Phase 66).
          # Must start before Detection.Engine/Behavioral/Baseline so the preset-resolved
          # ETS thresholds are available to Config.severity_from_score on the hot path.
          TamanduaServer.Detection.ThresholdConfig,

          # Start the Autonomous Storyline Engine (ETS-backed process tree + incident grouping)
          # Must start before Detection.Engine so the ETS tables are available
          TamanduaServer.Detection.Storyline,

          # Start the Storyline Persistence layer (periodic ETS -> PostgreSQL sync)
          # Must start after Storyline (needs ETS tables) and after Repo (needs DB).
          TamanduaServer.Detection.StorylinePersistence,

          # Start the Investigation Storyline Engine (attack narrative & causal graph)
          # Must start after PubSub (subscribes to alerts:feed) and after Repo.
          TamanduaServer.Investigations.Storyline,

          # Registry for shard-based worker lookup (used by EngineWorker via_shard/1)
          {Registry, keys: :unique, name: TamanduaServer.Detection.ShardRegistry},

          # Per-agent / per-process cache for the agent-side deterministic
          # risk score snapshot (`behavioral_risk_score` sideband event).
          # Must start before EngineSupervisor — EngineWorker reads/writes
          # the ETS table this GenServer owns.
          TamanduaServer.Detection.AgentRiskScoreStore,

          # Start the Sharded Detection Engine Supervisor (replaces single GenServer)
          # Creates ETS tables for rules + stats and spawns 16 EngineWorker shards.
          TamanduaServer.Detection.EngineSupervisor,

          # Start the Detection Engine facade (lightweight Agent for health checks;
          # also loads rules into ETS on startup)
          %{
            id: TamanduaServer.Detection.Engine,
            start: {TamanduaServer.Detection.Engine, :start_link, [[]]},
            restart: :permanent
          },

          # Start the Sandbox Detonation Engine (multi-sandbox dynamic analysis)
          TamanduaServer.Detection.Sandbox,

          # Populate shared ETS tables with rules from database
          # (runs once after EngineSupervisor + Engine are up)
          %{
            id: :detection_rules_loader,
            start:
              {Task, :start_link,
               [
                 fn ->
                   TamanduaServer.Detection.Engine.load_rules_into_ets()
                 end
               ]},
            restart: :temporary
          },

          # Start the YARA Auto-Generator (ML-driven rule generation)
          TamanduaServer.Detection.YaraGenerator,

          # Start the Correlation Engine
          TamanduaServer.Detection.Correlator,

          # Start the Cross-Agent Correlator (IOC-based cross-endpoint linking)
          # Detects campaigns by tracking shared hashes, IPs, domains across agents.
          # Must start after Detection Engine and Storyline.
          TamanduaServer.Detection.CrossAgentCorrelator,

          # Start the Provenance Graph Engine (causal analysis)
          TamanduaServer.Detection.Provenance,

          # Start the Lateral Movement Detection Engine (host-to-host path analysis)
          TamanduaServer.Detection.LateralMovement,

          # Start the Identity Threat Detection Engine (AD attack detection:
          # password spraying, impossible travel, lateral movement chains,
          # Kerberoasting, DCSync, Golden/Silver Ticket)
          TamanduaServer.Detection.IdentityThreats,

          # Start Dynamic Threat Hunter
          TamanduaServer.Detection.DynamicHunter,

          # Start Behavioral Detection Engine
          TamanduaServer.Detection.Behavioral,

          # Start Baseline Learning Engine
          TamanduaServer.Detection.Baseline,

          # Start Phishing Triage Engine
          TamanduaServer.Detection.PhishingTriage,

          # Start Phishing Analysis & Triage Engine (ETS-backed, campaign clustering)
          TamanduaServer.Detection.Phishing,

          # Enterprise Knowledge Graph & Analytics
          TamanduaServer.Graph.KnowledgeGraph,
          TamanduaServer.Graph.Analytics,

          # AI Asset Inventory (enterprise-wide AI component tracking)
          TamanduaServer.AISecurity.AIInventory,
          TamanduaServer.AISecurity.AIGateway,

          # AI Security Modules
          TamanduaServer.AISecurity.AttackSurface,
          TamanduaServer.AISecurity.AgenticAnalyst,
          TamanduaServer.AISecurity.PredictiveShield,
          TamanduaServer.AISecurity.AgentPosture,
          TamanduaServer.AISecurity.ExposureAgent,

          # AI Interaction Security (AIDR-equivalent: prompt injection, data leak, MCP governance)
          TamanduaServer.AISecurity.InteractionMonitor,
          TamanduaServer.AISecurity.MCPGovernance,
          TamanduaServer.AISecurity.ModelAuditor,

          # Start Natural Language Threat Hunting
          TamanduaServer.Hunting.NLHunter,

          # Start Query Scheduler (automated query execution)
          TamanduaServer.Hunting.QueryScheduler,

          # Response Executor is stateless - no need to supervise

          # Start Response History (DETS-backed action audit trail and deduplication)
          TamanduaServer.Response.ResponseHistory,

          # Start Network Isolation Manager (tracks isolation state per agent,
          # sends isolate/deisolate commands, supports full/partial/process levels)
          TamanduaServer.Response.NetworkIsolation,

          # Start Remediation Engine (ETS-backed job tracking & snapshot policies)
          TamanduaServer.Response.Remediation,

          # Start Response Playbook Engine
          TamanduaServer.Response.Playbook,

          # Start DAG-based Playbook Engine (parallel step execution, dependency
          # graphs, conditional branching, per-step timeouts, rollback on failure)
          TamanduaServer.Playbooks.DAGEngine,

          # Start Autonomous Response Engine
          TamanduaServer.Response.AutonomousRules,
          TamanduaServer.Response.AnalystLearning,
          TamanduaServer.Response.DecisionEngine,

          # Start ML-Driven Autonomous Response Engine (risk assessment, blast radius,
          # confidence thresholds, feedback loop, asset criticality)
          TamanduaServer.Response.AutonomousEngine,

          # Start Remediation Policy Engine (evaluates alerts against policies)
          TamanduaServer.Remediation.PolicyEngine,

          # Start Model Quarantine Vault (stores recovery keys, audit logs)
          TamanduaServer.Quarantine.ModelVault,

          # Start Advanced Remediation Engine (SentinelOne-class autonomous remediation)
          TamanduaServer.Response.AdvancedRemediation,

          # Start System-State Rollback Manager (SentinelOne-class full system rollback)
          TamanduaServer.Response.RollbackManager,

          # Start VSS Rollback Orchestration (1-click file rollback via Windows VSS)
          TamanduaServer.Response.VssRollback,

          # Start Response Simulator (dry-run and impact analysis)
          TamanduaServer.Response.Simulator,

          # Start Hyperautomation Engine
          TamanduaServer.Automation.Hyperautomation,

          # Agentic SOAR: Custom AI Agent Builder & Runtime
          # AgentBuilder: customer-facing agent creation via NL descriptions or explicit specs
          TamanduaServer.Agentic.AgentBuilder,
          # AgentRuntime: event-driven execution engine with guardrail enforcement
          TamanduaServer.Agentic.AgentRuntime,
          # WorkflowGenerator: converts completed investigations into reusable DAG workflows
          TamanduaServer.Agentic.WorkflowGenerator,
          # Orchestrator: central routing, collaboration, conflict resolution, priority queue
          TamanduaServer.Agentic.Orchestrator,
          # LearningLoop: self-improving detection with FP tracking, threshold adjustment
          TamanduaServer.Agentic.LearningLoop,

          # Start Forensics Collector
          TamanduaServer.Forensics.Collector,

          # Start Forensics Investigation Engine (ETS-backed investigation lifecycle)
          TamanduaServer.Forensics.Engine,

          # Check recording encryption config at startup (logs warning if no key)
          %{
            id: :recording_encryption_check,
            start:
              {Task, :start_link,
               [
                 fn ->
                   TamanduaServer.LiveResponse.SessionRecording.check_encryption_config()
                 end
               ]},
            restart: :temporary
          },

          # Start Live Response Session Manager (ETS-backed session lifecycle,
          # timeout, audit logging, concurrent session limits)
          TamanduaServer.LiveResponse.SessionManager,

          # Start ClickHouse client for high-volume telemetry storage
          # Must start before the Ingestor so it is available for dual-write.
          # The ClickHouse GenServer handles schema initialization and legacy queries.
          TamanduaServer.Telemetry.ClickHouse,

          # Start the ClickHouse Writer (batched, circuit-breaker-protected writer)
          # Buffers events and flushes asynchronously. If ClickHouse is unreachable
          # the circuit breaker opens and events are silently dropped until recovery.
          TamanduaServer.Telemetry.ClickHouseWriter,

          # Start the Syslog Receiver (Mini-SIEM: third-party log ingestion)
          # Listens on UDP/TCP for syslog, CEF, LEEF from firewalls, proxies, etc.
          # Must start after ClickHouseWriter since it forwards events there.
          TamanduaServer.Telemetry.SyslogReceiver,

          # Start Package Install Correlator (tracks package manager sessions)
          TamanduaServer.Telemetry.PackageInstallCorrelator,

          # Start ML Process Tracker (tracks ML runtime processes)
          TamanduaServer.Detection.MLProcessTracker,

          # Start Model File Correlator (correlates model file access with ML processes)
          TamanduaServer.Detection.ModelFileCorrelator,

          # Start LLM Request Tracker (tracks LLM API requests for Phase 27 analysis)
          TamanduaServer.Detection.LLMRequestTracker,

          # Start Inference Tracker (tracks request/response pairs for Phase 42 analysis)
          TamanduaServer.Detection.InferenceTracker,

          # Start Model Extraction Detector (detects model theft via query patterns)
          TamanduaServer.Detection.ModelExtractionDetector,

          # Start LLM Drift Detector (tracks output distribution drift for Phase 49)
          TamanduaServer.Detection.LLMDriftDetector,

          # Start MIA Detector (Membership Inference Attack detection)
          TamanduaServer.Detection.MIADetector,

          # Start OOD Tracker (Out-of-Distribution rate tracking per model)
          TamanduaServer.Detection.OODTracker,

          # Start Cache Poisoning Registry (ETS-backed known-good hash registry)
          TamanduaServer.Detection.CachePoisoningHandler.CacheRegistry,

          # Start Orchestration Detector (multi-LLM chain analysis: prompt laundering,
          # privilege escalation, extraction chains, recursive jailbreak detection)
          TamanduaServer.Detection.OrchestrationDetector,

          # Start the Broadway pipeline for telemetry ingestion
          # Note: IngestorProducer is started by Broadway, not separately
          {TamanduaServer.Telemetry.Ingestor, []},

          # Start the AI Conversation Store (ETS-backed persistence)
          TamanduaServer.AI.ConversationStore,

          # Start the AI Cost Governor (budget management, cost tracking, enforcement)
          TamanduaServer.AI.CostGovernor,

          # Start the AI Model Dependency Graph (tracks process->model and model->model dependencies)
          TamanduaServer.AI.DependencyGraph,

          # Start Registry Sync (periodic model registry metadata refresh)
          TamanduaServer.Registries.RegistrySync,

          # Start Registry Health Check (monitors HuggingFace, MLflow, W&B, Ollama connectivity)
          {TamanduaServer.Registries.HealthCheck,
           registries: [
             huggingface: [module: TamanduaServer.Registries.HuggingFace, config: %{}],
             mlflow: [module: TamanduaServer.Registries.MLflow, config: %{}],
             wandb: [module: TamanduaServer.Registries.WandB, config: %{}],
             ollama: [
               module: TamanduaServer.Registries.Ollama,
               config: %{base_url: System.get_env("OLLAMA_URL", "http://localhost:11434")}
             ]
           ],
           interval: 60_000},

          # Start Ollama Watcher (monitors for new model pulls, triggers security scanning)
          {TamanduaServer.Registries.OllamaWatcher,
           [
             poll_interval: 30_000,
             ollama_url: System.get_env("OLLAMA_URL", "http://localhost:11434")
           ]},

          # Start the ML Client
          TamanduaServer.Detection.ML.Client,

          # ML Model Lifecycle Management
          # ModelManager: ETS-backed model registry, canary deployment, performance tracking
          TamanduaServer.ML.ModelManager,
          # AnalystFeedback: verdict collection, FP/TP rate tracking, retraining triggers
          TamanduaServer.ML.AnalystFeedback,
          # TrainingScheduler: scheduled/on-demand retraining, job tracking
          TamanduaServer.ML.TrainingScheduler,

          # Integration Services
          TamanduaServer.Integrations.MCPServer,
          TamanduaServer.Integrations.CollaborationSecurity,
          TamanduaServer.Integrations.AISIEM,
          TamanduaServer.Integrations.SIEM,

          # Integration Logging (ETS-backed, must start before integrations)
          TamanduaServer.Integrations.IntegrationLog,

          # Ticketing Integration Router (Jira, ServiceNow dispatch with deduplication)
          TamanduaServer.Integrations.TicketingRouter,

          # Chat Integration Router (Slack, Teams dispatch for alerts and approvals)
          TamanduaServer.Integrations.ChatRouter,

          # Slack Bot (workspace configs, slash commands, interactive approval)
          TamanduaServer.Integrations.SlackBot,

          # Teams Bot (adaptive cards, bot commands, interactive approval)
          TamanduaServer.Integrations.TeamsBot,

          # SOAR Playbook Executor (execution dispatch, status tracking, retry)
          TamanduaServer.Integrations.SOAR.Executor,

          # Integration Alert Router (SIEM, SOAR, Ticketing routing)
          TamanduaServer.Integrations.Router,

          # Inbound Webhook Router (ETS-backed audit, rate limiting)
          TamanduaServer.Integrations.Webhook.InboundRouter,

          # Notification Throttler (ETS-backed rate limiting for notifications)
          TamanduaServer.Notifications.Throttler,

          # Notification Center Escalation Manager (auto-escalation, SLA tracking)
          TamanduaServer.NotificationCenter.EscalationManager,

          # Device Control & USB Policy Management
          TamanduaServer.DeviceControl,

          # DLP (Data Loss Prevention) Policy Engine and Incident Manager
          TamanduaServer.DLP.PolicyEngine,
          TamanduaServer.DLP.IncidentManager,

          # Compliance Reporting Framework
          TamanduaServer.Compliance,

          # Identity Protection
          TamanduaServer.Identity.RiskScoring,
          TamanduaServer.Identity.AzureAD,

          # Behavioral Baseline Learning & User Risk Scoring
          TamanduaServer.Detection.BaselineLearner,
          TamanduaServer.Identity.UserProfiler,
          TamanduaServer.Identity.PeerClustering,
          TamanduaServer.Identity.RiskEngine,

          # Vulnerability Management
          TamanduaServer.Vulnerability.NVD,
          TamanduaServer.Vulnerability.EPSS,
          TamanduaServer.Vulnerability.KEV,

          # Patch Management Engine (risk-based patch prioritization, canary deployment,
          # maintenance windows, rollback-on-failure; integrates with Vulnerability.*)
          TamanduaServer.PatchManagement.Engine,

          # Dark Web & Credential Breach Monitoring (HIBP, Intelligence X, custom feeds;
          # domain/email/executive monitoring, k-anonymity password checking)
          TamanduaServer.ThreatIntel.DarkWebMonitor,

          # Credential Hygiene Checker (password reuse detection, certificate expiry,
          # API key rotation tracking, service account hygiene)
          TamanduaServer.ThreatIntel.CredentialHygiene,

          # MDR (Managed Detection & Response) Delivery Framework
          # Alert queue, SLA timers, escalation paths, customer communication, service tiers
          TamanduaServer.MDR.Delivery,

          # MDR Analyst Console (triage, investigation workspaces, cross-customer
          # correlation, knowledge base, shift management, performance tracking)
          TamanduaServer.MDR.AnalystConsole,

          # MDR Metrics & Reporting (SLA compliance, MTTD/MTTR/MTTC, detection efficacy,
          # alert volume trends, executive reports)
          TamanduaServer.MDR.Metrics,

          # XDR (Extended Detection & Response)
          TamanduaServer.XDR.Correlator,
          {TamanduaServer.XDR.Ingestor, []},

          # Scalable Log Partitioning & Federated Search
          TamanduaServer.XDR.PartitionedStore,
          TamanduaServer.XDR.FederatedSearch,

          # Deception Technology (Breadcrumbs, Analytics)
          TamanduaServer.Deception.Breadcrumbs,
          TamanduaServer.Deception.Analytics,

          # Cloud Security Detection Rules (50+ rules)
          TamanduaServer.Cloud.DetectionRules,

          # Mobile Device Management (ETS-backed device registry, compliance, stats)
          TamanduaServer.Mobile.DeviceRegistry,

          # Update Rollout Supervisor (monitors active rollouts, auto-advances
          # staged/canary deployments, triggers auto-rollback on failure threshold)
          TamanduaServer.Updates.RolloutSupervisor,

          # Rollout Monitor — health-gated auto-advancement for staged/canary rollouts
          TamanduaServer.Updates.RolloutMonitor,

          # MITRE ATT&CK Coverage Tracker — maps rules to techniques, identifies gaps
          TamanduaServer.Detection.MitreCoverage,

          # SLO Monitoring & Error Budget Tracking
          TamanduaServer.SLO.Tracker,
          TamanduaServer.SLO.ErrorBudget,

          # False Positive Analysis & Tuning System
          TamanduaServer.FPAnalysis.FPTracker,
          TamanduaServer.FPAnalysis.FPPatterns,
          TamanduaServer.FPAnalysis.AutoTuner,
          TamanduaServer.FPAnalysis.BaselineLearner

          # Web endpoint starts near PubSub above so external feed initialization
          # cannot block HTTP readiness during deployment.
        ]
      end

    # Conditionally add ChromicPDF if Chrome is available
    children = maybe_add_chromic_pdf(children)

    # Conditionally add the DR FailoverManager (multi-site deployments only).
    # Gated behind :dr_failover_enabled (default false) so dev/test startup is
    # not impacted by DR peer health-check probes.
    children = maybe_add_dr_failover(children)

    # Conditionally start the OCSP revocation checker (owns its ETS status
    # cache). Gated behind :ocsp_enabled (default false) so dev/test -- which
    # have no live OCSP responder -- are unaffected.
    children = maybe_add_ocsp(children)

    opts = [
      strategy: :one_for_one,
      name: TamanduaServer.Supervisor,
      max_restarts: 50,
      max_seconds: 60
    ]

    Supervisor.start_link(children, opts)
  end

  # Start secrets management if enabled
  defp maybe_start_secrets_manager do
    secrets_enabled = Application.get_env(:tamandua_server, :secrets_enabled, false)
    secrets_backend = Application.get_env(:tamandua_server, :secrets_backend, :vault)

    if secrets_enabled do
      case secrets_backend do
        :vault ->
          vault_config = Application.get_env(:tamandua_server, :vault, [])

          [
            {TamanduaServer.Secrets.VaultProvider, vault_config},
            {TamanduaServer.Secrets.Manager, [primary_backend: :vault]}
          ]

        :aws ->
          aws_config = Application.get_env(:tamandua_server, :aws_secrets, [])

          [
            {TamanduaServer.Secrets.AWSProvider, aws_config},
            {TamanduaServer.Secrets.Manager, [primary_backend: :aws]}
          ]

        :both ->
          vault_config = Application.get_env(:tamandua_server, :vault, [])
          aws_config = Application.get_env(:tamandua_server, :aws_secrets, [])

          [
            {TamanduaServer.Secrets.VaultProvider, vault_config},
            {TamanduaServer.Secrets.AWSProvider, aws_config},
            {TamanduaServer.Secrets.Manager, [primary_backend: :vault, secondary_backend: :aws]}
          ]
      end
    else
      []
    end
  end

  # Check if Chrome/Chromium is available for PDF generation
  defp maybe_add_chromic_pdf(children) do
    chrome_executables = [
      "/usr/bin/chromium-browser",
      "/usr/bin/chromium",
      "/usr/bin/google-chrome",
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
      "/Applications/Chromium.app/Contents/MacOS/Chromium"
    ]

    chrome_available =
      Enum.any?(chrome_executables, fn exe ->
        File.regular?(exe)
      end)

    if chrome_available do
      require Logger
      Logger.info("[Application] Chrome detected, enabling PDF generation")
      [{ChromicPDF, chromic_pdf_config()} | children]
    else
      require Logger

      Logger.warning(
        "[Application] Chrome not found, PDF generation disabled. Install chromium for PDF support."
      )

      children
    end
  end

  # Conditionally start the OCSP revocation checker. Defaults to disabled so
  # dev/test boots never require a live OCSP responder. Enable via:
  #   config :tamandua_server, :ocsp_enabled, true
  defp maybe_add_ocsp(children) do
    if Application.get_env(:tamandua_server, :ocsp_enabled, false) do
      require Logger
      Logger.info("[Application] OCSP revocation checker enabled")
      children ++ [TamanduaServer.PKI.OCSP]
    else
      children
    end
  end

  # Conditionally start the DR FailoverManager. Defaults to disabled so dev/test
  # boots never probe absent DR peers. Enable via:
  #   config :tamandua_server, :dr_failover_enabled, true
  defp maybe_add_dr_failover(children) do
    if Application.get_env(:tamandua_server, :dr_failover_enabled, false) do
      require Logger
      Logger.info("[Application] DR FailoverManager enabled")
      children ++ [TamanduaServer.DR.FailoverManager]
    else
      children
    end
  end

  @impl true
  def config_change(changed, _new, removed) do
    TamanduaServerWeb.Endpoint.config_change(changed, removed)
    :ok
  end

  defp lab_light_children do
    [
      TamanduaServerWeb.Telemetry,
      %{
        id: :adaptive_rate_limiter_init,
        start:
          {Task, :start_link,
           [
             fn ->
               TamanduaServerWeb.Plugs.AdaptiveRateLimiter.ensure_table()
             end
           ]},
        restart: :temporary
      },
      TamanduaServer.Accounts.SessionStore,
      TamanduaServer.CLIAuth,
      TamanduaServer.Repo,
      {Phoenix.PubSub, name: TamanduaServer.PubSub},
      # Keep the web and agent mTLS listeners available before slower optional
      # workers initialize. This prevents Solana, validation, or ingestion boot
      # delays from making the console and agent socket look offline.
      TamanduaServerWeb.Presence,
      TamanduaServerWeb.Endpoint,
      TamanduaServer.PKI.CertificateAuthority,
      %{
        id: :pki_auto_init,
        start: {Task, :start_link, [fn -> maybe_auto_init_pki() end]},
        restart: :temporary
      },
      {Finch,
       name: TamanduaServer.Finch,
       pools: %{
         :default => [size: 10, count: 2, conn_max_idle_time: 60_000],
         "http://localhost:8123" => [size: 5, count: 1, conn_max_idle_time: 120_000]
       }},
      {Task.Supervisor, name: TamanduaServer.TaskSupervisor},
      {Redix,
       host: System.get_env("REDIS_HOST") || "localhost",
       port: String.to_integer(System.get_env("REDIS_PORT") || "6379"),
       name: :redix},
      # Solana Client for incident attestation
      TamanduaServer.Solana.Client,
      # Relay batcher for self-hosted public proof submissions
      TamanduaServer.Solana.RelayBatch,
      # Fleet Health Attestation (Proof of Health)
      TamanduaServer.Solana.FleetHealthAttestation,
      # Lightweight IOC cache for lab/demo alert enrichment. External feed
      # syncing remains outside lab-light; this gives the ingestor local IOC
      # lookups without booting the full threat-intel stack.
      TamanduaServer.ThreatIntel,
      TamanduaServer.Agents.OrgLookup,
      TamanduaServer.Agents.Registry,
      TamanduaServer.Agents.TokenManager,
      TamanduaServer.Agents.HealthMonitor,
      {DynamicSupervisor,
       name: TamanduaServer.Agents.Supervisor,
       strategy: :one_for_one,
       max_restarts: 100,
       max_seconds: 60},
      TamanduaServer.Validation.EDRTester,
      # NDR live views are in-memory GenServers. Keep them in lab-light so
      # /api/v1/ndr/* has live data without requiring the full detection stack.
      # Telemetry.Ingestor feeds these directly when Detection.Engine is absent.
      TamanduaServer.NDR.FlowAnalyzer,
      TamanduaServer.NDR.ProtocolAnalyzer,
      TamanduaServer.NDR.LateralDetector,
      TamanduaServer.NDR.EncryptedTraffic,
      TamanduaServer.AI.ConversationStore,
      # Live Response REST endpoints and tamandua-ctl rely on this ETS-backed
      # session lifecycle even in lab-light. Without it, session creation
      # returns 500 and the benchmark fallback transport is unusable.
      TamanduaServer.LiveResponse.SessionManager,
      TamanduaServer.Detection.TemporalScorer,
      TamanduaServer.Detection.Storyline,
      {Registry, keys: :unique, name: TamanduaServer.Detection.ShardRegistry},
      TamanduaServer.Detection.EngineSupervisor,
      %{
        id: TamanduaServer.Detection.Engine,
        start: {TamanduaServer.Detection.Engine, :start_link, [[]]},
        restart: :permanent
      },
      %{
        id: :detection_rules_loader,
        start:
          {Task, :start_link,
           [
             fn ->
               TamanduaServer.Detection.Engine.load_rules_into_ets()
             end
           ]},
        restart: :temporary
      },
      TamanduaServer.Detection.Correlator,
      # Lab-light still creates real alerts from telemetry. Keep the same
      # lightweight suppression/dedup path as the full profile so benchmarks
      # measure detector quality instead of supervision gaps.
      TamanduaServer.Alerts.Suppression,
      TamanduaServer.Alerts.SuppressionEngine,
      TamanduaServer.Alerts.Deduplication,
      {TamanduaServer.Telemetry.Ingestor, []}
    ]
  end

  defp lab_light? do
    System.get_env("TAMANDUA_LAB_LIGHT", "false") == "true"
  end

  defp maybe_auto_init_pki do
    if System.get_env("TAMANDUA_PKI_AUTO_INIT", "true") != "false" do
      case TamanduaServer.PKI.CertificateAuthority.ensure_initialized() do
        :ok ->
          require Logger
          Logger.info("[PKI] CA chain ready for CSR enrollment")

        {:error, reason} ->
          require Logger
          Logger.error("[PKI] CA auto-initialization failed: #{inspect(reason)}")
      end
    end
  end

  defp core_boot_profile? do
    lab_light?() || System.get_env("TAMANDUA_BOOT_PROFILE") in ["core", "demo"]
  end

  # SECURITY: Validate CORS configuration at startup
  # Wildcard "*" origin with session-based auth is dangerous (credential theft)
  defp check_cors_safety! do
    env = Application.get_env(:tamandua_server, :env)
    cors_origins = Application.get_env(:tamandua_server, :cors_origins)

    cond do
      # Production with wildcard CORS - warn strongly but don't block
      # (some deployments legitimately need this with bearer-only auth)
      cors_origins == "*" and env == :prod ->
        require Logger

        Logger.warning("""
        [SECURITY] WARNING: CORS_ORIGINS='*' detected in production!

        This allows any website to make authenticated API requests using session cookies.
        This is a security risk if your API accepts session-based authentication.

        Recommended: Set CORS_ORIGINS to specific allowed origins:
          CORS_ORIGINS=https://app.example.com,https://admin.example.com

        If your API uses Bearer token auth only (no session cookies), this warning
        can be safely ignored.
        """)

        :ok

      # Dev/test with wildcard - just log info
      cors_origins == "*" and env in [:dev, :test] ->
        :ok

      # Specific origins configured - safe
      true ->
        :ok
    end
  end

  # SECURITY: Prevent LAB_LIGHT mode from running in production
  # LAB_LIGHT allows unauthenticated WebSocket access as admin, which is dangerous
  defp check_lab_light_safety! do
    env = Application.get_env(:tamandua_server, :env)
    lab_light_enabled = System.get_env("TAMANDUA_LAB_LIGHT", "false") == "true"

    cond do
      # Production with LAB_LIGHT is FATAL - refuse to start
      lab_light_enabled and env == :prod ->
        require Logger

        Logger.critical("""
        [SECURITY] FATAL: TAMANDUA_LAB_LIGHT=true is set in production!

        This flag allows unauthenticated WebSocket connections with admin privileges.
        This is a critical security vulnerability and the application will not start.

        To fix: Remove TAMANDUA_LAB_LIGHT environment variable or set it to "false"
        """)

        raise "TAMANDUA_LAB_LIGHT cannot be enabled in production - security violation"

      # Dev/test with LAB_LIGHT - warn but allow
      lab_light_enabled and env in [:dev, :test] ->
        require Logger

        Logger.warning("""
        [SECURITY] LAB_LIGHT mode enabled (env=#{env})

        WebSocket connections without tokens will be authenticated as admin@tamandua.local.
        This is only allowed from loopback addresses (127.0.0.1, ::1).

        Do NOT expose this server to untrusted networks.
        """)

        :ok

      # No LAB_LIGHT - safe
      true ->
        :ok
    end
  end

  # ChromicPDF configuration
  defp chromic_pdf_config do
    [
      # Session pool for concurrent PDF generation
      session_pool: [size: 2],
      # Timeout for PDF generation (2 minutes)
      timeout: 120_000,
      # Chrome/Chromium options
      chrome_args: [
        "--headless",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--no-sandbox",
        "--disable-setuid-sandbox"
      ],
      # Offline mode - don't try to fetch external resources
      offline: false,
      # Disable JavaScript by default for security
      no_sandbox: true
    ]
  end
end
