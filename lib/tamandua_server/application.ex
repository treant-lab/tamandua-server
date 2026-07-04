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

  ## Supervision layout (fault isolation)

  CORE children (Repo, PubSub, Endpoint, registries, telemetry ingest /
  Broadway, detection engine + workers, ML client, agent supervision, alert /
  response pipeline) are direct children of the top-level `one_for_one`
  supervisor (max_restarts: 50 / 60s), in their original start order.

  PERIPHERAL children (external threat-intel feeds, cloud connectors,
  integrations, blockchain attestation, analytics, MDR/XDR, deception,
  compliance, ...) are grouped by domain into named supervisors under
  `TamanduaServer.Supervisors.*`, each `one_for_one` with its OWN restart
  budget (max_restarts: 10 / 60s). Each group supervisor is inserted at the
  exact list position where its children previously sat, so the global
  startup order is unchanged (each group's children start synchronously,
  in order, before the next top-level child starts).

  Containment semantics: a flapping peripheral child burns its group's
  budget, not the shared one. If a group exceeds its budget and dies, the
  top-level supervisor restarts that group — counting as ONE top-level
  restart — instead of the whole application dying with it.
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
                 end
               ]},
            restart: :temporary
          },

          # Periodic adaptive-rate-limiter cleanup every 5 minutes.
          # Previously an unsupervised `spawn` inside the init task; now a
          # supervised, permanent Task so a crash restarts the cleanup loop.
          %{
            id: :adaptive_rate_limiter_cleanup,
            start:
              {Task, :start_link,
               [
                 fn ->
                   Stream.interval(300_000)
                   |> Stream.each(fn _ ->
                     TamanduaServerWeb.Plugs.AdaptiveRateLimiter.cleanup()
                   end)
                   |> Stream.run()
                 end
               ]},
            restart: :permanent
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
          TamanduaServer.Alerts.AlertBroadcastRelay,

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

          # PERIPHERAL GROUP: Solana attestation (Client, RelayBatch,
          # FleetHealthAttestation) — isolated restart budget, same position/order
          TamanduaServer.Supervisors.BlockchainSupervisor,

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

          # PERIPHERAL GROUP: MISP sync + IOC scoring (MISP, MISPPublisher,
          # IOCScoring) — isolated restart budget, same position/order
          TamanduaServer.Supervisors.ThreatIntelSyncSupervisor,

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

          # PERIPHERAL GROUP: Kubernetes admission + serverless monitoring
          # (AdmissionController, AdmissionWebhook, KubernetesEnricher,
          # Serverless.*) — isolated restart budget, same position/order.
          # ContainerSecurity + EscapeDetector stay core above (alert-critical).
          TamanduaServer.Supervisors.CloudWorkloadSupervisor,

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

          # PERIPHERAL GROUP: SigmaHQ community rule sync (GitHub poller) —
          # isolated restart budget, same position. SigmaAggregator stays core.
          TamanduaServer.Supervisors.RuleSyncSupervisor,

          # Start the DNS Analyzer (must start before Detection Engine)
          TamanduaServer.Detection.DNSAnalyzer,

          # Start the C2 Detector (encrypted traffic pattern analysis)
          TamanduaServer.Detection.C2Detector,

          # Start NDR (Network Detection and Response) modules
          TamanduaServer.NDR.FlowAnalyzer,
          TamanduaServer.NDR.ProtocolAnalyzer,
          TamanduaServer.NDR.LateralDetector,
          TamanduaServer.NDR.EncryptedTraffic,

          # PERIPHERAL GROUP: network discovery + attack surface management
          # (NetworkDiscovery.*, ASM.*) — isolated restart budget, same
          # position/order (DeviceInventory first, then rogue/vuln scanners).
          TamanduaServer.Supervisors.NetworkDiscoverySupervisor,

          # PERIPHERAL GROUP: external threat-intel feeds, aggregation,
          # attribution, and third-party enrichment (ThreatIntelFeeds,
          # Feeds.*, Aggregator, Attribution, CampaignTracker,
          # RetroactiveScanner, Graph, TaxiiPoller, commercial + OSS feeds,
          # VirusTotal/AlienVault/Shodan/UnifiedEnrichment) — the highest-risk
          # flapper group; isolated restart budget, same position/order.
          TamanduaServer.Supervisors.ThreatIntelFeedsSupervisor,

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

          # PERIPHERAL GROUP: knowledge graph + AI security monitoring
          # (Graph.*, AISecurity.*) — isolated restart budget, same
          # position/order. Ingestor guards its AISecurity calls with
          # Process.whereis/1 so ingest degrades gracefully.
          TamanduaServer.Supervisors.AISecuritySupervisor,

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

          # PERIPHERAL GROUP: hyperautomation + Agentic SOAR (Hyperautomation,
          # Agentic.*) — isolated restart budget, same position/order.
          # Deterministic Response.* stack stays core above.
          TamanduaServer.Supervisors.AgenticSoarSupervisor,

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

          # PERIPHERAL GROUP: external model registry connectors (RegistrySync,
          # Registries.HealthCheck, OllamaWatcher) — isolated restart budget,
          # same position/order; child args live in the group module.
          TamanduaServer.Supervisors.ModelRegistrySupervisor,

          # Start the ML Client
          TamanduaServer.Detection.ML.Client,

          # ML Model Lifecycle Management
          # ModelManager: ETS-backed model registry, canary deployment, performance tracking
          TamanduaServer.ML.ModelManager,
          # AnalystFeedback: verdict collection, FP/TP rate tracking, retraining triggers
          TamanduaServer.ML.AnalystFeedback,
          # TrainingScheduler: scheduled/on-demand retraining, job tracking
          TamanduaServer.ML.TrainingScheduler,

          # PERIPHERAL GROUP: third-party integrations (MCPServer,
          # CollaborationSecurity, AISIEM, SIEM, IntegrationLog,
          # Ticketing/Chat routers, Slack/Teams bots, SOAR.Executor, Router,
          # Webhook.InboundRouter) — isolated restart budget, same
          # position/order. Notification Throttler/EscalationManager stay
          # core below (alert notification rate limiting / SLA escalation).
          TamanduaServer.Supervisors.IntegrationsSupervisor,

          # Notification Throttler (ETS-backed rate limiting for notifications)
          TamanduaServer.Notifications.Throttler,

          # Notification Center Escalation Manager (auto-escalation, SLA tracking)
          TamanduaServer.NotificationCenter.EscalationManager,

          # Device Control & USB Policy Management
          TamanduaServer.DeviceControl,

          # PERIPHERAL GROUP: DLP + compliance reporting (DLP.PolicyEngine,
          # DLP.IncidentManager, Compliance) — isolated restart budget,
          # same position/order. DeviceControl stays core above.
          TamanduaServer.Supervisors.DataGovernanceSupervisor,

          # PERIPHERAL GROUP: identity protection + UEBA (Identity.*,
          # Detection.BaselineLearner) — isolated restart budget, same
          # position/order. AzureAD is an external cloud connector.
          TamanduaServer.Supervisors.IdentitySupervisor,

          # PERIPHERAL GROUP: vulnerability intelligence + patching + breach
          # monitoring (Vulnerability.NVD/EPSS/KEV, PatchManagement.Engine,
          # DarkWebMonitor, CredentialHygiene) — external feed pollers;
          # isolated restart budget, same position/order.
          TamanduaServer.Supervisors.VulnerabilityManagementSupervisor,

          # PERIPHERAL GROUP: MDR service delivery (Delivery, AnalystConsole,
          # Metrics) — isolated restart budget, same position/order.
          TamanduaServer.Supervisors.MDRSupervisor,

          # PERIPHERAL GROUP: XDR (Correlator, Ingestor, PartitionedStore,
          # FederatedSearch) — third-party source ingest, separate from the
          # core agent telemetry pipeline; isolated restart budget, same
          # position/order.
          TamanduaServer.Supervisors.XDRSupervisor,

          # PERIPHERAL GROUP: deception technology (Breadcrumbs, Analytics) —
          # isolated restart budget, same position/order.
          TamanduaServer.Supervisors.DeceptionSupervisor,

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

          # PERIPHERAL GROUP: SLO tracking + FP analysis/tuning (SLO.*,
          # FPAnalysis.*) — isolated restart budget, same position/order.
          # MitreCoverage stays core above (detection domain).
          TamanduaServer.Supervisors.ObservabilitySupervisor

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

    # Top-level budget applies to CORE children. Peripheral domains run under
    # TamanduaServer.Supervisors.* group supervisors with their own smaller
    # budgets (10/60s); a group that exhausts its budget and dies costs ONE
    # top-level restart here instead of taking the whole application down.
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
      TamanduaServer.Alerts.AlertBroadcastRelay,
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
      # Keep the lightweight cache available for ML prediction caching and
      # dashboard/lifecycle services without booting the full cache stack.
      TamanduaServer.Cache,
      # Lightweight IOC cache for lab/demo alert enrichment. External feed
      # syncing remains outside lab-light; this gives the ingestor local IOC
      # lookups without booting the full threat-intel stack.
      TamanduaServer.ThreatIntel,
      # Expose DNS/threat-intel feed catalog health in lab-light without
      # automatically pulling large external feeds. Operators can opt in to
      # live feed sync with TAMANDUA_LAB_LIGHT_THREAT_INTEL_FEEDS=true.
      {TamanduaServer.Detection.ThreatIntelFeeds,
       [enabled: lab_light_threat_intel_feeds_enabled?()]},
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
      # DNSAnalyzer is lightweight ETS state plus persisted blocklist access.
      # Keep it available in lab-light so DNS blocklist management and NDR DNS
      # correlation do not degrade to controller fallbacks.
      TamanduaServer.Detection.DNSAnalyzer,
      # NDR live views are in-memory GenServers. Keep them in lab-light so
      # /api/v1/ndr/* has live data without requiring the full detection stack.
      # Telemetry.Ingestor feeds these directly when Detection.Engine is absent.
      TamanduaServer.NDR.FlowAnalyzer,
      TamanduaServer.NDR.ProtocolAnalyzer,
      TamanduaServer.NDR.LateralDetector,
      TamanduaServer.NDR.EncryptedTraffic,
      TamanduaServer.AI.ConversationStore,
      # AI/Hunting surfaces are visible in lab-light; start their local
      # GenServers so pages degrade with real state instead of empty/500 data.
      TamanduaServer.Detection.ML.Client,
      TamanduaServer.ML.ModelManager,
      TamanduaServer.ML.AnalystFeedback,
      TamanduaServer.ML.TrainingScheduler,
      TamanduaServer.AISecurity.MCPGovernance,
      TamanduaServer.Integrations.MCPServer,
      TamanduaServer.Automation.Hyperautomation,
      TamanduaServer.Hunting.NLHunter,
      TamanduaServer.Detection.Behavioral,
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

  defp lab_light_threat_intel_feeds_enabled? do
    System.get_env("TAMANDUA_LAB_LIGHT_THREAT_INTEL_FEEDS", "false") == "true"
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
      # Production with LAB_LIGHT is FATAL on public hosts. The lightweight lab
      # image runs with MIX_ENV=prod for asset/build parity, so allow it only on
      # private lab hosts or with an explicit operator override.
      lab_light_enabled and env == :prod and lab_light_prod_allowed?() ->
        require Logger

        Logger.warning("""
        [SECURITY] LAB_LIGHT mode enabled with MIX_ENV=prod on a private/acknowledged lab host.
        Do not expose this runtime to untrusted networks.
        """)

        :ok

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

  defp lab_light_prod_allowed? do
    System.get_env("TAMANDUA_ALLOW_PROD_LAB_LIGHT", "false") == "true" or
      private_lab_host?(System.get_env("PHX_HOST", ""))
  end

  defp private_lab_host?(host) do
    host in ["localhost", "127.0.0.1", "::1"] or
      String.starts_with?(host, "10.") or
      String.starts_with?(host, "192.168.") or
      private_172_host?(host)
  end

  defp private_172_host?(host) do
    case String.split(host, ".") do
      ["172", second | _] ->
        case Integer.parse(second) do
          {octet, ""} -> octet >= 16 and octet <= 31
          _ -> false
        end

      _ ->
        false
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
