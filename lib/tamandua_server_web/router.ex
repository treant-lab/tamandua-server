defmodule TamanduaServerWeb.Router do
  use TamanduaServerWeb, :router

  import TamanduaServerWeb.UserAuth

  Code.ensure_compiled!(TamanduaServerWeb.Plugs.SecurityHeaders)
  Code.ensure_compiled!(TamanduaServerWeb.Plugs.RateLimiter)
  Code.ensure_compiled!(TamanduaServerWeb.Plugs.AdaptiveRateLimiter)
  Code.ensure_compiled!(TamanduaServerWeb.Plugs.APIAuth)
  Code.ensure_compiled!(TamanduaServerWeb.Plugs.APICSRFProtection)
  Code.ensure_compiled!(TamanduaServerWeb.Plugs.CSRFCookie)
  Code.ensure_compiled!(TamanduaServerWeb.Plugs.InertiaSharedData)
  Code.ensure_compiled!(TamanduaServerWeb.Plugs.RequireTenantContext)
  Code.ensure_compiled!(TamanduaServerWeb.Plugs.SetOrganizationContext)
  Code.ensure_compiled!(TamanduaServerWeb.Plugs.TenantRateLimiter)
  Code.ensure_compiled!(TamanduaServerWeb.Plugs.TenantScope)
  Code.ensure_compiled!(TamanduaServerWeb.Plugs.TenantSuspension)

  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:fetch_session)
    plug(:fetch_live_flash)
    plug(:put_root_layout, html: {TamanduaServerWeb.Layouts, :root})
    plug(:protect_from_forgery)
    plug(:put_secure_browser_headers)
    plug(TamanduaServerWeb.Plugs.SecurityHeaders)
    plug(:fetch_current_user)
  end

  # Inertia.js pipeline for React frontend
  pipeline :inertia do
    plug(:accepts, ["html"])
    plug(:fetch_session)
    plug(:fetch_flash)
    plug(:put_root_layout, html: {TamanduaServerWeb.Layouts, :inertia_root})
    # Disable inner layout - Inertia uses React for layout
    plug(:put_layout, false)
    plug(:protect_from_forgery)
    plug(:put_secure_browser_headers)
    plug(TamanduaServerWeb.Plugs.SecurityHeaders)
    plug(TamanduaServerWeb.Plugs.CSRFCookie)
    plug(:fetch_current_user)
    plug(TamanduaServerWeb.Plugs.InertiaSharedData)
    plug(Inertia.Plug)
  end

  # SSO pipeline: like :browser but without CSRF protection.
  # SAML ACS receives HTTP-POST from external IdPs which cannot include a CSRF token.
  pipeline :sso do
    plug(:accepts, ["html"])
    plug(:fetch_session)
    plug(:fetch_live_flash)
    plug(:put_root_layout, html: {TamanduaServerWeb.Layouts, :root})
    plug(:put_secure_browser_headers)
    plug(TamanduaServerWeb.Plugs.SecurityHeaders)
    plug(:fetch_current_user)
  end

  # Public pages pipeline - no sidebar, minimal layout
  # Used for public audit pages like /public/attestations
  pipeline :public_browser do
    plug(:accepts, ["html"])
    plug(:fetch_session)
    plug(:fetch_live_flash)
    plug(:put_root_layout, html: {TamanduaServerWeb.Layouts, :root})
    plug(:put_layout, html: {TamanduaServerWeb.Layouts, :public})
    plug(:protect_from_forgery)
    plug(:put_secure_browser_headers)
    plug(TamanduaServerWeb.Plugs.SecurityHeaders)
  end

  pipeline :api do
    plug(:accepts, ["json"])
    # Enable session-based auth for internal frontend
    plug(:fetch_session)
    plug(TamanduaServerWeb.Plugs.RateLimiter)
    plug(TamanduaServerWeb.Plugs.AdaptiveRateLimiter)
  end

  # Pipeline for webhook endpoints that need raw body for signature verification
  pipeline :fetch_raw_body do
    plug(:capture_raw_body)
  end

  # Capture raw body for webhook signature verification
  # Returns 400 Bad Request for invalid JSON instead of crashing with 500
  defp capture_raw_body(conn, _opts) do
    {:ok, body, conn} = Plug.Conn.read_body(conn)

    case Jason.decode(body) do
      {:ok, decoded} ->
        conn
        |> assign(:raw_body, body)
        |> Map.put(:body_params, decoded)

      {:error, _reason} ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(400, Jason.encode!(%{error: "Invalid JSON in request body"}))
        |> halt()
    end
  end

  pipeline :api_auth do
    plug(TamanduaServerWeb.Plugs.APIAuth)
    # CSRF protection for session-authenticated API requests
    # Bearer token requests skip this check; session-based requests require valid CSRF token
    plug(TamanduaServerWeb.Plugs.APICSRFProtection)
    plug(TamanduaServerWeb.Plugs.SetOrganizationContext)

    plug(TamanduaServerWeb.Plugs.RequireTenantContext,
      except: [
        "/api/v1/health",
        "/api/v1/auth/login",
        "/api/v1/auth/register",
        "/api/v1/auth/refresh",
        "/socket/agent"
      ]
    )

    plug(TamanduaServerWeb.Plugs.TenantSuspension,
      except: [
        "/api/v1/health",
        "/api/v1/auth"
      ]
    )
  end

  # Tenant-scoped API pipeline (adds organization context and per-tenant rate limiting)
  pipeline :api_tenant do
    plug(TamanduaServerWeb.Plugs.TenantScope, preload_org: true, require_active: true)
    plug(TamanduaServerWeb.Plugs.TenantRateLimiter, limit_type: :minute)
  end

  # GraphQL API pipeline
  pipeline :graphql_context do
    plug(TamanduaServerWeb.GraphQL.Context)
  end

  # Public routes
  scope "/", TamanduaServerWeb do
    pipe_through(:browser)

    get("/", PageController, :home)
    get("/login", SessionController, :new)
    post("/login", SessionController, :create)
    get("/register", SessionController, :register)
    post("/register", SessionController, :create_register)
    post("/wallet/challenge", SessionController, :wallet_challenge)
    post("/wallet/login", SessionController, :wallet_login)
    get("/logout", SessionController, :delete)
    delete("/logout", SessionController, :delete)
  end

  # Public Attestation Audit Pages (no authentication required)
  # These pages show only privacy-safe blockchain attestation data
  # Uses :public_browser pipeline with minimal layout (no sidebar)
  scope "/public", TamanduaServerWeb do
    pipe_through(:public_browser)

    # Security Oracle - Main public proofs demo page
    live("/proofs", PublicProofsLive, :index)

    # Attestation list and detail pages
    live("/attestations", PublicAttestationsLive, :index)
    live("/attestations/:tx_id", PublicAttestationDetailLive, :show)
  end

  # Public agent binaries. Enrollment is still protected by short-lived tokens;
  # this route only exposes allowlisted installer artifacts.
  scope "/", TamanduaServerWeb do
    get("/downloads/agents/:filename", AgentDownloadController, :show)
    get("/downloads/gui/:filename", GuiDownloadController, :show)
  end

  # Compatibility redirects for in-app documentation links. The deployment
  # guide is currently implemented as the authenticated React deploy page.
  scope "/", TamanduaServerWeb do
    pipe_through(:browser)

    get("/docs/agent-deployment", RedirectController, :to_agent_deployment_docs)
    get("/docs/agent-deployment/:platform", RedirectController, :to_agent_deployment_docs)
    get("/docs/deployment", RedirectController, :to_agent_deployment_docs)
  end

  # SSO authentication routes (public - no auth required)
  # Uses :sso pipeline (no CSRF) because SAML ACS receives POST from external IdPs
  scope "/auth/sso", TamanduaServerWeb.Auth do
    pipe_through([:sso])

    # SAML 2.0 endpoints
    get("/saml/metadata/:provider_id", SSOController, :saml_metadata)
    get("/saml/login/:provider_id", SSOController, :saml_login)
    post("/saml/acs/:provider_id", SSOController, :saml_acs)
    get("/saml/slo/:provider_id", SSOController, :saml_slo)

    # OAuth 2.0 / OIDC endpoints
    get("/oauth/authorize/:provider_id", SSOController, :oauth_authorize)
    get("/oauth/callback/:provider_id", SSOController, :oauth_callback)
  end

  # Redirects from old LiveView routes to React UI
  scope "/", TamanduaServerWeb do
    pipe_through([:browser, :require_authenticated_user])

    get("/dashboard", RedirectController, :to_app_dashboard)
    get("/agents", RedirectController, :to_app_agents)
    get("/alerts", RedirectController, :to_app_alerts)
    get("/events", RedirectController, :to_app_events)
    get("/hunting", RedirectController, :to_app_hunt)
    get("/mitre", RedirectController, :to_app_mitre)
    get("/settings", RedirectController, :to_app_settings)
  end

  # API v1 routes
  scope "/api/v1", TamanduaServerWeb.API.V1, as: :api_v1_public do
    pipe_through(:api)

    post("/auth/login", MobileAuthController, :login)
    post("/cli-auth/device", CLIAuthController, :device)
    post("/cli-auth/token", CLIAuthController, :token)
  end

  scope "/", TamanduaServerWeb do
    pipe_through([:browser, :require_authenticated_user])

    get("/cli/auth", CLIAuthController, :show)
    post("/cli/auth/approve", CLIAuthController, :approve)
  end

  scope "/api/v1", TamanduaServerWeb.API.V1, as: :api_v1 do
    pipe_through([:api, :api_auth])

    post("/auth/logout", MobileAuthController, :logout)
    post("/auth/refresh", MobileAuthController, :refresh)

    # Batch Operations - keep specific /batch routes before dynamic resource ids.
    post("/alerts/batch/close", BatchController, :close_alerts)
    post("/alerts/batch/assign", BatchController, :assign_alerts)
    post("/alerts/batch/tag", BatchController, :tag_alerts)
    post("/alerts/batch/delete", BatchController, :delete_alerts)
    post("/iocs/batch/import", BatchController, :import_iocs)
    post("/iocs/batch/delete", BatchController, :delete_iocs)
    post("/iocs/batch/update", BatchController, :update_iocs)
    post("/agents/batch/isolate", BatchController, :isolate_agents)
    post("/agents/batch/scan", BatchController, :scan_agents)
    post("/agents/batch/collect-forensics", BatchController, :collect_forensics)
    get("/jobs/:id", BatchController, :get_job)

    # Agents
    get("/agents/data-sources/health", AgentController, :data_sources_health)
    resources("/agents", AgentController, only: [:index, :show, :update, :delete])
    post("/agents/:id/isolate", AgentController, :isolate)
    post("/agents/:id/unisolate", AgentController, :unisolate)
    get("/agents/:id/isolation", AgentController, :isolation_status)
    post("/agents/:id/restart", AgentController, :restart_agent)
    put("/agents/:id/config", AgentController, :update_config)
    get("/agents/:id/events", AgentController, :events)
    get("/agents/:id/processes", AgentController, :processes)
    get("/agents/:id/processes/:pid/children", AgentController, :process_children)
    get("/agents/:id/processes/:pid/ancestors", AgentController, :process_ancestors)

    # Baseline Learning
    get("/agents/:id/baseline/status", BaselineController, :status)
    post("/agents/:id/baseline/start", BaselineController, :start)
    post("/agents/:id/baseline/end", BaselineController, :end_learning)
    get("/agents/:id/baseline/patterns", BaselineController, :patterns)
    post("/agents/:id/baseline/score", BaselineController, :score)

    # Alerts
    get("/alerts/summary", AlertController, :summary)
    get("/alerts/trend", AlertController, :trend)
    post("/alerts/:id/assign", AlertController, :assign)
    post("/alerts/:id/resolve", AlertController, :resolve)
    post("/alerts/:id/false_positive", AlertController, :false_positive)
    patch("/alerts/:id/status", AlertController, :update_status)
    get("/alerts/:id/history", AlertController, :history)
    get("/alerts/:id/related", AlertController, :related)
    post("/alerts/:id/create-exclusion", AlertController, :create_exclusion_from_alert)

    # Analyst Verdict / Feedback Loop
    post("/alerts/:id/verdict", AlertController, :set_verdict)
    get("/alerts/:id/feedback-log", AlertController, :feedback_log)

    # Solana Attestation (Proof of Incident)
    post("/alerts/:id/attest", AlertController, :attest)
    get("/alerts/:id/attestation", AlertController, :get_attestation)
    get("/incidents/:id", AlertController, :incident)

    # Alert Bulk Operations
    post("/alerts/bulk", AlertController, :bulk_update)
    post("/alerts/bulk/add-to-investigation", AlertController, :bulk_add_to_investigation)
    post("/alerts/bulk_verdict", AlertController, :bulk_verdict)
    post("/alerts/search", AlertController, :search)
    post("/alerts/export", AlertController, :export)
    get("/alerts/stats", AlertController, :stats)
    get("/alerts/verdict-stats", AlertController, :verdict_stats)
    get("/alerts/assignable-users", AlertController, :assignable_users)
    get("/alerts/filter-presets", AlertController, :list_filter_presets)
    post("/alerts/filter-presets", AlertController, :save_filter_preset)

    # Alert Exclusion Rules
    get("/alerts/exclusions", AlertController, :list_exclusions)
    get("/alerts/exclusions/stats", AlertController, :exclusion_stats)
    post("/alerts/exclusions", AlertController, :create_exclusion)
    put("/alerts/exclusions/:id", AlertController, :update_exclusion)
    delete("/alerts/exclusions/:id", AlertController, :delete_exclusion)
    post("/alerts/exclusions/:id/toggle", AlertController, :toggle_exclusion)

    # Alert Suppression Rules (verdict-based)
    get("/alerts/suppression-rules", AlertController, :list_suppression_rules)
    post("/alerts/suppression-rules", AlertController, :create_suppression_rule)
    put("/alerts/suppression-rules/:id", AlertController, :update_suppression_rule)
    delete("/alerts/suppression-rules/:id", AlertController, :delete_suppression_rule)
    post("/alerts/suppression-rules/:id/toggle", AlertController, :toggle_suppression_rule)
    get("/alerts/suppression-stats", AlertController, :suppression_stats)
    resources("/alerts", AlertController, only: [:index, :show, :update])

    # False Positive Analysis & Tuning
    post("/fp-analysis/reports", FPAnalysisController, :create_report)
    get("/fp-analysis/alerts/:alert_id/reports", FPAnalysisController, :list_alert_reports)
    get("/fp-analysis/reports/pending", FPAnalysisController, :list_pending_reports)
    post("/fp-analysis/reports/:id/review", FPAnalysisController, :review_report)
    get("/fp-analysis/stats", FPAnalysisController, :stats)
    get("/fp-analysis/summary", FPAnalysisController, :summary)
    get("/fp-analysis/insights", FPAnalysisController, :insights)
    get("/fp-analysis/top-fp-rules", FPAnalysisController, :top_fp_rules)

    get(
      "/fp-analysis/rules/:detection_source/:rule_id/quality",
      FPAnalysisController,
      :rule_quality
    )

    get("/fp-analysis/rules/quality-dashboard", FPAnalysisController, :quality_dashboard)
    get("/fp-analysis/rules/quality-trend", FPAnalysisController, :quality_trend)
    get("/fp-analysis/rules/compare-sources", FPAnalysisController, :compare_sources)
    get("/fp-analysis/patterns", FPAnalysisController, :list_patterns)
    get("/fp-analysis/patterns/tunable", FPAnalysisController, :tunable_patterns)
    post("/fp-analysis/patterns/:id/confirm", FPAnalysisController, :confirm_pattern)
    post("/fp-analysis/patterns/:id/reject", FPAnalysisController, :reject_pattern)
    post("/fp-analysis/patterns/analyze", FPAnalysisController, :analyze_patterns)
    get("/fp-analysis/recommendations", FPAnalysisController, :list_recommendations)
    post("/fp-analysis/recommendations/:id/apply", FPAnalysisController, :apply_recommendation)
    get("/fp-analysis/tuning/stats", FPAnalysisController, :tuning_stats)
    post("/fp-analysis/tuning/evaluate", FPAnalysisController, :evaluate_organization)
    get("/fp-analysis/baselines/:profile_type/:profile_key", FPAnalysisController, :get_baseline)
    post("/fp-analysis/baselines", FPAnalysisController, :start_baseline)
    get("/fp-analysis/baselines/stats", FPAnalysisController, :baseline_stats)

    # Events
    resources("/events", EventController, only: [:index, :show])
    get("/events/:id/related", EventController, :related)
    post("/events/search", EventController, :search)
    delete("/events/purge", EventController, :purge)

    # Real-time Streaming (SSE)
    get("/stream/alerts", StreamController, :stream_alerts)
    get("/stream/events", StreamController, :stream_events)
    get("/stream/detections", StreamController, :stream_detections)

    # Long-polling (backward compatibility)
    get("/poll/alerts", PollController, :poll_alerts)
    get("/poll/events", PollController, :poll_events)

    # Case Investigations
    get("/case-investigations/stats", CaseInvestigationController, :stats)
    resources("/case-investigations", CaseInvestigationController, except: [:new, :edit])
    post("/case-investigations/:id/notes", CaseInvestigationController, :add_note)
    post("/case-investigations/:id/alerts", CaseInvestigationController, :add_alert)

    delete(
      "/case-investigations/:id/alerts/:alert_id",
      CaseInvestigationController,
      :remove_alert
    )

    patch("/case-investigations/:id/status", CaseInvestigationController, :update_status)
    post("/case-investigations/:id/assign", CaseInvestigationController, :assign)

    # Geo / Threat Map
    get("/geo/threats", GeoController, :threat_origins)
    get("/geo/agents", GeoController, :agent_locations)
    get("/geo/flows", GeoController, :threat_flows)
    get("/geo/summary", GeoController, :summary)
    get("/geo/map", GeoController, :map_data)

    # DNS Analytics & Blocklist
    get("/dns/stats", DNSController, :stats)
    get("/dns/queries", DNSController, :queries)
    get("/dns/top-domains", DNSController, :top_domains)
    get("/dns/alerts", DNSController, :alerts)
    get("/dns/blocklist", DNSController, :blocklist_index)
    post("/dns/blocklist", DNSController, :blocklist_create)
    delete("/dns/blocklist/:domain", DNSController, :blocklist_delete)
    post("/dns/blocklist/import", DNSController, :blocklist_import)

    # Response Actions
    post("/response/kill", ResponseController, :kill_process)
    post("/response/quarantine", ResponseController, :quarantine_file)
    post("/response/collect", ResponseController, :collect_artifact)
    post("/response/scan", ResponseController, :scan_path)
    post("/response/block-ip", ResponseController, :block_ip)
    post("/response/unblock-ip", ResponseController, :unblock_ip)
    post("/response/block-domain", ResponseController, :block_domain)
    post("/response/unblock-domain", ResponseController, :unblock_domain)

    # VSS Snapshots & Ransomware Remediation
    post("/agents/:id/snapshots", ResponseController, :create_snapshot)
    get("/agents/:id/snapshots", ResponseController, :list_snapshots)
    delete("/agents/:id/snapshots/:snapshot_id", ResponseController, :delete_snapshot)
    post("/agents/:id/restore", ResponseController, :restore_files)
    get("/agents/:id/encrypted-files", ResponseController, :find_encrypted_files)
    post("/agents/:id/remediate", ResponseController, :ransomware_remediate)

    # Response Metrics & Timeline
    get("/response/metrics", ResponseController, :metrics)
    post("/response/rollback/:response_id", ResponseController, :rollback)

    # Rules
    resources("/rules/sigma", SigmaRuleController)
    get("/rules/yara/status", YaraRuleController, :status)
    post("/rules/yara/scan", YaraRuleController, :scan)
    post("/rules/yara/clear_cache", YaraRuleController, :clear_cache)
    resources("/rules/yara", YaraRuleController)

    # Auto-Generated YARA Rules (ML-driven)
    get("/rules/yara/generated/stats", YaraRuleController, :generated_stats)
    get("/rules/yara/generated", YaraRuleController, :list_generated)
    get("/rules/yara/generated/:id", YaraRuleController, :show_generated)
    post("/rules/yara/generated/:id/promote", YaraRuleController, :promote_generated)
    post("/rules/yara/generated/:id/reject", YaraRuleController, :reject_generated)
    post("/rules/yara/generated/cleanup", YaraRuleController, :cleanup_generated)

    # IOCs
    resources("/iocs", IOCController)
    post("/iocs/bulk", IOCController, :bulk_create)

    # Detection Packs
    get("/detection-packs", DetectionPacksController, :index)
    get("/detection-packs/installed", DetectionPacksController, :installed)
    get("/detection-packs/stats", DetectionPacksController, :stats)
    get("/detection-packs/:id", DetectionPacksController, :show)
    post("/detection-packs/:id/install", DetectionPacksController, :install)
    delete("/detection-packs/:id/install", DetectionPacksController, :uninstall)
    patch("/detection-packs/:id/install", DetectionPacksController, :toggle)

    # Contributor Reputation (Bounty Anti-Fraud)
    get("/contributors/leaderboard", ContributorReputationController, :leaderboard)
    get("/contributors/:wallet", ContributorReputationController, :show)
    get("/contributors/:wallet/high-value", ContributorReputationController, :can_high_value)
    post("/contributors/:wallet/recalculate", ContributorReputationController, :recalculate)
    post("/contributors/:wallet/restrict", ContributorReputationController, :restrict)
    post("/contributors/:wallet/unrestrict", ContributorReputationController, :unrestrict)

    # Prevention Policies
    resources("/prevention-policies", PreventionPolicyController, except: [:new, :edit])
    post("/prevention-policies/:id/assign-agents", PreventionPolicyController, :assign_agents)
    post("/prevention-policies/:id/unassign-agents", PreventionPolicyController, :unassign_agents)
    get("/prevention-policies/agent/:agent_id", PreventionPolicyController, :agent_policy)

    get(
      "/prevention-policies/agent/:agent_id/ml-settings",
      PreventionPolicyController,
      :ml_settings
    )

    # Remediation Policies
    scope "/remediation" do
      resources("/policies", RemediationPolicyController, except: [:new, :edit])
      post("/policies/evaluate", RemediationPolicyController, :evaluate)
    end

    # Notification Templates
    resources("/notification_templates", NotificationTemplateController, except: [:new, :edit])

    # Response Action Audit Trail
    get("/response-audit", ResponseAuditController, :index)
    get("/response-audit/agent/:agent_id", ResponseAuditController, :agent_actions)
    get("/response-audit/alert/:alert_id", ResponseAuditController, :alert_actions)
    get("/response-audit/counts", ResponseAuditController, :counts)
    get("/response-audit/search", ResponseAuditController, :search)

    # Autonomous Response
    get("/autonomous/dashboard", AutonomousResponseController, :dashboard)
    get("/autonomous/settings", AutonomousResponseController, :settings)
    put("/autonomous/settings", AutonomousResponseController, :update_settings)
    post("/autonomous/emergency-disable", AutonomousResponseController, :emergency_disable)
    post("/autonomous/emergency-enable", AutonomousResponseController, :emergency_enable)

    # Autonomous Recommendations
    get("/autonomous/recommendations", AutonomousResponseController, :list_recommendations)

    post(
      "/autonomous/recommendations/:id/approve",
      AutonomousResponseController,
      :approve_recommendation
    )

    post(
      "/autonomous/recommendations/:id/reject",
      AutonomousResponseController,
      :reject_recommendation
    )

    get("/autonomous/history", AutonomousResponseController, :action_history)
    post("/autonomous/evaluate", AutonomousResponseController, :evaluate_alert)

    # Autonomous Rules
    get("/autonomous/rules/templates", AutonomousResponseController, :rule_templates)
    get("/autonomous/rules/schema", AutonomousResponseController, :rule_schema)
    post("/autonomous/rules/clone-template", AutonomousResponseController, :clone_template)
    get("/autonomous/rules", AutonomousResponseController, :list_rules)
    get("/autonomous/rules/:id", AutonomousResponseController, :show_rule)
    post("/autonomous/rules", AutonomousResponseController, :create_rule)
    put("/autonomous/rules/:id", AutonomousResponseController, :update_rule)
    delete("/autonomous/rules/:id", AutonomousResponseController, :delete_rule)
    post("/autonomous/rules/:id/toggle", AutonomousResponseController, :toggle_rule)
    post("/autonomous/rules/:id/test", AutonomousResponseController, :test_rule)

    # Analyst Learning
    get("/autonomous/learning/stats", AutonomousResponseController, :learning_stats)
    get("/autonomous/learning/patterns", AutonomousResponseController, :learned_patterns)
    get("/autonomous/learning/history", AutonomousResponseController, :decision_history)
    get("/autonomous/learning/analysts/:id", AutonomousResponseController, :analyst_profile)
    post("/autonomous/learning/retrain", AutonomousResponseController, :retrain_model)
    post("/autonomous/learning/feedback", AutonomousResponseController, :provide_feedback)

    # Asset Criticality
    get("/autonomous/assets", AutonomousResponseController, :list_assets)
    get("/autonomous/assets/critical", AutonomousResponseController, :critical_assets)

    get(
      "/autonomous/assets/distribution",
      AutonomousResponseController,
      :criticality_distribution
    )

    post("/autonomous/assets/import", AutonomousResponseController, :import_criticality)

    get(
      "/autonomous/assets/:agent_id/criticality",
      AutonomousResponseController,
      :get_asset_criticality
    )

    put(
      "/autonomous/assets/:agent_id/criticality",
      AutonomousResponseController,
      :set_asset_criticality
    )

    delete(
      "/autonomous/assets/:agent_id/criticality",
      AutonomousResponseController,
      :clear_asset_criticality
    )

    post(
      "/autonomous/assets/:agent_id/refresh",
      AutonomousResponseController,
      :refresh_criticality
    )

    # Autonomous Response ML Engine
    get("/autonomous-response/stats", AutonomousResponseController, :engine_stats)
    get("/autonomous-response/decisions", AutonomousResponseController, :engine_decisions)
    post("/autonomous-response/assess", AutonomousResponseController, :engine_assess)
    post("/autonomous-response/feedback", AutonomousResponseController, :engine_feedback)
    get("/autonomous-response/thresholds", AutonomousResponseController, :engine_get_thresholds)

    put(
      "/autonomous-response/thresholds",
      AutonomousResponseController,
      :engine_update_thresholds
    )

    get(
      "/autonomous-response/asset-criticality/:agent_id",
      AutonomousResponseController,
      :engine_get_criticality
    )

    put(
      "/autonomous-response/asset-criticality/:agent_id",
      AutonomousResponseController,
      :engine_set_criticality
    )

    post("/autonomous-response/simulate", AutonomousResponseController, :engine_simulate)

    # MITRE ATT&CK Coverage
    get("/mitre/coverage", MitreController, :coverage)
    get("/mitre/tactics", MitreController, :tactics)
    get("/mitre/technique/:id", MitreController, :technique_detail)
    get("/mitre/heatmap", MitreController, :heatmap)
    get("/mitre/trends", MitreController, :trends)
    get("/mitre/gaps", MitreController, :gaps)
    get("/mitre/navigator", MitreController, :navigator)

    # Threat Intelligence
    get("/threat-intel/attackers", ThreatIntelController, :top_attackers)
    get("/threat-intel/status", ThreatIntelController, :feed_status)
    get("/threat-intel/feed-status", ThreatIntelController, :per_feed_status)
    post("/threat-intel/sync", ThreatIntelController, :sync_all)
    post("/threat-intel/sync/:feed_name", ThreatIntelController, :sync_feed)
    post("/threat-intel/configure", ThreatIntelController, :configure_api_key)
    get("/threat-intel/feeds", ThreatIntelController, :list_custom_feeds)
    post("/threat-intel/feeds", ThreatIntelController, :add_custom_feed)
    get("/threat-intel/actors", ThreatIntelController, :list_actors)
    get("/threat-intel/actors/:id", ThreatIntelController, :show_actor)
    get("/threat-intel/campaigns", ThreatIntelController, :list_campaigns)
    get("/threat-intel/campaigns/:id", ThreatIntelController, :show_campaign)
    get("/threat-intel/sources", ThreatIntelController, :list_sources)
    get("/threat-intel/summary", ThreatIntelController, :summary)

    # Threat Intel Enrichment (real-time reputation lookups)
    post("/threat-intel/enrich/hash", ThreatIntelController, :enrich_hash)
    post("/threat-intel/enrich/domain", ThreatIntelController, :enrich_domain)
    post("/threat-intel/enrich/ip", ThreatIntelController, :enrich_ip)
    post("/threat-intel/enrich/url", ThreatIntelController, :enrich_url)
    post("/threat-intel/enrich/batch", ThreatIntelController, :enrich_batch)
    get("/threat-intel/enrich/status", ThreatIntelController, :enrich_status)

    # External Threat Intel Feeds (Abuse.ch integration)
    get("/threat-intel/lookup/:type/:value", ThreatIntelController, :lookup)
    get("/threat-intel/external/status", ThreatIntelController, :external_feeds_status)
    post("/threat-intel/external/refresh", ThreatIntelController, :refresh_external_feeds)
    post("/threat-intel/external/refresh/:feed", ThreatIntelController, :refresh_external_feed)
    get("/threat-intel/external/stats", ThreatIntelController, :external_feeds_stats)

    # MISP Integration - Instances
    get("/threat-intel/misp/instances", ThreatIntelController, :list_misp_instances)
    get("/threat-intel/misp/instances/:id", ThreatIntelController, :show_misp_instance)
    post("/threat-intel/misp/instances", ThreatIntelController, :create_misp_instance)
    put("/threat-intel/misp/instances/:id", ThreatIntelController, :update_misp_instance)
    delete("/threat-intel/misp/instances/:id", ThreatIntelController, :delete_misp_instance)
    post("/threat-intel/misp/instances/:id/test", ThreatIntelController, :test_misp_connection)
    post("/threat-intel/misp/instances/:id/sync", ThreatIntelController, :sync_misp_instance)
    get("/threat-intel/misp/sync-status", ThreatIntelController, :misp_sync_status)

    # MISP Integration - Events
    get("/threat-intel/misp/events", ThreatIntelController, :list_misp_events)
    get("/threat-intel/misp/events/:id", ThreatIntelController, :show_misp_event)

    # MISP Integration - Publishing (bidirectional sync)
    post("/threat-intel/misp/publish", ThreatIntelController, :publish_to_misp)
    post("/threat-intel/misp/publish/batch", ThreatIntelController, :batch_publish_to_misp)
    post("/threat-intel/misp/publish/iocs", ThreatIntelController, :publish_iocs_to_misp)
    post("/threat-intel/misp/publish/enqueue", ThreatIntelController, :enqueue_misp_publish)
    post("/threat-intel/misp/sighting", ThreatIntelController, :add_misp_sighting)

    get(
      "/threat-intel/misp/sharing-groups/:instance_id",
      ThreatIntelController,
      :list_sharing_groups
    )

    get("/threat-intel/misp/publisher/stats", ThreatIntelController, :misp_publisher_stats)
    post("/threat-intel/misp/publisher/flush", ThreatIntelController, :flush_misp_queue)

    # Threat Actors (Database-backed)
    get("/threat-intel/actors/db", ThreatIntelController, :list_db_actors)
    get("/threat-intel/actors/db/:id", ThreatIntelController, :show_db_actor)
    post("/threat-intel/actors/db", ThreatIntelController, :create_db_actor)
    put("/threat-intel/actors/db/:id", ThreatIntelController, :update_db_actor)
    get("/threat-intel/actors/stats", ThreatIntelController, :actor_stats)
    post("/threat-intel/actors/:id/attribute", ThreatIntelController, :attribute_to_actor)

    # IOC Scoring
    get("/threat-intel/ioc-scoring/config", ThreatIntelController, :ioc_scoring_config)
    post("/threat-intel/ioc-scoring/calculate", ThreatIntelController, :calculate_ioc_score)
    post("/threat-intel/ioc-scoring/sighting", ThreatIntelController, :record_ioc_sighting)
    post("/threat-intel/ioc-scoring/false-positive", ThreatIntelController, :record_ioc_fp)
    get("/threat-intel/ioc-scoring/stats", ThreatIntelController, :ioc_scoring_stats)
    get("/threat-intel/iocs/high-confidence", ThreatIntelController, :high_confidence_iocs)
    post("/threat-intel/ioc-scoring/recalculate", ThreatIntelController, :recalculate_all_scores)

    # Feed Aggregator (IOC deduplication, bloom filters, hot cache)
    get("/threat-intel/aggregator/stats", ThreatIntelController, :aggregator_stats)
    get("/threat-intel/aggregator/health", ThreatIntelController, :aggregator_health)
    get("/threat-intel/aggregator/multi-source", ThreatIntelController, :multi_source_iocs)
    post("/threat-intel/aggregator/lookup", ThreatIntelController, :fast_lookup)

    # Threat Attribution Engine (IOC-to-actor correlation, campaigns)
    post("/threat-intel/attribution/alert", ThreatIntelController, :attribute_alert)
    get("/threat-intel/attribution/campaigns", ThreatIntelController, :list_attribution_campaigns)

    get(
      "/threat-intel/attribution/campaigns/:id",
      ThreatIntelController,
      :get_attribution_campaign
    )

    post(
      "/threat-intel/attribution/campaigns",
      ThreatIntelController,
      :upsert_attribution_campaign
    )

    get("/threat-intel/attribution/actors/:id/profile", ThreatIntelController, :actor_profile)

    get(
      "/threat-intel/attribution/actors/by-ttp/:technique_id",
      ThreatIntelController,
      :actors_by_ttp
    )

    post("/threat-intel/attribution/correlate", ThreatIntelController, :correlate_iocs)
    get("/threat-intel/attribution/stats", ThreatIntelController, :attribution_stats)

    # Recent Attributions (alert-level attribution data)
    get("/threat-intel/attributions", ThreatIntelController, :list_attributions)

    # Campaign Tracker (auto-detected campaigns from alert clustering)
    get("/threat-intel/campaigns/tracked", ThreatIntelController, :list_tracked_campaigns)
    get("/threat-intel/campaigns/tracked/stats", ThreatIntelController, :tracked_campaign_stats)
    get("/threat-intel/campaigns/tracked/:id", ThreatIntelController, :get_tracked_campaign)

    # Full actor profile (enriched with campaign tracker and attribution data)
    get("/threat-intel/actors/:id/profile", ThreatIntelController, :full_actor_profile)

    # IOC Relationship Graph
    get("/threat-intel/graph/stats", ThreatIntelController, :graph_stats)
    get("/threat-intel/graph/paths", ThreatIntelController, :graph_paths)
    get("/threat-intel/graph/node/:ioc_value", ThreatIntelController, :graph_node)
    get("/threat-intel/graph/neighbors/:ioc_value", ThreatIntelController, :graph_neighbors)
    get("/threat-intel/graph/subgraph/:ioc_value", ThreatIntelController, :graph_subgraph)
    post("/threat-intel/graph/enrich", ThreatIntelController, :graph_enrich)

    # Commercial & Open Source Feed Status
    get("/threat-intel/feeds/commercial/status", ThreatIntelController, :commercial_feeds_status)
    get("/threat-intel/feeds/open/status", ThreatIntelController, :open_feeds_status)

    # Threat Hunting
    post("/hunting/search", HuntingController, :search)
    post("/hunting/query", HuntingController, :query)
    get("/hunting/schema", HuntingController, :schema)
    get("/hunting/templates", HuntingController, :templates)

    # TQL (Tamandua Query Language) -- Ecto/PostgreSQL backend
    post("/hunting/tql", HuntingController, :tql)
    post("/hunting/tql/validate", HuntingController, :validate_tql)
    post("/hunting/tql/explain", HuntingController, :explain_tql)
    get("/hunting/tql-schema", HuntingController, :tql_schema)

    # TQL/ClickHouse -- direct ClickHouse SQL compilation (v2)
    post("/hunting/query/clickhouse", HuntingController, :tql_clickhouse)
    post("/hunting/query/clickhouse/validate", HuntingController, :validate_tql_clickhouse)
    get("/hunting/query/clickhouse/schema", HuntingController, :tql_clickhouse_schema)

    # Saved Queries
    resources("/queries", SavedQueriesController,
      only: [:index, :show, :create, :update, :delete]
    )

    post("/queries/:id/use", SavedQueriesController, :record_use)
    get("/queries/search", SavedQueriesController, :search)
    get("/queries/templates", SavedQueriesController, :templates)
    get("/queries/popular", SavedQueriesController, :popular)
    get("/queries/history", SavedQueriesController, :history)
    post("/queries/history", SavedQueriesController, :record_history)

    # Stats & Reports
    get("/stats/overview", StatsController, :overview)
    get("/stats/agents", StatsController, :agents)
    get("/stats/alerts", StatsController, :alerts)
    get("/stats/detections", StatsController, :detections)
    get("/stats/attestations", StatsController, :attestations)

    # Reports
    get("/reports", ReportController, :index)
    post("/reports/generate", ReportController, :generate)
    post("/reports/generate-advanced", ReportController, :generate_advanced)
    get("/reports/history", ReportController, :history)
    get("/reports/templates", ReportController, :templates)
    get("/reports/:id", ReportController, :show)
    get("/reports/:id/download", ReportController, :download)

    # Scheduled Reports
    get("/reports/scheduled", ReportController, :list_scheduled)
    post("/reports/scheduled", ReportController, :create_schedule)
    get("/reports/scheduled/:id", ReportController, :show_schedule)
    put("/reports/scheduled/:id", ReportController, :update_schedule)
    delete("/reports/scheduled/:id", ReportController, :delete_schedule)
    post("/reports/scheduled/:id/run", ReportController, :run_schedule)
    post("/reports/scheduled/:id/pause", ReportController, :pause_schedule)
    post("/reports/scheduled/:id/resume", ReportController, :resume_schedule)
    get("/reports/scheduled/:id/history", ReportController, :schedule_history)

    # Audit Logs
    get("/audit/logs", AuditLogController, :index)
    get("/audit/stats", AuditLogController, :stats)

    # Settings
    post("/settings/general", SettingsController, :general)
    post("/settings/detection", SettingsController, :detection)
    post("/settings/notifications", SettingsController, :notifications)
    post("/settings/integrations", SettingsController, :integrations)
    post("/settings/system", SettingsController, :system)
    post("/settings/reload-rules", SettingsController, :reload_rules)
    post("/settings/clear-cache", SettingsController, :clear_cache)

    # Timeline / Attack Storyline
    get("/timeline", TimelineController, :index)
    get("/timeline/stats", TimelineController, :stats)
    get("/timeline/correlations", TimelineController, :correlations)
    get("/timeline/incident-candidates", TimelineController, :incident_candidates)
    post("/timeline/incident-candidates/:id/feedback", TimelineController, :candidate_feedback)
    get("/timeline/readiness", TimelineController, :readiness)
    get("/timeline/:incident_id", TimelineController, :show)
    post("/timeline/correlate", TimelineController, :correlate)
    post("/timeline/build", TimelineController, :build)

    # Storyline (SentinelOne-style attack visualization)
    get("/storyline/stats/:agent_id", StorylineController, :stats)
    get("/storyline/process/:agent_id/:pid", StorylineController, :from_process)
    get("/storyline/export/:alert_id", StorylineController, :export)
    get("/storyline/:alert_id", StorylineController, :show)
    post("/storyline/build", StorylineController, :build)
    post("/storyline/analyze", StorylineController, :analyze)

    # Autonomous Storyline Engine (real-time incident grouping)
    get("/storylines", StorylineController, :list_active)
    get("/storylines/engine-stats", StorylineController, :engine_stats)
    get("/storylines/:id", StorylineController, :show_autonomous)
    get("/agents/:agent_id/storylines", StorylineController, :agent_storylines)
    post("/storylines/:id1/merge/:id2", StorylineController, :merge)

    # Investigation Storyline Engine (attack narrative & causal analysis)
    post("/investigations/storylines", StorylineController, :create_investigation_story)
    get("/investigations/storylines/active", StorylineController, :list_investigation_stories)
    get("/investigations/storylines/stats", StorylineController, :investigation_stats)
    get("/investigations/storylines/:id/graph", StorylineController, :investigation_story_graph)

    get(
      "/investigations/storylines/:id/timeline",
      StorylineController,
      :investigation_story_timeline
    )

    get(
      "/investigations/storylines/:id/kill-chain",
      StorylineController,
      :investigation_kill_chain
    )

    post("/investigations/storylines/merge", StorylineController, :merge_investigation_stories)

    put(
      "/investigations/storylines/:id/resolve",
      StorylineController,
      :resolve_investigation_story
    )

    # Investigation Graph (for D3.js visualization)
    get("/investigation/:id", InvestigationController, :show)
    post("/investigation/process", InvestigationController, :from_process)
    post("/investigation/event", InvestigationController, :from_event)
    get("/investigation/:agent_id/timeline", InvestigationController, :timeline)

    # Provenance Graph (causal analysis)
    get("/provenance/:agent_id/chain/:entity_id", ProvenanceController, :chain)
    get("/provenance/:agent_id/impact/:entity_id", ProvenanceController, :impact)
    get("/provenance/:agent_id/attack-chains", ProvenanceController, :attack_chains)
    get("/provenance/:agent_id/context/:entity_id", ProvenanceController, :context)
    get("/provenance/:agent_id/blame/:entity_id", ProvenanceController, :blame)
    get("/provenance/:agent_id/stats", ProvenanceController, :stats)

    # AI Assistant
    post("/ai/query", AIController, :query)
    post("/ai/explain", AIController, :explain_detection)
    post("/ai/suggest", AIController, :suggest_actions)
    post("/ai/extract-iocs", AIController, :extract_iocs)
    post("/ai/hunt-query", AIController, :generate_hunt_query)

    # AI Chat & Conversations (server-side persistence)
    post("/ai/chat", AIController, :chat)
    get("/ai/conversations", AIController, :list_conversations)
    post("/ai/conversations", AIController, :save_conversation)
    get("/ai/conversations/:id", AIController, :get_conversation)
    delete("/ai/conversations/:id", AIController, :delete_conversation)
    post("/ai/suggestions", AIController, :suggestions)

    # AI Model Dependency Graph
    get("/ai/dependency-graph/stats", AIDependencyGraphController, :stats)

    get(
      "/ai/dependency-graph/model/:model_id/consumers",
      AIDependencyGraphController,
      :model_consumers
    )

    get(
      "/ai/dependency-graph/model/:model_id/lineage",
      AIDependencyGraphController,
      :model_lineage
    )

    get(
      "/ai/dependency-graph/model/:model_id/derivatives",
      AIDependencyGraphController,
      :model_derivatives
    )

    get(
      "/ai/dependency-graph/process/:process_id/models",
      AIDependencyGraphController,
      :process_models
    )

    post("/ai/dependency-graph/propagate-risk", AIDependencyGraphController, :propagate_risk)
    get("/ai/dependency-graph/critical-models", AIDependencyGraphController, :critical_models)
    get("/ai/dependency-graph/unusual-chains", AIDependencyGraphController, :unusual_chains)
    get("/ai/dependency-graph/subgraph/:node_id", AIDependencyGraphController, :subgraph)
    get("/ai/dependency-graph/export/:format", AIDependencyGraphController, :export)
    post("/ai/dependency-graph/dependency", AIDependencyGraphController, :add_dependency)
    delete("/ai/dependency-graph/dependency", AIDependencyGraphController, :remove_dependency)

    # Automated Playbooks
    # Static routes must come BEFORE dynamic :id routes
    get("/playbooks/recent-executions", PlaybookController, :recent_executions)
    get("/playbooks/templates", PlaybookController, :templates)
    resources("/playbooks", PlaybookController)
    post("/playbooks/:id/execute", PlaybookController, :execute)
    post("/playbooks/:id/clone", PlaybookController, :clone)
    get("/playbooks/:id/history", PlaybookController, :execution_history)

    # Asset Inventory
    resources("/assets", AssetController)
    post("/assets/:id/scan", AssetController, :trigger_scan)
    get("/assets/:id/vulnerabilities", AssetController, :vulnerabilities)
    get("/assets/:id/risk-score", AssetController, :risk_score)

    # Forensics (artifact collections)
    resources("/forensics", ForensicsController, only: [:index, :show, :create])
    get("/forensics/:id/download", ForensicsController, :download)
    post("/forensics/:id/download", ForensicsController, :download)
    post("/forensics/:id/analyze", ForensicsController, :analyze)

    # Forensics Investigations (full investigation lifecycle)
    get("/forensics/investigations/stats", ForensicsInvestigationController, :stats)

    resources("/forensics/investigations", ForensicsInvestigationController,
      only: [:index, :show, :create]
    )

    put("/forensics/investigations/:id/state", ForensicsInvestigationController, :update_state)
    get("/forensics/investigations/:id/timeline", ForensicsInvestigationController, :timeline)
    post("/forensics/investigations/:id/collect", ForensicsInvestigationController, :collect)

    get(
      "/forensics/investigations/:id/evidence",
      ForensicsInvestigationController,
      :list_evidence
    )

    post(
      "/forensics/investigations/:id/evidence",
      ForensicsInvestigationController,
      :record_evidence
    )

    post("/forensics/investigations/:id/notes", ForensicsInvestigationController, :add_note)
    post("/forensics/investigations/:id/report", ForensicsInvestigationController, :report)
    put("/forensics/investigations/:id/close", ForensicsInvestigationController, :close)

    # Live Response - Session Management (REST)
    post("/live-response/sessions", LiveResponseController, :create_session)
    get("/live-response/sessions", LiveResponseController, :list_sessions)
    get("/live-response/sessions/:id", LiveResponseController, :show_session)
    delete("/live-response/sessions/:id", LiveResponseController, :terminate_session)
    get("/live-response/sessions/:id/history", LiveResponseController, :session_command_history)
    get("/live-response/sessions/:id/recording", LiveResponseController, :session_recording)

    # Live Response - Legacy session endpoints (backward compatibility)
    post("/live-response/session", LiveResponseController, :start_session)
    post("/live-response/session/:session_id/execute", LiveResponseController, :execute)
    delete("/live-response/session/:session_id", LiveResponseController, :end_session)
    get("/live-response/session/:session_id/history", LiveResponseController, :session_history)

    # Live Response - Process Operations
    post("/live-response/:agent_id/cli-token", LiveResponseController, :create_cli_token)
    get("/live-response/:agent_id/processes", LiveResponseController, :list_processes)
    post("/live-response/:agent_id/processes/:pid/kill", LiveResponseController, :kill_process)

    post(
      "/live-response/:agent_id/processes/:pid/dump",
      LiveResponseController,
      :dump_process_memory
    )

    # Live Response - Memory Operations
    post("/live-response/:agent_id/memory/scan", LiveResponseController, :scan_memory)
    get("/live-response/:agent_id/memory/:pid/strings", LiveResponseController, :memory_strings)

    # Live Response - File Operations
    get("/live-response/:agent_id/files", LiveResponseController, :list_files)
    get("/live-response/:agent_id/files/download", LiveResponseController, :download_file)
    get("/live-response/:agent_id/files/hash", LiveResponseController, :hash_file)

    # Live Response - Network Operations
    get(
      "/live-response/:agent_id/network/connections",
      LiveResponseController,
      :network_connections
    )

    get("/live-response/:agent_id/network/dns-cache", LiveResponseController, :dns_cache)

    # Live Response - System Operations
    get("/live-response/:agent_id/registry", LiveResponseController, :registry_query)
    get("/live-response/:agent_id/services", LiveResponseController, :list_services)
    get("/live-response/:agent_id/scheduled-tasks", LiveResponseController, :scheduled_tasks)
    get("/live-response/:agent_id/startup-items", LiveResponseController, :startup_items)

    # Live Response - Artifact Collection
    post("/live-response/:agent_id/collect", LiveResponseController, :collect_artifacts)

    # Session Recordings (compressed, encrypted, with retention)
    get("/recordings", RecordingController, :index)
    get("/recordings/retention", RecordingController, :retention_info)
    get("/recordings/retention/stats", RecordingController, :retention_stats)
    post("/recordings/retention/purge", RecordingController, :trigger_retention_purge)
    get("/recordings/:session_id", RecordingController, :show)
    get("/recordings/:session_id/download", RecordingController, :download)
    delete("/recordings/:session_id", RecordingController, :delete)
    post("/recordings/purge", RecordingController, :purge)

    # Behavioral Analytics (UEBA)
    get("/behavioral/entities", BehavioralController, :entities)
    get("/behavioral/entities/:entity_type/:entity_id", BehavioralController, :entity_profile)
    get("/behavioral/entities/:id", BehavioralController, :entity_profile)
    get("/behavioral/anomalies", BehavioralController, :anomalies)
    get("/behavioral/anomalies/:anomaly_id/events", BehavioralController, :anomaly_events)
    get("/behavioral/baselines", BehavioralController, :baselines)
    post("/behavioral/baselines", BehavioralController, :baselines)
    get("/behavioral/statistics", BehavioralController, :statistics)
    get("/behavioral/risk-trends", BehavioralController, :risk_trends)
    get("/behavioral/peer-analysis/:entity_type/:entity_id", BehavioralController, :peer_analysis)

    get(
      "/behavioral/entity-history/:entity_type/:entity_id",
      BehavioralController,
      :entity_history
    )

    get("/behavioral/high-risk", BehavioralController, :high_risk_entities)
    # Detection categories and investigation
    get("/behavioral/categories", BehavioralController, :detection_categories)
    get("/behavioral/heatmap", BehavioralController, :heatmap)
    post("/behavioral/correlate", BehavioralController, :correlate_threats)
    # Thresholds configuration
    get("/behavioral/thresholds", BehavioralController, :thresholds)
    put("/behavioral/thresholds", BehavioralController, :update_thresholds)
    # Suppression rules (whitelist)
    get("/behavioral/suppressions", BehavioralController, :suppressions)
    post("/behavioral/suppressions", BehavioralController, :create_suppression)
    delete("/behavioral/suppressions/:id", BehavioralController, :delete_suppression)

    # Cloud Workloads
    get("/cloud/workloads", CloudController, :workloads)
    get("/cloud/containers", CloudController, :containers)
    get("/cloud/kubernetes", CloudController, :kubernetes)
    get("/cloud/security-posture", CloudController, :security_posture)

    # Cloud Detection Rules (50+ rules for cryptojacking, exfiltration, privilege escalation)
    get("/cloud/detection/rules", CloudDetectionController, :index)
    get("/cloud/detection/rules/:id", CloudDetectionController, :show)
    get("/cloud/detection/stats", CloudDetectionController, :stats)
    get("/cloud/detection/categories", CloudDetectionController, :categories)
    post("/cloud/detection/evaluate", CloudDetectionController, :evaluate)
    post("/cloud/detection/evaluate/cloudtrail", CloudDetectionController, :evaluate_cloudtrail)
    post("/cloud/detection/evaluate/azure", CloudDetectionController, :evaluate_azure)
    post("/cloud/detection/evaluate/gcp", CloudDetectionController, :evaluate_gcp)
    post("/cloud/detection/evaluate/runtime", CloudDetectionController, :evaluate_runtime)
    post("/cloud/detection/evaluate/kubernetes", CloudDetectionController, :evaluate_kubernetes)

    # CSPM (Cloud Security Posture Management)
    get("/cspm/dashboard", CSPMController, :dashboard)

    # CSPM Accounts
    get("/cspm/accounts", CSPMController, :list_accounts)
    get("/cspm/accounts/:id", CSPMController, :show_account)
    post("/cspm/accounts", CSPMController, :create_account)
    put("/cspm/accounts/:id", CSPMController, :update_account)
    delete("/cspm/accounts/:id", CSPMController, :delete_account)
    post("/cspm/accounts/:id/test", CSPMController, :test_connection)
    post("/cspm/accounts/:id/scan", CSPMController, :start_scan)
    get("/cspm/accounts/:id/stats", CSPMController, :account_stats)

    # CSPM Findings
    get("/cspm/findings", CSPMController, :list_findings)
    get("/cspm/findings/stats", CSPMController, :finding_stats)
    get("/cspm/findings/:id", CSPMController, :show_finding)
    patch("/cspm/findings/:id/status", CSPMController, :update_finding_status)
    post("/cspm/findings/bulk", CSPMController, :bulk_update_findings)

    # CSPM Policies
    get("/cspm/policies", CSPMController, :list_policies)
    get("/cspm/policies/stats", CSPMController, :policy_stats)
    get("/cspm/policies/:id", CSPMController, :show_policy)
    post("/cspm/policies", CSPMController, :create_policy)
    put("/cspm/policies/:id", CSPMController, :update_policy)
    delete("/cspm/policies/:id", CSPMController, :delete_policy)

    # CSPM Compliance
    get("/cspm/compliance", CSPMController, :compliance_overview)
    get("/cspm/compliance/:framework", CSPMController, :compliance_framework)

    # CSPM Topology & Visualization
    get("/cspm/topology", CSPMController, :topology)
    get("/cspm/risk-heatmap", CSPMController, :risk_heatmap)
    get("/cspm/assets", CSPMController, :list_assets)
    get("/cspm/assets/:id", CSPMController, :show_asset)

    # CSPM Security Groups
    get("/cspm/security-groups", CSPMController, :list_security_groups)
    get("/cspm/security-groups/:id", CSPMController, :show_security_group)
    get("/cspm/security-groups/:id/analysis", CSPMController, :analyze_security_group)

    # CSPM Identity Security
    get("/cspm/identities", CSPMController, :list_identities)
    get("/cspm/identities/:id", CSPMController, :show_identity)
    get("/cspm/identities/:id/escalation-paths", CSPMController, :identity_escalation_paths)

    # CSPM Runtime Protection
    get("/cspm/runtime/events", CSPMController, :runtime_events)
    get("/cspm/runtime/workloads", CSPMController, :runtime_workloads)
    get("/cspm/runtime/admission-policies", CSPMController, :admission_policies)

    # CSPM IaC Security
    post("/cspm/iac/scan", CSPMController, :scan_iac)

    # CSPM Remediation
    post("/cspm/findings/:id/remediate", CSPMController, :remediate_finding)
    get("/cspm/findings/export", CSPMController, :export_findings)

    # Serverless Security
    get("/serverless/functions", ServerlessController, :list_functions)
    get("/serverless/:provider/:function_id", ServerlessController, :get_function)
    post("/serverless/sync", ServerlessController, :sync_functions)
    get("/serverless/:provider/:function_id/executions", ServerlessController, :get_executions)

    get(
      "/serverless/:provider/:function_id/executions/:execution_id",
      ServerlessController,
      :get_execution
    )

    post("/serverless/:provider/:function_id/scan", ServerlessController, :scan_function)
    post("/serverless/:provider/scan-all", ServerlessController, :scan_all_functions)
    get("/serverless/findings", ServerlessController, :list_findings)
    get("/serverless/findings/:function_id", ServerlessController, :get_findings)
    patch("/serverless/findings/:finding_id", ServerlessController, :update_finding)
    get("/serverless/baselines", ServerlessController, :list_baselines)
    get("/serverless/baselines/:function_id", ServerlessController, :get_baseline)

    post(
      "/serverless/baselines/:function_id/start",
      ServerlessController,
      :start_baseline_learning
    )

    post("/serverless/baselines/:function_id/reset", ServerlessController, :reset_baseline)
    get("/serverless/anomalies", ServerlessController, :list_recent_anomalies)
    get("/serverless/anomalies/:function_id", ServerlessController, :get_anomalies)

    post(
      "/serverless/anomalies/:anomaly_id/acknowledge",
      ServerlessController,
      :acknowledge_anomaly
    )

    get("/serverless/statistics", ServerlessController, :get_statistics)
    get("/serverless/:provider/:function_id/metrics", ServerlessController, :get_metrics)

    # Container Runtime Security
    get("/containers", ContainerSecurityController, :index)
    get("/containers/statistics", ContainerSecurityController, :statistics)
    get("/containers/dashboard", ContainerSecurityController, :dashboard)
    get("/containers/high-risk", ContainerSecurityController, :high_risk)
    get("/containers/runtime-distribution", ContainerSecurityController, :runtime_distribution)
    get("/containers/:id", ContainerSecurityController, :show)
    get("/containers/agent/:agent_id", ContainerSecurityController, :agent_containers)

    # Container Images
    get("/container-images", ContainerSecurityController, :images)

    get(
      "/container-images/:image/vulnerabilities",
      ContainerSecurityController,
      :image_vulnerabilities
    )

    post("/container-images/:image/scan", ContainerSecurityController, :scan_image)

    # Container Security Policies
    get("/container-policies", ContainerSecurityController, :list_policies)
    post("/container-policies", ContainerSecurityController, :upsert_policy)
    put("/container-policies/:id", ContainerSecurityController, :upsert_policy)
    delete("/container-policies/:id", ContainerSecurityController, :delete_policy)

    # Container Escape Detection
    get("/containers/escape-detection/stats", ContainerSecurityController, :escape_stats)
    get("/containers/escape-detection/events", ContainerSecurityController, :escape_events)
    get("/containers/escape-detection/high-risk", ContainerSecurityController, :escape_high_risk)

    get(
      "/containers/escape-detection/escalation-chains",
      ContainerSecurityController,
      :escape_escalation_chains
    )

    get(
      "/containers/escape-detection/risk/:container_id",
      ContainerSecurityController,
      :escape_risk_score
    )

    # Kubernetes Workloads
    get("/k8s/workloads", ContainerSecurityController, :k8s_workloads)
    get("/k8s/namespaces", ContainerSecurityController, :k8s_namespaces)

    # Kubernetes Admission Control Policies
    resources("/kubernetes/admission-policies", KubernetesAdmissionPolicyController,
      except: [:new, :edit]
    )

    get("/kubernetes/admission-logs", KubernetesAdmissionPolicyController, :logs)
    get("/kubernetes/admission-stats", KubernetesAdmissionPolicyController, :admission_stats)

    get(
      "/kubernetes/admission-policies/:id/versions",
      KubernetesAdmissionPolicyController,
      :versions
    )

    post(
      "/kubernetes/admission-policies/:id/dry-run",
      KubernetesAdmissionPolicyController,
      :toggle_dry_run
    )

    post(
      "/kubernetes/admission-policies/reload",
      KubernetesAdmissionPolicyController,
      :reload_policies
    )

    post("/kubernetes/admission-simulate", KubernetesAdmissionPolicyController, :simulate)

    # Self-Healing
    post("/healing/execute", HealingController, :execute)
    get("/healing/history", HealingController, :history)
    post("/healing/rollback/:action_id", HealingController, :rollback)

    # AI Security - Attack Surface Protection
    get("/ai-security/attack-surface", AISecurityController, :attack_surface)

    post(
      "/ai-security/attack-surface/assess",
      AISecurityController,
      :schedule_attack_surface_assessment
    )

    post("/ai-security/prompt-scan", AISecurityController, :scan_prompt)
    get("/ai-security/shadow-ai", AISecurityController, :shadow_ai_inventory)
    post("/ai-security/risk-assess", AISecurityController, :risk_assessment)
    post("/ai-security/gateway/events", AISecurityController, :gateway_event)
    post("/ai-security/gateway/events/batch", AISecurityController, :gateway_events_batch)
    post("/ai-security/gateway/evaluate", AISecurityController, :gateway_evaluate)
    get("/ai-security/gateway/usage", AISecurityController, :gateway_usage)
    get("/ai-security/gateway/health", AISecurityController, :gateway_health)
    get("/ai-security/gateway/policy", AISecurityController, :gateway_policy)
    put("/ai-security/gateway/policy", AISecurityController, :update_gateway_policy)

    # AI Security - RAG Poisoning Detection
    post("/ai-security/rag-scan", AISecurityController, :scan_rag)
    post("/ai-security/rag-sources", AISecurityController, :register_rag_source)
    post("/ai-security/rag-sources/validate", AISecurityController, :validate_rag_source)

    # AI Security - Model Security Scanning
    get("/ai-security/models", AIModelController, :index)
    get("/ai-security/models/stats", AIModelController, :stats)
    post("/ai-security/models/scan", AIModelController, :bulk_scan)
    post("/ai-security/models/quarantine", AIModelController, :bulk_quarantine)
    post("/ai-security/models/block", AIModelController, :bulk_block)
    get("/ai-security/models/:id", AIModelController, :show)
    post("/ai-security/models/:id/scan", AIModelController, :scan)
    get("/ai-security/models/:id/history", AIModelController, :history)
    get("/ai-security/models/:id/status", AIModelController, :status)
    post("/ai-security/models/:id/quarantine", AIModelController, :quarantine)
    post("/ai-security/models/:id/block", AIModelController, :block)
    delete("/ai-security/models/:id/block", AIModelController, :unblock)
    post("/ai-security/models/:id/restore", AIModelController, :restore)

    # AI Security - Known-Good Hash Database
    get("/ai-security/known-good", KnownGoodController, :index)
    get("/ai-security/known-good/stats", KnownGoodController, :stats)
    get("/ai-security/known-good/export", KnownGoodController, :export_hashes)
    post("/ai-security/known-good/import", KnownGoodController, :import_hashes)
    get("/ai-security/known-good/:sha256", KnownGoodController, :show)
    post("/ai-security/known-good", KnownGoodController, :create)
    delete("/ai-security/known-good/:sha256", KnownGoodController, :delete)

    # AI Security - Agentic Analyst (Purple AI)
    post("/analyst/investigate", AnalystController, :start_investigation)
    get("/analyst/investigations", AnalystController, :list_investigations)
    get("/analyst/investigations/:id", AnalystController, :investigation_detail)
    post("/analyst/investigations/:id/feedback", AnalystController, :analyst_feedback)
    post("/analyst/triage", AnalystController, :auto_triage)

    # Detection Analytics & Tuning
    get("/detection-analytics/overview", DetectionAnalyticsController, :overview)
    get("/detection-analytics/rules", DetectionAnalyticsController, :rules)
    get("/detection-analytics/pipeline", DetectionAnalyticsController, :pipeline)
    get("/detection-analytics/blind-spots", DetectionAnalyticsController, :blind_spots)
    get("/detection-analytics/recommendations", DetectionAnalyticsController, :recommendations)
    get("/detection-analytics/trends", DetectionAnalyticsController, :trends)

    get(
      "/detection-analytics/precision-metrics",
      DetectionAnalyticsController,
      :precision_metrics
    )

    get(
      "/detection-analytics/collector-coverage",
      DetectionAnalyticsController,
      :collector_coverage
    )

    get(
      "/detection-analytics/effective-coverage",
      DetectionAnalyticsController,
      :effective_coverage
    )

    # Dynamic Threat Detection
    get("/dynamic-detection/status", DynamicDetectionController, :status)
    post("/dynamic-detection/hunt", DynamicDetectionController, :proactive_hunt)
    get("/dynamic-detection/blind-spots", DynamicDetectionController, :blind_spots)
    get("/dynamic-detection/false-negatives", DynamicDetectionController, :false_negatives)

    # EDR Validation & Testing (Atomic Red Team)
    get("/validation/tests", ValidationController, :list_tests)
    post("/validation/tests/:technique_id", ValidationController, :run_test)
    post("/validation/suite", ValidationController, :run_suite)
    post("/validation/tactic/:tactic", ValidationController, :run_tactic)
    get("/validation/results/:agent_id", ValidationController, :get_results)
    get("/validation/coverage/:agent_id", ValidationController, :coverage_report)
    get("/validation/benchmark", ValidationController, :benchmark)
    get("/validation/gaps/:agent_id", ValidationController, :gaps)
    get("/validation/stats", ValidationController, :stats)

    # Compliance Reporting
    get("/compliance/overview", ComplianceController, :overview)
    get("/compliance/dashboard", ComplianceController, :dashboard)
    get("/compliance/frameworks", ComplianceController, :list_frameworks)
    get("/compliance/frameworks/:framework", ComplianceController, :framework_posture)
    get("/compliance/frameworks/:framework/controls", ComplianceController, :list_controls)
    get("/compliance/frameworks/:framework/gap-analysis", ComplianceController, :gap_analysis)
    get("/compliance/frameworks/:framework/report", ComplianceController, :generate_report)
    get("/compliance/frameworks/:framework/export", ComplianceController, :export_audit)
    get("/compliance/controls/:control_id", ComplianceController, :control_detail)
    post("/compliance/controls/:control_id/assess", ComplianceController, :assess_control)
    post("/compliance/controls/:control_id/evidence", ComplianceController, :collect_evidence)

    # Deception Technology
    get("/deception/stats", DeceptionController, :stats)
    get("/deception/dashboard", DeceptionController, :dashboard)
    get("/deception/breadcrumbs", DeceptionController, :list_breadcrumbs)
    get("/deception/breadcrumbs/:agent_id", DeceptionController, :agent_breadcrumbs)
    post("/deception/deploy/:agent_id", DeceptionController, :deploy_to_agent)
    post("/deception/deploy/profile/:profile_id", DeceptionController, :deploy_by_profile)
    post("/deception/rotate/:agent_id", DeceptionController, :rotate_breadcrumbs)
    get("/deception/profiles", DeceptionController, :list_profiles)
    post("/deception/profiles", DeceptionController, :upsert_profile)
    put("/deception/profiles/:id", DeceptionController, :upsert_profile)
    get("/deception/attackers", DeceptionController, :list_attackers)
    get("/deception/attackers/:id", DeceptionController, :show_attacker)
    get("/deception/timeline", DeceptionController, :timeline)
    get("/deception/ttps", DeceptionController, :ttps)
    get("/deception/indicators", DeceptionController, :indicators)
    get("/deception/active-attacks", DeceptionController, :active_attacks)
    post("/deception/correlate", DeceptionController, :correlate)
    get("/deception/intel-report", DeceptionController, :intel_report)
    get("/deception/effectiveness", DeceptionController, :effectiveness)
    post("/deception/interaction", DeceptionController, :record_interaction)

    # Predictive Shielding
    get("/predictive/risk-forecast", PredictiveController, :risk_forecast)
    get("/predictive/attack-paths", PredictiveController, :attack_paths)
    post("/predictive/simulate", PredictiveController, :simulate_attack)
    get("/predictive/recommendations", PredictiveController, :hardening_recommendations)

    # Hyperautomation
    resources("/automation/workflows", WorkflowController)
    post("/automation/workflows/:id/execute", WorkflowController, :execute)
    get("/automation/actions", WorkflowController, :available_actions)
    get("/automation/templates", WorkflowController, :templates)

    # Exposure Prioritization
    get("/exposure/map", ExposureController, :attack_surface_map)
    get("/exposure/priorities", ExposureController, :prioritized_vulnerabilities)
    get("/exposure/crown-jewels", ExposureController, :crown_jewels)
    post("/exposure/remediation-plan", ExposureController, :generate_remediation_plan)

    # Attack Surface Management (ASM)
    # Dashboard & Overview
    get("/asm/dashboard", ASMController, :dashboard)
    get("/asm/overview", ASMController, :overview)
    get("/asm/stats", ASMController, :stats)

    # Domain Discovery
    get("/asm/domains", ASMController, :list_domains)
    post("/asm/domains", ASMController, :add_domain)
    delete("/asm/domains/:domain", ASMController, :remove_domain)
    post("/asm/discovery/start", ASMController, :start_discovery)
    get("/asm/discovery/status", ASMController, :discovery_status)
    get("/asm/ct-logs/:domain", ASMController, :ct_logs)
    get("/asm/passive-dns/:domain", ASMController, :passive_dns)
    get("/asm/whois/:domain", ASMController, :whois_lookup)

    # Asset Management
    get("/asm/assets", ASMController, :list_assets)
    get("/asm/assets/:id", ASMController, :show_asset)
    put("/asm/assets/:id", ASMController, :update_asset)
    delete("/asm/assets/:id", ASMController, :remove_asset)
    get("/asm/assets/:id/history", ASMController, :asset_history)
    post("/asm/assets/:id/scan", ASMController, :scan_asset)
    get("/asm/assets/by-type/:type", ASMController, :assets_by_type)
    get("/asm/assets/search", ASMController, :search_assets)

    # Exposure Analysis
    get("/asm/exposures", ASMController, :list_exposures)
    get("/asm/exposures/:asset_id", ASMController, :asset_exposures)
    post("/asm/exposures/analyze/:asset_id", ASMController, :analyze_exposures)
    post("/asm/port-scan/:asset_id", ASMController, :port_scan)
    get("/asm/tls-analysis/:asset_id", ASMController, :tls_analysis)
    get("/asm/headers/:asset_id", ASMController, :header_analysis)
    get("/asm/services/:asset_id", ASMController, :service_fingerprints)
    get("/asm/vulnerabilities/:asset_id", ASMController, :asset_vulnerabilities)

    # Risk Scoring
    get("/asm/risks", ASMController, :risk_overview)
    get("/asm/risks/:asset_id", ASMController, :asset_risk)
    get("/asm/risks/:asset_id/breakdown", ASMController, :risk_breakdown)
    get("/asm/risks/:asset_id/trend", ASMController, :risk_trend)
    get("/asm/top-risks", ASMController, :top_risks)
    get("/asm/risk-distribution", ASMController, :risk_distribution)
    get("/asm/aggregate-risk", ASMController, :aggregate_risk)
    post("/asm/risks/recalculate", ASMController, :recalculate_risks)

    # Change Monitoring
    get("/asm/changes", ASMController, :list_changes)
    get("/asm/changes/:asset_id", ASMController, :asset_changes)
    get("/asm/alert-rules", ASMController, :list_alert_rules)
    post("/asm/alert-rules", ASMController, :create_alert_rule)
    put("/asm/alert-rules/:id", ASMController, :update_alert_rule)
    delete("/asm/alert-rules/:id", ASMController, :delete_alert_rule)

    # Cloud Integration
    post("/asm/cloud/link", ASMController, :link_cloud_account)
    delete("/asm/cloud/unlink/:account_id", ASMController, :unlink_cloud_account)
    post("/asm/cloud/sync", ASMController, :sync_cloud_assets)

    # Shodan Integration
    post("/asm/shodan/configure", ASMController, :configure_shodan)
    get("/asm/shodan/search/:query", ASMController, :shodan_search)
    get("/asm/shodan/host/:ip", ASMController, :shodan_host)

    # Collaboration Security
    get("/collab/events", CollaborationController, :events)
    get("/collab/risks", CollaborationController, :risks)
    get("/collab/external-sharing", CollaborationController, :external_sharing)
    post("/collab/scan", CollaborationController, :scan_content)

    # MCP Server
    get("/mcp/rpc", MCPController, :schema_status)
    post("/mcp/rpc", MCPController, :json_rpc)
    get("/mcp/rpc/tools/schema/status", MCPController, :schema_status)
    get("/mcp/status", MCPController, :schema_status)
    get("/mcp/tools", MCPController, :available_tools)
    get("/mcp/context", MCPController, :security_context)

    # AI Agent Posture
    get("/ai-posture/agents", AIPostureController, :list_agents)
    get("/ai-posture/agents/:id", AIPostureController, :agent_detail)
    get("/ai-posture/compliance", AIPostureController, :compliance_status)
    get("/ai-posture/data-flows", AIPostureController, :data_flows)

    # Natural Language Hunting
    post("/nl-hunt/query", NLHuntController, :natural_language_query)
    post("/nl-hunt/hypothesis", NLHuntController, :generate_hypothesis)
    get("/nl-hunt/sessions", NLHuntController, :hunt_sessions)
    get("/nl-hunt/sessions/:id", NLHuntController, :session_detail)
    post("/nl-hunt/sessions/:id/query", NLHuntController, :session_query)

    # AI SIEM
    get("/ai-siem/patterns", AISIEMController, :discovered_patterns)
    get("/ai-siem/correlations", AISIEMController, :alert_correlations)
    post("/ai-siem/query", AISIEMController, :natural_language_log_query)
    get("/ai-siem/noise-reduction", AISIEMController, :noise_metrics)

    # Lateral Movement Detection & Path Analysis
    get("/lateral-movement/graph", LateralMovementController, :graph)
    get("/lateral-movement/paths/:source_ip", LateralMovementController, :paths)
    get("/lateral-movement/blast-radius/:host_ip", LateralMovementController, :blast_radius)
    get("/lateral-movement/choke-points", LateralMovementController, :choke_points)
    get("/lateral-movement/anomalies", LateralMovementController, :anomalies)
    get("/lateral-movement/stats", LateralMovementController, :stats)
    post("/lateral-movement/simulate", LateralMovementController, :simulate)

    # NDR (Network Detection and Response)
    get("/ndr/stats", NDRController, :stats)
    get("/ndr/data-sources", NDRController, :data_sources)
    get("/ndr/health", NDRController, :data_sources)
    get("/ndr/flows", NDRController, :list_flows)
    get("/ndr/flows/stats", NDRController, :flow_stats)
    get("/ndr/top-talkers", NDRController, :top_talkers)
    get("/ndr/topology", NDRController, :topology)
    get("/ndr/connection-graph", NDRController, :connection_graph)
    get("/ndr/protocols", NDRController, :protocol_distribution)
    get("/ndr/protocols/stats", NDRController, :protocol_stats)
    get("/ndr/smb", NDRController, :smb_activity)
    get("/ndr/rdp", NDRController, :rdp_sessions)
    get("/ndr/ssh", NDRController, :ssh_sessions)
    get("/ndr/lateral-movement", NDRController, :lateral_movement)
    get("/ndr/scan-activity", NDRController, :scan_activity)
    get("/ndr/credential-activity", NDRController, :credential_activity)
    get("/ndr/host-risk/:ip", NDRController, :host_risk)
    get("/ndr/ja3", NDRController, :ja3_stats)
    post("/ndr/ja3/check", NDRController, :check_ja3)
    post("/ndr/ja3/add", NDRController, :add_ja3_signature)
    get("/ndr/certificates", NDRController, :certificate_analysis)
    get("/ndr/tls-sessions", NDRController, :tls_sessions)
    get("/ndr/anomalies", NDRController, :anomalies)

    # Organizations (Multi-tenancy)
    get("/organizations", OrganizationController, :index)
    get("/organizations/current", OrganizationController, :current)
    get("/organizations/:id", OrganizationController, :show)
    post("/organizations", OrganizationController, :create)
    put("/organizations/:id", OrganizationController, :update)
    put("/organizations/:id/license", OrganizationController, :update_license)
    delete("/organizations/:id", OrganizationController, :delete)
    get("/organizations/:id/usage", OrganizationController, :usage)
    post("/organizations/:id/suspend", OrganizationController, :suspend)
    post("/organizations/:id/reactivate", OrganizationController, :reactivate)
    post("/organizations/provision", OrganizationController, :provision)

    # Tenant Management (system admin operations)
    resources("/tenants", TenantController, only: [:index, :show, :create, :update, :delete])
    post("/tenants/:id/suspend", TenantController, :suspend)
    post("/tenants/:id/reactivate", TenantController, :reactivate)
    post("/tenants/provision", TenantController, :provision)

    # API Keys (tenant-scoped)
    get("/api-keys", APIKeyController, :index)
    get("/api-keys/:id", APIKeyController, :show)
    post("/api-keys", APIKeyController, :create)
    put("/api-keys/:id", APIKeyController, :update)
    delete("/api-keys/:id", APIKeyController, :delete)
    post("/api-keys/:id/deactivate", APIKeyController, :deactivate)
    post("/api-keys/:id/rotate", APIKeyController, :rotate)

    # Tenant Rate Limits
    get("/rate-limits", RateLimitController, :show)
    put("/rate-limits", RateLimitController, :update)

    # Billing and Subscriptions
    get("/billing", BillingController, :show)
    post("/billing/subscribe", BillingController, :create_subscription)
    delete("/billing/subscribe", BillingController, :cancel_subscription)
    get("/billing/usage", BillingController, :usage)
    get("/billing/portal", BillingController, :portal)
    get("/billing/invoices", BillingController, :invoices)
    post("/billing/report-usage", BillingController, :report_usage)

    # Users (tenant-scoped)
    get("/users", UserController, :index)
    get("/users/me", UserController, :me)
    get("/users/:id", UserController, :show)
    post("/users", UserController, :create)
    put("/users/:id", UserController, :update)
    delete("/users/:id", UserController, :delete)
    post("/users/:id/role", UserController, :update_role)
    post("/users/:id/mfa", UserController, :toggle_mfa)
    post("/users/:id/status", UserController, :update_status)

    # RBAC - Role-Based Access Control
    get("/rbac/roles", RBACController, :list_roles)
    get("/rbac/roles/:id", RBACController, :show_role)
    post("/rbac/roles", RBACController, :create_role)
    put("/rbac/roles/:id", RBACController, :update_role)
    put("/rbac/roles/:id/permissions", RBACController, :update_role_permissions)
    delete("/rbac/roles/:id", RBACController, :delete_role)
    post("/rbac/roles/:id/clone", RBACController, :clone_role)

    # Role Templates & Hierarchy
    get("/rbac/templates", RBACController, :list_templates)
    post("/rbac/templates/create", RBACController, :create_from_template)
    get("/rbac/hierarchy", RBACController, :role_hierarchy)

    # User Role Management
    get("/rbac/users/:user_id/roles", RBACController, :user_roles)
    post("/rbac/users/:user_id/roles", RBACController, :assign_role)
    delete("/rbac/users/:user_id/roles/:role_id", RBACController, :revoke_role)
    post("/rbac/users/:user_id/elevate", RBACController, :elevate_role)
    get("/rbac/users/:user_id/effective-permissions", RBACController, :effective_permissions)
    get("/rbac/users/:user_id/audit-log", RBACController, :user_audit_log)

    # Bulk Operations
    post("/rbac/bulk-assign", RBACController, :bulk_assign)

    # Permissions
    get("/rbac/permissions", RBACController, :list_permissions)
    get("/rbac/permissions/check/:permission", RBACController, :check_permission)
    post("/rbac/permissions/check", RBACController, :check_permissions)
    post("/rbac/permissions/detect-conflicts", RBACController, :detect_conflicts)
    get("/rbac/my-permissions", RBACController, :my_permissions)
    get("/rbac/audit-log", RBACController, :audit_log)

    # Device Control & USB Management
    get("/device-control/policies", DeviceControlController, :list_policies)
    get("/device-control/policies/:group", DeviceControlController, :get_policy)
    put("/device-control/policies/:group", DeviceControlController, :upsert_policy)
    delete("/device-control/policies/:group", DeviceControlController, :delete_policy)

    get("/device-control/whitelist", DeviceControlController, :get_whitelist)
    post("/device-control/whitelist", DeviceControlController, :add_to_whitelist)
    delete("/device-control/whitelist", DeviceControlController, :remove_from_whitelist)

    get("/device-control/blocklist", DeviceControlController, :get_blocklist)
    post("/device-control/blocklist", DeviceControlController, :add_to_blocklist)
    delete("/device-control/blocklist", DeviceControlController, :remove_from_blocklist)

    post("/device-control/agents/:agent_id/group", DeviceControlController, :assign_agent_group)
    get("/device-control/agents/:agent_id/group", DeviceControlController, :get_agent_group)

    get("/device-control/devices", DeviceControlController, :list_connected_devices)
    get("/device-control/devices/history/:agent_id", DeviceControlController, :device_history)

    get("/device-control/encryption/status", DeviceControlController, :encryption_status)
    post("/device-control/encryption/configure", DeviceControlController, :configure_encryption)

    get(
      "/device-control/write-protection/status",
      DeviceControlController,
      :write_protection_status
    )

    post(
      "/device-control/write-protection/:group",
      DeviceControlController,
      :set_write_protection
    )

    get("/device-control/templates", DeviceControlController, :policy_templates)
    post("/device-control/templates/apply", DeviceControlController, :apply_template)

    get("/device-control/stats", DeviceControlController, :stats)

    # ML Service - Malware Analysis
    get("/ml/status", MLController, :status)
    get("/ml/model", MLController, :model_info)
    get("/ml/metrics", MLController, :metrics)
    get("/ml/models", MLController, :list_models)
    post("/ml/predict", MLController, :predict)
    post("/ml/predict/batch", MLController, :predict_batch)
    post("/ml/model/reload", MLController, :reload_model)
    get("/ml/statistics", MLController, :statistics)
    get("/ml/predictions/history", MLController, :prediction_history)

    # ML Training
    get("/ml/training/datasets", MLController, :training_datasets)
    post("/ml/training/start", MLController, :start_training)
    post("/ml/train", MLController, :train)
    get("/ml/training/status/:job_id", MLController, :training_status)

    # ML Model Lifecycle Management
    get("/ml/lifecycle/models", MLLifecycleController, :list_models)
    get("/ml/lifecycle/models/:model_type/active", MLLifecycleController, :get_active)
    get("/ml/lifecycle/models/:model_type/history", MLLifecycleController, :model_history)
    get("/ml/lifecycle/models/:model_type/:version/metrics", MLLifecycleController, :get_metrics)
    post("/ml/lifecycle/models/:model_type/:version/promote", MLLifecycleController, :promote)
    post("/ml/lifecycle/models/:model_type/rollback", MLLifecycleController, :rollback_model)
    post("/ml/lifecycle/models/:model_type/retrain", MLLifecycleController, :trigger_retrain)
    get("/ml/lifecycle/canary/status", MLLifecycleController, :canary_status)
    get("/ml/lifecycle/feedback/stats", MLLifecycleController, :feedback_stats)
    post("/ml/lifecycle/feedback", MLLifecycleController, :submit_feedback)
    get("/ml/lifecycle/stats", MLLifecycleController, :ml_stats)
    get("/ml/lifecycle/training/jobs", MLLifecycleController, :list_training_jobs)
    get("/ml/lifecycle/training/jobs/:job_id", MLLifecycleController, :get_training_job)

    # Sample Analysis
    get("/samples", SampleController, :index)
    get("/samples/stats", SampleController, :stats)
    post("/samples/analyze", SampleController, :analyze)
    post("/samples/batch", SampleController, :batch_analyze)
    get("/samples/:sha256", SampleController, :show)
    get("/samples/:sha256/result", SampleController, :result)

    # Sandbox Detonation & Dynamic Analysis
    post("/sandbox/submit", SandboxController, :submit)
    get("/sandbox/report/:hash", SandboxController, :report)
    get("/sandbox/status/:submission_id", SandboxController, :status)
    get("/sandbox/stats", SandboxController, :stats)
    post("/sandbox/resubmit/:hash", SandboxController, :resubmit)

    # Vulnerability Management
    get("/vulnerabilities", VulnerabilityController, :index)
    get("/vulnerabilities/stats", VulnerabilityController, :stats)
    get("/vulnerabilities/dashboard", VulnerabilityController, :dashboard)
    get("/vulnerabilities/kev", VulnerabilityController, :kev_list)
    get("/vulnerabilities/epss/top", VulnerabilityController, :epss_top)
    get("/vulnerabilities/search", VulnerabilityController, :search)
    post("/vulnerabilities/check-cpe", VulnerabilityController, :check_cpe)
    post("/vulnerabilities/batch-scan", VulnerabilityController, :batch_scan)
    post("/vulnerabilities/sync/nvd", VulnerabilityController, :sync_nvd)
    post("/vulnerabilities/sync/epss", VulnerabilityController, :sync_epss)
    post("/vulnerabilities/sync/kev", VulnerabilityController, :sync_kev)
    get("/vulnerabilities/sync/status", VulnerabilityController, :sync_status)
    get("/vulnerabilities/:cve_id/affected-assets", VulnerabilityController, :affected_assets)
    get("/vulnerabilities/:cve_id", VulnerabilityController, :show)
    post("/vulnerabilities/:id/accept-risk", VulnerabilityController, :accept_risk)
    post("/vulnerabilities/:id/remediate", VulnerabilityController, :remediate)
    post("/vulnerabilities/:id/false-positive", VulnerabilityController, :false_positive)

    # Identity Protection
    get("/identity/statistics", IdentityController, :statistics)
    get("/identity/high-risk-users", IdentityController, :list_high_risk_users)
    get("/identity/risky-sign-ins", IdentityController, :list_risky_sign_ins)
    get("/identity/users/:user_id/risk", IdentityController, :get_user_risk)
    get("/identity/users/:user_id/baseline", IdentityController, :get_baseline)
    post("/identity/users/:user_id/recalculate", IdentityController, :recalculate_risk)
    post("/identity/users/:user_id/reset", IdentityController, :reset_user_risk)

    # Azure AD Integration
    get("/identity/azure-ad/status", IdentityController, :azure_ad_status)
    post("/identity/azure-ad/sync", IdentityController, :azure_ad_sync)
    get("/identity/azure-ad/sign-ins", IdentityController, :azure_ad_sign_ins)
    get("/identity/azure-ad/risky-users", IdentityController, :azure_ad_risky_users)
    get("/identity/azure-ad/policies", IdentityController, :azure_ad_policies)
    get("/identity/azure-ad/service-principals", IdentityController, :azure_ad_service_principals)
    get("/identity/azure-ad/audits", IdentityController, :azure_ad_audits)
    get("/identity/azure-ad/users/:user_id", IdentityController, :azure_ad_user)

    # Identity Response Actions
    post("/identity/users/:user_id/confirm-compromised", IdentityController, :confirm_compromised)
    post("/identity/users/:user_id/dismiss-risk", IdentityController, :dismiss_risk)

    post(
      "/identity/users/:user_id/force-password-reset",
      IdentityController,
      :force_password_reset
    )

    # Behavioral Baseline Learning
    get("/baselines/stats", BaselineLearnerController, :baseline_stats)
    get("/baselines/:entity_type/:entity_id", BaselineLearnerController, :show_baseline)
    post("/baselines/:entity_type/:entity_id/reset", BaselineLearnerController, :reset_baseline)
    post("/baselines/:entity_type/:entity_id/mode", BaselineLearnerController, :set_mode)
    post("/baselines/:entity_type/:entity_id/check", BaselineLearnerController, :check_anomaly)

    # User Risk Scoring Engine
    get("/identity/risk/stats", BaselineLearnerController, :risk_stats)
    get("/identity/risk/high-risk", BaselineLearnerController, :high_risk_entities)
    get("/identity/risk/:entity_type/:entity_id", BaselineLearnerController, :get_risk)

    get(
      "/identity/risk/:entity_type/:entity_id/history",
      BaselineLearnerController,
      :risk_history
    )

    get("/identity/risk/:entity_type/:entity_id/trend", BaselineLearnerController, :risk_trend)

    # User Profiling & Peer Groups
    get("/identity/users/:user_id/profile", BaselineLearnerController, :user_profile)
    get("/identity/users/:user_id/peer-group", BaselineLearnerController, :peer_group)

    post(
      "/identity/users/:user_id/assign-peer-group",
      BaselineLearnerController,
      :assign_peer_group
    )

    get("/identity/peer-clusters", BaselineLearnerController, :list_clusters)
    get("/identity/profiler/stats", BaselineLearnerController, :profiler_stats)

    # Email Security
    get("/email-security", EmailSecurityController, :index)
    get("/email-security/dashboard", EmailSecurityController, :dashboard)

    # Email Security - Microsoft 365 Integration
    post("/email-security/m365/configure", EmailSecurityController, :configure_m365)
    get("/email-security/m365/threat-intel", EmailSecurityController, :m365_threat_intel)
    get("/email-security/m365/quarantine", EmailSecurityController, :m365_quarantine)

    post(
      "/email-security/m365/quarantine/:message_id/release",
      EmailSecurityController,
      :m365_release_quarantine
    )

    get("/email-security/m365/security-alerts", EmailSecurityController, :m365_security_alerts)
    post("/email-security/m365/search", EmailSecurityController, :m365_search_emails)

    # Email Security - Google Workspace Integration
    post("/email-security/google/configure", EmailSecurityController, :configure_google)
    get("/email-security/google/gmail-logs", EmailSecurityController, :google_gmail_logs)
    get("/email-security/google/dlp-incidents", EmailSecurityController, :google_dlp_incidents)

    get(
      "/email-security/google/user-security/:email",
      EmailSecurityController,
      :google_user_security
    )

    get("/email-security/google/login-events", EmailSecurityController, :google_login_events)

    # Email Security - Phishing Triage
    post("/email-security/analyze", EmailSecurityController, :analyze_email)
    get("/email-security/analysis/:id", EmailSecurityController, :get_analysis)
    post("/email-security/analysis/:id/feedback", EmailSecurityController, :submit_feedback)
    get("/email-security/triage/stats", EmailSecurityController, :triage_stats)

    # Email Security - URL Analysis
    post("/email-security/url/analyze", EmailSecurityController, :analyze_url)
    post("/email-security/url/detonate", EmailSecurityController, :detonate_url)

    # Email Security - Sender & Domain Analysis
    get("/email-security/sender/:email/reputation", EmailSecurityController, :check_sender)
    get("/email-security/domain/:domain/spoofing", EmailSecurityController, :check_domain)

    # Email Security - Campaign Analysis
    get("/email-security/campaign/:email_id", EmailSecurityController, :analyze_campaign)

    # Phishing Analysis Engine (dedicated endpoints)
    post("/phishing/analyze", PhishingController, :analyze)
    get("/phishing/report/:id", PhishingController, :report)
    get("/phishing/campaigns", PhishingController, :campaigns)
    get("/phishing/stats", PhishingController, :stats)
    post("/phishing/report-phish", PhishingController, :report_phish)

    # Email Security - Correlation
    get("/email-security/attack-chains", EmailSecurityController, :list_attack_chains)
    get("/email-security/attack-chains/:email_id", EmailSecurityController, :get_attack_chain)
    get("/email-security/user-risk/:email", EmailSecurityController, :get_user_risk)
    get("/email-security/user-chains/:email", EmailSecurityController, :get_user_chains)
    get("/email-security/correlation/stats", EmailSecurityController, :correlation_stats)

    # Integrations (SIEM, SOAR, Ticketing)
    get("/integrations/types", IntegrationsController, :types)
    get("/integrations/stats", IntegrationsController, :stats)
    get("/integrations/health", IntegrationsController, :health)
    post("/integrations/reload", IntegrationsController, :reload)
    post("/integrations/test-config", IntegrationsController, :test_config)
    resources("/integrations", IntegrationsController, except: [:new, :edit])
    post("/integrations/:id/test", IntegrationsController, :test)
    post("/integrations/:id/enable", IntegrationsController, :enable)
    post("/integrations/:id/disable", IntegrationsController, :disable)

    # Integration Routing Rules
    get("/integrations/rules", IntegrationsController, :list_rules)
    post("/integrations/rules", IntegrationsController, :create_rule)
    put("/integrations/rules/:id", IntegrationsController, :update_rule)
    delete("/integrations/rules/:id", IntegrationsController, :delete_rule)
    post("/integrations/rules/test", IntegrationsController, :test_routing)

    # Integration Logs
    get("/integrations/logs", IntegrationsController, :logs)

    # SIEM/SOAR Bidirectional Integration
    post("/integrations/siem/test", IntegrationsController, :test_siem_connection)
    post("/integrations/siem/forward", IntegrationsController, :forward_to_siem)
    get("/integrations/siem/stats", IntegrationsController, :siem_stats)

    # Inbound Webhooks (authenticated)
    get("/integrations/webhooks/history", IntegrationsController, :webhook_history)

    # Field Mappings
    post("/integrations/field-mappings/validate", IntegrationsController, :validate_field_mapping)

    # XDR (Extended Detection & Response)
    # Event Ingestion
    post("/xdr/ingest", XDRController, :ingest)
    post("/xdr/ingest/batch", XDRController, :ingest_batch)

    # Event Queries
    get("/xdr/events", XDRController, :index)
    get("/xdr/events/:id", XDRController, :show)
    post("/xdr/events/search", XDRController, :search)

    # Data Sources
    get("/xdr/sources", XDRController, :list_sources)
    post("/xdr/sources", XDRController, :create_source)
    put("/xdr/sources/:id", XDRController, :update_source)
    delete("/xdr/sources/:id", XDRController, :delete_source)
    get("/xdr/sources/:id/health", XDRController, :source_health)

    # Correlations
    get("/xdr/correlations/entity/:type/:value", XDRController, :entity_correlations)
    get("/xdr/correlations/kill-chain", XDRController, :detect_kill_chain)
    get("/xdr/correlations/stats", XDRController, :correlation_stats)

    # Attack Timelines
    get("/xdr/timelines", XDRController, :list_timelines)
    post("/xdr/timelines", XDRController, :build_timeline)

    # Webhook Receivers
    post("/xdr/webhooks/:source_type", XDRController, :webhook_receive)

    # Log Ingestion (Mini-SIEM - third-party log sources)
    post("/logs/ingest", LogIngestionController, :ingest_json)
    post("/logs/ingest/cef", LogIngestionController, :ingest_cef)
    post("/logs/ingest/leef", LogIngestionController, :ingest_leef)
    post("/logs/ingest/syslog", LogIngestionController, :ingest_syslog)
    get("/logs/stats", LogIngestionController, :stats)

    # Mobile Security (Foundation - API stubs)
    get("/mobile/agents/:agent_id/overview", MobileController, :agent_overview)
    get("/mobile/devices", MobileController, :index)
    get("/mobile/devices/:id", MobileController, :show)
    post("/mobile/devices/register", MobileController, :register)
    post("/mobile/devices/enroll", MobileController, :register)
    put("/mobile/devices/:id", MobileController, :update)
    delete("/mobile/devices/:id", MobileController, :delete)

    # Mobile Device Posture
    get("/mobile/devices/:id/posture", MobileController, :device_posture)
    post("/mobile/devices/:id/posture", MobileController, :update_posture)

    # Mobile App Inventory
    get("/mobile/devices/:id/apps", MobileController, :device_apps)
    post("/mobile/devices/:id/apps/sync", MobileController, :sync_apps)
    get("/mobile/apps/high-risk", MobileController, :high_risk_apps)
    get("/mobile/apps/sideloaded", MobileController, :sideloaded_apps)

    # Mobile Events
    get("/mobile/devices/:id/events", MobileController, :device_events)
    get("/mobile/events", MobileController, :events)
    post("/mobile/events", MobileController, :ingest_events)
    get("/mobile/app_guard/apps", MobileController, :app_guard_apps)
    post("/mobile/app_guard/apps", MobileController, :create_app_guard_app)
    get("/mobile/app_guard/apps/:app_id", MobileController, :show_app_guard_app)
    get("/mobile/app_guard/builds", MobileController, :app_guard_builds)
    post("/mobile/app_guard/builds", MobileController, :create_app_guard_build)
    post("/mobile/app_guard/builds/:build_id/verify", MobileController, :verify_app_guard_build)
    get("/mobile/app_guard/research/programs", MobileController, :app_guard_research_programs)

    post(
      "/mobile/app_guard/research/programs",
      MobileController,
      :create_app_guard_research_program
    )

    get(
      "/mobile/app_guard/research/submissions",
      MobileController,
      :app_guard_research_submissions
    )

    post(
      "/mobile/app_guard/research/submissions",
      MobileController,
      :create_app_guard_research_submission
    )

    post(
      "/mobile/app_guard/research/submissions/:submission_id/validate",
      MobileController,
      :validate_app_guard_research_submission
    )

    post("/mobile/app_guard/events", MobileController, :ingest_app_guard_event)

    # Mobile Stats & Posture
    get("/mobile/stats", MobileController, :stats)
    get("/mobile/posture", MobileController, :posture)
    get("/mobile/event-stats", MobileController, :event_stats)

    # Mobile Response Actions
    post("/mobile/devices/:id/lock", MobileController, :lock_device)
    post("/mobile/devices/:id/wipe", MobileController, :wipe_device)
    post("/mobile/devices/:id/locate", MobileController, :locate_device)
    post("/mobile/devices/:id/message", MobileController, :send_message)
    post("/mobile/devices/:id/ring", MobileController, :ring_device)
    post("/mobile/devices/:id/push-policy", MobileController, :push_policy)
    post("/mobile/devices/:id/remove-app", MobileController, :remove_app)
    post("/mobile/devices/:id/enable-vpn", MobileController, :enable_vpn)
    get("/mobile/devices/:id/compliance", MobileController, :device_compliance)

    # Mobile Configuration
    get("/mobile/config", MobileController, :get_config)
    put("/mobile/config", MobileController, :update_config)

    # Mobile MDM Integration
    get("/mobile/mdm/status", MobileController, :mdm_status)
    post("/mobile/mdm/sync", MobileController, :mdm_sync)

    # Mobile Event Types Reference
    get("/mobile/event-types", MobileController, :event_types)

    # Mobile Device Registry (ETS-backed lifecycle management)
    post("/mobile/devices/:id/compliance-check", MobileController, :compliance_check)
    get("/mobile/devices/:id/compliance-report", MobileController, :compliance_report)
    post("/mobile/devices/:id/threat-scan", MobileController, :threat_scan)
    get("/mobile/devices/:id/apps/inventory", MobileController, :app_inventory)
    get("/mobile/devices/:id/apps/risk", MobileController, :app_risk)
    post("/mobile/devices/:id/commands/:command", MobileController, :send_command)
    post("/mobile/devices/:id/enroll", MobileController, :enroll_device)
    post("/mobile/devices/:id/deactivate", MobileController, :deactivate)
    post("/mobile/mdm/sync-enhanced", MobileController, :mdm_sync_enhanced)
    get("/mobile/registry-stats", MobileController, :registry_stats)
    post("/mobile/compliance/bulk-check", MobileController, :bulk_compliance_check)

    # Mobile V2 - Devices (mobile_devices_v2 table)
    get("/mobile/v2/devices", MobileController, :index_v2)
    get("/mobile/v2/devices/:id", MobileController, :show_v2)
    post("/mobile/v2/devices", MobileController, :create_v2)
    put("/mobile/v2/devices/:id", MobileController, :update_v2)
    delete("/mobile/v2/devices/:id", MobileController, :delete_v2)
    get("/mobile/v2/stats", MobileController, :stats_v2)
    get("/mobile/v2/posture", MobileController, :posture_v2)

    # Mobile V2 - MDM Commands (mdm_commands table)
    get("/mobile/v2/commands", MobileController, :list_commands)
    post("/mobile/v2/commands", MobileController, :create_command)
    get("/mobile/v2/commands/:id", MobileController, :show_command)
    patch("/mobile/v2/commands/:id/status", MobileController, :update_command_status)

    # License Management
    get("/license", LicenseController, :show)
    post("/license/activate", LicenseController, :activate)
    post("/license/deactivate", LicenseController, :deactivate)
    get("/license/features", LicenseController, :features)
    get("/license/usage", LicenseController, :usage_metrics)
    post("/license/check-action", LicenseController, :check_action)
    get("/license/tiers", LicenseController, :tiers)
    post("/license/verify", LicenseController, :verify)

    # MSSP Sub-licensing
    get("/license/sub-licenses", LicenseController, :list_sub_licenses)
    post("/license/sub-licenses", LicenseController, :create_sub_license)
    delete("/license/sub-licenses/:id", LicenseController, :revoke_sub_license)

    # Agent Self-Update
    get("/updates/check", UpdateController, :check)
    get("/updates/download/:version/:platform", UpdateController, :download)
    post("/updates/report", UpdateController, :report)
    get("/updates/status", UpdateController, :rollout_status)

    # Update Management (Admin)
    get("/updates/packages", UpdateController, :list_packages)
    post("/updates/packages", UpdateController, :create_package)
    get("/updates/packages/:id", UpdateController, :show_package)
    delete("/updates/packages/:id", UpdateController, :delete_package)
    get("/updates/rollouts", UpdateController, :list_rollouts)
    post("/updates/rollouts", UpdateController, :create_rollout)
    get("/updates/rollouts/:id", UpdateController, :show_rollout)
    post("/updates/rollouts/:id/pause", UpdateController, :pause_rollout)
    post("/updates/rollouts/:id/resume", UpdateController, :resume_rollout)
    post("/updates/rollouts/:id/rollback", UpdateController, :rollback_rollout)

    # =========================================================================
    # Admin Tenant Management
    #
    # Used by: Tenants.tsx, TenantDetail.tsx, TenantCreate.tsx
    # All endpoints require :system_settings permission (enforced in controller)
    # =========================================================================
    scope "/admin" do
      get("/tenants", AdminController, :index)
      get("/tenants/:id", AdminController, :show)
      post("/tenants", AdminController, :create)
      put("/tenants/:id", AdminController, :update)
      delete("/tenants/:id", AdminController, :delete)

      # Tenant status actions
      post("/tenants/:id/suspend", AdminController, :suspend)
      post("/tenants/:id/activate", AdminController, :activate)

      # Tenant invitations
      get("/tenants/:id/invitations", AdminController, :list_invitations)
      post("/tenants/:id/invitations", AdminController, :create_invitation)
      delete("/tenants/:id/invitations/:invitation_id", AdminController, :delete_invitation)

      # Tenant user management
      delete("/tenants/:id/users/:user_id", AdminController, :remove_user)

      # Tenant API key management
      post("/tenants/:id/api-keys", AdminController, :create_api_key)
      delete("/tenants/:id/api-keys/:key_id", AdminController, :revoke_api_key)

      # Installation Token Management (for agent enrollment)
      get("/installation-tokens", EnrollmentController, :index)
      post("/installation-tokens", EnrollmentController, :create)
      delete("/installation-tokens/:id", EnrollmentController, :delete)
    end

    # =========================================================================
    # MSSP Portal
    #
    # Used by: MSSPPortal.tsx
    # Multi-tenant management dashboard for Managed Security Service Providers
    # =========================================================================
    scope "/mssp" do
      get("/tenants", MSSPController, :tenants)
      get("/search", MSSPController, :search)
    end

    # =========================================================================
    # Bounty Workflow
    #
    # Submission and bounty payment management for security researchers
    # Admin-only endpoints for validation and payment
    # =========================================================================
    resources("/submissions", BountyController, only: [:index, :show])
    post("/submissions/:id/validate", BountyController, :validate)
    post("/submissions/:id/reject", BountyController, :reject)
    post("/submissions/:id/pay", BountyController, :pay)

    # =========================================================================
    # Demo & Hackathon Endpoints
    #
    # Trigger detection scenarios for demos, creates real alerts with attestation
    # Admin-only access required
    # =========================================================================
    post("/demo/trigger-detection", DemoController, :trigger_detection)

    # =========================================================================
    # Health Attestations
    #
    # Privacy-preserving on-chain proofs of endpoint monitoring. Creates
    # attestation records with aggregate security metrics (alert counts by
    # severity) and submits to Solana blockchain.
    # =========================================================================
    resources("/health-attestations", HealthAttestationController, only: [:index, :show, :create])
    post("/health-attestations/:id/attest", HealthAttestationController, :attest)

    post(
      "/health-attestations/create-and-attest",
      HealthAttestationController,
      :create_and_attest
    )

    get("/health-attestations/stats", HealthAttestationController, :stats)
    get("/health-attestations/verify/:id", HealthAttestationController, :verify)

    get(
      "/health-attestations/agent/:agent_id/latest",
      HealthAttestationController,
      :latest_for_agent
    )

    get("/health-attestations/pseudonym/:pseudonym", HealthAttestationController, :by_pseudonym)

    # Fleet-level "Proof of Health" endpoints
    # Aggregate health metrics across all connected agents, published to Solana
    get("/health-attestations/fleet/status", HealthAttestationController, :fleet_status)
    post("/health-attestations/fleet/attest", HealthAttestationController, :fleet_attest)
    get("/health-attestations/fleet/latest", HealthAttestationController, :fleet_last_attestation)
    get("/health-attestations/fleet/enabled", HealthAttestationController, :fleet_enabled)

    # =========================================================================
    # Security Oracle / Endpoint Posture Attestation
    #
    # Privacy-safe posture proof for a monitored endpoint. The GET endpoint
    # returns a local manifest/hash; POST publishes the hash to Solana.
    # =========================================================================
    get("/security-status/agents/:id", SecurityStatusController, :show_agent)
    post("/security-status/agents/:id/attest", SecurityStatusController, :attest_agent)
  end

  # SSO Provider Configuration (API - separate scope for Auth namespace)
  scope "/api/v1/sso", TamanduaServerWeb.Auth, as: :api_v1_sso do
    pipe_through([:api, :api_auth])

    get("/providers", SSOController, :list_providers)
  end

  # Webhooks - require raw body capture for HMAC signature verification
  # SECURITY NOTE: All webhook endpoints should verify HMAC signatures.
  # Secrets are ALWAYS looked up server-side, NEVER from request params.
  scope "/webhooks", TamanduaServerWeb do
    pipe_through([:api, :fetch_raw_body])

    post("/threat-intel/:provider", WebhookController, :threat_intel)
    post("/alerts/:integration", WebhookController, :alert_integration)
    post("/soar/:platform/callback", WebhookController, :soar_callback)

    # Bidirectional sync webhooks (HMAC-authenticated)
    post("/:integration_type/:integration_id", WebhookController, :receive_webhook)
    get("/:integration_type/:integration_id", WebhookController, :verify_webhook)
  end

  # Model Registry Webhooks - require raw body for signature verification
  # Note: These registries may use their own auth mechanisms (API keys, OAuth)
  scope "/api/webhooks/registries", TamanduaServerWeb do
    pipe_through([:api, :fetch_raw_body])

    post("/mlflow", WebhookController, :mlflow)
    post("/huggingface", WebhookController, :huggingface)
    post("/wandb", WebhookController, :wandb)
  end

  # SIEM/SOAR Inbound Webhooks - HMAC signatures required in production
  # SECURITY: Secrets are looked up from server config, never from request
  scope "/api/v1/integrations/webhooks", TamanduaServerWeb.API.V1 do
    pipe_through([:api, :fetch_raw_body])

    post("/inbound/:source", IntegrationsController, :receive_webhook)
  end

  # SOAR Callback Webhooks - platform-specific auth (XSOAR API key, Tines HMAC)
  # Raw body needed for Tines signature verification
  scope "/api/v1/integrations/soar", TamanduaServerWeb.API.V1 do
    pipe_through([:api, :fetch_raw_body])

    post("/callback/:platform", SoarWebhookController, :callback)
    get("/callback/health", SoarWebhookController, :health)
  end

  # Webhook history and management (requires authentication)
  scope "/api/v1/webhooks", TamanduaServerWeb do
    pipe_through([:api, :api_auth])

    get("/:integration_id/history", WebhookController, :webhook_history)
  end

  # Kubernetes Admission Webhooks (NO authentication - called by K8s API server)
  scope "/webhooks/k8s", TamanduaServerWeb.Webhook do
    pipe_through(:api)

    post("/validate", KubernetesAdmissionController, :validate)
    post("/mutate", KubernetesAdmissionController, :mutate)
  end

  # Stripe Webhooks (NO authentication - signature verified in controller)
  # Requires raw body for signature verification
  scope "/webhooks/stripe", TamanduaServerWeb.Webhook do
    pipe_through([:api, :fetch_raw_body])

    post("/", StripeController, :handle_event)
  end

  # Agent Enrollment (NO authentication - the installation token IS the auth)
  scope "/api/v1/enrollment", TamanduaServerWeb.API.V1 do
    pipe_through(:api)

    post("/validate", EnrollmentController, :validate)
    post("/exchange", EnrollmentController, :exchange)
    # CSR-based enrollment (secure - private key never leaves agent)
    post("/csr", EnrollmentController, :csr_enroll)
  end

  # Legacy Windows MSI enrollment endpoint. Keep public because the enrollment
  # token is the authentication secret.
  scope "/api/v1/agents", TamanduaServerWeb.API.V1 do
    pipe_through(:api)

    post("/enroll", EnrollmentController, :enroll)
  end

  # Agent model/rule updates (no session auth; manifest is signed server-side)
  scope "/api/v1/updates/models", TamanduaServerWeb.API.V1 do
    pipe_through(:api)

    post("/check", ModelUpdateController, :check)
    get("/download/:asset_type/:version", ModelUpdateController, :download)
  end

  # Agent Authentication - Public endpoints (uses Bearer agent token from header)
  # These are legitimately public as they use the agent's own JWT for auth
  scope "/api/v1/agents/auth", TamanduaServerWeb.API.V1 do
    pipe_through(:api)

    post("/refresh", AuthController, :refresh)
    get("/status", AuthController, :status)
  end

  # Agent Certificate Renewal (uses Bearer agent token from header)
  scope "/api/v1/enrollment", TamanduaServerWeb.API.V1 do
    pipe_through(:api)

    # CSR-based certificate renewal for existing agents
    post("/renew", EnrollmentController, :csr_renew)
  end

  # Agent Authentication - Admin-only endpoints (requires user auth + admin role)
  scope "/api/v1/agents/auth", TamanduaServerWeb.API.V1 do
    pipe_through([:api, :api_auth])

    post("/revoke", AuthController, :revoke)
    get("/stats/:agent_id", AuthController, :stats)
  end

  # Health checks - Public endpoints (required for k8s/load balancer probes)
  scope "/health", TamanduaServerWeb do
    pipe_through(:api)

    get("/", HealthController, :index)
    get("/ready", HealthController, :ready)
    get("/live", HealthController, :live)
    get("/clickhouse", HealthController, :clickhouse)
  end

  # Compatibility health checks for API clients and older agents.
  scope "/api/v1/health", TamanduaServerWeb do
    pipe_through(:api)

    get("/", HealthController, :index)
    get("/ready", HealthController, :ready)
    get("/live", HealthController, :live)
  end

  # Health checks - Debug endpoints (DEV/TEST only, requires admin auth in prod)
  # SECURITY: These endpoints expose sensitive session data and should never be
  # publicly accessible in production.
  if Application.compile_env(:tamandua_server, :env) in [:dev, :test] do
    scope "/health/debug", TamanduaServerWeb do
      pipe_through(:api)

      get("/sessions", HealthController, :debug_sessions)
      get("/network", HealthController, :debug_network_events)
    end
  else
    # In production, debug endpoints require admin authentication
    scope "/health/debug", TamanduaServerWeb do
      pipe_through([:api, :api_auth])

      get("/sessions", HealthController, :debug_sessions_secured)
      get("/network", HealthController, :debug_network_events_secured)
    end
  end

  # =========================================================================
  # Attestation Relay - Public API for self-hosted instances
  # =========================================================================
  #
  # Self-hosted Tamandua instances send attestations here for batched
  # publication to Solana. Treant pays the transaction fees.
  #
  # Authentication: API key via X-Tamandua-Relay-Key header (optional for demo)
  # Rate limiting: By IP when no API key provided
  #
  scope "/api/v1/relay", TamanduaServerWeb.API.V1 do
    pipe_through(:api)

    # Queue attestation for batched publication
    post("/attestations", RelayController, :create_attestation)

    # Get relay service status
    get("/status", RelayController, :status)

    # Get specific batch status
    get("/batches/:id", RelayController, :batch_status)
  end

  # API Documentation (Swagger UI / ReDoc)
  scope "/api/docs", TamanduaServerWeb.API.V1 do
    pipe_through(:api)

    get("/", DocsController, :index)
    get("/openapi.yaml", DocsController, :spec)
    get("/openapi.json", DocsController, :spec_json)
    get("/redoc", DocsController, :redoc)
  end

  # GraphQL API v2
  scope "/api" do
    pipe_through([:api, :api_auth, :graphql_context])

    forward("/graphql", Absinthe.Plug,
      schema: TamanduaServerWeb.GraphQL.Schema,
      json_codec: Jason,
      # Bound query cost so a single deeply-nested/expensive query cannot exhaust
      # the server (GraphQL resource-exhaustion DoS).
      analyze_complexity: true,
      max_complexity: 200
    )
  end

  # GraphQL Playground (development only)
  if Application.compile_env(:tamandua_server, :dev_routes) do
    scope "/api/graphql" do
      pipe_through([:api])

      forward("/playground", Absinthe.Plug.GraphiQL,
        schema: TamanduaServerWeb.GraphQL.Schema,
        interface: :playground,
        json_codec: Jason
      )
    end
  end

  # Inertia.js routes (React frontend)
  scope "/app", TamanduaServerWeb do
    pipe_through([:inertia, :require_authenticated_user])

    get("/", InertiaController, :dashboard)
    get("/dashboard", InertiaController, :dashboard)
    get("/executive", InertiaController, :executive_dashboard)
    get("/process-tree", InertiaController, :process_tree)
    get("/agents", InertiaController, :agents)
    get("/deploy-agent", InertiaController, :deploy_agent)
    get("/agents/:id", InertiaController, :agent_detail_page)
    get("/alerts", InertiaController, :alerts)
    get("/alerts/:id", InertiaController, :alert_detail)
    get("/events", InertiaController, :events)
    get("/mitre", InertiaController, :mitre)
    get("/hunt", InertiaController, :hunt)
    get("/network", InertiaController, :network)
    get("/dns", InertiaController, :dns)
    get("/prevention-policies", InertiaController, :prevention_policies)
    get("/settings", InertiaController, :settings)
    get("/tenant-settings", InertiaController, :tenant_settings)
    get("/response", InertiaController, :response)

    # New advanced features
    get("/timeline", InertiaController, :timeline)
    get("/timeline/:incident_id", InertiaController, :timeline_detail)
    get("/storyline", InertiaController, :storyline_index)
    get("/storyline/:alert_id", InertiaController, :storyline)
    get("/storyline/process/:agent_id/:pid", InertiaController, :storyline_process)
    get("/investigations", InertiaController, :investigation_hub)
    get("/investigations/:id", InertiaController, :investigation_case_detail)
    get("/investigation", InertiaController, :investigation_hub)
    get("/investigation/:id", InertiaController, :investigation_graph_detail)
    get("/provenance", InertiaController, :provenance_graph)
    get("/ai-assistant", InertiaController, :ai_assistant)
    get("/playbooks", InertiaController, :playbooks)
    get("/playbooks/:id", InertiaController, :playbook_detail)
    get("/assets", InertiaController, :assets)
    get("/assets/:id", InertiaController, :asset_detail)
    get("/forensics", InertiaController, :forensics)
    get("/forensics/:collection_id", InertiaController, :forensics_detail)
    get("/live-response", InertiaController, :live_response)
    get("/live-response/:agent_id", InertiaController, :live_response_agent)
    get("/behavioral", InertiaController, :behavioral_analytics)
    # Cloud/CSPM/serverless pages are hidden for the hackathon build until they
    # are wired to verified tenant data instead of partial/demo workflows.
    # get "/cloud", InertiaController, :cloud_workloads
    # get "/cloud-security", InertiaController, :cloud_security
    # get "/serverless", InertiaController, :serverless
    get("/threat-intel", InertiaController, :threat_intel)

    # AI Security Features (2026)
    get("/ai-security/attack-surface", InertiaController, :ai_attack_surface)
    get("/ai-security/shadow-ai", InertiaController, :shadow_ai)
    get("/ai-security/posture", InertiaController, :ai_posture)
    get("/ai-security/agents", InertiaController, :ai_agent_registry)
    get("/ai-security/artifacts", InertiaController, :ai_artifacts)
    get("/ai-security/dependency-graph", InertiaController, :ai_dependency_graph)
    get("/ai-security/hunting", InertiaController, :nl_hunting)
    get("/ai-security/ml-dashboard", InertiaController, :ml_dashboard)
    get("/ai-security/behavioral", InertiaController, :behavioral_analytics)

    # Agentic Analyst (Purple AI)
    get("/analyst", InertiaController, :agentic_analyst)
    get("/analyst/investigations/:id", InertiaController, :investigation_detail)

    # Advanced Detection
    get("/detection-rules", InertiaController, :detection_rules)
    get("/detection-packs", InertiaController, :detection_packs)
    get("/dynamic-detection", InertiaController, :dynamic_detection)
    get("/predictive", InertiaController, :predictive_shielding)
    get("/detection-builder", InertiaController, :detection_builder)
    get("/detection-analytics", InertiaController, :detection_analytics)

    # Automation
    get("/automation", InertiaController, :hyperautomation)
    get("/automation/new", InertiaController, :hyperautomation)
    get("/hyperautomation", InertiaController, :hyperautomation)
    get("/automation/workflows/:id", InertiaController, :workflow_detail)

    # Exposure Management
    get("/exposure", InertiaController, :exposure_management)
    get("/exposure/attack-paths", InertiaController, :attack_paths)

    # Attack Surface Management (ASM)
    get("/attack-surface", InertiaController, :attack_surface)

    # Collaboration Security
    get("/collaboration", InertiaController, :collaboration_security)

    # Natural Language Hunting
    get("/nl-hunt", InertiaController, :nl_hunting)
    get("/nl-hunt/sessions/:id", InertiaController, :nl_hunt_session)

    # AI SIEM
    get("/ai-siem", InertiaController, :ai_siem)

    # Deception Technology
    get("/deception", InertiaController, :deception)

    # MCP Servers
    get("/mcp-servers", InertiaController, :mcp_servers)

    # Phishing Triage
    get("/phishing-triage", InertiaController, :phishing_triage)

    # Email Security
    get("/email-security", InertiaController, :email_security)

    get("/mobile", InertiaController, :mobile)

    # EDR Validation & Benchmark
    get("/validation", InertiaController, :validation_dashboard)
    get("/validation/benchmark", InertiaController, :validation_benchmark)
    get("/security-status", InertiaController, :security_status)
    get("/public-proofs", InertiaController, :public_proofs)

    # Solana / Web3 Integration
    # Policy Gate is hidden until the health attestation API is wired end-to-end.
    # get "/policy-gate", InertiaController, :policy_gate

    # Device Control
    get("/device-control", InertiaController, :device_control)
    get("/device-control/policies", InertiaController, :device_control_policies)

    # RBAC Management
    get("/settings/roles", InertiaController, :rbac_roles)
    get("/settings/roles/:id", InertiaController, :rbac_role_detail)
    get("/settings/users", InertiaController, :user_management)
    get("/users", InertiaController, :user_management)

    # Admin Tenant Management
    get("/admin/tenants", InertiaController, :admin_tenants)
    get("/admin/tenants/new", InertiaController, :admin_tenant_create)
    get("/admin/tenants/:id", InertiaController, :admin_tenant_detail)
    get("/admin/tenants/:id/settings", InertiaController, :admin_tenant_detail)

    # ML Malware Detection
    get("/ml", InertiaController, :ml_dashboard)
    get("/ml/detections", InertiaController, :ml_detections)
    get("/ml/processes", InertiaController, :ml_dashboard)

    get("/reports", InertiaController, :reports)
    get("/audit-log", InertiaController, :audit_log)

    # Identity Protection
    get("/identity", InertiaController, :identity)

    # Vulnerability Management
    get("/vulnerabilities", InertiaController, :vulnerabilities)
    get("/vulnerabilities/:cve_id", InertiaController, :vulnerability_detail)

    # Integrations (SIEM, SOAR, Ticketing)
    get("/integrations", InertiaController, :integrations)

    # XDR (Extended Detection & Response)
    # XDR UI remains hidden until cross-source incidents/health/insights APIs are complete.
    # get "/xdr", InertiaController, :xdr

    # NDR live runtime view. Historical flow persistence remains labeled in the UI.
    get("/ndr", InertiaController, :ndr)

    # Community Contributions - Bounty submissions and leaderboard
    get("/contributions", InertiaController, :contributions)

    # Keep unknown authenticated app routes inside the Inertia protocol.
    # Without this fallback, Inertia receives Phoenix's HTML 404 response and
    # displays it in its invalid-response modal during client-side navigation.
    get("/*path", InertiaController, :not_found)
  end

  # =========================================================================
  # LiveView Admin Pages
  #
  # Alternative admin UI using Phoenix LiveView for enhanced real-time features
  # These routes provide live-updating dashboards and interactive management tools
  # =========================================================================
  scope "/live", TamanduaServerWeb do
    pipe_through([:browser, :require_authenticated_user])

    # The :require_authenticated_user plug only guards the initial HTTP
    # dead-render; the stateful LiveView WebSocket mount does NOT run router
    # plugs. live_session enforces :ensure_authenticated on every socket mount
    # so an attacker cannot mount these LiveViews over the socket unauthenticated.
    live_session :live_admin,
      on_mount: {TamanduaServerWeb.UserAuth, :ensure_authenticated} do
      # Real-time Dashboard - Live threat feed with KPIs
      live("/dashboard", DashboardLive, :index)

      # On-Chain Incidents - Solana blockchain attestations (Hackathon MVP)
      live("/on-chain-incidents", OnChainIncidentsLive, :index)

      # SLO Dashboard - SLI/SLO monitoring and error budget tracking
      live("/slo", SLODashboardLive, :index)

      # Alert Management
      live("/alerts/:id", AlertDetailLive, :show)

      # YAML Playbook Editor
      live("/playbooks/new", PlaybookEditorLive, :new)
      live("/playbooks/:id/edit", PlaybookEditorLive, :edit)

      # Attack Correlation Graph Visualization
      live("/correlation-graph", CorrelationGraphLive, :index)
      live("/correlation-graph/campaign/:campaign_id", CorrelationGraphLive, :campaign)

      # SSO Configuration (admin only)
      live("/settings/sso", SSOConfigLive, :index)

      # AI Models Dashboard - AI/ML security inventory
      live("/ai-security/models", AIModelsLive, :index)
      live("/ai-security/models/:id", AIModelsLive, :show)

      # ML Process Monitoring - Track ML/AI runtime processes
      live("/ml-processes", MLProcessLive, :index)
      live("/ml-processes/:agent_id", MLProcessLive, :show)

      # LLM Request Monitoring - Track LLM API requests for Phase 27 analysis
      live("/llm-requests", LLMRequestsLive, :index)
      live("/llm-requests/:agent_id", LLMRequestsLive, :show)

      # AI Runtime Alerts - Security alerts for AI runtime threats (prompt injection, MCP abuse)
      live("/ai-runtime-alerts", AIRuntimeAlertsLive, :index)

      # Drift Monitor - LLM output distribution drift monitoring
      live("/drift-monitor", DriftMonitorLive, :index)

      # AI Runtime Security - Unified AI/ML runtime monitoring dashboard
      live("/ai/runtime", AIRuntimeLive, :index)

      # Remediation Approval Queue - Review and approve/reject pending remediation actions
      live("/remediation/approvals", ApprovalQueueLive, :index)

      # Remediation Dashboard - Pipeline status and activity feed
      live("/remediation/dashboard", RemediationDashboardLive, :index)

      # Model Registries Dashboard - Unified view of HuggingFace, MLflow, W&B, Ollama
      live("/registries", RegistriesLive, :index)

      # FIM Dashboard - File Integrity Monitoring
      live("/fim", FimLive, :index)

      # Contributor Dashboard - Submission management and bounty tracking
      live("/contributions", SubmissionsLive, :index)
      live("/contributions/new", SubmissionsLive, :new)

      # Bounty Leaderboard - Top contributors and wallet history
      live("/leaderboard", LeaderboardLive, :index)
      live("/leaderboard/:wallet", LeaderboardLive, :wallet)
    end

    # Legacy Kill Switch page used the old LiveView shell; keep the URL as a
    # compatibility redirect until the control is rebuilt in the React app.
    # Plain GET (not a LiveView) so it stays outside the live_session block.
    get("/runtime/kill-switch", RedirectController, :to_app_ai_attack_surface)
  end

  # =========================================================================
  # Live Response Routes
  #
  # Real-time incident response tools for remote agent interaction
  # =========================================================================
  scope "/agents", TamanduaServerWeb do
    pipe_through([:browser, :require_authenticated_user])

    # live_session enforces auth on the WebSocket mount (router plugs only run
    # on the initial dead-render, not on the stateful LiveView socket).
    live_session :live_response,
      on_mount: {TamanduaServerWeb.UserAuth, :ensure_authenticated} do
      # File Browser - Browse remote filesystems, download/upload files
      live("/:agent_id/files", FileBrowserLive, :index)
    end
  end

  # Phoenix LiveDashboard (dev/admin only)
  if Application.compile_env(:tamandua_server, :dev_routes) do
    import Phoenix.LiveDashboard.Router

    scope "/dev" do
      pipe_through(:browser)

      live_dashboard("/dashboard", metrics: TamanduaServerWeb.Telemetry)
    end

    scope "/dev/api", TamanduaServerWeb.API.V1, as: :dev_api do
      pipe_through(:api)

      delete("/events/purge", EventController, :purge)
    end
  end

  # Catch-all for SPA (if needed)
  scope "/", TamanduaServerWeb do
    pipe_through(:browser)

    get("/*path", PageController, :not_found)
  end
end
