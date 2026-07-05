defmodule TamanduaServer.Supervisors.ThreatIntelFeedsSupervisor do
  @moduledoc """
  Peripheral supervision group: external threat-intelligence feeds,
  aggregation, attribution, and third-party enrichment lookups.

  This is the highest-risk flapper group in the tree: nearly every child
  polls an external HTTP service (Abuse.ch, OTX, TAXII servers, commercial
  feeds, VirusTotal, Shodan, ...). The core IOC cache
  (`TamanduaServer.ThreatIntel`) stays at the top level so ingest-path IOC
  lookups survive this group dying. Core callers are already defensive:
  `EngineWorker` invokes Attribution/CampaignTracker fire-and-forget under
  `Task.Supervisor` with try/rescue, and enrichment entry points are
  controller-driven.

  Crash containment: a flapping feed consumes THIS group's restart budget
  (max_restarts: 10 / 60s) instead of the application-wide budget. If the
  group itself exceeds its budget and dies, the top-level supervisor restarts
  the whole group, which counts as ONE restart against the top-level budget —
  so a flapping threat-feed poller can no longer exhaust the shared budget
  and take down agent ingest/detection.

  Children and their relative start order are moved verbatim from
  `TamanduaServer.Application`; this module changes fault isolation only,
  not behavior.
  """

  use Supervisor

  def start_link(init_arg) do
    Supervisor.start_link(__MODULE__, init_arg, name: __MODULE__)
  end

  @impl true
  def init(_init_arg) do
    Supervisor.init(children(), strategy: :one_for_one, max_restarts: 10, max_seconds: 60)
  end

  @doc "Child specs for this group (also asserted by tests)."
  def children do
    [
      # Threat Intel Feed Synchronization
      TamanduaServer.Detection.ThreatIntelFeeds,

      # External Threat Intel Feeds (Abuse.ch, AlienVault OTX)
      TamanduaServer.Detection.ThreatIntel.Feeds,

      # Threat Intel Aggregator (deduplication, bloom filters, hot cache)
      TamanduaServer.ThreatIntel.Aggregator,

      # Threat Attribution Engine (IOC-to-actor correlation, campaigns)
      TamanduaServer.ThreatIntel.Attribution,

      # Campaign Tracker (auto-detects campaigns from attributed alerts)
      TamanduaServer.ThreatIntel.CampaignTracker,

      # Retroactive Scanner (scans historical telemetry for new IOCs)
      TamanduaServer.ThreatIntel.RetroactiveScanner,

      # IOC Relationship Graph (in-memory directed graph with confidence scoring)
      TamanduaServer.ThreatIntel.Graph,

      # TAXII Poller (scheduled polling of TAXII servers for new indicators)
      TamanduaServer.ThreatIntel.TaxiiPoller,

      # Commercial Threat Intel Feeds
      TamanduaServer.ThreatIntel.Feeds.RecordedFuture,
      TamanduaServer.ThreatIntel.Feeds.Mandiant,
      TamanduaServer.ThreatIntel.Feeds.CrowdStrikeIntel,
      TamanduaServer.ThreatIntel.Feeds.Proofpoint,

      # Additional Open Source Feeds
      TamanduaServer.ThreatIntel.Feeds.EmergingThreats,
      TamanduaServer.ThreatIntel.Feeds.FeodoTracker,
      TamanduaServer.ThreatIntel.Feeds.SSLBlacklist,
      TamanduaServer.ThreatIntel.Feeds.PhishTank,
      TamanduaServer.ThreatIntel.Feeds.OpenPhish,
      TamanduaServer.ThreatIntel.Feeds.Spamhaus,

      # Socket.dev Supply Chain Threat Intelligence Feed
      TamanduaServer.ThreatIntel.Feeds.SocketDev,

      # Threat Intel Enrichment Service
      TamanduaServer.Detection.ThreatIntelEnrichment,

      # VirusTotal Integration
      TamanduaServer.Detection.ThreatIntel.VirusTotal,

      # AlienVault OTX Integration
      TamanduaServer.Detection.ThreatIntel.AlienVault,

      # Shodan Integration
      TamanduaServer.Detection.ThreatIntel.Shodan,

      # Unified Threat Intel Enrichment
      TamanduaServer.Detection.ThreatIntel.UnifiedEnrichment
    ]
  end
end
