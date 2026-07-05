defmodule TamanduaServer.Supervisors.AISecuritySupervisor do
  @moduledoc """
  Peripheral supervision group: enterprise knowledge graph + AI security
  monitoring (AI-SIEM adjacent surfaces).

  The telemetry ingestor references `AIInventory`/`AIGateway`/`AttackSurface`
  but already guards every call with `Process.whereis/1` (see
  `TamanduaServer.Telemetry.Ingestor.maybe_ingest_ai_discovery/1` and
  friends), so ingest degrades gracefully if this group is down. The
  Detection.* AI trackers (MLProcessTracker, LLMRequestTracker, ...) are
  alert-critical and intentionally stay at the top level.

  Crash containment: a flapping child here consumes THIS group's restart
  budget (max_restarts: 10 / 60s) instead of the application-wide budget. If
  the group itself exceeds its budget and dies, the top-level supervisor
  restarts the whole group, which counts as ONE restart against the top-level
  budget — so a flapping peripheral child can no longer exhaust the shared
  budget and take down agent ingest/detection.

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
      TamanduaServer.AISecurity.ModelAuditor
    ]
  end
end
