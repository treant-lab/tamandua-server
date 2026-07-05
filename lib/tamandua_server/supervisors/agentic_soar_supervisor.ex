defmodule TamanduaServer.Supervisors.AgenticSoarSupervisor do
  @moduledoc """
  Peripheral supervision group: hyperautomation + Agentic SOAR (custom AI
  agent builder & runtime).

  The deterministic response stack (`TamanduaServer.Response.*`,
  `TamanduaServer.Playbooks.DAGEngine`, remediation/rollback managers) is
  response-critical and intentionally stays at the top level; only the
  AI-agent orchestration layer is isolated here.

  Crash containment: a flapping child here (e.g. LLM backend failures)
  consumes THIS group's restart budget (max_restarts: 10 / 60s) instead of
  the application-wide budget. If the group itself exceeds its budget and
  dies, the top-level supervisor restarts the whole group, which counts as
  ONE restart against the top-level budget — so a flapping peripheral child
  can no longer exhaust the shared budget and take down agent
  ingest/detection.

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
      # Hyperautomation Engine
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
      TamanduaServer.Agentic.LearningLoop
    ]
  end
end
