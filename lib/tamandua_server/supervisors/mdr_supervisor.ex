defmodule TamanduaServer.Supervisors.MDRSupervisor do
  @moduledoc """
  Peripheral supervision group: MDR (Managed Detection & Response) service
  delivery — alert queue/SLA delivery, analyst console, and metrics.

  MDR consumes alerts produced by the core pipeline; alert creation itself
  does not depend on these children.

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
      # MDR (Managed Detection & Response) Delivery Framework
      # Alert queue, SLA timers, escalation paths, customer communication, service tiers
      TamanduaServer.MDR.Delivery,

      # MDR Analyst Console (triage, investigation workspaces, cross-customer
      # correlation, knowledge base, shift management, performance tracking)
      TamanduaServer.MDR.AnalystConsole,

      # MDR Metrics & Reporting (SLA compliance, MTTD/MTTR/MTTC, detection efficacy,
      # alert volume trends, executive reports)
      TamanduaServer.MDR.Metrics
    ]
  end
end
