defmodule TamanduaServer.Supervisors.DataGovernanceSupervisor do
  @moduledoc """
  Peripheral supervision group: DLP policy engine/incident manager and the
  compliance reporting framework.

  `TamanduaServer.DeviceControl` intentionally stays at the top level (agent
  device-policy enforcement, actively developed in parallel).

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
      # DLP (Data Loss Prevention) Policy Engine and Incident Manager
      TamanduaServer.DLP.PolicyEngine,
      TamanduaServer.DLP.IncidentManager,

      # Compliance Reporting Framework
      TamanduaServer.Compliance
    ]
  end
end
