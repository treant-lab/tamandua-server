defmodule TamanduaServer.Supervisors.ThreatIntelSyncSupervisor do
  @moduledoc """
  Peripheral supervision group: MISP synchronization + IOC scoring.

  Note: the core IOC cache (`TamanduaServer.ThreatIntel`) intentionally stays
  a direct child of the top-level supervisor (it backs ingest-path IOC
  lookups); only the external MISP sync/publish machinery and the scoring
  service are isolated here.

  Crash containment: a flapping child here (e.g. unreachable MISP server)
  consumes THIS group's restart budget (max_restarts: 10 / 60s) instead of the
  application-wide budget. If the group itself exceeds its budget and dies,
  the top-level supervisor restarts the whole group, which counts as ONE
  restart against the top-level budget — so a flapping peripheral child can
  no longer exhaust the shared budget and take down agent ingest/detection.

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
      # MISP Integration (bidirectional sync with MISP servers)
      TamanduaServer.ThreatIntel.MISP,

      # MISP Publisher (queued batch publishing, conflict resolution, IOC sharing)
      TamanduaServer.ThreatIntel.MISPPublisher,

      # IOC Scoring Service (age-based decay, source reputation)
      TamanduaServer.ThreatIntel.IOCScoring
    ]
  end
end
