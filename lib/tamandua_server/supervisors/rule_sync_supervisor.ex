defmodule TamanduaServer.Supervisors.RuleSyncSupervisor do
  @moduledoc """
  Peripheral supervision group: external detection-rule synchronization
  (SigmaHQ community rules downloaded from GitHub).

  Single-child group on purpose: SigmaHQSync is exactly the "external poller
  flapper" class this restructure targets (network fetches from GitHub), while
  the rest of the Sigma stack (SigmaAggregator, Detection.Engine) is
  alert-critical and stays at the top level. Already-synced rules on disk /
  in ETS remain usable if this group dies.

  Crash containment: a flapping child here consumes THIS group's restart
  budget (max_restarts: 10 / 60s) instead of the application-wide budget. If
  the group itself exceeds its budget and dies, the top-level supervisor
  restarts the whole group, which counts as ONE restart against the top-level
  budget — so a flapping peripheral child can no longer exhaust the shared
  budget and take down agent ingest/detection.

  Children are moved verbatim from `TamanduaServer.Application`; this module
  changes fault isolation only, not behavior.
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
      # SigmaHQ Community Rules Synchronization (downloads Sigma rules from GitHub)
      {TamanduaServer.Detection.Rules.SigmaHQSync, [enabled: true, auto_sync: true]}
    ]
  end
end
