defmodule TamanduaServer.Supervisors.IdentitySupervisor do
  @moduledoc """
  Peripheral supervision group: identity protection and UEBA (user/entity
  behavioral baselining, peer clustering, user risk scoring, Azure AD
  connector).

  `TamanduaServer.Detection.BaselineLearner` lives here (not at the top
  level) because it belongs to this UEBA block per the original tree layout
  and is only referenced from its API controller — it is distinct from the
  detection-critical `TamanduaServer.Detection.Baseline`, which stays core.
  `Identity.AzureAD` is an external cloud connector (classic flapper).

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
      # Identity Protection
      TamanduaServer.Identity.RiskScoring,
      TamanduaServer.Identity.AzureAD,

      # Behavioral Baseline Learning & User Risk Scoring
      TamanduaServer.Detection.BaselineLearner,
      TamanduaServer.Identity.UserProfiler,
      TamanduaServer.Identity.PeerClustering,
      TamanduaServer.Identity.RiskEngine
    ]
  end
end
