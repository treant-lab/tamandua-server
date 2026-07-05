defmodule TamanduaServer.Supervisors.NetworkDiscoverySupervisor do
  @moduledoc """
  Peripheral supervision group: network discovery (SentinelOne Ranger-style)
  and attack surface management (ASM).

  These children perform active network scanning and external exposure
  probing. The NDR analyzers (`TamanduaServer.NDR.*`), which are fed directly
  by the telemetry ingest path, intentionally stay at the top level.

  Crash containment: a flapping child here (e.g. scan failures) consumes THIS
  group's restart budget (max_restarts: 10 / 60s) instead of the
  application-wide budget. If the group itself exceeds its budget and dies,
  the top-level supervisor restarts the whole group, which counts as ONE
  restart against the top-level budget — so a flapping peripheral child can
  no longer exhaust the shared budget and take down agent ingest/detection.

  Children and their relative start order are moved verbatim from
  `TamanduaServer.Application` (device inventory must start first, then rogue
  detector and vuln scanner); this module changes fault isolation only, not
  behavior.
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
      # Network Discovery modules (SentinelOne Ranger-style)
      # Device inventory must start first, then rogue detector and vuln scanner
      TamanduaServer.NetworkDiscovery.DeviceInventory,
      TamanduaServer.NetworkDiscovery.RogueDetector,
      TamanduaServer.NetworkDiscovery.DeviceVulnScanner,
      TamanduaServer.NetworkDiscovery.ScanPolicy,

      # ASM (Attack Surface Management) modules
      TamanduaServer.ASM.Discovery,
      TamanduaServer.ASM.Exposure,
      TamanduaServer.ASM.RiskScoring,
      TamanduaServer.ASM.Monitor
    ]
  end
end
