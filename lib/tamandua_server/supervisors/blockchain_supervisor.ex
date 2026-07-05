defmodule TamanduaServer.Supervisors.BlockchainSupervisor do
  @moduledoc """
  Peripheral supervision group: blockchain / Solana attestation.

  Crash containment: a flapping child here (e.g. Solana devnet unreachable)
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
      # Solana Client for incident attestation (hackathon MVP)
      # Submits tamper-evident attestations to Solana devnet
      TamanduaServer.Solana.Client,

      # Batches self-hosted instance attestations for relay publication
      TamanduaServer.Solana.RelayBatch,

      # Fleet Health Attestation (Proof of Health - hackathon)
      # Publishes periodic aggregate fleet health proofs to Solana devnet
      TamanduaServer.Solana.FleetHealthAttestation
    ]
  end
end
