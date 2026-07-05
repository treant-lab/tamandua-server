defmodule TamanduaServer.Supervisors.CloudWorkloadSupervisor do
  @moduledoc """
  Peripheral supervision group: Kubernetes admission control + serverless
  security monitoring.

  Note: container escape detection (`TamanduaServer.ContainerSecurity` and
  `TamanduaServer.ContainerSecurity.EscapeDetector`) intentionally stays at
  the top level — it is alert-critical (agent eBPF T1611 correlation).

  Crash containment: a flapping child here (e.g. unreachable K8s API or cloud
  provider API) consumes THIS group's restart budget (max_restarts: 10 / 60s)
  instead of the application-wide budget. If the group itself exceeds its
  budget and dies, the top-level supervisor restarts the whole group, which
  counts as ONE restart against the top-level budget — so a flapping
  peripheral child can no longer exhaust the shared budget and take down
  agent ingest/detection.

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
      # Kubernetes Admission Controller (validates/mutates pod deployments)
      TamanduaServer.Kubernetes.AdmissionController,

      # Kubernetes Admission Webhook Engine (full pipeline: pod security,
      # mutation, alerting, stats, versioning, dry-run)
      TamanduaServer.Kubernetes.AdmissionWebhook,

      # Kubernetes Enricher (caches pod metadata for alert enrichment)
      TamanduaServer.Alerts.Enrichers.KubernetesEnricher,

      # Serverless Security Monitoring (AWS Lambda, Azure Functions, GCP Cloud Functions)
      TamanduaServer.Serverless.Lambda,
      TamanduaServer.Serverless.AzureFunctions,
      TamanduaServer.Serverless.CloudFunctions,
      TamanduaServer.Serverless.SecurityAnalyzer,
      TamanduaServer.Serverless.BehavioralBaseline
    ]
  end
end
