defmodule TamanduaServer.Supervisors.ModelRegistrySupervisor do
  @moduledoc """
  Peripheral supervision group: external ML model registry connectors
  (HuggingFace, MLflow, Weights & Biases, Ollama).

  These children poll external services on fixed intervals (60s health
  checks, 30s Ollama watcher) and are classic flappers when the remote side
  is down. The ML lifecycle managers (`TamanduaServer.ML.*`) and the
  detection ML client (`TamanduaServer.Detection.ML.Client`) are
  detection-relevant and intentionally stay at the top level.

  Crash containment: a flapping child here consumes THIS group's restart
  budget (max_restarts: 10 / 60s) instead of the application-wide budget. If
  the group itself exceeds its budget and dies, the top-level supervisor
  restarts the whole group, which counts as ONE restart against the top-level
  budget — so a flapping peripheral child can no longer exhaust the shared
  budget and take down agent ingest/detection.

  Children, their arguments, and their relative start order are moved
  verbatim from `TamanduaServer.Application`; this module changes fault
  isolation only, not behavior.
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
      # Registry Sync (periodic model registry metadata refresh)
      TamanduaServer.Registries.RegistrySync,

      # Registry Health Check (monitors HuggingFace, MLflow, W&B, Ollama connectivity)
      {TamanduaServer.Registries.HealthCheck,
       registries: [
         huggingface: [module: TamanduaServer.Registries.HuggingFace, config: %{}],
         mlflow: [module: TamanduaServer.Registries.MLflow, config: %{}],
         wandb: [module: TamanduaServer.Registries.WandB, config: %{}],
         ollama: [
           module: TamanduaServer.Registries.Ollama,
           config: %{base_url: System.get_env("OLLAMA_URL", "http://localhost:11434")}
         ]
       ],
       interval: 60_000},

      # Ollama Watcher (monitors for new model pulls, triggers security scanning)
      {TamanduaServer.Registries.OllamaWatcher,
       [
         poll_interval: 30_000,
         ollama_url: System.get_env("OLLAMA_URL", "http://localhost:11434")
       ]}
    ]
  end
end
