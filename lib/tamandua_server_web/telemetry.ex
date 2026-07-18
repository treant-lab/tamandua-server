defmodule TamanduaServerWeb.Telemetry do
  @moduledoc """
  Telemetry supervisor for Phoenix and application metrics.
  """
  use Supervisor
  import Telemetry.Metrics

  def start_link(arg) do
    Supervisor.start_link(__MODULE__, arg, name: __MODULE__)
  end

  @impl true
  def init(_arg) do
    children = [
      {:telemetry_poller, measurements: periodic_measurements(), period: 10_000}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end

  def metrics do
    [
      # Phoenix Metrics
      summary("phoenix.endpoint.start.system_time",
        unit: {:native, :millisecond}
      ),
      summary("phoenix.endpoint.stop.duration",
        unit: {:native, :millisecond}
      ),
      summary("phoenix.router_dispatch.start.system_time",
        tags: [:route],
        unit: {:native, :millisecond}
      ),
      summary("phoenix.router_dispatch.exception.duration",
        tags: [:route],
        unit: {:native, :millisecond}
      ),
      summary("phoenix.router_dispatch.stop.duration",
        tags: [:route],
        unit: {:native, :millisecond}
      ),
      summary("phoenix.socket_connected.duration",
        unit: {:native, :millisecond}
      ),
      summary("phoenix.channel_joined.duration",
        unit: {:native, :millisecond}
      ),
      summary("phoenix.channel_handled_in.duration",
        tags: [:event],
        unit: {:native, :millisecond}
      ),

      # Database Metrics
      summary("tamandua_server.repo.query.total_time",
        unit: {:native, :millisecond},
        description: "The sum of the other measurements"
      ),
      summary("tamandua_server.repo.query.decode_time",
        unit: {:native, :millisecond},
        description: "The time spent decoding the data received from the database"
      ),
      summary("tamandua_server.repo.query.query_time",
        unit: {:native, :millisecond},
        description: "The time spent executing the query"
      ),
      summary("tamandua_server.repo.query.queue_time",
        unit: {:native, :millisecond},
        description: "The time spent waiting for a database connection"
      ),
      summary("tamandua_server.repo.query.idle_time",
        unit: {:native, :millisecond},
        description:
          "The time the connection spent waiting before being checked out for the query"
      ),

      # VM Metrics
      summary("vm.memory.total", unit: {:byte, :kilobyte}),
      summary("vm.total_run_queue_lengths.total"),
      summary("vm.total_run_queue_lengths.cpu"),
      summary("vm.total_run_queue_lengths.io"),

      # Tamandua Custom Metrics
      counter("tamandua.agent.connected.count"),
      counter("tamandua.agent.disconnected.count"),
      counter("tamandua.telemetry.events.count"),
      counter("tamandua.alerts.created.count"),
      summary("tamandua.detection.duration", unit: {:native, :millisecond}),
      summary("tamandua.ml.inference.duration", unit: {:native, :millisecond}),
      counter("tamandua.evidence_session.created.count", tags: [:platform, :status]),
      summary("tamandua.evidence_session.created.duration",
        tags: [:platform, :status],
        unit: {:native, :millisecond}
      ),
      counter("tamandua.evidence_session.frame.count", tags: [:platform, :status]),
      summary("tamandua.evidence_session.frame.duration",
        tags: [:platform, :status],
        unit: {:native, :millisecond}
      ),
      counter("tamandua.evidence_session.completed.count", tags: [:platform, :status]),
      summary("tamandua.evidence_session.completed.duration",
        tags: [:platform, :status],
        unit: {:native, :millisecond}
      ),
      last_value("tamandua.evidence_session.completed.coverage", tags: [:platform, :status]),
      counter("tamandua.evidence_session.failed.count", tags: [:platform, :status]),
      summary("tamandua.evidence_session.failed.duration",
        tags: [:platform, :status],
        unit: {:native, :millisecond}
      ),
      counter("tamandua.evidence_session.export.count", tags: [:platform, :status]),
      summary("tamandua.evidence_session.export.duration",
        tags: [:platform, :status],
        unit: {:native, :millisecond}
      ),
      counter("tamandua.evidence_session.diff.count", tags: [:platform, :status]),
      summary("tamandua.evidence_session.diff.duration",
        tags: [:platform, :status],
        unit: {:native, :millisecond}
      )
    ]
  end

  defp periodic_measurements do
    [
      {__MODULE__, :agent_count, []},
      {__MODULE__, :alert_count, []}
    ]
  end

  # NOTE: These metrics are intentionally NOT org-scoped. They provide system-wide
  # infrastructure metrics for observability (Prometheus, Grafana, etc.) and are
  # not exposed to end users. Multi-tenant isolation is enforced at the API/UI
  # layer, not in system telemetry.

  def agent_count do
    status_counts = TamanduaServer.Agents.Registry.count_by_status()
    count = Enum.reduce(status_counts, 0, fn {_status, c}, acc -> acc + c end)
    :telemetry.execute([:tamandua, :agents], %{count: count}, %{})
  rescue
    _ -> :ok
  end

  def alert_count do
    count = TamanduaServer.Alerts.count_open()
    :telemetry.execute([:tamandua, :alerts], %{open_count: count}, %{})
  rescue
    _ -> :ok
  end
end
