defmodule TamanduaServer.Analytics.APIUsageTracker do
  @moduledoc """
  Tracks API usage metrics for versioning analytics and sunset planning.

  Metrics tracked:
  - Request count per version
  - Endpoint usage per version
  - Latency per version
  - Error rate per version
  - Deprecated endpoint usage
  - Consumer adoption metrics
  """

  use GenServer
  require Logger
  import Ecto.Query

  alias TamanduaServer.Analytics.APIUsageMetric
  alias TamanduaServer.Repo

  @flush_interval :timer.seconds(60)
  @batch_size 1000

  defstruct [:metrics_buffer, :last_flush]

  ## Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Tracks an API request with metadata.
  """
  def track_request(conn, metadata \\ %{}) do
    metric = %{
      version: conn.assigns[:api_version],
      method: conn.method,
      path: conn.request_path,
      endpoint: normalize_endpoint(conn.request_path),
      status_code: conn.status,
      latency_ms: calculate_latency(conn),
      deprecated: metadata[:deprecated] || false,
      organization_id: conn.assigns[:current_organization_id],
      user_id: conn.assigns[:current_user_id],
      user_agent: get_header(conn, "user-agent"),
      client_ip: get_client_ip(conn),
      timestamp: DateTime.utc_now()
    }

    GenServer.cast(__MODULE__, {:track, metric})
  end

  @doc """
  Gets API usage statistics for a version.
  """
  def get_version_stats(version, opts \\ []) do
    days = Keyword.get(opts, :days, 30)
    start_date = DateTime.add(DateTime.utc_now(), -days * 24 * 60 * 60, :second)

    query =
      from m in APIUsageMetric,
        where: m.version == ^to_string(version),
        where: m.timestamp >= ^start_date,
        select: %{
          total_requests: count(m.id),
          unique_users: fragment("COUNT(DISTINCT ?)", m.user_id),
          unique_organizations: fragment("COUNT(DISTINCT ?)", m.organization_id),
          avg_latency_ms: avg(m.latency_ms),
          error_rate: fragment("AVG(CASE WHEN ? >= 400 THEN 1.0 ELSE 0.0 END)", m.status_code)
        }

    Repo.one(query)
  end

  @doc """
  Gets endpoint usage breakdown for a version.
  """
  def get_endpoint_usage(version, opts \\ []) do
    days = Keyword.get(opts, :days, 30)
    start_date = DateTime.add(DateTime.utc_now(), -days * 24 * 60 * 60, :second)

    query =
      from m in APIUsageMetric,
        where: m.version == ^to_string(version),
        where: m.timestamp >= ^start_date,
        group_by: [m.endpoint, m.method],
        select: %{
          endpoint: m.endpoint,
          method: m.method,
          count: count(m.id),
          avg_latency_ms: avg(m.latency_ms)
        },
        order_by: [desc: count(m.id)]

    Repo.all(query)
  end

  @doc """
  Gets version adoption metrics over time.
  """
  def get_version_adoption(opts \\ []) do
    days = Keyword.get(opts, :days, 90)
    start_date = DateTime.add(DateTime.utc_now(), -days * 24 * 60 * 60, :second)

    query =
      from m in APIUsageMetric,
        where: m.timestamp >= ^start_date,
        group_by: [fragment("DATE(?)", m.timestamp), m.version],
        select: %{
          date: fragment("DATE(?)", m.timestamp),
          version: m.version,
          requests: count(m.id),
          unique_users: fragment("COUNT(DISTINCT ?)", m.user_id)
        },
        order_by: [asc: fragment("DATE(?)", m.timestamp)]

    Repo.all(query)
  end

  @doc """
  Lists API consumers using a specific version.
  """
  def list_consumers_by_version(version, opts \\ []) do
    days = Keyword.get(opts, :days, 30)
    start_date = DateTime.add(DateTime.utc_now(), -days * 24 * 60 * 60, :second)

    # Get unique organizations that have used this version
    org_ids =
      from(m in APIUsageMetric,
        where: m.version == ^to_string(version),
        where: m.timestamp >= ^start_date,
        where: not is_nil(m.organization_id),
        distinct: true,
        select: m.organization_id
      )
      |> Repo.all()

    # Load organization details
    from(o in TamanduaServer.Accounts.Organization,
      where: o.id in ^org_ids,
      select: %{
        id: o.id,
        name: o.name,
        email: o.contact_email
      }
    )
    |> Repo.all()
  end

  @doc """
  Gets deprecated endpoint usage stats.
  """
  def get_deprecated_usage(opts \\ []) do
    days = Keyword.get(opts, :days, 30)
    start_date = DateTime.add(DateTime.utc_now(), -days * 24 * 60 * 60, :second)

    query =
      from m in APIUsageMetric,
        where: m.deprecated == true,
        where: m.timestamp >= ^start_date,
        group_by: [m.version, m.endpoint],
        select: %{
          version: m.version,
          endpoint: m.endpoint,
          count: count(m.id),
          unique_users: fragment("COUNT(DISTINCT ?)", m.user_id)
        },
        order_by: [desc: count(m.id)]

    Repo.all(query)
  end

  ## Server Callbacks

  @impl true
  def init(_opts) do
    schedule_flush()

    {:ok,
     %__MODULE__{
       metrics_buffer: [],
       last_flush: DateTime.utc_now()
     }}
  end

  @impl true
  def handle_cast({:track, metric}, state) do
    new_buffer = [metric | state.metrics_buffer]

    # Flush if buffer exceeds batch size
    if length(new_buffer) >= @batch_size do
      flush_metrics(new_buffer)
      {:noreply, %{state | metrics_buffer: [], last_flush: DateTime.utc_now()}}
    else
      {:noreply, %{state | metrics_buffer: new_buffer}}
    end
  end

  @impl true
  def handle_info(:flush, state) do
    if length(state.metrics_buffer) > 0 do
      flush_metrics(state.metrics_buffer)
    end

    schedule_flush()
    {:noreply, %{state | metrics_buffer: [], last_flush: DateTime.utc_now()}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  ## Private Functions

  defp flush_metrics(metrics) do
    Logger.debug("Flushing #{length(metrics)} API usage metrics to database")

    changesets =
      Enum.map(metrics, fn metric ->
        APIUsageMetric.changeset(%APIUsageMetric{}, metric)
      end)

    case Repo.insert_all(APIUsageMetric, Enum.map(changesets, &Ecto.Changeset.apply_changes/1),
           on_conflict: :nothing
         ) do
      {count, _} ->
        Logger.debug("Inserted #{count} API usage metrics")

      error ->
        Logger.error("Failed to flush API usage metrics: #{inspect(error)}")
    end
  rescue
    error ->
      Logger.error("Error flushing metrics: #{inspect(error)}")
  end

  defp schedule_flush do
    Process.send_after(self(), :flush, @flush_interval)
  end

  defp normalize_endpoint(path) do
    # Normalize path by replacing UUIDs and numeric IDs with placeholders
    path
    |> String.replace(~r/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/, ":id")
    |> String.replace(~r/\/\d+/, "/:id")
  end

  defp calculate_latency(conn) do
    case conn.private[:request_start_time] do
      nil -> nil
      start_time -> System.monotonic_time(:millisecond) - start_time
    end
  end

  defp get_header(conn, name) do
    case Plug.Conn.get_req_header(conn, name) do
      [value | _] -> value
      _ -> nil
    end
  end

  defp get_client_ip(conn) do
    case get_header(conn, "x-forwarded-for") do
      nil -> to_string(:inet_parse.ntoa(conn.remote_ip))
      ip -> ip
    end
  end
end
