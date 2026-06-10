defmodule TamanduaServer.Integrations.Schemas.UptimeRecord do
  @moduledoc """
  Schema for integration uptime tracking and SLA compliance.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Integrations.Schemas.{HealthMetric, Incident}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "integration_uptime" do
    field :integration_id, :binary_id
    field :date, :date

    # Uptime metrics (seconds)
    field :uptime_seconds, :integer
    field :downtime_seconds, :integer
    field :total_seconds, :integer

    # Incidents
    field :incident_count, :integer
    field :mttr_seconds, :integer  # Mean Time To Recovery

    # SLA
    field :sla_target, :float
    field :sla_actual, :float
    field :sla_compliant, :boolean

    timestamps()
  end

  @fields [
    :integration_id, :date, :uptime_seconds, :downtime_seconds, :total_seconds,
    :incident_count, :mttr_seconds, :sla_target, :sla_actual, :sla_compliant
  ]

  def changeset(record, attrs) do
    record
    |> cast(attrs, @fields)
    |> validate_required([:integration_id, :date])
  end

  @doc """
  Calculate daily uptime for an integration.
  """
  def calculate_daily_uptime(integration_id, date \\ Date.utc_today()) do
    # Get all incidents for the date
    start_of_day = DateTime.new!(date, ~T[00:00:00], "Etc/UTC")
    end_of_day = DateTime.new!(date, ~T[23:59:59], "Etc/UTC")

    incidents = Incident.list_for_date_range(integration_id, start_of_day, end_of_day)

    # Calculate downtime from incidents
    {downtime_seconds, incident_count, total_resolution_time} =
      Enum.reduce(incidents, {0, 0, 0}, fn incident, {down, count, resolution} ->
        # Calculate downtime for this incident
        incident_downtime = if incident.resolved_at do
          DateTime.diff(incident.resolved_at, incident.started_at)
        else
          # Ongoing incident - count time until end of day or now
          end_time = datetime_min(end_of_day, DateTime.utc_now())
          DateTime.diff(end_time, incident.started_at)
        end

        incident_downtime = max(incident_downtime, 0)

        resolution_time = incident.resolution_time_seconds || 0

        {down + incident_downtime, count + 1, resolution + resolution_time}
      end)

    # Calculate uptime
    total_seconds = 86400  # 24 hours
    uptime_seconds = total_seconds - downtime_seconds

    # Calculate SLA
    sla_actual = (uptime_seconds / total_seconds) * 100
    sla_target = 99.9
    sla_compliant = sla_actual >= sla_target

    # Calculate MTTR
    mttr_seconds = if incident_count > 0 do
      div(total_resolution_time, incident_count)
    else
      nil
    end

    attrs = %{
      integration_id: integration_id,
      date: date,
      uptime_seconds: uptime_seconds,
      downtime_seconds: downtime_seconds,
      total_seconds: total_seconds,
      incident_count: incident_count,
      mttr_seconds: mttr_seconds,
      sla_target: sla_target,
      sla_actual: sla_actual,
      sla_compliant: sla_compliant
    }

    # Upsert
    case get_for_date(integration_id, date) do
      nil ->
        %__MODULE__{}
        |> changeset(attrs)
        |> Repo.insert()

      existing ->
        existing
        |> changeset(attrs)
        |> Repo.update()
    end
  end

  @doc """
  Get uptime record for a specific date.
  """
  def get_for_date(integration_id, date) do
    from(r in __MODULE__,
      where: r.integration_id == ^integration_id and r.date == ^date
    )
    |> Repo.one()
  end

  @doc """
  Get uptime statistics for the last N days.
  """
  def get_uptime_stats(integration_id, days \\ 30) do
    start_date = Date.utc_today() |> Date.add(-days)

    records = from(r in __MODULE__,
      where: r.integration_id == ^integration_id and r.date >= ^start_date,
      order_by: [asc: r.date]
    )
    |> Repo.all()

    if length(records) > 0 do
      # Calculate aggregate stats
      total_uptime = Enum.sum(Enum.map(records, & &1.uptime_seconds))
      total_downtime = Enum.sum(Enum.map(records, & &1.downtime_seconds))
      total_seconds = Enum.sum(Enum.map(records, & &1.total_seconds))
      total_incidents = Enum.sum(Enum.map(records, & &1.incident_count))

      avg_uptime = (total_uptime / total_seconds) * 100
      sla_compliant_days = Enum.count(records, & &1.sla_compliant)

      # Calculate MTTR
      resolution_times = Enum.map(records, & &1.mttr_seconds) |> Enum.reject(&is_nil/1)
      avg_mttr = if length(resolution_times) > 0 do
        Enum.sum(resolution_times) / length(resolution_times)
      else
        0
      end

      %{
        period_days: days,
        avg_uptime_percent: Float.round(avg_uptime, 2),
        total_uptime_hours: Float.round(total_uptime / 3600, 2),
        total_downtime_hours: Float.round(total_downtime / 3600, 2),
        total_incidents: total_incidents,
        sla_compliant_days: sla_compliant_days,
        sla_compliance_percent: Float.round(sla_compliant_days / length(records) * 100, 2),
        avg_mttr_minutes: Float.round(avg_mttr / 60, 2),
        daily_records: records
      }
    else
      %{
        period_days: days,
        avg_uptime_percent: 0.0,
        total_uptime_hours: 0.0,
        total_downtime_hours: 0.0,
        total_incidents: 0,
        sla_compliant_days: 0,
        sla_compliance_percent: 0.0,
        avg_mttr_minutes: 0.0,
        daily_records: []
      }
    end
  end

  defp datetime_min(dt1, dt2) do
    if DateTime.compare(dt1, dt2) == :lt, do: dt1, else: dt2
  end
end
