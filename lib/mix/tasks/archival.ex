defmodule Mix.Tasks.Tamandua.Archival do
  @moduledoc """
  Mix tasks for managing event archival and retention.

  ## Tasks

      mix tamandua.archival.stats
      mix tamandua.archival.run [--dry-run] [--retention-days N]
      mix tamandua.archival.query [--days N]

  ## Examples

      # Get current archival statistics
      mix tamandua.archival.stats

      # Perform a dry run to see what would be archived
      mix tamandua.archival.run --dry-run

      # Archive events with custom retention period
      mix tamandua.archival.run --retention-days 60

      # Query recent archive data
      mix tamandua.archival.query --days 7
  """

  use Mix.Task
  alias TamanduaServer.Workers.ArchiveEventsWorker
  alias TamanduaServer.Repo
  import Ecto.Query

  @shortdoc "Manage event archival and retention"

  def run(["stats"]) do
    Mix.Task.run("app.start")
    print_stats()
  end

  def run(["run" | args]) do
    Mix.Task.run("app.start")
    run_archival(args)
  end

  def run(["query" | args]) do
    Mix.Task.run("app.start")
    query_archive(args)
  end

  def run(_) do
    Mix.shell().info("""
    Usage:
      mix tamandua.archival.stats              # Show archival statistics
      mix tamandua.archival.run [OPTIONS]      # Run archival job
      mix tamandua.archival.query [OPTIONS]    # Query archive data

    Run Options:
      --dry-run               Simulate archival without making changes
      --retention-days N      Archive events older than N days (default: 30)
      --sampling-age-days N   Start sampling events older than N days (default: 7)

    Query Options:
      --days N                Query archive data from last N days (default: 30)
      --agent-id ID           Filter by agent ID
      --event-type TYPE       Filter by event type
    """)
  end

  defp print_stats do
    stats = ArchiveEventsWorker.archival_stats()

    Mix.shell().info("""

    Event Archival Statistics
    ══════════════════════════════════════════════════════════════

    Total Events:           #{format_number(stats.total_events)}
    Recent Events (0-7d):   #{format_number(stats.recent_events)}
    Medium Events (7-30d):  #{format_number(stats.events_to_sample)}
    Old Events (30+d):      #{format_number(stats.events_to_archive)}
    Archived Events:        #{format_number(stats.archived_events)}

    Configuration
    ──────────────────────────────────────────────────────────────
    Retention Days:         #{stats.retention_days}
    Archive Enabled:        #{stats.archive_enabled}
    Sampling Enabled:       #{stats.sampling_enabled}
    Sampling Rate:          #{Float.round(stats.sampling_rate * 100, 1)}%

    Storage Impact
    ──────────────────────────────────────────────────────────────
    Events to Archive:      #{format_number(stats.events_to_archive)} (#{format_percentage(stats.events_to_archive, stats.total_events)})
    Events to Sample:       #{format_number(stats.events_to_sample)} (#{format_percentage(stats.events_to_sample, stats.total_events)})
    Expected Deletions:     #{format_number(round(stats.events_to_sample * (1 - stats.sampling_rate)))}

    ══════════════════════════════════════════════════════════════
    """)
  end

  defp run_archival(args) do
    opts = parse_run_options(args)

    if opts[:dry_run] do
      Mix.shell().info("Running dry-run archival (no changes will be made)...")
    else
      Mix.shell().info("Running archival...")
    end

    case ArchiveEventsWorker.enqueue_archival(opts) do
      {:ok, job} ->
        Mix.shell().info("Archival job enqueued: #{job.id}")
        Mix.shell().info("Monitor progress with: mix oban.jobs --queue archival")

      {:error, reason} ->
        Mix.shell().error("Failed to enqueue archival: #{inspect(reason)}")
    end
  end

  defp query_archive(args) do
    opts = parse_query_options(args)
    days = opts[:days] || 30
    cutoff = DateTime.add(DateTime.utc_now(), -days * 86400, :second)

    Mix.shell().info("Querying archive data from last #{days} days...")

    query =
      from("events_archive",
        where: fragment("timestamp > ?", ^cutoff),
        select: %{
          event_type: fragment("event_type"),
          count: count()
        },
        group_by: fragment("event_type"),
        order_by: [desc: count()]
      )

    query =
      if opts[:agent_id] do
        from(q in query, where: fragment("agent_id = ?", ^opts[:agent_id]))
      else
        query
      end

    query =
      if opts[:event_type] do
        from(q in query, where: fragment("event_type = ?", ^opts[:event_type]))
      else
        query
      end

    results = Repo.all(query)

    if Enum.empty?(results) do
      Mix.shell().info("No archived events found for the specified criteria.")
    else
      Mix.shell().info("""

      Archived Events (Last #{days} Days)
      ══════════════════════════════════════════════════════════════
      """)

      total = Enum.reduce(results, 0, fn r, acc -> acc + r.count end)

      Enum.each(results, fn result ->
        percentage = Float.round(result.count / total * 100, 1)
        Mix.shell().info("  #{String.pad_trailing(result.event_type, 30)} #{format_number(result.count)} (#{percentage}%)")
      end)

      Mix.shell().info("""
      ──────────────────────────────────────────────────────────────
      Total:                       #{format_number(total)}
      ══════════════════════════════════════════════════════════════
      """)
    end
  end

  defp parse_run_options(args) do
    {opts, _, _} =
      OptionParser.parse(args,
        switches: [
          dry_run: :boolean,
          retention_days: :integer,
          sampling_age_days: :integer
        ]
      )

    opts
  end

  defp parse_query_options(args) do
    {opts, _, _} =
      OptionParser.parse(args,
        switches: [
          days: :integer,
          agent_id: :string,
          event_type: :string
        ]
      )

    opts
  end

  defp format_number(num) when is_integer(num) do
    num
    |> Integer.to_string()
    |> String.graphemes()
    |> Enum.reverse()
    |> Enum.chunk_every(3)
    |> Enum.join(",")
    |> String.reverse()
  end

  defp format_number(_), do: "0"

  defp format_percentage(part, total) when total > 0 do
    "#{Float.round(part / total * 100, 1)}%"
  end

  defp format_percentage(_, _), do: "0.0%"
end
