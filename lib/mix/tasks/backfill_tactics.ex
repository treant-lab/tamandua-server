defmodule Mix.Tasks.Tamandua.BackfillTactics do
  @moduledoc """
  Normalize legacy `alerts.mitre_tactics` to the canonical MITRE vocabulary.

  Historical alerts accumulated tactic values in several incompatible formats
  (e.g. `attack.defense_evasion`, `Defense Evasion`, `TA0005`, plus non-tactic
  noise such as `stealth`, `multiple`, software IDs). New alerts are already
  normalized at the write choke point (`Alert.changeset/2`), but pre-existing
  rows still carry the polluted values that produce incoherent correlations in
  the dashboard.

  This task re-applies the exact same `TamanduaServer.Detection.Mitre.normalize_tactics/1`
  used by the changeset, so the result is identical to what a freshly-written
  alert would store. It is idempotent: re-running after a clean pass is a no-op.

  ## Tasks

      mix tamandua.backfill_tactics.stats
      mix tamandua.backfill_tactics.run [--execute] [--batch-size N]

  ## Examples

      # Show how many alerts would change and what the dropped/rewritten values are
      mix tamandua.backfill_tactics.stats

      # Dry-run (default): report changes without writing
      mix tamandua.backfill_tactics.run

      # Apply the changes for real
      mix tamandua.backfill_tactics.run --execute

      # Apply with a custom batch size (default 1000)
      mix tamandua.backfill_tactics.run --execute --batch-size 500
  """

  use Mix.Task
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Detection.Mitre

  @shortdoc "Normalize legacy alert mitre_tactics to canonical vocabulary"

  @default_batch_size 1000

  def run(["stats" | args]) do
    Mix.Task.run("app.start")
    print_stats(parse_options(args))
  end

  def run(["run" | args]) do
    Mix.Task.run("app.start")
    run_backfill(parse_options(args))
  end

  def run(_) do
    Mix.shell().info("""
    Usage:
      mix tamandua.backfill_tactics.stats              # Report alerts whose tactics would change
      mix tamandua.backfill_tactics.run [OPTIONS]      # Normalize legacy mitre_tactics

    Run Options:
      --execute            Persist the changes (without this flag the task is a DRY RUN)
      --batch-size N       Rows scanned per batch (default: #{@default_batch_size})
    """)
  end

  # ==========================================================================
  # Stats
  # ==========================================================================

  defp print_stats(opts) do
    Mix.shell().info("Scanning alerts for non-canonical mitre_tactics...")

    summary =
      reduce_changes(opts[:batch_size], fresh_acc(), fn change, acc ->
        accumulate(acc, change)
      end)

    report(summary, false)
  end

  # ==========================================================================
  # Backfill
  # ==========================================================================

  defp run_backfill(opts) do
    execute? = opts[:execute] == true

    if execute? do
      Mix.shell().info("Running backfill (changes WILL be written)...")
    else
      Mix.shell().info("Running DRY RUN (no changes written; pass --execute to persist)...")
    end

    summary =
      reduce_changes(opts[:batch_size], fresh_acc(), fn change, acc ->
        acc = accumulate(acc, change)
        if execute?, do: apply_change(change)
        acc
      end)

    report(summary, execute?)
  end

  # Updates are grouped per batch by their normalized value so that a batch of
  # 1000 rows collapses into a handful of `UPDATE ... WHERE id = ANY($ids)`
  # statements instead of one query per row.
  defp apply_change(%{ids: ids, normalized: normalized}) do
    {_count, _} =
      from(a in Alert, where: a.id in ^ids)
      |> Repo.update_all(set: [mitre_tactics: normalized])

    :ok
  end

  # ==========================================================================
  # Scan / fold
  # ==========================================================================

  # Streams alerts in keyset-paginated batches (ordered by id), computes the
  # normalized tactics for each, and folds only the rows that actually change.
  # For each batch we group the changed rows by their normalized value so the
  # caller can do grouped updates.
  defp reduce_changes(batch_size, acc, fun) do
    do_reduce(batch_size, nil, acc, fun)
  end

  defp do_reduce(batch_size, last_id, acc, fun) do
    rows = fetch_batch(batch_size, last_id)

    case rows do
      [] ->
        acc

      _ ->
        acc =
          rows
          |> changed_rows()
          |> group_by_normalized()
          |> Enum.reduce(acc, fun)

        do_reduce(batch_size, List.last(rows).id, acc, fun)
    end
  end

  defp fetch_batch(batch_size, last_id) do
    base =
      from a in Alert,
        where: fragment("array_length(?, 1) > 0", a.mitre_tactics),
        order_by: [asc: a.id],
        limit: ^batch_size,
        select: %{id: a.id, mitre_tactics: a.mitre_tactics}

    query = if last_id, do: from(a in base, where: a.id > ^last_id), else: base

    Repo.all(query)
  end

  defp changed_rows(rows) do
    rows
    |> Enum.map(fn %{id: id, mitre_tactics: tactics} ->
      %{id: id, original: tactics, normalized: Mitre.normalize_tactics(tactics)}
    end)
    |> Enum.filter(fn %{original: original, normalized: normalized} ->
      normalized != original
    end)
  end

  # Collapse rows sharing the same normalized result into a single change set
  # carrying the list of ids plus a sample of original values (for reporting).
  defp group_by_normalized(rows) do
    rows
    |> Enum.group_by(& &1.normalized)
    |> Enum.map(fn {normalized, group} ->
      %{
        normalized: normalized,
        ids: Enum.map(group, & &1.id),
        originals: Enum.map(group, & &1.original)
      }
    end)
  end

  # ==========================================================================
  # Accumulator / report
  # ==========================================================================

  defp fresh_acc do
    %{alerts_changed: 0, dropped: %{}, sample: []}
  end

  defp accumulate(acc, %{ids: ids, normalized: normalized, originals: originals}) do
    count = length(ids)

    dropped =
      originals
      |> Enum.reduce(acc.dropped, fn original, dropped ->
        original
        |> dropped_values(normalized)
        |> Enum.reduce(dropped, fn value, d -> Map.update(d, value, 1, &(&1 + 1)) end)
      end)

    sample =
      if length(acc.sample) < 15 do
        acc.sample ++ [{List.first(originals), normalized}]
      else
        acc.sample
      end

    %{acc | alerts_changed: acc.alerts_changed + count, dropped: dropped, sample: sample}
  end

  # Values present in the original list that have no canonical representation in
  # the normalized output (i.e. genuine noise that was discarded).
  defp dropped_values(original, normalized) do
    Enum.filter(original, fn value ->
      case Mitre.normalize_tactic(value) do
        nil -> true
        canonical -> canonical not in normalized
      end
    end)
  end

  defp report(summary, executed?) do
    verb = if executed?, do: "updated", else: "would change"

    Mix.shell().info("""

    MITRE Tactic Backfill
    ══════════════════════════════════════════════════════════════
    Alerts #{verb}: #{summary.alerts_changed}
    """)

    if summary.sample != [] do
      Mix.shell().info("Sample rewrites (original -> normalized):")

      Enum.each(summary.sample, fn {original, normalized} ->
        Mix.shell().info("  #{inspect(original)} -> #{inspect(normalized)}")
      end)
    end

    if summary.dropped != %{} do
      Mix.shell().info("\nDropped non-tactic values (count):")

      summary.dropped
      |> Enum.sort_by(fn {_v, c} -> -c end)
      |> Enum.each(fn {value, count} ->
        Mix.shell().info("  #{String.pad_trailing(inspect(value), 28)} #{count}")
      end)
    end

    Mix.shell().info("""
    ══════════════════════════════════════════════════════════════
    """)

    unless executed? do
      Mix.shell().info("Dry run only. Re-run with --execute to persist these changes.")
    end
  end

  # ==========================================================================
  # Options
  # ==========================================================================

  defp parse_options(args) do
    {opts, _, _} =
      OptionParser.parse(args,
        switches: [execute: :boolean, batch_size: :integer]
      )

    Keyword.put_new(opts, :batch_size, @default_batch_size)
  end
end
