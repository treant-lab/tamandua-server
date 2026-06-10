defmodule Mix.Tasks.Mitre.Sync do
  @moduledoc """
  Sync detection rule mappings to MITRE techniques.

  This task scans all Sigma and YARA rules, extracts MITRE technique tags,
  and creates/updates the technique_mappings table for coverage tracking.

  ## Usage

      # Sync all rules for all organizations
      mix mitre.sync

      # Sync for specific organization
      mix mitre.sync --org <org_id>

      # Verbose output
      mix mitre.sync --verbose

  ## Options

    * `--org` - Organization ID (UUID) to sync, default: all
    * `--verbose` - Show detailed output

  ## Examples

      # Sync all rules
      mix mitre.sync

      # Sync for one org with details
      mix mitre.sync --org 123e4567-e89b-12d3-a456-426614174000 --verbose
  """

  use Mix.Task

  alias TamanduaServer.Mitre.TechniqueMapper

  @shortdoc "Sync detection rule to technique mappings"

  @impl Mix.Task
  def run(args) do
    Mix.Task.run("app.start")

    {opts, _args, _} = OptionParser.parse(args,
      switches: [org: :string, verbose: :boolean],
      aliases: [o: :org, v: :verbose]
    )

    org_id = Keyword.get(opts, :org)
    verbose = Keyword.get(opts, :verbose, false)

    if verbose do
      Mix.shell().info("Syncing technique mappings#{if org_id, do: " for org #{org_id}", else: " for all organizations"}...")
    end

    case TechniqueMapper.sync_all_mappings(org_id) do
      {:ok, counts} ->
        Mix.shell().info("✓ Sync completed successfully!")
        Mix.shell().info("  - Sigma rules: #{counts.sigma}")
        Mix.shell().info("  - YARA rules: #{counts.yara}")

        if verbose do
          Mix.shell().info("\nTo view coverage:")
          Mix.shell().info("  iex> TamanduaServer.Detection.Mitre.get_coverage()")
        end

      {:error, reason} ->
        Mix.shell().error("✗ Sync failed: #{inspect(reason)}")
        exit(:shutdown)
    end
  end
end
