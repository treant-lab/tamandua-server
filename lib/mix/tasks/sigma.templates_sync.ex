defmodule Mix.Tasks.Sigma.TemplatesSync do
  @moduledoc """
  Sync Sigma templates to all organizations.

  This task copies system Sigma rule templates to all existing organizations
  that don't already have them. Useful for:

  - Backfilling templates to organizations created before templates existed
  - Adding newly created templates to all organizations
  - Verifying template coverage across organizations

  ## Usage

      # Sync templates to all active organizations
      mix sigma.templates_sync

      # Include inactive organizations
      mix sigma.templates_sync --all

      # Dry run (show what would be done without making changes)
      mix sigma.templates_sync --dry-run

      # Force re-copy even if templates exist
      mix sigma.templates_sync --force

      # Show detailed status for each organization
      mix sigma.templates_sync --verbose

  ## Options

    * `--all` - Include inactive organizations (default: active only)
    * `--dry-run` - Show what would be done without making changes
    * `--force` - Re-copy templates even if they already exist
    * `--verbose` - Show detailed output for each organization
    * `--org` - Sync to a specific organization by ID or slug

  ## Examples

      # Standard backfill
      mix sigma.templates_sync

      # Check status without making changes
      mix sigma.templates_sync --dry-run --verbose

      # Force full re-sync
      mix sigma.templates_sync --force

      # Sync specific organization
      mix sigma.templates_sync --org acme-corp
  """

  use Mix.Task

  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Accounts.OrganizationSetup
  alias TamanduaServer.Detection.SigmaTemplates

  import Ecto.Query

  @shortdoc "Sync Sigma templates to all organizations"

  @impl Mix.Task
  def run(args) do
    Mix.Task.run("app.start")

    {opts, _args, _} =
      OptionParser.parse(args,
        switches: [
          all: :boolean,
          dry_run: :boolean,
          force: :boolean,
          verbose: :boolean,
          org: :string
        ],
        aliases: [a: :all, n: :dry_run, f: :force, v: :verbose, o: :org]
      )

    active_only = !Keyword.get(opts, :all, false)
    dry_run = Keyword.get(opts, :dry_run, false)
    force = Keyword.get(opts, :force, false)
    verbose = Keyword.get(opts, :verbose, false)
    org_filter = Keyword.get(opts, :org)

    # Show template count
    template_count = SigmaTemplates.list_system_templates() |> length()
    Mix.shell().info("Found #{template_count} system Sigma templates")

    if template_count == 0 do
      Mix.shell().info("No templates to sync. Create templates first with is_system_template: true")
      exit(:normal)
    end

    # Get organizations to process
    organizations = get_organizations(org_filter, active_only)

    if length(organizations) == 0 do
      Mix.shell().info("No organizations found matching criteria")
      exit(:normal)
    end

    Mix.shell().info(
      "Syncing to #{length(organizations)} organization(s)" <>
        if(dry_run, do: " (DRY RUN)", else: "") <>
        if(force, do: " (FORCE)", else: "")
    )

    Mix.shell().info("")

    # Process each organization
    results =
      Enum.map(organizations, fn org ->
        process_organization(org, dry_run, force, verbose)
      end)

    # Summary
    Mix.shell().info("")
    Mix.shell().info("=" |> String.duplicate(60))

    total_copied = Enum.sum(Enum.map(results, fn r -> r.copied end))
    total_skipped = Enum.sum(Enum.map(results, fn r -> r.skipped end))
    total_errors = Enum.sum(Enum.map(results, fn r -> r.errors end))

    Mix.shell().info("Summary:")
    Mix.shell().info("  Organizations processed: #{length(results)}")
    Mix.shell().info("  Templates copied: #{total_copied}")
    Mix.shell().info("  Templates skipped: #{total_skipped}")

    if total_errors > 0 do
      Mix.shell().error("  Errors: #{total_errors}")
    end

    if dry_run do
      Mix.shell().info("\n[DRY RUN] No changes were made. Remove --dry-run to apply.")
    else
      Mix.shell().info("\nDone!")
    end
  end

  defp get_organizations(nil, active_only) do
    query =
      if active_only do
        from(o in Organization, where: o.is_active == true, order_by: [asc: o.name])
      else
        from(o in Organization, order_by: [asc: o.name])
      end

    Repo.all(query)
  end

  defp get_organizations(org_filter, _active_only) do
    # Try to find by ID first, then by slug
    case Ecto.UUID.cast(org_filter) do
      {:ok, uuid} ->
        case Repo.get(Organization, uuid) do
          nil -> []
          org -> [org]
        end

      :error ->
        case Repo.get_by(Organization, slug: org_filter) do
          nil -> []
          org -> [org]
        end
    end
  end

  defp process_organization(org, dry_run, force, verbose) do
    status = OrganizationSetup.check_setup_status(org)
    missing = status.sigma_templates.missing

    if verbose do
      Mix.shell().info("Organization: #{org.name} (#{org.slug})")
      Mix.shell().info("  ID: #{org.id}")
      Mix.shell().info("  Templates: #{status.sigma_templates.copied}/#{status.sigma_templates.available}")
      Mix.shell().info("  Missing: #{missing}")
    end

    cond do
      missing == 0 and not force ->
        if verbose do
          Mix.shell().info("  Status: Up to date")
          Mix.shell().info("")
        end

        %{org: org, copied: 0, skipped: status.sigma_templates.copied, errors: 0}

      dry_run ->
        to_copy = if force, do: status.sigma_templates.available, else: missing

        if verbose do
          Mix.shell().info("  [DRY RUN] Would copy #{to_copy} templates")
          Mix.shell().info("")
        end

        %{org: org, copied: 0, skipped: 0, errors: 0}

      true ->
        opts =
          if force do
            [skip_existing: false]
          else
            [skip_existing: true]
          end

        case SigmaTemplates.copy_templates_to_organization(org.id, opts) do
          {:ok, copies} when is_list(copies) ->
            if verbose do
              Mix.shell().info("  Copied: #{length(copies)} templates")
              Mix.shell().info("")
            end

            %{org: org, copied: length(copies), skipped: 0, errors: 0}

          {:error, {:partial_failure, results}} ->
            copied = Enum.count(results, fn {s, _} -> s == :ok end)
            errors = Enum.count(results, fn {s, _} -> s == :error end)

            if verbose do
              Mix.shell().info("  Copied: #{copied}, Errors: #{errors}")
              Mix.shell().info("")
            end

            %{org: org, copied: copied, skipped: 0, errors: errors}

          {:error, reason} ->
            Mix.shell().error("  Error: #{inspect(reason)}")
            %{org: org, copied: 0, skipped: 0, errors: 1}
        end
    end
  end
end
