defmodule TamanduaServer.Accounts.OrganizationSetup do
  @moduledoc """
  Handles post-creation setup for new organizations.

  This module is responsible for provisioning default resources when a new
  organization is created. It ensures that every organization starts with:

  - Sigma detection rule templates (copied from system templates)
  - Default configuration settings
  - Any other baseline resources

  ## Usage

  This module is automatically called when an organization is created through
  the standard creation flow in `TamanduaServer.Accounts` or `TamanduaServer.Tenants`.

  For manual setup or re-provisioning:

      # Full setup for a new organization
      OrganizationSetup.setup_new_organization(organization)

      # Copy only Sigma templates
      OrganizationSetup.copy_sigma_templates(organization)

  ## Backfilling Existing Organizations

  For existing organizations that need templates copied:

      mix sigma.templates_sync

  Or programmatically:

      OrganizationSetup.backfill_all_organizations()
  """

  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Detection.SigmaTemplates

  require Logger

  @doc """
  Sets up a newly created organization with default resources.

  Called after organization insertion to provision:
  - Sigma rule templates
  - Default settings (future)

  Returns `{:ok, organization}` on success or `{:error, reason}` on failure.

  ## Options

  - `:skip_sigma_templates` - Skip copying Sigma templates (default: false)
  - `:skip_settings` - Skip creating default settings (default: false)

  ## Examples

      iex> setup_new_organization(organization)
      {:ok, organization}

      iex> setup_new_organization(organization, skip_sigma_templates: true)
      {:ok, organization}
  """
  @spec setup_new_organization(Organization.t(), keyword()) ::
          {:ok, Organization.t()} | {:error, term()}
  def setup_new_organization(%Organization{} = organization, opts \\ []) do
    skip_sigma = Keyword.get(opts, :skip_sigma_templates, false)
    skip_settings = Keyword.get(opts, :skip_settings, false)

    Logger.info("Setting up new organization: #{organization.id} (#{organization.name})")

    with {:ok, _} <- maybe_copy_sigma_templates(organization, skip_sigma),
         {:ok, _} <- maybe_create_default_settings(organization, skip_settings) do
      Logger.info("Organization setup complete: #{organization.id}")
      {:ok, organization}
    else
      {:error, reason} = error ->
        Logger.error(
          "Organization setup failed for #{organization.id}: #{inspect(reason)}"
        )
        error
    end
  end

  @doc """
  Copies Sigma templates to an organization.

  This is a wrapper around `SigmaTemplates.copy_templates_to_organization/2`
  that handles logging and error formatting.

  ## Options

  - `:enabled_only` - Only copy enabled templates (default: true)
  - `:skip_existing` - Skip templates already copied (default: true)
  """
  @spec copy_sigma_templates(Organization.t(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def copy_sigma_templates(%Organization{id: org_id} = _organization, opts \\ []) do
    Logger.info("Copying Sigma templates to organization: #{org_id}")

    case SigmaTemplates.copy_templates_to_organization(org_id, opts) do
      {:ok, copies} when is_list(copies) ->
        Logger.info("Copied #{length(copies)} Sigma templates to organization: #{org_id}")
        {:ok, %{copied: length(copies), organization_id: org_id}}

      {:error, {:partial_failure, results}} ->
        copies = Enum.count(results, fn {status, _} -> status == :ok end)
        errors = Enum.count(results, fn {status, _} -> status == :error end)

        Logger.warning(
          "Partial Sigma template copy for organization #{org_id}: " <>
            "#{copies} copied, #{errors} failed"
        )

        {:ok, %{copied: copies, errors: errors, organization_id: org_id}}

      {:error, reason} = error ->
        Logger.error("Failed to copy Sigma templates to organization #{org_id}: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Creates default settings for an organization.

  Currently a placeholder for future settings provisioning.
  """
  @spec create_default_settings(Organization.t()) :: {:ok, Organization.t()}
  def create_default_settings(%Organization{} = organization) do
    # Future: Create default notification settings, retention policies, etc.
    {:ok, organization}
  end

  @doc """
  Backfills Sigma templates for all existing organizations.

  Useful for adding new system templates to organizations that were created
  before the templates existed.

  ## Options

  - `:dry_run` - Only report what would be done, don't make changes (default: false)
  - `:active_only` - Only process active organizations (default: true)

  ## Returns

  A map with summary statistics:

      %{
        organizations_processed: 10,
        organizations_skipped: 2,
        total_copies: 50,
        errors: 0
      }
  """
  @spec backfill_all_organizations(keyword()) :: {:ok, map()}
  def backfill_all_organizations(opts \\ []) do
    dry_run = Keyword.get(opts, :dry_run, false)
    active_only = Keyword.get(opts, :active_only, true)

    query =
      if active_only do
        import Ecto.Query
        from(o in Organization, where: o.is_active == true)
      else
        Organization
      end

    organizations = Repo.all(query)
    template_count = SigmaTemplates.list_system_templates() |> length()

    Logger.info(
      "Backfilling #{template_count} Sigma templates to #{length(organizations)} organizations" <>
        if(dry_run, do: " (DRY RUN)", else: "")
    )

    results =
      Enum.reduce(organizations, %{processed: 0, skipped: 0, copied: 0, errors: 0}, fn org, acc ->
        if dry_run do
          Logger.info("[DRY RUN] Would copy templates to organization: #{org.name} (#{org.id})")
          %{acc | processed: acc.processed + 1}
        else
          case copy_sigma_templates(org) do
            {:ok, %{copied: copied}} ->
              %{acc | processed: acc.processed + 1, copied: acc.copied + copied}

            {:error, _reason} ->
              %{acc | errors: acc.errors + 1}
          end
        end
      end)

    Logger.info(
      "Backfill complete: #{results.processed} organizations processed, " <>
        "#{results.copied} templates copied, #{results.errors} errors"
    )

    {:ok,
     %{
       organizations_processed: results.processed,
       organizations_skipped: results.skipped,
       total_copies: results.copied,
       errors: results.errors
     }}
  end

  @doc """
  Checks setup status for an organization.

  Returns information about what has been provisioned.
  """
  @spec check_setup_status(Organization.t()) :: map()
  def check_setup_status(%Organization{id: org_id}) do
    import Ecto.Query
    alias TamanduaServer.Detection.SigmaRule

    sigma_template_count = SigmaTemplates.list_system_templates() |> length()

    sigma_copied_count =
      from(r in SigmaRule,
        where: r.organization_id == ^org_id and not is_nil(r.copied_from_template_id),
        select: count()
      )
      |> Repo.one()

    %{
      organization_id: org_id,
      sigma_templates: %{
        available: sigma_template_count,
        copied: sigma_copied_count,
        missing: max(0, sigma_template_count - sigma_copied_count)
      },
      setup_complete: sigma_copied_count >= sigma_template_count
    }
  end

  # Private functions

  defp maybe_copy_sigma_templates(_organization, true = _skip), do: {:ok, :skipped}

  defp maybe_copy_sigma_templates(organization, false = _skip) do
    copy_sigma_templates(organization)
  end

  defp maybe_create_default_settings(_organization, true = _skip), do: {:ok, :skipped}

  defp maybe_create_default_settings(organization, false = _skip) do
    create_default_settings(organization)
  end
end
