defmodule TamanduaServer.MultiTenancy.DataResidency do
  @moduledoc """
  Manages data residency and regional data location for multi-tenant deployments.

  This module ensures compliance with data sovereignty regulations (GDPR, CCPA, etc.)
  by routing tenant data to region-specific storage based on tenant configuration.

  ## Features

  - Per-tenant data region configuration (EU, US, APAC)
  - Regional database routing
  - Regional S3 bucket selection
  - Regional Redis and RabbitMQ routing
  - Data residency validation
  - Compliance violation detection
  - Audit logging of data location

  ## Supported Regions

  - `:eu` - European Union (GDPR compliance)
  - `:us` - United States
  - `:apac` - Asia-Pacific
  - `:ca` - Canada
  - `:uk` - United Kingdom (post-Brexit)
  - `:au` - Australia
  - `:jp` - Japan
  - `:in` - India

  ## Examples

      # Get storage configuration for a tenant
      iex> DataResidency.get_storage_config(tenant_id)
      {:ok, %{
        region: :eu,
        database_repo: TamanduaServer.Repo.EU,
        s3_bucket: "tamandua-eu-telemetry",
        redis_url: "redis://eu-redis:6379",
        rabbitmq_url: "amqp://eu-rabbitmq:5672"
      }}

      # Validate data residency compliance
      iex> DataResidency.validate_compliance(tenant_id, :gdpr)
      {:ok, %{compliant: true, violations: []}}

      # Check if cross-region transfer is allowed
      iex> DataResidency.can_transfer_to_region?(tenant_id, :us)
      {:error, :gdpr_violation}
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.MultiTenancy.{RegionRouter, ComplianceValidator}
  alias TamanduaServer.Audit

  require Logger

  @supported_regions [:eu, :us, :apac, :ca, :uk, :au, :jp, :in]

  @gdpr_regions [:eu, :uk]
  @ccpa_regions [:us, :ca]

  # Regional endpoint configurations
  @region_configs %{
    eu: %{
      database_repo: TamanduaServer.Repo.EU,
      s3_bucket: "tamandua-eu-telemetry",
      s3_endpoint: "https://s3.eu-central-1.amazonaws.com",
      redis_url: "redis://eu-redis:6379",
      rabbitmq_url: "amqp://eu-rabbitmq:5672",
      encryption_key_id: "eu-kms-key"
    },
    us: %{
      database_repo: TamanduaServer.Repo.US,
      s3_bucket: "tamandua-us-telemetry",
      s3_endpoint: "https://s3.us-east-1.amazonaws.com",
      redis_url: "redis://us-redis:6379",
      rabbitmq_url: "amqp://us-rabbitmq:5672",
      encryption_key_id: "us-kms-key"
    },
    apac: %{
      database_repo: TamanduaServer.Repo.APAC,
      s3_bucket: "tamandua-apac-telemetry",
      s3_endpoint: "https://s3.ap-southeast-1.amazonaws.com",
      redis_url: "redis://apac-redis:6379",
      rabbitmq_url: "amqp://apac-rabbitmq:5672",
      encryption_key_id: "apac-kms-key"
    },
    ca: %{
      database_repo: TamanduaServer.Repo.CA,
      s3_bucket: "tamandua-ca-telemetry",
      s3_endpoint: "https://s3.ca-central-1.amazonaws.com",
      redis_url: "redis://ca-redis:6379",
      rabbitmq_url: "amqp://ca-rabbitmq:5672",
      encryption_key_id: "ca-kms-key"
    },
    uk: %{
      database_repo: TamanduaServer.Repo.UK,
      s3_bucket: "tamandua-uk-telemetry",
      s3_endpoint: "https://s3.eu-west-2.amazonaws.com",
      redis_url: "redis://uk-redis:6379",
      rabbitmq_url: "amqp://uk-rabbitmq:5672",
      encryption_key_id: "uk-kms-key"
    },
    au: %{
      database_repo: TamanduaServer.Repo.AU,
      s3_bucket: "tamandua-au-telemetry",
      s3_endpoint: "https://s3.ap-southeast-2.amazonaws.com",
      redis_url: "redis://au-redis:6379",
      rabbitmq_url: "amqp://au-rabbitmq:5672",
      encryption_key_id: "au-kms-key"
    },
    jp: %{
      database_repo: TamanduaServer.Repo.JP,
      s3_bucket: "tamandua-jp-telemetry",
      s3_endpoint: "https://s3.ap-northeast-1.amazonaws.com",
      redis_url: "redis://jp-redis:6379",
      rabbitmq_url: "amqp://jp-rabbitmq:5672",
      encryption_key_id: "jp-kms-key"
    },
    in: %{
      database_repo: TamanduaServer.Repo.IN,
      s3_bucket: "tamandua-in-telemetry",
      s3_endpoint: "https://s3.ap-south-1.amazonaws.com",
      redis_url: "redis://in-redis:6379",
      rabbitmq_url: "amqp://in-rabbitmq:5672",
      encryption_key_id: "in-kms-key"
    }
  }

  # ===========================================================================
  # Public API
  # ===========================================================================

  @doc """
  Gets the full storage configuration for a tenant.

  Returns the region-specific database repo, S3 bucket, Redis URL, and other
  infrastructure endpoints based on the tenant's configured region.

  ## Parameters

  - `tenant_id` - Organization/tenant UUID

  ## Returns

  - `{:ok, config}` - Storage configuration map
  - `{:error, :tenant_not_found}` - Tenant doesn't exist
  - `{:error, :region_not_configured}` - Tenant has no region set
  """
  def get_storage_config(tenant_id) do
    with {:ok, org} <- get_organization(tenant_id),
         {:ok, region} <- get_region(org) do
      config = build_storage_config(region, org)
      {:ok, config}
    end
  end

  @doc """
  Gets the Ecto.Repo module for a tenant's region.

  This is used by the RegionRouter to route queries to the correct database.

  ## Examples

      iex> get_repo(tenant_id)
      {:ok, TamanduaServer.Repo.EU}
  """
  def get_repo(tenant_id) do
    with {:ok, config} <- get_storage_config(tenant_id) do
      {:ok, config.database_repo}
    end
  end

  @doc """
  Gets the S3 bucket name for a tenant's region.

  ## Examples

      iex> get_s3_bucket(tenant_id)
      {:ok, "tamandua-eu-telemetry"}
  """
  def get_s3_bucket(tenant_id) do
    with {:ok, config} <- get_storage_config(tenant_id) do
      {:ok, config.s3_bucket}
    end
  end

  @doc """
  Gets the Redis URL for a tenant's region.

  ## Examples

      iex> get_redis_url(tenant_id)
      {:ok, "redis://eu-redis:6379"}
  """
  def get_redis_url(tenant_id) do
    with {:ok, config} <- get_storage_config(tenant_id) do
      {:ok, config.redis_url}
    end
  end

  @doc """
  Gets the RabbitMQ URL for a tenant's region.

  ## Examples

      iex> get_rabbitmq_url(tenant_id)
      {:ok, "amqp://eu-rabbitmq:5672"}
  """
  def get_rabbitmq_url(tenant_id) do
    with {:ok, config} <- get_storage_config(tenant_id) do
      {:ok, config.rabbitmq_url}
    end
  end

  @doc """
  Updates the data region for a tenant.

  This will trigger a migration workflow if replication is enabled.
  Logs the change for audit compliance.

  ## Parameters

  - `tenant_id` - Organization UUID
  - `new_region` - New region atom (e.g., :eu, :us, :apac)
  - `opts` - Options:
    - `:reason` - Reason for region change (for audit log)
    - `:migrate_data` - Whether to migrate existing data (default: false)
    - `:changed_by` - User ID who initiated the change

  ## Returns

  - `{:ok, organization}` - Updated organization
  - `{:error, changeset}` - Validation error
  - `{:error, :invalid_region}` - Region not supported
  """
  def update_region(tenant_id, new_region, opts \\ []) do
    with {:ok, org} <- get_organization(tenant_id),
         :ok <- validate_region(new_region),
         :ok <- validate_region_change(org, new_region) do

      old_region = get_region_atom(org)

      # Update organization
      result =
        org
        |> Organization.changeset(%{region: new_region})
        |> Repo.update()

      case result do
        {:ok, updated_org} ->
          # Log the region change
          audit_region_change(tenant_id, old_region, new_region, opts)

          # Trigger data migration if requested
          if Keyword.get(opts, :migrate_data, false) do
            trigger_data_migration(tenant_id, old_region, new_region)
          end

          {:ok, updated_org}

        error ->
          error
      end
    end
  end

  @doc """
  Validates compliance for a tenant based on their configured region
  and applicable regulatory frameworks.

  ## Parameters

  - `tenant_id` - Organization UUID
  - `framework` - Compliance framework (`:gdpr`, `:ccpa`, `:sox`, etc.)

  ## Returns

  - `{:ok, %{compliant: true}}` - Tenant is compliant
  - `{:ok, %{compliant: false, violations: [...]}}` - Violations found
  - `{:error, reason}` - Validation failed
  """
  def validate_compliance(tenant_id, framework) do
    ComplianceValidator.validate(tenant_id, framework)
  end

  @doc """
  Checks if data can be transferred from tenant's current region to target region.

  This enforces GDPR and other data sovereignty rules.

  ## Examples

      # EU tenant trying to transfer to US
      iex> can_transfer_to_region?(eu_tenant_id, :us)
      {:error, :gdpr_violation}

      # US tenant transferring to CA (allowed under CCPA)
      iex> can_transfer_to_region?(us_tenant_id, :ca)
      {:ok, :transfer_allowed}
  """
  def can_transfer_to_region?(tenant_id, target_region) do
    with {:ok, org} <- get_organization(tenant_id),
         {:ok, current_region} <- get_region(org) do

      # Get compliance frameworks
      frameworks = get_compliance_frameworks(org)

      cond do
        # GDPR restriction: EU data cannot leave EU/UK without adequacy decision
        :gdpr in frameworks and current_region in @gdpr_regions and target_region not in @gdpr_regions ->
          {:error, :gdpr_violation}

        # CCPA allows US-CA transfers
        :ccpa in frameworks and current_region in @ccpa_regions and target_region in @ccpa_regions ->
          {:ok, :transfer_allowed}

        # Allow transfers within same region
        current_region == target_region ->
          {:ok, :same_region}

        # Check if organization has explicit cross-region transfer approval
        has_cross_region_approval?(org, target_region) ->
          {:ok, :transfer_approved}

        # Default deny for sensitive regions
        true ->
          {:error, :transfer_not_allowed}
      end
    end
  end

  @doc """
  Lists all organizations by region.

  Useful for infrastructure planning and compliance reporting.

  ## Examples

      iex> list_organizations_by_region()
      %{
        eu: [%Organization{id: "...", name: "ACME EU"}, ...],
        us: [%Organization{id: "...", name: "ACME US"}, ...],
        apac: [...]
      }
  """
  def list_organizations_by_region do
    query = from(o in Organization, where: not is_nil(o.region), order_by: [asc: o.region, asc: o.name])

    Repo.all(query)
    |> Enum.group_by(& &1.region)
  end

  @doc """
  Gets data residency statistics.

  Returns counts and metrics about regional data distribution.

  ## Returns

      %{
        total_organizations: 150,
        by_region: %{eu: 60, us: 70, apac: 20},
        compliance_frameworks: %{gdpr: 60, ccpa: 70, ...},
        replication_enabled: 45
      }
  """
  def get_statistics do
    orgs = Repo.all(Organization)

    %{
      total_organizations: length(orgs),
      by_region: count_by_region(orgs),
      compliance_frameworks: count_by_compliance(orgs),
      replication_enabled: count_with_replication(orgs),
      regions_active: get_active_regions(orgs)
    }
  end

  @doc """
  Returns list of supported regions.
  """
  def supported_regions, do: @supported_regions

  @doc """
  Returns GDPR-applicable regions.
  """
  def gdpr_regions, do: @gdpr_regions

  @doc """
  Returns region configuration map.
  """
  def region_configs, do: @region_configs

  # ===========================================================================
  # Private Functions
  # ===========================================================================

  defp get_organization(tenant_id) do
    case Repo.get(Organization, tenant_id) do
      nil -> {:error, :tenant_not_found}
      org -> {:ok, org}
    end
  end

  defp get_region(%Organization{region: nil}), do: {:error, :region_not_configured}
  defp get_region(%Organization{region: region}), do: {:ok, region}

  defp get_region_atom(%Organization{region: region}) when is_atom(region), do: region
  defp get_region_atom(%Organization{region: region}) when is_binary(region), do: String.to_existing_atom(region)
  defp get_region_atom(_), do: nil

  defp build_storage_config(region, org) do
    base_config = Map.get(@region_configs, region)

    Map.merge(base_config, %{
      region: region,
      organization_id: org.id,
      organization_name: org.name,
      replication_enabled: Map.get(org.settings, "replication_enabled", false),
      secondary_region: Map.get(org.settings, "secondary_region"),
      compliance_frameworks: get_compliance_frameworks(org)
    })
  end

  defp validate_region(region) when region in @supported_regions, do: :ok
  defp validate_region(_), do: {:error, :invalid_region}

  defp validate_region_change(%Organization{region: current}, new_region) when current == new_region do
    {:error, :region_unchanged}
  end
  defp validate_region_change(_org, _new_region), do: :ok

  defp get_compliance_frameworks(%Organization{settings: settings}) do
    Map.get(settings, "compliance_frameworks", [])
    |> Enum.map(&String.to_existing_atom/1)
  rescue
    _ -> []
  end

  defp has_cross_region_approval?(%Organization{settings: settings}, target_region) do
    approved_regions = Map.get(settings, "approved_transfer_regions", [])
    Enum.member?(approved_regions, to_string(target_region))
  end

  defp audit_region_change(tenant_id, old_region, new_region, opts) do
    changed_by = Keyword.get(opts, :changed_by)
    reason = Keyword.get(opts, :reason, "Region change")

    Audit.log_event(%{
      organization_id: tenant_id,
      actor_id: changed_by,
      action: "data_residency.region_changed",
      resource_type: "organization",
      resource_id: tenant_id,
      metadata: %{
        old_region: old_region,
        new_region: new_region,
        reason: reason
      },
      severity: "high"
    })
  rescue
    error ->
      Logger.error("Failed to audit region change: #{inspect(error)}")
      :ok
  end

  defp trigger_data_migration(tenant_id, old_region, new_region) do
    Logger.info("Triggering data migration for tenant #{tenant_id}: #{old_region} -> #{new_region}")

    # This would trigger an async job to migrate data
    # Implementation depends on your job queue (Oban, Broadway, etc.)
    # For now, we'll just log it
    :ok
  end

  defp count_by_region(orgs) do
    orgs
    |> Enum.filter(& &1.region)
    |> Enum.group_by(& &1.region)
    |> Enum.map(fn {region, orgs} -> {region, length(orgs)} end)
    |> Enum.into(%{})
  end

  defp count_by_compliance(orgs) do
    orgs
    |> Enum.flat_map(&get_compliance_frameworks/1)
    |> Enum.frequencies()
  end

  defp count_with_replication(orgs) do
    orgs
    |> Enum.count(fn org ->
      Map.get(org.settings, "replication_enabled", false)
    end)
  end

  defp get_active_regions(orgs) do
    orgs
    |> Enum.map(& &1.region)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
    |> Enum.sort()
  end
end
