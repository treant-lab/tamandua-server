defmodule TamanduaServer.MultiTenancy.DataResidencyTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.MultiTenancy.DataResidency
  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Tenants

  describe "get_storage_config/1" do
    test "returns EU storage config for EU tenant" do
      {:ok, org} = create_org_with_region(:eu)

      assert {:ok, config} = DataResidency.get_storage_config(org.id)
      assert config.region == :eu
      assert config.database_repo == TamanduaServer.Repo.EU
      assert config.s3_bucket == "tamandua-eu-telemetry"
      assert config.redis_url == "redis://eu-redis:6379"
      assert config.rabbitmq_url == "amqp://eu-rabbitmq:5672"
      assert config.encryption_key_id == "eu-kms-key"
    end

    test "returns US storage config for US tenant" do
      {:ok, org} = create_org_with_region(:us)

      assert {:ok, config} = DataResidency.get_storage_config(org.id)
      assert config.region == :us
      assert config.database_repo == TamanduaServer.Repo.US
      assert config.s3_bucket == "tamandua-us-telemetry"
    end

    test "returns APAC storage config for APAC tenant" do
      {:ok, org} = create_org_with_region(:apac)

      assert {:ok, config} = DataResidency.get_storage_config(org.id)
      assert config.region == :apac
      assert config.database_repo == TamanduaServer.Repo.APAC
    end

    test "returns error for tenant without region" do
      {:ok, org} = create_org_with_region(nil)

      assert {:error, :region_not_configured} = DataResidency.get_storage_config(org.id)
    end

    test "returns error for non-existent tenant" do
      assert {:error, :tenant_not_found} = DataResidency.get_storage_config(Ecto.UUID.generate())
    end
  end

  describe "get_repo/1" do
    test "returns correct repo for each region" do
      regions_repos = [
        {:eu, TamanduaServer.Repo.EU},
        {:us, TamanduaServer.Repo.US},
        {:apac, TamanduaServer.Repo.APAC},
        {:ca, TamanduaServer.Repo.CA},
        {:uk, TamanduaServer.Repo.UK},
        {:au, TamanduaServer.Repo.AU},
        {:jp, TamanduaServer.Repo.JP},
        {:in, TamanduaServer.Repo.IN}
      ]

      Enum.each(regions_repos, fn {region, expected_repo} ->
        {:ok, org} = create_org_with_region(region)
        assert {:ok, ^expected_repo} = DataResidency.get_repo(org.id)
      end)
    end
  end

  describe "get_s3_bucket/1" do
    test "returns correct S3 bucket for region" do
      {:ok, org} = create_org_with_region(:eu)
      assert {:ok, "tamandua-eu-telemetry"} = DataResidency.get_s3_bucket(org.id)
    end
  end

  describe "update_region/2" do
    test "updates tenant region successfully" do
      {:ok, org} = create_org_with_region(:eu)

      assert {:ok, updated_org} = DataResidency.update_region(org.id, :us, reason: "Migration to US")
      assert updated_org.region == :us
    end

    test "rejects invalid region" do
      {:ok, org} = create_org_with_region(:eu)

      assert {:error, :invalid_region} = DataResidency.update_region(org.id, :invalid_region)
    end

    test "rejects same region" do
      {:ok, org} = create_org_with_region(:eu)

      assert {:error, :region_unchanged} = DataResidency.update_region(org.id, :eu)
    end

    test "rejects non-existent tenant" do
      assert {:error, :tenant_not_found} = DataResidency.update_region(Ecto.UUID.generate(), :us)
    end
  end

  describe "can_transfer_to_region?/2" do
    test "allows transfer within GDPR regions" do
      {:ok, org} = create_org_with_gdpr(:eu)

      assert {:ok, :transfer_allowed} = DataResidency.can_transfer_to_region?(org.id, :uk)
    end

    test "blocks GDPR to non-GDPR transfer" do
      {:ok, org} = create_org_with_gdpr(:eu)

      assert {:error, :gdpr_violation} = DataResidency.can_transfer_to_region?(org.id, :us)
    end

    test "allows CCPA transfers within US/CA" do
      {:ok, org} = create_org_with_ccpa(:us)

      assert {:ok, :transfer_allowed} = DataResidency.can_transfer_to_region?(org.id, :ca)
    end

    test "allows same region transfer" do
      {:ok, org} = create_org_with_region(:eu)

      assert {:ok, :same_region} = DataResidency.can_transfer_to_region?(org.id, :eu)
    end

    test "allows transfer with explicit approval" do
      {:ok, org} = create_org_with_approved_transfer(:eu, [:us, :apac])

      assert {:ok, :transfer_approved} = DataResidency.can_transfer_to_region?(org.id, :us)
    end

    test "blocks unauthorized transfers" do
      {:ok, org} = create_org_with_region(:us)

      assert {:error, :transfer_not_allowed} = DataResidency.can_transfer_to_region?(org.id, :apac)
    end
  end

  describe "validate_compliance/2" do
    test "validates GDPR compliance for EU tenant" do
      {:ok, org} = create_org_with_gdpr(:eu)

      assert {:ok, result} = DataResidency.validate_compliance(org.id, :gdpr)
      assert result.framework == :gdpr
      assert is_list(result.checks)
      assert is_list(result.violations)
    end

    test "rejects unsupported framework" do
      {:ok, org} = create_org_with_region(:eu)

      assert {:error, {:unsupported_framework, :invalid}} =
               DataResidency.validate_compliance(org.id, :invalid)
    end
  end

  describe "list_organizations_by_region/0" do
    test "groups organizations by region" do
      {:ok, _eu_org} = create_org_with_region(:eu)
      {:ok, _us_org1} = create_org_with_region(:us)
      {:ok, _us_org2} = create_org_with_region(:us)
      {:ok, _apac_org} = create_org_with_region(:apac)

      result = DataResidency.list_organizations_by_region()

      assert is_map(result)
      assert length(result[:eu]) == 1
      assert length(result[:us]) == 2
      assert length(result[:apac]) == 1
    end
  end

  describe "get_statistics/0" do
    test "returns accurate statistics" do
      {:ok, _eu_org} = create_org_with_region(:eu)
      {:ok, _us_org} = create_org_with_region(:us)
      {:ok, org_with_replication} = create_org_with_replication(:apac, :us)

      stats = DataResidency.get_statistics()

      assert stats.total_organizations >= 3
      assert stats.by_region[:eu] >= 1
      assert stats.by_region[:us] >= 1
      assert stats.by_region[:apac] >= 1
      assert stats.replication_enabled >= 1
      assert :eu in stats.regions_active
      assert :us in stats.regions_active
      assert :apac in stats.regions_active
    end
  end

  describe "supported_regions/0" do
    test "returns all supported regions" do
      regions = DataResidency.supported_regions()

      assert :eu in regions
      assert :us in regions
      assert :apac in regions
      assert :ca in regions
      assert :uk in regions
      assert :au in regions
      assert :jp in regions
      assert :in in regions
    end
  end

  describe "gdpr_regions/0" do
    test "returns GDPR-applicable regions" do
      regions = DataResidency.gdpr_regions()

      assert :eu in regions
      assert :uk in regions
      refute :us in regions
    end
  end

  # Helper functions

  defp create_org_with_region(region) do
    attrs = %{
      name: "Test Org #{:rand.uniform(10000)}",
      slug: "test-org-#{:rand.uniform(10000)}",
      region: region
    }

    Tenants.create_organization(attrs)
  end

  defp create_org_with_gdpr(region) do
    attrs = %{
      name: "GDPR Org #{:rand.uniform(10000)}",
      slug: "gdpr-org-#{:rand.uniform(10000)}",
      region: region,
      settings: %{
        "compliance_frameworks" => ["gdpr"]
      }
    }

    Tenants.create_organization(attrs)
  end

  defp create_org_with_ccpa(region) do
    attrs = %{
      name: "CCPA Org #{:rand.uniform(10000)}",
      slug: "ccpa-org-#{:rand.uniform(10000)}",
      region: region,
      settings: %{
        "compliance_frameworks" => ["ccpa"]
      }
    }

    Tenants.create_organization(attrs)
  end

  defp create_org_with_approved_transfer(region, approved_regions) do
    attrs = %{
      name: "Transfer Org #{:rand.uniform(10000)}",
      slug: "transfer-org-#{:rand.uniform(10000)}",
      region: region,
      settings: %{
        "approved_transfer_regions" => Enum.map(approved_regions, &to_string/1)
      }
    }

    Tenants.create_organization(attrs)
  end

  defp create_org_with_replication(primary_region, secondary_region) do
    attrs = %{
      name: "Replication Org #{:rand.uniform(10000)}",
      slug: "replication-org-#{:rand.uniform(10000)}",
      region: primary_region,
      settings: %{
        "replication_enabled" => true,
        "secondary_region" => to_string(secondary_region)
      }
    }

    Tenants.create_organization(attrs)
  end
end
