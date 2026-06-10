defmodule TamanduaServer.MultiTenancy.RegionRouterTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.MultiTenancy.RegionRouter
  alias TamanduaServer.Tenants

  describe "with_repo/2" do
    test "executes function with correct repo" do
      {:ok, org} = create_org_with_region(:eu)

      result =
        RegionRouter.with_repo(org.id, fn repo ->
          assert repo == TamanduaServer.Repo.EU
          :success
        end)

      assert {:ok, :success} = result
    end

    test "returns error for non-existent tenant" do
      result =
        RegionRouter.with_repo(Ecto.UUID.generate(), fn _repo ->
          :should_not_execute
        end)

      assert {:error, :tenant_not_found} = result
    end
  end

  describe "get_repo/1" do
    test "returns correct repo for EU tenant" do
      {:ok, org} = create_org_with_region(:eu)

      assert {:ok, TamanduaServer.Repo.EU} = RegionRouter.get_repo(org.id)
    end

    test "returns correct repo for US tenant" do
      {:ok, org} = create_org_with_region(:us)

      assert {:ok, TamanduaServer.Repo.US} = RegionRouter.get_repo(org.id)
    end

    test "returns correct repo for APAC tenant" do
      {:ok, org} = create_org_with_region(:apac)

      assert {:ok, TamanduaServer.Repo.APAC} = RegionRouter.get_repo(org.id)
    end
  end

  describe "repo/0" do
    test "returns repo from process dictionary" do
      {:ok, org} = create_org_with_region(:eu)

      RegionRouter.put_tenant_id(org.id)
      assert RegionRouter.repo() == TamanduaServer.Repo.EU

      RegionRouter.clear_tenant_id()
    end

    test "returns default repo when no tenant_id set" do
      RegionRouter.clear_tenant_id()
      assert RegionRouter.repo() == TamanduaServer.Repo
    end
  end

  describe "put_tenant_id/1 and clear_tenant_id/0" do
    test "sets and clears tenant_id in process dictionary" do
      tenant_id = Ecto.UUID.generate()

      assert :ok = RegionRouter.put_tenant_id(tenant_id)
      assert Process.get(:current_tenant_id) == tenant_id

      assert :ok = RegionRouter.clear_tenant_id()
      assert Process.get(:current_tenant_id) == nil
    end
  end

  describe "get_s3_bucket/1" do
    test "returns EU bucket for EU tenant" do
      {:ok, org} = create_org_with_region(:eu)

      assert {:ok, "tamandua-eu-telemetry"} = RegionRouter.get_s3_bucket(org.id)
    end

    test "returns US bucket for US tenant" do
      {:ok, org} = create_org_with_region(:us)

      assert {:ok, "tamandua-us-telemetry"} = RegionRouter.get_s3_bucket(org.id)
    end
  end

  describe "get_redis_url/1" do
    test "returns EU Redis URL for EU tenant" do
      {:ok, org} = create_org_with_region(:eu)

      assert {:ok, "redis://eu-redis:6379"} = RegionRouter.get_redis_url(org.id)
    end

    test "returns US Redis URL for US tenant" do
      {:ok, org} = create_org_with_region(:us)

      assert {:ok, "redis://us-redis:6379"} = RegionRouter.get_redis_url(org.id)
    end
  end

  describe "get_rabbitmq_url/1" do
    test "returns EU RabbitMQ URL for EU tenant" do
      {:ok, org} = create_org_with_region(:eu)

      assert {:ok, "amqp://eu-rabbitmq:5672"} = RegionRouter.get_rabbitmq_url(org.id)
    end

    test "returns US RabbitMQ URL for US tenant" do
      {:ok, org} = create_org_with_region(:us)

      assert {:ok, "amqp://us-rabbitmq:5672"} = RegionRouter.get_rabbitmq_url(org.id)
    end
  end

  describe "health_check/1" do
    test "returns health status for tenant infrastructure" do
      {:ok, org} = create_org_with_region(:eu)

      assert {:ok, health} = RegionRouter.health_check(org.id)
      assert health.region == :eu
      assert is_atom(health.database)
      assert is_atom(health.s3)
      assert is_atom(health.redis)
      assert is_atom(health.rabbitmq)
      assert is_atom(health.overall)
    end
  end

  describe "region_health/1" do
    test "returns health for specific region" do
      assert {:ok, health} = RegionRouter.region_health(:eu)
      assert health.region == :eu
      assert is_atom(health.database)
    end

    test "returns error for invalid region" do
      assert {:error, :invalid_region} = RegionRouter.region_health(:invalid)
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
end
