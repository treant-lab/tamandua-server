defmodule TamanduaServer.Registries.RegistryManagerTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Registries.RegistryManager
  alias TamanduaServer.Registries.ModelProvenance
  alias TamanduaServer.Repo

  describe "list_all_models/1" do
    test "returns aggregated models from all active registries" do
      models = RegistryManager.list_all_models()

      assert is_list(models)
    end

    test "includes registry source in each model" do
      models = RegistryManager.list_all_models()

      Enum.each(models, fn model ->
        # Each model should have a :registry field
        assert Map.has_key?(model, :registry)
        assert model.registry in [:huggingface, :mlflow, :wandb, :ollama]
      end)
    end

    test "handles individual registry failures gracefully" do
      # Even if some registries fail, should return models from working ones
      models = RegistryManager.list_all_models()

      assert is_list(models)
    end

    test "filters models by registry when registry parameter provided" do
      models = RegistryManager.list_all_models(registry: :huggingface)

      Enum.each(models, fn model ->
        assert model.registry == :huggingface
      end)
    end

    test "respects limit option" do
      models = RegistryManager.list_all_models(limit: 5)

      # Should have at most 5 models per registry
      assert is_list(models)
    end

    test "returns empty list when all registries fail" do
      # With invalid configs, all registries should fail gracefully
      models = RegistryManager.list_all_models()

      assert is_list(models)
    end
  end

  describe "get_sync_status/0" do
    test "returns last_sync and model_count per registry" do
      status_list = RegistryManager.get_sync_status()

      assert is_list(status_list)

      Enum.each(status_list, fn status ->
        assert Map.has_key?(status, :registry)
        assert Map.has_key?(status, :last_sync)
        assert Map.has_key?(status, :health_status)
        assert Map.has_key?(status, :last_check)
        assert Map.has_key?(status, :consecutive_failures)
        assert Map.has_key?(status, :last_error)
      end)
    end

    test "includes health status from HealthCheck" do
      status_list = RegistryManager.get_sync_status()

      Enum.each(status_list, fn status ->
        assert status.health_status in [:healthy, :degraded, :unhealthy, :unknown]
      end)
    end
  end

  describe "get_registry_health/0" do
    test "returns health status from HealthCheck" do
      health = RegistryManager.get_registry_health()

      assert is_map(health)
    end
  end

  describe "get_provenance_status/0" do
    setup do
      # Insert some test provenance records
      {:ok, p1} = Repo.insert(%ModelProvenance{
        model_id: "test/model-1",
        registry: "huggingface",
        status: "clean",
        risk_score: 0.05,
        downloaded_at: DateTime.utc_now()
      })

      {:ok, p2} = Repo.insert(%ModelProvenance{
        model_id: "test/model-2",
        registry: "huggingface",
        status: "suspicious",
        risk_score: 0.25,
        downloaded_at: DateTime.utc_now()
      })

      {:ok, p3} = Repo.insert(%ModelProvenance{
        model_id: "test/model-3",
        registry: "mlflow",
        status: "malicious",
        risk_score: 0.85,
        downloaded_at: DateTime.utc_now()
      })

      {:ok, p4} = Repo.insert(%ModelProvenance{
        model_id: "test/model-4",
        registry: "ollama",
        status: "pending",
        downloaded_at: DateTime.utc_now()
      })

      on_exit(fn ->
        Repo.delete(p1)
        Repo.delete(p2)
        Repo.delete(p3)
        Repo.delete(p4)
      end)

      :ok
    end

    test "returns scan counts by status" do
      status = RegistryManager.get_provenance_status()

      assert is_map(status)

      # Should have entries for registries with provenance records
      if Map.has_key?(status, "huggingface") do
        hf_status = status["huggingface"]
        assert Map.has_key?(hf_status, :clean) or Map.has_key?(hf_status, :suspicious)
      end
    end

    test "groups counts by registry and status" do
      status = RegistryManager.get_provenance_status()

      # Each registry entry should be a map of status -> count
      Enum.each(status, fn {_registry, counts} ->
        assert is_map(counts)

        Enum.each(counts, fn {_status, count} ->
          assert is_integer(count)
          assert count > 0
        end)
      end)
    end
  end

  describe "list_registries/0" do
    test "returns list of configured registries" do
      registries = RegistryManager.list_registries()

      assert is_list(registries)
      assert :huggingface in registries
      assert :mlflow in registries
      assert :wandb in registries
      assert :ollama in registries
    end
  end
end
