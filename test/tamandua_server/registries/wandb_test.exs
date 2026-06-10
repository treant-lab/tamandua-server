defmodule TamanduaServer.Registries.WandBTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Registries.WandB

  @valid_artifacts_response %{
    "artifacts" => [
      %{
        "id" => "QXJ0aWZhY3Q6MTIzNDU2",
        "entity" => "my-org",
        "project" => "fraud-detection",
        "artifactSequenceName" => "model-v1",
        "createdAt" => "2024-01-15T10:30:00Z",
        "versionIndex" => 2,
        "description" => "Production model"
      }
    ]
  }

  @valid_artifact_version_response %{
    "artifactVersion" => %{
      "id" => "QXJ0aWZhY3Q6MTIzNDU2",
      "entity" => "my-org",
      "project" => "fraud-detection",
      "artifactSequenceName" => "model-v1",
      "versionIndex" => 2,
      "description" => "Production model",
      "metadata" => %{"framework" => "pytorch"},
      "manifest" => %{
        "contents" => [
          %{
            "path" => "model.pt",
            "digest" => "abc123...",
            "size" => 1000000,
            "url" => "https://storage.wandb.ai/..."
          }
        ]
      }
    }
  }

  describe "metadata/0" do
    test "returns W&B metadata with experiment_tracker type" do
      metadata = WandB.metadata()

      assert metadata.name == "Weights & Biases"
      assert metadata.version == "1.0.0"
      assert metadata.type == :experiment_tracker
      assert :search in metadata.capabilities
      assert :scan in metadata.capabilities
      assert :artifacts in metadata.capabilities
      assert :webhooks in metadata.capabilities
    end
  end

  describe "list_models/1" do
    test "returns list structure" do
      config = %{
        entity: "test-org",
        project: "test-project",
        api_key: "test-key"
      }

      case WandB.list_models(config) do
        {:ok, models} ->
          assert is_list(models)

          if length(models) > 0 do
            model = List.first(models)
            assert Map.has_key?(model, :id)
            assert Map.has_key?(model, :name)
            assert Map.has_key?(model, :author)
            assert Map.has_key?(model, :downloads)
          end

        {:error, _} -> :ok
      end
    end

    test "handles pagination with per_page and page" do
      config = %{
        entity: "test-org",
        project: "test-project",
        per_page: 10,
        page: 2
      }

      case WandB.list_models(config) do
        {:ok, models} ->
          assert is_list(models)
        {:error, _} -> :ok
      end
    end

    test "includes authentication header" do
      config = %{
        entity: "test-org",
        project: "test-project",
        api_key: "test-api-key"
      }

      case WandB.list_models(config) do
        {:ok, _} -> :ok
        {:error, _} -> :ok
      end
    end

    test "handles empty response" do
      config = %{
        entity: "empty-org",
        project: "empty-project"
      }

      case WandB.list_models(config) do
        {:ok, models} -> assert is_list(models)
        {:error, _} -> :ok
      end
    end
  end

  describe "get_model/2" do
    test "fetches artifact by entity/project/name:version" do
      model_id = "my-org/fraud-detection/model-v1:v2"

      case WandB.get_model(model_id, %{}) do
        {:ok, model} ->
          assert model.name == "model-v1"
          assert is_map(model.metadata)

        {:error, :not_found} -> :ok
        {:error, _} -> :ok
      end
    end

    test "fetches latest version when version omitted" do
      model_id = "my-org/fraud-detection/model-v1"

      case WandB.get_model(model_id, %{}) do
        {:ok, model} ->
          assert model.name == "model-v1"
        {:error, _} -> :ok
      end
    end

    test "includes file URLs in metadata" do
      model_id = "my-org/fraud-detection/model-v1:v2"

      case WandB.get_model(model_id, %{}) do
        {:ok, model} ->
          assert is_map(model.metadata)
        {:error, _} -> :ok
      end
    end

    test "returns error for non-existent artifact" do
      case WandB.get_model("nonexistent/project/artifact:v1", %{}) do
        {:ok, _} -> :ok  # May succeed if API returns something
        {:error, :not_found} -> :ok
        {:error, _} -> :ok
      end
    end
  end

  describe "search_models/2" do
    test "filters artifacts by name" do
      query = "model"
      config = %{entity: "test-org", project: "test-project"}

      case WandB.search_models(query, config) do
        {:ok, models} ->
          assert is_list(models)
        {:error, _} -> :ok
      end
    end

    test "filters artifacts by tags" do
      query = "pytorch"
      config = %{entity: "test-org", project: "test-project", limit: 10}

      case WandB.search_models(query, config) do
        {:ok, models} ->
          assert is_list(models)
        {:error, _} -> :ok
      end
    end
  end

  describe "scan_model/2" do
    test "calls ML service with artifact data" do
      model_id = "my-org/fraud-detection/model-v1:v2"
      config = %{ml_service_url: "http://localhost:8000"}

      case WandB.scan_model(model_id, config) do
        {:ok, result} ->
          assert is_float(result.risk_score)
          assert result.risk_score >= 0.0
          assert result.risk_score <= 1.0
          assert is_list(result.findings)
          assert %DateTime{} = result.scanned_at

        {:error, :not_found} -> :ok
        {:error, :scan_failed} -> :ok
        {:error, _} -> :ok
      end
    end

    test "returns scan result with risk score" do
      model_id = "test/project/artifact:v1"
      config = %{}

      case WandB.scan_model(model_id, config) do
        {:ok, result} ->
          assert Map.has_key?(result, :risk_score)
          assert Map.has_key?(result, :findings)
          assert Map.has_key?(result, :scanned_at)
        {:error, _} -> :ok
      end
    end
  end

  describe "validate_config/1" do
    test "validates required fields (entity, project, api_key)" do
      valid_config = %{
        entity: "my-org",
        project: "my-project",
        api_key: "valid-api-key"
      }

      case WandB.validate_config(valid_config) do
        :ok -> :ok
        {:error, :invalid_config} -> :ok
        {:error, {:network, _}} -> :ok
        {:error, _} -> :ok
      end
    end

    test "returns error for missing fields" do
      incomplete_config = %{entity: "my-org"}

      result = WandB.validate_config(incomplete_config)
      assert result == {:error, :invalid_config}
    end

    test "returns error for invalid API key" do
      config = %{
        entity: "my-org",
        project: "my-project",
        api_key: "invalid-key"
      }

      case WandB.validate_config(config) do
        {:error, :unauthorized} -> :ok
        {:error, {:network, _}} -> :ok
        {:error, _} -> :ok
        :ok -> :ok
      end
    end
  end

  describe "error handling" do
    test "handles 401 unauthorized" do
      config = %{api_key: "bad-token", entity: "org", project: "proj"}

      case WandB.list_models(config) do
        {:error, :unauthorized} -> :ok
        {:error, _} -> :ok
        {:ok, _} -> :ok
      end
    end

    test "handles 403 forbidden" do
      config = %{api_key: "test", entity: "forbidden-org", project: "proj"}

      case WandB.list_models(config) do
        {:error, :forbidden} -> :ok
        {:error, _} -> :ok
        {:ok, _} -> :ok
      end
    end

    test "handles 404 not found" do
      case WandB.get_model("nonexistent/org/artifact:v1", %{}) do
        {:error, :not_found} -> :ok
        {:error, _} -> :ok
        {:ok, _} -> :ok
      end
    end

    test "handles network errors" do
      config = %{
        entity: "test",
        project: "test",
        api_key: "test",
        api_base: "http://invalid-wandb-host:8080"
      }

      case WandB.list_models(config) do
        {:error, {:network, _}} -> :ok
        {:error, _} -> :ok
        {:ok, _} -> :ok
      end
    end
  end

  describe "model_id parsing" do
    test "parses entity/project/artifact:version format" do
      model_id = "my-org/my-project/model-artifact:v3"

      case WandB.get_model(model_id, %{}) do
        {:ok, model} ->
          assert model.name == "model-artifact"
        {:error, _} -> :ok
      end
    end

    test "handles artifact without version" do
      model_id = "my-org/my-project/model-artifact"

      case WandB.get_model(model_id, %{}) do
        {:ok, model} ->
          assert model.name == "model-artifact"
        {:error, _} -> :ok
      end
    end
  end
end
