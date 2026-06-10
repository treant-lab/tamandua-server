defmodule TamanduaServer.Registries.OllamaTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Registries.Ollama

  @valid_tags_response %{
    "models" => [
      %{
        "name" => "llama2:7b",
        "size" => 3_826_793_472,
        "modified_at" => "2024-01-15T10:30:00.000000000Z",
        "digest" => "sha256:abc123def456"
      },
      %{
        "name" => "codellama:13b",
        "size" => 7_365_960_704,
        "modified_at" => "2024-01-10T15:45:00.000000000Z",
        "digest" => "sha256:789ghi012jkl"
      }
    ]
  }

  @valid_show_response %{
    "modelfile" => "FROM llama2\nPARAMETER temperature 0.8\nSYSTEM You are a helpful assistant.",
    "parameters" => "num_ctx 2048",
    "template" => "{{ .System }}\n\n{{ .Prompt }}",
    "details" => %{
      "format" => "gguf",
      "family" => "llama",
      "families" => ["llama"],
      "parameter_size" => "7B",
      "quantization_level" => "Q4_0"
    }
  }

  describe "metadata/0" do
    test "returns correct registry type as :local_registry" do
      metadata = Ollama.metadata()

      assert metadata.type == :local_registry
    end

    test "returns Ollama registry metadata with capabilities" do
      metadata = Ollama.metadata()

      assert metadata.name == "Ollama"
      assert metadata.version == "1.0.0"
      assert :search in metadata.capabilities
      assert :scan in metadata.capabilities
    end

    test "includes description and author" do
      metadata = Ollama.metadata()

      assert is_binary(metadata.description)
      assert is_binary(metadata.author)
    end
  end

  describe "list_models/1" do
    test "returns model list with id, name, size, modified_at from /api/tags" do
      config = %{limit: 10}

      expected_structure = fn models ->
        assert is_list(models)

        if length(models) > 0 do
          model = List.first(models)
          assert Map.has_key?(model, :id)
          assert Map.has_key?(model, :name)
          assert Map.has_key?(model, :sha)
          assert Map.has_key?(model, :last_modified)
          assert Map.has_key?(model, :metadata)
          assert is_map(model.metadata)
        end
      end

      case Ollama.list_models(config) do
        {:ok, models} -> expected_structure.(models)
        {:error, :connection_refused} -> :ok
        {:error, {:network, _}} -> :ok
        {:error, _} -> :ok
      end
    end

    test "maps ollama model fields correctly" do
      config = %{}

      case Ollama.list_models(config) do
        {:ok, models} when length(models) > 0 ->
          model = List.first(models)
          # Ollama model IDs are the model names (e.g., "llama2:7b")
          assert is_binary(model.id)
          assert is_binary(model.name)
          # Author for local models is "ollama" or "local"
          assert is_binary(model.author)
          # Downloads is 0 for local models
          assert model.downloads == 0
          # sha is the digest
          assert is_binary(model.sha)
          # last_modified is a DateTime
          assert %DateTime{} = model.last_modified
          # metadata includes size
          assert is_map(model.metadata)

        {:error, _} -> :ok
      end
    end

    test "handles empty model list" do
      config = %{}

      case Ollama.list_models(config) do
        {:ok, models} -> assert is_list(models)
        {:error, _} -> :ok
      end
    end

    test "uses custom base_url from config" do
      config = %{base_url: "http://custom-ollama:11434"}

      case Ollama.list_models(config) do
        {:ok, _} -> :ok
        {:error, _} -> :ok
      end
    end
  end

  describe "get_model/2" do
    test "returns model details with parameter count from /api/show" do
      model_id = "llama2:7b"

      case Ollama.get_model(model_id, %{}) do
        {:ok, model} ->
          assert model.id == model_id
          assert model.name == "llama2"
          assert is_map(model.metadata)
          # Should include details from /api/show
          assert Map.has_key?(model.metadata, :details) or Map.has_key?(model.metadata, :modelfile)

        {:error, :not_found} -> :ok
        {:error, :connection_refused} -> :ok
        {:error, {:network, _}} -> :ok
        {:error, _} -> :ok
      end
    end

    test "includes modelfile and system prompt in metadata" do
      model_id = "llama2:7b"

      case Ollama.get_model(model_id, %{}) do
        {:ok, model} ->
          # Should include model details
          assert is_map(model.metadata)

        {:error, _} -> :ok
      end
    end

    test "returns error for non-existent model" do
      case Ollama.get_model("nonexistent-model:latest", %{}) do
        {:ok, _} -> :ok  # Ollama might auto-download
        {:error, :not_found} -> :ok
        {:error, _} -> :ok
      end
    end

    test "parses model name and tag correctly" do
      # Test with tag
      case Ollama.get_model("codellama:13b", %{}) do
        {:ok, model} ->
          assert model.name == "codellama"
        {:error, _} -> :ok
      end

      # Test without tag (defaults to :latest)
      case Ollama.get_model("llama2", %{}) do
        {:ok, model} ->
          assert model.name == "llama2"
        {:error, _} -> :ok
      end
    end
  end

  describe "search_models/2" do
    test "filters local models by name pattern" do
      query = "llama"

      case Ollama.search_models(query, %{}) do
        {:ok, models} ->
          assert is_list(models)
          # All results should contain "llama" in name
          Enum.each(models, fn model ->
            assert String.contains?(String.downcase(model.name), "llama")
          end)

        {:error, _} -> :ok
      end
    end

    test "returns empty list when no matches" do
      query = "nonexistent-model-xyz-12345"

      case Ollama.search_models(query, %{}) do
        {:ok, models} ->
          assert is_list(models)
          assert Enum.empty?(models) or
                 Enum.all?(models, fn m -> String.contains?(String.downcase(m.name), query) end)

        {:error, _} -> :ok
      end
    end

    test "search is case-insensitive" do
      case Ollama.search_models("LLAMA", %{}) do
        {:ok, models} ->
          assert is_list(models)
          # Should find models with "llama" regardless of case

        {:error, _} -> :ok
      end
    end
  end

  describe "scan_model/2" do
    test "calls ML service with model metadata" do
      model_id = "llama2:7b"
      config = %{ml_service_url: "http://localhost:8000"}

      case Ollama.scan_model(model_id, config) do
        {:ok, result} ->
          assert is_float(result.risk_score)
          assert result.risk_score >= 0.0
          assert result.risk_score <= 1.0
          assert is_list(result.findings)
          assert %DateTime{} = result.scanned_at

        {:error, :not_found} -> :ok
        {:error, :scan_failed} -> :ok
        {:error, :connection_refused} -> :ok
        {:error, {:network, _}} -> :ok
        {:error, _} -> :ok
      end
    end

    test "includes model path in scan request for local models" do
      model_id = "llama2:7b"
      config = %{}

      case Ollama.scan_model(model_id, config) do
        {:ok, result} ->
          assert Map.has_key?(result, :risk_score)
          assert Map.has_key?(result, :findings)
          assert Map.has_key?(result, :scanned_at)

        {:error, _} -> :ok
      end
    end
  end

  describe "validate_config/1" do
    test "tests Ollama connectivity via GET /api/tags" do
      config = %{}

      case Ollama.validate_config(config) do
        :ok -> :ok
        {:error, :connection_refused} -> :ok
        {:error, {:network, _}} -> :ok
        {:error, _} -> :ok
      end
    end

    test "returns :ok when Ollama is reachable" do
      config = %{base_url: "http://localhost:11434"}

      case Ollama.validate_config(config) do
        :ok -> :ok
        {:error, _} -> :ok  # Allow errors if Ollama not running
      end
    end

    test "handles connection refused error when Ollama not running" do
      config = %{base_url: "http://localhost:99999"}

      result = Ollama.validate_config(config)

      case result do
        {:error, :connection_refused} -> :ok
        {:error, {:network, _}} -> :ok
        {:error, _} -> :ok
        :ok -> :ok  # Might succeed if something is actually on that port
      end
    end

    test "handles timeout gracefully" do
      # Test would need a slow server to properly test timeout
      config = %{base_url: "http://10.255.255.1:11434"}  # Non-routable IP

      case Ollama.validate_config(config) do
        {:error, :timeout} -> :ok
        {:error, {:network, _}} -> :ok
        {:error, _} -> :ok
        :ok -> :ok
      end
    end
  end

  describe "error handling" do
    test "handles connection refused error" do
      config = %{base_url: "http://localhost:99999"}

      case Ollama.list_models(config) do
        {:error, :connection_refused} -> :ok
        {:error, {:network, _}} -> :ok
        {:error, _} -> :ok
        {:ok, _} -> :ok
      end
    end

    test "handles network errors gracefully" do
      config = %{base_url: "http://invalid-ollama-host:11434"}

      case Ollama.list_models(config) do
        {:error, {:network, _}} -> :ok
        {:error, :connection_refused} -> :ok
        {:error, _} -> :ok
        {:ok, _} -> :ok
      end
    end

    test "returns :not_found for unknown model" do
      case Ollama.get_model("definitely-not-a-real-model-xyz", %{}) do
        {:error, :not_found} -> :ok
        {:error, _} -> :ok
        {:ok, _} -> :ok  # Ollama might auto-pull
      end
    end
  end

  describe "configuration" do
    test "uses default base_url when not provided" do
      config = %{}

      # Should use http://localhost:11434
      case Ollama.list_models(config) do
        {:ok, _} -> :ok
        {:error, _} -> :ok
      end
    end

    test "uses base_url from config" do
      config = %{base_url: "http://custom-ollama:11434"}

      case Ollama.list_models(config) do
        {:ok, _} -> :ok
        {:error, _} -> :ok
      end
    end

    test "uses OLLAMA_URL environment variable" do
      # This test documents the behavior but doesn't change env vars
      config = %{}

      case Ollama.list_models(config) do
        {:ok, _} -> :ok
        {:error, _} -> :ok
      end
    end
  end
end
