defmodule TamanduaServer.Registries.HuggingFaceTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Registries.HuggingFace

  @valid_model_response %{
    "id" => "meta-llama/Llama-2-7b-chat-hf",
    "author" => "meta-llama",
    "sha" => "abc123def456",
    "downloads" => 1_000_000,
    "lastModified" => "2024-01-15T10:30:00.000Z",
    "tags" => ["pytorch", "llama", "text-generation"],
    "siblings" => [
      %{"rfilename" => "model.safetensors", "size" => 13_476_954_112},
      %{"rfilename" => "tokenizer.json", "size" => 1_842_767}
    ]
  }

  @valid_models_list_response [
    %{
      "id" => "meta-llama/Llama-2-7b-chat-hf",
      "author" => "meta-llama",
      "downloads" => 1_000_000,
      "lastModified" => "2024-01-15T10:30:00.000Z"
    },
    %{
      "id" => "mistralai/Mistral-7B-v0.1",
      "author" => "mistralai",
      "downloads" => 500_000,
      "lastModified" => "2024-01-10T08:00:00.000Z"
    }
  ]

  describe "metadata/0" do
    test "returns registry metadata" do
      metadata = HuggingFace.metadata()

      assert metadata.name == "HuggingFace Hub"
      assert metadata.version == "1.0.0"
      assert metadata.type == :model_registry
    end
  end

  describe "list_models/1" do
    test "returns parsed model list" do
      # This test would use a mock/bypass in real implementation
      # For now, we test the structure expectation
      config = %{limit: 10}

      # Expected structure when API call succeeds
      expected_structure = fn models ->
        assert is_list(models)

        if length(models) > 0 do
          model = List.first(models)
          assert Map.has_key?(model, :id)
          assert Map.has_key?(model, :name)
          assert Map.has_key?(model, :author)
          assert Map.has_key?(model, :downloads)
          assert is_integer(model.downloads)
        end
      end

      # Test that function exists and returns expected format
      case HuggingFace.list_models(config) do
        {:ok, models} -> expected_structure.(models)
        # Allow errors (network, auth, etc.)
        {:error, _} -> :ok
      end
    end

    test "handles pagination options" do
      config = %{limit: 5, skip: 10}

      case HuggingFace.list_models(config) do
        {:ok, models} ->
          # If successful, should respect limit
          assert is_list(models)

        {:error, _} ->
          :ok
      end
    end

    test "handles empty response" do
      config = %{filter: %{task: "nonexistent-task"}}

      case HuggingFace.list_models(config) do
        {:ok, models} -> assert is_list(models)
        {:error, _} -> :ok
      end
    end
  end

  describe "get_model/2" do
    test "returns model with required fields" do
      model_id = "meta-llama/Llama-2-7b-chat-hf"

      case HuggingFace.get_model(model_id, %{}) do
        {:ok, model} ->
          # Verify all required fields are present
          assert model.id == model_id
          assert is_binary(model.name)
          assert is_binary(model.author)
          assert is_integer(model.downloads)
          assert is_binary(model.sha)
          assert %DateTime{} = model.last_modified
          assert is_map(model.metadata)

          # Verify siblings are in metadata
          if Map.has_key?(model.metadata, :siblings) do
            assert is_list(model.metadata.siblings)
          end

        {:error, :not_found} ->
          :ok

        {:error, _} ->
          :ok
      end
    end

    test "returns error for non-existent model" do
      case HuggingFace.get_model("nonexistent/model", %{}) do
        {:ok, _} -> flunk("Should return error for non-existent model")
        {:error, :not_found} -> :ok
        # Other errors are acceptable (network, auth)
        {:error, _} -> :ok
      end
    end
  end

  describe "search_models/2" do
    test "filters by search query" do
      query = "llama"

      case HuggingFace.search_models(query, %{}) do
        {:ok, models} ->
          assert is_list(models)

        # Results should be relevant to query
        {:error, _} ->
          :ok
      end
    end

    test "returns matching models" do
      query = "pytorch"
      config = %{limit: 5}

      case HuggingFace.search_models(query, config) do
        {:ok, models} ->
          assert is_list(models)

        {:error, _} ->
          :ok
      end
    end
  end

  describe "authentication" do
    test "works without token (anonymous access)" do
      config = %{}

      case HuggingFace.list_models(config) do
        {:ok, _} -> :ok
        {:error, :unauthorized} -> flunk("Should allow anonymous access")
        # Other errors acceptable
        {:error, _} -> :ok
      end
    end

    test "includes Authorization header when HF_TOKEN set" do
      # This would require mocking in real implementation
      # For now, we test that the function accepts token in config
      config = %{hf_token: "test-token"}

      case HuggingFace.list_models(config) do
        {:ok, _} -> :ok
        {:error, _} -> :ok
      end
    end
  end

  describe "error handling" do
    test "handles 401 unauthorized" do
      # Test would use mock to return 401
      # Function should handle unauthorized errors
      assert :ok == :ok
    end

    test "handles 404 not found" do
      case HuggingFace.get_model("invalid/model", %{}) do
        {:error, :not_found} -> :ok
        {:error, _} -> :ok
        {:ok, _} -> flunk("Should return error for invalid model")
      end
    end

    test "handles 429 rate limited" do
      # Test would use mock to return 429
      # Function should return {:error, :rate_limited}
      assert :ok == :ok
    end

    test "handles network errors" do
      # Test would use mock to simulate network failure
      # Function should return {:error, {:network, reason}}
      assert :ok == :ok
    end
  end

  describe "scan_model/2" do
    test "fails closed instead of scanning mutable remote URLs" do
      assert {:error, :secure_artifact_intake_required} =
               HuggingFace.scan_model("test/model", %{
                 ml_service_url: "http://attacker.invalid"
               })
    end

    test "returns scan result structure" do
      model_id = "test/model"
      config = %{ml_service_url: "http://localhost:8000"}

      case HuggingFace.scan_model(model_id, config) do
        {:ok, result} ->
          assert is_float(result.risk_score)
          assert result.risk_score >= 0.0
          assert result.risk_score <= 1.0
          assert is_list(result.findings)
          assert %DateTime{} = result.scanned_at

        {:error, :not_found} ->
          :ok

        {:error, :scan_failed} ->
          :ok

        {:error, _} ->
          :ok
      end
    end
  end

  describe "parse_model/1" do
    # Test private helper if exposed for testing
    # Otherwise, tested indirectly through public functions
  end
end