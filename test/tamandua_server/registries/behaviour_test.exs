defmodule TamanduaServer.Registries.BehaviourTest do
  use ExUnit.Case, async: true

  # Test implementation module
  defmodule TestRegistry do
    use TamanduaServer.Registries.Behaviour

    @impl true
    def metadata do
      %{
        name: "Test Registry",
        version: "1.0.0",
        type: :model_registry
      }
    end

    @impl true
    def list_models(_config) do
      {:ok, [
        %{
          id: "test/model",
          name: "Test Model",
          author: "test-author",
          downloads: 100,
          sha: "abc123",
          last_modified: ~U[2024-01-15 10:30:00Z],
          metadata: %{}
        }
      ]}
    end

    @impl true
    def get_model(_model_id, _config) do
      {:ok, %{
        id: "test/model",
        name: "Test Model",
        author: "test-author",
        downloads: 100,
        sha: "abc123",
        last_modified: ~U[2024-01-15 10:30:00Z],
        metadata: %{}
      }}
    end

    @impl true
    def scan_model(_model_id, _config) do
      {:ok, %{
        risk_score: 0.1,
        findings: [],
        scanned_at: DateTime.utc_now()
      }}
    end

    @impl true
    def search_models(_query, _config) do
      {:ok, []}
    end
  end

  describe "behaviour definition" do
    test "behaviour defines required callbacks" do
      callbacks = TamanduaServer.Registries.Behaviour.behaviour_info(:callbacks)

      assert Keyword.has_key?(callbacks, :metadata)
      assert Keyword.has_key?(callbacks, :list_models)
      assert Keyword.has_key?(callbacks, :get_model)
      assert Keyword.has_key?(callbacks, :scan_model)
      assert Keyword.has_key?(callbacks, :search_models)
    end

    test "behaviour defines optional callbacks" do
      optional = TamanduaServer.Registries.Behaviour.behaviour_info(:optional_callbacks)

      assert {:on_download, 2} in optional
      assert {:validate_config, 1} in optional
    end
  end

  describe "using macro provides defaults" do
    test "on_download defaults to :ok" do
      assert TestRegistry.on_download("test/model", %{}) == :ok
    end

    test "validate_config defaults to :ok" do
      assert TestRegistry.validate_config(%{}) == :ok
    end
  end

  describe "test implementation" do
    test "implements metadata/0" do
      metadata = TestRegistry.metadata()

      assert metadata.name == "Test Registry"
      assert metadata.version == "1.0.0"
      assert metadata.type == :model_registry
    end

    test "implements list_models/1" do
      {:ok, models} = TestRegistry.list_models(%{})

      assert is_list(models)
      assert length(models) == 1

      model = List.first(models)
      assert model.id == "test/model"
      assert model.name == "Test Model"
      assert model.author == "test-author"
      assert model.downloads == 100
      assert model.sha == "abc123"
      assert %DateTime{} = model.last_modified
      assert is_map(model.metadata)
    end

    test "implements get_model/2" do
      {:ok, model} = TestRegistry.get_model("test/model", %{})

      assert model.id == "test/model"
      assert model.name == "Test Model"
      assert model.author == "test-author"
    end

    test "implements scan_model/2" do
      {:ok, result} = TestRegistry.scan_model("test/model", %{})

      assert is_float(result.risk_score)
      assert is_list(result.findings)
      assert %DateTime{} = result.scanned_at
    end

    test "implements search_models/2" do
      {:ok, models} = TestRegistry.search_models("test", %{})

      assert is_list(models)
    end
  end
end
