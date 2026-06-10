defmodule TamanduaServer.Registries.Behaviour do
  @moduledoc """
  Behaviour definition for Tamandua EDR model registry connectors.

  All registry connectors must implement this behaviour to provide a unified
  interface for interacting with different model registries (HuggingFace Hub,
  MLflow, Weights & Biases, Ollama).

  This abstraction enables:
  - Consistent API for listing, searching, and retrieving model metadata
  - Triggering security scans on models before deployment
  - Model download tracking and approval workflows
  - Registry-agnostic security policies

  ## Supported Registry Types

  - `:model_registry` - ML model hosting platforms (HuggingFace, MLflow)
  - `:local_registry` - Local model storage (Ollama, custom)
  - `:experiment_tracker` - Experiment tracking platforms (W&B, MLflow)

  ## Example Implementation

      defmodule MyRegistry do
        use TamanduaServer.Registries.Behaviour

        @impl true
        def metadata do
          %{
            name: "My Registry",
            version: "1.0.0",
            type: :model_registry
          }
        end

        @impl true
        def list_models(config) do
          # Fetch models from registry API
          {:ok, [...]}
        end

        # ... implement other callbacks
      end
  """

  @type model :: %{
          id: String.t(),
          name: String.t(),
          author: String.t(),
          downloads: integer(),
          sha: String.t(),
          last_modified: DateTime.t(),
          metadata: map()
        }

  @type scan_result :: %{
          risk_score: float(),
          findings: [map()],
          scanned_at: DateTime.t()
        }

  @type config :: map()
  @type registry_type :: :model_registry | :local_registry | :experiment_tracker

  @doc """
  Returns metadata about the registry connector.

  ## Required fields:
  - `:name` - Human-readable registry name
  - `:version` - Semantic version string (e.g., "1.0.0")
  - `:type` - Registry type (see `registry_type()`)

  ## Optional fields:
  - `:description` - Brief description
  - `:author` - Connector author
  - `:capabilities` - List of supported features (e.g., [:search, :scan, :webhooks])

  ## Example:
      %{
        name: "HuggingFace Hub",
        version: "1.0.0",
        type: :model_registry,
        description: "Official HuggingFace model registry connector",
        author: "Tamandua Team",
        capabilities: [:search, :scan, :pagination]
      }
  """
  @callback metadata() :: map()

  @doc """
  List models from the registry.

  ## Parameters
  - `config` - Registry configuration map (API keys, URLs, filters)

  ## Config Options
  - `:limit` - Maximum number of models to return (default: 20)
  - `:offset` or `:skip` - Pagination offset
  - `:filter` - Registry-specific filters (e.g., task type, library)
  - `:sort` - Sort order (e.g., "downloads", "updated")

  ## Returns
  - `{:ok, [model()]}` - List of model structs
  - `{:error, term()}` - Error (e.g., `:unauthorized`, `:rate_limited`, `{:network, reason}`)

  ## Example:
      list_models(%{limit: 10, filter: %{task: "text-generation"}})
      # => {:ok, [%{id: "meta-llama/Llama-2-7b", ...}, ...]}
  """
  @callback list_models(config()) :: {:ok, [model()]} | {:error, term()}

  @doc """
  Get detailed information about a specific model.

  ## Parameters
  - `model_id` - Registry-specific model identifier (e.g., "org/model-name")
  - `config` - Registry configuration map

  ## Returns
  - `{:ok, model()}` - Model struct with all available metadata
  - `{:error, :not_found}` - Model does not exist
  - `{:error, :unauthorized}` - Authentication required or insufficient permissions
  - `{:error, term()}` - Other error

  ## Example:
      get_model("meta-llama/Llama-2-7b-chat-hf", %{})
      # => {:ok, %{id: "meta-llama/Llama-2-7b-chat-hf", author: "meta-llama", downloads: 1000000, ...}}
  """
  @callback get_model(model_id :: String.t(), config()) :: {:ok, model()} | {:error, term()}

  @doc """
  Search for models matching a query.

  ## Parameters
  - `query` - Search query string or map of filters
  - `config` - Registry configuration map (may include pagination, sort)

  ## Returns
  - `{:ok, [model()]}` - List of matching models
  - `{:error, term()}` - Error

  ## Example:
      search_models("llama pytorch", %{limit: 5})
      # => {:ok, [%{id: "meta-llama/Llama-2-7b", ...}, ...]}
  """
  @callback search_models(query :: String.t(), config()) :: {:ok, [model()]} | {:error, term()}

  @doc """
  Trigger a security scan on a model.

  This callback should:
  1. Fetch model file metadata (URLs, sizes, hashes)
  2. Submit scan request to ML security service
  3. Return scan results with risk assessment

  ## Parameters
  - `model_id` - Registry-specific model identifier
  - `config` - Registry configuration map (may include ML service URL)

  ## Returns
  - `{:ok, scan_result()}` - Scan completed with risk score and findings
  - `{:error, :not_found}` - Model does not exist
  - `{:error, :scan_failed}` - Scan failed (timeout, service unavailable)
  - `{:error, term()}` - Other error

  ## Scan Result Structure
  - `risk_score` - Float between 0.0 (safe) and 1.0 (high risk)
  - `findings` - List of security issues found (maps with `:severity`, `:type`, `:description`)
  - `scanned_at` - Timestamp of scan completion

  ## Example:
      scan_model("suspicious/model", %{})
      # => {:ok, %{risk_score: 0.85, findings: [...], scanned_at: ~U[2024-01-15 10:30:00Z]}}
  """
  @callback scan_model(model_id :: String.t(), config()) :: {:ok, scan_result()} | {:error, term()}

  @doc """
  Hook called when a model is downloaded (optional).

  Can be used for:
  - Tracking download events
  - Triggering post-download scans
  - Updating usage metrics

  Default implementation returns `:ok`.

  ## Parameters
  - `model_id` - Registry-specific model identifier
  - `config` - Registry configuration map

  ## Returns
  - `:ok` - Hook completed successfully
  - `{:error, term()}` - Hook failed (does not prevent download)
  """
  @callback on_download(model_id :: String.t(), config()) :: :ok | {:error, term()}

  @doc """
  Validate connector configuration (optional).

  Can be used to:
  - Check API keys are valid
  - Verify required fields are present
  - Test connectivity to registry

  Default implementation returns `:ok`.

  ## Parameters
  - `config` - Registry configuration map

  ## Returns
  - `:ok` - Configuration is valid
  - `{:error, term()}` - Configuration is invalid
  """
  @callback validate_config(config()) :: :ok | {:error, term()}

  @optional_callbacks [
    on_download: 2,
    validate_config: 1
  ]

  @doc """
  Default implementations for optional callbacks.

  When you `use TamanduaServer.Registries.Behaviour`, you get:
  - `on_download/2` - Returns `:ok`
  - `validate_config/1` - Returns `:ok`

  You can override these defaults by implementing them in your module.
  """
  defmacro __using__(_opts) do
    quote do
      @behaviour TamanduaServer.Registries.Behaviour

      @impl true
      def on_download(_model_id, _config), do: :ok

      @impl true
      def validate_config(_config), do: :ok

      defoverridable [on_download: 2, validate_config: 1]
    end
  end
end
