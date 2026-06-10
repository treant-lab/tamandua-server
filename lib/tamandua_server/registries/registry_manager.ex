defmodule TamanduaServer.Registries.RegistryManager do
  @moduledoc """
  Unified interface to all model registry connectors.

  Provides aggregated access to models from HuggingFace, MLflow, W&B, and Ollama
  registries, along with health status and provenance statistics.

  ## Features

  - **Unified model listing** - Aggregates models from all registries
  - **Sync status** - Reports last sync time and health per registry
  - **Provenance statistics** - Counts of models by scan status
  - **Graceful degradation** - Handles individual registry failures

  ## Example Usage

      # List all models from all registries
      models = RegistryManager.list_all_models()
      # => [%{id: "llama2:7b", registry: :ollama, ...}, ...]

      # Filter by registry
      hf_models = RegistryManager.list_all_models(registry: :huggingface)

      # Get sync status per registry
      status = RegistryManager.get_sync_status()
      # => [%{registry: :huggingface, health_status: :healthy, ...}, ...]

      # Get provenance scan statistics
      stats = RegistryManager.get_provenance_status()
      # => %{"huggingface" => %{clean: 10, suspicious: 2, malicious: 0}, ...}
  """

  require Logger

  alias TamanduaServer.Registries.{
    HuggingFace,
    MLflow,
    WandB,
    Ollama,
    HealthCheck,
    RegistrySync,
    ModelProvenance
  }

  alias TamanduaServer.Repo
  import Ecto.Query

  @registries [
    {:huggingface, HuggingFace},
    {:mlflow, MLflow},
    {:wandb, WandB},
    {:ollama, Ollama}
  ]

  @doc """
  Lists all configured registry identifiers.

  ## Returns

  List of registry atoms: `[:huggingface, :mlflow, :wandb, :ollama]`
  """
  @spec list_registries() :: [atom()]
  def list_registries do
    Enum.map(@registries, fn {name, _module} -> name end)
  end

  @doc """
  Lists models from all active registries.

  Queries each registry in parallel and merges results. Individual registry
  failures are handled gracefully - working registries still return models.

  ## Options

  - `:registry` - Filter to specific registry (e.g., `:huggingface`)
  - `:limit` - Maximum models per registry (default: 100)

  ## Returns

  List of model maps, each with a `:registry` field indicating source.

  ## Example

      models = RegistryManager.list_all_models(registry: :ollama, limit: 10)
      # => [%{id: "llama2:7b", name: "llama2", registry: :ollama, ...}, ...]
  """
  @spec list_all_models(keyword()) :: [map()]
  def list_all_models(opts \\ []) do
    registry_filter = Keyword.get(opts, :registry)
    limit = Keyword.get(opts, :limit, 100)

    registries =
      if registry_filter do
        Enum.filter(@registries, fn {name, _} -> name == registry_filter end)
      else
        @registries
      end

    registries
    |> Task.async_stream(
      fn {name, module} ->
        fetch_models(name, module, %{limit: limit})
      end,
      timeout: 30_000,
      on_timeout: :kill_task
    )
    |> Enum.flat_map(fn
      {:ok, models} -> models
      {:exit, _reason} -> []
    end)
  end

  defp fetch_models(name, module, config) do
    case module.list_models(config) do
      {:ok, models} ->
        Enum.map(models, &Map.put(&1, :registry, name))

      {:error, reason} ->
        Logger.debug("[RegistryManager] Failed to fetch from #{name}: #{inspect(reason)}")
        []
    end
  rescue
    error ->
      Logger.error("[RegistryManager] Exception fetching from #{name}: #{inspect(error)}")
      []
  end

  @doc """
  Gets sync status for all registries.

  Combines data from HealthCheck and RegistrySync to provide a complete
  picture of each registry's status.

  ## Returns

  List of status maps:

      [
        %{
          registry: :huggingface,
          last_sync: ~U[2024-01-15 10:30:00Z],
          health_status: :healthy,
          last_check: ~U[2024-01-15 10:30:00Z],
          consecutive_failures: 0,
          last_error: nil
        },
        ...
      ]
  """
  @spec get_sync_status() :: [map()]
  def get_sync_status do
    sync_status = get_sync_status_safe()
    health_status = get_health_status_safe()

    Enum.map(@registries, fn {name, _module} ->
      name_str = Atom.to_string(name)
      sync = Map.get(sync_status.last_sync, name_str)
      health = Map.get(health_status, name, %{})

      %{
        registry: name,
        last_sync: sync,
        health_status: health[:status] || :unknown,
        last_check: health[:last_check],
        consecutive_failures: health[:consecutive_failures] || 0,
        last_error: health[:last_error]
      }
    end)
  end

  defp get_sync_status_safe do
    RegistrySync.get_status()
  rescue
    _ -> %{registries: [], last_sync: %{}, errors: %{}, sync_in_progress: false}
  catch
    :exit, _ -> %{registries: [], last_sync: %{}, errors: %{}, sync_in_progress: false}
  end

  defp get_health_status_safe do
    HealthCheck.get_status()
  rescue
    _ -> %{}
  catch
    :exit, _ -> %{}
  end

  @doc """
  Gets health status for all registries from HealthCheck.

  ## Returns

  Map of registry name to health status:

      %{
        huggingface: %{status: :healthy, last_check: ~U[...], ...},
        mlflow: %{status: :degraded, last_error: :timeout, ...},
        ...
      }
  """
  @spec get_registry_health() :: map()
  def get_registry_health do
    get_health_status_safe()
  end

  @doc """
  Gets provenance scan statistics grouped by registry and status.

  Queries the ModelProvenance table to count models by their scan status
  for each registry.

  ## Returns

  Map of registry name (string) to status counts:

      %{
        "huggingface" => %{clean: 15, suspicious: 3, malicious: 1, pending: 2},
        "mlflow" => %{clean: 8, scanning: 1},
        ...
      }
  """
  @spec get_provenance_status() :: map()
  def get_provenance_status do
    query =
      from p in ModelProvenance,
        group_by: [p.registry, p.status],
        select: {p.registry, p.status, count(p.id)}

    Repo.all(query)
    |> Enum.group_by(&elem(&1, 0))
    |> Enum.map(fn {registry, counts} ->
      status_map =
        counts
        |> Enum.into(%{}, fn {_registry, status, count} ->
          {String.to_atom(status), count}
        end)

      {registry, status_map}
    end)
    |> Map.new()
  end

  @doc """
  Gets a specific model by ID from a registry.

  ## Parameters

  - `model_id` - Model identifier
  - `registry` - Registry atom (e.g., `:huggingface`)

  ## Returns

  - `{:ok, model}` - Model found
  - `{:error, :not_found}` - Model not found
  - `{:error, :unknown_registry}` - Invalid registry
  - `{:error, reason}` - Other error
  """
  @spec get_model(String.t(), atom()) :: {:ok, map()} | {:error, term()}
  def get_model(model_id, registry) do
    case find_registry_module(registry) do
      nil ->
        {:error, :unknown_registry}

      module ->
        case module.get_model(model_id, %{}) do
          {:ok, model} ->
            {:ok, Map.put(model, :registry, registry)}

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp find_registry_module(registry_name) do
    case Enum.find(@registries, fn {name, _} -> name == registry_name end) do
      {_, module} -> module
      nil -> nil
    end
  end
end
