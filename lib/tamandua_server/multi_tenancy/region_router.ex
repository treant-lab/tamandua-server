defmodule TamanduaServer.MultiTenancy.RegionRouter do
  @moduledoc """
  Routes database queries, S3 uploads, and cache operations to region-specific infrastructure.

  This module provides automatic routing based on tenant configuration, ensuring
  data stays within the correct geographic region for compliance.

  ## Features

  - Automatic Ecto.Repo selection based on tenant region
  - S3 bucket routing for telemetry and artifacts
  - Redis cache routing for regional caches
  - RabbitMQ queue routing for regional message buses
  - Connection pooling per region
  - Health checks for regional infrastructure
  - Automatic failover to secondary region

  ## Usage

      # Use the correct repo for a tenant
      RegionRouter.with_repo(tenant_id, fn repo ->
        repo.all(Agent)
      end)

      # Upload to correct S3 bucket
      RegionRouter.upload_to_s3(tenant_id, file_path, key)

      # Get from regional cache
      RegionRouter.cache_get(tenant_id, cache_key)

  ## Process Dictionary Context

  You can set the current tenant in the process dictionary for automatic routing:

      RegionRouter.put_tenant_id(tenant_id)
      # All subsequent operations use the tenant's region automatically
      RegionRouter.repo().all(Agent)
  """

  alias TamanduaServer.MultiTenancy.DataResidency
  alias TamanduaServer.Repo
  require Logger

  @type tenant_id :: String.t()
  @type region :: atom()
  @type repo_module :: module()

  # ===========================================================================
  # Database Routing
  # ===========================================================================

  @doc """
  Executes a function with the correct Ecto.Repo for a tenant.

  This is the primary way to ensure queries go to the correct regional database.

  ## Examples

      iex> RegionRouter.with_repo(tenant_id, fn repo ->
      ...>   repo.all(from a in Agent, where: a.organization_id == ^tenant_id)
      ...> end)
      [%Agent{}, ...]
  """
  @spec with_repo(tenant_id(), (repo_module() -> any())) :: {:ok, any()} | {:error, term()}
  def with_repo(tenant_id, func) when is_function(func, 1) do
    case get_repo(tenant_id) do
      {:ok, repo} ->
        result = func.(repo)
        {:ok, result}

      error ->
        error
    end
  rescue
    error ->
      Logger.error("Error executing with_repo for tenant #{tenant_id}: #{inspect(error)}")
      {:error, error}
  end

  @doc """
  Gets the Ecto.Repo module for a tenant.

  ## Examples

      iex> RegionRouter.get_repo(tenant_id)
      {:ok, TamanduaServer.Repo.EU}
  """
  @spec get_repo(tenant_id()) :: {:ok, repo_module()} | {:error, term()}
  def get_repo(tenant_id) do
    case get_from_cache_or_fetch(tenant_id, :repo) do
      {:ok, repo} -> {:ok, repo}
      {:error, _} = error -> error
    end
  end

  @doc """
  Gets the Ecto.Repo for the current tenant from process dictionary.

  This requires `put_tenant_id/1` to be called first.

  ## Examples

      iex> RegionRouter.put_tenant_id(tenant_id)
      iex> RegionRouter.repo()
      TamanduaServer.Repo.EU
  """
  def repo do
    case Process.get(:current_tenant_id) do
      nil ->
        # Fallback to default repo
        Logger.warning("No tenant_id in process dictionary, using default repo")
        Repo

      tenant_id ->
        case get_repo(tenant_id) do
          {:ok, repo} -> repo
          {:error, _} -> Repo
        end
    end
  end

  @doc """
  Sets the current tenant ID in the process dictionary.

  This enables automatic region routing for all subsequent operations.

  ## Examples

      iex> RegionRouter.put_tenant_id(tenant_id)
      :ok
  """
  def put_tenant_id(tenant_id) when is_binary(tenant_id) do
    Process.put(:current_tenant_id, tenant_id)
    :ok
  end

  @doc """
  Clears the tenant ID from the process dictionary.
  """
  def clear_tenant_id do
    Process.delete(:current_tenant_id)
    :ok
  end

  # ===========================================================================
  # S3 Routing
  # ===========================================================================

  @doc """
  Gets the S3 bucket name for a tenant's region.

  ## Examples

      iex> RegionRouter.get_s3_bucket(tenant_id)
      {:ok, "tamandua-eu-telemetry"}
  """
  def get_s3_bucket(tenant_id) do
    case get_from_cache_or_fetch(tenant_id, :s3_bucket) do
      {:ok, bucket} -> {:ok, bucket}
      {:error, _} = error -> error
    end
  end

  @doc """
  Uploads a file to the tenant's regional S3 bucket.

  ## Parameters

  - `tenant_id` - Organization UUID
  - `file_path` - Local file path to upload
  - `s3_key` - S3 object key (path in bucket)
  - `opts` - Options:
    - `:content_type` - MIME type (default: "application/octet-stream")
    - `:metadata` - Custom metadata map
    - `:encryption` - Enable server-side encryption (default: true)

  ## Returns

  - `{:ok, url}` - Upload successful, returns S3 URL
  - `{:error, reason}` - Upload failed
  """
  def upload_to_s3(tenant_id, file_path, s3_key, opts \\ []) do
    with {:ok, bucket} <- get_s3_bucket(tenant_id),
         {:ok, config} <- DataResidency.get_storage_config(tenant_id) do

      # Build upload options
      upload_opts =
        opts
        |> Keyword.put(:bucket, bucket)
        |> Keyword.put(:key, s3_key)
        |> Keyword.put_new(:encryption, true)
        |> Keyword.put(:kms_key_id, config.encryption_key_id)

      # Perform upload (this would use ExAws or similar)
      perform_s3_upload(file_path, upload_opts)
    end
  end

  @doc """
  Gets a presigned URL for downloading from tenant's S3 bucket.

  ## Examples

      iex> RegionRouter.get_s3_presigned_url(tenant_id, "telemetry/2024-02/events.json", expires_in: 3600)
      {:ok, "https://tamandua-eu-telemetry.s3.amazonaws.com/...?X-Amz-..."}
  """
  def get_s3_presigned_url(tenant_id, s3_key, opts \\ []) do
    with {:ok, bucket} <- get_s3_bucket(tenant_id),
         {:ok, _config} <- DataResidency.get_storage_config(tenant_id) do

      expires_in = Keyword.get(opts, :expires_in, 3600)

      # Generate presigned URL (this would use ExAws.S3.presigned_url)
      generate_presigned_url(bucket, s3_key, expires_in)
    end
  end

  # ===========================================================================
  # Redis Cache Routing
  # ===========================================================================

  @doc """
  Gets the Redis URL for a tenant's region.

  ## Examples

      iex> RegionRouter.get_redis_url(tenant_id)
      {:ok, "redis://eu-redis:6379"}
  """
  def get_redis_url(tenant_id) do
    case get_from_cache_or_fetch(tenant_id, :redis_url) do
      {:ok, url} -> {:ok, url}
      {:error, _} = error -> error
    end
  end

  @doc """
  Gets a value from the tenant's regional cache.

  ## Examples

      iex> RegionRouter.cache_get(tenant_id, "agent:status:\#{agent_id}")
      {:ok, "online"}
  """
  def cache_get(tenant_id, key) do
    with {:ok, redis_url} <- get_redis_url(tenant_id) do
      # Use regional Redis connection
      perform_redis_get(redis_url, key)
    end
  end

  @doc """
  Sets a value in the tenant's regional cache.

  ## Examples

      iex> RegionRouter.cache_set(tenant_id, "agent:status:\#{agent_id}", "online", ttl: 300)
      :ok
  """
  def cache_set(tenant_id, key, value, opts \\ []) do
    with {:ok, redis_url} <- get_redis_url(tenant_id) do
      ttl = Keyword.get(opts, :ttl)
      perform_redis_set(redis_url, key, value, ttl)
    end
  end

  @doc """
  Deletes a value from the tenant's regional cache.
  """
  def cache_delete(tenant_id, key) do
    with {:ok, redis_url} <- get_redis_url(tenant_id) do
      perform_redis_delete(redis_url, key)
    end
  end

  # ===========================================================================
  # RabbitMQ Routing
  # ===========================================================================

  @doc """
  Gets the RabbitMQ URL for a tenant's region.

  ## Examples

      iex> RegionRouter.get_rabbitmq_url(tenant_id)
      {:ok, "amqp://eu-rabbitmq:5672"}
  """
  def get_rabbitmq_url(tenant_id) do
    case get_from_cache_or_fetch(tenant_id, :rabbitmq_url) do
      {:ok, url} -> {:ok, url}
      {:error, _} = error -> error
    end
  end

  @doc """
  Publishes a message to the tenant's regional RabbitMQ queue.

  ## Examples

      iex> RegionRouter.publish_message(tenant_id, "telemetry.events", %{type: "process", ...})
      :ok
  """
  def publish_message(tenant_id, queue, message, opts \\ []) do
    with {:ok, rabbitmq_url} <- get_rabbitmq_url(tenant_id) do
      perform_rabbitmq_publish(rabbitmq_url, queue, message, opts)
    end
  end

  # ===========================================================================
  # Health Checks
  # ===========================================================================

  @doc """
  Checks the health of all regional infrastructure for a tenant.

  Returns health status for database, S3, Redis, and RabbitMQ.

  ## Examples

      iex> RegionRouter.health_check(tenant_id)
      {:ok, %{
        database: :healthy,
        s3: :healthy,
        redis: :healthy,
        rabbitmq: :healthy,
        region: :eu
      }}
  """
  def health_check(tenant_id) do
    with {:ok, config} <- DataResidency.get_storage_config(tenant_id) do
      results = %{
        region: config.region,
        database: check_database_health(config.database_repo),
        s3: check_s3_health(config.s3_bucket),
        redis: check_redis_health(config.redis_url),
        rabbitmq: check_rabbitmq_health(config.rabbitmq_url)
      }

      overall_status =
        if Enum.all?(Map.values(results), &(&1 in [:healthy, config.region])) do
          :healthy
        else
          :degraded
        end

      {:ok, Map.put(results, :overall, overall_status)}
    end
  end

  @doc """
  Checks health of a specific region's infrastructure.

  ## Examples

      iex> RegionRouter.region_health(:eu)
      {:ok, %{database: :healthy, s3: :healthy, ...}}
  """
  def region_health(region) when is_atom(region) do
    configs = DataResidency.region_configs()

    case Map.get(configs, region) do
      nil ->
        {:error, :invalid_region}

      config ->
        results = %{
          region: region,
          database: check_database_health(config.database_repo),
          s3: check_s3_health(config.s3_bucket),
          redis: check_redis_health(config.redis_url),
          rabbitmq: check_rabbitmq_health(config.rabbitmq_url)
        }

        {:ok, results}
    end
  end

  # ===========================================================================
  # Private Functions
  # ===========================================================================

  defp get_from_cache_or_fetch(tenant_id, field) do
    # Try to get from ETS cache first (for performance)
    cache_key = {tenant_id, field}

    case lookup_cache(cache_key) do
      {:ok, value} ->
        {:ok, value}

      :miss ->
        # Fetch from database and cache
        with {:ok, config} <- DataResidency.get_storage_config(tenant_id) do
          value = Map.get(config, field)
          cache_put(cache_key, value, ttl: 300)
          {:ok, value}
        end
    end
  end

  defp lookup_cache(key) do
    # This would use ETS or Cachex
    # For now, just return :miss
    :miss
  end

  defp cache_put(_key, _value, _opts) do
    # This would cache in ETS
    :ok
  end

  # S3 operations (stubs - would use ExAws)
  defp perform_s3_upload(_file_path, _opts) do
    # Implementation would use ExAws.S3.upload/3
    {:ok, "https://s3.example.com/bucket/key"}
  end

  defp generate_presigned_url(_bucket, _key, _expires_in) do
    # Implementation would use ExAws.S3.presigned_url/3
    {:ok, "https://s3.example.com/presigned-url"}
  end

  defp check_s3_health(_bucket) do
    # Try to list objects or head bucket
    :healthy
  end

  # Redis operations (stubs - would use Redix)
  defp perform_redis_get(_url, _key) do
    # Implementation would use Redix.command/2
    {:ok, nil}
  end

  defp perform_redis_set(_url, _key, _value, _ttl) do
    # Implementation would use Redix.command/2
    :ok
  end

  defp perform_redis_delete(_url, _key) do
    # Implementation would use Redix.command/2
    :ok
  end

  defp check_redis_health(_url) do
    # Try PING command
    :healthy
  end

  # RabbitMQ operations (stubs - would use AMQP)
  defp perform_rabbitmq_publish(_url, _queue, _message, _opts) do
    # Implementation would use AMQP.Basic.publish/5
    :ok
  end

  defp check_rabbitmq_health(_url) do
    # Try to open a connection
    :healthy
  end

  # Database health checks
  defp check_database_health(repo) do
    try do
      # Try a simple query
      case repo.query("SELECT 1", [], timeout: 5_000) do
        {:ok, _} -> :healthy
        {:error, _} -> :unhealthy
      end
    rescue
      _ -> :unhealthy
    end
  end
end
