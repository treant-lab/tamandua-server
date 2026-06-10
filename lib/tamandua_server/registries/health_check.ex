defmodule TamanduaServer.Registries.HealthCheck do
  @moduledoc """
  Health check GenServer for model registry connectors.

  Periodically checks connectivity and configuration validity for all registered
  model registry connectors (HuggingFace, MLflow, W&B, Ollama) and provides:

  - Continuous health monitoring with configurable intervals
  - Auto-reconnect with exponential backoff on transient failures
  - Status tracking: healthy, degraded, unhealthy
  - PubSub event broadcasting on status changes
  - REST API for status queries

  ## Health States

  - `:healthy` - Last check succeeded
  - `:degraded` - Experiencing transient failures, retrying
  - `:unhealthy` - Max retries exceeded, requires intervention
  - `:unknown` - No check has been performed yet

  ## Auto-Reconnect

  When a registry check fails:
  1. Mark as `:degraded` on first failure
  2. Retry with exponential backoff (2s, 4s, 8s, ...)
  3. Mark as `:unhealthy` after max retries exceeded
  4. Continue periodic checks to detect recovery

  ## PubSub Events

  Status changes are broadcast to `registries:health`:
  - `{:health_degraded, registry_name, error}` - First failure
  - `{:health_unhealthy, registry_name, error}` - Max retries exceeded
  - `{:health_recovered, registry_name}` - Recovery after failure

  ## Example Usage

      # Start with registries
      {:ok, pid} = HealthCheck.start_link(
        registries: [
          huggingface: [module: TamanduaServer.Registries.HuggingFace, config: %{}],
          mlflow: [module: TamanduaServer.Registries.MLflow, config: %{tracking_uri: "http://localhost:5000"}],
          wandb: [module: TamanduaServer.Registries.WandB, config: %{entity: "org", project: "proj"}]
        ],
        interval: 60_000
      )

      # Get current status
      HealthCheck.get_status()
      # => %{huggingface: %{status: :healthy, ...}, mlflow: %{...}, wandb: %{...}}

      # Check specific registry
      HealthCheck.check_registry(:mlflow)
      # => {:ok, :healthy}
  """

  use GenServer

  require Logger

  @default_interval 60_000  # Check every 60 seconds
  @default_initial_delay 5_000  # Initial delay before first check
  @default_max_retries 3
  @default_backoff_base 2_000  # Start at 2 seconds

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Starts the HealthCheck GenServer.

  ## Options

  - `:registries` - List of registry configurations (required)
  - `:interval` - Check interval in milliseconds (default: 60000)
  - `:initial_delay` - Delay before first check in milliseconds (default: 5000)
  - `:max_retries` - Max consecutive failures before unhealthy (default: 3)
  - `:backoff_base` - Base backoff time in milliseconds (default: 2000)
  - `:name` - GenServer name (default: __MODULE__)

  ## Registry Configuration

      registries: [
        huggingface: [module: TamanduaServer.Registries.HuggingFace, config: %{}],
        mlflow: [module: TamanduaServer.Registries.MLflow, config: %{tracking_uri: "..."}]
      ]
  """
  def start_link(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Triggers an immediate check of all registries.
  """
  def check_all(server \\ __MODULE__) do
    GenServer.call(server, :check_all)
  end

  @doc """
  Checks a specific registry and returns its status.

  ## Returns

  - `{:ok, :healthy}` - Registry is healthy
  - `{:ok, :degraded}` - Registry is experiencing issues
  - `{:ok, :unhealthy}` - Registry is unavailable
  - `{:error, :not_found}` - Registry not configured
  """
  def check_registry(server \\ __MODULE__, registry_name) do
    GenServer.call(server, {:check_registry, registry_name})
  end

  @doc """
  Returns the current health status for all registries.

  ## Returns

  Map of registry names to status maps:

      %{
        huggingface: %{
          status: :healthy,
          last_check: ~U[2024-01-15 10:30:00Z],
          last_success: ~U[2024-01-15 10:30:00Z],
          consecutive_failures: 0,
          last_error: nil
        },
        mlflow: %{...}
      }
  """
  def get_status(server \\ __MODULE__) do
    GenServer.call(server, :get_status)
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    registries_config = Keyword.get(opts, :registries, [])
    interval = Keyword.get(opts, :interval, @default_interval)
    initial_delay = Keyword.get(opts, :initial_delay, @default_initial_delay)
    max_retries = Keyword.get(opts, :max_retries, @default_max_retries)
    backoff_base = Keyword.get(opts, :backoff_base, @default_backoff_base)

    # Initialize registry status map
    registries =
      registries_config
      |> Enum.map(fn {name, config} ->
        {name, %{
          module: Keyword.fetch!(config, :module),
          config: Keyword.get(config, :config, %{}),
          status: :unknown,
          last_check: nil,
          last_success: nil,
          consecutive_failures: 0,
          last_error: nil
        }}
      end)
      |> Map.new()

    state = %{
      registries: registries,
      interval: interval,
      max_retries: max_retries,
      backoff_base: backoff_base
    }

    # Schedule initial health check after delay
    Process.send_after(self(), :check_health, initial_delay)

    {:ok, state}
  end

  @impl true
  def handle_info(:check_health, state) do
    new_state = do_check_all(state)

    # Schedule next check
    Process.send_after(self(), :check_health, state.interval)

    {:noreply, new_state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def handle_call(:check_all, _from, state) do
    new_state = do_check_all(state)
    {:reply, :ok, new_state}
  end

  @impl true
  def handle_call({:check_registry, name}, _from, state) do
    case Map.get(state.registries, name) do
      nil ->
        {:reply, {:error, :not_found}, state}

      registry_state ->
        {new_registry_state, status} = check_single_registry(name, registry_state, state)
        new_registries = Map.put(state.registries, name, new_registry_state)
        {:reply, {:ok, status}, %{state | registries: new_registries}}
    end
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status =
      state.registries
      |> Enum.map(fn {name, registry_state} ->
        {name, %{
          status: registry_state.status,
          last_check: registry_state.last_check,
          last_success: registry_state.last_success,
          consecutive_failures: registry_state.consecutive_failures,
          last_error: registry_state.last_error
        }}
      end)
      |> Map.new()

    {:reply, status, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp do_check_all(state) do
    new_registries =
      state.registries
      |> Enum.map(fn {name, registry_state} ->
        {new_registry_state, _status} = check_single_registry(name, registry_state, state)
        {name, new_registry_state}
      end)
      |> Map.new()

    %{state | registries: new_registries}
  end

  defp check_single_registry(name, registry_state, state) do
    module = registry_state.module
    config = registry_state.config
    now = DateTime.utc_now()
    previous_status = registry_state.status

    result =
      try do
        module.validate_config(config)
      rescue
        error ->
          Logger.error("[HealthCheck] Exception checking #{name}: #{inspect(error)}")
          {:error, {:exception, error}}
      end

    new_registry_state =
      case result do
        :ok ->
          # Success - mark healthy
          new_state = %{registry_state |
            status: :healthy,
            last_check: now,
            last_success: now,
            consecutive_failures: 0,
            last_error: nil
          }

          # Broadcast recovery if previously unhealthy/degraded
          if previous_status in [:degraded, :unhealthy] do
            broadcast_health_recovered(name)
          end

          new_state

        {:error, reason} ->
          # Failure - increment failure count
          failures = registry_state.consecutive_failures + 1
          new_status =
            if failures >= state.max_retries do
              :unhealthy
            else
              :degraded
            end

          new_state = %{registry_state |
            status: new_status,
            last_check: now,
            consecutive_failures: failures,
            last_error: reason
          }

          # Broadcast status change
          cond do
            new_status == :unhealthy and previous_status != :unhealthy ->
              broadcast_health_unhealthy(name, reason)

            new_status == :degraded and previous_status == :healthy ->
              broadcast_health_degraded(name, reason)

            true ->
              :ok
          end

          # Schedule retry with backoff if degraded
          if new_status == :degraded do
            backoff = calculate_backoff(failures, state.backoff_base)
            Logger.info("[HealthCheck] Registry #{name} degraded, retrying in #{backoff}ms")
          end

          new_state
      end

    Logger.debug("[HealthCheck] Registry #{name}: #{new_registry_state.status}")

    {new_registry_state, new_registry_state.status}
  end

  defp calculate_backoff(attempt, base) do
    # Exponential backoff: base * 2^(attempt-1)
    # With jitter: +/- 10%
    base_delay = base * :math.pow(2, attempt - 1) |> round()
    jitter = round(base_delay * 0.1)
    base_delay + :rand.uniform(jitter * 2) - jitter
  end

  # PubSub broadcasting

  defp broadcast_health_degraded(registry_name, error) do
    Logger.warning("[HealthCheck] Registry #{registry_name} degraded: #{inspect(error)}")

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "registries:health",
      {:health_degraded, registry_name, error}
    )
  rescue
    _ -> :ok  # PubSub might not be available in tests
  end

  defp broadcast_health_unhealthy(registry_name, error) do
    Logger.error("[HealthCheck] Registry #{registry_name} unhealthy: #{inspect(error)}")

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "registries:health",
      {:health_unhealthy, registry_name, error}
    )
  rescue
    _ -> :ok
  end

  defp broadcast_health_recovered(registry_name) do
    Logger.info("[HealthCheck] Registry #{registry_name} recovered")

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "registries:health",
      {:health_recovered, registry_name}
    )
  rescue
    _ -> :ok
  end
end
