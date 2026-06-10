defmodule TamanduaServer.Resilience.Fuse do
  @moduledoc """
  Circuit breaker implementation using the :fuse library.

  Provides a simple wrapper around :fuse with telemetry events
  and sensible defaults for Tamandua's production environment.

  ## Configuration

  Default fuse options:
  - 5 failures within 10 seconds triggers the breaker
  - 30 second cooldown before attempting recovery

  ## Usage

      # Install a fuse
      Fuse.install(:ml_service)

      # Run code with circuit breaker protection
      case Fuse.run(:ml_service, fn -> MLClient.scan(file) end) do
        {:ok, result} -> result
        {:error, :blown} -> {:error, :service_unavailable}
        {:error, reason} -> {:error, reason}
      end

  ## Telemetry Events

  - `[:tamandua, :fuse, :blown]` - Circuit breaker tripped
  - `[:tamandua, :fuse, :reset]` - Circuit breaker recovered
  """

  require Logger

  @default_fuse_opts {{:standard, 5, 10_000}, {:reset, 30_000}}

  @doc """
  Install a named fuse with optional configuration.

  ## Options

  Default: `{{:standard, 5, 10_000}, {:reset, 30_000}}`
  - 5 failures in 10 seconds triggers the breaker
  - 30 second reset period

  Custom example:
  ```elixir
  Fuse.install(:api, {{:standard, 3, 5000}, {:reset, 10_000}})
  ```
  """
  def install(name, opts \\ @default_fuse_opts) do
    case :fuse.install(name, opts) do
      :ok ->
        Logger.info("Fuse installed: #{name}")
        :ok

      {:error, :already_installed} ->
        Logger.debug("Fuse already installed: #{name}")
        :ok

      error ->
        Logger.error("Failed to install fuse #{name}: #{inspect(error)}")
        error
    end
  end

  @doc """
  Check fuse status without executing code.

  Returns `:ok` if healthy, `:blown` if tripped.
  """
  def ask(name, mode \\ :sync) do
    case :fuse.ask(name, mode) do
      :ok -> :ok
      :blown -> :blown
      {:error, :not_found} -> :ok  # Treat missing fuse as healthy
    end
  end

  @doc """
  Execute a function with circuit breaker protection.

  Returns `{:ok, result}` on success, `{:error, :blown}` if circuit is open,
  or `{:error, reason}` if the function fails.
  """
  def run(name, func, mode \\ :sync) do
    case :fuse.run(name, func, mode) do
      {:ok, result} ->
        {:ok, result}

      {:error, :blown} ->
        emit_telemetry(:blown, name)
        Logger.warning("Circuit breaker blown: #{name}")
        {:error, :blown}

      {:error, reason} ->
        Logger.warning("Circuit breaker error for #{name}: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    error ->
      Logger.error("Exception in circuit breaker #{name}: #{Exception.message(error)}")
      {:error, :exception}
  end

  @doc """
  Manually trip the fuse (put it in :blown state).
  """
  def melt(name) do
    :fuse.melt(name)
    emit_telemetry(:blown, name)
    Logger.warning("Fuse manually melted: #{name}")
    :ok
  end

  @doc """
  Manually reset the fuse (return to :ok state).
  """
  def reset(name) do
    :fuse.reset(name)
    emit_telemetry(:reset, name)
    Logger.info("Fuse manually reset: #{name}")
    :ok
  end

  @doc """
  Get the current status of a fuse.

  Returns `:ok` or `:blown`.
  """
  def status(name) do
    ask(name)
  end

  defp emit_telemetry(event, name) do
    :telemetry.execute(
      [:tamandua, :fuse, event],
      %{count: 1},
      %{fuse_name: name}
    )
  end
end
