defmodule TamanduaServer.EmailSecurity.RuntimeSupervisor do
  @moduledoc false

  use Supervisor

  @registry TamanduaServer.EmailSecurity.IntegrationRegistry
  @supervisor TamanduaServer.EmailSecurity.IntegrationSupervisor
  alias TamanduaServer.EmailSecurity.RuntimeConfigStore

  def start_link(opts \\ []) do
    Supervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    Supervisor.init(
      [
        {Registry, keys: :unique, name: @registry},
        RuntimeConfigStore,
        {DynamicSupervisor, name: @supervisor, strategy: :one_for_one}
      ],
      strategy: :one_for_all
    )
  end

  def registry, do: @registry

  def update_config(module, organization_id, config, opts \\ [])

  def update_config(module, organization_id, config, opts)
      when is_atom(module) and is_binary(organization_id) and organization_id != "" and
             is_map(config) and is_list(opts) do
    patch = Map.delete(config, :organization_id)
    reload_timeout = Keyword.get(opts, :reload_timeout, 5_000)
    lock = {{__MODULE__, module, organization_id}, self()}

    :global.trans(lock, fn ->
      do_update_config(module, organization_id, patch, reload_timeout)
    end)
  end

  def update_config(_module, _organization_id, _config, _opts),
    do: {:error, :organization_required}

  defp do_update_config(module, organization_id, patch, reload_timeout) do
    with {:ok, previous} <- current_snapshot(module, organization_id),
         {:ok, revision, _merged_config} <-
           RuntimeConfigStore.merge(module, organization_id, patch) do
      child_opts = [organization_id: organization_id]

      case safe_start_child(module, child_opts) do
        {:ok, pid} ->
          {:ok, pid, :started, revision}

        {:error, {:already_started, pid}} ->
          case safe_reload(pid, revision, reload_timeout) do
            :ok ->
              {:ok, pid, :existing, revision}

            {:error, _reason} ->
              rollback_and_recover(module, organization_id, revision, previous, pid)
          end

        {:error, _reason} ->
          rollback_start_failure(module, organization_id, revision, previous)
      end
    end
  end

  defp current_snapshot(module, organization_id) do
    case RuntimeConfigStore.fetch(module, organization_id) do
      {:ok, revision, config} -> {:ok, {revision, config}}
      {:error, :integration_not_configured} -> {:ok, :not_configured}
      {:error, reason} -> {:error, reason}
    end
  end

  defp safe_start_child(module, opts) do
    DynamicSupervisor.start_child(@supervisor, {module, opts})
  catch
    :exit, _reason -> {:error, :provider_start_failed}
  end

  defp safe_reload(pid, revision, timeout) do
    case GenServer.call(pid, {:reload_config, revision}, timeout) do
      :ok -> :ok
      _rejected -> {:error, :provider_reload_failed}
    end
  catch
    :exit, _reason -> {:error, :provider_reload_failed}
  end

  defp rollback_start_failure(module, organization_id, revision, previous) do
    case RuntimeConfigStore.rollback(module, organization_id, revision, previous) do
      :ok -> {:error, :provider_start_failed}
      {:error, _reason} -> {:error, :runtime_config_rollback_failed}
    end
  end

  defp rollback_and_recover(module, organization_id, revision, previous, pid) do
    case RuntimeConfigStore.rollback(module, organization_id, revision, previous) do
      :ok ->
        case restart_provider(module, organization_id, pid) do
          :ok -> {:error, :provider_reload_failed}
          {:error, _reason} -> {:error, :provider_recovery_failed}
        end

      {:error, _reason} ->
        {:error, :runtime_config_rollback_failed}
    end
  end

  defp restart_provider(module, organization_id, pid) do
    with :ok <- safe_terminate_child(pid),
         {:ok, replacement_pid} when replacement_pid != pid <-
           start_replacement(module, organization_id) do
      :ok
    else
      _failure -> {:error, :provider_restart_failed}
    end
  end

  defp safe_terminate_child(pid) do
    case DynamicSupervisor.terminate_child(@supervisor, pid) do
      :ok -> :ok
      {:error, :not_found} -> :ok
      {:error, _reason} -> {:error, :provider_stop_failed}
    end
  catch
    :exit, _reason -> {:error, :provider_stop_failed}
  end

  defp start_replacement(module, organization_id) do
    case safe_start_child(module, organization_id: organization_id) do
      {:ok, pid} -> {:ok, pid}
      {:error, {:already_started, pid}} -> {:ok, pid}
      {:error, _reason} -> {:error, :provider_restart_failed}
    end
  end

  def via(module, organization_id) do
    {:via, Registry, {@registry, {module, organization_id}}}
  end

  def lookup(module, organization_id)
      when is_atom(module) and is_binary(organization_id) and organization_id != "" do
    case Registry.lookup(@registry, {module, organization_id}) do
      [{pid, _}] -> {:ok, pid}
      [] -> {:error, :integration_not_configured}
    end
  end

  def lookup(_module, _organization_id), do: {:error, :organization_required}
end
