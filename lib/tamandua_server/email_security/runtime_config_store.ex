defmodule TamanduaServer.EmailSecurity.RuntimeConfigStore do
  @moduledoc false

  use GenServer

  @derive {Inspect, except: [:configs]}
  defstruct configs: %{}

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def merge(module, organization_id, patch)
      when is_atom(module) and is_binary(organization_id) and organization_id != "" and
             is_map(patch) do
    safe_call({:merge, module, organization_id, patch})
  end

  def merge(_module, _organization_id, _patch), do: {:error, :organization_required}

  def fetch(module, organization_id)
      when is_atom(module) and is_binary(organization_id) and organization_id != "" do
    safe_call({:fetch, module, organization_id})
  end

  def fetch(_module, _organization_id), do: {:error, :organization_required}

  def rollback(module, organization_id, expected_revision, :not_configured)
      when is_atom(module) and is_binary(organization_id) and organization_id != "" and
             is_integer(expected_revision) and expected_revision > 0 do
    safe_call({:rollback, module, organization_id, expected_revision, :not_configured})
  end

  def rollback(module, organization_id, expected_revision, {previous_revision, previous_config})
      when is_atom(module) and is_binary(organization_id) and organization_id != "" and
             is_integer(expected_revision) and expected_revision > 0 and
             is_integer(previous_revision) and previous_revision > 0 and is_map(previous_config) do
    safe_call(
      {:rollback, module, organization_id, expected_revision,
       {previous_revision, previous_config}}
    )
  end

  def rollback(_module, _organization_id, _expected_revision, _previous),
    do: {:error, :invalid_rollback}

  @impl true
  def init(_opts), do: {:ok, %__MODULE__{}}

  @impl true
  def handle_call({:merge, module, organization_id, patch}, _from, state) do
    key = {module, organization_id}
    {revision, current} = Map.get(state.configs, key, {0, %{}})
    next = {revision + 1, Map.merge(current, patch)}

    {:reply, {:ok, elem(next, 0), elem(next, 1)},
     %{state | configs: Map.put(state.configs, key, next)}}
  end

  def handle_call({:fetch, module, organization_id}, _from, state) do
    case Map.fetch(state.configs, {module, organization_id}) do
      {:ok, {revision, config}} -> {:reply, {:ok, revision, config}, state}
      :error -> {:reply, {:error, :integration_not_configured}, state}
    end
  end

  def handle_call(
        {:rollback, module, organization_id, expected_revision, previous},
        _from,
        state
      ) do
    key = {module, organization_id}

    case Map.fetch(state.configs, key) do
      {:ok, {^expected_revision, _current}} ->
        configs = restore_previous(state.configs, key, previous)
        {:reply, :ok, %{state | configs: configs}}

      _stale_or_missing ->
        {:reply, {:error, :revision_conflict}, state}
    end
  end

  defp safe_call(message) do
    GenServer.call(__MODULE__, message)
  catch
    :exit, _reason -> {:error, :runtime_config_unavailable}
  end

  defp restore_previous(configs, key, :not_configured), do: Map.delete(configs, key)

  defp restore_previous(configs, key, {revision, config})
       when is_integer(revision) and revision > 0 and is_map(config) do
    Map.put(configs, key, {revision, config})
  end
end
