defmodule TamanduaServer.Detection.IOCGenerationOwner do
  @moduledoc false

  use GenServer

  @version_table :detection_rule_versions

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, :ok, name: Keyword.get(opts, :name, __MODULE__))
  end

  def ensure_started do
    case Process.whereis(__MODULE__) do
      pid when is_pid(pid) -> :ok
      nil -> {:error, :generation_owner_unavailable}
    end
  end

  def create_generation do
    GenServer.call(__MODULE__, :create_generation)
  catch
    :exit, _reason -> {:error, :generation_owner_unavailable}
  end

  def pin_generation(table) when is_reference(table) do
    GenServer.call(__MODULE__, {:pin_generation, table})
  catch
    :exit, _reason -> {:error, :generation_owner_unavailable}
  end

  def pin_generation(_table), do: {:error, :ioc_generation_unavailable}

  def release_generation(table) when is_reference(table) do
    GenServer.call(__MODULE__, {:release_generation, table})
  catch
    :exit, _reason -> :ok
  end

  def release_generation(_table), do: :ok

  def retire_generation(table) when is_reference(table) do
    GenServer.call(__MODULE__, {:retire_generation, table})
  catch
    :exit, _reason -> :ok
  end

  def retire_generation(_table), do: :ok

  @impl true
  def init(:ok) do
    # If this owner restarted, every generation it owned disappeared. Mark the
    # publication fence unavailable so readiness fails closed and the local
    # reconciler rebuilds from database authority.
    if :ets.whereis(@version_table) != :undefined do
      :ets.insert(@version_table, {:ioc, :unavailable, -1})
    end

    {:ok, %{generations: %{}, readers: %{}}}
  end

  @impl true
  def handle_call(:create_generation, _from, state) do
    table =
      :ets.new(:detection_ioc_generation, [
        :set,
        :public,
        {:read_concurrency, true}
      ])

    generation = %{pin_count: 0, retired: false}
    {:reply, {:ok, table}, put_in(state, [:generations, table], generation)}
  end

  def handle_call({:pin_generation, table}, {reader, _tag}, state) do
    case Map.get(state.generations, table) do
      %{retired: false} = generation when is_pid(reader) ->
        {reader_state, readers} = ensure_reader(state.readers, reader)
        pins = Map.update(reader_state.pins, table, 1, &(&1 + 1))
        readers = Map.put(readers, reader, %{reader_state | pins: pins})

        generations =
          Map.put(state.generations, table, %{generation | pin_count: generation.pin_count + 1})

        {:reply, :ok, %{state | generations: generations, readers: readers}}

      _ ->
        {:reply, {:error, :ioc_generation_unavailable}, state}
    end
  end

  def handle_call({:release_generation, table}, {reader, _tag}, state) do
    {:reply, :ok, release_pin(state, reader, table)}
  end

  def handle_call({:retire_generation, table}, _from, state) do
    {:reply, :ok, retire_generation_now_or_later(state, table)}
  end

  @impl true
  def handle_info({:DOWN, monitor, :process, reader, _reason}, state) do
    case Map.get(state.readers, reader) do
      %{monitor: ^monitor, pins: pins} ->
        state = %{state | readers: Map.delete(state.readers, reader)}

        next =
          Enum.reduce(pins, state, fn {table, count}, acc ->
            decrement_generation(acc, table, count)
          end)

        {:noreply, next}

      _ ->
        {:noreply, state}
    end
  end

  defp ensure_reader(readers, reader) do
    case Map.fetch(readers, reader) do
      {:ok, reader_state} ->
        {reader_state, readers}

      :error ->
        reader_state = %{monitor: Process.monitor(reader), pins: %{}}
        {reader_state, Map.put(readers, reader, reader_state)}
    end
  end

  defp release_pin(state, reader, table) do
    case Map.get(state.readers, reader) do
      %{pins: pins} = reader_state ->
        case Map.get(pins, table, 0) do
          count when count > 1 ->
            readers =
              Map.put(state.readers, reader, %{
                reader_state
                | pins: Map.put(pins, table, count - 1)
              })

            state
            |> Map.put(:readers, readers)
            |> decrement_generation(table, 1)

          1 ->
            pins = Map.delete(pins, table)

            state =
              if map_size(pins) == 0 do
                Process.demonitor(reader_state.monitor, [:flush])
                %{state | readers: Map.delete(state.readers, reader)}
              else
                put_in(state, [:readers, reader, :pins], pins)
              end

            decrement_generation(state, table, 1)

          _ ->
            state
        end

      _ ->
        state
    end
  end

  defp decrement_generation(state, table, count) do
    case Map.get(state.generations, table) do
      %{pin_count: pin_count} = generation ->
        remaining = max(pin_count - count, 0)

        if generation.retired and remaining == 0 do
          delete_generation(state, table)
        else
          put_in(state, [:generations, table, :pin_count], remaining)
        end

      nil ->
        state
    end
  end

  defp retire_generation_now_or_later(state, table) do
    case Map.get(state.generations, table) do
      %{pin_count: 0} ->
        delete_generation(state, table)

      %{} ->
        put_in(state, [:generations, table, :retired], true)

      nil ->
        state
    end
  end

  defp delete_generation(state, table) do
    if :ets.info(table) != :undefined do
      :ets.delete(table)
    end

    %{state | generations: Map.delete(state.generations, table)}
  end
end
