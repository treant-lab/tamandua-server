defmodule TamanduaServerWeb.Plugs.RateLimiterStore do
  @moduledoc false

  use GenServer

  @table :rate_limiter

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def ensure_table do
    case :ets.whereis(@table) do
      :undefined ->
        case Process.whereis(__MODULE__) do
          nil -> create_table()
          _pid -> GenServer.call(__MODULE__, :ensure_table)
        end

      _table ->
        :ok
    end
  end

  @impl true
  def init(_opts) do
    create_table()
    {:ok, %{}}
  end

  @impl true
  def handle_call(:ensure_table, _from, state) do
    {:reply, create_table(), state}
  end

  defp create_table do
    case :ets.whereis(@table) do
      :undefined ->
        try do
          :ets.new(@table, [
            :set,
            :public,
            :named_table,
            read_concurrency: true,
            write_concurrency: true
          ])

          :ok
        rescue
          ArgumentError -> :ok
        end

      _table ->
        :ok
    end
  end
end
