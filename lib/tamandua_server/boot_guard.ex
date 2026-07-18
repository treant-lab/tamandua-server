defmodule TamanduaServer.BootGuard do
  @moduledoc false

  require Logger

  @status_key {__MODULE__, :status}

  @spec start((-> Supervisor.on_start()), :infinity | pos_integer()) :: Supervisor.on_start()
  def start(starter, :infinity) when is_function(starter, 0) do
    put_status(:starting, :infinity)

    starter.()
    |> record_result()
  end

  def start(starter, timeout_ms)
      when is_function(starter, 0) and is_integer(timeout_ms) and timeout_ms > 0 do
    put_status(:starting, timeout_ms)
    caller = self()
    result_ref = make_ref()

    {starter_pid, monitor_ref} =
      spawn_monitor(fn ->
        result = starter.()
        send(caller, {result_ref, result})
        remain_supervisor_parent(result)
      end)

    receive do
      {^result_ref, result} ->
        # Supervisor.start_link/2 ties the root supervisor to its calling
        # process. Keep this small proxy alive as that OTP parent, and link it
        # to the application callback so both lifecycles remain coupled.
        if match?({:ok, pid} when is_pid(pid), result) do
          Process.link(starter_pid)
        end

        Process.demonitor(monitor_ref, [:flush])
        record_result(result)

      {:DOWN, ^monitor_ref, :process, ^starter_pid, reason} ->
        put_status(:failed, timeout_ms)
        {:error, reason}
    after
      timeout_ms ->
        # A child may be stuck in a synchronous init callback. Killing the
        # linked starter also tears down any partially-started supervisor tree,
        # so the application fails cleanly instead of leaving orphan children.
        Process.exit(starter_pid, :kill)

        receive do
          {:DOWN, ^monitor_ref, :process, ^starter_pid, _reason} -> :ok
        after
          1_000 -> :ok
        end

        put_status(:timed_out, timeout_ms)

        Logger.error(
          "Tamandua supervision tree did not start within #{timeout_ms}ms; " <>
            "partial boot was terminated"
        )

        {:error, {:boot_timeout, timeout_ms}}
    end
  end

  @spec status() :: map()
  def status do
    :persistent_term.get(@status_key, %{
      state: :not_started,
      timeout_ms: nil,
      changed_at_ms: nil
    })
  end

  defp record_result({:ok, pid} = result) do
    # The supervisor was created by the bounded starter proxy. Link it to
    # the application callback process before returning, preserving OTP's
    # required application-master <-> root-supervisor lifecycle semantics.
    Process.link(pid)
    put_status(:ready, current_timeout())
    result
  end

  defp record_result({:error, _reason} = result) do
    put_status(:failed, current_timeout())
    result
  end

  defp record_result(other) do
    put_status(:failed, current_timeout())
    other
  end

  defp remain_supervisor_parent({:ok, pid}) when is_pid(pid) do
    monitor_ref = Process.monitor(pid)

    receive do
      {:DOWN, ^monitor_ref, :process, ^pid, _reason} -> :ok
    end
  end

  defp remain_supervisor_parent(_result), do: :ok

  defp current_timeout do
    status().timeout_ms
  end

  defp put_status(state, timeout_ms) do
    :persistent_term.put(@status_key, %{
      state: state,
      timeout_ms: timeout_ms,
      changed_at_ms: System.monotonic_time(:millisecond)
    })
  end
end
