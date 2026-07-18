defmodule TamanduaServer.Detection.IOCReconciler do
  @moduledoc """
  Per-node IOC snapshot reconciler.

  Each application node independently polls the durable authority epoch. This
  intentionally does not use cluster membership or remote process discovery.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Detection.{IOCSnapshotProvider, RuleLoader}

  @default_poll_interval_ms 5_000

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @spec request_reconcile(GenServer.server()) :: :ok
  def request_reconcile(server \\ __MODULE__) do
    GenServer.cast(server, :reconcile)
  end

  @spec reconcile_now(GenServer.server(), timeout()) :: {:ok, map()} | {:error, term()}
  def reconcile_now(server \\ __MODULE__, timeout \\ 65_000) do
    GenServer.call(server, :reconcile, timeout)
  end

  @spec status(GenServer.server()) :: map()
  def status(server \\ __MODULE__), do: GenServer.call(server, :status)

  @impl true
  def init(opts) do
    poll_interval = Keyword.get(opts, :poll_interval_ms, @default_poll_interval_ms)
    reconcile_fun = Keyword.get(opts, :reconcile_fun, &IOCSnapshotProvider.reconcile/0)
    epoch_fun = Keyword.get(opts, :epoch_fun, &IOCSnapshotProvider.probe/0)
    preflight_fun = Keyword.get(opts, :preflight_fun, fn -> :ok end)
    initial? = Keyword.get(opts, :initial_reconcile, true)

    state = %{
      poll_interval_ms: poll_interval,
      reconcile_fun: reconcile_fun,
      epoch_fun: epoch_fun,
      preflight_fun: preflight_fun,
      healthy: false,
      reconciling: false,
      reconcile_requested: false,
      last_error: nil,
      last_reconciled_at: nil
    }

    result =
      if initial? do
        with :ok <- validate_preflight(safe_preflight(preflight_fun)),
             {:ok, _epoch} <- safe_epoch(epoch_fun) do
          reconcile_fun.()
        end
      else
        {:ok, %{published_epoch: RuleLoader.published_ioc_epoch()}}
      end

    case apply_result(state, result) do
      {:ok, initialized} ->
        schedule_poll(poll_interval)
        {:ok, initialized}

      {:error, reason, _failed} ->
        {:stop, {:ioc_initial_snapshot_failed, reason}}
    end
  end

  @impl true
  def handle_cast(:reconcile, state) do
    {:noreply, request_reconcile_once(state)}
  end

  @impl true
  def handle_call(:reconcile, _from, state) do
    case run_reconcile(state) do
      {:ok, result, next} -> {:reply, {:ok, result}, next}
      {:error, reason, next} -> {:reply, {:error, reason}, next}
    end
  end

  def handle_call(:status, _from, state) do
    authority_epoch = safe_epoch(state.epoch_fun)
    preflight = safe_preflight(state.preflight_fun)
    published_epoch = RuleLoader.published_ioc_epoch()
    published_snapshot = RuleLoader.published_ioc_snapshot()
    regression = epoch_regression(authority_epoch, published_epoch)
    pending = pending?(authority_epoch, published_epoch)

    next =
      case validate_preflight(preflight) do
        {:error, reason} ->
          mark_unhealthy(state, reason)

        :ok ->
          case authority_epoch do
            {:error, reason} ->
              mark_unhealthy(state, reason)

            {:ok, epoch} when epoch < published_epoch ->
              mark_unhealthy(state, {:epoch_regression, epoch, published_epoch})

            {:ok, epoch} when epoch > published_epoch ->
              state
              |> mark_unhealthy({:epoch_pending, epoch, published_epoch})
              |> request_reconcile_once()

            {:ok, _equal_epoch}
            when not state.healthy or not is_nil(state.last_error) ->
              request_reconcile_once(state)

            {:ok, _equal_epoch} ->
              state
          end
      end

    healthy =
      next.healthy and match?({:ok, _}, authority_epoch) and preflight == :ok and
        is_nil(regression) and not pending

    availability =
      cond do
        published_snapshot.authority_epoch < 0 -> :unavailable
        healthy -> :ready
        true -> :degraded
      end

    {:reply,
     %{
       healthy: healthy,
       availability: availability,
       authority_epoch: epoch_value(authority_epoch),
       published_epoch: published_epoch,
       published_digest: published_snapshot.digest,
       published_provider: published_snapshot.provider,
       configured_provider: IOCSnapshotProvider.provider(),
       pending: pending or next.reconciling or next.reconcile_requested,
       last_error: error_category(regression || preflight_error(preflight) || next.last_error),
       last_reconciled_at: next.last_reconciled_at,
       node: node()
     }, next}
  end

  @impl true
  def handle_info(:poll, state) do
    schedule_poll(state.poll_interval_ms)
    published_epoch = RuleLoader.published_ioc_epoch()

    next =
      case validate_preflight(safe_preflight(state.preflight_fun)) do
        :ok ->
          case safe_epoch(state.epoch_fun) do
            {:ok, epoch} ->
              cond do
                epoch < published_epoch ->
                  mark_unhealthy(state, {:epoch_regression, epoch, published_epoch})

                epoch > published_epoch ->
                  state
                  |> mark_unhealthy({:epoch_pending, epoch, published_epoch})
                  |> request_reconcile_once()

                not state.healthy or not is_nil(state.last_error) ->
                  # Recovery at an equal epoch is evidence-backed: any prior
                  # DB/catalog failure must re-read and republish once before
                  # readiness can become healthy again.
                  request_reconcile_once(state)

                true ->
                  state
              end

            {:error, reason} ->
              mark_unhealthy(state, reason)
          end

        {:error, reason} ->
          mark_unhealthy(state, reason)
      end

    {:noreply, next}
  end

  def handle_info(:reconcile, %{reconciling: true} = state) do
    {:noreply, %{state | reconcile_requested: true}}
  end

  def handle_info(:reconcile, state) do
    case run_reconcile(state) do
      {:ok, _result, next} ->
        {:noreply, maybe_repeat(next)}

      {:error, reason, next} ->
        Logger.error("[IOCReconciler] local reconciliation failed: #{error_category(reason)}")
        {:noreply, maybe_repeat(next)}
    end
  end

  defp run_reconcile(state) do
    working = %{state | reconciling: true, reconcile_requested: false}

    with :ok <- validate_preflight(safe_preflight(working.preflight_fun)),
         {:ok, _epoch} <- safe_epoch(working.epoch_fun),
         {:ok, result} <- working.reconcile_fun.() do
      next = %{
        working
        | reconciling: false,
          healthy: true,
          last_error: nil,
          last_reconciled_at: DateTime.utc_now()
      }

      {:ok, result, next}
    else
      {:error, reason} ->
        {:error, reason, mark_unhealthy(%{working | reconciling: false}, reason)}

      other ->
        reason = {:unexpected_reconcile_result, other}
        {:error, reason, mark_unhealthy(%{working | reconciling: false}, reason)}
    end
  rescue
    error ->
      reason = {:reconcile_exception, Exception.message(error)}
      {:error, reason, %{state | reconciling: false, healthy: false, last_error: reason}}
  catch
    :exit, reason ->
      error = {:reconcile_exit, reason}
      {:error, error, %{state | reconciling: false, healthy: false, last_error: error}}
  end

  defp apply_result(state, {:ok, _result}) do
    {:ok, %{state | healthy: true, last_reconciled_at: DateTime.utc_now()}}
  end

  defp apply_result(state, {:error, reason}), do: {:error, reason, %{state | last_error: reason}}

  defp maybe_repeat(%{reconcile_requested: true} = state) do
    send(self(), :reconcile)
    state
  end

  defp maybe_repeat(state), do: state

  defp safe_epoch(fun) do
    fun.()
  rescue
    error -> {:error, {:epoch_exception, Exception.message(error)}}
  catch
    :exit, reason -> {:error, {:epoch_exit, reason}}
  end

  defp pending?({:ok, authority_epoch}, published_epoch), do: published_epoch != authority_epoch
  defp pending?(_, _), do: true

  defp epoch_regression({:ok, authority_epoch}, published_epoch)
       when published_epoch > authority_epoch,
       do: {:epoch_regression, authority_epoch, published_epoch}

  defp epoch_regression(_, _), do: nil

  defp safe_preflight(fun) do
    fun.()
  rescue
    error -> {:error, {:preflight_exception, Exception.message(error)}}
  catch
    :exit, reason -> {:error, {:preflight_exit, reason}}
  end

  defp preflight_error(:ok), do: nil
  defp preflight_error({:error, reason}), do: reason
  defp preflight_error(other), do: {:unexpected_preflight_result, other}

  defp epoch_value({:ok, epoch}), do: epoch
  defp epoch_value(_), do: nil

  defp validate_preflight(:ok), do: :ok
  defp validate_preflight({:error, reason}), do: {:error, reason}
  defp validate_preflight(other), do: {:error, {:unexpected_preflight_result, other}}

  defp mark_unhealthy(state, reason) do
    category = error_category(reason)

    :telemetry.execute(
      [:tamandua_server, :ioc_snapshot, :reconcile],
      %{failures: 1},
      %{provider: IOCSnapshotProvider.provider(), status: availability_for_state(state)}
    )

    %{state | healthy: false, last_error: category}
  end

  defp availability_for_state(_state) do
    if RuleLoader.published_ioc_epoch() < 0, do: :unavailable, else: :degraded
  end

  defp error_category(nil), do: nil
  defp error_category({:epoch_regression, _authority, _published}), do: :epoch_regression
  defp error_category({:epoch_pending, _authority, _published}), do: :epoch_pending
  defp error_category({category, _detail}) when is_atom(category), do: category
  defp error_category(category) when is_atom(category), do: category
  defp error_category(_reason), do: :ioc_snapshot_provider_failure

  defp request_reconcile_once(%{reconciling: true} = state),
    do: %{state | reconcile_requested: true}

  defp request_reconcile_once(%{reconcile_requested: true} = state), do: state

  defp request_reconcile_once(state) do
    send(self(), :reconcile)
    %{state | reconcile_requested: true}
  end

  defp schedule_poll(interval), do: Process.send_after(self(), :poll, interval)
end
