defmodule TamanduaServer.Solana.RelayBatch do
  @moduledoc """
  Batches attestations from self-hosted instances and publishes to Solana.

  ## How it works

  1. Self-hosted instances send attestation hashes to relay API
  2. Hashes are queued in a batch buffer
  3. Every N seconds (or when batch is full), publish single Solana tx
  4. One transaction can contain 10-50 attestation hashes (memo limit)
  5. Cost is amortized: 1 tx fee / N attestations

  ## Economics

  - Single Solana tx fee: ~0.000005 SOL (~$0.001)
  - Batch of 50 attestations: $0.00002 per attestation
  - 1000 operators × 100 attestations/month = 100,000 attestations
  - 2000 batch transactions × $0.001 = $2/month total

  This makes sponsoring the entire network viable.

  ## Configuration

      config :tamandua_server, TamanduaServer.Solana.RelayBatch,
        enabled: true,
        batch_size: 50,           # Max attestations per tx
        batch_interval_ms: 30_000, # Flush every 30s
        max_queue_size: 10_000    # Buffer limit
  """

  use GenServer
  require Logger

  alias TamanduaServer.Solana.Client

  @default_batch_size 50
  @default_batch_interval_ms 30_000
  @default_max_queue_size 10_000

  defmodule State do
    @moduledoc false
    defstruct [
      :queue,
      :batch_timer,
      :stats
    ]
  end

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Queue an attestation for batched publication.

  Returns {:ok, batch_info} with batch_id and position in queue.
  """
  @spec queue_attestation(map()) :: {:ok, map()} | {:error, term()}
  def queue_attestation(attestation) do
    if enabled?() do
      GenServer.call(__MODULE__, {:queue, attestation})
    else
      {:error, :relay_disabled}
    end
  end

  @doc """
  Get current batch status.
  """
  @spec status() :: map()
  def status do
    if Process.whereis(__MODULE__) do
      GenServer.call(__MODULE__, :status)
    else
      %{enabled: false, queue_size: 0}
    end
  end

  @doc """
  Force flush current batch (for testing/admin).
  """
  @spec flush() :: {:ok, map()} | {:error, term()}
  def flush do
    GenServer.call(__MODULE__, :flush, 60_000)
  end

  def enabled? do
    config()[:enabled] != false
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    state = %State{
      queue: :queue.new(),
      batch_timer: nil,
      stats: %{
        total_queued: 0,
        total_published: 0,
        total_batches: 0,
        last_batch_at: nil
      }
    }

    # Start batch timer
    timer = schedule_batch_flush()

    Logger.info("[RelayBatch] Started with batch_size=#{batch_size()}, interval=#{batch_interval_ms()}ms")

    {:ok, %{state | batch_timer: timer}}
  end

  @impl true
  def handle_call({:queue, attestation}, _from, state) do
    queue_size = :queue.len(state.queue)

    if queue_size >= max_queue_size() do
      {:reply, {:error, :queue_full}, state}
    else
      # Generate batch ID based on current time window
      batch_id = current_batch_id()
      position = queue_size + 1

      # Add to queue
      entry = %{
        attestation: attestation,
        queued_at: DateTime.utc_now(),
        batch_id: batch_id,
        position: position
      }

      new_queue = :queue.in(entry, state.queue)
      new_stats = %{state.stats | total_queued: state.stats.total_queued + 1}

      Logger.debug("[RelayBatch] Queued attestation: batch=#{batch_id}, position=#{position}")

      # Check if batch is full
      new_state = %{state | queue: new_queue, stats: new_stats}
      new_state = maybe_flush_batch(new_state)

      {:reply, {:ok, %{batch_id: batch_id, position: position, queue_size: :queue.len(new_state.queue)}}, new_state}
    end
  end

  @impl true
  def handle_call(:status, _from, state) do
    status = %{
      enabled: true,
      queue_size: :queue.len(state.queue),
      batch_size: batch_size(),
      batch_interval_ms: batch_interval_ms(),
      stats: state.stats
    }
    {:reply, status, state}
  end

  @impl true
  def handle_call(:flush, _from, state) do
    {result, new_state} = do_flush_batch(state)
    {:reply, result, new_state}
  end

  @impl true
  def handle_info(:batch_timer, state) do
    # Periodic flush
    {_result, new_state} = do_flush_batch(state)

    # Reschedule
    timer = schedule_batch_flush()

    {:noreply, %{new_state | batch_timer: timer}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private

  defp maybe_flush_batch(state) do
    if :queue.len(state.queue) >= batch_size() do
      {_result, new_state} = do_flush_batch(state)
      new_state
    else
      state
    end
  end

  defp do_flush_batch(state) do
    queue_size = :queue.len(state.queue)

    if queue_size == 0 do
      {{:ok, %{published: 0}}, state}
    else
      # Take up to batch_size items
      {batch, remaining_queue} = take_batch(state.queue, batch_size())

      # Build combined memo
      memo = build_batch_memo(batch)

      # Submit to Solana
      case submit_batch_tx(memo) do
        {:ok, signature} ->
          batch_count = length(batch)

          Logger.info("[RelayBatch] Published batch: #{batch_count} attestations, tx=#{signature}")

          new_stats = %{state.stats |
            total_published: state.stats.total_published + batch_count,
            total_batches: state.stats.total_batches + 1,
            last_batch_at: DateTime.utc_now()
          }

          result = {:ok, %{
            published: batch_count,
            tx_signature: signature,
            solscan_url: Client.solscan_url(signature)
          }}

          {result, %{state | queue: remaining_queue, stats: new_stats}}

        {:error, reason} ->
          Logger.error("[RelayBatch] Failed to publish batch: #{inspect(reason)}")
          # Keep items in queue for retry
          {{:error, reason}, state}
      end
    end
  end

  defp take_batch(queue, count) do
    take_batch(queue, count, [])
  end

  defp take_batch(queue, 0, acc) do
    {Enum.reverse(acc), queue}
  end

  defp take_batch(queue, count, acc) do
    case :queue.out(queue) do
      {{:value, item}, new_queue} ->
        take_batch(new_queue, count - 1, [item | acc])

      {:empty, queue} ->
        {Enum.reverse(acc), queue}
    end
  end

  defp build_batch_memo(batch) do
    # Compact format: array of attestation hashes
    hashes = Enum.map(batch, fn entry ->
      entry.attestation["ih"] || Base.encode16(entry.attestation[:incident_hash] || <<>>, case: :lower)
    end)

    Jason.encode!(%{
      t: "tamandua_batch",
      v: 1,
      n: length(batch),
      h: hashes,
      ts: DateTime.utc_now() |> DateTime.to_unix()
    })
  end

  defp submit_batch_tx(memo) do
    # Use existing Solana client
    if Client.enabled?() do
      Client.submit_memo(memo)
    else
      Logger.info("[RelayBatch] Solana disabled, batch remains queued")
      {:error, :solana_disabled}
    end
  end

  defp current_batch_id do
    # Batch ID based on 30-second windows
    now = DateTime.utc_now() |> DateTime.to_unix()
    window = div(now, 30)
    "batch_#{window}"
  end

  defp schedule_batch_flush do
    Process.send_after(self(), :batch_timer, batch_interval_ms())
  end

  defp batch_size, do: config()[:batch_size] || @default_batch_size
  defp batch_interval_ms, do: config()[:batch_interval_ms] || @default_batch_interval_ms
  defp max_queue_size, do: config()[:max_queue_size] || @default_max_queue_size

  defp config do
    Application.get_env(:tamandua_server, __MODULE__, [])
  end
end
