defmodule TamanduaServer.Detection.ML.ClientTest do
  @moduledoc """
  Circuit-breaker and caller-side HTTP tests for the ML client.

  Uses a minimal :gen_tcp HTTP stub (Bypass is not a project dependency) and
  the shared, app-started ML.Client singleton — so these tests are
  `async: false` and reset the circuit + :ml_service_url around each test.

  No database access is required.
  """
  use ExUnit.Case, async: false

  alias TamanduaServer.Detection.ML.Client

  @circuit_table :tamandua_ml_client_circuit
  @failure_threshold 5

  setup do
    # The application supervision tree starts the singleton; make sure it is
    # up (and thus the ETS table exists) even in trimmed test environments.
    unless Process.whereis(Client), do: start_supervised!(Client)

    previous_url = Application.get_env(:tamandua_server, :ml_service_url)
    Client.reset_circuit()

    on_exit(fn ->
      Application.put_env(:tamandua_server, :ml_service_url, previous_url)
      Client.reset_circuit()
    end)

    :ok
  end

  # ==========================================================================
  # Tests
  # ==========================================================================

  test "circuit opens after threshold consecutive failures" do
    # Point at a port with no listener -> fast connection refusals.
    Application.put_env(:tamandua_server, :ml_service_url, refused_url())

    # healthy?/0 performs a single, non-retried request per call.
    for _ <- 1..@failure_threshold do
      refute Client.healthy?()
    end

    status = Client.circuit_status()
    assert status.state == :open
    assert status.failures >= @failure_threshold
  end

  test "open circuit returns fast error without touching the ML service" do
    {url, counter} = start_http_stub(fn _n -> {200, ~s({"prediction":"benign"}), 0} end)
    Application.put_env(:tamandua_server, :ml_service_url, url)

    # Freshly opened circuit (reset timeout NOT yet elapsed).
    force_circuit(:open, opened_at: now_ms())

    {elapsed_us, result} = :timer.tc(fn -> Client.predict(unique_sample()) end)

    assert result == {:error, :ml_service_unavailable}
    # Pure ETS rejection: far below one retry backoff (200ms), no HTTP hit.
    assert elapsed_us < 500_000
    assert :counters.get(counter, 1) == 0
    assert Client.circuit_status().state == :open
  end

  test "half-open admits exactly one probe under concurrency" do
    # Slow success response keeps the probe in flight while the other
    # callers race through check_circuit.
    {url, counter} =
      start_http_stub(fn _n -> {200, ~s({"prediction":"benign","confidence":0.1}), 500} end)

    Application.put_env(:tamandua_server, :ml_service_url, url)

    # Open circuit whose reset timeout has elapsed -> next caller may probe.
    force_circuit(:open, opened_at: now_ms() - 61_000)

    tasks = for _ <- 1..8, do: Task.async(fn -> Client.predict(unique_sample()) end)
    results = Task.await_many(tasks, 15_000)

    successes = Enum.count(results, &match?({:ok, _}, &1))
    rejected = Enum.count(results, &(&1 == {:error, :ml_service_unavailable}))

    assert successes == 1
    assert rejected == 7
    # Exactly one HTTP request reached the service: the single probe.
    assert :counters.get(counter, 1) == 1
  end

  test "successful probe closes the circuit and subsequent requests flow" do
    {url, counter} =
      start_http_stub(fn _n -> {200, ~s({"prediction":"benign","confidence":0.2}), 0} end)

    Application.put_env(:tamandua_server, :ml_service_url, url)
    force_circuit(:open, opened_at: now_ms() - 61_000)

    assert {:ok, %{prediction: "benign"}} = Client.predict(unique_sample())

    status = Client.circuit_status()
    assert status.state == :closed
    assert status.failures == 0

    # Circuit closed: a new (uncached) prediction goes straight through.
    assert {:ok, _} = Client.predict(unique_sample())
    assert :counters.get(counter, 1) == 2
  end

  test "failed probe reopens the circuit" do
    {url, counter} = start_http_stub(fn _n -> {500, ~s({"error":"boom"}), 0} end)
    Application.put_env(:tamandua_server, :ml_service_url, url)
    force_circuit(:open, opened_at: now_ms() - 61_000)

    # The probe retries within its admission (3 attempts) and then fails.
    assert {:error, {:http_error, 500}} = Client.predict(unique_sample())
    assert :counters.get(counter, 1) == 3
    assert Client.circuit_status().state == :open

    # Fresh opened_at -> the next caller is rejected without HTTP.
    assert Client.predict(unique_sample()) == {:error, :ml_service_unavailable}
    assert :counters.get(counter, 1) == 3
  end

  test "success while closed resets the failure counter" do
    {url, _counter} = start_http_stub(fn _n -> {200, ~s({"status":"healthy"}), 0} end)

    # Two failures against a refused port (below the threshold)...
    Application.put_env(:tamandua_server, :ml_service_url, refused_url())
    refute Client.healthy?()
    refute Client.healthy?()
    assert Client.circuit_status().failures == 2
    assert Client.circuit_status().state == :closed

    # ...then a success resets the count.
    Application.put_env(:tamandua_server, :ml_service_url, url)
    assert Client.healthy?()
    assert Client.circuit_status() |> Map.take([:state, :failures]) ==
             %{state: :closed, failures: 0}
  end

  test "healthy?/0 returns false without HTTP when the circuit is open" do
    {url, counter} = start_http_stub(fn _n -> {200, ~s({"status":"healthy"}), 0} end)
    Application.put_env(:tamandua_server, :ml_service_url, url)

    force_circuit(:open, opened_at: now_ms())

    refute Client.healthy?()
    assert :counters.get(counter, 1) == 0
  end

  test "predict forwards model_trained and training_samples when present" do
    body =
      ~s({"prediction":"malicious","confidence":0.9,) <>
        ~s("model_trained":false,"training_samples":0})

    {url, _counter} = start_http_stub(fn _n -> {200, body, 0} end)
    Application.put_env(:tamandua_server, :ml_service_url, url)

    assert {:ok, prediction} = Client.predict(unique_sample())
    assert prediction.model_trained == false
    assert prediction.training_samples == 0
  end

  test "predict leaves model_trained and training_samples absent when the service omits them" do
    {url, _counter} =
      start_http_stub(fn _n -> {200, ~s({"prediction":"benign","confidence":0.2}), 0} end)

    Application.put_env(:tamandua_server, :ml_service_url, url)

    assert {:ok, prediction} = Client.predict(unique_sample())
    refute Map.has_key?(prediction, :model_trained)
    refute Map.has_key?(prediction, :training_samples)
  end

  test "predict_batch forwards trained-state fields per prediction, absent when omitted" do
    body =
      ~s({"predictions":[) <>
        ~s({"sha256":"aa","prediction":"malicious","confidence":0.8,) <>
        ~s("model_trained":true,"training_samples":1200},) <>
        ~s({"sha256":"bb","prediction":"benign","confidence":0.1}) <>
        ~s(]})

    {url, _counter} = start_http_stub(fn _n -> {200, body, 0} end)
    Application.put_env(:tamandua_server, :ml_service_url, url)

    assert {:ok, [first, second]} = Client.predict_batch([unique_sample(), unique_sample()])

    assert first.model_trained == true
    assert first.training_samples == 1200

    refute Map.has_key?(second, :model_trained)
    refute Map.has_key?(second, :training_samples)
  end

  # ==========================================================================
  # Helpers
  # ==========================================================================

  defp now_ms, do: System.monotonic_time(:millisecond)

  defp unique_sample do
    %{
      sha256: :crypto.strong_rand_bytes(32),
      content: :crypto.strong_rand_bytes(16),
      file_type: "test",
      entropy: 0.0,
      metadata: %{}
    }
  end

  # Directly seed the shared circuit record (documented layout:
  # {:circuit, state, failures, opened_at_ms, probe_acquired_at_ms}).
  defp force_circuit(:open, opts) do
    opened_at = Keyword.fetch!(opts, :opened_at)
    :ets.insert(@circuit_table, {:circuit, :open, @failure_threshold, opened_at, 0})
  end

  # A localhost URL that refuses connections: bind an ephemeral port, then
  # close the listener before returning.
  defp refused_url do
    {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(listen)
    :gen_tcp.close(listen)
    "http://127.0.0.1:#{port}"
  end

  # Minimal HTTP/1.1 stub server. `respond` receives the 1-based request
  # number and returns {status, json_body, delay_ms}. Returns {url, counter}
  # where counter tracks fully-read requests.
  defp start_http_stub(respond) do
    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, packet: :raw, active: false, reuseaddr: true])

    {:ok, port} = :inet.port(listen)
    counter = :counters.new(1, [:atomics])

    server = spawn(fn -> accept_loop(listen, respond, counter) end)

    on_exit(fn ->
      :gen_tcp.close(listen)
      Process.exit(server, :kill)
    end)

    {"http://127.0.0.1:#{port}", counter}
  end

  defp accept_loop(listen, respond, counter) do
    case :gen_tcp.accept(listen) do
      {:ok, sock} ->
        pid = spawn(fn -> handle_conn(sock, respond, counter) end)
        :gen_tcp.controlling_process(sock, pid)
        accept_loop(listen, respond, counter)

      {:error, _} ->
        :ok
    end
  end

  defp handle_conn(sock, respond, counter) do
    case read_request(sock, "") do
      :ok ->
        :counters.add(counter, 1, 1)
        n = :counters.get(counter, 1)
        {status, body, delay_ms} = respond.(n)
        if delay_ms > 0, do: Process.sleep(delay_ms)

        response =
          "HTTP/1.1 #{status} OK\r\n" <>
            "content-type: application/json\r\n" <>
            "content-length: #{byte_size(body)}\r\n" <>
            "connection: close\r\n\r\n" <> body

        :gen_tcp.send(sock, response)

      _error ->
        :ok
    end

    :gen_tcp.close(sock)
  end

  # Read headers + Content-Length bytes of body, then return :ok.
  defp read_request(sock, acc) do
    case :gen_tcp.recv(sock, 0, 5_000) do
      {:ok, data} ->
        acc = acc <> data

        case String.split(acc, "\r\n\r\n", parts: 2) do
          [headers, rest] -> read_body(sock, rest, content_length(headers))
          [_incomplete] -> read_request(sock, acc)
        end

      {:error, _} = error ->
        error
    end
  end

  defp read_body(_sock, rest, len) when byte_size(rest) >= len, do: :ok

  defp read_body(sock, rest, len) do
    case :gen_tcp.recv(sock, 0, 5_000) do
      {:ok, data} -> read_body(sock, rest <> data, len)
      {:error, _} = error -> error
    end
  end

  defp content_length(headers) do
    case Regex.run(~r/content-length:\s*(\d+)/i, headers) do
      [_, n] -> String.to_integer(n)
      nil -> 0
    end
  end
end
