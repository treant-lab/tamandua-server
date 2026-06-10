defmodule TamanduaServer.ThreatIntel.Feeds.PhishTank do
  @moduledoc """
  PhishTank Feed Integration.

  PhishTank is a community-driven phishing verification service:
  - Verified phishing URLs
  - Community voting on submissions
  - Real-time phishing detection
  - Historical phishing data

  The basic feed is free, API access requires registration.
  """

  use GenServer
  require Logger

  alias TamanduaServer.ThreatIntel.Aggregator

  @default_sync_interval :timer.hours(2)  # Phishing URLs change frequently
  @http_timeout 120_000  # PhishTank can be slow

  # PhishTank feeds
  @feeds %{
    verified_online: "http://data.phishtank.com/data/online-valid.csv",
    verified_json: "http://data.phishtank.com/data/online-valid.json"
  }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Trigger manual sync.
  """
  @spec sync_all() :: :ok
  def sync_all do
    GenServer.cast(__MODULE__, :sync_all)
  end

  @doc """
  Check if a URL is a known phishing URL.
  """
  @spec check_url(String.t()) :: {:ok, map()} | :not_found
  def check_url(url) do
    GenServer.call(__MODULE__, {:check_url, url})
  end

  @doc """
  Get recent phishing URLs.
  """
  @spec get_recent(keyword()) :: {:ok, [map()]} | {:error, term()}
  def get_recent(opts \\ []) do
    GenServer.call(__MODULE__, {:get_recent, opts}, @http_timeout)
  end

  @doc """
  Get current status.
  """
  @spec get_status() :: map()
  def get_status do
    GenServer.call(__MODULE__, :get_status)
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(opts) do
    # Create ETS table for URL lookups
    :ets.new(:phishtank_urls, [:named_table, :set, :public, read_concurrency: true])

    state = %{
      api_key: Keyword.get(opts, :api_key) || System.get_env("PHISHTANK_API_KEY"),
      enabled: Keyword.get(opts, :enabled, true),
      sync_interval: Keyword.get(opts, :sync_interval, @default_sync_interval),
      last_sync: nil,
      stats: %{
        urls_imported: 0,
        targets: %{}
      }
    }

    if state.enabled do
      Process.send_after(self(), :initial_sync, :timer.seconds(45))
      schedule_sync(state.sync_interval)
      Logger.info("[PhishTank] Initialized")
    end

    {:ok, state}
  end

  @impl true
  def handle_call({:check_url, url}, _from, state) do
    normalized = normalize_url(url)
    result = case :ets.lookup(:phishtank_urls, normalized) do
      [{_, data}] -> {:ok, data}
      [] -> :not_found
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_recent, opts}, _from, state) do
    limit = Keyword.get(opts, :limit, 100)

    recent = :ets.tab2list(:phishtank_urls)
    |> Enum.sort_by(fn {_, data} -> data.submission_time end, {:desc, DateTime})
    |> Enum.take(limit)
    |> Enum.map(fn {_, data} -> data end)

    {:reply, {:ok, recent}, state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      enabled: state.enabled,
      api_configured: state.api_key != nil,
      last_sync: state.last_sync,
      stats: %{
        urls_tracked: :ets.info(:phishtank_urls, :size),
        targets: state.stats.targets
      }
    }
    {:reply, status, state}
  end

  @impl true
  def handle_cast(:sync_all, state) do
    Task.start(fn -> do_sync(state) end)
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:initial_sync, state) do
    Logger.info("[PhishTank] Starting initial sync...")
    Task.start(fn -> do_sync(state) end)
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:periodic_sync, state) do
    Logger.info("[PhishTank] Starting periodic sync...")
    Task.start(fn -> do_sync(state) end)
    schedule_sync(state.sync_interval)
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp do_sync(state) do
    Logger.info("[PhishTank] Downloading phishing database...")

    # Use JSON feed for richer data
    url = @feeds[:verified_json]

    # Add API key if available for higher rate limits
    url = if state.api_key do
      "#{url}?api_key=#{state.api_key}"
    else
      url
    end

    case Finch.build(:get, url, [{"Accept", "application/json"}]) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, entries} when is_list(entries) ->
            iocs = parse_json_feed(entries)
            Aggregator.ingest_batch("phishtank", iocs)
            Logger.info("[PhishTank] Imported #{length(iocs)} phishing URLs")

          {:error, _} ->
            # Fallback to CSV
            do_sync_csv(state)
        end

      {:ok, %Finch.Response{status: 509}} ->
        # Rate limited, try CSV
        Logger.warning("[PhishTank] Rate limited, trying CSV feed")
        do_sync_csv(state)

      {:ok, %Finch.Response{status: code}} ->
        Logger.warning("[PhishTank] HTTP #{code}, trying CSV feed")
        do_sync_csv(state)

      {:error, %Mint.TransportError{reason: reason}} ->
        Logger.error("[PhishTank] Error: #{inspect(reason)}")
    end
  end

  defp do_sync_csv(_state) do
    url = @feeds[:verified_online]

    case Finch.build(:get, url) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        iocs = parse_csv_feed(body)
        Aggregator.ingest_batch("phishtank", iocs)
        Logger.info("[PhishTank] Imported #{length(iocs)} phishing URLs from CSV")

      {:ok, %Finch.Response{status: code}} ->
        Logger.error("[PhishTank] CSV feed returned HTTP #{code}")

      {:error, %Mint.TransportError{reason: reason}} ->
        Logger.error("[PhishTank] CSV error: #{inspect(reason)}")
    end
  end

  defp parse_json_feed(entries) do
    entries
    |> Enum.map(fn entry ->
      url = entry["url"]
      target = entry["target"] || "unknown"
      submission_time = parse_datetime(entry["submission_time"])

      # Store in ETS for lookups
      phish_data = %{
        url: url,
        phish_id: entry["phish_id"],
        target: target,
        submission_time: submission_time,
        verified_time: parse_datetime(entry["verification_time"]),
        online: entry["online"] == "yes",
        details_url: entry["phish_detail_url"]
      }

      :ets.insert(:phishtank_urls, {normalize_url(url), phish_data})

      # Build IOC
      %{
        type: "url",
        value: url,
        source: "phishtank",
        severity: "high",
        confidence: 0.95,  # PhishTank uses community verification
        tags: ["phishing", "verified", target_to_tag(target)],
        metadata: %{
          "phish_id" => entry["phish_id"],
          "target" => target,
          "submission_time" => entry["submission_time"],
          "verification_time" => entry["verification_time"],
          "provider" => "phishtank"
        }
      }
    end)
  end

  defp parse_csv_feed(body) do
    body
    |> String.split("\n")
    |> Enum.drop(1)  # Skip header
    |> Enum.reject(&(&1 == ""))
    |> Enum.map(fn line ->
      # CSV format: phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
      case parse_csv_line(line) do
        {:ok, fields} ->
          url = Enum.at(fields, 1, "")
          target = Enum.at(fields, 7, "unknown")

          # Store in ETS
          phish_data = %{
            url: url,
            phish_id: Enum.at(fields, 0),
            target: target,
            submission_time: parse_datetime(Enum.at(fields, 3)),
            online: Enum.at(fields, 6) == "yes"
          }

          :ets.insert(:phishtank_urls, {normalize_url(url), phish_data})

          %{
            type: "url",
            value: url,
            source: "phishtank",
            severity: "high",
            confidence: 0.95,
            tags: ["phishing", "verified", target_to_tag(target)],
            metadata: %{
              "phish_id" => Enum.at(fields, 0),
              "target" => target,
              "provider" => "phishtank"
            }
          }

        :error ->
          nil
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp parse_csv_line(line) do
    # Handle CSV with quoted fields
    case Regex.scan(~r/(?:^|,)(?:"([^"]*(?:""[^"]*)*)"|([^,]*))/, line) do
      matches when length(matches) > 0 ->
        fields = Enum.map(matches, fn
          [_, quoted, ""] -> String.replace(quoted, ~s(""), ~s("))
          [_, "", unquoted] -> unquoted
          [_, quoted] -> quoted
          _ -> ""
        end)
        {:ok, fields}

      _ ->
        :error
    end
  end

  defp normalize_url(url) do
    url
    |> String.downcase()
    |> String.trim_trailing("/")
    |> String.replace(~r/^https?:\/\//, "")
  end

  defp target_to_tag(nil), do: "unknown_target"
  defp target_to_tag(target) do
    target
    |> String.downcase()
    |> String.replace(~r/[^a-z0-9]/, "_")
    |> String.slice(0, 30)
  end

  defp parse_datetime(nil), do: nil
  defp parse_datetime(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> dt
      _ ->
        case NaiveDateTime.from_iso8601(str) do
          {:ok, ndt} -> DateTime.from_naive!(ndt, "Etc/UTC")
          _ -> nil
        end
    end
  end
  defp parse_datetime(_), do: nil

  defp schedule_sync(interval) do
    Process.send_after(self(), :periodic_sync, interval)
  end
end
