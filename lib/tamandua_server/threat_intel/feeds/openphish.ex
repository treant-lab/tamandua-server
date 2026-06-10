defmodule TamanduaServer.ThreatIntel.Feeds.OpenPhish do
  @moduledoc """
  OpenPhish Feed Integration.

  OpenPhish provides AI-powered phishing detection:
  - Real-time phishing URL detection
  - Zero-day phishing site identification
  - Brand impersonation tracking
  - Fast update frequency

  The community feed is free, premium feed requires subscription.
  """

  use GenServer
  require Logger

  alias TamanduaServer.ThreatIntel.Aggregator

  @default_sync_interval :timer.hours(1)  # OpenPhish updates frequently
  @http_timeout 60_000

  # OpenPhish feeds
  @feeds %{
    community: "https://openphish.com/feed.txt",
    # Premium feeds require authentication
    premium_urls: "https://openphish.com/prvt-intell/",
    premium_domains: "https://openphish.com/prvt-intell/"
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
    :ets.new(:openphish_urls, [:named_table, :set, :public, read_concurrency: true])

    state = %{
      api_key: Keyword.get(opts, :api_key) || System.get_env("OPENPHISH_API_KEY"),
      enabled: Keyword.get(opts, :enabled, true),
      sync_interval: Keyword.get(opts, :sync_interval, @default_sync_interval),
      last_sync: nil,
      stats: %{
        urls_imported: 0
      }
    }

    if state.enabled do
      Process.send_after(self(), :initial_sync, :timer.seconds(25))
      schedule_sync(state.sync_interval)
      Logger.info("[OpenPhish] Initialized")
    end

    {:ok, state}
  end

  @impl true
  def handle_call({:check_url, url}, _from, state) do
    normalized = normalize_url(url)
    result = case :ets.lookup(:openphish_urls, normalized) do
      [{_, data}] -> {:ok, data}
      [] -> :not_found
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      enabled: state.enabled,
      premium_configured: state.api_key != nil,
      last_sync: state.last_sync,
      stats: %{
        urls_tracked: :ets.info(:openphish_urls, :size)
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
    Logger.info("[OpenPhish] Starting initial sync...")
    Task.start(fn -> do_sync(state) end)
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:periodic_sync, state) do
    Logger.info("[OpenPhish] Starting periodic sync...")
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
    # Sync community feed (always available)
    do_sync_community_feed()

    # Sync premium feed if configured
    if state.api_key do
      do_sync_premium_feed(state)
    end
  end

  defp do_sync_community_feed do
    Logger.info("[OpenPhish] Downloading community feed...")

    url = @feeds[:community]

    case Finch.build(:get, url) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        iocs = parse_text_feed(body)

        # Store in ETS
        Enum.each(iocs, fn ioc ->
          :ets.insert(:openphish_urls, {normalize_url(ioc.value), %{
            url: ioc.value,
            first_seen: DateTime.utc_now(),
            source: "openphish_community"
          }})
        end)

        Aggregator.ingest_batch("openphish", iocs)
        Logger.info("[OpenPhish] Imported #{length(iocs)} phishing URLs")

      {:ok, %Finch.Response{status: code}} ->
        Logger.warning("[OpenPhish] Community feed returned HTTP #{code}")

      {:error, %Mint.TransportError{reason: reason}} ->
        Logger.error("[OpenPhish] Community feed error: #{inspect(reason)}")
    end
  end

  defp do_sync_premium_feed(state) do
    Logger.info("[OpenPhish] Downloading premium feed...")

    headers = [
      {"Authorization", "Bearer #{state.api_key}"},
      {"Accept", "text/plain"}
    ]

    case Finch.build(:get, @feeds[:premium_urls], headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        iocs = parse_premium_feed(body)

        Enum.each(iocs, fn ioc ->
          :ets.insert(:openphish_urls, {normalize_url(ioc.value), %{
            url: ioc.value,
            brand: ioc.metadata["brand"],
            first_seen: DateTime.utc_now(),
            source: "openphish_premium"
          }})
        end)

        Aggregator.ingest_batch("openphish", iocs)
        Logger.info("[OpenPhish] Imported #{length(iocs)} premium phishing URLs")

      {:ok, %Finch.Response{status: code}} ->
        Logger.warning("[OpenPhish] Premium feed returned HTTP #{code}")

      {:error, %Mint.TransportError{reason: reason}} ->
        Logger.error("[OpenPhish] Premium feed error: #{inspect(reason)}")
    end
  end

  defp parse_text_feed(body) do
    body
    |> String.split("\n")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == "" or String.starts_with?(&1, "#")))
    |> Enum.map(fn url ->
      # Extract brand from URL if possible
      brand = extract_brand_from_url(url)

      %{
        type: "url",
        value: url,
        source: "openphish",
        severity: "high",
        confidence: 0.9,  # OpenPhish uses AI verification
        tags: ["phishing", "openphish"] ++ (if brand, do: [brand], else: []),
        metadata: %{
          "brand" => brand,
          "provider" => "openphish"
        }
      }
    end)
  end

  defp parse_premium_feed(body) do
    # Premium feed may include additional metadata
    body
    |> String.split("\n")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == "" or String.starts_with?(&1, "#")))
    |> Enum.map(fn line ->
      # Premium format might be: url,brand,timestamp
      case String.split(line, ",") do
        [url, brand | _] ->
          %{
            type: "url",
            value: String.trim(url),
            source: "openphish",
            severity: "critical",  # Premium verified
            confidence: 0.95,
            tags: ["phishing", "openphish", "premium", String.downcase(brand)],
            metadata: %{
              "brand" => String.trim(brand),
              "provider" => "openphish_premium"
            }
          }

        [url] ->
          brand = extract_brand_from_url(url)
          %{
            type: "url",
            value: url,
            source: "openphish",
            severity: "high",
            confidence: 0.9,
            tags: ["phishing", "openphish"] ++ (if brand, do: [brand], else: []),
            metadata: %{
              "brand" => brand,
              "provider" => "openphish"
            }
          }
      end
    end)
  end

  defp extract_brand_from_url(url) do
    url_lower = String.downcase(url)

    brands = [
      {"paypal", "paypal"},
      {"apple", "apple"},
      {"microsoft", "microsoft"},
      {"facebook", "facebook"},
      {"google", "google"},
      {"amazon", "amazon"},
      {"netflix", "netflix"},
      {"dropbox", "dropbox"},
      {"linkedin", "linkedin"},
      {"instagram", "instagram"},
      {"twitter", "twitter"},
      {"chase", "chase"},
      {"wellsfargo", "wellsfargo"},
      {"bankofamerica", "bankofamerica"},
      {"citibank", "citibank"},
      {"usps", "usps"},
      {"fedex", "fedex"},
      {"dhl", "dhl"},
      {"adobe", "adobe"},
      {"office365", "office365"},
      {"outlook", "microsoft"},
      {"icloud", "apple"}
    ]

    Enum.find_value(brands, nil, fn {pattern, brand} ->
      if String.contains?(url_lower, pattern), do: brand
    end)
  end

  defp normalize_url(url) do
    url
    |> String.downcase()
    |> String.trim_trailing("/")
    |> String.replace(~r/^https?:\/\//, "")
  end

  defp schedule_sync(interval) do
    Process.send_after(self(), :periodic_sync, interval)
  end
end
