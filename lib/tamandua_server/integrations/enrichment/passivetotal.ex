defmodule TamanduaServer.Integrations.Enrichment.PassiveTotal do
  @moduledoc """
  PassiveTotal (RiskIQ) Integration for Threat Intelligence Enrichment

  Provides enrichment capabilities using PassiveTotal API:
  - Passive DNS history
  - WHOIS information
  - SSL certificate data
  - Host attributes
  - OSINT enrichment

  ## Configuration

      config :tamandua_server, TamanduaServer.Integrations.Enrichment.PassiveTotal,
        username: "your-email",
        api_key: "your-api-key",
        cache_ttl_seconds: 3600

  """

  use GenServer
  require Logger

  @base_url "https://api.passivetotal.org/v2"
  @default_timeout_ms 30_000
  @default_cache_ttl 3600

  defstruct [:config, :auth, :cache, :stats]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get passive DNS records for a domain or IP.
  """
  @spec passive_dns(String.t()) :: {:ok, map()} | {:error, term()}
  def passive_dns(query) do
    GenServer.call(__MODULE__, {:passive_dns, query}, 30_000)
  end

  @doc """
  Get WHOIS information.
  """
  @spec whois(String.t()) :: {:ok, map()} | {:error, term()}
  def whois(query) do
    GenServer.call(__MODULE__, {:whois, query}, 30_000)
  end

  @doc """
  Get SSL certificates for a domain.
  """
  @spec ssl_certificates(String.t()) :: {:ok, [map()]} | {:error, term()}
  def ssl_certificates(query) do
    GenServer.call(__MODULE__, {:ssl_certificates, query}, 30_000)
  end

  @doc """
  Get host attributes.
  """
  @spec host_attributes(String.t()) :: {:ok, map()} | {:error, term()}
  def host_attributes(query) do
    GenServer.call(__MODULE__, {:host_attributes, query}, 30_000)
  end

  @doc """
  Get OSINT enrichment.
  """
  @spec osint(String.t()) :: {:ok, map()} | {:error, term()}
  def osint(query) do
    GenServer.call(__MODULE__, {:osint, query}, 30_000)
  end

  @doc """
  Get reputation score.
  """
  @spec reputation(String.t()) :: {:ok, map()} | {:error, term()}
  def reputation(query) do
    GenServer.call(__MODULE__, {:reputation, query}, 30_000)
  end

  @doc """
  Enrich multiple IOCs in batch.
  """
  @spec enrich_batch([map()]) :: {:ok, [map()]} | {:error, term()}
  def enrich_batch(iocs) do
    GenServer.call(__MODULE__, {:enrich_batch, iocs}, 120_000)
  end

  @spec test_connection() :: {:ok, String.t()} | {:error, term()}
  def test_connection do
    GenServer.call(__MODULE__, :test_connection, 30_000)
  end

  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    Logger.info("Starting PassiveTotal Enrichment Integration")
    config = load_config(opts)

    state = %__MODULE__{
      config: config,
      auth: Base.encode64("#{config.username}:#{config.api_key}"),
      cache: %{},
      stats: %{
        pdns_lookups: 0,
        whois_lookups: 0,
        ssl_lookups: 0,
        cache_hits: 0,
        errors: 0,
        last_activity: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:passive_dns, query}, _from, state) do
    case check_cache(state, {:pdns, query}) do
      {:hit, result} ->
        new_stats = update_stat(state.stats, :cache_hits)
        {:reply, {:ok, result}, %{state | stats: new_stats}}

      :miss ->
        case get_request(state, "/dns/passive", %{query: query}) do
          {:ok, response} ->
            result = format_pdns_result(response)
            final_state = cache_result(state, {:pdns, query}, result)
            new_stats = update_stat(final_state.stats, :pdns_lookups)
            {:reply, {:ok, result}, %{final_state | stats: new_stats}}

          error ->
            {:reply, error, update_error_stat(state)}
        end
    end
  end

  @impl true
  def handle_call({:whois, query}, _from, state) do
    case check_cache(state, {:whois, query}) do
      {:hit, result} ->
        new_stats = update_stat(state.stats, :cache_hits)
        {:reply, {:ok, result}, %{state | stats: new_stats}}

      :miss ->
        case get_request(state, "/whois", %{query: query}) do
          {:ok, response} ->
            result = format_whois_result(response)
            final_state = cache_result(state, {:whois, query}, result)
            new_stats = update_stat(final_state.stats, :whois_lookups)
            {:reply, {:ok, result}, %{final_state | stats: new_stats}}

          error ->
            {:reply, error, update_error_stat(state)}
        end
    end
  end

  @impl true
  def handle_call({:ssl_certificates, query}, _from, state) do
    case check_cache(state, {:ssl, query}) do
      {:hit, result} ->
        new_stats = update_stat(state.stats, :cache_hits)
        {:reply, {:ok, result}, %{state | stats: new_stats}}

      :miss ->
        case get_request(state, "/ssl-certificate/history", %{query: query}) do
          {:ok, response} ->
            result = format_ssl_result(response)
            final_state = cache_result(state, {:ssl, query}, result)
            new_stats = update_stat(final_state.stats, :ssl_lookups)
            {:reply, {:ok, result}, %{final_state | stats: new_stats}}

          error ->
            {:reply, error, update_error_stat(state)}
        end
    end
  end

  @impl true
  def handle_call({:host_attributes, query}, _from, state) do
    case get_request(state, "/host-attributes/components", %{query: query}) do
      {:ok, response} ->
        result = format_host_attributes(response)
        {:reply, {:ok, result}, state}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:osint, query}, _from, state) do
    case get_request(state, "/enrichment/osint", %{query: query}) do
      {:ok, response} ->
        result = format_osint_result(response)
        {:reply, {:ok, result}, state}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:reputation, query}, _from, state) do
    case get_request(state, "/reputation", %{query: query}) do
      {:ok, response} ->
        result = %{
          query: query,
          score: response["score"],
          classification: response["classification"],
          rules: response["rules"] || []
        }
        {:reply, {:ok, result}, state}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:enrich_batch, iocs}, _from, state) do
    results = Enum.map(iocs, fn ioc ->
      value = ioc[:value] || ioc["value"]
      type = ioc[:type] || ioc["type"]

      enrichment = %{ioc: ioc}

      # Get PDNS
      enrichment = case get_request(state, "/dns/passive", %{query: value}) do
        {:ok, pdns} -> Map.put(enrichment, :passive_dns, format_pdns_result(pdns))
        _ -> enrichment
      end

      # Get WHOIS for domains
      enrichment = if type in ["domain", :domain] do
        case get_request(state, "/whois", %{query: value}) do
          {:ok, whois} -> Map.put(enrichment, :whois, format_whois_result(whois))
          _ -> enrichment
        end
      else
        enrichment
      end

      Process.sleep(200)  # Rate limiting
      enrichment
    end)

    {:reply, {:ok, results}, state}
  end

  @impl true
  def handle_call(:test_connection, _from, state) do
    case get_request(state, "/account/quota") do
      {:ok, _} -> {:reply, {:ok, "Connected to PassiveTotal"}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp load_config(opts) do
    app_config = Application.get_env(:tamandua_server, __MODULE__, [])

    %{
      username: opts[:username] || app_config[:username],
      api_key: opts[:api_key] || app_config[:api_key],
      cache_ttl: opts[:cache_ttl_seconds] || app_config[:cache_ttl_seconds] || @default_cache_ttl,
      timeout_ms: opts[:timeout_ms] || app_config[:timeout_ms] || @default_timeout_ms
    }
  end

  defp check_cache(state, key) do
    case Map.get(state.cache, key) do
      nil -> :miss
      {result, timestamp} ->
        age = DateTime.diff(DateTime.utc_now(), timestamp, :second)
        if age < state.config.cache_ttl, do: {:hit, result}, else: :miss
    end
  end

  defp cache_result(state, key, result) do
    new_cache = Map.put(state.cache, key, {result, DateTime.utc_now()})
    %{state | cache: new_cache}
  end

  defp format_pdns_result(response) do
    %{
      query: response["queryValue"],
      total_records: response["totalRecords"],
      first_seen: response["firstSeen"],
      last_seen: response["lastSeen"],
      records: Enum.map(response["results"] || [], fn r ->
        %{
          resolve: r["resolve"],
          resolve_type: r["resolveType"],
          record_type: r["recordType"],
          first_seen: r["firstSeen"],
          last_seen: r["lastSeen"],
          source: r["source"] || []
        }
      end)
    }
  end

  defp format_whois_result(response) do
    %{
      domain: response["domain"],
      registrar: response["registrar"],
      registered: response["registered"],
      expires: response["expiresAt"],
      registrant: response["registrant"],
      admin: response["admin"],
      tech: response["tech"],
      name_servers: response["nameServers"] || [],
      status: response["status"] || []
    }
  end

  defp format_ssl_result(response) do
    %{
      query: response["queryValue"],
      certificates: Enum.map(response["results"] || [], fn cert ->
        %{
          sha1: cert["sha1"],
          issuer: cert["issuerCommonName"],
          subject: cert["subjectCommonName"],
          not_before: cert["notBefore"],
          not_after: cert["notAfter"],
          san: cert["subjectAlternativeNames"] || []
        }
      end)
    }
  end

  defp format_host_attributes(response) do
    %{
      query: response["queryValue"],
      components: Enum.map(response["results"] || [], fn comp ->
        %{
          label: comp["label"],
          category: comp["category"],
          first_seen: comp["firstSeen"],
          last_seen: comp["lastSeen"]
        }
      end)
    }
  end

  defp format_osint_result(response) do
    %{
      query: response["queryValue"],
      sources: Enum.map(response["results"] || [], fn src ->
        %{
          source: src["source"],
          source_url: src["sourceUrl"],
          tags: src["tags"] || []
        }
      end)
    }
  end

  defp get_request(state, endpoint, params \\ %{}) do
    url = "#{@base_url}#{endpoint}"

    headers = [
      {"Authorization", "Basic #{state.auth}"},
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]

    options = [
      timeout: state.config.timeout_ms,
      recv_timeout: state.config.timeout_ms,
      params: params
    ]

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %{status_code: 200, body: body}} -> {:ok, Jason.decode!(body)}
      {:ok, %{status_code: 404}} -> {:error, :not_found}
      {:ok, %{status_code: code, body: body}} ->
        Logger.error("PassiveTotal API error: HTTP #{code} - #{body}")
        {:error, "HTTP #{code}: #{body}"}
      {:error, %{reason: reason}} ->
        Logger.error("PassiveTotal connection error: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("PassiveTotal exception: #{inspect(e)}")
      {:error, Exception.message(e)}
  end

  defp update_stat(stats, key) do
    stats |> Map.update(key, 1, &(&1 + 1)) |> Map.put(:last_activity, DateTime.utc_now())
  end

  defp update_error_stat(state) do
    new_stats = Map.update(state.stats, :errors, 1, &(&1 + 1))
    %{state | stats: new_stats}
  end
end
