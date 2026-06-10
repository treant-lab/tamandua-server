defmodule TamanduaServer.Integrations.Enrichment.HybridAnalysis do
  @moduledoc """
  Hybrid Analysis Integration for Malware Analysis

  Provides enrichment capabilities using Hybrid Analysis (Falcon Sandbox) API:
  - File submission for sandbox analysis
  - Hash lookup
  - URL analysis
  - Search for samples
  - MITRE ATT&CK mappings

  ## Configuration

      config :tamandua_server, TamanduaServer.Integrations.Enrichment.HybridAnalysis,
        api_key: "your-api-key",
        environment_id: 120,  # Windows 10 64-bit
        cache_ttl_seconds: 3600

  """

  use GenServer
  require Logger

  @base_url "https://www.hybrid-analysis.com/api/v2"
  @default_timeout_ms 30_000
  @default_cache_ttl 3600

  # Environment IDs
  @environments %{
    win7_32: 100,
    win7_64: 110,
    win10_64: 120,
    linux_64: 300,
    android: 200
  }

  defstruct [:config, :api_key, :cache, :stats]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Lookup a file hash.
  """
  @spec lookup_hash(String.t()) :: {:ok, map()} | {:error, term()}
  def lookup_hash(hash) do
    GenServer.call(__MODULE__, {:lookup_hash, hash}, 30_000)
  end

  @doc """
  Submit a file for analysis.
  """
  @spec submit_file(binary(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def submit_file(file_content, filename, opts \\ []) do
    GenServer.call(__MODULE__, {:submit_file, file_content, filename, opts}, 120_000)
  end

  @doc """
  Submit a URL for analysis.
  """
  @spec submit_url(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def submit_url(url, opts \\ []) do
    GenServer.call(__MODULE__, {:submit_url, url, opts}, 120_000)
  end

  @doc """
  Get analysis report by job ID.
  """
  @spec get_report(String.t()) :: {:ok, map()} | {:error, term()}
  def get_report(job_id) do
    GenServer.call(__MODULE__, {:get_report, job_id}, 30_000)
  end

  @doc """
  Get report summary by hash.
  """
  @spec get_summary(String.t()) :: {:ok, map()} | {:error, term()}
  def get_summary(hash) do
    GenServer.call(__MODULE__, {:get_summary, hash}, 30_000)
  end

  @doc """
  Search for samples.
  """
  @spec search(String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def search(query, opts \\ []) do
    GenServer.call(__MODULE__, {:search, query, opts}, 30_000)
  end

  @doc """
  Get MITRE ATT&CK mappings for a sample.
  """
  @spec get_mitre_attack(String.t()) :: {:ok, [map()]} | {:error, term()}
  def get_mitre_attack(hash) do
    GenServer.call(__MODULE__, {:get_mitre_attack, hash}, 30_000)
  end

  @doc """
  Get dropped files from analysis.
  """
  @spec get_dropped_files(String.t()) :: {:ok, [map()]} | {:error, term()}
  def get_dropped_files(job_id) do
    GenServer.call(__MODULE__, {:get_dropped_files, job_id}, 30_000)
  end

  @doc """
  Enrich multiple hashes.
  """
  @spec enrich_batch([String.t()]) :: {:ok, [map()]} | {:error, term()}
  def enrich_batch(hashes) do
    GenServer.call(__MODULE__, {:enrich_batch, hashes}, 120_000)
  end

  @doc """
  Get available analysis environments.
  """
  @spec environments() :: map()
  def environments, do: @environments

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
    Logger.info("Starting Hybrid Analysis Enrichment Integration")
    config = load_config(opts)

    state = %__MODULE__{
      config: config,
      api_key: config.api_key,
      cache: %{},
      stats: %{
        hash_lookups: 0,
        file_submissions: 0,
        url_submissions: 0,
        reports_fetched: 0,
        cache_hits: 0,
        errors: 0,
        last_activity: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:lookup_hash, hash}, _from, state) do
    normalized = String.downcase(hash)

    case check_cache(state, {:hash, normalized}) do
      {:hit, result} ->
        new_stats = update_stat(state.stats, :cache_hits)
        {:reply, {:ok, result}, %{state | stats: new_stats}}

      :miss ->
        case post_request(state, "/search/hash", %{hash: normalized}) do
          {:ok, response} when is_list(response) and length(response) > 0 ->
            result = format_hash_result(List.first(response))
            final_state = cache_result(state, {:hash, normalized}, result)
            new_stats = update_stat(final_state.stats, :hash_lookups)
            {:reply, {:ok, result}, %{final_state | stats: new_stats}}

          {:ok, []} ->
            {:reply, {:ok, %{found: false, hash: normalized}}, state}

          error ->
            {:reply, error, update_error_stat(state)}
        end
    end
  end

  @impl true
  def handle_call({:submit_file, file_content, filename, opts}, _from, state) do
    env_id = opts[:environment_id] || state.config.environment_id

    case upload_file(state, file_content, filename, env_id) do
      {:ok, response} ->
        result = %{
          job_id: response["job_id"],
          sha256: response["sha256"],
          environment_id: response["environment_id"],
          submission_type: response["submission_type"]
        }
        new_stats = update_stat(state.stats, :file_submissions)
        {:reply, {:ok, result}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:submit_url, url, opts}, _from, state) do
    env_id = opts[:environment_id] || state.config.environment_id

    body = %{
      url: url,
      environment_id: env_id,
      no_share_third_party: opts[:no_share] || false
    }

    case post_request(state, "/submit/url", body) do
      {:ok, response} ->
        result = %{
          job_id: response["job_id"],
          sha256: response["sha256"],
          environment_id: response["environment_id"]
        }
        new_stats = update_stat(state.stats, :url_submissions)
        {:reply, {:ok, result}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:get_report, job_id}, _from, state) do
    case check_cache(state, {:report, job_id}) do
      {:hit, result} ->
        new_stats = update_stat(state.stats, :cache_hits)
        {:reply, {:ok, result}, %{state | stats: new_stats}}

      :miss ->
        case get_request(state, "/report/#{job_id}/summary") do
          {:ok, response} ->
            result = format_report(response)
            final_state = cache_result(state, {:report, job_id}, result)
            new_stats = update_stat(final_state.stats, :reports_fetched)
            {:reply, {:ok, result}, %{final_state | stats: new_stats}}

          error ->
            {:reply, error, update_error_stat(state)}
        end
    end
  end

  @impl true
  def handle_call({:get_summary, hash}, _from, state) do
    case post_request(state, "/overview/#{hash}") do
      {:ok, response} ->
        result = format_summary(response)
        {:reply, {:ok, result}, state}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:search, query, opts}, _from, state) do
    params = %{
      query: query,
      minThreatScore: opts[:min_score] || 0,
      maxThreatScore: opts[:max_score] || 100
    }

    case post_request(state, "/search/terms", params) do
      {:ok, response} ->
        results = Enum.map(response["result"] || [], &format_search_result/1)
        {:reply, {:ok, results}, state}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:get_mitre_attack, hash}, _from, state) do
    case get_request(state, "/report/#{hash}/mitre-attack") do
      {:ok, response} ->
        techniques = Enum.map(response["mitre_attcks"] || [], fn t ->
          %{
            tactic: t["tactic"],
            technique: t["technique"],
            attck_id: t["attck_id"],
            malicious_identifiers: t["malicious_identifiers"] || []
          }
        end)
        {:reply, {:ok, techniques}, state}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:get_dropped_files, job_id}, _from, state) do
    case get_request(state, "/report/#{job_id}/dropped-files") do
      {:ok, response} ->
        files = Enum.map(response["dropped_files"] || [], fn f ->
          %{
            name: f["name"],
            path: f["filepath"],
            sha256: f["sha256"],
            md5: f["md5"],
            size: f["filesize"],
            type: f["type"]
          }
        end)
        {:reply, {:ok, files}, state}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:enrich_batch, hashes}, _from, state) do
    results = Enum.map(hashes, fn hash ->
      case post_request(state, "/search/hash", %{hash: String.downcase(hash)}) do
        {:ok, [result | _]} -> format_hash_result(result)
        _ -> %{found: false, hash: hash}
      end
    end)

    {:reply, {:ok, results}, state}
  end

  @impl true
  def handle_call(:test_connection, _from, state) do
    case get_request(state, "/system/queue-size") do
      {:ok, _} -> {:reply, {:ok, "Connected to Hybrid Analysis"}, state}
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
      api_key: opts[:api_key] || app_config[:api_key],
      environment_id: opts[:environment_id] || app_config[:environment_id] || @environments.win10_64,
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

  defp format_hash_result(result) do
    %{
      found: true,
      sha256: result["sha256"],
      sha1: result["sha1"],
      md5: result["md5"],
      threat_score: result["threat_score"],
      verdict: result["verdict"],
      threat_level: result["threat_level"],
      file_type: result["type"],
      size: result["size"],
      analysis_start_time: result["analysis_start_time"],
      environment: result["environment_description"],
      tags: result["tags"] || [],
      vx_family: result["vx_family"],
      classification_tags: result["classification_tags"] || [],
      mitre_attcks: result["mitre_attcks"] || []
    }
  end

  defp format_report(response) do
    %{
      job_id: response["job_id"],
      sha256: response["sha256"],
      sha1: response["sha1"],
      md5: response["md5"],
      state: response["state"],
      threat_score: response["threat_score"],
      verdict: response["verdict"],
      threat_level: response["threat_level"],
      file_type: response["type"],
      size: response["size"],
      environment: response["environment_description"],
      submit_name: response["submit_name"],
      analysis_start_time: response["analysis_start_time"],
      network_activity: %{
        domains: response["domains"] || [],
        hosts: response["hosts"] || [],
        http_requests: response["total_network_connections"] || 0
      },
      processes: response["processes"] || [],
      extracted_files: response["extracted_files"] || [],
      tags: response["tags"] || [],
      vx_family: response["vx_family"],
      classification_tags: response["classification_tags"] || [],
      mitre_attcks: Enum.map(response["mitre_attcks"] || [], fn t ->
        %{
          tactic: t["tactic"],
          technique: t["technique"],
          attck_id: t["attck_id"]
        }
      end)
    }
  end

  defp format_summary(response) do
    %{
      sha256: response["sha256"],
      md5: response["md5"],
      sha1: response["sha1"],
      size: response["size"],
      type: response["type"],
      type_short: response["type_short"],
      tags: response["tags"] || [],
      classification_tags: response["classification_tags"] || [],
      threat_score: response["threat_score"],
      threat_level: response["threat_level"],
      verdict: response["verdict"],
      vx_family: response["vx_family"],
      submissions: response["submissions"] || [],
      analysis_count: length(response["submissions"] || [])
    }
  end

  defp format_search_result(result) do
    %{
      sha256: result["sha256"],
      threat_score: result["threat_score"],
      verdict: result["verdict"],
      file_type: result["type"],
      size: result["size"],
      submit_name: result["submit_name"],
      analysis_start_time: result["analysis_start_time"]
    }
  end

  defp upload_file(state, file_content, filename, env_id) do
    boundary = "----HABoundary#{:crypto.strong_rand_bytes(8) |> Base.encode16()}"

    body = """
    --#{boundary}\r
    Content-Disposition: form-data; name="file"; filename="#{filename}"\r
    Content-Type: application/octet-stream\r
    \r
    #{file_content}\r
    --#{boundary}\r
    Content-Disposition: form-data; name="environment_id"\r
    \r
    #{env_id}\r
    --#{boundary}--\r
    """

    headers = [
      {"api-key", state.api_key},
      {"Content-Type", "multipart/form-data; boundary=#{boundary}"},
      {"User-Agent", "Tamandua-EDR/1.0"}
    ]

    options = [timeout: 120_000, recv_timeout: 120_000]

    case Finch.build(:post, "#{@base_url}/submit/file", headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 120_000)) do
      {:ok, %{status_code: 201, body: resp_body}} ->
        {:ok, Jason.decode!(resp_body)}

      {:ok, %{status_code: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %{reason: reason}} ->
        {:error, reason}
    end
  end

  defp get_request(state, endpoint) do
    url = "#{@base_url}#{endpoint}"

    headers = [
      {"api-key", state.api_key},
      {"Accept", "application/json"},
      {"User-Agent", "Tamandua-EDR/1.0"}
    ]

    options = [timeout: state.config.timeout_ms, recv_timeout: state.config.timeout_ms]

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %{status_code: 200, body: body}} -> {:ok, Jason.decode!(body)}
      {:ok, %{status_code: 404}} -> {:error, :not_found}
      {:ok, %{status_code: code, body: body}} ->
        Logger.error("Hybrid Analysis API error: HTTP #{code} - #{body}")
        {:error, "HTTP #{code}: #{body}"}
      {:error, %{reason: reason}} ->
        Logger.error("Hybrid Analysis connection error: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("Hybrid Analysis exception: #{inspect(e)}")
      {:error, Exception.message(e)}
  end

  defp post_request(state, endpoint, body \\ %{}) do
    url = "#{@base_url}#{endpoint}"

    headers = [
      {"api-key", state.api_key},
      {"Content-Type", "application/x-www-form-urlencoded"},
      {"Accept", "application/json"},
      {"User-Agent", "Tamandua-EDR/1.0"}
    ]

    options = [timeout: state.config.timeout_ms, recv_timeout: state.config.timeout_ms]
    encoded_body = URI.encode_query(body)

    case Finch.build(:post, url, headers, encoded_body) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %{status_code: code, body: resp_body}} when code in [200, 201] ->
        {:ok, Jason.decode!(resp_body)}

      {:ok, %{status_code: 404}} ->
        {:ok, []}

      {:ok, %{status_code: code, body: resp_body}} ->
        Logger.error("Hybrid Analysis API error: HTTP #{code} - #{resp_body}")
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %{reason: reason}} ->
        Logger.error("Hybrid Analysis connection error: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("Hybrid Analysis exception: #{inspect(e)}")
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
