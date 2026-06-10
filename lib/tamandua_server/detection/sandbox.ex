defmodule TamanduaServer.Detection.Sandbox do
  @moduledoc """
  Sandbox Detonation and Dynamic Analysis Engine.

  Manages file detonation workflows across multiple sandbox providers:
  - VirusTotal (v3 API)
  - Any.run
  - Hybrid Analysis
  - Cuckoo Sandbox
  - Joe Sandbox

  ## Features

  - Multi-sandbox submission with parallel or fallback chain execution
  - Deduplication via ETS (skip re-submission of known hashes within TTL)
  - Exponential backoff polling for completion
  - Normalized behavioral report schema across all providers
  - Auto-detonation rules (ML score threshold, suspicious YARA, quarantine)
  - Weighted verdict aggregation from multiple sandboxes
  - IOC extraction fed back to ThreatIntel module
  - PubSub broadcast for real-time dashboard updates

  ## Usage

      # Submit a file for analysis
      Sandbox.submit(file_bytes, %{sha256: hash, source: "quarantine", alert_id: id})

      # Get report by hash
      Sandbox.get_report(sha256)

      # Check submission status
      Sandbox.get_submission_status(submission_id)

      # Get usage statistics
      Sandbox.get_stats()
  """

  use GenServer
  require Logger

  @ets_submissions :sandbox_submissions
  @ets_reports :sandbox_reports
  @ets_stats :sandbox_stats

  # Default dedup TTL: 24 hours
  @default_dedup_ttl_seconds 86_400

  # Poll intervals (exponential backoff)
  @initial_poll_interval_ms 15_000
  @max_poll_interval_ms 300_000
  @max_poll_attempts 40

  # Default sandbox weights for verdict aggregation
  @default_weights %{
    virustotal: 1.0,
    anyrun: 0.9,
    hybrid: 0.85,
    cuckoo: 0.8,
    joe: 0.9
  }

  # Default auto-detonation ML score threshold
  @default_ml_threshold 0.6

  # ============================================================================
  # Structs
  # ============================================================================

  defmodule SandboxReport do
    @moduledoc "Normalized behavioral report from a sandbox detonation."
    defstruct [
      :file_hash,
      :sandbox,
      :verdict,
      :score,
      :behaviors,
      :network_iocs,
      :file_iocs,
      :registry_iocs,
      :signatures,
      :ttps,
      :submitted_at,
      :completed_at,
      :raw_report
    ]
  end

  defmodule Submission do
    @moduledoc "Tracks a single file submission to sandboxes."
    defstruct [
      :id,
      :file_hash,
      :file_name,
      :file_size,
      :source,
      :alert_id,
      :sandboxes,
      :status,
      :submitted_at,
      :completed_at,
      :sandbox_ids,
      :reports,
      :aggregated_verdict,
      :aggregated_score,
      :poll_count,
      :poll_interval_ms,
      :error
    ]
  end

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Submit a file for sandbox detonation.

  ## Parameters
  - `file_bytes` - The raw file content (binary)
  - `metadata` - Map with keys: `:sha256`, `:file_name`, `:source`, `:alert_id`

  ## Returns
  - `{:ok, submission_id}` on successful submission
  - `{:ok, :cached, existing_report}` if a recent report exists (dedup)
  - `{:error, reason}` on failure
  """
  @spec submit(binary(), map()) :: {:ok, String.t()} | {:ok, :cached, map()} | {:error, term()}
  def submit(file_bytes, metadata) do
    GenServer.call(__MODULE__, {:submit, file_bytes, metadata}, 30_000)
  end

  @doc """
  Force re-submission of a file by hash, bypassing dedup TTL.
  """
  @spec resubmit(String.t()) :: {:ok, String.t()} | {:error, term()}
  def resubmit(file_hash) do
    GenServer.call(__MODULE__, {:resubmit, file_hash}, 30_000)
  end

  @doc """
  Get the normalized sandbox report for a file hash.
  Returns the aggregated report if analyses from multiple sandboxes exist.
  """
  @spec get_report(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_report(file_hash) do
    case :ets.lookup(@ets_reports, file_hash) do
      [{^file_hash, report}] -> {:ok, report}
      [] -> {:error, :not_found}
    end
  rescue
    ArgumentError -> {:error, :not_found}
  end

  @doc """
  Get the status of a submission by ID.
  """
  @spec get_submission_status(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_submission_status(submission_id) do
    case :ets.lookup(@ets_submissions, submission_id) do
      [{^submission_id, submission}] -> {:ok, serialize_submission(submission)}
      [] -> {:error, :not_found}
    end
  rescue
    ArgumentError -> {:error, :not_found}
  end

  @doc """
  Get sandbox usage statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Check if a file should be auto-submitted based on analysis results.
  Called by the Detection Engine after ML / YARA analysis.
  """
  @spec maybe_auto_submit(map()) :: :ok | {:submitted, String.t()}
  def maybe_auto_submit(analysis_result) do
    GenServer.cast(__MODULE__, {:maybe_auto_submit, analysis_result})
  end

  @doc """
  Get configuration including enabled sandboxes, thresholds, weights.
  """
  @spec get_config() :: map()
  def get_config do
    GenServer.call(__MODULE__, :get_config)
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(_opts) do
    # Create ETS tables
    create_ets_tables()

    config = load_config()

    state = %{
      config: config,
      active_polls: %{},
      stats: %{
        total_submissions: 0,
        completed: 0,
        failed: 0,
        deduped: 0,
        by_sandbox: %{},
        by_verdict: %{clean: 0, suspicious: 0, malicious: 0},
        iocs_extracted: 0,
        last_submission_at: nil
      }
    }

    Logger.info("[Sandbox] Detonation engine started with sandboxes: #{inspect(Map.keys(config.sandboxes))}")

    {:ok, state}
  end

  @impl true
  def handle_call({:submit, file_bytes, metadata}, _from, state) do
    sha256 = metadata[:sha256] || metadata["sha256"] || compute_sha256(file_bytes)
    dedup_ttl = state.config[:dedup_ttl_seconds] || @default_dedup_ttl_seconds

    # Check dedup
    case check_dedup(sha256, dedup_ttl) do
      {:cached, report} ->
        state = update_stats(state, :deduped)
        {:reply, {:ok, :cached, report}, state}

      :not_found ->
        case do_submit(file_bytes, sha256, metadata, state) do
          {:ok, submission_id, new_state} ->
            {:reply, {:ok, submission_id}, new_state}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end
    end
  end

  @impl true
  def handle_call({:resubmit, file_hash}, _from, state) do
    # Clear any cached report so we force fresh analysis
    :ets.delete(@ets_reports, file_hash)

    # We don't have file_bytes for resubmit, so we check if any sandbox
    # supports hash-based re-analysis
    case resubmit_by_hash(file_hash, state) do
      {:ok, submission_id, new_state} ->
        {:reply, {:ok, submission_id}, new_state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = state.stats
    |> Map.put(:active_polls, map_size(state.active_polls))
    |> Map.put(:cached_reports, ets_size(@ets_reports))
    |> Map.put(:tracked_submissions, ets_size(@ets_submissions))
    |> Map.put(:enabled_sandboxes, enabled_sandbox_names(state.config))

    {:reply, stats, state}
  end

  @impl true
  def handle_call(:get_config, _from, state) do
    config_summary = %{
      sandboxes: Enum.map(state.config.sandboxes, fn {name, cfg} ->
        %{name: name, enabled: cfg[:enabled] || false, weight: cfg[:weight] || @default_weights[name] || 0.5}
      end),
      dedup_ttl_seconds: state.config[:dedup_ttl_seconds] || @default_dedup_ttl_seconds,
      ml_threshold: state.config[:ml_threshold] || @default_ml_threshold,
      mode: state.config[:mode] || :parallel
    }

    {:reply, config_summary, state}
  end

  @impl true
  def handle_cast({:maybe_auto_submit, analysis_result}, state) do
    ml_threshold = state.config[:ml_threshold] || @default_ml_threshold

    should_submit = cond do
      # ML score above threshold
      is_number(analysis_result[:ml_score]) and analysis_result[:ml_score] > ml_threshold ->
        true

      # From quarantine needing classification
      analysis_result[:source] == "quarantine" ->
        true

      # Suspicious YARA match but no definitive verdict
      length(analysis_result[:yara_matches] || []) > 0 and
        analysis_result[:verdict] in [nil, "unknown", "suspicious"] ->
        true

      true ->
        false
    end

    new_state = if should_submit and is_binary(analysis_result[:file_bytes]) do
      sha256 = analysis_result[:sha256] || compute_sha256(analysis_result[:file_bytes])
      dedup_ttl = state.config[:dedup_ttl_seconds] || @default_dedup_ttl_seconds

      case check_dedup(sha256, dedup_ttl) do
        {:cached, _report} ->
          update_stats(state, :deduped)

        :not_found ->
          metadata = %{
            sha256: sha256,
            source: "auto_detonation",
            alert_id: analysis_result[:alert_id],
            file_name: analysis_result[:file_name],
            ml_score: analysis_result[:ml_score]
          }

          case do_submit(analysis_result[:file_bytes], sha256, metadata, state) do
            {:ok, submission_id, updated_state} ->
              Logger.info("[Sandbox] Auto-submitted #{sha256} (ML score: #{analysis_result[:ml_score]}) -> #{submission_id}")
              updated_state

            {:error, reason} ->
              Logger.warning("[Sandbox] Auto-submit failed for #{sha256}: #{inspect(reason)}")
              state
          end
      end
    else
      state
    end

    {:noreply, new_state}
  end

  @impl true
  def handle_info({:poll_sandbox, submission_id, sandbox_name, sandbox_analysis_id}, state) do
    case :ets.lookup(@ets_submissions, submission_id) do
      [{^submission_id, submission}] ->
        new_state = poll_sandbox_result(submission, sandbox_name, sandbox_analysis_id, state)
        {:noreply, new_state}

      [] ->
        Logger.warning("[Sandbox] Poll for unknown submission #{submission_id}, ignoring")
        {:noreply, state}
    end
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ============================================================================
  # Submission Logic
  # ============================================================================

  defp do_submit(file_bytes, sha256, metadata, state) do
    submission_id = generate_submission_id()
    now = DateTime.utc_now()

    enabled_sandboxes = enabled_sandbox_configs(state.config)

    if Enum.empty?(enabled_sandboxes) do
      {:error, :no_sandboxes_enabled}
    else
      submission = %Submission{
        id: submission_id,
        file_hash: sha256,
        file_name: metadata[:file_name] || metadata["file_name"] || "unknown",
        file_size: byte_size(file_bytes),
        source: metadata[:source] || metadata["source"] || "manual",
        alert_id: metadata[:alert_id] || metadata["alert_id"],
        sandboxes: Enum.map(enabled_sandboxes, fn {name, _} -> name end),
        status: :submitting,
        submitted_at: now,
        completed_at: nil,
        sandbox_ids: %{},
        reports: %{},
        aggregated_verdict: nil,
        aggregated_score: nil,
        poll_count: 0,
        poll_interval_ms: @initial_poll_interval_ms,
        error: nil
      }

      :ets.insert(@ets_submissions, {submission_id, submission})

      # Submit to sandboxes based on mode
      mode = state.config[:mode] || :parallel

      {sandbox_ids, errors} = case mode do
        :parallel ->
          submit_parallel(file_bytes, sha256, metadata, enabled_sandboxes, state.config)

        :fallback ->
          submit_fallback(file_bytes, sha256, metadata, enabled_sandboxes, state.config)

        _ ->
          submit_parallel(file_bytes, sha256, metadata, enabled_sandboxes, state.config)
      end

      if map_size(sandbox_ids) == 0 do
        submission = %{submission | status: :failed, error: "All sandbox submissions failed: #{inspect(errors)}"}
        :ets.insert(@ets_submissions, {submission_id, submission})
        _new_state = update_stats(state, :failed)
        {:error, :all_submissions_failed}
      else
        submission = %{submission |
          status: :analyzing,
          sandbox_ids: sandbox_ids
        }
        :ets.insert(@ets_submissions, {submission_id, submission})

        # Schedule polling for each successful submission
        Enum.each(sandbox_ids, fn {sandbox_name, analysis_id} ->
          schedule_poll(submission_id, sandbox_name, analysis_id, @initial_poll_interval_ms)
        end)

        new_state = state
        |> update_stats(:submitted)
        |> put_in([:stats, :last_submission_at], now)

        # Broadcast submission event
        Phoenix.PubSub.broadcast(
          TamanduaServer.PubSub,
          "sandbox:submissions",
          {:sandbox_submitted, %{
            submission_id: submission_id,
            file_hash: sha256,
            sandboxes: Map.keys(sandbox_ids),
            source: submission.source
          }}
        )

        {:ok, submission_id, new_state}
      end
    end
  end

  defp resubmit_by_hash(file_hash, state) do
    submission_id = generate_submission_id()
    now = DateTime.utc_now()

    enabled_sandboxes = enabled_sandbox_configs(state.config)

    if Enum.empty?(enabled_sandboxes) do
      {:error, :no_sandboxes_enabled}
    else
      # For hash-based resubmit, we only use sandboxes that support it
      # (VirusTotal can look up by hash, others may need the file)
      {sandbox_ids, _errors} = submit_hash_based(file_hash, enabled_sandboxes, state.config)

      if map_size(sandbox_ids) == 0 do
        {:error, :no_sandbox_supports_hash_resubmit}
      else
        submission = %Submission{
          id: submission_id,
          file_hash: file_hash,
          file_name: "resubmit",
          file_size: 0,
          source: "resubmit",
          alert_id: nil,
          sandboxes: Map.keys(sandbox_ids),
          status: :analyzing,
          submitted_at: now,
          completed_at: nil,
          sandbox_ids: sandbox_ids,
          reports: %{},
          aggregated_verdict: nil,
          aggregated_score: nil,
          poll_count: 0,
          poll_interval_ms: @initial_poll_interval_ms,
          error: nil
        }

        :ets.insert(@ets_submissions, {submission_id, submission})

        Enum.each(sandbox_ids, fn {sandbox_name, analysis_id} ->
          schedule_poll(submission_id, sandbox_name, analysis_id, @initial_poll_interval_ms)
        end)

        new_state = update_stats(state, :submitted)
        {:ok, submission_id, new_state}
      end
    end
  end

  # ============================================================================
  # Sandbox Adapter Dispatching
  # ============================================================================

  defp submit_parallel(file_bytes, sha256, metadata, sandboxes, config) do
    results = Task.Supervisor.async_stream_nolink(
      TamanduaServer.TaskSupervisor,
      sandboxes,
      fn {name, cfg} ->
        {name, submit_to_sandbox(name, file_bytes, sha256, metadata, cfg, config)}
      end,
      timeout: 30_000,
      max_concurrency: length(sandboxes)
    )
    |> Enum.reduce({%{}, []}, fn
      {:ok, {name, {:ok, analysis_id}}}, {ids, errs} ->
        {Map.put(ids, name, analysis_id), errs}

      {:ok, {name, {:error, reason}}}, {ids, errs} ->
        Logger.warning("[Sandbox] Submission to #{name} failed: #{inspect(reason)}")
        {ids, [{name, reason} | errs]}

      {:exit, reason}, {ids, errs} ->
        Logger.warning("[Sandbox] Submission task crashed: #{inspect(reason)}")
        {ids, [{:unknown, reason} | errs]}
    end)

    results
  end

  defp submit_fallback(file_bytes, sha256, metadata, sandboxes, config) do
    Enum.reduce_while(sandboxes, {%{}, []}, fn {name, cfg}, {ids, errs} ->
      case submit_to_sandbox(name, file_bytes, sha256, metadata, cfg, config) do
        {:ok, analysis_id} ->
          {:halt, {Map.put(ids, name, analysis_id), errs}}

        {:error, reason} ->
          Logger.warning("[Sandbox] Fallback: #{name} failed (#{inspect(reason)}), trying next")
          {:cont, {ids, [{name, reason} | errs]}}
      end
    end)
  end

  defp submit_hash_based(file_hash, sandboxes, config) do
    Enum.reduce(sandboxes, {%{}, []}, fn {name, cfg}, {ids, errs} ->
      case request_report_by_hash(name, file_hash, cfg, config) do
        {:ok, analysis_id} ->
          {Map.put(ids, name, analysis_id), errs}

        {:error, reason} ->
          {ids, [{name, reason} | errs]}
      end
    end)
  end

  # ============================================================================
  # Individual Sandbox Adapters
  # ============================================================================

  defp submit_to_sandbox(:virustotal, file_bytes, _sha256, _metadata, cfg, _config) do
    api_key = cfg[:api_key] || System.get_env("VIRUSTOTAL_API_KEY")
    unless api_key, do: throw({:error, :no_api_key})

    url = "https://www.virustotal.com/api/v3/files"

    # Build multipart body
    boundary = "----TamanduaSandbox#{:erlang.unique_integer([:positive])}"
    body = build_multipart(boundary, "file", "sample.bin", file_bytes)

    headers = [
      {"x-apikey", api_key},
      {"content-type", "multipart/form-data; boundary=#{boundary}"}
    ]

    case do_http_request(:post, url, headers, body) do
      {:ok, %{status: status, body: resp_body}} when status in [200, 201] ->
        case Jason.decode(resp_body) do
          {:ok, %{"data" => %{"id" => analysis_id}}} ->
            {:ok, analysis_id}

          {:ok, other} ->
            {:error, {:unexpected_response, other}}

          {:error, _} ->
            {:error, :invalid_json}
        end

      {:ok, %{status: 429}} ->
        {:error, :rate_limited}

      {:ok, %{status: status, body: resp_body}} ->
        {:error, {:http_error, status, resp_body}}

      {:error, reason} ->
        {:error, {:request_failed, reason}}
    end
  catch
    {:error, reason} -> {:error, reason}
  end

  defp submit_to_sandbox(:anyrun, file_bytes, _sha256, metadata, cfg, _config) do
    api_key = cfg[:api_key] || System.get_env("ANYRUN_API_KEY")
    unless api_key, do: throw({:error, :no_api_key})

    url = "https://api.any.run/v1/analysis"

    boundary = "----TamanduaSandbox#{:erlang.unique_integer([:positive])}"
    file_name = metadata[:file_name] || "sample.bin"
    body = build_multipart(boundary, "file", file_name, file_bytes)

    headers = [
      {"authorization", "API-Key #{api_key}"},
      {"content-type", "multipart/form-data; boundary=#{boundary}"}
    ]

    case do_http_request(:post, url, headers, body) do
      {:ok, %{status: status, body: resp_body}} when status in [200, 201] ->
        case Jason.decode(resp_body) do
          {:ok, %{"data" => %{"taskid" => task_id}}} -> {:ok, task_id}
          {:ok, %{"taskid" => task_id}} -> {:ok, task_id}
          {:ok, other} -> {:error, {:unexpected_response, other}}
          {:error, _} -> {:error, :invalid_json}
        end

      {:ok, %{status: status, body: resp_body}} ->
        {:error, {:http_error, status, resp_body}}

      {:error, reason} ->
        {:error, {:request_failed, reason}}
    end
  catch
    {:error, reason} -> {:error, reason}
  end

  defp submit_to_sandbox(:hybrid, file_bytes, _sha256, metadata, cfg, _config) do
    api_key = cfg[:api_key] || System.get_env("HYBRID_ANALYSIS_API_KEY")
    unless api_key, do: throw({:error, :no_api_key})

    url = "https://www.hybrid-analysis.com/api/v2/submit/file"

    boundary = "----TamanduaSandbox#{:erlang.unique_integer([:positive])}"
    file_name = metadata[:file_name] || "sample.bin"

    # Hybrid Analysis requires environment_id
    env_id = cfg[:environment_id] || "160"
    body = build_multipart_with_fields(boundary, "file", file_name, file_bytes, %{"environment_id" => env_id})

    headers = [
      {"api-key", api_key},
      {"content-type", "multipart/form-data; boundary=#{boundary}"},
      {"user-agent", "Tamandua-EDR/1.0"}
    ]

    case do_http_request(:post, url, headers, body) do
      {:ok, %{status: status, body: resp_body}} when status in [200, 201] ->
        case Jason.decode(resp_body) do
          {:ok, %{"job_id" => job_id}} -> {:ok, job_id}
          {:ok, %{"sha256" => sha}} -> {:ok, sha}
          {:ok, other} -> {:error, {:unexpected_response, other}}
          {:error, _} -> {:error, :invalid_json}
        end

      {:ok, %{status: status, body: resp_body}} ->
        {:error, {:http_error, status, resp_body}}

      {:error, reason} ->
        {:error, {:request_failed, reason}}
    end
  catch
    {:error, reason} -> {:error, reason}
  end

  defp submit_to_sandbox(:cuckoo, file_bytes, _sha256, metadata, cfg, _config) do
    base_url = cfg[:base_url] || "http://localhost:8090"
    api_token = cfg[:api_key] || System.get_env("CUCKOO_API_TOKEN")

    url = "#{base_url}/tasks/create/file"

    boundary = "----TamanduaSandbox#{:erlang.unique_integer([:positive])}"
    file_name = metadata[:file_name] || "sample.bin"
    body = build_multipart(boundary, "file", file_name, file_bytes)

    headers = [
      {"content-type", "multipart/form-data; boundary=#{boundary}"}
    ]

    headers = if api_token, do: [{"Authorization", "Bearer #{api_token}"} | headers], else: headers

    case do_http_request(:post, url, headers, body) do
      {:ok, %{status: 200, body: resp_body}} ->
        case Jason.decode(resp_body) do
          {:ok, %{"task_id" => task_id}} -> {:ok, to_string(task_id)}
          {:ok, %{"task_ids" => [task_id | _]}} -> {:ok, to_string(task_id)}
          {:ok, other} -> {:error, {:unexpected_response, other}}
          {:error, _} -> {:error, :invalid_json}
        end

      {:ok, %{status: status, body: resp_body}} ->
        {:error, {:http_error, status, resp_body}}

      {:error, reason} ->
        {:error, {:request_failed, reason}}
    end
  end

  defp submit_to_sandbox(:joe, file_bytes, _sha256, metadata, cfg, _config) do
    api_key = cfg[:api_key] || System.get_env("JOE_SANDBOX_API_KEY")
    unless api_key, do: throw({:error, :no_api_key})

    base_url = cfg[:base_url] || "https://jbxcloud.joesecurity.org/api/v2"
    url = "#{base_url}/analysis"

    boundary = "----TamanduaSandbox#{:erlang.unique_integer([:positive])}"
    file_name = metadata[:file_name] || "sample.bin"
    body = build_multipart_with_fields(boundary, "sample", file_name, file_bytes, %{"apikey" => api_key})

    headers = [
      {"content-type", "multipart/form-data; boundary=#{boundary}"}
    ]

    case do_http_request(:post, url, headers, body) do
      {:ok, %{status: 200, body: resp_body}} ->
        case Jason.decode(resp_body) do
          {:ok, %{"data" => %{"webid" => web_id}}} -> {:ok, to_string(web_id)}
          {:ok, other} -> {:error, {:unexpected_response, other}}
          {:error, _} -> {:error, :invalid_json}
        end

      {:ok, %{status: status, body: resp_body}} ->
        {:error, {:http_error, status, resp_body}}

      {:error, reason} ->
        {:error, {:request_failed, reason}}
    end
  catch
    {:error, reason} -> {:error, reason}
  end

  defp submit_to_sandbox(unknown, _file_bytes, _sha256, _metadata, _cfg, _config) do
    {:error, {:unknown_sandbox, unknown}}
  end

  # ============================================================================
  # Hash-Based Report Retrieval (for resubmit)
  # ============================================================================

  defp request_report_by_hash(:virustotal, file_hash, cfg, _config) do
    api_key = cfg[:api_key] || System.get_env("VIRUSTOTAL_API_KEY")

    if api_key do
      # For VirusTotal, requesting the file report by hash also triggers re-analysis
      {:ok, "hash:#{file_hash}"}
    else
      {:error, :no_api_key}
    end
  end

  defp request_report_by_hash(:hybrid, file_hash, cfg, _config) do
    api_key = cfg[:api_key] || System.get_env("HYBRID_ANALYSIS_API_KEY")

    if api_key do
      {:ok, "hash:#{file_hash}"}
    else
      {:error, :no_api_key}
    end
  end

  defp request_report_by_hash(_sandbox, _file_hash, _cfg, _config) do
    {:error, :hash_resubmit_not_supported}
  end

  # ============================================================================
  # Polling Logic
  # ============================================================================

  defp poll_sandbox_result(submission, sandbox_name, sandbox_analysis_id, state) do
    cfg = get_sandbox_config(state.config, sandbox_name)

    case fetch_sandbox_report(sandbox_name, sandbox_analysis_id, cfg, state.config) do
      {:ok, :pending} ->
        # Still analyzing, schedule next poll with backoff
        new_interval = min(submission.poll_interval_ms * 2, @max_poll_interval_ms)
        new_count = (submission.poll_count || 0) + 1

        if new_count < @max_poll_attempts do
          updated = %{submission | poll_count: new_count, poll_interval_ms: new_interval}
          :ets.insert(@ets_submissions, {submission.id, updated})
          schedule_poll(submission.id, sandbox_name, sandbox_analysis_id, new_interval)
          state
        else
          Logger.warning("[Sandbox] Max poll attempts reached for #{submission.id}:#{sandbox_name}")
          handle_sandbox_timeout(submission, sandbox_name, state)
        end

      {:ok, raw_report} ->
        # Got a report - normalize and store
        normalized = normalize_report(sandbox_name, raw_report, submission.file_hash)
        handle_report_received(submission, sandbox_name, normalized, state)

      {:error, reason} ->
        Logger.warning("[Sandbox] Poll error for #{submission.id}:#{sandbox_name}: #{inspect(reason)}")
        new_count = (submission.poll_count || 0) + 1

        if new_count < @max_poll_attempts do
          new_interval = min((submission.poll_interval_ms || @initial_poll_interval_ms) * 2, @max_poll_interval_ms)
          updated = %{submission | poll_count: new_count, poll_interval_ms: new_interval}
          :ets.insert(@ets_submissions, {submission.id, updated})
          schedule_poll(submission.id, sandbox_name, sandbox_analysis_id, new_interval)
          state
        else
          handle_sandbox_timeout(submission, sandbox_name, state)
        end
    end
  end

  defp fetch_sandbox_report(:virustotal, analysis_id, cfg, _config) do
    api_key = cfg[:api_key] || System.get_env("VIRUSTOTAL_API_KEY")

    url = if String.starts_with?(analysis_id, "hash:") do
      hash = String.replace_prefix(analysis_id, "hash:", "")
      "https://www.virustotal.com/api/v3/files/#{hash}"
    else
      "https://www.virustotal.com/api/v3/analyses/#{analysis_id}"
    end

    headers = [{"x-apikey", api_key}]

    case do_http_request(:get, url, headers, "") do
      {:ok, %{status: 200, body: resp_body}} ->
        case Jason.decode(resp_body) do
          {:ok, %{"data" => %{"attributes" => %{"status" => "queued"}}}} ->
            {:ok, :pending}

          {:ok, %{"data" => %{"attributes" => %{"status" => "completed"}}} = report} ->
            {:ok, report}

          {:ok, %{"data" => %{"attributes" => %{"last_analysis_results" => _}}} = report} ->
            {:ok, report}

          {:ok, _other} ->
            {:ok, :pending}

          {:error, _} ->
            {:error, :invalid_json}
        end

      {:ok, %{status: 404}} ->
        {:ok, :pending}

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_sandbox_report(:anyrun, analysis_id, cfg, _config) do
    api_key = cfg[:api_key] || System.get_env("ANYRUN_API_KEY")
    url = "https://api.any.run/v1/analysis/#{analysis_id}"
    headers = [{"authorization", "API-Key #{api_key}"}]

    case do_http_request(:get, url, headers, "") do
      {:ok, %{status: 200, body: resp_body}} ->
        case Jason.decode(resp_body) do
          {:ok, %{"data" => %{"status" => "running"}}} -> {:ok, :pending}
          {:ok, %{"data" => %{"status" => "pending"}}} -> {:ok, :pending}
          {:ok, report} -> {:ok, report}
          {:error, _} -> {:error, :invalid_json}
        end

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_sandbox_report(:hybrid, analysis_id, cfg, _config) do
    api_key = cfg[:api_key] || System.get_env("HYBRID_ANALYSIS_API_KEY")

    url = if String.starts_with?(analysis_id, "hash:") do
      _hash = String.replace_prefix(analysis_id, "hash:", "")
      "https://www.hybrid-analysis.com/api/v2/search/hash"
    else
      "https://www.hybrid-analysis.com/api/v2/report/#{analysis_id}/summary"
    end

    headers = [
      {"api-key", api_key},
      {"user-agent", "Tamandua-EDR/1.0"}
    ]

    case do_http_request(:get, url, headers, "") do
      {:ok, %{status: 200, body: resp_body}} ->
        case Jason.decode(resp_body) do
          {:ok, %{"state" => "IN_QUEUE"}} -> {:ok, :pending}
          {:ok, %{"state" => "IN_PROGRESS"}} -> {:ok, :pending}
          {:ok, report} -> {:ok, report}
          {:error, _} -> {:error, :invalid_json}
        end

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_sandbox_report(:cuckoo, analysis_id, cfg, _config) do
    base_url = cfg[:base_url] || "http://localhost:8090"
    url = "#{base_url}/tasks/view/#{analysis_id}"

    headers = []
    headers = if token = cfg[:api_key], do: [{"Authorization", "Bearer #{token}"} | headers], else: headers

    case do_http_request(:get, url, headers, "") do
      {:ok, %{status: 200, body: resp_body}} ->
        case Jason.decode(resp_body) do
          {:ok, %{"task" => %{"status" => "pending"}}} -> {:ok, :pending}
          {:ok, %{"task" => %{"status" => "running"}}} -> {:ok, :pending}
          {:ok, %{"task" => %{"status" => "processing"}}} -> {:ok, :pending}
          {:ok, report} -> {:ok, report}
          {:error, _} -> {:error, :invalid_json}
        end

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_sandbox_report(:joe, analysis_id, cfg, _config) do
    api_key = cfg[:api_key] || System.get_env("JOE_SANDBOX_API_KEY")
    base_url = cfg[:base_url] || "https://jbxcloud.joesecurity.org/api/v2"
    url = "#{base_url}/analysis/#{analysis_id}/report"

    headers = [{"apikey", api_key}]

    case do_http_request(:get, url, headers, "") do
      {:ok, %{status: 200, body: resp_body}} ->
        case Jason.decode(resp_body) do
          {:ok, %{"data" => %{"status" => "running"}}} -> {:ok, :pending}
          {:ok, %{"data" => %{"status" => "pending"}}} -> {:ok, :pending}
          {:ok, report} -> {:ok, report}
          {:error, _} -> {:error, :invalid_json}
        end

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_sandbox_report(unknown, _analysis_id, _cfg, _config) do
    {:error, {:unknown_sandbox, unknown}}
  end

  # ============================================================================
  # Report Normalization
  # ============================================================================

  defp normalize_report(:virustotal, raw_report, file_hash) do
    attrs = get_in(raw_report, ["data", "attributes"]) || %{}
    results = attrs["last_analysis_results"] || %{}
    stats = attrs["last_analysis_stats"] || %{}

    malicious_count = stats["malicious"] || 0
    total_count = Enum.count(results)

    score = if total_count > 0, do: round(malicious_count / total_count * 100), else: 0

    verdict = cond do
      score >= 50 -> :malicious
      score >= 15 -> :suspicious
      true -> :clean
    end

    signatures = results
    |> Enum.filter(fn {_engine, result} -> result["category"] == "malicious" end)
    |> Enum.map(fn {_engine, result} -> result["result"] end)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
    |> Enum.take(20)

    _tags = attrs["tags"] || []
    popular_threat = get_in(attrs, ["popular_threat_classification", "suggested_threat_label"]) || nil

    %SandboxReport{
      file_hash: file_hash,
      sandbox: :virustotal,
      verdict: verdict,
      score: score,
      behaviors: extract_vt_behaviors(attrs),
      network_iocs: extract_vt_network_iocs(attrs),
      file_iocs: extract_vt_file_iocs(attrs),
      registry_iocs: [],
      signatures: if(popular_threat, do: [popular_threat | signatures], else: signatures),
      ttps: extract_vt_ttps(attrs),
      submitted_at: parse_vt_timestamp(attrs["first_submission_date"]),
      completed_at: parse_vt_timestamp(attrs["last_analysis_date"]),
      raw_report: raw_report
    }
  end

  defp normalize_report(:anyrun, raw_report, file_hash) do
    data = raw_report["data"] || raw_report
    analysis = data["analysis"] || %{}

    score_val = analysis["scores"] || %{}
    threat_level = analysis["threat_level"] || data["threat_level"]

    score = score_val["spec"] || score_val["verdict"] || 0
    score = if is_number(score), do: score, else: 0

    verdict = case threat_level do
      "malicious" -> :malicious
      "suspicious" -> :suspicious
      _ -> :clean
    end

    processes = data["processes"] || []
    network = data["network"] || %{}
    mitre = data["mitre"] || []

    %SandboxReport{
      file_hash: file_hash,
      sandbox: :anyrun,
      verdict: verdict,
      score: min(score, 100),
      behaviors: extract_anyrun_behaviors(processes, mitre),
      network_iocs: extract_anyrun_network_iocs(network),
      file_iocs: extract_anyrun_file_iocs(data),
      registry_iocs: extract_anyrun_registry_iocs(data),
      signatures: data["tags"] || [],
      ttps: Enum.map(mitre, fn m -> m["id"] || m["technique_id"] end) |> Enum.reject(&is_nil/1),
      submitted_at: parse_iso_timestamp(data["created"]),
      completed_at: parse_iso_timestamp(data["completed"]),
      raw_report: raw_report
    }
  end

  defp normalize_report(:hybrid, raw_report, file_hash) do
    data = if is_list(raw_report), do: List.first(raw_report) || %{}, else: raw_report

    threat_score = data["threat_score"] || data["av_detect"] || 0
    verdict_str = data["verdict"] || ""

    verdict = cond do
      verdict_str =~ ~r/malicious/i -> :malicious
      threat_score >= 70 -> :malicious
      threat_score >= 30 or verdict_str =~ ~r/suspicious/i -> :suspicious
      true -> :clean
    end

    mitre_attacks = data["mitre_attcks"] || []

    %SandboxReport{
      file_hash: file_hash,
      sandbox: :hybrid,
      verdict: verdict,
      score: min(threat_score, 100),
      behaviors: extract_hybrid_behaviors(data, mitre_attacks),
      network_iocs: extract_hybrid_network_iocs(data),
      file_iocs: extract_hybrid_file_iocs(data),
      registry_iocs: extract_hybrid_registry_iocs(data),
      signatures: data["classification_tags"] || [],
      ttps: Enum.map(mitre_attacks, fn m -> m["technique_id"] || m["attck_id"] end) |> Enum.reject(&is_nil/1),
      submitted_at: parse_iso_timestamp(data["analysis_start_time"]),
      completed_at: parse_iso_timestamp(data["analysis_end_time"] || data["report_created_at"]),
      raw_report: raw_report
    }
  end

  defp normalize_report(:cuckoo, raw_report, file_hash) do
    task = raw_report["task"] || %{}
    info = raw_report["info"] || %{}
    behavior = raw_report["behavior"] || %{}
    network = raw_report["network"] || %{}
    signatures = raw_report["signatures"] || []
    _target = raw_report["target"] || %{}

    score_val = info["score"] || task["score"] || 0

    verdict = cond do
      score_val >= 7 -> :malicious
      score_val >= 4 -> :suspicious
      true -> :clean
    end

    %SandboxReport{
      file_hash: file_hash,
      sandbox: :cuckoo,
      verdict: verdict,
      score: min(round(score_val * 10), 100),
      behaviors: extract_cuckoo_behaviors(behavior, signatures),
      network_iocs: extract_cuckoo_network_iocs(network),
      file_iocs: extract_cuckoo_file_iocs(behavior),
      registry_iocs: extract_cuckoo_registry_iocs(behavior),
      signatures: Enum.map(signatures, fn s -> s["name"] || s["description"] end) |> Enum.reject(&is_nil/1),
      ttps: extract_cuckoo_ttps(signatures),
      submitted_at: parse_iso_timestamp(info["started"]),
      completed_at: parse_iso_timestamp(info["ended"]),
      raw_report: raw_report
    }
  end

  defp normalize_report(:joe, raw_report, file_hash) do
    data = raw_report["data"] || raw_report
    analysis = data["analysis"] || %{}

    score_val = analysis["score"] || data["detection_score"] || 0

    verdict = cond do
      score_val >= 70 -> :malicious
      score_val >= 30 -> :suspicious
      true -> :clean
    end

    signatures = analysis["signatures"] || data["signatures"] || []

    %SandboxReport{
      file_hash: file_hash,
      sandbox: :joe,
      verdict: verdict,
      score: min(score_val, 100),
      behaviors: extract_joe_behaviors(analysis),
      network_iocs: extract_joe_network_iocs(analysis),
      file_iocs: extract_joe_file_iocs(analysis),
      registry_iocs: extract_joe_registry_iocs(analysis),
      signatures: Enum.map(signatures, fn s ->
        if is_map(s), do: s["name"] || s["description"], else: s
      end) |> Enum.reject(&is_nil/1),
      ttps: extract_joe_ttps(analysis),
      submitted_at: parse_iso_timestamp(data["created_at"]),
      completed_at: parse_iso_timestamp(data["completed_at"]),
      raw_report: raw_report
    }
  end

  defp normalize_report(_sandbox, raw_report, file_hash) do
    %SandboxReport{
      file_hash: file_hash,
      sandbox: :unknown,
      verdict: :clean,
      score: 0,
      behaviors: [],
      network_iocs: [],
      file_iocs: [],
      registry_iocs: [],
      signatures: [],
      ttps: [],
      submitted_at: DateTime.utc_now(),
      completed_at: DateTime.utc_now(),
      raw_report: raw_report
    }
  end

  # ============================================================================
  # Behavior Extraction Helpers
  # ============================================================================

  # -- VirusTotal --
  defp extract_vt_behaviors(attrs) do
    sandbox_verdicts = attrs["sandbox_verdicts"] || %{}
    Enum.flat_map(sandbox_verdicts, fn {_sandbox, info} ->
      categories = info["malware_classification"] || []
      Enum.map(List.wrap(categories), fn cat ->
        %{category: :process, action: cat, mitre: nil}
      end)
    end)
    |> Enum.take(50)
  end

  defp extract_vt_network_iocs(_attrs) do
    # VT doesn't directly expose contacted IPs in file reports
    []
  end

  defp extract_vt_file_iocs(_attrs), do: []

  defp extract_vt_ttps(attrs) do
    (attrs["tags"] || [])
    |> Enum.filter(fn tag -> String.match?(tag, ~r/^T\d{4}/) end)
  end

  defp parse_vt_timestamp(nil), do: nil
  defp parse_vt_timestamp(ts) when is_integer(ts) do
    case DateTime.from_unix(ts) do
      {:ok, dt} -> dt
      _ -> nil
    end
  end
  defp parse_vt_timestamp(_), do: nil

  # -- Any.run --
  defp extract_anyrun_behaviors(processes, mitre) do
    process_behaviors = Enum.map(Enum.take(processes, 20), fn proc ->
      %{
        category: :process,
        action: proc["name"] || proc["cmd"] || "unknown process",
        mitre: nil
      }
    end)

    mitre_behaviors = Enum.map(mitre, fn m ->
      %{
        category: :process,
        action: m["name"] || m["description"] || m["id"],
        mitre: m["id"] || m["technique_id"]
      }
    end)

    process_behaviors ++ mitre_behaviors
  end

  defp extract_anyrun_network_iocs(network) do
    connections = network["connections"] || []
    dns = network["dns_requests"] || []

    ips = Enum.map(connections, fn c -> c["ip"] || c["dst_ip"] end) |> Enum.reject(&is_nil/1)
    domains = Enum.map(dns, fn d -> d["domain"] || d["request"] end) |> Enum.reject(&is_nil/1)

    ips ++ domains
  end

  defp extract_anyrun_file_iocs(data) do
    dropped = data["dropped_files"] || data["modified_files"] || []
    Enum.map(dropped, fn f ->
      %{name: f["name"] || f["path"], hash: f["sha256"] || f["md5"]}
    end)
  end

  defp extract_anyrun_registry_iocs(data) do
    reg = data["registry"] || data["registry_keys"] || []
    Enum.map(reg, fn r -> r["key"] || r["path"] end) |> Enum.reject(&is_nil/1)
  end

  # -- Hybrid Analysis --
  defp extract_hybrid_behaviors(data, mitre_attacks) do
    processes = data["processes"] || []
    proc_behaviors = Enum.map(Enum.take(processes, 20), fn p ->
      %{category: :process, action: p["name"] || p["command_line"], mitre: nil}
    end)

    mitre_behaviors = Enum.map(mitre_attacks, fn m ->
      %{category: :process, action: m["attck_id_wiki"] || m["technique"], mitre: m["technique_id"] || m["attck_id"]}
    end)

    proc_behaviors ++ mitre_behaviors
  end

  defp extract_hybrid_network_iocs(data) do
    hosts = data["domains"] || []
    ips = data["compromised_hosts"] || data["hosts"] || []
    hosts ++ ips
  end

  defp extract_hybrid_file_iocs(data) do
    (data["extracted_files"] || [])
    |> Enum.map(fn f -> %{name: f["name"], hash: f["sha256"]} end)
  end

  defp extract_hybrid_registry_iocs(data) do
    (data["registry"] || [])
    |> Enum.map(fn r -> r["key"] end)
    |> Enum.reject(&is_nil/1)
  end

  # -- Cuckoo --
  defp extract_cuckoo_behaviors(behavior, signatures) do
    processes = behavior["processes"] || []
    proc_behaviors = Enum.map(Enum.take(processes, 20), fn p ->
      %{category: :process, action: "#{p["process_name"]} (PID #{p["process_id"]})", mitre: nil}
    end)

    sig_behaviors = Enum.map(signatures, fn s ->
      ttp = get_in(s, ["ttp", 0]) || nil
      %{category: :process, action: s["description"] || s["name"], mitre: ttp}
    end)

    proc_behaviors ++ sig_behaviors
  end

  defp extract_cuckoo_network_iocs(network) do
    hosts = Enum.map(network["hosts"] || [], fn h -> h end)
    domains = Enum.map(network["domains"] || [], fn d -> d["domain"] end) |> Enum.reject(&is_nil/1)
    dns = Enum.map(network["dns"] || [], fn d -> d["request"] end) |> Enum.reject(&is_nil/1)
    hosts ++ domains ++ dns
  end

  defp extract_cuckoo_file_iocs(behavior) do
    (behavior["summary"] || %{})
    |> Map.get("files", [])
    |> Enum.map(fn f -> %{name: f, hash: nil} end)
    |> Enum.take(30)
  end

  defp extract_cuckoo_registry_iocs(behavior) do
    (behavior["summary"] || %{})
    |> Map.get("regkeys", [])
    |> Enum.take(30)
  end

  defp extract_cuckoo_ttps(signatures) do
    Enum.flat_map(signatures, fn s ->
      (s["ttp"] || []) |> List.wrap()
    end)
    |> Enum.uniq()
  end

  # -- Joe Sandbox --
  defp extract_joe_behaviors(analysis) do
    sigs = analysis["signatures"] || []
    Enum.map(Enum.take(sigs, 30), fn s ->
      name = if is_map(s), do: s["name"] || s["description"], else: s
      %{category: :process, action: name, mitre: nil}
    end)
  end

  defp extract_joe_network_iocs(analysis) do
    network = analysis["network"] || %{}
    ips = Enum.map(network["ip"] || network["contacted_ips"] || [], fn i ->
      if is_map(i), do: i["ip"] || i["address"], else: i
    end)
    domains = Enum.map(network["domains"] || network["contacted_domains"] || [], fn d ->
      if is_map(d), do: d["domain"] || d["name"], else: d
    end)
    (ips ++ domains) |> Enum.reject(&is_nil/1)
  end

  defp extract_joe_file_iocs(analysis) do
    dropped = analysis["dropped"] || analysis["dropped_files"] || []
    Enum.map(dropped, fn f ->
      if is_map(f) do
        %{name: f["name"] || f["path"], hash: f["sha256"] || f["md5"]}
      else
        %{name: f, hash: nil}
      end
    end)
  end

  defp extract_joe_registry_iocs(analysis) do
    (analysis["registry"] || analysis["registry_keys"] || [])
    |> Enum.map(fn r -> if is_map(r), do: r["key"] || r["path"], else: r end)
    |> Enum.reject(&is_nil/1)
  end

  defp extract_joe_ttps(analysis) do
    mitre = analysis["mitre"] || analysis["mitre_attack"] || []
    Enum.map(mitre, fn m ->
      if is_map(m), do: m["technique_id"] || m["id"], else: m
    end) |> Enum.reject(&is_nil/1)
  end

  # ============================================================================
  # Report Completion Handling
  # ============================================================================

  defp handle_report_received(submission, sandbox_name, normalized_report, state) do
    # Store individual sandbox report
    reports = Map.put(submission.reports || %{}, sandbox_name, normalized_report)

    # Check if all sandboxes have reported
    expected = MapSet.new(submission.sandboxes)
    received = MapSet.new(Map.keys(reports))
    all_done = MapSet.subset?(expected, received)

    updated_submission = %{submission | reports: reports}

    {updated_submission, new_state} = if all_done do
      # All sandboxes reported - aggregate and finalize
      finalize_submission(updated_submission, state)
    else
      {%{updated_submission | status: :analyzing}, state}
    end

    :ets.insert(@ets_submissions, {submission.id, updated_submission})

    # Update per-sandbox stats
    sandbox_stats = Map.get(new_state.stats.by_sandbox, sandbox_name, %{completed: 0, failed: 0})
    sandbox_stats = %{sandbox_stats | completed: sandbox_stats.completed + 1}
    put_in(new_state, [:stats, :by_sandbox, sandbox_name], sandbox_stats)
  end

  defp handle_sandbox_timeout(submission, sandbox_name, state) do
    # Mark this sandbox as timed out, check if others completed
    reports = submission.reports || %{}
    expected = MapSet.new(submission.sandboxes)
    received = MapSet.new(Map.keys(reports))
    timed_out = MapSet.new([sandbox_name])

    remaining = MapSet.difference(expected, MapSet.union(received, timed_out))

    if MapSet.size(remaining) == 0 do
      # All sandboxes either reported or timed out
      if map_size(reports) > 0 do
        {updated, new_state} = finalize_submission(submission, state)
        :ets.insert(@ets_submissions, {submission.id, updated})
        new_state
      else
        updated = %{submission | status: :failed, error: "All sandboxes timed out", completed_at: DateTime.utc_now()}
        :ets.insert(@ets_submissions, {submission.id, updated})
        update_stats(state, :failed)
      end
    else
      state
    end
  end

  defp finalize_submission(submission, state) do
    reports = submission.reports || %{}
    now = DateTime.utc_now()

    # Aggregate verdicts using weighted voting
    {agg_verdict, agg_score} = aggregate_verdicts(reports, state.config)

    # Merge all IOCs
    all_network_iocs = Enum.flat_map(reports, fn {_, r} -> r.network_iocs || [] end) |> Enum.uniq()
    all_file_iocs = Enum.flat_map(reports, fn {_, r} -> r.file_iocs || [] end) |> Enum.uniq()
    all_registry_iocs = Enum.flat_map(reports, fn {_, r} -> r.registry_iocs || [] end) |> Enum.uniq()
    all_ttps = Enum.flat_map(reports, fn {_, r} -> r.ttps || [] end) |> Enum.uniq()
    all_signatures = Enum.flat_map(reports, fn {_, r} -> r.signatures || [] end) |> Enum.uniq()
    all_behaviors = Enum.flat_map(reports, fn {_, r} -> r.behaviors || [] end) |> Enum.uniq()

    aggregated_report = %{
      file_hash: submission.file_hash,
      verdict: agg_verdict,
      score: agg_score,
      sandbox_reports: Enum.map(reports, fn {name, r} ->
        %{sandbox: name, verdict: r.verdict, score: r.score}
      end),
      behaviors: Enum.take(all_behaviors, 100),
      network_iocs: all_network_iocs,
      file_iocs: all_file_iocs,
      registry_iocs: all_registry_iocs,
      signatures: all_signatures,
      ttps: all_ttps,
      submitted_at: submission.submitted_at,
      completed_at: now,
      source: submission.source,
      alert_id: submission.alert_id
    }

    # Store aggregated report in ETS
    :ets.insert(@ets_reports, {submission.file_hash, aggregated_report})

    updated_submission = %{submission |
      status: :completed,
      completed_at: now,
      aggregated_verdict: agg_verdict,
      aggregated_score: agg_score
    }

    # Update stats
    new_state = state
    |> update_stats(:completed)
    |> update_in([:stats, :by_verdict, agg_verdict], &((&1 || 0) + 1))
    |> update_in([:stats, :iocs_extracted], &(&1 + length(all_network_iocs) + length(all_file_iocs)))

    # Broadcast completion
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "sandbox:reports",
      {:sandbox_report_complete, aggregated_report}
    )

    # Feed IOCs to threat intel
    feed_iocs_to_threat_intel(aggregated_report)

    # Update alert verdict if linked
    maybe_update_alert(aggregated_report)

    Logger.info("[Sandbox] Analysis complete for #{submission.file_hash}: verdict=#{agg_verdict}, score=#{agg_score}, ttps=#{length(all_ttps)}")

    {updated_submission, new_state}
  end

  # ============================================================================
  # Verdict Aggregation
  # ============================================================================

  defp aggregate_verdicts(reports, config) do
    weights = config[:weights] || @default_weights

    {total_weight, weighted_score} = Enum.reduce(reports, {0.0, 0.0}, fn {sandbox_name, report}, {tw, ws} ->
      w = weights[sandbox_name] || 0.5
      s = (report.score || 0) / 1
      {tw + w, ws + (s * w)}
    end)

    avg_score = if total_weight > 0, do: round(weighted_score / total_weight), else: 0

    # Count verdicts with weights
    verdict_scores = Enum.reduce(reports, %{clean: 0.0, suspicious: 0.0, malicious: 0.0}, fn {sandbox_name, report}, acc ->
      w = weights[sandbox_name] || 0.5
      verdict_key = report.verdict || :clean
      Map.update(acc, verdict_key, w, &(&1 + w))
    end)

    # Pick the verdict with highest weighted vote
    agg_verdict = verdict_scores
    |> Enum.max_by(fn {_k, v} -> v end)
    |> elem(0)

    {agg_verdict, avg_score}
  end

  # ============================================================================
  # Integration: ThreatIntel & Alerts
  # ============================================================================

  defp feed_iocs_to_threat_intel(report) do
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      # Feed network IOCs
      Enum.each(report.network_iocs || [], fn ioc ->
        type = cond do
          ioc_looks_like_ip?(ioc) -> :ip
          ioc_looks_like_domain?(ioc) -> :domain
          true -> :url
        end

        try do
          TamanduaServer.ThreatIntel.add_ioc(%{
            type: type,
            value: ioc,
            source: "sandbox_detonation",
            confidence: verdict_to_confidence(report.verdict),
            description: "Extracted from sandbox analysis of #{report.file_hash}"
          })
        rescue
          _ -> :ok
        end
      end)

      # Feed file IOCs (dropped file hashes)
      Enum.each(report.file_iocs || [], fn file_ioc ->
        if hash = file_ioc[:hash] || file_ioc["hash"] do
          try do
            TamanduaServer.ThreatIntel.add_ioc(%{
              type: :hash_sha256,
              value: hash,
              source: "sandbox_detonation",
              confidence: verdict_to_confidence(report.verdict),
              description: "Dropped file from sandbox analysis of #{report.file_hash}"
            })
          rescue
            _ -> :ok
          end
        end
      end)
    end)
  rescue
    _ -> :ok
  end

  defp maybe_update_alert(%{alert_id: nil}), do: :ok
  defp maybe_update_alert(%{alert_id: alert_id, verdict: verdict, score: score}) when is_binary(alert_id) do
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      try do
        severity = case verdict do
          :malicious -> "critical"
          :suspicious -> "high"
          :clean -> "low"
          _ -> nil
        end

        if severity do
          case TamanduaServer.Repo.get(TamanduaServer.Alerts.Alert, alert_id) do
            nil -> :ok
            alert ->
              changeset = Ecto.Changeset.change(alert, %{
                severity: severity,
                enrichment: Map.merge(alert.enrichment || %{}, %{
                  "sandbox_verdict" => to_string(verdict),
                  "sandbox_score" => score,
                  "sandbox_analyzed_at" => DateTime.utc_now() |> DateTime.to_iso8601()
                })
              })
              TamanduaServer.Repo.update(changeset)
          end
        end
      rescue
        e -> Logger.warning("[Sandbox] Failed to update alert #{alert_id}: #{Exception.message(e)}")
      end
    end)
  rescue
    _ -> :ok
  end
  defp maybe_update_alert(_), do: :ok

  # ============================================================================
  # Deduplication
  # ============================================================================

  defp check_dedup(sha256, ttl_seconds) do
    case :ets.lookup(@ets_reports, sha256) do
      [{^sha256, report}] ->
        completed_at = report[:completed_at]
        if completed_at && DateTime.diff(DateTime.utc_now(), completed_at, :second) < ttl_seconds do
          {:cached, report}
        else
          :not_found
        end

      [] ->
        :not_found
    end
  rescue
    ArgumentError -> :not_found
  end

  # ============================================================================
  # HTTP Client
  # ============================================================================

  defp do_http_request(method, url, headers, body) do
    request = Finch.build(method, url, headers, body)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: 60_000) do
      {:ok, %Finch.Response{status: status, body: resp_body}} ->
        {:ok, %{status: status, body: resp_body}}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, {:exception, Exception.message(e)}}
  end

  # ============================================================================
  # Multipart Helpers
  # ============================================================================

  defp build_multipart(boundary, field_name, file_name, file_bytes) do
    "--#{boundary}\r\n" <>
    "Content-Disposition: form-data; name=\"#{field_name}\"; filename=\"#{file_name}\"\r\n" <>
    "Content-Type: application/octet-stream\r\n\r\n" <>
    file_bytes <>
    "\r\n--#{boundary}--\r\n"
  end

  defp build_multipart_with_fields(boundary, file_field, file_name, file_bytes, fields) do
    field_parts = Enum.map(fields, fn {key, value} ->
      "--#{boundary}\r\n" <>
      "Content-Disposition: form-data; name=\"#{key}\"\r\n\r\n" <>
      "#{value}\r\n"
    end)
    |> Enum.join("")

    file_part =
      "--#{boundary}\r\n" <>
      "Content-Disposition: form-data; name=\"#{file_field}\"; filename=\"#{file_name}\"\r\n" <>
      "Content-Type: application/octet-stream\r\n\r\n" <>
      file_bytes <>
      "\r\n"

    field_parts <> file_part <> "--#{boundary}--\r\n"
  end

  # ============================================================================
  # Utility Functions
  # ============================================================================

  defp create_ets_tables do
    safe_create_ets(@ets_submissions, [:set, :public, :named_table, read_concurrency: true])
    safe_create_ets(@ets_reports, [:set, :public, :named_table, read_concurrency: true])
    safe_create_ets(@ets_stats, [:set, :public, :named_table, read_concurrency: true])
  end

  defp safe_create_ets(name, opts) do
    case :ets.info(name) do
      :undefined -> :ets.new(name, opts)
      _ -> name
    end
  end

  defp generate_submission_id do
    "sbx_" <> Base.encode16(:crypto.strong_rand_bytes(12), case: :lower)
  end

  defp compute_sha256(data) do
    :crypto.hash(:sha256, data) |> Base.encode16(case: :lower)
  end

  defp schedule_poll(submission_id, sandbox_name, analysis_id, interval_ms) do
    Process.send_after(self(), {:poll_sandbox, submission_id, sandbox_name, analysis_id}, interval_ms)
  end

  defp load_config do
    app_config = Application.get_env(:tamandua_server, __MODULE__, [])

    sandboxes = Keyword.get(app_config, :sandboxes, %{})

    # If no sandboxes configured, set up defaults from env vars
    sandboxes = if map_size(sandboxes) == 0 do
      build_default_sandbox_config()
    else
      sandboxes
    end

    %{
      sandboxes: sandboxes,
      mode: Keyword.get(app_config, :mode, :parallel),
      dedup_ttl_seconds: Keyword.get(app_config, :dedup_ttl_seconds, @default_dedup_ttl_seconds),
      ml_threshold: Keyword.get(app_config, :ml_threshold, @default_ml_threshold),
      weights: Keyword.get(app_config, :weights, @default_weights)
    }
  end

  defp build_default_sandbox_config do
    configs = %{}

    configs = if System.get_env("VIRUSTOTAL_API_KEY") do
      Map.put(configs, :virustotal, %{
        enabled: true,
        api_key: System.get_env("VIRUSTOTAL_API_KEY"),
        weight: 1.0
      })
    else
      configs
    end

    configs = if System.get_env("ANYRUN_API_KEY") do
      Map.put(configs, :anyrun, %{
        enabled: true,
        api_key: System.get_env("ANYRUN_API_KEY"),
        weight: 0.9
      })
    else
      configs
    end

    configs = if System.get_env("HYBRID_ANALYSIS_API_KEY") do
      Map.put(configs, :hybrid, %{
        enabled: true,
        api_key: System.get_env("HYBRID_ANALYSIS_API_KEY"),
        weight: 0.85,
        environment_id: System.get_env("HYBRID_ANALYSIS_ENV_ID") || "160"
      })
    else
      configs
    end

    configs = if System.get_env("CUCKOO_API_TOKEN") || System.get_env("CUCKOO_BASE_URL") do
      Map.put(configs, :cuckoo, %{
        enabled: true,
        api_key: System.get_env("CUCKOO_API_TOKEN"),
        base_url: System.get_env("CUCKOO_BASE_URL") || "http://localhost:8090",
        weight: 0.8
      })
    else
      configs
    end

    configs = if System.get_env("JOE_SANDBOX_API_KEY") do
      Map.put(configs, :joe, %{
        enabled: true,
        api_key: System.get_env("JOE_SANDBOX_API_KEY"),
        base_url: System.get_env("JOE_SANDBOX_BASE_URL") || "https://jbxcloud.joesecurity.org/api/v2",
        weight: 0.9
      })
    else
      configs
    end

    configs
  end

  defp enabled_sandbox_configs(config) do
    (config.sandboxes || %{})
    |> Enum.filter(fn {_name, cfg} -> cfg[:enabled] == true end)
  end

  defp enabled_sandbox_names(config) do
    enabled_sandbox_configs(config)
    |> Enum.map(fn {name, _} -> name end)
  end

  defp get_sandbox_config(config, sandbox_name) do
    (config.sandboxes || %{})[sandbox_name] || %{}
  end

  defp update_stats(state, :submitted) do
    update_in(state, [:stats, :total_submissions], &(&1 + 1))
  end
  defp update_stats(state, :completed) do
    update_in(state, [:stats, :completed], &(&1 + 1))
  end
  defp update_stats(state, :failed) do
    update_in(state, [:stats, :failed], &(&1 + 1))
  end
  defp update_stats(state, :deduped) do
    update_in(state, [:stats, :deduped], &(&1 + 1))
  end

  defp ets_size(table) do
    case :ets.info(table, :size) do
      :undefined -> 0
      n -> n
    end
  rescue
    _ -> 0
  end

  defp serialize_submission(submission) do
    %{
      id: submission.id,
      file_hash: submission.file_hash,
      file_name: submission.file_name,
      file_size: submission.file_size,
      source: submission.source,
      alert_id: submission.alert_id,
      sandboxes: submission.sandboxes,
      status: submission.status,
      submitted_at: format_dt(submission.submitted_at),
      completed_at: format_dt(submission.completed_at),
      sandbox_ids: submission.sandbox_ids,
      aggregated_verdict: submission.aggregated_verdict,
      aggregated_score: submission.aggregated_score,
      poll_count: submission.poll_count,
      error: submission.error,
      reports: Enum.map(submission.reports || %{}, fn {name, r} ->
        %{sandbox: name, verdict: r.verdict, score: r.score}
      end)
    }
  end

  defp format_dt(nil), do: nil
  defp format_dt(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_dt(other), do: to_string(other)

  defp parse_iso_timestamp(nil), do: nil
  defp parse_iso_timestamp(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _offset} -> dt
      _ ->
        case NaiveDateTime.from_iso8601(str) do
          {:ok, ndt} -> DateTime.from_naive!(ndt, "Etc/UTC")
          _ -> nil
        end
    end
  end
  defp parse_iso_timestamp(_), do: nil

  defp verdict_to_confidence(:malicious), do: 90
  defp verdict_to_confidence(:suspicious), do: 60
  defp verdict_to_confidence(:clean), do: 20
  defp verdict_to_confidence(_), do: 50

  defp ioc_looks_like_ip?(str) when is_binary(str) do
    String.match?(str, ~r/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)
  end
  defp ioc_looks_like_ip?(_), do: false

  defp ioc_looks_like_domain?(str) when is_binary(str) do
    String.match?(str, ~r/^[a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,}/)
  end
  defp ioc_looks_like_domain?(_), do: false
end
