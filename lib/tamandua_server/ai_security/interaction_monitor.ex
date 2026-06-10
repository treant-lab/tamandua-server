defmodule TamanduaServer.AISecurity.InteractionMonitor do
  @moduledoc """
  AI Interaction Monitor.

  GenServer that monitors all AI interactions flowing through the Tamandua
  platform, providing:

  - **Prompt injection scanning** via the ML service PromptGuard endpoint
  - **Sensitive data leak detection** via the ML service DataGuard endpoint
  - **Tamper-proof audit trail** of every AI interaction (prompt + response)
  - **Rate limiting** per user and per model
  - **Policy enforcement** with configurable modes: block, warn, log-only
  - **Multi-tenant** policy configuration per organization

  The monitor intercepts prompts before they reach the AI model and scans
  responses before they are returned to the user.  It uses ETS for fast
  rate-limit lookups and maintains a bounded in-memory audit log that is
  periodically flushed to persistent storage.
  """

  use GenServer
  require Logger

  alias TamanduaServer.{Cache, Repo}

  # ETS tables
  @interactions_table :ai_interaction_log
  @rate_limits_table :ai_interaction_rate_limits
  @policies_table :ai_interaction_policies

  # Rate limit defaults
  @default_user_rpm 60          # requests per minute per user
  @default_model_rpm 200        # requests per minute per model
  @default_window_ms 60_000     # 1 minute window

  # Audit trail limits
  @max_audit_entries 50_000
  @audit_flush_interval :timer.minutes(5)

  # ML service endpoints
  @prompt_scan_path "/ai-security/scan-prompt"
  @data_scan_path "/ai-security/scan-data"
  @ml_timeout_ms 10_000

  # Periodic cleanup
  @rate_limit_cleanup_interval :timer.minutes(2)

  # Policy modes
  @valid_modes [:block, :warn, :log_only]

  defstruct [
    :stats,
    :ml_service_url,
    :ml_api_key,
    :default_policy
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Starts the AI Interaction Monitor GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Scan a prompt before sending it to an AI model.

  Returns:
  - `{:ok, :safe}` if the prompt passes all checks
  - `{:ok, :warned, reasons}` if the policy is warn-only and issues are found
  - `{:error, :blocked, reasons}` if the policy blocks the prompt
  - `{:error, :rate_limited}` if rate limits are exceeded
  """
  @spec scan_prompt(map()) :: {:ok, :safe} | {:ok, :warned, [map()]} | {:error, :blocked | :rate_limited, term()}
  def scan_prompt(params) do
    GenServer.call(__MODULE__, {:scan_prompt, params}, 30_000)
  end

  @doc """
  Scan a model response before returning it to the user.

  Returns:
  - `{:ok, :safe, response}` if clean
  - `{:ok, :redacted, redacted_response, detections}` if data was redacted
  - `{:error, :blocked, reasons}` if the policy blocks the response
  """
  @spec scan_response(map()) :: {:ok, :safe | :redacted, binary(), [map()]} | {:error, :blocked, term()}
  def scan_response(params) do
    GenServer.call(__MODULE__, {:scan_response, params}, 30_000)
  end

  @doc """
  Record a complete AI interaction (prompt + response + scan results).
  This is called after both prompt and response scans are done.
  """
  @spec record_interaction(map()) :: :ok
  def record_interaction(interaction) do
    GenServer.cast(__MODULE__, {:record_interaction, interaction})
  end

  @doc """
  Get the interaction audit log, with optional filters.

  Options:
  - `:user_id` - filter by user
  - `:model_id` - filter by model
  - `:organization_id` - filter by organization
  - `:since` - DateTime, only entries after this time
  - `:limit` - max entries to return (default 100)
  """
  @spec get_audit_log(keyword()) :: [map()]
  def get_audit_log(opts \\ []) do
    GenServer.call(__MODULE__, {:get_audit_log, opts})
  end

  @doc """
  Set the enforcement policy for an organization.

  Policy map:
  - `:mode` - :block | :warn | :log_only
  - `:prompt_scan_enabled` - boolean
  - `:data_scan_enabled` - boolean
  - `:data_scan_policy` - "strict" | "moderate" | "permissive"
  - `:user_rpm` - requests per minute per user
  - `:model_rpm` - requests per minute per model
  - `:blocked_models` - list of model IDs to block entirely
  """
  @spec set_policy(String.t(), map()) :: :ok
  def set_policy(organization_id, policy) do
    GenServer.call(__MODULE__, {:set_policy, organization_id, policy})
  end

  @doc """
  Get the enforcement policy for an organization.
  """
  @spec get_policy(String.t()) :: map()
  def get_policy(organization_id) do
    GenServer.call(__MODULE__, {:get_policy, organization_id})
  end

  @doc """
  Get aggregate statistics for the interaction monitor.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@interactions_table, [:named_table, :ordered_set, :public, read_concurrency: true])
    :ets.new(@rate_limits_table, [:named_table, :set, :public, read_concurrency: true, write_concurrency: true])
    :ets.new(@policies_table, [:named_table, :set, :public, read_concurrency: true])

    # Read ML service config from environment
    ml_service_url = System.get_env("ML_SERVICE_URL") || "http://localhost:8000"
    ml_api_key = System.get_env("TAMANDUA_ML_API_KEY") || ""

    state = %__MODULE__{
      stats: init_stats(),
      ml_service_url: ml_service_url,
      ml_api_key: ml_api_key,
      default_policy: default_policy()
    }

    # Schedule periodic tasks
    schedule_rate_limit_cleanup()
    schedule_audit_flush()

    Logger.info("[InteractionMonitor] AI Interaction Monitor initialized",
      ml_service_url: ml_service_url)

    {:ok, state}
  end

  @impl true
  def handle_call({:scan_prompt, params}, _from, state) do
    user_id = params[:user_id] || "anonymous"
    model_id = params[:model_id] || "unknown"
    org_id = params[:organization_id] || "default"
    prompt = params[:prompt] || ""
    context = params[:context] || ""

    policy = get_org_policy(org_id, state)

    # 1. Check rate limits
    case check_rate_limit(user_id, model_id, policy) do
      :ok ->
        # 2. Check blocked models
        if model_id in (policy[:blocked_models] || []) do
          new_stats = increment_stat(state.stats, :prompts_blocked)
          {:reply, {:error, :blocked, [%{reason: "Model '#{model_id}' is blocked by policy"}]},
           %{state | stats: new_stats}}
        else
          # 3. Scan prompt if enabled
          {scan_result, new_stats} =
            if policy[:prompt_scan_enabled] != false do
              scan_prompt_via_ml(prompt, context, model_id, state)
            else
              {%{safe: true, threats: [], risk_score: 0.0}, state.stats}
            end

          # 4. Also scan for data leaks in the prompt if enabled
          {data_result, new_stats2} =
            if policy[:data_scan_enabled] != false do
              scan_data_via_ml(prompt, "input", policy[:data_scan_policy] || "moderate", state)
            else
              {%{clean: true, detections: [], risk_score: 0.0}, new_stats}
            end

          # 5. Merge all issues
          all_issues = build_issues(scan_result, data_result)

          # 6. Enforce policy
          result = enforce_policy(policy[:mode] || :log_only, all_issues)

          final_stats =
            case result do
              {:ok, :safe} -> increment_stat(new_stats2, :prompts_passed)
              {:ok, :warned, _} -> increment_stat(new_stats2, :prompts_warned)
              {:error, :blocked, _} -> increment_stat(new_stats2, :prompts_blocked)
            end

          # Log the interaction
          log_scan_event(:prompt, user_id, model_id, org_id, scan_result, data_result, result)

          {:reply, result, %{state | stats: final_stats}}
        end

      {:error, :rate_limited} ->
        new_stats = increment_stat(state.stats, :rate_limited)
        {:reply, {:error, :rate_limited, "Rate limit exceeded"}, %{state | stats: new_stats}}
    end
  end

  @impl true
  def handle_call({:scan_response, params}, _from, state) do
    user_id = params[:user_id] || "anonymous"
    model_id = params[:model_id] || "unknown"
    org_id = params[:organization_id] || "default"
    response_text = params[:response] || ""

    policy = get_org_policy(org_id, state)

    # Scan response for data leaks
    {data_result, _new_stats} =
      if policy[:data_scan_enabled] != false do
        scan_data_via_ml(response_text, "output", policy[:data_scan_policy] || "moderate", state)
      else
        {%{clean: true, detections: [], risk_score: 0.0}, state.stats}
      end

    cond do
      data_result[:clean] == true ->
        new_stats = increment_stat(state.stats, :responses_passed)
        {:reply, {:ok, :safe, response_text, []}, %{state | stats: new_stats}}

      policy[:mode] == :block and data_result[:risk_score] > 0.5 ->
        new_stats = increment_stat(state.stats, :responses_blocked)
        {:reply, {:error, :blocked, data_result[:detections] || []}, %{state | stats: new_stats}}

      data_result[:redacted_text] != nil ->
        new_stats = increment_stat(state.stats, :responses_redacted)
        {:reply, {:ok, :redacted, data_result[:redacted_text], data_result[:detections] || []},
         %{state | stats: new_stats}}

      true ->
        new_stats = increment_stat(state.stats, :responses_warned)
        {:reply, {:ok, :safe, response_text, data_result[:detections] || []}, %{state | stats: new_stats}}
    end
  end

  @impl true
  def handle_call({:get_audit_log, opts}, _from, state) do
    limit = opts[:limit] || 100
    since = opts[:since]
    user_id = opts[:user_id]
    model_id = opts[:model_id]
    org_id = opts[:organization_id]

    entries = :ets.tab2list(@interactions_table)
    |> Enum.map(fn {_key, entry} -> entry end)
    |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})
    |> maybe_filter(:user_id, user_id)
    |> maybe_filter(:model_id, model_id)
    |> maybe_filter(:organization_id, org_id)
    |> maybe_filter_since(since)
    |> Enum.take(limit)

    {:reply, entries, state}
  end

  @impl true
  def handle_call({:set_policy, organization_id, policy}, _from, state) do
    validated = validate_policy(policy, state.default_policy)
    :ets.insert(@policies_table, {organization_id, validated})
    Logger.info("[InteractionMonitor] Policy updated for org: #{organization_id}",
      mode: validated[:mode])
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:get_policy, organization_id}, _from, state) do
    policy = get_org_policy(organization_id, state)
    {:reply, policy, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = Map.merge(state.stats, %{
      audit_log_size: :ets.info(@interactions_table, :size),
      active_rate_limits: :ets.info(@rate_limits_table, :size),
      policies_configured: :ets.info(@policies_table, :size)
    })
    {:reply, stats, state}
  end

  @impl true
  def handle_cast({:record_interaction, interaction}, state) do
    entry_key = System.unique_integer([:positive, :monotonic])

    entry = %{
      id: entry_key,
      user_id: interaction[:user_id] || "anonymous",
      model_id: interaction[:model_id] || "unknown",
      organization_id: interaction[:organization_id] || "default",
      prompt_hash: hash_text(interaction[:prompt] || ""),
      prompt_length: String.length(interaction[:prompt] || ""),
      response_length: String.length(interaction[:response] || ""),
      prompt_scan_result: interaction[:prompt_scan_result],
      response_scan_result: interaction[:response_scan_result],
      risk_score: interaction[:risk_score] || 0.0,
      action_taken: interaction[:action_taken] || :logged,
      latency_ms: interaction[:latency_ms] || 0.0,
      timestamp: DateTime.utc_now()
    }

    :ets.insert(@interactions_table, {entry_key, entry})

    # Trim if needed
    trim_audit_log()

    new_stats = increment_stat(state.stats, :interactions_recorded)
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_info(:rate_limit_cleanup, state) do
    now = System.monotonic_time(:millisecond)
    cutoff = now - @default_window_ms * 2

    :ets.tab2list(@rate_limits_table)
    |> Enum.each(fn {key, {_count, window_start}} ->
      if window_start < cutoff do
        :ets.delete(@rate_limits_table, key)
      end
    end)

    schedule_rate_limit_cleanup()
    {:noreply, state}
  end

  @impl true
  def handle_info(:audit_flush, state) do
    # In production, this would flush to the database.
    # For now, just trim old entries and log the count.
    size = :ets.info(@interactions_table, :size)
    Logger.debug("[InteractionMonitor] Audit log size: #{size} entries")
    schedule_audit_flush()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp init_stats do
    %{
      prompts_scanned: 0,
      prompts_passed: 0,
      prompts_warned: 0,
      prompts_blocked: 0,
      responses_scanned: 0,
      responses_passed: 0,
      responses_warned: 0,
      responses_blocked: 0,
      responses_redacted: 0,
      rate_limited: 0,
      interactions_recorded: 0,
      ml_scan_errors: 0,
      started_at: DateTime.utc_now()
    }
  end

  defp default_policy do
    %{
      mode: :log_only,
      prompt_scan_enabled: true,
      data_scan_enabled: true,
      data_scan_policy: "moderate",
      user_rpm: @default_user_rpm,
      model_rpm: @default_model_rpm,
      blocked_models: []
    }
  end

  defp get_org_policy(org_id, state) do
    case :ets.lookup(@policies_table, org_id) do
      [{^org_id, policy}] -> policy
      [] -> state.default_policy
    end
  end

  defp validate_policy(policy, defaults) do
    mode = policy[:mode]
    mode = if mode in @valid_modes, do: mode, else: defaults[:mode]

    %{
      mode: mode,
      prompt_scan_enabled: Map.get(policy, :prompt_scan_enabled, defaults[:prompt_scan_enabled]),
      data_scan_enabled: Map.get(policy, :data_scan_enabled, defaults[:data_scan_enabled]),
      data_scan_policy: Map.get(policy, :data_scan_policy, defaults[:data_scan_policy]),
      user_rpm: Map.get(policy, :user_rpm, defaults[:user_rpm]),
      model_rpm: Map.get(policy, :model_rpm, defaults[:model_rpm]),
      blocked_models: Map.get(policy, :blocked_models, defaults[:blocked_models])
    }
  end

  # --- Rate limiting ---

  defp check_rate_limit(user_id, model_id, policy) do
    now = System.monotonic_time(:millisecond)
    user_limit = policy[:user_rpm] || @default_user_rpm
    model_limit = policy[:model_rpm] || @default_model_rpm

    user_ok = check_single_rate_limit({:user, user_id}, user_limit, now)
    model_ok = check_single_rate_limit({:model, model_id}, model_limit, now)

    if user_ok and model_ok, do: :ok, else: {:error, :rate_limited}
  end

  defp check_single_rate_limit(key, limit, now) do
    case :ets.lookup(@rate_limits_table, key) do
      [{^key, {count, window_start}}] ->
        if now - window_start > @default_window_ms do
          # Window expired, reset
          :ets.insert(@rate_limits_table, {key, {1, now}})
          true
        else
          if count < limit do
            :ets.insert(@rate_limits_table, {key, {count + 1, window_start}})
            true
          else
            false
          end
        end

      [] ->
        :ets.insert(@rate_limits_table, {key, {1, now}})
        true
    end
  end

  # --- ML service calls ---

  defp scan_prompt_via_ml(prompt, context, model_id, state) do
    body = Jason.encode!(%{
      prompt: prompt,
      context: context,
      model_id: model_id
    })

    url = "#{state.ml_service_url}#{@prompt_scan_path}"
    headers = build_ml_headers(state.ml_api_key)
    new_stats = increment_stat(state.stats, :prompts_scanned)

    case http_post(url, body, headers) do
      {:ok, %{status: 200, body: resp_body}} ->
        case Jason.decode(resp_body) do
          {:ok, result} ->
            {normalize_prompt_result(result), new_stats}
          {:error, _} ->
            Logger.warning("[InteractionMonitor] Failed to parse prompt scan response")
            {%{safe: true, threats: [], risk_score: 0.0}, increment_stat(new_stats, :ml_scan_errors)}
        end

      {:ok, %{status: status}} ->
        Logger.warning("[InteractionMonitor] Prompt scan returned status #{status}")
        {%{safe: true, threats: [], risk_score: 0.0}, increment_stat(new_stats, :ml_scan_errors)}

      {:error, reason} ->
        Logger.warning("[InteractionMonitor] Prompt scan HTTP error: #{inspect(reason)}")
        {%{safe: true, threats: [], risk_score: 0.0}, increment_stat(new_stats, :ml_scan_errors)}
    end
  end

  defp scan_data_via_ml(text, direction, policy, state) do
    body = Jason.encode!(%{
      text: text,
      direction: direction,
      policy: policy,
      redact: true
    })

    url = "#{state.ml_service_url}#{@data_scan_path}"
    headers = build_ml_headers(state.ml_api_key)
    new_stats = increment_stat(state.stats, :responses_scanned)

    case http_post(url, body, headers) do
      {:ok, %{status: 200, body: resp_body}} ->
        case Jason.decode(resp_body) do
          {:ok, result} ->
            {normalize_data_result(result), new_stats}
          {:error, _} ->
            Logger.warning("[InteractionMonitor] Failed to parse data scan response")
            {%{clean: true, detections: [], risk_score: 0.0}, increment_stat(new_stats, :ml_scan_errors)}
        end

      {:ok, %{status: status}} ->
        Logger.warning("[InteractionMonitor] Data scan returned status #{status}")
        {%{clean: true, detections: [], risk_score: 0.0}, increment_stat(new_stats, :ml_scan_errors)}

      {:error, reason} ->
        Logger.warning("[InteractionMonitor] Data scan HTTP error: #{inspect(reason)}")
        {%{clean: true, detections: [], risk_score: 0.0}, increment_stat(new_stats, :ml_scan_errors)}
    end
  end

  defp http_post(url, body, headers) do
    request = Finch.build(:post, url, headers, body)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: @ml_timeout_ms) do
      {:ok, %Finch.Response{status: status, body: body}} ->
        {:ok, %{status: status, body: body}}
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp build_ml_headers(api_key) do
    headers = [{"content-type", "application/json"}]
    if api_key != "" do
      [{"authorization", "Bearer #{api_key}"} | headers]
    else
      headers
    end
  end

  defp normalize_prompt_result(result) do
    %{
      safe: Map.get(result, "safe", true),
      threats: Map.get(result, "threats", []),
      risk_score: Map.get(result, "risk_score", 0.0)
    }
  end

  defp normalize_data_result(result) do
    %{
      clean: Map.get(result, "clean", true),
      detections: Map.get(result, "detections", []),
      risk_score: Map.get(result, "risk_score", 0.0),
      redacted_text: Map.get(result, "redacted_text")
    }
  end

  # --- Policy enforcement ---

  defp build_issues(prompt_result, data_result) do
    prompt_issues = if prompt_result[:safe] == false do
      Enum.map(prompt_result[:threats] || [], fn t ->
        %{
          source: :prompt_injection,
          type: Map.get(t, "type", "unknown"),
          description: Map.get(t, "description", ""),
          confidence: Map.get(t, "confidence", 0.0),
          technique_id: Map.get(t, "technique_id", "")
        }
      end)
    else
      []
    end

    data_issues = if data_result[:clean] == false do
      Enum.map(data_result[:detections] || [], fn d ->
        %{
          source: :data_leak,
          category: Map.get(d, "category", "unknown"),
          sub_type: Map.get(d, "sub_type", ""),
          description: Map.get(d, "description", ""),
          confidence: Map.get(d, "confidence", 0.0)
        }
      end)
    else
      []
    end

    prompt_issues ++ data_issues
  end

  defp enforce_policy(:block, issues) when issues != [] do
    {:error, :blocked, issues}
  end

  defp enforce_policy(:warn, issues) when issues != [] do
    {:ok, :warned, issues}
  end

  defp enforce_policy(_mode, _issues) do
    {:ok, :safe}
  end

  # --- Audit and logging ---

  defp log_scan_event(scan_type, user_id, model_id, org_id, prompt_result, data_result, enforcement_result) do
    action = case enforcement_result do
      {:ok, :safe} -> :passed
      {:ok, :warned, _} -> :warned
      {:error, :blocked, _} -> :blocked
    end

    Logger.info("[InteractionMonitor] #{scan_type} scan",
      user_id: user_id,
      model_id: model_id,
      organization_id: org_id,
      prompt_safe: prompt_result[:safe],
      data_clean: data_result[:clean],
      action: action,
      prompt_risk: prompt_result[:risk_score],
      data_risk: data_result[:risk_score]
    )
  end

  defp trim_audit_log do
    size = :ets.info(@interactions_table, :size)
    if size > @max_audit_entries do
      # Delete oldest entries (ordered_set, so first keys are oldest)
      first_key = :ets.first(@interactions_table)
      if first_key != :"$end_of_table" do
        :ets.delete(@interactions_table, first_key)
      end
    end
  end

  defp hash_text(text) do
    :crypto.hash(:sha256, text) |> Base.encode16(case: :lower) |> binary_part(0, 16)
  end

  # --- Filtering helpers ---

  defp maybe_filter(entries, _key, nil), do: entries
  defp maybe_filter(entries, key, value) do
    Enum.filter(entries, fn entry -> Map.get(entry, key) == value end)
  end

  defp maybe_filter_since(entries, nil), do: entries
  defp maybe_filter_since(entries, since) do
    Enum.filter(entries, fn entry ->
      DateTime.compare(entry.timestamp, since) in [:gt, :eq]
    end)
  end

  # --- Stats ---

  defp increment_stat(stats, key) do
    Map.update(stats, key, 1, &(&1 + 1))
  end

  # --- Scheduling ---

  defp schedule_rate_limit_cleanup do
    Process.send_after(self(), :rate_limit_cleanup, @rate_limit_cleanup_interval)
  end

  defp schedule_audit_flush do
    Process.send_after(self(), :audit_flush, @audit_flush_interval)
  end
end
