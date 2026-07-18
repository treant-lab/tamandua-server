defmodule TamanduaServer.AISecurity.AIGateway do
  @moduledoc """
  Metadata-only AI Gateway usage registry.

  This is the server-side foundation for future AI gateway, browser extension,
  and proxy integrations. It intentionally stores request metadata only. Prompt,
  response, body, messages, and authorization-like fields are rejected.
  """

  use GenServer
  import Ecto.Query, warn: false
  require Logger

  alias TamanduaServer.Repo

  @events_table :ai_gateway_events
  @stats_table :ai_gateway_stats
  @policy_table :ai_gateway_policy
  @max_events 10_000
  @events_prewarm 1_000

  @sensitive_fields ~w(
    prompt prompts message messages body request_body response response_body content
    input output text completion choices authorization api_key access_token refresh_token
    password secret credential headers cookie cookies
  )

  @allowed_metadata_fields ~w(
    source integration_id tenant_id organization_id user_id username department
    app application provider model domain url_host access_method agent_id hostname
    process_name process_path pid request_count input_tokens output_tokens total_tokens
    bytes_sent bytes_received cost_usd policy_id policy_decision decision reason
    risk_level risk_score data_categories classification verdict trace_id session_id
    source_event_type ai_signal confidence remote_ip remote_port local_ip local_port
    protocol direction content_inspection prompt_capture collection_mode
    url_path page_url_host tab_id title_present transition_type transition_qualifiers
    file_count file_size filename_extension mime_type file_summaries form_method
    form_action_host form_field_count form_field_types pasted_chars classifier_counts
    extension_id extension_name extension_enabled extension_install_type
    extension_permissions wallet_provider_count wallet_method
    schema_version extension_version policy_mode policy_source policy_version
    queue_length dynamic_rule_count configured last_flush_at last_flush_error
    local_blocklist_count local_warnlist_count
    mitre_techniques mitre_tactics attack_mappings
  )

  @policy_fields ~w(
    allowlist_providers blocklist_providers allowlist_domains blocklist_domains
    blocked_data_categories high_risk_data_categories default_decision
    max_risk_score_allow max_risk_score_monitor enforce_block policy_id updated_by
  )

  @default_policy %{
    policy_id: "default-metadata-only",
    default_decision: "monitor",
    enforce_block: false,
    allowlist_providers: [],
    blocklist_providers: [],
    allowlist_domains: [],
    blocklist_domains: [],
    blocked_data_categories: ["credentials", "secrets"],
    high_risk_data_categories: ["pii", "source_code", "customer_data", "financial_data"],
    max_risk_score_allow: 25,
    max_risk_score_monitor: 70,
    updated_at: nil,
    updated_by: nil
  }

  @provider_domains %{
    "openai" => ["openai.com", "chatgpt.com", "api.openai.com"],
    "anthropic" => ["anthropic.com", "claude.ai"],
    "google" => ["gemini.google.com", "generativelanguage.googleapis.com", "aistudio.google.com"],
    "microsoft" => ["copilot.microsoft.com", "bing.com", "azure.com", "openai.azure.com"],
    "huggingface" => ["huggingface.co"],
    "mistral" => ["mistral.ai"],
    "groq" => ["groq.com"],
    "openrouter" => ["openrouter.ai"],
    "perplexity" => ["perplexity.ai"]
  }

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @spec ingest_event(map()) :: {:ok, map()} | {:error, term()}
  def ingest_event(attrs) when is_map(attrs) do
    GenServer.call(__MODULE__, {:ingest, attrs})
  end

  @spec ingest_batch([map()]) :: {:ok, map()} | {:error, term()}
  def ingest_batch(events) when is_list(events) do
    GenServer.call(__MODULE__, {:ingest_batch, events}, 30_000)
  end

  @spec evaluate_event(map()) :: {:ok, map()} | {:error, term()}
  def evaluate_event(attrs) when is_map(attrs) do
    GenServer.call(__MODULE__, {:evaluate, attrs})
  end

  @spec list_usage(keyword() | map()) :: {:ok, [map()]}
  def list_usage(opts \\ []) do
    GenServer.call(__MODULE__, {:list_usage, normalize_opts(opts)})
  end

  @spec get_policy() :: map()
  def get_policy do
    GenServer.call(__MODULE__, :get_policy)
  end

  @spec update_policy(map()) :: {:ok, map()} | {:error, term()}
  def update_policy(attrs) when is_map(attrs) do
    GenServer.call(__MODULE__, {:update_policy, attrs})
  end

  @spec health() :: map()
  def health do
    GenServer.call(__MODULE__, :health)
  end

  @impl true
  def init(_opts) do
    :ets.new(@events_table, [:ordered_set, :public, :named_table, read_concurrency: true])
    :ets.new(@stats_table, [:set, :public, :named_table, read_concurrency: true])
    :ets.new(@policy_table, [:set, :public, :named_table, read_concurrency: true])
    :ets.insert(@stats_table, {:counters, %{total_ingested: 0, rejected_sensitive: 0}})
    :ets.insert(@stats_table, {:persistence, persistence_status()})
    :ets.insert(@policy_table, {:policy, load_persisted_policy()})
    preload_recent_events()

    Logger.info("[AIGateway] Metadata-only AI Gateway registry started")
    {:ok, %{}}
  end

  @impl true
  def handle_call({:ingest, attrs}, _from, state) do
    case normalize_event(attrs) do
      {:ok, event} ->
        store_event(event)
        {:reply, {:ok, event}, state}

      {:error, {:sensitive_fields, fields}} ->
        update_counter(:rejected_sensitive, 1)
        {:reply, {:error, {:sensitive_fields, fields}}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:ingest_batch, events}, _from, state) do
    summary =
      Enum.reduce(events, %{accepted: [], rejected: []}, fn attrs, acc ->
        case normalize_event(attrs) do
          {:ok, event} ->
            store_event(event)
            %{acc | accepted: [event | acc.accepted]}

          {:error, {:sensitive_fields, fields}} ->
            update_counter(:rejected_sensitive, 1)
            rejected = %{reason: "sensitive_fields", rejected_fields: fields}
            %{acc | rejected: [rejected | acc.rejected]}

          {:error, reason} ->
            rejected = %{reason: inspect(reason)}
            %{acc | rejected: [rejected | acc.rejected]}
        end
      end)

    accepted = Enum.reverse(summary.accepted)
    rejected = Enum.reverse(summary.rejected)

    {:reply,
     {:ok,
      %{
        accepted_count: length(accepted),
        rejected_count: length(rejected),
        accepted: accepted,
        rejected: rejected
      }}, state}
  end

  @impl true
  def handle_call({:evaluate, attrs}, _from, state) do
    case normalize_event(attrs) do
      {:ok, event} ->
        {:reply,
         {:ok,
          %{
            id: event.id,
            provider: event.provider,
            domain: event.domain,
            policy_id: event.policy_id,
            policy_decision: event.policy_decision,
            policy_reasons: event.policy_reasons,
            policy_enforced: event.policy_enforced,
            effective_risk_score: event.effective_risk_score,
            risk_level: event.risk_level,
            content_inspection: false,
            prompt_capture: false
          }}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:list_usage, opts}, _from, state) do
    limit = Map.get(opts, :limit, 250)
    since_ms = Map.get(opts, :since_ms)

    events =
      persisted_events(limit, since_ms)
      |> merge_usage_events(ets_events(), limit, since_ms)

    {:reply, {:ok, events}, state}
  end

  @impl true
  def handle_call(:get_policy, _from, state) do
    {:reply, current_policy(), state}
  end

  @impl true
  def handle_call({:update_policy, attrs}, _from, state) do
    case normalize_policy(attrs) do
      {:ok, policy_patch} ->
        policy =
          current_policy()
          |> Map.merge(policy_patch)
          |> Map.put(:updated_at, DateTime.utc_now() |> DateTime.to_iso8601())

        :ets.insert(@policy_table, {:policy, policy})
        persist_policy(policy)
        {:reply, {:ok, policy}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:health, _from, state) do
    events = ets_events()
    persisted = persistence_status()

    persisted_count = persisted[:event_count] || 0
    runtime_count = length(events)
    count = max(persisted_count, runtime_count)

    runtime_last_seen =
      events
      |> Enum.map(& &1.timestamp_ms)
      |> Enum.max(fn -> nil end)
      |> format_unix_ms()

    last_seen =
      persisted[:last_seen] || runtime_last_seen

    counters =
      case :ets.lookup(@stats_table, :counters) do
        [{:counters, c}] -> c
        _ -> %{}
      end

    {:reply,
     %{
       status: if(count > 0, do: "active", else: "no_data"),
       event_count: count,
       last_seen: last_seen,
       collection_mode: "gateway_metadata",
       content_inspection: false,
       prompt_capture: false,
       inline_proxy: false,
       decision_simulation_available: true,
       dry_run_available: false,
       enforcement: %{
         available: true,
         mode: "endpoint_action_bridge",
         note:
           "Policy decisions remain metadata-only. Enforced block decisions from endpoint telemetry can queue conservative endpoint block actions; true inline blocking still requires a proxy, browser extension, SDK, or endpoint control integration."
       },
       persistence: persisted,
       policy: %{
         policy_id: current_policy().policy_id,
         default_decision: current_policy().default_decision,
         enforce_block: current_policy().enforce_block
       },
       counters: counters
     }, state}
  end

  defp normalize_event(attrs) do
    normalized = atomize_known_keys(attrs)

    case sensitive_fields_present(attrs) do
      [] ->
        timestamp_ms = parse_timestamp_ms(normalized[:timestamp] || normalized[:timestamp_ms])

        base_event = %{
          id: normalized[:id] || normalized[:event_id] || UUID.uuid4(),
          timestamp_ms: timestamp_ms,
          observed_at: format_unix_ms(timestamp_ms),
          source: normalized[:source] || "ai_gateway",
          integration_id: normalized[:integration_id],
          tenant_id: normalized[:tenant_id],
          organization_id: normalized[:organization_id],
          user_id: normalized[:user_id],
          username: normalized[:username],
          department: normalized[:department],
          app: normalized[:app] || normalized[:application],
          provider:
            normalized[:provider] || infer_provider(normalized[:domain] || normalized[:url_host]),
          model: normalized[:model],
          domain: normalized[:domain] || normalized[:url_host],
          access_method: normalized[:access_method] || "gateway",
          agent_id: normalized[:agent_id],
          hostname: normalized[:hostname],
          process_name: normalized[:process_name],
          process_path: normalized[:process_path],
          pid: normalized[:pid],
          request_count: to_int(normalized[:request_count], 1),
          input_tokens: to_int(normalized[:input_tokens], 0),
          output_tokens: to_int(normalized[:output_tokens], 0),
          total_tokens: to_int(normalized[:total_tokens], nil),
          bytes_sent: to_int(normalized[:bytes_sent], 0),
          bytes_received: to_int(normalized[:bytes_received], 0),
          cost_usd: to_float(normalized[:cost_usd]),
          policy_id: normalized[:policy_id],
          policy_decision: normalized[:policy_decision] || normalized[:decision],
          reason: normalized[:reason],
          risk_level: normalized[:risk_level],
          risk_score: to_int(normalized[:risk_score], 0),
          data_categories: List.wrap(normalized[:data_categories] || []),
          classification: normalized[:classification],
          verdict: normalized[:verdict],
          trace_id: normalized[:trace_id],
          session_id: normalized[:session_id],
          content_inspection: normalized[:content_inspection] == true,
          prompt_capture: normalized[:prompt_capture] == true,
          collection_mode: normalized[:collection_mode] || "gateway_metadata",
          metadata: metadata_subset(attrs)
        }

        evaluation = evaluate_policy(base_event)

        event =
          base_event
          |> Map.put(:policy_id, base_event.policy_id || evaluation.policy_id)
          |> Map.put(:policy_decision, base_event.policy_decision || evaluation.decision)
          |> Map.put(:policy_reasons, evaluation.reasons)
          |> Map.put(:policy_enforced, evaluation.enforced)
          |> Map.put(:effective_risk_score, evaluation.risk_score)
          |> Map.put(
            :risk_level,
            base_event.risk_level || risk_level_from_score(evaluation.risk_score)
          )

        {:ok, event}

      fields ->
        {:error, {:sensitive_fields, fields}}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp store_event(event) do
    key = {event.timestamp_ms, event.id}
    :ets.insert(@events_table, {key, event})
    trim_events()
    update_counter(:total_ingested, 1)
    persist_event(event)
  end

  defp current_policy do
    case :ets.lookup(@policy_table, :policy) do
      [{:policy, policy}] -> policy
      _ -> @default_policy
    end
  end

  defp load_persisted_policy do
    if table_exists?("ai_gateway_policies") do
      "ai_gateway_policies"
      |> active_policy_query()
      |> Repo.one()
      |> case do
        nil ->
          default = default_policy_with_timestamp()
          persist_policy(default)
          default

        row ->
          policy_from_row(row)
      end
    else
      default_policy_with_timestamp()
    end
  rescue
    e ->
      remember_persistence_error(e)
      default_policy_with_timestamp()
  end

  defp default_policy_with_timestamp do
    Map.put(@default_policy, :updated_at, DateTime.utc_now() |> DateTime.to_iso8601())
  end

  defp active_policy_query(table) do
    from(p in table,
      where: field(p, :active) == true,
      order_by: [desc: field(p, :inserted_at)],
      limit: 1,
      select: %{
        policy_id: field(p, :policy_id),
        default_decision: field(p, :default_decision),
        enforce_block: field(p, :enforce_block),
        allowlist_providers: field(p, :allowlist_providers),
        blocklist_providers: field(p, :blocklist_providers),
        allowlist_domains: field(p, :allowlist_domains),
        blocklist_domains: field(p, :blocklist_domains),
        blocked_data_categories: field(p, :blocked_data_categories),
        high_risk_data_categories: field(p, :high_risk_data_categories),
        max_risk_score_allow: field(p, :max_risk_score_allow),
        max_risk_score_monitor: field(p, :max_risk_score_monitor),
        updated_by: field(p, :updated_by),
        inserted_at: field(p, :inserted_at),
        updated_at: field(p, :updated_at)
      }
    )
  end

  defp policy_from_row(row) do
    @default_policy
    |> Map.merge(%{
      policy_id: row.policy_id,
      default_decision: row.default_decision,
      enforce_block: row.enforce_block,
      allowlist_providers: row.allowlist_providers || [],
      blocklist_providers: row.blocklist_providers || [],
      allowlist_domains: row.allowlist_domains || [],
      blocklist_domains: row.blocklist_domains || [],
      blocked_data_categories: row.blocked_data_categories || [],
      high_risk_data_categories: row.high_risk_data_categories || [],
      max_risk_score_allow: row.max_risk_score_allow,
      max_risk_score_monitor: row.max_risk_score_monitor,
      updated_by: row.updated_by,
      updated_at: format_datetime(row.updated_at || row.inserted_at)
    })
  end

  defp preload_recent_events do
    persisted_events(@events_prewarm, nil)
    |> Enum.each(fn event ->
      :ets.insert(@events_table, {{event.timestamp_ms, event.id}, event})
    end)
  rescue
    e -> remember_persistence_error(e)
  end

  defp persisted_events(limit, since_ms) do
    if table_exists?("ai_gateway_events") do
      query =
        from(e in "ai_gateway_events",
          order_by: [desc: field(e, :timestamp_ms)],
          limit: ^limit,
          select: %{
            id: field(e, :id),
            timestamp_ms: field(e, :timestamp_ms),
            observed_at: field(e, :observed_at),
            source: field(e, :source),
            integration_id: field(e, :integration_id),
            tenant_id: field(e, :tenant_id),
            organization_id: field(e, :organization_id),
            user_id: field(e, :user_id),
            username: field(e, :username),
            department: field(e, :department),
            app: field(e, :app),
            provider: field(e, :provider),
            model: field(e, :model),
            domain: field(e, :domain),
            access_method: field(e, :access_method),
            agent_id: field(e, :agent_id),
            hostname: field(e, :hostname),
            process_name: field(e, :process_name),
            process_path: field(e, :process_path),
            pid: field(e, :pid),
            request_count: field(e, :request_count),
            input_tokens: field(e, :input_tokens),
            output_tokens: field(e, :output_tokens),
            total_tokens: field(e, :total_tokens),
            bytes_sent: field(e, :bytes_sent),
            bytes_received: field(e, :bytes_received),
            cost_usd: field(e, :cost_usd),
            policy_id: field(e, :policy_id),
            policy_decision: field(e, :policy_decision),
            policy_reasons: field(e, :policy_reasons),
            policy_enforced: field(e, :policy_enforced),
            effective_risk_score: field(e, :effective_risk_score),
            reason: field(e, :reason),
            risk_level: field(e, :risk_level),
            risk_score: field(e, :risk_score),
            data_categories: field(e, :data_categories),
            classification: field(e, :classification),
            verdict: field(e, :verdict),
            trace_id: field(e, :trace_id),
            session_id: field(e, :session_id),
            metadata: field(e, :metadata)
          }
        )

      query =
        if is_nil(since_ms) do
          query
        else
          from(e in query, where: field(e, :timestamp_ms) >= ^since_ms)
        end

      Repo.all(query)
      |> Enum.map(&event_from_row/1)
    else
      []
    end
  rescue
    e ->
      remember_persistence_error(e)
      []
  end

  defp event_from_row(row) do
    row
    |> Map.put(:observed_at, format_datetime(row.observed_at))
    |> Map.update(:policy_reasons, [], &normalize_string_list/1)
    |> Map.update(:data_categories, [], &normalize_string_list/1)
    |> Map.update(:metadata, %{}, &(&1 || %{}))
  end

  defp ets_events do
    @events_table
    |> :ets.tab2list()
    |> Enum.map(fn {_key, event} -> event end)
  rescue
    _ -> []
  end

  defp merge_usage_events(persisted, live, limit, since_ms) do
    (persisted ++ live)
    |> maybe_filter_since(since_ms)
    |> Enum.uniq_by(& &1.id)
    |> Enum.sort_by(& &1.timestamp_ms, :desc)
    |> Enum.take(limit)
  end

  defp persist_event(event) do
    if table_exists?("ai_gateway_events") do
      now = DateTime.utc_now() |> DateTime.truncate(:second) |> ensure_usec()

      Repo.insert_all(
        "ai_gateway_events",
        [
          event
          |> Map.take([
            :id,
            :timestamp_ms,
            :source,
            :integration_id,
            :tenant_id,
            :organization_id,
            :user_id,
            :username,
            :department,
            :app,
            :provider,
            :model,
            :domain,
            :access_method,
            :agent_id,
            :hostname,
            :process_name,
            :process_path,
            :pid,
            :request_count,
            :input_tokens,
            :output_tokens,
            :total_tokens,
            :bytes_sent,
            :bytes_received,
            :cost_usd,
            :policy_id,
            :policy_decision,
            :policy_reasons,
            :policy_enforced,
            :effective_risk_score,
            :reason,
            :risk_level,
            :risk_score,
            :data_categories,
            :classification,
            :verdict,
            :trace_id,
            :session_id,
            :metadata
          ])
          |> Map.put(:observed_at, timestamp_ms_to_datetime(event.timestamp_ms))
          |> Map.update(:pid, nil, &nullable_string/1)
          |> Map.put(:policy_reasons, normalize_string_list(event.policy_reasons))
          |> Map.put(:data_categories, normalize_string_list(event.data_categories))
          |> Map.put(:metadata, event.metadata || %{})
          |> Map.put(:inserted_at, now)
          |> Map.put(:updated_at, now)
        ],
        on_conflict: {:replace_all_except, [:id, :inserted_at]},
        conflict_target: [:id]
      )
    end
  rescue
    e -> remember_persistence_error(e)
  end

  defp persist_policy(policy) do
    if table_exists?("ai_gateway_policies") do
      now = DateTime.utc_now() |> DateTime.truncate(:second) |> ensure_usec()

      Repo.transaction(fn ->
        from(p in "ai_gateway_policies", where: field(p, :active) == true)
        |> Repo.update_all(set: [active: false, updated_at: now])

        Repo.insert_all("ai_gateway_policies", [
          %{
            id: Ecto.UUID.generate(),
            policy_id: policy.policy_id,
            active: true,
            default_decision: policy.default_decision,
            enforce_block: policy.enforce_block,
            allowlist_providers: normalize_string_list(policy.allowlist_providers),
            blocklist_providers: normalize_string_list(policy.blocklist_providers),
            allowlist_domains: normalize_string_list(policy.allowlist_domains),
            blocklist_domains: normalize_string_list(policy.blocklist_domains),
            blocked_data_categories: normalize_string_list(policy.blocked_data_categories),
            high_risk_data_categories: normalize_string_list(policy.high_risk_data_categories),
            max_risk_score_allow: policy.max_risk_score_allow,
            max_risk_score_monitor: policy.max_risk_score_monitor,
            updated_by: policy.updated_by,
            policy: policy,
            inserted_at: now,
            updated_at: now
          }
        ])
      end)
    end
  rescue
    e -> remember_persistence_error(e)
  end

  defp persistence_status do
    events_table = table_exists?("ai_gateway_events")
    policies_table = table_exists?("ai_gateway_policies")
    event_stats = persisted_event_stats(events_table)

    status =
      cond do
        events_table and policies_table -> "available"
        events_table or policies_table -> "partial"
        true -> "unconfigured"
      end

    %{
      status: status,
      events_table: events_table,
      policies_table: policies_table,
      event_count: event_stats.count,
      last_seen: event_stats.last_seen,
      retention: persistence_retention(event_stats.first_seen, event_stats.last_seen),
      last_error: last_persistence_error()
    }
  rescue
    e ->
      remember_persistence_error(e)

      %{
        status: "unavailable",
        events_table: false,
        policies_table: false,
        event_count: 0,
        last_seen: nil,
        retention: "coverage query failed",
        last_error: Exception.message(e)
      }
  end

  defp persisted_event_stats(false), do: %{count: 0, first_seen: nil, last_seen: nil}

  defp persisted_event_stats(true) do
    Repo.one(
      from(e in "ai_gateway_events",
        select: %{
          count: count(),
          first_seen: min(field(e, :observed_at)),
          last_seen: max(field(e, :observed_at))
        }
      )
    )
    |> case do
      nil ->
        %{count: 0, first_seen: nil, last_seen: nil}

      stats ->
        %{
          count: stats.count || 0,
          first_seen: stats.first_seen,
          last_seen: format_datetime(stats.last_seen)
        }
    end
  end

  defp persistence_retention(nil, nil), do: "no rows retained"
  defp persistence_retention(_first_seen, nil), do: "newest timestamp unavailable"
  defp persistence_retention(nil, _last_seen), do: "oldest timestamp unavailable"

  defp persistence_retention(%DateTime{} = first_seen, last_seen) when is_binary(last_seen) do
    case DateTime.from_iso8601(last_seen) do
      {:ok, dt, _} -> persistence_retention(first_seen, dt)
      _ -> "retention unavailable"
    end
  end

  defp persistence_retention(%DateTime{} = first_seen, %DateTime{} = last_seen) do
    seconds = max(DateTime.diff(last_seen, first_seen, :second), 0)

    cond do
      seconds == 0 -> "single timestamp"
      seconds < 3_600 -> "#{div(seconds, 60)}m"
      seconds < 86_400 -> "#{Float.round(seconds / 3_600, 1)}h"
      true -> "#{Float.round(seconds / 86_400, 1)}d"
    end
  end

  defp table_exists?(table) do
    case Ecto.Adapters.SQL.query(Repo, "SELECT to_regclass($1) IS NOT NULL", ["public.#{table}"]) do
      {:ok, %{rows: [[exists?]]}} -> exists?
      _ -> false
    end
  rescue
    _ -> false
  end

  defp normalize_policy(attrs) do
    policy_patch =
      Enum.reduce(attrs, %{}, fn {key, value}, acc ->
        normalized_key =
          key
          |> to_string()
          |> String.trim()
          |> String.downcase()
          |> String.replace("-", "_")

        if normalized_key in @policy_fields do
          Map.put(
            acc,
            String.to_atom(normalized_key),
            normalize_policy_value(normalized_key, value)
          )
        else
          acc
        end
      end)

    default_decision = Map.get(policy_patch, :default_decision)

    if default_decision && default_decision not in ["allow", "monitor", "review", "block"] do
      {:error, :invalid_default_decision}
    else
      {:ok, policy_patch}
    end
  end

  defp normalize_policy_value(key, value)
       when key in [
              "allowlist_providers",
              "blocklist_providers",
              "allowlist_domains",
              "blocklist_domains",
              "blocked_data_categories",
              "high_risk_data_categories"
            ] do
    value
    |> List.wrap()
    |> Enum.map(&normalize_string/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  defp normalize_policy_value(key, value)
       when key in ["max_risk_score_allow", "max_risk_score_monitor"],
       do: to_int(value, Map.get(@default_policy, String.to_atom(key)))

  defp normalize_policy_value("enforce_block", value), do: value in [true, "true", "1", 1]
  defp normalize_policy_value(_key, value) when is_binary(value), do: String.trim(value)
  defp normalize_policy_value(_key, value), do: value

  defp evaluate_policy(event) do
    policy = current_policy()
    provider = normalize_string(event.provider)
    domain = normalize_domain(event.domain)
    categories = Enum.map(event.data_categories || [], &normalize_string/1)
    base_score = event.risk_score || 0

    {decision, reasons, score} =
      cond do
        intersects?(categories, policy.blocked_data_categories) ->
          {"block", ["blocked_data_category"], max(base_score, 95)}

        provider != "" and provider in policy.blocklist_providers ->
          {"block", ["blocked_provider"], max(base_score, 90)}

        domain != "" and domain_matches_any?(domain, policy.blocklist_domains) ->
          {"block", ["blocked_domain"], max(base_score, 90)}

        base_score >= policy.max_risk_score_monitor ->
          {"review", ["risk_score_above_monitor_threshold"], base_score}

        intersects?(categories, policy.high_risk_data_categories) ->
          {"review", ["high_risk_data_category"], max(base_score, 70)}

        approved_provider_or_domain?(provider, domain, policy) and
            base_score <= policy.max_risk_score_allow ->
          {"allow", ["approved_provider_or_domain"], base_score}

        true ->
          {policy.default_decision, ["default_policy"], base_score}
      end

    %{
      policy_id: policy.policy_id,
      decision: decision,
      reasons: reasons,
      risk_score: score,
      enforced: decision == "block" and policy.enforce_block == true
    }
  end

  defp approved_provider_or_domain?(provider, domain, policy) do
    (provider != "" and provider in policy.allowlist_providers) or
      (domain != "" and domain_matches_any?(domain, policy.allowlist_domains))
  end

  defp intersects?(left, right) do
    right_set = MapSet.new(Enum.map(right || [], &normalize_string/1))
    Enum.any?(left || [], &MapSet.member?(right_set, normalize_string(&1)))
  end

  defp domain_matches_any?(_domain, []), do: false

  defp domain_matches_any?(domain, patterns) do
    Enum.any?(patterns || [], fn pattern ->
      normalized = normalize_domain(pattern)
      normalized != "" and (domain == normalized or String.ends_with?(domain, "." <> normalized))
    end)
  end

  defp normalize_domain(nil), do: ""

  defp normalize_domain(value) do
    raw =
      value
      |> to_string()
      |> String.trim()
      |> String.downcase()

    host =
      if String.contains?(raw, "://") do
        case URI.parse(raw) do
          %URI{host: host} when is_binary(host) -> host
          _ -> raw
        end
      else
        raw
      end

    host
    |> String.split("/", parts: 2)
    |> List.first()
    |> String.split(":", parts: 2)
    |> List.first()
    |> to_string()
    |> String.trim()
    |> String.trim_leading(".")
  end

  defp normalize_string(nil), do: ""
  defp normalize_string(value), do: value |> to_string() |> String.trim() |> String.downcase()

  defp risk_level_from_score(score) when score >= 90, do: "critical"
  defp risk_level_from_score(score) when score >= 70, do: "high"
  defp risk_level_from_score(score) when score >= 40, do: "medium"
  defp risk_level_from_score(_score), do: "low"

  defp atomize_known_keys(map) do
    Enum.reduce(map, %{}, fn {key, value}, acc ->
      normalized_key =
        key
        |> to_string()
        |> String.trim()
        |> String.downcase()
        |> String.replace("-", "_")

      if normalized_key in @allowed_metadata_fields or
           normalized_key in ["id", "event_id", "timestamp", "timestamp_ms"] do
        Map.put(acc, String.to_atom(normalized_key), value)
      else
        acc
      end
    end)
  end

  defp sensitive_fields_present(map) do
    map
    |> flatten_keys()
    |> Enum.map(&String.downcase/1)
    |> Enum.filter(fn key -> key in @sensitive_fields end)
    |> Enum.uniq()
  end

  defp flatten_keys(map) when is_map(map) do
    Enum.flat_map(map, fn {key, value} ->
      key_string = to_string(key)
      if is_map(value), do: [key_string | flatten_keys(value)], else: [key_string]
    end)
  end

  defp flatten_keys(_), do: []

  defp metadata_subset(map) do
    map
    |> Enum.reduce(%{}, fn {key, value}, acc ->
      key_string = to_string(key)
      normalized = key_string |> String.downcase() |> String.replace("-", "_")

      cond do
        normalized in @sensitive_fields -> acc
        normalized == "metadata" and is_map(value) -> Map.merge(acc, metadata_subset(value))
        normalized in @allowed_metadata_fields -> Map.put(acc, key_string, value)
        true -> acc
      end
    end)
  end

  defp maybe_filter_since(events, nil), do: events

  defp maybe_filter_since(events, since_ms),
    do: Enum.filter(events, &(&1.timestamp_ms >= since_ms))

  defp normalize_opts(opts) when is_list(opts), do: Map.new(opts)
  defp normalize_opts(opts) when is_map(opts), do: opts
  defp normalize_opts(_), do: %{}

  defp parse_timestamp_ms(nil), do: System.system_time(:millisecond)
  defp parse_timestamp_ms(value) when is_integer(value), do: value

  defp parse_timestamp_ms(value) when is_binary(value) do
    case Integer.parse(value) do
      {int, ""} ->
        int

      _ ->
        case DateTime.from_iso8601(value) do
          {:ok, dt, _} -> DateTime.to_unix(dt, :millisecond)
          _ -> System.system_time(:millisecond)
        end
    end
  end

  defp parse_timestamp_ms(_), do: System.system_time(:millisecond)

  defp format_unix_ms(nil), do: nil

  defp format_unix_ms(timestamp_ms) when is_integer(timestamp_ms) do
    timestamp_ms
    |> DateTime.from_unix!(:millisecond)
    |> DateTime.to_iso8601()
  rescue
    _ -> nil
  end

  defp timestamp_ms_to_datetime(timestamp_ms) when is_integer(timestamp_ms) do
    timestamp_ms
    |> DateTime.from_unix!(:millisecond)
    |> ensure_usec()
  rescue
    _ -> DateTime.utc_now() |> ensure_usec()
  end

  defp timestamp_ms_to_datetime(_), do: DateTime.utc_now() |> ensure_usec()

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)

  defp format_datetime(%NaiveDateTime{} = ndt),
    do: ndt |> DateTime.from_naive!("Etc/UTC") |> DateTime.to_iso8601()

  defp format_datetime(value), do: value

  defp ensure_usec(%DateTime{microsecond: {value, precision}} = dt) when precision < 6 do
    %{dt | microsecond: {value, 6}}
  end

  defp ensure_usec(%DateTime{} = dt), do: dt

  defp normalize_string_list(nil), do: []
  defp normalize_string_list(values) when is_list(values), do: Enum.map(values, &to_string/1)
  defp normalize_string_list(value), do: [to_string(value)]

  defp nullable_string(nil), do: nil
  defp nullable_string(value), do: to_string(value)

  defp to_int(nil, default), do: default
  defp to_int(value, _default) when is_integer(value), do: value

  defp to_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      _ -> default
    end
  end

  defp to_int(_, default), do: default

  defp to_float(nil), do: nil
  defp to_float(value) when is_float(value), do: value
  defp to_float(value) when is_integer(value), do: value / 1

  defp to_float(value) when is_binary(value) do
    case Float.parse(value) do
      {float, _} -> float
      _ -> nil
    end
  end

  defp to_float(_), do: nil

  defp infer_provider(domain) when is_binary(domain) do
    normalized_domain = normalize_domain(domain)

    @provider_domains
    |> Enum.find_value(fn {provider, domains} ->
      if domain_matches_any?(normalized_domain, domains), do: provider
    end)
  end

  defp infer_provider(_), do: nil

  defp trim_events do
    size = :ets.info(@events_table, :size) || 0

    if size > @max_events do
      @events_table
      |> :ets.first()
      |> delete_oldest(size - @max_events)
    end
  end

  defp delete_oldest(:"$end_of_table", _remaining), do: :ok
  defp delete_oldest(_key, remaining) when remaining <= 0, do: :ok

  defp delete_oldest(key, remaining) do
    next = :ets.next(@events_table, key)
    :ets.delete(@events_table, key)
    delete_oldest(next, remaining - 1)
  end

  defp update_counter(key, amount) do
    counters =
      case :ets.lookup(@stats_table, :counters) do
        [{:counters, c}] -> c
        _ -> %{}
      end

    :ets.insert(@stats_table, {:counters, Map.update(counters, key, amount, &(&1 + amount))})
  end

  defp remember_persistence_error(error) do
    message =
      case error do
        %_{} -> Exception.message(error)
        _ -> inspect(error)
      end

    persistence =
      case :ets.lookup(@stats_table, :persistence) do
        [{:persistence, current}] -> current
        _ -> %{}
      end

    :ets.insert(@stats_table, {:persistence, Map.put(persistence, :last_error, message)})
  rescue
    _ -> :ok
  end

  defp last_persistence_error do
    case :ets.lookup(@stats_table, :persistence) do
      [{:persistence, %{last_error: error}}] -> error
      _ -> nil
    end
  rescue
    _ -> nil
  end
end
