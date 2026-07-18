defmodule TamanduaServer.AISecurity.ExfiltrationCorrelator do
  @moduledoc """
  Correlates metadata from sensitive resource access and AI egress surfaces.

  The correlator is deliberately stateless and does not persist its inputs. It
  never includes file paths, MCP parameters, prompts, responses, or network
  payloads in a detection. Callers may provide already-collected metadata to
  `correlate/2`, or use `correlate_live/2` to augment resource access events
  with metadata exposed by the existing AI security registries.
  """

  alias TamanduaServer.AISecurity.{
    AIGateway,
    InteractionMonitor,
    MCPGovernance,
    ModelAuditor
  }

  @default_window_ms :timer.minutes(5)
  @default_token_threshold 50_000
  @default_byte_threshold 5 * 1024 * 1024
  @default_spike_multiplier 4.0

  @ai_domains ~w(
    openai.com chatgpt.com anthropic.com claude.ai gemini.google.com
    generativelanguage.googleapis.com aistudio.google.com
    copilot.microsoft.com openai.azure.com huggingface.co mistral.ai
    groq.com openrouter.ai perplexity.ai
  )

  @ai_providers ~w(openai anthropic google microsoft huggingface mistral groq openrouter perplexity)
  @sensitive_categories ~w(credentials secrets cloud_credentials private_key source_code customer_data financial_data pii)

  @type report :: %{
          detections: [map()],
          recommendations: [map()],
          coverage: map(),
          metadata_only: true
        }

  @doc """
  Correlate supplied metadata.

  Accepted source keys are `:sensitive_accesses`, `:gateway_events`,
  `:mcp_tool_calls`, `:interaction_events`, `:model_invocations`, and
  `:network_events`. String keys are accepted as well.
  """
  @spec correlate(map(), keyword()) :: report()
  def correlate(sources, opts \\ []) when is_map(sources) do
    window_ms = positive_integer(opts[:window_ms], @default_window_ms)

    normalized = %{
      sensitive_accesses:
        normalize_events(source(sources, :sensitive_accesses), :sensitive_access),
      gateway_events: normalize_events(source(sources, :gateway_events), :gateway),
      mcp_tool_calls: normalize_events(source(sources, :mcp_tool_calls), :mcp),
      interaction_events: normalize_events(source(sources, :interaction_events), :interaction),
      model_invocations: normalize_events(source(sources, :model_invocations), :model_invocation),
      network_events: normalize_events(source(sources, :network_events), :network)
    }

    accesses = Enum.filter(normalized.sensitive_accesses, &sensitive_access?/1)
    ai_egress = Enum.filter(normalized.gateway_events, &ai_egress?/1)
    mcp_http = Enum.filter(normalized.mcp_tool_calls, &mcp_http_tool?/1)

    detections =
      correlate_sensitive_egress(accesses, ai_egress ++ mcp_http, window_ms) ++
        spike_detections(normalized, opts) ++
        doh_proxy_detections(normalized.network_events, ai_egress, window_ms)

    detections =
      detections
      |> Enum.uniq_by(&detection_fingerprint/1)
      |> Enum.sort_by(&{-&1.risk_score, &1.observed_at})

    %{
      detections: detections,
      recommendations: recommendations(detections),
      coverage: %{
        sensitive_accesses: length(normalized.sensitive_accesses),
        gateway_events: length(normalized.gateway_events),
        mcp_tool_calls: length(normalized.mcp_tool_calls),
        interaction_events: length(normalized.interaction_events),
        model_invocations: length(normalized.model_invocations),
        network_events: length(normalized.network_events)
      },
      metadata_only: true
    }
  end

  @doc """
  Collect available metadata from existing AI security processes, then
  correlate it with supplied sensitive resource access metadata.

  Missing processes and unavailable database-backed gateway storage are
  reported in `coverage.collectors`; they do not make correlation fail.
  Network metadata can be supplied with `:network_events` and additional
  already-collected gateway/MCP/interaction/model events with matching option
  names.
  """
  @spec correlate_live([map()], keyword()) :: report()
  def correlate_live(sensitive_accesses, opts \\ []) when is_list(sensitive_accesses) do
    window_ms = positive_integer(opts[:window_ms], @default_window_ms)
    since_ms = latest_timestamp_ms(sensitive_accesses) - window_ms
    since = DateTime.from_unix!(since_ms, :millisecond)

    {gateway, gateway_status} =
      collect(
        AIGateway,
        :list_usage,
        [[limit: opts[:limit] || 1_000, since_ms: since_ms]],
        {:ok, []}
      )

    gateway = unwrap_ok_list(gateway) ++ List.wrap(opts[:gateway_events])

    {mcp, mcp_status} =
      collect(MCPGovernance, :get_audit_log, [[limit: opts[:limit] || 1_000]], [])

    mcp = List.wrap(mcp) ++ List.wrap(opts[:mcp_tool_calls])

    {interactions, interaction_status} =
      collect(
        InteractionMonitor,
        :get_audit_log,
        [[limit: opts[:limit] || 1_000, since: since]],
        []
      )

    interactions = List.wrap(interactions) ++ List.wrap(opts[:interaction_events])
    model_ids = (opts[:model_ids] || inferred_model_ids(gateway)) |> Enum.uniq()

    {models, model_status} = collect_model_events(model_ids, since, opts[:limit] || 1_000)
    models = models ++ List.wrap(opts[:model_invocations])

    report =
      correlate(
        %{
          sensitive_accesses: sensitive_accesses,
          gateway_events: gateway,
          mcp_tool_calls: mcp,
          interaction_events: interactions,
          model_invocations: models,
          network_events: List.wrap(opts[:network_events])
        },
        opts
      )

    put_in(report, [:coverage, :collectors], %{
      ai_gateway: gateway_status,
      mcp_governance: mcp_status,
      interaction_monitor: interaction_status,
      model_auditor: model_status
    })
  end

  defp correlate_sensitive_egress(accesses, egress_events, window_ms) do
    for access <- accesses,
        egress <- egress_events,
        correlated?(access, egress, window_ms) do
      category = resource_category(access)
      mcp? = egress.kind == :mcp
      score = if category in ["credentials", "cloud_credentials", "private_key"], do: 95, else: 85

      detection(
        if(mcp?, do: "sensitive_resource_to_mcp_http", else: "sensitive_resource_to_ai_egress"),
        score,
        max(access.timestamp_ms, egress.timestamp_ms),
        shared_entity(access, egress),
        [
          evidence(access, %{resource_category: category, operation: access.operation}),
          evidence(egress, egress_evidence(egress))
        ],
        if(mcp?,
          do:
            "Review and constrain the MCP HTTP tool permission; isolate the originating process if the access was not expected.",
          else:
            "Validate the AI upload and restrict AI egress for the originating identity or process until the sensitive access is explained."
        )
      )
    end
  end

  defp spike_detections(normalized, opts) do
    token_threshold = positive_integer(opts[:token_threshold], @default_token_threshold)
    byte_threshold = positive_integer(opts[:byte_threshold], @default_byte_threshold)
    multiplier = positive_number(opts[:spike_multiplier], @default_spike_multiplier)

    events =
      normalized.gateway_events ++ normalized.model_invocations ++ normalized.interaction_events

    events
    |> Enum.group_by(&entity_for/1)
    |> Enum.reject(fn {entity, _} -> is_nil(entity) end)
    |> Enum.flat_map(fn {entity, group} ->
      sorted = Enum.sort_by(group, & &1.timestamp_ms)

      Enum.with_index(sorted)
      |> Enum.flat_map(fn {event, index} ->
        prior = Enum.take(sorted, index)

        token_spike =
          spike?(event.tokens, Enum.map(prior, & &1.tokens), token_threshold, multiplier)

        byte_spike =
          spike?(event.bytes_sent, Enum.map(prior, & &1.bytes_sent), byte_threshold, multiplier)

        if token_spike or byte_spike do
          score = if token_spike and byte_spike, do: 90, else: 78

          [
            detection(
              "ai_usage_volume_spike",
              score,
              event.timestamp_ms,
              entity,
              [
                evidence(event, %{
                  total_tokens: event.tokens,
                  bytes_sent: event.bytes_sent,
                  token_spike: token_spike,
                  byte_spike: byte_spike
                })
              ],
              "Confirm the AI usage volume with the owner and apply token, request, or egress-byte limits for this identity."
            )
          ]
        else
          []
        end
      end)
    end)
  end

  defp doh_proxy_detections(network_events, ai_egress, window_ms) do
    covert = Enum.filter(network_events, &doh_or_proxy?/1)

    for network <- covert,
        egress <- ai_egress,
        egress.bytes_sent > 0,
        correlated?(network, egress, window_ms) do
      detection(
        "doh_or_proxy_with_ai_upload",
        88,
        max(network.timestamp_ms, egress.timestamp_ms),
        shared_entity(network, egress),
        [
          evidence(network, %{channel: network.channel}),
          evidence(egress, egress_evidence(egress))
        ],
        "Inspect the encrypted DNS or proxy route and require the AI destination to use an approved, attributable egress path."
      )
    end
  end

  defp detection(type, score, timestamp_ms, entity, evidence, recommendation) do
    %{
      id: detection_id(type, evidence),
      type: type,
      severity: severity(score),
      risk_score: score,
      confidence: if(length(evidence) > 1, do: "high", else: "medium"),
      observed_at: iso8601(timestamp_ms),
      entity: entity,
      evidence: evidence,
      recommendation: recommendation,
      mitre_techniques: ["T1567"],
      metadata_only: true,
      payload_capture: false,
      prompt_capture: false
    }
  end

  defp evidence(event, extra) do
    %{
      source: Atom.to_string(event.kind),
      event_id: event.id,
      observed_at: iso8601(event.timestamp_ms)
    }
    |> Map.merge(extra)
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Map.new()
  end

  defp egress_evidence(event) do
    %{
      provider: event.provider,
      domain: event.domain,
      tool_name: event.tool_name,
      bytes_sent: event.bytes_sent,
      total_tokens: event.tokens,
      access_method: event.access_method
    }
  end

  defp recommendations(detections) do
    detections
    |> Enum.map(fn detection ->
      %{
        priority: detection.severity,
        detection_type: detection.type,
        action: detection.recommendation
      }
    end)
    |> Enum.uniq_by(&{&1.detection_type, &1.action})
  end

  defp normalize_events(events, kind) do
    events
    |> List.wrap()
    |> Enum.filter(&is_map/1)
    |> Enum.map(&normalize_event(&1, kind))
  end

  defp normalize_event(event, kind) do
    metadata = map_value(event, :metadata) || %{}
    timestamp = value(event, metadata, [:timestamp_ms, :timestamp, :observed_at, :detected_at])
    path = value(event, metadata, [:path, :file_path, :resource, :resource_name, :filename])

    categories =
      value(event, metadata, [:data_categories, :categories, :classification, :resource_type])

    %{
      kind: kind,
      id: safe_id(value(event, metadata, [:id, :event_id, :trace_id])),
      timestamp_ms: timestamp_ms(timestamp),
      agent_id: safe_scalar(value(event, metadata, [:agent_id, :device_id, :endpoint_id])),
      hostname: safe_scalar(value(event, metadata, [:hostname, :host, :device_name])),
      user_id: safe_scalar(value(event, metadata, [:user_id, :username, :caller_id, :principal])),
      session_id: safe_scalar(value(event, metadata, [:session_id, :trace_id, :correlation_id])),
      process_name: safe_scalar(value(event, metadata, [:process_name, :process])),
      pid: safe_scalar(value(event, metadata, [:pid, :process_id])),
      operation:
        normalize_string(
          value(event, metadata, [:operation, :action, :event_type, :source_event_type])
        ),
      resource_hint: normalize_string(path),
      categories: normalize_list(categories),
      provider: normalize_string(value(event, metadata, [:provider])),
      domain:
        normalize_domain(value(event, metadata, [:domain, :url_host, :host, :destination_domain])),
      access_method:
        normalize_string(value(event, metadata, [:access_method, :transport, :protocol])),
      tool_name: normalize_string(value(event, metadata, [:tool_name, :tool])),
      tokens: token_count(event, metadata),
      bytes_sent:
        numeric(
          value(event, metadata, [
            :bytes_sent,
            :upload_bytes,
            :request_bytes,
            :prompt_length,
            :result_size_bytes
          ])
        ),
      channel:
        normalize_string(
          value(event, metadata, [
            :channel,
            :tunnel,
            :resolver_type,
            :proxy_type,
            :access_method,
            :protocol
          ])
        )
    }
  end

  defp sensitive_access?(event) do
    category = resource_category(event)
    operation = event.operation

    category != "sensitive_resource" or
      Enum.any?(@sensitive_categories, &(&1 in event.categories)) or
      operation in ~w(read open file_read resource_read download access)
  end

  defp resource_category(event) do
    hint = event.resource_hint

    cond do
      Enum.any?(event.categories, &(&1 in ~w(cloud_credentials cloud_credential))) ->
        "cloud_credentials"

      Enum.any?(event.categories, &(&1 in ~w(credentials credential secrets secret))) ->
        "credentials"

      Enum.any?(event.categories, &(&1 in ~w(private_key ssh_key))) ->
        "private_key"

      Regex.match?(
        ~r/(^|[\\\/])\.env(?:\.|$)|aws[\\\/]credentials|application_default_credentials|service[_-]account|azure.*credential|kube[\\\/]config/i,
        hint
      ) ->
        "cloud_credentials"

      Regex.match?(~r/(id_rsa|id_ed25519|\.pem$|\.p12$|\.npmrc$|\.pypirc$)/i, hint) ->
        "private_key"

      Enum.any?(event.categories, &(&1 in @sensitive_categories)) ->
        Enum.find(event.categories, &(&1 in @sensitive_categories))

      true ->
        "sensitive_resource"
    end
  end

  defp ai_egress?(event) do
    event.provider in @ai_providers or Enum.any?(@ai_domains, &domain_matches?(event.domain, &1))
  end

  defp mcp_http_tool?(event) do
    event.kind == :mcp and
      Regex.match?(
        ~r/(http|fetch|request|upload|post|put|curl|webhook|browser|url)/i,
        event.tool_name
      )
  end

  defp doh_or_proxy?(event) do
    Regex.match?(
      ~r/(doh|dns.over.https|https_dns|proxy|socks|tunnel)/i,
      Enum.join([event.channel, event.access_method, event.operation], " ")
    )
  end

  defp correlated?(left, right, window_ms) do
    shared_entity(left, right) != nil and
      right.timestamp_ms >= left.timestamp_ms and
      right.timestamp_ms - left.timestamp_ms <= window_ms
  end

  defp shared_entity(left, right) do
    left_entities = entity_candidates(left)
    Enum.find(left_entities, &(&1 in entity_candidates(right)))
  end

  defp entity_candidates(event) do
    [
      if(present?(event.agent_id), do: "agent:#{event.agent_id}"),
      if(present?(event.session_id), do: "session:#{event.session_id}"),
      if(present?(event.hostname) and present?(event.user_id),
        do: "host_user:#{event.hostname}:#{event.user_id}"
      ),
      if(present?(event.hostname) and present?(event.pid),
        do: "host_pid:#{event.hostname}:#{event.pid}"
      ),
      if(present?(event.user_id), do: "user:#{event.user_id}")
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp entity_for(event) do
    List.first(entity_candidates(event))
  end

  defp spike?(value, prior_values, absolute_threshold, multiplier) do
    prior = Enum.filter(prior_values, &(&1 > 0))
    baseline = median(prior)

    value >= absolute_threshold or
      (baseline > 0 and value >= baseline * multiplier and value - baseline >= 1_000)
  end

  defp median([]), do: 0

  defp median(values) do
    sorted = Enum.sort(values)
    Enum.at(sorted, div(length(sorted) - 1, 2))
  end

  defp collect(module, function, args, fallback) do
    if Process.whereis(module) do
      try do
        {apply(module, function, args), "available"}
      rescue
        _ -> {fallback, "unavailable"}
      catch
        :exit, _ -> {fallback, "unavailable"}
      end
    else
      {fallback, "not_started"}
    end
  end

  defp collect_model_events([], _since, _limit), do: {[], "no_model_ids"}

  defp collect_model_events(model_ids, since, limit) do
    if Process.whereis(ModelAuditor) do
      events =
        Enum.flat_map(model_ids, fn model_id ->
          try do
            ModelAuditor.get_compliance_log(model_id, since: since, limit: limit)
          rescue
            _ -> []
          catch
            :exit, _ -> []
          end
        end)

      {events, "available"}
    else
      {[], "not_started"}
    end
  end

  defp inferred_model_ids(events),
    do: events |> Enum.map(&map_value(&1, :model)) |> Enum.reject(&is_nil/1)

  defp unwrap_ok_list({:ok, events}) when is_list(events), do: events
  defp unwrap_ok_list(_), do: []

  defp source(sources, key), do: map_value(sources, key) || []

  defp value(event, metadata, keys),
    do: Enum.find_value(keys, fn key -> map_value(event, key) || map_value(metadata, key) end)

  defp map_value(map, key) when is_map(map),
    do: Map.get(map, key) || Map.get(map, Atom.to_string(key))

  defp map_value(_, _), do: nil

  defp normalize_list(nil), do: []
  defp normalize_list(value) when is_list(value), do: Enum.map(value, &normalize_string/1)
  defp normalize_list(value), do: [normalize_string(value)]
  defp normalize_string(nil), do: ""

  defp normalize_string(value) when is_atom(value),
    do: value |> Atom.to_string() |> String.downcase()

  defp normalize_string(value) when is_binary(value), do: String.downcase(value)
  defp normalize_string(value), do: to_string(value) |> String.downcase()

  defp normalize_domain(nil), do: ""

  defp normalize_domain(value) do
    value = value |> to_string() |> String.downcase()
    uri = URI.parse(if String.contains?(value, "://"), do: value, else: "//" <> value)
    (uri.host || value) |> String.trim_trailing(".")
  end

  defp domain_matches?(domain, suffix),
    do: domain == suffix or String.ends_with?(domain, "." <> suffix)

  defp present?(value), do: value not in [nil, ""]

  defp safe_scalar(value) when is_binary(value) or is_number(value) or is_atom(value),
    do: to_string(value)

  defp safe_scalar(_), do: nil
  defp safe_id(nil), do: nil
  defp safe_id(value), do: safe_scalar(value)

  defp numeric(value) when is_integer(value) and value > 0, do: value
  defp numeric(value) when is_float(value) and value > 0, do: trunc(value)

  defp numeric(value) when is_binary(value) do
    case Integer.parse(value) do
      {number, _} when number > 0 -> number
      _ -> 0
    end
  end

  defp numeric(_), do: 0

  defp token_count(event, metadata) do
    case numeric(value(event, metadata, [:total_tokens])) do
      0 ->
        numeric(value(event, metadata, [:prompt_tokens, :input_tokens])) +
          numeric(value(event, metadata, [:completion_tokens, :output_tokens]))

      total ->
        total
    end
  end

  defp timestamp_ms(%DateTime{} = value), do: DateTime.to_unix(value, :millisecond)

  defp timestamp_ms(%NaiveDateTime{} = value),
    do: value |> DateTime.from_naive!("Etc/UTC") |> DateTime.to_unix(:millisecond)

  defp timestamp_ms(value) when is_integer(value) and value < 10_000_000_000, do: value * 1_000
  defp timestamp_ms(value) when is_integer(value), do: value

  defp timestamp_ms(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _} -> DateTime.to_unix(datetime, :millisecond)
      _ -> numeric(value)
    end
  end

  defp timestamp_ms(_), do: System.system_time(:millisecond)

  defp latest_timestamp_ms([]), do: System.system_time(:millisecond)

  defp latest_timestamp_ms(events) do
    events
    |> Enum.map(fn event ->
      timestamp_ms(map_value(event, :timestamp_ms) || map_value(event, :timestamp))
    end)
    |> Enum.max(fn -> System.system_time(:millisecond) end)
  end

  defp iso8601(timestamp_ms),
    do: timestamp_ms |> DateTime.from_unix!(:millisecond) |> DateTime.to_iso8601()

  defp positive_integer(value, _default) when is_integer(value) and value > 0, do: value
  defp positive_integer(_, default), do: default
  defp positive_number(value, _default) when is_number(value) and value > 0, do: value
  defp positive_number(_, default), do: default
  defp severity(score) when score >= 90, do: "critical"
  defp severity(score) when score >= 75, do: "high"
  defp severity(_), do: "medium"

  defp detection_id(type, evidence) do
    digest =
      :crypto.hash(:sha256, :erlang.term_to_binary({type, evidence}))
      |> Base.encode16(case: :lower)

    "ai-exfil-" <> binary_part(digest, 0, 16)
  end

  defp detection_fingerprint(detection),
    do: {detection.type, detection.entity, Enum.map(detection.evidence, &Map.get(&1, :event_id))}
end
