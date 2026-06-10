defmodule TamanduaServer.AISecurity.EndpointUsage do
  @moduledoc """
  Converts endpoint telemetry into metadata-only AI usage events.

  This module is intentionally conservative: it uses DNS/network/process
  metadata only and never forwards prompt, response, body, header, cookie, or
  credential material to the AI Gateway.
  """

  require Logger

  alias TamanduaServer.AISecurity.{AIGateway, Enforcement}

  @ai_event_types ~w(dns_query network_connect network_close network llm_request inference_request)

  @provider_patterns [
    {"api.openai.com", "openai", "remote_ai_api", 95},
    {"chat.openai.com", "openai", "remote_ai_browser", 95},
    {"chatgpt.com", "openai", "remote_ai_browser", 95},
    {"platform.openai.com", "openai", "remote_ai_console", 90},
    {"api.anthropic.com", "anthropic", "remote_ai_api", 95},
    {"claude.ai", "anthropic", "remote_ai_browser", 95},
    {"generativelanguage.googleapis.com", "google", "remote_ai_api", 95},
    {"ai.google.dev", "google", "remote_ai_console", 90},
    {"gemini.google.com", "google", "remote_ai_browser", 95},
    {"bard.google.com", "google", "remote_ai_browser", 85},
    {"copilot.microsoft.com", "microsoft", "remote_ai_browser", 95},
    {"openai.azure.com", "microsoft", "remote_ai_api", 90},
    {"api.cognitive.microsoft.com", "microsoft", "remote_ai_api", 85},
    {"huggingface.co", "huggingface", "remote_ai_service", 85},
    {"api-inference.huggingface.co", "huggingface", "remote_ai_api", 95},
    {"api.cohere.ai", "cohere", "remote_ai_api", 95},
    {"cohere.com", "cohere", "remote_ai_service", 80},
    {"api.replicate.com", "replicate", "remote_ai_api", 95},
    {"replicate.com", "replicate", "remote_ai_service", 80},
    {"api.mistral.ai", "mistral", "remote_ai_api", 95},
    {"api.groq.com", "groq", "remote_ai_api", 95},
    {"console.groq.com", "groq", "remote_ai_console", 85},
    {"openrouter.ai", "openrouter", "remote_ai_gateway", 90},
    {"api.openrouter.ai", "openrouter", "remote_ai_gateway", 95},
    {"api.perplexity.ai", "perplexity", "remote_ai_api", 95},
    {"perplexity.ai", "perplexity", "remote_ai_browser", 90},
    {"bedrock-runtime.", "aws_bedrock", "remote_ai_api", 85}
  ]

  @local_inference_ports %{
    11434 => {"ollama", "local_inference", 80},
    8000 => {"vllm_or_fastapi_ml", "local_inference", 70},
    8080 => {"llama_cpp", "local_inference", 70},
    8081 => {"localai", "local_inference", 75},
    5000 => {"text_generation_inference", "local_inference", 70},
    7860 => {"gradio", "local_inference", 65},
    8501 => {"streamlit_ml", "local_inference", 60},
    8888 => {"jupyter", "local_ai_workspace", 55}
  }

  @sensitive_keys ~w(
    prompt prompts message messages body request_body response response_body content
    input output text completion choices authorization api_key access_token refresh_token
    password secret credential headers cookie cookies
  )

  @doc """
  Builds a metadata-only AI Gateway event from endpoint telemetry.
  """
  @spec build_gateway_event(map()) :: {:ok, map()} | :ignore
  def build_gateway_event(event) when is_map(event) do
    event_type = event |> field(:event_type) |> normalize_type()
    payload = field(event, :payload) || %{}
    metadata = field(event, :metadata) || %{}

    with true <- event_type in @ai_event_types or truthy?(field(metadata, :ai_usage)),
         {:ok, classification} <- classify(event_type, payload, metadata) do
      {:ok, gateway_attrs(event, payload, metadata, event_type, classification)}
    else
      _ -> :ignore
    end
  end

  def build_gateway_event(_), do: :ignore

  @doc """
  Sends endpoint-derived AI usage to the AI Gateway if the gateway is running.
  """
  @spec ingest_telemetry_event(map()) :: :ok | :ignore
  def ingest_telemetry_event(event) do
    with {:ok, attrs} <- build_gateway_event(event),
         pid when is_pid(pid) <- Process.whereis(AIGateway) do
      case AIGateway.ingest_event(attrs) do
        {:ok, event} ->
          maybe_enforce(event)
          :ok

        {:error, reason} ->
          Logger.debug("[EndpointUsage] AI Gateway ingest rejected event: #{inspect(reason)}")
          :ignore
      end
    else
      _ -> :ignore
    end
  rescue
    e ->
      Logger.debug("[EndpointUsage] AI Gateway ingest skipped: #{Exception.message(e)}")
      :ignore
  catch
    _, _ -> :ignore
  end

  defp maybe_enforce(event) do
    Task.start(fn -> Enforcement.enforce_event(event) end)
    :ok
  rescue
    e ->
      Logger.debug("[EndpointUsage] AI endpoint enforcement skipped: #{Exception.message(e)}")
      :ok
  end

  defp gateway_attrs(event, payload, metadata, event_type, classification) do
    domain = classification[:domain] || best_domain(event, payload)

    %{
      id: "endpoint:" <> to_string(field(event, :event_id) || Ecto.UUID.generate()),
      timestamp_ms: field(event, :timestamp),
      source: "endpoint_telemetry",
      integration_id: "tamandua_agent",
      organization_id: field(event, :organization_id),
      agent_id: field(event, :agent_id),
      hostname: field(event, :hostname) || field(payload, :hostname),
      app: field(payload, :app) || field(payload, :application),
      provider: classification.provider,
      domain: domain,
      access_method: access_method(event_type, classification.category),
      process_name: field(payload, :process_name) || field(payload, :name),
      process_path: field(payload, :process_path) || field(payload, :path),
      pid: field(payload, :pid),
      request_count: 1,
      bytes_sent: int_field(payload, :bytes_sent) || int_field(payload, :bytes_out) || 0,
      bytes_received: int_field(payload, :bytes_received) || int_field(payload, :bytes_in) || 0,
      risk_score: risk_score(classification),
      risk_level: risk_level(classification),
      classification: classification.category,
      verdict: "observed",
      trace_id: field(event, :event_id),
      metadata: %{
        "source_event_type" => event_type,
        "ai_signal" => field(metadata, :ai_signal) || classification.signal,
        "confidence" => classification.confidence,
        "remote_ip" => field(payload, :remote_ip),
        "remote_port" => field(payload, :remote_port),
        "local_ip" => field(payload, :local_ip),
        "local_port" => field(payload, :local_port),
        "protocol" => field(payload, :protocol),
        "direction" => field(payload, :direction),
        "content_inspection" => false,
        "prompt_capture" => false
      }
    }
    |> reject_nil_values()
  end

  defp classify(_event_type, payload, metadata) do
    cond do
      truthy?(field(metadata, :ai_usage)) ->
        {:ok,
         %{
           provider: field(metadata, :ai_provider) || "unknown_ai",
           category: field(metadata, :ai_category) || "endpoint_ai_usage",
           confidence: parse_int(field(metadata, :ai_confidence), 70),
           signal: field(metadata, :ai_signal) || "agent_metadata",
           domain: best_domain(%{}, payload)
         }}

      domain = best_domain(%{}, payload) ->
        classify_domain(domain)

      local = classify_local_port(field(payload, :remote_ip), field(payload, :remote_port)) ->
        {:ok, local}

      true ->
        :ignore
    end
  end

  defp classify_domain(domain) when is_binary(domain) do
    normalized = normalize_domain(domain)

    @provider_patterns
    |> Enum.find(fn {pattern, _provider, _category, _confidence} ->
      normalized == pattern or String.ends_with?(normalized, "." <> pattern) or
        String.contains?(normalized, pattern)
    end)
    |> case do
      {_, provider, category, confidence} ->
        {:ok,
         %{
           provider: provider,
           category: category,
           confidence: confidence,
           signal: "domain",
           domain: normalized
         }}

      nil ->
        :ignore
    end
  end

  defp classify_domain(_), do: :ignore

  defp classify_local_port(remote_ip, remote_port) do
    port = parse_int(remote_port, nil)

    if local_address?(remote_ip) and is_integer(port) do
      case Map.get(@local_inference_ports, port) do
        {provider, category, confidence} ->
          %{
            provider: provider,
            category: category,
            confidence: confidence,
            signal: "local_port",
            domain: "#{remote_ip}:#{port}"
          }

        nil ->
          nil
      end
    end
  end

  defp best_domain(event, payload) do
    [
      field(event, :remote_domain),
      field(payload, :remote_domain),
      field(payload, :domain),
      field(payload, :query),
      field(payload, :host),
      field(payload, :sni),
      field(payload, :tls_sni),
      domain_candidate(payload)
    ]
    |> Enum.find(&present_string?/1)
    |> normalize_domain_or_nil()
  end

  defp domain_candidate(payload) do
    case field(payload, :domain_candidates) do
      [first | _] -> first
      _ -> nil
    end
  end

  defp access_method("dns_query", _category), do: "endpoint_dns"
  defp access_method("network_connect", "local_inference"), do: "endpoint_local_network"
  defp access_method("network", "local_inference"), do: "endpoint_local_network"
  defp access_method("llm_request", _category), do: "endpoint_llm_metadata"
  defp access_method("inference_request", _category), do: "endpoint_inference_metadata"
  defp access_method(_event_type, _category), do: "endpoint_network"

  defp risk_score(%{category: "local_inference"}), do: 35
  defp risk_score(%{category: "local_ai_workspace"}), do: 30
  defp risk_score(%{category: "remote_ai_api"}), do: 45
  defp risk_score(%{category: "remote_ai_gateway"}), do: 40
  defp risk_score(%{category: "remote_ai_browser"}), do: 30
  defp risk_score(_), do: 25

  defp risk_level(%{} = classification) do
    case risk_score(classification) do
      score when score >= 70 -> "high"
      score when score >= 40 -> "medium"
      score when score >= 20 -> "low"
      _ -> "info"
    end
  end

  defp field(map, key) when is_map(map), do: Map.get(map, key) || Map.get(map, to_string(key))
  defp field(_, _), do: nil

  defp normalize_type(value) when is_atom(value),
    do: value |> Atom.to_string() |> normalize_type()

  defp normalize_type(value) when is_binary(value),
    do: value |> String.downcase() |> String.trim()

  defp normalize_type(_), do: ""

  defp normalize_domain_or_nil(value) when is_binary(value), do: normalize_domain(value)
  defp normalize_domain_or_nil(_), do: nil

  defp normalize_domain(value),
    do: value |> String.trim() |> String.trim_trailing(".") |> String.downcase()

  defp local_address?(value) when value in ["127.0.0.1", "::1", "localhost"], do: true
  defp local_address?(_), do: false

  defp present_string?(value), do: is_binary(value) and String.trim(value) != ""

  defp int_field(map, key), do: parse_int(field(map, key), nil)

  defp parse_int(value, _default) when is_integer(value), do: value

  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      _ -> default
    end
  end

  defp parse_int(_, default), do: default

  defp truthy?(value), do: value in [true, "true", "1", 1]

  defp reject_nil_values(map) do
    Map.new(map, fn
      {:metadata, metadata} -> {:metadata, reject_nil_values(metadata)}
      {key, value} -> {key, value}
    end)
    |> Enum.reject(fn
      {_key, nil} -> true
      {_key, ""} -> true
      {key, _value} when key in @sensitive_keys -> true
      _ -> false
    end)
    |> Map.new()
  end
end
