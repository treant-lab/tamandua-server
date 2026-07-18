defmodule TamanduaServer.AI.LLMClient do
  @moduledoc """
  LLM client for OpenAI and Anthropic APIs.

  Provides a unified interface for chat completions across multiple LLM providers,
  used for natural language processing tasks like query translation, alert
  summarization, and threat hunting assistance.

  ## Configuration

  Configure via environment variables:
  - `OPENAI_API_KEY` - OpenAI API key
  - `ANTHROPIC_API_KEY` - Anthropic API key

  Or application config:

      config :tamandua_server, TamanduaServer.AI.LLMClient,
        provider: :openai,
        model: "gpt-4o-mini",
        openai_api_key: "sk-...",
        anthropic_api_key: "sk-ant-...",
        timeout: 60_000,
        max_retries: 3

  ## Usage

      # Basic chat completion
      messages = [
        %{role: "system", content: "You are a security analyst assistant."},
        %{role: "user", content: "Translate this to TQL: show powershell from last 24h"}
      ]

      {:ok, response} = LLMClient.chat_completion(messages)

      # With options
      {:ok, response} = LLMClient.chat_completion(messages,
        model: "gpt-4o",
        temperature: 0.1,
        max_tokens: 1000
      )

      # Translate natural language to TQL
      {:ok, tql} = LLMClient.translate_to_tql(
        "show me all powershell executions from the last 24 hours",
        %{tables: ["process", "network"], fields: [...]}
      )

  ## Supported Models

  OpenAI:
  - gpt-4o-mini (default, cost-effective)
  - gpt-4o (more capable)
  - gpt-4-turbo
  - gpt-3.5-turbo

  Anthropic:
  - claude-3-haiku-20240307 (fast, cheap)
  - claude-3-sonnet-20240229 (balanced)
  - claude-3-opus-20240229 (most capable)
  - claude-3-5-sonnet-20241022 (latest)

  ## Telemetry

  Emits the following telemetry events:
  - `[:tamandua, :ai, :llm, :request, :start]`
  - `[:tamandua, :ai, :llm, :request, :stop]`
  - `[:tamandua, :ai, :llm, :request, :exception]`

  Measurements include latency_ms, tokens_in, tokens_out, and cost_usd.
  """

  require Logger

  alias TamanduaServer.AI.CostGovernor
  alias TamanduaServer.Hunting.QueryLanguage

  # Default configuration
  @default_provider :openai
  @default_model "gpt-4o-mini"
  @default_timeout 60_000
  @default_max_retries 3
  @default_retry_delay 1_000
  @default_max_tokens 4096
  @default_temperature 0.7

  # Rate limit retry config
  @rate_limit_codes [429, 529]
  @server_error_codes [500, 502, 503, 504]

  # API endpoints
  @openai_chat_url "https://api.openai.com/v1/chat/completions"
  @anthropic_messages_url "https://api.anthropic.com/v1/messages"
  @anthropic_api_version "2023-06-01"

  # ============================================================================
  # Type Definitions
  # ============================================================================

  @type message :: %{
    role: String.t(),
    content: String.t()
  }

  @type chat_response :: %{
    content: String.t(),
    model: String.t(),
    provider: atom(),
    tokens_in: non_neg_integer(),
    tokens_out: non_neg_integer(),
    finish_reason: String.t() | nil,
    latency_ms: non_neg_integer()
  }

  @type completion_opts :: [
    provider: atom(),
    model: String.t(),
    temperature: float(),
    max_tokens: pos_integer(),
    timeout: pos_integer(),
    max_retries: non_neg_integer(),
    user_id: String.t(),
    session_id: String.t()
  ]

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Send a chat completion request to the configured LLM provider.

  ## Parameters

  - `messages` - List of message maps with :role and :content keys
  - `opts` - Optional configuration overrides

  ## Options

  - `:provider` - `:openai` or `:anthropic` (default from config)
  - `:model` - Model identifier (default: "gpt-4o-mini")
  - `:temperature` - Sampling temperature 0.0-2.0 (default: 0.7)
  - `:max_tokens` - Maximum tokens in response (default: 4096)
  - `:timeout` - Request timeout in ms (default: 60000)
  - `:max_retries` - Number of retry attempts (default: 3)
  - `:user_id` - User ID for cost tracking
  - `:session_id` - Session ID for cost tracking

  ## Returns

  - `{:ok, response}` - Successful completion with content and metadata
  - `{:error, reason}` - Error with descriptive message

  ## Examples

      messages = [
        %{role: "system", content: "You are a helpful assistant."},
        %{role: "user", content: "Hello!"}
      ]

      {:ok, %{content: content}} = LLMClient.chat_completion(messages)

      # Use Anthropic instead
      {:ok, response} = LLMClient.chat_completion(messages,
        provider: :anthropic,
        model: "claude-3-haiku-20240307"
      )
  """
  @spec chat_completion([message()], completion_opts()) :: {:ok, chat_response()} | {:error, String.t()}
  def chat_completion(messages, opts \\ []) when is_list(messages) do
    start_time = System.monotonic_time(:millisecond)
    provider = get_provider(opts)
    model = get_model(opts, provider)

    # Emit telemetry start event
    :telemetry.execute(
      [:tamandua, :ai, :llm, :request, :start],
      %{system_time: System.system_time()},
      %{provider: provider, model: model, message_count: length(messages)}
    )

    result = do_chat_completion(messages, provider, model, opts, 0)

    # Calculate latency
    latency_ms = System.monotonic_time(:millisecond) - start_time

    # Emit telemetry and track costs
    case result do
      {:ok, response} ->
        response = Map.put(response, :latency_ms, latency_ms)

        :telemetry.execute(
          [:tamandua, :ai, :llm, :request, :stop],
          %{
            latency_ms: latency_ms,
            tokens_in: response.tokens_in,
            tokens_out: response.tokens_out
          },
          %{
            provider: provider,
            model: model,
            finish_reason: response.finish_reason
          }
        )

        # Track cost with CostGovernor if available
        track_cost(response, opts)

        {:ok, response}

      {:error, reason} = error ->
        :telemetry.execute(
          [:tamandua, :ai, :llm, :request, :exception],
          %{latency_ms: latency_ms},
          %{provider: provider, model: model, error: reason}
        )

        error
    end
  end

  @doc """
  Translate a natural language query to TQL (Tamandua Query Language).

  Uses the LLM to understand the user's intent and generate a valid TQL query
  that can be executed against ClickHouse.

  ## Parameters

  - `natural_language_query` - The user's query in plain English
  - `schema_context` - Schema information to help the LLM generate correct queries

  ## Schema Context

  The schema context should include:
  - `:tables` - Available table prefixes (process, file, network, dns, registry, alert)
  - `:fields` - Field mappings with descriptions
  - `:operators` - Available operators
  - `:examples` - Example TQL queries

  ## Returns

  - `{:ok, %{tql: query, explanation: text}}` - Successfully translated query
  - `{:error, reason}` - Translation failed

  ## Example

      schema = %{
        tables: ["process", "network", "file"],
        fields: QueryLanguage.field_mappings(),
        examples: [
          {"show powershell", "process.name = 'powershell.exe'"},
          {"network to port 4444", "network.dst_port = 4444"}
        ]
      }

      {:ok, result} = LLMClient.translate_to_tql(
        "find all processes that connected to suspicious ports after 6pm",
        schema
      )

      result.tql
      # => "process.name != '' AND network.dst_port IN (4444, 5555, 8080) | where timestamp > ago(24h)"
  """
  @spec translate_to_tql(String.t(), map()) :: {:ok, map()} | {:error, String.t()}
  def translate_to_tql(natural_language_query, schema_context \\ %{}) when is_binary(natural_language_query) do
    # Build the system prompt with TQL schema information
    system_prompt = build_tql_system_prompt(schema_context)

    # Build the user prompt
    user_prompt = """
    Translate this natural language query to TQL:

    "#{natural_language_query}"

    Respond with ONLY the TQL query, no explanation or markdown formatting.
    """

    messages = [
      %{role: "system", content: system_prompt},
      %{role: "user", content: user_prompt}
    ]

    case chat_completion(messages, temperature: 0.1, max_tokens: 500) do
      {:ok, %{content: content}} ->
        # Clean up the response
        tql = content
        |> String.trim()
        |> String.replace(~r/^```\w*\n?/, "")
        |> String.replace(~r/\n?```$/, "")
        |> String.trim()

        # Validate the generated TQL
        case QueryLanguage.validate(tql) do
          :ok ->
            {:ok, %{
              tql: tql,
              natural_query: natural_language_query,
              valid: true
            }}

          {:error, parse_error} ->
            # If validation fails, return the query anyway with a warning
            Logger.warning("[LLMClient] Generated TQL failed validation: #{parse_error}")
            {:ok, %{
              tql: tql,
              natural_query: natural_language_query,
              valid: false,
              validation_error: parse_error
            }}
        end

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Check if the LLM client is configured and ready to use.

  Returns `{:ok, provider}` if configured, `{:error, reason}` otherwise.
  """
  @spec health_check() :: {:ok, atom()} | {:error, String.t()}
  def health_check do
    provider = get_provider([])

    case get_api_key(provider) do
      nil ->
        {:error, "No API key configured for #{provider}"}

      _key ->
        # Optionally do a lightweight request to verify connectivity
        {:ok, provider}
    end
  end

  @doc """
  Get the currently configured provider and model.
  """
  @spec get_config() :: map()
  def get_config do
    provider = get_provider([])
    %{
      provider: provider,
      model: get_model([], provider),
      openai_configured: get_api_key(:openai) != nil,
      anthropic_configured: get_api_key(:anthropic) != nil,
      timeout: get_config_value(:timeout, @default_timeout),
      max_retries: get_config_value(:max_retries, @default_max_retries)
    }
  end

  # ============================================================================
  # Private Implementation
  # ============================================================================

  defp do_chat_completion(messages, provider, model, opts, attempt) do
    max_retries = Keyword.get(opts, :max_retries, get_config_value(:max_retries, @default_max_retries))

    case make_request(messages, provider, model, opts) do
      {:ok, _} = success ->
        success

      {:error, {:rate_limited, retry_after}} when attempt < max_retries ->
        Logger.warning("[LLMClient] Rate limited, retrying in #{retry_after}ms (attempt #{attempt + 1}/#{max_retries})")
        Process.sleep(retry_after)
        do_chat_completion(messages, provider, model, opts, attempt + 1)

      {:error, {:server_error, status}} when attempt < max_retries ->
        delay = calculate_backoff(attempt)
        Logger.warning("[LLMClient] Server error #{status}, retrying in #{delay}ms (attempt #{attempt + 1}/#{max_retries})")
        Process.sleep(delay)
        do_chat_completion(messages, provider, model, opts, attempt + 1)

      {:error, _} = error ->
        error
    end
  end

  defp make_request(messages, :openai, model, opts) do
    case get_api_key(:openai) do
      nil ->
        {:error, "OPENAI_API_KEY not configured"}

      api_key ->
        make_openai_request(messages, model, api_key, opts)
    end
  end

  defp make_request(messages, :anthropic, model, opts) do
    case get_api_key(:anthropic) do
      nil ->
        {:error, "ANTHROPIC_API_KEY not configured"}

      api_key ->
        make_anthropic_request(messages, model, api_key, opts)
    end
  end

  defp make_request(_messages, provider, _model, _opts) do
    {:error, "Unsupported provider: #{provider}"}
  end

  # OpenAI API request
  defp make_openai_request(messages, model, api_key, opts) do
    timeout = Keyword.get(opts, :timeout, get_config_value(:timeout, @default_timeout))
    temperature = Keyword.get(opts, :temperature, @default_temperature)
    max_tokens = Keyword.get(opts, :max_tokens, @default_max_tokens)

    body = %{
      model: model,
      messages: normalize_messages_for_openai(messages),
      temperature: temperature,
      max_tokens: max_tokens
    }

    headers = [
      {"authorization", "Bearer #{api_key}"},
      {"content-type", "application/json"}
    ]

    case Req.post(@openai_chat_url,
      json: body,
      headers: headers,
      receive_timeout: timeout,
      connect_options: [timeout: 10_000]
    ) do
      {:ok, %{status: 200, body: response_body}} ->
        parse_openai_response(response_body, model)

      {:ok, %{status: status, body: body}} when status in @rate_limit_codes ->
        retry_after = extract_retry_after(body) || @default_retry_delay
        {:error, {:rate_limited, retry_after}}

      {:ok, %{status: status}} when status in @server_error_codes ->
        {:error, {:server_error, status}}

      {:ok, %{status: status, body: body}} ->
        error_msg = extract_error_message(body, status)
        {:error, "OpenAI API error (#{status}): #{error_msg}"}

      {:error, %Req.TransportError{reason: :timeout}} ->
        {:error, "Request timed out after #{timeout}ms"}

      {:error, %Req.TransportError{reason: reason}} ->
        {:error, "Connection error: #{inspect(reason)}"}

      {:error, reason} ->
        {:error, "Request failed: #{inspect(reason)}"}
    end
  end

  # Anthropic API request
  defp make_anthropic_request(messages, model, api_key, opts) do
    timeout = Keyword.get(opts, :timeout, get_config_value(:timeout, @default_timeout))
    temperature = Keyword.get(opts, :temperature, @default_temperature)
    max_tokens = Keyword.get(opts, :max_tokens, @default_max_tokens)

    {system_content, user_messages} = extract_system_message(messages)

    body = %{
      model: model,
      messages: normalize_messages_for_anthropic(user_messages),
      max_tokens: max_tokens,
      temperature: temperature
    }

    # Add system prompt if present
    body = if system_content do
      Map.put(body, :system, system_content)
    else
      body
    end

    headers = [
      {"x-api-key", api_key},
      {"anthropic-version", @anthropic_api_version},
      {"content-type", "application/json"}
    ]

    case Req.post(@anthropic_messages_url,
      json: body,
      headers: headers,
      receive_timeout: timeout,
      connect_options: [timeout: 10_000]
    ) do
      {:ok, %{status: 200, body: response_body}} ->
        parse_anthropic_response(response_body, model)

      {:ok, %{status: status, body: body}} when status in @rate_limit_codes ->
        retry_after = extract_retry_after(body) || @default_retry_delay
        {:error, {:rate_limited, retry_after}}

      {:ok, %{status: status}} when status in @server_error_codes ->
        {:error, {:server_error, status}}

      {:ok, %{status: status, body: body}} ->
        error_msg = extract_error_message(body, status)
        {:error, "Anthropic API error (#{status}): #{error_msg}"}

      {:error, %Req.TransportError{reason: :timeout}} ->
        {:error, "Request timed out after #{timeout}ms"}

      {:error, %Req.TransportError{reason: reason}} ->
        {:error, "Connection error: #{inspect(reason)}"}

      {:error, reason} ->
        {:error, "Request failed: #{inspect(reason)}"}
    end
  end

  # Parse OpenAI response
  defp parse_openai_response(body, model) when is_map(body) do
    case body do
      %{"choices" => [%{"message" => %{"content" => content}} | _]} ->
        usage = Map.get(body, "usage", %{})
        finish_reason = get_in(body, ["choices", Access.at(0), "finish_reason"])

        {:ok, %{
          content: content || "",
          model: model,
          provider: :openai,
          tokens_in: Map.get(usage, "prompt_tokens", 0),
          tokens_out: Map.get(usage, "completion_tokens", 0),
          finish_reason: finish_reason,
          latency_ms: 0  # Will be set by caller
        }}

      _ ->
        {:error, "Invalid OpenAI response format"}
    end
  end

  defp parse_openai_response(body, _model) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, decoded} -> parse_openai_response(decoded, nil)
      {:error, _} -> {:error, "Failed to parse OpenAI response"}
    end
  end

  defp parse_openai_response(_, _), do: {:error, "Invalid OpenAI response"}

  # Parse Anthropic response
  defp parse_anthropic_response(body, model) when is_map(body) do
    case body do
      %{"content" => [%{"text" => text} | _]} ->
        usage = Map.get(body, "usage", %{})

        {:ok, %{
          content: text || "",
          model: model,
          provider: :anthropic,
          tokens_in: Map.get(usage, "input_tokens", 0),
          tokens_out: Map.get(usage, "output_tokens", 0),
          finish_reason: Map.get(body, "stop_reason"),
          latency_ms: 0  # Will be set by caller
        }}

      %{"content" => []} ->
        {:ok, %{
          content: "",
          model: model,
          provider: :anthropic,
          tokens_in: 0,
          tokens_out: 0,
          finish_reason: Map.get(body, "stop_reason"),
          latency_ms: 0
        }}

      _ ->
        {:error, "Invalid Anthropic response format"}
    end
  end

  defp parse_anthropic_response(body, model) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, decoded} -> parse_anthropic_response(decoded, model)
      {:error, _} -> {:error, "Failed to parse Anthropic response"}
    end
  end

  defp parse_anthropic_response(_, _), do: {:error, "Invalid Anthropic response"}

  # Message normalization
  defp normalize_messages_for_openai(messages) do
    Enum.map(messages, fn msg ->
      %{
        "role" => to_string(Map.get(msg, :role, Map.get(msg, "role", "user"))),
        "content" => to_string(Map.get(msg, :content, Map.get(msg, "content", "")))
      }
    end)
  end

  defp normalize_messages_for_anthropic(messages) do
    messages
    |> Enum.reject(fn msg ->
      role = Map.get(msg, :role, Map.get(msg, "role", ""))
      role == "system" or role == :system
    end)
    |> Enum.map(fn msg ->
      %{
        "role" => to_string(Map.get(msg, :role, Map.get(msg, "role", "user"))),
        "content" => to_string(Map.get(msg, :content, Map.get(msg, "content", "")))
      }
    end)
  end

  defp extract_system_message(messages) do
    system_msg = Enum.find(messages, fn msg ->
      role = Map.get(msg, :role, Map.get(msg, "role", ""))
      role == "system" or role == :system
    end)

    system_content = if system_msg do
      Map.get(system_msg, :content, Map.get(system_msg, "content"))
    else
      nil
    end

    other_messages = Enum.reject(messages, fn msg ->
      role = Map.get(msg, :role, Map.get(msg, "role", ""))
      role == "system" or role == :system
    end)

    {system_content, other_messages}
  end

  # Error extraction
  defp extract_error_message(body, status) when is_map(body) do
    body["error"]["message"] ||
      body["error"] ||
      body["message"] ||
      body["detail"] ||
      "HTTP #{status}"
  end

  defp extract_error_message(body, _status) when is_binary(body), do: String.slice(body, 0, 200)
  defp extract_error_message(_, status), do: "HTTP #{status}"

  defp extract_retry_after(body) when is_map(body) do
    case body["error"]["retry_after"] || body["retry_after"] do
      nil -> nil
      seconds when is_number(seconds) -> trunc(seconds * 1000)
      _ -> nil
    end
  end

  defp extract_retry_after(_), do: nil

  # Exponential backoff with jitter
  defp calculate_backoff(attempt) do
    base_delay = @default_retry_delay * :math.pow(2, attempt)
    jitter = :rand.uniform(trunc(base_delay * 0.1))
    trunc(base_delay + jitter)
  end

  # Configuration helpers
  defp get_provider(opts) do
    Keyword.get(opts, :provider) ||
      get_config_value(:provider, @default_provider)
  end

  defp get_model(opts, provider) do
    Keyword.get(opts, :model) ||
      get_config_value(:model, default_model_for_provider(provider))
  end

  defp default_model_for_provider(:openai), do: @default_model
  defp default_model_for_provider(:anthropic), do: "claude-3-haiku-20240307"
  defp default_model_for_provider(_), do: @default_model

  defp get_api_key(:openai) do
    get_config_value(:openai_api_key) ||
      System.get_env("OPENAI_API_KEY")
  end

  defp get_api_key(:anthropic) do
    get_config_value(:anthropic_api_key) ||
      System.get_env("ANTHROPIC_API_KEY")
  end

  defp get_api_key(_), do: nil

  defp get_config_value(key, default \\ nil) do
    Application.get_env(:tamandua_server, __MODULE__, [])
    |> Keyword.get(key, default)
  end

  # Cost tracking integration
  defp track_cost(response, opts) do
    # Only track if CostGovernor is available and we have an agent_id
    if function_exported?(CostGovernor, :track_inference, 6) do
      agent_id = Keyword.get(opts, :agent_id, "llm_client")
      user_id = Keyword.get(opts, :user_id)
      session_id = Keyword.get(opts, :session_id)

      try do
        CostGovernor.track_inference(
          agent_id,
          response.model,
          response.tokens_in,
          response.tokens_out,
          response.latency_ms,
          user_id: user_id,
          session_id: session_id
        )
      rescue
        _ -> :ok  # Silently ignore if CostGovernor is not running
      end
    end

    :ok
  end

  # TQL translation helpers
  defp build_tql_system_prompt(schema_context) do
    tables = Map.get(schema_context, :tables, ["process", "file", "network", "dns", "registry", "alert"])
    fields = Map.get(schema_context, :fields, QueryLanguage.field_mappings())
    operators = Map.get(schema_context, :operators, QueryLanguage.operators())
    examples = Map.get(schema_context, :examples, default_tql_examples())

    fields_doc = fields
    |> Enum.take(30)  # Limit to avoid token overflow
    |> Enum.map_join("\n", fn {tql_name, {_table, _col}} -> "  - #{tql_name}" end)

    examples_doc = examples
    |> Enum.map_join("\n", fn {query, tql} -> "  Q: \"#{query}\"\n  TQL: #{tql}" end)

    operators_doc = operators
    |> Enum.map_join(", ", fn {op, _} -> op end)

    """
    You are a TQL (Tamandua Query Language) translator for an EDR (Endpoint Detection and Response) system.

    TQL is a query language that compiles to ClickHouse SQL. It uses `table.field` references and pipe operators.

    ## Available Tables
    #{Enum.join(tables, ", ")}

    ## Common Fields
    #{fields_doc}

    ## Operators
    #{operators_doc}

    ## Pipe Operators
    | where <expr>          - post-aggregation filter
    | count by f1, f2       - GROUP BY with COUNT
    | sort field [asc|desc] - ORDER BY
    | limit N               - LIMIT
    | timeline field        - timeline view

    ## Time Functions
    ago(24h), ago(7d), ago(1h30m) - relative time

    ## Examples
    #{examples_doc}

    ## Rules
    1. Use table.field format (e.g., process.name, network.dst_ip)
    2. String values must be quoted with double quotes
    3. Use AND/OR for boolean logic, parentheses for grouping
    4. Common patterns: CONTAINS, STARTS_WITH, ENDS_WITH, MATCHES (glob), REGEX
    5. For IP ranges, use: network.dst_ip IN CIDR "10.0.0.0/8"
    6. For lists: process.name IN ("cmd.exe", "powershell.exe")

    Generate only valid TQL. No explanations, no markdown.
    """
  end

  defp default_tql_examples do
    [
      {"show powershell from last 24 hours", "process.name = \"powershell.exe\" | where timestamp > ago(24h)"},
      {"find connections to port 4444", "network.dst_port = 4444"},
      {"processes with encoded commands", "process.command_line CONTAINS \"-enc\" OR process.command_line CONTAINS \"-encodedcommand\""},
      {"lateral movement activity", "network.dst_port IN (445, 5985, 5986, 135) | count by network.dst_ip | where count > 5"},
      {"suspicious DNS queries", "dns.query MATCHES \"*.xyz\" OR dns.query MATCHES \"*.top\" | sort timestamp desc | limit 100"},
      {"registry persistence", "registry.key CONTAINS \"\\\\Run\" | where timestamp > ago(7d)"},
      {"large file transfers", "network.bytes_sent > 10000000 | sort network.bytes_sent desc | limit 50"}
    ]
  end
end
