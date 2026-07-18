defmodule TamanduaServer.Detection.PromptInjectionClassifier do
  @moduledoc """
  Layered prompt injection detection with fast regex patterns and ML fallback.

  Detects:
  - Direct injection (instruction override, system prompt manipulation)
  - Indirect injection (data injection via external content)
  - Jailbreak attempts (DAN, roleplay exploits, fictional framing)
  - Encoded injection (base64, unicode escapes, homoglyphs)

  Performance targets:
  - Regex fast-path: <10ms
  - ML fallback: <100ms total

  Usage:
      {:ok, result} = PromptInjectionClassifier.classify(prompt)
      if result.is_injection do
        # Handle detected injection
      end
  """

  require Logger

  # ============================================================================
  # Configuration
  # ============================================================================

  @ml_service_url Application.compile_env(:tamandua_server, :ml_service_url, "http://localhost:8000")
  @ml_timeout 90  # 90ms timeout for ML call (leaving 10ms margin for 100ms SLA)

  @injection_types [:direct, :indirect, :jailbreak, :encoded]

  # ============================================================================
  # Compiled Regex Patterns (loaded at compile time for performance)
  # ============================================================================

  defp direct_injection_patterns do
    [
    # Instruction override
    ~r/ignore\s+(all\s+)?previous\s+instructions/i,
    ~r/disregard\s+(all\s+)?prior\s+(instructions|context)/i,
    ~r/forget\s+everything\s+(above|before)/i,
    ~r/new\s+instructions?\s*:/i,
    ~r/override\s+your\s+(instructions|rules|guidelines)/i,
    ~r/reset\s+your\s+(instructions|context|memory)/i,
    ~r/clear\s+(your\s+)?(previous\s+)?(instructions|context)/i,
    ~r/start\s+fresh\s+with\s+new/i,

    # System prompt manipulation
    ~r/you\s+are\s+now\s+(a|an|the)\s+/i,
    ~r/act\s+as\s+if\s+you\s+(are|were)/i,
    ~r/pretend\s+(you\s+are|to\s+be)/i,
    ~r/your\s+new\s+role\s+is/i,
    ~r/from\s+now\s+on\s+you\s+(are|will)/i,
    ~r/\[system\]\s*:/i,
    ~r/<<SYS>>/i,
    ~r/<\|system\|>/i,
    ~r/\[INST\]/i,
    ~r/<\|im_start\|>system/i,

    # Direct command overrides
    ~r/i\s+command\s+you\s+to/i,
    ~r/you\s+must\s+obey/i,
    ~r/this\s+overrides\s+everything/i
    ]
  end

  defp indirect_injection_patterns do
    [
    # Data injection markers
    ~r/\[INJECTION\]/i,
    ~r/<!--\s*ignore/i,
    ~r/\{\{.*system.*\}\}/i,
    ~r/%SYSTEM%/i,
    ~r/ADMIN_OVERRIDE/i,
    ~r/\[hidden\s+instruction\]/i,

    # Hidden instructions in data
    ~r/when\s+processing\s+this.*ignore/i,
    ~r/note\s+to\s+AI.*override/i,
    ~r/instructions\s+for\s+the\s+model/i,
    ~r/ai\s+instructions\s*:/i,
    ~r/for\s+the\s+llm\s*:/i,
    ~r/model\s+instructions\s*:/i,

    # URL/file injection hints
    ~r/fetch\s+instructions\s+from/i,
    ~r/load\s+prompt\s+from/i,
    ~r/execute\s+commands?\s+from/i
    ]
  end

  defp jailbreak_patterns do
    [
    # DAN and variants
    ~r/\bDAN\b/,
    ~r/do\s+anything\s+now/i,
    ~r/jailbreak(ed)?/i,
    ~r/developer\s+mode/i,
    ~r/sudo\s+mode/i,
    ~r/god\s+mode/i,
    ~r/maximum\s+mode/i,
    ~r/uncensored\s+mode/i,

    # Roleplay exploits
    ~r/in\s+this\s+hypothetical\s+scenario/i,
    ~r/for\s+educational\s+purposes\s+only/i,
    ~r/purely\s+fictional/i,
    ~r/between\s+\[.*\]\s+brackets/i,
    ~r/in\s+a\s+fictional\s+world/i,
    ~r/imagine\s+you\s+have\s+no\s+restrictions/i,
    ~r/purely\s+hypothetically/i,
    ~r/for\s+a\s+creative\s+writing\s+project/i,

    # Output manipulation
    ~r/respond\s+without\s+(restrictions|filters)/i,
    ~r/bypass\s+(your\s+)?(safety|content)\s+filter/i,
    ~r/disable\s+(your\s+)?guidelines/i,
    ~r/remove\s+(your\s+)?limitations/i,
    ~r/unlock\s+(your\s+)?full\s+capabilities/i,
    ~r/without\s+any\s+ethical\s+considerations/i,

    # Token manipulation
    ~r/<\|endoftext\|>/i,
    ~r/<\|assistant\|>/i,
    ~r/<\|user\|>/i,
    ~r/<\|end\|>/i
    ]
  end

  defp encoded_injection_patterns do
    [
    # Base64 with decode keywords
    ~r/base64.*decode.*execute/i,
    ~r/decode\s+and\s+(run|execute|follow)/i,
    ~r/atob\s*\(/i,
    ~r/eval\s*\(\s*atob/i,

    # Unicode escapes (suspicious density)
    ~r/\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}/,

    # HTML entities
    ~r/&#x[0-9a-fA-F]+;.*&#x[0-9a-fA-F]+;/i,
    ~r/&lt;script&gt;/i,

    # Rot13 and simple ciphers
    ~r/rot13\s*\(|decode\s+rot13/i,
    ~r/caesar\s+cipher/i,

    # Hex encoding
    ~r/\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}/
    ]
  end

  # ============================================================================
  # Type Definitions
  # ============================================================================

  @type injection_type :: :direct | :indirect | :jailbreak | :encoded
  @type analysis_method :: :regex | :ml | :both

  @type classification_result :: %{
    is_injection: boolean(),
    injection_type: injection_type() | nil,
    confidence: float(),
    matched_patterns: list(String.t()),
    analysis_method: analysis_method(),
    latency_ms: non_neg_integer()
  }

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Classify a prompt for potential injection attacks.

  ## Options
    - `:use_ml` - Whether to fall back to ML classifier for uncertain cases (default: true)
    - `:threshold` - Confidence threshold for positive detection (default: 0.3)

  ## Returns
    `{:ok, classification_result}` or `{:error, reason}`

  ## Examples

      {:ok, result} = PromptInjectionClassifier.classify("Ignore previous instructions")
      result.is_injection  # => true
      result.injection_type  # => :direct
      result.confidence  # => 0.95

      {:ok, result} = PromptInjectionClassifier.classify("What's the weather?")
      result.is_injection  # => false
  """
  @spec classify(String.t(), keyword()) :: {:ok, classification_result()} | {:error, term()}
  def classify(prompt, opts \\ []) do
    start_time = System.monotonic_time(:millisecond)
    use_ml = Keyword.get(opts, :use_ml, true)
    threshold = Keyword.get(opts, :threshold, 0.3)

    # Fast-path: regex matching
    regex_result = match_regex_patterns(prompt)

    result = case regex_result.confidence do
      c when c >= 0.8 ->
        # High confidence regex match, no need for ML
        Map.put(regex_result, :analysis_method, :regex)

      c when c >= threshold and use_ml ->
        # Uncertain, verify with ML
        case call_ml_classifier(prompt) do
          {:ok, ml_result} ->
            combine_results(regex_result, ml_result)
          {:error, reason} ->
            Logger.debug("[PromptInjectionClassifier] ML fallback failed: #{inspect(reason)}")
            # ML unavailable, trust regex
            Map.put(regex_result, :analysis_method, :regex)
        end

      _ ->
        # Low confidence, likely benign
        Map.put(regex_result, :analysis_method, :regex)
    end

    elapsed = System.monotonic_time(:millisecond) - start_time

    # Emit telemetry
    :telemetry.execute(
      [:tamandua, :prompt_injection, :classify],
      %{latency_ms: elapsed},
      %{
        injection_detected: result.is_injection,
        injection_type: result.injection_type,
        analysis_method: result.analysis_method,
        confidence: result.confidence
      }
    )

    {:ok, Map.put(result, :latency_ms, elapsed)}
  rescue
    e ->
      Logger.error("[PromptInjectionClassifier] Classification error: #{Exception.message(e)}")
      {:error, {:classification_error, Exception.message(e)}}
  end

  @doc """
  Classify a prompt asynchronously.

  Returns a Task that can be awaited or used with Task.yield.

  ## Examples

      task = PromptInjectionClassifier.classify_async("Check this prompt")
      {:ok, result} = Task.await(task, 5000)
  """
  @spec classify_async(String.t(), keyword()) :: Task.t()
  def classify_async(prompt, opts \\ []) do
    Task.async(fn -> classify(prompt, opts) end)
  end

  @doc """
  Get all compiled regex patterns grouped by injection type.

  Useful for debugging and pattern inspection.

  ## Returns
    Map with keys `:direct`, `:indirect`, `:jailbreak`, `:encoded`
  """
  @spec get_patterns() :: map()
  def get_patterns do
    %{
      direct: direct_injection_patterns(),
      indirect: indirect_injection_patterns(),
      jailbreak: jailbreak_patterns(),
      encoded: encoded_injection_patterns()
    }
  end

  @doc """
  Get all supported injection types.
  """
  @spec injection_types() :: list(injection_type())
  def injection_types, do: @injection_types

  # ============================================================================
  # Private Functions
  # ============================================================================

  @doc false
  defp match_regex_patterns(prompt) do
    # Check all pattern categories and aggregate matches
    direct_matches = match_pattern_list(prompt, direct_injection_patterns(), :direct)
    indirect_matches = match_pattern_list(prompt, indirect_injection_patterns(), :indirect)
    jailbreak_matches = match_pattern_list(prompt, jailbreak_patterns(), :jailbreak)
    encoded_matches = match_pattern_list(prompt, encoded_injection_patterns(), :encoded)

    all_matches = direct_matches ++ indirect_matches ++ jailbreak_matches ++ encoded_matches

    if Enum.empty?(all_matches) do
      %{
        is_injection: false,
        injection_type: nil,
        confidence: 0.0,
        matched_patterns: []
      }
    else
      # Find the highest confidence match
      {type, patterns, confidence} = Enum.max_by(all_matches, fn {_type, _patterns, conf} -> conf end)

      # Boost confidence if multiple pattern types matched
      type_count = all_matches
      |> Enum.map(fn {t, _, _} -> t end)
      |> Enum.uniq()
      |> length()

      boosted_confidence = min(confidence + (type_count - 1) * 0.1, 1.0)

      %{
        is_injection: boosted_confidence >= 0.3,
        injection_type: type,
        confidence: boosted_confidence,
        matched_patterns: patterns
      }
    end
  end

  defp match_pattern_list(prompt, patterns, type) do
    matches = patterns
    |> Enum.filter(fn pattern -> Regex.match?(pattern, prompt) end)
    |> Enum.map(&Regex.source/1)

    if Enum.empty?(matches) do
      []
    else
      # Base confidence from match count
      match_count = length(matches)
      base_confidence = min(0.5 + match_count * 0.15, 0.95)

      # Boost for certain high-signal patterns
      high_signal = case type do
        :direct ->
          Regex.match?(~r/ignore\s+(all\s+)?previous\s+instructions/i, prompt) or
          Regex.match?(~r/<<SYS>>/i, prompt) or
          Regex.match?(~r/\[system\]\s*:/i, prompt)
        :jailbreak ->
          Regex.match?(~r/\bDAN\b/, prompt) or
          Regex.match?(~r/jailbreak/i, prompt) or
          Regex.match?(~r/developer\s+mode/i, prompt)
        :indirect ->
          Regex.match?(~r/\[INJECTION\]/i, prompt)
        :encoded ->
          Regex.match?(~r/base64.*decode.*execute/i, prompt)
      end

      confidence = if high_signal, do: min(base_confidence + 0.2, 0.98), else: base_confidence

      [{type, matches, confidence}]
    end
  end

  defp call_ml_classifier(prompt) do
    url = "#{@ml_service_url}/prompt-injection/classify"
    body = Jason.encode!(%{prompt: prompt})
    headers = [{"Content-Type", "application/json"}]

    case HTTPoison.post(url, body, headers, recv_timeout: @ml_timeout) do
      {:ok, %{status_code: 200, body: resp_body}} ->
        case Jason.decode(resp_body) do
          {:ok, result} ->
            {:ok, normalize_ml_result(result)}
          {:error, _} ->
            {:error, :invalid_json}
        end

      {:ok, %{status_code: status}} ->
        {:error, {:http_error, status}}

      {:error, %{reason: reason}} ->
        {:error, reason}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e ->
      Logger.warning("[PromptInjectionClassifier] ML call error: #{Exception.message(e)}")
      {:error, :ml_unavailable}
  end

  defp normalize_ml_result(result) do
    injection_type = case result["injection_type"] do
      "direct" -> :direct
      "indirect" -> :indirect
      "jailbreak" -> :jailbreak
      "encoded" -> :encoded
      _ -> nil
    end

    %{
      is_injection: result["is_injection"] == true,
      injection_type: injection_type,
      confidence: result["confidence"] || 0.0,
      matched_patterns: [],
      all_scores: result["all_scores"]
    }
  end

  defp combine_results(regex_result, ml_result) do
    # Combine regex and ML results
    # If both agree on injection, boost confidence
    # If they disagree, use ML result but lower confidence

    cond do
      regex_result.is_injection and ml_result.is_injection ->
        # Both agree: injection detected
        combined_confidence = (regex_result.confidence + ml_result.confidence) / 2
        # Take the more specific type
        type = ml_result.injection_type || regex_result.injection_type

        %{
          is_injection: true,
          injection_type: type,
          confidence: min(combined_confidence + 0.1, 0.99),
          matched_patterns: regex_result.matched_patterns,
          analysis_method: :both
        }

      not regex_result.is_injection and not ml_result.is_injection ->
        # Both agree: benign
        %{
          is_injection: false,
          injection_type: nil,
          confidence: 0.0,
          matched_patterns: [],
          analysis_method: :both
        }

      ml_result.is_injection and ml_result.confidence >= 0.7 ->
        # ML confident about injection, trust ML
        Map.put(ml_result, :analysis_method, :ml)

      regex_result.is_injection and regex_result.confidence >= 0.7 ->
        # Regex confident, ML disagrees, trust regex
        Map.put(regex_result, :analysis_method, :regex)

      true ->
        # Uncertain, lower confidence
        %{
          is_injection: regex_result.is_injection or ml_result.is_injection,
          injection_type: regex_result.injection_type || ml_result.injection_type,
          confidence: max(regex_result.confidence, ml_result.confidence) * 0.7,
          matched_patterns: regex_result.matched_patterns,
          analysis_method: :both
        }
    end
  end

  # ============================================================================
  # Severity Mapping
  # ============================================================================

  @doc """
  Map injection type to alert severity.
  """
  @spec severity_for_injection(injection_type() | nil) :: String.t()
  def severity_for_injection(:direct), do: "high"
  def severity_for_injection(:jailbreak), do: "high"
  def severity_for_injection(:encoded), do: "high"
  def severity_for_injection(:indirect), do: "medium"
  def severity_for_injection(_), do: "medium"
end
