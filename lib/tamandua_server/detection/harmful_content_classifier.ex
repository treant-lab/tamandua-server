defmodule TamanduaServer.Detection.HarmfulContentClassifier do
  @moduledoc """
  Layered harmful content classifier with fast regex patterns and ML fallback.

  Detects:
  - Violence/threats: explicit threat patterns, weapon instructions
  - Hate speech: slurs, discriminatory language
  - Self-harm: suicide/self-harm discussion patterns
  - Illegal activity: drug manufacturing, hacking instructions
  - Explicit content: sexual content indicators

  Performance targets:
  - Regex fast-path: <10ms
  - ML fallback: <100ms total

  Usage:
      {:ok, result} = HarmfulContentClassifier.classify("text to analyze")
      if result.is_harmful do
        # Handle detected harmful content
      end
  """

  require Logger

  # ============================================================================
  # Configuration
  # ============================================================================

  @ml_service_url Application.compile_env(:tamandua_server, :ml_service_url, "http://localhost:8000")
  @ml_timeout 90  # 90ms timeout for ML call

  @categories [:violence, :hate_speech, :self_harm, :illegal, :explicit]

  # Severity mapping
  @severity_mapping %{
    violence: "critical",
    self_harm: "critical",
    hate_speech: "high",
    illegal: "high",
    explicit: "medium"
  }

  # ============================================================================
  # Compiled Regex Patterns
  # ============================================================================

  @violence_patterns [
    # Explicit threats
    ~r/\bi\s+will\s+kill\s+you\b/i,
    ~r/\bgoing\s+to\s+murder\b/i,
    ~r/\bkill\s+(?:your|the|all)\s+\w+/i,
    ~r/\bshoot\s+(?:you|them|everyone)/i,
    ~r/\bbomb\s+(?:the|a)\s+\w+/i,
    ~r/\bthreat(?:en|ening)?\s+to\s+(?:kill|harm|hurt)/i,
    ~r/\bmass\s+shooting\b/i,
    ~r/\bterrorist\s+attack\b/i,

    # Weapon instructions
    ~r/\bhow\s+to\s+make\s+a\s+(?:bomb|explosive|weapon)/i,
    ~r/\bbuild\s+a\s+(?:gun|weapon|explosive)/i,
    ~r/\bpipe\s+bomb\s+instructions\b/i,
    ~r/\bassault\s+rifle\s+modifications\b/i,
    ~r/\bchemical\s+weapon\b/i,

    # Violence glorification
    ~r/\bviolence\s+is\s+(?:good|necessary|justified)\b/i,
    ~r/\bdeserve\s+to\s+(?:die|suffer)\b/i
  ]

  @hate_speech_patterns [
    # Discriminatory language (patterns, not specific slurs)
    ~r/\ball\s+\[?\w+\]?\s+(?:should|must)\s+(?:die|be\s+killed)\b/i,
    ~r/\b(?:inferior|subhuman)\s+(?:race|people|species)\b/i,
    ~r/\bethnic\s+cleansing\b/i,
    ~r/\bracial\s+(?:purity|superiority)\b/i,
    ~r/\bwhite\s+(?:power|supremacy|genocide)\b/i,
    ~r/\b(?:gas|exterminate)\s+the\s+\w+\b/i,

    # Derogatory generalizations
    ~r/\b(?:all|those|the)\s+\w+\s+are\s+(?:animals|savages|vermin)\b/i,
    ~r/\b(?:deport|eliminate)\s+all\s+\w+\b/i,

    # Extremist rhetoric
    ~r/\bhate\s+all\s+\w+\b/i,
    ~r/\b(?:death|destruction)\s+to\s+(?:all\s+)?\w+\b/i
  ]

  @self_harm_patterns [
    # Suicide discussion
    ~r/\bhow\s+to\s+(?:kill\s+myself|commit\s+suicide)\b/i,
    ~r/\bways\s+to\s+(?:end\s+(?:my\s+)?life|die)\b/i,
    ~r/\bsuicide\s+methods?\b/i,
    ~r/\bpainless\s+(?:death|way\s+to\s+die)\b/i,
    ~r/\blethal\s+dose\b/i,
    ~r/\bno\s+reason\s+to\s+live\b/i,

    # Self-harm encouragement (very high signal)
    ~r/\b(?:you\s+should|just)\s+kill\s+yourself\b/i,
    ~r/\bgo\s+(?:hang|cut)\s+yourself\b/i,
    ~r/\bencouraging\s+(?:suicide|self[- ]harm)\b/i,

    # Self-injury patterns
    ~r/\bcut(?:ting)?\s+(?:myself|yourself)\b/i,
    ~r/\bself[- ](?:harm|injury|mutilation)\s+(?:tips|methods)\b/i
  ]

  @illegal_patterns [
    # Drug manufacturing
    ~r/\bhow\s+to\s+(?:make|cook|synthesize)\s+(?:meth|cocaine|heroin|fentanyl)\b/i,
    ~r/\bmeth(?:amphetamine)?\s+(?:recipe|synthesis|cook)\b/i,
    ~r/\bdrug\s+(?:manufacturing|synthesis)\s+(?:guide|instructions)\b/i,

    # Hacking/cybercrime
    ~r/\bhow\s+to\s+hack\s+(?:into|a)\s+\w+/i,
    ~r/\bsteal\s+(?:credit\s+card|identity|password)/i,
    ~r/\bransomware\s+(?:attack|tutorial)\b/i,
    ~r/\bddos\s+(?:attack|tool|script)\b/i,
    ~r/\bphishing\s+(?:kit|tutorial|template)\b/i,

    # Fraud instructions
    ~r/\b(?:credit\s+card|identity)\s+fraud\s+(?:guide|tutorial)\b/i,
    ~r/\bmoney\s+laundering\s+(?:guide|how\s+to)\b/i,

    # Human trafficking
    ~r/\b(?:human|sex)\s+trafficking\b/i,
    ~r/\bchild\s+(?:exploitation|trafficking)\b/i
  ]

  @explicit_patterns [
    # Sexual content indicators
    ~r/\bexplicit\s+sexual\s+content\b/i,
    ~r/\bgraphic\s+sexual\s+(?:description|content)\b/i,
    ~r/\bpornograph(?:y|ic)\b/i,
    ~r/\bsexually\s+explicit\b/i,
    ~r/\bnude\s+(?:photos?|images?|pictures?)\b/i,

    # CSAM indicators (critical)
    ~r/\bchild\s+(?:pornography|exploitation|abuse\s+material)\b/i,
    ~r/\bminor\s+sexual\b/i,
    ~r/\bunderage\s+(?:sex|nude|porn)\b/i
  ]

  # ============================================================================
  # Type Definitions
  # ============================================================================

  @type category :: :violence | :hate_speech | :self_harm | :illegal | :explicit
  @type analysis_method :: :regex | :ml | :both

  @type classification_result :: %{
          is_harmful: boolean(),
          category: category() | nil,
          confidence: float(),
          matched_patterns: list(String.t()),
          analysis_method: analysis_method(),
          latency_ms: non_neg_integer(),
          severity: String.t() | nil
        }

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Classify text for harmful content.

  ## Options
    - `:use_ml` - Whether to fall back to ML classifier (default: true)
    - `:threshold` - Confidence threshold for detection (default: 0.3)

  ## Returns
    `{:ok, classification_result}` or `{:error, reason}`
  """
  @spec classify(String.t(), keyword()) :: {:ok, classification_result()} | {:error, term()}
  def classify(text, opts \\ []) do
    start_time = System.monotonic_time(:millisecond)
    use_ml = Keyword.get(opts, :use_ml, true)
    threshold = Keyword.get(opts, :threshold, 0.3)

    # Fast-path: regex matching
    regex_result = match_regex_patterns(text)

    result =
      case regex_result.confidence do
        c when c >= 0.8 ->
          # High confidence regex match, no need for ML
          Map.put(regex_result, :analysis_method, :regex)

        c when c >= threshold and use_ml ->
          # Uncertain, verify with ML
          case call_ml_classifier(text) do
            {:ok, ml_result} ->
              combine_results(regex_result, ml_result)

            {:error, reason} ->
              Logger.debug(
                "[HarmfulContentClassifier] ML fallback failed: #{inspect(reason)}"
              )

              Map.put(regex_result, :analysis_method, :regex)
          end

        _ ->
          # Low confidence or no match
          Map.put(regex_result, :analysis_method, :regex)
      end

    elapsed = System.monotonic_time(:millisecond) - start_time

    # Add severity based on category
    severity =
      if result.is_harmful do
        Map.get(@severity_mapping, result.category, "medium")
      else
        nil
      end

    final_result =
      result
      |> Map.put(:latency_ms, elapsed)
      |> Map.put(:severity, severity)

    # Emit telemetry
    :telemetry.execute(
      [:tamandua, :harmful_content, :classify],
      %{latency_ms: elapsed},
      %{
        harmful_detected: final_result.is_harmful,
        category: final_result.category,
        analysis_method: final_result.analysis_method,
        confidence: final_result.confidence,
        severity: severity
      }
    )

    {:ok, final_result}
  rescue
    e ->
      Logger.error(
        "[HarmfulContentClassifier] Classification error: #{Exception.message(e)}"
      )

      {:error, {:classification_error, Exception.message(e)}}
  end

  @doc """
  Classify text asynchronously.

  Returns a Task that can be awaited.
  """
  @spec classify_async(String.t(), keyword()) :: Task.t()
  def classify_async(text, opts \\ []) do
    Task.async(fn -> classify(text, opts) end)
  end

  @doc """
  Get all harmful content categories.
  """
  @spec categories() :: list(category())
  def categories, do: @categories

  @doc """
  Get severity for a category.
  """
  @spec severity_for_category(category()) :: String.t()
  def severity_for_category(category) do
    Map.get(@severity_mapping, category, "medium")
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp match_regex_patterns(text) do
    violence_matches = match_pattern_list(text, @violence_patterns, :violence)
    hate_matches = match_pattern_list(text, @hate_speech_patterns, :hate_speech)
    self_harm_matches = match_pattern_list(text, @self_harm_patterns, :self_harm)
    illegal_matches = match_pattern_list(text, @illegal_patterns, :illegal)
    explicit_matches = match_pattern_list(text, @explicit_patterns, :explicit)

    all_matches =
      violence_matches ++ hate_matches ++ self_harm_matches ++
        illegal_matches ++ explicit_matches

    if Enum.empty?(all_matches) do
      %{
        is_harmful: false,
        category: nil,
        confidence: 0.0,
        matched_patterns: []
      }
    else
      # Find the highest confidence match
      {category, patterns, confidence} =
        Enum.max_by(all_matches, fn {_cat, _patterns, conf} -> conf end)

      # Boost confidence if multiple categories matched
      category_count =
        all_matches
        |> Enum.map(fn {cat, _, _} -> cat end)
        |> Enum.uniq()
        |> length()

      boosted_confidence = min(confidence + (category_count - 1) * 0.1, 1.0)

      %{
        is_harmful: boosted_confidence >= 0.3,
        category: category,
        confidence: boosted_confidence,
        matched_patterns: patterns
      }
    end
  end

  defp match_pattern_list(text, patterns, category) do
    matches =
      patterns
      |> Enum.filter(fn pattern -> Regex.match?(pattern, text) end)
      |> Enum.map(&Regex.source/1)

    if Enum.empty?(matches) do
      []
    else
      match_count = length(matches)
      # Base confidence from match count
      base_confidence = min(0.5 + match_count * 0.15, 0.95)

      # High-signal patterns get extra boost
      high_signal =
        case category do
          :self_harm ->
            Regex.match?(~r/\b(?:you\s+should|just)\s+kill\s+yourself\b/i, text) or
              Regex.match?(~r/\bhow\s+to\s+(?:kill\s+myself|commit\s+suicide)\b/i, text)

          :violence ->
            Regex.match?(~r/\bi\s+will\s+kill\s+you\b/i, text) or
              Regex.match?(~r/\bhow\s+to\s+make\s+a\s+bomb\b/i, text)

          :explicit ->
            Regex.match?(~r/\bchild\s+(?:pornography|exploitation)\b/i, text)

          :illegal ->
            Regex.match?(~r/\bchild\s+trafficking\b/i, text)

          _ ->
            false
        end

      confidence = if high_signal, do: min(base_confidence + 0.2, 0.98), else: base_confidence

      [{category, matches, confidence}]
    end
  end

  defp call_ml_classifier(text) do
    url = "#{@ml_service_url}/output-validation/classify"

    body =
      Jason.encode!(%{
        text: text,
        categories: Enum.map(@categories, &to_string/1)
      })

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
      Logger.warning("[HarmfulContentClassifier] ML call error: #{Exception.message(e)}")
      {:error, :ml_unavailable}
  end

  defp normalize_ml_result(result) do
    category =
      case result["category"] do
        "violence" -> :violence
        "hate_speech" -> :hate_speech
        "self_harm" -> :self_harm
        "illegal" -> :illegal
        "explicit" -> :explicit
        _ -> nil
      end

    %{
      is_harmful: result["is_harmful"] == true,
      category: category,
      confidence: result["confidence"] || 0.0,
      matched_patterns: [],
      all_scores: result["all_scores"]
    }
  end

  defp combine_results(regex_result, ml_result) do
    cond do
      regex_result.is_harmful and ml_result.is_harmful ->
        # Both agree: harmful
        combined_confidence = (regex_result.confidence + ml_result.confidence) / 2
        category = ml_result.category || regex_result.category

        %{
          is_harmful: true,
          category: category,
          confidence: min(combined_confidence + 0.1, 0.99),
          matched_patterns: regex_result.matched_patterns,
          analysis_method: :both
        }

      not regex_result.is_harmful and not ml_result.is_harmful ->
        # Both agree: benign
        %{
          is_harmful: false,
          category: nil,
          confidence: 0.0,
          matched_patterns: [],
          analysis_method: :both
        }

      ml_result.is_harmful and ml_result.confidence >= 0.7 ->
        # ML confident about harmful, trust ML
        Map.put(ml_result, :analysis_method, :ml)

      regex_result.is_harmful and regex_result.confidence >= 0.7 ->
        # Regex confident, trust regex
        Map.put(regex_result, :analysis_method, :regex)

      true ->
        # Uncertain, conservative approach
        %{
          is_harmful: regex_result.is_harmful or ml_result.is_harmful,
          category: regex_result.category || ml_result.category,
          confidence: max(regex_result.confidence, ml_result.confidence) * 0.8,
          matched_patterns: regex_result.matched_patterns,
          analysis_method: :both
        }
    end
  end
end
