defmodule TamanduaServer.Detection.Poisoning do
  @moduledoc """
  Client for model poisoning detection via the Python ML service.

  Provides functions to detect:
  - Label-flip attacks (inverted class weights)
  - Backdoor trigger patterns (sparse activation patterns)
  - Data contamination (gradient poisoning, training anomalies)
  - Known attack signatures (BadNets, TrojanNN, Clean-Label, Witches' Brew)

  ## Configuration

  The ML service URL can be configured via:
  - Environment variable: `ML_SERVICE_URL`
  - Application config: `config :tamandua_server, :ml_service_url`
  - Default: `http://localhost:8000`

  ## Example

      iex> Poisoning.detect_poisoning("/path/to/model.safetensors")
      {:ok, %{
        poisoning_score: 0.75,
        label_flip_score: 0.8,
        is_poisoned: true,
        trigger_patterns: [%{layer_name: "classifier.weight", ...}],
        indicators: [%{indicator_type: "label_flip", severity: "high", ...}],
        analysis_time_ms: 1234
      }}

  ## MITRE ATLAS Mapping

  Detection findings map to MITRE ATLAS techniques:
  - AML.T0019: Publish Poisoned Model
  - AML.T0020: Poison Training Data
  - AML.T0018: Backdoor ML Model
  """

  require Logger

  @default_ml_service_url "http://localhost:8000"
  @timeout 120_000  # 2 minutes for large models

  # ---------------------------------------------------------------------------
  # Type Definitions
  # ---------------------------------------------------------------------------

  @type trigger_pattern :: %{
    layer_name: String.t(),
    pattern_type: String.t(),
    confidence: float(),
    description: String.t()
  }

  @type poisoning_indicator :: %{
    indicator_type: String.t(),
    severity: String.t(),
    evidence: String.t(),
    recommendation: String.t()
  }

  @type poisoning_result :: %{
    poisoning_score: float(),
    label_flip_score: float(),
    trigger_patterns: [trigger_pattern()],
    indicators: [poisoning_indicator()],
    is_poisoned: boolean(),
    file_name: String.t(),
    analysis_time_ms: integer()
  }

  @type known_signature :: %{
    attack_name: String.t(),
    confidence: float(),
    technique_id: String.t(),
    references: [String.t()]
  }

  @type contamination_result :: %{
    gradient_poisoning: map(),
    training_anomalies: [map()],
    known_signatures: [known_signature()],
    integrity_valid: boolean() | nil,
    risk_score: float(),
    file_name: String.t(),
    analysis_time_ms: integer()
  }

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  @doc """
  Perform full poisoning analysis on a model file.

  Analyzes the model for:
  - Label-flip attack signatures
  - Backdoor trigger patterns
  - Training artifact anomalies

  ## Parameters

    * `file_path` - Absolute path to the model file

  ## Returns

    * `{:ok, poisoning_result()}` - Analysis completed
    * `{:error, reason}` - Analysis failed

  ## Example

      iex> Poisoning.detect_poisoning("/models/suspicious.safetensors")
      {:ok, %{poisoning_score: 0.85, is_poisoned: true, ...}}
  """
  @spec detect_poisoning(String.t()) :: {:ok, poisoning_result()} | {:error, String.t()}
  def detect_poisoning(file_path) when is_binary(file_path) do
    url = "#{ml_service_url()}/ai-security/poisoning/detect"

    Logger.info("[Poisoning] Starting poisoning detection for #{file_path}")

    unless File.exists?(file_path) do
      Logger.warning("[Poisoning] File not found: #{file_path}")
      {:error, "File not found: #{file_path}"}
    else
      case Req.post(url,
        form_multipart: [file: {:file, file_path}],
        receive_timeout: @timeout,
        connect_options: [timeout: 10_000]
      ) do
        {:ok, %{status: 200, body: body}} ->
          Logger.info("[Poisoning] Detection completed for #{file_path}")
          {:ok, parse_poisoning_response(body)}

        {:ok, %{status: status, body: body}} ->
          error_msg = extract_error_message(body, status)
          Logger.warning("[Poisoning] ML service returned #{status}: #{error_msg}")
          {:error, "ML service returned #{status}: #{error_msg}"}

        {:error, %Req.TransportError{reason: :timeout}} ->
          Logger.warning("[Poisoning] Request timed out for #{file_path}")
          {:error, "Analysis timed out - model may be too large"}

        {:error, %Req.TransportError{reason: :econnrefused}} ->
          Logger.warning("[Poisoning] ML service connection refused")
          {:error, "ML service unavailable - connection refused"}

        {:error, reason} ->
          Logger.warning("[Poisoning] Request failed: #{inspect(reason)}")
          {:error, "ML service request failed: #{inspect(reason)}"}
      end
    end
  end

  @doc """
  Detect label-flip specific patterns in a model file.

  Label-flip attacks invert class labels during training, causing the model
  to misclassify specific inputs. This endpoint specifically targets
  label-flip detection patterns.

  ## Parameters

    * `file_path` - Absolute path to the model file

  ## Returns

    * `{:ok, result}` - Analysis completed
    * `{:error, reason}` - Analysis failed

  ## Result Map

    * `:label_flip_score` - Likelihood of label-flip attack (0.0-1.0)
    * `:affected_classes` - List of class indices with inverted patterns
    * `:file_name` - Original filename
    * `:analysis_time_ms` - Analysis time in milliseconds

  ## Example

      iex> Poisoning.detect_label_flip("/models/classifier.safetensors")
      {:ok, %{label_flip_score: 0.9, affected_classes: [3, 7], ...}}
  """
  @spec detect_label_flip(String.t()) :: {:ok, map()} | {:error, String.t()}
  def detect_label_flip(file_path) when is_binary(file_path) do
    url = "#{ml_service_url()}/ai-security/poisoning/label-flip"

    Logger.info("[Poisoning] Starting label-flip detection for #{file_path}")

    unless File.exists?(file_path) do
      {:error, "File not found: #{file_path}"}
    else
      case Req.post(url,
        form_multipart: [file: {:file, file_path}],
        receive_timeout: @timeout,
        connect_options: [timeout: 10_000]
      ) do
        {:ok, %{status: 200, body: body}} ->
          {:ok, parse_label_flip_response(body)}

        {:ok, %{status: status, body: body}} ->
          error_msg = extract_error_message(body, status)
          {:error, "ML service returned #{status}: #{error_msg}"}

        {:error, reason} ->
          {:error, "ML service request failed: #{inspect(reason)}"}
      end
    end
  end

  @doc """
  Check for data contamination in a model file.

  Analyzes for:
  - Gradient poisoning patterns (aligned/manipulated gradients)
  - Known attack signatures (BadNets, TrojanNN, Clean-Label, Witches' Brew)
  - Dataset integrity (if hashes provided)

  ## Parameters

    * `file_path` - Absolute path to the model file
    * `opts` - Keyword list of options:
      * `:dataset_hashes` - Optional comma-separated list of dataset sample hashes
      * `:expected_count` - Optional expected number of samples

  ## Returns

    * `{:ok, contamination_result()}` - Analysis completed
    * `{:error, reason}` - Analysis failed

  ## Example

      iex> Poisoning.check_contamination("/models/trained.safetensors")
      {:ok, %{risk_score: 0.4, known_signatures: [...], ...}}

      iex> Poisoning.check_contamination("/models/trained.safetensors",
      ...>   dataset_hashes: "hash1,hash2,hash3", expected_count: 3)
      {:ok, %{integrity_valid: true, ...}}
  """
  @spec check_contamination(String.t(), keyword()) :: {:ok, contamination_result()} | {:error, String.t()}
  def check_contamination(file_path, opts \\ []) when is_binary(file_path) do
    url = "#{ml_service_url()}/ai-security/poisoning/contamination"

    Logger.info("[Poisoning] Starting contamination check for #{file_path}")

    unless File.exists?(file_path) do
      {:error, "File not found: #{file_path}"}
    else
      # Build query params from opts
      query_params = build_contamination_params(opts)

      case Req.post(url,
        form_multipart: [file: {:file, file_path}],
        params: query_params,
        receive_timeout: @timeout,
        connect_options: [timeout: 10_000]
      ) do
        {:ok, %{status: 200, body: body}} ->
          {:ok, parse_contamination_response(body)}

        {:ok, %{status: status, body: body}} ->
          error_msg = extract_error_message(body, status)
          {:error, "ML service returned #{status}: #{error_msg}"}

        {:error, reason} ->
          {:error, "ML service request failed: #{inspect(reason)}"}
      end
    end
  end

  @doc """
  List all known poisoning attack signatures.

  Returns the database of known attack patterns including:
  - BadNets: Localized trigger patterns
  - TrojanNN: Weight perturbations
  - Clean-Label: Subtle boundary shifts
  - Witches' Brew: Gradient alignment

  Each signature includes MITRE ATLAS technique IDs for threat intelligence
  integration.

  ## Returns

    * `{:ok, [signature]}` - List of signature definitions
    * `{:error, reason}` - Request failed

  ## Example

      iex> Poisoning.list_signatures()
      {:ok, [
        %{attack_name: "BadNets", technique_id: "AML.T0019", ...},
        %{attack_name: "TrojanNN", technique_id: "AML.T0019", ...},
        ...
      ]}
  """
  @spec list_signatures() :: {:ok, [map()]} | {:error, String.t()}
  def list_signatures do
    url = "#{ml_service_url()}/ai-security/poisoning/signatures"

    case Req.get(url, receive_timeout: 10_000) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, parse_signatures_response(body)}

      {:ok, %{status: status, body: body}} ->
        error_msg = extract_error_message(body, status)
        {:error, "ML service returned #{status}: #{error_msg}"}

      {:error, reason} ->
        {:error, "ML service request failed: #{inspect(reason)}"}
    end
  end

  @doc """
  Run full poisoning analysis including contamination check.

  Combines `detect_poisoning/1` and `check_contamination/1` for a
  comprehensive analysis. This is the recommended entry point for
  model security scanning workflows.

  ## Parameters

    * `file_path` - Absolute path to the model file
    * `opts` - Options passed to `check_contamination/2`

  ## Returns

    * `{:ok, result}` - Combined analysis result
    * `{:error, reason}` - Analysis failed

  ## Result Map

  Combines fields from both `poisoning_result()` and `contamination_result()`:
    * `:poisoning_score` - Overall poisoning likelihood (0.0-1.0)
    * `:contamination_risk_score` - Data contamination risk (0.0-1.0)
    * `:combined_risk_score` - Weighted average of both scores
    * `:is_poisoned` - True if combined_risk_score > 0.3
    * `:findings` - Consolidated list of all findings

  ## Example

      iex> Poisoning.analyze_full("/models/model.safetensors")
      {:ok, %{
        poisoning_score: 0.6,
        contamination_risk_score: 0.4,
        combined_risk_score: 0.5,
        is_poisoned: true,
        findings: [...]
      }}
  """
  @spec analyze_full(String.t(), keyword()) :: {:ok, map()} | {:error, String.t()}
  def analyze_full(file_path, opts \\ []) when is_binary(file_path) do
    Logger.info("[Poisoning] Starting full analysis for #{file_path}")

    with {:ok, poisoning} <- detect_poisoning(file_path),
         {:ok, contamination} <- check_contamination(file_path, opts) do
      combined_score = poisoning.poisoning_score * 0.5 + contamination.risk_score * 0.5

      findings = build_findings(poisoning, contamination)

      {:ok, %{
        poisoning_score: poisoning.poisoning_score,
        label_flip_score: poisoning.label_flip_score,
        contamination_risk_score: contamination.risk_score,
        combined_risk_score: combined_score,
        is_poisoned: combined_score > 0.3,
        trigger_patterns: poisoning.trigger_patterns,
        indicators: poisoning.indicators,
        known_signatures: contamination.known_signatures,
        gradient_poisoning: contamination.gradient_poisoning,
        findings: findings,
        file_name: poisoning.file_name,
        analysis_time_ms: poisoning.analysis_time_ms + contamination.analysis_time_ms
      }}
    end
  end

  # ---------------------------------------------------------------------------
  # Private Helpers
  # ---------------------------------------------------------------------------

  defp ml_service_url do
    Application.get_env(:tamandua_server, :ml_service_url, @default_ml_service_url)
  end

  defp build_contamination_params(opts) do
    params = %{}

    params = case Keyword.get(opts, :dataset_hashes) do
      nil -> params
      hashes -> Map.put(params, :dataset_hashes, hashes)
    end

    params = case Keyword.get(opts, :expected_count) do
      nil -> params
      count -> Map.put(params, :expected_count, count)
    end

    params
  end

  defp parse_poisoning_response(body) when is_map(body) do
    %{
      poisoning_score: body["poisoning_score"] || 0.0,
      label_flip_score: body["label_flip_score"] || 0.0,
      trigger_patterns: parse_trigger_patterns(body["trigger_patterns"]),
      indicators: parse_indicators(body["indicators"]),
      is_poisoned: body["is_poisoned"] || false,
      file_name: body["file_name"] || "",
      analysis_time_ms: body["analysis_time_ms"] || 0
    }
  end

  defp parse_poisoning_response(body) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, decoded} -> parse_poisoning_response(decoded)
      {:error, _} -> %{poisoning_score: 0.0, is_poisoned: false}
    end
  end

  defp parse_poisoning_response(_), do: %{poisoning_score: 0.0, is_poisoned: false}

  defp parse_trigger_patterns(nil), do: []
  defp parse_trigger_patterns(patterns) when is_list(patterns) do
    Enum.map(patterns, fn p ->
      %{
        layer_name: p["layer_name"] || "",
        pattern_type: p["pattern_type"] || "",
        confidence: p["confidence"] || 0.0,
        description: p["description"] || ""
      }
    end)
  end
  defp parse_trigger_patterns(_), do: []

  defp parse_indicators(nil), do: []
  defp parse_indicators(indicators) when is_list(indicators) do
    Enum.map(indicators, fn i ->
      %{
        indicator_type: i["indicator_type"] || "",
        severity: i["severity"] || "low",
        evidence: i["evidence"] || "",
        recommendation: i["recommendation"] || ""
      }
    end)
  end
  defp parse_indicators(_), do: []

  defp parse_label_flip_response(body) when is_map(body) do
    %{
      label_flip_score: body["label_flip_score"] || 0.0,
      affected_classes: body["affected_classes"] || [],
      file_name: body["file_name"] || "",
      analysis_time_ms: body["analysis_time_ms"] || 0
    }
  end

  defp parse_label_flip_response(body) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, decoded} -> parse_label_flip_response(decoded)
      {:error, _} -> %{label_flip_score: 0.0, affected_classes: []}
    end
  end

  defp parse_label_flip_response(_), do: %{label_flip_score: 0.0, affected_classes: []}

  defp parse_contamination_response(body) when is_map(body) do
    %{
      gradient_poisoning: parse_gradient_poisoning(body["gradient_poisoning"]),
      training_anomalies: body["training_anomalies"] || [],
      known_signatures: parse_known_signatures(body["known_signatures"]),
      integrity_valid: body["integrity_valid"],
      risk_score: body["risk_score"] || 0.0,
      file_name: body["file_name"] || "",
      analysis_time_ms: body["analysis_time_ms"] || 0
    }
  end

  defp parse_contamination_response(body) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, decoded} -> parse_contamination_response(decoded)
      {:error, _} -> %{risk_score: 0.0, known_signatures: []}
    end
  end

  defp parse_contamination_response(_), do: %{risk_score: 0.0, known_signatures: []}

  defp parse_gradient_poisoning(nil), do: %{detected: false, confidence: 0.0}
  defp parse_gradient_poisoning(gp) when is_map(gp) do
    %{
      detected: gp["detected"] || false,
      confidence: gp["confidence"] || 0.0,
      affected_layers: gp["affected_layers"] || [],
      description: gp["description"] || ""
    }
  end
  defp parse_gradient_poisoning(_), do: %{detected: false, confidence: 0.0}

  defp parse_known_signatures(nil), do: []
  defp parse_known_signatures(sigs) when is_list(sigs) do
    Enum.map(sigs, fn s ->
      %{
        attack_name: s["attack_name"] || "",
        confidence: s["confidence"] || 0.0,
        technique_id: s["technique_id"] || "",
        references: s["references"] || []
      }
    end)
  end
  defp parse_known_signatures(_), do: []

  defp parse_signatures_response(body) when is_list(body) do
    Enum.map(body, fn sig ->
      %{
        attack_name: sig["attack_name"] || "",
        technique_id: sig["technique_id"] || "",
        pattern: sig["pattern"] || "",
        description: sig["description"] || "",
        references: sig["references"] || []
      }
    end)
  end

  defp parse_signatures_response(body) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, decoded} -> parse_signatures_response(decoded)
      {:error, _} -> []
    end
  end

  defp parse_signatures_response(_), do: []

  defp build_findings(poisoning, contamination) do
    findings = []

    # Add poisoning indicators as findings
    findings = Enum.reduce(poisoning.indicators, findings, fn ind, acc ->
      [%{
        type: :poisoning_indicator,
        severity: severity_to_atom(ind.severity),
        source: "poisoning_detector",
        evidence: ind.evidence,
        recommendation: ind.recommendation,
        mitre_technique: "AML.T0019"
      } | acc]
    end)

    # Add trigger patterns as findings
    findings = Enum.reduce(poisoning.trigger_patterns, findings, fn pat, acc ->
      [%{
        type: :trigger_pattern,
        severity: if(pat.confidence > 0.7, do: :high, else: :medium),
        source: "poisoning_detector",
        layer: pat.layer_name,
        pattern_type: pat.pattern_type,
        confidence: pat.confidence,
        description: pat.description,
        mitre_technique: "AML.T0018"
      } | acc]
    end)

    # Add known signatures as findings
    findings = Enum.reduce(contamination.known_signatures, findings, fn sig, acc ->
      [%{
        type: :known_signature,
        severity: if(sig.confidence > 0.7, do: :critical, else: :high),
        source: "contamination_detector",
        attack_name: sig.attack_name,
        confidence: sig.confidence,
        mitre_technique: sig.technique_id,
        references: sig.references
      } | acc]
    end)

    # Add gradient poisoning if detected
    findings = if contamination.gradient_poisoning.detected do
      [%{
        type: :gradient_poisoning,
        severity: if(contamination.gradient_poisoning.confidence > 0.7, do: :high, else: :medium),
        source: "contamination_detector",
        confidence: contamination.gradient_poisoning.confidence,
        affected_layers: contamination.gradient_poisoning.affected_layers,
        description: contamination.gradient_poisoning.description,
        mitre_technique: "AML.T0020"
      } | findings]
    else
      findings
    end

    Enum.reverse(findings)
  end

  defp severity_to_atom("critical"), do: :critical
  defp severity_to_atom("high"), do: :high
  defp severity_to_atom("medium"), do: :medium
  defp severity_to_atom("low"), do: :low
  defp severity_to_atom(_), do: :low

  defp extract_error_message(body, status) when is_map(body) do
    body["detail"] || body["error"] || body["message"] || "HTTP #{status}"
  end

  defp extract_error_message(body, _status) when is_binary(body), do: body
  defp extract_error_message(_, status), do: "HTTP #{status}"
end
