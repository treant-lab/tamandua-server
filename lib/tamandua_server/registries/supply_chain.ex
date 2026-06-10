defmodule TamanduaServer.Registries.SupplyChain do
  @moduledoc """
  Supply chain security scanning for AI models.

  Provides detection for:
  - Typosquatting attacks (e.g., "metta-llama" vs "meta-llama")
  - Dependency confusion (internal package names on public registries)
  - Manifest security scanning

  All operations call the Python ML service supply chain endpoints.

  ## Example

      iex> SupplyChain.detect_typosquatting("metta-llama")
      {:ok, %{
        matches: [%{similar_to: "meta-llama", similarity_score: 0.9, ...}],
        is_suspicious: true
      }}

      iex> SupplyChain.scan_model("suspicious-model", manifest_path: "/path/to/requirements.txt")
      {:ok, %{risk_score: 0.6, findings: [...], typosquat_matches: [...]}}
  """

  require Logger

  @default_ml_service_url "http://localhost:8000"
  @timeout 30_000

  # ---------------------------------------------------------------------------
  # Type Definitions
  # ---------------------------------------------------------------------------

  @type typosquat_match :: %{
    original_name: String.t(),
    similar_to: String.t(),
    similarity_score: float(),
    match_type: String.t(),
    is_suspicious: boolean()
  }

  @type confusion_finding :: %{
    package_name: String.t(),
    internal_namespace: String.t(),
    public_registry: String.t(),
    risk_level: String.t(),
    description: String.t()
  }

  @type scan_result :: %{
    findings: [confusion_finding()],
    typosquat_matches: [typosquat_match()],
    risk_score: float(),
    recommendations: [String.t()],
    scanned_files: [String.t()],
    analysis_time_ms: integer()
  }

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  @doc """
  Scan a model for supply chain security issues.

  Performs typosquatting detection and optional manifest scanning.

  ## Parameters

    * `model_name` - Name of the model to scan
    * `opts` - Options:
      * `:manifest_path` - Optional path to manifest file (requirements.txt, etc.)

  ## Returns

    * `{:ok, scan_result()}` - Scan completed
    * `{:error, reason}` - Scan failed

  ## Example

      iex> SupplyChain.scan_model("my-model", manifest_path: "/path/to/requirements.txt")
      {:ok, %{risk_score: 0.0, findings: [], typosquat_matches: []}}
  """
  @spec scan_model(String.t(), keyword()) :: {:ok, scan_result()} | {:error, String.t()}
  def scan_model(model_name, opts \\ []) when is_binary(model_name) do
    url = "#{ml_service_url()}/api/v1/security/supply-chain/scan"

    body = %{
      "model_name" => model_name,
      "manifest_path" => Keyword.get(opts, :manifest_path)
    }

    Logger.info("[SupplyChain] Scanning model: #{model_name}")

    case Req.post(url,
      json: body,
      receive_timeout: @timeout,
      connect_options: [timeout: 10_000]
    ) do
      {:ok, %{status: 200, body: response}} ->
        {:ok, parse_scan_result(response)}

      {:ok, %{status: status, body: body}} ->
        error_msg = extract_error_message(body, status)
        {:error, "ML service returned #{status}: #{error_msg}"}

      {:error, reason} ->
        {:error, "ML service request failed: #{inspect(reason)}"}
    end
  end

  @doc """
  Check a model name for typosquatting against popular models.

  ## Parameters

    * `model_name` - Model name to check

  ## Returns

    * `{:ok, result}` - Check completed with matches
    * `{:error, reason}` - Check failed

  ## Example

      iex> SupplyChain.detect_typosquatting("metta-llama")
      {:ok, %{
        matches: [%{similar_to: "meta-llama", similarity_score: 0.9}],
        is_suspicious: true
      }}
  """
  @spec detect_typosquatting(String.t()) :: {:ok, map()} | {:error, String.t()}
  def detect_typosquatting(model_name) when is_binary(model_name) do
    url = "#{ml_service_url()}/api/v1/security/supply-chain/typosquat"

    body = %{"model_name" => model_name}

    case Req.post(url,
      json: body,
      receive_timeout: @timeout,
      connect_options: [timeout: 10_000]
    ) do
      {:ok, %{status: 200, body: response}} ->
        {:ok, parse_typosquat_response(response)}

      {:ok, %{status: status, body: body}} ->
        error_msg = extract_error_message(body, status)
        {:error, "ML service returned #{status}: #{error_msg}"}

      {:error, reason} ->
        {:error, "ML service request failed: #{inspect(reason)}"}
    end
  end

  @doc """
  Check a manifest for dependency confusion vulnerabilities.

  ## Parameters

    * `manifest` - Map with "dependencies" key containing package list

  ## Returns

    * `{:ok, result}` - Check completed with findings
    * `{:error, reason}` - Check failed

  ## Example

      iex> SupplyChain.check_dependency_confusion(%{"dependencies" => ["numpy", "internal-utils"]})
      {:ok, %{findings: [...], risk_level: "medium"}}
  """
  @spec check_dependency_confusion(map()) :: {:ok, map()} | {:error, String.t()}
  def check_dependency_confusion(manifest) when is_map(manifest) do
    url = "#{ml_service_url()}/api/v1/security/supply-chain/dependency-confusion"

    body = %{"manifest" => manifest}

    case Req.post(url,
      json: body,
      receive_timeout: @timeout,
      connect_options: [timeout: 10_000]
    ) do
      {:ok, %{status: 200, body: response}} ->
        {:ok, parse_confusion_response(response)}

      {:ok, %{status: status, body: body}} ->
        error_msg = extract_error_message(body, status)
        {:error, "ML service returned #{status}: #{error_msg}"}

      {:error, reason} ->
        {:error, "ML service request failed: #{inspect(reason)}"}
    end
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  defp ml_service_url do
    Application.get_env(:tamandua_server, :ml_service_url, @default_ml_service_url)
  end

  defp parse_scan_result(response) when is_map(response) do
    %{
      findings: parse_findings(response["findings"]),
      typosquat_matches: parse_typosquat_matches(response["typosquat_matches"]),
      risk_score: response["risk_score"] || 0.0,
      recommendations: response["recommendations"] || [],
      scanned_files: response["scanned_files"] || [],
      analysis_time_ms: response["analysis_time_ms"] || 0
    }
  end

  defp parse_scan_result(_), do: %{risk_score: 0.0, findings: [], typosquat_matches: []}

  defp parse_typosquat_response(response) when is_map(response) do
    %{
      matches: parse_typosquat_matches(response["matches"]),
      is_suspicious: response["is_suspicious"] || false,
      analysis_time_ms: response["analysis_time_ms"] || 0
    }
  end

  defp parse_typosquat_response(_), do: %{matches: [], is_suspicious: false}

  defp parse_confusion_response(response) when is_map(response) do
    %{
      findings: parse_findings(response["findings"]),
      risk_level: response["risk_level"] || "low",
      analysis_time_ms: response["analysis_time_ms"] || 0
    }
  end

  defp parse_confusion_response(_), do: %{findings: [], risk_level: "low"}

  defp parse_findings(nil), do: []
  defp parse_findings(findings) when is_list(findings) do
    Enum.map(findings, fn f ->
      %{
        package_name: f["package_name"] || "",
        internal_namespace: f["internal_namespace"] || "",
        public_registry: f["public_registry"] || "",
        risk_level: f["risk_level"] || "low",
        description: f["description"] || ""
      }
    end)
  end
  defp parse_findings(_), do: []

  defp parse_typosquat_matches(nil), do: []
  defp parse_typosquat_matches(matches) when is_list(matches) do
    Enum.map(matches, fn m ->
      %{
        original_name: m["original_name"] || "",
        similar_to: m["similar_to"] || "",
        similarity_score: m["similarity_score"] || 0.0,
        match_type: m["match_type"] || "",
        is_suspicious: m["is_suspicious"] || false
      }
    end)
  end
  defp parse_typosquat_matches(_), do: []

  defp extract_error_message(body, status) when is_map(body) do
    body["detail"] || body["error"] || body["message"] || "HTTP #{status}"
  end

  defp extract_error_message(body, _status) when is_binary(body), do: body
  defp extract_error_message(_, status), do: "HTTP #{status}"
end
