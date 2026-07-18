defmodule TamanduaServer.Detection.CredentialDetector do
  @moduledoc """
  Detects exposed API keys and credentials in ML workflows.

  Scans process environment variables, file contents, and command lines
  for patterns matching known ML service credentials:
  - HuggingFace: HF_TOKEN (hf_[a-zA-Z0-9]{34})
  - OpenAI: OPENAI_API_KEY (sk-[a-zA-Z0-9]{48})
  - AWS: AWS_ACCESS_KEY_ID (AKIA[0-9A-Z]{16}), AWS_SECRET_ACCESS_KEY
  - Anthropic: ANTHROPIC_API_KEY (sk-ant-[a-zA-Z0-9-]{48})
  - Google AI: GOOGLE_API_KEY, GOOGLE_CLOUD_API_KEY
  - Cohere: COHERE_API_KEY (co-[a-zA-Z0-9]{40})
  - Replicate: REPLICATE_API_TOKEN (r8_[a-zA-Z0-9]{40})

  ## Examples

      # Process event with exposed HF_TOKEN
      event = %{
        "event_type" => "process_create",
        "payload" => %{
          "environment" => %{"HF_TOKEN" => "hf_abcd1234567890abcd1234567890abcdef"}
        }
      }
      CredentialDetector.detect_credentials(event)
      # => {:ok, [%{type: :credential_exposure, credential_type: "HuggingFace Token", ...}]}

      # File content scan
      CredentialDetector.scan_for_secrets("OPENAI_API_KEY=sk-abcd1234...")
      # => [{"OpenAI API Key", "sk-abcd...", "openai", "critical"}]

      # Check sensitive files
      CredentialDetector.sensitive_file?(".env")
      # => true
  """

  require Logger

  @doc "Returns all credential patterns for external use"
  @spec credential_patterns() :: [map()]
  def credential_patterns do
    [
      %{
      name: "HuggingFace Token",
      env_var: "HF_TOKEN",
      pattern: ~r/hf_[a-zA-Z0-9]{34}/,
      service: "huggingface",
      severity: "high",
      mitre_technique: "T1552.001"
    },
    %{
      name: "OpenAI API Key",
      env_var: "OPENAI_API_KEY",
      pattern: ~r/sk-[a-zA-Z0-9]{48}/,
      service: "openai",
      severity: "critical",
      mitre_technique: "T1552.001"
    },
    %{
      name: "AWS Access Key ID",
      env_var: "AWS_ACCESS_KEY_ID",
      pattern: ~r/AKIA[0-9A-Z]{16}/,
      service: "aws",
      severity: "critical",
      mitre_technique: "T1552.001"
    },
    %{
      name: "AWS Secret Access Key",
      env_var: "AWS_SECRET_ACCESS_KEY",
      pattern: ~r/[A-Za-z0-9\/+=]{40}/,
      service: "aws",
      severity: "critical",
      mitre_technique: "T1552.001",
      context_required: true
    },
    %{
      name: "Anthropic API Key",
      env_var: "ANTHROPIC_API_KEY",
      pattern: ~r/sk-ant-[a-zA-Z0-9\-]{48}/,
      service: "anthropic",
      severity: "critical",
      mitre_technique: "T1552.001"
    },
    %{
      name: "Google AI API Key",
      env_var: "GOOGLE_API_KEY",
      pattern: ~r/AIza[0-9A-Za-z\-_]{35}/,
      service: "google",
      severity: "high",
      mitre_technique: "T1552.001"
    },
    %{
      name: "Cohere API Key",
      env_var: "COHERE_API_KEY",
      pattern: ~r/co-[a-zA-Z0-9]{40}/,
      service: "cohere",
      severity: "high",
      mitre_technique: "T1552.001"
    },
    %{
      name: "Replicate API Token",
      env_var: "REPLICATE_API_TOKEN",
      pattern: ~r/r8_[a-zA-Z0-9]{40}/,
      service: "replicate",
      severity: "high",
      mitre_technique: "T1552.001"
      }
    ]
  end

  @sensitive_file_patterns [
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".ipynb",
    "config.json",
    "config.yaml",
    "config.yml",
    "settings.py",
    "credentials.json",
    "credentials.yaml",
    "secrets.json",
    "secrets.yaml"
  ]

  @sensitive_file_keywords ["token", "key", "secret", "credential", "password"]

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Detect credentials in a telemetry event.

  Checks:
  - Process environment variables for exposed credentials
  - File paths for sensitive config files
  - Command lines for hardcoded credentials

  Returns {:ok, [detection]} or {:ok, []} if no credentials found.

  ## Parameters
    - event: Map containing event_type and payload

  ## Returns
    - `{:ok, [detection_map]}` - List of detected credentials (may be empty)

  ## Examples

      event = %{
        "event_type" => "process_create",
        "payload" => %{
          "environment" => %{"HF_TOKEN" => "hf_abcd1234567890abcd1234567890abcdef"}
        }
      }
      CredentialDetector.detect_credentials(event)
      # => {:ok, [%{type: :credential_exposure, credential_type: "HuggingFace Token", ...}]}
  """
  @spec detect_credentials(map()) :: {:ok, [map()]}
  def detect_credentials(event) when is_map(event) do
    detections = []

    event_type = to_string(event[:event_type] || event["event_type"] || "")
    payload = event[:payload] || event["payload"] || %{}

    # 1. Check environment variables
    detections = case check_environment_variables(payload, event_type) do
      [] -> detections
      env_detections -> detections ++ env_detections
    end

    # 2. Check command line
    detections = case check_command_line(payload) do
      [] -> detections
      cmdline_detections -> detections ++ cmdline_detections
    end

    # 3. Check file access patterns
    detections = case check_file_patterns(payload, event_type) do
      [] -> detections
      file_detections -> detections ++ file_detections
    end

    {:ok, detections}
  end
  def detect_credentials(_), do: {:ok, []}

  @doc """
  Scan arbitrary text content for secrets.

  Returns list of {pattern_name, matched_value_preview, service, severity} tuples.

  ## Parameters
    - content: String to scan for secrets

  ## Returns
    List of tuples: `{pattern_name, value_preview, service, severity}`

  ## Examples

      CredentialDetector.scan_for_secrets("HF_TOKEN=hf_abcd1234567890abcd1234567890abcdef")
      # => [{"HuggingFace Token", "hf_abcd...", "huggingface", "high"}]
  """
  @spec scan_for_secrets(String.t()) :: [{String.t(), String.t(), String.t(), String.t()}]
  def scan_for_secrets(content) when is_binary(content) do
    credential_patterns()
    |> Enum.filter(fn pattern ->
      # Skip context-required patterns (AWS secret) unless we have context
      not Map.get(pattern, :context_required, false)
    end)
    |> Enum.flat_map(fn pattern ->
      case Regex.scan(pattern.pattern, content) do
        [] -> []
        matches ->
          matches
          |> Enum.map(fn [match | _] ->
            {
              pattern.name,
              redact_value(match),
              pattern.service,
              pattern.severity
            }
          end)
      end
    end)
    |> Enum.uniq()
  end
  def scan_for_secrets(_), do: []

  @doc """
  Check if a file path indicates a sensitive config file.

  ## Parameters
    - path: String file path to check

  ## Returns
    - `true` if file is sensitive
    - `false` otherwise

  ## Examples

      CredentialDetector.sensitive_file?(".env")
      # => true

      CredentialDetector.sensitive_file?("/path/to/config.json")
      # => true

      CredentialDetector.sensitive_file?("/path/to/model.safetensors")
      # => false
  """
  @spec sensitive_file?(String.t()) :: boolean()
  def sensitive_file?(path) when is_binary(path) do
    path_lower = String.downcase(path)
    basename = Path.basename(path_lower)

    # Check exact matches
    exact_match = Enum.any?(@sensitive_file_patterns, fn pattern ->
      String.ends_with?(path_lower, pattern)
    end)

    # Check keyword matches
    keyword_match = Enum.any?(@sensitive_file_keywords, fn keyword ->
      String.contains?(basename, keyword)
    end)

    exact_match or keyword_match
  end
  def sensitive_file?(_), do: false

  # ============================================================================
  # Private Functions - Environment Variable Checking
  # ============================================================================

  defp check_environment_variables(payload, event_type) do
    environment = payload[:environment] || payload["environment"] || payload[:env] || payload["env"]

    if is_map(environment) and event_type in ["process_create", "process_creation"] do
      environment
      |> Enum.flat_map(fn {key, value} ->
        check_env_pair(key, value)
      end)
    else
      []
    end
  end

  defp check_env_pair(key, value) do
    key_str = to_string(key)
    value_str = to_string(value)

    # Check if env var name matches known credential env vars
    matched_patterns = credential_patterns()
    |> Enum.filter(fn pattern ->
      pattern.env_var == key_str
    end)

    # Also check value patterns
    value_matches = credential_patterns()
    |> Enum.filter(fn pattern ->
      # Skip context-required unless key provides context
      if Map.get(pattern, :context_required, false) do
        has_aws_context?(key_str)
      else
        true
      end
    end)
    |> Enum.filter(fn pattern ->
      Regex.match?(pattern.pattern, value_str)
    end)

    # Combine matches
    all_matches = Enum.uniq(matched_patterns ++ value_matches)

    Enum.map(all_matches, fn pattern ->
      %{
        type: :credential_exposure,
        credential_type: pattern.name,
        service: pattern.service,
        severity: pattern.severity,
        source: "environment_variable",
        context: %{
          env_var: key_str,
          value_preview: redact_value(value_str),
          file_path: nil
        },
        mitre_tactics: ["credential_access"],
        mitre_techniques: [pattern.mitre_technique]
      }
    end)
  end

  defp has_aws_context?(key_str) do
    String.contains?(String.downcase(key_str), "aws") or
    String.contains?(String.downcase(key_str), "amazon")
  end

  # ============================================================================
  # Private Functions - Command Line Checking
  # ============================================================================

  defp check_command_line(payload) do
    cmdline = payload[:cmdline] || payload["cmdline"] || payload[:command_line] || payload["command_line"]

    if is_binary(cmdline) do
      credential_patterns()
      |> Enum.filter(fn pattern ->
        # Skip context-required patterns in cmdline
        not Map.get(pattern, :context_required, false)
      end)
      |> Enum.flat_map(fn pattern ->
        case Regex.scan(pattern.pattern, cmdline) do
          [] -> []
          matches ->
            matches
            |> Enum.map(fn [match | _] ->
              %{
                type: :credential_exposure,
                credential_type: pattern.name,
                service: pattern.service,
                severity: pattern.severity,
                source: "command_line",
                context: %{
                  env_var: nil,
                  value_preview: redact_value(match),
                  file_path: nil,
                  command_preview: redact_cmdline(cmdline, match)
                },
                mitre_tactics: ["credential_access"],
                mitre_techniques: [pattern.mitre_technique]
              }
            end)
        end
      end)
      |> Enum.uniq_by(fn d -> {d.credential_type, d.context.value_preview} end)
    else
      []
    end
  end

  defp redact_cmdline(cmdline, matched_value) do
    cmdline
    |> String.replace(matched_value, redact_value(matched_value))
    |> String.slice(0, 200)
  end

  # ============================================================================
  # Private Functions - File Pattern Checking
  # ============================================================================

  defp check_file_patterns(payload, event_type) do
    if event_type in ["file_create", "file_modify", "file_access", "file_read"] do
      path = payload[:path] || payload["path"] || payload[:target_filename] || payload["target_filename"]

      if is_binary(path) and sensitive_file?(path) do
        # Create a detection for accessing sensitive file
        [%{
          type: :credential_exposure,
          credential_type: "Sensitive File Access",
          service: "filesystem",
          severity: "medium",
          source: "file_content",
          context: %{
            env_var: nil,
            value_preview: nil,
            file_path: path
          },
          mitre_tactics: ["credential_access"],
          mitre_techniques: ["T1552.001"]
        }]
      else
        []
      end
    else
      []
    end
  end

  # ============================================================================
  # Private Functions - Helpers
  # ============================================================================

  @doc """
  Redact a credential value for safe logging.
  Shows first 8 characters followed by "...".

  ## Examples

      iex> CredentialDetector.redact_value("hf_abcd1234567890abcd1234567890abcdef")
      "hf_abcd1..."

      iex> CredentialDetector.redact_value("short")
      "short"
  """
  @spec redact_value(String.t()) :: String.t()
  def redact_value(value) when is_binary(value) do
    if String.length(value) > 8 do
      String.slice(value, 0, 8) <> "..."
    else
      value
    end
  end
  def redact_value(_), do: "***"

  @doc """
  Check if a file is a Jupyter notebook.

  ## Examples

      iex> CredentialDetector.is_jupyter_notebook?("model.ipynb")
      true

      iex> CredentialDetector.is_jupyter_notebook?("config.json")
      false
  """
  @spec is_jupyter_notebook?(String.t()) :: boolean()
  def is_jupyter_notebook?(path) when is_binary(path) do
    String.ends_with?(String.downcase(path), ".ipynb")
  end
  def is_jupyter_notebook?(_), do: false

  @doc """
  Parse Jupyter notebook cells from JSON content.
  Extracts code cells for deep credential scanning.

  ## Parameters
    - json_content: String containing notebook JSON

  ## Returns
    - `{:ok, [code_cell_source]}` on success
    - `{:error, reason}` on parse failure

  ## Examples

      iex> notebook = ~s({"cells": [{"cell_type": "code", "source": ["import os"]}]})
      iex> CredentialDetector.parse_notebook_cells(notebook)
      {:ok, ["import os"]}
  """
  @spec parse_notebook_cells(String.t()) :: {:ok, [String.t()]} | {:error, term()}
  def parse_notebook_cells(json_content) when is_binary(json_content) do
    try do
      case Jason.decode(json_content) do
        {:ok, %{"cells" => cells}} when is_list(cells) ->
          code_sources = cells
          |> Enum.filter(fn cell ->
            is_map(cell) and Map.get(cell, "cell_type") == "code"
          end)
          |> Enum.flat_map(fn cell ->
            source = Map.get(cell, "source", [])
            if is_list(source) do
              [Enum.join(source, "\n")]
            else
              [to_string(source)]
            end
          end)

          {:ok, code_sources}

        {:ok, _} ->
          {:error, "Invalid notebook format: missing cells"}

        {:error, reason} ->
          {:error, reason}
      end
    rescue
      e ->
        {:error, Exception.message(e)}
    end
  end
  def parse_notebook_cells(_), do: {:error, "Invalid input"}
end
