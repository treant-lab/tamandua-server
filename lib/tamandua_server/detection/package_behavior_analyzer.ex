defmodule TamanduaServer.Detection.PackageBehaviorAnalyzer do
  @moduledoc """
  Analyzes package installation behavior for supply chain attacks.

  Orchestrates the PackageInstallCorrelator and InstallScriptAnalyzer to detect
  anomalous behavior during package installation:
  - Suspicious command patterns in install scripts
  - Unexpected network destinations (non-package-registry)
  - Sensitive file access (.ssh, .aws, credentials)

  Generates supply chain alerts with risk categorization.
  """

  alias TamanduaServer.Detection.InstallScriptAnalyzer

  @trusted_destinations [
    # npm
    ~r/registry\.npmjs\.org/,
    ~r/npm\.pkg\.github\.com/,
    # pip
    ~r/pypi\.org/,
    ~r/files\.pythonhosted\.org/,
    # cargo
    ~r/crates\.io/,
    ~r/static\.crates\.io/,
    # gem
    ~r/rubygems\.org/,
    # go
    ~r/proxy\.golang\.org/,
    ~r/sum\.golang\.org/,
    # common CDNs
    ~r/cloudflare/,
    ~r/fastly/
  ]

  @sensitive_file_patterns [
    ~r/\.ssh[\/\\]/i,
    ~r/id_rsa|id_ed25519|id_dsa/i,
    ~r/\.aws[\/\\]credentials/i,
    ~r/\.env$/i,
    ~r/\.npmrc$/i,
    ~r/\.pypirc$/i,
    ~r/config\.json.*token/i,
    ~r/secrets?\.(json|ya?ml|env)/i,
    ~r/\.gnupg[\/\\]/i,
    ~r/\.kube[\/\\]config/i
  ]

  @doc """
  Analyze events collected during a package install window.

  ## Parameters
    - agent_id: The agent identifier
    - root_pid: The root package manager PID
    - events: List of events from PackageInstallCorrelator

  ## Returns
    - :ok if no anomalies detected
    - {:anomalous, anomalies, risk_score} if suspicious behavior found
  """
  def analyze_install_window(_agent_id, _root_pid, events) do
    # Analyze process creation command lines
    process_events = Enum.filter(events, &(&1["type"] == "process_creation"))
    command_lines = Enum.map(process_events, &(&1["command_line"]))
    script_analysis = InstallScriptAnalyzer.analyze_scripts(command_lines)

    # Check network destinations
    network_events = Enum.filter(events, &(&1["type"] == "network_connection"))
    anomalous_network = Enum.filter(network_events, &is_anomalous_network?/1)

    # Check file access
    file_events = Enum.filter(events, &(&1["type"] == "file_write"))
    sensitive_files = Enum.filter(file_events, &is_sensitive_file?/1)

    anomalies = %{
      suspicious_scripts: script_analysis,
      anomalous_network: anomalous_network,
      sensitive_file_access: sensitive_files
    }

    if has_anomalies?(anomalies) do
      risk_score = calculate_overall_risk(anomalies)
      {:anomalous, anomalies, risk_score}
    else
      :ok
    end
  end

  @doc """
  Check if a network connection is to an anomalous (non-trusted) destination.

  ## Parameters
    - event: Network connection event map

  ## Returns
    Boolean indicating if the destination is anomalous
  """
  def is_anomalous_network?(%{"destination_hostname" => hostname}) when is_binary(hostname) do
    not Enum.any?(@trusted_destinations, &Regex.match?(&1, hostname))
  end

  def is_anomalous_network?(%{"destination_ip" => ip}) when is_binary(ip) do
    # Flag external IPs (not localhost, not private ranges)
    not private_ip?(ip)
  end

  def is_anomalous_network?(_), do: false

  @doc """
  Check if a file path is sensitive (credentials, keys, etc.).

  ## Parameters
    - event: File write event map

  ## Returns
    Boolean indicating if the file is sensitive
  """
  def is_sensitive_file?(%{"file_path" => path}) when is_binary(path) do
    Enum.any?(@sensitive_file_patterns, &Regex.match?(&1, path))
  end

  def is_sensitive_file?(_), do: false

  @doc """
  Build a supply chain alert from detected anomalies.

  ## Parameters
    - agent_id: The agent identifier
    - ecosystem: Package ecosystem (:npm, :pip, :cargo, :gem, :go)
    - anomalies: Map containing detected anomalies

  ## Returns
    Map with alert structure
  """
  def build_supply_chain_alert(agent_id, ecosystem, anomalies) do
    risk_score = calculate_overall_risk(anomalies)

    %{
      type: "supply_chain",
      severity: severity_from_risk(risk_score),
      title: "Suspicious package install behavior detected",
      description: build_description(anomalies),
      enrichment: %{
        "agent_id" => agent_id,
        "ecosystem" => to_string(ecosystem),
        "risk_type" => categorize_risk(anomalies),
        "suspicious_patterns" => get_patterns(anomalies),
        "network_destinations" => get_network_destinations(anomalies),
        "sensitive_files" => get_sensitive_files(anomalies)
      },
      mitre_techniques: ["T1195.001", "T1059"],
      mitre_tactics: ["initial_access", "execution"]
    }
  end

  # Private functions

  defp private_ip?(ip) when is_binary(ip) do
    case :inet.parse_address(to_charlist(ip)) do
      {:ok, {127, _, _, _}} -> true
      {:ok, {10, _, _, _}} -> true
      {:ok, {172, b, _, _}} when b >= 16 and b <= 31 -> true
      {:ok, {192, 168, _, _}} -> true
      _ -> false
    end
  end

  defp has_anomalies?(%{
    suspicious_scripts: script_result,
    anomalous_network: network_list,
    sensitive_file_access: file_list
  }) do
    match?({:suspicious, _}, script_result) or
    not Enum.empty?(network_list) or
    not Enum.empty?(file_list)
  end

  defp calculate_overall_risk(%{
    suspicious_scripts: script_result,
    anomalous_network: network_list,
    sensitive_file_access: file_list
  }) do
    script_score = case script_result do
      {:suspicious, %{risk_score: score}} -> score
      _ -> 0.0
    end

    # Network anomalies add 0.3 per destination (capped at 0.6)
    network_score = min(length(network_list) * 0.3, 0.6)

    # Sensitive file access adds 0.5 per file (capped at 0.9)
    file_score = min(length(file_list) * 0.5, 0.9)

    # Combine using complement product
    [script_score, network_score, file_score]
    |> Enum.filter(&(&1 > 0))
    |> case do
      [] -> 0.0
      scores ->
        scores
        |> Enum.map(&(1 - &1))
        |> Enum.reduce(1.0, &(&1 * &2))
        |> then(&(1 - &1))
        |> Float.round(3)
    end
  end

  defp severity_from_risk(risk_score) when risk_score >= 0.9, do: "critical"
  defp severity_from_risk(risk_score) when risk_score >= 0.7, do: "high"
  defp severity_from_risk(risk_score) when risk_score >= 0.5, do: "medium"
  defp severity_from_risk(_), do: "low"

  defp build_description(%{
    suspicious_scripts: script_result,
    anomalous_network: network_list,
    sensitive_file_access: file_list
  }) do
    parts = []

    parts = if match?({:suspicious, _}, script_result) do
      ["Suspicious command patterns detected in install scripts" | parts]
    else
      parts
    end

    parts = if not Enum.empty?(network_list) do
      ["Unexpected network connections to #{length(network_list)} destination(s)" | parts]
    else
      parts
    end

    parts = if not Enum.empty?(file_list) do
      ["Access to #{length(file_list)} sensitive file(s)" | parts]
    else
      parts
    end

    Enum.join(parts, ". ") <> "."
  end

  defp categorize_risk(%{
    suspicious_scripts: script_result,
    anomalous_network: network_list,
    sensitive_file_access: file_list
  }) do
    script_patterns =
      case script_result do
        {:suspicious, %{patterns: patterns}} -> patterns
        _ -> []
      end

    cond do
      not Enum.empty?(file_list) -> "credential_theft"
      :code_execution in script_patterns -> "code_execution"
      not Enum.empty?(network_list) -> "data_exfiltration"
      true -> "suspicious_behavior"
    end
  end

  defp get_patterns(%{suspicious_scripts: {:suspicious, %{patterns: patterns}}}), do: Enum.map(patterns, &to_string/1)
  defp get_patterns(_), do: []

  defp get_network_destinations(%{anomalous_network: network_list}) do
    Enum.map(network_list, fn event ->
      event["destination_hostname"] || event["destination_ip"] || "unknown"
    end)
  end

  defp get_sensitive_files(%{sensitive_file_access: file_list}) do
    Enum.map(file_list, fn event ->
      event["file_path"] || "unknown"
    end)
  end
end
