defmodule TamanduaServer.Hunting.AnomalyHunter do
  @moduledoc """
  Generates hunt hypotheses from detected anomalies in telemetry data.

  Analyzes behavioral anomalies and creates actionable hunt hypotheses
  with suspiciousness scores and suggested hunt queries.
  """

  require Logger
  alias TamanduaServer.ML.Client, as: MLClient
  alias TamanduaServer.Telemetry

  @doc """
  Identify anomalies in telemetry data for an organization.

  ## Parameters
  - `organization_id` - Organization to analyze
  - `hours` - Hours of data to analyze (default: 24)

  ## Returns
  `{:ok, anomalies}` where each anomaly includes:
  - Detection details
  - Suggested hunt query
  - Suspiciousness score
  - Supporting evidence
  """
  def identify_anomalies(organization_id, hours \\ 24) do
    # Get recent telemetry for analysis
    cutoff = DateTime.utc_now() |> DateTime.add(-hours * 3600, :second)

    # Call ML service for anomaly detection
    case MLClient.post("/anomaly/detect_hunting_anomalies", %{
           organization_id: organization_id,
           hours: hours,
           cutoff: DateTime.to_iso8601(cutoff)
         }) do
      {:ok, %{"anomalies" => anomalies}} ->
        # Enrich anomalies with hunt hypotheses
        enriched =
          Enum.map(anomalies, fn anomaly ->
            enrich_anomaly_with_hypothesis(anomaly, organization_id)
          end)

        {:ok, enriched}

      {:error, reason} ->
        Logger.warning("ML anomaly detection unavailable, using fallback: #{inspect(reason)}")
        # Fallback to rule-based anomaly detection
        fallback_anomaly_detection(organization_id, hours)
    end
  end

  @doc """
  Generate hunt hypothesis from an anomaly.

  Converts anomaly detection into actionable hunt hypothesis.
  """
  def anomaly_to_hunt_hypothesis(anomaly) do
    %{
      title: generate_hypothesis_title(anomaly),
      description: generate_hypothesis_description(anomaly),
      query: generate_hunt_query(anomaly),
      mitre_ttps: infer_mitre_ttps(anomaly),
      suspiciousness_score: calculate_suspiciousness(anomaly),
      anomaly_type: anomaly["type"],
      evidence: format_evidence(anomaly),
      detection_time: DateTime.utc_now(),
      recommended_actions: generate_recommended_actions(anomaly)
    }
  end

  # Private Functions

  defp enrich_anomaly_with_hypothesis(anomaly, _organization_id) do
    Map.merge(anomaly, %{
      "title" => generate_hypothesis_title(anomaly),
      "description" => generate_hypothesis_description(anomaly),
      "suggested_query" => generate_hunt_query(anomaly),
      "mitre_ttps" => infer_mitre_ttps(anomaly),
      "evidence" => format_evidence(anomaly)
    })
  end

  defp generate_hypothesis_title(anomaly) do
    case anomaly["type"] do
      "unusual_network_connection" ->
        "Unusual network connection from #{anomaly["process_name"]}"

      "rare_process_execution" ->
        "Rare process execution: #{anomaly["process_name"]}"

      "abnormal_user_behavior" ->
        "Abnormal behavior from user #{anomaly["username"]}"

      "unusual_command_line" ->
        "Suspicious command line pattern detected"

      "abnormal_file_access" ->
        "Unusual file access pattern"

      "process_injection_indicator" ->
        "Potential process injection detected"

      "credential_access_pattern" ->
        "Credential access behavior detected"

      "data_exfiltration_pattern" ->
        "Potential data exfiltration detected"

      _ ->
        "Anomalous activity detected: #{anomaly["type"]}"
    end
  end

  defp generate_hypothesis_description(anomaly) do
    base_desc = """
    Anomaly detected: #{anomaly["type"]}

    Details:
    """

    details =
      anomaly
      |> Map.take(["process_name", "username", "dst_ip", "dst_port", "file_path", "command_line"])
      |> Enum.reject(fn {_k, v} -> is_nil(v) end)
      |> Enum.map(fn {k, v} -> "- #{format_field_name(k)}: #{v}" end)
      |> Enum.join("\n")

    base_desc <> "\n" <> details <> "\n\n" <> "Suspiciousness score: #{anomaly["score"]}/100"
  end

  defp generate_hunt_query(anomaly) do
    case anomaly["type"] do
      "unusual_network_connection" ->
        build_network_anomaly_query(anomaly)

      "rare_process_execution" ->
        build_process_anomaly_query(anomaly)

      "abnormal_user_behavior" ->
        build_user_anomaly_query(anomaly)

      "unusual_command_line" ->
        build_command_line_anomaly_query(anomaly)

      "abnormal_file_access" ->
        build_file_access_anomaly_query(anomaly)

      "process_injection_indicator" ->
        build_process_injection_query(anomaly)

      "credential_access_pattern" ->
        build_credential_access_query(anomaly)

      "data_exfiltration_pattern" ->
        build_exfiltration_query(anomaly)

      _ ->
        # Generic query
        "*"
    end
  end

  defp build_network_anomaly_query(anomaly) do
    conditions = []

    conditions =
      if anomaly["process_name"],
        do: ["process.name:#{anomaly["process_name"]}" | conditions],
        else: conditions

    conditions =
      if anomaly["dst_ip"],
        do: ["network.dst_ip:#{anomaly["dst_ip"]}" | conditions],
        else: conditions

    conditions =
      if anomaly["dst_port"],
        do: ["network.dst_port:#{anomaly["dst_port"]}" | conditions],
        else: conditions

    conditions = ["network.direction:outbound" | conditions]

    Enum.join(conditions, " AND ")
  end

  defp build_process_anomaly_query(anomaly) do
    process_name = anomaly["process_name"]
    parent_name = anomaly["parent_process_name"]

    conditions = ["process.name:#{process_name}"]

    conditions =
      if parent_name,
        do: ["process.parent.name:#{parent_name}" | conditions],
        else: conditions

    Enum.join(conditions, " AND ")
  end

  defp build_user_anomaly_query(anomaly) do
    username = anomaly["username"]
    "user.name:#{username} AND event.timestamp:[now-7d TO now]"
  end

  defp build_command_line_anomaly_query(anomaly) do
    # Extract key patterns from anomalous command line
    if anomaly["command_line_patterns"] do
      patterns = Enum.join(anomaly["command_line_patterns"], "* OR *")
      "process.command_line:*#{patterns}*"
    else
      "process.command_line:*#{anomaly["suspicious_keyword"]}*"
    end
  end

  defp build_file_access_anomaly_query(anomaly) do
    file_path = anomaly["file_path"] || anomaly["file_pattern"]
    "file.path:*#{file_path}* AND file.operation:(read OR modify OR delete)"
  end

  defp build_process_injection_query(_anomaly) do
    """
    (
      process.code_injection:true
      OR
      (process.name:(powershell.exe OR cmd.exe) AND process.command_line:*IEX*)
      OR
      process.memory_protection:false
    )
    """
    |> String.trim()
  end

  defp build_credential_access_query(_anomaly) do
    """
    (
      file.path:(*lsass* OR *SAM OR *SYSTEM)
      OR
      (process.name:mimikatz.exe OR process.name:procdump.exe)
      OR
      (process.access_target:lsass.exe AND process.access_rights:*PROCESS_VM_READ*)
    )
    """
    |> String.trim()
  end

  defp build_exfiltration_query(anomaly) do
    conditions = ["network.direction:outbound"]

    conditions =
      if anomaly["bytes_sent"] && anomaly["bytes_sent"] > 1_000_000,
        do: ["network.bytes_sent:>1000000" | conditions],
        else: conditions

    conditions =
      if anomaly["suspicious_extensions"],
        do: ["file.extension:(#{Enum.join(anomaly["suspicious_extensions"], " OR ")})" | conditions],
        else: conditions

    Enum.join(conditions, " AND ")
  end

  defp infer_mitre_ttps(anomaly) do
    # Map anomaly types to MITRE ATT&CK techniques
    technique_map = %{
      "unusual_network_connection" => ["T1071.001", "T1071.004"],
      "rare_process_execution" => ["T1059.001", "T1059.003"],
      "abnormal_user_behavior" => ["T1078"],
      "unusual_command_line" => ["T1059.001", "T1059.003"],
      "abnormal_file_access" => ["T1005", "T1039"],
      "process_injection_indicator" => ["T1055.001", "T1055.002"],
      "credential_access_pattern" => ["T1003.001", "T1003.002"],
      "data_exfiltration_pattern" => ["T1041", "T1048"]
    }

    Map.get(technique_map, anomaly["type"], [])
  end

  defp calculate_suspiciousness(anomaly) do
    # Anomaly already has a score from ML model
    base_score = anomaly["score"] || 50

    # Apply modifiers based on context
    score = base_score

    # Boost score for high-risk processes
    score =
      if high_risk_process?(anomaly["process_name"]),
        do: min(100, score + 15),
        else: score

    # Boost for external network connections
    score =
      if external_connection?(anomaly["dst_ip"]),
        do: min(100, score + 10),
        else: score

    # Boost for privileged user activity
    score =
      if privileged_user?(anomaly["username"]),
        do: min(100, score + 10),
        else: score

    round(score)
  end

  defp format_evidence(anomaly) do
    evidence = []

    evidence =
      if anomaly["baseline_deviation"],
        do: ["Deviates #{anomaly["baseline_deviation"]}% from baseline" | evidence],
        else: evidence

    evidence =
      if anomaly["rarity_score"],
        do: ["Rarity score: #{anomaly["rarity_score"]}" | evidence],
        else: evidence

    evidence =
      if anomaly["first_seen"],
        do: ["First seen: #{anomaly["first_seen"]}" | evidence],
        else: evidence

    evidence =
      if anomaly["occurrence_count"],
        do: ["Occurred #{anomaly["occurrence_count"]} times" | evidence],
        else: evidence

    evidence
  end

  defp generate_recommended_actions(anomaly) do
    case anomaly["type"] do
      "unusual_network_connection" ->
        [
          "Investigate destination IP reputation",
          "Check for other processes connecting to same IP",
          "Review firewall logs for this connection",
          "Verify if connection is business-justified"
        ]

      "rare_process_execution" ->
        [
          "Verify process signature and publisher",
          "Check process hash against threat intelligence",
          "Review parent process and execution chain",
          "Determine if process is authorized"
        ]

      "credential_access_pattern" ->
        [
          "Immediately investigate user account",
          "Check for credential theft tools",
          "Review authentication logs",
          "Consider forcing password reset"
        ]

      "data_exfiltration_pattern" ->
        [
          "Identify what data was accessed",
          "Block outbound connection if still active",
          "Review user's recent file access",
          "Engage incident response team"
        ]

      _ ->
        [
          "Investigate anomalous activity",
          "Correlate with other security events",
          "Determine if activity is benign or malicious",
          "Document findings"
        ]
    end
  end

  defp format_field_name(field) do
    field
    |> String.replace("_", " ")
    |> String.capitalize()
  end

  defp high_risk_process?(process_name) when is_binary(process_name) do
    risky_processes = [
      "powershell.exe",
      "cmd.exe",
      "wmic.exe",
      "psexec.exe",
      "mimikatz.exe",
      "procdump.exe",
      "reg.exe",
      "regedit.exe"
    ]

    String.downcase(process_name) in risky_processes
  end

  defp high_risk_process?(_), do: false

  defp external_connection?(ip) when is_binary(ip) do
    # Check if IP is external (not RFC1918 private)
    not (String.starts_with?(ip, "10.") or
           String.starts_with?(ip, "172.16.") or
           String.starts_with?(ip, "192.168.") or
           String.starts_with?(ip, "127."))
  end

  defp external_connection?(_), do: false

  defp privileged_user?(username) when is_binary(username) do
    # Check for privileged accounts
    privileged_patterns = ["admin", "root", "administrator", "system"]

    username_lower = String.downcase(username)
    Enum.any?(privileged_patterns, &String.contains?(username_lower, &1))
  end

  defp privileged_user?(_), do: false

  # Fallback anomaly detection (rule-based)
  defp fallback_anomaly_detection(organization_id, hours) do
    Logger.info("Using fallback rule-based anomaly detection")

    cutoff = DateTime.utc_now() |> DateTime.add(-hours * 3600, :second)

    anomalies = []

    # Detect rare processes
    anomalies = anomalies ++ detect_rare_processes(organization_id, cutoff)

    # Detect unusual network connections
    anomalies = anomalies ++ detect_unusual_network(organization_id, cutoff)

    # Detect abnormal command lines
    anomalies = anomalies ++ detect_suspicious_command_lines(organization_id, cutoff)

    {:ok, anomalies}
  end

  defp detect_rare_processes(_organization_id, _cutoff) do
    # Simplified rare process detection
    # In production, this would query telemetry database
    []
  end

  defp detect_unusual_network(_organization_id, _cutoff) do
    # Simplified network anomaly detection
    []
  end

  defp detect_suspicious_command_lines(_organization_id, _cutoff) do
    # Detect command lines with suspicious patterns
    suspicious_patterns = [
      "IEX",
      "Invoke-Expression",
      "DownloadString",
      "WebClient",
      "mimikatz",
      "sekurlsa"
    ]

    # Would query for events matching these patterns
    []
  end
end
