defmodule TamanduaServer.Hunting.QuerySuggester do
  @moduledoc """
  Generates intelligent hunt query suggestions based on alerts and patterns.

  Uses a combination of rule-based heuristics and ML-powered query generation.
  """

  require Logger
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.ML.Client, as: MLClient

  @doc """
  Suggest hunt queries based on an alert.

  Returns multiple query suggestions to hunt for similar or related activity.
  """
  def suggest_from_alert(%Alert{} = alert, organization_id) do
    # Generate suggestions from multiple strategies
    suggestions =
      [
        # Rule-based suggestions
        suggest_similar_activity(alert),
        suggest_lateral_movement(alert),
        suggest_persistence_check(alert),
        suggest_related_ttps(alert),

        # ML-powered suggestions
        ml_powered_suggestions(alert, organization_id)
      ]
      |> List.flatten()
      |> Enum.filter(& &1 != nil)
      |> Enum.uniq_by(& &1.query)

    suggestions
  end

  @doc """
  Generate hunt query from alert characteristics.

  Creates a TQL query that captures the essence of the alert.
  """
  def generate_hunt_query_from_alert(%Alert{} = alert) do
    query_parts = []

    # Add process-based conditions
    query_parts =
      if alert.process_name do
        ["process.name:#{alert.process_name}" | query_parts]
      else
        query_parts
      end

    # Add file-based conditions
    query_parts =
      if alert.file_path do
        ["file.path:*#{Path.basename(alert.file_path)}*" | query_parts]
      else
        query_parts
      end

    # Add network-based conditions
    query_parts =
      if alert.network_info do
        network_conditions = build_network_conditions(alert.network_info)
        [network_conditions | query_parts]
      else
        query_parts
      end

    # Add IOC-based conditions
    query_parts =
      if alert.iocs && length(alert.iocs) > 0 do
        ioc_conditions = build_ioc_conditions(alert.iocs)
        query_parts ++ ioc_conditions
      else
        query_parts
      end

    # Combine with OR if multiple conditions
    if length(query_parts) > 1 do
      "(#{Enum.join(query_parts, ") OR (")})"
    else
      Enum.join(query_parts, " AND ")
    end
  end

  # Private Functions

  defp suggest_similar_activity(alert) do
    %{
      title: "Find similar #{alert.title}",
      query: generate_similar_query(alert),
      description: "Hunt for similar activity patterns in the last 7 days",
      confidence: 90,
      source: "pattern_matching",
      mitre_ttps: alert.mitre_techniques || [],
      reasoning: "Looks for exact or similar patterns to the original alert"
    }
  end

  defp suggest_lateral_movement(alert) do
    # Check if alert involves network activity or authentication
    if involves_lateral_movement?(alert) do
      %{
        title: "Hunt for lateral movement from #{alert.agent_hostname || "this host"}",
        query: build_lateral_movement_query(alert),
        description: "Search for signs of lateral movement (SMB, RDP, WinRM)",
        confidence: 75,
        source: "ttp_correlation",
        mitre_ttps: ["T1021.001", "T1021.002", "T1021.006"] ++ (alert.mitre_techniques || []),
        reasoning: "Alert involves network/auth activity suggesting potential lateral movement"
      }
    else
      nil
    end
  end

  defp suggest_persistence_check(alert) do
    # Check if alert involves persistence mechanisms
    if involves_persistence?(alert) do
      %{
        title: "Check for persistence mechanisms",
        query: build_persistence_query(alert),
        description: "Hunt for common persistence techniques (registry, scheduled tasks, services)",
        confidence: 80,
        source: "ttp_correlation",
        mitre_ttps: ["T1547", "T1053", "T1543"] ++ (alert.mitre_techniques || []),
        reasoning: "Alert suggests possible persistence establishment"
      }
    else
      nil
    end
  end

  defp suggest_related_ttps(alert) do
    # Suggest hunting for related MITRE techniques
    if alert.mitre_techniques && length(alert.mitre_techniques) > 0 do
      related_ttps = get_related_mitre_techniques(alert.mitre_techniques)

      if length(related_ttps) > 0 do
        %{
          title: "Hunt for related MITRE techniques",
          query: build_mitre_ttp_query(related_ttps),
          description: "Search for activities matching related MITRE ATT&CK techniques",
          confidence: 70,
          source: "mitre_correlation",
          mitre_ttps: related_ttps,
          reasoning: "Common attack chains include these related techniques"
        }
      else
        nil
      end
    else
      nil
    end
  end

  defp ml_powered_suggestions(alert, organization_id) do
    # Call ML service for GPT-powered query generation
    case MLClient.post("/hunting/suggest_queries", %{
           alert_title: alert.title,
           alert_description: alert.description,
           process_name: alert.process_name,
           file_path: alert.file_path,
           mitre_techniques: alert.mitre_techniques,
           organization_id: organization_id
         }) do
      {:ok, %{"suggestions" => suggestions}} ->
        Enum.map(suggestions, fn suggestion ->
          %{
            title: suggestion["title"],
            query: suggestion["query"],
            description: suggestion["description"],
            confidence: suggestion["confidence"],
            source: "ml_generation",
            mitre_ttps: suggestion["mitre_ttps"] || [],
            reasoning: suggestion["reasoning"]
          }
        end)

      {:error, reason} ->
        Logger.warning("ML query suggestion failed: #{inspect(reason)}")
        []
    end
  rescue
    error ->
      Logger.warning("ML query suggestion error: #{inspect(error)}")
      []
  end

  defp generate_similar_query(alert) do
    # Build query that matches alert characteristics
    conditions = []

    # Process conditions
    conditions =
      if alert.process_name do
        ["process.name:#{alert.process_name}" | conditions]
      else
        conditions
      end

    # Command line conditions (fuzzy match)
    conditions =
      if alert.command_line do
        # Extract key arguments
        key_args = extract_key_arguments(alert.command_line)

        if length(key_args) > 0 do
          arg_conditions = Enum.map(key_args, &"process.command_line:*#{&1}*")
          conditions ++ arg_conditions
        else
          conditions
        end
      else
        conditions
      end

    # File path conditions
    conditions =
      if alert.file_path do
        # Match file name or directory
        filename = Path.basename(alert.file_path)
        dirname = Path.dirname(alert.file_path)
        ["file.name:#{filename} OR file.path:#{dirname}/*" | conditions]
      else
        conditions
      end

    # Network conditions
    conditions =
      if alert.network_info do
        network_cond = build_network_conditions(alert.network_info)
        [network_cond | conditions]
      else
        conditions
      end

    # Combine conditions
    if length(conditions) > 0 do
      Enum.join(conditions, " AND ")
    else
      "*"
    end
  end

  defp build_lateral_movement_query(alert) do
    host = alert.agent_hostname

    """
    (
      (process.name:psexec.exe OR process.name:wmic.exe OR process.name:winrs.exe)
      OR
      (network.port:(445 OR 3389 OR 5985) AND network.direction:outbound)
      OR
      (event.type:authentication AND auth.logon_type:3)
    )
    #{if host, do: "AND source.host:#{host}", else: ""}
    """
    |> String.trim()
  end

  defp build_persistence_query(alert) do
    """
    (
      registry.path:(*\\Run OR *\\RunOnce OR *\\RunServices)
      OR
      (file.path:*\\Startup\\* AND file.operation:create)
      OR
      (process.name:schtasks.exe AND process.command_line:*/create*)
      OR
      (process.name:sc.exe AND process.command_line:*create*)
      OR
      (wmi.operation:create AND wmi.class:*Filter*)
    )
    """
    |> String.trim()
  end

  defp build_mitre_ttp_query(techniques) do
    # Build query that matches events tagged with these techniques
    technique_ids = Enum.join(techniques, " OR ")
    "mitre.technique:(#{technique_ids})"
  end

  defp build_network_conditions(network_info) do
    conditions = []

    conditions =
      if network_info["dst_ip"] do
        ["network.dst_ip:#{network_info["dst_ip"]}" | conditions]
      else
        conditions
      end

    conditions =
      if network_info["dst_port"] do
        ["network.dst_port:#{network_info["dst_port"]}" | conditions]
      else
        conditions
      end

    conditions =
      if network_info["protocol"] do
        ["network.protocol:#{network_info["protocol"]}" | conditions]
      else
        conditions
      end

    Enum.join(conditions, " AND ")
  end

  defp build_ioc_conditions(iocs) do
    Enum.map(iocs, fn ioc ->
      case ioc.type do
        "ip" -> "network.dst_ip:#{ioc.value}"
        "domain" -> "dns.query:#{ioc.value}"
        "hash" -> "file.hash.sha256:#{ioc.value}"
        "process" -> "process.name:#{ioc.value}"
        "file" -> "file.path:*#{ioc.value}*"
        _ -> nil
      end
    end)
    |> Enum.filter(& &1 != nil)
  end

  defp extract_key_arguments(command_line) do
    # Extract important arguments from command line
    # Remove common noise words
    noise_words = ~w(the and or in on at to of for)

    command_line
    |> String.split()
    |> Enum.reject(fn word ->
      String.length(word) < 3 or
        String.starts_with?(word, "-") or
        String.downcase(word) in noise_words
    end)
    |> Enum.take(5)
  end

  defp involves_lateral_movement?(alert) do
    title_lower = String.downcase(alert.title || "")
    desc_lower = String.downcase(alert.description || "")

    Enum.any?(
      [
        "lateral",
        "smb",
        "rdp",
        "psexec",
        "wmic",
        "winrm",
        "remote",
        "logon type 3"
      ],
      fn keyword ->
        String.contains?(title_lower, keyword) or String.contains?(desc_lower, keyword)
      end
    ) or
      has_network_activity?(alert) or
      has_authentication_event?(alert)
  end

  defp involves_persistence?(alert) do
    title_lower = String.downcase(alert.title || "")
    desc_lower = String.downcase(alert.description || "")

    Enum.any?(
      [
        "persistence",
        "startup",
        "registry run",
        "scheduled task",
        "service",
        "wmi subscription",
        "autostart"
      ],
      fn keyword ->
        String.contains?(title_lower, keyword) or String.contains?(desc_lower, keyword)
      end
    ) or
      has_persistence_indicators?(alert)
  end

  defp has_network_activity?(alert) do
    not is_nil(alert.network_info)
  end

  defp has_authentication_event?(alert) do
    alert.event_type == "authentication" or
      (alert.tags && "authentication" in alert.tags)
  end

  defp has_persistence_indicators?(alert) do
    cond do
      alert.file_path && String.contains?(alert.file_path, "Startup") -> true
      alert.registry_path && String.contains?(alert.registry_path, "Run") -> true
      alert.process_name in ["schtasks.exe", "sc.exe"] -> true
      true -> false
    end
  end

  defp get_related_mitre_techniques(techniques) do
    # Map of technique to commonly co-occurring techniques
    related_techniques = %{
      "T1059.001" => ["T1059.003", "T1059.005", "T1047"],
      # PowerShell -> cmd, VBScript, WMI
      "T1003.001" => ["T1003.002", "T1003.003", "T1558"],
      # LSASS -> SAM, NTDS, Kerberos
      "T1021.001" => ["T1021.002", "T1021.006", "T1570"],
      # RDP -> SMB, WinRM, Lateral Tool Transfer
      "T1547.001" => ["T1547.009", "T1053.005", "T1543.003"],
      # Registry Run -> Shortcut, Scheduled Task, Service
      "T1071.001" => ["T1071.004", "T1573", "T1132"]
      # Web Protocol -> DNS, Encrypted Channel, Encoding
    }

    techniques
    |> Enum.flat_map(fn technique ->
      Map.get(related_techniques, technique, [])
    end)
    |> Enum.uniq()
  end
end
