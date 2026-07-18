defmodule TamanduaServer.Alerts.SupplyChainEnricher do
  @moduledoc """
  Enriches supply chain security alerts with additional context and metadata.

  This module processes supply chain alerts (malicious packages, typosquatting,
  install script attacks, anomalous behavior) and adds contextual information
  to help analysts quickly assess and respond to threats.

  ## Enrichment Types

  - **known_malicious**: Adds Socket.dev threat intelligence data
  - **typosquatting**: Adds similar package names and detection method
  - **malicious_script**: Adds pattern details and script analysis
  - **anomalous_behavior**: Adds behavior categorization and counts

  ## Alert Broadcasting

  Enriched alerts are broadcast to the "alerts:supply_chain" PubSub topic
  for real-time dashboard updates.
  """

  alias TamanduaServer.Alerts.Alert


  @ecosystem_display %{
    npm: "npm",
    pypi: "PyPI",
    cargo: "Cargo",
    gem: "RubyGems",
    go: "Go Modules"
  }

  @doc """
  Enriches a supply chain alert with additional context based on risk type.

  ## Examples

      iex> alert = %Alert{enrichment: %{"ecosystem" => "npm", "risk_type" => "typosquatting", "similar_to" => ["lodash"]}}
      iex> enriched = SupplyChainEnricher.enrich(alert)
      iex> enriched.enrichment["similar_packages"]
      ["lodash"]
  """
  def enrich(%Alert{enrichment: existing} = alert) do
    ecosystem = existing["ecosystem"]
    risk_type = existing["risk_type"]

    additional =
      case risk_type do
        "known_malicious" ->
          fetch_socket_dev_context(ecosystem, existing["package_name"], existing)

        "typosquatting" ->
          %{
            "similar_packages" => existing["similar_to"] || [],
            "detection_method" => existing["detection_method"],
            "distance" => existing["levenshtein_distance"]
          }

        "malicious_script" ->
          %{
            "patterns_detected" => existing["suspicious_patterns"],
            "risk_score" => existing["risk_score"],
            "script_hash" => hash_script(existing["script_content"])
          }

        "anomalous_behavior" ->
          %{
            "anomaly_types" => categorize_anomalies(existing),
            "network_count" => length(existing["network_destinations"] || []),
            "files_count" => length(existing["sensitive_files"] || [])
          }

        _ ->
          %{}
      end

    updated_enrichment =
      Map.merge(existing, %{
        "ecosystem_display" => get_ecosystem_display(ecosystem),
        "severity_reason" => build_severity_reason(risk_type, additional),
        "recommended_action" => recommend_action(risk_type)
      })
      |> Map.merge(additional)

    %{alert | enrichment: updated_enrichment}
  end

  @doc """
  Creates a supply chain alert with proper schema fields.

  ## Parameters

  - `agent_id`: The agent UUID where the package was detected
  - `details`: Map with keys:
    - `:ecosystem` - Package ecosystem atom (:npm, :pypi, :cargo, :gem, :go)
    - `:package_name` - Package name string
    - `:version` - Package version (optional, defaults to "unknown")
    - `:risk_type` - Risk type atom (:known_malicious, :typosquatting, etc.)
    - `:extra` - Additional enrichment fields (optional)

  ## Examples

      iex> create_supply_chain_alert(agent_id, %{
      ...>   ecosystem: :npm,
      ...>   package_name: "evil-package",
      ...>   version: "1.0.0",
      ...>   risk_type: :known_malicious
      ...> })
      %Alert{severity: "critical", ...}
  """
  def create_supply_chain_alert(agent_id, %{} = details) do
    %Alert{
      severity: severity_from_risk_type(details.risk_type),
      title: build_title(details),
      description: build_description(details),
      mitre_tactics: ["initial_access"],
      mitre_techniques: ["T1195.001", "T1195.002"],
      agent_id: agent_id,
      enrichment:
        %{
          "ecosystem" => to_string(details.ecosystem),
          "package_name" => details.package_name,
          "package_version" => details[:version] || "unknown",
          "risk_type" => to_string(details.risk_type)
        }
        |> Map.merge(details[:extra] || %{})
    }
  end

  @doc """
  Broadcasts a supply chain alert to the PubSub topic for real-time updates.

  ## Examples

      iex> broadcast_alert(alert)
      :ok
  """
  def broadcast_alert(alert) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alerts:supply_chain",
      %{event: "new_alert", payload: alert}
    )
  end

  # Private Functions

  defp fetch_socket_dev_context(_ecosystem, _package_name, existing) do
    # In a real implementation, this would query Socket.dev API
    # For now, we just preserve any existing socket_dev fields
    existing
    |> Map.take(["socket_dev_score", "socket_dev_data"])
  end

  defp get_ecosystem_display(ecosystem) when is_binary(ecosystem) do
    ecosystem
    |> String.to_existing_atom()
    |> then(&Map.get(@ecosystem_display, &1, ecosystem))
  rescue
    ArgumentError -> ecosystem
  end

  defp get_ecosystem_display(ecosystem) when is_atom(ecosystem) do
    Map.get(@ecosystem_display, ecosystem, to_string(ecosystem))
  end

  defp hash_script(nil), do: nil

  defp hash_script(script_content) when is_binary(script_content) do
    :crypto.hash(:sha256, script_content)
    |> Base.encode16(case: :lower)
  end

  defp categorize_anomalies(enrichment) do
    types = []

    types =
      if length(enrichment["network_destinations"] || []) > 0 do
        ["network_exfiltration" | types]
      else
        types
      end

    types =
      if length(enrichment["sensitive_files"] || []) > 0 do
        ["credential_access" | types]
      else
        types
      end

    types =
      if enrichment["suspicious_patterns"] do
        ["code_execution" | types]
      else
        types
      end

    types
  end

  defp severity_from_risk_type(:known_malicious), do: "critical"
  defp severity_from_risk_type(:typosquatting), do: "high"
  defp severity_from_risk_type(:malicious_script), do: "high"
  defp severity_from_risk_type(:anomalous_behavior), do: "medium"
  defp severity_from_risk_type(_), do: "medium"

  defp build_title(%{ecosystem: ecosystem, package_name: name, version: version}) do
    "Malicious #{ecosystem} package: #{name}@#{version}"
  end

  defp build_title(%{ecosystem: ecosystem, package_name: name, risk_type: risk_type}) do
    risk_display =
      case risk_type do
        :known_malicious -> "Malicious"
        :typosquatting -> "Typosquatting"
        :malicious_script -> "Suspicious"
        :anomalous_behavior -> "Anomalous"
        _ -> "Suspicious"
      end

    "#{risk_display} #{ecosystem} package: #{name}"
  end

  defp build_description(%{risk_type: :known_malicious, package_name: name}) do
    "Package '#{name}' is flagged as malicious by threat intelligence feeds. This package may contain malware, backdoors, or other malicious code."
  end

  defp build_description(%{risk_type: :typosquatting, package_name: name}) do
    "Package '#{name}' appears to be a typosquatting attempt, mimicking a popular package name to trick developers into installing malicious code."
  end

  defp build_description(%{risk_type: :malicious_script, package_name: name}) do
    "Package '#{name}' contains suspicious install scripts with patterns indicating malicious behavior (obfuscation, network downloads, code execution)."
  end

  defp build_description(%{risk_type: :anomalous_behavior, package_name: name}) do
    "Package '#{name}' exhibited anomalous behavior during installation, including unexpected network connections or access to sensitive files."
  end

  defp build_description(_details) do
    "Supply chain security threat detected in package installation."
  end

  defp build_severity_reason("known_malicious", _additional) do
    "Confirmed malicious package in threat intelligence database"
  end

  defp build_severity_reason("typosquatting", %{"detection_method" => method}) do
    "Typosquatting detected via #{method} analysis"
  end

  defp build_severity_reason(
         "malicious_script",
         %{"patterns_detected" => patterns, "risk_score" => score}
       ) do
    "Install script contains #{length(patterns)} suspicious patterns (risk score: #{Float.round(score, 2)})"
  end

  defp build_severity_reason("anomalous_behavior", %{
         "network_count" => net,
         "files_count" => files
       }) do
    parts = []

    parts =
      if net > 0 do
        ["#{net} anomalous network connection(s)" | parts]
      else
        parts
      end

    parts =
      if files > 0 do
        ["#{files} sensitive file access(es)" | parts]
      else
        parts
      end

    Enum.join(parts, ", ")
  end

  defp build_severity_reason(_risk_type, _additional) do
    "Supply chain security risk detected"
  end

  defp recommend_action(:known_malicious) do
    "BLOCK installation immediately. Remove package if already installed. Scan affected systems for indicators of compromise."
  end

  defp recommend_action(:typosquatting) do
    "BLOCK installation and verify correct package name. Review project dependencies for similar typosquatting attempts."
  end

  defp recommend_action(:malicious_script) do
    "BLOCK installation and analyze script behavior. Quarantine affected endpoints and review recent package installations."
  end

  defp recommend_action(:anomalous_behavior) do
    "INVESTIGATE install behavior. Review network connections and file access patterns. Consider blocking until investigation complete."
  end

  defp recommend_action(_) do
    "Investigate package and verify legitimacy before allowing installation."
  end
end
