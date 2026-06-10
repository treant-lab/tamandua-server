defmodule TamanduaServer.Notifications.Router do
  @moduledoc """
  Notification routing engine.

  Applies routing rules to determine which integrations should receive a notification
  for a given alert. Handles severity filtering, alert type filtering, MITRE technique
  filtering, and tag-based routing.
  """

  require Logger
  alias TamanduaServer.Notifications.{Integration, Throttler}
  alias TamanduaServer.Repo

  @doc """
  Get all integrations that should receive a notification for the given alert.

  Returns a list of integrations that:
  - Are enabled
  - Match the routing rules
  - Are not currently throttled
  """
  def route_alert(alert, organization_id) do
    organization_id
    |> get_active_integrations()
    |> Enum.filter(&matches_routing_rules?(&1, alert))
    |> Enum.reject(&Throttler.throttled?(&1))
  end

  @doc """
  Check if an integration's routing rules match the given alert.
  """
  def matches_routing_rules?(%Integration{routing_rules: rules}, alert) do
    cond do
      # No rules = match all
      map_size(rules) == 0 -> true

      # Check all rule types
      true ->
        matches_severity?(rules, alert) and
          matches_alert_type?(rules, alert) and
          matches_mitre_technique?(rules, alert) and
          matches_tags?(rules, alert)
    end
  end

  # Private helpers

  defp get_active_integrations(organization_id) do
    Integration
    |> Repo.get_by(organization_id: organization_id, enabled: true)
    |> case do
      nil ->
        # Fallback: query all active integrations for the org
        import Ecto.Query

        Integration
        |> where([i], i.organization_id == ^organization_id and i.enabled == true)
        |> Repo.all()

      integration ->
        [integration]
    end
  rescue
    _ ->
      # If there's an error, return empty list
      []
  end

  defp matches_severity?(rules, alert) do
    case Map.get(rules, "severity") || Map.get(rules, :severity) do
      nil -> true
      [] -> true
      severities when is_list(severities) -> alert.severity in severities
      severity when is_binary(severity) -> alert.severity == severity
      _ -> true
    end
  end

  defp matches_alert_type?(rules, alert) do
    case Map.get(rules, "alert_types") || Map.get(rules, :alert_types) do
      nil -> true
      [] -> true
      types when is_list(types) -> matches_any_type?(alert, types)
      type when is_binary(type) -> matches_type?(alert, type)
      _ -> true
    end
  end

  defp matches_any_type?(alert, types) do
    alert_type = extract_alert_type(alert)
    alert_type in types
  end

  defp matches_type?(alert, type) do
    alert_type = extract_alert_type(alert)
    alert_type == type
  end

  defp extract_alert_type(alert) do
    # Extract type from alert title, description, or metadata
    cond do
      Map.has_key?(alert, :alert_type) -> alert.alert_type
      Map.has_key?(alert, :type) -> alert.type
      true -> extract_type_from_title(alert.title)
    end
  end

  defp extract_type_from_title(title) when is_binary(title) do
    title_lower = String.downcase(title)

    cond do
      String.contains?(title_lower, "malware") -> "malware"
      String.contains?(title_lower, "ransomware") -> "ransomware"
      String.contains?(title_lower, "phishing") -> "phishing"
      String.contains?(title_lower, "c2") or String.contains?(title_lower, "command and control") -> "c2"
      String.contains?(title_lower, "lateral") -> "lateral_movement"
      String.contains?(title_lower, "privilege") -> "privilege_escalation"
      String.contains?(title_lower, "persistence") -> "persistence"
      String.contains?(title_lower, "exfiltration") -> "exfiltration"
      true -> "other"
    end
  end

  defp extract_type_from_title(_), do: "other"

  defp matches_mitre_technique?(rules, alert) do
    case Map.get(rules, "mitre_techniques") || Map.get(rules, :mitre_techniques) do
      nil -> true
      [] -> true
      techniques when is_list(techniques) -> matches_any_technique?(alert, techniques)
      technique when is_binary(technique) -> matches_technique?(alert, technique)
      _ -> true
    end
  end

  defp matches_any_technique?(alert, techniques) do
    alert_technique = extract_mitre_technique(alert)

    cond do
      is_nil(alert_technique) -> false
      alert_technique in techniques -> true
      # Also check if any technique is a prefix (e.g., "T1059" matches "T1059.001")
      Enum.any?(techniques, &String.starts_with?(alert_technique, &1)) -> true
      true -> false
    end
  end

  defp matches_technique?(alert, technique) do
    alert_technique = extract_mitre_technique(alert)

    cond do
      is_nil(alert_technique) -> false
      alert_technique == technique -> true
      String.starts_with?(alert_technique, technique) -> true
      true -> false
    end
  end

  defp extract_mitre_technique(alert) do
    Map.get(alert, :mitre_technique) || Map.get(alert, :mitre_attack_id)
  end

  defp matches_tags?(rules, alert) do
    case Map.get(rules, "tags") || Map.get(rules, :tags) do
      nil -> true
      [] -> true
      required_tags when is_list(required_tags) -> matches_any_tag?(alert, required_tags)
      tag when is_binary(tag) -> has_tag?(alert, tag)
      _ -> true
    end
  end

  defp matches_any_tag?(alert, required_tags) do
    alert_tags = extract_tags(alert)

    if Enum.empty?(alert_tags) do
      false
    else
      Enum.any?(required_tags, &(&1 in alert_tags))
    end
  end

  defp has_tag?(alert, tag) do
    alert_tags = extract_tags(alert)
    tag in alert_tags
  end

  defp extract_tags(alert) do
    case Map.get(alert, :tags) do
      nil -> []
      tags when is_list(tags) -> tags
      tags when is_binary(tags) -> String.split(tags, ",") |> Enum.map(&String.trim/1)
      _ -> []
    end
  end
end
