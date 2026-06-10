defmodule TamanduaServer.Detection.Confidence do
  @moduledoc """
  Alert Confidence Scoring Module

  Calculates confidence scores for alerts based on multiple factors:
  - Detection source reliability (Sigma, YARA, ML, IOC, behavioral)
  - Historical accuracy for the specific rule
  - Corroborating evidence count
  - False positive rate for the asset
  - Temporal patterns (time of day, day of week)
  - User/entity behavior analysis

  Output: Confidence score 0-100 with detailed factor breakdown
  """

  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.Alert

  # Detection source base reliability scores
  @source_reliability %{
    sigma: 75,
    sigma_aggregation: 80,
    yara: 85,
    threat_intel_feed: 80,
    ioc: 70,
    ml: 65,
    behavioral: 60,
    c2_beacon_strong: 90,
    c2_beacon_moderate: 75,
    c2_ja3_match: 85,
    heuristic: 50,
    custom_rule: 70,
    agent_detection: 75
  }

  # Severity base confidence boost
  @severity_boost %{
    "critical" => 15,
    "high" => 10,
    "medium" => 5,
    "low" => 0,
    "info" => -5
  }

  @doc """
  Calculate the confidence score for an alert.

  Returns a map with:
  - score: 0-100 confidence score
  - factors: list of factors that contributed to the score
  - breakdown: detailed breakdown of each component
  """
  @spec calculate(Alert.t()) :: %{score: float(), factors: [String.t()], breakdown: map()}
  def calculate(%Alert{} = alert) do
    breakdown = %{
      source_reliability: calculate_source_reliability(alert),
      historical_accuracy: calculate_historical_accuracy(alert),
      corroborating_evidence: calculate_corroborating_evidence(alert),
      false_positive_rate: calculate_false_positive_rate(alert),
      temporal_analysis: calculate_temporal_analysis(alert),
      mitre_coverage: calculate_mitre_coverage(alert),
      enrichment_quality: calculate_enrichment_quality(alert)
    }

    # Calculate weighted score
    weights = %{
      source_reliability: 0.25,
      historical_accuracy: 0.20,
      corroborating_evidence: 0.20,
      false_positive_rate: 0.15,
      temporal_analysis: 0.05,
      mitre_coverage: 0.10,
      enrichment_quality: 0.05
    }

    weighted_sum = Enum.reduce(breakdown, 0.0, fn {key, value}, acc ->
      weight = Map.get(weights, key, 0.1)
      acc + (value.score * weight)
    end)

    # Apply severity boost
    severity_bonus = Map.get(@severity_boost, alert.severity, 0)
    final_score = min(max(weighted_sum + severity_bonus, 0), 100)

    # Collect significant factors
    factors = collect_significant_factors(breakdown, alert)

    %{
      score: round(final_score * 10) / 10,  # Round to 1 decimal
      factors: factors,
      breakdown: breakdown
    }
  end

  @doc """
  Get the reliability score for a specific detection source type.
  """
  @spec source_reliability(atom()) :: integer()
  def source_reliability(source_type) do
    Map.get(@source_reliability, source_type, 50)
  end

  @doc """
  Calculate historical accuracy for a specific rule.
  Returns accuracy percentage based on past detections and analyst feedback.
  """
  @spec rule_accuracy(String.t()) :: float()
  def rule_accuracy(rule_name) do
    case get_rule_stats(rule_name) do
      {:ok, stats} ->
        if stats.total_alerts > 0 do
          true_positives = stats.true_positives || 0
          false_positives = stats.false_positives || 0
          total = true_positives + false_positives

          if total > 0 do
            (true_positives / total) * 100
          else
            75.0  # Default if no feedback yet
          end
        else
          75.0  # Default for new rules
        end

      _ ->
        75.0
    end
  end

  @doc """
  Get false positive rate for an asset (agent).
  """
  @spec asset_fp_rate(String.t()) :: float()
  def asset_fp_rate(agent_id) do
    case get_asset_stats(agent_id) do
      {:ok, stats} ->
        if stats.total_alerts > 0 do
          (stats.false_positives / stats.total_alerts) * 100
        else
          0.0
        end

      _ ->
        0.0
    end
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp calculate_source_reliability(alert) do
    # Extract detection sources from alert metadata
    detection_metadata = alert.detection_metadata || %{}
    detections = detection_metadata["detections"] || []

    if Enum.empty?(detections) do
      # Fallback: infer from alert content
      inferred_score = infer_source_from_alert(alert)
      %{
        score: inferred_score,
        sources: ["inferred"],
        description: "Source reliability inferred from alert content"
      }
    else
      # Calculate average reliability across all detection sources
      source_scores = Enum.map(detections, fn detection ->
        source_type = normalize_source_type(detection["type"] || detection[:type])
        Map.get(@source_reliability, source_type, 50)
      end)

      avg_score = if length(source_scores) > 0 do
        Enum.sum(source_scores) / length(source_scores)
      else
        50
      end

      # Bonus for multiple sources agreeing
      multi_source_bonus = min((length(detections) - 1) * 5, 15)

      %{
        score: min(avg_score + multi_source_bonus, 100),
        sources: Enum.map(detections, & &1["type"] || &1[:type]),
        description: "Based on #{length(detections)} detection source(s)"
      }
    end
  end

  defp infer_source_from_alert(alert) do
    title = alert.title || ""
    description = alert.description || ""

    cond do
      String.contains?(title, ["YARA", "Yara"]) -> 85
      String.contains?(title, ["Sigma", "sigma"]) -> 75
      String.contains?(title, ["ML", "Malware", "Machine Learning"]) -> 65
      String.contains?(title, ["IOC", "indicator"]) -> 70
      String.contains?(title, ["C2", "beacon", "Command"]) -> 80
      String.contains?(description, "behavioral") -> 60
      true -> 50
    end
  end

  defp normalize_source_type(type) when is_atom(type), do: type
  defp normalize_source_type(type) when is_binary(type) do
    case String.downcase(type) do
      "sigma" -> :sigma
      "sigma_aggregation" -> :sigma_aggregation
      "yara" -> :yara
      "ioc" -> :ioc
      "ml" -> :ml
      "threat_intel_feed" -> :threat_intel_feed
      "behavioral" -> :behavioral
      "c2_beacon_strong" -> :c2_beacon_strong
      "c2_beacon_moderate" -> :c2_beacon_moderate
      "c2_ja3_match" -> :c2_ja3_match
      _ -> String.to_atom(type)
    end
  end
  defp normalize_source_type(_), do: :unknown

  defp calculate_historical_accuracy(alert) do
    # Get rule name from detection metadata
    detection_metadata = alert.detection_metadata || %{}
    rule_name = detection_metadata["rule_name"] ||
                detection_metadata["sigma_rule"] ||
                extract_rule_from_title(alert.title)

    if rule_name do
      accuracy = rule_accuracy(rule_name)
      stats = get_rule_stats(rule_name)

      sample_size = case stats do
        {:ok, s} -> s.total_alerts
        _ -> 0
      end

      # Reduce confidence if sample size is small
      confidence_factor = cond do
        sample_size >= 100 -> 1.0
        sample_size >= 50 -> 0.9
        sample_size >= 20 -> 0.8
        sample_size >= 5 -> 0.7
        true -> 0.5
      end

      %{
        score: accuracy * confidence_factor,
        rule_name: rule_name,
        sample_size: sample_size,
        description: "Rule accuracy: #{round(accuracy)}% (#{sample_size} samples)"
      }
    else
      %{
        score: 70.0,  # Default for unknown rules
        rule_name: nil,
        sample_size: 0,
        description: "No rule history available"
      }
    end
  end

  defp extract_rule_from_title(nil), do: nil
  defp extract_rule_from_title(title) do
    # Try to extract rule name from common patterns
    cond do
      String.contains?(title, ": ") ->
        title |> String.split(": ") |> List.last()
      true ->
        nil
    end
  end

  defp calculate_corroborating_evidence(alert) do
    evidence = alert.evidence || %{}
    event_ids = alert.event_ids || []
    contributing_events = alert.contributing_events || []

    # Count different types of evidence
    evidence_counts = %{
      file_hashes: length(Map.get(evidence, "file_hashes", [])),
      network: length(Map.get(evidence, "network", [])),
      registry: length(Map.get(evidence, "registry", [])),
      related_events: length(event_ids) + length(contributing_events),
      process_chain: length(alert.process_chain || [])
    }

    total_evidence = Enum.sum(Map.values(evidence_counts))

    # Score based on evidence count and diversity
    diversity = evidence_counts
    |> Enum.count(fn {_k, v} -> v > 0 end)

    base_score = case total_evidence do
      0 -> 30
      1 -> 45
      n when n <= 3 -> 60
      n when n <= 5 -> 75
      n when n <= 10 -> 85
      _ -> 95
    end

    # Bonus for evidence diversity
    diversity_bonus = diversity * 5

    %{
      score: min(base_score + diversity_bonus, 100),
      evidence_counts: evidence_counts,
      total_evidence: total_evidence,
      diversity: diversity,
      description: "#{total_evidence} evidence items across #{diversity} categories"
    }
  end

  defp calculate_false_positive_rate(alert) do
    agent_id = alert.agent_id

    if agent_id do
      fp_rate = asset_fp_rate(agent_id)

      # Lower FP rate = higher confidence
      # FP rate 0% -> score 100
      # FP rate 50% -> score 50
      # FP rate 100% -> score 0
      score = 100 - fp_rate

      %{
        score: score,
        fp_rate: fp_rate,
        agent_id: agent_id,
        description: "Asset FP rate: #{round(fp_rate)}%"
      }
    else
      %{
        score: 75.0,  # Default when agent unknown
        fp_rate: nil,
        agent_id: nil,
        description: "No asset FP data available"
      }
    end
  end

  defp calculate_temporal_analysis(alert) do
    # Analyze timing patterns
    created_at = alert.inserted_at || DateTime.utc_now()

    hour = created_at.hour
    day_of_week = Date.day_of_week(DateTime.to_date(created_at))

    # Business hours analysis (attacks during off-hours may be more suspicious)
    is_business_hours = hour >= 9 and hour <= 17 and day_of_week in 1..5

    # Weekend activity is often more suspicious
    is_weekend = day_of_week in [6, 7]

    # Night activity
    is_night = hour < 6 or hour > 22

    base_score = 70

    adjustments = 0
    adjustments = if is_night, do: adjustments + 15, else: adjustments
    adjustments = if is_weekend, do: adjustments + 10, else: adjustments
    adjustments = if not is_business_hours and not is_weekend, do: adjustments + 5, else: adjustments

    %{
      score: min(base_score + adjustments, 100),
      hour: hour,
      day_of_week: day_of_week,
      is_business_hours: is_business_hours,
      description: "#{if is_business_hours, do: "Business hours", else: "Off-hours"} activity"
    }
  end

  defp calculate_mitre_coverage(alert) do
    tactics = alert.mitre_tactics || []
    techniques = alert.mitre_techniques || []

    # More MITRE coverage = more confidence (well-understood attack)
    tactic_count = length(tactics)
    technique_count = length(techniques)

    base_score = 50

    # Bonus for MITRE mapping
    mapping_bonus = min(tactic_count * 10 + technique_count * 5, 40)

    # Extra bonus for high-confidence techniques
    high_value_techniques = ["T1003", "T1055", "T1059", "T1486", "T1547"]
    has_high_value = Enum.any?(techniques, fn t ->
      Enum.any?(high_value_techniques, &String.starts_with?(t, &1))
    end)

    high_value_bonus = if has_high_value, do: 10, else: 0

    %{
      score: min(base_score + mapping_bonus + high_value_bonus, 100),
      tactics: tactics,
      techniques: techniques,
      description: "#{tactic_count} tactics, #{technique_count} techniques mapped"
    }
  end

  defp calculate_enrichment_quality(alert) do
    enrichment = alert.enrichment || %{}

    # Check what enrichments are available
    has_geo = Map.has_key?(enrichment, "geo") or Map.has_key?(enrichment, "geoip")
    has_threat_intel = Map.has_key?(enrichment, "threat_intel") or Map.has_key?(enrichment, "reputation")
    has_whois = Map.has_key?(enrichment, "whois")
    has_asn = Map.has_key?(enrichment, "asn")
    has_malware_family = Map.has_key?(enrichment, "malware_family")

    enrichments_present = Enum.count([has_geo, has_threat_intel, has_whois, has_asn, has_malware_family], & &1)

    base_score = 40
    enrichment_bonus = enrichments_present * 12

    # Extra bonus if threat intel matches
    threat_intel_match = case enrichment["threat_intel"] do
      %{"match" => true} -> 15
      %{"found" => true} -> 15
      _ -> 0
    end

    %{
      score: min(base_score + enrichment_bonus + threat_intel_match, 100),
      enrichments_present: enrichments_present,
      has_threat_intel_match: threat_intel_match > 0,
      description: "#{enrichments_present} enrichment sources"
    }
  end

  defp collect_significant_factors(breakdown, alert) do
    factors = []

    # Source reliability
    factors = if breakdown.source_reliability.score >= 80 do
      factors ++ ["High-confidence detection source"]
    else
      factors
    end

    # Multiple sources
    sources = breakdown.source_reliability[:sources] || []
    factors = if length(sources) > 1 do
      factors ++ ["Multiple detection sources agree"]
    else
      factors
    end

    # Historical accuracy
    factors = if breakdown.historical_accuracy.score >= 85 do
      factors ++ ["Rule has high historical accuracy"]
    else
      factors
    end

    # Low sample size warning
    factors = if breakdown.historical_accuracy.sample_size < 10 do
      factors ++ ["Limited rule history"]
    else
      factors
    end

    # Corroborating evidence
    factors = if breakdown.corroborating_evidence.total_evidence >= 5 do
      factors ++ ["Strong corroborating evidence"]
    else
      factors
    end

    # Asset FP rate
    factors = if breakdown.false_positive_rate.fp_rate && breakdown.false_positive_rate.fp_rate > 30 do
      factors ++ ["Asset has elevated FP rate"]
    else
      factors
    end

    # Temporal
    factors = if not breakdown.temporal_analysis.is_business_hours do
      factors ++ ["Off-hours activity"]
    else
      factors
    end

    # MITRE coverage
    factors = if breakdown.mitre_coverage.score >= 80 do
      factors ++ ["Well-mapped to ATT&CK framework"]
    else
      factors
    end

    # Threat intel match
    factors = if breakdown.enrichment_quality.has_threat_intel_match do
      factors ++ ["Threat intelligence match"]
    else
      factors
    end

    # Severity factor
    factors = if alert.severity in ["critical", "high"] do
      factors ++ ["#{String.capitalize(alert.severity)} severity"]
    else
      factors
    end

    factors
  end

  defp get_rule_stats(rule_name) do
    try do
      query = from(a in Alert,
        where: fragment("?->>'rule_name' = ?", a.detection_metadata, ^rule_name),
        select: %{
          total_alerts: count(a.id),
          true_positives: sum(fragment("CASE WHEN ? NOT IN ('false_positive') THEN 1 ELSE 0 END", a.status)),
          false_positives: sum(fragment("CASE WHEN ? = 'false_positive' THEN 1 ELSE 0 END", a.status))
        }
      )

      case Repo.one(query) do
        nil -> {:ok, %{total_alerts: 0, true_positives: 0, false_positives: 0}}
        stats -> {:ok, stats}
      end
    rescue
      e ->
        Logger.warning("Failed to get rule stats for #{rule_name}: #{inspect(e)}")
        {:error, e}
    end
  end

  defp get_asset_stats(agent_id) do
    try do
      query = from(a in Alert,
        where: a.agent_id == ^agent_id,
        where: a.inserted_at > ago(90, "day"),
        select: %{
          total_alerts: count(a.id),
          false_positives: sum(fragment("CASE WHEN ? = 'false_positive' THEN 1 ELSE 0 END", a.status))
        }
      )

      case Repo.one(query) do
        nil -> {:ok, %{total_alerts: 0, false_positives: 0}}
        stats -> {:ok, stats}
      end
    rescue
      e ->
        Logger.warning("Failed to get asset stats for #{agent_id}: #{inspect(e)}")
        {:error, e}
    end
  end
end
