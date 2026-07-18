defmodule TamanduaServer.ThreatIntel.AlertScoringIntegration do
  @moduledoc """
  Automatically enriches alerts with threat intelligence reputation scores.

  When alerts are created, this module:
  1. Extracts indicators from alert data (IPs, domains, hashes, URLs)
  2. Scores each indicator using the ReputationScorer
  3. Updates the alert with aggregated threat scores
  4. Adjusts alert severity based on reputation scores
  5. Triggers escalation for high-reputation threats

  ## Usage

  This module is called automatically by the alert creation pipeline.
  Manual scoring can be triggered via:

      AlertScoringIntegration.score_alert(alert)
  """

  require Logger

  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.ThreatIntel.ReputationScorer
  alias TamanduaServer.Repo

  @doc """
  Score an alert by extracting and scoring all indicators.

  Returns updated alert with threat scores in the enrichment field.
  """
  @spec score_alert(Alert.t()) :: {:ok, Alert.t()} | {:error, term()}
  def score_alert(alert) do
    # Extract indicators from alert
    indicators = extract_indicators(alert)

    if Enum.empty?(indicators) do
      Logger.debug("[AlertScoring] No indicators found in alert #{alert.id}")
      {:ok, alert}
    else
      Logger.info("[AlertScoring] Scoring #{length(indicators)} indicators for alert #{alert.id}")

      # Score all indicators
      scores = score_indicators(indicators)

      # Calculate aggregate threat score
      aggregate_score = calculate_aggregate_score(scores)

      # Update alert with scores
      update_alert_with_scores(alert, scores, aggregate_score)
    end
  end

  @doc """
  Extract indicators from alert data.

  Looks in multiple fields:
  - raw_event
  - evidence
  - enrichment
  - process_chain
  """
  def extract_indicators(alert) do
    indicators = []

    # Extract from raw_event
    indicators = indicators ++ extract_from_raw_event(alert.raw_event)

    # Extract from evidence
    indicators = indicators ++ extract_from_evidence(alert.evidence)

    # Extract from enrichment
    indicators = indicators ++ extract_from_enrichment(alert.enrichment)

    # Extract from process chain
    indicators = indicators ++ extract_from_process_chain(alert.process_chain)

    # Deduplicate
    indicators
    |> Enum.uniq()
    |> Enum.filter(fn {_type, value} -> valid_indicator?(value) end)
  end

  # ============================================================================
  # Private Functions - Extraction
  # ============================================================================

  defp extract_from_raw_event(nil), do: []
  defp extract_from_raw_event(raw_event) when is_map(raw_event) do
    indicators = []

    # Extract IP addresses
    indicators = indicators ++ extract_ips(raw_event)

    # Extract domains
    indicators = indicators ++ extract_domains(raw_event)

    # Extract URLs
    indicators = indicators ++ extract_urls(raw_event)

    # Extract file hashes
    indicators = indicators ++ extract_hashes(raw_event)

    indicators
  end

  defp extract_from_evidence(nil), do: []
  defp extract_from_evidence(evidence) when is_map(evidence) do
    extract_from_raw_event(evidence)
  end

  defp extract_from_enrichment(nil), do: []
  defp extract_from_enrichment(enrichment) when is_map(enrichment) do
    # Enrichment may already contain scored indicators
    []
  end

  defp extract_from_process_chain(nil), do: []
  defp extract_from_process_chain(process_chain) when is_list(process_chain) do
    Enum.flat_map(process_chain, fn process ->
      indicators = []

      # Extract from process executable hash
      indicators = if Map.has_key?(process, "hash_sha256") do
        [{:hash_sha256, process["hash_sha256"]} | indicators]
      else
        indicators
      end

      indicators = if Map.has_key?(process, "hash_md5") do
        [{:hash_md5, process["hash_md5"]} | indicators]
      else
        indicators
      end

      # Extract network connections
      if Map.has_key?(process, "network_connections") do
        Enum.flat_map(process["network_connections"], fn conn ->
          [
            {:ip, Map.get(conn, "remote_ip")},
            {:domain, Map.get(conn, "domain")}
          ]
          |> Enum.reject(fn {_type, val} -> is_nil(val) end)
        end) ++ indicators
      else
        indicators
      end
    end)
  end

  defp extract_ips(data) do
    [
      Map.get(data, "src_ip"),
      Map.get(data, "dst_ip"),
      Map.get(data, "remote_ip"),
      Map.get(data, "source_ip"),
      Map.get(data, "destination_ip"),
      Map.get(data, "ip_address")
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.filter(&valid_ip?/1)
    |> Enum.map(&{:ip, &1})
  end

  defp extract_domains(data) do
    [
      Map.get(data, "domain"),
      Map.get(data, "hostname"),
      Map.get(data, "dns_query")
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.filter(&valid_domain?/1)
    |> Enum.map(&{:domain, &1})
  end

  defp extract_urls(data) do
    [
      Map.get(data, "url"),
      Map.get(data, "http_url"),
      Map.get(data, "request_url")
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.filter(&valid_url?/1)
    |> Enum.map(&{:url, &1})
  end

  defp extract_hashes(data) do
    sha256 = Map.get(data, "hash_sha256") || Map.get(data, "sha256")
    md5 = Map.get(data, "hash_md5") || Map.get(data, "md5")

    indicators = []

    indicators = if sha256 && valid_hash?(sha256, 64) do
      [{:hash_sha256, sha256} | indicators]
    else
      indicators
    end

    indicators = if md5 && valid_hash?(md5, 32) do
      [{:hash_md5, md5} | indicators]
    else
      indicators
    end

    indicators
  end

  # ============================================================================
  # Private Functions - Validation
  # ============================================================================

  defp valid_indicator?(""), do: false
  defp valid_indicator?(nil), do: false
  defp valid_indicator?(value) when is_binary(value), do: String.length(value) > 0
  defp valid_indicator?(_), do: false

  defp valid_ip?(ip) when is_binary(ip) do
    # Basic IP validation (IPv4)
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, _} -> true
      {:error, _} -> false
    end
  end
  defp valid_ip?(_), do: false

  defp valid_domain?(domain) when is_binary(domain) do
    # Basic domain validation
    String.match?(domain, ~r/^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$/i)
  end
  defp valid_domain?(_), do: false

  defp valid_url?(url) when is_binary(url) do
    # Basic URL validation
    String.match?(url, ~r/^https?:\/\//i)
  end
  defp valid_url?(_), do: false

  defp valid_hash?(hash, length) when is_binary(hash) do
    String.length(hash) == length and String.match?(hash, ~r/^[a-f0-9]+$/i)
  end
  defp valid_hash?(_, _), do: false

  # ============================================================================
  # Private Functions - Scoring
  # ============================================================================

  defp score_indicators(indicators) do
    # Use batch scoring for efficiency
    ReputationScorer.batch_score(indicators)
    |> Enum.map(fn {{type, value}, result} ->
      case result do
        {:ok, score_data} ->
          %{
            type: type,
            value: value,
            score: score_data.score,
            confidence: score_data.confidence,
            verdict: score_data.verdict,
            sources: score_data.sources_used
          }

        {:error, _reason} ->
          nil
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp calculate_aggregate_score([]), do: nil
  defp calculate_aggregate_score(scores) do
    # Calculate weighted average based on confidence
    {total_weighted, total_confidence} = Enum.reduce(scores, {0, 0}, fn score, {sum_w, sum_c} ->
      weighted = score.score * score.confidence
      {sum_w + weighted, sum_c + score.confidence}
    end)

    average_score = if total_confidence > 0 do
      round(total_weighted / total_confidence)
    else
      0
    end

    # Find highest individual score
    max_score = Enum.max_by(scores, & &1.score, fn -> %{score: 0} end).score

    # Find most malicious verdict
    verdict = determine_aggregate_verdict(scores)

    # Calculate overall confidence
    avg_confidence = if length(scores) > 0 do
      Enum.sum(Enum.map(scores, & &1.confidence)) / length(scores)
    else
      0.0
    end

    %{
      aggregate_score: average_score,
      max_indicator_score: max_score,
      verdict: verdict,
      confidence: Float.round(avg_confidence, 2),
      total_indicators: length(scores),
      malicious_count: Enum.count(scores, &(&1.verdict == "malicious")),
      suspicious_count: Enum.count(scores, &(&1.verdict == "suspicious"))
    }
  end

  defp determine_aggregate_verdict(scores) do
    verdicts = Enum.map(scores, & &1.verdict)

    cond do
      Enum.any?(verdicts, &(&1 == "malicious")) -> "malicious"
      Enum.any?(verdicts, &(&1 == "suspicious")) -> "suspicious"
      Enum.any?(verdicts, &(&1 == "unknown")) -> "unknown"
      true -> "clean"
    end
  end

  # ============================================================================
  # Private Functions - Alert Update
  # ============================================================================

  defp update_alert_with_scores(alert, indicator_scores, aggregate_score) do
    # Build enrichment data
    enrichment = Map.merge(alert.enrichment || %{}, %{
      "reputation_scores" => %{
        "indicators" => Enum.map(indicator_scores, fn score ->
          %{
            "type" => Atom.to_string(score.type),
            "value" => score.value,
            "score" => score.score,
            "confidence" => score.confidence,
            "verdict" => score.verdict,
            "sources" => score.sources
          }
        end),
        "aggregate" => aggregate_score,
        "scored_at" => DateTime.to_iso8601(DateTime.utc_now())
      }
    })

    # Update threat_score field
    threat_score = if aggregate_score do
      aggregate_score.aggregate_score / 100.0
    else
      alert.threat_score
    end

    # Adjust severity based on scores
    new_severity = adjust_severity_by_score(alert.severity, aggregate_score)

    # Update alert
    changeset = Alert.changeset(alert, %{
      enrichment: enrichment,
      threat_score: threat_score,
      severity: new_severity
    })

    case Repo.update(changeset) do
      {:ok, updated_alert} ->
        Logger.info("[AlertScoring] Alert #{alert.id} scored: aggregate=#{inspect(aggregate_score)}")

        # Check if we should escalate
        maybe_escalate_alert(updated_alert, aggregate_score)

        {:ok, updated_alert}

      {:error, changeset} ->
        Logger.error("[AlertScoring] Failed to update alert #{alert.id}: #{inspect(changeset.errors)}")
        {:error, changeset}
    end
  end

  defp adjust_severity_by_score(current_severity, nil), do: current_severity
  defp adjust_severity_by_score(current_severity, aggregate_score) do
    score = aggregate_score.aggregate_score

    # Only upgrade severity, never downgrade
    cond do
      score >= 90 and current_severity != "critical" ->
        Logger.info("[AlertScoring] Upgrading severity to critical (score: #{score})")
        "critical"

      score >= 75 and current_severity not in ["critical", "high"] ->
        Logger.info("[AlertScoring] Upgrading severity to high (score: #{score})")
        "high"

      score >= 50 and current_severity not in ["critical", "high", "medium"] ->
        Logger.info("[AlertScoring] Upgrading severity to medium (score: #{score})")
        "medium"

      true ->
        current_severity
    end
  end

  defp maybe_escalate_alert(_alert, nil), do: :ok
  defp maybe_escalate_alert(alert, aggregate_score) do
    # Escalate if:
    # 1. Aggregate score >= 90
    # 2. Multiple malicious indicators with high confidence
    should_escalate = aggregate_score.aggregate_score >= 90 or
                      (aggregate_score.malicious_count >= 2 and aggregate_score.confidence >= 0.8)

    if should_escalate do
      Logger.warning("[AlertScoring] Alert #{alert.id} should be escalated (score: #{aggregate_score.aggregate_score}, malicious: #{aggregate_score.malicious_count})")

      # Publish escalation event
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "alerts:escalation",
        {:alert_escalated, alert.id, aggregate_score}
      )
    end

    :ok
  end
end
