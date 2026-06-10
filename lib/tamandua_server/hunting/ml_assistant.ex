defmodule TamanduaServer.Hunting.MLAssistant do
  @moduledoc """
  ML-assisted threat hunting coordinator.

  Provides intelligent hunting assistance including:
  - Automatic query suggestions based on alerts
  - Anomaly-driven hunt hypotheses
  - Behavioral cluster identification
  - Hunt result ranking by suspiciousness
  - Template generation from alerts
  - ML-powered hunt pivoting
  """

  require Logger
  alias TamanduaServer.Hunting.{QuerySuggester, AnomalyHunter}
  alias TamanduaServer.Alerts
  alias TamanduaServer.ML.Client, as: MLClient

  @doc """
  Generate hunt suggestions based on recent activity.

  ## Options
  - `:organization_id` - Organization ID (required)
  - `:alert_id` - Specific alert to base suggestions on
  - `:days` - Number of days to look back (default: 7)
  - `:limit` - Maximum suggestions to return (default: 10)

  ## Returns
  `{:ok, suggestions}` where each suggestion has:
  - `:title` - Descriptive title
  - `:query` - TQL query string
  - `:description` - Why this hunt is suggested
  - `:mitre_ttps` - Related MITRE ATT&CK techniques
  - `:confidence` - Confidence score 0-100
  - `:source` - Source of suggestion (alert, anomaly, pattern)
  """
  def suggest_hunts(opts) do
    organization_id = Keyword.fetch!(opts, :organization_id)
    alert_id = Keyword.get(opts, :alert_id)
    days = Keyword.get(opts, :days, 7)
    limit = Keyword.get(opts, :limit, 10)

    suggestions =
      if alert_id do
        suggest_from_alert(alert_id, organization_id)
      else
        suggest_from_recent_activity(organization_id, days)
      end

    # Rank suggestions by confidence and relevance
    ranked = rank_suggestions(suggestions, limit)

    {:ok, ranked}
  rescue
    error ->
      Logger.error("Failed to generate hunt suggestions: #{inspect(error)}")
      {:error, :suggestion_failed}
  end

  @doc """
  Generate hunt hypotheses from detected anomalies.

  Analyzes telemetry anomalies and creates actionable hunt hypotheses.

  ## Options
  - `:organization_id` - Organization ID (required)
  - `:hours` - Hours to analyze (default: 24)
  - `:min_suspiciousness` - Minimum suspiciousness score 0-100 (default: 60)

  ## Returns
  `{:ok, hypotheses}` where each hypothesis has:
  - `:title` - Hypothesis title
  - `:description` - Detailed description
  - `:query` - Hunt query to test hypothesis
  - `:mitre_ttps` - Related TTPs
  - `:suspiciousness_score` - Score 0-100
  - `:anomaly_type` - Type of anomaly detected
  - `:evidence` - Supporting evidence
  """
  def generate_hypotheses(opts) do
    organization_id = Keyword.fetch!(opts, :organization_id)
    hours = Keyword.get(opts, :hours, 24)
    min_suspiciousness = Keyword.get(opts, :min_suspiciousness, 60)

    case AnomalyHunter.identify_anomalies(organization_id, hours) do
      {:ok, anomalies} ->
        hypotheses =
          anomalies
          |> Enum.map(&anomaly_to_hypothesis/1)
          |> Enum.filter(&(&1.suspiciousness_score >= min_suspiciousness))
          |> Enum.sort_by(& &1.suspiciousness_score, :desc)

        {:ok, hypotheses}

      {:error, reason} ->
        Logger.error("Failed to generate hypotheses: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Identify behavioral clusters and flag suspicious ones.

  Uses ML clustering to group similar behaviors and identify outliers.

  ## Options
  - `:organization_id` - Organization ID (required)
  - `:entity_type` - What to cluster: :process, :network, :user (default: :process)
  - `:hours` - Hours of data to analyze (default: 24)
  - `:min_cluster_size` - Minimum cluster size (default: 3)

  ## Returns
  `{:ok, clusters}` where each cluster has:
  - `:cluster_id` - Unique cluster identifier
  - `:entity_type` - Type of entities clustered
  - `:size` - Number of entities in cluster
  - `:is_outlier` - Whether cluster is suspicious
  - `:suspiciousness_score` - Score 0-100
  - `:representative_entities` - Sample entities from cluster
  - `:hunt_query` - Query to hunt for this cluster
  """
  def identify_clusters(opts) do
    organization_id = Keyword.fetch!(opts, :organization_id)
    entity_type = Keyword.get(opts, :entity_type, :process)
    hours = Keyword.get(opts, :hours, 24)
    min_cluster_size = Keyword.get(opts, :min_cluster_size, 3)

    # Call ML service for clustering
    case MLClient.post("/hunting/cluster", %{
           organization_id: organization_id,
           entity_type: entity_type,
           hours: hours,
           min_cluster_size: min_cluster_size
         }) do
      {:ok, %{"clusters" => clusters}} ->
        formatted =
          Enum.map(clusters, fn cluster ->
            %{
              cluster_id: cluster["cluster_id"],
              entity_type: String.to_atom(cluster["entity_type"]),
              size: cluster["size"],
              is_outlier: cluster["is_outlier"],
              suspiciousness_score: cluster["suspiciousness_score"],
              representative_entities: cluster["representative_entities"],
              hunt_query: build_cluster_hunt_query(cluster, entity_type),
              features: cluster["features"]
            }
          end)

        {:ok, formatted}

      {:error, reason} ->
        Logger.error("Clustering failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Rank hunt results by suspiciousness.

  Uses ML model to score and rank hunt results.

  ## Parameters
  - `hunt_results` - List of hunt results to rank
  - `organization_id` - Organization ID

  ## Returns
  `{:ok, ranked_results}` with suspiciousness scores added
  """
  def rank_hunt_results(hunt_results, organization_id) do
    case MLClient.post("/hunting/rank", %{
           results: hunt_results,
           organization_id: organization_id
         }) do
      {:ok, %{"ranked_results" => ranked}} ->
        {:ok, ranked}

      {:error, reason} ->
        Logger.warning("ML ranking failed, using fallback: #{inspect(reason)}")
        # Fallback to simple heuristic ranking
        {:ok, fallback_rank_results(hunt_results)}
    end
  end

  @doc """
  Generate a hunt template from an alert.

  Automatically creates reusable hunt templates based on alert characteristics.

  ## Parameters
  - `alert_id` - Alert ID to generate template from
  - `organization_id` - Organization ID

  ## Returns
  `{:ok, template_attrs}` with template ready to save
  """
  def generate_template_from_alert(alert_id, organization_id) do
    case Alerts.get_alert(alert_id) do
      nil ->
        {:error, :alert_not_found}

      alert ->
        template = %{
          name: "Hunt: #{alert.title}",
          description: """
          Auto-generated hunt template based on alert '#{alert.title}'.

          Original alert: #{alert.description}

          This template searches for similar activity patterns.
          """,
          category: infer_category_from_alert(alert),
          query: QuerySuggester.generate_hunt_query_from_alert(alert),
          mitre_techniques: alert.mitre_techniques || [],
          severity: alert.severity,
          is_built_in: false,
          is_public: false,
          organization_id: organization_id,
          variables: extract_variables_from_alert(alert),
          tags: ["auto-generated", "ml-assisted"] ++ (alert.tags || []),
          metadata: %{
            source_alert_id: alert.id,
            generated_at: DateTime.utc_now(),
            generator: "ml_assistant"
          }
        }

        {:ok, template}
    end
  end

  @doc """
  Suggest next pivot steps based on hunt results.

  Analyzes hunt results and recommends follow-up hunts.

  ## Parameters
  - `hunt_results` - Current hunt results
  - `query` - Original hunt query
  - `organization_id` - Organization ID

  ## Returns
  `{:ok, pivot_suggestions}` where each suggestion has:
  - `:title` - Pivot suggestion title
  - `:query` - Suggested pivot query
  - `:reasoning` - Why this pivot is suggested
  - `:confidence` - Confidence score 0-100
  """
  def suggest_pivots(hunt_results, query, organization_id) do
    case MLClient.post("/hunting/pivot", %{
           hunt_results: hunt_results,
           original_query: query,
           organization_id: organization_id
         }) do
      {:ok, %{"pivots" => pivots}} ->
        {:ok, pivots}

      {:error, _reason} ->
        # Fallback to rule-based pivot suggestions
        {:ok, fallback_pivot_suggestions(hunt_results, query)}
    end
  end

  @doc """
  Get "users also hunted for" recommendations.

  Collaborative filtering based on hunt patterns.

  ## Parameters
  - `query` - Current hunt query
  - `organization_id` - Organization ID
  - `limit` - Max recommendations (default: 5)

  ## Returns
  `{:ok, recommendations}` list of related hunt queries
  """
  def get_hunt_recommendations(query, organization_id, limit \\ 5) do
    # Query hunt history for similar patterns
    similar_hunts =
      TamanduaServer.Hunting.SavedQueries.find_similar_queries(query, organization_id, limit)

    recommendations =
      Enum.map(similar_hunts, fn saved_query ->
        %{
          title: saved_query.name,
          query: saved_query.query,
          usage_count: saved_query.usage_count || 0,
          success_rate: calculate_success_rate(saved_query),
          tags: saved_query.tags || []
        }
      end)

    {:ok, recommendations}
  end

  # Private Functions

  defp suggest_from_alert(alert_id, organization_id) do
    case Alerts.get_alert(alert_id) do
      nil ->
        []

      alert ->
        QuerySuggester.suggest_from_alert(alert, organization_id)
    end
  end

  defp suggest_from_recent_activity(organization_id, days) do
    cutoff = DateTime.utc_now() |> DateTime.add(-days * 86400, :second)

    # Get recent high-severity alerts
    alerts =
      Alerts.list_alerts_for_org(organization_id,
        severity: ["high", "critical"],
        since: cutoff,
        limit: 20
      )

    # Generate suggestions from each alert
    alerts
    |> Enum.flat_map(&QuerySuggester.suggest_from_alert(&1, organization_id))
    |> Enum.uniq_by(& &1.query)
  end

  defp rank_suggestions(suggestions, limit) do
    suggestions
    |> Enum.sort_by(& &1.confidence, :desc)
    |> Enum.take(limit)
  end

  defp anomaly_to_hypothesis(anomaly) do
    %{
      title: anomaly["title"],
      description: anomaly["description"],
      query: anomaly["suggested_query"],
      mitre_ttps: anomaly["mitre_ttps"] || [],
      suspiciousness_score: anomaly["score"],
      anomaly_type: anomaly["anomaly_type"],
      evidence: anomaly["evidence"],
      timestamp: DateTime.utc_now()
    }
  end

  defp build_cluster_hunt_query(cluster, entity_type) do
    case entity_type do
      :process ->
        # Build query to find processes in this cluster
        entities = cluster["representative_entities"]
        process_names = Enum.map(entities, & &1["process_name"])

        if length(process_names) > 1 do
          names = Enum.join(process_names, " OR process.name:")
          "process.name:#{names}"
        else
          "process.name:#{hd(process_names)}"
        end

      :network ->
        # Build query for network cluster
        entities = cluster["representative_entities"]
        ips = Enum.map(entities, & &1["dst_ip"]) |> Enum.uniq()
        "network.dst_ip:(#{Enum.join(ips, " OR ")})"

      :user ->
        # Build query for user behavior cluster
        entities = cluster["representative_entities"]
        usernames = Enum.map(entities, & &1["username"]) |> Enum.uniq()
        "user.name:(#{Enum.join(usernames, " OR ")})"
    end
  end

  defp fallback_rank_results(results) do
    # Simple heuristic-based ranking
    Enum.map(results, fn result ->
      score = calculate_heuristic_score(result)
      Map.put(result, :suspiciousness_score, score)
    end)
    |> Enum.sort_by(& &1.suspiciousness_score, :desc)
  end

  defp calculate_heuristic_score(result) do
    score = 0

    # Rarity bonus (uncommon = suspicious)
    score = if Map.get(result, :rarity, 1.0) < 0.01, do: score + 30, else: score

    # MITRE mapping bonus
    score = if Map.get(result, :mitre_ttps, []) != [], do: score + 20, else: score

    # Obfuscation indicators
    score = if Map.get(result, :has_obfuscation, false), do: score + 25, else: score

    # High severity
    score =
      if Map.get(result, :severity) in ["high", "critical"], do: score + 15, else: score

    # External network connections
    score = if Map.get(result, :external_connection, false), do: score + 10, else: score

    min(100, score)
  end

  defp fallback_pivot_suggestions(hunt_results, _query) do
    # Extract common patterns from results
    suggestions = []

    # Suggest pivoting on parent process if we found suspicious children
    suggestions =
      if has_suspicious_child_processes?(hunt_results) do
        [
          %{
            title: "Investigate parent processes",
            query: build_parent_process_query(hunt_results),
            reasoning: "Multiple suspicious child processes detected",
            confidence: 75
          }
          | suggestions
        ]
      else
        suggestions
      end

    # Suggest network pivot if processes made connections
    suggestions =
      if has_network_activity?(hunt_results) do
        [
          %{
            title: "Hunt for network connections",
            query: build_network_pivot_query(hunt_results),
            reasoning: "Processes communicated with external hosts",
            confidence: 70
          }
          | suggestions
        ]
      else
        suggestions
      end

    # Suggest file pivot if file modifications detected
    suggestions =
      if has_file_modifications?(hunt_results) do
        [
          %{
            title: "Track file modifications",
            query: build_file_pivot_query(hunt_results),
            reasoning: "File system modifications detected",
            confidence: 65
          }
          | suggestions
        ]
      else
        suggestions
      end

    suggestions
  end

  defp has_suspicious_child_processes?(results) do
    Enum.any?(results, fn r ->
      Map.has_key?(r, :parent_process) and r[:parent_process] != nil
    end)
  end

  defp has_network_activity?(results) do
    Enum.any?(results, fn r -> Map.has_key?(r, :network_connections) end)
  end

  defp has_file_modifications?(results) do
    Enum.any?(results, fn r -> Map.has_key?(r, :modified_files) end)
  end

  defp build_parent_process_query(results) do
    parent_pids =
      results
      |> Enum.map(& &1[:parent_process][:pid])
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    if length(parent_pids) > 0 do
      "process.pid:(#{Enum.join(parent_pids, " OR ")})"
    else
      "process.parent.name:*"
    end
  end

  defp build_network_pivot_query(results) do
    "network.direction:outbound AND process.name:(#{extract_process_names(results)})"
  end

  defp build_file_pivot_query(results) do
    "file.operation:(create OR modify OR delete) AND process.name:(#{extract_process_names(results)})"
  end

  defp extract_process_names(results) do
    results
    |> Enum.map(& &1[:process_name])
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
    |> Enum.join(" OR ")
  end

  defp infer_category_from_alert(alert) do
    cond do
      alert.title =~ ~r/credential|password|hash/i -> "credential_access"
      alert.title =~ ~r/lateral|smb|rdp/i -> "lateral_movement"
      alert.title =~ ~r/exfil|upload|transfer/i -> "exfiltration"
      alert.title =~ ~r/persistence|startup|registry/i -> "persistence"
      alert.title =~ ~r/execution|command|script/i -> "execution"
      alert.title =~ ~r/privilege|elevat|admin/i -> "privilege_escalation"
      alert.title =~ ~r/defense|evasion|disable/i -> "defense_evasion"
      true -> "general"
    end
  end

  defp extract_variables_from_alert(alert) do
    variables = %{}

    # Extract IOCs as variables
    variables =
      if alert.iocs do
        alert.iocs
        |> Enum.reduce(variables, fn ioc, acc ->
          case ioc.type do
            "ip" -> Map.put(acc, :suspicious_ip, ioc.value)
            "domain" -> Map.put(acc, :suspicious_domain, ioc.value)
            "hash" -> Map.put(acc, :suspicious_hash, ioc.value)
            "process" -> Map.put(acc, :suspicious_process, ioc.value)
            _ -> acc
          end
        end)
      else
        variables
      end

    # Add time window
    Map.put(variables, :time_window, "7d")
  end

  defp calculate_success_rate(saved_query) do
    # Calculate success rate based on historical executions
    executions = saved_query.execution_count || 0
    findings = saved_query.findings_count || 0

    if executions > 0 do
      round(findings / executions * 100)
    else
      0
    end
  end
end
