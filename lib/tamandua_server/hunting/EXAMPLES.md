# ML-Assisted Hunting Usage Examples

Practical examples of using ML-assisted threat hunting in Tamandua EDR.

## Example 1: Alert-Driven Hunt Workflow

Investigate a critical alert using ML-assisted suggestions.

```elixir
# Get ML-powered hunt suggestions from alert
{:ok, suggestions} = TamanduaServer.Hunting.MLAssistant.suggest_hunts(
  organization_id: org_id,
  alert_id: alert_id,
  limit: 10
)

# Execute top suggestion
top_suggestion = hd(suggestions)
{:ok, results} = TamanduaServer.Hunting.QueryExecutor.execute(
  top_suggestion.query,
  org_id,
  limit: 100
)

# Rank results by suspiciousness
{:ok, ranked_results} = TamanduaServer.Hunting.MLAssistant.rank_hunt_results(
  results,
  org_id
)

# Get pivot suggestions
{:ok, pivots} = TamanduaServer.Hunting.MLAssistant.suggest_pivots(
  ranked_results,
  top_suggestion.query,
  org_id
)
```

## Example 2: Proactive Anomaly Hunting

```elixir
# Generate hunt hypotheses from anomalies
{:ok, hypotheses} = TamanduaServer.Hunting.MLAssistant.generate_hypotheses(
  organization_id: org_id,
  hours: 24,
  min_suspiciousness: 70
)

# Test each hypothesis
Enum.each(hypotheses, fn hypothesis ->
  {:ok, results} = TamanduaServer.Hunting.QueryExecutor.execute(
    hypothesis.query,
    org_id
  )

  if length(results) > 0 do
    # Create alert from confirmed hypothesis
    TamanduaServer.Alerts.create_alert(%{
      title: "Anomaly Hunt: #{hypothesis.title}",
      description: hypothesis.description,
      severity: "high",
      organization_id: org_id
    })
  end
end)
```

## Example 3: Behavioral Clustering

```elixir
# Cluster process behaviors
{:ok, clusters} = TamanduaServer.Hunting.MLAssistant.identify_clusters(
  organization_id: org_id,
  entity_type: :process,
  hours: 24
)

# Hunt for outlier clusters
outliers = Enum.filter(clusters, & &1.is_outlier)
|> Enum.sort_by(& &1.suspiciousness_score, :desc)

Enum.each(outliers, fn cluster ->
  {:ok, results} = TamanduaServer.Hunting.QueryExecutor.execute(
    cluster.hunt_query,
    org_id
  )

  IO.puts("Cluster ##{cluster.cluster_id}: #{length(results)} results")
end)
```

See ML_ASSISTED_HUNTING.md for complete documentation.
