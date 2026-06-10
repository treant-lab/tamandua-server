# ML-Assisted Threat Hunting

Tamandua EDR provides advanced ML-powered threat hunting capabilities to help security analysts discover threats proactively.

## Overview

ML-assisted hunting combines:
- **Automatic query suggestions** based on alerts and patterns
- **Anomaly-driven hunt hypotheses** from behavioral analysis
- **Behavioral clustering** to identify suspicious activity groups
- **Suspiciousness ranking** of hunt results using ensemble ML
- **Hunt template generation** for reusable hunts
- **ML-powered pivot suggestions** for multi-step investigations

## Features

### 1. Automatic Query Suggestion

Generate hunt queries automatically based on alert context:

```elixir
# Suggest hunts from a specific alert
{:ok, suggestions} = TamanduaServer.Hunting.MLAssistant.suggest_hunts(
  organization_id: org_id,
  alert_id: alert_id,
  limit: 10
)

# Suggest hunts from recent activity
{:ok, suggestions} = TamanduaServer.Hunting.MLAssistant.suggest_hunts(
  organization_id: org_id,
  days: 7,
  limit: 10
)
```

Each suggestion includes:
- `title` - Descriptive hunt title
- `query` - Ready-to-execute TQL query
- `description` - What the hunt looks for
- `mitre_ttps` - Related MITRE ATT&CK techniques
- `confidence` - Confidence score 0-100
- `source` - How suggestion was generated (pattern_matching, ml_generation, etc.)
- `reasoning` - Why this hunt is recommended

**Example suggestions for a mimikatz alert:**
```elixir
[
  %{
    title: "Find similar Mimikatz Execution Detected",
    query: "process.name:mimikatz.exe AND process.command_line:*sekurlsa*",
    description: "Hunt for similar activity patterns in the last 7 days",
    confidence: 90,
    mitre_ttps: ["T1003.001"],
    source: "pattern_matching",
    reasoning: "Looks for exact or similar patterns to the original alert"
  },
  %{
    title: "Hunt for credential dumping tools",
    query: "(process.name:mimikatz.exe OR process.name:procdump.exe) AND (file.path:*lsass* OR process.access_target:lsass.exe)",
    description: "Search for common credential theft tools and LSASS access",
    confidence: 90,
    mitre_ttps: ["T1003.001", "T1003.002"],
    source: "ttp_correlation",
    reasoning: "Alert indicates credential access, hunt for related tools"
  }
]
```

### 2. Anomaly-Driven Hunt Hypotheses

Generate actionable hunt hypotheses from detected anomalies:

```elixir
{:ok, hypotheses} = TamanduaServer.Hunting.MLAssistant.generate_hypotheses(
  organization_id: org_id,
  hours: 24,
  min_suspiciousness: 60
)
```

**Example hypothesis:**
```elixir
%{
  title: "Unusual network connection from powershell.exe",
  description: "Anomaly detected: unusual_network_connection\n\nDetails:\n- Process name: powershell.exe\n- Destination IP: 1.2.3.4\n- Destination port: 8080\n\nSuspiciousness score: 85/100",
  query: "process.name:powershell.exe AND network.dst_ip:1.2.3.4 AND network.dst_port:8080 AND network.direction:outbound",
  mitre_ttps: ["T1071.001", "T1071.004"],
  suspiciousness_score: 85,
  anomaly_type: "unusual_network_connection",
  evidence: [
    "Deviates 85% from baseline",
    "Rarity score: 0.995",
    "First seen: 2024-01-01T12:00:00Z"
  ],
  recommended_actions: [
    "Investigate destination IP reputation",
    "Check for other processes connecting to same IP",
    "Review firewall logs for this connection",
    "Verify if connection is business-justified"
  ]
}
```

**Anomaly types detected:**
- `unusual_network_connection` - Rare external connections
- `rare_process_execution` - Uncommon process executions
- `abnormal_user_behavior` - Unusual user activity patterns
- `unusual_command_line` - Suspicious command line patterns
- `abnormal_file_access` - Unexpected file access patterns
- `process_injection_indicator` - Signs of process injection
- `credential_access_pattern` - Credential theft behaviors
- `data_exfiltration_pattern` - Large data uploads

### 3. Behavioral Cluster Identification

Group similar behaviors and identify suspicious outlier clusters:

```elixir
# Cluster process behaviors
{:ok, clusters} = TamanduaServer.Hunting.MLAssistant.identify_clusters(
  organization_id: org_id,
  entity_type: :process,
  hours: 24,
  min_cluster_size: 3
)

# Cluster network activity
{:ok, clusters} = TamanduaServer.Hunting.MLAssistant.identify_clusters(
  organization_id: org_id,
  entity_type: :network,
  hours: 24
)

# Cluster user behaviors
{:ok, clusters} = TamanduaServer.Hunting.MLAssistant.identify_clusters(
  organization_id: org_id,
  entity_type: :user,
  hours: 24
)
```

**Cluster structure:**
```elixir
%{
  cluster_id: 5,
  entity_type: :process,
  size: 3,
  is_outlier: true,
  suspiciousness_score: 85.5,
  representative_entities: [
    %{process_name: "powershell.exe", command_line: "..."},
    %{process_name: "powershell.exe", command_line: "..."}
  ],
  hunt_query: "process.name:powershell.exe",
  features: %{
    "command_line_length" => 150.5,
    "is_elevated" => 1.0,
    "external_conn_count" => 2.3
  }
}
```

**Clustering algorithm:**
- Uses HDBSCAN for density-based clustering
- Features extracted: process lineage, command line patterns, network activity, file access
- Small clusters (< 5% of total) flagged as outliers
- Suspiciousness score based on cluster size, isolation, and behavioral features

### 4. Hunt Result Ranking

Rank hunt results by suspiciousness using ML ensemble:

```elixir
hunt_results = [
  %{
    process_name: "mimikatz.exe",
    rarity: 0.001,
    mitre_ttps: ["T1003.001"],
    is_elevated: true,
    is_signed: false,
    has_obfuscation: true
  },
  %{
    process_name: "notepad.exe",
    rarity: 0.8,
    mitre_ttps: [],
    is_elevated: false,
    is_signed: true
  }
]

{:ok, ranked_results} = TamanduaServer.Hunting.MLAssistant.rank_hunt_results(
  hunt_results,
  org_id
)
```

**Ranked result:**
```elixir
[
  %{
    process_name: "mimikatz.exe",
    # ... original fields ...
    suspiciousness_score: 95.0,
    ranking_factors: %{
      rarity: 30.0,
      mitre_mapping: 20.0,
      behavioral_indicators: 25.0,
      ml_prediction: 20.0
    },
    risk_level: "critical"
  }
]
```

**Ranking factors:**
1. **Rarity (0-30 points)**: Uncommon processes/IPs = suspicious
2. **MITRE mapping (0-20 points)**: Known TTP = suspicious
3. **Behavioral indicators (0-25 points)**: Obfuscation, evasion, credential access
4. **ML prediction (0-25 points)**: XGBoost ensemble prediction

**Risk levels:**
- `critical`: Score ≥ 80
- `high`: Score ≥ 60
- `medium`: Score ≥ 40
- `low`: Score < 40

### 5. Hunt Template Generation

Auto-generate reusable hunt templates from alerts:

```elixir
{:ok, template_attrs} = TamanduaServer.Hunting.MLAssistant.generate_template_from_alert(
  alert_id,
  org_id
)

# Save as QueryTemplate
{:ok, template} = TamanduaServer.Repo.insert(
  TamanduaServer.Hunting.QueryTemplate.changeset(
    %TamanduaServer.Hunting.QueryTemplate{},
    template_attrs
  )
)
```

**Generated template:**
```elixir
%{
  name: "Hunt: Mimikatz Credential Dumping",
  description: "Auto-generated hunt template...",
  category: "credential_access",
  query: "(process.name:mimikatz.exe OR process.name:procdump.exe) AND (file.path:*lsass* OR process.access_target:lsass.exe)",
  mitre_techniques: ["T1003.001"],
  severity: "critical",
  variables: %{
    suspicious_process: "mimikatz.exe",
    time_window: "7d"
  },
  tags: ["auto-generated", "ml-assisted", "credential_access"],
  metadata: %{
    source_alert_id: "...",
    generated_at: ~U[2024-01-01 12:00:00Z],
    generator: "ml_assistant"
  }
}
```

### 6. ML-Powered Hunt Pivoting

Get intelligent suggestions for next hunt steps:

```elixir
{:ok, pivot_suggestions} = TamanduaServer.Hunting.MLAssistant.suggest_pivots(
  hunt_results,
  original_query,
  org_id
)
```

**Pivot suggestions:**
```elixir
[
  %{
    title: "Investigate parent processes",
    query: "process.name:(cmd.exe OR explorer.exe)",
    reasoning: "Multiple suspicious child processes detected",
    confidence: 75
  },
  %{
    title: "Hunt for network connections",
    query: "network.direction:outbound AND process.name:(powershell.exe OR cmd.exe)",
    reasoning: "Processes communicated with external hosts",
    confidence: 70
  },
  %{
    title: "Track file modifications",
    query: "file.operation:(create OR modify OR delete) AND process.name:powershell.exe",
    reasoning: "File system modifications detected",
    confidence: 65
  }
]
```

### 7. Hunt Recommendations

Get "analysts also hunted for" recommendations:

```elixir
{:ok, recommendations} = TamanduaServer.Hunting.MLAssistant.get_hunt_recommendations(
  current_query,
  org_id,
  limit: 5
)
```

## Architecture

### Backend (Elixir)

**Modules:**
- `TamanduaServer.Hunting.MLAssistant` - Main coordinator
- `TamanduaServer.Hunting.QuerySuggester` - Query generation logic
- `TamanduaServer.Hunting.AnomalyHunter` - Anomaly-to-hypothesis converter

### ML Service (Python)

**Modules:**
- `src.hunting.cluster_analyzer.BehavioralClusterAnalyzer` - HDBSCAN clustering
- `src.hunting.suspiciousness_ranker.SuspiciousnessRanker` - XGBoost ranking
- `src.hunting.suspiciousness_ranker.PivotSuggester` - Pivot recommendations

**API Endpoints:**
- `POST /hunting/cluster` - Cluster behavioral entities
- `POST /hunting/rank` - Rank hunt results
- `POST /hunting/suggest_queries` - Generate query suggestions (GPT-based)
- `POST /hunting/pivot` - Suggest pivot steps

## Usage Examples

### Example 1: Hunt from Alert

```elixir
# 1. Get suggestions from alert
{:ok, suggestions} = MLAssistant.suggest_hunts(
  organization_id: org_id,
  alert_id: alert_id,
  limit: 5
)

# 2. Execute top suggestion
top_suggestion = hd(suggestions)
{:ok, results} = TamanduaServer.Hunting.QueryExecutor.execute(
  top_suggestion.query,
  org_id
)

# 3. Rank results
{:ok, ranked} = MLAssistant.rank_hunt_results(results, org_id)

# 4. Investigate top result
top_result = hd(ranked)
IO.puts("Risk: #{top_result.risk_level}, Score: #{top_result.suspiciousness_score}")

# 5. Get pivot suggestions
{:ok, pivots} = MLAssistant.suggest_pivots(results, top_suggestion.query, org_id)

# 6. Execute pivot
top_pivot = hd(pivots)
{:ok, pivot_results} = TamanduaServer.Hunting.QueryExecutor.execute(
  top_pivot.query,
  org_id
)
```

### Example 2: Anomaly-Driven Hunt

```elixir
# 1. Generate hypotheses from anomalies
{:ok, hypotheses} = MLAssistant.generate_hypotheses(
  organization_id: org_id,
  hours: 24,
  min_suspiciousness: 70
)

# 2. Test highest-scoring hypothesis
hypothesis = hd(hypotheses)
IO.puts("Testing: #{hypothesis.title}")
IO.puts("Score: #{hypothesis.suspiciousness_score}")

{:ok, results} = TamanduaServer.Hunting.QueryExecutor.execute(
  hypothesis.query,
  org_id
)

# 3. Review recommended actions
Enum.each(hypothesis.recommended_actions, fn action ->
  IO.puts("- #{action}")
end)
```

### Example 3: Cluster-Based Hunt

```elixir
# 1. Identify suspicious process clusters
{:ok, clusters} = MLAssistant.identify_clusters(
  organization_id: org_id,
  entity_type: :process,
  hours: 24
)

# 2. Focus on outlier clusters
outliers = Enum.filter(clusters, & &1.is_outlier)

# 3. Hunt for each outlier cluster
Enum.each(outliers, fn cluster ->
  IO.puts("Cluster #{cluster.cluster_id}: #{cluster.size} entities, score #{cluster.suspiciousness_score}")

  {:ok, results} = TamanduaServer.Hunting.QueryExecutor.execute(
    cluster.hunt_query,
    org_id
  )

  IO.puts("Found #{length(results)} results")
end)
```

### Example 4: Generate and Save Template

```elixir
# 1. Generate template from alert
{:ok, template_attrs} = MLAssistant.generate_template_from_alert(alert_id, org_id)

# 2. Customize if needed
template_attrs = Map.put(template_attrs, :name, "Custom Hunt: #{template_attrs.name}")

# 3. Save template
{:ok, template} = TamanduaServer.Repo.insert(
  TamanduaServer.Hunting.QueryTemplate.changeset(
    %TamanduaServer.Hunting.QueryTemplate{},
    template_attrs
  )
)

# 4. Use template later
rendered = TamanduaServer.Hunting.QueryTemplate.render(
  template,
  %{time_window: "30d"}
)

{:ok, results} = TamanduaServer.Hunting.QueryExecutor.execute(
  rendered.query,
  org_id
)
```

## Configuration

### ML Service

Configure in `apps/tamandua_ml/src/utils/config.py`:

```python
# Clustering
MIN_CLUSTER_SIZE = 3
MIN_SAMPLES = 2
OUTLIER_THRESHOLD = 0.05

# Ranking
SUSPICIOUSNESS_MODEL_PATH = "models/suspiciousness_ranker.xgb"
```

### Backend

Configure in `config/config.exs`:

```elixir
config :tamandua_server, :ml_service,
  url: System.get_env("ML_SERVICE_URL") || "http://localhost:8000",
  timeout: 30_000,
  api_key: System.get_env("ML_SERVICE_API_KEY")
```

## Performance

- **Query suggestion**: < 500ms (rule-based), < 2s (ML-powered)
- **Clustering**: 100-1000 events/sec (depends on feature dimensionality)
- **Ranking**: 1000-10000 results/sec
- **Hypothesis generation**: < 1s per anomaly

## Best Practices

1. **Start with high-confidence suggestions**: Filter by `confidence >= 80`
2. **Investigate critical risk first**: Sort by `risk_level: "critical"`
3. **Use templates for common hunts**: Save successful hunts as templates
4. **Follow pivot chains**: Multi-step investigations often reveal more
5. **Tune suspiciousness threshold**: Adjust based on alert volume
6. **Review anomaly hypotheses daily**: Proactive threat discovery

## Future Enhancements

- [ ] GPT-4 integration for natural language query generation
- [ ] Automated hunt workflows (hunt → investigate → respond)
- [ ] Hunt result deduplication
- [ ] Collaborative filtering for hunt recommendations
- [ ] Hunt success metrics and feedback loop
- [ ] Cross-organization threat intelligence sharing
