defmodule TamanduaServer.Mitre.Navigator do
  @moduledoc """
  MITRE ATT&CK Navigator layer generator.

  Generates Navigator-compatible JSON layers for:
  - Detection coverage heatmaps
  - Alert frequency heatmaps
  - Technique severity scoring
  - Custom visualizations

  Navigator layers can be imported into the official MITRE ATT&CK Navigator:
  https://mitre-attack.github.io/attack-navigator/
  """

  require Logger
  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Mitre.{TechniqueMapping, NavigatorLayer, Technique}
  import Ecto.Query

  @navigator_version "4.9"
  @domain "enterprise-attack"

  @doc """
  Generate a coverage layer showing which techniques have detection rules.

  Options:
  - `:organization_id` - Filter by organization
  - `:include_disabled` - Include disabled rules (default: false)
  """
  def generate_coverage_layer(opts \\ []) do
    org_id = Keyword.get(opts, :organization_id)
    _include_disabled = Keyword.get(opts, :include_disabled, false)

    # Get all technique mappings
    query = from m in TechniqueMapping

    query = if org_id do
      from m in query, where: m.organization_id == ^org_id or is_nil(m.organization_id)
    else
      query
    end

    mappings = Repo.all(query)

    # Group by technique and count rules
    technique_coverage =
      mappings
      |> Enum.group_by(& &1.technique_id)
      |> Enum.map(fn {tech_id, rules} ->
        %{
          techniqueID: tech_id,
          score: min(length(rules) * 25, 100),  # Scale: 1 rule = 25, capped at 100
          color: coverage_color(length(rules)),
          comment: "#{length(rules)} detection rules",
          metadata: %{
            rule_count: length(rules),
            rule_types: Enum.frequencies_by(rules, & &1.rule_type)
          }
        }
      end)

    %{
      name: "Tamandua EDR - Detection Coverage",
      versions: %{
        attack: "14",
        navigator: @navigator_version,
        layer: "4.5"
      },
      domain: @domain,
      description: "Detection rule coverage across MITRE ATT&CK techniques. Darker colors indicate more detection rules.",
      techniques: technique_coverage,
      gradient: %{
        colors: ["#ffffff", "#66b3ff", "#0066cc"],
        minValue: 0,
        maxValue: 100
      },
      legendItems: [
        %{label: "No coverage", color: "#ffffff"},
        %{label: "1 rule", color: "#ccddff"},
        %{label: "2-3 rules", color: "#66b3ff"},
        %{label: "4+ rules", color: "#0066cc"}
      ],
      showTacticRowBackground: true,
      tacticRowBackground: "#dddddd",
      selectTechniquesAcrossTactics: true
    }
  end

  @doc """
  Generate an alert frequency layer showing which techniques fired alerts.

  Options:
  - `:organization_id` - Filter by organization
  - `:agent_id` - Filter by specific agent
  - `:time_range` - Time range (default: last 30 days)
  - `:severity_weight` - Weight alerts by severity (default: true)
  """
  def generate_frequency_layer(opts \\ []) do
    org_id = Keyword.get(opts, :organization_id)
    agent_id = Keyword.get(opts, :agent_id)
    days = Keyword.get(opts, :time_range, 30)
    severity_weight = Keyword.get(opts, :severity_weight, true)

    since = DateTime.utc_now() |> DateTime.add(-days * 24 * 60 * 60, :second)

    # Query alerts with MITRE techniques
    query = from a in Alert,
      where: not is_nil(a.mitre_techniques) and a.inserted_at >= ^since,
      select: %{techniques: a.mitre_techniques, severity: a.severity}

    query = if org_id, do: from(a in query, where: a.organization_id == ^org_id), else: query
    query = if agent_id, do: from(a in query, where: a.agent_id == ^agent_id), else: query

    alerts = Repo.all(query)

    # Calculate technique scores
    technique_scores =
      alerts
      |> Enum.flat_map(fn alert ->
        weight = if severity_weight, do: severity_to_weight(alert.severity), else: 1.0
        Enum.map(alert.techniques, fn tech -> {tech, weight} end)
      end)
      |> Enum.group_by(fn {tech, _} -> tech end, fn {_, weight} -> weight end)
      |> Enum.map(fn {tech_id, weights} ->
        total_weight = Enum.sum(weights)
        count = length(weights)
        avg_weight = total_weight / count

        %{
          techniqueID: tech_id,
          score: min(round(total_weight * 10), 100),
          color: frequency_color(count),
          comment: "#{count} alerts (avg severity: #{format_weight(avg_weight)})",
          metadata: %{
            alert_count: count,
            total_score: total_weight,
            avg_severity: avg_weight
          }
        }
      end)

    %{
      name: "Tamandua EDR - Alert Frequency (Last #{days} Days)",
      versions: %{
        attack: "14",
        navigator: @navigator_version,
        layer: "4.5"
      },
      domain: @domain,
      description: "Alert frequency by technique over the last #{days} days. Color intensity indicates alert volume and severity.",
      techniques: technique_scores,
      gradient: %{
        colors: ["#ffffff", "#ffcc66", "#ff6666"],
        minValue: 0,
        maxValue: 100
      },
      legendItems: [
        %{label: "No alerts", color: "#ffffff"},
        %{label: "1-5 alerts", color: "#ffddaa"},
        %{label: "6-20 alerts", color: "#ffcc66"},
        %{label: "21+ alerts", color: "#ff6666"}
      ],
      showTacticRowBackground: true,
      tacticRowBackground: "#dddddd",
      selectTechniquesAcrossTactics: true,
      metadata: %{
        time_range_days: days,
        severity_weighted: severity_weight
      }
    }
  end

  @doc """
  Generate a gap analysis layer showing uncovered techniques.

  Highlights techniques with NO detection rules, helping prioritize
  detection engineering efforts.
  """
  def generate_gap_layer(opts \\ []) do
    org_id = Keyword.get(opts, :organization_id)

    # Get all techniques from database
    all_techniques = Repo.all(from t in Technique, select: t.technique_id)

    # Get covered techniques
    query = from m in TechniqueMapping, select: m.technique_id, distinct: true
    query = if org_id do
      from m in query, where: m.organization_id == ^org_id or is_nil(m.organization_id)
    else
      query
    end

    covered_techniques = Repo.all(query) |> MapSet.new()

    # Find gaps
    gap_techniques =
      all_techniques
      |> Enum.reject(&MapSet.member?(covered_techniques, &1))
      |> Enum.map(fn tech_id ->
        %{
          techniqueID: tech_id,
          color: "#ff6666",
          comment: "No detection coverage",
          metadata: %{gap: true}
        }
      end)

    %{
      name: "Tamandua EDR - Coverage Gaps",
      versions: %{
        attack: "14",
        navigator: @navigator_version,
        layer: "4.5"
      },
      domain: @domain,
      description: "Techniques with NO detection rules. Red = gap, prioritize these for detection engineering.",
      techniques: gap_techniques,
      legendItems: [
        %{label: "No coverage (gap)", color: "#ff6666"}
      ],
      showTacticRowBackground: true,
      tacticRowBackground: "#dddddd",
      selectTechniquesAcrossTactics: true
    }
  end

  @doc """
  Generate a custom layer with user-defined technique scores/colors.

  Expects a list of technique data:
  [
    %{technique_id: "T1059", score: 75, color: "#ff0000", comment: "Custom"},
    ...
  ]
  """
  def generate_custom_layer(name, description, technique_data, opts \\ []) do
    techniques =
      technique_data
      |> Enum.map(fn data ->
        %{
          techniqueID: data.technique_id,
          score: Map.get(data, :score),
          color: Map.get(data, :color),
          comment: Map.get(data, :comment),
          metadata: Map.get(data, :metadata, %{})
        }
        |> Enum.reject(fn {_k, v} -> is_nil(v) end)
        |> Map.new()
      end)

    %{
      name: name,
      versions: %{
        attack: "14",
        navigator: @navigator_version,
        layer: "4.5"
      },
      domain: @domain,
      description: description,
      techniques: techniques,
      gradient: Keyword.get(opts, :gradient, %{
        colors: ["#ffffff", "#66b3ff", "#0066cc"],
        minValue: 0,
        maxValue: 100
      }),
      showTacticRowBackground: true,
      tacticRowBackground: "#dddddd",
      selectTechniquesAcrossTactics: true
    }
  end

  @doc """
  Save a navigator layer to the database.
  """
  def save_layer(layer_data, name, opts \\ []) do
    attrs = %{
      name: name,
      description: Keyword.get(opts, :description, layer_data[:description]),
      layer_data: layer_data,
      layer_type: Keyword.get(opts, :layer_type, "custom"),
      is_public: Keyword.get(opts, :is_public, false),
      time_range_start: Keyword.get(opts, :time_range_start),
      time_range_end: Keyword.get(opts, :time_range_end),
      organization_id: Keyword.get(opts, :organization_id),
      created_by_id: Keyword.get(opts, :created_by_id)
    }

    %NavigatorLayer{}
    |> NavigatorLayer.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Export layer as JSON string.
  """
  def export_layer_json(layer_data) do
    Jason.encode!(layer_data, pretty: true)
  end

  @doc """
  Get saved layer by ID.
  """
  def get_layer(layer_id) do
    Repo.get(NavigatorLayer, layer_id)
  end

  @doc """
  List all saved layers for an organization.
  """
  def list_layers(organization_id) do
    Repo.all(
      from l in NavigatorLayer,
      where: l.organization_id == ^organization_id or l.is_public == true,
      order_by: [desc: l.inserted_at]
    )
  end

  @doc """
  Delete a saved layer.
  """
  def delete_layer(layer_id) do
    case Repo.get(NavigatorLayer, layer_id) do
      nil -> {:error, :not_found}
      layer -> Repo.delete(layer)
    end
  end

  # Private helper functions

  defp coverage_color(rule_count) do
    cond do
      rule_count >= 4 -> "#0066cc"
      rule_count >= 2 -> "#66b3ff"
      rule_count >= 1 -> "#ccddff"
      true -> "#ffffff"
    end
  end

  defp frequency_color(alert_count) do
    cond do
      alert_count >= 21 -> "#ff6666"
      alert_count >= 6 -> "#ffcc66"
      alert_count >= 1 -> "#ffddaa"
      true -> "#ffffff"
    end
  end

  defp severity_to_weight(severity) do
    case severity do
      "critical" -> 5.0
      "high" -> 3.0
      "medium" -> 2.0
      "low" -> 1.0
      _ -> 1.0
    end
  end

  defp format_weight(weight) do
    case weight do
      w when w >= 4.0 -> "critical"
      w when w >= 2.5 -> "high"
      w when w >= 1.5 -> "medium"
      _ -> "low"
    end
  end
end
