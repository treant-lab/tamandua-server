defmodule TamanduaServerWeb.API.V1.MitreController do
  @moduledoc """
  API Controller for MITRE ATT&CK coverage metrics.

  Provides endpoints for:
  - Overall coverage statistics
  - Per-tactic coverage breakdown
  - Technique detection details
  - Detection trends
  - Navigator layer export
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Detection
  alias TamanduaServer.Detection.MitreCoverage
  alias TamanduaServer.Alerts

  action_fallback TamanduaServerWeb.FallbackController

  # Extract organization_id from current user for multi-tenant isolation
  defp get_org_id(conn) do
    case conn.assigns[:current_user] do
      %{organization_id: org_id} when not is_nil(org_id) -> org_id
      _ -> nil
    end
  end

  # MITRE ATT&CK Framework data (subset for common techniques)
  @tactics [
    %{id: "TA0001", name: "Initial Access", shortname: "initial-access", description: "Techniques used to gain initial foothold in a network"},
    %{id: "TA0002", name: "Execution", shortname: "execution", description: "Techniques that result in adversary-controlled code running on a system"},
    %{id: "TA0003", name: "Persistence", shortname: "persistence", description: "Techniques used to maintain presence on a system across restarts"},
    %{id: "TA0004", name: "Privilege Escalation", shortname: "privilege-escalation", description: "Techniques used to gain higher-level permissions"},
    %{id: "TA0005", name: "Defense Evasion", shortname: "defense-evasion", description: "Techniques used to avoid detection throughout a compromise"},
    %{id: "TA0006", name: "Credential Access", shortname: "credential-access", description: "Techniques used to steal credentials"},
    %{id: "TA0007", name: "Discovery", shortname: "discovery", description: "Techniques used to gain knowledge about the system and internal network"},
    %{id: "TA0008", name: "Lateral Movement", shortname: "lateral-movement", description: "Techniques used to move through a network"},
    %{id: "TA0009", name: "Collection", shortname: "collection", description: "Techniques used to gather data for exfiltration"},
    %{id: "TA0010", name: "Exfiltration", shortname: "exfiltration", description: "Techniques used to steal data from a network"},
    %{id: "TA0011", name: "Command and Control", shortname: "command-and-control", description: "Techniques used to communicate with compromised systems"},
    %{id: "TA0040", name: "Impact", shortname: "impact", description: "Techniques used to disrupt availability or compromise integrity"}
  ]

  @techniques_by_tactic %{
    "TA0001" => [
      %{id: "T1566", name: "Phishing", subtechniques: ["T1566.001", "T1566.002", "T1566.003"]},
      %{id: "T1190", name: "Exploit Public-Facing Application", subtechniques: []},
      %{id: "T1133", name: "External Remote Services", subtechniques: []},
      %{id: "T1078", name: "Valid Accounts", subtechniques: ["T1078.001", "T1078.002", "T1078.003", "T1078.004"]},
      %{id: "T1189", name: "Drive-by Compromise", subtechniques: []}
    ],
    "TA0002" => [
      %{id: "T1059", name: "Command and Scripting Interpreter", subtechniques: ["T1059.001", "T1059.003", "T1059.005", "T1059.007"]},
      %{id: "T1053", name: "Scheduled Task/Job", subtechniques: ["T1053.005"]},
      %{id: "T1204", name: "User Execution", subtechniques: ["T1204.001", "T1204.002"]},
      %{id: "T1106", name: "Native API", subtechniques: []},
      %{id: "T1047", name: "Windows Management Instrumentation", subtechniques: []}
    ],
    "TA0003" => [
      %{id: "T1547", name: "Boot or Logon Autostart Execution", subtechniques: ["T1547.001", "T1547.004", "T1547.009"]},
      %{id: "T1053", name: "Scheduled Task/Job", subtechniques: ["T1053.005"]},
      %{id: "T1136", name: "Create Account", subtechniques: ["T1136.001", "T1136.002"]},
      %{id: "T1543", name: "Create or Modify System Process", subtechniques: ["T1543.003"]},
      %{id: "T1546", name: "Event Triggered Execution", subtechniques: ["T1546.001", "T1546.003"]}
    ],
    "TA0004" => [
      %{id: "T1548", name: "Abuse Elevation Control Mechanism", subtechniques: ["T1548.002"]},
      %{id: "T1134", name: "Access Token Manipulation", subtechniques: ["T1134.001", "T1134.002"]},
      %{id: "T1055", name: "Process Injection", subtechniques: ["T1055.001", "T1055.002", "T1055.012"]},
      %{id: "T1068", name: "Exploitation for Privilege Escalation", subtechniques: []},
      %{id: "T1078", name: "Valid Accounts", subtechniques: ["T1078.001", "T1078.002", "T1078.003"]}
    ],
    "TA0005" => [
      %{id: "T1070", name: "Indicator Removal", subtechniques: ["T1070.001", "T1070.004", "T1070.006"]},
      %{id: "T1562", name: "Impair Defenses", subtechniques: ["T1562.001", "T1562.004"]},
      %{id: "T1036", name: "Masquerading", subtechniques: ["T1036.003", "T1036.005"]},
      %{id: "T1027", name: "Obfuscated Files or Information", subtechniques: ["T1027.001", "T1027.002"]},
      %{id: "T1055", name: "Process Injection", subtechniques: ["T1055.001", "T1055.002", "T1055.012"]}
    ],
    "TA0006" => [
      %{id: "T1003", name: "OS Credential Dumping", subtechniques: ["T1003.001", "T1003.002", "T1003.003"]},
      %{id: "T1555", name: "Credentials from Password Stores", subtechniques: ["T1555.003"]},
      %{id: "T1056", name: "Input Capture", subtechniques: ["T1056.001"]},
      %{id: "T1110", name: "Brute Force", subtechniques: ["T1110.001", "T1110.003"]},
      %{id: "T1557", name: "Adversary-in-the-Middle", subtechniques: ["T1557.001"]}
    ],
    "TA0007" => [
      %{id: "T1087", name: "Account Discovery", subtechniques: ["T1087.001", "T1087.002"]},
      %{id: "T1083", name: "File and Directory Discovery", subtechniques: []},
      %{id: "T1057", name: "Process Discovery", subtechniques: []},
      %{id: "T1082", name: "System Information Discovery", subtechniques: []},
      %{id: "T1016", name: "System Network Configuration Discovery", subtechniques: []}
    ],
    "TA0008" => [
      %{id: "T1021", name: "Remote Services", subtechniques: ["T1021.001", "T1021.002", "T1021.006"]},
      %{id: "T1570", name: "Lateral Tool Transfer", subtechniques: []},
      %{id: "T1080", name: "Taint Shared Content", subtechniques: []},
      %{id: "T1550", name: "Use Alternate Authentication Material", subtechniques: ["T1550.002"]}
    ],
    "TA0009" => [
      %{id: "T1560", name: "Archive Collected Data", subtechniques: ["T1560.001"]},
      %{id: "T1005", name: "Data from Local System", subtechniques: []},
      %{id: "T1039", name: "Data from Network Shared Drive", subtechniques: []},
      %{id: "T1113", name: "Screen Capture", subtechniques: []},
      %{id: "T1115", name: "Clipboard Data", subtechniques: []}
    ],
    "TA0010" => [
      %{id: "T1041", name: "Exfiltration Over C2 Channel", subtechniques: []},
      %{id: "T1048", name: "Exfiltration Over Alternative Protocol", subtechniques: ["T1048.002"]},
      %{id: "T1567", name: "Exfiltration Over Web Service", subtechniques: ["T1567.002"]},
      %{id: "T1029", name: "Scheduled Transfer", subtechniques: []}
    ],
    "TA0011" => [
      %{id: "T1071", name: "Application Layer Protocol", subtechniques: ["T1071.001", "T1071.004"]},
      %{id: "T1105", name: "Ingress Tool Transfer", subtechniques: []},
      %{id: "T1571", name: "Non-Standard Port", subtechniques: []},
      %{id: "T1572", name: "Protocol Tunneling", subtechniques: []},
      %{id: "T1090", name: "Proxy", subtechniques: ["T1090.001", "T1090.002"]}
    ],
    "TA0040" => [
      %{id: "T1486", name: "Data Encrypted for Impact", subtechniques: []},
      %{id: "T1485", name: "Data Destruction", subtechniques: []},
      %{id: "T1489", name: "Service Stop", subtechniques: []},
      %{id: "T1490", name: "Inhibit System Recovery", subtechniques: []},
      %{id: "T1491", name: "Defacement", subtechniques: ["T1491.001", "T1491.002"]}
    ]
  }

  # ============================================================================
  # Coverage Statistics
  # ============================================================================

  @doc "GET /api/v1/mitre/coverage - Get overall coverage statistics"
  def coverage(conn, _params) do
    org_id = get_org_id(conn)

    # Use the MitreCoverage GenServer for rule-based coverage data
    # (what CAN be detected), enriched with alert-based detection counts
    # (what HAS been detected).
    try do
      summary = MitreCoverage.get_summary()

      json(conn, %{
        data: %{
          total_techniques: summary.total_techniques,
          covered_count: summary.covered_techniques,
          active_count: summary.active_techniques,
          gap_count: summary.gap_techniques,
          coverage_percent: summary.overall_coverage_pct,
          active_percent: summary.active_coverage_pct,
          tactics: summary.tactics,
          generated_at: summary.generated_at
        }
      })
    catch
      _kind, _reason ->
        # Fallback to alert-based coverage if GenServer unavailable
        detection_counts = get_detection_counts(org_id)
        coverage_stats = calculate_coverage(detection_counts)
        json(conn, %{data: coverage_stats})
    end
  end

  @doc "GET /api/v1/mitre/tactics - Get coverage by tactic"
  def tactics(conn, _params) do
    org_id = get_org_id(conn)
    detection_counts = get_detection_counts(org_id)

    by_tactic = Enum.map(@tactics, fn tactic ->
      techniques = @techniques_by_tactic[tactic.id] || []
      technique_details = Enum.map(techniques, fn tech ->
        count = detection_counts[tech.id] || 0
        subtechnique_counts = Enum.map(tech.subtechniques, fn sub ->
          %{id: sub, count: detection_counts[sub] || 0}
        end)

        %{
          id: tech.id,
          name: tech.name,
          detected: count > 0,
          detection_count: count,
          subtechniques: subtechnique_counts,
          severity: if(count > 10, do: "high", else: if(count > 0, do: "medium", else: nil))
        }
      end)

      covered = Enum.count(technique_details, & &1.detected)
      total = length(technique_details)

      %{
        tactic: tactic,
        techniques: technique_details,
        covered_count: covered,
        total_count: total,
        coverage_percent: if(total > 0, do: round(covered / total * 100), else: 0)
      }
    end)

    json(conn, %{data: by_tactic})
  end

  @doc "GET /api/v1/mitre/technique/:id - Get detailed stats for a technique"
  def technique_detail(conn, %{"id" => technique_id}) do
    org_id = get_org_id(conn)
    detection_counts = get_detection_counts(org_id)
    count = detection_counts[technique_id] || 0

    # Get recent detections for this technique (org-scoped)
    recent = get_recent_detections(org_id, technique_id)

    # Get trend data (org-scoped)
    trend = get_technique_trend(org_id, technique_id)

    # Find technique info
    technique_info = find_technique_info(technique_id)

    json(conn, %{
      data: %{
        id: technique_id,
        name: technique_info[:name],
        tactics: technique_info[:tactics] || [],
        total_detections: count,
        recent_detections: recent,
        trend: trend,
        severity_breakdown: get_severity_breakdown(org_id, technique_id)
      }
    })
  end

  @doc "GET /api/v1/mitre/heatmap - Get heatmap data for visualization"
  def heatmap(conn, params) do
    org_id = get_org_id(conn)
    time_range = params["time_range"] || "30d"
    detection_counts = get_detection_counts(org_id, time_range)

    heatmap_data = Enum.flat_map(@tactics, fn tactic ->
      techniques = @techniques_by_tactic[tactic.id] || []
      Enum.map(techniques, fn tech ->
        count = detection_counts[tech.id] || 0
        %{
          tactic_id: tactic.id,
          tactic_name: tactic.name,
          technique_id: tech.id,
          technique_name: tech.name,
          count: count,
          intensity: calculate_intensity(count)
        }
      end)
    end)

    json(conn, %{data: heatmap_data})
  end

  @doc "GET /api/v1/mitre/trends - Get detection trends over time"
  def trends(conn, params) do
    org_id = get_org_id(conn)
    time_range = params["time_range"] || "30d"
    granularity = params["granularity"] || "day"

    trends = get_detection_trends(org_id, time_range, granularity)

    json(conn, %{data: trends})
  end

  @doc "GET /api/v1/mitre/gaps - Get coverage gaps (uncovered techniques)"
  def gaps(conn, _params) do
    org_id = get_org_id(conn)

    # Use the MitreCoverage GenServer for rule-based gaps.
    # A gap means no detection rule is mapped to the technique at all -
    # even if alerts happened to fire for it via generic rules.
    try do
      real_gaps = MitreCoverage.get_gaps()

      enriched_gaps =
        real_gaps
        |> Enum.map(fn gap ->
          Map.put(gap, :priority, get_gap_priority(gap.technique_id))
        end)
        |> Enum.sort_by(& &1.priority, :desc)

      json(conn, %{data: enriched_gaps, total_gaps: length(enriched_gaps)})
    catch
      _kind, _reason ->
        # Fallback to alert-based gaps (org-scoped)
        detection_counts = get_detection_counts(org_id)

        gaps = Enum.flat_map(@tactics, fn tactic ->
          techniques = @techniques_by_tactic[tactic.id] || []
          Enum.filter(techniques, fn tech ->
            count = detection_counts[tech.id] || 0
            count == 0
          end)
          |> Enum.map(fn tech ->
            %{
              tactic: tactic,
              technique_id: tech.id,
              technique_name: tech.name,
              priority: get_gap_priority(tech.id)
            }
          end)
        end)

        sorted_gaps = Enum.sort_by(gaps, & &1.priority, :desc)
        json(conn, %{data: sorted_gaps})
    end
  end

  @doc "GET /api/v1/mitre/navigator - Export ATT&CK Navigator layer"
  def navigator(conn, _params) do
    org_id = get_org_id(conn)
    detection_counts = get_detection_counts(org_id)

    techniques = Enum.flat_map(@techniques_by_tactic, fn {_tactic_id, techs} ->
      Enum.map(techs, fn tech ->
        count = detection_counts[tech.id] || 0
        %{
          "techniqueID" => tech.id,
          "score" => min(100, count),
          "color" => if(count > 0, do: score_to_color(count), else: ""),
          "comment" => "#{count} detections",
          "enabled" => true
        }
      end)
    end)

    layer = %{
      "name" => "Tamandua EDR Coverage",
      "version" => "4.5",
      "domain" => "enterprise-attack",
      "description" => "Detection coverage from Tamandua EDR",
      "techniques" => techniques,
      "gradient" => %{
        "colors" => ["#ff6666", "#ffff66", "#66ff66"],
        "minValue" => 0,
        "maxValue" => 100
      }
    }

    conn
    |> put_resp_content_type("application/json")
    |> put_resp_header("content-disposition", "attachment; filename=\"tamandua-mitre-layer.json\"")
    |> json(layer)
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp get_detection_counts(org_id, time_range \\ "all") do
    # Get MITRE technique detection counts from alerts (org-scoped for multi-tenant isolation)
    try do
      Alerts.count_by_mitre_technique_for_org(org_id, time_range)
    rescue
      _ -> %{}
    end
  end

  defp calculate_coverage(detection_counts) do
    all_techniques = Enum.flat_map(@techniques_by_tactic, fn {_tactic, techs} ->
      Enum.map(techs, & &1.id)
    end)

    total = length(all_techniques)
    covered = Enum.count(all_techniques, fn id -> (detection_counts[id] || 0) > 0 end)

    %{
      total_techniques: total,
      covered_count: covered,
      coverage_percent: if(total > 0, do: round(covered / total * 100), else: 0)
    }
  end

  defp get_recent_detections(org_id, technique_id) do
    try do
      # Multi-tenant scoped: only list alerts for this organization
      Alerts.list_by_mitre_technique_for_org(org_id, technique_id, limit: 10)
      |> Enum.map(fn alert ->
        %{
          id: alert.id,
          title: alert.title,
          severity: alert.severity,
          timestamp: alert.inserted_at,
          agent_id: alert.agent_id
        }
      end)
    rescue
      _ -> []
    end
  end

  defp get_technique_trend(org_id, technique_id) do
    # Get daily detection counts for the past 30 days (org-scoped)
    try do
      Alerts.get_technique_trend_for_org(org_id, technique_id, days: 30)
    rescue
      _ ->
        # Return sample data if not available
        Enum.map(0..29, fn days_ago ->
          date = Date.add(Date.utc_today(), -days_ago)
          %{date: Date.to_iso8601(date), count: 0}
        end)
        |> Enum.reverse()
    end
  end

  defp get_severity_breakdown(org_id, technique_id) do
    try do
      Alerts.count_by_severity_for_technique_for_org(org_id, technique_id)
    rescue
      _ -> %{critical: 0, high: 0, medium: 0, low: 0}
    end
  end

  defp find_technique_info(technique_id) do
    Enum.find_value(@techniques_by_tactic, fn {tactic_id, techs} ->
      tech = Enum.find(techs, fn t -> t.id == technique_id end)
      if tech do
        Map.put(tech, :tactics, [tactic_id])
      end
    end) || %{name: "Unknown Technique", tactics: []}
  end

  defp calculate_intensity(count) do
    cond do
      count == 0 -> 0
      count < 5 -> 1
      count < 20 -> 2
      count < 50 -> 3
      count < 100 -> 4
      true -> 5
    end
  end

  defp get_detection_trends(org_id, time_range, granularity) do
    days = case time_range do
      "7d" -> 7
      "30d" -> 30
      "90d" -> 90
      _ -> 30
    end

    try do
      Detection.get_mitre_trends_for_org(org_id, days: days, granularity: granularity)
    rescue
      _ ->
        # Return empty trend data
        Enum.map(0..(days - 1), fn days_ago ->
          date = Date.add(Date.utc_today(), -days_ago)
          %{date: Date.to_iso8601(date), detections: 0, techniques: []}
        end)
        |> Enum.reverse()
    end
  end

  defp get_gap_priority(technique_id) do
    # High-risk techniques that should be prioritized for coverage
    high_priority = [
      "T1003",  # Credential Dumping
      "T1055",  # Process Injection
      "T1059",  # Command and Scripting Interpreter
      "T1486",  # Ransomware
      "T1566",  # Phishing
      "T1547",  # Persistence via Autostart
      "T1078"   # Valid Accounts
    ]

    base_id = String.split(technique_id, ".") |> hd()
    if base_id in high_priority, do: :high, else: :medium
  end

  defp score_to_color(count) do
    cond do
      count >= 50 -> "#66ff66"  # Green - well covered
      count >= 10 -> "#ffff66"  # Yellow - some coverage
      count > 0 -> "#ffcc66"    # Orange - minimal coverage
      true -> ""                # No coverage
    end
  end
end
