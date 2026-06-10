defmodule TamanduaServerWeb.API.V1.CSPMController do
  @moduledoc """
  API Controller for Cloud Security Posture Management (CSPM).

  Provides comprehensive REST endpoints for:
  - Cloud account management (AWS, Azure, GCP)
  - Security findings lifecycle
  - Policy management (built-in and custom)
  - Compliance dashboards
  - Scan management
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Cloud.CloudAccount
  alias TamanduaServer.Cloud.Finding
  alias TamanduaServer.Cloud.PolicyEngine

  action_fallback TamanduaServerWeb.FallbackController

  # ============================================================================
  # Cloud Accounts
  # ============================================================================

  @doc """
  List all cloud accounts.

  ## Query Parameters
  - `provider` - Filter by provider: "aws", "azure", "gcp"
  - `status` - Filter by status: "active", "inactive", "error"
  """
  def list_accounts(conn, params) do
    filters = %{
      provider: params["provider"],
      status: params["status"],
      organization_id: conn.assigns[:organization_id]
    }

    accounts = CloudAccount.list(filters)

    json(conn, %{
      data: Enum.map(accounts, &serialize_account/1),
      meta: %{
        count: length(accounts)
      }
    })
  end

  @doc """
  Get a single cloud account.
  """
  def show_account(conn, %{"id" => id}) do
    case CloudAccount.get(id) do
      nil ->
        {:error, :not_found}

      account ->
        json(conn, %{data: serialize_account(account)})
    end
  end

  @doc """
  Create a new cloud account.

  ## Request Body
  - `name` - Display name for the account
  - `provider` - "aws", "azure", or "gcp"
  - `account_id` - Provider-specific account identifier
  - `credentials` - Provider-specific credentials
  - `regions` - List of regions to scan
  """
  def create_account(conn, params) do
    attrs = %{
      name: params["name"],
      provider: params["provider"],
      account_id: params["account_id"],
      external_id: params["external_id"],
      alias: params["alias"],
      description: params["description"],
      credentials: params["credentials"] || %{},
      regions: params["regions"] || [],
      scan_enabled: Map.get(params, "scan_enabled", true),
      scan_schedule: params["scan_schedule"] || "0 */4 * * *",
      organization_id: conn.assigns[:organization_id],
      created_by: get_current_user(conn)
    }

    case CloudAccount.create(attrs) do
      {:ok, account} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize_account(account), message: "Cloud account created successfully"})

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Update a cloud account.
  """
  def update_account(conn, %{"id" => id} = params) do
    case CloudAccount.get(id) do
      nil ->
        {:error, :not_found}

      account ->
        attrs =
          params
          |> Map.take(["name", "alias", "description", "credentials", "regions",
                       "scan_enabled", "scan_schedule", "status"])
          |> atomize_keys()

        case CloudAccount.update(account, attrs) do
          {:ok, updated} ->
            json(conn, %{data: serialize_account(updated)})

          {:error, changeset} ->
            {:error, changeset}
        end
    end
  end

  @doc """
  Delete a cloud account.
  """
  def delete_account(conn, %{"id" => id}) do
    case CloudAccount.delete(id) do
      {:ok, _} ->
        json(conn, %{message: "Cloud account deleted successfully"})

      {:error, :not_found} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Test cloud account connectivity.
  """
  def test_connection(conn, %{"id" => id}) do
    case CloudAccount.get(id) do
      nil ->
        {:error, :not_found}

      account ->
        case CloudAccount.test_connection(account) do
          {:ok, result} ->
            json(conn, %{
              data: %{
                status: result.status,
                identity: result[:identity] || result[:info]
              },
              message: "Connection successful"
            })

          {:error, reason} ->
            conn
            |> put_status(:bad_request)
            |> json(%{
              error: "Connection failed",
              details: reason
            })
        end
    end
  end

  @doc """
  Start a security scan for a cloud account.
  """
  def start_scan(conn, %{"id" => id}) do
    case CloudAccount.get(id) do
      nil ->
        {:error, :not_found}

      account ->
        # Run scan asynchronously
        Task.start(fn -> CloudAccount.start_scan(account) end)

        json(conn, %{
          message: "Scan started",
          data: %{
            account_id: account.id,
            provider: account.provider,
            started_at: DateTime.utc_now()
          }
        })
    end
  end

  @doc """
  Get account statistics.
  """
  def account_stats(conn, %{"id" => id}) do
    case CloudAccount.get(id) do
      nil ->
        {:error, :not_found}

      account ->
        stats = Finding.statistics(account.provider, account.account_id)

        json(conn, %{
          data: %{
            account_id: account.id,
            provider: account.provider,
            resources_count: account.resources_count,
            findings: stats,
            last_scan_at: account.last_scan_at,
            compliance_score: account.compliance_score
          }
        })
    end
  end

  # ============================================================================
  # Findings
  # ============================================================================

  @doc """
  List security findings.

  ## Query Parameters
  - `provider` - Filter by provider
  - `account_id` - Filter by cloud account ID
  - `status` - Filter by status: "open", "acknowledged", "resolved", "exception"
  - `severity` - Filter by severity: "critical", "high", "medium", "low"
  - `category` - Filter by category
  - `resource_type` - Filter by resource type
  - `compliance` - Filter by compliance framework (e.g., "CIS")
  - `search` - Search in title, description, resource name
  - `limit` - Maximum results (default: 100)
  - `offset` - Pagination offset
  """
  def list_findings(conn, params) do
    filters = %{
      provider: params["provider"],
      account_id: params["account_id"],
      status: parse_list(params["status"]),
      severity: parse_list(params["severity"]),
      category: params["category"],
      resource_type: params["resource_type"],
      compliance: params["compliance"],
      search: params["search"],
      region: params["region"],
      organization_id: conn.assigns[:organization_id],
      limit: parse_int(params["limit"], 100),
      offset: parse_int(params["offset"], 0),
      order_by: params["order_by"] || "severity",
      order_dir: params["order_dir"] || "asc"
    }

    findings = Finding.list_findings(filters)
    total = Finding.count_findings(Map.drop(filters, [:limit, :offset]))

    json(conn, %{
      data: findings,
      meta: %{
        count: length(findings),
        total: total,
        limit: filters.limit,
        offset: filters.offset
      }
    })
  end

  @doc """
  Get a single finding.
  """
  def show_finding(conn, %{"id" => id}) do
    case Finding.get_finding(id) do
      nil ->
        {:error, :not_found}

      finding ->
        json(conn, %{data: finding})
    end
  end

  @doc """
  Update finding status.

  ## Request Body
  - `status` - New status: "acknowledged", "resolved", "exception", "false_positive", "open"
  - `reason` - Reason for status change
  - `exception_expiry` - Expiry date for exceptions (ISO8601)
  - `exception_justification` - Justification for exception
  """
  def update_finding_status(conn, %{"id" => id} = params) do
    opts = %{
      updated_by: get_current_user(conn),
      reason: params["reason"],
      exception_expiry: parse_datetime(params["exception_expiry"]),
      exception_justification: params["exception_justification"]
    }

    case Finding.update_status(id, params["status"], opts) do
      {:ok, finding} ->
        json(conn, %{data: finding})

      {:error, :not_found} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Bulk update finding status.
  """
  def bulk_update_findings(conn, params) do
    finding_ids = params["finding_ids"] || []
    status = params["status"]
    opts = %{
      updated_by: get_current_user(conn),
      reason: params["reason"]
    }

    case Finding.bulk_update_status(finding_ids, status, opts) do
      {:ok, count} ->
        json(conn, %{
          message: "Updated #{count} findings",
          data: %{updated_count: count}
        })

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Get finding statistics.
  """
  def finding_stats(conn, params) do
    filters = %{
      provider: params["provider"],
      account_id: params["account_id"],
      organization_id: conn.assigns[:organization_id]
    }

    stats =
      if filters.provider && filters.account_id do
        Finding.statistics(filters.provider, filters.account_id)
      else
        Finding.global_statistics()
      end

    json(conn, %{data: stats})
  end

  # ============================================================================
  # Policies
  # ============================================================================

  @doc """
  List all security policies.

  ## Query Parameters
  - `provider` - Filter by provider
  - `severity` - Filter by severity
  - `category` - Filter by category
  - `compliance` - Filter by compliance framework
  - `enabled` - Filter by enabled status
  """
  def list_policies(conn, params) do
    filters = %{
      provider: params["provider"],
      severity: params["severity"],
      category: params["category"],
      compliance: params["compliance"],
      enabled: parse_bool(params["enabled"])
    }

    policies = PolicyEngine.list_policies(filters)

    json(conn, %{
      data: policies,
      meta: %{
        count: length(policies)
      }
    })
  end

  @doc """
  Get a single policy.
  """
  def show_policy(conn, %{"id" => id}) do
    case PolicyEngine.get_policy(id) do
      {:ok, policy} ->
        json(conn, %{data: policy})

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  @doc """
  Create a custom policy.
  """
  def create_policy(conn, params) do
    case PolicyEngine.add_custom_policy(params) do
      {:ok, policy} ->
        conn
        |> put_status(:created)
        |> json(%{data: policy, message: "Custom policy created"})

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: reason})
    end
  end

  @doc """
  Update a custom policy.
  """
  def update_policy(conn, %{"id" => id} = params) do
    case PolicyEngine.update_custom_policy(id, params) do
      {:ok, policy} ->
        json(conn, %{data: policy})

      {:error, :not_found} ->
        {:error, :not_found}

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: reason})
    end
  end

  @doc """
  Delete a custom policy.
  """
  def delete_policy(conn, %{"id" => id}) do
    case PolicyEngine.delete_custom_policy(id) do
      :ok ->
        json(conn, %{message: "Policy deleted successfully"})

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  @doc """
  Get policy statistics.
  """
  def policy_stats(conn, _params) do
    stats = PolicyEngine.statistics()
    json(conn, %{data: stats})
  end

  # ============================================================================
  # Compliance
  # ============================================================================

  @doc """
  Get compliance overview across all accounts.
  """
  def compliance_overview(conn, params) do
    accounts = CloudAccount.list(%{organization_id: conn.assigns[:organization_id]})

    compliance_data =
      Enum.map(accounts, fn account ->
        %{
          account_id: account.id,
          provider: account.provider,
          name: account.name,
          compliance_score: account.compliance_score,
          findings_count: account.findings_count,
          critical_findings: account.critical_findings_count,
          last_scan_at: account.last_scan_at
        }
      end)

    # Calculate overall compliance by framework
    frameworks = ["CIS", "PCI DSS", "HIPAA", "NIST", "SOC 2"]

    framework_scores =
      Enum.map(frameworks, fn framework ->
        policies = PolicyEngine.policies_by_compliance(framework)

        %{
          framework: framework,
          total_policies: length(policies),
          providers: %{
            aws: count_provider_policies(policies, "aws"),
            azure: count_provider_policies(policies, "azure"),
            gcp: count_provider_policies(policies, "gcp")
          }
        }
      end)

    json(conn, %{
      data: %{
        accounts: compliance_data,
        frameworks: framework_scores,
        summary: %{
          total_accounts: length(accounts),
          average_compliance_score: calculate_average(compliance_data, :compliance_score),
          total_findings: Enum.sum(Enum.map(compliance_data, & &1.findings_count)),
          critical_findings: Enum.sum(Enum.map(compliance_data, & &1.critical_findings))
        }
      }
    })
  end

  @doc """
  Get compliance posture for a specific framework.
  """
  def compliance_framework(conn, %{"framework" => framework} = params) do
    provider = params["provider"]
    account_id = params["account_id"]

    policies = PolicyEngine.policies_by_compliance(framework)
    policies = if provider, do: Enum.filter(policies, & &1.provider == provider), else: policies

    # Get findings for these policies
    findings =
      if account_id do
        Finding.list_findings(%{
          account_id: account_id,
          compliance: framework,
          status: "open"
        })
      else
        Finding.list_findings(%{
          compliance: framework,
          status: "open",
          organization_id: conn.assigns[:organization_id]
        })
      end

    # Group findings by policy
    findings_by_policy = Enum.group_by(findings, & &1.title)

    controls =
      Enum.map(policies, fn policy ->
        policy_findings = Map.get(findings_by_policy, policy.name, [])

        %{
          policy_id: policy.id,
          name: policy.name,
          description: policy.description,
          severity: policy.severity,
          category: policy.category,
          resource_type: policy.resource_type,
          status: if(length(policy_findings) == 0, do: "passed", else: "failed"),
          findings_count: length(policy_findings),
          compliance_tags: policy.compliance
        }
      end)

    passed = Enum.count(controls, & &1.status == "passed")
    failed = Enum.count(controls, & &1.status == "failed")
    total = passed + failed
    score = if total > 0, do: Float.round(passed / total * 100, 1), else: 100.0

    json(conn, %{
      data: %{
        framework: framework,
        provider: provider,
        account_id: account_id,
        score: score,
        passed_controls: passed,
        failed_controls: failed,
        total_controls: total,
        controls: controls
      }
    })
  end

  # ============================================================================
  # Dashboard
  # ============================================================================

  @doc """
  Get CSPM dashboard data.
  """
  def dashboard(conn, _params) do
    accounts = CloudAccount.list(%{organization_id: conn.assigns[:organization_id]})
    global_stats = Finding.global_statistics()
    policy_stats = PolicyEngine.statistics()

    # Recent critical findings
    recent_critical = Finding.list_findings(%{
      severity: ["critical", "high"],
      status: "open",
      limit: 10,
      order_by: "last_seen_at",
      order_dir: "desc"
    })

    # Resources by type
    resources_by_provider =
      Enum.map(accounts, fn a ->
        %{provider: a.provider, count: a.resources_count || 0}
      end)
      |> Enum.group_by(& &1.provider)
      |> Enum.map(fn {provider, items} ->
        {provider, Enum.sum(Enum.map(items, & &1.count))}
      end)
      |> Enum.into(%{})

    json(conn, %{
      data: %{
        summary: %{
          total_accounts: length(accounts),
          connected_accounts: Enum.count(accounts, & &1.connection_status == "connected"),
          total_resources: Enum.sum(Enum.map(accounts, fn a -> a.resources_count || 0 end)),
          total_findings: global_stats.total_findings,
          open_findings: global_stats.open_findings,
          critical_findings: global_stats.critical_findings,
          high_findings: global_stats.high_findings,
          average_compliance_score: CloudAccount.global_statistics().average_compliance_score
        },
        by_provider: %{
          aws: %{
            accounts: Enum.count(accounts, & &1.provider == "aws"),
            findings: global_stats.by_provider.aws,
            resources: Map.get(resources_by_provider, "aws", 0)
          },
          azure: %{
            accounts: Enum.count(accounts, & &1.provider == "azure"),
            findings: global_stats.by_provider.azure,
            resources: Map.get(resources_by_provider, "azure", 0)
          },
          gcp: %{
            accounts: Enum.count(accounts, & &1.provider == "gcp"),
            findings: global_stats.by_provider.gcp,
            resources: Map.get(resources_by_provider, "gcp", 0)
          }
        },
        policies: policy_stats,
        recent_critical_findings: recent_critical,
        accounts: Enum.map(accounts, &serialize_account_summary/1)
      }
    })
  end

  # ============================================================================
  # Topology & Visualization
  # ============================================================================

  @doc """
  Get cloud resource topology for visualization.
  Returns nodes (resources) and relationships (connections).
  """
  def topology(conn, params) do
    provider = params["provider"]
    account_id = params["account_id"]
    filters = %{organization_id: conn.assigns[:organization_id]}
    findings =
      Finding.list_findings(%{
        status: "open",
        organization_id: conn.assigns[:organization_id],
        limit: 10000
      })

    accounts =
      CloudAccount.list(filters)
      |> maybe_filter_provider(provider)
      |> maybe_filter_account_id(account_id)

    nodes =
      Enum.flat_map(accounts, fn account ->
        account_findings =
          Enum.filter(findings, &(&1.provider == account.provider and &1.account_id == account.account_id))

        build_topology_nodes(account, account_findings)
      end)

    relationships =
      Enum.flat_map(nodes, fn node ->
        build_node_relationships(node, nodes)
      end)

    json(conn, %{
      data: %{
        nodes: nodes,
        relationships: relationships,
        status: if(Enum.empty?(nodes), do: "insufficient_data", else: "ok"),
        source: "cloud_findings",
        summary: %{
          total_nodes: length(nodes),
          by_type: count_by_type(nodes),
          by_provider: count_by_provider(nodes),
          by_status: count_by_status(nodes)
        }
      }
    })
  end

  @doc """
  Get risk heat map data by region and resource type.
  """
  def risk_heatmap(conn, params) do
    provider = params["provider"]
    accounts = CloudAccount.list(%{organization_id: conn.assigns[:organization_id]})
    findings = Finding.list_findings(%{status: "open", organization_id: conn.assigns[:organization_id], limit: 10000})

    # Group findings by region and resource type
    grouped =
      findings
      |> maybe_filter_findings_provider(provider)
      |> Enum.group_by(fn f -> {f.provider, f.region || "global", f.resource_type} end)

    heat_map =
      Enum.map(grouped, fn {{prov, region, resource_type}, region_findings} ->
        critical_count = Enum.count(region_findings, & &1.severity == "critical")
        high_count = Enum.count(region_findings, & &1.severity == "high")
        medium_count = Enum.count(region_findings, & &1.severity == "medium")

        risk_score = min(100, critical_count * 20 + high_count * 10 + medium_count * 3)

        %{
          provider: prov,
          region: region,
          resource_type: resource_type,
          risk_score: risk_score,
          findings_count: length(region_findings),
          critical_count: critical_count,
          high_count: high_count,
          medium_count: medium_count
        }
      end)

    json(conn, %{data: heat_map})
  end

  @doc """
  List cloud assets with security status.
  """
  def list_assets(conn, params) do
    provider = params["provider"]
    resource_type = params["type"]
    region = params["region"]

    accounts = CloudAccount.list(%{organization_id: conn.assigns[:organization_id]})
    findings = Finding.list_findings(%{status: "open", organization_id: conn.assigns[:organization_id], limit: 10000})

    # Group findings by resource
    findings_by_resource = Enum.group_by(findings, & &1.resource_id)

    # Build asset list from account data and findings
    assets =
      Enum.flat_map(accounts, fn account ->
        build_account_assets(account, findings_by_resource)
      end)
      |> maybe_filter_assets_provider(provider)
      |> maybe_filter_assets_type(resource_type)
      |> maybe_filter_assets_region(region)

    json(conn, %{
      data: assets,
      meta: %{
        count: length(assets),
        by_type: count_assets_by_type(assets),
        by_provider: count_assets_by_provider(assets)
      }
    })
  end

  @doc """
  Get a single asset with findings.
  """
  def show_asset(conn, %{"id" => id}) do
    findings = Finding.list_findings(%{resource_id: id, organization_id: conn.assigns[:organization_id]})

    if length(findings) > 0 do
      sample = hd(findings)
      asset = %{
        id: id,
        name: sample.resource_name,
        type: sample.resource_type,
        provider: sample.provider,
        region: sample.region,
        account_id: sample.account_id,
        findings: findings,
        findings_count: length(findings),
        critical_count: Enum.count(findings, & &1.severity == "critical"),
        high_count: Enum.count(findings, & &1.severity == "high")
      }
      json(conn, %{data: asset})
    else
      {:error, :not_found}
    end
  end

  # ============================================================================
  # Security Groups
  # ============================================================================

  @doc """
  List security groups with analysis.
  """
  def list_security_groups(conn, params) do
    provider = params["provider"]

    # Get findings related to security groups/NSGs/firewall rules
    findings = Finding.list_findings(%{
      category: "network_security",
      status: "open",
      organization_id: conn.assigns[:organization_id],
      limit: 1000
    })
    |> maybe_filter_findings_provider(provider)

    # Group findings by security group
    grouped = Enum.group_by(findings, & &1.resource_id)

    security_groups =
      Enum.map(grouped, fn {sg_id, sg_findings} ->
        sample = hd(sg_findings)

        # Analyze inbound rules from finding details
        inbound_issues = extract_inbound_issues(sg_findings)

        risk_level = cond do
          Enum.any?(sg_findings, & &1.severity == "critical") -> "critical"
          Enum.any?(sg_findings, & &1.severity == "high") -> "high"
          Enum.any?(sg_findings, & &1.severity == "medium") -> "medium"
          true -> "low"
        end

        %{
          id: sg_id,
          name: sample.resource_name,
          provider: sample.provider,
          vpc_id: get_in(sample, [:metadata, "vpc_id"]) || get_in(sample, [:metadata, "vnet_id"]),
          region: sample.region,
          inbound_rules: inbound_issues.rules,
          outbound_rules: [],
          attached_resources: get_in(sample, [:metadata, "attached_resources"]) || 0,
          risk_level: risk_level,
          issues: Enum.map(sg_findings, & &1.title),
          findings_count: length(sg_findings)
        }
      end)

    json(conn, %{
      data: security_groups,
      meta: %{
        count: length(security_groups),
        critical: Enum.count(security_groups, & &1.risk_level == "critical"),
        high: Enum.count(security_groups, & &1.risk_level == "high")
      }
    })
  end

  @doc """
  Get a single security group with detailed analysis.
  """
  def show_security_group(conn, %{"id" => id}) do
    findings = Finding.list_findings(%{
      resource_id: id,
      category: "network_security",
      organization_id: conn.assigns[:organization_id]
    })

    if length(findings) > 0 do
      sample = hd(findings)

      security_group = %{
        id: id,
        name: sample.resource_name,
        provider: sample.provider,
        findings: findings,
        risk_level: determine_risk_level(findings)
      }

      json(conn, %{data: security_group})
    else
      {:error, :not_found}
    end
  end

  @doc """
  Analyze a security group for risks.
  """
  def analyze_security_group(conn, %{"id" => id}) do
    findings = Finding.list_findings(%{
      resource_id: id,
      organization_id: conn.assigns[:organization_id]
    })

    analysis = %{
      id: id,
      findings_count: length(findings),
      risk_level: determine_risk_level(findings),
      recommendations: Enum.flat_map(findings, fn f -> [f.recommendation] end) |> Enum.uniq(),
      compliance_issues: Enum.flat_map(findings, fn f -> f.compliance end) |> Enum.uniq()
    }

    json(conn, %{data: analysis})
  end

  # ============================================================================
  # Identity Security
  # ============================================================================

  @doc """
  List cloud identities with risk assessment.
  """
  def list_identities(conn, params) do
    provider = params["provider"]

    # Get IAM-related findings
    findings = Finding.list_findings(%{
      category: "identity_access",
      status: "open",
      organization_id: conn.assigns[:organization_id],
      limit: 1000
    })
    |> maybe_filter_findings_provider(provider)

    # Group by identity
    grouped = Enum.group_by(findings, & &1.resource_id)

    identities =
      Enum.map(grouped, fn {identity_id, identity_findings} ->
        sample = hd(identity_findings)

        risk_score = calculate_identity_risk_score(identity_findings)

        %{
          id: identity_id,
          name: sample.resource_name,
          type: sample.resource_type,
          provider: sample.provider,
          account_id: sample.account_id,
          risk_score: risk_score,
          risk_level: risk_level_from_score(risk_score),
          findings: identity_findings,
          findings_count: length(identity_findings),
          has_admin_access: Enum.any?(identity_findings, fn f ->
            String.contains?(String.downcase(f.title), "admin") or
            String.contains?(String.downcase(f.title), "privilege")
          end),
          last_activity: get_in(sample, [:metadata, "last_activity"]),
          permissions_count: get_in(sample, [:metadata, "permissions_count"])
        }
      end)

    json(conn, %{
      data: identities,
      meta: %{
        count: length(identities),
        high_risk: Enum.count(identities, & &1.risk_level == "high"),
        with_admin: Enum.count(identities, & &1.has_admin_access)
      }
    })
  end

  @doc """
  Get a single identity with detailed analysis.
  """
  def show_identity(conn, %{"id" => id}) do
    findings = Finding.list_findings(%{
      resource_id: id,
      category: "identity_access",
      organization_id: conn.assigns[:organization_id]
    })

    if length(findings) > 0 do
      sample = hd(findings)

      identity = %{
        id: id,
        name: sample.resource_name,
        type: sample.resource_type,
        provider: sample.provider,
        findings: findings,
        risk_score: calculate_identity_risk_score(findings)
      }

      json(conn, %{data: identity})
    else
      {:error, :not_found}
    end
  end

  @doc """
  Get privilege escalation paths for an identity.
  """
  def identity_escalation_paths(conn, %{"id" => id}) do
    findings = Finding.list_findings(%{
      resource_id: id,
      category: "identity_access",
      organization_id: conn.assigns[:organization_id]
    })

    escalation_findings = Enum.filter(findings, fn f ->
      String.contains?(String.downcase(f.title), "escalation") or
      String.contains?(String.downcase(f.description || ""), "escalation")
    end)

    paths = Enum.map(escalation_findings, fn f ->
      %{
        finding_id: f.id,
        title: f.title,
        description: f.description,
        severity: f.severity,
        steps: get_in(f, [:metadata, "escalation_steps"]) || []
      }
    end)

    json(conn, %{
      data: %{
        identity_id: id,
        escalation_paths: paths,
        paths_count: length(paths),
        highest_severity: determine_risk_level(escalation_findings)
      }
    })
  end

  # ============================================================================
  # Runtime Protection
  # ============================================================================

  @doc """
  Get runtime security events.
  """
  def runtime_events(conn, params) do
    limit = parse_int(params["limit"], 100)
    offset = parse_int(params["offset"], 0)

    # Get runtime-related findings
    findings = Finding.list_findings(%{
      category: "runtime_security",
      organization_id: conn.assigns[:organization_id],
      limit: limit,
      offset: offset,
      order_by: "last_seen_at",
      order_dir: "desc"
    })

    events = Enum.map(findings, fn f ->
      %{
        id: f.id,
        type: get_in(f, [:metadata, "event_type"]) || "unknown",
        resource_id: f.resource_id,
        resource_name: f.resource_name,
        resource_type: f.resource_type,
        provider: f.provider,
        severity: f.severity,
        title: f.title,
        description: f.description,
        detected_at: f.first_seen_at,
        last_seen_at: f.last_seen_at,
        mitre_techniques: f.mitre_techniques || []
      }
    end)

    json(conn, %{
      data: events,
      meta: %{
        count: length(events),
        limit: limit,
        offset: offset
      }
    })
  end

  @doc """
  Get monitored workloads.
  """
  def runtime_workloads(conn, params) do
    provider = params["provider"]

    accounts =
      CloudAccount.list(%{organization_id: conn.assigns[:organization_id]})
      |> maybe_filter_provider(provider)

    findings =
      Finding.list_findings(%{
        category: "runtime_security",
        organization_id: conn.assigns[:organization_id],
        limit: 10000
      })

    workloads =
      Enum.flat_map(accounts, fn account ->
        account_findings =
          Enum.filter(findings, &(&1.provider == account.provider and &1.account_id == account.account_id))

        build_workloads(account, account_findings)
      end)

    json(conn, %{
      data: workloads,
      meta: %{
        count: length(workloads),
        by_type: count_by_type(workloads),
        status: if(Enum.empty?(workloads), do: "insufficient_data", else: "ok"),
        source: "runtime_security_findings"
      }
    })
  end

  @doc """
  Get admission control policies.
  """
  def admission_policies(conn, _params) do
    # Return configured admission policies
    policies = [
      %{
        id: "deny-privileged",
        name: "Deny Privileged Containers",
        enabled: true,
        action: "deny",
        scope: "all",
        rule: %{
          type: "container",
          condition: "privileged == true"
        }
      },
      %{
        id: "deny-host-network",
        name: "Deny Host Network",
        enabled: true,
        action: "deny",
        scope: "all",
        rule: %{
          type: "container",
          condition: "host_network == true"
        }
      },
      %{
        id: "require-resource-limits",
        name: "Require Resource Limits",
        enabled: true,
        action: "warn",
        scope: "production",
        rule: %{
          type: "pod",
          condition: "missing resource limits"
        }
      }
    ]

    json(conn, %{data: policies})
  end

  # ============================================================================
  # IaC Security
  # ============================================================================

  @doc """
  Scan Infrastructure as Code content.
  """
  def scan_iac(conn, params) do
    content = params["content"]
    file_type = params["type"] || detect_iac_type(content)

    case TamanduaServer.Cloud.IacSecurity.scan(content, file_type) do
      {:ok, results} ->
        json(conn, %{
          data: %{
            file_type: file_type,
            findings: results.findings,
            findings_count: length(results.findings),
            critical_count: Enum.count(results.findings, & &1.severity == "critical"),
            high_count: Enum.count(results.findings, & &1.severity == "high"),
            passed_checks: results.passed_checks || 0
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Failed to scan IaC", details: reason})
    end
  end

  # ============================================================================
  # Remediation
  # ============================================================================

  @doc """
  Apply remediation for a finding.
  """
  def remediate_finding(conn, %{"id" => id} = params) do
    remediation_type = params["type"] || "auto"

    case Finding.get_finding(id) do
      nil ->
        {:error, :not_found}

      finding ->
        # Log remediation action
        user = get_current_user(conn)

        case remediation_type do
          "auto" ->
            conn
            |> put_status(:not_implemented)
            |> json(%{
              error: "auto_remediation_unavailable",
              message: "Auto-remediation is unavailable because no real cloud provider remediation executor is configured",
              data: %{
                finding_id: finding.id,
                type: "auto",
                status: "unavailable",
                requested_by: user
              }
            })

          "manual" ->
            json(conn, %{
              data: %{
                finding_id: id,
                terraform_code: finding.remediation_terraform,
                cloudformation_code: finding.remediation_cloudformation,
                arm_code: finding.remediation_arm,
                cli_command: get_in(finding, [:metadata, "cli_command"])
              }
            })
        end
    end
  end

  @doc """
  Export findings in various formats.
  """
  def export_findings(conn, params) do
    format = params["format"] || "json"

    filters = %{
      provider: params["provider"],
      severity: parse_list(params["severity"]),
      status: parse_list(params["status"]),
      organization_id: conn.assigns[:organization_id],
      limit: 10000
    }

    findings = Finding.list_findings(filters)

    case format do
      "csv" ->
        csv_content = export_findings_csv(findings)

        conn
        |> put_resp_content_type("text/csv")
        |> put_resp_header("content-disposition", "attachment; filename=cloud-findings.csv")
        |> send_resp(200, csv_content)

      "json" ->
        json(conn, %{data: findings})

      _ ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Unsupported format: #{format}"})
    end
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  defp serialize_account(account) do
    %{
      id: account.id,
      name: account.name,
      provider: account.provider,
      account_id: account.account_id,
      alias: account.alias,
      description: account.description,
      status: account.status,
      connection_status: account.connection_status,
      regions: account.regions,
      scan_enabled: account.scan_enabled,
      scan_schedule: account.scan_schedule,
      last_scan_at: account.last_scan_at,
      last_scan_status: account.last_scan_status,
      resources_count: account.resources_count,
      findings_count: account.findings_count,
      critical_findings_count: account.critical_findings_count,
      compliance_score: account.compliance_score,
      created_at: account.inserted_at,
      updated_at: account.updated_at
    }
  end

  defp serialize_account_summary(account) do
    %{
      id: account.id,
      name: account.name,
      provider: account.provider,
      account_id: account.account_id,
      status: account.status,
      connection_status: account.connection_status,
      compliance_score: account.compliance_score,
      findings_count: account.findings_count,
      critical_findings_count: account.critical_findings_count,
      last_scan_at: account.last_scan_at
    }
  end

  defp get_current_user(conn) do
    case conn.assigns[:current_user] do
      %{email: email} -> email
      %{id: id} -> id
      _ -> "system"
    end
  end

  defp parse_int(nil, default), do: default
  defp parse_int(value, _default) when is_integer(value), do: value
  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_bool(nil), do: nil
  defp parse_bool("true"), do: true
  defp parse_bool("false"), do: false
  defp parse_bool(value) when is_boolean(value), do: value
  defp parse_bool(_), do: nil

  defp parse_list(nil), do: nil
  defp parse_list(value) when is_list(value), do: value
  defp parse_list(value) when is_binary(value), do: String.split(value, ",")

  defp parse_datetime(nil), do: nil
  defp parse_datetime(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end

  defp atomize_keys(map) when is_map(map) do
    Enum.reduce(map, %{}, fn
      {key, value}, acc when is_binary(key) ->
        Map.put(acc, String.to_existing_atom(key), value)

      {key, value}, acc ->
        Map.put(acc, key, value)
    end)
  rescue
    ArgumentError -> map
  end

  defp count_provider_policies(policies, provider) do
    Enum.count(policies, fn p -> p.provider == provider or p.provider == "all" end)
  end

  defp calculate_average(items, key) do
    values = Enum.map(items, & Map.get(&1, key)) |> Enum.filter(& &1)

    if length(values) > 0 do
      Float.round(Enum.sum(values) / length(values), 1)
    else
      0.0
    end
  end

  # Topology helpers
  defp maybe_filter_provider(accounts, nil), do: accounts
  defp maybe_filter_provider(accounts, "all"), do: accounts
  defp maybe_filter_provider(accounts, provider), do: Enum.filter(accounts, & &1.provider == provider)

  defp maybe_filter_account_id(accounts, nil), do: accounts
  defp maybe_filter_account_id(accounts, ""), do: accounts
  defp maybe_filter_account_id(accounts, account_id) do
    Enum.filter(accounts, &(&1.account_id == account_id or &1.id == account_id))
  end

  defp maybe_filter_findings_provider(findings, nil), do: findings
  defp maybe_filter_findings_provider(findings, "all"), do: findings
  defp maybe_filter_findings_provider(findings, provider), do: Enum.filter(findings, & &1.provider == provider)

  defp build_topology_nodes(_account, findings) do
    findings
    |> Enum.group_by(& &1.resource_id)
    |> Enum.map(fn {resource_id, resource_findings} ->
      sample = hd(resource_findings)

      %{
        id: resource_id,
        name: sample.resource_name,
        type: sample.resource_type,
        provider: sample.provider,
        region: sample.region,
        security_status: determine_security_status(resource_findings),
        findings_count: length(resource_findings),
        public_exposure: Enum.any?(resource_findings, &(&1.category == "network_security")),
        tags: %{},
        source: "cloud_findings"
      }
    end)
  end

  defp build_node_relationships(_node, _all_nodes), do: []

  defp count_by_type(items) do
    Enum.reduce(items, %{}, fn item, acc ->
      type = item.type || item[:type] || "unknown"
      Map.update(acc, type, 1, & &1 + 1)
    end)
  end

  defp count_by_provider(items) do
    Enum.reduce(items, %{}, fn item, acc ->
      provider = item.provider || item[:provider] || "unknown"
      Map.update(acc, provider, 1, & &1 + 1)
    end)
  end

  defp count_by_status(items) do
    Enum.reduce(items, %{}, fn item, acc ->
      status = item.security_status || item[:security_status] || "unknown"
      Map.update(acc, status, 1, & &1 + 1)
    end)
  end

  # Asset helpers
  defp build_account_assets(account, findings_by_resource) do
    # Build asset list from findings
    Enum.map(findings_by_resource, fn {resource_id, findings} ->
      sample = hd(findings)
      if sample.account_id == account.account_id do
        %{
          id: resource_id,
          name: sample.resource_name,
          type: sample.resource_type,
          provider: sample.provider,
          region: sample.region,
          account_id: account.id,
          findings_count: length(findings),
          critical_count: Enum.count(findings, & &1.severity == "critical"),
          high_count: Enum.count(findings, & &1.severity == "high"),
          security_status: determine_security_status(findings)
        }
      else
        nil
      end
    end)
    |> Enum.filter(& &1)
  end

  defp maybe_filter_assets_provider(assets, nil), do: assets
  defp maybe_filter_assets_provider(assets, "all"), do: assets
  defp maybe_filter_assets_provider(assets, provider), do: Enum.filter(assets, & &1.provider == provider)

  defp maybe_filter_assets_type(assets, nil), do: assets
  defp maybe_filter_assets_type(assets, "all"), do: assets
  defp maybe_filter_assets_type(assets, type), do: Enum.filter(assets, & &1.type == type)

  defp maybe_filter_assets_region(assets, nil), do: assets
  defp maybe_filter_assets_region(assets, region), do: Enum.filter(assets, & &1.region == region)

  defp count_assets_by_type(assets), do: count_by_type(assets)
  defp count_assets_by_provider(assets), do: count_by_provider(assets)

  defp determine_security_status(findings) do
    cond do
      Enum.any?(findings, & &1.severity == "critical") -> "critical"
      Enum.any?(findings, & &1.severity == "high") -> "at_risk"
      length(findings) > 0 -> "at_risk"
      true -> "secure"
    end
  end

  # Security group helpers
  defp extract_inbound_issues(findings) do
    rules = Enum.flat_map(findings, fn f ->
      port = get_in(f, [:metadata, "port"]) || "all"
      source = get_in(f, [:metadata, "source"]) || "0.0.0.0/0"

      [%{
        protocol: get_in(f, [:metadata, "protocol"]) || "tcp",
        port_range: port,
        source: source,
        description: f.title,
        is_risky: f.severity in ["critical", "high"],
        risk_reason: f.description
      }]
    end)

    %{rules: rules}
  end

  defp determine_risk_level([]), do: "low"
  defp determine_risk_level(findings) do
    cond do
      Enum.any?(findings, & &1.severity == "critical") -> "critical"
      Enum.any?(findings, & &1.severity == "high") -> "high"
      Enum.any?(findings, & &1.severity == "medium") -> "medium"
      true -> "low"
    end
  end

  # Identity helpers
  defp calculate_identity_risk_score(findings) do
    base_score = length(findings) * 10
    critical_score = Enum.count(findings, & &1.severity == "critical") * 25
    high_score = Enum.count(findings, & &1.severity == "high") * 15
    min(100, base_score + critical_score + high_score)
  end

  defp risk_level_from_score(score) when score >= 80, do: "critical"
  defp risk_level_from_score(score) when score >= 60, do: "high"
  defp risk_level_from_score(score) when score >= 40, do: "medium"
  defp risk_level_from_score(_score), do: "low"

  # Runtime helpers
  defp build_workloads(account, findings) do
    findings
    |> Enum.group_by(& &1.resource_id)
    |> Enum.map(fn {resource_id, resource_findings} ->
      sample = hd(resource_findings)

      %{
        id: resource_id,
        name: sample.resource_name,
        type: sample.resource_type,
        provider: account.provider,
        account_id: account.id,
        region: sample.region,
        status: "unknown",
        monitoring_enabled: false,
        findings_count: length(resource_findings),
        security_status: determine_security_status(resource_findings),
        source: "runtime_security_findings"
      }
    end)
  end

  # IaC helpers
  defp detect_iac_type(content) when is_binary(content) do
    cond do
      String.contains?(content, "resource \"") -> "terraform"
      String.contains?(content, "AWSTemplateFormatVersion") -> "cloudformation"
      String.contains?(content, "apiVersion:") and String.contains?(content, "kind:") -> "kubernetes"
      String.contains?(content, "$schema") and String.contains?(content, "resources") -> "arm"
      true -> "unknown"
    end
  end
  defp detect_iac_type(_), do: "unknown"

  defp export_findings_csv(findings) do
    headers = ["ID", "Title", "Severity", "Status", "Provider", "Resource", "Resource Type", "Region", "Category", "Compliance", "Created At"]

    rows = Enum.map(findings, fn f ->
      [
        f.id,
        f.title,
        f.severity,
        f.status,
        f.provider,
        f.resource_name,
        f.resource_type,
        f.region || "",
        f.category,
        Enum.join(f.compliance || [], "; "),
        DateTime.to_iso8601(f.first_seen_at || DateTime.utc_now())
      ]
    end)

    csv_rows = [headers | rows]
    |> Enum.map(fn row ->
      Enum.map(row, fn cell ->
        cell = to_string(cell || "")
        if String.contains?(cell, ",") or String.contains?(cell, "\"") do
          "\"#{String.replace(cell, "\"", "\"\"")}\""
        else
          cell
        end
      end)
      |> Enum.join(",")
    end)
    |> Enum.join("\n")

    csv_rows
  end
end
