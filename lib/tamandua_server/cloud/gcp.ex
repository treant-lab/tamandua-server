defmodule TamanduaServer.Cloud.GCP do
  @moduledoc """
  Google Cloud Platform (GCP) Cloud Security Posture Management (CSPM) integration.

  Provides comprehensive security scanning and assessment of GCP resources
  including Compute Engine, Cloud Storage, IAM, GKE, and VPC.

  ## Features
  - Service account authentication
  - IAM policy analysis
  - Firewall rule analysis
  - Storage bucket security analysis
  - Resource inventory collection
  """

  require Logger
  alias TamanduaServer.Cloud.Finding

  @type project :: %{
          project_id: String.t(),
          project_name: String.t(),
          project_number: String.t() | nil,
          service_account_key: map() | nil,
          status: :connected | :disconnected | :error,
          last_scan: DateTime.t() | nil,
          access_token: String.t() | nil,
          token_expires_at: DateTime.t() | nil
        }

  @type resource :: %{
          id: String.t(),
          self_link: String.t(),
          type: String.t(),
          name: String.t(),
          zone: String.t() | nil,
          region: String.t() | nil,
          project_id: String.t(),
          labels: map(),
          metadata: map(),
          created_at: DateTime.t() | nil
        }

  # ETS tables for GCP data
  @projects_table :gcp_projects
  @resources_table :gcp_resources

  @gcp_auth_url "https://oauth2.googleapis.com/token"
  @gcp_compute_api "https://compute.googleapis.com/compute/v1"
  @gcp_storage_api "https://storage.googleapis.com/storage/v1"
  @gcp_iam_api "https://iam.googleapis.com/v1"
  @gcp_container_api "https://container.googleapis.com/v1"

  # Common GCP zones
  @default_zones [
    "us-central1-a",
    "us-central1-b",
    "us-east1-b",
    "us-west1-a",
    "europe-west1-b",
    "europe-west2-a",
    "asia-east1-a",
    "asia-southeast1-a"
  ]

  # ============================================================================
  # Project Management
  # ============================================================================

  @doc """
  Add a new GCP project for CSPM scanning.
  """
  @spec add_project(map()) :: {:ok, project()} | {:error, term()}
  def add_project(params) do
    ensure_tables()

    project = %{
      project_id: params["project_id"] || params[:project_id],
      project_name: params["project_name"] || params[:project_name],
      project_number: params["project_number"] || params[:project_number],
      service_account_key: params["service_account_key"] || params[:service_account_key],
      status: :disconnected,
      last_scan: nil,
      access_token: nil,
      token_expires_at: nil,
      added_at: DateTime.utc_now()
    }

    # Validate required fields
    case validate_project(project) do
      :ok ->
        :ets.insert(@projects_table, {project.project_id, project})
        Logger.info("Added GCP project: #{project.project_id}")

        # Test connection
        case get_access_token(project) do
          {:ok, token, expires_at} ->
            updated = %{
              project
              | status: :connected,
                access_token: token,
                token_expires_at: expires_at
            }

            :ets.insert(@projects_table, {project.project_id, updated})
            {:ok, sanitize_project(updated)}

          {:error, reason} ->
            Logger.warning(
              "GCP project #{project.project_id} connection test failed: #{inspect(reason)}"
            )

            {:ok, sanitize_project(project)}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Remove a GCP project from CSPM scanning.
  """
  @spec remove_project(String.t()) :: :ok | {:error, :not_found}
  def remove_project(project_id) do
    ensure_tables()

    case :ets.lookup(@projects_table, project_id) do
      [{^project_id, _}] ->
        :ets.delete(@projects_table, project_id)
        # Clean up resources for this project
        :ets.match_delete(@resources_table, {:_, %{project_id: project_id}})
        :ok

      [] ->
        {:error, :not_found}
    end
  end

  @doc """
  List all configured GCP projects.
  """
  @spec list_projects() :: [project()]
  def list_projects do
    ensure_tables()

    :ets.tab2list(@projects_table)
    |> Enum.map(fn {_id, project} -> sanitize_project(project) end)
  end

  @doc """
  Get a specific GCP project.
  """
  @spec get_project(String.t()) :: {:ok, project()} | {:error, :not_found}
  def get_project(project_id) do
    ensure_tables()

    case :ets.lookup(@projects_table, project_id) do
      [{^project_id, project}] -> {:ok, sanitize_project(project)}
      [] -> {:error, :not_found}
    end
  end

  # ============================================================================
  # Resource Scanning
  # ============================================================================

  @doc """
  Scan all resources for a GCP project.
  """
  @spec scan_project(String.t()) ::
          {:ok, %{resources: integer(), findings: integer()}} | {:error, term()}
  def scan_project(project_id) do
    ensure_tables()

    case :ets.lookup(@projects_table, project_id) do
      [{^project_id, project}] ->
        case get_valid_token(project) do
          {:ok, token} ->
            Logger.info("Starting GCP scan for project: #{project_id}")

            # Scan all resource types in parallel
            tasks = [
              Task.async(fn -> scan_compute_instances(project, token) end),
              Task.async(fn -> scan_firewall_rules(project, token) end),
              Task.async(fn -> scan_storage_buckets(project, token) end),
              Task.async(fn -> scan_iam_policies(project, token) end),
              Task.async(fn -> scan_service_accounts(project, token) end),
              Task.async(fn -> scan_gke_clusters(project, token) end),
              Task.async(fn -> scan_sql_instances(project, token) end),
              Task.async(fn -> scan_vpcs(project, token) end),
              Task.async(fn -> scan_audit_logs(project, token) end)
            ]

            results = Task.await_many(tasks, 300_000)

            total_resources =
              results
              |> Enum.map(fn
                {:ok, %{count: count}} -> count
                _ -> 0
              end)
              |> Enum.sum()

            total_findings =
              results
              |> Enum.map(fn
                {:ok, %{findings: findings}} -> length(findings)
                _ -> 0
              end)
              |> Enum.sum()

            # Update project last scan time
            updated = %{project | last_scan: DateTime.utc_now(), status: :connected}
            :ets.insert(@projects_table, {project_id, updated})

            Logger.info(
              "GCP scan complete for #{project_id}: #{total_resources} resources, #{total_findings} findings"
            )

            {:ok, %{resources: total_resources, findings: total_findings}}

          {:error, reason} ->
            updated = %{project | status: :error}
            :ets.insert(@projects_table, {project_id, updated})
            {:error, reason}
        end

      [] ->
        {:error, :project_not_found}
    end
  end

  @doc """
  List all resources for a project with optional filters.
  """
  @spec list_resources(String.t(), map()) :: [resource()]
  def list_resources(project_id, filters \\ %{}) do
    ensure_tables()

    :ets.tab2list(@resources_table)
    |> Enum.map(fn {_id, resource} -> resource end)
    |> Enum.filter(fn r -> r.project_id == project_id end)
    |> apply_resource_filters(filters)
  end

  # ============================================================================
  # Compute Instance Scanning
  # ============================================================================

  defp scan_compute_instances(project, token) do
    resources = []
    findings = []

    for zone <- @default_zones, reduce: {resources, findings} do
      {acc_resources, acc_findings} ->
        case list_instances(project.project_id, zone, token) do
          {:ok, instances} ->
            new_resources =
              Enum.map(instances, fn instance ->
                resource = %{
                  id: instance["id"],
                  self_link: instance["selfLink"],
                  type: "gcp_compute_instance",
                  name: instance["name"],
                  zone: zone,
                  region: extract_region(zone),
                  project_id: project.project_id,
                  labels: instance["labels"] || %{},
                  metadata: %{
                    machine_type: extract_name(instance["machineType"]),
                    status: instance["status"],
                    can_ip_forward: instance["canIpForward"],
                    network_interfaces: instance["networkInterfaces"] || [],
                    service_accounts: instance["serviceAccounts"] || [],
                    disks: instance["disks"] || [],
                    shielded_instance_config: instance["shieldedInstanceConfig"],
                    deletion_protection: instance["deletionProtection"]
                  },
                  created_at: parse_datetime(instance["creationTimestamp"])
                }

                :ets.insert(@resources_table, {resource.id, resource})
                resource
              end)

            new_findings = analyze_compute_instances(new_resources, project.project_id)
            {acc_resources ++ new_resources, acc_findings ++ new_findings}

          {:error, reason} ->
            Logger.warning("Failed to scan Compute instances in #{zone}: #{inspect(reason)}")
            {acc_resources, acc_findings}
        end
    end

    {:ok, %{count: length(resources), findings: findings}}
  end

  defp analyze_compute_instances(instances, project_id) do
    Enum.flat_map(instances, fn instance ->
      findings = []

      # Check for external IP
      has_external_ip =
        Enum.any?(instance.metadata.network_interfaces || [], fn ni ->
          access_configs = ni["accessConfigs"] || []
          Enum.any?(access_configs, fn ac -> not is_nil(ac["natIP"]) end)
        end)

      findings =
        if has_external_ip do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: instance.id,
              resource_arn: instance.self_link,
              resource_name: instance.name,
              resource_type: "Compute Instance",
              region: instance.zone,
              category: "network_security",
              severity: "medium",
              title: "Compute instance has external IP",
              description:
                "Instance #{instance.name} has an external IP address. Consider using Cloud NAT.",
              recommendation:
                "Remove external IP and use Cloud NAT for outbound traffic or Cloud IAP for SSH.",
              compliance: ["CIS GCP 4.9"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for default service account
      uses_default_sa =
        Enum.any?(instance.metadata.service_accounts || [], fn sa ->
          email = sa["email"] || ""
          String.contains?(email, "-compute@developer.gserviceaccount.com")
        end)

      findings =
        if uses_default_sa do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: instance.id,
              resource_arn: instance.self_link,
              resource_name: instance.name,
              resource_type: "Compute Instance",
              region: instance.zone,
              category: "identity_and_access",
              severity: "medium",
              title: "Instance uses default service account",
              description:
                "Instance #{instance.name} uses the default Compute Engine service account.",
              recommendation:
                "Create a custom service account with minimal required permissions.",
              compliance: ["CIS GCP 4.1"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for full API access scope
      has_full_api_access =
        Enum.any?(instance.metadata.service_accounts || [], fn sa ->
          scopes = sa["scopes"] || []
          "https://www.googleapis.com/auth/cloud-platform" in scopes
        end)

      findings =
        if has_full_api_access do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: instance.id,
              resource_arn: instance.self_link,
              resource_name: instance.name,
              resource_type: "Compute Instance",
              region: instance.zone,
              category: "identity_and_access",
              severity: "high",
              title: "Instance has full API access scope",
              description:
                "Instance #{instance.name} has cloud-platform scope (full API access).",
              recommendation:
                "Use specific scopes instead of cloud-platform for principle of least privilege.",
              compliance: ["CIS GCP 4.2"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for shielded VM
      shielded_config = instance.metadata.shielded_instance_config

      findings =
        if is_nil(shielded_config) or shielded_config["enableSecureBoot"] != true do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: instance.id,
              resource_arn: instance.self_link,
              resource_name: instance.name,
              resource_type: "Compute Instance",
              region: instance.zone,
              category: "compute_security",
              severity: "medium",
              title: "Shielded VM features not fully enabled",
              description: "Instance #{instance.name} does not have Secure Boot enabled.",
              recommendation: "Enable Shielded VM features including Secure Boot.",
              compliance: ["CIS GCP 4.8"]
            })
            | findings
          ]
        else
          findings
        end

      # Check disk encryption
      custom_encrypted =
        Enum.all?(instance.metadata.disks || [], fn disk ->
          encryption = disk["diskEncryptionKey"]
          not is_nil(encryption) and not is_nil(encryption["kmsKeyName"])
        end)

      findings =
        if not custom_encrypted and length(instance.metadata.disks || []) > 0 do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: instance.id,
              resource_arn: instance.self_link,
              resource_name: instance.name,
              resource_type: "Compute Instance",
              region: instance.zone,
              category: "data_protection",
              severity: "low",
              title: "Instance disks not using customer-managed encryption keys",
              description:
                "Instance #{instance.name} uses Google-managed encryption keys instead of CMEK.",
              recommendation:
                "Consider using Customer-Managed Encryption Keys for sensitive workloads.",
              compliance: ["CIS GCP 4.7"]
            })
            | findings
          ]
        else
          findings
        end

      findings
    end)
  end

  # ============================================================================
  # Firewall Rules Scanning
  # ============================================================================

  defp scan_firewall_rules(project, token) do
    case list_firewall_rules(project.project_id, token) do
      {:ok, rules} ->
        resources =
          Enum.map(rules, fn rule ->
            resource = %{
              id: rule["id"],
              self_link: rule["selfLink"],
              type: "gcp_firewall_rule",
              name: rule["name"],
              zone: nil,
              region: "global",
              project_id: project.project_id,
              labels: %{},
              metadata: %{
                network: rule["network"],
                direction: rule["direction"],
                priority: rule["priority"],
                source_ranges: rule["sourceRanges"] || [],
                destination_ranges: rule["destinationRanges"] || [],
                source_tags: rule["sourceTags"] || [],
                target_tags: rule["targetTags"] || [],
                allowed: rule["allowed"] || [],
                denied: rule["denied"] || [],
                disabled: rule["disabled"]
              },
              created_at: parse_datetime(rule["creationTimestamp"])
            }

            :ets.insert(@resources_table, {resource.id, resource})
            resource
          end)

        findings = analyze_firewall_rules(resources, project.project_id)
        {:ok, %{count: length(resources), findings: findings}}

      {:error, reason} ->
        Logger.warning("Failed to scan GCP firewall rules: #{inspect(reason)}")
        {:ok, %{count: 0, findings: []}}
    end
  end

  defp analyze_firewall_rules(rules, project_id) do
    Enum.flat_map(rules, fn rule ->
      findings = []

      # Only check ingress rules
      if rule.metadata.direction == "INGRESS" do
        # Check for unrestricted SSH
        findings =
          findings ++ check_unrestricted_port_gcp(rule, 22, "SSH", project_id)

        # Check for unrestricted RDP
        findings =
          findings ++ check_unrestricted_port_gcp(rule, 3389, "RDP", project_id)

        # Check for unrestricted all ports
        findings =
          findings ++ check_unrestricted_all_gcp(rule, project_id)

        findings
      else
        findings
      end
    end)
  end

  defp check_unrestricted_port_gcp(rule, port, service, project_id) do
    source_ranges = rule.metadata.source_ranges || []
    allowed = rule.metadata.allowed || []

    open_to_internet = "0.0.0.0/0" in source_ranges

    port_allowed =
      Enum.any?(allowed, fn allow ->
        ports = allow["ports"] || []
        protocol = allow["IPProtocol"]

        (protocol == "tcp" or protocol == "all") and
          (Enum.empty?(ports) or "#{port}" in ports or
             Enum.any?(ports, fn p -> port_in_range?(p, port) end))
      end)

    if open_to_internet and port_allowed do
      [
        Finding.create(%{
          provider: "gcp",
          account_id: project_id,
          resource_id: rule.id,
          resource_arn: rule.self_link,
          resource_name: rule.name,
          resource_type: "Firewall Rule",
          region: "global",
          category: "network_security",
          severity: "critical",
          title: "Firewall rule allows unrestricted #{service} access",
          description:
            "Firewall rule #{rule.name} allows inbound #{service} traffic (port #{port}) from 0.0.0.0/0.",
          recommendation:
            "Restrict #{service} access to specific IP ranges or use Cloud IAP.",
          compliance: ["CIS GCP 3.6", "CIS GCP 3.7", "PCI DSS 1.3.1"],
          remediation_terraform: """
          resource "google_compute_firewall" "#{rule.name}" {
            source_ranges = ["10.0.0.0/8"]  # Restrict to internal network
            allow {
              protocol = "tcp"
              ports    = ["#{port}"]
            }
          }
          """
        })
      ]
    else
      []
    end
  end

  defp check_unrestricted_all_gcp(rule, project_id) do
    source_ranges = rule.metadata.source_ranges || []
    allowed = rule.metadata.allowed || []

    open_to_internet = "0.0.0.0/0" in source_ranges

    all_ports_allowed =
      Enum.any?(allowed, fn allow ->
        protocol = allow["IPProtocol"]
        ports = allow["ports"]
        protocol == "all" or (protocol == "tcp" and is_nil(ports))
      end)

    if open_to_internet and all_ports_allowed do
      [
        Finding.create(%{
          provider: "gcp",
          account_id: project_id,
          resource_id: rule.id,
          resource_arn: rule.self_link,
          resource_name: rule.name,
          resource_type: "Firewall Rule",
          region: "global",
          category: "network_security",
          severity: "critical",
          title: "Firewall rule allows all inbound traffic from the internet",
          description:
            "Firewall rule #{rule.name} allows all inbound traffic from 0.0.0.0/0.",
          recommendation:
            "Remove the rule or restrict to specific ports and source ranges.",
          compliance: ["CIS GCP 3.6", "PCI DSS 1.2.1"]
        })
      ]
    else
      []
    end
  end

  defp port_in_range?(range, port) when is_binary(range) do
    case String.split(range, "-") do
      [start_str, end_str] ->
        with {start, _} <- Integer.parse(start_str),
             {end_port, _} <- Integer.parse(end_str) do
          port >= start and port <= end_port
        else
          _ -> false
        end

      _ ->
        false
    end
  end

  defp port_in_range?(_, _), do: false

  # ============================================================================
  # Storage Bucket Scanning
  # ============================================================================

  defp scan_storage_buckets(project, token) do
    case list_buckets(project.project_id, token) do
      {:ok, buckets} ->
        resources =
          Enum.map(buckets, fn bucket ->
            # Get bucket IAM and lifecycle
            iam_policy = get_bucket_iam_policy(bucket["name"], token)
            encryption = bucket["encryption"]

            resource = %{
              id: bucket["id"],
              self_link: bucket["selfLink"],
              type: "gcp_storage_bucket",
              name: bucket["name"],
              zone: nil,
              region: bucket["location"],
              project_id: project.project_id,
              labels: bucket["labels"] || %{},
              metadata: %{
                storage_class: bucket["storageClass"],
                versioning: bucket["versioning"],
                logging: bucket["logging"],
                iam_configuration: bucket["iamConfiguration"],
                iam_policy: iam_policy,
                encryption: encryption,
                lifecycle: bucket["lifecycle"],
                retention_policy: bucket["retentionPolicy"]
              },
              created_at: parse_datetime(bucket["timeCreated"])
            }

            :ets.insert(@resources_table, {resource.id, resource})
            resource
          end)

        findings = analyze_storage_buckets(resources, project.project_id)
        {:ok, %{count: length(resources), findings: findings}}

      {:error, reason} ->
        Logger.warning("Failed to scan GCP storage buckets: #{inspect(reason)}")
        {:ok, %{count: 0, findings: []}}
    end
  end

  defp analyze_storage_buckets(buckets, project_id) do
    Enum.flat_map(buckets, fn bucket ->
      findings = []

      # Check for public access
      findings =
        if bucket_is_public_gcp?(bucket) do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: bucket.id,
              resource_arn: bucket.self_link,
              resource_name: bucket.name,
              resource_type: "Cloud Storage Bucket",
              region: bucket.region,
              category: "data_protection",
              severity: "critical",
              title: "Storage bucket is publicly accessible",
              description:
                "Bucket #{bucket.name} allows public access (allUsers or allAuthenticatedUsers).",
              recommendation:
                "Remove public access and enable uniform bucket-level access.",
              compliance: ["CIS GCP 5.1", "PCI DSS 7.1"],
              remediation_terraform: """
              resource "google_storage_bucket_iam_member" "remove_public" {
                bucket = "#{bucket.name}"
                # Remove these members:
                # - allUsers
                # - allAuthenticatedUsers
              }
              """
            })
            | findings
          ]
        else
          findings
        end

      # Check for uniform bucket-level access
      iam_config = bucket.metadata.iam_configuration

      findings =
        if is_nil(iam_config) or
             get_in(iam_config, ["uniformBucketLevelAccess", "enabled"]) != true do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: bucket.id,
              resource_arn: bucket.self_link,
              resource_name: bucket.name,
              resource_type: "Cloud Storage Bucket",
              region: bucket.region,
              category: "identity_and_access",
              severity: "medium",
              title: "Uniform bucket-level access not enabled",
              description:
                "Bucket #{bucket.name} does not have uniform bucket-level access enabled.",
              recommendation:
                "Enable uniform bucket-level access for consistent IAM policies.",
              compliance: ["CIS GCP 5.2"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for versioning
      versioning = bucket.metadata.versioning

      findings =
        if is_nil(versioning) or versioning["enabled"] != true do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: bucket.id,
              resource_arn: bucket.self_link,
              resource_name: bucket.name,
              resource_type: "Cloud Storage Bucket",
              region: bucket.region,
              category: "data_protection",
              severity: "medium",
              title: "Bucket versioning not enabled",
              description: "Bucket #{bucket.name} does not have versioning enabled.",
              recommendation: "Enable versioning to protect against accidental deletion.",
              compliance: ["GCP Best Practices"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for logging
      findings =
        if is_nil(bucket.metadata.logging) do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: bucket.id,
              resource_arn: bucket.self_link,
              resource_name: bucket.name,
              resource_type: "Cloud Storage Bucket",
              region: bucket.region,
              category: "logging_monitoring",
              severity: "medium",
              title: "Bucket access logging not enabled",
              description: "Bucket #{bucket.name} does not have access logging enabled.",
              recommendation: "Enable access logging to track bucket access.",
              compliance: ["CIS GCP 5.3"]
            })
            | findings
          ]
        else
          findings
        end

      findings
    end)
  end

  defp bucket_is_public_gcp?(bucket) do
    iam_policy = bucket.metadata.iam_policy

    case iam_policy do
      %{"bindings" => bindings} when is_list(bindings) ->
        Enum.any?(bindings, fn binding ->
          members = binding["members"] || []
          "allUsers" in members or "allAuthenticatedUsers" in members
        end)

      _ ->
        false
    end
  end

  # ============================================================================
  # IAM Policy Scanning
  # ============================================================================

  defp scan_iam_policies(project, token) do
    case get_project_iam_policy(project.project_id, token) do
      {:ok, policy} ->
        bindings = policy["bindings"] || []

        resource = %{
          id: "#{project.project_id}-iam-policy",
          self_link: "projects/#{project.project_id}/iamPolicy",
          type: "gcp_iam_policy",
          name: "Project IAM Policy",
          zone: nil,
          region: "global",
          project_id: project.project_id,
          labels: %{},
          metadata: %{
            bindings: bindings,
            version: policy["version"],
            etag: policy["etag"]
          },
          created_at: nil
        }

        :ets.insert(@resources_table, {resource.id, resource})

        findings = analyze_iam_policies([resource], project.project_id)
        {:ok, %{count: 1, findings: findings}}

      {:error, reason} ->
        Logger.warning("Failed to scan GCP IAM policies: #{inspect(reason)}")
        {:ok, %{count: 0, findings: []}}
    end
  end

  defp analyze_iam_policies(policies, project_id) do
    Enum.flat_map(policies, fn policy ->
      bindings = policy.metadata.bindings || []
      findings = []

      # Check for primitive roles
      primitive_bindings =
        Enum.filter(bindings, fn binding ->
          role = binding["role"] || ""
          role in ["roles/owner", "roles/editor", "roles/viewer"]
        end)

      findings =
        Enum.reduce(primitive_bindings, findings, fn binding, acc ->
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: policy.id,
              resource_arn: policy.self_link,
              resource_name: policy.name,
              resource_type: "IAM Policy",
              region: "global",
              category: "identity_and_access",
              severity: "medium",
              title: "Primitive role in use",
              description:
                "Project uses primitive role #{binding["role"]} which grants broad permissions.",
              recommendation:
                "Replace primitive roles with predefined or custom roles following least privilege.",
              compliance: ["CIS GCP 1.6"]
            })
            | acc
          ]
        end)

      # Check for service account keys with owner role
      owner_bindings = Enum.filter(bindings, fn b -> b["role"] == "roles/owner" end)

      sa_owners =
        Enum.flat_map(owner_bindings, fn binding ->
          members = binding["members"] || []
          Enum.filter(members, fn m -> String.starts_with?(m, "serviceAccount:") end)
        end)

      findings =
        if length(sa_owners) > 0 do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: policy.id,
              resource_arn: policy.self_link,
              resource_name: policy.name,
              resource_type: "IAM Policy",
              region: "global",
              category: "identity_and_access",
              severity: "high",
              title: "Service account has Owner role",
              description:
                "#{length(sa_owners)} service account(s) have the Owner role on the project.",
              recommendation:
                "Remove Owner role from service accounts. Use specific roles instead.",
              compliance: ["CIS GCP 1.5"]
            })
            | findings
          ]
        else
          findings
        end

      findings
    end)
  end

  # ============================================================================
  # Service Account Scanning
  # ============================================================================

  defp scan_service_accounts(project, token) do
    case list_service_accounts(project.project_id, token) do
      {:ok, accounts} ->
        resources =
          Enum.map(accounts, fn account ->
            keys = list_service_account_keys(account["email"], project.project_id, token)

            resource = %{
              id: account["uniqueId"],
              self_link: account["name"],
              type: "gcp_service_account",
              name: account["email"],
              zone: nil,
              region: "global",
              project_id: project.project_id,
              labels: %{},
              metadata: %{
                email: account["email"],
                display_name: account["displayName"],
                disabled: account["disabled"],
                keys: keys
              },
              created_at: nil
            }

            :ets.insert(@resources_table, {resource.id, resource})
            resource
          end)

        findings = analyze_service_accounts(resources, project.project_id)
        {:ok, %{count: length(resources), findings: findings}}

      {:error, reason} ->
        Logger.warning("Failed to scan GCP service accounts: #{inspect(reason)}")
        {:ok, %{count: 0, findings: []}}
    end
  end

  defp analyze_service_accounts(accounts, project_id) do
    Enum.flat_map(accounts, fn account ->
      findings = []
      keys = account.metadata.keys || []

      # Filter out system-managed keys
      user_keys =
        Enum.filter(keys, fn key ->
          key["keyType"] == "USER_MANAGED"
        end)

      # Check for user-managed keys
      findings =
        if length(user_keys) > 0 do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: account.id,
              resource_arn: account.self_link,
              resource_name: account.name,
              resource_type: "Service Account",
              region: "global",
              category: "identity_and_access",
              severity: "medium",
              title: "Service account has user-managed keys",
              description:
                "Service account #{account.name} has #{length(user_keys)} user-managed key(s).",
              recommendation:
                "Avoid user-managed keys. Use workload identity or attached service accounts.",
              compliance: ["CIS GCP 1.4"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for old keys
      ninety_days_ago = DateTime.add(DateTime.utc_now(), -90 * 24 * 60 * 60, :second)

      old_keys =
        Enum.filter(user_keys, fn key ->
          case parse_datetime(key["validAfterTime"]) do
            nil -> false
            created -> DateTime.compare(created, ninety_days_ago) == :lt
          end
        end)

      findings =
        if length(old_keys) > 0 do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: account.id,
              resource_arn: account.self_link,
              resource_name: account.name,
              resource_type: "Service Account",
              region: "global",
              category: "identity_and_access",
              severity: "medium",
              title: "Service account has keys older than 90 days",
              description:
                "Service account #{account.name} has #{length(old_keys)} key(s) older than 90 days.",
              recommendation: "Rotate service account keys regularly.",
              compliance: ["CIS GCP 1.7"]
            })
            | findings
          ]
        else
          findings
        end

      findings
    end)
  end

  # ============================================================================
  # GKE Cluster Scanning
  # ============================================================================

  defp scan_gke_clusters(project, token) do
    case list_gke_clusters(project.project_id, token) do
      {:ok, clusters} ->
        resources =
          Enum.map(clusters, fn cluster ->
            resource = %{
              id: cluster["id"],
              self_link: cluster["selfLink"],
              type: "gcp_gke_cluster",
              name: cluster["name"],
              zone: cluster["zone"],
              region: cluster["location"],
              project_id: project.project_id,
              labels: cluster["resourceLabels"] || %{},
              metadata: %{
                status: cluster["status"],
                current_node_version: cluster["currentNodeVersion"],
                current_master_version: cluster["currentMasterVersion"],
                legacy_abac: get_in(cluster, ["legacyAbac", "enabled"]),
                master_auth: cluster["masterAuth"],
                network_policy: cluster["networkPolicy"],
                private_cluster_config: cluster["privateClusterConfig"],
                master_authorized_networks:
                  cluster["masterAuthorizedNetworksConfig"],
                database_encryption: cluster["databaseEncryption"],
                shielded_nodes: cluster["shieldedNodes"],
                workload_identity: get_in(cluster, ["workloadIdentityConfig"])
              },
              created_at: parse_datetime(cluster["createTime"])
            }

            :ets.insert(@resources_table, {resource.id, resource})
            resource
          end)

        findings = analyze_gke_clusters(resources, project.project_id)
        {:ok, %{count: length(resources), findings: findings}}

      {:error, reason} ->
        Logger.warning("Failed to scan GCP GKE clusters: #{inspect(reason)}")
        {:ok, %{count: 0, findings: []}}
    end
  end

  defp analyze_gke_clusters(clusters, project_id) do
    Enum.flat_map(clusters, fn cluster ->
      findings = []

      # Check for legacy ABAC
      findings =
        if cluster.metadata.legacy_abac == true do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: cluster.id,
              resource_arn: cluster.self_link,
              resource_name: cluster.name,
              resource_type: "GKE Cluster",
              region: cluster.region,
              category: "identity_and_access",
              severity: "high",
              title: "GKE cluster has legacy ABAC enabled",
              description:
                "GKE cluster #{cluster.name} has legacy ABAC (Attribute-Based Access Control) enabled.",
              recommendation: "Disable legacy ABAC and use RBAC instead.",
              compliance: ["CIS GCP 7.3"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for client certificate auth
      master_auth = cluster.metadata.master_auth

      findings =
        if not is_nil(master_auth) and not is_nil(master_auth["clientCertificate"]) do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: cluster.id,
              resource_arn: cluster.self_link,
              resource_name: cluster.name,
              resource_type: "GKE Cluster",
              region: cluster.region,
              category: "identity_and_access",
              severity: "medium",
              title: "GKE cluster uses client certificate authentication",
              description:
                "GKE cluster #{cluster.name} has client certificate authentication enabled.",
              recommendation:
                "Disable client certificate authentication and use Google Cloud IAM.",
              compliance: ["CIS GCP 7.10"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for network policy
      network_policy = cluster.metadata.network_policy

      findings =
        if is_nil(network_policy) or network_policy["enabled"] != true do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: cluster.id,
              resource_arn: cluster.self_link,
              resource_name: cluster.name,
              resource_type: "GKE Cluster",
              region: cluster.region,
              category: "network_security",
              severity: "medium",
              title: "GKE network policy not enabled",
              description: "GKE cluster #{cluster.name} does not have network policy enabled.",
              recommendation: "Enable network policy for pod-level network segmentation.",
              compliance: ["CIS GCP 7.11"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for private cluster
      private_config = cluster.metadata.private_cluster_config

      findings =
        if is_nil(private_config) or private_config["enablePrivateNodes"] != true do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: cluster.id,
              resource_arn: cluster.self_link,
              resource_name: cluster.name,
              resource_type: "GKE Cluster",
              region: cluster.region,
              category: "network_security",
              severity: "medium",
              title: "GKE cluster not using private nodes",
              description: "GKE cluster #{cluster.name} does not use private nodes.",
              recommendation:
                "Enable private nodes to remove external IP addresses from nodes.",
              compliance: ["CIS GCP 7.15"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for workload identity
      findings =
        if is_nil(cluster.metadata.workload_identity) do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: cluster.id,
              resource_arn: cluster.self_link,
              resource_name: cluster.name,
              resource_type: "GKE Cluster",
              region: cluster.region,
              category: "identity_and_access",
              severity: "medium",
              title: "GKE workload identity not enabled",
              description: "GKE cluster #{cluster.name} does not have workload identity enabled.",
              recommendation:
                "Enable workload identity for secure access to Google Cloud APIs.",
              compliance: ["CIS GCP 7.17"]
            })
            | findings
          ]
        else
          findings
        end

      findings
    end)
  end

  # ============================================================================
  # Cloud SQL Scanning
  # ============================================================================

  defp scan_sql_instances(project, token) do
    case list_sql_instances(project.project_id, token) do
      {:ok, instances} ->
        resources =
          Enum.map(instances, fn instance ->
            resource = %{
              id: instance["name"],
              self_link: instance["selfLink"],
              type: "gcp_sql_instance",
              name: instance["name"],
              zone: instance["gceZone"],
              region: instance["region"],
              project_id: project.project_id,
              labels: instance["settings"]["userLabels"] || %{},
              metadata: %{
                database_version: instance["databaseVersion"],
                state: instance["state"],
                ip_configuration:
                  get_in(instance, ["settings", "ipConfiguration"]),
                backup_configuration:
                  get_in(instance, ["settings", "backupConfiguration"]),
                database_flags: get_in(instance, ["settings", "databaseFlags"]) || [],
                ssl_enabled:
                  get_in(instance, ["serverCaCert"]) != nil
              },
              created_at: parse_datetime(instance["createTime"])
            }

            :ets.insert(@resources_table, {resource.id, resource})
            resource
          end)

        findings = analyze_sql_instances(resources, project.project_id)
        {:ok, %{count: length(resources), findings: findings}}

      {:error, reason} ->
        Logger.warning("Failed to scan GCP SQL instances: #{inspect(reason)}")
        {:ok, %{count: 0, findings: []}}
    end
  end

  defp analyze_sql_instances(instances, project_id) do
    Enum.flat_map(instances, fn instance ->
      findings = []
      ip_config = instance.metadata.ip_configuration || %{}

      # Check for public IP
      findings =
        if ip_config["ipv4Enabled"] == true do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: instance.id,
              resource_arn: instance.self_link,
              resource_name: instance.name,
              resource_type: "Cloud SQL Instance",
              region: instance.region,
              category: "network_security",
              severity: "high",
              title: "Cloud SQL instance has public IP",
              description: "Cloud SQL instance #{instance.name} has a public IP address.",
              recommendation:
                "Disable public IP and use Private IP with Private Service Access.",
              compliance: ["CIS GCP 6.6", "PCI DSS 1.3.1"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for SSL enforcement
      findings =
        if ip_config["requireSsl"] != true do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: instance.id,
              resource_arn: instance.self_link,
              resource_name: instance.name,
              resource_type: "Cloud SQL Instance",
              region: instance.region,
              category: "network_security",
              severity: "high",
              title: "Cloud SQL does not require SSL",
              description: "Cloud SQL instance #{instance.name} does not require SSL connections.",
              recommendation: "Enable 'Require SSL' for all connections.",
              compliance: ["CIS GCP 6.1", "PCI DSS 4.1"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for automated backups
      backup_config = instance.metadata.backup_configuration || %{}

      findings =
        if backup_config["enabled"] != true do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: instance.id,
              resource_arn: instance.self_link,
              resource_name: instance.name,
              resource_type: "Cloud SQL Instance",
              region: instance.region,
              category: "data_protection",
              severity: "high",
              title: "Cloud SQL automated backups disabled",
              description:
                "Cloud SQL instance #{instance.name} does not have automated backups enabled.",
              recommendation: "Enable automated backups for data protection.",
              compliance: ["CIS GCP 6.7"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for authorized networks (0.0.0.0/0)
      authorized_networks = ip_config["authorizedNetworks"] || []

      open_to_all =
        Enum.any?(authorized_networks, fn net ->
          net["value"] == "0.0.0.0/0"
        end)

      findings =
        if open_to_all do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: instance.id,
              resource_arn: instance.self_link,
              resource_name: instance.name,
              resource_type: "Cloud SQL Instance",
              region: instance.region,
              category: "network_security",
              severity: "critical",
              title: "Cloud SQL accessible from any IP",
              description:
                "Cloud SQL instance #{instance.name} allows connections from 0.0.0.0/0.",
              recommendation: "Restrict authorized networks to specific IP ranges.",
              compliance: ["CIS GCP 6.5", "PCI DSS 1.3.1"]
            })
            | findings
          ]
        else
          findings
        end

      findings
    end)
  end

  # ============================================================================
  # VPC Scanning
  # ============================================================================

  defp scan_vpcs(project, token) do
    case list_networks(project.project_id, token) do
      {:ok, networks} ->
        resources =
          Enum.map(networks, fn network ->
            resource = %{
              id: network["id"],
              self_link: network["selfLink"],
              type: "gcp_vpc_network",
              name: network["name"],
              zone: nil,
              region: "global",
              project_id: project.project_id,
              labels: %{},
              metadata: %{
                auto_create_subnetworks: network["autoCreateSubnetworks"],
                subnetworks: network["subnetworks"] || [],
                routing_config: network["routingConfig"]
              },
              created_at: parse_datetime(network["creationTimestamp"])
            }

            :ets.insert(@resources_table, {resource.id, resource})
            resource
          end)

        findings = analyze_vpcs(resources, project.project_id)
        {:ok, %{count: length(resources), findings: findings}}

      {:error, reason} ->
        Logger.warning("Failed to scan GCP VPCs: #{inspect(reason)}")
        {:ok, %{count: 0, findings: []}}
    end
  end

  defp analyze_vpcs(networks, project_id) do
    Enum.flat_map(networks, fn network ->
      findings = []

      # Check for default network
      findings =
        if network.name == "default" do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: network.id,
              resource_arn: network.self_link,
              resource_name: network.name,
              resource_type: "VPC Network",
              region: "global",
              category: "network_security",
              severity: "medium",
              title: "Default VPC network in use",
              description:
                "Project uses the default VPC network which has permissive firewall rules.",
              recommendation:
                "Delete the default network and create custom VPCs with appropriate firewall rules.",
              compliance: ["CIS GCP 3.1"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for legacy (auto mode) network
      findings =
        if network.metadata.auto_create_subnetworks == true do
          [
            Finding.create(%{
              provider: "gcp",
              account_id: project_id,
              resource_id: network.id,
              resource_arn: network.self_link,
              resource_name: network.name,
              resource_type: "VPC Network",
              region: "global",
              category: "network_security",
              severity: "low",
              title: "VPC uses auto mode subnets",
              description:
                "VPC network #{network.name} uses auto mode (legacy) subnet creation.",
              recommendation:
                "Consider using custom mode for better control over IP ranges.",
              compliance: ["GCP Best Practices"]
            })
            | findings
          ]
        else
          findings
        end

      findings
    end)
  end

  # ============================================================================
  # Audit Log Scanning
  # ============================================================================

  defp scan_audit_logs(project, token) do
    case get_audit_log_config(project.project_id, token) do
      {:ok, config} ->
        findings = analyze_audit_logs(config, project.project_id)
        {:ok, %{count: 1, findings: findings}}

      {:error, reason} ->
        Logger.warning("Failed to scan GCP audit logs: #{inspect(reason)}")
        {:ok, %{count: 0, findings: []}}
    end
  end

  defp analyze_audit_logs(config, project_id) do
    audit_configs = config["auditConfigs"] || []

    # Check if Data Access logs are enabled
    has_data_access =
      Enum.any?(audit_configs, fn ac ->
        log_types = ac["auditLogConfigs"] || []
        Enum.any?(log_types, fn lt -> lt["logType"] == "DATA_READ" end) and
          Enum.any?(log_types, fn lt -> lt["logType"] == "DATA_WRITE" end)
      end)

    if not has_data_access do
      [
        Finding.create(%{
          provider: "gcp",
          account_id: project_id,
          resource_id: "audit-log-config",
          resource_arn: "projects/#{project_id}/iamPolicy",
          resource_name: "Audit Log Configuration",
          resource_type: "Audit Log",
          region: "global",
          category: "logging_monitoring",
          severity: "high",
          title: "Data Access audit logs not fully enabled",
          description:
            "Project does not have comprehensive Data Access audit logging enabled.",
          recommendation:
            "Enable DATA_READ and DATA_WRITE audit logs for all services.",
          compliance: ["CIS GCP 2.1", "PCI DSS 10.2"]
        })
      ]
    else
      []
    end
  end

  # ============================================================================
  # GCP API Calls — Real implementations using Finch + Bearer token (JWT)
  # ============================================================================

  @cache_namespace :cloud_gcp
  @cache_ttl 300
  @http_timeout 30_000

  defp get_access_token(project) do
    key = project.service_account_key

    if is_nil(key) or not is_map(key) do
      {:error, :not_configured}
    else
      Logger.debug("Getting GCP access token for project: #{project.project_id}")

      # Build JWT for service account authentication
      now = System.system_time(:second)
      client_email = key["client_email"]
      private_key_pem = key["private_key"]

      if is_nil(client_email) or is_nil(private_key_pem) do
        {:error, :invalid_service_account_key}
      else
        jwt_header = Base.url_encode64(Jason.encode!(%{"alg" => "RS256", "typ" => "JWT"}), padding: false)

        jwt_claims =
          Base.url_encode64(
            Jason.encode!(%{
              "iss" => client_email,
              "scope" => "https://www.googleapis.com/auth/cloud-platform",
              "aud" => @gcp_auth_url,
              "iat" => now,
              "exp" => now + 3600
            }),
            padding: false
          )

        signing_input = "#{jwt_header}.#{jwt_claims}"

        case sign_jwt_rs256(signing_input, private_key_pem) do
          {:ok, signature} ->
            jwt = "#{signing_input}.#{signature}"

            body =
              URI.encode_query(%{
                "grant_type" => "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion" => jwt
              })

            headers = [{"Content-Type", "application/x-www-form-urlencoded"}]

            case finch_request(:post, @gcp_auth_url, headers, body) do
              {:ok, %{status: 200, body: resp_body}} ->
                case Jason.decode(resp_body) do
                  {:ok, %{"access_token" => token, "expires_in" => expires_in}} ->
                    expires_at = DateTime.add(DateTime.utc_now(), expires_in, :second)
                    {:ok, token, expires_at}

                  {:ok, data} ->
                    Logger.error("Unexpected GCP token response: #{inspect(Map.keys(data))}")
                    {:error, :unexpected_response}

                  _ ->
                    {:error, :parse_error}
                end

              {:ok, %{status: status, body: resp_body}} ->
                Logger.error("GCP OAuth failed (#{status}): #{String.slice(resp_body, 0..300)}")
                {:error, {:auth_error, status}}

              {:error, reason} ->
                Logger.error("GCP OAuth request failed: #{inspect(reason)}")
                {:error, reason}
            end

          {:error, reason} ->
            Logger.error("Failed to sign GCP JWT: #{inspect(reason)}")
            {:error, :jwt_signing_failed}
        end
      end
    end
  end

  defp sign_jwt_rs256(input, private_key_pem) do
    try do
      [pem_entry | _] = :public_key.pem_decode(private_key_pem)
      private_key = :public_key.pem_entry_decode(pem_entry)
      signature = :public_key.sign(input, :sha256, private_key)
      {:ok, Base.url_encode64(signature, padding: false)}
    rescue
      e ->
        {:error, Exception.message(e)}
    end
  end

  defp get_valid_token(project) do
    case project do
      %{access_token: token, token_expires_at: expires_at}
      when not is_nil(token) and not is_nil(expires_at) ->
        if DateTime.compare(expires_at, DateTime.utc_now()) == :gt do
          {:ok, token}
        else
          case get_access_token(project) do
            {:ok, new_token, _} -> {:ok, new_token}
            error -> error
          end
        end

      _ ->
        case get_access_token(project) do
          {:ok, new_token, _} -> {:ok, new_token}
          error -> error
        end
    end
  end

  # ---------- Compute Instances ----------

  defp list_instances(project_id, zone, token) do
    cache_key = "instances:#{project_id}:#{zone}"

    TamanduaServer.Cache.get_or_fetch(@cache_namespace, cache_key, @cache_ttl, fn ->
      gcp_get("#{@gcp_compute_api}/projects/#{project_id}/zones/#{zone}/instances", token)
    end)
  end

  # ---------- Firewall Rules ----------

  defp list_firewall_rules(project_id, token) do
    cache_key = "firewall_rules:#{project_id}"

    TamanduaServer.Cache.get_or_fetch(@cache_namespace, cache_key, @cache_ttl, fn ->
      gcp_get("#{@gcp_compute_api}/projects/#{project_id}/global/firewalls", token)
    end)
  end

  # ---------- Storage Buckets ----------

  defp list_buckets(project_id, token) do
    cache_key = "buckets:#{project_id}"

    TamanduaServer.Cache.get_or_fetch(@cache_namespace, cache_key, @cache_ttl, fn ->
      gcp_get("#{@gcp_storage_api}/b?project=#{project_id}", token, "items")
    end)
  end

  defp get_bucket_iam_policy(bucket_name, token) do
    url = "#{@gcp_storage_api}/b/#{URI.encode(bucket_name)}/iam"

    case gcp_get_raw(url, token) do
      {:ok, policy} -> policy
      _ -> nil
    end
  end

  # ---------- IAM Policies ----------

  defp get_project_iam_policy(project_id, token) do
    url = "https://cloudresourcemanager.googleapis.com/v1/projects/#{project_id}:getIamPolicy"

    Logger.debug("GCP: getIamPolicy for #{project_id}")

    headers = [
      {"Authorization", "Bearer #{token}"},
      {"Content-Type", "application/json"}
    ]

    case finch_request(:post, url, headers, "{}") do
      {:ok, %{status: 200, body: resp_body}} ->
        Jason.decode(resp_body)

      {:ok, %{status: status}} ->
        {:error, {:api_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ---------- Service Accounts ----------

  defp list_service_accounts(project_id, token) do
    cache_key = "service_accounts:#{project_id}"

    TamanduaServer.Cache.get_or_fetch(@cache_namespace, cache_key, @cache_ttl, fn ->
      gcp_get("#{@gcp_iam_api}/projects/#{project_id}/serviceAccounts", token, "accounts")
    end)
  end

  defp list_service_account_keys(email, project_id, token) do
    url = "#{@gcp_iam_api}/projects/#{project_id}/serviceAccounts/#{URI.encode(email)}/keys"

    case gcp_get_raw(url, token) do
      {:ok, %{"keys" => keys}} when is_list(keys) -> keys
      _ -> []
    end
  end

  # ---------- GKE Clusters ----------

  defp list_gke_clusters(project_id, token) do
    cache_key = "gke_clusters:#{project_id}"

    TamanduaServer.Cache.get_or_fetch(@cache_namespace, cache_key, @cache_ttl, fn ->
      url = "#{@gcp_container_api}/projects/#{project_id}/locations/-/clusters"

      case gcp_get_raw(url, token) do
        {:ok, %{"clusters" => clusters}} when is_list(clusters) ->
          {:ok, clusters}

        {:ok, _} ->
          {:ok, []}

        error ->
          error
      end
    end)
  end

  # ---------- Cloud SQL ----------

  defp list_sql_instances(project_id, token) do
    cache_key = "sql_instances:#{project_id}"

    TamanduaServer.Cache.get_or_fetch(@cache_namespace, cache_key, @cache_ttl, fn ->
      url = "https://sqladmin.googleapis.com/v1/projects/#{project_id}/instances"

      case gcp_get_raw(url, token) do
        {:ok, %{"items" => items}} when is_list(items) ->
          {:ok, items}

        {:ok, _} ->
          {:ok, []}

        error ->
          error
      end
    end)
  end

  # ---------- VPC Networks ----------

  defp list_networks(project_id, token) do
    cache_key = "networks:#{project_id}"

    TamanduaServer.Cache.get_or_fetch(@cache_namespace, cache_key, @cache_ttl, fn ->
      gcp_get("#{@gcp_compute_api}/projects/#{project_id}/global/networks", token)
    end)
  end

  # ---------- Audit Logs ----------

  defp get_audit_log_config(project_id, token) do
    # Audit log configuration is part of the IAM policy
    case get_project_iam_policy(project_id, token) do
      {:ok, policy} -> {:ok, policy}
      error -> error
    end
  end

  # ============================================================================
  # GCP HTTP Helpers
  # ============================================================================

  defp gcp_get(url, token, items_key \\ "items") do
    Logger.debug("GCP GET: #{URI.parse(url).path}")

    headers = [
      {"Authorization", "Bearer #{token}"},
      {"Content-Type", "application/json"}
    ]

    case finch_request(:get, url, headers, "") do
      {:ok, %{status: 200, body: resp_body}} ->
        case Jason.decode(resp_body) do
          {:ok, %{^items_key => items}} when is_list(items) ->
            {:ok, items}

          {:ok, _} ->
            {:ok, []}

          _ ->
            {:error, :parse_error}
        end

      {:ok, %{status: 401}} ->
        {:error, :unauthorized}

      {:ok, %{status: 403}} ->
        {:error, :forbidden}

      {:ok, %{status: 404}} ->
        {:ok, []}

      {:ok, %{status: 429}} ->
        Logger.warning("GCP rate limited")
        {:error, :rate_limited}

      {:ok, %{status: status, body: resp_body}} ->
        Logger.warning("GCP API failed (#{status}): #{String.slice(resp_body, 0..200)}")
        {:error, {:api_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp gcp_get_raw(url, token) do
    headers = [
      {"Authorization", "Bearer #{token}"},
      {"Content-Type", "application/json"}
    ]

    case finch_request(:get, url, headers, "") do
      {:ok, %{status: 200, body: resp_body}} ->
        Jason.decode(resp_body)

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      {:ok, %{status: status}} ->
        {:error, {:api_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp finch_request(method, url, headers, body) do
    req_body = if body == "", do: nil, else: body
    request = Finch.build(method, url, headers, req_body)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: status, body: resp_body}} ->
        {:ok, %{status: status, body: resp_body}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  defp ensure_tables do
    tables = [@projects_table, @resources_table]

    Enum.each(tables, fn table ->
      case :ets.whereis(table) do
        :undefined -> :ets.new(table, [:set, :public, :named_table])
        _ -> :ok
      end
    end)
  end

  defp validate_project(project) do
    cond do
      is_nil(project.project_id) ->
        {:error, "Project ID is required"}

      is_nil(project.service_account_key) ->
        {:error, "Service account key is required"}

      true ->
        :ok
    end
  end

  defp sanitize_project(project) do
    Map.drop(project, [:service_account_key, :access_token])
  end

  defp extract_region(zone) do
    case String.split(zone, "-") do
      [region, _zone_letter | _] -> "#{region}-#{_zone_letter}"
      _ -> zone
    end
  end

  defp extract_name(url) when is_binary(url) do
    url
    |> String.split("/")
    |> List.last()
  end

  defp extract_name(_), do: nil

  defp parse_datetime(nil), do: nil

  defp parse_datetime(dt) when is_binary(dt) do
    case DateTime.from_iso8601(dt) do
      {:ok, datetime, _} -> datetime
      _ -> nil
    end
  end

  defp parse_datetime(_), do: nil

  defp apply_resource_filters(resources, filters) do
    resources
    |> maybe_filter(:type, filters[:type])
    |> maybe_filter(:region, filters[:region])
    |> maybe_filter(:zone, filters[:zone])
  end

  defp maybe_filter(list, _field, nil), do: list

  defp maybe_filter(list, field, value) do
    Enum.filter(list, fn r -> Map.get(r, field) == value end)
  end
end
