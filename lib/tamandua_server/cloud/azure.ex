defmodule TamanduaServer.Cloud.Azure do
  @moduledoc """
  Azure Cloud Security Posture Management (CSPM) integration.

  Provides comprehensive security scanning and assessment of Azure resources
  including VMs, Storage Accounts, Key Vault, AKS, and NSGs.

  ## Features
  - Service principal authentication
  - RBAC analysis
  - Network security analysis
  - Storage account security analysis
  - Resource inventory collection
  """

  require Logger
  alias TamanduaServer.Cloud.Finding

  @type subscription :: %{
          subscription_id: String.t(),
          display_name: String.t(),
          tenant_id: String.t(),
          client_id: String.t(),
          client_secret: String.t() | nil,
          status: :connected | :disconnected | :error,
          last_scan: DateTime.t() | nil,
          access_token: String.t() | nil,
          token_expires_at: DateTime.t() | nil
        }

  @type resource :: %{
          id: String.t(),
          name: String.t(),
          type: String.t(),
          location: String.t(),
          subscription_id: String.t(),
          resource_group: String.t(),
          tags: map(),
          metadata: map(),
          created_at: DateTime.t() | nil
        }

  # ETS tables for Azure data
  @subscriptions_table :azure_subscriptions
  @resources_table :azure_resources

  @azure_management_api "https://management.azure.com"
  @azure_auth_url "https://login.microsoftonline.com"

  # ============================================================================
  # Subscription Management
  # ============================================================================

  @doc """
  Add a new Azure subscription for CSPM scanning.
  """
  @spec add_subscription(map()) :: {:ok, subscription()} | {:error, term()}
  def add_subscription(params) do
    ensure_tables()

    subscription = %{
      subscription_id: params["subscription_id"] || params[:subscription_id],
      display_name: params["display_name"] || params[:display_name],
      tenant_id: params["tenant_id"] || params[:tenant_id],
      client_id: params["client_id"] || params[:client_id],
      client_secret: params["client_secret"] || params[:client_secret],
      status: :disconnected,
      last_scan: nil,
      access_token: nil,
      token_expires_at: nil,
      added_at: DateTime.utc_now()
    }

    # Validate required fields
    case validate_subscription(subscription) do
      :ok ->
        :ets.insert(@subscriptions_table, {subscription.subscription_id, subscription})
        Logger.info("Added Azure subscription: #{subscription.subscription_id}")

        # Test connection
        case get_access_token(subscription) do
          {:ok, token, expires_at} ->
            updated = %{
              subscription
              | status: :connected,
                access_token: token,
                token_expires_at: expires_at
            }

            :ets.insert(@subscriptions_table, {subscription.subscription_id, updated})
            {:ok, sanitize_subscription(updated)}

          {:error, reason} ->
            Logger.warning(
              "Azure subscription #{subscription.subscription_id} connection test failed: #{inspect(reason)}"
            )

            {:ok, sanitize_subscription(subscription)}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Remove an Azure subscription from CSPM scanning.
  """
  @spec remove_subscription(String.t()) :: :ok | {:error, :not_found}
  def remove_subscription(subscription_id) do
    ensure_tables()

    case :ets.lookup(@subscriptions_table, subscription_id) do
      [{^subscription_id, _}] ->
        :ets.delete(@subscriptions_table, subscription_id)
        # Clean up resources for this subscription
        :ets.match_delete(@resources_table, {:_, %{subscription_id: subscription_id}})
        :ok

      [] ->
        {:error, :not_found}
    end
  end

  @doc """
  List all configured Azure subscriptions.
  """
  @spec list_subscriptions() :: [subscription()]
  def list_subscriptions do
    ensure_tables()

    :ets.tab2list(@subscriptions_table)
    |> Enum.map(fn {_id, sub} -> sanitize_subscription(sub) end)
  end

  @doc """
  Get a specific Azure subscription.
  """
  @spec get_subscription(String.t()) :: {:ok, subscription()} | {:error, :not_found}
  def get_subscription(subscription_id) do
    ensure_tables()

    case :ets.lookup(@subscriptions_table, subscription_id) do
      [{^subscription_id, sub}] -> {:ok, sanitize_subscription(sub)}
      [] -> {:error, :not_found}
    end
  end

  # ============================================================================
  # Resource Scanning
  # ============================================================================

  @doc """
  Scan all resources for an Azure subscription.
  """
  @spec scan_subscription(String.t()) ::
          {:ok, %{resources: integer(), findings: integer()}} | {:error, term()}
  def scan_subscription(subscription_id) do
    ensure_tables()

    case :ets.lookup(@subscriptions_table, subscription_id) do
      [{^subscription_id, subscription}] ->
        case get_valid_token(subscription) do
          {:ok, token} ->
            Logger.info("Starting Azure scan for subscription: #{subscription_id}")

            # Scan all resource types in parallel
            tasks = [
              Task.async(fn -> scan_virtual_machines(subscription, token) end),
              Task.async(fn -> scan_storage_accounts(subscription, token) end),
              Task.async(fn -> scan_network_security_groups(subscription, token) end),
              Task.async(fn -> scan_key_vaults(subscription, token) end),
              Task.async(fn -> scan_aks_clusters(subscription, token) end),
              Task.async(fn -> scan_sql_servers(subscription, token) end),
              Task.async(fn -> scan_app_services(subscription, token) end),
              Task.async(fn -> scan_rbac_assignments(subscription, token) end),
              Task.async(fn -> scan_activity_logs(subscription, token) end)
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

            # Update subscription last scan time
            updated = %{subscription | last_scan: DateTime.utc_now(), status: :connected}
            :ets.insert(@subscriptions_table, {subscription_id, updated})

            Logger.info(
              "Azure scan complete for #{subscription_id}: #{total_resources} resources, #{total_findings} findings"
            )

            {:ok, %{resources: total_resources, findings: total_findings}}

          {:error, reason} ->
            updated = %{subscription | status: :error}
            :ets.insert(@subscriptions_table, {subscription_id, updated})
            {:error, reason}
        end

      [] ->
        {:error, :subscription_not_found}
    end
  end

  @doc """
  List all resources for a subscription with optional filters.
  """
  @spec list_resources(String.t(), map()) :: [resource()]
  def list_resources(subscription_id, filters \\ %{}) do
    ensure_tables()

    :ets.tab2list(@resources_table)
    |> Enum.map(fn {_id, resource} -> resource end)
    |> Enum.filter(fn r -> r.subscription_id == subscription_id end)
    |> apply_resource_filters(filters)
  end

  # ============================================================================
  # Virtual Machines Scanning
  # ============================================================================

  defp scan_virtual_machines(subscription, token) do
    case list_vms(subscription.subscription_id, token) do
      {:ok, vms} ->
        resources =
          Enum.map(vms, fn vm ->
            resource = %{
              id: vm["id"],
              name: vm["name"],
              type: "azure_virtual_machine",
              location: vm["location"],
              subscription_id: subscription.subscription_id,
              resource_group: extract_resource_group(vm["id"]),
              tags: vm["tags"] || %{},
              metadata: %{
                vm_size: get_in(vm, ["properties", "hardwareProfile", "vmSize"]),
                os_type:
                  get_in(vm, ["properties", "storageProfile", "osDisk", "osType"]),
                provisioning_state: get_in(vm, ["properties", "provisioningState"]),
                network_interfaces:
                  get_in(vm, ["properties", "networkProfile", "networkInterfaces"]) || [],
                availability_set:
                  get_in(vm, ["properties", "availabilitySet", "id"]),
                disk_encryption:
                  get_in(vm, ["properties", "storageProfile", "osDisk", "encryptionSettings"]),
                extensions: get_in(vm, ["resources"]) || []
              },
              created_at: parse_datetime(get_in(vm, ["properties", "timeCreated"]))
            }

            :ets.insert(@resources_table, {resource.id, resource})
            resource
          end)

        findings = analyze_virtual_machines(resources, subscription.subscription_id)
        {:ok, %{count: length(resources), findings: findings}}

      {:error, reason} ->
        Logger.warning("Failed to scan Azure VMs: #{inspect(reason)}")
        {:ok, %{count: 0, findings: []}}
    end
  end

  defp analyze_virtual_machines(vms, subscription_id) do
    Enum.flat_map(vms, fn vm ->
      findings = []

      # Check for disk encryption
      findings =
        if is_nil(vm.metadata.disk_encryption) do
          [
            Finding.create(%{
              provider: "azure",
              account_id: subscription_id,
              resource_id: vm.id,
              resource_arn: vm.id,
              resource_name: vm.name,
              resource_type: "Virtual Machine",
              region: vm.location,
              category: "data_protection",
              severity: "high",
              title: "VM disk encryption not enabled",
              description:
                "Virtual machine #{vm.name} does not have Azure Disk Encryption enabled.",
              recommendation: "Enable Azure Disk Encryption for all VM disks.",
              compliance: ["CIS Azure 7.1", "PCI DSS 3.4"],
              remediation_terraform: """
              resource "azurerm_virtual_machine_extension" "disk_encryption" {
                name                 = "AzureDiskEncryption"
                virtual_machine_id   = "#{vm.id}"
                publisher            = "Microsoft.Azure.Security"
                type                 = "AzureDiskEncryption"
                type_handler_version = "2.2"
              }
              """
            })
            | findings
          ]
        else
          findings
        end

      # Check for endpoint protection
      has_endpoint_protection =
        Enum.any?(vm.metadata.extensions || [], fn ext ->
          ext_type = ext["properties"]["type"] || ""

          String.contains?(ext_type, "MicrosoftMonitoringAgent") or
            String.contains?(ext_type, "IaaSAntimalware")
        end)

      findings =
        if not has_endpoint_protection do
          [
            Finding.create(%{
              provider: "azure",
              account_id: subscription_id,
              resource_id: vm.id,
              resource_arn: vm.id,
              resource_name: vm.name,
              resource_type: "Virtual Machine",
              region: vm.location,
              category: "compute_security",
              severity: "medium",
              title: "VM missing endpoint protection",
              description:
                "Virtual machine #{vm.name} does not have endpoint protection installed.",
              recommendation:
                "Install Microsoft Antimalware or a third-party endpoint protection solution.",
              compliance: ["CIS Azure 7.5"]
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
  # Storage Account Scanning
  # ============================================================================

  defp scan_storage_accounts(subscription, token) do
    case list_storage_accounts(subscription.subscription_id, token) do
      {:ok, accounts} ->
        resources =
          Enum.map(accounts, fn account ->
            resource = %{
              id: account["id"],
              name: account["name"],
              type: "azure_storage_account",
              location: account["location"],
              subscription_id: subscription.subscription_id,
              resource_group: extract_resource_group(account["id"]),
              tags: account["tags"] || %{},
              metadata: %{
                kind: account["kind"],
                sku: get_in(account, ["sku", "name"]),
                https_only: get_in(account, ["properties", "supportsHttpsTrafficOnly"]),
                encryption_services:
                  get_in(account, ["properties", "encryption", "services"]),
                network_acls: get_in(account, ["properties", "networkAcls"]),
                allow_blob_public_access:
                  get_in(account, ["properties", "allowBlobPublicAccess"]),
                minimum_tls_version:
                  get_in(account, ["properties", "minimumTlsVersion"]),
                key_source: get_in(account, ["properties", "encryption", "keySource"])
              },
              created_at: parse_datetime(get_in(account, ["properties", "creationTime"]))
            }

            :ets.insert(@resources_table, {resource.id, resource})
            resource
          end)

        findings = analyze_storage_accounts(resources, subscription.subscription_id)
        {:ok, %{count: length(resources), findings: findings}}

      {:error, reason} ->
        Logger.warning("Failed to scan Azure Storage Accounts: #{inspect(reason)}")
        {:ok, %{count: 0, findings: []}}
    end
  end

  defp analyze_storage_accounts(accounts, subscription_id) do
    Enum.flat_map(accounts, fn account ->
      findings = []

      # Check for HTTPS only
      findings =
        if account.metadata.https_only != true do
          [
            Finding.create(%{
              provider: "azure",
              account_id: subscription_id,
              resource_id: account.id,
              resource_arn: account.id,
              resource_name: account.name,
              resource_type: "Storage Account",
              region: account.location,
              category: "network_security",
              severity: "high",
              title: "Storage account allows insecure HTTP traffic",
              description:
                "Storage account #{account.name} does not enforce HTTPS-only traffic.",
              recommendation: "Enable 'Secure transfer required' setting.",
              compliance: ["CIS Azure 3.1", "PCI DSS 4.1"],
              remediation_terraform: """
              resource "azurerm_storage_account" "#{account.name}" {
                enable_https_traffic_only = true
              }
              """
            })
            | findings
          ]
        else
          findings
        end

      # Check for public blob access
      findings =
        if account.metadata.allow_blob_public_access == true do
          [
            Finding.create(%{
              provider: "azure",
              account_id: subscription_id,
              resource_id: account.id,
              resource_arn: account.id,
              resource_name: account.name,
              resource_type: "Storage Account",
              region: account.location,
              category: "data_protection",
              severity: "high",
              title: "Storage account allows public blob access",
              description:
                "Storage account #{account.name} allows public access to blob containers.",
              recommendation: "Disable 'Allow Blob public access' at the storage account level.",
              compliance: ["CIS Azure 3.6"],
              remediation_terraform: """
              resource "azurerm_storage_account" "#{account.name}" {
                allow_blob_public_access = false
              }
              """
            })
            | findings
          ]
        else
          findings
        end

      # Check TLS version
      findings =
        if account.metadata.minimum_tls_version != "TLS1_2" do
          [
            Finding.create(%{
              provider: "azure",
              account_id: subscription_id,
              resource_id: account.id,
              resource_arn: account.id,
              resource_name: account.name,
              resource_type: "Storage Account",
              region: account.location,
              category: "network_security",
              severity: "medium",
              title: "Storage account allows TLS versions below 1.2",
              description:
                "Storage account #{account.name} allows connections with TLS version lower than 1.2.",
              recommendation: "Set minimum TLS version to 1.2.",
              compliance: ["CIS Azure 3.12", "PCI DSS 4.1"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for network restrictions
      network_acls = account.metadata.network_acls

      findings =
        if is_nil(network_acls) or network_acls["defaultAction"] == "Allow" do
          [
            Finding.create(%{
              provider: "azure",
              account_id: subscription_id,
              resource_id: account.id,
              resource_arn: account.id,
              resource_name: account.name,
              resource_type: "Storage Account",
              region: account.location,
              category: "network_security",
              severity: "medium",
              title: "Storage account accessible from all networks",
              description:
                "Storage account #{account.name} allows access from all networks.",
              recommendation:
                "Configure network rules to restrict access to specific virtual networks.",
              compliance: ["CIS Azure 3.7"]
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
  # Network Security Groups Scanning
  # ============================================================================

  defp scan_network_security_groups(subscription, token) do
    case list_nsgs(subscription.subscription_id, token) do
      {:ok, nsgs} ->
        resources =
          Enum.map(nsgs, fn nsg ->
            resource = %{
              id: nsg["id"],
              name: nsg["name"],
              type: "azure_network_security_group",
              location: nsg["location"],
              subscription_id: subscription.subscription_id,
              resource_group: extract_resource_group(nsg["id"]),
              tags: nsg["tags"] || %{},
              metadata: %{
                security_rules: get_in(nsg, ["properties", "securityRules"]) || [],
                default_rules:
                  get_in(nsg, ["properties", "defaultSecurityRules"]) || [],
                subnets: get_in(nsg, ["properties", "subnets"]) || [],
                network_interfaces:
                  get_in(nsg, ["properties", "networkInterfaces"]) || []
              },
              created_at: nil
            }

            :ets.insert(@resources_table, {resource.id, resource})
            resource
          end)

        findings = analyze_nsgs(resources, subscription.subscription_id)
        {:ok, %{count: length(resources), findings: findings}}

      {:error, reason} ->
        Logger.warning("Failed to scan Azure NSGs: #{inspect(reason)}")
        {:ok, %{count: 0, findings: []}}
    end
  end

  defp analyze_nsgs(nsgs, subscription_id) do
    Enum.flat_map(nsgs, fn nsg ->
      rules = nsg.metadata.security_rules || []

      # Check for unrestricted SSH
      ssh_findings = check_unrestricted_port_azure(nsg, rules, "22", "SSH", subscription_id)

      # Check for unrestricted RDP
      rdp_findings = check_unrestricted_port_azure(nsg, rules, "3389", "RDP", subscription_id)

      # Check for unrestricted inbound from internet
      any_findings =
        check_unrestricted_inbound_azure(nsg, rules, subscription_id)

      ssh_findings ++ rdp_findings ++ any_findings
    end)
  end

  defp check_unrestricted_port_azure(nsg, rules, port, service, subscription_id) do
    unrestricted =
      Enum.any?(rules, fn rule ->
        props = rule["properties"] || %{}

        direction = props["direction"]
        access = props["access"]
        source = props["sourceAddressPrefix"]
        dest_port = props["destinationPortRange"]
        dest_ports = props["destinationPortRanges"] || []

        direction == "Inbound" and
          access == "Allow" and
          (source == "*" or source == "Internet" or source == "0.0.0.0/0") and
          (dest_port == port or dest_port == "*" or port in dest_ports)
      end)

    if unrestricted do
      [
        Finding.create(%{
          provider: "azure",
          account_id: subscription_id,
          resource_id: nsg.id,
          resource_arn: nsg.id,
          resource_name: nsg.name,
          resource_type: "Network Security Group",
          region: nsg.location,
          category: "network_security",
          severity: "critical",
          title: "NSG allows unrestricted #{service} access",
          description:
            "Network Security Group #{nsg.name} allows inbound #{service} traffic (port #{port}) from the internet.",
          recommendation:
            "Restrict #{service} access to specific IP addresses or use Azure Bastion.",
          compliance: ["CIS Azure 6.1", "CIS Azure 6.2", "PCI DSS 1.3.1"]
        })
      ]
    else
      []
    end
  end

  defp check_unrestricted_inbound_azure(nsg, rules, subscription_id) do
    unrestricted =
      Enum.any?(rules, fn rule ->
        props = rule["properties"] || %{}

        direction = props["direction"]
        access = props["access"]
        source = props["sourceAddressPrefix"]
        dest_port = props["destinationPortRange"]

        direction == "Inbound" and
          access == "Allow" and
          (source == "*" or source == "Internet" or source == "0.0.0.0/0") and
          dest_port == "*"
      end)

    if unrestricted do
      [
        Finding.create(%{
          provider: "azure",
          account_id: subscription_id,
          resource_id: nsg.id,
          resource_arn: nsg.id,
          resource_name: nsg.name,
          resource_type: "Network Security Group",
          region: nsg.location,
          category: "network_security",
          severity: "critical",
          title: "NSG allows all inbound traffic from the internet",
          description:
            "Network Security Group #{nsg.name} allows all inbound traffic from the internet.",
          recommendation:
            "Remove the rule allowing all inbound traffic. Implement least-privilege network access.",
          compliance: ["CIS Azure 6.5", "PCI DSS 1.2.1"]
        })
      ]
    else
      []
    end
  end

  # ============================================================================
  # Key Vault Scanning
  # ============================================================================

  defp scan_key_vaults(subscription, token) do
    case list_key_vaults(subscription.subscription_id, token) do
      {:ok, vaults} ->
        resources =
          Enum.map(vaults, fn vault ->
            resource = %{
              id: vault["id"],
              name: vault["name"],
              type: "azure_key_vault",
              location: vault["location"],
              subscription_id: subscription.subscription_id,
              resource_group: extract_resource_group(vault["id"]),
              tags: vault["tags"] || %{},
              metadata: %{
                sku: get_in(vault, ["properties", "sku", "name"]),
                tenant_id: get_in(vault, ["properties", "tenantId"]),
                soft_delete_enabled:
                  get_in(vault, ["properties", "enableSoftDelete"]),
                purge_protection:
                  get_in(vault, ["properties", "enablePurgeProtection"]),
                network_acls: get_in(vault, ["properties", "networkAcls"]),
                access_policies: get_in(vault, ["properties", "accessPolicies"]) || [],
                enable_rbac: get_in(vault, ["properties", "enableRbacAuthorization"])
              },
              created_at: nil
            }

            :ets.insert(@resources_table, {resource.id, resource})
            resource
          end)

        findings = analyze_key_vaults(resources, subscription.subscription_id)
        {:ok, %{count: length(resources), findings: findings}}

      {:error, reason} ->
        Logger.warning("Failed to scan Azure Key Vaults: #{inspect(reason)}")
        {:ok, %{count: 0, findings: []}}
    end
  end

  defp analyze_key_vaults(vaults, subscription_id) do
    Enum.flat_map(vaults, fn vault ->
      findings = []

      # Check for soft delete
      findings =
        if vault.metadata.soft_delete_enabled != true do
          [
            Finding.create(%{
              provider: "azure",
              account_id: subscription_id,
              resource_id: vault.id,
              resource_arn: vault.id,
              resource_name: vault.name,
              resource_type: "Key Vault",
              region: vault.location,
              category: "data_protection",
              severity: "high",
              title: "Key Vault soft delete not enabled",
              description: "Key Vault #{vault.name} does not have soft delete enabled.",
              recommendation: "Enable soft delete to protect against accidental deletion.",
              compliance: ["CIS Azure 8.4"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for purge protection
      findings =
        if vault.metadata.purge_protection != true do
          [
            Finding.create(%{
              provider: "azure",
              account_id: subscription_id,
              resource_id: vault.id,
              resource_arn: vault.id,
              resource_name: vault.name,
              resource_type: "Key Vault",
              region: vault.location,
              category: "data_protection",
              severity: "medium",
              title: "Key Vault purge protection not enabled",
              description:
                "Key Vault #{vault.name} does not have purge protection enabled.",
              recommendation:
                "Enable purge protection to prevent permanent deletion of secrets.",
              compliance: ["CIS Azure 8.5"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for network restrictions
      network_acls = vault.metadata.network_acls

      findings =
        if is_nil(network_acls) or network_acls["defaultAction"] == "Allow" do
          [
            Finding.create(%{
              provider: "azure",
              account_id: subscription_id,
              resource_id: vault.id,
              resource_arn: vault.id,
              resource_name: vault.name,
              resource_type: "Key Vault",
              region: vault.location,
              category: "network_security",
              severity: "high",
              title: "Key Vault accessible from all networks",
              description: "Key Vault #{vault.name} allows access from all networks.",
              recommendation: "Configure network rules to restrict access to specific VNets.",
              compliance: ["CIS Azure 8.6"]
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
  # AKS Cluster Scanning
  # ============================================================================

  defp scan_aks_clusters(subscription, token) do
    case list_aks_clusters(subscription.subscription_id, token) do
      {:ok, clusters} ->
        resources =
          Enum.map(clusters, fn cluster ->
            resource = %{
              id: cluster["id"],
              name: cluster["name"],
              type: "azure_aks_cluster",
              location: cluster["location"],
              subscription_id: subscription.subscription_id,
              resource_group: extract_resource_group(cluster["id"]),
              tags: cluster["tags"] || %{},
              metadata: %{
                kubernetes_version:
                  get_in(cluster, ["properties", "kubernetesVersion"]),
                provisioning_state:
                  get_in(cluster, ["properties", "provisioningState"]),
                enable_rbac: get_in(cluster, ["properties", "enableRBAC"]),
                aad_profile: get_in(cluster, ["properties", "aadProfile"]),
                network_profile: get_in(cluster, ["properties", "networkProfile"]),
                api_server_access_profile:
                  get_in(cluster, ["properties", "apiServerAccessProfile"]),
                agent_pools:
                  get_in(cluster, ["properties", "agentPoolProfiles"]) || []
              },
              created_at: nil
            }

            :ets.insert(@resources_table, {resource.id, resource})
            resource
          end)

        findings = analyze_aks_clusters(resources, subscription.subscription_id)
        {:ok, %{count: length(resources), findings: findings}}

      {:error, reason} ->
        Logger.warning("Failed to scan Azure AKS clusters: #{inspect(reason)}")
        {:ok, %{count: 0, findings: []}}
    end
  end

  defp analyze_aks_clusters(clusters, subscription_id) do
    Enum.flat_map(clusters, fn cluster ->
      findings = []

      # Check for RBAC
      findings =
        if cluster.metadata.enable_rbac != true do
          [
            Finding.create(%{
              provider: "azure",
              account_id: subscription_id,
              resource_id: cluster.id,
              resource_arn: cluster.id,
              resource_name: cluster.name,
              resource_type: "AKS Cluster",
              region: cluster.location,
              category: "identity_and_access",
              severity: "high",
              title: "AKS cluster RBAC not enabled",
              description:
                "AKS cluster #{cluster.name} does not have Kubernetes RBAC enabled.",
              recommendation: "Enable RBAC for the AKS cluster.",
              compliance: ["CIS Azure 8.5"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for Azure AD integration
      findings =
        if is_nil(cluster.metadata.aad_profile) do
          [
            Finding.create(%{
              provider: "azure",
              account_id: subscription_id,
              resource_id: cluster.id,
              resource_arn: cluster.id,
              resource_name: cluster.name,
              resource_type: "AKS Cluster",
              region: cluster.location,
              category: "identity_and_access",
              severity: "medium",
              title: "AKS cluster not integrated with Azure AD",
              description:
                "AKS cluster #{cluster.name} is not integrated with Azure Active Directory.",
              recommendation:
                "Enable Azure AD integration for centralized identity management.",
              compliance: ["CIS Azure 8.5"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for private API server
      api_access = cluster.metadata.api_server_access_profile

      findings =
        if is_nil(api_access) or api_access["enablePrivateCluster"] != true do
          [
            Finding.create(%{
              provider: "azure",
              account_id: subscription_id,
              resource_id: cluster.id,
              resource_arn: cluster.id,
              resource_name: cluster.name,
              resource_type: "AKS Cluster",
              region: cluster.location,
              category: "network_security",
              severity: "medium",
              title: "AKS API server is publicly accessible",
              description:
                "AKS cluster #{cluster.name} has a publicly accessible API server.",
              recommendation:
                "Consider enabling private cluster to restrict API server access.",
              compliance: ["CIS Azure 8.5"]
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
  # SQL Server Scanning
  # ============================================================================

  defp scan_sql_servers(subscription, token) do
    case list_sql_servers(subscription.subscription_id, token) do
      {:ok, servers} ->
        resources =
          Enum.map(servers, fn server ->
            # Get additional details
            auditing = get_sql_auditing(subscription.subscription_id, server, token)
            tde = get_sql_tde(subscription.subscription_id, server, token)

            resource = %{
              id: server["id"],
              name: server["name"],
              type: "azure_sql_server",
              location: server["location"],
              subscription_id: subscription.subscription_id,
              resource_group: extract_resource_group(server["id"]),
              tags: server["tags"] || %{},
              metadata: %{
                version: get_in(server, ["properties", "version"]),
                state: get_in(server, ["properties", "state"]),
                admin_login:
                  get_in(server, ["properties", "administratorLogin"]),
                minimal_tls_version:
                  get_in(server, ["properties", "minimalTlsVersion"]),
                public_network_access:
                  get_in(server, ["properties", "publicNetworkAccess"]),
                auditing_enabled: auditing,
                tde_enabled: tde
              },
              created_at: nil
            }

            :ets.insert(@resources_table, {resource.id, resource})
            resource
          end)

        findings = analyze_sql_servers(resources, subscription.subscription_id)
        {:ok, %{count: length(resources), findings: findings}}

      {:error, reason} ->
        Logger.warning("Failed to scan Azure SQL Servers: #{inspect(reason)}")
        {:ok, %{count: 0, findings: []}}
    end
  end

  defp analyze_sql_servers(servers, subscription_id) do
    Enum.flat_map(servers, fn server ->
      findings = []

      # Check for auditing
      findings =
        if server.metadata.auditing_enabled != true do
          [
            Finding.create(%{
              provider: "azure",
              account_id: subscription_id,
              resource_id: server.id,
              resource_arn: server.id,
              resource_name: server.name,
              resource_type: "SQL Server",
              region: server.location,
              category: "logging_monitoring",
              severity: "high",
              title: "SQL Server auditing not enabled",
              description: "SQL Server #{server.name} does not have auditing enabled.",
              recommendation:
                "Enable auditing to track database events and maintain compliance.",
              compliance: ["CIS Azure 4.1.1", "PCI DSS 10.2"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for TLS version
      findings =
        if server.metadata.minimal_tls_version != "1.2" do
          [
            Finding.create(%{
              provider: "azure",
              account_id: subscription_id,
              resource_id: server.id,
              resource_arn: server.id,
              resource_name: server.name,
              resource_type: "SQL Server",
              region: server.location,
              category: "network_security",
              severity: "medium",
              title: "SQL Server allows TLS versions below 1.2",
              description:
                "SQL Server #{server.name} allows connections with TLS version lower than 1.2.",
              recommendation: "Set minimum TLS version to 1.2.",
              compliance: ["CIS Azure 4.1.2", "PCI DSS 4.1"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for public network access
      findings =
        if server.metadata.public_network_access == "Enabled" do
          [
            Finding.create(%{
              provider: "azure",
              account_id: subscription_id,
              resource_id: server.id,
              resource_arn: server.id,
              resource_name: server.name,
              resource_type: "SQL Server",
              region: server.location,
              category: "network_security",
              severity: "high",
              title: "SQL Server publicly accessible",
              description:
                "SQL Server #{server.name} allows public network access.",
              recommendation:
                "Disable public network access and use Private Endpoints.",
              compliance: ["CIS Azure 4.1.3", "PCI DSS 1.3.1"]
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
  # App Service Scanning
  # ============================================================================

  defp scan_app_services(subscription, token) do
    case list_web_apps(subscription.subscription_id, token) do
      {:ok, apps} ->
        resources =
          Enum.map(apps, fn app ->
            resource = %{
              id: app["id"],
              name: app["name"],
              type: "azure_app_service",
              location: app["location"],
              subscription_id: subscription.subscription_id,
              resource_group: extract_resource_group(app["id"]),
              tags: app["tags"] || %{},
              metadata: %{
                kind: app["kind"],
                state: get_in(app, ["properties", "state"]),
                https_only: get_in(app, ["properties", "httpsOnly"]),
                min_tls_version:
                  get_in(app, ["properties", "siteConfig", "minTlsVersion"]),
                ftps_state:
                  get_in(app, ["properties", "siteConfig", "ftpsState"]),
                client_cert_enabled:
                  get_in(app, ["properties", "clientCertEnabled"]),
                identity: app["identity"]
              },
              created_at: nil
            }

            :ets.insert(@resources_table, {resource.id, resource})
            resource
          end)

        findings = analyze_app_services(resources, subscription.subscription_id)
        {:ok, %{count: length(resources), findings: findings}}

      {:error, reason} ->
        Logger.warning("Failed to scan Azure App Services: #{inspect(reason)}")
        {:ok, %{count: 0, findings: []}}
    end
  end

  defp analyze_app_services(apps, subscription_id) do
    Enum.flat_map(apps, fn app ->
      findings = []

      # Check for HTTPS only
      findings =
        if app.metadata.https_only != true do
          [
            Finding.create(%{
              provider: "azure",
              account_id: subscription_id,
              resource_id: app.id,
              resource_arn: app.id,
              resource_name: app.name,
              resource_type: "App Service",
              region: app.location,
              category: "network_security",
              severity: "high",
              title: "App Service allows HTTP traffic",
              description: "App Service #{app.name} does not enforce HTTPS-only traffic.",
              recommendation: "Enable 'HTTPS Only' setting for the App Service.",
              compliance: ["CIS Azure 9.2", "PCI DSS 4.1"]
            })
            | findings
          ]
        else
          findings
        end

      # Check TLS version
      findings =
        if app.metadata.min_tls_version != "1.2" do
          [
            Finding.create(%{
              provider: "azure",
              account_id: subscription_id,
              resource_id: app.id,
              resource_arn: app.id,
              resource_name: app.name,
              resource_type: "App Service",
              region: app.location,
              category: "network_security",
              severity: "medium",
              title: "App Service allows TLS versions below 1.2",
              description:
                "App Service #{app.name} allows connections with TLS version lower than 1.2.",
              recommendation: "Set minimum TLS version to 1.2.",
              compliance: ["CIS Azure 9.3", "PCI DSS 4.1"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for managed identity
      findings =
        if is_nil(app.metadata.identity) do
          [
            Finding.create(%{
              provider: "azure",
              account_id: subscription_id,
              resource_id: app.id,
              resource_arn: app.id,
              resource_name: app.name,
              resource_type: "App Service",
              region: app.location,
              category: "identity_and_access",
              severity: "low",
              title: "App Service not using managed identity",
              description: "App Service #{app.name} is not configured with a managed identity.",
              recommendation:
                "Enable managed identity for secure access to Azure resources.",
              compliance: ["Azure Best Practices"]
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
  # RBAC Scanning
  # ============================================================================

  defp scan_rbac_assignments(subscription, token) do
    case list_role_assignments(subscription.subscription_id, token) do
      {:ok, assignments} ->
        resources =
          Enum.map(assignments, fn assignment ->
            resource = %{
              id: assignment["id"],
              name: assignment["name"],
              type: "azure_role_assignment",
              location: "global",
              subscription_id: subscription.subscription_id,
              resource_group: "N/A",
              tags: %{},
              metadata: %{
                principal_id: get_in(assignment, ["properties", "principalId"]),
                principal_type: get_in(assignment, ["properties", "principalType"]),
                role_definition_id:
                  get_in(assignment, ["properties", "roleDefinitionId"]),
                scope: get_in(assignment, ["properties", "scope"])
              },
              created_at:
                parse_datetime(get_in(assignment, ["properties", "createdOn"]))
            }

            :ets.insert(@resources_table, {resource.id, resource})
            resource
          end)

        findings = analyze_rbac_assignments(resources, subscription.subscription_id)
        {:ok, %{count: length(resources), findings: findings}}

      {:error, reason} ->
        Logger.warning("Failed to scan Azure RBAC: #{inspect(reason)}")
        {:ok, %{count: 0, findings: []}}
    end
  end

  defp analyze_rbac_assignments(assignments, subscription_id) do
    # Check for owner role assignments
    owner_assignments =
      Enum.filter(assignments, fn a ->
        role_def = a.metadata.role_definition_id || ""
        # Owner role definition ID ends with specific GUID
        String.contains?(role_def, "8e3af657-a8ff-443c-a75c-2fe8c4bcb635")
      end)

    if length(owner_assignments) > 3 do
      [
        Finding.create(%{
          provider: "azure",
          account_id: subscription_id,
          resource_id: "rbac-config",
          resource_arn: "subscription/#{subscription_id}",
          resource_name: "RBAC Configuration",
          resource_type: "RBAC",
          region: "global",
          category: "identity_and_access",
          severity: "high",
          title: "Too many subscription owners",
          description:
            "Subscription has #{length(owner_assignments)} owner role assignments. Limit to 3 or fewer.",
          recommendation:
            "Review owner assignments and remove unnecessary ones. Use custom roles instead.",
          compliance: ["CIS Azure 1.3"]
        })
      ]
    else
      []
    end
  end

  # ============================================================================
  # Activity Log Scanning
  # ============================================================================

  defp scan_activity_logs(subscription, token) do
    case get_diagnostic_settings(subscription.subscription_id, token) do
      {:ok, settings} ->
        findings = analyze_activity_logs(settings, subscription.subscription_id)
        {:ok, %{count: length(settings), findings: findings}}

      {:error, reason} ->
        Logger.warning("Failed to scan Azure Activity Logs: #{inspect(reason)}")
        {:ok, %{count: 0, findings: []}}
    end
  end

  defp analyze_activity_logs(settings, subscription_id) do
    # Check if activity logs are exported
    has_log_export =
      Enum.any?(settings, fn s ->
        logs = get_in(s, ["properties", "logs"]) || []

        Enum.any?(logs, fn log ->
          log["enabled"] == true and
            (get_in(s, ["properties", "storageAccountId"]) != nil or
               get_in(s, ["properties", "workspaceId"]) != nil)
        end)
      end)

    if not has_log_export do
      [
        Finding.create(%{
          provider: "azure",
          account_id: subscription_id,
          resource_id: "activity-log-config",
          resource_arn: "subscription/#{subscription_id}",
          resource_name: "Activity Log",
          resource_type: "Activity Log",
          region: "global",
          category: "logging_monitoring",
          severity: "high",
          title: "Activity Log not exported",
          description:
            "Azure Activity Log is not configured to export to a storage account or Log Analytics workspace.",
          recommendation:
            "Configure diagnostic settings to export Activity Log for long-term retention.",
          compliance: ["CIS Azure 5.1.1", "PCI DSS 10.2"]
        })
      ]
    else
      []
    end
  end

  # ============================================================================
  # Azure API Calls — Real implementations using Finch + Bearer token
  # ============================================================================

  @cache_namespace :cloud_azure
  @cache_ttl 300
  @http_timeout 30_000

  defp get_access_token(subscription) do
    if is_nil(subscription.client_id) or is_nil(subscription.client_secret) or
         is_nil(subscription.tenant_id) do
      {:error, :not_configured}
    else
      url = "#{@azure_auth_url}/#{subscription.tenant_id}/oauth2/v2.0/token"

      body =
        URI.encode_query(%{
          "grant_type" => "client_credentials",
          "client_id" => subscription.client_id,
          "client_secret" => subscription.client_secret,
          "scope" => "https://management.azure.com/.default"
        })

      Logger.debug("Getting Azure access token from: #{url}")

      headers = [{"Content-Type", "application/x-www-form-urlencoded"}]

      case finch_request(:post, url, headers, body) do
        {:ok, %{status: 200, body: resp_body}} ->
          case Jason.decode(resp_body) do
            {:ok, %{"access_token" => token, "expires_in" => expires_in}} ->
              expires_at = DateTime.add(DateTime.utc_now(), expires_in, :second)
              {:ok, token, expires_at}

            {:ok, data} ->
              Logger.error("Unexpected Azure token response: #{inspect(Map.keys(data))}")
              {:error, :unexpected_response}

            {:error, _} ->
              {:error, :parse_error}
          end

        {:ok, %{status: status, body: resp_body}} ->
          Logger.error("Azure OAuth failed (#{status}): #{String.slice(resp_body, 0..300)}")
          {:error, {:auth_error, status}}

        {:error, reason} ->
          Logger.error("Azure OAuth request failed: #{inspect(reason)}")
          {:error, reason}
      end
    end
  end

  defp get_valid_token(subscription) do
    case subscription do
      %{access_token: token, token_expires_at: expires_at}
      when not is_nil(token) and not is_nil(expires_at) ->
        if DateTime.compare(expires_at, DateTime.utc_now()) == :gt do
          {:ok, token}
        else
          case get_access_token(subscription) do
            {:ok, new_token, _} -> {:ok, new_token}
            error -> error
          end
        end

      _ ->
        case get_access_token(subscription) do
          {:ok, new_token, _} -> {:ok, new_token}
          error -> error
        end
    end
  end

  # ---------- Virtual Machines ----------

  defp list_vms(subscription_id, token) do
    cache_key = "vms:#{subscription_id}"

    TamanduaServer.Cache.get_or_fetch(@cache_namespace, cache_key, @cache_ttl, fn ->
      azure_get(
        "/subscriptions/#{subscription_id}/providers/Microsoft.Compute/virtualMachines",
        "2023-09-01",
        token
      )
    end)
  end

  # ---------- Storage Accounts ----------

  defp list_storage_accounts(subscription_id, token) do
    cache_key = "storage_accounts:#{subscription_id}"

    TamanduaServer.Cache.get_or_fetch(@cache_namespace, cache_key, @cache_ttl, fn ->
      azure_get(
        "/subscriptions/#{subscription_id}/providers/Microsoft.Storage/storageAccounts",
        "2023-01-01",
        token
      )
    end)
  end

  # ---------- Network Security Groups ----------

  defp list_nsgs(subscription_id, token) do
    cache_key = "nsgs:#{subscription_id}"

    TamanduaServer.Cache.get_or_fetch(@cache_namespace, cache_key, @cache_ttl, fn ->
      azure_get(
        "/subscriptions/#{subscription_id}/providers/Microsoft.Network/networkSecurityGroups",
        "2023-09-01",
        token
      )
    end)
  end

  # ---------- Key Vaults ----------

  defp list_key_vaults(subscription_id, token) do
    cache_key = "key_vaults:#{subscription_id}"

    TamanduaServer.Cache.get_or_fetch(@cache_namespace, cache_key, @cache_ttl, fn ->
      azure_get(
        "/subscriptions/#{subscription_id}/providers/Microsoft.KeyVault/vaults",
        "2023-07-01",
        token
      )
    end)
  end

  # ---------- AKS ----------

  defp list_aks_clusters(subscription_id, token) do
    cache_key = "aks_clusters:#{subscription_id}"

    TamanduaServer.Cache.get_or_fetch(@cache_namespace, cache_key, @cache_ttl, fn ->
      azure_get(
        "/subscriptions/#{subscription_id}/providers/Microsoft.ContainerService/managedClusters",
        "2023-10-01",
        token
      )
    end)
  end

  # ---------- SQL Servers ----------

  defp list_sql_servers(subscription_id, token) do
    cache_key = "sql_servers:#{subscription_id}"

    TamanduaServer.Cache.get_or_fetch(@cache_namespace, cache_key, @cache_ttl, fn ->
      azure_get(
        "/subscriptions/#{subscription_id}/providers/Microsoft.Sql/servers",
        "2023-05-01-preview",
        token
      )
    end)
  end

  defp get_sql_auditing(subscription_id, server, token) do
    server_name = server["name"]
    rg = extract_resource_group(server["id"])

    path =
      "/subscriptions/#{subscription_id}/resourceGroups/#{rg}/providers/Microsoft.Sql/servers/#{server_name}/auditingSettings/default"

    case azure_get_raw(path, "2023-05-01-preview", token) do
      {:ok, %{"properties" => %{"state" => state}}} ->
        state == "Enabled"

      _ ->
        false
    end
  end

  defp get_sql_tde(subscription_id, server, token) do
    server_name = server["name"]
    rg = extract_resource_group(server["id"])

    path =
      "/subscriptions/#{subscription_id}/resourceGroups/#{rg}/providers/Microsoft.Sql/servers/#{server_name}/encryptionProtector"

    case azure_get_raw_list(path, "2023-05-01-preview", token) do
      {:ok, protectors} ->
        Enum.any?(protectors, fn p ->
          get_in(p, ["properties", "serverKeyType"]) == "AzureKeyVault"
        end)

      _ ->
        false
    end
  end

  # ---------- App Services ----------

  defp list_web_apps(subscription_id, token) do
    cache_key = "web_apps:#{subscription_id}"

    TamanduaServer.Cache.get_or_fetch(@cache_namespace, cache_key, @cache_ttl, fn ->
      azure_get(
        "/subscriptions/#{subscription_id}/providers/Microsoft.Web/sites",
        "2023-01-01",
        token
      )
    end)
  end

  # ---------- RBAC ----------

  defp list_role_assignments(subscription_id, token) do
    cache_key = "role_assignments:#{subscription_id}"

    TamanduaServer.Cache.get_or_fetch(@cache_namespace, cache_key, @cache_ttl, fn ->
      azure_get(
        "/subscriptions/#{subscription_id}/providers/Microsoft.Authorization/roleAssignments",
        "2022-04-01",
        token
      )
    end)
  end

  # ---------- Diagnostic Settings ----------

  defp get_diagnostic_settings(subscription_id, token) do
    cache_key = "diagnostic_settings:#{subscription_id}"

    TamanduaServer.Cache.get_or_fetch(@cache_namespace, cache_key, @cache_ttl, fn ->
      azure_get(
        "/subscriptions/#{subscription_id}/providers/Microsoft.Insights/diagnosticSettings",
        "2021-05-01-preview",
        token
      )
    end)
  end

  # ============================================================================
  # Azure HTTP Helpers
  # ============================================================================

  defp azure_get(path, api_version, token) do
    url = "#{@azure_management_api}#{path}?api-version=#{api_version}"

    Logger.debug("Azure GET: #{path}")

    headers = [
      {"Authorization", "Bearer #{token}"},
      {"Content-Type", "application/json"}
    ]

    case finch_request(:get, url, headers, "") do
      {:ok, %{status: 200, body: resp_body}} ->
        case Jason.decode(resp_body) do
          {:ok, %{"value" => items}} when is_list(items) ->
            {:ok, items}

          {:ok, %{"value" => _}} ->
            {:ok, []}

          {:ok, data} when is_map(data) ->
            # Some endpoints return a single object
            {:ok, [data]}

          _ ->
            {:error, :parse_error}
        end

      {:ok, %{status: 401}} ->
        {:error, :unauthorized}

      {:ok, %{status: 403}} ->
        {:error, :forbidden}

      {:ok, %{status: 404}} ->
        {:ok, []}

      {:ok, %{status: 429, body: resp_body}} ->
        retry_after = extract_retry_after(resp_body)
        Logger.warning("Azure rate limited, retry after: #{retry_after}s")
        {:error, {:rate_limited, retry_after}}

      {:ok, %{status: status, body: resp_body}} ->
        Logger.warning("Azure API failed (#{status}): #{String.slice(resp_body, 0..200)}")
        {:error, {:api_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp azure_get_raw(path, api_version, token) do
    url = "#{@azure_management_api}#{path}?api-version=#{api_version}"

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

  defp azure_get_raw_list(path, api_version, token) do
    case azure_get(path, api_version, token) do
      {:ok, items} -> {:ok, items}
      error -> error
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

  defp extract_retry_after(body) do
    case Jason.decode(body) do
      {:ok, %{"error" => %{"retryAfterSeconds" => seconds}}} when is_integer(seconds) ->
        seconds

      _ ->
        60
    end
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  defp ensure_tables do
    tables = [@subscriptions_table, @resources_table]

    Enum.each(tables, fn table ->
      case :ets.whereis(table) do
        :undefined -> :ets.new(table, [:set, :public, :named_table])
        _ -> :ok
      end
    end)
  end

  defp validate_subscription(subscription) do
    cond do
      is_nil(subscription.subscription_id) ->
        {:error, "Subscription ID is required"}

      is_nil(subscription.tenant_id) ->
        {:error, "Tenant ID is required"}

      is_nil(subscription.client_id) ->
        {:error, "Client ID is required"}

      is_nil(subscription.client_secret) ->
        {:error, "Client secret is required"}

      true ->
        :ok
    end
  end

  defp sanitize_subscription(subscription) do
    Map.drop(subscription, [:client_secret, :access_token])
  end

  defp extract_resource_group(resource_id) do
    case Regex.run(~r/resourceGroups\/([^\/]+)/i, resource_id || "") do
      [_, group] -> group
      _ -> "unknown"
    end
  end

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
    |> maybe_filter(:location, filters[:location])
    |> maybe_filter(:resource_group, filters[:resource_group])
  end

  defp maybe_filter(list, _field, nil), do: list

  defp maybe_filter(list, field, value) do
    Enum.filter(list, fn r -> Map.get(r, field) == value end)
  end
end
