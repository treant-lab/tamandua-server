defmodule TamanduaServer.Cloud.AWS do
  @moduledoc """
  AWS Cloud Security Posture Management (CSPM) integration.

  Provides comprehensive security scanning and assessment of AWS resources
  including EC2, S3, IAM, RDS, Lambda, VPC, and CloudTrail.

  ## Features
  - AssumeRole for cross-account access
  - Security group analysis
  - S3 bucket policy analysis
  - IAM policy analysis
  - Resource inventory collection
  """

  require Logger
  alias TamanduaServer.Cloud.Finding

  @type account :: %{
          account_id: String.t(),
          account_alias: String.t() | nil,
          role_arn: String.t(),
          external_id: String.t() | nil,
          regions: [String.t()],
          status: :connected | :disconnected | :error,
          last_scan: DateTime.t() | nil,
          credentials: map() | nil
        }

  @type resource :: %{
          id: String.t(),
          arn: String.t(),
          type: String.t(),
          name: String.t(),
          region: String.t(),
          account_id: String.t(),
          tags: map(),
          metadata: map(),
          created_at: DateTime.t() | nil
        }

  # ETS tables for AWS data
  @accounts_table :aws_accounts
  @resources_table :aws_resources
  @credentials_cache :aws_credentials_cache

  @default_regions [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-west-1",
    "eu-west-2",
    "eu-central-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1"
  ]

  # ============================================================================
  # Account Management
  # ============================================================================

  @doc """
  Add a new AWS account for CSPM scanning.
  """
  @spec add_account(map()) :: {:ok, account()} | {:error, term()}
  def add_account(params) do
    ensure_tables()

    account = %{
      account_id: params["account_id"] || params[:account_id],
      account_alias: params["account_alias"] || params[:account_alias],
      role_arn: params["role_arn"] || params[:role_arn],
      external_id: params["external_id"] || params[:external_id],
      regions: params["regions"] || params[:regions] || @default_regions,
      status: :disconnected,
      last_scan: nil,
      credentials: nil,
      added_at: DateTime.utc_now()
    }

    # Validate role ARN format
    case validate_role_arn(account.role_arn) do
      :ok ->
        :ets.insert(@accounts_table, {account.account_id, account})
        Logger.info("Added AWS account: #{account.account_id}")

        # Test connection
        case assume_role(account) do
          {:ok, creds} ->
            updated = %{account | status: :connected, credentials: creds}
            :ets.insert(@accounts_table, {account.account_id, updated})
            {:ok, updated}

          {:error, reason} ->
            Logger.warning("AWS account #{account.account_id} connection test failed: #{inspect(reason)}")
            {:ok, account}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Remove an AWS account from CSPM scanning.
  """
  @spec remove_account(String.t()) :: :ok | {:error, :not_found}
  def remove_account(account_id) do
    ensure_tables()

    case :ets.lookup(@accounts_table, account_id) do
      [{^account_id, _}] ->
        :ets.delete(@accounts_table, account_id)
        # Clean up resources for this account
        :ets.match_delete(@resources_table, {:_, %{account_id: account_id}})
        :ok

      [] ->
        {:error, :not_found}
    end
  end

  @doc """
  List all configured AWS accounts.
  """
  @spec list_accounts() :: [account()]
  def list_accounts do
    ensure_tables()

    :ets.tab2list(@accounts_table)
    |> Enum.map(fn {_id, account} -> sanitize_account(account) end)
  end

  @doc """
  Get a specific AWS account.
  """
  @spec get_account(String.t()) :: {:ok, account()} | {:error, :not_found}
  def get_account(account_id) do
    ensure_tables()

    case :ets.lookup(@accounts_table, account_id) do
      [{^account_id, account}] -> {:ok, sanitize_account(account)}
      [] -> {:error, :not_found}
    end
  end

  # ============================================================================
  # Resource Scanning
  # ============================================================================

  @doc """
  Scan all resources for an AWS account.
  """
  @spec scan_account(String.t()) :: {:ok, %{resources: integer(), findings: integer()}} | {:error, term()}
  def scan_account(account_id) do
    ensure_tables()

    case :ets.lookup(@accounts_table, account_id) do
      [{^account_id, account}] ->
        case get_credentials(account) do
          {:ok, creds} ->
            Logger.info("Starting AWS scan for account: #{account_id}")

            # Scan all resource types in parallel
            tasks = [
              Task.async(fn -> scan_ec2_instances(account, creds) end),
              Task.async(fn -> scan_security_groups(account, creds) end),
              Task.async(fn -> scan_s3_buckets(account, creds) end),
              Task.async(fn -> scan_iam_users(account, creds) end),
              Task.async(fn -> scan_iam_roles(account, creds) end),
              Task.async(fn -> scan_iam_policies(account, creds) end),
              Task.async(fn -> scan_rds_instances(account, creds) end),
              Task.async(fn -> scan_lambda_functions(account, creds) end),
              Task.async(fn -> scan_vpcs(account, creds) end),
              Task.async(fn -> scan_cloudtrail(account, creds) end)
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

            # Update account last scan time
            updated = %{account | last_scan: DateTime.utc_now(), status: :connected}
            :ets.insert(@accounts_table, {account_id, updated})

            Logger.info("AWS scan complete for #{account_id}: #{total_resources} resources, #{total_findings} findings")
            {:ok, %{resources: total_resources, findings: total_findings}}

          {:error, reason} ->
            updated = %{account | status: :error}
            :ets.insert(@accounts_table, {account_id, updated})
            {:error, reason}
        end

      [] ->
        {:error, :account_not_found}
    end
  end

  @doc """
  List all resources for an account with optional filters.
  """
  @spec list_resources(String.t(), map()) :: [resource()]
  def list_resources(account_id, filters \\ %{}) do
    ensure_tables()

    :ets.tab2list(@resources_table)
    |> Enum.map(fn {_id, resource} -> resource end)
    |> Enum.filter(fn r -> r.account_id == account_id end)
    |> apply_resource_filters(filters)
  end

  # ============================================================================
  # EC2 Scanning
  # ============================================================================

  defp scan_ec2_instances(account, creds) do
    resources = []
    findings = []

    for region <- account.regions, reduce: {resources, findings} do
      {acc_resources, acc_findings} ->
        case describe_ec2_instances(region, creds) do
          {:ok, instances} ->
            new_resources =
              Enum.map(instances, fn instance ->
                resource = %{
                  id: instance["InstanceId"],
                  arn: "arn:aws:ec2:#{region}:#{account.account_id}:instance/#{instance["InstanceId"]}",
                  type: "aws_ec2_instance",
                  name: get_tag_value(instance["Tags"], "Name") || instance["InstanceId"],
                  region: region,
                  account_id: account.account_id,
                  tags: parse_tags(instance["Tags"]),
                  metadata: %{
                    instance_type: instance["InstanceType"],
                    state: instance["State"]["Name"],
                    vpc_id: instance["VpcId"],
                    subnet_id: instance["SubnetId"],
                    public_ip: instance["PublicIpAddress"],
                    private_ip: instance["PrivateIpAddress"],
                    iam_profile: instance["IamInstanceProfile"]["Arn"],
                    security_groups: Enum.map(instance["SecurityGroups"] || [], & &1["GroupId"])
                  },
                  created_at: parse_datetime(instance["LaunchTime"])
                }

                :ets.insert(@resources_table, {resource.id, resource})
                resource
              end)

            new_findings = analyze_ec2_instances(new_resources, account.account_id)
            {acc_resources ++ new_resources, acc_findings ++ new_findings}

          {:error, reason} ->
            Logger.warning("Failed to scan EC2 in #{region}: #{inspect(reason)}")
            {acc_resources, acc_findings}
        end
    end

    {:ok, %{count: length(resources), findings: findings}}
  end

  defp analyze_ec2_instances(instances, account_id) do
    Enum.flat_map(instances, fn instance ->
      findings = []

      # Check for public IP
      findings =
        if instance.metadata.public_ip do
          [
            Finding.create(%{
              provider: "aws",
              account_id: account_id,
              resource_id: instance.id,
              resource_arn: instance.arn,
              resource_name: instance.name,
              resource_type: "EC2 Instance",
              region: instance.region,
              category: "network_security",
              severity: "medium",
              title: "EC2 instance has public IP address",
              description: "Instance #{instance.name} has a public IP address (#{instance.metadata.public_ip}). Consider using a NAT gateway or bastion host.",
              recommendation: "Use a NAT gateway for outbound traffic or a bastion host for SSH access. Remove public IP if not required.",
              compliance: ["CIS AWS 5.1"],
              remediation_terraform: """
              resource "aws_instance" "example" {
                associate_public_ip_address = false
              }
              """
            })
            | findings
          ]
        else
          findings
        end

      # Check for missing IAM profile
      findings =
        if is_nil(instance.metadata.iam_profile) do
          [
            Finding.create(%{
              provider: "aws",
              account_id: account_id,
              resource_id: instance.id,
              resource_arn: instance.arn,
              resource_name: instance.name,
              resource_type: "EC2 Instance",
              region: instance.region,
              category: "identity_and_access",
              severity: "low",
              title: "EC2 instance missing IAM instance profile",
              description: "Instance #{instance.name} does not have an IAM instance profile. This may indicate use of long-term credentials.",
              recommendation: "Attach an IAM instance profile with minimal required permissions.",
              compliance: ["CIS AWS 1.20"]
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
  # Security Groups Scanning
  # ============================================================================

  defp scan_security_groups(account, creds) do
    resources = []
    findings = []

    for region <- account.regions, reduce: {resources, findings} do
      {acc_resources, acc_findings} ->
        case describe_security_groups(region, creds) do
          {:ok, security_groups} ->
            new_resources =
              Enum.map(security_groups, fn sg ->
                resource = %{
                  id: sg["GroupId"],
                  arn: "arn:aws:ec2:#{region}:#{account.account_id}:security-group/#{sg["GroupId"]}",
                  type: "aws_security_group",
                  name: sg["GroupName"],
                  region: region,
                  account_id: account.account_id,
                  tags: parse_tags(sg["Tags"]),
                  metadata: %{
                    description: sg["Description"],
                    vpc_id: sg["VpcId"],
                    ingress_rules: sg["IpPermissions"],
                    egress_rules: sg["IpPermissionsEgress"]
                  },
                  created_at: nil
                }

                :ets.insert(@resources_table, {resource.id, resource})
                resource
              end)

            new_findings = analyze_security_groups(new_resources, account.account_id)
            {acc_resources ++ new_resources, acc_findings ++ new_findings}

          {:error, reason} ->
            Logger.warning("Failed to scan Security Groups in #{region}: #{inspect(reason)}")
            {acc_resources, acc_findings}
        end
    end

    {:ok, %{count: length(resources), findings: findings}}
  end

  defp analyze_security_groups(security_groups, account_id) do
    Enum.flat_map(security_groups, fn sg ->
      findings = []

      # Check for unrestricted SSH
      findings =
        findings ++
          check_unrestricted_port(sg, 22, "SSH", account_id)

      # Check for unrestricted RDP
      findings =
        findings ++
          check_unrestricted_port(sg, 3389, "RDP", account_id)

      # Check for unrestricted all traffic
      findings =
        findings ++
          check_unrestricted_all_traffic(sg, account_id)

      findings
    end)
  end

  defp check_unrestricted_port(sg, port, service, account_id) do
    ingress_rules = sg.metadata.ingress_rules || []

    unrestricted =
      Enum.any?(ingress_rules, fn rule ->
        from_port = rule["FromPort"]
        to_port = rule["ToPort"]
        ip_ranges = rule["IpRanges"] || []

        port_match = (from_port == port and to_port == port) or (from_port <= port and to_port >= port)

        open_to_world =
          Enum.any?(ip_ranges, fn range ->
            range["CidrIp"] == "0.0.0.0/0" or range["CidrIp"] == "::/0"
          end)

        port_match and open_to_world
      end)

    if unrestricted do
      [
        Finding.create(%{
          provider: "aws",
          account_id: account_id,
          resource_id: sg.id,
          resource_arn: sg.arn,
          resource_name: sg.name,
          resource_type: "Security Group",
          region: sg.region,
          category: "network_security",
          severity: "critical",
          title: "Security group allows unrestricted #{service} access",
          description: "Security group #{sg.name} (#{sg.id}) allows inbound #{service} traffic (port #{port}) from 0.0.0.0/0.",
          recommendation: "Restrict #{service} access to specific IP ranges or use a bastion host.",
          compliance: ["CIS AWS 5.2", "CIS AWS 5.3", "PCI DSS 1.3.1"],
          remediation_terraform: """
          resource "aws_security_group_rule" "#{String.downcase(service)}" {
            type              = "ingress"
            from_port         = #{port}
            to_port           = #{port}
            protocol          = "tcp"
            cidr_blocks       = ["10.0.0.0/8"]  # Restrict to internal network
            security_group_id = "#{sg.id}"
          }
          """
        })
      ]
    else
      []
    end
  end

  defp check_unrestricted_all_traffic(sg, account_id) do
    ingress_rules = sg.metadata.ingress_rules || []

    unrestricted =
      Enum.any?(ingress_rules, fn rule ->
        ip_protocol = rule["IpProtocol"]
        ip_ranges = rule["IpRanges"] || []

        all_traffic = ip_protocol == "-1"

        open_to_world =
          Enum.any?(ip_ranges, fn range ->
            range["CidrIp"] == "0.0.0.0/0" or range["CidrIp"] == "::/0"
          end)

        all_traffic and open_to_world
      end)

    if unrestricted do
      [
        Finding.create(%{
          provider: "aws",
          account_id: account_id,
          resource_id: sg.id,
          resource_arn: sg.arn,
          resource_name: sg.name,
          resource_type: "Security Group",
          region: sg.region,
          category: "network_security",
          severity: "critical",
          title: "Security group allows all inbound traffic from the internet",
          description: "Security group #{sg.name} (#{sg.id}) allows all inbound traffic from 0.0.0.0/0.",
          recommendation: "Remove the rule allowing all traffic from 0.0.0.0/0. Implement least-privilege access.",
          compliance: ["CIS AWS 5.4", "PCI DSS 1.2.1"]
        })
      ]
    else
      []
    end
  end

  # ============================================================================
  # S3 Bucket Scanning
  # ============================================================================

  defp scan_s3_buckets(account, creds) do
    # S3 is global, only scan once
    case list_s3_buckets(creds) do
      {:ok, buckets} ->
        resources =
          Enum.map(buckets, fn bucket ->
            bucket_name = bucket["Name"]

            # Get bucket details
            acl = get_bucket_acl(bucket_name, creds)
            policy = get_bucket_policy(bucket_name, creds)
            encryption = get_bucket_encryption(bucket_name, creds)
            versioning = get_bucket_versioning(bucket_name, creds)
            logging = get_bucket_logging(bucket_name, creds)
            public_access_block = get_public_access_block(bucket_name, creds)

            resource = %{
              id: bucket_name,
              arn: "arn:aws:s3:::#{bucket_name}",
              type: "aws_s3_bucket",
              name: bucket_name,
              region: "global",
              account_id: account.account_id,
              tags: get_bucket_tags(bucket_name, creds),
              metadata: %{
                acl: acl,
                policy: policy,
                encryption: encryption,
                versioning: versioning,
                logging: logging,
                public_access_block: public_access_block
              },
              created_at: parse_datetime(bucket["CreationDate"])
            }

            :ets.insert(@resources_table, {resource.id, resource})
            resource
          end)

        findings = analyze_s3_buckets(resources, account.account_id)
        {:ok, %{count: length(resources), findings: findings}}

      {:error, reason} ->
        Logger.warning("Failed to scan S3 buckets: #{inspect(reason)}")
        {:ok, %{count: 0, findings: []}}
    end
  end

  defp analyze_s3_buckets(buckets, account_id) do
    Enum.flat_map(buckets, fn bucket ->
      findings = []

      # Check for public access
      findings =
        if bucket_is_public?(bucket) do
          [
            Finding.create(%{
              provider: "aws",
              account_id: account_id,
              resource_id: bucket.id,
              resource_arn: bucket.arn,
              resource_name: bucket.name,
              resource_type: "S3 Bucket",
              region: bucket.region,
              category: "data_protection",
              severity: "critical",
              title: "S3 bucket is publicly accessible",
              description: "Bucket #{bucket.name} allows public access. This may expose sensitive data.",
              recommendation: "Enable S3 Block Public Access settings and review bucket policy.",
              compliance: ["CIS AWS 2.1.1", "CIS AWS 2.1.2", "PCI DSS 7.1", "HIPAA 164.312(a)(1)"],
              remediation_terraform: """
              resource "aws_s3_bucket_public_access_block" "#{bucket.name}" {
                bucket = "#{bucket.name}"

                block_public_acls       = true
                block_public_policy     = true
                ignore_public_acls      = true
                restrict_public_buckets = true
              }
              """
            })
            | findings
          ]
        else
          findings
        end

      # Check for encryption
      findings =
        if not bucket_has_encryption?(bucket) do
          [
            Finding.create(%{
              provider: "aws",
              account_id: account_id,
              resource_id: bucket.id,
              resource_arn: bucket.arn,
              resource_name: bucket.name,
              resource_type: "S3 Bucket",
              region: bucket.region,
              category: "data_protection",
              severity: "high",
              title: "S3 bucket does not have default encryption enabled",
              description: "Bucket #{bucket.name} does not have server-side encryption enabled by default.",
              recommendation: "Enable default encryption using SSE-S3 or SSE-KMS.",
              compliance: ["CIS AWS 2.1.1", "PCI DSS 3.4", "HIPAA 164.312(a)(2)(iv)"],
              remediation_terraform: """
              resource "aws_s3_bucket_server_side_encryption_configuration" "#{bucket.name}" {
                bucket = "#{bucket.name}"

                rule {
                  apply_server_side_encryption_by_default {
                    sse_algorithm = "AES256"
                  }
                }
              }
              """
            })
            | findings
          ]
        else
          findings
        end

      # Check for versioning
      findings =
        if not bucket_has_versioning?(bucket) do
          [
            Finding.create(%{
              provider: "aws",
              account_id: account_id,
              resource_id: bucket.id,
              resource_arn: bucket.arn,
              resource_name: bucket.name,
              resource_type: "S3 Bucket",
              region: bucket.region,
              category: "data_protection",
              severity: "medium",
              title: "S3 bucket versioning not enabled",
              description: "Bucket #{bucket.name} does not have versioning enabled. This may result in data loss.",
              recommendation: "Enable versioning to protect against accidental deletion and overwrites.",
              compliance: ["CIS AWS 2.1.3"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for logging
      findings =
        if not bucket_has_logging?(bucket) do
          [
            Finding.create(%{
              provider: "aws",
              account_id: account_id,
              resource_id: bucket.id,
              resource_arn: bucket.arn,
              resource_name: bucket.name,
              resource_type: "S3 Bucket",
              region: bucket.region,
              category: "logging_monitoring",
              severity: "medium",
              title: "S3 bucket access logging not enabled",
              description: "Bucket #{bucket.name} does not have server access logging enabled.",
              recommendation: "Enable access logging to track requests made to the bucket.",
              compliance: ["CIS AWS 2.6", "PCI DSS 10.2"]
            })
            | findings
          ]
        else
          findings
        end

      findings
    end)
  end

  defp bucket_is_public?(bucket) do
    public_access_block = bucket.metadata.public_access_block

    # If public access block is not configured or allows public access
    if is_nil(public_access_block) do
      # Check ACL and policy
      acl_public?(bucket.metadata.acl) or policy_public?(bucket.metadata.policy)
    else
      not (public_access_block["BlockPublicAcls"] and
             public_access_block["BlockPublicPolicy"] and
             public_access_block["IgnorePublicAcls"] and
             public_access_block["RestrictPublicBuckets"])
    end
  end

  defp acl_public?(nil), do: false

  defp acl_public?(acl) do
    grants = acl["Grants"] || []

    Enum.any?(grants, fn grant ->
      grantee = grant["Grantee"] || %{}
      uri = grantee["URI"]
      uri == "http://acs.amazonaws.com/groups/global/AllUsers" or
        uri == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
    end)
  end

  defp policy_public?(nil), do: false

  defp policy_public?(policy) do
    case Jason.decode(policy) do
      {:ok, parsed} ->
        statements = parsed["Statement"] || []

        Enum.any?(statements, fn stmt ->
          effect = stmt["Effect"]
          principal = stmt["Principal"]

          effect == "Allow" and (principal == "*" or principal == %{"AWS" => "*"})
        end)

      _ ->
        false
    end
  end

  defp bucket_has_encryption?(bucket) do
    encryption = bucket.metadata.encryption
    not is_nil(encryption) and not is_nil(encryption["Rules"])
  end

  defp bucket_has_versioning?(bucket) do
    versioning = bucket.metadata.versioning
    not is_nil(versioning) and versioning["Status"] == "Enabled"
  end

  defp bucket_has_logging?(bucket) do
    logging = bucket.metadata.logging
    not is_nil(logging) and not is_nil(logging["LoggingEnabled"])
  end

  # ============================================================================
  # IAM Scanning
  # ============================================================================

  defp scan_iam_users(account, creds) do
    case list_iam_users(creds) do
      {:ok, users} ->
        resources =
          Enum.map(users, fn user ->
            # Get user details
            access_keys = list_access_keys(user["UserName"], creds)
            mfa_devices = list_mfa_devices(user["UserName"], creds)
            login_profile = get_login_profile(user["UserName"], creds)
            attached_policies = list_attached_user_policies(user["UserName"], creds)

            resource = %{
              id: user["UserId"],
              arn: user["Arn"],
              type: "aws_iam_user",
              name: user["UserName"],
              region: "global",
              account_id: account.account_id,
              tags: parse_tags(user["Tags"]),
              metadata: %{
                access_keys: access_keys,
                mfa_devices: mfa_devices,
                has_console_access: not is_nil(login_profile),
                password_last_used: user["PasswordLastUsed"],
                attached_policies: attached_policies
              },
              created_at: parse_datetime(user["CreateDate"])
            }

            :ets.insert(@resources_table, {resource.id, resource})
            resource
          end)

        findings = analyze_iam_users(resources, account.account_id)
        {:ok, %{count: length(resources), findings: findings}}

      {:error, reason} ->
        Logger.warning("Failed to scan IAM users: #{inspect(reason)}")
        {:ok, %{count: 0, findings: []}}
    end
  end

  defp analyze_iam_users(users, account_id) do
    Enum.flat_map(users, fn user ->
      findings = []

      # Check for MFA
      findings =
        if user.metadata.has_console_access and Enum.empty?(user.metadata.mfa_devices || []) do
          [
            Finding.create(%{
              provider: "aws",
              account_id: account_id,
              resource_id: user.id,
              resource_arn: user.arn,
              resource_name: user.name,
              resource_type: "IAM User",
              region: "global",
              category: "identity_and_access",
              severity: "high",
              title: "IAM user without MFA",
              description: "IAM user #{user.name} has console access but MFA is not enabled.",
              recommendation: "Enable MFA for all IAM users with console access.",
              compliance: ["CIS AWS 1.10", "CIS AWS 1.14", "PCI DSS 8.3"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for old access keys
      findings =
        findings ++
          check_old_access_keys(user, account_id)

      # Check for inactive users
      findings =
        findings ++
          check_inactive_user(user, account_id)

      findings
    end)
  end

  defp check_old_access_keys(user, account_id) do
    access_keys = user.metadata.access_keys || []
    ninety_days_ago = DateTime.add(DateTime.utc_now(), -90 * 24 * 60 * 60, :second)

    old_keys =
      Enum.filter(access_keys, fn key ->
        case parse_datetime(key["CreateDate"]) do
          nil -> false
          create_date -> DateTime.compare(create_date, ninety_days_ago) == :lt
        end
      end)

    Enum.map(old_keys, fn key ->
      Finding.create(%{
        provider: "aws",
        account_id: account_id,
        resource_id: user.id,
        resource_arn: user.arn,
        resource_name: user.name,
        resource_type: "IAM User",
        region: "global",
        category: "identity_and_access",
        severity: "medium",
        title: "IAM user has access key older than 90 days",
        description: "IAM user #{user.name} has access key #{key["AccessKeyId"]} that is older than 90 days.",
        recommendation: "Rotate access keys regularly (at least every 90 days).",
        compliance: ["CIS AWS 1.4"]
      })
    end)
  end

  defp check_inactive_user(user, account_id) do
    ninety_days_ago = DateTime.add(DateTime.utc_now(), -90 * 24 * 60 * 60, :second)

    last_used = user.metadata.password_last_used

    if user.metadata.has_console_access and not is_nil(last_used) do
      case parse_datetime(last_used) do
        nil ->
          []

        last_used_dt ->
          if DateTime.compare(last_used_dt, ninety_days_ago) == :lt do
            [
              Finding.create(%{
                provider: "aws",
                account_id: account_id,
                resource_id: user.id,
                resource_arn: user.arn,
                resource_name: user.name,
                resource_type: "IAM User",
                region: "global",
                category: "identity_and_access",
                severity: "medium",
                title: "IAM user inactive for 90+ days",
                description: "IAM user #{user.name} has not used their password in over 90 days.",
                recommendation: "Disable or remove inactive IAM users.",
                compliance: ["CIS AWS 1.12"]
              })
            ]
          else
            []
          end
      end
    else
      []
    end
  end

  defp scan_iam_roles(account, creds) do
    case list_iam_roles(creds) do
      {:ok, roles} ->
        resources =
          Enum.map(roles, fn role ->
            attached_policies = list_attached_role_policies(role["RoleName"], creds)

            resource = %{
              id: role["RoleId"],
              arn: role["Arn"],
              type: "aws_iam_role",
              name: role["RoleName"],
              region: "global",
              account_id: account.account_id,
              tags: parse_tags(role["Tags"]),
              metadata: %{
                assume_role_policy: role["AssumeRolePolicyDocument"],
                attached_policies: attached_policies,
                max_session_duration: role["MaxSessionDuration"]
              },
              created_at: parse_datetime(role["CreateDate"])
            }

            :ets.insert(@resources_table, {resource.id, resource})
            resource
          end)

        findings = analyze_iam_roles(resources, account.account_id)
        {:ok, %{count: length(resources), findings: findings}}

      {:error, reason} ->
        Logger.warning("Failed to scan IAM roles: #{inspect(reason)}")
        {:ok, %{count: 0, findings: []}}
    end
  end

  defp analyze_iam_roles(roles, account_id) do
    Enum.flat_map(roles, fn role ->
      # Check for overly permissive trust relationships
      check_trust_policy(role, account_id)
    end)
  end

  defp check_trust_policy(role, account_id) do
    trust_policy = role.metadata.assume_role_policy

    case decode_policy(trust_policy) do
      {:ok, policy} ->
        statements = policy["Statement"] || []

        overly_permissive =
          Enum.any?(statements, fn stmt ->
            principal = stmt["Principal"]
            principal == "*" or principal == %{"AWS" => "*"}
          end)

        if overly_permissive do
          [
            Finding.create(%{
              provider: "aws",
              account_id: account_id,
              resource_id: role.id,
              resource_arn: role.arn,
              resource_name: role.name,
              resource_type: "IAM Role",
              region: "global",
              category: "identity_and_access",
              severity: "critical",
              title: "IAM role has overly permissive trust policy",
              description: "IAM role #{role.name} allows any AWS principal to assume it.",
              recommendation: "Restrict the trust policy to specific AWS accounts or principals.",
              compliance: ["CIS AWS 1.16"]
            })
          ]
        else
          []
        end

      _ ->
        []
    end
  end

  defp scan_iam_policies(account, creds) do
    case list_iam_policies(creds) do
      {:ok, policies} ->
        # Only scan customer-managed policies
        customer_policies = Enum.filter(policies, fn p -> p["Arn"] =~ account.account_id end)

        resources =
          Enum.map(customer_policies, fn policy ->
            policy_version = get_policy_version(policy["Arn"], policy["DefaultVersionId"], creds)

            resource = %{
              id: policy["PolicyId"],
              arn: policy["Arn"],
              type: "aws_iam_policy",
              name: policy["PolicyName"],
              region: "global",
              account_id: account.account_id,
              tags: [],
              metadata: %{
                policy_document: policy_version,
                attachment_count: policy["AttachmentCount"]
              },
              created_at: parse_datetime(policy["CreateDate"])
            }

            :ets.insert(@resources_table, {resource.id, resource})
            resource
          end)

        findings = analyze_iam_policies(resources, account.account_id)
        {:ok, %{count: length(resources), findings: findings}}

      {:error, reason} ->
        Logger.warning("Failed to scan IAM policies: #{inspect(reason)}")
        {:ok, %{count: 0, findings: []}}
    end
  end

  defp analyze_iam_policies(policies, account_id) do
    Enum.flat_map(policies, fn policy ->
      check_admin_policy(policy, account_id)
    end)
  end

  defp check_admin_policy(policy, account_id) do
    policy_doc = policy.metadata.policy_document

    case decode_policy(policy_doc) do
      {:ok, doc} ->
        statements = doc["Statement"] || []

        has_admin =
          Enum.any?(statements, fn stmt ->
            effect = stmt["Effect"]
            action = stmt["Action"]
            resource = stmt["Resource"]

            effect == "Allow" and
              (action == "*" or action == ["*"]) and
              (resource == "*" or resource == ["*"])
          end)

        if has_admin do
          [
            Finding.create(%{
              provider: "aws",
              account_id: account_id,
              resource_id: policy.id,
              resource_arn: policy.arn,
              resource_name: policy.name,
              resource_type: "IAM Policy",
              region: "global",
              category: "identity_and_access",
              severity: "high",
              title: "IAM policy grants full administrative privileges",
              description: "IAM policy #{policy.name} grants Action:* on Resource:* (full admin access).",
              recommendation: "Follow the principle of least privilege. Remove admin access and grant only required permissions.",
              compliance: ["CIS AWS 1.22", "PCI DSS 7.1.2"]
            })
          ]
        else
          []
        end

      _ ->
        []
    end
  end

  # ============================================================================
  # RDS Scanning
  # ============================================================================

  defp scan_rds_instances(account, creds) do
    resources = []
    findings = []

    for region <- account.regions, reduce: {resources, findings} do
      {acc_resources, acc_findings} ->
        case describe_rds_instances(region, creds) do
          {:ok, instances} ->
            new_resources =
              Enum.map(instances, fn instance ->
                resource = %{
                  id: instance["DBInstanceIdentifier"],
                  arn: instance["DBInstanceArn"],
                  type: "aws_rds_instance",
                  name: instance["DBInstanceIdentifier"],
                  region: region,
                  account_id: account.account_id,
                  tags: parse_tags(instance["TagList"]),
                  metadata: %{
                    engine: instance["Engine"],
                    engine_version: instance["EngineVersion"],
                    instance_class: instance["DBInstanceClass"],
                    publicly_accessible: instance["PubliclyAccessible"],
                    storage_encrypted: instance["StorageEncrypted"],
                    multi_az: instance["MultiAZ"],
                    backup_retention_period: instance["BackupRetentionPeriod"],
                    vpc_security_groups: instance["VpcSecurityGroups"]
                  },
                  created_at: parse_datetime(instance["InstanceCreateTime"])
                }

                :ets.insert(@resources_table, {resource.id, resource})
                resource
              end)

            new_findings = analyze_rds_instances(new_resources, account.account_id)
            {acc_resources ++ new_resources, acc_findings ++ new_findings}

          {:error, reason} ->
            Logger.warning("Failed to scan RDS in #{region}: #{inspect(reason)}")
            {acc_resources, acc_findings}
        end
    end

    {:ok, %{count: length(resources), findings: findings}}
  end

  defp analyze_rds_instances(instances, account_id) do
    Enum.flat_map(instances, fn instance ->
      findings = []

      # Check for public accessibility
      findings =
        if instance.metadata.publicly_accessible do
          [
            Finding.create(%{
              provider: "aws",
              account_id: account_id,
              resource_id: instance.id,
              resource_arn: instance.arn,
              resource_name: instance.name,
              resource_type: "RDS Instance",
              region: instance.region,
              category: "network_security",
              severity: "critical",
              title: "RDS instance is publicly accessible",
              description: "RDS instance #{instance.name} is configured with PubliclyAccessible=true.",
              recommendation: "Disable public accessibility and access via private subnets only.",
              compliance: ["CIS AWS 4.1", "PCI DSS 1.3.1"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for encryption
      findings =
        if not instance.metadata.storage_encrypted do
          [
            Finding.create(%{
              provider: "aws",
              account_id: account_id,
              resource_id: instance.id,
              resource_arn: instance.arn,
              resource_name: instance.name,
              resource_type: "RDS Instance",
              region: instance.region,
              category: "data_protection",
              severity: "high",
              title: "RDS instance storage is not encrypted",
              description: "RDS instance #{instance.name} does not have storage encryption enabled.",
              recommendation: "Enable encryption at rest for the RDS instance.",
              compliance: ["CIS AWS 4.3", "PCI DSS 3.4", "HIPAA 164.312(a)(2)(iv)"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for backup retention
      findings =
        if instance.metadata.backup_retention_period == 0 do
          [
            Finding.create(%{
              provider: "aws",
              account_id: account_id,
              resource_id: instance.id,
              resource_arn: instance.arn,
              resource_name: instance.name,
              resource_type: "RDS Instance",
              region: instance.region,
              category: "data_protection",
              severity: "high",
              title: "RDS instance has no automated backups",
              description: "RDS instance #{instance.name} has backup retention period set to 0.",
              recommendation: "Enable automated backups with a retention period of at least 7 days.",
              compliance: ["CIS AWS 4.6"]
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
  # Lambda Scanning
  # ============================================================================

  defp scan_lambda_functions(account, creds) do
    resources = []
    findings = []

    for region <- account.regions, reduce: {resources, findings} do
      {acc_resources, acc_findings} ->
        case list_lambda_functions(region, creds) do
          {:ok, functions} ->
            new_resources =
              Enum.map(functions, fn func ->
                resource = %{
                  id: func["FunctionName"],
                  arn: func["FunctionArn"],
                  type: "aws_lambda_function",
                  name: func["FunctionName"],
                  region: region,
                  account_id: account.account_id,
                  tags: func["Tags"] || %{},
                  metadata: %{
                    runtime: func["Runtime"],
                    role: func["Role"],
                    handler: func["Handler"],
                    memory_size: func["MemorySize"],
                    timeout: func["Timeout"],
                    vpc_config: func["VpcConfig"],
                    kms_key_arn: func["KMSKeyArn"]
                  },
                  created_at: parse_datetime(func["LastModified"])
                }

                :ets.insert(@resources_table, {resource.id, resource})
                resource
              end)

            new_findings = analyze_lambda_functions(new_resources, account.account_id)
            {acc_resources ++ new_resources, acc_findings ++ new_findings}

          {:error, reason} ->
            Logger.warning("Failed to scan Lambda in #{region}: #{inspect(reason)}")
            {acc_resources, acc_findings}
        end
    end

    {:ok, %{count: length(resources), findings: findings}}
  end

  defp analyze_lambda_functions(functions, account_id) do
    Enum.flat_map(functions, fn func ->
      findings = []

      # Check for deprecated runtime
      deprecated_runtimes = ["python2.7", "nodejs10.x", "nodejs8.10", "ruby2.5", "dotnetcore2.1"]

      findings =
        if func.metadata.runtime in deprecated_runtimes do
          [
            Finding.create(%{
              provider: "aws",
              account_id: account_id,
              resource_id: func.id,
              resource_arn: func.arn,
              resource_name: func.name,
              resource_type: "Lambda Function",
              region: func.region,
              category: "compute_security",
              severity: "medium",
              title: "Lambda function uses deprecated runtime",
              description: "Lambda function #{func.name} uses deprecated runtime #{func.metadata.runtime}.",
              recommendation: "Upgrade to a supported runtime version.",
              compliance: ["AWS Best Practices"]
            })
            | findings
          ]
        else
          findings
        end

      # Check for missing VPC configuration
      findings =
        if is_nil(func.metadata.vpc_config) or Enum.empty?(func.metadata.vpc_config["SubnetIds"] || []) do
          [
            Finding.create(%{
              provider: "aws",
              account_id: account_id,
              resource_id: func.id,
              resource_arn: func.arn,
              resource_name: func.name,
              resource_type: "Lambda Function",
              region: func.region,
              category: "network_security",
              severity: "low",
              title: "Lambda function not configured with VPC",
              description: "Lambda function #{func.name} is not configured to run within a VPC.",
              recommendation: "Consider configuring VPC access if the function needs to access private resources.",
              compliance: ["AWS Best Practices"]
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

  defp scan_vpcs(account, creds) do
    resources = []
    findings = []

    for region <- account.regions, reduce: {resources, findings} do
      {acc_resources, acc_findings} ->
        case describe_vpcs(region, creds) do
          {:ok, vpcs} ->
            new_resources =
              Enum.map(vpcs, fn vpc ->
                flow_logs = describe_flow_logs(vpc["VpcId"], region, creds)

                resource = %{
                  id: vpc["VpcId"],
                  arn: "arn:aws:ec2:#{region}:#{account.account_id}:vpc/#{vpc["VpcId"]}",
                  type: "aws_vpc",
                  name: get_tag_value(vpc["Tags"], "Name") || vpc["VpcId"],
                  region: region,
                  account_id: account.account_id,
                  tags: parse_tags(vpc["Tags"]),
                  metadata: %{
                    cidr_block: vpc["CidrBlock"],
                    is_default: vpc["IsDefault"],
                    state: vpc["State"],
                    flow_logs: flow_logs
                  },
                  created_at: nil
                }

                :ets.insert(@resources_table, {resource.id, resource})
                resource
              end)

            new_findings = analyze_vpcs(new_resources, account.account_id)
            {acc_resources ++ new_resources, acc_findings ++ new_findings}

          {:error, reason} ->
            Logger.warning("Failed to scan VPCs in #{region}: #{inspect(reason)}")
            {acc_resources, acc_findings}
        end
    end

    {:ok, %{count: length(resources), findings: findings}}
  end

  defp analyze_vpcs(vpcs, account_id) do
    Enum.flat_map(vpcs, fn vpc ->
      findings = []

      # Check for flow logs
      findings =
        if Enum.empty?(vpc.metadata.flow_logs || []) do
          [
            Finding.create(%{
              provider: "aws",
              account_id: account_id,
              resource_id: vpc.id,
              resource_arn: vpc.arn,
              resource_name: vpc.name,
              resource_type: "VPC",
              region: vpc.region,
              category: "logging_monitoring",
              severity: "medium",
              title: "VPC flow logs not enabled",
              description: "VPC #{vpc.name} does not have flow logs enabled.",
              recommendation: "Enable VPC flow logs to capture network traffic information.",
              compliance: ["CIS AWS 3.9", "PCI DSS 10.2"]
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
  # CloudTrail Scanning
  # ============================================================================

  defp scan_cloudtrail(account, creds) do
    case describe_trails(creds) do
      {:ok, trails} ->
        resources =
          Enum.map(trails, fn trail ->
            trail_status = get_trail_status(trail["Name"], creds)

            resource = %{
              id: trail["Name"],
              arn: trail["TrailARN"],
              type: "aws_cloudtrail",
              name: trail["Name"],
              region: trail["HomeRegion"] || "global",
              account_id: account.account_id,
              tags: [],
              metadata: %{
                s3_bucket: trail["S3BucketName"],
                is_multi_region: trail["IsMultiRegionTrail"],
                is_organization_trail: trail["IsOrganizationTrail"],
                log_file_validation: trail["LogFileValidationEnabled"],
                kms_key_id: trail["KMSKeyId"],
                is_logging: trail_status["IsLogging"]
              },
              created_at: nil
            }

            :ets.insert(@resources_table, {resource.id, resource})
            resource
          end)

        findings = analyze_cloudtrail(resources, account.account_id)
        {:ok, %{count: length(resources), findings: findings}}

      {:error, reason} ->
        Logger.warning("Failed to scan CloudTrail: #{inspect(reason)}")
        {:ok, %{count: 0, findings: []}}
    end
  end

  defp analyze_cloudtrail(trails, account_id) do
    findings = []

    # Check if multi-region trail exists
    has_multi_region = Enum.any?(trails, fn t -> t.metadata.is_multi_region end)

    findings =
      if not has_multi_region and not Enum.empty?(trails) do
        [
          Finding.create(%{
            provider: "aws",
            account_id: account_id,
            resource_id: "cloudtrail-config",
            resource_arn: "arn:aws:cloudtrail:::trail/*",
            resource_name: "CloudTrail Configuration",
            resource_type: "CloudTrail",
            region: "global",
            category: "logging_monitoring",
            severity: "high",
            title: "No multi-region CloudTrail trail configured",
            description: "No CloudTrail trail is configured to log events from all regions.",
            recommendation: "Configure a multi-region CloudTrail trail to capture all API activity.",
            compliance: ["CIS AWS 3.1"]
          })
          | findings
        ]
      else
        findings
      end

    # Check individual trails
    trail_findings =
      Enum.flat_map(trails, fn trail ->
        tf = []

        # Check if logging is enabled
        tf =
          if not trail.metadata.is_logging do
            [
              Finding.create(%{
                provider: "aws",
                account_id: account_id,
                resource_id: trail.id,
                resource_arn: trail.arn,
                resource_name: trail.name,
                resource_type: "CloudTrail",
                region: trail.region,
                category: "logging_monitoring",
                severity: "critical",
                title: "CloudTrail logging is disabled",
                description: "CloudTrail trail #{trail.name} has logging disabled.",
                recommendation: "Enable logging for the CloudTrail trail.",
                compliance: ["CIS AWS 3.1"]
              })
              | tf
            ]
          else
            tf
          end

        # Check for log file validation
        tf =
          if not trail.metadata.log_file_validation do
            [
              Finding.create(%{
                provider: "aws",
                account_id: account_id,
                resource_id: trail.id,
                resource_arn: trail.arn,
                resource_name: trail.name,
                resource_type: "CloudTrail",
                region: trail.region,
                category: "logging_monitoring",
                severity: "medium",
                title: "CloudTrail log file validation disabled",
                description: "CloudTrail trail #{trail.name} does not have log file validation enabled.",
                recommendation: "Enable log file validation to detect tampering.",
                compliance: ["CIS AWS 3.2"]
              })
              | tf
            ]
          else
            tf
          end

        # Check for encryption
        tf =
          if is_nil(trail.metadata.kms_key_id) do
            [
              Finding.create(%{
                provider: "aws",
                account_id: account_id,
                resource_id: trail.id,
                resource_arn: trail.arn,
                resource_name: trail.name,
                resource_type: "CloudTrail",
                region: trail.region,
                category: "data_protection",
                severity: "medium",
                title: "CloudTrail logs not encrypted with KMS",
                description: "CloudTrail trail #{trail.name} is not using KMS encryption for log files.",
                recommendation: "Enable KMS encryption for CloudTrail logs.",
                compliance: ["CIS AWS 3.7"]
              })
              | tf
            ]
          else
            tf
          end

        tf
      end)

    findings ++ trail_findings
  end

  # ============================================================================
  # AWS API Calls — Real implementations using Finch + SigV4
  # ============================================================================

  @cache_namespace :cloud_aws
  @cache_ttl 300
  @http_timeout 30_000

  # ---------- Credential helpers ----------

  defp get_base_credentials do
    aws_config = Application.get_env(:tamandua_server, __MODULE__, [])
    access_key = aws_config[:access_key_id]
    secret_key = aws_config[:secret_access_key]

    if is_nil(access_key) or is_nil(secret_key) do
      {:error, :not_configured}
    else
      {:ok,
       %{
         access_key_id: access_key,
         secret_access_key: secret_key,
         session_token: nil,
         expiration: nil
       }}
    end
  end

  defp assume_role(account) do
    Logger.debug("Assuming role: #{account.role_arn}")

    case get_base_credentials() do
      {:error, :not_configured} ->
        {:error, :not_configured}

      {:ok, base_creds} ->
        body_params = %{
          "Action" => "AssumeRole",
          "Version" => "2011-06-15",
          "RoleArn" => account.role_arn,
          "RoleSessionName" => "tamandua-cspm-#{System.system_time(:second)}"
        }

        body_params =
          if account.external_id do
            Map.put(body_params, "ExternalId", account.external_id)
          else
            body_params
          end

        body = URI.encode_query(body_params)
        url = "https://sts.amazonaws.com/"

        headers = [
          {"Content-Type", "application/x-www-form-urlencoded"},
          {"Host", "sts.amazonaws.com"}
        ]

        signed_headers =
          sign_aws_request("POST", url, headers, body, base_creds, "sts", "us-east-1")

        case finch_request(:post, url, signed_headers, body) do
          {:ok, %{status: 200, body: resp_body}} ->
            parse_assume_role_response(resp_body)

          {:ok, %{status: status, body: resp_body}} ->
            Logger.error("STS AssumeRole failed (#{status}): #{String.slice(resp_body, 0..500)}")
            {:error, {:sts_error, status}}

          {:error, reason} ->
            Logger.error("STS AssumeRole request failed: #{inspect(reason)}")
            {:error, reason}
        end
    end
  end

  defp parse_assume_role_response(xml_body) do
    # Parse STS XML response for credentials
    with {:ok, access_key} <- extract_xml_value(xml_body, "AccessKeyId"),
         {:ok, secret_key} <- extract_xml_value(xml_body, "SecretAccessKey"),
         {:ok, session_token} <- extract_xml_value(xml_body, "SessionToken"),
         {:ok, expiration_str} <- extract_xml_value(xml_body, "Expiration") do
      {:ok,
       %{
         access_key_id: access_key,
         secret_access_key: secret_key,
         session_token: session_token,
         expiration: parse_datetime(expiration_str)
       }}
    else
      _ ->
        Logger.error("Failed to parse STS AssumeRole response")
        {:error, :parse_error}
    end
  end

  defp get_credentials(account) do
    case account.credentials do
      %{expiration: exp} = creds when not is_nil(exp) ->
        if DateTime.compare(exp, DateTime.utc_now()) == :gt do
          {:ok, creds}
        else
          assume_role(account)
        end

      _ ->
        assume_role(account)
    end
  end

  # ---------- EC2 ----------

  defp describe_ec2_instances(region, creds) do
    cache_key = "ec2_instances:#{region}"

    TamanduaServer.Cache.get_or_fetch(@cache_namespace, cache_key, @cache_ttl, fn ->
      Logger.debug("AWS: DescribeInstances in #{region}")

      body = URI.encode_query(%{
        "Action" => "DescribeInstances",
        "Version" => "2016-11-15"
      })

      url = "https://ec2.#{region}.amazonaws.com/"
      host = "ec2.#{region}.amazonaws.com"

      headers = [
        {"Content-Type", "application/x-www-form-urlencoded"},
        {"Host", host}
      ]

      signed = sign_aws_request("POST", url, headers, body, creds, "ec2", region)

      case finch_request(:post, url, signed, body) do
        {:ok, %{status: 200, body: resp_body}} ->
          {:ok, parse_ec2_instances_xml(resp_body)}

        {:ok, %{status: status, body: resp_body}} ->
          Logger.warning("DescribeInstances failed (#{status}) in #{region}: #{String.slice(resp_body, 0..200)}")
          {:error, {:api_error, status}}

        {:error, reason} ->
          {:error, reason}
      end
    end)
  end

  defp parse_ec2_instances_xml(xml) do
    # Parse the DescribeInstances XML response into a list of instance maps.
    # Iterate over <reservationSet> -> <instancesSet> -> <item> blocks.
    reservation_blocks =
      Regex.scan(~r/<reservationSet>(.+?)<\/reservationSet>/s, xml)
      |> Enum.flat_map(fn [_, inner] ->
        Regex.scan(~r/<instancesSet>(.+?)<\/instancesSet>/s, inner)
        |> Enum.flat_map(fn [_, instances_inner] ->
          split_xml_items(instances_inner)
        end)
      end)

    Enum.map(reservation_blocks, fn item_xml ->
      %{
        "InstanceId" => extract_xml_text(item_xml, "instanceId"),
        "InstanceType" => extract_xml_text(item_xml, "instanceType"),
        "State" => %{"Name" => extract_xml_text(item_xml, "name")},
        "VpcId" => extract_xml_text(item_xml, "vpcId"),
        "SubnetId" => extract_xml_text(item_xml, "subnetId"),
        "PublicIpAddress" => extract_xml_text(item_xml, "ipAddress"),
        "PrivateIpAddress" => extract_xml_text(item_xml, "privateIpAddress"),
        "IamInstanceProfile" =>
          case extract_xml_text(item_xml, "arn") do
            nil -> nil
            arn -> %{"Arn" => arn}
          end,
        "SecurityGroups" => parse_security_group_refs(item_xml),
        "Tags" => parse_xml_tags(item_xml),
        "LaunchTime" => extract_xml_text(item_xml, "launchTime")
      }
    end)
  end

  # ---------- Security Groups ----------

  defp describe_security_groups(region, creds) do
    cache_key = "security_groups:#{region}"

    TamanduaServer.Cache.get_or_fetch(@cache_namespace, cache_key, @cache_ttl, fn ->
      Logger.debug("AWS: DescribeSecurityGroups in #{region}")

      body = URI.encode_query(%{
        "Action" => "DescribeSecurityGroups",
        "Version" => "2016-11-15"
      })

      url = "https://ec2.#{region}.amazonaws.com/"
      host = "ec2.#{region}.amazonaws.com"
      headers = [{"Content-Type", "application/x-www-form-urlencoded"}, {"Host", host}]
      signed = sign_aws_request("POST", url, headers, body, creds, "ec2", region)

      case finch_request(:post, url, signed, body) do
        {:ok, %{status: 200, body: resp_body}} ->
          {:ok, parse_security_groups_xml(resp_body)}

        {:ok, %{status: status}} ->
          {:error, {:api_error, status}}

        {:error, reason} ->
          {:error, reason}
      end
    end)
  end

  defp parse_security_groups_xml(xml) do
    blocks = split_xml_items(xml, "securityGroupInfo")

    Enum.map(blocks, fn item ->
      %{
        "GroupId" => extract_xml_text(item, "groupId"),
        "GroupName" => extract_xml_text(item, "groupName"),
        "Description" => extract_xml_text(item, "groupDescription"),
        "VpcId" => extract_xml_text(item, "vpcId"),
        "IpPermissions" => parse_ip_permissions(item, "ipPermissions"),
        "IpPermissionsEgress" => parse_ip_permissions(item, "ipPermissionsEgress"),
        "Tags" => parse_xml_tags(item)
      }
    end)
  end

  # ---------- S3 ----------

  defp list_s3_buckets(creds) do
    TamanduaServer.Cache.get_or_fetch(@cache_namespace, "s3_buckets", @cache_ttl, fn ->
      Logger.debug("AWS: ListBuckets")

      url = "https://s3.amazonaws.com/"
      headers = [{"Host", "s3.amazonaws.com"}]
      signed = sign_aws_request("GET", url, headers, "", creds, "s3", "us-east-1")

      case finch_request(:get, url, signed, "") do
        {:ok, %{status: 200, body: resp_body}} ->
          buckets =
            Regex.scan(~r/<Bucket>\s*<Name>(.*?)<\/Name>\s*<CreationDate>(.*?)<\/CreationDate>\s*<\/Bucket>/s, resp_body)
            |> Enum.map(fn [_, name, creation_date] ->
              %{"Name" => name, "CreationDate" => creation_date}
            end)

          {:ok, buckets}

        {:ok, %{status: status}} ->
          {:error, {:api_error, status}}

        {:error, reason} ->
          {:error, reason}
      end
    end)
  end

  defp get_bucket_acl(bucket, creds) do
    url = "https://#{bucket}.s3.amazonaws.com/?acl"
    headers = [{"Host", "#{bucket}.s3.amazonaws.com"}]
    signed = sign_aws_request("GET", url, headers, "", creds, "s3", "us-east-1")

    case finch_request(:get, url, signed, "") do
      {:ok, %{status: 200, body: resp_body}} ->
        grants =
          Regex.scan(~r/<Grant>(.+?)<\/Grant>/s, resp_body)
          |> Enum.map(fn [_, grant_xml] ->
            %{
              "Grantee" => %{
                "URI" => extract_xml_text(grant_xml, "URI"),
                "Type" => extract_xml_text(grant_xml, "Type") || extract_xml_attr(grant_xml, "xsi:type")
              },
              "Permission" => extract_xml_text(grant_xml, "Permission")
            }
          end)

        %{"Grants" => grants}

      _ ->
        nil
    end
  end

  defp get_bucket_policy(bucket, creds) do
    url = "https://#{bucket}.s3.amazonaws.com/?policy"
    headers = [{"Host", "#{bucket}.s3.amazonaws.com"}]
    signed = sign_aws_request("GET", url, headers, "", creds, "s3", "us-east-1")

    case finch_request(:get, url, signed, "") do
      {:ok, %{status: 200, body: resp_body}} -> resp_body
      _ -> nil
    end
  end

  defp get_bucket_encryption(bucket, creds) do
    url = "https://#{bucket}.s3.amazonaws.com/?encryption"
    headers = [{"Host", "#{bucket}.s3.amazonaws.com"}]
    signed = sign_aws_request("GET", url, headers, "", creds, "s3", "us-east-1")

    case finch_request(:get, url, signed, "") do
      {:ok, %{status: 200, body: resp_body}} ->
        rules =
          Regex.scan(~r/<Rule>(.+?)<\/Rule>/s, resp_body)
          |> Enum.map(fn [_, rule_xml] ->
            %{
              "SSEAlgorithm" => extract_xml_text(rule_xml, "SSEAlgorithm"),
              "KMSMasterKeyID" => extract_xml_text(rule_xml, "KMSMasterKeyID")
            }
          end)

        %{"Rules" => rules}

      _ ->
        nil
    end
  end

  defp get_bucket_versioning(bucket, creds) do
    url = "https://#{bucket}.s3.amazonaws.com/?versioning"
    headers = [{"Host", "#{bucket}.s3.amazonaws.com"}]
    signed = sign_aws_request("GET", url, headers, "", creds, "s3", "us-east-1")

    case finch_request(:get, url, signed, "") do
      {:ok, %{status: 200, body: resp_body}} ->
        %{"Status" => extract_xml_text(resp_body, "Status")}

      _ ->
        nil
    end
  end

  defp get_bucket_logging(bucket, creds) do
    url = "https://#{bucket}.s3.amazonaws.com/?logging"
    headers = [{"Host", "#{bucket}.s3.amazonaws.com"}]
    signed = sign_aws_request("GET", url, headers, "", creds, "s3", "us-east-1")

    case finch_request(:get, url, signed, "") do
      {:ok, %{status: 200, body: resp_body}} ->
        target = extract_xml_text(resp_body, "TargetBucket")

        if target do
          %{"LoggingEnabled" => %{"TargetBucket" => target}}
        else
          nil
        end

      _ ->
        nil
    end
  end

  defp get_public_access_block(bucket, creds) do
    url = "https://#{bucket}.s3.amazonaws.com/?publicAccessBlock"
    headers = [{"Host", "#{bucket}.s3.amazonaws.com"}]
    signed = sign_aws_request("GET", url, headers, "", creds, "s3", "us-east-1")

    case finch_request(:get, url, signed, "") do
      {:ok, %{status: 200, body: resp_body}} ->
        %{
          "BlockPublicAcls" => extract_xml_bool(resp_body, "BlockPublicAcls"),
          "BlockPublicPolicy" => extract_xml_bool(resp_body, "BlockPublicPolicy"),
          "IgnorePublicAcls" => extract_xml_bool(resp_body, "IgnorePublicAcls"),
          "RestrictPublicBuckets" => extract_xml_bool(resp_body, "RestrictPublicBuckets")
        }

      _ ->
        nil
    end
  end

  defp get_bucket_tags(bucket, creds) do
    url = "https://#{bucket}.s3.amazonaws.com/?tagging"
    headers = [{"Host", "#{bucket}.s3.amazonaws.com"}]
    signed = sign_aws_request("GET", url, headers, "", creds, "s3", "us-east-1")

    case finch_request(:get, url, signed, "") do
      {:ok, %{status: 200, body: resp_body}} -> parse_xml_tags(resp_body)
      _ -> %{}
    end
  end

  # ---------- IAM ----------

  defp list_iam_users(creds) do
    TamanduaServer.Cache.get_or_fetch(@cache_namespace, "iam_users", @cache_ttl, fn ->
      aws_query_api("iam", "us-east-1", "iam.amazonaws.com",
        %{"Action" => "ListUsers", "Version" => "2010-05-08"}, creds, fn resp_body ->
          blocks = split_xml_items(resp_body, "Users")

          Enum.map(blocks, fn item ->
            %{
              "UserId" => extract_xml_text(item, "UserId"),
              "UserName" => extract_xml_text(item, "UserName"),
              "Arn" => extract_xml_text(item, "Arn"),
              "PasswordLastUsed" => extract_xml_text(item, "PasswordLastUsed"),
              "CreateDate" => extract_xml_text(item, "CreateDate"),
              "Tags" => parse_xml_tags(item)
            }
          end)
        end)
    end)
  end

  defp list_access_keys(username, creds) do
    case aws_query_api("iam", "us-east-1", "iam.amazonaws.com",
           %{"Action" => "ListAccessKeys", "Version" => "2010-05-08", "UserName" => username},
           creds, fn resp_body ->
             split_xml_items(resp_body, "AccessKeyMetadata")
             |> Enum.map(fn item ->
               %{
                 "AccessKeyId" => extract_xml_text(item, "AccessKeyId"),
                 "Status" => extract_xml_text(item, "Status"),
                 "CreateDate" => extract_xml_text(item, "CreateDate")
               }
             end)
           end) do
      {:ok, keys} -> keys
      _ -> []
    end
  end

  defp list_mfa_devices(username, creds) do
    case aws_query_api("iam", "us-east-1", "iam.amazonaws.com",
           %{"Action" => "ListMFADevices", "Version" => "2010-05-08", "UserName" => username},
           creds, fn resp_body ->
             split_xml_items(resp_body, "MFADevices")
             |> Enum.map(fn item ->
               %{"SerialNumber" => extract_xml_text(item, "SerialNumber")}
             end)
           end) do
      {:ok, devices} -> devices
      _ -> []
    end
  end

  defp get_login_profile(username, creds) do
    case aws_query_api("iam", "us-east-1", "iam.amazonaws.com",
           %{"Action" => "GetLoginProfile", "Version" => "2010-05-08", "UserName" => username},
           creds, fn resp_body ->
             %{"CreateDate" => extract_xml_text(resp_body, "CreateDate")}
           end) do
      {:ok, profile} -> profile
      _ -> nil
    end
  end

  defp list_attached_user_policies(username, creds) do
    case aws_query_api("iam", "us-east-1", "iam.amazonaws.com",
           %{"Action" => "ListAttachedUserPolicies", "Version" => "2010-05-08", "UserName" => username},
           creds, fn resp_body ->
             split_xml_items(resp_body, "AttachedPolicies")
             |> Enum.map(fn item ->
               %{
                 "PolicyName" => extract_xml_text(item, "PolicyName"),
                 "PolicyArn" => extract_xml_text(item, "PolicyArn")
               }
             end)
           end) do
      {:ok, policies} -> policies
      _ -> []
    end
  end

  defp list_iam_roles(creds) do
    TamanduaServer.Cache.get_or_fetch(@cache_namespace, "iam_roles", @cache_ttl, fn ->
      aws_query_api("iam", "us-east-1", "iam.amazonaws.com",
        %{"Action" => "ListRoles", "Version" => "2010-05-08"}, creds, fn resp_body ->
          split_xml_items(resp_body, "Roles")
          |> Enum.map(fn item ->
            %{
              "RoleId" => extract_xml_text(item, "RoleId"),
              "RoleName" => extract_xml_text(item, "RoleName"),
              "Arn" => extract_xml_text(item, "Arn"),
              "AssumeRolePolicyDocument" =>
                extract_xml_text(item, "AssumeRolePolicyDocument") |> decode_uri_safe(),
              "MaxSessionDuration" => extract_xml_text(item, "MaxSessionDuration"),
              "CreateDate" => extract_xml_text(item, "CreateDate"),
              "Tags" => parse_xml_tags(item)
            }
          end)
        end)
    end)
  end

  defp list_attached_role_policies(role_name, creds) do
    case aws_query_api("iam", "us-east-1", "iam.amazonaws.com",
           %{"Action" => "ListAttachedRolePolicies", "Version" => "2010-05-08", "RoleName" => role_name},
           creds, fn resp_body ->
             split_xml_items(resp_body, "AttachedPolicies")
             |> Enum.map(fn item ->
               %{
                 "PolicyName" => extract_xml_text(item, "PolicyName"),
                 "PolicyArn" => extract_xml_text(item, "PolicyArn")
               }
             end)
           end) do
      {:ok, policies} -> policies
      _ -> []
    end
  end

  defp list_iam_policies(creds) do
    TamanduaServer.Cache.get_or_fetch(@cache_namespace, "iam_policies", @cache_ttl, fn ->
      aws_query_api("iam", "us-east-1", "iam.amazonaws.com",
        %{"Action" => "ListPolicies", "Version" => "2010-05-08", "Scope" => "Local"},
        creds, fn resp_body ->
          split_xml_items(resp_body, "Policies")
          |> Enum.map(fn item ->
            %{
              "PolicyId" => extract_xml_text(item, "PolicyId"),
              "PolicyName" => extract_xml_text(item, "PolicyName"),
              "Arn" => extract_xml_text(item, "Arn"),
              "DefaultVersionId" => extract_xml_text(item, "DefaultVersionId"),
              "AttachmentCount" =>
                case extract_xml_text(item, "AttachmentCount") do
                  nil -> 0
                  n -> String.to_integer(n)
                end,
              "CreateDate" => extract_xml_text(item, "CreateDate")
            }
          end)
        end)
    end)
  end

  defp get_policy_version(policy_arn, version_id, creds) do
    case aws_query_api("iam", "us-east-1", "iam.amazonaws.com",
           %{
             "Action" => "GetPolicyVersion",
             "Version" => "2010-05-08",
             "PolicyArn" => policy_arn,
             "VersionId" => version_id
           },
           creds, fn resp_body ->
             extract_xml_text(resp_body, "Document") |> decode_uri_safe()
           end) do
      {:ok, doc} -> doc
      _ -> nil
    end
  end

  # ---------- RDS ----------

  defp describe_rds_instances(region, creds) do
    cache_key = "rds_instances:#{region}"

    TamanduaServer.Cache.get_or_fetch(@cache_namespace, cache_key, @cache_ttl, fn ->
      aws_query_api("rds", region, "rds.#{region}.amazonaws.com",
        %{"Action" => "DescribeDBInstances", "Version" => "2014-10-31"},
        creds, fn resp_body ->
          split_xml_items(resp_body, "DBInstances")
          |> Enum.map(fn item ->
            %{
              "DBInstanceIdentifier" => extract_xml_text(item, "DBInstanceIdentifier"),
              "DBInstanceArn" => extract_xml_text(item, "DBInstanceArn"),
              "Engine" => extract_xml_text(item, "Engine"),
              "EngineVersion" => extract_xml_text(item, "EngineVersion"),
              "DBInstanceClass" => extract_xml_text(item, "DBInstanceClass"),
              "PubliclyAccessible" => extract_xml_bool(item, "PubliclyAccessible"),
              "StorageEncrypted" => extract_xml_bool(item, "StorageEncrypted"),
              "MultiAZ" => extract_xml_bool(item, "MultiAZ"),
              "BackupRetentionPeriod" =>
                case extract_xml_text(item, "BackupRetentionPeriod") do
                  nil -> 0
                  n -> String.to_integer(n)
                end,
              "VpcSecurityGroups" => parse_security_group_refs(item),
              "InstanceCreateTime" => extract_xml_text(item, "InstanceCreateTime"),
              "TagList" => parse_xml_tags(item)
            }
          end)
        end)
    end)
  end

  # ---------- Lambda ----------

  defp list_lambda_functions(region, creds) do
    cache_key = "lambda_functions:#{region}"

    TamanduaServer.Cache.get_or_fetch(@cache_namespace, cache_key, @cache_ttl, fn ->
      Logger.debug("AWS: ListFunctions in #{region}")

      url = "https://lambda.#{region}.amazonaws.com/2015-03-31/functions"
      host = "lambda.#{region}.amazonaws.com"
      headers = [{"Host", host}]
      signed = sign_aws_request("GET", url, headers, "", creds, "lambda", region)

      case finch_request(:get, url, signed, "") do
        {:ok, %{status: 200, body: resp_body}} ->
          case Jason.decode(resp_body) do
            {:ok, %{"Functions" => functions}} -> {:ok, functions}
            {:ok, _} -> {:ok, []}
            _ -> {:error, :parse_error}
          end

        {:ok, %{status: status}} ->
          {:error, {:api_error, status}}

        {:error, reason} ->
          {:error, reason}
      end
    end)
  end

  # ---------- VPC ----------

  defp describe_vpcs(region, creds) do
    cache_key = "vpcs:#{region}"

    TamanduaServer.Cache.get_or_fetch(@cache_namespace, cache_key, @cache_ttl, fn ->
      aws_query_api("ec2", region, "ec2.#{region}.amazonaws.com",
        %{"Action" => "DescribeVpcs", "Version" => "2016-11-15"},
        creds, fn resp_body ->
          split_xml_items(resp_body, "vpcSet")
          |> Enum.map(fn item ->
            %{
              "VpcId" => extract_xml_text(item, "vpcId"),
              "CidrBlock" => extract_xml_text(item, "cidrBlock"),
              "IsDefault" => extract_xml_bool(item, "isDefault"),
              "State" => extract_xml_text(item, "state"),
              "Tags" => parse_xml_tags(item)
            }
          end)
        end)
    end)
  end

  defp describe_flow_logs(vpc_id, region, creds) do
    body = URI.encode_query(%{
      "Action" => "DescribeFlowLogs",
      "Version" => "2016-11-15",
      "Filter.1.Name" => "resource-id",
      "Filter.1.Value.1" => vpc_id
    })

    url = "https://ec2.#{region}.amazonaws.com/"
    host = "ec2.#{region}.amazonaws.com"
    headers = [{"Content-Type", "application/x-www-form-urlencoded"}, {"Host", host}]
    signed = sign_aws_request("POST", url, headers, body, creds, "ec2", region)

    case finch_request(:post, url, signed, body) do
      {:ok, %{status: 200, body: resp_body}} ->
        split_xml_items(resp_body, "flowLogSet")
        |> Enum.map(fn item ->
          %{
            "FlowLogId" => extract_xml_text(item, "flowLogId"),
            "ResourceId" => extract_xml_text(item, "resourceId"),
            "FlowLogStatus" => extract_xml_text(item, "flowLogStatus")
          }
        end)

      _ ->
        []
    end
  end

  # ---------- CloudTrail ----------

  defp describe_trails(creds) do
    TamanduaServer.Cache.get_or_fetch(@cache_namespace, "cloudtrail_trails", @cache_ttl, fn ->
      Logger.debug("AWS: DescribeTrails")

      url = "https://cloudtrail.us-east-1.amazonaws.com/"
      host = "cloudtrail.us-east-1.amazonaws.com"

      body = Jason.encode!(%{})

      headers = [
        {"Content-Type", "application/x-amz-json-1.1"},
        {"Host", host},
        {"X-Amz-Target", "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.DescribeTrails"}
      ]

      signed = sign_aws_request("POST", url, headers, body, creds, "cloudtrail", "us-east-1")

      case finch_request(:post, url, signed, body) do
        {:ok, %{status: 200, body: resp_body}} ->
          case Jason.decode(resp_body) do
            {:ok, %{"trailList" => trails}} -> {:ok, trails}
            {:ok, _} -> {:ok, []}
            _ -> {:error, :parse_error}
          end

        {:ok, %{status: status}} ->
          {:error, {:api_error, status}}

        {:error, reason} ->
          {:error, reason}
      end
    end)
  end

  defp get_trail_status(trail_name, creds) do
    url = "https://cloudtrail.us-east-1.amazonaws.com/"
    host = "cloudtrail.us-east-1.amazonaws.com"

    body = Jason.encode!(%{"Name" => trail_name})

    headers = [
      {"Content-Type", "application/x-amz-json-1.1"},
      {"Host", host},
      {"X-Amz-Target", "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.GetTrailStatus"}
    ]

    signed = sign_aws_request("POST", url, headers, body, creds, "cloudtrail", "us-east-1")

    case finch_request(:post, url, signed, body) do
      {:ok, %{status: 200, body: resp_body}} ->
        case Jason.decode(resp_body) do
          {:ok, data} -> data
          _ -> %{"IsLogging" => false}
        end

      _ ->
        %{"IsLogging" => false}
    end
  end

  # ============================================================================
  # AWS SigV4 Signing
  # ============================================================================

  defp sign_aws_request(method, url, headers, body, creds, service, region) do
    now = DateTime.utc_now()
    date_stamp = Calendar.strftime(now, "%Y%m%d")
    amz_date = Calendar.strftime(now, "%Y%m%dT%H%M%SZ")

    uri = URI.parse(url)
    host = uri.host
    path = uri.path || "/"
    query = uri.query || ""

    # Add required headers
    headers =
      headers
      |> put_header("Host", host)
      |> put_header("X-Amz-Date", amz_date)

    headers =
      if creds[:session_token] do
        put_header(headers, "X-Amz-Security-Token", creds[:session_token])
      else
        headers
      end

    # Canonical request
    signed_header_keys =
      headers
      |> Enum.map(fn {k, _} -> String.downcase(k) end)
      |> Enum.sort()
      |> Enum.join(";")

    canonical_headers =
      headers
      |> Enum.map(fn {k, v} -> "#{String.downcase(k)}:#{String.trim(v)}" end)
      |> Enum.sort()
      |> Enum.join("\n")

    payload_hash = :crypto.hash(:sha256, body) |> Base.encode16(case: :lower)

    canonical_request =
      [
        String.upcase(method),
        uri_encode_path(path),
        normalize_query_string(query),
        canonical_headers <> "\n",
        signed_header_keys,
        payload_hash
      ]
      |> Enum.join("\n")

    # String to sign
    credential_scope = "#{date_stamp}/#{region}/#{service}/aws4_request"

    string_to_sign =
      [
        "AWS4-HMAC-SHA256",
        amz_date,
        credential_scope,
        :crypto.hash(:sha256, canonical_request) |> Base.encode16(case: :lower)
      ]
      |> Enum.join("\n")

    # Signing key
    signing_key =
      ("AWS4" <> creds.secret_access_key)
      |> hmac_sha256(date_stamp)
      |> hmac_sha256(region)
      |> hmac_sha256(service)
      |> hmac_sha256("aws4_request")

    signature =
      hmac_sha256(signing_key, string_to_sign)
      |> Base.encode16(case: :lower)

    authorization =
      "AWS4-HMAC-SHA256 Credential=#{creds.access_key_id}/#{credential_scope}, " <>
        "SignedHeaders=#{signed_header_keys}, Signature=#{signature}"

    put_header(headers, "Authorization", authorization)
  end

  defp hmac_sha256(key, data) do
    :crypto.mac(:hmac, :sha256, key, data)
  end

  defp uri_encode_path(path) do
    path
    |> String.split("/")
    |> Enum.map(&URI.encode_www_form/1)
    |> Enum.join("/")
  end

  defp normalize_query_string(""), do: ""

  defp normalize_query_string(query) do
    query
    |> URI.decode_query()
    |> Enum.sort_by(fn {k, _} -> k end)
    |> URI.encode_query()
  end

  defp put_header(headers, key, value) do
    key_lower = String.downcase(key)
    headers = Enum.reject(headers, fn {k, _} -> String.downcase(k) == key_lower end)
    [{key, value} | headers]
  end

  # ============================================================================
  # HTTP + XML Helpers
  # ============================================================================

  defp finch_request(method, url, headers, body) do
    request = Finch.build(method, url, headers, body)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: status, body: resp_body}} ->
        {:ok, %{status: status, body: resp_body}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp aws_query_api(service, region, host, params, creds, parse_fn) do
    body = URI.encode_query(params)
    url = "https://#{host}/"

    headers = [
      {"Content-Type", "application/x-www-form-urlencoded"},
      {"Host", host}
    ]

    signed = sign_aws_request("POST", url, headers, body, creds, service, region)

    case finch_request(:post, url, signed, body) do
      {:ok, %{status: 200, body: resp_body}} ->
        {:ok, parse_fn.(resp_body)}

      {:ok, %{status: status, body: resp_body}} ->
        Logger.warning("AWS #{params["Action"]} failed (#{status}): #{String.slice(resp_body, 0..200)}")
        {:error, {:api_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp extract_xml_value(xml, tag) do
    case Regex.run(~r/<#{Regex.escape(tag)}>(.*?)<\/#{Regex.escape(tag)}>/s, xml) do
      [_, value] -> {:ok, value}
      _ -> :error
    end
  end

  defp extract_xml_text(xml, tag) do
    case Regex.run(~r/<#{Regex.escape(tag)}>(.*?)<\/#{Regex.escape(tag)}>/s, xml) do
      [_, value] -> String.trim(value)
      _ -> nil
    end
  end

  defp extract_xml_bool(xml, tag) do
    case extract_xml_text(xml, tag) do
      "true" -> true
      "false" -> false
      _ -> false
    end
  end

  defp extract_xml_attr(xml, attr) do
    case Regex.run(~r/#{Regex.escape(attr)}="(.*?)"/, xml) do
      [_, value] -> value
      _ -> nil
    end
  end

  defp split_xml_items(xml, wrapper_tag \\ nil) do
    scoped =
      if wrapper_tag do
        case Regex.run(~r/<#{Regex.escape(wrapper_tag)}>(.*)<\/#{Regex.escape(wrapper_tag)}>/s, xml) do
          [_, inner] -> inner
          _ -> xml
        end
      else
        xml
      end

    Regex.scan(~r/<item>(.*?)<\/item>/s, scoped)
    |> Enum.map(fn [_, inner] -> inner end)
  end

  defp parse_xml_tags(xml) do
    Regex.scan(~r/<Tag>\s*<Key>(.*?)<\/Key>\s*<Value>(.*?)<\/Value>\s*<\/Tag>/s, xml)
    |> Enum.reduce(%{}, fn [_, key, value], acc ->
      Map.put(acc, key, value)
    end)
  end

  defp parse_security_group_refs(xml) do
    Regex.scan(~r/<groupId>(.*?)<\/groupId>/s, xml)
    |> Enum.map(fn [_, id] -> %{"GroupId" => id} end)
  end

  defp parse_ip_permissions(xml, wrapper_tag) do
    case Regex.run(~r/<#{Regex.escape(wrapper_tag)}>(.*?)<\/#{Regex.escape(wrapper_tag)}>/s, xml) do
      [_, inner] ->
        Regex.scan(~r/<item>(.*?)<\/item>/s, inner)
        |> Enum.map(fn [_, perm_xml] ->
          from_port = extract_xml_text(perm_xml, "fromPort")
          to_port = extract_xml_text(perm_xml, "toPort")

          ip_ranges =
            Regex.scan(~r/<cidrIp>(.*?)<\/cidrIp>/s, perm_xml)
            |> Enum.map(fn [_, cidr] -> %{"CidrIp" => cidr} end)

          %{
            "IpProtocol" => extract_xml_text(perm_xml, "ipProtocol"),
            "FromPort" => if(from_port, do: String.to_integer(from_port)),
            "ToPort" => if(to_port, do: String.to_integer(to_port)),
            "IpRanges" => ip_ranges
          }
        end)

      _ ->
        []
    end
  end

  defp decode_uri_safe(nil), do: nil

  defp decode_uri_safe(str) when is_binary(str) do
    case URI.decode(str) do
      decoded when decoded != str -> decoded
      _ -> str
    end
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  defp ensure_tables do
    tables = [@accounts_table, @resources_table, @credentials_cache]

    Enum.each(tables, fn table ->
      case :ets.whereis(table) do
        :undefined -> :ets.new(table, [:set, :public, :named_table])
        _ -> :ok
      end
    end)
  end

  defp validate_role_arn(nil), do: {:error, "Role ARN is required"}

  defp validate_role_arn(arn) do
    if String.match?(arn, ~r/^arn:aws:iam::\d{12}:role\/.+$/) do
      :ok
    else
      {:error, "Invalid role ARN format"}
    end
  end

  defp sanitize_account(account) do
    Map.drop(account, [:credentials])
  end

  defp parse_tags(nil), do: %{}

  defp parse_tags(tags) when is_list(tags) do
    Enum.reduce(tags, %{}, fn tag, acc ->
      Map.put(acc, tag["Key"], tag["Value"])
    end)
  end

  defp parse_tags(tags) when is_map(tags), do: tags

  defp get_tag_value(tags, key) do
    tags
    |> parse_tags()
    |> Map.get(key)
  end

  defp parse_datetime(nil), do: nil
  defp parse_datetime(dt) when is_binary(dt) do
    case DateTime.from_iso8601(dt) do
      {:ok, datetime, _} -> datetime
      _ -> nil
    end
  end
  defp parse_datetime(%DateTime{} = dt), do: dt
  defp parse_datetime(_), do: nil

  defp decode_policy(nil), do: {:error, :no_policy}
  defp decode_policy(policy) when is_binary(policy) do
    case URI.decode(policy) do
      decoded when decoded != policy -> Jason.decode(decoded)
      _ -> Jason.decode(policy)
    end
  end
  defp decode_policy(policy) when is_map(policy), do: {:ok, policy}

  defp apply_resource_filters(resources, filters) do
    resources
    |> maybe_filter(:type, filters[:type])
    |> maybe_filter(:region, filters[:region])
  end

  defp maybe_filter(list, _field, nil), do: list
  defp maybe_filter(list, field, value) do
    Enum.filter(list, fn r -> Map.get(r, field) == value end)
  end
end
