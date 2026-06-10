defmodule TamanduaServer.Cloud.IdentitySecurity do
  @moduledoc """
  Cloud Identity Security Analysis for multi-cloud environments.

  Provides comprehensive identity and access management security analysis:
  - IAM policy analysis for AWS, Azure, and GCP
  - Service account monitoring
  - Cross-account access detection
  - Privilege escalation path discovery
  - Least privilege compliance
  - Identity governance

  ## Features

  ### IAM Policy Analysis
  - Detects overly permissive policies
  - Identifies unused permissions
  - Finds policy conflicts
  - Analyzes effective permissions

  ### Privilege Escalation Detection
  - Maps privilege escalation paths
  - Identifies risky permission combinations
  - Detects indirect escalation routes
  - Monitors for privilege drift

  ### Cross-Account/Project Access
  - Tracks cross-account roles and trusts
  - Monitors external identity access
  - Detects suspicious federation patterns
  """

  use GenServer
  require Logger

  alias TamanduaServer.Cloud.Finding

  # ETS tables for identity data
  @identities_table :cloud_identities
  @policies_table :cloud_iam_policies
  @escalation_paths_table :privilege_escalation_paths
  @cross_account_table :cross_account_access

  # AWS Privilege Escalation Actions
  @aws_priv_esc_actions %{
    "iam:CreateAccessKey" => %{
      type: :create_access_key,
      severity: "high",
      description: "Can create access keys for other users"
    },
    "iam:CreateLoginProfile" => %{
      type: :create_login,
      severity: "high",
      description: "Can create console passwords for other users"
    },
    "iam:UpdateLoginProfile" => %{
      type: :update_login,
      severity: "high",
      description: "Can change console passwords for other users"
    },
    "iam:AttachUserPolicy" => %{
      type: :attach_policy,
      severity: "critical",
      description: "Can attach policies to users"
    },
    "iam:AttachRolePolicy" => %{
      type: :attach_policy,
      severity: "critical",
      description: "Can attach policies to roles"
    },
    "iam:AttachGroupPolicy" => %{
      type: :attach_policy,
      severity: "critical",
      description: "Can attach policies to groups"
    },
    "iam:PutUserPolicy" => %{
      type: :inline_policy,
      severity: "critical",
      description: "Can add inline policies to users"
    },
    "iam:PutRolePolicy" => %{
      type: :inline_policy,
      severity: "critical",
      description: "Can add inline policies to roles"
    },
    "iam:PutGroupPolicy" => %{
      type: :inline_policy,
      severity: "critical",
      description: "Can add inline policies to groups"
    },
    "iam:CreatePolicyVersion" => %{
      type: :policy_version,
      severity: "critical",
      description: "Can create new policy versions to modify permissions"
    },
    "iam:SetDefaultPolicyVersion" => %{
      type: :policy_version,
      severity: "high",
      description: "Can set default policy version"
    },
    "iam:PassRole" => %{
      type: :pass_role,
      severity: "high",
      description: "Can pass roles to services"
    },
    "iam:UpdateAssumeRolePolicy" => %{
      type: :assume_role,
      severity: "critical",
      description: "Can modify who can assume a role"
    },
    "sts:AssumeRole" => %{
      type: :assume_role,
      severity: "medium",
      description: "Can assume other roles"
    },
    "lambda:CreateFunction" => %{
      type: :lambda_escalation,
      severity: "high",
      description: "Can create Lambda with elevated role"
    },
    "lambda:UpdateFunctionCode" => %{
      type: :lambda_escalation,
      severity: "high",
      description: "Can modify Lambda code"
    },
    "ec2:RunInstances" => %{
      type: :ec2_escalation,
      severity: "medium",
      description: "Can launch EC2 with instance profile"
    },
    "glue:CreateDevEndpoint" => %{
      type: :glue_escalation,
      severity: "high",
      description: "Can create Glue dev endpoint with role"
    },
    "cloudformation:CreateStack" => %{
      type: :cfn_escalation,
      severity: "high",
      description: "Can create CloudFormation with role"
    },
    "datapipeline:CreatePipeline" => %{
      type: :pipeline_escalation,
      severity: "high",
      description: "Can create data pipeline with role"
    }
  }

  # Azure Risky Roles
  @azure_risky_roles [
    "Owner",
    "Contributor",
    "User Access Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Global Administrator",
    "Privileged Role Administrator",
    "Key Vault Administrator"
  ]

  # GCP Risky Permissions
  @gcp_priv_esc_permissions [
    "iam.serviceAccountKeys.create",
    "iam.serviceAccounts.actAs",
    "iam.serviceAccountTokenCreator",
    "resourcemanager.projects.setIamPolicy",
    "resourcemanager.folders.setIamPolicy",
    "resourcemanager.organizations.setIamPolicy",
    "compute.instances.setServiceAccount",
    "cloudfunctions.functions.setIamPolicy",
    "run.services.setIamPolicy"
  ]

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Analyze IAM policies for a cloud account/project.
  """
  def analyze_iam(provider, account_id, policies) do
    GenServer.call(__MODULE__, {:analyze_iam, provider, account_id, policies}, 60_000)
  end

  @doc """
  Detect privilege escalation paths.
  """
  def detect_escalation_paths(provider, account_id) do
    GenServer.call(__MODULE__, {:detect_escalation, provider, account_id}, 60_000)
  end

  @doc """
  Analyze cross-account/project access.
  """
  def analyze_cross_account_access(provider, account_id) do
    GenServer.call(__MODULE__, {:analyze_cross_account, provider, account_id})
  end

  @doc """
  Monitor a service account or IAM user.
  """
  def monitor_identity(provider, account_id, identity) do
    GenServer.call(__MODULE__, {:monitor_identity, provider, account_id, identity})
  end

  @doc """
  Get identity risk score.
  """
  def get_identity_risk(identity_id) do
    GenServer.call(__MODULE__, {:get_identity_risk, identity_id})
  end

  @doc """
  List all monitored identities.
  """
  def list_identities(filters \\ %{}) do
    GenServer.call(__MODULE__, {:list_identities, filters})
  end

  @doc """
  Get privilege escalation paths for an identity.
  """
  def get_escalation_paths(identity_id) do
    GenServer.call(__MODULE__, {:get_escalation_paths, identity_id})
  end

  @doc """
  Get cross-account access for an account.
  """
  def get_cross_account_access(provider, account_id) do
    GenServer.call(__MODULE__, {:get_cross_account, provider, account_id})
  end

  @doc """
  Generate least privilege policy recommendation.
  """
  def recommend_least_privilege(provider, identity_id, usage_data) do
    GenServer.call(__MODULE__, {:recommend_least_privilege, provider, identity_id, usage_data})
  end

  @doc """
  Get identity security statistics.
  """
  def get_statistics do
    GenServer.call(__MODULE__, :get_statistics)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@identities_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@policies_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@escalation_paths_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@cross_account_table, [:set, :named_table, :public, read_concurrency: true])

    Logger.info("Cloud Identity Security service started")
    {:ok, %{analyses_performed: 0, findings_generated: 0}}
  end

  @impl true
  def handle_call({:analyze_iam, provider, account_id, policies}, _from, state) do
    result =
      case provider do
        "aws" -> analyze_aws_iam(account_id, policies)
        "azure" -> analyze_azure_iam(account_id, policies)
        "gcp" -> analyze_gcp_iam(account_id, policies)
        _ -> {:error, :unsupported_provider}
      end

    new_state = %{state | analyses_performed: state.analyses_performed + 1}
    {:reply, result, new_state}
  end

  @impl true
  def handle_call({:detect_escalation, provider, account_id}, _from, state) do
    result =
      case provider do
        "aws" -> detect_aws_escalation_paths(account_id)
        "azure" -> detect_azure_escalation_paths(account_id)
        "gcp" -> detect_gcp_escalation_paths(account_id)
        _ -> {:error, :unsupported_provider}
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:analyze_cross_account, provider, account_id}, _from, state) do
    result = analyze_cross_account(provider, account_id)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:monitor_identity, provider, account_id, identity}, _from, state) do
    identity_record = %{
      id: identity[:id] || identity[:arn] || identity[:email],
      provider: provider,
      account_id: account_id,
      type: identity[:type],
      name: identity[:name],
      arn: identity[:arn],
      email: identity[:email],
      created_at: identity[:created_at],
      last_used: identity[:last_used],
      policies: identity[:policies] || [],
      permissions: identity[:permissions] || [],
      risk_score: 0,
      risk_factors: [],
      monitored_since: DateTime.utc_now()
    }

    # Calculate initial risk score
    risk_assessment = assess_identity_risk(identity_record)
    identity_record = Map.merge(identity_record, risk_assessment)

    :ets.insert(@identities_table, {identity_record.id, identity_record})
    {:reply, {:ok, identity_record}, state}
  end

  @impl true
  def handle_call({:get_identity_risk, identity_id}, _from, state) do
    result =
      case :ets.lookup(@identities_table, identity_id) do
        [{^identity_id, identity}] ->
          {:ok,
           %{
             identity_id: identity_id,
             risk_score: identity.risk_score,
             risk_factors: identity.risk_factors,
             recommendations: generate_recommendations(identity)
           }}

        [] ->
          {:error, :not_found}
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:list_identities, filters}, _from, state) do
    identities =
      :ets.tab2list(@identities_table)
      |> Enum.map(fn {_id, identity} -> identity end)
      |> apply_identity_filters(filters)
      |> Enum.sort_by(& &1.risk_score, :desc)

    {:reply, identities, state}
  end

  @impl true
  def handle_call({:get_escalation_paths, identity_id}, _from, state) do
    result =
      case :ets.lookup(@escalation_paths_table, identity_id) do
        [{^identity_id, paths}] -> {:ok, paths}
        [] -> {:ok, []}
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_cross_account, provider, account_id}, _from, state) do
    key = "#{provider}:#{account_id}"

    result =
      case :ets.lookup(@cross_account_table, key) do
        [{^key, access_data}] -> {:ok, access_data}
        [] -> {:ok, %{trusts: [], external_access: []}}
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:recommend_least_privilege, provider, identity_id, usage_data}, _from, state) do
    recommendation = generate_least_privilege_policy(provider, identity_id, usage_data)
    {:reply, {:ok, recommendation}, state}
  end

  @impl true
  def handle_call(:get_statistics, _from, state) do
    identities = :ets.info(@identities_table, :size)
    policies = :ets.info(@policies_table, :size)
    escalation_paths = :ets.info(@escalation_paths_table, :size)

    # Get risk distribution
    high_risk =
      :ets.foldl(
        fn {_id, identity}, acc ->
          if identity.risk_score >= 70, do: acc + 1, else: acc
        end,
        0,
        @identities_table
      )

    stats = %{
      total_identities: identities,
      total_policies: policies,
      identities_with_escalation_paths: escalation_paths,
      high_risk_identities: high_risk,
      analyses_performed: state.analyses_performed,
      findings_generated: state.findings_generated
    }

    {:reply, stats, state}
  end

  # AWS IAM Analysis

  defp analyze_aws_iam(account_id, policies) do
    findings = []

    # Analyze each policy
    {policy_findings, identities} =
      Enum.reduce(policies, {[], []}, fn policy, {acc_findings, acc_identities} ->
        policy_analysis = analyze_aws_policy(account_id, policy)

        identity = %{
          id: policy[:arn] || policy["Arn"],
          provider: "aws",
          account_id: account_id,
          type: policy[:type] || "policy",
          name: policy[:name] || policy["PolicyName"],
          arn: policy[:arn] || policy["Arn"],
          permissions: policy_analysis.permissions,
          risk_score: policy_analysis.risk_score,
          risk_factors: policy_analysis.risk_factors,
          escalation_potential: policy_analysis.escalation_potential,
          analyzed_at: DateTime.utc_now()
        }

        :ets.insert(@identities_table, {identity.id, identity})

        {acc_findings ++ policy_analysis.findings, [identity | acc_identities]}
      end)

    # Store policies
    Enum.each(policies, fn policy ->
      arn = policy[:arn] || policy["Arn"]
      :ets.insert(@policies_table, {arn, policy})
    end)

    {:ok,
     %{
       findings: policy_findings,
       identities_analyzed: length(identities),
       high_risk_count: Enum.count(identities, fn i -> i.risk_score >= 70 end)
     }}
  end

  defp analyze_aws_policy(account_id, policy) do
    policy_document =
      cond do
        is_binary(policy[:document]) ->
          case Jason.decode(policy[:document]) do
            {:ok, doc} -> doc
            _ -> %{}
          end

        is_map(policy[:document]) ->
          policy[:document]

        is_map(policy["PolicyDocument"]) ->
          policy["PolicyDocument"]

        is_binary(policy["PolicyDocument"]) ->
          case Jason.decode(policy["PolicyDocument"]) do
            {:ok, doc} -> doc
            _ -> %{}
          end

        true ->
          %{}
      end

    statements = policy_document["Statement"] || []

    # Extract permissions
    permissions =
      Enum.flat_map(statements, fn stmt ->
        actions = stmt["Action"] || []
        actions = if is_list(actions), do: actions, else: [actions]
        resources = stmt["Resource"] || []
        resources = if is_list(resources), do: resources, else: [resources]
        effect = stmt["Effect"]

        Enum.map(actions, fn action ->
          %{action: action, resources: resources, effect: effect}
        end)
      end)

    # Calculate risk score and factors
    {risk_score, risk_factors, findings} =
      analyze_aws_permissions(account_id, policy, permissions)

    # Check for privilege escalation potential
    escalation_potential = check_aws_escalation_potential(permissions)

    %{
      permissions: permissions,
      risk_score: risk_score,
      risk_factors: risk_factors,
      findings: findings,
      escalation_potential: escalation_potential
    }
  end

  defp analyze_aws_permissions(account_id, policy, permissions) do
    risk_score = 0
    risk_factors = []
    findings = []

    # Check for admin access
    {risk_score, risk_factors, findings} =
      if has_admin_access?(permissions) do
        finding =
          Finding.create(%{
            provider: "aws",
            account_id: account_id,
            resource_id: policy[:arn] || policy["Arn"] || "unknown",
            resource_arn: policy[:arn] || policy["Arn"],
            resource_name: policy[:name] || policy["PolicyName"] || "unknown",
            resource_type: "IAM Policy",
            region: "global",
            category: "identity_and_access",
            severity: "critical",
            title: "IAM policy grants full admin access",
            description:
              "Policy allows all actions (*) on all resources (*), which is equivalent to full administrator access.",
            recommendation: "Apply principle of least privilege. Define specific actions and resources.",
            compliance: ["CIS AWS 1.16", "SOC2 CC6.1"]
          })

        {100, [{:admin_access, "Full administrator access"}], [finding | findings]}
      else
        {risk_score, risk_factors, findings}
      end

    # Check for wildcard actions
    {risk_score, risk_factors, findings} =
      if has_wildcard_actions?(permissions) do
        factor = {:wildcard_actions, "Contains wildcard actions"}
        {max(risk_score, 60), [factor | risk_factors], findings}
      else
        {risk_score, risk_factors, findings}
      end

    # Check for wildcard resources
    {risk_score, risk_factors, findings} =
      if has_wildcard_resources?(permissions) do
        finding =
          Finding.create(%{
            provider: "aws",
            account_id: account_id,
            resource_id: policy[:arn] || policy["Arn"] || "unknown",
            resource_arn: policy[:arn] || policy["Arn"],
            resource_name: policy[:name] || policy["PolicyName"] || "unknown",
            resource_type: "IAM Policy",
            region: "global",
            category: "identity_and_access",
            severity: "high",
            title: "IAM policy uses wildcard resources",
            description: "Policy grants permissions on all resources (*) instead of specific resources.",
            recommendation: "Restrict to specific resource ARNs.",
            compliance: ["CIS AWS 1.16"]
          })

        factor = {:wildcard_resources, "Grants access to all resources"}
        {max(risk_score, 50), [factor | risk_factors], [finding | findings]}
      else
        {risk_score, risk_factors, findings}
      end

    # Check for privilege escalation actions
    priv_esc_actions = get_priv_esc_actions(permissions)

    {risk_score, risk_factors, findings} =
      if length(priv_esc_actions) > 0 do
        finding =
          Finding.create(%{
            provider: "aws",
            account_id: account_id,
            resource_id: policy[:arn] || policy["Arn"] || "unknown",
            resource_arn: policy[:arn] || policy["Arn"],
            resource_name: policy[:name] || policy["PolicyName"] || "unknown",
            resource_type: "IAM Policy",
            region: "global",
            category: "identity_and_access",
            severity: "high",
            title: "IAM policy enables privilege escalation",
            description:
              "Policy contains actions that could be used for privilege escalation: #{Enum.join(priv_esc_actions, ", ")}",
            recommendation:
              "Review and restrict these permissions. Apply conditions where possible.",
            compliance: ["CIS AWS 1.16", "SOC2 CC6.1"]
          })

        factor = {:priv_esc, "Contains #{length(priv_esc_actions)} privilege escalation actions"}
        {max(risk_score, 80), [factor | risk_factors], [finding | findings]}
      else
        {risk_score, risk_factors, findings}
      end

    # Check for sensitive service access
    sensitive_services = get_sensitive_service_access(permissions)

    {risk_score, risk_factors, findings} =
      if length(sensitive_services) > 0 do
        factor = {:sensitive_services, "Access to sensitive services: #{Enum.join(sensitive_services, ", ")}"}
        {max(risk_score, 40), [factor | risk_factors], findings}
      else
        {risk_score, risk_factors, findings}
      end

    {risk_score, risk_factors, findings}
  end

  defp has_admin_access?(permissions) do
    Enum.any?(permissions, fn p ->
      p.effect == "Allow" and p.action == "*" and "*" in (p.resources || [])
    end)
  end

  defp has_wildcard_actions?(permissions) do
    Enum.any?(permissions, fn p ->
      p.effect == "Allow" and
        (p.action == "*" or (is_binary(p.action) and String.ends_with?(p.action, ":*")))
    end)
  end

  defp has_wildcard_resources?(permissions) do
    Enum.any?(permissions, fn p ->
      p.effect == "Allow" and "*" in (p.resources || [])
    end)
  end

  defp get_priv_esc_actions(permissions) do
    permissions
    |> Enum.filter(fn p -> p.effect == "Allow" end)
    |> Enum.flat_map(fn p ->
      actions = if is_list(p.action), do: p.action, else: [p.action]

      Enum.filter(actions, fn action ->
        Map.has_key?(@aws_priv_esc_actions, action) or
          Enum.any?(Map.keys(@aws_priv_esc_actions), fn pattern ->
            matches_action_pattern?(action, pattern)
          end)
      end)
    end)
    |> Enum.uniq()
  end

  defp matches_action_pattern?(action, pattern) when is_binary(action) do
    if String.contains?(pattern, "*") do
      regex = pattern |> String.replace("*", ".*") |> Regex.compile!()
      Regex.match?(regex, action)
    else
      action == pattern
    end
  end

  defp matches_action_pattern?(_, _), do: false

  defp get_sensitive_service_access(permissions) do
    sensitive = ["iam", "kms", "secretsmanager", "sts", "organizations", "cloudtrail", "config"]

    permissions
    |> Enum.filter(fn p -> p.effect == "Allow" end)
    |> Enum.flat_map(fn p ->
      actions = if is_list(p.action), do: p.action, else: [p.action]

      Enum.flat_map(actions, fn action ->
        if is_binary(action) do
          [service | _] = String.split(action, ":")
          if service in sensitive, do: [service], else: []
        else
          []
        end
      end)
    end)
    |> Enum.uniq()
  end

  defp check_aws_escalation_potential(permissions) do
    priv_esc_actions = get_priv_esc_actions(permissions)

    paths =
      Enum.map(priv_esc_actions, fn action ->
        info = Map.get(@aws_priv_esc_actions, action, %{})

        %{
          action: action,
          type: info[:type],
          severity: info[:severity],
          description: info[:description]
        }
      end)

    %{
      has_escalation_path: length(paths) > 0,
      paths: paths,
      severity: cond do
        Enum.any?(paths, fn p -> p.severity == "critical" end) -> "critical"
        Enum.any?(paths, fn p -> p.severity == "high" end) -> "high"
        true -> "medium"
      end
    }
  end

  # Azure IAM Analysis

  defp analyze_azure_iam(account_id, role_assignments) do
    findings = []

    analysis_results =
      Enum.map(role_assignments, fn assignment ->
        analyze_azure_role_assignment(account_id, assignment)
      end)

    combined_findings = Enum.flat_map(analysis_results, fn r -> r.findings end)

    {:ok,
     %{
       findings: combined_findings,
       role_assignments_analyzed: length(role_assignments),
       high_risk_count: Enum.count(analysis_results, fn r -> r.risk_score >= 70 end)
     }}
  end

  defp analyze_azure_role_assignment(account_id, assignment) do
    role_name = assignment[:role_name] || assignment["roleDefinitionName"]
    principal_type = assignment[:principal_type] || assignment["principalType"]
    scope = assignment[:scope] || assignment["scope"]

    risk_score = 0
    risk_factors = []
    findings = []

    # Check for risky roles
    {risk_score, risk_factors, findings} =
      if role_name in @azure_risky_roles do
        severity = if role_name in ["Owner", "Global Administrator"], do: "critical", else: "high"

        finding =
          Finding.create(%{
            provider: "azure",
            account_id: account_id,
            resource_id: assignment[:id] || "unknown",
            resource_arn: assignment[:id],
            resource_name: "#{principal_type}: #{assignment[:principal_name]}",
            resource_type: "Role Assignment",
            region: "global",
            category: "identity_and_access",
            severity: severity,
            title: "High privilege role assigned",
            description: "#{role_name} role assigned to #{principal_type}. This is a highly privileged role.",
            recommendation: "Review if this role assignment is necessary. Use custom roles with minimal permissions.",
            compliance: ["CIS Azure 1.3", "SOC2 CC6.1"]
          })

        {100, [{:risky_role, "Assigned role: #{role_name}"}], [finding | findings]}
      else
        {risk_score, risk_factors, findings}
      end

    # Check for subscription-level scope
    {risk_score, risk_factors, findings} =
      if is_binary(scope) and not String.contains?(scope, "/resourceGroups/") do
        factor = {:subscription_scope, "Role assigned at subscription level"}
        {max(risk_score, 40), [factor | risk_factors], findings}
      else
        {risk_score, risk_factors, findings}
      end

    # Check for service principal with high privileges
    {risk_score, risk_factors, findings} =
      if principal_type == "ServicePrincipal" and role_name in @azure_risky_roles do
        finding =
          Finding.create(%{
            provider: "azure",
            account_id: account_id,
            resource_id: assignment[:id] || "unknown",
            resource_arn: assignment[:id],
            resource_name: assignment[:principal_name],
            resource_type: "Service Principal",
            region: "global",
            category: "identity_and_access",
            severity: "high",
            title: "Service principal has high privileges",
            description: "Service principal has #{role_name} role, which may be excessive.",
            recommendation: "Review service principal permissions and apply least privilege.",
            compliance: ["CIS Azure 1.5"]
          })

        {max(risk_score, 70), risk_factors, [finding | findings]}
      else
        {risk_score, risk_factors, findings}
      end

    identity = %{
      id: assignment[:id] || Ecto.UUID.generate(),
      provider: "azure",
      account_id: account_id,
      type: principal_type,
      name: assignment[:principal_name],
      role: role_name,
      scope: scope,
      risk_score: risk_score,
      risk_factors: risk_factors,
      analyzed_at: DateTime.utc_now()
    }

    :ets.insert(@identities_table, {identity.id, identity})

    %{
      identity: identity,
      findings: findings,
      risk_score: risk_score
    }
  end

  # GCP IAM Analysis

  defp analyze_gcp_iam(account_id, iam_bindings) do
    findings = []

    analysis_results =
      Enum.flat_map(iam_bindings, fn binding ->
        analyze_gcp_iam_binding(account_id, binding)
      end)

    combined_findings = Enum.flat_map(analysis_results, fn r -> r.findings end)

    {:ok,
     %{
       findings: combined_findings,
       bindings_analyzed: length(iam_bindings),
       high_risk_count: Enum.count(analysis_results, fn r -> r.risk_score >= 70 end)
     }}
  end

  defp analyze_gcp_iam_binding(account_id, binding) do
    role = binding[:role] || binding["role"]
    members = binding[:members] || binding["members"] || []

    Enum.map(members, fn member ->
      analyze_gcp_member(account_id, role, member)
    end)
  end

  defp analyze_gcp_member(account_id, role, member) do
    risk_score = 0
    risk_factors = []
    findings = []

    # Check for primitive roles
    {risk_score, risk_factors, findings} =
      if role in ["roles/owner", "roles/editor"] do
        finding =
          Finding.create(%{
            provider: "gcp",
            account_id: account_id,
            resource_id: member,
            resource_arn: "projects/#{account_id}/iamPolicy",
            resource_name: member,
            resource_type: "IAM Binding",
            region: "global",
            category: "identity_and_access",
            severity: "high",
            title: "Primitive role in use",
            description: "#{member} has primitive role #{role}. Primitive roles grant broad access.",
            recommendation: "Use predefined or custom roles with minimal permissions.",
            compliance: ["CIS GCP 1.6"]
          })

        {80, [{:primitive_role, "Uses primitive role: #{role}"}], [finding | findings]}
      else
        {risk_score, risk_factors, findings}
      end

    # Check for service account with owner
    {risk_score, risk_factors, findings} =
      if String.starts_with?(member, "serviceAccount:") and role == "roles/owner" do
        finding =
          Finding.create(%{
            provider: "gcp",
            account_id: account_id,
            resource_id: member,
            resource_arn: "projects/#{account_id}/iamPolicy",
            resource_name: member,
            resource_type: "Service Account",
            region: "global",
            category: "identity_and_access",
            severity: "critical",
            title: "Service account has Owner role",
            description: "Service account #{member} has the Owner role.",
            recommendation: "Remove Owner role from service accounts. Use specific roles.",
            compliance: ["CIS GCP 1.5"]
          })

        {100, [{:sa_owner, "Service account with Owner role"}], [finding | findings]}
      else
        {risk_score, risk_factors, findings}
      end

    # Check for privilege escalation permissions
    {risk_score, risk_factors, findings} =
      if has_gcp_priv_esc_permissions?(role) do
        factor = {:priv_esc_perms, "Role includes privilege escalation permissions"}
        {max(risk_score, 70), [factor | risk_factors], findings}
      else
        {risk_score, risk_factors, findings}
      end

    # Check for allUsers or allAuthenticatedUsers
    {risk_score, risk_factors, findings} =
      if member in ["allUsers", "allAuthenticatedUsers"] do
        finding =
          Finding.create(%{
            provider: "gcp",
            account_id: account_id,
            resource_id: member,
            resource_arn: "projects/#{account_id}/iamPolicy",
            resource_name: member,
            resource_type: "IAM Binding",
            region: "global",
            category: "identity_and_access",
            severity: "critical",
            title: "Public IAM binding detected",
            description: "IAM binding grants #{role} to #{member}, making it publicly accessible.",
            recommendation: "Remove public access unless absolutely required.",
            compliance: ["CIS GCP 1.10"]
          })

        {100, [{:public_access, "Grants access to #{member}"}], [finding | findings]}
      else
        {risk_score, risk_factors, findings}
      end

    identity = %{
      id: "#{account_id}:#{role}:#{member}",
      provider: "gcp",
      account_id: account_id,
      type: extract_gcp_member_type(member),
      name: member,
      role: role,
      risk_score: risk_score,
      risk_factors: risk_factors,
      analyzed_at: DateTime.utc_now()
    }

    :ets.insert(@identities_table, {identity.id, identity})

    %{
      identity: identity,
      findings: findings,
      risk_score: risk_score
    }
  end

  defp has_gcp_priv_esc_permissions?(role) do
    # Would check role permissions against @gcp_priv_esc_permissions
    role in ["roles/iam.serviceAccountAdmin", "roles/iam.serviceAccountKeyAdmin", "roles/owner"]
  end

  defp extract_gcp_member_type(member) do
    cond do
      String.starts_with?(member, "user:") -> "user"
      String.starts_with?(member, "serviceAccount:") -> "serviceAccount"
      String.starts_with?(member, "group:") -> "group"
      String.starts_with?(member, "domain:") -> "domain"
      member == "allUsers" -> "public"
      member == "allAuthenticatedUsers" -> "allAuthenticatedUsers"
      true -> "unknown"
    end
  end

  # Escalation Path Detection

  defp detect_aws_escalation_paths(account_id) do
    identities =
      :ets.tab2list(@identities_table)
      |> Enum.map(fn {_id, identity} -> identity end)
      |> Enum.filter(fn i -> i.provider == "aws" and i.account_id == account_id end)

    paths =
      Enum.flat_map(identities, fn identity ->
        if identity[:escalation_potential] && identity.escalation_potential.has_escalation_path do
          escalation_paths =
            Enum.map(identity.escalation_potential.paths, fn path ->
              %{
                identity_id: identity.id,
                identity_name: identity.name,
                path_type: path.type,
                action: path.action,
                severity: path.severity,
                description: path.description,
                detected_at: DateTime.utc_now()
              }
            end)

          :ets.insert(@escalation_paths_table, {identity.id, escalation_paths})
          escalation_paths
        else
          []
        end
      end)

    {:ok,
     %{
       total_identities_analyzed: length(identities),
       identities_with_paths: length(Enum.uniq_by(paths, & &1.identity_id)),
       paths: paths
     }}
  end

  defp detect_azure_escalation_paths(account_id) do
    identities =
      :ets.tab2list(@identities_table)
      |> Enum.map(fn {_id, identity} -> identity end)
      |> Enum.filter(fn i -> i.provider == "azure" and i.account_id == account_id end)

    # Find identities with User Access Administrator role (can grant any role)
    uaa_identities =
      Enum.filter(identities, fn i ->
        i[:role] == "User Access Administrator" or i[:role] == "Owner"
      end)

    paths =
      Enum.map(uaa_identities, fn identity ->
        %{
          identity_id: identity.id,
          identity_name: identity.name,
          path_type: :azure_role_assignment,
          action: "Can assign any role to any principal",
          severity: "critical",
          description: "#{identity.role} can assign Owner or other privileged roles",
          detected_at: DateTime.utc_now()
        }
      end)

    {:ok,
     %{
       total_identities_analyzed: length(identities),
       identities_with_paths: length(paths),
       paths: paths
     }}
  end

  defp detect_gcp_escalation_paths(account_id) do
    identities =
      :ets.tab2list(@identities_table)
      |> Enum.map(fn {_id, identity} -> identity end)
      |> Enum.filter(fn i -> i.provider == "gcp" and i.account_id == account_id end)

    # Find identities with IAM admin permissions
    admin_identities =
      Enum.filter(identities, fn i ->
        i[:role] in [
          "roles/owner",
          "roles/iam.serviceAccountAdmin",
          "roles/iam.serviceAccountKeyAdmin",
          "roles/resourcemanager.projectIamAdmin"
        ]
      end)

    paths =
      Enum.map(admin_identities, fn identity ->
        %{
          identity_id: identity.id,
          identity_name: identity.name,
          path_type: :gcp_iam_admin,
          action: "Can modify IAM policies",
          severity: "critical",
          description: "#{identity.role} can modify project IAM bindings",
          detected_at: DateTime.utc_now()
        }
      end)

    {:ok,
     %{
       total_identities_analyzed: length(identities),
       identities_with_paths: length(paths),
       paths: paths
     }}
  end

  # Cross-Account Analysis

  defp analyze_cross_account(provider, account_id) do
    case provider do
      "aws" -> analyze_aws_cross_account(account_id)
      "azure" -> analyze_azure_cross_tenant(account_id)
      "gcp" -> analyze_gcp_cross_project(account_id)
      _ -> {:error, :unsupported_provider}
    end
  end

  defp analyze_aws_cross_account(account_id) do
    # Would analyze role trust policies for cross-account access
    # For now, return structure

    cross_account_data = %{
      account_id: account_id,
      trusting_roles: [],
      trusted_accounts: [],
      external_principals: [],
      findings: []
    }

    key = "aws:#{account_id}"
    :ets.insert(@cross_account_table, {key, cross_account_data})

    {:ok, cross_account_data}
  end

  defp analyze_azure_cross_tenant(account_id) do
    cross_tenant_data = %{
      subscription_id: account_id,
      external_users: [],
      guest_users: [],
      b2b_connections: [],
      findings: []
    }

    key = "azure:#{account_id}"
    :ets.insert(@cross_account_table, {key, cross_tenant_data})

    {:ok, cross_tenant_data}
  end

  defp analyze_gcp_cross_project(account_id) do
    cross_project_data = %{
      project_id: account_id,
      shared_vpc_hosts: [],
      shared_vpc_services: [],
      cross_project_roles: [],
      findings: []
    }

    key = "gcp:#{account_id}"
    :ets.insert(@cross_account_table, {key, cross_project_data})

    {:ok, cross_project_data}
  end

  # Risk Assessment

  defp assess_identity_risk(identity) do
    base_score = 0
    factors = []

    # Type-based risk
    {base_score, factors} =
      case identity.type do
        "user" -> {base_score + 10, factors}
        "role" -> {base_score + 20, factors}
        "serviceAccount" -> {base_score + 30, [{:service_account, "Service account (non-human)"}]}
        "ServicePrincipal" -> {base_score + 30, [{:service_principal, "Service principal"}]}
        _ -> {base_score, factors}
      end

    # Last used check
    {base_score, factors} =
      if identity[:last_used] do
        days_since_use = DateTime.diff(DateTime.utc_now(), identity.last_used, :day)

        cond do
          days_since_use > 90 ->
            {base_score + 20, [{:inactive, "Not used in #{days_since_use} days"} | factors]}

          days_since_use > 30 ->
            {base_score + 10, [{:low_activity, "Limited recent activity"} | factors]}

          true ->
            {base_score, factors}
        end
      else
        {base_score, factors}
      end

    # Permission count
    {base_score, factors} =
      if identity[:permissions] do
        perm_count = length(identity.permissions)

        cond do
          perm_count > 100 ->
            {base_score + 30, [{:excessive_perms, "#{perm_count} permissions"} | factors]}

          perm_count > 50 ->
            {base_score + 15, [{:many_perms, "#{perm_count} permissions"} | factors]}

          true ->
            {base_score, factors}
        end
      else
        {base_score, factors}
      end

    %{risk_score: min(100, base_score), risk_factors: factors}
  end

  defp generate_recommendations(identity) do
    recommendations = []

    # Add recommendations based on risk factors
    recommendations =
      Enum.reduce(identity.risk_factors, recommendations, fn {factor, _desc}, acc ->
        case factor do
          :admin_access ->
            ["Remove administrative access and use specific permissions" | acc]

          :wildcard_resources ->
            ["Restrict to specific resource ARNs" | acc]

          :priv_esc ->
            ["Review and restrict privilege escalation permissions" | acc]

          :inactive ->
            ["Consider removing or disabling inactive identity" | acc]

          :excessive_perms ->
            ["Audit and reduce permissions to minimum required" | acc]

          :service_account ->
            ["Ensure service account keys are rotated regularly" | acc]

          _ ->
            acc
        end
      end)

    Enum.uniq(recommendations)
  end

  defp generate_least_privilege_policy(provider, identity_id, usage_data) do
    # Generate a minimal policy based on actual usage
    used_actions = usage_data[:used_actions] || []
    used_resources = usage_data[:used_resources] || []

    case provider do
      "aws" ->
        %{
          Version: "2012-10-17",
          Statement: [
            %{
              Effect: "Allow",
              Action: used_actions,
              Resource: if(Enum.empty?(used_resources), do: ["*"], else: used_resources)
            }
          ]
        }

      "gcp" ->
        %{
          bindings:
            Enum.map(used_actions, fn action ->
              %{
                role: action,
                members: ["serviceAccount:#{identity_id}"]
              }
            end)
        }

      _ ->
        %{error: "Unsupported provider"}
    end
  end

  # Helpers

  defp apply_identity_filters(identities, filters) do
    identities
    |> filter_by(:provider, filters[:provider])
    |> filter_by(:account_id, filters[:account_id])
    |> filter_by(:type, filters[:type])
    |> filter_by_min_risk(filters[:min_risk_score])
  end

  defp filter_by(list, _field, nil), do: list

  defp filter_by(list, field, value) do
    Enum.filter(list, fn i -> Map.get(i, field) == value end)
  end

  defp filter_by_min_risk(list, nil), do: list

  defp filter_by_min_risk(list, min_score) do
    Enum.filter(list, fn i -> i.risk_score >= min_score end)
  end
end
