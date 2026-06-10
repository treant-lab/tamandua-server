# IAM Role Analysis Implementation

## Overview

Implemented real IAM policy evaluation for privilege escalation detection in Lambda functions. The `do_analyze_iam_role/1` function now performs comprehensive security analysis of AWS IAM roles.

## Implementation Details

### File
`apps/tamandua_server/lib/tamandua_server/serverless/lambda.ex`

### Function
`do_analyze_iam_role/1` (lines 960-1001)

### What Changed

**Before:**
- Returned hardcoded mock data with all zeros
- No real policy analysis
- No privilege escalation detection

**After:**
- Fetches real IAM policies via ExAws.IAM (when available)
- Parses policy document JSON
- Analyzes permissions against dangerous_permissions list
- Calculates risk score based on multiple factors
- Detects overprivileged roles
- Identifies privilege escalation vectors

## Features

### 1. Policy Fetching
- Fetches both inline and managed policies attached to the role
- Uses ExAws.IAM conditionally (graceful degradation if not available)
- Retrieves policy documents and parses JSON
- Handles both inline role policies and attached managed policies

### 2. Permission Analysis

**Dangerous Permissions Checked:**
- `iam:*` or `*:*` (wildcard permissions)
- IAM privilege escalation vectors (PutUserPolicy, AttachUserPolicy, etc.)
- Lambda manipulation (UpdateFunctionCode, InvokeFunction)
- Data access (secretsmanager:GetSecretValue, ssm:GetParameter, kms:Decrypt)
- EC2 escalation (RunInstances, CreateSnapshot)
- STS role assumption (AssumeRole)

**Privilege Escalation Vectors (24 specific permissions):**
- IAM: PutUserPolicy, AttachRolePolicy, CreateAccessKey, PassRole, etc.
- Lambda: CreateFunction, UpdateFunctionCode, UpdateFunctionConfiguration
- EC2: RunInstances, ModifyInstanceAttribute
- STS: AssumeRole
- Secrets: GetSecretValue, GetParameter, Decrypt

### 3. Risk Scoring (0-100)

The risk score is calculated based on:
- **Dangerous permissions**: +5 points each (max 40)
- **Privilege escalation vectors**: +10 points each (max 30)
- **Admin policies**: Automatic 100 points
- **Unrestricted resources**: +20 points each (max 20)
- **Wildcard permissions** (`*:*`): Automatic 90+ points

### 4. Overprivileged Detection

A role is flagged as overprivileged if:
- Risk score >= 70
- Has admin policies (AdministratorAccess, PowerUserAccess)
- Has wildcard permissions (`*:*`)

### 5. Admin Policy Detection

Checks for:
- `arn:aws:iam::aws:policy/AdministratorAccess`
- `arn:aws:iam::aws:policy/PowerUserAccess`
- Policies matching `/Admin/i` or `/FullAccess/i` patterns

### 6. Unrestricted Resource Analysis

Detects when dangerous permissions apply to all resources (`Resource: "*"`)

## Output Format

```elixir
{:ok, %{
  role_arn: "arn:aws:iam::123456789012:role/MyLambdaRole",
  role_name: "MyLambdaRole",
  overprivileged: true,
  dangerous_permissions: [
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "lambda:UpdateFunctionCode"
  ],
  privilege_escalation_vectors: [
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy"
  ],
  unrestricted_resources: [
    "All resources (*) with dangerous permissions: iam:AttachRolePolicy, lambda:UpdateFunctionCode"
  ],
  admin_policies: [],
  risk_score: 85,
  policy_count: 3,
  recommendations: [
    "Role has privilege escalation vectors: iam:AttachRolePolicy, iam:PutRolePolicy. Review and restrict these permissions",
    "Restrict resource access from wildcard (*) to specific ARNs",
    "Role has 3 dangerous permissions. Apply principle of least privilege"
  ]
}}
```

## Error Handling

### When ExAws is not available:
- Logs debug message: "ExAws not available, skipping IAM policy fetch"
- Returns fallback response with risk_score: 0
- Includes recommendation to configure AWS credentials

### When invalid role ARN:
- Returns `{:error, :invalid_role_arn}`

### When AWS API fails:
- Catches exceptions and returns fallback analysis
- Logs warning with error details
- Includes error information in response

## Usage Example

```elixir
# Analyze a Lambda function's IAM role
{:ok, function} = TamanduaServer.Serverless.Lambda.get_function("my-function-arn")
{:ok, analysis} = TamanduaServer.Serverless.Lambda.analyze_iam_role(function.role)

# Check results
if analysis.overprivileged do
  IO.puts "WARNING: Role is overprivileged (risk score: #{analysis.risk_score})"
  IO.puts "Escalation vectors: #{inspect(analysis.privilege_escalation_vectors)}"
  IO.puts "Recommendations:"
  Enum.each(analysis.recommendations, &IO.puts("  - #{&1}"))
end
```

## Integration with Function Security Analysis

The IAM analysis integrates with the broader function security analysis in `analyze_function_security/1` via the `check_iam_permissions/1` helper function (line 1032).

## Testing Approach

To test this implementation:

1. **With ExAws installed:**
   - Configure AWS credentials
   - Create test Lambda functions with various IAM roles
   - Roles to test:
     - Admin role (should score 100)
     - Minimal role (should score low)
     - Role with privilege escalation vectors (should flag)
     - Role with wildcard resources (should flag)

2. **Without ExAws:**
   - Should gracefully degrade
   - Should return error information
   - Should not crash

## Security Considerations

This implementation follows AWS IAM security best practices:
- Detects 14+ privilege escalation techniques from Rhino Security Labs research
- Checks for AWS-managed admin policies
- Identifies wildcard resource access
- Flags unrestricted IAM permissions
- Provides actionable remediation recommendations

## Future Enhancements

Potential improvements:
1. Add more privilege escalation vectors (IAM has 20+ known techniques)
2. Integrate with AWS Access Analyzer findings
3. Check for cross-account trust relationships
4. Analyze condition statements in policies
5. Compare against AWS Well-Architected Framework
6. Add policy simulation via `iam:SimulatePrincipalPolicy`

## References

- AWS IAM Privilege Escalation Techniques: https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- AWS Security Best Practices: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- MITRE ATT&CK Cloud Matrix: T1078.004 (Valid Accounts: Cloud Accounts)
