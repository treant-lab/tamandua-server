defmodule TamanduaServer.Integrations.SIEM.SentinelDataConnector do
  @moduledoc """
  Azure Sentinel Data Connector registration and management.

  Registers Tamandua EDR as a custom data connector in Azure Sentinel,
  enabling automatic alert ingestion and correlation with other security data.

  ## Features

  - `register_connector/1` - Register Tamandua as a Data Connector
  - `unregister_connector/1` - Remove the Data Connector registration
  - `get_connector_status/1` - Check connection health and sync status
  - `create_analytics_rule/2` - Create detection rules for alert patterns
  - `list_analytics_rules/1` - List Tamandua-related analytics rules
  - `install_default_rules/1` - Install predefined analytics rules

  Uses Azure Management API with OAuth2 authentication.
  """

  require Logger

  alias TamanduaServer.Integrations.IntegrationLog

  @sentinel_api_version "2022-11-01"
  @azure_login_url "https://login.microsoftonline.com"
  @management_url "https://management.azure.com"
  @default_timeout_ms 30_000
  @connector_name "Tamandua-EDR-Connector"

  # Tamandua connector definition for Azure Sentinel
  @connector_definition %{
    kind: "APIPolling",
    properties: %{
      connectorUiConfig: %{
        title: "Tamandua EDR",
        publisher: "Tamandua",
        descriptionMarkdown: "Connect to Tamandua EDR to ingest endpoint security alerts, AI/ML model threats, and behavioral detections into Microsoft Sentinel.",
        graphQueries: [
          %{
            metricName: "Total alerts received",
            legend: "TamanduaEDR_CL"
          }
        ],
        dataTypes: [
          %{
            name: "TamanduaEDR_CL",
            lastDataReceivedQuery: "TamanduaEDR_CL | summarize max(TimeGenerated)"
          },
          %{
            name: "TamanduaSecurityAlert_CL",
            lastDataReceivedQuery: "TamanduaSecurityAlert_CL | summarize max(TimeGenerated)"
          }
        ],
        connectivityCriteria: [
          %{
            type: "IsConnectedQuery",
            value: ["TamanduaEDR_CL | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)"]
          }
        ],
        availability: %{
          status: 1,
          isPreview: false
        },
        permissions: %{
          resourceProvider: [
            %{
              provider: "Microsoft.OperationalInsights/workspaces",
              permissionsDisplayText: "read and write permissions are required.",
              providerDisplayName: "Workspace",
              scope: "Workspace",
              requiredPermissions: %{
                write: true,
                read: true,
                delete: true
              }
            }
          ]
        },
        instructionSteps: [
          %{
            title: "Connect Tamandua EDR",
            description: "Configure your Tamandua EDR server to send alerts to Microsoft Sentinel using the Log Analytics Data Collector API.",
            instructions: [
              %{
                type: "Basic",
                parameters: %{
                  linkText: "Learn more",
                  linkUrl: "https://docs.treantlab.org/integrations/sentinel"
                }
              }
            ]
          }
        ]
      }
    }
  }

  # Default analytics rules for Tamandua alerts
  @default_analytics_rules [
    %{
      name: "Tamandua - Critical Security Alert",
      description: "Alert on critical severity detections from Tamandua EDR",
      query: """
      TamanduaEDR_CL
      | where Severity == "critical" or Severity == "Critical"
      | project TimeGenerated, AlertName, Description, Hostname, AgentId, Tactics, Techniques, ThreatScore
      """,
      severity: "High",
      enabled: true,
      query_frequency: "PT5M",
      query_period: "PT5M",
      trigger_operator: "GreaterThan",
      trigger_threshold: 0,
      tactics: ["Impact", "Execution"]
    },
    %{
      name: "Tamandua - Credential Access Detected",
      description: "Credential theft or dumping attempts detected by Tamandua EDR",
      query: """
      TamanduaEDR_CL
      | where Tactics contains "credential_access" or Techniques contains "T1003"
      | project TimeGenerated, AlertName, Description, Hostname, AgentId, Tactics, Techniques
      """,
      severity: "High",
      enabled: true,
      query_frequency: "PT5M",
      query_period: "PT5M",
      trigger_operator: "GreaterThan",
      trigger_threshold: 0,
      tactics: ["CredentialAccess"]
    },
    %{
      name: "Tamandua - Persistence Mechanism Detected",
      description: "Persistence techniques detected by Tamandua EDR",
      query: """
      TamanduaEDR_CL
      | where Tactics contains "persistence" or Techniques contains "T1547" or Techniques contains "T1543"
      | project TimeGenerated, AlertName, Description, Hostname, AgentId, Tactics, Techniques
      """,
      severity: "Medium",
      enabled: true,
      query_frequency: "PT15M",
      query_period: "PT15M",
      trigger_operator: "GreaterThan",
      trigger_threshold: 0,
      tactics: ["Persistence"]
    },
    %{
      name: "Tamandua - AI/ML Model Threat",
      description: "AI model security threats detected (backdoors, pickle exploits, etc.)",
      query: """
      TamanduaEDR_CL
      | where AlertName contains "model" or AlertName contains "pickle" or AlertName contains "backdoor" or AlertName contains "ML"
      | project TimeGenerated, AlertName, Description, Hostname, AgentId, ThreatScore
      """,
      severity: "High",
      enabled: true,
      query_frequency: "PT10M",
      query_period: "PT10M",
      trigger_operator: "GreaterThan",
      trigger_threshold: 0,
      tactics: ["Impact", "Execution"]
    },
    %{
      name: "Tamandua - High Threat Score Alert",
      description: "Alerts with threat score above 0.8 from Tamandua EDR",
      query: """
      TamanduaEDR_CL
      | where ThreatScore > 0.8
      | project TimeGenerated, AlertName, Description, Hostname, AgentId, ThreatScore, Severity
      """,
      severity: "High",
      enabled: true,
      query_frequency: "PT5M",
      query_period: "PT5M",
      trigger_operator: "GreaterThan",
      trigger_threshold: 0,
      tactics: ["Impact"]
    }
  ]

  @type config :: %{
          optional(:tenant_id) => String.t(),
          optional(:client_id) => String.t(),
          optional(:client_secret) => String.t(),
          optional(:subscription_id) => String.t(),
          optional(:resource_group) => String.t(),
          optional(:workspace_name) => String.t(),
          optional(:timeout_ms) => non_neg_integer()
        }

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Register Tamandua EDR as a Data Connector in Azure Sentinel.

  ## Parameters

  - `config` - Azure configuration with tenant_id, client_id, client_secret,
               subscription_id, resource_group, workspace_name

  ## Returns

  `{:ok, connector_id}` on success, `{:error, reason}` on failure.
  """
  @spec register_connector(config()) :: {:ok, String.t()} | {:error, term()}
  def register_connector(config) do
    with {:ok, token} <- get_azure_management_token(config) do
      connector_id = UUID.uuid4()

      url = build_connector_url(config, connector_id)

      body = Jason.encode!(@connector_definition)

      headers = [
        {"Authorization", "Bearer #{token}"},
        {"Content-Type", "application/json"}
      ]

      timeout = config[:timeout_ms] || @default_timeout_ms

      IntegrationLog.log_api_call("sentinel_connector", "register", connector_id, fn ->
        case do_http(:put, url, headers, body, timeout) do
          {:ok, %{status: status, body: resp_body}} when status in [200, 201] ->
            response = Jason.decode!(resp_body)
            {:ok, response["id"] || connector_id}

          {:ok, %{status: status, body: resp_body}} ->
            {:error, "Register connector failed: HTTP #{status} - #{truncate(resp_body)}"}

          {:error, reason} ->
            {:error, reason}
        end
      end)
    end
  end

  @doc """
  Remove the Tamandua Data Connector registration from Azure Sentinel.

  ## Parameters

  - `config` - Azure configuration

  ## Returns

  `:ok` on success, `{:error, reason}` on failure.
  """
  @spec unregister_connector(config()) :: :ok | {:error, term()}
  def unregister_connector(config) do
    with {:ok, token} <- get_azure_management_token(config) do
      url = build_connector_url(config, @connector_name)

      headers = [
        {"Authorization", "Bearer #{token}"}
      ]

      timeout = config[:timeout_ms] || @default_timeout_ms

      IntegrationLog.log_api_call("sentinel_connector", "unregister", nil, fn ->
        case do_http(:delete, url, headers, nil, timeout) do
          {:ok, %{status: status}} when status in 200..299 ->
            :ok

          {:ok, %{status: 404}} ->
            :ok  # Already deleted

          {:ok, %{status: status, body: resp_body}} ->
            {:error, "Unregister connector failed: HTTP #{status} - #{truncate(resp_body)}"}

          {:error, reason} ->
            {:error, reason}
        end
      end)
    end
  end

  @doc """
  Get the status of the Tamandua Data Connector.

  ## Parameters

  - `config` - Azure configuration

  ## Returns

  `{:ok, status}` with connection state and last sync time,
  `{:error, reason}` on failure.
  """
  @spec get_connector_status(config()) :: {:ok, map()} | {:error, term()}
  def get_connector_status(config) do
    with {:ok, token} <- get_azure_management_token(config) do
      url = build_connector_url(config, @connector_name)

      headers = [
        {"Authorization", "Bearer #{token}"}
      ]

      timeout = config[:timeout_ms] || @default_timeout_ms

      IntegrationLog.log_api_call("sentinel_connector", "status", nil, fn ->
        case do_http(:get, url, headers, nil, timeout) do
          {:ok, %{status: 200, body: resp_body}} ->
            response = Jason.decode!(resp_body)
            props = response["properties"] || %{}

            status = %{
              id: response["id"],
              name: response["name"],
              state: props["connectorState"] || "Unknown",
              last_data_received: props["lastDataReceivedOn"],
              data_types: get_in(props, ["connectorUiConfig", "dataTypes"]) || []
            }

            {:ok, status}

          {:ok, %{status: 404}} ->
            {:error, :not_found}

          {:ok, %{status: status, body: resp_body}} ->
            {:error, "Get connector status failed: HTTP #{status} - #{truncate(resp_body)}"}

          {:error, reason} ->
            {:error, reason}
        end
      end)
    end
  end

  @doc """
  Create an analytics rule in Azure Sentinel for Tamandua alerts.

  ## Parameters

  - `rule_config` - Rule configuration with name, description, query, severity
  - `config` - Azure configuration

  ## Returns

  `{:ok, rule_id}` on success, `{:error, reason}` on failure.
  """
  @spec create_analytics_rule(map(), config()) :: {:ok, String.t()} | {:error, term()}
  def create_analytics_rule(rule_config, config) do
    with {:ok, token} <- get_azure_management_token(config) do
      rule_id = UUID.uuid4()

      url = build_analytics_rule_url(config, rule_id)

      body = Jason.encode!(%{
        kind: "Scheduled",
        properties: %{
          displayName: rule_config[:name] || rule_config["name"],
          description: rule_config[:description] || rule_config["description"],
          severity: map_severity(rule_config[:severity] || rule_config["severity"]),
          enabled: rule_config[:enabled] != false,
          query: rule_config[:query] || rule_config["query"],
          queryFrequency: rule_config[:query_frequency] || "PT5M",
          queryPeriod: rule_config[:query_period] || "PT5M",
          triggerOperator: rule_config[:trigger_operator] || "GreaterThan",
          triggerThreshold: rule_config[:trigger_threshold] || 0,
          suppressionDuration: "PT1H",
          suppressionEnabled: false,
          tactics: rule_config[:tactics] || [],
          incidentConfiguration: %{
            createIncident: true,
            groupingConfiguration: %{
              enabled: true,
              reopenClosedIncident: false,
              lookbackDuration: "PT5H",
              matchingMethod: "AllEntities"
            }
          }
        }
      })

      headers = [
        {"Authorization", "Bearer #{token}"},
        {"Content-Type", "application/json"}
      ]

      timeout = config[:timeout_ms] || @default_timeout_ms

      IntegrationLog.log_api_call("sentinel_connector", "create_rule", rule_config[:name], fn ->
        case do_http(:put, url, headers, body, timeout) do
          {:ok, %{status: status, body: resp_body}} when status in [200, 201] ->
            response = Jason.decode!(resp_body)
            {:ok, response["id"] || rule_id}

          {:ok, %{status: status, body: resp_body}} ->
            {:error, "Create analytics rule failed: HTTP #{status} - #{truncate(resp_body)}"}

          {:error, reason} ->
            {:error, reason}
        end
      end)
    end
  end

  @doc """
  List all Tamandua-related analytics rules in Azure Sentinel.

  ## Parameters

  - `config` - Azure configuration

  ## Returns

  `{:ok, rules}` list of analytics rules, `{:error, reason}` on failure.
  """
  @spec list_analytics_rules(config()) :: {:ok, [map()]} | {:error, term()}
  def list_analytics_rules(config) do
    with {:ok, token} <- get_azure_management_token(config) do
      url = build_analytics_rules_list_url(config)

      headers = [
        {"Authorization", "Bearer #{token}"}
      ]

      timeout = config[:timeout_ms] || @default_timeout_ms

      IntegrationLog.log_api_call("sentinel_connector", "list_rules", nil, fn ->
        case do_http(:get, url, headers, nil, timeout) do
          {:ok, %{status: 200, body: resp_body}} ->
            response = Jason.decode!(resp_body)
            rules = response["value"] || []

            # Filter to only Tamandua rules
            tamandua_rules = Enum.filter(rules, fn rule ->
              name = get_in(rule, ["properties", "displayName"]) || rule["name"] || ""
              String.contains?(String.downcase(name), "tamandua")
            end)

            {:ok, tamandua_rules}

          {:ok, %{status: status, body: resp_body}} ->
            {:error, "List analytics rules failed: HTTP #{status} - #{truncate(resp_body)}"}

          {:error, reason} ->
            {:error, reason}
        end
      end)
    end
  end

  @doc """
  Get predefined default analytics rules for Tamandua alerts.

  Returns rules for:
  - Critical security alerts
  - Credential access detection
  - Persistence mechanism detection
  - AI/ML model threats
  - High threat score alerts

  ## Returns

  List of rule configuration maps.
  """
  @spec get_default_analytics_rules() :: [map()]
  def get_default_analytics_rules do
    @default_analytics_rules
  end

  @doc """
  Install all default analytics rules in Azure Sentinel.

  ## Parameters

  - `config` - Azure configuration

  ## Returns

  `{:ok, created_ids}` list of created rule IDs, `{:error, reason}` on failure.
  """
  @spec install_default_analytics_rules(config()) :: {:ok, [String.t()]} | {:error, term()}
  def install_default_analytics_rules(config) do
    results = @default_analytics_rules
    |> Enum.map(fn rule_def ->
      case create_analytics_rule(rule_def, config) do
        {:ok, rule_id} ->
          Logger.info("[SentinelDataConnector] Created analytics rule: #{rule_def.name}")
          {:ok, rule_id}

        {:error, reason} ->
          Logger.warning("[SentinelDataConnector] Failed to create rule #{rule_def.name}: #{inspect(reason)}")
          {:error, {rule_def.name, reason}}
      end
    end)

    created = results
    |> Enum.filter(&match?({:ok, _}, &1))
    |> Enum.map(fn {:ok, id} -> id end)

    if length(created) > 0 do
      {:ok, created}
    else
      {:error, :all_rules_failed}
    end
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp build_connector_url(config, connector_id) do
    "#{@management_url}/subscriptions/#{config[:subscription_id]}" <>
    "/resourceGroups/#{config[:resource_group]}" <>
    "/providers/Microsoft.OperationalInsights/workspaces/#{config[:workspace_name]}" <>
    "/providers/Microsoft.SecurityInsights/dataConnectors/#{connector_id}" <>
    "?api-version=#{@sentinel_api_version}"
  end

  defp build_analytics_rule_url(config, rule_id) do
    "#{@management_url}/subscriptions/#{config[:subscription_id]}" <>
    "/resourceGroups/#{config[:resource_group]}" <>
    "/providers/Microsoft.OperationalInsights/workspaces/#{config[:workspace_name]}" <>
    "/providers/Microsoft.SecurityInsights/alertRules/#{rule_id}" <>
    "?api-version=#{@sentinel_api_version}"
  end

  defp build_analytics_rules_list_url(config) do
    "#{@management_url}/subscriptions/#{config[:subscription_id]}" <>
    "/resourceGroups/#{config[:resource_group]}" <>
    "/providers/Microsoft.OperationalInsights/workspaces/#{config[:workspace_name]}" <>
    "/providers/Microsoft.SecurityInsights/alertRules" <>
    "?api-version=#{@sentinel_api_version}"
  end

  defp get_azure_management_token(config) do
    unless config[:tenant_id] && config[:client_id] && config[:client_secret] do
      {:error, :azure_credentials_not_configured}
    else
      url = "#{@azure_login_url}/#{config[:tenant_id]}/oauth2/v2.0/token"

      body = URI.encode_query(%{
        "client_id" => config[:client_id],
        "client_secret" => config[:client_secret],
        "scope" => "https://management.azure.com/.default",
        "grant_type" => "client_credentials"
      })

      headers = [{"Content-Type", "application/x-www-form-urlencoded"}]
      timeout = config[:timeout_ms] || @default_timeout_ms

      case do_http(:post, url, headers, body, timeout) do
        {:ok, %{status: 200, body: resp_body}} ->
          response = Jason.decode!(resp_body)
          {:ok, response["access_token"]}

        {:ok, %{status: status, body: resp_body}} ->
          {:error, "OAuth token failed: HTTP #{status} - #{truncate(resp_body)}"}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  defp map_severity("critical"), do: "High"
  defp map_severity("Critical"), do: "High"
  defp map_severity("high"), do: "High"
  defp map_severity("High"), do: "High"
  defp map_severity("medium"), do: "Medium"
  defp map_severity("Medium"), do: "Medium"
  defp map_severity("low"), do: "Low"
  defp map_severity("Low"), do: "Low"
  defp map_severity("info"), do: "Informational"
  defp map_severity("Informational"), do: "Informational"
  defp map_severity(_), do: "Medium"

  defp do_http(method, url, headers, body, timeout) do
    request = Finch.build(method, url, headers, body)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: timeout) do
      {:ok, %Finch.Response{status: status, body: resp_body}} ->
        {:ok, %{status: status, body: resp_body}}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp truncate(str) when is_binary(str) and byte_size(str) > 500 do
    String.slice(str, 0, 500) <> "..."
  end

  defp truncate(str) when is_binary(str), do: str
  defp truncate(other), do: inspect(other)
end
