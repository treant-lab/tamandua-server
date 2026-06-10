defmodule TamanduaServer.Alerts.SuppressionIntegrationExample do
  @moduledoc """
  Example integration of the Alert Suppression System in the detection flow.

  This module demonstrates how to integrate suppression checks when creating alerts
  from detection engine results.
  """

  alias TamanduaServer.Alerts
  alias TamanduaServer.Alerts.{SuppressionEngine, SuppressedAlert}
  alias TamanduaServer.Repo

  @doc """
  Create an alert with suppression check (recommended approach).

  This function checks suppression rules before creating the alert and takes
  appropriate action based on the result.

  ## Example

      alert_data = %{
        title: "Suspicious PowerShell Execution",
        description: "Encoded command detected",
        severity: "high",
        organization_id: org_id,
        agent_id: agent_id,
        evidence: %{
          process: %{
            name: "powershell.exe",
            command_line: "powershell -enc ..."
          }
        },
        mitre_techniques: ["T1059.001"],
        detection_metadata: %{
          rule_name: "EncodedPowerShell",
          confidence: 0.85
        }
      }

      context = %{
        user_email: "admin@example.com",
        source: "detection_engine"
      }

      create_alert_with_suppression(alert_data, context)

  ## Returns

  - `{:ok, :suppressed, suppressed_alert}` - Alert was suppressed
  - `{:ok, :created, alert}` - Alert was created normally
  - `{:ok, :severity_reduced, alert}` - Alert was created with reduced severity
  - `{:error, reason}` - Failed to create alert

  """
  @spec create_alert_with_suppression(map(), map()) ::
    {:ok, :suppressed | :created | :severity_reduced, struct()} | {:error, term()}
  def create_alert_with_suppression(alert_data, context \\ %{}) do
    # 1. Evaluate suppression rules
    case SuppressionEngine.evaluate_rules(alert_data, context) do
      :allow ->
        # No suppression - create alert normally
        case Alerts.create_alert(alert_data) do
          {:ok, alert} -> {:ok, :created, alert}
          error -> error
        end

      {:suppress, rule_id, reason} ->
        # Completely suppress - store in suppressed_alerts table
        suppression_details = %{
          reason: reason,
          type: "rule",
          rule_id: rule_id,
          user_id: context[:user_id]
        }

        case SuppressionEngine.store_suppressed_alert(alert_data, suppression_details) do
          {:ok, suppressed} -> {:ok, :suppressed, suppressed}
          error -> error
        end

      {:reduce_severity, new_severity, rule_id, reason} ->
        # Reduce severity and create alert
        original_severity = alert_data[:severity] || alert_data["severity"]

        updated_alert_data = alert_data
        |> Map.put(:severity, new_severity)
        |> Map.put(:detection_metadata,
          Map.merge(
            alert_data[:detection_metadata] || %{},
            %{
              severity_reduced: true,
              original_severity: original_severity,
              suppression_rule_id: rule_id,
              suppression_reason: reason
            }
          )
        )

        case Alerts.create_alert(updated_alert_data) do
          {:ok, alert} -> {:ok, :severity_reduced, alert}
          error -> error
        end

      {:tag, tags, rule_id, reason} ->
        # Add tags and create alert
        existing_tags = alert_data[:tags] || alert_data["tags"] || []
        new_tags = Enum.uniq(existing_tags ++ tags)

        updated_alert_data = alert_data
        |> Map.put(:tags, new_tags)
        |> Map.put(:detection_metadata,
          Map.merge(
            alert_data[:detection_metadata] || %{},
            %{
              auto_tagged: true,
              suppression_rule_id: rule_id,
              suppression_reason: reason
            }
          )
        )

        case Alerts.create_alert(updated_alert_data) do
          {:ok, alert} -> {:ok, :created, alert}
          error -> error
        end
    end
  end

  @doc """
  Batch process detection results with suppression.

  Useful for processing multiple detection results from Broadway pipeline.

  ## Example

      detection_results = [
        %{title: "Alert 1", severity: "high", ...},
        %{title: "Alert 2", severity: "medium", ...}
      ]

      results = batch_create_with_suppression(detection_results, org_id)
      # Returns: %{created: 5, suppressed: 3, severity_reduced: 2, errors: 0}
  """
  @spec batch_create_with_suppression([map()], String.t()) :: map()
  def batch_create_with_suppression(detection_results, organization_id, context \\ %{}) do
    detection_results
    |> Enum.map(fn result ->
      result
      |> Map.put(:organization_id, organization_id)
      |> create_alert_with_suppression(context)
    end)
    |> Enum.reduce(
      %{created: 0, suppressed: 0, severity_reduced: 0, errors: 0},
      fn result, acc ->
        case result do
          {:ok, :created, _} -> Map.update!(acc, :created, &(&1 + 1))
          {:ok, :suppressed, _} -> Map.update!(acc, :suppressed, &(&1 + 1))
          {:ok, :severity_reduced, _} -> Map.update!(acc, :severity_reduced, &(&1 + 1))
          {:error, _} -> Map.update!(acc, :errors, &(&1 + 1))
        end
      end
    )
  end

  @doc """
  Create suppression rule from a false positive alert.

  When an analyst marks an alert as false positive, this function can create
  a suppression rule to prevent similar alerts in the future.

  ## Example

      alert = Repo.get(Alert, alert_id)

      {:ok, rule} = create_rule_from_false_positive(alert, %{
        user_id: analyst_id,
        ttl_days: 30,
        action: "suppress",
        scope: :similar  # :similar or :exact
      })
  """
  @spec create_rule_from_false_positive(struct(), map()) :: {:ok, struct()} | {:error, term()}
  def create_rule_from_false_positive(alert, opts \\ %{}) do
    scope = Keyword.get(opts, :scope, :similar)
    user_id = Keyword.get(opts, :user_id)
    ttl_days = Keyword.get(opts, :ttl_days, 30)
    action = Keyword.get(opts, :action, "suppress")

    # Build rule attributes based on scope
    rule_attrs = case scope do
      :exact ->
        # Exact match - very specific
        %{
          title_pattern: alert.title,
          severity: alert.severity,
          agent_id: alert.agent_id
        }

      :similar ->
        # Similar match - more flexible
        evidence = alert.evidence || %{}
        process = evidence["process"] || evidence[:process] || %{}

        %{
          process_name_pattern: process["name"] || process[:name],
          severity: alert.severity,
          mitre_techniques: alert.mitre_techniques
        }
    end

    # Create the rule
    TamanduaServer.Alerts.Suppression.create_rule_from_alert(
      alert,
      [
        user_id: user_id,
        ttl_days: ttl_days,
        action: action,
        name: "FP: #{String.slice(alert.title, 0, 50)}"
      ] ++ Map.to_list(rule_attrs)
    )
  end

  @doc """
  Unsuppress alerts and optionally recreate them.

  Useful when a suppression rule was overly aggressive and needs to be reversed.

  ## Example

      # Find suppressed alerts from a specific rule
      suppressed_alerts = Repo.all(
        from sa in SuppressedAlert,
        where: sa.suppression_rule_id == ^rule_id,
        where: sa.unsuppressed == false
      )

      # Unsuppress and recreate as real alerts
      results = bulk_unsuppress_and_recreate(suppressed_alerts, analyst_id)
  """
  @spec bulk_unsuppress_and_recreate([struct()], String.t()) :: map()
  def bulk_unsuppress_and_recreate(suppressed_alerts, user_id) do
    suppressed_alerts
    |> Enum.map(fn sa ->
      SuppressionEngine.unsuppress_alert(sa.id, user_id, %{create_alert: true})
    end)
    |> Enum.reduce(%{success: 0, errors: 0}, fn result, acc ->
      case result do
        {:ok, _} -> Map.update!(acc, :success, &(&1 + 1))
        {:error, _} -> Map.update!(acc, :errors, &(&1 + 1))
      end
    end)
  end

  @doc """
  Example Broadway processor with suppression integration.

  This shows how to integrate suppression into a Broadway pipeline that
  processes detection results.
  """
  def handle_detection_result(detection_result, context) do
    # Normalize detection result to alert format
    alert_data = %{
      title: detection_result.title,
      description: detection_result.description,
      severity: detection_result.severity,
      organization_id: context.organization_id,
      agent_id: detection_result.agent_id,
      evidence: detection_result.evidence,
      mitre_techniques: detection_result.mitre_techniques,
      mitre_tactics: detection_result.mitre_tactics,
      detection_metadata: detection_result.metadata,
      threat_score: detection_result.confidence
    }

    # Create with suppression check
    case create_alert_with_suppression(alert_data, context) do
      {:ok, :created, alert} ->
        # Alert was created - trigger notifications
        notify_alert_created(alert)
        {:ok, alert}

      {:ok, :severity_reduced, alert} ->
        # Alert created with reduced severity
        notify_severity_reduced(alert)
        {:ok, alert}

      {:ok, :suppressed, suppressed} ->
        # Alert was suppressed - log for audit
        log_suppression(suppressed)
        {:ok, :suppressed}

      {:error, reason} ->
        # Handle error
        {:error, reason}
    end
  end

  # Private helper functions for example
  defp notify_alert_created(alert), do: :ok
  defp notify_severity_reduced(alert), do: :ok
  defp log_suppression(suppressed), do: :ok
end
