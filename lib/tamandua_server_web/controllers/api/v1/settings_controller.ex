defmodule TamanduaServerWeb.API.V1.SettingsController do
  @moduledoc """
  API controller for managing application settings.

  Provides endpoints for:
  - General settings (agent heartbeat, telemetry batch config)
  - Detection settings (ML threshold, auto-response)
  - Notification settings (email, Slack, webhooks)
  - Integration settings (third-party services)
  - System maintenance (reload rules, clear cache)
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Settings
  alias TamanduaServer.Detection
  alias TamanduaServer.Cache

  require Logger

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Updates general settings.

  POST /api/v1/settings/general

  ## Request Body
  ```json
  {
    "agentHeartbeatInterval": 30,
    "telemetryBatchSize": 100,
    "telemetryBatchTimeout": 5
  }
  ```

  ## Response
  ```json
  {
    "success": true,
    "message": "General settings saved successfully",
    "data": {...}
  }
  ```
  """
  def general(conn, params) do
    # Convert camelCase keys to snake_case atoms
    updates = %{
      agent_heartbeat_interval: params["agentHeartbeatInterval"],
      telemetry_batch_size: params["telemetryBatchSize"],
      telemetry_batch_timeout: params["telemetryBatchTimeout"]
    }
    |> reject_nil_values()

    case Settings.update(:general, updates) do
      {:ok, updated} ->
        Logger.info("General settings updated: #{inspect(updates)}")
        json(conn, %{
          success: true,
          message: "General settings saved successfully",
          data: serialize_general(updated)
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{success: false, error: "Failed to save settings: #{inspect(reason)}"})
    end
  end

  @doc """
  Updates detection settings.

  POST /api/v1/settings/detection

  ## Request Body
  ```json
  {
    "mlEnabled": true,
    "mlThreshold": 0.7,
    "autoResponseEnabled": false
  }
  ```
  """
  def detection(conn, params) do
    updates = %{
      ml_enabled: params["mlEnabled"],
      ml_threshold: params["mlThreshold"],
      auto_response_enabled: params["autoResponseEnabled"]
    }
    |> reject_nil_values()

    case Settings.update(:detection, updates) do
      {:ok, updated} ->
        Logger.info("Detection settings updated: #{inspect(updates)}")
        json(conn, %{
          success: true,
          message: "Detection settings saved successfully",
          data: serialize_detection(updated)
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{success: false, error: "Failed to save settings: #{inspect(reason)}"})
    end
  end

  @doc """
  Updates notification settings.

  POST /api/v1/settings/notifications

  ## Request Body
  ```json
  {
    "emailNotifications": {
      "Critical alerts": true,
      "High severity alerts": false,
      "Daily digest": false,
      "Weekly report": false
    },
    "slackWebhookUrl": "https://hooks.slack.com/..."
  }
  ```
  """
  def notifications(conn, params) do
    # Parse email notification preferences
    email_notifications = params["emailNotifications"] || %{}

    updates = %{
      critical_alerts: Map.get(email_notifications, "Critical alerts", true),
      high_alerts: Map.get(email_notifications, "High severity alerts", false),
      daily_digest: Map.get(email_notifications, "Daily digest", false),
      weekly_report: Map.get(email_notifications, "Weekly report", false)
    }

    # Only update Slack webhook if provided (non-empty)
    slack_webhook = params["slackWebhookUrl"]
    updates = if slack_webhook && String.length(slack_webhook) > 0 do
      Map.merge(updates, %{
        slack_enabled: true,
        slack_webhook: slack_webhook
      })
    else
      updates
    end

    # Enable email if any notification type is enabled
    updates = if updates.critical_alerts || updates.high_alerts || updates.daily_digest || updates.weekly_report do
      Map.put(updates, :email_enabled, true)
    else
      updates
    end

    case Settings.update(:notifications, updates) do
      {:ok, updated} ->
        Logger.info("Notification settings updated")
        json(conn, %{
          success: true,
          message: "Notification settings saved successfully",
          data: serialize_notifications(updated)
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{success: false, error: "Failed to save settings: #{inspect(reason)}"})
    end
  end

  @doc """
  Updates integration settings.

  POST /api/v1/settings/integrations

  ## Request Body
  ```json
  {
    "integrations": [
      {"id": "1", "enabled": true},
      {"id": "2", "enabled": false}
    ]
  }
  ```
  """
  def integrations(conn, params) do
    integration_updates = params["integrations"] || []

    # Map the integration updates to our internal structure
    updates = Enum.reduce(integration_updates, %{}, fn integration, acc ->
      id = integration["id"]
      enabled = integration["enabled"]

      # Map IDs to our internal keys
      key = case id do
        "1" -> :virustotal
        "virustotal" -> :virustotal
        "2" -> :abuseipdb
        "abuseipdb" -> :abuseipdb
        "3" -> :misp
        "misp" -> :misp
        "4" -> :splunk
        "splunk" -> :splunk
        "5" -> :elasticsearch
        "elasticsearch" -> :elasticsearch
        other when is_binary(other) ->
          try do
            String.to_existing_atom(other)
          rescue
            ArgumentError -> nil
          end
        _ -> nil
      end

      if key do
        Map.put(acc, key, %{enabled: enabled})
      else
        acc
      end
    end)

    case Settings.update(:integrations, updates) do
      {:ok, updated} ->
        Logger.info("Integration settings updated: #{inspect(updates)}")
        json(conn, %{
          success: true,
          message: "Integration settings saved successfully",
          data: serialize_integrations(updated)
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{success: false, error: "Failed to save settings: #{inspect(reason)}"})
    end
  end

  @doc """
  Updates system settings (data retention).

  POST /api/v1/settings/system

  ## Request Body
  ```json
  {
    "eventRetentionDays": 30,
    "alertRetentionDays": 90
  }
  ```
  """
  def system(conn, params) do
    updates = %{
      event_retention_days: params["eventRetentionDays"],
      alert_retention_days: params["alertRetentionDays"]
    }
    |> reject_nil_values()

    case Settings.update(:system, updates) do
      {:ok, updated} ->
        Logger.info("System settings updated: #{inspect(updates)}")
        json(conn, %{
          success: true,
          message: "System settings saved successfully",
          data: serialize_system(updated)
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{success: false, error: "Failed to save settings: #{inspect(reason)}"})
    end
  end

  @doc """
  Reloads all detection rules (YARA, Sigma).

  POST /api/v1/settings/reload-rules

  This triggers a reload of all detection rules from the database and
  broadcasts the updated rules to all connected agents.
  """
  def reload_rules(conn, _params) do
    try do
      # Get rule counts before for logging
      sigma_count = Detection.count_sigma_rules()
      yara_count = Detection.count_yara_rules()

      # Broadcast rule updates to all agents
      TamanduaServerWeb.Endpoint.broadcast("agents:config", "rules_updated", %{
        timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
      })

      Logger.info("Detection rules reloaded - Sigma: #{sigma_count}, YARA: #{yara_count}")

      json(conn, %{
        success: true,
        message: "Detection rules reloaded successfully",
        data: %{
          sigma_rules: sigma_count,
          yara_rules: yara_count,
          reloaded_at: DateTime.utc_now() |> DateTime.to_iso8601()
        }
      })
    rescue
      e ->
        Logger.error("Failed to reload rules: #{Exception.message(e)}")
        conn
        |> put_status(:internal_server_error)
        |> json(%{success: false, error: "Failed to reload rules: #{Exception.message(e)}"})
    end
  end

  @doc """
  Clears the event cache.

  POST /api/v1/settings/clear-cache

  Clears the in-memory cache used for event processing, ML predictions,
  and other runtime data.
  """
  def clear_cache(conn, _params) do
    try do
      # Get cache stats before clearing
      cache_size = if Cache.initialized?() do
        Cache.size()
      else
        0
      end

      # Clear the cache
      if Cache.initialized?() do
        Cache.clear()
      end

      Logger.info("Event cache cleared - #{cache_size} entries removed")

      json(conn, %{
        success: true,
        message: "Event cache cleared successfully",
        data: %{
          entries_cleared: cache_size,
          cleared_at: DateTime.utc_now() |> DateTime.to_iso8601()
        }
      })
    rescue
      e ->
        Logger.error("Failed to clear cache: #{Exception.message(e)}")
        conn
        |> put_status(:internal_server_error)
        |> json(%{success: false, error: "Failed to clear cache: #{Exception.message(e)}"})
    end
  end

  # Private helpers

  defp reject_nil_values(map) do
    map
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Enum.into(%{})
  end

  defp serialize_general(settings) do
    %{
      agentHeartbeatInterval: settings[:agent_heartbeat_interval],
      telemetryBatchSize: settings[:telemetry_batch_size],
      telemetryBatchTimeout: settings[:telemetry_batch_timeout]
    }
  end

  defp serialize_detection(settings) do
    %{
      mlEnabled: settings[:ml_enabled],
      mlThreshold: settings[:ml_threshold],
      autoResponseEnabled: settings[:auto_response_enabled]
    }
  end

  defp serialize_notifications(settings) do
    %{
      emailEnabled: settings[:email_enabled],
      emailRecipients: settings[:email_recipients] || [],
      slackEnabled: settings[:slack_enabled],
      slackWebhook: if(settings[:slack_webhook], do: "***configured***", else: nil),
      webhookEnabled: settings[:webhook_enabled],
      webhookUrl: if(settings[:webhook_url], do: "***configured***", else: nil),
      criticalAlerts: settings[:critical_alerts],
      highAlerts: settings[:high_alerts],
      mediumAlerts: settings[:medium_alerts]
    }
  end

  defp serialize_integrations(settings) do
    settings
    |> Enum.map(fn {key, value} ->
      %{
        id: Atom.to_string(key),
        name: key |> Atom.to_string() |> String.capitalize(),
        enabled: value[:enabled] || false
      }
    end)
  end

  defp serialize_system(settings) do
    %{
      eventRetentionDays: settings[:event_retention_days],
      alertRetentionDays: settings[:alert_retention_days]
    }
  end
end
