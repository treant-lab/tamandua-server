defmodule TamanduaServer.Webhooks.Integration do
  @moduledoc """
  Integration helpers for dispatching webhook events from different parts of the application.

  This module provides convenience functions for triggering webhooks when key events occur.
  """

  alias TamanduaServer.Webhooks

  @doc """
  Dispatches a webhook event when an alert is created.

  ## Example

      iex> alert = %Alert{id: "123", title: "Malware detected", severity: "critical"}
      iex> Integration.dispatch_alert_created(alert)
      {:ok, 3}  # 3 webhooks were triggered

  """
  def dispatch_alert_created(alert) do
    payload = %{
      alert: %{
        id: alert.id,
        title: alert.title,
        severity: alert.severity,
        description: alert.description,
        agent_id: alert.agent_id,
        threat_score: alert.threat_score,
        mitre_tactics: alert.mitre_tactics,
        mitre_techniques: alert.mitre_techniques,
        status: alert.status,
        created_at: alert.inserted_at
      }
    }

    Webhooks.dispatch_event(
      "alert.created",
      alert.id,
      payload,
      organization_id: alert.organization_id
    )
  end

  @doc """
  Dispatches a webhook event when an alert is updated.
  """
  def dispatch_alert_updated(alert, changes) do
    payload = %{
      alert: %{
        id: alert.id,
        title: alert.title,
        status: alert.status,
        changes: changes,
        updated_at: alert.updated_at
      }
    }

    Webhooks.dispatch_event(
      "alert.updated",
      alert.id,
      payload,
      organization_id: alert.organization_id
    )
  end

  @doc """
  Dispatches a webhook event when an alert is resolved.
  """
  def dispatch_alert_resolved(alert, resolution_notes) do
    payload = %{
      alert: %{
        id: alert.id,
        title: alert.title,
        severity: alert.severity,
        resolution_notes: resolution_notes,
        resolved_at: alert.resolved_at,
        resolved_by: alert.assigned_to_id
      }
    }

    Webhooks.dispatch_event(
      "alert.resolved",
      alert.id,
      payload,
      organization_id: alert.organization_id
    )
  end

  @doc """
  Dispatches a webhook event when an agent connects.
  """
  def dispatch_agent_connected(agent) do
    payload = %{
      agent: %{
        id: agent.id,
        hostname: agent.hostname,
        ip_address: agent.ip_address,
        os_type: agent.os_type,
        os_version: agent.os_version,
        agent_version: agent.agent_version,
        connected_at: DateTime.utc_now()
      }
    }

    Webhooks.dispatch_event(
      "agent.connected",
      agent.id,
      payload,
      organization_id: agent.organization_id
    )
  end

  @doc """
  Dispatches a webhook event when an agent disconnects.
  """
  def dispatch_agent_disconnected(agent, reason \\ nil) do
    payload = %{
      agent: %{
        id: agent.id,
        hostname: agent.hostname,
        ip_address: agent.ip_address,
        os_type: agent.os_type,
        last_seen_at: agent.last_seen_at,
        disconnection_reason: reason,
        disconnected_at: DateTime.utc_now()
      }
    }

    Webhooks.dispatch_event(
      "agent.disconnected",
      agent.id,
      payload,
      organization_id: agent.organization_id
    )
  end

  @doc """
  Dispatches a webhook event when a detection is triggered.
  """
  def dispatch_detection_triggered(detection_type, detection_data, agent_id, organization_id) do
    payload = %{
      detection: %{
        type: detection_type,
        data: detection_data,
        agent_id: agent_id,
        triggered_at: DateTime.utc_now()
      }
    }

    event_id = Ecto.UUID.generate()

    Webhooks.dispatch_event(
      "detection.triggered",
      event_id,
      payload,
      organization_id: organization_id
    )
  end

  @doc """
  Dispatches a webhook event when a response action is executed.
  """
  def dispatch_response_executed(action_type, action_data, agent_id, organization_id) do
    payload = %{
      response: %{
        action: action_type,
        data: action_data,
        agent_id: agent_id,
        executed_at: DateTime.utc_now()
      }
    }

    event_id = Ecto.UUID.generate()

    Webhooks.dispatch_event(
      "response.executed",
      event_id,
      payload,
      organization_id: organization_id
    )
  end

  @doc """
  Dispatches a webhook event when system health changes.
  """
  def dispatch_health_changed(health_status, organization_id) do
    payload = %{
      health: %{
        status: health_status.status,
        metrics: health_status.metrics,
        issues: health_status.issues,
        changed_at: DateTime.utc_now()
      }
    }

    event_id = Ecto.UUID.generate()

    Webhooks.dispatch_event(
      "system.health_changed",
      event_id,
      payload,
      organization_id: organization_id
    )
  end
end
