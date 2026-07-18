defmodule TamanduaServer.Notifications do
  @moduledoc """
  Notifications context.

  Manages notification integrations, routing, delivery, and logging.
  """

  import Ecto.Query
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Notifications.{Integration, DeliveryLog, Router, Throttler}
  alias TamanduaServer.Notifications.Providers

  @doc """
  List all integrations for an organization.
  """
  def list_integrations(organization_id) do
    Integration
    |> where([i], i.organization_id == ^organization_id)
    |> order_by([i], [desc: i.enabled, asc: i.name])
    |> Repo.all()
  end

  @doc """
  Get a single integration.
  """
  def get_integration!(id, organization_id) do
    Integration
    |> where([i], i.id == ^id and i.organization_id == ^organization_id)
    |> Repo.one!()
  end

  @doc """
  Create a new integration.
  """
  def create_integration(attrs) do
    %Integration{}
    |> Integration.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update an integration.
  """
  def update_integration(%Integration{} = integration, attrs) do
    integration
    |> Integration.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete an integration.
  """
  def delete_integration(%Integration{} = integration) do
    Repo.delete(integration)
  end

  @doc """
  Test an integration's connection.
  """
  def test_integration(%Integration{} = integration) do
    provider_module = get_provider_module(integration.provider)

    case provider_module.test_connection(integration.config) do
      {:ok, message} ->
        Logger.info("[Notifications] Test successful for #{integration.name}: #{message}")
        {:ok, message}

      {:error, reason} ->
        Logger.error("[Notifications] Test failed for #{integration.name}: #{reason}")
        {:error, reason}
    end
  end

  @doc """
  Send a notification for an alert through all matching integrations.

  This is the main entry point for alert notifications. It:
  1. Routes the alert to matching integrations
  2. Enqueues delivery jobs via Oban
  3. Returns the list of integrations that will receive the notification
  """
  def notify_alert(alert, organization_id) do
    # Get all integrations that should receive this alert
    integrations = Router.route_alert(alert, organization_id)

    if Enum.empty?(integrations) do
      Logger.debug("[Notifications] No integrations matched for alert #{alert.id}")
      {:ok, []}
    else
      # Enqueue delivery jobs for each integration
      jobs =
        Enum.map(integrations, fn integration ->
          TamanduaServer.Notifications.DeliveryWorker.new(%{
            integration_id: integration.id,
            alert_id: alert.id,
            organization_id: organization_id
          })
        end)

      # Insert all jobs. `Oban.insert_all/1` returns the list of inserted
      # jobs and raises on failure (it never returns `{count, _}` or an
      # `{:error, _}` tuple), so failures are rescued to preserve the
      # `{:error, reason}` contract callers rely on.
      try do
        inserted = Oban.insert_all(jobs)

        Logger.info(
          "[Notifications] Enqueued #{length(inserted)} notification jobs for alert #{alert.id}"
        )

        {:ok, integrations}
      rescue
        error ->
          Logger.error("[Notifications] Failed to enqueue jobs: #{inspect(error)}")
          {:error, error}
      end
    end
  end

  @doc """
  Send a notification immediately (synchronous).

  Used for test notifications and critical alerts.
  """
  def send_notification_now(integration, alert, agent \\ nil) do
    # Check throttling
    if Throttler.throttled?(integration) do
      log_delivery(integration, alert, "throttled", %{
        error_message: "Throttled: exceeded max notifications per hour"
      })

      {:error, :throttled}
    else
      # Get provider module
      provider_module = get_provider_module(integration.provider)

      # Build template variables
      variables = Providers.Base.build_variables(alert, agent)

      # Render templates
      rendered_title = Providers.Base.render_template(integration.template_title, variables)
      rendered_body = Providers.Base.render_template(integration.template_body, variables)

      # Send notification
      case provider_module.send_notification(integration, rendered_title, rendered_body) do
        {:ok, response} ->
          # Record success
          log_delivery(integration, alert, "sent", %{
            rendered_title: rendered_title,
            rendered_body: rendered_body,
            response_code: Map.get(response, :status_code),
            response_body: Map.get(response, :body)
          })

          update_integration_health(integration, :success)
          Throttler.record(integration.id)

          {:ok, response}

        {:error, reason} ->
          # Record failure
          log_delivery(integration, alert, "failed", %{
            rendered_title: rendered_title,
            rendered_body: rendered_body,
            error_message: reason
          })

          update_integration_health(integration, :failure)

          {:error, reason}
      end
    end
  end

  @doc """
  Get delivery logs for an integration.
  """
  def list_delivery_logs(integration_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)

    DeliveryLog
    |> where([l], l.integration_id == ^integration_id)
    |> order_by([l], desc: l.inserted_at)
    |> limit(^limit)
    |> Repo.all()
  end

  @doc """
  Get delivery logs for an alert.
  """
  def list_alert_delivery_logs(alert_id) do
    DeliveryLog
    |> where([l], l.alert_id == ^alert_id)
    |> order_by([l], desc: l.inserted_at)
    |> Repo.all()
  end

  @doc """
  Get delivery statistics for an integration.
  """
  def get_delivery_stats(integration_id) do
    query = from l in DeliveryLog,
      where: l.integration_id == ^integration_id,
      group_by: l.status,
      select: {l.status, count(l.id)}

    stats = Repo.all(query) |> Map.new()

    %{
      total: Map.values(stats) |> Enum.sum(),
      sent: Map.get(stats, "sent", 0),
      failed: Map.get(stats, "failed", 0),
      throttled: Map.get(stats, "throttled", 0),
      retry: Map.get(stats, "retry", 0)
    }
  end

  # Private helpers

  defp get_provider_module(provider) do
    case provider do
      "slack" -> Providers.Slack
      "teams" -> Providers.Teams
      "email" -> Providers.Email
      "pagerduty" -> Providers.PagerDuty
      "opsgenie" -> Providers.OpsGenie
      "discord" -> Providers.Discord
      "telegram" -> Providers.Telegram
      _ -> raise "Unknown provider: #{provider}"
    end
  end

  defp log_delivery(%Integration{} = integration, alert, status, attrs) do
    %DeliveryLog{}
    |> DeliveryLog.changeset(
      Map.merge(attrs, %{
        integration_id: integration.id,
        organization_id: integration.organization_id,
        alert_id: alert.id,
        provider: integration.provider,
        status: status
      })
    )
    |> Repo.insert()
  end

  defp update_integration_health(%Integration{} = integration, result) do
    now = DateTime.utc_now()

    attrs =
      case result do
        :success ->
          %{
            last_success_at: now,
            failure_count: 0,
            total_sent: (integration.total_sent || 0) + 1
          }

        :failure ->
          %{
            last_failure_at: now,
            failure_count: (integration.failure_count || 0) + 1,
            total_failed: (integration.total_failed || 0) + 1
          }
      end

    integration
    |> Integration.health_changeset(attrs)
    |> Repo.update()
  end
end
