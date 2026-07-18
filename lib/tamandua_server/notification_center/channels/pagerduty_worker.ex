defmodule TamanduaServer.NotificationCenter.Channels.PagerDutyWorker do
  @moduledoc """
  Oban worker for creating PagerDuty incidents.
  """
  use Oban.Worker,
    queue: :notifications,
    max_attempts: 3

  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.NotificationCenter.{NotificationDelivery}

  @pagerduty_api_url "https://api.pagerduty.com/incidents"

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"delivery_id" => delivery_id}}) do
    delivery = Repo.get!(NotificationDelivery, delivery_id) |> Repo.preload(:notification)
    notification = Repo.preload(delivery.notification, :user)

    # Get PagerDuty config
    case get_pagerduty_config(notification.organization_id) do
      nil ->
        delivery
        |> NotificationDelivery.failed_changeset("PagerDuty not configured")
        |> Repo.update()

        {:error, "PagerDuty not configured"}

      config ->
        create_incident(delivery, notification, config)
    end
  end

  defp create_incident(delivery, notification, config) do
    payload = build_incident_payload(notification, config)

    headers = [
      {"Authorization", "Token token=#{config["api_key"]}"},
      {"Content-Type", "application/json"},
      {"Accept", "application/vnd.pagerduty+json;version=2"},
      {"From", config["from_email"] || "noreply@treantlab.org"}
    ]

    case HTTPoison.post(@pagerduty_api_url, Jason.encode!(payload), headers) do
      {:ok, %{status_code: code, body: body}} when code in 200..299 ->
        response = Jason.decode!(body)

        delivery
        |> NotificationDelivery.sent_changeset(%{
          status_code: code,
          incident_id: response["incident"]["id"]
        })
        |> Repo.update()

        Logger.info("[PagerDutyWorker] Incident created: #{response["incident"]["id"]}")
        :ok

      {:ok, %{status_code: code, body: body}} ->
        delivery
        |> NotificationDelivery.failed_changeset("HTTP #{code}: #{body}")
        |> Repo.update()

        Logger.error("[PagerDutyWorker] Failed to create incident: HTTP #{code}")
        {:error, "HTTP #{code}"}

      {:error, %{reason: reason}} ->
        delivery
        |> NotificationDelivery.failed_changeset(reason)
        |> Repo.update()

        Logger.error("[PagerDutyWorker] Failed to create incident: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp build_incident_payload(notification, config) do
    severity = pagerduty_severity(notification.priority)
    alert_url = build_alert_url(notification)

    %{
      incident: %{
        type: "incident",
        title: notification.title,
        service: %{
          id: config["service_id"],
          type: "service_reference"
        },
        urgency: severity,
        body: %{
          type: "incident_body",
          details: notification.body || "No details provided"
        },
        incident_key: "tamandua-#{notification.id}",
        custom_details: %{
          notification_type: notification.type,
          priority: notification.priority,
          resource_type: notification.related_resource_type,
          resource_id: notification.related_resource_id,
          alert_url: alert_url
        }
      }
    }
  end

  defp pagerduty_severity("critical"), do: "high"
  defp pagerduty_severity("high"), do: "high"
  defp pagerduty_severity(_), do: "low"

  defp build_alert_url(%{related_resource_type: "alert", related_resource_id: alert_id}) do
    "#{TamanduaServerWeb.Endpoint.url()}/alerts/#{alert_id}"
  end

  defp build_alert_url(_), do: TamanduaServerWeb.Endpoint.url()

  # Org-scoped settings live on Organization.settings (string-keyed map);
  # TamanduaServer.Settings is the global ETS store and has no per-org API.
  defp get_pagerduty_config(organization_id) do
    settings =
      case TamanduaServer.Accounts.get_organization(organization_id) do
        %{settings: settings} when is_map(settings) -> settings
        _ -> %{}
      end

    api_key = non_empty_setting(settings["pagerduty_api_key"])
    service_id = non_empty_setting(settings["pagerduty_service_id"])

    if api_key && service_id do
      %{
        "api_key" => api_key,
        "service_id" => service_id,
        "from_email" => non_empty_setting(settings["pagerduty_from_email"])
      }
    else
      nil
    end
  end

  defp non_empty_setting(value) when is_binary(value) and value != "", do: value
  defp non_empty_setting(_), do: nil
end
