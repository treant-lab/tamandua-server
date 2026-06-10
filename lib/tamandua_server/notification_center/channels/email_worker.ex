defmodule TamanduaServer.NotificationCenter.Channels.EmailWorker do
  @moduledoc """
  Oban worker for sending email notifications.
  """
  use Oban.Worker,
    queue: :notifications,
    max_attempts: 3

  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.NotificationCenter.{Notification, NotificationDelivery, NotificationTemplate}
  alias TamanduaServer.Mailer

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"delivery_id" => delivery_id}}) do
    delivery = Repo.get!(NotificationDelivery, delivery_id) |> Repo.preload(:notification)
    notification = Repo.preload(delivery.notification, :user)

    # Get template
    template =
      get_template(notification.type, "email", notification.organization_id) ||
        default_template(notification.type)

    # Render template
    variables = build_variables(notification)
    subject = render_template(template.subject_template, variables)
    body = render_template(template.body_template, variables)

    # Send email
    case send_email(notification.user, subject, body) do
      {:ok, response} ->
        delivery
        |> NotificationDelivery.sent_changeset(%{provider: "email"})
        |> Repo.update()

        Logger.info("[EmailWorker] Email sent to #{notification.user.email}")
        :ok

      {:error, reason} ->
        delivery
        |> NotificationDelivery.failed_changeset(reason)
        |> Repo.update()

        Logger.error("[EmailWorker] Failed to send email: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp get_template(type, channel, organization_id) do
    NotificationTemplate
    |> where([t], t.type == ^type and t.channel == ^channel)
    |> where([t], t.organization_id == ^organization_id or is_nil(t.organization_id))
    |> order_by([t], desc: t.organization_id)
    |> limit(1)
    |> Repo.one()
  end

  defp default_template(type) do
    %{
      subject_template: "[Tamandua EDR] <%= notification.title %>",
      body_template: """
      <%= notification.title %>

      <%= notification.body %>

      Priority: <%= notification.priority %>
      Time: <%= notification.inserted_at %>

      View in Tamandua: <%= alert_url %>
      """
    }
  end

  defp build_variables(notification) do
    %{
      "notification" => notification,
      "alert_url" => build_alert_url(notification),
      "user" => notification.user
    }
  end

  defp render_template(template, variables) do
    EEx.eval_string(template, assigns: variables)
  rescue
    error ->
      Logger.error("[EmailWorker] Template rendering error: #{inspect(error)}")
      template
  end

  defp build_alert_url(%{related_resource_type: "alert", related_resource_id: alert_id}) do
    "#{TamanduaServerWeb.Endpoint.url()}/alerts/#{alert_id}"
  end

  defp build_alert_url(_), do: TamanduaServerWeb.Endpoint.url()

  defp send_email(user, subject, body) do
    # Use existing mailer
    TamanduaServer.Mailer.send_notification_email(user.email, subject, body)
  end
end
