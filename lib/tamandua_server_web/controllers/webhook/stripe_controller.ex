defmodule TamanduaServerWeb.Webhook.StripeController do
  @moduledoc """
  Stripe webhook handler.

  Receives and processes Stripe webhook events for:
  - Subscription lifecycle (created, updated, deleted)
  - Payment events (succeeded, failed)
  - Invoice events

  ## Webhook Setup

  Configure a webhook endpoint in the Stripe dashboard pointing to:
  `https://your-domain.com/webhook/stripe`

  Required events:
  - `customer.subscription.created`
  - `customer.subscription.updated`
  - `customer.subscription.deleted`
  - `invoice.payment_succeeded`
  - `invoice.payment_failed`

  ## Signature Verification

  All incoming webhooks are verified using the signing secret configured in:
  `config :stripity_stripe, webhook_signing_secret: "whsec_..."`

  Requests without valid signatures are rejected with 400 Bad Request.
  """

  use TamanduaServerWeb, :controller
  require Logger

  alias TamanduaServer.Billing

  @doc """
  Handle incoming Stripe webhook events.

  Verifies webhook signature and dispatches to appropriate handler.
  """
  def handle_event(conn, _params) do
    payload = conn.assigns[:raw_body]
    sig_header = get_req_header(conn, "stripe-signature") |> List.first()
    webhook_secret = Application.get_env(:stripity_stripe, :webhook_signing_secret)

    case verify_and_construct_event(payload, sig_header, webhook_secret) do
      {:ok, event} ->
        handle_stripe_event(event)
        json(conn, %{received: true})

      {:error, :missing_signature} ->
        Logger.warning("Stripe webhook missing signature header")

        conn
        |> put_status(:bad_request)
        |> json(%{error: "Missing signature"})

      {:error, :invalid_signature} ->
        Logger.warning("Stripe webhook signature verification failed")

        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid signature"})

      {:error, reason} ->
        Logger.error("Stripe webhook error: #{inspect(reason)}")

        conn
        |> put_status(:bad_request)
        |> json(%{error: "Webhook processing failed"})
    end
  end

  # ===========================================================================
  # Event Handlers
  # ===========================================================================

  defp handle_stripe_event(%Stripe.Event{
         type: "customer.subscription.created",
         data: %{object: subscription}
       }) do
    Logger.info("Subscription created: #{subscription.id}")
    Billing.update_subscription_from_webhook(subscription)
  end

  defp handle_stripe_event(%Stripe.Event{
         type: "customer.subscription.updated",
         data: %{object: subscription}
       }) do
    Logger.info("Subscription updated: #{subscription.id} -> #{subscription.status}")
    Billing.update_subscription_from_webhook(subscription)
  end

  defp handle_stripe_event(%Stripe.Event{
         type: "customer.subscription.deleted",
         data: %{object: subscription}
       }) do
    Logger.info("Subscription deleted: #{subscription.id}")
    Billing.update_subscription_from_webhook(subscription)
  end

  defp handle_stripe_event(%Stripe.Event{
         type: "invoice.payment_succeeded",
         data: %{object: invoice}
       }) do
    Logger.info("Payment succeeded for invoice #{invoice.id}")
    # Could trigger email notification here
    :ok
  end

  defp handle_stripe_event(%Stripe.Event{
         type: "invoice.payment_failed",
         data: %{object: invoice}
       }) do
    Logger.warning("Payment failed for invoice #{invoice.id}")
    # Could trigger notification to org admin here
    # Could also update subscription status
    :ok
  end

  defp handle_stripe_event(%Stripe.Event{type: type}) do
    Logger.debug("Unhandled Stripe event: #{type}")
    :ok
  end

  # ===========================================================================
  # Helpers
  # ===========================================================================

  defp verify_and_construct_event(nil, _, _), do: {:error, :missing_payload}
  defp verify_and_construct_event(_, nil, _), do: {:error, :missing_signature}
  defp verify_and_construct_event(_, _, nil), do: {:error, :missing_webhook_secret}

  defp verify_and_construct_event(payload, sig_header, webhook_secret) do
    case Stripe.Webhook.construct_event(payload, sig_header, webhook_secret) do
      {:ok, event} ->
        {:ok, event}

      {:error, %{__struct__: struct}} when struct in [Stripe.Error, Stripe.APIError] ->
        {:error, :invalid_signature}

      {:error, :invalid_signature} ->
        {:error, :invalid_signature}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
