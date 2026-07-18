defmodule TamanduaServerWeb.API.V1.BillingController do
  @moduledoc """
  Billing API controller for tenant billing management.

  Provides endpoints for:
  - Viewing subscription status
  - Usage summaries
  - Billing portal access
  - Invoice history
  - Subscription management

  ## Authorization

  Most endpoints require `organization_read` permission.
  Subscription modification requires `organization_update`.
  Usage reporting is restricted to system settings permission.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Billing
  alias TamanduaServer.Billing.Subscription

  action_fallback TamanduaServerWeb.FallbackController

  # Authorization
  plug TamanduaServerWeb.Plugs.RBAC, [permission: :organization_read]
       when action in [:show, :usage, :invoices]

  plug TamanduaServerWeb.Plugs.RBAC, [permission: :organization_update]
       when action in [:create_subscription, :cancel_subscription, :portal]

  plug TamanduaServerWeb.Plugs.RBAC, [permission: :system_settings]
       when action in [:report_usage]

  @doc """
  Get current subscription and billing status.

  Returns the current subscription details and real-time usage metrics.

  ## Response

  ```json
  {
    "data": {
      "id": "uuid",
      "status": "active",
      "current_period_start": "2024-01-01T00:00:00Z",
      "current_period_end": "2024-02-01T00:00:00Z"
    },
    "usage": {
      "api_calls": 1234,
      "model_scans": 56,
      "storage_bytes": 1048576
    }
  }
  ```
  """
  def show(conn, _params) do
    org_id = conn.assigns[:current_organization_id]

    case Billing.get_subscription(org_id) do
      {:ok, subscription} ->
        json(conn, %{
          data: serialize_subscription(subscription),
          usage: Billing.get_current_usage(org_id)
        })

      {:error, :not_found} ->
        json(conn, %{
          data: nil,
          message: "No active subscription. Using free tier.",
          usage: Billing.get_current_usage(org_id)
        })
    end
  end

  @doc """
  Create a new subscription.

  ## Parameters

  - `tier` - License tier ("pro" or "enterprise")
  - `trial_days` - Optional trial period in days

  ## Response

  Returns the created subscription details.
  """
  def create_subscription(conn, %{"tier" => tier_str} = params) do
    org_id = conn.assigns[:current_organization_id]

    tier =
      case tier_str do
        "pro" -> :pro
        "enterprise" -> :enterprise
        _ -> nil
      end

    if tier do
      opts = if params["trial_days"], do: [trial_days: params["trial_days"]], else: []

      case Billing.create_subscription(org_id, tier, opts) do
        {:ok, subscription} ->
          conn
          |> put_status(:created)
          |> json(%{data: serialize_subscription(subscription)})

        {:error, reason} ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{error: format_error(reason)})
      end
    else
      conn
      |> put_status(:bad_request)
      |> json(%{error: "Invalid tier. Must be 'pro' or 'enterprise'."})
    end
  end

  @doc """
  Cancel current subscription.

  ## Parameters

  - `immediately` - If "true", cancels immediately. Otherwise, cancels at period end.
  """
  def cancel_subscription(conn, params) do
    org_id = conn.assigns[:current_organization_id]
    immediately = params["immediately"] == "true"

    case Billing.cancel_subscription(org_id, immediately: immediately) do
      {:ok, _} ->
        json(conn, %{
          message:
            if(immediately,
              do: "Subscription canceled",
              else: "Subscription will cancel at period end"
            )
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "No active subscription"})
    end
  end

  @doc """
  Get usage summary.

  ## Parameters

  - `days` - Number of days to look back (default: 30)

  ## Response

  ```json
  {
    "current": {"api_calls": 100, "model_scans": 10, "storage_bytes": 1024},
    "summary": {"total_api_calls": 5000, "total_scans": 200, ...},
    "period_days": 30
  }
  ```
  """
  def usage(conn, params) do
    org_id = conn.assigns[:current_organization_id]
    days = parse_int(params["days"], 30)

    current = Billing.get_current_usage(org_id)
    summary = Billing.get_usage_summary(org_id, days: days)

    json(conn, %{
      current: current,
      summary: summary,
      period_days: days
    })
  end

  @doc """
  Get billing portal URL for self-service.

  ## Parameters

  - `return_url` - URL to return to after portal session (optional)

  ## Response

  ```json
  {
    "url": "https://billing.stripe.com/session/..."
  }
  ```
  """
  def portal(conn, params) do
    org_id = conn.assigns[:current_organization_id]
    return_url = params["return_url"] || default_return_url(conn)

    case Billing.get_portal_url(org_id, return_url) do
      {:ok, url} ->
        json(conn, %{url: url})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "No billing account. Create a subscription first."})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: format_error(reason)})
    end
  end

  @doc """
  Get invoice history.

  ## Parameters

  - `limit` - Maximum number of invoices (default: 10)
  """
  def invoices(conn, params) do
    org_id = conn.assigns[:current_organization_id]
    limit = parse_int(params["limit"], 10)

    case Billing.get_invoices(org_id, limit: limit) do
      {:ok, invoices} ->
        json(conn, %{
          data: Enum.map(invoices, &serialize_invoice/1)
        })

      {:error, :not_found} ->
        json(conn, %{data: []})
    end
  end

  @doc """
  Trigger usage report to Stripe (admin/cron endpoint).

  This is typically called by a scheduled job, not manually.
  """
  def report_usage(conn, _params) do
    Billing.report_usage_to_stripe()
    json(conn, %{message: "Usage report triggered"})
  end

  # ===========================================================================
  # Private Helpers
  # ===========================================================================

  defp serialize_subscription(sub) when is_map(sub) do
    %{
      id: sub.id,
      status: sub.status,
      stripe_subscription_id: sub.stripe_subscription_id,
      current_period_start: sub.current_period_start,
      current_period_end: sub.current_period_end,
      cancel_at_period_end: sub.cancel_at_period_end,
      active: Subscription.active?(sub)
    }
  end

  defp serialize_invoice(invoice) do
    %{
      id: invoice.id,
      number: invoice.number,
      status: invoice.status,
      amount_due: invoice.amount_due,
      amount_paid: invoice.amount_paid,
      currency: invoice.currency,
      created: DateTime.from_unix!(invoice.created),
      hosted_invoice_url: invoice.hosted_invoice_url,
      pdf: invoice.invoice_pdf
    }
  end

  defp format_error({:stripe_error, message}), do: message
  defp format_error(:price_not_configured), do: "Billing not configured for this tier"
  defp format_error(:not_found), do: "Resource not found"
  defp format_error(error), do: inspect(error)

  defp parse_int(nil, default), do: default

  defp parse_int(str, default) when is_binary(str) do
    case Integer.parse(str) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_int(int, _) when is_integer(int), do: int

  defp default_return_url(_conn) do
    base_url = Application.get_env(:tamandua_server, :base_url) || "http://localhost:4000"
    "#{base_url}/settings/billing"
  end
end
