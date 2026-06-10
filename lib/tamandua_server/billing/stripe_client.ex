defmodule TamanduaServer.Billing.StripeClient do
  @moduledoc """
  Stripe API client wrapper for Tamandua billing.

  Provides a simplified interface to Stripe for:
  - Customer management
  - Subscription lifecycle
  - Usage-based billing

  All functions return `{:ok, result}` or `{:error, reason}`.

  ## Configuration

  Configure Stripe credentials in config:

      config :stripity_stripe,
        api_key: System.get_env("STRIPE_SECRET_KEY"),
        webhook_signing_secret: System.get_env("STRIPE_WEBHOOK_SECRET")

  ## Usage

      # Create a customer
      {:ok, customer} = StripeClient.create_customer(org_id, %{email: "admin@acme.com"})

      # Create a subscription
      {:ok, subscription} = StripeClient.create_subscription(customer.id, "price_xxx")

      # Report metered usage
      {:ok, usage_record} = StripeClient.report_usage(subscription_item_id, 100)
  """

  require Logger

  @doc """
  Creates a Stripe customer for an organization.

  ## Parameters

  - `org_id` - Organization ID (stored in customer metadata)
  - `attrs` - Customer attributes (email, name, slug)

  ## Returns

  - `{:ok, %Stripe.Customer{}}` on success
  - `{:error, {:stripe_error, message}}` on failure
  """
  def create_customer(org_id, attrs) do
    params = %{
      email: attrs[:email],
      name: attrs[:name],
      metadata: %{
        organization_id: org_id,
        slug: attrs[:slug]
      }
    }

    case Stripe.Customer.create(params) do
      {:ok, customer} ->
        Logger.info("Created Stripe customer #{customer.id} for org #{org_id}")
        {:ok, customer}

      {:error, %Stripe.Error{} = error} ->
        Logger.error("Failed to create Stripe customer: #{inspect(error)}")
        {:error, {:stripe_error, error.message}}
    end
  end

  @doc """
  Updates a Stripe customer.

  ## Parameters

  - `customer_id` - Stripe customer ID
  - `attrs` - Attributes to update (email, name, metadata)
  """
  def update_customer(customer_id, attrs) do
    params = Map.take(attrs, [:email, :name, :metadata])

    case Stripe.Customer.update(customer_id, params) do
      {:ok, customer} -> {:ok, customer}
      {:error, %Stripe.Error{} = error} -> {:error, {:stripe_error, error.message}}
    end
  end

  @doc """
  Retrieves a Stripe customer.
  """
  def get_customer(customer_id) do
    case Stripe.Customer.retrieve(customer_id) do
      {:ok, customer} -> {:ok, customer}
      {:error, %Stripe.Error{} = error} -> {:error, {:stripe_error, error.message}}
    end
  end

  @doc """
  Creates a subscription for a customer.

  ## Parameters

  - `customer_id` - Stripe customer ID
  - `price_id` - Stripe price ID for the subscription
  - `opts` - Options:
    - `:trial_days` - Number of trial days
    - `:payment_behavior` - Payment behavior (default: "default_incomplete")
    - `:metadata` - Additional metadata

  ## Returns

  Returns the subscription with expanded `latest_invoice.payment_intent`
  for handling payment confirmation.
  """
  def create_subscription(customer_id, price_id, opts \\ []) do
    params = %{
      customer: customer_id,
      items: [%{price: price_id}],
      payment_behavior: Keyword.get(opts, :payment_behavior, "default_incomplete"),
      expand: ["latest_invoice.payment_intent"]
    }

    # Add trial period if specified
    params =
      if trial_days = Keyword.get(opts, :trial_days) do
        Map.put(params, :trial_period_days, trial_days)
      else
        params
      end

    # Add metadata
    params =
      if metadata = Keyword.get(opts, :metadata) do
        Map.put(params, :metadata, metadata)
      else
        params
      end

    case Stripe.Subscription.create(params) do
      {:ok, subscription} ->
        Logger.info("Created Stripe subscription #{subscription.id} for customer #{customer_id}")
        {:ok, subscription}

      {:error, %Stripe.Error{} = error} ->
        Logger.error("Failed to create subscription: #{inspect(error)}")
        {:error, {:stripe_error, error.message}}
    end
  end

  @doc """
  Updates a subscription (e.g., change plan, cancel at period end).

  ## Parameters

  - `subscription_id` - Stripe subscription ID
  - `attrs` - Attributes to update:
    - `:items` - New subscription items
    - `:cancel_at_period_end` - Cancel at end of period
    - `:metadata` - Metadata updates
    - `:proration_behavior` - How to handle prorations
  """
  def update_subscription(subscription_id, attrs) do
    params = Map.take(attrs, [:items, :cancel_at_period_end, :metadata, :proration_behavior])

    case Stripe.Subscription.update(subscription_id, params) do
      {:ok, subscription} -> {:ok, subscription}
      {:error, %Stripe.Error{} = error} -> {:error, {:stripe_error, error.message}}
    end
  end

  @doc """
  Retrieves a subscription with expanded items.
  """
  def get_subscription(subscription_id) do
    case Stripe.Subscription.retrieve(subscription_id, expand: ["items"]) do
      {:ok, subscription} -> {:ok, subscription}
      {:error, %Stripe.Error{} = error} -> {:error, {:stripe_error, error.message}}
    end
  end

  @doc """
  Cancels a subscription.

  ## Options

  - `:immediately` - If true, cancels immediately. Otherwise, cancels at period end.
  """
  def cancel_subscription(subscription_id, opts \\ []) do
    if Keyword.get(opts, :immediately, false) do
      case Stripe.Subscription.delete(subscription_id) do
        {:ok, subscription} -> {:ok, subscription}
        {:error, %Stripe.Error{} = error} -> {:error, {:stripe_error, error.message}}
      end
    else
      # Cancel at period end
      update_subscription(subscription_id, %{cancel_at_period_end: true})
    end
  end

  @doc """
  Reports metered usage to Stripe.

  ## Parameters

  - `subscription_item_id` - The subscription item ID for metered billing
  - `quantity` - The quantity to report
  - `opts` - Options:
    - `:timestamp` - Unix timestamp (defaults to now)
    - `:action` - "increment" or "set" (defaults to "increment")

  ## Returns

  - `{:ok, %Stripe.UsageRecord{}}` on success
  """
  def report_usage(subscription_item_id, quantity, opts \\ []) do
    params = %{
      quantity: quantity,
      timestamp: Keyword.get(opts, :timestamp, DateTime.utc_now() |> DateTime.to_unix()),
      action: Keyword.get(opts, :action, "increment")
    }

    case Stripe.SubscriptionItem.create_usage_record(subscription_item_id, params) do
      {:ok, usage_record} ->
        Logger.debug("Reported usage: #{quantity} to subscription item #{subscription_item_id}")
        {:ok, usage_record}

      {:error, %Stripe.Error{} = error} ->
        Logger.error("Failed to report usage: #{inspect(error)}")
        {:error, {:stripe_error, error.message}}
    end
  end

  @doc """
  Lists invoices for a customer.

  ## Options

  - `:limit` - Maximum number of invoices to return (default: 10)
  """
  def list_invoices(customer_id, opts \\ []) do
    params = %{
      customer: customer_id,
      limit: Keyword.get(opts, :limit, 10)
    }

    case Stripe.Invoice.list(params) do
      {:ok, %{data: invoices}} -> {:ok, invoices}
      {:error, %Stripe.Error{} = error} -> {:error, {:stripe_error, error.message}}
    end
  end

  @doc """
  Creates a billing portal session for customer self-service.

  Returns a URL the customer can use to manage their subscription.
  """
  def create_portal_session(customer_id, return_url) do
    params = %{
      customer: customer_id,
      return_url: return_url
    }

    case Stripe.BillingPortal.Session.create(params) do
      {:ok, session} -> {:ok, session.url}
      {:error, %Stripe.Error{} = error} -> {:error, {:stripe_error, error.message}}
    end
  end

  @doc """
  Retrieves an invoice by ID.
  """
  def get_invoice(invoice_id) do
    case Stripe.Invoice.retrieve(invoice_id) do
      {:ok, invoice} -> {:ok, invoice}
      {:error, %Stripe.Error{} = error} -> {:error, {:stripe_error, error.message}}
    end
  end

  @doc """
  Creates a checkout session for new subscriptions.

  This is useful for embedding Stripe Checkout in your app.
  """
  def create_checkout_session(customer_id, price_id, opts \\ []) do
    params = %{
      customer: customer_id,
      mode: "subscription",
      line_items: [%{price: price_id, quantity: 1}],
      success_url: Keyword.fetch!(opts, :success_url),
      cancel_url: Keyword.fetch!(opts, :cancel_url)
    }

    case Stripe.Session.create(params) do
      {:ok, session} -> {:ok, session}
      {:error, %Stripe.Error{} = error} -> {:error, {:stripe_error, error.message}}
    end
  end
end
