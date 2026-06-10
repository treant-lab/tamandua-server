defmodule TamanduaServer.Billing do
  @moduledoc """
  Billing context for managing subscriptions and usage.

  Coordinates between:
  - UsageMeter (real-time tracking)
  - StripeClient (payment processing)
  - Database (persistence)

  ## Usage Flow

  1. Tenant provisioned -> create Stripe customer
  2. Upgrade to paid tier -> create Stripe subscription
  3. API call/scan -> record in UsageMeter
  4. End of period -> report usage to Stripe
  5. Webhook -> update subscription status

  ## License Tiers

  - `:trial` - Free tier, no Stripe subscription
  - `:pro` - Monthly subscription with base + usage overage
  - `:enterprise` - Annual contract with usage-based billing

  ## Example

      # Record usage
      Billing.record_usage(org_id, :api_call)
      Billing.record_usage(org_id, :scan, 5)

      # Get usage
      Billing.get_current_usage(org_id)
      Billing.get_usage_summary(org_id, days: 30)

      # Subscription management
      Billing.create_subscription(org_id, :pro)
      Billing.cancel_subscription(org_id)
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Billing.{StripeClient, UsageMeter, Subscription, UsageRecord}
  alias TamanduaServer.Tenants
  alias TamanduaServer.Accounts.Organization

  require Logger

  # ===========================================================================
  # Subscription Management
  # ===========================================================================

  @doc """
  Gets the subscription for an organization.

  Returns `{:ok, subscription}` or `{:error, :not_found}`.
  """
  def get_subscription(org_id) do
    case Repo.get_by(Subscription, organization_id: org_id) do
      nil -> {:error, :not_found}
      sub -> {:ok, sub}
    end
  end

  @doc """
  Gets the subscription for an organization, or nil.
  """
  def get_subscription!(org_id) do
    Repo.get_by(Subscription, organization_id: org_id)
  end

  @doc """
  Creates a subscription for an organization.

  If the org doesn't have a Stripe customer, creates one first.

  ## Parameters

  - `org_id` - Organization ID
  - `tier` - License tier (:pro or :enterprise)
  - `opts` - Options:
    - `:trial_days` - Number of trial days

  ## Returns

  - `{:ok, subscription}` on success
  - `{:error, reason}` on failure
  """
  def create_subscription(org_id, tier, opts \\ []) when tier in [:pro, :enterprise] do
    with {:ok, org} <- Tenants.get_organization(org_id),
         {:ok, customer_id} <- ensure_stripe_customer(org),
         {:ok, price_id} <- get_price_for_tier(tier),
         {:ok, stripe_sub} <- StripeClient.create_subscription(customer_id, price_id, opts) do
      # Create local subscription record
      attrs = %{
        organization_id: org_id,
        stripe_customer_id: customer_id,
        stripe_subscription_id: stripe_sub.id,
        stripe_price_id: price_id,
        status: stripe_sub.status,
        current_period_start: DateTime.from_unix!(stripe_sub.current_period_start),
        current_period_end: DateTime.from_unix!(stripe_sub.current_period_end)
      }

      %Subscription{}
      |> Subscription.changeset(attrs)
      |> Repo.insert()
    end
  end

  @doc """
  Updates subscription status from a Stripe webhook event.

  Called when receiving subscription.created, subscription.updated,
  or subscription.deleted events.
  """
  def update_subscription_from_webhook(stripe_subscription) do
    case Repo.get_by(Subscription, stripe_subscription_id: stripe_subscription.id) do
      nil ->
        Logger.warning("Received webhook for unknown subscription: #{stripe_subscription.id}")
        {:error, :not_found}

      subscription ->
        attrs = %{
          status: stripe_subscription.status,
          current_period_start: DateTime.from_unix!(stripe_subscription.current_period_start),
          current_period_end: DateTime.from_unix!(stripe_subscription.current_period_end),
          canceled_at:
            if(stripe_subscription.canceled_at,
              do: DateTime.from_unix!(stripe_subscription.canceled_at)
            ),
          cancel_at_period_end: stripe_subscription.cancel_at_period_end
        }

        subscription
        |> Subscription.update_changeset(attrs)
        |> Repo.update()
        |> tap(fn
          {:ok, sub} ->
            # Sync status to organization
            maybe_update_org_status(sub)

          _ ->
            :ok
        end)
    end
  end

  @doc """
  Cancels a subscription.

  ## Options

  - `:immediately` - If true, cancels immediately. Otherwise, cancels at period end.
  """
  def cancel_subscription(org_id, opts \\ []) do
    with {:ok, subscription} <- get_subscription(org_id),
         {:ok, _} <- StripeClient.cancel_subscription(subscription.stripe_subscription_id, opts) do
      # Status will be updated via webhook
      {:ok, subscription}
    end
  end

  # ===========================================================================
  # Usage Tracking
  # ===========================================================================

  @doc """
  Records usage for billing.

  ## Types

  - `:api_call` - API request
  - `:scan` - Model scan
  - `:storage` - Storage bytes (can be negative for deletions)

  ## Examples

      Billing.record_usage(org_id, :api_call)
      Billing.record_usage(org_id, :scan, 5)
      Billing.record_usage(org_id, :storage, 1024)
  """
  def record_usage(org_id, type, count \\ 1)

  def record_usage(org_id, :api_call, count) do
    UsageMeter.record_api_call(org_id, count)
  end

  def record_usage(org_id, :scan, count) do
    UsageMeter.record_scan(org_id, count)
  end

  def record_usage(org_id, :storage, bytes) do
    UsageMeter.record_storage(org_id, bytes)
  end

  @doc """
  Gets current (in-memory) usage for an organization.
  """
  def get_current_usage(org_id) do
    UsageMeter.get_all_usage(org_id)
  end

  @doc """
  Gets usage summary for a time period from the database.

  ## Options

  - `:days` - Number of days to look back (default: 30)

  ## Returns

  A map with aggregated usage:
  - `total_api_calls`
  - `total_scans`
  - `total_storage`
  - `period_count`
  """
  def get_usage_summary(org_id, opts \\ []) do
    days = Keyword.get(opts, :days, 30)
    since = DateTime.utc_now() |> DateTime.add(-days * 24 * 60 * 60, :second)

    query =
      from r in UsageRecord,
        where: r.organization_id == ^org_id and r.period_start >= ^since,
        select: %{
          total_api_calls: sum(r.api_calls),
          total_scans: sum(r.model_scans),
          total_storage: max(r.storage_bytes),
          period_count: count(r.id)
        }

    case Repo.one(query) do
      nil ->
        %{total_api_calls: 0, total_scans: 0, total_storage: 0, period_count: 0}

      result ->
        # Handle nil values from empty results
        %{
          total_api_calls: result.total_api_calls || 0,
          total_scans: result.total_scans || 0,
          total_storage: result.total_storage || 0,
          period_count: result.period_count || 0
        }
    end
  end

  @doc """
  Reports unreported usage to Stripe (called by scheduler).

  Finds all usage records not yet reported to Stripe and syncs them.
  """
  def report_usage_to_stripe do
    unreported =
      from(r in UsageRecord,
        where: r.reported_to_stripe == false,
        preload: [:organization]
      )
      |> Repo.all()

    Enum.each(unreported, fn record ->
      case get_subscription(record.organization_id) do
        {:ok, subscription} when subscription.status in ["active", "trialing"] ->
          report_record_to_stripe(record, subscription)

        _ ->
          # No active subscription, mark as reported (trial/free tier)
          record
          |> Ecto.Changeset.change(reported_to_stripe: true)
          |> Repo.update()
      end
    end)
  end

  # ===========================================================================
  # Billing Portal
  # ===========================================================================

  @doc """
  Generates a billing portal URL for self-service subscription management.

  Returns `{:ok, url}` or `{:error, reason}`.
  """
  def get_portal_url(org_id, return_url) do
    with {:ok, subscription} <- get_subscription(org_id) do
      StripeClient.create_portal_session(subscription.stripe_customer_id, return_url)
    end
  end

  @doc """
  Gets invoices for an organization.

  ## Options

  - `:limit` - Maximum number of invoices (default: 10)
  """
  def get_invoices(org_id, opts \\ []) do
    with {:ok, subscription} <- get_subscription(org_id) do
      StripeClient.list_invoices(subscription.stripe_customer_id, opts)
    end
  end

  # ===========================================================================
  # Private Helpers
  # ===========================================================================

  defp ensure_stripe_customer(org) do
    if org.stripe_customer_id do
      {:ok, org.stripe_customer_id}
    else
      # Create new Stripe customer
      case StripeClient.create_customer(org.id, %{
             email: get_org_email(org),
             name: org.name,
             slug: org.slug
           }) do
        {:ok, customer} ->
          # Save customer ID to org
          case Tenants.update_organization(org, %{stripe_customer_id: customer.id}) do
            {:ok, _} -> {:ok, customer.id}
            error -> error
          end

        error ->
          error
      end
    end
  end

  defp get_org_email(org) do
    # Get admin user email for billing contact
    alias TamanduaServer.Accounts.User

    case Repo.one(
           from u in User,
             where: u.organization_id == ^org.id and u.role == "admin",
             limit: 1,
             select: u.email
         ) do
      nil -> "billing@#{org.slug}.treantlab.org"
      email -> email
    end
  end

  defp get_price_for_tier(tier) do
    prices = Application.get_env(:tamandua_server, __MODULE__)[:prices] || %{}

    price_id =
      case tier do
        :pro -> prices[:pro_monthly]
        :enterprise -> prices[:enterprise_annual]
        _ -> nil
      end

    case price_id do
      nil -> {:error, :price_not_configured}
      id -> {:ok, id}
    end
  end

  defp maybe_update_org_status(%Subscription{} = subscription) do
    case subscription.status do
      status when status in ["canceled", "unpaid"] ->
        # Suspend the organization
        with {:ok, org} <- Tenants.get_organization(subscription.organization_id) do
          Tenants.suspend_organization(org, "Subscription #{status}")
        end

      "active" ->
        # Reactivate if was suspended for billing
        with {:ok, org} <- Tenants.get_organization(subscription.organization_id),
             false <- org.is_active do
          Tenants.reactivate_organization(org)
        end

      _ ->
        :ok
    end
  end

  defp report_record_to_stripe(record, subscription) do
    # Get metered subscription items
    with {:ok, stripe_sub} <- StripeClient.get_subscription(subscription.stripe_subscription_id) do
      record_ids =
        stripe_sub.items.data
        |> Enum.filter(fn item ->
          item.price.recurring && item.price.recurring.usage_type == "metered"
        end)
        |> Enum.flat_map(fn item ->
          # Report based on item's price metadata
          quantity =
            case item.price.metadata["metric"] do
              "api_calls" -> record.api_calls
              "model_scans" -> record.model_scans
              _ -> 0
            end

          if quantity > 0 do
            case StripeClient.report_usage(item.id, quantity) do
              {:ok, usage_record} -> [usage_record.id]
              _ -> []
            end
          else
            []
          end
        end)

      record
      |> Ecto.Changeset.change(
        reported_to_stripe: true,
        stripe_usage_record_ids: record_ids
      )
      |> Repo.update()
    end
  end
end
