defmodule TamanduaServer.Billing.Subscription do
  @moduledoc """
  Subscription schema linking Stripe subscriptions to organizations.

  Tracks subscription status, billing periods, and syncs with Stripe webhooks.

  ## Statuses

  - `active` - Subscription is active and paid
  - `past_due` - Payment failed but subscription not yet canceled
  - `canceled` - Subscription has been canceled
  - `trialing` - In trial period
  - `incomplete` - Initial payment failed
  - `incomplete_expired` - Initial payment failed and grace period expired
  - `unpaid` - Invoice remains unpaid after grace period
  - `paused` - Subscription is paused (manual or scheduled)
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @statuses ~w(active past_due canceled trialing incomplete incomplete_expired unpaid paused)

  schema "subscriptions" do
    belongs_to :organization, TamanduaServer.Accounts.Organization

    field :stripe_customer_id, :string
    field :stripe_subscription_id, :string
    field :stripe_price_id, :string

    field :status, :string, default: "active"
    field :current_period_start, :utc_datetime_usec
    field :current_period_end, :utc_datetime_usec
    field :canceled_at, :utc_datetime_usec
    field :cancel_at_period_end, :boolean, default: false

    field :metadata, :map, default: %{}

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(organization_id stripe_customer_id status)a
  @optional_fields ~w(stripe_subscription_id stripe_price_id current_period_start current_period_end canceled_at cancel_at_period_end metadata)a

  @doc """
  Creates a changeset for a new subscription.
  """
  def changeset(subscription, attrs) do
    subscription
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:status, @statuses)
    |> foreign_key_constraint(:organization_id)
    |> unique_constraint(:organization_id)
    |> unique_constraint(:stripe_customer_id)
    |> unique_constraint(:stripe_subscription_id)
  end

  @doc """
  Creates a changeset for updating a subscription (e.g., from webhook).
  """
  def update_changeset(subscription, attrs) do
    subscription
    |> cast(attrs, @optional_fields ++ [:status])
    |> validate_inclusion(:status, @statuses)
  end

  @doc """
  Returns true if the subscription is active (paying or trialing).
  """
  def active?(%__MODULE__{status: status}) when status in ["active", "trialing"], do: true
  def active?(_), do: false

  @doc """
  Returns true if the subscription is in a warning state (payment issues).
  """
  def warning?(%__MODULE__{status: status}) when status in ["past_due", "incomplete"], do: true
  def warning?(_), do: false

  @doc """
  Returns true if the subscription is canceled or will be canceled.
  """
  def canceled?(%__MODULE__{status: "canceled"}), do: true
  def canceled?(%__MODULE__{cancel_at_period_end: true}), do: true
  def canceled?(_), do: false

  @doc """
  Returns the list of valid statuses.
  """
  def statuses, do: @statuses
end
