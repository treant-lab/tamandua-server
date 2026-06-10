defmodule TamanduaServer.Accounts.Organization do
  @moduledoc """
  Schema for organizations (multi-tenant support).

  Organizations are the primary tenant unit in Tamandua. Each organization
  has its own:
  - Users and roles
  - Agents and alerts
  - License tier with feature limits
  - Isolated data access

  ## License Tiers

  - `:trial` - 10 agents, basic features, 14-day limit
  - `:pro` - 100 agents, advanced detection, 1-year subscription
  - `:enterprise` - Unlimited agents, full features, custom terms

  ## Features by Tier

  Trial: Basic detection, dashboards, alerts
  Pro: + Advanced hunting, behavioral analytics, playbooks
  Enterprise: + Custom integrations, API access, dedicated support, MSSP capabilities
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @license_tiers [:trial, :pro, :enterprise]
  @max_agents_by_tier %{trial: 10, pro: 100, enterprise: 10_000}
  @regions [:eu, :us, :apac, :ca, :uk, :au, :jp, :in]

  @derive {Jason.Encoder, only: [:id, :name, :slug, :settings, :license_tier, :max_agents, :features, :subscription_expires_at, :is_active, :region, :inserted_at, :updated_at]}

  schema "organizations" do
    field :name, :string
    field :slug, :string
    field :settings, :map, default: %{}
    field :license_tier, Ecto.Enum, values: @license_tiers, default: :trial
    field :max_agents, :integer, default: 10
    field :features, :map, default: %{}
    field :subscription_expires_at, :utc_datetime_usec
    field :is_active, :boolean, default: true
    field :region, Ecto.Enum, values: @regions

    has_many :users, TamanduaServer.Accounts.User
    has_many :agents, TamanduaServer.Agents.Agent
    has_many :alerts, TamanduaServer.Alerts.Alert
    has_many :roles, TamanduaServer.Accounts.Role

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(name slug)a
  @optional_fields ~w(settings license_tier max_agents features subscription_expires_at is_active region)a

  def changeset(org, attrs) do
    org
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_format(:slug, ~r/^[a-z0-9-]+$/, message: "must be lowercase alphanumeric with hyphens")
    |> validate_length(:slug, min: 2, max: 50)
    |> validate_length(:name, min: 1, max: 255)
    |> validate_inclusion(:license_tier, @license_tiers)
    |> validate_inclusion(:region, @regions)
    |> validate_number(:max_agents, greater_than: 0, less_than_or_equal_to: 100_000)
    |> unique_constraint(:slug)
    |> set_max_agents_from_tier()
  end

  @doc """
  Changeset for upgrading/downgrading license tier.
  """
  def license_changeset(org, attrs) do
    org
    |> cast(attrs, [:license_tier, :max_agents, :subscription_expires_at, :features])
    |> validate_inclusion(:license_tier, @license_tiers)
    |> set_max_agents_from_tier()
  end

  defp set_max_agents_from_tier(changeset) do
    case get_change(changeset, :license_tier) do
      nil ->
        changeset

      tier ->
        default_max = Map.get(@max_agents_by_tier, tier, 10)
        # Only set if not explicitly provided
        if get_change(changeset, :max_agents) do
          changeset
        else
          put_change(changeset, :max_agents, default_max)
        end
    end
  end

  @doc """
  Returns the license tiers.
  """
  def license_tiers, do: @license_tiers

  @doc """
  Returns default max agents for a tier.
  """
  def default_max_agents(tier), do: Map.get(@max_agents_by_tier, tier, 10)

  @doc """
  Returns the default features for a tier.
  """
  def default_features(:trial) do
    %{
      detection: true,
      dashboards: true,
      alerts: true,
      basic_response: true,
      hunting: false,
      behavioral_analytics: false,
      playbooks: false,
      api_access: false,
      custom_integrations: false,
      mssp_features: false
    }
  end

  def default_features(:pro) do
    %{
      detection: true,
      dashboards: true,
      alerts: true,
      basic_response: true,
      hunting: true,
      behavioral_analytics: true,
      playbooks: true,
      api_access: true,
      custom_integrations: false,
      mssp_features: false
    }
  end

  def default_features(:enterprise) do
    %{
      detection: true,
      dashboards: true,
      alerts: true,
      basic_response: true,
      hunting: true,
      behavioral_analytics: true,
      playbooks: true,
      api_access: true,
      custom_integrations: true,
      mssp_features: true
    }
  end

  @doc """
  Checks if organization has a specific feature enabled.
  """
  def has_feature?(%__MODULE__{features: features, license_tier: tier}, feature) when is_atom(feature) do
    # Check explicit features first, then fall back to tier defaults
    case Map.get(features, to_string(feature)) do
      nil -> Map.get(default_features(tier), feature, false)
      value -> value
    end
  end

  @doc """
  Checks if the organization subscription is active.
  """
  def subscription_active?(%__MODULE__{is_active: false}), do: false
  def subscription_active?(%__MODULE__{subscription_expires_at: nil}), do: true
  def subscription_active?(%__MODULE__{subscription_expires_at: expires_at}) do
    DateTime.compare(expires_at, DateTime.utc_now()) == :gt
  end

  @doc """
  Checks if the organization can add more agents.
  """
  def can_add_agent?(%__MODULE__{} = org, current_agent_count) do
    subscription_active?(org) && current_agent_count < org.max_agents
  end

  @doc """
  Returns list of supported regions.
  """
  def regions, do: @regions

  @doc """
  Checks if a region is valid.
  """
  def valid_region?(region) when region in @regions, do: true
  def valid_region?(_), do: false
end
