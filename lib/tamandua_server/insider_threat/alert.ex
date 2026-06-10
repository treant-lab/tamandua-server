defmodule TamanduaServer.InsiderThreat.Alert do
  @moduledoc """
  Insider threat alert schema and management.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query, except: [update: 2]

  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts.{User, Organization}

  @type t :: %__MODULE__{}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "insider_threat_alerts" do
    field :risk_score, :float
    field :severity, :string
    field :indicators, {:array, :map}, default: []
    field :risk_breakdown, :map, default: %{}
    field :user_metrics, :map, default: %{}
    field :trend, :string
    field :status, :string, default: "open"
    field :requires_investigation, :boolean, default: false
    field :investigation_notes, :string
    field :resolution_notes, :string
    field :resolved_at, :utc_datetime_usec
    field :false_positive, :boolean, default: false
    field :suppressed, :boolean, default: false

    # Investigation case linkage
    field :investigation_id, :binary_id

    belongs_to :user, User
    belongs_to :organization, Organization
    belongs_to :investigated_by, User, foreign_key: :investigated_by_id
    belongs_to :resolved_by, User, foreign_key: :resolved_by_id

    timestamps()
  end

  @doc false
  def changeset(alert, attrs) do
    alert
    |> cast(attrs, [
      :user_id,
      :organization_id,
      :risk_score,
      :severity,
      :indicators,
      :risk_breakdown,
      :user_metrics,
      :trend,
      :status,
      :requires_investigation,
      :investigation_notes,
      :resolution_notes,
      :resolved_at,
      :resolved_by_id,
      :investigated_by_id,
      :investigation_id,
      :false_positive,
      :suppressed
    ])
    |> validate_required([:user_id, :risk_score, :severity, :status])
    |> validate_inclusion(:severity, ~w(critical high medium low))
    |> validate_inclusion(:status, ~w(open investigating resolved suppressed))
    |> validate_inclusion(:trend, ~w(increasing decreasing stable))
    |> validate_number(:risk_score, greater_than_or_equal_to: 0, less_than_or_equal_to: 100)
    |> maybe_resolve_organization()
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:investigated_by_id)
    |> foreign_key_constraint(:resolved_by_id)
  end

  @doc """
  Create a new insider threat alert.
  """
  @spec create(map()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def create(attrs) do
    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update an alert.
  """
  @spec update(t(), map()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def update(alert, attrs) do
    alert
    |> changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Get alert by ID.
  """
  @spec get(Ecto.UUID.t()) :: t() | nil
  def get(id) do
    Repo.get(__MODULE__, id)
    |> Repo.preload([:user, :organization, :investigated_by, :resolved_by])
  end

  @doc """
  List alerts for an organization.
  """
  @spec list_by_organization(Ecto.UUID.t(), map()) :: [t()]
  def list_by_organization(organization_id, opts \\ %{}) do
    query =
      from(a in __MODULE__,
        where: a.organization_id == ^organization_id,
        order_by: [desc: a.inserted_at]
      )

    query
    |> apply_filters(opts)
    |> Repo.all()
    |> Repo.preload([:user, :investigated_by, :resolved_by])
  end

  @doc """
  List alerts for a user.
  """
  @spec list_by_user(Ecto.UUID.t(), map()) :: [t()]
  def list_by_user(user_id, opts \\ %{}) do
    query =
      from(a in __MODULE__,
        where: a.user_id == ^user_id,
        order_by: [desc: a.inserted_at]
      )

    query
    |> apply_filters(opts)
    |> Repo.all()
    |> Repo.preload([:user, :investigated_by, :resolved_by])
  end

  @doc """
  Get top users by risk score.
  """
  @spec top_users_by_risk(Ecto.UUID.t(), integer()) :: [map()]
  def top_users_by_risk(organization_id, limit \\ 10) do
    # Get most recent alert for each user
    subquery =
      from(a in __MODULE__,
        where: a.organization_id == ^organization_id and a.status != "resolved",
        distinct: a.user_id,
        order_by: [desc: a.inserted_at],
        select: %{
          user_id: a.user_id,
          risk_score: a.risk_score,
          severity: a.severity,
          trend: a.trend,
          inserted_at: a.inserted_at
        }
      )

    from(s in subquery(subquery),
      order_by: [desc: s.risk_score],
      limit: ^limit,
      preload: [:user]
    )
    |> Repo.all()
  end

  @doc """
  Get risk score distribution.
  """
  @spec risk_distribution(Ecto.UUID.t()) :: map()
  def risk_distribution(organization_id) do
    query =
      from(a in __MODULE__,
        where: a.organization_id == ^organization_id and a.status != "resolved",
        group_by: a.severity,
        select: {a.severity, count(a.id)}
      )

    Repo.all(query)
    |> Map.new()
  end

  @doc """
  Mark alert as under investigation.
  """
  @spec start_investigation(t(), Ecto.UUID.t()) :: {:ok, t()} | {:error, any()}
  def start_investigation(alert, investigator_id) do
    update(alert, %{
      status: "investigating",
      investigated_by_id: investigator_id
    })
  end

  @doc """
  Resolve an alert.
  """
  @spec resolve(t(), Ecto.UUID.t(), String.t(), boolean()) :: {:ok, t()} | {:error, any()}
  def resolve(alert, resolver_id, resolution_notes, false_positive \\ false) do
    update(alert, %{
      status: "resolved",
      resolved_by_id: resolver_id,
      resolved_at: DateTime.utc_now(),
      resolution_notes: resolution_notes,
      false_positive: false_positive
    })
  end

  @doc """
  Suppress an alert.
  """
  @spec suppress(t()) :: {:ok, t()} | {:error, any()}
  def suppress(alert) do
    update(alert, %{
      status: "suppressed",
      suppressed: true
    })
  end

  @doc """
  Link alert to investigation case.
  """
  @spec link_investigation(t(), Ecto.UUID.t()) :: {:ok, t()} | {:error, any()}
  def link_investigation(alert, investigation_id) do
    update(alert, %{investigation_id: investigation_id})
  end

  @doc """
  Get recent alerts (last 24 hours).
  """
  @spec recent_alerts(Ecto.UUID.t(), integer()) :: [t()]
  def recent_alerts(organization_id, hours \\ 24) do
    cutoff = DateTime.add(DateTime.utc_now(), -hours * 3600, :second)

    from(a in __MODULE__,
      where: a.organization_id == ^organization_id and a.inserted_at >= ^cutoff,
      order_by: [desc: a.inserted_at]
    )
    |> Repo.all()
    |> Repo.preload([:user, :investigated_by])
  end

  @doc """
  Get alert statistics.
  """
  @spec statistics(Ecto.UUID.t(), DateTime.t(), DateTime.t()) :: map()
  def statistics(organization_id, start_time, end_time) do
    query =
      from(a in __MODULE__,
        where:
          a.organization_id == ^organization_id and
            a.inserted_at >= ^start_time and
            a.inserted_at <= ^end_time
      )

    total = Repo.aggregate(query, :count)

    open =
      from(a in query, where: a.status == "open")
      |> Repo.aggregate(:count)

    investigating =
      from(a in query, where: a.status == "investigating")
      |> Repo.aggregate(:count)

    resolved =
      from(a in query, where: a.status == "resolved")
      |> Repo.aggregate(:count)

    false_positives =
      from(a in query, where: a.false_positive == true)
      |> Repo.aggregate(:count)

    avg_risk_score =
      Repo.aggregate(query, :avg, :risk_score) || 0.0

    by_severity =
      from(a in query,
        group_by: a.severity,
        select: {a.severity, count(a.id)}
      )
      |> Repo.all()
      |> Map.new()

    %{
      total: total,
      open: open,
      investigating: investigating,
      resolved: resolved,
      false_positives: false_positives,
      avg_risk_score: Float.round(avg_risk_score, 2),
      by_severity: by_severity
    }
  end

  # Private helpers

  defp apply_filters(query, opts) do
    query
    |> filter_by_status(opts[:status])
    |> filter_by_severity(opts[:severity])
    |> filter_by_requires_investigation(opts[:requires_investigation])
    |> apply_limit(opts[:limit])
  end

  defp filter_by_status(query, nil), do: query

  defp filter_by_status(query, status) do
    from(a in query, where: a.status == ^status)
  end

  defp filter_by_severity(query, nil), do: query

  defp filter_by_severity(query, severity) do
    from(a in query, where: a.severity == ^severity)
  end

  defp filter_by_requires_investigation(query, nil), do: query

  defp filter_by_requires_investigation(query, true) do
    from(a in query, where: a.requires_investigation == true)
  end

  defp filter_by_requires_investigation(query, false) do
    from(a in query, where: a.requires_investigation == false)
  end

  defp apply_limit(query, nil), do: query

  defp apply_limit(query, limit) do
    from(a in query, limit: ^limit)
  end

  defp maybe_resolve_organization(changeset) do
    org_id = get_change(changeset, :organization_id) || get_field(changeset, :organization_id)
    user_id = get_change(changeset, :user_id) || get_field(changeset, :user_id)

    if is_nil(org_id) and not is_nil(user_id) do
      case get_user_organization(user_id) do
        nil -> changeset
        resolved_org_id -> put_change(changeset, :organization_id, resolved_org_id)
      end
    else
      changeset
    end
  end

  defp get_user_organization(user_id) do
    from(u in User,
      where: u.id == ^user_id,
      select: u.organization_id
    )
    |> Repo.one()
  end
end
