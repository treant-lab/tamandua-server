defmodule TamanduaServer.Detection.StorylineRecord do
  @moduledoc """
  Ecto schema for persisted storylines.

  Maps the in-memory `StorylineData` struct (from the Storyline GenServer's
  ETS tables) into a PostgreSQL row for durability across restarts and for
  historical querying.

  The autonomous Storyline engine keeps the hot working set in ETS for
  sub-millisecond reads. The `StorylinePersistence` module periodically
  snapshots active storylines into this table.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Repo

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  schema "storylines" do
    belongs_to :agent, TamanduaServer.Agents.Agent
    belongs_to :organization, TamanduaServer.Organizations.Organization
    belongs_to :alert, TamanduaServer.Alerts.Alert

    field :root_pid, :integer
    field :status, :string, default: "active"
    field :severity, :string, default: "low"
    field :total_score, :float, default: 0.0

    field :process_pids, {:array, :integer}, default: []
    field :mitre_tactics, {:array, :string}, default: []
    field :mitre_techniques, {:array, :string}, default: []
    field :detections, {:array, :map}, default: []

    field :detection_count, :integer, default: 0
    field :process_count, :integer, default: 0
    field :tactic_count, :integer, default: 0

    field :first_seen_at, :utc_datetime_usec
    field :last_seen_at, :utc_datetime_usec

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(id agent_id status severity total_score)a
  @optional_fields ~w(
    organization_id alert_id root_pid process_pids
    mitre_tactics mitre_techniques detections
    detection_count process_count tactic_count
    first_seen_at last_seen_at
  )a

  def changeset(record, attrs) do
    record
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:status, ~w(active resolved))
    |> validate_inclusion(:severity, ~w(low medium high critical))
    |> validate_number(:total_score, greater_than_or_equal_to: 0.0)
    |> foreign_key_constraint(:agent_id)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:alert_id)
  end

  # ------------------------------------------------------------------
  # Query helpers
  # ------------------------------------------------------------------

  @doc "List storylines with filters."
  def list(opts \\ []) do
    base_query()
    |> maybe_filter_agent(opts[:agent_id])
    |> maybe_filter_org(opts[:organization_id])
    |> maybe_filter_status(opts[:status])
    |> maybe_filter_min_severity(opts[:min_severity])
    |> order_by([s], desc: s.last_seen_at)
    |> limit(^(opts[:limit] || 50))
    |> offset(^(opts[:offset] || 0))
    |> Repo.all()
  end

  @doc "Count storylines with filters."
  def count(opts \\ []) do
    base_query()
    |> maybe_filter_agent(opts[:agent_id])
    |> maybe_filter_org(opts[:organization_id])
    |> maybe_filter_status(opts[:status])
    |> maybe_filter_min_severity(opts[:min_severity])
    |> Repo.aggregate(:count, :id)
  end

  @doc "Get a single storyline by ID."
  def get(id) do
    Repo.get(__MODULE__, id)
  end

  @doc "Upsert a storyline record (insert or update on conflict)."
  def upsert!(attrs) do
    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert!(
      on_conflict: {:replace, [
        :status, :severity, :total_score, :process_pids,
        :mitre_tactics, :mitre_techniques, :detections,
        :detection_count, :process_count, :tactic_count,
        :alert_id, :last_seen_at, :updated_at
      ]},
      conflict_target: :id
    )
  end

  @doc "Mark resolved storylines older than `cutoff` as resolved in DB."
  def mark_resolved_before(cutoff) do
    from(s in __MODULE__,
      where: s.status == "active" and s.last_seen_at < ^cutoff
    )
    |> Repo.update_all(set: [status: "resolved", updated_at: DateTime.utc_now()])
  end

  @doc "Get summary statistics."
  def stats(opts \\ []) do
    query =
      base_query()
      |> maybe_filter_org(opts[:organization_id])

    active =
      query
      |> where([s], s.status == "active")
      |> Repo.aggregate(:count, :id)

    resolved =
      query
      |> where([s], s.status == "resolved")
      |> Repo.aggregate(:count, :id)

    critical =
      query
      |> where([s], s.severity == "critical" and s.status == "active")
      |> Repo.aggregate(:count, :id)

    high =
      query
      |> where([s], s.severity == "high" and s.status == "active")
      |> Repo.aggregate(:count, :id)

    %{
      active: active,
      resolved: resolved,
      total: active + resolved,
      active_critical: critical,
      active_high: high
    }
  end

  # ------------------------------------------------------------------
  # Private query helpers
  # ------------------------------------------------------------------

  defp base_query, do: from(s in __MODULE__)

  defp maybe_filter_agent(query, nil), do: query
  defp maybe_filter_agent(query, agent_id) do
    where(query, [s], s.agent_id == ^agent_id)
  end

  defp maybe_filter_org(query, nil), do: query
  defp maybe_filter_org(query, org_id) do
    where(query, [s], s.organization_id == ^org_id)
  end

  defp maybe_filter_status(query, nil), do: query
  defp maybe_filter_status(query, status) when is_atom(status) do
    maybe_filter_status(query, to_string(status))
  end
  defp maybe_filter_status(query, status) do
    where(query, [s], s.status == ^status)
  end

  defp maybe_filter_min_severity(query, nil), do: query
  defp maybe_filter_min_severity(query, min_severity) do
    severity_order = %{"low" => 0, "medium" => 1, "high" => 2, "critical" => 3}
    min_str = to_string(min_severity)
    min_ord = Map.get(severity_order, min_str, 0)

    severities =
      severity_order
      |> Enum.filter(fn {_k, v} -> v >= min_ord end)
      |> Enum.map(fn {k, _v} -> k end)

    where(query, [s], s.severity in ^severities)
  end
end
