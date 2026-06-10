defmodule TamanduaServer.Kubernetes.AdmissionLog do
  @moduledoc """
  Ecto schema for Kubernetes admission decision audit logs.

  Every admission decision (allow, deny, mutate) is recorded for compliance
  and forensic analysis. Logs include the requesting user, resource details,
  which policies matched, and the final decision.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query
  alias TamanduaServer.Repo

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "k8s_admission_logs" do
    field :uid, :string
    field :namespace, :string
    field :name, :string
    field :resource_kind, :string
    field :operation, :string
    field :decision, :string
    field :reason, :string
    field :warnings, {:array, :string}, default: []
    field :policy_names, {:array, :string}, default: []
    field :patches_applied, :integer, default: 0
    field :requesting_user, :string
    field :requesting_groups, {:array, :string}, default: []
    field :dry_run, :boolean, default: false
    field :duration_us, :integer
    field :metadata, :map, default: %{}

    timestamps(updated_at: false)
  end

  @required [:uid, :decision]
  @optional [
    :namespace, :name, :resource_kind, :operation, :reason,
    :warnings, :policy_names, :patches_applied, :requesting_user,
    :requesting_groups, :dry_run, :duration_us, :metadata
  ]

  def changeset(log, attrs) do
    log
    |> cast(attrs, @required ++ @optional)
    |> validate_required(@required)
    |> validate_inclusion(:decision, ["allow", "deny", "mutate", "error"])
  end

  @doc "Insert an admission log entry."
  def record(attrs) do
    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc "List recent admission logs with optional filters."
  def list_logs(filters \\ %{}, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)

    __MODULE__
    |> apply_filters(filters)
    |> order_by([l], desc: l.inserted_at)
    |> limit(^limit)
    |> offset(^offset)
    |> Repo.all()
  end

  @doc "Count logs by decision type."
  def decision_counts(since \\ nil) do
    query =
      from l in __MODULE__,
        group_by: l.decision,
        select: {l.decision, count(l.id)}

    query =
      if since do
        from l in query, where: l.inserted_at >= ^since
      else
        query
      end

    query
    |> Repo.all()
    |> Map.new()
  end

  defp apply_filters(query, filters) do
    query
    |> maybe_filter(:namespace, filters["namespace"] || filters[:namespace])
    |> maybe_filter(:decision, filters["decision"] || filters[:decision])
    |> maybe_filter(:resource_kind, filters["resource_kind"] || filters[:resource_kind])
    |> maybe_filter_since(filters["since"] || filters[:since])
  end

  defp maybe_filter(query, _field, nil), do: query
  defp maybe_filter(query, :namespace, ns), do: from(l in query, where: l.namespace == ^ns)
  defp maybe_filter(query, :decision, d), do: from(l in query, where: l.decision == ^d)
  defp maybe_filter(query, :resource_kind, k), do: from(l in query, where: l.resource_kind == ^k)

  defp maybe_filter_since(query, nil), do: query
  defp maybe_filter_since(query, since) when is_binary(since) do
    case DateTime.from_iso8601(since) do
      {:ok, dt, _} -> from(l in query, where: l.inserted_at >= ^dt)
      _ -> query
    end
  end
  defp maybe_filter_since(query, %DateTime{} = since) do
    from(l in query, where: l.inserted_at >= ^since)
  end
end
