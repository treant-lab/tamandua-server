defmodule TamanduaServer.InsiderThreat.PeerGroup do
  @moduledoc """
  Peer group management and baseline calculation for insider threat detection.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts.User
  alias TamanduaServer.InsiderThreat.PeerGroupMember

  @type t :: %__MODULE__{}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "insider_threat_peer_groups" do
    field :name, :string
    field :description, :string
    field :group_type, :string
    field :baseline, :map, default: %{}
    field :organization_id, :binary_id

    has_many :members, PeerGroupMember
    many_to_many :users, User, join_through: PeerGroupMember

    timestamps()
  end

  @doc false
  def changeset(peer_group, attrs) do
    peer_group
    |> cast(attrs, [:name, :description, :group_type, :baseline, :organization_id])
    |> validate_required([:name, :group_type, :organization_id])
    |> validate_inclusion(:group_type, ~w(role department location manual))
    |> unique_constraint([:name, :organization_id])
  end

  @doc """
  Calculate baseline statistics for a peer group.
  """
  @spec calculate_baseline(String.t() | Ecto.UUID.t(), DateTime.t(), DateTime.t()) ::
          {:ok, map()} | {:error, any()}
  def calculate_baseline(peer_group_id, start_time, end_time) do
    case get(peer_group_id) do
      nil ->
        {:error, :peer_group_not_found}

      peer_group ->
        user_ids = get_user_ids(peer_group)

        baseline = %{
          calculated_at: DateTime.utc_now(),
          period: %{
            start: start_time,
            end: end_time
          },
          data_access: calculate_data_access_baseline(user_ids, start_time, end_time),
          access_hours: calculate_access_hours_baseline(user_ids, start_time, end_time),
          file_shares: calculate_file_share_baseline(user_ids, start_time, end_time),
          applications: calculate_application_baseline(user_ids, start_time, end_time),
          authentication: calculate_auth_baseline(user_ids, start_time, end_time),
          network: calculate_network_baseline(user_ids, start_time, end_time)
        }

        peer_group
        |> changeset(%{baseline: baseline})
        |> Repo.update()

        {:ok, baseline}
    end
  end

  @doc """
  Get a peer group by ID.
  """
  @spec get(String.t() | Ecto.UUID.t()) :: t() | nil
  def get(id) do
    Repo.get(__MODULE__, id)
    |> Repo.preload(:members)
  end

  @doc """
  List all peer groups for an organization.
  """
  @spec list_by_organization(Ecto.UUID.t()) :: [t()]
  def list_by_organization(organization_id) do
    from(pg in __MODULE__,
      where: pg.organization_id == ^organization_id,
      order_by: [asc: pg.name]
    )
    |> Repo.all()
    |> Repo.preload(:members)
  end

  @doc """
  Create a new peer group.
  """
  @spec create(map()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def create(attrs) do
    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Add a user to a peer group.
  """
  @spec add_member(String.t() | Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, PeerGroupMember.t()} | {:error, any()}
  def add_member(peer_group_id, user_id) do
    %PeerGroupMember{}
    |> PeerGroupMember.changeset(%{
      peer_group_id: peer_group_id,
      user_id: user_id
    })
    |> Repo.insert()
  end

  @doc """
  Remove a user from a peer group.
  """
  @spec remove_member(String.t() | Ecto.UUID.t(), Ecto.UUID.t()) :: :ok | {:error, any()}
  def remove_member(peer_group_id, user_id) do
    from(m in PeerGroupMember,
      where: m.peer_group_id == ^peer_group_id and m.user_id == ^user_id
    )
    |> Repo.delete_all()

    :ok
  end

  @doc """
  Get user IDs for a peer group.
  """
  @spec get_user_ids(t()) :: [Ecto.UUID.t()]
  def get_user_ids(%__MODULE__{members: members}) do
    Enum.map(members, & &1.user_id)
  end

  @doc """
  Check if user is an outlier compared to peer group baseline.
  """
  @spec is_outlier?(t(), Ecto.UUID.t(), atom(), float()) :: boolean()
  def is_outlier?(%__MODULE__{baseline: baseline}, user_id, metric, user_value) do
    case get_in(baseline, [metric]) do
      nil ->
        false

      baseline_stats ->
        mean = baseline_stats[:mean] || 0.0
        std_dev = baseline_stats[:std_dev] || 0.0

        # Consider outlier if more than 2 standard deviations from mean
        abs(user_value - mean) > 2 * std_dev
    end
  end

  @doc """
  Calculate deviation from peer group baseline.
  """
  @spec calculate_deviation(t(), atom(), float()) :: float()
  def calculate_deviation(%__MODULE__{baseline: baseline}, metric, user_value) do
    case get_in(baseline, [metric]) do
      nil ->
        0.0

      baseline_stats ->
        mean = baseline_stats[:mean] || 0.0
        std_dev = baseline_stats[:std_dev] || 1.0

        (user_value - mean) / std_dev
    end
  end

  # Private functions for baseline calculation

  defp calculate_data_access_baseline(user_ids, start_time, end_time) do
    # Query events for data access
    query =
      from(e in "events",
        where:
          e.user_id in ^user_ids and
            e.inserted_at >= ^start_time and
            e.inserted_at <= ^end_time and
            e.event_type in ["file_access", "data_read"],
        select: %{
          user_id: e.user_id,
          bytes: fragment("COALESCE((payload->>'bytes_read')::bigint, 0)")
        }
      )

    user_totals =
      Repo.all(query)
      |> Enum.group_by(& &1.user_id)
      |> Enum.map(fn {user_id, events} ->
        {user_id, Enum.sum(Enum.map(events, & &1.bytes))}
      end)
      |> Map.new()

    calculate_stats(Map.values(user_totals))
  end

  defp calculate_access_hours_baseline(user_ids, start_time, end_time) do
    # Query events for access patterns
    query =
      from(e in "events",
        where:
          e.user_id in ^user_ids and
            e.inserted_at >= ^start_time and
            e.inserted_at <= ^end_time,
        select: %{
          hour: fragment("EXTRACT(HOUR FROM ?)", e.inserted_at)
        }
      )

    hour_counts =
      Repo.all(query)
      |> Enum.map(& &1.hour)
      |> Enum.frequencies()

    typical_hours =
      hour_counts
      |> Enum.filter(fn {_hour, count} -> count > length(user_ids) * 5 end)
      |> Enum.map(fn {hour, _count} -> trunc(hour) end)
      |> Enum.sort()

    %{
      typical_hours: typical_hours,
      hour_distribution: hour_counts
    }
  end

  defp calculate_file_share_baseline(user_ids, start_time, end_time) do
    query =
      from(e in "events",
        where:
          e.user_id in ^user_ids and
            e.inserted_at >= ^start_time and
            e.inserted_at <= ^end_time and
            e.event_type == "file_access",
        select: fragment("DISTINCT payload->>'share_path'")
      )

    shares = Repo.all(query) |> Enum.reject(&is_nil/1)

    %{
      typical_shares: shares,
      share_count: length(shares)
    }
  end

  defp calculate_application_baseline(user_ids, start_time, end_time) do
    query =
      from(e in "events",
        where:
          e.user_id in ^user_ids and
            e.inserted_at >= ^start_time and
            e.inserted_at <= ^end_time and
            e.event_type == "process_start",
        select: fragment("payload->>'process_name'")
      )

    apps =
      Repo.all(query)
      |> Enum.reject(&is_nil/1)
      |> Enum.frequencies()
      |> Enum.filter(fn {_app, count} -> count > length(user_ids) * 2 end)
      |> Enum.map(fn {app, _count} -> app end)

    %{
      typical_applications: apps,
      application_count: length(apps)
    }
  end

  defp calculate_auth_baseline(user_ids, start_time, end_time) do
    query =
      from(e in "events",
        where:
          e.user_id in ^user_ids and
            e.inserted_at >= ^start_time and
            e.inserted_at <= ^end_time and
            e.event_type in ["authentication_success", "authentication_failure"],
        select: %{
          user_id: e.user_id,
          success: fragment("CASE WHEN event_type = 'authentication_success' THEN 1 ELSE 0 END")
        }
      )

    auth_data =
      Repo.all(query)
      |> Enum.group_by(& &1.user_id)

    success_counts =
      auth_data
      |> Enum.map(fn {_user_id, events} ->
        Enum.sum(Enum.map(events, & &1.success))
      end)

    %{
      mean_auths_per_day: calculate_stats(success_counts)[:mean] || 0.0,
      stats: calculate_stats(success_counts)
    }
  end

  defp calculate_network_baseline(user_ids, start_time, end_time) do
    query =
      from(e in "events",
        where:
          e.user_id in ^user_ids and
            e.inserted_at >= ^start_time and
            e.inserted_at <= ^end_time and
            e.event_type == "network_connection",
        select: %{
          user_id: e.user_id,
          bytes: fragment("COALESCE((payload->>'bytes_sent')::bigint, 0)")
        }
      )

    user_totals =
      Repo.all(query)
      |> Enum.group_by(& &1.user_id)
      |> Enum.map(fn {user_id, events} ->
        {user_id, Enum.sum(Enum.map(events, & &1.bytes))}
      end)
      |> Map.new()

    calculate_stats(Map.values(user_totals))
  end

  defp calculate_stats([]), do: %{mean: 0.0, std_dev: 0.0, min: 0.0, max: 0.0, count: 0}

  defp calculate_stats(values) do
    count = length(values)
    mean = Enum.sum(values) / count

    variance =
      values
      |> Enum.map(fn x -> :math.pow(x - mean, 2) end)
      |> Enum.sum()
      |> Kernel./(count)

    std_dev = :math.sqrt(variance)

    %{
      mean: mean,
      std_dev: std_dev,
      min: Enum.min(values),
      max: Enum.max(values),
      median: median(values),
      count: count
    }
  end

  defp median([]), do: 0.0

  defp median(values) do
    sorted = Enum.sort(values)
    count = length(sorted)
    mid = div(count, 2)

    if rem(count, 2) == 0 do
      (Enum.at(sorted, mid - 1) + Enum.at(sorted, mid)) / 2
    else
      Enum.at(sorted, mid)
    end
  end
end
