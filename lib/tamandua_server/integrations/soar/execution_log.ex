defmodule TamanduaServer.Integrations.SOAR.ExecutionLog do
  @moduledoc """
  Log of SOAR playbook executions.

  Tracks all playbook triggers with:
  - Alert and rule associations
  - SOAR platform and playbook details
  - Execution status and timing
  - Result data from SOAR callbacks

  ## Status Values

  - `pending` - Trigger sent, awaiting confirmation
  - `running` - Playbook is executing
  - `completed` - Playbook finished successfully
  - `failed` - Playbook failed
  - `timeout` - No response received within timeout
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Repo

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "soar_execution_logs" do
    field :alert_id, :binary_id
    field :trigger_rule_id, :binary_id
    field :soar_platform, :string        # "xsoar", "tines"
    field :playbook_name, :string
    field :execution_id, :string         # ID from SOAR platform
    field :status, :string, default: "pending"  # pending, running, completed, failed, timeout
    field :result, :map
    field :error_message, :string
    field :started_at, :utc_datetime_usec
    field :completed_at, :utc_datetime_usec

    # Callback tracking
    field :callback_received_at, :utc_datetime_usec
    field :callback_payload, :map

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields [:soar_platform, :playbook_name]
  @optional_fields [:alert_id, :trigger_rule_id, :execution_id, :status, :result, :error_message,
                    :started_at, :completed_at, :callback_received_at, :callback_payload]

  @valid_statuses ["pending", "running", "completed", "failed", "timeout"]

  @type t :: %__MODULE__{}

  @doc """
  Changeset for creating/updating execution logs.
  """
  def changeset(log, attrs) do
    log
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:status, @valid_statuses)
    |> validate_inclusion(:soar_platform, ["xsoar", "tines"])
  end

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Create a new execution log entry.

  ## Parameters

  - `attrs` - Map with soar_platform, playbook_name, alert_id, etc.

  ## Returns

  `{:ok, log}` or `{:error, changeset}`.
  """
  @spec create(map()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def create(attrs) do
    attrs = Map.put(attrs, :started_at, DateTime.utc_now())

    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update execution log status.

  ## Parameters

  - `log` - ExecutionLog struct or ID
  - `status` - New status
  - `attrs` - Additional attributes to update

  ## Returns

  `{:ok, log}` or `{:error, reason}`.
  """
  @spec update_status(t() | binary(), String.t(), map()) :: {:ok, t()} | {:error, term()}
  def update_status(%__MODULE__{} = log, status, attrs \\ %{}) do
    attrs = attrs
    |> Map.put(:status, status)
    |> maybe_set_completed_at(status)

    log
    |> changeset(attrs)
    |> Repo.update()
  end

  def update_status(log_id, status, attrs) when is_binary(log_id) do
    case get(log_id) do
      nil -> {:error, :not_found}
      log -> update_status(log, status, attrs)
    end
  end

  @doc """
  Update execution log from a SOAR callback.

  ## Parameters

  - `log` - ExecutionLog struct or ID
  - `callback_data` - Parsed callback payload

  ## Returns

  `{:ok, log}` or `{:error, reason}`.
  """
  @spec update_from_callback(t() | binary(), map()) :: {:ok, t()} | {:error, term()}
  def update_from_callback(%__MODULE__{} = log, callback_data) do
    status = normalize_callback_status(callback_data[:status] || callback_data["status"])

    attrs = %{
      status: status,
      result: callback_data[:result] || callback_data["result"],
      error_message: callback_data[:error] || callback_data["error"],
      callback_received_at: DateTime.utc_now(),
      callback_payload: callback_data
    }
    |> maybe_set_completed_at(status)

    update_status(log, status, attrs)
  end

  def update_from_callback(log_id, callback_data) when is_binary(log_id) do
    case get(log_id) do
      nil -> {:error, :not_found}
      log -> update_from_callback(log, callback_data)
    end
  end

  @doc """
  Get execution log by ID.
  """
  @spec get(binary()) :: t() | nil
  def get(id) do
    Repo.get(__MODULE__, id)
  end

  @doc """
  Get execution log by SOAR execution ID.
  """
  @spec get_by_execution_id(String.t()) :: t() | nil
  def get_by_execution_id(execution_id) do
    from(l in __MODULE__, where: l.execution_id == ^execution_id)
    |> Repo.one()
  end

  @doc """
  List execution logs for an alert.
  """
  @spec list_for_alert(binary()) :: [t()]
  def list_for_alert(alert_id) do
    from(l in __MODULE__,
      where: l.alert_id == ^alert_id,
      order_by: [desc: l.inserted_at]
    )
    |> Repo.all()
  end

  @doc """
  List execution logs by status.
  """
  @spec list_by_status(String.t(), keyword()) :: [t()]
  def list_by_status(status, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)

    from(l in __MODULE__,
      where: l.status == ^status,
      order_by: [desc: l.inserted_at],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Get pending executions older than a threshold (for timeout handling).
  """
  @spec list_stale_pending(non_neg_integer()) :: [t()]
  def list_stale_pending(minutes \\ 30) do
    threshold = DateTime.add(DateTime.utc_now(), -minutes * 60, :second)

    from(l in __MODULE__,
      where: l.status == "pending",
      where: l.started_at < ^threshold,
      order_by: [asc: l.started_at]
    )
    |> Repo.all()
  end

  @doc """
  Mark stale pending executions as timed out.
  """
  @spec timeout_stale_executions(non_neg_integer()) :: {non_neg_integer(), nil}
  def timeout_stale_executions(minutes \\ 30) do
    threshold = DateTime.add(DateTime.utc_now(), -minutes * 60, :second)
    now = DateTime.utc_now()

    from(l in __MODULE__,
      where: l.status == "pending",
      where: l.started_at < ^threshold
    )
    |> Repo.update_all(set: [status: "timeout", completed_at: now, updated_at: now])
  end

  @doc """
  Get execution statistics.
  """
  @spec get_stats(keyword()) :: map()
  def get_stats(opts \\ []) do
    since = Keyword.get(opts, :since, DateTime.add(DateTime.utc_now(), -24 * 60 * 60, :second))

    query = from(l in __MODULE__,
      where: l.inserted_at >= ^since,
      group_by: [l.soar_platform, l.status],
      select: {l.soar_platform, l.status, count(l.id)}
    )

    results = Repo.all(query)

    # Transform to nested map
    Enum.reduce(results, %{}, fn {platform, status, count}, acc ->
      platform_stats = Map.get(acc, platform, %{})
      updated_platform = Map.put(platform_stats, status, count)
      Map.put(acc, platform, updated_platform)
    end)
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp maybe_set_completed_at(attrs, status) when status in ["completed", "failed", "timeout"] do
    Map.put_new(attrs, :completed_at, DateTime.utc_now())
  end

  defp maybe_set_completed_at(attrs, _status), do: attrs

  defp normalize_callback_status(status) when is_binary(status) do
    case String.downcase(status) do
      s when s in ["completed", "success", "succeeded", "done"] -> "completed"
      s when s in ["failed", "error", "errored", "failure"] -> "failed"
      s when s in ["running", "in_progress", "executing"] -> "running"
      s when s in ["pending", "queued", "waiting"] -> "pending"
      s when s in ["timeout", "timed_out"] -> "timeout"
      _ -> "completed"  # Default to completed if unknown
    end
  end

  defp normalize_callback_status(_), do: "completed"
end
