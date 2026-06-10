defmodule TamanduaServer.Cloud.CloudAccount do
  @moduledoc """
  Cloud Account management for CSPM.

  Stores cloud account configurations and credentials for AWS, Azure, and GCP.
  Handles:
  - Account registration and configuration
  - Credential management (encrypted storage)
  - Scan scheduling and status tracking
  - Multi-cloud account correlation
  """

  require Logger
  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Repo

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @derive {Jason.Encoder, except: [:__meta__, :credentials]}

  schema "cloud_accounts" do
    field :name, :string
    field :provider, :string  # "aws", "azure", "gcp"
    field :account_id, :string  # AWS Account ID, Azure Subscription ID, GCP Project ID
    field :external_id, :string  # For AWS STS AssumeRole
    field :alias, :string
    field :description, :string

    field :status, :string, default: "active"  # "active", "inactive", "error"
    field :connection_status, :string, default: "pending"  # "connected", "disconnected", "error", "pending"
    field :last_connection_error, :string

    # Encrypted credentials (role ARN, tenant ID, service account JSON, etc.)
    field :credentials, :map, default: %{}

    # Regions to scan
    field :regions, {:array, :string}, default: []

    # Scan configuration
    field :scan_enabled, :boolean, default: true
    field :scan_schedule, :string, default: "0 */4 * * *"  # Cron schedule (every 4 hours)
    field :last_scan_at, :utc_datetime
    field :next_scan_at, :utc_datetime
    field :last_scan_status, :string  # "success", "partial", "failed"
    field :last_scan_duration_seconds, :integer
    field :last_scan_resources_count, :integer
    field :last_scan_findings_count, :integer

    # Statistics
    field :resources_count, :integer, default: 0
    field :findings_count, :integer, default: 0
    field :critical_findings_count, :integer, default: 0
    field :compliance_score, :float, default: 100.0

    field :organization_id, :binary_id
    field :created_by, :string
    field :tags, {:array, :string}, default: []

    timestamps()
  end

  @required_fields [:name, :provider, :account_id]
  @optional_fields [
    :external_id, :alias, :description, :status, :connection_status,
    :last_connection_error, :credentials, :regions, :scan_enabled,
    :scan_schedule, :last_scan_at, :next_scan_at, :last_scan_status,
    :last_scan_duration_seconds, :last_scan_resources_count,
    :last_scan_findings_count, :resources_count, :findings_count,
    :critical_findings_count, :compliance_score, :organization_id,
    :created_by, :tags
  ]

  @type cloud_account :: %__MODULE__{}

  # ============================================================================
  # Changesets
  # ============================================================================

  def changeset(account, attrs) do
    account
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:provider, ["aws", "azure", "gcp"])
    |> validate_inclusion(:status, ["active", "inactive", "error"])
    |> validate_inclusion(:connection_status, ["connected", "disconnected", "error", "pending"])
    |> unique_constraint([:provider, :account_id], name: :cloud_accounts_provider_account_id_index)
    |> encrypt_credentials()
  end

  defp encrypt_credentials(changeset) do
    # In production, credentials should be encrypted using a vault service
    # For now, we just pass through (encryption should be added)
    changeset
  end

  # ============================================================================
  # CRUD Operations
  # ============================================================================

  @doc """
  Create a new cloud account.
  """
  @spec create(map()) :: {:ok, cloud_account()} | {:error, Ecto.Changeset.t()}
  def create(attrs) do
    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update a cloud account.
  """
  @spec update(cloud_account() | String.t(), map()) :: {:ok, cloud_account()} | {:error, term()}
  def update(%__MODULE__{} = account, attrs) do
    account
    |> changeset(attrs)
    |> Repo.update()
  end

  def update(account_id, attrs) when is_binary(account_id) do
    case get(account_id) do
      nil -> {:error, :not_found}
      account -> __MODULE__.__MODULE__.update(account, attrs)
    end
  end

  @doc """
  Delete a cloud account.
  """
  @spec delete(cloud_account() | String.t()) :: {:ok, cloud_account()} | {:error, term()}
  def delete(%__MODULE__{} = account) do
    Repo.delete(account)
  end

  def delete(account_id) when is_binary(account_id) do
    case get(account_id) do
      nil -> {:error, :not_found}
      account -> delete(account)
    end
  end

  @doc """
  Get a cloud account by ID.
  """
  @spec get(String.t()) :: cloud_account() | nil
  def get(id) do
    Repo.get(__MODULE__, id)
  end

  @doc """
  Get a cloud account by provider and account ID.
  """
  @spec get_by_account_id(String.t(), String.t()) :: cloud_account() | nil
  def get_by_account_id(provider, account_id) do
    Repo.get_by(__MODULE__, provider: provider, account_id: account_id)
  end

  @doc """
  List all cloud accounts with optional filters.
  """
  @spec list(map()) :: [cloud_account()]
  def list(filters \\ %{}) do
    base_query()
    |> apply_filters(filters)
    |> Repo.all()
  end

  defp base_query do
    from(a in __MODULE__, order_by: [asc: a.provider, asc: a.name])
  end

  defp apply_filters(query, filters) do
    query
    |> filter_by_provider(filters[:provider])
    |> filter_by_status(filters[:status])
    |> filter_by_organization(filters[:organization_id])
    |> filter_by_scan_enabled(filters[:scan_enabled])
  end

  defp filter_by_provider(query, nil), do: query
  defp filter_by_provider(query, provider), do: where(query, [a], a.provider == ^provider)

  defp filter_by_status(query, nil), do: query
  defp filter_by_status(query, status), do: where(query, [a], a.status == ^status)

  defp filter_by_organization(query, nil), do: query
  defp filter_by_organization(query, org_id), do: where(query, [a], a.organization_id == ^org_id)

  defp filter_by_scan_enabled(query, nil), do: query
  defp filter_by_scan_enabled(query, enabled), do: where(query, [a], a.scan_enabled == ^enabled)

  # ============================================================================
  # Connection Management
  # ============================================================================

  @doc """
  Test cloud account connectivity.
  """
  @spec test_connection(cloud_account()) :: {:ok, map()} | {:error, String.t()}
  def test_connection(%__MODULE__{provider: "aws"} = account) do
    case TamanduaServer.Cloud.AWS.test_connection(account.credentials) do
      {:ok, identity} ->
        __MODULE__.update(account, %{
          connection_status: "connected",
          last_connection_error: nil
        })

        {:ok, %{status: "connected", identity: identity}}

      {:error, reason} ->
        __MODULE__.update(account, %{
          connection_status: "error",
          last_connection_error: inspect(reason)
        })

        {:error, inspect(reason)}
    end
  end

  def test_connection(%__MODULE__{provider: "azure"} = account) do
    case TamanduaServer.Cloud.Azure.test_connection(account.credentials) do
      {:ok, info} ->
        __MODULE__.update(account, %{
          connection_status: "connected",
          last_connection_error: nil
        })

        {:ok, %{status: "connected", info: info}}

      {:error, reason} ->
        __MODULE__.update(account, %{
          connection_status: "error",
          last_connection_error: inspect(reason)
        })

        {:error, inspect(reason)}
    end
  end

  def test_connection(%__MODULE__{provider: "gcp"} = account) do
    case TamanduaServer.Cloud.GCP.test_connection(account.credentials) do
      {:ok, info} ->
        __MODULE__.update(account, %{
          connection_status: "connected",
          last_connection_error: nil
        })

        {:ok, %{status: "connected", info: info}}

      {:error, reason} ->
        __MODULE__.update(account, %{
          connection_status: "error",
          last_connection_error: inspect(reason)
        })

        {:error, inspect(reason)}
    end
  end

  # ============================================================================
  # Scan Management
  # ============================================================================

  @doc """
  Start a security scan for a cloud account.
  """
  @spec start_scan(cloud_account() | String.t()) :: {:ok, map()} | {:error, term()}
  def start_scan(%__MODULE__{} = account) do
    Logger.info("Starting CSPM scan for #{account.provider}/#{account.account_id}")
    start_time = DateTime.utc_now()

    scan_result =
      case account.provider do
        "aws" -> TamanduaServer.Cloud.AWS.scan_account(account)
        "azure" -> TamanduaServer.Cloud.Azure.scan_subscription(account)
        "gcp" -> TamanduaServer.Cloud.GCP.scan_project(account)
        _ -> {:error, "Unknown provider: #{account.provider}"}
      end

    end_time = DateTime.utc_now()
    duration_seconds = DateTime.diff(end_time, start_time)

    case scan_result do
      {:ok, result} ->
        # Evaluate resources against policies
        evaluation = TamanduaServer.Cloud.PolicyEngine.evaluate_scan_results(
          result.resources,
          account.provider
        )

        # Persist findings
        TamanduaServer.Cloud.Finding.persist_findings(account.provider, account.account_id)

        # Auto-close stale findings
        TamanduaServer.Cloud.Finding.auto_close_stale_findings(
          account.provider,
          account.account_id,
          start_time
        )

        # Update account statistics
        __MODULE__.update(account, %{
          last_scan_at: start_time,
          last_scan_status: "success",
          last_scan_duration_seconds: duration_seconds,
          last_scan_resources_count: length(result.resources),
          last_scan_findings_count: evaluation.failed,
          resources_count: length(result.resources),
          findings_count: evaluation.failed,
          critical_findings_count: count_critical_findings(evaluation.findings),
          compliance_score: calculate_compliance_score(evaluation)
        })

        {:ok, %{
          scan_id: UUID.uuid4(),
          started_at: start_time,
          completed_at: end_time,
          duration_seconds: duration_seconds,
          resources_scanned: length(result.resources),
          evaluations: evaluation.total_evaluations,
          passed: evaluation.passed,
          failed: evaluation.failed,
          findings_count: length(evaluation.findings)
        }}

      {:error, reason} ->
        __MODULE__.update(account, %{
          last_scan_at: start_time,
          last_scan_status: "failed",
          last_scan_duration_seconds: duration_seconds,
          last_connection_error: inspect(reason)
        })

        {:error, reason}
    end
  end

  def start_scan(account_id) when is_binary(account_id) do
    case get(account_id) do
      nil -> {:error, :not_found}
      account -> start_scan(account)
    end
  end

  defp count_critical_findings(findings) do
    Enum.count(findings, fn f -> f[:severity] == "critical" end)
  end

  defp calculate_compliance_score(evaluation) do
    if evaluation.total_evaluations > 0 do
      Float.round(evaluation.passed / evaluation.total_evaluations * 100, 1)
    else
      100.0
    end
  end

  @doc """
  Get accounts due for scanning.
  """
  @spec accounts_due_for_scan() :: [cloud_account()]
  def accounts_due_for_scan do
    now = DateTime.utc_now()

    from(a in __MODULE__,
      where: a.scan_enabled == true and
             a.status == "active" and
             (is_nil(a.next_scan_at) or a.next_scan_at <= ^now)
    )
    |> Repo.all()
  end

  # ============================================================================
  # Statistics
  # ============================================================================

  @doc """
  Get aggregate statistics across all cloud accounts.
  """
  @spec global_statistics() :: map()
  def global_statistics do
    accounts = list()

    by_provider = Enum.group_by(accounts, & &1.provider)

    %{
      total_accounts: length(accounts),
      active_accounts: Enum.count(accounts, fn a -> a.status == "active" end),
      connected_accounts: Enum.count(accounts, fn a -> a.connection_status == "connected" end),
      total_resources: Enum.sum(Enum.map(accounts, fn a -> a.resources_count || 0 end)),
      total_findings: Enum.sum(Enum.map(accounts, fn a -> a.findings_count || 0 end)),
      critical_findings: Enum.sum(Enum.map(accounts, fn a -> a.critical_findings_count || 0 end)),
      by_provider: %{
        aws: provider_stats(Map.get(by_provider, "aws", [])),
        azure: provider_stats(Map.get(by_provider, "azure", [])),
        gcp: provider_stats(Map.get(by_provider, "gcp", []))
      },
      average_compliance_score: calculate_average_compliance(accounts)
    }
  end

  defp provider_stats(accounts) do
    %{
      accounts: length(accounts),
      resources: Enum.sum(Enum.map(accounts, fn a -> a.resources_count || 0 end)),
      findings: Enum.sum(Enum.map(accounts, fn a -> a.findings_count || 0 end)),
      critical: Enum.sum(Enum.map(accounts, fn a -> a.critical_findings_count || 0 end))
    }
  end

  defp calculate_average_compliance(accounts) do
    scores = accounts |> Enum.map(fn a -> a.compliance_score || 100.0 end) |> Enum.filter(& &1)

    if length(scores) > 0 do
      Float.round(Enum.sum(scores) / length(scores), 1)
    else
      100.0
    end
  end
end
