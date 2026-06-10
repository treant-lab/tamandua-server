defmodule TamanduaServer.Cloud.Finding do
  @moduledoc """
  Cloud Security Finding management for CSPM.

  Handles the lifecycle of security findings including:
  - Finding creation and storage
  - Lifecycle management (open, acknowledged, resolved, exception)
  - Auto-close when remediated
  - Finding deduplication
  - Remediation tracking
  """

  require Logger
  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Repo

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @derive {Jason.Encoder, except: [:__meta__]}

  schema "cloud_findings" do
    field :provider, :string  # "aws", "azure", "gcp"
    field :account_id, :string
    field :resource_id, :string
    field :resource_arn, :string
    field :resource_name, :string
    field :resource_type, :string
    field :region, :string

    field :category, :string  # "identity_and_access", "network_security", "data_protection", etc.
    field :severity, :string  # "critical", "high", "medium", "low"
    field :title, :string
    field :description, :string
    field :recommendation, :string

    field :compliance, {:array, :string}, default: []
    field :remediation_terraform, :string
    field :remediation_cloudformation, :string
    field :remediation_arm, :string

    field :status, :string, default: "open"  # "open", "acknowledged", "resolved", "exception", "false_positive"
    field :status_reason, :string
    field :status_updated_at, :utc_datetime
    field :status_updated_by, :string

    field :exception_expiry, :utc_datetime
    field :exception_justification, :string

    field :first_seen_at, :utc_datetime
    field :last_seen_at, :utc_datetime
    field :resolved_at, :utc_datetime

    field :fingerprint, :string  # For deduplication

    field :organization_id, :binary_id
    field :assigned_to, :string

    timestamps()
  end

  @required_fields [:provider, :account_id, :resource_id, :resource_name, :resource_type,
                    :category, :severity, :title, :description]
  @optional_fields [:resource_arn, :region, :recommendation, :compliance,
                    :remediation_terraform, :remediation_cloudformation, :remediation_arm,
                    :status, :status_reason, :status_updated_at, :status_updated_by,
                    :exception_expiry, :exception_justification, :first_seen_at, :last_seen_at,
                    :resolved_at, :fingerprint, :organization_id, :assigned_to]

  # ETS table for in-memory findings (for real-time scanning)
  @findings_table :cloud_findings_cache

  @type finding :: %__MODULE__{}

  @type finding_params :: %{
          provider: String.t(),
          account_id: String.t(),
          resource_id: String.t(),
          resource_arn: String.t() | nil,
          resource_name: String.t(),
          resource_type: String.t(),
          region: String.t() | nil,
          category: String.t(),
          severity: String.t(),
          title: String.t(),
          description: String.t(),
          recommendation: String.t() | nil,
          compliance: [String.t()] | nil,
          remediation_terraform: String.t() | nil,
          remediation_cloudformation: String.t() | nil,
          remediation_arm: String.t() | nil
        }

  # ============================================================================
  # Changesets
  # ============================================================================

  def changeset(finding, attrs) do
    finding
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:provider, ["aws", "azure", "gcp"])
    |> validate_inclusion(:severity, ["critical", "high", "medium", "low", "informational"])
    |> validate_inclusion(:category, [
      "identity_and_access",
      "network_security",
      "data_protection",
      "compute_security",
      "logging_monitoring",
      "encryption",
      "compliance",
      "other"
    ])
    |> validate_inclusion(:status, ["open", "acknowledged", "resolved", "exception", "false_positive"])
    |> put_fingerprint()
    |> put_timestamps()
  end

  defp put_fingerprint(changeset) do
    if get_change(changeset, :fingerprint) do
      changeset
    else
      provider = get_field(changeset, :provider)
      account_id = get_field(changeset, :account_id)
      resource_id = get_field(changeset, :resource_id)
      title = get_field(changeset, :title)

      fingerprint =
        :crypto.hash(:sha256, "#{provider}:#{account_id}:#{resource_id}:#{title}")
        |> Base.encode16(case: :lower)

      put_change(changeset, :fingerprint, fingerprint)
    end
  end

  defp put_timestamps(changeset) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    changeset
    |> put_change(:first_seen_at, get_field(changeset, :first_seen_at) || now)
    |> put_change(:last_seen_at, now)
  end

  # ============================================================================
  # Creating Findings (In-Memory for Scanning)
  # ============================================================================

  @doc """
  Create a finding struct (in-memory, not persisted).
  Used during scanning to collect findings before batch persistence.
  """
  @spec create(finding_params()) :: map()
  def create(params) do
    ensure_table()

    now = DateTime.utc_now() |> DateTime.truncate(:second)

    finding = %{
      id: generate_uuid(),
      provider: params[:provider],
      account_id: params[:account_id],
      resource_id: params[:resource_id],
      resource_arn: params[:resource_arn],
      resource_name: params[:resource_name],
      resource_type: params[:resource_type],
      region: params[:region],
      category: params[:category],
      severity: params[:severity],
      title: params[:title],
      description: params[:description],
      recommendation: params[:recommendation],
      compliance: params[:compliance] || [],
      remediation_terraform: params[:remediation_terraform],
      remediation_cloudformation: params[:remediation_cloudformation],
      remediation_arm: params[:remediation_arm],
      status: "open",
      first_seen_at: now,
      last_seen_at: now,
      fingerprint: generate_fingerprint(params)
    }

    # Store in ETS for deduplication during scan
    :ets.insert(@findings_table, {finding.fingerprint, finding})

    finding
  end

  @doc """
  Persist all in-memory findings to the database.
  Handles deduplication and updates for existing findings.
  """
  @spec persist_findings(String.t(), String.t()) :: {:ok, %{inserted: integer(), updated: integer()}}
  def persist_findings(provider, account_id) do
    ensure_table()

    # Get all findings from ETS for this account
    findings =
      :ets.tab2list(@findings_table)
      |> Enum.map(fn {_fp, finding} -> finding end)
      |> Enum.filter(fn f -> f.provider == provider and f.account_id == account_id end)

    {inserted, updated} =
      Enum.reduce(findings, {0, 0}, fn finding, {ins_count, upd_count} ->
        case upsert_finding(finding) do
          {:ok, :inserted} -> {ins_count + 1, upd_count}
          {:ok, :updated} -> {ins_count, upd_count + 1}
          {:error, _} -> {ins_count, upd_count}
        end
      end)

    # Clear findings from ETS after persistence
    :ets.match_delete(@findings_table, {:_, %{provider: provider, account_id: account_id}})

    {:ok, %{inserted: inserted, updated: updated}}
  end

  defp upsert_finding(finding_params) do
    fingerprint = finding_params.fingerprint

    case Repo.get_by(__MODULE__, fingerprint: fingerprint) do
      nil ->
        # New finding
        changeset = changeset(%__MODULE__{}, from_struct_like(finding_params))

        case Repo.insert(changeset) do
          {:ok, _} -> {:ok, :inserted}
          {:error, cs} -> {:error, cs}
        end

      existing ->
        # Update existing finding
        attrs = %{
          last_seen_at: DateTime.utc_now() |> DateTime.truncate(:second),
          description: finding_params.description,
          recommendation: finding_params.recommendation
        }

        # If previously resolved but found again, reopen
        attrs =
          if existing.status == "resolved" do
            Map.merge(attrs, %{
              status: "open",
              resolved_at: nil,
              status_reason: "Finding detected again after being resolved"
            })
          else
            attrs
          end

        changeset = changeset(existing, attrs)

        case Repo.update(changeset) do
          {:ok, _} -> {:ok, :updated}
          {:error, cs} -> {:error, cs}
        end
    end
  end

  defp from_struct_like(map) when is_map(map) do
    map
    |> Map.delete(:__struct__)
    |> Enum.into(%{})
  end

  # ============================================================================
  # Querying Findings
  # ============================================================================

  @doc """
  List findings with optional filters.
  """
  @spec list_findings(map()) :: [finding()]
  def list_findings(filters \\ %{}) do
    base_query()
    |> apply_filters(filters)
    |> apply_ordering(filters)
    |> apply_pagination(filters)
    |> Repo.all()
  end

  @doc """
  Count findings by criteria.
  """
  @spec count_findings(map()) :: integer()
  def count_findings(filters \\ %{}) do
    base_query()
    |> apply_filters(filters)
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Get findings grouped by severity.
  """
  @spec count_by_severity(String.t(), String.t()) :: map()
  def count_by_severity(provider, account_id) do
    from(f in __MODULE__,
      where: f.provider == ^provider and f.account_id == ^account_id and f.status == "open",
      group_by: f.severity,
      select: {f.severity, count(f.id)}
    )
    |> Repo.all()
    |> Enum.into(%{})
  end

  @doc """
  Get findings grouped by category.
  """
  @spec count_by_category(String.t(), String.t()) :: map()
  def count_by_category(provider, account_id) do
    from(f in __MODULE__,
      where: f.provider == ^provider and f.account_id == ^account_id and f.status == "open",
      group_by: f.category,
      select: {f.category, count(f.id)}
    )
    |> Repo.all()
    |> Enum.into(%{})
  end

  @doc """
  Get a single finding by ID.
  """
  @spec get_finding(String.t()) :: finding() | nil
  def get_finding(id) do
    Repo.get(__MODULE__, id)
  end

  @doc """
  Get finding by fingerprint.
  """
  @spec get_by_fingerprint(String.t()) :: finding() | nil
  def get_by_fingerprint(fingerprint) do
    Repo.get_by(__MODULE__, fingerprint: fingerprint)
  end

  defp base_query do
    from(f in __MODULE__)
  end

  defp apply_filters(query, filters) do
    query
    |> filter_by_provider(filters[:provider])
    |> filter_by_account(filters[:account_id])
    |> filter_by_status(filters[:status])
    |> filter_by_severity(filters[:severity])
    |> filter_by_category(filters[:category])
    |> filter_by_resource_type(filters[:resource_type])
    |> filter_by_region(filters[:region])
    |> filter_by_compliance(filters[:compliance])
    |> filter_by_search(filters[:search])
    |> filter_by_organization(filters[:organization_id])
  end

  defp filter_by_provider(query, nil), do: query
  defp filter_by_provider(query, provider), do: where(query, [f], f.provider == ^provider)

  defp filter_by_account(query, nil), do: query
  defp filter_by_account(query, account_id), do: where(query, [f], f.account_id == ^account_id)

  defp filter_by_status(query, nil), do: query
  defp filter_by_status(query, status) when is_list(status), do: where(query, [f], f.status in ^status)
  defp filter_by_status(query, status), do: where(query, [f], f.status == ^status)

  defp filter_by_severity(query, nil), do: query
  defp filter_by_severity(query, severity) when is_list(severity), do: where(query, [f], f.severity in ^severity)
  defp filter_by_severity(query, severity), do: where(query, [f], f.severity == ^severity)

  defp filter_by_category(query, nil), do: query
  defp filter_by_category(query, category), do: where(query, [f], f.category == ^category)

  defp filter_by_resource_type(query, nil), do: query
  defp filter_by_resource_type(query, type), do: where(query, [f], f.resource_type == ^type)

  defp filter_by_region(query, nil), do: query
  defp filter_by_region(query, region), do: where(query, [f], f.region == ^region)

  defp filter_by_compliance(query, nil), do: query
  defp filter_by_compliance(query, framework) do
    where(query, [f], ^framework in f.compliance)
  end

  defp filter_by_search(query, nil), do: query
  defp filter_by_search(query, search) do
    pattern = "%#{search}%"
    where(query, [f],
      ilike(f.title, ^pattern) or
      ilike(f.description, ^pattern) or
      ilike(f.resource_name, ^pattern)
    )
  end

  defp filter_by_organization(query, nil), do: query
  defp filter_by_organization(query, org_id), do: where(query, [f], f.organization_id == ^org_id)

  defp apply_ordering(query, filters) do
    order_by = filters[:order_by] || "severity"
    order_dir = filters[:order_dir] || "asc"

    # Custom ordering for severity
    case {order_by, order_dir} do
      {"severity", "asc"} ->
        order_by(query, [f], fragment("CASE ? WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END", f.severity))

      {"severity", "desc"} ->
        order_by(query, [f], fragment("CASE ? WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END DESC", f.severity))

      {field, "asc"} when field in ["first_seen_at", "last_seen_at", "title"] ->
        order_by(query, [f], asc: field(f, ^String.to_atom(field)))

      {field, "desc"} when field in ["first_seen_at", "last_seen_at", "title"] ->
        order_by(query, [f], desc: field(f, ^String.to_atom(field)))

      _ ->
        order_by(query, [f], fragment("CASE ? WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END", f.severity))
    end
  end

  defp apply_pagination(query, filters) do
    limit = filters[:limit] || 100
    offset = filters[:offset] || 0

    query
    |> limit(^limit)
    |> offset(^offset)
  end

  # ============================================================================
  # Status Management
  # ============================================================================

  @doc """
  Update finding status.
  """
  @spec update_status(String.t(), String.t(), map()) :: {:ok, finding()} | {:error, term()}
  def update_status(finding_id, new_status, opts \\ %{}) do
    case get_finding(finding_id) do
      nil ->
        {:error, :not_found}

      finding ->
        now = DateTime.utc_now() |> DateTime.truncate(:second)

        attrs = %{
          status: new_status,
          status_updated_at: now,
          status_updated_by: opts[:updated_by],
          status_reason: opts[:reason]
        }

        attrs =
          case new_status do
            "resolved" ->
              Map.put(attrs, :resolved_at, now)

            "exception" ->
              Map.merge(attrs, %{
                exception_expiry: opts[:exception_expiry],
                exception_justification: opts[:exception_justification]
              })

            _ ->
              attrs
          end

        finding
        |> changeset(attrs)
        |> Repo.update()
    end
  end

  @doc """
  Acknowledge a finding.
  """
  @spec acknowledge(String.t(), String.t(), String.t() | nil) :: {:ok, finding()} | {:error, term()}
  def acknowledge(finding_id, updated_by, reason \\ nil) do
    update_status(finding_id, "acknowledged", %{updated_by: updated_by, reason: reason})
  end

  @doc """
  Resolve a finding.
  """
  @spec resolve(String.t(), String.t(), String.t() | nil) :: {:ok, finding()} | {:error, term()}
  def resolve(finding_id, updated_by, reason \\ nil) do
    update_status(finding_id, "resolved", %{updated_by: updated_by, reason: reason})
  end

  @doc """
  Mark finding as exception.
  """
  @spec mark_exception(String.t(), map()) :: {:ok, finding()} | {:error, term()}
  def mark_exception(finding_id, opts) do
    update_status(finding_id, "exception", opts)
  end

  @doc """
  Mark finding as false positive.
  """
  @spec mark_false_positive(String.t(), String.t(), String.t() | nil) :: {:ok, finding()} | {:error, term()}
  def mark_false_positive(finding_id, updated_by, reason \\ nil) do
    update_status(finding_id, "false_positive", %{updated_by: updated_by, reason: reason})
  end

  @doc """
  Reopen a finding.
  """
  @spec reopen(String.t(), String.t(), String.t() | nil) :: {:ok, finding()} | {:error, term()}
  def reopen(finding_id, updated_by, reason \\ nil) do
    update_status(finding_id, "open", %{updated_by: updated_by, reason: reason})
  end

  @doc """
  Bulk update status for multiple findings.
  """
  @spec bulk_update_status([String.t()], String.t(), map()) :: {:ok, integer()}
  def bulk_update_status(finding_ids, new_status, opts \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    attrs = %{
      status: new_status,
      status_updated_at: now,
      status_updated_by: opts[:updated_by],
      status_reason: opts[:reason],
      updated_at: now
    }

    attrs =
      if new_status == "resolved" do
        Map.put(attrs, :resolved_at, now)
      else
        attrs
      end

    {count, _} =
      from(f in __MODULE__, where: f.id in ^finding_ids)
      |> Repo.update_all(set: Enum.to_list(attrs))

    {:ok, count}
  end

  # ============================================================================
  # Auto-Remediation Detection
  # ============================================================================

  @doc """
  Mark stale findings as resolved.
  Findings not seen in the latest scan are considered remediated.
  """
  @spec auto_close_stale_findings(String.t(), String.t(), DateTime.t()) :: {:ok, integer()}
  def auto_close_stale_findings(provider, account_id, scan_timestamp) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    {count, _} =
      from(f in __MODULE__,
        where: f.provider == ^provider and
               f.account_id == ^account_id and
               f.status == "open" and
               f.last_seen_at < ^scan_timestamp
      )
      |> Repo.update_all(
        set: [
          status: "resolved",
          resolved_at: now,
          status_reason: "Auto-resolved: Finding not detected in latest scan",
          status_updated_at: now,
          updated_at: now
        ]
      )

    Logger.info("Auto-closed #{count} stale findings for #{provider}/#{account_id}")
    {:ok, count}
  end

  @doc """
  Check and expire findings with expired exceptions.
  """
  @spec expire_exceptions() :: {:ok, integer()}
  def expire_exceptions do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    {count, _} =
      from(f in __MODULE__,
        where: f.status == "exception" and
               not is_nil(f.exception_expiry) and
               f.exception_expiry < ^now
      )
      |> Repo.update_all(
        set: [
          status: "open",
          status_reason: "Exception expired, finding reopened",
          status_updated_at: now,
          updated_at: now
        ]
      )

    Logger.info("Reopened #{count} findings with expired exceptions")
    {:ok, count}
  end

  # ============================================================================
  # Statistics
  # ============================================================================

  @doc """
  Get compliance score for an account.
  """
  @spec compliance_score(String.t(), String.t()) :: float()
  def compliance_score(provider, account_id) do
    total = count_findings(%{provider: provider, account_id: account_id})
    open = count_findings(%{provider: provider, account_id: account_id, status: "open"})

    if total > 0 do
      Float.round((1 - open / total) * 100, 1)
    else
      100.0
    end
  end

  @doc """
  Get finding statistics for dashboard.
  """
  @spec statistics(String.t(), String.t()) :: map()
  def statistics(provider, account_id) do
    %{
      total: count_findings(%{provider: provider, account_id: account_id}),
      by_status: %{
        open: count_findings(%{provider: provider, account_id: account_id, status: "open"}),
        acknowledged: count_findings(%{provider: provider, account_id: account_id, status: "acknowledged"}),
        resolved: count_findings(%{provider: provider, account_id: account_id, status: "resolved"}),
        exception: count_findings(%{provider: provider, account_id: account_id, status: "exception"}),
        false_positive: count_findings(%{provider: provider, account_id: account_id, status: "false_positive"})
      },
      by_severity: count_by_severity(provider, account_id),
      by_category: count_by_category(provider, account_id),
      compliance_score: compliance_score(provider, account_id)
    }
  end

  @doc """
  Get aggregated statistics across all accounts.
  """
  @spec global_statistics() :: map()
  def global_statistics do
    %{
      total_findings: count_findings(%{}),
      open_findings: count_findings(%{status: "open"}),
      critical_findings: count_findings(%{status: "open", severity: "critical"}),
      high_findings: count_findings(%{status: "open", severity: "high"}),
      by_provider: %{
        aws: count_findings(%{provider: "aws", status: "open"}),
        azure: count_findings(%{provider: "azure", status: "open"}),
        gcp: count_findings(%{provider: "gcp", status: "open"})
      }
    }
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  defp ensure_table do
    case :ets.whereis(@findings_table) do
      :undefined -> :ets.new(@findings_table, [:set, :public, :named_table])
      _ -> :ok
    end
  end

  defp generate_uuid do
    UUID.uuid4()
  end

  defp generate_fingerprint(params) do
    data = "#{params[:provider]}:#{params[:account_id]}:#{params[:resource_id]}:#{params[:title]}"
    :crypto.hash(:sha256, data) |> Base.encode16(case: :lower)
  end
end
