defmodule TamanduaServer.Alerts do
  @moduledoc """
  The Alerts context.

  All functions that access alert data support multi-tenancy through
  organization_id filtering. Use the tenant-scoped versions when operating
  in a multi-tenant context.
  """

  import Ecto.Query, warn: false
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.TenantScope

  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Alerts.SuppressionRule
  alias TamanduaServer.Alerts.VerdictFeedbackLog
  alias TamanduaServer.Alerts.Suppression
  alias TamanduaServer.Alerts.SavedSearch
  alias TamanduaServer.Alerts.FilterBuilder
  alias TamanduaServer.Alerts.SupplyChainEnricher
  alias TamanduaServer.Alerts.Enrichers.KubernetesEnricher
  alias TamanduaServer.Detection.Evidence
  alias TamanduaServer.Detection.PrecisionMetrics
  alias TamanduaServer.Solana.{Attestation, Bounty, Client}

  # Default deduplication window in seconds (5 minutes)
  @default_dedup_window_seconds 300
  @active_alert_statuses ~w(new open acknowledged triaged investigating)

  # ===========================================================================
  # Tenant-Scoped Functions
  # ===========================================================================

  @doc """
  Returns the list of alerts for an organization.

  ## Options
  - `:severity` - Filter by severity
  - `:status` - Filter by status
  - `:source` - Filter by detection source
  - `:category` - Filter by category (e.g., "ai_runtime", "supply_chain")
  - `:agent_id` - Filter by agent
  - `:assigned_to_id` - Filter by assigned user
  - `:limit` - Maximum number of results
  - `:offset` - Offset for pagination
  """
  def list_alerts_for_org(organization_id, opts \\ []) do
    query =
      Alert
      |> TenantScope.scope_to_tenant(organization_id)
      |> order_by([a], [desc: a.inserted_at])

    query = apply_alert_filters(query, opts)

    query =
      if limit = Keyword.get(opts, :limit) do
        limit(query, ^limit)
      else
        query
      end

    query =
      if offset = Keyword.get(opts, :offset) do
        offset(query, ^offset)
      else
        query
      end

    Repo.all(query)
  end

  defp apply_alert_filters(query, opts) do
    query
    |> maybe_filter(:severity, Keyword.get(opts, :severity))
    |> maybe_filter(:status, Keyword.get(opts, :status))
    |> maybe_filter(:source, Keyword.get(opts, :source))
    |> maybe_filter(:category, Keyword.get(opts, :category))
    |> maybe_filter(:agent_id, Keyword.get(opts, :agent_id))
    |> maybe_filter(:assigned_to_id, Keyword.get(opts, :assigned_to_id))
  end

  defp maybe_filter(query, _field, nil), do: query
  defp maybe_filter(query, _field, ""), do: query
  defp maybe_filter(query, :severity, value), do: where(query, [a], a.severity == ^value)
  defp maybe_filter(query, :status, values) when is_list(values), do: where(query, [a], a.status in ^values)
  defp maybe_filter(query, :status, value), do: where(query, [a], a.status == ^value)
  defp maybe_filter(query, :source, value) do
    where(
      query,
      [a],
      fragment(
        """
        lower(
          coalesce(
            ?->>'source',
            ?->>'detection_source',
            ?->>'source',
            ?->>'alert_source',
            ?#>>'{payload,detection_source}',
            ?#>>'{payload,source}',
            ?#>>'{metadata,detection_source}',
            ?#>>'{metadata,source}',
            ?->>'source',
            ?->>'detection_source',
            ?->>'alert_source',
            case
              when lower(coalesce(?->>'detection_type', '')) = 'ml' then 'ml'
              when lower(coalesce(?->>'rule_type', '')) = 'ml' then 'ml'
              when upper(coalesce(?->>'rule_name', '')) like 'ML\\_%' then 'ml'
              when lower(coalesce(?#>>'{payload,detection_type}', '')) = 'ml' then 'ml'
              when lower(coalesce(?#>>'{payload,rule_type}', '')) = 'ml' then 'ml'
              when upper(coalesce(?#>>'{payload,rule_name}', '')) like 'ML\\_%' then 'ml'
              when lower(coalesce(?->>'detection_type', '')) = 'ml' then 'ml'
              when lower(coalesce(?->>'rule_type', '')) = 'ml' then 'ml'
              when upper(coalesce(?->>'rule_name', '')) like 'ML\\_%' then 'ml'
              else ''
            end
          )
        ) = lower(?)
        """,
        a.detection_metadata,
        a.detection_metadata,
        a.raw_event,
        a.raw_event,
        a.raw_event,
        a.raw_event,
        a.raw_event,
        a.raw_event,
        a.evidence,
        a.evidence,
        a.evidence,
        a.detection_metadata,
        a.detection_metadata,
        a.detection_metadata,
        a.raw_event,
        a.raw_event,
        a.raw_event,
        a.evidence,
        a.evidence,
        a.evidence,
        ^value
      )
    )
  end
  defp maybe_filter(query, :category, value), do: where(query, [a], fragment("?->>'category' = ?", a.detection_metadata, ^value))
  defp maybe_filter(query, :agent_id, value), do: where(query, [a], a.agent_id == ^value)
  defp maybe_filter(query, :assigned_to_id, value), do: where(query, [a], a.assigned_to_id == ^value)

  @doc """
  Gets a single alert scoped to an organization.

  Returns `{:ok, alert}` or `{:error, :not_found}`.
  """
  def get_alert_for_org(organization_id, alert_id) do
    case TenantScope.get_scoped(Alert, organization_id, alert_id) do
      nil -> {:error, :not_found}
      alert -> {:ok, alert}
    end
  end

  @doc """
  Lists alerts that have been attested on-chain (Solana blockchain).

  ## Options
  - `:severity` - Filter by severity
  - `:bounty_only` - Only show alerts with bounties paid
  - `:date_range` - "24h", "7d", "30d", or "all"
  """
  def list_attested_alerts(organization_id, opts \\ []) do
    if is_nil(organization_id) do
      []
    else
      do_list_attested_alerts(organization_id, opts)
    end
  end

  defp do_list_attested_alerts(organization_id, opts) do
    query =
      Alert
      |> TenantScope.scope_to_tenant(organization_id)
      |> where([a], not is_nil(a.blockchain_tx_id))
      |> order_by([a], [desc: a.blockchain_attested_at])

    query =
      if severity = Keyword.get(opts, :severity) do
        where(query, [a], a.severity == ^severity)
      else
        query
      end

    query =
      if Keyword.get(opts, :bounty_only, false) do
        where(query, [a], not is_nil(a.bounty_tx_id))
      else
        query
      end

    query =
      case Keyword.get(opts, :date_range, "7d") do
        "24h" ->
          cutoff = DateTime.add(DateTime.utc_now(), -1, :day)
          where(query, [a], a.blockchain_attested_at >= ^cutoff)

        "7d" ->
          cutoff = DateTime.add(DateTime.utc_now(), -7, :day)
          where(query, [a], a.blockchain_attested_at >= ^cutoff)

        "30d" ->
          cutoff = DateTime.add(DateTime.utc_now(), -30, :day)
          where(query, [a], a.blockchain_attested_at >= ^cutoff)

        _ ->
          query
      end

    Repo.all(query)
  end

  # ===========================================================================
  # Public Attestation Functions (no tenant scoping - for public audit pages)
  # ===========================================================================

  @doc """
  Lists all public attestations across all organizations.

  Returns only privacy-safe fields suitable for public display.
  No PII, no org/agent identifiers, no IOC values.

  ## Options
  - `:severity` - Filter by severity
  - `:mitre_technique` - Filter by MITRE technique
  - `:date_range` - "24h", "7d", "30d", or "all"
  - `:limit` - Maximum results (default 100)
  - `:offset` - Pagination offset
  """
  def list_public_attestations(opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)

    query =
      Alert
      |> where([a], not is_nil(a.blockchain_tx_id))
      |> order_by([a], [desc: a.blockchain_attested_at])
      # Select only privacy-safe fields
      |> select([a], %{
        id: a.id,
        severity: a.severity,
        mitre_techniques: a.mitre_techniques,
        blockchain_tx_id: a.blockchain_tx_id,
        blockchain_attested_at: a.blockchain_attested_at,
        threat_score: a.threat_score,
        detection_metadata: a.detection_metadata,
        bounty_tx_id: a.bounty_tx_id,
        bounty_amount_lamports: a.bounty_amount_lamports
      })

    query =
      if severity = Keyword.get(opts, :severity) do
        where(query, [a], a.severity == ^severity)
      else
        query
      end

    query =
      if mitre = Keyword.get(opts, :mitre_technique) do
        where(query, [a], ^mitre in a.mitre_techniques)
      else
        query
      end

    query =
      case Keyword.get(opts, :date_range, "7d") do
        "24h" ->
          cutoff = DateTime.add(DateTime.utc_now(), -1, :day)
          where(query, [a], a.blockchain_attested_at >= ^cutoff)

        "7d" ->
          cutoff = DateTime.add(DateTime.utc_now(), -7, :day)
          where(query, [a], a.blockchain_attested_at >= ^cutoff)

        "30d" ->
          cutoff = DateTime.add(DateTime.utc_now(), -30, :day)
          where(query, [a], a.blockchain_attested_at >= ^cutoff)

        _ ->
          query
      end

    query
    |> limit(^limit)
    |> offset(^offset)
    |> Repo.all()
  end

  @doc """
  Gets a single public attestation by blockchain transaction ID.

  Returns only privacy-safe fields suitable for public display.
  """
  def get_public_attestation_by_tx(tx_id) when is_binary(tx_id) do
    Alert
    |> where([a], a.blockchain_tx_id == ^tx_id)
    |> select([a], %{
      id: a.id,
      severity: a.severity,
      mitre_techniques: a.mitre_techniques,
      mitre_tactics: a.mitre_tactics,
      blockchain_tx_id: a.blockchain_tx_id,
      blockchain_attested_at: a.blockchain_attested_at,
      threat_score: a.threat_score,
      detection_metadata: a.detection_metadata,
      bounty_tx_id: a.bounty_tx_id,
      bounty_amount_lamports: a.bounty_amount_lamports,
      bounty_paid_at: a.bounty_paid_at
    })
    |> Repo.one()
  end

  def get_public_attestation_by_tx(_), do: nil

  @doc """
  Counts total public attestations.
  """
  def count_public_attestations do
    Alert
    |> where([a], not is_nil(a.blockchain_tx_id))
    |> Repo.aggregate(:count)
  end

  @doc """
  Gets public attestation statistics.
  """
  def public_attestation_stats do
    total = count_public_attestations()

    bounty_count =
      Alert
      |> where([a], not is_nil(a.blockchain_tx_id) and not is_nil(a.bounty_tx_id))
      |> Repo.aggregate(:count)

    total_bounty_lamports =
      Alert
      |> where([a], not is_nil(a.bounty_tx_id))
      |> Repo.aggregate(:sum, :bounty_amount_lamports) || 0

    %{
      total_attested: total,
      total_bounties: bounty_count,
      total_bounty_sol: total_bounty_lamports / 1_000_000_000
    }
  end

  @doc """
  Manually trigger attestation for an alert.

  This is useful for re-processing failed attestations or attesting
  existing alerts that weren't attested at creation time.

  ## Examples

      iex> attest_alert(alert_id)
      {:ok, %Oban.Job{}}

      iex> attest_alert(already_attested_id)
      {:error, :already_attested}
  """
  def attest_alert(alert_id) when is_binary(alert_id) do
    case Repo.get(Alert, alert_id) do
      nil -> {:error, :not_found}
      alert -> attest_alert(alert)
    end
  end

  def attest_alert(%Alert{} = alert) do
    alias TamanduaServer.Workers.AttestationWorker
    AttestationWorker.enqueue_for_alert(alert)
  end

  @doc """
  Enqueue attestation jobs for all pending (unattested) high/critical alerts.

  This is useful for batch processing after enabling Solana integration
  or recovering from outages.

  ## Options

  - `:severity` - Filter by severity ("critical", "high", "medium")
  - `:limit` - Maximum number of alerts to process (default: 100)
  - `:organization_id` - Scope to a specific organization

  ## Examples

      iex> attest_pending_alerts()
      {:ok, 42}  # Number of jobs enqueued

      iex> attest_pending_alerts(severity: "critical", limit: 10)
      {:ok, 5}
  """
  def attest_pending_alerts(opts \\ []) do
    alias TamanduaServer.Workers.AttestationWorker

    severity = Keyword.get(opts, :severity)
    limit = Keyword.get(opts, :limit, 100)
    organization_id = Keyword.get(opts, :organization_id)

    query =
      Alert
      |> where([a], is_nil(a.blockchain_tx_id))
      |> where([a], a.severity in ["medium", "high", "critical"])
      |> order_by([a], desc: a.inserted_at)
      |> limit(^limit)

    query =
      if severity do
        where(query, [a], a.severity == ^severity)
      else
        query
      end

    query =
      if organization_id do
        where(query, [a], a.organization_id == ^organization_id)
      else
        query
      end

    alerts = Repo.all(query)

    enqueued =
      Enum.reduce(alerts, 0, fn alert, count ->
        case AttestationWorker.enqueue_for_alert(alert) do
          {:ok, _job} -> count + 1
          _ -> count
        end
      end)

    Logger.info("[Alerts] Enqueued #{enqueued} attestation jobs (of #{length(alerts)} pending)")

    {:ok, enqueued}
  end

  @doc """
  Gets a single alert scoped to an organization, raises if not found.
  """
  def get_alert_for_org!(organization_id, alert_id) do
    TenantScope.get_scoped!(Alert, organization_id, alert_id)
  end

  @doc """
  Creates an alert for an organization.
  """
  def create_alert_for_org(organization_id, attrs) do
    attrs = Map.put(attrs, :organization_id, organization_id)
    create_alert(attrs)
  end

  @doc """
  Counts alerts for an organization.
  """
  def count_alerts_for_org(organization_id, opts \\ []) do
    Alert
    |> TenantScope.scope_to_tenant(organization_id)
    |> apply_alert_filters(opts)
    |> Repo.aggregate(:count)
  end

  @doc """
  Counts active (non-resolved) alerts for an organization.
  """
  def count_active_for_org(organization_id) do
    Alert
    |> TenantScope.scope_to_tenant(organization_id)
    |> where([a], a.status in ^@active_alert_statuses)
    |> Repo.aggregate(:count)
  end

  @doc """
  Counts alerts by severity for an organization.
  """
  def count_by_severity_for_org(organization_id, severity) do
    severity = to_string(severity)

    Alert
    |> TenantScope.scope_to_tenant(organization_id)
    |> where([a], a.severity == ^severity and a.status in ^@active_alert_statuses)
    |> Repo.aggregate(:count)
  end

  @doc """
  Returns privacy-safe alert posture counts for a single agent in an organization.

  This is used by endpoint security posture attestations. It intentionally returns
  aggregate counts only: no hostnames, usernames, paths, commands, or alert titles.
  """
  def posture_counts_for_agent(organization_id, agent_id, opts \\ []) do
    window_started_at = Keyword.get(opts, :since, DateTime.add(DateTime.utc_now(), -24 * 60 * 60, :second))

    base_query =
      Alert
      |> TenantScope.scope_to_tenant(organization_id)
      |> where([a], a.agent_id == ^agent_id)
      |> where([a], a.status in ^@active_alert_statuses)

    window_query =
      base_query
      |> where([a], a.inserted_at >= ^window_started_at)

    severity_counts =
      window_query
      |> group_by([a], a.severity)
      |> select([a], {a.severity, count(a.id)})
      |> Repo.all()
      |> Enum.into(%{})

    %{
      window_started_at: window_started_at,
      window_ended_at: DateTime.utc_now(),
      active_alerts: Repo.aggregate(base_query, :count),
      window_alerts: Enum.sum(Map.values(severity_counts)),
      critical_alerts: Map.get(severity_counts, "critical", 0),
      high_alerts: Map.get(severity_counts, "high", 0),
      medium_alerts: Map.get(severity_counts, "medium", 0),
      low_alerts: Map.get(severity_counts, "low", 0)
    }
  end

  @doc """
  Gets alert trend over time for an organization.
  """
  def get_trend_for_org(organization_id, time_range) do
    days = case time_range do
      "7d" -> 7
      "30d" -> 30
      "90d" -> 90
      _ -> 7
    end

    start_date = Date.utc_today() |> Date.add(-days)

    Alert
    |> TenantScope.scope_to_tenant(organization_id)
    |> where([a], fragment("?::date", a.inserted_at) >= ^start_date)
    |> group_by([a], fragment("?::date", a.inserted_at))
    |> select([a], {fragment("?::date", a.inserted_at), count(a.id)})
    |> order_by([a], [asc: fragment("?::date", a.inserted_at)])
    |> Repo.all()
    |> Enum.map(fn {date, count} -> %{date: Date.to_iso8601(date), count: count} end)
  end

  @doc """
  Lists recent alerts for an organization.
  """
  def list_recent_for_org(organization_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 10)

    Alert
    |> TenantScope.scope_to_tenant(organization_id)
    |> order_by([a], [desc: a.inserted_at])
    |> limit(^limit)
    |> Repo.all()
  end

  @doc """
  Counts alerts by MITRE technique for an organization and time range.
  """
  def count_by_mitre_technique_for_org(organization_id, time_range \\ "all") do
    Alert
    |> TenantScope.scope_to_tenant(organization_id)
    |> where([a], not is_nil(a.mitre_techniques) and a.mitre_techniques != [])
    |> maybe_filter_time_range(time_range)
    |> select([a], a.mitre_techniques)
    |> Repo.all()
    |> List.flatten()
    |> Enum.frequencies()
  end

  @doc """
  Lists recent alerts mapped to a MITRE technique for an organization.
  """
  def list_by_mitre_technique_for_org(organization_id, technique_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 10)

    Alert
    |> TenantScope.scope_to_tenant(organization_id)
    |> where([a], fragment("? = ANY(?)", ^technique_id, a.mitre_techniques))
    |> order_by([a], [desc: a.inserted_at])
    |> limit(^limit)
    |> Repo.all()
  end

  @doc """
  Returns daily detection counts for one MITRE technique in an organization.
  """
  def get_technique_trend_for_org(organization_id, technique_id, opts \\ []) do
    days = Keyword.get(opts, :days, 30)
    start_date = Date.utc_today() |> Date.add(-days)

    Alert
    |> TenantScope.scope_to_tenant(organization_id)
    |> where([a], fragment("? = ANY(?)", ^technique_id, a.mitre_techniques))
    |> where([a], fragment("?::date", a.inserted_at) >= ^start_date)
    |> group_by([a], fragment("?::date", a.inserted_at))
    |> select([a], {fragment("?::date", a.inserted_at), count(a.id)})
    |> order_by([a], [asc: fragment("?::date", a.inserted_at)])
    |> Repo.all()
    |> Enum.map(fn {date, count} -> %{date: Date.to_iso8601(date), count: count} end)
  end

  @doc """
  Counts alert severities for a MITRE technique in an organization.
  """
  def count_by_severity_for_technique_for_org(organization_id, technique_id) do
    base = %{critical: 0, high: 0, medium: 0, low: 0}

    Alert
    |> TenantScope.scope_to_tenant(organization_id)
    |> where([a], fragment("? = ANY(?)", ^technique_id, a.mitre_techniques))
    |> group_by([a], a.severity)
    |> select([a], {a.severity, count(a.id)})
    |> Repo.all()
    |> Enum.reduce(base, fn {severity, count}, acc ->
      Map.put(acc, normalize_severity_key(severity), count)
    end)
  end

  # ===========================================================================
  # Legacy/Unscoped Functions
  # ===========================================================================

  @doc """
  Returns the list of alerts.
  """
  def list_alerts(filters \\ %{}) do
    filters
    |> build_alert_query()
    |> Repo.all()
  end

  @doc """
  Returns a paginated list of alerts.

  ## Options
  - `:limit` - Maximum number of results
  - `:offset` - Offset for pagination
  """
  def list_alerts_paginated(filters, opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)
    offset = Keyword.get(opts, :offset, 0)

    filters
    |> build_alert_query()
    |> order_by([a], [desc: a.inserted_at])
    |> limit(^limit)
    |> offset(^offset)
    |> Repo.all()
  end

  @doc """
  Counts alerts matching the given filters.
  """
  def count_alerts(filters \\ %{}) do
    filters
    |> build_alert_query()
    |> Repo.aggregate(:count, :id)
  end

  defp build_alert_query(filters) do
    query = from a in Alert
    query =
      if organization_id = filters[:organization_id], do: where(query, [a], a.organization_id == ^organization_id), else: query
    query =
      if agent_id = filters[:agent_id], do: where(query, [a], a.agent_id == ^agent_id), else: query
    query =
      if severity = filters[:severity], do: where(query, [a], a.severity == ^severity), else: query
    query =
      if status = filters[:status], do: where(query, [a], a.status == ^status), else: query

    if assigned_to_id = filters[:assigned_to_id], do: where(query, [a], a.assigned_to_id == ^assigned_to_id), else: query
  end

  @doc """
  Gets a single alert.
  """
  def get_alert!(id), do: Repo.get!(Alert, id)

  @doc """
  Creates an alert.

  ## Parameters

  - `attrs` - Alert attributes map. May include:
    - `:severity` - Alert severity (critical, high, medium, low, info)
    - `:title` - Alert title
    - `:description` - Alert description
    - `:agent_id` - Associated agent ID
    - `:organization_id` - Organization ID (auto-resolved from agent if not provided)
    - `:source_event_id` - ID of the triggering event
    - `:event` - Raw event map (for evidence extraction)
    - `:detections` - List of detection results (for evidence extraction)
    - `:evidence` - Pre-extracted evidence map (optional)
    - `:process_chain` - Pre-built process chain (optional)
    - `:raw_event` - Raw event payload for forensics (optional)
    - `:detection_metadata` - Detection rule metadata (optional)
    - `:contributing_events` - List of event IDs for correlation alerts (optional)
  """
  def create_alert(attrs \\ %{}) do
    alias TamanduaServer.Alerts.Deduplication

    attrs = attrs
    |> normalize_alert_attrs()
    |> maybe_extract_source_event_id()
    |> maybe_extract_evidence()
    |> maybe_set_raw_event()
    |> maybe_attach_alert_quality()
    |> maybe_set_recommended_response()

    agent_id = attrs[:agent_id] || attrs["agent_id"]

    case apply_suppression(attrs, agent_id) do
      {:suppress, reason} ->
        Logger.debug("[Alerts] Suppressed alert before creation: #{reason}")
        {:error, {:suppressed, reason}}

      {:allow, attrs} ->
        Suppression.record_occurrence(attrs, agent_id)

        # Use the ETS-backed Deduplication Engine for fast O(1) lookups.
        # Falls back to DB-based dedup if the GenServer is unavailable.
        case Deduplication.check_and_deduplicate(attrs) do
          {:duplicate, existing_alert_id, new_count} ->
            # Duplicate found via ETS window -- alert already updated in DB.
            # Return the existing alert.
            Logger.debug("[Alerts] Deduplicated alert (id=#{existing_alert_id}, count=#{new_count})")
            case Repo.get(Alert, existing_alert_id) do
              nil -> do_create_new_alert(attrs)
              alert -> {:ok, alert}
            end

          {:new, attrs} ->
            do_create_new_alert(attrs)
        end
    end
  end

  defp apply_suppression(attrs, agent_id) do
    case obvious_false_positive_reason(attrs) do
      {:suppress, reason} ->
        {:suppress, reason}

      {:reduce_severity, new_severity, reason} ->
        Logger.debug("[Alerts] Reduced alert severity to #{new_severity}: #{reason}")
        {:allow, reduce_alert_severity(attrs, new_severity, reason)}

      :allow ->
        apply_configured_suppression(attrs, agent_id)
    end
  end

  defp apply_configured_suppression(attrs, agent_id) do
    case Suppression.check_suppression(attrs, agent_id) do
      :allow ->
        {:allow, attrs}

      {:reduce_severity, new_severity, reason} ->
        Logger.debug("[Alerts] Reduced alert severity to #{new_severity}: #{reason}")
        {:allow, Map.put(attrs, :severity, new_severity)}

      {:suppress, reason} ->
        {:suppress, reason}

      {:auto_suppress, count, reason} ->
        {:suppress, "#{reason}; occurrence_count=#{count}"}

      _ ->
        {:allow, attrs}
    end
  rescue
    e ->
      Logger.warning("[Alerts] Suppression check failed, allowing alert: #{Exception.message(e)}")
      {:allow, attrs}
  catch
    :exit, reason ->
      Logger.warning("[Alerts] Suppression check exited, allowing alert: #{inspect(reason)}")
      {:allow, attrs}
  end

  defp obvious_false_positive_reason(attrs) do
    title = attrs |> alert_attr(:title) |> normalize_fp_text()
    context = structured_fp_context(attrs)

    cond do
      title == "retroactive ioc match: ip 0.0.0.0" and invalid_zero_ioc?(context) ->
        {:suppress, "invalid_ioc_0_0_0_0"}

      title == "ndr: rapid internal connections" and benign_rapid_connection_fp?(context) ->
        {:reduce_severity, "low", "benign_rapid_internal_connection_structured"}

      ntdll_self_write_no_permission_transition_fp?(context) ->
        {:reduce_severity, "medium", "ntdll_self_write_no_permission_transition_structured"}

      contextless_ntdll_write_detection?(context) ->
        {:reduce_severity, "medium", "ntdll_write_missing_target_context"}

      ntdll_cross_process_legitimacy_fp?(context) ->
        {:reduce_severity, "medium", ntdll_cross_process_legitimacy_reason(context)}

      title == "agent detection: behavioral_high_risk_score" and unusual_time_only_risk_fp?(context) ->
        {:reduce_severity, "low", "behavioral_score_only_unusual_time_structured"}

      title == "agent detection: behavioral_high_risk_score" and benign_operational_high_risk_score?(context) ->
        {:reduce_severity, "medium", "behavioral_score_only_operational_tool_context"}

      title == "agent detection: behavioral_high_risk_score" and macos_benign_operational_high_risk_score?(context) ->
        {:reduce_severity, "medium", "macos_behavioral_score_only_operational_tool_context"}

      title == "agent detection: behavioral_unusual_execution_time" and benign_unusual_time_process_fp?(context) ->
        {:reduce_severity, "info", "benign_unusual_execution_time_structured"}

      title == "agent detection: behavioral_unusual_execution_time" and macos_benign_unusual_time_process_fp?(context) ->
        {:reduce_severity, "info", "macos_benign_unusual_execution_time_structured"}

      title == "agent detection: behavioral_lsass_access" and lsass_self_event_fp?(context) ->
        {:reduce_severity, "info", "lsass_self_process_event_structured"}

      windows_core_service_process_fp?(context) ->
        {:reduce_severity, "info", "windows_core_service_process_chain_structured"}

      title == "agent detection: behavioral_rundll32_network" and nvidia_rundll32_rxdiag_fp?(context) ->
        {:reduce_severity, "low", "benign_nvidia_rundll32_rxdiag_structured"}

      title == "agent detection: registry_t1547_001" and edge_webview_runonce_cleanup_fp?(context) ->
        {:reduce_severity, "info", "benign_edge_webview_runonce_cleanup_structured"}

      edge_update_etw_patch_fp?(context) ->
        {:reduce_severity, "medium", "edge_update_etw_patch_without_actionable_context"}

      contextless_etw_tamper_detection?(context) ->
        {:reduce_severity, "medium", "etw_tamper_missing_actionable_context"}

      contextless_service_registry_detection?(context) ->
        {:reduce_severity, "medium", "service_registry_change_missing_process_context"}

      ngen_runtime_maintenance_fp?(context) ->
        {:reduce_severity, "info", "benign_dotnet_ngen_runtime_maintenance_structured"}

      contextless_kernel_memory_detection?(context) ->
        {:reduce_severity, "medium", "kernel_memory_detection_without_process_context"}

      benign_benchmark_run_key_persistence_fp?(context) ->
        {:reduce_severity, "info", "benign_benchmark_persistence_setup_structured"}

      true ->
        :allow
    end
  end

  defp reduce_alert_severity(attrs, new_severity, reason) do
    current = alert_attr(attrs, :severity) |> normalize_fp_text()

    attrs
    |> Map.put(:severity, new_severity)
    |> Map.put_new(:original_severity, current)
    |> Map.put(:severity_adjusted, true)
    |> Map.put(:severity_adjusted_at, DateTime.utc_now())
    |> Map.put(:false_positive_notes, reason)
    |> Map.update(:detection_metadata, %{"fp_action" => "reduce_severity", "fp_reason" => reason}, fn metadata ->
      metadata
      |> ensure_map()
      |> Map.put("fp_action", "reduce_severity")
      |> Map.put("fp_reason", reason)
      |> Map.put("fp_basis", "structured_fields")
    end)
  end

  defp alert_attr(attrs, key) do
    Map.get(attrs, key) || Map.get(attrs, Atom.to_string(key))
  end

  defp normalize_fp_text(nil), do: ""
  defp normalize_fp_text(value) when is_binary(value), do: String.downcase(value)
  defp normalize_fp_text(value) when is_atom(value), do: value |> Atom.to_string() |> String.downcase()

  defp normalize_fp_text(value) when is_list(value) or is_map(value) do
    value
    |> inspect(limit: :infinity, printable_limit: :infinity)
    |> String.downcase()
  end

  defp normalize_fp_text(value), do: value |> to_string() |> String.downcase()

  defp structured_fp_context(attrs) do
    evidence = attrs |> alert_attr(:evidence) |> ensure_map()
    raw_event = attrs |> alert_attr(:raw_event) |> ensure_map()
    process = first_map([map_get(evidence, :process), raw_event])
    network = first_map(List.wrap(map_get(evidence, :network)) ++ [raw_event])
    registry = first_map(List.wrap(map_get(evidence, :registry)) ++ [raw_event])
    detection = first_map([map_get(evidence, :detection), alert_attr(attrs, :detection_metadata)])

    %{
      attrs: attrs,
      evidence: evidence,
      raw_event: raw_event,
      process: process,
      network: network,
      registry: registry,
      detection: detection
    }
  end

  defp benign_rapid_connection_fp?(ctx) do
    process = process_basename(ctx)
    remote_ip = field(ctx, [:network, :remote_ip]) || field(ctx, [:raw_event, :remote_ip]) || field(ctx, [:network, :value])

    process in ["synergy-core", "google chrome helper"] and
      private_ipv4?(remote_ip) and
      trusted_process_context?(ctx)
  end

  defp ntdll_self_write_no_permission_transition_fp?(ctx) do
    ntdll_write_detection?(ctx) and
      ntdll_same_process_target?(ctx) and
      ntdll_image_text_target?(ctx) and
      ntdll_no_permission_transition?(ctx) and
      not ntdll_thread_execution_context?(ctx) and
      not credential_target?(ctx)
  end

  defp ntdll_write_detection?(ctx) do
    detection_name(ctx) in [
      "ntdll_write_writeprocessmemory",
      "ntdll_write_ntwritevirtualmemory",
      "ntdll_write_ntmapviewofsection"
    ] or
      ctx
      |> field([:attrs, :title])
      |> normalize_fp_text()
      |> String.starts_with?("agent detection: ntdll_write_")
  end

  defp ntdll_same_process_target?(ctx) do
    source_pid =
      first_context_value(ctx, [
        [:raw_event, :source_pid],
        [:raw_event, :metadata, :source_pid],
        [:raw_event, :enrichment, :source_pid],
        [:raw_event, :enrichment, :metadata, :source_pid],
        [:raw_event, :pid],
        [:process, :pid]
      ])

    target_pid =
      first_context_value(ctx, [
        [:raw_event, :target_pid],
        [:raw_event, :metadata, :target_pid],
        [:raw_event, :enrichment, :target_pid],
        [:raw_event, :enrichment, :metadata, :target_pid],
        [:process, :target_pid]
      ])

    same_non_nil?(source_pid, target_pid)
  end

  defp ntdll_image_text_target?(ctx) do
    mem_type =
      first_context_value(ctx, [
        [:raw_event, :mem_type_str],
        [:raw_event, :metadata, :mem_type_str],
        [:raw_event, :enrichment, :mem_type_str],
        [:raw_event, :enrichment, :metadata, :mem_type_str],
        [:raw_event, :memory_type],
        [:raw_event, :enrichment, :metadata, :memory_type]
      ])
      |> normalize_fp_text()

    target_function =
      first_context_value(ctx, [
        [:raw_event, :target_function],
        [:raw_event, :metadata, :target_function],
        [:raw_event, :enrichment, :target_function],
        [:raw_event, :enrichment, :metadata, :target_function],
        [:raw_event, :target_module],
        [:raw_event, :enrichment, :metadata, :target_module]
      ])
      |> normalize_fp_text()

    mem_type in ["mem_image", "image", "0x1000000"] and
      (target_function == "" or String.contains?(target_function, "ntdll.dll!.text"))
  end

  defp ntdll_no_permission_transition?(ctx) do
    old_protection =
      first_context_value(ctx, [
        [:raw_event, :old_protection_str],
        [:raw_event, :metadata, :old_protection_str],
        [:raw_event, :enrichment, :old_protection_str],
        [:raw_event, :enrichment, :metadata, :old_protection_str],
        [:raw_event, :old_protection],
        [:raw_event, :enrichment, :metadata, :old_protection]
      ])
      |> normalize_memory_protection()

    new_protection =
      first_context_value(ctx, [
        [:raw_event, :new_protection_str],
        [:raw_event, :metadata, :new_protection_str],
        [:raw_event, :enrichment, :new_protection_str],
        [:raw_event, :enrichment, :metadata, :new_protection_str],
        [:raw_event, :new_protection],
        [:raw_event, :enrichment, :metadata, :new_protection]
      ])
      |> normalize_memory_protection()

    old_protection in ["page_execute_read", "0x20"] and
      new_protection in ["page_execute_read", "0x20"] and
      old_protection == new_protection
  end

  defp ntdll_thread_execution_context?(ctx) do
    thread_from_unbacked =
      first_context_value(ctx, [
        [:raw_event, :thread_from_unbacked],
        [:raw_event, :metadata, :thread_from_unbacked],
        [:raw_event, :enrichment, :thread_from_unbacked],
        [:raw_event, :enrichment, :metadata, :thread_from_unbacked]
      ])

    thread_start =
      first_context_value(ctx, [
        [:raw_event, :thread_start_address],
        [:raw_event, :metadata, :thread_start_address],
        [:raw_event, :enrichment, :thread_start_address],
        [:raw_event, :enrichment, :metadata, :thread_start_address]
      ])

    thread_from_unbacked in [true, "true", "1", 1] or not blank?(thread_start)
  end

  # Cross-process ntdll write where the SOURCE is legitimate. This is an EDR:
  # we never suppress an ntdll write, but a signed/known writer hitting .text
  # without an RWX transition, a credential target, or an unbacked thread is
  # benign tooling (debuggers, anti-cheat, security agents) rather than
  # injection. We only DOWNGRADE severity; the alert is preserved for triage.
  defp ntdll_cross_process_legitimacy_fp?(ctx) do
    ntdll_write_detection?(ctx) and
      ntdll_cross_process_target?(ctx) and
      not credential_target?(ctx) and
      not ntdll_export_table_target?(ctx) and
      not ntdll_rwx_region?(ctx) and
      not ntdll_thread_execution_context?(ctx) and
      ntdll_legitimate_source?(ctx)
  end

  # Encodes the basis for the downgrade in the reason so it surfaces in
  # false_positive_notes / detection_metadata["fp_reason"].
  defp ntdll_cross_process_legitimacy_reason(ctx) do
    if ntdll_source_signed?(ctx) do
      "cross_process_ntdll_write_legitimate_signed_source"
    else
      "cross_process_ntdll_write_legitimate_known_tool"
    end
  end

  defp ntdll_legitimate_source?(ctx) do
    ntdll_source_signed?(ctx) or ntdll_known_tool_source?(ctx)
  end

  # Primary legitimacy signal: the agent's Authenticode verdict on the writer.
  # Absent (older agents) -> not signed, fall back to the path allowlist.
  defp ntdll_source_signed?(ctx) do
    first_context_value(ctx, [
      [:raw_event, :source_is_signed],
      [:raw_event, :metadata, :source_is_signed],
      [:raw_event, :enrichment, :source_is_signed],
      [:raw_event, :enrichment, :metadata, :source_is_signed],
      [:detection, :source_is_signed]
    ]) in [true, "true", "1", 1]
  end

  # Conservative fallback for agents that do not yet emit source_is_signed:
  # a small allowlist of known cross-process writers (debuggers, anti-cheat,
  # security products). Anything not matched stays at full severity.
  defp ntdll_known_tool_source?(ctx) do
    source_name =
      first_context_value(ctx, [
        [:raw_event, :source_process],
        [:raw_event, :metadata, :source_process],
        [:raw_event, :source_process_name],
        [:process, :name]
      ])
      |> basename()

    source_path =
      first_context_value(ctx, [
        [:raw_event, :source_path],
        [:raw_event, :metadata, :source_path],
        [:process, :path],
        [:process, :image_path]
      ])
      |> normalize_path()

    source_name in ntdll_known_tool_basenames() or
      Enum.any?(ntdll_known_tool_path_markers(), &String.contains?(source_path, &1))
  end

  defp ntdll_known_tool_basenames do
    [
      "windbg.exe",
      "windbgx.exe",
      "cdb.exe",
      "ntsd.exe",
      "x64dbg.exe",
      "x32dbg.exe",
      "devenv.exe",
      "vsdebugconsole.exe",
      "easyanticheat.exe",
      "beservice.exe",
      "vgc.exe",
      "vgtray.exe",
      "msmpeng.exe",
      "tamandua-agent.exe",
      "tamandua_agent.exe"
    ]
  end

  defp ntdll_known_tool_path_markers do
    [
      "\\windows kits\\",
      "\\microsoft visual studio\\",
      "\\debuggers\\"
    ]
  end

  # Cross-process when the explicit agent flag says so, otherwise when source
  # and target PIDs are both present and differ.
  defp ntdll_cross_process_target?(ctx) do
    flag =
      first_context_value(ctx, [
        [:raw_event, :cross_process],
        [:raw_event, :metadata, :cross_process],
        [:raw_event, :enrichment, :cross_process],
        [:raw_event, :enrichment, :metadata, :cross_process],
        [:detection, :cross_process]
      ])

    cond do
      flag in [true, "true", "1", 1] ->
        true

      flag in [false, "false", "0", 0] ->
        false

      true ->
        source_pid = ntdll_source_pid(ctx)
        target_pid = ntdll_target_pid(ctx)

        not blank?(source_pid) and not blank?(target_pid) and
          to_string(source_pid) != to_string(target_pid)
    end
  end

  defp ntdll_source_pid(ctx) do
    first_context_value(ctx, [
      [:raw_event, :source_pid],
      [:raw_event, :metadata, :source_pid],
      [:raw_event, :enrichment, :source_pid],
      [:raw_event, :enrichment, :metadata, :source_pid],
      [:raw_event, :pid],
      [:process, :pid]
    ])
  end

  defp ntdll_target_pid(ctx) do
    first_context_value(ctx, [
      [:raw_event, :target_pid],
      [:raw_event, :metadata, :target_pid],
      [:raw_event, :enrichment, :target_pid],
      [:raw_event, :enrichment, :metadata, :target_pid],
      [:process, :target_pid]
    ])
  end

  defp ntdll_target_function(ctx) do
    first_context_value(ctx, [
      [:raw_event, :target_function],
      [:raw_event, :metadata, :target_function],
      [:raw_event, :enrichment, :target_function],
      [:raw_event, :enrichment, :metadata, :target_function],
      [:raw_event, :target_module],
      [:raw_event, :enrichment, :metadata, :target_module]
    ])
    |> normalize_fp_text()
  end

  defp ntdll_region_class(ctx) do
    first_context_value(ctx, [
      [:raw_event, :region_class],
      [:raw_event, :metadata, :region_class],
      [:raw_event, :enrichment, :region_class],
      [:raw_event, :enrichment, :metadata, :region_class],
      [:detection, :region_class]
    ])
    |> normalize_fp_text()
  end

  # Strongest tampering signal: a write into the export table keeps full
  # severity even from a signed source.
  defp ntdll_export_table_target?(ctx) do
    region = ntdll_region_class(ctx)
    func = ntdll_target_function(ctx)

    region == "export_table" or
      String.contains?(func, "export") or
      String.contains?(func, "eat")
  end

  # RWX (or W^X-violating) regions keep full severity. Prefer the agent's
  # region_class; fall back to the resulting protection flags.
  defp ntdll_rwx_region?(ctx) do
    case ntdll_region_class(ctx) do
      "rwx" -> true
      region when region in ["text", "data", "export_table"] -> false
      _ -> ntdll_rwx_protection?(ctx)
    end
  end

  defp ntdll_rwx_protection?(ctx) do
    new_protection =
      first_context_value(ctx, [
        [:raw_event, :new_protection_str],
        [:raw_event, :metadata, :new_protection_str],
        [:raw_event, :enrichment, :new_protection_str],
        [:raw_event, :enrichment, :metadata, :new_protection_str],
        [:raw_event, :new_protection],
        [:raw_event, :enrichment, :metadata, :new_protection]
      ])
      |> normalize_memory_protection()

    new_protection in ["page_execute_readwrite", "page_execute_writecopy", "0x40", "0x80"]
  end

  defp unusual_time_only_risk_fp?(ctx) do
    factors =
      field(ctx, [:raw_event, :factors]) ||
        field(ctx, [:detection, :factors]) ||
        []

    factor_names =
      factors
      |> List.wrap()
      |> Enum.map(fn
        factor when is_map(factor) -> map_get(factor, :name) || map_get(factor, :factor)
        factor -> factor
      end)
      |> Enum.map(&normalize_fp_text/1)
      |> Enum.reject(&(&1 == ""))

    factor_names != [] and
      Enum.all?(factor_names, &(&1 == "unusual_time" or &1 == "unusual_execution_time"))
  end

  defp benign_operational_high_risk_score?(ctx) do
    process = process_basename(ctx)
    parent = parent_basename(ctx)
    path = normalize_path(field(ctx, [:process, :path]) || field(ctx, [:process, :image_path]))
    parent_path = normalize_path(field(ctx, [:process, :parent_path]) || field(ctx, [:raw_event, :parent_path]))
    cmdline = normalize_fp_text(field(ctx, [:process, :cmdline]) || field(ctx, [:process, :command_line]))

    cond do
      process in ["pwsh.exe", "dotnet.exe"] ->
        operational_shell_command?(cmdline) and
          (
            String.contains?(path, "\\users\\") or
              String.contains?(path, "\\program files\\dotnet\\dotnet.exe")
          ) and
          (
            parent in ["codex.exe", "antigravity.exe", "pwsh.exe"] or
              String.contains?(parent_path, "\\antigravity\\") or
              String.contains?(parent_path, "\\@openai\\codex\\")
          )

      process == "antigravity.exe" ->
        String.contains?(path, "\\users\\") and String.contains?(path, "\\antigravity\\") and
          (String.contains?(cmdline, "tsserver.js") or
             String.contains?(cmdline, "--type=gpu-process") or
             String.contains?(cmdline, "--type=utility"))

      process == "brave.exe" ->
        String.contains?(path, "\\bravesoftware\\brave-browser\\application\\brave.exe") and
          (String.contains?(cmdline, "--type=renderer") or String.contains?(cmdline, "--extension-process"))

      process == "postgres.exe" ->
        String.contains?(path, "\\program files\\postgresql\\") and
          (String.contains?(cmdline, "--forkbgworker") or String.contains?(cmdline, "\\postgresql\\"))

      true ->
        false
    end
  end

  defp macos_benign_operational_high_risk_score?(ctx) do
    process = process_basename(ctx)
    path = normalize_posix_path(field(ctx, [:process, :path]) || field(ctx, [:process, :image_path]))
    cmdline = normalize_fp_text(field(ctx, [:process, :cmdline]) || field(ctx, [:process, :command_line]))
    parent = parent_basename(ctx)
    parent_path = normalize_posix_path(field(ctx, [:process, :parent_path]) || field(ctx, [:raw_event, :parent_path]))

    cond do
      process == "osascript" ->
        path == "/usr/bin/osascript" and
          trusted_macos_operator_parent?(parent, parent_path) and
          String.contains?(cmdline, "do shell script") and
          String.contains?(cmdline, "with administrator privileges") and
          String.contains?(cmdline, "tamandua")

      process == "launchctl" ->
        path in ["/bin/launchctl", "/usr/bin/launchctl"] and
          trusted_macos_operator_parent?(parent, parent_path) and
          macos_launchctl_tamandua_command?(cmdline)

      process in ["lsof", "netstat", "scutil", "plutil", "sw_vers"] ->
        String.starts_with?(path, "/usr/") and
          trusted_macos_operator_parent?(parent, parent_path) and
          macos_diagnostic_command?(process, cmdline)

      true ->
        false
    end
  end

  defp macos_benign_unusual_time_process_fp?(ctx) do
    process = process_basename(ctx)
    path = normalize_posix_path(field(ctx, [:process, :path]) || field(ctx, [:process, :image_path]))
    cmdline = normalize_fp_text(field(ctx, [:process, :cmdline]) || field(ctx, [:process, :command_line]))

    process in ["launchctl", "lsof", "netstat", "plutil", "sw_vers", "scutil"] and
      String.starts_with?(path, "/") and
      (macos_launchctl_tamandua_command?(cmdline) or macos_diagnostic_command?(process, cmdline))
  end

  defp trusted_macos_operator_parent?(parent, parent_path) do
    parent in ["tamandua edr", "tamandua-agent", "zsh", "bash", "sh", "codex"] or
      String.contains?(parent_path, "/tamandua") or
      String.contains?(parent_path, "/.codex/")
  end

  defp macos_launchctl_tamandua_command?(cmdline) do
    String.contains?(cmdline, "launchctl") and
      String.contains?(cmdline, "com.tamandua.") and
      (String.contains?(cmdline, " print ") or
         String.contains?(cmdline, " bootstrap ") or
         String.contains?(cmdline, " bootout ") or
         String.contains?(cmdline, " kickstart ") or
         String.contains?(cmdline, " enable "))
  end

  defp macos_diagnostic_command?("lsof", cmdline), do: String.contains?(cmdline, "-i") or String.contains?(cmdline, "-n")
  defp macos_diagnostic_command?("netstat", cmdline), do: String.contains?(cmdline, "-an") or String.contains?(cmdline, "-anv")
  defp macos_diagnostic_command?("scutil", cmdline), do: String.contains?(cmdline, "--dns") or String.contains?(cmdline, "--proxy")
  defp macos_diagnostic_command?("plutil", cmdline), do: String.contains?(cmdline, "-lint")
  defp macos_diagnostic_command?("sw_vers", _cmdline), do: true
  defp macos_diagnostic_command?(_, _), do: false

  defp operational_shell_command?(cmdline) do
    String.contains?(cmdline, "shellintegration.ps1") or
      String.contains?(cmdline, "get-ciminstance win32_process") or
      String.contains?(cmdline, "get-childitem tools\\detection_validation") or
      String.contains?(cmdline, "get-content .tmp\\") or
      String.contains?(cmdline, "python .tmp\\") or
      String.contains?(cmdline, "git pull") or
      String.contains?(cmdline, "rg -n ")
  end

  defp benign_unusual_time_process_fp?(ctx) do
    benign = [
      "dotnet.exe",
      "pwsh.exe",
      "node.exe",
      "searchprotocolhost.exe",
      "netstat.exe",
      "schtasks.exe",
      "rustc.exe",
      "antigravity.exe",
      "claude.exe",
      "msedgewebview2.exe",
      "brave.exe",
      "csrss.exe",
      "nordvpn-service.exe",
      "twingate.exe",
      "explorer.exe",
      "dwm.exe"
    ]

    process_basename(ctx) in benign and
      detection_name(ctx) == "behavioral_unusual_execution_time"
  end

  defp lsass_self_event_fp?(ctx) do
    process_basename(ctx) == "lsass.exe" and
      parent_basename(ctx) == "wininit.exe" and
      windows_system32_path?(field(ctx, [:process, :path]) || field(ctx, [:process, :image_path]))
  end

  defp windows_core_service_process_fp?(ctx) do
    process = process_basename(ctx)
    parent = parent_basename(ctx)
    rule = detection_name(ctx)
    path = field(ctx, [:process, :path]) || field(ctx, [:process, :image_path])
    parent_path = field(ctx, [:process, :parent_path])
    cmdline = normalize_fp_text(field(ctx, [:process, :cmdline]) || field(ctx, [:process, :command_line]))

    core_services_chain? =
      process == "services.exe" and parent == "wininit.exe" and
        (cmdline == "" or String.ends_with?(cmdline, "\\system32\\services.exe") or cmdline == "services.exe")

    core_svchost_chain? =
      process == "svchost.exe" and parent == "services.exe" and
        String.contains?(cmdline, "svchost.exe") and
        String.contains?(cmdline, " -k ") and
        String.contains?(cmdline, " -s ")

    noisy_rule? =
      rule in [
        "system file execution location anomaly",
        "hacktool - crackmapexec execution",
        "renamed plink execution",
        "lateral wmi winrm remote management discovery"
      ] or String.contains?(rule, "masquerad")

    (core_services_chain? or core_svchost_chain?) and noisy_rule? and
      windows_system32_path?(path) and
      (blank?(parent_path) or windows_system32_path?(parent_path)) and
      not String.contains?(cmdline, "powershell") and
      not String.contains?(cmdline, "cmd.exe /c") and
      not String.contains?(cmdline, "wmic") and
      not String.contains?(cmdline, "winrm")
  end

  defp nvidia_rundll32_rxdiag_fp?(ctx) do
    process_basename(ctx) == "rundll32.exe" and
      parent_basename(ctx) == "nvcontainer.exe" and
      String.contains?(normalize_fp_text(field(ctx, [:process, :cmdline]) || field(ctx, [:raw_event, :cmdline])), "rxdiag.dll") and
      trusted_parent_context?(ctx, ["nvidia", "nvidia corporation"])
  end

  defp edge_webview_runonce_cleanup_fp?(ctx) do
    key = normalize_fp_text(field(ctx, [:registry, :key]) || field(ctx, [:raw_event, :registry_key]) || field(ctx, [:raw_event, :key_path]))
    data = normalize_fp_text(field(ctx, [:registry, :data]) || field(ctx, [:raw_event, :registry_data]) || field(ctx, [:raw_event, :value_data]))

    String.contains?(key, "\\currentversion\\runonce") and
      String.contains?(data, "msedgewebview") and
      String.contains?(data, "--delete-old-versions")
  end

  # Benchmark-harness false positive: the harness/setup step writes its own
  # Run-key value (e.g. value name "TamanduaBenchRun", data "tamandua-bench-run")
  # under HKCU\...\CurrentVersion\Run. This is gated on the Run-key path AND a
  # registry value-name/data carrying the harness marker "tamandua"; it does NOT
  # blanket-downgrade REGISTRY_PERSISTENCE for any unmarked Run-key write.
  defp benign_benchmark_run_key_persistence_fp?(ctx) do
    rule = detection_name(ctx)

    persistence_rule? =
      rule in ["registry_persistence", "persistence_t1547_001", "registry_t1547_001"]

    key =
      normalize_fp_text(
        field(ctx, [:registry, :key]) ||
          field(ctx, [:registry, :key_path]) ||
          field(ctx, [:raw_event, :registry_key]) ||
          field(ctx, [:raw_event, :key_path])
      )

    value_name =
      normalize_fp_text(
        field(ctx, [:registry, :value]) ||
          field(ctx, [:registry, :value_name]) ||
          field(ctx, [:raw_event, :registry_value]) ||
          field(ctx, [:raw_event, :value_name])
      )

    data =
      normalize_fp_text(
        field(ctx, [:registry, :data]) ||
          field(ctx, [:raw_event, :registry_data]) ||
          field(ctx, [:raw_event, :value_data])
      )

    run_key? =
      String.contains?(key, "\\currentversion\\run") and
        not String.contains?(key, "\\currentversion\\runonce")

    harness_marker? =
      String.contains?(value_name, "tamandua") or String.contains?(data, "tamandua")

    persistence_rule? and run_key? and harness_marker?
  end

  defp edge_update_etw_patch_fp?(ctx) do
    rule = detection_name(ctx)
    technique = normalize_fp_text(field(ctx, [:detection, :mitre_technique]) || field(ctx, [:detection, :mitre_techniques]))
    process = process_basename(ctx)
    parent = parent_basename(ctx)
    path = normalize_path(field(ctx, [:process, :path]) || field(ctx, [:process, :image_path]))
    cmdline = normalize_fp_text(field(ctx, [:process, :cmdline]) || field(ctx, [:process, :command_line]))

    etw_tamper_rule? =
      String.starts_with?(rule, "etw_") or String.contains?(technique, "t1562.006")

    etw_tamper_rule? and
      process == "microsoftedgeupdate.exe" and
      parent in ["", "svchost.exe", "microsoftedgeupdate.exe"] and
      String.contains?(path, "\\program files (x86)\\microsoft\\edgeupdate\\microsoftedgeupdate.exe") and
      benign_edge_update_command?(cmdline)
  end

  defp contextless_kernel_memory_detection?(ctx) do
    rule = detection_name(ctx)

    kernel_memory_rule? =
      String.starts_with?(rule, "kernel_poolparty_") or
        String.starts_with?(rule, "kernel_syscall_")

    process_fields = [
      field(ctx, [:process, :name]),
      field(ctx, [:process, :process_name]),
      field(ctx, [:process, :pid]),
      field(ctx, [:process, :command_line]),
      field(ctx, [:process, :cmdline]),
      field(ctx, [:raw_event, :process_name]),
      field(ctx, [:raw_event, :pid]),
      field(ctx, [:raw_event, :source_pid]),
      field(ctx, [:raw_event, :target_pid])
    ]

    kernel_memory_rule? and Enum.all?(process_fields, &blank?/1)
  end

  defp contextless_etw_tamper_detection?(ctx) do
    rule = detection_name(ctx)

    technique =
      normalize_fp_text(
        field(ctx, [:detection, :mitre_technique]) ||
          field(ctx, [:detection, :mitre_techniques]) ||
          field(ctx, [:raw_event, :mitre_technique]) ||
          field(ctx, [:raw_event, :mitre_techniques])
      )

    context_fields = [
      field(ctx, [:process, :name]),
      field(ctx, [:process, :process_name]),
      field(ctx, [:process, :path]),
      field(ctx, [:process, :image_path]),
      field(ctx, [:process, :command_line]),
      field(ctx, [:process, :cmdline]),
      field(ctx, [:raw_event, :process_name]),
      field(ctx, [:raw_event, :path]),
      field(ctx, [:raw_event, :image_path]),
      field(ctx, [:raw_event, :command_line]),
      field(ctx, [:raw_event, :provider_name]),
      field(ctx, [:raw_event, :session_name]),
      field(ctx, [:raw_event, :operation]),
      field(ctx, [:raw_event, :target_provider]),
      field(ctx, [:raw_event, :target_session])
    ]

    String.starts_with?(rule, "etw_") and
      String.contains?(technique, "t1562.006") and
      Enum.all?(context_fields, &blank?/1)
  end

  defp contextless_ntdll_write_detection?(ctx) do
    rule = detection_name(ctx)

    ntdll_write_rule? =
      rule in [
        "ntdll_write_writeprocessmemory",
        "ntdll_write_ntwritevirtualmemory",
        "ntdll_write_ntmapviewofsection"
      ]

    target_fields = [
      field(ctx, [:raw_event, :target_pid]),
      field(ctx, [:raw_event, :target_process]),
      field(ctx, [:raw_event, :target_process_name]),
      field(ctx, [:raw_event, :target_image]),
      field(ctx, [:raw_event, :target_module]),
      field(ctx, [:raw_event, :target_address]),
      field(ctx, [:raw_event, :write_size]),
      field(ctx, [:raw_event, :bytes_written]),
      field(ctx, [:raw_event, :call_stack]),
      field(ctx, [:process, :target_pid]),
      field(ctx, [:process, :target_process]),
      field(ctx, [:process, :target_process_name])
    ]

    ntdll_write_rule? and Enum.all?(target_fields, &blank?/1)
  end

  defp contextless_service_registry_detection?(ctx) do
    rule = detection_name(ctx)
    key =
      normalize_path(
        field(ctx, [:registry, :key]) ||
          field(ctx, [:registry, :key_path]) ||
          field(ctx, [:raw_event, :registry_key]) ||
          field(ctx, [:raw_event, :key_path])
      )

    process_fields = [
      field(ctx, [:process, :name]),
      field(ctx, [:process, :process_name]),
      field(ctx, [:process, :path]),
      field(ctx, [:process, :image_path]),
      field(ctx, [:process, :command_line]),
      field(ctx, [:process, :cmdline]),
      field(ctx, [:raw_event, :process_name]),
      field(ctx, [:raw_event, :name]),
      field(ctx, [:raw_event, :path]),
      field(ctx, [:raw_event, :pid])
    ]

    rule == "registry_t1543_003" and
      String.contains?(key, "\\system\\currentcontrolset\\services") and
      Enum.all?(process_fields, fn value ->
        normalized = normalize_fp_text(value)
        blank?(value) or normalized in ["0", "unknown"]
      end)
  end

  defp ngen_runtime_maintenance_fp?(ctx) do
    rule = detection_name(ctx)
    process = process_basename(ctx)
    parent = parent_basename(ctx)
    path = normalize_path(field(ctx, [:process, :path]) || field(ctx, [:process, :image_path]))
    cmdline = normalize_fp_text(field(ctx, [:process, :cmdline]) || field(ctx, [:process, :command_line]))

    (rule == "ntdll_write_ntmapviewofsection" or String.starts_with?(rule, "etw_")) and
      process == "ngentask.exe" and
      parent in ["taskhostw.exe", ""] and
      String.contains?(path, "\\windows\\microsoft.net\\framework\\") and
      String.contains?(cmdline, "ngentask.exe") and
      String.contains?(cmdline, "/runtimewide")
  end

  defp invalid_zero_ioc?(ctx) do
    indicators =
      List.wrap(map_get(ctx.evidence, :indicators)) ++
        List.wrap(map_get(ctx.evidence, :network)) ++
        [ctx.raw_event]

    Enum.any?(indicators, fn item ->
      value = map_get(item, :value) || map_get(item, :remote_ip) || map_get(item, :local_ip) || map_get(item, :ip)
      normalize_fp_text(value) == "0.0.0.0"
    end)
  end

  defp process_basename(ctx), do: field(ctx, [:process, :name]) |> basename()
  defp parent_basename(ctx), do: field(ctx, [:process, :parent_name]) |> basename()

  defp detection_name(ctx) do
    (field(ctx, [:detection, :rule_name]) || field(ctx, [:detection, :name]))
    |> normalize_fp_text()
  end

  defp credential_target?(ctx) do
    target =
      first_context_value(ctx, [
        [:raw_event, :target_process],
        [:raw_event, :target_process_name],
        [:raw_event, :metadata, :target_process],
        [:raw_event, :metadata, :target_process_name],
        [:raw_event, :enrichment, :target_process],
        [:raw_event, :enrichment, :target_process_name],
        [:raw_event, :enrichment, :metadata, :target_process],
        [:raw_event, :enrichment, :metadata, :target_process_name]
      ])
      |> normalize_fp_text()

    String.contains?(target, "lsass") or String.contains?(target, "sam")
  end

  defp trusted_process_context?(ctx) do
    path = normalize_fp_text(field(ctx, [:process, :path]) || field(ctx, [:process, :image_path]))
    signer = normalize_fp_text(field(ctx, [:process, :signer]))
    process = process_basename(ctx)

    cond do
      process == "google chrome helper" ->
        String.contains?(path, "/applications/google chrome.app/") or
          String.contains?(path, "\\google\\chrome\\application\\") or
          String.contains?(signer, "google")

      process == "synergy-core" ->
        String.contains?(path, "synergy") or String.contains?(signer, "synergy")

      true ->
        signer != ""
    end
  end

  defp trusted_parent_context?(ctx, expected_signers) do
    signer = normalize_fp_text(field(ctx, [:process, :parent_signer]) || field(ctx, [:raw_event, :parent_signer]))
    path = normalize_path(field(ctx, [:process, :parent_path]) || field(ctx, [:raw_event, :parent_path]))

    Enum.any?(expected_signers, fn expected ->
      String.contains?(signer, expected) or String.contains?(path, expected)
    end)
  end

  defp private_ipv4?(ip) do
    case ip |> to_string() |> String.split(".") |> Enum.map(&Integer.parse/1) do
      [{10, ""}, {_, ""}, {_, ""}, {_, ""}] -> true
      [{172, ""}, {second, ""}, {_, ""}, {_, ""}] when second in 16..31 -> true
      [{192, ""}, {168, ""}, {_, ""}, {_, ""}] -> true
      _ -> false
    end
  end

  defp windows_system32_path?(path) do
    normalize_path(path) =~ ~r/^[a-z]:\\windows\\system32\\lsass\.exe$/
  end

  defp benign_edge_update_command?(cmdline) do
    normalized = cmdline |> normalize_fp_text() |> String.trim()

    String.ends_with?(normalized, "microsoftedgeupdate.exe /c") or
      (String.contains?(normalized, "microsoftedgeupdate.exe") and
         String.contains?(normalized, " /ua ") and
         (String.contains?(normalized, "/installsource scheduler") or
            String.contains?(normalized, "/installsource core")))
  end

  defp same_non_nil?(left, right), do: not is_nil(left) and not is_nil(right) and to_string(left) == to_string(right)
  defp blank?(value), do: value in [nil, "", []]

  defp basename(nil), do: ""
  defp basename(value) do
    value
    |> to_string()
    |> String.replace("\\", "/")
    |> Path.basename()
    |> String.downcase()
  end

  defp normalize_path(value) do
    value
    |> to_string()
    |> String.replace("/", "\\")
    |> String.downcase()
  end

  defp normalize_posix_path(value) do
    value
    |> to_string()
    |> String.replace("\\", "/")
    |> String.downcase()
  end

  defp first_map(values) do
    Enum.find(values, %{}, &is_map/1)
  end

  defp ensure_map(value) when is_map(value), do: value
  defp ensure_map(_), do: %{}

  defp field(ctx, [section, key]) do
    ctx
    |> Map.get(section, %{})
    |> map_get(key)
  end

  defp first_context_value(ctx, paths) do
    Enum.find_value(paths, fn path ->
      value = nested_context_value(ctx, path)
      if blank?(value), do: nil, else: value
    end)
  end

  defp nested_context_value(value, []), do: value

  defp nested_context_value(value, [key | rest]) when is_map(value) do
    value
    |> map_get(key)
    |> nested_context_value(rest)
  end

  defp nested_context_value(_, _), do: nil

  defp normalize_memory_protection(value) do
    value
    |> normalize_fp_text()
    |> String.replace(" ", "_")
  end

  defp map_get(map, key) when is_map(map) do
    Map.get(map, key) || Map.get(map, Atom.to_string(key))
  end

  defp map_get(_, _), do: nil

  # Insert a new alert row when no duplicate was found.
  defp do_create_new_alert(attrs) do
    alias TamanduaServer.Alerts.Deduplication

    # Ensure dedup_key is set (Deduplication.check_and_deduplicate sets it)
    dedup_key = attrs[:dedup_key] || compute_dedup_key(attrs)
    attrs = Map.put(attrs, :dedup_key, dedup_key)

    now = DateTime.utc_now()
    attrs = Map.put(attrs, :last_seen_at, now)

    result = %Alert{}
    |> Alert.changeset(attrs)
    |> Repo.insert()

    # Trigger playbooks and broadcasts on successful alert creation
    case result do
      {:ok, alert} ->
        # Apply enrichers after creation (enrichment is non-blocking)
        enriched_alert = apply_enrichers(alert)

        # Register the new alert in the dedup ETS window
        Deduplication.register_new_alert(dedup_key, enriched_alert.id, attrs)

        # Async trigger playbooks for this alert
        spawn(fn ->
          try do
            TamanduaServer.Response.Playbook.trigger_for_alert(enriched_alert)
          rescue
            e -> Logger.warning("Failed to trigger playbooks for alert: #{inspect(e)}")
          catch
            _, _ -> :ok
          end
        end)

        # Broadcast to dashboard and geo channels
        spawn(fn ->
          try do
            TamanduaServerWeb.Broadcaster.broadcast_new_alert(enriched_alert)
            TamanduaServerWeb.Broadcaster.broadcast_geo_update()
          rescue
            _ -> :ok
          catch
            _, _ -> :ok
          end
        end)

        # Send notifications for the new alert
        spawn(fn ->
          try do
            TamanduaServer.Alerts.Notifier.notify_alert(enriched_alert)
          rescue
            e -> Logger.warning("Failed to send notifications for alert: #{inspect(e)}")
          catch
            _, _ -> :ok
          end
        end)

        # Schedule async threat attribution for high/critical alerts.
        # This calls Attribution.attribute_alert/1 in a background task
        # and updates the alert if a match is found. Never blocks alert
        # creation.
        maybe_schedule_attribution(enriched_alert)

        # Schedule async cross-agent correlation
        # This correlates the alert with other alerts to detect attack campaigns
        maybe_schedule_correlation(enriched_alert)

        maybe_submit_on_chain(enriched_alert)

        {:ok, enriched_alert}

      error ->
        error
    end
  end

  # Apply alert enrichers based on alert type and context.
  # Enrichers are fail-safe: errors are logged but don't block alert creation.
  defp apply_enrichers(alert) do
    alert
    |> maybe_enrich_supply_chain()
    |> maybe_enrich_kubernetes()
  end

  defp maybe_submit_on_chain(%Alert{} = alert) do
    alias TamanduaServer.Workers.AttestationWorker

    if is_nil(Process.whereis(Oban)) do
      Logger.debug("[Alerts] Oban unavailable, skipping attestation for alert #{alert.id}")
      :ok
    else
      do_submit_on_chain(alert, AttestationWorker)
    end
  rescue
    e ->
      Logger.warning("[Alerts] Attestation scheduling failed for #{alert.id}: #{Exception.message(e)}")
      :ok
  catch
    :exit, reason ->
      Logger.warning("[Alerts] Attestation scheduling unavailable for #{alert.id}: #{inspect(reason)}")
      :ok
  end

  defp do_submit_on_chain(alert, attestation_worker) do
    # Use Oban worker for reliable, retryable attestation processing
    # The worker handles:
    # - Severity validation (medium/high/critical only)
    # - Duplicate prevention (already attested alerts)
    # - Bounty payment to rule authors
    # - PubSub broadcast on success
    case attestation_worker.enqueue_for_alert(alert) do
      {:ok, job} ->
        Logger.debug("[Alerts] Attestation job enqueued for alert #{alert.id}: job_id=#{job.id}")

      {:error, :already_attested} ->
        Logger.debug("[Alerts] Alert #{alert.id} already attested, skipping")

      {:error, :severity_not_eligible} ->
        Logger.debug("[Alerts] Alert #{alert.id} not eligible for attestation (severity: #{alert.severity})")

      {:error, :solana_disabled} ->
        Logger.debug("[Alerts] Solana disabled, skipping attestation for alert #{alert.id}")

      {:error, reason} ->
        Logger.warning("[Alerts] Failed to enqueue attestation for #{alert.id}: #{inspect(reason)}")
    end

    :ok
  end

  defp maybe_enrich_supply_chain(alert) do
    enrichment = alert.enrichment || %{}
    risk_type = enrichment["risk_type"]

    if risk_type in ["known_malicious", "typosquatting", "malicious_script", "anomalous_behavior"] do
      try do
        SupplyChainEnricher.enrich(alert)
      rescue
        e ->
          Logger.warning("[Alerts] Supply chain enrichment failed: #{Exception.message(e)}")
          alert
      catch
        :exit, _ -> alert
      end
    else
      alert
    end
  end

  defp maybe_enrich_kubernetes(alert) do
    # Check if alert has container context that can be enriched
    enrichment = alert.enrichment || %{}
    evidence = alert.evidence || %{}
    raw_event = alert.raw_event || %{}

    container_id = enrichment["container_id"] ||
                   get_in(evidence, [:process, :container_id]) ||
                   get_in(evidence, ["process", "container_id"]) ||
                   raw_event["container_id"] ||
                   raw_event[:container_id]

    if container_id && container_id != "" do
      try do
        KubernetesEnricher.enrich(alert, container_id: container_id)
      rescue
        e ->
          Logger.warning("[Alerts] Kubernetes enrichment failed: #{Exception.message(e)}")
          alert
      catch
        :exit, _ -> alert
      end
    else
      alert
    end
  end

  @doc """
  Creates an alert with full evidence extraction.

  This function extracts evidence from the provided event and detections,
  making it easier to create fully-populated alerts from the detection engine.

  ## Parameters

  - `event` - The triggering telemetry event
  - `detections` - List of detection results
  - `attrs` - Additional alert attributes

  ## Examples

      iex> create_alert_with_evidence(event, detections, %{severity: :high, title: "Suspicious Process"})
      {:ok, %Alert{evidence: %{...}, ...}}
  """
  def create_alert_with_evidence(event, detections, attrs \\ %{}) do
    evidence = Evidence.extract(event, detections)
    detection_metadata = Evidence.extract_detection_info(detections)
    payload = event[:payload] || event["payload"] || %{}
    event_id = event[:event_id] || event["event_id"]

    attrs = attrs
    |> Map.put(:evidence, evidence)
    |> Map.put(:detection_metadata, detection_metadata)
    |> Map.put(:raw_event, payload)
    |> Map.put(:source_event_id, event_id)
    |> Map.update(:event_ids, List.wrap(event_id), fn existing ->
      if is_list(existing) and existing != [] do
        Enum.uniq(List.wrap(event_id) ++ existing)
      else
        List.wrap(event_id)
      end
    end)

    create_alert(attrs)
  end

  # Normalize atom values to strings for fields that the schema stores as strings.
  defp normalize_alert_attrs(attrs) do
    attrs
    |> maybe_stringify(:severity)
    |> maybe_stringify(:status)
  end

  defp maybe_stringify(attrs, key) do
    case Map.get(attrs, key) do
      val when is_atom(val) and not is_nil(val) -> Map.put(attrs, key, Atom.to_string(val))
      _ -> attrs
    end
  end

  # Extract source_event_id and event_ids from event if provided and not already set
  defp maybe_extract_source_event_id(attrs) do
    has_source_event_id = Map.has_key?(attrs, :source_event_id) and attrs[:source_event_id] != nil
    has_event = Map.has_key?(attrs, :event) or Map.has_key?(attrs, "event")

    if !has_source_event_id and has_event do
      event = attrs[:event] || attrs["event"]
      event_id = event[:event_id] || event["event_id"]

      attrs = if event_id do
        attrs
        |> Map.put(:source_event_id, event_id)
        |> Map.update(:event_ids, [event_id], fn existing ->
          if is_list(existing) and existing != [] do
            Enum.uniq([event_id | existing])
          else
            [event_id]
          end
        end)
      else
        attrs
      end

      attrs
    else
      attrs
    end
  end

  # Extract evidence from event and detections if provided and evidence not already set
  defp maybe_extract_evidence(attrs) do
    has_evidence = Map.has_key?(attrs, :evidence) and attrs[:evidence] != %{}
    has_event = Map.has_key?(attrs, :event) or Map.has_key?(attrs, "event")

    if !has_evidence and has_event do
      event = attrs[:event] || attrs["event"]
      detections = attrs[:detections] || attrs["detections"] || []

      evidence = Evidence.extract(event, detections)
      detection_metadata = Evidence.extract_detection_info(detections)

      attrs
      |> Map.put(:evidence, evidence)
      |> Map.put(:detection_metadata, detection_metadata)
      |> Map.delete(:event)
      |> Map.delete("event")
      |> Map.delete(:detections)
      |> Map.delete("detections")
    else
      attrs
    end
  end

  # Set raw_event from event payload if not already set.
  #
  # The agent ships forensic context in two places: the typed `payload`
  # (e.g. MemoryPermission) and a flat `metadata` map (target_pid,
  # source_pid, target_address, operation, new_protection, ...). Folding
  # both the metadata and enrichment sections into raw_event is what lets
  # the structured FP detectors resolve [:raw_event, :metadata, :target_pid]
  # and [:raw_event, :enrichment, :metadata, ...]; without this they always
  # see blank target context and collapse every ntdll_write to the generic
  # "missing_target_context" reduction.
  defp maybe_set_raw_event(attrs) do
    has_raw_event = Map.has_key?(attrs, :raw_event) and attrs[:raw_event] != nil
    has_event = Map.has_key?(attrs, :event) or Map.has_key?(attrs, "event")

    if !has_raw_event and has_event do
      event = attrs[:event] || attrs["event"]
      payload = (event[:payload] || event["payload"] || %{}) |> ensure_map()
      metadata = event[:metadata] || event["metadata"]
      enrichment = event[:enrichment] || event["enrichment"]

      raw_event =
        payload
        |> put_event_section("metadata", metadata)
        |> put_event_section("enrichment", enrichment)

      Map.put(attrs, :raw_event, raw_event)
    else
      attrs
    end
  end

  # Fold an agent-supplied event section (metadata/enrichment) into the
  # raw_event map without clobbering existing payload keys. Existing payload
  # values win on conflict; the section is only added when it carries data.
  defp put_event_section(raw_event, _key, value) when value == nil or value == %{},
    do: raw_event

  defp put_event_section(raw_event, key, value) when is_map(value) do
    Map.update(raw_event, key, value, fn
      existing when is_map(existing) -> Map.merge(value, existing)
      _existing -> value
    end)
  end

  defp put_event_section(raw_event, _key, _value), do: raw_event

  defp maybe_attach_alert_quality(attrs) do
    quality = build_alert_quality(attrs)

    attrs
    |> Map.update(:detection_metadata, %{"telemetry_quality" => quality}, fn metadata ->
      metadata
      |> ensure_map()
      |> Map.put("telemetry_quality", quality)
    end)
  end

  # Provide conservative, severity-based analyst guidance when a detection
  # source does not supply its own recommended_response. Keeps all alert
  # creation paths (correlator, dynamic_hunter, etc.) consistent with the
  # engine worker, which sets a tailored value.
  defp maybe_set_recommended_response(attrs) do
    existing = attrs[:recommended_response] || attrs["recommended_response"]

    if is_binary(existing) and existing != "" do
      attrs
    else
      severity = attrs[:severity] || attrs["severity"]
      Map.put(attrs, :recommended_response, default_recommended_response(severity))
    end
  end

  defp default_recommended_response(severity) do
    case severity |> to_string() |> String.downcase() do
      "critical" -> "Triage immediately: isolate the affected host and preserve volatile evidence."
      "high" -> "Triage promptly: review the process chain and contain the host if confirmed."
      "medium" -> "Investigate the surrounding telemetry and validate against expected baseline activity."
      _ -> "Review the alert evidence and confirm whether the activity is expected."
    end
  end

  defp build_alert_quality(attrs) do
    evidence = attrs |> alert_attr(:evidence) |> ensure_map()
    raw_event = attrs |> alert_attr(:raw_event) |> ensure_map()
    detection = attrs |> alert_attr(:detection_metadata) |> ensure_map()
    category = alert_quality_category(attrs, evidence, raw_event, detection)
    required = required_alert_fields(category, detection)

    present =
      required
      |> Enum.filter(&alert_quality_present?(&1, evidence, raw_event))

    missing = required -- present
    score = alert_quality_score(required, present)

    %{
      "schema_version" => "alert-telemetry-quality/v1",
      "category" => category,
      "score" => score,
      "level" => alert_quality_level(score),
      "required_fields" => required,
      "present" => present,
      "missing" => missing,
      "correlation_ready" => missing == [],
      "generated_at" => DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()
    }
  end

  defp alert_quality_category(attrs, evidence, raw_event, detection) do
    event_type =
      alert_attr(attrs, :event_type) ||
        map_get(raw_event, :event_type) ||
        map_get(detection, :event_type) ||
        map_get(detection, :category) ||
        alert_attr(attrs, :title)

    evidence_keys =
      evidence
      |> Map.keys()
      |> Enum.map(&to_string/1)

    normalized = event_type |> to_string() |> String.downcase()

    cond do
      "network" in evidence_keys or String.contains?(normalized, "network") or
          String.contains?(normalized, "connect") or String.contains?(normalized, "dns") ->
        "network"

      "registry" in evidence_keys or String.contains?(normalized, "registry") or
          String.contains?(normalized, "reg_") ->
        "registry"

      "file" in evidence_keys or String.contains?(normalized, "file") or
          String.contains?(normalized, "write") or String.contains?(normalized, "delete") ->
        "file"

      true ->
        "process"
    end
  end

  defp required_alert_fields("network", _detection),
    do: ["process.name", "process.pid", "network.remote_ip", "network.remote_port", "network.protocol"]

  defp required_alert_fields("registry", _detection),
    do: ["process.name", "process.pid", "registry.key"]

  defp required_alert_fields("file", _detection),
    do: ["process.name", "process.pid", "file.path"]

  defp required_alert_fields(_category, _detection),
    do: ["process.name", "process.pid", "process.command_line", "process.parent_name"]

  defp alert_quality_present?(field, evidence, raw_event) do
    field
    |> alert_quality_values(evidence, raw_event)
    |> Enum.any?(&present_value?/1)
  end

  defp alert_quality_values("process.name", evidence, raw_event) do
    process = map_get(evidence, :process) |> ensure_map()
    [map_get(process, :name), map_get(raw_event, :process_name), map_get(raw_event, :name)]
  end

  defp alert_quality_values("process.pid", evidence, raw_event) do
    process = map_get(evidence, :process) |> ensure_map()
    [map_get(process, :pid), map_get(raw_event, :pid), map_get(raw_event, :process_pid)]
  end

  defp alert_quality_values("process.command_line", evidence, raw_event) do
    process = map_get(evidence, :process) |> ensure_map()
    [map_get(process, :cmdline), map_get(process, :command_line), map_get(raw_event, :cmdline), map_get(raw_event, :command_line)]
  end

  defp alert_quality_values("process.parent_name", evidence, raw_event) do
    process = map_get(evidence, :process) |> ensure_map()
    [map_get(process, :parent_name), map_get(raw_event, :parent_name), map_get(raw_event, :parent_process_name)]
  end

  defp alert_quality_values("file.path", evidence, raw_event) do
    file = map_get(evidence, :file) |> ensure_map()
    [map_get(file, :path), map_get(raw_event, :path), map_get(raw_event, :file_path), map_get(raw_event, :target_path)]
  end

  defp alert_quality_values("network.remote_ip", evidence, raw_event) do
    network = first_map(List.wrap(map_get(evidence, :network)) ++ [raw_event])
    [map_get(network, :remote_ip), map_get(network, :dst_ip), map_get(network, :resolved_ip)]
  end

  defp alert_quality_values("network.remote_port", evidence, raw_event) do
    network = first_map(List.wrap(map_get(evidence, :network)) ++ [raw_event])
    [map_get(network, :remote_port), map_get(network, :dst_port)]
  end

  defp alert_quality_values("network.protocol", evidence, raw_event) do
    network = first_map(List.wrap(map_get(evidence, :network)) ++ [raw_event])
    [map_get(network, :protocol)]
  end

  defp alert_quality_values("registry.key", evidence, raw_event) do
    registry = first_map(List.wrap(map_get(evidence, :registry)) ++ [raw_event])
    [map_get(registry, :key), map_get(registry, :key_path), map_get(registry, :registry_key)]
  end

  defp alert_quality_values(_field, _evidence, _raw_event), do: []

  defp present_value?(value) when value in [nil, "", []], do: false
  defp present_value?(value) when is_binary(value), do: String.trim(value) != ""
  defp present_value?(_), do: true

  defp alert_quality_score([], _present), do: 100

  defp alert_quality_score(required, present) do
    total = length(required)
    Float.round(length(present) / total * 100, 1)
  end

  defp alert_quality_level(score) when score >= 90, do: "excellent"
  defp alert_quality_level(score) when score >= 70, do: "good"
  defp alert_quality_level(score) when score >= 40, do: "partial"
  defp alert_quality_level(_score), do: "poor"

  # ===========================================================================
  # Alert Deduplication
  # ===========================================================================

  @doc """
  Compute a dedup key for an alert from its attributes.

  The key is a hash of {rule_id, agent_id, primary_entity} where primary_entity
  is the process name, file path, or network entity that triggered the alert.
  """
  def compute_dedup_key(attrs) do
    rule_id = extract_rule_id(attrs)
    agent_id = to_string(attrs[:agent_id] || attrs["agent_id"] || "")
    primary_entity = extract_primary_entity(attrs)

    key_material = "#{rule_id}:#{agent_id}:#{primary_entity}"
    :crypto.hash(:sha256, key_material) |> Base.encode16(case: :lower) |> binary_part(0, 40)
  end

  # Extract the detection rule identifier from alert attributes.
  defp extract_rule_id(attrs) do
    detection_meta = attrs[:detection_metadata] || attrs["detection_metadata"] || %{}

    rule_name = detection_meta[:rule_name] || detection_meta["rule_name"]
    rule_type = detection_meta[:rule_type] || detection_meta["rule_type"]

    cond do
      rule_name && rule_name != "" -> "#{rule_type}:#{rule_name}"
      true -> to_string(attrs[:title] || attrs["title"] || "unknown")
    end
  end

  # Extract the primary entity (process, file, or network) that triggered the alert.
  defp extract_primary_entity(attrs) do
    evidence = attrs[:evidence] || attrs["evidence"] || %{}
    file = evidence[:file] || evidence["file"] || %{}
    process = evidence[:process] || evidence["process"] || %{}
    raw_event = attrs[:raw_event] || attrs["raw_event"] || %{}

    # Try process name first, then file path, then network entity
    process_name = process[:name] || process["name"]
    process_path = process[:path] || process["path"]
    file_path = file[:path] || file["path"]
    remote_ip = raw_event[:remote_ip] || raw_event["remote_ip"]
    query = raw_event[:query] || raw_event["query"]

    cond do
      file_path && file_path != "" -> file_path
      process_name && process_name != "" -> process_name
      process_path && process_path != "" -> process_path
      remote_ip && remote_ip != "" -> remote_ip
      query && query != "" -> query
      true -> ""
    end
  end

  @doc """
  Find an existing duplicate alert within the dedup time window.

  Looks for a non-resolved alert with the same dedup_key that was
  created within the configurable dedup window (default 5 minutes).
  """
  def find_duplicate(nil), do: :not_found
  def find_duplicate(""), do: :not_found

  def find_duplicate(dedup_key) do
    window_seconds = dedup_window_seconds()
    cutoff = NaiveDateTime.utc_now() |> NaiveDateTime.add(-window_seconds, :second)

    query = from(a in Alert,
      where: a.dedup_key == ^dedup_key,
      where: a.inserted_at >= ^cutoff,
      where: a.status not in ["resolved", "false_positive"],
      order_by: [desc: a.inserted_at],
      limit: 1
    )

    case Repo.one(query) do
      nil -> :not_found
      alert -> {:ok, alert}
    end
  end

  @doc """
  Increment the occurrence count and update last_seen_at on an existing
  duplicate alert. Returns the updated alert.
  """
  def increment_duplicate(%Alert{} = alert) do
    now = DateTime.utc_now()

    alert
    |> Alert.changeset(%{
      occurrence_count: (alert.occurrence_count || 1) + 1,
      last_seen_at: now
    })
    |> Repo.update()
  end

  # Get the configurable dedup window in seconds. Defaults to 5 minutes.
  defp dedup_window_seconds do
    Application.get_env(:tamandua_server, :alert_dedup_window_seconds, @default_dedup_window_seconds)
  end

  @doc """
  Updates an alert.
  """
  def update_alert(%Alert{} = alert, attrs) do
    result =
      alert
      |> Alert.changeset(attrs)
      |> Repo.update()

    maybe_record_precision_outcome(result, attrs)
    result
  end

  defp maybe_record_precision_outcome({:ok, %Alert{} = alert}, attrs) do
    outcome =
      Map.get(attrs, :verdict) || Map.get(attrs, "verdict") ||
        Map.get(attrs, :status) || Map.get(attrs, "status")

    if outcome in ["true_positive", "false_positive", "benign", "suspicious", :true_positive, :false_positive, :benign, :suspicious] do
      safe_precision_record(fn -> PrecisionMetrics.record_alert_outcome(alert, outcome) end)
    end
  end

  defp maybe_record_precision_outcome(_result, _attrs), do: :ok

  defp safe_precision_record(fun) do
    try do
      fun.()
    rescue
      _ -> :ok
    catch
      :exit, _ -> :ok
    end
  end

  @doc """
  Deletes an alert.
  """
  def delete_alert(%Alert{} = alert) do
    Repo.delete(alert)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking alert changes.
  """
  def change_alert(%Alert{} = alert, attrs \\ %{}) do
    Alert.changeset(alert, attrs)
  end

  @doc """
  Counts active alerts.
  """
  def count_active_alerts do
    from(a in Alert, where: a.status in ^@active_alert_statuses)
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Counts open alerts (same as active).
  """
  def count_open, do: count_active_alerts()

  @doc """
  Counts alerts by severity.
  """
  def count_by_severity(severity) when is_atom(severity) do
    count_by_severity(Atom.to_string(severity))
  end

  def count_by_severity(severity) when is_binary(severity) do
    from(a in Alert,
      where: a.severity == ^severity and a.status in ^@active_alert_statuses
    )
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Counts alerts by status.
  """
  def count_by_status(status) when is_atom(status) do
    count_by_status(Atom.to_string(status))
  end

  def count_by_status(status) when is_binary(status) do
    from(a in Alert,
      where: a.status == ^status
    )
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Lists alerts within a date range.
  """
  def list_alerts_in_range(date_from, date_to) when is_binary(date_from) and is_binary(date_to) do
    from_date = parse_date(date_from)
    to_date = parse_date(date_to)

    query = from(a in Alert,
      order_by: [desc: a.inserted_at],
      preload: [:assigned_to]
    )

    query =
      if from_date do
        from_naive = NaiveDateTime.new!(from_date, ~T[00:00:00])
        where(query, [a], a.inserted_at >= ^from_naive)
      else
        query
      end

    query =
      if to_date do
        # Add 1 day to include the entire end date
        to_naive = NaiveDateTime.new!(Date.add(to_date, 1), ~T[00:00:00])
        where(query, [a], a.inserted_at < ^to_naive)
      else
        query
      end

    Repo.all(query)
  end

  defp parse_date(date_string) when is_binary(date_string) do
    case Date.from_iso8601(date_string) do
      {:ok, date} -> date
      _ -> nil
    end
  end

  defp parse_date(_), do: nil

  @doc """
  Lists recent alerts.
  """
  def list_recent(opts \\ []) do
    limit = Keyword.get(opts, :limit, 10)

    from(a in Alert,
      order_by: [desc: a.inserted_at],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Lists all alerts.
  """
  def list_all do
    from(a in Alert, order_by: [desc: a.inserted_at])
    |> Repo.all()
  end

  @doc """
  Get alert trend over time range.
  Returns daily counts.
  """
  def get_trend(time_range) do
    days = case time_range do
      "7d" -> 7
      "30d" -> 30
      "90d" -> 90
      _ -> 7
    end

    start_date = Date.utc_today() |> Date.add(-days)

    from(a in Alert,
      where: fragment("?::date", a.inserted_at) >= ^start_date,
      group_by: fragment("?::date", a.inserted_at),
      select: {fragment("?::date", a.inserted_at), count(a.id)},
      order_by: [asc: fragment("?::date", a.inserted_at)]
    )
    |> Repo.all()
    |> Enum.map(fn {date, count} -> %{date: Date.to_iso8601(date), count: count} end)
  end

  @doc """
  Gets a single alert, returning {:ok, alert} or {:error, :not_found}.
  """
  def get_alert(id) do
    case Repo.get(Alert, id) do
      nil -> {:error, :not_found}
      alert -> {:ok, alert}
    end
  end

  @doc """
  Gets related alerts for a given alert.
  Finds alerts from the same agent within a time window, or with overlapping MITRE techniques.
  """
  def get_related_alerts(alert_id) do
    case get_alert(alert_id) do
      {:ok, alert} ->
        time_window_minutes = 60

        query = from(a in Alert,
          where: a.id != ^alert_id,
          order_by: [desc: a.inserted_at],
          limit: 10
        )

        # Filter by same agent or overlapping MITRE techniques
        query = if alert.agent_id do
          from(a in query,
            where: a.agent_id == ^alert.agent_id
          )
        else
          query
        end

        Repo.all(query)

      {:error, _} ->
        []
    end
  end

  @doc """
  Gets an alert with full evidence details.

  Returns the alert with all evidence fields populated, along with
  preloaded associations (agent, organization, assigned_to).

  ## Parameters

  - `id` - The alert ID

  ## Returns

  - `{:ok, alert}` with preloaded associations and evidence
  - `{:error, :not_found}` if alert doesn't exist

  ## Examples

      iex> get_alert_with_evidence("550e8400-e29b-41d4-a716-446655440000")
      {:ok, %Alert{evidence: %{file_hashes: [...], ...}, process_chain: [...], ...}}
  """
  def get_alert_with_evidence(id) do
    query = from(a in Alert,
      where: a.id == ^id,
      preload: [:agent, :organization, :assigned_to]
    )

    case Repo.one(query) do
      nil -> {:error, :not_found}
      alert -> {:ok, alert}
    end
  end

  @doc """
  Gets an alert with evidence, scoped to a specific organization.

  This is the tenant-safe version that ensures multi-tenant isolation.

  ## Examples

      iex> get_alert_with_evidence_for_org(org_id, alert_id)
      {:ok, %Alert{evidence: %{...}, ...}}

      iex> get_alert_with_evidence_for_org(wrong_org_id, alert_id)
      {:error, :not_found}
  """
  def get_alert_with_evidence_for_org(organization_id, id) do
    query = from(a in Alert,
      where: a.id == ^id and a.organization_id == ^organization_id,
      preload: [:agent, :organization, :assigned_to]
    )

    case Repo.one(query) do
      nil -> {:error, :not_found}
      alert -> {:ok, alert}
    end
  end

  @doc """
  Updates an alert's process chain.

  This is typically called after building the process ancestry tree
  from the Correlator module.

  ## Parameters

  - `alert` - The alert struct or alert ID
  - `process_chain` - List of process maps representing the ancestry chain

  ## Examples

      iex> update_process_chain(alert, [%{pid: 1, name: "init"}, %{pid: 1234, name: "malware.exe"}])
      {:ok, %Alert{process_chain: [...]}}
  """
  def update_process_chain(%Alert{} = alert, process_chain) when is_list(process_chain) do
    update_alert(alert, %{process_chain: process_chain})
  end

  def update_process_chain(alert_id, process_chain) when is_binary(alert_id) and is_list(process_chain) do
    case get_alert(alert_id) do
      {:ok, alert} -> update_process_chain(alert, process_chain)
      error -> error
    end
  end

  @doc """
  Adds contributing events to a correlation alert.

  ## Parameters

  - `alert` - The alert struct or alert ID
  - `event_ids` - List of event IDs to add as contributing events
  """
  def add_contributing_events(%Alert{} = alert, event_ids) when is_list(event_ids) do
    existing = alert.contributing_events || []
    new_events = Enum.uniq(existing ++ event_ids)
    update_alert(alert, %{contributing_events: new_events})
  end

  def add_contributing_events(alert_id, event_ids) when is_binary(alert_id) and is_list(event_ids) do
    case get_alert(alert_id) do
      {:ok, alert} -> add_contributing_events(alert, event_ids)
      error -> error
    end
  end

  @doc """
  Search alerts by evidence field values.

  Searches the JSONB evidence field for matching values. Useful for
  threat hunting and correlation.

  ## Parameters

  - `field_path` - The JSON path to search (e.g., "process.sha256", "network.value")
  - `value` - The value to search for
  - `opts` - Additional options (limit, organization_id)

  ## Examples

      iex> search_by_evidence("process.sha256", "abc123...")
      [%Alert{...}, ...]

      iex> search_by_evidence("network.value", "192.168.1.1", limit: 50)
      [%Alert{...}, ...]
  """
  def search_by_evidence(field_path, value, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    organization_id = Keyword.get(opts, :organization_id)

    # Parse the field path for nested JSON queries
    path_parts = String.split(field_path, ".")

    query = from(a in Alert,
      order_by: [desc: a.inserted_at],
      limit: ^limit
    )

    # Add organization filter if provided
    query = if organization_id do
      from(a in query, where: a.organization_id == ^organization_id)
    else
      query
    end

    # Build the JSON path query
    query = case path_parts do
      [top_level] ->
        from(a in query,
          where: fragment("?->? @> ?", a.evidence, ^top_level, ^Jason.encode!(value))
        )

      [top_level, nested] ->
        from(a in query,
          where: fragment("?->?->>? = ?", a.evidence, ^top_level, ^nested, ^to_string(value))
        )

      _ ->
        # For deeper paths, use a more general approach
        json_path = Enum.join(path_parts, ",")
        from(a in query,
          where: fragment("?#>>? = ?", a.evidence, ^"{#{json_path}}", ^to_string(value))
        )
    end

    Repo.all(query)
  end

  # ===========================================================================
  # Bulk Operations
  # ===========================================================================

  @doc """
  Updates multiple alerts at once.

  ## Parameters

  - `alert_ids` - List of alert IDs to update
  - `attrs` - Attributes to apply to all alerts
  - `opts` - Options (organization_id for tenant scoping)

  ## Examples

      iex> bulk_update(["id1", "id2"], %{status: "resolved"})
      {:ok, 2}
  """
  def bulk_update(alert_ids, attrs, opts \\ []) when is_list(alert_ids) do
    organization_id = Keyword.get(opts, :organization_id)

    query = from(a in Alert, where: a.id in ^alert_ids)

    query = if organization_id do
      from(a in query, where: a.organization_id == ^organization_id)
    else
      query
    end

    # Normalize attributes
    attrs = normalize_alert_attrs(attrs)
    precision_alerts =
      if Map.get(attrs, :status) == "false_positive" do
        Repo.all(query)
      else
        []
      end

    # Build update list dynamically
    updates = Enum.filter([
      if(Map.has_key?(attrs, :status), do: {:status, attrs.status}),
      if(Map.has_key?(attrs, :assigned_to_id), do: {:assigned_to_id, attrs.assigned_to_id}),
      if(Map.has_key?(attrs, :resolution_notes), do: {:resolution_notes, attrs.resolution_notes}),
      if(Map.has_key?(attrs, :severity), do: {:severity, attrs.severity})
    ], & &1)

    if updates == [] do
      {:ok, 0}
    else
      updates = updates ++ [updated_at: NaiveDateTime.utc_now()]

      {count, _} = Repo.update_all(query, set: updates)

      Enum.each(precision_alerts, fn alert ->
        safe_precision_record(fn -> PrecisionMetrics.record_alert_outcome(alert, "false_positive") end)
      end)

      {:ok, count}
    end
  end

  @doc """
  Bulk updates alert status.
  """
  def bulk_update_status(alert_ids, new_status, opts \\ []) do
    valid_statuses = ["open", "new", "investigating", "resolved", "false_positive"]

    if new_status in valid_statuses do
      bulk_update(alert_ids, %{status: new_status}, opts)
    else
      {:error, :invalid_status}
    end
  end

  @doc """
  Bulk assigns alerts to a user.
  """
  def bulk_assign(alert_ids, user_id, opts \\ []) do
    attrs = %{assigned_to_id: user_id}

    # Set status to investigating if assigning
    attrs = if user_id, do: Map.put(attrs, :status, "investigating"), else: attrs

    bulk_update(alert_ids, attrs, opts)
  end

  @doc """
  Bulk resolves alerts.
  """
  def bulk_resolve(alert_ids, resolution_notes \\ nil, opts \\ []) do
    attrs = %{status: "resolved"}
    attrs = if resolution_notes, do: Map.put(attrs, :resolution_notes, resolution_notes), else: attrs

    bulk_update(alert_ids, attrs, opts)
  end

  @doc """
  Bulk marks alerts as false positive.
  """
  def bulk_false_positive(alert_ids, notes \\ nil, opts \\ []) do
    attrs = %{status: "false_positive"}
    attrs = if notes, do: Map.put(attrs, :resolution_notes, notes), else: attrs

    bulk_update(alert_ids, attrs, opts)
  end

  @doc """
  Gets alerts by a list of IDs.
  """
  def get_alerts_by_ids(alert_ids, opts \\ []) when is_list(alert_ids) do
    organization_id = Keyword.get(opts, :organization_id)

    query = from(a in Alert, where: a.id in ^alert_ids)

    query = if organization_id do
      from(a in query, where: a.organization_id == ^organization_id)
    else
      query
    end

    Repo.all(query)
  end

  @doc """
  Bulk deletes alerts with audit logging.
  """
  def bulk_delete(alert_ids, user, opts \\ []) when is_list(alert_ids) do
    organization_id = Keyword.get(opts, :organization_id)

    # Get alerts for audit logging before deletion
    alerts = get_alerts_by_ids(alert_ids, organization_id: organization_id)

    query = from(a in Alert, where: a.id in ^alert_ids)

    query = if organization_id do
      from(a in query, where: a.organization_id == ^organization_id)
    else
      query
    end

    {count, _} = Repo.delete_all(query)

    # Audit log the bulk deletion
    if count > 0 do
      TamanduaServer.AuditLog.log(%{
        user_id: user && user.id,
        user_email: user && user.email,
        action: "bulk_delete_alerts",
        action_type: "alert_management",
        resource_type: "alert",
        severity: :high,
        details: %{
          alert_count: count,
          alert_ids: alert_ids,
          alert_summaries: Enum.map(alerts, fn a -> %{id: a.id, title: a.title, severity: a.severity} end)
        },
        ip_address: opts[:ip_address],
        user_agent: opts[:user_agent],
        organization_id: organization_id || (user && user.organization_id)
      })

      # Broadcast update
      broadcast_bulk_operation(:deleted, alert_ids, organization_id)
    end

    {:ok, count}
  end

  @doc """
  Bulk adds tags to alerts.
  """
  def bulk_add_tags(alert_ids, tags, user, opts \\ []) when is_list(alert_ids) and is_list(tags) do
    organization_id = Keyword.get(opts, :organization_id)

    # Use Ecto.Multi for transactional operations
    alias Ecto.Multi

    multi =
      alert_ids
      |> Enum.with_index()
      |> Enum.reduce(Multi.new(), fn {alert_id, index}, multi ->
        Multi.run(multi, {:update_tags, index}, fn repo, _changes ->
          case repo.get(Alert, alert_id) do
            nil ->
              {:ok, nil}
            alert ->
              if organization_id && alert.organization_id != organization_id do
                {:ok, nil}
              else
                existing_tags = Map.get(alert.enrichment, "tags", [])
                new_tags = Enum.uniq(existing_tags ++ tags)
                enrichment = Map.put(alert.enrichment, "tags", new_tags)

                alert
                |> Alert.changeset(%{enrichment: enrichment})
                |> repo.update()
              end
          end
        end)
      end)

    case Repo.transaction(multi) do
      {:ok, results} ->
        updated_count = results
          |> Map.values()
          |> Enum.count(fn
            {:ok, %Alert{}} -> true
            _ -> false
          end)

        # Audit log
        if updated_count > 0 do
          TamanduaServer.AuditLog.log(%{
            user_id: user && user.id,
            user_email: user && user.email,
            action: "bulk_add_tags",
            action_type: "alert_management",
            resource_type: "alert",
            severity: :info,
            details: %{
              alert_count: updated_count,
              alert_ids: alert_ids,
              tags_added: tags
            },
            ip_address: opts[:ip_address],
            user_agent: opts[:user_agent],
            organization_id: organization_id || (user && user.organization_id)
          })

          broadcast_bulk_operation(:updated, alert_ids, organization_id)
        end

        {:ok, updated_count}

      {:error, _operation, reason, _changes} ->
        {:error, reason}
    end
  end

  @doc """
  Bulk removes tags from alerts.
  """
  def bulk_remove_tags(alert_ids, tags, user, opts \\ []) when is_list(alert_ids) and is_list(tags) do
    organization_id = Keyword.get(opts, :organization_id)

    alias Ecto.Multi

    multi =
      alert_ids
      |> Enum.with_index()
      |> Enum.reduce(Multi.new(), fn {alert_id, index}, multi ->
        Multi.run(multi, {:update_tags, index}, fn repo, _changes ->
          case repo.get(Alert, alert_id) do
            nil ->
              {:ok, nil}
            alert ->
              if organization_id && alert.organization_id != organization_id do
                {:ok, nil}
              else
                existing_tags = Map.get(alert.enrichment, "tags", [])
                new_tags = existing_tags -- tags
                enrichment = Map.put(alert.enrichment, "tags", new_tags)

                alert
                |> Alert.changeset(%{enrichment: enrichment})
                |> repo.update()
              end
          end
        end)
      end)

    case Repo.transaction(multi) do
      {:ok, results} ->
        updated_count = results
          |> Map.values()
          |> Enum.count(fn
            {:ok, %Alert{}} -> true
            _ -> false
          end)

        # Audit log
        if updated_count > 0 do
          TamanduaServer.AuditLog.log(%{
            user_id: user && user.id,
            user_email: user && user.email,
            action: "bulk_remove_tags",
            action_type: "alert_management",
            resource_type: "alert",
            severity: :info,
            details: %{
              alert_count: updated_count,
              alert_ids: alert_ids,
              tags_removed: tags
            },
            ip_address: opts[:ip_address],
            user_agent: opts[:user_agent],
            organization_id: organization_id || (user && user.organization_id)
          })

          broadcast_bulk_operation(:updated, alert_ids, organization_id)
        end

        {:ok, updated_count}

      {:error, _operation, reason, _changes} ->
        {:error, reason}
    end
  end

  @doc """
  Performs a transactional bulk update operation with audit logging.
  Returns {:ok, updated_count, failed_ids} or {:error, reason}.
  """
  def bulk_update_transactional(alert_ids, attrs, user, opts \\ []) when is_list(alert_ids) do
    organization_id = Keyword.get(opts, :organization_id)

    alias Ecto.Multi

    # Normalize attributes
    attrs = normalize_alert_attrs(attrs)

    # Build multi transaction
    multi =
      alert_ids
      |> Enum.with_index()
      |> Enum.reduce(Multi.new(), fn {alert_id, index}, multi ->
        Multi.run(multi, {:update, index}, fn repo, _changes ->
          case repo.get(Alert, alert_id) do
            nil ->
              {:ok, {:skipped, alert_id}}
            alert ->
              if organization_id && alert.organization_id != organization_id do
                {:ok, {:skipped, alert_id}}
              else
                case repo.update(Alert.changeset(alert, attrs)) do
                  {:ok, updated} -> {:ok, {:updated, updated}}
                  {:error, changeset} -> {:ok, {:failed, alert_id, changeset}}
                end
              end
          end
        end)
      end)

    case Repo.transaction(multi) do
      {:ok, results} ->
        updated = results
          |> Map.values()
          |> Enum.filter(fn
            {:ok, {:updated, _}} -> true
            _ -> false
          end)
          |> length()

        failed = results
          |> Map.values()
          |> Enum.filter(fn
            {:ok, {:failed, _, _}} -> true
            _ -> false
          end)
          |> Enum.map(fn {:ok, {:failed, id, _}} -> id end)

        # Audit log successful updates
        if updated > 0 do
          TamanduaServer.AuditLog.log(%{
            user_id: user && user.id,
            user_email: user && user.email,
            action: "bulk_update_alerts",
            action_type: "alert_management",
            resource_type: "alert",
            severity: :info,
            details: %{
              alert_count: updated,
              alert_ids: alert_ids -- failed,
              failed_ids: failed,
              updates: Map.take(attrs, [:status, :assigned_to_id, :severity])
            },
            ip_address: opts[:ip_address],
            user_agent: opts[:user_agent],
            organization_id: organization_id || (user && user.organization_id)
          })

          broadcast_bulk_operation(:updated, alert_ids -- failed, organization_id)
        end

        {:ok, updated, failed}

      {:error, _operation, reason, _changes} ->
        {:error, reason}
    end
  end

  # Broadcast bulk operation updates via PubSub
  defp broadcast_bulk_operation(action, alert_ids, organization_id) do
    topic = if organization_id do
      "alerts:org:#{organization_id}"
    else
      "alerts:global"
    end

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      topic,
      {:bulk_operation, action, alert_ids}
    )
  end

  # ===========================================================================
  # Advanced Filtering
  # ===========================================================================

  @doc """
  Searches alerts with advanced filtering options.

  ## Parameters

  - `filters` - Map of filter criteria:
    - `:search` - Text search in title/description
    - `:severity` - Severity level(s)
    - `:status` - Status value(s)
    - `:agent_id` - Agent ID(s)
    - `:assigned_to_id` - Assigned user ID
    - `:mitre_techniques` - MITRE technique IDs
    - `:mitre_tactics` - MITRE tactic names
    - `:date_from` - Start date (ISO8601)
    - `:date_to` - End date (ISO8601)
    - `:threat_score_min` - Minimum threat score
    - `:threat_score_max` - Maximum threat score
    - `:has_evidence` - Boolean, filter for alerts with evidence
    - `:tags` - List of tags (if implemented)
  - `opts` - Options for pagination and sorting

  ## Examples

      iex> search_alerts(%{severity: ["critical", "high"], status: "open"})
      [%Alert{}, ...]
  """
  def search_alerts(filters, opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)
    sort_by = Keyword.get(opts, :sort_by, :inserted_at)
    sort_order = Keyword.get(opts, :sort_order, :desc)

    query = from(a in Alert, order_by: [{^sort_order, ^sort_by}])

    query = if organization_id do
      from(a in query, where: a.organization_id == ^organization_id)
    else
      query
    end

    # Apply filters
    query = apply_search_filters(query, filters)

    # Apply pagination
    query = from(a in query, limit: ^limit, offset: ^offset)

    Repo.all(query)
  end

  @doc """
  Counts alerts matching the given filters.
  """
  def count_search_results(filters, opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)

    query = from(a in Alert)

    query = if organization_id do
      from(a in query, where: a.organization_id == ^organization_id)
    else
      query
    end

    query = apply_search_filters(query, filters)

    Repo.aggregate(query, :count, :id)
  end

  defp apply_search_filters(query, filters) when is_map(filters) do
    query
    |> filter_by_search(filters[:search] || filters["search"])
    |> filter_by_severity(filters[:severity] || filters["severity"])
    |> filter_by_status(filters[:status] || filters["status"])
    |> filter_by_agent_id(filters[:agent_id] || filters["agent_id"])
    |> filter_by_assigned_to(filters[:assigned_to_id] || filters["assigned_to_id"])
    |> filter_by_mitre_techniques(filters[:mitre_techniques] || filters["mitre_techniques"])
    |> filter_by_mitre_tactics(filters[:mitre_tactics] || filters["mitre_tactics"])
    |> filter_by_date_range(
      filters[:date_from] || filters["date_from"],
      filters[:date_to] || filters["date_to"]
    )
    |> filter_by_threat_score(
      filters[:threat_score_min] || filters["threat_score_min"],
      filters[:threat_score_max] || filters["threat_score_max"]
    )
    |> filter_by_has_evidence(filters[:has_evidence] || filters["has_evidence"])
    # ETW tampering specific filters
    |> filter_by_mitre_technique(filters[:mitre_technique] || filters["mitre_technique"])
    |> filter_by_patch_pattern(filters[:patch_pattern] || filters["patch_pattern"])
    |> filter_by_target_function(filters[:target_function] || filters["target_function"])
    |> filter_by_verdict(filters[:verdict] || filters["verdict"])
  end

  defp filter_by_search(query, nil), do: query
  defp filter_by_search(query, ""), do: query
  defp filter_by_search(query, search) when is_binary(search) do
    search_term = "%#{search}%"
    from(a in query,
      where: ilike(a.title, ^search_term) or ilike(a.description, ^search_term)
    )
  end

  defp filter_by_severity(query, nil), do: query
  defp filter_by_severity(query, severity) when is_list(severity) do
    from(a in query, where: a.severity in ^severity)
  end
  defp filter_by_severity(query, severity) when is_binary(severity) do
    from(a in query, where: a.severity == ^severity)
  end

  defp filter_by_status(query, nil), do: query
  defp filter_by_status(query, status) when is_list(status) do
    from(a in query, where: a.status in ^status)
  end
  defp filter_by_status(query, status) when is_binary(status) do
    from(a in query, where: a.status == ^status)
  end

  defp filter_by_verdict(query, nil), do: query
  defp filter_by_verdict(query, ""), do: query
  defp filter_by_verdict(query, verdict) when is_list(verdict) do
    from(a in query, where: a.verdict in ^verdict)
  end
  defp filter_by_verdict(query, verdict) when is_binary(verdict) do
    from(a in query, where: a.verdict == ^verdict)
  end

  defp filter_by_agent_id(query, nil), do: query
  defp filter_by_agent_id(query, agent_ids) when is_list(agent_ids) do
    from(a in query, where: a.agent_id in ^agent_ids)
  end
  defp filter_by_agent_id(query, agent_id) when is_binary(agent_id) do
    from(a in query, where: a.agent_id == ^agent_id)
  end

  defp filter_by_assigned_to(query, nil), do: query
  defp filter_by_assigned_to(query, "unassigned") do
    from(a in query, where: is_nil(a.assigned_to_id))
  end
  defp filter_by_assigned_to(query, user_id) when is_binary(user_id) do
    from(a in query, where: a.assigned_to_id == ^user_id)
  end

  defp filter_by_mitre_techniques(query, nil), do: query
  defp filter_by_mitre_techniques(query, []), do: query
  defp filter_by_mitre_techniques(query, techniques) when is_list(techniques) do
    from(a in query, where: fragment("? && ?", a.mitre_techniques, ^techniques))
  end

  defp filter_by_mitre_tactics(query, nil), do: query
  defp filter_by_mitre_tactics(query, []), do: query
  defp filter_by_mitre_tactics(query, tactics) when is_list(tactics) do
    from(a in query, where: fragment("? && ?", a.mitre_tactics, ^tactics))
  end

  defp filter_by_date_range(query, nil, nil), do: query
  defp filter_by_date_range(query, from_date, to_date) do
    query = if from_date do
      case parse_date(from_date) do
        nil -> query
        date ->
          from_naive = NaiveDateTime.new!(date, ~T[00:00:00])
          from(a in query, where: a.inserted_at >= ^from_naive)
      end
    else
      query
    end

    if to_date do
      case parse_date(to_date) do
        nil -> query
        date ->
          to_naive = NaiveDateTime.new!(Date.add(date, 1), ~T[00:00:00])
          from(a in query, where: a.inserted_at < ^to_naive)
      end
    else
      query
    end
  end

  defp filter_by_threat_score(query, nil, nil), do: query
  defp filter_by_threat_score(query, min, max) do
    query = if min do
      min_val = if is_binary(min), do: String.to_float(min), else: min
      from(a in query, where: a.threat_score >= ^min_val)
    else
      query
    end

    if max do
      max_val = if is_binary(max), do: String.to_float(max), else: max
      from(a in query, where: a.threat_score <= ^max_val)
    else
      query
    end
  end

  defp filter_by_has_evidence(query, nil), do: query
  defp filter_by_has_evidence(query, true) do
    from(a in query, where: a.evidence != ^%{})
  end
  defp filter_by_has_evidence(query, false) do
    from(a in query, where: a.evidence == ^%{} or is_nil(a.evidence))
  end
  defp filter_by_has_evidence(query, "true"), do: filter_by_has_evidence(query, true)
  defp filter_by_has_evidence(query, "false"), do: filter_by_has_evidence(query, false)

  # ETW tampering specific filters
  defp filter_by_mitre_technique(query, nil), do: query
  defp filter_by_mitre_technique(query, ""), do: query
  defp filter_by_mitre_technique(query, technique) when is_binary(technique) do
    from(a in query, where: ^technique in a.mitre_techniques)
  end

  defp filter_by_patch_pattern(query, nil), do: query
  defp filter_by_patch_pattern(query, ""), do: query
  defp filter_by_patch_pattern(query, pattern) when is_binary(pattern) do
    from(a in query, where: a.patch_pattern == ^pattern)
  end

  defp filter_by_target_function(query, nil), do: query
  defp filter_by_target_function(query, ""), do: query
  defp filter_by_target_function(query, function) when is_binary(function) do
    search_term = "%#{function}%"
    from(a in query, where: ilike(a.target_function, ^search_term))
  end

  # ===========================================================================
  # Alert Statistics & Analytics
  # ===========================================================================

  @doc """
  Gets comprehensive statistics about alerts.
  """
  def get_alert_stats(opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)
    time_range = Keyword.get(opts, :time_range, "7d")

    days = case time_range do
      "24h" -> 1
      "7d" -> 7
      "30d" -> 30
      "90d" -> 90
      _ -> 7
    end

    start_date = NaiveDateTime.utc_now() |> NaiveDateTime.add(-days * 24 * 60 * 60, :second)

    base_query = from(a in Alert, where: a.inserted_at >= ^start_date)

    base_query = if organization_id do
      from(a in base_query, where: a.organization_id == ^organization_id)
    else
      base_query
    end

    total = Repo.aggregate(base_query, :count, :id)

    by_severity =
      from(a in base_query,
        group_by: a.severity,
        select: {a.severity, count(a.id)}
      )
      |> Repo.all()
      |> Map.new()

    by_status =
      from(a in base_query,
        group_by: a.status,
        select: {a.status, count(a.id)}
      )
      |> Repo.all()
      |> Map.new()

    # Mean time to acknowledge (status change from open to investigating)
    avg_threat_score =
      from(a in base_query,
        where: not is_nil(a.threat_score),
        select: avg(a.threat_score)
      )
      |> Repo.one()

    %{
      total: total,
      by_severity: by_severity,
      by_status: by_status,
      average_threat_score: avg_threat_score && Float.round(avg_threat_score, 2),
      time_range: time_range,
      start_date: NaiveDateTime.to_iso8601(start_date)
    }
  end

  @doc """
  Gets historical occurrence count for similar alerts.

  This helps analysts understand if an alert pattern has been seen before.
  """
  def get_historical_count(alert, opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id) || alert.organization_id
    days_back = Keyword.get(opts, :days_back, 30)

    start_date = NaiveDateTime.utc_now() |> NaiveDateTime.add(-days_back * 24 * 60 * 60, :second)

    # Match by detection rule name if available
    rule_name = get_in(alert.detection_metadata || %{}, [:rule_name]) ||
                get_in(alert.detection_metadata || %{}, ["rule_name"])

    query = from(a in Alert,
      where: a.inserted_at >= ^start_date,
      where: a.id != ^alert.id
    )

    query = if organization_id do
      from(a in query, where: a.organization_id == ^organization_id)
    else
      query
    end

    # Match by rule name or title
    query = if rule_name do
      from(a in query,
        where: fragment("?->'rule_name' = ?", a.detection_metadata, ^rule_name) or
               a.title == ^alert.title
      )
    else
      from(a in query, where: a.title == ^alert.title)
    end

    count = Repo.aggregate(query, :count, :id)

    # Get recent occurrences
    recent = from(a in query, limit: 5, order_by: [desc: a.inserted_at])
             |> Repo.all()

    %{
      count: count,
      days_back: days_back,
      recent_occurrences: Enum.map(recent, fn a ->
        %{id: a.id, created_at: a.inserted_at, agent_id: a.agent_id, status: a.status}
      end)
    }
  end

  # ===========================================================================
  # Dashboard Widget Endpoints
  # ===========================================================================

  @doc """
  Returns an alert summary for the ThreatSummary dashboard widget.

  Provides severity distribution, computed threat level, active threat score,
  top active threats, and recommendations.

  ## Options
  - `:organization_id` - Scope to a specific organization
  - `:range` - Time range: "24h", "7d", "30d" (default "7d")
  """
  def get_alert_summary(opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)
    range = Keyword.get(opts, :range, "7d")

    days = range_to_days(range)
    now = NaiveDateTime.utc_now()
    start_date = NaiveDateTime.add(now, -days * 86_400, :second)

    base_query = from(a in Alert, where: a.inserted_at >= ^start_date)
    base_query = scope_org(base_query, organization_id)

    # Severity distribution (open/active only)
    active_query = from(a in base_query, where: a.status not in ["resolved", "false_positive"])

    severity_counts =
      from(a in active_query,
        group_by: a.severity,
        select: {a.severity, count(a.id)}
      )
      |> Repo.all()
      |> Map.new()

    total_active = Enum.sum(Map.values(severity_counts))
    critical = Map.get(severity_counts, "critical", 0)
    high = Map.get(severity_counts, "high", 0)
    medium = Map.get(severity_counts, "medium", 0)
    low = Map.get(severity_counts, "low", 0)

    # Active threat score: weighted severity score normalized to 0-100
    active_threat_score = compute_threat_score(critical, high, medium, low, total_active)

    # Threat level based on score
    threat_level = cond do
      active_threat_score >= 75 -> "critical"
      active_threat_score >= 50 -> "elevated"
      active_threat_score >= 25 -> "moderate"
      true -> "low"
    end

    # Total alerts in period (including resolved)
    total_in_period = Repo.aggregate(base_query, :count, :id)

    # Count resolved/blocked alerts in period
    blocked_count = from(a in base_query,
      where: a.status in ["resolved", "false_positive"]
    ) |> Repo.aggregate(:count, :id)

    # Average threat score
    avg_score = from(a in base_query,
      where: not is_nil(a.threat_score),
      select: avg(a.threat_score)
    ) |> Repo.one()

    # Top active threats: most recent critical/high alerts
    top_threats =
      from(a in active_query,
        where: a.severity in ["critical", "high"],
        order_by: [desc: a.inserted_at],
        limit: 5
      )
      |> Repo.all()
      |> Enum.map(fn a ->
        %{
          id: a.id,
          title: a.title,
          severity: a.severity,
          type: List.first(a.mitre_tactics || []) || "unknown",
          affectedAssets: 1,
          firstSeen: naive_to_unix_ms(a.inserted_at),
          mitreTechnique: List.first(a.mitre_techniques || [])
        }
      end)

    # Build recommendations
    recommendations = build_recommendations(critical, high, total_active, blocked_count)

    # Metric trends (compare current vs previous period)
    prev_start = NaiveDateTime.add(start_date, -days * 86_400, :second)
    prev_query = from(a in Alert, where: a.inserted_at >= ^prev_start and a.inserted_at < ^start_date)
    prev_query = scope_org(prev_query, organization_id)

    prev_active = from(a in prev_query, where: a.status not in ["resolved", "false_positive"])
                  |> Repo.aggregate(:count, :id)
    prev_total = Repo.aggregate(prev_query, :count, :id)
    prev_blocked = from(a in prev_query, where: a.status in ["resolved", "false_positive"])
                   |> Repo.aggregate(:count, :id)

    %{
      threatLevel: threat_level,
      threatScore: active_threat_score,
      metrics: %{
        activeThreats: build_metric("Active Threats", total_active, prev_active),
        blockedAttacks: build_metric("Blocked Attacks", blocked_count, prev_blocked),
        compromisedAssets: %{
          label: "Compromised Assets",
          value: count_compromised_assets(active_query),
          trend: "stable",
          format: "number"
        },
        meanTimeToDetect: %{
          label: "Mean Time to Detect",
          value: 0,
          trend: "stable",
          format: "duration"
        },
        meanTimeToRespond: %{
          label: "Mean Time to Respond",
          value: 0,
          trend: "stable",
          format: "duration"
        }
      },
      topThreats: top_threats,
      recommendations: recommendations,
      lastUpdated: System.system_time(:millisecond)
    }
  end

  @doc """
  Returns alert trend data for the DetectionTrend dashboard widget.

  Provides time-series data points with severity breakdowns, category distributions,
  overall trend direction, and peak-hour analysis.

  ## Options
  - `:organization_id` - Scope to a specific organization
  - `:period` - Time period: "24h", "7d", "30d" (default "7d")
  """
  def get_alert_trend(opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)
    period = Keyword.get(opts, :period, "7d")

    days = range_to_days(period)
    now = NaiveDateTime.utc_now()
    start_date = NaiveDateTime.add(now, -days * 86_400, :second)
    prev_start = NaiveDateTime.add(start_date, -days * 86_400, :second)

    base_query = from(a in Alert, where: a.inserted_at >= ^start_date)
    base_query = scope_org(base_query, organization_id)

    # Generate data points: hourly for 24h, daily for 7d/30d
    data_points = if period == "24h" do
      build_hourly_data_points(base_query, start_date, now)
    else
      build_daily_data_points(base_query, start_date, now)
    end

    # Total detections in current period
    total = Repo.aggregate(base_query, :count, :id)

    # Total in previous period for trend
    prev_query = from(a in Alert, where: a.inserted_at >= ^prev_start and a.inserted_at < ^start_date)
    prev_query = scope_org(prev_query, organization_id)
    prev_total = Repo.aggregate(prev_query, :count, :id)

    # Trend direction and percentage
    {trend_dir, change_pct} = compute_trend(total, prev_total)

    # Category breakdown
    categories = build_category_breakdown(base_query, prev_query)

    # Average per day and peak hour
    avg_per_day = if days > 0, do: Float.round(total / days, 1), else: 0.0

    peak_hour = from(a in base_query,
      group_by: fragment("extract(hour from ?)", a.inserted_at),
      select: {fragment("extract(hour from ?)", a.inserted_at), count(a.id)},
      order_by: [desc: count(a.id)],
      limit: 1
    )
    |> Repo.one()
    |> case do
      {hour, _count} -> trunc(hour)
      nil -> 0
    end

    %{
      dataPoints: data_points,
      totalDetections: total,
      change: change_pct,
      trend: trend_dir,
      categories: categories,
      averagePerDay: avg_per_day,
      peakHour: peak_hour,
      lastUpdated: System.system_time(:millisecond)
    }
  end

  @doc """
  Returns top threat actors/attackers for the TopAttackers dashboard widget.

  Extracts attacker information from alert data including MITRE techniques,
  enrichment data, and threat intel attributions.

  ## Options
  - `:organization_id` - Scope to a specific organization
  - `:range` - Time range: "24h", "7d", "30d" (default "7d")
  """
  def get_top_attackers(opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)
    range = Keyword.get(opts, :range, "7d")

    days = range_to_days(range)
    now = NaiveDateTime.utc_now()
    start_date = NaiveDateTime.add(now, -days * 86_400, :second)

    base_query = from(a in Alert, where: a.inserted_at >= ^start_date)
    base_query = scope_org(base_query, organization_id)

    # Count unique source agents (as proxy for unique sources)
    unique_sources = from(a in base_query,
      where: not is_nil(a.agent_id),
      select: count(a.agent_id, :distinct)
    ) |> Repo.one() || 0

    # Total attacks
    total_attacks = Repo.aggregate(base_query, :count, :id)

    # Build attacker profiles from alert MITRE techniques and enrichment data
    # Group alerts by top MITRE tactics to derive "attacker groups"
    tactic_groups =
      from(a in base_query,
        where: fragment("array_length(?, 1) > 0", a.mitre_tactics),
        select: %{
          tactics: a.mitre_tactics,
          techniques: a.mitre_techniques,
          severity: a.severity,
          inserted_at: a.inserted_at,
          enrichment: a.enrichment,
          threat_score: a.threat_score
        }
      )
      |> Repo.all()

    # Build attacker profiles from grouped alert data
    attackers = build_attacker_profiles(tactic_groups, start_date, now)

    # Top country and tactic
    top_country = attackers
    |> Enum.filter(& &1.country)
    |> Enum.group_by(& &1.country)
    |> Enum.max_by(fn {_k, v} -> length(v) end, fn -> {"Unknown", []} end)
    |> elem(0)

    top_tactic = attackers
    |> Enum.flat_map(& &1.tactics)
    |> Enum.frequencies()
    |> Enum.max_by(fn {_k, v} -> v end, fn -> {"none", 0} end)
    |> elem(0)

    %{
      attackers: attackers,
      totalAttacks: total_attacks,
      uniqueSources: unique_sources,
      topCountry: top_country,
      topTactic: top_tactic,
      lastUpdated: System.system_time(:millisecond)
    }
  end

  # ---------------------------------------------------------------------------
  # Private helpers for dashboard widget queries
  # ---------------------------------------------------------------------------

  defp range_to_days("24h"), do: 1
  defp range_to_days("7d"), do: 7
  defp range_to_days("30d"), do: 30
  defp range_to_days("90d"), do: 90
  defp range_to_days(_), do: 7

  defp scope_org(query, nil), do: from(a in query, where: false)
  defp scope_org(query, organization_id) do
    from(a in query, where: a.organization_id == ^organization_id)
  end

  defp maybe_filter_time_range(query, "all"), do: query
  defp maybe_filter_time_range(query, nil), do: query

  defp maybe_filter_time_range(query, time_range) do
    days =
      case time_range do
        "7d" -> 7
        "30d" -> 30
        "90d" -> 90
        _ -> nil
      end

    if days do
      start_date = Date.utc_today() |> Date.add(-days)
      where(query, [a], fragment("?::date", a.inserted_at) >= ^start_date)
    else
      query
    end
  end

  defp normalize_severity_key(severity) when is_atom(severity), do: severity

  defp normalize_severity_key(severity) when is_binary(severity) do
    case severity do
      "critical" -> :critical
      "high" -> :high
      "medium" -> :medium
      "low" -> :low
      _ -> :low
    end
  end

  defp normalize_severity_key(_), do: :low

  defp naive_to_unix_ms(%NaiveDateTime{} = ndt) do
    ndt
    |> DateTime.from_naive!("Etc/UTC")
    |> DateTime.to_unix(:millisecond)
  end
  defp naive_to_unix_ms(_), do: 0

  defp compute_threat_score(critical, high, medium, low, total) do
    if total == 0 do
      0.0
    else
      # Weighted score: critical=4, high=3, medium=2, low=1
      raw = critical * 4 + high * 3 + medium * 2 + low * 1
      max_possible = total * 4
      Float.round(raw / max_possible * 100, 1)
    end
  end

  defp build_metric(label, current, previous) do
    {trend_dir, change} = compute_trend(current, previous)

    %{
      label: label,
      value: current,
      previousValue: previous,
      trend: trend_dir,
      trendPercent: abs(change),
      format: "number"
    }
  end

  defp compute_trend(current, previous) when previous == 0 and current == 0, do: {"stable", 0.0}
  defp compute_trend(current, 0), do: {if(current > 0, do: "up", else: "stable"), 100.0}
  defp compute_trend(current, previous) do
    pct = Float.round((current - previous) / previous * 100, 1)
    dir = cond do
      pct > 5 -> "up"
      pct < -5 -> "down"
      true -> "stable"
    end
    {dir, pct}
  end

  defp count_compromised_assets(active_query) do
    from(a in active_query,
      where: a.severity in ["critical", "high"],
      where: not is_nil(a.agent_id),
      select: count(a.agent_id, :distinct)
    )
    |> Repo.one() || 0
  end

  defp build_recommendations(critical, high, total_active, _blocked) do
    recommendations = []

    recommendations = if critical > 0 do
      ["Investigate #{critical} critical alert(s) immediately" | recommendations]
    else
      recommendations
    end

    recommendations = if high > 5 do
      ["Review high-severity alert volume -- consider tuning detection rules" | recommendations]
    else
      recommendations
    end

    recommendations = if total_active > 50 do
      ["Alert backlog is high (#{total_active}) -- prioritize triage" | recommendations]
    else
      recommendations
    end

    recommendations = if total_active == 0 do
      ["No active threats detected -- all clear" | recommendations]
    else
      recommendations
    end

    Enum.reverse(recommendations)
  end

  defp build_hourly_data_points(base_query, start_date, _now) do
    from(a in base_query,
      group_by: fragment("date_trunc('hour', ?)", a.inserted_at),
      select: %{
        bucket: fragment("date_trunc('hour', ?)", a.inserted_at),
        total: count(a.id),
        critical: fragment("count(*) filter (where ? = 'critical')", a.severity),
        high: fragment("count(*) filter (where ? = 'high')", a.severity),
        medium: fragment("count(*) filter (where ? = 'medium')", a.severity),
        low: fragment("count(*) filter (where ? = 'low')", a.severity)
      },
      order_by: [asc: fragment("date_trunc('hour', ?)", a.inserted_at)]
    )
    |> Repo.all()
    |> Enum.map(fn row ->
      %{
        timestamp: naive_to_unix_ms(row.bucket),
        total: row.total,
        critical: row.critical,
        high: row.high,
        medium: row.medium,
        low: row.low
      }
    end)
  end

  defp build_daily_data_points(base_query, _start_date, _now) do
    from(a in base_query,
      group_by: fragment("date_trunc('day', ?)", a.inserted_at),
      select: %{
        bucket: fragment("date_trunc('day', ?)", a.inserted_at),
        total: count(a.id),
        critical: fragment("count(*) filter (where ? = 'critical')", a.severity),
        high: fragment("count(*) filter (where ? = 'high')", a.severity),
        medium: fragment("count(*) filter (where ? = 'medium')", a.severity),
        low: fragment("count(*) filter (where ? = 'low')", a.severity)
      },
      order_by: [asc: fragment("date_trunc('day', ?)", a.inserted_at)]
    )
    |> Repo.all()
    |> Enum.map(fn row ->
      %{
        timestamp: naive_to_unix_ms(row.bucket),
        total: row.total,
        critical: row.critical,
        high: row.high,
        medium: row.medium,
        low: row.low
      }
    end)
  end

  defp build_category_breakdown(current_query, prev_query) do
    # Current period tactic counts
    current_tactics = from(a in current_query,
      where: fragment("array_length(?, 1) > 0", a.mitre_tactics),
      select: a.mitre_tactics
    )
    |> Repo.all()
    |> List.flatten()
    |> Enum.frequencies()

    # Previous period tactic counts
    prev_tactics = from(a in prev_query,
      where: fragment("array_length(?, 1) > 0", a.mitre_tactics),
      select: a.mitre_tactics
    )
    |> Repo.all()
    |> List.flatten()
    |> Enum.frequencies()

    category_colors = %{
      "initial-access" => "#ef4444",
      "execution" => "#f97316",
      "persistence" => "#eab308",
      "privilege-escalation" => "#84cc16",
      "defense-evasion" => "#22c55e",
      "credential-access" => "#14b8a6",
      "discovery" => "#06b6d4",
      "lateral-movement" => "#3b82f6",
      "collection" => "#6366f1",
      "exfiltration" => "#a855f7",
      "command-and-control" => "#ec4899",
      "impact" => "#f43f5e"
    }

    current_tactics
    |> Enum.sort_by(fn {_tactic, count} -> -count end)
    |> Enum.take(6)
    |> Enum.map(fn {tactic, count} ->
      prev_count = Map.get(prev_tactics, tactic, 0)
      {trend_dir, change} = compute_trend(count, prev_count)

      %{
        name: tactic,
        count: count,
        change: change,
        trend: trend_dir,
        color: Map.get(category_colors, String.downcase(tactic), "#64748b")
      }
    end)
  end

  # Known APT group mappings from MITRE tactics/techniques
  @known_actor_groups %{
    "T1566" => %{name: "Phishing Campaign", type: "criminal", country: "Unknown"},
    "T1566.001" => %{name: "Spear-Phishing Group", type: "criminal", country: "Unknown"},
    "T1059" => %{name: "Script-Based Attacker", type: "criminal", country: "Unknown"},
    "T1059.001" => %{name: "PowerShell Operator", type: "criminal", country: "Unknown"},
    "T1059.005" => %{name: "VBA Macro Attacker", type: "criminal", country: "Unknown"},
    "T1055" => %{name: "Process Injection Actor", type: "nation_state", country: "Unknown"},
    "T1071" => %{name: "C2 Communication Group", type: "nation_state", country: "Unknown"},
    "T1486" => %{name: "Ransomware Operator", type: "criminal", country: "Unknown"},
    "T1027" => %{name: "Obfuscation Actor", type: "criminal", country: "Unknown"},
    "T1105" => %{name: "Remote Tool Transfer", type: "nation_state", country: "Unknown"},
    "T1003" => %{name: "Credential Dumper", type: "criminal", country: "Unknown"},
    "T1021" => %{name: "Lateral Mover", type: "nation_state", country: "Unknown"},
    "T1547" => %{name: "Persistence Actor", type: "criminal", country: "Unknown"},
    "T1048" => %{name: "Exfiltration Group", type: "nation_state", country: "Unknown"},
    "T1190" => %{name: "Exploit-Based Attacker", type: "nation_state", country: "Unknown"},
    "T1078" => %{name: "Valid Accounts Abuser", type: "insider", country: "Internal"}
  }

  defp build_attacker_profiles(tactic_groups, start_date, now) do
    # Group alerts by their primary MITRE technique to create "attacker" clusters
    technique_clusters = tactic_groups
    |> Enum.flat_map(fn alert_data ->
      primary_technique = List.first(alert_data.techniques || [])
      if primary_technique do
        [{primary_technique, alert_data}]
      else
        []
      end
    end)
    |> Enum.group_by(fn {technique, _} -> technique end, fn {_, data} -> data end)

    technique_clusters
    |> Enum.sort_by(fn {_technique, alerts} -> -length(alerts) end)
    |> Enum.take(10)
    |> Enum.with_index()
    |> Enum.map(fn {{technique, alerts}, idx} ->
      actor_info = Map.get(@known_actor_groups, technique, %{
        name: "Threat Group #{technique}",
        type: "unknown",
        country: nil
      })

      # Extract enrichment data for country info
      country = alerts
      |> Enum.find_value(fn a ->
        enrichment = a.enrichment || %{}
        enrichment["source_country"] || enrichment["country"] || enrichment[:country]
      end) || actor_info[:country]

      all_tactics = alerts |> Enum.flat_map(& &1.tactics) |> Enum.uniq()
      all_techniques = alerts |> Enum.flat_map(& &1.techniques) |> Enum.uniq()
      severities = alerts |> Enum.map(& &1.severity)

      # Determine worst severity
      worst_severity = cond do
        "critical" in severities -> "critical"
        "high" in severities -> "high"
        "medium" in severities -> "medium"
        true -> "low"
      end

      timestamps = alerts |> Enum.map(& &1.inserted_at) |> Enum.sort(NaiveDateTime)
      first_seen = List.first(timestamps)
      last_seen = List.last(timestamps)

      avg_score = alerts
      |> Enum.map(& &1.threat_score)
      |> Enum.reject(&is_nil/1)
      |> case do
        [] -> 50
        scores -> trunc(Enum.sum(scores) / length(scores))
      end

      %{
        id: "attacker-#{idx + 1}-#{technique}",
        name: actor_info[:name],
        type: actor_info[:type],
        country: country,
        countryCode: nil,
        attackCount: length(alerts),
        targetedAssets: alerts |> Enum.count(fn a -> a != nil end),
        severity: worst_severity,
        firstSeen: naive_to_unix_ms(first_seen),
        lastSeen: naive_to_unix_ms(last_seen),
        tactics: all_tactics,
        techniques: all_techniques,
        confidence: min(avg_score, 100),
        trend: "stable",
        change: 0,
        blocked: 0,
        iocCount: 0
      }
    end)
  end

  # ===========================================================================
  # Analyst Verdict / Feedback Loop
  # ===========================================================================

  @valid_verdicts ~w(unconfirmed true_positive false_positive benign suspicious)

  @doc """
  Set the analyst verdict on an alert.

  When the verdict is `false_positive` or `benign`:
  - Optionally creates a suppression rule to auto-suppress similar future alerts
  - Records the FP pattern in the baseline to strengthen normal behavior scoring

  When the verdict is `true_positive`:
  - Boosts the detection rule's confidence in the baseline

  ## Options
  - `:notes` - Analyst notes explaining the verdict
  - `:create_suppression_rule` - If true, create a suppression rule (FP/benign only)
  - `:suppression_ttl_days` - TTL for the suppression rule (default 30)
  - `:suppression_action` - "suppress" or "reduce_severity" (default "suppress")

  ## Returns
  - `{:ok, %{alert: alert, suppression_rule: rule | nil, feedback_log: log}}`
  - `{:error, reason}`
  """
  @spec set_verdict(String.t(), String.t(), String.t() | nil, keyword()) ::
    {:ok, map()} | {:error, term()}
  def set_verdict(alert_id, verdict, user_id, opts \\ []) do
    if verdict not in @valid_verdicts do
      {:error, :invalid_verdict}
    else
      case get_alert(alert_id) do
        {:ok, alert} ->
          do_set_verdict(alert, verdict, user_id, opts)
        {:error, _} = error ->
          error
      end
    end
  end

  defp do_set_verdict(alert, verdict, user_id, opts) do
    notes = Keyword.get(opts, :notes)
    create_suppression = Keyword.get(opts, :create_suppression_rule, false)
    now = DateTime.utc_now()

    previous_verdict = alert.verdict || "unconfirmed"

    # Update the alert verdict
    verdict_attrs = %{
      verdict: verdict,
      verdict_by_id: user_id,
      verdict_at: now,
      verdict_notes: notes
    }

    # Also update status if appropriate
    verdict_attrs = case verdict do
      "false_positive" -> Map.put(verdict_attrs, :status, "false_positive")
      "true_positive" -> Map.put(verdict_attrs, :status, "investigating")
      "benign" -> Map.put(verdict_attrs, :status, "resolved")
      _ -> verdict_attrs
    end

    result = Repo.transaction(fn ->
      # 1. Update the alert
      {:ok, updated_alert} = update_alert(alert, verdict_attrs)

      # 2. Create feedback audit log
      {:ok, feedback_log} = create_feedback_log(%{
        alert_id: alert.id,
        user_id: user_id,
        previous_verdict: previous_verdict,
        new_verdict: verdict,
        notes: notes,
        metadata: %{
          "agent_id" => alert.agent_id,
          "title" => alert.title,
          "severity" => alert.severity,
          "threat_score" => alert.threat_score
        }
      })

      # 3. Handle FP/benign: create suppression rule and update baseline
      suppression_rule = if verdict in ["false_positive", "benign"] do
        # Update baseline to record false positive pattern
        update_baseline_for_fp(alert)

        # Optionally create a suppression rule
        if create_suppression do
          ttl_days = Keyword.get(opts, :suppression_ttl_days, 30)
          action = Keyword.get(opts, :suppression_action, "suppress")

          case Suppression.create_rule_from_alert(alert, [
            user_id: user_id,
            ttl_days: ttl_days,
            action: action
          ]) do
            {:ok, rule} ->
              # Link the rule to the alert
              update_alert(updated_alert, %{suppression_rule_id: rule.id})

              # Update feedback log
              Repo.update_all(
                from(l in VerdictFeedbackLog, where: l.id == ^feedback_log.id),
                set: [suppression_rule_created: true]
              )

              rule

            {:error, reason} ->
              require Logger
              Logger.warning("Failed to create suppression rule for alert #{alert.id}: #{inspect(reason)}")
              nil
          end
        else
          nil
        end
      else
        nil
      end

      # 4. Handle TP: boost detection confidence in baseline
      if verdict == "true_positive" do
        update_baseline_for_tp(alert)
      end

      %{
        alert: Repo.get!(Alert, alert.id),
        suppression_rule: suppression_rule,
        feedback_log: feedback_log
      }
    end)

    # Broadcast post-commit so the analyst dashboard FP Review card
    # and any subscribed alert-detail views refresh immediately.
    # Mirrors the topic/event shape used by `webhook_receiver.ex`
    # (`broadcast_alert_update/1`).
    case result do
      {:ok, %{alert: updated_alert}} ->
        broadcast_verdict_update(updated_alert)
        result

      _ ->
        result
    end
  end

  defp broadcast_verdict_update(alert) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alerts:#{alert.organization_id}",
      {:alert_updated, alert}
    )

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alert:#{alert.id}",
      {:alert_updated, alert}
    )

    :ok
  end

  @doc """
  Bulk set verdict on multiple alerts.

  ## Parameters
  - `alert_ids` - List of alert IDs
  - `verdict` - The verdict to apply
  - `user_id` - The user setting the verdict
  - `opts` - Options (see `set_verdict/4`)

  ## Returns
  - `{:ok, %{updated: count, errors: count, suppression_rules_created: count}}`
  """
  @spec bulk_set_verdict([String.t()], String.t(), String.t() | nil, keyword()) ::
    {:ok, map()}
  def bulk_set_verdict(alert_ids, verdict, user_id, opts \\ []) do
    if verdict not in @valid_verdicts do
      {:error, :invalid_verdict}
    else
      results = Enum.map(alert_ids, fn alert_id ->
        case set_verdict(alert_id, verdict, user_id, opts) do
          {:ok, result} -> {:ok, result}
          {:error, reason} -> {:error, alert_id, reason}
        end
      end)

      updated = Enum.count(results, &match?({:ok, _}, &1))
      errors = Enum.count(results, &match?({:error, _, _}, &1))
      rules_created = results
      |> Enum.filter(&match?({:ok, _}, &1))
      |> Enum.count(fn {:ok, r} -> r.suppression_rule != nil end)

      {:ok, %{
        updated: updated,
        errors: errors,
        suppression_rules_created: rules_created
      }}
    end
  end

  @doc """
  Get all suppression rules for an agent.
  Returns active, non-expired rules that match the given agent.
  """
  @spec get_suppression_rules(String.t() | nil) :: [SuppressionRule.t()]
  def get_suppression_rules(agent_id) do
    now = DateTime.utc_now()
    dumped_agent_id = dump_uuid(agent_id)

    query = from(r in SuppressionRule,
      where: r.enabled == true,
      where: is_nil(r.expires_at) or r.expires_at > ^now,
      order_by: [desc: r.inserted_at]
    )

    query = if dumped_agent_id do
      from(r in query,
        where: is_nil(r.agent_id) or r.agent_id == ^dumped_agent_id
      )
    else
      query
    end

    Repo.all(query)
  end

  @doc """
  Check if an alert should be suppressed based on existing FP patterns.

  This is called from the Detection Engine before creating an alert.

  Returns:
  - `:allow` - Alert should be created normally
  - `{:suppress, reason}` - Alert should be suppressed
  - `{:reduce_severity, new_severity, reason}` - Severity should be reduced
  - `{:auto_suppress, count, reason}` - Auto-suppressed by occurrence count
  """
  @spec should_suppress?(map(), String.t() | nil) ::
    :allow | {:suppress, String.t()} | {:reduce_severity, String.t(), String.t()} | {:auto_suppress, integer(), String.t()}
  def should_suppress?(alert_data, agent_id) do
    Suppression.check_suppression(alert_data, agent_id)
  rescue
    e ->
      Logger.warning("[Alerts] Suppression precheck failed, allowing alert: #{Exception.message(e)}")
      :allow
  catch
    :exit, reason ->
      Logger.warning("[Alerts] Suppression precheck exited, allowing alert: #{inspect(reason)}")
      :allow
  end

  defp dump_uuid(nil), do: nil
  defp dump_uuid(<<_::128>> = uuid), do: uuid

  defp dump_uuid(uuid) when is_binary(uuid) do
    case Ecto.UUID.dump(uuid) do
      {:ok, dumped} -> dumped
      :error -> nil
    end
  end

  defp dump_uuid(_), do: nil

  @doc """
  Get verdict statistics for analytics.
  """
  @spec get_verdict_stats(keyword()) :: map()
  def get_verdict_stats(opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)
    days = Keyword.get(opts, :days, 30)

    start_date = NaiveDateTime.utc_now() |> NaiveDateTime.add(-days * 24 * 60 * 60, :second)

    base_query = from(a in Alert, where: a.inserted_at >= ^start_date)

    base_query = if organization_id do
      from(a in base_query, where: a.organization_id == ^organization_id)
    else
      base_query
    end

    # Count by verdict
    by_verdict = from(a in base_query,
      group_by: a.verdict,
      select: {a.verdict, count(a.id)}
    )
    |> Repo.all()
    |> Map.new()

    total = Repo.aggregate(base_query, :count, :id)
    fp_count = Map.get(by_verdict, "false_positive", 0)
    tp_count = Map.get(by_verdict, "true_positive", 0)

    # FP rate
    reviewed = fp_count + tp_count + Map.get(by_verdict, "benign", 0)
    fp_rate = if reviewed > 0, do: Float.round(fp_count / reviewed * 100, 1), else: 0.0

    # Get top FP rules (rules that generate the most FPs)
    top_fp_rules = from(a in base_query,
      where: a.verdict == "false_positive",
      where: not is_nil(a.detection_metadata),
      group_by: fragment("?->>'rule_name'", a.detection_metadata),
      select: {fragment("?->>'rule_name'", a.detection_metadata), count(a.id)},
      order_by: [desc: count(a.id)],
      limit: 10
    )
    |> Repo.all()
    |> Enum.map(fn {rule, count} -> %{rule_name: rule, fp_count: count} end)

    # Active suppression rules count
    now = DateTime.utc_now()
    active_suppression_rules = Repo.aggregate(
      from(r in SuppressionRule,
        where: r.enabled == true,
        where: is_nil(r.expires_at) or r.expires_at > ^now
      ),
      :count, :id
    )

    # Total alerts suppressed (from match_count)
    total_suppressed = Repo.one(
      from(r in SuppressionRule, select: coalesce(sum(r.match_count), 0))
    ) || 0

    %{
      total_alerts: total,
      by_verdict: by_verdict,
      false_positive_rate: fp_rate,
      reviewed_count: reviewed,
      unreviewed_count: Map.get(by_verdict, "unconfirmed", 0),
      top_fp_rules: top_fp_rules,
      active_suppression_rules: active_suppression_rules,
      total_suppressed: total_suppressed,
      days: days
    }
  end

  @doc """
  Get feedback log entries for an alert.
  """
  @spec get_feedback_log(String.t()) :: [VerdictFeedbackLog.t()]
  def get_feedback_log(alert_id) do
    from(l in VerdictFeedbackLog,
      where: l.alert_id == ^alert_id,
      order_by: [desc: l.inserted_at],
      preload: [:user]
    )
    |> Repo.all()
  end

  # ===========================================================================
  # Suppression Rule CRUD
  # ===========================================================================

  @doc """
  List all suppression rules.
  """
  def list_suppression_rules(opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)
    enabled_only = Keyword.get(opts, :enabled_only, false)

    query = from(r in SuppressionRule, order_by: [desc: r.inserted_at])

    query = if organization_id do
      from(r in query, where: r.organization_id == ^organization_id)
    else
      query
    end

    query = if enabled_only do
      now = DateTime.utc_now()
      from(r in query,
        where: r.enabled == true,
        where: is_nil(r.expires_at) or r.expires_at > ^now
      )
    else
      query
    end

    Repo.all(query)
  end

  @doc """
  Get a single suppression rule.
  """
  def get_suppression_rule(id) do
    case Repo.get(SuppressionRule, id) do
      nil -> {:error, :not_found}
      rule -> {:ok, rule}
    end
  end

  @doc """
  Gets a suppression rule scoped to an organization.
  """
  def get_suppression_rule_for_org(organization_id, rule_id) do
    case TenantScope.get_scoped(SuppressionRule, organization_id, rule_id) do
      nil -> {:error, :not_found}
      rule -> {:ok, rule}
    end
  end

  @doc """
  Create a suppression rule manually.
  """
  def create_suppression_rule(attrs) do
    result = struct(SuppressionRule)
    |> SuppressionRule.changeset(attrs)
    |> Repo.insert()

    case result do
      {:ok, _rule} -> Suppression.refresh_cache()
      _ -> :ok
    end

    result
  end

  @doc """
  Update a suppression rule.
  """
  def update_suppression_rule(rule, attrs) when is_map(rule) do
    result = rule
    |> SuppressionRule.changeset(attrs)
    |> Repo.update()

    case result do
      {:ok, _rule} -> Suppression.refresh_cache()
      _ -> :ok
    end

    result
  end

  @doc """
  Delete a suppression rule.
  """
  def delete_suppression_rule(rule) when is_map(rule) do
    result = Repo.delete(rule)

    case result do
      {:ok, _} -> Suppression.refresh_cache()
      _ -> :ok
    end

    result
  end

  @doc """
  Toggle a suppression rule's enabled status.
  """
  def toggle_suppression_rule(rule) when is_map(rule) do
    update_suppression_rule(rule, %{enabled: !rule.enabled})
  end

  # ===========================================================================
  # Baseline Integration (Private)
  # ===========================================================================

  # Record a false positive in the baseline to strengthen normal behavior.
  # This makes the baseline consider this pattern as more normal, reducing
  # future threat scores for similar events.
  defp update_baseline_for_fp(alert) do
    agent_id = alert.agent_id

    if agent_id do
      try do
        alias TamanduaServer.Detection.Baseline

        # Extract event features from the alert's raw event / evidence
        event_features = extract_event_features_from_alert(alert)

        if event_features != %{} do
          # Boost baseline for this pattern -- makes it appear more normal
          Baseline.record_false_positive(agent_id, event_features)

          require Logger
          Logger.info("Baseline strengthened for FP: agent=#{agent_id}, alert=#{alert.id}")
        end
      rescue
        e ->
          require Logger
          Logger.warning("Failed to update baseline for FP alert #{alert.id}: #{inspect(e)}")
      catch
        :exit, _ -> :ok
      end
    end
  end

  # Record a true positive in the baseline to weaken normal behavior for
  # this pattern. This ensures the baseline does NOT suppress future
  # similar events.
  defp update_baseline_for_tp(alert) do
    agent_id = alert.agent_id

    if agent_id do
      try do
        alias TamanduaServer.Detection.Baseline

        # Extract the feature keys from the alert
        event_features = extract_event_features_from_alert(alert)

        if event_features != %{} do
          # Weaken baseline for this pattern so it is NOT suppressed in the future
          Baseline.record_true_positive(agent_id, event_features)

          require Logger
          Logger.info("Baseline weakened for TP: agent=#{agent_id}, alert=#{alert.id}")
        end
      rescue
        e ->
          require Logger
          Logger.warning("Failed to weaken baseline for TP alert #{alert.id}: #{inspect(e)}")
      catch
        :exit, _ -> :ok
      end
    end
  end

  # Extract event-like features from an alert for baseline recording.
  defp extract_event_features_from_alert(alert) do
    evidence = alert.evidence || %{}
    raw_event = alert.raw_event || %{}
    detection_meta = alert.detection_metadata || %{}

    process = evidence["process"] || evidence[:process] || %{}

    # Reconstruct a minimal event map the baseline can use
    payload = %{}
    |> maybe_put(:name, process["name"] || process[:name])
    |> maybe_put(:parent_name, process["parent_name"] || process[:parent_name])
    |> maybe_put(:path, process["path"] || process[:path])
    |> maybe_put(:pid, process["pid"] || process[:pid])
    |> maybe_put(:remote_ip, raw_event["remote_ip"] || raw_event[:remote_ip])
    |> maybe_put(:remote_port, raw_event["remote_port"] || raw_event[:remote_port])
    |> maybe_put(:query, raw_event["query"] || raw_event[:query])

    # Determine event type from detection metadata or alert title
    event_type = detection_meta["event_type"] || detection_meta[:event_type] || guess_event_type(alert)

    %{
      event_type: event_type,
      payload: payload,
      agent_id: alert.agent_id
    }
  end

  defp guess_event_type(alert) do
    title = String.downcase(alert.title || "")
    cond do
      String.contains?(title, "process") -> "process_create"
      String.contains?(title, "network") -> "network_connect"
      String.contains?(title, "dns") -> "dns_query"
      String.contains?(title, "file") -> "file_create"
      true -> "unknown"
    end
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  # ===========================================================================
  # Cross-Agent Alert Correlation
  # ===========================================================================

  @doc """
  Find related alerts across all agents within a time window.

  ## Options
  - `:time_window_minutes` - Time window in minutes (default: 30)
  - `:threshold` - Minimum similarity threshold (default: 0.7)
  - `:organization_id` - Filter by organization

  ## Examples

      iex> find_related_alerts(alert, time_window_minutes: 60)
      {:ok, [{related_alert1, 0.85}, {related_alert2, 0.72}]}
  """
  def find_related_alerts(alert, opts \\ []) do
    alias TamanduaServer.Alerts.CrossAgentCorrelator
    CrossAgentCorrelator.find_related_alerts(alert, opts)
  end

  @doc """
  Detect attack chains in a set of alerts.

  Returns patterns like lateral_movement, ransomware, exfiltration, etc.

  ## Examples

      iex> detect_attack_chains([alert1, alert2, alert3])
      {:ok, [%{pattern: :lateral_movement, alerts: [...], confidence: 0.9}]}
  """
  def detect_attack_chains(alerts) when is_list(alerts) do
    alias TamanduaServer.Alerts.CrossAgentCorrelator
    CrossAgentCorrelator.detect_attack_chains(alerts)
  end

  @doc """
  Build network graph for a set of alerts or a campaign.

  Returns a graph structure with nodes (agents) and edges (network connections).

  ## Examples

      iex> build_network_graph([alert_id1, alert_id2])
      %{
        "nodes" => [%{"id" => "agent-1", "hostname" => "server1", ...}],
        "edges" => [%{"source" => "agent-1", "target" => "agent-2", ...}]
      }
  """
  def build_network_graph(alert_ids) when is_list(alert_ids) do
    alias TamanduaServer.Alerts.CrossAgentCorrelator
    CrossAgentCorrelator.build_network_graph(alert_ids)
  end

  @doc """
  Get correlations for an alert.

  Returns all alert correlations (relationships) for a given alert.
  """
  def get_alert_correlations(alert_id) do
    alias TamanduaServer.Alerts.AlertCorrelation

    from(c in AlertCorrelation,
      where: c.alert_id == ^alert_id or c.related_alert_id == ^alert_id,
      order_by: [desc: :confidence],
      preload: [:alert, :related_alert]
    )
    |> Repo.all()
  end

  @doc """
  List all attack campaigns.

  ## Options
  - `:organization_id` - Filter by organization
  - `:status` - Filter by status (active, contained, resolved)
  - `:severity` - Filter by severity
  """
  def list_attack_campaigns(opts \\ []) do
    alias TamanduaServer.Alerts.AttackCampaign

    organization_id = Keyword.get(opts, :organization_id)
    status = Keyword.get(opts, :status)
    severity = Keyword.get(opts, :severity)

    query = from c in AttackCampaign,
      order_by: [desc: :last_activity],
      preload: [:alerts, :assigned_to]

    query = if organization_id, do: from(c in query, where: c.organization_id == ^organization_id), else: query
    query = if status, do: from(c in query, where: c.status == ^status), else: query
    query = if severity, do: from(c in query, where: c.severity == ^severity), else: query

    Repo.all(query)
  end

  @doc """
  Get a single attack campaign with full details.
  """
  def get_attack_campaign(campaign_id) do
    alias TamanduaServer.Alerts.AttackCampaign

    case Repo.get(AttackCampaign, campaign_id) do
      nil -> {:error, :not_found}
      campaign ->
        campaign = Repo.preload(campaign, [:alerts, :assigned_to, :created_by, campaign_alerts: [:alert]])
        {:ok, campaign}
    end
  end

  @doc """
  Create an attack campaign manually.
  """
  def create_attack_campaign(attrs) do
    alias TamanduaServer.Alerts.AttackCampaign

    struct(AttackCampaign)
    |> AttackCampaign.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update an attack campaign.
  """
  def update_attack_campaign(campaign, attrs) when is_map(campaign) do
    campaign
    |> TamanduaServer.Alerts.AttackCampaign.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Add an alert to an existing campaign.
  """
  def add_alert_to_campaign(campaign_id, alert_id, opts \\ []) do
    alias TamanduaServer.Alerts.{CampaignAlert, AttackCampaign}

    role = Keyword.get(opts, :role)

    attrs = %{
      campaign_id: campaign_id,
      alert_id: alert_id,
      role: role,
      added_at: DateTime.utc_now()
    }

    Repo.transaction(fn ->
      # Insert campaign_alert
      {:ok, campaign_alert} = struct(CampaignAlert)
      |> CampaignAlert.changeset(attrs)
      |> Repo.insert()

      # Update campaign stats
      Repo.update_all(
        from(c in AttackCampaign, where: c.id == ^campaign_id),
        inc: [alert_count: 1],
        set: [last_activity: DateTime.utc_now()]
      )

      # Update alert with campaign_id
      Repo.update_all(
        from(a in Alert, where: a.id == ^alert_id),
        set: [campaign_id: campaign_id]
      )

      campaign_alert
    end)
  end

  @doc """
  Remove an alert from a campaign.
  """
  def remove_alert_from_campaign(campaign_id, alert_id) do
    alias TamanduaServer.Alerts.{CampaignAlert, AttackCampaign}

    Repo.transaction(fn ->
      # Delete campaign_alert
      from(ca in CampaignAlert,
        where: ca.campaign_id == ^campaign_id and ca.alert_id == ^alert_id
      )
      |> Repo.delete_all()

      # Update campaign stats
      Repo.update_all(
        from(c in AttackCampaign, where: c.id == ^campaign_id),
        inc: [alert_count: -1]
      )

      # Clear alert campaign_id
      Repo.update_all(
        from(a in Alert, where: a.id == ^alert_id),
        set: [campaign_id: nil]
      )
    end)
  end

  @doc """
  Get campaign statistics for an organization.
  """
  def get_campaign_stats(opts \\ []) do
    alias TamanduaServer.Alerts.AttackCampaign

    organization_id = Keyword.get(opts, :organization_id)
    days = Keyword.get(opts, :days, 30)

    start_date = NaiveDateTime.utc_now() |> NaiveDateTime.add(-days * 24 * 60 * 60, :second)

    base_query = from c in AttackCampaign, where: c.inserted_at >= ^start_date

    base_query = if organization_id do
      from c in base_query, where: c.organization_id == ^organization_id
    else
      base_query
    end

    total = Repo.aggregate(base_query, :count, :id)

    by_status = from(c in base_query,
      group_by: c.status,
      select: {c.status, count(c.id)}
    )
    |> Repo.all()
    |> Map.new()

    by_pattern = from(c in base_query,
      where: not is_nil(c.attack_pattern),
      group_by: c.attack_pattern,
      select: {c.attack_pattern, count(c.id)}
    )
    |> Repo.all()
    |> Map.new()

    by_severity = from(c in base_query,
      group_by: c.severity,
      select: {c.severity, count(c.id)}
    )
    |> Repo.all()
    |> Map.new()

    # Average alerts per campaign
    avg_alerts = from(c in base_query,
      select: avg(c.alert_count)
    )
    |> Repo.one()

    # Average agents affected
    avg_agents = from(c in base_query,
      select: avg(c.agent_count)
    )
    |> Repo.one()

    %{
      total_campaigns: total,
      by_status: by_status,
      by_pattern: by_pattern,
      by_severity: by_severity,
      average_alerts_per_campaign: avg_alerts && Float.round(avg_alerts, 1),
      average_agents_affected: avg_agents && Float.round(avg_agents, 1),
      days: days
    }
  end

  # ===========================================================================
  # Feedback Log (Private)
  # ===========================================================================

  defp create_feedback_log(attrs) do
    struct(VerdictFeedbackLog)
    |> VerdictFeedbackLog.changeset(attrs)
    |> Repo.insert()
  end

  # ===========================================================================
  # Async Threat Attribution
  # ===========================================================================

  # Schedule asynchronous threat attribution for high/critical severity alerts.
  # Runs in a background task so alert creation is never blocked.
  # Gracefully handles the Attribution module not being started.
  defp maybe_schedule_attribution(%Alert{severity: severity} = alert)
       when severity in ["high", "critical"] do
    spawn(fn ->
      try do
        # Build a map the Attribution module can work with
        alert_data = %{
          id: alert.id,
          severity: alert.severity,
          title: alert.title,
          mitre_tactics: alert.mitre_tactics || [],
          mitre_techniques: alert.mitre_techniques || [],
          threat_score: alert.threat_score,
          enrichment: alert.enrichment || %{},
          evidence: alert.evidence || %{},
          detection_metadata: alert.detection_metadata || %{},
          agent_id: alert.agent_id
        }

        case TamanduaServer.ThreatIntel.Attribution.attribute_alert(alert_data) do
          {:ok, attributions} when is_list(attributions) and length(attributions) > 0 ->
            top = List.first(attributions)

            actor_names = attributions
            |> Enum.take(3)
            |> Enum.map(fn a -> a[:actor_name] || a[:actor_id] || "unknown" end)

            details = %{
              "attributions" => Enum.take(attributions, 5) |> Enum.map(fn a ->
                %{
                  "actor_name" => a[:actor_name],
                  "actor_id" => a[:actor_id],
                  "confidence" => a[:confidence],
                  "matching_iocs" => a[:matching_iocs] || [],
                  "matching_ttps" => a[:matching_ttps] || [],
                  "matching_malware" => a[:matching_malware] || [],
                  "evidence" => a[:evidence] || []
                }
              end),
              "attributed_at" => DateTime.to_iso8601(DateTime.utc_now())
            }

            update_alert(alert, %{
              attributed_actors: actor_names,
              campaign_id: top[:campaign_id],
              attribution_confidence: top[:confidence],
              attribution_details: details
            })

            # Notify CampaignTracker
            try do
              TamanduaServer.ThreatIntel.CampaignTracker.record_attribution(%{
                alert_id: alert.id,
                actor_names: actor_names,
                confidence: top[:confidence],
                timestamp: DateTime.utc_now()
              })
            rescue
              _ -> :ok
            catch
              :exit, _ -> :ok
            end

          _ ->
            :ok
        end
      rescue
        e ->
          Logger.warning("[Alerts] Async attribution failed for alert #{alert.id}: #{inspect(e)}")
      catch
        :exit, _ ->
          Logger.debug("[Alerts] Attribution service not available, skipping for alert #{alert.id}")
      end
    end)
  end

  defp maybe_schedule_attribution(_alert), do: :ok

  # ===========================================================================
  # Async Cross-Agent Correlation
  # ===========================================================================

  # Schedule asynchronous cross-agent correlation for all alerts.
  # Runs in a background process so alert creation is never blocked.
  defp maybe_schedule_correlation(alert) do
    spawn(fn ->
      try do
        alias TamanduaServer.Alerts.CrossAgentCorrelator
        CrossAgentCorrelator.correlate_alert(alert)
      rescue
        e ->
          Logger.debug("[Alerts] Correlation failed for alert #{alert.id}: #{inspect(e)}")
      catch
        :exit, _ ->
          Logger.debug("[Alerts] Correlator not available for alert #{alert.id}")
      end
    end)
  end

  # ===========================================================================
  # Saved Searches
  # ===========================================================================

  @doc """
  Lists saved searches for a user and organization.

  ## Options
  - `:include_shared` - Include shared searches from the organization (default: true)
  - `:include_templates` - Include search templates (default: true)
  - `:starred_only` - Only return starred searches (default: false)
  - `:category` - Filter by category
  """
  def list_saved_searches(user_id, organization_id, opts \\ []) do
    include_shared = Keyword.get(opts, :include_shared, true)
    include_templates = Keyword.get(opts, :include_templates, true)
    starred_only = Keyword.get(opts, :starred_only, false)
    category = Keyword.get(opts, :category)

    query =
      SavedSearch
      |> where([s], s.organization_id == ^organization_id)
      |> where([s], s.user_id == ^user_id or (s.is_shared == true and ^include_shared))
      |> order_by([s], [desc: s.usage_count, desc: s.updated_at])

    query =
      if starred_only do
        where(query, [s], s.is_starred == true)
      else
        query
      end

    query =
      if category do
        where(query, [s], s.category == ^category)
      else
        query
      end

    query =
      unless include_templates do
        where(query, [s], s.is_template == false)
      else
        query
      end

    Repo.all(query)
  end

  @doc """
  Gets a single saved search.
  """
  def get_saved_search(id) do
    case Repo.get(SavedSearch, id) do
      nil -> {:error, :not_found}
      search -> {:ok, search}
    end
  end

  @doc """
  Gets a saved search scoped to organization.
  """
  def get_saved_search_for_org(organization_id, id) do
    case Repo.get_by(SavedSearch, id: id, organization_id: organization_id) do
      nil -> {:error, :not_found}
      search -> {:ok, search}
    end
  end

  @doc """
  Creates a saved search.
  """
  def create_saved_search(attrs) do
    struct(SavedSearch)
    |> SavedSearch.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a saved search.
  """
  def update_saved_search(search, attrs) when is_map(search) do
    search
    |> SavedSearch.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a saved search.
  """
  def delete_saved_search(search) when is_map(search) do
    Repo.delete(search)
  end

  @doc """
  Stars/unstars a saved search.
  """
  def toggle_star_saved_search(search) when is_map(search) do
    update_saved_search(search, %{is_starred: !search.is_starred})
  end

  @doc """
  Records usage of a saved search.
  """
  def record_search_usage(search) when is_map(search) do
    search
    |> SavedSearch.record_usage_changeset()
    |> Repo.update()
  end

  @doc """
  Creates a new version of a saved search.
  """
  def create_search_version(search, attrs) when is_map(search) do
    search
    |> SavedSearch.create_version_changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Lists versions of a saved search.
  """
  def list_search_versions(search) when is_map(search) do
    parent_id = search.parent_id || search.id

    SavedSearch
    |> where([s], s.parent_id == ^parent_id or s.id == ^parent_id)
    |> order_by([s], desc: s.version)
    |> Repo.all()
  end

  @doc """
  Lists pre-built search templates.
  """
  def list_search_templates(organization_id) do
    SavedSearch
    |> where([s], s.organization_id == ^organization_id and s.is_template == true)
    |> order_by([s], asc: s.name)
    |> Repo.all()
  end

  @doc """
  Creates default search templates for an organization.
  """
  def create_default_templates(organization_id, user_id) do
    templates = [
      %{
        name: "Critical Alerts - Unresolved",
        description: "All critical alerts that haven't been resolved",
        category: "detection",
        is_template: true,
        is_shared: true,
        filter_json: %{
          "logic" => "AND",
          "conditions" => [
            %{"field" => "severity", "operator" => "eq", "value" => "critical"},
            %{"field" => "status", "operator" => "in", "value" => ["new", "investigating"]}
          ]
        },
        organization_id: organization_id,
        user_id: user_id
      },
      %{
        name: "Ransomware Indicators",
        description: "Alerts related to ransomware tactics and techniques",
        category: "threat_hunting",
        is_template: true,
        is_shared: true,
        filter_json: %{
          "logic" => "OR",
          "conditions" => [
            %{"field" => "mitre_technique", "operator" => "array_contains", "value" => "T1486"},
            %{"field" => "mitre_technique", "operator" => "array_contains", "value" => "T1490"},
            %{"field" => "file_path", "operator" => "regex", "value" => "\\.(encrypted|locked|crypt)$"}
          ]
        },
        organization_id: organization_id,
        user_id: user_id
      },
      %{
        name: "Lateral Movement",
        description: "Alerts indicating potential lateral movement",
        category: "threat_hunting",
        is_template: true,
        is_shared: true,
        filter_json: %{
          "logic" => "AND",
          "conditions" => [
            %{
              "field" => "mitre_tactic",
              "operator" => "array_contains",
              "value" => "lateral-movement"
            },
            %{"field" => "threat_score", "operator" => "gte", "value" => 0.7}
          ]
        },
        organization_id: organization_id,
        user_id: user_id
      },
      %{
        name: "High Confidence ML Detections",
        description: "Machine learning detections with high confidence",
        category: "detection",
        is_template: true,
        is_shared: true,
        filter_json: %{
          "logic" => "AND",
          "conditions" => [
            %{"field" => "detection_source", "operator" => "eq", "value" => "ml"},
            %{"field" => "threat_score", "operator" => "gte", "value" => 0.85}
          ]
        },
        organization_id: organization_id,
        user_id: user_id
      },
      %{
        name: "Unassigned Critical Alerts",
        description: "Critical alerts that haven't been assigned to anyone",
        category: "investigation",
        is_template: true,
        is_shared: true,
        filter_json: %{
          "logic" => "AND",
          "conditions" => [
            %{"field" => "severity", "operator" => "in", "value" => ["critical", "high"]},
            %{"field" => "assigned_to_id", "operator" => "is_null", "value" => nil},
            %{"field" => "status", "operator" => "ne", "value" => "resolved"}
          ]
        },
        organization_id: organization_id,
        user_id: user_id
      },
      %{
        name: "False Positive Candidates",
        description: "Alerts that might be false positives based on patterns",
        category: "investigation",
        is_template: true,
        is_shared: true,
        filter_json: %{
          "logic" => "AND",
          "conditions" => [
            %{"field" => "occurrence_count", "operator" => "gte", "value" => 10},
            %{"field" => "threat_score", "operator" => "lt", "value" => 0.5},
            %{"field" => "status", "operator" => "eq", "value" => "new"}
          ]
        },
        organization_id: organization_id,
        user_id: user_id
      },
      %{
        name: "Campaign Alerts",
        description: "Alerts attributed to attack campaigns",
        category: "investigation",
        is_template: true,
        is_shared: true,
        filter_json: %{
          "logic" => "AND",
          "conditions" => [
            %{"field" => "campaign_id", "operator" => "is_not_null", "value" => nil}
          ]
        },
        organization_id: organization_id,
        user_id: user_id
      }
    ]

    Enum.reduce(templates, {:ok, []}, fn template_attrs, {:ok, acc} ->
      case create_saved_search(template_attrs) do
        {:ok, template} -> {:ok, [template | acc]}
        error -> error
      end
    end)
  end

  @doc """
  Lists alerts using a saved search filter.
  """
  def list_alerts_with_saved_search(organization_id, search, opts \\ []) when is_map(search) do
    # Record usage
    record_search_usage(search)

    # Apply the filter
    list_alerts_with_filter(organization_id, search.filter_json, opts)
  end

  @doc """
  Lists alerts using a filter structure.

  ## Options
  - `:current_user_id` - For "my_alerts" quick filter
  - `:limit` - Maximum results
  - `:offset` - Pagination offset
  - `:preload` - Associations to preload
  """
  def list_alerts_with_filter(organization_id, filter, opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)
    offset = Keyword.get(opts, :offset, 0)
    preload = Keyword.get(opts, :preload, [])
    current_user_id = Keyword.get(opts, :current_user_id)

    query =
      Alert
      |> TenantScope.scope_to_tenant(organization_id)
      |> order_by([a], [desc: a.inserted_at])

    # Handle quick filter "my_alerts"
    query =
      if is_map(filter) && Map.get(filter, "quick_filter") == "my_alerts" && current_user_id do
        where(query, [a], a.assigned_to_id == ^current_user_id)
      else
        query
      end

    # Apply the filter
    query = FilterBuilder.build_query(query, filter)

    # Apply pagination
    query =
      query
      |> limit(^limit)
      |> offset(^offset)

    # Preload associations
    query =
      if preload != [] do
        preload(query, ^preload)
      else
        query
      end

    Repo.all(query)
  end

  @doc """
  Counts alerts matching a filter.
  """
  def count_alerts_with_filter(organization_id, filter, opts \\ []) do
    current_user_id = Keyword.get(opts, :current_user_id)

    query =
      Alert
      |> TenantScope.scope_to_tenant(organization_id)

    # Handle quick filter "my_alerts"
    query =
      if is_map(filter) && Map.get(filter, "quick_filter") == "my_alerts" && current_user_id do
        where(query, [a], a.assigned_to_id == ^current_user_id)
      else
        query
      end

    # Apply the filter
    query = FilterBuilder.build_query(query, filter)

    Repo.aggregate(query, :count)
  end

  @doc """
  Validates a filter structure.
  """
  def validate_filter(filter) do
    FilterBuilder.validate_filter(filter)
  end

  @doc """
  Returns supported filter fields and operators.
  """
  def filter_metadata do
    FilterBuilder.supported_fields()
  end
end
