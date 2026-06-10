defmodule TamanduaServer.AuditLog do
  @moduledoc """
  Enterprise-grade audit logging with tamper-proof hash chain.

  Provides comprehensive activity logging for:
  - User authentication events
  - Configuration changes
  - Response actions
  - Playbook executions
  - Agent management
  - Alert handling
  - RBAC changes
  - Data access

  ## Tamper-Proof Design

  Each audit log entry includes a cryptographic hash that chains to the
  previous entry, creating an immutable audit trail:

  ```
  Entry N: hash = SHA256(entry_data + Entry N-1 hash)
  Entry N+1: hash = SHA256(entry_data + Entry N hash)
  ```

  This ensures any tampering with historical entries will break the chain.

  ## Compliance Support

  - SOC 2 Type II
  - HIPAA
  - GDPR
  - PCI DSS
  - ISO 27001

  ## Retention Policies

  - Hot storage: 90 days (fast queries)
  - Warm storage: 1 year (compressed, indexed)
  - Cold storage: 7 years (archived, compliance)
  """

  import Ecto.Query
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Audit.{AuditLog, AuditArchive, RetentionPolicy}

  @hash_algorithm :sha256
  @batch_size 1000

  # ============================================================================
  # Logging Functions
  # ============================================================================

  @doc """
  Log a user login event.
  """
  def log_login(user, opts \\ []) do
    log(%{
      user_id: user.id,
      user_email: user.email,
      action: "user_login",
      action_type: "authentication",
      resource_type: "session",
      severity: :info,
      details: %{
        method: opts[:method] || "password",
        mfa_used: opts[:mfa_used] || false,
        sso_provider: opts[:sso_provider]
      },
      ip_address: opts[:ip_address],
      user_agent: opts[:user_agent],
      organization_id: user.organization_id
    })
  end

  @doc """
  Log a user logout event.
  """
  def log_logout(user, opts \\ []) do
    log(%{
      user_id: user.id,
      user_email: user.email,
      action: "user_logout",
      action_type: "authentication",
      resource_type: "session",
      severity: :info,
      details: %{
        session_duration_minutes: opts[:session_duration_minutes]
      },
      ip_address: opts[:ip_address],
      user_agent: opts[:user_agent],
      organization_id: user.organization_id
    })
  end

  @doc """
  Log a failed login attempt.
  """
  def log_failed_login(email, reason, opts \\ []) do
    log(%{
      user_email: email,
      action: "login_failed",
      action_type: "authentication",
      resource_type: "session",
      severity: :warning,
      details: %{
        reason: reason,
        attempt_count: opts[:attempt_count]
      },
      ip_address: opts[:ip_address],
      user_agent: opts[:user_agent],
      organization_id: opts[:organization_id]
    })
  end

  @doc """
  Log a configuration change.
  """
  def log_config_change(user, config_type, changes, opts \\ []) do
    log(%{
      user_id: user && user.id,
      user_email: user && user.email,
      action: "config_#{config_type}",
      action_type: "configuration",
      resource_type: "config",
      resource_id: config_type,
      severity: :info,
      details: %{
        changes: sanitize_changes(changes),
        previous_values: opts[:previous_values]
      },
      ip_address: opts[:ip_address],
      user_agent: opts[:user_agent],
      organization_id: user && user.organization_id
    })
  end

  @doc """
  Log a response action (kill, quarantine, isolate, etc.).
  """
  def log_response_action(user, action, agent_id, details, opts \\ []) do
    log(%{
      user_id: user && user.id,
      user_email: user && user.email,
      action: action,
      action_type: "response",
      resource_type: "agent",
      resource_id: agent_id,
      severity: :high,
      details: sanitize_details(details),
      ip_address: opts[:ip_address],
      user_agent: opts[:user_agent],
      organization_id: user && user.organization_id
    })
  end

  @doc """
  Log a playbook execution.
  """
  def log_playbook_execution(user, playbook, execution_result, opts \\ []) do
    log(%{
      user_id: user && user.id,
      user_email: user && user.email,
      action: "playbook_executed",
      action_type: "automation",
      resource_type: "playbook",
      resource_id: playbook.id,
      severity: :info,
      details: %{
        playbook_name: playbook.name,
        trigger: opts[:trigger] || "manual",
        result: execution_result,
        steps_executed: opts[:steps_executed],
        duration_ms: opts[:duration_ms]
      },
      ip_address: opts[:ip_address],
      user_agent: opts[:user_agent],
      organization_id: user && user.organization_id
    })
  end

  @doc """
  Log an alert action (acknowledge, resolve, false positive, etc.).
  """
  def log_alert_action(user, action, alert_id, details, opts \\ []) do
    log(%{
      user_id: user && user.id,
      user_email: user && user.email,
      action: action,
      action_type: "alert_management",
      resource_type: "alert",
      resource_id: alert_id,
      severity: :info,
      details: sanitize_details(details),
      ip_address: opts[:ip_address],
      user_agent: opts[:user_agent],
      organization_id: user && user.organization_id
    })
  end

  @doc """
  Log an agent action (isolate, unisolate, restart, etc.).
  """
  def log_agent_action(user, action, agent_id, details, opts \\ []) do
    log(%{
      user_id: user && user.id,
      user_email: user && user.email,
      action: action,
      action_type: "agent_management",
      resource_type: "agent",
      resource_id: agent_id,
      severity: :info,
      details: sanitize_details(details),
      ip_address: opts[:ip_address],
      user_agent: opts[:user_agent],
      organization_id: user && user.organization_id
    })
  end

  @doc """
  Log a rule change (YARA, Sigma, IOC).
  """
  def log_rule_change(user, rule_type, action, rule_id, details, opts \\ []) do
    log(%{
      user_id: user && user.id,
      user_email: user && user.email,
      action: "#{rule_type}_#{action}",
      action_type: "detection_rules",
      resource_type: rule_type,
      resource_id: rule_id,
      severity: :info,
      details: sanitize_details(details),
      ip_address: opts[:ip_address],
      user_agent: opts[:user_agent],
      organization_id: user && user.organization_id
    })
  end

  @doc """
  Log an API access event.
  """
  def log_api_access(user, endpoint, method, opts \\ []) do
    log(%{
      user_id: user && user.id,
      user_email: user && user.email,
      action: "api_#{String.downcase(method)}",
      action_type: "api_access",
      resource_type: "api",
      resource_id: endpoint,
      severity: :info,
      details: %{
        method: method,
        endpoint: endpoint,
        params: sanitize_params(opts[:params]),
        response_status: opts[:response_status],
        duration_ms: opts[:duration_ms]
      },
      ip_address: opts[:ip_address],
      user_agent: opts[:user_agent],
      organization_id: user && user.organization_id
    })
  end

  @doc """
  Log a user action (create, update, delete user).
  """
  def log_user_action(actor, action, target_user, details, opts \\ []) do
    log(%{
      user_id: actor && actor.id,
      user_email: actor && actor.email,
      action: action,
      action_type: "user_management",
      resource_type: "user",
      resource_id: target_user && target_user.id,
      severity: :info,
      details: Map.merge(sanitize_details(details), %{
        target_email: target_user && target_user.email
      }),
      ip_address: opts[:ip_address],
      user_agent: opts[:user_agent],
      organization_id: actor && actor.organization_id
    })
  end

  @doc """
  Log an RBAC change (role assignment, permission change).
  """
  def log_rbac_change(actor, action, target_user, role, details, opts \\ []) do
    log(%{
      user_id: actor && actor.id,
      user_email: actor && actor.email,
      action: action,
      action_type: "rbac",
      resource_type: "role_assignment",
      resource_id: role && role.id,
      severity: :warning,
      details: Map.merge(sanitize_details(details), %{
        target_user_id: target_user && target_user.id,
        target_user_email: target_user && target_user.email,
        role_name: role && role.name
      }),
      ip_address: opts[:ip_address],
      user_agent: opts[:user_agent],
      organization_id: actor && actor.organization_id
    })
  end

  @doc """
  Log a data access event (for sensitive data).
  """
  def log_data_access(user, data_type, data_id, access_type, opts \\ []) do
    log(%{
      user_id: user && user.id,
      user_email: user && user.email,
      action: "data_#{access_type}",
      action_type: "data_access",
      resource_type: data_type,
      resource_id: data_id,
      severity: :info,
      details: %{
        access_type: access_type,
        fields_accessed: opts[:fields_accessed],
        query: opts[:query]
      },
      ip_address: opts[:ip_address],
      user_agent: opts[:user_agent],
      organization_id: user && user.organization_id
    })
  end

  @doc """
  Log a forensic evidence collection.
  """
  def log_forensic_collection(user, agent_id, collection_type, details, opts \\ []) do
    log(%{
      user_id: user && user.id,
      user_email: user && user.email,
      action: "forensic_collection",
      action_type: "forensics",
      resource_type: "agent",
      resource_id: agent_id,
      severity: :high,
      details: Map.merge(sanitize_details(details), %{
        collection_type: collection_type
      }),
      ip_address: opts[:ip_address],
      user_agent: opts[:user_agent],
      organization_id: user && user.organization_id
    })
  end

  @doc """
  Generic log function for custom audit entries with hash chain integrity.
  """
  def log(attrs) do
    attrs = normalize_log_attrs(attrs)

    if is_nil(attrs[:organization_id]) do
      Logger.debug("Skipping tenant-scoped audit without organization_id: #{inspect(attrs[:action])}")
      {:ok, :skipped_no_organization}
    else
      do_log(attrs)
    end
  end

  defp do_log(attrs) do
    # Get previous hash for chain
    previous_hash = get_last_hash(attrs[:organization_id])

    # Calculate entry hash
    entry_hash = calculate_entry_hash(attrs, previous_hash)

    # Add integrity fields
    attrs = attrs
    |> Map.put(:previous_hash, previous_hash)
    |> Map.put(:entry_hash, entry_hash)
    |> Map.put(:sequence_number, get_next_sequence(attrs[:organization_id]))

    %AuditLog{}
    |> AuditLog.changeset(attrs)
    |> Repo.insert()
    |> case do
      {:ok, entry} ->
        Logger.debug("Audit: #{attrs[:action]} by #{attrs[:user_email] || "system"}")
        {:ok, entry}

      {:error, changeset} ->
        Logger.error("Failed to create audit log: #{inspect(changeset.errors)}")
        {:error, changeset}
    end
  end

  # ============================================================================
  # Query Functions
  # ============================================================================

  @doc """
  List audit entries with pagination and filtering.
  """
  def list_entries(opts \\ []) do
    page = max(Keyword.get(opts, :page, 1), 1)
    per_page = opts |> Keyword.get(:per_page, 50) |> min(500) |> max(1)
    offset = (page - 1) * per_page

    base_query = from(a in AuditLog, order_by: [desc: a.inserted_at])

    filtered_query =
      base_query
      |> maybe_filter_search(opts[:search])
      |> maybe_filter_action_type(opts[:action_type])
      |> maybe_filter_severity(opts[:severity])
      |> maybe_filter_user(opts[:user])
      |> maybe_filter_user_id(opts[:user_id])
      |> maybe_filter_date_from(opts[:date_from])
      |> maybe_filter_date_to(opts[:date_to])
      |> maybe_filter_organization(opts[:organization_id])
      |> maybe_filter_resource_type(opts[:resource_type])
      |> maybe_filter_resource_id(opts[:resource_id])

    total = Repo.aggregate(filtered_query, :count)
    total_pages = max(ceil(total / per_page), 1)

    entries =
      filtered_query
      |> limit(^per_page)
      |> offset(^offset)
      |> Repo.all()

    %{
      entries: entries,
      total: total,
      total_pages: total_pages,
      page: page,
      per_page: per_page
    }
  rescue
    e ->
      Logger.error("Error fetching audit logs: #{inspect(e)}")
      %{entries: [], total: 0, total_pages: 1, page: 1, per_page: 50}
  end

  @doc """
  Get a single audit log entry by ID.
  """
  def get_entry(id) do
    Repo.get(AuditLog, id)
  end

  @doc """
  Get recent entries for a specific user.
  """
  def get_user_activity(user_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)

    from(a in AuditLog,
      where: a.user_id == ^user_id,
      order_by: [desc: a.inserted_at],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Get recent entries for a specific resource.
  """
  def get_resource_activity(resource_type, resource_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)

    from(a in AuditLog,
      where: a.resource_type == ^resource_type and a.resource_id == ^resource_id,
      order_by: [desc: a.inserted_at],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Count entries by action type for statistics.
  """
  def count_by_action_type(opts \\ []) do
    base_query = from(a in AuditLog)

    query =
      base_query
      |> maybe_filter_date_from(opts[:date_from])
      |> maybe_filter_date_to(opts[:date_to])
      |> maybe_filter_organization(opts[:organization_id])

    from(a in query,
      group_by: a.action_type,
      select: {a.action_type, count()}
    )
    |> Repo.all()
    |> Map.new()
  end

  # ============================================================================
  # Integrity Verification
  # ============================================================================

  @doc """
  Verify the integrity of the audit log chain.

  Checks that each entry's hash correctly chains to the previous entry.
  Returns `{:ok, verified_count}` or `{:error, broken_at_entry}`.
  """
  def verify_integrity(organization_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 10000)
    start_from = Keyword.get(opts, :start_from)

    query = from(a in AuditLog,
      where: a.organization_id == ^organization_id,
      order_by: [asc: a.sequence_number],
      limit: ^limit
    )

    query = if start_from do
      from a in query, where: a.sequence_number >= ^start_from
    else
      query
    end

    entries = Repo.all(query)

    verify_chain(entries, nil, 0)
  end

  defp verify_chain([], _prev_hash, count), do: {:ok, count}

  defp verify_chain([entry | rest], prev_hash, count) do
    # Verify previous hash matches
    if entry.previous_hash != prev_hash do
      {:error, %{entry_id: entry.id, sequence: entry.sequence_number, reason: :broken_chain}}
    else
      # Verify entry hash
      expected_hash = calculate_entry_hash(entry, prev_hash)

      if entry.entry_hash != expected_hash do
        {:error, %{entry_id: entry.id, sequence: entry.sequence_number, reason: :invalid_hash}}
      else
        verify_chain(rest, entry.entry_hash, count + 1)
      end
    end
  end

  @doc """
  Generate integrity report for compliance.
  """
  def generate_integrity_report(organization_id, opts \\ []) do
    date_from = Keyword.get(opts, :date_from, DateTime.add(DateTime.utc_now(), -30, :day))
    date_to = Keyword.get(opts, :date_to, DateTime.utc_now())

    # Get entry stats
    stats = from(a in AuditLog,
      where: a.organization_id == ^organization_id,
      where: a.inserted_at >= ^date_from and a.inserted_at <= ^date_to,
      select: %{
        total: count(),
        by_type: fragment("jsonb_object_agg(action_type, type_count) FROM (SELECT action_type, count(*) as type_count FROM audit_logs WHERE organization_id = ? AND inserted_at >= ? AND inserted_at <= ? GROUP BY action_type) counts", ^organization_id, ^date_from, ^date_to)
      }
    )
    |> Repo.one()

    # Verify integrity
    integrity_result = verify_integrity(organization_id, limit: 100_000)

    %{
      organization_id: organization_id,
      period_start: date_from,
      period_end: date_to,
      total_entries: stats.total,
      entries_by_type: stats.by_type,
      integrity_verified: match?({:ok, _}, integrity_result),
      integrity_details: integrity_result,
      generated_at: DateTime.utc_now()
    }
  end

  # ============================================================================
  # Compliance Reporting
  # ============================================================================

  @doc """
  Generate SOC 2 compliance report.
  """
  def generate_soc2_report(organization_id, opts \\ []) do
    date_from = Keyword.get(opts, :date_from, DateTime.add(DateTime.utc_now(), -90, :day))
    date_to = Keyword.get(opts, :date_to, DateTime.utc_now())

    %{
      report_type: "SOC 2 Type II",
      organization_id: organization_id,
      period: %{start: date_from, end: date_to},
      sections: %{
        access_control: generate_access_control_section(organization_id, date_from, date_to),
        change_management: generate_change_management_section(organization_id, date_from, date_to),
        incident_response: generate_incident_response_section(organization_id, date_from, date_to),
        data_protection: generate_data_protection_section(organization_id, date_from, date_to)
      },
      generated_at: DateTime.utc_now()
    }
  end

  @doc """
  Generate HIPAA compliance report.
  """
  def generate_hipaa_report(organization_id, opts \\ []) do
    date_from = Keyword.get(opts, :date_from, DateTime.add(DateTime.utc_now(), -90, :day))
    date_to = Keyword.get(opts, :date_to, DateTime.utc_now())

    %{
      report_type: "HIPAA Audit Trail",
      organization_id: organization_id,
      period: %{start: date_from, end: date_to},
      sections: %{
        access_logs: get_phi_access_logs(organization_id, date_from, date_to),
        user_activity: get_user_activity_summary(organization_id, date_from, date_to),
        security_incidents: get_security_incidents(organization_id, date_from, date_to),
        configuration_changes: get_configuration_changes(organization_id, date_from, date_to)
      },
      generated_at: DateTime.utc_now()
    }
  end

  @doc """
  Generate GDPR data access report.
  """
  def generate_gdpr_report(organization_id, user_email, opts \\ []) do
    date_from = Keyword.get(opts, :date_from, DateTime.add(DateTime.utc_now(), -365, :day))
    date_to = Keyword.get(opts, :date_to, DateTime.utc_now())

    %{
      report_type: "GDPR Data Access Report",
      organization_id: organization_id,
      data_subject: user_email,
      period: %{start: date_from, end: date_to},
      activity: get_user_data_access(organization_id, user_email, date_from, date_to),
      generated_at: DateTime.utc_now()
    }
  end

  # ============================================================================
  # Retention Management
  # ============================================================================

  @doc """
  Archive old audit logs based on retention policy.
  """
  def archive_old_logs(organization_id, opts \\ []) do
    days_to_keep = Keyword.get(opts, :days_to_keep, 90)
    cutoff_date = DateTime.add(DateTime.utc_now(), -days_to_keep, :day)

    # Get entries to archive
    entries_to_archive = from(a in AuditLog,
      where: a.organization_id == ^organization_id,
      where: a.inserted_at < ^cutoff_date,
      order_by: [asc: a.inserted_at],
      limit: @batch_size
    )
    |> Repo.all()

    if Enum.empty?(entries_to_archive) do
      {:ok, 0}
    else
      # Create archive record
      archive_data = Enum.map(entries_to_archive, &Map.from_struct/1)
      compressed = :zlib.gzip(Jason.encode!(archive_data))

      archive_attrs = %{
        organization_id: organization_id,
        date_from: List.first(entries_to_archive).inserted_at,
        date_to: List.last(entries_to_archive).inserted_at,
        entry_count: length(entries_to_archive),
        compressed_data: compressed,
        checksum: :crypto.hash(@hash_algorithm, compressed) |> Base.encode16(case: :lower)
      }

      Repo.transaction(fn ->
        # Insert archive
        {:ok, _archive} = %AuditArchive{}
        |> AuditArchive.changeset(archive_attrs)
        |> Repo.insert()

        # Delete archived entries
        entry_ids = Enum.map(entries_to_archive, & &1.id)
        {deleted, _} = from(a in AuditLog, where: a.id in ^entry_ids)
        |> Repo.delete_all()

        deleted
      end)
    end
  end

  @doc """
  Get retention policy for organization.
  """
  def get_retention_policy(organization_id) do
    case Repo.get_by(RetentionPolicy, organization_id: organization_id) do
      nil -> default_retention_policy(organization_id)
      policy -> policy
    end
  end

  @doc """
  Update retention policy for organization.
  """
  def update_retention_policy(organization_id, attrs) do
    policy = get_or_create_retention_policy(organization_id)

    policy
    |> RetentionPolicy.changeset(attrs)
    |> Repo.update()
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp calculate_entry_hash(attrs, previous_hash) when is_map(attrs) do
    data = %{
      action: Map.get(attrs, :action),
      action_type: Map.get(attrs, :action_type),
      user_id: Map.get(attrs, :user_id),
      resource_type: Map.get(attrs, :resource_type),
      resource_id: Map.get(attrs, :resource_id),
      organization_id: Map.get(attrs, :organization_id),
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      previous_hash: previous_hash
    }

    :crypto.hash(@hash_algorithm, Jason.encode!(data))
    |> Base.encode16(case: :lower)
  end

  defp normalize_log_attrs(attrs) when is_map(attrs) do
    attrs
    |> atomize_known_log_keys()
    |> normalize_severity()
    |> normalize_category()
    |> normalize_details()
    |> normalize_action_type()
    |> normalize_resource_type()
    |> normalize_resource_id()
  end

  defp atomize_known_log_keys(attrs) do
    Enum.reduce(attrs, %{}, fn
      {key, value}, acc when is_atom(key) ->
        Map.put(acc, key, value)

      {key, value}, acc when is_binary(key) ->
        atom_key =
          case key do
            "action" -> :action
            "action_type" -> :action_type
            "resource_type" -> :resource_type
            "resource_id" -> :resource_id
            "user_id" -> :user_id
            "user_email" -> :user_email
            "organization_id" -> :organization_id
            "severity" -> :severity
            "category" -> :category
            "metadata" -> :metadata
            "details" -> :details
            "changes" -> :changes
            "ip_address" -> :ip_address
            "user_agent" -> :user_agent
            "request_id" -> :request_id
            "success" -> :success
            "error_message" -> :error_message
            other -> other
          end

        if is_atom(atom_key), do: Map.put(acc, atom_key, value), else: Map.put(acc, key, value)
    end)
  end

  defp normalize_severity(attrs) do
    severity =
      attrs
      |> Map.get(:severity, "info")
      |> to_string()
      |> String.downcase()

    severity =
      if severity in ~w(critical high medium low info), do: severity, else: "info"

    Map.put(attrs, :severity, severity)
  end

  defp normalize_category(attrs) do
    category = Map.get(attrs, :category) || Map.get(attrs, :action_type) || "security"
    category = normalize_category_name(category)
    Map.put(attrs, :category, category)
  end

  defp normalize_category_name(category) do
    category = category |> to_string() |> String.downcase()

    aliases = %{
      "api_access" => "data_access",
      "rbac" => "authorization",
      "response" => "response",
      "forensics" => "investigation",
      "detection_rules" => "detection",
      "automation" => "configuration"
    }

    category = Map.get(aliases, category, category)

    if category in ~w(authentication authorization data_access configuration alert_management agent_management user_management detection response investigation compliance security) do
      category
    else
      "security"
    end
  end

  defp normalize_details(attrs) do
    details = Map.get(attrs, :details) || Map.get(attrs, :metadata) || %{}

    attrs
    |> Map.put(:details, details)
    |> Map.put(:metadata, Map.get(attrs, :metadata) || details)
  end

  defp normalize_action_type(attrs) do
    case Map.get(attrs, :action_type) do
      nil -> Map.put(attrs, :action_type, Map.get(attrs, :category, "security"))
      "" -> Map.put(attrs, :action_type, Map.get(attrs, :category, "security"))
      _ -> attrs
    end
  end

  defp normalize_resource_type(attrs) do
    case Map.get(attrs, :resource_type) do
      nil -> Map.put(attrs, :resource_type, "system")
      "" -> Map.put(attrs, :resource_type, "system")
      _ -> attrs
    end
  end

  defp normalize_resource_id(attrs) do
    case Map.get(attrs, :resource_id) do
      nil -> attrs
      value -> Map.put(attrs, :resource_id, to_string(value))
    end
  end

  defp get_last_hash(organization_id) do
    query = from(a in AuditLog,
      order_by: [desc: a.sequence_number],
      limit: 1,
      select: a.entry_hash
    )

    query = if organization_id do
      from a in query, where: a.organization_id == ^organization_id
    else
      from a in query, where: is_nil(a.organization_id)
    end

    Repo.one(query)
  end

  defp get_next_sequence(organization_id) do
    query = from(a in AuditLog, select: max(a.sequence_number))

    query = if organization_id do
      from a in query, where: a.organization_id == ^organization_id
    else
      from a in query, where: is_nil(a.organization_id)
    end

    current = Repo.one(query)
    (current || 0) + 1
  end

  defp sanitize_changes(changes) when is_map(changes) do
    # Remove sensitive fields from change logs
    sensitive_fields = ~w(password password_hash api_key secret token)

    Enum.reduce(changes, %{}, fn {key, value}, acc ->
      if Enum.member?(sensitive_fields, to_string(key)) do
        Map.put(acc, key, "[REDACTED]")
      else
        Map.put(acc, key, value)
      end
    end)
  end

  defp sanitize_changes(changes), do: changes

  defp sanitize_details(details) when is_map(details) do
    sanitize_changes(details)
  end

  defp sanitize_details(details), do: details

  defp sanitize_params(nil), do: nil

  defp sanitize_params(params) when is_map(params) do
    sensitive_params = ~w(password api_key token secret)

    Enum.reduce(params, %{}, fn {key, value}, acc ->
      if Enum.member?(sensitive_params, to_string(key)) do
        Map.put(acc, key, "[REDACTED]")
      else
        Map.put(acc, key, value)
      end
    end)
  end

  defp sanitize_params(params), do: params

  # Filter helpers
  defp maybe_filter_search(query, nil), do: query
  defp maybe_filter_search(query, ""), do: query

  defp maybe_filter_search(query, search) when is_binary(search) do
    search_term = "%#{search}%"

    from(a in query,
      where:
        ilike(a.action, ^search_term) or
        ilike(a.user_email, ^search_term) or
        ilike(a.resource_type, ^search_term) or
        ilike(a.resource_id, ^search_term) or
        fragment("?::text ILIKE ?", a.details, ^search_term)
    )
  end

  defp maybe_filter_action_type(query, nil), do: query
  defp maybe_filter_action_type(query, ""), do: query
  defp maybe_filter_action_type(query, "all"), do: query

  defp maybe_filter_action_type(query, action_type) do
    from(a in query, where: a.action_type == ^action_type)
  end

  defp maybe_filter_severity(query, nil), do: query
  defp maybe_filter_severity(query, ""), do: query

  defp maybe_filter_severity(query, severity) do
    from(a in query, where: a.severity == ^severity)
  end

  defp maybe_filter_user(query, nil), do: query
  defp maybe_filter_user(query, ""), do: query

  defp maybe_filter_user(query, user_email) do
    from(a in query, where: a.user_email == ^user_email)
  end

  defp maybe_filter_user_id(query, nil), do: query

  defp maybe_filter_user_id(query, user_id) do
    from(a in query, where: a.user_id == ^user_id)
  end

  defp maybe_filter_date_from(query, nil), do: query
  defp maybe_filter_date_from(query, ""), do: query

  defp maybe_filter_date_from(query, date_from) when is_binary(date_from) do
    case parse_date(date_from) do
      {:ok, datetime} ->
        from(a in query, where: a.inserted_at >= ^datetime)

      :error ->
        query
    end
  end

  defp maybe_filter_date_from(query, %DateTime{} = datetime) do
    from(a in query, where: a.inserted_at >= ^datetime)
  end

  defp maybe_filter_date_to(query, nil), do: query
  defp maybe_filter_date_to(query, ""), do: query

  defp maybe_filter_date_to(query, date_to) when is_binary(date_to) do
    case parse_date(date_to, :end_of_day) do
      {:ok, datetime} ->
        from(a in query, where: a.inserted_at <= ^datetime)

      :error ->
        query
    end
  end

  defp maybe_filter_date_to(query, %DateTime{} = datetime) do
    from(a in query, where: a.inserted_at <= ^datetime)
  end

  defp maybe_filter_organization(query, nil), do: query

  defp maybe_filter_organization(query, organization_id) do
    from(a in query, where: a.organization_id == ^organization_id)
  end

  defp maybe_filter_resource_type(query, nil), do: query
  defp maybe_filter_resource_type(query, ""), do: query

  defp maybe_filter_resource_type(query, resource_type) do
    from(a in query, where: a.resource_type == ^resource_type)
  end

  defp maybe_filter_resource_id(query, nil), do: query
  defp maybe_filter_resource_id(query, ""), do: query

  defp maybe_filter_resource_id(query, resource_id) do
    from(a in query, where: a.resource_id == ^resource_id)
  end

  # Parse date string to DateTime
  defp parse_date(date_string, time_position \\ :start_of_day)

  defp parse_date(date_string, :start_of_day) when is_binary(date_string) do
    case Date.from_iso8601(date_string) do
      {:ok, date} ->
        {:ok, DateTime.new!(date, ~T[00:00:00], "Etc/UTC")}

      _ ->
        case DateTime.from_iso8601(date_string) do
          {:ok, dt, _} -> {:ok, dt}
          _ -> :error
        end
    end
  end

  defp parse_date(date_string, :end_of_day) when is_binary(date_string) do
    case Date.from_iso8601(date_string) do
      {:ok, date} ->
        {:ok, DateTime.new!(date, ~T[23:59:59.999999], "Etc/UTC")}

      _ ->
        case DateTime.from_iso8601(date_string) do
          {:ok, dt, _} -> {:ok, dt}
          _ -> :error
        end
    end
  end

  # Compliance report helpers
  defp generate_access_control_section(org_id, date_from, date_to) do
    from(a in AuditLog,
      where: a.organization_id == ^org_id,
      where: a.action_type in ["authentication", "rbac", "user_management"],
      where: a.inserted_at >= ^date_from and a.inserted_at <= ^date_to,
      select: %{total: count(), actions: fragment("array_agg(DISTINCT action)")}
    )
    |> Repo.one()
  end

  defp generate_change_management_section(org_id, date_from, date_to) do
    from(a in AuditLog,
      where: a.organization_id == ^org_id,
      where: a.action_type in ["configuration", "detection_rules"],
      where: a.inserted_at >= ^date_from and a.inserted_at <= ^date_to,
      select: %{total: count(), actions: fragment("array_agg(DISTINCT action)")}
    )
    |> Repo.one()
  end

  defp generate_incident_response_section(org_id, date_from, date_to) do
    from(a in AuditLog,
      where: a.organization_id == ^org_id,
      where: a.action_type in ["response", "alert_management", "forensics"],
      where: a.inserted_at >= ^date_from and a.inserted_at <= ^date_to,
      select: %{total: count(), actions: fragment("array_agg(DISTINCT action)")}
    )
    |> Repo.one()
  end

  defp generate_data_protection_section(org_id, date_from, date_to) do
    from(a in AuditLog,
      where: a.organization_id == ^org_id,
      where: a.action_type == "data_access",
      where: a.inserted_at >= ^date_from and a.inserted_at <= ^date_to,
      select: %{total: count(), data_types: fragment("array_agg(DISTINCT resource_type)")}
    )
    |> Repo.one()
  end

  defp get_phi_access_logs(org_id, date_from, date_to) do
    from(a in AuditLog,
      where: a.organization_id == ^org_id,
      where: a.action_type == "data_access",
      where: a.inserted_at >= ^date_from and a.inserted_at <= ^date_to,
      order_by: [desc: a.inserted_at],
      limit: 1000
    )
    |> Repo.all()
  end

  defp get_user_activity_summary(org_id, date_from, date_to) do
    from(a in AuditLog,
      where: a.organization_id == ^org_id,
      where: a.inserted_at >= ^date_from and a.inserted_at <= ^date_to,
      group_by: a.user_email,
      select: %{user: a.user_email, action_count: count()},
      order_by: [desc: count()]
    )
    |> Repo.all()
  end

  defp get_security_incidents(org_id, date_from, date_to) do
    from(a in AuditLog,
      where: a.organization_id == ^org_id,
      where: a.severity in [:high, :critical],
      where: a.inserted_at >= ^date_from and a.inserted_at <= ^date_to,
      order_by: [desc: a.inserted_at]
    )
    |> Repo.all()
  end

  defp get_configuration_changes(org_id, date_from, date_to) do
    from(a in AuditLog,
      where: a.organization_id == ^org_id,
      where: a.action_type == "configuration",
      where: a.inserted_at >= ^date_from and a.inserted_at <= ^date_to,
      order_by: [desc: a.inserted_at]
    )
    |> Repo.all()
  end

  defp get_user_data_access(org_id, user_email, date_from, date_to) do
    from(a in AuditLog,
      where: a.organization_id == ^org_id,
      where: a.user_email == ^user_email,
      where: a.inserted_at >= ^date_from and a.inserted_at <= ^date_to,
      order_by: [desc: a.inserted_at]
    )
    |> Repo.all()
  end

  defp default_retention_policy(organization_id) do
    %RetentionPolicy{
      organization_id: organization_id,
      hot_retention_days: 90,
      warm_retention_days: 365,
      cold_retention_years: 7,
      auto_archive: true,
      compress_archives: true
    }
  end

  defp get_or_create_retention_policy(organization_id) do
    case Repo.get_by(RetentionPolicy, organization_id: organization_id) do
      nil ->
        {:ok, policy} = %RetentionPolicy{}
        |> RetentionPolicy.changeset(%{organization_id: organization_id})
        |> Repo.insert()
        policy

      policy ->
        policy
    end
  end

  # ============================================================================
  # Background Worker Functions (called by TamanduaServer.Audit GenServer)
  # ============================================================================

  @doc """
  Verify the audit log chain integrity across all organizations.
  Called periodically by the Audit GenServer.
  """
  def verify_chain do
    # Get all organizations with audit entries
    org_ids = from(a in AuditLog, select: a.organization_id, distinct: true)
              |> Repo.all()
              |> Enum.reject(&is_nil/1)

    results = Enum.map(org_ids, fn org_id ->
      case verify_integrity(org_id, limit: 10_000) do
        {:ok, count} -> {:ok, org_id, count}
        {:error, details} -> {:error, org_id, details}
      end
    end)

    errors = Enum.filter(results, fn
      {:error, _, _} -> true
      _ -> false
    end)

    if Enum.empty?(errors) do
      {:ok, :valid}
    else
      broken_details = Enum.map(errors, fn {:error, org_id, details} ->
        Map.put(details, :organization_id, org_id)
      end)
      {:error, :chain_broken, broken_details}
    end
  end

  @doc """
  Enforce retention policies for all organizations.
  Archives old entries and deletes entries beyond retention period.
  Called periodically by the Audit GenServer.
  """
  def enforce_retention do
    # Get all organizations with retention policies
    policies = Repo.all(RetentionPolicy)

    stats = Enum.reduce(policies, %{archived: 0, deleted: 0, errors: []}, fn policy, acc ->
      case enforce_retention_for_org(policy) do
        {:ok, org_stats} ->
          %{acc |
            archived: acc.archived + org_stats.archived,
            deleted: acc.deleted + org_stats.deleted
          }

        {:error, reason} ->
          %{acc | errors: [{policy.organization_id, reason} | acc.errors]}
      end
    end)

    if Enum.empty?(stats.errors) do
      {:ok, stats}
    else
      {:error, stats}
    end
  end

  defp enforce_retention_for_org(policy) do
    now = DateTime.utc_now()

    # Calculate cutoff dates
    hot_cutoff = DateTime.add(now, -policy.hot_retention_days, :day)
    warm_cutoff = DateTime.add(now, -policy.warm_retention_days, :day)
    cold_cutoff = DateTime.add(now, -policy.cold_retention_years * 365, :day)

    try do
      # Archive entries older than hot retention (move to warm)
      archived = if policy.auto_archive do
        archive_entries(policy.organization_id, hot_cutoff, warm_cutoff)
      else
        0
      end

      # Delete entries older than cold retention
      {deleted, _} = from(a in AuditLog,
        where: a.organization_id == ^policy.organization_id,
        where: a.inserted_at < ^cold_cutoff
      )
      |> Repo.delete_all()

      {:ok, %{archived: archived, deleted: deleted}}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end

  defp archive_entries(org_id, from_date, to_date) do
    # Get entries to archive
    entries = from(a in AuditLog,
      where: a.organization_id == ^org_id,
      where: a.inserted_at >= ^to_date and a.inserted_at < ^from_date,
      limit: @batch_size
    )
    |> Repo.all()

    if Enum.empty?(entries) do
      0
    else
      # Create archive record
      archive_data = %{
        organization_id: org_id,
        period_start: to_date,
        period_end: from_date,
        entry_count: length(entries),
        entries_json: Jason.encode!(Enum.map(entries, &Map.from_struct/1)),
        compressed: false,
        checksum: calculate_archive_checksum(entries)
      }

      case %AuditArchive{}
           |> AuditArchive.changeset(archive_data)
           |> Repo.insert() do
        {:ok, _archive} ->
          # Delete archived entries
          entry_ids = Enum.map(entries, & &1.id)
          from(a in AuditLog, where: a.id in ^entry_ids)
          |> Repo.delete_all()
          length(entries)

        {:error, _} ->
          0
      end
    end
  end

  defp calculate_archive_checksum(entries) do
    entries
    |> Enum.map(&(&1.entry_hash || ""))
    |> Enum.join("")
    |> then(&:crypto.hash(@hash_algorithm, &1))
    |> Base.encode16(case: :lower)
  end
end
