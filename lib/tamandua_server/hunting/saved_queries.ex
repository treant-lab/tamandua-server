defmodule TamanduaServer.Hunting.SavedQueries do
  @moduledoc """
  Context for managing saved hunt queries and query history.
  """

  import Ecto.Query, warn: false
  alias TamanduaServer.Repo
  alias TamanduaServer.Hunting.{SavedQuery, QueryHistory, QueryBuilder, QueryCompiler, QueryTemplates}
  alias TamanduaServer.{Agents.Agent, Alerts.Alert}
  alias TamanduaServer.Telemetry.Event

  @missing_organization_scope_error "Query organization scope required"

  # ============================================================================
  # Saved Queries
  # ============================================================================

  @doc """
  Lists all saved queries with optional filters.
  """
  def list_saved_queries(opts \\ []) do
    query = from(sq in SavedQuery, order_by: [desc: sq.use_count, desc: sq.inserted_at])

    query
    |> filter_by_type(opts[:query_type])
    |> filter_by_category(opts[:category])
    |> filter_by_user(opts[:user_id])
    |> filter_by_organization(opts[:organization_id], opts[:include_global_templates])
    |> filter_templates(opts[:templates_only])
    |> filter_public(opts[:public_only])
    |> maybe_limit(opts[:limit])
    |> Repo.all()
  end

  @doc """
  Gets a single saved query.
  """
  def get_saved_query(id) do
    get_saved_query(id, [])
  end

  def get_saved_query(id, opts) when is_list(opts) do
    organization_id = opts[:organization_id]
    include_global_templates = opts[:include_global_templates]

    SavedQuery
    |> where([sq], sq.id == ^id)
    |> filter_by_organization(organization_id, include_global_templates)
    |> Repo.one()
  end

  def get_saved_query!(id) do
    get_saved_query!(id, [])
  end

  def get_saved_query!(id, opts) when is_list(opts) do
    organization_id = opts[:organization_id]
    include_global_templates = opts[:include_global_templates]

    SavedQuery
    |> where([sq], sq.id == ^id)
    |> filter_by_organization(organization_id, include_global_templates)
    |> Repo.one!()
  end

  @doc """
  Creates a saved query.
  """
  def create_saved_query(attrs \\ %{}) do
    %SavedQuery{}
    |> SavedQuery.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a saved query.
  """
  def update_saved_query(%SavedQuery{} = saved_query, attrs) do
    saved_query
    |> SavedQuery.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a saved query.
  """
  def delete_saved_query(%SavedQuery{} = saved_query) do
    Repo.delete(saved_query)
  end

  @doc """
  Increments the use count and updates last_used_at.
  """
  def record_query_use(%SavedQuery{} = saved_query) do
    saved_query
    |> SavedQuery.increment_use_changeset()
    |> Repo.update()
  end

  @doc """
  Searches saved queries by name or query content.
  """
  def search_saved_queries(search_term, opts \\ []) do
    search_pattern = "%#{search_term}%"

    query = from(sq in SavedQuery,
      where: ilike(sq.name, ^search_pattern) or ilike(sq.query, ^search_pattern),
      order_by: [desc: sq.use_count, desc: sq.inserted_at]
    )

    query
    |> filter_by_user(opts[:user_id])
    |> filter_by_organization(opts[:organization_id], opts[:include_global_templates])
    |> maybe_limit(opts[:limit] || 20)
    |> Repo.all()
  end

  @doc """
  Gets template queries for a specific category (e.g., MITRE tactic).
  """
  def get_templates_by_category(category, opts \\ []) do
    from(sq in SavedQuery,
      where: sq.is_template == true and sq.category == ^category,
      order_by: [desc: sq.use_count]
    )
    |> filter_by_organization(opts[:organization_id], opts[:include_global_templates])
    |> Repo.all()
  end

  @doc """
  Gets popular public queries.
  """
  def get_popular_queries(limit \\ 10, opts \\ []) do
    from(sq in SavedQuery,
      where: sq.is_public == true,
      order_by: [desc: sq.use_count],
      limit: ^limit
    )
    |> filter_by_organization(opts[:organization_id], opts[:include_global_templates])
    |> Repo.all()
  end

  @doc """
  Execute a saved query by ID.

  Automatically detects query type and routes to appropriate executor:
  - "hunt" or "custom" -> TQL pipe syntax (QueryCompiler)
  - SQL-like SELECT syntax -> QueryBuilder

  ## Examples

      iex> execute_saved_query(query_id, user_id: user_id)
      {:ok, %{data: [...], meta: %{...}}}

      iex> execute_saved_query(invalid_id, user_id: user_id)
      {:error, "Query not found"}
  """
  def execute_saved_query(query_id, opts \\ []) do
    if missing_organization_scope?(opts) do
      {:error, @missing_organization_scope_error}
    else
      do_execute_saved_query(query_id, opts)
    end
  end

  defp do_execute_saved_query(query_id, opts) do
    query =
      get_saved_query(query_id,
        organization_id: opts[:organization_id],
        include_global_templates: opts[:include_global_templates]
      )

    case query do
      nil ->
        {:error, "Query not found"}

      query ->
        # Record usage
        record_query_use(query)

        # Record in history if user_id provided
        if user_id = opts[:user_id] do
          record_query_history(%{
            query: query.query,
            query_type: query.query_type,
            user_id: user_id,
            saved_query_id: query_id
          })
        end

        # Detect and execute appropriate query type
        execute_query_by_type(query.query, query.query_type, opts)
    end
  end

  @doc """
  Execute a query string with automatic type detection.

  Detects SQL-like SELECT queries vs. TQL pipe syntax.
  """
  def execute_query(query_string, opts \\ []) do
    if missing_organization_scope?(opts) do
      {:error, @missing_organization_scope_error}
    else
      do_execute_query(query_string, opts)
    end
  end

  defp do_execute_query(query_string, opts) do
    # Record in history if user_id provided
    if user_id = opts[:user_id] do
      query_type = detect_query_type(query_string)

      record_query_history(%{
        query: query_string,
        query_type: query_type,
        user_id: user_id
      })
    end

    query_type = detect_query_type(query_string)
    execute_query_by_type(query_string, query_type, opts)
  end

  # ============================================================================
  # Private Query Execution Helpers
  # ============================================================================

  defp execute_query_by_type(query_string, query_type, opts) do
    cond do
      # SQL-like SELECT queries
      String.upcase(String.trim(query_string)) |> String.starts_with?("SELECT") ->
        execute_sql_query(query_string, opts)

      # TQL pipe syntax (events | where ...)
      query_type in ["hunt", "custom"] ->
        with {:ok, compiled} <- QueryCompiler.compile(query_string),
             {:ok, scoped_compiled} <- scope_compiled_query(compiled, opts),
             {:ok, results} <- execute_compiled_query(scoped_compiled) do
          {:ok, %{
            data: results,
            meta: %{
              query: query_string,
              total: length(results)
            }
          }}
        end

      true ->
        {:error, "Unsupported query type: #{query_type}"}
    end
  end

  defp execute_sql_query(query_string, opts) do
    start_time = System.monotonic_time(:millisecond)

    with {:ok, parsed} <- QueryBuilder.parse(query_string),
         {:ok, ecto_query} <- QueryBuilder.build_query(parsed) do
      scoped_query = apply_tenant_scope(ecto_query, opts[:organization_id], :sql_events)

      try do
        results = Repo.all(scoped_query)
        execution_time = System.monotonic_time(:millisecond) - start_time

        {:ok, %{
          data: results,
          meta: %{
            query_dsl: query_string,
            sql: inspect_sql(scoped_query),
            total: length(results),
            execution_time_ms: execution_time
          }
        }}
      rescue
        e -> {:error, "Query execution error: #{Exception.message(e)}"}
      end
    end
  end

  defp scope_compiled_query(%{query: ecto_query, source: source} = compiled, opts) do
    {:ok, %{compiled | query: apply_tenant_scope(ecto_query, opts[:organization_id], source)}}
  end

  defp apply_tenant_scope(query, organization_id, source \\ Event)

  defp apply_tenant_scope(query, organization_id, Event) do
    where(
      query,
      [event, agent],
      event.organization_id == ^organization_id or
        (is_nil(event.organization_id) and agent.organization_id == ^organization_id)
    )
  end

  defp apply_tenant_scope(query, organization_id, :sql_events) do
    where(query, [event], event.organization_id == ^organization_id)
  end

  defp apply_tenant_scope(query, organization_id, source) when source in [Agent, Alert] do
    where(query, [resource], resource.organization_id == ^organization_id)
  end

  defp inspect_sql(query) do
    try do
      {sql, _params} = Repo.to_sql(:all, query)
      sql
    rescue
      _ -> "(SQL generation failed)"
    end
  end

  defp missing_organization_scope?(opts), do: is_nil(opts[:organization_id])

  defp detect_query_type(query_string) do
    trimmed = String.trim(query_string)

    cond do
      String.upcase(trimmed) |> String.starts_with?("SELECT") -> "sql"
      String.contains?(trimmed, "|") -> "hunt"
      true -> "custom"
    end
  end

  defp execute_compiled_query(%{query: ecto_query}) do
    try do
      results = Repo.all(ecto_query)
      {:ok, results}
    rescue
      e -> {:error, "Query execution error: #{Exception.message(e)}"}
    end
  end

  # ============================================================================
  # Query History
  # ============================================================================

  @doc """
  Records a query execution in history.
  """
  def record_query_history(attrs) do
    %QueryHistory{}
    |> QueryHistory.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Gets recent query history for a user.
  """
  def get_recent_history(user_id, limit \\ 20) do
    from(qh in QueryHistory,
      where: qh.user_id == ^user_id,
      order_by: [desc: qh.inserted_at],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Gets unique recent queries (deduplicated).
  """
  def get_unique_recent_queries(user_id, limit \\ 10) do
    from(qh in QueryHistory,
      where: qh.user_id == ^user_id,
      distinct: qh.query,
      order_by: [desc: qh.inserted_at],
      limit: ^limit,
      select: %{query: qh.query, query_type: qh.query_type, last_run: qh.inserted_at}
    )
    |> Repo.all()
  end

  @doc """
  Clears old history entries (older than days_to_keep).
  """
  def cleanup_old_history(days_to_keep \\ 30) do
    cutoff = DateTime.utc_now() |> DateTime.add(-days_to_keep * 24 * 60 * 60, :second)

    from(qh in QueryHistory, where: qh.inserted_at < ^cutoff)
    |> Repo.delete_all()
  end

  # ============================================================================
  # Default Templates (Seeding)
  # ============================================================================

  @doc """
  Returns all default MITRE-based query templates.
  This is the single source of truth - also used for seeding database.

  Delegates to QueryTemplates module for the comprehensive template library.
  """
  def default_templates do
    # Use comprehensive template library from QueryTemplates module
    QueryTemplates.all_templates()
  end

  # Legacy implementation (kept for reference, not used)
  def legacy_templates do
    [
      %{
        name: "Phishing Attachments (Legacy)",
        query: "file.path:*\\Downloads\\* AND (file.name:*.exe OR file.name:*.dll OR file.name:*.js)",
        category: "Initial Access",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Detect executable downloads that may indicate phishing payloads"
      },
      %{
        name: "Drive-by Downloads",
        query: "process.parent:*browser* AND process.name:*.exe",
        category: "Initial Access",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Browser spawning executables - potential drive-by compromise"
      },
      %{
        name: "Office Spawning Process",
        query: "(process.parent:*word* OR process.parent:*excel* OR process.parent:*outlook*) AND process.name:*.exe",
        category: "Initial Access",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Office applications spawning executables - macro malware indicator"
      },

      # ========================================================================
      # Execution (TA0002)
      # ========================================================================
      %{
        name: "PowerShell Execution",
        query: "process.name:powershell.exe",
        category: "Execution",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Any PowerShell execution"
      },
      %{
        name: "Encoded PowerShell",
        query: "process.cmdline:*-enc* OR process.cmdline:*encodedcommand*",
        category: "Execution",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Base64 encoded PowerShell commands - evasion technique"
      },
      %{
        name: "Script Interpreters",
        query: "process.name:wscript.exe OR process.name:cscript.exe OR process.name:mshta.exe",
        category: "Execution",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Windows script hosts executing scripts"
      },
      %{
        name: "WMIC Execution",
        query: "process.name:wmic.exe",
        category: "Execution",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "WMI command-line execution"
      },
      %{
        name: "Regsvr32 Execution",
        query: "process.name:regsvr32.exe",
        category: "Execution",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Regsvr32 execution - often used for LOLBin attacks"
      },
      %{
        name: "Rundll32 Execution",
        query: "process.name:rundll32.exe",
        category: "Execution",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Rundll32 executing DLLs - common attack vector"
      },
      %{
        name: "MSBuild Execution",
        query: "process.name:msbuild.exe AND process.parent:!devenv.exe",
        category: "Execution",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "MSBuild running outside Visual Studio - potential code execution"
      },

      # ========================================================================
      # Persistence (TA0003)
      # ========================================================================
      %{
        name: "Run Key Modifications",
        query: "registry.path:*\\Run\\* OR registry.path:*\\RunOnce\\*",
        category: "Persistence",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Autorun registry keys for persistence"
      },
      %{
        name: "Scheduled Tasks",
        query: "process.name:schtasks.exe OR registry.path:*\\Schedule\\TaskCache\\*",
        category: "Persistence",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Task scheduler activity for persistence"
      },
      %{
        name: "Service Creation",
        query: "process.name:sc.exe AND process.cmdline:*create*",
        category: "Persistence",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "New Windows service installation"
      },
      %{
        name: "WMI Event Subscription",
        query: "process.cmdline:*EventSubscription* OR process.cmdline:*__EventFilter*",
        category: "Persistence",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "WMI event subscriptions for persistence"
      },
      %{
        name: "Startup Folder Modifications",
        query: "file.path:*\\Startup\\* AND file.operation:create",
        category: "Persistence",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Files added to startup folder"
      },

      # ========================================================================
      # Privilege Escalation (TA0004)
      # ========================================================================
      %{
        name: "UAC Bypass Attempts",
        query: "process.cmdline:*fodhelper* OR process.cmdline:*eventvwr*",
        category: "Privilege Escalation",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Common UAC bypass techniques"
      },
      %{
        name: "Token Manipulation",
        query: "process.name:runas.exe OR process.cmdline:*SeDebugPrivilege*",
        category: "Privilege Escalation",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Privilege token operations"
      },
      %{
        name: "Named Pipe Impersonation",
        query: "process.cmdline:*\\\\.\\pipe\\*",
        category: "Privilege Escalation",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Named pipe access for potential impersonation"
      },

      # ========================================================================
      # Defense Evasion (TA0005)
      # ========================================================================
      %{
        name: "Process Hollowing",
        query: "process.name:svchost.exe AND process.parent:!services.exe",
        category: "Defense Evasion",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Suspicious svchost parent - potential process hollowing"
      },
      %{
        name: "Timestomping",
        query: "file.operation:setinfo AND file.path:*\\Windows\\*",
        category: "Defense Evasion",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "File timestamp modifications in system directories"
      },
      %{
        name: "AMSI Bypass",
        query: "process.cmdline:*AmsiScanBuffer* OR process.cmdline:*amsi.dll*",
        category: "Defense Evasion",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "AMSI (Antimalware Scan Interface) bypass attempts"
      },
      %{
        name: "Disabling Security Tools",
        query: "process.cmdline:*Stop-Service* AND (process.cmdline:*Defender* OR process.cmdline:*Security*)",
        category: "Defense Evasion",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Attempts to stop security services"
      },
      %{
        name: "Clearing Event Logs",
        query: "process.name:wevtutil.exe AND process.cmdline:*cl*",
        category: "Defense Evasion",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Windows event log clearing"
      },
      %{
        name: "Masquerading",
        query: "process.name:svchost.exe AND process.path:!*\\Windows\\System32\\*",
        category: "Defense Evasion",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Svchost running from non-standard location"
      },

      # ========================================================================
      # Credential Access (TA0006)
      # ========================================================================
      %{
        name: "LSASS Access",
        query: "process.name:lsass.exe OR file.path:*\\lsass*",
        category: "Credential Access",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "LSASS memory access for credential dumping"
      },
      %{
        name: "Mimikatz Indicators",
        query: "process.name:mimikatz* OR process.cmdline:*sekurlsa*",
        category: "Credential Access",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Mimikatz activity patterns"
      },
      %{
        name: "SAM Database Access",
        query: "file.path:*\\SAM OR registry.path:*\\SAM\\*",
        category: "Credential Access",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "SAM hive access for password extraction"
      },
      %{
        name: "NTDS.dit Access",
        query: "file.path:*\\ntds.dit* OR process.cmdline:*ntdsutil*",
        category: "Credential Access",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Active Directory database access"
      },
      %{
        name: "Credential Manager Access",
        query: "file.path:*\\Credentials\\* OR registry.path:*\\Credentials*",
        category: "Credential Access",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Windows Credential Manager access"
      },

      # ========================================================================
      # Discovery (TA0007)
      # ========================================================================
      %{
        name: "System Enumeration",
        query: "process.name:systeminfo.exe OR process.name:hostname.exe",
        category: "Discovery",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "System information gathering"
      },
      %{
        name: "Network Discovery",
        query: "process.name:net.exe OR process.name:ipconfig.exe OR process.name:arp.exe",
        category: "Discovery",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Network enumeration commands"
      },
      %{
        name: "AD Enumeration",
        query: "process.cmdline:*dsquery* OR process.cmdline:*ldapsearch*",
        category: "Discovery",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Active Directory queries"
      },
      %{
        name: "Process Enumeration",
        query: "process.name:tasklist.exe OR process.cmdline:*Get-Process*",
        category: "Discovery",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Process listing for reconnaissance"
      },
      %{
        name: "Security Tool Discovery",
        query: "process.cmdline:*antivirus* OR process.cmdline:*defender* OR process.cmdline:*firewall*",
        category: "Discovery",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Queries about security tools"
      },

      # ========================================================================
      # Lateral Movement (TA0008)
      # ========================================================================
      %{
        name: "PsExec Activity",
        query: "process.name:psexec* OR file.name:psexec*",
        category: "Lateral Movement",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "PsExec remote execution"
      },
      %{
        name: "WMI Remote",
        query: "process.cmdline:*/node:* AND process.name:wmic.exe",
        category: "Lateral Movement",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Remote WMI execution"
      },
      %{
        name: "RDP Connections",
        query: "network.remote_port:3389 OR process.name:mstsc.exe",
        category: "Lateral Movement",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Remote Desktop Protocol activity"
      },
      %{
        name: "SMB/Admin Shares",
        query: "network.remote_port:445 OR file.path:*\\$*\\*",
        category: "Lateral Movement",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "SMB and administrative share access"
      },
      %{
        name: "WinRM Activity",
        query: "network.remote_port:5985 OR network.remote_port:5986 OR process.cmdline:*winrm*",
        category: "Lateral Movement",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Windows Remote Management activity"
      },

      # ========================================================================
      # Collection (TA0009)
      # ========================================================================
      %{
        name: "Archive Creation",
        query: "process.name:7z.exe OR process.name:rar.exe OR process.name:zip.exe",
        category: "Collection",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Data archiving tools for staging"
      },
      %{
        name: "Clipboard Access",
        query: "process.cmdline:*clip* OR process.cmdline:*clipboard*",
        category: "Collection",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Clipboard data access"
      },
      %{
        name: "Screen Capture",
        query: "process.cmdline:*screenshot* OR process.cmdline:*screen capture*",
        category: "Collection",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Screen capture activity"
      },
      %{
        name: "Email Collection",
        query: "file.path:*.pst OR file.path:*.ost OR process.cmdline:*outlook*",
        category: "Collection",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Email file access and collection"
      },

      # ========================================================================
      # Command and Control (TA0011)
      # ========================================================================
      %{
        name: "Suspicious Ports",
        query: "network.remote_port:4444 OR network.remote_port:8080 OR network.remote_port:1337",
        category: "Command and Control",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Common C2 ports"
      },
      %{
        name: "DNS Tunneling",
        query: "dns.query_type:TXT AND dns.query:*",
        category: "Command and Control",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Potential DNS tunneling via TXT records"
      },
      %{
        name: "Known Bad IPs",
        query: "network.remote_ip:185.* OR network.remote_ip:91.* OR network.remote_ip:45.*",
        category: "Command and Control",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Suspicious IP address ranges"
      },
      %{
        name: "Long DNS Queries",
        query: "dns.query:*.*.*.*.*.*",
        category: "Command and Control",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Unusually long subdomain queries - potential exfiltration"
      },
      %{
        name: "Non-Standard HTTP Ports",
        query: "network.remote_port:8443 OR network.remote_port:8888 OR network.remote_port:9000",
        category: "Command and Control",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "HTTP traffic on non-standard ports"
      },

      # ========================================================================
      # Exfiltration (TA0010)
      # ========================================================================
      %{
        name: "Large Uploads",
        query: "network.bytes_sent:>1000000",
        category: "Exfiltration",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Large outbound data transfers (>1MB)"
      },
      %{
        name: "Cloud Storage",
        query: "dns.query:*dropbox* OR dns.query:*drive.google* OR dns.query:*onedrive*",
        category: "Exfiltration",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Cloud storage service access"
      },
      %{
        name: "FTP Exfiltration",
        query: "network.remote_port:21 OR process.name:ftp.exe",
        category: "Exfiltration",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "FTP-based data exfiltration"
      },
      %{
        name: "USB Data Copy",
        query: "file.operation:create AND file.path:*removable*",
        category: "Exfiltration",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Files copied to removable media"
      },

      # ========================================================================
      # Impact (TA0040)
      # ========================================================================
      %{
        name: "Ransomware Extensions",
        query: "file.name:*.encrypted OR file.name:*.locked OR file.name:*.crypto",
        category: "Impact",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Common ransomware file extensions"
      },
      %{
        name: "Mass File Modification",
        query: "file.operation:modify",
        category: "Impact",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "High volume file modifications"
      },
      %{
        name: "Shadow Copy Deletion",
        query: "process.cmdline:*vssadmin* AND process.cmdline:*delete*",
        category: "Impact",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Volume Shadow Copy deletion - ransomware indicator"
      },
      %{
        name: "Service Stop",
        query: "process.name:net.exe AND process.cmdline:*stop*",
        category: "Impact",
        query_type: "hunt",
        is_template: true,
        is_public: true,
        description: "Service stopping - potential impact phase"
      },

      # ========================================================================
      # SQL-Style Query Examples
      # ========================================================================
      %{
        name: "Top 10 Processes (SQL)",
        query: "SELECT COUNT(*) as count, event_type FROM events WHERE event_type = 'process_create' AND timestamp > NOW() - INTERVAL '24 hours' GROUP BY event_type ORDER BY count DESC LIMIT 10",
        category: "Discovery",
        query_type: "sql",
        is_template: true,
        is_public: true,
        description: "Top 10 process creation events in last 24 hours (SQL syntax)"
      },
      %{
        name: "Recent Network Connections (SQL)",
        query: "SELECT * FROM events WHERE event_type = 'network_connect' AND timestamp > NOW() - INTERVAL '1 hour' ORDER BY timestamp DESC LIMIT 100",
        category: "Discovery",
        query_type: "sql",
        is_template: true,
        is_public: true,
        description: "Recent network connections in last hour (SQL syntax)"
      },
      %{
        name: "Event Type Distribution (SQL)",
        query: "SELECT event_type, COUNT(*) as count FROM events WHERE timestamp > NOW() - INTERVAL '24 hours' GROUP BY event_type ORDER BY count DESC",
        category: "Discovery",
        query_type: "sql",
        is_template: true,
        is_public: true,
        description: "Distribution of event types in last 24 hours (SQL syntax)"
      },
      %{
        name: "High Severity Events (SQL)",
        query: "SELECT * FROM events WHERE severity IN ('high', 'critical') AND timestamp > NOW() - INTERVAL '24 hours' ORDER BY timestamp DESC LIMIT 50",
        category: "Execution",
        query_type: "sql",
        is_template: true,
        is_public: true,
        description: "High and critical severity events in last 24 hours (SQL syntax)"
      },
      %{
        name: "Distinct Event Types (SQL)",
        query: "SELECT DISTINCT event_type FROM events WHERE timestamp > NOW() - INTERVAL '7 days' ORDER BY event_type",
        category: "Discovery",
        query_type: "sql",
        is_template: true,
        is_public: true,
        description: "All unique event types seen in last 7 days (SQL syntax)"
      }
    ]
  end

  @doc """
  Returns templates grouped by MITRE category.
  """
  def templates_by_category do
    default_templates()
    |> Enum.group_by(& &1.category)
    |> Enum.sort_by(fn {category, _} ->
      category_order = [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact"
      ]
      Enum.find_index(category_order, &(&1 == category)) || 99
    end)
    |> Enum.into(%{})
  end

  @doc """
  Seeds default MITRE-based query templates.
  """
  def seed_default_templates do
    templates = default_templates()

    Enum.each(templates, fn template ->
      case Repo.get_by(SavedQuery, name: template.name, is_template: true) do
        nil -> create_saved_query(template)
        _existing -> :ok
      end
    end)

    {:ok, length(templates)}
  end

  @doc """
  Force re-seeds all templates (updates existing ones).
  """
  def reseed_templates! do
    templates = default_templates()

    results = Enum.map(templates, fn template ->
      case Repo.get_by(SavedQuery, name: template.name, is_template: true) do
        nil ->
          create_saved_query(template)
        existing ->
          update_saved_query(existing, template)
      end
    end)

    success_count = Enum.count(results, &match?({:ok, _}, &1))
    {:ok, success_count}
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp filter_by_type(query, nil), do: query
  defp filter_by_type(query, type), do: where(query, [sq], sq.query_type == ^type)

  defp filter_by_category(query, nil), do: query
  defp filter_by_category(query, category), do: where(query, [sq], sq.category == ^category)

  defp filter_by_user(query, nil), do: query
  defp filter_by_user(query, user_id), do: where(query, [sq], sq.created_by == ^user_id)

  defp filter_by_organization(query, org_id, include_global \\ false)
  defp filter_by_organization(query, nil, true),
    do: where(query, [sq], sq.is_template == true and is_nil(sq.organization_id))
  defp filter_by_organization(query, nil, _include_global), do: where(query, [sq], false)
  defp filter_by_organization(query, org_id, true),
    do: where(query, [sq], sq.organization_id == ^org_id or (sq.is_template == true and is_nil(sq.organization_id)))
  defp filter_by_organization(query, org_id, _include_global),
    do: where(query, [sq], sq.organization_id == ^org_id)

  defp filter_templates(query, true), do: where(query, [sq], sq.is_template == true)
  defp filter_templates(query, _), do: query

  defp filter_public(query, true), do: where(query, [sq], sq.is_public == true)
  defp filter_public(query, _), do: query

  defp maybe_limit(query, nil), do: query
  defp maybe_limit(query, limit), do: limit(query, ^limit)
end
