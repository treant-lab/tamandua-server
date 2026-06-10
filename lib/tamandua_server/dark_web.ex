defmodule TamanduaServer.DarkWeb do
  @moduledoc """
  The DarkWeb context - manages dark web monitoring, breaches, and threat intelligence.

  Provides functions for:
  - Managing dark web breaches
  - Tracking compromised credentials
  - Dark web intelligence gathering
  - Threat actor tracking
  - Monitoring configurations
  - Response workflows
  """

  import Ecto.Query, warn: false
  alias TamanduaServer.Repo

  alias TamanduaServer.DarkWeb.{
    Breach,
    Credential,
    Intelligence,
    ThreatActor,
    Monitor,
    ResponseWorkflow
  }

  # ============================================================================
  # Breaches
  # ============================================================================

  @doc """
  Returns the list of breaches.

  ## Options

    - `:limit` - Maximum number of results (default: 100)
    - `:offset` - Offset for pagination (default: 0)
    - `:source` - Filter by source (hibp, intel471, flashpoint, custom)
    - `:order_by` - Order by field (default: :breach_date)
  """
  def list_breaches(opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)
    source = Keyword.get(opts, :source)
    order_by = Keyword.get(opts, :order_by, :breach_date)

    query = from(b in Breach)

    query =
      if source do
        from(b in query, where: b.source == ^source)
      else
        query
      end

    query
    |> order_by([b], desc: field(b, ^order_by))
    |> limit(^limit)
    |> offset(^offset)
    |> Repo.all()
  end

  @doc """
  Gets a single breach.
  """
  def get_breach!(id), do: Repo.get!(Breach, id)

  @doc """
  Gets a breach by name and source.
  """
  def get_breach_by_name(name, source) do
    Repo.get_by(Breach, breach_name: name, source: source)
  end

  @doc """
  Creates a breach.
  """
  def create_breach(attrs \\ %{}) do
    %Breach{}
    |> Breach.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a breach.
  """
  def update_breach(%Breach{} = breach, attrs) do
    breach
    |> Breach.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a breach.
  """
  def delete_breach(%Breach{} = breach) do
    Repo.delete(breach)
  end

  @doc """
  Returns breach statistics.
  """
  def get_breach_stats do
    %{
      total: Repo.aggregate(Breach, :count, :id),
      by_source: get_breach_count_by_source(),
      recent: count_recent_breaches(30)
    }
  end

  defp get_breach_count_by_source do
    query =
      from(b in Breach,
        group_by: b.source,
        select: {b.source, count(b.id)}
      )

    Repo.all(query) |> Map.new()
  end

  defp count_recent_breaches(days) do
    cutoff = DateTime.utc_now() |> DateTime.add(-days * 24 * 3600, :second)

    query =
      from(b in Breach,
        where: b.inserted_at >= ^cutoff
      )

    Repo.aggregate(query, :count, :id)
  end

  # ============================================================================
  # Credentials
  # ============================================================================

  @doc """
  Returns the list of compromised credentials.

  ## Options

    - `:limit` - Maximum number of results (default: 100)
    - `:offset` - Offset for pagination (default: 0)
    - `:status` - Filter by status (new, investigating, resolved, false_positive)
    - `:severity` - Filter by severity (critical, high, medium, low)
    - `:user_id` - Filter by user
  """
  def list_credentials(opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)
    status = Keyword.get(opts, :status)
    severity = Keyword.get(opts, :severity)
    user_id = Keyword.get(opts, :user_id)

    query = from(c in Credential)

    query =
      if status do
        from(c in query, where: c.status == ^status)
      else
        query
      end

    query =
      if severity do
        from(c in query, where: c.severity == ^severity)
      else
        query
      end

    query =
      if user_id do
        from(c in query, where: c.user_id == ^user_id)
      else
        query
      end

    query
    |> order_by([c], desc: c.first_seen)
    |> limit(^limit)
    |> offset(^offset)
    |> preload([:breach, :user])
    |> Repo.all()
  end

  @doc """
  Gets a single credential.
  """
  def get_credential!(id) do
    Credential
    |> Repo.get!(id)
    |> Repo.preload([:breach, :user, :workflows])
  end

  @doc """
  Creates a credential.
  """
  def create_credential(attrs \\ %{}) do
    %Credential{}
    |> Credential.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a credential.
  """
  def update_credential(%Credential{} = credential, attrs) do
    credential
    |> Credential.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a credential.
  """
  def delete_credential(%Credential{} = credential) do
    Repo.delete(credential)
  end

  @doc """
  Returns credential statistics.
  """
  def get_credential_stats do
    %{
      total: Repo.aggregate(Credential, :count, :id),
      by_status: get_credential_count_by_status(),
      by_severity: get_credential_count_by_severity(),
      matched_users: count_matched_credentials(),
      recent: count_recent_credentials(7)
    }
  end

  defp get_credential_count_by_status do
    query =
      from(c in Credential,
        group_by: c.status,
        select: {c.status, count(c.id)}
      )

    Repo.all(query) |> Map.new()
  end

  defp get_credential_count_by_severity do
    query =
      from(c in Credential,
        group_by: c.severity,
        select: {c.severity, count(c.id)}
      )

    Repo.all(query) |> Map.new()
  end

  defp count_matched_credentials do
    query = from(c in Credential, where: not is_nil(c.user_id))
    Repo.aggregate(query, :count, :id)
  end

  defp count_recent_credentials(days) do
    cutoff = DateTime.utc_now() |> DateTime.add(-days * 24 * 3600, :second)

    query =
      from(c in Credential,
        where: c.inserted_at >= ^cutoff
      )

    Repo.aggregate(query, :count, :id)
  end

  # ============================================================================
  # Intelligence
  # ============================================================================

  @doc """
  Returns the list of intelligence findings.
  """
  def list_intelligence(opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)
    intelligence_type = Keyword.get(opts, :intelligence_type)
    status = Keyword.get(opts, :status)
    severity = Keyword.get(opts, :severity)

    query = from(i in Intelligence)

    query =
      if intelligence_type do
        from(i in query, where: i.intelligence_type == ^intelligence_type)
      else
        query
      end

    query =
      if status do
        from(i in query, where: i.status == ^status)
      else
        query
      end

    query =
      if severity do
        from(i in query, where: i.severity == ^severity)
      else
        query
      end

    query
    |> order_by([i], desc: i.first_seen)
    |> limit(^limit)
    |> offset(^offset)
    |> preload(:assigned_to)
    |> Repo.all()
  end

  @doc """
  Gets a single intelligence finding.
  """
  def get_intelligence!(id) do
    Intelligence
    |> Repo.get!(id)
    |> Repo.preload([:assigned_to, :workflows])
  end

  @doc """
  Creates an intelligence finding.
  """
  def create_intelligence(attrs \\ %{}) do
    %Intelligence{}
    |> Intelligence.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates an intelligence finding.
  """
  def update_intelligence(%Intelligence{} = intelligence, attrs) do
    intelligence
    |> Intelligence.changeset(attrs)
    |> Repo.update()
  end

  # ============================================================================
  # Threat Actors
  # ============================================================================

  @doc """
  Returns the list of threat actors.
  """
  def list_threat_actors(opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)
    actor_type = Keyword.get(opts, :actor_type)
    activity_level = Keyword.get(opts, :activity_level)

    query = from(t in ThreatActor)

    query =
      if actor_type do
        from(t in query, where: t.actor_type == ^actor_type)
      else
        query
      end

    query =
      if activity_level do
        from(t in query, where: t.activity_level == ^activity_level)
      else
        query
      end

    query
    |> order_by([t], desc: t.last_seen)
    |> limit(^limit)
    |> offset(^offset)
    |> Repo.all()
  end

  @doc """
  Gets a single threat actor.
  """
  def get_threat_actor!(id), do: Repo.get!(ThreatActor, id)

  @doc """
  Creates a threat actor.
  """
  def create_threat_actor(attrs \\ %{}) do
    %ThreatActor{}
    |> ThreatActor.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a threat actor.
  """
  def update_threat_actor(%ThreatActor{} = actor, attrs) do
    actor
    |> ThreatActor.changeset(attrs)
    |> Repo.update()
  end

  # ============================================================================
  # Monitors
  # ============================================================================

  @doc """
  Returns the list of monitors.
  """
  def list_monitors(opts \\ []) do
    active_only = Keyword.get(opts, :active_only, false)

    query = from(m in Monitor)

    query =
      if active_only do
        from(m in query, where: m.is_active == true)
      else
        query
      end

    query
    |> order_by([m], desc: m.inserted_at)
    |> preload(:created_by)
    |> Repo.all()
  end

  @doc """
  Gets a single monitor.
  """
  def get_monitor!(id) do
    Monitor
    |> Repo.get!(id)
    |> Repo.preload(:created_by)
  end

  @doc """
  Creates a monitor.
  """
  def create_monitor(attrs \\ %{}) do
    %Monitor{}
    |> Monitor.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a monitor.
  """
  def update_monitor(%Monitor{} = monitor, attrs) do
    monitor
    |> Monitor.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a monitor.
  """
  def delete_monitor(%Monitor{} = monitor) do
    Repo.delete(monitor)
  end

  # ============================================================================
  # Response Workflows
  # ============================================================================

  @doc """
  Returns the list of response workflows.
  """
  def list_workflows(opts \\ []) do
    credential_id = Keyword.get(opts, :credential_id)
    status = Keyword.get(opts, :status)

    query = from(w in ResponseWorkflow)

    query =
      if credential_id do
        from(w in query, where: w.credential_id == ^credential_id)
      else
        query
      end

    query =
      if status do
        from(w in query, where: w.status == ^status)
      else
        query
      end

    query
    |> order_by([w], desc: w.triggered_at)
    |> preload([:credential, :intelligence, :executed_by])
    |> Repo.all()
  end

  @doc """
  Gets a single workflow.
  """
  def get_workflow!(id) do
    ResponseWorkflow
    |> Repo.get!(id)
    |> Repo.preload([:credential, :intelligence, :executed_by])
  end

  # ============================================================================
  # Search and Query
  # ============================================================================

  @doc """
  Search across all dark web data.
  """
  def search(query_string, opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)

    %{
      credentials: search_credentials(query_string, limit),
      breaches: search_breaches(query_string, limit),
      intelligence: search_intelligence(query_string, limit),
      threat_actors: search_threat_actors(query_string, limit)
    }
  end

  defp search_credentials(query_string, limit) do
    pattern = "%#{query_string}%"

    from(c in Credential,
      where: ilike(c.email, ^pattern) or ilike(c.username, ^pattern),
      limit: ^limit,
      preload: [:breach, :user]
    )
    |> Repo.all()
  end

  defp search_breaches(query_string, limit) do
    pattern = "%#{query_string}%"

    from(b in Breach,
      where: ilike(b.breach_name, ^pattern) or ilike(b.description, ^pattern),
      limit: ^limit
    )
    |> Repo.all()
  end

  defp search_intelligence(query_string, limit) do
    pattern = "%#{query_string}%"

    from(i in Intelligence,
      where: ilike(i.title, ^pattern) or ilike(i.description, ^pattern) or ilike(i.content, ^pattern),
      limit: ^limit,
      preload: :assigned_to
    )
    |> Repo.all()
  end

  defp search_threat_actors(query_string, limit) do
    pattern = "%#{query_string}%"

    from(t in ThreatActor,
      where: ilike(t.name, ^pattern) or ilike(t.description, ^pattern),
      limit: ^limit
    )
    |> Repo.all()
  end
end
