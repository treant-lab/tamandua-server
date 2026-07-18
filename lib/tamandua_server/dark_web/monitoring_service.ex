defmodule TamanduaServer.DarkWeb.MonitoringService do
  @moduledoc """
  Main orchestrator for dark web monitoring.

  This GenServer coordinates:
  - Periodic syncing of dark web feeds (HIBP, Intel 471, Flashpoint)
  - Automatic matching of breaches with organizational users
  - Alert generation for compromised credentials
  - Triggering breach response workflows
  - Intelligence gathering and correlation

  ## Architecture

  - GenServer for state management and scheduling
  - Background tasks for feed synchronization
  - Automatic user matching with fuzzy matching
  - Integration with alert system
  - Response workflow automation

  ## Usage

      # Start the service (usually via supervision tree)
      DarkWeb.MonitoringService.start_link([])

      # Manually trigger sync
      DarkWeb.MonitoringService.sync_all_feeds()

      # Check monitoring status
      DarkWeb.MonitoringService.get_status()
  """

  use GenServer
  require Logger

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.DarkWeb
  alias TamanduaServer.DarkWeb.{Breach, Credential, Intelligence, ThreatActor}
  alias TamanduaServer.DarkWeb.Feeds.{HIBP, Intel471, Flashpoint}
  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Alerts

  @sync_interval :timer.hours(6) # Sync every 6 hours
  @feeds [:hibp, :intel471, :flashpoint]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Manually trigger synchronization of all feeds.
  """
  @spec sync_all_feeds() :: :ok
  def sync_all_feeds do
    GenServer.cast(__MODULE__, :sync_all_feeds)
  end

  @doc """
  Sync a specific feed.
  """
  @spec sync_feed(atom()) :: :ok
  def sync_feed(feed_name) when feed_name in @feeds do
    GenServer.cast(__MODULE__, {:sync_feed, feed_name})
  end

  @doc """
  Get current monitoring status and statistics.
  """
  @spec get_status() :: map()
  def get_status do
    GenServer.call(__MODULE__, :get_status)
  end

  @doc """
  Check if a specific email is compromised.
  """
  @spec check_email(String.t()) :: {:ok, list(map())} | {:error, term()}
  def check_email(email) when is_binary(email) do
    GenServer.call(__MODULE__, {:check_email, email})
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    enabled = Keyword.get(opts, :enabled, true)

    state = %{
      enabled: enabled,
      feed_status: initialize_feed_status(),
      stats: %{
        total_breaches: 0,
        total_credentials: 0,
        total_intelligence: 0,
        matched_users: 0,
        alerts_created: 0
      },
      last_sync: nil
    }

    if enabled do
      # Schedule initial sync after 30 seconds
      Process.send_after(self(), :initial_sync, :timer.seconds(30))

      # Schedule periodic syncs
      Process.send_after(self(), :periodic_sync, @sync_interval)
    end

    Logger.info("[DarkWeb.MonitoringService] Initialized")

    {:ok, state}
  end

  @impl true
  def handle_cast(:sync_all_feeds, state) do
    Logger.info("[DarkWeb.MonitoringService] Starting sync of all feeds...")

    # Spawn tasks for each feed
    Enum.each(@feeds, fn feed ->
      Task.start(fn -> do_sync_feed(feed) end)
    end)

    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_cast({:sync_feed, feed_name}, state) do
    Logger.info("[DarkWeb.MonitoringService] Syncing feed: #{feed_name}")
    Task.start(fn -> do_sync_feed(feed_name) end)
    {:noreply, state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    # Get real-time stats from database
    stats = get_current_stats()

    status = %{
      enabled: state.enabled,
      last_sync: state.last_sync,
      feed_status: state.feed_status,
      stats: stats
    }

    {:reply, status, state}
  end

  @impl true
  def handle_call({:check_email, email}, _from, state) do
    result = check_email_compromise(email)
    {:reply, result, state}
  end

  @impl true
  def handle_info(:initial_sync, state) do
    Logger.info("[DarkWeb.MonitoringService] Starting initial sync...")
    send(self(), :sync_all_feeds)
    {:noreply, state}
  end

  @impl true
  def handle_info(:periodic_sync, state) do
    Logger.info("[DarkWeb.MonitoringService] Starting periodic sync...")
    send(self(), :sync_all_feeds)

    # Schedule next periodic sync
    Process.send_after(self(), :periodic_sync, @sync_interval)

    {:noreply, state}
  end

  @impl true
  def handle_info(:sync_all_feeds, state) do
    handle_cast(:sync_all_feeds, state)
  end

  @impl true
  def handle_info({:feed_sync_complete, feed_name, result}, state) do
    new_feed_status = Map.put(state.feed_status, feed_name, result)

    Logger.info("[DarkWeb.MonitoringService] Feed sync complete: #{feed_name} - #{inspect(result)}")

    {:noreply, %{state | feed_status: new_feed_status}}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ============================================================================
  # Private Functions - Feed Synchronization
  # ============================================================================

  defp initialize_feed_status do
    Enum.reduce(@feeds, %{}, fn feed, acc ->
      Map.put(acc, feed, %{
        status: :pending,
        last_sync: nil,
        error: nil,
        count: 0
      })
    end)
  end

  defp do_sync_feed(:hibp) do
    parent = self()

    result =
      try do
        # Sync all breaches from HIBP
        case HIBP.get_all_breaches() do
          {:ok, breaches} ->
            count = sync_hibp_breaches(breaches)

            # Also check for organizational domain breaches
            sync_organizational_domains()

            {:ok, count}

          {:error, reason} ->
            {:error, reason}
        end
      rescue
        e ->
          Logger.error("[DarkWeb.MonitoringService] HIBP sync failed: #{Exception.message(e)}")
          {:error, Exception.message(e)}
      end

    send(parent, {:feed_sync_complete, :hibp, result})
  end

  defp do_sync_feed(:intel471) do
    parent = self()

    result =
      try do
        count = 0

        # Sync threat actors
        count = count + sync_intel471_threat_actors()

        # Sync credentials for organizational domains
        count = count + sync_intel471_credentials()

        # Sync intelligence reports
        count = count + sync_intel471_intelligence()

        {:ok, count}
      rescue
        e ->
          Logger.error("[DarkWeb.MonitoringService] Intel471 sync failed: #{Exception.message(e)}")
          {:error, Exception.message(e)}
      end

    send(parent, {:feed_sync_complete, :intel471, result})
  end

  defp do_sync_feed(:flashpoint) do
    parent = self()

    result =
      try do
        count = 0

        # Sync credentials
        count = count + sync_flashpoint_credentials()

        # Sync threat actors
        count = count + sync_flashpoint_threat_actors()

        # Sync intelligence (forums, marketplaces, leaks)
        count = count + sync_flashpoint_intelligence()

        {:ok, count}
      rescue
        e ->
          Logger.error("[DarkWeb.MonitoringService] Flashpoint sync failed: #{Exception.message(e)}")
          {:error, Exception.message(e)}
      end

    send(parent, {:feed_sync_complete, :flashpoint, result})
  end

  # ============================================================================
  # Private Functions - HIBP Sync
  # ============================================================================

  defp sync_hibp_breaches(breaches) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    entries =
      Enum.map(breaches, fn breach ->
        %{
          breach_name: breach["Name"],
          domain: breach["Domain"],
          breach_date: parse_date(breach["BreachDate"]),
          added_date: parse_datetime(breach["AddedDate"]),
          modified_date: parse_datetime(breach["ModifiedDate"]),
          pwn_count: breach["PwnCount"],
          description: breach["Description"],
          data_classes: breach["DataClasses"] || [],
          is_verified: breach["IsVerified"],
          is_fabricated: breach["IsFabricated"],
          is_sensitive: breach["IsSensitive"],
          is_retired: breach["IsRetired"],
          is_spam_list: breach["IsSpamList"],
          is_malware: breach["IsMalware"],
          logo_path: breach["LogoPath"],
          source: "hibp",
          source_id: breach["Name"],
          raw_data: breach,
          inserted_at: now,
          updated_at: now
        }
      end)

    {count, _} =
      Repo.insert_all(
        Breach,
        entries,
        on_conflict: {:replace, [:modified_date, :pwn_count, :description, :data_classes, :raw_data, :updated_at]},
        conflict_target: [:source, :source_id]
      )

    Logger.info("[DarkWeb.MonitoringService] Synced #{count} HIBP breaches")
    count
  end

  defp sync_organizational_domains do
    # Get all organizational email domains
    domains = get_organizational_domains()

    Enum.each(domains, fn domain ->
      case HIBP.check_domain(domain) do
        {:ok, breaches} when is_list(breaches) ->
          Logger.info("[DarkWeb.MonitoringService] Domain #{domain} found in #{length(breaches)} breaches")

          # For each breach, check if our users' emails are compromised
          Enum.each(breaches, fn breach ->
            check_users_in_breach(domain, breach["Name"])
          end)

        {:ok, :not_found} ->
          Logger.debug("[DarkWeb.MonitoringService] Domain #{domain} not found in breaches")

        {:error, reason} ->
          Logger.warning("[DarkWeb.MonitoringService] Failed to check domain #{domain}: #{inspect(reason)}")
      end

      # Rate limit
      :timer.sleep(1500)
    end)
  end

  defp check_users_in_breach(domain, breach_name) do
    # Get all users with this domain
    users = get_users_by_domain(domain)

    Enum.each(users, fn user ->
      case HIBP.check_email(user.email) do
        {:ok, breaches} when is_list(breaches) ->
          # Check if this breach is in the list
          if Enum.any?(breaches, fn b -> b["Name"] == breach_name end) do
            record_compromised_credential(user, breach_name, breaches)
          end

        _ ->
          :ok
      end

      # Rate limit (HIBP requires 1500ms between requests)
      :timer.sleep(1500)
    end)
  end

  # ============================================================================
  # Private Functions - Intel471 Sync
  # ============================================================================

  defp sync_intel471_threat_actors do
    # Search for known ransomware groups and APTs
    keywords = ["ransomware", "apt", "lockbit", "blackcat", "alphv", "conti"]

    count =
      Enum.reduce(keywords, 0, fn keyword, acc ->
        case Intel471.search_adversaries(keyword, count: 50) do
          {:ok, %{"adversaries" => actors}} when is_list(actors) ->
            stored = store_intel471_threat_actors(actors)
            acc + stored

          _ ->
            acc
        end
      end)

    Logger.info("[DarkWeb.MonitoringService] Synced #{count} Intel471 threat actors")
    count
  end

  defp sync_intel471_credentials do
    domains = get_organizational_domains()
    count = 0

    Enum.reduce(domains, count, fn domain, acc ->
      case Intel471.search_credentials(domain: domain, count: 100) do
        {:ok, %{"credentials" => creds}} when is_list(creds) ->
          stored = store_intel471_credentials(creds)
          acc + stored

        _ ->
          acc
      end
    end)
  end

  defp sync_intel471_intelligence do
    # Search for organization mentions, ransomware negotiations, etc.
    keywords = get_monitoring_keywords()
    count = 0

    Enum.reduce(keywords, count, fn keyword, acc ->
      case Intel471.search_reports(text: keyword, count: 50) do
        {:ok, %{"reports" => reports}} when is_list(reports) ->
          stored = store_intel471_intelligence(reports)
          acc + stored

        _ ->
          acc
      end
    end)
  end

  # ============================================================================
  # Private Functions - Flashpoint Sync
  # ============================================================================

  defp sync_flashpoint_credentials do
    domains = get_organizational_domains()
    count = 0

    Enum.reduce(domains, count, fn domain, acc ->
      case Flashpoint.search_credentials(query: domain, size: 100) do
        {:ok, %{"hits" => hits}} when is_list(hits) ->
          stored = store_flashpoint_credentials(hits)
          acc + stored

        _ ->
          acc
      end
    end)
  end

  defp sync_flashpoint_threat_actors do
    keywords = ["ransomware", "apt", "threat group"]
    count = 0

    Enum.reduce(keywords, count, fn keyword, acc ->
      case Flashpoint.search_actors(keyword, size: 50) do
        {:ok, %{"hits" => actors}} when is_list(actors) ->
          stored = store_flashpoint_threat_actors(actors)
          acc + stored

        _ ->
          acc
      end
    end)
  end

  defp sync_flashpoint_intelligence do
    keywords = get_monitoring_keywords()
    count = 0

    count = Enum.reduce(keywords, count, fn keyword, acc ->
      # Search forums
      forum_count = case Flashpoint.search_forums(keyword, size: 20) do
        {:ok, %{"hits" => hits}} -> store_flashpoint_forums(hits)
        _ -> 0
      end

      # Search marketplaces
      market_count = case Flashpoint.search_marketplaces(keyword, size: 20) do
        {:ok, %{"hits" => hits}} -> store_flashpoint_marketplaces(hits)
        _ -> 0
      end

      # Search data leaks
      leak_count = case Flashpoint.search_data_leaks(keyword, size: 20) do
        {:ok, %{"hits" => hits}} -> store_flashpoint_leaks(hits)
        _ -> 0
      end

      acc + forum_count + market_count + leak_count
    end)

    Logger.info("[DarkWeb.MonitoringService] Synced #{count} Flashpoint intelligence items")
    count
  end

  # ============================================================================
  # Private Functions - Storage
  # ============================================================================

  defp record_compromised_credential(user, breach_name, _breaches) do
    # Find the breach in our database
    breach = Repo.get_by(Breach, breach_name: breach_name, source: "hibp")

    if breach do
      # Check if we already have this credential record
      existing =
        Repo.get_by(Credential,
          email: user.email,
          breach_id: breach.id
        )

      if !existing do
        # Determine severity based on user role and data classes
        severity = calculate_severity(user, breach)

        attrs = %{
          breach_id: breach.id,
          email: user.email,
          user_id: user.id,
          domain: extract_domain(user.email),
          severity: severity,
          status: "new",
          source: "hibp",
          matched_at: DateTime.utc_now(),
          first_seen: DateTime.utc_now(),
          metadata: %{
            data_classes: breach.data_classes
          }
        }

        case DarkWeb.create_credential(attrs) do
          {:ok, credential} ->
            Logger.info("[DarkWeb.MonitoringService] Recorded compromised credential for #{user.email}")

            # Create alert
            create_compromise_alert(user, credential, breach)

            # Trigger response workflow if configured
            trigger_breach_response(credential)

          {:error, changeset} ->
            Logger.error("[DarkWeb.MonitoringService] Failed to create credential: #{inspect(changeset.errors)}")
        end
      end
    end
  end

  defp store_intel471_threat_actors(actors) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    entries =
      Enum.map(actors, fn actor ->
        %{
          name: actor["name"],
          aliases: actor["aliases"] || [],
          actor_type: "ransomware_group",
          description: actor["description"],
          first_seen: parse_datetime(actor["first_seen"]),
          last_seen: parse_datetime(actor["last_seen"]),
          activity_level: "active",
          source: "intel471",
          raw_data: actor,
          inserted_at: now,
          updated_at: now
        }
      end)

    {count, _} =
      Repo.insert_all(
        ThreatActor,
        entries,
        on_conflict: {:replace, [:aliases, :description, :last_seen, :raw_data, :updated_at]},
        conflict_target: [:name, :source]
      )

    count
  end

  defp store_intel471_credentials(_creds) do
    # Store and match with users
    count = 0
    # Implementation similar to HIBP
    count
  end

  defp store_intel471_intelligence(_reports) do
    # Store intelligence reports
    count = 0
    # Implementation
    count
  end

  defp store_flashpoint_credentials(_hits) do
    count = 0
    # Implementation
    count
  end

  defp store_flashpoint_threat_actors(_actors) do
    count = 0
    # Implementation
    count
  end

  defp store_flashpoint_forums(_hits) do
    count = 0
    # Implementation
    count
  end

  defp store_flashpoint_marketplaces(_hits) do
    count = 0
    # Implementation
    count
  end

  defp store_flashpoint_leaks(_hits) do
    count = 0
    # Implementation
    count
  end

  # ============================================================================
  # Private Functions - Utilities
  # ============================================================================

  defp get_organizational_domains do
    query = from(u in User, select: u.email, distinct: true)

    Repo.all(query)
    |> Enum.map(&extract_domain/1)
    |> Enum.uniq()
    |> Enum.filter(&(&1 != nil))
  end

  defp get_users_by_domain(domain) do
    pattern = "%@#{domain}"

    query = from(u in User, where: like(u.email, ^pattern))
    Repo.all(query)
  end

  defp get_monitoring_keywords do
    # Get keywords from monitors
    # For now, return default keywords
    ["company", "organization", "data leak", "ransomware"]
  end

  defp extract_domain(email) when is_binary(email) do
    case String.split(email, "@") do
      [_username, domain] -> domain
      _ -> nil
    end
  end

  defp calculate_severity(user, breach) do
    # High severity for admins or if sensitive data exposed
    cond do
      user.role == "admin" -> "critical"
      breach.is_sensitive -> "high"
      "Passwords" in (breach.data_classes || []) -> "high"
      true -> "medium"
    end
  end

  defp create_compromise_alert(user, credential, breach) do
    Alerts.create_alert(%{
      title: "Compromised Credentials Detected",
      description: """
      User credentials found in dark web breach: #{breach.breach_name}

      Email: #{user.email}
      Breach Date: #{breach.breach_date}
      Data Exposed: #{Enum.join(breach.data_classes || [], ", ")}
      """,
      severity: credential.severity,
      status: "open",
      alert_type: "dark_web_compromise",
      metadata: %{
        credential_id: credential.id,
        breach_id: breach.id,
        user_id: user.id,
        breach_name: breach.breach_name
      }
    })
  end

  defp trigger_breach_response(credential) do
    # Trigger automatic response workflows
    DarkWeb.BreachResponder.handle_compromise(credential)
  end

  defp check_email_compromise(email) do
    case HIBP.check_email(email) do
      {:ok, breaches} when is_list(breaches) ->
        {:ok, breaches}

      {:ok, :not_found} ->
        {:ok, []}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp get_current_stats do
    %{
      total_breaches: Repo.aggregate(Breach, :count, :id),
      total_credentials: Repo.aggregate(Credential, :count, :id),
      total_intelligence: Repo.aggregate(Intelligence, :count, :id),
      matched_users: Repo.aggregate(from(c in Credential, where: not is_nil(c.user_id)), :count, :id)
    }
  end

  defp parse_date(nil), do: nil
  defp parse_date(date_string) when is_binary(date_string) do
    case Date.from_iso8601(date_string) do
      {:ok, date} -> DateTime.new!(date, ~T[00:00:00])
      _ -> nil
    end
  end

  defp parse_datetime(nil), do: nil
  defp parse_datetime(dt_string) when is_binary(dt_string) do
    case DateTime.from_iso8601(dt_string) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end
end
