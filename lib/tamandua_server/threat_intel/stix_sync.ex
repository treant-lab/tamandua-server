defmodule TamanduaServer.ThreatIntel.StixSync do
  @moduledoc """
  STIX/TAXII Sync Orchestrator for Tamandua EDR.

  Manages bi-directional synchronization with TAXII servers:
  - Import STIX objects from TAXII collections
  - Export Tamandua IOCs and alerts as STIX
  - Publish STIX bundles to TAXII servers
  - Schedule periodic sync jobs
  - Track sync status and statistics

  Uses Oban for scheduled background jobs.
  """

  use Oban.Worker,
    queue: :threat_intel,
    max_attempts: 3

  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.ThreatIntel.{StixConverter, StixTaxii, TaxiiPoller}
  alias TamanduaServer.Detection.IOCs

  @python_ml_url Application.compile_env(:tamandua_server, :ml_service_url, "http://localhost:8000")

  # ── Oban Job Handler ────────────────────────────────────────────────────

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"action" => "sync_server", "server_id" => server_id}}) do
    server = Repo.get(TamanduaServer.ThreatIntel.TaxiiServer, server_id)

    if server && server.enabled do
      case sync_server(server) do
        {:ok, result} ->
          Logger.info("[StixSync] Synced server #{server.name}: #{inspect(result)}")
          :ok

        {:error, reason} ->
          Logger.error("[StixSync] Failed to sync server #{server.name}: #{inspect(reason)}")
          {:error, reason}
      end
    else
      Logger.warning("[StixSync] Server not found or disabled: #{server_id}")
      :ok
    end
  end

  def perform(%Oban.Job{args: %{"action" => "sync_collection", "collection_id" => collection_id}}) do
    collection = Repo.get(TamanduaServer.ThreatIntel.TaxiiCollection, collection_id)

    if collection && collection.enabled do
      case sync_collection(collection) do
        {:ok, result} ->
          Logger.info("[StixSync] Synced collection #{collection.title}: #{inspect(result)}")
          :ok

        {:error, reason} ->
          Logger.error("[StixSync] Failed to sync collection #{collection.title}: #{inspect(reason)}")
          {:error, reason}
      end
    else
      Logger.warning("[StixSync] Collection not found or disabled: #{collection_id}")
      :ok
    end
  end

  def perform(%Oban.Job{args: %{"action" => "export_bundle", "bundle" => bundle, "server_id" => server_id}}) do
    server = Repo.get(TamanduaServer.ThreatIntel.TaxiiServer, server_id)

    if server && server.enabled do
      case export_bundle(server, bundle) do
        {:ok, result} ->
          Logger.info("[StixSync] Exported bundle to #{server.name}: #{inspect(result)}")
          :ok

        {:error, reason} ->
          Logger.error("[StixSync] Failed to export bundle: #{inspect(reason)}")
          {:error, reason}
      end
    else
      :ok
    end
  end

  # ── Public API ──────────────────────────────────────────────────────────

  @doc """
  Sync all collections from a TAXII server.

  Discovers collections, polls objects, converts to internal format,
  and stores in database.
  """
  @spec sync_server(map()) :: {:ok, map()} | {:error, term()}
  def sync_server(server) do
    auth = build_auth_config(server)

    # Discover API roots and collections
    case StixTaxii.discover(server.url, auth) do
      {:ok, discovery} ->
        api_roots = discovery["api_roots"] || []
        default_root = discovery["default"] || List.first(api_roots)

        if default_root do
          # List collections
          case StixTaxii.list_collections(default_root, auth) do
            {:ok, collections} ->
              # Update server with API roots
              Repo.update_all(
                from(s in TamanduaServer.ThreatIntel.TaxiiServer, where: s.id == ^server.id),
                set: [
                  api_roots: api_roots,
                  default_api_root: default_root,
                  last_success_at: DateTime.utc_now(),
                  status: "ok"
                ]
              )

              # Sync each collection
              results = Enum.map(collections, fn coll ->
                sync_or_create_collection(server, coll, default_root)
              end)

              total_imported = results
                |> Enum.map(fn
                  {:ok, %{iocs_inserted: count}} -> count
                  _ -> 0
                end)
                |> Enum.sum()

              {:ok, %{
                collections_synced: length(collections),
                total_imported: total_imported,
                api_root: default_root
              }}

            {:error, reason} ->
              update_server_error(server, reason)
              {:error, reason}
          end
        else
          {:error, :no_api_roots}
        end

      {:error, reason} ->
        update_server_error(server, reason)
        {:error, reason}
    end
  end

  @doc """
  Sync a single TAXII collection.

  Polls objects, parses STIX, converts to IOCs, and stores.
  """
  @spec sync_collection(map()) :: {:ok, map()} | {:error, term()}
  def sync_collection(collection) do
    server = Repo.get(TamanduaServer.ThreatIntel.TaxiiServer, collection.taxii_server_id)

    if server && server.enabled do
      auth = build_auth_config(server)
      opts = build_poll_opts(collection)

      case StixTaxii.import_from_collection(
        collection.api_root,
        collection.collection_id,
        auth,
        opts
      ) do
        {:ok, result} ->
          # Update collection status
          Repo.update_all(
            from(c in TamanduaServer.ThreatIntel.TaxiiCollection, where: c.id == ^collection.id),
            set: [
              last_poll_at: DateTime.utc_now(),
              objects_imported: result.iocs_inserted || 0,
              last_added_after: DateTime.utc_now(),
              status: "ok",
              last_error: nil
            ],
            inc: [objects_imported: result.iocs_inserted || 0]
          )

          # Store STIX objects in database
          if result[:total_objects] && result[:total_objects] > 0 do
            store_stix_objects(collection, result)
          end

          {:ok, result}

        {:error, reason} ->
          # Update collection error
          Repo.update_all(
            from(c in TamanduaServer.ThreatIntel.TaxiiCollection, where: c.id == ^collection.id),
            set: [
              last_poll_at: DateTime.utc_now(),
              status: "error",
              last_error: inspect(reason)
            ]
          )

          {:error, reason}
      end
    else
      {:error, :server_not_found}
    end
  end

  @doc """
  Export IOCs as a STIX bundle and publish to a TAXII server.

  ## Options
    - `:collection_id` - Target collection UUID (required if server has multiple writable collections)
    - `:type` - Filter by IOC type
    - `:source` - Filter by source
    - `:limit` - Maximum IOCs to export (default: 1000)
  """
  @spec export_iocs_to_server(map(), keyword()) :: {:ok, map()} | {:error, term()}
  def export_iocs_to_server(server, opts \\ []) do
    # Build STIX bundle from IOCs
    bundle = StixConverter.export_iocs_as_bundle(opts)

    # Find writable collection
    collection_id = opts[:collection_id] || find_writable_collection(server)

    if collection_id do
      auth = build_auth_config(server)
      api_root = server.default_api_root || List.first(server.api_roots)

      case StixTaxii.publish_bundle(api_root, collection_id, bundle, auth) do
        {:ok, status} ->
          Logger.info("[StixSync] Published #{length(bundle["objects"])} objects to #{server.name}")
          {:ok, %{
            status_id: status["id"],
            objects_published: length(bundle["objects"]),
            server: server.name
          }}

        {:error, reason} ->
          Logger.error("[StixSync] Failed to publish to #{server.name}: #{inspect(reason)}")
          {:error, reason}
      end
    else
      {:error, :no_writable_collection}
    end
  end

  @doc """
  Export alerts as STIX sightings and publish to TAXII server.
  """
  @spec export_alerts_to_server(map(), keyword()) :: {:ok, map()} | {:error, term()}
  def export_alerts_to_server(server, opts \\ []) do
    # Fetch recent alerts
    hours = opts[:hours] || 24
    cutoff = DateTime.add(DateTime.utc_now(), -hours * 3600, :second)

    alerts = from(a in TamanduaServer.Alerts.Alert,
      where: a.inserted_at >= ^cutoff,
      limit: ^(opts[:limit] || 1000)
    )
    |> Repo.all()

    # Convert to STIX sightings
    sightings = Enum.map(alerts, &StixConverter.alert_to_sighting/1)

    # Create bundle
    bundle = StixConverter.create_bundle(sightings)

    # Publish
    collection_id = opts[:collection_id] || find_writable_collection(server)

    if collection_id do
      auth = build_auth_config(server)
      api_root = server.default_api_root || List.first(server.api_roots)

      case StixTaxii.publish_bundle(api_root, collection_id, bundle, auth) do
        {:ok, status} ->
          {:ok, %{
            status_id: status["id"],
            sightings_published: length(sightings),
            server: server.name
          }}

        {:error, reason} ->
          {:error, reason}
      end
    else
      {:error, :no_writable_collection}
    end
  end

  @doc """
  Schedule periodic sync for a server using Oban.
  """
  @spec schedule_server_sync(String.t(), integer()) :: {:ok, Oban.Job.t()} | {:error, term()}
  def schedule_server_sync(server_id, interval_minutes \\ 60) do
    %{action: "sync_server", server_id: server_id}
    |> __MODULE__.new(schedule_in: interval_minutes * 60)
    |> Oban.insert()
  end

  @doc """
  Schedule periodic sync for a collection using Oban.
  """
  @spec schedule_collection_sync(String.t(), integer()) :: {:ok, Oban.Job.t()} | {:error, term()}
  def schedule_collection_sync(collection_id, interval_minutes \\ 60) do
    %{action: "sync_collection", collection_id: collection_id}
    |> __MODULE__.new(schedule_in: interval_minutes * 60)
    |> Oban.insert()
  end

  @doc """
  Get sync statistics for all servers.
  """
  @spec get_sync_stats() :: map()
  def get_sync_stats do
    servers = Repo.all(TamanduaServer.ThreatIntel.TaxiiServer)

    %{
      total_servers: length(servers),
      enabled_servers: Enum.count(servers, & &1.enabled),
      total_objects_imported: Enum.sum(Enum.map(servers, & &1.total_objects_imported)),
      servers: Enum.map(servers, fn s ->
        collections = Repo.all(
          from c in TamanduaServer.ThreatIntel.TaxiiCollection,
          where: c.taxii_server_id == ^s.id
        )

        %{
          id: s.id,
          name: s.name,
          status: s.status,
          last_poll: s.last_poll_at,
          objects_imported: s.total_objects_imported,
          collections: length(collections)
        }
      end)
    }
  end

  # ── Private Helpers ─────────────────────────────────────────────────────

  defp build_auth_config(server) do
    case server.auth_type do
      "basic" ->
        %{
          type: :basic,
          username: server.auth_config["username"],
          password: server.auth_config["password"]
        }

      "api_key" ->
        %{
          type: :api_key,
          key: server.auth_config["key"],
          header: server.auth_config["header"] || "X-API-Key"
        }

      "bearer" ->
        %{
          type: :bearer,
          token: server.auth_config["token"]
        }

      _ ->
        %{}
    end
  end

  defp build_poll_opts(collection) do
    opts = []

    opts = if collection.last_added_after do
      Keyword.put(opts, :added_after, collection.last_added_after)
    else
      opts
    end

    opts = if collection.filter_types && length(collection.filter_types) > 0 do
      Keyword.put(opts, :types, collection.filter_types)
    else
      opts
    end

    opts
  end

  defp sync_or_create_collection(server, coll_data, api_root) do
    coll_id = coll_data["id"]

    collection = Repo.get_by(
      TamanduaServer.ThreatIntel.TaxiiCollection,
      taxii_server_id: server.id,
      collection_id: coll_id
    )

    collection = if collection do
      collection
    else
      # Create new collection
      {:ok, new_coll} = Repo.insert(%TamanduaServer.ThreatIntel.TaxiiCollection{
        id: Ecto.UUID.generate(),
        taxii_server_id: server.id,
        collection_id: coll_id,
        api_root: api_root,
        title: coll_data["title"],
        description: coll_data["description"],
        can_read: coll_data["can_read"] || false,
        can_write: coll_data["can_write"] || false,
        media_types: coll_data["media_types"] || [],
        poll_enabled: coll_data["can_read"] || false,
        enabled: true
      })
      new_coll
    end

    if collection.poll_enabled && collection.can_read do
      sync_collection(collection)
    else
      {:ok, %{iocs_inserted: 0}}
    end
  end

  defp store_stix_objects(collection, result) do
    # This would store STIX objects in the stix_objects table
    # For now, we rely on StixConverter.import_bundle which handles IOC conversion
    # In a full implementation, we would also store raw STIX objects and relationships
    Logger.debug("[StixSync] Storing STIX objects for collection #{collection.title}")
    :ok
  end

  defp find_writable_collection(server) do
    collection = Repo.one(
      from c in TamanduaServer.ThreatIntel.TaxiiCollection,
      where: c.taxii_server_id == ^server.id and c.can_write == true,
      limit: 1
    )

    if collection, do: collection.collection_id, else: nil
  end

  defp update_server_error(server, reason) do
    Repo.update_all(
      from(s in TamanduaServer.ThreatIntel.TaxiiServer, where: s.id == ^server.id),
      set: [
        status: "error",
        last_error: inspect(reason),
        last_poll_at: DateTime.utc_now()
      ],
      inc: [total_errors: 1]
    )
  end

  defp export_bundle(server, bundle) do
    # Implementation for exporting a pre-built bundle
    collection_id = find_writable_collection(server)

    if collection_id do
      auth = build_auth_config(server)
      api_root = server.default_api_root || List.first(server.api_roots)

      StixTaxii.publish_bundle(api_root, collection_id, bundle, auth)
    else
      {:error, :no_writable_collection}
    end
  end
end
