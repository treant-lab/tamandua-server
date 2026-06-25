defmodule TamanduaServerWeb.API.V1.ThreatIntelController do
  @moduledoc """
  API Controller for Threat Intelligence management.

  Handles:
  - Feed status and sync
  - Threat actors
  - Campaigns
  - Source management
  - Real-time IOC enrichment
  - MISP integration (instances, events, publishing)
  - IOC scoring
  """

  use TamanduaServerWeb, :controller

  require Logger

  alias TamanduaServer.AuditLog
  alias TamanduaServer.Alerts
  alias TamanduaServer.Detection.{ThreatIntelFeeds, ThreatIntelEnrichment, IOCs}
  alias TamanduaServer.Detection.ThreatIntel.Feeds, as: ExternalFeeds
  alias TamanduaServer.ThreatIntel.{MISP, MISPPublisher, MISPInstance, MISPEvent, ThreatActor, IOCScoring}
  alias TamanduaServer.Repo

  import Ecto.Query

  action_fallback TamanduaServerWeb.FallbackController

  @default_dns_feed_names [
    "abusech_feodo",
    "abusech_urlhaus",
    "abusech_threatfox",
    "abusech_malware_bazaar",
    "abusech_ssl_blacklist",
    "emergingthreats",
    "tor_exit_nodes",
    "phishtank",
    "openphish",
    "spamhaus_drop",
    "firehol_level1",
    "c2_intel_feeds"
  ]

  # ============================================================================
  # Feed Status & Sync
  # ============================================================================

  @doc "GET /api/v1/threat-intel/status - Get status of all feeds"
  def feed_status(conn, _params) do
    status = ThreatIntelFeeds.get_status()

    # Build per-feed status with IOC counts from source
    iocs_by_source = status[:iocs_by_source] || %{}

    json(conn, %{
      data: %{
        enabled: status.enabled,
        last_sync: format_datetime(status.last_sync),
        sync_interval_hours: div(status.sync_interval || 14_400_000, 3_600_000),
        feeds: serialize_feed_status(status.sync_status),
        iocs_by_source: iocs_by_source,
        total_iocs: status.total_iocs,
        api_keys_configured: %{
          misp: get_in(status, [:api_keys, :misp, :key]) != nil,
          otx: get_in(status, [:api_keys, :otx, :key]) != nil,
          virustotal: get_in(status, [:api_keys, :virustotal, :key]) != nil,
          shodan: get_in(status, [:api_keys, :shodan, :key]) != nil
        },
        custom_feeds_count: length(status.custom_feeds || [])
      }
    })
  rescue
    e ->
      Logger.warning("Error getting feed status: #{inspect(e)}")
      json(conn, %{
        data: %{
          enabled: false,
          last_sync: nil,
          sync_interval_hours: 4,
          feeds: default_dns_threat_feeds("unavailable"),
          iocs_by_source: %{},
          total_iocs: 0,
          api_keys_configured: %{misp: false, otx: false, virustotal: false, shodan: false},
          custom_feeds_count: 0
        }
      })
  catch
    :exit, reason ->
      Logger.warning("Error getting feed status: exit #{inspect(reason)}")

      json(conn, %{
        data: %{
          enabled: false,
          last_sync: nil,
          sync_interval_hours: 4,
          feeds: default_dns_threat_feeds("unavailable"),
          iocs_by_source: %{},
          total_iocs: 0,
          api_keys_configured: %{misp: false, otx: false, virustotal: false, shodan: false},
          custom_feeds_count: 0
        }
      })
  end

  @doc """
  GET /api/v1/threat-intel/feed-status - Per-feed health monitoring.

  Returns per-feed status including: name, enabled, last_sync_at, ioc_count,
  health (ok/error/stale/pending). A feed is "stale" if last_sync > 2x sync_interval.
  """
  def per_feed_status(conn, _params) do
    status = ThreatIntelFeeds.get_status()

    sync_status = status[:sync_status] || %{}
    iocs_by_source = status[:iocs_by_source] || %{}
    iocs_by_type = status[:iocs_by_type] || %{}
    feed_config = status[:feed_config] || %{}

    # Build per-feed status entries
    feeds = Enum.map(sync_status, fn {name, info} ->
      %{
        name: name,
        enabled: true,
        last_sync_at: format_datetime(info[:last_sync]),
        ioc_count: info[:count] || Map.get(iocs_by_source, to_string(name), 0),
        inserted: info[:inserted] || 0,
        health: info[:health] || "unknown",
        error: info[:error],
        description: get_in(feed_config, [name, :description])
      }
    end)

    # Include configured feeds that haven't synced yet
    configured_not_synced = Enum.reduce(feed_config, [], fn {name, cfg}, acc ->
      if is_map(cfg) and Map.get(cfg, :enabled, false) and not Map.has_key?(sync_status, name) do
        [%{
          name: name,
          enabled: true,
          last_sync_at: nil,
          ioc_count: 0,
          inserted: 0,
          health: "pending",
          error: nil,
          description: Map.get(cfg, :description)
        } | acc]
      else
        acc
      end
    end)

    all_feeds = feeds ++ configured_not_synced

    json(conn, %{
      data: %{
        enabled: status.enabled,
        last_global_sync: format_datetime(status.last_sync),
        sync_interval_hours: div(status.sync_interval || 14_400_000, 3_600_000),
        total_iocs: status.total_iocs,
        iocs_by_type: iocs_by_type,
        iocs_by_source: iocs_by_source,
        feeds: all_feeds
      }
    })
  rescue
    e ->
      Logger.warning("Error getting per-feed status: #{inspect(e)}")
      json(conn, %{
        data: %{
          enabled: false,
          last_global_sync: nil,
          sync_interval_hours: 4,
          total_iocs: 0,
          iocs_by_type: %{},
          iocs_by_source: %{},
          feeds: default_dns_threat_feeds("unavailable")
        }
      })
  catch
    :exit, reason ->
      Logger.warning("Error getting per-feed status: exit #{inspect(reason)}")

      json(conn, %{
        data: %{
          enabled: false,
          last_global_sync: nil,
          sync_interval_hours: 4,
          total_iocs: 0,
          iocs_by_type: %{},
          iocs_by_source: %{},
          feeds: default_dns_threat_feeds("unavailable")
        }
      })
  end

  @doc "POST /api/v1/threat-intel/sync - Trigger sync of all feeds"
  def sync_all(conn, _params) do
    user = conn.assigns[:current_user]
    ThreatIntelFeeds.sync_all()
    AuditLog.log_config_change(user, "threat_intel", %{action: "sync_all_feeds"}, request_metadata(conn))
    json(conn, %{message: "Sync started"})
  end

  @doc "POST /api/v1/threat-intel/sync/:feed_name - Sync a specific feed"
  def sync_feed(conn, %{"feed_name" => feed_name}) do
    user = conn.assigns[:current_user]
    feed_atom = try do
      String.to_existing_atom(feed_name)
    rescue
      ArgumentError -> nil
    end
    if feed_atom, do: ThreatIntelFeeds.sync_feed(feed_atom)
    AuditLog.log_config_change(user, "threat_intel", %{action: "sync_feed", feed: feed_name}, request_metadata(conn))
    json(conn, %{message: "Feed sync started", feed: feed_name})
  end

  # ============================================================================
  # API Key Configuration
  # ============================================================================

  @doc "POST /api/v1/threat-intel/configure - Configure API key for a provider"
  def configure_api_key(conn, %{"provider" => provider, "api_key" => api_key}) do
    provider_atom = String.to_existing_atom(provider)

    case ThreatIntelFeeds.configure_api_key(provider_atom, api_key) do
      :ok ->
        user = conn.assigns[:current_user]
        AuditLog.log_config_change(user, "threat_intel", %{
          action: "configure_api_key",
          provider: provider
        }, request_metadata(conn))

        json(conn, %{message: "API key configured", provider: provider})

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: to_string(reason)})
    end
  rescue
    ArgumentError ->
      conn
      |> put_status(:bad_request)
      |> json(%{error: "Invalid provider"})
  end

  # ============================================================================
  # Custom Feeds
  # ============================================================================

  @doc "GET /api/v1/threat-intel/feeds - List all custom feeds"
  def list_custom_feeds(conn, _params) do
    status = ThreatIntelFeeds.get_status()

    json(conn, %{
      data: Enum.map(status.custom_feeds, fn feed ->
        %{
          name: feed.name,
          url: feed.url,
          format: feed[:format] || "txt",
          ioc_type: feed[:ioc_type] || "ip",
          enabled: feed[:enabled] != false
        }
      end)
    })
  rescue
    e ->
      Logger.warning("[ThreatIntelController] list_custom_feeds failed: #{Exception.message(e)}")
      json(conn, %{data: []})
  end

  @doc "POST /api/v1/threat-intel/feeds - Add a custom feed"
  def add_custom_feed(conn, params) do
    case ThreatIntelFeeds.add_custom_feed(
      params["name"],
      params["url"],
      format: params["format"] || "txt",
      ioc_type: params["ioc_type"] || "ip"
    ) do
      :ok ->
        user = conn.assigns[:current_user]
        AuditLog.log_config_change(user, "threat_intel", %{
          action: "add_custom_feed",
          feed_name: params["name"],
          feed_url: params["url"]
        }, request_metadata(conn))

        conn
        |> put_status(:created)
        |> json(%{message: "Custom feed added", name: params["name"]})

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: to_string(reason)})
    end
  end

  # ============================================================================
  # Threat Actors
  # ============================================================================

  @doc "GET /api/v1/threat-intel/actors - List threat actors"
  def list_actors(conn, _params) do
    # For now, return sample data. In production, this would come from a database
    actors = get_sample_actors()
    json(conn, %{data: actors})
  end

  @doc "GET /api/v1/threat-intel/actors/:id - Get a single threat actor"
  def show_actor(conn, %{"id" => id}) do
    actors = get_sample_actors()

    case Enum.find(actors, fn a -> a.id == id end) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Actor not found"})

      actor ->
        json(conn, %{data: actor})
    end
  end

  # ============================================================================
  # Campaigns
  # ============================================================================

  @doc "GET /api/v1/threat-intel/campaigns - List campaigns"
  def list_campaigns(conn, _params) do
    campaigns = get_sample_campaigns()
    json(conn, %{data: campaigns})
  end

  @doc "GET /api/v1/threat-intel/campaigns/:id - Get a single campaign"
  def show_campaign(conn, %{"id" => id}) do
    campaigns = get_sample_campaigns()

    case Enum.find(campaigns, fn c -> c.id == id end) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Campaign not found"})

      campaign ->
        json(conn, %{data: campaign})
    end
  end

  # ============================================================================
  # Intel Sources
  # ============================================================================

  @doc "GET /api/v1/threat-intel/sources - List intel sources with stats"
  def list_sources(conn, _params) do
    status = ThreatIntelFeeds.get_status()
    iocs_by_source = status[:iocs_by_source] || %{}
    sync_status = status[:sync_status] || %{}

    # Get feed status helper
    get_feed_status = fn feed_name ->
      case Map.get(sync_status, feed_name) do
        %{status: :ok, last_sync: last_sync, count: count} ->
          {"online", format_datetime(last_sync), count}
        %{status: :error} ->
          {"degraded", nil, Map.get(iocs_by_source, to_string(feed_name), 0)}
        _ ->
          if status.enabled do
            {"online", format_datetime(status.last_sync), Map.get(iocs_by_source, to_string(feed_name), 0)}
          else
            {"offline", nil, 0}
          end
      end
    end

    # Build sources from both configured feeds and actual sync status
    abuse_ch_feeds = [:malware_bazaar_recent, :feodo_ip_blocklist, :urlhaus_urls, :threatfox_iocs, :ssl_blacklist]
    abuse_ch_count = Enum.sum(Enum.map(abuse_ch_feeds, fn f ->
      Map.get(iocs_by_source, to_string(f), 0)
    end))

    external_feeds = [:et_compromised_ips, :spamhaus_drop, :tor_exit_nodes, :openphish]
    external_count = Enum.sum(Enum.map(external_feeds, fn f ->
      Map.get(iocs_by_source, to_string(f), 0)
    end))

    sources = [
      %{
        id: "abusech",
        name: "Abuse.ch (MalwareBazaar, URLhaus, Feodo, ThreatFox)",
        type: "feed",
        status: if(status.enabled, do: "online", else: "offline"),
        last_sync: format_datetime(status.last_sync),
        ioc_count: abuse_ch_count
      },
      %{
        id: "external",
        name: "External Free Feeds (ET, Spamhaus, TOR, OpenPhish)",
        type: "feed",
        status: if(status.enabled, do: "online", else: "offline"),
        last_sync: format_datetime(status.last_sync),
        ioc_count: external_count
      },
      %{
        id: "otx",
        name: "AlienVault OTX",
        type: "commercial",
        status: if(get_in(status, [:api_keys, :otx, :key]), do: "online", else: "offline"),
        last_sync: elem(get_feed_status.(:alienvault_otx), 1),
        ioc_count: Map.get(iocs_by_source, "alienvault_otx", 0)
      },
      %{
        id: "misp",
        name: "MISP",
        type: "osint",
        status: if(get_in(status, [:api_keys, :misp, :key]), do: "online", else: "offline"),
        last_sync: elem(get_feed_status.(:misp), 1),
        ioc_count: Map.get(iocs_by_source, "misp", 0)
      },
      %{
        id: "virustotal",
        name: "VirusTotal",
        type: "commercial",
        status: if(get_in(status, [:api_keys, :virustotal, :key]), do: "configured", else: "offline"),
        last_sync: nil,
        ioc_count: 0
      }
    ]

    # Add custom feeds
    custom_feeds = status[:custom_feeds] || []
    custom_sources = Enum.map(custom_feeds, fn feed ->
      feed_name_atom = try do
        String.to_existing_atom(feed.name)
      rescue
        ArgumentError -> String.to_atom(feed.name)
      end
      {feed_status, last_sync, count} = get_feed_status.(feed_name_atom)
      %{
        id: "custom_#{feed.name}",
        name: feed.name,
        type: "internal",
        status: feed_status,
        last_sync: last_sync,
        ioc_count: count
      }
    end)

    json(conn, %{data: sources ++ custom_sources})
  rescue
    e ->
      Logger.warning("Error listing sources: #{inspect(e)}")
      json(conn, %{data: [
        %{id: "abusech", name: "Abuse.ch", type: "feed", status: "offline", last_sync: nil, ioc_count: 0},
        %{id: "external", name: "External Free Feeds", type: "feed", status: "offline", last_sync: nil, ioc_count: 0}
      ]})
  end

  # ============================================================================
  # Top Attackers (Dashboard Widget)
  # ============================================================================

  @doc """
  GET /api/v1/threat-intel/attackers?range=7d

  Returns top threat actors derived from alert data for the TopAttackers
  dashboard widget. Extracts attacker information from alerts' MITRE techniques,
  enrichment data, and threat intelligence attributions.
  """
  def top_attackers(conn, params) do
    range = params["range"] || "7d"
    organization_id = conn.assigns[:organization_id]

    attackers_data = TamanduaServer.Alerts.get_top_attackers(
      organization_id: organization_id,
      range: range
    )

    json(conn, %{data: attackers_data})
  end

  # ============================================================================
  # IOC Summary
  # ============================================================================

  @doc "GET /api/v1/threat-intel/summary - Get IOC summary stats with per-type breakdown"
  def summary(conn, _params) do
    total = IOCs.count()
    by_type = IOCs.count_by_type()
    by_source = IOCs.count_by_source()
    recent = IOCs.list_recent(10)

    # Feed sync health overview
    feed_status = try do
      status = ThreatIntelFeeds.get_status()
      sync_status = status[:sync_status] || %{}

      %{
        enabled: status.enabled,
        last_sync: format_datetime(status.last_sync),
        total_feeds: map_size(sync_status),
        healthy_feeds: Enum.count(sync_status, fn {_, info} -> info[:status] == :ok end),
        error_feeds: Enum.count(sync_status, fn {_, info} -> info[:status] == :error end)
      }
    rescue
      e ->
        Logger.warning("[ThreatIntelController] feed_status lookup in summary failed: #{Exception.message(e)}")
        %{enabled: false, last_sync: nil, total_feeds: 0, healthy_feeds: 0, error_feeds: 0}
    end

    json(conn, %{
      data: %{
        total_iocs: total,
        by_type: by_type,
        by_source: by_source,
        feed_health: feed_status,
        recent_iocs: Enum.map(recent, &serialize_ioc/1)
      }
    })
  rescue
    e ->
      Logger.warning("[ThreatIntelController] summary failed: #{Exception.message(e)}")
      json(conn, %{
        data: %{
          total_iocs: 0,
          by_type: %{},
          by_source: %{},
          feed_health: %{enabled: false, last_sync: nil, total_feeds: 0, healthy_feeds: 0, error_feeds: 0},
          recent_iocs: []
        }
      })
  end

  # ============================================================================
  # Real-time Enrichment
  # ============================================================================

  @doc "POST /api/v1/threat-intel/enrich/hash - Enrich a file hash"
  def enrich_hash(conn, %{"hash" => hash}) do
    case ThreatIntelEnrichment.enrich_hash(hash) do
      {:ok, enrichment} ->
        json(conn, %{
          data: %{
            hash: enrichment.hash,
            hash_type: enrichment.hash_type,
            verdict: enrichment.verdict,
            local_match: enrichment.local_match,
            virustotal: serialize_vt_result(enrichment.virustotal),
            enriched_at: DateTime.to_iso8601(enrichment.enriched_at)
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc "POST /api/v1/threat-intel/enrich/domain - Check domain reputation"
  def enrich_domain(conn, %{"domain" => domain}) do
    case ThreatIntelEnrichment.check_domain(domain) do
      {:ok, enrichment} ->
        json(conn, %{
          data: %{
            domain: enrichment.domain,
            verdict: enrichment.verdict,
            local_match: enrichment.local_match,
            virustotal: serialize_vt_result(enrichment.virustotal),
            enriched_at: DateTime.to_iso8601(enrichment.enriched_at)
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc "POST /api/v1/threat-intel/enrich/ip - Check IP reputation"
  def enrich_ip(conn, %{"ip" => ip}) do
    case ThreatIntelEnrichment.check_ip(ip) do
      {:ok, enrichment} ->
        json(conn, %{
          data: %{
            ip: enrichment.ip,
            verdict: enrichment.verdict,
            local_match: enrichment.local_match,
            abuseipdb: enrichment.abuseipdb,
            virustotal: serialize_vt_result(enrichment.virustotal),
            enriched_at: DateTime.to_iso8601(enrichment.enriched_at)
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc "POST /api/v1/threat-intel/enrich/url - Check URL reputation"
  def enrich_url(conn, %{"url" => url}) do
    case ThreatIntelEnrichment.check_url(url) do
      {:ok, enrichment} ->
        json(conn, %{
          data: %{
            url: enrichment.url,
            verdict: enrichment.verdict,
            local_match: enrichment.local_match,
            virustotal: serialize_vt_result(enrichment.virustotal),
            extracted_domain: enrichment[:extracted_domain],
            enriched_at: DateTime.to_iso8601(enrichment.enriched_at)
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc "POST /api/v1/threat-intel/enrich/batch - Batch enrich multiple IOCs"
  def enrich_batch(conn, %{"iocs" => iocs}) when is_list(iocs) do
    parsed_iocs = Enum.map(iocs, fn ioc ->
      %{
        type: String.to_existing_atom(ioc["type"] || "unknown"),
        value: ioc["value"]
      }
    end)

    case ThreatIntelEnrichment.batch_enrich(parsed_iocs) do
      {:ok, results} ->
        json(conn, %{
          data: Enum.map(results, fn
            {{:ok, enrichment}, _} -> %{status: "ok", enrichment: enrichment}
            {{:error, reason}, _} -> %{status: "error", reason: to_string(reason)}
            {:ok, enrichment} -> %{status: "ok", enrichment: enrichment}
            {:error, reason} -> %{status: "error", reason: to_string(reason)}
          end)
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: to_string(reason)})
    end
  rescue
    ArgumentError ->
      conn
      |> put_status(:bad_request)
      |> json(%{error: "Invalid IOC type"})
  end

  @doc "GET /api/v1/threat-intel/enrich/status - Get enrichment service status"
  def enrich_status(conn, _params) do
    status = ThreatIntelEnrichment.get_config_status()

    json(conn, %{
      data: %{
        enabled: status.enabled,
        configured: status.configured,
        stats: status.stats
      }
    })
  rescue
    e ->
      Logger.warning("[ThreatIntelController] enrich_status failed: #{Exception.message(e)}")
      json(conn, %{
        data: %{
          enabled: false,
          configured: %{virustotal: false, abuseipdb: false, urlscan: false},
          stats: %{lookups: 0, cache_hits: 0, api_calls: 0, errors: 0}
        }
      })
  end

  # ============================================================================
  # IOC Lookup (new ThreatIntel.Feeds integration)
  # ============================================================================

  @doc "GET /api/v1/threat-intel/lookup/:type/:value - Lookup an IOC by type and value"
  def lookup(conn, %{"type" => type, "value" => value}) do
    result = case type do
      "hash" -> ExternalFeeds.check_hash(value)
      "ip" -> ExternalFeeds.check_ip(value)
      "domain" -> ExternalFeeds.check_domain(value)
      "url" -> ExternalFeeds.check_url(value)
      _ ->
        {:error, :invalid_type}
    end

    case result do
      {:ok, %{found: true} = data} ->
        json(conn, %{
          data: %{
            found: true,
            type: type,
            value: value,
            source: data[:source],
            threat_type: data[:threat_type],
            malware_family: data[:malware_family],
            confidence: data[:confidence],
            tags: data[:tags] || [],
            first_seen: format_datetime(data[:first_seen]),
            last_seen: format_datetime(data[:last_seen])
          }
        })

      {:ok, %{found: false}} ->
        json(conn, %{
          data: %{
            found: false,
            type: type,
            value: value
          }
        })

      {:error, :invalid_type} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid IOC type. Supported types: hash, ip, domain, url"})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc "GET /api/v1/threat-intel/feeds/status - Get external feed status (new Feeds module)"
  def external_feeds_status(conn, _params) do
    try do
      status = ExternalFeeds.get_feed_status()

      json(conn, %{
        data: %{
          enabled: status.enabled,
          total_iocs: status.total_iocs,
          feeds: status.feeds,
          api_keys_configured: status.api_keys_configured
        }
      })
    rescue
      e ->
        Logger.warning("Error getting external feed status: #{inspect(e)}")
        json(conn, %{
          data: %{
            enabled: false,
            total_iocs: 0,
            feeds: [],
            api_keys_configured: %{}
          }
        })
    end
  end

  @doc "POST /api/v1/threat-intel/feeds/refresh - Trigger refresh of external feeds"
  def refresh_external_feeds(conn, _params) do
    ExternalFeeds.refresh_all()
    json(conn, %{message: "External feed refresh started"})
  end

  @doc "POST /api/v1/threat-intel/feeds/refresh/:feed - Refresh specific external feed"
  def refresh_external_feed(conn, %{"feed" => feed_name}) do
    feed_atom = String.to_existing_atom(feed_name)
    ExternalFeeds.refresh_feed(feed_atom)
    json(conn, %{message: "Feed refresh started", feed: feed_name})
  rescue
    ArgumentError ->
      conn
      |> put_status(:bad_request)
      |> json(%{error: "Unknown feed: #{feed_name}"})
  end

  @doc "GET /api/v1/threat-intel/feeds/stats - Get external feed statistics"
  def external_feeds_stats(conn, _params) do
    try do
      stats = ExternalFeeds.get_stats()

      json(conn, %{
        data: %{
          ets_cache_size: stats.ets_cache_size,
          lookups: stats.lookups,
          cache_hits: stats.cache_hits,
          cache_misses: stats.cache_misses,
          api_queries: stats.api_queries
        }
      })
    rescue
      e ->
        Logger.warning("[ThreatIntelController] external_feeds_stats failed: #{Exception.message(e)}")
        json(conn, %{
          data: %{
            ets_cache_size: 0,
            lookups: 0,
            cache_hits: 0,
            cache_misses: 0,
            api_queries: 0
          }
        })
    end
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp serialize_vt_result(nil), do: nil
  defp serialize_vt_result(%{rate_limited: true}), do: %{status: "rate_limited"}
  defp serialize_vt_result(%{not_found: true}), do: %{status: "not_found"}
  defp serialize_vt_result(result), do: result

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
  defp format_datetime(ts) when is_integer(ts), do: DateTime.from_unix!(ts) |> DateTime.to_iso8601()

  defp serialize_feed_status(status_map) when is_map(status_map) do
    Enum.map(status_map, fn {name, info} ->
      %{
        name: name,
        last_sync: format_datetime(info[:last_sync]),
        status: info[:status] || "unknown",
        ioc_count: info[:count] || 0,
        error: info[:error]
      }
    end)
  end
  defp serialize_feed_status(_), do: []

  defp default_dns_threat_feeds(health) do
    Enum.map(@default_dns_feed_names, fn name ->
      %{
        name: name,
        enabled: false,
        last_sync_at: nil,
        ioc_count: 0,
        inserted: 0,
        health: health,
        error: "Threat intel feed service is unavailable",
        description: default_dns_feed_description(name)
      }
    end)
  end

  defp default_dns_feed_description("abusech_feodo"), do: "Abuse.ch Feodo Tracker indicators"
  defp default_dns_feed_description("abusech_urlhaus"), do: "Abuse.ch URLhaus malware URLs"
  defp default_dns_feed_description("abusech_threatfox"), do: "Abuse.ch ThreatFox IOCs"
  defp default_dns_feed_description("abusech_malware_bazaar"), do: "Abuse.ch MalwareBazaar sample intelligence"
  defp default_dns_feed_description("abusech_ssl_blacklist"), do: "Abuse.ch SSL certificate blacklist"
  defp default_dns_feed_description("emergingthreats"), do: "Emerging Threats open indicators"
  defp default_dns_feed_description("tor_exit_nodes"), do: "Tor exit node feed"
  defp default_dns_feed_description("phishtank"), do: "PhishTank phishing URL feed"
  defp default_dns_feed_description("openphish"), do: "OpenPhish phishing feed"
  defp default_dns_feed_description("spamhaus_drop"), do: "Spamhaus DROP blocklist"
  defp default_dns_feed_description("firehol_level1"), do: "FireHOL level 1 blocklist"
  defp default_dns_feed_description("c2_intel_feeds"), do: "Command-and-control intelligence feeds"
  defp default_dns_feed_description(_name), do: "Threat intelligence feed"

  defp serialize_ioc(ioc) do
    %{
      id: ioc.id,
      type: ioc.type,
      value: ioc.value,
      threat_type: Map.get(ioc, :threat_type) || ioc.description,
      confidence: ioc.confidence || 50,
      source: ioc.source,
      severity: ioc.severity,
      first_seen: format_datetime(ioc.inserted_at),
      last_seen: format_datetime(ioc.updated_at),
      tags: ioc.tags || []
    }
  end

  # Returns sample threat actors only when DEMO_MODE is enabled
  defp get_sample_actors do
    if Application.get_env(:tamandua_server, :demo_mode, false) do
      [
        %{
          id: "apt29",
          name: "APT29 (Cozy Bear)",
          aliases: ["The Dukes", "CozyDuke", "YTTRIUM"],
          motivation: "espionage",
          target_sectors: ["Government", "Think Tanks", "Defense"],
          origin_country: "Russia",
          active_since: "2008",
          last_activity: "2024",
          ttps: ["T1566.001", "T1204.002", "T1059.001", "T1105", "T1071.001"],
          _demo: true
        },
        %{
          id: "lazarus",
          name: "Lazarus Group",
          aliases: ["Hidden Cobra", "APT38", "ZINC"],
          motivation: "financial",
          target_sectors: ["Financial", "Cryptocurrency", "Defense"],
          origin_country: "North Korea",
          active_since: "2009",
          last_activity: "2024",
          ttps: ["T1566.002", "T1059.005", "T1055", "T1486", "T1560.001"],
          _demo: true
        },
        %{
          id: "fin7",
          name: "FIN7",
          aliases: ["Carbanak", "Carbon Spider", "ITG14"],
          motivation: "financial",
          target_sectors: ["Retail", "Hospitality", "Healthcare"],
          origin_country: "Russia",
          active_since: "2013",
          last_activity: "2024",
          ttps: ["T1566.001", "T1059.001", "T1055.012", "T1071.001", "T1005"],
          _demo: true
        }
      ]
    else
      # Return empty list - real actors should come from threat intel feeds
      []
    end
  end

  # Returns sample campaigns only when DEMO_MODE is enabled
  defp get_sample_campaigns do
    if Application.get_env(:tamandua_server, :demo_mode, false) do
      [
        %{
          id: "campaign_1",
          name: "SolarWinds Supply Chain Attack",
          actor: "APT29",
          status: "concluded",
          start_date: "2020-03",
          end_date: "2021-01",
          target_regions: ["North America", "Europe"],
          description: "Sophisticated supply chain attack targeting SolarWinds Orion software to compromise government and enterprise networks.",
          _demo: true
        },
        %{
          id: "campaign_2",
          name: "Conti Ransomware Operations",
          actor: "FIN7",
          status: "dormant",
          start_date: "2020-12",
          end_date: "2022-05",
          target_regions: ["Worldwide"],
          description: "Ransomware-as-a-Service operation with double extortion tactics targeting critical infrastructure and healthcare.",
          _demo: true
        },
        %{
          id: "campaign_3",
          name: "Cryptocurrency Exchange Heists",
          actor: "Lazarus Group",
          status: "active",
          start_date: "2021-01",
          end_date: nil,
          target_regions: ["Asia", "North America", "Europe"],
          description: "Ongoing campaign targeting cryptocurrency exchanges and DeFi platforms for financial theft.",
          _demo: true
        }
      ]
    else
      # Return empty list - real campaigns should come from threat intel feeds
      []
    end
  end

  # ============================================================================
  # MISP Instance Management
  # ============================================================================

  @doc "GET /api/v1/threat-intel/misp/instances - List MISP instances"
  def list_misp_instances(conn, _params) do
    instances = MISP.list_instances()

    json(conn, %{
      data: Enum.map(instances, &serialize_misp_instance/1)
    })
  rescue
    e ->
      Logger.error("Error listing MISP instances: #{inspect(e)}")
      json(conn, %{data: []})
  end

  @doc "GET /api/v1/threat-intel/misp/instances/:id - Get a MISP instance"
  def show_misp_instance(conn, %{"id" => id}) do
    case Repo.get(MISPInstance, id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "MISP instance not found"})

      instance ->
        json(conn, %{data: serialize_misp_instance(instance)})
    end
  rescue
    e ->
      Logger.error("Error getting MISP instance: #{inspect(e)}")
      conn
      |> put_status(:internal_server_error)
      |> json(%{error: "Failed to get MISP instance"})
  end

  @doc "POST /api/v1/threat-intel/misp/instances - Create a MISP instance"
  def create_misp_instance(conn, params) do
    attrs = %{
      name: params["name"],
      url: params["url"],
      api_key: params["api_key"],
      verify_ssl: params["verify_ssl"] != false,
      enabled: params["enabled"] != false,
      pull_enabled: params["pull_enabled"] != false,
      push_enabled: params["push_enabled"] == true,
      trust_level: params["trust_level"] || 50,
      sync_interval_hours: params["sync_interval_hours"] || 4,
      tags_filter: params["tags_filter"] || [],
      threat_level_filter: params["threat_level_filter"] || [],
      published_only: params["published_only"] != false
    }

    case MISP.add_instance(attrs) do
      {:ok, instance} ->
        user = conn.assigns[:current_user]
        AuditLog.log_config_change(user, "threat_intel", %{
          action: "create_misp_instance",
          instance_id: instance.id,
          instance_name: instance.name
        }, request_metadata(conn))

        conn
        |> put_status(:created)
        |> json(%{data: serialize_misp_instance(instance)})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: format_changeset_errors(changeset)})
    end
  end

  @doc "PUT /api/v1/threat-intel/misp/instances/:id - Update a MISP instance"
  def update_misp_instance(conn, %{"id" => id} = params) do
    attrs = Map.drop(params, ["id"])

    case MISP.update_instance(id, attrs) do
      {:ok, instance} ->
        user = conn.assigns[:current_user]
        AuditLog.log_config_change(user, "threat_intel", %{
          action: "update_misp_instance",
          instance_id: id,
          changes: Map.drop(attrs, ["api_key"])
        }, request_metadata(conn))

        json(conn, %{data: serialize_misp_instance(instance)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "MISP instance not found"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: format_changeset_errors(changeset)})
    end
  end

  @doc "DELETE /api/v1/threat-intel/misp/instances/:id - Delete a MISP instance"
  def delete_misp_instance(conn, %{"id" => id}) do
    case MISP.remove_instance(id) do
      :ok ->
        user = conn.assigns[:current_user]
        AuditLog.log_config_change(user, "threat_intel", %{
          action: "delete_misp_instance",
          instance_id: id
        }, request_metadata(conn))

        json(conn, %{message: "Instance deleted"})

      {:ok, _} ->
        user = conn.assigns[:current_user]
        AuditLog.log_config_change(user, "threat_intel", %{
          action: "delete_misp_instance",
          instance_id: id
        }, request_metadata(conn))

        json(conn, %{message: "Instance deleted"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "MISP instance not found"})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc "POST /api/v1/threat-intel/misp/instances/:id/test - Test MISP connection"
  def test_misp_connection(conn, %{"id" => id}) do
    case MISP.test_connection(id) do
      {:ok, info} ->
        json(conn, %{
          data: %{
            connected: info.connected,
            version: info.version,
            can_sync: info.perm_sync,
            can_sighting: info.perm_sighting
          }
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "MISP instance not found"})

      {:error, :unauthorized} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Invalid API key"})

      {:error, reason} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc "POST /api/v1/threat-intel/misp/instances/:id/sync - Sync a specific MISP instance"
  def sync_misp_instance(conn, %{"id" => id}) do
    MISP.sync_instance(id)
    json(conn, %{message: "Sync started", instance_id: id})
  end

  @doc "GET /api/v1/threat-intel/misp/sync-status - Get sync status for all instances"
  def misp_sync_status(conn, _params) do
    status = MISP.get_sync_status()

    json(conn, %{
      data: Enum.map(status, fn {instance_id, info} ->
        %{
          instance_id: instance_id,
          status: info[:status],
          last_sync: format_datetime(info[:last_sync]),
          events_synced: info[:events_synced] || 0,
          iocs_imported: info[:iocs_imported] || 0,
          error: info[:error]
        }
      end)
    })
  rescue
    e ->
      Logger.warning("[ThreatIntelController] misp_sync_status failed: #{Exception.message(e)}")
      json(conn, %{data: []})
  end

  # ============================================================================
  # MISP Events
  # ============================================================================

  @doc "GET /api/v1/threat-intel/misp/events - List synced MISP events"
  def list_misp_events(conn, params) do
    limit = bounded_limit(params["limit"], 50, 500)
    instance_id = params["instance_id"]

    opts = [limit: limit]
    opts = if instance_id, do: Keyword.put(opts, :instance_id, instance_id), else: opts

    events = MISP.list_events(opts)

    json(conn, %{
      data: Enum.map(events, &serialize_misp_event/1)
    })
  rescue
    e ->
      Logger.warning("[ThreatIntelController] list_misp_events failed: #{Exception.message(e)}")
      json(conn, %{data: []})
  end

  @doc "GET /api/v1/threat-intel/misp/events/:id - Get a MISP event"
  def show_misp_event(conn, %{"id" => id}) do
    case Repo.get(MISPEvent, id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Event not found"})

      event ->
        json(conn, %{data: serialize_misp_event(event)})
    end
  end

  # ============================================================================
  # MISP Publishing
  # ============================================================================

  @doc "POST /api/v1/threat-intel/misp/publish - Publish an alert to MISP"
  def publish_to_misp(conn, %{"alert_id" => alert_id, "instance_id" => instance_id} = params) do
    opts = [
      tlp: params["tlp"] || "AMBER",
      sharing_group_id: params["sharing_group_id"],
      publish: params["auto_publish"] == true,
      tags: params["tags"] || []
    ]

    case MISPPublisher.publish_alert(alert_id, instance_id, opts) do
      {:ok, event_id} ->
        user = conn.assigns[:current_user]
        AuditLog.log_config_change(user, "threat_intel", %{
          action: "publish_to_misp",
          alert_id: alert_id,
          instance_id: instance_id,
          misp_event_id: event_id
        }, request_metadata(conn))

        conn
        |> put_status(:created)
        |> json(%{
          message: "Alert published to MISP",
          misp_event_id: event_id,
          alert_id: alert_id,
          instance_id: instance_id
        })

      {:error, :instance_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "MISP instance not found"})

      {:error, :alert_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Alert not found"})

      {:error, :push_not_enabled} ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Push is not enabled for this MISP instance"})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc "POST /api/v1/threat-intel/misp/publish/batch - Batch publish alerts to MISP"
  def batch_publish_to_misp(conn, %{"alert_ids" => alert_ids, "instance_id" => instance_id} = params) do
    opts = [
      tlp: params["tlp"] || "AMBER",
      sharing_group_id: params["sharing_group_id"],
      publish: params["auto_publish"] == true,
      tags: params["tags"] || []
    ]

    case MISPPublisher.batch_publish(alert_ids, instance_id, opts) do
      {:ok, result} ->
        json(conn, %{
          data: %{
            total: result.total,
            successful: result.successful,
            failed: result.failed,
            errors: result.errors
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc "POST /api/v1/threat-intel/misp/sighting - Add a sighting to MISP"
  def add_misp_sighting(conn, %{"instance_id" => instance_id, "attribute_uuid" => uuid} = params) do
    sighting_type = params["type"] || 0

    case MISPPublisher.add_sighting(instance_id, uuid, sighting_type) do
      {:ok, sighting_id} ->
        json(conn, %{message: "Sighting added", sighting_id: sighting_id})

      {:error, :instance_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "MISP instance not found"})

      {:error, :sighting_not_enabled} ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Sighting is not enabled for this MISP instance"})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc "GET /api/v1/threat-intel/misp/sharing-groups/:instance_id - List sharing groups"
  def list_sharing_groups(conn, %{"instance_id" => instance_id}) do
    case MISPPublisher.list_sharing_groups(instance_id) do
      {:ok, groups} ->
        json(conn, %{data: groups})

      {:error, :instance_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "MISP instance not found"})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc "POST /api/v1/threat-intel/misp/publish/iocs - Publish confirmed IOCs to MISP"
  def publish_iocs_to_misp(conn, %{"iocs" => iocs, "instance_id" => instance_id} = params) do
    opts = [
      tlp: params["tlp"] || "AMBER",
      sharing_group_id: params["sharing_group_id"],
      publish: params["auto_publish"] == true
    ]

    case MISPPublisher.publish_iocs(iocs, instance_id, opts) do
      {:ok, result} ->
        conn
        |> put_status(:created)
        |> json(%{data: result})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc "POST /api/v1/threat-intel/misp/publish/enqueue - Queue an alert for batch publishing"
  def enqueue_misp_publish(conn, %{"alert_id" => alert_id, "instance_id" => instance_id} = params) do
    opts = [
      tlp: params["tlp"] || "AMBER",
      sharing_group_id: params["sharing_group_id"],
      publish: params["auto_publish"] == true,
      tags: params["tags"] || []
    ]

    MISPPublisher.enqueue_alert(alert_id, instance_id, opts)

    json(conn, %{message: "Alert queued for MISP publishing", alert_id: alert_id, instance_id: instance_id})
  end

  @doc "GET /api/v1/threat-intel/misp/publisher/stats - Get MISP publisher queue and publish stats"
  def misp_publisher_stats(conn, _params) do
    stats = MISPPublisher.get_stats()
    json(conn, %{data: stats})
  end

  @doc "POST /api/v1/threat-intel/misp/publisher/flush - Force-flush the MISP publish queue"
  def flush_misp_queue(conn, _params) do
    MISPPublisher.flush_queue()
    json(conn, %{message: "MISP publish queue flush triggered"})
  end

  # ============================================================================
  # Threat Actors (Database-backed)
  # ============================================================================

  @doc "GET /api/v1/threat-intel/actors/db - List threat actors from database"
  def list_db_actors(conn, params) do
    opts = [
      limit: bounded_limit(params["limit"], 50, 500),
      active: params["active"] != "false"
    ]

    opts = if params["motivation"], do: Keyword.put(opts, :motivation, params["motivation"]), else: opts
    opts = if params["origin_country"], do: Keyword.put(opts, :origin_country, params["origin_country"]), else: opts
    opts = if params["search"], do: Keyword.put(opts, :search, params["search"]), else: opts

    actors = ThreatActor.list(opts)

    json(conn, %{
      data: Enum.map(actors, &serialize_threat_actor/1)
    })
  rescue
    e ->
      Logger.error("Error listing threat actors: #{inspect(e)}")
      json(conn, %{data: []})
  end

  @doc "GET /api/v1/threat-intel/actors/db/:id - Get a threat actor"
  def show_db_actor(conn, %{"id" => id}) do
    case ThreatActor.get(id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Threat actor not found"})

      actor ->
        # Get linked IOCs
        iocs = ThreatActor.get_linked_iocs(actor, limit: 20)

        json(conn, %{
          data: Map.merge(serialize_threat_actor(actor), %{
            linked_iocs: Enum.map(iocs, &serialize_ioc/1)
          })
        })
    end
  end

  @doc "POST /api/v1/threat-intel/actors/db - Create a threat actor"
  def create_db_actor(conn, params) do
    attrs = %{
      name: params["name"],
      description: params["description"],
      aliases: params["aliases"] || [],
      motivation: params["motivation"],
      sophistication: params["sophistication"],
      resource_level: params["resource_level"],
      origin_country: params["origin_country"],
      target_countries: params["target_countries"] || [],
      target_sectors: params["target_sectors"] || [],
      ttps: params["ttps"] || [],
      known_malware: params["known_malware"] || [],
      known_tools: params["known_tools"] || [],
      first_seen: parse_datetime(params["first_seen"]),
      source: "manual"
    }

    case ThreatActor.create(attrs) do
      {:ok, actor} ->
        user = conn.assigns[:current_user]
        AuditLog.log_config_change(user, "threat_intel", %{
          action: "create_threat_actor",
          actor_id: actor.id,
          actor_name: actor.name
        }, request_metadata(conn))

        conn
        |> put_status(:created)
        |> json(%{data: serialize_threat_actor(actor)})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: format_changeset_errors(changeset)})
    end
  end

  @doc "PUT /api/v1/threat-intel/actors/db/:id - Update a threat actor"
  def update_db_actor(conn, %{"id" => id} = params) do
    case ThreatActor.get(id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Threat actor not found"})

      actor ->
        attrs = Map.drop(params, ["id"])
        case ThreatActor.update(actor, attrs) do
          {:ok, updated} ->
            user = conn.assigns[:current_user]
            AuditLog.log_config_change(user, "threat_intel", %{
              action: "update_threat_actor",
              actor_id: id,
              actor_name: updated.name
            }, request_metadata(conn))

            json(conn, %{data: serialize_threat_actor(updated)})

          {:error, changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: format_changeset_errors(changeset)})
        end
    end
  end

  @doc "GET /api/v1/threat-intel/actors/stats - Get threat actor statistics"
  def actor_stats(conn, _params) do
    stats = ThreatActor.get_stats()

    json(conn, %{
      data: %{
        total: stats.total,
        active: stats.active,
        by_motivation: stats.by_motivation,
        by_country: stats.by_country
      }
    })
  rescue
    e ->
      Logger.warning("[ThreatIntelController] actor_stats failed: #{Exception.message(e)}")
      json(conn, %{
        data: %{total: 0, active: 0, by_motivation: %{}, by_country: %{}}
      })
  end

  @doc "POST /api/v1/threat-intel/actors/:id/attribute - Attribute alert to threat actor"
  def attribute_to_actor(conn, %{"id" => actor_id, "alert_id" => alert_id}) do
    org_id = current_organization_id(conn)

    case ThreatActor.get(actor_id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Threat actor not found"})

      actor when not is_nil(org_id) ->
        case Alerts.get_alert_for_org(org_id, alert_id) do
          {:ok, alert} ->
            # Find attribution matches
            attributions = ThreatActor.find_attribution(alert)

            json(conn, %{
              data: %{
                actor: serialize_threat_actor(actor),
                attributions: Enum.map(attributions, fn attr ->
                  %{
                    actor: serialize_threat_actor(attr.actor),
                    confidence: attr.confidence,
                    matching_ttps: attr.matching_ttps,
                    matching_malware: attr.matching_malware
                  }
                end)
              }
            })

          _ ->
            conn
            |> put_status(:not_found)
            |> json(%{error: "Alert not found"})
        end

      _actor ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "organization_required"})
    end
  end

  # ============================================================================
  # IOC Scoring
  # ============================================================================

  @doc "GET /api/v1/threat-intel/ioc-scoring/config - Get IOC scoring configuration"
  def ioc_scoring_config(conn, _params) do
    config = IOCScoring.get_config()

    json(conn, %{
      data: %{
        half_life_days: config.half_life_days,
        min_score_threshold: config.min_score_threshold,
        max_sighting_boost: config.max_sighting_boost,
        fp_weight: config.fp_weight,
        correlation_boost: config.correlation_boost,
        source_reputation: config.source_reputation,
        type_weights: config.type_weights
      }
    })
  rescue
    e ->
      Logger.warning("[ThreatIntelController] ioc_scoring_config failed: #{Exception.message(e)}")
      json(conn, %{
        data: %{
          half_life_days: 90,
          min_score_threshold: 20,
          max_sighting_boost: 30,
          fp_weight: 10,
          correlation_boost: 20,
          source_reputation: %{},
          type_weights: %{}
        }
      })
  end

  @doc "POST /api/v1/threat-intel/ioc-scoring/calculate - Calculate score for IOC"
  def calculate_ioc_score(conn, %{"ioc_id" => ioc_id}) do
    case get_ioc_for_current_org(conn, ioc_id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "IOC not found"})

      ioc ->
        score = IOCScoring.calculate_score(ioc)
        json(conn, %{data: score})
    end
  rescue
    e ->
      Logger.error("Error calculating IOC score: #{inspect(e)}")
      conn
      |> put_status(:internal_server_error)
      |> json(%{error: "Failed to calculate score"})
  end

  @doc "POST /api/v1/threat-intel/ioc-scoring/sighting - Record IOC sighting"
  def record_ioc_sighting(conn, %{"ioc_id" => ioc_id} = params) do
    opts = [
      source: params["source"] || "manual",
      type: String.to_existing_atom(params["type"] || "sighting")
    ]

    case get_ioc_for_current_org(conn, ioc_id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "IOC not found"})

      _ioc ->
        case IOCScoring.record_sighting(ioc_id, opts) do
          :ok ->
            json(conn, %{message: "Sighting recorded"})

          {:error, reason} ->
            conn
            |> put_status(:internal_server_error)
            |> json(%{error: inspect(reason)})
        end
    end
  rescue
    ArgumentError ->
      conn
      |> put_status(:bad_request)
      |> json(%{error: "Invalid sighting type"})
  end

  @doc "POST /api/v1/threat-intel/ioc-scoring/false-positive - Record false positive"
  def record_ioc_fp(conn, %{"ioc_id" => ioc_id} = params) do
    analyst_id = get_current_user_id(conn)

    opts = [
      reason: params["reason"],
      confidence: params["confidence"] || 1.0
    ]

    case get_ioc_for_current_org(conn, ioc_id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "IOC not found"})

      _ioc ->
        case IOCScoring.record_false_positive(ioc_id, analyst_id, opts) do
          :ok ->
            json(conn, %{message: "False positive recorded"})

          {:error, reason} ->
            conn
            |> put_status(:internal_server_error)
            |> json(%{error: inspect(reason)})
        end
    end
  end

  @doc "GET /api/v1/threat-intel/ioc-scoring/stats - Get IOC scoring statistics"
  def ioc_scoring_stats(conn, _params) do
    stats = IOCScoring.get_stats()
    json(conn, %{data: stats})
  rescue
    e ->
      Logger.warning("[ThreatIntelController] ioc_scoring_stats failed: #{Exception.message(e)}")
      json(conn, %{
        data: %{iocs_scored: 0, sightings_recorded: 0, fps_recorded: 0}
      })
  end

  @doc "GET /api/v1/threat-intel/iocs/high-confidence - Get high confidence IOCs"
  def high_confidence_iocs(conn, params) do
    opts = [
      min_score: bounded_score(params["min_score"], 70),
      limit: bounded_limit(params["limit"], 100, 500)
    ]

    opts = if params["type"], do: Keyword.put(opts, :type, params["type"]), else: opts

    iocs = IOCScoring.get_high_confidence_iocs(opts)
    json(conn, %{data: iocs})
  rescue
    e ->
      Logger.warning("[ThreatIntelController] high_confidence_iocs failed: #{Exception.message(e)}")
      json(conn, %{data: []})
  end

  @doc "POST /api/v1/threat-intel/ioc-scoring/recalculate - Recalculate all IOC scores"
  def recalculate_all_scores(conn, _params) do
    # Run in background
    Task.start(fn ->
      IOCScoring.recalculate_all()
    end)

    json(conn, %{message: "Score recalculation started"})
  end

  # ============================================================================
  # Additional Serializers
  # ============================================================================

  defp serialize_misp_instance(instance) do
    %{
      id: instance.id,
      name: instance.name,
      url: instance.url,
      enabled: instance.enabled,
      verify_ssl: instance.verify_ssl,
      pull_enabled: instance.pull_enabled,
      push_enabled: instance.push_enabled,
      trust_level: instance.trust_level,
      sync_interval_hours: instance.sync_interval_hours,
      last_sync: format_datetime(instance.last_sync),
      last_sync_status: instance.last_sync_status,
      events_synced: instance.events_synced || 0,
      iocs_imported: instance.iocs_imported || 0,
      server_version: instance.server_version,
      can_publish: instance.can_publish,
      can_sighting: instance.can_sighting,
      tags_filter: instance.tags_filter || [],
      threat_level_filter: instance.threat_level_filter || []
    }
  end

  defp serialize_misp_event(event) do
    %{
      id: event.id,
      misp_event_id: event.misp_event_id,
      uuid: event.uuid,
      info: event.info,
      threat_level_id: event.threat_level_id,
      threat_level: MISPEvent.threat_level_name(event.threat_level_id),
      analysis: event.analysis,
      analysis_status: MISPEvent.analysis_status(event.analysis),
      date: event.date,
      published: event.published,
      org_name: event.org_name,
      orgc_name: event.orgc_name,
      tags: event.tags || [],
      galaxies: event.galaxies || [],
      attribute_count: event.attribute_count,
      tlp: event.tlp,
      threat_actor_name: event.threat_actor_name,
      campaign_name: event.campaign_name,
      malware_family: event.malware_family,
      synced_at: format_datetime(event.inserted_at)
    }
  end

  defp serialize_threat_actor(actor) do
    %{
      id: actor.id,
      name: actor.name,
      description: actor.description,
      aliases: actor.aliases || [],
      motivation: actor.motivation,
      sophistication: actor.sophistication,
      resource_level: actor.resource_level,
      origin_country: actor.origin_country,
      target_countries: actor.target_countries || [],
      target_sectors: actor.target_sectors || [],
      target_regions: actor.target_regions || [],
      ttps: actor.ttps || [],
      primary_tactics: actor.primary_tactics || [],
      known_malware: actor.known_malware || [],
      known_tools: actor.known_tools || [],
      first_seen: format_datetime(actor.first_seen),
      last_seen: format_datetime(actor.last_seen),
      active: actor.active,
      source: actor.source,
      confidence: actor.confidence,
      ioc_count: actor.ioc_count || 0,
      created_at: format_datetime(actor.inserted_at)
    }
  end

  defp format_changeset_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
    |> Enum.map(fn {field, errors} -> "#{field}: #{Enum.join(errors, ", ")}" end)
    |> Enum.join("; ")
  end

  defp parse_datetime(nil), do: nil
  defp parse_datetime(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end
  defp parse_datetime(_), do: nil

  defp get_current_user_id(conn) do
    case conn.assigns[:current_user] do
      %{id: id} -> id
      _ -> "system"
    end
  end

  defp current_organization_id(conn) do
    conn.assigns[:organization_id] ||
      conn.assigns[:current_organization_id] ||
      get_in(conn.assigns, [:current_user, Access.key(:organization_id)])
  end

  defp get_ioc_for_current_org(conn, ioc_id) do
    org_id = current_organization_id(conn)

    if org_id do
      Repo.one(
        from i in TamanduaServer.Detection.IOC,
          where: i.id == ^ioc_id and i.organization_id == ^org_id,
          limit: 1
      )
    end
  end

  # ============================================================================
  # Aggregator Stats & Health
  # ============================================================================

  @doc "GET /api/v1/threat-intel/aggregator/stats - Get aggregator statistics"
  def aggregator_stats(conn, _params) do
    stats = TamanduaServer.ThreatIntel.Aggregator.get_stats()

    json(conn, %{
      data: %{
        total_ingested: stats.total_ingested,
        total_deduplicated: stats.total_deduplicated,
        total_enriched: stats.total_enriched,
        by_source: stats.by_source,
        by_type: stats.by_type,
        multi_source_count: stats.multi_source_count,
        last_ingestion: format_datetime(stats.last_ingestion),
        hot_cache_size: stats.hot_cache_size,
        dedup_index_size: stats.dedup_index_size,
        cache_hit_rate: stats.cache_hit_rate,
        enrichment_queue_size: stats.enrichment_queue_size
      }
    })
  rescue
    e ->
      Logger.warning("[ThreatIntelController] aggregator_stats failed: #{Exception.message(e)}")
      json(conn, %{data: %{
        total_ingested: 0,
        total_deduplicated: 0,
        hot_cache_size: 0,
        cache_hit_rate: 0.0
      }})
  end

  @doc "GET /api/v1/threat-intel/aggregator/health - Get feed health status"
  def aggregator_health(conn, _params) do
    health = TamanduaServer.ThreatIntel.Aggregator.get_feed_health()

    json(conn, %{
      data: Enum.map(health, fn {source, h} ->
        %{
          source: source,
          status: h.status,
          last_seen: format_datetime(h.last_seen),
          iocs_last_batch: h.iocs_last_batch
        }
      end)
    })
  rescue
    e ->
      Logger.warning("[ThreatIntelController] aggregator_health failed: #{Exception.message(e)}")
      json(conn, %{data: []})
  end

  @doc "GET /api/v1/threat-intel/aggregator/multi-source - Get multi-source IOCs"
  def multi_source_iocs(conn, params) do
    opts = [
      min_sources: bounded_min_sources(params["min_sources"], 2),
      limit: bounded_limit(params["limit"], 100, 500)
    ]

    iocs = TamanduaServer.ThreatIntel.Aggregator.get_multi_source_iocs(opts)

    json(conn, %{
      data: Enum.map(iocs, fn ioc ->
        %{
          type: ioc.type,
          value: ioc.value,
          confidence: ioc.confidence,
          severity: ioc.severity,
          sources: ioc.sources,
          source_count: ioc.source_count,
          tags: ioc.tags,
          first_seen: format_datetime(ioc.first_seen),
          last_seen: format_datetime(ioc.last_seen)
        }
      end)
    })
  rescue
    e ->
      Logger.warning("[ThreatIntelController] multi_source_iocs failed: #{Exception.message(e)}")
      json(conn, %{data: []})
  end

  @doc "POST /api/v1/threat-intel/aggregator/lookup - Fast IOC lookup"
  def fast_lookup(conn, %{"type" => type, "value" => value}) do
    type_atom = String.to_existing_atom(type)

    case TamanduaServer.ThreatIntel.Aggregator.fast_lookup(type_atom, value) do
      {:ok, data} ->
        json(conn, %{data: Map.merge(data, %{found: true})})

      :not_found ->
        json(conn, %{data: %{found: false, value: value}})

      :maybe ->
        # Need full lookup
        case TamanduaServer.ThreatIntel.Aggregator.detailed_lookup(type_atom, value) do
          {:ok, data} -> json(conn, %{data: Map.merge(data, %{found: true})})
          :not_found -> json(conn, %{data: %{found: false, value: value}})
        end
    end
  rescue
    e ->
      Logger.warning("[ThreatIntelController] fast_lookup failed: #{Exception.message(e)}")
      json(conn, %{data: %{found: false, error: "Lookup failed"}})
  end

  # ============================================================================
  # Attribution Engine
  # ============================================================================

  @doc "POST /api/v1/threat-intel/attribution/alert - Attribute an alert to threat actors"
  def attribute_alert(conn, %{"alert" => alert_params}) do
    case TamanduaServer.ThreatIntel.Attribution.attribute_alert(alert_params) do
      {:ok, attributions} ->
        json(conn, %{
          data: %{
            attributions: Enum.map(attributions, fn attr ->
              %{
                actor_id: attr.actor_id,
                actor_name: attr.actor_name,
                aliases: attr.aliases,
                motivation: attr.motivation,
                confidence: attr.confidence,
                matching_iocs: attr.matching_iocs,
                matching_ttps: attr.matching_ttps,
                matching_malware: attr.matching_malware,
                evidence: attr.evidence,
                metadata: attr.metadata
              }
            end)
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc "GET /api/v1/threat-intel/attribution/campaigns - List tracked campaigns"
  def list_attribution_campaigns(conn, params) do
    opts = [
      limit: bounded_limit(params["limit"], 50, 500),
      status: params["status"]
    ]

    campaigns = TamanduaServer.ThreatIntel.Attribution.list_campaigns(opts)

    json(conn, %{
      data: Enum.map(campaigns, fn c ->
        %{
          id: c.id,
          name: c.name,
          description: c.description,
          status: c.status,
          actors: c.actors,
          malware: c.malware,
          ttps: c.ttps,
          targets: c.targets,
          start_date: format_datetime(c.start_date),
          end_date: format_datetime(c.end_date),
          last_activity: format_datetime(c.last_activity),
          confidence: c.confidence,
          ioc_count: length(c.iocs || [])
        }
      end)
    })
  end

  @doc "GET /api/v1/threat-intel/attribution/campaigns/:id - Get campaign details"
  def get_attribution_campaign(conn, %{"id" => campaign_id}) do
    case TamanduaServer.ThreatIntel.Attribution.get_campaign(campaign_id) do
      {:ok, campaign} ->
        json(conn, %{data: campaign})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Campaign not found"})
    end
  end

  @doc "POST /api/v1/threat-intel/attribution/campaigns - Create or update a campaign"
  def upsert_attribution_campaign(conn, %{"campaign" => campaign_params}) do
    case TamanduaServer.ThreatIntel.Attribution.upsert_campaign(campaign_params) do
      {:ok, campaign} ->
        user = conn.assigns[:current_user]
        AuditLog.log_config_change(user, "threat_intel", %{
          action: "upsert_campaign",
          campaign_name: campaign_params["name"]
        }, request_metadata(conn))

        conn
        |> put_status(:created)
        |> json(%{data: campaign})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc "GET /api/v1/threat-intel/attribution/actors/:id/profile - Get detailed actor profile"
  def actor_profile(conn, %{"id" => actor_id}) do
    case TamanduaServer.ThreatIntel.Attribution.get_actor_profile(actor_id) do
      {:ok, profile} ->
        json(conn, %{data: profile})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Actor not found"})
    end
  end

  @doc "GET /api/v1/threat-intel/attribution/actors/by-ttp/:technique_id - Find actors by TTP"
  def actors_by_ttp(conn, %{"technique_id" => technique_id}) do
    actors = TamanduaServer.ThreatIntel.Attribution.find_actors_by_ttp(technique_id)
    json(conn, %{data: actors})
  end

  @doc "POST /api/v1/threat-intel/attribution/correlate - Correlate IOCs to campaigns"
  def correlate_iocs(conn, %{"iocs" => iocs}) do
    case TamanduaServer.ThreatIntel.Attribution.correlate_iocs(iocs) do
      {:ok, result} ->
        json(conn, %{data: result})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc "GET /api/v1/threat-intel/attribution/stats - Get attribution statistics"
  def attribution_stats(conn, _params) do
    stats = TamanduaServer.ThreatIntel.Attribution.get_stats()
    json(conn, %{data: stats})
  rescue
    e ->
      Logger.warning("[ThreatIntelController] attribution_stats failed: #{Exception.message(e)}")
      json(conn, %{data: %{attributions_made: 0, campaigns_tracked: 0, iocs_linked: 0}})
  end

  # ============================================================================
  # Recent Attributions (from attributed alerts)
  # ============================================================================

  @doc "GET /api/v1/threat-intel/attributions - List recent alert attributions"
  def list_attributions(conn, params) do
    limit = bounded_limit(params["limit"], 50, 500)
    offset = bounded_offset(params["offset"])

    query =
      from(a in TamanduaServer.Alerts.Alert,
        where: not is_nil(a.attribution_confidence),
        where: a.attribution_confidence > 0.0,
        where: fragment("cardinality(?) > 0", a.attributed_actors),
        order_by: [desc: a.inserted_at],
        limit: ^limit,
        offset: ^offset,
        select: %{
          alert_id: a.id,
          title: a.title,
          severity: a.severity,
          attributed_actors: a.attributed_actors,
          campaign_id: a.campaign_id,
          attribution_confidence: a.attribution_confidence,
          attribution_details: a.attribution_details,
          mitre_techniques: a.mitre_techniques,
          threat_score: a.threat_score,
          agent_id: a.agent_id,
          inserted_at: a.inserted_at
        }
      )

    attributions = Repo.all(query)

    json(conn, %{
      data: Enum.map(attributions, fn a ->
        %{
          alert_id: a.alert_id,
          title: a.title,
          severity: a.severity,
          attributed_actors: a.attributed_actors,
          campaign_id: a.campaign_id,
          attribution_confidence: a.attribution_confidence,
          attribution_details: a.attribution_details,
          mitre_techniques: a.mitre_techniques,
          threat_score: a.threat_score,
          agent_id: a.agent_id,
          attributed_at: format_datetime(a.inserted_at)
        }
      end),
      meta: %{limit: limit, offset: offset, count: length(attributions)}
    })
  rescue
    e ->
      Logger.warning("Failed to list attributions: #{inspect(e)}")
      json(conn, %{data: [], meta: %{limit: 50, offset: 0, count: 0}})
  end

  # ============================================================================
  # Campaign Tracker (auto-detected campaigns from alert clustering)
  # ============================================================================

  @doc "GET /api/v1/threat-intel/campaigns/tracked - List auto-detected campaigns"
  def list_tracked_campaigns(conn, params) do
    opts = [
      limit: bounded_limit(params["limit"], 50, 500),
      status: params["status"]
    ]

    campaigns = TamanduaServer.ThreatIntel.CampaignTracker.list_campaigns(opts)

    json(conn, %{
      data: Enum.map(campaigns, fn c ->
        %{
          id: c.id,
          name: c.name,
          actor: c.actor,
          start_time: format_datetime(c.start_time),
          end_time: format_datetime(c.end_time),
          alert_count: length(c.alert_ids || []),
          alert_ids: c.alert_ids,
          affected_agents: c.affected_agents,
          ioc_count: c.ioc_count,
          status: c.status,
          confidence: c.confidence,
          mitre_techniques: c[:mitre_techniques] || [],
          created_at: format_datetime(c[:created_at]),
          updated_at: format_datetime(c[:updated_at])
        }
      end)
    })
  rescue
    e ->
      Logger.warning("Failed to list tracked campaigns: #{inspect(e)}")
      json(conn, %{data: []})
  end

  @doc "GET /api/v1/threat-intel/campaigns/tracked/:id - Get tracked campaign details"
  def get_tracked_campaign(conn, %{"id" => campaign_id}) do
    case TamanduaServer.ThreatIntel.CampaignTracker.get_campaign(campaign_id) do
      {:ok, campaign} ->
        # Fetch the actual alerts for the timeline
        alert_ids = campaign.alert_ids || []

        alerts = if length(alert_ids) > 0 do
          from(a in TamanduaServer.Alerts.Alert,
            where: a.id in ^alert_ids,
            order_by: [asc: a.inserted_at],
            select: %{
              id: a.id,
              title: a.title,
              severity: a.severity,
              threat_score: a.threat_score,
              mitre_techniques: a.mitre_techniques,
              agent_id: a.agent_id,
              inserted_at: a.inserted_at
            }
          )
          |> Repo.all()
        else
          []
        end

        json(conn, %{
          data: %{
            id: campaign.id,
            name: campaign.name,
            actor: campaign.actor,
            start_time: format_datetime(campaign.start_time),
            end_time: format_datetime(campaign.end_time),
            alert_count: length(campaign.alert_ids || []),
            affected_agents: campaign.affected_agents,
            ioc_count: campaign.ioc_count,
            status: campaign.status,
            confidence: campaign.confidence,
            mitre_techniques: campaign[:mitre_techniques] || [],
            created_at: format_datetime(campaign[:created_at]),
            updated_at: format_datetime(campaign[:updated_at]),
            timeline: Enum.map(alerts, fn a ->
              %{
                alert_id: a.id,
                title: a.title,
                severity: a.severity,
                threat_score: a.threat_score,
                mitre_techniques: a.mitre_techniques,
                agent_id: a.agent_id,
                timestamp: format_datetime(a.inserted_at)
              }
            end)
          }
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Campaign not found"})
    end
  rescue
    e ->
      Logger.warning("Failed to get tracked campaign: #{inspect(e)}")
      conn
      |> put_status(:internal_server_error)
      |> json(%{error: "Failed to retrieve campaign"})
  end

  @doc "GET /api/v1/threat-intel/campaigns/tracked/stats - Campaign tracker stats"
  def tracked_campaign_stats(conn, _params) do
    stats = TamanduaServer.ThreatIntel.CampaignTracker.get_stats()
    json(conn, %{data: stats})
  rescue
    e ->
      Logger.warning("[ThreatIntelController] tracked_campaign_stats failed: #{Exception.message(e)}")
      json(conn, %{data: %{
        active_campaigns: 0,
        resolved_campaigns: 0,
        total_campaigns: 0,
        auto_detect_runs: 0,
        attributions_recorded: 0
      }})
  end

  @doc "GET /api/v1/threat-intel/actors/:id/profile - Full actor profile with IOCs, techniques, campaigns"
  def full_actor_profile(conn, %{"id" => actor_id}) do
    case TamanduaServer.ThreatIntel.Attribution.get_actor_profile(actor_id) do
      {:ok, profile} ->
        # Enrich with campaign tracker data
        tracked_campaigns = try do
          TamanduaServer.ThreatIntel.CampaignTracker.list_campaigns(status: "active")
          |> Enum.filter(fn c -> c.actor == get_in(profile, [:actor, :name]) end)
          |> Enum.map(fn c ->
            %{
              id: c.id,
              name: c.name,
              status: c.status,
              alert_count: length(c.alert_ids || []),
              start_time: format_datetime(c.start_time),
              end_time: format_datetime(c.end_time)
            }
          end)
        rescue
          _ -> []
        end

        # Count recent attributions for this actor
        actor_name = get_in(profile, [:actor, :name])
        recent_attributions = if actor_name do
          try do
            from(a in TamanduaServer.Alerts.Alert,
              where: ^actor_name in a.attributed_actors,
              where: a.inserted_at >= ^DateTime.add(DateTime.utc_now(), -30, :day),
              select: count(a.id)
            )
            |> Repo.one()
          rescue
            _ -> 0
          end
        else
          0
        end

        json(conn, %{
          data: %{
            actor: profile.actor,
            iocs: profile.iocs,
            ioc_count: profile.ioc_count,
            campaigns: profile.campaigns,
            tracked_campaigns: tracked_campaigns,
            related_actors: profile.related_actors,
            recent_attribution_count: recent_attributions || 0
          }
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Actor not found"})
    end
  rescue
    e ->
      Logger.warning("Failed to get actor profile: #{inspect(e)}")
      conn
      |> put_status(:internal_server_error)
      |> json(%{error: "Failed to retrieve actor profile"})
  end

  # ============================================================================
  # Commercial Feed Status
  # ============================================================================

  @doc "GET /api/v1/threat-intel/feeds/commercial/status - Get commercial feed status"
  def commercial_feeds_status(conn, _params) do
    feeds = %{
      recorded_future: get_feed_status_safe(TamanduaServer.ThreatIntel.Feeds.RecordedFuture),
      mandiant: get_feed_status_safe(TamanduaServer.ThreatIntel.Feeds.Mandiant),
      crowdstrike: get_feed_status_safe(TamanduaServer.ThreatIntel.Feeds.CrowdStrikeIntel),
      proofpoint: get_feed_status_safe(TamanduaServer.ThreatIntel.Feeds.Proofpoint)
    }

    json(conn, %{data: feeds})
  end

  @doc "GET /api/v1/threat-intel/feeds/open/status - Get open source feed status"
  def open_feeds_status(conn, _params) do
    feeds = %{
      emerging_threats: get_feed_status_safe(TamanduaServer.ThreatIntel.Feeds.EmergingThreats),
      feodo_tracker: get_feed_status_safe(TamanduaServer.ThreatIntel.Feeds.FeodoTracker),
      ssl_blacklist: get_feed_status_safe(TamanduaServer.ThreatIntel.Feeds.SSLBlacklist),
      phishtank: get_feed_status_safe(TamanduaServer.ThreatIntel.Feeds.PhishTank),
      openphish: get_feed_status_safe(TamanduaServer.ThreatIntel.Feeds.OpenPhish),
      spamhaus: get_feed_status_safe(TamanduaServer.ThreatIntel.Feeds.Spamhaus)
    }

    json(conn, %{data: feeds})
  end

  defp get_feed_status_safe(module) do
    try do
      module.get_status()
    rescue
      _ -> %{enabled: false, configured: false, error: "Module not available"}
    end
  end

  defp request_metadata(conn) do
    [
      ip_address: get_client_ip(conn),
      user_agent: get_user_agent(conn)
    ]
  end

  defp get_client_ip(conn) do
    case Plug.Conn.get_req_header(conn, "x-forwarded-for") do
      [forwarded | _] -> forwarded |> String.split(",") |> List.first() |> String.trim()
      [] -> conn.remote_ip |> :inet.ntoa() |> to_string()
    end
  end

  defp get_user_agent(conn) do
    case Plug.Conn.get_req_header(conn, "user-agent") do
      [ua | _] -> ua
      [] -> nil
    end
  end

  # ============================================================================
  # IOC Relationship Graph
  # ============================================================================

  alias TamanduaServer.ThreatIntel.Graph

  @doc "GET /api/v1/threat-intel/graph/node/:ioc_value - Get graph node with confidence"
  def graph_node(conn, %{"ioc_value" => ioc_value}) do
    case Graph.get_node(ioc_value) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "IOC not found in graph"})

      node ->
        json(conn, %{data: serialize_graph_node(node)})
    end
  rescue
    e ->
      Logger.warning("Error getting graph node: #{inspect(e)}")
      conn
      |> put_status(:internal_server_error)
      |> json(%{error: "Failed to retrieve graph node"})
  end

  @doc "GET /api/v1/threat-intel/graph/neighbors/:ioc_value - Get neighbors of a node"
  def graph_neighbors(conn, %{"ioc_value" => ioc_value} = params) do
    depth = parse_int(params["depth"], 1)
    depth = min(max(depth, 1), 3)

    edge_types = parse_edge_types(params["edge_types"])

    opts = [depth: depth]
    opts = if edge_types, do: Keyword.put(opts, :edge_types, edge_types), else: opts

    neighbors = Graph.get_neighbors(ioc_value, opts)

    json(conn, %{
      data: %{
        center: ioc_value,
        depth: depth,
        neighbors: Enum.map(neighbors, fn n ->
          %{
            node: serialize_graph_node(n[:node]),
            edge_type: n.edge_type,
            direction: n.direction,
            edge_confidence: n.edge_confidence
          }
        end),
        count: length(neighbors)
      }
    })
  rescue
    e ->
      Logger.warning("Error getting graph neighbors: #{inspect(e)}")
      json(conn, %{data: %{center: ioc_value, depth: 1, neighbors: [], count: 0}})
  end

  @doc "GET /api/v1/threat-intel/graph/paths - Find paths between two IOCs"
  def graph_paths(conn, %{"source" => source_id, "target" => target_id} = params) do
    max_depth = parse_int(params["max_depth"], 4)
    max_depth = min(max(max_depth, 1), 4)

    paths = Graph.find_paths(source_id, target_id, max_depth: max_depth)

    json(conn, %{
      data: %{
        source: source_id,
        target: target_id,
        max_depth: max_depth,
        paths: Enum.map(paths, fn path ->
          Enum.map(path, fn step ->
            %{
              node_id: step.node_id,
              from: step.from,
              edge_type: step.edge_type
            }
          end)
        end),
        path_count: length(paths)
      }
    })
  rescue
    e ->
      Logger.warning("Error finding graph paths: #{inspect(e)}")
      json(conn, %{data: %{source: params["source"], target: params["target"], paths: [], path_count: 0}})
  end

  def graph_paths(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameters: source and target"})
  end

  @doc "GET /api/v1/threat-intel/graph/subgraph/:ioc_value - Get connected component"
  def graph_subgraph(conn, %{"ioc_value" => ioc_value} = params) do
    depth = parse_int(params["depth"], 2)
    depth = min(max(depth, 1), 3)

    subgraph = Graph.get_subgraph(ioc_value, depth: depth)

    json(conn, %{
      data: %{
        center: subgraph.center,
        nodes: Enum.map(subgraph.nodes, &serialize_graph_node/1),
        edges: Enum.map(subgraph.edges, fn e ->
          %{
            source_id: e.source_id,
            target_id: e.target_id,
            edge_type: e.edge_type,
            confidence: e.confidence
          }
        end),
        node_count: subgraph.node_count,
        edge_count: subgraph.edge_count
      }
    })
  rescue
    e ->
      Logger.warning("Error getting graph subgraph: #{inspect(e)}")
      json(conn, %{data: %{center: ioc_value, nodes: [], edges: [], node_count: 0, edge_count: 0}})
  end

  @doc "GET /api/v1/threat-intel/graph/stats - Get graph statistics"
  def graph_stats(conn, _params) do
    graph_stats_data = Graph.stats()

    json(conn, %{
      data: %{
        node_count: graph_stats_data.node_count,
        edge_count: graph_stats_data.edge_count,
        source_entries: graph_stats_data.source_entries,
        node_types: graph_stats_data.node_types,
        edge_types: graph_stats_data.edge_types
      }
    })
  rescue
    e ->
      Logger.warning("Error getting graph stats: #{inspect(e)}")
      json(conn, %{data: %{node_count: 0, edge_count: 0, source_entries: 0, node_types: %{}, edge_types: %{}}})
  end

  @doc "POST /api/v1/threat-intel/graph/enrich - Enrich an alert with graph context"
  def graph_enrich(conn, %{"alert" => alert_params}) do
    enrichment = Graph.enrich_alert(alert_params)

    json(conn, %{
      data: %{
        alert_iocs: enrichment.alert_iocs,
        related_iocs: Enum.map(enrichment.related_iocs, fn ioc ->
          %{
            id: ioc.id,
            type: ioc.type,
            confidence: ioc.confidence,
            distance: ioc.distance
          }
        end),
        threat_actors: enrichment.threat_actors,
        campaigns: enrichment.campaigns,
        malware_families: enrichment.malware_families,
        vulnerabilities: enrichment.vulnerabilities,
        total_related: enrichment.total_related
      }
    })
  rescue
    e ->
      Logger.warning("Error enriching alert from graph: #{inspect(e)}")
      json(conn, %{
        data: %{
          alert_iocs: [],
          related_iocs: [],
          threat_actors: [],
          campaigns: [],
          malware_families: [],
          vulnerabilities: [],
          total_related: 0
        }
      })
  end

  def graph_enrich(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameter: alert"})
  end

  # Graph serialization helpers

  defp serialize_graph_node(nil), do: nil
  defp serialize_graph_node(node) do
    %{
      id: node[:id] || node.id,
      type: to_string(node[:type] || node.type),
      confidence: node[:confidence],
      first_seen: format_datetime(node[:first_seen]),
      last_seen: format_datetime(node[:last_seen]),
      metadata: node[:metadata] || %{}
    }
  end

  defp bounded_limit(value, default, max_limit),
    do: value |> parse_int(default) |> max(1) |> min(max_limit)

  defp bounded_offset(value), do: value |> parse_int(0) |> max(0)

  defp bounded_score(value, default), do: value |> parse_int(default) |> max(0) |> min(100)

  defp bounded_min_sources(value, default), do: value |> parse_int(default) |> max(1) |> min(25)

  defp parse_int(nil, default), do: default
  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {n, _} -> n
      :error -> default
    end
  end
  defp parse_int(val, _default) when is_integer(val), do: val
  defp parse_int(_, default), do: default

  defp parse_edge_types(nil), do: nil
  defp parse_edge_types(types) when is_binary(types) do
    types
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.map(fn t ->
      try do
        String.to_existing_atom(t)
      rescue
        ArgumentError -> nil
      end
    end)
    |> Enum.reject(&is_nil/1)
    |> case do
      [] -> nil
      list -> list
    end
  end
  defp parse_edge_types(_), do: nil
end
