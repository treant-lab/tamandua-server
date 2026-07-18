defmodule TamanduaServer.Telemetry.Enrichment do
  @moduledoc """
  Parent module for telemetry event enrichment.

  Enrichment adds context to raw telemetry events by looking up:
  - Threat intelligence (IOCs from threat feeds)
  - Geographic and ASN information (IP geolocation)
  - Asset context (hostname, OS, tags, criticality)
  - User context (email, department, role)

  ## Architecture

  Enrichment happens in two phases:

  ### Phase 1: Synchronous (Fast)
  Happens inline in the Broadway pipeline before persistence.
  Uses cached lookups to avoid blocking. Includes:
  - Threat intel lookups (cached IOC database)
  - GeoIP lookups (cached MMDB or API)
  - Asset context (cached agent metadata)

  ### Phase 2: Asynchronous (Slow)
  Happens after event persistence via AsyncWorker.
  Handles expensive operations:
  - External API calls
  - Deep threat intel analysis
  - ML-based enrichment
  - Historical context building

  ## Usage

  The enrichment pipeline is automatically invoked by the Ingestor:

      # In the Broadway pipeline
      event
      |> Enrichment.ThreatIntel.enrich_event()
      |> Enrichment.Geo.enrich_event()
      |> Enrichment.Asset.enrich_event()

  ## Enrichment Schema

  The enrichment field is a JSONB map with the following structure:

      %{
        threat_intel: %{
          ip: [%{type: "ip", value: "1.2.3.4", source: "malwarebazaar", ...}],
          hash_sha256: [%{type: "hash_sha256", value: "abc123...", ...}]
        },
        geo: %{
          "1.2.3.4" => %{country_code: "US", city: "San Francisco", asn: 15169, ...}
        },
        asset: %{
          hostname: "workstation-1",
          os_type: "windows",
          criticality: "high",
          tags: ["engineering", "production"]
        },
        user: %{
          email: "jsmith@example.com",
          department: "Engineering",
          is_admin: false
        },
        analysis: %{...}  # Legacy field from detection engine
      }

  ## Performance

  - **Caching**: All lookups are cached with appropriate TTLs
    - Threat intel: 1 hour
    - GeoIP: 24 hours
    - Asset context: 5 minutes
    - User context: 10 minutes

  - **Batch processing**: IOC lookups are batched for efficiency

  - **Non-blocking**: Enrichment never crashes the pipeline
    - All enrichment functions are wrapped in try/rescue
    - Failed lookups are logged but don't block event processing

  ## Modules

  - `Enrichment.ThreatIntel` - IOC and threat feed matching
  - `Enrichment.Geo` - IP geolocation and ASN resolution
  - `Enrichment.Asset` - Agent/endpoint context
  - `Enrichment.User` - User account context
  - `Enrichment.Cache` - Shared caching layer
  - `Enrichment.AsyncWorker` - Asynchronous enrichment queue
  """

  # Re-export submodules for convenience
  alias __MODULE__.{ThreatIntel, Geo, Asset, User, Cache, AsyncWorker}

  defdelegate enrich_threat_intel(event), to: ThreatIntel, as: :enrich_event
  defdelegate enrich_geo(event), to: Geo, as: :enrich_event
  defdelegate enrich_asset(event), to: Asset, as: :enrich_event
  defdelegate enrich_user(event), to: User, as: :enrich_event

  defdelegate get_or_lookup_threat_intel(type, value), to: Cache
  defdelegate get_or_lookup_geo(ip), to: Cache
  defdelegate get_or_lookup_asset(agent_id), to: Cache
  defdelegate get_or_lookup_user(username), to: Cache

  defdelegate enrich_async(event_id), to: AsyncWorker
  defdelegate enrich_async_batch(event_ids), to: AsyncWorker

  @doc """
  Apply all fast enrichments to an event.

  This is the main entry point for synchronous enrichment in the pipeline.
  """
  def enrich_all(event) do
    event
    |> ThreatIntel.enrich_event()
    |> Geo.enrich_event()
    |> Asset.enrich_event()
    |> User.enrich_event()
  end

  @doc """
  Clear all enrichment caches.
  """
  def clear_caches do
    Cache.clear_all()
  end

  @doc """
  Get enrichment statistics.

  Returns cache stats and async worker stats.
  """
  def stats do
    %{
      # entry_stats/0 is the hand-written per-type breakdown; Cache.stats/0
      # is the Nebulex-generated adapter counters and previously shadowed it.
      cache: Cache.entry_stats(),
      async_worker: AsyncWorker.stats()
    }
  end
end
