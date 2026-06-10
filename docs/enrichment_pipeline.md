# Enrichment Pipeline Documentation

## Overview

The Enrichment Pipeline adds contextual intelligence to raw telemetry events by correlating them with threat intelligence, geographic data, asset metadata, and user context. This enrichment enables faster triage, better detection, and richer analytics.

## Architecture

### Two-Phase Enrichment

#### Phase 1: Synchronous (Fast)
Happens inline in the Broadway pipeline before database persistence.

**Modules:**
- `TamanduaServer.Telemetry.Enrichment.ThreatIntel` - IOC matching
- `TamanduaServer.Telemetry.Enrichment.Geo` - IP geolocation
- `TamanduaServer.Telemetry.Enrichment.Asset` - Agent metadata
- `TamanduaServer.Telemetry.Enrichment.User` - User account context

**Performance:**
- All lookups are cached (Nebulex)
- Non-blocking: failures don't crash pipeline
- Batch processing for IOC lookups
- Target: <10ms per event

#### Phase 2: Asynchronous (Deep)
Happens after persistence via `AsyncWorker` GenServer.

**Operations:**
- External API calls (VirusTotal, etc.)
- ML-based enrichment
- Historical context building
- Deep threat analysis

**Performance:**
- Queue-based processing
- Concurrent workers (configurable)
- Timeout protection
- Backpressure handling

### Data Flow

```
Raw Event
    ↓
[Ingestor: handle_message]
    ↓
[enrich_event]
    ├─→ ThreatIntel.enrich_event()  ← IOC database + ETS cache
    ├─→ Geo.enrich_event()          ← GeoIP MMDB + API fallback
    ├─→ Asset.enrich_event()        ← Agent registry
    └─→ sanitize_null_bytes()
    ↓
[persist_events] → PostgreSQL (enrichment JSONB column)
    ↓
[AsyncWorker.enrich_async] (optional deep enrichment)
    ↓
[update enrichment field]
```

## Enrichment Schema

Events are enriched with a structured JSONB map:

```elixir
%{
  enrichment: %{
    # Threat Intelligence Matches
    threat_intel: %{
      ip: [
        %{
          type: "ip",
          value: "192.0.2.1",
          source: "malwarebazaar",
          severity: "critical",
          confidence: 0.95,
          tags: ["malware", "c2"],
          malware_family: "Emotet",
          threat_actor: "TA505",
          first_seen: ~U[2024-01-01 00:00:00Z],
          last_seen: ~U[2024-02-01 00:00:00Z]
        }
      ],
      hash_sha256: [...]
    },

    # Geographic Data
    geo: %{
      "192.0.2.1" => %{
        country_code: "US",
        country_name: "United States",
        city: "San Francisco",
        region: "California",
        latitude: 37.7749,
        longitude: -122.4194,
        asn: 15169,
        asn_org: "Google LLC",
        is_tor: false,
        is_proxy: false,
        is_datacenter: true,
        is_high_risk_country: false,
        risk_score: 20
      }
    },

    # Asset Context
    asset: %{
      hostname: "workstation-1",
      os_type: "windows",
      os_version: "Windows 11",
      tags: ["engineering", "production"],
      criticality: "high",
      location: "HQ-SanFrancisco",
      organization_id: "org-123"
    },

    # User Context
    user: %{
      email: "jsmith@example.com",
      department: "Engineering",
      is_admin: false
    },

    # Legacy analysis field (from detection engine)
    analysis: %{...}
  }
}
```

## Caching Strategy

### Cache TTLs

| Data Type | TTL | Rationale |
|-----------|-----|-----------|
| Threat Intel | 1 hour | IOCs change frequently |
| GeoIP | 24 hours | Geographic data is stable |
| Asset Context | 5 minutes | Agent metadata may change |
| User Context | 10 minutes | User data is relatively stable |

### Cache Implementation

Uses Nebulex (Erlang ETS-backed cache) for:
- Fast local lookups (microseconds)
- TTL-based expiration
- Memory-efficient storage
- Process-isolated caching

Cache keys:
```elixir
{:threat_intel, ioc_type, ioc_value}
{:geo_ip, ip_address}
{:asset, agent_id}
{:user, username}
```

## Threat Intelligence Enrichment

### IOC Extraction

The `ThreatIntel.enrich_event/1` function extracts observables from events:

**Network Events:**
- IP addresses (remote_ip, source_ip, dest_ip)
- Domains (hostname, domain)
- Excludes private IPs (RFC 1918)

**Process Events:**
- File hashes (MD5, SHA1, SHA256)
- Filenames (from image_path)

**File Events:**
- File hashes (MD5, SHA1, SHA256)
- Filenames (from path)

**DNS Events:**
- Domain queries

### IOC Lookup

1. **Database Lookup** - `TamanduaServer.Detection.IOCs`
   - Persistent IOC database
   - Imported from threat feeds
   - Manual IOC additions

2. **ETS Cache Lookup** - `TamanduaServer.ThreatIntel`
   - In-memory IOC cache
   - Feed-sourced indicators
   - Fast lookups

3. **Batch Processing**
   - IOCs grouped by type
   - Single query per type
   - Reduces database load

### Supported IOC Types

- `ip` - IPv4/IPv6 addresses
- `domain` - Domain names
- `hash_md5` - MD5 file hashes
- `hash_sha1` - SHA1 file hashes
- `hash_sha256` - SHA256 file hashes
- `url` - URLs
- `email` - Email addresses
- `filename` - File names

## Geographic Enrichment

### GeoIP Resolution

Uses MaxMind GeoLite2 databases:

1. **City Database** - Country, city, coordinates
2. **ASN Database** - Autonomous System Number and organization

### Fallback Strategy

If MMDB databases are not available:
1. Try local database first
2. Fall back to ip-api.com (free tier)
3. Cache results to minimize API calls

### Risk Scoring

Geographic risk score (0-100):
- Tor exit nodes: +40
- Proxy/VPN: +30
- Datacenter IP: +20
- High-risk country: +20

High-risk countries (configurable):
- RU, CN, KP, IR, SY

## Asset Enrichment

Adds agent/endpoint context from the Agent Registry:

```elixir
%{
  hostname: "workstation-1",
  os_type: "windows",
  os_version: "Windows 11 Pro",
  tags: ["engineering", "production", "critical"],
  criticality: "high",
  location: "HQ-SanFrancisco",
  organization_id: "org-abc123"
}
```

Used for:
- Alert prioritization
- Context in investigations
- Asset-based detection rules
- Compliance reporting

## User Enrichment

Adds user account context when events contain usernames:

```elixir
%{
  email: "jsmith@example.com",
  department: "Engineering",
  role: "Senior Engineer",
  is_admin: false,
  risk_score: 25
}
```

**Note:** User enrichment currently returns `:not_implemented`. Integration with user directory (AD, LDAP, etc.) is required.

## Asynchronous Enrichment

### AsyncWorker Architecture

GenServer-based queue for expensive enrichment:

```elixir
# Queue events for async enrichment
Enrichment.enrich_async("event-id-123")

# Batch enqueue
Enrichment.enrich_async_batch(["event-1", "event-2", "event-3"])
```

### Configuration

- **Max Queue Size:** 10,000 events
- **Batch Size:** 10 events per batch
- **Process Interval:** 100ms
- **Concurrency:** 4 workers
- **Timeout:** 30 seconds per event

### Statistics

Monitor async worker:

```elixir
Enrichment.AsyncWorker.stats()
# => %{
#      queue_size: 42,
#      processed: 1234,
#      failed: 5,
#      uptime_seconds: 3600,
#      throughput: 0.34  # events/sec
#    }
```

## Performance Optimization

### 1. Caching

All enrichment lookups are cached:
- First lookup: database/API query
- Subsequent lookups: cache hit (microseconds)

### 2. Batch Processing

IOC lookups are batched by type:
```elixir
# Instead of 10 queries
[query(ip, "1.2.3.4"), query(ip, "5.6.7.8"), ...]

# Single batched query
query(ip, ["1.2.3.4", "5.6.7.8", ...])
```

### 3. Non-Blocking

Enrichment never crashes the pipeline:
- All functions wrapped in try/rescue
- Failed lookups logged and skipped
- Events persist even if enrichment fails

### 4. Private IP Filtering

Private IPs excluded from GeoIP lookups:
- 10.0.0.0/8
- 172.16.0.0/12
- 192.168.0.0/16
- 127.0.0.0/8 (loopback)
- 169.254.0.0/16 (link-local)

### 5. Observable Type Detection

Generic extraction uses heuristics:
- IP regex matching
- Domain validation
- Hash length detection (32/40/64 chars)

## Database Indexes

For efficient enrichment queries:

```sql
-- GIN index for JSONB queries
CREATE INDEX events_enrichment_gin_idx
ON events USING GIN (enrichment jsonb_path_ops);

-- Functional indexes for common queries
CREATE INDEX events_enrichment_threat_intel_idx
ON events ((enrichment->'threat_intel'))
WHERE enrichment ? 'threat_intel';

CREATE INDEX events_enrichment_geo_idx
ON events ((enrichment->'geo'))
WHERE enrichment ? 'geo';
```

## Querying Enriched Events

### Find events with threat intel matches

```elixir
from e in Event,
  where: fragment("? ? 'threat_intel'", e.enrichment)
```

### Find events from high-risk countries

```elixir
from e in Event,
  where: fragment("""
    EXISTS (
      SELECT 1 FROM jsonb_each(? -> 'geo') AS geo
      WHERE (geo.value->>'is_high_risk_country')::boolean = true
    )
  """, e.enrichment)
```

### Find events matching specific IOC

```elixir
from e in Event,
  where: fragment("""
    ? @> ?::jsonb
  """, e.enrichment,
    Jason.encode!(%{
      threat_intel: %{
        ip: [%{value: "192.0.2.1"}]
      }
    })
  )
```

## Monitoring

### Cache Statistics

```elixir
Enrichment.Cache.stats()
# => %{
#      total_entries: 1234,
#      threat_intel_entries: 500,
#      geo_entries: 400,
#      asset_entries: 200,
#      user_entries: 134
#    }
```

### Clear Caches

```elixir
# Clear all caches
Enrichment.clear_caches()

# Clear specific cache
Enrichment.Cache.clear_threat_intel()
Enrichment.Cache.clear_geo()
```

### Full Statistics

```elixir
Enrichment.stats()
# => %{
#      cache: %{total_entries: 1234, ...},
#      async_worker: %{queue_size: 42, ...}
#    }
```

## Configuration

### GeoIP Database Path

```elixir
# config/config.exs
config :tamandua_server,
  geoip_db_path: "/var/lib/tamandua/geoip"
```

Download GeoLite2 databases:
1. Sign up at MaxMind
2. Download GeoLite2-City.mmdb
3. Download GeoLite2-ASN.mmdb
4. Place in configured path

### Threat Intel Feeds

Configure feeds in `TamanduaServer.ThreatIntel`:

```elixir
# Environment variables
OTX_API_KEY=your-api-key
ABUSEIPDB_API_KEY=your-api-key
```

## Troubleshooting

### Enrichment not appearing

1. Check cache is running:
   ```elixir
   GenServer.whereis(TamanduaServer.Telemetry.Enrichment.Cache)
   ```

2. Check for errors in logs:
   ```bash
   grep "Enrichment failed" log/dev.log
   ```

3. Verify IOC database has data:
   ```elixir
   TamanduaServer.Detection.IOCs.count()
   ```

### Slow enrichment

1. Check cache hit rate (add logging)
2. Monitor async worker queue:
   ```elixir
   Enrichment.AsyncWorker.stats()
   ```
3. Verify GeoIP database is loaded:
   ```elixir
   TamanduaServer.Enrichment.GeoIP.lookup("8.8.8.8")
   ```

### High memory usage

1. Clear caches periodically:
   ```elixir
   Enrichment.clear_caches()
   ```

2. Reduce cache TTLs in `Cache` module

3. Monitor async worker queue size

## Future Enhancements

1. **User Directory Integration**
   - Active Directory connector
   - LDAP integration
   - Azure AD sync

2. **Advanced Threat Intel**
   - VirusTotal lookups
   - Shodan integration
   - Commercial feed support

3. **ML-Based Enrichment**
   - Behavioral scoring
   - Anomaly detection
   - Risk prediction

4. **Historical Context**
   - Previous detections on asset
   - User activity baseline
   - Process lineage

5. **External APIs**
   - IP reputation services
   - Certificate transparency logs
   - Malware sandboxes

## API Reference

See module documentation:
- `TamanduaServer.Telemetry.Enrichment`
- `TamanduaServer.Telemetry.Enrichment.ThreatIntel`
- `TamanduaServer.Telemetry.Enrichment.Geo`
- `TamanduaServer.Telemetry.Enrichment.Asset`
- `TamanduaServer.Telemetry.Enrichment.User`
- `TamanduaServer.Telemetry.Enrichment.Cache`
- `TamanduaServer.Telemetry.Enrichment.AsyncWorker`
