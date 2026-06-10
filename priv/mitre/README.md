# MITRE ATT&CK Data

This directory contains MITRE ATT&CK framework data in STIX 2.0 format.

## Quick Start

### 1. Download Latest Data

```bash
# From project root
cd apps/tamandua_server

# Download latest enterprise attack data
curl -o priv/mitre/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

Or use the Elixir helper:

```elixir
# In iex -S mix
TamanduaServer.Mitre.AttackFramework.download_latest_stix()
```

### 2. Import Data

```bash
# Run migration first
mix ecto.migrate

# Then import data
mix run -e "TamanduaServer.Mitre.AttackFramework.import_attack_data(force: true)"
```

## Data Sources

### Official MITRE CTI Repository

The canonical source for ATT&CK data:
- **Repository**: https://github.com/mitre/cti
- **Enterprise ATT&CK**: `enterprise-attack/enterprise-attack.json`
- **Mobile ATT&CK**: `mobile-attack/mobile-attack.json`
- **ICS ATT&CK**: `ics-attack/ics-attack.json`

### Update Frequency

MITRE updates ATT&CK approximately quarterly. Check for updates:
- https://attack.mitre.org/resources/updates/

## File Structure

```
priv/mitre/
├── README.md                    # This file
├── enterprise-attack.json       # Main ATT&CK data (download separately)
├── tactics.json                 # Tactic definitions (optional)
├── techniques.json              # Technique catalog (optional)
└── threat-actors.json           # APT group data (optional)
```

## STIX Format

The data uses STIX 2.0 (Structured Threat Information Expression) format.

### Key Object Types

1. **attack-pattern**: Techniques and sub-techniques
2. **intrusion-set**: Threat actor groups (APTs)
3. **malware**: Malware families
4. **tool**: Software tools
5. **course-of-action**: Mitigations
6. **relationship**: Links between objects

### Example Technique

```json
{
  "type": "attack-pattern",
  "id": "attack-pattern--...",
  "created": "2017-05-31T21:30:44.329Z",
  "modified": "2023-03-30T14:26:51.867Z",
  "name": "PowerShell",
  "description": "Adversaries may abuse PowerShell...",
  "kill_chain_phases": [
    {
      "kill_chain_name": "mitre-attack",
      "phase_name": "execution"
    }
  ],
  "external_references": [
    {
      "source_name": "mitre-attack",
      "external_id": "T1059.001",
      "url": "https://attack.mitre.org/techniques/T1059/001"
    }
  ],
  "x_mitre_platforms": ["Windows"],
  "x_mitre_data_sources": ["Process: Process Creation"],
  "x_mitre_detection": "Detection guidance...",
  "x_mitre_version": "2.3"
}
```

## Custom Data

You can supplement official data with custom techniques:

### Custom Technique Example

Create `priv/mitre/custom-techniques.json`:

```json
[
  {
    "technique_id": "T9001",
    "name": "Custom Lateral Movement Technique",
    "description": "Organization-specific technique",
    "platforms": ["windows", "linux"],
    "tactics": ["TA0008"],
    "is_subtechnique": false,
    "detection_guidance": "Monitor for unusual SMB traffic patterns",
    "metadata": {
      "custom": true,
      "organization": "acme-corp"
    }
  }
]
```

Then import:

```elixir
TamanduaServer.Mitre.AttackFramework.import_attack_data(
  source: "priv/mitre/custom-techniques.json",
  force: true
)
```

## Version Tracking

Track which ATT&CK version you're using:

```sql
-- Check imported data version
SELECT metadata->>'version' as version,
       COUNT(*) as technique_count
FROM mitre_techniques
GROUP BY metadata->>'version';
```

## Maintenance

### Update Workflow

1. Download latest STIX bundle
2. Review changes (compare versions)
3. Test import in dev environment
4. Run import with `force: true`
5. Verify technique counts
6. Re-sync rule mappings

### Backup Before Update

```bash
# Backup current data
pg_dump -t mitre_techniques -t mitre_threat_actors tamandua_dev > mitre_backup.sql

# Import new data
mix run -e "TamanduaServer.Mitre.AttackFramework.import_attack_data(force: true)"

# If issues, restore
psql tamandua_dev < mitre_backup.sql
```

## Performance

The enterprise-attack.json file contains ~600 techniques and ~130 threat actors.

Import times:
- Initial import: ~10-30 seconds
- Force re-import: ~15-45 seconds

Database size:
- ~2-5 MB for techniques table
- ~1-2 MB for threat actors table

## Troubleshooting

### Import Fails with "Invalid STIX Format"

- Verify JSON is valid: `jq . enterprise-attack.json`
- Check file is not truncated
- Re-download from official source

### Missing Techniques

- Ensure you're using enterprise-attack.json (not mobile or ICS)
- Check MITRE version (v14+ recommended)
- Verify no filters applied during import

### Slow Import

- Use database indexes (created by migration)
- Import in transaction (default)
- Consider batching for very large datasets

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE CTI Repository](https://github.com/mitre/cti)
- [STIX 2.0 Specification](https://docs.oasis-open.org/cti/stix/v2.0/stix-v2.0-part1-stix-core.html)
- [ATT&CK Data Model](https://attack.mitre.org/resources/working-with-attack/)
