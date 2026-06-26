# Tamandua Backup Module

AES-256-GCM encrypted backup system with envelope encryption and secure key management.

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                   Backup Module                        │
├────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────┐ │
│  │  Scheduler  │───▶│  Encryptor   │◀──▶│  Vault   │ │
│  │   (Oban)    │    │ (AES-256-GCM)│    │  Client  │ │
│  └─────────────┘    └──────────────┘    └──────────┘ │
│         │                   │                          │
│         ▼                   ▼                          │
│  ┌─────────────────────────────────────────────────┐  │
│  │          Backup Modules                         │  │
│  ├─────────────────────────────────────────────────┤  │
│  │  • PostgresBackup   - Database dumps + WAL      │  │
│  │  • RedisBackup      - RDB snapshots + AOF       │  │
│  │  • ClickHouseBackup - Table exports             │  │
│  │  • ConfigBackup     - YARA/Sigma/IOC rules      │  │
│  │  • MLModelBackup    - PyTorch models            │  │
│  └─────────────────────────────────────────────────┘  │
│                          │                             │
│                          ▼                             │
│  ┌─────────────────────────────────────────────────┐  │
│  │            Verifier                             │  │
│  │  • Integrity checks                             │  │
│  │  • Restore testing                              │  │
│  │  • Monthly verification                         │  │
│  └─────────────────────────────────────────────────┘  │
│                                                         │
└────────────────────────────────────────────────────────┘
```

## Modules

### Encryptor

Core encryption/decryption module using AES-256-GCM with envelope encryption.

**Features:**
- Random DEK (Data Encryption Key) per backup
- KEK (Key Encryption Key) from Vault
- HMAC-SHA256 integrity verification
- Compression (zlib)
- File-level encryption

**Usage:**

```elixir
# Encrypt data
{:ok, encrypted, metadata} = Encryptor.encrypt(data, compression: 9)

# Decrypt data
{:ok, decrypted} = Encryptor.decrypt(encrypted)

# Encrypt file
Encryptor.encrypt_file("backup.sql", "backup.sql.enc")

# Decrypt file
Encryptor.decrypt_file("backup.sql.enc", "backup.sql")

# Rotate encryption keys
{:ok, re_encrypted, new_metadata} = Encryptor.rotate_keys(old_encrypted)
```

### VaultClient

HashiCorp Vault integration for secure key management.

**Features:**
- Master key storage and retrieval
- Key rotation support
- Key versioning for backward compatibility
- In-memory caching (1 hour TTL)
- Fallback to environment variable (dev only)

**Usage:**

```elixir
# Get current master key
{:ok, master_key} = VaultClient.get_master_key()

# Rotate master key
{:ok, new_version} = VaultClient.rotate_master_key()

# Get specific key version
{:ok, old_key} = VaultClient.get_key_version(1)

# Invalidate cache
VaultClient.invalidate_cache()
```

### Scheduler

Oban-based backup scheduling and orchestration.

**Features:**
- Daily full backups (2 AM UTC)
- Hourly incremental backups
- Monthly restore verification (1st of month, 3 AM UTC)
- Daily cleanup (4 AM UTC)
- 30-day retention

**Usage:**

```elixir
# Schedule recurring jobs (called on app start)
Scheduler.schedule_recurring_jobs()

# Trigger manual backups
{:ok, job} = Scheduler.trigger_full_backup()
{:ok, job} = Scheduler.trigger_incremental_backup()

# Verify restore capability
{:ok, job} = Scheduler.trigger_verify_restore()
```

### Verifier

Backup integrity verification and restore testing.

**Features:**
- Encryption format validation
- HMAC verification
- Full decryption testing
- Automated restore tests
- Verification reports (JSON/HTML/text)

**Usage:**

```elixir
# Verify single backup
{:ok, result} = Verifier.verify_backup("/backups/postgres.sql.enc")

# Verify directory
{:ok, results} = Verifier.verify_backup_directory("/backups/full_20260220")

# Test restore procedure
{:ok, report} = Verifier.test_restore("/backups/full_20260220")

# Generate verification report
{:ok, report} = Verifier.generate_verification_report(
  "/var/backups/tamandua",
  format: :json,
  output_file: "/reports/backup_health.json"
)
```

### Component Backup Modules

#### PostgresBackup

PostgreSQL database backup and restore.

```elixir
# Full dump
{:ok, sql_dump} = PostgresBackup.dump_database()

# Archive WAL logs
{:ok, wal_archive} = PostgresBackup.archive_wal_logs()

# Restore from dump
PostgresBackup.restore_from_dump("dump.sql", "target_db")
```

#### RedisBackup

Redis snapshot and AOF backup.

```elixir
# RDB snapshot
{:ok, rdb_data} = RedisBackup.save_snapshot()

# AOF file
{:ok, aof_data} = RedisBackup.get_aof()

# Background save (non-blocking)
{:ok, :scheduled} = RedisBackup.background_save()

# Restore from RDB
RedisBackup.restore_from_rdb("dump.rdb", target_db: 0)
```

#### ClickHouseBackup

ClickHouse table export and restore.

```elixir
# Export all data
{:ok, archive_path} = ClickHouseBackup.export_data()

# Restore from archive
ClickHouseBackup.restore_from_archive("clickhouse_backup.tar")
```

#### ConfigBackup

Configuration files and detection rules backup.

```elixir
# Archive configs
{:ok, archive} = ConfigBackup.archive_configs()

# Restore configs
ConfigBackup.restore_from_archive("configs.tar.gz")

# Validate configs
{:ok, errors} = ConfigBackup.validate_configs("/path/to/configs")
```

#### MLModelBackup

Machine learning model backup and validation.

```elixir
# Archive ML models
{:ok, archive} = MLModelBackup.archive_models()

# Restore models
MLModelBackup.restore_from_archive("ml_models.tar.gz")

# List models
{:ok, models} = MLModelBackup.list_models()

# Validate models
{:ok, errors} = MLModelBackup.validate_models("/app/models")
```

## Encrypted File Format

```
┌─────────────────────────────────────────────────────────┐
│ Offset │ Field         │ Size    │ Description          │
├────────┼───────────────┼─────────┼──────────────────────┤
│ 0      │ Version       │ 1 byte  │ Format version (1)   │
│ 1      │ IV            │ 12 bytes│ AES-GCM IV           │
│ 13     │ Encrypted DEK │ 48 bytes│ DEK + tag            │
│ 61     │ Tag           │ 16 bytes│ AES-GCM auth tag     │
│ 77     │ Encrypted Data│ Variable│ Compressed data      │
│ N-32   │ HMAC          │ 32 bytes│ SHA-256 HMAC         │
└─────────────────────────────────────────────────────────┘
```

## Configuration

### Runtime Configuration

Add to `config/runtime.exs`:

```elixir
# Vault configuration
config :tamandua_server, TamanduaServer.Backup.VaultClient,
  vault_url: System.get_env("VAULT_ADDR") || "http://localhost:8200",
  vault_token: System.get_env("VAULT_TOKEN"),
  vault_path: "secret/data/tamandua/backup",
  key_name: "master_encryption_key",
  fallback_key: System.get_env("BACKUP_MASTER_KEY")  # Dev only

# Backup paths
config :tamandua_server,
  backup_dir: System.get_env("BACKUP_ROOT") || "/var/backups/tamandua",
  postgres_wal_dir: "/var/lib/postgresql/data/pg_wal",
  clickhouse_url: System.get_env("CLICKHOUSE_URL") || "http://localhost:8123",
  redis_url: System.get_env("REDIS_URL") || "redis://localhost:6379",
  ml_models_dir: System.get_env("ML_MODELS_DIR") || "/app/models"
```

### Application Supervision

Add to `application.ex`:

```elixir
def start(_type, _args) do
  children = [
    # ... existing children ...
    TamanduaServer.Backup.VaultClient,
    {Oban, Application.fetch_env!(:tamandua_server, Oban)}
  ]

  # Schedule recurring backup jobs
  Task.start(fn ->
    Process.sleep(5000)
    TamanduaServer.Backup.Scheduler.schedule_recurring_jobs()
  end)

  Supervisor.start_link(children, opts)
end
```

### Oban Configuration

Add to `config/config.exs`:

```elixir
config :tamandua_server, Oban,
  repo: TamanduaServer.Repo,
  queues: [
    default: 10,
    backups: 1  # Single worker for backups to avoid conflicts
  ],
  plugins: [
    Oban.Plugins.Pruner,
    {Oban.Plugins.Cron,
     crontab: [
       {"0 2 * * *", TamanduaServer.Backup.Scheduler, args: %{type: "full_backup"}},
       {"0 * * * *", TamanduaServer.Backup.Scheduler, args: %{type: "incremental_backup"}},
       {"0 3 1 * *", TamanduaServer.Backup.Scheduler, args: %{type: "verify_restore"}},
       {"0 4 * * *", TamanduaServer.Backup.Scheduler, args: %{type: "cleanup_old_backups"}}
     ]}
  ]
```

## Environment Variables

```bash
# Vault
VAULT_ADDR=https://vault.example.com:8200
VAULT_TOKEN=hvs.XXXXXXXXXXXXXXXXXXXXX

# Backup
BACKUP_ROOT=/var/backups/tamandua
RETENTION_DAYS=30

# Databases
DATABASE_URL=postgresql://tamandua:password@localhost:5432/tamandua_dev
REDIS_URL=redis://localhost:6379
CLICKHOUSE_URL=http://localhost:8123

# Paths
APP_ROOT=/opt/tamandua/apps/tamandua_server
ML_MODELS_DIR=/opt/tamandua/models

# Alerts (optional)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
ALERT_EMAIL=ops@example.com
```

## Testing

```bash
# Run all backup tests
mix test test/tamandua_server/backup/

# Run specific test file
mix test test/tamandua_server/backup/encryptor_test.exs

# Run with coverage
mix coveralls.html --include backup:true
```

## Security Best Practices

1. **Never commit master keys** - Use Vault or environment variables
2. **Rotate keys annually** - Schedule during maintenance windows
3. **Test restores monthly** - Automated via Scheduler
4. **Monitor backup health** - Check verification reports
5. **Off-site backups** - Copy to different region/cloud
6. **Audit access** - Log all backup operations
7. **Encrypt transfers** - Use TLS/SSH for backup copies
8. **Validate integrity** - Run verification before critical operations

## Troubleshooting

### Common Issues

**"No master key available"**
- Check Vault connectivity
- Verify VAULT_TOKEN is set
- Ensure secret exists: `vault kv get secret/tamandua/backup`

**"HMAC verification failed"**
- Backup may be corrupted
- Check if correct key version is being used
- Verify disk integrity

**"Permission denied"**
- Check backup directory permissions
- Ensure write access to BACKUP_ROOT
- Verify PostgreSQL/Redis data directory access

**Backup size suddenly changed**
- May indicate database corruption
- Check application logs for errors
- Verify backup completeness

## Performance

### Optimization Tips

1. **Parallel backups** - Run component backups concurrently
2. **Compression tuning** - Adjust level based on CPU/size tradeoff
3. **Incremental backups** - Use hourly incrementals, weekly fulls
4. **Network optimization** - Use local storage for backups
5. **Resource limits** - Monitor CPU/memory during backups

### Benchmarks

Typical backup times (production-sized dataset):

- PostgreSQL (100GB): 15-20 minutes
- Redis (10GB): 2-3 minutes
- ClickHouse (500GB): 30-45 minutes
- Configs (100MB): <1 minute
- ML Models (5GB): 3-5 minutes

Total full backup: ~1 hour

## Disaster Recovery

See [BACKUP_RESTORE.md](../../../../../docs/BACKUP_RESTORE.md) for complete disaster recovery procedures.

## References

- [AES-GCM Specification](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [NIST Key Management](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
- [HashiCorp Vault](https://www.vaultproject.io/docs)
- [Envelope Encryption](https://cloud.google.com/kms/docs/envelope-encryption)
