# Audit Integrity Integration Guide

This guide shows how to integrate the audit log integrity verification system into Tamandua EDR.

## Quick Start

### 1. Run Migration

```bash
mix ecto.migrate
```

This creates:
- `audit_signatures` table
- Adds `merkle_proof` and `seal_id` to `audit_logs`

### 2. Start Sealer Worker

Add to your application supervision tree:

```elixir
# lib/tamandua_server/application.ex
defmodule TamanduaServer.Application do
  use Application

  def start(_type, _args) do
    children = [
      # ... existing children ...

      # Audit integrity worker
      TamanduaServer.Audit.SealerWorker,

      # ... other children ...
    ]

    opts = [strategy: :one_for_one, name: TamanduaServer.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
```

### 3. Add Route

Add to your router:

```elixir
# lib/tamandua_server_web/router.ex
scope "/", TamanduaServerWeb do
  pipe_through :browser

  # ... existing routes ...

  live "/audit/integrity", Audit.IntegrityLive, :index
end
```

### 4. Test It

```elixir
# Create some audit log entries
{:ok, _} = TamanduaServer.AuditLog.log_login(user, ip_address: "192.168.1.1")
{:ok, _} = TamanduaServer.AuditLog.log_config_change(user, "yara_rules", %{added: 5})

# Seal the batch (force for testing)
{:ok, seal} = TamanduaServer.Audit.Verifier.seal_batch(org_id, force: true)

# Verify it
{:ok, :valid} = TamanduaServer.Audit.Verifier.verify_seal(seal.id)
```

## Integration Points

### 1. Automatic Sealing

The `SealerWorker` automatically seals batches every 15 minutes if conditions are met:
- More than 10,000 unsealed entries, OR
- Oldest unsealed entry is older than 1 hour

No manual intervention needed!

### 2. Existing Audit Logs

All existing audit log functions work as before:

```elixir
# These automatically participate in the integrity system
TamanduaServer.AuditLog.log_login(user, opts)
TamanduaServer.AuditLog.log_response_action(user, "kill_process", agent_id, details)
TamanduaServer.AuditLog.log_alert_action(user, "resolve", alert_id, details)
```

Entries get sealed periodically and can be verified later.

### 3. Compliance Reports

Generate reports for auditors:

```elixir
# SOC 2 report
report = TamanduaServer.AuditLog.generate_soc2_report(org_id)

# HIPAA report
report = TamanduaServer.AuditLog.generate_hipaa_report(org_id)

# Integrity report
report = TamanduaServer.Audit.Verifier.generate_integrity_report(org_id)
```

### 4. Tampering Alerts

Subscribe to tampering detection:

```elixir
# In your GenServer or LiveView
Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "audit:tampering")

def handle_info({:tampering_detected, org_id, errors}, state) do
  # CRITICAL ALERT
  Logger.error("Tampering detected in org #{org_id}")

  # Send notifications
  TamanduaServer.Alerts.create_alert(%{
    severity: :critical,
    title: "Audit Log Tampering Detected",
    description: "#{length(errors)} sealed batches have been tampered with",
    organization_id: org_id
  })

  # Notify security team
  TamanduaServer.Mailer.send_security_alert(org_id, :tampering, errors)

  {:noreply, state}
end
```

## API Integration

### REST API Endpoints

Add these to your API router:

```elixir
# lib/tamandua_server_web/controllers/api/v1/audit_integrity_controller.ex
defmodule TamanduaServerWeb.API.V1.AuditIntegrityController do
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Audit.Verifier

  def seal_batch(conn, _params) do
    org_id = conn.assigns.current_user.organization_id

    case Verifier.seal_batch(org_id, force: true) do
      {:ok, seal} ->
        json(conn, %{
          status: "sealed",
          seal_number: seal.seal_number,
          entry_count: seal.entry_count,
          merkle_root: seal.merkle_root,
          sealed_at: seal.sealed_at
        })

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: to_string(reason)})
    end
  end

  def verify_entry(conn, %{"id" => entry_id}) do
    case Verifier.verify_entry(entry_id) do
      {:ok, :valid} ->
        json(conn, %{verified: true, status: "valid"})

      {:error, reason} ->
        json(conn, %{verified: false, error: to_string(reason)})
    end
  end

  def integrity_report(conn, _params) do
    org_id = conn.assigns.current_user.organization_id
    report = Verifier.generate_integrity_report(org_id)

    json(conn, report)
  end
end
```

Router:
```elixir
scope "/api/v1", TamanduaServerWeb.API.V1, as: :api_v1 do
  pipe_through :api

  post "/audit/seal", AuditIntegrityController, :seal_batch
  get "/audit/verify/:id", AuditIntegrityController, :verify_entry
  get "/audit/report", AuditIntegrityController, :integrity_report
end
```

### GraphQL Integration

```elixir
# lib/tamandua_server_web/graphql/types/audit_types.ex
defmodule TamanduaServerWeb.GraphQL.Types.AuditTypes do
  use Absinthe.Schema.Notation

  object :audit_seal do
    field :id, non_null(:id)
    field :seal_number, non_null(:integer)
    field :entry_count, non_null(:integer)
    field :merkle_root, non_null(:string)
    field :sealed_at, non_null(:datetime)
    field :verification_status, :string
  end

  object :integrity_report do
    field :organization_id, non_null(:id)
    field :summary, :report_summary
    field :generated_at, non_null(:datetime)
  end

  object :report_summary do
    field :total_seals, non_null(:integer)
    field :valid_seals, non_null(:integer)
    field :invalid_seals, non_null(:integer)
    field :integrity_score, non_null(:float)
  end
end

# lib/tamandua_server_web/graphql/resolvers/audit_resolver.ex
defmodule TamanduaServerWeb.GraphQL.Resolvers.AuditResolver do
  alias TamanduaServer.Audit.Verifier

  def seal_batch(_parent, _args, %{context: %{current_user: user}}) do
    case Verifier.seal_batch(user.organization_id, force: true) do
      {:ok, seal} -> {:ok, seal}
      {:error, reason} -> {:error, message: to_string(reason)}
    end
  end

  def verify_entry(_parent, %{id: entry_id}, _context) do
    case Verifier.verify_entry(entry_id) do
      {:ok, :valid} -> {:ok, %{verified: true}}
      {:error, reason} -> {:ok, %{verified: false, error: to_string(reason)}}
    end
  end

  def integrity_report(_parent, _args, %{context: %{current_user: user}}) do
    report = Verifier.generate_integrity_report(user.organization_id)
    {:ok, report}
  end
end

# In your schema
object :audit_queries do
  field :integrity_report, :integrity_report do
    resolve &Resolvers.AuditResolver.integrity_report/3
  end

  field :verify_audit_entry, :verification_result do
    arg :id, non_null(:id)
    resolve &Resolvers.AuditResolver.verify_entry/3
  end
end

object :audit_mutations do
  field :seal_audit_batch, :audit_seal do
    resolve &Resolvers.AuditResolver.seal_batch/3
  end
end
```

## External Verification

### Export Public Key

For external auditors to verify seals:

```elixir
# Get organization's current signing key
keypair = TamanduaServer.Audit.Signature.get_or_create_signing_key(org_id)

# Export public key in PEM format
pem = TamanduaServer.Audit.Signature.export_public_key_pem(keypair.public_key)

File.write!("org_#{org_id}_audit_pubkey.pem", pem)
```

### Verify Externally (Python Example)

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import json

# Load public key
with open('org_audit_pubkey.pem', 'rb') as f:
    public_key = serialization.load_pem_public_key(f.read())

# Get seal from API
seal = requests.get('https://tamandua.example/api/v1/audit/seal/123').json()

# Verify signature
merkle_root = seal['merkle_root'].encode()
signature = bytes.fromhex(seal['signature'])

try:
    public_key.verify(signature, merkle_root)
    print("✓ Seal signature is valid")
except:
    print("✗ Seal signature is INVALID - TAMPERING DETECTED")
```

## Monitoring Integration

### Prometheus Metrics

```elixir
# lib/tamandua_server/metrics.ex
defmodule TamanduaServer.Metrics do
  use Prometheus.Metric

  def setup do
    # Audit integrity metrics
    Gauge.declare(
      name: :audit_unsealed_entries_total,
      help: "Number of unsealed audit log entries",
      labels: [:organization_id]
    )

    Counter.declare(
      name: :audit_seals_total,
      help: "Total number of audit log seals created",
      labels: [:organization_id]
    )

    Counter.declare(
      name: :audit_tampering_detected_total,
      help: "Number of times tampering was detected",
      labels: [:organization_id]
    )

    Histogram.declare(
      name: :audit_seal_duration_seconds,
      help: "Time taken to seal audit batch",
      labels: [:organization_id]
    )
  end

  def record_seal(org_id, entry_count, duration_ms) do
    Counter.inc(name: :audit_seals_total, labels: [org_id])
    Histogram.observe(
      [name: :audit_seal_duration_seconds, labels: [org_id]],
      duration_ms / 1000
    )
  end

  def record_tampering(org_id) do
    Counter.inc(name: :audit_tampering_detected_total, labels: [org_id])
  end

  def update_unsealed_count(org_id, count) do
    Gauge.set([name: :audit_unsealed_entries_total, labels: [org_id]], count)
  end
end
```

### Datadog Integration

```elixir
# Report to Datadog
defp report_seal_metrics(seal, duration_ms) do
  tags = [
    "organization_id:#{seal.organization_id}",
    "seal_number:#{seal.seal_number}"
  ]

  # Seal created
  DogStatsd.increment("audit.seal.created", tags: tags)

  # Entry count
  DogStatsd.gauge("audit.seal.entry_count", seal.entry_count, tags: tags)

  # Duration
  DogStatsd.histogram("audit.seal.duration", duration_ms, tags: tags)
end

defp report_tampering(org_id, error_count) do
  tags = ["organization_id:#{org_id}", "severity:critical"]

  DogStatsd.increment("audit.tampering.detected", tags: tags)
  DogStatsd.gauge("audit.tampering.error_count", error_count, tags: tags)

  # Send event
  DogStatsd.event("Audit Log Tampering Detected",
    "#{error_count} sealed batches have invalid signatures",
    alert_type: "error",
    tags: tags
  )
end
```

## Scheduled Tasks

### Cron Jobs (if not using SealerWorker)

```elixir
# config/config.exs
config :tamandua_server, TamanduaServer.Scheduler,
  jobs: [
    # Seal audit batches every 15 minutes
    {"*/15 * * * *", {TamanduaServer.Audit.Verifier, :seal_all_pending, []}},

    # Verify integrity every 6 hours
    {"0 */6 * * *", {TamanduaServer.Audit.IntegrityChecker, :verify_all, []}},

    # Generate compliance reports weekly
    {"0 0 * * 0", {TamanduaServer.Audit.ComplianceReporter, :generate_weekly_reports, []}}
  ]
```

### Oban Jobs

```elixir
# lib/tamandua_server/jobs/audit_seal_job.ex
defmodule TamanduaServer.Jobs.AuditSealJob do
  use Oban.Worker, queue: :audit, max_attempts: 3

  alias TamanduaServer.Audit.Verifier

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"organization_id" => org_id}}) do
    case Verifier.auto_seal(org_id) do
      {:ok, %Signature{}} -> :ok
      {:ok, :not_needed} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end
end

# Schedule for all organizations
defp schedule_audit_seals do
  organizations = Repo.all(Organization)

  Enum.each(organizations, fn org ->
    %{organization_id: org.id}
    |> TamanduaServer.Jobs.AuditSealJob.new()
    |> Oban.insert()
  end)
end
```

## Testing in Development

```elixir
# Create test data
user = TamanduaServer.Repo.get_by!(TamanduaServer.Accounts.User, email: "admin@example.com")

# Generate lots of audit entries
for i <- 1..100 do
  TamanduaServer.AuditLog.log(%{
    organization_id: user.organization_id,
    user_id: user.id,
    user_email: user.email,
    action: "test_action_#{i}",
    action_type: "test",
    resource_type: "test_resource",
    resource_id: "resource_#{i}",
    severity: :info
  })
end

# Force seal
{:ok, seal} = TamanduaServer.Audit.Verifier.seal_batch(user.organization_id, force: true)

IO.inspect(seal)

# Verify it
{:ok, :all_valid} = TamanduaServer.Audit.Verifier.verify_seal(seal.id)

# Check tampering
{:ok, :no_tampering} = TamanduaServer.Audit.Verifier.check_tampering(user.organization_id)

# Generate report
report = TamanduaServer.Audit.Verifier.generate_integrity_report(user.organization_id)
IO.inspect(report.summary)

# Visit UI
# http://localhost:4000/audit/integrity
```

## Production Checklist

- [ ] Run migrations
- [ ] Configure KMS/Vault for key storage (CRITICAL!)
- [ ] Add SealerWorker to supervision tree
- [ ] Add route to router
- [ ] Configure seal intervals (optional)
- [ ] Set up monitoring/alerts
- [ ] Test sealing process
- [ ] Test tampering detection
- [ ] Train security team on dashboard
- [ ] Document key rotation procedures
- [ ] Set up compliance reporting schedule
- [ ] Configure external verification (optional)

## Troubleshooting

### No seals being created

Check:
1. SealerWorker is running: `Process.whereis(TamanduaServer.Audit.SealerWorker)`
2. Unsealed entries exist: `Verifier.count_unsealed_entries(org_id)`
3. Conditions met: `Verifier.auto_seal(org_id)`

### Verification failures

Check:
1. Seal signature valid: `Signature.verify_seal(seal)`
2. Entry has proof: `entry.merkle_proof`
3. Logs for errors

### Performance issues

Optimize:
1. Add database indexes
2. Adjust batch size
3. Use async verification
4. Archive old seals

## Support

For issues or questions:
- Check logs: `tail -f log/dev.log | grep Audit`
- Test in IEx: `iex -S mix phx.server`
- Review README.md for API details
