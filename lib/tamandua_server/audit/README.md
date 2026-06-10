# Audit Log Integrity Verification

Cryptographic log integrity verification system using Merkle trees and Ed25519 digital signatures.

## Overview

The audit integrity system provides tamper-proof logging for compliance and forensic purposes. It uses a combination of:

- **Merkle Trees**: Efficient cryptographic data structure for verifying log entries
- **Ed25519 Signatures**: Fast, secure digital signatures for sealing log batches
- **Periodic Sealing**: Automatic batch sealing every hour or 10,000 entries
- **Merkle Proofs**: Individual entry verification without full tree reconstruction

## Architecture

```
┌─────────────┐
│ Audit Logs  │  Each entry gets:
│   Entries   │  - SHA256 hash (entry_hash)
└──────┬──────┘  - Sequence number
       │         - Previous hash (chain)
       │
       ▼
┌─────────────┐
│   Sealing   │  Every 1hr or 10K entries:
│   Process   │  1. Build Merkle tree
└──────┬──────┘  2. Generate root hash
       │         3. Sign with Ed25519
       │         4. Store signature
       ▼
┌─────────────┐
│   Sealed    │  Contains:
│   Batches   │  - Merkle root hash
└──────┬──────┘  - Digital signature
       │         - Public key
       │         - Sequence range
       ▼
┌─────────────┐
│ Merkle Tree │  Structure:
│   Proofs    │  - Leaf hashes (entries)
└──────┬──────┘  - Branch hashes (pairs)
       │         - Root hash (signed)
       │
       ▼
┌─────────────┐
│Verification │  Checks:
│   Process   │  1. Merkle proof validity
└─────────────┘  2. Signature verification
                 3. Chain integrity
```

## Components

### 1. MerkleTree (`merkle_tree.ex`)

Builds and verifies Merkle trees from audit log entries.

**Key Functions:**
- `build/1` - Build tree from entries
- `root_hash/1` - Get tree root hash for signing
- `generate_proof/2` - Create proof for specific entry
- `verify_proof/3` - Verify entry proof against root
- `verify_tree/1` - Verify entire tree structure

**Example:**
```elixir
# Build tree from entries
tree = MerkleTree.build(entries)

# Get root hash
root = MerkleTree.root_hash(tree)

# Generate proof for entry
proof = MerkleTree.generate_proof(tree, entry.id)

# Verify proof
MerkleTree.verify_proof(entry, proof, root)
# => true
```

### 2. Signature (`signature.ex`)

Ed25519 digital signature management.

**Key Functions:**
- `generate_keypair/0` - Create new Ed25519 keypair
- `sign/2` - Sign data with private key
- `verify/3` - Verify signature with public key
- `get_or_create_signing_key/1` - Get org signing key
- `rotate_signing_key/1` - Rotate organization keys
- `verify_seal/1` - Verify sealed batch signature

**Example:**
```elixir
# Generate keypair
keypair = Signature.generate_keypair()

# Sign data
signature = Signature.sign(merkle_root, keypair.private_key)

# Verify
Signature.verify(merkle_root, signature, keypair.public_key)
# => true
```

### 3. Verifier (`verifier.ex`)

Main integrity verification orchestrator.

**Key Functions:**
- `seal_batch/2` - Seal batch of unsealed entries
- `auto_seal/1` - Auto-seal if conditions met
- `seal_all_pending/0` - Seal across all organizations
- `verify_entry/1` - Verify specific entry
- `verify_seal/1` - Verify entire sealed batch
- `check_tampering/2` - Scan for tampering
- `generate_integrity_report/2` - Compliance report

**Example:**
```elixir
# Manual seal
{:ok, seal} = Verifier.seal_batch(org_id, force: true)

# Verify entry
{:ok, :valid} = Verifier.verify_entry(entry_id)

# Check for tampering
case Verifier.check_tampering(org_id) do
  {:ok, :no_tampering} -> :ok
  {:error, {:tampering_detected, details}} -> :alert!
end
```

### 4. SealerWorker (`sealer_worker.ex`)

Background worker for automatic sealing.

**Schedule:**
- Seal check: Every 15 minutes
- Integrity verification: Every 6 hours

**Broadcasts:**
- `audit:seals` - New seals created
- `audit:tampering` - Tampering detected

## Database Schema

### audit_signatures

```sql
CREATE TABLE audit_signatures (
  id               UUID PRIMARY KEY,
  organization_id  UUID REFERENCES organizations,
  seal_number      BIGINT NOT NULL,
  start_sequence   BIGINT NOT NULL,
  end_sequence     BIGINT NOT NULL,
  entry_count      INTEGER NOT NULL,
  merkle_root      TEXT NOT NULL,
  signature        BYTEA NOT NULL,    -- 64 bytes (Ed25519)
  public_key       BYTEA NOT NULL,    -- 32 bytes (Ed25519)
  sealed_at        TIMESTAMP NOT NULL,
  verified_at      TIMESTAMP,
  verification_status TEXT DEFAULT 'pending',
  verification_details JSONB DEFAULT '{}'::jsonb
);
```

### audit_logs (enhanced)

```sql
ALTER TABLE audit_logs
  ADD COLUMN merkle_proof JSONB,
  ADD COLUMN seal_id UUID REFERENCES audit_signatures;
```

**merkle_proof format:**
```json
{
  "proof": [
    {"hash": "abc123...", "position": "left"},
    {"hash": "def456...", "position": "right"}
  ],
  "root_hash": "xyz789..."
}
```

## Sealing Process

### Trigger Conditions

Automatic sealing occurs when:
1. **Time-based**: Oldest unsealed entry > 1 hour old, OR
2. **Volume-based**: Unsealed entries ≥ 10,000

### Steps

1. **Fetch Unsealed Entries**
   ```elixir
   entries = get_unsealed_entries(org_id, 10_000)
   ```

2. **Build Merkle Tree**
   ```elixir
   tree = MerkleTree.build(entries)
   root_hash = MerkleTree.root_hash(tree)
   ```

3. **Generate Proofs**
   ```elixir
   proofs = MerkleTree.generate_all_proofs(tree, entries)
   ```

4. **Sign Root Hash**
   ```elixir
   keypair = Signature.get_or_create_signing_key(org_id)
   signature = Signature.sign(root_hash, keypair.private_key)
   ```

5. **Store Seal Record**
   ```elixir
   %Signature{
     merkle_root: root_hash,
     signature: signature,
     public_key: keypair.public_key,
     ...
   }
   ```

6. **Update Entries**
   ```elixir
   UPDATE audit_logs
   SET seal_id = seal.id,
       merkle_proof = proof
   WHERE id IN (...)
   ```

## Verification Process

### Entry Verification

1. Check entry has seal and proof
2. Verify seal signature
3. Verify Merkle proof against root
4. Confirm root hash matches seal

```elixir
def verify_entry_with_seal(entry, seal) do
  # 1. Verify seal signature
  {:ok, :valid} = Signature.verify_seal(seal)

  # 2. Verify Merkle proof
  proof = entry.merkle_proof["proof"]
  root = entry.merkle_proof["root_hash"]

  # 3. Check proof
  true = MerkleTree.verify_proof(entry, proof, root)

  # 4. Confirm root matches seal
  true = (root == seal.merkle_root)
end
```

### Batch Verification

1. Verify seal signature
2. Fetch all entries in batch
3. Verify each entry's Merkle proof
4. Report any invalid entries

### Tampering Detection

Iterates through all sealed batches:
- Verifies each seal's signature
- Checks all entries in each seal
- Updates verification status
- Alerts on failures

## Security Properties

### Tamper Detection

Any modification to a sealed entry will:
1. **Break Merkle proof** - Entry hash won't match
2. **Break signature** - If root is modified
3. **Break chain** - If sequence modified

### Non-Repudiation

- Ed25519 signatures provide cryptographic proof
- Public keys stored with seals
- Cannot forge signatures without private key
- Private keys never exposed

### Forensic Integrity

- Merkle proofs allow entry-specific verification
- Full audit trail preserved
- Compliance-ready (SOC 2, HIPAA, GDPR, PCI DSS)
- Exportable integrity reports

## API Examples

### Seal Current Batch

```elixir
{:ok, seal} = Verifier.seal_batch(org_id, force: true)

IO.inspect seal
# %Signature{
#   seal_number: 42,
#   entry_count: 1337,
#   merkle_root: "a1b2c3...",
#   signature: <<...>>,
#   sealed_at: ~U[2026-02-20 10:00:00Z]
# }
```

### Verify Entry

```elixir
case Verifier.verify_entry(entry_id) do
  {:ok, :valid} ->
    IO.puts "Entry verified"

  {:error, :entry_not_sealed} ->
    IO.puts "Entry not yet sealed"

  {:error, :invalid_merkle_proof} ->
    IO.puts "TAMPERING DETECTED"
end
```

### Generate Integrity Report

```elixir
report = Verifier.generate_integrity_report(org_id)

IO.inspect report.summary
# %{
#   total_seals: 100,
#   valid_seals: 100,
#   invalid_seals: 0,
#   integrity_score: 100.0,
#   unsealed_entries: 42
# }
```

### Check for Tampering

```elixir
case Verifier.check_tampering(org_id) do
  {:ok, :no_tampering} ->
    Logger.info "Integrity verified"

  {:error, {:tampering_detected, errors}} ->
    Logger.error "TAMPERING in #{length(errors)} seals"
    alert_security_team(errors)
end
```

## Compliance Reports

### SOC 2 Type II
- Access control verification
- Change management audit
- Incident response tracking
- Data protection evidence

### HIPAA
- PHI access logs
- User activity tracking
- Security incident documentation
- Configuration change history

### GDPR
- Data subject access reports
- Processing activity logs
- Retention compliance
- Right to be forgotten audit

## Performance Considerations

### Merkle Tree Complexity

- **Build**: O(n) where n = number of entries
- **Proof Generation**: O(log n)
- **Proof Verification**: O(log n)
- **Storage**: O(n) for all proofs

### Batch Size Tuning

- **Smaller batches**: More frequent sealing, higher overhead
- **Larger batches**: Less frequent sealing, verification delays
- **Default: 10K entries** balances these tradeoffs

### Database Indexes

Critical indexes:
```sql
CREATE INDEX idx_audit_logs_seal_id ON audit_logs(seal_id);
CREATE INDEX idx_audit_logs_unsealed ON audit_logs(organization_id)
  WHERE seal_id IS NULL;
CREATE INDEX idx_signatures_org_seal ON audit_signatures(organization_id, seal_number);
```

## Key Management

### Current Implementation

- Keys stored in Application environment (DEV ONLY)
- Cached in `:persistent_term`
- One keypair per organization

### Production Requirements

**CRITICAL**: Current key storage is NOT production-ready!

Must integrate with:
- **AWS KMS** - Key Management Service
- **HashiCorp Vault** - Secrets management
- **Azure Key Vault** - Cloud key storage
- **Hardware HSM** - For maximum security

### Key Rotation

```elixir
# Rotate organization signing key
{:ok, new_keypair} = Signature.rotate_signing_key(org_id)

# Old seals remain valid with their original public keys
# New seals use the new keypair
```

## Monitoring & Alerts

### Metrics to Track

- Unsealed entry count
- Seal frequency
- Verification success rate
- Tampering incidents
- Key rotation events

### Alert Conditions

- **CRITICAL**: Tampering detected
- **WARNING**: Unsealed entries > 50K
- **WARNING**: Verification failures
- **INFO**: Batch sealed
- **INFO**: Key rotated

## Testing

Run tests:
```bash
mix test test/tamandua_server/audit/
```

Test coverage:
- Merkle tree operations
- Ed25519 signatures
- Sealing process
- Verification logic
- Tampering detection

## UI Dashboard

Access at: `/audit/integrity`

Features:
- View sealed batches
- Verify individual seals
- Check for tampering
- Generate integrity reports
- Export reports (JSON)
- Real-time statistics

## Future Enhancements

1. **Blockchain Anchoring**
   - Anchor root hashes to public blockchain
   - Provides external timestamp proof
   - Cannot be backdated

2. **Multi-Signature**
   - Require multiple keys to seal
   - Prevents single-point compromise
   - Higher security for critical orgs

3. **Zero-Knowledge Proofs**
   - Prove integrity without revealing data
   - Privacy-preserving verification
   - Regulatory compliance

4. **Distributed Verification**
   - External validators
   - Consensus-based sealing
   - Decentralized trust

## References

- [Merkle Trees](https://en.wikipedia.org/wiki/Merkle_tree)
- [Ed25519 Signatures](https://ed25519.cr.yp.to/)
- [NIST SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [SOC 2 Compliance](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html)
