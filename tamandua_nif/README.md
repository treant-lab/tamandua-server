# Tamandua NIF

Native Implemented Functions (NIFs) for high-performance operations in Tamandua EDR.

## Overview

This library provides Rust-based NIFs for performance-critical operations in the Tamandua backend:

- **YARA Scanning**: Fast malware detection with YARA rules
- **Hashing**: Efficient SHA256, SHA1, MD5 computation
- **Entropy Analysis**: Shannon entropy and packing detection
- **Sigma Rules**: Parse and match Sigma detection rules
- **IOC Matching**: IP, domain, and hash matching with wildcards

## Architecture

```
┌─────────────────────────────────────────┐
│         Elixir Application              │
│   TamanduaServer.Native module          │
└────────────────┬────────────────────────┘
                 │ FFI (Rustler)
┌────────────────▼────────────────────────┐
│          Rust NIF Library               │
│                                         │
│  ┌──────────┐  ┌──────────┐            │
│  │  YARA    │  │  Hashing │            │
│  │ Scanner  │  │          │            │
│  └──────────┘  └──────────┘            │
│                                         │
│  ┌──────────┐  ┌──────────┐            │
│  │ Entropy  │  │  Sigma   │            │
│  │ Analysis │  │  Rules   │            │
│  └──────────┘  └──────────┘            │
│                                         │
│  ┌──────────────────────┐              │
│  │   IOC Matching       │              │
│  └──────────────────────┘              │
└─────────────────────────────────────────┘
```

## Features

### YARA Scanning

Compile and scan with YARA rules for malware detection:

```elixir
# Compile rules
{:ok, rules} = TamanduaServer.Native.compile_rules("""
rule ransomware {
  strings:
    $s1 = "encrypt"
    $s2 = "ransom"
  condition:
    all of them
}
""")

# Scan file
{:ok, matches} = TamanduaServer.Native.scan_file(rules, "/suspicious/file.exe")

# Scan memory/bytes
{:ok, matches} = TamanduaServer.Native.scan_bytes(rules, binary_data)
```

### Multi-Hash (Efficient)

Calculate multiple hashes in a single pass:

```elixir
# Much faster than calling sha256, sha1, md5 separately
{:ok, {sha256, sha1, md5, size}} =
  TamanduaServer.Native.multi_hash_file("/path/to/file")
```

### Entropy Analysis

Detect packed/encrypted executables:

```elixir
# Calculate Shannon entropy
{:ok, entropy} = TamanduaServer.Native.calculate_file("/path/to/file")

# Detect packing
{:ok, is_packed} = TamanduaServer.Native.detect_packed(binary_data)

# Comprehensive analysis
{:ok, analysis} = TamanduaServer.Native.analyze_file("/path/to/file")
# Returns: %{entropy: 7.8, is_packed: true, file_size: 12345, high_entropy_regions: [...]}
```

### Sigma Rules

Parse and match Sigma detection rules:

```elixir
# Parse Sigma rule
{:ok, rule} = TamanduaServer.Native.parse_rule("""
id: test-001
title: Suspicious PowerShell
logsource:
  product: windows
detection:
  selection:
    EventID: 4688
    CommandLine: "*powershell*"
  condition: selection
""")

# Match event
event = %{"EventID" => "4688", "CommandLine" => "powershell.exe -enc ..."}
{:ok, matched} = TamanduaServer.Native.match_event(
  Jason.encode!(rule),
  Jason.encode!(event)
)
```

### IOC Matching

Fast IOC matching with wildcards and CIDR support:

```elixir
# IP matching with CIDR
{:ok, true} = TamanduaServer.Native.match_ip("192.168.1.50", "192.168.1.0/24")

# Domain matching with wildcards
{:ok, true} = TamanduaServer.Native.match_domain("sub.evil.com", "*.evil.com")

# Extract IOCs from text
text = "Connect to 192.168.1.1 or visit evil.com"
{:ok, iocs} = TamanduaServer.Native.extract_iocs(text)
# Returns: %{ips: [...], domains: [...], urls: [...], hashes: [...], emails: [...]}
```

## Building

### Prerequisites

- Rust toolchain (1.70+)
- Elixir 1.14+
- YARA library (optional, for YARA feature)

### Development Build

```bash
cd apps/tamandua_nif
mix deps.get
mix compile
```

### Production Build

```bash
MIX_ENV=prod mix compile
```

The Rust code is compiled in release mode for production, with optimizations:
- LTO (Link-Time Optimization)
- Single codegen unit
- Optimized for speed
- Stripped symbols

### Cross-Compilation

For precompiled binaries:

```bash
# Linux (GNU)
cargo build --release --target x86_64-unknown-linux-gnu

# Linux (MUSL)
cargo build --release --target x86_64-unknown-linux-musl

# Windows
cargo build --release --target x86_64-pc-windows-msvc

# macOS (Intel)
cargo build --release --target x86_64-apple-darwin

# macOS (Apple Silicon)
cargo build --release --target aarch64-apple-darwin
```

## Testing

```bash
# Run all tests
mix test

# Run only NIF tests
mix test --only native

# Run with benchmarks
mix test --include benchmark
```

## Performance

### Benchmarks

On a typical workstation (Intel i7, 16GB RAM):

- **Multi-hash**: ~2GB/s (10x faster than sequential hashing)
- **Entropy**: ~1GB/s for full file analysis
- **YARA scanning**: ~500MB/s (depends on rule complexity)
- **IOC matching**: <1μs per comparison

### Memory Usage

- **YARA rules**: ~5-10MB per compiled ruleset
- **Entropy analysis**: Streaming (constant memory)
- **Hashing**: 8KB buffer (constant memory)

## Features

The Rust crate supports optional features:

- `yara` (default): Enable YARA scanning support
  - Requires YARA library installed
  - To disable: Add `default-features = false` in mix.exs

## Error Handling

All NIFs return standard Elixir tuples:

```elixir
{:ok, result}     # Success
{:error, message} # Error with description
```

Common errors:
- `"File not found"`: Invalid file path
- `"Invalid IP"`: Malformed IP address
- `"YAML parse error"`: Invalid Sigma rule syntax
- `"Compilation failed"`: YARA rule syntax error

## Precompiled Binaries

For CI/CD and distribution, precompiled binaries are supported via `rustler_precompiled`:

```elixir
# In mix.exs
{:rustler_precompiled, "~> 0.7"}
```

Supported targets:
- Linux (x86_64, GNU and MUSL)
- Windows (x86_64, MSVC and GNU)
- macOS (x86_64 and ARM64)

## Integration

### In Detection Engine

```elixir
defmodule TamanduaServer.Detection.Engine do
  alias TamanduaServer.Native

  def analyze_file(path) do
    with {:ok, {sha256, sha1, md5, size}} <- Native.multi_hash_file(path),
         {:ok, entropy} <- Native.calculate_file(path),
         {:ok, is_packed} <- Native.detect_packed(File.read!(path)),
         {:ok, matches} <- scan_yara(path) do
      %{
        hashes: %{sha256: sha256, sha1: sha1, md5: md5},
        size: size,
        entropy: entropy,
        is_packed: is_packed,
        yara_matches: matches
      }
    end
  end

  defp scan_yara(path) do
    {:ok, rules} = load_compiled_rules()
    Native.scan_file(rules, path)
  end
end
```

### In IOC Checker

```elixir
defmodule TamanduaServer.ThreatIntel.IocChecker do
  alias TamanduaServer.Native

  def check_network_iocs(event) do
    iocs = load_network_iocs()

    with {:ok, ip_matches} <- Native.match_iocs_batch(
           event.ips,
           iocs.ips,
           "ip"
         ),
         {:ok, domain_matches} <- Native.match_iocs_batch(
           event.domains,
           iocs.domains,
           "domain"
         ) do
      ip_matches ++ domain_matches
    end
  end
end
```

## Safety

NIFs are inherently unsafe and can crash the BEAM VM if they:
1. Panic or segfault
2. Block for extended periods
3. Consume excessive memory

This library mitigates these risks:

- **Panic Safety**: All operations use `Result<T, E>` with proper error handling
- **Timeouts**: YARA scans have 60-second timeout
- **Memory Limits**: File operations limited to 100MB
- **Non-Blocking**: All operations complete quickly or stream data

## License

MIT License - See LICENSE file

## Contributing

1. Add tests for new functionality
2. Run `cargo clippy` and `cargo test`
3. Ensure benchmarks show performance improvement
4. Update documentation

## References

- [Rustler Documentation](https://docs.rs/rustler/)
- [YARA Documentation](https://yara.readthedocs.io/)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [Firezone wireguardex](https://github.com/firezone/wireguardex) (reference pattern)
