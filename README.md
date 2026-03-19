# arkd-rs

**Rust implementation of [arkd](https://github.com/arkade-os/arkd) by the [Arkade team](https://github.com/arkade-os)** — Ark protocol server for Bitcoin Layer 2 scaling.

---

## What is arkd?

arkd is a server implementation of the **Ark protocol**, a Bitcoin scaling solution that enables fast, low-cost off-chain Bitcoin transactions with on-chain security guarantees.

---

## Why Rust?

**Advantages over the Go implementation:**

- 🔒 **Memory safety at compile time** — no null pointers, no data races, no memory leaks without `unsafe`
- ⚡ **Deterministic, zero-GC performance** — no garbage collector pauses during round finalization or signing sessions
- 🛠️ **Native Bitcoin ecosystem** — `rust-bitcoin`, `BDK`, `secp256k1` are first-class; Go relies on `btcd` ports
- 🔐 **Stronger type system** — protocol invariants encoded in types, not just documentation
- 📦 **Single static binary** — no runtime dependencies, simpler deployment than Go's dynamic linking

---

## What's Implemented

arkd-rs is a full behavioral-parity Rust reimplementation of the Go arkd server. It covers the complete Ark protocol: VTXO tree construction, round management, MuSig2 signing (BIP-327), fraud detection, forfeit verification (Tapscript), SQLite/PostgreSQL persistence, Esplora scanning, gRPC API (ArkService + AdminService + WalletService + IndexerService + SignerManagerService), CEL-based fee programs, macaroon auth + TLS auto-generation, Nostr VTXO notifications, OpenTelemetry scaffolding, and a regtest E2E integration test suite.

---

## Project Structure

```
arkd-rs/
├── src/
│   ├── main.rs           # Server binary entry point
│   ├── cli.rs            # CLI argument parsing
│   ├── config.rs         # Configuration loading
│   └── telemetry.rs      # OpenTelemetry setup
├── crates/
│   ├── arkd-core/        # Core domain models and business logic (rounds, VTXOs, exits)
│   ├── arkd-bitcoin/     # Bitcoin primitives (PSBTs, Tapscript, MuSig2, TxBuilder)
│   ├── arkd-wallet/      # BDK-based Bitcoin wallet service (UTXO management, signing)
│   ├── arkd-api/         # gRPC API layer (tonic + prost) — all gRPC services
│   ├── arkd-client/      # gRPC client library for arkd-rs
│   ├── arkd-db/          # Database layer (SQLite, PostgreSQL, migrations)
│   ├── arkd-live-store/  # Ephemeral round state (in-memory + Redis)
│   ├── arkd-fee-manager/ # Fee estimation (static + Bitcoin Core RPC + CEL programs)
│   ├── arkd-scanner/     # Blockchain scanner for on-chain VTXO watching (Esplora)
│   ├── arkd-scheduler/   # Time-based and block-height-based round schedulers
│   ├── arkd-nostr/       # Nostr event publishing for VTXO notifications
│   └── ark-cli/          # Command-line client for testing interactively
├── proto/                # Protocol Buffer definitions (Ark v1)
├── tests/
│   ├── e2e_regtest.rs    # E2E regtest integration test suite
│   └── integration/      # Integration tests
├── scripts/
│   ├── e2e-test.sh       # E2E test runner
│   └── gen-tls-certs.sh  # TLS certificate generation
├── contrib/
│   ├── arkd.service      # systemd service unit
│   ├── config.example.toml
│   └── install.sh        # Bare-metal install script
├── config/
│   └── arkd.light.toml   # Light-mode config template
├── docs/
│   ├── light-mode.md     # Light mode deployment guide
│   ├── runbook.md        # Operational runbook
│   └── testing.md        # Testing guide
├── benches/              # Benchmarks
├── config.example.toml   # Fully documented config template
├── Justfile              # Task runner (build, test, e2e, lint)
├── Dockerfile            # Dev image
├── Dockerfile.prod       # Distroless production image
├── docker-compose.yml            # Full stack (arkd + Bitcoin Core + Postgres + Redis)
├── docker-compose.prod.yml       # Production compose
├── docker-compose.light.yml      # Light mode (no external deps)
├── docker-compose.ci.yml         # CI compose
├── prometheus.yml        # Prometheus scrape config
├── deny.toml             # cargo-deny config (licenses, advisories)
├── buf.work.yaml         # Buf workspace config (proto linting)
├── SECURITY.md
├── WORKFLOW.md
└── Cargo.toml            # Workspace configuration
```

---

## Quick Start

### Prerequisites

- **Rust** 1.75+ (install: https://rustup.rs/)
- **Nigiri** (Bitcoin regtest + Esplora): `curl https://getnigiri.vulpem.com | bash`
- **grpcurl** (for API testing): `brew install grpcurl`
- **Docker** (required by Nigiri)
- **PostgreSQL** (optional, can use SQLite)
- **Redis** (optional, can use in-memory cache)

### Installation

```bash
# Clone the repo
git clone https://github.com/lobbyclawy/arkd-rs.git
cd arkd-rs

# Build
cargo build --release

# Run tests
cargo test

# Run the server (dev mode)
cargo run -- --network regtest --config config.example.toml
```

### Using Just

```bash
just build    # Build the binary
just test     # Run all tests
just e2e      # Run E2E regtest suite
just lint     # Run clippy + fmt check
```

### Configuration

Create `config.toml` (see `config.example.toml` for full reference):

```toml
[server]
port = 7070
admin_port = 7071

[bitcoin]
network = "regtest"
rpc_url = "http://localhost:18443"
rpc_user = "bitcoin"
rpc_password = "bitcoin"

[database]
type = "postgres"  # or "sqlite"
url = "postgres://user:pass@localhost/arkd"

[cache]
type = "redis"  # or "inmemory"
url = "redis://localhost:6379"

[ark]
vtxo_expiry_seconds = 604800  # 7 days
unilateral_exit_delay = 86400  # 24 hours
round_max_participants = 128
```

---

## Development

### Running locally

```bash
# Start Nigiri (Bitcoin regtest + explorer)
nigiri start

# Run arkd-rs
cargo run

# In another terminal, test the API
grpcurl -plaintext localhost:7070 list
```

### Testing

```bash
# Unit + integration tests (no external dependencies)
cargo test --workspace
```

### End-to-End Tests (Nigiri)

Requires: `nigiri`, `docker`, `grpcurl`

```bash
# 1. Start Nigiri (keep running in background)
nigiri start

# 2. Build the binary (once, or after code changes)
cargo build --release

# 3. Run the e2e test
./scripts/e2e-test.sh
```

The script starts arkd, hits `GetInfo` via gRPC, and cleans up on exit.

---

## Deployment

### Docker (Quickstart)

```bash
# Build production image
docker build -f Dockerfile.prod -t arkd .

# Run with your config
docker run -d --name arkd \
  -p 7070:7070 -p 7071:7071 \
  -v ./config.toml:/home/arkd/.arkd/config.toml:ro \
  -v arkd-data:/home/arkd/.arkd \
  arkd
```

Or use the production compose file (includes Bitcoin Core regtest):

```bash
docker compose -f docker-compose.prod.yml up -d
```

### Light Mode (no external deps)

For single-process deployments with no Postgres or Redis:

```bash
docker compose -f docker-compose.light.yml up -d
```

See [`docs/light-mode.md`](docs/light-mode.md) for details.

### Docker Image (GHCR)

Pre-built images are published on version tags:

```bash
docker pull ghcr.io/lobbyclawy/arkd-rs:v0.1.0
```

### Systemd

For bare-metal / VM deployments:

```bash
# 1. Build the binary
cargo build --release

# 2. Install binary, config, and service
sudo cp target/release/arkd /usr/local/bin/
sudo bash contrib/install.sh

# 3. Edit configuration
sudo nano /etc/arkd/config.toml

# 4. Start the service
sudo systemctl enable --now arkd

# 5. Check status / logs
systemctl status arkd
journalctl -u arkd -f
```

### Configuration Reference

See [`config.example.toml`](config.example.toml) for a fully documented template.

| Section | Key Fields | Description |
|---------|-----------|-------------|
| `[server]` | `network`, `grpc_addr`, `admin_addr`, `round_interval` | Core server settings |
| `[bitcoin]` | `rpc_url`, `rpc_user`, `rpc_password`, `esplora_url` | Bitcoin node connection |
| `[database]` | `type`, `url` | Storage backend (sqlite/postgres) |
| `[wallet]` | `descriptor` | BDK wallet configuration |
| `[nostr]` | `relay_url`, `private_key_hex` | Optional Nostr integration |
| `[fees]` | `base_fee`, `*_input_fee`, `*_output_fee` | Fee schedule |

---

## Comparison: Go vs Rust

| Feature | arkd (Go) | arkd-rs (Rust) |
|---------|-----------|----------------|
| Language | Go 1.23+ | Rust 1.75+ |
| Bitcoin lib | btcd, btcsuite | rust-bitcoin, BDK |
| gRPC | google.golang.org/grpc | tonic + prost |
| Database | sqlc | sqlx |
| Async runtime | goroutines | tokio |
| Performance | ~Good | **Excellent** |
| Memory safety | Runtime checks | **Compile-time** |
| Ecosystem | Mature | **Growing fast** |

---

## Resources

**Original arkd (Go):**
- Repo: https://github.com/arkade-os/arkd
- Docs: https://deepwiki.com/arkade-os/arkd

**Ark Protocol:**
- Spec: https://ark-protocol.org/

**Rust Bitcoin:**
- rust-bitcoin: https://github.com/rust-bitcoin/rust-bitcoin
- BDK: https://bitcoindevkit.org/

---

## License

MIT (same as original arkd)

---

## Authors

- **Lobby** (lobbyclawy@gmail.com) - Rust implementation
- **Andrea Carotti** (ac.carotti@gmail.com) - Core contributor

Based on [arkd](https://github.com/arkade-os/arkd) by Arkade team.
