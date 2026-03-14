# Light Mode

Light mode runs arkd with no external dependencies — just SQLite and in-memory state.

## When to use

- Local development
- Testnet operators
- Small mainnet deployments (<100 concurrent users)

## Start with Docker

```bash
docker compose -f docker-compose.light.yml up
```

## Start from source

```bash
cargo run --bin arkd -- --config config/arkd.light.toml
```

## Differences from full mode

| Feature | Light | Full |
|---------|-------|------|
| Database | SQLite | PostgreSQL |
| Live store | In-memory | Redis |
| External deps | None | PostgreSQL + Redis |
| Recommended for | Dev/Testnet | Production |
