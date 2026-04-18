# 0005 — CEL fee programs

- **Status**: accepted
- **Date**: 2026-04-17 (backfilled)
- **Deciders**: core maintainers

## Context

Round fees have to reflect the operator's cost of broadcasting the
commitment transaction, plus a margin. The cost varies with network
fee conditions and with the specific round's shape (participant count,
VTXO tree depth, boarding input count). Static fee tables are too
coarse; hard-coded formulas require a release to tune.

The Go arkd reference grew support for scripted fee programs written in
[CEL](https://github.com/google/cel-spec) (Common Expression Language)
— a sandboxed, deterministic expression language with good bindings
across ecosystems. Operators edit fee logic in config; the server
evaluates the program against a fixed input schema per fee request.

## Decision

dark supports three fee sources behind a single `FeeSource` trait
(#502):

1. `StaticFees` — a fixed fee table from config.
2. `RpcFees` — polled from Bitcoin Core RPC (`estimatesmartfee`).
3. `CelProgramFees` — a CEL program compiled once at config-load time;
   each fee request evaluates it with a typed input.

The Admin hot-reload RPC re-runs `FeeSource::reload(new_config)`,
which recompiles the CEL program before swapping it in — a malformed
program rejects the reload rather than bricking fee estimation.

## Consequences

- Operators can tune fee logic without recompiling dark. The CEL
  program is part of config, not code.
- CEL is sandboxed: the program cannot read the filesystem, open
  sockets, or loop unbounded. Worst-case program errors bubble up as
  `FeeError::Evaluation`.
- The input schema is a protocol-adjacent contract. Changing it is a
  breaking change for operators with deployed CEL programs. New fields
  are additive and versioned.
- Performance: CEL evaluation per fee request is sub-millisecond on
  the reference program. Compilation is eager (one-time, at load) —
  per-request compile would have been a meaningful regression.

## Alternatives considered

- **Static fee table only**: simpler, loses tunability. Deployments
  would have to ship a new binary to adjust fees during a congestion
  event.
- **A Rust DSL / embedded scripting language (Rhai, rune)**: lost on
  (1) less widely understood than CEL, (2) no cross-implementation
  parity with the Go reference.
- **Lua / WebAssembly sandboxed plugins**: more powerful than needed;
  CEL's deterministic, bounded-evaluation guarantees match fee
  programs exactly — these plugin runtimes do not.
