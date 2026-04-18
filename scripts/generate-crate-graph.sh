#!/usr/bin/env bash
#
# Regenerate the workspace crate dependency graph.
#
# Produces:
#   docs/assets/crate-graph.dot   (source of truth, committed)
#   docs/assets/crate-graph.svg   (rendered; committed)
#
# Requirements:
#   cargo-depgraph    cargo install cargo-depgraph
#   graphviz (dot)    apt-get install graphviz | brew install graphviz
#
# Running this script is idempotent: it overwrites the artifacts in
# docs/assets/ with whatever the current Cargo.toml files imply. A CI
# job (tracked as a follow-up to #510) re-runs this on main and fails
# the build if the committed artifacts are stale.

set -euo pipefail

cd "$(dirname "$0")/.."

OUT_DIR="docs/assets"
DOT_FILE="$OUT_DIR/crate-graph.dot"
SVG_FILE="$OUT_DIR/crate-graph.svg"

if ! command -v cargo-depgraph >/dev/null 2>&1; then
    echo "error: cargo-depgraph is not installed" >&2
    echo "install: cargo install cargo-depgraph" >&2
    exit 1
fi

if ! command -v dot >/dev/null 2>&1; then
    echo "error: graphviz 'dot' is not installed" >&2
    echo "install (Debian/Ubuntu): apt-get install graphviz" >&2
    echo "install (macOS):         brew install graphviz" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

# Workspace-only graph: skip transitive deps outside the workspace so
# the picture stays readable. Dedup feature edges.
cargo depgraph \
    --workspace-only \
    --dedup-transitive-deps \
    > "$DOT_FILE"

dot -Tsvg "$DOT_FILE" -o "$SVG_FILE"

echo "wrote $DOT_FILE and $SVG_FILE"
