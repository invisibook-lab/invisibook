#!/usr/bin/env bash
# dev-dual.sh — Launch two isolated desktop instances (Alice + Bob) for local testing.
#
# Usage:
#   ./scripts/dev-dual.sh          # launch both Alice and Bob
#   ./scripts/dev-dual.sh alice    # launch Alice only
#   ./scripts/dev-dual.sh bob      # launch Bob only
#   ./scripts/dev-dual.sh clean    # wipe both data dirs and start fresh
#
# Each instance uses --data-dir to isolate mnemonic, cash.json, etc.
# Both connect to the same local chain (localhost:7999 / ws:8999).
#
# Prerequisites:
#   - Chain running on localhost:7999 / ws:8999 (cd chain && go run .)
#   - Desktop binary built (cd app/desktop && cargo build)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEST_DATA="$REPO_ROOT/chain/cfg/tests"
DATA_ROOT="$REPO_ROOT/.dev"

# Point both app instances at the collaborative-settlement prover
# subprocess (build it with `make build-settle2p`). Respects an existing
# override; the launch subshells inherit this env var.
export INVISIBOOK_SETTLE2P_BIN="${INVISIBOOK_SETTLE2P_BIN:-$REPO_ROOT/cozk2p/target/release/settle2p_session}"

ALICE_DIR="$DATA_ROOT/alice"
BOB_DIR="$DATA_ROOT/bob"

ALICE_MNEMONIC="test test test test test test test test test test test junk"
BOB_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Seed a user's data directory: write mnemonic, always reset cash.json to genesis.
setup_user() {
    local dir="$1" name="$2" mnemonic="$3" cash_json="$4"

    mkdir -p "$dir"
    echo "$mnemonic" > "$dir/mnemonic"
    cp "$cash_json" "$dir/cash.json"
    echo "[$name] data dir ready (cash reset): $dir"
}

# Launch a desktop instance with isolated --data-dir.
launch() {
    local dir="$1" name="$2"
    echo "[$name] launching desktop (data-dir=$dir) ..."
    (cd "$REPO_ROOT/app/desktop" && cargo run -- --data-dir "$dir") &
}

# ── Commands ──

case "${1:-both}" in
    clean)
        echo "Wiping dev data dirs..."
        rm -rf "$DATA_ROOT"
        echo "Done. Run again without 'clean' to start fresh."
        exit 0
        ;;
    alice)
        setup_user "$ALICE_DIR" "alice" "$ALICE_MNEMONIC" "$TEST_DATA/alice_cash.json"
        launch "$ALICE_DIR" "alice"
        wait
        ;;
    bob)
        setup_user "$BOB_DIR" "bob" "$BOB_MNEMONIC" "$TEST_DATA/bob_cash.json"
        launch "$BOB_DIR" "bob"
        wait
        ;;
    both)
        setup_user "$ALICE_DIR" "alice" "$ALICE_MNEMONIC" "$TEST_DATA/alice_cash.json"
        setup_user "$BOB_DIR" "bob" "$BOB_MNEMONIC" "$TEST_DATA/bob_cash.json"
        launch "$ALICE_DIR" "alice"
        launch "$BOB_DIR" "bob"
        echo "Both instances launched. Press Ctrl+C to stop all."
        wait
        ;;
    *)
        echo "Usage: $0 [alice|bob|both|clean]"
        exit 1
        ;;
esac
