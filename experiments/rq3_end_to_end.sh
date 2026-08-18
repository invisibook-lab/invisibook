#!/usr/bin/env bash
# RQ3 — the end-to-end cost of one trade and what it costs the chain.
#
# Runs a complete trade on a live single-node chain with two real trader
# processes: order proving and submission, matching, the collaborative
# comparison, the on-chain comparison anchor, the two local settlement
# proofs, the settlement-message exchange, and the atomic settlement.
# Every proof is verified on chain, so the node log carries the
# verification time of each proof and the payload size of each writing.
#
#   ./experiments/rq3_end_to_end.sh [--runs 1] [--keep-log]
#
# The trade needs about 15 GB of free memory (two collaborative provers).
#
# Output: experiments/results/rq3_*.json, rq3_summary.md

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

RUNS=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --runs) RUNS="$2"; shift 2 ;;
        --out-dir) OUT="$2"; shift 2 ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
        *) die "unknown option $1" ;;
    esac
done

need_cmd cargo go python3
mkdir -p "$OUT"
write_environment "$OUT/rq3_environment.json"

log "building the chain with the PLONK verifier, the prover, and the chain fixture"
make -C "$REPO" build-chain-cozk2p build-settle2p >"$OUT/rq3_build.log" 2>&1 \
    || die "the build failed, see $OUT/rq3_build.log"
make -C "$REPO" dump-cozk2p-fixture >>"$OUT/rq3_build.log" 2>&1 \
    || die "the fixture dump failed, see $OUT/rq3_build.log"

log "building the end-to-end test (release)"
(cd "$REPO/app" && cargo build --release --tests -p invisibook-ui) \
    >>"$OUT/rq3_build.log" 2>&1 || die "the test build failed, see $OUT/rq3_build.log"

for RUN in $(seq 1 "$RUNS"); do
    STATS="$OUT/rq3_run${RUN}_stats.json"
    LOG="$OUT/rq3_run${RUN}.log"
    log "trade $RUN of $RUNS — chain, two traders, every proof verified"
    (cd "$REPO/app" && INVISIBOOK_E2E_STATS="$STATS" \
        cargo test --release -p invisibook-ui --test settle_e2e \
        -- --ignored --nocapture --test-threads=1) >"$LOG" 2>&1 \
        || die "the trade failed, see $LOG"
    [[ -f "$STATS" ]] || die "the test wrote no statistics, see $LOG"
done

python3 "$REPO/experiments/summarize.py" rq3 \
    --out-dir "$OUT" --runs "$RUNS" --environment "$OUT/rq3_environment.json" \
    --json-out "$OUT/rq3_summary.json" --md-out "$OUT/rq3_summary.md"

log "done — $OUT/rq3_summary.md"
cat "$OUT/rq3_summary.md"
