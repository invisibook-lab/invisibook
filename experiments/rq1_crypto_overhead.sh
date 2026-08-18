#!/usr/bin/env bash
# RQ1 — the cost of the cryptography.
#
# Measures the collaborative comparison protocol against a single prover of
# the SAME relation and keys, in three configurations:
#
#   1. single prover        — the computational lower bound
#   2. two parties, one process, in-memory channels
#   3. two parties, two processes, QUIC over the loopback interface
#
# It reports the latency of each phase (circuit build and witness check,
# collaborative prove, authenticated open, local verify), the peak memory
# of each trader, the traffic each trader sends, and the constant sizes of
# the circuit, the proof, and the verifying key.
#
#   ./experiments/rq1_crypto_overhead.sh [--runs 20] [--warmup 3]
#
# Output: experiments/results/rq1_*.json and rq1_summary.md

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

RUNS=20
WARMUP=3
BASE_PORT=23611
RELAY_PORT=23640

while [[ $# -gt 0 ]]; do
    case "$1" in
        --runs) RUNS="$2"; shift 2 ;;
        --warmup) WARMUP="$2"; shift 2 ;;
        --out-dir) OUT="$2"; shift 2 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) die "unknown option $1" ;;
    esac
done

need_cmd cargo python3
mkdir -p "$OUT"
build_cozk2p
build_netdelay
warm_keys
write_environment "$OUT/rq1_environment.json"

RAW="$OUT/rq1_raw.json"
log "measuring $RUNS runs per configuration (after $WARMUP warm-up runs)"
"$COZK2P/target/release/bench_settle2p" \
    --runs "$RUNS" --warmup "$WARMUP" --base-port "$BASE_PORT" --out "$RAW" \
    >"$OUT/rq1_bench.log" 2>&1 || die "the benchmark failed, see $OUT/rq1_bench.log"

# The traffic between the traders is measured on a relay run: Linux does
# not count socket bytes in the per-process I/O counters. The relay adds
# one local hop, so this run supplies the traffic volume only.
TRAFFIC="$OUT/rq1_traffic.json"
log "measuring the traffic between the traders through the relay"
"$REPO/experiments/netdelay/target/release/netdelay" \
    --listen "127.0.0.1:$RELAY_PORT" --peer "127.0.0.1:$((BASE_PORT + 1))" \
    --delay-ms 0 --rate-mbit 100000 --stats-out "$TRAFFIC" \
    >"$OUT/rq1_relay.log" 2>&1 &
RELAY_PID=$!
trap 'kill "$RELAY_PID" 2>/dev/null || true' EXIT
sleep 1
"$COZK2P/target/release/bench_settle2p" \
    --runs 1 --skip-single --skip-mock --base-port "$BASE_PORT" \
    --quic-peer-a "127.0.0.1:$RELAY_PORT" --out "$OUT/rq1_traffic_run.json" \
    >>"$OUT/rq1_bench.log" 2>&1 || die "the traffic run failed, see $OUT/rq1_bench.log"
sleep 1
kill "$RELAY_PID" 2>/dev/null || true
wait "$RELAY_PID" 2>/dev/null || true
trap - EXIT

python3 "$REPO/experiments/summarize.py" rq1 \
    --raw "$RAW" --traffic "$TRAFFIC" --environment "$OUT/rq1_environment.json" \
    --json-out "$OUT/rq1_summary.json" --md-out "$OUT/rq1_summary.md" \
    --csv-out "$OUT/rq1_phases.csv"

log "done — $OUT/rq1_summary.md"
cat "$OUT/rq1_summary.md"
