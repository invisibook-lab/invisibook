#!/usr/bin/env bash
# RQ2 — how much the round-trip time between the traders costs.
#
# The two trader processes speak QUIC through a UDP relay
# (experiments/netdelay) that holds every datagram for half of the wanted
# round-trip time and caps the link at a fixed rate. The relay runs in user
# space, so the sweep needs neither root rights nor `tc`.
#
# Everything except the round-trip time stays equal: the same order, the
# same witness, the same binaries, the same machine, the same rate cap.
#
#   ./experiments/rq2_network_latency.sh [--runs 3] [--rtts "0 10 30 60 100"]
#                                        [--rate-mbit 1000] [--timeout 3600]
#
# Output: experiments/results/rq2_*.json, rq2_summary.md, rq2_latency.csv

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

RUNS=3
RTTS="0 10 30 60 100"
RATE_MBIT=1000
RUN_TIMEOUT=3600
BASE_PORT=23711
RELAY_PORT=23740

while [[ $# -gt 0 ]]; do
    case "$1" in
        --runs) RUNS="$2"; shift 2 ;;
        --rtts) RTTS="$2"; shift 2 ;;
        --rate-mbit) RATE_MBIT="$2"; shift 2 ;;
        --timeout) RUN_TIMEOUT="$2"; shift 2 ;;
        --out-dir) OUT="$2"; shift 2 ;;
        -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
        *) die "unknown option $1" ;;
    esac
done

need_cmd cargo python3 timeout
mkdir -p "$OUT"
build_cozk2p
build_netdelay
warm_keys
write_environment "$OUT/rq2_environment.json"

INDEX="$OUT/rq2_index.json"
printf '{"rate_mbit": %s, "runs": %s, "points": [' "$RATE_MBIT" "$RUNS" >"$INDEX"
FIRST=1

for RTT in $RTTS; do
    DELAY=$(python3 -c "print($RTT / 2)")
    BENCH_OUT="$OUT/rq2_rtt${RTT}.json"
    TRAFFIC_OUT="$OUT/rq2_rtt${RTT}_traffic.json"
    log "round-trip time ${RTT} ms (one-way delay ${DELAY} ms), $RUNS runs"

    "$REPO/experiments/netdelay/target/release/netdelay" \
        --listen "127.0.0.1:$RELAY_PORT" --peer "127.0.0.1:$((BASE_PORT + 1))" \
        --delay-ms "$DELAY" --rate-mbit "$RATE_MBIT" --stats-out "$TRAFFIC_OUT" \
        >"$OUT/rq2_relay_rtt${RTT}.log" 2>&1 &
    RELAY_PID=$!
    trap 'kill "$RELAY_PID" 2>/dev/null || true' EXIT
    sleep 1

    STATUS=ok
    timeout "$RUN_TIMEOUT" "$COZK2P/target/release/bench_settle2p" \
        --runs "$RUNS" --skip-single --skip-mock --base-port "$BASE_PORT" \
        --quic-peer-a "127.0.0.1:$RELAY_PORT" --out "$BENCH_OUT" \
        >"$OUT/rq2_bench_rtt${RTT}.log" 2>&1 || STATUS=failed

    sleep 1
    kill "$RELAY_PID" 2>/dev/null || true
    wait "$RELAY_PID" 2>/dev/null || true
    trap - EXIT

    [[ $FIRST -eq 1 ]] || printf ',' >>"$INDEX"
    FIRST=0
    printf '\n  {"rtt_ms": %s, "one_way_delay_ms": %s, "status": "%s", "bench": "%s", "traffic": "%s"}' \
        "$RTT" "$DELAY" "$STATUS" "$BENCH_OUT" "$TRAFFIC_OUT" >>"$INDEX"
    [[ "$STATUS" == ok ]] || log "the ${RTT} ms point did not finish inside ${RUN_TIMEOUT} s"
done

printf '\n]}\n' >>"$INDEX"

python3 "$REPO/experiments/summarize.py" rq2 \
    --index "$INDEX" --environment "$OUT/rq2_environment.json" \
    --json-out "$OUT/rq2_summary.json" --md-out "$OUT/rq2_summary.md" \
    --csv-out "$OUT/rq2_latency.csv"

log "done — $OUT/rq2_summary.md"
cat "$OUT/rq2_summary.md"
