#!/usr/bin/env bash
#
# Stands up a local CKB devnet and runs the Invisibook L2 against it, so that
# the whole Proof-of-Buy path — prepay, commit, anchor, reveal, settle — runs
# against a real chain instead of the in-memory mock.
#
#   scripts/devnet.sh up       build, deploy, prepay and start everything
#   scripts/devnet.sh status   where things are: L1 tip, L2 tip, anchoring
#   scripts/devnet.sh logs     follow the L2 node's log
#   scripts/devnet.sh down     stop the processes, keep the chain data
#   scripts/devnet.sh clean    stop and delete everything
#
# Everything lives under .devnet/ and nothing touches the repo's own configs
# or databases, so `clean` really does put the machine back.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV="${DEV:-$ROOT/.devnet}"
CHAIN="$ROOT/chain"
RPC="http://127.0.0.1:8114"
PAYMENT="http://127.0.0.1:8081"

# The standard sighash lock. Same on a devnet as everywhere else — only the
# genesis transaction holding it differs, which is why that is looked up.
SIGHASH_CODE_HASH="0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"

# The operator's mining addr: every miner's prepayment lands here. One of the
# dev spec's own issued cells, so a devnet has a key for it — on a real chain
# this is chosen once and can never be changed, since pob-spent carries its
# lock hash in args (ckb_layout.md §4).
MINING_ADDR_ARGS="0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7"

# How many heights to bid on, and what to pay for each.
BID_FROM="${BID_FROM:-1}"
BID_COUNT="${BID_COUNT:-200}"
BID_AMOUNT="${BID_AMOUNT:-10000000000}"   # 100 CKB per height

# PaymentLeadBlocks is 24 (whitepaper §7.3); a couple spare so that a block
# produced the moment the node starts still clears it.
LEAD_BLOCKS=26

# http_code probes a URL and prints its status code, or 000 when nothing is
# listening. curl's own exit status turned out not to be dependable for this,
# so the code is what the readiness loops test.
http_code() { curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$1" || true; }

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m warn\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror\033[0m %s\n' "$*" >&2; exit 1; }

# rpc calls one CKB JSON-RPC method and prints its `result` as JSON.
rpc() {
    local method="$1" params="${2:-[]}"
    curl -s -H 'content-type: application/json' \
        -d "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params}" \
        "$RPC"
}

# tip prints L1's current block number as a decimal, or 0 when the node is not
# answering yet — callers poll on it while the chain is still coming up.
tip() {
    rpc get_tip_block_number | python3 -c '
import json, sys
try:
    print(int(json.load(sys.stdin)["result"], 16))
except Exception:
    print(0)
'
}

preflight() {
    for tool in ckb go cargo curl python3; do
        command -v "$tool" >/dev/null || die "$tool is not installed"
    done
    rustup target list --installed 2>/dev/null | grep -q riscv64imac-unknown-none-elf \
        || die "rustup target add riscv64imac-unknown-none-elf (see ckb/README.md)"
}

# init_devnet creates a fresh CKB dev chain funded for this node's miner.
#
# The spec is edited before the chain is ever started, because editing it
# afterwards changes the genesis hash and invalidates the database.
init_devnet() {
    local lock_args="$1"

    say "initialising a CKB devnet in $DEV"
    rm -rf "$DEV/ckb"
    mkdir -p "$DEV/ckb" "$DEV/logs"
    (cd "$DEV/ckb" && ckb init --chain dev >/dev/null)

    # Fund the miner. Without an issued cell under its lock it owns nothing,
    # and cellbase rewards only mature after the maturity period.
    cat >>"$DEV/ckb/specs/dev.toml" <<EOF

# Invisibook L2 miner — funded by scripts/devnet.sh
[[genesis.issued_cells]]
capacity = 50_000_000_00000000
lock.code_hash = "$SIGHASH_CODE_HASH"
lock.args = "$lock_args"
lock.hash_type = "type"
EOF

    python3 - "$DEV/ckb/ckb.toml" "$lock_args" "$SIGHASH_CODE_HASH" <<'EOF'
import sys
path, args, code_hash = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path).read()

# get_cells backs cell collection, and it is served only when the Indexer
# module is on. It is off by default, and without it every transaction this
# node tries to build fails with "no enough capacity".
old = '''modules = ["Net", "Pool", "Miner", "Chain", "Stats", "Subscription", "Experiment", "Debug", "Terminal"]'''
new = '''modules = ["Net", "Pool", "Miner", "Chain", "Stats", "Subscription", "Experiment", "Debug", "Indexer", "Terminal"]'''
assert old in text, "ckb.toml does not have the rpc module list this script knows how to edit"
text = text.replace(old, new)

# ckb miner refuses to run without somewhere to send the reward.
text += f'''
[block_assembler]
code_hash = "{code_hash}"
args = "{args}"
hash_type = "type"
message = "0x"
'''
open(path, 'w').write(text)
EOF

    # 5s a block is the default and makes the 24-block payment lead a
    # two-minute wait; 1s keeps the whole run under a minute.
    python3 - "$DEV/ckb/ckb-miner.toml" <<'EOF'
import sys
path = sys.argv[1]
text = open(path).read().replace("value = 5000", "value = 1000")
open(path, 'w').write(text)
EOF
}

start_l1() {
    say "starting the CKB node and miner"
    (cd "$DEV/ckb" && exec ckb run) >"$DEV/logs/ckb.log" 2>&1 &
    echo $! >"$DEV/ckb.pid"

    for _ in $(seq 1 60); do
        [ "$(http_code "$RPC")" != "000" ] && break
        sleep 1
    done
    [ "$(http_code "$RPC")" != "000" ] || die "the CKB node did not come up; see $DEV/logs/ckb.log"

    (cd "$DEV/ckb" && exec ckb miner) >"$DEV/logs/ckb-miner.log" 2>&1 &
    echo $! >"$DEV/ckb-miner.pid"

    say "waiting for L1 to produce its first blocks"
    for _ in $(seq 1 60); do
        [ "$(tip)" -ge 2 ] && return 0
        sleep 1
    done
    die "L1 is not producing blocks; see $DEV/logs/ckb-miner.log"
}

# genesis_dep_tx prints the transaction holding the sighash dep group.
#
# CKB's genesis puts the system code cells in its first transaction and the
# dep groups in its second. On a public network that hash is a constant; a
# devnet mints its own, which is what `sighash_dep_tx_hash` in the config is
# for.
genesis_dep_tx() {
    rpc get_block_by_number '["0x0"]' \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["transactions"][1]["hash"])'
}

build_contracts() {
    say "building the four PoB scripts"
    export CC_riscv64imac_unknown_none_elf="${CC_riscv64imac_unknown_none_elf:-riscv64-elf-gcc}"
    export AR_riscv64imac_unknown_none_elf="${AR_riscv64imac_unknown_none_elf:-riscv64-elf-ar}"
    for c in pob-budget pob-submission pob-vault pob-spent; do
        cargo build --manifest-path "$ROOT/ckb/contracts/$c/Cargo.toml" \
            --target riscv64imac-unknown-none-elf --release >/dev/null 2>&1 \
            || die "building $c failed; run it by hand to see why (ckb/README.md)"
    done
}

# write_configs produces the node's configs under $DEV, leaving the repo's own
# untouched so that a devnet run never competes with a normal one for
# databases or ports.
write_configs() {
    local dep_tx="$1" mining_addr="$2"

    say "writing the L2 node's devnet config"
    python3 - "$CHAIN/cfg/core.toml" "$DEV/core.toml" "$DEV" <<'EOF'
import sys
src, dst, dev = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(src).read()
text = text.replace('db_path      = "data/chain.db"', f'db_path      = "{dev}/chain.db"')
# The protocol behaviour: sit out any height with no L1-confirmed declaration.
# Off in the repo's config because the mock L1 can confirm nothing.
text = text.replace('require_declared_payment = false', 'require_declared_payment = true')
open(dst, 'w').write(text)
EOF

    python3 - "$CHAIN/cfg/chain.toml" "$DEV/chain.toml" "$DEV" <<'EOF'
import sys
src, dst, dev = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(src).read().replace('data_dir    = "data"', f'data_dir    = "{dev}/yu"')
open(dst, 'w').write(text)
EOF

    # The deployer is the miner here, and its key is derived from the same
    # config the node reads — so nothing has to write a private key to disk.
    say "deploying the scripts and appending the [ckb] section"
    (cd "$CHAIN" && go run ./cmd/ckb-deploy \
        -rpc "$RPC" -network devnet \
        -sighash-dep "$dep_tx" \
        -mining-addr "$mining_addr" \
        -core-config "$DEV/core.toml" \
        -contracts "$ROOT/ckb/contracts") >>"$DEV/core.toml"
}

prepay() {
    say "prepaying: $BID_COUNT heights from $BID_FROM at $BID_AMOUNT shannon each"
    (cd "$CHAIN" && go run ./cmd/pob-miner prepay \
        -core-config "$DEV/core.toml" \
        -from "$BID_FROM" -count "$BID_COUNT" -amount "$BID_AMOUNT" \
        -out "$DEV/schedule.json")
}

# wait_for_lead holds until the prepayment is old enough to bid with.
#
# V4 requires an allocation to predate the anchoring of the block spending it
# by 24 L1 blocks. An anchor's height is fixed the moment it lands, so a block
# produced too early can never clear the rule — it does not become valid
# later, it stays unsettleable forever. Hence waiting here rather than
# starting the L2 and hoping.
wait_for_lead() {
    local budget_block target
    # Measured from the block the budget cell landed in, not from whatever the
    # tip happens to be now — those differ by however long the prepayment sat
    # in the pool, and guessing short here is unrecoverable.
    budget_block="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["l1_block"])' "$DEV/schedule.json")"
    target=$((budget_block + LEAD_BLOCKS))
    say "prepayment landed in L1 block $budget_block; waiting for block $target so it clears V4's lead"
    while [ "$(tip)" -lt "$target" ]; do sleep 1; done
}

start_l2() {
    say "starting the Invisibook L2 node"
    (cd "$CHAIN" && exec go run . -config "$DEV/chain.toml" -core-config "$DEV/core.toml") \
        >"$DEV/logs/l2.log" 2>&1 &
    echo $! >"$DEV/l2.pid"

    for _ in $(seq 1 120); do
        [ "$(http_code "$PAYMENT/pay_l1_token")" != "000" ] && return 0
        sleep 1
    done
    die "the L2 node's payment endpoint never came up; see $DEV/logs/l2.log"
}

declare_bids() {
    say "declaring the openings to the node"
    # Retried because the node has only just bound its port, and because a
    # `go run` here may spend a while compiling before it connects.
    for attempt in 1 2 3 4 5; do
        if (cd "$CHAIN" && go run ./cmd/pob-miner declare \
            -in "$DEV/schedule.json" -node "$PAYMENT"); then
            return 0
        fi
        warn "declaring failed (attempt $attempt), retrying"
        sleep 3
    done
    die "the node never accepted the declarations; see $DEV/logs/l2.log"
}

up() {
    preflight
    mkdir -p "$DEV"

    local lock_args mining_addr
    lock_args="$(cd "$CHAIN" && go run ./cmd/pob-miner address -core-config cfg/core.toml \
        | awk '/^lock_args/ {print $2}')"
    [ -n "$lock_args" ] || die "could not derive the miner's lock args"
    say "miner lock args $lock_args"

    mining_addr="$(cd "$CHAIN" && go run ./cmd/pob-miner address -lock-args "$MINING_ADDR_ARGS" \
        | awk '/^address/ {print $2}')"
    say "mining addr $mining_addr"

    init_devnet "$lock_args"
    start_l1
    build_contracts
    write_configs "$(genesis_dep_tx)" "$mining_addr"
    prepay
    wait_for_lead
    start_l2
    declare_bids

    say "up. \`scripts/devnet.sh status\` to watch it, \`logs\` to follow the node."
}

status() {
    printf 'L1 tip      %s\n' "$(tip 2>/dev/null || echo 'not running')"
    if [ -f "$DEV/logs/l2.log" ]; then
        printf 'L2 blocks   %s\n' "$(grep -c 'PoB: committed block to L1' "$DEV/logs/l2.log" || echo 0)"
        printf 'settled     %s\n' "$(grep -c 'PoB: settled' "$DEV/logs/l2.log" || echo 0)"
        printf '\nlast lines of the L2 log:\n'
        tail -15 "$DEV/logs/l2.log"
    else
        printf 'L2          not started\n'
    fi
}

down() {
    for name in l2 ckb-miner ckb; do
        if [ -f "$DEV/$name.pid" ]; then
            # `go run` execs the binary as a child, so the recorded pid is the
            # wrapper and killing it alone leaves the node holding its ports.
            pkill -P "$(cat "$DEV/$name.pid")" 2>/dev/null || true
            kill "$(cat "$DEV/$name.pid")" 2>/dev/null || true
            rm -f "$DEV/$name.pid"
        fi
    done

    # Waited for, because the next `up` probes these ports to decide the node
    # is ready: a process on its way out answers, and the run then declares
    # its payments into a socket that is about to close.
    for _ in $(seq 1 30); do
        if [ "$(http_code "$PAYMENT/pay_l1_token")" = "000" ] && [ "$(http_code "$RPC")" = "000" ]; then
            break
        fi
        sleep 1
    done
    say "stopped"
}

case "${1:-up}" in
    up)     up ;;
    status) status ;;
    logs)   tail -f "$DEV/logs/l2.log" ;;
    down)   down ;;
    clean)  down; rm -rf "$DEV"; say "removed $DEV" ;;
    *)      die "usage: $0 up|status|logs|down|clean" ;;
esac
