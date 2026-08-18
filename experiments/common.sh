#!/usr/bin/env bash
# Helpers shared by the experiment scripts. Source it, do not run it.
#
#   REPO   — repository root
#   OUT    — directory for the generated data (default experiments/results)
#   COZK2P — the cozk2p workspace (prover binaries and the key cache)

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COZK2P="$REPO/cozk2p"
KEYS_DIR="$COZK2P/target/settle2p-keys"
OUT="${OUT:-$REPO/experiments/results}"

# Print a progress line with a timestamp.
log() {
    printf '\033[1;34m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2
}

# Stop with a message on standard error.
die() {
    printf '\033[1;31merror:\033[0m %s\n' "$*" >&2
    exit 1
}

# Stop unless every named program is on the PATH.
need_cmd() {
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || die "$cmd is not installed"
    done
}

# Build the collaborative prover and the benchmark harness (release).
build_cozk2p() {
    log "building the cozk2p binaries (release)"
    (cd "$COZK2P" && cargo build --release --bins)
}

# Build the UDP delay relay (release).
build_netdelay() {
    log "building the netdelay relay (release)"
    (cd "$REPO/experiments/netdelay" && cargo build --release)
}

# Generate or load the proving keys, so no measured run pays key setup.
warm_keys() {
    log "warming the proving-key cache in $KEYS_DIR"
    mkdir -p "$KEYS_DIR"
    "$COZK2P/target/release/settle2p_session" --warm-keys --keys-dir "$KEYS_DIR" >/dev/null
}

# Record the machine and the software versions the run used.
write_environment() {
    local path="$1"
    python3 - "$path" <<'PY'
import json, platform, subprocess, sys, os

def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception:
        return ""

def cpu_model():
    for line in open("/proc/cpuinfo"):
        if line.startswith("model name"):
            return line.split(":", 1)[1].strip()
    return ""

def mem_total_gib():
    for line in open("/proc/meminfo"):
        if line.startswith("MemTotal:"):
            return round(int(line.split()[1]) / 1024 / 1024, 1)
    return 0

json.dump({
    "cpu": cpu_model(),
    "logical_cpus": os.cpu_count(),
    "memory_gib": mem_total_gib(),
    "kernel": platform.release(),
    "os": run(["bash", "-lc", "source /etc/os-release && echo $PRETTY_NAME"]),
    "rustc": run(["rustc", "--version"]),
    "cargo": run(["cargo", "--version"]),
    "go": run(["go", "version"]),
    "git_commit": run(["git", "rev-parse", "HEAD"]),
    "git_branch": run(["git", "rev-parse", "--abbrev-ref", "HEAD"]),
}, open(sys.argv[1], "w"), indent=2)
PY
}
